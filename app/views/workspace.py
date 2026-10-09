import re
from urllib.parse import quote

from flask import Blueprint, render_template, jsonify, request
from flask_login import current_user, login_required
from ..auth.decorators import require_permission
from ..models import Appliance
from ..models import visible_appliances, visible_appliance_or_404
from ..clients.fortiweb import FortiWebClient
from ..clients import client_for
from ..services.fortiweb_field_schema import (
    build_groups, descriptor, is_noise, is_on, REF_ENDPOINTS, ALL_REF_ENDPOINTS,
    CREATE_FIELDS,
)
from ..services import policy_form
from ..services import policy_ops
from ..services import policy_links
from ..services.fortiweb_ops import FortiWebOps
from ..services import appids as appids_svc
from ..services.audit import log_action
from ..errors import flash_error, json_error, log_exception

bp = Blueprint('workspace', __name__, url_prefix='/workspace')

# Full cmdb endpoints the editable workspace reads/writes (allow-listed for
# save). FortiWeb writes go to the REST cmdb tree and the body must be wrapped
# in {"data": {...}}; child sub-tables are addressed with &sub_mkey=<id>.
EP_POLICY = '/api/v2.0/cmdb/server-policy/policy'
EP_POOL = '/api/v2.0/cmdb/server-policy/server-pool'
EP_WPP = '/api/v2.0/cmdb/waf/web-protection-profile.inline-protection'
EP_VIPLIST = '/api/v2.0/cmdb/server-policy/vserver/vip-list'
EP_PSERVER = '/api/v2.0/cmdb/server-policy/server-pool/pserver-list'
# A FortiWeb port name: port1, port1.100 (VLAN), vzone names, aggregates.
# Deliberately narrow — the value is written verbatim into a device payload,
# and "the browser sent it" is not a reason to relay arbitrary text to a
# firewall's config.
_IFACE_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')


def clean_iface_map(action, raw):
    """Normalise the dialog's ``{source port: destination port}`` mapping.

    Returns ``(mapping, bad_name)``; ``bad_name`` is ``None`` on success and
    the offending string otherwise, so the caller can refuse rather than
    silently drop (a mapping quietly discarded would clone onto the source's
    ports while the operator watched a selector say otherwise).

    A FUNCTION, not four lines inline in the route, because the two rules it
    encodes are the kind that get verified by grepping the route for a
    keyword — and that assertion passes for the wrong reason as soon as the
    keyword appears anywhere else in the same function. Here they are
    executable:

      * cross-box actions ONLY. A same-box clone shares the chassis, so
        re-binding it would move the copy to a network nobody asked for.
      * port names, not free text. The value is written verbatim into a
        firewall's config; "the browser sent it" is not provenance.
    """
    if action not in policy_ops._NEEDS_TARGET or not isinstance(raw, dict):
        return {}, None
    out = {}
    for src_if, dst_if in raw.items():
        s, d = str(src_if or '').strip(), str(dst_if or '').strip()
        if not s or not d or s == d:
            continue
        if not _IFACE_NAME_RE.match(s):
            return {}, s
        if not _IFACE_NAME_RE.match(d):
            return {}, d
        out[s] = d
    return out, None

_NF_NAME_RE = re.compile(r'^[A-Za-z0-9_.\-]{1,160}$')
_NF_MAX_KEYS, _NF_MAX_FIELDS, _NF_MAX_LEN = 50, 100, 1024


def clean_new_field_values(action, raw):
    """Shape-check the dialog's ``{object: {field: value}}`` new-field answers.

    Returns ``(values, error)``. SHAPE only — names, scalar values, sizes. The
    authoritative rule (the destination build is known to serve the field, the
    source lacks it, the value fits its type/options) is enforced by
    ``version_compat.validate_new_values`` inside the engine, so a caller that
    skips this route is held to it too. Empty values are "not opted in" and
    are dropped here, so "left blank" reaches the engine as absent.
    """
    if action not in policy_ops._CLONE_ACTIONS or raw in (None, {}, ''):
        return {}, None
    if not isinstance(raw, dict) or len(raw) > _NF_MAX_KEYS:
        return {}, 'new field values must be an object of {object: {field: value}}'
    out = {}
    for key, fields in raw.items():
        key = str(key or '')
        if not _NF_NAME_RE.match(key) or not isinstance(fields, dict) \
                or len(fields) > _NF_MAX_FIELDS:
            return {}, 'new field values for %r are malformed' % key[:80]
        for f, v in fields.items():
            f = str(f or '')
            if not _NF_NAME_RE.match(f):
                return {}, '%r is not a field name' % f[:80]
            if v is None or (isinstance(v, str) and not v.strip()):
                continue
            if not isinstance(v, (str, int, float, bool)) or len(str(v)) > _NF_MAX_LEN:
                return {}, 'value for %s.%s must be short text' % (key, f)
            out.setdefault(key, {})[f] = v
    return out, None


_SAVE_EPS = {EP_POLICY, EP_POOL, EP_WPP, EP_VIPLIST, EP_PSERVER}
_CHILD_EPS = {EP_VIPLIST, EP_PSERVER}

# Referenced objects are editable in place — the ✎ on a dropdown opens the
# selected object. Allow-list their full cmdb paths through the same audited save.
_REF_COLLECTIONS = {c for ep in REF_ENDPOINTS.values() for c in ep.split('|')}
_REF_FULL_EPS = {'/api/v2.0/cmdb/' + c for c in _REF_COLLECTIONS}
_SAVE_EPS = _SAVE_EPS | _REF_FULL_EPS

# Keys pulled out of the policy field groups into their own card: the operator
# picks the profile, its contents are NOT edited from the policy form.
_HOIST_KEYS = {'web-protection-profile'}

_NOISE_SUFFIX = ("_val",)
_NOISE_PREFIX = ("q_", "sub_table", "sz_", "can_")
_NOISE_KEYS = {"id", "policy-id", "tags", "flag", "trigger", "host-for-deny",
               "url-for-deny", "hostname", "domainname"}


def _clean_policy(policy):
    """Trim FortiWeb's *_val companions / q_* metadata for the raw-JSON view."""
    out = {}
    for k, v in (policy or {}).items():
        if (k in _NOISE_KEYS or k.endswith(_NOISE_SUFFIX) or k.startswith(_NOISE_PREFIX)):
            continue
        if v in (None, "", []):
            continue
        out[k] = v
    return out


def _filter_groups(groups, drop_keys):
    """Drop hoisted keys (rendered in their own card) from grouped fields."""
    out = []
    for g in groups:
        fields = [f for f in g['fields'] if f['key'] not in drop_keys]
        if fields:
            out.append({'title': g['title'], 'fields': fields})
    return out


@bp.route('/')
@login_required
@require_permission('protection.view')
def index():
    appliances = visible_appliances().order_by(Appliance.name).all()
    from flask import redirect as _redir, url_for as _ufor
    from ..services import device_context as _dc
    _cur = _dc.current_appliance()
    if _cur is None:
        return _redir(_ufor('architecture.index'))
    return _redir(_ufor('workspace.appliance', appliance_id=_cur.id))


@bp.route('/<int:appliance_id>')
@login_required
@require_permission('protection.view')
def appliance(appliance_id):
    appl = visible_appliance_or_404(appliance_id)
    policies = []
    error = None
    meta = {}
    try:
        if appl.kind == 'fortiweb':
            # DB-first: serve the local source of truth; the box is touched only
            # on an explicit Refresh (see workspace.refresh). Empty cache => the
            # badge prompts a refresh rather than auto-hitting the device.
            from ..services import read_layer
            policies, meta = read_layer.read_policies(appl)
        # No FortiADC branch: this blueprint is FortiWeb-scoped (the product
        # gate) and visible_appliance_or_404 hides ADC boxes from that ADOM;
        # FortiADC virtual servers live in the adc blueprint.
    except Exception as exc:
        error = str(exc)
    from ..services import read_layer as _rl
    # Filter facets (VIP IP / backend server IP / pool / cert type) + the list of
    # OTHER FortiWebs (clone-to / migrate-to targets). Both are DB-first — the
    # facets read the deep cache, the target list is pure config. Best-effort so a
    # cold cache never breaks the page (backend/VIP filters just show nothing).
    facets, other_appliances, clone_events = {}, [], {}
    if appl.kind == 'fortiweb':
        names = [(p.get('name') if isinstance(p, dict) else getattr(p, 'name', ''))
                 for p in (policies or [])]
        names = [n for n in names if n]
        try:
            facets = _rl.policy_filter_facets(appl.id, names)
        except Exception as exc:  # noqa: BLE001
            log_exception(exc, context='workspace.appliance.facets')
        # Clone/migrate history for every row on the page — ONE query, keyed by
        # (appliance, policy name). Deliberately NOT joined onto the cache
        # projection: device_server_policies is rebuilt on every ingest.
        from ..services import policy_lineage as _lin
        clone_events = _lin.for_policies(appl.id, names)
        other_appliances = [a for a in visible_appliances()
                            .filter(Appliance.kind == 'fortiweb')
                            .order_by(Appliance.name).all() if a.id != appl.id]
    from ..services import clone_rules as _cr
    try:
        clone_cfg = _cr.config()
        clone_rules_summary = _cr.rules_summary(clone_cfg)
    except Exception:  # noqa: BLE001 — never let settings break the list page
        clone_cfg, clone_rules_summary = {'copy_wpp_default': True}, ''
    return render_template('workspace/policies.html', appliance=appl,
                           policies=policies, error=error, cache_meta=meta,
                           facets=facets, other_appliances=other_appliances,
                           clone_cfg=clone_cfg,
                           clone_events=clone_events,
                           clone_rules_summary=clone_rules_summary,
                           cache_freshness=_rl.freshness_label(meta) if appl.kind == 'fortiweb' else '')


@bp.route('/<int:appliance_id>/refresh', methods=['POST'])
@login_required
@require_permission('config_write')
def refresh(appliance_id):
    """Pull live config from the device into the local source of truth (cache +
    JSON backup), then return to the Server Policy list. DB-first reads serve
    everything else; this is the explicit ⟳ the user controls."""
    from flask import redirect, url_for, flash
    from flask_login import current_user
    appl = visible_appliance_or_404(appliance_id)
    try:
        if appl.kind == 'fortiweb':
            from ..services import device_sync
            run = device_sync.sync_device(
                appl, publish=False,
                user_label=getattr(current_user, 'username', None),
                trigger='manual')
            flash(f"Refreshed from {appl.name}: {run.detail}",
                  "success" if run.status == 'ok' else "danger")
        else:
            flash("Refresh is FortiWeb-only for now.", "warning")
    except Exception as exc:  # noqa: BLE001
        flash_error(exc, "Refresh failed", context="workspace.refresh")
    return redirect(url_for('workspace.appliance', appliance_id=appliance_id))


EP_CRLIST = '/api/v2.0/cmdb/server-policy/policy/http-content-routing-list'
EP_CRPOLICY = '/api/v2.0/cmdb/server-policy/http-content-routing-policy'
_SAVE_EPS = _SAVE_EPS | {EP_CRLIST, EP_CRPOLICY}
_CHILD_EPS = _CHILD_EPS | {EP_CRLIST}


# ───────────────────── Server-Policy row / bulk actions ──────────────────────
# Enable/Disable · Delete · Clone (same box) · Clone to another FortiWeb ·
# Migrate to another FortiWeb — for one policy (the row ⚙) or many (checkboxes).
# Preview is a synchronous dry-run (no writes); a real run spawns a background
# job (services.policy_ops → services.jobs) so the user gets progress + history +
# a bell notification, and every object write is audited via FortiWebOps.
def _parse_action(appliance_id):
    """Validate an action request. Returns ``(appl, action, policies, new_name,
    dest, opts, None)`` or ``(…, error_response)`` on a bad request.

    ``opts`` = the clone/migrate knobs from the dialog: ``vip_ip`` (explicit
    IPv4 for a SINGLE clone/migrate; every BULK run is forced to ``"auto"`` so
    the admin dummy-IP rules apply), ``copy_wpp`` (defaults to the admin
    setting) and ``wpp_new_name`` (copy the WPP under a new name)."""
    import ipaddress as _ip
    from ..services import clone_rules
    appl = visible_appliance_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    action = body.get('action', '')
    policies = [p for p in (body.get('policies') or []) if p]
    new_name = (body.get('new_name') or '').strip()
    dest_id = body.get('dest_id')
    _err = lambda msg, code=400: (appl, None, None, None, None, None,
                                  (jsonify(ok=False, error=msg), code))
    if action not in policy_ops.ACTIONS:
        return _err('unknown action')
    if appl.kind != 'fortiweb':
        return _err('FortiWeb-only')
    if not policies:
        return _err('no policies selected')
    dest = None
    if action in policy_ops._NEEDS_TARGET:
        if not dest_id:
            return _err('destination appliance required')
        dest = visible_appliance_or_404(int(dest_id))
        if dest.id == appl.id:
            return _err('pick a DIFFERENT destination')
        if dest.kind != 'fortiweb':
            return _err('destination must be a FortiWeb')
    if action in policy_ops._NEEDS_NAME and len(policies) == 1 and not new_name:
        return _err('a new name is required')
    opts = {}
    if action in policy_ops._CLONE_ACTIONS:
        cfg = clone_rules.config()
        copy_wpp = body.get('copy_wpp')
        opts['copy_wpp'] = cfg['copy_wpp_default'] if copy_wpp is None else bool(copy_wpp)
        opts['wpp_new_name'] = (body.get('wpp_new_name') or '').strip()
        # Bulk clones send a suffix instead of a name (one per source WPP).
        opts['wpp_suffix'] = (body.get('wpp_suffix') or '').strip()
        vip_ip = (body.get('vip_ip') or '').strip()
        if len(policies) > 1:
            vip_ip = 'auto'   # bulk ⇒ dummy IP per the admin rules, always
        elif vip_ip and vip_ip != 'auto':
            try:
                _ip.IPv4Address(vip_ip)
            except ValueError:
                return _err('VIP IP %r is not a valid IPv4 address' % vip_ip)
        opts['vip_ip'] = vip_ip
        # {source port: destination port}. Cross-box only: a same-box clone
        # shares the chassis, so re-binding there would move the copy to a
        # different network without the operator having asked for that.
        iface_map, bad = clean_iface_map(action, body.get('iface_map'))
        if bad is not None:
            return _err('interface name %r is not a valid port name' % bad)
        opts['iface_map'] = iface_map
        # The destination's NEW fields the operator chose to set (opt-in; the
        # default is to add nothing). Read from the request every time, like
        # the artifact acknowledgement, and re-validated by the engine.
        nf_values, nf_bad = clean_new_field_values(action, body.get('new_field_values'))
        if nf_bad is not None:
            return _err(nf_bad)
        if nf_values:
            opts['new_field_values'] = nf_values
        # The operator's acknowledgement that a file-backed object (XML schema,
        # DTD, WSDL, OpenAPI, gRPC IDL, Lua script) whose CONTENT SATOM cannot
        # obtain may be skipped. Read from the REQUEST every time, never cached
        # server-side: the checklist the browser is showing could be minutes old
        # and describe a different set of missing files than the one this apply
        # would skip. The engine re-derives the missing set itself and refuses
        # unless this is set, so a stale tick can only ever authorise less than
        # the operator saw — never more.
        opts['accept_missing_artifacts'] = bool(body.get('accept_missing_artifacts'))
        # ── knobs that were engine-only until now ────────────────────────────
        # These existed in `policy_ops` and were never parsed here, so nothing
        # a browser sent could reach them. An option the engine honours and the
        # HTTP layer drops is worse than an absent one: the service reads its
        # own default and the run looks like it obeyed.
        rec_rows = body.get('reconcile_rows')
        opts['reconcile_rows'] = True if rec_rows is None else bool(rec_rows)
        # "Only add what is missing": never write INTO an object the destination
        # already owns. DEFAULTS ON here — this is the operator-facing surface,
        # and the safe posture is the one a caller gets by saying nothing. The
        # engine's own default is OFF for the opposite reason: `policy_ops` has
        # library callers whose deliveries must keep completing. So the default
        # lives here, once, where an operator can see it and turn it off.
        add_only = body.get('additive_only')
        opts['additive_only'] = True if add_only is None else bool(add_only)
        opts['dst_wpp'] = (body.get('dst_wpp') or '').strip()
        opts['wpp_only_if_missing'] = bool(body.get('wpp_only_if_missing'))
        # Carrying certificate MATERIAL moves a PRIVATE KEY over the CLI. Off
        # unless asked, explicitly, on this request — never remembered.
        opts['copy_cert_material'] = bool(body.get('copy_cert_material'))
        # Reachability of the copied policy's real servers, after the write.
        opts['probe_backends'] = bool(body.get('probe_backends'))
        opts['probe_ssh'] = bool(body.get('probe_ssh'))
        # Concurrent READERS for a preview. The apply is sequential and never
        # reads this — policies share objects, so parallel applies produce
        # clock-dependent duplicate errors.
        try:
            opts['analyse_workers'] = int(body.get('analyse_workers') or 1)
        except (TypeError, ValueError):
            opts['analyse_workers'] = 1
        # "New, compare and decide": the operator's answer to the comparison.
        # BOTH lists are kept — an apply whose re-plan offers something that was
        # never shown is refused, and only `shown` can tell that from a decline.
        dec = body.get('wpp_decisions')
        if isinstance(dec, dict):
            opts['wpp_decisions'] = {
                'accepted': [str(k) for k in (dec.get('accepted') or []) if k],
                'shown': [str(k) for k in (dec.get('shown') or []) if k],
            }
    return appl, action, policies, new_name, dest, opts, None


@bp.route('/<int:appliance_id>/policy-action/preview', methods=['POST'])
@login_required
@require_permission('config_write')
def policy_action_preview(appliance_id):
    """Synchronous dry-run of an action across the selected policies — no device
    writes. For clone/migrate this reads the source (and validates the target)."""
    appl, action, policies, new_name, dest, opts, err = _parse_action(appliance_id)
    if err:
        return err
    try:
        results = policy_ops.preview(action, source_appl=appl, dest_appl=dest,
                                     policies=policies, new_name=new_name, opts=opts)
    except Exception as exc:  # noqa: BLE001
        return json_error(exc, 'Preview failed', context='workspace.policy_action_preview')
    return jsonify(ok=True, action=action, label=policy_ops.action_label(action),
                   dest=(dest.name if dest else ''), results=results)


@bp.route('/<int:appliance_id>/policy-action/wpp-compare', methods=['POST'])
@login_required
@require_permission('config_write')
def policy_action_wpp_compare(appliance_id):
    """PHASE ONE of "new, compare and decide" (read-only).

    Returns, per policy, every change this run would make INSIDE a Web
    Protection Profile the destination ALREADY HAS — the profile's own fields
    first, then each row. Nothing is pre-selected: this is the one profile
    policy that edits a live object, possibly one other policies share, so the
    default answer is no.

    The operator's reply comes back on the APPLY as
    ``opts["wpp_decisions"] = {"accepted": [key…], "shown": [key…]}``. Both
    lists, not just the accepted one: an apply whose re-plan offers something
    the operator was never shown is REFUSED rather than guessed at, and only
    ``shown`` can tell those two apart.
    """
    appl, action, policies, new_name, dest, opts, err = _parse_action(appliance_id)
    if err:
        return err
    if action not in policy_ops._CLONE_ACTIONS:
        return jsonify(ok=False,
                       error='compare applies to clone/migrate only'), 400
    try:
        data = policy_ops.wpp_compare(action, source_appl=appl, dest_appl=dest,
                                      policies=policies, new_name=new_name,
                                      opts=opts)
    except Exception as exc:  # noqa: BLE001
        return json_error(exc, 'Compare failed',
                          context='workspace.policy_action_wpp_compare')
    return jsonify(ok=True, action=action, dest=(dest.name if dest else ''),
                   policies=data)


@bp.route('/<int:appliance_id>/policy-action/checklist', methods=['POST'])
@login_required
@require_permission('config_write')
def policy_action_checklist(appliance_id):
    """Pre-flight checklist for clone/migrate (read-only): WPP present/identical
    at the destination, target-name and VIP-IP collisions, certificate
    carry-over, capacity — plus the dummy-IP / copy-WPP suggestions the dialog
    prefills from the admin defaults."""
    appl, action, policies, new_name, dest, opts, err = _parse_action(appliance_id)
    if err:
        return err
    if action not in policy_ops._CLONE_ACTIONS:
        return jsonify(ok=False, error='checklist applies to clone/migrate only'), 400
    try:
        data = policy_ops.preflight(action, source_appl=appl, dest_appl=dest,
                                    policies=policies, new_name=new_name, opts=opts)
    except Exception as exc:  # noqa: BLE001
        return json_error(exc, 'Checklist failed', context='workspace.policy_action_checklist')
    return jsonify(ok=True, action=action, dest=(dest.name if dest else ''), **data)


@bp.route('/clone-report/<job_id>')
@login_required
@require_permission('config_write')
def clone_report(job_id):
    """Reconciliation report for a clone/migrate job: per policy, what SHOULD
    have been created vs what WAS created (verified live) vs what FAILED. Reads
    the persisted job result — no device call. Owner or admin only."""
    from flask_login import current_user
    from ..services import jobs as jobsvc
    job = jobsvc.get_job(job_id)
    if not job:
        return render_template('workspace/clone_report.html', job=None), 404
    me = getattr(current_user, 'username', '') or ''
    can = getattr(current_user, 'can', None)
    if (job.get('by') or '') != me and not (can and can('user_manage')):
        return render_template('workspace/clone_report.html', job=None), 403
    result = job.get('result') or {}
    return render_template('workspace/clone_report.html', job=job, result=result,
                           policies=result.get('results') or [])


@bp.route('/<int:appliance_id>/policy-action', methods=['POST'])
@login_required
@require_permission('config_write')
def policy_action(appliance_id):
    """Apply an action for real. Spawns a background job (poll ``/jobs/<id>``)."""
    from flask import current_app
    from flask_login import current_user
    appl, action, policies, new_name, dest, opts, err = _parse_action(appliance_id)
    if err:
        return err
    try:
        job = policy_ops.start_policy_job(
            current_app._get_current_object(), action=action, source_appl=appl,
            dest_appl=dest, policies=policies, new_name=new_name,
            by=getattr(current_user, 'username', '') or 'system',
            user_id=getattr(current_user, 'id', None), opts=opts)
    except Exception as exc:  # noqa: BLE001
        return json_error(exc, 'Could not start the action', context='workspace.policy_action')
    return jsonify(ok=True, job_id=job['id'])


@bp.route('/<int:appliance_id>/policy/<path:name>')
@login_required
@require_permission('protection.view')
def policy_detail(appliance_id, name):
    appl = visible_appliance_or_404(appliance_id)
    data = {}
    cr_entries = []
    error = None
    cache_meta = {}
    # DB-first: the deep layer holds the FULL per-policy tree (vserver+vip-list,
    # pool+pserver-list, WPP, content-routing) — serve it with zero device calls.
    # A policy without a deep capture falls back to the live composite read; a
    # dead/locked device then falls back to the config-layer cache (top-level
    # payloads, no sub-tables) so the page is never blank.
    from ..services import read_layer
    if appl.kind == 'fortiweb':
        _d, _cr, _meta = read_layer.policy_full_cached(appl.id, name)
        if _d is not None and _meta.get('layer') == 'deep':
            data, cr_entries, cache_meta = _d, _cr, _meta
    if not data:
        try:
            client = FortiWebClient(appl)
            data = client.policy_full(name)
            # Content-routing bindings (a by-parent sub-table of the policy, scoped
            # ?mkey=<policy>) — fetched regardless of mode so the card is ready if
            # the operator switches Deployment Mode to HTTP Content Routing.
            cr_entries = client._safe_list(
                '%s?mkey=%s' % (EP_CRLIST, quote(name, safe='')))
            # Break each routing rule down to its back-end pool: the CR-list row
            # only names the routing policy; the pool lives on that
            # http-content-routing-policy object's server-pool field.
            for e in cr_entries:
                crp = e.get('content-routing-policy-name')
                if not crp:
                    continue
                hcr = client._safe_one(
                    '%s?mkey=%s' % (EP_CRPOLICY, quote(crp, safe=''))) or {}
                pool_name = hcr.get('server-pool') or ''
                e['pool'] = pool_name
                e['backends'] = (client._safe_list(
                    '%s?mkey=%s' % (EP_PSERVER, quote(pool_name, safe='')))
                    if pool_name else [])
            cache_meta = {"generated_at": None, "source": "live", "cached": False}
        except Exception as exc:
            error = str(exc)
            if appl.kind == 'fortiweb':
                _d, _cr, _meta = read_layer.policy_full_cached(appl.id, name)
                if _d is not None:
                    data, cr_entries, cache_meta = _d, _cr, _meta
                    error = ("%s — showing the last cached copy (%s)"
                             % (error, read_layer.freshness_label(_meta)))
    policy = data.get('policy') or {}
    pool = data.get('pool') or {}
    wpp_sel = policy.get('web-protection-profile') or ''
    # Dynamic admin-configured deep links (Splunk, Grafana, tickets…), rendered
    # with THIS policy's own context substituted for {tokens}. Pure DB read, no
    # device call; a link naming an empty field is dropped (policy_links).
    link_ctx = {
        'policy': policy.get('name') or name,
        'device': appl.name,
        'device_ip': appl.host,
        'vip': ', '.join(v.get('effective_ip') for v in (data.get('vips') or [])
                         if v.get('effective_ip')),
        'port': policy.get('https-service') or policy.get('service') or '',
        'pool': policy.get('server-pool') or '',
        'vserver': policy.get('vserver') or '',
        'wpp': wpp_sel,
    }
    # Permanent rule: every page that edits an object shows its "Not in GUI,
    # but in CLI" section — this page too, not only the object editor.
    from .objedit import _not_in_gui
    policy_sections, policy_nig = _not_in_gui(
        appl, EP_POLICY, policy, policy_form.build_policy_sections(policy))
    pool_groups, pool_nig = _not_in_gui(appl, EP_POOL, pool, build_groups('pool', pool))
    return render_template(
        'workspace/policy_detail.html',
        appliance=appl, policy_name=name, policy=policy,
        policy_on=is_on(policy.get('status')),
        deploy_mode=policy.get('deployment-mode') or '',
        vserver_name=policy.get('vserver') or '', vips=data.get('vips') or [],
        pool_name=policy.get('server-pool') or '', pool=pool, backends=data.get('backends') or [],
        wpp_name=wpp_sel,
        # GUI-faithful, ordered, conditional-visibility sections (the desktop form).
        policy_sections=policy_sections, policy_nig=policy_nig,
        pool_groups=pool_groups, pool_nig=pool_nig,
        cr_entries=cr_entries,
        policy_clean=_clean_policy(policy),
        cache_meta=cache_meta,
        cache_freshness=(read_layer.freshness_label(cache_meta)
                         if cache_meta.get('cached') else ''),
        create_fields=CREATE_FIELDS,
        eps={'policy': EP_POLICY, 'pool': EP_POOL, 'wpp': EP_WPP,
             'viplist': EP_VIPLIST, 'pserver': EP_PSERVER,
             'crlist': EP_CRLIST, 'crpolicy': EP_CRPOLICY},
        policy_links=policy_links.rendered_links(link_ctx),
        error=error,
    )


# Live backend-health mapping: healthCheckStatus enable=UP / disable=DOWN /
# anything else (N/A) = no health check. Same authoritative field the team's
# fortiweb_pool_health.py script keys on.
_HC_UP = {'enable', 'enabled', 'up', 'ok'}
_HC_DOWN = {'disable', 'disabled', 'down', 'dead'}


def _hc_state(v):
    v = str(v or '').strip().lower()
    if v in _HC_UP:
        return 'up'
    if v in _HC_DOWN:
        return 'down'
    return 'na'


@bp.route('/<int:appliance_id>/policy/<path:name>/health')
@login_required
@require_permission('protection.view')
def policy_health(appliance_id, name):
    """Live per-backend health for one policy (runtime policystatus.detail probe).

    OPT-IN from the topology card only — it is NOT part of the DB-first page
    render, so a license-locked / offline box never blocks the policy page. A
    device refusal is surfaced as ok=false with the reason."""
    appl = visible_appliance_or_404(appliance_id)
    if appl.kind != 'fortiweb':
        return jsonify(ok=False, error='FortiWeb-only', members=[]), 400
    try:
        rows, err = FortiWebClient(appl).policy_health(name)
    except Exception as exc:  # noqa: BLE001
        return json_error(exc, 'Health probe failed', context='workspace.policy_health')
    if err:
        return jsonify(ok=False, error=err, members=[])
    members = [{
        'pool': str(m.get('pool') or ''),
        'ip': str(m.get('ipDomainName') or m.get('ip') or ''),
        'port': str(m.get('port') or ''),
        'health': _hc_state(m.get('healthCheckStatus')),
        'raw': str(m.get('healthCheckStatus') or ''),
    } for m in (rows or []) if isinstance(m, dict)]
    return jsonify(ok=True, members=members)


@bp.route('/<int:appliance_id>/cmdb-options')
@login_required
@require_permission('protection.view')
def cmdb_options(appliance_id):
    """Lazy options for a reference <select> — names of configured objects in
    the given cmdb collection. Allow-listed to the endpoints our schema declares
    (so this can't be used to read arbitrary cmdb paths)."""
    appl = visible_appliance_or_404(appliance_id)
    endpoint = request.args.get('endpoint', '')
    if endpoint not in ALL_REF_ENDPOINTS:
        return jsonify(error='endpoint not allowed', names=[]), 400
    names, err, eid = [], '', None
    try:
        names = FortiWebClient(appl).cmdb_names(endpoint)
    except Exception as exc:
        err = str(exc)
        eid = log_exception(exc, context='workspace.cmdb_options')
    if names:
        return jsonify(names=names, source='live')
    # DB-first net: an offline / license-locked box answers with nothing — serve
    # the cached object names so the policy form's dropdowns stay usable.
    from ..services import read_layer
    cached = read_layer.cached_ref_names(appl.id, endpoint)
    if cached:
        return jsonify(names=cached, source='cache', error=err)
    return jsonify(names=[], source='live', error=err, error_id=eid)


@bp.route('/<int:appliance_id>/save', methods=['POST'])
@login_required
@require_permission('config_write')
def save(appliance_id):
    """Apply a minimal-diff change to one object. dry_run (default) previews the
    exact PUT body without touching the device; apply=true writes it through
    FortiWebOps (before/after snapshot + ChangeHistory + audit)."""
    appl = visible_appliance_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    endpoint = body.get('endpoint', '')
    mkey = body.get('mkey', '')
    fields = body.get('fields') or {}
    child_id = body.get('child_id')
    do_apply = bool(body.get('apply'))
    if endpoint not in _SAVE_EPS:
        return jsonify(ok=False, error='endpoint not allowed'), 400
    if not isinstance(fields, dict) or not fields:
        return jsonify(ok=False, error='no changes to save'), 400

    # child sub-table rows (VIP, back-end server) are keyed by &sub_mkey=<id>;
    # the id stays out of the body. Top-level objects key on ?mkey=<name>.
    ep = endpoint
    if endpoint in _CHILD_EPS and child_id not in (None, ''):
        ep = '%s%ssub_mkey=%s' % (endpoint, '&' if '?' in endpoint else '?', child_id)
    # Same pre-write reference check as the object editor: a value naming an
    # object the device does not have is refused HERE, with the field name,
    # instead of coming back as a mute -651 that also discards the good fields.
    from ..services import ref_validate
    problems, unverified = ref_validate.check(appl, fields)
    if problems:
        return jsonify(ok=False, error=ref_validate.message(problems),
                       invalid_refs=problems), 400

    # Same channel split as the object editor: a field CLI-only/hidden on this
    # build (its "Not in GUI, but in CLI" section) goes by the CLI writer, the
    # rest by REST. Child rows keep the REST path (they carry no section here).
    from .objedit import _channel_split, _cli_part, _cli_error
    split = None if endpoint in _CHILD_EPS else _channel_split(appl, endpoint, fields)
    cli_fields = dict((split or {}).get('cli') or {})
    payload = {'data': {k: v for k, v in fields.items() if k not in cli_fields}}
    try:
        if payload['data']:
            res = FortiWebOps(appl).update(ep, mkey, payload, dry_run=not do_apply)
        else:
            from ..services.fortiweb_ops import OpResult
            res = OpResult(ok=True, dry_run=not do_apply, request=None, error='')
    except Exception as exc:
        return json_error(exc, 'Save failed on the device', context='workspace.save')
    cli = _cli_part(appl, split, mkey, do_apply, res.ok) if cli_fields else None
    ok = res.ok and (cli is None or bool(cli.get('ok')))
    error = res.get('error', '') or (_cli_error(cli) if cli and not cli.get('ok') else '')
    # Lifecycle hook (WAF rule 1): re-binding a policy's Web Protection Profile
    # orphans the carve-outs authored against the OLD profile — flag them stale
    # (never silently delete; the Exceptions page shows the banner and the
    # operator migrates or removes each one).
    stale_marked = 0
    if do_apply and ok and endpoint == EP_POLICY and 'web-protection-profile' in fields:
        try:
            from ..services import wpp_exceptions as exc_store
            new_wpp = fields.get('web-protection-profile') or ''
            stale_marked = exc_store.mark_stale_for_policy(
                appl.id, mkey, new_wpp,
                reason='Server Policy "%s" was re-bound to WPP "%s" on %s.'
                       % (mkey, new_wpp or '?', appl.name))
        except Exception:  # noqa: BLE001 — the flag is advisory, never sink the save
            pass
    # The FortiWeb-layout view draws from the cache: re-read the policy just
    # written so the page shows the device's value, not the pre-save copy.
    cache_refreshed = False
    if do_apply and ok and endpoint == EP_POLICY and ep == endpoint:
        try:
            from ..services import write_through
            live = FortiWebClient(appl).get_server_policy(mkey)
            cache_refreshed = write_through.local_refresh(
                appl.id, 'server_policy', mkey, live) > 0
        except Exception as exc:  # noqa: BLE001 — the write itself succeeded
            log_exception(exc, context='workspace.save.cache')
    return jsonify(
        ok=ok, dry_run=res.get('dry_run'),
        request=res.get('request'), error=error, cli=cli,
        stale_carveouts=stale_marked, unverified_refs=unverified,
        cache_refreshed=cache_refreshed, cli_fields=sorted(cli_fields),
    )


@bp.route('/<int:appliance_id>/create-ref', methods=['POST'])
@login_required
@require_permission('config_write')
def create_ref(appliance_id):
    """Create-new for a reference field (mirrors the FortiWeb dropdown '+').
    Optionally clones an existing object's fields under a new name — used for
    spinning up a Web Protection Profile from one of the inline templates."""
    appl = visible_appliance_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    endpoint = body.get('endpoint', '')
    name = (body.get('name') or '').strip()
    clone_from = (body.get('clone_from') or '').strip()
    extra = body.get('fields') or {}
    do_apply = bool(body.get('apply'))
    if endpoint not in ALL_REF_ENDPOINTS:
        return jsonify(ok=False, error='endpoint not allowed'), 400
    if not name:
        return jsonify(ok=False, error='name required'), 400
    ep = endpoint.split('|')[0]                 # create in the primary collection
    client = FortiWebClient(appl)
    payload = {'name': name}
    if clone_from:
        src = client._safe_one('/api/v2.0/cmdb/%s?mkey=%s' % (ep, quote(clone_from, safe='')))
        for k, v in (src or {}).items():
            if k == 'name' or is_noise(k):
                continue
            payload[k] = v
    # Up-front fields the create modal collected (VIP IP/interface, Service port…),
    # restricted to the keys CREATE_FIELDS declares for this collection so the
    # form can't post arbitrary keys.
    allowed = {f['key'] for f in CREATE_FIELDS.get(ep, [])}
    if isinstance(extra, dict):
        for k, v in extra.items():
            if k in allowed and v not in (None, '', []):
                payload[k] = v
    # Required extras (a custom Service's port, a VIP's IP): reject with the
    # real reason instead of the device's opaque HTTP 500 (errcode -56
    # "Empty value isn't allowed."). A clone inherits them from its source.
    if not clone_from:
        missing = [f.get('label') or f['key'] for f in CREATE_FIELDS.get(ep, [])
                   if f.get('required') and not str(payload.get(f['key']) or '').strip()]
        if missing:
            return jsonify(ok=False, error='%s required for this object type'
                           % ' and '.join(missing)), 400
    res = FortiWebOps(appl).create('/api/v2.0/cmdb/' + ep, {'data': payload}, dry_run=not do_apply)
    return jsonify(ok=res.ok, dry_run=res.get('dry_run'),
                   request=res.get('request'), error=res.get('error', ''))


# ─────────────────────────── CREATE Server Policy ────────────────────────────
# Schema-driven create: the form renders the COMPLETE live-validated field set
# (policy 121 / pool 17 / vserver+VIP / pserver), grouped like the GUI. Build
# order on apply mirrors FortiWeb's dependency graph: vserver → vip-list →
# server-pool → pserver-list → policy (binds vserver + pool). Preview (dry_run)
# shows the exact POST bodies; apply=true writes each through audited create.
from ..services.fortiweb_field_schema import build_create_groups, create_skeleton_keys

_CREATE_EPS = {
    'policy':  EP_POLICY,
    'vserver': '/api/v2.0/cmdb/server-policy/vserver',
    'vip':     EP_VIPLIST,
    'pool':    EP_POOL,
    'pserver': EP_PSERVER,
}


# ── FortiWeb GUI layout (read-only) ─────────────────────────────────────────
# Server Policy drawn from a GUI template (services.gui_template): the list,
# Create New menu and dialogs FortiWeb itself shows, per firmware train. Reads
# the local cache only — never the device — and writes nothing.

def _gui_device(appl):
    from ..services import gui_template, read_layer, feature_visibility
    opmode = None
    try:
        rows, _ = read_layer.read_objects(appl.id, 'system_settings')
        if rows and isinstance(rows[0], dict):
            opmode = rows[0].get('opmode') or None
    except Exception as exc:  # noqa: BLE001 — a cold cache leaves opmode unknown
        log_exception(exc, context='workspace.gui.opmode')
    try:
        vis = feature_visibility.toggles_for(appl.id)
    except Exception as exc:  # noqa: BLE001
        log_exception(exc, context='workspace.gui.visibility')
        vis = {}
    return gui_template.device_context(opmode=opmode, visibility=vis,
                                       firmware=appl.firmware, model=appl.model)


def _int_or_zero(v) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _gui_subtables(appl, name, tpl, key, policy=None):
    """Rows of the dialog's inline sub-tables from the deep cache, and the
    objects their columns join against. A sub-table the deep capture does not
    walk (not in the dependency registry), or a policy without a deep capture,
    is None -- unknown, never drawn as empty. So is one the policy itself
    counts rows for (``sz_<subtable>``) while the cache holds none: a capture
    taken before the walk covered that sub-table, not an empty list."""
    from ..registry import dependencies
    from ..services import gui_template, read_layer
    got = read_layer.policy_subrows(appl.id, name) if name else None
    subrows = {}
    for b in tpl['dialogs'][key]['blocks']:
        for f in b['fields']:
            st = f.get('subtable')
            if f.get('kind') != 'table' or not st:
                continue
            walked = dependencies.dep_node_for_urn('cmdb/' + (f.get('endpoint') or '')) is not None
            rows = (got or {}).get(st, []) if (got is not None and walked) else None
            if rows == [] and _int_or_zero((policy or {}).get('sz_' + st)) > 0:
                rows = None
            subrows[st] = rows
    refs = {}
    for lg in gui_template.needed_refs(tpl, key):
        try:
            objs, _ = read_layer.read_objects(appl.id, lg)
        except Exception as exc:  # noqa: BLE001 — a cold cache leaves the join empty
            log_exception(exc, context='workspace.gui.refs')
            objs = []
        refs[lg] = {o.get('name'): o for o in objs or [] if isinstance(o, dict)}
    return subrows, refs


def _gui_template_or_404(appl):
    from flask import abort, flash as _flash, redirect as _redirect, url_for as _url_for
    from flask_babel import gettext as _
    from ..services import gui_store, gui_template
    if appl.kind != 'fortiweb':
        abort(404)
    tpl, match = gui_template.select('fortiweb', 'server-policy', gui_store.firmware_of(appl))
    if tpl is None:
        # The release ships no layout: a node that has not imported a knowledge
        # pack yet (fresh install, offline, knowledge.fetch_mode=off) has none.
        # The sidebar's Server Policy leaf opens this view, so a 404 here would
        # take Server Policy away; SATOM's own list is the fallback.
        _flash(_('No FortiWeb GUI layout has been imported on this node yet (it comes '
                 'with the knowledge packs). Showing the SATOM Server Policy list.'), 'info')
        abort(_redirect(_url_for('workspace.appliance', appliance_id=appl.id)))
    return tpl, match


@bp.route('/<int:appliance_id>/gui')
@login_required
@require_permission('protection.view')
def gui_list(appliance_id):
    from ..services import gui_template, read_layer
    appl = visible_appliance_or_404(appliance_id)
    tpl, match = _gui_template_or_404(appl)
    dev = _gui_device(appl)
    rows, meta = read_layer.read_policies(appl)
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    view = gui_template.list_view(tpl, rows, dev)
    labels = tpl['list'].get('value_labels', {})
    # VIP / Port: FortiWeb joins each row with its virtual server (VIP list and
    # the vserver's interface). Same join, from the deep cache. A vip-list entry
    # carries an interface only with use-interface-ip; otherwise the port is the
    # one of the VIP object it names (system vip) -- measured on fortiweb17.
    try:
        vip_rows, _ = read_layer.read_objects(appl.id, 'vip')
    except Exception as exc:  # noqa: BLE001 — a cold cache leaves Port empty
        log_exception(exc, context='workspace.gui.vip')
        vip_rows = []
    vip_itf = {o.get('name'): o.get('interface') or ''
               for o in vip_rows or [] if isinstance(o, dict)}
    joins = {}
    for r in rows:
        vips, ports = [], []
        try:
            data, _cr, _m = read_layer.policy_full_cached(appl.id, r.get('name'))
        except Exception:  # noqa: BLE001 — a bad row never breaks the list
            data = None
        for v in (data or {}).get('vips') or []:
            ip = v.get('effective_ip') or v.get('vip') or ''
            if ip and ip not in vips:
                vips.append(str(ip))
            itf = v.get('interface') or vip_itf.get(v.get('vip')) or ''
            if itf and itf not in ports:
                ports.append(str(itf))
        joins[r.get('name')] = {'vip': vips, 'port': ports, 'deep': data is not None}
    return render_template('workspace/gui_list.html', appliance=appl, tpl=tpl, match=match,
                           dev=dev, view=view, labels=labels, cache_meta=meta, joins=joins,
                           protocol_cell=gui_template.protocol_cell,
                           status_running=gui_template.status_running)


@bp.route('/<int:appliance_id>/gui/policy/<path:name>')
@login_required
@require_permission('protection.view')
def gui_policy(appliance_id, name):
    from flask import abort
    from ..services import gui_template, objform, read_layer
    appl = visible_appliance_or_404(appliance_id)
    tpl, match = _gui_template_or_404(appl)
    dev = _gui_device(appl)
    rows, _ = read_layer.read_objects(appl.id, 'server_policy')
    row = next((r for r in rows or [] if isinstance(r, dict) and r.get('name') == name), None)
    if row is None:
        abort(404)
    main = tpl['list']['edit_dialog_by_protocol'].get(row.get('protocol') or 'HTTP')
    key = request.args.get('dialog') or main
    if key not in tpl['dialogs']:
        abort(404)
    row_dialogs = gui_template.row_dialogs(tpl, main)
    writer = current_user.can('config_write')
    row_ctx = None
    is_new_row = False
    if key in row_dialogs:
        # a sub-table row (?sub=<id>) in the dialog that row opens in FortiWeb,
        # or a new row (?new=1) filled with the GUI's own defaults
        subrows, _refs = _gui_subtables(appl, name, tpl, main, row)
        st = row_dialogs[key]
        coll = _gui_subtable_endpoint(tpl, main, st)
        if request.args.get('new'):
            if subrows.get(st) is None or not writer:
                abort(404)      # a sub-table SATOM cannot read is not written blind
            row = dict(tpl['dialogs'][key].get('new_defaults') or {})
            is_new_row = True
        else:
            sub = request.args.get('sub')
            row = next((r for r in subrows.get(st) or []
                        if sub is not None and str(r.get('id')) == sub), None)
            if row is None:
                abort(404)
        _subrows, refs = _gui_subtables(appl, name, tpl, key)
        writable_row = writer and bool(coll) and objform.is_known_collection(coll)
        view = gui_template.dialog_view(tpl, key, row, dev, refs=refs, live=writable_row)
        row_ctx = {'subtable': st, 'collection': coll or '', 'writable': writable_row,
                   'sub_id': '' if is_new_row else str(row.get('id', '')), 'new': is_new_row}
    # otherwise only the row's own dialog and the sub-dialogs it links to
    elif key == main or key.startswith((main or '') + '-'):
        subrows, refs = _gui_subtables(appl, name, tpl, key, row)
        view = gui_template.dialog_view(tpl, key, row, dev, subrows=subrows, refs=refs,
                                        live=writer)
    else:
        abort(404)
    # The policy's own dialog and its sub-dialogs (Advanced SSL…) edit the
    # policy object itself: Save goes through workspace.save (REST / CLI split
    # by the build's channels). A sub-table row dialog saves the row through
    # gui_save_row (the object editor's row save: same split, inside the
    # parent policy) when SATOM's registry knows the sub-table.
    can_edit = (row_ctx['writable'] if row_ctx else writer)
    # sub-tables whose rows this page can create (Create New in their toolbar)
    writable_subtables = sorted(
        st for st in row_dialogs.values()
        if writer and st and objform.is_known_collection(_gui_subtable_endpoint(tpl, main, st)
                                                         or '-'))
    # Permanent rule: the fields this policy has that the FortiWeb GUI does not
    # show are listed under the main dialog, with their write channel, and are
    # edited there like every other field.
    nig = nig_edit = None
    if key == main:
        if can_edit:
            from .objedit import _not_in_gui
            _groups, nig_edit = _not_in_gui(appl, EP_POLICY, row, [])
        if nig_edit is None:
            from ..services import not_in_gui
            nig = not_in_gui.for_view(appl, 'server-policy/policy', row)
    return render_template('workspace/gui_dialog.html', appliance=appl, tpl=tpl, match=match,
                           dev=dev, view=view, name=name, main=main, is_new=False,
                           not_in_gui=nig, nig_row=row, nig_edit=nig_edit,
                           can_edit=can_edit, save_ep=EP_POLICY, row_ctx=row_ctx,
                           writable_subtables=writable_subtables)


def _gui_subtable_endpoint(tpl, dialog, subtable):
    """The REST collection of one inline sub-table of a dialog (the template
    names it: ``server-policy/policy/http-content-routing-list``)."""
    for b in tpl['dialogs'][dialog]['blocks']:
        for f in b['fields']:
            if f.get('kind') == 'table' and f.get('subtable') == subtable:
                return f.get('endpoint') or ''
    return ''


@bp.route('/<int:appliance_id>/gui/policy/<path:name>/row', methods=['POST'])
@login_required
@require_permission('config_write')
def gui_save_row(appliance_id, name):
    """Create / update one sub-table row of a policy from its FortiWeb-layout
    dialog. The write is the object editor's row save (``objedit.save_row_for``:
    reference check, build gate, REST / CLI split inside the parent policy);
    after an applied write the sub-table is re-read from the device into the
    SATOM cache so the page shows the device's rows."""
    from ..services import gui_template, objform, read_layer, write_through
    from .objedit import save_row_for
    appl = visible_appliance_or_404(appliance_id)
    tpl, _match = _gui_template_or_404(appl)
    body = request.get_json(silent=True) or {}
    st = str(body.get('subtable') or '')
    rows, _ = read_layer.read_objects(appl.id, 'server_policy')
    pol = next((r for r in rows or [] if isinstance(r, dict) and r.get('name') == name), None)
    if pol is None:
        return jsonify(ok=False, error='policy not in the SATOM cache'), 404
    main = tpl['list']['edit_dialog_by_protocol'].get(pol.get('protocol') or 'HTTP')
    if st not in gui_template.row_dialogs(tpl, main).values():
        return jsonify(ok=False, error='not a sub-table of this policy'), 400
    coll = _gui_subtable_endpoint(tpl, main, st)
    do_apply = bool(body.get('apply'))
    sub_id = body.get('sub_id')
    resp = save_row_for(appl, {'collection': coll, 'parent': name,
                               'sub_id': None if sub_id in (None, '') else str(sub_id),
                               'fields': body.get('fields') or {}, 'apply': do_apply})
    resp, code = (resp if isinstance(resp, tuple) else (resp, 200))
    data = resp.get_json() or {}
    data['cache_refreshed'] = False
    if do_apply and data.get('ok'):
        try:
            client = FortiWebClient(appl)
            live = client.get(objform.scoped_path(coll, name))
            got = client._results_list(live.json()) if live.status_code == 200 else None
            if isinstance(got, list):
                n = write_through.local_subrows(appl.id, 'server_policy', name, st, got)
                data['cache_refreshed'] = n is not None
        except Exception as exc:  # noqa: BLE001 — the write itself succeeded
            log_exception(exc, context='workspace.gui_save_row.cache')
    return jsonify(**data), code


@bp.route('/<int:appliance_id>/gui/new/<dialog>')
@login_required
@require_permission('protection.view')
def gui_new(appliance_id, dialog):
    """The Create New form as FortiWeb lays it out, filled with its own defaults
    (a preview: nothing is submitted from this page)."""
    from flask import abort
    from ..services import gui_template
    appl = visible_appliance_or_404(appliance_id)
    tpl, match = _gui_template_or_404(appl)
    if dialog not in tpl['list']['edit_dialog_by_protocol'].values():
        abort(404)
    dev = _gui_device(appl)
    row = dict(tpl['dialogs'][dialog].get('new_defaults') or {})
    # a new policy's sub-tables start empty in FortiWeb too
    subrows = {st: [] for st in gui_template.row_dialogs(tpl, dialog).values() if st}
    can_edit = current_user.can('config_write')
    view = gui_template.dialog_view(tpl, dialog, row, dev, subrows=subrows,
                                    live=can_edit, new=can_edit)
    return render_template('workspace/gui_dialog.html', appliance=appl, tpl=tpl, match=match,
                           dev=dev, view=view, name=None, main=dialog, is_new=True,
                           can_edit=can_edit, save_ep=EP_POLICY, row_ctx=None)


# ── FortiWeb GUI layout: every other page (generic templates) ───────────────
# One route set for every page the knowledge feed brought a measured layout for
# (services.gui_pages): the grid of each tab, the dialog a row opens (variant
# dialogs by row, e.g. an FTP pool), its inline tables and their row dialogs,
# and Create New. Reads the SATOM cache; an object's sub-table rows the cache
# does not hold are read from the device as the object editor does. Writes go
# through the object editor's endpoints (save-object / create-object /
# save-row: reference check, build gate, REST / CLI split).

def _fwgui_tpl(appl, page):
    from flask import abort, flash as _flash, redirect as _redirect, url_for as _url_for
    from flask_babel import gettext as _
    from ..services import gui_pages, gui_store
    if appl.kind != 'fortiweb':
        abort(404)
    if page in gui_pages.SPECIAL:
        abort(_redirect(_url_for(gui_pages.SPECIAL[page], appliance_id=appl.id)))
    tpl, match = gui_pages.template(page, gui_store.firmware_of(appl))
    if tpl is None:
        _flash(_('No FortiWeb GUI layout for this page has been imported on this node '
                 '(layouts come with the knowledge packs).'), 'info')
        abort(_redirect(_url_for('workspace.fwgui_index', appliance_id=appl.id)))
    return tpl, match


def _fwgui_subrows(appl, tpl, key, name, obj_row):
    """{sub-table: rows | None} of a dialog's inline tables, read as the object
    editor reads them: the device first (a row saved here shows at once), the
    SATOM cache (deep capture) when the device answers nothing. None = unknown
    (device unreachable and nothing cached): drawn as such, never as empty."""
    from ..services import objform
    from .objedit import _cached_rows, _read_rows
    out = {}
    client = None
    for b in tpl['dialogs'][key]['blocks']:
        for f in b['fields']:
            st, coll = f.get('subtable'), f.get('endpoint')
            if f.get('kind') != 'table' or not st:
                continue
            if not coll:
                out[st] = None
                continue
            if not name:
                # a settings form's table lists a collection of its own
                # (SNMP communities): cache, else the device
                from ..services import gui_pages
                rows, _m = gui_pages.rows(appl.id, coll)
                if not rows:
                    try:
                        client = client or FortiWebClient(appl)
                        rows = client._safe_list(objform.rest_path(coll)) or []
                    except Exception as exc:  # noqa: BLE001
                        log_exception(exc, context='workspace.fwgui.formrows')
                        rows = None
                out[st] = rows
                continue
            parent = coll.rsplit('/', 1)[0]
            try:
                client = client or FortiWebClient(appl)
                rows = _read_rows(client, coll, name)
            except Exception as exc:  # noqa: BLE001 — unreachable: the cache decides
                log_exception(exc, context='workspace.fwgui.subrows')
                rows = None
            if not rows:
                cached = _cached_rows(appl.id, parent, name, st)
                rows = cached or ([] if rows == [] else None)
            if rows == [] and _int_or_zero((obj_row or {}).get('sz_' + st)) > 0:
                rows = None
            out[st] = rows
    return out


@bp.route('/<int:appliance_id>/fwgui')
@login_required
@require_permission('protection.view')
def fwgui_index(appliance_id):
    """FortiWeb's menu, every page SATOM has a measured layout for."""
    from flask import abort
    from ..services import gui_pages
    appl = visible_appliance_or_404(appliance_id)
    if appl.kind != 'fortiweb':
        abort(404)
    nav = gui_pages.nav_for(appl)
    return render_template('workspace/fwgui_index.html', appliance=appl, nav=nav)


@bp.route('/<int:appliance_id>/fwgui/<page>')
@login_required
@require_permission('protection.view')
def fwgui_list(appliance_id, page):
    from ..services import gui_pages
    appl = visible_appliance_or_404(appliance_id)
    tpl, match = _fwgui_tpl(appl, page)
    dev = _gui_device(appl)
    vi, view = gui_pages.view_of(tpl, request.args.get('v'))
    tabs = [{'i': i, 'label': gui_pages.tab_label(tpl, v, i)}
            for i, v in enumerate(gui_pages.views(tpl))] if len(gui_pages.views(tpl)) > 1 else []
    if view.get('form'):
        return _fwgui_form(appl, page, tpl, match, dev, vi, view, tabs)
    rows, meta = gui_pages.rows(appl.id, view.get('endpoint'))
    return render_template('workspace/fwgui_list.html', appliance=appl, tpl=tpl, match=match,
                           dev=dev, page=page, vi=vi, view=view, rows=rows, cache_meta=meta,
                           tabs=tabs, cell=gui_pages.cell, labels=gui_pages.value_labels(tpl),
                           dialog_for=gui_pages.dialog_for,
                           can_edit=current_user.can('config_write'))


def _fwgui_form(appl, page, tpl, match, dev, vi, view, tabs):
    """A settings page (no grid): the form over its ONE object, from the SATOM
    cache, else read from the device; Save is a mkey-less update."""
    from ..services import gui_bound, gui_pages, gui_template, objform
    coll = view.get('endpoint') or ''
    key = view['form']
    api = gui_bound.is_api(coll)
    if api:
        # a form the GUI writes through its own API (log settings, admin
        # settings): never cached, read live from the device
        obj = gui_bound.read(appl, coll)
    else:
        rows, _meta = gui_pages.rows(appl.id, coll)
        obj = rows[0] if rows else None
    if obj is None and coll and not api:
        from .objedit import _read_object
        try:
            obj = _read_object(FortiWebClient(appl), coll, '', singleton=True) or None
        except Exception as exc:  # noqa: BLE001 — unreachable: drawn empty, said so
            log_exception(exc, context='workspace.fwgui.form')
    can_edit = current_user.can('config_write') and obj is not None \
        and (api or objform.is_known_collection(coll))
    subrows = _fwgui_subrows(appl, tpl, key, None, obj)
    tpl, row, groups = gui_bound.prepare(tpl, key, obj or {}, appl)
    dview = gui_template.dialog_view(tpl, key, row, dev, subrows=subrows, live=can_edit)
    nig = nig_edit = None
    if obj is not None and not api:
        if can_edit:
            from .objedit import _not_in_gui
            _groups, nig_edit = _not_in_gui(appl, coll, obj, [])
        if nig_edit is None:
            from ..services import not_in_gui
            nig = not_in_gui.for_view(appl, coll, obj)
    gp = {'page': page, 'v': vi, 'collection': coll, 'name': '', 'mode': 'object',
          'form': True, 'tabs': tabs, 'missing': obj is None, 'api': api,
          'method': (tpl['dialogs'][key].get('write') or {}).get('method') or 'PUT',
          'body': (tpl['dialogs'][key].get('write') or {}).get('body') or 'data',
          'bound': groups}
    return render_template('workspace/gui_dialog.html', appliance=appl, tpl=tpl, match=match,
                           dev=dev, view=dview, name='', main=key, is_new=False,
                           not_in_gui=nig, nig_row=obj or {}, nig_edit=nig_edit,
                           can_edit=can_edit, save_ep=coll, row_ctx=None,
                           writable_subtables=[], gp=gp)


@bp.route('/<int:appliance_id>/fwgui/<page>/o/<path:name>')
@login_required
@require_permission('protection.view')
def fwgui_object(appliance_id, page, name):
    """One object in the dialog FortiWeb opens for it; ``?d=`` a sub-dialog,
    or a sub-table row dialog with ``?sub=<id>`` / ``?new=1``."""
    from flask import abort
    from ..services import gui_pages, gui_template, objform
    appl = visible_appliance_or_404(appliance_id)
    tpl, match = _fwgui_tpl(appl, page)
    dev = _gui_device(appl)
    vi, view = gui_pages.view_of(tpl, request.args.get('v'))
    coll = view.get('endpoint') or ''
    rows, _meta = gui_pages.rows(appl.id, coll)
    obj = next((r for r in rows if str(r.get('name', r.get('id', ''))) == name), None)
    if obj is None:
        from .objedit import _cached_object
        obj, _row = _cached_object(appl.id, coll, name)
    if obj is None:
        abort(404)
    main = gui_pages.dialog_for(view, obj)
    if not main or main not in tpl['dialogs']:
        abort(404)
    key = request.args.get('d') or main
    if key not in tpl['dialogs']:
        abort(404)
    writer = current_user.can('config_write')
    row_dialogs = gui_template.row_dialogs(tpl, main)
    row_ctx = None
    groups = {}
    if key in row_dialogs:
        st = row_dialogs[key]
        sub_coll = gui_pages.table_endpoint(tpl, main, st)
        subrows = _fwgui_subrows(appl, tpl, main, name, obj)
        if request.args.get('new'):
            if subrows.get(st) is None or not writer:
                abort(404)      # a sub-table SATOM cannot read is not written blind
            row = dict(tpl['dialogs'][key].get('new_defaults') or {})
            is_new_row = True
        else:
            sub = request.args.get('sub')
            row = next((r for r in subrows.get(st) or []
                        if sub is not None and str(r.get('id')) == sub), None)
            if row is None:
                abort(404)
            is_new_row = False
        writable = writer and bool(sub_coll) and objform.is_known_collection(sub_coll)
        dview = gui_template.dialog_view(tpl, key, row, dev, live=writable)
        row_ctx = {'subtable': st, 'collection': sub_coll, 'writable': writable,
                   'sub_id': '' if is_new_row else str(row.get('id', '')), 'new': is_new_row}
        can_edit = writable
    elif key == main:
        from ..services import gui_bound
        subrows = _fwgui_subrows(appl, tpl, key, name, obj)
        can_edit = writer and objform.is_known_collection(coll)
        tpl, prow, groups = gui_bound.prepare(tpl, key, obj, appl)
        dview = gui_template.dialog_view(tpl, key, prow, dev, subrows=subrows, live=can_edit)
    else:
        abort(404)
    writable_subtables = sorted(
        st for st in row_dialogs.values()
        if writer and st and objform.is_known_collection(
            gui_pages.table_endpoint(tpl, main, st) or '-'))
    nig = nig_edit = None
    if key == main:
        if can_edit:
            from .objedit import _not_in_gui
            _groups, nig_edit = _not_in_gui(appl, coll, obj, [])
        if nig_edit is None:
            from ..services import not_in_gui
            nig = not_in_gui.for_view(appl, coll, obj)
    gp = {'page': page, 'v': vi, 'collection': coll, 'name': name,
          'mode': 'row' if row_ctx else 'object', 'bound': groups if key == main else {}}
    return render_template('workspace/gui_dialog.html', appliance=appl, tpl=tpl, match=match,
                           dev=dev, view=dview, name=name, main=main, is_new=False,
                           not_in_gui=nig, nig_row=obj, nig_edit=nig_edit,
                           can_edit=can_edit, save_ep=coll, row_ctx=row_ctx,
                           writable_subtables=writable_subtables, gp=gp)


@bp.route('/<int:appliance_id>/fwgui/<page>/new/<dialog>')
@login_required
@require_permission('protection.view')
def fwgui_new(appliance_id, page, dialog):
    """Create New as FortiWeb lays it out, filled with its own defaults; Save
    creates the object through the object editor's create-object."""
    from flask import abort
    from ..services import gui_pages, gui_template, objform
    appl = visible_appliance_or_404(appliance_id)
    tpl, match = _fwgui_tpl(appl, page)
    if dialog not in tpl['dialogs'] or dialog in (tpl.get('subtable_dialogs') or ()):
        abort(404)
    vi, view = gui_pages.view_for_dialog(tpl, dialog)
    coll = view.get('endpoint') or ''
    dev = _gui_device(appl)
    row = dict(tpl['dialogs'][dialog].get('new_defaults') or {})
    subrows = {st: [] for st in gui_template.row_dialogs(tpl, dialog).values() if st}
    can_edit = current_user.can('config_write') and objform.is_known_collection(coll)
    from ..services import gui_bound
    tpl, row, groups = gui_bound.prepare(tpl, dialog, row, appl, read_device=False)
    dview = gui_template.dialog_view(tpl, dialog, row, dev, subrows=subrows,
                                     live=can_edit, new=can_edit)
    gp = {'page': page, 'v': vi, 'collection': coll, 'name': None, 'mode': 'new-object',
          'bound': groups}
    return render_template('workspace/gui_dialog.html', appliance=appl, tpl=tpl, match=match,
                           dev=dev, view=dview, name=None, main=dialog, is_new=True,
                           can_edit=can_edit, save_ep=coll, row_ctx=None, gp=gp)

@bp.route('/<int:appliance_id>/fwgui-save-api', methods=['POST'])
@login_required
@require_permission('config_write')
def fwgui_save_api(appliance_id):
    """Save a form FortiWeb's GUI writes through its own API (``api:<path>``:
    log settings, admin settings): read the current object, set the changed
    key paths (types kept), send it back with the GUI's own method. Dry run
    first (the exact request), then apply; the write is snapshotted and
    audited by FortiWebOps like every other write."""
    from ..services import gui_bound
    from ..services.fortiweb_ops import FortiWebOps
    appl = visible_appliance_or_404(appliance_id)
    if appl.kind != 'fortiweb':
        return jsonify(ok=False, error='FortiWeb only'), 400
    body = request.get_json(silent=True) or {}
    ep = body.get('endpoint') or ''
    method = (body.get('method') or 'PUT').upper()
    shape = body.get('body') or 'data'
    fields = body.get('fields') or {}
    do_apply = bool(body.get('apply'))
    if not gui_bound.safe_api(ep) or method not in ('PUT', 'POST') or shape not in gui_bound.BODIES:
        return jsonify(ok=False, error='not a GUI API endpoint'), 400
    if not isinstance(fields, dict) or not fields:
        return jsonify(ok=False, error='no changes to save'), 400
    current = gui_bound.read(appl, ep)
    if current is None:
        return jsonify(ok=False, error='the device did not answer for %s: nothing was sent' % ep), 409
    new = gui_bound.merged(current, fields)
    diff = gui_bound.changes(current, new)
    path = gui_bound.rest_path(ep)
    ops = FortiWebOps(appl)
    data = gui_bound.body_of(new, shape)
    if method == 'POST':
        res = ops.create(path, data, dry_run=not do_apply)
    else:
        res = ops.update(path, None, data, dry_run=not do_apply)
    after = None
    if do_apply and res.ok:
        after = gui_bound.read(appl, ep)
    # what the device stored differently from what was sent (re-read)
    drift = None if after is None else gui_bound.changes(new, after)
    if drift:
        # the device can answer a read before it has committed the write:
        # one more read before calling it a difference
        import time as _time
        _time.sleep(1.0)
        after = gui_bound.read(appl, ep)
        drift = None if after is None else gui_bound.changes(new, after)
    return jsonify(ok=res.ok, dry_run=res.get('dry_run'), request=res.get('request'),
                   diff=diff, error=res.get('error', ''),
                   verified=None if drift is None else not drift, drift=drift)


@bp.route('/<int:appliance_id>/new-policy')
@login_required
@require_permission('protection.view')
def new_policy(appliance_id):
    appl = visible_appliance_or_404(appliance_id)
    return render_template(
        'workspace/policy_new.html',
        appliance=appl,
        policy_groups=_filter_groups(build_create_groups('policy'), _HOIST_KEYS),
        pool_groups=build_create_groups('pool'),
        vip_fields=[f for g in build_create_groups('vip') for f in g['fields']],
        pserver_keys=[k for k in create_skeleton_keys('pserver') if k != 'name'],
        wpp_field=descriptor('policy', 'web-protection-profile', '', {}),
        eps=_CREATE_EPS,
        # Binding a policy to an AppID is an AppIDs-page (user_manage) action;
        # the picker is offered only to users who could do it there.
        appid_catalog=(appids_svc.catalog() if current_user.can('user_manage')
                       else []),
    )


def _clean_create_fields(fields):
    """Drop blanks and noise from a submitted create object."""
    out = {}
    for k, v in (fields or {}).items():
        if k == '' or is_noise(k):
            continue
        if v in (None, '', []):
            continue
        out[k] = v
    return out


@bp.route('/<int:appliance_id>/create-policy', methods=['POST'])
@login_required
@require_permission('config_write')
def create_policy(appliance_id):
    """Create a Server Policy and its objects in dependency order. dry_run
    (default) returns the exact POST bodies without touching the device."""
    appl = visible_appliance_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    do_apply = bool(body.get('apply'))
    ops = FortiWebOps(appl)

    policy = dict(body.get('policy') or {})
    pname = (policy.get('name') or '').strip()
    if not pname:
        return jsonify(ok=False, error='Policy name is required'), 400
    app_id_pk = None
    if str(body.get('app_id_pk') or '').strip():
        if not current_user.can('user_manage'):
            return jsonify(ok=False, error='assigning an AppID requires the '
                                           'user_manage permission'), 403
        try:
            app_id_pk = int(body.get('app_id_pk'))
        except (TypeError, ValueError):
            return jsonify(ok=False, error='invalid AppID'), 400
        if appids_svc.get(app_id_pk) is None:
            return jsonify(ok=False, error='no such AppID'), 400
    vserver_name = (body.get('vserver_name') or '').strip()
    pool_name = (body.get('pool_name') or '').strip()
    vips = body.get('vips') or []
    pool = dict(body.get('pool') or {})
    pservers = body.get('pservers') or []

    steps = []   # ordered (label, endpoint, payload, child_of)

    if vserver_name:
        steps.append(('Virtual Server', _CREATE_EPS['vserver'], {'name': vserver_name}, None))
        for i, v in enumerate(vips):
            vf = _clean_create_fields(v)
            if vf:
                steps.append(('VIP %d' % (i + 1), _CREATE_EPS['vip'], vf, vserver_name))
        policy['vserver'] = vserver_name
    if pool_name:
        pf = _clean_create_fields(pool)
        pf['name'] = pool_name
        steps.append(('Server Pool', _CREATE_EPS['pool'], pf, None))
        for i, ps in enumerate(pservers):
            pf2 = _clean_create_fields(ps)
            if pf2:
                steps.append(('Pool member %d' % (i + 1), _CREATE_EPS['pserver'], pf2, pool_name))
        policy['server-pool'] = pool_name
    steps.append(('Server Policy', _CREATE_EPS['policy'], _clean_create_fields(policy) | {'name': pname}, None))

    results = []
    for label, ep, payload, child_of in steps:
        full_ep = ep
        if ep in _CHILD_EPS and child_of:
            full_ep = '%s%smkey=%s' % (ep, '&' if '?' in ep else '?', quote(child_of, safe=''))
        if not do_apply:
            results.append({'label': label, 'endpoint': full_ep,
                            'body': {'data': payload}, 'dry_run': True})
            continue
        res = ops.create(full_ep, {'data': payload}, dry_run=False)
        results.append({'label': label, 'endpoint': full_ep, 'ok': res.ok,
                        'error': res.get('error', ''), 'request': res.get('request')})
        if not res.ok:
            return jsonify(ok=False, applied=results,
                           error='%s failed: %s' % (label, res.get('error', ''))), 200
    appid = ''
    if do_apply and app_id_pk is not None:
        row = appids_svc.assign(app_id_pk=app_id_pk, appliance_id=appl.id,
                                server_policy=pname,
                                by=getattr(current_user, 'username', '') or '')
        appid = row.app.app_id if row.app is not None else ''
        log_action('appid.assign', target=pname,
                   extra={'app_id_pk': app_id_pk, 'appliance_id': appl.id})
    # The FortiWeb-layout view reads the cache: cache the new policy as the
    # device returns it so its page opens right after Create New.
    cache_refreshed = False
    if do_apply:
        try:
            from ..services import write_through
            live = FortiWebClient(appl).get_server_policy(pname)
            cache_refreshed = write_through.local_insert(appl.id, 'server_policy', pname, live)
        except Exception as exc:  # noqa: BLE001 — the write itself succeeded
            log_exception(exc, context='workspace.create_policy.cache')
    return jsonify(ok=True, dry_run=not do_apply, steps=results,
                   app_id=appid, cache_refreshed=cache_refreshed)
