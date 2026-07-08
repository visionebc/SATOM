from urllib.parse import quote

from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required
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
        elif appl.kind == 'fortiadc':
            client = client_for(appl)
            raw = client.list_virtual_servers()
            policies = raw.get('payload', [])
    except Exception as exc:
        error = str(exc)
    from ..services import read_layer as _rl
    # Filter facets (VIP IP / backend server IP / pool / cert type) + the list of
    # OTHER FortiWebs (clone-to / migrate-to targets). Both are DB-first — the
    # facets read the deep cache, the target list is pure config. Best-effort so a
    # cold cache never breaks the page (backend/VIP filters just show nothing).
    facets, other_appliances = {}, []
    if appl.kind == 'fortiweb':
        names = [(p.get('name') if isinstance(p, dict) else getattr(p, 'name', ''))
                 for p in (policies or [])]
        names = [n for n in names if n]
        try:
            facets = _rl.policy_filter_facets(appl.id, names)
        except Exception as exc:  # noqa: BLE001
            log_exception(exc, context='workspace.appliance.facets')
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
                           clone_rules_summary=clone_rules_summary,
                           cache_freshness=_rl.freshness_label(meta) if appl.kind == 'fortiweb' else '')


@bp.route('/<int:appliance_id>/refresh', methods=['POST'])
@login_required
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
        vip_ip = (body.get('vip_ip') or '').strip()
        if len(policies) > 1:
            vip_ip = 'auto'   # bulk ⇒ dummy IP per the admin rules, always
        elif vip_ip and vip_ip != 'auto':
            try:
                _ip.IPv4Address(vip_ip)
            except ValueError:
                return _err('VIP IP %r is not a valid IPv4 address' % vip_ip)
        opts['vip_ip'] = vip_ip
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
    return render_template(
        'workspace/policy_detail.html',
        appliance=appl, policy_name=name, policy=policy,
        policy_on=is_on(policy.get('status')),
        deploy_mode=policy.get('deployment-mode') or '',
        vserver_name=policy.get('vserver') or '', vips=data.get('vips') or [],
        pool_name=policy.get('server-pool') or '', pool=pool, backends=data.get('backends') or [],
        wpp_name=wpp_sel,
        # GUI-faithful, ordered, conditional-visibility sections (the desktop form).
        policy_sections=policy_form.build_policy_sections(policy),
        pool_groups=build_groups('pool', pool),
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
    payload = {'data': dict(fields)}   # FortiWeb cmdb writes are {"data": {...}}

    try:
        res = FortiWebOps(appl).update(ep, mkey, payload, dry_run=not do_apply)
    except Exception as exc:
        return json_error(exc, 'Save failed on the device', context='workspace.save')
    # Lifecycle hook (WAF rule 1): re-binding a policy's Web Protection Profile
    # orphans the carve-outs authored against the OLD profile — flag them stale
    # (never silently delete; the Exceptions page shows the banner and the
    # operator migrates or removes each one).
    stale_marked = 0
    if do_apply and res.ok and endpoint == EP_POLICY and 'web-protection-profile' in fields:
        try:
            from ..services import wpp_exceptions as exc_store
            new_wpp = fields.get('web-protection-profile') or ''
            stale_marked = exc_store.mark_stale_for_policy(
                appl.id, mkey, new_wpp,
                reason='Server Policy "%s" was re-bound to WPP "%s" on %s.'
                       % (mkey, new_wpp or '?', appl.name))
        except Exception:  # noqa: BLE001 — the flag is advisory, never sink the save
            pass
    return jsonify(
        ok=res.ok, dry_run=res.get('dry_run'),
        request=res.get('request'), error=res.get('error', ''),
        stale_carveouts=stale_marked,
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


@bp.route('/<int:appliance_id>/browse/<path:endpoint_path>')
@login_required
def browse(appliance_id, endpoint_path):
    appl = visible_appliance_or_404(appliance_id)
    data = None
    error = None
    try:
        client = client_for(appl)
        resp = client.api_call('GET', '/' + endpoint_path)
        data = resp.json()
    except Exception as exc:
        error = str(exc)
    return render_template('workspace/browse.html', appliance=appl, endpoint_path=endpoint_path,
                           data=data, error=error)


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


@bp.route('/<int:appliance_id>/new-policy')
@login_required
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
    return jsonify(ok=True, dry_run=not do_apply, steps=results)
