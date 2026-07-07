"""Exceptions — author desired-state WAF / signature carve-outs bound to a
Server Policy.

A Web Protection Profile is usually SHARED, so an exception on it applies to
every policy that binds it and FortiWeb can't record which policy a carve-out
was authored for. This page records that intent in the manager DB (NEVER on the
box from here — pushing to a device is a separate, later step). It REPLACES the
old stub that listed url-access rules and mislabelled them "exceptions".
"""
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

from ..auth.decorators import require_permission
from ..models import Appliance
from ..models import visible_appliances, visible_appliance_or_404
from ..clients.fortiweb import FortiWebClient
from ..services import wpp_exceptions as store
from ..services.fortiweb_ops import FortiWebOps
from ..services import exception_inject, exception_detect
from ..services.audit import log_action

bp = Blueprint('exceptions', __name__, url_prefix='/exceptions')

_WPP_COLL = 'waf/web-protection-profile.inline-protection'
EP_POLICY = '/api/v2.0/cmdb/server-policy/policy'


def _clone_suggestion(appliance, source, policies):
    """The guided-clone offer (rule 3): derive the per-policy WPP clone name from
    the Naming catalog (element ``wpp_exception``, default ``wpp-{name}`` where
    {name} = the server policy) and check WPP headroom (rule 4) up front."""
    from ..services import naming as naming_svc
    from ..services import settings_store as sstore
    from ..services import capacity
    pol = next((p for p in (policies or []) if p), '')
    new_name = ''
    if pol:
        scheme = naming_svc.effective_scheme(
            sstore.naming_overrides(naming_svc.PRODUCT_FORTIWEB),
            naming_svc.PRODUCT_FORTIWEB)
        pattern = scheme.get('wpp_exception', 'wpp-{name}')
        new_name = naming_svc.render_one(pattern, naming_svc.slugify(pol) or pol)
    try:
        allowed, msg = capacity.check_headroom(appliance, 'web_protection_profile', want=1)
    except Exception:  # noqa: BLE001 — a capacity hiccup never blocks the offer UI
        allowed, msg = True, ''
    return {'source': source, 'policy': pol, 'new_name': new_name,
            'headroom_ok': bool(allowed), 'headroom': msg}


def _device_lists(appliance):
    """Best-effort server-policy + WPP names off the device (for the pickers)."""
    policies, wpps = [], []
    try:
        client = FortiWebClient(appliance)
        raw = client.list_server_policies()
        rows = raw.get('results', raw.get('data', [])) if isinstance(raw, dict) else []
        policies = sorted(r.get('name', '') for r in rows if isinstance(r, dict) and r.get('name'))
        wpps = sorted(client.cmdb_names(_WPP_COLL))
    except Exception:  # noqa: BLE001 — dead device → empty pickers, page still works
        pass
    return policies, wpps


@bp.route('/')
@login_required
def index():
    appliances = visible_appliances().order_by(Appliance.name).all()
    from flask import redirect as _redir, url_for as _ufor
    from ..services import device_context as _dc
    _cur = _dc.current_appliance()
    if _cur is None:
        return _redir(_ufor('architecture.index'))
    return _redir(_ufor('exceptions.list_exceptions', id=_cur.id))


@bp.route('/<int:id>')
@login_required
def list_exceptions(id):
    appliance = visible_appliance_or_404(id)
    policies, wpps = _device_lists(appliance)
    items = store.list_exceptions(appliance.id)
    from ..services.templates import managed_wpp_names
    return render_template(
        'exceptions/list.html',
        appliance=appliance,
        items=items,
        exception_types=store.EXCEPTION_TYPES,
        signature_types=store.SIGNATURE_TYPES,
        policies=policies,
        wpps=wpps,
        managed_wpps=managed_wpp_names(),
        stale_count=sum(1 for it in items if getattr(it, 'stale', False)),
        cat_exception=store.CAT_EXCEPTION,
        cat_signature=store.CAT_SIGNATURE,
    )


@bp.route('/type-fields')
@login_required
def type_fields(id=None):
    """Field spec for a carve-out type, so the New/Edit form renders inputs."""
    key = request.args.get('type', '')
    t = store.type_for(key)
    if not t:
        return jsonify(ok=False, error='unknown type', fields=[]), 400
    return jsonify(ok=True, type=t, fields=store.fields_for(key),
                   help=store.help_for(key))


@bp.route('/<int:id>/save', methods=['POST'])
@require_permission('config_write')
def save(id):
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    exc_id = body.get('exc_id')
    exc_type = (body.get('exc_type') or '').strip()
    wpp_mkey = (body.get('wpp_mkey') or '').strip()
    name = (body.get('name') or '').strip()
    reason = (body.get('reason') or '').strip()
    policies = body.get('policies') or []
    fields = body.get('fields') or {}
    if not isinstance(fields, dict):
        fields = {}
    payload = {k: v for k, v in fields.items() if v not in (None, '', [])}

    # Rule 2 — templates stay clean: a carve-out can never target a
    # template-managed WPP. The 403 carries the guided-clone offer (rule 3):
    # clone the profile as wpp-{policy}, rebind the policy, author on the clone.
    lock = store.template_lock_error(wpp_mkey)
    if lock:
        return jsonify(ok=False, error=lock, template_locked=True,
                       clone_suggestion=_clone_suggestion(appliance, wpp_mkey, policies)), 403

    if exc_id:
        existing = store.get(int(exc_id))
        if existing is None:
            return jsonify(ok=False, error='not found'), 404
        errors = store.validate_payload(existing.exc_type, payload)
        if errors:
            return jsonify(ok=False, error='; '.join(errors), errors=errors), 400
        exc = store.update(int(exc_id), wpp_mkey=wpp_mkey, payload=payload,
                           name=name, reason=reason, policies=policies)
        return jsonify(ok=True, id=exc.id)

    if not store.type_for(exc_type):
        return jsonify(ok=False, error='unknown carve-out type'), 400
    errors = store.validate_payload(exc_type, payload)
    if errors:
        return jsonify(ok=False, error='; '.join(errors), errors=errors), 400
    author = getattr(current_user, 'username', '') or ''
    exc = store.add(appliance.id, wpp_mkey=wpp_mkey, exc_type=exc_type, payload=payload,
                    name=name, reason=reason, author=author, policies=policies)
    return jsonify(ok=True, id=exc.id)


@bp.route('/<int:id>/delete', methods=['POST'])
@require_permission('config_write')
def delete(id):
    visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    ok = store.delete(int(body.get('exc_id') or 0))
    return jsonify(ok=ok)


@bp.route('/<int:id>/purge', methods=['POST'])
@require_permission('config_write')
def purge(id):
    """Clean-migration purge: drop every carve-out bound to a Server Policy."""
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    pol = (body.get('server_policy') or '').strip()
    if not pol:
        return jsonify(ok=False, error='server policy required'), 400
    n = store.delete_for_policy(appliance.id, pol, body.get('category') or None)
    return jsonify(ok=True, deleted=n)


@bp.route('/<int:id>/clone-for-policy', methods=['POST'])
@require_permission('config_write')
def clone_for_policy(id):
    """Rule 3 — the guided flow: deep-clone a (template-managed) WPP under the
    Naming-derived per-policy name, re-bind the Server Policy to the clone, and
    re-point any authored carve-outs. Headroom-checked (rule 4). Dry-run unless
    ``apply=true``."""
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    source = (body.get('source') or '').strip()
    policy = (body.get('server_policy') or '').strip()
    new_name = (body.get('new_name') or '').strip()
    do_apply = bool(body.get('apply'))
    if not source or not policy:
        return jsonify(ok=False, error='source WPP and server policy are required'), 400
    if not new_name:
        new_name = _clone_suggestion(appliance, source, [policy])['new_name']
    if not new_name or new_name == source:
        return jsonify(ok=False, error='could not derive a distinct clone name'), 400
    if store.template_lock_error(new_name):
        return jsonify(ok=False, error='"%s" is itself a template name — pick another'
                       % new_name), 400

    # Rule 4: never multiply WPPs past the model's capacity.
    from ..services import capacity
    allowed, hmsg = capacity.check_headroom(appliance, 'web_protection_profile', want=1)
    if not allowed:
        return jsonify(ok=False, error=hmsg), 409

    from ..services import clone, objform
    try:
        client = FortiWebClient(appliance)
        reader = clone.ClientReader(client)
        planner = clone.ClonePlanner(reader, reader)
        items = planner.plan(clone.ROOT_WPP, source, new_name=new_name)
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error='device read failed: %s' % exc), 502
    summary = clone.summarize(items)
    if not do_apply:
        return jsonify(ok=True, dry_run=True, new_name=new_name, summary=summary,
                       headroom=hmsg, plan=clone.render_plan(items))

    if any(it.status == 'create' for it in items):
        ops = FortiWebOps(appliance)

        def _write(item):
            ep = objform.rest_path(item.urn)
            mkey = item.parent_mkey if item.kind == 'subrow' else None
            res = ops.create(ep, {'data': item.payload}, mkey=mkey, dry_run=False)
            if not res.ok:
                raise RuntimeError(res.get('error') or 'write failed')

        clone.apply_clone(items, _write, dry_run=False)
        failed = [it for it in items
                  if (it.result or '').startswith('error')]
        if failed:
            return jsonify(ok=False,
                           error='%d object(s) failed to clone — policy NOT re-bound'
                                 % len(failed),
                           plan=clone.render_plan(items)), 502
    # else: the clone already exists on the box → just re-bind.

    res = FortiWebOps(appliance).update(
        EP_POLICY, policy, {'data': {'web-protection-profile': new_name}},
        dry_run=False)
    if not res.ok:
        return jsonify(ok=False, new_name=new_name,
                       error='clone "%s" is on the device but the policy re-bind '
                             'failed: %s' % (new_name, res.get('error', ''))), 502
    moved = store.retarget_for_policy(appliance.id, policy, source, new_name)
    log_action('exceptions.clone_for_policy', target='%s/%s' % (appliance.name, policy),
               appliance_id=appliance.id,
               detail='wpp %s -> %s (re-pointed %d carve-out(s))'
                      % (source, new_name, moved))
    # Keep the DB-first pickers current (best-effort — the device write already
    # succeeded; a refresh failure only delays the new name showing in lists).
    try:
        from ..services import device_sync
        device_sync.sync_device(appliance, publish=False,
                                user_label=getattr(current_user, 'username', None),
                                trigger='exceptions.clone_for_policy')
    except Exception:  # noqa: BLE001
        pass
    return jsonify(ok=True, new_name=new_name, rebound=True, moved=moved,
                   summary=summary)


# --------------------------------------------------------------------------- #
#  Inject to device (dry-run preview -> real push) + Detect from device         #
# --------------------------------------------------------------------------- #
def _policy_wpp_bindings(appliance):
    """Live ``{server_policy: wpp}`` map off the device (empty on a dead box)."""
    try:
        client = FortiWebClient(appliance)
        rows = client._results_list(client.list_server_policies())
        return {r['name']: (r.get('web-protection-profile') or '')
                for r in rows if isinstance(r, dict) and r.get('name')}
    except Exception:  # noqa: BLE001 - dead device -> no bindings
        return {}


@bp.route('/<int:id>/inject-targets')
@login_required
def inject_targets(id):
    """Candidate parent objects on the device a carve-out type can target."""
    appliance = visible_appliance_or_404(id)
    rest = exception_inject.rest_for(request.args.get('type', ''))
    if rest is None:
        return jsonify(ok=False, error='type cannot be injected', targets=[]), 400
    try:
        targets = exception_inject.candidate_targets(FortiWebClient(appliance),
                                                     request.args.get('type', ''))
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc), targets=[])
    # Rule 4 — a signature set caps at 128 filter_list (per-signature exception)
    # entries. Show each candidate set's usage so the operator sees headroom
    # BEFORE picking a target. Best-effort: a read failure just omits counts.
    counts = {}
    if request.args.get('type', '') == 'signature_filter_item':
        try:
            from .objedit import _read_rows
            client = FortiWebClient(appliance)
            for t in targets[:20]:
                counts[t] = len(_read_rows(client, 'waf/signature/filter_list', t))
        except Exception:  # noqa: BLE001
            counts = {}
    return jsonify(ok=True, targets=targets, inline=rest.inline,
                   counts=counts, limit=store.SIG_FILTER_MAX,
                   can_create=(not rest.inline
                               and rest.parent_logical not in ('signature', 'signature_group_rule')))


@bp.route('/<int:id>/inject', methods=['POST'])
@require_permission('config_write')
def inject(id):
    """Push one authored carve-out onto the device (dry-run unless apply=true)."""
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    exc = store.get(int(body.get('exc_id') or 0))
    if exc is None or exc.appliance_id != appliance.id:
        return jsonify(ok=False, error='carve-out not found'), 404
    # Rule 2 also holds at PUSH time: never inject into a template-managed WPP.
    lock = store.template_lock_error(exc.wpp_mkey)
    if lock:
        return jsonify(ok=False, error=lock, template_locked=True), 403
    # Rule 4 — hard FortiWeb cap: 128 filter_list entries per signature set.
    target = (body.get('target') or '').strip()
    if exc.exc_type == 'signature_filter_item' and target:
        try:
            from .objedit import _read_rows
            used = len(_read_rows(FortiWebClient(appliance),
                                  'waf/signature/filter_list', target))
        except Exception:  # noqa: BLE001 — unreadable set → let the box decide
            used = None
        if used is not None and used >= store.SIG_FILTER_MAX:
            return jsonify(ok=False, error=(
                'Signature set "%s" already holds %d/%d exception entries — '
                'FortiWeb rejects more. Remove an entry first.' % (
                    target, used, store.SIG_FILTER_MAX))), 409
    res = exception_inject.apply_injection(
        FortiWebOps(appliance), exc_type=exc.exc_type, payload=exc.payload_dict,
        target=target, dry_run=not bool(body.get('apply')),
        create_container=bool(body.get('create_container')))
    return jsonify(ok=res['ok'], dry_run=res['dry_run'], steps=res['steps'],
                   plan={k: res['plan'].get(k) for k in ('status', 'method', 'endpoint', 'error')})


@bp.route('/<int:id>/detect', methods=['POST'])
@require_permission('config_write')
def detect(id):
    """Read live per-signature exceptions off the device, bound to their policy."""
    appliance = visible_appliance_or_404(id)
    bindings = _policy_wpp_bindings(appliance)
    if not bindings:
        return jsonify(ok=False, error='no server policies / device unreachable', found=[])
    try:
        found = exception_detect.detect_signature_exceptions(
            exception_detect.ClientReader(FortiWebClient(appliance)), bindings)
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc), found=[])
    return jsonify(ok=True, found=found, policies=len(bindings))


@bp.route('/<int:id>/detect-import', methods=['POST'])
@require_permission('config_write')
def detect_import(id):
    """Import chosen detected carve-outs into desired-state (idempotent)."""
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    incoming = body.get('found') or []
    existing = store.list_exceptions(appliance.id, store.CAT_SIGNATURE)

    def _dup(d):
        sid = (d.get('payload') or {}).get('signature_id') or d.get('signature_id')
        pol = d.get('policy')
        return any(e.wpp_mkey == d.get('wpp') and e.payload_dict.get('signature_id') == sid
                   and pol in (e.policy_names or []) for e in existing)

    author = getattr(current_user, 'username', '') or ''
    fresh = [d for d in incoming if not _dup(d)]

    def _add(**kw):
        store.add(appliance.id, author=author, **kw)

    n = exception_detect.import_detected_signature_exceptions(fresh, add=_add)
    return jsonify(ok=True, imported=n, skipped=len(incoming) - n)
