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
from ..clients.fortiweb import FortiWebClient
from ..services import wpp_exceptions as store
from ..services.fortiweb_ops import FortiWebOps
from ..services import exception_inject, exception_detect

bp = Blueprint('exceptions', __name__, url_prefix='/exceptions')

_WPP_COLL = 'waf/web-protection-profile.inline-protection'


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
    appliances = Appliance.query.order_by(Appliance.name).all()
    from flask import redirect as _redir, url_for as _ufor
    from ..services import device_context as _dc
    _cur = _dc.current_appliance()
    if _cur is None:
        return _redir(_ufor('architecture.index'))
    return _redir(_ufor('exceptions.list_exceptions', id=_cur.id))


@bp.route('/<int:id>')
@login_required
def list_exceptions(id):
    appliance = Appliance.query.get_or_404(id)
    policies, wpps = _device_lists(appliance)
    items = store.list_exceptions(appliance.id)
    return render_template(
        'exceptions/list.html',
        appliance=appliance,
        items=items,
        exception_types=store.EXCEPTION_TYPES,
        signature_types=store.SIGNATURE_TYPES,
        policies=policies,
        wpps=wpps,
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
    appliance = Appliance.query.get_or_404(id)
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
    Appliance.query.get_or_404(id)
    body = request.get_json(silent=True) or {}
    ok = store.delete(int(body.get('exc_id') or 0))
    return jsonify(ok=ok)


@bp.route('/<int:id>/purge', methods=['POST'])
@require_permission('config_write')
def purge(id):
    """Clean-migration purge: drop every carve-out bound to a Server Policy."""
    appliance = Appliance.query.get_or_404(id)
    body = request.get_json(silent=True) or {}
    pol = (body.get('server_policy') or '').strip()
    if not pol:
        return jsonify(ok=False, error='server policy required'), 400
    n = store.delete_for_policy(appliance.id, pol, body.get('category') or None)
    return jsonify(ok=True, deleted=n)


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
    appliance = Appliance.query.get_or_404(id)
    rest = exception_inject.rest_for(request.args.get('type', ''))
    if rest is None:
        return jsonify(ok=False, error='type cannot be injected', targets=[]), 400
    try:
        targets = exception_inject.candidate_targets(FortiWebClient(appliance),
                                                     request.args.get('type', ''))
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc), targets=[])
    return jsonify(ok=True, targets=targets, inline=rest.inline,
                   can_create=(not rest.inline
                               and rest.parent_logical not in ('signature', 'signature_group_rule')))


@bp.route('/<int:id>/inject', methods=['POST'])
@require_permission('config_write')
def inject(id):
    """Push one authored carve-out onto the device (dry-run unless apply=true)."""
    appliance = Appliance.query.get_or_404(id)
    body = request.get_json(silent=True) or {}
    exc = store.get(int(body.get('exc_id') or 0))
    if exc is None or exc.appliance_id != appliance.id:
        return jsonify(ok=False, error='carve-out not found'), 404
    res = exception_inject.apply_injection(
        FortiWebOps(appliance), exc_type=exc.exc_type, payload=exc.payload_dict,
        target=(body.get('target') or '').strip(), dry_run=not bool(body.get('apply')),
        create_container=bool(body.get('create_container')))
    return jsonify(ok=res['ok'], dry_run=res['dry_run'], steps=res['steps'],
                   plan={k: res['plan'].get(k) for k in ('status', 'method', 'endpoint', 'error')})


@bp.route('/<int:id>/detect', methods=['POST'])
@require_permission('config_write')
def detect(id):
    """Read live per-signature exceptions off the device, bound to their policy."""
    appliance = Appliance.query.get_or_404(id)
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
    appliance = Appliance.query.get_or_404(id)
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
