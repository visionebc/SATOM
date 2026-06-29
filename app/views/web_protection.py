from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission, UserSetting, Template
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('web_protection', __name__, url_prefix='/web-protection')

# Real FortiWeb 7.6 cmdb endpoints (verified against the live appliance).
EP_INLINE = '/api/v2.0/cmdb/waf/web-protection-profile.inline-protection'
EP_SIGNATURE = '/api/v2.0/cmdb/waf/signature'


def _results(resp):
    """Extract the object list from a FortiWeb cmdb response (``{"results": …}``)."""
    j = resp.json()
    if isinstance(j, dict):
        out = j.get('results', j.get('data', []))
        return out if isinstance(out, list) else ([out] if out else [])
    return j if isinstance(j, list) else []


@bp.route('/')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    from flask import redirect as _redir, url_for as _ufor
    from ..services import device_context as _dc
    _cur = _dc.current_appliance()
    if _cur is None:
        return _redir(_ufor('architecture.index'))
    return _redir(_ufor('web_protection.overview', id=_cur.id))


@bp.route('/<int:id>')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def overview(id):
    appliance = Appliance.query.get_or_404(id)
    # DB-first: serve from the local source of truth; the device is touched only
    # on an explicit refresh (see web_protection.refresh).
    from ..services import read_layer
    error = None
    wpp_profiles, wmeta = read_layer.read_objects(
        appliance.id, "webprotection_profile_inline")
    signatures, _ = read_layer.read_objects(appliance.id, "signature")
    hide_default = UserSetting.get(current_user.id, "wpp.hide_default", "0") == "1"
    return render_template(
        'web_protection/overview.html',
        appliance=appliance,
        wpp_profiles=wpp_profiles,
        signatures=signatures,
        hide_default=hide_default,
        freshness=read_layer.freshness_label(wmeta),
        cached=wmeta.get("cached"),
        error=error,
    )


@bp.route('/<int:id>/refresh', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def refresh(id):
    """Pull live config into the local source of truth, then return to the
    Web Protection overview (DB-first)."""
    appliance = Appliance.query.get_or_404(id)
    try:
        from ..services import device_sync
        run = device_sync.sync_device(appliance, publish=False,
                                      user_label=getattr(current_user, 'username', None),
                                      trigger='manual')
        flash(f"Refreshed from {appliance.name}: {run.detail}",
              "success" if run.status == 'ok' else "danger")
    except Exception as exc:
        flash(f"Refresh failed: {exc}", "danger")
    return redirect(url_for('web_protection.overview', id=id))


@bp.route('/<int:id>/wpp/<name>')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def wpp_detail(id, name):
    appliance = Appliance.query.get_or_404(id)
    wpp = None
    sub_policies = {}
    error = None
    try:
        client = FortiWebClient(appliance)
        result = _results(client.api_call('GET', f'{EP_INLINE}?mkey={name}'))
        wpp = result[0] if result else None
        if isinstance(wpp, dict):
            for key, endpoint in [('signature', EP_SIGNATURE)]:
                try:
                    sub_policies[key] = _results(client.api_call('GET', endpoint))
                except Exception:
                    sub_policies[key] = []
    except Exception as exc:
        error = str(exc)
    return render_template(
        'web_protection/wpp_detail.html',
        appliance=appliance,
        wpp_name=name,
        wpp=wpp,
        sub_policies=sub_policies,
        error=error,
    )


# Whitelist of per-user Web Protection view preferences (UserSetting keys are
# stored prefixed with "wpp.").
_WPP_PREF_KEYS = {"hide_default"}

@bp.route('/prefs', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def set_pref():
    """Persist a per-user Web Protection view preference (DB-backed).

    Body: {"key": "hide_default", "value": true|false}. Used by the
    'Hide default (predefined) profiles' toggle on the overview page.
    """
    data = request.get_json(silent=True) or {}
    key = data.get('key')
    if key not in _WPP_PREF_KEYS:
        abort(400)
    value = '1' if data.get('value') else '0'
    UserSetting.set(current_user.id, f'wpp.{key}', value)
    return jsonify(ok=True, key=key, value=value)


# --------------------------------------------------------------------------- #
#  Deep clone  +  save-as-template  (Web Protection Profile)                    #
#                                                                               #
#  Deep clone = the full dependency-tree clone engine (services.clone): walk    #
#  the WPP's ~40 sub-policy references on THIS device, recreate the ones that    #
#  are missing under the new name, and VALIDATE (skip) the ones that already     #
#  exist. Save-as-template stores the same deep snapshot as a PENDING template   #
#  the admin approves in Settings -> WPP Templates (the existing workflow).      #
# --------------------------------------------------------------------------- #
def _wpp_plan(appliance, source, new_name):
    """Build a dry-run plan for a deep WPP clone on ``appliance`` (read-only)."""
    from ..services import clone
    client = FortiWebClient(appliance)
    reader = clone.ClientReader(client)
    planner = clone.ClonePlanner(reader, reader)
    return clone, planner.plan(clone.ROOT_WPP, source, new_name=new_name)


@bp.route('/<int:id>/clone/plan', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def clone_plan(id):
    """Dry-run preview of a deep WPP clone (read-only, no writes). Returns the
    per-object plan + counts so the modal shows what is created vs already there."""
    appliance = Appliance.query.get_or_404(id)
    data = request.get_json(silent=True) or {}
    source = (data.get('source') or '').strip()
    new_name = (data.get('new_name') or '').strip()
    if not source or not new_name:
        return jsonify(ok=False, error='source and new_name are required'), 400
    try:
        clone, items = _wpp_plan(appliance, source, new_name)
        return jsonify(ok=True, summary=clone.summarize(items),
                       plan=clone.render_plan(items),
                       items=[it.to_dict() for it in items])
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc)), 500


@bp.route('/<int:id>/clone', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def clone_apply(id):
    """Deep-clone a WPP on THIS device under a new name. Creates only the missing
    referenced objects (existing ones are validated, not copied); each create
    goes through FortiWebOps (sanitize + audit + change-history)."""
    appliance = Appliance.query.get_or_404(id)
    data = request.get_json(silent=True) or {}
    source = (data.get('source') or '').strip()
    new_name = (data.get('new_name') or '').strip()
    if not source or not new_name:
        return jsonify(ok=False, error='source and new_name are required'), 400
    from ..services import clone, objform
    from ..services.fortiweb_ops import FortiWebOps
    try:
        client = FortiWebClient(appliance)
        reader = clone.ClientReader(client)
        planner = clone.ClonePlanner(reader, reader)
        items = planner.plan(clone.ROOT_WPP, source, new_name=new_name)
        if not any(it.status == 'create' for it in items):
            return jsonify(
                ok=False,
                error='Nothing to create — "%s" already exists on %s' % (new_name, appliance.name)
            ), 409
        ops = FortiWebOps(appliance)

        def _write(item):
            ep = objform.rest_path(item.urn)
            mkey = item.parent_mkey if item.kind == 'subrow' else None
            res = ops.create(ep, {'data': item.payload}, mkey=mkey, dry_run=False)
            if not res.ok:
                raise RuntimeError(res.get('error') or 'write failed')

        clone.apply_clone(items, _write, dry_run=False)
        created = [it for it in items if it.applied]
        failed = [it for it in items if (it.result or '').startswith('error')]
        # Per-object failure detail for the modal: WHAT failed and WHY.
        failures = [
            {'label': it.label, 'mkey': it.mkey, 'urn': it.urn,
             'reason': (it.result or '').split('error:', 1)[-1].strip() or 'write failed'}
            for it in failed
        ]
        log_action('wpp.clone', target=source, appliance_id=appliance.id,
                   detail='new_name=%s created=%d failed=%d' % (new_name, len(created), len(failed)))
        # The clone wrote to the DEVICE; the overview is DB-first, so refresh the
        # local source-of-truth here or the new profile won't show until a manual
        # Refresh. Best-effort: the clone already succeeded regardless -- but if the
        # refresh fails we tell the client so it can prompt a manual Refresh.
        cache_refresh_failed = False
        if created:
            try:
                from ..services import device_sync
                device_sync.sync_device(
                    appliance, publish=False,
                    user_label=getattr(current_user, 'username', None),
                    trigger='wpp.clone')
            except Exception as _exc:  # noqa: BLE001
                cache_refresh_failed = True
                log_action('wpp.clone', target=source, appliance_id=appliance.id,
                           detail='cache refresh failed: %s' % _exc)
        return jsonify(ok=(not failed), created=len(created), failed=len(failed),
                       failures=failures, cache_refresh_failed=cache_refresh_failed,
                       new_name=new_name, items=[it.to_dict() for it in items],
                       plan=clone.render_plan(items))
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc)), 500


@bp.route('/<int:id>/save-as-template', methods=['POST'])
@login_required
@require_permission('operations.template_save')
def save_as_template(id):
    """Save a WPP (deep) to the template library as a PENDING draft. The admin
    approves it in Settings -> WPP Templates — same workflow as every template."""
    appliance = Appliance.query.get_or_404(id)
    data = request.get_json(silent=True) or {}
    source = (data.get('source') or '').strip()
    name = (data.get('name') or '').strip() or source
    if not source:
        return jsonify(ok=False, error='source is required'), 400
    from ..services import clone
    from ..services import templates as tpl
    try:
        client = FortiWebClient(appliance)
        reader = clone.ClientReader(client)
        planner = clone.ClonePlanner(reader, reader)
        items = planner.collect(clone.ROOT_WPP, source, new_name=name)
        body = clone.template_body(items, name)
        if not body.get('data'):
            return jsonify(
                ok=False,
                error='Profile "%s" not found on %s' % (source, appliance.name)
            ), 404
        row = tpl.save_template(
            Template.KIND_WEB_PROTECTION, name, body,
            note='Cloned from %s on %s (pending approval)' % (source, appliance.name),
            author=getattr(current_user, 'username', '') or '')
        log_action('wpp.save_template', target=source, appliance_id=appliance.id,
                   detail='template=%s v%s status=%s' % (row.name, row.version, row.status))
        return jsonify(ok=True, template_id=row.id, name=row.name,
                       version=row.version, status=row.status)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc)), 500
