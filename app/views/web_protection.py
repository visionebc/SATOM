"""Web Protection — an exact mirror of the FortiWeb 7.6 GUI area.

Left menu = the appliance's own **Web Protection** menu (Known Attacks /
Protocol / Access / Input Validation / Cookie Security / Advanced Protection /
Data Loss Prevention — :mod:`app.services.wp_menu`, harvested from the 7.6.4
admin guide). Each menu entry is one page whose TABS are FortiWeb's own tabs;
every tab lists that object type (DB-first) and edits through the generic
recursive editor (:mod:`app.views.objedit`).

**Web Protection Profile** keeps FortiWeb's *Policy > Web Protection Profile*
shape: Inline / Offline Protection Profile tabs (plus the deep-clone and
save-as-template flows this app adds on top).

**Signatures** gets the dedicated FortiWeb-style editor: Signature Category
table (main-class rows), the searchable Signature Details list, and the
per-signature **Exception** tab writing the signature set's ``filter_list``
rows — the same flow as *Signature Details → <id> → Exception* on the box.
"""
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission, UserSetting, Template
from ..clients.fortiweb import FortiWebClient
from ..services.audit import log_action
from ..services import wp_menu

bp = Blueprint('web_protection', __name__, url_prefix='/web-protection')

# Real FortiWeb 7.6 cmdb endpoints (verified against the live appliance).
EP_INLINE = '/api/v2.0/cmdb/waf/web-protection-profile.inline-protection'


def _results(resp):
    """Extract the object list from a FortiWeb cmdb response (``{"results": …}``)."""
    j = resp.json()
    if isinstance(j, dict):
        out = j.get('results', j.get('data', []))
        return out if isinstance(out, list) else ([out] if out else [])
    return j if isinstance(j, list) else []


def _row_view(obj):
    """A compact list-row projection (name + a couple of GUI-meaningful fields)."""
    if not isinstance(obj, dict):
        return {'name': str(obj), 'status': '', 'detail': ''}
    name = obj.get('name') or obj.get('mkey') or obj.get('id') or '—'
    status = obj.get('status') or ''
    detail = ''
    for k in ('comment', 'comments', 'action', 'severity', 'host', 'url',
              'request-file', 'request-type', 'type', 'mode'):
        v = obj.get(k)
        if v not in (None, '', []):
            detail = '%s: %s' % (k, v)
            break
    return {'name': name, 'status': status, 'detail': detail}


@bp.route('/')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def index():
    from ..services import device_context as _dc
    _cur = _dc.current_appliance()
    if _cur is None:
        return redirect(url_for('architecture.index'))
    return redirect(url_for('web_protection.overview', id=_cur.id))


# --------------------------------------------------------------------------- #
#  Web Protection Profile (Policy > Web Protection Profile on the box):        #
#  Inline Protection Profile | Offline Protection Profile tabs.                #
# --------------------------------------------------------------------------- #
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
    offline_profiles, _ometa = read_layer.read_objects(
        appliance.id, "webprotection_profile_offline")
    hide_default = UserSetting.get(current_user.id, "wpp.hide_default", "0") == "1"
    return render_template(
        'web_protection/overview.html',
        appliance=appliance,
        wpp_profiles=wpp_profiles,
        offline_profiles=offline_profiles,
        hide_default=hide_default,
        freshness=read_layer.freshness_label(wmeta),
        cached=wmeta.get("cached"),
        error=error,
        wp_groups=wp_menu.menu(),
        active_item='__profile__',
    )


@bp.route('/<int:id>/refresh', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def refresh(id):
    """Pull live config into the local source of truth, then return to where
    the ⟳ was clicked (DB-first)."""
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
    nxt = request.form.get('next') or url_for('web_protection.overview', id=id)
    return redirect(nxt)


@bp.route('/<int:id>/wpp/<name>')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def wpp_detail(id, name):
    """Legacy detail URL → the FortiWeb-style profile form (generic editor,
    grouped exactly like the box's own profile page)."""
    appliance = Appliance.query.get_or_404(id)
    return redirect(url_for(
        'objedit.edit', appliance_id=appliance.id,
        collection='waf/web-protection-profile.inline-protection',
        mkey=name, title='Web Protection Profile'))


# --------------------------------------------------------------------------- #
#  FortiWeb menu pages — one page per menu entry, FortiWeb's own tabs.          #
# --------------------------------------------------------------------------- #
@bp.route('/<int:id>/m/<item_key>')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def menu_page(id, item_key):
    appliance = Appliance.query.get_or_404(id)
    item = wp_menu.item_for(item_key)
    if item is None:
        abort(404)
    logical = (request.args.get('tab') or '').strip() or item.tabs[0].logical
    tab = wp_menu.tab_for(item, logical)
    if tab is None:
        abort(404)

    from ..services import read_layer, objform
    error = None
    raw, cache_meta = read_layer.read_objects(appliance.id, tab.logical)
    if not raw and not read_layer.has_any_cache(appliance.id):
        # Fresh install with no cache at all — best-effort live read.
        try:
            client = FortiWebClient(appliance)
            raw, error = client.list_with_error(objform.rest_path(tab.collection))
            cache_meta = {"generated_at": None, "source": "live", "cached": False}
        except Exception as exc:  # noqa: BLE001 — dead device → empty list + note
            error = str(exc)
            raw = []
    rows = [_row_view(o) for o in raw]
    return render_template(
        'web_protection/section.html',
        appliance=appliance,
        item=item,
        tab=tab,
        rows=rows,
        error=error,
        cache_meta=cache_meta,
        freshness=read_layer.freshness_label(cache_meta) if cache_meta else '',
        wp_groups=wp_menu.menu(),
        active_item=item.key,
    )


# --------------------------------------------------------------------------- #
#  Signatures — the FortiWeb-style signature policy editor.                    #
#  (Signature Category rows + searchable Signature Details + per-signature      #
#   Exception tab = the set's filter_list, like the box's own page.)            #
# --------------------------------------------------------------------------- #
_SIG_SUBLISTS = {
    'main_class_list': 'classes',
    'signature_disable_list': 'disable',
    'alert_only_list': 'alert',
    'filter_list': 'exceptions',
    'sub_class_disable_list': 'subclass',
    'fpm_disable_list': 'fpm',
}


def _sig_state(appliance, name, force_live=False):
    """The signature set's sub-lists — DB-first (deep-capture layer), live
    ``?mkey=`` scoped reads as fallback. ``force_live=True`` skips the cache
    (used right after a write, when the box is ahead of the local DB).
    Returns (state dict, source str)."""
    state = {v: [] for v in _SIG_SUBLISTS.values()}
    if force_live:
        try:
            from .objedit import _read_rows
            client = FortiWebClient(appliance)
            for seg, key in _SIG_SUBLISTS.items():
                state[key] = _read_rows(client, 'waf/signature/%s' % seg, name)
            return state, 'live'
        except Exception:  # noqa: BLE001 — fall through to the cached path
            state = {v: [] for v in _SIG_SUBLISTS.values()}
    # 1) deep layer: the signature node cached under a policy/WPP tree carries
    #    the sub-lists as children (subtable = the REST segment name).
    try:
        from ..extensions import db as _db
        from ..models_cache import DeviceObject
        parents = (_db.session.query(DeviceObject)
                   .filter(DeviceObject.appliance_id == appliance.id,
                           DeviceObject.mkey == str(name),
                           DeviceObject.logical_name.like('%signature'))
                   .all())
        for p in parents:
            kids = (_db.session.query(DeviceObject)
                    .filter_by(parent_id=p.id)
                    .order_by(DeviceObject.idx).all())
            if not kids:
                continue
            for k in kids:
                key = _SIG_SUBLISTS.get(k.subtable or '')
                if key:
                    state[key].append(k.payload or {})
            if any(state.values()):
                return state, 'db'
    except Exception:  # noqa: BLE001 — cache miss must never sink the page
        pass
    # 2) live scoped reads (works only when the device is reachable/licensed).
    try:
        from .objedit import _read_rows
        client = FortiWebClient(appliance)
        for seg, key in _SIG_SUBLISTS.items():
            state[key] = _read_rows(client, 'waf/signature/%s' % seg, name)
        return state, 'live'
    except Exception:  # noqa: BLE001
        return state, 'none'


def _sig_catalog():
    """The cached signature database (data/signatures.json) or ``None``."""
    import os
    from flask import current_app
    from ..services import signature_catalog as sigcat
    path = os.path.join(os.path.dirname(current_app.root_path),
                        'data', 'signatures.json')
    return sigcat.load_signature_db(path)


@bp.route('/<int:id>/signatures/<path:name>')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def signature_policy(id, name):
    appliance = Appliance.query.get_or_404(id)
    from ..services import read_layer, waf_specs

    obj_row = read_layer.object_by_mkey(appliance.id, 'signature', name)
    sig_obj = obj_row.payload if obj_row else None
    if sig_obj is None:
        try:
            client = FortiWebClient(appliance)
            res = _results(client.api_call(
                'GET', '/api/v2.0/cmdb/waf/signature?mkey=%s' % name))
            sig_obj = res[0] if res else None
        except Exception:  # noqa: BLE001
            sig_obj = None

    state, state_source = _sig_state(appliance, name)
    catalog = _sig_catalog()
    # Class tree for the filters (small: ~10 main classes, ~50 sub-classes).
    classes = {}
    if catalog:
        for s in catalog.signatures:
            m = classes.setdefault(s.main_id, {
                'name': s.main_name or s.main_id, 'subs': {}})
            m['subs'].setdefault(s.sub_id, s.sub_name or s.sub_id)
    vlabels = waf_specs.value_labels()
    filter_spec = (waf_specs.kinds().get('signature_filter_item') or {})
    class_spec = (waf_specs.kinds().get('signature_class_item') or {})
    return render_template(
        'web_protection/signature_policy.html',
        appliance=appliance,
        set_name=name,
        sig_obj=sig_obj,
        state=state,
        state_source=state_source,
        classes=classes,
        catalog_ready=bool(catalog),
        catalog_count=len(catalog.signatures) if catalog else 0,
        value_labels=vlabels,
        filter_spec=filter_spec,
        class_spec=class_spec,
        wp_groups=wp_menu.menu(),
        active_item='signatures',
    )


@bp.route('/<int:id>/signatures/<path:name>/search')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def sig_search(id, name):
    """Signature Details search — the catalog joined with THIS set's state
    (disabled / alert-only / exception count per signature id)."""
    appliance = Appliance.query.get_or_404(id)
    q = (request.args.get('q') or '').strip().lower()
    main = (request.args.get('main') or '').strip()
    sub = (request.args.get('sub') or '').strip()
    flt = (request.args.get('filter') or '').strip()  # '', disabled, alert, exception
    page = max(request.args.get('page', type=int) or 1, 1)
    per_page = min(max(request.args.get('per_page', type=int) or 100, 10), 400)

    force_live = (request.args.get('live') or '') in ('1', 'true')

    catalog = _sig_catalog()
    if catalog is None:
        return jsonify(ok=False, total=0, rows=[],
                       error='No signature catalog cached — sync it in '
                             'Settings → Signatures first.')
    state, src = _sig_state(appliance, name, force_live=force_live)
    # sig id → sub-row id (needed to DELETE a disable / alert-only row).
    disabled = {str(r.get('signature_id') or '').strip():
                str(r.get('id', r.get('_id', '')))
                for r in state['disable'] if isinstance(r, dict)}
    alert = {str(r.get('signature_id') or '').strip():
             str(r.get('id', r.get('_id', '')))
             for r in state['alert'] if isinstance(r, dict)}
    exc_count = {}
    for r in state['exceptions']:
        if isinstance(r, dict):
            sid = str(r.get('signature_id') or '').strip()
            if sid:
                exc_count[sid] = exc_count.get(sid, 0) + 1

    hits = []
    for s in catalog.signatures:
        if main and s.main_id != main:
            continue
        if sub and s.sub_id != sub:
            continue
        if q and q not in s.id and q not in s.desc.lower():
            continue
        if flt == 'disabled' and s.id not in disabled:
            continue
        if flt == 'alert' and s.id not in alert:
            continue
        if flt == 'exception' and s.id not in exc_count:
            continue
        hits.append(s)
    total = len(hits)
    start = (page - 1) * per_page
    rows = [{
        'id': s.id,
        'desc': s.desc,
        'main_id': s.main_id, 'main': s.main_name or s.main_id,
        'sub_id': s.sub_id, 'sub': s.sub_name or s.sub_id,
        'disabled': s.id in disabled,
        'disable_row': disabled.get(s.id, ''),
        'alert_only': s.id in alert,
        'alert_row': alert.get(s.id, ''),
        'exceptions': exc_count.get(s.id, 0),
    } for s in hits[start:start + per_page]]
    return jsonify(ok=True, total=total, page=page, per_page=per_page,
                   source=src, rows=rows)


@bp.route('/<int:id>/signatures/<path:name>/exceptions/<sig_id>')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def sig_exceptions(id, name, sig_id):
    """The Exception tab rows for ONE signature id (the set's filter_list
    entries whose ``signature_id`` matches) — freshest source available."""
    appliance = Appliance.query.get_or_404(id)
    force_live = (request.args.get('live') or '') in ('1', 'true')
    state, src = _sig_state(appliance, name, force_live=force_live)
    rows = [r for r in state['exceptions']
            if isinstance(r, dict)
            and str(r.get('signature_id') or '').strip() == str(sig_id)]
    return jsonify(ok=True, source=src, rows=rows)


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
