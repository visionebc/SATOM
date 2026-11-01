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
import json
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission, UserSetting, Template
from ..models import visible_appliances, visible_appliance_or_404
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


# GUI labels for enum tokens value_labels doesn't carry (fw6-verified tokens).
_EXTRA_LABELS = {
    'security-mode': {'no': 'None', 'signed': 'Signed', 'encrypted': 'Encrypted'},
    'type': {'request': 'Request', 'response': 'Response',
             'Allow': 'Allow File Types', 'Block': 'Block File Types'},
    'match-type': {'any': 'Any', 'all': 'All'},
    'direction': {'request': 'Request', 'response': 'Response', 'both': 'Both'},
}


def _cell(obj, col, vlabels):
    """Render ONE FortiWeb list cell for a WpCol (see wp_menu column kinds)."""
    v = obj.get(col.key)
    if col.kind == 'count':
        try:
            n = int(v)
        except (TypeError, ValueError):
            n = 0
        return {'kind': 'count', 'text': str(n)}
    if col.kind == 'host':
        return {'kind': 'text',
                'text': (obj.get('host') or '—')
                        if obj.get('host-status') == 'enable' else 'Any'}
    if col.kind == 'onoff':
        tok = str(v or '')
        return {'kind': 'onoff', 'on': tok == 'enable',
                'text': 'Enabled' if tok == 'enable'
                        else ('Disabled' if tok == 'disable' else (tok or '—'))}
    if v in (None, '', []):
        return {'kind': 'text', 'text': '—'}
    tok = str(v).strip()
    lbl = ((vlabels.get(col.key) or {}).get(tok)
           or _EXTRA_LABELS.get(col.key, {}).get(tok))
    if not lbl and col.kind == 'enum' and tok.islower():
        lbl = tok.replace('_', ' ').replace('-', ' ').title()
    return {'kind': 'text', 'text': lbl or tok}


def _row_view(obj, columns, vlabels):
    """One FortiWeb-style list row: name + the tab's own GUI columns."""
    if not isinstance(obj, dict):
        return {'name': str(obj), 'cells': [{'kind': 'text', 'text': '—'}
                                            for _ in columns]}
    name = obj.get('name') or obj.get('mkey') or obj.get('id') or '—'
    return {'name': name, 'cells': [_cell(obj, c, vlabels) for c in columns]}


@bp.route('/')
@login_required
@require_permission('protection.view')
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
@require_permission('protection.view')
def overview(id):
    appliance = visible_appliance_or_404(id)
    # the profile list the FortiWeb menu draws moves there (?classic=1 stays)
    from ..services import gui_classic
    moved = gui_classic.redirect_for(appliance, "webprotection_profile_inline", request.args)
    if moved:
        return redirect(moved)
    # DB-first: serve from the local source of truth; the device is touched only
    # on an explicit refresh (see web_protection.refresh).
    from ..services import read_layer
    from ..services.templates import managed_wpp_names
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
        managed_names=managed_wpp_names(),
        hide_default=hide_default,
        freshness=read_layer.freshness_label(wmeta),
        cached=wmeta.get("cached"),
        error=error,
    )


@bp.route('/<int:id>/refresh', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def refresh(id):
    """Pull live config into the local source of truth, then return to where
    the ⟳ was clicked (DB-first)."""
    appliance = visible_appliance_or_404(id)
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
@require_permission('protection.view')
def wpp_detail(id, name):
    """Legacy detail URL → the FortiWeb-style profile form (generic editor,
    grouped exactly like the box's own profile page)."""
    appliance = visible_appliance_or_404(id)
    return redirect(url_for(
        'objedit.edit', appliance_id=appliance.id,
        collection='waf/web-protection-profile.inline-protection',
        mkey=name, title='Web Protection Profile'))


# --------------------------------------------------------------------------- #
#  FortiWeb menu pages — one page per menu entry, FortiWeb's own tabs.          #
# --------------------------------------------------------------------------- #
@bp.route('/<int:id>/m/<item_key>')
@login_required
@require_permission('protection.view')
def menu_page(id, item_key):
    appliance = visible_appliance_or_404(id)
    item = wp_menu.item_for(item_key)
    if item is None:
        abort(404)
    logical = (request.args.get('tab') or '').strip() or item.tabs[0].logical
    tab = wp_menu.tab_for(item, logical)
    if tab is None:
        abort(404)
    if not item.special:
        # a collection the FortiWeb menu draws moves there (?classic=1 stays)
        from ..services import gui_classic
        moved = gui_classic.redirect_for(appliance, tab.logical, request.args)
        if moved:
            return redirect(moved)

    from ..services import read_layer, objform, waf_specs
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
    vlabels = waf_specs.value_labels()
    rows = [_row_view(o, tab.columns, vlabels) for o in raw]
    return render_template(
        'web_protection/section.html',
        appliance=appliance,
        item=item,
        tab=tab,
        rows=rows,
        error=error,
        cache_meta=cache_meta,
        freshness=read_layer.freshness_label(cache_meta) if cache_meta else '',
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
    Returns (state dict, source str): ``none`` when neither answered -- a
    device REFUSAL (401, licence) is not an empty policy; its text is in
    ``state['error']``."""
    state = {v: [] for v in _SIG_SUBLISTS.values()}
    if force_live:
        try:
            return _sig_state_live(appliance, name), 'live'
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
        return _sig_state_live(appliance, name), 'live'
    except Exception as exc:  # noqa: BLE001
        state['error'] = str(exc) or exc.__class__.__name__
        return state, 'none'


def _global_disabled(appliance_id) -> set:
    """Signature ids disabled in every policy: the ``signature_id`` of each
    cached waf/base-signature-disable row. Not the cached mkey: the cache keys
    a row by its first of name/mkey/id, and FortiWeb gives these rows a
    sequence ``id`` (1, 2...) while its own key is ``signature_id`` (measured,
    fortiweb19 7.6.8: GET ?mkey=<signature id> returns the row). No cache:
    nothing is claimed."""
    from ..extensions import db as _db
    from ..models_cache import DeviceObject
    from ..services import read_layer
    out = set()
    try:
        for ln in read_layer.registry_logicals('waf/base-signature-disable'):
            q = (_db.session.query(DeviceObject.payload)
                 .filter(DeviceObject.appliance_id == appliance_id,
                         _db.or_(DeviceObject.logical_name == ln,
                                 DeviceObject.logical_name.like('%/' + ln))))
            for (payload,) in q.all():
                sid = str((payload or {}).get('signature_id') or '').strip()
                if sid:
                    out.add(sid)
    except Exception:  # noqa: BLE001 — no cache: nothing claimed
        return set()
    return out


def _sig_state_live(appliance, name):
    """Every sub-list read from the device; the first refusal raises (an
    answered empty list is a real empty list)."""
    from ..services import objform
    client = FortiWebClient(appliance)
    state = {}
    for seg, key in _SIG_SUBLISTS.items():
        rows, err = client.list_with_error(objform.scoped_path('waf/signature/%s' % seg, name))
        if err:
            raise RuntimeError('%s: %s' % (seg, err))
        state[key] = rows or []
    return state


def _sig_catalog():
    """The cached signature database (data/signatures.json, written from the
    signature source by ``signature_index``) or ``None``."""
    from ..services import signature_catalog as sigcat
    from ..services import signature_index as sidx
    return sigcat.load_signature_db(sidx.catalog_path())


@bp.route('/<int:id>/signatures/<path:name>')
@login_required
@require_permission('protection.view')
def signature_policy(id, name):
    appliance = visible_appliance_or_404(id)
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
    from ..services import gui_store, signature_dialog_gui as sdg
    sig_fw = gui_store.firmware_of(appliance)
    # FortiWeb draws all ten classes; one the policy has no row for (a policy
    # made over REST) with its defaults, saved by creating the row
    if state_source != 'none':
        state = dict(state, classes=sdg.fill_classes(state.get('classes') or [], sig_fw))
    catalog = _sig_catalog()
    # Class tree for the filters (small: ~10 main classes, ~50 sub-classes).
    classes = {}
    if catalog:
        for s in catalog.signatures:
            m = classes.setdefault(s.main_id, {
                'name': s.main_name or s.main_id, 'subs': {}})
            m['subs'].setdefault(s.sub_id, s.sub_name or s.sub_id)
    # the Dictionaries tree as FortiWeb draws it: main class -> sub-class, each
    # with the status this policy gives it (main_class_list status,
    # sub_class_disable_list), then Search and Filters
    main_on = {str(c.get('main_class_id')): c.get('status') == 'enable'
               for c in state.get('classes') or [] if isinstance(c, dict)}
    # sub_class_disable_list: sub-class id -> its row id (Enable deletes it)
    sub_off = {str(r.get('sub_class_id') or r.get('id') or ''): str(r.get('id', r.get('_id', '')))
               for r in state.get('subclass') or [] if isinstance(r, dict)}
    sdg_data = sdg.data(sig_fw)
    rank = {mid: i for i, mid in enumerate(sdg_data.get('order') or [])}
    # status None = unknown (nothing answered): drawn as unknown, not enabled
    known = state_source != 'none'
    tree = [{'id': mid, 'name': m['name'], 'on': main_on.get(mid) if known else None,
             'subs': [{'id': sid, 'name': sname,
                       'on': ((main_on.get(mid) is not False) and sid not in sub_off) if known else None,
                       'row': sub_off.get(sid, '')}
                      for sid, sname in m['subs'].items()]}
            for mid, m in sorted(classes.items(), key=lambda kv: (rank.get(kv[0], 99), kv[0]))]
    back = request.args.get('back') or ''
    if not (back.startswith('/') and not back.startswith('//')):
        back = url_for('web_protection.menu_page', id=appliance.id, item_key='signatures')
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
        tree=tree,
        back=back,
        sdg=sdg_data,
        threat_levels=THREAT_LEVELS,
    )


@bp.route('/<int:id>/signatures/<path:name>/search')
@login_required
@require_permission('protection.view')
def sig_search(id, name):
    """Signature Details search — the catalog joined with THIS set's state
    (disabled / alert-only / exception count per signature id)."""
    appliance = visible_appliance_or_404(id)
    q = (request.args.get('q') or '').strip().lower()
    main = (request.args.get('main') or '').strip()
    sub = (request.args.get('sub') or '').strip()
    flt = (request.args.get('filter') or '').strip()  # '', disabled, fpm, alert, exception
    # FortiWeb's Search: CVE number (``CVE-2021-44228``), from the FortiGuard
    # metadata a knowledge pack brought (no pack: no CVE is known, said so)
    cve = (request.args.get('cve') or '').strip().upper()
    page = max(request.args.get('page', type=int) or 1, 1)
    per_page = min(max(request.args.get('per_page', type=int) or 100, 10), 400)

    force_live = (request.args.get('live') or '') in ('1', 'true')

    catalog = _sig_catalog()
    if catalog is None:
        return jsonify(ok=False, total=0, rows=[],
                       error='No signature catalog cached — sync it in '
                             'Administrator → Signatures first.')
    state, src = _sig_state(appliance, name, force_live=force_live)
    if src == 'none':
        # nothing answered: every signature would read "enabled" -- say it
        return jsonify(ok=False, total=0, rows=[],
                       error="This policy's signature state could not be read "
                             "(no SATOM cache; the device: %s)." % (state.get('error') or 'no answer'))
    # sig id → sub-row id (needed to DELETE a disable / alert-only row).
    disabled = {str(r.get('signature_id') or '').strip():
                str(r.get('id', r.get('_id', '')))
                for r in state['disable'] if isinstance(r, dict)}
    alert = {str(r.get('signature_id') or '').strip():
             str(r.get('id', r.get('_id', '')))
             for r in state['alert'] if isinstance(r, dict)}
    fpm_off = {str(r.get('signature_id') or '').strip(): str(r.get('id', r.get('_id', '')))
               for r in state.get('fpm') or [] if isinstance(r, dict)}
    # disabled in every policy (Disable in all policies): the cached
    # waf/base-signature-disable rows
    global_off = _global_disabled(appliance.id)
    exc_count = {}
    for r in state['exceptions']:
        if isinstance(r, dict):
            sid = str(r.get('signature_id') or '').strip()
            if sid:
                exc_count[sid] = exc_count.get(sid, 0) + 1

    cve_ids = None
    if cve:
        from ..services import signature_freshness
        allm = signature_freshness.meta_for(appliance.kind or 'fortiweb',
                                            [s.id for s in catalog.signatures])
        cve_ids = {sid for sid, m in allm.items()
                   if any(cve in str(c).upper() for c in m.get('cve') or [])}
        if not allm:
            return jsonify(ok=False, total=0, rows=[],
                           error='No FortiGuard signature metadata imported (knowledge '
                                 'pack), so no CVE is known for any signature.')
    hits = []
    for s in catalog.signatures:
        if cve_ids is not None and s.id not in cve_ids:
            continue
        if main and s.main_id != main:
            continue
        if sub and s.sub_id != sub:
            continue
        if q and q not in s.id and q not in s.desc.lower():
            continue
        if flt == 'disabled' and s.id not in disabled:
            continue
        if flt == 'fpm' and s.id not in fpm_off:
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
        'fpm_disabled': s.id in fpm_off,
        'fpm_row': fpm_off.get(s.id, ''),
        'global_disabled': s.id in global_off,
    } for s in hits[start:start + per_page]]
    # Public FortiGuard metadata (name / severity / CVE / link) from the
    # signature-meta section of an imported knowledge pack, when there is any.
    from ..services import signature_freshness
    meta = signature_freshness.meta_for(appliance.kind or 'fortiweb',
                                        [r['id'] for r in rows])
    for r in rows:
        r['meta'] = meta.get(r['id'])
    return jsonify(ok=True, total=total, page=page, per_page=per_page,
                   source=src, rows=rows)


@bp.route('/<int:id>/signatures/<path:name>/exceptions/<sig_id>')
@login_required
@require_permission('protection.view')
def sig_exceptions(id, name, sig_id):
    """The Exception tab rows for ONE signature id (the set's filter_list
    entries whose ``signature_id`` matches) — freshest source available."""
    appliance = visible_appliance_or_404(id)
    force_live = (request.args.get('live') or '') in ('1', 'true')
    state, src = _sig_state(appliance, name, force_live=force_live)
    rows = [r for r in state['exceptions']
            if isinstance(r, dict)
            and str(r.get('signature_id') or '').strip() == str(sig_id)]
    return jsonify(ok=True, source=src, rows=rows)


#: The fields FortiWeb's Signature Details pane reads off one signature
#: (fwb-signature-detail setDetail / setSample / setThreat, 7.6.8 bundle):
#: nothing else of the answer is passed on.
SIG_DETAIL_FIELDS = ('main_class_name', 'sub_class_name', 'sensitivity_level', 'protocol',
                     'fpm_mitigation', 'fpm_disable', 'alert_only', 'attack_reference',
                     'meet_target', 'sample', 'sample2', 'score', 'default_score', 'concat')


def _sig_ids_ok(sig_id, main, sub) -> bool:
    import re as _re
    return all(_re.fullmatch(r'\d{9}', str(v or '')) for v in (sig_id, main, sub))


class _ReadError(str):
    """Why a read failed; ``status`` = the device's HTTP status, if it refused."""
    def __new__(cls, text, status=None):
        obj = super().__new__(cls, text)
        obj.status = status
        return obj


def _read_sigdetail(client, name, main, sub, sig_id):
    """``(detail, "")`` of one signature from the device
    (``waf/signature.sigdetail``), or ``(None, why)``: unreachable, refused,
    not JSON, or a 200 that carries no signature (HTTP 200 is not success:
    FortiWeb reports refusals in the body)."""
    from urllib.parse import urlencode
    path = '/api/v2.0/waf/signature.sigdetail?' + urlencode(
        {'mkey': name, 'main_class_id': main, 'sub_class_id': sub, 'sig_id': sig_id})
    try:
        resp = client.api_call('GET', path)
    except Exception as exc:  # noqa: BLE001 — unreachable: said, not hidden
        return None, 'device unreachable: %s' % type(exc).__name__
    if resp.status_code != 200:
        return None, _ReadError('the device refused the read (HTTP %s)' % resp.status_code,
                                resp.status_code)
    try:
        body = resp.json()
    except ValueError:
        return None, 'the device answered something that is not JSON'
    res = body.get('results', body) if isinstance(body, dict) else None
    if isinstance(res, list):
        res = res[0] if len(res) == 1 and isinstance(res[0], dict) else None
    if not isinstance(res, dict) or not any(k in res for k in SIG_DETAIL_FIELDS):
        msg = res.get('errcode') if isinstance(res, dict) else None
        return None, ('the device returned no signature detail%s'
                      % (' (errcode %s)' % msg if msg is not None else ''))
    return res, ''


#: FortiWeb's Threat Weight levels, in its slider's order
#: (``THREAT_LEVEL_WITH_OFF``, 7.6.8 GUI bundle): label -> the integer the
#: device stores. ``-1`` puts the signature back on its default. Measured on
#: fortiweb19 7.6.8 (2026-11-01): 7, 0 and -1 are stored as sent; a value
#: outside this set is answered 200 ``status: 1`` and stored as ANOTHER level
#: (3 -> 6), so nothing else is sent.
THREAT_LEVELS = (('Off', 0), ('Informational', 5), ('Low', 1), ('Moderate', 6),
                 ('Substantial', 7), ('Severe', 8), ('Critical', 4))
_SCORE_OK = frozenset([-1] + [v for _l, v in THREAT_LEVELS])


@bp.route('/<int:id>/signatures/<path:name>/detail/<sig_id>/score', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def sig_score(id, name, sig_id):
    """Set one signature's Threat Weight in this signature policy, as
    FortiWeb's Signature Details does (``PUT waf/signature.advanced.signature
    .score?mkey=&sig_id=&score=``, body ``{}``). Pre-check = the current value
    read off the device; dry run unless ``apply``; after the write the
    signature is READ BACK and only the value it holds counts (an accepted
    write the device does not hold FAILS). Recorded in ChangeHistory and the
    Audit Log with the before value and the verdict."""
    from urllib.parse import urlencode
    from ..models import ChangeHistory
    appliance = visible_appliance_or_404(id)
    if getattr(appliance, 'kind', 'fortiweb') != 'fortiweb':
        return jsonify(ok=False, error='Threat Weight is a FortiWeb signature setting'), 400
    body = request.get_json(silent=True) or {}
    main = str(body.get('main') or '').strip()
    sub = str(body.get('sub') or '').strip()
    if not _sig_ids_ok(sig_id, main, sub):
        return jsonify(ok=False, error='signature, main and sub class ids are 9 digits'), 400
    try:
        score = int(body.get('score'))
    except (TypeError, ValueError):
        score = None
    if score not in _SCORE_OK:
        return jsonify(ok=False, error='score must be one of %s'
                       % ', '.join(str(v) for v in sorted(_SCORE_OK))), 400
    client = FortiWebClient(appliance)
    before, err = _read_sigdetail(client, name, main, sub, sig_id)
    if err:
        return jsonify(ok=False, error='pre-check: %s' % err), 502
    path = '/api/v2.0/waf/signature.advanced.signature.score?' + urlencode(
        {'mkey': name, 'sig_id': sig_id, 'score': score})
    req = {'method': 'PUT', 'path': path, 'body': {}}
    was = before.get('score')
    if not body.get('apply'):
        return jsonify(ok=True, dry_run=True, request=req, before=was,
                       default=before.get('default_score'))
    try:
        resp = client.api_call('PUT', path, {})
        ans = resp.json() if resp is not None else None
    except Exception as exc:  # noqa: BLE001
        resp, ans, err = None, None, 'device unreachable: %s' % type(exc).__name__
    if resp is not None:
        res = ans.get('results') if isinstance(ans, dict) else None
        if resp.status_code != 200:
            err = 'the device refused the write (HTTP %s)' % resp.status_code
        elif not isinstance(res, dict) or str(res.get('status')) != '1':
            err = 'the device did not accept the write: %s' % (
                res.get('errcode') if isinstance(res, dict) and 'errcode' in res else ans)
    verdict, held = 'unverified', None
    if not err:
        from ..services import jobs as _jobs
        _jobs.note_write(appliance.id)
        after, rerr = _read_sigdetail(client, name, main, sub, sig_id)
        if rerr:
            verdict = 'unverified'
        else:
            held = after.get('score')
            verdict = 'verified' if str(held) == str(score) else 'mismatch'
            if verdict == 'mismatch':
                err = ('Not applied: the device kept Threat Weight = %s (sent %s)'
                       % (held, score))
    try:
        db.session.add(ChangeHistory(
            appliance_id=appliance.id, endpoint='waf/signature.advanced.signature.score',
            mkey='%s/%s' % (name, sig_id), action='update',
            before=json.dumps({'score': was}), after=json.dumps({'score': score}),
            dry_run=False, username=current_user.username))
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
    log_action('signature.score' + ('.not_applied' if verdict == 'mismatch' else ''),
               target='%s/%s' % (name, sig_id), appliance_id=appliance.id,
               detail='score %s -> %s error=%s' % (was, score, err), verify=verdict)
    return jsonify(ok=not err, dry_run=False, request=req, before=was, score=held,
                   verify=verdict, error=err)


@bp.route('/<int:id>/signatures/<path:name>/detail/<sig_id>')
@login_required
@require_permission('protection.view')
def sig_detail(id, name, sig_id):
    """One signature as FortiWeb's Signature Details pane shows it
    (``waf/signature.sigdetail``: sensitivity level, where it looks, attack
    reference, match example, threat weight). A device read, so an explicit
    operator action (the pane's "Read from device"), audited; a refused read
    is an error with the device's status, never an empty pane."""
    appliance = visible_appliance_or_404(id)
    main = (request.args.get('main') or '').strip()
    sub = (request.args.get('sub') or '').strip()
    if not _sig_ids_ok(sig_id, main, sub):
        return jsonify(ok=False, error='signature, main and sub class ids are 9 digits'), 400
    log_action('signature.detail_read', target='%s/%s' % (name, sig_id),
               appliance_id=appliance.id)
    res, err = _read_sigdetail(FortiWebClient(appliance), name, main, sub, sig_id)
    if err:
        extra = {'status': err.status} if getattr(err, 'status', None) else {}
        return jsonify(ok=False, error=str(err), **extra), 502
    import re as _re
    out = {k: res.get(k) for k in SIG_DETAIL_FIELDS if k in res}
    refs = []
    for line in str(out.get('attack_reference') or '').split('\n'):
        m = _re.match(r'^(.*?)&lt;#(.*?)::(.*?)#&gt;$', line.strip())
        if m:
            refs.append({'label': m.group(2), 'target': m.group(3)})
    out['attack_refs'] = refs
    out['filters'] = [f for f in (res.get('filters') or []) if isinstance(f, dict)]
    return jsonify(ok=True, source='live', detail=out)


# Whitelist of per-user Web Protection view preferences (UserSetting keys are
# stored prefixed with "wpp.").
_WPP_PREF_KEYS = {"hide_default"}

@bp.route('/prefs', methods=['POST'])
@login_required
@require_permission('protection.view')
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
#  the admin approves in Administrator -> Template Library (the existing workflow).      #
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
    appliance = visible_appliance_or_404(id)
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
    appliance = visible_appliance_or_404(id)
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
    approves it in Administrator -> Template Library — same workflow as every template."""
    appliance = visible_appliance_or_404(id)
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
        from ..services import template_compat as tc
        row = tpl.save_template(
            Template.KIND_WEB_PROTECTION, name, body,
            note='Cloned from %s on %s (pending approval)' % (source, appliance.name),
            author=getattr(current_user, 'username', '') or '',
            stamp=tc.stamp_from_appliance(appliance))
        log_action('wpp.save_template', target=source, appliance_id=appliance.id,
                   detail='template=%s v%s status=%s' % (row.name, row.version, row.status))
        return jsonify(ok=True, template_id=row.id, name=row.name,
                       version=row.version, status=row.status,
                       source_firmware=row.source_firmware or '',
                       compat_check=row.compat_check_dict)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc)), 500
