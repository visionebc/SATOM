"""Generic recursive object editor — the web consumer of ``services.objform``.

Edits ANY FortiWeb cmdb object **and its by-parent sub-tables** (pool→members,
vserver→VIPs, health→rules, SNI→members, content-routing→matches …) through the
audited ``FortiWebOps`` write path (dry-run default). Server Objects, Web
Protection and the Server Policy linked-object cards all open THIS editor, so
deep object editing lives in one place instead of per-area bespoke forms.

Security: every ``collection`` parameter is checked against
``objform.is_known_collection`` (the registry allow-list), so the editor can
never be pointed at an arbitrary REST path. Reads are open to any signed-in
user; writes require ``config_write`` and default to a dry-run preview — a real
device write needs an explicit ``apply=true``.
"""
from urllib.parse import quote

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

from ..auth.decorators import require_permission
from ..models import Appliance
from ..models import visible_appliances, visible_appliance_or_404
from ..clients.fortiweb import FortiWebClient
from ..services.fortiweb_ops import FortiWebOps, sanitize_payload
from ..services.fortiweb_field_schema import ALL_REF_ENDPOINTS, CREATE_FIELDS
from ..services import objform, config_catalog
from ..services.templates import save_template

bp = Blueprint('objedit', __name__, url_prefix='/objedit')


# --------------------------------------------------------------------------- #
#  Sub-tables that hang off a SINGLETON parent (no mkey)                        #
# --------------------------------------------------------------------------- #
# Verified live on fw1 (7.6/8.0): the NTP-server list is a by-parent sub-table
# of the singleton ``system/ntp``. Unlike every other sub-table it is addressed
# PATH-STYLE — a POST/GET carry NO ``?mkey=<parent>`` (that returns HTTP 500),
# and FortiWeb exposes NO per-row delete: ``DELETE ?mkey=<id>`` wipes the WHOLE
# table. So add = a plain POST, and remove/edit = a safe REPLACE-SET (wipe the
# table, re-add the rows we want to keep, and restore the originals if a re-add
# fails so the box is never left without its NTP servers).
_SINGLETON_SUBTABLES = {"system/ntp/ntpserver"}


def _is_singleton_subtable(coll) -> bool:
    return objform.collection_of(coll) in _SINGLETON_SUBTABLES


def _server_field(coll) -> str:
    """The required identity field of a singleton sub-table row."""
    return "server" if objform.collection_of(coll) == "system/ntp/ntpserver" else "name"


def _replace_set(ops, coll, desired, *, dry_run):
    """Rebuild a singleton sub-table to exactly ``desired`` (list of payloads).

    Used for remove/edit, which FortiWeb's REST can't do per-row. On a real
    apply: read the current rows, wipe the table, re-add ``desired``; if any
    re-add fails, re-add the ORIGINAL rows so the device is never left empty.
    Pure preview on ``dry_run``. Returns ``(ok, error)``.
    """
    path = objform.rest_path(coll)
    fld = _server_field(coll)
    desired_payloads = [{fld: d[fld]} for d in desired if d.get(fld)]
    if dry_run:
        return True, ""
    # Snapshot current rows so we can roll back on a partial failure.
    try:
        current = ops.client._safe_list(path) or []
    except Exception:  # noqa: BLE001
        current = []
    originals = [{fld: r.get(fld)} for r in current if isinstance(r, dict) and r.get(fld)]
    # Wipe: a single ``?mkey=<any id>`` delete clears the whole table.
    if current:
        any_id = current[0].get("id", current[0].get("_id", ""))
        ops.delete(path, str(any_id), dry_run=False)
    for p in desired_payloads:
        res = ops.create(path, {"data": p}, dry_run=False)
        if not res.ok:
            # Roll back to the original set, best-effort.
            try:
                cur2 = ops.client._safe_list(path) or []
                if cur2:
                    ops.delete(path, str(cur2[0].get("id", "")), dry_run=False)
                for o in originals:
                    ops.create(path, {"data": o}, dry_run=False)
            except Exception:  # noqa: BLE001
                pass
            return False, res.get("error", "re-add failed; original servers restored")
    return True, ""


# --------------------------------------------------------------------------- #
#  Device reads (parent-scoped — never path-style, which leaks the parent set) #
# --------------------------------------------------------------------------- #
def _read_object(client, coll, mkey, singleton=False):
    if not mkey:
        # A singleton config object (global, dns, ntp, ha, log settings…) has no
        # mkey — read the whole object straight off the collection path so the
        # editor pre-fills with its current values (it saves as a mkey-less PUT).
        if singleton:
            return client._safe_one(objform.rest_path(coll)) or {}
        return {}
    path = '%s?mkey=%s' % (objform.rest_path(coll), quote(mkey, safe=''))
    return client._safe_one(path) or {}


def _read_rows(client, sub_coll, parent):
    """By-parent sub-table rows, scoped with ``?mkey=<parent>``.

    A singleton sub-table (e.g. NTP servers) has no parent mkey and is read
    PATH-STYLE — the ``?mkey=`` form returns HTTP 500 for it.
    """
    if _is_singleton_subtable(sub_coll):
        try:
            return client._safe_list(objform.rest_path(sub_coll)) or []
        except Exception:  # noqa: BLE001
            return []
    if not parent:
        return []
    try:
        return client._safe_list(objform.scoped_path(sub_coll, parent)) or []
    except Exception:  # noqa: BLE001 — dead device / empty table → no rows
        return []


# Collections that must NOT offer "＋ Create new" from a reference dropdown:
# interfaces are hardware-bound, and a Local Certificate's key material can only
# be uploaded over SSH (REST cmdb can't carry a PEM) — a name-only create fails.
_NO_REF_CREATE = {'system/interface', 'system/certificate.local'}


def _enable_ref_actions(groups):
    """FortiWeb-GUI parity for the generic editor: every reference dropdown gets
    the ＋ create-new affordance (the slide-over panel opens the target object's
    full create form), except the few collections a REST create can't build."""
    for sec in groups or []:
        for f in sec.get('fields', ()):
            if f.get('widget') != 'ref' or not f.get('ref'):
                continue
            primary = (f['ref'] or '').split('|')[0]
            f['create_new'] = primary not in _NO_REF_CREATE
    return groups


def _blank_sample(rows):
    """A blank row template: union of the keys seen across existing rows."""
    sample = {}
    for r in rows or []:
        if isinstance(r, dict):
            for k in r:
                sample.setdefault(k, "")
    return sample


# --------------------------------------------------------------------------- #
#  Cache fallback (DB-first net): a live read against an offline or            #
#  license-locked box comes back EMPTY through the silent _safe_* readers —    #
#  the editor then rendered a blank form (looked read-only / contentless).     #
#  Serve the local device cache instead, flagged with a freshness note.        #
# --------------------------------------------------------------------------- #
# The deep-capture tree roots a few objects under their OWN logical name
# (not the registry one) — map the editor collections onto them.
_DEEP_ROOT_ALIAS = {
    'waf/web-protection-profile.inline-protection': 'web_protection_profile',
    'waf/web-protection-profile.offline-protection': 'web_protection_profile',
    'server-policy/policy': 'server_policy',
}

def _registry_logicals(coll) -> list:
    """Registry logical names whose urn resolves to this collection (shared
    TTL-cached reverse map — see ``read_layer.registry_logicals``)."""
    from ..services import read_layer
    return read_layer.registry_logicals(coll)


def _deep_row(appliance_id, coll, mkey):
    """The deep-capture tree node for (coll, mkey) — nested objects live under
    PATH logical names (``server_policy/server_pool``), or a root alias."""
    from ..extensions import db
    from ..models_cache import DeviceObject
    names = _registry_logicals(coll)
    alias = _DEEP_ROOT_ALIAS.get(objform.collection_of(coll))
    deep_names = names + ([alias] if alias else [])
    if not deep_names or not mkey:
        return None
    conds = [DeviceObject.logical_name.in_(deep_names)]
    conds += [DeviceObject.logical_name.like('%/' + n) for n in deep_names]
    return (db.session.query(DeviceObject)
            .filter_by(appliance_id=appliance_id, layer='deep', mkey=str(mkey))
            .filter(db.or_(*conds))
            .order_by(DeviceObject.depth)
            .first())


def _cached_object(appliance_id, coll, mkey):
    """(payload, DeviceObject row) from the local cache, or (None, None).

    Config layer first (the freshest top-level sweep), then the deep-capture
    tree — whose sub-table rows carry ``subtable`` = the REST segment.
    """
    from ..services import read_layer
    if not mkey:
        return None, None
    for ln in _registry_logicals(coll):
        row = read_layer.object_by_mkey(appliance_id, ln, mkey)
        if row is not None:
            return dict(row.payload or {}), row
    row = _deep_row(appliance_id, coll, mkey)
    if row is not None:
        return dict(row.payload or {}), row
    return None, None


def _cached_rows(appliance_id, coll, mkey, seg, row=None) -> list:
    """Cached by-parent sub-table rows. Children only exist in the DEEP layer,
    so when the object payload came from the config sweep (top-level only) the
    deep-tree node for the same (coll, mkey) is looked up for its children."""
    if not seg or not mkey:
        return []
    from ..services import read_layer
    if row is None or getattr(row, 'layer', '') != 'deep':
        row = _deep_row(appliance_id, coll, mkey)
    if row is None:
        return []
    out = []
    for k in read_layer._children(row, subtable=seg):
        p = dict(k.payload or {})
        if k.mkey:
            p.setdefault('id', k.mkey)
        out.append(p)
    return out


def _fleet_sample(coll, seg=None, parent_coll=None) -> dict:
    """Blank-form field template derived from ANY cached object of *coll* across
    the whole fleet (device_objects) — the offline schema source for collections
    with no curated kind. For a sub-table row pass ``seg`` + ``parent_coll``: the
    sample comes from a deep-tree child whose PARENT matches the parent
    collection (seg alone is ambiguous — 'members' exists under several types).
    Returns ``{key: ''}`` for every non-noise payload key, or ``{}``.
    """
    from sqlalchemy.orm import aliased

    from ..extensions import db
    from ..models_cache import DeviceObject
    from ..services.fortiweb_field_schema import is_noise

    row = None
    if seg and parent_coll:
        names = _registry_logicals(parent_coll)
        alias = _DEEP_ROOT_ALIAS.get(objform.collection_of(parent_coll))
        deep_names = names + ([alias] if alias else [])
        if deep_names:
            parent = aliased(DeviceObject)
            conds = [parent.logical_name.in_(deep_names)]
            conds += [parent.logical_name.like('%/' + n) for n in deep_names]
            row = (db.session.query(DeviceObject)
                   .join(parent, DeviceObject.parent_id == parent.id)
                   .filter(DeviceObject.subtable == seg, db.or_(*conds))
                   .first())
    else:
        names = _registry_logicals(coll)
        if names:
            conds = [DeviceObject.logical_name.in_(names)]
            conds += [DeviceObject.logical_name.like('%/' + n) for n in names]
            row = (db.session.query(DeviceObject)
                   .filter(db.or_(*conds))
                   .order_by(DeviceObject.depth)
                   .first())
    payload = dict(getattr(row, 'payload', None) or {})
    return {k: '' for k in payload if isinstance(k, str) and not is_noise(k)}


# --------------------------------------------------------------------------- #
#  Editor page (object fields + each sub-table's rows)                          #
# --------------------------------------------------------------------------- #
@bp.route('/<int:appliance_id>/edit')
@login_required
def edit(appliance_id):
    appl = visible_appliance_or_404(appliance_id)
    coll = objform.collection_of(request.args.get('collection', ''))
    mkey = request.args.get('mkey', '')
    create = request.args.get('create', '') in ('1', 'true', 'True')
    singleton = request.args.get('singleton', '') in ('1', 'true', 'True')
    title = request.args.get('title', '') or objform.collection_of(coll).rsplit('/', 1)[-1]
    partial = request.args.get('partial', '') in ('1', 'true', 'True')
    tmpl = 'objedit/_body.html' if partial else 'objedit/editor.html'
    from ..services import waf_specs
    action_explain = waf_specs.action_explanations()
    if not objform.is_known_collection(coll):
        return render_template(tmpl, appliance=appl, error='Unknown object type',
                               collection=coll, mkey=mkey, title=title, create=create,
                               obj_groups=[], subtables=[], help_info=None,
                               action_explain=action_explain), 400

    # CREATE mode: a blank top-level object — render the curated form skeleton
    # (no device read, no sub-tables; those open once the object exists and the
    # operator is promoted to the normal edit view via ?mkey=<name>).
    if create:
        form = objform.object_form(coll, {})
        # Curated kinds render the FULL blank field set (the device object is
        # empty, so build_groups alone would yield an empty form). Un-curated
        # kinds fall back to the CREATE_FIELDS catalog (the required extras a
        # bare name can't define — a custom Service's port, a VIP's IP) plus a
        # fleet-cached sample of the same collection, so the create form is
        # never just a Name box for an object the device will refuse name-only.
        sample = objform.blank_row_sample(coll)
        for f in CREATE_FIELDS.get(objform.collection_of(coll), []):
            sample.setdefault(f['key'], '')
        if not sample:
            sample = _fleet_sample(coll)
        obj_groups = form['groups'] or objform.field_groups(
            coll, sample, keep_name=False)
        return render_template(tmpl, appliance=appl, error=None,
                               collection=coll, mkey='', title=title, create=True,
                               obj_groups=_enable_ref_actions(obj_groups), subtables=[],
                               help_info=form.get('help'), action_explain=action_explain)

    # Device reads are best-effort: the editor STRUCTURE (fields + sub-tables)
    # always renders from the registry even when the box is unreachable, so the
    # operator sees the object's editable shape regardless of connectivity.
    error = None
    obj = {}
    client = None
    try:
        client = FortiWebClient(appl)
        obj = _read_object(client, coll, mkey, singleton=singleton)
    except Exception as exc:  # noqa: BLE001
        error = str(exc)

    # DB-first net: an offline / license-locked box answers the silent _safe_*
    # readers with NOTHING — fall back to the local device cache so the object
    # is still fully visible (and editable; Save keeps writing to the device).
    data_src = 'live'
    cache_row = None
    freshness = None
    if not obj and mkey:
        cobj, cache_row = _cached_object(appl.id, coll, mkey)
        if cobj:
            from ..services import read_layer
            obj, data_src = cobj, 'cache'
            meta = read_layer._layer_meta(appl.id, layer=cache_row.layer,
                                          section=cache_row.section)
            freshness = read_layer.freshness_label(meta)

    form = objform.object_form(coll, obj)
    obj_groups = _enable_ref_actions(form['groups'])
    subtables = []
    for st in form['subtables']:
        rows = _read_rows(client, st['collection'], mkey) if client else []
        if not rows and data_src == 'cache':
            rows = _cached_rows(appl.id, coll, mkey, st['seg'], row=cache_row)
        # Blank add-row template: curated/seeded keys + existing-row union; a
        # still-empty template (un-curated sub-table on a parent with no rows)
        # falls back to a fleet-cached sample so "Add row" is never a dead form.
        blank = objform.blank_row_sample(st['collection'], rows)
        if not blank:
            blank = _fleet_sample(st['collection'], seg=st['seg'], parent_coll=coll)
        subtables.append({
            'label': st['label'], 'collection': st['collection'], 'seg': st['seg'],
            'rows': [{
                'sub_id': r.get('id', r.get('_id', '')),
                'label': objform.row_label(r),
                'groups': _enable_ref_actions(objform.field_groups(st['collection'], r, keep_name=True)),
            } for r in rows if isinstance(r, dict)],
            'blank_groups': _enable_ref_actions(objform.field_groups(st['collection'], blank, keep_name=True)),
        })

    return render_template(tmpl, appliance=appl, error=error,
                           collection=coll, mkey=mkey, title=title, create=False,
                           obj_groups=obj_groups, subtables=subtables,
                           data_src=data_src, freshness=freshness,
                           help_info=form.get('help'), action_explain=action_explain)


@bp.route('/<int:appliance_id>/ref-options')
@login_required
def ref_options(appliance_id):
    """Names of configured objects in a reference field's cmdb collection, so a
    ref ``<select>`` can be CHANGED on the device (not just preserve its current
    value). Allow-list: a schema-declared ref endpoint (incls multi-source
    ``a|b`` forms) OR any known registry collection."""
    appl = visible_appliance_or_404(appliance_id)
    coll = request.args.get('endpoint', '')
    if coll not in ALL_REF_ENDPOINTS and not objform.is_known_collection(coll):
        return jsonify(error='endpoint not allowed', names=[]), 400
    names, err = [], ''
    try:
        names = FortiWebClient(appl).cmdb_names(coll)
    except Exception as exc:  # noqa: BLE001
        err = str(exc)
    if names:
        return jsonify(names=names, source='live')
    # DB-first net: an offline / license-locked box answers with nothing — serve
    # the cached object names so reference dropdowns stay usable.
    from ..services import read_layer
    cached = read_layer.cached_ref_names(appl.id, coll)
    if cached:
        return jsonify(names=cached, source='cache', error=err)
    return jsonify(names=[], source='live', error=err)


# --------------------------------------------------------------------------- #
#  Writes (dry-run default; apply=true writes through the audited path)         #
# --------------------------------------------------------------------------- #
def _payload(body):
    fields = body.get('fields') or {}
    return {k: v for k, v in fields.items() if isinstance(fields, dict)}


# Team rule: a Web Protection Profile governed by an APPROVED template is
# read-only on every device page. It is edited ONLY in Administrator → WPP
# Templates, and saving there deploys the change to ALL devices.
_WPP_COLLECTIONS = ('waf/web-protection-profile.inline-protection',
                    'waf/web-protection-profile.offline-protection')


def _template_lock_error(coll, name):
    """Non-empty reason when (coll, name) targets a template-managed WPP."""
    coll = objform.collection_of(coll)
    if not any(coll == c or coll.startswith(c + '/') for c in _WPP_COLLECTIONS):
        return ''
    if not name:
        return ''
    from ..services.templates import managed_wpp_names
    if str(name) in managed_wpp_names():
        return ('"%s" is a template-managed profile. Edit it in Administrator '
                '→ WPP Templates — saving an approved template deploys the '
                'change to ALL devices.' % name)
    return ''


def _writethrough(appliance_id, coll, mkey, fields, op):
    """Phase 5: after an APPROVED apply, keep the local source of truth
    consistent (no full re-sweep) and release the edit lease. Best-effort."""
    try:
        from ..services import write_through, lock_service
        if op == 'update':
            write_through.local_update(appliance_id, coll, mkey, fields)
        elif op == 'delete':
            write_through.local_delete(appliance_id, coll, mkey)
        lock_service.release(appliance_id, "%s:%s" % (coll, mkey))
    except Exception:  # noqa: BLE001 — never sink the write
        pass


@bp.route('/<int:appliance_id>/save-object', methods=['POST'])
@require_permission('config_write')
def save_object(appliance_id):
    """Update an object's scalar fields (FortiWeb cmdb write is ``{"data": …}``)."""
    appl = visible_appliance_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    coll = objform.collection_of(body.get('collection', ''))
    mkey = body.get('mkey', '')
    fields = _payload(body)
    do_apply = bool(body.get('apply'))
    if not objform.is_known_collection(coll):
        return jsonify(ok=False, error='endpoint not allowed'), 400
    if not fields:
        return jsonify(ok=False, error='no changes to save'), 400
    lock = _template_lock_error(coll, mkey)
    if lock:
        return jsonify(ok=False, error=lock), 403
    res = FortiWebOps(appl).update(objform.rest_path(coll), mkey, {'data': fields},
                                   dry_run=not do_apply)
    diff = None
    if do_apply and res.ok:
        _writethrough(appliance_id, coll, mkey, fields, 'update')
        # Lifecycle hook (WAF rule 1): swapping a Server Policy's WPP from the
        # generic editor also flags that policy's authored carve-outs stale.
        if (objform.collection_of(coll) == 'server-policy/policy'
                and 'web-protection-profile' in fields):
            try:
                from ..services import wpp_exceptions as exc_store
                new_wpp = fields.get('web-protection-profile') or ''
                exc_store.mark_stale_for_policy(
                    appliance_id, mkey, new_wpp,
                    reason='Server Policy "%s" was re-bound to WPP "%s" on %s.'
                           % (mkey, new_wpp or '?', appl.name))
            except Exception:  # noqa: BLE001 — advisory flag, never sink the save
                pass
    else:
        from ..services import write_through as _wt
        diff = _wt.diff_object(appliance_id, coll, mkey, fields)
    return jsonify(ok=res.ok, dry_run=res.get('dry_run'), request=res.get('request'),
                   diff=diff, error=res.get('error', ''))


@bp.route('/<int:appliance_id>/create-object', methods=['POST'])
@require_permission('config_write')
def create_object(appliance_id):
    """Create a NEW top-level cmdb object (name + a few initial fields).

    Used by the Server Objects "New …" flow and the Content Routing card's 'New
    routing policy' flow: create the object (name + initial fields), then the
    operator opens it in the editor to add its by-parent sub-tables (members,
    rules, match conditions…). Dry-run default; a real create needs ``apply=true``.
    """
    appl = visible_appliance_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    coll = objform.collection_of(body.get('collection', ''))
    name = (body.get('mkey') or body.get('name') or '').strip()
    fields = _payload(body)
    do_apply = bool(body.get('apply'))
    if not objform.is_known_collection(coll):
        return jsonify(ok=False, error='endpoint not allowed'), 400
    if not name:
        return jsonify(ok=False, error='name required'), 400
    # CREATE_FIELDS-declared required extras (a custom Service's port, a VIP's
    # IP): reject here with the real reason instead of letting the device
    # answer an opaque HTTP 500 (errcode -56 "Empty value isn't allowed.").
    missing = [f.get('label') or f['key']
               for f in CREATE_FIELDS.get(coll, [])
               if f.get('required') and not str(fields.get(f['key']) or '').strip()]
    if missing:
        return jsonify(ok=False, error='%s required for this object type'
                       % ' and '.join(missing)), 400
    lock = _template_lock_error(coll, name)
    if lock:
        return jsonify(ok=False, error=lock), 403
    data = {k: v for k, v in fields.items() if v not in (None, '', [])}
    data['name'] = name
    res = FortiWebOps(appl).create(objform.rest_path(coll), {'data': data},
                                   dry_run=not do_apply)
    return jsonify(ok=res.ok, dry_run=res.get('dry_run'), request=res.get('request'),
                   error=res.get('error', ''))


@bp.route('/<int:appliance_id>/save-row', methods=['POST'])
@require_permission('config_write')
def save_row(appliance_id):
    """Create or update a by-parent sub-table row.

    Create → POST ``<sub>?mkey=<parent>``; update → PUT
    ``<sub>?mkey=<parent>&sub_mkey=<id>``. The id stays out of the body.
    """
    appl = visible_appliance_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    coll = objform.collection_of(body.get('collection', ''))
    parent = body.get('parent', '')
    sub_id = body.get('sub_id')
    fields = _payload(body)
    do_apply = bool(body.get('apply'))
    if not objform.is_known_collection(coll):
        return jsonify(ok=False, error='endpoint not allowed'), 400
    if not fields:
        return jsonify(ok=False, error='no changes to save'), 400
    lock = _template_lock_error(coll, parent)
    if lock:
        return jsonify(ok=False, error=lock), 403

    ops = FortiWebOps(appl)

    # Singleton sub-table (NTP servers): no parent mkey. Add = a plain PATH-STYLE
    # POST; edit an existing row = a REPLACE-SET (FortiWeb has no per-row PUT).
    if _is_singleton_subtable(coll):
        path = objform.rest_path(coll)
        fld = _server_field(coll)
        if sub_id in (None, ''):
            res = ops.create(path, {'data': fields}, dry_run=not do_apply)
            return jsonify(ok=res.ok, dry_run=res.get('dry_run'),
                           request=res.get('request'), error=res.get('error', ''))
        rows = ops.client._safe_list(path) or []
        desired = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            rid = str(r.get('id', r.get('_id', '')))
            desired.append({fld: fields.get(fld, r.get(fld))} if rid == str(sub_id)
                           else {fld: r.get(fld)})
        ok, err = _replace_set(ops, coll, desired, dry_run=not do_apply)
        return jsonify(ok=ok, dry_run=not do_apply, error=err,
                       request={'method': 'REPLACE-SET', 'path': path,
                                'body': {'servers': [d.get(fld) for d in desired]}})

    if not parent:
        return jsonify(ok=False, error='parent object required'), 400
    if sub_id in (None, ''):
        path = objform.scoped_path(coll, parent)
        res = ops.create(path, {'data': fields}, dry_run=not do_apply)
    else:
        path = objform.scoped_path(coll, parent, sub_id)
        res = ops.update(path, '', {'data': fields}, dry_run=not do_apply)
    return jsonify(ok=res.ok, dry_run=res.get('dry_run'), request=res.get('request'),
                   error=res.get('error', ''))


@bp.route('/<int:appliance_id>/delete-row', methods=['POST'])
@require_permission('config_write')
def delete_row(appliance_id):
    """Delete a by-parent sub-table row (``<sub>?mkey=<parent>&sub_mkey=<id>``)."""
    appl = visible_appliance_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    coll = objform.collection_of(body.get('collection', ''))
    parent = body.get('parent', '')
    sub_id = body.get('sub_id')
    do_apply = bool(body.get('apply'))
    if not objform.is_known_collection(coll):
        return jsonify(ok=False, error='endpoint not allowed'), 400
    if sub_id in (None, ''):
        return jsonify(ok=False, error='row id required'), 400
    lock = _template_lock_error(coll, parent)
    if lock:
        return jsonify(ok=False, error=lock), 403

    ops = FortiWebOps(appl)

    # Singleton sub-table (NTP servers): no per-row delete on FortiWeb, so remove
    # = REPLACE-SET to every row EXCEPT the one being deleted.
    if _is_singleton_subtable(coll):
        path = objform.rest_path(coll)
        fld = _server_field(coll)
        rows = ops.client._safe_list(path) or []
        desired = [{fld: r.get(fld)} for r in rows
                   if isinstance(r, dict)
                   and str(r.get('id', r.get('_id', ''))) != str(sub_id)
                   and r.get(fld)]
        ok, err = _replace_set(ops, coll, desired, dry_run=not do_apply)
        return jsonify(ok=ok, dry_run=not do_apply, error=err,
                       request={'method': 'REPLACE-SET', 'path': path,
                                'body': {'servers': [d.get(fld) for d in desired]}})

    if not parent:
        return jsonify(ok=False, error='parent + row id required'), 400
    res = ops.delete(objform.scoped_path(coll, parent, sub_id), '',
                     dry_run=not do_apply)
    return jsonify(ok=res.ok, dry_run=res.get('dry_run'), request=res.get('request'),
                   error=res.get('error', ''))


@bp.route('/<int:appliance_id>/delete-object', methods=['POST'])
@require_permission('config_write')
def delete_object(appliance_id):
    """Delete a top-level object (its by-parent sub-tables go with it)."""
    appl = visible_appliance_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    coll = objform.collection_of(body.get('collection', ''))
    mkey = body.get('mkey', '')
    do_apply = bool(body.get('apply'))
    if not objform.is_known_collection(coll):
        return jsonify(ok=False, error='endpoint not allowed'), 400
    if not mkey:
        return jsonify(ok=False, error='object name required'), 400
    lock = _template_lock_error(coll, mkey)
    if lock:
        return jsonify(ok=False, error=lock), 403
    res = FortiWebOps(appl).delete(objform.rest_path(coll), mkey, dry_run=not do_apply)
    if do_apply and res.ok:
        _writethrough(appliance_id, coll, mkey, {}, 'delete')
    return jsonify(ok=res.ok, dry_run=res.get('dry_run'), request=res.get('request'),
                   error=res.get('error', ''))


@bp.route('/<int:appliance_id>/clone-object', methods=['POST'])
@require_permission('config_write')
def clone_object(appliance_id):
    """Clone a top-level object under a new name — FortiWeb's own per-row Clone.

    Reads the source object + its by-parent sub-tables live, strips the
    auto-assigned ids/read-only keys (shared sanitizer), creates the copy and
    then its rows scoped to the new name. Dry-run default; ``apply=true``
    writes through the audited FortiWebOps path.
    """
    appl = visible_appliance_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    coll = objform.collection_of(body.get('collection', ''))
    mkey = (body.get('mkey') or '').strip()
    new_name = (body.get('new_name') or '').strip()
    do_apply = bool(body.get('apply'))
    if not objform.is_known_collection(coll):
        return jsonify(ok=False, error='endpoint not allowed'), 400
    if not mkey or not new_name:
        return jsonify(ok=False, error='mkey and new_name required'), 400
    if new_name == mkey:
        return jsonify(ok=False, error='new name must differ from the source'), 400
    lock = _template_lock_error(coll, new_name)
    if lock:
        return jsonify(ok=False, error=lock), 403

    try:
        client = FortiWebClient(appl)
        obj = _read_object(client, coll, mkey)
        if not obj:
            return jsonify(ok=False, error='"%s" not found on device' % mkey), 404
        subtables = []
        for st in objform.object_form(coll, obj)['subtables']:
            rows = _read_rows(client, st['collection'], mkey)
            subtables.append({'collection': st['collection'], 'seg': st['seg'],
                              'rows': [r for r in rows if isinstance(r, dict)]})
    except Exception as exc:  # noqa: BLE001 — dead device -> cannot clone
        return jsonify(ok=False, error='device read failed: %s' % exc), 502

    drop = {st['seg'] for st in subtables}
    fields = sanitize_payload({k: v for k, v in obj.items() if k not in drop})
    fields['name'] = new_name
    plan = {'object': coll, 'new_name': new_name,
            'rows': sum(len(st['rows']) for st in subtables)}
    if not do_apply:
        return jsonify(ok=True, dry_run=True, plan=plan)

    ops = FortiWebOps(appl)
    res = ops.create(objform.rest_path(coll), {'data': fields}, dry_run=False)
    if not res.ok:
        return jsonify(ok=False, error=res.get('error') or 'create failed')
    row_fail = []
    for st in subtables:
        for r in st['rows']:
            rf = sanitize_payload({k: v for k, v in r.items() if k != 'id'})
            if not rf:
                continue
            rr = ops.create(objform.scoped_path(st['collection'], new_name),
                            {'data': rf}, dry_run=False)
            if not rr.ok:
                row_fail.append({'sub': st['seg'],
                                 'error': rr.get('error') or 'row create failed'})
    return jsonify(ok=not row_fail, dry_run=False, plan=plan,
                   row_failures=row_fail,
                   error=('%d sub-table row(s) failed to copy' % len(row_fail)
                          if row_fail else ''))


# --------------------------------------------------------------------------- #
#  Capture an EXISTING object (+ its sub-tables) as a config template          #
# --------------------------------------------------------------------------- #
def build_config_template_body(coll, mkey, obj, subtables, *, singleton=False):
    """Capture a live object (+ its by-parent sub-tables) as an apply-ready
    config-template body.

    The body is a ROOT node with NO endpoint whose ``subobjects`` are the parent
    object FIRST, then each owned sub-table row. ``bulk.iter_push_items`` emits a
    node's subobjects in list order BEFORE the node itself, so this flattens to
    parent-first / rows-after — the correct create order for OWNED by-parent rows
    (which need their parent to exist). Each node's ``data`` is the FortiWeb write
    body ``{"data": {...}}``; ids / read-only keys are stripped via the shared
    sanitizer so the template applies cleanly (no errcode-10 on auto-ids).
    """
    nodes = []
    drop = {st["seg"] for st in (subtables or [])}
    fields = sanitize_payload({k: v for k, v in (obj or {}).items() if k not in drop})
    if singleton:
        nodes.append({"action": "update", "endpoint": objform.rest_path(coll),
                      "mkey": "", "data": {"data": fields}})
    else:
        fields["name"] = mkey
        nodes.append({"action": "create", "endpoint": objform.rest_path(coll),
                      "mkey": None, "data": {"data": fields}})
        for st in subtables or []:
            for row in st.get("rows", []):
                if not isinstance(row, dict):
                    continue
                rf = sanitize_payload({k: v for k, v in row.items() if k != "id"})
                if rf:
                    nodes.append({"action": "create",
                                  "endpoint": objform.scoped_path(st["collection"], mkey),
                                  "mkey": None, "data": {"data": rf}})
    return {"subobjects": nodes}


@bp.route("/<int:appliance_id>/save-template", methods=["POST"])
@require_permission("operations.template_save")
def save_template_from_object(appliance_id):
    """Capture an EXISTING device object (+ its sub-tables) as a config template.

    Reads the live object and its by-parent rows, builds an apply-ready body, and
    saves it under the section's ``config:<section>`` kind. Lands PENDING (the
    admin approval gate) like every authored template; this NEVER writes to a
    device. Scoped to the Configuration area: the caller passes the GUI section.
    """
    appl = visible_appliance_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    coll = objform.collection_of(body.get("collection", ""))
    mkey = (body.get("mkey") or "").strip()
    section = (body.get("section") or "").strip()
    name = (body.get("name") or "").strip()
    note = (body.get("note") or "").strip()
    singleton = bool(body.get("singleton"))
    if not objform.is_known_collection(coll):
        return jsonify(ok=False, error="endpoint not allowed"), 400
    if section not in config_catalog.SECTION_BY_KEY:
        return jsonify(ok=False, error="unknown section"), 400
    if not name:
        return jsonify(ok=False, error="template name required"), 400
    if not singleton and not mkey:
        return jsonify(ok=False, error="object name required"), 400

    # Live read (best-effort): the object + each by-parent sub-table's rows.
    try:
        client = FortiWebClient(appl)
        obj = _read_object(client, coll, mkey, singleton=singleton)
        subtables = []
        if not singleton:
            for st in objform.object_form(coll, obj)["subtables"]:
                rows = _read_rows(client, st["collection"], mkey)
                subtables.append({"seg": st["seg"], "collection": st["collection"],
                                  "rows": [r for r in rows if isinstance(r, dict)]})
    except Exception as exc:  # noqa: BLE001 — dead device -> cannot capture
        return jsonify(ok=False, error="device read failed: %s" % exc), 502

    if not obj:
        return jsonify(ok=False, error="object not found on device"), 404

    tbody = build_config_template_body(coll, mkey, obj, subtables, singleton=singleton)
    kind = config_catalog.config_template_kind(section)
    try:
        row = save_template(kind, name, tbody, note=note,
                            author=getattr(current_user, "username", ""))
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400
    return jsonify(ok=True, id=row.id, name=row.name, version=row.version,
                   kind=row.kind, status=row.status,
                   item_count=len(tbody["subobjects"]))
