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
from ..clients.fortiweb import FortiWebClient
from ..services.fortiweb_ops import FortiWebOps, sanitize_payload
from ..services.fortiweb_field_schema import ALL_REF_ENDPOINTS
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


def _blank_sample(rows):
    """A blank row template: union of the keys seen across existing rows."""
    sample = {}
    for r in rows or []:
        if isinstance(r, dict):
            for k in r:
                sample.setdefault(k, "")
    return sample


# --------------------------------------------------------------------------- #
#  Editor page (object fields + each sub-table's rows)                          #
# --------------------------------------------------------------------------- #
@bp.route('/<int:appliance_id>/edit')
@login_required
def edit(appliance_id):
    appl = Appliance.query.get_or_404(appliance_id)
    coll = objform.collection_of(request.args.get('collection', ''))
    mkey = request.args.get('mkey', '')
    create = request.args.get('create', '') in ('1', 'true', 'True')
    singleton = request.args.get('singleton', '') in ('1', 'true', 'True')
    title = request.args.get('title', '') or objform.collection_of(coll).rsplit('/', 1)[-1]
    partial = request.args.get('partial', '') in ('1', 'true', 'True')
    tmpl = 'objedit/_body.html' if partial else 'objedit/editor.html'
    if not objform.is_known_collection(coll):
        return render_template(tmpl, appliance=appl, error='Unknown object type',
                               collection=coll, mkey=mkey, title=title, create=create,
                               obj_groups=[], subtables=[]), 400

    # CREATE mode: a blank top-level object — render the curated form skeleton
    # (no device read, no sub-tables; those open once the object exists and the
    # operator is promoted to the normal edit view via ?mkey=<name>).
    if create:
        form = objform.object_form(coll, {})
        return render_template(tmpl, appliance=appl, error=None,
                               collection=coll, mkey='', title=title, create=True,
                               obj_groups=form['groups'], subtables=[])

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

    form = objform.object_form(coll, obj)
    obj_groups = form['groups']
    subtables = []
    for st in form['subtables']:
        rows = _read_rows(client, st['collection'], mkey) if client else []
        subtables.append({
            'label': st['label'], 'collection': st['collection'], 'seg': st['seg'],
            'rows': [{
                'sub_id': r.get('id', r.get('_id', '')),
                'label': objform.row_label(r),
                'groups': objform.field_groups(st['collection'], r, keep_name=True),
            } for r in rows if isinstance(r, dict)],
            'blank_groups': objform.field_groups(st['collection'], objform.blank_row_sample(st['collection'], rows), keep_name=True),
        })

    return render_template(tmpl, appliance=appl, error=error,
                           collection=coll, mkey=mkey, title=title, create=False,
                           obj_groups=obj_groups, subtables=subtables)


@bp.route('/<int:appliance_id>/ref-options')
@login_required
def ref_options(appliance_id):
    """Names of configured objects in a reference field's cmdb collection, so a
    ref ``<select>`` can be CHANGED on the device (not just preserve its current
    value). Allow-list: a schema-declared ref endpoint (incls multi-source
    ``a|b`` forms) OR any known registry collection."""
    appl = Appliance.query.get_or_404(appliance_id)
    coll = request.args.get('endpoint', '')
    if coll not in ALL_REF_ENDPOINTS and not objform.is_known_collection(coll):
        return jsonify(error='endpoint not allowed', names=[]), 400
    try:
        return jsonify(names=FortiWebClient(appl).cmdb_names(coll))
    except Exception as exc:  # noqa: BLE001
        return jsonify(error=str(exc), names=[])


# --------------------------------------------------------------------------- #
#  Writes (dry-run default; apply=true writes through the audited path)         #
# --------------------------------------------------------------------------- #
def _payload(body):
    fields = body.get('fields') or {}
    return {k: v for k, v in fields.items() if isinstance(fields, dict)}


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
    appl = Appliance.query.get_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    coll = objform.collection_of(body.get('collection', ''))
    mkey = body.get('mkey', '')
    fields = _payload(body)
    do_apply = bool(body.get('apply'))
    if not objform.is_known_collection(coll):
        return jsonify(ok=False, error='endpoint not allowed'), 400
    if not fields:
        return jsonify(ok=False, error='no changes to save'), 400
    res = FortiWebOps(appl).update(objform.rest_path(coll), mkey, {'data': fields},
                                   dry_run=not do_apply)
    diff = None
    if do_apply and res.ok:
        _writethrough(appliance_id, coll, mkey, fields, 'update')
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
    appl = Appliance.query.get_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    coll = objform.collection_of(body.get('collection', ''))
    name = (body.get('mkey') or body.get('name') or '').strip()
    fields = _payload(body)
    do_apply = bool(body.get('apply'))
    if not objform.is_known_collection(coll):
        return jsonify(ok=False, error='endpoint not allowed'), 400
    if not name:
        return jsonify(ok=False, error='name required'), 400
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
    appl = Appliance.query.get_or_404(appliance_id)
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
    appl = Appliance.query.get_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    coll = objform.collection_of(body.get('collection', ''))
    parent = body.get('parent', '')
    sub_id = body.get('sub_id')
    do_apply = bool(body.get('apply'))
    if not objform.is_known_collection(coll):
        return jsonify(ok=False, error='endpoint not allowed'), 400
    if sub_id in (None, ''):
        return jsonify(ok=False, error='row id required'), 400

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
    appl = Appliance.query.get_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    coll = objform.collection_of(body.get('collection', ''))
    mkey = body.get('mkey', '')
    do_apply = bool(body.get('apply'))
    if not objform.is_known_collection(coll):
        return jsonify(ok=False, error='endpoint not allowed'), 400
    if not mkey:
        return jsonify(ok=False, error='object name required'), 400
    res = FortiWebOps(appl).delete(objform.rest_path(coll), mkey, dry_run=not do_apply)
    if do_apply and res.ok:
        _writethrough(appliance_id, coll, mkey, {}, 'delete')
    return jsonify(ok=res.ok, dry_run=res.get('dry_run'), request=res.get('request'),
                   error=res.get('error', ''))


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
    appl = Appliance.query.get_or_404(appliance_id)
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
