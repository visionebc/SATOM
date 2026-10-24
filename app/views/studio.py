"""Python Studio -- Administrator > Studio (2026-10-20).

One page for the two Python tools, which used to be separate menu entries:

* **Scripts** -- the Script Library list (scripts with a form that operators
  run). The editor stays in ``views.script_library`` under ``/studio/scripts``.
* **Console** -- the scratch Python console over the curated datasets
  (``services.py_console``), formerly ``/database/py-console``.

Each pane keeps its own key and its own sandbox: the console runs in a
bubblewrap jail with no network that only receives the masked, SELECT-only
data bundle; scripts run in ``satom-scripts.service`` with the network their
author declared. Uniting the pages unites neither the keys nor the jails.
"""
from __future__ import annotations

from flask import (Blueprint, Response, abort, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_any_permission, require_permission
from ..services import plugin_sandbox
from ..services import py_console as pyc
from ..services import py_examples
from ..services.audit import log_action

bp = Blueprint("studio", __name__, url_prefix="/studio")

#: The largest Studio request is a CSV import (8 MiB, checked by its route).
MAX_BODY = 12 * 1024 * 1024


@bp.before_request
def _bounded_bodies():
    from ..services.request_limits import refuse_larger_than
    return refuse_larger_than(MAX_BODY)
CONSOLE = "studio.python_console"
LIBRARY = "studio.script_library"
#: "scripts" is gone (2026-10-23: every script is an app); an old link to it
#: lands on Apps.
PANES = ("apps", "console", "stores", "connections", "apis", "examples")


def _who() -> str:
    return getattr(current_user, "username", "?")


@bp.route("/")
@login_required
@require_any_permission(LIBRARY, CONSOLE)
def index():
    from ..services import sandbox
    from ..services import script_library as SL
    can_console = current_user.can(CONSOLE)
    can_library = current_user.can(LIBRARY)
    pane = request.args.get("pane")
    if pane == "scripts":
        pane = "apps"
    if pane not in PANES or (pane != "console" and not can_library) \
            or (pane == "console" and not can_console):
        pane = "apps" if can_library else "console"
    from ..extensions import db
    from ..services import studio_apps as SA
    from ..services import studio_apis as SAPI
    from ..services import studio_connections as SC
    from ..services import studio_store as SS
    apis = []
    if can_library:
        for a in SAPI.list_apis():
            vs = SAPI.versions(a)
            lt = SAPI.latest(a)
            apis.append({"a": a, "versions": len(vs), "latest": lt.version if lt else "",
                         "drafts": sum(1 for v in vs if v.status == "draft"),
                         "connections": [c.slug for c in SAPI.connections_of(a)]})
        try:
            SA.adopt_scripts(_who())
        except Exception:  # noqa: BLE001 -- a read-only standby lists what is there
            db.session.rollback()
    return render_template(
        "studio/index.html", pane=pane,
        can_console=can_console, can_library=can_library,
        stores=SS.list_stores() if can_library else [],
        connections=SC.list_connections() if can_library else [],
        apis=apis,
        apps=SA.list_rows() if can_library else [],
        runs=SL.recent_runs(limit=15) if can_library else [],
        datasets=plugin_sandbox.dataset_catalog() if can_console else [],
        examples=py_examples.all_examples() if can_console else [],
        bundles=_bundles() if can_library else [],
        sandbox_ok=sandbox.available())


def _bundles() -> list[dict]:
    from ..services import studio_examples as EX
    links = {"connection": "studio.connection", "store": "studio.store",
             "script": "script_library.edit", "app": "studio.app_edit"}
    out = EX.status()
    for b in out:
        for o in b["objects"]:
            o["url"] = url_for(links[o["kind"]], slug=o["slug"]) if o["installed"] else ""
    return out


@bp.route("/examples/<key>/install", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def example_install(key):
    """Create the missing objects of an example bundle. Existing objects with
    the same id are kept as they are (an edited example survives)."""
    from ..services import studio_examples as EX
    from ..extensions import db
    if key not in EX.BUNDLE_KEYS:
        abort(404)
    try:
        res = EX.install(key, _who())
    except Exception as exc:  # noqa: BLE001 -- any layer's refusal, shown as is
        db.session.rollback()
        return _err(exc)
    log_action("studio.example.install", target=key, extra=res)
    return jsonify({"ok": True, **res})


# A locked-down bwrap sandbox (services.py_console) runs ADMIN-authored
# arbitrary Python over the SAME curated, masked, SELECT-only datasets the
# plugins use (services.plugin_sandbox.load_datasets). The sandbox has NO
# secrets, NO network and NO app filesystem -- the security contract is pinned
# by tests/test_py_console.py. Every run is audited.
@bp.route("/console/run", methods=["POST"])
@login_required
@require_permission(CONSOLE)
def console_run():
    body = request.get_json(silent=True) or {}
    source = (body.get("source") or "")[:100_000]
    req_keys = body.get("datasets") or []
    known = {d["key"] for d in plugin_sandbox.dataset_catalog()}
    # dedupe + keep only entitled dataset keys -- a client can never widen access
    keys = [k for k in dict.fromkeys(req_keys) if k in known]
    bundle = plugin_sandbox.load_datasets(keys)
    result = pyc.run_python(source, bundle)
    log_action("py_console.run", target="python-console", extra={
        "datasets": keys,
        "ok": result["ok"],
        "returncode": result["returncode"],
        "timed_out": result["timed_out"],
        "duration_ms": result["duration_ms"],
        "source": source[:1000],
    })
    return jsonify({**result, "datasets": keys})


# =========================================================================== #
#  Data stores (Python Studio > Data stores) -- the author's key              #
# =========================================================================== #
def _store_or_404(slug):
    from ..services import studio_store as SS
    st = SS.get(slug)
    if st is None:
        abort(404)
    return st


def _err(exc, code=400):
    return jsonify({"ok": False, "error": str(exc)}), code


@bp.route("/stores/create", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def store_create():
    from ..services import studio_store as SS
    slug = (request.form.get("slug") or "").strip()
    try:
        SS.create(slug, request.form.get("name") or "", _who())
    except SS.StoreError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("studio.index", pane="stores"))
    log_action("studio.store.create", target=slug)
    return redirect(url_for("studio.store", slug=slug))


@bp.route("/stores/<slug>")
@login_required
@require_permission(LIBRARY)
def store(slug):
    from ..services import studio_store as SS
    st = _store_or_404(slug)
    from ..services import studio_examples as EX
    return render_template("studio/store.html", store=st, column_types=SS.COLUMN_TYPES,
                           template=EX.is_template("store", slug),
                           rows=SS.query(st, limit=SS.MAX_QUERY_LIMIT), count=SS.count(st),
                           limits={"rows": SS.MAX_ROWS, "columns": SS.MAX_COLUMNS})


@bp.route("/stores/<slug>/schema", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def store_schema(slug):
    from ..services import studio_store as SS
    st = _store_or_404(slug)
    body = request.get_json(silent=True) or {}
    try:
        warnings = SS.save_schema(st, body.get("name") or "", body.get("description") or "",
                                  body.get("columns"), _who())
    except SS.StoreError as exc:
        return _err(exc)
    log_action("studio.store.schema", target=slug,
               extra={"columns": [c["name"] for c in st.columns], "warnings": warnings})
    return jsonify({"ok": True, "columns": st.columns, "warnings": warnings})


@bp.route("/stores/<slug>/rows", methods=["GET", "POST"])
@login_required
@require_permission(LIBRARY)
def store_rows(slug):
    from ..services import studio_store as SS
    st = _store_or_404(slug)
    if request.method == "GET":
        import json as _json
        try:
            flt = _json.loads(request.args.get("filter") or "{}")
            return jsonify({"rows": SS.query(st, flt, limit=request.args.get("limit") or 500)})
        except (ValueError, SS.StoreError) as exc:
            return _err(exc)
    body = request.get_json(silent=True) or {}
    try:
        row = SS.insert(st, body.get("values") or {}, _who())
    except SS.StoreError as exc:
        return _err(exc)
    log_action("studio.store.row_insert", target=slug, extra={"row": row["_id"]})
    return jsonify({"ok": True, "row": row})


@bp.route("/stores/<slug>/rows/<int:rid>", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def store_row_update(slug, rid):
    from ..services import studio_store as SS
    st = _store_or_404(slug)
    body = request.get_json(silent=True) or {}
    try:
        row = SS.update(st, rid, body.get("values") or {}, _who())
    except SS.StoreError as exc:
        return _err(exc)
    log_action("studio.store.row_update", target=slug, extra={"row": rid})
    return jsonify({"ok": True, "row": row})


@bp.route("/stores/<slug>/rows/<int:rid>/delete", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def store_row_delete(slug, rid):
    from ..services import studio_store as SS
    st = _store_or_404(slug)
    if not SS.delete_row(st, rid):
        return _err("row %s not found" % rid, 404)
    log_action("studio.store.row_delete", target=slug, extra={"row": rid})
    return jsonify({"ok": True})


@bp.route("/stores/<slug>/export.csv")
@login_required
@require_permission(LIBRARY)
def store_export(slug):
    from ..services import studio_store as SS
    st = _store_or_404(slug)
    log_action("studio.store.export", target=slug)
    return Response(SS.to_csv(st), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=%s.csv" % st.slug})


@bp.route("/stores/<slug>/import", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def store_import(slug):
    from ..services import studio_store as SS
    st = _store_or_404(slug)
    f = request.files.get("file")
    if f is None or not f.filename:
        return _err("choose a .csv file")
    raw = f.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        return _err("the file is larger than 8 MiB")
    try:
        res = SS.from_csv(st, raw.decode("utf-8-sig", "replace"), _who())
    except SS.StoreError as exc:
        return _err(exc)
    log_action("studio.store.import", target=slug, extra=res)
    return jsonify({"ok": True, **res})


@bp.route("/stores/<slug>/delete", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def store_delete(slug):
    from ..services import studio_store as SS
    from ..services import studio_apps as SA
    from ..services import studio_examples as EX
    st = _store_or_404(slug)
    if EX.is_template("store", slug):
        return _err("%s is a template (Examples): templates are not deleted" % slug, 409)
    users = SA.used_by("store", slug)
    if users:
        return _err("used by app(s) %s: remove it from them first" % ", ".join(users), 409)
    n = SS.delete_store(st)
    log_action("studio.store.delete", target=slug, extra={"rows": n})
    return jsonify({"ok": True, "rows": n})


# =========================================================================== #
#  Connections (Python Studio > Connections)                                   #
# =========================================================================== #
def _conn_or_404(slug):
    from ..services import studio_connections as SC
    c = SC.get(slug)
    if c is None:
        abort(404)
    return c


@bp.route("/connections/create", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def connection_create():
    from ..services import studio_connections as SC
    slug = (request.form.get("slug") or "").strip()
    try:
        SC.create(slug, request.form.get("name") or "", request.form.get("kind") or "http", _who())
    except SC.ConnectionError_ as exc:
        flash(str(exc), "danger")
        return redirect(url_for("studio.index", pane="connections"))
    log_action("studio.connection.create", target=slug)
    return redirect(url_for("studio.connection", slug=slug))


@bp.route("/connections/<slug>")
@login_required
@require_permission(LIBRARY)
def connection(slug):
    from ..services import studio_connections as SC
    from ..services import studio_apis as SAPI
    c = _conn_or_404(slug)
    secret, problem = SC.secret_state(slug)
    from ..services import studio_examples as EX
    return render_template("studio/connection.html", c=c, has_secret=SC.has_secret(slug),
                           template=EX.is_template("connection", slug),
                           secret_problem=problem, http_auth=SC.HTTP_AUTH, methods=SC.METHODS,
                           api_versions=SAPI.bindable() if c.kind == "http" else [])


@bp.route("/connections/<slug>/save", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def connection_save(slug):
    from ..services import studio_connections as SC
    from ..services import studio_apis as SAPI
    c = _conn_or_404(slug)
    body = request.get_json(silent=True) or {}
    before = c.api_version_id
    # Moving the connection to another API version: the app steps that call
    # an endpoint the new version lacks are named, and the move needs
    # "confirm" (they stop being publishable and fail when they run).
    impact = []
    if c.kind == "http" and "api_version_id" in body:
        try:
            new = SAPI.resolve_binding(body.get("api_version_id"))
        except SAPI.ApiError as exc:
            return _err(exc)
        if (new.id if new else None) != before:
            impact = SAPI.impact(c, new)
            if impact and not body.get("confirm"):
                return jsonify({"ok": False, "needs_confirm": True, "impact": impact,
                                "error": "%d app step(s) call an endpoint %s does not have"
                                         % (len(impact), new.label)}), 409
    try:
        dropped = SC.save(c, body, _who())
    except SC.ConnectionError_ as exc:
        from ..extensions import db
        db.session.rollback()
        return _err(exc)
    log_action("studio.connection.save", target=slug,
               extra={"kind": c.kind, "auth": c.auth, "base_url": c.base_url, "host": c.host,
                      "secret_dropped": dropped,
                      "api_version": c.api_version.label if c.api_version else None,
                      "api_version_was": before, "impact": impact})
    return jsonify({"ok": True, "secret_dropped": dropped, "has_secret": SC.has_secret(slug),
                    "impact": impact})


@bp.route("/connections/<slug>/secret", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def connection_secret(slug):
    """Write-only: nothing here ever returns a stored value."""
    from ..services import studio_connections as SC
    _conn_or_404(slug)
    value = str((request.get_json(silent=True) or {}).get("value") or "")
    try:
        SC.set_secret(slug, value)
    except SC.ConnectionError_ as exc:
        return _err(exc)
    log_action("studio.connection.secret", target=slug, extra={"cleared": not value})
    return jsonify({"ok": True, "has_secret": SC.has_secret(slug)})


@bp.route("/connections/<slug>/test", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def connection_test(slug):
    from ..services import studio_connections as SC
    c = _conn_or_404(slug)
    body = request.get_json(silent=True) or {}
    res = SC.test(c, method=str(body.get("method") or "GET"), path=str(body.get("path") or ""),
                  sql=str(body.get("sql") or ""), extract=str(body.get("extract") or ""))
    log_action("studio.connection.test", target=slug,
               extra={"ok": res.get("ok"), "status": res.get("status"), "path": body.get("path")})
    return jsonify(res)


@bp.route("/connections/<slug>/delete", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def connection_delete(slug):
    from ..services import studio_connections as SC
    from ..services import studio_apps as SA
    from ..services import studio_examples as EX
    c = _conn_or_404(slug)
    if EX.is_template("connection", slug):
        return _err("%s is a template (Examples): templates are not deleted" % slug, 409)
    users = SA.used_by("connection", slug)
    if users:
        return _err("used by app(s) %s: remove it from them first" % ", ".join(users), 409)
    scripts = SC.used_by_scripts(slug)
    if scripts:
        return _err("declared by script(s) %s: remove it from their settings first"
                    % ", ".join(scripts), 409)
    SC.delete(c)
    log_action("studio.connection.delete", target=slug)
    return jsonify({"ok": True})


# =========================================================================== #
#  API Catalog (Python Studio > API Catalog) -- FA-0006                        #
# =========================================================================== #
def _api_or_404(slug):
    from ..services import studio_apis as SAPI
    a = SAPI.get(slug)
    if a is None:
        abort(404)
    return a


def _version_or_404(a, version):
    from ..services import studio_apis as SAPI
    v = SAPI.get_version(a, version)
    if v is None:
        abort(404)
    return v


def _api_call(fn, action, target, extra=None):
    """Run a catalog change; a refusal is a 400 with its text."""
    from ..extensions import db
    from ..services import studio_apis as SAPI
    try:
        res = fn()
    except SAPI.ApiError as exc:
        db.session.rollback()
        return _err(exc)
    log_action(action, target=target, extra=extra if extra is not None else (res or {}))
    return jsonify({"ok": True, **(res or {})})


@bp.route("/apis/create", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def api_create():
    from ..services import studio_apis as SAPI
    slug = (request.form.get("slug") or "").strip()
    try:
        SAPI.create(slug, request.form.get("name") or "", _who())
    except SAPI.ApiError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("studio.index", pane="apis"))
    log_action("studio.api.create", target=slug)
    return redirect(url_for("studio.api", slug=slug))


@bp.route("/apis/<slug>")
@login_required
@require_permission(LIBRARY)
def api(slug):
    from ..services import studio_apis as SAPI
    a = _api_or_404(slug)
    users = SAPI.connections_of(a)
    by_version = {}
    for c in users:
        by_version.setdefault(c.api_version_id, []).append(c.slug)
    return render_template("studio/api.html", a=a, versions=SAPI.versions(a),
                           connections=users, by_version=by_version)


@bp.route("/apis/<slug>/save", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def api_save(slug):
    from ..services import studio_apis as SAPI
    a = _api_or_404(slug)
    return _api_call(lambda: SAPI.save(a, request.get_json(silent=True) or {}, _who()),
                     "studio.api.save", slug, {})


@bp.route("/apis/<slug>/delete", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def api_delete(slug):
    from ..services import studio_apis as SAPI
    a = _api_or_404(slug)
    n = len(a.versions)
    return _api_call(lambda: SAPI.delete(a), "studio.api.delete", slug, {"versions": n})


@bp.route("/apis/<slug>/versions/create", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def api_version_create(slug):
    from ..services import studio_apis as SAPI
    a = _api_or_404(slug)
    body = request.get_json(silent=True) or {}
    src = None
    if body.get("copy_from"):
        src = SAPI.get_version(a, str(body["copy_from"]))
        if src is None:
            return _err("version %s does not exist" % body["copy_from"], 404)

    def go():
        v = SAPI.create_version(a, str(body.get("version") or ""), _who(), copy_from=src)
        return {"version": v.version, "url": url_for("studio.api_version", slug=slug, version=v.version)}
    return _api_call(go, "studio.api.version_create", slug,
                     {"version": body.get("version"), "copy_from": body.get("copy_from")})


@bp.route("/apis/<slug>/v/<version>")
@login_required
@require_permission(LIBRARY)
def api_version(slug, version):
    from ..services import studio_api_spec as SP
    a = _api_or_404(slug)
    v = _version_or_404(a, version)
    users = [c.slug for c in _version_users(v)]
    return render_template("studio/api_version.html", a=a, v=v, ops=v.operations,
                           methods=SP.METHODS, param_in=SP.PARAM_IN, users=users,
                           limits={"operations": SP.MAX_OPERATIONS,
                                   "spec_mib": SP.MAX_SPEC_BYTES // 1024 // 1024})


def _version_users(v):
    from ..models_studio import StudioConnection
    return StudioConnection.query.filter_by(api_version_id=v.id).order_by(StudioConnection.slug).all()


@bp.route("/apis/<slug>/v/<version>/import", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def api_version_import(slug, version):
    """An OpenAPI 3 / Swagger 2 document, uploaded or pasted (JSON or YAML)."""
    from ..services import studio_api_spec as SP
    from ..services import studio_apis as SAPI
    a = _api_or_404(slug)
    v = _version_or_404(a, version)
    f = request.files.get("file")
    if f is not None and f.filename:
        raw = f.read(SP.MAX_SPEC_BYTES + 1)
        text = raw.decode("utf-8-sig", "replace")
    else:
        text = str((request.get_json(silent=True) or {}).get("text") or request.form.get("text") or "")
    if not text.strip():
        return _err("choose a file or paste the document")
    return _api_call(lambda: SAPI.import_openapi(v, text, _who()),
                     "studio.api.import", "%s/%s" % (slug, version))


@bp.route("/apis/<slug>/v/<version>/save", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def api_version_save(slug, version):
    from ..services import studio_apis as SAPI
    a = _api_or_404(slug)
    v = _version_or_404(a, version)
    body = request.get_json(silent=True) or {}

    def go():
        SAPI.save_draft(v, operations=body.get("operations"), notes=body.get("notes"),
                        base_path=body.get("base_path"), by=_who())
        return {"operations": len(v.operations)}
    return _api_call(go, "studio.api.version_save", "%s/%s" % (slug, version))


@bp.route("/apis/<slug>/v/<version>/publish", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def api_version_publish(slug, version):
    from ..services import studio_apis as SAPI
    a = _api_or_404(slug)
    v = _version_or_404(a, version)
    return _api_call(lambda: SAPI.publish(v, _who()), "studio.api.publish",
                     "%s/%s" % (slug, version), {"operations": len(v.operations)})


@bp.route("/apis/<slug>/v/<version>/deprecate", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def api_version_deprecate(slug, version):
    from ..services import studio_apis as SAPI
    a = _api_or_404(slug)
    v = _version_or_404(a, version)
    on = bool((request.get_json(silent=True) or {}).get("on", True))
    return _api_call(lambda: SAPI.set_deprecated(v, on, _who()), "studio.api.deprecate",
                     "%s/%s" % (slug, version), {"on": on})


@bp.route("/apis/<slug>/v/<version>/delete", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def api_version_delete(slug, version):
    from ..services import studio_apis as SAPI
    a = _api_or_404(slug)
    v = _version_or_404(a, version)
    return _api_call(lambda: SAPI.delete_version(v), "studio.api.version_delete",
                     "%s/%s" % (slug, version), {})


@bp.route("/apis/<slug>/v/<version>/endpoints.json")
@login_required
@require_permission(LIBRARY)
def api_version_export(slug, version):
    """The endpoint list as JSON -- the same shape the manual editor saves,
    so it can be pasted into another version or another SATOM."""
    import json as _json
    a = _api_or_404(slug)
    v = _version_or_404(a, version)
    return Response(_json.dumps(v.operations, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=%s-%s-endpoints.json"
                             % (a.slug, v.version)})


@bp.route("/apis/<slug>/compare")
@login_required
@require_permission(LIBRARY)
def api_compare(slug):
    from ..services import studio_apis as SAPI
    a = _api_or_404(slug)
    old = SAPI.get_version(a, request.args.get("a") or "")
    new = SAPI.get_version(a, request.args.get("b") or "")
    if old is None or new is None:
        return _err("pick two versions of %s" % slug, 404)
    return jsonify({"ok": True, "a": old.version, "b": new.version, **SAPI.compare(old, new)})


# =========================================================================== #
#  Apps (Python Studio > Apps) -- the author's side                            #
# =========================================================================== #
def _app_or_404(slug):
    from ..services import studio_apps as SA
    a = SA.get(slug)
    if a is None:
        abort(404)
    return a


def _product_key() -> str:
    from flask import g, session
    from ..branding import get_product
    return get_product(getattr(g, "product", None) or session.get("product"))["key"]


def _adom_choices() -> list[tuple[str, str]]:
    from ..branding import PRODUCTS
    return [(k, v.get("name") or k) for k, v in PRODUCTS.items()
            if not v.get("placeholder")]


@bp.route("/apps/create", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_create():
    """New app. Kind "flow" = a form and a diagram; kind "script" = Python
    code with a form, run in the sandbox (the Script Library editor), whose
    app is created with it under the same id."""
    from ..services import script_library as SL
    from ..services import studio_apps as SA
    slug = (request.form.get("slug") or "").strip()
    kind = request.form.get("kind") or "flow"
    try:
        if kind == "script":
            if SA.get(slug) is not None:
                raise SA.AppError("an app with id %s already exists" % slug)
            SL.create(slug, request.form.get("name") or "", _who())
            SA.ensure_script_app(slug, _who())
        else:
            SA.create(slug, request.form.get("name") or "", _who())
    except (SA.AppError, SL.ScriptError) as exc:
        flash(str(exc), "danger")
        return redirect(url_for("studio.index", pane="apps"))
    log_action("studio.app.create", target=slug, extra={"kind": kind})
    if kind == "script":
        return redirect(url_for("script_library.edit", slug=slug))
    return redirect(url_for("studio.app_edit", slug=slug))


@bp.route("/apps/<slug>")
@login_required
@require_permission(LIBRARY)
def app_edit(slug):
    from ..models import User
    from ..models_studio import UserGroup
    from ..services import studio_apps as SA
    from ..services import studio_design as D
    from ..services import studio_flow as F
    a = _app_or_404(slug)
    if a.kind == "script":  # its form, code and versions live in the script editor
        return redirect(url_for("script_library.edit", slug=a.script_slug))
    ch = SA.choices()
    return render_template(
        "studio/app.html", a=a, problems=SA.problems(a), kinds=F.kinds(ch),
        kinds_json=F.kinds_json(ch), branches=F.BRANCHES, field_types=SA.FIELD_TYPES,
        action_schema=SA.action_schema(ch), choices=ch, adoms=_adom_choices(),
        groups=UserGroup.query.order_by(UserGroup.name).all(),
        users=User.query.filter_by(is_active=True).order_by(User.username).all(),
        runs=SA.recent_runs(a, current_user), used_by=SA.used_by("app", slug),
        template=SA.is_template(a), design_schema=D.schema(), design=a.design or D.empty(),
        assets=[_asset_json(a, r) for r in D.assets_of(a.id)],
        output_titles=D.output_titles(a.graph))


@bp.route("/apps/<slug>/settings", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_settings(slug):
    from ..services import studio_apps as SA
    a = _app_or_404(slug)
    body = request.get_json(silent=True) or {}
    try:
        SA.save_settings(a, body, [k for k, _ in _adom_choices()], _who())
    except SA.AppError as exc:
        from ..extensions import db
        db.session.rollback()
        return _err(exc)
    log_action("studio.app.settings", target=slug,
               extra={"adoms": a.adoms, "access": a.access})
    return jsonify({"ok": True})


@bp.route("/apps/<slug>/draft", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_draft(slug):
    from ..services import studio_apps as SA
    a = _app_or_404(slug)
    body = request.get_json(silent=True) or {}
    try:
        SA.save_draft(a, fields=body.get("fields"), actions=body.get("actions"), by=_who())
    except SA.AppError as exc:
        from ..extensions import db
        db.session.rollback()
        return _err(exc)
    log_action("studio.app.draft", target=slug,
               extra={"fields": len(a.fields), "actions": len(a.actions)})
    return jsonify({"ok": True, "problems": SA.problems(a)})


@bp.route("/apps/<slug>/export")
@login_required
@require_permission(LIBRARY)
def app_export(slug):
    """The app as an unsigned satom.plugin/1 package (kind app): its form,
    diagram, actions, data stores, connections without secrets and API
    Catalog versions."""
    from flask import Response
    from ..services import studio_app_package as SAP
    from ..version import app_version
    a = _app_or_404(slug)
    name, data = SAP.export_app(a, app_version())
    log_action("studio.app.export", target=slug)
    return Response(data, mimetype="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % name})


@bp.route("/apps/<slug>/analyze", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_analyze(slug):
    """What the diagram does, step by step, and what happens when each step
    fails -- for the graph being edited (posted) or the saved draft."""
    from ..services import studio_apps as SA
    from ..services import studio_flow as F
    a = _app_or_404(slug)
    body = request.get_json(silent=True) or {}
    graph = body.get("graph") if isinstance(body.get("graph"), dict) else a.graph
    return jsonify({"ok": True, **F.analyze(graph, SA.choices(), fields=a.fields)})


@bp.route("/apps/<slug>/last-run")
@login_required
@require_permission(LIBRARY)
def app_last_run(slug):
    """The newest run of this app, steps in full (the author's view) -- for
    the diagram overlay."""
    from ..services import studio_apps as SA
    a = _app_or_404(slug)
    runs = SA.recent_runs(a, current_user)
    if not runs:
        return jsonify({"ok": True, "run": None})
    return jsonify({"ok": True, "run": SA.run_json(runs[0], a, current_user)})


@bp.route("/apps/<slug>/graph", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_graph(slug):
    """The diagram editor (process_editor.js) posts the graph itself."""
    from ..services import studio_apps as SA
    a = _app_or_404(slug)
    try:
        SA.save_draft(a, graph=request.get_json(silent=True) or {}, by=_who())
    except SA.AppError as exc:
        return jsonify({"ok": False, "errors": [str(exc)]}), 400
    g = a.graph
    log_action("studio.app.graph", target=slug, extra={"nodes": len(g["nodes"]), "edges": len(g["edges"])})
    return jsonify({"ok": True, "nodes": len(g["nodes"]), "edges": len(g["edges"]),
                    "problems": SA.problems(a)})


@bp.route("/apps/<slug>/design", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_design(slug):
    """The Design tab saves the whole design (theme, page, result)."""
    from ..extensions import db
    from ..services import studio_apps as SA
    from ..services import studio_design as D
    a = _app_or_404(slug)
    if a.kind != "flow":
        return _err("a script app is designed in the Script Library")
    try:
        SA.save_draft(a, design=(request.get_json(silent=True) or {}).get("design") or {}, by=_who())
    except SA.AppError as exc:
        db.session.rollback()
        return _err(exc)
    d = a.design
    log_action("studio.app.design", target=slug,
               extra={s: sum(1 for _ in D.walk(d.get(s))) for s in D.SURFACES})
    return jsonify({"ok": True, "problems": SA.problems(a), "warnings": D.warnings(d)})


@bp.route("/apps/<slug>/design/preview", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_design_preview(slug):
    """The design being edited, drawn: ``mode`` "edit" = exactly the blocks,
    with the editor's handles; "view" = what users get (fields left out and
    a missing Run button / result area added). Nothing is saved."""
    from ..services import studio_apps as SA
    from ..services import studio_design as D
    a = _app_or_404(slug)
    body = request.get_json(silent=True) or {}
    surface = body.get("surface") if body.get("surface") in D.SURFACES else "page"
    editing = body.get("mode") != "view"
    try:
        design = D.clean(body.get("design") or {})
    except D.DesignError as exc:
        return _err(exc)
    fields = SA.form_view(a.fields)
    if surface == "page":
        tree = design["page"] if editing else D.page_tree(design, fields)
        html = render_template("apps/_design_page.html", tree=tree or [], D=D, a=a, editing=editing,
                               theme=design["theme"], prefix="d-",
                               fields_by_name={f["name"]: f for f in fields},
                               all_runs=SA.recent_runs(a, current_user)) if tree is not None else ""
        sample = None
    else:
        html = D.render_result(design, graph=a.graph, editing=editing, app=a)
        runs = SA.recent_runs(a, current_user)
        sample = SA.run_json(runs[0], a, current_user) if runs else None
        if sample:
            sample.pop("layout", None)
    return jsonify({"ok": True, "html": html, "sample": sample, "warnings": D.warnings(design),
                    "problems": D.problems(design, a.fields, a.graph, D.asset_keys(a.id))})


@bp.route("/apps/<slug>/design/starter")
@login_required
@require_permission(LIBRARY)
def app_design_starter(slug):
    """SATOM's standard layout as a design, to start from."""
    from ..services import studio_design as D
    a = _app_or_404(slug)
    return jsonify({"ok": True, "design": D.starter(a.fields, a.graph)})


@bp.route("/apps/<slug>/assets", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_asset_upload(slug):
    from ..extensions import db
    from ..services import studio_design as D
    a = _app_or_404(slug)
    f = request.files.get("file")
    if f is None:
        return _err("no file")
    data = f.read(D.ASSET_MAX + 1)
    try:
        row = D.add_asset(a.id, f.filename or "", data, _who())
    except D.DesignError as exc:
        db.session.rollback()
        return _err(exc)
    log_action("studio.app.asset", target=slug, extra={"sha256": row.sha256, "size": row.size})
    return jsonify({"ok": True, "asset": _asset_json(a, row)})


@bp.route("/apps/<slug>/assets/<sha>/delete", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_asset_delete(slug, sha):
    from ..extensions import db
    from ..services import studio_design as D
    a = _app_or_404(slug)
    try:
        D.remove_asset(a, sha)
    except D.DesignError as exc:
        db.session.rollback()
        return _err(exc)
    log_action("studio.app.asset.delete", target=slug, extra={"sha256": sha})
    return jsonify({"ok": True})


def _asset_json(a, row) -> dict:
    return {"sha": row.sha256, "name": row.name, "size": row.size, "mime": row.mime,
            "url": url_for("apps.asset", slug=a.slug, sha=row.sha256)}


@bp.route("/apps/<slug>/form")
@login_required
@require_permission(LIBRARY)
def app_form(slug):
    """The draft's form, drawn for the Test tab."""
    from ..services import studio_apps as SA
    a = _app_or_404(slug)
    # Two copies on one page (Test tab, Simulate panel): their ids must differ.
    prefix = request.args.get("prefix") if request.args.get("prefix") in ("t-", "s-") else "t-"
    return render_template("apps/_form.html", fields=SA.form_view(a.fields), prefix=prefix)


@bp.route("/apps/<slug>/test", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_test(slug):
    from ..services import studio_apps as SA
    a = _app_or_404(slug)
    body = request.get_json(silent=True) or {}
    rehearsal = bool(body.get("rehearsal", True))
    try:
        run = SA.start_run(a, user=current_user, product=_product_key(),
                           raw_inputs=body.get("inputs"), draft=True, armed=not rehearsal)
    except SA.AppError as exc:
        return _err(exc)
    log_action("studio.app.test", target=slug, extra={"run": run.id, "rehearsal": rehearsal})
    return jsonify({"ok": True, "run_id": run.id,
                    "status_url": url_for("apps.run_status", rid=run.id)})


@bp.route("/apps/<slug>/publish", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_publish(slug):
    from ..services import studio_apps as SA
    a = _app_or_404(slug)
    note = str((request.get_json(silent=True) or {}).get("note") or "")
    try:
        n = SA.publish(a, note, _who())
    except SA.AppError as exc:
        return _err(exc)
    log_action("studio.app.publish", target=slug, extra={"version": n, "note": note[:200]})
    return jsonify({"ok": True, "version": n})


@bp.route("/apps/<slug>/unpublish", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_unpublish(slug):
    from ..services import studio_apps as SA
    a = _app_or_404(slug)
    SA.unpublish(a, _who())
    log_action("studio.app.unpublish", target=slug)
    return jsonify({"ok": True})


@bp.route("/apps/<slug>/delete", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_delete(slug):
    """Delete for good (studio_apps.remove): never a template, never an app
    another app runs."""
    from ..extensions import db
    from ..services import studio_apps as SA
    a = _app_or_404(slug)
    try:
        res = SA.remove(a)
    except SA.AppError as exc:
        db.session.rollback()
        return _err(exc, 409)
    log_action("studio.app.delete", target=slug, extra=res)
    return jsonify({"ok": True, **res})


@bp.route("/apps/<slug>/enable", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_enable(slug):
    """Disable / enable: a disabled app leaves every menu and starts no run
    (event automations included); nothing is deleted."""
    from ..services import studio_apps as SA
    a = _app_or_404(slug)
    on = bool((request.get_json(silent=True) or {}).get("enabled"))
    SA.set_enabled(a, on, _who())
    log_action("studio.app.enable" if on else "studio.app.disable", target=slug)
    return jsonify({"ok": True, "enabled": a.enabled})


@bp.route("/apps/<slug>/reset", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def app_reset(slug):
    """Delete the app's data from the database: its runs and the rows of the
    data stores only it uses (studio_apps.reset). Templates too."""
    from ..extensions import db
    from ..services import studio_apps as SA
    a = _app_or_404(slug)
    try:
        res = SA.reset(a)
    except SA.AppError as exc:
        db.session.rollback()
        return _err(exc, 409)
    log_action("studio.app.reset", target=slug, extra=res)
    return jsonify({"ok": True, **res})


@bp.route("/apps/<slug>/data.zip")
@login_required
@require_permission(LIBRARY)
def app_data(slug):
    """Download everything the app holds: runs and its data stores (CSV)."""
    from ..services import studio_apps as SA
    a = _app_or_404(slug)
    name, data = SA.data_zip(a)
    log_action("studio.app.data_download", target=slug, extra={"bytes": len(data)})
    return Response(data, mimetype="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % name})
