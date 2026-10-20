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
CONSOLE = "studio.python_console"
LIBRARY = "studio.script_library"
PANES = ("scripts", "console", "stores", "connections")


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
    if pane not in PANES or (pane != "console" and not can_library) \
            or (pane == "console" and not can_console):
        pane = "scripts" if can_library else "console"
    from ..services import studio_connections as SC
    from ..services import studio_store as SS
    return render_template(
        "studio/index.html", pane=pane,
        can_console=can_console, can_library=can_library,
        stores=SS.list_stores() if can_library else [],
        connections=SC.list_connections() if can_library else [],
        scripts=SL.list_scripts() if can_library else [],
        runs=SL.recent_runs(limit=15) if can_library else [],
        datasets=plugin_sandbox.dataset_catalog() if can_console else [],
        examples=py_examples.all_examples() if can_console else [],
        sandbox_ok=sandbox.available())


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
    return render_template("studio/store.html", store=st, column_types=SS.COLUMN_TYPES,
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
    st = _store_or_404(slug)
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
    c = _conn_or_404(slug)
    secret, problem = SC.secret_state(slug)
    return render_template("studio/connection.html", c=c, has_secret=SC.has_secret(slug),
                           secret_problem=problem, http_auth=SC.HTTP_AUTH, methods=SC.METHODS)


@bp.route("/connections/<slug>/save", methods=["POST"])
@login_required
@require_permission(LIBRARY)
def connection_save(slug):
    from ..services import studio_connections as SC
    c = _conn_or_404(slug)
    try:
        SC.save(c, request.get_json(silent=True) or {}, _who())
    except SC.ConnectionError_ as exc:
        from ..extensions import db
        db.session.rollback()
        return _err(exc)
    log_action("studio.connection.save", target=slug,
               extra={"kind": c.kind, "auth": c.auth, "base_url": c.base_url, "host": c.host})
    return jsonify({"ok": True})


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
    c = _conn_or_404(slug)
    users = SA.used_by("connection", slug)
    if users:
        return _err("used by app(s) %s: remove it from them first" % ", ".join(users), 409)
    SC.delete(c)
    log_action("studio.connection.delete", target=slug)
    return jsonify({"ok": True})
