"""Phase 8 — Database page (the Postgres source-of-truth browser).

A dedicated TOP-LEVEL page (kept OUT of Settings so Settings stays light),
admin-only (USER_MANAGE). Three tabs:
  1. Relational model — tables + columns + PK/FK edges (services.dbintrospect.relations)
  2. Tables — browse any table's rows, paginated
  3. SQL console — run READ-ONLY queries (SELECT/WITH/EXPLAIN); CSV export

The console is read-only by construction (dbintrospect.run_query rejects any
write/DDL and runs inside a rolled-back, time-limited transaction), so a stray
statement can never mutate the source of truth.
"""
from __future__ import annotations

import csv
import io

from flask import (Blueprint, render_template, request, jsonify, Response,
                   redirect, url_for, flash)
from flask_login import login_required

from ..auth.decorators import require_permission
from ..services import dbintrospect
from ..services import db_reports as reports_svc
from ..services import report_builder
from ..services.csv_safe import spreadsheet_safe
from ..services.audit import log_action
from ..extensions import db
from ..models import DbReport, PluginDataset

bp = Blueprint("database", __name__, url_prefix="/database")

#: Endpoints a profile confined to some ADOMs may still open: the redirects
#: to Python Studio (the console runs in a sandbox without the database).
_CONFINED_OK = frozenset({"database.py_console_page", "database.legacy_scripts"})
CONFINED_REFUSAL = ("The database browser, the SQL console and DB reports read "
                    "every ADOM's rows. A profile confined to some ADOMs "
                    "cannot open them.")


@bp.before_request
def _refuse_confined_profiles():
    """Raw SQL cannot be scoped to an ADOM: refuse it to a confined profile
    rather than show it the whole fleet (services.product_scope)."""
    from ..services.product_scope import restricted_adoms
    if restricted_adoms() is None or request.endpoint in _CONFINED_OK:
        return None
    if request.method != "GET" or request.is_json \
            or request.accept_mimetypes.best == "application/json":
        return jsonify({"ok": False, "error": CONFINED_REFUSAL}), 403
    flash(CONFINED_REFUSAL, "warning")
    return redirect(url_for("index"))


@bp.route("/")
@login_required
@require_permission("user_manage")
def index():
    from ..services import plugin_datasets as PD
    rel = dbintrospect.relations()
    reports = DbReport.query.order_by(DbReport.updated_at.desc()).all()
    return render_template("database/index.html",
                           tables=rel["tables"], edges=rel["edges"],
                           table_names=[t["name"] for t in rel["tables"]],
                           reports=reports,
                           plugin_datasets=PluginDataset.query.order_by(PluginDataset.key).all(),
                           plugin_dataset_usage=_dataset_usage(),
                           dataset_summary=PD.summary(""),
                           dataset_browser=PD.browser_items(),
                           can_plugin_datasets=_can_plugin_datasets())


@bp.route("/table")
@login_required
@require_permission("user_manage")
def table():
    name = request.args.get("name", "")
    page = request.args.get("page", 1)
    info = dbintrospect.table_page(name, page=page)
    # schema (columns + types + pk/fk) for the header
    info["schema"] = dbintrospect.table_info(name).get("columns", [])
    return jsonify(info)


@bp.route("/query", methods=["POST"])
@login_required
@require_permission("user_manage")
def query():
    body = request.get_json(silent=True) or {}
    res = dbintrospect.run_query(body.get("sql", ""))
    return jsonify(res)


@bp.route("/query.csv", methods=["POST"])
@login_required
@require_permission("user_manage")
def query_csv():
    sql = (request.form.get("sql") or "")
    res = dbintrospect.run_query(sql)
    if res.get("error"):
        return Response(f"error,{res['error']}\n", mimetype="text/csv")
    buf = io.StringIO()
    w = csv.writer(buf)
    # Cells are database text that operators, devices and failed logins wrote
    # (audit usernames, object names): never let a spreadsheet evaluate them.
    w.writerow([spreadsheet_safe(c) for c in res["columns"]])
    for row in res["rows"]:
        w.writerow([spreadsheet_safe(c) for c in row])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=query_result.csv"})


# ---------------------------------------------------------------------------
# Reports & dashboards (over the same read-only query layer)
# ---------------------------------------------------------------------------

@bp.route("/reports/new")
@login_required
@require_permission("user_manage")
def report_new():
    rel = dbintrospect.relations()
    return render_template("database/report_edit.html", report=None,
                           table_names=[t["name"] for t in rel["tables"]],
                           builder_catalog=report_builder.catalog())


@bp.route("/reports/<int:report_id>/edit")
@login_required
@require_permission("user_manage")
def report_edit(report_id: int):
    report = DbReport.query.get_or_404(report_id)
    rel = dbintrospect.relations()
    return render_template("database/report_edit.html", report=report,
                           table_names=[t["name"] for t in rel["tables"]],
                           builder_catalog=report_builder.catalog())


@bp.route("/reports/save", methods=["POST"])
@login_required
@require_permission("user_manage")
def report_save():
    from flask_login import current_user
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()[:200]
    if not name:
        return jsonify({"ok": False, "errors": ["a report needs a name"]}), 400
    definition, errors = reports_svc.validate_definition(
        body.get("definition") or {})
    if errors:
        return jsonify({"ok": False, "errors": errors}), 400
    rid = body.get("id")
    if rid:
        report = DbReport.query.get_or_404(int(rid))
        if report.builtin:
            return jsonify({"ok": False, "errors": [
                "built-in reports are read-only — clone it to edit"]}), 403
        action = "database.report_update"
    else:
        report = DbReport(created_by=getattr(current_user, "username", "") or "")
        db.session.add(report)
        action = "database.report_create"
    report.name = name
    report.description = (body.get("description") or "").strip()[:2000]
    import json as _json
    report.definition = _json.dumps(definition)
    db.session.commit()
    try:
        log_action(action, target=report.name,
                   extra={"report_id": report.id,
                          "widgets": len(definition["widgets"])})
    except Exception:
        pass
    return jsonify({"ok": True, "id": report.id,
                    "view_url": url_for("database.report_view",
                                        report_id=report.id)})


@bp.route("/reports/<int:report_id>/delete", methods=["POST"])
@login_required
@require_permission("user_manage")
def report_delete(report_id: int):
    report = DbReport.query.get_or_404(report_id)
    if report.builtin:
        flash("Built-in reports cannot be deleted — clone it instead.", "warning")
        return redirect(url_for("database.index") + "#tab-reports")
    name = report.name
    db.session.delete(report)
    db.session.commit()
    try:
        log_action("database.report_delete", target=name,
                   extra={"report_id": report_id})
    except Exception:
        pass
    flash(f"Report '{name}' deleted.", "info")
    return redirect(url_for("database.index") + "#tab-reports")


@bp.route("/reports/<int:report_id>/clone", methods=["POST"])
@login_required
@require_permission("user_manage")
def report_clone(report_id: int):
    from flask_login import current_user
    src = DbReport.query.get_or_404(report_id)
    copy = DbReport(
        name=("Copy of " + src.name)[:200],
        description=src.description,
        definition=src.definition,
        builtin=False,
        created_by=getattr(current_user, "username", "") or "")
    db.session.add(copy)
    db.session.commit()
    try:
        log_action("database.report_clone", target=copy.name,
                   extra={"source_id": src.id, "report_id": copy.id})
    except Exception:
        pass
    flash(f"Cloned '{src.name}' — editing the copy.", "info")
    return redirect(url_for("database.report_edit", report_id=copy.id))


@bp.route("/reports/build-sql", methods=["POST"])
@login_required
@require_permission("user_manage")
def report_build_sql():
    body = request.get_json(silent=True) or {}
    sql, errors = report_builder.build_sql(body.get("spec") or {})
    return jsonify({"ok": not errors, "sql": sql, "errors": errors})


@bp.route("/reports/column-values")
@login_required
@require_permission("user_manage")
def report_column_values():
    table = request.args.get("table", "")
    col = request.args.get("col", "")
    return jsonify({"values": report_builder.column_values(table, col)})


@bp.route("/reports/<int:report_id>")
@login_required
@require_permission("user_manage")
def report_view(report_id: int):
    report = DbReport.query.get_or_404(report_id)
    return render_template("database/report_view.html", report=report)


@bp.route("/reports/<int:report_id>/data")
@login_required
@require_permission("user_manage")
def report_data(report_id: int):
    report = DbReport.query.get_or_404(report_id)
    return jsonify(reports_svc.run_report(report))


@bp.route("/reports/<int:report_id>/pdf")
@login_required
@require_permission("user_manage")
def report_pdf(report_id: int):
    from flask_login import current_user
    report = DbReport.query.get_or_404(report_id)
    result = reports_svc.run_report(report)
    pdf = reports_svc.build_pdf(
        result, author=getattr(current_user, "username", "") or "")
    try:
        log_action("database.report_pdf", target=report.name,
                   extra={"report_id": report.id})
    except Exception:
        pass
    fname = "".join(c if c.isalnum() or c in "-_" else "_"
                    for c in report.name.lower()) or "report"
    return Response(pdf, mimetype="application/pdf",
                    headers={"Content-Disposition":
                             f"attachment; filename={fname}.pdf"})


# --- Old Studio URLs ---------------------------------------------------------
# The Python console and the Script Library live in Python Studio
# (views.studio, /studio) since 2026-10-20. The old addresses redirect so
# bookmarks and links in old notes keep working; nothing is served here.
@bp.route("/py-console")
@login_required
def py_console_page():
    return redirect(url_for("studio.index", pane="console"))


@bp.route("/scripts/", defaults={"rest": ""}, methods=["GET", "POST"])
@bp.route("/scripts/<path:rest>", methods=["GET", "POST"])
@login_required
def legacy_scripts(rest):
    """308 keeps the method and body, so an old POST lands on the same route."""
    target = "/studio/scripts/" + rest
    if request.query_string:
        target += "?" + request.query_string.decode("latin-1")
    return redirect(target, code=308)


# ---------------------------------------------------------------------------
# Plugin datasets (services.plugin_datasets): an administrator's query,
# published for plugins and pulled by SATOM Builder.
# ---------------------------------------------------------------------------
def _can_plugin_datasets() -> bool:
    from flask_login import current_user
    return bool(getattr(current_user, "is_authenticated", False)
                and current_user.can("studio.plugin_studio"))


def _need_plugin_datasets():
    from flask import abort
    if not _can_plugin_datasets():
        abort(403)


def _dataset_usage() -> dict:
    """``{dataset key: [plugin slugs]}`` over every ADOM's plugins."""
    from ..models import Plugin
    out: dict = {}
    for p in Plugin.query.all():
        for k in p.datasets:
            out.setdefault(k, []).append(p.slug)
    return out


def _dataset_form(ds):
    rel = dbintrospect.relations()
    from ..services.plugin_datasets import PRODUCTS
    return render_template("database/plugin_dataset_edit.html", ds=ds,
                           table_names=[t["name"] for t in rel["tables"]],
                           builder_catalog=report_builder.catalog(), products=PRODUCTS,
                           used_by=_dataset_usage().get(ds.key, []) if ds else [])


@bp.route("/plugin-datasets/new")
@login_required
@require_permission("user_manage")
def plugin_dataset_new():
    _need_plugin_datasets()
    return _dataset_form(None)


@bp.route("/plugin-datasets/<int:ds_id>/edit")
@login_required
@require_permission("user_manage")
def plugin_dataset_edit(ds_id: int):
    _need_plugin_datasets()
    return _dataset_form(PluginDataset.query.get_or_404(ds_id))


@bp.route("/plugin-datasets/preview", methods=["POST"])
@login_required
@require_permission("user_manage")
def plugin_dataset_preview():
    """What a plugin would read from this query, for the signed-in
    administrator's ADOM: the column names a view uses and the first rows."""
    from ..services import db_lookup
    from ..services import plugin_datasets as PD
    _need_plugin_datasets()
    body = request.get_json(silent=True) or {}
    try:
        clean = PD.clean_admin(body.get("key") or "preview", body.get("label") or "preview", "",
                               body.get("spec"), body.get("product") or "")
        entry = {"key": clean["key"], "source": "admin", "spec": clean["spec"],
                 "columns": PD.admin_columns(clean["spec"])}
        data = PD.load([entry], None)[clean["key"]]
    except (PD.DatasetError, db_lookup.LookupError_) as exc:
        return jsonify({"ok": False, "errors": [str(exc)]}), 400
    if data.get("error"):
        return jsonify({"ok": False, "errors": [data["error"]]}), 400
    sql, _errs = report_builder.build_sql(clean["spec"])
    return jsonify({"ok": True, "key": clean["key"], "columns": data["columns"],
                    "rows": data["rows"][:20], "row_count": len(data["rows"]), "sql": sql})


@bp.route("/plugin-datasets/save", methods=["POST"])
@login_required
@require_permission("user_manage")
def plugin_dataset_save():
    from flask_login import current_user
    from ..services import plugin_datasets as PD
    _need_plugin_datasets()
    body = request.get_json(silent=True) or {}
    try:
        clean = PD.clean_admin(body.get("key"), body.get("label"), body.get("description"),
                               body.get("spec"), body.get("product"))
    except PD.DatasetError as exc:
        return jsonify({"ok": False, "errors": [str(exc)]}), 400
    status = body.get("status") if body.get("status") in ("draft", "published") else "draft"
    who = getattr(current_user, "username", "") or ""
    ds_id = body.get("id")
    other = PluginDataset.query.filter_by(key=clean["key"]).first()
    if ds_id:
        ds = PluginDataset.query.get_or_404(int(ds_id))
        if ds.key != clean["key"]:
            return jsonify({"ok": False, "errors": [
                "The key cannot change: plugins name the dataset by it. Create a new one."]}), 400
        action = "plugin_dataset.update"
    else:
        if other is not None:
            return jsonify({"ok": False, "errors": ["%s already exists." % clean["key"]]}), 400
        ds = PluginDataset(key=clean["key"], created_by=who)
        db.session.add(ds)
        action = "plugin_dataset.create"
    import json as _json
    ds.label = clean["label"]
    ds.description = clean["description"]
    ds.spec = _json.dumps(clean["spec"])
    ds.product = clean["product"]
    ds.status = status
    ds.updated_by = who
    db.session.commit()
    log_action(action, target=ds.key, extra={"status": status, "product": ds.product,
                                             "base": clean["spec"].get("base")})
    return jsonify({"ok": True, "id": ds.id, "key": ds.key,
                    "back_url": url_for("database.index") + "#tab-plugin-datasets"})


@bp.route("/plugin-datasets/generate", methods=["POST"])
@login_required
@require_permission("user_manage")
def plugin_dataset_generate():
    """Write the joined datasets the device cache allows (services.dataset_examples):
    only keys that do not exist, published, one ADOM each."""
    from flask_login import current_user
    from ..services import dataset_examples as DX
    _need_plugin_datasets()
    res = DX.generate(by=getattr(current_user, "username", "") or "")
    log_action("plugin_dataset.generate", target="device cache",
               extra={"created": res["created"], "existing": res["existing"],
                      "refused": [k for k, _w in res["refused"]][:50],
                      "by_product": res["by_product"]})
    msg = "Created %d dataset(s) from the device cache (%s); %d already existed." % (
        res["created"], ", ".join("%s %d" % kv for kv in sorted(res["by_product"].items())) or "none new",
        res["existing"])
    if res["refused"]:
        msg += " %d could not be built on this server: %s." % (
            len(res["refused"]), ", ".join(k for k, _w in res["refused"][:5]))
    flash(msg, "success" if not res["refused"] else "warning")
    return redirect(url_for("database.index") + "#tab-plugin-datasets")


@bp.route("/plugin-datasets/<int:ds_id>/status", methods=["POST"])
@login_required
@require_permission("user_manage")
def plugin_dataset_status(ds_id: int):
    """Publish (also approves one an imported package brought) or unpublish."""
    from ..services import plugin_datasets as PD
    _need_plugin_datasets()
    ds = PluginDataset.query.get_or_404(ds_id)
    new = request.form.get("status")
    if new not in ("draft", "published"):
        flash("Unknown status.", "warning")
        return redirect(url_for("database.index") + "#tab-plugin-datasets")
    if new == "published":
        try:
            PD.clean_admin(ds.key, ds.label or ds.key, "", ds.spec_dict, ds.product)
        except PD.DatasetError as exc:
            flash("%s cannot be published: %s" % (ds.key, exc), "error")
            return redirect(url_for("database.plugin_dataset_edit", ds_id=ds.id))
    before = ds.status
    ds.status = new
    db.session.commit()
    log_action("plugin_dataset.status", target=ds.key, extra={"from": before, "to": new})
    used = _dataset_usage().get(ds.key, [])
    msg = "%s is now %s." % (ds.key, new)
    if new == "draft" and used:
        msg += " Plugins that read it now get no rows from it: " + ", ".join(used) + "."
    flash(msg, "warning" if new == "draft" and used else "success")
    return redirect(url_for("database.index") + "#tab-plugin-datasets")


@bp.route("/plugin-datasets/<int:ds_id>/delete", methods=["POST"])
@login_required
@require_permission("user_manage")
def plugin_dataset_delete(ds_id: int):
    _need_plugin_datasets()
    ds = PluginDataset.query.get_or_404(ds_id)
    used = _dataset_usage().get(ds.key, [])
    if used:
        flash("%s is read by %s: remove it from those plugins first (or unpublish it)."
              % (ds.key, ", ".join(used)), "warning")
        return redirect(url_for("database.index") + "#tab-plugin-datasets")
    key = ds.key
    db.session.delete(ds)
    db.session.commit()
    log_action("plugin_dataset.delete", target=key)
    flash("%s deleted." % key, "info")
    return redirect(url_for("database.index") + "#tab-plugin-datasets")

