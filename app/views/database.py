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
from ..services.audit import log_action
from ..extensions import db
from ..models import DbReport

bp = Blueprint("database", __name__, url_prefix="/database")


@bp.route("/")
@login_required
@require_permission("user_manage")
def index():
    rel = dbintrospect.relations()
    reports = DbReport.query.order_by(DbReport.updated_at.desc()).all()
    return render_template("database/index.html",
                           tables=rel["tables"], edges=rel["edges"],
                           table_names=[t["name"] for t in rel["tables"]],
                           reports=reports)


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
    w.writerow(res["columns"])
    for row in res["rows"]:
        w.writerow(row)
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
