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

from flask import (Blueprint, render_template, request, jsonify, Response)
from flask_login import login_required

from ..auth.decorators import require_permission
from ..services import dbintrospect

bp = Blueprint("database", __name__, url_prefix="/database")


@bp.route("/")
@login_required
@require_permission("user_manage")
def index():
    rel = dbintrospect.relations()
    return render_template("database/index.html",
                           tables=rel["tables"], edges=rel["edges"],
                           table_names=[t["name"] for t in rel["tables"]])


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
