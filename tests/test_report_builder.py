"""Report Builder — catalog, safe SQL builder, builtin seeds, route guards."""
from __future__ import annotations

import json

from tests.conftest import login, admin_user_id
from app.services import report_builder as RB
from app.services import dbintrospect as D
from app.services import db_reports as DR


# --------------------------------------------------------------------------
# build_sql — happy path
# --------------------------------------------------------------------------

def test_build_sql_happy_path(app):
    with app.app_context():
        spec = {
            "base": "device_server_policies",
            "joins": [{"table": "appliances",
                       "from_table": "device_server_policies",
                       "from_col": "appliance_id", "to_col": "id"}],
            "columns": [
                {"table": "appliances", "col": "name"},
                {"table": "device_server_policies", "col": "status",
                 "agg": "count"},
            ],
            "filters": [{"table": "device_server_policies", "col": "status",
                         "op": "=", "value": "enable"}],
            "group_by": [{"table": "appliances", "col": "name"}],
            "order_by": {"table": None, "col": "n", "dir": "desc"},
            "limit": 50,
        }
        sql, errs = RB.build_sql(spec)
        assert errs == [], errs
        assert "LEFT JOIN" in sql
        assert "GROUP BY" in sql
        assert "AS \"n\"" in sql
        assert sql.rstrip().endswith("LIMIT 50")
        ok, why = D.is_read_only(sql)
        assert ok, why
        # executes against the (empty) test DB without error
        res = D.run_query(sql)
        assert res["error"] == "", res["error"]


def test_build_sql_default_limit_and_clamp(app):
    with app.app_context():
        sql, errs = RB.build_sql({
            "base": "appliances",
            "columns": [{"table": "appliances", "col": "name"}],
            "limit": 99999})
        assert errs == []
        assert sql.rstrip().endswith("LIMIT 500")


# --------------------------------------------------------------------------
# build_sql — rejections
# --------------------------------------------------------------------------

def test_build_sql_unknown_table(app):
    with app.app_context():
        sql, errs = RB.build_sql({"base": "nope",
                                  "columns": [{"table": "nope", "col": "x"}]})
        assert sql == "" and errs


def test_build_sql_unknown_column(app):
    with app.app_context():
        sql, errs = RB.build_sql({
            "base": "appliances",
            "columns": [{"table": "appliances", "col": "does_not_exist"}]})
        assert sql == "" and any("does_not_exist" in e for e in errs)


def test_build_sql_sensitive_column_rejected(app):
    with app.app_context():
        sql, errs = RB.build_sql({
            "base": "appliances",
            "columns": [{"table": "appliances", "col": "password_enc"}]})
        assert sql == "" and any("sensitive" in e for e in errs)
        sql2, errs2 = RB.build_sql({
            "base": "users",
            "columns": [{"table": "users", "col": "password_hash"}]})
        assert sql2 == "" and any("sensitive" in e for e in errs2)


def test_build_sql_bad_operator(app):
    with app.app_context():
        sql, errs = RB.build_sql({
            "base": "appliances",
            "columns": [{"table": "appliances", "col": "name"}],
            "filters": [{"table": "appliances", "col": "name",
                         "op": "regexp", "value": "x"}]})
        assert sql == "" and any("operator" in e for e in errs)


def test_build_sql_bad_agg(app):
    with app.app_context():
        sql, errs = RB.build_sql({
            "base": "appliances",
            "columns": [{"table": "appliances", "col": "name",
                         "agg": "median"}]})
        assert sql == "" and any("aggregate" in e for e in errs)


# --------------------------------------------------------------------------
# value escaping / injection inertness
# --------------------------------------------------------------------------

def test_build_sql_escapes_single_quote(app):
    with app.app_context():
        sql, errs = RB.build_sql({
            "base": "appliances",
            "columns": [{"table": "appliances", "col": "name"}],
            "filters": [{"table": "appliances", "col": "name",
                         "op": "=", "value": "O'Brien"}]})
        assert errs == []
        assert "'O''Brien'" in sql
        ok, _ = D.is_read_only(sql)
        assert ok


def test_build_sql_semicolon_value_stays_inert(app):
    """A ';' in a value can never enable a second statement. The value is first
    escaped into a single-quoted literal (so the ';' is inert SQL text), and the
    read-only guard — which bans any ';' outright — is asserted before returning,
    so build_sql refuses the query entirely rather than emitting anything unsafe.
    Either way no injection is possible; here the guard rejects it."""
    with app.app_context():
        # escaping happens first: the raw value is doubled + single-quoted
        frag = RB._scalar_value("x'; DROP TABLE users; --")
        assert frag == "'x''; DROP TABLE users; --'"
        # the guard refuses any query carrying a ';' — belt-and-braces rejection
        sql, errs = RB.build_sql({
            "base": "appliances",
            "columns": [{"table": "appliances", "col": "name"}],
            "filters": [{"table": "appliances", "col": "name",
                         "op": "=", "value": "x'; DROP TABLE users; --"}]})
        assert sql == "" and errs
        assert any("read-only" in e for e in errs)
        # and a benign ';'-free value with an embedded quote still builds fine
        sql2, errs2 = RB.build_sql({
            "base": "appliances",
            "columns": [{"table": "appliances", "col": "name"}],
            "filters": [{"table": "appliances", "col": "name",
                         "op": "=", "value": "O'Brien-- x"}]})
        assert errs2 == []
        assert "'O''Brien-- x'" in sql2
        ok, _ = D.is_read_only(sql2)
        assert ok


def test_build_sql_like_wraps_wildcards(app):
    with app.app_context():
        sql, errs = RB.build_sql({
            "base": "appliances",
            "columns": [{"table": "appliances", "col": "name"}],
            "filters": [{"table": "appliances", "col": "name",
                         "op": "like", "value": "edge"}]})
        assert errs == []
        assert "LIKE '%edge%'" in sql


# --------------------------------------------------------------------------
# catalog / related_tables
# --------------------------------------------------------------------------

def test_catalog_excludes_sensitive_and_has_phrases(app):
    with app.app_context():
        cat = RB.catalog()
        appl = next(t for t in cat["tables"] if t["name"] == "appliances")
        cols = [c["name"] for c in appl["columns"]]
        assert "password_enc" not in cols
        assert appl["label"] == "Appliances (fleet)"
        assert any(e["phrase"] for e in cat["edges"])
        assert cat["domains"][0]["key"] == "fleet"


def test_related_tables_reachable(app):
    with app.app_context():
        rel = RB.related_tables("device_server_policies", max_hops=2)
        names = {r["table"] for r in rel}
        assert "appliances" in names


# --------------------------------------------------------------------------
# column_values
# --------------------------------------------------------------------------

def test_column_values_sensitive_and_unknown_return_empty(app):
    with app.app_context():
        assert RB.column_values("appliances", "password_enc") == []
        assert RB.column_values("appliances", "nope") == []
        assert RB.column_values("nope", "x") == []
        # a valid column returns a list (possibly empty on an empty test DB)
        assert isinstance(RB.column_values("appliances", "kind"), list)


# --------------------------------------------------------------------------
# seed_builtin_reports — idempotency + validity
# --------------------------------------------------------------------------

def test_seed_builtin_reports_idempotent(app):
    from app.models import DbReport
    with app.app_context():
        n1 = RB.seed_builtin_reports()
        assert n1 > 0
        n2 = RB.seed_builtin_reports()
        assert n2 == 0
        builtins = DbReport.query.filter_by(builtin=True).all()
        assert len(builtins) == n1
        for rep in builtins:
            _, errs = DR.validate_definition(rep.definition)
            assert errs == [], (rep.name, errs)


# --------------------------------------------------------------------------
# route guards
# --------------------------------------------------------------------------

def _make_builtin(app):
    from app.extensions import db
    from app.models import DbReport
    with app.app_context():
        RB.seed_builtin_reports()
        rep = DbReport.query.filter_by(builtin=True).first()
        return rep.id, rep.name


def test_report_save_on_builtin_is_403(client, app):
    login(client, admin_user_id(app))
    rid, name = _make_builtin(app)
    r = client.post("/database/reports/save", json={
        "id": rid, "name": "hacked",
        "definition": {"widgets": [{"title": "x", "sql": "SELECT 1",
                                    "viz": "stat"}]}})
    assert r.status_code == 403
    assert "read-only" in " ".join(r.get_json()["errors"])


def test_report_delete_on_builtin_is_blocked(client, app):
    from app.models import DbReport
    login(client, admin_user_id(app))
    rid, name = _make_builtin(app)
    client.post(f"/database/reports/{rid}/delete")
    with app.app_context():
        assert DbReport.query.get(rid) is not None


def test_report_clone_of_builtin_creates_editable_copy(client, app):
    from app.models import DbReport
    login(client, admin_user_id(app))
    rid, name = _make_builtin(app)
    r = client.post(f"/database/reports/{rid}/clone")
    assert r.status_code in (301, 302)
    with app.app_context():
        copy = DbReport.query.filter_by(name="Copy of " + name).first()
        assert copy is not None
        assert copy.builtin is False
        assert copy.definition == DbReport.query.get(rid).definition


def test_build_sql_route(client, app):
    login(client, admin_user_id(app))
    r = client.post("/database/reports/build-sql", json={"spec": {
        "base": "appliances",
        "columns": [{"table": "appliances", "col": "name"}]}})
    j = r.get_json()
    assert j["ok"] is True and j["sql"].startswith("SELECT")
    r2 = client.post("/database/reports/build-sql", json={"spec": {
        "base": "appliances",
        "columns": [{"table": "appliances", "col": "password_enc"}]}})
    assert r2.get_json()["ok"] is False


def test_column_values_route(client, app):
    login(client, admin_user_id(app))
    r = client.get("/database/reports/column-values?table=appliances&col=kind")
    assert isinstance(r.get_json()["values"], list)
    r2 = client.get("/database/reports/column-values?table=appliances&col=password_enc")
    assert r2.get_json()["values"] == []
