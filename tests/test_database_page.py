"""Phase 8 — Database page + read-only SQL console guard."""
from __future__ import annotations

from tests.conftest import login, admin_user_id
from app.services import dbintrospect as D


def test_read_only_guard_accepts_select():
    ok, _ = D.is_read_only("SELECT 1")
    assert ok is True
    ok2, _ = D.is_read_only("WITH x AS (SELECT 1) SELECT * FROM x")
    assert ok2 is True


def test_read_only_guard_rejects_writes():
    for bad in ["DROP TABLE users", "DELETE FROM users", "UPDATE users SET x=1",
                "INSERT INTO users VALUES (1)", "SELECT 1; DROP TABLE users",
                "TRUNCATE users", ""]:
        ok, why = D.is_read_only(bad)
        assert ok is False, bad


def test_run_query_executes_select(app):
    with app.app_context():
        res = D.run_query("SELECT 1 AS one")
        assert res["error"] == ""
        assert res["columns"] == ["one"]
        assert res["rows"][0][0] == "1"


def test_run_query_blocks_write(app):
    with app.app_context():
        res = D.run_query("DELETE FROM users")
        assert res["error"]
        assert res["rows"] == []


def test_database_page_admin_only(client, app):
    # not logged in → redirect to login
    r = client.get("/database/")
    assert r.status_code in (301, 302)
    login(client, admin_user_id(app))
    r2 = client.get("/database/")
    assert r2.status_code == 200
    assert b"Relational model" in r2.data


def test_query_route(client, app):
    login(client, admin_user_id(app))
    r = client.post("/database/query", json={"sql": "SELECT 1 AS n"})
    j = r.get_json()
    assert j["error"] == "" and j["columns"] == ["n"]
    r2 = client.post("/database/query", json={"sql": "DROP TABLE users"})
    assert r2.get_json()["error"]

def test_database_page_renders_er_diagram(client, app):
    """The relational model tab is a real ER DIAGRAM (nodes + FK lines), not a
    row-table: assert the SVG host, the diagram script, and a well-formed
    tables+edges JSON data island are all present."""
    import json
    import re
    from tests.conftest import login, admin_user_id
    login(client, admin_user_id(app))
    r = client.get("/database/")
    assert r.status_code == 200
    assert b'id="er-diagram"' in r.data
    assert b"er_diagram.js" in r.data
    assert b'id="er-data"' in r.data
    m = re.search(rb'id="er-data"[^>]*>(.*?)</script>', r.data, re.S)
    assert m, "er-data JSON island missing"
    data = json.loads(m.group(1).decode())
    assert isinstance(data.get("tables"), list) and len(data["tables"]) >= 1
    assert "edges" in data


# --- Documentation Center audit, 2026-10-03 (AD-56) -------------------------
import pytest  # noqa: E402


@pytest.mark.parametrize("sql", [
    "SELECT username FROM users",
    "SELECT row_to_json(u) FROM users u",
    'SELECT * FROM "Users"',
    "SELECT t.* FROM public.users t(a, b, c)",
    "SELECT name FROM profiles WHERE id IN (SELECT profile_id FROM users)",
    "WITH x AS (SELECT token_hash AS h FROM api_tokens) SELECT h FROM x",
    "SELECT value FROM app_settings",
])
def test_queries_on_credential_tables_are_refused_and_audited(app, sql):
    from app.models import AuditLog
    with app.app_context():
        res = D.run_query(sql)
        assert res["error"].startswith("refused"), (sql, res)
        assert res["rows"] == []
        assert AuditLog.query.filter_by(action="database.query_refused").count() == 1


def test_a_table_name_inside_a_string_literal_is_not_a_reference(app):
    with app.app_context():
        res = D.run_query("SELECT 'users' AS label, name FROM profiles")
        assert res["error"] == "" and res["rows"], res


def test_alias_masking_still_applies_to_ordinary_tables(app):
    with app.app_context():
        res = D.run_query("SELECT name, 'x' AS password FROM profiles")
        assert res["error"] == ""
        assert all(r[1] == "••• (hidden)" for r in res["rows"])


def test_the_console_endpoint_returns_the_refusal(client, app):
    login(client, admin_user_id(app))
    r = client.post("/database/query", json={"sql": "SELECT password_hash AS x FROM users"})
    body = r.get_json()
    assert "refused" in (body.get("error") or ""), body
    assert "scrypt" not in r.get_data(as_text=True)
