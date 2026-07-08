"""Database reports & dashboards — definition guard, routes, PDF export."""
from __future__ import annotations

import json

from tests.conftest import login, admin_user_id
from app.services import db_reports as R


def test_validate_definition_accepts_select_widgets():
    d, errs = R.validate_definition({"widgets": [
        {"title": "Users", "sql": "SELECT username FROM users", "viz": "table"},
        {"title": "Count", "sql": "SELECT COUNT(*) FROM users", "viz": "stat"},
    ]})
    assert errs == []
    assert len(d["widgets"]) == 2
    assert d["widgets"][1]["viz"] == "stat"


def test_validate_definition_rejects_writes_and_junk():
    _, errs = R.validate_definition({"widgets": [
        {"title": "bad", "sql": "DELETE FROM users", "viz": "table"},
    ]})
    assert errs and "bad" in errs[0]
    _, errs2 = R.validate_definition({"widgets": []})
    assert errs2
    _, errs3 = R.validate_definition("not json {{")
    assert errs3


def test_validate_definition_clamps_limit_and_viz():
    d, _ = R.validate_definition({"widgets": [
        {"title": "x", "sql": "SELECT 1", "viz": "hologram", "limit": 99999},
    ]})
    w = d["widgets"][0]
    assert w["viz"] == "table"
    assert w["limit"] == R.MAX_ROWS_PER_WIDGET


def test_report_crud_and_dashboard(client, app):
    login(client, admin_user_id(app))
    body = {"name": "Smoke report", "description": "test",
            "definition": {"widgets": [
                {"title": "One", "sql": "SELECT 1 AS n", "viz": "stat"},
                {"title": "Tbl", "sql": "SELECT username FROM users",
                 "viz": "table"},
            ]}}
    r = client.post("/database/reports/save", json=body)
    assert r.status_code == 200, r.data
    rid = r.get_json()["id"]

    # listed on the database page
    page = client.get("/database/")
    assert b"Smoke report" in page.data

    # dashboard + data endpoint
    assert client.get(f"/database/reports/{rid}").status_code == 200
    data = client.get(f"/database/reports/{rid}/data").get_json()
    assert data["name"] == "Smoke report"
    assert data["widgets"][0]["stat"] == "1"
    assert data["widgets"][1]["columns"] == ["username"]

    # update keeps the same id
    body["id"] = rid
    body["name"] = "Smoke report v2"
    r2 = client.post("/database/reports/save", json=body)
    assert r2.get_json()["id"] == rid

    # delete
    r3 = client.post(f"/database/reports/{rid}/delete")
    assert r3.status_code in (301, 302)
    assert client.get(f"/database/reports/{rid}").status_code == 404


def test_report_save_rejects_write_sql(client, app):
    login(client, admin_user_id(app))
    r = client.post("/database/reports/save", json={
        "name": "evil", "definition": {"widgets": [
            {"title": "w", "sql": "DROP TABLE users", "viz": "table"}]}})
    assert r.status_code == 400
    assert r.get_json()["ok"] is False


def test_report_pdf_export(client, app):
    login(client, admin_user_id(app))
    r = client.post("/database/reports/save", json={
        "name": "PDF report", "definition": {"widgets": [
            {"title": "Stat", "sql": "SELECT COUNT(*) AS users FROM users",
             "viz": "stat"},
            {"title": "Bar", "sql": "SELECT username, id FROM users",
             "viz": "bar", "x": "username", "y": "id"},
            {"title": "Rows", "sql": "SELECT id, username FROM users",
             "viz": "table"},
        ]}})
    rid = r.get_json()["id"]
    pdf = client.get(f"/database/reports/{rid}/pdf")
    assert pdf.status_code == 200
    assert pdf.mimetype == "application/pdf"
    assert pdf.data.startswith(b"%PDF")
    assert len(pdf.data) > 1500


def test_reports_admin_only(client, app):
    r = client.get("/database/reports/new")
    assert r.status_code in (301, 302)  # anonymous → login
