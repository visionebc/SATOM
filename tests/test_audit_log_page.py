"""Audit Log page: pagination, inclusive "To" date, CSV export.

Documentation Center audit, 2026-10-03 (AD-16, AD-17, AD-18).
"""
from __future__ import annotations

from datetime import datetime

from conftest import admin_user_id, login


def _seed(app, n, when=None, action="seed.row", target="t"):
    from app.models import AuditLog, db
    with app.app_context():
        for i in range(n):
            db.session.add(AuditLog(username="admin", action=action, target=f"{target}{i}",
                                    extra="{}", product="",
                                    timestamp=when or datetime.utcnow()))
        db.session.commit()


def test_pagination_renders_and_reaches_page_two(app, client):
    _seed(app, 25)
    login(client, admin_user_id(app))
    import re
    html = client.get("/audit/?per_page=10&action=seed.row").get_data(as_text=True)
    links = re.findall(r'href="(/audit/\?[^"]*page=2[^"]*)"', html)
    assert links, "no pagination control"
    assert "action=seed.row" in links[0] and "per_page=10" in links[0], "filters lost on paging"
    html2 = client.get("/audit/?per_page=10&action=seed.row&page=3").get_data(as_text=True)
    assert "Previous" in html2 and "page=2" in html2


def test_to_date_includes_the_whole_day(app, client):
    _seed(app, 1, when=datetime(2026, 5, 4, 15, 30), action="late.in.day", target="late")
    login(client, admin_user_id(app))
    html = client.get("/audit/?action=late.in.day&date_from=2026-05-04&date_to=2026-05-04"
                      ).get_data(as_text=True)
    assert "late0" in html, "an entry at 15:30 is excluded by To = the same day"
    html = client.get("/audit/?action=late.in.day&date_to=2026-05-03").get_data(as_text=True)
    assert "late0" not in html


def test_export_csv_downloads_the_filtered_rows(app, client):
    _seed(app, 3, action="export.me", target="exp")
    _seed(app, 2, action="other.thing", target="oth")
    _seed(app, 1, action="export.me", target="=cmd|' /C calc'!A0")
    login(client, admin_user_id(app))
    page = client.get("/audit/?action=export.me").get_data(as_text=True)
    assert "/audit/export.csv?action=export.me" in page, "Export CSV must carry the filters"
    r = client.get("/audit/export.csv?action=export.me")
    assert r.status_code == 200
    assert r.mimetype == "text/csv"
    body = r.get_data(as_text=True)
    assert body.splitlines()[0].startswith("id,timestamp_utc,username,action,target")
    assert body.count("export.me") == 4 and "other.thing" not in body
    assert "'=cmd" in body, "a formula-looking cell must be neutralised"


def test_export_csv_needs_audit_view(app, client):
    from app.models import Profile, db
    from conftest import make_user
    with app.app_context():
        p = Profile(name="p-noaudit-csv", is_system=False)
        p.permission_set = {"monitoring.view"}
        db.session.add(p); db.session.commit()
        pid = p.id
    login(client, make_user(app, "noaudit", profile_id=pid))
    assert client.get("/audit/export.csv").status_code == 403
