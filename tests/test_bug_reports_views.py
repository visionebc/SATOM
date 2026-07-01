"""HTTP tests for the reports blueprint (test client, CSRF disabled)."""
import pytest


@pytest.fixture()
def app():
    from app import create_app
    from app.models import db, User

    class _Cfg:
        TESTING = True
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        WTF_CSRF_ENABLED = False
        RATELIMIT_ENABLED = False
        SECRET_KEY = "test"

    app = create_app(_Cfg)
    with app.app_context():
        db.create_all()
        for name, role in [("alice", "readonly"), ("adm", "admin")]:
            u = User(username=name, role=role)
            u.set_password("pw")
            db.session.add(u)
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()


def _login(client, username):
    client.post("/auth/login",
                data={"username": username, "password": "pw"},
                follow_redirects=True)
    # App gates all views behind a product selection; pick one for the session.
    return client.post("/product/select",
                       data={"product": "fortiweb"},
                       follow_redirects=True)


def test_submit_creates_report(app):
    from app.services import bug_reports as svc
    c = app.test_client()
    _login(c, "alice")
    resp = c.post("/reports",
                  data={"title": "Nav broken", "body": "menu dead",
                        "page_url": "https://x/p", "user_agent": "UA"},
                  follow_redirects=False)
    assert resp.status_code in (200, 302)
    with app.app_context():
        assert svc.open_count() == 1


def test_submit_requires_login(app):
    c = app.test_client()
    resp = c.post("/reports", data={"title": "x", "body": "y"})
    # redirect to login (302) — not created
    assert resp.status_code in (301, 302)
    assert "/auth/login" in resp.headers.get("Location", "")


def test_inbox_requires_admin(app):
    c = app.test_client()
    _login(c, "alice")  # readonly
    resp = c.get("/reports")
    assert resp.status_code == 403


def test_admin_resolves_report(app):
    from app.models import db, User, BugReport
    from app.services import bug_reports as svc
    with app.app_context():
        alice = User.query.filter_by(username="alice").one()
        r = svc.create_report(alice, "t", "b", None, None)
        rid = r.id
    c = app.test_client()
    _login(c, "adm")
    resp = c.post(f"/reports/{rid}/resolve",
                  data={"note": "done"}, follow_redirects=True)
    assert resp.status_code == 200
    with app.app_context():
        got = BugReport.query.get(rid)
        assert got.status == BugReport.STATUS_RESOLVED
        assert got.resolution_note == "done"


def test_mark_mine_seen(app):
    from app.models import db, User
    from app.services import bug_reports as svc
    with app.app_context():
        alice = User.query.filter_by(username="alice").one()
        adm = User.query.filter_by(username="adm").one()
        r = svc.create_report(alice, "t", "b", None, None)
        svc.resolve_report(r, adm, "fixed")
        aid = alice.id
    c = app.test_client()
    _login(c, "alice")
    resp = c.post("/reports/mine/seen", follow_redirects=False)
    assert resp.status_code in (200, 302)
    with app.app_context():
        assert svc.unseen_resolved_count(aid) == 0


def test_admin_sees_inbox_link_without_optin(app):
    """An admin who has NOT opted into email should still reach the bug
    inbox from the shell (in-app management is not gated by the email opt-in)."""
    from app.models import User
    from app.services import bug_reports as svc
    with app.app_context():
        alice = User.query.filter_by(username="alice").one()
        svc.create_report(alice, "t", "b", None, None)  # one OPEN report
        adm = User.query.filter_by(username="adm").one()
        assert not svc.is_opted_in(adm.id)  # precondition: opt-in off
    c = app.test_client()
    resp = _login(c, "adm")
    html = resp.get_data(as_text=True)
    assert "Bug Reports" in html  # admin inbox link in the shell/user menu


def test_admin_open_count_ignores_optin(app):
    """open_report_count in the template context is populated for any admin,
    independent of the email opt-in flag."""
    from app.models import User
    from app.services import bug_reports as svc
    with app.app_context():
        alice = User.query.filter_by(username="alice").one()
        svc.create_report(alice, "t", "b", None, None)
    c = app.test_client()
    resp = _login(c, "adm")
    html = resp.get_data(as_text=True)
    # the red notification badge (count 1) must render for the admin
    assert "bi-bell-fill" in html
