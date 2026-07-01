"""Service-layer tests for bug_reports (in-memory SQLite, no HTTP, no SMTP)."""
import pytest


@pytest.fixture()
def app_ctx():
    from app import create_app
    from app.models import db

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
        yield app
        db.session.remove()
        db.drop_all()


def _mk_user(username, role="readonly"):
    from app.models import db, User
    u = User(username=username, role=role)
    u.set_password("x")
    db.session.add(u)
    db.session.commit()
    return u


def test_create_report_snapshots_username(app_ctx):
    from app.models import BugReport
    from app.services import bug_reports as svc

    u = _mk_user("alice")
    r = svc.create_report(u, "Broken thing", "details", "https://x/y", "UA/1")
    assert r.id is not None
    assert r.reporter_username == "alice"
    assert r.status == BugReport.STATUS_OPEN
    assert svc.open_count() == 1


def test_opted_in_admins_only_returns_admins_with_flag(app_ctx):
    from app.models import UserSetting
    from app.services import bug_reports as svc

    admin1 = _mk_user("adm1", role="admin")
    admin2 = _mk_user("adm2", role="admin")
    _mk_user("viewer", role="readonly")
    # admin1 opts in, admin2 does not
    UserSetting.set(admin1.id, svc.OPT_IN_KEY, "1")

    ids = {u.id for u in svc.opted_in_admins()}
    assert admin1.id in ids
    assert admin2.id not in ids


def test_resolve_sets_fields_and_marks_unseen(app_ctx):
    from app.models import BugReport
    from app.services import bug_reports as svc

    reporter = _mk_user("rep")
    admin = _mk_user("adm", role="admin")
    r = svc.create_report(reporter, "t", "b", None, None)

    svc.resolve_report(r, admin, "Fixed it.")
    assert r.status == BugReport.STATUS_RESOLVED
    assert r.resolved_by_id == admin.id
    assert r.resolution_note == "Fixed it."
    assert r.reporter_seen is False
    # reporter now has 1 unseen resolved report
    assert svc.unseen_resolved_count(reporter.id) == 1
    # after marking seen, count drops to 0
    svc.mark_reporter_seen(reporter.id)
    assert svc.unseen_resolved_count(reporter.id) == 0


def test_open_reports_lists_newest_first(app_ctx):
    from app.services import bug_reports as svc
    u = _mk_user("u")
    svc.create_report(u, "first", "b", None, None)
    svc.create_report(u, "second", "b", None, None)
    titles = [r.title for r in svc.open_reports()]
    assert titles == ["second", "first"]
