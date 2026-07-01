"""Model-level tests for BugReport (no HTTP, in-memory SQLite)."""
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


def test_bug_report_defaults_and_roundtrip(app_ctx):
    from app.models import db, BugReport

    r = BugReport(
        reporter_id=1,
        reporter_username="alice",
        title="Login button broken",
        body="Clicking Login does nothing on Firefox.",
        page_url="https://fw.example/policies",
        user_agent="Mozilla/5.0 Firefox/128",
    )
    db.session.add(r)
    db.session.commit()

    got = BugReport.query.one()
    assert got.status == BugReport.STATUS_OPEN
    assert got.resolved_by_id is None
    assert got.resolved_at is None
    assert got.resolution_note is None
    assert got.reporter_seen is False
    assert got.created_at is not None


def test_bug_report_resolve_fields(app_ctx):
    from app.models import db, BugReport
    from datetime import datetime

    r = BugReport(reporter_id=2, reporter_username="bob", title="t", body="b")
    db.session.add(r)
    db.session.commit()

    r.status = BugReport.STATUS_RESOLVED
    r.resolved_by_id = 9
    r.resolved_at = datetime.utcnow()
    r.resolution_note = "Fixed in build 42."
    db.session.commit()

    got = BugReport.query.get(r.id)
    assert got.status == BugReport.STATUS_RESOLVED
    assert got.resolution_note == "Fixed in build 42."
