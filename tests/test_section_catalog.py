from tests.conftest import login, admin_user_id


def _approved(app, kind, name):
    from app.models import db, Template
    with app.app_context():
        t = Template(kind=kind, name=name, version=1, body='{"a":1}',
                     status=Template.STATUS_APPROVED, author="admin")
        db.session.add(t); db.session.commit()
        return t.id


def _pending(app, kind, name):
    from app.models import db, Template
    with app.app_context():
        t = Template(kind=kind, name=name, version=1, body="{}",
                     status=Template.STATUS_PENDING)
        db.session.add(t); db.session.commit()
        return t.id


def test_catalog_requires_login(client):
    r = client.get("/section-catalog/")
    assert r.status_code in (301, 302)


def test_catalog_lists_only_approved_grouped(client, app):
    from app.models import Template
    _approved(app, Template.KIND_WEB_PROTECTION, "wpp-approved")
    _pending(app, Template.KIND_WEB_PROTECTION, "wpp-pending")
    _approved(app, Template.KIND_SYSTEM, "sys-approved")
    login(client, admin_user_id(app))
    r = client.get("/section-catalog/")
    assert r.status_code == 200
    assert b"wpp-approved" in r.data
    assert b"sys-approved" in r.data
    assert b"wpp-pending" not in r.data        # pending never shows
    assert b"Web Protection" in r.data         # section grouping headers
    assert b"System" in r.data


def test_catalog_has_no_live_device_artifacts(client, app):
    # The page must be DB-only: no device picker / live object rows.
    login(client, admin_user_id(app))
    r = client.get("/section-catalog/")
    assert b"Select a device" not in r.data
    assert b"objedit" not in r.data
