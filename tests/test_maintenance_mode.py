"""Maintenance mode: appliances flagged as in-maintenance are hidden from
anyone lacking the appliances.view_maintenance permission (operators),
while admins see them plus a badge and can still use them for testing.

This is a VISIBILITY-SECURITY feature: its failure mode is silent (a hidden
device leaking to an operator), so the matrix below is the regression guard.
"""
from __future__ import annotations

import pytest
from werkzeug.exceptions import NotFound

from tests.conftest import login, make_user, profile_id, admin_user_id


def _make_appliance(app, name="fw-normal", maintenance=False):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name=name, kind="fortiweb", host="192.0.2.99",
                      port=443, username="admin", verify_ssl=False)
        a.password = "secret"
        a.maintenance = maintenance
        db.session.add(a); db.session.commit()
        return a.id


# --- catalog + model --------------------------------------------------------

def test_permission_catalog_has_view_maintenance():
    from app import permissions as perm
    assert "appliances.view_maintenance" in perm.all_keys()


def test_admin_profile_has_it_operator_does_not(app):
    from app.models import Profile
    with app.app_context():
        admin = Profile.query.filter_by(name="admin").first()
        operator = Profile.query.filter_by(name="operator").first()
        readonly = Profile.query.filter_by(name="readonly").first()
        assert "appliances.view_maintenance" in admin.effective
        assert "appliances.view_maintenance" not in operator.effective
        assert "appliances.view_maintenance" not in readonly.effective


def test_maintenance_defaults_false(app):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw-x", kind="fortiweb", host="h", port=443,
                      username="u", verify_ssl=False)
        a.password = "p"
        db.session.add(a); db.session.commit()
        assert a.maintenance is False


# --- helper: visible_appliances / can_view_maintenance ----------------------

def test_visible_appliances_hides_from_operator(app):
    from app.models import User, visible_appliances
    normal = _make_appliance(app, "fw-normal")
    maint = _make_appliance(app, "fw-maint", maintenance=True)
    op_id = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    with app.app_context():
        op = User.query.get(op_id)
        ids = {a.id for a in visible_appliances(user=op).all()}
        assert normal in ids
        assert maint not in ids


def test_visible_appliances_shows_admin(app):
    from app.models import User, visible_appliances
    normal = _make_appliance(app, "fw-normal")
    maint = _make_appliance(app, "fw-maint", maintenance=True)
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        ids = {a.id for a in visible_appliances(user=admin).all()}
        assert normal in ids and maint in ids


def test_visible_appliance_or_404_operator(app):
    from app.models import User, visible_appliance_or_404
    maint = _make_appliance(app, "fw-maint", maintenance=True)
    op_id = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    with app.app_context():
        op = User.query.get(op_id)
        with pytest.raises(NotFound):
            visible_appliance_or_404(maint, user=op)


def test_visible_appliance_or_404_admin(app):
    from app.models import User, visible_appliance_or_404
    maint = _make_appliance(app, "fw-maint", maintenance=True)
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        got = visible_appliance_or_404(maint, user=admin)
        assert got.id == maint


# --- integration: list / detail / api / create ------------------------------

def test_index_hides_maintenance_from_operator(app, client):
    _make_appliance(app, "fw-normal")
    _make_appliance(app, "fw-secret-maint", maintenance=True)
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, op)
    r = client.get("/appliances/")
    assert r.status_code == 200
    assert b"fw-normal" in r.data
    assert b"fw-secret-maint" not in r.data


def test_index_shows_maintenance_to_admin(app, client):
    _make_appliance(app, "fw-secret-maint", maintenance=True)
    login(client, admin_user_id(app))
    r = client.get("/appliances/")
    assert r.status_code == 200
    assert b"fw-secret-maint" in r.data


def test_detail_404_for_operator_on_maintenance(app, client):
    maint = _make_appliance(app, "fw-maint", maintenance=True)
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, op)
    r = client.get(f"/appliances/{maint}")
    assert r.status_code == 404


def test_detail_ok_for_admin_on_maintenance(app, client):
    maint = _make_appliance(app, "fw-maint", maintenance=True)
    login(client, admin_user_id(app))
    r = client.get(f"/appliances/{maint}")
    assert r.status_code == 200


def test_api_list_hides_maintenance_from_operator(app, client):
    _make_appliance(app, "fw-normal")
    _make_appliance(app, "fw-secret-maint", maintenance=True)
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, op)
    r = client.get("/api/appliances")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "fw-normal" in body
    assert "fw-secret-maint" not in body


def test_operator_cannot_set_maintenance_on_create(app, client):
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, op)
    r = client.post("/appliances/", data={
        "name": "fw-op-made", "kind": "fortiweb", "host": "192.0.2.5",
        "port": "443", "username": "admin", "password": "x",
        "maintenance": "on",
    }, follow_redirects=False)
    from app.models import Appliance
    with app.app_context():
        a = Appliance.query.filter_by(name="fw-op-made").first()
        assert a is not None
        assert a.maintenance is False


def test_admin_can_set_maintenance_on_create(app, client):
    login(client, admin_user_id(app))
    client.post("/appliances/", data={
        "name": "fw-admin-made", "kind": "fortiweb", "host": "192.0.2.6",
        "port": "443", "username": "admin", "password": "x",
        "maintenance": "on",
    }, follow_redirects=False)
    from app.models import Appliance
    with app.app_context():
        a = Appliance.query.filter_by(name="fw-admin-made").first()
        assert a is not None
        assert a.maintenance is True


def test_device_context_hides_maintenance_from_operator(app):
    from app.models import User
    from app.services import device_context
    from flask_login import login_user
    op_id = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    maint = _make_appliance(app, "fw-maint", maintenance=True)
    with app.test_request_context():
        op = User.query.get(op_id)
        login_user(op)
        from flask import session
        session[device_context.SESSION_KEY] = maint
        assert device_context.current_appliance() is None


# --- edit_save sentinel: maintenance changes ONLY when the control was rendered

def test_edit_preserves_maintenance_without_sentinel(app, client):
    maint = _make_appliance(app, "fw-e1", maintenance=True)
    login(client, admin_user_id(app))
    client.post(f"/appliances/{maint}/edit", data={
        "name": "fw-e1", "kind": "fortiweb", "host": "192.0.2.9",
        "port": "443", "username": "admin",
    }, follow_redirects=False)
    from app.models import Appliance
    with app.app_context():
        assert Appliance.query.get(maint).maintenance is True


def test_edit_clears_maintenance_with_sentinel_unchecked(app, client):
    maint = _make_appliance(app, "fw-e2", maintenance=True)
    login(client, admin_user_id(app))
    client.post(f"/appliances/{maint}/edit", data={
        "name": "fw-e2", "kind": "fortiweb", "host": "192.0.2.9",
        "port": "443", "username": "admin", "maintenance_present": "1",
    }, follow_redirects=False)
    from app.models import Appliance
    with app.app_context():
        assert Appliance.query.get(maint).maintenance is False


def test_edit_sets_maintenance_with_sentinel_checked(app, client):
    a = _make_appliance(app, "fw-e3", maintenance=False)
    login(client, admin_user_id(app))
    client.post(f"/appliances/{a}/edit", data={
        "name": "fw-e3", "kind": "fortiweb", "host": "192.0.2.9",
        "port": "443", "username": "admin",
        "maintenance_present": "1", "maintenance": "on",
    }, follow_redirects=False)
    from app.models import Appliance
    with app.app_context():
        assert Appliance.query.get(a).maintenance is True


def test_operator_edit_cannot_forge_maintenance(app, client):
    a = _make_appliance(app, "fw-e4", maintenance=False)
    op = make_user(app, "ope", role="operator", profile_id=profile_id(app, "operator"))
    login(client, op)
    client.post(f"/appliances/{a}/edit", data={
        "name": "fw-e4", "kind": "fortiweb", "host": "192.0.2.9",
        "port": "443", "username": "admin",
        "maintenance_present": "1", "maintenance": "on",
    }, follow_redirects=False)
    from app.models import Appliance
    with app.app_context():
        assert Appliance.query.get(a).maintenance is False
