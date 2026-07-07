"""Render smoke tests for the new profile/user admin pages."""
from __future__ import annotations

from tests.conftest import login, admin_user_id, profile_id


def _admin(app, client):
    login(client, admin_user_id(app))


def test_profiles_index_renders(app, client):
    _admin(app, client)
    r = client.get("/profiles/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Permission Profiles" in body
    assert "readonly" in body and "operator" in body and "admin" in body


def test_system_profile_matrix_renders_readonly(app, client):
    _admin(app, client)
    r = client.get(f"/profiles/{profile_id(app, 'operator')}/edit")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Web Protection" in body          # an area label
    assert "appliances.apply" in body        # a permission key checkbox
    assert "managed automatically" in body   # system read-only notice


def test_custom_profile_matrix_renders_editable(app, client):
    _admin(app, client)
    client.post("/profiles/", data={"name": "Auditor", "description": "read audit"},
                follow_redirects=True)
    pid = profile_id(app, "Auditor")
    r = client.get(f"/profiles/{pid}/edit")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Save permissions" in body        # editable form present
    assert 'name="perms"' in body


def test_users_index_shows_profile_column(app, client):
    _admin(app, client)
    r = client.get("/users/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert ">Profile<" in body                # column header
    assert "Change Profile" in body           # per-row control
    assert "profile_id" in body               # add-user picker


def test_user_edit_page_renders_profile_picker(app, client):
    _admin(app, client)
    r = client.get(f"/users/{admin_user_id(app)}/edit")
    assert r.status_code == 200
    assert 'name="profile_id"' in r.get_data(as_text=True)


def test_home_is_global_dashboard_when_logged_in(app, client):
    # '/' is the GLOBAL ADOM (2026-07-07): a logged-in user gets the
    # fleet-wide dashboard directly, not a redirect.
    _admin(app, client)
    r = client.get("/")
    assert r.status_code == 200
    assert "Global" in r.get_data(as_text=True)
