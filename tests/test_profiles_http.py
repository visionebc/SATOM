"""HTTP-level security contract for the profiles admin blueprint."""
from __future__ import annotations

from tests.conftest import login, make_user, profile_id, admin_user_id


def _admin_login(app, client):
    login(client, admin_user_id(app))


def test_profiles_index_requires_profiles_manage(app, client):
    # operator (no profiles.manage) is forbidden
    op_id = make_user(app, "op1", role="operator", profile_id=profile_id(app, "operator"))
    login(client, op_id)
    assert client.get("/profiles/").status_code == 403

    # admin can see it
    _admin_login(app, client)
    assert client.get("/profiles/").status_code == 200


def test_admin_can_create_custom_profile_dropping_bogus_keys(app, client):
    _admin_login(app, client)
    r = client.post("/profiles/", data={
        "name": "WAF Editor",
        "description": "WAF only",
        "perms": ["protection.view", "protection.edit", "protection.apply", "bogus.key"],
    }, follow_redirects=True)
    assert r.status_code == 200
    from app.models import Profile
    with app.app_context():
        p = Profile.query.filter_by(name="WAF Editor").first()
        assert p is not None
        assert p.permission_set == {"protection.view", "protection.edit", "protection.apply"}
        assert p.is_system is False


def test_cannot_delete_system_profile(app, client):
    _admin_login(app, client)
    pid = profile_id(app, "admin")
    client.post(f"/profiles/{pid}/delete", follow_redirects=True)
    from app.models import Profile, db
    with app.app_context():
        assert db.session.get(Profile, pid) is not None  # still there


def test_cannot_delete_profile_assigned_to_users(app, client):
    _admin_login(app, client)
    # custom profile with a user on it
    from app.models import Profile, db
    with app.app_context():
        p = Profile(name="inuse"); p.permission_set = {"monitoring.view"}
        db.session.add(p); db.session.commit()
        pid = p.id
    make_user(app, "member", role="readonly", profile_id=pid)
    client.post(f"/profiles/{pid}/delete", follow_redirects=True)
    from app.models import Profile, db
    with app.app_context():
        assert db.session.get(Profile, pid) is not None  # blocked — still assigned


def test_cannot_strip_admin_caps_from_last_admin_profile(app, client):
    """Editing the admin profile to drop users.manage/profiles.manage must be
    blocked while admin-capable users depend on it (anti-lockout)."""
    _admin_login(app, client)
    pid = profile_id(app, "admin")
    client.post(f"/profiles/{pid}/edit", data={
        "name": "admin",
        "description": "nerfed",
        "perms": ["monitoring.view"],   # removes all admin capabilities
    }, follow_redirects=True)
    from app.models import Profile, db
    with app.app_context():
        p = db.session.get(Profile, pid)
        # unchanged: still admin-capable
        assert p.is_admin_capable is True


def test_can_edit_admin_profile_when_another_admin_exists(app, client):
    """If a second admin-capable profile/user exists, editing one admin profile
    down is allowed."""
    _admin_login(app, client)
    from app.models import Profile, db
    with app.app_context():
        # a second admin-capable profile, with its own active user
        p2 = Profile(name="admin2")
        p2.permission_set = set(__import__("app.permissions", fromlist=["x"]).SYSTEM_PROFILES["admin"])
        db.session.add(p2); db.session.commit()
        pid2 = p2.id
    make_user(app, "boss2", role="admin", profile_id=pid2)

    # now nerf the FIRST (custom, non-system) admin-capable profile -> allowed
    from app.models import Profile, db
    with app.app_context():
        cust = Profile(name="cadmin")
        cust.permission_set = set(__import__("app.permissions", fromlist=["x"]).SYSTEM_PROFILES["admin"])
        db.session.add(cust); db.session.commit()
        cid = cust.id
    client.post(f"/profiles/{cid}/edit", data={
        "name": "cadmin", "description": "", "perms": ["monitoring.view"],
    }, follow_redirects=True)
    with app.app_context():
        assert db.session.get(Profile, cid).is_admin_capable is False  # edit applied


def test_clone_creates_non_system_copy(app, client):
    _admin_login(app, client)
    pid = profile_id(app, "operator")
    client.post(f"/profiles/{pid}/clone", follow_redirects=True)
    from app.models import Profile
    with app.app_context():
        clones = Profile.query.filter(Profile.name.like("operator%"),
                                      Profile.is_system.is_(False)).all()
        assert len(clones) >= 1
        assert clones[0].permission_set == Profile.query.filter_by(name="operator").first().permission_set
