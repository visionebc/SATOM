"""HTTP contract for user<->profile assignment and capability anti-lockout."""
from __future__ import annotations

from tests.conftest import login, make_user, profile_id, admin_user_id


def _admin_login(app, client):
    login(client, admin_user_id(app))


def test_create_user_with_profile_assigns_and_syncs_role(app, client):
    _admin_login(app, client)
    op_pid = profile_id(app, "operator")
    client.post("/users/", data={
        "username": "alice", "password": "secret123",
        "confirm_password": "secret123", "profile_id": str(op_pid),
    }, follow_redirects=True)
    from app.models import User
    with app.app_context():
        u = User.query.filter_by(username="alice").first()
        assert u is not None
        assert u.profile_id == op_pid
        assert u.role == "operator"          # synced from profile
        assert u.can("config_write") is True
        assert u.can("user_manage") is False


def test_create_user_legacy_role_still_works(app, client):
    _admin_login(app, client)
    client.post("/users/", data={
        "username": "bobby", "password": "secret123",
        "confirm_password": "secret123", "role": "operator",
    }, follow_redirects=True)
    from app.models import User
    with app.app_context():
        u = User.query.filter_by(username="bobby").first()
        assert u is not None
        # legacy role path still assigns the matching system profile
        assert u.profile is not None and u.profile.name == "operator"


def test_set_profile_changes_assignment(app, client):
    _admin_login(app, client)
    uid = make_user(app, "carol", role="readonly", profile_id=profile_id(app, "readonly"))
    op_pid = profile_id(app, "operator")
    client.post(f"/users/{uid}/profile", data={"profile_id": str(op_pid)},
                follow_redirects=True)
    from app.models import User, db
    with app.app_context():
        u = db.session.get(User, uid)
        assert u.profile_id == op_pid
        assert u.role == "operator"


def test_cannot_downgrade_last_admin_profile(app, client):
    """Changing the only admin's profile to a non-admin one is blocked."""
    _admin_login(app, client)
    aid = admin_user_id(app)
    op_pid = profile_id(app, "operator")
    client.post(f"/users/{aid}/profile", data={"profile_id": str(op_pid)},
                follow_redirects=True)
    from app.models import User, db
    with app.app_context():
        u = db.session.get(User, aid)
        assert u.is_admin_capable is True          # unchanged
        assert u.profile.name == "admin"


def test_can_downgrade_admin_when_a_second_admin_exists(app, client):
    _admin_login(app, client)
    # second admin user
    make_user(app, "boss2", role="admin", profile_id=profile_id(app, "admin"))
    aid = admin_user_id(app)
    op_pid = profile_id(app, "operator")
    client.post(f"/users/{aid}/profile", data={"profile_id": str(op_pid)},
                follow_redirects=True)
    from app.models import User, db
    with app.app_context():
        assert db.session.get(User, aid).profile.name == "operator"   # applied


def test_cannot_delete_last_admin_user(app, client):
    _admin_login(app, client)
    # a non-admin to actually attempt deleting (admin can't delete self anyway,
    # but the capability guard is what we assert): make the seeded admin the
    # ONLY admin, add a custom admin via profile then delete it -> blocked when
    # it's the last one.
    aid = admin_user_id(app)
    # delete the seeded admin via a second admin acting:
    boss2 = make_user(app, "boss2", role="admin", profile_id=profile_id(app, "admin"))
    login(client, boss2)
    # now demote boss2-not-needed; instead delete the seeded admin (allowed, 2 admins)
    client.post(f"/users/{aid}/delete", follow_redirects=True)
    from app.models import User, db
    with app.app_context():
        assert db.session.get(User, aid) is None            # deleted (2 admins existed)
        # now boss2 is the LAST admin — deleting it must be blocked
    login(client, boss2)
    client.post(f"/users/{boss2}/delete", follow_redirects=True)
    with app.app_context():
        assert db.session.get(User, boss2) is not None       # blocked (self + last admin)


def test_cannot_disable_last_admin_user(app, client):
    _admin_login(app, client)
    boss2 = make_user(app, "boss2", role="admin", profile_id=profile_id(app, "admin"))
    # disable the seeded admin while boss2 exists -> allowed
    aid = admin_user_id(app)
    login(client, boss2)
    client.post(f"/users/{aid}/toggle-active", follow_redirects=True)
    from app.models import User, db
    with app.app_context():
        assert db.session.get(User, aid).is_active is False
    # now boss2 is the only active admin; disabling it (self) must be blocked
    client.post(f"/users/{boss2}/toggle-active", follow_redirects=True)
    with app.app_context():
        assert db.session.get(User, boss2).is_active is True
