"""HTTP contract for user<->profile assignment and capability anti-lockout."""
from __future__ import annotations

from tests.conftest import login, make_user, profile_id, admin_user_id


def _admin_login(app, client):
    login(client, admin_user_id(app))


def test_create_user_with_profile_assigns_and_syncs_role(app, client):
    _admin_login(app, client)
    op_pid = profile_id(app, "operator")
    client.post("/users/", data={
        "username": "alice", "password": "secret-123456",
        "confirm_password": "secret-123456", "profile_id": str(op_pid),
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
        "username": "bobby", "password": "secret-123456",
        "confirm_password": "secret-123456", "role": "operator",
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


# --- Documentation Center audit, 2026-10-03 (AD-02, AD-07, AD-08, AD-09,
# AD-10, AD-11, AD-12, AD-61) ------------------------------------------------

def _custom_user(app, name, keys):
    from app.models import Profile, db
    with app.app_context():
        p = Profile(name=f"p-{name}", is_system=False)
        p.permission_set = set(keys)
        db.session.add(p)
        db.session.commit()
        pid = p.id
    return make_user(app, name, profile_id=pid)


def _audit_rows(app, action):
    from app.models import AuditLog
    with app.app_context():
        return [(r.target, r.extra) for r in AuditLog.query.filter_by(action=action).all()]


def test_profile_change_writes_one_audit_row_with_from_and_to(app, client):
    _admin_login(app, client)
    uid = make_user(app, "dana", role="readonly", profile_id=profile_id(app, "readonly"))
    r = client.post(f"/users/{uid}/profile", data={"profile_id": str(profile_id(app, "operator"))})
    assert r.status_code == 302
    rows = _audit_rows(app, "user.profile.set")
    assert len(rows) == 1, rows
    assert rows[0][0] == "dana"
    import ast
    assert ast.literal_eval(rows[0][1]) == {"from": "readonly", "to": "operator"}


def test_dead_edit_and_role_routes_are_gone(app, client):
    _admin_login(app, client)
    uid = make_user(app, "erin")
    assert client.get(f"/users/{uid}/edit").status_code == 404
    assert client.post(f"/users/{uid}/edit", data={"username": "admin"}).status_code == 404
    assert client.post(f"/users/{uid}/role", data={"role": "admin"}).status_code == 404


def test_users_view_opens_a_read_only_list(app, client):
    uid = _custom_user(app, "viewer", {"users.view"})
    make_user(app, "someone")
    login(client, uid)
    r = client.get("/users/")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "someone" in html
    assert "Read-only view" in html
    for marker in ('id="modalAddUser"', 'action="/users/', 'id="modalResetPassword"',
                   'title="Change Profile"'):
        assert marker not in html, marker
    # The sidebar offers the list to a users.view holder.
    assert 'href="/users/"' in html
    # ...and every action stays behind users.manage.
    other = make_user(app, "target2")
    assert client.post(f"/users/{other}/toggle-active").status_code == 403
    assert client.post(f"/users/{other}/unlock").status_code == 403
    assert client.post(f"/users/{other}/reset-password",
                       data={"new_password": "twelve-chars-x"}).status_code == 403


def test_without_users_view_the_list_stays_closed(app, client):
    uid = _custom_user(app, "nolist", {"monitoring.view"})
    login(client, uid)
    assert client.get("/users/").status_code == 403


def test_admin_counter_counts_admin_capable_users(app, client):
    _admin_login(app, client)
    # legacy role says admin, profile says readonly: NOT an admin
    make_user(app, "fakeadmin", role="admin", profile_id=profile_id(app, "readonly"))
    _custom_user(app, "realadmin", {"users.manage", "profiles.manage"})
    _custom_user(app, "realadmin2", {"users.manage", "profiles.manage"})
    html = client.get("/users/").get_data(as_text=True)
    import re
    m = re.search(r'fw-stat-value">\s*(\d+)\s*</div>\s*<div class="fw-stat-label"[^>]*>Admins<', html)
    # admin + realadmin + realadmin2; the legacy-role count would say 2
    assert m and m.group(1) == "3", "admin counter must count admin-capable users"
    assert "Settings → Access &amp; Identity → Profiles" in html or \
        "Settings → Access & Identity → Profiles" in html


def test_unlock_clears_the_lockout_is_audited_and_keeps_the_account_disabled(app, client):
    from datetime import datetime, timedelta
    from app.models import User, db
    uid = make_user(app, "lockedout", active=False)
    with app.app_context():
        u = db.session.get(User, uid)
        u.failed_logins = 10
        u.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()
    _admin_login(app, client)
    html = client.get("/users/").get_data(as_text=True)
    assert f"/users/{uid}/unlock" in html, "no Unlock control for a locked account"
    r = client.post(f"/users/{uid}/unlock")
    assert r.status_code == 302
    with app.app_context():
        u = db.session.get(User, uid)
        assert (u.failed_logins, u.locked_until) == (0, None)
        assert u.is_active is False
    assert [t for t, _ in _audit_rows(app, "user.unlock")] == ["lockedout"]


def test_reset_password_and_clear_2fa_are_reachable_and_audited(app, client):
    from app.models import User, db
    uid = make_user(app, "frank")
    with app.app_context():
        u = db.session.get(User, uid)
        u.totp_enabled = True
        u.totp_secret = "x"
        db.session.commit()
    _admin_login(app, client)
    html = client.get("/users/").get_data(as_text=True)
    assert 'title="Reset password" data-js="reset-password"' in html
    assert f"/users/{uid}/clear-2fa" in html
    client.post(f"/users/{uid}/reset-password",
                data={"new_password": "brand-new-pass", "confirm_password": "brand-new-pass"})
    client.post(f"/users/{uid}/clear-2fa")
    with app.app_context():
        u = db.session.get(User, uid)
        assert u.check_password("brand-new-pass")
        assert u.totp_enabled is False and u.totp_secret is None
    assert [t for t, _ in _audit_rows(app, "user.reset_password")] == ["frank"]
    assert [t for t, _ in _audit_rows(app, "user.clear_2fa")] == ["frank"]


def test_reset_password_refuses_a_directory_account_and_a_mismatch(app, client):
    from app.models import User, db
    uid = make_user(app, "ldapguy")
    with app.app_context():
        db.session.get(User, uid).auth_source = "ldap"
        db.session.commit()
    local = make_user(app, "localguy")
    _admin_login(app, client)
    client.post(f"/users/{uid}/reset-password",
                data={"new_password": "brand-new-pass", "confirm_password": "brand-new-pass"})
    client.post(f"/users/{local}/reset-password",
                data={"new_password": "brand-new-pass", "confirm_password": "other-pass-123"})
    with app.app_context():
        assert db.session.get(User, uid).check_password("pw")
        assert db.session.get(User, local).check_password("pw")
    assert _audit_rows(app, "user.reset_password") == []
