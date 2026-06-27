"""TDD: Profile ORM model, User<->Profile resolution, anti-lockout counting."""
from __future__ import annotations


def _mk_profile(name, perms, system=False):
    from app.models import Profile, db
    p = Profile(name=name, description="", is_system=system)
    p.permission_set = set(perms)
    db.session.add(p)
    db.session.commit()
    return p


def test_profile_stores_and_round_trips_permission_set(app):
    with app.app_context():
        p = _mk_profile("custom", {"monitoring.view", "protection.edit"})
        assert p.permission_set == {"monitoring.view", "protection.edit"}
        assert p.has("protection.edit") is True
        assert p.has("network.apply") is False


def test_profile_ignores_unknown_keys(app):
    with app.app_context():
        p = _mk_profile("weird", {"monitoring.view", "totally.bogus"})
        assert "totally.bogus" not in p.permission_set
        assert "monitoring.view" in p.permission_set


def test_user_with_profile_resolves_permissions_from_it(app):
    from app import permissions as P
    from app.models import User, db
    with app.app_context():
        op = _mk_profile("ops", P.SYSTEM_PROFILES["operator"])
        u = User(username="opuser", role="readonly")  # role intentionally stale
        u.set_password("x"); u.profile_id = op.id
        db.session.add(u); db.session.commit()

        # granular checks
        assert u.can("appliances.apply") is True
        assert u.can("registry.edit") is False
        assert u.can("users.manage") is False
        # legacy coarse still works (profile derives them)
        assert u.can("config_write") is True
        assert u.can("backup") is True
        assert u.can("user_manage") is False
        # profile wins over the stale role
        assert u.can("view") is True


def test_admin_profile_user_has_admin_capabilities(app):
    from app import permissions as P
    from app.models import User, db
    with app.app_context():
        ad = _mk_profile("supers", P.SYSTEM_PROFILES["admin"])
        u = User(username="boss", role="readonly")
        u.set_password("x"); u.profile_id = ad.id
        db.session.add(u); db.session.commit()
        assert u.can("users.manage") is True
        assert u.can("profiles.manage") is True
        assert u.is_admin_capable is True
        for c in ("view", "backup", "config_write", "registry_edit", "user_manage"):
            assert u.can(c) is True


def test_user_without_profile_falls_back_to_role(app):
    from app.models import User, db
    with app.app_context():
        u = User(username="legacy_admin", role="admin")
        u.set_password("x")
        db.session.add(u); db.session.commit()
        assert u.profile_id is None
        # legacy coarse + granular fallback both work
        assert u.can("user_manage") is True
        assert u.can("users.manage") is True
        assert u.is_admin_capable is True


def test_boot_seeds_system_profiles_and_assigns_admin(app):
    from app.models import Profile, User
    with app.app_context():
        for name in ("readonly", "operator", "admin"):
            p = Profile.query.filter_by(name=name).first()
            assert p is not None, name
            assert p.is_system is True
        admin = User.query.filter_by(username="admin").first()
        assert admin.profile is not None
        assert admin.profile.name == "admin"


def test_active_admin_count_is_capability_based(app):
    from app import permissions as P
    from app.models import User, db
    from app.services.access import active_admin_count
    with app.app_context():
        start = active_admin_count()
        assert start >= 1  # the seeded admin
        # add a second admin-capable user
        ad = Profile_admin_id()
        u = User(username="boss2", role="admin"); u.set_password("x"); u.profile_id = ad
        db.session.add(u); db.session.commit()
        assert active_admin_count() == start + 1
        # excluding that user drops the count again
        assert active_admin_count(exclude_id=u.id) == start
        # a disabled admin is not counted
        u.is_active = False; db.session.commit()
        assert active_admin_count() == start


def Profile_admin_id():
    from app.models import Profile
    return Profile.query.filter_by(name="admin").first().id
