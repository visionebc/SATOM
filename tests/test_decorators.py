"""The decorators must honour the assigned PROFILE, not the stale role."""
from __future__ import annotations


def _user_with_profile(app, perms, role="admin"):
    """A user whose legacy role is deliberately stale (admin) but whose profile
    grants only ``perms`` — exposes any code path still reading the role."""
    from app.models import User, Profile, db
    with app.app_context():
        p = Profile(name="narrow", is_system=False)
        p.permission_set = set(perms)
        db.session.add(p); db.session.commit()
        u = User(username="narrowuser", role=role)
        u.set_password("x"); u.profile_id = p.id
        db.session.add(u); db.session.commit()
        return db.session.get(User, u.id)


def test_rbac_has_permission_uses_profile_not_role(app):
    from app.rbac import has_permission
    with app.app_context():
        u = _user_with_profile(app, {"monitoring.view"})
        assert has_permission(u, "view") is True            # derived from monitoring.view
        assert has_permission(u, "config_write") is False   # role says admin, profile says no
        assert has_permission(u, "user_manage") is False
        assert has_permission(u, "monitoring.view") is True  # granular key honoured


def test_rbac_anonymous_denied(app):
    from app.rbac import has_permission
    class _Anon:
        is_authenticated = False
    assert has_permission(_Anon(), "view") is False
