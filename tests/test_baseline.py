"""Characterization tests: lock the CURRENT RBAC behavior before refactoring.

These must keep passing after profiles land — they encode the back-compat
contract (legacy roles + legacy coarse permission keys keep working).
"""
from __future__ import annotations


def test_app_boots_and_seeds_admin(app):
    from app.models import User
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        assert admin is not None
        assert admin.role == "admin"


def test_legacy_role_permissions_unchanged(app):
    """readonly→{view}, operator→{view,backup,config_write}, admin→all five."""
    from app.models import User, db, Role
    with app.app_context():
        ro = User(username="ro", role="readonly"); ro.set_password("x")
        op = User(username="op", role="operator"); op.set_password("x")
        ad = User(username="ad", role="admin"); ad.set_password("x")
        db.session.add_all([ro, op, ad]); db.session.commit()

        assert ro.can("view") is True
        assert ro.can("config_write") is False
        assert ro.can("user_manage") is False

        assert op.can("view") is True
        assert op.can("backup") is True
        assert op.can("config_write") is True
        assert op.can("user_manage") is False

        for perm in ("view", "backup", "config_write", "registry_edit", "user_manage"):
            assert ad.can(perm) is True, perm
