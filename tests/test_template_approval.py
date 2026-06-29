"""TDD for the template approval workflow: permissions, status lifecycle,
gated save/apply/approve."""
from __future__ import annotations

import app.permissions as P


def test_template_permissions_exist_and_map():
    keys = P.all_keys()
    assert "operations.template_save" in keys
    assert "operations.template_apply" in keys
    assert "operations.template_approve" in keys

    # save + apply are ordinary writes -> light up the legacy config_write gate
    assert "config_write" in P.derive_coarse({"operations.template_save"})
    assert "config_write" in P.derive_coarse({"operations.template_apply"})

    # operator gets author + device-apply, but NOT approval
    op = P.SYSTEM_PROFILES["operator"]
    assert "operations.template_save" in op
    assert "operations.template_apply" in op
    assert "operations.template_approve" not in op

    # admin gets all three (admin == all_keys)
    ad = P.SYSTEM_PROFILES["admin"]
    assert "operations.template_approve" in ad

    # template_approve is admin-only in the catalog metadata
    by_key = {p["key"]: p for p in P.GRANULAR_PERMISSIONS}
    assert by_key["operations.template_approve"]["admin_only"] is True
    assert by_key["operations.template_save"]["admin_only"] is False


def test_template_status_defaults_pending(app):
    from app.extensions import db
    from app.models import Template
    with app.app_context():
        t = Template(kind=Template.KIND_SYSTEM, name="t1", version=1, body="{}")
        db.session.add(t)
        db.session.commit()
        assert t.status == Template.STATUS_PENDING
        assert t.is_approved is False
        assert t.reject_reason in ("", None)
        assert t.reviewed_by in ("", None)
        assert t.reviewed_at is None


def test_approve_and_reject_service(app):
    from app.extensions import db
    from app.models import Template
    from app.services import templates as lib
    with app.app_context():
        row = lib.save_template(Template.KIND_SYSTEM, "svc-1", {"a": 1},
                                author="bob")
        assert row.status == Template.STATUS_PENDING
        assert row.author == "bob"

        approved = lib.approve_template(row.id, reviewer="admin")
        assert approved.status == Template.STATUS_APPROVED
        assert approved.reviewed_by == "admin"
        assert approved.reviewed_at is not None
        assert approved.reject_reason == ""

        rejected = lib.reject_template(row.id, reviewer="admin",
                                       reason="bad cipher list")
        assert rejected.status == Template.STATUS_REJECTED
        assert rejected.reject_reason == "bad cipher list"
        assert rejected.reviewed_by == "admin"


def test_edit_makes_new_pending_version_old_stays_approved(app):
    from app.models import Template
    from app.services import templates as lib
    with app.app_context():
        v1 = lib.save_template(Template.KIND_SYSTEM, "svc-2", {"a": 1},
                               author="bob")
        lib.approve_template(v1.id, reviewer="admin")
        # editing == saving a NEW version of the same kind/name
        v2 = lib.save_template(Template.KIND_SYSTEM, "svc-2", {"a": 2},
                               author="bob", new_version=True)
        assert v2.version == 2
        assert v2.status == Template.STATUS_PENDING
        # the previously approved version is untouched / still fleet-usable
        again = lib.get_template(v1.id)
        assert again.status == Template.STATUS_APPROVED


def _seed_template(app, status="pending", author="bob"):
    from app.models import Template
    from app.services import templates as lib
    with app.app_context():
        row = lib.save_template(Template.KIND_SYSTEM, "route-t", {"a": 1},
                                author=author)
        if status != Template.STATUS_PENDING:
            if status == Template.STATUS_APPROVED:
                lib.approve_template(row.id, reviewer="admin")
            else:
                lib.reject_template(row.id, reviewer="admin", reason="no")
        return row.id


def test_operator_can_save_but_not_approve(app, client):
    from tests.conftest import make_user, profile_id, login
    op = make_user(app, username="op", role="operator",
                   profile_id=profile_id(app, "operator"))
    login(client, op)
    # save allowed
    r = client.post("/templates/", data={
        "kind": "system-profile", "name": "op-made", "body": "{}", "note": ""},
        follow_redirects=False)
    assert r.status_code in (302, 200)
    tid = _seed_template(app)
    # approve forbidden for operator
    r2 = client.post(f"/templates/{tid}/approve")
    assert r2.status_code == 403


def test_admin_can_approve_and_reject(app, client):
    from tests.conftest import admin_user_id, login
    login(client, admin_user_id(app))
    tid = _seed_template(app)
    r = client.post(f"/templates/{tid}/approve")
    assert r.status_code in (302, 200)
    from app.services import templates as lib
    with app.app_context():
        assert lib.get_template(tid).status == "approved"
    r2 = client.post(f"/templates/{tid}/reject", data={"reason": "rollback risk"})
    assert r2.status_code in (302, 200)
    with app.app_context():
        row = lib.get_template(tid)
        assert row.status == "rejected"
        assert row.reject_reason == "rollback risk"


def test_single_device_apply_allowed_on_pending(app, client, monkeypatch):
    from tests.conftest import make_user, profile_id, login
    # avoid touching a real device: stub the runner used by the apply view
    import app.views.templates as v
    monkeypatch.setattr(v.BulkRunner, "preview",
                        lambda self, ids: [{"device_id": i, "ok": True} for i in ids])
    op = make_user(app, username="op2", role="operator",
                   profile_id=profile_id(app, "operator"))
    login(client, op)
    tid = _seed_template(app, status="pending")
    # dry-run preview (no confirm) to ONE device — allowed even while pending
    r = client.post(f"/templates/{tid}/apply",
                    data={"device_ids": "1", "format": "json"})
    assert r.status_code == 200
    assert r.get_json()["ok"] is True


def test_multi_device_apply_blocked_until_approved(app, client, monkeypatch):
    from tests.conftest import make_user, profile_id, login
    import app.views.templates as v
    monkeypatch.setattr(v.BulkRunner, "preview",
                        lambda self, ids: [{"device_id": i, "ok": True} for i in ids])
    op = make_user(app, username="op3", role="operator",
                   profile_id=profile_id(app, "operator"))
    login(client, op)
    tid = _seed_template(app, status="pending")
    # >1 device on a PENDING template -> refused
    r = client.post(f"/templates/{tid}/apply",
                    data={"device_ids": ["1", "2"], "format": "json"})
    assert r.status_code == 403
    # after approval, the same multi-device preview is allowed
    from app.services import templates as lib
    with app.app_context():
        lib.approve_template(tid, reviewer="admin")
    r2 = client.post(f"/templates/{tid}/apply",
                     data={"device_ids": ["1", "2"], "format": "json"})
    assert r2.status_code == 200


def test_templates_index_renders(app, client):
    from tests.conftest import admin_user_id, login
    login(client, admin_user_id(app))
    r = client.get("/templates/")
    assert r.status_code == 200
    assert b"Status" in r.data  # the new Status column header
