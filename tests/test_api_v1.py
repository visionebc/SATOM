"""TDD for the /api/v1 third-party token surface + the ApiToken model.

Covers: hash-only storage, scope hierarchy, owner-RBAC ceiling, product/ADOM
binding, revoke/expiry, and the hard block on destructive actions.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from tests.conftest import admin_user_id, make_user


def _mint(app, *, owner_id, scopes, product="fortiweb", expires_at=None):
    from app.extensions import db
    from app.models import User
    from app.models_api_token import mint_token
    with app.app_context():
        owner = db.session.get(User, owner_id)
        tok, plaintext = mint_token(name="t", owner=owner, scopes=scopes,
                                    product=product, expires_at=expires_at)
        return tok.public_id, plaintext


def _auth(tokenstr):
    return {"Authorization": f"Bearer {tokenstr}"}


# --------------------------------------------------------------------- model

def test_secret_is_hashed_not_stored(app):
    _pid, plaintext = _mint(app, owner_id=admin_user_id(app), scopes=["read"])
    from app.extensions import db
    from app.models_api_token import ApiToken
    with app.app_context():
        row = ApiToken.query.first()
        assert row.token_hash and row.token_hash not in plaintext
        assert plaintext.split("_", 2)[2] not in row.token_hash
        assert "•" in row.masked and row.masked.startswith("fmk_")


def test_lookup_verifies_and_rejects(app):
    _pid, plaintext = _mint(app, owner_id=admin_user_id(app), scopes=["read"])
    from app.models_api_token import lookup
    with app.app_context():
        assert lookup(plaintext) is not None
        assert lookup(plaintext[:-3] + "xxx") is None  # tampered secret
        assert lookup("garbage") is None
        assert lookup("") is None


def test_scope_hierarchy(app):
    from app.extensions import db
    from app.models import User
    from app.models_api_token import mint_token
    with app.app_context():
        owner = db.session.get(User, admin_user_id(app))
        tok, _ = mint_token(name="a", owner=owner, scopes=["write"],
                            product="fortiweb")
        assert tok.has_scope("read") and tok.has_scope("write")
        assert not tok.has_scope("admin")


def test_revoked_and_expired_are_inactive(app):
    from app.extensions import db
    from app.models import User
    from app.models_api_token import mint_token
    with app.app_context():
        owner = db.session.get(User, admin_user_id(app))
        past = datetime.utcnow() - timedelta(days=1)
        exp, _ = mint_token(name="e", owner=owner, scopes=["read"],
                            product="fortiweb", expires_at=past)
        assert not exp.is_active
        rev, _ = mint_token(name="r", owner=owner, scopes=["read"],
                            product="fortiweb")
        rev.revoked = True
        db.session.commit()
        assert not rev.is_active


# ---------------------------------------------------------------------- http

def test_ping_requires_token(client):
    assert client.get("/api/v1/ping").status_code == 401


def test_ping_ok_with_token(app, client):
    _pid, plaintext = _mint(app, owner_id=admin_user_id(app), scopes=["read"])
    r = client.get("/api/v1/ping", headers=_auth(plaintext))
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] and body["owner"] == "admin" and "read" in body["scopes"]


def test_appliances_listing_is_json(app, client):
    _pid, plaintext = _mint(app, owner_id=admin_user_id(app), scopes=["read"])
    r = client.get("/api/v1/appliances", headers=_auth(plaintext))
    assert r.status_code == 200
    assert "appliances" in r.get_json()


def test_read_scope_cannot_run(app, client):
    _pid, plaintext = _mint(app, owner_id=admin_user_id(app), scopes=["read"])
    r = client.post("/api/v1/actions/1/run", headers=_auth(plaintext))
    assert r.status_code == 403
    assert r.get_json()["error"] == "insufficient_scope"


def test_write_token_owned_by_readonly_is_forbidden(app, client):
    uid = make_user(app, username="ro", role="readonly")
    _pid, plaintext = _mint(app, owner_id=uid, scopes=["write"])
    # scope is held, but the OWNER lacks config_write -> owner_forbidden
    r = client.post("/api/v1/actions/999/run", headers=_auth(plaintext))
    assert r.status_code == 403
    assert r.get_json()["error"] == "owner_forbidden"


def _make_action(app, action="upgrade", product="fortiweb"):
    from app.extensions import db
    from app.models import ScheduledAction
    with app.app_context():
        a = ScheduledAction(name="x", scope="admin", product=product,
                            action=action, enabled=True, schedule_kind="once")
        db.session.add(a)
        db.session.commit()
        return a.id


def test_destructive_action_blocked_even_with_write(app, client):
    aid = _make_action(app, action="upgrade")
    _pid, plaintext = _mint(app, owner_id=admin_user_id(app), scopes=["write"])
    r = client.post(f"/api/v1/actions/{aid}/run", headers=_auth(plaintext))
    assert r.status_code == 403
    assert r.get_json()["error"] == "destructive_blocked"


def test_wrong_product_token_cannot_run(app, client):
    # a fortiweb action, but the token is bound to the fortiadc ADOM
    aid = _make_action(app, action="stats", product="fortiweb")
    _pid, plaintext = _mint(app, owner_id=admin_user_id(app), scopes=["write"],
                            product="fortiadc")
    r = client.post(f"/api/v1/actions/{aid}/run", headers=_auth(plaintext))
    assert r.status_code == 403
    assert r.get_json()["error"] == "wrong_product"


# ------------------------------------------- external approval (audit AU-07)

def _ext_cr(app, *, mode="external", status="approved", kind="fortiweb"):
    import json as _json
    from app.extensions import db
    from app.models import Appliance, ChangeRequest
    with app.app_context():
        a = Appliance(name=f"ext-{kind}-{mode}-{status}", kind=kind,
                      host="192.0.2.50", username="admin", password_enc="x")
        db.session.add(a)
        db.session.commit()
        now = datetime.utcnow()
        cr = ChangeRequest(title="ext", status=status, action="device_sync",
                           approval_mode=mode, device_ids=_json.dumps([a.id]),
                           window_start=now - timedelta(minutes=5),
                           window_end=now + timedelta(hours=1))
        db.session.add(cr)
        db.session.commit()
        return cr.id


def _cr(app, cid):
    from app.extensions import db
    from app.models import ChangeRequest
    with app.app_context():
        cr = db.session.get(ChangeRequest, cid)
        return cr.external_approved_at, cr.external_approved_by


def _url(cid):
    return f"/api/v1/change-requests/{cid}/external-approval"


def test_an_admin_token_records_and_withdraws_an_external_approval(app, client):
    from app.models import AuditLog
    from app.services import change_requests as svc
    cid = _ext_cr(app)
    _pid, tok = _mint(app, owner_id=admin_user_id(app), scopes=["admin"])
    r = client.post(_url(cid), json={"approved": True, "by": "CAB",
                                     "detail": "CHG-7"}, headers=_auth(tok))
    assert r.status_code == 200, r.get_json()
    at, by = _cr(app, cid)
    assert at is not None and by == "api:CAB"
    with app.app_context():
        from app.extensions import db
        from app.models import ChangeRequest
        ok, why = svc.cr_runnable(db.session.get(ChangeRequest, cid))
        assert ok, why
        assert AuditLog.query.filter_by(
            action="api.change_request.external_approval").count() == 1
    r = client.post(_url(cid), json={"approved": False}, headers=_auth(tok))
    assert r.status_code == 200
    assert _cr(app, cid)[0] is None


def test_external_approval_needs_the_admin_scope(app, client):
    cid = _ext_cr(app)
    _pid, tok = _mint(app, owner_id=admin_user_id(app), scopes=["write"])
    r = client.post(_url(cid), json={"approved": True}, headers=_auth(tok))
    assert r.status_code == 403
    assert _cr(app, cid)[0] is None


def test_external_approval_token_owner_needs_user_manage(app, client):
    from tests.conftest import profile_id
    cid = _ext_cr(app)
    op = make_user(app, username="opx", role="operator",
                   profile_id=profile_id(app, "operator"))
    _pid, tok = _mint(app, owner_id=op, scopes=["admin"])
    r = client.post(_url(cid), json={"approved": True}, headers=_auth(tok))
    assert r.status_code == 403
    assert _cr(app, cid)[0] is None


def test_a_manual_or_closed_change_refuses_an_external_verdict(app, client):
    from app.models import AuditLog
    _pid, tok = _mint(app, owner_id=admin_user_id(app), scopes=["admin"])
    for kw in ({"mode": "manual"}, {"status": "completed"}):
        cid = _ext_cr(app, **kw)
        r = client.post(_url(cid), json={"approved": True}, headers=_auth(tok))
        assert r.status_code == 409, kw
        assert _cr(app, cid)[0] is None
    with app.app_context():
        assert AuditLog.query.filter_by(
            action="api.change_request.external_approval_refused").count() == 2


def test_external_approval_requires_a_boolean(app, client):
    cid = _ext_cr(app)
    _pid, tok = _mint(app, owner_id=admin_user_id(app), scopes=["admin"])
    r = client.post(_url(cid), json={"approved": "yes"}, headers=_auth(tok))
    assert r.status_code == 400
    assert _cr(app, cid)[0] is None


def test_a_change_in_another_adom_is_not_found(app, client):
    cid = _ext_cr(app, kind="fortiadc")
    _pid, tok = _mint(app, owner_id=admin_user_id(app), scopes=["admin"],
                      product="fortiweb")
    r = client.post(_url(cid), json={"approved": True}, headers=_auth(tok))
    assert r.status_code == 404
    assert _cr(app, cid)[0] is None


def test_the_console_records_an_external_verdict_by_hand(app, client):
    from tests.conftest import login, profile_id
    cid = _ext_cr(app)
    op = make_user(app, username="opy", role="operator",
                   profile_id=profile_id(app, "operator"))
    login(client, op)
    client.post(f"/change-requests/{cid}/external-approval",
                data={"decision": "approve"})
    assert _cr(app, cid)[0] is None
    login(client, admin_user_id(app))
    page = client.get(f"/change-requests/{cid}").get_data(as_text=True)
    import re
    assert re.search(r'action="[^"]*/change-requests/%d/external-approval"' % cid, page)
    r = client.post(f"/change-requests/{cid}/external-approval",
                    data={"decision": "approve", "detail": "phone"})
    assert r.status_code == 302
    at, by = _cr(app, cid)
    assert at is not None and by.endswith("(by hand)")
    manual = _ext_cr(app, mode="manual")
    client.post(f"/change-requests/{manual}/external-approval",
                data={"decision": "approve"})
    assert _cr(app, manual)[0] is None
