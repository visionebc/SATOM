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
