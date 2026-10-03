"""Smaller security findings of the Documentation Center audit (2026-10-03).

* GS-02 / AD-03 / AD-04 / AD-05 -- one password minimum on every web path
  (Settings -> Change Password, Add User and the admin reset accepted any
  non-empty password under an "at least 8 characters" placeholder).
* AD-47 -- an ``admin``-scope token widened the WAF listing even when its
  owner had no Manage users; AD-48 -- minting/editing gave a token scopes its
  owner cannot use.
* TR-01 -- the System Backup peer comparison talked to the peer on plain
  :8000, which the loopback-only unit no longer answers; it goes through the
  node vhost (:8443) like every other peer probe.
"""
from __future__ import annotations

import pytest

from conftest import admin_user_id, login, make_user, profile_id


def _pw_ok(app, uid, pw):
    from app.models import User
    with app.app_context():
        return User.query.get(uid).check_password(pw)


def test_change_password_refuses_a_short_password(app, client):
    uid = make_user(app, "self")
    login(client, uid)
    client.post("/settings/change-password", data={
        "current_password": "pw", "new_password": "abc", "confirm_password": "abc"})
    assert _pw_ok(app, uid, "pw"), "a 3-character password was accepted"
    # The ONE policy is 12 characters (AD-06/GS-03/TR-18): 11 is refused...
    client.post("/settings/change-password", data={
        "current_password": "pw", "new_password": "elevenchars",
        "confirm_password": "elevenchars"})
    assert _pw_ok(app, uid, "pw"), "an 11-character password was accepted"
    client.post("/settings/change-password", data={
        "current_password": "pw", "new_password": "twelve-chars",
        "confirm_password": "twelve-chars"})
    assert _pw_ok(app, uid, "twelve-chars"), "control: a 12-character change still works"


def test_add_user_refuses_a_short_password(app, client):
    from app.models import User
    login(client, admin_user_id(app))
    client.post("/users/", data={"username": "shorty", "password": "abc",
                                 "confirm_password": "abc", "role": "readonly"})
    with app.app_context():
        assert User.query.filter_by(username="shorty").first() is None


def test_admin_reset_refuses_a_short_password(app, client):
    uid = make_user(app, "target")
    login(client, admin_user_id(app))
    client.post(f"/users/{uid}/reset-password", data={"new_password": "abc"})
    assert _pw_ok(app, uid, "pw")


def test_minting_refuses_a_scope_the_owner_cannot_use(app, client):
    from app.models_api_token import ApiToken
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, admin_user_id(app))
    client.post("/api-tokens/create", data={"name": "t", "owner_id": str(op),
                                            "product": "fortiweb", "scopes": ["admin"]})
    with app.app_context():
        assert ApiToken.query.count() == 0, "an operator got an admin-scope token"
    client.post("/api-tokens/create", data={"name": "t", "owner_id": str(op),
                                            "product": "fortiweb", "scopes": ["write"]})
    with app.app_context():
        assert ApiToken.query.count() == 1, "control: a scope the owner holds is minted"


def test_editing_refuses_a_scope_the_owner_cannot_use(app, client):
    from app.models import User
    from app.models_api_token import ApiToken, mint_token
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    with app.app_context():
        tok, _ = mint_token(name="t", owner=User.query.get(op), scopes=["read"],
                            product="fortiweb")
        tid = tok.id
    login(client, admin_user_id(app))
    client.post(f"/api-tokens/{tid}/edit", data={"product": "fortiweb", "scopes": ["admin"]})
    with app.app_context():
        assert "admin" not in ApiToken.query.get(tid).scope_list


def test_an_admin_scope_token_of_an_operator_does_not_widen_the_listing(app):
    """Tokens minted before AD-48 can still carry the scope: the handler must
    not honour it."""
    from app.models import User
    from app.models_api_token import mint_token
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    with app.app_context():
        tok, _ = mint_token(name="t", owner=User.query.get(op), scopes=["admin"],
                            product="fortiweb")
        assert tok.has_scope("admin")
        assert not tok.owner_may_use("admin")
        adm, _ = mint_token(name="a", owner=User.query.filter_by(username="admin").one(),
                            scopes=["admin"], product="fortiweb")
        assert adm.owner_may_use("admin")


def test_the_waf_listing_ignores_an_admin_scope_the_owner_cannot_use(app, client):
    from app.models import Appliance, User, db
    from app.models_api_token import mint_token
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    with app.app_context():
        a = Appliance(name="fw1", host="192.0.2.1", kind="fortiweb", username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        aid = a.id
        _, op_tok = mint_token(name="o", owner=User.query.get(op), scopes=["admin"],
                               product="fortiweb")
        _, adm_tok = mint_token(name="a", owner=User.query.filter_by(username="admin").one(),
                                scopes=["admin"], product="fortiweb")
    url = f"/api/v1/waf/exceptions?appliance_id={aid}&all=1"
    r = client.get(url, headers={"Authorization": f"Bearer {op_tok}"})
    assert r.status_code == 403, "an operator's admin-scope token listed every tenant"
    r = client.get(url, headers={"Authorization": f"Bearer {adm_tok}"})
    assert r.status_code == 200 and r.get_json()["scope"] == "all", "control"


def test_peer_inventory_goes_through_the_node_vhost(app, monkeypatch):
    from app.services import node_security, system_backup
    seen = {}

    def fake(host, path, timeout=2.0):
        seen["call"] = (host, path)
        return 200, b'{"bundles": [{"name": "b1"}], "vault": 3}', True

    monkeypatch.setattr(node_security, "peer_get", fake)
    out = system_backup.peer_inventory("192.0.2.2")
    assert seen["call"] == ("192.0.2.2", "/healthz/backups")
    assert out["reachable"] and out["vault"] == 3
