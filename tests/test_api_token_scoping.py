"""API-token fine-grained authorization (Phase 2).

Covers the "what" (capabilities) and the "where" (AppID scope): the pure
authorization math on the token model + the appids scope resolver, plus the
/api/v1 run-action enforcement 403 paths (which return BEFORE any device I/O).
"""
from __future__ import annotations

import json

import pytest

from app.extensions import db
from app.models import AppId, Appliance, User
from app.models_api_token import ApiToken, mint_token
from app.services import appids as svc


# --------------------------------------------------------------------------- #
#  Pure token authorization — capabilities + AppID gating (no DB commit)        #
# --------------------------------------------------------------------------- #
def _tok(caps=None, app_ids=None):
    t = ApiToken(name="t", public_id="x", token_hash="h", owner_user_id=1)
    t.set_scopes(["write"])
    t.set_capabilities(caps or [])
    t.set_app_ids(app_ids or [])
    return t


def test_capability_roundtrip_ignores_unknown():
    t = _tok(caps=["backend_edit", "bogus", "reports"])
    assert t.capability_list == ["backend_edit", "reports"]


def test_no_capabilities_allows_any_known_action():
    t = _tok()
    ok, code, _ = t.authorize_capability("backup")
    assert ok and code == ""


def test_capability_allowlist_blocks_ungranted():
    t = _tok(caps=["backend_edit"])
    assert t.authorize_capability("backend_set_status")[0] is True
    ok, code, _ = t.authorize_capability("backup")
    assert not ok and code == "capability_denied"


def test_appid_scoped_token_cannot_run_fleet_actions():
    # An AppID-scoped token may only run policy-targeted (scopable) actions.
    t = _tok(caps=["backend_edit", "maintenance"], app_ids=["APP-1"])
    assert t.is_appid_scoped
    ok, code, _ = t.authorize_capability("backup")  # maintenance = fleet
    assert not ok and code == "not_appid_scopable"
    # backend_set_status is scopable → capability check passes
    assert t.authorize_capability("backend_set_status")[0] is True


# --------------------------------------------------------------------------- #
#  Action target resolution (the "where" the action actually touches)           #
# --------------------------------------------------------------------------- #
class _FakeAction:
    def __init__(self, action, params, targets):
        self.action = action
        self._p = params
        self._t = targets

    @property
    def params_dict(self):
        return self._p

    @property
    def targets_list(self):
        return self._t


def test_action_target_scope_policy_op():
    a = _FakeAction("policy_set_status", {"policy": "pol-x"}, [3])
    assert svc.action_target_scope(a) == {(3, "pol-x")}


def test_action_target_scope_cert_swap():
    a = _FakeAction("swap_certificate", {"policy": "pol-y", "certificate": "c"}, [7])
    assert svc.action_target_scope(a) == {(7, "pol-y")}


def test_action_target_scope_no_target_is_empty():
    assert svc.action_target_scope(_FakeAction("policy_set_status", {}, [3])) == set()
    assert svc.action_target_scope(_FakeAction("policy_set_status", {"policy": "p"}, [])) == set()


def test_action_target_scope_backend_uses_pool_resolution(monkeypatch):
    monkeypatch.setattr(svc, "policies_using_pool",
                        lambda aid, pool: {"pol-a", "pol-b"} if pool == "pool-1" else set())
    a = _FakeAction("backend_set_status", {"server_pool": "pool-1", "member": "1"}, [5])
    assert svc.action_target_scope(a) == {(5, "pol-a"), (5, "pol-b")}


def test_policies_using_pool_reads_cache(session, monkeypatch):
    from app.services import read_layer
    monkeypatch.setattr(read_layer, "read_objects",
                        lambda aid, ln, **kw: ([{"name": "pol-a", "server-pool": "pool-1"},
                                                {"name": "pol-b", "server-pool": "pool-2"}], {}))
    assert svc.policies_using_pool(1, "pool-1") == {"pol-a"}
    assert svc.policies_using_pool(1, "nope") == set()


# --------------------------------------------------------------------------- #
#  Fixtures for the /api/v1 enforcement paths                                   #
# --------------------------------------------------------------------------- #
def _admin(session):
    u = User(username="apiowner", password_hash="x", role="admin")
    session.add(u)
    session.commit()
    return u


def _appliance(session, name="fw1"):
    a = Appliance(name=name, host="192.0.2.1", kind="fortiweb", username="admin")
    a.password = "pw"
    session.add(a)
    session.commit()
    return a


def _action(session, *, action, params, targets, product="fortiweb"):
    from app.models import ScheduledAction
    row = ScheduledAction(name="a", scope="user", product=product, action=action,
                          targets=json.dumps(targets), params=json.dumps(params),
                          enabled=True)
    session.add(row)
    session.commit()
    return row


def _bearer(client, plaintext):
    return {"Authorization": f"Bearer {plaintext}"}


def test_run_denied_capability(app, client, session):
    owner = _admin(session)
    a = _appliance(session)
    row = _action(session, action="backup", params={}, targets=[a.id])
    tok, pt = mint_token(name="t", owner=owner, scopes=["write"],
                         product="fortiweb", capabilities=["backend_edit"])
    r = client.post(f"/api/v1/actions/{row.id}/run", headers=_bearer(client, pt))
    assert r.status_code == 403
    assert r.get_json()["error"] == "capability_denied"


def test_run_denied_appid_out_of_scope(app, client, session):
    owner = _admin(session)
    a = _appliance(session)
    app1 = svc.create_manual(app_id="APP-1", product="fortiweb")
    svc.assign(app_id_pk=app1.id, appliance_id=a.id, server_policy="pol-mine")
    # Action targets a DIFFERENT policy than the one bound to APP-1.
    row = _action(session, action="policy_set_status",
                  params={"policy": "pol-theirs", "enabled": False}, targets=[a.id])
    tok, pt = mint_token(name="t", owner=owner, scopes=["write"], product="fortiweb",
                         capabilities=["policy_status"], app_ids=["APP-1"])
    r = client.post(f"/api/v1/actions/{row.id}/run", headers=_bearer(client, pt))
    assert r.status_code == 403
    assert r.get_json()["error"] == "appid_scope_denied"


def test_run_denied_appid_unresolved_fail_closed(app, client, session):
    owner = _admin(session)
    a = _appliance(session)
    app1 = svc.create_manual(app_id="APP-1", product="fortiweb")
    svc.assign(app_id_pk=app1.id, appliance_id=a.id, server_policy="pol-mine")
    # backend_set_status → pool resolves to NOTHING (empty cache) → fail-closed.
    row = _action(session, action="backend_set_status",
                  params={"server_pool": "pool-x", "member": "1"}, targets=[a.id])
    tok, pt = mint_token(name="t", owner=owner, scopes=["write"], product="fortiweb",
                         capabilities=["backend_edit"], app_ids=["APP-1"])
    r = client.post(f"/api/v1/actions/{row.id}/run", headers=_bearer(client, pt))
    assert r.status_code == 403
    assert r.get_json()["error"] == "appid_scope_unresolved"


def test_run_allowed_in_scope(app, client, session, monkeypatch):
    owner = _admin(session)
    a = _appliance(session)
    app1 = svc.create_manual(app_id="APP-1", product="fortiweb")
    svc.assign(app_id_pk=app1.id, appliance_id=a.id, server_policy="pol-mine")
    row = _action(session, action="policy_set_status",
                  params={"policy": "pol-mine", "enabled": False}, targets=[a.id])
    tok, pt = mint_token(name="t", owner=owner, scopes=["write"], product="fortiweb",
                         capabilities=["policy_status"], app_ids=["APP-1"])
    # Stop before device I/O — we're asserting the boundary ALLOWS, not the op.
    from app.api_v1 import routes as api_routes

    class _Run:
        id = 1
        status = "ok"
        summary = "done"
    monkeypatch.setattr(api_routes.sa, "execute_and_record", lambda row, **kw: _Run())
    r = client.post(f"/api/v1/actions/{row.id}/run", headers=_bearer(client, pt))
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["ok"] is True
