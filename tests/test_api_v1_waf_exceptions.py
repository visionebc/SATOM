"""The third-party carve-out surface: /api/v1/waf/* and /api/v1/adc/*.

An external team gets a Bearer token and authors a WAF carve-out WITHOUT ever
being handed the cmdb. Everything here guards ONE promise: the token can only
reach the allow-listed carve-out catalog, only on its own ADOM, only on its own
AppIDs, and it never writes to a device unless it was granted that separately.

The asymmetry that shapes the tests: refusing a legitimate carve-out costs the
external team a support ticket. Accepting one it was not entitled to writes a
protection bypass onto a live appliance under someone else's name.
"""
from __future__ import annotations

import ast
import json

import pytest

from tests.conftest import admin_user_id, make_user

DRAFT = "waf_exception_draft"
APPLY = "waf_exception_apply"

# A minimal carve-out that PASSES wpp_exceptions.validate_payload.
GOOD_TYPE = "allow_method_exception_item"
GOOD_PAYLOAD = {"request-type": "plain", "request-file": "/health",
                "allow-request": "GET"}


# --------------------------------------------------------------------------- #
#  Fixtures / helpers                                                          #
# --------------------------------------------------------------------------- #
def _mint(app, *, owner_id=None, scopes=("write",), product="fortiweb",
          capabilities=(), app_ids=()):
    from app.extensions import db
    from app.models import User
    from app.models_api_token import mint_token
    with app.app_context():
        owner = db.session.get(User, owner_id if owner_id is not None
                               else admin_user_id(app))
        tok, plaintext = mint_token(name="ext", owner=owner, scopes=list(scopes),
                                    product=product,
                                    capabilities=list(capabilities),
                                    app_ids=list(app_ids))
        return tok.public_id, plaintext


def _auth(plaintext):
    return {"Authorization": f"Bearer {plaintext}"}


def _appliance(app, name="fw-t", kind="fortiweb"):
    from app.extensions import db
    from app.models import Appliance
    with app.app_context():
        a = Appliance(name=name, kind=kind, host="192.0.2.13", port=443,
                      username="api-test")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        return a.id


def _body(appliance_id, **over):
    b = {"appliance": appliance_id, "wpp": "wpp-a", "type": GOOD_TYPE,
         "payload": dict(GOOD_PAYLOAD), "policies": ["pol-a"],
         "reason": "CVE-2026-1 mitigation breaks /health"}
    b.update(over)
    return b


class _FakeOps:
    """Duck-typed FortiWebOps: records the writes, never touches a device."""

    def __init__(self, appliance=None):
        self.appliance = appliance
        self.calls: list[dict] = []
        _FakeOps.last = self

    def create(self, endpoint, body, dry_run=True):
        self.calls.append({"op": "create", "endpoint": endpoint,
                           "dry_run": dry_run, "body": body})
        return {"ok": True, "request": {"path": endpoint}, "error": ""}

    def update(self, endpoint, mkey, body, dry_run=True):
        self.calls.append({"op": "update", "endpoint": endpoint,
                           "dry_run": dry_run, "body": body})
        return {"ok": True, "request": {"path": endpoint}, "error": ""}


@pytest.fixture()
def ops(monkeypatch):
    import app.api_v1.waf as waf
    _FakeOps(None)          # __init__ rebinds _FakeOps.last -> a fresh, empty one
    monkeypatch.setattr(waf, "FortiWebOps", _FakeOps)
    return _FakeOps


# --------------------------------------------------------------------------- #
#  ROUND 1 — the catalog is the allow-list                                     #
# --------------------------------------------------------------------------- #
def test_the_catalog_needs_a_token(client):
    assert client.get("/api/v1/waf/exception-types").status_code == 401


def test_only_waf_carve_outs_are_offered_never_signature_customisations(app, client):
    """A signature customisation edits a shared signature SET (128-row cap, blast
    radius across every policy that binds it). It stays operator-only in v1."""
    _pid, tokstr = _mint(app, scopes=["read"])
    r = client.get("/api/v1/waf/exception-types", headers=_auth(tokstr))
    assert r.status_code == 200
    keys = {t["key"] for t in r.get_json()["types"]}
    from app.services import wpp_exceptions as store
    offered_cats = {store.category_for(k) for k in keys}
    assert offered_cats == {store.CAT_EXCEPTION}, \
        "a signature customisation leaked into the third-party catalog"
    assert keys, "the catalog must not be empty"
    # and it is the WHOLE exception half, not an accidental subset
    assert keys == {t["key"] for t in store.catalog(store.CAT_EXCEPTION)}


def test_each_type_carries_the_fields_and_the_required_keys(app, client):
    _pid, tokstr = _mint(app, scopes=["read"])
    types = client.get("/api/v1/waf/exception-types",
                       headers=_auth(tokstr)).get_json()["types"]
    row = next(t for t in types if t["key"] == GOOD_TYPE)
    assert row["required"] and "allow-request" in row["required"]
    assert row["fields"] and all("key" in f for f in row["fields"])


# --------------------------------------------------------------------------- #
#  ROUND 1 — the capability is opt-in (the asymmetry that matters)             #
# --------------------------------------------------------------------------- #
def test_an_unrestricted_token_does_NOT_inherit_the_carve_out_surface(app, client):
    """``capabilities == []`` means "unrestricted" for the ACTION catalog — a
    backwards-compat affordance for tokens minted before capabilities existed.
    Extending it here would silently hand every one of those tokens the power to
    author WAF bypasses. This surface is EXPLICIT-GRANT ONLY."""
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[])
    r = client.post("/api/v1/waf/exceptions", json=_body(aid),
                    headers=_auth(tokstr))
    assert r.status_code == 403
    assert r.get_json()["error"] == "capability_denied"
    from app.models import WppException
    with app.app_context():
        assert WppException.query.count() == 0


def test_a_draft_capability_authors_the_row_and_returns_the_plan(app, client, ops):
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT])
    r = client.post("/api/v1/waf/exceptions", json=_body(aid),
                    headers=_auth(tokstr))
    assert r.status_code == 201, r.get_json()
    body = r.get_json()
    assert body["created"] is True
    assert body["exception"]["type"] == GOOD_TYPE
    assert body["exception"]["policies"] == ["pol-a"]
    assert body["plan"]["status"] in ("ready", "no-target")
    from app.models import WppException
    with app.app_context():
        assert WppException.query.count() == 1


def test_authoring_is_a_preview_and_never_touches_the_device(app, client, ops):
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT])
    r = client.post("/api/v1/waf/exceptions",
                    json=_body(aid, target="am-exc"), headers=_auth(tokstr))
    body = r.get_json()
    assert body["device_written"] is False
    assert body["dry_run"] is True
    assert all(c["dry_run"] is True for c in getattr(_FakeOps, "last", _FakeOps(None)).calls)


def test_an_unknown_type_is_refused(app, client):
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT])
    r = client.post("/api/v1/waf/exceptions",
                    json=_body(aid, type="system_admin"), headers=_auth(tokstr))
    assert r.status_code == 400
    assert r.get_json()["error"] == "unknown_type"


def test_a_signature_type_is_refused_even_though_it_exists_in_the_catalog(app, client):
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT])
    r = client.post("/api/v1/waf/exceptions",
                    json=_body(aid, type="signature_disable_item",
                               payload={"signature_id": "010000001"}),
                    headers=_auth(tokstr))
    assert r.status_code == 400
    assert r.get_json()["error"] == "unknown_type"


def test_a_payload_missing_its_match_key_is_refused_with_the_reasons(app, client):
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT])
    r = client.post("/api/v1/waf/exceptions",
                    json=_body(aid, payload={"request-type": "plain"}),
                    headers=_auth(tokstr))
    assert r.status_code == 400
    body = r.get_json()
    assert body["error"] == "invalid_payload"
    assert any("allow-request" in e for e in body["errors"])


def test_a_template_managed_profile_is_refused(app, client, monkeypatch):
    aid = _appliance(app)
    monkeypatch.setattr("app.services.templates.managed_wpp_names",
                        lambda: {"wpp-a"})
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT])
    r = client.post("/api/v1/waf/exceptions", json=_body(aid),
                    headers=_auth(tokstr))
    assert r.status_code == 409
    assert r.get_json()["error"] == "template_locked"


def test_a_token_bound_to_another_adom_cannot_author_here(app, client):
    aid = _appliance(app, kind="fortiweb")
    _pid, tokstr = _mint(app, scopes=["write"], product="fortiadc",
                         capabilities=[DRAFT])
    r = client.post("/api/v1/waf/exceptions", json=_body(aid),
                    headers=_auth(tokstr))
    assert r.status_code == 403
    assert r.get_json()["error"] == "wrong_product"


# --------------------------------------------------------------------------- #
#  ROUND 1 — AppID scope fails CLOSED                                          #
# --------------------------------------------------------------------------- #
def _bind_appid(app, appliance_id, app_id="APP-1", policy="pol-a"):
    from app.extensions import db
    from app.models import AppId, AppIdPolicy
    with app.app_context():
        a = AppId(app_id=app_id, product="fortiweb")
        db.session.add(a)
        db.session.commit()
        db.session.add(AppIdPolicy(app_id_id=a.id, appliance_id=appliance_id,
                                   server_policy=policy))
        db.session.commit()


def test_an_appid_scoped_token_cannot_author_on_someone_elses_policy(app, client):
    aid = _appliance(app)
    _bind_appid(app, aid, "APP-1", "pol-a")
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT],
                         app_ids=["APP-1"])
    r = client.post("/api/v1/waf/exceptions",
                    json=_body(aid, policies=["pol-a", "pol-OTHER"]),
                    headers=_auth(tokstr))
    assert r.status_code == 403
    assert r.get_json()["error"] == "appid_scope_denied"


def test_an_appid_scoped_token_naming_no_policy_is_denied_not_allowed(app, client):
    """No policy named = the carve-out's location is unprovable. An unprovable
    location is a DENY, never a fleet-wide allow."""
    aid = _appliance(app)
    _bind_appid(app, aid, "APP-1", "pol-a")
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT],
                         app_ids=["APP-1"])
    r = client.post("/api/v1/waf/exceptions", json=_body(aid, policies=[]),
                    headers=_auth(tokstr))
    assert r.status_code == 403
    assert r.get_json()["error"] == "appid_scope_unresolved"


def test_an_appid_scoped_token_authors_inside_its_scope(app, client, ops):
    aid = _appliance(app)
    _bind_appid(app, aid, "APP-1", "pol-a")
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT],
                         app_ids=["APP-1"])
    r = client.post("/api/v1/waf/exceptions", json=_body(aid),
                    headers=_auth(tokstr))
    assert r.status_code == 201, r.get_json()


def test_listing_hides_rows_outside_the_appid_scope(app, client, ops):
    aid = _appliance(app)
    _bind_appid(app, aid, "APP-1", "pol-a")
    from app.services import wpp_exceptions as store
    with app.app_context():
        store.add(aid, wpp_mkey="wpp-a", exc_type=GOOD_TYPE,
                  payload=GOOD_PAYLOAD, author="operator",
                  policies=["pol-SECRET"])
        store.add(aid, wpp_mkey="wpp-a", exc_type=GOOD_TYPE,
                  payload=GOOD_PAYLOAD, author="operator", policies=["pol-a"])
    _pid, tokstr = _mint(app, scopes=["read"], capabilities=[DRAFT],
                         app_ids=["APP-1"])
    rows = client.get("/api/v1/waf/exceptions",
                      headers=_auth(tokstr)).get_json()["exceptions"]
    assert [r["policies"] for r in rows] == [["pol-a"]]


# --------------------------------------------------------------------------- #
#  ROUND 2 — apply is a second grant                                           #
# --------------------------------------------------------------------------- #
def test_apply_needs_its_own_capability_and_nothing_is_created(app, client, ops):
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT])
    r = client.post("/api/v1/waf/exceptions",
                    json=_body(aid, apply=True, target="am-exc"),
                    headers=_auth(tokstr))
    assert r.status_code == 403
    assert r.get_json()["error"] == "capability_denied"
    from app.models import WppException
    with app.app_context():
        assert WppException.query.count() == 0, \
            "the row was authored before the apply grant was checked"


def test_apply_writes_to_the_device_and_reports_the_steps(app, client, ops):
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT, APPLY])
    r = client.post("/api/v1/waf/exceptions",
                    json=_body(aid, apply=True, target="am-exc"),
                    headers=_auth(tokstr))
    assert r.status_code == 201, r.get_json()
    body = r.get_json()
    assert body["device_written"] is True
    assert body["dry_run"] is False
    assert body["steps"] and body["steps"][-1]["ok"] is True
    assert any(c["dry_run"] is False for c in _FakeOps.last.calls)


def test_apply_without_a_target_is_refused_before_touching_the_device(app, client, ops):
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT, APPLY])
    r = client.post("/api/v1/waf/exceptions",
                    json=_body(aid, apply=True), headers=_auth(tokstr))
    assert r.status_code == 400
    assert r.get_json()["error"] == "target_required"
    assert not getattr(_FakeOps, "last", _FakeOps(None)).calls


# --------------------------------------------------------------------------- #
#  ROUND 2 — idempotency: a SOAR retries                                        #
# --------------------------------------------------------------------------- #
def test_the_same_request_twice_does_not_create_a_second_row(app, client, ops):
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT])
    first = client.post("/api/v1/waf/exceptions", json=_body(aid),
                        headers=_auth(tokstr)).get_json()
    again = client.post("/api/v1/waf/exceptions", json=_body(aid),
                        headers=_auth(tokstr))
    assert again.status_code == 200
    body = again.get_json()
    assert body["created"] is False
    assert body["exception"]["id"] == first["exception"]["id"]
    from app.models import WppException
    with app.app_context():
        assert WppException.query.count() == 1


def test_a_different_payload_is_a_different_carve_out(app, client, ops):
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT])
    client.post("/api/v1/waf/exceptions", json=_body(aid), headers=_auth(tokstr))
    other = dict(GOOD_PAYLOAD, **{"request-file": "/metrics"})
    r = client.post("/api/v1/waf/exceptions", json=_body(aid, payload=other),
                    headers=_auth(tokstr))
    assert r.status_code == 201
    from app.models import WppException
    with app.app_context():
        assert WppException.query.count() == 2


def test_the_fingerprint_ignores_key_order_and_scalar_spelling(app, client, ops):
    """A SOAR that serialises 1 and "1" differently across retries must not
    double-author. Dedupe compares VALUES, not their JSON spelling."""
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT])
    client.post("/api/v1/waf/exceptions", json=_body(aid), headers=_auth(tokstr))
    shuffled = {k: GOOD_PAYLOAD[k] for k in reversed(list(GOOD_PAYLOAD))}
    r = client.post("/api/v1/waf/exceptions", json=_body(aid, payload=shuffled),
                    headers=_auth(tokstr))
    assert r.get_json()["created"] is False


def test_another_token_does_not_silently_adopt_this_tokens_row(app, client, ops):
    """Dedupe is per-author. Returning token B a row authored by token A would
    hand B an id it cannot delete — a 200 that promises ownership it lacks."""
    aid = _appliance(app)
    _a, tok_a = _mint(app, scopes=["write"], capabilities=[DRAFT])
    _b, tok_b = _mint(app, scopes=["write"], capabilities=[DRAFT])
    first = client.post("/api/v1/waf/exceptions", json=_body(aid),
                        headers=_auth(tok_a)).get_json()
    second = client.post("/api/v1/waf/exceptions", json=_body(aid),
                         headers=_auth(tok_b))
    assert second.status_code == 201
    assert second.get_json()["exception"]["id"] != first["exception"]["id"]


# --------------------------------------------------------------------------- #
#  ROUND 2 — ownership + honesty on delete                                     #
# --------------------------------------------------------------------------- #
def test_a_token_cannot_delete_what_an_operator_authored(app, client):
    aid = _appliance(app)
    from app.services import wpp_exceptions as store
    with app.app_context():
        exc = store.add(aid, wpp_mkey="wpp-a", exc_type=GOOD_TYPE,
                        payload=GOOD_PAYLOAD, author="admin", policies=["pol-a"])
        exc_id = exc.id
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT])
    r = client.delete(f"/api/v1/waf/exceptions/{exc_id}", headers=_auth(tokstr))
    assert r.status_code == 403
    assert r.get_json()["error"] == "not_token_owned"
    from app.models import WppException
    with app.app_context():
        assert WppException.query.get(exc_id) is not None


def test_a_token_deletes_its_own_row_and_is_told_the_device_still_has_it(app, client, ops):
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT])
    created = client.post("/api/v1/waf/exceptions", json=_body(aid),
                          headers=_auth(tokstr)).get_json()
    r = client.delete(f"/api/v1/waf/exceptions/{created['exception']['id']}",
                      headers=_auth(tokstr))
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert body["device_unchanged"] is True
    assert "device" in body["message"].lower()


# --------------------------------------------------------------------------- #
#  ROUND 2 — the drift attributor must be able to read these writes            #
# --------------------------------------------------------------------------- #
def test_an_applied_carve_out_leaves_an_audit_receipt(app, client, ops):
    """Without this row the config change shows up on the Alerts page as drift
    "with no receipt" — the console would tell the operator a device-side change
    happened when SATOM itself made it."""
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT, APPLY])
    client.post("/api/v1/waf/exceptions",
                json=_body(aid, apply=True, target="am-exc"),
                headers=_auth(tokstr))
    from app.models import AuditLog
    with app.app_context():
        rows = AuditLog.query.filter_by(action="api.waf_exception.apply").all()
        assert len(rows) == 1
        extra = ast.literal_eval(rows[0].extra)   # audit stores repr(), not JSON
        assert extra["via"] == "api"
        assert extra["owner"] == "admin"
        assert extra["token"]
        assert str(aid) in rows[0].target


def test_a_preview_is_not_recorded_as_a_write(app, client, ops):
    """A dry-run changed nothing. Filing it as a write would let the attributor
    credit SATOM for a device-side change it never made."""
    aid = _appliance(app)
    _pid, tokstr = _mint(app, scopes=["write"], capabilities=[DRAFT])
    client.post("/api/v1/waf/exceptions", json=_body(aid, target="am-exc"),
                headers=_auth(tokstr))
    from app.models import AuditLog
    with app.app_context():
        assert AuditLog.query.filter_by(action="api.waf_exception.apply").count() == 0
        assert AuditLog.query.filter_by(action="api.waf_exception.create").count() == 1


# --------------------------------------------------------------------------- #
#  ROUND 3 — FortiADC: different catalog, same guardian                        #
# --------------------------------------------------------------------------- #
def test_the_adc_catalog_is_not_the_fortiweb_one(app, client):
    _pid, tokstr = _mint(app, scopes=["read"], product="fortiadc")
    r = client.get("/api/v1/adc/exception-types", headers=_auth(tokstr))
    assert r.status_code == 200
    keys = {t["key"] for t in r.get_json()["types"]}
    assert keys
    from app.services import wpp_exceptions as store
    assert not (keys & {t["key"] for t in store.CATALOG}), \
        "the ADC surface is reusing FortiWeb carve-out types"


def test_the_adc_endpoint_refuses_a_fortiweb_appliance(app, client):
    """A 'global' token CAN see both families, so the kind gate is the only
    thing standing between /adc and a FortiWeb. (An ADOM-scoped token never
    gets this far — see the 404 test below.)"""
    aid = _appliance(app, name="fw-x", kind="fortiweb")
    _pid, tokstr = _mint(app, scopes=["write"], product="global",
                         capabilities=["adc_exception_draft"])
    r = client.post("/api/v1/adc/exceptions",
                    json={"appliance": aid, "profile": "prof-a",
                          "type": "adc_waf_exception", "payload": {"mkey": "e1"}},
                    headers=_auth(tokstr))
    assert r.status_code == 400
    assert r.get_json()["error"] == "wrong_kind"


def test_the_fortiweb_endpoint_refuses_an_adc_appliance(app, client):
    aid = _appliance(app, name="adc-x", kind="fortiadc")
    _pid, tokstr = _mint(app, scopes=["write"], product="global",
                         capabilities=[DRAFT])
    r = client.post("/api/v1/waf/exceptions", json=_body(aid),
                    headers=_auth(tokstr))
    assert r.status_code == 400
    assert r.get_json()["error"] == "wrong_kind"


def test_an_adom_scoped_token_is_not_even_told_the_other_family_exists(app, client):
    """Stronger than ``wrong_kind``: the token's ADOM already hides the row, so
    the refusal is a 404 that confirms nothing. ``wrong_kind`` would tell an
    external caller that an appliance by that id exists."""
    aid = _appliance(app, name="adc-hidden", kind="fortiadc")
    _pid, tokstr = _mint(app, scopes=["write"], product="fortiweb",
                         capabilities=[DRAFT])
    r = client.post("/api/v1/waf/exceptions", json=_body(aid),
                    headers=_auth(tokstr))
    assert r.status_code == 404
    assert r.get_json()["error"] == "not_found"


def test_the_adc_plan_resolves_a_real_registry_endpoint(app, client):
    aid = _appliance(app, name="adc-y", kind="fortiadc")
    _pid, tokstr = _mint(app, scopes=["write"], product="fortiadc",
                         capabilities=["adc_exception_draft"])
    r = client.post("/api/v1/adc/exceptions",
                    json={"appliance": aid, "profile": "prof-a",
                          "type": "adc_waf_exception",
                          "payload": {"mkey": "cve-2026-1"}},
                    headers=_auth(tokstr))
    assert r.status_code == 201, r.get_json()
    plan = r.get_json()["plan"]
    assert plan["status"] == "ready"
    assert plan["logical"] == "security_waf_exception"
    assert plan["method"] == "POST"
    assert r.get_json()["device_written"] is False


def test_the_adc_payload_needs_its_identity_field(app, client):
    aid = _appliance(app, name="adc-z", kind="fortiadc")
    _pid, tokstr = _mint(app, scopes=["write"], product="fortiadc",
                         capabilities=["adc_exception_draft"])
    r = client.post("/api/v1/adc/exceptions",
                    json={"appliance": aid, "profile": "prof-a",
                          "type": "adc_waf_exception", "payload": {}},
                    headers=_auth(tokstr))
    assert r.status_code == 400
    assert r.get_json()["error"] == "invalid_payload"


def test_the_adc_apply_needs_its_own_capability(app, client):
    aid = _appliance(app, name="adc-w", kind="fortiadc")
    _pid, tokstr = _mint(app, scopes=["write"], product="fortiadc",
                         capabilities=["adc_exception_draft"])
    r = client.post("/api/v1/adc/exceptions",
                    json={"appliance": aid, "profile": "prof-a",
                          "type": "adc_waf_exception",
                          "payload": {"mkey": "e1"}, "apply": True},
                    headers=_auth(tokstr))
    assert r.status_code == 403
    assert r.get_json()["error"] == "capability_denied"


# --------------------------------------------------------------------------- #
#  Structural: the surface can never become a cmdb passthrough                 #
# --------------------------------------------------------------------------- #
def test_no_caller_supplied_collection_ever_reaches_a_rest_path(app):
    """The whole design rests on the endpoint being derived from the CATALOG.
    The moment a request field can name a collection, this is a cmdb proxy and
    ``system/admin`` is one POST away."""
    import inspect
    import app.api_v1.waf as waf
    src = inspect.getsource(waf)
    # strip comments/docstrings: an assertion that matches its own rationale
    # guards nothing (this repo has collected ten of those).
    code = "\n".join(l for l in src.splitlines()
                     if not l.lstrip().startswith("#"))
    for forbidden in ("rest_path(", "scoped_path(", "collection_of("):
        assert forbidden not in code, (
            f"{forbidden} builds a device path — it must stay inside the "
            "catalog-driven planner, never in a request handler")
    assert "objedit" not in code


def test_the_two_new_capabilities_are_declared(app):
    from app.models_api_token import CAPABILITIES
    for cap in (DRAFT, APPLY, "adc_exception_draft", "adc_exception_apply"):
        assert cap in CAPABILITIES
