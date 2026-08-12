"""Guards for the /api/v1 OBJECT-write surface (WAF carve-outs + ADC rules).

The class of failure this file exists to catch is not "the endpoint 500s". It is
an endpoint that answers 200 while granting more than anyone approved:

* a token minted BEFORE this surface existed silently gaining WAF config-write
  (the empty-capability-list default);
* a caller choosing its own privilege by setting ``apply: true``;
* a carve-out authored on a SHARED Web Protection Profile, which lands on every
  other tenant that binds it;
* a retry leaving a second identical desired-state row;
* one team deleting another team's carve-out.

Every test below pins one of those. Device I/O is never reached: each 4xx path
returns before an appliance is touched, and the apply paths are exercised
through a stubbed ops object.
"""
from __future__ import annotations

import json

import pytest

# Module-level so SQLAlchemy has every mapped class registered before a bare
# ``ApiToken(...)`` is constructed in the pure-model tests: ApiToken.owner is a
# string-named relationship to "User", and resolving it needs app.models
# imported. Lazy in-function imports left it unresolvable.
from app.models import AppId, AppIdPolicy, Appliance, User  # noqa: F401
from tests.conftest import admin_user_id, make_user

CT = {"Content-Type": "application/json"}


# --------------------------------------------------------------------------- #
#  Fixtures                                                                     #
# --------------------------------------------------------------------------- #
def _appliance(app, name="fw1", kind="fortiweb"):
    from app.extensions import db
    from app.models import Appliance
    with app.app_context():
        a = Appliance(name=name, host="192.0.2.1", kind=kind, username="admin")
        a.password = "pw"          # password_enc is NOT NULL (Fernet setter)
        db.session.add(a)
        db.session.commit()
        return a.id


def _mint(app, *, owner_id=None, scopes=("write",), product="fortiweb",
          capabilities=(), app_ids=()):
    from app.extensions import db
    from app.models import User
    from app.models_api_token import mint_token
    with app.app_context():
        owner = db.session.get(User, owner_id or admin_user_id(app))
        tok, plaintext = mint_token(
            name="t", owner=owner, scopes=list(scopes), product=product,
            capabilities=list(capabilities), app_ids=list(app_ids))
        return plaintext


def _auth(t):
    return {"Authorization": f"Bearer {t}", **CT}


def _seed_policies(app, appliance_id, bindings):
    """Cache ``{policy: wpp}`` as depth-0 server_policy objects (DB-first read)."""
    from app.extensions import db
    from app.models_cache import DeviceObject
    with app.app_context():
        for i, (pol, wpp) in enumerate(bindings.items()):
            db.session.add(DeviceObject(
                appliance_id=appliance_id, layer="config", section="config",
                logical_name="server_policy", mkey=pol, depth=0, idx=i,
                payload={"name": pol, "web-protection-profile": wpp}))
        db.session.commit()


def _bind_appid(app, appliance_id, *, app_id, policies):
    from app.extensions import db
    from app.models import AppId, AppIdPolicy
    with app.app_context():
        row = AppId(app_id=app_id, product="global", active=True)
        db.session.add(row)
        db.session.commit()
        for p in policies:
            db.session.add(AppIdPolicy(app_id_id=row.id,
                                       appliance_id=appliance_id,
                                       server_policy=p))
        db.session.commit()


#: A minimally valid allow-method carve-out (all three REQUIRED_FIELDS present).
GOOD = {
    "exc_type": "allow_method_exception_item",
    "wpp_mkey": "wpp-app1",
    "payload": {"request-type": "plain", "request-file": "/api/v2/upload",
                "allow-request": "put patch"},
}


def _body(appliance_id, **over):
    b = {"appliance_id": appliance_id, **GOOD}
    b.update(over)
    return b


# --------------------------------------------------------------------------- #
#  1. The empty-capability default must NOT reach the object writers            #
# --------------------------------------------------------------------------- #
def test_a_token_with_no_capabilities_cannot_author_a_carve_out(app, client):
    """The regression this whole design turns on.

    For catalog actions an empty capability list means "unrestricted". If the
    object writers reused that default, every token already in a third party's
    hands would have gained FortiWeb config-write the moment this shipped.
    """
    aid = _appliance(app)
    t = _mint(app, capabilities=[])          # the pre-existing shape
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid)))
    assert r.status_code == 403
    assert r.get_json()["error"] == "capability_denied"


def test_the_object_capabilities_are_declared_explicit_only():
    from app.models_api_token import (CAPABILITIES, CAPABILITY_PRODUCTS,
                                      EXPLICIT_ONLY_CAPABILITIES)
    assert EXPLICIT_ONLY_CAPABILITIES, "the explicit-only set must not be empty"
    for cap in EXPLICIT_ONLY_CAPABILITIES:
        assert cap in CAPABILITIES, f"{cap} is not mintable"
        assert cap in CAPABILITY_PRODUCTS, f"{cap} has no product binding"


def test_an_object_capability_can_never_be_reached_through_the_action_path():
    """``authorize_capability`` is the ACTION gate and treats [] as unrestricted.

    If an object capability ever appeared as an action's tag, holding it would
    let a token run that action — and, worse, an unrestricted token would reach
    the object writer through the action path the object gate refuses.
    """
    from app.models_api_token import (ACTION_CAPABILITY,
                                      EXPLICIT_ONLY_CAPABILITIES)
    assert not (set(ACTION_CAPABILITY.values()) & EXPLICIT_ONLY_CAPABILITIES)


def test_authorize_object_refuses_an_unknown_capability():
    from app.models_api_token import ApiToken
    t = ApiToken(name="t", public_id="x", token_hash="h", owner_user_id=1)
    t.set_capabilities(["waf_exception_draft"])
    ok, code, _ = t.authorize_object("maintenance")   # a real ACTION capability
    assert not ok and code == "unknown_capability"


def test_a_capability_is_refused_on_the_wrong_adom():
    from app.models_api_token import ApiToken
    t = ApiToken(name="t", public_id="x", token_hash="h", owner_user_id=1,
                 product="fortiadc")
    t.set_capabilities(["waf_exception_draft"])
    ok, code, _ = t.authorize_object("waf_exception_draft")
    assert not ok and code == "wrong_product"
    # A global token reaches both products — but the ADOM gate is the SECOND
    # check, not a substitute for the grant: 'adc_rule_draft' stays denied until
    # it is actually on the token.
    t.product = "global"
    assert t.authorize_object("waf_exception_draft")[0] is True
    assert t.authorize_object("adc_rule_draft")[1] == "capability_denied"
    t.set_capabilities(["waf_exception_draft", "adc_rule_draft"])
    assert t.authorize_object("adc_rule_draft")[0] is True


# --------------------------------------------------------------------------- #
#  2. The caller never picks its own privilege                                  #
# --------------------------------------------------------------------------- #
def test_draft_capability_records_desired_state_and_touches_no_device(app, client):
    aid = _appliance(app)
    t = _mint(app, capabilities=["waf_exception_draft"])
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid, reason="CVE-2026-1 mitigation")))
    assert r.status_code == 201, r.get_json()
    j = r.get_json()
    assert j["created"] is True and j["applied"] is False
    assert j["plan"]["status"] == "no-target"      # nothing was planned to send
    from app.models import WppException
    with app.app_context():
        rows = WppException.query.all()
        assert len(rows) == 1
        assert rows[0].author.startswith("api:")
        assert rows[0].reason == "CVE-2026-1 mitigation"


def test_apply_true_is_refused_for_a_draft_only_token_and_writes_nothing(app, client):
    """A draft-only token asking to apply is told so — never silently downgraded.

    A silent downgrade returns 201 to an automation that then believes the hole
    is closed on the appliance. It is not.
    """
    aid = _appliance(app)
    t = _mint(app, capabilities=["waf_exception_draft"])
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid, apply=True, target="am-exc")))
    assert r.status_code == 403
    assert r.get_json()["error"] == "capability_denied"
    from app.models import WppException
    with app.app_context():
        assert WppException.query.count() == 0


def test_apply_needs_a_device_target_but_keeps_the_record(app, client):
    aid = _appliance(app)
    t = _mint(app, capabilities=["waf_exception_draft", "waf_exception_apply"])
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid, apply=True)))
    assert r.status_code == 400
    assert r.get_json()["error"] == "target_required"
    from app.models import WppException
    with app.app_context():
        assert WppException.query.count() == 1      # desired state survived


def test_apply_pushes_through_the_injector(app, client, monkeypatch):
    aid = _appliance(app)
    t = _mint(app, capabilities=["waf_exception_draft", "waf_exception_apply"])
    seen = {}

    def _fake_apply(ops, **kw):
        seen.update(kw)
        return {"ok": True, "already_present": False, "dry_run": False,
                "steps": [{"step": "entry", "ok": True, "duplicate": False,
                           "note": "", "request": None, "error": ""}],
                "plan": {"status": "ready", "method": "POST",
                         "endpoint": "/api/v2.0/cmdb/waf/x", "error": ""}}

    monkeypatch.setattr("app.api_v1.waf.exception_inject.apply_injection",
                        _fake_apply)
    monkeypatch.setattr("app.services.fortiweb_ops.FortiWebOps",
                        lambda appliance: object())
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid, apply=True, target="am-exc")))
    assert r.status_code == 200, r.get_json()
    j = r.get_json()
    assert j["applied"] is True and j["ok"] is True
    assert seen["dry_run"] is False and seen["target"] == "am-exc"


# --------------------------------------------------------------------------- #
#  3. The allow-list is the type catalog, not the cmdb                          #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("exc_type", [
    "signature_disable_item",           # in CATALOG, but signature category
    "signature_class_action",
    "system_admin",                     # not in CATALOG at all
    "",
])
def test_only_waf_exception_types_are_authorable(app, client, exc_type):
    aid = _appliance(app)
    t = _mint(app, capabilities=["waf_exception_draft"])
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid, exc_type=exc_type)))
    assert r.status_code == 400
    assert r.get_json()["error"] == "type_not_allowed"


def test_the_published_catalog_is_exactly_the_authorable_set(app, client):
    """The advertised allow-list and the enforced one must be the same list.

    Two authors of one fact is how a caller ends up building a valid-looking
    request the server then refuses (or worse, the reverse).
    """
    t = _mint(app, scopes=["read"], capabilities=["waf_exception_draft"])
    r = client.get("/api/v1/waf/exception-types", headers=_auth(t))
    assert r.status_code == 200
    published = {x["key"] for x in r.get_json()["types"]}
    from app.services import wpp_exceptions as store
    enforced = {x["key"] for x in store.catalog(store.CAT_EXCEPTION)}
    assert published == enforced
    assert not (published & {x["key"] for x in store.catalog(store.CAT_SIGNATURE)})


def test_an_invalid_payload_is_refused_with_its_reasons(app, client):
    aid = _appliance(app)
    t = _mint(app, capabilities=["waf_exception_draft"])
    # allow-request missing: FortiWeb stores the row and allows NOTHING.
    bad = dict(GOOD["payload"])
    bad.pop("allow-request")
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid, payload=bad)))
    assert r.status_code == 400
    j = r.get_json()
    assert j["error"] == "invalid_payload"
    assert any("allow-request" in e for e in j["errors"])


def test_a_carve_out_must_name_the_profile_it_belongs_to(app, client):
    """An empty ``wpp_mkey`` is not a smaller record, it is an unreconcilable one.

    Two things break at once. ``alignment()`` matches an authored carve-out to a
    live ``policy → profile`` binding, so a record with no profile can never
    match and sits in the stale bucket for ever. And ``template_lock_error("")``
    returns "" — the template lock is simply skipped — so an empty profile is
    also the way around the rule that template-managed profiles stay clean.
    """
    aid = _appliance(app)
    t = _mint(app, capabilities=["waf_exception_draft"])
    for missing in ("", "   ", None):
        r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                        data=json.dumps(_body(aid, wpp_mkey=missing)))
        assert r.status_code == 400, (missing, r.get_json())
        assert "wpp_mkey" in r.get_json()["message"]
    from app.models import WppException
    with app.app_context():
        assert WppException.query.count() == 0


def test_a_template_managed_profile_is_refused(app, client, monkeypatch):
    aid = _appliance(app)
    t = _mint(app, capabilities=["waf_exception_draft"])
    monkeypatch.setattr("app.services.templates.managed_wpp_names",
                        lambda: {"wpp-app1"})
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid)))
    assert r.status_code == 409
    assert r.get_json()["error"] == "template_locked"


# --------------------------------------------------------------------------- #
#  4. Idempotency by content                                                    #
# --------------------------------------------------------------------------- #
def test_a_retried_post_does_not_create_a_second_row(app, client):
    aid = _appliance(app)
    t = _mint(app, capabilities=["waf_exception_draft"])
    first = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                        data=json.dumps(_body(aid)))
    second = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                         data=json.dumps(_body(aid)))
    assert first.status_code == 201 and first.get_json()["created"] is True
    assert second.status_code == 200
    assert second.get_json()["idempotent"] is True
    assert second.get_json()["exception"]["id"] == first.get_json()["exception"]["id"]
    from app.models import WppException
    with app.app_context():
        assert WppException.query.count() == 1


def test_whitespace_only_differences_are_the_same_carve_out(app, client):
    """Normalisation happens on the way IN and on COMPARISON, or dedupe leaks."""
    aid = _appliance(app)
    t = _mint(app, capabilities=["waf_exception_draft"])
    client.post("/api/v1/waf/exceptions", headers=_auth(t),
                data=json.dumps(_body(aid)))
    padded = {k: f"  {v} " for k, v in GOOD["payload"].items()}
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid, payload=padded)))
    assert r.get_json()["idempotent"] is True
    from app.models import WppException
    with app.app_context():
        assert WppException.query.count() == 1


def test_a_different_payload_is_a_different_carve_out(app, client):
    aid = _appliance(app)
    t = _mint(app, capabilities=["waf_exception_draft"])
    client.post("/api/v1/waf/exceptions", headers=_auth(t),
                data=json.dumps(_body(aid)))
    other = dict(GOOD["payload"], **{"request-file": "/api/v2/download"})
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid, payload=other)))
    assert r.status_code == 201 and r.get_json()["created"] is True
    from app.models import WppException
    with app.app_context():
        assert WppException.query.count() == 2


def test_two_tokens_authoring_the_same_content_each_keep_their_own_row(app, client):
    """Dedupe is per-author on purpose: collapsing across teams would hand team
    B a row it cannot delete and silently drop its reason."""
    aid = _appliance(app)
    a = _mint(app, capabilities=["waf_exception_draft"])
    b = _mint(app, capabilities=["waf_exception_draft"])
    client.post("/api/v1/waf/exceptions", headers=_auth(a),
                data=json.dumps(_body(aid, reason="team A")))
    r = client.post("/api/v1/waf/exceptions", headers=_auth(b),
                    data=json.dumps(_body(aid, reason="team B")))
    assert r.get_json()["created"] is True
    from app.models import WppException
    with app.app_context():
        assert WppException.query.count() == 2


# --------------------------------------------------------------------------- #
#  5. Ownership                                                                 #
# --------------------------------------------------------------------------- #
def test_a_token_cannot_read_or_delete_another_tokens_carve_out(app, client):
    aid = _appliance(app)
    a = _mint(app, capabilities=["waf_exception_draft"])
    b = _mint(app, capabilities=["waf_exception_draft"])
    made = client.post("/api/v1/waf/exceptions", headers=_auth(a),
                       data=json.dumps(_body(aid))).get_json()
    exc_id = made["exception"]["id"]

    assert client.get(f"/api/v1/waf/exceptions/{exc_id}",
                      headers=_auth(b)).status_code == 404
    assert client.delete(f"/api/v1/waf/exceptions/{exc_id}",
                         headers=_auth(b)).status_code == 404
    from app.models import WppException
    with app.app_context():
        assert WppException.query.count() == 1      # still there


def test_an_operator_authored_carve_out_is_invisible_to_the_api(app, client):
    """The dangerous direction: an external token retracting the operator's."""
    aid = _appliance(app)
    from app.services import wpp_exceptions as store
    with app.app_context():
        exc = store.add(aid, wpp_mkey="wpp-app1",
                        exc_type="allow_method_exception_item",
                        payload=GOOD["payload"], author="admin",
                        policies=["pol-a"])
        exc_id = exc.id
    t = _mint(app, capabilities=["waf_exception_draft"])
    assert client.delete(f"/api/v1/waf/exceptions/{exc_id}",
                         headers=_auth(t)).status_code == 404
    listing = client.get(f"/api/v1/waf/exceptions?appliance_id={aid}",
                         headers=_auth(t)).get_json()
    assert listing["exceptions"] == [] and listing["scope"] == "own"


def test_listing_everything_needs_the_admin_scope(app, client):
    aid = _appliance(app)
    t = _mint(app, scopes=["write"], capabilities=["waf_exception_draft"])
    r = client.get(f"/api/v1/waf/exceptions?appliance_id={aid}&all=1",
                   headers=_auth(t))
    assert r.status_code == 403
    assert r.get_json()["error"] == "insufficient_scope"


def test_delete_says_the_appliance_still_holds_it(app, client):
    aid = _appliance(app)
    t = _mint(app, capabilities=["waf_exception_draft"])
    exc_id = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                         data=json.dumps(_body(aid))).get_json()["exception"]["id"]
    r = client.delete(f"/api/v1/waf/exceptions/{exc_id}", headers=_auth(t))
    assert r.status_code == 200
    note = r.get_json()["note"].lower()
    assert "still" in note and "appliance" in note
    from app.models import WppException
    with app.app_context():
        assert WppException.query.count() == 0


# --------------------------------------------------------------------------- #
#  6. AppID scope + the shared-profile blast radius                             #
# --------------------------------------------------------------------------- #
def test_a_scoped_token_must_name_its_policies(app, client):
    aid = _appliance(app)
    _bind_appid(app, aid, app_id="APP-1", policies=["pol-a"])
    t = _mint(app, capabilities=["waf_exception_draft"], app_ids=["APP-1"])
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid)))          # no "policies"
    assert r.status_code == 403
    assert r.get_json()["error"] == "appid_scope_unresolved"


def test_a_scoped_token_cannot_name_someone_elses_policy(app, client):
    aid = _appliance(app)
    _bind_appid(app, aid, app_id="APP-1", policies=["pol-a"])
    _bind_appid(app, aid, app_id="APP-2", policies=["pol-b"])
    t = _mint(app, capabilities=["waf_exception_draft"], app_ids=["APP-1"])
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid, policies=["pol-a", "pol-b"])))
    assert r.status_code == 403
    j = r.get_json()
    assert j["error"] == "appid_scope_denied" and "pol-b" in j["message"]


def test_a_shared_profile_is_refused_for_a_scoped_token(app, client):
    """Owning the policies you listed is NOT owning the profile they share."""
    aid = _appliance(app)
    _bind_appid(app, aid, app_id="APP-1", policies=["pol-a"])
    _bind_appid(app, aid, app_id="APP-2", policies=["pol-b"])
    _seed_policies(app, aid, {"pol-a": "wpp-app1", "pol-b": "wpp-app1"})
    t = _mint(app, capabilities=["waf_exception_draft"], app_ids=["APP-1"])
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid, policies=["pol-a"])))
    assert r.status_code == 403
    j = r.get_json()
    assert j["error"] == "wpp_shared_denied" and "pol-b" in j["message"]


def test_a_dedicated_profile_is_allowed_for_a_scoped_token(app, client):
    aid = _appliance(app)
    _bind_appid(app, aid, app_id="APP-1", policies=["pol-a"])
    _bind_appid(app, aid, app_id="APP-2", policies=["pol-b"])
    _seed_policies(app, aid, {"pol-a": "wpp-app1", "pol-b": "wpp-other"})
    t = _mint(app, capabilities=["waf_exception_draft"], app_ids=["APP-1"])
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid, policies=["pol-a"])))
    assert r.status_code == 201, r.get_json()


def test_an_unreadable_cache_fails_closed_not_open(app, client):
    """No cached policies = the profile's blast radius is UNPROVABLE.

    Treating "I could not read it" as "it is not shared" is how a scoped token
    writes onto another tenant's profile.
    """
    aid = _appliance(app)
    _bind_appid(app, aid, app_id="APP-1", policies=["pol-a"])
    t = _mint(app, capabilities=["waf_exception_draft"], app_ids=["APP-1"])
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid, policies=["pol-a"])))
    assert r.status_code == 403
    assert r.get_json()["error"] == "wpp_scope_unprovable"


def test_an_unscoped_token_is_not_subjected_to_the_wpp_probe(app, client):
    """An unscoped token has no AppID boundary to police, so an empty cache
    must not block it — otherwise the guard becomes an outage for everyone."""
    aid = _appliance(app)
    t = _mint(app, capabilities=["waf_exception_draft"])
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid, policies=["pol-a"])))
    assert r.status_code == 201, r.get_json()


def test_wpp_blast_radius_reports_none_when_nothing_is_cached(app):
    from app.services.api_object_rules import wpp_blast_radius
    aid = _appliance(app)
    with app.app_context():
        assert wpp_blast_radius(aid, "wpp-app1") is None


# --------------------------------------------------------------------------- #
#  7. The owner ceiling still holds for object writes                           #
# --------------------------------------------------------------------------- #
def test_a_token_cannot_outrank_its_owner(app, client):
    """A readonly owner's token holding write+the capability is still refused:
    revoking the human must neuter the credential."""
    aid = _appliance(app)
    uid = make_user(app, username="ext-team", role="readonly")
    t = _mint(app, owner_id=uid, scopes=["write"],
              capabilities=["waf_exception_draft"])
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid)))
    assert r.status_code == 403
    assert r.get_json()["error"] == "owner_forbidden"


def test_a_disabled_owner_neuters_the_token(app, client):
    aid = _appliance(app)
    uid = make_user(app, username="gone", role="admin")
    t = _mint(app, owner_id=uid, capabilities=["waf_exception_draft"])
    from app.extensions import db
    from app.models import User
    with app.app_context():
        db.session.get(User, uid).is_active = False
        db.session.commit()
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(aid)))
    assert r.status_code == 403
    assert r.get_json()["error"] == "owner_disabled"


def test_an_appliance_of_the_wrong_kind_is_not_found(app, client):
    adc = _appliance(app, name="adc1", kind="fortiadc")
    t = _mint(app, product="global",
              capabilities=["waf_exception_draft", "adc_rule_draft"])
    r = client.post("/api/v1/waf/exceptions", headers=_auth(t),
                    data=json.dumps(_body(adc)))
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
#  8. FortiADC                                                                  #
# --------------------------------------------------------------------------- #
def test_the_adc_allowlist_is_registry_backed(app):
    """A curated logical that the registry no longer knows would otherwise be a
    blind POST to a path whose meaning changed."""
    from app.api_v1.adc import ADC_RULE_LOGICALS
    from app.services import adc_objform
    with app.app_context():
        for logical in ADC_RULE_LOGICALS:
            assert adc_objform.is_known(logical), logical


def test_the_adc_allowlist_holds_no_system_or_router_objects():
    from app.api_v1.adc import ADC_RULE_LOGICALS
    for logical in ADC_RULE_LOGICALS:
        assert not logical.startswith(("system_", "router_", "user_")), logical


@pytest.mark.parametrize("logical", ["system_admin", "security_waf_profile", ""])
def test_adc_refuses_a_logical_outside_the_allowlist(app, client, logical):
    aid = _appliance(app, name="adc1", kind="fortiadc")
    t = _mint(app, product="fortiadc", capabilities=["adc_rule_draft"])
    r = client.post("/api/v1/adc/rules", headers=_auth(t),
                    data=json.dumps({"appliance_id": aid, "logical": logical,
                                     "mkey": "x", "fields": {}}))
    assert r.status_code == 400
    assert r.get_json()["error"] == "type_not_allowed"


def test_adc_dry_run_returns_the_request_and_opens_no_session(app, client,
                                                              monkeypatch):
    aid = _appliance(app, name="adc1", kind="fortiadc")
    t = _mint(app, product="fortiadc", capabilities=["adc_rule_draft"])

    def _boom(*a, **k):  # any device call is a failure of the contract
        raise AssertionError("dry-run must not touch the appliance")

    monkeypatch.setattr("app.clients.fortiadc.FortiADCClient.login", _boom)
    monkeypatch.setattr("app.clients.fortiadc.FortiADCClient._api", _boom)
    r = client.post("/api/v1/adc/rules", headers=_auth(t),
                    data=json.dumps({"appliance_id": aid,
                                     "logical": "security_waf_exception",
                                     "mkey": "exc-1",
                                     "fields": {"comments": "team X"}}))
    assert r.status_code == 200, r.get_json()
    j = r.get_json()
    assert j["applied"] is False and j["dry_run"] is True
    assert j["request"]["method"] == "POST"
    assert j["request"]["body"]["mkey"] == "exc-1"


def test_adc_apply_needs_its_own_capability(app, client):
    aid = _appliance(app, name="adc1", kind="fortiadc")
    t = _mint(app, product="fortiadc", capabilities=["adc_rule_draft"])
    r = client.post("/api/v1/adc/rules", headers=_auth(t),
                    data=json.dumps({"appliance_id": aid,
                                     "logical": "security_waf_exception",
                                     "mkey": "exc-1", "fields": {}, "apply": True}))
    assert r.status_code == 403
    assert r.get_json()["error"] == "capability_denied"


def test_adc_refuses_an_appid_scoped_token(app, client):
    """AppID scope resolves to FortiWeb server policies; on ADC it is
    unprovable, and unprovable must not mean allowed."""
    aid = _appliance(app, name="adc1", kind="fortiadc")
    _bind_appid(app, aid, app_id="APP-1", policies=["vs-a"])
    t = _mint(app, product="fortiadc", capabilities=["adc_rule_draft"],
              app_ids=["APP-1"])
    r = client.post("/api/v1/adc/rules", headers=_auth(t),
                    data=json.dumps({"appliance_id": aid,
                                     "logical": "security_waf_exception",
                                     "mkey": "exc-1", "fields": {}}))
    assert r.status_code == 403
    assert r.get_json()["error"] == "not_appid_scopable"


def test_adc_create_never_clobbers_an_existing_object(app, client, monkeypatch):
    aid = _appliance(app, name="adc1", kind="fortiadc")
    t = _mint(app, product="fortiadc",
              capabilities=["adc_rule_draft", "adc_rule_apply"])
    monkeypatch.setattr("app.clients.fortiadc.FortiADCClient.get_object",
                        lambda self, logical, mkey, **kw: {"mkey": mkey})
    created = []
    monkeypatch.setattr("app.clients.fortiadc.FortiADCClient.create",
                        lambda self, logical, data, **kw: created.append(data))
    r = client.post("/api/v1/adc/rules", headers=_auth(t),
                    data=json.dumps({"appliance_id": aid,
                                     "logical": "security_waf_exception",
                                     "mkey": "exc-1", "fields": {}, "apply": True}))
    assert r.status_code == 409
    assert r.get_json()["error"] == "already_exists"
    assert created == []


def test_adc_rule_types_advertises_that_delete_is_unsupported(app, client):
    """An integrator must learn this from the API, not from a support ticket."""
    t = _mint(app, product="fortiadc", scopes=["read"],
              capabilities=["adc_rule_draft"])
    r = client.get("/api/v1/adc/rule-types", headers=_auth(t))
    assert r.status_code == 200
    assert r.get_json()["delete_supported"] is False


def test_there_is_no_adc_delete_route(app):
    """The endpoint must be ABSENT, not present-and-403: ownership of an ADC
    object is unprovable, so there is nothing correct for it to do."""
    rules = [(str(r), sorted(r.methods)) for r in app.url_map.iter_rules()
             if str(r).startswith("/api/v1/adc/")]
    assert rules, "the ADC surface disappeared"
    assert not any("DELETE" in m for _p, m in rules)


# --------------------------------------------------------------------------- #
#  9. The admin page must not describe the grant it does not make               #
# --------------------------------------------------------------------------- #
def test_the_token_page_never_calls_an_empty_capability_list_all(app):
    """"all" was true while every capability was permissive-by-default. With
    explicit-only object writers it tells the operator a token can author WAF
    carve-outs when it cannot — a false statement about a security boundary."""
    from pathlib import Path
    src = Path(app.root_path, "templates", "api_tokens", "index.html").read_text()
    # Strip the comments that legitimately discuss the old label.
    body = "".join(part.split("#}")[-1] for part in src.split("{#"))
    assert "else 'all'" not in body and 'else "all"' not in body
    assert "NO_CAPS_LABEL" in body


def test_every_mintable_capability_is_described_on_the_page(app):
    from pathlib import Path
    from app.models_api_token import CAPABILITIES
    src = Path(app.root_path, "templates", "api_tokens", "index.html").read_text()
    block = src.split("{% set CAP_DESC = {", 1)[1].split("} %}", 1)[0]
    for cap in CAPABILITIES:
        assert f"'{cap}'" in block, f"{cap} has no operator-facing description"
