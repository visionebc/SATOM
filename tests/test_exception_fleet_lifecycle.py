"""Fleet inventory, lifecycle control, multi-FortiWeb deploy, the advisory gate
and the file-backed create surface.

Each block guards a claim that is invisible until it is wrong:

* the fleet page's DENOMINATOR is the visible scope list, so a scope with zero
  carve-outs must be carried — dropping it makes "nobody authored anything
  here" indistinguishable from "this box is not in the list";
* two placements are the same carve-out by CONTENT, not by profile: folding the
  profile in makes every placement unique and the page reports a fleet of
  singletons;
* a delete is refused when it would take a waiver away from a policy that does
  not appear in the row, and the remedy (split) is not destructive, so no
  acknowledgement may bypass it;
* a deploy REFUSES loudly: a list of only the eligible destinations cannot be
  audited, because "not offered" and "not applicable" look identical;
* the advisory never returns "proportionate" from facts alone — nothing in it
  has been told what problem is being solved;
* the artifact kind behind a Section Config leaf is DERIVED from the registry
  collection, so a new leaf or kind wires itself up instead of silently
  offering no way to create the object.
"""
from __future__ import annotations

from tests.conftest import admin_user_id, login


def _appliance(app, name="fw1", vdom=""):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name=name, kind="fortiweb", host="192.0.2.99", port=443,
                      username="admin", verify_ssl=False)
        if vdom:
            a.vdom = vdom
        a.password = "secret"
        db.session.add(a); db.session.commit()
        return a.id


def _add(aid, **kw):
    from app.services import wpp_exceptions as s
    kw.setdefault("wpp_mkey", "wpp-x")
    kw.setdefault("exc_type", "signature_filter_item")
    kw.setdefault("payload", {"signature_id": "1"})
    return s.add(aid, **kw)


# ── fleet identity ─────────────────────────────────────────────────────────
def test_fingerprint_ignores_where_it_is_placed():
    """A carve-out for the same signature on two profiles is ONE intent placed
    twice. Folding the profile into the identity makes every placement unique
    and the whole page reports a fleet of singletons."""
    from app.services import exception_fleet as F
    a = F.fingerprint("signature_filter_item", {"signature_id": "1"})
    b = F.fingerprint("signature_filter_item", {"signature_id": "1"})
    c = F.fingerprint("signature_filter_item", {"signature_id": "2"})
    assert a == b and a != c


def test_fingerprint_is_key_order_independent():
    from app.services import exception_fleet as F
    assert (F.fingerprint("t", {"a": 1, "b": 2})
            == F.fingerprint("t", {"b": 2, "a": 1}))


def test_fingerprint_folds_a_retired_type_key():
    """A carve-out stored under the pre-Tanda-0 key is the SAME carve-out as
    one stored under the canonical key — grouping them apart would report one
    intent as two and hide that both boxes already have it."""
    from app.services import exception_fleet as F
    from app.services import wpp_exceptions as s
    old = "signature_group_rule_condition"
    assert s.canonical_type(old) != old, "this test needs a live alias"
    assert F.fingerprint(old, {"x": 1}) == F.fingerprint(s.canonical_type(old), {"x": 1})


def test_library_link_beats_the_content_guess(app):
    """A library link is somebody STATING two placements are the same; a
    fingerprint is this module inferring it. Where both exist the statement
    wins, and the page says which was used."""
    from app.services import exception_fleet as F
    aid = _appliance(app)
    with app.app_context():
        exc = _add(aid, library_uid="uid-1")
        assert F.group_key(exc) == ("library", "uid-1")
        plain = _add(aid, payload={"signature_id": "9"})
        assert F.group_key(plain)[0] == "content"


# ── the denominator ────────────────────────────────────────────────────────
def test_empty_scopes_are_carried(app):
    """A scope with no carve-outs is the normal state of a freshly added box.
    Dropping it makes "nobody authored anything here" and "this box is not in
    the list" indistinguishable, and they mean opposite things."""
    from app.services import exception_fleet as F
    a1 = _appliance(app, "fw1")
    _appliance(app, "fw2")
    with app.app_context():
        _add(a1)
        u = F.collect()
        assert len(u["scopes"]) == 2
        assert u["stats"]["scopes"] == 2 and u["stats"]["scopes_with_any"] == 1


def test_everywhere_counts_scopes_not_placements(app):
    """Two placements on the SAME box are not two boxes."""
    from app.services import exception_fleet as F
    a1 = _appliance(app, "fw1")
    _appliance(app, "fw2")
    with app.app_context():
        _add(a1, library_uid="u")
        _add(a1, library_uid="u", wpp_mkey="wpp-other")
        g = F.collect()["groups"][0]
        assert g["held_by"] == 1 and g["everywhere"] is False


def test_a_carve_out_on_every_scope_is_everywhere(app):
    from app.services import exception_fleet as F
    a1 = _appliance(app, "fw1")
    a2 = _appliance(app, "fw2")
    with app.app_context():
        _add(a1, library_uid="u")
        _add(a2, library_uid="u")
        g = F.collect()["groups"][0]
        assert g["held_by"] == 2 and g["everywhere"] is True and g["missing_from"] == 0


def test_orphans_are_reported_and_never_counted_against_a_live_scope(app):
    """A carve-out whose appliance is gone inflates exactly the box somebody is
    about to trust if it is folded into that box's tally."""
    from app.models import Appliance, db
    from app.services import exception_fleet as F
    a1 = _appliance(app, "fw1")
    a2 = _appliance(app, "fw2")
    with app.app_context():
        _add(a1)
        _add(a2, payload={"signature_id": "77"})
        db.session.delete(db.session.get(Appliance, a2))
        db.session.commit()
        u = F.collect()
        assert u["stats"]["orphans"] == 1
        assert u["stats"]["placements"] == 1
        assert sum(s["count"] for s in u["scopes"]) == 1


def test_unversioned_is_its_own_figure(app):
    """"13 carve-outs, 0 recoverable" is the fact that decides whether the undo
    button means anything. It cannot be folded into a health number."""
    from app.models import WppException, db
    from app.services import exception_fleet as F
    aid = _appliance(app)
    with app.app_context():
        _add(aid)                       # versioned
        legacy = WppException(appliance_id=aid, wpp_mkey="w",
                              exc_type="signature_filter_item", payload="{}")
        db.session.add(legacy); db.session.commit()
        assert F.collect()["stats"]["unversioned"] == 1


def test_type_choices_only_offer_what_is_present(app):
    """A filter that can only ever return nothing makes an empty table look
    like data loss."""
    from app.services import exception_fleet as F
    aid = _appliance(app)
    with app.app_context():
        _add(aid)
        rows = F.collect()["rows"]
        keys = {k for k, _l in F.type_choices(rows)}
        assert keys == {"signature_filter_item"}


def test_filter_rows_is_server_side_and_narrows(app):
    from app.services import exception_fleet as F
    rows = [{"exc_type": "a", "category": "exception", "scope": "s1",
             "stale": False, "enabled": True, "versioned": True,
             "name": "", "wpp_mkey": "", "policies": [], "payload": {}},
            {"exc_type": "b", "category": "signature", "scope": "s2",
             "stale": True, "enabled": True, "versioned": False,
             "name": "", "wpp_mkey": "", "policies": [], "payload": {}}]
    assert len(F.filter_rows(rows, exc_type="a")) == 1
    assert len(F.filter_rows(rows, state="stale")) == 1
    assert len(F.filter_rows(rows, state="unversioned")) == 1
    assert len(F.filter_rows(rows, state="active")) == 1
    assert F.filter_rows(rows, scope="nope") == []


# ── lifecycle ──────────────────────────────────────────────────────────────
def test_multi_policy_delete_demands_a_split(app):
    from app.services import exception_lifecycle as L
    aid = _appliance(app)
    with app.app_context():
        exc = _add(aid, policies=["pol-a", "pol-b"])
        rep = L.impact(exc, bindings={"pol-a": "wpp-x", "pol-b": "wpp-x"})
        assert rep["verdict"] == L.SPLIT
        assert rep["can_delete"] is False and rep["can_clone"] is True


def test_an_unread_device_is_never_reported_as_safe(app):
    """"We could not read the box" and "the profile is not shared" are the same
    empty map and mean opposite things. Only one makes a delete safe."""
    from app.services import exception_lifecycle as L
    aid = _appliance(app)
    with app.app_context():
        exc = _add(aid, policies=["pol-a"])
        assert L.impact(exc, bindings=None)["verdict"] == L.REVIEW
        assert L.impact(exc, bindings={"pol-a": "wpp-x"})["verdict"] == L.ALLOW


def test_a_shared_profile_needs_review(app):
    from app.services import exception_lifecycle as L
    aid = _appliance(app)
    with app.app_context():
        exc = _add(aid, policies=["pol-a"])
        rep = L.impact(exc, bindings={"pol-a": "wpp-x", "pol-z": "wpp-x"})
        assert rep["verdict"] == L.REVIEW and rep["shared_with"] == ["pol-z"]


def test_acknowledge_cannot_bypass_a_required_split(app):
    """The remedy exists and is not destructive. Letting an acknowledgement
    skip it would make the safer path the one nobody takes."""
    from app.services import exception_lifecycle as L
    from app.services import wpp_exceptions as s
    aid = _appliance(app)
    with app.app_context():
        exc = _add(aid, policies=["pol-a", "pol-b"])
        res = L.guarded_delete(exc, acknowledge=True,
                               bindings={"pol-a": "wpp-x", "pol-b": "wpp-x"})
        assert res["ok"] is False and res["code"] == 409
        assert s.get(exc.id) is not None


def test_acknowledge_does_release_a_review(app):
    from app.services import exception_lifecycle as L
    from app.services import wpp_exceptions as s
    aid = _appliance(app)
    with app.app_context():
        exc = _add(aid, policies=["pol-a"])
        eid = exc.id
        assert L.guarded_delete(exc, bindings=None)["ok"] is False
        exc = s.get(eid)
        assert L.guarded_delete(exc, bindings=None, acknowledge=True)["ok"] is True
        assert s.get(eid) is None


def test_split_never_leaves_a_policy_without_its_waiver(app):
    """A delete-then-recreate would strip every policy for as long as the
    operation takes. The original KEEPS the first policy throughout."""
    from app.services import exception_lifecycle as L
    from app.services import wpp_exceptions as s
    aid = _appliance(app)
    with app.app_context():
        exc = _add(aid, name="fp", policies=["pol-a", "pol-b", "pol-c"])
        res = L.split_by_policy(exc)
        assert res["ok"] and len(res["created"]) == 2
        assert s.get(exc.id).policy_names == ["pol-a"]
        pols = sorted(sum((s.get(c["id"]).policy_names for c in res["created"]), []))
        assert pols == ["pol-b", "pol-c"]


def test_split_copies_get_their_own_lineage(app):
    """Sharing one lineage would make a rollback on policy B's copy rewrite
    the carve-out policy A depends on — the exact coupling the split removes."""
    from app.services import exception_lifecycle as L
    from app.services import wpp_exceptions as s
    aid = _appliance(app)
    with app.app_context():
        exc = _add(aid, policies=["pol-a", "pol-b"])
        res = L.split_by_policy(exc)
        lineages = {s.get(c["id"]).lineage for c in res["created"]}
        assert exc.lineage not in lineages and len(lineages) == 1


def test_split_copies_join_the_same_library_item(app):
    """They ARE one intent placed several times — which is what the library
    models. Only the version lineage is private."""
    from app.services import exception_lifecycle as L
    from app.services import wpp_exceptions as s
    aid = _appliance(app)
    with app.app_context():
        exc = _add(aid, policies=["pol-a", "pol-b"], library_uid="u1")
        res = L.split_by_policy(exc)
        assert all(s.get(c["id"]).library_uid == "u1" for c in res["created"])


def test_policy_cascade_previews_before_it_deletes(app):
    from app.services import exception_lifecycle as L
    from app.services import wpp_exceptions as s
    aid = _appliance(app)
    with app.app_context():
        _add(aid, name="only-a", policies=["pol-a"])
        _add(aid, name="a-and-b", payload={"signature_id": "2"},
             policies=["pol-a", "pol-b"])
        prev = L.on_server_policy_deleted(aid, "pol-a")
        assert prev["applied"] is False
        assert [r["name"] for r in prev["to_delete"]] == ["only-a"]
        assert [r["name"] for r in prev["to_unbind"]] == ["a-and-b"]
        assert len(s.list_exceptions(aid)) == 2, "a preview writes nothing"
        L.on_server_policy_deleted(aid, "pol-a", apply=True)
        left = s.list_exceptions(aid)
        assert [e.name for e in left] == ["a-and-b"]
        assert left[0].policy_names == ["pol-b"]


def test_cascade_counts_stay_numbers(app):
    """`deleted` was a NUMBER in this response before the preview existed and
    the page prints it. Turning it into a list renders '[object Object]'."""
    from app.services import exception_lifecycle as L
    aid = _appliance(app)
    with app.app_context():
        res = L.on_server_policy_deleted(aid, "nothing")
        assert isinstance(res["deleted"], int) and isinstance(res["unbound"], int)


# ── deploy ─────────────────────────────────────────────────────────────────
def test_deploy_returns_refusals_rather_than_hiding_them(app):
    """A list of only the eligible destinations cannot be audited: "not
    offered" and "not applicable" look the same."""
    from app.services import exception_deploy as D
    a1 = _appliance(app, "fw1")
    a2 = _appliance(app, "fw2")
    with app.app_context():
        exc = _add(a1)
        _add(a2)                                   # identical content
        rows = {t["appliance_id"]: t for t in D.targets(exc)}
        assert rows[a1]["verdict"] == D.SOURCE
        assert rows[a2]["verdict"] == D.DUPLICATE
        assert len(rows) == 2, "every scope is returned, refused or not"


def test_deploy_refuses_a_scope_without_the_profile(app):
    from app.services import exception_deploy as D
    a1 = _appliance(app, "fw1")
    a2 = _appliance(app, "fw2")
    with app.app_context():
        exc = _add(a1, wpp_mkey="wpp-only-here")
        rows = {t["appliance_id"]: t for t in
                D.targets(exc, known_profiles={a2: {"something-else"}})}
        assert rows[a2]["verdict"] == D.NO_PROFILE


def test_an_unknown_profile_set_does_not_refuse(app):
    """Refusing because SATOM has not looked blocks a correct deploy on a
    missing snapshot rather than on a fact."""
    from app.services import exception_deploy as D
    a1 = _appliance(app, "fw1")
    a2 = _appliance(app, "fw2")
    with app.app_context():
        exc = _add(a1, wpp_mkey="wpp-only-here")
        rows = {t["appliance_id"]: t for t in D.targets(exc, known_profiles={})}
        assert rows[a2]["verdict"] == D.READY
        assert rows[a2]["profiles_known"] is False


def test_place_writes_one_library_uid_for_the_whole_batch(app):
    """Promoting per destination would mint a fresh uid each pass and the
    copies would not recognise each other — the entire point of placing."""
    from app.services import exception_deploy as D
    from app.services import wpp_exceptions as s
    a1 = _appliance(app, "fw1")
    a2 = _appliance(app, "fw2")
    a3 = _appliance(app, "fw3")
    with app.app_context():
        exc = _add(a1, name="fp")
        res = D.place(exc, [a2, a3], author="ann")
        assert res["ok"] and len(res["placed"]) == 2
        uids = {s.get(p["id"]).library_uid for p in res["placed"]}
        assert uids == {res["library_uid"]} and exc.library_uid == res["library_uid"]


def test_place_does_not_copy_policy_bindings(app):
    """A Server Policy name is a fact about the SOURCE appliance. Carrying it
    over asserts a binding on a box where that policy may not exist."""
    from app.services import exception_deploy as D
    from app.services import wpp_exceptions as s
    a1 = _appliance(app, "fw1")
    a2 = _appliance(app, "fw2")
    with app.app_context():
        exc = _add(a1, policies=["pol-a"])
        res = D.place(exc, [a2])
        assert s.get(res["placed"][0]["id"]).policy_names == []
        assert res["unbound"] == [p["id"] for p in res["placed"]]


def test_place_refuses_an_invisible_destination(app):
    from app.services import exception_deploy as D
    a1 = _appliance(app, "fw1")
    with app.app_context():
        exc = _add(a1)
        res = D.place(exc, [999999])
        assert res["ok"] is False and res["refused"][0]["appliance_id"] == 999999


def test_placing_is_versioned(app):
    from app.services import exception_deploy as D
    from app.services import exception_versions as V
    from app.services import wpp_exceptions as s
    a1 = _appliance(app, "fw1")
    a2 = _appliance(app, "fw2")
    with app.app_context():
        exc = _add(a1)
        res = D.place(exc, [a2], author="ann")
        copy = s.get(res["placed"][0]["id"])
        hist = V.history(copy.lineage)
        assert hist and hist[-1].action == V.ACT_CLONE


# ── advisory gate ──────────────────────────────────────────────────────────
def test_deterministic_advice_never_says_proportionate():
    """It is a judgement about the problem being solved, and nothing here has
    been told what the problem is."""
    from app.services import exception_advice as A
    d = A.deterministic("signature_filter_item",
                        {"signature_id": "1", "match-target": "URI",
                         "operator": "REGEXP_MATCH", "value": "^/checkout$"})
    assert d["verdict"] != A.PROPORTIONATE


def test_a_shared_profile_becomes_a_high_concern():
    from app.services import exception_advice as A
    d = A.deterministic("geo_ip_exception_member_item", {"ip": "1.2.3.4"},
                        scope_verdict={"needs_clone": True, "summary": "shared"})
    assert any(c["key"] == "shared-profile" and c["severity"] == "high"
               for c in d["concerns"])


def test_advice_returns_the_facts_when_no_model_is_reachable():
    """Making the checkable half depend on a provider being up ties it to the
    guessing one."""
    from app.services import exception_advice as A
    out = A.analyse("geo_ip_exception_member_item", {"ip": "1.2.3.4"},
                    use_model=False)
    assert out["explain"] and out["model"] is None


def test_parse_verdict_degrades_toward_caution():
    from app.services import exception_advice as A
    assert A.parse_verdict("wrong-tool\nbecause…") == A.WRONG_TOOL
    assert A.parse_verdict("proportionate — fine") == A.PROPORTIONATE
    assert A.parse_verdict("no idea at all") == A.UNKNOWN
    # An answer that ARGUES its way past a token in the tail must not be read
    # off the tail; only the head is scanned.
    assert A.parse_verdict("cannot-tell\n\n" + "x" * 50
                           + "\n\n\n\nproportionate") == A.UNKNOWN


def test_the_outbound_prompt_is_producible_without_sending():
    """An operator about to hand a carve-out to a provider is entitled to read
    the exact bytes first."""
    from app.services import exception_advice as A
    p = A.prompt_for("signature_filter_item",
                     {"signature_id": "010000001", "value": "ZZUNIQUEZZ"},
                     problem="checkout false positive")
    assert "checkout false positive" in p
    # The VALUES must travel, not just the labels: a prompt that carries the
    # field names and drops what they are set to asks the model to judge an
    # empty carve-out and get an opinion about it anyway.
    assert "010000001" in p and "ZZUNIQUEZZ" in p


# ── file-backed objects from Section Config ────────────────────────────────
def test_artifact_kind_is_derived_from_the_registry_collection():
    """A hand-written second map needs extending every time a leaf or a kind is
    added, and forgetting is SILENT — the create affordance just never shows."""
    from app.services import config_sections as cs, waf_artifacts as wa
    for logical, want in (("xml_protection_wsdl", "wsdl"),
                          ("xml_protection_xml_schema", "xml_schema"),
                          ("xml_protection_dtd", "xml_dtd"),
                          ("json_schema", "json_schema"),
                          ("openapi_file", "openapi")):
        t = cs.type_for("api_protection", logical)
        assert t is not None, logical
        assert wa.kind_for_collection(t.collection) == want, logical


def test_every_artifact_kind_is_reachable_by_collection():
    from app.services import waf_artifacts as wa
    for kind, spec in wa.KINDS.items():
        coll = spec["urn"].split("cmdb/", 1)[1]
        assert wa.kind_for_collection(coll) == kind, kind


def test_an_ordinary_leaf_derives_no_kind():
    from app.services import config_sections as cs, waf_artifacts as wa
    t = cs.type_for("api_protection", "api_policy")
    assert wa.kind_for_collection(t.collection) == ""
    assert wa.kind_for_collection("") == ""


# ── routes ─────────────────────────────────────────────────────────────────
def test_fleet_page_and_feed_agree(app, client):
    from app.services import wpp_exceptions as s  # noqa: F401
    a1 = _appliance(app, "fw1")
    login(client, admin_user_id(app))
    with app.app_context():
        _add(a1, name="one")
    r = client.get("/waf/exceptions")
    assert r.status_code == 200 and b"one" in r.data
    feed = client.get("/waf/api/exceptions.json").get_json()
    assert feed["stats"]["placements"] == 1
    assert sum(p["value"] for p in feed["per_scope"]) == 1


def test_fleet_csv_header_matches_the_table(app, client):
    from app.views.waf import EXCEPTION_COLUMNS
    a1 = _appliance(app, "fw1")
    login(client, admin_user_id(app))
    with app.app_context():
        _add(a1)
    r = client.get("/waf/exceptions?format=csv")
    assert r.status_code == 200
    head = r.data.decode().splitlines()[0]
    assert head.split(",")[0] == EXCEPTION_COLUMNS[0][1]
    assert len(head.split(",")) == len(EXCEPTION_COLUMNS)


def test_device_inventory_filters_are_server_side(app, client):
    a1 = _appliance(app, "fw1")
    login(client, admin_user_id(app))
    with app.app_context():
        # Distinctive names on purpose: "other" is a substring of ordinary
        # page chrome, so an absence assertion on it passes or fails for
        # reasons that have nothing to do with the filter.
        _add(a1, name="ZZKEEPMEZZ")
        _add(a1, name="ZZOTHERZZ", exc_type="geo_ip_exception_member_item",
             payload={"ip": "1.1.1.1"})
    all_rows = client.get("/exceptions/%d" % a1).data
    assert b"ZZKEEPMEZZ" in all_rows and b"ZZOTHERZZ" in all_rows
    filtered = client.get("/exceptions/%d?type=signature_filter_item" % a1).data
    assert b"ZZKEEPMEZZ" in filtered and b"ZZOTHERZZ" not in filtered, (
        "the filter must narrow the SHIPPED page, not hide rows in the browser")


def test_deploy_and_lifecycle_routes_refuse_a_foreign_scope(app, client):
    a1 = _appliance(app, "fw1")
    a2 = _appliance(app, "fw2")
    login(client, admin_user_id(app))
    with app.app_context():
        exc = _add(a1)
        eid = exc.id
    for path in ("/exceptions/%d/impact?exc_id=%d" % (a2, eid),
                 "/exceptions/%d/deploy-targets?exc_id=%d" % (a2, eid)):
        assert client.get(path).status_code == 404, path
    for path in ("/exceptions/%d/guarded-delete" % a2,
                 "/exceptions/%d/split" % a2,
                 "/exceptions/%d/deploy" % a2):
        assert client.post(path, json={"exc_id": eid,
                                       "appliance_ids": [a1]}).status_code == 404, path


def test_purge_route_previews_by_default(app, client):
    from app.services import wpp_exceptions as s
    a1 = _appliance(app, "fw1")
    login(client, admin_user_id(app))
    with app.app_context():
        _add(a1, policies=["pol-a"])
    r = client.post("/exceptions/%d/purge" % a1, json={"server_policy": "pol-a"})
    assert r.status_code == 200 and r.get_json()["applied"] is False
    with app.app_context():
        assert len(s.list_exceptions(a1)) == 1
    r = client.post("/exceptions/%d/purge" % a1,
                    json={"server_policy": "pol-a", "apply": True})
    assert r.get_json()["applied"] is True
    with app.app_context():
        assert s.list_exceptions(a1) == []
