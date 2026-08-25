"""Guards for the artifact → Web Protection Profile attribution and the audit.

Everything pinned here fails SILENTLY. The page keeps rendering, the column
keeps holding a string, and the string is wrong in the direction that sends an
operator to a profile which does not mention the file:

  * ``None`` (nobody attributed this edge) and ``""`` (walked, and it genuinely
    hangs off the server policy) are OPPOSITE answers. One says "unknown", the
    other is a positive finding about a Lua script. Collapsing them is free —
    a ``DEFAULT ''`` on the column would have done it to 432 historical rows —
    and nothing fails afterwards;
  * a policy with content routing binds SEVERAL profiles. ``next(...)`` over the
    plan picks one and drops the rest without an error, and the policies that
    lose profiles this way are exactly the complicated ones;
  * Lua scripting hangs off the POLICY, never a profile. "the plan has one
    profile, so everything belongs to it" labels it with a profile that has
    never heard of it;
  * the referrer graph of a real appliance is not guaranteed acyclic, and an
    unguarded upward walk HANGS the sweep instead of failing it;
  * "borrowed" (SATOM would fall back to another appliance's bytes) must not
    render as "ok" — that fallback is a guess, and the divergence report is the
    only thing that says when the guess is between two different files;
  * a device with an EMPTY index must not read as a clean device. An audit that
    lists only the boxes it has data for reads as an audit of the fleet.

No device and no network: the referrer graph and the plan items are the exact
shapes ``ClonePlanner.collect`` produces, verified live against fortiweb12.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

XSD = "cmdb/waf/xml-schema.file"
LUA = "cmdb/server-policy/scripting"
WPP_INLINE = "cmdb/waf/web-protection-profile.inline-protection"
POLICY = "cmdb/server-policy/policy"


class _Item:
    """The two attributes ``artifact_wpp`` reads off a CloneItem."""

    def __init__(self, urn, mkey, kind="object"):
        self.urn, self.mkey, self.kind = urn, mkey, kind


def _art(kind="xml_schema", name="xsd-order", urn=XSD):
    return {"kind": kind, "name": name, "urn": urn, "label": kind,
            "status": "create", "readable": False, "name_warning": ""}


@pytest.fixture()
def store(app, tmp_path, monkeypatch):
    monkeypatch.setenv("SATOM_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    with app.app_context():
        yield


# ── the graph walk ───────────────────────────────────────────────────────────
def test_the_walk_climbs_more_than_one_level():
    """policy → profile → rule → file. Stopping at the immediate referrer names
    the RULE, which is not the object the operator opens."""
    from app.services import artifact_wpp as aw

    refs = {
        (XSD, "xsd-order"): {("cmdb/waf/xml-protection", "rule-x")},
        ("cmdb/waf/xml-protection", "rule-x"): {(WPP_INLINE, "wpp-a")},
        (WPP_INLINE, "wpp-a"): {(POLICY, "pol-a")},
    }
    up = aw.ancestors(refs, (XSD, "xsd-order"))
    assert (WPP_INLINE, "wpp-a") in up, (
        "the profile is two hops up; a one-hop lookup reports the rule instead")
    assert (POLICY, "pol-a") in up


def test_a_cycle_in_the_referrer_graph_does_not_hang_the_sweep():
    """Two objects naming each other is a configuration a FortiWeb accepts. An
    unguarded upward walk spins forever, and a sweep that HANGS is worse than a
    sweep that fails: nothing times out and nothing is reported."""
    from app.services import artifact_wpp as aw

    refs = {("a", "1"): {("b", "2")}, ("b", "2"): {("a", "1")}}
    # It TERMINATES, and reports the one real ancestor. The start node is not
    # listed as its own ancestor — the point of the guard is the termination,
    # and a mutation that drops `seen` never reaches this assertion at all: it
    # spins. That is why the contract is pinned exactly rather than loosely.
    assert aw.ancestors(refs, ("a", "1")) == {("b", "2")}


def test_only_profile_OBJECTS_count_as_profiles():
    """A sub-table row carrying the profile urn is not the profile."""
    from app.services import artifact_wpp as aw

    items = [_Item(WPP_INLINE, "wpp-a"),
             _Item(WPP_INLINE, "row-1", kind="subrow"),
             _Item(POLICY, "pol-a")]
    assert aw.wpp_nodes(items) == {(WPP_INLINE, "wpp-a")}


# ── the three states, which is the whole design ──────────────────────────────
def test_no_referrer_graph_yields_NOT_ATTRIBUTED_and_never_policy_level():
    """The load-bearing one. A caller with no graph knows NOTHING about the
    profile; answering ``""`` claims the walk positively found none."""
    from app.services import artifact_wpp as aw

    rows = aw.expand(aw.attribute([_art()], [], None))
    assert [r["wpp"] for r in rows] == [None], (
        "an unattributed edge must be None (unknown), never '' (a finding)")


def test_a_walked_artifact_with_no_profile_above_it_is_POLICY_LEVEL():
    """Lua scripting. Walked, and it genuinely hangs off the policy — which is
    a positive finding, not missing data."""
    from app.services import artifact_wpp as aw

    items = [_Item(WPP_INLINE, "wpp-a"), _Item(POLICY, "pol-a")]
    refs = {(LUA, "lua-rewrite"): {(POLICY, "pol-a")},
            (WPP_INLINE, "wpp-a"): {(POLICY, "pol-a")}}
    rows = aw.expand(aw.attribute(
        [_art(kind="scripting", name="lua-rewrite", urn=LUA)], items, refs))
    assert [r["wpp"] for r in rows] == [""], (
        "the plan HAS a profile, but this artifact does not reach the policy "
        "through it — labelling it 'wpp-a' names a profile that never mentions "
        "the script")


def test_the_profile_is_reported_when_the_artifact_really_travels_through_it():
    """The positive control. Without it, both assertions above are satisfied by
    an attribution that simply never finds anything."""
    from app.services import artifact_wpp as aw

    items = [_Item(WPP_INLINE, "wpp-a"), _Item(POLICY, "pol-a")]
    refs = {(XSD, "xsd-order"): {(WPP_INLINE, "wpp-a")},
            (WPP_INLINE, "wpp-a"): {(POLICY, "pol-a")}}
    rows = aw.expand(aw.attribute([_art()], items, refs))
    assert [r["wpp"] for r in rows] == ["wpp-a"]


def test_content_routing_two_profiles_produce_TWO_rows():
    """A policy can bind several profiles (``clone._visit`` follows a profile
    reference from a content-routing row too). One row holding 'a, b' is a fact
    nobody can filter on; dropping one is worse."""
    from app.services import artifact_wpp as aw

    items = [_Item(WPP_INLINE, "wpp-a"), _Item(WPP_INLINE, "wpp-b")]
    refs = {(XSD, "xsd-order"): {(WPP_INLINE, "wpp-a"), (WPP_INLINE, "wpp-b")}}
    rows = aw.expand(aw.attribute([_art()], items, refs))
    assert sorted(r["wpp"] for r in rows) == ["wpp-a", "wpp-b"]


def test_describe_keeps_the_three_states_distinguishable_in_prose():
    from app.services import artifact_wpp as aw

    assert aw.describe(None) != aw.describe("")
    assert "not attributed" in aw.describe(None)
    assert aw.describe("wpp-a") == "wpp-a"


# ── persistence ──────────────────────────────────────────────────────────────
def test_the_edge_key_includes_the_profile(store):
    """Under a (appliance, policy, kind, name) key the second profile collides
    with the first and the walk silently loses it."""
    from app.models_artifact_refs import WafArtifactRef
    from app.services import artifact_refs as ar

    ar.record(1, "pol-a", [dict(_art(), wpp="wpp-a"), dict(_art(), wpp="wpp-b")])
    assert WafArtifactRef.query.count() == 2
    assert sorted(r.wpp_mkey for r in WafArtifactRef.query.all()) == \
        ["wpp-a", "wpp-b"]


def test_re_deriving_replaces_an_unattributed_edge_with_an_attributed_one(store):
    """The 432 historical rows. A re-walk must not leave the NULL row sitting
    next to its attributed twin — that is the same edge counted twice."""
    from app.models_artifact_refs import WafArtifactRef
    from app.services import artifact_refs as ar

    ar.record(1, "pol-a", [dict(_art(), wpp=None)])
    assert WafArtifactRef.query.one().wpp_mkey is None
    ar.record(1, "pol-a", [dict(_art(), wpp="wpp-a")])
    rows = WafArtifactRef.query.all()
    assert len(rows) == 1 and rows[0].wpp_mkey == "wpp-a"


def test_a_donated_plan_with_no_graph_records_NOT_ATTRIBUTED(store):
    """``record_from_plan`` is called by the clone pre-flight. A donor that has
    no referrer graph must not manufacture 'policy-level' edges."""
    from app.models_artifact_refs import WafArtifactRef
    from app.services import artifact_refs as ar

    ar.record_from_plan(1, "pol-a", [_Item(XSD, "xsd-order")], refs=None)
    rows = WafArtifactRef.query.all()
    assert len(rows) == 1
    assert rows[0].wpp_mkey is None, (
        "no graph means unknown; '' would claim the walk found no profile")


def test_a_donated_plan_WITH_a_graph_records_the_profile(store):
    """Positive control for the previous guard: it must be possible to record a
    profile through this path, or the assertion above passes for the wrong
    reason (nothing recorded at all)."""
    from app.models_artifact_refs import WafArtifactRef
    from app.services import artifact_refs as ar

    ar.record_from_plan(
        1, "pol-a", [_Item(XSD, "xsd-order"), _Item(WPP_INLINE, "wpp-a")],
        refs={(XSD, "xsd-order"): {(WPP_INLINE, "wpp-a")}})
    assert WafArtifactRef.query.one().wpp_mkey == "wpp-a"


def test_the_serialised_edge_renders_the_state_as_words(store):
    """``to_dict`` feeds three templates. A blank cell in a table reads as
    'no data' and '' means the opposite."""
    from app.models_artifact_refs import WafArtifactRef
    from app.services import artifact_refs as ar

    ar.record(1, "pol-a", [dict(_art(), wpp="")])
    d = WafArtifactRef.query.one().to_dict()
    assert d["wpp"] == "" and d["wpp_text"] == "on the policy itself"
    ar.record(1, "pol-b", [dict(_art(), wpp=None)])
    d2 = [r.to_dict() for r in WafArtifactRef.query
          .filter_by(policy_mkey="pol-b").all()][0]
    assert d2["wpp"] is None and d2["wpp_text"] == "not attributed"


# ── the audit ────────────────────────────────────────────────────────────────
def test_an_unrecoverable_missing_artifact_is_BLOCKED_not_at_risk(store):
    """XML Schema cannot be read back from any FortiWeb. 'capture it before the
    move' is advice that cannot be followed."""
    from app.services import artifact_refs as ar

    ar.record(1, "pol-a", [dict(_art(kind="xml_schema"), wpp="wpp-a")])
    rep = ar.device_audit(1)
    assert [a["verdict"] for a in rep["artifacts"]] == ["blocked"]
    assert rep["totals"]["blocked"] == 1


def test_a_readable_missing_artifact_is_AT_RISK(store):
    """Positive control for the verdict ladder: without it, 'blocked' above is
    explained by everything being blocked."""
    from app.services import artifact_refs as ar

    ar.record(1, "pol-a", [dict(_art(kind="xml_dtd", name="dtd-order",
                                     urn="cmdb/waf/xml-dtd.file"), wpp="wpp-a")])
    assert [a["verdict"] for a in ar.device_audit(1)["artifacts"]] == ["at-risk"]


def test_another_appliances_copy_is_BORROWED_not_ok(store):
    """``waf_artifacts.resolve`` falls back to any appliance's copy of the same
    name. That fallback is a GUESS — two boxes can hold different content under
    one name — and rendering it as 'ok' is how the guess becomes invisible."""
    from app.services import artifact_files as af
    from app.services import artifact_refs as ar

    af.save_text("xml_schema", "xsd-order", "<xs:schema/>", appliance_id=2)
    ar.record(1, "pol-a", [dict(_art(), wpp="wpp-a")])
    rep = ar.device_audit(1)
    assert [a["verdict"] for a in rep["artifacts"]] == ["borrowed"]
    assert rep["totals"]["borrowed"] == 1 and rep["totals"]["ok"] == 0


def test_a_copy_scoped_to_this_device_is_OK(store):
    from app.services import artifact_files as af
    from app.services import artifact_refs as ar

    af.save_text("xml_schema", "xsd-order", "<xs:schema/>", appliance_id=1)
    ar.record(1, "pol-a", [dict(_art(), wpp="wpp-a")])
    assert [a["verdict"] for a in ar.device_audit(1)["artifacts"]] == ["ok"]


def test_a_device_with_nothing_indexed_reports_zero_policies(store):
    """It must be possible to tell 'never swept' from 'swept and clean'. The
    template keys off exactly these emptied lists."""
    from app.services import artifact_refs as ar

    rep = ar.device_audit(999)
    assert rep["policies"] == [] and rep["stored"] == []
    assert rep["totals"]["policies"] == 0


def test_a_failed_walk_is_carried_into_the_audit_with_its_error(store):
    """The three FortiADCs answer no server-policy endpoint. An audit that drops
    the failure shows a device with zero blocked artifacts, which reads clean."""
    from app.services import artifact_refs as ar

    ar.record_failure(1, "pol-a", "HTTPError: 405 invalid HTTP method")
    rep = ar.device_audit(1)
    assert rep["totals"]["walk_failed"] == 1
    assert "405" in rep["policies"][0]["error"]


def test_the_audit_ships_its_own_blind_spot(store):
    """The report is built without reading a device, so a policy created since
    the last sweep is absent. That sentence has to travel INSIDE the JSON and
    CSV an auditor keeps, not sit in template prose."""
    from app.services import artifact_refs as ar

    assert "created after the last sweep" in ar.device_audit(1)["caveat"]


def test_a_stored_object_nobody_references_is_an_orphan(store):
    from app.services import artifact_files as af
    from app.services import artifact_refs as ar

    af.save_text("xml_schema", "xsd-unused", "<xs:schema/>", appliance_id=1)
    rep = ar.device_audit(1)
    assert rep["totals"]["orphans"] == 1
    assert rep["stored"][0]["orphan"] is True


def test_divergence_flags_two_scopes_holding_DIFFERENT_bytes(store):
    from app.services import artifact_files as af
    from app.services import artifact_refs as ar

    af.save_text("xml_schema", "xsd-order", "<a/>", appliance_id=1)
    af.save_text("xml_schema", "xsd-order", "<b/>", appliance_id=2)
    rows = ar.content_divergence()
    assert len(rows) == 1 and rows[0]["name"] == "xsd-order"
    assert len({c["sha256"] for c in rows[0]["copies"]}) == 2


def test_editing_one_scope_twice_is_history_not_divergence(store):
    """Judged on the LATEST version per scope. Comparing every version flags any
    object that was ever edited, which is normal and would bury the real ones."""
    from app.services import artifact_files as af
    from app.services import artifact_refs as ar

    af.save_text("xml_schema", "xsd-order", "<a/>", appliance_id=1)
    af.save_text("xml_schema", "xsd-order", "<b/>", appliance_id=1)
    assert ar.content_divergence() == []


# ── the pages ────────────────────────────────────────────────────────────────
def test_the_four_artifact_pages_all_answer(app, client):
    from tests.conftest import admin_user_id, login

    login(client, admin_user_id(app))
    for url in ("/artifacts/", "/artifacts/inventory", "/artifacts/manage",
                "/artifacts/audit"):
        assert client.get(url).status_code == 200, url


def test_the_audit_exports_as_json_and_csv(app, client):
    from tests.conftest import admin_user_id, login

    login(client, admin_user_id(app))
    j = client.get("/artifacts/audit?format=json")
    assert j.status_code == 200 and j.get_json()["ok"] is True
    assert "generated_at" in j.get_json()

    c = client.get("/artifacts/audit?format=csv")
    assert c.status_code == 200
    assert "text/csv" in c.headers["Content-Type"]
    assert "attachment;" in c.headers["Content-Disposition"]
    head = c.get_data(as_text=True).splitlines()[0]
    assert head.startswith("generated_at,")


def test_the_csv_writes_the_profile_states_as_words(app, client, store):
    """A blank spreadsheet cell reads as 'no data'. '' here means the walk
    positively found no profile in between, and NULL means nobody looked."""
    from app.models import Appliance, db
    from app.services import artifact_refs as ar
    from tests.conftest import admin_user_id, login

    login(client, admin_user_id(app))
    dev = Appliance(name="fw-test", host="192.0.2.9", port=443, kind="fortiweb",
                    username="admin")
    dev.password = "pw"
    db.session.add(dev)
    db.session.commit()
    ar.record(dev.id, "pol-lua", [dict(_art(kind="scripting", name="lua-x",
                                       urn=LUA), wpp="")])
    ar.record(dev.id, "pol-old", [dict(_art(), wpp=None)])
    body = client.get("/artifacts/audit?format=csv").get_data(as_text=True)
    assert "(on the policy itself)" in body
    assert "(not attributed)" in body


def test_the_nav_uses_the_products_own_submenu_shape(app):
    """`fw-nav-sub` has no rule in fortiweb.css. Two children wearing it
    rendered flush with their parent — three top-level entries and no group.
    Pinned against the SOURCE, because a class that does not exist styles
    nothing and the page still returns 200."""
    import io
    import os
    import re

    src = io.open(os.path.join(app.root_path, "templates", "base.html"),
                  encoding="utf-8").read()
    i = src.find('data-nav-group="WAF"')
    assert i > 0
    nav = src[i:i + 6000]
    # Comments are stripped first: the comment EXPLAINING this guard names
    # `fw-nav-sub`, and asserting over it would match its own prose.
    nav = re.sub(r"\{#.*?#\}", "", nav, flags=re.S)

    assert "fw-nav-sub " not in nav and 'fw-nav-sub"' not in nav
    assert 'url_for(\'artifacts.index\')' in nav
    j = nav.find("artifacts.index")
    block = nav[max(0, j - 900):j + 1800]
    assert 'class="fw-so-parent"' in block
    assert "fw-so-parent-head" in block
    assert block.count("fw-so-nav-flat") == 4, (
        "four leaves: object types, inventory, files, device audit")
    for endpoint in ("artifacts.index", "artifacts.inventory",
                     "artifacts.manage", "artifacts.audit"):
        assert endpoint in block, endpoint
