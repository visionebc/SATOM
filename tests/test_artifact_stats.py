"""Guards for the (device, ADOM) artifact statistics on ``/artifacts/``.

Every failure mode pinned here is SILENT — the page still renders, the numbers
still look like numbers, and each wrong one is wrong in the direction that
clears a migration nobody checked:

  * two ADOMs of one chassis merged into one scope makes a profile that binds
    ``schema-a`` in ``adom_prod`` look like coverage for the *different*
    ``schema-a`` in ``adom_dev`` — the two files never met;
  * a reference bound directly on a server policy (Lua scripting, which passes
    through NO profile) counted as a profile invents a profile that does not
    mention the file, and an operator sent to open it finds nothing;
  * a reference nobody attributed counted as "no profile" turns an unanswered
    question into an answer;
  * an ADOM nobody ever walked rendered as a row of zeros reads as "walked, and
    it carries nothing" — the exact false all-clear the whole subsystem exists
    to withhold;
  * a scope filter that silently falls back to the fleet answers a question
    about one ADOM with the numbers of twelve;
  * ``kinds_present`` summed across scopes is not a quantity of anything, and
    prints 35 for a fleet that uses seven object types.

No device and no network: the rows are written straight to the index, because
what is under test is the arithmetic over them, not the walk.
"""
from __future__ import annotations

from datetime import datetime

import pytest


class _Appl:
    """Minimal stand-in for an Appliance row.

    ``chassis_key`` reads kind/host/port and ``adom_of`` reads ``vdom``; nothing
    in this module touches the ORM, so a real row would only add a database
    round-trip to every assertion.
    """

    def __init__(self, id, name, host="192.0.2.13", port=443, vdom="root",
                 kind="fortiweb", maintenance=False, is_cluster=False):
        self.id = id
        self.name = name
        self.host = host
        self.port = port
        self.vdom = vdom
        self.kind = kind
        self.maintenance = maintenance
        self.is_cluster = is_cluster


def _ref(aid, policy, kind, name, wpp, seen=None):
    from app.models_artifact_refs import WafArtifactRef
    from app import db

    row = WafArtifactRef(appliance_id=aid, policy_mkey=policy, kind=kind,
                         name=name, wpp_mkey=wpp, urn="", derived_from="test",
                         first_seen_at=seen or datetime.utcnow(),
                         seen_at=seen or datetime.utcnow())
    db.session.add(row)
    return row


def _scan(aid, policy, ok=True, refs=0):
    from app.models_artifact_refs import WafArtifactScan
    from app import db

    row = WafArtifactScan(appliance_id=aid, policy_mkey=policy, ok=ok,
                          error="" if ok else "device unreachable", refs=refs,
                          scanned_at=datetime.utcnow())
    db.session.add(row)
    return row


def _stored(kind, name, aid, sha="a" * 64, size=10, source="uploaded"):
    from app.models_artifacts import WafArtifact
    from app import db

    row = WafArtifact(kind=kind, name=name, appliance_id=aid, sha256=sha,
                      size=size, source=source)
    db.session.add(row)
    return row


@pytest.fixture()
def ctx(app):
    with app.app_context():
        from app import db
        yield db


# ── the scope is (device, ADOM), never the chassis ──────────────────────────
def test_two_adoms_of_one_chassis_are_two_scopes_not_one(ctx):
    """The load-bearing split. ``fortiweb12`` and ``fortiweb12@adom_prod`` dial
    the same address; their configurations are unrelated."""
    from app.services import artifact_stats as st

    prod = _Appl(24, "fw12@prod", vdom="adom_prod")
    dev = _Appl(26, "fw12@dev", vdom="adom_dev")
    _ref(24, "pol-a", "wsdl", "schema-a", "wpp-shared")
    _ref(26, "pol-b", "wsdl", "schema-a", "wpp-shared")
    ctx.session.flush()

    out = st.fleet_stats([prod, dev])
    assert len(out["scopes"]) == 2, "the two ADOMs collapsed into one scope"
    # One chassis, because both rows dial 192.0.2.13:443.
    assert len(out["devices"]) == 1
    assert out["devices"][0]["adom_count"] == 2
    # A profile NAME is unique only within an ADOM, so one name in two ADOMs is
    # two profiles. Counting it once would say the second ADOM is covered by the
    # first ADOM's file.
    assert out["totals"]["profiles_with_files"] == 2
    assert out["totals"]["objects"] == 2


def test_a_profile_name_shared_across_adoms_is_not_deduplicated(ctx):
    """Positive control for the test above: with the ADOM dropped from the key
    both numbers fall to 1, and that is the bug, not a tidier count."""
    from app.services import artifact_stats as st

    a = _Appl(24, "fw12@prod", vdom="adom_prod")
    b = _Appl(26, "fw12@dev", vdom="adom_dev")
    for aid in (24, 26):
        _ref(aid, "pol", "wsdl", "same-name", "same-wpp")
    ctx.session.flush()

    dev_row = st.fleet_stats([a, b])["devices"][0]
    assert dev_row["totals"]["profiles_with_files"] == 2
    assert dev_row["totals"]["objects"] == 2


def test_an_unrelated_host_is_its_own_chassis(ctx):
    from app.services import artifact_stats as st

    a = _Appl(22, "fw12", host="192.0.2.13")
    b = _Appl(23, "fw13", host="192.0.2.14")
    _ref(22, "p", "wsdl", "x", "wpp-a")
    _ref(23, "p", "wsdl", "x", "wpp-a")
    ctx.session.flush()

    assert len(st.fleet_stats([a, b])["devices"]) == 2


# ── the three attribution states must never merge ───────────────────────────
def test_policy_level_and_unattributed_are_not_profiles(ctx):
    """``""`` is a FINDING (Lua hangs off the policy); ``None`` is an
    unanswered question. Either one counted as a profile prints a profile that
    does not mention the file."""
    from app.services import artifact_stats as st

    appl = _Appl(22, "fw12")
    _ref(22, "pol-a", "wsdl", "real", "wpp-a")       # a genuine profile
    _ref(22, "pol-b", "scripting", "lua-a", "")      # policy-level
    _ref(22, "pol-c", "wsdl", "old", None)           # never attributed
    ctx.session.flush()

    out = st.fleet_stats([appl])
    t = out["totals"]
    assert t["profiles_with_files"] == 1, "a non-profile edge was counted as a profile"
    assert t["policy_level_edges"] == 1
    assert t["unattributed_edges"] == 1
    # ...and all three still show up as references. A state that is excluded
    # from every bucket is a reference that silently vanished.
    assert t["edges"] == 3

    # The PER-ADOM counter, asserted separately and not as a formality:
    # fleet_stats RECOMPUTES the fleet figure from the raw rows and overwrites
    # whatever scope_stats produced, so a scope-level counter that swallowed
    # policy-level edges would be invisible in the total above — while being
    # exactly the number the "By device and ADOM" table prints per row.
    scope = out["scopes"][0]["totals"]
    assert scope["profiles_with_files"] == 1
    assert scope["policy_level_edges"] == 1
    assert scope["unattributed_edges"] == 1


def test_the_three_states_survive_into_the_per_profile_rows(ctx):
    from app.services import artifact_stats as st

    appl = _Appl(22, "fw12")
    _ref(22, "pol-a", "wsdl", "real", "wpp-a")
    _ref(22, "pol-b", "scripting", "lua-a", "")
    _ref(22, "pol-c", "wsdl", "old", None)
    ctx.session.flush()

    rows = st.fleet_stats([appl])["scopes"][0]["by_profile"]
    states = {r["state"] for r in rows}
    assert states == {"profile", "policy-level", "not-attributed"}, (
        "two attribution states were bucketed together")
    # Named profiles sort first: the other two are findings about the walk, not
    # profiles anyone can go and open.
    assert rows[0]["state"] == "profile"


# ── never swept is not zero ─────────────────────────────────────────────────
def test_a_scope_nobody_walked_is_flagged_not_zeroed(ctx):
    from app.services import artifact_stats as st

    walked = _Appl(22, "fw12")
    never = _Appl(24, "fw12@prod", vdom="adom_prod")
    # THE THIRD SCOPE IS THE POINT: walked, and it carries no artifact at all.
    # It is the only fixture that separates "was walked" from "has edges" —
    # with just the first two, a `swept = bool(refs)` reads correctly by
    # coincidence and this ADOM would be filed with the ones nobody looked at.
    empty = _Appl(25, "fw12@dmz", vdom="adom_dmz")
    _ref(22, "pol-a", "wsdl", "x", "wpp-a")
    _scan(22, "pol-a", ok=True, refs=1)
    _scan(25, "pol-none", ok=True, refs=0)
    ctx.session.flush()

    out = st.fleet_stats([walked, never, empty])
    by_id = {s["appliance_id"]: s for s in out["scopes"]}
    assert by_id[22]["swept"] is True
    assert by_id[25]["swept"] is True, (
        "an ADOM that WAS walked and carries nothing was filed as unswept — "
        "that turns a clean result into 'nobody looked'")
    assert by_id[25]["totals"]["edges"] == 0
    assert by_id[24]["swept"] is False, (
        "an ADOM nobody walked reported as swept — a row of zeros reads as "
        "'walked, and it carries nothing'")
    assert out["swept_scopes"] == 2 and out["scope_count"] == 3


def test_a_walked_policy_that_needs_nothing_is_swept(ctx):
    """Positive control: 'swept' must not be a synonym for 'has edges'."""
    from app.services import artifact_stats as st

    appl = _Appl(22, "fw12")
    _scan(22, "pol-clean", ok=True, refs=0)
    # A SECOND policy that does carry an artifact. Without it "clean policies"
    # and "scanned policies" are the same number, and a counter that forgot to
    # subtract the ones with artifacts would pass — while reporting every
    # policy on the box as carrying no file.
    _scan(22, "pol-loaded", ok=True, refs=1)
    _ref(22, "pol-loaded", "wsdl", "x", "wpp-a")
    ctx.session.flush()

    s = st.fleet_stats([appl])["scopes"][0]
    assert s["swept"] is True
    assert s["totals"]["policies_walked"] == 2
    assert s["totals"]["policies_with_artifacts"] == 1
    assert s["totals"]["policies_clean"] == 1
    assert s["totals"]["edges"] == 1


def test_a_failed_walk_is_counted_and_visible(ctx):
    from app.services import artifact_stats as st

    appl = _Appl(22, "fw12")
    _scan(22, "pol-a", ok=True, refs=0)
    _scan(22, "pol-b", ok=False)
    ctx.session.flush()

    t = st.fleet_stats([appl])["totals"]
    assert t["walk_failed"] == 1 and t["walk_ok"] == 1
    assert t["policies_walked"] == 2


def test_an_edge_without_a_scan_row_still_counts_as_a_policy(ctx):
    """A policy whose scan record was lost must not shrink the denominator."""
    from app.services import artifact_stats as st

    appl = _Appl(22, "fw12")
    _ref(22, "orphan-policy", "wsdl", "x", "wpp-a")
    ctx.session.flush()

    assert st.fleet_stats([appl])["totals"]["policies_walked"] == 1


# ── verdicts ────────────────────────────────────────────────────────────────
def test_an_unreadable_kind_with_no_copy_anywhere_is_blocked_not_at_risk(ctx):
    """``blocked`` means no FortiWeb will ever hand it back. ``at-risk`` means
    it is still capturable while the box is alive — opposite amounts of time."""
    from app.services import artifact_stats as st

    appl = _Appl(22, "fw12")
    # DELIBERATELY ASYMMETRIC — 2 unreadable against 1 readable. With one of
    # each, "2 == 2" holds just as well with the two counters swapped, and the
    # guard passes on a page that labels every blocked object capturable.
    _ref(22, "pol-a", "wsdl", "no-copy", "wpp-a")           # unreadable
    _ref(22, "pol-a", "grpc_idl", "no-copy-3", "wpp-a")     # unreadable
    _ref(22, "pol-a", "json_schema", "no-copy-2", "wpp-a")  # readable
    ctx.session.flush()

    t = st.fleet_stats([appl])["totals"]
    assert t["blocked"] == 2, "an unreadable, uncopied object was not blocked"
    assert t["at-risk"] == 1
    assert t["unreadable_needed"] == 2
    assert t["readable_needed"] == 1


def test_another_scopes_copy_is_borrowed_never_ok(ctx):
    """resolve() would serve the OTHER box's bytes. That is a guess, and it must
    not render as a copy of this device's file."""
    from app.services import artifact_stats as st

    mine = _Appl(22, "fw12")
    other = _Appl(23, "fw13", host="192.0.2.14")
    _ref(22, "pol-a", "wsdl", "shared", "wpp-a")
    _stored("wsdl", "shared", 23)          # stored for the OTHER appliance
    ctx.session.flush()

    t = st.fleet_stats([mine, other])["totals"]
    assert t["borrowed"] == 1 and t["ok"] == 0


def test_a_copy_scoped_to_this_device_is_ok(ctx):
    """Positive control for the guard above."""
    from app.services import artifact_stats as st

    mine = _Appl(22, "fw12")
    _ref(22, "pol-a", "wsdl", "shared", "wpp-a")
    _stored("wsdl", "shared", 22)
    ctx.session.flush()

    t = st.fleet_stats([mine])["totals"]
    assert t["ok"] == 1 and t["borrowed"] == 0


def test_a_library_wide_copy_is_named_rather_than_hidden_inside_borrowed(ctx):
    """resolve() falls back to the library BEFORE another device. 'an operator
    uploaded this for everyone' and 'some other box has the name' are not the
    same risk, so the subset is counted."""
    from app.services import artifact_stats as st

    mine = _Appl(22, "fw12")
    _ref(22, "pol-a", "wsdl", "shared", "wpp-a")
    _stored("wsdl", "shared", None)        # library-wide
    ctx.session.flush()

    out = st.fleet_stats([mine])
    assert out["totals"]["library_only"] == 1
    assert out["library"]["objects"] == 1
    # ...and it is NOT folded into a device scope, which owns no library row.
    assert out["totals"]["stored_objects"] == 0


def test_an_orphan_is_held_and_named_by_nobody(ctx):
    from app.services import artifact_stats as st

    appl = _Appl(22, "fw12")
    _stored("wsdl", "unused", 22)
    _ref(22, "pol-a", "wsdl", "used", "wpp-a")
    _stored("wsdl", "used", 22, sha="b" * 64)
    ctx.session.flush()

    t = st.fleet_stats([appl])["totals"]
    assert t["orphans"] == 1, "an object no walked policy names was not an orphan"
    assert t["stored_objects"] == 2


# ── rollups that must not be sums ───────────────────────────────────────────
def test_kinds_present_is_distinct_types_not_a_sum_over_scopes(ctx):
    """Summed, this reads 4 for two scopes that between them use two types —
    which is not a quantity of anything."""
    from app.services import artifact_stats as st

    a = _Appl(24, "fw12@prod", vdom="adom_prod")
    b = _Appl(26, "fw12@dev", vdom="adom_dev")
    for aid in (24, 26):
        _ref(aid, "p", "wsdl", "x", "wpp-a")
        _ref(aid, "p", "json_schema", "y", "wpp-a")
    ctx.session.flush()

    out = st.fleet_stats([a, b])
    assert out["totals"]["kinds_present"] == 2
    assert out["devices"][0]["totals"]["kinds_present"] == 2


def test_every_object_type_gets_a_row_even_at_zero(ctx):
    """A type with no references is an ANSWER. Omitting it makes the table read
    as though the type does not exist in this product."""
    from app.services import artifact_stats as st
    from app.services import waf_artifacts as wa

    appl = _Appl(22, "fw12")
    _ref(22, "pol-a", "wsdl", "x", "wpp-a")
    ctx.session.flush()

    rows = st.fleet_stats([appl])["by_kind"]
    assert {r["kind"] for r in rows} >= set(wa.KINDS)
    assert any(r["kind"] == "grpc_idl" and r["edges"] == 0 for r in rows)


# ── the ADOM label follows the repo's existing rule ─────────────────────────
def test_an_empty_adom_renders_as_root_and_is_device_scope(ctx):
    """models.DEVICE_SCOPE_ADOMS already settled that a row with no ADOM IS
    root. A second answer here is how two pages start disagreeing."""
    from app.services import artifact_stats as st

    assert st.adom_of(_Appl(1, "x", vdom=None)) == ("root", True)
    assert st.adom_of(_Appl(1, "x", vdom="root")) == ("root", True)
    assert st.adom_of(_Appl(1, "x", vdom="adom_prod")) == ("adom_prod", False)


# ── the page ────────────────────────────────────────────────────────────────
def test_the_scope_filter_narrows_the_statistics(client, ctx):
    """A ``?scope=`` that quietly widened back to the fleet would answer a
    question about one ADOM with everybody's numbers."""
    from app.models import Appliance
    from app import db

    a = Appliance(name="t-fw-a", kind="fortiweb", host="192.0.2.1", port=443,
                  username="u", password_enc="x", vdom="adom_a")
    b = Appliance(name="t-fw-b", kind="fortiweb", host="192.0.2.1", port=443,
                  username="u", password_enc="x", vdom="adom_b")
    db.session.add_all([a, b])
    db.session.commit()
    _ref(a.id, "pol-a", "wsdl", "x", "wpp-only-in-a")
    _ref(b.id, "pol-b", "wsdl", "y", "wpp-only-in-b")
    db.session.commit()

    from app.services import artifact_stats as st
    narrowed = st.fleet_stats([a])
    assert narrowed["totals"]["profiles_with_files"] == 1
    assert narrowed["scope_count"] == 1
    assert all(s["appliance_id"] == a.id for s in narrowed["scopes"])

    both = st.fleet_stats([a, b])
    assert both["totals"]["profiles_with_files"] == 2


def test_the_caveat_travels_with_the_numbers(ctx):
    """It is part of the payload, not a note in the template: a reader who
    copies these totals into a migration plan copies the blind spot too."""
    from app.services import artifact_stats as st

    out = st.fleet_stats([_Appl(22, "fw12")])
    assert "after the last sweep" in out["caveat"]


def test_stats_survive_an_empty_fleet(ctx):
    from app.services import artifact_stats as st

    out = st.fleet_stats([])
    assert out["scope_count"] == 0 and out["devices"] == []
    assert out["totals"]["edges"] == 0
    assert len(out["by_kind"]) >= 7
