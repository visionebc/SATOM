"""Unit tests for services.config_compare — the full source↔destination diff.

Everything runs on in-memory fakes: no Flask request, no network, no appliance.
The synthetic dependency tree mirrors the shape of a real server policy (a root
that names a pool through one field and a profile through another, a by-parent
sub-table under the pool, and a WPP whose subtree must collapse to one row).

The four rules of the module are what these tests are for:
  1. counterparts pair by ROLE (the reference field), not by name
  2. a WPP is ONE row, never entry by entry
  3. the field diff is SYMMETRIC
  4. nothing is dropped in silence
"""
import pytest

from app.registry.dependencies import DepNode
from app.services import clone, config_compare as cc


# --------------------------------------------------------------------------- #
#  Synthetic tree + fakes                                                       #
# --------------------------------------------------------------------------- #
def _node(name, urn, via="", children=()):
    return DepNode(name, urn, via, "", tuple(children))


_MEMBER = _node("Pool Member", "u/pool/member")          # by-parent sub-table
_POOL = _node("Server Pool", "u/pool", children=(_MEMBER,))
_CERT = _node("Certificate", "u/cert")
_SIG = _node("Signature Rule", "u/sig")
# A WPP root, spelled with a REAL wpp urn so _is_wpp() recognises it.
_WPP_URN = clone.WPP_URNS[0]
# The WPP subtree is TWO levels deep on purpose: with a single hop the first
# role and the leaf role are the same string, so a bucketing rule that groups
# package differences by the LEAF (one bucket per entry — exactly what rule 2
# forbids) would be indistinguishable from the correct one.
_CR = _node("Custom Rule", "u/cr", via="custom-rule")
_SIGTREE = _node("Signature Rule", "u/sig", via="signature-rule",
                 children=(_CR,))
_WPP = _node("Web Protection Profile", _WPP_URN, children=(_SIGTREE,))
_POLICY = _node("Server Policy", "u/policy", children=(
    _node("Server Pool", "u/pool", via="server-pool", children=(_MEMBER,)),
    _node("Certificate", "u/cert", via="certificate"),
    _node("Web Protection Profile", _WPP_URN, via="web-protection-profile",
          children=(_SIGTREE,)),
))

_URN_INDEX = {"u/policy": "pol_l", "u/pool": "pool_l", "u/cert": "cert_l",
              "u/sig": "sig_l", "u/cr": "cr_l", "u/pool/member": "mem_l",
              _WPP_URN: "wpp_l"}


class FakeReader:
    """``{(urn, mkey): dict|list}`` lookup; mirrors ClientReader.get_raw."""

    def __init__(self, data):
        self.data = data

    def get_raw(self, urn, mkey=""):
        v = self.data.get((urn, mkey))
        if v is None:
            return []
        return v if isinstance(v, list) else [v]


def _tree(data, policy="spo1"):
    reader = FakeReader(data)
    planner = clone.ClonePlanner(reader, reader)
    planner.urn_index = dict(_URN_INDEX)   # decouple from the registry yaml
    tree, err = cc.collect_tree(reader, policy, root=_POLICY, planner=planner)
    assert err == "", err
    return tree


def _base(pool="pool1", cert="cert1", wpp="wpp1", policy="spo1",
          member_ip="192.0.2.1", pool_extra=None, policy_extra=None):
    data = {
        ("u/policy", policy): {"name": policy, "server-pool": pool,
                               "certificate": cert,
                               "web-protection-profile": wpp,
                               **(policy_extra or {})},
        ("u/pool", pool): {"name": pool, "type": "http", **(pool_extra or {})},
        ("u/pool/member", pool): [{"id": "1", "ip": member_ip, "port": "80"}],
        ("u/cert", cert): {"name": cert},
        (_WPP_URN, wpp): {"name": wpp, "signature-rule": "sig1"},
        ("u/sig", "sig1"): {"name": "sig1", "action": "block",
                            "custom-rule": "cr1"},
        ("u/cr", "cr1"): {"name": "cr1", "pattern": "/admin"},
    }
    return data


def _rows(src_data, dst_data):
    return cc.compare_trees(_tree(src_data), _tree(dst_data))


def _by_via(rows, via):
    return next(r for r in rows if r["via"] == via)


# --------------------------------------------------------------------------- #
#  Canonical values                                                             #
# --------------------------------------------------------------------------- #
def test_int_and_string_of_the_same_setting_are_not_a_difference():
    assert cc._diff_fields({"port": 80}, {"port": "80"}) == []


def test_absent_and_empty_are_the_same_field():
    assert cc._diff_fields({"comment": ""}, {}) == []


def test_bool_is_spelled_the_fortiweb_way():
    assert cc._scalar(True) == "enable"
    assert cc._diff_fields({"ssl": True}, {"ssl": "enable"}) == []


def test_a_real_difference_is_still_reported():
    assert cc._diff_fields({"port": 80}, {"port": 8080}) == [
        {"field": "port", "src": "80", "dst": "8080"}]


def test_bookkeeping_fields_are_not_differences():
    for field in ("id", "q_ref", "q_type", "q_path", "_mkey"):
        assert cc._diff_fields({field: "1"}, {field: "999"}) == [], field


# --------------------------------------------------------------------------- #
#  Rule 3 — the diff is symmetric                                               #
# --------------------------------------------------------------------------- #
def test_destination_only_field_is_a_difference():
    """The write-shaped diff (clone.subrow_diff) looks only at source fields.
    A comparison that inherited that would hide every destination-only setting,
    which is exactly the drift an operator opens this page to find."""
    out = cc._diff_fields({"name": "a"}, {"name": "a", "http2": "enable"})
    assert out == [{"field": "http2", "src": "", "dst": "enable"}]


def test_source_only_field_is_a_difference_too():
    out = cc._diff_fields({"name": "a", "http2": "enable"}, {"name": "a"})
    assert out == [{"field": "http2", "src": "enable", "dst": ""}]


def test_symmetry_holds_over_the_whole_tree():
    src = _base(pool_extra={"http2": "enable"})
    dst = _base()
    a = _by_via(_rows(src, dst), "server-pool")
    b = _by_via(_rows(dst, src), "server-pool")
    assert a["state"] == b["state"] == "changed"
    assert [f["field"] for f in a["fields"]] == [f["field"] for f in b["fields"]]


# --------------------------------------------------------------------------- #
#  Rule 1 — pairing is by ROLE, not by name                                     #
# --------------------------------------------------------------------------- #
def test_identical_trees_are_all_same():
    rows = _rows(_base(), _base())
    assert {r["state"] for r in rows} == {"same"}
    assert cc._verdict(rows) == "identical"


def test_renamed_object_pairs_and_is_reported_as_renamed():
    """A pool called differently on the destination is the SAME pool in the
    policy's ``server-pool`` role. Pairing on the name would emit
    only_source + only_destination — two findings that hide the one fact."""
    rows = _rows(_base(pool="pool1"), _base(pool="pool-mx"))
    row = _by_via(rows, "server-pool")
    assert row["state"] == "renamed"
    assert (row["src_name"], row["dst_name"]) == ("pool1", "pool-mx")
    assert not [r for r in rows if r["state"] in
                ("only_source", "only_destination")]


def test_a_renamed_object_that_also_drifted_reads_as_changed():
    rows = _rows(_base(pool="pool1"),
                 _base(pool="pool-mx", pool_extra={"type": "https"}))
    row = _by_via(rows, "server-pool")
    assert row["state"] == "changed"
    assert {"field": "type", "src": "http", "dst": "https"} in row["fields"]


def test_object_missing_on_the_destination_is_only_source():
    dst = _base()
    del dst[("u/cert", "cert1")]
    dst[("u/policy", "spo1")] = {k: v for k, v in dst[("u/policy", "spo1")].items()
                                 if k != "certificate"}
    row = _by_via(_rows(_base(), dst), "certificate")
    assert row["state"] == "only_source"
    assert row["src_name"] == "cert1" and row["dst_name"] == ""


def test_object_only_on_the_destination_is_reported_as_such():
    src = _base()
    del src[("u/cert", "cert1")]
    src[("u/policy", "spo1")] = {k: v for k, v in src[("u/policy", "spo1")].items()
                                 if k != "certificate"}
    row = _by_via(_rows(src, _base()), "certificate")
    assert row["state"] == "only_destination"
    assert row["src_name"] == "" and row["dst_name"] == "cert1"


def test_two_objects_in_one_field_pair_by_name_not_by_position():
    """With one candidate the field IS the evidence; with several the name is
    the only evidence of which is which, and guessing would be worse than
    reporting one gone and one new."""
    src = {"a": [{"via": "cert", "node": {"item": _fake("u/cert", "c1"),
                                          "children": [], "subrows": []}},
                 {"via": "cert", "node": {"item": _fake("u/cert", "c2"),
                                          "children": [], "subrows": []}}]}
    dst = {"a": [{"via": "cert", "node": {"item": _fake("u/cert", "c2"),
                                          "children": [], "subrows": []}},
                 {"via": "cert", "node": {"item": _fake("u/cert", "c3"),
                                          "children": [], "subrows": []}}]}
    pairs = cc._pair(src["a"], dst["a"])
    got = {(s["item"].mkey if s else None, d["item"].mkey if d else None)
           for _v, s, d in pairs}
    assert got == {("c1", None), ("c2", "c2"), (None, "c3")}


class _FakeItem:
    def __init__(self, urn, mkey, payload=None, label="X", kind="object",
                 depth=1, parent_mkey=""):
        self.urn, self.mkey, self.label = urn, mkey, label
        self.kind, self.depth, self.parent_mkey = kind, depth, parent_mkey
        self.payload = payload or {"name": mkey}


def _fake(urn, mkey, **kw):
    return _FakeItem(urn, mkey, **kw)


# --------------------------------------------------------------------------- #
#  Rule 2 — the WPP is ONE package row                                          #
# --------------------------------------------------------------------------- #
def test_wpp_is_a_single_row_not_one_per_entry():
    rows = _rows(_base(), _base())
    wpp = [r for r in rows if r["kind"] == "wpp"]
    assert len(wpp) == 1
    # its contents must NOT appear as rows of their own
    assert not [r for r in rows if r["urn"] in ("u/sig", "u/cr")]


def test_wpp_renamed_but_identical_is_not_a_content_difference():
    """A landed clone normally carries a derived profile name. Letting that one
    string flip a whole package to 'different' makes the verdict useless."""
    rows = _rows(_base(wpp="wpp1"), _base(wpp="spo1_wpp"))
    wpp = next(r for r in rows if r["kind"] == "wpp")
    assert wpp["state"] == "renamed"
    assert wpp["package"]["added"] == wpp["package"]["removed"] == 0
    assert wpp["package"]["changed"] == 0
    assert wpp["package"]["src_fingerprint"] == wpp["package"]["dst_fingerprint"]


def test_wpp_content_drift_is_counted_not_listed():
    dst = _base()
    dst[("u/sig", "sig1")] = {"name": "sig1", "action": "alert"}
    rows = _rows(_base(), dst)
    wpp = next(r for r in rows if r["kind"] == "wpp")
    assert wpp["state"] == "changed"
    assert wpp["package"]["changed"] == 1
    assert wpp["package"]["src_fingerprint"] != wpp["package"]["dst_fingerprint"]
    # still ONE row — the drift is a count, not a row per entry
    assert len([r for r in rows if r["kind"] == "wpp"]) == 1
    assert not [r for r in rows if r["urn"] in ("u/sig", "u/cr")]


def test_wpp_names_which_sub_profile_drifted():
    dst = _base()
    dst[("u/sig", "sig1")] = {"name": "sig1", "action": "alert",
                              "custom-rule": "cr1"}
    wpp = next(r for r in _rows(_base(), dst) if r["kind"] == "wpp")
    profiles = wpp["package"]["profiles"]
    assert len(profiles) == 1
    assert "signature-rule" in profiles[0]["profile"]
    assert profiles[0]["changed"] == 1


def test_everything_under_one_sub_profile_lands_in_ONE_bucket():
    """Two entries of different classes under the same sub-profile are ONE
    sub-profile drifting, not two. Bucketing on the entry's own label split
    them and made a single drift read as a broader one."""
    dst = _base()
    dst[("u/sig", "sig1")] = {"name": "sig1", "action": "alert",
                              "custom-rule": "cr1"}
    dst[("u/cr", "cr1")] = {"name": "cr1", "pattern": "/root"}
    wpp = next(r for r in _rows(_base(), dst) if r["kind"] == "wpp")
    profiles = wpp["package"]["profiles"]
    assert len(profiles) == 1
    assert profiles[0]["changed"] == 2


def test_wpp_added_and_removed_entries_are_counted_separately():
    dst = _base()
    dst[(_WPP_URN, "wpp1")] = {"name": "wpp1", "signature-rule": "sig2"}
    dst[("u/sig", "sig2")] = {"name": "sig2", "action": "block"}
    del dst[("u/sig", "sig1")]
    wpp = next(r for r in _rows(_base(), dst) if r["kind"] == "wpp")
    # sig2 arrives (1); sig1 leaves AND takes the custom rule it was the only
    # holder of with it (2). A sub-profile that goes takes its subtree.
    assert wpp["package"]["added"] == 1
    assert wpp["package"]["removed"] == 2
    assert wpp["package"]["changed"] == 0


def test_wpp_root_field_drift_is_reported_on_the_package_row():
    dst = _base()
    dst[(_WPP_URN, "wpp1")] = {"name": "wpp1", "signature-rule": "sig1",
                               "http2": "disable"}
    wpp = next(r for r in _rows(_base(), dst) if r["kind"] == "wpp")
    assert wpp["state"] == "changed"
    assert [f["field"] for f in wpp["fields"]] == ["http2"]


def test_the_packages_own_name_is_out_of_the_fingerprint():
    a = cc.compare_package(_tree(_base(wpp="w1"))["children"][-1]["node"],
                           _tree(_base(wpp="w2"))["children"][-1]["node"], "x")
    assert a["package"]["src_fingerprint"] == a["package"]["dst_fingerprint"]


# --------------------------------------------------------------------------- #
#  By-parent rows                                                               #
# --------------------------------------------------------------------------- #
def test_identical_members_produce_no_row():
    rows = _rows(_base(), _base())
    assert not [r for r in rows if r["kind"] == "subrow"]


def test_a_member_only_on_one_side_is_reported():
    rows = _rows(_base(member_ip="192.0.2.1"), _base(member_ip="192.0.2.9"))
    subs = [r for r in rows if r["kind"] == "subrow"]
    assert {r["state"] for r in subs} == {"only_source", "only_destination"}
    assert len(subs) == 2


def test_the_appliance_assigned_row_id_never_decides_identity():
    """Two boxes allocate their own ids. Comparing them would mark every
    by-parent row on every line as different — a report that says nothing."""
    dst = _base()
    dst[("u/pool/member", "pool1")] = [{"id": "77", "ip": "192.0.2.1",
                                        "port": "80"}]
    assert not [r for r in _rows(_base(), dst) if r["kind"] == "subrow"]


def test_rows_are_attached_to_their_own_parent_not_to_a_namesake():
    """A row carries its parent's NAME, not its parent's collection. Two
    objects of different collections sharing a name would otherwise each be
    handed the other's rows."""
    data = _base(pool="dup")
    data[("u/cert", "dup")] = {"name": "dup"}
    data[("u/policy", "spo1")]["certificate"] = "dup"
    del data[("u/cert", "cert1")]
    tree = _tree(data)
    pool = next(e["node"] for e in tree["children"] if e["via"] == "server-pool")
    cert = next(e["node"] for e in tree["children"] if e["via"] == "certificate")
    assert len(pool["subrows"]) == 1
    assert cert["subrows"] == []


# --------------------------------------------------------------------------- #
#  Absence — the trap collect() sets                                            #
# --------------------------------------------------------------------------- #
def test_a_missing_policy_is_absent_not_an_empty_tree():
    """collect() answers a missing policy with its depth-0 item and an EMPTY
    payload — never an empty list. ``if not items`` would read that as an empty
    tree and then declare two absent services identical."""
    reader = FakeReader({})
    planner = clone.ClonePlanner(reader, reader)
    planner.urn_index = dict(_URN_INDEX)
    tree, err = cc.collect_tree(reader, "nope", root=_POLICY, planner=planner)
    assert err == ""
    assert tree == {}


def test_a_present_policy_is_not_absent():
    assert _tree(_base()) != {}


# --------------------------------------------------------------------------- #
#  Verdicts                                                                     #
# --------------------------------------------------------------------------- #
def test_verdict_is_the_worst_state_present():
    assert cc._verdict([{"state": "same"}]) == "identical"
    assert cc._verdict([{"state": "same"}, {"state": "renamed"}]) == "differs"
    assert cc._verdict([{"state": "same"},
                        {"state": "only_destination"}]) == "differs"


def test_counts_add_up_per_state():
    counts = cc._counts([{"state": "same"}, {"state": "same"},
                         {"state": "changed"}])
    assert counts["same"] == 2 and counts["changed"] == 1


# --------------------------------------------------------------------------- #
#  run_batch — orchestration, with the walk stubbed                             #
# --------------------------------------------------------------------------- #
class _Appl:
    def __init__(self, name, host="192.0.2.1", kind="fortiweb", id=1):
        self.name, self.host, self.kind, self.id = name, host, kind, id


def _run(text, trees, **kw):
    """``trees`` maps appliance NAME -> {policy: (tree, error)}."""
    appls = [_Appl("fwA", "192.0.2.1", id=1), _Appl("fwB", "192.0.2.2", id=2)]
    seen = []

    def reader_factory(client):
        return client

    def client_factory(appl):
        return appl.name

    def collect(reader, policy):
        seen.append((reader, policy))
        return trees.get(reader, {}).get(policy, ({}, ""))

    rows, dropped = cc.parse_batch(text)
    report = cc.run_batch(rows, appliances=appls, client_factory=client_factory,
                          reader_factory=reader_factory, collect=collect, **kw)
    report["dropped"] = dropped
    report["_seen"] = seen
    return report


_T = {"item": _fake("u/policy", "spo1", depth=0), "children": [], "subrows": []}


def test_batch_reports_identical_lines():
    rep = _run("fwA;spo1;fwB", {"fwA": {"spo1": (_T, "")},
                                "fwB": {"spo1": (_T, "")}})
    assert rep["totals"]["identical"] == 1
    assert rep["lines"][0]["verdict"] == "identical"


def test_the_source_is_read_before_the_destination():
    """Not decoration: the source tree is the reference the destination is
    subtracted from, and when the budget expires it is the half that has to
    already be on the page."""
    rep = _run("fwA;spo1;fwB", {"fwA": {"spo1": (_T, "")},
                                "fwB": {"spo1": (_T, "")}})
    assert [r for r, _p in rep["_seen"]] == ["fwA", "fwB"]


def test_a_policy_absent_on_the_destination_is_missing_not_identical():
    rep = _run("fwA;spo1;fwB", {"fwA": {"spo1": (_T, "")},
                                "fwB": {"spo1": ({}, "")}})
    line = rep["lines"][0]
    assert line["verdict"] == "missing"
    assert line["dst_absent"] and not line["src_absent"]
    assert "not configured on fwB" in line["rows"][0]["note"]


def test_absent_on_both_sides_is_an_error_not_a_match():
    rep = _run("fwA;spo1;fwB", {"fwA": {"spo1": ({}, "")},
                                "fwB": {"spo1": ({}, "")}})
    assert rep["lines"][0]["verdict"] == "error"
    assert "neither" in rep["lines"][0]["error"]


def test_a_read_error_on_one_side_is_an_error_line():
    rep = _run("fwA;spo1;fwB", {"fwA": {"spo1": ({}, "boom")},
                                "fwB": {"spo1": (_T, "")}})
    assert rep["lines"][0]["verdict"] == "error"
    assert "boom" in rep["lines"][0]["error"]


def test_a_line_without_a_destination_is_refused_with_a_reason():
    """The reachability page accepts a two-field line (source only). A
    comparison cannot: half a line here is not a narrower answer, it is no
    answer, and silently treating it as 'identical' would be a lie."""
    rep = _run("fwA;spo1", {"fwA": {"spo1": (_T, "")}})
    assert rep["lines"][0]["verdict"] == "error"
    assert "needs both sides" in rep["lines"][0]["error"]


def test_an_unknown_appliance_is_named():
    rep = _run("nope;spo1;fwB", {"fwB": {"spo1": (_T, "")}})
    assert "nope" in rep["lines"][0]["error"]


def test_a_retired_placeholder_host_is_refused_before_a_read():
    appls = [_Appl("fw6", "retired-fw6.invalid", id=9), _Appl("fwB", id=2)]
    rows, _d = cc.parse_batch("fw6;spo1;fwB")
    rep = cc.run_batch(rows, appliances=appls,
                       client_factory=lambda a: a.name,
                       reader_factory=lambda c: c,
                       collect=lambda r, p: (_T, ""))
    assert "retired" in rep["lines"][0]["error"]


def test_each_appliance_policy_pair_is_read_once():
    rep = _run("fwA;spo1;fwB\nfwA;spo1;fwB",
               {"fwA": {"spo1": (_T, "")}, "fwB": {"spo1": (_T, "")}})
    assert len(rep["_seen"]) == 2      # not 4
    assert len(rep["lines"]) == 2


# --------------------------------------------------------------------------- #
#  Rule 4 — nothing is dropped in silence                                       #
# --------------------------------------------------------------------------- #
def test_the_format_header_is_skipped_and_said_so():
    rep = _run("source;policy;destination\nfwA;spo1;fwB",
               {"fwA": {"spo1": (_T, "")}, "fwB": {"spo1": (_T, "")}})
    assert len(rep["lines"]) == 1
    assert rep["dropped"] and "header" in rep["dropped"][0]["why"]


def test_over_limit_lines_are_named_not_trimmed():
    text = "\n".join("fwA;p%d;fwB" % i for i in range(cc.MAX_LINES + 3))
    rows, dropped = cc.parse_batch(text, max_lines=cc.MAX_LINES)
    assert len(rows) == cc.MAX_LINES
    assert len(dropped) == 3
    assert all(str(cc.MAX_LINES) in d["why"] for d in dropped)


def test_a_line_the_budget_never_reached_is_listed_by_name():
    calls = []

    def clock():
        calls.append(1)
        return 0.0 if len(calls) <= 2 else 999.0

    rep = _run("fwA;spo1;fwB\nfwA;spo2;fwB",
               {"fwA": {"spo1": (_T, ""), "spo2": (_T, "")},
                "fwB": {"spo1": (_T, ""), "spo2": (_T, "")}},
               clock=clock)
    assert rep["budget_hit"] is True
    assert rep["skipped"] and rep["skipped"][0]["raw"] == "fwA;spo2;fwB"
    assert "budget" in rep["skipped"][0]["why"]


def test_a_capped_field_list_says_how_many_were_hidden():
    src = {"name": "a", **{"f%02d" % i: "s" for i in range(cc.MAX_FIELD_ROWS + 5)}}
    dst = {"name": "a", **{"f%02d" % i: "d" for i in range(cc.MAX_FIELD_ROWS + 5)}}
    rows = cc.compare_trees(
        {"item": _fake("u/x", "x", payload=src, depth=0), "children": [],
         "subrows": []},
        {"item": _fake("u/x", "x", payload=dst, depth=0), "children": [],
         "subrows": []})
    assert len(rows[0]["fields"]) == cc.MAX_FIELD_ROWS
    assert rows[0]["truncated"] == 5


def test_a_row_whose_parent_vanished_is_still_reported():
    """Rule 4 at the tree level: a by-parent row that cannot be matched to its
    owner is re-homed, never dropped. A row that disappears here is a
    difference the report would claim does not exist."""
    root = _fake("u/policy", "spo1", depth=0)
    orphan = _fake("u/pool/member", "1", kind="subrow", depth=5,
                   parent_mkey="ghost")
    tree = cc.build_tree([root, orphan], [])
    assert tree["subrows"] == [orphan]


# --------------------------------------------------------------------------- #
#  Robustness                                                                   #
# --------------------------------------------------------------------------- #
def test_a_reference_cycle_does_not_hang():
    root = _fake("u/a", "a", depth=0)
    other = _fake("u/b", "b", depth=1)
    edges = [("u/a", "a", "to_b", "u/b", "b"),
             ("u/b", "b", "to_a", "u/a", "a")]
    tree = cc.build_tree([root, other], edges)
    assert cc.compare_trees(tree, tree) is not None


def test_an_empty_tree_compares_to_nothing_rather_than_raising():
    assert cc.compare_trees({}, {}) == []


# --------------------------------------------------------------------------- #
#  Export                                                                       #
# --------------------------------------------------------------------------- #
def test_tsv_has_one_line_per_difference_and_a_header():
    src = _base()
    dst = _base(pool_extra={"type": "https"})
    rows = _rows(src, dst)
    report = {"lines": [{"lineno": 1, "source": "fwA", "policy": "spo1",
                         "destination": "fwB", "verdict": "differs",
                         "error": "", "rows": rows}]}
    out = cc.to_tsv(report).splitlines()
    assert out[0].split("\t")[0] == "lineno"
    assert any("\ttype\thttp\thttps" in ln for ln in out)


def test_tsv_carries_the_package_verdict_without_its_entries():
    dst = _base()
    dst[("u/sig", "sig1")] = {"name": "sig1", "action": "alert"}
    rows = _rows(_base(), dst)
    report = {"lines": [{"lineno": 1, "source": "fwA", "policy": "spo1",
                         "destination": "fwB", "verdict": "differs",
                         "error": "", "rows": rows}]}
    out = cc.to_tsv(report)
    assert "package" in out
    assert "sig1" not in out          # entries never reach the export either


def test_tsv_reports_an_error_line():
    report = {"lines": [{"lineno": 3, "source": "fwA", "policy": "p",
                         "destination": "fwB", "verdict": "error",
                         "error": "no such device", "rows": []}]}
    assert "no such device" in cc.to_tsv(report)


# --------------------------------------------------------------------------- #
#  The planner seam this page depends on                                        #
# --------------------------------------------------------------------------- #
def test_the_planner_records_one_edge_per_reference_it_follows():
    """``clone._refs`` answers 'who names this?'. This page needs 'what ROLE
    does it play?', and only the FIELD says that — so the edge list must stay
    in step with _refs, never behind it."""
    reader = FakeReader(_base())
    planner = clone.ClonePlanner(reader, reader)
    planner.urn_index = dict(_URN_INDEX)
    planner.collect(_POLICY, "spo1")
    from_edges = {(c_urn, c_mkey) for _pu, _pm, _v, c_urn, c_mkey
                  in planner.edges}
    assert from_edges == set(planner._refs)
    assert ("u/policy", "spo1", "server-pool", "u/pool", "pool1") in planner.edges


def test_collect_resets_the_edge_log():
    """A second walk that inherited the first walk's edges would graft one
    service's objects onto another's tree."""
    reader = FakeReader(_base())
    planner = clone.ClonePlanner(reader, reader)
    planner.urn_index = dict(_URN_INDEX)
    planner.collect(_POLICY, "spo1")
    first = len(planner.edges)
    planner.collect(_POLICY, "spo1")
    assert len(planner.edges) == first


def test_wpp_urns_is_the_same_tuple_the_planner_prunes_on():
    assert clone.WPP_URNS == clone._WPP_URNS


# --------------------------------------------------------------------------- #
#  Rename suppression — the line between "renamed" and "reconfigured"           #
# --------------------------------------------------------------------------- #
def test_the_parent_reference_field_does_not_repeat_the_rename():
    """The policy's ``server-pool`` field naming the new pool IS the rename,
    already stated on the pool's own row. Letting it through would mark the
    ROOT policy as changed on every renamed clone."""
    rows = _rows(_base(pool="pool1"), _base(pool="pool-mx"))
    root = next(r for r in rows if r["via"] == "")
    assert root["state"] == "same"
    assert "server-pool" not in [f["field"] for f in root["fields"]]


def test_a_reference_field_that_moved_to_an_UNPAIRED_name_is_still_a_difference():
    """Suppression is exact-pair only. A field pointing somewhere that is not
    the paired counterpart is real drift and must survive."""
    out = cc._diff_fields({"server-pool": "a"}, {"server-pool": "c"},
                          suppress={"server-pool": ("a", "b")})
    assert out == [{"field": "server-pool", "src": "a", "dst": "c"}]


def test_a_payload_name_that_disagrees_with_its_own_mkey_is_shown():
    """``name`` is suppressed because it normally ECHOES the mkey. When it does
    not, the two have diverged on that box — an anomaly, not identity."""
    src = _fake("u/x", "x1", payload={"name": "x1"})
    dst = _fake("u/x", "x1", payload={"name": "somethingelse"})
    assert cc._identity_suppression(src, dst) == {}


def test_identity_suppression_only_covers_the_name_field():
    src = _fake("u/x", "a", payload={"name": "a", "type": "http"})
    dst = _fake("u/x", "b", payload={"name": "b", "type": "https"})
    assert cc._identity_suppression(src, dst) == {"name": ("a", "b")}


# --------------------------------------------------------------------------- #
#  Package bucketing + package-level field noise                                #
# --------------------------------------------------------------------------- #
def test_a_nested_package_difference_is_bucketed_by_its_FIRST_role():
    """Grouping by the leaf would give one bucket per entry — which is the
    entry-by-entry report rule 2 exists to prevent, wearing a summary's
    clothes. The bucket must name the sub-profile the entry hangs off."""
    dst = _base()
    dst[("u/cr", "cr1")] = {"name": "cr1", "pattern": "/root"}
    wpp = next(r for r in _rows(_base(), dst) if r["kind"] == "wpp")
    profiles = wpp["package"]["profiles"]
    assert len(profiles) == 1
    assert "signature-rule" in profiles[0]["profile"]
    assert "custom-rule" not in profiles[0]["profile"]
    assert profiles[0]["changed"] == 1


def test_a_nested_package_entry_never_becomes_a_row_of_its_own():
    dst = _base()
    dst[("u/cr", "cr1")] = {"name": "cr1", "pattern": "/root"}
    rows = _rows(_base(), dst)
    assert len([r for r in rows if r["kind"] == "wpp"]) == 1
    assert not [r for r in rows if r["urn"] in ("u/sig", "u/cr")]


def test_an_empty_valued_field_inside_a_package_is_not_content_drift():
    """FortiWeb omits an unset field from some collections and returns it as
    "" in others. Hashing that into the package fingerprint would report drift
    between two boxes holding identical config — and at package granularity the
    operator has no row to look at to see it was nothing."""
    dst = _base()
    dst[("u/sig", "sig1")] = {"name": "sig1", "action": "block",
                              "custom-rule": "cr1", "comment": ""}
    wpp = next(r for r in _rows(_base(), dst) if r["kind"] == "wpp")
    assert wpp["package"]["changed"] == 0
    assert wpp["package"]["src_fingerprint"] == wpp["package"]["dst_fingerprint"]
    assert wpp["state"] == "same"


def test_every_paired_child_is_recorded_renamed_or_not():
    """The suppression map covers every paired child; the exact-value match in
    _diff_fields is what decides. A ``s != d`` filter here looked protective
    and could only ever skip a pair that suppresses nothing."""
    pairs = [("server-pool", {"item": _fake("u/pool", "p1")},
                             {"item": _fake("u/pool", "p1")})]
    assert cc._rename_suppression(pairs) == {"server-pool": ("p1", "p1")}
