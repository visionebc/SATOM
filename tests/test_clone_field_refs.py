"""Cross-cutting reference FIELDS and type-discriminated references.

Two defects, both reproduced on fortiweb12 (7.6.8) before a line was written.

1. ``trigger`` names a ``log/trigger-policy`` and nothing ever created it. The
   name rode inside the object's payload, so the appliance REJECTED the whole
   object on a destination that lacked the policy: the exact payload the planner
   builds answered HTTP 500 with no errcode and no message, while the same
   payload minus ``trigger`` answered 200. The field is carried by 10 of the
   tree's object collections — including ``server-policy/policy`` itself — and
   ``recaptcha-server`` by 3, so the edge is keyed by FIELD, not by tree
   position: only 51 of 130 object collections had any row on the lab appliance,
   so 79 could never have been inspected one by one.

2. A Custom Signature FILTER row (``custom-access.rule/custom-signature``)
   addresses TWO collections through ONE name field, chosen by a sibling
   ``custom-signature-type``. The name is validated by the box (a name that does
   not exist is rejected), so a dangling one breaks the row. Following both
   edges unconditionally is not a cheaper equivalent: the wrong collection
   answers with no object, which reads as "referenced on the source but not
   found live" and BLOCKS the apply.

``threat-weight`` is deliberately tested too and is NOT a reference: it is a
scalar that must ride inside the object's own body. A payload filter that
dropped it would be invisible — the create still succeeds, just weighted wrong.
"""
import pytest

from app.services import clone
from app.registry import dependencies as deps
from app.registry.dependencies import (
    DepNode,
    WEB_PROTECTION_PROFILE,
    FIELD_REFS,
    field_ref_edges,
    when_holds,
)

CPR = "cmdb/waf/custom-protection-rule"
CPG = "cmdb/waf/custom-protection-group"
TRIG = "cmdb/log/trigger-policy"
CAR = "cmdb/waf/custom-access.rule"
FILT = CAR + "/custom-signature"


class FakeReader:
    """Serves fixture rows by (urn, mkey); anything unknown is empty."""

    def __init__(self, data):
        self.data = data

    def get_raw(self, urn, mkey=""):
        return list(self.data.get((urn, mkey), []))


def _plan(data, root, mkey):
    p = clone.ClonePlanner(FakeReader(data), FakeReader({}))
    return [(i.urn, i.mkey) for i in p.collect(root, mkey)]


RULE_ROOT = DepNode("Custom Signature", CPR, "", "",
                    deps._CUSTOM_SIG_RULE_CHILDREN, ())


# --------------------------------------------------------------------------- #
#  1. the trigger edge                                                          #
# --------------------------------------------------------------------------- #
def test_a_trigger_becomes_its_own_object_in_the_plan():
    urns = _plan({(CPR, "r1"): [{"name": "r1", "trigger": "t1"}],
                  (TRIG, "t1"): [{"name": "t1"}]}, RULE_ROOT, "r1")
    assert (TRIG, "t1") in urns


def test_the_trigger_policy_is_planned_before_the_object_naming_it():
    # This ordering IS the fix: the appliance rejects the dependent outright
    # when the policy it names is absent.
    urns = _plan({(CPR, "r1"): [{"name": "r1", "trigger": "t1"}],
                  (TRIG, "t1"): [{"name": "t1"}]}, RULE_ROOT, "r1")
    assert urns.index((TRIG, "t1")) < urns.index((CPR, "r1"))


def test_an_empty_trigger_produces_no_edge():
    # The state of every object on a stock appliance. An edge here would plan a
    # phantom object named "" on every single clone.
    urns = _plan({(CPR, "r1"): [{"name": "r1", "trigger": ""}]}, RULE_ROOT, "r1")
    assert not [u for u, _k in urns if u == TRIG]


def test_an_object_without_the_field_produces_no_edge():
    urns = _plan({(CPR, "r1"): [{"name": "r1"}]}, RULE_ROOT, "r1")
    assert not [u for u, _k in urns if u == TRIG]


def test_a_trigger_on_a_sub_row_is_followed_too():
    root = DepNode("Holder", "u/holder", "", "",
                   (DepNode("Rows", "u/holder/rows", "", "", (), ()),), ())
    urns = _plan({("u/holder", "h"): [{"name": "h"}],
                  ("u/holder/rows", "h"): [{"id": "1", "trigger": "t9"}],
                  (TRIG, "t9"): [{"name": "t9"}]}, root, "h")
    assert (TRIG, "t9") in urns


def test_recaptcha_server_uses_the_same_machinery():
    urns = _plan({(CPR, "r1"): [{"name": "r1", "recaptcha-server": "rc1"}],
                  ("cmdb/user/recaptcha-user", "rc1"): [{"name": "rc1"}]},
                 RULE_ROOT, "r1")
    assert ("cmdb/user/recaptcha-user", "rc1") in urns


def test_threat_weight_travels_inside_the_objects_own_payload():
    p = clone.ClonePlanner(
        FakeReader({(CPR, "r1"): [{"name": "r1", "threat-weight": "severe"}]}),
        FakeReader({}))
    items = p.collect(RULE_ROOT, "r1")
    assert items[0].payload.get("threat-weight") == "severe"


# --------------------------------------------------------------------------- #
#  2. the type discriminator                                                    #
# --------------------------------------------------------------------------- #
FILTER_ROOT = DepNode("Rule", CAR, "", "", (
    DepNode("Custom Signature Filter", FILT, "", "",
            deps._CUSTOM_SIGNATURE_FILTER_REFS, ()),), ())


def _filter_plan(row):
    return _plan({(CAR, "car"): [{"name": "car"}],
                  (FILT, "car"): [dict(row, id="1")],
                  (CPG, "n1"): [{"name": "n1"}],
                  # a DIFFERENT rule name, so "no CPR/n1 item" keeps meaning
                  # "n1 was not resolved as a rule" even though the group
                  # legitimately drags one in through its type-list
                  (CPG + "/type-list", "n1"): [
                      {"id": "1", "custom-protection-rule": "inner"}],
                  (CPR, "inner"): [{"name": "inner"}],
                  (CPR, "n1"): [{"name": "n1"}]}, FILTER_ROOT, "car")


def test_type_custom_signature_resolves_the_name_as_a_rule():
    urns = _filter_plan({"custom-signature-type": "custom-signature",
                         "custom-signature-name": "n1"})
    assert (CPR, "n1") in urns and (CPG, "n1") not in urns


def test_type_group_resolves_the_same_name_as_a_group():
    urns = _filter_plan({"custom-signature-type": "custom-signature-group",
                         "custom-signature-name": "n1"})
    assert (CPG, "n1") in urns and (CPR, "n1") not in urns


@pytest.mark.parametrize("row", [
    {"custom-signature-type": "something-else", "custom-signature-name": "n1"},
    {"custom-signature-name": "n1"},
])
def test_an_unusable_discriminator_resolves_to_neither(row):
    # Guessing is what sends a name to the wrong collection, where it reads back
    # empty and blocks the apply on a reference that was never broken.
    assert not [u for u, _k in _filter_plan(row) if u in (CPG, CPR)]


def test_a_group_reached_through_the_filter_keeps_its_type_list():
    urns = _filter_plan({"custom-signature-type": "custom-signature-group",
                         "custom-signature-name": "n1"})
    # a sub-ROW is keyed by its own row id, never by the parent mkey
    assert CPG + "/type-list" in [u for u, _k in urns]


def test_when_holds_is_exact_not_a_substring():
    node = DepNode("x", "u/x", "f", "", (), ("t", "custom-signature"))
    assert when_holds(node, {"t": "custom-signature"})
    assert not when_holds(node, {"t": "custom-signature-group"})


# --------------------------------------------------------------------------- #
#  3. shape of the declarations                                                 #
# --------------------------------------------------------------------------- #
def test_every_field_ref_target_is_a_real_named_ref():
    for field, ref in FIELD_REFS.items():
        assert ref.via == field
        assert ref.urn.startswith("cmdb/")


def test_the_fortianalyzer_edge_keeps_field_and_collection_apart():
    # The FIELD is `analyzer-policy`; the COLLECTION is `fortianalyzer-policy`.
    # `cmdb/log/analyzer-policy` answers -20001.
    edges = {c.via: c.urn for c in deps._TRIGGER_POLICY_REF.children}
    assert edges["analyzer-policy"] == "cmdb/log/fortianalyzer-policy"
    assert set(edges) == {"email-policy", "syslog-policy", "analyzer-policy",
                          "siem-policy"}


def test_verified_notification_policies_carry_their_server_list():
    # A notification policy without its server list clones as a shell that
    # notifies nobody, and nothing fails.
    srv = {c.via: [g.urn for g in c.children]
           for c in deps._TRIGGER_POLICY_REF.children}
    assert srv["syslog-policy"] == ["cmdb/log/syslog-policy/syslog-server-list"]
    assert srv["analyzer-policy"] == [
        "cmdb/log/fortianalyzer-policy/fortianalyzer-server-list"]
    assert srv["siem-policy"] == ["cmdb/log/siem-policy/siem-server-list"]
    # left a leaf ON PURPOSE: `mail-server-list` came back non-list on 7.6.8,
    # and an unverified sub-table path echoes the parent instead of 404ing.
    assert srv["email-policy"] == []


def test_only_the_custom_signature_filter_carries_the_signature_edges():
    # Hanging them on all 17 filters is inert today (no other filter row has the
    # discriminator), which is exactly why it needs saying: it would read as
    # "any filter may name a signature".
    assert [c.urn for c in deps._CUSTOM_ACCESS_RULE_FILTERS if c.children] == [FILT]


def test_the_wpp_and_the_filter_share_one_custom_signature_subtree():
    # One shape, one author: two literal copies means the one nobody looks at
    # goes stale unnoticed.
    sig = next(g for c in WEB_PROTECTION_PROFILE.children
               for g in c.children if g.urn == CPG)
    assert sig.children is deps._CUSTOM_SIG_GROUP_CHILDREN
    assert deps._CUSTOM_SIGNATURE_FILTER_REFS[0].children is \
        deps._CUSTOM_SIG_GROUP_CHILDREN
