"""The two ``<datasource>`` fields the Web Protection Profile OBJECT itself names.

Reported as "the redirect URL is not being cloned". Measured on fortiweb12
(7.6.8) before a line was written, and the report was right about the symptom
and wrong about the cause:

* ``redirect-url`` is a ``<string>`` (``set redirect-url ?`` answers
  ``<string>  Http redirect URL``) and it always travelled — a WPP POSTed to a
  clean fortiweb13 reads it back verbatim.
* What did NOT travel are the two ``<datasource>`` fields sitting beside it on
  the same object:

  - ``custom-response``    -> ``waf/custom-response.custom-response-policy``
  - ``quarantined-ip-trigger`` -> ``log/trigger-policy``

  and the visible effect is exactly the reported one, only worse: a dangling
  reference makes the destination answer **-651 to the WHOLE profile**, so
  ``redirect-url`` and every other setting are lost together with it. Proven end
  to end: the planner's own payload with either reference answers -651 on a
  clean box; the same payload without them answers 200 and reads ``redirect-url``
  back intact.

Two shape facts that are not guesses:

* ``custom-response`` is UNDOCUMENTED on the 7.6.8 CLI reference page for this
  profile — the appliance is the only authority. Its table is TWO-LEVEL
  (``config waf custom-response custom-response-policy``), so the REST path
  takes a dot; every single-level spelling answers -20001.
* The custom-response POLICY has no scalar fields at all — ``name`` plus a
  read-only ``sz_rule`` counter. Its entire content is the ``rule`` sub-table,
  which was settled by creating a parent and reading the child path: ``rule``
  answers a LIST, while ``rule-list``/``rule_list`` echo the PARENT object back.
"""
from app.services import clone
from app.registry import dependencies as deps
from app.registry.dependencies import WEB_PROTECTION_PROFILE, FIELD_REFS

WPP = "cmdb/waf/web-protection-profile.inline-protection"
CRP = "cmdb/waf/custom-response.custom-response-policy"
CRR = "cmdb/waf/custom-response.custom-response-rule"
TRIG = "cmdb/log/trigger-policy"


class FakeReader:
    def __init__(self, data):
        self.data = data

    def get_raw(self, urn, mkey=""):
        return list(self.data.get((urn, mkey), []))


def _plan(row):
    data = {(WPP, "p1"): [dict(row, name="p1")],
            (CRP, "cr1"): [{"name": "cr1"}],
            (CRP + "/rule", "cr1"): [{"id": "1",
                                      "custom-response-rule-name": "crr1"}],
            (CRR, "crr1"): [{"name": "crr1", "url": "/denied",
                             "content": "<html>blocked</html>"}],
            (TRIG, "tp1"): [{"name": "tp1"}]}
    p = clone.ClonePlanner(FakeReader(data), FakeReader({}))
    return [(i.urn, i.mkey) for i in p.collect(WEB_PROTECTION_PROFILE, "p1")]


FULL = {"custom-response": "cr1", "quarantined-ip-trigger": "tp1",
        "redirect-url": "https://blocked.example/denied", "rdt-reason": "enable"}


# --------------------------------------------------------------------------- #
#  custom-response                                                              #
# --------------------------------------------------------------------------- #
def test_a_wpp_naming_a_custom_response_carries_the_policy():
    assert (CRP, "cr1") in _plan(FULL)


def test_it_carries_the_rule_rows_that_are_its_entire_content():
    # The policy has no scalar fields; without this sub-table it lands complete
    # and enforces nothing.
    assert (CRP + "/rule", "1") in _plan(FULL)


def test_it_carries_the_rule_object_those_rows_name():
    assert (CRR, "crr1") in _plan(FULL)


def test_the_rule_object_is_planned_before_the_row_that_names_it():
    urns = _plan(FULL)
    assert urns.index((CRR, "crr1")) < urns.index((CRP + "/rule", "1"))


def test_an_empty_custom_response_plans_no_phantom_policy():
    assert not [u for u, _k in _plan({"custom-response": ""}) if u == CRP]


def test_a_wpp_without_the_field_plans_nothing():
    assert not [u for u, _k in _plan({}) if u in (CRP, CRR)]


def test_the_declared_sub_table_is_the_path_that_was_verified():
    # `rule-list`/`rule_list` echo the parent object back — an unverified child
    # path does not 404 on FortiWeb, it re-POSTs the policy inside itself.
    node = next(c for c in WEB_PROTECTION_PROFILE.children
                if c.via == "custom-response")
    assert [g.urn for g in node.children] == [CRP + "/rule"]
    assert node.urn == CRP


def test_the_rule_is_reached_by_its_own_name_field():
    node = next(c for c in WEB_PROTECTION_PROFILE.children
                if c.via == "custom-response")
    assert [(g.urn, g.via) for g in node.children[0].children] == [
        (CRR, "custom-response-rule-name")]


# --------------------------------------------------------------------------- #
#  quarantined-ip-trigger                                                       #
# --------------------------------------------------------------------------- #
def test_a_wpp_naming_a_quarantined_ip_trigger_carries_the_trigger_policy():
    assert (TRIG, "tp1") in _plan(FULL)


def test_the_trigger_is_reached_through_the_wpp_own_field_name():
    # The `trigger` edge keys on that exact field name and a WPP never carries
    # it — which is the whole reason this went unseen for twelve releases.
    row = {"quarantined-ip-trigger": "tp1"}
    assert "trigger" not in row
    assert (TRIG, "tp1") in _plan(row)


def test_the_trigger_policy_is_planned_before_the_profile_naming_it():
    urns = _plan(FULL)
    assert urns.index((TRIG, "tp1")) < urns.index((WPP, "p1"))


def test_an_empty_quarantined_trigger_plans_nothing():
    assert not [u for u, _k in _plan({"quarantined-ip-trigger": ""})
                if u == TRIG]


def test_both_trigger_edges_share_one_notification_subtree():
    # A second literal copy of that subtree would be a second author of one
    # shape, and the two would drift the first time only one was corrected.
    q = FIELD_REFS["quarantined-ip-trigger"]
    t = FIELD_REFS["trigger"]
    assert q.children is t.children
    assert q.urn == t.urn == TRIG
    assert q.via == "quarantined-ip-trigger"


def test_every_field_ref_target_is_still_a_self_consistent_node():
    assert all(r.via == f and r.urn.startswith("cmdb/")
               for f, r in FIELD_REFS.items())


# --------------------------------------------------------------------------- #
#  redirect-url — a scalar, and it must stay one                                #
# --------------------------------------------------------------------------- #
def test_redirect_url_reaches_the_write_payload():
    # Asserted through the PLANNED ITEM, not through the sanitiser: the write
    # path goes via an alias, so a filter installed on the alias is invisible to
    # a test that pokes the function it points at today. A dropped redirect-url
    # is invisible in production too — the create still answers 200.
    data = {(WPP, "p1"): [{"name": "p1", "rdt-reason": "enable",
                           "redirect-url": "https://x/d"}]}
    p = clone.ClonePlanner(FakeReader(data), FakeReader({}))
    obj = next(i for i in p.collect(WEB_PROTECTION_PROFILE, "p1")
               if i.urn == WPP)
    assert obj.payload.get("redirect-url") == "https://x/d"
    assert obj.payload.get("rdt-reason") == "enable"


def test_redirect_url_is_not_declared_as_a_reference():
    # It is a <string>. An edge here would plan a phantom object named after a
    # URL on every clone.
    assert "redirect-url" not in FIELD_REFS
    assert not [c for c in WEB_PROTECTION_PROFILE.children
                if c.via in ("redirect-url", "rdt-reason")]
