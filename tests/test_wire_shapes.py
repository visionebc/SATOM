"""The custom-signature catalogue against the WIRE, and the write-path gate.

Every fact asserted here was read off a live FortiWeb 7.6.8 (fortiweb13) on
2026-08-27 -- ``config waf custom-protection-rule`` / ``config meet-condition``
/ ``set <field> ?`` for the enums, and real REST writes for the behaviour.
None of it comes from the admin guide, which is where the previous shape came
from and where it was wrong.

Why these are guards and not comments: a catalogue that disagrees with the
device fails SILENTLY in the direction that matters. The old shape was
authorable in the UI and unpushable at the appliance, and the only symptom was
an opaque ``-651`` at deploy time -- long after the operator believed the
carve-out existed.
"""
import pytest

from app.services import wpp_exceptions as w
from app.services import exception_inject as inj
from app.services import waf_artifacts as WA


def _opts(exc_type, key):
    for f in w.FIELD_SPECS[exc_type]:
        if f["key"] == key:
            return list(f.get("options") or [])
    raise AssertionError("no field %r on %r" % (key, exc_type))


# ------------------------------------------------------------------ the parent
def test_custom_signature_actions_are_the_union_of_both_directions():
    """``set action ?`` answers differently per Direction: 7 for a request
    rule, 9 for a response rule. The catalogue carries the union and gates the
    difference, because a request-only list would delete the erase signatures
    the admin guide leads with, and a flat union would let a request rule
    claim an action the box refuses."""
    assert set(_opts("custom_signature_item", "action")) == {
        "alert", "alert_deny", "alert_erase", "block-period",
        "client-id-block-period", "deny_no_log", "only_erase", "redirect",
        "send_http_response"}


def test_the_erase_actions_are_response_only():
    assert w.RESPONSE_ONLY_ACTIONS == {"alert_erase", "only_erase"}
    bad = w.validate_for_wire("custom_signature_item",
                              {"name": "x", "type": "request", "action": "alert_erase"})
    assert bad and "response" in bad[0]
    assert w.validate_for_wire(
        "custom_signature_item",
        {"name": "x", "type": "response", "action": "alert_erase"}) == []


def test_severity_carries_the_token_not_the_description():
    """The device prints "Informative" as the DESCRIPTION of the token
    ``Info``. Storing the description is a payload the box refuses."""
    assert _opts("custom_signature_item", "severity") == [
        "Info", "Low", "Medium", "High"]


# --------------------------------------------------------------- the condition
def test_condition_keys_are_the_ones_the_device_names():
    keys = [f["key"] for f in w.FIELD_SPECS["custom_signature_condition_item"]]
    assert set(keys) == {"operator", "case-sensitive", "expression",
                         "request-target", "response-target", "threshold"}
    # 'target' was ONE field in the old shape and the device has two, split by
    # the parent rule's Direction. Collapsing them is how a response rule ends
    # up carrying a request-only target that can never match.
    assert "target" not in keys


def test_operator_tokens_are_the_two_letter_codes():
    assert set(_opts("custom_signature_condition_item", "operator")) == {
        "EQ", "NE", "GT", "LT", "RE"}


def test_the_two_target_lists_do_not_overlap_and_match_the_device():
    req = set(_opts("custom_signature_condition_item", "request-target"))
    res = set(_opts("custom_signature_condition_item", "response-target"))
    assert res == {"RESPONSE_BODY", "RESPONSE_HEADER"}
    assert len(req) == 12 and "REQUEST_RAW_URI" in req and "ARGS_NAMES" in req
    assert not (req & res)


def test_expression_is_the_required_key_not_the_target():
    """``end`` without it answers "attribute 'expression' must be set". The
    device marks nothing else mandatory on this subtable."""
    req = set(w.REQUIRED_FIELDS["custom_signature_condition_item"])
    assert "expression" in req and "target" not in req


# ------------------------------------------------- a target field is a LIST
def test_a_multi_target_condition_is_accepted():
    """The GUI calls it "Available Target / Selected Target" and the device
    stores what you send verbatim -- ``"REQUEST_URI REQUEST_BODY "``, trailing
    space and all. Validating it as one token rejects the normal case."""
    assert "request-target" in w.SPACE_LIST_FIELDS
    assert w.validate_for_wire("custom_signature_condition_item", {
        "operator": "RE", "expression": "x",
        "request-target": "REQUEST_URI REQUEST_BODY"}) == []


def test_one_bad_token_in_the_list_still_refuses():
    bad = w.validate_for_wire("custom_signature_condition_item", {
        "operator": "RE", "expression": "x",
        "request-target": "REQUEST_URI NOPE"})
    assert bad and "NOPE" in bad[0]


# ------------------------------------------------------------ the write gate
def test_the_write_path_refuses_a_token_the_device_refuses():
    plan = inj.plan_injection("custom_signature_condition_item",
                              {"operator": "regular-expression", "expression": "x"},
                              "sig")
    assert plan["status"] == "invalid"
    assert not plan.get("body")


def test_an_invalid_body_never_preempts_no_target():
    """``no-target`` describes a plan that cannot be built at all. An operator
    told "'x' is not valid" when the real problem is that no target was picked
    goes looking in the wrong place."""
    plan = inj.plan_injection("custom_signature_condition_item",
                              {"operator": "NOPE"}, "")
    assert plan["status"] == "no-target"


def test_the_write_gate_does_not_enforce_required_fields():
    """Deliberately narrower than ``validate_payload``: required/format rules
    are this catalogue's judgement, so enforcing them at deploy would convert
    stored, working carve-outs authored before a rule existed into errors on
    the push to a second appliance.

    Asserted through ``plan_injection`` and not on the two catalogue functions
    alone: which one the write path CALLS is the whole decision, and a guard
    that only compares the functions passes happily while the write path uses
    the wrong one. (A mutation that swapped them survived exactly that guard.)
    """
    assert w.validate_for_wire("signature_filter_item", {"signature_id": "1"}) == []
    assert w.validate_payload("signature_filter_item", {"signature_id": "1"}) != []
    plan = inj.plan_injection("signature_filter_item", {"signature_id": "1"},
                              "sig-set")
    assert plan["status"] == "ready", (
        "a body the catalogue merely dislikes must still deploy — only what "
        "the DEVICE refuses may block a write")


def test_a_valid_custom_signature_still_plans_ready():
    plan = inj.plan_injection("custom_signature_item", {
        "name": "n", "type": "request", "action": "alert_deny",
        "severity": "High", "threat-weight": "severe"}, "")
    assert plan["status"] == "ready" and plan["method"] == "POST"


# --------------------------------------------------------- file-name rules
@pytest.mark.parametrize("kind,name,warns", [
    # MEASURED: OpenAPI REQUIRES an extension, JSON Schema forbids one, and
    # the other four kinds accept any name. Two opposite rules is exactly why
    # this is a table and not an ``if``.
    ("openapi", "spec.yaml", False), ("openapi", "spec.json", False),
    ("openapi", "spec", True), ("openapi", "spec.yml", True),
    ("json_schema", "sch", False), ("json_schema", "sch.json", True),
    ("json_schema", "sch.txt", True), ("json_schema", "sch.schema", True),
    ("xml_schema", "s.xsd", False), ("xml_schema", "s", False),
    ("xml_schema", "s.txt", False), ("xml_dtd", "d", False),
    ("wsdl", "w.wsdl", False), ("grpc_idl", "i.proto", False),
])
def test_name_warning_matches_the_measured_device(kind, name, warns):
    assert bool(WA.name_warning(kind, name)) is warns


def test_the_json_schema_rule_names_the_errcode_it_was_measured_from():
    msg = WA.name_warning("json_schema", "sch.json")
    assert "-61" in msg and "no extension" in msg.lower()

# ------------------------------------------------------- one rule, one handler
def test_no_url_rule_is_served_by_two_handlers(app):
    """A stray decorator is invisible in review and silent at runtime.

    ``@bp.route(...)`` with no function under it does not fail -- it STACKS
    onto the next ``def``, so that view answers a second URL nobody meant to
    give it. On 2026-08-27 a leftover ``@bp.route('/<id>/detect')`` sat above
    ``clone_for_policy``: posting to the detect endpoint ran the
    clone-and-rebind planner and returned a body with no ``found`` key, so the
    detect button had been quietly dead while looking wired up.

    Checked over the whole url_map rather than over the one route that broke,
    because the mistake is a typing accident and the next one will be
    somewhere else entirely. Flask's own duplicate-endpoint error does not
    catch it: the two rules have DIFFERENT urls and the SAME endpoint, which
    is legal and occasionally intended -- so the guard allows a rule set that
    an endpoint declares deliberately (aliases with a shared prefix) and
    refuses the shape a stray decorator produces: one endpoint answering two
    unrelated paths, each of which also exists as another endpoint's own rule.
    """
    by_endpoint: dict[str, set[str]] = {}
    for rule in app.url_map.iter_rules():
        by_endpoint.setdefault(rule.endpoint, set()).add(str(rule.rule))
    owned = {r for rules in by_endpoint.values() if len(rules) == 1 for r in rules}
    stolen = []
    for endpoint, rules in by_endpoint.items():
        if len(rules) < 2:
            continue
        # A path that is ALSO some other endpoint's only rule is not an alias,
        # it is a hijack: two handlers claim it and one of them silently wins.
        for r in rules:
            if r in owned:
                stolen.append((endpoint, r))
    assert not stolen, (
        "these endpoints answer a URL that belongs to another view -- look "
        "for a @route decorator with no function under it: %r" % stolen)
