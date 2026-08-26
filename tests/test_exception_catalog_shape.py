"""Guards for the exception CATALOG (safeguards §124).

Nothing in this product fails when the catalog is wrong. A missing type simply
does not appear in the picker; a wrong enum token is posted to the appliance
and either bounces with a device-side error nobody reads, or is STORED and
never matches. Both read on the Exceptions page as a working carve-out, which
is why every claim below is asserted rather than eyeballed.
"""
from __future__ import annotations

import pytest

from app.services import wpp_exceptions as w


def _opts(exc_type: str, key: str) -> list[str]:
    """Options the FORM will actually render for a field.

    Read through ``fields_for`` rather than off ``FIELD_SPECS``: the form
    prefers the curated WAF engine and only falls back to the static seed, so
    asserting the seed can pass while the picker shows something else.
    """
    for f in w.fields_for(exc_type):
        if f.get("key") == key:
            return [o["value"] if isinstance(o, dict) else o
                    for o in (f.get("options") or [])]
    raise AssertionError("field %r absent from %s" % (key, exc_type))


# --------------------------------------------------------------------- custom
def test_custom_signature_is_a_first_class_signature_type():
    keys = {t["key"]: t for t in w.CATALOG}
    assert "custom_signature_item" in keys
    assert keys["custom_signature_item"]["category"] == w.CAT_SIGNATURE


def test_custom_signature_group_and_condition_are_present():
    keys = {t["key"] for t in w.CATALOG}
    assert {"custom_signature_group_item", "custom_signature_condition_item"} <= keys


def test_direction_uses_device_tokens_not_gui_labels():
    """The guide says "Request"/"Response"; the wire says request/response.

    Storing the label produces a payload the box rejects — and the rejection
    surfaces as a generic device error, not as "you sent the GUI string".
    """
    opts = _opts("custom_signature_item", "type")
    assert opts == ["request", "response"]
    assert "Request" not in opts and "Data Leakage" not in opts


def test_custom_signature_actions_are_sdk_tokens():
    opts = set(_opts("custom_signature_item", "action"))
    # the six the admin guide lists for this object
    assert opts == {"alert", "alert_deny", "alert_erase", "block-period",
                    "only_erase", "send_http_response"}
    # and every one of them is a token the generated SDK catalog knows
    assert opts <= {"alert", "alert_deny", "alert_erase", "block-period",
                    "deny_no_log", "only_erase", "pass", "redirect",
                    "send_http_response"}


def test_threat_weight_is_a_token_scale_not_a_number():
    opts = _opts("custom_signature_item", "threat-weight")
    assert opts == ["low", "informational", "moderate", "substantial",
                    "severe", "critical"]


def test_custom_signature_requires_direction_and_action():
    req = set(w.REQUIRED_FIELDS["custom_signature_item"])
    assert {"name", "type", "action"} <= req
    errs = w.validate_payload("custom_signature_item", {"name": "x"})
    assert any("type" in e for e in errs) and any("action" in e for e in errs)


def test_a_condition_without_a_target_is_rejected():
    """A condition that names no target matches everywhere it is evaluated."""
    errs = w.validate_payload("custom_signature_condition_item",
                              {"operator": "regular-expression"})
    assert any("target" in e for e in errs)


# ---------------------------------------------------------------- orphan type
def test_the_orphan_stored_type_resolves_to_a_real_type():
    """``disabled_signature_item`` is persisted on a live row (id 13) and was
    defined nowhere: ``type_for`` returned None, so it rendered unlabelled and
    skipped validation entirely on the way in."""
    assert w.canonical_type("disabled_signature_item") == "signature_disable_item"
    spec = w.type_for("disabled_signature_item")
    assert spec and spec["label"] == "Disabled Signature"
    assert w.category_for("disabled_signature_item") == w.CAT_SIGNATURE


def test_the_orphan_now_gets_validated_like_its_canonical_type():
    assert w.validate_payload(
        w.canonical_type("disabled_signature_item"), {}) != []


def test_fields_for_resolves_the_alias():
    assert w.fields_for("disabled_signature_item") == \
        w.fields_for("signature_disable_item")


def test_there_is_exactly_one_catalog_entry_per_device_object():
    """The meet-condition had TWO names. Two entries for one device object is
    how a form ends up posting to the endpoint nobody maintained."""
    keys = {t["key"] for t in w.CATALOG}
    assert "signature_group_rule_condition" not in keys
    assert w.canonical_type("signature_group_rule_condition") == \
        "custom_signature_condition_item"


# ------------------------------------------------------------- operator gate
def test_operator_is_coupled_to_the_element_type():
    assert w.operators_for("signature_filter_item", "HTTP_METHOD") == \
        ["INCLUDE", "EXCLUDE"]
    assert w.operators_for("signature_filter_item", "CLIENT_IP") == ["EQ", "NE"]
    for tgt in ("HOST", "URI", "FULL_URL", "PARAMETER", "COOKIE",
                "HTTP_HEADER", "JSON_ELEMENTS"):
        assert w.operators_for("signature_filter_item", tgt) == \
            ["STRING_MATCH", "REGEXP_MATCH"], tgt


def test_the_union_of_all_operators_is_no_longer_offered_to_every_target():
    """The defect: the picker offered all six operations for any element type,
    so HOST + INCLUDE was authorable and savable."""
    everything = {"STRING_MATCH", "REGEXP_MATCH", "EQ", "NE", "INCLUDE", "EXCLUDE"}
    assert set(w.operators_for("signature_filter_item", "HOST")) != everything


def test_a_mismatched_operation_is_rejected_on_save():
    errs = w.validate_payload("signature_filter_item", {
        "signature_id": "010000001", "match-target": "HOST",
        "operator": "INCLUDE"})
    assert errs and "INCLUDE" in errs[0] and "HOST" in errs[0]


def test_the_matching_operation_is_accepted():
    """Control. Without this the gate could reject everything and still pass."""
    assert w.validate_payload("signature_filter_item", {
        "signature_id": "010000001", "match-target": "HOST",
        "operator": "STRING_MATCH"}) == []


def test_the_gate_only_ever_subtracts():
    """It may forbid a combination the guide rules out. It may NOT invent a
    requirement — an absent operator is a separate question owned by
    REQUIRED_FIELDS, and an unknown target means 'this catalog does not know'."""
    assert w._operator_errors("signature_filter_item",
                              {"match-target": "HOST"}) == []
    assert w._operator_errors("signature_filter_item",
                              {"match-target": "SOMETHING_NEW",
                               "operator": "INCLUDE"}) == []
    assert w._operator_errors("no_such_type",
                              {"match-target": "HOST", "operator": "INCLUDE"}) == []


def test_bot_element_types_are_deliberately_ungated():
    """Its element types are human labels and its operator carries no enum;
    the live appliance's subtable was empty so no token set could be read off
    the wire. Guessing would forbid working input."""
    assert "bot_exception_element_item" not in w.OPERATORS_BY_TARGET
    assert w.operators_for("bot_exception_element_item", "Host") == []
    assert w.validate_payload("bot_exception_element_item", {
        "match-target": "Host", "operator": "whatever-the-box-calls-it"}) == []


def test_syntax_exception_keeps_its_own_hyphenated_token():
    """Three element-type conventions live in this catalog (CLIENT_IP /
    FULL-URL / "Client IP"). They were NOT normalised: every matching subtable
    on the live appliance was empty, so which convention each endpoint accepts
    could not be established. This guard pins the status quo so a later session
    changes it on evidence rather than on tidiness."""
    assert "FULL-URL" in w.OPERATORS_BY_TARGET["syntax_exception_item"]
    assert "FULL_URL" in w.OPERATORS_BY_TARGET["signature_filter_item"]


def test_unverified_shapes_are_recorded_rather_than_forgotten():
    assert "custom_signature_condition_item" in w.UNVERIFIED_SHAPES
    assert "bot_exception_element_item" in w.UNVERIFIED_SHAPES
    for note in w.UNVERIFIED_SHAPES.values():
        assert len(note) > 40
