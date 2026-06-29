"""Inject desired-state carve-outs onto a FortiWeb — the device write-path.

A WAF/signature carve-out is always a by-parent sub-table row, so the inject is
uniformly ``ops.create(<sub-table>?mkey=<target>, {"data": payload})`` (the
class-action override is the one ``update``). These tests pin the PURE planner
(registry resolution + path/method) and the apply orchestration in dry-run, so
they need no device. The live round-trip is verified separately against fw2.
"""
from __future__ import annotations

import types

from app.services import exception_inject as inj


# ── registry parity: every catalog type maps to a real endpoint ────────────
def test_every_catalog_type_has_a_resolvable_mapping():
    from app.services import wpp_exceptions as cat
    for t in cat.CATALOG:
        key = t["key"]
        rest = inj.rest_for(key)
        assert rest is not None, f"no EXCEPTION_REST entry for {key}"
        assert inj.resolve_collection(rest.item_logical), \
            f"{key}: item_logical {rest.item_logical!r} not in registry"
        assert inj.resolve_collection(rest.parent_logical), \
            f"{key}: parent_logical {rest.parent_logical!r} not in registry"


# ── planner (pure) ─────────────────────────────────────────────────────────
def test_plan_signature_filter_is_a_scoped_post():
    plan = inj.plan_injection(
        "signature_filter_item",
        {"signature_id": "010000001", "match-target": "URI", "operator": "REGEXP_MATCH"},
        "sig-set-ecom",
    )
    assert plan["status"] == "ready"
    assert plan["method"] == "POST"
    assert plan["endpoint"].endswith("waf/signature/filter_list?mkey=sig-set-ecom")
    assert plan["body"] == {"data": {"signature_id": "010000001",
                                     "match-target": "URI", "operator": "REGEXP_MATCH"}}
    assert plan["inline"] is False


def test_plan_container_exception_targets_the_by_parent_list():
    plan = inj.plan_injection(
        "http_constraint_exception_item",
        {"host-status": "enable", "host": "shop.example.com"},
        "exc-shop",
    )
    assert plan["status"] == "ready"
    assert plan["endpoint"].endswith(
        "waf/http-constraints-exceptions/http_constraints-exception-list?mkey=exc-shop")
    assert plan["container_logical"] == "http_constraint_exception"
    assert plan["inline"] is False


def test_plan_inline_type_targets_the_subpolicy_itself():
    plan = inj.plan_injection(
        "cookie_security_exception_item", {"cookie-name": "SESSIONID"}, "cookie-pol")
    assert plan["status"] == "ready"
    assert plan["endpoint"].endswith(
        "waf/cookie-security/cookie-security-exception-list?mkey=cookie-pol")
    assert plan["inline"] is True


def test_plan_class_action_is_a_keyed_update():
    plan = inj.plan_injection(
        "signature_class_action",
        {"main_class_id": "10000000", "action": "alert_deny"},
        "sig-set-ecom",
    )
    assert plan["status"] == "ready"
    assert plan["method"] == "PUT"
    assert plan["endpoint"].endswith(
        "waf/signature/main_class_list?mkey=sig-set-ecom&sub_mkey=10000000")


def test_plan_without_target_is_no_target():
    plan = inj.plan_injection("signature_filter_item", {"signature_id": "1"}, "")
    assert plan["status"] == "no-target"


def test_plan_update_without_key_field_is_no_target():
    plan = inj.plan_injection("signature_class_action", {"action": "alert"}, "sig-set")
    assert plan["status"] == "no-target"


def test_plan_unknown_type_is_no_endpoint():
    plan = inj.plan_injection("does_not_exist", {}, "x")
    assert plan["status"] == "no-endpoint"


# ── apply orchestration (dry-run, real FortiWebOps, no device) ─────────────
def _ops():
    from app.services.fortiweb_ops import FortiWebOps
    # dry-run preview never touches the device or the DB, so a stub appliance
    # with just an ``id`` is enough to exercise the real write layer.
    return FortiWebOps(types.SimpleNamespace(id=1))


def test_apply_signature_filter_dry_run_records_the_post():
    res = inj.apply_injection(
        _ops(), exc_type="signature_filter_item",
        payload={"signature_id": "010000001", "match-target": "URI"},
        target="sig-set-ecom", dry_run=True)
    assert res["ok"] is True and res["dry_run"] is True
    entry = [s for s in res["steps"] if s["step"] == "entry"][0]
    assert entry["request"]["method"] == "POST"
    assert entry["request"]["path"].endswith("waf/signature/filter_list?mkey=sig-set-ecom")
    assert entry["request"]["body"] == {"data": {"signature_id": "010000001",
                                                  "match-target": "URI"}}


def test_apply_class_action_dry_run_is_a_put():
    res = inj.apply_injection(
        _ops(), exc_type="signature_class_action",
        payload={"main_class_id": "10000000", "action": "alert_deny"},
        target="sig-set-ecom", dry_run=True)
    entry = [s for s in res["steps"] if s["step"] == "entry"][0]
    assert entry["request"]["method"] == "PUT"
    assert "sub_mkey=10000000" in entry["request"]["path"]


def test_apply_with_create_container_emits_two_steps():
    res = inj.apply_injection(
        _ops(), exc_type="http_constraint_exception_item",
        payload={"host-status": "enable"}, target="exc-shop",
        dry_run=True, create_container=True)
    steps = {s["step"] for s in res["steps"]}
    assert steps == {"container", "entry"}
    container = [s for s in res["steps"] if s["step"] == "container"][0]
    assert container["request"]["method"] == "POST"
    assert container["request"]["path"].endswith("waf/http-constraints-exceptions")
    assert container["request"]["body"] == {"data": {"name": "exc-shop"}}


def test_apply_no_target_does_not_write():
    res = inj.apply_injection(
        _ops(), exc_type="signature_filter_item",
        payload={"signature_id": "1"}, target="", dry_run=True)
    assert res["ok"] is False
    assert res["steps"] == []
    assert res["plan"]["status"] == "no-target"
