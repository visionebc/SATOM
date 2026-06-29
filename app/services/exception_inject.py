"""Inject authored carve-outs onto a FortiWeb — the desired-state → device step.

Authoring (``wpp_exceptions``) records a carve-out as desired-state in the
manager DB; pushing it onto a box is THIS separate, explicit step (dry-run by
default). A WAF/signature carve-out is always a **by-parent sub-table row**, so
the write is uniformly::

    ops.create(<sub-table>?mkey=<target>, {"data": payload})

(the class-action override is the one ``update``, keyed by ``main_class_id``).

``EXCEPTION_REST`` maps each catalog ``exc_type`` → the registry LOGICAL names of
the row sub-table (``item_logical``) and of its parent object (``parent_logical``
— a dedicated *named container*, an *inline* sub-policy, or the signature SET).
Both are resolved against the live registry, so a renamed/missing endpoint shows
up as ``no-endpoint`` instead of a blind POST. The **target** (parent object
name) is a LIVE box concept chosen at inject time (``candidate_targets`` lists
them off the device) — never stored in the desired-state DB.

Pure planner + duck-typed apply (the view supplies a :class:`FortiWebOps`), so
the whole thing is headless-testable; mirrors the desktop ``exception_inject``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..registry import loader
from . import objform


@dataclass(frozen=True)
class ExcRest:
    """How one carve-out type is written to the box.

    * ``item_logical``   – registry key of the by-parent sub-table the row goes in
    * ``parent_logical`` – registry key of the parent object (container / inline
      sub-policy / signature set) whose name is the write ``mkey``
    * ``inline``         – True = the parent is an existing sub-policy/rule (the
      entry lives on it); False = a dedicated named exception container
    * ``op``             – ``create`` (default) or ``update`` (class-action)
    * ``key_field``      – for ``update``: payload field identifying the row → sub_mkey
    * ``bind_logical`` / ``bind_field`` – the WPP sub-policy + field that NAMES a
      freshly-created container (best-effort auto-bind), where one cleanly exists
    """
    item_logical: str
    parent_logical: str
    inline: bool
    op: str = "create"
    key_field: str = ""
    bind_logical: str = ""
    bind_field: str = ""


# A signature SET / custom rule already exists on the box — never auto-create it.
_NO_CONTAINER = {"signature", "signature_group_rule"}


EXCEPTION_REST: dict[str, ExcRest] = {
    # ── WAF exceptions ──────────────────────────────────────────────────────
    "http_constraint_exception_item": ExcRest(
        "http_constraint_exception_item", "http_constraint_exception", False),
    "allow_method_exception_item": ExcRest(
        "allow_method_exception_item", "allow_method_exception", False,
        bind_logical="allow_method_policy", bind_field="allow-method-exception"),
    "geo_ip_exception_member_item": ExcRest(
        "geo_ip_exception_member_item", "geo_ip_exception", False),
    "syntax_exception_item": ExcRest(
        "syntax_based_detection_exception_item", "syntax_based_detection", True),
    "bot_exception_element_item": ExcRest(
        "bot_exception_policy_element_item", "bot_detection", False,
        bind_logical="bot_mitigation_policy", bind_field="exception"),
    "http_header_security_exception_item": ExcRest(
        "http_header_security_exception_item", "http_header_security_exception", False),
    "cookie_security_exception_item": ExcRest(
        "cookie_security_exception_item", "cookie_security", True),
    "url_enc_exc_item": ExcRest(
        "url_encryption_rule_exception_item", "url_encryption_rule", True),
    "link_cloak_exc_item": ExcRest(
        "link_cloaking_rule_exception_item", "link_cloaking_rule", True),
    "file_exception_item": ExcRest(
        "fiel_exception_policy_item", "fiel_exception_policy", False),
    # ── Signature carve-outs (target = the signature SET, or the custom rule) ─
    "signature_filter_item": ExcRest("signature_filter_item", "signature", False),
    "signature_disable_item": ExcRest("signature_disable_item", "signature", False),
    "signature_alert_only_item": ExcRest("signature_alert_only_item", "signature", False),
    "signature_subclass_disable_item": ExcRest(
        "signature_subclass_disable_item", "signature", False),
    "signature_class_action": ExcRest(
        "signature_class_item", "signature", False, op="update", key_field="main_class_id"),
    "signature_group_rule_condition": ExcRest(
        "signature_group_rule_condition", "signature_group_rule", False),
}


def rest_for(exc_type: str) -> ExcRest | None:
    return EXCEPTION_REST.get(exc_type)


def resolve_collection(logical: str) -> str | None:
    """Registry logical name → bare cmdb collection (``None`` if unknown)."""
    urn = loader.load_registry().get(logical)
    return objform.collection_of(urn) if urn else None


def supports_auto_bind(exc_type: str) -> bool:
    rest = EXCEPTION_REST.get(exc_type)
    return bool(rest and rest.bind_logical and rest.bind_field)


# --------------------------------------------------------------------------- #
#  Planner (pure)                                                              #
# --------------------------------------------------------------------------- #
def _plan(status: str, *, error: str = "", **extra) -> dict:
    base = {"status": status, "method": "", "endpoint": "", "collection": "",
            "target": "", "inline": False, "container_logical": "",
            "body": None, "error": error}
    base.update(extra)
    return base


def plan_injection(exc_type: str, payload: dict, target: str) -> dict:
    """Resolve the single write that pushes *payload* onto *target*.

    Returns a plan dict with ``status`` ∈ ``ready`` / ``no-endpoint`` (no
    registry mapping) / ``no-target`` (no parent object chosen, or an update
    missing its key field). ``endpoint`` is the full scoped REST path.
    """
    rest = EXCEPTION_REST.get(exc_type)
    if rest is None:
        return _plan("no-endpoint", error=f"no inject mapping for {exc_type!r}")
    coll = resolve_collection(rest.item_logical)
    if not coll:
        return _plan("no-endpoint",
                     error=f"registry has no endpoint {rest.item_logical!r}")
    payload = dict(payload or {})
    target = (target or "").strip()
    if not target:
        return _plan("no-target", error="a target object must be chosen on the device",
                     collection=coll, inline=rest.inline,
                     container_logical=rest.parent_logical)

    if rest.op == "update":
        sub = str(payload.get(rest.key_field, "")).strip()
        if not sub:
            return _plan("no-target", error=f"{rest.key_field} is required", collection=coll)
        endpoint, method = objform.scoped_path(coll, target, sub), "PUT"
    else:
        endpoint, method = objform.scoped_path(coll, target), "POST"

    return _plan("ready", method=method, endpoint=endpoint, collection=coll,
                 target=target, inline=rest.inline,
                 container_logical=rest.parent_logical, body={"data": payload})


# --------------------------------------------------------------------------- #
#  Apply (duck-typed on FortiWebOps; dry-run default)                          #
# --------------------------------------------------------------------------- #
def _step(name: str, res) -> dict:
    return {"step": name, "ok": bool(getattr(res, "ok", res.get("ok"))),
            "request": res.get("request"), "error": res.get("error", "")}


def apply_injection(ops, *, exc_type: str, payload: dict, target: str,
                    dry_run: bool = True, create_container: bool = False) -> dict:
    """Push one carve-out via *ops* (a :class:`FortiWebOps`). Dry-run by default.

    Optionally creates the named container first (``create_container``) for the
    dedicated-container types. Never raises — a non-``ready`` plan returns
    ``ok=False`` with no writes.
    """
    plan = plan_injection(exc_type, payload, target)
    if plan["status"] != "ready":
        return {"ok": False, "plan": plan, "steps": [], "dry_run": dry_run}

    rest = EXCEPTION_REST[exc_type]
    steps: list[dict] = []

    if create_container and not rest.inline and rest.parent_logical not in _NO_CONTAINER:
        pcoll = resolve_collection(rest.parent_logical)
        if pcoll:
            cres = ops.create(objform.rest_path(pcoll), {"data": {"name": target}},
                              dry_run=dry_run)
            steps.append(_step("container", cres))

    body = plan["body"]
    if plan["method"] == "PUT":
        wres = ops.update(plan["endpoint"], "", body, dry_run=dry_run)
    else:
        wres = ops.create(plan["endpoint"], body, dry_run=dry_run)
    steps.append(_step("entry", wres))

    return {"ok": all(s["ok"] for s in steps), "plan": plan, "steps": steps,
            "dry_run": dry_run}


# --------------------------------------------------------------------------- #
#  Candidate targets (off the device)                                          #
# --------------------------------------------------------------------------- #
def candidate_targets(client, exc_type: str) -> list[str]:
    """Names of the objects a carve-out of *exc_type* can target, off the box.

    Container/inline → that object's collection; signature carve-outs → the
    signature SETs (a WPP ``signature-rule``). Best-effort: a dead device or an
    unmapped type yields ``[]``.
    """
    rest = EXCEPTION_REST.get(exc_type)
    if rest is None:
        return []
    coll = resolve_collection(rest.parent_logical)
    if not coll:
        return []
    try:
        return sorted(client.cmdb_names(coll))
    except Exception:  # noqa: BLE001 — dead device → no candidates
        return []


__all__ = [
    "ExcRest", "EXCEPTION_REST", "rest_for", "resolve_collection",
    "supports_auto_bind", "plan_injection", "apply_injection", "candidate_targets",
]
