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

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from ..registry import loader
from . import objform

#: FortiWeb's "A duplicate entry has already existed." Matched on the CODE, not
#: on the sentence: the message is the localisable half of the answer and the
#: code is the stable one.
DUPLICATE_ERRCODE = "-5"

_ERRCODE_RE = re.compile(r"errcode\s+(-?\d+)")


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
    * ``top_level``      – True = the object is NOT a by-parent sub-table row but
      a named object of its own (``waf/custom-protection-rule``). There is no
      parent mkey to scope the write to, so demanding a target would either
      block the push or scope it to a path the box answers with the WRONG
      object.
    """
    item_logical: str
    parent_logical: str
    inline: bool
    op: str = "create"
    key_field: str = ""
    bind_logical: str = ""
    bind_field: str = ""
    top_level: bool = False


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
    # ── Custom signatures ──────────────────────────────────────────────────
    # The chain, read off a live 7.6.8 box and not from the admin guide:
    #   waf/custom-protection-rule                 the signature (TOP-LEVEL)
    #     .../meet-condition                       its AND-ed conditions
    #   waf/custom-protection-group/type-list      bundles rules into a group
    #   waf/signature.custom-protection-group      binds the group to a policy
    # so a custom signature is reached through the SIGNATURE POLICY, never
    # through the Web Protection Profile — which is why nothing in the WPP-
    # shaped half of this table could express it.
    "custom_signature_item": ExcRest(
        "signature_group_rule", "", False, top_level=True),
    "custom_signature_condition_item": ExcRest(
        "signature_group_rule_condition", "signature_group_rule", False),
    "custom_signature_group_item": ExcRest(
        "signature_group_type_item", "signature_group", False),
}


def rest_for(exc_type: str) -> ExcRest | None:
    """Mapping for *exc_type*, resolved through the catalog's ALIASES first.

    A carve-out stored under a retired key (``signature_group_rule_condition``
    before Tanda 0 folded it into ``custom_signature_condition_item``) is still
    on the box and still in the DB. Looking it up raw would answer ``None`` and
    render it un-pushable — the record would silently lose a capability it had
    the day it was authored.
    """
    from . import wpp_exceptions as _cat
    return (EXCEPTION_REST.get(exc_type)
            or EXCEPTION_REST.get(_cat.canonical_type(exc_type)))


def resolve_collection(logical: str) -> str | None:
    """Registry logical name → bare cmdb collection (``None`` if unknown)."""
    urn = loader.load_registry().get(logical)
    return objform.collection_of(urn) if urn else None


def supports_auto_bind(exc_type: str) -> bool:
    rest = rest_for(exc_type)
    return bool(rest and rest.bind_logical and rest.bind_field)


def needs_target(exc_type: str) -> bool:
    """Does pushing this type require choosing a parent object on the box?

    False for top-level objects. The inject UI asks this instead of inferring
    it from an empty candidate list, because "no candidates" is also what an
    unreachable device produces and the two need different words.
    """
    rest = rest_for(exc_type)
    return bool(rest and not rest.top_level)


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
    missing its key field) / ``invalid`` (the catalogue refuses the body).
    ``endpoint`` is the full scoped REST path.

    ``invalid`` closes a hole the deploy work opened: the catalogue's required
    fields and enums were enforced by the AUTHORING FORM only, so every other
    route to a write -- a push to a second appliance, a restored version, a
    row authored before a token was corrected -- reached the device
    unchecked and came back as a bare ``-651``. Refusing here costs one
    dictionary lookup and names the field.
    """
    rest = rest_for(exc_type)
    if rest is None:
        return _plan("no-endpoint", error=f"no inject mapping for {exc_type!r}")
    coll = resolve_collection(rest.item_logical)
    if not coll:
        return _plan("no-endpoint",
                     error=f"registry has no endpoint {rest.item_logical!r}")
    payload = dict(payload or {})
    target = (target or "").strip()
    from . import wpp_exceptions as _cat
    # Runs at the READY boundary, never earlier: ``no-target`` and
    # ``no-endpoint`` describe a plan that cannot be built at all, and a body
    # complaint must not preempt them -- an operator told "x is required"
    # when the real problem is that no target was picked goes looking in the
    # wrong place.
    def _checked(plan):
        bad = _cat.validate_for_wire(exc_type, payload)
        if not bad:
            return plan
        return _plan("invalid", error="; ".join(bad), collection=coll,
                     inline=rest.inline, container_logical=rest.parent_logical)
    if rest.top_level:
        # A named object of its own: the collection path IS the write target.
        # Any target the caller passed is IGNORED rather than appended — an
        # appended one produces a path the box answers with a different object.
        return _checked(_plan(
            "ready", method="POST", endpoint=objform.rest_path(coll),
            collection=coll, target="", inline=False,
            container_logical="", body={"data": payload}))
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

    return _checked(_plan(
        "ready", method=method, endpoint=endpoint, collection=coll,
        target=target, inline=rest.inline,
        container_logical=rest.parent_logical, body={"data": payload}))


# --------------------------------------------------------------------------- #
#  Apply (duck-typed on FortiWebOps; dry-run default)                          #
# --------------------------------------------------------------------------- #
def errcode_of(error: Any) -> str:
    """The FortiWeb ``errcode`` inside an ``OpResult`` error string, or ``''``.

    ``fortiweb_ops`` renders it two ways — ``"errcode -5: …"`` on an HTTP 200
    logical error and ``"HTTP 500 — errcode -5: …"`` when the box also sets a
    status — so both have to parse to the same code.
    """
    m = _ERRCODE_RE.search(str(error or ""))
    return m.group(1) if m else ""


def is_duplicate(res) -> bool:
    """Did this write fail ONLY because the object/row is already there?"""
    if getattr(res, "ok", None) or (isinstance(res, dict) and res.get("ok")):
        return False
    return errcode_of(res.get("error", "") if hasattr(res, "get") else "") \
        == DUPLICATE_ERRCODE


def _step(name: str, res, *, note: str = "") -> dict:
    """One write in the plan, with duplicates told apart from rejections.

    A ``-5`` is the box saying "this already exists", which is the DESIRED state
    — not a refusal. Reporting it as a failed write is what put "The appliance
    rejected the write" on screen for a carve-out that had just landed, and sent
    the operator back to press the button again (2026-08-08, allow-method
    exception on fortiweb08: the container step ``-5``'d on the first try
    because ``am-exc`` already existed, ``ok = all(steps)`` dragged the whole
    result down with it, and the entry it had genuinely just created was
    reported as rejected).
    """
    ok = bool(getattr(res, "ok", res.get("ok")))
    dup = not ok and is_duplicate(res)
    if dup:
        ok, note = True, note or "already-present"
    return {"step": name, "ok": ok, "duplicate": dup, "note": note,
            "request": res.get("request"), "error": res.get("error", "")}


def container_exists(ops, pcoll: str, target: str) -> bool | None:
    """Is the named container already on the box? ``None`` = could not tell.

    The checkbox says "create the container if it does not exist" and the code
    POSTed unconditionally, so the answer was always the device's ``-5``. Three
    states, not two: an unreadable box must not be reported as "absent", because
    that turns a read failure into a create attempt.
    """
    try:
        rows = ops.client.get(objform.rest_path(pcoll)
                              + "?mkey=%s" % quote(str(target), safe="")).json()
    except Exception:  # noqa: BLE001 — unreadable box is not "absent"
        return None
    res = rows.get("results") if isinstance(rows, dict) else None
    if isinstance(res, dict):
        return res.get("errcode") in (None, 0)
    if isinstance(res, list):
        return any(isinstance(r, dict) and str(r.get("name", "")) == str(target)
                   for r in res)
    return None


def apply_injection(ops, *, exc_type: str, payload: dict, target: str,
                    dry_run: bool = True, create_container: bool = False) -> dict:
    """Push one carve-out via *ops* (a :class:`FortiWebOps`). Dry-run by default.

    Optionally creates the named container first (``create_container``) for the
    dedicated-container types — and only when it is genuinely missing, which is
    what the option has always claimed to do. The probe runs on the REAL path
    only: ``dry_run`` is contractually device-free in ``FortiWebOps``, and a
    preview that quietly opened a session would break that guarantee for every
    other caller.

    Never raises — a non-``ready`` plan returns ``ok=False`` with no writes.
    ``already_present`` is True when the box reported the entry was already
    there, so a caller can say "nothing to do" instead of either "created" or
    "rejected", both of which would be false.
    """
    plan = plan_injection(exc_type, payload, target)
    if plan["status"] != "ready":
        return {"ok": False, "plan": plan, "steps": [], "dry_run": dry_run,
                "already_present": False}

    rest = rest_for(exc_type)
    steps: list[dict] = []

    if create_container and not rest.inline and rest.parent_logical not in _NO_CONTAINER:
        pcoll = resolve_collection(rest.parent_logical)
        if pcoll:
            present = None if dry_run else container_exists(ops, pcoll, target)
            if present is True:
                steps.append({"step": "container", "ok": True, "duplicate": False,
                              "note": "already-present", "request": None, "error": ""})
            else:
                cres = ops.create(objform.rest_path(pcoll), {"data": {"name": target}},
                                  dry_run=dry_run)
                steps.append(_step("container", cres))

    body = plan["body"]
    if plan["method"] == "PUT":
        wres = ops.update(plan["endpoint"], "", body, dry_run=dry_run)
    else:
        wres = ops.create(plan["endpoint"], body, dry_run=dry_run)
    steps.append(_step("entry", wres))

    entry = steps[-1]
    return {"ok": all(s["ok"] for s in steps), "plan": plan, "steps": steps,
            "dry_run": dry_run,
            "already_present": bool(entry.get("duplicate"))}


# --------------------------------------------------------------------------- #
#  Candidate targets (off the device)                                          #
# --------------------------------------------------------------------------- #
def candidate_targets(client, exc_type: str) -> list[str]:
    """Names of the objects a carve-out of *exc_type* can target, off the box.

    Container/inline → that object's collection; signature carve-outs → the
    signature SETs (a WPP ``signature-rule``). Best-effort: a dead device or an
    unmapped type yields ``[]``.
    """
    rest = rest_for(exc_type)
    if rest is None or rest.top_level:
        # top-level object -> there is no parent to pick. Returning [] here and
        # letting the view say "no target needed" is the honest answer; an
        # empty picker with no explanation reads as an unreachable device.
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
    "needs_target",
    "DUPLICATE_ERRCODE", "errcode_of", "is_duplicate", "container_exists",
]
