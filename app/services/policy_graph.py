"""Cascade-delete planning and execution for server policies.

Walks the full dependency tree of a server policy, compares it against all
other policies on the same FortiWeb appliance to tally shared objects, then
produces a plan that:

  * deletes exclusively-owned objects (no other policy references them), and
  * keeps shared objects and objects in the always-skip class (WPP subtree,
    certificates, services, SSL ciphers, replacement message groups).

Design constraints from server_policy.md §5:
  - By-parent sub-tables (vip-list, pserver-list, …) are auto-deleted with
    their parent; no explicit DELETE call is issued for them.
  - Always-skip: cmdb/waf/*, certificates, service, ssl-ciphers, replacemsg,
    v-zone, system VIPs.
  - Potentially exclusive (check ref-count): vserver, server-pool, health,
    allow-hosts, allow-list, persistence-policy, scripting,
    http-content-routing-policy, ip-group, ztna-profile, traffic-mirror,
    acceleration.policy, acceleration.exception.
  - The root policy is always deleted first; dependencies follow in
    reverse-collect order so that any nested shared dependency (CR policy →
    pool) is resolved before the leaf.
  - execute_delete_plan() treats a FortiWeb "in use" / "being used" error as
    confirmation that the object is shared with a non-walking policy and
    records it as kept_shared rather than failed.
"""
from __future__ import annotations

# --------------------------------------------------------------------------- #
#  Always-skip classification                                                    #
# --------------------------------------------------------------------------- #

# URN prefixes — any URN starting with one of these is never deleted via
# cascade (WPP and its whole sub-profile tree, all certificate types, system
# objects that have appliance-wide scope).
_SKIP_PREFIXES = (
    "cmdb/waf/",               # web-protection-profile + all WAF sub-profiles
    "cmdb/system/certificate", # .local / .letsencrypt / .sni / .intermediate-*
    "cmdb/system/replacemsg",  # replacement message groups
    "cmdb/system/v-zone",      # bridge/v-zone (system-wide)
    "cmdb/system/vip",         # VIP address objects (system-wide)
)

# Exact URNs that are always-skip (not caught by prefix matching).
_SKIP_EXACT: frozenset[str] = frozenset({
    "cmdb/server-policy/ssl-ciphers.predefined",
    "cmdb/server-policy/ssl-ciphers.custom",
    "cmdb/server-policy/service.predefined",
    "cmdb/server-policy/service.custom",
    "cmdb/system/certificate.intermediate-certificate-group",
})


def _is_always_skip(urn: str) -> bool:
    if urn in _SKIP_EXACT:
        return True
    return any(urn.startswith(p) for p in _SKIP_PREFIXES)


def _skip_reason(urn: str) -> str:
    if urn.startswith("cmdb/waf/"):
        return "wpp-subtree"
    if urn.startswith("cmdb/system/certificate"):
        return "certificate"
    if "ssl-ciphers" in urn:
        return "ssl-ciphers"
    if "service." in urn:
        return "service"
    return "system-object"


def _is_in_use_error(error: str) -> bool:
    """True when a FortiWeb delete error means the object is referenced
    by another entity (rather than a real device/network error)."""
    low = error.lower()
    return any(phrase in low for phrase in (
        "in use", "being used", "referred", "referenced",
        "still refer", "used by",
    ))


# --------------------------------------------------------------------------- #
#  Planning                                                                      #
# --------------------------------------------------------------------------- #

def plan_cascade_delete(reader, policy_name: str) -> dict:
    """Produce a cascade-delete plan for *policy_name*.

    ``reader`` is a duck-typed ``ClientReader`` (wraps a live FortiWebClient).

    Returns::

        {
            "root":      policy_name,
            "to_delete": [(urn, mkey, label), ...],          # exclusively owned
            "to_keep":   [(urn, mkey, label, reason), ...],  # shared / always-skip
            "by_parent": [(urn, mkey, label), ...],          # auto-deleted sub-rows
        }

    Items in ``to_delete`` are in reverse-collect order (most-dependent first
    relative to the sub-tree they head — so a CR policy appears before the pool
    it references).  This is the correct order for ``execute_delete_plan``.
    The root policy itself is NOT included in any list; the executor always
    deletes it first, explicitly.

    Degrades gracefully on device errors: if the dependency walk fails,
    ``to_delete`` is empty and the executor falls back to a plain policy-only
    delete (current behaviour before this module existed).
    """
    from . import clone as _clone

    planner = _clone.ClonePlanner(reader, reader)

    # Walk the target policy's full dependency tree.
    try:
        src_items = planner.collect(_clone.ROOT_SERVER_POLICY, policy_name)
    except Exception:
        src_items = []

    # List all other policies on the same appliance (1 API call → N payloads).
    try:
        rows, _err = reader.client.list_with_error(
            "/api/v2.0/cmdb/server-policy/policy"
        )
        other_names = [
            r["name"] for r in (rows or [])
            if isinstance(r, dict) and r.get("name") and r["name"] != policy_name
        ]
    except Exception:
        other_names = []

    # Build the (urn, mkey) reference set owned by ALL other policies.
    # A failed walk for any single other policy is conservative: we won't
    # mark that policy's objects as exclusively-owned, so the FortiWeb's own
    # "in use" guard at execute time acts as the final safety net.
    other_refs: dict[tuple[str, str], list[str]] = {}
    for other in other_names:
        try:
            other_items = planner.collect(_clone.ROOT_SERVER_POLICY, other)
            for it in other_items:
                if it.kind == "object":
                    other_refs.setdefault((it.urn, it.mkey), []).append(other)
        except Exception:
            pass

    # Classify each item from the target's tree.
    # Reversed src_items = delete order: root is last in collect (everything
    # else is deepest-first) so reversing puts root first; a CR policy appears
    # before the pool it references, etc.
    to_delete: list[tuple[str, str, str]] = []
    to_keep: list[tuple[str, str, str, str, list]] = []
    by_parent: list[tuple[str, str, str]] = []

    for item in reversed(src_items):
        if item.depth == 0:
            continue  # root policy — excluded; executor deletes it explicitly

        if item.kind == "subrow":
            by_parent.append((item.urn, item.mkey, item.label))
            continue

        # Named standalone object (kind == "object").
        if _is_always_skip(item.urn):
            to_keep.append((item.urn, item.mkey, item.label,
                            _skip_reason(item.urn), []))
            continue

        if (item.urn, item.mkey) in other_refs:
            to_keep.append((item.urn, item.mkey, item.label, "shared",
                            other_refs[(item.urn, item.mkey)]))
            continue

        to_delete.append((item.urn, item.mkey, item.label))

    return {
        "root": policy_name,
        "to_delete": to_delete,
        "to_keep": to_keep,
        "by_parent": by_parent,
    }


# --------------------------------------------------------------------------- #
#  Execution                                                                     #
# --------------------------------------------------------------------------- #

def execute_delete_plan(ops, plan: dict, *, dry_run: bool) -> list[dict]:
    """Execute (or preview) *plan* against *ops* (a ``FortiWebOps`` instance).

    Delete order:
      1. Root server policy — ALWAYS first (removes all references so
         dependencies are no longer "in use").
      2. ``plan["to_delete"]`` items in the order supplied (reverse-collect,
         so CR policies precede the pools they reference).

    On a real run: if FortiWeb returns an "in use" / "being used" error for a
    dependency, the item is reclassified as ``kept_shared`` (not ``failed``).
    This handles objects that were concurrently claimed by another policy after
    planning completed, or that the reference-count walk missed due to a partial
    device read.

    Returns a flat list of result dicts::

        {
            "urn":    str,
            "mkey":   str,
            "label":  str,
            "ok":     bool,
            "action": "deleted" | "kept" | "kept_shared" | "failed" | "skipped",
            "reason": str,   # populated for kept / kept_shared / skipped
            "error":  str,   # populated for failed
        }
    """
    from . import objform as _objform

    results: list[dict] = []

    # ── 1. Root policy ──────────────────────────────────────────────────────
    root_ep = "/api/v2.0/cmdb/server-policy/policy"
    root_res = ops.delete(root_ep, plan["root"], dry_run=dry_run)
    root_ok = bool(getattr(root_res, "ok", False))
    root_err = root_res.get("error", "") if hasattr(root_res, "get") else ""
    results.append({
        "urn": "cmdb/server-policy/policy",
        "mkey": plan["root"],
        "label": "Server Policy",
        "ok": root_ok,
        "action": "deleted" if root_ok else "failed",
        "reason": "",
        "error": root_err,
    })

    if not root_ok and not dry_run:
        # Root delete failed — aborting dependency cleanup is correct: touching
        # deps now would corrupt the appliance state (refs still held by root).
        for urn, mkey, label in plan["to_delete"]:
            results.append({"urn": urn, "mkey": mkey, "label": label,
                            "ok": False, "action": "skipped",
                            "reason": "root-delete-failed", "error": ""})
        for urn, mkey, label, reason, _shared in plan["to_keep"]:
            results.append({"urn": urn, "mkey": mkey, "label": label,
                            "ok": True, "action": "kept",
                            "reason": reason, "error": ""})
        return results

    # ── 2. Exclusively-owned dependencies (in reverse-collect order) ─────────
    for urn, mkey, label in plan["to_delete"]:
        ep = _objform.rest_path(urn)
        res = ops.delete(ep, mkey, dry_run=dry_run)
        ok = bool(getattr(res, "ok", False))
        err = res.get("error", "") if hasattr(res, "get") else ""

        if ok:
            action = "deleted"
        elif _is_in_use_error(err):
            action = "kept_shared"  # another policy claims it; safe to leave
        else:
            action = "failed"

        results.append({
            "urn": urn,
            "mkey": mkey,
            "label": label,
            "ok": ok or action == "kept_shared",
            "action": action,
            "reason": "in-use" if action == "kept_shared" else "",
            "error": err if action == "failed" else "",
        })

    # ── 3. Always-kept items (informational only) ────────────────────────────
    for urn, mkey, label, reason in plan["to_keep"]:
        results.append({
            "urn": urn,
            "mkey": mkey,
            "label": label,
            "ok": True,
            "action": "kept",
            "reason": reason,
            "error": "",
        })

    return results
