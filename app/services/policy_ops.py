"""Server-Policy action engine — enable/disable, delete, clone (same box),
clone-to-another and migrate-to-another FortiWeb, for the Workspace row + bulk
actions.

Every REAL action is auditable and reversible-aware:

  * per-object write goes through :class:`FortiWebOps` (before/after snapshot +
    ``ChangeHistory`` + audit, dry-run-capable, never raises on a dead device);
  * a whole-policy tree copy reuses the validated :mod:`services.clone` engine
    (deepest-first, skip-if-exists at the destination), so a clone/migrate never
    blindly overwrites an object that already lives on the target;
  * the caller (the route) wraps a real run in a background **job**
    (:mod:`services.jobs`) so the user gets live progress, a history entry and a
    bell notification — a fleet/policy write is never a silent fire-and-forget.

The per-policy functions take *duck-typed* ops/planner objects, so
``tests/test_policy_ops.py`` drives them with in-memory fakes (no Flask, no
device). ``start_policy_job`` is the only Flask/DB-aware entry point.

Design decisions (see PLAN):
  * **Migrate ≠ delete-source.** A migrate clones the policy tree onto the
    destination and, ONLY when that landed cleanly, disables the SOURCE policy
    (a built-in rollback — the source is kept, never deleted). A failed clone
    leaves the source untouched and live. Deleting a policy is a separate,
    explicit action.
  * **Clone/migrate leave the new root DISABLED** (``clone.disable_root``) so a
    freshly-copied policy can't take real traffic before a human cutover.
"""
from __future__ import annotations

from typing import Any, Callable

from . import clone

EP_POLICY = "/api/v2.0/cmdb/server-policy/policy"

# The 5 workspace actions (single + bulk share these keys).
ACTIONS = ("enable", "disable", "delete", "clone_here", "clone_to", "migrate_to")
_NEEDS_TARGET = ("clone_to", "migrate_to")   # a destination appliance
_NEEDS_NAME = ("clone_here",)                # a distinct name on the same box
_CLONE_ACTIONS = ("clone_here", "clone_to", "migrate_to")


# --------------------------------------------------------------------------- #
#  Per-policy primitives (duck-typed ops/planner — unit-tested with fakes)      #
# --------------------------------------------------------------------------- #
def set_status(ops, policy: str, *, enable: bool, dry_run: bool):
    """Enable/disable one Server Policy (a single ``status`` field write)."""
    status = "enable" if enable else "disable"
    return ops.update(EP_POLICY, policy, {"data": {"status": status}}, dry_run=dry_run)


def delete_policy(ops, policy: str, *, dry_run: bool):
    """Delete the Server Policy object itself. Shared building blocks it
    referenced (WPP, pool, cert, service…) are left in place — a policy delete
    is not a cascade (that is a separate, deliberate operation)."""
    return ops.delete(EP_POLICY, policy, dry_run=dry_run)


def clone_policy(planner, ops, policy: str, *, new_name: str, dry_run: bool,
                 disable: bool = True) -> list[clone.CloneItem]:
    """Plan the full policy tree on the source and create the missing objects on
    the ``ops`` device (same box or another). The new root is left DISABLED.

    ``ops`` is where writes land: for a same-box clone it wraps the source
    device; for a cross-box clone/migrate it wraps the DESTINATION."""
    items = planner.plan(clone.ROOT_SERVER_POLICY, policy, new_name=new_name)
    if disable:
        clone.disable_root(items)

    def _write(item: clone.CloneItem) -> None:
        from . import objform
        ep = objform.rest_path(item.urn)
        mkey = item.parent_mkey if item.kind == "subrow" else None
        res = ops.create(ep, {"data": item.payload}, mkey=mkey, dry_run=False)
        if not res.ok:
            raise RuntimeError(res.get("error") or "write failed")

    clone.apply_clone(items, _write, dry_run=dry_run)
    return items


def clone_summary(items: list[clone.CloneItem]) -> dict[str, int]:
    """Roll a planned/applied clone up to ``{created, exists, failed, skipped,
    total}`` for the job result + audit line."""
    created = sum(1 for it in items if it.applied)
    failed = sum(1 for it in items if (it.result or "").startswith("error"))
    counts = clone.summarize(items)
    return {
        "created": created,
        "failed": failed,
        "exists": counts.get("exists", 0),
        "skipped": counts.get("exists", 0) + counts.get("cert", 0)
        + counts.get("no-endpoint", 0) + counts.get("empty", 0),
        "to_create": counts.get("create", 0),
        "total": len(items),
    }


def migrate_policy(dst_planner, dst_ops, src_ops, policy: str, *,
                   new_name: str, dry_run: bool) -> dict:
    """Clone the policy tree onto the destination, then — ONLY on a clean clone
    and a real apply — disable the SOURCE policy (rollback-friendly; the source
    is kept). A failed clone leaves the source LIVE and untouched."""
    items = clone_policy(dst_planner, dst_ops, policy, new_name=new_name,
                         dry_run=dry_run, disable=True)
    summary = clone_summary(items)
    clone_ok = summary["failed"] == 0 and (dry_run or summary["created"] > 0
                                           or summary["exists"] > 0)
    source_disabled = False
    if clone_ok and not dry_run:
        res = set_status(src_ops, policy, enable=False, dry_run=False)
        source_disabled = bool(getattr(res, "ok", False))
    return {
        "ok": bool(clone_ok),
        "summary": summary,
        "items": items,
        "source_disabled": source_disabled,
    }


# --------------------------------------------------------------------------- #
#  Flask/DB-aware orchestration (real objects; wrapped in a background job)      #
# --------------------------------------------------------------------------- #
def _ops(appliance):
    from .fortiweb_ops import FortiWebOps
    return FortiWebOps(appliance)


def _planner(src_appl, dst_appl):
    """A :class:`clone.ClonePlanner` reading the source device and validating
    against the destination (same object when it is the same box)."""
    from ..clients.fortiweb import FortiWebClient
    src_reader = clone.ClientReader(FortiWebClient(src_appl))
    dst_reader = (src_reader if dst_appl.id == src_appl.id
                  else clone.ClientReader(FortiWebClient(dst_appl)))
    return clone.ClonePlanner(src_reader, dst_reader)


def perform_one(action: str, *, source_appl, dest_appl=None, policy: str,
                new_name: str = "", dry_run: bool) -> dict:
    """Execute (or preview) ONE action against ONE policy with real appliances.

    Returns a normalised ``{policy, action, ok, error, detail}`` record; never
    raises (a device/logic failure is captured in ``ok``/``error``)."""
    rec = {"policy": policy, "action": action, "ok": False, "error": "",
           "detail": {}}
    try:
        if action in ("enable", "disable"):
            res = set_status(_ops(source_appl), policy,
                             enable=(action == "enable"), dry_run=dry_run)
            rec["ok"] = bool(getattr(res, "ok", False))
            rec["error"] = res.get("error", "") if hasattr(res, "get") else ""
            rec["detail"] = {"request": res.get("request") if hasattr(res, "get") else None}
        elif action == "delete":
            res = delete_policy(_ops(source_appl), policy, dry_run=dry_run)
            rec["ok"] = bool(getattr(res, "ok", False))
            rec["error"] = res.get("error", "") if hasattr(res, "get") else ""
            rec["detail"] = {"request": res.get("request") if hasattr(res, "get") else None}
            # Lifecycle hook (WAF rule 1): a deleted policy takes its authored
            # desired-state carve-outs with it (shared ones just lose the
            # binding) — no orphans waiting for a manual Purge. Best-effort:
            # a store hiccup never turns a successful device delete into a
            # failure; it just leaves the manual Purge as the fallback.
            if rec["ok"] and not dry_run:
                try:
                    from . import wpp_exceptions as exc_store
                    purged = exc_store.delete_for_policy(source_appl.id, policy)
                    rec["detail"]["carveouts_purged"] = purged
                except Exception:  # noqa: BLE001
                    rec["detail"]["carveouts_purged"] = None
        elif action == "clone_here":
            planner = _planner(source_appl, source_appl)
            items = clone_policy(planner, _ops(source_appl), policy,
                                 new_name=new_name, dry_run=dry_run)
            summary = clone_summary(items)
            rec["ok"] = summary["failed"] == 0 and (dry_run or summary["created"] > 0)
            rec["detail"] = {"summary": summary, "plan": clone.render_plan(items),
                             "new_name": new_name}
            if summary["failed"]:
                rec["error"] = "%d object(s) failed" % summary["failed"]
            elif not dry_run and summary["created"] == 0:
                rec["ok"], rec["error"] = False, 'nothing to create — "%s" exists' % new_name
        elif action == "clone_to":
            planner = _planner(source_appl, dest_appl)
            items = clone_policy(planner, _ops(dest_appl), policy,
                                 new_name=new_name or policy, dry_run=dry_run)
            summary = clone_summary(items)
            rec["ok"] = summary["failed"] == 0 and (dry_run or summary["created"] > 0
                                                    or summary["exists"] > 0)
            rec["detail"] = {"summary": summary, "plan": clone.render_plan(items),
                             "dest": dest_appl.name, "new_name": new_name or policy}
            if summary["failed"]:
                rec["error"] = "%d object(s) failed on %s" % (summary["failed"], dest_appl.name)
        elif action == "migrate_to":
            planner = _planner(source_appl, dest_appl)
            out = migrate_policy(planner, _ops(dest_appl), _ops(source_appl),
                                 policy, new_name=new_name or policy, dry_run=dry_run)
            rec["ok"] = out["ok"]
            rec["detail"] = {"summary": out["summary"],
                             "plan": clone.render_plan(out["items"]),
                             "dest": dest_appl.name, "new_name": new_name or policy,
                             "source_disabled": out["source_disabled"]}
            if not out["ok"]:
                rec["error"] = "clone failed — source left live"
        else:
            rec["error"] = "unknown action %r" % action
    except Exception as exc:  # noqa: BLE001 — one policy's failure never sinks the run
        rec["error"] = "%s: %s" % (type(exc).__name__, exc)
    return rec


def action_label(action: str) -> str:
    return {
        "enable": "Enable", "disable": "Disable", "delete": "Delete",
        "clone_here": "Clone (same box)", "clone_to": "Clone to another FortiWeb",
        "migrate_to": "Migrate to another FortiWeb",
    }.get(action, action)


def preview(action: str, *, source_appl, dest_appl=None, policies: list[str],
            new_name: str = "") -> list[dict]:
    """Synchronous dry-run across the selected policies (read-only). For
    clone/migrate this reads the source device (and validates the destination)
    but writes nothing."""
    return [
        perform_one(action, source_appl=source_appl, dest_appl=dest_appl,
                    policy=p, new_name=_name_for(action, p, new_name, policies),
                    dry_run=True)
        for p in policies
    ]


def _name_for(action: str, policy: str, new_name: str, policies: list[str]) -> str:
    """The destination name for one policy. A same-box clone of ONE policy uses
    the given name; a bulk same-box clone suffixes each ('-copy') so names stay
    unique. Cross-box keeps the original name unless one was given."""
    if action == "clone_here":
        if len(policies) == 1 and new_name:
            return new_name
        return "%s-copy" % policy
    return new_name or policy


def start_policy_job(flask_app, *, action: str, source_appl, dest_appl=None,
                     policies: list[str], new_name: str = "", by: str,
                     user_id: int | None = None) -> dict:
    """Run a REAL policy action across ``policies`` as a background job.

    The job iterates policies, checks the Stop flag between each (never
    mid-write), calls :func:`perform_one` for real, and finishes with a summary
    the Job Manager shows. It writes ONE audit summary row and pushes a bell
    notification. Returns the created job dict (poll ``/jobs/<id>``)."""
    from . import jobs

    dest_id = dest_appl.id if dest_appl else None
    dest_name = dest_appl.name if dest_appl else ""
    src_id, src_name = source_appl.id, source_appl.name
    title = "%s — %d server polic%s on %s" % (
        action_label(action), len(policies),
        "y" if len(policies) == 1 else "ies", src_name)

    job = jobs.create_job(
        "policy_action", title, by=by,
        meta={"action": action, "source_id": src_id, "source": src_name,
              "dest_id": dest_id, "dest": dest_name,
              "policies": list(policies), "new_name": new_name},
        cancelable=True)

    def _worker(app, job_id):
        with app.app_context():
            from ..models import Appliance
            from .audit import log_action
            from . import notifications as notify
            src = Appliance.query.get(src_id)
            dst = Appliance.query.get(dest_id) if dest_id else None
            results = []
            total = len(policies)
            for i, pol in enumerate(policies):
                jobs.checkpoint(job_id)   # cooperative Stop, between policies
                jobs.set_progress(job_id, int(i * 100 / max(1, total)),
                                  "%s — %s (%d/%d)" % (action_label(action), pol, i + 1, total))
                rec = perform_one(
                    action, source_appl=src, dest_appl=dst, policy=pol,
                    new_name=_name_for(action, pol, new_name, policies), dry_run=False)
                results.append(rec)
                # Clear, per-object audit line for THIS policy.
                log_action(
                    "policy.%s" % action, target="%s/%s" % (src_name, pol),
                    detail="%s policy=%s dest=%s ok=%s %s" % (
                        action_label(action), pol, dest_name or "-", rec["ok"],
                        rec.get("error") or ""))
            ok = sum(1 for r in results if r["ok"])
            failed = total - ok
            summary = {"action": action, "label": action_label(action),
                       "source": src_name, "dest": dest_name,
                       "ok": ok, "failed": failed, "total": total,
                       "results": results}
            log_action(
                "policy.%s.summary" % action, target=src_name,
                detail="by=%s %s policies=%s dest=%s ok=%d/%d" % (
                    by, action_label(action), policies, dest_name or "-", ok, total))
            if user_id:
                kind = notify.Notification.KIND_SUCCESS if failed == 0 else notify.Notification.KIND_ERROR
                notify.push(
                    user_id,
                    "%s: %d/%d server polic%s ok" % (
                        action_label(action), ok, total, "y" if total == 1 else "ies"),
                    kind=kind,
                    body=("on %s%s" % (src_name, (" → " + dest_name) if dest_name else ""))
                    + ("" if failed == 0 else " — %d failed" % failed))
            if failed:
                jobs.update_job(job_id, result=summary)
                jobs.finish_error(job_id, "%s completed with %d/%d failure(s)"
                                  % (action_label(action), failed, total))
            else:
                jobs.finish_success(job_id, result=summary,
                                    message="%s applied to %d/%d server polic%s"
                                    % (action_label(action), ok, total,
                                       "y" if total == 1 else "ies"))

    jobs.run_async(flask_app, job["id"], _worker)
    return job
