"""Catalog + headless executor for the Automation subsystem's Scheduled Actions.

This is the SERVICE layer (no Flask views, no Qt) the desktop ``scheduled_actions``
logic is ported onto. The web differences from the desktop are deliberate:

  * persistence is plain SQLAlchemy (``db.session`` + the ORM models) instead of a
    ``store`` abstraction;
  * the in-process lock that guarded a desktop run is replaced by a **DB-claim
    lease** (``scheduled_action.running_at``) so exactly one process — the
    scheduler sidecar — fires a given action even across the gunicorn workers;
  * ``scheduler.compute_next_run`` returns a ``datetime`` (UTC) here, which is
    stored straight into the ``next_run`` DateTime column.

The catalog keeps ONLY server-sensible actions. Read-/file-writers (backup,
signature sync, a stats summary) run unattended; the box-mutating user-scope
object ops go through :class:`FortiWebOps` (snapshot + ChangeHistory + audit, and
they never raise on a dead device). ``upgrade_prep`` is a SAFE pre-upgrade
snapshot (backup + health); a real firmware ``upgrade`` is gated by an approved
Change Request inside its maintenance window (see :mod:`.change_requests`).

Import side-effect-free: importing this module touches no DB and contacts no
device.
"""
from __future__ import annotations

import json
import os
import traceback
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlencode

from sqlalchemy import text

from ..models import (Appliance, ChangeRequest, ScheduledAction,
                      ScheduledActionRun, db)
from . import backup, scheduler, signature_catalog
from .fortiweb_ops import FortiWebOps

# REST endpoints for the user-scope object ops (FortiWeb v2.0 cmdb).
SERVER_POLICY_EP = "/api/v2.0/cmdb/server-policy/policy"
SERVER_POOL_MEMBER_EP = "/api/v2.0/cmdb/server-policy/server-pool/pserver-list"

# Bound the text we persist so a chatty device response can't bloat a DB row.
_LOG_MAX = 8000
_SUMMARY_MAX = 500


# --------------------------------------------------------------------------- #
#  Catalog                                                                      #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ActionSpec:
    """One catalog entry: an automatable operation.

    Fields (the contract the blueprints/UI build against):
      key                  catalog key stored in ``ScheduledAction.action``
      label                human label shown in the editor / history
      scope                'admin' | 'user'
      needs_targets        acts on FortiWeb appliances? (False = no device call)
      single_target        exactly one device (the user-scope object ops)
      danger               destructive / requires care (the UI flags it)
      forced_schedule_kind lock the schedule to one kind ('' = any; upgrade='once')
      summary              short English description (optional, for the UI)
    """

    key: str
    label: str
    scope: str
    needs_targets: bool = True
    single_target: bool = False
    danger: bool = False
    forced_schedule_kind: str = ""
    summary: str = ""


# Admin maintenance automations (read-/file-writers + the gated firmware flow).
ADMIN_ACTIONS: list[ActionSpec] = [
    ActionSpec(
        "backup", "Config backup", "admin", needs_targets=True,
        summary="Trigger an on-device local configuration backup of each target "
                "appliance (services.backup).",
    ),
    ActionSpec(
        "signature_sync", "Sync signature database", "admin", needs_targets=True,
        summary="Refresh the FortiWeb signature catalog from a target device and "
                "cache it as the shared reference DB (services.signature_catalog).",
    ),
    ActionSpec(
        "stats", "Build statistics summary", "admin", needs_targets=False,
        summary="Aggregate a fleet statistics summary. No device call.",
    ),
    ActionSpec(
        "upgrade_prep", "Upgrade preparation (backup + health)", "admin",
        needs_targets=True, danger=True,
        summary="Pre-upgrade snapshot: a config backup AND a health read per "
                "device, so a maintenance window starts from a known-good "
                "baseline. Does NOT flash firmware.",
    ),
    ActionSpec(
        "upgrade", "Firmware upgrade (FULL - flashes + reboots)", "admin",
        needs_targets=True, danger=True, forced_schedule_kind="once",
        summary="Run the firmware upgrade at a FIXED date/time. DESTRUCTIVE. "
                "Authorized by an approved Change Request inside its maintenance "
                "window (change_requests.cr_runnable).",
    ),
]

# User-scope Server-Policy automations scheduled for a specific time. These MUTATE
# the box, so they go through FortiWebOps (snapshot + audit + change history) and
# each acts on exactly ONE device (single_target).
USER_ACTIONS: list[ActionSpec] = [
    ActionSpec(
        "policy_set_status", "Enable / disable a server policy", "user",
        needs_targets=True, single_target=True,
        summary="Turn a server policy on or off at a scheduled time - a cutover, "
                "or a planned pause/restore.",
    ),
    ActionSpec(
        "backend_set_status", "Enable / disable a backend (pool member)", "user",
        needs_targets=True, single_target=True,
        summary="Turn a back-end real server (a server-pool member) on or off - "
                "drain a backend for maintenance or restore it on schedule.",
    ),
    ActionSpec(
        "swap_certificate", "Swap a server-policy certificate", "user",
        needs_targets=True, single_target=True,
        summary="Change the local certificate bound to a server policy at a "
                "scheduled time (e.g. a certificate rotation).",
    ),
]

# key -> ActionSpec for both scopes.
ALL_ACTIONS: dict[str, ActionSpec] = {
    a.key: a for a in (*ADMIN_ACTIONS, *USER_ACTIONS)
}


def get_spec(key: str) -> ActionSpec | None:
    """The :class:`ActionSpec` for ``key``, or ``None`` if it is not in the catalog."""
    return ALL_ACTIONS.get(key)


# --------------------------------------------------------------------------- #
#  Single-action executor (one action vs one appliance)                         #
# --------------------------------------------------------------------------- #
def run_action(spec, appliance, params: dict | None, dry_run: bool = False) -> dict:
    """Run ONE catalog action against ONE appliance (or ``None`` for a no-device
    action such as ``stats``). Returns ``{"ok": bool, "summary": str, "log": str}``
    and NEVER raises - every device call is wrapped so a dead box yields ok=False.

    ``spec`` may be an :class:`ActionSpec` or a bare catalog key. ``dry_run`` skips
    the device write (the FortiWebOps ops return a pure preview; the read/file
    actions report what they would do).
    """
    params = dict(params or {})
    key = getattr(spec, "key", None) or str(spec)
    try:
        if key == "backup":
            return _do_backup(appliance, dry_run)
        if key == "signature_sync":
            return _do_signature_sync(appliance, dry_run)
        if key == "stats":
            return _do_stats(dry_run)
        if key == "upgrade_prep":
            return _do_upgrade_prep(appliance, dry_run)
        if key == "upgrade":
            return _do_upgrade(appliance, params, dry_run)
        if key in ("policy_set_status", "backend_set_status", "swap_certificate"):
            return _do_user_op(key, appliance, params, dry_run)
        return {"ok": False, "summary": f"No executor for {key!r}.", "log": ""}
    except Exception as exc:  # noqa: BLE001 - run_action must never raise
        return {
            "ok": False,
            "summary": f"{type(exc).__name__}: {exc}",
            "log": traceback.format_exc()[:_LOG_MAX],
        }


# --- admin read / file writers --------------------------------------------- #
def _do_backup(appliance, dry_run: bool) -> dict:
    if appliance is None:
        return {"ok": False, "summary": "backup needs a target device.", "log": ""}
    if dry_run:
        return {"ok": True,
                "summary": f"[dry-run] would back up {appliance.name}.", "log": ""}
    resp = backup.create_backup(appliance.build_client())
    name = resp.get("name", "") if isinstance(resp, dict) else ""
    tail = f" ({name})" if name else ""
    return {"ok": True, "summary": f"Backup created on {appliance.name}{tail}.",
            "log": json.dumps(resp)[:_LOG_MAX] if resp else ""}


def _do_signature_sync(appliance, dry_run: bool) -> dict:
    if appliance is None:
        return {"ok": False,
                "summary": "signature_sync needs a target device.", "log": ""}
    if dry_run:
        return {"ok": True,
                "summary": f"[dry-run] would sync signatures from {appliance.name}.",
                "log": ""}
    client = appliance.build_client()
    sset = signature_catalog.pick_signature_set(client)
    if not sset:
        return {"ok": False,
                "summary": f"No signature set found on {appliance.name}.", "log": ""}
    sig_db = signature_catalog.sync_signature_database(client, sset)
    count = len(sig_db.signatures)
    log = ""
    try:  # persistence is a bonus - a write failure must not fail the sync
        path = os.path.join(_data_dir(), "signatures.json")
        signature_catalog.save_signature_db(sig_db, path)
        log = f"cached -> {path}"
    except Exception as exc:  # noqa: BLE001
        log = f"[cache skipped: {type(exc).__name__}: {exc}]"
    return {"ok": True,
            "summary": f"{count} signatures synced from {appliance.name}.",
            "log": log}


def _do_stats(dry_run: bool) -> dict:
    # The web has no offline statistics-site builder yet; this is the no-op
    # summary the spec calls for (a placeholder for the desktop's stats site).
    try:
        count = Appliance.query.filter_by(kind="fortiweb").count()
    except Exception:  # noqa: BLE001 - outside an app context / empty DB
        count = 0
    verb = "would summarise" if dry_run else "summarised"
    return {"ok": True,
            "summary": f"Statistics {verb} the fleet ({count} FortiWeb appliance(s)).",
            "log": ""}


def _do_upgrade_prep(appliance, dry_run: bool) -> dict:
    if appliance is None:
        return {"ok": False,
                "summary": "upgrade_prep needs a target device.", "log": ""}
    if dry_run:
        return {"ok": True,
                "summary": f"[dry-run] would snapshot {appliance.name} (backup + health).",
                "log": ""}
    client = appliance.build_client()
    lines: list[str] = []
    # The backup is MANDATORY - if it raises, run_action reports ok=False.
    resp = backup.create_backup(client)
    bname = resp.get("name", "") if isinstance(resp, dict) else ""
    lines.append(f"backup: {bname or 'created'}")
    # Health read is best-effort (a bonus baseline), never fatal.
    try:
        status = client.status_check()
        lines.append("health: " + json.dumps(status)[:1000])
    except Exception as exc:  # noqa: BLE001
        lines.append(f"health read skipped: {type(exc).__name__}: {exc}")
    return {"ok": True,
            "summary": f"{appliance.name}: pre-upgrade snapshot ready (backup + health).",
            "log": "\n".join(lines)[:_LOG_MAX]}


def _do_upgrade(appliance, params: dict, dry_run: bool) -> dict:
    """Firmware upgrade. The FULL flash runbook (upload .out, reboot, monitor
    recovery, validate services) is NOT part of the headless web service layer
    yet - there is no web ``upgrade`` service to call. Authorization (an approved
    Change Request inside its window) is enforced upstream in
    :func:`execute_and_record` via ``change_requests.cr_runnable``; here we
    deliberately do NOT flash. Guarded stub pending the upgrade-runbook port."""
    who = getattr(appliance, "name", "device")
    return {
        "ok": False,
        "summary": (f"Firmware upgrade for {who} is not executed by the headless "
                    "service layer (no upgrade runbook); no firmware was flashed."),
        "log": "stub: the upgrade runbook is not yet ported to the web service layer.",
    }


# --- user-scope object ops (mutate the box via FortiWebOps) ----------------- #
def _do_user_op(key: str, appliance, params: dict, dry_run: bool) -> dict:
    if appliance is None:
        return {"ok": False, "summary": f"{key} needs a target device.", "log": ""}
    ops = FortiWebOps(appliance)
    enabled = bool(params.get("enabled", True))
    status_val = "enable" if enabled else "disable"
    verb = "enable" if enabled else "disable"

    if key == "policy_set_status":
        policy = str(params.get("policy") or "").strip()
        if not policy:
            return {"ok": False, "summary": "no server policy selected.", "log": ""}
        result = ops.update(SERVER_POLICY_EP, policy,
                            {"status": status_val}, dry_run=dry_run)
        label = f"{verb} server policy {policy} on {appliance.name}"
    elif key == "backend_set_status":
        pool = str(params.get("server_pool") or "").strip()
        member = str(params.get("member") or "").strip()
        if not pool or not member:
            return {"ok": False, "summary": "set the server pool + member id.", "log": ""}
        # FortiWeb addresses a pool member by parent ?mkey=<pool>&sub_mkey=<member>;
        # FortiWebOps only appends a single mkey, so we pre-bake the full query and
        # pass mkey=None (its _path leaves an endpoint that already has a query as-is).
        endpoint = SERVER_POOL_MEMBER_EP + "?" + urlencode(
            {"mkey": pool, "sub_mkey": member})
        result = ops.update(endpoint, None, {"status": status_val}, dry_run=dry_run)
        label = f"{verb} backend {member}@{pool} on {appliance.name}"
    else:  # swap_certificate
        policy = str(params.get("policy") or "").strip()
        cert = str(params.get("certificate") or "").strip()
        if not policy or not cert:
            return {"ok": False, "summary": "set the server policy + certificate.",
                    "log": ""}
        result = ops.update(SERVER_POLICY_EP, policy,
                            {"certificate": cert}, dry_run=dry_run)
        label = f"certificate -> {cert} on policy {policy} ({appliance.name})"

    ok = bool(result.get("ok"))
    err = result.get("error") or ""
    prefix = "[dry-run] " if dry_run else ""
    if dry_run:
        summary = f"{prefix}{label} (preview)"
    elif ok:
        summary = label
    else:
        summary = f"{label} - {err}" if err else f"{label} - failed"
    return {"ok": ok, "summary": summary,
            "log": json.dumps(result.get("request") or {})[:_LOG_MAX]}


# --------------------------------------------------------------------------- #
#  Run-and-record (the single fire path: sidecar tick + the page's "Run now")    #
# --------------------------------------------------------------------------- #
def execute_and_record(action_row, *, trigger: str = "schedule"):
    """Claim, run, and persist one ``ScheduledAction`` fire.

    1. **DB-claim dedupe** - an atomic ``UPDATE ... SET running_at=now WHERE id=:id
       AND running_at IS NULL``. If it updates 0 rows the action is already running
       (another process / a concurrent Run-now), so we return ``None``.
    2. open a ``ScheduledActionRun`` (status 'running').
    3. for an ``upgrade`` bound to a Change Request, re-check
       ``change_requests.cr_runnable`` at fire time; if not runnable -> 'skipped',
       no device write.
    4. run the action against each target (``targets_list``; ``[]`` = the whole
       FortiWeb fleet; a no-target action runs once).
    5. finalize the run, roll ``next_run`` ('once' -> ``None``), and ALWAYS clear
       ``running_at`` (a ``finally`` lease release, even on error).

    Returns the ``ScheduledActionRun`` row, or ``None`` if the claim was lost.
    """
    now = datetime.utcnow()

    # (1) Atomic DB-claim lease - the cross-process replacement for the desktop lock.
    claimed = db.session.execute(
        text("UPDATE scheduled_action SET running_at = :now "
             "WHERE id = :id AND running_at IS NULL"),
        {"now": now, "id": action_row.id},
    )
    db.session.commit()
    if claimed.rowcount == 0:
        return None  # already running elsewhere

    # (2) Open the history row immediately (visible to the UI while it runs).
    run = ScheduledActionRun(
        action_id=action_row.id, status="running", trigger=trigger,
        started_at=now, summary="", log="")
    db.session.add(run)
    db.session.commit()

    status = "failed"
    summary = ""
    log_lines: list[str] = []
    try:
        spec = get_spec(action_row.action)
        if spec is None:
            status, summary = "failed", f"Unknown action {action_row.action!r}."
            log_lines.append(summary)
        else:
            params = action_row.params_dict
            gated = False
            # (3) Upgrade authorized by a Change Request: re-check at fire time.
            if action_row.action == "upgrade" and params.get("change_request_id"):
                from . import change_requests  # local import: avoid any import cycle
                cr = db.session.get(
                    ChangeRequest, _as_int(params.get("change_request_id")))
                ok, reason = change_requests.cr_runnable(cr)
                if not ok:
                    status = "skipped"
                    summary = f"change request: {reason}"
                    log_lines.append(summary)
                    gated = True
            # (4) Run per target.
            if not gated:
                status, summary, log_lines = _run_targets(action_row, spec, params)
    except Exception as exc:  # noqa: BLE001 - a run must never crash the sidecar
        status = "failed"
        summary = f"{type(exc).__name__}: {exc}"
        log_lines = [traceback.format_exc()]
    finally:
        # (5) Finalize + ALWAYS release the lease.
        try:
            next_run = (
                None if action_row.schedule_kind == "once"
                else scheduler.compute_next_run(
                    action_row.schedule_kind, action_row.schedule_dict)
            )
        except Exception:  # noqa: BLE001 - a bad spec must not strand the lease
            next_run = None
        try:
            run.status = status
            run.summary = (summary or "")[:_SUMMARY_MAX]
            run.log = "\n".join(log_lines)[:_LOG_MAX]
            run.finished_at = datetime.utcnow()
            action_row.last_run = now
            action_row.last_status = status
            action_row.next_run = next_run
            action_row.running_at = None
            db.session.commit()
        except Exception:  # noqa: BLE001
            db.session.rollback()
            # Last-ditch: clear the lease by id so the action is never stuck.
            try:
                db.session.execute(
                    text("UPDATE scheduled_action SET running_at = NULL WHERE id = :id"),
                    {"id": action_row.id})
                db.session.commit()
            except Exception:  # noqa: BLE001
                db.session.rollback()
    return run


def _run_targets(action_row, spec: ActionSpec, params: dict):
    """Resolve the action's targets and run it against each; aggregate the outcome.

    Returns ``(status, summary, log_lines)`` where status is one of
    'ok' | 'failed' | 'skipped'.
    """
    targets = _resolve_targets(action_row, spec)
    if spec.needs_targets and not targets:
        return "skipped", "No matching FortiWeb appliance.", ["no targets resolved"]

    ok_n = 0
    total = 0
    fails: list[str] = []
    lines: list[str] = []
    for appliance in targets:
        out = run_action(spec, appliance, params, dry_run=False)
        name = getattr(appliance, "name", "(no device)")
        total += 1
        if out.get("ok"):
            ok_n += 1
            lines.append(f"[ok] {name}: {out.get('summary', '')}")
        else:
            fails.append(name)
            lines.append(f"[FAIL] {name}: {out.get('summary', '')}")
        if out.get("log"):
            lines.append(out["log"])

    status = "ok" if (total and ok_n == total) else ("failed" if total else "skipped")
    summary = f"{spec.label}: {ok_n}/{total} ok"
    if fails:
        summary += " (failed: " + ", ".join(fails) + ")"
    return status, summary, lines


def _resolve_targets(action_row, spec: ActionSpec) -> list:
    """The appliances an action fires against.

    A no-target action (``needs_targets`` False) runs exactly once (``[None]``).
    Otherwise ``targets_list`` selects FortiWeb appliances by id; an empty list
    means the whole FortiWeb fleet. ``single_target`` actions take only the first.
    """
    if not spec.needs_targets:
        return [None]
    ids = [v for v in (_as_int(t) for t in action_row.targets_list) if v is not None]
    if ids:
        devices = (Appliance.query
                   .filter(Appliance.kind == "fortiweb", Appliance.id.in_(ids))
                   .all())
    else:
        devices = Appliance.query.filter_by(kind="fortiweb").all()
    if spec.single_target:
        devices = devices[:1]
    return devices


# --------------------------------------------------------------------------- #
#  Due-now query (consumed by the scheduler sidecar)                            #
# --------------------------------------------------------------------------- #
def due_actions(now: datetime | None = None) -> list[ScheduledAction]:
    """Enabled actions whose ``next_run`` has arrived and that are NOT already
    leased (``running_at IS NULL``) - i.e. ready to fire right now."""
    now = now or datetime.utcnow()
    return (ScheduledAction.query
            .filter(ScheduledAction.enabled.is_(True),
                    ScheduledAction.next_run.isnot(None),
                    ScheduledAction.next_run <= now,
                    ScheduledAction.running_at.is_(None))
            .all())


# --------------------------------------------------------------------------- #
#  Small helpers                                                                #
# --------------------------------------------------------------------------- #
def _as_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _data_dir() -> str:
    """The writable data directory (next to the SQLite DB, or project ``data/``).

    Resolved lazily (never at import) and created on demand. Used to cache the
    signature DB; any failure here is swallowed by the caller.
    """
    base = ""
    try:
        from flask import current_app
        uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "") or ""
        prefix = "sqlite:///"
        if uri.startswith(prefix):
            base = os.path.dirname(uri[len(prefix):])
    except Exception:  # noqa: BLE001 - outside an app context
        base = ""
    if not base:
        base = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "data")
    os.makedirs(base, exist_ok=True)
    return base


__all__ = [
    "ActionSpec",
    "ADMIN_ACTIONS",
    "USER_ACTIONS",
    "ALL_ACTIONS",
    "get_spec",
    "run_action",
    "execute_and_record",
    "due_actions",
    "SERVER_POLICY_EP",
    "SERVER_POOL_MEMBER_EP",
]
