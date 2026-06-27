"""Change-request orchestration for the Automation subsystem (maintenance windows).

A Change Request (CR) is the control record for a risky, windowed change - above
all a firmware UPGRADE: WHICH devices + server policies are affected (the clients
to warn), WHEN (the window), WHAT runs (the action + params), an APPROVAL gate,
and the bound one-shot :class:`ScheduledAction` that actually executes it inside
the window. The upgrade executor refuses to flash unless its CR is approved/
scheduled and the clock is INSIDE the window (:func:`cr_runnable`).

This module is HEADLESS (no Qt, no Flask views). It is a pure SQLAlchemy port of
the desktop ``change_requests`` service: the status workflow stamps a
``ChangeRequestEvent`` per transition, scheduling binds a ``ScheduledAction``, the
maintenance notice is plain text rendering, and affected-policy discovery is a
best-effort live read (the web has no local policy cache).

Import side-effect-free: importing this module touches no DB and contacts no
device.
"""
from __future__ import annotations

import json
from datetime import datetime

from ..models import (Appliance, ChangeRequest, ChangeRequestEvent,
                      ScheduledAction, db)
from . import scheduler

# Convenience constants for the UI (the lifecycle itself lives on the model:
# ChangeRequest.STATUSES / ChangeRequest.TERMINAL).
RISKS = ("low", "medium", "high")

# A CR may fire only from one of these live states (terminal/draft cannot run).
_RUNNABLE_STATES = ("approved", "scheduled", "in_progress")


# --------------------------------------------------------------------------- #
#  Status workflow (every transition stamps a timeline event)                   #
# --------------------------------------------------------------------------- #
def _transition(cr, status: str, by: str = "", detail: str = "", **fields) -> None:
    """Move ``cr`` to ``status``, set any extra ``fields``, append a
    :class:`ChangeRequestEvent`, and commit."""
    cr.status = status
    for key, value in fields.items():
        setattr(cr, key, value)
    db.session.add(ChangeRequestEvent(
        cr_id=cr.id, kind=status, by=by, detail=detail, ts=datetime.utcnow()))
    db.session.commit()


def approve(cr_id: int, by: str) -> ChangeRequest:
    """Approve a CR (stamps ``approved_by`` / ``approved_at``)."""
    cr = db.session.get(ChangeRequest, cr_id)
    if cr is None:
        raise ValueError("change request not found")
    _transition(cr, "approved", by=by, detail="Change request approved",
                approved_by=by, approved_at=datetime.utcnow())
    return cr


def cancel(cr_id: int, by: str, reason: str = "") -> ChangeRequest:
    """Cancel a CR and disable its bound scheduled action (so it won't fire)."""
    cr = db.session.get(ChangeRequest, cr_id)
    if cr is None:
        raise ValueError("change request not found")
    if cr.scheduled_action_id:
        action = db.session.get(ScheduledAction, cr.scheduled_action_id)
        if action is not None:
            action.enabled = False  # committed by _transition below
    _transition(cr, "cancelled", by=by,
                detail=reason or "Change request cancelled")
    return cr


def schedule_change_request(cr_id: int, by: str) -> int:
    """Bind a ``once`` scheduled action at the window start and move the CR to
    ``scheduled``. Returns the bound ``scheduled_action`` id.

    Requires an approved (or already scheduled) CR with a window start. The
    created action carries ``change_request_id`` in its params so the executor can
    re-check approval + window at fire time (:func:`cr_runnable`)."""
    cr = db.session.get(ChangeRequest, cr_id)
    if cr is None:
        raise ValueError("change request not found")
    if cr.status not in ("approved", "scheduled"):
        raise ValueError("approve the change request before scheduling it")
    if cr.window_start is None:
        raise ValueError("set a maintenance-window start first")

    params = dict(cr.params_dict)
    params["change_request_id"] = cr.id
    schedule = {"at": cr.window_start.isoformat()}
    next_run = scheduler.compute_next_run("once", schedule)
    name = f"CR #{cr.id}: {cr.title}"[:120]

    action = None
    if cr.scheduled_action_id:
        action = db.session.get(ScheduledAction, cr.scheduled_action_id)
    if action is None:
        action = ScheduledAction(created_by=by)
        db.session.add(action)
    action.name = name
    action.scope = "admin"
    action.action = cr.action
    action.targets = json.dumps(cr.device_ids_list)
    action.params = json.dumps(params)
    action.schedule_kind = "once"
    action.schedule = json.dumps(schedule)
    action.enabled = True
    action.catch_up = True
    action.next_run = next_run
    db.session.flush()  # assign action.id before binding it back to the CR

    _transition(cr, "scheduled", by=by,
                detail=f"Scheduled for {_fmt_window(cr.window_start)}",
                scheduled_action_id=action.id)
    return action.id


def cr_runnable(cr, now: datetime | None = None) -> tuple[bool, str]:
    """``(ok, reason)`` - may the bound action run NOW? Ok only if the CR is
    approved/scheduled/in_progress AND the clock is inside the window
    (``window_start <= now <= window_end``). The upgrade executor uses this as the
    unattended authorization that replaces the desktop's interactive unlock."""
    if cr is None:
        return False, "no change request"
    now = now or datetime.utcnow()
    if cr.status in ChangeRequest.TERMINAL:
        return False, f"change request is {cr.status}"
    if cr.status not in _RUNNABLE_STATES:
        return False, "change request is not approved"
    if cr.window_start is None:
        return False, "no maintenance window"
    if now < cr.window_start:
        return False, "before the maintenance window"
    if cr.window_end is not None and now > cr.window_end:
        return False, "after the maintenance window"
    return True, "inside the maintenance window"


# --------------------------------------------------------------------------- #
#  Client maintenance notice (pure text)                                        #
# --------------------------------------------------------------------------- #
def _fmt_window(dt) -> str:
    """Format a stored (naive UTC) window datetime for display."""
    if dt is None:
        return "(time TBD)"
    try:
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:  # noqa: BLE001
        return str(dt)


def _policies(cr) -> list:
    """The CR's stored affected-policy list (JSON in ``ChangeRequest.policies``)."""
    try:
        value = json.loads(cr.policies or "[]")
        return value if isinstance(value, list) else []
    except (ValueError, TypeError):
        return []


def maintenance_notice(cr) -> str:
    """Render the client-facing maintenance notice (English, plain text).

    Lists every affected service policy + the window so it can be emailed/posted
    to the clients before the change. Pure text - sending is out of scope (the CR
    records ``notify_status`` / ``notify_log`` once the operator confirms)."""
    start = _fmt_window(cr.window_start)
    end = _fmt_window(cr.window_end) if cr.window_end else None
    when = f"from {start} to {end}" if end else f"starting {start}"
    lines = [
        "Subject: Scheduled maintenance window - service may be briefly interrupted",
        "",
        "Dear customer,",
        "",
        f"We will perform scheduled maintenance {when}.",
    ]
    if cr.reason:
        lines.append(f"Reason: {cr.reason}.")
    policies = _policies(cr)
    if policies:
        lines.append("")
        lines.append("Affected services:")
        seen = set()
        for p in policies:
            if not isinstance(p, dict):
                continue
            label = p.get("service") or p.get("policy") or "service"
            dedupe = (p.get("device"), p.get("policy"))
            if dedupe in seen:
                continue
            seen.add(dedupe)
            host = f" ({p['vserver']})" if p.get("vserver") else ""
            lines.append(f"  - {p.get('policy', 'service')}{host} on "
                         f"{p.get('device', '')} - {label}")
    lines += [
        "",
        "During the window the service(s) above may be briefly unavailable while "
        "the change is applied. We expect minimal disruption and will restore full "
        "service as soon as possible.",
        "",
        "We apologise for any inconvenience.",
        "",
        "- Operations team",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  Affected-policy discovery (best-effort live read - the clients to warn)       #
# --------------------------------------------------------------------------- #
def affected_policies(device_ids, *, timeout: float = 8.0) -> list[dict]:
    """Every server policy on the targeted devices -> the clients impacted by the
    window. Each row is ``{device, device_id, policy, vserver, service, status}``.

    Best-effort: the web has no local policy cache, so this reads each device live
    (like ``services.fleet_objects``) wrapped per-device - a dead/unauthenticated
    appliance is skipped rather than raising. An empty result is fine (the UI just
    shows no pre-filled policies)."""
    ids = [v for v in (_as_int(t) for t in (device_ids or [])) if v is not None]
    if not ids:
        return []
    appliances = {a.id: a for a in
                  Appliance.query.filter(Appliance.id.in_(ids)).all()}
    out: list[dict] = []
    for dev_id in ids:
        appliance = appliances.get(dev_id)
        if appliance is None:
            continue
        try:
            raw = appliance.build_client(timeout=timeout).list_server_policies()
        except Exception:  # noqa: BLE001 - connectivity miss must not break planning
            continue
        rows = raw.get("results", raw) if isinstance(raw, dict) else raw
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            service = (r.get("https-service") or r.get("http-service")
                       or r.get("service") or "")
            out.append({
                "device": appliance.name,
                "device_id": dev_id,
                "policy": r.get("name", ""),
                "vserver": r.get("vserver", ""),
                "service": service,
                "status": r.get("status", ""),
            })
    return out


def _as_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


__all__ = [
    "RISKS",
    "approve",
    "cancel",
    "schedule_change_request",
    "cr_runnable",
    "maintenance_notice",
    "affected_policies",
]
