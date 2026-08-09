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

# Cap for the stored outcome blurb (result_summary is TEXT; this only stops an
# executor traceback from being pasted whole into the record).
_RESULT_MAX = 4000


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
    # Tell the integrations the gate is passed. Best-effort by contract: an
    # approval is a decision a human made in this product, and a downstream
    # system being unreachable must not be able to un-make it.
    from . import cr_orchestrator
    cr_orchestrator.announce_approved(cr, by=by)
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


# --------------------------------------------------------------------------- #
#  Execution transitions (written by the EXECUTOR, never by a human)            #
# --------------------------------------------------------------------------- #
def _resolve(cr_or_id):
    """Accept a ``ChangeRequest`` row or its id - the executor only holds the id
    it read out of the action params."""
    if isinstance(cr_or_id, ChangeRequest):
        return cr_or_id
    return db.session.get(ChangeRequest, _as_int(cr_or_id))


def start(cr_or_id, by: str = "scheduler", detail: str = ""):
    """Move a firing CR to ``in_progress``.

    Called by the executor only AFTER :func:`cr_runnable` authorized this fire,
    so a gated (skipped) fire never touches the CR: a window that never opened
    must not leave a record that looks like a change that started. Idempotent
    and terminal-safe - a CR already closed is returned untouched."""
    cr = _resolve(cr_or_id)
    if cr is None or cr.status in ChangeRequest.TERMINAL:
        return cr
    if cr.status == "in_progress":
        return cr
    _transition(cr, "in_progress", by=by, detail=detail or "Execution started")
    # Open the external maintenance window HERE rather than in the executor:
    # a caller that forgets is a device changed with no window on record,
    # and this transition is the one place every authorized fire passes
    # through. Best-effort by contract - see cr_orchestrator.
    from . import cr_orchestrator
    cr_orchestrator.on_start(cr, by=by)
    return cr


def finish(cr_or_id, outcome: str, by: str = "scheduler", summary: str = ""):
    """Close a CR from an executor outcome: ``ok`` -> ``completed``, ANYTHING
    ELSE -> ``failed``, with the reason kept in ``result_summary``.

    ``skipped`` maps to **failed** on purpose. The bound action is a one-shot:
    its ``next_run`` is cleared after the fire, so a CR left open because
    nothing ran can never close by itself - which is exactly the stall these
    transitions exist to remove. A change whose window elapsed without the
    change happening did not succeed, and the operator has to see that with the
    reason attached rather than find a CR parked at ``scheduled`` forever."""
    cr = _resolve(cr_or_id)
    if cr is None or cr.status in ChangeRequest.TERMINAL:
        return cr
    status = "completed" if outcome == "ok" else "failed"
    _transition(cr, status, by=by, detail=(summary or f"run {outcome}")[:_RESULT_MAX],
                result_summary=(summary or outcome)[:_RESULT_MAX])
    # Close the window, tell the hooks, mail the affected clients - in that
    # order, so nobody is told service is restored before the window that
    # covered the outage is closed. Never re-grades the outcome above.
    from . import cr_orchestrator
    cr_orchestrator.on_finish(cr, outcome, summary=summary, by=by)
    return cr


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
    # Fail-closed external approval. A CR routed through an external change
    # authority is authorized by THAT authority saying yes, never by it
    # failing to say no: unreachable, slow and ambiguous all land on the
    # un-runnable side of this line.
    from . import cr_orchestrator
    ext_ok, ext_reason = cr_orchestrator.external_gate(cr, now)
    if not ext_ok:
        return False, ext_reason
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


def recipients_for(cr) -> list[str]:
    """Who this CR mails: its own ``notify_to`` list, else the Email settings
    default list. ``[]`` means nobody is configured - an empty list is a REFUSAL
    to guess an address, not an error, and the caller records that as the
    reason nothing was sent."""
    from . import email_service as email
    explicit = email.parse_recipients(getattr(cr, "notify_to", "") or "")
    if explicit:
        return explicit
    return email.parse_recipients(email.config().get("default_to", ""))


def outcome_notice(cr, status: str | None = None) -> tuple[str, str]:
    """``(subject, body)`` for the END of the window - what the affected clients
    are told once the change is over.

    Deliberately NOT :func:`maintenance_notice` again: that one warns service
    *may* be interrupted. Re-sending it at the end would tell a customer to
    brace for an outage that already finished."""
    status = status or cr.status
    ok = status == "completed"
    when = _fmt_window(cr.window_start)
    head = ("Maintenance completed - service restored" if ok else
            "Maintenance window closed - change NOT completed")
    lines = [f"Subject: {head}", "", "Dear customer,", ""]
    if ok:
        lines.append(f"The scheduled maintenance that began {when} is complete "
                     "and the affected services are back in normal operation.")
    else:
        lines.append(f"The maintenance window that began {when} has closed "
                     "WITHOUT the planned change being applied. Services were "
                     "left in their previous state.")
    if cr.reason:
        lines += ["", f"Change: {cr.reason}"]
    policies = _policies(cr)
    if policies:
        lines += ["", "Services covered by this window:"]
        seen = set()
        for p in policies:
            if not isinstance(p, dict):
                continue
            dedupe = (p.get("device"), p.get("policy"))
            if dedupe in seen:
                continue
            seen.add(dedupe)
            host = f" ({p['vserver']})" if p.get("vserver") else ""
            lines.append(f"  - {p.get('policy', 'service')}{host} on "
                         f"{p.get('device', '')}")
    if not ok and cr.result_summary:
        lines += ["", f"Outcome: {cr.result_summary}"]
    lines += ["", "Thank you for your patience.", "", "- Operations team"]
    body = "\n".join(lines[1:]).lstrip("\n")
    return head, body


def notify_outcome(cr, *, by: str = "scheduler") -> dict:
    """Mail the end-of-window notice ONCE. Returns
    ``{sent: bool, detail: str, recipients: [...]}``.

    Best-effort BY CONTRACT: the caller records what happened but must never let
    it change the CR outcome. An upgrade that worked worked whether or not the
    SMTP server answered, and letting a mail failure re-grade the change would
    make the record lie about the device.

    Idempotent via ``final_notified_at`` - a second call after a successful send
    is a no-op, so a retried/duplicated fire cannot mail the customer twice."""
    from . import email_service as email
    if cr is None:
        return {"sent": False, "detail": "no change request", "recipients": []}
    if getattr(cr, "final_notified_at", None):
        return {"sent": False, "detail": "already notified", "recipients": []}

    stamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    def _log(text_line: str) -> None:
        cr.notify_log = ((cr.notify_log or "") + f"\n[{stamp}] {text_line}")[-8000:]
        db.session.commit()

    if not email.is_configured():
        _log("outcome notice NOT sent: email is not configured")
        return {"sent": False, "detail": "email not configured", "recipients": []}
    recipients = recipients_for(cr)
    if not recipients:
        _log("outcome notice NOT sent: no recipients configured")
        return {"sent": False, "detail": "no recipients", "recipients": []}

    subject, body = outcome_notice(cr)
    result = email.send_email(recipients, subject, body)
    if result.get("ok"):
        cr.final_notified_at = datetime.utcnow()
        _log(f"outcome notice sent to {', '.join(recipients)}")
        db.session.add(ChangeRequestEvent(
            cr_id=cr.id, kind="notified", by=by,
            detail=f"outcome notice to {len(recipients)} recipient(s)",
            ts=datetime.utcnow()))
        db.session.commit()
        return {"sent": True, "detail": result.get("detail", ""),
                "recipients": recipients}
    _log(f"outcome notice FAILED: {result.get('detail', '')}")
    return {"sent": False, "detail": result.get("detail", ""),
            "recipients": recipients}


# --------------------------------------------------------------------------- #
#  Affected-policy discovery (best-effort live read - the clients to warn)       #
# --------------------------------------------------------------------------- #
def _published_frontends(appliance, *, timeout: float) -> list[dict]:
    """The front-ends a window takes offline, read in THIS product's shape.

    FortiWeb publishes server POLICIES; FortiADC publishes VIRTUAL SERVERS.
    Reading only the FortiWeb shape made every FortiADC in a window come back
    with nothing - a maintenance notice that silently under-states the outage.
    FortiAnalyzer and FortiAuthenticator publish no equivalent object, so an
    empty list there is a fact about the product, not a failed read.
    """
    kind = (getattr(appliance, "kind", "") or "fortiweb").strip().lower()
    out: list[dict] = []
    if kind not in ("fortiweb", "fortiadc"):
        return out          # no front-end object for this product: do not connect
    client = appliance.build_client(timeout=timeout)
    if kind == "fortiweb":
        raw = client.list_server_policies()
        rows = raw.get("results", raw) if isinstance(raw, dict) else raw
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            out.append({
                "policy": r.get("name", ""),
                "vserver": r.get("vserver", ""),
                "service": (r.get("https-service") or r.get("http-service")
                            or r.get("service") or ""),
                "status": r.get("status", ""),
            })
        return out
    if kind == "fortiadc":
        raw = client.list_virtual_servers()
        rows = raw.get("payload", raw) if isinstance(raw, dict) else raw
        if isinstance(rows, dict):          # single object reads come back keyed
            rows = list(rows.values())
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            out.append({
                "policy": r.get("mkey") or r.get("name", ""),
                "vserver": r.get("interface", ""),
                "service": str(r.get("port") or r.get("port-range") or ""),
                "status": r.get("status", ""),
            })
        return out
    # No published-service object is modelled for this product.
    return out


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
            rows = _published_frontends(appliance, timeout=timeout)
        except Exception:  # noqa: BLE001 - connectivity miss must not break planning
            continue
        for row in rows:
            row["device"] = appliance.name
            row["device_id"] = dev_id
            out.append(row)
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
    "start",
    "finish",
    "cr_runnable",
    "maintenance_notice",
    "outcome_notice",
    "recipients_for",
    "notify_outcome",
    "affected_policies",
]
