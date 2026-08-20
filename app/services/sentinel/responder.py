"""The response runner — the only component that changes an appliance.

Why this is not in the web worker
---------------------------------
The web process ENQUEUES; this module executes. That is the same split
``satom-updater.path`` already uses in this product, and the reason is not
tidiness: a request handler that writes to firewalls means every future bug in
a view — a stray retry, a double-submitted form, a crawler hitting a URL — is
one hop from a production block. Here the web tier can only ever move a row to
``queued``. Execution runs from ``satom-responder.timer`` under its own unit.

Gates are re-evaluated at EXECUTION time
----------------------------------------
An action approved at 12:00 and executed at 12:03 is executed under 12:03's
state. In between, an operator may have thrown the kill switch, a maintenance
window may have opened, or the source may have been added to the trust list —
each of which is somebody deciding "not this". Trusting the verdict recorded at
enqueue time would carry out a decision the state has since reversed. So
:func:`_execute` calls ``actions.evaluate`` again, and then asks the DEVICE
whether it can even enforce (``transport.preflight``).

Expiry runs even when the kill switch is off
--------------------------------------------
This is the one asymmetry in the file and it is deliberate. Disarming the
response engine must stop NEW blocks; if it also stopped expiry, throwing the
kill switch during an incident would strand every live block permanently — the
safety control would cause the outage. Stopping is not the same as freezing.

Nothing here retries blindly. An action that fails is recorded ``failed`` with
the device's own words, and an action that applied but changed nothing is
recorded ``ineffective`` and escalated to a human. Retrying the thing that just
did not work, harder, is how an automation turns a bad minute into a bad hour.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from ...clients import client_for
from ...models import Appliance, db
from ...models_sentinel import (SentinelAction, SentinelActionResult,
                                SentinelEvent, SentinelIncident)
from . import actions, config, transports
from .. import audit


def _node_role() -> str:
    """``primary`` | ``standby`` | ``unknown``. ``unknown`` is NOT primary: a
    node that cannot say what it is must not be the one writing enforcement."""
    try:
        from ..self_update import node_role
        return node_role() or "unknown"
    except Exception:                                       # pragma: no cover
        return "unknown"


def _why_not_primary(role: str) -> str:
    """The refusal, naming the cause rather than the symptom."""
    if role == "standby":
        return ("this node is the standby — the response runner only ever "
                "acts from the primary, or two nodes race on the same rule")
    try:
        from ...models import db
        uri = str(db.engine.url)
    except Exception:                                       # pragma: no cover
        uri = ""
    if uri.startswith("sqlite"):
        return ("this process is bound to SQLITE, not the production "
                "database: the environment was not loaded, so every query "
                "would succeed against an empty file and a live block would "
                "never be expired. Run it through satom-responder.service, "
                "which passes /opt/satom/.env as its EnvironmentFile.")
    return (f"this node reports role '{role}' — it cannot prove it is the "
            f"primary, and a node that cannot say what it is must not be the "
            f"one writing enforcement rules")


def _client(device: str):
    """A live client for the device named on the action, or (None, reason)."""
    if not device:
        return None, "the action names no device"
    ap = Appliance.query.filter_by(name=device).first()
    if ap is None:
        return None, f"appliance '{device}' is not in the inventory"
    try:
        return client_for(ap), ""
    except Exception as exc:                                # pragma: no cover
        return None, f"could not build a client for '{device}': {exc}"


def _record(action: SentinelAction, *, applied_ok=None, effective=None,
            expected="", observed="", verdict="", detail=None):
    res = SentinelActionResult(
        action_id=action.id, applied_ok=applied_ok, effective=effective,
        expected=expected[:300], observed=observed[:300], verdict=verdict)
    res.detail = detail or {}
    db.session.add(res)
    return res


# --------------------------------------------------------------------------- #
#  1. Apply                                                                     #
# --------------------------------------------------------------------------- #
def _execute(action: SentinelAction) -> str:
    incident = action.incident
    if incident is None:
        action.status = SentinelAction.STATUS_FAILED
        action.detail = "the incident this action belongs to is gone"
        return action.status

    verdict = actions.evaluate(incident, action.action_type)
    if not verdict.get("allowed"):
        action.status = SentinelAction.STATUS_REJECTED
        action.detail = f"refused at execution time: {verdict.get('reason')}"
        _record(action, applied_ok=False, verdict="refused",
                expected="all gates pass at execution time",
                observed=verdict.get("reason", ""),
                detail={"checks": verdict.get("checks", [])})
        return action.status

    transport = transports.get(action.action_type)
    if transport is None:
        action.status = SentinelAction.STATUS_FAILED
        action.detail = (f"no verified transport for '{action.action_type}' — "
                         f"it is a specification, not an executable action")
        _record(action, applied_ok=False, verdict="no_transport",
                observed=action.detail)
        return action.status

    params = dict(action.params or {})
    client, why = _client(params.get("device") or incident.device or "")
    if client is None:
        action.status = SentinelAction.STATUS_FAILED
        action.detail = why
        _record(action, applied_ok=False, verdict="no_client", observed=why)
        return action.status

    ok, reason = transport.preflight(client, params)
    if not ok:
        action.status = SentinelAction.STATUS_FAILED
        action.detail = f"preflight: {reason}"
        _record(action, applied_ok=False, verdict="preflight_failed",
                expected="the appliance can enforce this action",
                observed=reason)
        return action.status

    result = transport.apply(client, params)
    if not result.ok:
        action.status = SentinelAction.STATUS_FAILED
        action.detail = result.detail
        _record(action, applied_ok=False, verdict="apply_failed",
                observed=result.detail)
        return action.status

    # The write is not the proof. Read the device back.
    present, detail = transport.verify_applied(client, result.handle)
    action.status = (SentinelAction.STATUS_APPLIED if present
                     else SentinelAction.STATUS_FAILED)
    action.applied_at = datetime.utcnow()
    action.detail = detail
    params["handle"] = result.handle
    params["baseline_events"] = _event_count(incident.src_ip,
                                             _effect_window(), before=True)
    action.params = params
    _record(action, applied_ok=present, verdict="applied" if present else "not_applied",
            expected="the rule is present on the appliance",
            observed=detail, detail=result.evidence)
    audit.log_action("sentinel.action.apply",
                     f"{action.action_type} {params.get('src_ip')} on "
                     f"{params.get('device')} -> {action.status}")
    return action.status


# --------------------------------------------------------------------------- #
#  2. Expire — the primary rollback                                             #
# --------------------------------------------------------------------------- #
def expire_due() -> list:
    """Undo every applied action whose TTL has run out. Runs unconditionally."""
    now = datetime.utcnow()
    due = (SentinelAction.query
           .filter(SentinelAction.status == SentinelAction.STATUS_APPLIED,
                   SentinelAction.expires_at.isnot(None),
                   SentinelAction.expires_at <= now).all())
    done = []
    for action in due:
        transport = transports.get(action.action_type)
        params = dict(action.params or {})
        client, why = _client(params.get("device") or "")
        if transport is None or client is None:
            # Say so loudly. An expiry that could not run leaves a live block
            # with nothing scheduled to lift it, which is worse than a failure
            # to apply and must not look like a quiet success.
            action.detail = f"expiry could not run: {why or 'no transport'}"
            _record(action, verdict="expiry_blocked", observed=action.detail)
            done.append((action.id, "blocked"))
            continue
        out = transport.rollback(client, params.get("handle") or {})
        action.status = (SentinelAction.STATUS_EXPIRED if out.ok
                         else SentinelAction.STATUS_FAILED)
        action.detail = out.detail
        _record(action, verdict="expired" if out.ok else "expiry_failed",
                expected="the rule is gone from the appliance",
                observed=out.detail)
        audit.log_action("sentinel.action.expire",
                         f"{action.action_type} {params.get('src_ip')} -> "
                         f"{action.status}")
        done.append((action.id, action.status))
    if done:
        db.session.commit()
    return done


# --------------------------------------------------------------------------- #
#  3. Effectiveness — applied is not effective                                  #
# --------------------------------------------------------------------------- #
def _effect_window() -> int:
    return max(1, int(config.get("effect_window_minutes") or 5))


def _event_count(src_ip: str, minutes: int, *, before: bool,
                 pivot: datetime | None = None) -> int:
    """Attack events from this source in the window before/after ``pivot``."""
    if not src_ip:
        return 0
    pivot = pivot or datetime.utcnow()
    span = timedelta(minutes=minutes)
    lo, hi = (pivot - span, pivot) if before else (pivot, pivot + span)
    return (SentinelEvent.query
            .filter(SentinelEvent.src_ip == src_ip,
                    SentinelEvent.ts >= lo, SentinelEvent.ts < hi).count())


def verify_effect() -> list:
    """Judge whether applied actions actually changed anything."""
    window = _effect_window()
    cutoff = datetime.utcnow() - timedelta(minutes=window)
    candidates = (SentinelAction.query
                  .filter(SentinelAction.status == SentinelAction.STATUS_APPLIED,
                          SentinelAction.applied_at.isnot(None),
                          SentinelAction.applied_at <= cutoff).all())
    out = []
    for action in candidates:
        if any(r.effective is not None for r in action.results):
            continue                      # already judged; never re-judge
        params = dict(action.params or {})
        src = params.get("src_ip") or ""
        before = int(params.get("baseline_events") or 0)
        after = _event_count(src, window, before=False,
                             pivot=action.applied_at)
        if before == 0:
            verdict, effective = "unknown", None
            observed = (f"no attack events from {src} in the {window} min "
                        f"before the action — nothing to compare against")
        elif after == 0:
            verdict, effective = "success", True
            observed = f"{before} events before, 0 after"
        elif after >= before * 0.5:
            verdict, effective = "ineffective", False
            observed = f"{before} events before, {after} after — barely changed"
        else:
            verdict, effective = "partial", True
            observed = f"{before} events before, {after} after"
        _record(action, applied_ok=True, effective=effective, verdict=verdict,
                expected=f"attack volume from {src} falls after the action",
                observed=observed,
                detail={"before": before, "after": after, "window_min": window})
        if verdict == "ineffective":
            _escalate(action, observed)
        out.append((action.id, verdict))
    if out:
        db.session.commit()
    return out


def _escalate(action: SentinelAction, observed: str) -> None:
    """An action that did nothing is a finding, not a retry trigger.

    There is no ``escalated`` incident status and none is invented here: adding
    a state means every filter, badge and count that enumerates statuses has to
    learn it, and half of them would not. What DOES happen is the correction
    that matters — an incident sitting in ``mitigated`` on the strength of an
    action that changed nothing is making a false claim, so it goes back to
    ``open`` where it reads as needing a person.
    """
    incident = action.incident
    if incident is None:
        return
    if incident.status == SentinelIncident.STATUS_MITIGATED:
        incident.status = SentinelIncident.STATUS_OPEN
    stamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    incident.resolution_note = (
        (incident.resolution_note or "") +
        f"\n[{stamp}] action {action.action_type} applied but INEFFECTIVE: "
        f"{observed}. Escalated for a human decision; Sentinel does not retry "
        f"the same action.").strip()
    audit.log_action("sentinel.action.ineffective",
                     f"{action.action_type} on incident {incident.ref}: {observed}")


# --------------------------------------------------------------------------- #
#  4. The tick                                                                  #
# --------------------------------------------------------------------------- #
def drain(limit: int = 10) -> list:
    """Execute queued actions. Silent no-op while the kill switch is off."""
    if not config.get("response_enabled"):
        return []
    queued = (SentinelAction.query
              .filter(SentinelAction.status == SentinelAction.STATUS_QUEUED)
              .order_by(SentinelAction.created_at).limit(limit).all())
    out = []
    for action in queued:
        out.append((action.id, _execute(action)))
    if out:
        db.session.commit()
    return out


def tick() -> dict:
    """One full pass. Expiry first — freeing precedes acting, always.

    If applying ran first, a pass that hits the circuit breaker could refuse a
    new block while an expired one it was about to lift still counted against
    the ceiling.

    Refuses outright on a standby. Two nodes applying and expiring against the
    same appliance would race — one deleting the member the other had just
    written — and which one won would depend on tick order. The read-only
    replica is not the guard: relying on it turns a design error into a
    database error inside the component that writes to firewalls, and it
    disappears the moment the standby is promoted.
    """
    role = _node_role()
    if role != "primary":
        return {"expired": [], "applied": [], "judged": [], "skipped": role,
                "reason": _why_not_primary(role),
                "armed": bool(config.get("response_enabled"))}
    expired = expire_due()
    applied = drain()
    judged = verify_effect()
    return {"expired": expired, "applied": applied, "judged": judged,
            "armed": bool(config.get("response_enabled"))}
