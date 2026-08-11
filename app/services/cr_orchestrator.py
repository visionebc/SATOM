"""Change-request orchestration ACROSS systems: CRM ticket -> approval ->
NetBox maintenance window -> upgrade -> window close -> customer notice.

:mod:`change_requests` owns the CR's own lifecycle (draft/approved/scheduled/
in_progress/completed/failed) and never leaves this product. THIS module owns
everything that leaves it: the external CRQ ticket raised through a user hook,
the external approval verdict, and the maintenance window written into NetBox.

Three properties hold the design together, and each one is a guard test:

1. **Fail-closed approval.** When a CR is bound to an external approver
   (``approval_mode="external"``) it is runnable only after that approver said
   yes *explicitly* (``external_approved_at``). A CRM that is unreachable,
   slow, or returning garbage is NOT an approval. The whole point of routing
   approval through a change-management system is that silence means no.

2. **The window is opened by the orchestrator and closed by the outcome.** A
   failed upgrade leaves the NetBox window in ``error`` rather than closing it
   as if the change had landed - and the customer notice says the change did
   not happen. Closing a window is a statement about the device, so it may only
   be made by whatever actually observed the device.

3. **Nothing external can change the CR's outcome.** NetBox being down, a hook
   erroring, SMTP refusing - all of these are recorded on the CR and none of
   them re-grade it. An upgrade that worked worked whether or not a ticket
   system agreed to write it down.

Import side-effect-free: importing this module touches no DB, contacts no
device and reaches no external system. Every integration is imported lazily
inside the function that uses it so a deployment with the integrations disabled
(or the modules absent) still boots.
"""
from __future__ import annotations

from datetime import datetime

from ..models import Appliance, ChangeRequest, ChangeRequestEvent, db

# Window bookkeeping states for ChangeRequest.mw_state.
#   none   - no window was ever requested (integration off, or CR never ran)
#   open   - NetBox acknowledged the window and it is still open
#   closed - the window was closed after a run we observed
#   error  - we tried and NetBox refused/never answered. NOT the same as none:
#            "we never asked" and "we asked and it failed" must stay
#            distinguishable, or a silent integration failure reads as a
#            deliberate decision not to use one.
MW_STATES = ("none", "open", "closed", "error")

APPROVAL_MODES = ("manual", "external")

_LOG_MAX = 8000

# How many affected-policy NAMES ride in one hook payload. A window over one
# appliance carried a few dozen; a bulk window over sixty FortiWeb carries tens
# of thousands, and the payload is written to a queue file and POSTed to
# somebody else's ticket system. The cap is NOT a silent truncation: the exact
# total always travels in ``policy_count`` and ``policies_truncated`` says so
# out loud, because a receiver that reads 500 names and believes that is the
# whole outage under-states it by an order of magnitude.
MAX_POLICY_NAMES = 500


# --------------------------------------------------------------------------- #
#  Timeline / log helpers                                                       #
# --------------------------------------------------------------------------- #
def _event(cr, kind: str, by: str, detail: str) -> None:
    db.session.add(ChangeRequestEvent(
        cr_id=cr.id, kind=kind, by=by, detail=(detail or "")[:2000],
        ts=datetime.utcnow()))
    db.session.commit()


def _log(cr, line: str) -> None:
    """Append to the CR's integration log. Kept separate from the timeline:
    the timeline is the record of state changes, this is the noisy detail of
    talking to systems we do not control."""
    stamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    cr.integration_log = ((cr.integration_log or "") + f"\n[{stamp}] {line}")[-_LOG_MAX:]
    db.session.commit()


def _devices(cr) -> list:
    ids = cr.device_ids_list
    if not ids:
        return []
    return Appliance.query.filter(Appliance.id.in_(ids)).all()


# --------------------------------------------------------------------------- #
#  1. CRQ ticket (external change-management record)                            #
# --------------------------------------------------------------------------- #
def request_crq(cr, *, by: str = "operator") -> dict:
    """Raise the external change ticket by dispatching the ``change.requested``
    hook. Returns ``{dispatched: int, detail: str}``.

    The ticket id is NOT known here: hooks run out-of-process, so the CRM's
    answer arrives later through :func:`record_crq`. Pretending to return an id
    synchronously would mean either blocking the web worker on someone else's
    CRM or inventing one.

    **One ticket for the whole window.** A change covering sixty appliances
    raises ONE CRQ carrying sixty baselines, not sixty tickets — and the
    payload has to actually carry them. It used to send ``device_ids``: bare
    integers that mean nothing outside this database, with no names, no
    products and no pre-flight evidence at all. A change-management system
    received a request to take down "[17, 18, 19]" and an approver had to come
    back here to find out what that was. The evidence the whole bulk pre-upgrade
    exists to produce never left the product."""
    try:
        from . import integration_hooks as hooks
    except ImportError:  # pragma: no cover - integrations not installed
        return {"dispatched": 0, "detail": "integrations unavailable"}

    names = _policy_names(cr)
    evidence, uncovered = _evidence_rows(cr)
    payload = {
        "cr_id": cr.id,
        # The human reference printed on the change document. Without it the
        # ticket and the paper an approver signs share no identifier, and
        # reconciling them means somebody opening this console.
        "cr_ref": getattr(cr, "ref", "") or "",
        "title": cr.title,
        "status": cr.status,
        "action": cr.action,
        "risk": cr.risk,
        "reason": cr.reason or "",
        "device_ids": cr.device_ids_list,
        "devices": _device_rows(cr),
        "device_count": len(cr.device_ids_list),
        "evidence": evidence,
        # NAMED, never inferred from a short list. "twelve of twenty devices
        # have a baseline" is only actionable if the other eight are on the
        # ticket; a receiver counting list lengths cannot tell an appliance
        # that was never pre-flighted from one this payload simply omitted.
        "evidence_missing": uncovered,
        "policies": names[:MAX_POLICY_NAMES],
        "policy_count": len(names),
        "policies_truncated": len(names) > MAX_POLICY_NAMES,
        # Whether THIS ticket system is the gate. A CR in external mode cannot
        # run until an approval verdict comes back through record_crq's sibling
        # — and a receiver that was never told it holds the gate will not send
        # one, leaving the window to elapse with nobody aware they were waited on.
        "approval_mode": (getattr(cr, "approval_mode", "") or "manual"),
        # An existing reference means this is a RE-request. Sending it lets a
        # receiver update its ticket instead of opening a second one for the
        # same window; without it, a double-clicked button is two CRQs.
        "crq_ref": getattr(cr, "crq_ref", "") or "",
        "window_start": _iso(cr.window_start),
        "window_end": _iso(cr.window_end),
        "requested_by": cr.requested_by or by,
    }
    results = hooks.dispatch("change.requested", payload, by=by)
    detail = (f"{len(payload['devices'])} device(s), {len(evidence)} with a "
              f"stored pre-upgrade run"
              + (f", {len(uncovered)} without" if uncovered else ""))
    _log(cr, f"change.requested dispatched to {len(results)} hook(s) — {detail}")
    if results:
        _event(cr, "crq_requested", by,
               f"CRQ requested via {len(results)} integration hook(s) — {detail}")
    return {"dispatched": len(results), "detail": "queued",
            "evidence": len(evidence), "uncovered": uncovered,
            "policy_count": len(names),
            "truncated": bool(payload["policies_truncated"]),
            "requests": [r.get("request_id") for r in results]}


def record_crq(cr, ref: str, url: str = "", *, by: str = "integration") -> None:
    """Store the external ticket reference once the CRM answered."""
    cr.crq_ref = (ref or "")[:128]
    cr.crq_url = (url or "")[:512]
    db.session.commit()
    _event(cr, "crq_created", by, f"CRQ {cr.crq_ref}")
    _log(cr, f"CRQ recorded: {cr.crq_ref}")


def record_external_approval(cr, *, approved: bool, by: str = "integration",
                             detail: str = "") -> None:
    """Record the external approver's verdict.

    ``approved=False`` stamps nothing - it clears the timestamp. A CR that was
    approved and then rejected must go back to being un-runnable, and leaving a
    stale timestamp behind would let a withdrawn approval still open a window."""
    if approved:
        cr.external_approved_at = datetime.utcnow()
        cr.external_approved_by = (by or "")[:64]
    else:
        cr.external_approved_at = None
    db.session.commit()
    _event(cr, "approved" if approved else "rejected", by,
           detail or ("external approval granted" if approved
                      else "external approval withdrawn/denied"))
    _log(cr, f"external approval: {'granted' if approved else 'denied'}"
             f"{(' - ' + detail) if detail else ''}")
    if approved:
        announce_approved(cr, by=by)


def external_gate(cr, now: datetime | None = None) -> tuple[bool, str]:
    """``(ok, reason)`` - the FAIL-CLOSED external-approval check.

    A CR in ``manual`` mode passes (its approval is the in-product one that
    :func:`change_requests.cr_runnable` already checked). A CR in ``external``
    mode passes only with an explicit ``external_approved_at``. Every failure
    mode of the external system - down, slow, ambiguous answer, never asked -
    lands on the same side of this line: not approved."""
    mode = (getattr(cr, "approval_mode", "") or "manual").strip().lower()
    if mode not in APPROVAL_MODES:
        # An unrecognised mode is treated as external, i.e. the strict side. A
        # typo in a config field must not silently downgrade the gate.
        return False, f"unknown approval mode {mode!r}"
    if mode == "manual":
        return True, "manual approval"
    if getattr(cr, "external_approved_at", None) is None:
        return False, "waiting for external change approval"
    return True, "external approval on record"


# --------------------------------------------------------------------------- #
#  2. Maintenance window in NetBox                                              #
# --------------------------------------------------------------------------- #
def open_window(cr, *, by: str = "scheduler") -> dict:
    """Open the NetBox maintenance window for every device on this CR.

    Returns ``{ok, opened, failed, detail}``. Never raises: NetBox is an
    external system and its absence must not stop a change the operator already
    approved. It IS recorded - ``mw_state='error'`` plus a log line - so nobody
    later reads a missing window as a decision.

    Idempotent: a CR whose window is already ``open`` returns without opening a
    second one (a retried fire must not litter NetBox with duplicate windows)."""
    if (cr.mw_state or "none") == "open":
        return {"ok": True, "opened": 0, "failed": 0, "detail": "already open"}
    try:
        from . import netbox_client as netbox
    except ImportError:  # pragma: no cover
        return {"ok": False, "opened": 0, "failed": 0,
                "detail": "netbox integration unavailable"}
    if not netbox.is_configured():
        _log(cr, "maintenance window NOT opened: NetBox is not configured")
        return {"ok": False, "opened": 0, "failed": 0,
                "detail": "netbox not configured"}

    refs, failures = [], []
    for dev in _devices(cr):
        res = netbox.open_window(
            dev.id, cr_id=cr.id, title=cr.title, start=cr.window_start,
            end=cr.window_end, reason=cr.reason or "")
        if res.get("ok"):
            refs.append(f"{dev.name}={res.get('ref', '')}")
        else:
            failures.append(f"{dev.name}: {res.get('detail', 'failed')}")

    cr.mw_ref = ",".join(refs)[:512]
    cr.mw_state = "open" if refs and not failures else ("error" if failures else "none")
    db.session.commit()
    detail = f"opened {len(refs)}, failed {len(failures)}"
    _log(cr, f"maintenance window: {detail}"
             + (f" - {'; '.join(failures)}" if failures else ""))
    _event(cr, "window_opened", by, detail)
    _dispatch_quiet("window.opening", cr, by=by, extra={
        "action": cr.action, "policies": _policy_names(cr)})
    return {"ok": bool(refs) and not failures, "opened": len(refs),
            "failed": len(failures), "detail": detail}


def close_window(cr, *, ok: bool, summary: str = "", by: str = "scheduler") -> dict:
    """Close the NetBox window after the run.

    ``ok`` is the OUTCOME OF THE CHANGE, not of this call. A failed upgrade
    still closes its window - the window is over either way - but it closes with
    the failure recorded, and ``mw_state`` becomes ``closed`` only when NetBox
    confirmed. A window we could not close stays ``error`` so the operator knows
    NetBox still shows a device in maintenance."""
    if (cr.mw_state or "none") not in ("open", "error"):
        return {"ok": True, "detail": "no window to close"}
    try:
        from . import netbox_client as netbox
    except ImportError:  # pragma: no cover
        return {"ok": False, "detail": "netbox integration unavailable"}

    failures, closed = [], 0
    for chunk in (cr.mw_ref or "").split(","):
        ref = chunk.split("=", 1)[-1].strip()
        if not ref:
            continue
        res = netbox.close_window(ref, ok=ok, summary=summary)
        if res.get("ok"):
            closed += 1
        else:
            failures.append(f"{ref}: {res.get('detail', 'failed')}")

    cr.mw_state = "closed" if closed and not failures else "error"
    db.session.commit()
    detail = f"closed {closed}, failed {len(failures)}"
    _log(cr, f"maintenance window close: {detail}"
             + (f" - {'; '.join(failures)}" if failures else ""))
    _event(cr, "window_closed", by, detail)
    _dispatch_quiet("window.closing", cr, by=by,
                    extra={"outcome": "ok" if ok else "failed",
                           "result_summary": summary})
    return {"ok": not failures, "detail": detail}


# --------------------------------------------------------------------------- #
#  3. Executor entry points (called from change_requests.start/finish)          #
# --------------------------------------------------------------------------- #
def on_start(cr, *, by: str = "scheduler") -> None:
    """Everything that must happen the moment an authorized CR begins running.

    Best-effort BY CONTRACT - see the module docstring. A raise here would abort
    an upgrade that was already authorized, because a ticket system was down."""
    try:
        open_window(cr, by=by)
    except Exception as exc:  # noqa: BLE001 - external systems must not abort a change
        _safe_log(cr, f"window open raised: {exc}")


def on_finish(cr, outcome: str, *, summary: str = "", by: str = "scheduler") -> None:
    """Everything that must happen once the run is over: close the window, tell
    the hooks, mail the affected customers. Order matters - the window closes
    before anyone is told service is restored."""
    ok = outcome == "ok"
    try:
        close_window(cr, ok=ok, summary=summary, by=by)
    except Exception as exc:  # noqa: BLE001
        _safe_log(cr, f"window close raised: {exc}")
    try:
        _dispatch_per_device(cr, ok=ok, summary=summary, by=by)
    except Exception as exc:  # noqa: BLE001
        _safe_log(cr, f"hook dispatch raised: {exc}")
    try:
        from . import change_requests as crs
        crs.notify_outcome(cr, by=by)
    except Exception as exc:  # noqa: BLE001
        _safe_log(cr, f"outcome notice raised: {exc}")


# --------------------------------------------------------------------------- #
#  helpers                                                                      #
# --------------------------------------------------------------------------- #
def announce_approved(cr, *, by: str = "operator") -> int:
    """Fire ``change.approved`` — the gate is passed, downstream systems may act.

    Emitted from BOTH approval paths (the in-product approve() and an external
    authority's verdict): they are the same fact from two doors, and a hook
    bound to "this change was approved" must not have to know which one.
    """
    approved_at = getattr(cr, "approved_at", None) or getattr(
        cr, "external_approved_at", None)
    return _dispatch_quiet("change.approved", cr, by=by, extra={
        "action": cr.action,
        "risk": cr.risk,
        "policies": _policy_names(cr),
        "requested_by": cr.requested_by or "",
        "approved_by": (getattr(cr, "approved_by", "") or
                        getattr(cr, "external_approved_by", "") or by),
        "approved_at": _iso(approved_at),
    })


def _device_rows(cr) -> list:
    """The appliances this change takes down, as an external system can read them.

    Ordered by NAME, not by id: a ticket body is read by a human, and row order
    that follows an internal sequence looks arbitrary to everyone outside this
    database. ``firmware`` is the version the box is running NOW — the
    from-version an approver needs to sanity-check the change against.
    """
    rows = []
    for dev in sorted(_devices(cr), key=lambda d: (d.name or "").lower()):
        rows.append({
            "appliance_id": dev.id,
            "appliance": dev.name or "",
            "kind": getattr(dev, "kind", "") or "",
            "host": getattr(dev, "host", "") or "",
            "firmware": getattr(dev, "firmware", "") or "",
        })
    return rows


def _evidence_rows(cr) -> tuple[list, list]:
    """``(evidence, uncovered)`` — one pre-flight summary PER APPLIANCE, plus
    the names of the appliances that have none.

    Reads the bridge table through :func:`prep_store.preps_for_cr`, so a change
    raised before that table existed still reports the single run it carried
    rather than reading as evidence-free.

    Only the VERDICT and the facts behind it travel — never the whole stored
    result. That blob holds a config-backup listing and per-service probe rows
    for every published service on the box: megabytes per appliance, shipped
    into a third-party ticket system that never asked for the fleet's service
    topology. What an approver needs is whether the pre-flight passed, when,
    against which firmware, and whether a rollback point exists.
    """
    try:
        from . import prep_store
    except ImportError:  # pragma: no cover
        return [], []
    devices = _devices(cr)
    by_id = {d.id: d for d in devices}
    # prep_store.coverage is the ONE author of "which appliances have a
    # baseline". Recomputing it here would let the ticket and the console
    # disagree about the same change.
    cov = prep_store.coverage(cr, devices)
    evidence = []
    for prep in cov["by_appliance"].values():
        dev = by_id.get(prep.appliance_id)
        result = prep.result_dict if isinstance(prep.result_dict, dict) else {}
        backup = result.get("backup") if isinstance(result.get("backup"), dict) else {}
        evidence.append({
            "prep_id": prep.id,
            "appliance_id": prep.appliance_id,
            "appliance": (dev.name if dev is not None else "") or "",
            "ok": bool(prep.ok),
            "summary": prep.summary or "",
            "firmware": (prep.firmware or "").strip(),
            # Quoted ONLY when the backup actually succeeded. Naming a backup
            # that failed puts a rollback in writing with nothing behind it.
            "backup": ((backup.get("name") or "").strip()
                       if backup.get("ok") else ""),
            "services": len(prep.inventory_list),
            "at": _iso(prep.created_at),
        })
    evidence.sort(key=lambda r: (r["appliance"] or "").lower())
    return evidence, list(cov["missing"])


def _policy_names(cr) -> list:
    """The affected server-policy NAMES, which is what the event contract
    documents. The CR stores richer dicts; sending those instead would hand a
    hook a shape its documentation never described."""
    import json
    try:
        rows = json.loads(cr.policies or "[]")
    except (ValueError, TypeError):
        return []
    if not isinstance(rows, list):
        return []
    out = []
    for row in rows:
        name = row.get("policy") if isinstance(row, dict) else row
        if name and name not in out:
            out.append(name)
    return out


def _dispatch_per_device(cr, *, ok: bool, summary: str, by: str) -> int:
    """``upgrade.finished`` / ``upgrade.failed`` are documented PER APPLIANCE,
    so they are emitted per appliance rather than once per change request.

    ``to_version`` is deliberately ABSENT rather than null: the change request
    knows which image was requested, not which firmware the box came back
    running. A null there would look like a measurement that was taken and
    found empty."""
    try:
        from . import integration_hooks as hooks
    except ImportError:  # pragma: no cover
        return 0
    import json
    try:
        params = json.loads(cr.params or "{}")
    except (ValueError, TypeError):
        params = {}
    event = "upgrade.finished" if ok else "upgrade.failed"
    sent = 0
    for dev in _devices(cr):
        payload = {
            "appliance_id": dev.id,
            "appliance": dev.name,
            "kind": getattr(dev, "kind", ""),
            "from_version": getattr(dev, "firmware", "") or "",
            "image": params.get("image") or params.get("filename") or "",
            "cr_id": cr.id,
        }
        if ok:
            payload["dry_run"] = bool(params.get("dry_run"))
        else:
            payload["stage"] = "change-request"
            payload["error"] = summary or "run failed"
        try:
            sent += len(hooks.dispatch(event, payload, by=by))
        except Exception as exc:  # noqa: BLE001
            _safe_log(cr, f"{event} dispatch failed for {dev.name}: {exc}")
    return sent


def _dispatch_quiet(event: str, cr, *, by: str, extra: dict | None = None) -> int:
    try:
        from . import integration_hooks as hooks
    except ImportError:  # pragma: no cover
        return 0
    payload = {
        "cr_id": cr.id,
        "title": cr.title,
        "device_ids": cr.device_ids_list,
        "window_start": _iso(cr.window_start),
        "window_end": _iso(cr.window_end),
    }
    payload.update(extra or {})
    try:
        results = hooks.dispatch(event, payload, by=by)
    except Exception as exc:  # noqa: BLE001
        _safe_log(cr, f"{event} dispatch failed: {exc}")
        return 0
    if results:
        _safe_log(cr, f"{event} dispatched to {len(results)} hook(s)")
    return len(results)


def _safe_log(cr, line: str) -> None:
    """Log without letting a broken session turn bookkeeping into an outage."""
    try:
        _log(cr, line)
    except Exception:  # noqa: BLE001
        db.session.rollback()


def _iso(dt) -> str | None:
    """Stored windows are naive UTC. Emit an EXPLICIT +00:00 offset: a naive
    string handed to an external system is read in that system's local zone,
    which is how a window silently moves by hours."""
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


__all__ = [
    "MW_STATES", "APPROVAL_MODES",
    "request_crq", "record_crq", "record_external_approval", "external_gate",
    "announce_approved",
    "open_window", "close_window", "on_start", "on_finish",
]
