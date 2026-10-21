"""Process triggers — an event asks for a walk, a job performs it.

WHAT THIS MODULE DECIDES
------------------------
Which processes an event starts, and whether THIS occurrence may start one.
It never walks a process. The walk is handed to ``services.jobs`` and runs in
a job thread; the caller (an alert evaluation inside the scheduler tick, or an
integration-hook dispatch) gets a list of what was queued and returns at once.

WHY NEVER INLINE
----------------
The alert checks run inside ``scheduler_runtime.tick``. A process can contain
SSH reads, HTTP checks with ten-second budgets and a manual gate. Walking it
where the event was noticed would stall every other scheduled action behind
one diagram, and a tick that takes minutes is how "the scheduler is dead"
tickets start. :func:`on_event` therefore calls ``jobs.run_async`` and NOTHING
in this module calls ``process_engine.start_run`` except the job worker —
``tests/test_process_triggers.py`` reads this file's source to keep it so.

THREE RULES THAT BOUND A STORM
------------------------------
1. **One running instance per (process, appliance).** A second trigger while a
   walk is running or parked on a gate is recorded as a run with status
   ``skipped`` and the reason, never queued behind it. An alert that fires every
   three minutes must not stack twenty identical walks.
2. **A budget per process per hour** (``Process.trigger_rate_limit``,
   default 10). Spent means ``skipped`` with the reason. The budget counts
   event-triggered runs that STARTED; skipped rows do not consume it.
3. **Rehearsal unless the process says otherwise.** ``armed_on_trigger`` is off
   by default; on, SATOM writes to an appliance with nobody at the screen, and
   the form says so in one sentence.

Every triggered run carries ``trigger_key`` (the finding or event key) so a
walk in the history can be traced back to the thing that asked for it.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from ..models_process import (DONE, RUN_SKIPPED, RUNNING, TRIGGER_EVENT, WAITING,
                              DEFAULT_TRIGGER_RATE_LIMIT, Process, ProcessRun)

#: The job type the Jobs page shows for a triggered walk.
JOB_TYPE = "process_run"

#: Severity ladder for ``min_severity`` in a trigger filter (alert.fired only).
_SEV_RANK = {"info": 0, "warning": 1, "critical": 2}


# ---------------------------------------------------------------------------
# matching
# ---------------------------------------------------------------------------

def triggered_by(event: str):
    """Enabled processes whose trigger names ``event``, by key."""
    if not event:
        return []
    return (Process.query.filter_by(enabled=True, trigger_event=event)
            .order_by(Process.key.asc()).all())


def _as_int_list(value) -> list[int]:
    out: list[int] = []
    for v in (value or []):
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            continue
    return out


def matches(proc, payload: dict) -> tuple[bool, str]:
    """Does this occurrence pass the process's trigger filter?

    Every key is optional and an empty key means "any". The filter narrows,
    it never widens: a payload that lacks the field a key asks about does NOT
    match (an ``appliance_ids`` filter on an event that names no appliance is
    a filter nothing satisfies, and that is the honest answer).
    """
    flt = proc.trigger_filter or {}
    payload = payload or {}

    products = [str(p) for p in (flt.get("products") or []) if str(p)]
    if products:
        got = str(payload.get("product") or payload.get("kind") or "")
        if got not in products:
            return False, "product %r is not in the trigger filter" % got

    ids = _as_int_list(flt.get("appliance_ids"))
    if ids:
        have = _as_int_list([payload.get("appliance_id")] +
                            list(payload.get("device_ids") or []))
        if not any(i in ids for i in have):
            return False, "the appliance is not in the trigger filter"

    families = [str(f) for f in (flt.get("families") or []) if str(f)]
    if families and str(payload.get("family") or "") not in families:
        return False, "family %r is not in the trigger filter" % payload.get("family")

    floor = str(flt.get("min_severity") or "")
    if floor:
        got = str(payload.get("severity") or "")
        if _SEV_RANK.get(got, -1) < _SEV_RANK.get(floor, 0):
            return False, "severity %r is below the trigger floor %r" % (got, floor)
    return True, ""


# ---------------------------------------------------------------------------
# the two bounds
# ---------------------------------------------------------------------------

def running_instance(proc, appliance_id) -> ProcessRun | None:
    """A walk of ``proc`` on this appliance that has not settled yet."""
    q = ProcessRun.query.filter(ProcessRun.process_id == proc.id,
                                ProcessRun.status.in_((RUNNING, WAITING)))
    if appliance_id is None:
        q = q.filter(ProcessRun.appliance_id.is_(None))
    else:
        q = q.filter(ProcessRun.appliance_id == int(appliance_id))
    return q.order_by(ProcessRun.id.desc()).first()


def budget_left(proc, now: datetime | None = None) -> int:
    """Event-triggered runs this process may still start this hour."""
    limit = proc.trigger_rate_limit
    if limit is None or int(limit) <= 0:
        limit = DEFAULT_TRIGGER_RATE_LIMIT
    since = (now or datetime.utcnow()) - timedelta(hours=1)
    started = (ProcessRun.query
               .filter(ProcessRun.process_id == proc.id,
                       ProcessRun.trigger == TRIGGER_EVENT,
                       ProcessRun.status != RUN_SKIPPED,
                       ProcessRun.started_at >= since)
               .count())
    return max(0, int(limit) - started)


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

def _resolve_appliance(payload: dict):
    """The appliance an event names, if any. By id first, by name second."""
    from ..models import Appliance, db
    aid = payload.get("appliance_id")
    if aid not in (None, ""):
        try:
            row = db.session.get(Appliance, int(aid))
        except (TypeError, ValueError):
            row = None
        if row is not None:
            return row
    name = str(payload.get("appliance") or "").strip()
    if name:
        return Appliance.query.filter_by(name=name).first()
    return None


def _run_product(proc, payload: dict) -> str:
    """The ADOM a triggered run is stamped with: the event's, else the one
    ADOM the process is offered in, else '' (Global)."""
    got = str(payload.get("product") or "")
    if got:
        return got
    prods = proc.products or []
    return str(prods[0]) if len(prods) == 1 else ""


def _skip(proc, appliance, *, event: str, key: str, reason: str, product: str) -> ProcessRun:
    """A run row that records a refused trigger. No steps; the summary says why."""
    from ..models import db
    now = datetime.utcnow()
    run = ProcessRun(
        process_id=proc.id, process_key=proc.key, process_name=proc.name,
        product=product, graph={},
        appliance_id=getattr(appliance, "id", None),
        appliance_name=getattr(appliance, "name", "") or "",
        armed=False, status=RUN_SKIPPED, verdict="", summary="skipped: " + reason,
        trigger=TRIGGER_EVENT, trigger_key=(key or event)[:200],
        started_by="event:" + event, started_at=now, ended_at=now,
    )
    db.session.add(run)
    db.session.commit()
    return run


def _job_worker(proc_id: int, appliance_id, *, armed: bool, event: str,
                key: str, product: str):
    """The ONLY path from a trigger to ``process_engine.start_run``."""
    def worker(flask_app, job_id):
        from ..models import Appliance, db
        from . import jobs
        from . import process_engine as engine
        with flask_app.app_context():
            proc = db.session.get(Process, proc_id)
            if proc is None:
                jobs.finish_error(job_id, "the process was deleted before the walk started")
                return None
            appliance = (db.session.get(Appliance, int(appliance_id))
                         if appliance_id is not None else None)
            jobs.set_progress(job_id, 5, "walking %s" % proc.name)
            run = engine.start_run(proc, appliance=appliance, armed=armed,
                                   trigger=TRIGGER_EVENT, user="event:" + event,
                                   product=product, trigger_key=key or event)
            result = {"run_id": run.id, "status": run.status,
                      "verdict": run.verdict, "armed": bool(run.armed)}
            if run.status == WAITING:
                jobs.finish_success(job_id, message="parked on a manual gate — "
                                    "answer it on the run page", result=result)
            elif run.status == DONE and run.verdict == "ok":
                jobs.finish_success(job_id, message=run.summary, result=result)
            else:
                # A walk that failed or aborted is a job that failed: the
                # Jobs page and the bell must not read a red run as green.
                jobs.finish_error(job_id, (run.summary or run.status)[:300])
            return result
    return worker


def on_event(event: str, payload: dict, *, by: str = "event") -> list[dict]:
    """Queue a walk of every process this event triggers. Returns one row per
    matching process: ``{process, status: queued|skipped, job_id, run_id,
    reason}``. Never raises past a single process; never walks inline.
    """
    from flask import current_app
    from . import jobs
    from .audit import log_action

    out: list[dict] = []
    payload = dict(payload or {})
    key = str(payload.get("key") or "")
    for proc in triggered_by(event):
        ok, why = matches(proc, payload)
        if not ok:
            continue
        product = _run_product(proc, payload)
        appliance = _resolve_appliance(payload)
        try:
            from . import process_kinds as pk
            graph = proc.graph()
            if pk.needs_appliance(graph) and appliance is None:
                run = _skip(proc, None, event=event, key=key, product=product,
                            reason="this process acts on a device and the event "
                                   "named none")
                out.append({"process": proc.key, "status": RUN_SKIPPED,
                            "run_id": run.id, "job_id": "", "reason": run.summary})
                continue
            busy = running_instance(proc, getattr(appliance, "id", None))
            if busy is not None:
                run = _skip(proc, appliance, event=event, key=key, product=product,
                            reason="run #%d of this process is still %s on %s"
                                   % (busy.id, busy.status,
                                      busy.appliance_name or "no appliance"))
                out.append({"process": proc.key, "status": RUN_SKIPPED,
                            "run_id": run.id, "job_id": "", "reason": run.summary})
                continue
            if budget_left(proc) <= 0:
                run = _skip(proc, appliance, event=event, key=key, product=product,
                            reason="the budget of %d event-triggered runs per hour "
                                   "is spent" % (proc.trigger_rate_limit or
                                                 DEFAULT_TRIGGER_RATE_LIMIT))
                out.append({"process": proc.key, "status": RUN_SKIPPED,
                            "run_id": run.id, "job_id": "", "reason": run.summary})
                continue
            armed = bool(proc.armed_on_trigger)
            job = jobs.create_job(
                JOB_TYPE, "Process %s (%s)" % (proc.name, event), by=by,
                meta={"process": proc.key, "event": event, "trigger_key": key,
                      "appliance_id": getattr(appliance, "id", None),
                      "armed": armed, "product": product},
                cancelable=False, background=True)
            jobs.run_async(current_app._get_current_object(), job["id"],
                           _job_worker(proc.id, getattr(appliance, "id", None),
                                       armed=armed, event=event, key=key,
                                       product=product))
            log_action("process.trigger", target=proc.key,
                       extra={"event": event, "key": key, "job": job["id"],
                              "armed": armed,
                              "appliance": getattr(appliance, "name", "") or ""})
            out.append({"process": proc.key, "status": "queued",
                        "job_id": job["id"], "run_id": None, "reason": ""})
        except Exception as exc:  # noqa: BLE001 — one process must not sink the event
            out.append({"process": proc.key, "status": "error", "job_id": "",
                        "run_id": None, "reason": "%s: %s" % (type(exc).__name__, exc)})
    return out


def on_findings(findings, node: str) -> list[dict]:
    """``alert.fired`` for each fresh finding. The alert module calls this for
    the findings that passed the cooldown, whether or not any notification
    sink is on: a trigger is orchestration, not a notification channel."""
    from .alerts import alert_event_payload
    rows: list[dict] = []
    for f in findings:
        key = f.get("key", "")
        try:
            new = on_event("alert.fired", alert_event_payload(f, node), by="alerts")
        except Exception as exc:  # noqa: BLE001 — one finding must not sink the rest
            new = [{"process": "", "status": "error", "job_id": "", "run_id": None,
                    "reason": "%s: %s" % (type(exc).__name__, exc)}]
        for r in new:
            r["key"] = key
        rows.extend(new)
    return rows
