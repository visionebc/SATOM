"""Triggers → event automations: the orchestrator's dispatch.

WHAT HAPPENS WHEN SOMETHING HAPPENS
-----------------------------------
:func:`emit` is called where an event is noticed: an alert evaluation (for
every FRESH finding, whatever the notification sinks say — a trigger is a plan,
not a channel), a change-request transition, the end of an event automation,
and ``POST /api/v1/events`` from an outside system. It finds the enabled
triggers that name the event, checks each one's conditions, its cooldown per
subject and its hourly budget, RECORDS the outcome (``trigger_fires``) and
queues one JOB per enabled automation bound to it. It never runs an automation
inline: an alert evaluation runs inside the scheduler tick, and an app with SSH
reads there would stall every scheduled action behind it. ``tests/test_triggers.py`` reads this
file's source to keep :func:`_perform` reachable only from the job worker.

WHAT AN AUTOMATION CAN DO
-------------------------
Every kind delegates to the runner SATOM already has, so an automation obeys
the same gates as the page that owns the thing it runs:

* ``app``      — a published Python Studio app, run as the automation's owner
  (who must be allowed to use it), with ``{{ event }}`` in its scope.
* ``script`` / ``api_call`` / ``sql_query`` / ``store_write`` — ONE Studio step
  (``studio_flow``): a Script Library script, a call to an HTTP connection
  (an API Catalog endpoint when the connection is pinned), SQL over a
  PostgreSQL connection, a data-store write. Same validation, same rehearsal.
* ``hook``     — an integration hook, through the de-privileged runner.
* ``action``   — an existing scheduled action, run now through
  ``scheduled_actions.execute_and_record`` (its change-request gates intact).
* ``notify``   — the in-app bell and/or an e-mail, text rendered from the event.

CHAINING, AND WHAT STOPS A LOOP
-------------------------------
A finished automation emits ``automation.finished``; a trigger on that event
is how "when the diagnostics walk FAILS, open a ticket" is written. Each hop
carries a depth, and :data:`MAX_DEPTH` hops is the end of the chain: a trigger
on ``automation.finished`` that matches its own automation would otherwise be
a loop with a job queue for a body. The refusal is recorded like any other.
"""
from __future__ import annotations

import fnmatch
import json
import re
import time
from datetime import datetime, timedelta

from ..models_triggers import (FIRE_MATCHED, FIRE_SUPPRESSED, RUN_FAILED, RUN_OK,
                               RUN_QUEUED, RUN_RUNNING, RUN_SKIPPED, EventAutomation,
                               EventAutomationRun, Trigger, TriggerFire)

#: Hops of ``automation.finished`` a chain may take.
MAX_DEPTH = 3
#: The job type the Jobs page shows for an automation.
JOB_TYPE = "event_automation"
#: Rows kept in the two history tables (oldest pruned first).
KEEP_FIRES = 10_000
KEEP_RUNS = 10_000
#: Payload bytes stored on a fire row.
PAYLOAD_CAP = 16_000
#: How long a job waits for a hook it queued (the runner is another unit).
HOOK_WAIT_EXTRA_S = 30
HOOK_POLL_S = 1.0

_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,47}$")
_SEV_RANK = {"info": 0, "warning": 1, "critical": 2}

# --------------------------------------------------------------------------- #
#  the event catalog                                                           #
# --------------------------------------------------------------------------- #
#: Events that exist only for triggers (the hook catalog has the rest).
OWN_EVENTS: dict[str, dict] = {
    "automation.finished": {
        "description": "An event automation finished (ok, failed or skipped). "
                       "A trigger on it chains one automation after another.",
        "payload": {
            "automation": "str — the automation's key",
            "automation_name": "str",
            "trigger": "str — the key of the trigger that started it",
            "kind": "str — app | script | api_call | sql_query | "
                    "store_write | hook | action | notify",
            "status": "str — ok | failed | skipped",
            "summary": "str — one line about what happened",
            "ref": "str — where the real run is recorded (process-run:12, "
                   "app-run:5, …)",
            "armed": "bool — false when it ran as a rehearsal",
            "subject": "str — the subject of the event that started the chain",
            "appliance_id": "int|null", "product": "str",
            "depth": "int — hops since the first event",
        },
        "example": {
            "automation": "collect-diagnostics", "automation_name": "Collect diagnostics",
            "trigger": "critical-device-alert", "kind": "app", "status": "failed",
            "summary": "app diag v2 run #41: failed",
            "ref": "app-run:41", "armed": False, "subject": "device.fortiweb01",
            "appliance_id": 3, "product": "fortiweb", "depth": 1,
        },
    },
    "api.event": {
        "description": "An outside system posted an event to POST /api/v1/events "
                       "(a monitoring tool, a CI pipeline, a ticketing system).",
        "payload": {
            "type": "str — the caller's event type, e.g. 'ticket.created'",
            "subject": "str — what the cooldown is counted on ('' = the type)",
            "source": "str — the API token's id",
            "product": "str — the token's ADOM, or the one the caller named "
                       "from a Global token",
            "appliance_id": "int|null", "data": "object — anything the caller sent",
        },
        "example": {"type": "ticket.approved", "subject": "CHG0012345",
                    "source": "tok_abc123", "product": "fortiweb", "appliance_id": None,
                    "data": {"ticket": "CHG0012345", "approver": "jdoe"}},
    },
}

#: What the cooldown is counted on, per event.
_SUBJECT = {
    "alert.fired": ("key",), "intent.deviation": ("key",),
    "change.requested": ("cr_id",), "change.approved": ("cr_id",),
    "window.opening": ("cr_id",), "window.closing": ("cr_id",),
    "upgrade.finished": ("cr_id", "appliance_id"),
    "upgrade.failed": ("cr_id", "appliance_id"),
    "automation.finished": ("automation", "subject"),
    "api.event": ("subject",),
}


def events() -> dict[str, dict]:
    """Every event a trigger may name: the integration-hook catalog (the
    published contract) plus the trigger-only events above."""
    from . import integration_hooks as ih
    out = {k: {"description": v.get("description", ""), "payload": v.get("payload", {}),
               "example": v.get("example", {}), "source": "hooks"}
           for k, v in ih.EVENTS.items()}
    for k, v in OWN_EVENTS.items():
        out[k] = dict(v, source="triggers")
    return out


def event_names() -> list[str]:
    return sorted(events())


def subject_of(event: str, payload: dict) -> str:
    keys = _SUBJECT.get(event, ("key",))
    parts = [str(payload.get(k)) for k in keys if payload.get(k) not in (None, "")]
    if event == "api.event" and not parts:
        parts = [str(payload.get("type") or "")]
    return ":".join(parts)[:200]


# --------------------------------------------------------------------------- #
#  conditions                                                                  #
# --------------------------------------------------------------------------- #
WHERE_OPS = ("equals", "not_equals", "contains", "glob", "greater", "less", "empty",
             "not_empty")
#: The keys a condition may hold, for the form and for clean_conditions.
CONDITION_KEYS = ("products", "appliance_ids", "families", "min_severity", "key_glob",
                  "text_contains", "outcome", "automations", "api_type", "where")


def _as_list(value) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        value = re.split(r"[,\n]", value)
    return [str(v).strip() for v in value if str(v).strip()]


def _as_ints(value) -> list[int]:
    out = []
    for v in _as_list(value):
        try:
            out.append(int(v))
        except ValueError:
            continue
    return out


def clean_conditions(raw: dict) -> tuple[dict, list[str]]:
    """``(conditions, problems)`` from a form or an API body."""
    raw = raw or {}
    out: dict = {}
    problems: list[str] = []
    for k in ("products", "families", "automations"):
        v = _as_list(raw.get(k))
        if v:
            out[k] = v
    ids = _as_ints(raw.get("appliance_ids"))
    if ids:
        out["appliance_ids"] = ids
    sev = str(raw.get("min_severity") or "").strip()
    if sev:
        if sev not in _SEV_RANK:
            problems.append("minimum severity must be info, warning or critical")
        else:
            out["min_severity"] = sev
    for k in ("key_glob", "text_contains", "api_type"):
        v = str(raw.get(k) or "").strip()
        if v:
            out[k] = v[:200]
    oc = str(raw.get("outcome") or "").strip()
    if oc:
        if oc not in ("ok", "failed", "skipped"):
            problems.append("outcome must be ok, failed or skipped")
        else:
            out["outcome"] = oc
    where = raw.get("where")
    if isinstance(where, str) and where.strip():
        try:
            where = json.loads(where)
        except ValueError as exc:
            problems.append("payload conditions are not valid JSON: %s" % exc)
            where = []
    rows = []
    for i, w in enumerate(where or []):
        if not isinstance(w, dict) or not str(w.get("field") or "").strip():
            problems.append("payload condition %d needs a field" % (i + 1))
            continue
        op = str(w.get("op") or "equals")
        if op not in WHERE_OPS:
            problems.append("payload condition %d: unknown test %r" % (i + 1, op))
            continue
        rows.append({"field": str(w["field"]).strip()[:120], "op": op,
                     "value": "" if w.get("value") is None else str(w.get("value"))[:200]})
    if rows:
        out["where"] = rows
    return out, problems


def _field(payload: dict, path: str):
    cur = payload
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _where_ok(w: dict, payload: dict) -> bool:
    got = _field(payload, w["field"])
    op, want = w["op"], w.get("value", "")
    if op == "empty":
        return got in (None, "", [], {})
    if op == "not_empty":
        return got not in (None, "", [], {})
    if got is None:
        return False
    text = json.dumps(got, default=str) if isinstance(got, (dict, list)) else str(got)
    if isinstance(got, bool):
        text = "true" if got else "false"
    if op == "equals":
        return text == want
    if op == "not_equals":
        return text != want
    if op == "contains":
        return want.lower() in text.lower()
    if op == "glob":
        return fnmatch.fnmatchcase(text, want)
    a, b = _num(got), _num(want)
    if a is None or b is None:
        return False
    return a > b if op == "greater" else a < b


def matches(conditions: dict, payload: dict) -> tuple[bool, str]:
    """Does this occurrence pass the conditions? Empty = any. A condition
    on a field the payload does not carry is NOT met: a filter narrows, it
    never widens."""
    c = conditions or {}
    p = payload or {}
    prods = c.get("products") or []
    if prods:
        got = str(p.get("product") or p.get("kind") or "")
        if got not in prods:
            return False, "product %r is not in %s" % (got, ", ".join(prods))
    ids = c.get("appliance_ids") or []
    if ids:
        have = _as_ints([p.get("appliance_id")] + list(p.get("device_ids") or []))
        if not any(i in ids for i in have):
            return False, "no appliance of the event is in the condition"
    fams = c.get("families") or []
    if fams and str(p.get("family") or "") not in fams:
        return False, "family %r is not in %s" % (p.get("family"), ", ".join(fams))
    floor = c.get("min_severity") or ""
    if floor and _SEV_RANK.get(str(p.get("severity") or ""), -1) < _SEV_RANK[floor]:
        return False, "severity %r is below %s" % (p.get("severity"), floor)
    kg = c.get("key_glob") or ""
    if kg and not fnmatch.fnmatchcase(str(p.get("key") or ""), kg):
        return False, "key %r does not match %s" % (p.get("key"), kg)
    tc = (c.get("text_contains") or "").lower()
    if tc:
        hay = " ".join(str(p.get(k) or "") for k in
                       ("title", "detail", "summary", "reason")).lower()
        if tc not in hay:
            return False, "the text does not contain %r" % tc
    oc = c.get("outcome") or ""
    if oc and str(p.get("status") or "") != oc:
        return False, "outcome %r is not %s" % (p.get("status"), oc)
    autos = c.get("automations") or []
    if autos and str(p.get("automation") or "") not in autos:
        return False, "automation %r is not in %s" % (p.get("automation"), ", ".join(autos))
    at = c.get("api_type") or ""
    if at and not fnmatch.fnmatchcase(str(p.get("type") or ""), at):
        return False, "type %r does not match %s" % (p.get("type"), at)
    for w in c.get("where") or []:
        if not _where_ok(w, p):
            return False, "%s %s %r is not met" % (w["field"], w["op"], w.get("value", ""))
    return True, ""


# --------------------------------------------------------------------------- #
#  dispatch                                                                    #
# --------------------------------------------------------------------------- #
def _cap_payload(payload: dict) -> str:
    s = json.dumps(payload, default=str, sort_keys=True)
    if len(s) > PAYLOAD_CAP:
        s = json.dumps({"_truncated": "larger than %d bytes" % PAYLOAD_CAP,
                        "key": payload.get("key"), "type": payload.get("type")})
    return s


def _in_cooldown(trig: Trigger, subject: str, now: datetime) -> TriggerFire | None:
    minutes = int(trig.cooldown_minutes or 0)
    if minutes <= 0 or not subject:
        return None
    return (TriggerFire.query
            .filter(TriggerFire.trigger_id == trig.id, TriggerFire.subject == subject,
                    TriggerFire.status == FIRE_MATCHED,
                    TriggerFire.fired_at >= now - timedelta(minutes=minutes))
            .order_by(TriggerFire.id.desc()).first())


def budget_left(trig: Trigger, now: datetime | None = None) -> int:
    limit = int(trig.rate_limit_per_hour or 0)
    if limit <= 0:
        return 1 << 30
    since = (now or datetime.utcnow()) - timedelta(hours=1)
    used = (TriggerFire.query
            .filter(TriggerFire.trigger_id == trig.id, TriggerFire.status == FIRE_MATCHED,
                    TriggerFire.fired_at >= since).count())
    return max(0, limit - used)


def _prune() -> None:
    from ..models import db
    for model, keep in ((TriggerFire, KEEP_FIRES), (EventAutomationRun, KEEP_RUNS)):
        n = model.query.count()
        if n > keep + 500:
            cut = (db.session.query(model.id).order_by(model.id.desc())
                   .offset(keep).limit(1).scalar())
            if cut:
                model.query.filter(model.id <= cut).delete(synchronize_session=False)
    db.session.commit()


def emit(event: str, payload: dict, *, by: str = "event", depth: int = 0) -> list[dict]:
    """Match *event* against every enabled trigger and queue their
    automations. One row per (trigger, automation) touched:
    ``{trigger, automation, status: queued|suppressed|error, fire_id, run_id,
    job_id, reason, key}``. Never raises past one trigger; never runs inline."""
    from flask import current_app
    from ..models import db
    from . import jobs
    from .audit import log_action

    payload = dict(payload or {})
    out: list[dict] = []
    if not event:
        return out
    trigs = (Trigger.query.filter_by(enabled=True, event=event)
             .order_by(Trigger.key.asc()).all())
    if not trigs:
        return out
    subject = subject_of(event, payload)
    now = datetime.utcnow()
    for trig in trigs:
        try:
            ok, _why = matches(trig.conditions, payload)
            if not ok:
                continue
            reason = ""
            if depth > MAX_DEPTH:
                reason = ("the chain is %d hops deep; %d is the limit (a trigger that "
                          "matches its own automation?)" % (depth, MAX_DEPTH))
            elif _in_cooldown(trig, subject, now) is not None:
                reason = ("subject %s matched within the last %d minute(s)"
                          % (subject or "-", trig.cooldown_minutes))
            elif budget_left(trig, now) <= 0:
                reason = ("the budget of %d matches per hour is spent"
                          % trig.rate_limit_per_hour)
            fire = TriggerFire(trigger_id=trig.id, event=event, subject=subject,
                               status=FIRE_SUPPRESSED if reason else FIRE_MATCHED,
                               reason=reason, depth=depth, by=(by or "")[:64],
                               payload_json=_cap_payload(payload), fired_at=now)
            db.session.add(fire)
            if not reason:
                trig.last_fired_at = now
            db.session.commit()
            if reason:
                out.append({"trigger": trig.key, "automation": "", "status": "suppressed",
                            "fire_id": fire.id, "run_id": None, "job_id": "",
                            "reason": reason, "key": payload.get("key", "")})
                continue
            autos = [a for a in trig.automations if a.enabled]
            if not autos:
                fire.reason = "no enabled automation is bound to this trigger"
                db.session.commit()
            for auto in sorted(autos, key=lambda a: a.key):
                out.append(_queue(current_app._get_current_object(), auto, trig, fire,
                                  payload, depth=depth, by=by))
            log_action("trigger.fire", target=trig.key,
                       extra={"event": event, "subject": subject, "fire": fire.id,
                              "automations": [a.key for a in autos], "by": by})
        except Exception as exc:  # noqa: BLE001 -- one trigger must not sink the event
            db.session.rollback()
            out.append({"trigger": trig.key, "automation": "", "status": "error",
                        "fire_id": None, "run_id": None, "job_id": "",
                        "reason": "%s: %s" % (type(exc).__name__, exc),
                        "key": payload.get("key", "")})
    try:
        _prune()
    except Exception:  # noqa: BLE001 -- housekeeping never sinks a dispatch
        db.session.rollback()
    return out


def _queue(flask_app, auto: EventAutomation, trig: Trigger | None, fire, payload: dict,
           *, depth: int, by: str, test: bool = False) -> dict:
    from ..models import db
    from . import jobs
    armed = bool(auto.armed) and not test
    run = EventAutomationRun(automation_id=auto.id, fire_id=getattr(fire, "id", None),
                             status=RUN_QUEUED, armed=armed, test=test)
    db.session.add(run)
    db.session.commit()
    job = jobs.create_job(
        JOB_TYPE, "Automation %s (%s)" % (auto.name, getattr(trig, "key", "test")),
        by=by, cancelable=False, background=True,
        meta={"automation": auto.key, "trigger": getattr(trig, "key", ""),
              "run": run.id, "armed": armed, "test": test})
    run.job_id = job["id"]
    db.session.commit()
    jobs.run_async(flask_app, job["id"],
                   _job_worker(auto.id, run.id, payload, depth=depth, test=test,
                               trigger_key=getattr(trig, "key", "")))
    return {"trigger": getattr(trig, "key", ""), "automation": auto.key, "status": "queued",
            "fire_id": getattr(fire, "id", None), "run_id": run.id, "job_id": job["id"],
            "reason": "", "key": payload.get("key", "")}


def test_run(auto: EventAutomation, payload: dict | None, *, by: str) -> dict:
    """Queue ONE rehearsal of *auto* with a sample (or given) payload. Never
    armed, never chained, never counted against a trigger's budget."""
    from flask import current_app
    trig = auto.trigger
    if payload is None:
        payload = dict(events().get(getattr(trig, "event", ""), {}).get("example") or {})
    return _queue(current_app._get_current_object(), auto, trig, None, payload,
                  depth=0, by=by, test=True)


def _job_worker(auto_id: int, run_id: int, payload: dict, *, depth: int, test: bool,
                trigger_key: str):
    """The ONLY path from a dispatch to :func:`_perform`."""
    def worker(flask_app, job_id):
        from ..models import db
        from . import jobs
        with flask_app.app_context():
            auto = db.session.get(EventAutomation, auto_id)
            run = db.session.get(EventAutomationRun, run_id)
            if auto is None or run is None:
                jobs.finish_error(job_id, "the automation was deleted before it ran")
                return None
            run.status = RUN_RUNNING
            db.session.commit()
            jobs.set_progress(job_id, 5, "running %s" % auto.name)
            try:
                status, summary, ref = _perform(auto, run, payload, trigger_key=trigger_key)
            except Exception as exc:  # noqa: BLE001 -- a run never stays "running"
                db.session.rollback()
                status, summary, ref = RUN_FAILED, "%s: %s" % (type(exc).__name__, exc), ""
            run = db.session.get(EventAutomationRun, run_id)
            auto = db.session.get(EventAutomation, auto_id)
            run.status, run.summary, run.ref = status, (summary or "")[:4000], (ref or "")[:120]
            run.ended_at = datetime.utcnow()
            if not test and auto is not None:
                auto.last_run_at, auto.last_status = run.ended_at, status
            db.session.commit()
            result = {"run": run.id, "status": status, "ref": run.ref}
            if status == RUN_FAILED:
                jobs.finish_error(job_id, run.summary[:300] or "failed")
            else:
                jobs.finish_success(job_id, message=run.summary[:300], result=result)
            if not test and auto is not None:
                _chain(auto, run, payload, depth=depth, trigger_key=trigger_key)
            return result
    return worker


def _chain(auto, run, payload: dict, *, depth: int, trigger_key: str) -> None:
    try:
        emit("automation.finished", {
            "automation": auto.key, "automation_name": auto.name, "trigger": trigger_key,
            "kind": auto.kind, "status": run.status, "summary": run.summary[:500],
            "ref": run.ref, "armed": bool(run.armed),
            "subject": subject_of(_event_of(auto), payload),
            "appliance_id": payload.get("appliance_id"),
            "product": payload.get("product") or auto.product or "",
            "depth": depth + 1,
        }, by="automation:%s" % auto.key, depth=depth + 1)
    except Exception:  # noqa: BLE001 -- a chain must not fail the run it follows
        from ..models import db
        db.session.rollback()


def _event_of(auto) -> str:
    return getattr(getattr(auto, "trigger", None), "event", "") or ""


# --------------------------------------------------------------------------- #
#  the kinds                                                                   #
# --------------------------------------------------------------------------- #
KINDS = {
    "app": "Run a Plugin Studio app",
    "script": "Run a Script Library script",
    "api_call": "Call an API (HTTP connection / API Catalog)",
    "sql_query": "Query a database (PostgreSQL connection)",
    "store_write": "Write a Studio data store",
    "hook": "Run an integration hook",
    "action": "Run a scheduled action now",
    "notify": "Notify (bell / e-mail)",
}
#: Kinds that run as ONE Studio step (studio_flow), and the step's target param.
FLOW_KINDS = {"script": "script", "api_call": "connection", "sql_query": "connection",
              "store_write": "store"}
#: Kinds whose ``armed`` switch means something (the others say why not).
ARMABLE = ("app", "api_call", "sql_query", "store_write", "action")


def scope_of(payload: dict, trigger_key: str = "", event: str = "") -> dict:
    return {"event": payload, "trigger": {"key": trigger_key, "event": event}}


def render(value, scope: dict):
    from . import studio_flow as F
    return F.render(value, scope)


def _owner(auto):
    from ..models import User
    u = User.query.filter_by(username=auto.owner).first() if auto.owner else None
    if u is None or not getattr(u, "is_active", False):
        return None
    return u


def flow_graph(auto) -> dict:
    """The one-step diagram a FLOW_KINDS automation runs."""
    p = {k: v for k, v in (auto.params or {}).items() if not k.startswith("_")}
    p[FLOW_KINDS[auto.kind]] = auto.target
    p["save_as"] = "result"
    return {"nodes": [{"key": "start", "kind": "start", "params": {}},
                      {"key": "step", "kind": auto.kind, "label": auto.name, "params": p},
                      {"key": "end", "kind": "end", "params": {}}],
            "edges": [{"src": "start", "dst": "step", "branch": "always"},
                      {"src": "step", "dst": "end", "branch": "always"}]}


def problems(auto, *, choices: dict | None = None) -> list[str]:
    """What stops this automation from running — shown on its form."""
    from ..models import db
    errs: list[str] = []
    if auto.kind not in KINDS:
        return ["unknown kind %r" % auto.kind]
    if auto.kind != "notify" and not str(auto.target or "").strip():
        errs.append("choose what it runs")
    if auto.kind == "app":
        from . import studio_apps as SA
        a = SA.get(auto.target)
        if a is None:
            errs.append("app %r does not exist" % auto.target)
        elif a.kind == "script":
            errs.append("app %r is a script app: pick the script kind for script %r"
                        % (auto.target, a.script_slug))
        elif not a.published:
            errs.append("app %r has no published version" % auto.target)
    elif auto.kind in FLOW_KINDS:
        from . import studio_apps as SA
        from . import studio_flow as F
        ch = choices if choices is not None else SA.choices()
        errs.extend(e.replace("step: ", "") for e in F.validate_graph(flow_graph(auto), ch))
    elif auto.kind == "hook":
        from . import integration_hooks as ih
        if ih.get_hook(auto.target) is None:
            errs.append("hook %r does not exist" % auto.target)
    elif auto.kind == "action":
        from ..models import ScheduledAction
        try:
            row = db.session.get(ScheduledAction, int(auto.target))
        except (TypeError, ValueError):
            row = None
        if row is None:
            errs.append("scheduled action %r does not exist" % auto.target)
    elif auto.kind == "notify":
        p = auto.params or {}
        if not str(p.get("title") or "").strip():
            errs.append("a notification needs a title")
        if not (p.get("bell") or str(p.get("email_to") or "").strip()
                or p.get("email_alerts")):
            errs.append("a notification needs a channel (bell or e-mail)")
    return errs


def _perform(auto, run, payload: dict, *, trigger_key: str) -> tuple[str, str, str]:
    """``(status, summary, ref)``. Reached only from :func:`_job_worker`."""
    probs = problems(auto)
    if probs:
        return RUN_SKIPPED, "cannot run: " + "; ".join(probs), ""
    owner = _owner(auto)
    if owner is None and auto.kind in ("app", "script", "api_call", "sql_query",
                                       "store_write"):
        return RUN_SKIPPED, ("the owner %r is missing or disabled; save the automation "
                             "again as an active user" % auto.owner), ""
    scope = scope_of(payload, trigger_key, _event_of(auto))
    fn = {"app": _do_app, "hook": _do_hook,
          "action": _do_action, "notify": _do_notify}.get(auto.kind, _do_flow)
    return fn(auto, run, payload, scope, owner)


def _inputs(auto, scope) -> dict:
    from . import studio_flow as F
    raw = (auto.params or {}).get("inputs")
    val = F.parse_json_param(raw, "Inputs") if isinstance(raw, str) else raw
    val = render(val or {}, scope)
    if not isinstance(val, dict):
        raise F.FlowError("inputs must be an object of field: value")
    return val


def _do_app(auto, run, payload, scope, owner):
    from . import studio_apps as SA
    a = SA.get(auto.target)
    if not a.enabled:  # Plugin Studio > Apps > Disable (2026-10-23)
        return RUN_SKIPPED, "app %r is disabled" % a.slug, ""
    if not SA.can_use(owner, a):
        return RUN_SKIPPED, "the owner %r may not use app %r" % (auto.owner, a.slug), ""
    inputs = _inputs(auto, scope)
    r = SA.start_run(a, user=owner, product=str(payload.get("product") or auto.product or ""),
                     raw_inputs=inputs, rehearsal=not run.armed, inline=True, event=payload)
    # Parked on "Ask a person" is the app working as designed: somebody
    # answers on the run page.
    ok = r.status in ("done", "waiting")
    summary = "%sapp %s v%s run #%d: %s%s" % (
        "" if run.armed else "[rehearsal] ", a.slug, r.version, r.id,
        "waiting for a person" if r.status == "waiting" else r.status,
        (": " + r.error[:300]) if r.error else "")
    return (RUN_OK if ok else RUN_FAILED), summary, "app-run:%d" % r.id


def _do_flow(auto, run, payload, scope, owner):
    from . import studio_flow as F
    ctx = F.Ctx(form=payload, vars={"event": payload}, armed=bool(run.armed),
                user=owner.username, user_obj=owner, run_id=0)
    res = F.walk(flow_graph(auto), ctx)
    step = next((s for s in res.get("steps") or [] if s.get("key") == "step"), {})
    detail = step.get("detail") or res.get("error") or ""
    value = ctx.vars.get("result")
    shown = ""
    if value is not None:
        shown = json.dumps(value, default=str)
        shown = " → " + (shown[:600] + "…" if len(shown) > 600 else shown)
    summary = "%s%s %s: %s%s" % ("" if run.armed else "[rehearsal] ", KINDS[auto.kind].lower(),
                                 auto.target, detail, shown)
    return (RUN_OK if res.get("status") == "done" else RUN_FAILED), summary, ""


def _do_hook(auto, run, payload, scope, owner):
    from . import integration_hooks as ih
    hook = ih.get_hook(auto.target) or {}
    if not hook.get("enabled", True):
        return RUN_SKIPPED, "hook %r is disabled" % auto.target, ""
    st = ih.dispatch_one(auto.target, sample=False, payload=payload,
                         by="automation:%s" % auto.key)
    rid = st["request_id"]
    wait_until = time.time() + ih.clamp_timeout(hook.get("timeout")) + HOOK_WAIT_EXTRA_S
    while True:
        cur = ih.result(rid) or {}
        status = cur.get("status")
        if status in ("ok", "failed", "timeout"):
            break
        if time.time() > wait_until:
            return RUN_FAILED, ("hook %s is still %s: the integrations runner did not "
                                "finish it" % (auto.target, status or "queued")), "hook:%s" % rid
        time.sleep(HOOK_POLL_S)
    text = (cur.get("error") or cur.get("stdout") or "")[-500:]
    return ((RUN_OK if status == "ok" else RUN_FAILED),
            "hook %s ended %s%s" % (auto.target, status, (": " + text) if text else ""),
            "hook:%s" % rid)


def _do_action(auto, run, payload, scope, owner):
    from ..models import ScheduledAction, db
    from . import scheduled_actions as sa
    row = db.session.get(ScheduledAction, int(auto.target))
    spec = sa.get_spec(row.action)
    if spec is None:
        return RUN_SKIPPED, "action %r is no longer in the catalog" % row.action, ""
    if spec.danger and not run.armed:
        return RUN_SKIPPED, ("[rehearsal] %r is a danger action: it runs only from an ARMED "
                             "automation (and, where it needs one, inside its change "
                             "request's window)" % row.name), ""
    r = sa.execute_and_record(row, trigger="event")
    if r is None:
        return RUN_SKIPPED, "scheduled action %r is already running" % row.name, ""
    ok = r.status in ("ok", "success")
    return ((RUN_OK if ok else (RUN_SKIPPED if r.status == "skipped" else RUN_FAILED)),
            "scheduled action %r: %s — %s" % (row.name, r.status, (r.summary or "")[:400]),
            "action-run:%d" % r.id)


def _do_notify(auto, run, payload, scope, owner):
    from . import notifications as notify
    from . import email_service
    p = auto.params or {}
    title = str(render(p.get("title") or "", scope))[:200]
    body = str(render(p.get("body") or "", scope))[:4000]
    sent = []
    failed = []
    if p.get("bell"):
        from .alerts import _admin_ids
        ids = _admin_ids()
        if ids:
            kind = (notify.Notification.KIND_ERROR if p.get("level") == "error"
                    else notify.Notification.KIND_INFO)
            notify.push_many(ids, title, kind=kind, body=body[:1500],
                             product=(payload.get("product") or None))
            sent.append("bell (%d)" % len(ids))
        else:
            failed.append("bell: no administrator to notify")
    to = _as_list(p.get("email_to"))
    if p.get("email_alerts"):
        from . import alerts
        to += alerts.recipients()
    if to:
        res = email_service.send_email(sorted(set(to)), title, body)
        if (res or {}).get("ok"):
            sent.append("e-mail (%d)" % len(set(to)))
        else:
            failed.append("e-mail: %s" % ((res or {}).get("detail") or "send failed"))
    if failed and not sent:
        return RUN_FAILED, "; ".join(failed), ""
    return RUN_OK, "notified %s%s" % (", ".join(sent) or "nobody",
                                      ("; " + "; ".join(failed)) if failed else ""), ""


# --------------------------------------------------------------------------- #
#  sources                                                                     #
# --------------------------------------------------------------------------- #
def on_findings(findings, node: str) -> list[dict]:
    """``alert.fired`` for each FRESH finding (and ``intent.deviation`` for an
    intent finding). Called by the alert engine whatever the notification
    sinks say. Rows carry the finding key so the engine can stamp the cooldown
    of a finding that started an automation."""
    from .alerts import alert_event_payload, intent_event_payload
    if not Trigger.query.filter_by(enabled=True).count():
        return []
    rows: list[dict] = []
    for f in findings:
        key = f.get("key", "")
        for event, payload in (("alert.fired", alert_event_payload(f, node)),
                               ("intent.deviation", intent_event_payload(f, node))):
            if payload is None:
                continue
            try:
                new = emit(event, payload, by="alerts")
            except Exception as exc:  # noqa: BLE001
                new = [{"trigger": "", "automation": "", "status": "error",
                        "reason": "%s: %s" % (type(exc).__name__, exc)}]
            for r in new:
                r["key"] = key
            rows.extend(new)
    return rows


def emit_quiet(event: str, payload: dict, *, by: str) -> int:
    """For the change-request bookkeeping paths: emit and never raise."""
    try:
        return sum(1 for r in emit(event, payload, by=by) if r["status"] == "queued")
    except Exception:  # noqa: BLE001
        try:
            from ..models import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return 0


# --------------------------------------------------------------------------- #
#  editing                                                                     #
# --------------------------------------------------------------------------- #
def validate_key(key: str) -> str:
    key = (key or "").strip().lower()
    if not _KEY_RE.match(key):
        raise ValueError("the key is 2–48 characters: lowercase letters, digits, - and _")
    return key

