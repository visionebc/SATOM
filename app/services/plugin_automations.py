"""Plugin Studio apps on a schedule -- Automations > On a schedule, ``plugin_app``.

An app is a form and a diagram somebody runs. Some apps are meant to run on
their own -- "every day, put the IP of every FortiWeb in this FortiGate
address group" -- and SATOM already has the place where things run on their
own: Automations. So a schedule for an app is not a second scheduler inside
Plugin Studio; it is a ``ScheduledAction`` with the catalog action
``plugin_app`` (``scheduled_actions``), on the Automations page with every
other automation, fired by the same sidecar, with the same history, Run now
and lease.

WHAT A ``plugin_app`` ROW HOLDS
-------------------------------
``params = {"app": <slug>, "inputs": {field: value}, "owner": <username>}``.
The run is the app's PUBLISHED version (a script app: its script's published
version), started as ``owner`` -- the user who saved the automation last, as
an event automation runs (``trigger_engine``) -- with ``inputs`` as the form.
A device step still needs ``config_write`` of that user, and an app the owner
may not use is refused, not run as somebody else.

WHERE A ROW COMES FROM, AND WHAT KEEPS IT LINKED
-----------------------------------------------
* the Automations form (action "Run a Plugin Studio app");
* an app package (contract section 18): ``app.json`` may carry
  ``"automations": [{name, schedule_kind, schedule, inputs, description}]``.
  The import creates each one DISABLED -- the app itself lands as a draft and
  publishing it is the administrator's act on this server, so is switching on
  what runs it. An automation that already exists (same app, same name) is
  this server's: its schedule, inputs and on/off are kept, with a warning when
  the package's differ.
* export puts the app's automations back into its package.

Deleting the app deletes its automations (a row that runs a missing app would
fail every night in silence).
"""
from __future__ import annotations

import json
import re

ACTION = "plugin_app"
#: An app package carries at most this many automations.
MAX_PER_APP = 10
#: The shortest interval an app may run at: a diagram that writes to devices
#: every minute is a mistake, not a schedule.
MIN_INTERVAL_MINUTES = 5
#: What a package may schedule: a recurring time. ``once`` is an instant on
#: one server's clock and does not travel.
PACKAGE_KINDS = ("interval", "daily", "weekly", "monthly", "cron")
NAME_MAX = 128
_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_UNITS = {"minutes": 1, "hours": 60, "days": 1440}
_WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")


class AutomationError(ValueError):
    pass


# --------------------------------------------------------------------------- #
#  pure: what a schedule and an entry may be                                   #
# --------------------------------------------------------------------------- #
def clean_schedule(kind: str, spec) -> dict:
    """The schedule spec ``scheduler.compute_next_run`` reads, or AutomationError
    naming what is wrong. Recurring kinds only (PACKAGE_KINDS)."""
    from . import scheduler
    if kind not in PACKAGE_KINDS:
        raise AutomationError("schedule_kind %r: one of %s" % (kind, ", ".join(PACKAGE_KINDS)))
    if not isinstance(spec, dict):
        raise AutomationError("schedule is an object, e.g. {\"time\": \"02:00\"}")

    def hhmm():
        t = str(spec.get("time") or "").strip()
        if not _HHMM.match(t):
            raise AutomationError("time %r: HH:MM, 00:00 to 23:59" % spec.get("time"))
        return t

    def whole(name, lo, hi):
        v = spec.get(name)
        if isinstance(v, bool) or not isinstance(v, (int, str)) or not str(v).strip().isdigit():
            raise AutomationError("%s %r: a whole number from %d to %d" % (name, v, lo, hi))
        n = int(v)
        if not lo <= n <= hi:
            raise AutomationError("%s %d: from %d to %d" % (name, n, lo, hi))
        return n
    if kind == "interval":
        unit = str(spec.get("unit") or "minutes")
        if unit not in _UNITS:
            raise AutomationError("unit %r: minutes, hours or days" % unit)
        every = whole("every", 1, 10000)
        if every * _UNITS[unit] < MIN_INTERVAL_MINUTES:
            raise AutomationError("an app runs at most every %d minutes" % MIN_INTERVAL_MINUTES)
        return {"every": every, "unit": unit}
    if kind == "daily":
        return {"time": hhmm()}
    if kind == "weekly":
        return {"weekday": whole("weekday", 0, 6), "time": hhmm()}
    if kind == "monthly":
        return {"day": whole("day", 1, 31), "time": hhmm()}
    expr = " ".join(str(spec.get("expr") or "").split())
    try:
        if not scheduler.cron_preview(expr, 1):
            raise AutomationError("cron %r never fires (for example 30 February)" % expr)
    except scheduler.CronError as exc:
        raise AutomationError("cron %r: %s" % (expr, exc)) from None
    return {"expr": expr}


def describe(kind: str, spec: dict) -> str:
    spec = spec or {}
    if kind == "interval":
        return "every %s %s" % (spec.get("every"), spec.get("unit"))
    if kind == "daily":
        return "daily at %s" % spec.get("time")
    if kind == "weekly":
        wd = spec.get("weekday")
        return "weekly on %s at %s" % (_WEEKDAYS[wd] if isinstance(wd, int) and 0 <= wd < 7
                                       else wd, spec.get("time"))
    if kind == "monthly":
        return "monthly on day %s at %s" % (spec.get("day"), spec.get("time"))
    if kind == "cron":
        return "cron %s" % spec.get("expr")
    return kind or "?"


def clean_entries(raw) -> tuple[list[dict], list[tuple[str, str]]]:
    """``(entries, problems)`` of an app package's ``automations``; a problem
    is ``(where, message)``. Entries keep only the keys this module reads."""
    if raw in (None, ""):
        return [], []
    if not isinstance(raw, list):
        return [], [("automations", "automations must be a list")]
    out, problems, seen = [], [], set()
    if len(raw) > MAX_PER_APP:
        problems.append(("automations", "an app carries at most %d automations" % MAX_PER_APP))
    for i, it in enumerate(raw[:MAX_PER_APP]):
        where = "automations[%d]" % i
        if not isinstance(it, dict):
            problems.append((where, "each automation is an object"))
            continue
        name = " ".join(str(it.get("name") or "").split())
        if not name or len(name) > NAME_MAX:
            problems.append((where, "a name of 1 to %d characters is required" % NAME_MAX))
            continue
        where = "automations[%s]" % name
        if name.lower() in seen:
            problems.append((where, "automation %r is listed twice" % name))
            continue
        seen.add(name.lower())
        try:
            spec = clean_schedule(str(it.get("schedule_kind") or ""), it.get("schedule"))
        except AutomationError as exc:
            problems.append((where, str(exc)))
            continue
        inputs = it.get("inputs")
        if inputs in (None, ""):
            inputs = {}
        if not isinstance(inputs, dict):
            problems.append((where, "inputs is an object of form field: value"))
            continue
        out.append({"name": name, "schedule_kind": str(it["schedule_kind"]), "schedule": spec,
                    "inputs": inputs,
                    "description": str(it.get("description") or "")[:500]})
    return out, problems


def input_problems(entries: list[dict], fields: list[dict]) -> list[tuple[str, str]]:
    """An automation fills the form with no person there: every input names a
    field of the form, and every required field without a default has one."""
    names = {f.get("name") for f in fields or [] if isinstance(f, dict)}
    out = []
    for e in entries:
        where = "automations[%s]" % e["name"]
        for k in e["inputs"]:
            if k not in names:
                out.append((where, "input %r is not a field of the app's form" % k))
        for f in fields or []:
            if not isinstance(f, dict) or not f.get("required"):
                continue
            given = e["inputs"].get(f.get("name"))
            if (given is None or (isinstance(given, str) and not given.strip())) \
                    and f.get("default") in (None, ""):
                # an empty value is not given: the run would stop at "is required"
                # every time (Builder lab, 2026-10-26: "inputs": {"group": ""})
                out.append((where, "form field %r is required and has no default: the "
                                   "automation must give it a value in inputs%s"
                            % (f.get("name"), " (it is empty)" if f.get("name") in e["inputs"]
                               else "")))
    return out


# --------------------------------------------------------------------------- #
#  the rows                                                                    #
# --------------------------------------------------------------------------- #
def linked(slug: str) -> list:
    """The ``plugin_app`` automations that run app *slug*, by name."""
    from ..models import ScheduledAction
    rows = ScheduledAction.query.filter_by(action=ACTION).order_by(ScheduledAction.name).all()
    return [r for r in rows if str(r.params_dict.get("app") or "") == slug]


def export(slug: str) -> list[dict]:
    """The app's automations as a package carries them (recurring ones only)."""
    out = []
    for r in linked(slug):
        if r.schedule_kind not in PACKAGE_KINDS:
            continue
        p = r.params_dict
        out.append({"name": r.name, "schedule_kind": r.schedule_kind,
                    "schedule": r.schedule_dict, "inputs": p.get("inputs") or {},
                    "description": str(p.get("description") or "")})
    return out


def _product() -> str:
    from .product_scope import ProductScopeUnresolved, stamp
    try:
        return stamp() or ""
    except (ProductScopeUnresolved, RuntimeError):
        return ""


def install(slug: str, entries: list[dict], *, by: str) -> dict:
    """Create the package's automations of app *slug* that this server does not
    have, DISABLED. ``{created, kept, warnings, todo}``. No commit."""
    from ..models import ScheduledAction, db
    from . import scheduler
    have = {r.name.lower(): r for r in linked(slug)}
    created, kept, warnings, todo = [], [], [], []
    for e in entries:
        row = have.get(e["name"].lower())
        if row is not None:
            kept.append("automation %s (exists: its schedule, inputs and on/off are this "
                        "server's)" % row.name)
            p = row.params_dict
            if (row.schedule_kind, row.schedule_dict, p.get("inputs") or {}) != \
                    (e["schedule_kind"], e["schedule"], e["inputs"]):
                warnings.append("automation %s exists here with another schedule or inputs: "
                                "this server's are kept (%s)"
                                % (row.name, describe(row.schedule_kind, row.schedule_dict)))
            continue
        row = ScheduledAction(
            name=e["name"][:NAME_MAX], scope="user", product=_product(), action=ACTION,
            targets="[]", schedule_kind=e["schedule_kind"], schedule=json.dumps(e["schedule"]),
            params=json.dumps({"app": slug, "inputs": e["inputs"], "owner": by,
                               "description": e.get("description") or ""}),
            enabled=False, catch_up=False, created_by=by,
            next_run=scheduler.compute_next_run(e["schedule_kind"], e["schedule"],
                                                tz=_tz()))
        db.session.add(row)
        created.append("automation %s (%s, off)" % (row.name, describe(row.schedule_kind,
                                                                         e["schedule"])))
        todo.append("switch on automation %s (Automations) once the app is published"
                    % row.name)
    return {"created": created, "kept": kept, "warnings": warnings, "todo": todo}


def delete_for_app(slug: str) -> list[str]:
    """Delete the automations that run app *slug* and their history. No commit."""
    from ..models import ScheduledActionRun, db
    names = []
    for r in linked(slug):
        ScheduledActionRun.query.filter_by(action_id=r.id).delete(synchronize_session=False)
        names.append(r.name)
        db.session.delete(r)
    return names


def _tz() -> str:
    from . import settings_store
    try:
        return settings_store.tz_name()
    except Exception:  # noqa: BLE001
        return "UTC"


# --------------------------------------------------------------------------- #
#  the run                                                                     #
# --------------------------------------------------------------------------- #
def _owner(params: dict):
    from ..models import ScheduledAction, User, db
    name = str(params.get("owner") or "")
    if not name and params.get("_action_id"):
        row = db.session.get(ScheduledAction, int(params["_action_id"]))
        name = (row.created_by or "") if row is not None else ""
    u = User.query.filter_by(username=name).first() if name else None
    if u is None or not getattr(u, "is_active", False):
        return None, name
    return u, name


def _product_of(params: dict) -> str:
    from ..models import ScheduledAction, db
    if params.get("_action_id"):
        row = db.session.get(ScheduledAction, int(params["_action_id"]))
        if row is not None:
            return row.product or ""
    return ""


def run(params: dict, dry_run: bool = False) -> dict:
    """``{"ok", "summary", "log"}`` -- one run of the app the row names, as
    ``run_action`` expects. Never raises (run_action wraps it anyway)."""
    from . import studio_apps as SA
    slug = str(params.get("app") or "").strip()
    a = SA.get(slug) if slug else None
    if a is None:
        return {"ok": False, "summary": "app %r does not exist (deleted?)" % slug, "log": ""}
    if not a.enabled:
        return {"ok": False, "summary": "app %s is disabled (Plugin Studio > Apps)" % slug,
                "log": ""}
    owner, name = _owner(params)
    if owner is None:
        return {"ok": False, "summary": "the owner %r is missing or disabled: save the "
                                        "automation again as an active user" % name, "log": ""}
    inputs = params.get("inputs") or {}
    if not isinstance(inputs, dict):
        return {"ok": False, "summary": "inputs is not an object of field: value", "log": ""}
    if a.kind == "script":
        return _run_script_app(a, owner, inputs, dry_run)
    if not a.published:
        return {"ok": False, "summary": "app %s has no published version: publish it "
                                        "(Plugin Studio > Apps)" % slug, "log": ""}
    if not SA.can_use(owner, a):
        return {"ok": False, "summary": "the owner %s may not use app %s" % (name, slug),
                "log": ""}
    try:
        r = SA.start_run(a, user=owner, product=_product_of(params), raw_inputs=inputs,
                         rehearsal=dry_run, inline=True)
    except SA.AppError as exc:
        return {"ok": False, "summary": "app %s: %s" % (slug, exc), "log": ""}
    ok = r.status in ("done", "waiting")
    steps = "\n".join("%s %s: %s" % (s.get("outcome"), s.get("label") or s.get("key"),
                                     str(s.get("detail") or "")[:300]) for s in r.steps)
    return {"ok": ok, "log": steps,
            "summary": "%sapp %s v%s run #%d: %s%s" % (
                "[rehearsal] " if dry_run else "", slug, r.version, r.id,
                "waiting for a person" if r.status == "waiting" else r.status,
                (": " + r.error[:300]) if r.error else "")}


def _run_script_app(a, owner, inputs: dict, dry_run: bool) -> dict:
    """A script app runs its script's published version, as its owner may."""
    from . import script_schedules as SSch
    from . import studio_apps as SA
    from . import studio_flow as F
    meta = SA.script_meta(a)
    if not SSch.can_run(owner, meta):
        return {"ok": False, "summary": "the owner %s may not run script %s (published, enabled, "
                                        "its audience)" % (owner.username, a.script_slug),
                "log": ""}
    if dry_run:
        return {"ok": True, "summary": "[rehearsal] script %s not run" % a.script_slug, "log": ""}
    graph = {"nodes": [{"key": "start", "kind": "start", "params": {}},
                       {"key": "step", "kind": "script", "label": a.name,
                        "params": {"script": a.script_slug, "inputs": inputs,
                                   "save_as": "result"}},
                       {"key": "end", "kind": "end", "params": {}}],
             "edges": [{"src": "start", "dst": "step", "branch": "always"},
                       {"src": "step", "dst": "end", "branch": "always"}]}
    ctx = F.Ctx(form=inputs, armed=True, user=owner.username, user_obj=owner)
    res = F.walk(graph, ctx)
    step = next((s for s in res.get("steps") or [] if s.get("key") == "step"), {})
    shown = json.dumps(ctx.vars.get("result"), default=str)[:600] \
        if ctx.vars.get("result") is not None else ""
    return {"ok": res.get("status") == "done", "log": shown,
            "summary": "script %s: %s" % (a.script_slug,
                                          step.get("detail") or res.get("error") or "")}
