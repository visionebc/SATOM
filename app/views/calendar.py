"""Change Calendar — Fleet -> Calendar.

GET  /calendar/       month | week | agenda | year over changes + automations
POST /calendar/plan   raise a planned change from a day cell

This blueprint reads the form, resolves a target SELECTOR into concrete devices,
and renders. It decides nothing else:

  * what a legal change is           -> ``change_requests.create_change_request``
  * when a schedule next fires       -> ``services.scheduler.compute_next_run``
  * what goes on which day           -> ``services.calendar_plan``
  * which rows this ADOM may see     -> ``change_requests._cr_in_scope`` and
                                        ``services.product_scope.scope_query``

Importing the change-request helpers rather than restating them is the point.
The defect this product has paid for twice is two implementations of the same
judgement, neither of which ever failed — they simply disagreed, and the
disagreement surfaced hours later inside a maintenance window.

PERMISSION. The page needs ``USER_MANAGE``, the same gate as its two sources
(Change Requests and Scheduled Actions). A weaker gate here would be a read-side
hole into both; a link that leads to a 403 is a bug report waiting to be filed,
so the nav entry carries the same condition.

A GROUP IS RESOLVED AT PLANNING TIME, NOT AT FIRE TIME. "Every FortiWeb tagged
prod" becomes an explicit list of device ids the moment the change is raised,
and the change records both the selector and what it resolved to. Storing the
selector live would let the target set change between the day it was approved
and the night it runs — an approval for one set of boxes executing against
another.
"""
from __future__ import annotations

import json
from datetime import date, datetime, timedelta

from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import (Appliance, ChangeRequest, Permission, ScheduledAction,
                      ScheduledActionRun, visible_appliances)
from ..services import calendar_plan as cal
from ..services import settings_store
from ..services import user_settings_store
from ..services.audit import log_action

bp = Blueprint("calendar_plan", __name__, url_prefix="/calendar")

VIEWS = ("month", "week", "agenda", "year")

#: Group dimensions an operator may plan against. These are the columns
#: ``Appliance`` already carries — the calendar does not invent a grouping
#: concept, it plans against the one the inventory uses.
GROUP_FIELDS = {
    "tag": "Tag",
    "department": "Department",
    "zone": "Zone",
    "line": "Line",
}

#: History drawn behind the grid. A month view of a fleet running a three-minute
#: sweep is ~15k runs; the calendar shows the ones that FAILED plus a bounded
#: sample of the rest, and says which. An unbounded read here is the page that
#: times out on the busiest month of the year.
MAX_RUNS = 400

#: How many event blocks the page pre-renders into hidden day panels so that
#: picking a day costs nothing. Past this, a day still opens — through the
#: ordinary link, which server-renders exactly the same panel. The bound is on
#: BLOCKS, not days: one appliance with four hundred runs on a Tuesday is the
#: page this exists to keep openable.
MAX_PANEL_EVENTS = 400


def _calendar_on() -> bool:
    """Has the signed-in user left the Calendar switched on? (Default: yes.)

    A view must not read this from the template context: the context processor
    exists for the three nav menus, and a route that trusted a rendering
    variable for a decision would be a second implementation of the answer.
    """
    try:
        return user_settings_store.calendar_enabled(current_user.id)
    except Exception:  # noqa: BLE001 — a preference must not 500 the page
        return True


def _panel_days(buckets: dict, selected, day_from, day_to) -> list:
    """The days whose detail panel is pre-rendered into the page.

    THE SELECTED DAY IS ALWAYS FIRST AND ALWAYS INCLUDED. Every other day falls
    back to a page load when the budget runs out, and that fallback lands on a
    page where the requested day IS the selected one — so a day that could not
    be pre-rendered here is still pre-rendered there. Budgeting the selected day
    like any other would break that: the fallback could arrive and find the day
    missing again, and the panel would never open.
    """
    out = [selected] if selected else []
    budget = MAX_PANEL_EVENTS - len(buckets.get(selected, [])) if selected else MAX_PANEL_EVENTS
    for day in sorted(k for k in buckets if day_from <= k <= day_to):
        if day == selected:
            continue
        size = len(buckets[day])
        # ``continue``, not ``break``: one crowded day must not cost every
        # quiet day after it in the month.
        if size > budget:
            continue
        budget -= size
        out.append(day)
    return sorted(out)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _int(value, default=None):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _anchor() -> date:
    """The day the view is centred on, from ``?d=`` / ``?y=`` / ``?m=``."""
    raw = (request.args.get("d") or "").strip()
    if raw:
        try:
            return date.fromisoformat(raw)
        except ValueError:
            pass
    today = cal.local_dt(datetime.utcnow(), settings_store.tz_name()).date()
    year = _int(request.args.get("y"), today.year)
    month = _int(request.args.get("m"), today.month)
    if not (1 <= (month or 0) <= 12):
        month = today.month
    if not (1970 <= (year or 0) <= 2999):
        year = today.year
    return date(year, month, 1) if (request.args.get("y")
                                    or request.args.get("m")) else today


def _range_for(view: str, anchor: date) -> tuple:
    """The LOCAL day range a view covers."""
    if view == "year":
        return date(anchor.year, 1, 1), date(anchor.year, 12, 31)
    if view == "week":
        monday = anchor - timedelta(days=anchor.weekday())
        return monday, monday + timedelta(days=6)
    if view == "agenda":
        # 30 days, not 60. The agenda lists every row rather than
        # collapsing to a cell, so a fleet with fourteen recurring jobs
        # rendered half a megabyte of "sweep x480" repeated sixty times,
        # with the actual changes buried inside it. A planning horizon
        # nobody can read is not a longer horizon.
        return anchor, anchor + timedelta(days=29)
    # month — pad to whole weeks so the leading/trailing cells are populated
    first = date(anchor.year, anchor.month, 1)
    nxt = date(anchor.year + (anchor.month // 12), (anchor.month % 12) + 1, 1)
    last = nxt - timedelta(days=1)
    return first - timedelta(days=first.weekday()), last + timedelta(days=6 - last.weekday())


def _cr_scope_filter(crs):
    """ADOM scope, borrowed from the Change Requests list — not restated."""
    from .change_requests import _cr_in_scope, _visible_appliance_ids
    visible = _visible_appliance_ids()
    return [c for c in crs if _cr_in_scope(c, visible)]


def _type_entries():
    from .change_requests import cr_type_entries
    return cr_type_entries()


def _labeller():
    entries = {e["key"]: e["label"] for e in _type_entries()}

    def label_for(key):
        return entries.get(key) or (key or "")
    return label_for


def _device_names():
    """``cr -> [name]``, resolved once for the whole page.

    One query for every appliance the ADOM can see, not one per change: a month
    with sixty changes was sixty round-trips, and the page that renders a
    maintenance calendar must not be the slowest page in the console.
    """
    rows = visible_appliances().with_entities(Appliance.id, Appliance.name).all()
    by_id = {r[0]: r[1] for r in rows}

    def names_for(cr):
        # A device deleted after the change was raised still has to appear, by
        # id, in the record of what that window was going to touch. Rendering
        # it as a blank would quietly shrink the blast radius.
        return [by_id.get(i) or f"#{i}" for i in (cr.device_ids_list or [])]
    return names_for


def _collect(view: str, anchor: date, kinds: set) -> dict:
    """Everything the grid draws, already scoped. Returns the render context."""
    tz = settings_store.tz_name()
    day_from, day_to = _range_for(view, anchor)
    start, end = cal.to_utc_bounds(day_from, day_to, tz)
    now = datetime.utcnow()

    events: list = []
    notes: list = []

    if "change" in kinds:
        crs = _cr_scope_filter(
            ChangeRequest.query.order_by(ChangeRequest.created_at.desc()).all())
        events += cal.change_events(
            crs, tz,
            label_for=_labeller(),
            names_for=_device_names(),
            url_for_cr=lambda c: url_for("change_requests.detail", id=c.id))

    if "automation" in kinds:
        from ..services.product_scope import scope_query
        actions = (scope_query(ScheduledAction.query, ScheduledAction.product)
                   .order_by(ScheduledAction.name).all())
        # PROJECTION IS FUTURE-ONLY: a computed dot on a past day would assert a
        # run nobody observed. The past comes from ScheduledActionRun below.
        auto = cal.automation_events(
            actions, max(start, now), end, tz,
            label_for=_labeller(),
            url_for_action=lambda a: url_for("scheduled_actions.index"))
        events += auto
        for act in actions:
            if act.enabled and any(e["id"] == act.id and e.get("truncated")
                                   for e in auto):
                notes.append(
                    f"“{act.name or act.action}” fires more often than the "
                    f"calendar draws: only the first {cal.MAX_PER_SERIES} "
                    f"occurrences in this range are shown.")
        disabled = [a for a in actions if not a.enabled]
        if disabled:
            notes.append(
                f"{len(disabled)} disabled automation(s) are not drawn: "
                + ", ".join(sorted((a.name or a.action) for a in disabled)))

    if "run" in kinds:
        q = (ScheduledActionRun.query
             .filter(ScheduledActionRun.started_at >= start,
                     ScheduledActionRun.started_at < end)
             .order_by(ScheduledActionRun.started_at.desc()))
        total = q.count()
        runs = q.limit(MAX_RUNS).all()
        if total > len(runs):
            notes.append(
                f"{total} runs happened in this range; the {len(runs)} most "
                f"recent are drawn. Open Scheduled Actions → History for the rest.")
        names = {a.id: (a.name or a.action) for a in ScheduledAction.query.all()}
        events += cal.run_events(
            runs, tz,
            name_for=lambda r: names.get(r.action_id, f"action #{r.action_id}"),
            url_for_run=lambda r: url_for("scheduled_actions.history",
                                          id=r.action_id))

    buckets = cal.bucket_by_day(events)
    today = cal.local_dt(now, tz).date()
    ctx = {
        "view": view,
        "anchor": anchor,
        "today": today,
        "tz": tz,
        "events": events,
        "buckets": buckets,
        "notes": notes,
        "conflicts": cal.conflicts(events),
        "invalid": [e for e in events
                    if e["kind"] == "change" and e["window_state"] == "invalid"],
        "kinds": kinds,
        "all_kinds": cal.KINDS,
        "day_from": day_from,
        "day_to": day_to,
    }
    if view == "month":
        ctx["weeks"] = cal.month_matrix(anchor.year, anchor.month, buckets,
                                        today=today)
    elif view == "week":
        ctx["week"] = cal.week_days(anchor, buckets, today=today)
    elif view == "year":
        ctx["months"] = cal.year_matrix(anchor.year, buckets)
    else:
        ctx["agenda"] = [
            {"date": d, "events": buckets[d]}
            for d in sorted(k for k in buckets if day_from <= k <= day_to)]
    return ctx


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #
@bp.route("/")
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    # Switched off in this user's profile. NOT a 403: they hold the permission,
    # they hid the page, and a refusal that does not name the switch is a dead
    # end for anybody who arrives from a bookmark or a colleague's link.
    if not _calendar_on():
        return render_template("calendar/off.html")

    view = (request.args.get("view") or "month").strip().lower()
    if view not in VIEWS:
        view = "month"
    anchor = _anchor()
    picked = {k for k in request.args.getlist("kind") if k in cal.KINDS}
    kinds = picked or set(cal.KINDS)

    ctx = _collect(view, anchor, kinds)

    # The day panel. ``?d=`` doubles as the selected day so a link from a cell
    # both centres the view and opens the planner prefilled for that date.
    sel_raw = (request.args.get("d") or "").strip()
    selected = None
    if sel_raw:
        try:
            selected = date.fromisoformat(sel_raw)
        except ValueError:
            selected = None
    if selected is None:
        # A DAY IS ALWAYS SELECTED, so the detail panel is never an empty box
        # the operator has to discover is clickable. Today when the drawn range
        # holds it, otherwise the anchor — never ``day_from``, which in a month
        # view is padding that belongs to the PREVIOUS month, and which would
        # pre-fill the planner with a window outside the month on screen.
        selected = (ctx["today"] if ctx["day_from"] <= ctx["today"] <= ctx["day_to"]
                    else anchor)
    ctx["selected"] = selected
    ctx["selected_events"] = ctx["buckets"].get(selected, [])
    ctx["panel_days"] = _panel_days(
        ctx["buckets"], selected, ctx["day_from"], ctx["day_to"])

    ctx["types"] = _type_entries()
    ctx["group_fields"] = GROUP_FIELDS
    ctx["group_values"] = _group_values()
    ctx["appliances"] = visible_appliances().order_by(Appliance.name).all()
    ctx["risks"] = ("low", "medium", "high")
    ctx["prev"], ctx["next"] = _neighbours(view, anchor)
    return render_template("calendar/index.html", **ctx)


def _neighbours(view: str, anchor: date) -> tuple:
    if view == "year":
        return date(anchor.year - 1, 1, 1), date(anchor.year + 1, 1, 1)
    if view in ("week", "agenda"):
        return anchor - timedelta(days=7), anchor + timedelta(days=7)
    first = date(anchor.year, anchor.month, 1)
    prev = first - timedelta(days=1)
    nxt = date(anchor.year + (anchor.month // 12), (anchor.month % 12) + 1, 1)
    return date(prev.year, prev.month, 1), nxt


def _group_values() -> dict:
    """The distinct values each group dimension actually has, per ADOM scope.

    Read from the inventory, never a hand-kept list: a dimension offering a
    value no device carries produces a plan that resolves to zero targets, and
    the operator finds out only when the refusal comes back.
    """
    rows = visible_appliances().with_entities(
        Appliance.tags, Appliance.department, Appliance.zone, Appliance.line).all()
    out = {k: set() for k in GROUP_FIELDS}
    for tags, dept, zone, line in rows:
        for value, key in ((dept, "department"), (zone, "zone"), (line, "line")):
            if (value or "").strip():
                out[key].add(value.strip())
        try:
            parsed = json.loads(tags or "[]")
        except (ValueError, TypeError):
            parsed = []
        if isinstance(parsed, list):
            for t in parsed:
                if str(t or "").strip():
                    out["tag"].add(str(t).strip())
    return {k: sorted(v) for k, v in out.items()}


def _resolve_targets(mode: str, field: str, value: str, kinds) -> tuple:
    """``(device_ids, description, error)`` for the chosen target selector.

    ``kinds`` is the set of appliance kinds the chosen change type runs against;
    filtering here means the operator is refused at planning time with a
    sentence, instead of the scheduled run resolving to zero targets and closing
    the change as skipped hours later, inside the window.
    """
    q = visible_appliances()
    if mode == "devices":
        ids = [n for n in (_int(x) for x in request.form.getlist("device_ids"))
               if n is not None]
        if not ids:
            return [], "", "Pick at least one appliance."
        return ids, f"{len(ids)} appliance(s) selected by hand", ""

    rows = q.all()
    if mode == "adom":
        picked = [a for a in rows if (a.kind or "fortiweb") in kinds]
        desc = "every appliance in this ADOM the change type runs against"
    elif mode == "group":
        if field not in GROUP_FIELDS:
            return [], "", "Unknown group dimension."
        value = (value or "").strip()
        if not value:
            return [], "", "Pick a group value."
        picked = []
        for a in rows:
            if (a.kind or "fortiweb") not in kinds:
                continue
            if field == "tag":
                try:
                    tags = json.loads(a.tags or "[]")
                except (ValueError, TypeError):
                    tags = []
                hit = isinstance(tags, list) and value in [str(t) for t in tags]
            else:
                hit = (getattr(a, field, "") or "").strip() == value
            if hit:
                picked.append(a)
        desc = f"{GROUP_FIELDS[field]} = {value}"
    else:
        return [], "", "Unknown target mode."

    if not picked:
        # Refuse, never create an empty change. A change naming no device is
        # legal in this product (it stays visible in every ADOM), so an empty
        # resolution would save happily and do nothing on the night — the
        # failure mode this whole check exists to prevent.
        return [], "", (f"No visible appliance matches {desc}. Nothing was created.")
    return ([a.id for a in picked],
            f"{desc} → " + ", ".join(sorted(a.name for a in picked)), "")


@bp.route("/plan", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def plan():
    from .change_requests import _parse_dt, create_change_request

    # The page is switched off for this user, so this is a stale form or a
    # replay. Refused BEFORE anything is created: a change raised from a
    # calendar its author cannot open is a change nobody is watching for.
    if not _calendar_on():
        flash("Your Calendar is switched off — nothing was created. "
              "Switch it back on in your profile to plan from the grid.",
              "warning")
        return redirect(url_for("auth.profile") + "#calendar")

    back = request.form.get("back") or url_for("calendar_plan.index")
    action = (request.form.get("action") or "").strip()
    entry = {e["key"]: e for e in _type_entries()}.get(action)
    if entry is None:
        flash(f"{action or '(none)'} is not a change-controlled action.", "danger")
        return redirect(back)

    ids, desc, error = _resolve_targets(
        (request.form.get("target_mode") or "devices").strip(),
        (request.form.get("group_field") or "").strip(),
        request.form.get("group_value") or "",
        set(entry["products"]))
    if error:
        flash(error, "danger")
        return redirect(back)

    reason = (request.form.get("reason") or "").strip()
    # The selector is recorded next to the resolved list. Six months later
    # "which boxes was this approved for" must be answerable from the change
    # itself, and so must "what did the operator ask for" — they are different
    # questions and the second one has no other home.
    reason = (reason + ("\n\n" if reason else "")
              + f"Planned from the calendar. Target selector: {desc}.")

    cr, error = create_change_request({
        "title": request.form.get("title"),
        "action": action,
        "risk": request.form.get("risk"),
        "reason": reason,
        "device_ids": ids,
        "prep_ids": [],
        "window_start": _parse_dt(request.form.get("window_start")),
        "window_end": _parse_dt(request.form.get("window_end")),
        "rollback": request.form.get("rollback"),
        "notify_to": request.form.get("notify_to"),
        "owner": request.form.get("owner"),
        "doc_lang": request.form.get("doc_lang"),
        "requested_by": getattr(current_user, "username", ""),
        "approval_mode": request.form.get("approval_mode"),
    })
    if cr is None:
        flash(error, "danger")
        return redirect(back)

    log_action("calendar.plan", target=cr.title,
               detail=f"{cr.ref} / {action} / {desc}")
    flash(f"{cr.ref} raised as a draft — approve and schedule it to make it run.",
          "success")
    return redirect(url_for("change_requests.detail", id=cr.id))
