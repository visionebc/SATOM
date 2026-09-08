"""Change Calendar — the planning surface over changes and automations.

Fleet -> Calendar. One grid that answers "what is happening to this fleet, and
when", across the two objects that already carry that fact:

  * :class:`~app.models.ChangeRequest`  — a PLANNED change: a window, a type of
    change, the devices it touches, its risk, its rollback and the person
    accountable for it (``owner``).
  * :class:`~app.models.ScheduledAction` — a RECURRING automation: a schedule
    kind and a spec, projected forward into the occurrences it will fire.
  * :class:`~app.models.ScheduledActionRun` — what actually RAN. History is
    measured, never re-derived (see PROJECTION IS FUTURE-ONLY below).

THIS MODULE INVENTS NO PLANNING OBJECT. A calendar that stored its own "planned
item" would be a second author of "what is a planned change", and the two would
disagree the first time somebody approved a change from the Change Requests page
instead of from here. Creating an entry from the calendar goes through
``views.change_requests.create_change_request`` — the ONE implementation of
"raise a change", with its device-visibility, product and single-target checks
intact. This module never writes.

It is also pure: no ORM query, no Flask, no ``current_user``. Callers hand it
rows they have ALREADY scoped to the active ADOM and to the viewer's
permissions, because scoping is a property of the request and this module has no
request. Filtering the grid while the by-id routes read the table raw is not
scoping, it is decoration.

Five rules it exists to keep. Each one is a mutation test in
``tests/test_calendar_plan.py``; none of them fails loudly if broken, which is
exactly why they are written down.

**PROJECTION IS FUTURE-ONLY; THE PAST IS MEASURED.**
Schedule math can say when a daily job *would have* fired last Tuesday. It
cannot say whether it did: the action may have been disabled, the sidecar may
have been down, the box may have been in maintenance. Painting a computed dot on
a past day asserts a run that nobody observed. Past days therefore carry
``ScheduledActionRun`` rows and nothing else, and :func:`project` starts at
``max(window_start, now)``.

**A DISABLED ACTION PROJECTS NOTHING.**
``enabled=False`` is the operator saying "not this one". Drawing its future
occurrences would put work on the calendar that the fleet has been told not to
do — and somebody plans around it.

**A TRUNCATED SERIES SAYS SO.**
A three-minute sweep is ~14,400 occurrences in a month. It is capped, and the
cap is reported per series so the grid can say "+N more" rather than showing a
number that quietly means "the first 200".

**DAYS ARE BUCKETED IN THE OPERATOR'S TIMEZONE.**
A window at 23:30 UTC is tomorrow in Europe/Zurich. Bucketing in UTC puts the
outage on the wrong day of the wall calendar the operator is reading — the same
class of defect already fixed once in this product, where a window typed as
22:00 Zurich was stored as if it were UTC and opened two hours late.

**A MULTI-DAY WINDOW APPEARS ON EVERY DAY IT SPANS.**
A four-day migration that shows only on its start date is invisible to whoever
opens the calendar on day three — which is precisely when they need to see it.

And one that is not a rule but a repair: an **inverted window**
(``window_end <= window_start``) is surfaced as ``invalid``, never dropped. Such
a change can never fire, because no instant lies inside its window. Hiding it is
how CR-0011 sat in ``approved`` for a month looking healthy.
"""
from __future__ import annotations

import calendar as _calendar
from datetime import date, datetime, timedelta, timezone

from .scheduler import compute_next_run

try:  # pragma: no cover - the stdlib path is the only one in production
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore[assignment]

__all__ = [
    "MAX_PER_SERIES", "MAX_SPAN_DAYS", "MAX_TIMES_PER_DAY", "KINDS",
    "project", "local_date", "local_dt", "to_utc_bounds",
    "change_events", "automation_events", "run_events",
    "bucket_by_day", "month_matrix", "week_days", "year_matrix",
    "conflicts", "window_state",
]

#: Occurrences drawn for ONE recurring action inside ONE view window. A
#: three-minute sweep would otherwise contribute five figures of identical dots
#: and drown every change in the month. Truncation is reported, never silent.
MAX_PER_SERIES = 200

#: How many days one change window may paint. A window is normally hours; a
#: five-year span is a typo in a ``datetime-local`` field, and letting it colour
#: every cell would make the grid useless rather than making the typo obvious.
#: The event is still shown (on its first MAX_SPAN_DAYS days) and flagged.
MAX_SPAN_DAYS = 90

#: Individual fire times listed for one automation on one day. Past this the row
#: reports its ``count`` alone: a reader gets nothing from the 43rd timestamp of
#: a three-minute sweep that they did not already have from "×480".
MAX_TIMES_PER_DAY = 12

#: The three event families. Kept as data because the filter chips, the legend
#: and the per-day counters all render from it — three hand-copied lists is how
#: a legend ends up describing a colour the grid does not use.
KINDS = ("change", "automation", "run")


# --------------------------------------------------------------------------- #
# timezone helpers
# --------------------------------------------------------------------------- #
def _zone(tz: str | None):
    if not tz or ZoneInfo is None:
        return timezone.utc
    try:
        return ZoneInfo(tz)
    except Exception:  # noqa: BLE001 — an unknown tz must not 500 the page
        return timezone.utc


def local_dt(dt: datetime | None, tz: str | None) -> datetime | None:
    """A naive-UTC instant rendered in the operator's timezone (naive again).

    Naive out as well as in: every consumer here formats or compares against
    other local values, and mixing aware and naive datetimes in the same
    comparison is a TypeError that only fires on the one row that has a
    timezone.
    """
    if dt is None:
        return None
    return (dt.replace(tzinfo=timezone.utc)
              .astimezone(_zone(tz))
              .replace(tzinfo=None))


def local_date(dt: datetime | None, tz: str | None) -> date | None:
    """Which day of the operator's wall calendar an instant falls on."""
    loc = local_dt(dt, tz)
    return loc.date() if loc is not None else None


def to_utc_bounds(day_from: date, day_to: date, tz: str | None) -> tuple:
    """``[start, end)`` in naive UTC covering these LOCAL days, inclusive.

    The half-open end is midnight after ``day_to``: a change starting at 23:59
    local on the last day of the month belongs to that month, and a closed
    bound computed from the same day would drop it.
    """
    zone = _zone(tz)
    start = (datetime(day_from.year, day_from.month, day_from.day, tzinfo=zone)
             .astimezone(timezone.utc).replace(tzinfo=None))
    nxt = day_to + timedelta(days=1)
    end = (datetime(nxt.year, nxt.month, nxt.day, tzinfo=zone)
           .astimezone(timezone.utc).replace(tzinfo=None))
    return start, end


# --------------------------------------------------------------------------- #
# projection
# --------------------------------------------------------------------------- #
def project(kind: str, spec: dict, start: datetime, end: datetime,
            tz: str | None = None, cap: int = MAX_PER_SERIES) -> tuple:
    """``(occurrences, truncated)`` for one schedule inside ``[start, end)``.

    Schedule math is NOT reimplemented here: every step is
    :func:`app.services.scheduler.compute_next_run`, the function the sidecar
    itself fires from. A second implementation would let the calendar promise a
    time the executor does not keep, and the disagreement would only ever be
    discovered by someone waiting for a job at the hour the grid claimed.

    ``truncated`` is True only when the cap cut off occurrences that really do
    fall inside the window — not merely when the series continues past it.
    """
    out: list[datetime] = []
    cursor = start
    for _ in range(max(0, int(cap))):
        nxt = compute_next_run(kind, spec, cursor, tz)
        # ``nxt <= cursor`` cannot happen for a well-formed spec, and it is a
        # non-negotiable loop guard: a schedule that fails to advance would
        # otherwise spin here until the request times out, taking the page down
        # rather than rendering one wrong row.
        if nxt is None or nxt >= end or nxt <= cursor:
            return out, False
        out.append(nxt)
        cursor = nxt
    nxt = compute_next_run(kind, spec, cursor, tz)
    return out, bool(nxt is not None and cursor < nxt < end)


# --------------------------------------------------------------------------- #
# event construction
# --------------------------------------------------------------------------- #
def window_state(cr) -> str:
    """``ok`` | ``invalid`` | ``open`` — is this change's window usable?

    ``open`` is a change with no window yet (a draft somebody is still writing);
    it is a legitimate state and must not read as broken. ``invalid`` is a
    window that ends at or before it starts, which can never contain an instant
    and therefore can never fire. That is a defect in the row, and the calendar
    is the surface where it becomes visible.
    """
    if cr.window_start is None and cr.window_end is None:
        return "open"
    if cr.window_start is None or cr.window_end is None:
        return "open"
    return "ok" if cr.window_end > cr.window_start else "invalid"


def _span_days(start_d: date, end_d: date) -> tuple:
    """Every local day a window covers, and whether the span was clamped."""
    if end_d < start_d:
        return [start_d], False
    total = (end_d - start_d).days + 1
    clipped = total > MAX_SPAN_DAYS
    n = MAX_SPAN_DAYS if clipped else total
    return [start_d + timedelta(days=i) for i in range(n)], clipped


def change_events(crs, tz: str | None, *, label_for=None, names_for=None,
                  url_for_cr=None) -> list:
    """Planned changes as calendar events.

    ``crs`` are ALREADY scoped by the caller. ``label_for(action_key)`` renders
    the change type in the viewer's language (administrator-defined types have
    no compiled label), ``names_for(cr)`` resolves device ids to names, and
    ``url_for_cr(cr)`` builds the link — all injected, so this module needs
    neither the ORM, the i18n store nor a request context.
    """
    events = []
    for cr in crs:
        state = window_state(cr)
        start = cr.window_start
        end = cr.window_end
        if state == "open":
            # No window: it still belongs on the calendar, on the day it was
            # raised, flagged as unscheduled. Dropping it would hide the drafts
            # that most need somebody to give them a date.
            anchor = local_date(start or cr.created_at, tz)
            days, clipped = [anchor], False
        elif state == "invalid":
            days, clipped = [local_date(start, tz)], False
        else:
            days, clipped = _span_days(local_date(start, tz), local_date(end, tz))
        events.append({
            "kind": "change",
            "id": cr.id,
            "ref": getattr(cr, "ref", "") or f"CR-{cr.id}",
            "title": cr.title or "(untitled)",
            "action": cr.action,
            "action_label": (label_for(cr.action) if label_for else cr.action),
            "status": cr.status,
            "risk": cr.risk or "medium",
            "owner": (cr.owner or cr.requested_by or "").strip(),
            "requested_by": (cr.requested_by or "").strip(),
            "approved_by": (cr.approved_by or "").strip(),
            "start": local_dt(start, tz),
            "end": local_dt(end, tz),
            "window_state": state,
            "span_clipped": clipped,
            "devices": (names_for(cr) if names_for else []),
            "device_ids": list(cr.device_ids_list or []),
            "wave": (getattr(cr, "wave_group", "") or ""),
            "wave_index": getattr(cr, "wave_index", None),
            "url": (url_for_cr(cr) if url_for_cr else ""),
            "days": [d for d in days if d is not None],
        })
    return events


def automation_events(actions, start: datetime, end: datetime, tz: str | None,
                      *, label_for=None, url_for_action=None,
                      cap: int = MAX_PER_SERIES) -> list:
    """Future occurrences of the recurring automations, **one event per
    (action, day)** — not one per fire.

    ONE ROW PER ACTION PER DAY IS THE WHOLE POINT. The fleet runs sweeps every
    three minutes; a month of those is fourteen thousand occurrences, and drawn
    one-per-fire they rendered a 900 kB agenda in which four hundred and eighty
    identical lines said the same thing and buried every actual change under
    them. "metrics_scrape ×480" is what somebody planning a maintenance window
    needs to know. Four hundred and eighty chips is not more detail, it is the
    same fact repeated until the page stops being readable.

    The individual times are kept (``times``, capped at
    :data:`MAX_TIMES_PER_DAY`) so a daily or weekly job — the kind that fires
    once or twice and whose exact hour matters — still shows its hour, and
    ``count`` always reports the true number even when ``times`` was clipped.

    ``start`` is clamped forward to "now" by the caller; see PROJECTION IS
    FUTURE-ONLY in the module docstring.
    """
    events = []
    for act in actions:
        if not act.enabled:
            continue
        occurrences, truncated = project(
            act.schedule_kind, act.schedule_dict, start, end, tz, cap)
        by_day: dict = {}
        for at in occurrences:
            day = local_date(at, tz)
            if day is not None:
                by_day.setdefault(day, []).append(at)
        for day in sorted(by_day):
            times = by_day[day]
            events.append({
                "kind": "automation",
                "id": act.id,
                "ref": f"SA-{act.id}",
                "title": act.name or act.action,
                "action": act.action,
                "action_label": (label_for(act.action) if label_for else act.action),
                "status": "planned",
                "risk": "",
                "owner": (act.created_by or "").strip(),
                "schedule_kind": act.schedule_kind,
                "product": act.product,
                "start": local_dt(times[0], tz),
                "end": local_dt(times[-1], tz) if len(times) > 1 else None,
                "count": len(times),
                "times": [local_dt(t, tz) for t in times[:MAX_TIMES_PER_DAY]],
                "times_clipped": len(times) > MAX_TIMES_PER_DAY,
                "truncated": truncated,
                "url": (url_for_action(act) if url_for_action else ""),
                "days": [day],
            })
    return events


def run_events(runs, tz: str | None, *, name_for=None, url_for_run=None) -> list:
    """What actually ran — the measured past.

    ``runs`` are ``(ScheduledActionRun, action_name)`` pairs or rows the caller
    can name through ``name_for``. Status is the row's own, never inferred: a
    run recorded as ``failed`` is drawn as failed even if the schedule says it
    should have succeeded.
    """
    events = []
    for run in runs:
        day = local_date(run.started_at, tz)
        if day is None:
            continue
        events.append({
            "kind": "run",
            "id": run.id,
            "ref": f"RUN-{run.id}",
            "title": (name_for(run) if name_for else f"action #{run.action_id}"),
            "action": "",
            "action_label": "",
            "status": run.status or "running",
            "risk": "",
            "owner": "",
            "trigger": run.trigger or "schedule",
            "summary": (run.summary or "").strip(),
            "start": local_dt(run.started_at, tz),
            "end": local_dt(run.finished_at, tz),
            "url": (url_for_run(run) if url_for_run else ""),
            "days": [day],
        })
    return events


# --------------------------------------------------------------------------- #
# layout
# --------------------------------------------------------------------------- #
def _sort_key(ev):
    """Order inside a day: changes first, then automations, then history.

    A window that takes production down outranks the hourly sync that happens
    during it, and an operator scanning a cell reads the first line.
    """
    rank = {"change": 0, "automation": 1, "run": 2}.get(ev["kind"], 3)
    return (rank, ev["start"] or datetime.max, str(ev.get("ref") or ""))


def bucket_by_day(events) -> dict:
    """``{date: [event, ...]}``, each event repeated on every day it spans."""
    out: dict = {}
    for ev in events:
        for day in ev.get("days") or []:
            out.setdefault(day, []).append(ev)
    for day in out:
        out[day].sort(key=_sort_key)
    return out


def month_matrix(year: int, month: int, buckets: dict, *,
                 today: date | None = None, first_weekday: int = 0) -> list:
    """Weeks of cells for one month, Monday-first by default.

    Leading/trailing cells belong to the neighbouring months and are marked
    ``outside``; they still carry their events, because a window that starts on
    the 31st of the previous month and runs into this one is this month's
    problem too.
    """
    cal = _calendar.Calendar(firstweekday=first_weekday)
    weeks = []
    for week in cal.monthdatescalendar(year, month):
        row = []
        for day in week:
            items = buckets.get(day, [])
            row.append({
                "date": day,
                "outside": day.month != month,
                "today": (today is not None and day == today),
                "events": items,
                "counts": {k: sum(1 for e in items if e["kind"] == k)
                           for k in KINDS},
            })
        weeks.append(row)
    return weeks


def week_days(anchor: date, buckets: dict, *, today: date | None = None,
              first_weekday: int = 0) -> list:
    """The seven cells of the week containing ``anchor``."""
    offset = (anchor.weekday() - first_weekday) % 7
    monday = anchor - timedelta(days=offset)
    out = []
    for i in range(7):
        day = monday + timedelta(days=i)
        items = buckets.get(day, [])
        out.append({
            "date": day,
            "outside": False,
            "today": (today is not None and day == today),
            "events": items,
            "counts": {k: sum(1 for e in items if e["kind"] == k) for k in KINDS},
        })
    return out


def year_matrix(year: int, buckets: dict) -> list:
    """Twelve months of per-day counts — the whole-year planning view.

    Counts only; a year of event objects is a page nobody can read. The month
    header links through to the month grid, which is where the detail lives.
    """
    months = []
    for m in range(1, 13):
        days = []
        total = {k: 0 for k in KINDS}
        for day in _calendar.Calendar().itermonthdates(year, m):
            if day.month != m:
                continue
            items = buckets.get(day, [])
            counts = {k: sum(1 for e in items if e["kind"] == k) for k in KINDS}
            for k in KINDS:
                total[k] += counts[k]
            days.append({"date": day, "counts": counts,
                         "n": sum(counts.values())})
        months.append({"month": m, "name": _calendar.month_name[m],
                       "days": days, "totals": total})
    return months


# --------------------------------------------------------------------------- #
# conflicts
# --------------------------------------------------------------------------- #
def conflicts(events) -> list:
    """Pairs of planned changes that overlap in time AND share a device.

    SHARING A DEVICE IS THE WHOLE TEST. Two windows at the same hour against
    different appliances are ordinary parallel operations; flagging them would
    put a warning on most Tuesdays and train every operator to ignore the
    warning that matters. What is worth stopping is two changes reconfiguring
    the SAME box at the same time, where the second one's pre-flight was taken
    against a state the first one is in the middle of replacing.

    Cancelled and completed changes never conflict: a window that is over, or
    that was called off, cannot contend for anything.
    """
    live = [e for e in events
            if e["kind"] == "change"
            and e["window_state"] == "ok"
            and e["status"] not in ("cancelled", "completed", "failed")
            and e["device_ids"]]
    live.sort(key=lambda e: e["start"])
    out = []
    for i, a in enumerate(live):
        for b in live[i + 1:]:
            if b["start"] >= a["end"]:
                # Sorted by start: nothing further along can overlap ``a``
                # either. Half-open comparison on purpose — a window that ends
                # at exactly the instant the next one begins is a handover, not
                # a collision.
                break
            shared = sorted(set(a["device_ids"]) & set(b["device_ids"]))
            if shared:
                out.append({"a": a, "b": b, "devices": shared})
    return out
