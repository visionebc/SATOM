"""Guards for the Change Calendar (services.calendar_plan + views.calendar).

Every test here defends a rule that FAILS SILENTLY if broken — a change on the
wrong day, a projected dot asserting a run nobody observed, a conflict warning
that fires on every Tuesday until operators stop reading it. None of these
produce a traceback; they produce a calendar that is confidently wrong, which is
worse than a calendar that is obviously broken.

Companion mutation harness: tests/mutants_calendar.py (26 mutations, all must
bite). A guard that does not bite is not verification.
"""
from __future__ import annotations

import json
from datetime import date, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.services import calendar_plan as cal

TZ = "Europe/Zurich"          # UTC+2 in summer — the offset is the whole point


# --------------------------------------------------------------------------- #
# doubles
# --------------------------------------------------------------------------- #
def mk_cr(**kw):
    base = dict(id=1, ref="CR-0001", title="t", action="upgrade", status="draft",
                risk="medium", owner="", requested_by="", approved_by="",
                window_start=None, window_end=None, created_at=datetime(2026, 9, 1, 8, 0),
                device_ids_list=[], wave_group="", wave_index=None)
    base.update(kw)
    return SimpleNamespace(**base)


def mk_action(**kw):
    base = dict(id=1, name="sweep", action="metrics_scrape", product="fortiweb",
                enabled=True, schedule_kind="daily", created_by="admin",
                schedule_dict={"time": "02:00"})
    base.update(kw)
    return SimpleNamespace(**base)


def mk_run(**kw):
    base = dict(id=1, action_id=1, status="ok", trigger="schedule",
                summary="", started_at=datetime(2026, 9, 3, 1, 0),
                finished_at=datetime(2026, 9, 3, 1, 5))
    base.update(kw)
    return SimpleNamespace(**base)


# --------------------------------------------------------------------------- #
# timezone bucketing
# --------------------------------------------------------------------------- #
def test_day_is_bucketed_in_the_operator_timezone_not_utc():
    """23:30 UTC is TOMORROW in Zurich. Bucketing in UTC files the outage on
    the wrong day of the wall calendar the operator is reading."""
    dt = datetime(2026, 9, 8, 23, 30)          # 01:30 on the 9th, Zurich
    assert cal.local_date(dt, TZ) == date(2026, 9, 9)
    assert cal.local_date(dt, "UTC") == date(2026, 9, 8)


def test_utc_bounds_cover_the_whole_local_last_day():
    """A change starting 23:59 local on the last day belongs to that range."""
    start, end = cal.to_utc_bounds(date(2026, 9, 1), date(2026, 9, 30), TZ)
    late = datetime(2026, 9, 30, 21, 59)       # 23:59 Zurich
    assert start <= late < end


def test_unknown_timezone_degrades_to_utc_instead_of_500ing():
    assert cal.local_date(datetime(2026, 9, 8, 12, 0), "Mars/Olympus") == date(2026, 9, 8)


# --------------------------------------------------------------------------- #
# projection
# --------------------------------------------------------------------------- #
def test_projection_walks_the_real_scheduler():
    """Occurrences come from compute_next_run, not from a second implementation
    of schedule math that could promise an hour the executor does not keep."""
    start = datetime(2026, 9, 1, 0, 0)
    occ, trunc = cal.project("daily", {"time": "02:00"}, start,
                             start + timedelta(days=5), "UTC")
    assert [d.hour for d in occ] == [2, 2, 2, 2, 2]
    assert [d.day for d in occ] == [1, 2, 3, 4, 5]
    assert trunc is False


def test_projection_is_capped_and_says_so():
    """A three-minute sweep is 14k occurrences a month. Cut, and REPORTED cut —
    a number that quietly means 'the first 200' is a lie by omission."""
    start = datetime(2026, 9, 1, 0, 0)
    occ, trunc = cal.project("interval", {"minutes": 3}, start,
                             start + timedelta(days=30), "UTC", cap=50)
    assert len(occ) == 50
    assert trunc is True


def test_truncated_is_false_when_the_series_merely_continues_past_the_window():
    start = datetime(2026, 9, 1, 0, 0)
    occ, trunc = cal.project("daily", {"time": "02:00"}, start,
                             start + timedelta(days=3), "UTC", cap=200)
    assert len(occ) == 3 and trunc is False


def test_a_once_schedule_already_at_the_cursor_yields_nothing():
    stuck = datetime(2026, 9, 1, 0, 0)
    occ, trunc = cal.project("once", {"at": stuck.isoformat()}, stuck,
                             stuck + timedelta(days=5), "UTC")
    assert occ == [] and trunc is False


def test_a_non_advancing_scheduler_cannot_make_project_repeat_an_instant(
        monkeypatch):
    """``project`` never emits the same instant twice, whatever the scheduler
    says.

    Today's ``compute_next_run`` always advances — ``_interval_seconds`` has a
    one-second floor and every wall-clock kind rolls forward past ``now`` — so
    this cannot be provoked through a real schedule spec, and a test that fed
    one would pass on the ``nxt is None`` branch while claiming to exercise the
    guard. The scheduler is a DIFFERENT module and a future kind of its own is
    exactly the change that would break this silently: the cap bounds the loop,
    so the page would not hang, it would render two hundred identical rows for
    one job. The double is the only honest way to state that contract.
    """
    stuck = datetime(2026, 9, 1, 0, 0)
    monkeypatch.setattr(cal, "compute_next_run",
                        lambda kind, spec, cursor, tz=None: stuck)
    occ, trunc = cal.project("interval", {"every": 5}, stuck,
                             stuck + timedelta(days=5), "UTC")
    assert occ == [] and trunc is False


# --------------------------------------------------------------------------- #
# automation events
# --------------------------------------------------------------------------- #
def test_a_disabled_automation_projects_nothing():
    """enabled=False is the operator saying 'not this one'. Drawing its future
    puts work on the calendar the fleet has been told not to do."""
    start = datetime(2026, 9, 1)
    evs = cal.automation_events([mk_action(enabled=False)], start,
                                start + timedelta(days=10), TZ)
    assert evs == []


def test_automation_collapses_to_one_row_per_action_per_day():
    """480 identical chips is the same fact repeated until the page stops being
    readable. One row, with the count."""
    start = datetime(2026, 9, 1, 0, 0)
    evs = cal.automation_events([mk_action(schedule_kind="interval",
                                           schedule_dict={"minutes": 30})],
                                start, start + timedelta(days=2), TZ)
    days = [e["days"][0] for e in evs]
    assert len(days) == len(set(days)), "one row per day, not one per fire"
    assert all(e["count"] > 1 for e in evs)
    assert sum(e["count"] for e in evs) > 40


def test_individual_times_are_kept_but_capped_and_the_count_stays_true():
    start = datetime(2026, 9, 1, 0, 0)
    evs = cal.automation_events([mk_action(schedule_kind="interval",
                                           schedule_dict={"minutes": 3})],
                                start, start + timedelta(days=1), TZ, cap=400)
    ev = evs[0]
    assert len(ev["times"]) == cal.MAX_TIMES_PER_DAY
    assert ev["times_clipped"] is True
    assert ev["count"] > cal.MAX_TIMES_PER_DAY


# --------------------------------------------------------------------------- #
# change events
# --------------------------------------------------------------------------- #
def test_a_multi_day_window_appears_on_every_day_it_spans():
    """A four-day migration that shows only on its start date is invisible to
    whoever opens the calendar on day three — which is when they need it."""
    cr = mk_cr(window_start=datetime(2026, 9, 7, 20, 0),
               window_end=datetime(2026, 9, 10, 4, 0))
    ev = cal.change_events([cr], "UTC")[0]
    assert ev["days"] == [date(2026, 9, 7), date(2026, 9, 8),
                          date(2026, 9, 9), date(2026, 9, 10)]


def test_an_inverted_window_is_surfaced_as_invalid_never_dropped():
    """CR-0011 ended a day before it began and sat in 'approved' looking
    healthy. A change that can never fire must be visible, not filtered."""
    cr = mk_cr(window_start=datetime(2026, 8, 12, 0, 40),
               window_end=datetime(2026, 8, 11, 0, 40), status="approved")
    ev = cal.change_events([cr], "UTC")[0]
    assert ev["window_state"] == "invalid"
    assert ev["days"] == [date(2026, 8, 12)]


def test_a_zero_length_window_is_invalid_on_the_grid_too():
    """end == start contains no instant either, so it can never fire. ``>=``
    here would paint it as a healthy window right next to the ones that work —
    and the alert banner exists precisely to stop that."""
    at = datetime(2026, 9, 8, 22, 0)
    ev = cal.change_events([mk_cr(window_start=at, window_end=at)], "UTC")[0]
    assert ev["window_state"] == "invalid"


def test_a_change_with_no_window_is_open_not_invalid():
    """A draft nobody has dated yet is a legitimate state, not a defect."""
    ev = cal.change_events([mk_cr()], "UTC")[0]
    assert ev["window_state"] == "open"
    assert ev["days"] == [date(2026, 9, 1)]        # falls back to created_at


def test_a_runaway_span_is_clamped_and_flagged_not_silently_painted():
    cr = mk_cr(window_start=datetime(2026, 1, 1, 0, 0),
               window_end=datetime(2031, 1, 1, 0, 0))
    ev = cal.change_events([cr], "UTC")[0]
    assert len(ev["days"]) == cal.MAX_SPAN_DAYS
    assert ev["span_clipped"] is True


def test_a_deleted_device_is_named_by_id_never_rendered_blank():
    cr = mk_cr(device_ids_list=[7, 99])
    names = cal.change_events(
        [cr], "UTC",
        names_for=lambda c: [{7: "fortiweb12"}.get(i) or f"#{i}"
                             for i in c.device_ids_list])[0]["devices"]
    assert names == ["fortiweb12", "#99"]


def test_owner_falls_back_to_the_requester_never_to_blank():
    """'Who is accountable' is the column the whole feature was asked for."""
    ev = cal.change_events([mk_cr(owner="", requested_by="ana")], "UTC")[0]
    assert ev["owner"] == "ana"


# --------------------------------------------------------------------------- #
# runs — the measured past
# --------------------------------------------------------------------------- #
def test_a_run_keeps_its_own_status_never_an_inferred_one():
    ev = cal.run_events([mk_run(status="failed")], "UTC")[0]
    assert ev["status"] == "failed" and ev["kind"] == "run"


# --------------------------------------------------------------------------- #
# layout
# --------------------------------------------------------------------------- #
def test_changes_sort_above_automations_and_history_inside_a_day():
    day = date(2026, 9, 8)
    at = datetime(2026, 9, 8, 12, 0)
    events = (cal.run_events([mk_run(started_at=at)], "UTC")
              + cal.automation_events([mk_action()], datetime(2026, 9, 8),
                                      datetime(2026, 9, 9), "UTC")
              + cal.change_events([mk_cr(window_start=at,
                                         window_end=at + timedelta(hours=1))], "UTC"))
    order = [e["kind"] for e in cal.bucket_by_day(events)[day]]
    assert order[0] == "change" and order[-1] == "run"


def test_month_matrix_keeps_neighbour_month_events_in_the_padding_cells():
    """A window that starts on the 31st of last month and runs into this one is
    this month's problem too; blanking the padding cells hides it."""
    cr = mk_cr(window_start=datetime(2026, 8, 31, 22, 0),
               window_end=datetime(2026, 9, 1, 4, 0))
    buckets = cal.bucket_by_day(cal.change_events([cr], "UTC"))
    weeks = cal.month_matrix(2026, 9, buckets)
    outside = [c for w in weeks for c in w if c["outside"] and c["events"]]
    assert outside and outside[0]["date"] == date(2026, 8, 31)


def test_year_matrix_counts_only_the_days_of_its_own_month():
    buckets = cal.bucket_by_day(cal.change_events(
        [mk_cr(window_start=datetime(2026, 3, 4, 1, 0),
               window_end=datetime(2026, 3, 4, 2, 0))], "UTC"))
    months = cal.year_matrix(2026, buckets)
    assert months[2]["totals"]["change"] == 1
    assert sum(m["totals"]["change"] for m in months) == 1
    assert all(d["date"].month == m["month"] for m in months for d in m["days"])


def test_week_days_returns_seven_cells_starting_monday():
    week = cal.week_days(date(2026, 9, 10), {})       # a Thursday
    assert len(week) == 7
    assert week[0]["date"] == date(2026, 9, 7)
    assert week[0]["date"].weekday() == 0


# --------------------------------------------------------------------------- #
# conflicts
# --------------------------------------------------------------------------- #
def _pair(a_dev, b_dev, b_start_hour=1):
    a = mk_cr(id=1, ref="CR-1", status="approved", device_ids_list=a_dev,
              window_start=datetime(2026, 9, 8, 0, 0),
              window_end=datetime(2026, 9, 8, 4, 0))
    b = mk_cr(id=2, ref="CR-2", status="approved", device_ids_list=b_dev,
              window_start=datetime(2026, 9, 8, b_start_hour, 0),
              window_end=datetime(2026, 9, 8, b_start_hour + 3, 0))
    return cal.change_events([a, b], "UTC")


def test_overlapping_windows_on_a_shared_device_are_a_conflict():
    out = cal.conflicts(_pair([1, 2], [2, 3]))
    assert len(out) == 1 and out[0]["devices"] == [2]


def test_overlapping_windows_on_different_devices_are_NOT_a_conflict():
    """Parallel operations on different boxes are ordinary. Flagging them puts
    a warning on most Tuesdays and trains operators to ignore the one that
    matters."""
    assert cal.conflicts(_pair([1], [3])) == []


def test_a_handover_at_the_exact_boundary_is_not_a_collision():
    a = mk_cr(id=1, status="approved", device_ids_list=[1],
              window_start=datetime(2026, 9, 8, 0, 0),
              window_end=datetime(2026, 9, 8, 2, 0))
    b = mk_cr(id=2, status="approved", device_ids_list=[1],
              window_start=datetime(2026, 9, 8, 2, 0),
              window_end=datetime(2026, 9, 8, 4, 0))
    assert cal.conflicts(cal.change_events([a, b], "UTC")) == []


def test_cancelled_and_completed_changes_never_conflict():
    for dead in ("cancelled", "completed", "failed"):
        a = mk_cr(id=1, status=dead, device_ids_list=[1],
                  window_start=datetime(2026, 9, 8, 0, 0),
                  window_end=datetime(2026, 9, 8, 4, 0))
        b = mk_cr(id=2, status="approved", device_ids_list=[1],
                  window_start=datetime(2026, 9, 8, 1, 0),
                  window_end=datetime(2026, 9, 8, 3, 0))
        assert cal.conflicts(cal.change_events([a, b], "UTC")) == [], dead


def test_an_invalid_window_never_produces_a_conflict():
    """It cannot contend for anything — it can never open."""
    a = mk_cr(id=1, status="approved", device_ids_list=[1],
              window_start=datetime(2026, 9, 8, 4, 0),
              window_end=datetime(2026, 9, 8, 1, 0))
    b = mk_cr(id=2, status="approved", device_ids_list=[1],
              window_start=datetime(2026, 9, 8, 2, 0),
              window_end=datetime(2026, 9, 8, 5, 0))
    assert cal.conflicts(cal.change_events([a, b], "UTC")) == []
