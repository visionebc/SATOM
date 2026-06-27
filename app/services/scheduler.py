"""Pure schedule math for ScheduledAction — no DB, no Flask, fully testable.

All datetimes are treated as UTC: the web service and the scheduler sidecar run
in UTC and use ``datetime.utcnow`` as the time source. Web port of the desktop
``services.scheduler``.
"""
from __future__ import annotations

from datetime import datetime, timedelta

SCHEDULE_KINDS = ("once", "interval", "daily", "weekly", "monthly")

_UNIT_SECONDS = {"minutes": 60, "hours": 3600, "days": 86400}


def _parse_hhmm(value: str, default=(0, 0)) -> tuple[int, int]:
    try:
        h, m = (value or "").split(":")
        return max(0, min(23, int(h))), max(0, min(59, int(m)))
    except (ValueError, AttributeError):
        return default


def _days_in_month(year: int, month: int) -> int:
    nxt = datetime(year + 1, 1, 1) if month == 12 else datetime(year, month + 1, 1)
    return (nxt - timedelta(days=1)).day


def _interval_seconds(spec: dict) -> int:
    try:
        every = int(spec.get("every", 0))
    except (ValueError, TypeError):
        every = 0
    return max(1, every) * _UNIT_SECONDS.get(spec.get("unit", "minutes"), 60)


def compute_next_run(kind: str, spec: dict, now: datetime | None = None) -> datetime | None:
    """Next fire time (UTC), or None if it never fires again (past one-shot)."""
    now = now or datetime.utcnow()
    spec = spec or {}

    if kind == "once":
        at = spec.get("at")
        if not at:
            return None
        try:
            dt = datetime.fromisoformat(at)
        except (ValueError, TypeError):
            return None
        return dt if dt > now else None

    if kind == "interval":
        return now + timedelta(seconds=_interval_seconds(spec))

    if kind == "daily":
        h, m = _parse_hhmm(spec.get("time", "00:00"))
        cand = now.replace(hour=h, minute=m, second=0, microsecond=0)
        if cand <= now:
            cand += timedelta(days=1)
        return cand

    if kind == "weekly":
        h, m = _parse_hhmm(spec.get("time", "00:00"))
        try:
            target = int(spec.get("weekday", 0)) % 7  # Mon=0 .. Sun=6
        except (ValueError, TypeError):
            target = 0
        cand = now.replace(hour=h, minute=m, second=0, microsecond=0)
        cand += timedelta(days=(target - cand.weekday()) % 7)
        if cand <= now:
            cand += timedelta(days=7)
        return cand

    if kind == "monthly":
        h, m = _parse_hhmm(spec.get("time", "00:00"))
        try:
            day = max(1, min(31, int(spec.get("day", 1))))
        except (ValueError, TypeError):
            day = 1
        year, month = now.year, now.month
        for _ in range(2):  # this month, then next month
            dim = _days_in_month(year, month)
            cand = datetime(year, month, min(day, dim), h, m)
            if cand > now:
                return cand
            month, year = (1, year + 1) if month == 12 else (month + 1, year)
        return None

    return None


def is_missed_fire(schedule_kind: str, spec: dict, next_run: datetime | None,
                   now: datetime | None = None) -> bool:
    """True when a non-catch-up action is overdue beyond its grace window and
    should be rolled forward WITHOUT running (so a box that was off for a week
    doesn't fire a week of backups at once)."""
    now = now or datetime.utcnow()
    if next_run is None or next_run > now:
        return False
    if schedule_kind == "interval":
        grace = max(_interval_seconds(spec) * 3, 300)
    else:
        grace = 300
    return (now - next_run).total_seconds() > grace
