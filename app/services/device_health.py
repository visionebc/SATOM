"""Device health roll-up for Monitoring -> Fleet health.

Until 2026-07-28 the badge on each appliance card was computed **only** from
capacity headroom (``services.capacity.fleet_headroom``). No appliance in this
fleet has an ``effective_cap``, so every headroom row scored ``nocap`` and the
badge was *structurally incapable* of leaving ``healthy``: a powered-off box, a
harvest that had been failing for days and an expired licence all rendered
green. A monitoring page that can only deliver good news teaches the operator
to ignore it.

This module adds the signals that answer *"is the device still there?"* and
rolls them up with capacity into ONE status plus the human reasons behind it.
Everything is DB-first -- a page load still never touches an appliance (the
same contract as the rest of Monitoring).

Signals
-------
``sync``      the last ``SyncRun`` rows for the device. One error is a warning,
              an unbroken streak is critical, and a device that never synced is
              ``unknown`` (NOT ok).
``cache``     age of the newest ``DeviceSnapshot``. Nothing cached is a
              warning; older than ``monitoring.stale_hours`` is a warning;
              older than ``CRIT_STALE_MULT`` x that is critical.
``probe``     worst ``last_status`` across the device's ENABLED deep monitors.
              Probes that are all disabled are reported as *lost coverage*, not
              as health -- a disabled probe is not a passing probe.
``capacity``  the pre-existing headroom check, unchanged.

The roll-up is the worst of the four. ``unknown`` ranks BELOW ``ok`` so a
device we can say nothing about renders as unknown rather than healthy, but a
single measured-good signal is enough to leave that state.
"""
from __future__ import annotations

from datetime import datetime

# Severity ladder. ``unknown`` is deliberately the LOWEST rank: it must never
# win over a real measurement, but it must also never be printed as "healthy".
RANK = {"unknown": 0, "ok": 1, "warn": 2, "crit": 3}

DEFAULT_STALE_HOURS = 6.0     # device_sync runs hourly (scheduled action id 5)
CRIT_STALE_MULT = 4.0
ERROR_STREAK_CRIT = 3
SYNC_LOOKBACK = 5             # how many runs back a streak is measured over

# Deep-monitor statuses (services.deep_monitor.STATUS_ORDER) mapped onto the
# ladder above. ``error`` means the probe could not be EXECUTED (SSH refused,
# connect timeout): a warning on its own, and the sync streak escalates the
# genuinely dead devices to critical.
_PROBE_MAP = {"crit": "crit", "error": "warn", "warn": "warn",
              "ok": "ok", "unknown": "unknown"}

SIGNAL_LABEL = {"sync": "Harvest", "cache": "Cache",
                "probe": "Deep monitors", "capacity": "Capacity"}


def worst_of(statuses) -> str:
    """Highest-severity status in *statuses* (``unknown`` ranks lowest)."""
    out = "unknown"
    for s in statuses:
        if RANK.get(s, 0) > RANK.get(out, 0):
            out = s
    return out


def stale_hours() -> float:
    """Cache-age budget before a device is called stale. Operator-tunable via
    the ``monitoring.stale_hours`` setting."""
    from ..models import AppSetting
    try:
        v = float(AppSetting.get("monitoring.stale_hours", "") or DEFAULT_STALE_HOURS)
    except (TypeError, ValueError):
        return DEFAULT_STALE_HOURS
    return v if v > 0 else DEFAULT_STALE_HOURS


def _ago(dt) -> str:
    if not isinstance(dt, datetime):
        return "at an unknown time"
    secs = int((datetime.utcnow() - dt).total_seconds())
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{secs // 60} min ago"
    if secs < 86400:
        return f"{secs // 3600} h ago"
    return f"{secs // 86400} d ago"


def _hours(h: float) -> str:
    if h < 1:
        return f"{int(h * 60)} min"
    if h < 48:
        return f"{h:.0f} h"
    return f"{h / 24:.0f} d"


# --- individual signals ------------------------------------------------------

def sync_signal(appliance_id: int) -> dict:
    """Status of the hourly harvest for one device."""
    from ..models_cache import SyncRun
    try:
        rows = (SyncRun.query
                .filter(SyncRun.appliance_id == appliance_id,
                        SyncRun.status.in_(("ok", "error")))
                .order_by(SyncRun.started_at.desc())
                .limit(SYNC_LOOKBACK).all())
    except Exception:  # noqa: BLE001 -- a broken signal must not break the page
        return {"status": "unknown", "text": "harvest history unavailable"}
    if not rows:
        return {"status": "unknown", "text": "never harvested"}
    last = rows[0]
    if last.status != "error":
        return {"status": "ok", "text": f"harvest ok {_ago(last.started_at)}"}
    streak = 0
    for r in rows:
        if r.status != "error":
            break
        streak += 1
    head = ((last.detail or "").strip().splitlines() or ["no detail"])[0][:160]
    status = "crit" if streak >= ERROR_STREAK_CRIT else "warn"
    plural = "s" if streak != 1 else ""
    return {"status": status, "streak": streak,
            "text": f"harvest failing ({streak} run{plural} in a row) - {head}"}


def cache_signal(meta: dict | None, hours: float | None = None) -> dict:
    """Freshness of the cached configuration this ADOM renders from."""
    hours = stale_hours() if hours is None else hours
    ga = (meta or {}).get("generated_at")
    if isinstance(ga, str):
        try:
            ga = datetime.fromisoformat(ga)
        except ValueError:
            ga = None
    if not isinstance(ga, datetime):
        return {"status": "warn", "text": "no cached configuration on this node"}
    age = (datetime.utcnow() - ga).total_seconds() / 3600.0
    if age >= hours * CRIT_STALE_MULT:
        return {"status": "crit",
                "text": f"cache {_hours(age)} old (budget {hours:g} h)"}
    if age >= hours:
        return {"status": "warn",
                "text": f"cache {_hours(age)} old (budget {hours:g} h)"}
    return {"status": "ok", "text": f"cache {_hours(age)} old"}


def probe_signal(appliance_id: int) -> dict:
    """Worst enabled deep monitor bound to this device."""
    from ..models import MonitorProbe
    try:
        rows = MonitorProbe.query.filter(
            MonitorProbe.appliance_id == appliance_id).all()
    except Exception:  # noqa: BLE001
        return {"status": "unknown", "text": "deep monitors unavailable"}
    if not rows:
        return {"status": "unknown", "text": "no deep monitors configured"}
    on = [p for p in rows if p.enabled]
    if not on:
        n = len(rows)
        return {"status": "warn",
                "text": f"all {n} deep monitor{'s' if n != 1 else ''} disabled - no coverage"}
    mapped = [_PROBE_MAP.get(p.last_status or "unknown", "unknown") for p in on]
    st = worst_of(mapped)
    if st in ("warn", "crit"):
        bad = [p.name or p.kind for p, m in zip(on, mapped) if m in ("warn", "crit")]
        return {"status": st,
                "text": f"{len(bad)}/{len(on)} probes alerting: " + ", ".join(bad[:4])}
    if st == "ok":
        return {"status": "ok", "text": f"{len(on)} probes ok"}
    return {"status": "unknown", "text": f"{len(on)} probes have never run"}


def capacity_signal(caps) -> dict:
    """Roll the pre-existing headroom rows into one signal. Rows with no
    admin cap stay ``unknown`` -- 'not measured' is not 'fine'."""
    caps = caps or []
    graded = [c for c in caps if c.get("status") in ("ok", "warn", "crit")]
    if not graded:
        return {"status": "unknown",
                "text": f"no admin caps set ({len(caps)} object types)"}
    st = worst_of([c["status"] for c in graded])
    if st in ("warn", "crit"):
        bad = [f"{c.get('label')} {c.get('pct')}%" for c in graded
               if c["status"] in ("warn", "crit")]
        return {"status": st, "text": "over threshold: " + ", ".join(bad[:4])}
    return {"status": "ok", "text": f"{len(graded)} capped object types within budget"}


# --- roll-up -----------------------------------------------------------------

def collect(appliance, caps=None, meta=None, hours: float | None = None) -> dict:
    """Full health verdict for one appliance.

    Returns ``{status, signals: {key: {status, text}}, reasons: [...]}`` where
    *reasons* holds only the signals that are not ok, worst first -- what the
    card prints under the badge so the state is never unexplained.
    """
    hours = stale_hours() if hours is None else hours
    aid = getattr(appliance, "id", None)
    signals = {
        "sync": sync_signal(aid) if aid else {"status": "unknown", "text": "no device"},
        "cache": cache_signal(meta, hours),
        "probe": probe_signal(aid) if aid else {"status": "unknown", "text": "no device"},
        "capacity": capacity_signal(caps),
    }
    status = worst_of([s["status"] for s in signals.values()])
    reasons = [{"signal": k, "label": SIGNAL_LABEL[k], **v}
               for k, v in signals.items() if v["status"] != "ok"]
    reasons.sort(key=lambda r: -RANK.get(r["status"], 0))
    return {"status": status, "signals": signals, "reasons": reasons,
            "maintenance": bool(getattr(appliance, "maintenance_mode", False)
                                or getattr(appliance, "maintenance", False))}
