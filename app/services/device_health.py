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


#: Roll-up keys this module resolves from a product scope. The constants above
#: remain the SHIPPED defaults; ``services.thresholds`` decides whether a
#: product overrides them.
_ROLLUP_KEYS = ("stale_hours", "crit_stale_mult", "error_streak_crit",
                "capacity_warn_pct", "capacity_crit_pct")


def scope_of(appliance) -> str:
    """The threshold scope a device inherits — its product key."""
    return (getattr(appliance, "kind", "") or "").strip().lower()


def limits(scope: str = "") -> dict:
    """Every roll-up threshold for one product, resolved once per device.

    A FortiAnalyzer legitimately lives at a different cache cadence and a
    different disk-shaped normality than a FortiWeb; one global number for the
    whole fleet is how a correct product ends up permanently amber, and a check
    that always complains is a check the operator learns to skip.
    """
    out = {"stale_hours": DEFAULT_STALE_HOURS,
           "crit_stale_mult": CRIT_STALE_MULT,
           "error_streak_crit": ERROR_STREAK_CRIT,
           "capacity_warn_pct": 80.0, "capacity_crit_pct": 95.0}
    try:
        from . import thresholds as th
        for k in _ROLLUP_KEYS:
            v = th.rollup(scope, k).value
            if v is not None:
                out[k] = v
    except Exception:  # noqa: BLE001 — a threshold read must never sink the page
        pass
    if not out["stale_hours"] or float(out["stale_hours"]) <= 0:
        out["stale_hours"] = DEFAULT_STALE_HOURS
    return out


def stale_hours(scope: str = "") -> float:
    """Cache-age budget before a device is called stale.

    Resolution order (``services.thresholds``): the product's own
    ``stale_hours`` > the legacy global ``monitoring.stale_hours`` > the
    shipped default. The legacy key is honoured so an operator who set it years
    ago keeps what they set until they say otherwise on the Thresholds page."""
    return float(limits(scope)["stale_hours"])


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

def sync_signal(appliance_id: int, streak_crit: int | None = None) -> dict:
    """Status of the hourly harvest for one device."""
    streak_crit = int(streak_crit or ERROR_STREAK_CRIT)
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
    status = "crit" if streak >= streak_crit else "warn"
    plural = "s" if streak != 1 else ""
    return {"status": status, "streak": streak,
            "text": f"harvest failing ({streak} run{plural} in a row) - {head}"}


def cache_signal(meta: dict | None, hours: float | None = None,
                 mult: float | None = None) -> dict:
    """Freshness of the cached configuration this ADOM renders from."""
    hours = stale_hours() if hours is None else hours
    mult = float(mult or CRIT_STALE_MULT)
    ga = (meta or {}).get("generated_at")
    if isinstance(ga, str):
        try:
            ga = datetime.fromisoformat(ga)
        except ValueError:
            ga = None
    if not isinstance(ga, datetime):
        return {"status": "warn", "text": "no cached configuration on this node"}
    age = (datetime.utcnow() - ga).total_seconds() / 3600.0
    if age >= hours * mult:
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
    # A SUPPRESSED probe is withheld from the roll-up -- from this ONE roll-up,
    # which is what both the badge and the mail read, so the page and the
    # mailbox cannot disagree (the divergence device_health exists to prevent).
    # The probe itself keeps running, keeps storing samples and keeps showing
    # its real status on its own row with a reason and an expiry; what it stops
    # doing is speaking for the whole device. It is reported here as lost
    # coverage for the same reason a disabled probe is: a silence somebody
    # chose is still a silence.
    sup = [p for p in on if getattr(p, "suppressed", False)]
    live = [p for p in on if not getattr(p, "suppressed", False)]
    tail = (f"; {len(sup)} suppressed" if sup else "")
    if not live:
        return {"status": "unknown", "suppressed": len(sup),
                "text": f"all {len(on)} enabled probes suppressed - no coverage"}
    mapped = [_PROBE_MAP.get(p.last_status or "unknown", "unknown") for p in live]
    st = worst_of(mapped)
    if st in ("warn", "crit"):
        bad = [p.name or p.kind for p, m in zip(live, mapped) if m in ("warn", "crit")]
        return {"status": st, "suppressed": len(sup),
                "text": f"{len(bad)}/{len(live)} probes alerting: "
                        + ", ".join(bad[:4]) + tail}
    if st == "ok":
        return {"status": "ok", "suppressed": len(sup),
                "text": f"{len(live)} probes ok" + tail}
    return {"status": "unknown", "suppressed": len(sup),
            "text": f"{len(live)} probes have never run" + tail}


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

def collect(appliance, caps=None, meta=None, hours: float | None = None,
            lim: dict | None = None) -> dict:
    """Full health verdict for one appliance.

    Returns ``{status, signals: {key: {status, text}}, reasons: [...]}`` where
    *reasons* holds only the signals that are not ok, worst first -- what the
    card prints under the badge so the state is never unexplained.
    """
    scope = scope_of(appliance)
    lim = lim or limits(scope)
    hours = float(lim["stale_hours"]) if hours is None else hours
    aid = getattr(appliance, "id", None)
    signals = {
        "sync": (sync_signal(aid, lim["error_streak_crit"]) if aid
                 else {"status": "unknown", "text": "no device"}),
        "cache": cache_signal(meta, hours, lim["crit_stale_mult"]),
        "probe": probe_signal(aid) if aid else {"status": "unknown", "text": "no device"},
        "capacity": capacity_signal(caps),
    }
    status = worst_of([s["status"] for s in signals.values()])
    reasons = [{"signal": k, "label": SIGNAL_LABEL[k], **v}
               for k, v in signals.items() if v["status"] != "ok"]
    reasons.sort(key=lambda r: -RANK.get(r["status"], 0))
    return {"status": status, "signals": signals, "reasons": reasons,
            "scope": scope, "limits": lim,
            "maintenance": bool(getattr(appliance, "maintenance_mode", False)
                                or getattr(appliance, "maintenance", False))}


# --- shared gathering path ---------------------------------------------------
# The Monitoring view and the alert engine MUST grade a device the same way.
# Two ladders would let the page print "critical" while the mail stays silent --
# which is the failure this whole module exists to remove. These helpers are the
# single gathering path; the view still owns rendering, the engine owns dispatch.

def thresholds(scope: str = "") -> tuple[float, float]:
    """Capacity warn/crit percentages for one product.

    Resolution order: the product's ``capacity_warn_pct`` / ``capacity_crit_pct``
    on the Thresholds page > the legacy global ``capacity.warn_pct`` /
    ``capacity.crit_pct`` > 80 / 95."""
    from ..models import AppSetting

    def _f(key, default):
        try:
            return float(AppSetting.get(key, str(default)) or default)
        except (TypeError, ValueError):
            return float(default)

    lim = limits(scope)
    warn = lim.get("capacity_warn_pct")
    crit = lim.get("capacity_crit_pct")
    if warn is None:
        warn = _f("capacity.warn_pct", 80.0)
    if crit is None:
        crit = _f("capacity.crit_pct", 95.0)
    return float(warn), float(crit)


def capacity_rows(appliance, warn: float, crit: float) -> list:
    """Headroom rows for *appliance*, each graded ok/warn/crit/nocap.

    ``nocap`` means no admin cap is set for that object type -- deliberately NOT
    graded, so :func:`capacity_signal` can report it as unknown instead of
    passing it off as healthy."""
    from . import capacity as capsvc
    rows = []
    try:
        headroom = capsvc.fleet_headroom(appliance)
    except Exception:  # noqa: BLE001 -- a broken cap table must not sink the page
        return rows
    for h in headroom:
        pct, status = None, "nocap"
        if h.effective_cap:
            pct = round(100.0 * h.used / h.effective_cap, 1)
            status = "crit" if pct >= crit else ("warn" if pct >= warn else "ok")
        row = h.to_dict()
        row.update(pct=pct, status=status)
        rows.append(row)
    return rows


def cache_meta(appliance) -> dict:
    """Freshness meta for the NEWEST cached layer of *appliance*.

    Every layer is asked and the newest ``generated_at`` wins, because the
    layers refresh on different clocks: ``config`` hourly (``device_sync``),
    ``deep`` nightly (``deep_capture``, FortiWeb-only). Two things follow, and
    both were live bugs until 2026-08-05:

    * Grading the NIGHTLY layer against ``monitoring.stale_hours`` (6 h, the
      cadence of the HOURLY sync) is red 18 hours out of 24 on a healthy box.
    * FortiADC / FortiAnalyzer / FortiAuthenticator have no deep layer at all,
      so a deep-first reader calls them "never cached" while they hold a
      snapshot minutes old.

    The membership test is ``cached``, NOT the truthiness of the dict:
    :func:`read_layer._layer_meta` returns a populated four-key dict even when
    there is no snapshot, so ``if meta:`` is always true and the second layer
    was unreachable.
    """
    from . import read_layer
    best: dict = {}
    for layer in ("config", "deep"):
        try:
            meta = read_layer._layer_meta(appliance.id, layer=layer) or {}
        except Exception:  # noqa: BLE001
            continue
        if not meta.get("cached"):
            continue
        ga, best_ga = meta.get("generated_at"), best.get("generated_at")
        if best_ga is None or (ga is not None and ga > best_ga):
            best = meta
    return best


def collect_for(appliance, warn=None, crit=None, hours: float | None = None) -> dict:
    """:func:`collect` for a caller that has not gathered caps/meta itself --
    the entry point for everything outside the Monitoring view.

    ``warn``/``crit`` are resolved from the DEVICE's own product when the caller
    does not pass them. The alert engine used to resolve them once for the whole
    fleet and pass the same pair to every device, which silently defeated
    per-product capacity thresholds for exactly the caller that sends the mail."""
    scope = scope_of(appliance)
    lim = limits(scope)
    if warn is None or crit is None:
        w, c = thresholds(scope)
        warn = w if warn is None else warn
        crit = c if crit is None else crit
    return collect(appliance, capacity_rows(appliance, warn, crit),
                   cache_meta(appliance), hours=hours, lim=lim)
