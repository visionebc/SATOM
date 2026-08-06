"""Compose many monitor series into one chart.

Every existing chart in this product is bound to a single probe: the drill-down
modal opened from a row. That answers "how has THIS been behaving" and cannot
answer "how do the FortiWebs compare", which is the question an operator
actually opens a dashboard to ask.

This module is the composition layer. It reads only what
``services.deep_monitor`` already stored — no new collection, no new scheduler,
and, per the standing contract of every Monitoring view, **no device call on a
page load**.

Three rules carry most of the correctness here.

**One resolution per panel.** ``deep_monitor.pick_source`` chooses raw / hourly
/ daily per probe, based on how much history that probe has. Drawing two probes
at two resolutions on one axis is a lie no legend repairs. So the panel asks
every series which table it needs and pins the COARSEST answer for all of them.
A three-day-old probe forces its neighbours to hourly, and the panel says so in
its footer.

**Gaps stay gaps.** Buckets with no data render ``None`` and the front end draws
with ``spanGaps: false``. Interpolating across an outage draws a clean straight
line through the exact interval the chart was opened to examine.

**Absence of data is not health.** A series with nothing in the window reports
``healthy_pct: None``, never ``0`` and never ``100``. This is the same rule that
kept the Fleet-health badge structurally unable to report bad news before §9b.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from . import deep_monitor as dm

# Ranges the picker offers. Deliberately reaching 90d: that is exactly the
# hourly rollup retention (``dm.HOURLY_KEEP_DAYS``), so the longest offered
# window is the longest one that can be answered at hourly detail.
RANGES: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}
DEFAULT_RANGE = "24h"

# Coarsest wins. Ordered least → most aggregated.
_SOURCE_RANK = {"raw": 0, "hour": 1, "day": 2}
_BUCKET_SECONDS = {"raw": 0, "hour": 3600, "day": 86400}

# Series colours. Fixed, ordered and colour-blind-safe-ish, assigned by POSITION
# so a panel keeps its colours across refreshes. Derived from the light chrome
# the product actually ships (see ``docs/theming.md``): saturated enough to read
# on white, dark enough to pass against it.
SERIES_COLORS = (
    "#0A3F9F", "#C4401A", "#15692A", "#7A5700", "#4C2A85",
    "#0E7C86", "#8B1C2A", "#3D4550", "#B0561B", "#1F5FBF",
)


def range_bounds(key: str, *, now: datetime | None = None,
                 frm: datetime | None = None,
                 to: datetime | None = None) -> tuple[datetime, datetime, str]:
    """Resolve a range key (or an explicit from/to) to ``(start, end, key)``.

    An explicit pair wins and is reported as ``custom``. An unknown key falls
    back to the default rather than raising: a stale bookmark should open a
    dashboard, not an error page.
    """
    now = now or datetime.utcnow()
    if frm and to and to > frm:
        span = to - frm
        if span > timedelta(days=dm.MAX_RANGE_DAYS):
            frm = to - timedelta(days=dm.MAX_RANGE_DAYS)
        return frm, to, "custom"
    delta = RANGES.get(key) or RANGES[DEFAULT_RANGE]
    key = key if key in RANGES else DEFAULT_RANGE
    return now - delta, now, key


def panel_source(probe_ids: list[int], start: datetime, end: datetime, *,
                 session=None) -> str:
    """The one table every series in this panel will be read from.

    Takes the coarsest source any member needs. An empty panel answers ``hour``:
    it has no series to constrain it and the footer has to name *something*.
    """
    if not probe_ids:
        return "hour"
    ranks = [_SOURCE_RANK.get(dm.source_for(pid, start, end, session=session), 1)
             for pid in probe_ids]
    worst = max(ranks)
    for name, rank in _SOURCE_RANK.items():
        if rank == worst:
            return name
    return "hour"


def grid(start: datetime, end: datetime, source: str,
         points_by_series: list[list[dict]]) -> list[str]:
    """The shared x axis for a panel.

    For bucketed sources the grid is generated, so a series that went silent for
    six hours shows six empty buckets rather than closing the gap by simply
    having fewer points than its neighbour.

    Raw samples are not on a fixed cadence (probes have different intervals, and
    a sweep can be late), so there the grid is the union of the timestamps that
    actually exist. Generating a synthetic raw grid would invent buckets no
    probe ever reported.
    """
    step = _BUCKET_SECONDS.get(source, 0)
    if not step:
        seen: set[str] = set()
        for pts in points_by_series:
            seen.update(p["t"] for p in pts)
        return sorted(seen)

    span = "day" if source == "day" else "hour"
    cur = dm.bucket_key(start, span)
    if cur < start:
        cur = cur + timedelta(seconds=step)
    out: list[str] = []
    limit = end + timedelta(seconds=step)
    # Hard cap: 90 days of hourly is 2160 buckets. The cap exists so a bad
    # custom range cannot ask the server to build a million-element list.
    while cur <= limit and len(out) < 5000:
        out.append(cur.isoformat(timespec="seconds"))
        cur = cur + timedelta(seconds=step)
    return out


def align(axis: list[str], points: list[dict], field: str = "avg") -> list:
    """Project one series onto the shared axis, ``None`` where it has no bucket."""
    have = {p["t"]: p for p in points}
    out: list = []
    for t in axis:
        row = have.get(t)
        out.append(None if row is None else row.get(field))
    return out


def stat_of(points: list[dict], func: str, *, field: str = "avg"):
    """Reduce a series to the single number a stat/gauge panel shows.

    Skips ``None`` rather than treating it as zero: a probe that reported
    nothing for an hour did not report zero throughput, and averaging the two
    together would quietly drag every headline number toward the floor.
    """
    vals = [p.get(field) for p in points]
    vals = [v for v in vals if v is not None]
    if not vals:
        return None
    if func == "last":
        return vals[-1]
    if func == "min":
        return min(vals)
    if func == "max":
        return max(vals)
    if func == "sum":
        return round(sum(vals), 3)
    return round(sum(vals) / len(vals), 3)


def healthy_pct(points: list[dict]) -> float | None:
    """Share of graded buckets that were ``ok``. ``None`` when nothing graded.

    The None matters more than the number. A panel that renders 0 % for "we
    never measured" tells the operator the service is down; one that renders
    100 % tells them it is fine. Both are inventions.
    """
    ok = graded = 0
    for p in points:
        st = p.get("status")
        if st in ("ok", "warn", "crit", "error"):
            graded += 1
            if st == "ok":
                ok += 1
    if not graded:
        return None
    return round(100.0 * ok / graded, 1)


# --------------------------------------------------------------------------- #
#  Probe selection                                                             #
# --------------------------------------------------------------------------- #
def _visible_probe_query(session=None):
    """Every probe this session's ADOM may see, device-less ones included."""
    from ..models import MonitorProbe, db, visible_appliances

    session = session or db.session
    ids = [a.id for a in visible_appliances().all()]
    return (session.query(MonitorProbe)
            .filter(db.or_(MonitorProbe.appliance_id.is_(None),
                           MonitorProbe.appliance_id.in_(ids or [-1]))))


def resolve_panel_probes(panel, *, session=None) -> list:
    """Probes this panel draws, in a stable order.

    ADOM scoping is applied HERE and not in the template, so a panel authored in
    the Global ADOM against a FortiADC device contributes nothing when the board
    is opened from the FortiWeb ADOM — it does not merely render hidden.
    """
    from ..models import MonitorProbe

    q = _visible_probe_query(session=session)
    if panel.select_mode == "probes":
        ids = panel.id_list()
        if not ids:
            return []
        rows = q.filter(MonitorProbe.id.in_(ids)).all()
        # Preserve the author's ordering, which is the legend order they chose.
        order = {pid: i for i, pid in enumerate(ids)}
        return sorted(rows, key=lambda p: order.get(p.id, 1_000_000))

    if panel.rule_kind:
        q = q.filter(MonitorProbe.kind == panel.rule_kind)
    devices = panel.device_list()
    if devices:
        q = q.filter(MonitorProbe.appliance_id.in_(devices))
    if panel.rule_match:
        q = q.filter(MonitorProbe.name.ilike("%%%s%%" % panel.rule_match))
    # A disabled probe is excluded from a RULE panel but honoured in an explicit
    # id list: a rule describes "everything of this shape", and a paused probe
    # is not currently of that shape. An explicit pick is a deliberate request
    # for that exact probe, and dropping it silently would leave the operator
    # staring at a legend that lost a line for no stated reason.
    q = q.filter(MonitorProbe.enabled.is_(True))
    return q.order_by(MonitorProbe.kind, MonitorProbe.name).all()


def metric_catalog(*, session=None) -> dict:
    """What a panel editor can offer: kinds, devices and probes in scope."""
    from ..models import Appliance, MonitorProbe

    rows = _visible_probe_query(session=session).order_by(
        MonitorProbe.kind, MonitorProbe.name).all()

    kinds: dict[str, dict] = {}
    devices: dict[int, dict] = {}
    probes: list[dict] = []
    for p in rows:
        meta = dm.METRIC_META.get(p.kind, {})
        k = kinds.setdefault(p.kind, {
            "kind": p.kind,
            "label": dm.KIND_LABEL.get(p.kind, p.kind),
            "unit": meta.get("unit", ""),
            "metric": meta.get("label", ""),
            "v2_label": meta.get("v2_label", ""),
            "v2_unit": meta.get("v2_unit", ""),
            "n": 0,
        })
        k["n"] += 1
        if p.appliance_id:
            d = devices.setdefault(p.appliance_id, {
                "id": p.appliance_id,
                "name": getattr(p.appliance, "name", "") or "",
                "device_kind": getattr(p.appliance, "kind", "") or "",
                "maintenance": bool(getattr(p.appliance, "maintenance", False)),
                "n": 0,
            })
            d["n"] += 1
        probes.append({
            "id": p.id, "kind": p.kind, "name": p.name,
            "appliance_id": p.appliance_id,
            "appliance": getattr(p.appliance, "name", "") or "",
            "enabled": bool(p.enabled),
            "unit": dm.NUM_UNIT.get(p.kind, meta.get("unit", "")),
            "interval_min": p.interval_min,
        })
    return {
        "kinds": sorted(kinds.values(), key=lambda r: r["label"]),
        "devices": sorted(devices.values(), key=lambda r: r["name"]),
        "probes": probes,
        "viz": list(_VIZ_META),
        "ranges": list(RANGES),
        "stat_funcs": list(_STAT_META),
        "viz_meta": _VIZ_META,
        "stat_meta": _STAT_META,
    }


_VIZ_META = {
    "line": "Line — one line per series over time",
    "area": "Area — filled line, for volumes",
    "bar": "Bars — one column per bucket",
    "stat": "Stat — one number, sparkline and change",
    "gauge": "Gauge — latest value against its thresholds",
    "heatmap": "Heatmap — status per series per bucket",
    "table": "Table — min / avg / max / last per series",
    "status": "Availability — a coloured band per bucket",
}

_STAT_META = {
    "last": "Latest reading",
    "avg": "Average over the range",
    "min": "Minimum over the range",
    "max": "Peak over the range",
    "sum": "Total over the range",
    "healthy_pct": "Healthy %",
}


# --------------------------------------------------------------------------- #
#  Panel rendering                                                             #
# --------------------------------------------------------------------------- #
def _thresholds_of(probe) -> dict:
    """Threshold lines for a probe, in the units its own series is drawn in."""
    if probe.kind in ("cpu", "memory"):
        return {"warn": probe.warn_pct or 0, "crit": probe.crit_pct or 0}
    if probe.kind == "https":
        return {"warn": probe.warn_ms or 0, "crit": 0}
    if probe.kind in dm.API_KINDS:
        return {"warn": probe.warn_num or 0, "crit": probe.crit_num or 0}
    return {}


# -- MetricsQL panels (the fleet-scale selection mode) ------------------------

# Step chosen so a panel never asks the store for more points than a chart can
# honestly draw (~600). A 90-day range at 3-minute resolution is 43,200 points,
# which is not more detail on a 900 px canvas -- it is a slower query and a
# thicker line.
_MAX_POINTS = 600
_MIN_STEP_S = 60


def vm_step(start, end) -> str:
    span = max(60, int((end - start).total_seconds()))
    return "%ds" % max(_MIN_STEP_S, span // _MAX_POINTS)


def _vm_label(metric: dict, legend_key: str) -> str:
    """Series label from the returned labels. An explicit legend key wins;
    otherwise device[/policy|iface] -- the identity the operator reads."""
    if legend_key and metric.get(legend_key):
        return str(metric[legend_key])
    dev = metric.get("device") or ""
    sub = (metric.get("policy") or metric.get("iface")
           or metric.get("collector") or "")
    if dev and sub:
        return "%s / %s" % (dev, sub)
    return dev or sub or (metric.get("__name__") or "series")


def _vm_stat(values: list, func: str):
    if not values:
        return None
    if func == "min":
        return min(values)
    if func == "max":
        return max(values)
    if func == "sum":
        return sum(values)
    if func == "avg":
        return sum(values) / len(values)
    return values[-1]


def vm_panel_payload(panel, start: datetime, end: datetime,
                     variables: list | None = None) -> dict:
    """Draw a panel from a MetricsQL expression.

    Unlike the probe path there is no rollup table to choose: the store keeps
    full-resolution raw for the whole retention window, so the only decision is
    the query step -- reported in ``source`` so the footer stays honest about
    what was actually drawn.
    """
    from . import vm_store

    from . import dashboard_vars as dv

    raw_expr = (panel.vm_expr or "").strip()
    # Substitute board variables BEFORE anything else. An expression that
    # references an unresolvable variable becomes a panel ERROR: running it
    # with the token still in would make the store reject a parse error, which
    # on screen is indistinguishable from the store being down.
    expr = dv.interpolate(raw_expr, variables or []) if raw_expr else raw_expr
    step = vm_step(start, end)
    out = {
        "panel": panel.to_dict(), "axis": [], "series": [],
        "source": "store (step %s)" % step, "bucket_seconds": 0,
        "from": start.isoformat(timespec="seconds"),
        "to": end.isoformat(timespec="seconds"),
        "units": [panel.vm_unit] if panel.vm_unit else [],
        "mixed_units": False, "empty": True, "expr": expr or raw_expr,
    }
    if not raw_expr:
        out["error"] = "no expression"
        return out
    if expr is None:
        out["error"] = ("expression references a variable this board could "
                        "not resolve — the picker has no confirmed value for "
                        "it, so the query was not run")
        out["expr"] = raw_expr
        return out
    res = vm_store.query_range(expr, start.timestamp(), end.timestamp(), step)
    if res.get("status") != "success":
        # A store that cannot answer is an ERROR on the panel, never an empty
        # chart: "no data" and "the query failed" look identical on a canvas
        # and mean opposite things.
        out["error"] = res.get("error") or "query failed"
        return out
    result = (res.get("data") or {}).get("result") or []
    axis_ts = sorted({float(ts) for s in result
                      for ts, _v in (s.get("values") or [])})
    out["axis"] = [datetime.utcfromtimestamp(t).isoformat(timespec="seconds")
                   for t in axis_ts]
    index = {t: i for i, t in enumerate(axis_ts)}
    for i, s in enumerate(result):
        vals = [None] * len(axis_ts)
        for ts, v in s.get("values") or []:
            try:
                vals[index[float(ts)]] = float(v)
            except (KeyError, TypeError, ValueError):
                continue
        present = [v for v in vals if v is not None]
        out["series"].append({
            "probe_id": None,
            "label": _vm_label(s.get("metric") or {}, panel.vm_legend or ""),
            "device": (s.get("metric") or {}).get("device", ""),
            "kind": "metricsql",
            "unit": panel.vm_unit or "",
            "metric": (s.get("metric") or {}).get("__name__", ""),
            "color": SERIES_COLORS[i % len(SERIES_COLORS)],
            "avg": vals, "status": [None] * len(axis_ts),
            "enabled": True, "thresholds": {},
            "stat": _vm_stat(present, panel.stat_func or "last"),
            "healthy_pct": None,
            "summary": {
                "min": min(present) if present else None,
                "max": max(present) if present else None,
                "avg": (sum(present) / len(present)) if present else None,
                "last": present[-1] if present else None,
                "points": len(present), "changes": 0,
            },
        })
    out["empty"] = not out["series"]
    return out


def panel_payload(panel, start: datetime, end: datetime, *, session=None,
                  variables: list | None = None) -> dict:
    """Everything the front end needs to draw ONE panel.

    Returns the shared axis plus one entry per series, already aligned to it, so
    the browser never has to reconcile two different time bases — a place where
    an off-by-one silently shifts one device's line against another's.
    """
    if (panel.select_mode or "") == "metricsql":
        return vm_panel_payload(panel, start, end, variables)
    probes = resolve_panel_probes(panel, session=session)
    ids = [p.id for p in probes]
    source = panel_source(ids, start, end, session=session)

    raw: list[dict] = []
    for p in probes:
        raw.append(dm.series(p.id, start, end, session=session,
                             force_source=source))

    axis = grid(start, end, source, [r["points"] for r in raw])
    series_out: list[dict] = []
    units: set[str] = set()
    for i, (p, res) in enumerate(zip(probes, raw)):
        meta = dm.METRIC_META.get(p.kind, {})
        unit = dm.NUM_UNIT.get(p.kind) or meta.get("unit", "")
        units.add(unit)
        pts = res["points"]
        entry = {
            "probe_id": p.id,
            "label": _series_label(p),
            "device": getattr(p.appliance, "name", "") or "",
            "kind": p.kind,
            "unit": unit,
            "metric": meta.get("label", ""),
            "color": SERIES_COLORS[i % len(SERIES_COLORS)],
            "avg": align(axis, pts, "avg"),
            "status": align(axis, pts, "status"),
            "enabled": bool(p.enabled),
            "thresholds": _thresholds_of(p) if panel.show_thresholds else {},
            "stat": stat_of(pts, panel.stat_func or "last"),
            "healthy_pct": healthy_pct(pts),
            "summary": {
                "min": stat_of(pts, "min"), "max": stat_of(pts, "max"),
                "avg": stat_of(pts, "avg"), "last": stat_of(pts, "last"),
                "points": sum(1 for v in align(axis, pts, "avg") if v is not None),
                "changes": sum(int(p2.get("changes") or 0) for p2 in pts),
            },
        }
        if panel.stat_func == "healthy_pct":
            entry["stat"] = entry["healthy_pct"]
        if panel.show_band:
            entry["min"] = align(axis, pts, "min")
            entry["max"] = align(axis, pts, "max")
        if panel.show_v2 and meta.get("v2_label"):
            entry["v2"] = align(axis, pts, "v2")
            entry["v2_label"] = meta["v2_label"]
            entry["v2_unit"] = meta.get("v2_unit", "")
        series_out.append(entry)

    out = {
        "panel": panel.to_dict(),
        "axis": axis,
        "source": source,
        "bucket_seconds": _BUCKET_SECONDS.get(source, 0),
        "from": start.isoformat(timespec="seconds"),
        "to": end.isoformat(timespec="seconds"),
        "series": series_out,
        # One unit means one axis is honest. Two units on one axis is not, and
        # the front end degrades to a second scale (or, for a stat panel, prints
        # the unit per row) rather than pretending they are comparable.
        "units": sorted(u for u in units if u),
        "mixed_units": len([u for u in units if u]) > 1,
        "empty": not series_out,
    }
    if panel.compare_prev:
        out["previous"] = _previous_window(panel, start, end, session=session)
    return out


def _series_label(probe) -> str:
    dev = getattr(probe.appliance, "name", "") or ""
    name = probe.name or probe.kind
    return ("%s — %s" % (dev, name)) if dev else name


def _previous_window(panel, start: datetime, end: datetime, *,
                     session=None) -> dict:
    """Headline numbers for the immediately preceding window of equal length.

    Only the reduced statistic travels, not the points: the comparison a panel
    makes is "is this worse than last week", and shipping a second full series
    to answer that doubles the payload for a number the chart never plots.
    """
    span = end - start
    p_start, p_end = start - span, start
    probes = resolve_panel_probes(panel, session=session)
    ids = [p.id for p in probes]
    source = panel_source(ids, p_start, p_end, session=session)
    out: dict[str, Any] = {"from": p_start.isoformat(timespec="seconds"),
                           "to": p_end.isoformat(timespec="seconds"),
                           "series": {}}
    for p in probes:
        res = dm.series(p.id, p_start, p_end, session=session,
                        force_source=source)
        pts = res["points"]
        val = (healthy_pct(pts) if panel.stat_func == "healthy_pct"
               else stat_of(pts, panel.stat_func or "last"))
        out["series"][str(p.id)] = {
            "stat": val, "healthy_pct": healthy_pct(pts),
            "avg": stat_of(pts, "avg"), "max": stat_of(pts, "max"),
        }
    return out


def dashboard_payload(dash, start: datetime, end: datetime, *,
                      session=None, selected: dict | None = None) -> dict:
    """Every panel of a board, resolved. One request, one consistent window.

    Variables are resolved ONCE for the board, not per panel. Two panels
    resolving the same picker independently could disagree — one enumerating
    the store a second later than the other — and a board whose panels quietly
    describe different device sets is worse than one that fails.
    """
    from . import dashboard_vars as dv

    variables = dv.resolve(dash, selected or {})
    panels = [panel_payload(p, start, end, session=session, variables=variables)
              for p in dash.panels]
    return {
        "dashboard": dash.to_dict(),
        "from": start.isoformat(timespec="seconds"),
        "to": end.isoformat(timespec="seconds"),
        "variables": variables,
        "panels": panels,
    }


# --------------------------------------------------------------------------- #
#  Collection cadence                                                          #
# --------------------------------------------------------------------------- #
def effective_interval(interval_min: int, tick_min: int) -> int:
    """What a probe's cadence ACTUALLY is, given the sweep it rides on.

    ``dm.due_probes`` fires a probe once its own interval has fully elapsed AND
    a sweep happens to run. The real cadence is therefore
    ``tick * ceil(interval / tick)`` — a 5-minute probe under a 3-minute sweep
    is a 6-minute probe, and its row still says 5.

    That silent rounding is what degraded ``proxyd`` — the check that exists to
    catch a mute daemon restart — from 5 minutes to 6 when the sweep moved to 3.
    Exposing it is the point: an operator cannot align intervals to a tick they
    cannot see.
    """
    tick = max(1, int(tick_min or 1))
    want = max(1, int(interval_min or 1))
    blocks = (want + tick - 1) // tick
    return blocks * tick


def sweep_tick_minutes(*, session=None) -> int:
    """Interval of the ``deep_monitor`` scheduled action, in minutes.

    ``0`` when the sweep is not on a minute interval — no such row (the state of
    every fresh install, because this product deliberately seeds no
    ``ScheduledAction``; see safeguards §10), the row disabled, or a
    daily/weekly schedule, where "tick" has no meaning. Zero is reported as zero
    rather than defaulted to a plausible 3: a caller that substitutes a number
    would compute and display an effective cadence for a sweep that never runs.

    The spec is parsed with the scheduler's OWN ``_interval_seconds`` rather
    than a local copy of its unit table. A private import is the smaller evil:
    a second table is a second thing to update, and the failure mode of missing
    that update is a cadence page that disagrees with the scheduler actually
    firing the probes.
    """
    import json as _json

    from ..models import ScheduledAction, db
    from .scheduler import _interval_seconds

    session = session or db.session
    row = (session.query(ScheduledAction)
           .filter(ScheduledAction.action == "deep_monitor",
                   ScheduledAction.enabled.is_(True))
           .order_by(ScheduledAction.id).first())
    if row is None or (row.schedule_kind or "") != "interval":
        return 0
    try:
        spec = _json.loads(row.schedule or "{}")
    except (ValueError, TypeError):
        return 0
    if not isinstance(spec, dict):
        return 0
    return max(1, round(_interval_seconds(spec) / 60))


def cadence_report(*, session=None) -> dict:
    """Declared vs effective cadence for every visible probe."""
    from ..models import MonitorProbe

    tick = sweep_tick_minutes(session=session)
    rows = []
    drifted = 0
    for p in _visible_probe_query(session=session).order_by(
            MonitorProbe.kind, MonitorProbe.name).all():
        eff = effective_interval(p.interval_min, tick) if tick else 0
        drift = bool(tick and eff != p.interval_min)
        if drift and p.enabled:
            drifted += 1
        rows.append({
            "id": p.id, "name": p.name, "kind": p.kind,
            "appliance": getattr(p.appliance, "name", "") or "",
            "enabled": bool(p.enabled),
            "interval_min": p.interval_min,
            "effective_min": eff,
            "drift": drift,
        })
    return {
        "tick_min": tick,
        "sweep_configured": tick > 0,
        "probes": rows,
        "drifted": drifted,
        "total": len(rows),
    }
