"""Daily / weekly / monthly summaries of what the monitors recorded.

The rollup tables already hold ninety days of hourly buckets and two years of
daily ones. What they do not hold is a *statement*: "last week the fleet was
healthy 98.4 % of the time, fortiweb08 restarted proxyd twice, and peak
throughput rose 40 % against the week before." A chart can be read to reach that
conclusion; a report says it, keeps it, and can be mailed to somebody who will
never open the console.

Two properties carry the correctness here, and both have bitten this repo before
in other guises.

**Periods are half-open.** ``[start, end)``. Monday's report and Tuesday's must
not both claim midnight, or every boundary bucket is counted twice and every
"total" is quietly inflated.

**Nothing measured is not a healthy zero.** A period with no samples reports
``healthy_pct: None`` and a worst status of ``unknown``. It renders as *no data*.
A report that prints 100 % for a week in which the scheduler was dead is worse
than no report at all: it is a signed statement that the fleet was fine.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from . import deep_monitor as dm
from . import monitor_analytics as ma

PERIODS = ("daily", "weekly", "monthly")

PERIOD_LABEL = {"daily": "Daily", "weekly": "Weekly", "monthly": "Monthly"}

# Status ranking for the report roll-up. Distinct from ``dm.STATUS_ORDER``:
# there, ``unknown`` sorts BELOW ``ok`` so an unmeasured device can never roll
# up green. The same rule applies here.
_RANK = {"crit": 0, "error": 1, "warn": 2, "unknown": 3, "ok": 4}


def worst_status(values: list[str]) -> str:
    """Worst of a set, with ``unknown`` ranked below ``ok``.

    "We did not measure" must never aggregate to "fine". A device that reported
    nothing all week alongside one that reported healthy rolls up to
    ``unknown``, not ``ok`` — the operator has to be told which of the two they
    are looking at.
    """
    vals = [v for v in values if v]
    if not vals:
        return "unknown"
    return min(vals, key=lambda v: _RANK.get(v, 3))


def period_bounds(period: str, ref: datetime | None = None,
                  *, offset: int = 1) -> tuple[datetime, datetime]:
    """The ``[start, end)`` window of a COMPLETE period before ``ref``.

    ``offset=1`` is the most recently finished period, which is what a report
    run at 02:00 wants — never the partial one still in progress, whose
    "throughput fell 80 %" only means the day is two hours old.
    """
    ref = ref or datetime.utcnow()
    if period == "monthly":
        anchor = ref.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        for _ in range(max(0, offset)):
            anchor = (anchor - timedelta(days=1)).replace(day=1)
        end = _add_month(anchor)
        return anchor, end
    if period == "weekly":
        day = ref.replace(hour=0, minute=0, second=0, microsecond=0)
        # ISO weeks start Monday. weekday() is 0 for Monday.
        start = day - timedelta(days=day.weekday())
        start = start - timedelta(weeks=max(0, offset))
        return start, start + timedelta(weeks=1)
    day = ref.replace(hour=0, minute=0, second=0, microsecond=0)
    start = day - timedelta(days=max(0, offset))
    return start, start + timedelta(days=1)


def _add_month(dt: datetime) -> datetime:
    return (dt.replace(year=dt.year + 1, month=1) if dt.month == 12
            else dt.replace(month=dt.month + 1))


def period_title(period: str, start: datetime, end: datetime) -> str:
    if period == "monthly":
        return "Monthly report — %s" % start.strftime("%B %Y")
    if period == "weekly":
        return ("Weekly report — %s to %s"
                % (start.strftime("%d %b %Y"),
                   (end - timedelta(days=1)).strftime("%d %b %Y")))
    return "Daily report — %s" % start.strftime("%d %b %Y")


def _pct_delta(cur, prev):
    """Percentage change, or ``None`` when it cannot honestly be computed.

    A change from nothing is not "+100 %", and a change from zero is not
    infinite growth. Both return ``None`` so the renderer prints an em dash
    instead of a number the operator would act on.
    """
    if cur is None or prev is None:
        return None
    try:
        if not prev:
            return None
        return round(100.0 * (cur - prev) / abs(prev), 1)
    except (TypeError, ZeroDivisionError):
        return None


# --------------------------------------------------------------------------- #
#  Building                                                                    #
# --------------------------------------------------------------------------- #
def _probe_stats(probe, start: datetime, end: datetime, *, session=None) -> dict:
    """One probe's numbers for the window, plus its threshold breaches."""
    # ``series`` takes an inclusive end; the period is half-open, so step back
    # one second. Without this, the last bucket of the window is also the first
    # bucket of the next report.
    res = dm.series(probe.id, start, end - timedelta(seconds=1), session=session)
    pts = res["points"]
    meta = dm.METRIC_META.get(probe.kind, {})
    th = ma._thresholds_of(probe)

    vals = [p.get("avg") for p in pts if p.get("avg") is not None]
    peaks = [p.get("max") for p in pts if p.get("max") is not None]
    breaches = 0
    crit_level = th.get("crit") or 0
    warn_level = th.get("warn") or 0
    for v in peaks:
        if crit_level and v >= crit_level:
            breaches += 1
        elif warn_level and v >= warn_level:
            breaches += 1

    statuses = [p.get("status") for p in pts]
    return {
        "probe_id": probe.id,
        "name": probe.name,
        "kind": probe.kind,
        "kind_label": dm.KIND_LABEL.get(probe.kind, probe.kind),
        "device": getattr(probe.appliance, "name", "") or "",
        "device_id": probe.appliance_id,
        "enabled": bool(probe.enabled),
        "unit": dm.NUM_UNIT.get(probe.kind) or meta.get("unit", ""),
        "metric": meta.get("label", ""),
        "source": res["source"],
        "samples": sum(int(p.get("n") or 0) for p in pts),
        "buckets": len(pts),
        "min": min(vals) if vals else None,
        "avg": round(sum(vals) / len(vals), 3) if vals else None,
        "max": max(peaks) if peaks else None,
        "p95": _percentile(vals, 95),
        "last": vals[-1] if vals else None,
        "healthy_pct": ma.healthy_pct(pts),
        "worst": worst_status(statuses),
        "changes": sum(int(p.get("changes") or 0) for p in pts),
        "breaches": breaches,
        "thresholds": th,
        "transitions": _transitions(pts),
    }


def _percentile(vals: list[float], pct: int):
    """Nearest-rank percentile. ``None`` on an empty set, never 0."""
    if not vals:
        return None
    ordered = sorted(vals)
    k = max(0, min(len(ordered) - 1,
                   int(round((pct / 100.0) * len(ordered) + 0.5)) - 1))
    return round(ordered[k], 3)


def _transitions(pts: list[dict]) -> list[dict]:
    """Status changes inside the window — the incident timeline.

    Only transitions INTO a non-ok state are reported. A recovery is implied by
    the next entry, and listing both doubles the length of an incident list that
    an operator reads to find out what went wrong.
    """
    out: list[dict] = []
    prev = None
    for p in pts:
        st = p.get("status")
        if st != prev and st in ("warn", "crit", "error"):
            out.append({"t": p.get("t"), "status": st})
        prev = st
    return out[:50]


def build(period: str, *, start: datetime | None = None,
          end: datetime | None = None, product: str = "",
          ref: datetime | None = None, session=None) -> dict:
    """Assemble (but do not persist) one report body."""
    from ..models import MonitorProbe

    if start is None or end is None:
        start, end = period_bounds(period, ref)

    probes = (ma._visible_probe_query(session=session)
              .order_by(MonitorProbe.kind, MonitorProbe.name).all())

    stats = [_probe_stats(p, start, end, session=session) for p in probes]

    # Previous window of equal length, for the deltas.
    span = end - start
    prev_stats = {}
    for p in probes:
        row = _probe_stats(p, start - span, start, session=session)
        prev_stats[p.id] = row
    for row in stats:
        prev = prev_stats.get(row["probe_id"], {})
        row["prev_avg"] = prev.get("avg")
        row["prev_max"] = prev.get("max")
        row["prev_healthy_pct"] = prev.get("healthy_pct")
        row["delta_avg_pct"] = _pct_delta(row["avg"], prev.get("avg"))
        row["delta_max_pct"] = _pct_delta(row["max"], prev.get("max"))

    # Group by device.
    devices: dict[Any, dict] = {}
    for row in stats:
        key = row["device_id"] or 0
        d = devices.setdefault(key, {
            "device_id": row["device_id"],
            "device": row["device"] or "(no device)",
            "probes": [], "healthy_pct": None, "worst": "unknown",
            "changes": 0, "breaches": 0, "samples": 0,
        })
        d["probes"].append(row)
        d["changes"] += row["changes"]
        d["breaches"] += row["breaches"]
        d["samples"] += row["samples"]
    for d in devices.values():
        measured = [r["healthy_pct"] for r in d["probes"]
                    if r["healthy_pct"] is not None]
        d["healthy_pct"] = (round(sum(measured) / len(measured), 1)
                            if measured else None)
        d["worst"] = worst_status([r["worst"] for r in d["probes"]])

    measured_all = [r["healthy_pct"] for r in stats if r["healthy_pct"] is not None]
    total_samples = sum(r["samples"] for r in stats)
    incidents = [
        {"probe": r["name"], "device": r["device"], "kind": r["kind"],
         "status": t["status"], "t": t["t"]}
        for r in stats for t in r["transitions"]
    ]
    incidents.sort(key=lambda r: r["t"] or "")

    # Probes that produced nothing. Named explicitly, because a report whose
    # averages simply omit them looks complete while covering less than it says.
    silent = [{"probe": r["name"], "device": r["device"], "kind": r["kind"],
               "enabled": r["enabled"]}
              for r in stats if not r["samples"]]

    body = {
        "period": period,
        "period_label": PERIOD_LABEL.get(period, period),
        "from": start.isoformat(timespec="seconds"),
        "to": end.isoformat(timespec="seconds"),
        "product": product or "",
        "generated_at": datetime.utcnow().isoformat(timespec="seconds"),
        "totals": {
            "probes": len(stats),
            "devices": len(devices),
            "samples": total_samples,
            # None when nothing was measured, all the way up the chain.
            "healthy_pct": (round(sum(measured_all) / len(measured_all), 1)
                            if measured_all else None),
            "worst": worst_status([r["worst"] for r in stats]),
            "incidents": len(incidents),
            "changes": sum(r["changes"] for r in stats),
            "breaches": sum(r["breaches"] for r in stats),
            "silent": len(silent),
            "measured_probes": len(measured_all),
        },
        "devices": sorted(devices.values(), key=lambda d: d["device"]),
        "probes": stats,
        "incidents": incidents[:200],
        "silent": silent,
        "no_data": total_samples == 0,
        "fleet": fleet_section(start, end, product=product),
    }
    return body


# -- fleet section, computed from the metrics store --------------------------
#
# The probe tables describe what an operator explicitly asked to watch. The
# store holds the whole fleet, including everything nobody wrote a probe row
# for -- which at 100 devices is nearly all of it. A report that only
# summarised probes would shrink as the fleet grew.

# Metrics every product with a ``box`` collector reports.
FLEET_QUERIES_COMMON = (
    ("cpu_pct", "Processor used", "%", "satom_box_cpu_pct"),
    ("mem_pct", "Memory used", "%", "satom_box_mem_pct"),
)

# Metrics only one product has. Until 2026-08-06 the throughput and per-policy
# rows below were unconditional, so a report generated while scoped to the
# FortiAuthenticator ADOM carried two sections that product cannot produce —
# and, worse, filled them with the FortiWeb fleet's numbers, because the query
# had no ``kind`` matcher. The report row was product-scoped; its fleet section
# was not.
FLEET_QUERIES_BY_PRODUCT = {
    "fortiweb": (
        ("throughput_bps", "Device throughput", "bit/s",
         "satom_total_throughput_bps"),
        ("policy_conn_per_sec", "Policy connection rate", "conn/s",
         "satom_policy_conn_per_sec"),
    ),
    "fortiauthenticator": (
        ("licence_pct", "Licence consumed", "%", "satom_fac_licence_pct"),
        ("token_pct", "FortiToken pool consumed", "%", "satom_fac_token_pct"),
    ),
}

# Products whose fleet section carries the "policies with every backend down"
# roll-up. An identity or log product has no such concept, and an empty
# "0 policies down" line reads as a clean bill of health for a check that was
# never applicable.
POLICY_PRODUCTS = ("fortiweb",)


def fleet_queries(product: str = "") -> tuple:
    """The metric set for this ADOM.

    Global gets the union: it is the manager-wide view and must not shrink to
    the intersection just because one product lacks throughput.
    """
    extra: tuple = ()
    if product:
        extra = FLEET_QUERIES_BY_PRODUCT.get(product, ())
    else:
        seen = set()
        for rows in FLEET_QUERIES_BY_PRODUCT.values():
            for row in rows:
                if row[0] not in seen:
                    seen.add(row[0])
                    extra += (row,)
    return FLEET_QUERIES_COMMON + extra


def _sel(base: str, product: str = "") -> str:
    """Add the ``kind`` matcher for a product-scoped report.

    Every series the collectors write carries ``kind=<appliance.kind>``, and the
    ADOM key IS the appliance kind, so scoping is one label matcher rather than
    a device list that would have to be rebuilt whenever the fleet changes.
    """
    if not product:
        return base
    return '%s{kind="%s"}' % (base, product)


#: Retained name for callers that still import the flat tuple.
FLEET_QUERIES = fleet_queries()


def fleet_section(start: datetime, end: datetime,
                  product: str = "") -> dict:
    """min/avg/max per device per metric over the window, plus the fleet-wide
    facts a summary must not omit: policies that were down, and collectors that
    failed. Absence is reported as ``available: False``, never as zeros.

    ``product`` scopes BOTH the metric set and every query. Without the second
    half, a FortiAuthenticator report would still be computed over the FortiWeb
    fleet's series — a document that names one ADOM and describes another.
    """
    from . import vm_store

    span = "%ds" % max(60, int((end - start).total_seconds()))
    out = {"available": False, "metrics": [], "down_policies": [],
           "failed_collectors": [], "detail": "", "product": product or "",
           "policy_scope": bool(not product or product in POLICY_PRODUCTS)}
    h = vm_store.health()
    if not h.get("up"):
        out["detail"] = h.get("detail") or "metrics store unreachable"
        return out
    out["available"] = True
    ts = end.timestamp()
    for key, label, unit, base in fleet_queries(product):
        rows = []
        aggs = {}
        for agg in ("min", "avg", "max"):
            expr = "%s_over_time(%s[%s])" % (agg, _sel(base, product), span)
            res = vm_store.query(expr, ts=ts)
            for r in (res.get("data") or {}).get("result", []):
                m = r.get("metric") or {}
                name = m.get("device") or "?"
                # One series per device is the FortiWeb case; identity metrics
                # are per resource/pool and traffic is per policy. Whichever
                # sub-label the series carries becomes part of the row name, or
                # every resource of a device collapses onto one line.
                for sub in ("policy", "resource", "pool", "iface"):
                    if m.get(sub):
                        name = "%s / %s" % (name, m[sub])
                        break
                try:
                    aggs.setdefault(name, {})[agg] = float(r["value"][1])
                except (KeyError, IndexError, TypeError, ValueError):
                    continue
        for name in sorted(aggs):
            rows.append({"series": name, **aggs[name]})
        out["metrics"].append({"key": key, "label": label, "unit": unit,
                               "rows": rows})
    if out["policy_scope"]:
        res = vm_store.query(
            "max_over_time((%s == 0)[%s])" % (_sel("satom_policy_up", product),
                                              span), ts=ts)
        for r in (res.get("data") or {}).get("result", []):
            m = r.get("metric") or {}
            out["down_policies"].append({"device": m.get("device", ""),
                                         "policy": m.get("policy", "")})
    res = vm_store.query(
        "max_over_time((%s == 0)[%s])" % (_sel("satom_scrape_up", product),
                                          span), ts=ts)
    for r in (res.get("data") or {}).get("result", []):
        m = r.get("metric") or {}
        out["failed_collectors"].append({"device": m.get("device", ""),
                                         "collector": m.get("collector", "")})
    return out


def generate(period: str, *, product: str = "", ref: datetime | None = None,
             by: str = "", session=None, replace: bool = True,
             start: datetime | None = None,
             end: datetime | None = None):
    """Build a report and persist it. Returns the ``MonitorReport`` row.

    Re-running a period REPLACES its row by default. Reports are keyed by
    (period, start, product), so a retry after a failed mail run updates the
    record rather than accumulating near-duplicates an operator has to tell
    apart by timestamp.
    """
    from ..models import db
    from ..models_analytics import MonitorReport

    session = session or db.session
    if start is None or end is None:
        start, end = period_bounds(period, ref)
    body = build(period, start=start, end=end, product=product, session=session)

    row = (session.query(MonitorReport)
           .filter(MonitorReport.period == period,
                   MonitorReport.period_start == start,
                   MonitorReport.product == (product or "")).first())
    if row is not None and not replace:
        return row
    if row is None:
        row = MonitorReport(period=period, period_start=start,
                            period_end=end, product=product or "")
        session.add(row)

    t = body["totals"]
    row.period_end = end
    row.title = period_title(period, start, end)
    row.generated_at = datetime.utcnow()
    row.generated_by = by or ""
    row.probes_n = t["probes"]
    row.devices_n = t["devices"]
    row.samples_n = t["samples"]
    row.healthy_pct = t["healthy_pct"]
    row.worst_status = t["worst"]
    row.incidents_n = t["incidents"]
    row.payload = json.dumps(body, separators=(",", ":"))
    session.commit()
    return row


def push_to_backup_server(row) -> dict:
    """Upload one stored report to the external backup server as JSON + text.

    Why off-box at all: a report exists to describe a window AFTER it closed,
    which is exactly when the node that holds it may be the thing that failed.
    Both formats travel — the JSON so a future console can re-render it, the
    text so a human with nothing but an SFTP client can still read it.
    Best-effort: the report is already stored, so a push failure is reported,
    never raised.
    """
    import os
    import tempfile
    try:
        from . import backup_server as _bk
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "detail": "backup_server unavailable: %s" % exc}
    body = row.body()
    stamp = row.period_start.strftime("%Y%m%d") if row.period_start else "unknown"
    base = "satom-report-%s-%s" % (row.period, stamp)
    if row.product:
        base += "-" + row.product
    pushed, errs = [], []
    tmpdir = tempfile.mkdtemp(prefix="satom-report-")
    try:
        for name, data in ((base + ".json",
                            json.dumps(body, indent=2, default=str)),
                           (base + ".txt", render_text(body))):
            path = os.path.join(tmpdir, name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(data)
            res = _bk.push_bundle(path, remote_name=name,
                                  remote_dir=_reports_remote_dir())
            (pushed if res.get("ok") else errs).append(
                name if res.get("ok") else "%s: %s" % (name, res.get("detail")))
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    return {"ok": not errs,
            "detail": ("uploaded %s" % ", ".join(pushed)) if pushed and not errs
                      else "; ".join(errs) or "nothing uploaded"}


def _reports_remote_dir() -> str:
    import posixpath
    from . import settings_store as _st
    cfg = _st.backup_server()
    return posixpath.join(cfg.get("system_path") or "/system", "reports")


def prune(period: str, keep: int, *, product: str = "", session=None) -> int:
    """Keep the newest ``keep`` reports of a period. Returns rows removed."""
    from ..models import db
    from ..models_analytics import MonitorReport

    session = session or db.session
    if keep <= 0:
        return 0
    rows = (session.query(MonitorReport)
            .filter(MonitorReport.period == period,
                    MonitorReport.product == (product or ""))
            .order_by(MonitorReport.period_start.desc()).all())
    doomed = rows[keep:]
    for r in doomed:
        session.delete(r)
    if doomed:
        session.commit()
    return len(doomed)


# --------------------------------------------------------------------------- #
#  Rendering                                                                   #
# --------------------------------------------------------------------------- #
def _fmt(val, unit: str = "") -> str:
    if val is None:
        return "—"
    if isinstance(val, float):
        txt = ("%.2f" % val).rstrip("0").rstrip(".")
    else:
        txt = str(val)
    return ("%s %s" % (txt, unit)).strip()


def render_text(body: dict) -> str:
    """Plain-text rendering, used for the email body.

    Text and not HTML-only on purpose: this mail is read on a phone at 03:00 by
    somebody deciding whether to get up, and every mail client renders text.
    """
    t = body["totals"]
    lines = [
        period_title(body["period"],
                     datetime.fromisoformat(body["from"]),
                     datetime.fromisoformat(body["to"])),
        "=" * 60,
        "Window   : %s → %s (UTC)" % (body["from"], body["to"]),
        "Devices  : %d    Probes: %d    Samples: %d"
        % (t["devices"], t["probes"], t["samples"]),
    ]
    if t["healthy_pct"] is None:
        lines.append("Health   : NO DATA — nothing was measured in this window.")
    else:
        lines.append("Health   : %.1f %% healthy across %d measured probe(s)"
                     % (t["healthy_pct"], t["measured_probes"]))
    lines.append("Worst    : %s" % t["worst"].upper())
    lines.append("Incidents: %d    Threshold breaches: %d    Drift events: %d"
                 % (t["incidents"], t["breaches"], t["changes"]))
    if t["silent"]:
        lines.append("Silent   : %d probe(s) reported nothing" % t["silent"])
    lines.append("")

    for d in body["devices"]:
        health = ("no data" if d["healthy_pct"] is None
                  else "%.1f %% healthy" % d["healthy_pct"])
        lines.append("-- %s  [%s]  %s" % (d["device"], d["worst"].upper(), health))
        for r in d["probes"]:
            delta = ""
            if r.get("delta_avg_pct") is not None:
                delta = "  (%+.1f %% vs previous)" % r["delta_avg_pct"]
            lines.append("   %-28s avg %-12s peak %-12s%s"
                         % (r["name"][:28],
                            _fmt(r["avg"], r["unit"]),
                            _fmt(r["max"], r["unit"]), delta))
        lines.append("")

    if body["incidents"]:
        lines.append("Incidents")
        lines.append("-" * 60)
        for inc in body["incidents"][:40]:
            lines.append("  %s  %-6s %s / %s"
                         % (inc["t"], inc["status"].upper(),
                            inc["device"] or "-", inc["probe"]))
        if len(body["incidents"]) > 40:
            lines.append("  … %d more" % (len(body["incidents"]) - 40))
    return "\n".join(lines)


def to_csv(body: dict) -> str:
    """One row per probe. Deliberately flat — this goes into a spreadsheet."""
    import csv
    import io

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["device", "probe", "kind", "metric", "unit", "samples",
                "min", "avg", "p95", "max", "last", "healthy_pct", "worst",
                "breaches", "changes", "prev_avg", "delta_avg_pct", "source"])
    for r in body["probes"]:
        w.writerow([r["device"], r["name"], r["kind"], r["metric"], r["unit"],
                    r["samples"], r["min"], r["avg"], r["p95"], r["max"],
                    r["last"], r["healthy_pct"], r["worst"], r["breaches"],
                    r["changes"], r.get("prev_avg"), r.get("delta_avg_pct"),
                    r["source"]])
    return buf.getvalue()


def email_report(row, *, to=None, session=None) -> dict:
    """Mail one stored report. Returns ``{ok, detail, to}``.

    Recipients fall back through the same chain the alert engine uses, so a
    working alert configuration means working report delivery with nothing extra
    to set up.
    """
    from ..models import db
    from . import email_service
    from . import settings_store

    session = session or db.session
    if to is None:
        raw = (settings_store.get_str("reports.email_to", "")
               or settings_store.get_str("alerts.email_to", "")
               or (email_service.config().get("default_to") or ""))
        to = email_service.parse_recipients(raw)
    if not to:
        return {"ok": False, "detail": "No recipients configured "
                                       "(reports.email_to / alerts.email_to / "
                                       "email.default_to).", "to": []}
    if not email_service.is_configured():
        return {"ok": False, "detail": "SMTP is not configured.", "to": to}

    body = row.body()
    res = email_service.send_email(to, row.title, render_text(body))
    ok = bool(res.get("ok", True)) if isinstance(res, dict) else True
    if ok:
        row.emailed_at = datetime.utcnow()
        session.commit()
    detail = (res.get("detail", "") if isinstance(res, dict) else "") or "sent"
    return {"ok": ok, "detail": detail, "to": to}
