"""Fleet metrics collection — scrape targets → VictoriaMetrics.

The unit of configuration is (appliance, collector), never (appliance,
policy): ``policy_status`` returns EVERY policy's counters in one 14 ms call,
so per-policy probes multiply device round-trips by N for data that is free
in aggregate. Measured 2026-08-05: the per-series design needed ~56 min of
device I/O per 3-minute window at fleet scale; this one needs seconds.

Cost tiers (defaults; every target's interval is operator-editable):

* cheap-and-complete — one call covers the device: ``box``, ``policies``,
  ``interfaces``. Default every 3 min.
* expensive-per-policy — one call PER policy: ``traffic`` (60 s of 1 Hz
  samples), ``transactions``. Default 15/60 min, and only the top-N policies
  by live connection rate (plus the device-total pseudo-policy for traffic) —
  full fidelity where the traffic is, bounded cost where it is not.

Rules carried over from the probe subsystem's scars:

* ``maintenance=True`` suppresses SCHEDULED collection entirely (the deep
  monitors forgot this once and probed recycled IPs every 3 minutes).
* A sweep that ran is ``ok`` even when devices errored — per-target status
  carries the failures; the action must not stick permanently red.
* Absence of data is never health: a failed collector writes
  ``satom_scrape_up 0``, it does not silently write nothing.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from . import vm_store

# Tolerance subtracted from the interval when deciding "due": the sweep runs
# on the scheduler tick, so a probe interval that misses the tick by seconds
# would silently double its effective cadence (the 5-under-3 lesson).
DUE_SLACK_S = 45

MAX_WORKERS = 8

COLLECTORS: dict = {
    "box": {
        "label": "Box resources (CPU, memory, sessions)",
        "products": ("fortiweb", "fortiadc"),
        "interval": 3, "params": {},
    },
    "policies": {
        "label": "Server policies — sessions / conn rate / RTT (one call, all policies)",
        "products": ("fortiweb",),
        "interval": 3, "params": {},
    },
    "interfaces": {
        "label": "Interfaces — link state + byte counters",
        "products": ("fortiweb",),
        "interval": 3, "params": {},
    },
    "traffic": {
        "label": "Throughput — device total + top-N policies",
        "products": ("fortiweb",),
        "interval": 15, "params": {"top_n": 10},
    },
    "transactions": {
        "label": "HTTP transactions — top-N policies",
        "products": ("fortiweb",),
        "interval": 60, "params": {"top_n": 10, "hours": 1},
    },
}


# ── provisioning ─────────────────────────────────────────────────────────────

def ensure_targets(appliance) -> int:
    """Create missing scrape targets for one appliance (INSERT-only: operator
    edits — intervals, enabled, params — always win). Returns rows created."""
    from ..models import db
    from ..models_metrics import ScrapeTarget

    existing = {t.collector for t in
                ScrapeTarget.query.filter_by(appliance_id=appliance.id).all()}
    created = 0
    for key, spec in COLLECTORS.items():
        if appliance.kind not in spec["products"] or key in existing:
            continue
        t = ScrapeTarget(appliance_id=appliance.id, collector=key,
                         interval_min=spec["interval"])
        t.params = dict(spec["params"])
        db.session.add(t)
        created += 1
    if created:
        db.session.commit()
    return created


def due_targets(now: datetime | None = None) -> list:
    """Enabled targets whose interval has elapsed, on live (non-maintenance,
    non-retired) appliances."""
    from ..models import Appliance
    from ..models_metrics import ScrapeTarget

    now = now or datetime.utcnow()
    rows = (ScrapeTarget.query.join(Appliance)
            .filter(ScrapeTarget.enabled.is_(True),
                    Appliance.maintenance.is_(False))
            .all())
    due = []
    for t in rows:
        host = (t.appliance.host or "") if t.appliance else ""
        if host.endswith(".invalid"):
            continue   # neutralised/retired device — structurally unreachable
        if t.last_run_at is None:
            due.append(t)
            continue
        elapsed = (now - t.last_run_at).total_seconds()
        if elapsed >= t.interval_min * 60 - DUE_SLACK_S:
            due.append(t)
    return due


# ── collectors ───────────────────────────────────────────────────────────────

def _num(v):
    try:
        return float(str(v).rstrip("%"))
    except (TypeError, ValueError):
        return None


def _labels(appliance, **extra) -> dict:
    d = {"device": appliance.name, "kind": appliance.kind}
    d.update(extra)
    return d


def _collect_box(appliance, params, ts) -> list:
    if appliance.kind == "fortiweb":
        from ..clients.fortiweb import FortiWebClient
        client = FortiWebClient(appliance, timeout=10.0)
        res, err = client.system_resource()
        if err:
            raise RuntimeError(str(err)[:150])
        row = res if isinstance(res, dict) else (res[0] if res else {})
        L = _labels(appliance)
        return [
            vm_store.line("satom_box_cpu_pct", L, _num(row.get("cpu")), ts),
            vm_store.line("satom_box_mem_pct", L, _num(row.get("mem")), ts),
            vm_store.line("satom_box_disk_pct", L, _num(row.get("diskUsage")), ts),
            vm_store.line("satom_box_logdisk_pct", L, _num(row.get("logDisk")), ts),
            vm_store.line("satom_box_sessions", L, _num(row.get("sessionCount")), ts),
            vm_store.line("satom_box_conn_per_sec", L, _num(row.get("connCntPerSec")), ts),
        ]
    # FortiADC: `get system performance` over read-only SSH — same parser the
    # deep monitors trust (REST has no equivalent on this product).
    from . import deep_monitor as dm
    from . import ssh_ops
    raw = ssh_ops.run_command(appliance, dm.PERF_CMD, timeout=12.0)
    perf = dm.parse_performance(raw)
    L = _labels(appliance)
    return [
        vm_store.line("satom_box_cpu_pct", L, perf.get("cpu_used"), ts),
        vm_store.line("satom_box_mem_pct", L, perf.get("mem_used"), ts),
    ]


def _collect_policies(appliance, params, ts) -> list:
    from ..clients.fortiweb import FortiWebClient
    client = FortiWebClient(appliance, timeout=10.0)
    rows, err = client.policy_status()
    if err:
        raise RuntimeError(str(err)[:150])
    lines = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        name = row.get("name") or row.get("policy_name")
        if not name:
            continue
        L = _labels(appliance, policy=name)
        up = 1 if str(row.get("status", "")).lower() in ("enable", "up", "1", "running") else 0
        lines += [
            vm_store.line("satom_policy_up", L, up, ts),
            vm_store.line("satom_policy_sessions", L, _num(row.get("sessionCount")), ts),
            vm_store.line("satom_policy_conn_per_sec", L, _num(row.get("connCntPerSec")), ts),
            vm_store.line("satom_policy_client_rtt_ms", L, _num(row.get("client_rtt")), ts),
            vm_store.line("satom_policy_server_rtt_ms", L, _num(row.get("server_rtt")), ts),
            vm_store.line("satom_policy_app_response_ms", L, _num(row.get("app_response_time")), ts),
        ]
    lines.append(vm_store.line("satom_policy_count", _labels(appliance),
                               len(rows or []), ts))
    return lines


def _collect_interfaces(appliance, params, ts) -> list:
    from ..clients.fortiweb import FortiWebClient
    client = FortiWebClient(appliance, timeout=10.0)
    res, err = client.system_operation()
    if err:
        raise RuntimeError(str(err)[:150])
    # Live shape (verified on fortiweb08 7.6.8): a dict whose "network" key
    # holds the interface list; older builds returned a bare list.
    rows = res if isinstance(res, list) else (res or {}).get("network") or []
    lines = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("name") or row.get("interface")
        if not name:
            continue
        L = _labels(appliance, iface=name)
        link_up = 1 if str(row.get("link", "")).lower() in ("up", "1", "true") else 0
        lines.append(vm_store.line("satom_iface_up", L, link_up, ts))
        # Cumulative counters — rate() in MetricsQL turns them into bandwidth.
        for metric, key in (("satom_iface_rx_bytes_total", "rx_bytes"),
                            ("satom_iface_tx_bytes_total", "tx_bytes")):
            val = _num(row.get(key))
            if val is not None:
                lines.append(vm_store.line(metric, L, val, ts))
    return lines


def _top_policies(client, n: int) -> list:
    rows, err = client.policy_status()
    if err:
        raise RuntimeError(str(err)[:150])
    scored = []
    for row in rows or []:
        if isinstance(row, dict) and (row.get("name") or row.get("policy_name")):
            scored.append((_num(row.get("connCntPerSec")) or 0.0,
                           row.get("name") or row.get("policy_name")))
    scored.sort(reverse=True)
    return [name for _score, name in scored[:max(1, n)]]


def _tp_values(res) -> list:
    """policy_traffic returns a bare list (no cache) or a dict with
    ``throughput``; values are BYTES/s as strings."""
    vals = res.get("throughput") if isinstance(res, dict) else res
    out = []
    for v in vals or []:
        n = _num(v)
        if n is not None:
            out.append(n)
    return out


def _collect_traffic(appliance, params, ts) -> list:
    from ..clients.fortiweb import FortiWebClient
    client = FortiWebClient(appliance, timeout=15.0)
    lines = []
    # Device total first: the aggregate pseudo-policy — one call, whole box.
    res, err = client.policy_traffic("Total HTTP Throughput")
    if not err:
        vals = _tp_values(res)
        if vals:
            L = _labels(appliance)
            lines.append(vm_store.line("satom_total_throughput_bps", L,
                                       sum(vals) / len(vals) * 8, ts))
            lines.append(vm_store.line("satom_total_throughput_peak_bps", L,
                                       max(vals) * 8, ts))
    for name in _top_policies(client, int(params.get("top_n") or 10)):
        res, err = client.policy_traffic(name)
        if err:
            continue
        vals = _tp_values(res)
        if not vals:
            continue
        L = _labels(appliance, policy=name)
        lines.append(vm_store.line("satom_policy_throughput_bps", L,
                                   sum(vals) / len(vals) * 8, ts))
        lines.append(vm_store.line("satom_policy_throughput_peak_bps", L,
                                   max(vals) * 8, ts))
    return lines


def _collect_transactions(appliance, params, ts) -> list:
    from ..clients.fortiweb import FortiWebClient
    client = FortiWebClient(appliance, timeout=15.0)
    hours = int(params.get("hours") or 1)
    lines = []
    for name in _top_policies(client, int(params.get("top_n") or 10)):
        rows, err = client.http_transactions(name, hours=hours)
        if err:
            continue
        total = 0
        for b in rows or []:
            if isinstance(b, dict):
                total += int(_num(b.get("count") or b.get("value") or 0) or 0)
        L = _labels(appliance, policy=name)
        lines.append(vm_store.line("satom_policy_transactions_window", L,
                                   total, ts))
    return lines


_RUNNERS = {
    "box": _collect_box,
    "policies": _collect_policies,
    "interfaces": _collect_interfaces,
    "traffic": _collect_traffic,
    "transactions": _collect_transactions,
}


# ── execution ────────────────────────────────────────────────────────────────

def run_target(target) -> dict:
    """Run ONE target: collect → ingest → record outcome on the row.
    Returns {ok, series, ms, detail}. Never raises."""
    from ..models import db

    t0 = time.time()
    ts = int(t0 * 1000)
    appliance = target.appliance
    ok, detail, lines = True, "", []
    try:
        fn = _RUNNERS[target.collector]
        lines = [l for l in fn(appliance, target.params, ts) if l]
    except Exception as exc:  # noqa: BLE001 — a dead box is a result
        ok, detail = False, str(exc)[:250]
    # The scrape's own health is a metric too: a broken collector must be
    # VISIBLE in the store, not an absence someone has to notice.
    lines.append(vm_store.line(
        "satom_scrape_up",
        {"device": appliance.name, "kind": appliance.kind,
         "collector": target.collector}, 1 if ok else 0, ts))
    ing = vm_store.ingest(lines)
    if not ing["ok"]:
        ok, detail = False, (detail + " | ingest: " + ing["detail"]).strip(" |")
    ms = int((time.time() - t0) * 1000)
    target.last_run_at = datetime.utcnow()
    target.last_status = "ok" if ok else "error"
    target.last_detail = detail
    target.last_series = max(0, len(lines) - 1)
    target.last_ms = ms
    db.session.commit()
    return {"ok": ok, "series": target.last_series, "ms": ms, "detail": detail}


def sweep() -> dict:
    """One scheduled pass: auto-provision targets for new appliances, then run
    everything due, concurrently across devices."""
    from ..models import Appliance

    created = 0
    for a in Appliance.query.filter(Appliance.maintenance.is_(False)).all():
        if (a.host or "").endswith(".invalid"):
            continue
        created += ensure_targets(a)
    due = due_targets()
    results = []
    if due:
        # Concurrency is per-target; each worker commits its own row, and
        # SQLAlchemy sessions are not thread-safe — so collect first, run
        # serially through the session-bound update. The device I/O dominates
        # (a policy_status is ~14 ms; SSH perf ~1 s), so parallelise ONLY the
        # device calls via a thread pool bounded well below the appliances'
        # admin-session limits.
        from flask import current_app
        app_obj = current_app._get_current_object()

        def _one(t_id):
            with app_obj.app_context():
                from ..models_metrics import ScrapeTarget
                t = ScrapeTarget.query.get(t_id)
                return run_target(t) if t else {"ok": False, "detail": "gone"}

        ids = [t.id for t in due]
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            results = list(pool.map(_one, ids))
    n_ok = sum(1 for r in results if r["ok"])
    return {"targets": len(due), "ok": n_ok,
            "errors": len(results) - n_ok, "created": created,
            "series": sum(r.get("series", 0) for r in results),
            "ms": sum(r.get("ms", 0) for r in results)}
