"""Resource history of the SATOM nodes themselves: CPU, memory and disk over time.

``system_health.host_stats()`` has measured both nodes since the Monitoring
page was written and :mod:`app.services.host_health` grades them, but every
reading was a snapshot: printed on a card, graded, then thrown away. "Was the
disk at 60 % last week?" and "did memory climb after the upgrade?" had no
answer anywhere in the product. On 2026-10-21 the primary stood at 77.8 % disk,
three points under the warning budget, and the only way to tell whether that
was a slow climb or a sudden jump was to go and read ``du`` by hand.

This module keeps the readings. Every ``metrics_scrape`` pass (3 min) samples
both nodes from :func:`app.services.infra_health.nodes` -- the same payload the
page and the grader read, so there is one measurement and no second
implementation -- and writes ``satom_node_*`` series to the local
VictoriaMetrics store, mirrored to the peer's store like every other series, so
a promoted standby inherits the history instead of starting empty.

Rules it keeps:

**A node we could not read writes ``satom_node_up 0`` and nothing else.** A gap
in the chart is the honest picture of a dead standby; carrying its last value
forward would draw a healthy line through an outage.

**The values are the ones the node reported, in the node's units.**
``host_stats`` rounds disks to 0.1 GB and memory to whole MB; the series are
named ``*_gb`` / ``*_mb`` rather than multiplied into bytes, because
"20400000000 bytes" claims a precision nobody measured.

**A failed query is an error, never an empty chart.** :func:`history` returns
the store's message under ``errors`` and the page paints it.

CPU is what :func:`app.services.system_health.cpu_pct` reports: the share of
the container's cores busy since the previous reading of that node, so each
point is an average over the window since the last read, not an instant.
"""
from __future__ import annotations

import math
import re
import time

UP = "satom_node_up"

# key -> (metric, unit, has a ``mount`` label)
SERIES = {
    "cpu": ("satom_node_cpu_pct", "%", False),
    "mem": ("satom_node_mem_pct", "%", False),
    "disk": ("satom_node_disk_pct", "%", True),
    "mem_used_mb": ("satom_node_mem_used_mb", "MB", False),
    "mem_total_mb": ("satom_node_mem_total_mb", "MB", False),
    "disk_used_gb": ("satom_node_disk_used_gb", "GB", True),
    "disk_total_gb": ("satom_node_disk_total_gb", "GB", True),
    "up": (UP, "", False),
}
DEFAULT_METRICS = ("cpu", "mem", "disk")

RANGES = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400,
          "30d": 30 * 86400, "90d": 90 * 86400}
DEFAULT_RANGE = "24h"

# The sample cadence: metrics_scrape runs every 3 minutes. A finer step would
# only repeat the same sample.
MIN_STEP_S = 180
# How far past the step each point looks back. Measured on a1 (2026-10-21,
# 199 runs): metrics_scrape fires every 185-342 s, mean 239 s, not every 180 s.
WINDOW_PAD_S = 360
MAX_POINTS = 400

NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def _name(node: dict) -> str:
    return (node.get("name")
            or ((node.get("host_stats") or {}).get("hostname")) or "")


def sample_lines(nodes, ts_ms: int | None = None) -> list[str]:
    """Exposition lines for one pass over ``nodes``. Pure: no I/O."""
    from .vm_store import line

    ts = ts_ms if ts_ms is not None else int(time.time() * 1000)
    out: list[str] = []
    for n in nodes or []:
        name = _name(n)
        if not name:
            continue
        hs = n.get("host_stats") if n.get("reachable") else None
        lab = {"node": name}
        out.append(line(UP, lab, 1 if hs else 0, ts))
        if not hs:
            continue
        out.append(line(SERIES["cpu"][0], lab, hs.get("cpu_pct"), ts))
        out.append(line(SERIES["mem"][0], lab, hs.get("mem_pct"), ts))
        out.append(line(SERIES["mem_used_mb"][0], lab, hs.get("mem_used_mb"), ts))
        out.append(line(SERIES["mem_total_mb"][0], lab, hs.get("mem_total_mb"), ts))
        for d in hs.get("disks") or []:
            dl = {"node": name, "mount": d.get("mount") or "?"}
            out.append(line(SERIES["disk"][0], dl, d.get("pct"), ts))
            out.append(line(SERIES["disk_used_gb"][0], dl, d.get("used_gb"), ts))
            out.append(line(SERIES["disk_total_gb"][0], dl, d.get("total_gb"), ts))
    # vm_store.line() answers '' for a missing value: an absent reading is
    # skipped, never written as 0.
    return [l for l in out if l]


def record(nodes=None) -> dict:
    """Sample every node into the local store and mirror it to the peer.

    Never raises: a resource sample must not cost the scrape pass it rides on.
    Returns ``{ok, nodes, series, detail, peer}``.
    """
    try:
        if nodes is None:
            from . import infra_health
            nodes = infra_health.nodes()
        lines = sample_lines(nodes)
        from . import vm_store
        ing = vm_store.ingest(lines)
        from . import metrics_collect as mc
        peer = mc.peer_write(lines)
        return {"ok": bool(ing["ok"]), "nodes": len(nodes or []),
                "series": len(lines), "detail": ing.get("detail") or "",
                "peer": peer.get("state")}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "nodes": 0, "series": 0,
                "detail": str(exc)[:200], "peer": None}


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def resolve_range(key: str | None) -> tuple[str, int]:
    key = (key or DEFAULT_RANGE).strip()
    if key not in RANGES:
        raise ValueError("range must be one of %s" % ", ".join(RANGES))
    return key, RANGES[key]


def step_for(seconds: int) -> int:
    """Whole minutes, never finer than the sample cadence, ≤ MAX_POINTS points."""
    step = max(MIN_STEP_S, int(math.ceil(seconds / MAX_POINTS / 60.0)) * 60)
    return step


def resolve_metrics(raw) -> list[str]:
    if not raw:
        return list(DEFAULT_METRICS)
    keys = [k.strip() for k in (raw.split(",") if isinstance(raw, str) else raw)
            if k and k.strip()]
    bad = [k for k in keys if k not in SERIES]
    if bad:
        raise ValueError("unknown metric %r; known: %s"
                         % (bad[0][:40], ", ".join(SERIES)))
    return list(dict.fromkeys(keys))


def check_node(node: str | None) -> str:
    node = (node or "").strip()
    if node and not NODE_RE.match(node):
        raise ValueError("node must be a node name (letters, digits, . _ -)")
    return node


def expr_for(key: str, step_s: int, node: str = "") -> str:
    """MetricsQL for one series key. ``max_over_time`` so a capacity chart
    never hides a peak between two plotted points.

    The window is the step plus :data:`WINDOW_PAD_S`. A window equal to the
    step (180 s on the short ranges) is shorter than the real scrape spacing
    (185-342 s), so most windows held no sample and drew a gap -- which this
    chart uses to mean "the node did not answer".
    """
    from .vm_store import escape_label

    metric = SERIES[key][0]
    sel = '{node="%s"}' % escape_label(node) if node else ""
    return "max_over_time(%s%s[%ds])" % (metric, sel, step_s + WINDOW_PAD_S)


def history(range_key: str | None = None, node: str | None = None,
            metrics=None, now: float | None = None) -> dict:
    """Time series for the nodes. Raises ``ValueError`` on a bad argument.

    ``{ok, range, start, end, step_s, series: [{key, metric, unit, node,
    mount, points: [[ts, value], ...]}], errors: [...]}``
    """
    from . import vm_store

    key, secs = resolve_range(range_key)
    node = check_node(node)
    keys = resolve_metrics(metrics)
    end = float(now if now is not None else time.time())
    step = step_for(secs)
    # The store plots points at start + k*step. Anchor that grid on ``end``:
    # with start = end - secs, a range that is not a whole number of steps
    # (7 d = 387.7 steps of 26 min) put the last point up to one step before
    # now, and the newest readings never reached the chart.
    start = end - int(math.ceil(secs / float(step))) * step
    out = {"ok": True, "range": key, "start": int(start), "end": int(end),
           "step_s": step, "series": [], "errors": []}
    for k in keys:
        metric, unit, _has_mount = SERIES[k]
        # nocache: the store's response cache hid a series' first ~5 minutes
        # (a node coming back, a new mount) from every range of 3 h or more.
        # At ≤ 400 points per series the raw read costs nothing.
        res = vm_store.query_range(expr_for(k, step, node), start, end,
                                   step="%ds" % step, nocache=True)
        if (res or {}).get("status") != "success":
            out["ok"] = False
            out["errors"].append({"key": k, "error": str((res or {}).get(
                "error") or "query failed")[:200]})
            continue
        for r in (res.get("data") or {}).get("result") or []:
            lab = r.get("metric") or {}
            pts = []
            for t, v in r.get("values") or []:
                try:
                    pts.append([int(float(t)), round(float(v), 2)])
                except (TypeError, ValueError):
                    continue
            out["series"].append({"key": k, "metric": metric, "unit": unit,
                                  "node": lab.get("node") or "",
                                  "mount": lab.get("mount"), "points": pts})
    out["series"].sort(key=lambda s: (s["key"], s["node"], s["mount"] or ""))
    return out


def snapshot(nodes=None) -> dict:
    """The current reading of every node, graded, without infrastructure
    addresses: what the API hands out (the page has its own feed)."""
    from . import host_health

    graded = host_health.fleet(nodes)
    out = []
    for g in graded["nodes"]:
        st = g.get("stats") or {}
        out.append({
            "name": g.get("name"),
            "role": g.get("role"),
            "is_local": bool(g.get("is_local")),
            "reachable": bool(g.get("reachable")),
            "status": g.get("status"),
            "reasons": [{"signal": r.get("signal"), "status": r.get("status"),
                         "text": r.get("text")} for r in g.get("reasons") or []],
            "cpus": st.get("cpus"),
            "cpu_pct": st.get("cpu_pct"),
            "mem_total_mb": st.get("mem_total_mb"),
            "mem_used_mb": st.get("mem_used_mb"),
            "mem_pct": st.get("mem_pct"),
            "disks": [{"mount": d.get("mount"), "total_gb": d.get("total_gb"),
                       "used_gb": d.get("used_gb"), "pct": d.get("pct")}
                      for d in st.get("disks") or []],
            "uptime_s": st.get("uptime_s"),
        })
    return {"status": graded.get("status"), "nodes": out,
            "limits": graded.get("limits")}
