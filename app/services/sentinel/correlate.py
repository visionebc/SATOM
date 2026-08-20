"""The correlation engine — a trigger becomes a multi-layer picture.

What correlation actually is here
---------------------------------
Not "several rules fired". A :class:`WindowContext` is one time window
[T-pre, T+post] resolved simultaneously against every layer that can speak
about the target: the attack events themselves, the appliance's own counters,
the VM it runs in, the hypervisor node under that, and the backend behind it.
Each layer contributes a measured delta against its own hour-of-week baseline,
plus the LAG between T0 and the moment that layer moved.

The lag is the part that carries causality. Attack at T0, appliance CPU at
T0+2s, disk I/O at T0+3s, backend latency at T0+8s is a chain. The same five
readings with no ordering are five coincidences. This engine records the
ordering explicitly so an operator (and the score) can tell the difference.

The join key is topology, not the log
-------------------------------------
An appliance's VM and host layers are reachable only through
``sentinel_topology``. With no row, those layers report ``unknown`` — never
``no impact``. That distinction is the reason the table exists: a saturated
hypervisor that nobody mapped must not read as a healthy one.

Cost
----
A window resolves with ONE ranged query per series against the node's local
VictoriaMetrics over loopback. Zero appliance calls: by the time an incident
is being correlated the device is, by hypothesis, under load, and adding
round-trips to a box that is already saturating is how a monitoring system
becomes part of the outage.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ...models_sentinel import SentinelEvent
from . import baseline, config, enrich
from .. import vm_store

#: Which series describe which layer, and how to select them. ``by`` names the
#: label the device is matched on. Keeping this as data (not a chain of ifs)
#: is what lets the UI, the scoring and the evidence builder all iterate the
#: same list — three hand-written copies is how layers silently go missing.
LAYER_SERIES: list[dict] = [
    {"layer": "box", "metric": "satom_box_cpu_pct", "by": "device",
     "label": "appliance CPU", "unit": "%", "agg": "max"},
    {"layer": "box", "metric": "satom_box_mem_pct", "by": "device",
     "label": "appliance memory", "unit": "%", "agg": "max"},
    {"layer": "box", "metric": "satom_box_conn_per_sec", "by": "device",
     "label": "connections per second", "unit": "/s", "agg": "max"},
    {"layer": "box", "metric": "satom_box_sessions", "by": "device",
     "label": "sessions", "unit": "", "agg": "max"},
    {"layer": "traffic", "metric": "satom_traffic_mbps", "by": "device",
     "label": "throughput", "unit": "Mbps", "agg": "max"},
    {"layer": "http_status", "metric": "satom_http_status_rate", "by": "device",
     "label": "HTTP status rate", "unit": "/s", "agg": "max"},
    {"layer": "backend", "metric": "satom_policy_rtt_ms", "by": "device",
     "label": "backend round-trip time", "unit": "ms", "agg": "max"},
    {"layer": "vm", "metric": "satom_vm_cpu_pct", "by": "device",
     "label": "VM CPU", "unit": "%", "agg": "max"},
    {"layer": "vm", "metric": "satom_vm_mem_pct", "by": "device",
     "label": "VM memory", "unit": "%", "agg": "max"},
    # Cumulative counters, so the RATE is derived here by the store rather than
    # by the collector: MetricsQL's rate() handles the counter reset a VM
    # restart causes, and a collector-side delta does not — it goes negative.
    {"layer": "vm", "metric": "satom_vm_disk_bytes_per_sec", "by": "device",
     "label": "VM disk I/O", "unit": "B/s", "agg": "max",
     "match": "satom_vm_disk_read_bytes_total",
     "expr": "rate(satom_vm_disk_read_bytes_total{sel}[5m]) + "
             "rate(satom_vm_disk_write_bytes_total{sel}[5m])"},
    {"layer": "vm", "metric": "satom_vm_net_bytes_per_sec", "by": "device",
     "label": "VM network", "unit": "B/s", "agg": "max",
     "match": "satom_vm_net_in_bytes_total",
     "expr": "rate(satom_vm_net_in_bytes_total{sel}[5m]) + "
             "rate(satom_vm_net_out_bytes_total{sel}[5m])"},
    {"layer": "host", "metric": "satom_host_cpu_pct", "by": "node",
     "label": "host CPU", "unit": "%", "agg": "max"},
    {"layer": "host", "metric": "satom_host_mem_pct", "by": "node",
     "label": "host memory", "unit": "%", "agg": "max"},
]

#: Layers whose absence means "we could not look", not "nothing happened".
TOPOLOGY_LAYERS = ("vm", "host")


@dataclass
class LayerReading:
    """One series' behaviour inside the window, judged against its baseline."""

    layer: str
    metric: str
    label: str
    unit: str
    series_key: str
    peak: float | None = None
    peak_at: datetime | None = None
    pre_value: float | None = None
    median: float | None = None
    deviation: float = 0.0
    ratio: float = 0.0
    anomalous: bool = False
    usable: bool = False
    state: str = ""
    lag_s: float | None = None
    points: list = field(default_factory=list)   # [(epoch_s, value), ...]

    def to_dict(self) -> dict:
        return {"layer": self.layer, "metric": self.metric, "label": self.label,
                "unit": self.unit, "series_key": self.series_key,
                "peak": self.peak, "pre_value": self.pre_value,
                "median": self.median, "deviation": round(self.deviation, 2),
                "ratio": round(self.ratio, 2), "anomalous": self.anomalous,
                "usable": self.usable, "state": self.state,
                "lag_s": self.lag_s,
                "peak_at": self.peak_at.isoformat(timespec="seconds")
                           if self.peak_at else "",
                "points": self.points}


@dataclass
class WindowContext:
    """Everything known about one window, before any scoring happens."""

    device: str
    src_ip: str
    attack_family: str
    t0: datetime
    start: datetime
    end: datetime
    events: list = field(default_factory=list)
    readings: list = field(default_factory=list)
    layers_unknown: list = field(default_factory=list)
    source: dict = field(default_factory=dict)
    http: dict = field(default_factory=dict)
    vuln: dict = field(default_factory=dict)
    store_ok: bool = True
    store_detail: str = ""

    # ── derived views the scorer and the UI both use ──────────────────────
    def layer_readings(self, layer: str) -> list:
        return [r for r in self.readings if r.layer == layer]

    def layer_anomalous(self, layer: str):
        """``True`` / ``False`` / ``None``. ``None`` means we could not look —
        no topology row, or no usable baseline — and it is propagated all the
        way to the incident's impact flags rather than collapsed into False."""
        rows = [r for r in self.readings if r.layer == layer]
        usable = [r for r in rows if r.usable]
        if not usable:
            return None
        return any(r.anomalous for r in usable)

    def worst(self, layer: str):
        rows = [r for r in self.readings if r.layer == layer and r.usable]
        return max(rows, key=lambda r: abs(r.deviation), default=None)

    @property
    def blocked_count(self) -> int:
        return sum(e.count or 1 for e in self.events if e.blocked)

    @property
    def passed_count(self) -> int:
        return sum(e.count or 1 for e in self.events if not e.blocked)

    @property
    def event_count(self) -> int:
        return sum(e.count or 1 for e in self.events)

    @property
    def worst_severity(self) -> str:
        best, rank = "info", -1
        for e in self.events:
            if e.severity_rank > rank:
                best, rank = (e.severity or "info"), e.severity_rank
        return best

    @property
    def causal_chain(self) -> list:
        """Anomalous layers ordered by when they moved. The evidence of
        causality — an ordered chain, not a bag of coincidences."""
        rows = [r for r in self.readings
                if r.anomalous and r.lag_s is not None]
        rows.sort(key=lambda r: r.lag_s)
        return rows

    def to_dict(self) -> dict:
        return {
            "device": self.device, "src_ip": self.src_ip,
            "attack_family": self.attack_family,
            "t0": self.t0.isoformat(timespec="seconds"),
            "start": self.start.isoformat(timespec="seconds"),
            "end": self.end.isoformat(timespec="seconds"),
            "event_count": self.event_count,
            "blocked_count": self.blocked_count,
            "passed_count": self.passed_count,
            "worst_severity": self.worst_severity,
            "readings": [r.to_dict() for r in self.readings],
            "layers_unknown": self.layers_unknown,
            "source": self.source, "http": self.http, "vuln": self.vuln,
            "store_ok": self.store_ok, "store_detail": self.store_detail,
            "chain": [{"layer": r.layer, "label": r.label, "lag_s": r.lag_s,
                       "ratio": round(r.ratio, 2)} for r in self.causal_chain],
        }


# --------------------------------------------------------------------------- #
#  Store access                                                                 #
# --------------------------------------------------------------------------- #
def _epoch(dt: datetime) -> float:
    return dt.replace(tzinfo=timezone.utc).timestamp()


def _selector(spec: dict, device: str, node: str) -> str:
    """The query for one layer series.

    A spec may carry an explicit ``expr`` template with a ``{sel}`` placeholder
    — that is how a CUMULATIVE counter becomes a rate. The template owns the
    metric names; ``metric`` remains the stable identity used for the baseline
    key, so switching a series from gauge to rate does not silently orphan the
    baseline it has already learned.
    """
    value = node if spec["by"] == "node" else device
    if not value:
        return ""
    sel = '{%s="%s"}' % (spec["by"], _escape(value))
    template = spec.get("expr")
    if template:
        return template.replace("{sel}", sel)
    return spec["metric"] + sel


def _escape(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"')


def _series_points(payload: dict) -> list:
    """Flatten a query_range payload into [(epoch, value)], merged across
    series by taking the maximum at each timestamp.

    Maximum, not mean: a device with ten policies where ONE is saturating is
    a device with a problem, and averaging it against nine idle ones is how
    that problem disappears into the arithmetic.
    """
    if (payload or {}).get("status") != "success":
        return []
    merged: dict = {}
    for series in ((payload.get("data") or {}).get("result") or []):
        for point in (series.get("values") or []):
            try:
                ts, raw = float(point[0]), float(point[1])
            except (TypeError, ValueError, IndexError):
                continue
            if ts not in merged or raw > merged[ts]:
                merged[ts] = raw
    return sorted(merged.items())


def _read_layer(spec: dict, device: str, node: str, start: datetime,
                end: datetime, t0: datetime, step: str) -> "LayerReading | None":
    expr = _selector(spec, device, node)
    if not expr:
        return None
    payload = vm_store.query_range(expr, _epoch(start), _epoch(end), step=step)
    points = _series_points(payload)
    key = baseline.series_key(spec["metric"],
                              {spec["by"]: node if spec["by"] == "node" else device})
    reading = LayerReading(layer=spec["layer"], metric=spec["metric"],
                           label=spec["label"], unit=spec["unit"],
                           series_key=key, points=points)
    if not points:
        return reading
    peak_ts, peak_val = max(points, key=lambda p: p[1])
    reading.peak = peak_val
    reading.peak_at = datetime.fromtimestamp(peak_ts, tz=timezone.utc
                                             ).replace(tzinfo=None)
    pre = [v for ts, v in points if ts <= _epoch(t0)]
    reading.pre_value = pre[-1] if pre else None
    verdict = baseline.evaluate(key, peak_val, t0)
    reading.usable = verdict["usable"]
    reading.state = verdict["state"]
    reading.median = verdict.get("median")
    reading.deviation = verdict.get("deviation") or 0.0
    reading.ratio = verdict.get("ratio") or 0.0
    reading.anomalous = bool(verdict.get("anomalous"))
    if reading.anomalous:
        # Lag is measured to the FIRST crossing, not to the peak: the peak of
        # a saturating series arrives minutes after the cause, and using it
        # would scramble the causal ordering the chain depends on.
        reading.lag_s = _first_crossing(points, verdict, t0)
    return reading


def _first_crossing(points: list, verdict: dict, t0: datetime):
    med = verdict.get("median")
    mad_v = verdict.get("mad") or 0.0
    k = verdict.get("threshold_k") or float(config.get("baseline_k"))
    t0e = _epoch(t0)
    for ts, val in points:
        if ts < t0e:
            continue
        if abs(baseline.deviation(val, med, mad_v)) >= k:
            return round(ts - t0e, 1)
    return None


# --------------------------------------------------------------------------- #
#  HTTP status behaviour                                                        #
# --------------------------------------------------------------------------- #
def http_picture(events: list) -> dict:
    """What the response codes say — a behaviour layer, not a verdict.

    An HTTP status does not map to a vulnerability and nothing here pretends
    it does. What it carries is the OUTCOME of each attack request, and the
    two outcomes mean opposite things:

    * the WAF answered 403 (or the action was a block) — the defence worked,
      and a wall of these is a quiet night, not an emergency;
    * the origin answered 200 to a request carrying an attack signature — the
      defence did not work, and that single fact outweighs volume.

    5xx is the backend's own distress, and 404 across many distinct URIs is
    enumeration rather than exploitation.
    """
    classes = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "unknown": 0}
    codes: dict = {}
    uris: set = set()
    success_on_attack = 0
    for ev in events:
        n = ev.count or 1
        code = ev.http_status
        if code:
            codes[code] = codes.get(code, 0) + n
            bucket = f"{code // 100}xx"
            classes[bucket] = classes.get(bucket, 0) + n
            if 200 <= code < 300 and not ev.blocked:
                success_on_attack += n
        else:
            classes["unknown"] += n
        if ev.uri:
            uris.add(ev.uri[:200])
    total = sum(classes.values()) or 1
    return {
        "classes": classes, "codes": codes, "total": total,
        "distinct_uris": len(uris),
        "success_on_attack": success_on_attack,
        "evasion_suspected": success_on_attack > 0,
        "server_error_pct": round(100.0 * classes.get("5xx", 0) / total, 1),
        "client_error_pct": round(100.0 * classes.get("4xx", 0) / total, 1),
        "enumeration_suspected": len(uris) >= 20 and classes.get("4xx", 0) > 0,
    }


# --------------------------------------------------------------------------- #
#  Entry point                                                                  #
# --------------------------------------------------------------------------- #
def build(device: str, src_ip: str, attack_family: str, t0: datetime, *,
          appliance_id: int | None = None, events: list | None = None,
          step: str = "30s") -> WindowContext:
    """Resolve one correlation window across every reachable layer."""
    pre = int(config.get("window_pre_s"))
    post = int(config.get("window_post_s"))
    start, end = t0 - timedelta(seconds=pre), t0 + timedelta(seconds=post)

    if events is None:
        q = SentinelEvent.query.filter(SentinelEvent.ts >= start,
                                       SentinelEvent.ts <= end)
        if device:
            q = q.filter(SentinelEvent.device == device)
        if src_ip:
            q = q.filter(SentinelEvent.src_ip == src_ip)
        events = q.order_by(SentinelEvent.ts).all()

    ctx = WindowContext(device=device, src_ip=src_ip,
                        attack_family=attack_family, t0=t0, start=start,
                        end=end, events=list(events))

    topo = enrich.topology_for(appliance_id) if appliance_id else None
    node = (topo.node if topo else "") or ""

    health = vm_store.health()
    ctx.store_ok = bool(health.get("up"))
    ctx.store_detail = health.get("detail") or ""

    for spec in LAYER_SERIES:
        if spec["layer"] in TOPOLOGY_LAYERS and not (topo and topo.complete):
            if spec["layer"] not in ctx.layers_unknown:
                ctx.layers_unknown.append(spec["layer"])
            continue
        if not ctx.store_ok:
            if spec["layer"] not in ctx.layers_unknown:
                ctx.layers_unknown.append(spec["layer"])
            continue
        reading = _read_layer(spec, device, node, start, end, t0, step)
        if reading is not None:
            ctx.readings.append(reading)

    ctx.source = enrich.source_context(src_ip, device=device, when=t0)
    ctx.http = http_picture(ctx.events)

    cve_ids = _cves_from_events(ctx.events)
    from . import vuln as vuln_mod
    ctx.vuln = vuln_mod.enrich_cves(cve_ids,
                                    cpe_hints=enrich.cpe_hints(topo))
    return ctx


def _cves_from_events(events: list) -> list:
    """CVE ids the DEVICE annotated, with the local mapping table as fallback."""
    from . import normalize
    from . import vuln as vuln_mod
    found: list = []
    for ev in events:
        found.extend(normalize.cve_ids(ev.raw or {}))
        if not found and ev.signature_id:
            found.extend(vuln_mod.cves_for_signature(ev.signature_id))
    return list(dict.fromkeys(found))
