"""Behavioural baselines — median + MAD per series, per hour-of-week.

Why robust statistics and not mean + sigma
------------------------------------------
A security baseline is trained on data that CONTAINS attacks. With a mean, one
8,500 req/s flood drags the centre up and inflates the standard deviation, so
the next identical flood scores as *less* anomalous than the first — the
detector desensitises itself with every incident it sees. The median is
unaffected by a minority of extreme samples, and the MAD (median absolute
deviation) inherits that immunity. This is the property that makes the number
usable without a human curating the training set.

Why 168 buckets and not one
---------------------------
Fleet traffic is not stationary. 8,000 req/s at Tuesday noon may be a sale;
the same figure at Sunday 03:00 is not. One bucket per hour-of-week is the
cheapest structure that captures both the daily and the weekly shape, and it
stays explainable to an operator — "17x the Tuesday-12h median" is a sentence
someone can argue with, which is the whole point.

Why no machine learning here
----------------------------
It was considered and rejected for v1: an isolation forest produces a score
nobody can defend in a post-mortem, needs its own retraining and drift
monitoring, and would be the second non-deterministic component in a system
whose entire safety argument is that the deciding path is reproducible.
Median/MAD is ~30 lines, costs one nightly pass over a store that already
keeps 396 days raw, and every number it emits can be recomputed by hand.

Cost
----
The recompute reads the TSDB, not the appliances. A full pass touches zero
devices; it is safe to run at any hour and its only budget is the node's own
CPU and the store's query time.
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta

from ...models import db
from ...models_sentinel import SentinelBaseline
from . import config

#: 1.4826 makes the MAD a consistent estimator of the standard deviation for
#: normally-distributed data, so the k in "k x MAD" keeps the intuition of a
#: sigma multiple for the well-behaved series while staying robust for the
#: rest. Without it, k would mean something different for every series.
MAD_SCALE = 1.4826

#: Series Sentinel baselines. Key is the metric name in the store; ``layer``
#: is which stratum of the correlation this series belongs to, and ``unit``/
#: ``label`` exist so evidence rows read as sentences rather than metric names.
SERIES: dict[str, dict] = {
    "satom_box_cpu_pct": {"layer": "box", "unit": "%", "label": "appliance CPU"},
    "satom_box_mem_pct": {"layer": "box", "unit": "%", "label": "appliance memory"},
    "satom_box_sessions": {"layer": "box", "unit": "", "label": "sessions"},
    "satom_box_conn_per_sec": {"layer": "box", "unit": "/s",
                               "label": "connections per second"},
    "satom_policy_conn_per_sec": {"layer": "traffic", "unit": "/s",
                                  "label": "policy connection rate"},
    "satom_policy_sessions": {"layer": "traffic", "unit": "",
                              "label": "policy sessions"},
    "satom_policy_rtt_ms": {"layer": "backend", "unit": "ms",
                            "label": "backend round-trip time"},
    "satom_traffic_mbps": {"layer": "traffic", "unit": "Mbps",
                           "label": "throughput"},
    "satom_http_status_rate": {"layer": "http_status", "unit": "/s",
                               "label": "HTTP status rate"},
    "satom_vm_cpu_pct": {"layer": "vm", "unit": "%", "label": "VM CPU"},
    "satom_vm_mem_pct": {"layer": "vm", "unit": "%", "label": "VM memory"},
    "satom_vm_disk_bytes_per_sec": {"layer": "vm", "unit": "B/s",
                                   "label": "VM disk I/O"},
    "satom_vm_net_bytes_per_sec": {"layer": "vm", "unit": "B/s",
                                   "label": "VM network"},
    "satom_host_cpu_pct": {"layer": "host", "unit": "%", "label": "host CPU"},
    "satom_host_mem_pct": {"layer": "host", "unit": "%", "label": "host memory"},
}


def dow_hour(when: datetime) -> int:
    """Bucket index 0..167. Monday 00:00 is 0."""
    return when.weekday() * 24 + when.hour


def series_key(metric: str, labels: dict) -> str:
    """Stable identity for one time series.

    Labels are sorted so the same series cannot acquire two keys because two
    call sites built the dict in a different order — that silently doubles a
    baseline's learning time and halves its sample count.
    """
    parts = ",".join(f"{k}={labels[k]}" for k in sorted(labels or {}))
    return f"{metric}{{{parts}}}" if parts else metric


def median(values: list) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return float(s[mid]) if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def mad(values: list, med: float | None = None) -> float:
    """Median absolute deviation, scaled to be sigma-comparable."""
    if not values:
        return 0.0
    m = median(values) if med is None else med
    return MAD_SCALE * median([abs(v - m) for v in values])


def percentile(values: list, q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
    return float(s[idx])


def deviation(value: float, med: float, m: float) -> float:
    """Robust z-score, with the degenerate case handled honestly.

    A MAD of zero means "this series has been perfectly flat" — every DHCP-
    quiet interface, every idle policy. Dividing by it yields infinity, and an
    infinite deviation on an idle series is the single easiest way to build a
    detector that screams at nothing. So a flat series produces a deviation
    only when the sample ALSO differs from the median in absolute terms, and
    the magnitude is capped: an idle series can report "something changed",
    never "this is the most anomalous event in the fleet".
    """
    if value is None or med is None:
        return 0.0
    diff = float(value) - float(med)
    if m and m > 1e-9:
        return diff / m
    if abs(diff) < 1e-9:
        return 0.0
    # Flat-series fallback: sign-preserving, magnitude-capped.
    return math.copysign(min(abs(diff), 10.0), diff)


def ratio(value: float, med: float) -> float:
    """value / median, with a zero median reported as 0.0 rather than infinity.
    The UI prints ratios; an 'inf x baseline' badge is not information."""
    try:
        if not med:
            return 0.0
        return float(value) / float(med)
    except (TypeError, ValueError, ZeroDivisionError):
        return 0.0


# --------------------------------------------------------------------------- #
#  Persistence                                                                  #
# --------------------------------------------------------------------------- #
def get_bucket(key: str, bucket: int) -> "SentinelBaseline | None":
    return SentinelBaseline.query.filter_by(series_key=key,
                                            dow_hour=bucket).first()


def upsert(key: str, bucket: int, values: list, *,
           frozen: bool = False) -> "SentinelBaseline":
    """Recompute one bucket from raw samples.

    A frozen bucket keeps its statistics and only records that it was skipped:
    maintenance windows exist so an authorised pentest does not poison the
    profile, and silently folding those samples in would do exactly that.
    """
    row = get_bucket(key, bucket)
    if row is None:
        row = SentinelBaseline(series_key=key, dow_hour=bucket)
        db.session.add(row)
    if frozen:
        row.state = SentinelBaseline.STATE_FROZEN
        return row
    med = median(values)
    row.median = med
    row.mad = mad(values, med)
    row.p95 = percentile(values, 0.95)
    row.n = len(values)
    min_n = int(config.get("baseline_min_samples"))
    row.state = (SentinelBaseline.STATE_ACTIVE if len(values) >= min_n
                 else SentinelBaseline.STATE_LEARNING)
    row.updated_at = datetime.utcnow()
    return row


def evaluate(key: str, value: float, when: datetime | None = None) -> dict:
    """Judge one sample against its bucket.

    Returns a dict that always contains ``usable``. A caller that ignores it
    and reads ``deviation`` gets 0.0 — the safe direction. There is no code
    path here that produces a firing verdict from a learning baseline.
    """
    when = when or datetime.utcnow()
    bucket = dow_hour(when)
    row = get_bucket(key, bucket)
    if row is None or not row.usable:
        return {"usable": False, "state": row.state if row else "missing",
                "n": row.n if row else 0, "value": value, "median": None,
                "mad": None, "deviation": 0.0, "ratio": 0.0,
                "anomalous": False, "bucket": bucket}
    dev = deviation(value, row.median, row.mad)
    k = float(config.get("baseline_k"))
    return {"usable": True, "state": row.state, "n": row.n, "value": value,
            "median": row.median, "mad": row.mad, "p95": row.p95,
            "deviation": dev, "ratio": ratio(value, row.median),
            "anomalous": abs(dev) >= k, "bucket": bucket,
            "threshold_k": k}


def recompute(metric: str, labels: dict, samples: list) -> int:
    """Rebuild every bucket of one series from ``[(datetime, value), ...]``.

    Returns the number of buckets written. Samples landing inside a frozen
    window are dropped by the caller (:func:`app.services.sentinel.pipeline`),
    not here — this function has no opinion about maintenance, only about
    statistics.
    """
    key = series_key(metric, labels)
    buckets: dict[int, list] = {}
    for when, value in samples:
        if value is None:
            continue
        buckets.setdefault(dow_hour(when), []).append(float(value))
    for bucket, values in buckets.items():
        upsert(key, bucket, values)
    return len(buckets)


def coverage() -> dict:
    """How much of the profile is actually usable — the honest health number.

    A page that shows "baselines: 1,240" tells an operator nothing about
    whether detection works. What matters is how many buckets have crossed
    into ACTIVE, because the learning ones cannot fire.
    """
    rows = SentinelBaseline.query.all()
    total = len(rows)
    active = sum(1 for r in rows if r.state == SentinelBaseline.STATE_ACTIVE)
    usable = sum(1 for r in rows if r.usable)
    learning = sum(1 for r in rows if r.state == SentinelBaseline.STATE_LEARNING)
    frozen = sum(1 for r in rows if r.state == SentinelBaseline.STATE_FROZEN)
    series = len({r.series_key for r in rows})
    newest = max((r.updated_at for r in rows if r.updated_at), default=None)
    return {"total": total, "active": active, "usable": usable,
            "learning": learning, "frozen": frozen, "series": series,
            "pct_usable": round(100.0 * usable / total, 1) if total else 0.0,
            "updated_at": newest.isoformat(timespec="seconds") if newest else ""}


def purge_older_than(days: int) -> int:
    """Drop buckets untouched for ``days`` — a series whose device is gone."""
    cutoff = datetime.utcnow() - timedelta(days=max(1, int(days)))
    q = SentinelBaseline.query.filter(SentinelBaseline.updated_at < cutoff)
    n = q.count()
    q.delete(synchronize_session=False)
    return n
