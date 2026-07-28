"""Per-device and per-policy consolidation of the REST telemetry probes.

The Service Monitor table answers *"is this probe healthy?"*. These two views
answer the questions an operator actually arrives with: **how much traffic is
this appliance moving**, and **what is happening inside this server policy**.

Both are built ENTIRELY from stored samples. A page load never contacts an
appliance — same contract as the probe table itself, and the reason either view
still renders with the box powered off or its cmdb API licence-locked.

Three rules are enforced here, all carried over from ``device_health``:

* **Absence of a probe is never health.** A device with no throughput probe
  reports ``unknown`` and says so, never ``0 Mbps``. A zero that means "not
  measured" is indistinguishable on screen from a zero that means "idle", and
  the first one is a monitoring gap wearing the costume of good news.
* **A disabled probe is not a passing probe.** It reports ``unknown`` with the
  reason, and it counts as a coverage gap.
* **Stale is stated, not hidden.** Every block carries the age of the sample it
  was built from and a ``stale`` flag, because a number frozen an hour ago
  renders exactly like one read a minute ago.

Deliberately NOT computed: a single rolled-up status badge per device.
``deep_monitor.worst`` ranks ``unknown`` as *less* severe than ``ok`` (it is the
tail of ``STATUS_ORDER``), so one healthy probe beside three missing ones would
roll up green. Rather than fork the fleet-wide severity ordering for one card,
this module returns each block's own status plus an explicit ``coverage``
summary, and the template renders both.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from ..models import Appliance, MonitorProbe, MonitorSample
from . import deep_monitor as dm

# A sample older than this is flagged stale. A small multiple of the 5-minute
# sweep on purpose: two missed sweeps is a signal, one is jitter.
STALE_AFTER = timedelta(minutes=16)

# Points kept for the inline sparkline on a rollup card. The full chart is one
# click away on the probe itself; this is a shape, not a dataset.
SPARK_POINTS = 40


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _load(raw) -> dict:
    """``MonitorSample.payload`` is stored as a JSON string; never raise."""
    if isinstance(raw, dict):
        return raw
    try:
        out = json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}
    return out if isinstance(out, dict) else {}


def _age_s(ts) -> int | None:
    if not ts:
        return None
    return max(0, int((datetime.utcnow() - ts).total_seconds()))


def _latest(probe_id: int):
    return (MonitorSample.query
            .filter(MonitorSample.probe_id == probe_id)
            .order_by(MonitorSample.ts.desc()).first())


def _spark(probe_id: int, limit: int = SPARK_POINTS) -> list[dict]:
    rows = (MonitorSample.query
            .filter(MonitorSample.probe_id == probe_id)
            .order_by(MonitorSample.ts.desc()).limit(limit).all())
    return [{"ts": r.ts.isoformat(timespec="seconds"), "status": r.status,
             "value_num": r.value_num, "value2_num": r.value2_num}
            for r in reversed(rows)]


def _block(probe, *, payload: bool = False, spark: bool = False) -> dict:
    """The current reading of one probe — or an honest account of its absence.

    Returns a dict that ALWAYS carries ``present``/``status``/``detail`` so the
    caller never has to distinguish "missing" from "measured zero" by looking at
    whether a number is falsy.
    """
    if probe is None:
        return {"present": False, "status": "unknown", "measured": False,
                "detail": "no probe configured", "gap": "missing"}
    sample = _latest(probe.id)
    out = {
        "present": True, "probe_id": probe.id, "name": probe.name,
        "kind": probe.kind, "target": probe.target or "",
        "enabled": bool(probe.enabled), "interval_min": probe.interval_min,
        "unit": dm.NUM_UNIT.get(probe.kind, ""),
        "warn_num": probe.warn_num, "crit_num": probe.crit_num,
        "ts": sample.ts.isoformat(timespec="seconds") if sample else None,
        "age_s": _age_s(sample.ts) if sample else None,
        "value_num": sample.value_num if sample else None,
        "value2_num": sample.value2_num if sample else None,
    }
    out["stale"] = bool(sample and sample.ts
                        and datetime.utcnow() - sample.ts > STALE_AFTER)
    if not probe.enabled:
        # A disabled probe is coverage lost, not a check that passed.
        out.update({"status": "unknown", "measured": False, "gap": "disabled",
                    "detail": "probe disabled — not measured"})
    elif sample is None:
        out.update({"status": "unknown", "measured": False, "gap": "never-run",
                    "detail": "never run"})
    else:
        out.update({"status": sample.status, "measured": True,
                    "detail": sample.detail or ""})
        if out["stale"]:
            out["gap"] = "stale"
    if not out["measured"]:
        # A block that measured nothing must carry NO numbers. Without this a
        # disabled probe would keep serving its last reading — 336 Mbps from an
        # hour ago rendering exactly like 336 Mbps from a minute ago. Stale is
        # different and deliberately still `measured`: it keeps its values and
        # is labelled, because an old reading is a reading.
        out["value_num"] = None
        out["value2_num"] = None
    elif payload and sample is not None:
        out["payload"] = _load(sample.payload)
    if spark:
        out["series"] = _spark(probe.id)
    return out


def _coverage(blocks: list[dict]) -> dict:
    """What this view could NOT measure, named rather than averaged away."""
    gaps = [b for b in blocks if b.get("gap")]
    return {
        "measured": sum(1 for b in blocks if b.get("measured")),
        "total": len(blocks),
        "gaps": [{"what": b.get("label") or b.get("kind") or "probe",
                  "why": b["gap"]} for b in gaps],
    }


def _probes_for(appliance_id: int) -> list[MonitorProbe]:
    return (MonitorProbe.query
            .filter(MonitorProbe.appliance_id == appliance_id)
            .filter(MonitorProbe.kind.in_(dm.API_KINDS)).all())


def _pick(probes: list[MonitorProbe], kind: str, target: str):
    """First probe of ``kind`` whose target matches, case/space-insensitively."""
    want = (target or "").strip().lower()
    for p in probes:
        if p.kind == kind and (p.target or "").strip().lower() == want:
            return p
    return None


# ---------------------------------------------------------------------------
# device rollup
# ---------------------------------------------------------------------------

def device_rollup(appliances) -> list[dict]:
    """One traffic card per REST-capable appliance, newest sample per probe.

    ``appliances`` is whatever the caller's ADOM scope resolved to; only kinds
    in :data:`deep_monitor.API_PRODUCTS` are included, because the monitor API
    this reads is FortiWeb-only and rendering an empty FortiADC card would read
    as "no traffic" rather than "not applicable".
    """
    out = []
    for ap in appliances:
        if (ap.kind or "fortiweb") not in dm.API_PRODUCTS:
            continue
        probes = _probes_for(ap.id)
        box = _block(_pick(probes, "sessions", ""), spark=True, payload=True)
        box["label"] = "box sessions"
        total = _block(_pick(probes, "throughput", dm.TOTAL_HTTP), spark=True,
                       payload=True)
        total["label"] = "total throughput"

        policies = []
        for p in probes:
            if p.kind != "policy_sessions":
                continue
            name = (p.target or "").strip()
            if not name:
                continue
            sess = _block(p, payload=True)
            pol = (sess.get("payload") or {}).get("policy") or {}
            members = (sess.get("payload") or {}).get("members") or []
            tp = _block(_pick(probes, "throughput", name), spark=True,
                        payload=True)
            tx = _block(_pick(probes, "transactions", name))
            stats = (tp.get("payload") or {}).get("stats") or {}
            down = [m for m in members
                    if not m.get("up") or str(m.get("health", "")).lower() == "disable"]
            policies.append({
                "name": name, "probe_id": p.id,
                "status": sess["status"], "detail": sess["detail"],
                "measured": sess["measured"], "stale": sess.get("stale", False),
                "age_s": sess.get("age_s"),
                "policy_status": pol.get("status") or "",
                "protocol": pol.get("protocol") or "",
                "vserver": pol.get("vserver") or "",
                "port": pol.get("port") or "",
                "sessions": pol.get("sessions"),
                "conn_per_sec": pol.get("conn_per_sec"),
                "app_response_time": pol.get("app_response_time"),
                "backends_total": len(members),
                "backends_down": len(down),
                "throughput": {
                    "present": tp["present"], "status": tp["status"],
                    "measured": tp["measured"],
                    "avg_mbps": stats.get("avg_mbps"),
                    "peak_mbps": stats.get("peak_mbps"),
                    "series": tp.get("series") or [],
                    "probe_id": tp.get("probe_id"),
                },
                "transactions": {
                    "present": tx["present"], "status": tx["status"],
                    "measured": tx["measured"], "probe_id": tx.get("probe_id"),
                    "value_num": tx.get("value_num"),
                },
            })
        policies.sort(key=lambda r: r["name"])

        blocks = [box, total] + [
            {"label": "%s sessions" % p["name"], "measured": p["measured"],
             "gap": (None if p["measured"] else "unmeasured")}
            for p in policies]
        stats = (total.get("payload") or {}).get("stats") or {}
        out.append({
            "id": ap.id, "name": ap.name, "kind": ap.kind or "fortiweb",
            "host": ap.host, "maintenance": bool(getattr(ap, "maintenance", False)),
            "box": {k: v for k, v in box.items() if k != "payload"},
            "box_metrics": (_load_box(box)),
            "total_throughput": {
                "present": total["present"], "status": total["status"],
                "measured": total["measured"], "stale": total.get("stale", False),
                "age_s": total.get("age_s"), "detail": total["detail"],
                "probe_id": total.get("probe_id"),
                "avg_mbps": stats.get("avg_mbps"),
                "peak_mbps": stats.get("peak_mbps"),
                "last_mbps": stats.get("last_mbps"),
                "window_s": (total.get("payload") or {}).get("window_s"),
                "series": total.get("series") or [],
            },
            "policies": policies,
            "policy_count": len(policies),
            "coverage": _coverage(blocks),
        })
    out.sort(key=lambda r: r["name"].lower())
    return out


def _load_box(box: dict) -> dict:
    """cpu/mem/session counters out of a ``sessions`` probe payload."""
    return (box.get("payload") or {}).get("box") or {}


# ---------------------------------------------------------------------------
# policy detail
# ---------------------------------------------------------------------------

def policy_detail(appliance: Appliance, name: str) -> dict | None:
    """Everything stored about ONE server policy, in one object.

    Returns ``None`` when no REST-telemetry probe on this appliance targets
    ``name`` — the caller turns that into a 404. Deliberately not an empty
    skeleton: "we have no probe for this policy" and "this policy is idle" must
    not render the same.
    """
    probes = _probes_for(appliance.id)
    want = (name or "").strip().lower()
    mine = [p for p in probes if (p.target or "").strip().lower() == want]
    if not mine:
        return None

    sess = _block(_pick(mine, "policy_sessions", name), payload=True, spark=True)
    sess["label"] = "sessions & latency"
    tp = _block(_pick(mine, "throughput", name), payload=True, spark=True)
    tp["label"] = "throughput"
    tx = _block(_pick(mine, "transactions", name), payload=True, spark=True)
    tx["label"] = "transactions"

    pol = (sess.get("payload") or {}).get("policy") or {}
    members = (sess.get("payload") or {}).get("members") or []
    members_error = (sess.get("payload") or {}).get("members_error") or ""
    stats = (tp.get("payload") or {}).get("stats") or {}
    txp = tx.get("payload") or {}

    return {
        "appliance": {"id": appliance.id, "name": appliance.name,
                      "kind": appliance.kind or "fortiweb", "host": appliance.host},
        "name": name,
        "policy": pol,
        "members": members,
        "members_error": members_error,
        "backends_down": [m for m in members
                          if not m.get("up")
                          or str(m.get("health", "")).lower() == "disable"],
        "sessions": sess,
        "throughput": dict(tp, stats=stats),
        "transactions": dict(tx, buckets=(txp.get("buckets") or []),
                             total=txp.get("total")),
        "coverage": _coverage([sess, tp, tx]),
    }
