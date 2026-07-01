"""Fleet inventory metrics.

Count how many of each object type EXIST per device (from the local cache) and
record a daily snapshot so the counts can be compared across dates.

Object types:
  server_policy  -> device_server_policies
  backend        -> device_objects, pserver-list rows (real back-end servers)
  wpp            -> device_web_protection_profiles
  certificate    -> device_objects, logical_name certificate*
"""
from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy import text, func

from ..extensions import db

OBJECT_TYPES = ("server_policy", "backend", "wpp", "certificate")

_COUNT_SQL = {
    "server_policy":
        "select appliance_id, count(*) c from device_server_policies "
        "group by appliance_id",
    "backend":
        "select appliance_id, count(*) c from device_objects "
        "where subtable = 'pserver-list' group by appliance_id",
    "wpp":
        "select appliance_id, count(*) c from device_web_protection_profiles "
        "group by appliance_id",
    "certificate":
        "select appliance_id, count(distinct mkey) c from device_objects "
        "where lower(logical_name) like '%certificate%' and mkey <> '' "
        "group by appliance_id",
}


def current_counts():
    """{object_type: {appliance_id: count}} from the live cache."""
    out = {}
    for t, sql in _COUNT_SQL.items():
        rows = db.session.execute(text(sql)).all()
        out[t] = {r[0]: r[1] for r in rows}
    return out


def current_totals():
    """{object_type: fleet_total} from the live cache."""
    counts = current_counts()
    return {t: sum(counts[t].values()) for t in OBJECT_TYPES}


def record_snapshot(for_date=None):
    """Upsert the given date's per-appliance counts into inventory_snapshots.
    Idempotent per date (re-running replaces that day's rows)."""
    from ..models_cache import InventorySnapshot
    d = for_date or date.today()
    counts = current_counts()
    InventorySnapshot.query.filter_by(snapshot_date=d).delete()
    n = 0
    devices = set()
    for t in OBJECT_TYPES:
        for appliance_id, c in counts[t].items():
            db.session.add(InventorySnapshot(
                snapshot_date=d, appliance_id=appliance_id,
                object_type=t, count=c))
            devices.add(appliance_id)
            n += 1
    db.session.commit()
    return {"date": str(d), "rows": n, "appliances": len(devices),
            "totals": {t: sum(counts[t].values()) for t in OBJECT_TYPES}}


def series(d_from, d_to):
    """Per-date fleet totals for each object type, d_from..d_to inclusive.
    -> {'labels': [...], 'server_policy': [...], 'backend': [...], ...}."""
    from ..models_cache import InventorySnapshot
    rows = db.session.query(
        InventorySnapshot.snapshot_date,
        InventorySnapshot.object_type,
        func.sum(InventorySnapshot.count),
    ).filter(
        InventorySnapshot.snapshot_date >= d_from,
        InventorySnapshot.snapshot_date <= d_to,
    ).group_by(
        InventorySnapshot.snapshot_date,
        InventorySnapshot.object_type,
    ).all()

    by_day = {}
    for d, t, c in rows:
        by_day.setdefault(str(d), {})[t] = int(c or 0)

    labels = []
    cur = d_from
    while cur <= d_to:
        labels.append(str(cur))
        cur += timedelta(days=1)

    out = {"labels": labels}
    for t in OBJECT_TYPES:
        out[t] = [by_day.get(lbl, {}).get(t, 0) for lbl in labels]
    return out
