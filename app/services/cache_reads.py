"""Answer a read from SATOM's device cache instead of from the device.

The API used to read FortiADC rules from the appliance on every call: a
hundred integrations polling one table opened a hundred sessions to one box,
and a box that is slow, locked or licence-expired made every caller wait or
fail. The hourly sweep already holds the same rows (``device_objects``); this
module serves them, and says how old they are, so the caller decides whether
that is fresh enough.

A cache read has three outcomes, and none of them guesses:

* ``ok``       -- the last good sweep read the table (``DeviceCoverage``):
                  its rows, possibly none. ``as_of`` is that sweep.
* ``failed``   -- the last sweep asked and the device refused this table:
                  whatever an older sweep cached is NOT presented as current.
* ``unknown``  -- the table was never swept on this device (new appliance,
                  a build that does not serve it, a sweep from before coverage
                  was recorded). The caller may read live.

``stale`` is set when the cache cannot be trusted to be recent: the newest
sync of the device failed, or ``as_of`` is older than the Monitoring
staleness threshold (``device_health.stale_hours``). The rows are still
returned -- an operator can act on yesterday's list -- but never silently.
"""
from __future__ import annotations

from datetime import datetime


def _tree(appliance_id: int, logical: str, session) -> list[dict]:
    """The cached top-level objects of *logical*, sub-tables re-nested."""
    from ..models_cache import DeviceObject
    roots = (session.query(DeviceObject)
             .filter_by(appliance_id=appliance_id, logical_name=logical,
                        depth=0, layer="config")
             .order_by(DeviceObject.idx, DeviceObject.id).all())
    if not roots:
        return []
    out: dict[int, dict] = {}
    order: list[int] = []
    for r in roots:
        out[r.id] = dict(r.payload or {})
        order.append(r.id)
    frontier = list(out)
    while frontier:
        kids = (session.query(DeviceObject)
                .filter(DeviceObject.parent_id.in_(frontier))
                .order_by(DeviceObject.idx, DeviceObject.id).all())
        nxt = []
        for k in kids:
            parent = out.get(k.parent_id)
            if parent is None:
                continue
            row = dict(k.payload or {})
            out[k.id] = row
            parent.setdefault(k.subtable or "children", []).append(row)
            nxt.append(k.id)
        frontier = nxt
    return [out[i] for i in order]


def freshness(appliance_id: int, as_of: datetime | None, *, product: str = "",
              session=None) -> dict:
    """``{stale, reason, sync_failing_since}`` for a cache taken at *as_of*."""
    from ..extensions import db
    from ..models_cache import SyncRun
    from . import device_health
    session = session or db.session
    out = {"stale": False, "reason": "", "sync_failing_since": None}
    try:
        runs = (session.query(SyncRun)
                .filter(SyncRun.appliance_id == appliance_id,
                        SyncRun.status.in_(("ok", "error")))
                .order_by(SyncRun.started_at.desc()).limit(48).all())
    except Exception:  # noqa: BLE001
        session.rollback()
        runs = []
    if runs and runs[0].status == "error":
        since = runs[0].started_at
        for r in runs:
            if r.status != "error":
                break
            since = r.started_at
        out.update(stale=True, sync_failing_since=since.isoformat() + "Z",
                   reason=("the device's sync has been failing since "
                           f"{since:%Y-%m-%d %H:%M} UTC: "
                           + ((runs[0].detail or "").splitlines() or [""])[0][:160]))
        return out
    if as_of is not None:
        try:
            hours = float(device_health.stale_hours(product))
        except Exception:  # noqa: BLE001
            hours = device_health.DEFAULT_STALE_HOURS
        age_h = (datetime.utcnow() - as_of).total_seconds() / 3600.0
        if age_h > hours:
            out.update(stale=True,
                       reason=f"the cache is {age_h:.1f} h old (threshold {hours:g} h)")
    return out


def read_table(appliance, logical: str, *, session=None) -> dict:
    """``{status, rows, as_of, stale, reason, sync_failing_since, error}``."""
    from ..extensions import db
    from .device_sync import coverage_for
    session = session or db.session
    aid = appliance.id
    cov = coverage_for(aid, session=session)
    base = {"rows": [], "as_of": None, "stale": False, "reason": "",
            "sync_failing_since": None, "error": ""}
    if cov is None:
        return {**base, "status": "unknown",
                "reason": "this device has not been swept with coverage yet"}
    as_of = cov.swept_at
    fresh = freshness(aid, as_of, product=appliance.kind or "", session=session)
    stamp = as_of.isoformat() + "Z" if as_of else None
    if logical in (cov.failed or {}):
        return {**base, **fresh, "status": "failed", "as_of": stamp,
                "error": str((cov.failed or {}).get(logical) or "")}
    if logical not in (cov.tables or {}):
        return {**base, **fresh, "status": "unknown", "as_of": stamp,
                "reason": (f"the last sweep of this device ({cov.build or 'unknown build'}) "
                           f"did not read '{logical}'")}
    return {**base, **fresh, "status": "ok", "as_of": stamp,
            "rows": _tree(aid, logical, session)}
