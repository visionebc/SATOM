"""Phase 5 — approval diff + write-through to the local source of truth.

After a write is APPROVED and applied to the device, we keep the DB-first cache
consistent WITHOUT re-sweeping the whole device (the 2000-object problem): we
update just the affected cached object in place. We also expose a pure ``diff``
the approval modal shows before the user confirms (proposed vs the cached
before-state).

All functions are best-effort over the cache and NEVER raise into the write
path — a stale cache row just gets refreshed on the next ⟳.
"""
from __future__ import annotations

import functools

from . import device_store


def _norm_tail(urn: str) -> str:
    """The part of a urn after the cmdb/ prefix, hyphen path (match key)."""
    u = (urn or "").lstrip("/")
    if "cmdb/" in u:
        u = u.split("cmdb/", 1)[1]
    elif "/api/" in u:
        u = u.split("/", 3)[-1]
    return u.strip("/")


@functools.lru_cache(maxsize=1)
def _tail_to_logical() -> dict:
    """Reverse the registry {logical: urn} into {cmdb-tail: logical}."""
    from ..registry import loader
    out = {}
    for logical, urn in (loader.load_registry() or {}).items():
        out[_norm_tail(urn)] = logical
    return out


def logical_for_collection(coll: str) -> str | None:
    """Map an objedit collection (``server-policy/server-pool``) to the cache
    logical name (``server_pool``). Falls back to None when unknown."""
    if not coll:
        return None
    return _tail_to_logical().get(coll.strip("/"))


def _find(session, appliance_id, mkey, logical=None):
    from ..models_cache import DeviceObject
    q = (session.query(DeviceObject)
         .filter_by(appliance_id=appliance_id, depth=0, mkey=mkey))
    if logical:
        q = q.filter_by(logical_name=logical)
    return q.first()


def diff_object(appliance_id, coll, mkey, proposed, *, session=None):
    """Pure: {field: {before, after}} for fields the proposed payload changes
    vs the cached before-state. Unknown/absent cache → all proposed are 'new'."""
    from ..extensions import db
    session = session or db.session
    logical = logical_for_collection(coll)
    obj = _find(session, appliance_id, mkey, logical)
    before = (obj.payload if obj and obj.payload else {}) or {}
    changes = {}
    for k, v in (proposed or {}).items():
        old = before.get(k)
        if old != v:
            changes[k] = {"before": old, "after": v}
    return changes


def local_update(appliance_id, coll, mkey, fields, *, session=None):
    """Merge approved field changes into the cached object payload (+ recompute
    hash, refresh the typed projection). Best-effort; returns True if a row was
    updated."""
    from ..extensions import db
    session = session or db.session
    logical = logical_for_collection(coll)
    obj = _find(session, appliance_id, mkey, logical)
    if obj is None:
        return False
    payload = dict(obj.payload or {})
    payload.update(fields or {})
    obj.payload = payload
    try:
        obj.content_hash = device_store.content_hash(payload)
    except Exception:  # noqa: BLE001
        pass
    _refresh_projection(session, obj)
    session.commit()
    return True


def local_delete(appliance_id, coll, mkey, *, session=None):
    """Delete the cached object and all its descendants (by-parent rows)."""
    from ..extensions import db
    from ..models_cache import DeviceObject
    session = session or db.session
    logical = logical_for_collection(coll)
    obj = _find(session, appliance_id, mkey, logical)
    if obj is None:
        return False
    # collect the subtree (depth-first via parent_id chain)
    ids = [obj.id]
    frontier = [obj.id]
    while frontier:
        kids = (session.query(DeviceObject.id)
                .filter(DeviceObject.parent_id.in_(frontier)).all())
        kid_ids = [k[0] for k in kids]
        ids.extend(kid_ids)
        frontier = kid_ids
    (session.query(DeviceObject)
     .filter(DeviceObject.id.in_(ids)).delete(synchronize_session=False))
    session.commit()
    return True


def _refresh_projection(session, obj):
    """Keep the hot typed projection (server policy) consistent after an update."""
    from ..models_cache import DeviceServerPolicy, DeviceServerPool
    p = obj.payload or {}
    if obj.logical_name == "server_policy":
        row = session.get(DeviceServerPolicy, obj.id)
        if row is not None:
            row.deployment_mode = p.get("deployment-mode")
            row.vserver = p.get("vserver")
            row.server_pool = p.get("server-pool")
            row.web_protection_profile = p.get("web-protection-profile")
            row.status = p.get("status")
            row.monitor_mode = p.get("monitor-mode")
    elif obj.logical_name == "server_pool":
        row = session.get(DeviceServerPool, obj.id)
        if row is not None:
            row.type = p.get("type")
            row.protocol = p.get("protocol")
