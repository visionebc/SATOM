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

from . import device_store


def _norm_tail(urn: str) -> str:
    """The part of a urn after the cmdb/ prefix, hyphen path (match key)."""
    u = (urn or "").lstrip("/")
    if "cmdb/" in u:
        u = u.split("cmdb/", 1)[1]
    elif "/api/" in u:
        u = u.split("/", 3)[-1]
    return u.strip("/")


def _tail_to_logical(version: str = "") -> dict:
    """Reverse the registry {logical: urn} into {cmdb-tail: logical}.

    ``version`` is the box's build (``loader.registry_for``; empty → the pure
    registry). Not memoised here: the loader already caches the map with its
    TTL, and a process-lifetime memo never saw a registry edit.
    """
    from ..registry import loader
    out = {}
    for logical, urn in (loader.registry_for("fortiweb", version) or {}).items():
        out[_norm_tail(urn)] = logical
    return out


def _version_for(session, appliance_id) -> str:
    """The build the cached appliance runs, ``""`` when unknown."""
    if appliance_id is None:
        return ""
    try:
        from ..models import Appliance
        from ..registry import loader
        return loader.version_of(session.get(Appliance, appliance_id))
    except Exception:  # noqa: BLE001 — best-effort, like the rest of this module
        return ""


def logical_for_collection(coll: str, version: str = "") -> str | None:
    """Map an objedit collection (``server-policy/server-pool``) to the cache
    logical name (``server_pool``) for a box on ``version``. Falls back to
    None when unknown."""
    if not coll:
        return None
    return _tail_to_logical(version).get(coll.strip("/"))


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
    logical = logical_for_collection(coll, _version_for(session, appliance_id))
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
    hash, refresh the typed projection) of EVERY cached layer that holds the
    object (config, deep…): the readers pick one layer, so updating only the
    first row found could leave the page on the old value. Best-effort;
    returns True if a row was updated."""
    from ..extensions import db
    session = session or db.session
    logical = logical_for_collection(coll, _version_for(session, appliance_id))
    if logical:
        return local_refresh(appliance_id, logical, mkey, dict(fields or {}),
                             session=session) > 0
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


def local_refresh(appliance_id, logical, mkey, payload, *, session=None) -> int:
    """Merge a fresh device read of one top-level object into EVERY cached
    layer that holds it (config, deep…): the readers pick one layer, so
    updating only the first row found can leave the page on the old value.
    Keys the read did not return are kept. Returns the rows updated."""
    from ..extensions import db
    from ..models_cache import DeviceObject
    session = session or db.session
    if not isinstance(payload, dict) or not payload:
        return 0
    rows = (session.query(DeviceObject)
            .filter_by(appliance_id=appliance_id, logical_name=logical,
                       mkey=str(mkey), depth=0).all())
    for obj in rows:
        merged = {**(obj.payload or {}), **payload}   # new dict: the JSON column sees it
        obj.payload = merged
        try:
            obj.content_hash = device_store.content_hash(merged)
        except Exception:  # noqa: BLE001
            pass
        _refresh_projection(session, obj)
    if rows:
        session.commit()
    return len(rows)


def local_subrows(appliance_id, logical, mkey, subtable, rows, *, session=None) -> int | None:
    """Replace the cached rows of ONE sub-table of a deep-captured object with
    a fresh device read of that sub-table (``rows``: the whole list, so a row
    the device no longer has is dropped and a new one is added). Rows match on
    ``id``. Returns the rows now cached, or None when the object has no deep
    capture (its sub-tables are unknown, not empty) or a new row cannot be
    placed (no sibling row to copy the cache identity from)."""
    from ..extensions import db
    from ..models_cache import DeviceObject
    session = session or db.session
    if not isinstance(rows, list):
        return None
    root = (session.query(DeviceObject)
            .filter_by(appliance_id=appliance_id, logical_name=logical, mkey=str(mkey),
                       depth=0, layer="deep").first())
    if root is None:
        return None
    kids = (session.query(DeviceObject)
            .filter_by(parent_id=root.id, subtable=subtable).order_by(DeviceObject.idx).all())
    by_id = {str((k.payload or {}).get("id")): k for k in kids}
    proto = kids[0] if kids else None
    fresh = [r for r in rows if isinstance(r, dict)]
    if proto is None and fresh:
        return None
    seen = set()
    for i, r in enumerate(fresh):
        rid = str(r.get("id"))
        seen.add(rid)
        row = by_id.get(rid)
        if row is None:
            row = DeviceObject(appliance_id=appliance_id, snapshot_id=proto.snapshot_id,
                               parent_id=root.id, layer=proto.layer, section=proto.section,
                               logical_name=proto.logical_name, urn=proto.urn,
                               subtable=subtable, depth=proto.depth)
            session.add(row)
            row.mkey = rid if proto.mkey not in (None, "") else None
        row.payload = dict(r)
        row.idx = i
        try:
            row.content_hash = device_store.content_hash(row.payload)
        except Exception:  # noqa: BLE001
            pass
    for rid, k in by_id.items():
        if rid not in seen:
            session.delete(k)
    session.commit()
    return len(fresh)


def local_insert(appliance_id, logical, mkey, payload, *, session=None) -> bool:
    """Cache a top-level object just created on the device (config layer),
    with the cache identity (section, urn, snapshot) of a sibling of the same
    type. False when there is no sibling to copy it from or it is already
    cached (then :func:`local_refresh` applies)."""
    from ..extensions import db
    from ..models_cache import DeviceObject
    session = session or db.session
    if not isinstance(payload, dict) or not payload:
        return False
    if _find(session, appliance_id, str(mkey), logical) is not None:
        return local_refresh(appliance_id, logical, mkey, payload, session=session) > 0
    sib = (session.query(DeviceObject)
           .filter_by(appliance_id=appliance_id, logical_name=logical, depth=0,
                      layer="config").first())
    if sib is None:
        return False
    obj = DeviceObject(appliance_id=appliance_id, snapshot_id=sib.snapshot_id, parent_id=None,
                       layer="config", section=sib.section, logical_name=logical, urn=sib.urn,
                       mkey=str(mkey), payload=dict(payload), depth=0,
                       idx=(session.query(DeviceObject)
                            .filter_by(appliance_id=appliance_id, logical_name=logical,
                                       depth=0, layer="config").count()))
    try:
        obj.content_hash = device_store.content_hash(obj.payload)
    except Exception:  # noqa: BLE001
        pass
    session.add(obj)
    session.flush()
    _refresh_projection(session, obj)
    session.commit()
    return True


def local_delete(appliance_id, coll, mkey, *, session=None):
    """Delete the cached object and all its descendants (by-parent rows)."""
    from ..extensions import db
    from ..models_cache import DeviceObject
    session = session or db.session
    logical = logical_for_collection(coll, _version_for(session, appliance_id))
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
