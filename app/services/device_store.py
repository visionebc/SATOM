"""Decompose a device config snapshot into the cache tables, and read it back.

Pure decomposition (``nodes_from_sections``/``flatten``) has no DB dependency
and is unit-tested directly. ``ingest_sections`` persists nodes into
``device_objects`` (replace-per-section, diff-by-content-hash for change
detection) and rebuilds the hot-type typed projections.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# --- pure decomposition -----------------------------------------------------

_MKEY_FIELDS = ("name", "mkey", "id")


def _is_subtable(v: Any) -> bool:
    """A list whose items are all dicts = a by-parent sub-table."""
    return isinstance(v, list) and len(v) > 0 and all(isinstance(x, dict) for x in v)


def _mkey_of(obj: dict) -> str:
    for k in _MKEY_FIELDS:
        val = obj.get(k)
        if val not in (None, ""):
            return str(val)
    return ""


# deep_capture nests referenced objects + by-parent sub-tables under this key
# so the decomposer can split them out into child rows (parent_id hierarchy).
DEEP_KEY = "_deep"


def split_payload(obj: dict) -> tuple[dict, dict]:
    """Split an object dict into (own scalar/simple fields, sub-tables).

    A ``_deep`` mapping (emitted by services.deep_capture) is expanded so each
    entry becomes a child sub-table: a nested object dict is wrapped as a
    one-row list; a list-of-dicts passes through. This is what lands the full
    WPP / Server-Policy graph into device_objects at depth with no schema change.
    """
    own: dict = {}
    subs: dict = {}
    for k, v in obj.items():
        if k == DEEP_KEY and isinstance(v, dict):
            for dk, dv in v.items():
                if isinstance(dv, dict):
                    subs[dk] = [dv]
                elif _is_subtable(dv):
                    subs[dk] = dv
        elif _is_subtable(v):
            subs[k] = v
        else:
            own[k] = v
    return own, subs


def content_hash(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def blob_hash(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


@dataclass
class CacheNode:
    section: str
    logical_name: str
    mkey: str
    payload: dict
    depth: int
    idx: int
    subtable: str | None = None
    children: list["CacheNode"] = field(default_factory=list)

    @property
    def content_hash(self) -> str:
        return content_hash(self.payload)


def _build_node(obj: dict, section: str, logical_name: str, depth: int,
                idx: int, subtable: str | None = None) -> CacheNode:
    own, subs = split_payload(obj)
    node = CacheNode(section=section, logical_name=logical_name,
                     mkey=_mkey_of(obj), payload=own, depth=depth, idx=idx,
                     subtable=subtable)
    for fname, rows in subs.items():
        child_logical = f"{logical_name}/{fname}"
        for j, row in enumerate(rows):
            node.children.append(
                _build_node(row, section, child_logical, depth + 1, j, subtable=fname)
            )
    return node


def nodes_from_sections(sections: dict) -> list[CacheNode]:
    """sections = {section: {logical_name: [obj, ...]}} -> root CacheNodes."""
    roots: list[CacheNode] = []
    for section, logicals in (sections or {}).items():
        if not isinstance(logicals, dict):
            continue
        for logical_name, rows in logicals.items():
            if not isinstance(rows, list):
                continue
            for i, obj in enumerate(rows):
                if isinstance(obj, dict):
                    roots.append(_build_node(obj, section, logical_name, 0, i))
    return roots


def flatten(roots: list[CacheNode]) -> list[tuple[CacheNode, int | None]]:
    """Pre-order list of (node, parent_index_in_list)."""
    out: list[tuple[CacheNode, int | None]] = []

    def walk(node: CacheNode, parent_idx: int | None) -> None:
        my_idx = len(out)
        out.append((node, parent_idx))
        for c in node.children:
            walk(c, my_idx)

    for r in roots:
        walk(r, None)
    return out


def count_nodes(roots: list[CacheNode]) -> int:
    return len(flatten(roots))


# --- typed projection extraction (pure) -------------------------------------

def _g(payload: dict, *keys: str) -> Any:
    for k in keys:
        if k in payload and payload[k] not in (None, ""):
            return payload[k]
    return None


def server_policy_row(payload: dict) -> dict:
    return {
        "name": _g(payload, "name", "mkey"),
        "deployment_mode": _g(payload, "deployment-mode", "deployment_mode"),
        "vserver": _g(payload, "vserver"),
        "server_pool": _g(payload, "server-pool", "server_pool"),
        "web_protection_profile": _g(payload, "web-protection-profile",
                                      "web_protection_profile"),
        "http_service": _g(payload, "service"),
        "https_service": _g(payload, "https-service", "https_service"),
        "monitor_mode": _g(payload, "monitor-mode", "monitor_mode"),
        "status": _g(payload, "status"),
    }


def server_pool_row(payload: dict) -> dict:
    return {
        "name": _g(payload, "name", "mkey"),
        "type": _g(payload, "type", "server-pool-type"),
        "protocol": _g(payload, "protocol"),
    }


def wpp_row(payload: dict, kind: str) -> dict:
    return {
        "name": _g(payload, "name", "mkey"),
        "kind": kind,
        "signature_rule": _g(payload, "signature-rule", "signature_rule"),
    }


# Hot-type logical-name → (projection model attr, row builder)
_SERVER_POLICY_LOGICALS = {"server_policy"}
_SERVER_POOL_LOGICALS = {"server_pool"}
_WPP_INLINE_LOGICALS = {"web_protection_profile", "webprotection_profile_inline",
                        "web_protection_profile_inline"}
_WPP_OFFLINE_LOGICALS = {"webprotection_profile_offline",
                         "web_protection_profile_offline"}


# --- persistence ------------------------------------------------------------

def ingest_sections(appliance_id: int, sections: dict, *, source: str = "live",
                    layer: str = "config", generated_at: datetime | None = None,
                    session=None) -> dict:
    """Replace-per-section ingest. Returns {section: {objects, changed}}.

    For each section: snapshot row + decompose + replace device_objects of that
    (appliance, layer, section) + rebuild typed projections. ``changed`` is
    True when the section's blob hash differs from the previous snapshot.
    """
    from ..extensions import db  # local import: pure functions stay import-light
    from ..models_cache import (DeviceObject, DeviceSnapshot,
                               DeviceServerPolicy, DeviceServerPool,
                               DeviceWebProtectionProfile)

    session = session or db.session
    generated_at = generated_at or datetime.utcnow()
    result: dict = {}

    for section, logicals in (sections or {}).items():
        if not isinstance(logicals, dict):
            continue
        bhash = blob_hash(logicals)
        prev = (session.query(DeviceSnapshot)
                .filter_by(appliance_id=appliance_id, layer=layer, section=section)
                .order_by(DeviceSnapshot.generated_at.desc())
                .first())
        changed = (prev is None) or (prev.blob_hash != bhash)

        # wipe old objects of this section
        old_ids = [r.id for r in session.query(DeviceObject.id)
                   .filter_by(appliance_id=appliance_id, layer=layer, section=section)]
        if old_ids:
            for proj in (DeviceServerPolicy, DeviceServerPool,
                         DeviceWebProtectionProfile):
                session.query(proj).filter(proj.object_id.in_(old_ids)).delete(
                    synchronize_session=False)
            session.query(DeviceObject).filter(
                DeviceObject.id.in_(old_ids)).delete(synchronize_session=False)

        snap = DeviceSnapshot(appliance_id=appliance_id, layer=layer,
                              section=section, source=source,
                              generated_at=generated_at, blob_hash=bhash)
        session.add(snap)
        session.flush()  # snap.id

        roots = nodes_from_sections({section: logicals})
        flat = flatten(roots)
        id_map: dict[int, int] = {}      # list index -> DeviceObject.id
        obj_count = 0
        projections: list[tuple] = []    # (list_idx, kind, row)
        for list_idx, (node, parent_idx) in enumerate(flat):
            row = DeviceObject(
                appliance_id=appliance_id, snapshot_id=snap.id,
                parent_id=id_map.get(parent_idx) if parent_idx is not None else None,
                layer=layer, section=section, logical_name=node.logical_name,
                mkey=node.mkey, subtable=node.subtable, payload=node.payload,
                content_hash=node.content_hash, depth=node.depth, idx=node.idx,
            )
            session.add(row)
            session.flush()
            id_map[list_idx] = row.id
            obj_count += 1
            if node.depth == 0:
                ln = node.logical_name
                if ln in _SERVER_POLICY_LOGICALS:
                    projections.append((row.id, "sp", server_policy_row(node.payload)))
                elif ln in _SERVER_POOL_LOGICALS:
                    projections.append((row.id, "pool", server_pool_row(node.payload)))
                elif ln in _WPP_INLINE_LOGICALS:
                    projections.append((row.id, "wpp", wpp_row(node.payload, "inline")))
                elif ln in _WPP_OFFLINE_LOGICALS:
                    projections.append((row.id, "wpp", wpp_row(node.payload, "offline")))

        for oid, kind, prow in projections:
            if kind == "sp":
                session.add(DeviceServerPolicy(object_id=oid, appliance_id=appliance_id, **prow))
            elif kind == "pool":
                session.add(DeviceServerPool(object_id=oid, appliance_id=appliance_id, **prow))
            elif kind == "wpp":
                session.add(DeviceWebProtectionProfile(object_id=oid, appliance_id=appliance_id, **prow))

        snap.object_count = obj_count
        result[section] = {"objects": obj_count, "changed": changed, "blob_hash": bhash}

    session.commit()
    return result


def ingest_snapshot(appliance_id: int, snapshot: dict, *, source: str = "live",
                    layer: str = "config", session=None) -> dict:
    """Ingest a full rediscovery snapshot dict ({sections, generated_at, ...})."""
    sections = snapshot.get("sections", {})
    gen = snapshot.get("generated_at")
    ga = None
    if isinstance(gen, str):
        try:
            ga = datetime.fromisoformat(gen)
        except ValueError:
            ga = None
    return ingest_sections(appliance_id, sections, source=source, layer=layer,
                           generated_at=ga, session=session)


# --- read-back --------------------------------------------------------------

def list_objects(appliance_id: int, section: str, *, logical_name: str | None = None,
                 depth: int = 0, page: int = 1, per_page: int = 100,
                 q: str | None = None, session=None):
    """Paginated read of cached objects. Returns (rows, total)."""
    from ..extensions import db
    from ..models_cache import DeviceObject
    session = session or db.session
    query = session.query(DeviceObject).filter_by(
        appliance_id=appliance_id, section=section, depth=depth)
    if logical_name:
        query = query.filter(DeviceObject.logical_name == logical_name)
    if q:
        query = query.filter(DeviceObject.mkey.ilike(f"%{q}%"))
    total = query.count()
    rows = (query.order_by(DeviceObject.logical_name, DeviceObject.idx)
            .limit(per_page).offset((page - 1) * per_page).all())
    return rows, total


def section_meta(appliance_id: int, section: str, *, layer: str = "config",
                 session=None):
    """Latest snapshot meta for a (device, section): generated_at/source/count."""
    from ..extensions import db
    from ..models_cache import DeviceSnapshot
    session = session or db.session
    return (session.query(DeviceSnapshot)
            .filter_by(appliance_id=appliance_id, layer=layer, section=section)
            .order_by(DeviceSnapshot.generated_at.desc())
            .first())


def wipe_layer(appliance_id: int, layer: str, *, session=None) -> int:
    """Atomically delete every device_object + snapshot for (appliance, layer).

    Used to replace-per-device the whole ``deep`` layer before a fresh deep
    ingest, so re-runs never accumulate stale rows. Returns objects removed.
    Projections are deleted first (FK), then objects, then snapshots.
    """
    from ..extensions import db
    from ..models_cache import (DeviceObject, DeviceSnapshot, DeviceServerPolicy,
                               DeviceServerPool, DeviceWebProtectionProfile)
    session = session or db.session
    old_ids = [r.id for r in session.query(DeviceObject.id)
               .filter_by(appliance_id=appliance_id, layer=layer)]
    if old_ids:
        for proj in (DeviceServerPolicy, DeviceServerPool,
                     DeviceWebProtectionProfile):
            session.query(proj).filter(proj.object_id.in_(old_ids)).delete(
                synchronize_session=False)
        session.query(DeviceObject).filter(DeviceObject.id.in_(old_ids)).delete(
            synchronize_session=False)
    session.query(DeviceSnapshot).filter_by(
        appliance_id=appliance_id, layer=layer).delete(synchronize_session=False)
    session.commit()
    return len(old_ids)
