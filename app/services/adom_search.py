"""ADOM Search — free-text search over the synced configuration of the
appliances in the active ADOM (``device_objects``; no device call).

Every product's ``device_sync`` lands its configuration in ``device_objects``
(layer ``config``, plus ``deep`` for FortiWeb). Searching that cache covers
FortiWeb, FortiADC, FortiGate, FortiAuthenticator and FortiAnalyzer the same
way and every collection the sync captures. The live sweep it replaces read
five hard-coded FortiWeb REST paths and sent them to every device that was
not a FortiADC, so a FortiAuthenticator RADIUS client or a FortiGate address
was never found. Results are as fresh as the last sync; each appliance carries
the time of its newest snapshot.

Secret fields never match and are never shown: a substring search over a
password or pre-shared key answers "is this character next?" and recovers it
one character at a time. A field is secret when any segment of its path looks
like one (``_SECRET_FIELD``) or its value is a FortiOS ``ENC`` blob.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

LAYERS = ("config", "deep")
RESULT_LIMIT = 500
# Rows fetched from the database before the per-field check. Bounds one search
# on a large estate; hitting it marks the result truncated.
ROW_LIMIT = 5000
VALUE_MAX = 240

# Deliberately not cli_writer.is_secret: its ``key$`` also swallows ``mkey``
# (the FortiADC object name) and ``pass`` swallows ``bypass``/``passive``.
_SECRET_FIELD = re.compile(
    r"(passw|passwd|password|secret|psk|private[-_]?key|token|credential"
    r"|^key$|[-_]key$|^pwd$|[-_]pwd$)", re.I)


def is_secret_path(path: str) -> bool:
    return any(_SECRET_FIELD.search(seg) for seg in re.split(r"[.\[\]]+", path) if seg)


def _is_enc(value: Any) -> bool:
    if isinstance(value, str):
        return value.startswith("ENC ")
    if isinstance(value, list):
        return bool(value) and value[0] == "ENC"
    return False


def flatten(payload: Any, prefix: str = ""):
    """Yield (path, text) for every scalar under *payload*, secrets dropped."""
    if isinstance(payload, dict):
        for k, v in payload.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if is_secret_path(path) or _is_enc(v):
                continue
            yield from flatten(v, path)
    elif isinstance(payload, list):
        if all(not isinstance(x, (dict, list)) for x in payload):
            text = ", ".join("" if x is None else str(x) for x in payload)
            if text:
                yield prefix, text
        else:
            for i, v in enumerate(payload):
                yield from flatten(v, f"{prefix}[{i}]")
    elif payload is not None and payload != "":
        if isinstance(payload, bool):
            yield prefix, "enable" if payload else "disable"
        else:
            yield prefix, str(payload)


@dataclass
class Hit:
    section: str
    logical: str
    obj: str
    field: str
    value: str
    at: int  # where the term starts inside ``value``


@dataclass
class Group:
    appliance: Any
    as_of: datetime | None
    hits: list[Hit] = field(default_factory=list)


@dataclass
class Result:
    groups: list[Group] = field(default_factory=list)
    not_synced: list[Any] = field(default_factory=list)
    truncated: bool = False

    @property
    def total(self) -> int:
        return sum(len(g.hits) for g in self.groups)


def _prefilter(needle: str) -> str:
    """The part of *needle* that survives JSON text encoding unchanged.

    The SQL pre-filter matches the payload's JSON text, where ``"`` and ``\\``
    are escaped; matching the whole term there would miss such values. The
    exact check runs per field afterwards."""
    parts = [p for p in re.split(r'["\\]', needle) if p]
    return max(parts, key=len) if parts else ""


def synced_at(appliance_ids: list[int], session=None) -> dict[int, datetime]:
    from sqlalchemy import func
    from ..extensions import db
    from ..models_cache import DeviceSnapshot
    session = session or db.session
    if not appliance_ids:
        return {}
    rows = (session.query(DeviceSnapshot.appliance_id,
                          func.max(DeviceSnapshot.generated_at))
            .filter(DeviceSnapshot.appliance_id.in_(appliance_ids),
                    DeviceSnapshot.layer.in_(LAYERS))
            .group_by(DeviceSnapshot.appliance_id).all())
    return {aid: at for aid, at in rows}


def sections_for(appliance_ids: list[int], session=None) -> list[str]:
    """Sections the ADOM's appliances actually have in the cache."""
    from ..extensions import db
    from ..models_cache import DeviceObject
    session = session or db.session
    if not appliance_ids:
        return []
    rows = (session.query(DeviceObject.section)
            .filter(DeviceObject.appliance_id.in_(appliance_ids),
                    DeviceObject.layer.in_(LAYERS))
            .distinct().all())
    return sorted({r[0] for r in rows if r[0]}, key=str.lower)


def _roots(rows, session) -> dict[int, str]:
    """object id -> name of its top-level ancestor (for sub-table hits)."""
    from ..models_cache import DeviceObject
    names: dict[int, tuple[int | None, str]] = {
        r.id: (r.parent_id, r.mkey or "") for r in rows}
    want = {p for p, _ in names.values() if p and p not in names}
    while want:
        found = (session.query(DeviceObject.id, DeviceObject.parent_id,
                               DeviceObject.mkey)
                 .filter(DeviceObject.id.in_(want)).all())
        for oid, pid, mkey in found:
            names[oid] = (pid, mkey or "")
        want = {pid for _, pid, _ in found if pid and pid not in names}
        if not found:
            break

    def root(oid):
        seen = set()
        while oid in names and names[oid][0] and oid not in seen:
            seen.add(oid)
            oid = names[oid][0]
        return names.get(oid, (None, ""))[1]

    return {r.id: root(r.id) for r in rows if r.parent_id}


def search(term: str, appliances: list, *, section: str | None = None,
           session=None) -> Result:
    """Case-insensitive substring search over *appliances*' synced config."""
    from sqlalchemy import Text, cast, func, or_
    from ..extensions import db
    from ..models_cache import DeviceObject
    session = session or db.session
    needle = (term or "").strip().lower()
    result = Result()
    if not needle or not appliances:
        return result

    ids = [a.id for a in appliances]
    as_of = synced_at(ids, session)
    result.not_synced = [a for a in appliances if a.id not in as_of]
    synced = [a for a in appliances if a.id in as_of]
    if not synced:
        return result

    q = session.query(DeviceObject).filter(
        DeviceObject.appliance_id.in_([a.id for a in synced]),
        DeviceObject.layer.in_(LAYERS))
    if section:
        q = q.filter(DeviceObject.section == section)
    pre = _prefilter(needle)
    if pre:
        q = q.filter(or_(
            func.lower(cast(DeviceObject.payload, Text)).contains(pre, autoescape=True),
            func.lower(DeviceObject.mkey).contains(pre, autoescape=True)))
    rows = (q.order_by(DeviceObject.appliance_id, DeviceObject.section,
                       DeviceObject.logical_name, DeviceObject.depth,
                       DeviceObject.idx)
            .limit(ROW_LIMIT + 1).all())
    if len(rows) > ROW_LIMIT:
        rows = rows[:ROW_LIMIT]
        result.truncated = True
    roots = _roots(rows, session)

    groups = {a.id: Group(appliance=a, as_of=as_of[a.id]) for a in synced}
    seen: set = set()
    count = 0
    for r in rows:
        name = r.mkey or ""
        obj = f"{roots[r.id]} › {name}" if r.id in roots and roots[r.id] else name
        for path, text in flatten(r.payload or {}):
            at = text.lower().find(needle)
            if at < 0:
                continue
            key = (r.appliance_id, r.section, r.logical_name, obj, path, text)
            if key in seen:  # FortiWeb objects sit in both layers
                continue
            seen.add(key)
            if count >= RESULT_LIMIT:
                result.truncated = True
                break
            if len(text) > VALUE_MAX:
                start = max(0, min(at - 40, len(text) - VALUE_MAX))
                text = text[start:start + VALUE_MAX]
                at -= start
            groups[r.appliance_id].hits.append(Hit(
                section=r.section, logical=r.logical_name, obj=obj,
                field=path, value=text, at=at))
            count += 1
        if count >= RESULT_LIMIT and result.truncated:
            break
    result.groups = [g for g in groups.values() if g.hits]
    return result
