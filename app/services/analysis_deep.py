"""SQL aggregations over the DEEP layer of the device cache (the full WPP subtree
+ Server-Policy dependency graph captured by services.deep_capture). Reads only
the local cache — never a live box. Every aggregate is a GROUP BY / filtered
count / indexed lookup over ``device_objects``, never a load-all-into-Python
pass, so it scales to a 100-device fleet.

Returns plain JSON-serialisable dicts/lists for the Analysis dashboard.
"""
from __future__ import annotations

from sqlalchemy import func

from ..extensions import db
from ..models_cache import DeviceObject
from ..registry.dependencies import WEB_PROTECTION_PROFILE

# Values that mean "nothing referenced" (mirrors clone._EMPTY_REFS).
_EMPTY = {"", "0", "disable", "enable", "none", "None"}
_EMPTY_STR = {str(x) for x in _EMPTY} | {"None"}

_WPP_LOGICAL = "web_protection_profile"


def wpp_feature_fields() -> list[dict]:
    """The WPP sub-policy reference fields (the GUI dropdowns), derived from the
    dependency tree's named-ref children — no hardcoding. Each is one protection
    feature: ``{field (wire), label (GUI name)}``."""
    out: list[dict] = []
    seen: set[str] = set()
    for child in WEB_PROTECTION_PROFILE.children:
        via = (getattr(child, "via", "") or "").strip()
        if not via or "=" in via or via in seen:
            continue
        seen.add(via)
        out.append({"field": via, "label": getattr(child, "fortiweb", via) or via})
    return out


def _wpp_query(device_ids=None):
    q = DeviceObject.query.filter_by(layer="deep", depth=0, logical_name=_WPP_LOGICAL)
    if device_ids:
        q = q.filter(DeviceObject.appliance_id.in_(list(device_ids)))
    return q


def wpp_feature_matrix(device_ids=None) -> list[dict]:
    """Per WPP-feature: how many fleet WPPs bind it vs total WPPs (the
    feature-coverage matrix). One pass over the depth-0 WPP rows."""
    wpps = _wpp_query(device_ids).all()
    total = len(wpps)
    rows: list[dict] = []
    for feat in wpp_feature_fields():
        field = feat["field"]
        bound = 0
        for w in wpps:
            val = (w.payload or {}).get(field)
            if str(val) not in _EMPTY_STR:
                bound += 1
        rows.append({"field": field, "label": feat["label"],
                     "bound": bound, "total": total})
    rows.sort(key=lambda r: r["bound"], reverse=True)
    return rows


def subelement_counts(device_ids=None) -> list[dict]:
    """Fleet-wide GROUP BY: row count per deep logical_name at depth>0 — the
    sub-elements (pool members, rule-list rows, disabled signatures, exception
    entries…). Ordered by count desc. Pure SQL aggregation."""
    q = (db.session.query(DeviceObject.logical_name, func.count(DeviceObject.id))
         .filter(DeviceObject.layer == "deep", DeviceObject.depth > 0))
    if device_ids:
        q = q.filter(DeviceObject.appliance_id.in_(list(device_ids)))
    q = q.group_by(DeviceObject.logical_name).order_by(func.count(DeviceObject.id).desc())
    return [{"logical_name": ln, "count": int(n)} for ln, n in q.all()]


def _node_tree(obj: DeviceObject) -> dict:
    """A depth-0 object as a nested {…, children:[…]} tree (recurses parent_id)."""
    children = (db.session.query(DeviceObject)
                .filter_by(parent_id=obj.id)
                .order_by(DeviceObject.idx).all())
    return {
        "id": obj.id, "logical_name": obj.logical_name, "mkey": obj.mkey,
        "subtable": obj.subtable, "depth": obj.depth, "payload": obj.payload or {},
        "children": [_node_tree(c) for c in children],
    }


def _drilldown(appliance_id: int, logical_name: str, mkey: str) -> dict | None:
    root = (db.session.query(DeviceObject)
            .filter_by(appliance_id=appliance_id, layer="deep", depth=0,
                       logical_name=logical_name, mkey=mkey).first())
    return _node_tree(root) if root else None


def wpp_drilldown(appliance_id: int, mkey: str) -> dict | None:
    """The full nested sub-tree for one WPP (sub-policies + their rows)."""
    return _drilldown(appliance_id, _WPP_LOGICAL, mkey)


def server_policy_drilldown(appliance_id: int, mkey: str) -> dict | None:
    """The full nested dependency graph for one server policy."""
    return _drilldown(appliance_id, "server_policy", mkey)


def orphan_objects(device_ids=None) -> list[dict]:
    """Deep depth-0 WPPs that NO server policy binds (defined-but-unused). A WPP
    is reusable/shared, so an unbound one is dead weight worth surfacing."""
    from ..models_cache import DeviceServerPolicy
    refq = db.session.query(DeviceServerPolicy.web_protection_profile)
    if device_ids:
        refq = refq.filter(DeviceServerPolicy.appliance_id.in_(list(device_ids)))
    referenced = {str(v) for (v,) in refq.all() if v}
    out: list[dict] = []
    for w in _wpp_query(device_ids).all():
        if str(w.mkey) not in referenced:
            out.append({"appliance_id": w.appliance_id,
                        "logical_name": w.logical_name, "mkey": w.mkey,
                        "kind": "web_protection_profile"})
    return out
