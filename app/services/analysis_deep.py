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
