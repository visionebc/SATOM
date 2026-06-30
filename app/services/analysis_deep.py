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


def deep_objects(device_ids=None, logical_name: str = _WPP_LOGICAL) -> list[dict]:
    """Depth-0 deep objects of a type (WPPs or server policies) with their device
    — drives the drill-down picker. ``{appliance_id, device, mkey}``."""
    from ..models import Appliance
    names = {a.id: a.name for a in Appliance.query.all()}
    q = DeviceObject.query.filter_by(layer="deep", depth=0, logical_name=logical_name)
    if device_ids:
        q = q.filter(DeviceObject.appliance_id.in_(list(device_ids)))
    q = q.order_by(DeviceObject.appliance_id, DeviceObject.mkey)
    return [{"appliance_id": o.appliance_id,
             "device": names.get(o.appliance_id, str(o.appliance_id)),
             "mkey": o.mkey} for o in q.all()]


# --- Fleet inventory (cardinality) -----------------------------------------
_BACKEND_LN = "server_policy/server_pool/pserver-list"
_POOL_LN = "server_policy/server_pool"
_VIP_LN = "server_policy/vserver/vip-list"
_SNI_LN = "certificate_sni"
_CERT_LN = "certificate"


def _scope(q, device_ids):
    return q.filter(DeviceObject.appliance_id.in_(list(device_ids))) if device_ids else q


def fleet_inventory(device_ids=None) -> dict:
    """The cardinality an operator asks first: how many server policies, how many
    DISTINCT server pools (and which are unique vs shared), how many back-end real
    servers and on what ports, how many VIPs, SNI policies and certificates. All
    over the deep cache (every device); bounded queries (the leaf real-server set
    is naturally small); never a live box."""
    from ..models import Appliance
    names = {a.id: a.name for a in Appliance.query.all()}

    def total(ln, depth=None):
        q = _scope(DeviceObject.query.filter_by(layer="deep", logical_name=ln), device_ids)
        if depth is not None:
            q = q.filter_by(depth=depth)
        return q.count()

    def per_dev(ln, depth=None):
        q = (db.session.query(DeviceObject.appliance_id, func.count())
             .filter(DeviceObject.layer == "deep", DeviceObject.logical_name == ln))
        if depth is not None:
            q = q.filter(DeviceObject.depth == depth)
        q = _scope(q, device_ids).group_by(DeviceObject.appliance_id)
        return {aid: int(n) for aid, n in q.all()}

    n_policies = total("server_policy", depth=0)
    n_vips = total(_VIP_LN)
    n_sni = total(_SNI_LN, depth=0)
    n_certs = total(_CERT_LN, depth=0)

    # Server pools: each policy nests its bound pool, so dedup by (device, name).
    pool_rows = _scope(db.session.query(DeviceObject.appliance_id, DeviceObject.mkey)
                       .filter(DeviceObject.layer == "deep",
                               DeviceObject.logical_name == _POOL_LN), device_ids).all()
    pool_use: dict = {}
    for aid, mk in pool_rows:
        pool_use[(aid, mk)] = pool_use.get((aid, mk), 0) + 1
    distinct_pools = len(pool_use)
    unique_pools = sum(1 for c in pool_use.values() if c == 1)

    # Back-ends (real servers) + port histogram, from the small leaf set.
    be_rows = _scope(db.session.query(DeviceObject.appliance_id, DeviceObject.payload)
                     .filter(DeviceObject.layer == "deep",
                             DeviceObject.logical_name == _BACKEND_LN), device_ids).all()
    ports: dict = {}
    ips: set = set()
    d_be: dict = {}
    for aid, pay in be_rows:
        pay = pay or {}
        p = pay.get("port") or pay.get("https-port") or pay.get("http-port")
        if p not in (None, "", 0, "0"):
            ports[str(p)] = ports.get(str(p), 0) + 1
        ip = pay.get("ip")
        if ip:
            ips.add((aid, str(ip)))
        d_be[aid] = d_be.get(aid, 0) + 1
    port_list = sorted(({"port": k, "count": v} for k, v in ports.items()),
                       key=lambda r: r["count"], reverse=True)

    d_pol = per_dev("server_policy", 0)
    d_sni = per_dev(_SNI_LN, 0)
    d_cert = per_dev(_CERT_LN, 0)
    d_pool: dict = {}
    for (aid, _mk) in pool_use:
        d_pool[aid] = d_pool.get(aid, 0) + 1

    all_dev = set(d_pol) | set(d_be) | set(d_sni) | set(d_cert) | set(d_pool)
    per_device = [{
        "appliance_id": aid, "device": names.get(aid, str(aid)),
        "policies": d_pol.get(aid, 0), "pools": d_pool.get(aid, 0),
        "backends": d_be.get(aid, 0), "sni": d_sni.get(aid, 0),
        "certificates": d_cert.get(aid, 0),
    } for aid in sorted(all_dev)]

    return {
        "totals": {
            "server_policies": n_policies,
            "server_pools": {"distinct": distinct_pools, "unique": unique_pools,
                             "shared": distinct_pools - unique_pools,
                             "references": len(pool_rows)},
            "backends": {"count": len(be_rows), "distinct_ips": len(ips)},
            "vips": n_vips, "sni": n_sni, "certificates": n_certs,
        },
        "ports": port_list,
        "per_device": per_device,
    }
