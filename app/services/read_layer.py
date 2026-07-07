"""DB-first read layer — the source of truth serves the UI; the box is touched
only on an explicit refresh (⟳). Centralises cached reads so views stop calling
the appliance on every page load (the 2000-policy problem).
"""
from __future__ import annotations

from datetime import datetime


def read_objects(appliance_id: int, logical_name: str, *, q: str | None = None,
                 page: int = 1, per_page: int = 10000, session=None):
    """Return (payloads, meta) for the top-level objects of a logical type.

    payloads keep the raw FortiWeb shape (hyphenated keys) so existing templates
    render unchanged. meta carries freshness: generated_at / source / total.
    """
    from ..extensions import db
    from ..models_cache import DeviceObject, DeviceSnapshot
    session = session or db.session

    query = session.query(DeviceObject).filter_by(
        appliance_id=appliance_id, logical_name=logical_name, depth=0)
    # A logical type can live in several layers at once (config = flat
    # snapshot, deep = per-policy tree roots). Each carries the SAME depth-0
    # objects, so listing across layers duplicates every row. Read from ONE
    # layer -- the most authoritative present -- as the detail readers do.
    present = [r[0] for r in query.with_entities(DeviceObject.layer).distinct()]
    for _pref in ("config", "deep", "inventory", "report"):
        if _pref in present:
            query = query.filter(DeviceObject.layer == _pref)
            break
    if q:
        query = query.filter(DeviceObject.mkey.ilike(f"%{q}%"))
    total = query.count()
    rows = (query.order_by(DeviceObject.idx)
            .limit(per_page).offset((page - 1) * per_page).all())
    payloads = [r.payload or {} for r in rows]

    section = rows[0].section if rows else None
    snap = None
    if section:
        snap = (session.query(DeviceSnapshot)
                .filter_by(appliance_id=appliance_id, section=section)
                .order_by(DeviceSnapshot.generated_at.desc()).first())
    meta = {
        "total": total,
        "count": len(payloads),
        "generated_at": snap.generated_at if snap else None,
        "source": snap.source if snap else None,
        "section": section,
        "cached": bool(rows),
    }
    return payloads, meta


def read_policies(appliance, *, q: str | None = None, session=None):
    """Server policies for the Server Policy page (DB-first)."""
    return read_objects(appliance.id, "server_policy", q=q, session=session)


# --- registry collection → logical-name reverse map (shared, TTL-cached) -----
_coll_logicals_cache: dict = {"built": None, "map": {}}


def registry_logicals(coll) -> list:
    """Registry logical names whose urn resolves to this cmdb collection."""
    import time
    from ..registry import loader
    from . import objform
    now = time.monotonic()
    built = _coll_logicals_cache["built"]
    if built is None or now - built > 300:
        rev: dict = {}
        for e in loader.get_all_endpoints():
            try:
                rev.setdefault(objform.collection_of(e["urn"]), []).append(e["name"])
            except Exception:  # noqa: BLE001
                continue
        _coll_logicals_cache["map"] = rev
        _coll_logicals_cache["built"] = now
    from . import objform as _of
    return list(_coll_logicals_cache["map"].get(_of.collection_of(coll), []))


def cached_ref_names(appliance_id: int, endpoint: str, *, session=None) -> list:
    """DB fallback for a reference dropdown: the cached object names of a
    (possibly multi-source ``a|b``) cmdb collection. Covers the config layer
    (top-level sweep) AND deep-capture nested nodes (path logical names), so
    dropdowns populate even when the box is offline or license-locked."""
    from ..extensions import db
    from ..models_cache import DeviceObject
    session = session or db.session
    names: list = []
    for coll in (endpoint or "").split("|"):
        coll = coll.strip()
        if not coll:
            continue
        for ln in registry_logicals(coll):
            q = (session.query(DeviceObject.mkey)
                 .filter(DeviceObject.appliance_id == appliance_id,
                         db.or_(DeviceObject.logical_name == ln,
                                DeviceObject.logical_name.like("%/" + ln)))
                 .distinct())
            for (mk,) in q.all():
                if mk and mk not in names:
                    names.append(mk)
    return sorted(names)


def freshness_label(meta: dict) -> str:
    """Human 'DB · hace 3 h' style label for a freshness badge."""
    ga = meta.get("generated_at")
    if not ga:
        return "no local data — refresh"
    if isinstance(ga, str):
        try:
            ga = datetime.fromisoformat(ga)
        except ValueError:
            return "DB"
    delta = datetime.utcnow() - ga
    secs = int(delta.total_seconds())
    if secs < 60:
        ago = "just now"
    elif secs < 3600:
        ago = f"{secs // 60} min ago"
    elif secs < 86400:
        ago = f"{secs // 3600} h ago"
    else:
        ago = f"{secs // 86400} d ago"
    src = meta.get("source") or "DB"
    return f"DB · {ago}" + (f" · {src}" if src and src != "DB" else "")


# --- composite cached readers (the detail-page holdouts) ---------------------

def _layer_meta(appliance_id: int, *, layer: str, section: str | None = None,
                session=None) -> dict:
    """Freshness meta for a (device, layer[, section])."""
    from ..extensions import db
    from ..models_cache import DeviceSnapshot
    session = session or db.session
    q = session.query(DeviceSnapshot).filter_by(appliance_id=appliance_id, layer=layer)
    if section:
        q = q.filter_by(section=section)
    snap = q.order_by(DeviceSnapshot.generated_at.desc()).first()
    return {
        "generated_at": snap.generated_at if snap else None,
        "source": snap.source if snap else None,
        "layer": layer,
        "cached": snap is not None,
    }


def object_by_mkey(appliance_id: int, logical_name: str, mkey: str, *,
                   layer: str = "config", session=None):
    """One cached top-level object row (or None)."""
    from ..extensions import db
    from ..models_cache import DeviceObject
    session = session or db.session
    return (session.query(DeviceObject)
            .filter_by(appliance_id=appliance_id, layer=layer,
                       logical_name=logical_name, mkey=str(mkey), depth=0)
            .first())


def _children(row, *, subtable: str | None = None, session=None):
    """Direct children of a cached object row, in ingest order."""
    from ..extensions import db
    from ..models_cache import DeviceObject
    session = session or db.session
    q = session.query(DeviceObject).filter_by(parent_id=row.id)
    if subtable:
        q = q.filter_by(subtable=subtable)
    return q.order_by(DeviceObject.idx).all()


def first_cached_logical(appliance_id: int, logicals, *, session=None):
    """First logical name (given order) that has cached top-level objects —
    the DB replacement for the live first-loaded-type probe."""
    from ..extensions import db
    from ..models_cache import DeviceObject
    session = session or db.session
    for ln in logicals:
        hit = (session.query(DeviceObject.id)
               .filter_by(appliance_id=appliance_id, logical_name=ln, depth=0)
               .first())
        if hit:
            return ln
    return None


def has_any_cache(appliance_id: int, *, session=None) -> bool:
    from ..extensions import db
    from ..models_cache import DeviceObject
    session = session or db.session
    return (session.query(DeviceObject.id)
            .filter_by(appliance_id=appliance_id).first()) is not None


def _resolve_vips_cached(appliance_id: int, vip_rows, vip_children, *, session=None):
    """Mirror FortiWebClient._resolve_vip_ips over cached rows; a cached
    system/vip child upgrades the static case from name to the real IP."""
    ip_by_name = {}
    for c in vip_children:
        p = c.payload or {}
        if p.get("name"):
            ip_by_name[p["name"]] = p.get("vip") or ""
    for v in vip_rows:
        use_if = str(v.get("use-interface-ip", "")).lower() in (
            "enable", "enabled", "1", "true")
        if use_if and v.get("interface"):
            iface = object_by_mkey(appliance_id, "interface", v["interface"],
                                   session=session)
            ip = (iface.payload or {}).get("ip") if iface else ""
            v["effective_ip"] = ip or ""
            v["ip_source"] = "interface (%s)" % v["interface"]
        elif v.get("vip"):
            v["effective_ip"] = ip_by_name.get(v["vip"]) or v["vip"]
            v["ip_source"] = "static"
        else:
            v["effective_ip"] = ""
            v["ip_source"] = ""
    return vip_rows


def policy_full_cached(appliance_id: int, name: str, *, session=None):
    """Reassemble ``FortiWebClient.policy_full``'s shape from the cache.

    Prefers the ``deep`` layer (the full per-policy tree: vserver + vip-list,
    pool + pserver-list, WPP); falls back to the ``config`` layer (top-level
    payloads only). Returns ``(data, cr_entries, meta)``; ``data`` is None when
    the policy isn't cached at all (caller falls back to a live read).
    """
    root = object_by_mkey(appliance_id, "server_policy", name, layer="deep",
                          session=session)
    if root is not None:
        data = {"policy": dict(root.payload or {})}
        cr_entries = []
        kids = _children(root, session=session)
        by_sub = {}
        for k in kids:
            by_sub.setdefault(k.subtable or "", []).append(k)
        for k in by_sub.get("http-content-routing-list", []):
            cr_entries.append(dict(k.payload or {}))
        vs = by_sub.get("vserver", [])
        if vs:
            data["vserver"] = dict(vs[0].payload or {})
            vrows = _children(vs[0], subtable="vip-list", session=session)
            vip_rows = [dict(r.payload or {}) for r in vrows]
            vip_children = []
            for r in vrows:
                vip_children.extend(_children(r, subtable="vip", session=session))
            data["vips"] = _resolve_vips_cached(appliance_id, vip_rows,
                                                vip_children, session=session)
        pools = by_sub.get("server_pool", [])
        if pools:
            data["pool"] = dict(pools[0].payload or {})
            data["backends"] = [dict(r.payload or {}) for r in
                                _children(pools[0], subtable="pserver-list",
                                          session=session)]
        wpps = (by_sub.get("webprotection_profile_inline", [])
                or by_sub.get("web_protection_profile", []))
        if wpps:
            data["wpp"] = dict(wpps[0].payload or {})
        meta = _layer_meta(appliance_id, layer="deep", section=root.section,
                           session=session)
        return data, cr_entries, meta

    # config-layer fallback: top-level payloads, no sub-tables
    prow = object_by_mkey(appliance_id, "server_policy", name, session=session)
    if prow is None:
        return None, [], _layer_meta(appliance_id, layer="config", session=session)
    policy = dict(prow.payload or {})
    data = {"policy": policy}
    vs_name = policy.get("vserver")
    if vs_name:
        r = object_by_mkey(appliance_id, "vserver", vs_name, session=session)
        if r:
            data["vserver"] = dict(r.payload or {})
    sp_name = policy.get("server-pool")
    if sp_name:
        r = object_by_mkey(appliance_id, "server_pool", sp_name, session=session)
        if r:
            data["pool"] = dict(r.payload or {})
    wpp_name = policy.get("web-protection-profile")
    if wpp_name:
        r = (object_by_mkey(appliance_id, "webprotection_profile_inline",
                            wpp_name, session=session)
             or object_by_mkey(appliance_id, "web_protection_profile",
                               wpp_name, session=session))
        if r:
            data["wpp"] = dict(r.payload or {})
    meta = _layer_meta(appliance_id, layer="config", section=prow.section,
                       session=session)
    return data, [], meta


def policy_filter_facets(appliance_id: int, policy_names, *, session=None):
    """``{policy_name: {"vips":[ip], "backends":[ip], "pool":str, "cert":str}}``
    for the Server-Policy filter bar, built DB-first from the deep cache (zero
    device calls). Backend/VIP facets need a deep capture; a policy with only the
    config layer (or no cache) yields empty lists so the UI can hint that a deep
    capture is required for those two filters. Certificate type + pool come from
    the policy's own top-level fields, so they work off the config layer too."""
    out = {}
    for name in policy_names:
        facet = {"vips": [], "backends": [], "pool": "", "cert": ""}
        try:
            data, _cr, _meta = policy_full_cached(appliance_id, name, session=session)
        except Exception:  # noqa: BLE001 — a bad row never breaks the whole list
            data = None
        if data:
            policy = data.get("policy") or {}
            facet["pool"] = policy.get("server-pool") or ""
            facet["cert"] = (policy.get("certificate-type")
                             or policy.get("certificate_type")
                             or ("local" if policy.get("certificate") else ""))
            for v in data.get("vips") or []:
                ip = v.get("effective_ip") or v.get("vip") or ""
                if ip and ip not in facet["vips"]:
                    facet["vips"].append(str(ip))
            for b in data.get("backends") or []:
                ip = b.get("ip") or b.get("domain") or ""
                if ip and ip not in facet["backends"]:
                    facet["backends"].append(str(ip))
        out[name] = facet
    return out


def wpp_cached(appliance_id: int, name: str, *, session=None):
    """A cached Web Protection Profile payload + freshness meta (or (None, meta))."""
    row = (object_by_mkey(appliance_id, "webprotection_profile_inline", name,
                          session=session)
           or object_by_mkey(appliance_id, "web_protection_profile", name,
                             layer="deep", session=session))
    if row is None:
        return None, _layer_meta(appliance_id, layer="config", session=session)
    meta = _layer_meta(appliance_id, layer=row.layer, section=row.section,
                       session=session)
    return dict(row.payload or {}), meta
