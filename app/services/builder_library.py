"""What a plugin author can build ON, for the SATOM Builder's library page
(contract section 14). Structure only: names, columns, operations, fields.
Never a row of data, never a secret.

* ``datasets`` -- every dataset a view reads (``plugin_datasets``: built-in,
  administrator, device objects), with its columns and relations;
* ``stores`` -- the data stores this server has, with their full column
  definitions (an app's store steps read and write these);
* ``apis`` -- the API Catalog: every API, its versions and their endpoints,
  which is what a connection pinned to a version may call
  (``connection("x").op("getHost", ...)``);
* ``fortinet`` -- the API library of the token's ADOM: the builds SATOM knows
  of each product. One build's endpoints, and one endpoint's fields, are
  separate calls (:func:`fortinet_endpoints`, :func:`fortinet_fields`): a
  FortiGate build alone is about 720 endpoints.
"""
from __future__ import annotations

FORMAT = "satom.builder-library/1"
_BUILD_KEYS = ("version", "build", "line", "measured", "vendor_only", "cli_measured", "in_fleet")


def products_for(adom: str, owner=None) -> list[str]:
    """The API library products a call in ADOM *adom* may read: that one, or
    in Global every product whose ADOM the owner may enter."""
    from . import api_library as L
    if adom in L.PRODUCTS:
        return [adom]
    if adom not in ("", "global"):
        return []
    if owner is None:
        return list(L.PRODUCTS)
    from . import builder_target as BT
    mine = set(BT.adoms_for(owner))
    return [p for p in L.PRODUCTS if p in mine]


def datasets(owner=None, adom: str | None = None) -> list[dict]:
    """Every dataset of the call's ADOM (built-in, administrator, device
    objects) with its columns, relations, group and, for a built-in one, its
    fixed SQL; an administrator dataset says how it is built (its query).
    In Global: every ADOM the owner may enter (``builder_target.offered``)."""
    from flask import g, has_request_context
    from . import builder_target as BT
    if adom is None:
        adom = (getattr(g, "product", "") or "") if has_request_context() else ""
    keep = ("key", "label", "description", "columns", "source", "group", "product",
            "relations", "masked", "sql", "spec", "object")
    return [{k: d[k] for k in keep if k in d} for d in BT.offered(owner, adom)]


def stores() -> dict:
    from ..models_studio import StudioDataStore
    out = {}
    for s in StudioDataStore.query.order_by(StudioDataStore.slug).all():
        out[s.slug] = {"name": s.name, "description": s.description or "",
                       "columns": [dict(c) for c in s.columns if isinstance(c, dict)]}
    return out


def apis() -> list[dict]:
    from . import studio_apis as SA
    out = []
    for a in SA.list_apis():
        out.append({"slug": a.slug, "name": a.name, "owner": a.owner or "",
                    "docs_url": a.docs_url or "", "description": a.description or "",
                    "versions": [{"version": v.version, "status": v.status,
                                  "base_path": v.base_path or "", "notes": v.notes or "",
                                  "operations": list(v.operations or [])}
                                 for v in SA.versions(a)]})
    return out


def fortinet(adom: str, owner=None) -> dict:
    from . import api_library as L
    out = {}
    for p in products_for(adom, owner):
        try:
            rows = L.builds(p)
        except Exception:  # noqa: BLE001 -- a product with no library tables yet
            rows = []
        out[p] = [{k: b.get(k) for k in _BUILD_KEYS} for b in rows]
    return {"products": out}


def library(adom: str, owner=None, token_adom: str | None = None) -> dict:
    """Contract §14, plus §17: ``reach`` (what the connection reaches, when
    the call came with a token) and ``elsewhere`` (the datasets of the
    owner's other ADOMs, names only)."""
    from . import builder_target as BT
    out = {"format": FORMAT, "product": adom or "", "datasets": datasets(owner, adom),
           "stores": stores(), "apis": apis(), "fortinet": fortinet(adom, owner),
           "elsewhere": BT.elsewhere(owner, adom)}
    if token_adom is not None:
        out["reach"] = BT.reach(owner, token_adom, adom)
    return out


def fortinet_endpoints(product: str, version: str) -> dict:
    from . import api_library as L
    eps = L.endpoints_at(product, version)
    keep = ("endpoint", "urn", "section", "verdict", "fields_known", "sources", "vendor_only")
    return {"product": product, "version": version,
            "endpoints": [{k: e.get(k) for k in keep} for e in eps.values()]}


def fortinet_fields(product: str, version: str, endpoint: str) -> dict:
    from . import api_library as L
    res = L.fields_at(product, endpoint, version)
    return {"product": product, "version": version, "endpoint": endpoint,
            "status": res.get("status"), "fields": res.get("fields") or {}}
