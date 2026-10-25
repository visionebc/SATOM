"""What a plugin author can build ON, for the SATOM Builder's library page
(contract section 14). Structure only: names, columns, operations, fields.
Never a row of data, never a secret.

* ``datasets`` -- the curated datasets a view reads (label, description and
  the columns its rows carry: ``plugin_sandbox.dataset_columns``);
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


def products_for(adom: str) -> list[str]:
    """The API library products a token bound to *adom* may read."""
    from . import api_library as L
    if adom in L.PRODUCTS:
        return [adom]
    return list(L.PRODUCTS) if adom in ("", "global") else []


def datasets() -> list[dict]:
    from . import plugin_sandbox as PS
    return [{"key": k, "label": v[0], "description": v[1], "columns": PS.dataset_columns(k)}
            for k, v in PS.DATASETS.items()]


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


def fortinet(adom: str) -> dict:
    from . import api_library as L
    out = {}
    for p in products_for(adom):
        try:
            rows = L.builds(p)
        except Exception:  # noqa: BLE001 -- a product with no library tables yet
            rows = []
        out[p] = [{k: b.get(k) for k in _BUILD_KEYS} for b in rows]
    return {"products": out}


def library(adom: str) -> dict:
    return {"format": FORMAT, "product": adom or "", "datasets": datasets(),
            "stores": stores(), "apis": apis(), "fortinet": fortinet(adom)}


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
