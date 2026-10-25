"""This server's data for the SATOM Builder's test data (contract section 15).

``GET /api/v1/builder/data`` lets an author start testing on what SATOM
holds instead of synthetic rows: the rows of the curated datasets, the rows
of the data stores, and the lists a ``satom_select`` field offers. Every row
comes through the path a view's render takes here:

* datasets come through ``plugin_datasets.load_datasets`` -- a built-in one's
  fixed SELECT through ``dbintrospect.run_query`` (read-only, sensitive
  columns masked, values as text), an administrator's query through
  ``db_lookup``, a device-object type from the cache with its secret fields
  masked -- cut to what the token's OWNER may see (visible appliances, the
  token's ADOM, the audit log only with ``audit.view``). Without
  ``datasets`` the built-in and administrator ones are sent; a device-object
  dataset only when named;
* data stores are what a Plugin Studio author already reads on the Data
  stores page: declared columns plus ``_id``, never the ``_by`` user names;
* the ``satom_select`` lists are ``studio_satom.source_options``, which is
  scoped to the viewer's appliances.

At most :data:`MAX_LIMIT` rows per table, and the whole answer stays under
:data:`MAX_BYTES` (the Builder keeps at most 4 MB of test data): tables are
cut, the cut is reported, nothing fails for being large.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

FORMAT = "satom.builder-data/1"
DEFAULT_LIMIT = 200
MAX_LIMIT = 2000
MAX_BYTES = 3 * 1024 * 1024


def clean_limit(raw) -> int:
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_LIMIT
    return max(1, min(n, MAX_LIMIT))


def _names(raw, allowed) -> tuple[list[str], list[str]]:
    """``(known, unknown)`` from a comma list; ``None`` = every allowed name."""
    if raw is None:
        return list(allowed), []
    asked = [x.strip() for x in str(raw).split(",") if x.strip()]
    known = [x for x in dict.fromkeys(asked) if x in allowed]
    unknown = [x[:60] for x in dict.fromkeys(asked) if x not in allowed][:20]
    return known, unknown


def _size(obj) -> int:
    return len(json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"))


def _fit(rows: list, budget: int) -> list:
    """The longest prefix of *rows* whose JSON fits in *budget* bytes."""
    out, used = [], 2
    for r in rows:
        n = _size(r) + 1
        if used + n > budget:
            break
        out.append(r)
        used += n
    return out


def sample(datasets=None, stores=None, limit=DEFAULT_LIMIT) -> dict:
    """The rows, for the request's ``current_user`` (the token's owner)."""
    from flask import g
    from . import plugin_datasets as PD
    from . import studio_satom as S
    from . import studio_store as SS
    from ..version import app_version

    limit = clean_limit(limit)
    catalog = {d["key"]: d for d in PD.catalog()}
    # absent = the built-in and administrator datasets; a device-object
    # dataset (about 600 of them) is sent only when named
    default = [k for k, d in catalog.items() if d["source"] != "objects"]
    ds_keys, ds_unknown = _names(datasets, catalog) if datasets is not None else (default, [])
    store_slugs = [s.slug for s in SS.StudioDataStore.query.order_by(SS.StudioDataStore.slug).all()]
    st_keys, st_unknown = _names(stores, store_slugs)
    budget = MAX_BYTES
    out = {"format": FORMAT, "satom_version": app_version(),
           "product": getattr(g, "product", "") or "",
           "taken_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "limit": limit, "datasets": {}, "stores": {}, "sources": {},
           "unknown": {"datasets": ds_unknown, "stores": st_unknown}}

    loaded = PD.load_datasets(ds_keys)
    for key in ds_keys:
        cols = list(catalog[key]["columns"])
        d = loaded.get(key) or {"columns": cols, "rows": []}
        rows = list(d.get("rows") or [])
        kept = _fit(rows[:limit], budget)
        budget -= _size(kept)
        entry = {"columns": list(d.get("columns") or cols), "rows": kept,
                 "total": len(rows), "truncated": len(kept) < len(rows)}
        if d.get("error"):
            entry["error"] = str(d["error"])[:200]
        out["datasets"][key] = entry

    for slug in st_keys:
        store = SS.get(slug)
        if store is None:
            continue
        cols = [dict(c) for c in store.columns if isinstance(c, dict)]
        names = [c["name"] for c in cols]
        total = SS.count(store)
        rows = [dict({n: r.get(n) for n in names}, _id=r.get("_id"))
                for r in SS.query(store, limit=min(limit, SS.MAX_QUERY_LIMIT))]
        kept = _fit(rows, budget)
        budget -= _size(kept)
        out["stores"][slug] = {"columns": cols, "rows": kept, "total": total,
                               "truncated": len(kept) < total}

    for key in S.SOURCE_KEYS:
        try:
            opts, problem = S.source_options(key)
        except Exception:  # noqa: BLE001 -- a list this server cannot build is left out
            continue
        if problem:
            continue
        opts = [{"value": str(o.get("value", "")), "label": str(o.get("label", ""))}
                for o in opts[:500]]
        if _size(opts) > budget:
            continue
        budget -= _size(opts)
        out["sources"][key] = opts
    return out


def counts(answer: dict) -> dict:
    """Row counts per table, for the audit line."""
    return {"datasets": {k: len(v["rows"]) for k, v in answer.get("datasets", {}).items()},
            "stores": {k: len(v["rows"]) for k, v in answer.get("stores", {}).items()}}
