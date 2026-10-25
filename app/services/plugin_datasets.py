"""Every dataset a plugin can read, from three sources (2026-10-25).

A plugin never runs SQL: it declares dataset KEYS and SATOM hands it the rows.
Until 4.3.0 the only datasets were the nine written in
``plugin_sandbox.DATASETS``. Now there are three sources, one catalogue:

* ``builtin`` -- the nine curated queries of ``plugin_sandbox.DATASETS``.
* ``objects`` -- one dataset per object type the device cache holds
  (``device_objects``: product × layer × logical name, ~600 on a lab fleet),
  generated, never hand-written. Key ``<product>_<logical>`` (config layer) or
  ``<product>_deep_<logical>`` (deep layer); a sub-object's ``/`` becomes
  ``__``: ``fortiweb_vip``, ``fortigate_firewall_policy``,
  ``fortiadc_load_balance_pool__pool_member``. Columns: ``id``,
  ``appliance_id``, ``device``, ``mkey``, ``parent_id`` and the object's own
  fields as the cache holds them (``-`` → ``_``; at most :data:`MAX_FIELDS`,
  the most common first). A field whose name says secret (password, passwd,
  psk, secret, token, private, ``*key``) is masked.
* ``admin`` -- what an administrator built with the Report Builder's query
  builder (Administrator › Database › Plugin datasets, model
  ``PluginDataset``), run through ``db_lookup``: catalogue-checked
  identifiers, sensitive columns refused, the read-only console role, the
  ADOM scope added by the server. Key ``admin_<slug>``; only ``published``
  ones are offered.

Every key is a Jinja identifier: a view reads ``{{ fortiweb_vip.rows }}``.

Rows are always cut to the person rendering (:func:`plugin_sandbox._viewer_scope`):
their ADOM's devices, maintenance devices only with the permission. A concrete
ADOM only lists its own product's object datasets and the admin datasets of
that ADOM or of every ADOM.

Relations (for diagrams: the Builder's Database tab, the author guide) are
``[{"column", "to", "to_column", "inferred"}]``: ``appliance_id`` → the
fleet; a sub-object's ``parent_id`` → its parent type's ``id``; an object
field named like another object type of the same product (a policy's
``vserver``) → that type's ``mkey`` (inferred, like the ER diagram's dashed
lines).
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from typing import Any

SOURCES = ("builtin", "objects", "admin")
PRODUCTS = ("fortiweb", "fortigate", "fortiadc", "fortianalyzer", "fortiauthenticator")
MAX_FIELDS = 80
MAX_ROWS = 1000
SAMPLE_ROWS = 25
CATALOG_TTL = 300.0
MASK = "********"
FIXED_OBJECT_COLUMNS = ("id", "appliance_id", "device", "mkey", "parent_id")
_SECRET_RE = re.compile(r"(passw|passwd|psk|secret|token|private|fernet|_enc$|(^|[_-])key$)", re.I)
_IDENT_RE = re.compile(r"[^a-z0-9_]+")
ADMIN_SLUG_RE = re.compile(r"^[a-z][a-z0-9_]{1,59}$")
ADMIN_PREFIX = "admin_"
#: Built-in columns that point at another built-in dataset.
BUILTIN_REFS = (("appliance_id", "fleet_appliances", "id"), ("device", "fleet_appliances", "name"),
                ("server_pool", "server_pools", "name"), ("wpp", "web_protection_profiles", "name"))

_lock = threading.Lock()
_cache: dict[str, Any] = {"at": 0.0, "objects": None, "db": None}


class DatasetError(ValueError):
    pass


# --------------------------------------------------------------------------
# names
# --------------------------------------------------------------------------
def ident(text: str) -> str:
    s = _IDENT_RE.sub("_", str(text or "").lower().replace("/", "__"))
    s = re.sub(r"_{3,}", "__", s).strip("_")
    return s or "x"


def object_key(product: str, layer: str, logical: str) -> str:
    stem = product + ("_deep_" if layer == "deep" else "_") + ident(logical)
    if len(stem) <= 100:
        return stem
    return stem[:90].rstrip("_") + "_" + hashlib.sha256(stem.encode()).hexdigest()[:8]


def admin_key(slug: str) -> str:
    return ADMIN_PREFIX + slug


def is_secret(field: str) -> bool:
    return bool(_SECRET_RE.search(str(field or "")))


def field_column(name: str) -> str:
    c = ident(name.replace("-", "_"))
    return ("f_" + c) if c in FIXED_OBJECT_COLUMNS else c


# --------------------------------------------------------------------------
# object datasets: what the device cache holds
# --------------------------------------------------------------------------
def _db_identity() -> str:
    try:
        from ..extensions import db
        return str(db.engine.url)
    except Exception:  # noqa: BLE001
        return ""


def invalidate() -> None:
    with _lock:
        _cache["at"] = 0.0
        _cache["objects"] = None


def _scan_objects() -> dict[str, dict]:
    """``{key: {product, layer, logical, rows, fields: [(column, field)]}}``
    from one pass over a sample of every cached object type."""
    from ..extensions import db
    from sqlalchemy import text
    q = text(
        "SELECT kind, layer, logical_name, n, payload FROM ("
        " SELECT a.kind AS kind, o.layer AS layer, o.logical_name AS logical_name, o.payload AS payload,"
        "  COUNT(*) OVER (PARTITION BY a.kind, o.layer, o.logical_name) AS n,"
        "  ROW_NUMBER() OVER (PARTITION BY a.kind, o.layer, o.logical_name ORDER BY o.id) AS rn"
        " FROM device_objects o JOIN appliances a ON a.id = o.appliance_id"
        " WHERE a.kind IS NOT NULL AND a.kind <> ''"
        ") t WHERE rn <= :k")
    types: dict[tuple, dict] = {}
    for kind, layer, logical, n, payload in db.session.execute(q, {"k": SAMPLE_ROWS}):
        if kind not in PRODUCTS or not logical:
            continue
        t = types.setdefault((kind, layer or "config", logical),
                             {"rows": int(n or 0), "freq": {}, "order": []})
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except ValueError:
                payload = None
        if isinstance(payload, dict):
            for f, v in payload.items():
                if isinstance(v, (dict, list)):
                    continue
                if f not in t["freq"]:
                    t["order"].append(f)
                t["freq"][f] = t["freq"].get(f, 0) + 1
    out: dict[str, dict] = {}
    for (kind, layer, logical), t in sorted(types.items()):
        key = object_key(kind, layer, logical)
        ranked = sorted(t["order"], key=lambda f: (-t["freq"][f], t["order"].index(f)))
        fields, seen = [], set(FIXED_OBJECT_COLUMNS)
        for f in ranked:
            col = field_column(f)
            if col in seen:
                continue
            seen.add(col)
            fields.append((col, f))
            if len(fields) >= MAX_FIELDS:
                break
        out[key] = {"product": kind, "layer": layer, "logical": logical, "rows": t["rows"],
                    "fields": fields}
    return out


def _objects() -> dict[str, dict]:
    now = time.monotonic()
    ident_ = _db_identity()
    with _lock:
        if (_cache["objects"] is not None and _cache["db"] == ident_
                and now - _cache["at"] < CATALOG_TTL):
            return _cache["objects"]
    try:
        objs = _scan_objects()
    except Exception:  # noqa: BLE001 -- no cache table on this deployment: no object datasets
        objs = {}
    with _lock:
        _cache.update(at=now, objects=objs, db=ident_)
    return objs


def _object_entry(key: str, o: dict, all_objs: dict) -> dict:
    cols = list(FIXED_OBJECT_COLUMNS) + [c for c, _f in o["fields"]]
    secret = [c for c, f in o["fields"] if is_secret(f)]
    rels = [{"column": "appliance_id", "to": "fleet_appliances", "to_column": "id", "inferred": False}]
    if "/" in o["logical"]:
        parent = object_key(o["product"], o["layer"], o["logical"].rsplit("/", 1)[0])
        if parent in all_objs:
            rels.append({"column": "parent_id", "to": parent, "to_column": "id", "inferred": False})
    for c, f in o["fields"]:
        target = object_key(o["product"], o["layer"], f.replace("-", "_"))
        if target != key and target in all_objs and "/" not in all_objs[target]["logical"]:
            rels.append({"column": c, "to": target, "to_column": "mkey", "inferred": True})
    label = "%s %s%s" % (_PRODUCT_LABEL.get(o["product"], o["product"]),
                          o["logical"].replace("/", " › ").replace("_", " "),
                          " (deep)" if o["layer"] == "deep" else "")
    return {"key": key, "source": "objects", "label": label,
            "description": "Every cached %s object of type %s (%s layer): %d on this server. "
                           "Fields as the device cache holds them%s." % (
                               o["product"], o["logical"], o["layer"], o["rows"],
                               "; masked: " + ", ".join(secret) if secret else ""),
            "product": o["product"], "columns": cols, "relations": rels, "masked": secret,
            "group": "%s › %s" % (_PRODUCT_LABEL.get(o["product"], o["product"]),
                                  o["logical"].split("/", 1)[0].replace("_", " ")),
            "object": {"product": o["product"], "layer": o["layer"], "logical_name": o["logical"]},
            "rows": o["rows"]}


_PRODUCT_LABEL = {"fortiweb": "FortiWeb", "fortigate": "FortiGate", "fortiadc": "FortiADC",
                  "fortianalyzer": "FortiAnalyzer", "fortiauthenticator": "FortiAuthenticator"}


def _load_objects(key: str, o: dict, scope) -> dict:
    from ..extensions import db
    from ..models import Appliance
    from ..models_cache import DeviceObject
    q = (Appliance.query.with_entities(Appliance.id, Appliance.name)
         .filter(Appliance.kind == o["product"]))
    if scope is not None:
        ids = {int(i) for i in scope[0]}
        q = q.filter(Appliance.id.in_(ids or {-1}))
    names = {i: n for i, n in q.all()}
    cols = list(FIXED_OBJECT_COLUMNS) + [c for c, _f in o["fields"]]
    if not names:
        return {"columns": cols, "rows": []}
    rows_q = (db.session.query(DeviceObject.id, DeviceObject.appliance_id, DeviceObject.mkey,
                               DeviceObject.parent_id, DeviceObject.payload)
              .filter(DeviceObject.appliance_id.in_(list(names)),
                      DeviceObject.layer == o["layer"],
                      DeviceObject.logical_name == o["logical"])
              .order_by(DeviceObject.appliance_id, DeviceObject.idx, DeviceObject.id)
              .limit(MAX_ROWS))
    rows = []
    for oid, aid, mkey, parent, payload in rows_q.all():
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except ValueError:
                payload = {}
        payload = payload if isinstance(payload, dict) else {}
        row = {"id": oid, "appliance_id": aid, "device": names.get(aid, ""), "mkey": mkey,
               "parent_id": parent}
        for c, f in o["fields"]:
            v = payload.get(f)
            if isinstance(v, (dict, list)):
                v = json.dumps(v)
            row[c] = (MASK if v not in (None, "") else v) if is_secret(f) else v
        rows.append(row)
    return {"columns": cols, "rows": rows}


# --------------------------------------------------------------------------
# admin datasets
# --------------------------------------------------------------------------
def admin_columns(spec: dict) -> list[str]:
    """Result names a view reads: the column itself when it is unique in the
    query, else ``<table>_<column>``; aggregates keep their alias."""
    from . import db_lookup
    raw = db_lookup.column_names(spec)
    plain = [n.split(".", 1)[1] if "." in n else n for n in raw]
    out = []
    for n, p in zip(raw, plain):
        out.append(ident(p) if plain.count(p) == 1 else ident(n.replace(".", "_")))
    return out


def _admin_rows():
    from ..models import PluginDataset
    try:
        return PluginDataset.query.order_by(PluginDataset.key).all()
    except Exception:  # noqa: BLE001 -- table not migrated yet
        return []


def _admin_entry(d) -> dict:
    spec = d.spec_dict
    try:
        cols = admin_columns(spec)
    except Exception:  # noqa: BLE001
        cols = []
    rels = []
    for c in cols:
        if c == "appliance_id" or c.endswith("_appliance_id"):
            rels.append({"column": c, "to": "fleet_appliances", "to_column": "id", "inferred": True})
    return {"key": d.key, "source": "admin", "label": d.label or d.key,
            "description": d.description or "", "product": d.product or "", "columns": cols,
            "relations": rels, "masked": [], "group": "Administrator datasets",
            "status": d.status, "spec": spec, "updated_by": d.updated_by or d.created_by or ""}


def _adoms_for(scope_product: str):
    """The ADOMs a dataset query is confined to for the current viewer
    (``None`` = no confinement), as db_lookup reads them."""
    from flask import has_request_context
    if not has_request_context():
        return None
    from .product_scope import restricted_adoms
    allowed = restricted_adoms()
    p = scope_product
    if p:
        return frozenset([p]) if allowed is None or p in allowed else frozenset()
    return None if allowed is None else frozenset(allowed)


def _load_admin(entry: dict, scope) -> dict:
    from . import db_lookup
    from flask import g, has_request_context
    product = ""
    if has_request_context():
        product = (getattr(g, "product", "") or "").strip()
        product = "" if product in ("", "global") else product
    res = db_lookup.run(entry["spec"], _adoms_for(product))
    names = entry["columns"]
    rows = [dict(zip(names, (r.get(k) for k in res["columns"]))) for r in res["rows"]]
    if scope is not None and "appliance_id" in names:
        ids = {str(i) for i in scope[0]}
        rows = [r for r in rows if r.get("appliance_id") in (None, "") or str(r["appliance_id"]) in ids]
    return {"columns": names, "rows": rows}


def clean_admin(key_slug: str, label: str, description: str, spec, product: str) -> dict:
    """Validate an admin dataset definition. Raises :class:`DatasetError`."""
    from . import db_lookup
    slug = str(key_slug or "").strip().lower()
    if slug.startswith(ADMIN_PREFIX):
        slug = slug[len(ADMIN_PREFIX):]
    if not ADMIN_SLUG_RE.match(slug):
        raise DatasetError("Key: a letter, then lowercase letters, digits and _ (2 to 60).")
    label = str(label or "").strip()[:120]
    if not label:
        raise DatasetError("Give the dataset a name.")
    product = str(product or "").strip()
    if product and product not in PRODUCTS:
        raise DatasetError("Unknown ADOM %r." % product[:40])
    try:
        clean = db_lookup.clean_spec(spec, allow_aggregates=True)
    except db_lookup.LookupError_ as exc:
        raise DatasetError(str(exc)) from None
    cols = admin_columns(clean)
    if len(set(cols)) != len(cols):
        raise DatasetError("Two result columns have the same name.")
    return {"key": admin_key(slug), "label": label, "description": str(description or "")[:2000],
            "spec": clean, "product": product}


# --------------------------------------------------------------------------
# the catalogue
# --------------------------------------------------------------------------
def _builtin_entries() -> list[dict]:
    from . import plugin_sandbox as PS
    out = []
    for k, (label, desc, sql) in PS.DATASETS.items():
        cols = PS.dataset_columns(k)
        rels = [{"column": c, "to": t, "to_column": tc, "inferred": False}
                for c, t, tc in BUILTIN_REFS if c in cols and t != k]
        out.append({"key": k, "source": "builtin", "label": label, "description": desc,
                    "product": "", "columns": cols, "relations": rels, "masked": [],
                    "group": "Built-in", "sql": sql})
    return out


def _current_product() -> str:
    from flask import g, has_request_context
    if not has_request_context():
        return ""
    p = (getattr(g, "product", "") or "").strip()
    return "" if p in ("", "global") else p


def catalog(product: str | None = None, *, include_unpublished: bool = False) -> list[dict]:
    """Every dataset offered in *product* (default: the request's ADOM;
    '' = Global, everything). Built-in first, then administrator datasets,
    then object datasets by product and type."""
    product = _current_product() if product is None else (product or "")
    out = _builtin_entries()
    for d in _admin_rows():
        if d.status != "published" and not include_unpublished:
            continue
        if product and d.product and d.product != product:
            continue
        out.append(_admin_entry(d))
    objs = _objects()
    for key, o in objs.items():
        if product and o["product"] != product:
            continue
        out.append(_object_entry(key, o, objs))
    return out


def keys(product: str | None = None) -> list[str]:
    return [d["key"] for d in catalog(product)]


def get(key: str, product: str | None = None) -> dict | None:
    from . import plugin_sandbox as PS
    if key in PS.DATASETS:
        return next(d for d in _builtin_entries() if d["key"] == key)
    product = _current_product() if product is None else (product or "")
    if key.startswith(ADMIN_PREFIX):
        for d in _admin_rows():
            if d.key == key and d.status == "published" and (
                    not product or not d.product or d.product == product):
                return _admin_entry(d)
        return None
    objs = _objects()
    o = objs.get(key)
    if o is None or (product and o["product"] != product):
        return None
    return _object_entry(key, o, objs)


def columns(key: str) -> list[str]:
    d = get(key, "")
    return list(d["columns"]) if d else []


def load(entries: list[dict], scope) -> dict[str, dict]:
    """``{key: {"columns", "rows"[, "error"]}}`` for admin and object entries
    (built-in ones are ``plugin_sandbox.load_datasets``'s)."""
    out = {}
    for e in entries:
        try:
            if e["source"] == "objects":
                objs = _objects()
                o = objs.get(e["key"])
                out[e["key"]] = _load_objects(e["key"], o, scope) if o else \
                    {"columns": e["columns"], "rows": [], "error": "no such object type"}
            elif e["source"] == "admin":
                out[e["key"]] = _load_admin(e, scope)
        except Exception as exc:  # noqa: BLE001 -- never fatal to a render
            out[e["key"]] = {"columns": e.get("columns") or [], "rows": [],
                             "error": str(exc)[:200]}
    return out


def summary(product: str | None = None) -> dict:
    """Counts per source and per product, for the author guide and pickers."""
    cat = catalog(product)
    per = {}
    for d in cat:
        if d["source"] == "objects":
            per[d["product"]] = per.get(d["product"], 0) + 1
    return {"builtin": sum(1 for d in cat if d["source"] == "builtin"),
            "admin": sum(1 for d in cat if d["source"] == "admin"),
            "objects": per, "total": len(cat)}


# --------------------------------------------------------------------------
# what callers use (plugin_sandbox stays the pure built-in layer: it travels
# in the rules pack, this module needs the server)
# --------------------------------------------------------------------------
def admin_row(key: str):
    """The administrator dataset *key* in any status, or None."""
    if not str(key).startswith(ADMIN_PREFIX):
        return None
    from ..models import PluginDataset
    try:
        return PluginDataset.query.filter_by(key=str(key)).first()
    except Exception:  # noqa: BLE001
        return None


def declarable(keys, product: str | None = None) -> list[str]:
    """What a plugin may declare: an offered dataset, or an administrator
    dataset that exists but is not published yet (it reads no rows until it
    is)."""
    product = _current_product() if product is None else (product or "")

    def unpublished_here(k):
        row = admin_row(k)
        return row is not None and (not product or not row.product or row.product == product)
    return [str(k) for k in keys or [] if is_known(str(k), product) or unpublished_here(str(k))]


def create_pending(d: dict, *, by: str, source: str) -> str:
    """Create, PENDING, an administrator dataset a package brought. Returns
    "" or why it was refused (the query is compiled on THIS server)."""
    from ..extensions import db
    from ..models import PluginDataset
    try:
        clean = clean_admin(d.get("key"), d.get("label") or d.get("key"), d.get("description"),
                            d.get("spec"), d.get("product") or "")
    except DatasetError as exc:
        return str(exc)
    if clean["key"] != d.get("key"):
        return "the key is not admin_<name>"
    if admin_row(clean["key"]) is not None:
        return ""
    db.session.add(PluginDataset(key=clean["key"], label=clean["label"],
                                 description=clean["description"],
                                 spec=json.dumps(clean["spec"]), product=clean["product"],
                                 status="pending", source=source[:120], created_by=by,
                                 updated_by=by))
    db.session.flush()
    from .audit import log_action
    log_action("plugin_dataset.pending", target=clean["key"], extra={"source": source[:120]})
    return ""


def is_known(key: str, product: str | None = None) -> bool:
    try:
        return get(str(key), product) is not None
    except Exception:  # noqa: BLE001
        from . import plugin_sandbox as PS
        return key in PS.DATASETS


def known(keys, product: str | None = None) -> list[str]:
    return [str(k) for k in keys or [] if is_known(str(k), product)]


def load_datasets(keys) -> dict[str, Any]:
    """``plugin_sandbox.load_datasets`` for every source: the rows of each
    known key, cut to the viewer, ``error`` when a query failed."""
    from . import plugin_sandbox as PS
    keys = [str(k) for k in keys or []]
    out = PS.load_datasets([k for k in keys if k in PS.DATASETS])
    entries = []
    for k in keys:
        if k in PS.DATASETS:
            continue
        e = get(k)
        if e:
            entries.append(e)
        elif admin_row(k) is not None:
            # declared, not published: no rows, said, and the view still renders
            out[k] = {"columns": [], "rows": [],
                      "error": "%s is not published on this server yet" % k}
    if entries:
        out.update(load(entries, PS._viewer_scope()))
    return {k: out[k] for k in keys if k in out}


def picker(product: str | None = None) -> list[dict]:
    """The catalogue for a picker: key, label, description, group, source,
    columns (no spec, no rows)."""
    return [{k: d.get(k) for k in ("key", "label", "description", "group", "source", "product",
                                   "columns")} for d in catalog(product)]
