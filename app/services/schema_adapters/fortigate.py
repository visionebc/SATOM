"""FortiGate: CLI ``tree`` (FortiOS format) + REST ``?action=schema``.

* **CLI** -- ``cli_schema.parse_tree`` reads the FortiOS ``tree`` (tables
  ``[name]``, singletons ``<name>``, key field ``*``, ``(lo,hi)`` ranges,
  ``(N)`` sizes; no types, no options). Verified on fgt02, FortiOS 8.0.1
  build0245: 2023 objects, 13611 fields.
* **REST schema** -- ``GET /api/v2/cmdb/<path>/<name>?action=schema`` answers
  one object's schema. VERIFIED 2026-10-07 on fgt02 (FortiOS 8.0.1 build0245,
  evaluation licence, read-only token): 618 tables, 14,836 fields. The real
  answer (fixture ``tests/fixtures/schema_adapters/fgt_8.0.1_action_schema.json``)::

      {"http_method": "GET", "revision": ..., "vdom": ..., "path": "firewall",
       "name": "policy", "action": "schema", "status": "success",
       "http_status": 200, "serial": ..., "version": "v8.0.1", "build": 245,
       "results": {"name", "category": "table"|"complex", "help", "mkey",
                   "mkey_type", "path", "object_range": "global"|"vdom",
                   "access_group", "q_type", "readonly", "hidden",
                   "max_table_size_vdom|global|item",
                   "children": {field: {"name", "category", "type", "help",
                                        "size", "min-value", "max-value",
                                        "options": [{"name", "help"}],
                                        "default", "required", "readonly",
                                        "datasource": ["system.interface.name", ...],
                                        "multiple_values", "max_num_values",
                                        # a nested table/complex:
                                        "mkey", "member_table", "children"}}}}

  What the real answer taught (documented format -> measured):

  - child ``category`` has FOUR values: ``unitary``, ``table``, ``complex``
    and ``info-read-only`` (33 on 8.0.1: ``get``-style print helpers such as
    ``application name status`` or ``certificate local details``, type
    ``key``). They are not configuration: they are kept out of the fields
    and listed in the object's ``info_read_only``.
  - ``datasource`` is a LIST of ``table.column`` targets, not a flag.
  - ``readonly``/``required``/``max_num_values`` exist per field;
    ``hidden``/``readonly``/``object_range`` per object.
  - The global index ``GET /api/v2/cmdb/?action=schema`` answers **403** to a
    read-only token while every per-table read answers 200: the table list
    must be enumerated (``capture(..., fallback_keys=...)``,
    :func:`enumerate_keys`: the CLI tree's objects + a catalogue).
  - A per-table **404** is a measured absence (the path is not a cmdb table
    on this build: ``get``-only CLI objects such as ``system status``), never
    an error.
  - The tree does NOT list every table: 9 cmdb tables of 8.0.1 are REST-only
    (``llm/*``, ``waf/signature|main-class|sub-class``,
    ``firewall/access-proxy[6]``, ``system/vdom``); ``channels_at`` reports
    them ``rest_only``. ``tree`` alone is not a complete schema on FortiOS.

The schema evidence is keyed exactly like the CLI evidence (``a.b/c``, the
FortiOS rule of ``cli_schema.rest_path``), and a nested table is a FIELD of its
top-level object with ``type = "table"`` (``"singleton"`` for a complex) and
``children`` -- the shape ``cli_schema`` folds a nested ``tree`` table into --
so the two channels join field by field, and nested member names compare too.

FortiGate is catalog-only in SATOM (no FortiGate appliance is managed), so the
adapter is not live: evidence arrives by pack (the separate harvester tool
runs the same parser against a device) or by ``flask apilib schema-import``.
"""
from __future__ import annotations

import json
import os

from . import Adapter, Capabilities, Verification, register

PRODUCT = "fortigate"
URN_PREFIX = "/api/v2/cmdb/"

#: Every capability was checked on a device (see ``ADAPTER.verified_on``).
UNVERIFIED: dict = {}

#: Statuses that mean "this box will not show its schema" rather than "this
#: object does not exist": licence/auth gates.
GATED_STATUSES = (401, 403)
#: A per-table answer that measures the path absent on the build.
ABSENT_STATUSES = (404,)

CAT_NESTED = ("table", "complex")
#: ``get``-style print helpers listed among an object's children: not configuration.
CAT_INFO = "info-read-only"


def _is_helper(node) -> bool:
    """An ``info-read-only`` child that is ONLY a print helper. One that also
    carries a value (``options``/``default``: ``ips rule status`` on 8.0.1,
    which the tree lists as a field) is a read-only field."""
    return (isinstance(node, dict) and node.get("category") == CAT_INFO
            and "options" not in node and "default" not in node)


class SchemaGated(RuntimeError):
    """The device refused the schema read as a whole (licence or auth)."""


def _key(path: str, name: str) -> str:
    return "%s/%s" % (path, name) if path else name


def _cli_path(path: str, name: str) -> str:
    return " ".join([p for p in path.split(".") if p] + [name])


def _options(node: dict) -> list:
    out = []
    for o in node.get("options") or []:
        if isinstance(o, dict) and o.get("name") is not None:
            out.append(str(o["name"]))
        elif isinstance(o, str):
            out.append(o)
    return out


def _field(node: dict) -> dict:
    """One ``unitary`` child -> field spec (type raw FortiOS type, attrs)."""
    t = str(node.get("type") or "") or None
    opts = _options(node)
    attrs: dict = {}
    if t:
        attrs["cli_type"] = t
    if node.get("help"):
        attrs["help"] = str(node["help"])
    lo, hi = node.get("min-value"), node.get("max-value")
    if isinstance(lo, int) and isinstance(hi, int):
        attrs["range"] = [lo, hi]
    if isinstance(node.get("size"), int):
        attrs["size"] = node["size"]
    ds = node.get("datasource")
    if ds:
        attrs["datasource"] = True
        if isinstance(ds, list):
            # Real 8.0.1 answer: the list of ``table.column`` targets.
            attrs["datasource_ref"] = [str(x) for x in ds]
    if node.get("multiple_values"):
        attrs["multiple"] = True
    if isinstance(node.get("max_num_values"), int):
        attrs["max_values"] = node["max_num_values"]
    if node.get("readonly"):
        attrs["readonly"] = True
    spec = {"type": t, "options": opts or None, "attrs": attrs}
    if node.get("required"):
        spec["required"] = True
    if node.get("default") not in (None, ""):
        spec["default"] = node["default"]
    return spec


def _members(node: dict) -> tuple[list, list]:
    """``(configuration member names, info-read-only names)`` of a node."""
    names, info = [], []
    for k, v in (node.get("children") or {}).items():
        if _is_helper(v):
            info.append(str(k))
        else:
            names.append(str(k))
    return sorted(names), sorted(info)


def _nested(node: dict) -> dict:
    """A ``table``/``complex`` child -> the folded field cli_schema makes of a
    nested ``tree`` object: ``type`` = its kind, ``children`` = its member
    names (``info-read-only`` helpers excluded, as the tree prints none)."""
    kind = "table" if node.get("category") == "table" else "singleton"
    attrs = {"help": str(node["help"])} if node.get("help") else {}
    if node.get("mkey"):
        attrs["mkey"] = str(node["mkey"])
    if node.get("readonly"):
        attrs["readonly"] = True
    names, _info = _members(node)
    spec = {"type": kind, "options": None, "children": names, "attrs": attrs}
    if node.get("required"):
        spec["required"] = True
    return spec


def endpoint_from_schema(path: str, name: str, node: dict) -> tuple[str, dict, dict]:
    """``(key, endpoint, summary object)`` of one object's schema."""
    key = _key(path, name)
    fields, info = {}, []
    for fname, child in (node.get("children") or {}).items():
        if not isinstance(child, dict):
            continue
        cat = child.get("category")
        if _is_helper(child):
            info.append(str(fname))
        elif cat in CAT_NESTED:
            fields[str(fname)] = _nested(child)
        else:
            fields[str(fname)] = spec = _field(child)
            if cat == CAT_INFO:
                spec["attrs"].update(info_read_only=True, readonly=True)
    kind = "table" if node.get("category") == "table" else "singleton"
    meta = {"cli_path": _cli_path(path, name), "kind": kind,
            "mkey": str(node.get("mkey") or ""), "parent": "", "cli_id": None}
    attrs = dict(meta)
    if node.get("help"):
        attrs["help"] = str(node["help"])
    if node.get("object_range"):
        attrs["scope"] = str(node["object_range"])
    if node.get("readonly"):
        attrs["readonly"] = True
    if node.get("hidden"):
        # the REST schema's own flag (the tree still lists these 12 tables);
        # not the contract's field-level ``hidden`` (show-full-only names).
        attrs["rest_hidden"] = True
    if info:
        attrs["info_read_only"] = sorted(info)
        meta = dict(meta, info_read_only=sorted(info))
    ep = {"urn": URN_PREFIX + key, "section": path.split(".", 1)[0] if path else name,
          "verdict": "ok", "rows": None, "fields": fields, "attrs": attrs}
    return key, ep, meta


def _entries(body) -> list:
    """Accept the shapes a capture may hold:

    * ``{"results": {...}, "path": "system", "name": "global", ...}`` -- ONE
      real per-table answer (what FortiOS 8.0.1 serves);
    * ``{"<path>/<name>": <one-object answer>, ...}`` -- a per-table capture
      (:func:`capture`, :func:`load_capture_dir`);
    * ``{"results": [{"path", "name", "schema"|children...}, ...]}`` -- a
      whole-cmdb list (documented; the 8.0.1 index answers 403 to a
      read-only token, so never seen).
    """
    out = []
    if isinstance(body, dict) and "results" not in body and body and all(
            isinstance(v, dict) and "/" in str(k) for k, v in body.items()):
        for k, v in body.items():
            path, name = str(k).rsplit("/", 1)
            node = v.get("results") if isinstance(v.get("results"), dict) else v
            out.append((path, name, node))
        return out
    res = body.get("results") if isinstance(body, dict) else body
    if isinstance(res, dict):
        out.append((str(body.get("path") or res.get("path") or ""),
                    str(body.get("name") or res.get("name") or ""), res))
    elif isinstance(res, list):
        for e in res:
            if not isinstance(e, dict):
                continue
            node = e.get("schema") if isinstance(e.get("schema"), dict) else e
            out.append((str(e.get("path") or ""), str(e.get("name") or node.get("name") or ""),
                        node))
    return [(p, n, node) for p, n, node in out if n and isinstance(node, dict)]


def evidence_from_schema(body, version: str, build: str, device: dict | None,
                         origin_ref: str, *, captured_at: str = "",
                         errors: dict | None = None) -> dict:
    """FortiOS ``?action=schema`` answer(s) -> ``schema`` evidence document.

    ``errors`` = ``{key: http_status}`` of the per-table reads that did not
    answer 200. A 404 is a measured absence (``verdict = "absent"``: the path
    is no cmdb table on this build); anything else is ``verdict = "error"``
    (a refused read says nothing about the object).
    """
    from .. import firmware_versions as fv
    endpoints, objects = {}, {}
    for path, name, node in _entries(body):
        key, ep, meta = endpoint_from_schema(path, name, node)
        endpoints[key] = ep
        objects[key] = meta
    absent = 0
    for key, status in sorted((errors or {}).items()):
        if key in endpoints:
            continue
        gone = status in ABSENT_STATUSES
        absent += gone
        endpoints[key] = {"urn": URN_PREFIX + key,
                          "section": key.split("/", 1)[0].split(".", 1)[0],
                          "verdict": "absent" if gone else "error", "rows": None,
                          "fields": None, "attrs": {"http_status": status}}
    errs = sum(1 for e in endpoints.values() if e["verdict"] == "error")
    doc = {"product": PRODUCT, "source": "schema", "captured_at": str(captured_at or "")[:19],
           "origin_ref": origin_ref or "", "device": device,
           "scope": {"kind": "build", "version": fv.normalize(version) or str(version or ""),
                     "build": build or ""},
           "healthy": True, "skip_reason": "", "endpoints": endpoints,
           "summary": {"objects": objects, "format": "fortios_action_schema",
                       "verified": True, "verified_on": VERIFIED_ON,
                       "counts": {"endpoints": len(endpoints),
                                  "tables": len(objects),
                                  "fields": sum(len(e.get("fields") or {})
                                                for e in endpoints.values()),
                                  "absent": absent, "errors": errs}}}
    asked = len(objects) + errs
    if not objects:
        doc.update(healthy=False, skip_reason="the schema answer holds no object")
    elif errs / asked > 0.25:
        doc.update(healthy=False, skip_reason="%d/%d schema reads failed" % (errs, asked))
    return doc


def enumerate_keys(tree_doc: dict | None = None, catalog=()) -> list:
    """The table list to read one by one when the global index is refused
    (403 on 8.0.1 with a read-only token): the top-level objects of the build's
    ``cli_tree`` evidence plus a catalogue (e.g. the vendor URNs), as keys.
    The tree alone misses tables (9 on 8.0.1), hence the catalogue."""
    keys = set()
    for k in ((tree_doc or {}).get("endpoints") or {}):
        keys.add(str(k))
    for k in catalog or ():
        k = str(k or "").split("?", 1)[0]
        if k.startswith(URN_PREFIX):
            k = k[len(URN_PREFIX):]
        k = k.strip("/")
        if k.count("/") == 1:          # ``a.b/c``: a table, never a nested path
            keys.add(k)
    return sorted(keys)


def capture(get, keys=None, *, fallback_keys=None) -> tuple[dict, dict]:
    """Read the schema through ``get(url) -> (status, json)``. GET only.

    Without ``keys`` one request for the whole cmdb index; when the box refuses
    the index (401/403) and ``fallback_keys`` are given (:func:`enumerate_keys`),
    every table is read one by one instead -- the only way a read-only token
    gets the schema on 8.0.1. With ``keys``, one request per table. Raises
    :class:`SchemaGated` when the very first per-table answer is a licence/auth
    refusal: a box that refuses everything must not be recorded as a build
    whose objects all errored. Returns ``(answers, {key: status})``.
    """
    if not keys:
        status, body = get(URN_PREFIX + "?action=schema")
        if status == 200:
            return body, {}
        if status in GATED_STATUSES and fallback_keys:
            return capture(get, list(fallback_keys))
        if status in GATED_STATUSES:
            raise SchemaGated("HTTP %s on %s?action=schema" % (status, URN_PREFIX))
        raise RuntimeError("HTTP %s on %s?action=schema" % (status, URN_PREFIX))
    out, errors = {}, {}
    for i, key in enumerate(keys):
        status, body = get("%s%s?action=schema" % (URN_PREFIX, key))
        if status in GATED_STATUSES and i == 0:
            raise SchemaGated("HTTP %s on %s%s?action=schema" % (status, URN_PREFIX, key))
        if status == 200 and isinstance(body, dict):
            out[key] = body
        else:
            errors[key] = status
    return out, errors


def load_capture_dir(path: str) -> tuple[dict, dict]:
    """A saved per-table capture -> ``(answers, {key: status})``.

    Layout (what a per-table capture writes): one ``<path>__<name>.json``
    answer per table, optionally ``fetch_summary.json`` = ``{key: {"status"}}``
    next to it or one level up (the non-200 answers: 404 = absent)."""
    out, errors = {}, {}
    for fn in sorted(os.listdir(path)):
        if not fn.endswith(".json") or "__" not in fn:
            continue
        with open(os.path.join(path, fn), encoding="utf-8") as fh:
            body = json.load(fh)
        if isinstance(body, dict) and isinstance(body.get("results"), dict):
            out["%s/%s" % (body.get("path") or fn.split("__", 1)[0],
                           body.get("name") or fn[:-5].split("__", 1)[1])] = body
    for cand in (os.path.join(path, "fetch_summary.json"),
                 os.path.join(os.path.dirname(os.path.abspath(path)), "fetch_summary.json")):
        if os.path.isfile(cand):
            with open(cand, encoding="utf-8") as fh:
                summ = json.load(fh)
            for k, v in (summ or {}).items():
                st = v.get("status") if isinstance(v, dict) else v
                if st != 200 and k not in out:
                    errors[k] = st
            break
    return out, errors


VERIFIED_ON = {"date": "2026-10-07", "device": "fgt02 (lab)", "build": "8.0.1 build0245"}

ADAPTER = register(Adapter(
    product=PRODUCT, label="FortiGate",
    capabilities=Capabilities(tree=True, show_full=True, rest_schema=True, rest_probe=False),
    verified_on=(Verification(VERIFIED_ON["date"], VERIFIED_ON["device"], VERIFIED_ON["build"],
                              "CLI tree + REST ?action=schema read per table (618 tables, "
                              "14,836 fields; the global index answers 403 to a read-only "
                              "token)"),),
    unverified=UNVERIFIED, live=False,
    notes="Catalog-only in SATOM: evidence arrives by pack (satom-harvester) or by "
          "`flask apilib schema-import` (a per-table capture directory is accepted). "
          "The CLI tree misses REST tables (9 on 8.0.1): both channels are needed."),
    None)


__all__ = ["PRODUCT", "UNVERIFIED", "VERIFIED_ON", "SchemaGated", "endpoint_from_schema",
           "evidence_from_schema", "enumerate_keys", "capture", "load_capture_dir", "ADAPTER"]
