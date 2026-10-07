"""FortiGate: CLI ``tree`` (FortiOS format) + REST ``?action=schema``.

* **CLI** -- ``cli_schema.parse_tree`` reads the FortiOS ``tree`` (tables
  ``[name]``, singletons ``<name>``, key field ``*``, ``(lo,hi)`` ranges,
  ``(N)`` sizes; no types, no options). Verified on fgt02, FortiOS 8.0.1
  build0245: 2023 objects, 13610 fields.
* **REST schema** -- ``GET /api/v2/cmdb/<path>/<name>?action=schema`` answers
  the object's schema: ``{"name", "category": "table"|"complex", "mkey",
  "mkey_type", "help", "children": {field: {"name", "category": "unitary"|
  "table"|"complex", "type", "help", "size", "min-value", "max-value",
  "options": [{"name", "help"}], "default", "datasource": [...],
  "multiple_values"}}}``. The whole cmdb at once is ``GET /api/v2/cmdb/?action=schema``
  (a list of such objects, each with its ``path``).

  NOT VERIFIED against a box: fgt02 is an unlicensed evaluation VM and answers
  401 to every cmdb read, ``?action=schema`` included (confirmed 2026-10-07:
  ``/api/v2/cmdb/system/global?action=schema`` and ``/api/v2/cmdb/?action=schema``
  -> 401; only ``/api/v2/monitor/license/status`` answers). The parser follows the
  documented FortiOS schema format; the fixture it is tested with is written
  in that format, not captured.

The schema evidence is keyed exactly like the CLI evidence (``a.b/c``, the
FortiOS rule of ``cli_schema.rest_path``), and a nested table is a FIELD of its
top-level object with ``type = "table"`` and ``children`` -- the shape
``cli_schema`` folds a nested ``tree`` table into -- so the two channels join
field by field.

FortiGate is catalog-only in SATOM (no FortiGate appliance is managed), so the
adapter is not live: evidence arrives by pack (the separate harvester tool
runs the same parser against a device) or by ``flask apilib schema-import``.
"""
from __future__ import annotations

from . import Adapter, Capabilities, Verification, register

PRODUCT = "fortigate"
URN_PREFIX = "/api/v2/cmdb/"

UNVERIFIED = {
    "rest_schema": "fgt02 (FortiOS 8.0.1, unlicensed eval VM) answers 401 to "
                   "?action=schema; parser follows the documented FortiOS format",
}

#: Statuses that mean "this box will not show its schema" rather than "this
#: object does not exist": licence/auth gates.
GATED_STATUSES = (401, 403)


class SchemaGated(RuntimeError):
    """The device refused the schema read as a whole (licence or auth)."""


def _key(path: str, name: str) -> str:
    return "%s/%s" % (path, name) if path else name


def _cli_path(path: str, name: str) -> str:
    return " ".join([p for p in path.split(".") if p] + [name])


def _field(node: dict) -> dict:
    """One ``unitary`` child -> field spec (type raw FortiOS type, attrs)."""
    t = str(node.get("type") or "") or None
    opts = []
    for o in node.get("options") or []:
        if isinstance(o, dict) and o.get("name") is not None:
            opts.append(str(o["name"]))
        elif isinstance(o, str):
            opts.append(o)
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
    if node.get("datasource"):
        attrs["datasource"] = True
    if node.get("multiple_values"):
        attrs["multiple"] = True
    spec = {"type": t, "options": opts or None, "attrs": attrs}
    if node.get("default") not in (None, ""):
        spec["default"] = node["default"]
    return spec


def _nested(node: dict) -> dict:
    """A ``table``/``complex`` child -> the folded field cli_schema makes of a
    nested ``tree`` object: ``type`` = its kind, ``children`` = its names."""
    kind = "table" if node.get("category") == "table" else "singleton"
    attrs = {"help": str(node["help"])} if node.get("help") else {}
    if node.get("mkey"):
        attrs["mkey"] = str(node["mkey"])
    return {"type": kind, "options": None,
            "children": sorted(str(k) for k in (node.get("children") or {})),
            "attrs": attrs}


def endpoint_from_schema(path: str, name: str, node: dict) -> tuple[str, dict, dict]:
    """``(key, endpoint, summary object)`` of one object's schema."""
    key = _key(path, name)
    fields = {}
    for fname, child in (node.get("children") or {}).items():
        if not isinstance(child, dict):
            continue
        if child.get("category") in ("table", "complex"):
            fields[str(fname)] = _nested(child)
        else:
            fields[str(fname)] = _field(child)
    kind = "table" if node.get("category") == "table" else "singleton"
    meta = {"cli_path": _cli_path(path, name), "kind": kind,
            "mkey": str(node.get("mkey") or ""), "parent": "", "cli_id": None}
    attrs = dict(meta)
    if node.get("help"):
        attrs["help"] = str(node["help"])
    ep = {"urn": URN_PREFIX + key, "section": path.split(".", 1)[0] if path else name,
          "verdict": "ok", "rows": None, "fields": fields, "attrs": attrs}
    return key, ep, meta


def _entries(body) -> list:
    """Accept the three shapes a capture may hold:

    * ``{"results": [{"path", "name", "schema"|children...}, ...]}`` (whole cmdb);
    * ``{"results": {...}, "path": "system", "name": "global"}`` (one object);
    * ``{"<path>/<name>": <one-object response>, ...}`` (a per-object capture).
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
        out.append((str(body.get("path") or ""), str(body.get("name") or res.get("name") or ""),
                    res))
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

    ``errors`` = ``{key: http_status}`` for objects whose schema read failed;
    they are recorded ``verdict = "error"`` (never absent: a refused read says
    nothing about the object).
    """
    from .. import firmware_versions as fv
    endpoints, objects = {}, {}
    for path, name, node in _entries(body):
        key, ep, meta = endpoint_from_schema(path, name, node)
        endpoints[key] = ep
        objects[key] = meta
    for key, status in sorted((errors or {}).items()):
        endpoints.setdefault(key, {"urn": URN_PREFIX + key, "section": key.split(".", 1)[0]
                                   .split("/", 1)[0], "verdict": "error", "rows": None,
                                   "fields": None, "attrs": {"http_status": status}})
    doc = {"product": PRODUCT, "source": "schema", "captured_at": str(captured_at or "")[:19],
           "origin_ref": origin_ref or "", "device": device,
           "scope": {"kind": "build", "version": fv.normalize(version) or str(version or ""),
                     "build": build or ""},
           "healthy": True, "skip_reason": "", "endpoints": endpoints,
           "summary": {"objects": objects, "format": "fortios_action_schema",
                       "verified": False,
                       "counts": {"endpoints": len(endpoints),
                                  "fields": sum(len(e.get("fields") or {})
                                                for e in endpoints.values()),
                                  "errors": len(errors or {})}}}
    errs = sum(1 for e in endpoints.values() if e["verdict"] == "error")
    if not endpoints:
        doc.update(healthy=False, skip_reason="the schema answer holds no object")
    elif errs / len(endpoints) > 0.25:
        doc.update(healthy=False, skip_reason="%d/%d schema reads failed" % (errs, len(endpoints)))
    return doc


def capture(get, keys=None) -> tuple[dict, dict]:
    """Read the schema through ``get(url) -> (status, json)``. GET only.

    Without ``keys`` one request for the whole cmdb; with ``keys`` (the tree's
    objects) one request per object. Raises :class:`SchemaGated` when the very
    first answer is a licence/auth refusal: a box that refuses everything must
    not be recorded as a build whose objects all errored.
    """
    if not keys:
        status, body = get(URN_PREFIX + "?action=schema")
        if status in GATED_STATUSES:
            raise SchemaGated("HTTP %s on %s?action=schema" % (status, URN_PREFIX))
        if status != 200:
            raise RuntimeError("HTTP %s on %s?action=schema" % (status, URN_PREFIX))
        return body, {}
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


ADAPTER = register(Adapter(
    product=PRODUCT, label="FortiGate",
    capabilities=Capabilities(tree=True, show_full=True, rest_schema=True, rest_probe=False),
    verified_on=(Verification("2026-10-07", "fgt02 (lab)", "8.0.1 build0245",
                              "CLI tree only; REST is licence-gated (401) on the eval VM"),),
    unverified=UNVERIFIED, live=False,
    notes="Catalog-only in SATOM: evidence arrives by pack (satom-harvester) or by "
          "`flask apilib schema-import`. REST-channel facts come from ?action=schema "
          "when a licensed box answers it."),
    None)


__all__ = ["PRODUCT", "UNVERIFIED", "SchemaGated", "endpoint_from_schema",
           "evidence_from_schema", "capture", "ADAPTER"]
