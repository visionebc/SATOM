"""API Catalog -- the endpoint list of one API version, without a database.

An *operation* is one endpoint of an API version::

    {"id": "getHost", "method": "GET", "path": "/hosts/{id}",
     "summary": "One host", "params": [{"name": "id", "in": "path",
     "required": True, "type": "integer"}], "body": False,
     "tags": ["hosts"], "deprecated": False}

This module turns an OpenAPI 3 / Swagger 2 document (JSON or YAML) or a list a
person typed into that shape, checks it, matches a request against it and
compares two versions. ``services.studio_apis`` stores it; the connection
broker (``studio_broker``, DATABASE-FREE like the Script Library runner)
resolves ``connection("x").op("getHost")`` with it, so it imports nothing of
the database.

Paths are relative to the connection's base URL, exactly as a step or a script
writes them. Matching is by segment, the way ``studio_http.build_url`` sends
them: empty segments (a doubled or trailing slash) are dropped, and
``{name}`` in the catalog matches any one segment. A path parameter value is
percent-encoded into ONE segment; ``build_url`` refuses an encoded ``/``, so a
value can never reach another endpoint.
"""
from __future__ import annotations

import json
import re
from urllib.parse import quote

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
PARAM_IN = ("path", "query", "header", "body")
MAX_OPERATIONS = 3000
MAX_SPEC_BYTES = 8 * 1024 * 1024

_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_.-]{1,64})\}")
_TEMPLATE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.S)
_WILD = "\x00"


class SpecError(ValueError):
    """The document or the list cannot be used; the text says why."""


# --------------------------------------------------------------------------- #
#  one operation                                                               #
# --------------------------------------------------------------------------- #
def clean_path(path: str) -> str:
    path = str(path or "").strip()
    if not path.startswith("/"):
        path = "/" + path
    if _CTRL.search(path) or len(path) > 500:
        raise SpecError("path %r has control characters or is too long" % path[:80])
    if "://" in path or path.startswith("//") or "\\" in path or "?" in path or "#" in path:
        raise SpecError("path %r must be a plain path under the base URL" % path[:80])
    if any(seg in ("..", ".") for seg in path.split("/")):
        raise SpecError("path %r cannot hold . or .. segments" % path[:80])
    return path


def _auto_id(method: str, path: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", path).strip("_") or "root"
    return ("%s_%s" % (method.lower(), slug))[:128]


def clean_operation(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise SpecError("an endpoint is an object")
    method = str(raw.get("method") or "GET").strip().upper()
    if method not in METHODS:
        raise SpecError("method %r: one of %s" % (method, ", ".join(METHODS)))
    path = clean_path(raw.get("path") or "")
    oid = str(raw.get("id") or "").strip() or _auto_id(method, path)
    if not _ID_RE.match(oid):
        raise SpecError("endpoint id %r: letters, digits and _ . : -, up to 128" % oid[:80])
    params, seen = [], set()
    placeholders = set(_PLACEHOLDER.findall(path))
    for p in raw.get("params") or []:
        if not isinstance(p, dict) or not str(p.get("name") or "").strip():
            continue
        name = str(p["name"]).strip()[:64]
        where = str(p.get("in") or "query")
        if where not in PARAM_IN or (name, where) in seen:
            continue
        if where == "path" and name not in placeholders:
            continue                    # the path no longer has {name}
        seen.add((name, where))
        params.append({"name": name, "in": where,
                       "required": bool(p.get("required")) or where == "path",
                       "type": str(p.get("type") or "string")[:32]})
    for name in _PLACEHOLDER.findall(path):
        if (name, "path") not in seen:
            params.append({"name": name, "in": "path", "required": True, "type": "string"})
            seen.add((name, "path"))
    return {"id": oid, "method": method, "path": path,
            "summary": _CTRL.sub(" ", str(raw.get("summary") or "")).strip()[:300],
            "params": params, "body": bool(raw.get("body")),
            "tags": [str(t)[:64] for t in (raw.get("tags") or []) if str(t).strip()][:10],
            "deprecated": bool(raw.get("deprecated"))}


def clean_operations(raw_list) -> list[dict]:
    """Every endpoint checked; ids and (method, path) pairs unique."""
    if not isinstance(raw_list, list):
        raise SpecError("the endpoints are a list")
    if len(raw_list) > MAX_OPERATIONS:
        raise SpecError("more than %d endpoints in one version" % MAX_OPERATIONS)
    out, ids, pairs = [], set(), set()
    for i, raw in enumerate(raw_list, 1):
        try:
            op = clean_operation(raw)
        except SpecError as exc:
            raise SpecError("endpoint %d: %s" % (i, exc)) from None
        if op["id"] in ids:
            raise SpecError("endpoint id %s is used twice" % op["id"])
        if (op["method"], op["path"]) in pairs:
            raise SpecError("%s %s is listed twice" % (op["method"], op["path"]))
        ids.add(op["id"])
        pairs.add((op["method"], op["path"]))
        out.append(op)
    return sorted(out, key=lambda o: (o["path"], METHODS.index(o["method"])))


# --------------------------------------------------------------------------- #
#  OpenAPI / Swagger                                                           #
# --------------------------------------------------------------------------- #
def load_document(text: str) -> dict:
    """JSON, or YAML (safe loader). Never executes anything."""
    if len(text.encode("utf-8", "replace")) > MAX_SPEC_BYTES:
        raise SpecError("the document is larger than %d MiB" % (MAX_SPEC_BYTES // 1024 // 1024))
    text = text.lstrip("﻿")
    try:
        doc = json.loads(text)
    except ValueError:
        try:
            import yaml
            doc = yaml.safe_load(text)
        except Exception as exc:  # noqa: BLE001 -- any parser error, shown
            raise SpecError("neither JSON nor YAML: %s" % str(exc)[:200]) from None
    if not isinstance(doc, dict):
        raise SpecError("the document is not an object")
    return doc


def _local_ref(doc: dict, obj):
    """``{"$ref": "#/components/parameters/x"}`` -> the object; one level,
    this document only (a remote reference is never fetched)."""
    if not isinstance(obj, dict) or "$ref" not in obj:
        return obj
    ref = str(obj["$ref"])
    if not ref.startswith("#/"):
        return {}
    cur = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        cur = cur.get(part) if isinstance(cur, dict) else None
        if cur is None:
            return {}
    return cur if isinstance(cur, dict) else {}


def _param(doc: dict, raw) -> dict | None:
    p = _local_ref(doc, raw)
    if not isinstance(p, dict) or not p.get("name"):
        return None
    schema = _local_ref(doc, p.get("schema") or {})
    typ = p.get("type") or (schema.get("type") if isinstance(schema, dict) else "") or "string"
    return {"name": p["name"], "in": p.get("in") or "query",
            "required": bool(p.get("required")), "type": str(typ)}


def parse_openapi(text: str) -> dict:
    """``{"title", "version", "base_path", "operations", "warnings"}`` from an
    OpenAPI 3.x or Swagger 2.0 document."""
    doc = load_document(text)
    swagger = str(doc.get("swagger") or "")
    openapi = str(doc.get("openapi") or "")
    if not swagger.startswith("2") and not openapi.startswith("3"):
        raise SpecError("not an OpenAPI 3 or Swagger 2 document (no openapi/swagger field)")
    paths = doc.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise SpecError("the document has no paths")
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    if swagger:
        base_path = str(doc.get("basePath") or "")
    else:
        servers = doc.get("servers") or []
        url = str(servers[0].get("url") or "") if servers and isinstance(servers[0], dict) else ""
        m = re.match(r"^(?:[a-z]+://[^/]+)?(/[^?#]*)?", url)
        base_path = (m.group(1) or "") if m else ""
    base_path = base_path.rstrip("/")
    warnings, raw_ops = [], []
    for path, item in paths.items():
        item = _local_ref(doc, item)
        if not isinstance(item, dict):
            continue
        shared = [x for x in (_param(doc, r) for r in item.get("parameters") or []) if x]
        for m_name, op in item.items():
            method = str(m_name).upper()
            if method not in METHODS:
                if method in ("HEAD", "OPTIONS", "TRACE"):
                    warnings.append("%s %s skipped: SATOM calls %s only"
                                    % (method, path, "/".join(METHODS)))
                continue
            if not isinstance(op, dict):
                continue
            params = {(p["name"], p["in"]): p for p in shared}
            for r in op.get("parameters") or []:
                p = _param(doc, r)
                if p:
                    params[(p["name"], p["in"])] = p
            body = bool(op.get("requestBody")) or any(k[1] in ("body", "formData") for k in params)
            raw_ops.append({
                "id": op.get("operationId") or "", "method": method, "path": path,
                "summary": op.get("summary") or op.get("description") or "",
                "params": [p for k, p in params.items() if k[1] in PARAM_IN],
                "body": body, "tags": op.get("tags") or [],
                "deprecated": bool(op.get("deprecated"))})
    # An operationId that is not a usable id (spaces, too long) or a repeated
    # one is replaced by the generated method_path id, and said so.
    ids: set[str] = set()
    for op in raw_ops:
        oid = str(op["id"] or "")
        if oid and (not _ID_RE.match(oid) or oid in ids):
            warnings.append("operationId %r replaced by %s" % (oid[:60], _auto_id(op["method"], op["path"])))
            op["id"] = ""
        ids.add(op["id"] or _auto_id(op["method"], op["path"]))
    return {"title": str(info.get("title") or "")[:120], "version": str(info.get("version") or "")[:32],
            "base_path": base_path[:200], "operations": clean_operations(raw_ops),
            "warnings": warnings[:50]}


# --------------------------------------------------------------------------- #
#  matching and filling                                                        #
# --------------------------------------------------------------------------- #
def _segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s not in ("", ".")]


def _seg_match(want: str, have: str) -> bool:
    if _PLACEHOLDER.fullmatch(have):
        return want != ""
    if _WILD in want:
        rx = "^" + ".*".join(re.escape(x) for x in want.split(_WILD)) + "$"
        return bool(re.match(rx, have))
    return want == have


def find(operations: list[dict], method: str, path: str, *, template: bool = False) -> dict | None:
    """The catalog endpoint a request (*method*, *path*) hits, or None. With
    *template*, ``{{ ... }}`` parts of *path* (an app step not rendered yet)
    match any text."""
    method = (method or "GET").upper()
    path = str(path or "").split("?", 1)[0].split("#", 1)[0]
    if template:
        path = _TEMPLATE.sub(_WILD, path)
    if not path.startswith("/"):
        path = "/" + path
    want = _segments(path)
    for op in operations or []:
        if op.get("method") != method:
            continue
        have = _segments(op.get("path") or "")
        if len(have) == len(want) and all(_seg_match(w, h) for w, h in zip(want, have)):
            return op
    return None


def by_id(operations: list[dict], oid: str) -> dict | None:
    for op in operations or []:
        if op.get("id") == oid:
            return op
    return None


def fill_path(op: dict, values: dict | None) -> str:
    """The endpoint's path with every ``{name}`` replaced by its value,
    percent-encoded (a value can never add a segment)."""
    values = values if isinstance(values, dict) else {}
    missing = [n for n in _PLACEHOLDER.findall(op["path"])
               if values.get(n) in (None, "")]
    if missing:
        raise SpecError("endpoint %s needs path parameter(s) %s" % (op["id"], ", ".join(missing)))
    return _PLACEHOLDER.sub(lambda m: quote(str(values[m.group(1)]), safe=""), op["path"])


def label(op: dict) -> str:
    return "%s %s" % (op.get("method"), op.get("path"))


# --------------------------------------------------------------------------- #
#  comparing two versions                                                      #
# --------------------------------------------------------------------------- #
_COMPARED = ("method", "path", "params", "body", "deprecated")


def diff(old: list[dict], new: list[dict]) -> dict:
    """``{added, removed, changed, same}`` by endpoint id. ``changed`` entries
    are ``{"id", "fields": [...], "old", "new"}``. A removed id is what breaks
    the apps and scripts that call it."""
    a = {o["id"]: o for o in old or []}
    b = {o["id"]: o for o in new or []}
    changed, same = [], 0
    for oid in sorted(set(a) & set(b)):
        fields = [f for f in _COMPARED if _norm(a[oid].get(f)) != _norm(b[oid].get(f))]
        if fields:
            changed.append({"id": oid, "fields": fields, "old": a[oid], "new": b[oid]})
        else:
            same += 1
    return {"added": [b[k] for k in sorted(set(b) - set(a))],
            "removed": [a[k] for k in sorted(set(a) - set(b))],
            "changed": changed, "same": same}


def _norm(v):
    if isinstance(v, list):
        return sorted(json.dumps(x, sort_keys=True) for x in v)
    return v


# --------------------------------------------------------------------------- #
#  what a connection carries to the runner                                     #
# --------------------------------------------------------------------------- #
def compact(operations: list[dict]) -> list[dict]:
    """The fields the broker and ``.operations()`` need."""
    return [{"id": o["id"], "method": o["method"], "path": o["path"],
             "summary": o.get("summary", ""), "body": bool(o.get("body")),
             "params": [p for p in o.get("params") or [] if p.get("in") in ("path", "query")]}
            for o in operations or []]
