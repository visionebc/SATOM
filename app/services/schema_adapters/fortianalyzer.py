"""FortiAnalyzer: JSON-RPC ``get`` with ``option: syntax`` (UNVERIFIED -- no device).

FortiAnalyzer's API is JSON-RPC (``POST /jsonrpc``), and its global system
configuration lives under ``/cli/global/...`` URLs that ARE the CLI paths:

    config system admin user            <->  /cli/global/system/admin/user
    config system admin user / dashboard <-> /cli/global/system/admin/user/{user}/dashboard

So the CLI channel and the API channel of FAZ are one channel spelled two
ways, and the schema comes from the API itself: a ``get`` with
``"option": ["syntax"]`` answers the attribute syntax of the object (the
FortiManager/FortiAnalyzer JSON-RPC framework), documented as::

    {"result": [{"data": {"firewall address": {
        "alimit": 400000,
        "attr": {"allow-routing": {"default": "disable", "help": "...",
                                   "opts": {"disable": 0, "enable": 1},
                                   "sz": 4, "type": "uint32"},
                 "ztna-geo-tag": {"help": "...", "max_argv": -1, "type": "datasrc",
                                  "ref": [{"category": "firewall address", "mkey": "name"}]}}}},
                 "status": {"code": 0, "message": "OK"}, "url": "..."}]}

(source: "The option attribute" -> "syntax", How-to FortiManager API,
how-to-fortimanager-api.readthedocs.io, read 2026-10-07; the same JSON-RPC
engine serves FortiAnalyzer). The ``data`` key is the CLI path with spaces --
the mapping below relies on it.

EVERYTHING here is :data:`UNVERIFIED`: there is no FortiAnalyzer in the lab.
The path rule and the response shape are vendor-documented (FortiManager
examples), never measured on a FAZ build. The channel key is the URL without
its leading ``/`` (``cli/global/system/admin/user``) -- exactly what
``api_library.urn_key`` makes of the URLs the vendor Ansible evidence
(``fortinet.fortianalyzer``) carries, so the two join.
"""
from __future__ import annotations

import re

from . import Adapter, Capabilities, register

PRODUCT = "fortianalyzer"
URL_PREFIX = "/cli/global/"
#: The whole adapter is unverified; the UI shows these reasons.
UNVERIFIED = {
    "path_rule": "CLI <-> /cli/global/... mapping is documented, not measured (no FAZ lab)",
    "rest_schema": "option=syntax response shape from FortiManager documentation; "
                   "never read from a FortiAnalyzer",
    "nested": "nested tables follow the {parent} placeholder convention of the vendor "
              "Ansible URLs; unchecked",
}
#: FMG/FAZ JSON-RPC ``type`` -> library type.
_TYPES = {"uint32": "integer", "int32": "integer", "uint8": "integer", "uint16": "integer",
          "uint64": "integer", "string": "string", "datasrc": "datasource",
          "ipv4": "ip", "ipv4mask": "ipmask", "ipv6": "ipv6", "ipv6prefix": "ipv6",
          "password": "password", "user": "string", "color": "integer"}


def jsonrpc_url(cli_path: str, parents=()) -> str:
    """``config system admin user`` -> ``/cli/global/system/admin/user``.

    ``parents`` = the enclosing TABLES' CLI paths, outermost first: each one
    contributes a ``{<its last word>}`` row placeholder before the child, the
    form of the vendor's own URLs (``.../admin/user/{user}/dashboard``).
    """
    words = cli_path.split()
    url = URL_PREFIX.rstrip("/")
    done = 0
    for parent in parents:
        pw = parent.split()
        if words[:len(pw)] != pw or len(pw) <= done:
            raise ValueError("%r is not under %r" % (cli_path, parent))
        url += "/" + "/".join(pw[done:]) + "/{%s}" % pw[-1]
        done = len(pw)
    return url + "/" + "/".join(words[done:])


_PLACEHOLDER = re.compile(r"^\{[^{}/]+\}$")


def cli_path(url: str) -> str:
    """Inverse of :func:`jsonrpc_url`: drop the prefix and the row placeholders."""
    u = (url or "").split("?", 1)[0]
    if not u.startswith(URL_PREFIX):
        raise ValueError("%r is not a /cli/global/ URL" % url)
    parts = [p for p in u[len(URL_PREFIX):].split("/") if p and not _PLACEHOLDER.match(p)]
    return " ".join(parts)


def channel_key(url: str) -> str:
    """The library key of a JSON-RPC URL (what ``urn_key`` makes of it)."""
    return (url or "").split("?", 1)[0].strip("/")


def syntax_request(url: str, req_id: int = 1, session: str = "") -> dict:
    """The read-only JSON-RPC request for one object's syntax."""
    req = {"id": req_id, "method": "get", "params": [{"url": url, "option": ["syntax"]}]}
    if session:
        req["session"] = session
    return req


def _field(spec: dict) -> dict:
    t = str(spec.get("type") or "") or None
    opts = spec.get("opts")
    options = sorted(opts, key=lambda k: (opts[k], k)) if isinstance(opts, dict) and opts else None
    attrs: dict = {}
    if t:
        attrs["cli_type"] = t
    if spec.get("help"):
        attrs["help"] = str(spec["help"])
    if isinstance(spec.get("min"), int) and isinstance(spec.get("max"), int) and t != "string":
        attrs["range"] = [spec["min"], spec["max"]]
    if isinstance(spec.get("sz"), int) and t == "string":
        attrs["size"] = spec["sz"]
    if t == "datasrc" or spec.get("ref"):
        attrs["datasource"] = True
    out = {"type": "option" if options else _TYPES.get(t or "", t), "options": options,
           "attrs": attrs}
    if spec.get("default") not in (None, ""):
        out["default"] = spec["default"]
    return out


def evidence_from_syntax(responses: dict, version: str, build: str, device: dict | None,
                         origin_ref: str, *, captured_at: str = "", parents: dict | None = None
                         ) -> dict:
    """``{url: json-rpc response}`` of syntax reads -> ``schema`` evidence.

    Each response's ``result[0].data`` maps CLI paths (``"system admin user"``)
    to ``{"attr": {...}, "alimit"?, ...}``; every entry becomes one endpoint
    keyed by the JSON-RPC URL it maps to. ``parents`` = ``{cli_path: [table
    paths]}`` for nested objects. ``status.code != 0`` -> ``verdict = "error"``.
    Stored with ``summary.verified = False``.
    """
    from .. import firmware_versions as fv
    endpoints, objects = {}, {}
    for url, resp in sorted((responses or {}).items()):
        result = ((resp or {}).get("result") or [{}])[0] if isinstance(resp, dict) else {}
        code = ((result.get("status") or {}).get("code"))
        if code not in (0, None) or not isinstance(result.get("data"), dict):
            key = channel_key(url)
            endpoints[key] = {"urn": url, "section": key.split("/")[2] if key.count("/") >= 2
                              else key, "verdict": "error", "rows": None, "fields": None,
                              "attrs": {"jsonrpc_code": code}}
            continue
        data = {p: n for p, n in result["data"].items()
                if isinstance(n, dict) and isinstance(n.get("attr"), dict)}
        for path, node in data.items():
            given = (parents or {}).get(path)
            if given is None:
                # An object whose CLI path extends another answered object is
                # nested in it (one syntax read of a parent URL answers its
                # sub-tables too).
                given = sorted((q for q in data if path.startswith(q + " ")), key=len)
            u = jsonrpc_url(path, given)
            key = channel_key(u)
            fields = {str(f): _field(s if isinstance(s, dict) else {})
                      for f, s in node["attr"].items()}
            meta = {"cli_path": path, "kind": "table" if node.get("alimit") is not None
                    or node.get("mkey") else "object",
                    "mkey": str(node.get("mkey") or ""), "parent": "", "cli_id": None}
            endpoints[key] = {"urn": u, "section": path.split()[0], "verdict": "ok",
                              "rows": None, "fields": fields, "attrs": dict(meta)}
            objects[key] = meta
    doc = {"product": PRODUCT, "source": "schema", "captured_at": str(captured_at or "")[:19],
           "origin_ref": origin_ref or "", "device": device,
           "scope": {"kind": "build", "version": fv.normalize(version) or str(version or ""),
                     "build": build or ""},
           "healthy": bool(endpoints), "skip_reason": "" if endpoints else "no syntax answer",
           "endpoints": endpoints,
           "summary": {"objects": objects, "format": "jsonrpc_syntax", "verified": False,
                       "unverified": sorted(UNVERIFIED)}}
    return doc


#: One syntax read per root answers every object below it (documented for
#: FortiManager: "Syntax for all kind of objects tables: url .../obj").
SYNTAX_ROOTS = ("/cli/global/system", "/cli/global/fmupdate")


def harvest(appliance, *, client=None, roots=SYNTAX_ROOTS, now=None, **_ignored) -> dict:
    """Live syntax read of a FortiAnalyzer (JSON-RPC ``get`` only). NEVER raises.

    UNVERIFIED: written against the documented FortiManager behaviour; the
    result names the gap (``unverified``) so a run is never read as checked.
    """
    from datetime import datetime

    from .. import api_library as lib
    from .. import firmware_versions as fv
    name = getattr(appliance, "name", "") or "?"
    out = {"ok": False, "appliance": name, "product": PRODUCT, "version": "",
           "unverified": sorted(UNVERIFIED), "schema": None}
    try:
        raw_fw = getattr(appliance, "fw_version", "") or getattr(appliance, "firmware", "") or ""
        version = fv.normalize(raw_fw)
        if not version or fv.is_line_only(version):
            return dict(out, reason="firmware_unknown",
                        msg="the running build of %s is unknown" % name)
        out["version"] = version
        client = client or appliance.build_client()
        responses = {}
        for url in roots:
            responses[url] = client.rpc("get", url, option=["syntax"])
        now = now or datetime.utcnow()
        device = {"appliance_id": getattr(appliance, "id", None), "name": name,
                  "model": str(getattr(appliance, "model", "") or ""),
                  "hw_type": str(getattr(appliance, "hw_type", "") or ""),
                  "firmware_raw": str(getattr(appliance, "firmware", "") or "")}
        doc = evidence_from_syntax(responses, version, lib._build_token(raw_fw), device,
                                   "schema_adapter:%s@%s" % (getattr(appliance, "id", ""),
                                                             version),
                                   captured_at=now.isoformat(timespec="seconds"))
        res = lib.ingest(doc, raw={"doc": doc, "roots": list(roots)})
        out["schema"] = {"evidence_id": res["evidence_id"], "healthy": doc["healthy"],
                         "endpoints": len(doc["endpoints"])}
    except Exception as exc:  # noqa: BLE001
        try:
            from ...extensions import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return dict(out, reason="error", msg=("%s: %s" % (type(exc).__name__, exc))[:300])
    ok = bool(out["schema"]["healthy"])
    return dict(out, ok=ok, reason="" if ok else "unhealthy",
                msg="FAZ %s syntax read (UNVERIFIED adapter): %d objects" % (
                    out["version"], out["schema"]["endpoints"]))


ADAPTER = register(Adapter(
    product=PRODUCT, label="FortiAnalyzer",
    capabilities=Capabilities(tree=False, show_full=False, rest_schema=True, rest_probe=False),
    verified_on=(), unverified=UNVERIFIED, live=True, cli_source="schema",
    notes="JSON-RPC /cli/global/... URLs are the CLI paths; schema via get + "
          "option=syntax. No FortiAnalyzer in the lab: everything is documented "
          "behaviour, flagged unverified."),
    harvest)


__all__ = ["PRODUCT", "UNVERIFIED", "jsonrpc_url", "cli_path", "channel_key",
           "syntax_request", "evidence_from_syntax", "harvest", "SYNTAX_ROOTS", "ADAPTER"]
