"""FortiAnalyzer: JSON-RPC ``get`` with ``option: syntax``, walked per OBJECT.

FortiAnalyzer's API is JSON-RPC (``POST /jsonrpc``), and its global system
configuration lives under ``/cli/global/...`` URLs that ARE the CLI paths:

    config system admin user            <->  /cli/global/system/admin/user
    config system admin user / dashboard <-> /cli/global/system/admin/user/{user}/dashboard

So the CLI channel and the API channel of FAZ are one channel spelled two
ways, and the schema comes from the API itself.

Measured on a FortiAnalyzer-VM64-KVM 7.6.7 build3737 (the harvester,
``satom_harvester/faz.py``, 2026-10-12) -- NOT the documented FortiManager
format the first version of this adapter assumed:

* ``syntax`` answers one OBJECT, never a branch: ``/cli/global/system`` is
  ``-3 Object does not exist`` (the old ``SYNTAX_ROOTS`` read of
  ``/cli/global/system`` and ``/cli/global/fmupdate`` measured nothing). The
  walk asks a catalog -- the URLs SATOM's API library and registry know --
  object by object and follows each node's ``subobj`` list.
* The answer is ``data = {"/system/global": {"type": "obj"|"table", "mkey",
  "subobj": [...], "attr": {field: {type, sz, max, default, opts}}}}`` -- one
  node, keyed by a slash path (a child: by its bare name).
* A child of a table is only answered under a REAL row
  (``.../interface/port1/ipv6``); a made-up row is ``-3``. The walk reads the
  table once, keeps the first row's key and drops the row data; a table with
  no row leaves its children unasked (``summary.not_probed``).
* ``-3`` = absent on this build; ``-11`` (no permission) and any other code =
  an error, NOT measured (never an absence).
* :data:`MAX_REQUESTS` caps one walk (7.6.7 needs a few hundred requests).

The documented multi-node shape (``{"system admin user": {...}, ...}``) is
still read, for answers saved before this was measured.

Read-only: every request is ``get`` (with or without the syntax option).
"""
from __future__ import annotations

import re

from . import Adapter, Capabilities, register

PRODUCT = "fortianalyzer"
URL_PREFIX = "/cli/global/"
#: CLI sections that live under ``/cli/global/`` (a vendor catalog URL outside
#: them -- ``/dvmdb``, ``/eventmgmt`` ... -- is ADOM data, not configuration).
SECTIONS = ("system", "fmupdate")
#: What is still not checked (the UI shows these reasons).
UNVERIFIED = {
    "rest_schema": "the per-object syntax walk is the harvester's, measured on a "
                   "FortiAnalyzer 7.6.7 build3737 lab unit (2026-10-12); SATOM's port of it "
                   "has not run against a device yet",
}
#: Hard cap on the requests one walk sends.
MAX_REQUESTS = 3000
#: ``syntax`` / ``get`` status of an object this build does not have.
ABSENT_CODE = -3
#: FMG/FAZ JSON-RPC ``type`` -> library type.
_TYPES = {"uint32": "integer", "int32": "integer", "uint8": "integer", "uint16": "integer",
          "uint64": "integer", "string": "string", "datasrc": "datasource",
          "ipv4": "ip", "ipv4mask": "ipmask", "ipv6": "ipv6", "ipv6prefix": "ipv6",
          "password": "password", "user": "string", "color": "integer"}
_PLACEHOLDER = re.compile(r"^\{[^{}/]+\}$")


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


def canonical_url(url: str) -> str:
    """A ``/cli/global`` URL whose placeholders are named after the table they
    follow (``.../admin/user/{user}/dashboard``), the vendor's own convention."""
    out = []
    for p in (url or "").split("?", 1)[0].split("/"):
        if p:
            out.append("{%s}" % out[-1] if _PLACEHOLDER.match(p) and out else p)
    return "/" + "/".join(out)


def catalog_urls(urls) -> list:
    """The configuration objects among ``urls`` (canonical, de-duplicated)."""
    out = set()
    for u in urls or ():
        u = canonical_url(str(u or ""))
        if u.startswith(URL_PREFIX) and u[len(URL_PREFIX):].split("/")[0] in SECTIONS \
                and u.count("/") >= 4:
            out.add(u)
    return sorted(out)


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


def _answer(resp) -> tuple:
    """``(status code, {node path: node})`` of one JSON-RPC answer."""
    result = (resp.get("result") or [{}]) if isinstance(resp, dict) else [{}]
    result = result[0] if isinstance(result, list) and result else result
    result = result if isinstance(result, dict) else {}
    data = result.get("data")
    nodes = {str(p): n for p, n in data.items()
             if isinstance(n, dict) and isinstance(n.get("attr"), dict)} \
        if isinstance(data, dict) else {}
    return (result.get("status") or {}).get("code"), nodes


def _fields(node: dict) -> dict:
    return {str(f): _field(s if isinstance(s, dict) else {}) for f, s in node["attr"].items()}


def _section(key: str) -> str:
    parts = key.split("/")
    return parts[2] if len(parts) > 2 else key


def _subobjects(node: dict) -> list:
    sub = node.get("subobj")
    return [str(s) for s in (sub if isinstance(sub, (list, dict)) else ())]


class _Budget(Exception):
    pass


def measure(get, catalog, *, max_requests: int = MAX_REQUESTS) -> tuple:
    """Ask ``syntax`` for every catalog URL and every sub-object an answer names.

    ``get(url, syntax)`` sends ONE JSON-RPC ``get`` (``syntax`` True: with
    ``option: ["syntax"]``) and returns the raw answer -- the only call made.
    -> ``({canonical url: answer}, {canonical url: why it was not asked})``.
    A child of a table is asked under the table's first REAL row (read once
    with a plain ``get``; only that row's key is kept, the row data dropped).
    """
    answers, not_probed, rows = {}, {}, {}
    sent = [0]

    def budget():
        if sent[0] >= max_requests:
            raise _Budget
        sent[0] += 1

    def row_of(table: str, real_table: str):
        if table not in rows:
            ask(table)
            code, nodes = _answer(answers.get(table))
            node = next(iter(nodes.values())) if code in (0, None) and len(nodes) == 1 else {}
            mkey, row = str(node.get("mkey") or ""), None
            if mkey:
                budget()
                res = get(real_table, False)
                result = (res.get("result") or [{}]) if isinstance(res, dict) else [{}]
                result = result[0] if isinstance(result, list) and result else result
                data = result.get("data") if isinstance(result, dict) else None
                for r in data if isinstance(data, list) else ():
                    v = r.get(mkey) if isinstance(r, dict) else None
                    if v not in (None, "") and "/" not in str(v):
                        row = str(v)
                        break
            rows[table] = (row, "" if row is not None else
                           not_probed.get(table) or ("no row in %s" % channel_key(table)
                                                     if mkey else "%s is not a measured table"
                                                     % channel_key(table)))
        return rows[table]

    def ask(url: str):
        if url in answers or url in not_probed:
            return
        parts, real = url.split("/"), []
        for i, p in enumerate(parts):
            if _PLACEHOLDER.match(p):
                table = "/".join(parts[:i])
                row, why = row_of(table, "/".join(real))
                if row is None:
                    not_probed[url] = why
                    return
                real.append(row)
            else:
                real.append(p)
        budget()
        answers[url] = get("/".join(real), True)
        code, nodes = _answer(answers[url])
        if code in (0, None) and len(nodes) == 1:
            node = next(iter(nodes.values()))
            hop = "/{%s}" % parts[-1] if node.get("type") == "table" else ""
            queue.extend("%s%s/%s" % (url, hop, s) for s in _subobjects(node))

    queue = sorted(set(catalog_urls(catalog)), key=lambda u: (u.count("/"), u))
    try:
        while queue:
            ask(queue.pop(0))
    except _Budget:
        for u in queue:
            not_probed.setdefault(u, "request budget (%d) spent" % max_requests)
    return answers, not_probed


def evidence_from_syntax(responses: dict, version: str, build: str, device: dict | None,
                         origin_ref: str, *, captured_at: str = "", parents: dict | None = None,
                         not_probed: dict | None = None) -> dict:
    """``{url: json-rpc response}`` of syntax reads -> ``schema`` evidence.

    Measured shape (7.6.7): one node per answer, the URL asked names it; the
    endpoint is that URL in its canonical form, a child's parent table is
    the URL before its last ``{placeholder}``. Documented shape (older saved
    answers): ``result[0].data`` maps CLI paths (``"system admin user"``) to
    nodes, a nested one found from the CLI path prefix (or ``parents`` =
    ``{cli_path: [table paths]}``). ``-3`` -> ``verdict = "absent"``, any other
    refusal -> ``"error"`` (not measured). ``summary.verified`` is True only
    when a measured-shape answer was read."""
    from .. import firmware_versions as fv
    endpoints, objects = {}, {}
    measured = False
    for url, resp in sorted((responses or {}).items()):
        code, nodes = _answer(resp)
        key = channel_key(url)
        if code in (0, None) and nodes and any(" " in p for p in nodes):
            for path, node in nodes.items():
                given = (parents or {}).get(path)
                if given is None:
                    given = sorted((q for q in nodes if path.startswith(q + " ")), key=len)
                u = jsonrpc_url(path, given)
                k = channel_key(u)
                meta = {"cli_path": path, "kind": "table" if node.get("alimit") is not None
                        or node.get("mkey") else "object",
                        "mkey": str(node.get("mkey") or ""), "parent": "", "cli_id": None}
                endpoints[k] = {"urn": u, "section": path.split()[0], "verdict": "ok",
                                "rows": None, "fields": _fields(node), "attrs": dict(meta)}
                objects[k] = meta
            continue
        if code in (0, None) and len(nodes) == 1:
            node = next(iter(nodes.values()))
            u = canonical_url(url)
            k = channel_key(u)
            parent = u.rsplit("/{", 1)[0] if "/{" in u else ""
            meta = {"cli_path": cli_path(u),
                    "kind": "table" if node.get("type") == "table" or node.get("mkey")
                    else "object", "mkey": str(node.get("mkey") or ""),
                    "parent": cli_path(parent) if parent else "", "cli_id": None}
            endpoints[k] = {"urn": u, "section": _section(k), "verdict": "ok", "rows": None,
                            "fields": _fields(node), "attrs": dict(meta)}
            objects[k] = meta
            measured = True
            continue
        endpoints[key] = {"urn": url, "section": _section(key),
                          "verdict": "absent" if code == ABSENT_CODE else "error",
                          "rows": None, "fields": None, "attrs": {"jsonrpc_code": code}}
    ok = any(e["verdict"] == "ok" for e in endpoints.values())
    summary = {"objects": objects, "format": "jsonrpc_syntax", "verified": measured,
               "unverified": sorted(UNVERIFIED) if measured
               else ["nested", "path_rule"] + sorted(UNVERIFIED)}
    if not_probed:
        summary["not_probed"] = {channel_key(u): why for u, why in sorted(not_probed.items())}
    return {"product": PRODUCT, "source": "schema", "captured_at": str(captured_at or "")[:19],
            "origin_ref": origin_ref or "", "device": device,
            "scope": {"kind": "build", "version": fv.normalize(version) or str(version or ""),
                      "build": build or ""},
            "healthy": ok, "skip_reason": "" if ok else "no syntax answer",
            "endpoints": endpoints, "summary": summary}


def known_urls() -> list:
    """The ``/cli/global`` objects SATOM knows by name for FortiAnalyzer: every
    API-library endpoint of the product (vendor documentation, earlier
    measurements of any build) and every registry URN."""
    urls = set()
    try:
        from ...models_apilib import ApiLibEndpoint
        for (name,) in ApiLibEndpoint.query.with_entities(ApiLibEndpoint.name) \
                .filter_by(product=PRODUCT).all():
            urls.add("/" + str(name or "").strip("/"))
    except Exception:  # noqa: BLE001 -- no library: the registry alone
        pass
    try:
        from ...registry import loader
        urls.update(str(u) for u in (loader.load_faz_registry() or {}).values())
    except Exception:  # noqa: BLE001
        pass
    return catalog_urls(urls)


def harvest(appliance, *, client=None, catalog=None, now=None,
            max_requests: int = MAX_REQUESTS, **_ignored) -> dict:
    """Live syntax walk of a FortiAnalyzer (JSON-RPC ``get`` only). NEVER raises.

    ``catalog``: the URLs to start from (default :func:`known_urls`). An empty
    catalog sends nothing. The result names what is still unverified."""
    from datetime import datetime

    from .. import api_library as lib
    from .. import firmware_versions as fv
    name = getattr(appliance, "name", "") or "?"
    out = {"ok": False, "appliance": name, "product": PRODUCT, "version": "",
           "unverified": sorted(UNVERIFIED), "schema": None}
    own = client is None
    try:
        raw_fw = getattr(appliance, "fw_version", "") or getattr(appliance, "firmware", "") or ""
        version = fv.normalize(raw_fw)
        if not version or fv.is_line_only(version):
            return dict(out, reason="firmware_unknown",
                        msg="the running build of %s is unknown" % name)
        out["version"] = version
        catalog = catalog_urls(known_urls() if catalog is None else catalog)
        if not catalog:
            return dict(out, reason="no_catalog",
                        msg="SATOM knows no FortiAnalyzer /cli/global object to ask about "
                            "(import the fortianalyzer API library or registry first)")
        client = client or appliance.build_client()

        def get(url, syntax):
            return client.rpc("get", url, **({"option": ["syntax"]} if syntax else {}))
        try:
            responses, not_probed = measure(get, catalog, max_requests=max_requests)
        finally:
            if own:
                try:
                    client.logout()
                except Exception:  # noqa: BLE001
                    pass
        now = now or datetime.utcnow()
        device = {"appliance_id": getattr(appliance, "id", None), "name": name,
                  "model": str(getattr(appliance, "model", "") or ""),
                  "hw_type": str(getattr(appliance, "hw_type", "") or ""),
                  "firmware_raw": str(getattr(appliance, "firmware", "") or "")}
        doc = evidence_from_syntax(responses, version, lib._build_token(
            getattr(appliance, "firmware", "") or raw_fw), device,
            "schema_adapter:%s@%s" % (getattr(appliance, "id", ""), version),
            captured_at=now.isoformat(timespec="seconds"), not_probed=not_probed)
        if not doc["healthy"]:
            return dict(out, reason="unhealthy",
                        msg="FAZ %s answered no syntax for %d catalog objects" % (
                            version, len(catalog)))
        res = lib.ingest(doc, raw={"doc": doc, "catalog": catalog})
        verdicts = [e["verdict"] for e in doc["endpoints"].values()]
        out["schema"] = {"evidence_id": res["evidence_id"], "healthy": doc["healthy"],
                         "endpoints": len(doc["endpoints"]), "measured": verdicts.count("ok"),
                         "absent": verdicts.count("absent"), "error": verdicts.count("error"),
                         "not_probed": len(not_probed)}
    except Exception as exc:  # noqa: BLE001
        try:
            from ...extensions import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return dict(out, reason="error", msg=("%s: %s" % (type(exc).__name__, exc))[:300])
    s = out["schema"]
    return dict(out, ok=True, reason="",
                msg="FAZ %s syntax walk: %d objects measured, %d absent, %d error, %d not "
                    "asked (catalog %d)" % (out["version"], s["measured"], s["absent"],
                                            s["error"], s["not_probed"], len(catalog)))


ADAPTER = register(Adapter(
    product=PRODUCT, label="FortiAnalyzer",
    capabilities=Capabilities(tree=False, show_full=False, rest_schema=True, rest_probe=False),
    verified_on=(), unverified=UNVERIFIED, live=True, cli_source="schema",
    notes="JSON-RPC /cli/global/... URLs are the CLI paths; schema via get + "
          "option=syntax, asked per object (a branch answers -3) and per real row for a "
          "table's children, as measured on FortiAnalyzer 7.6.7 build3737."),
    harvest)


__all__ = ["PRODUCT", "UNVERIFIED", "SECTIONS", "MAX_REQUESTS", "jsonrpc_url", "cli_path",
           "channel_key", "canonical_url", "catalog_urls", "syntax_request", "measure",
           "evidence_from_syntax", "known_urls", "harvest", "ADAPTER"]
