"""API Catalog versions built from SATOM's API library (contract section 19).

The API library knows, per Fortinet product and firmware build, which REST
endpoints the build serves (measured on devices, from schemas and from vendor
documentation) and, from the CLI evidence, whether each object is a table
(with its ``mkey``) or a single settings object. This module turns one build
into an API Catalog version -- API ``fortigate``, version ``8.0.1`` -- so a
Plugin Studio connection can be pinned to it. From then on the rules that
already guard a pinned connection apply: an ``Call an API`` step whose method
and path are not an endpoint of the build is a problem that blocks publishing
(and the Builder's check), and the broker refuses the request.

How each product addresses one object:

* **FortiGate** ``/api/v2/cmdb/<path>``: a table is ``GET``/``POST`` on the
  path and ``GET``/``PUT``/``DELETE`` on ``<path>/{<mkey>}``; a settings
  object is ``GET``/``PUT`` on the path; a list field with its own key (an
  address group's ``member``) is a child table:
  ``GET``/``POST <path>/{<mkey>}/<field>`` (POST adds ONE entry, the others
  stay) and ``GET``/``DELETE <path>/{<mkey>}/<field>/{<field>_<key>}`` (GET
  answers 404 when the item is not in the list: measured on fgt02 8.0.1).
* **FortiWeb** ``/api/v2.0/cmdb/<path>`` and **FortiADC** ``/api/<name>``:
  the object's key travels as ``?mkey=``, so every method is on the one path.
  FortiWeb's sub-tables are library endpoints of their own
  (``server-pool/pserver-list``); FortiADC's child tables
  (``/api/load_balance_pool_child_pool_member?pkey=<pool>``, row ``&mkey=``)
  are not in the library -- its sweep cannot read them without a parent -- so
  they come from SATOM's FortiADC registry for the build, the map SATOM's
  own client calls, when their parent table is in the library.
* **FortiAuthenticator** ``/api/v1/<resource>/``, in the shape its Tastypie
  schema harvest measured (fact ``attrs.shape``/``attrs.methods``): a
  collection is ``<resource>/`` and ``<resource>/{id}/`` with only the
  methods its schema allows, a single object (``systeminfo``) is read and
  changed at ``<resource>/`` with no ``{id}/``, an action (GET answers 405,
  ``auth``) takes its writes at ``<resource>/``. Not measured: every shape.
* **FortiAnalyzer** speaks JSON-RPC: ONE operation, ``POST /jsonrpc``, whose
  ``rpc`` lists the urls the build serves (``/cli/global/...`` from the
  library, with ``/{<mkey>}`` for a table; ``/dvmdb``, ``/logview``,
  ``/report``... from SATOM's registry, any ADOM as ``adom/{adom}``). The
  body's ``params[].url`` must be one of them (``studio_api_spec.rpc_problem``,
  in the check, the app step and the broker).

Endpoints the build is measured NOT to serve (verdict ``absent``) are left
out. An object whose kind the CLI evidence never measured gets both shapes:
the library does not know which one is right, and refusing a real endpoint
would be worse than allowing a method the device then refuses.
"""
from __future__ import annotations

import re

from . import studio_api_spec as S

#: product -> how one object is addressed (see the module docstring)
STYLES = {"fortigate": "path_mkey", "fortiweb": "query_mkey", "fortiadc": "query_mkey",
          "fortiauthenticator": "path_id", "fortianalyzer": "jsonrpc"}
NAMES = {"fortigate": "FortiGate", "fortiweb": "FortiWeb", "fortiadc": "FortiADC",
         "fortiauthenticator": "FortiAuthenticator", "fortianalyzer": "FortiAnalyzer"}
SOURCE = "library"
OWNER = "Fortinet"
DESCRIPTION = ("REST endpoints of %s from SATOM's API library (measured on devices, from "
               "schemas and from vendor documentation), one version per firmware build. "
               "Built by SATOM: Plugin Studio > API Catalog > Add from SATOM's API library.")
_PH = re.compile(r"[^A-Za-z0-9_.-]+")


class LibraryApiError(ValueError):
    """Why a version cannot be built; the UI shows it as is."""


def _ph(name: str) -> str:
    return _PH.sub("_", str(name or "")).strip("_")[:64] or "mkey"


def _op(method: str, path: str, summary: str, tag: str, body: bool = False) -> dict:
    return {"method": method, "path": path, "summary": summary[:300], "tags": [tag],
            "body": body}


def _child_lists(product: str, version: str, endpoint: str) -> list[tuple[str, str]]:
    """``[(field, child key)]`` of the list fields with their own key."""
    from . import api_library as L
    fields = (L.fields_at(product, endpoint, version) or {}).get("fields") or {}
    out = []
    for name, spec in sorted(fields.items()):
        if not isinstance(spec, dict) or spec.get("type") != "list":
            continue
        key = (spec.get("attrs") or {}).get("mkey")
        if key and not str(name).startswith("q_"):
            out.append((str(name), str(key)))
    return out


#: FortiAuthenticator (Tastypie): what each method does on the collection
#: (``list``) and on one entry (``detail``)
_PATH_ID_TEXT = {
    ("list", "GET"): ": list", ("list", "POST"): ": add one",
    ("list", "PUT"): ": replace EVERY entry (bulk)", ("list", "PATCH"): ": add or change entries (bulk)",
    ("list", "DELETE"): ": delete EVERY entry the query selects (bulk)",
    ("detail", "GET"): ": one, by id", ("detail", "PUT"): ": replace one",
    ("detail", "PATCH"): ": change some fields of one", ("detail", "DELETE"): ": delete one",
    ("detail", "POST"): ": post to one (an action on it)",
}
#: a collection whose schema was not read: the methods every resource had
_PATH_ID_DEFAULT = {"list": ("GET", "POST"), "detail": ("GET", "PUT", "PATCH", "DELETE")}


def _path_id_ops(path: str, what: str, tag: str, kind: str | None, attrs: dict) -> list[dict]:
    """A FortiAuthenticator resource in the shape the build measured:

    * ``table`` (a collection): ``<res>/`` and ``<res>/{id}/`` with exactly the
      methods its schema allows (``localusers`` 8.0.3: DELETE on the
      collection, no PUT on one entry), every usual one when the schema did
      not answer;
    * ``singleton`` (a bare object, e.g. ``systeminfo``): ``<res>/`` read and
      changed in place, no ``{id}/``;
    * ``action`` (GET answers 405, e.g. ``auth``): the methods its schema
      allows on ``<res>/``, else every write;
    * not measured: every operation of a collection, as before.
    """
    base = path if path.endswith("/") else path + "/"
    item = base + "{id}/"
    methods = attrs.get("methods") if isinstance(attrs.get("methods"), dict) else None
    allowed = {k: [m for m in ("GET", "POST", "PUT", "PATCH", "DELETE")
                   if m in {str(x).upper() for x in (methods or {}).get(k) or []}]
               for k in ("list", "detail")}
    if kind == "singleton":
        return [_op("GET", base, what + ": read (one object)", tag),
                _op("PUT", base, what + ": replace it", tag, True),
                _op("PATCH", base, what + ": change some fields of it", tag, True)]
    if kind == "action":
        verbs = [m for m in allowed["list"] if m != "GET"] or ["POST", "PUT", "PATCH", "DELETE"]
        return [_op(m, base, what + ": action (GET is refused)", tag, m != "DELETE")
                for m in verbs]
    use = allowed if (kind == "table" and methods) else _PATH_ID_DEFAULT
    out = []
    for scope, where in (("list", base), ("detail", item)):
        for m in use[scope]:
            out.append(_op(m, where, what + _PATH_ID_TEXT.get((scope, m), ": " + m), tag,
                           m in ("POST", "PUT", "PATCH")))
    return out


#: FAC ``attrs.shape`` -> the kind the counts and :func:`_path_id_ops` use
_FAC_KIND = {"collection": "table", "singleton": "singleton", "action": "action"}


def _adc_children(version: str, served: dict) -> list[tuple[str, str, str]]:
    """``[(name, urn, parent)]``: FortiADC child tables of the build whose
    parent table the library has. The library sweep never reads them (each
    needs ``?pkey=<parent entry>``), so they come from SATOM's registry for
    that build -- the same map SATOM's own FortiADC client calls."""
    from ..registry import loader
    try:
        reg = loader.registry_for("fortiadc", version)
    except Exception:  # noqa: BLE001 -- no registry: the tables alone still stand
        return []
    out = []
    for name, urn in sorted((reg or {}).items()):
        if "_child_" not in name or not str(urn or "").startswith("/"):
            continue
        parent = name.split("_child_", 1)[0]
        if parent in served:
            out.append((name, str(urn), parent))
    return out


def _adc_child_ops(name: str, urn: str, parent: str, tag: str) -> list[dict]:
    path = S.clean_path(urn)
    what = name.split("_child_", 1)[1]
    scope = "?pkey=<the %s entry>" % parent
    return [_op("GET", path, "%s: the %s rows of one %s entry (%s; one row: &mkey=)"
                % (parent, what, parent, scope), tag),
            _op("POST", path, "%s: add ONE %s row to one entry (%s; the others stay)"
                % (parent, what, scope), tag, True),
            _op("PUT", path, "%s: change the %s row %s&mkey= names" % (parent, what, scope),
                tag, True),
            _op("DELETE", path, "%s: remove the %s row %s&mkey= names" % (parent, what, scope),
                tag)]


def _ops_for(product: str, version: str, name: str, urn: str, section: str,
             kind: str | None, mkey: str, attrs: dict | None = None) -> tuple[list[dict], int]:
    """``(operations, child lists)`` of one library endpoint."""
    style = STYLES[product]
    tag = section or name.split("/", 1)[0]
    what = name.rsplit("/", 1)[-1]       # the path already says the rest
    path = S.clean_path(urn)
    out = []
    if style == "query_mkey":
        out.append(_op("GET", path, what + ": read (a table: all entries, or one with ?mkey=)", tag))
        out.append(_op("PUT", path, what + ": change (a table: the entry ?mkey= names)", tag, True))
        if kind != "singleton":
            out.append(_op("POST", path, what + ": add an entry", tag, True))
            out.append(_op("DELETE", path, what + ": delete the entry ?mkey= names", tag))
        return out, 0
    if style == "path_id":
        return _path_id_ops(path, what, tag, kind, attrs or {}), 0
    # path_mkey (FortiGate)
    if kind in ("singleton", None):
        out.append(_op("GET", path, what + ": read" + (" (a table: every entry)" if kind is None else ""), tag))
        out.append(_op("PUT", path, what + ": change the settings", tag, True))
    children = 0
    if kind in ("table", None):
        key = _ph(mkey or "mkey")
        item = "%s/{%s}" % (path, key)
        if kind == "table":
            out.append(_op("GET", path, what + ": every entry", tag))
        out += [_op("POST", path, what + ": add an entry (the body is the entry)", tag, True),
                _op("GET", item, what + ": one entry, by %s" % key, tag),
                _op("PUT", item, what + ": change one entry (a list field sent here REPLACES "
                    "the whole list)", tag, True),
                _op("DELETE", item, what + ": delete one entry", tag)]
        if kind == "table":
            for field, ckey in _child_lists(product, version, name):
                children += 1
                child = "%s/%s" % (item, field)
                cph = _ph("%s_%s" % (field, ckey))
                out += [_op("GET", child, "%s: the %s list of one entry" % (what, field), tag),
                        _op("POST", child, "%s: add ONE item to the %s list of one entry "
                            "(the others stay; body {\"%s\": ...})" % (what, field, ckey),
                            tag, True),
                        _op("GET", "%s/{%s}" % (child, cph),
                            "%s: one item of the %s list of one entry (404 = not in the list)"
                            % (what, field), tag),
                        _op("DELETE", "%s/{%s}" % (child, cph),
                            "%s: remove one item from the %s list of one entry"
                            % (what, field), tag)]
    return out, children


def operations(product: str, version: str) -> tuple[list[dict], dict]:
    """``(operations, counts)`` for one build, checked like any API Catalog
    version (:func:`studio_api_spec.clean_operations`)."""
    from . import api_library as L
    if product not in STYLES:
        raise LibraryApiError("%s is not a product of SATOM's API library" % product)
    eps = L.endpoints_at(product, version)
    if not eps:
        raise LibraryApiError("SATOM's API library has not measured %s %s: pick a measured "
                              "build" % (NAMES[product], version))
    kinds = L.object_kinds(product, version)
    b = L._build_row(product, L.fv.normalize(version))
    objs = L._cli_objects(L._cli_evidence(b.id)) if b is not None else {}
    if STYLES[product] == "jsonrpc":
        return _jsonrpc_operations(product, version, eps, kinds, objs)
    shapes = L.rest_attrs(product, version) if product == "fortiauthenticator" else {}
    raw, counts = [], {"table": 0, "singleton": 0, "action": 0, "unknown": 0, "absent": 0,
                       "child_lists": 0}
    served: dict = {}
    for name, e in sorted(eps.items()):
        if e.get("verdict") == L.VERDICT_ABSENT:
            counts["absent"] += 1
            continue
        urn = str(e.get("urn") or "")
        if not urn.startswith("/"):
            continue
        attrs = shapes.get(name) or {}
        kind = (_FAC_KIND.get(attrs.get("shape")) if product == "fortiauthenticator"
                else kinds.get(L.object_kind_key(name)))
        mkey = (objs.get(name) or {}).get("mkey") or ""
        section = str(e.get("section") or "")
        ops, children = _ops_for(product, version, name, urn, section, kind, mkey, attrs)
        counts[kind or "unknown"] += 1
        counts["child_lists"] += children
        served[name] = section
        raw.extend(ops)
    if product == "fortiadc":
        for name, urn, parent in _adc_children(version, served):
            counts["child_lists"] += 1
            raw.extend(_adc_child_ops(name, urn, parent, served[parent] or parent))
    seen, uniq = set(), []
    for o in raw:                       # two library names, one URN: one endpoint
        if (o["method"], o["path"]) not in seen:
            seen.add((o["method"], o["path"]))
            uniq.append(o)
    try:
        return S.clean_operations(uniq), counts
    except S.SpecError as exc:
        raise LibraryApiError("%s %s: %s" % (NAMES[product], version, exc)) from None


#: FortiAnalyzer urls outside ``/cli/global`` come from SATOM's registry
#: (``/dvmdb``, ``/logview``, ``/report``, ...), which writes the ADOM it was
#: censused in (``adom/root``): the version takes any ADOM there
_ADOM_SEG = re.compile(r"/adom/root(?=/|$)")


def _jsonrpc_operations(product: str, version: str, eps: dict, kinds: dict,
                        objs: dict) -> tuple[list[dict], dict]:
    """FortiAnalyzer: ONE operation, ``POST /jsonrpc``, whose ``rpc`` lists the
    urls the build serves. A ``/cli/global`` table is reached at its url (all
    entries) and at ``<url>/{<mkey>}`` (one), a settings object at its url, an
    object of unmeasured kind both ways; a library name the vendor documented
    without a url is filed under ``/cli/global/<name>`` (``.`` = ``/``)."""
    from . import api_library as L
    urls: set = set()
    counts = {"table": 0, "singleton": 0, "action": 0, "unknown": 0, "absent": 0,
              "child_lists": 0}
    for name, e in sorted(eps.items()):
        if e.get("verdict") == L.VERDICT_ABSENT:
            counts["absent"] += 1
            continue
        urn = str(e.get("urn") or "") or "/cli/global/" + str(name).replace(".", "/")
        if not urn.startswith("/"):
            continue
        kind = kinds.get(L.object_kind_key(name))
        counts[kind or "unknown"] += 1
        urls.add(urn)
        if kind in ("table", None):
            if not urn.endswith("}"):
                urls.add("%s/{%s}" % (urn, _ph((objs.get(name) or {}).get("mkey") or "name")))
    from ..registry import loader
    try:
        reg = loader.registry_for(product, version) or {}
    except Exception:  # noqa: BLE001 -- the library's own urls still stand
        reg = {}
    for urn in sorted(set(reg.values())):
        urn = _ADOM_SEG.sub("/adom/{adom}", str(urn or ""))
        if not urn.startswith("/") or urn in urls:
            continue
        urls.add(urn)
        if urn.startswith("/dvmdb/"):
            # a device database table: one entry by name, and per ADOM
            rest = urn[len("/dvmdb/"):]
            urls.add(urn + "/{name}")
            if not rest.startswith("adom"):
                urls.update({"/dvmdb/adom/{adom}/" + rest, "/dvmdb/adom/{adom}/%s/{name}" % rest})
    op = {"method": "POST", "path": "/jsonrpc", "id": "jsonrpc", "body": True,
          "tags": ["jsonrpc"], "rpc": sorted(urls),
          "summary": ("Every call (JSON-RPC): the body is {\"method\": \"get|set|add|update|"
                      "delete|exec\", \"params\": [{\"url\": ...}]} and each url must be one "
                      "of this version's %d urls" % len(urls))}
    counts["rpc_urls"] = len(urls)
    try:
        return S.clean_operations([op]), counts
    except S.SpecError as exc:
        raise LibraryApiError("%s %s: %s" % (NAMES[product], version, exc)) from None


def notes(product: str, version: str, counts: dict, build: str = "") -> str:
    head = "Built from SATOM's API library: %s %s%s. " % (
        NAMES[product], version, " (%s)" % build if build else "")
    tail = " %d endpoint(s) the build does not serve are left out." % counts["absent"]
    if STYLES[product] == "jsonrpc":
        return head + ("JSON-RPC: one endpoint, POST /jsonrpc; the body's params[].url must be "
                       "one of %d urls (%d tables, %d settings objects, %d objects of unmeasured "
                       "kind, plus the device database, logs and reports SATOM's registry calls)."
                       % (counts.get("rpc_urls", 0), counts["table"], counts["singleton"],
                          counts["unknown"])) + tail
    if STYLES[product] == "path_id":
        return head + ("%d collections (<resource>/ and {id}/ items, the methods the schema "
                       "allows), %d single objects (<resource>/ only), %d actions (no GET), "
                       "%d resources whose shape the library has not measured (both shapes "
                       "allowed)." % (counts["table"], counts["singleton"],
                                      counts.get("action", 0), counts["unknown"])) + tail
    kids = ("%d child tables (?pkey=<parent entry>, from SATOM's registry)" if product == "fortiadc"
            else "%d child lists") % counts["child_lists"]
    return head + ("%d tables, %d settings objects, %d objects whose kind the library has not "
                   "measured (both shapes allowed), %s."
                   % (counts["table"], counts["singleton"], counts["unknown"], kids)) + tail


def entry(product: str, version: str) -> dict:
    """The version as an app package carries it (``app.json`` ``"apis"``)."""
    ops, counts = operations(product, version)
    return {"slug": product, "name": "%s REST API" % NAMES[product], "owner": OWNER,
            "docs_url": "", "description": DESCRIPTION % NAMES[product],
            "version": version, "base_path": "", "operations": ops,
            "notes": notes(product, version, counts), "source": SOURCE}


def offered() -> list[dict]:
    """``[{product, name, versions: [{version, build, in_fleet}]}]``: what the
    API Catalog page offers -- measured builds, the fleet's first."""
    from . import api_library as L
    out = []
    for p in L.PRODUCTS:
        if p not in STYLES:
            continue
        try:
            rows = [b for b in L.builds(p) if b.get("measured")]
        except Exception:  # noqa: BLE001 -- a product with no library tables yet
            rows = []
        if not rows:
            continue
        rows.sort(key=lambda b: _vkey(b["version"]), reverse=True)
        rows.sort(key=lambda b: not b.get("in_fleet"))      # stable: the fleet's first
        out.append({"product": p, "name": NAMES[p],
                    "versions": [{"version": b["version"], "build": b.get("build") or "",
                                  "in_fleet": bool(b.get("in_fleet"))} for b in rows]})
    return out


def _vkey(v: str):
    from . import studio_apis as SAPI
    return SAPI._vkey(v)


def refresh(v, entry_: dict, by: str) -> int:
    """Add to a library version the endpoints a newer build of the list has.
    -> how many were added (endpoints, and urls of a JSON-RPC endpoint). ONLY additive and only for ``source ==
    "library"``: a person's published version never changes, and no endpoint
    an app may call is ever taken away -- a library version is SATOM's
    measurement of a firmware build, and it can only learn more about it
    (2026-10-26: the GET of a list item was added after a1 had published
    FortiGate 8.0.1 without it)."""
    import json as _json
    from ..extensions import db
    if v.source != SOURCE:
        return 0
    ops = [dict(o) for o in v.operations]
    have = {(o["method"], o["path"]): o for o in ops}
    new, grown = [], 0
    for o in entry_.get("operations") or []:
        old = have.get((o["method"], o["path"]))
        if old is None:
            new.append(o)
        elif o.get("rpc"):             # a JSON-RPC endpoint learns urls the same way
            more = set(o["rpc"]) - set(old.get("rpc") or [])
            if more:
                old["rpc"] = sorted(set(old.get("rpc") or []) | more)
                grown += len(more)
    if not new and not grown:
        return 0
    v.operations_json = _json.dumps(S.clean_operations(ops + new))
    v.notes = str(entry_.get("notes") or v.notes)[:8000]
    v.updated_by = by
    db.session.commit()
    return len(new) + grown


def ensure(product: str, version: str, by: str):
    """The published API Catalog version of one build, created when missing.
    -> ``(StudioApiVersion, created: bool)``."""
    from . import studio_apis as SAPI
    a = SAPI.get(product)
    if a is not None:
        other = [v.version for v in a.versions if v.source != SOURCE]
        if other:
            raise LibraryApiError("API %s exists and was not built from SATOM's API library "
                                  "(versions %s): it cannot take a library version"
                                  % (product, ", ".join(sorted(other))))
        v = SAPI.get_version(a, version)
        if v is not None:
            refresh(v, entry(product, version), by)
            return v, False
    e = entry(product, version)
    if a is None:
        a = SAPI.create(product, e["name"], by)
        SAPI.save(a, {"name": e["name"], "owner": e["owner"], "docs_url": "",
                      "description": e["description"]}, by)
    v = SAPI.create_version(a, version, by)
    SAPI.save_draft(v, operations=e["operations"], notes=e["notes"], by=by)
    v.source = SOURCE
    SAPI.publish(v, by)
    return v, True
