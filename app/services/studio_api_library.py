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
  stay) and ``GET``/``DELETE <path>/{<mkey>}/<field>/{<field>_<key>}``.
* **FortiWeb** ``/api/v2.0/cmdb/<path>`` and **FortiADC** ``/api/<name>``:
  the object's key travels as ``?mkey=``, so every method is on the one path.
* **FortiAuthenticator** ``/api/v1/<resource>/``: ``GET``/``POST`` on the
  collection, ``GET``/``PUT``/``PATCH``/``DELETE`` on ``<resource>/{id}/``.
* **FortiAnalyzer** speaks JSON-RPC: every call is ``POST /jsonrpc`` with the
  object in the body, so a path says nothing and no version is built.

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
          "fortiauthenticator": "path_id"}
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


def _ops_for(product: str, version: str, name: str, urn: str, section: str,
             kind: str | None, mkey: str) -> tuple[list[dict], int]:
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
        base = path if path.endswith("/") else path + "/"
        item = base + "{id}/"
        out += [_op("GET", base, what + ": list", tag),
                _op("POST", base, what + ": add one", tag, True),
                _op("GET", item, what + ": one, by id", tag),
                _op("PUT", item, what + ": replace one", tag, True),
                _op("PATCH", item, what + ": change some fields of one", tag, True),
                _op("DELETE", item, what + ": delete one", tag)]
        return out, 0
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
                        _op("DELETE", "%s/{%s}" % (child, cph),
                            "%s: remove one item from the %s list of one entry"
                            % (what, field), tag)]
    return out, children


def operations(product: str, version: str) -> tuple[list[dict], dict]:
    """``(operations, counts)`` for one build, checked like any API Catalog
    version (:func:`studio_api_spec.clean_operations`)."""
    from . import api_library as L
    if product == "fortianalyzer":
        raise LibraryApiError("FortiAnalyzer speaks JSON-RPC: every call is POST /jsonrpc with "
                              "the object in the body, so an endpoint list by path would say "
                              "nothing. Call it with a connection that is not pinned.")
    if product not in STYLES:
        raise LibraryApiError("%s is not a product of SATOM's API library" % product)
    eps = L.endpoints_at(product, version)
    if not eps:
        raise LibraryApiError("SATOM's API library has not measured %s %s: pick a measured "
                              "build" % (NAMES[product], version))
    kinds = L.object_kinds(product, version)
    b = L._build_row(product, L.fv.normalize(version))
    objs = L._cli_objects(L._cli_evidence(b.id)) if b is not None else {}
    raw, counts = [], {"table": 0, "singleton": 0, "unknown": 0, "absent": 0, "child_lists": 0}
    for name, e in sorted(eps.items()):
        if e.get("verdict") == L.VERDICT_ABSENT:
            counts["absent"] += 1
            continue
        urn = str(e.get("urn") or "")
        if not urn.startswith("/"):
            continue
        kind = kinds.get(L.object_kind_key(name))
        mkey = (objs.get(name) or {}).get("mkey") or ""
        ops, children = _ops_for(product, version, name, urn, str(e.get("section") or ""),
                                 kind, mkey)
        counts[kind or "unknown"] += 1
        counts["child_lists"] += children
        raw.extend(ops)
    seen, uniq = set(), []
    for o in raw:                       # two library names, one URN: one endpoint
        if (o["method"], o["path"]) not in seen:
            seen.add((o["method"], o["path"]))
            uniq.append(o)
    try:
        return S.clean_operations(uniq), counts
    except S.SpecError as exc:
        raise LibraryApiError("%s %s: %s" % (NAMES[product], version, exc)) from None


def notes(product: str, version: str, counts: dict, build: str = "") -> str:
    head = "Built from SATOM's API library: %s %s%s. " % (
        NAMES[product], version, " (%s)" % build if build else "")
    tail = " %d endpoint(s) the build does not serve are left out." % counts["absent"]
    if STYLES[product] == "path_id":
        n = counts["table"] + counts["singleton"] + counts["unknown"]
        return head + "%d resources (a collection and {id}/ items)." % n + tail
    return head + ("%d tables, %d settings objects, %d objects whose kind the library has not "
                   "measured (both shapes allowed), %d child lists."
                   % (counts["table"], counts["singleton"], counts["unknown"],
                      counts["child_lists"])) + tail


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
