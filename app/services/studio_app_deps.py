"""Plugin Studio > Apps > <app> > Dependencies -- everything an app needs,
the way Plugin Studio lists it (FA-0017, 2026-11-11).

The operator: "in each app, put everything it depends on, the same as Plugin
Studio: data stores, connections, sign-in directories and the API Catalog".
An app is more than its diagram, and until now the only list of what it
reads and calls was the export package (``studio_app_package.build_body``).
This module answers the same question for the editor, with the state of
each object HERE: does it exist, does the connection have its secret, is the
API version published, which other apps share the store, is the sign-in
directory switched on.

Where a name is read (one rule for every kind):

* the DRAFT and the PUBLISHED version: the diagram's nodes, the actions, the
  form fields (``store_select`` / ``api_select``) and the view's context
  steps (``view.context[].params``) and ``view.uses`` (other apps);
* the scripts the diagram's ``script`` steps run: the connections their
  published version declares (``via`` names the script);
* the connections: the API Catalog version each one is pinned to;
* the app's sign-in policy: the directory connections its rules name.

Each entry says ``where``: ``draft`` (not published yet -- operators do not
run it), ``published`` (removed from the draft, still what operators run) or
``both``. Nothing here writes; nothing here returns a secret (only whether
one is set).
"""
from __future__ import annotations

#: Parameters (of a node, action, field or view context step) naming another
#: Studio object, by the kind of object.
_PARAMS = {"store": "stores", "connection": "connections", "script": "scripts",
           "app": "apps"}


def _scan(defn: dict, out: dict) -> None:
    """Add the names *defn* (a draft or a published version) uses to *out*."""
    graph = defn.get("graph") or {}
    items = list(graph.get("nodes") or []) + list(defn.get("actions") or [])
    view = defn.get("view") or {}
    if isinstance(view, dict):
        items += [c for c in (view.get("context") or []) if isinstance(c, dict)]
        for u in view.get("uses") or []:
            if u:
                out["apps"].add(str(u))
    for it in items:
        p = it.get("params") if isinstance(it, dict) else None
        if not isinstance(p, dict):
            continue
        for k, bucket in _PARAMS.items():
            if p.get(k):
                out[bucket].add(str(p[k]))
    for f in defn.get("fields") or []:
        if not isinstance(f, dict):
            continue
        for k, bucket in _PARAMS.items():
            if f.get(k):
                out[bucket].add(str(f[k]))


def _names(defn: dict) -> dict:
    out = {b: set() for b in _PARAMS.values()}
    if defn:
        _scan(defn, out)
    return out


def _where(name, draft: set, pub: set) -> str:
    return "both" if (name in draft and name in pub) else ("draft" if name in draft else "published")


def _script_connections(slug: str) -> tuple[str, list[str], int]:
    """(name, connections its published version declares, published version)."""
    from . import script_library as SL
    try:
        meta = SL.get(slug)
    except SL.ScriptError:
        meta = None
    if not meta:
        return "", [], 0
    n = int(meta.get("published") or 0)
    v = SL.version(slug, n) if n else None
    return (str((v or {}).get("name") or meta.get("name") or slug),
            [str(c) for c in ((v or {}).get("connections") or []) if c], n)


def of(a) -> dict:
    """What app *a* depends on, grouped as Plugin Studio's panes are."""
    from . import app_signin as AS
    from . import directory_connections as DC
    from . import plugin_automations as PA
    from . import studio_apps as SA
    from . import studio_connections as SC
    from . import studio_store as SS

    if a.kind in ("script", "page"):
        return {"kind": a.kind, "empty": True}
    pub = a.published or {}
    draft_def = {"graph": a.graph, "actions": a.actions, "fields": a.fields, "view": a.view}
    d, p = _names(draft_def), _names(pub)
    names = {k: d[k] | p[k] for k in d}

    # -- scripts, and the connections they call
    scripts, via = [], {}
    for slug in sorted(names["scripts"]):
        name, conns, n = _script_connections(slug)
        scripts.append({"slug": slug, "name": name or slug, "missing": not name,
                        "published": n, "where": _where(slug, d["scripts"], p["scripts"]),
                        "connections": conns})
        for c in conns:
            via.setdefault(c, []).append(slug)

    # -- data stores
    stores = []
    for slug in sorted(names["stores"]):
        st = SS.get(slug)
        others = [x for x in SA.used_by("store", slug) if x != a.slug]
        stores.append({"slug": slug, "name": st.name if st else slug, "missing": st is None,
                       "rows": SS.count(st) if st is not None else 0,
                       "columns": len(st.columns or []) if st is not None else 0,
                       "shared_with": others, "where": _where(slug, d["stores"], p["stores"])})

    # -- connections (direct, and through a script) and their API versions
    conns, apis = [], {}
    for slug in sorted(names["connections"] | set(via)):
        c = SC.get(slug)
        direct = slug in names["connections"]
        e = {"slug": slug, "name": c.name if c else slug, "missing": c is None,
             "kind": c.kind if c else "", "via": sorted(via.get(slug, [])),
             "where": _where(slug, d["connections"], p["connections"]) if direct else "script",
             "shared_with": [x for x in SA.used_by("connection", slug) if x != a.slug]}
        if c is not None:
            e["target"] = (c.base_url if c.kind == "http"
                           else ("%s:%s" % (c.host, c.port) if c.port else c.host) or "")
            e["auth"] = c.auth or "none"
            e["needs_secret"] = SC.needs_secret(c)
            e["has_secret"] = SC.has_secret(slug) if e["needs_secret"] else True
            v = getattr(c, "api_version", None)
            if v is not None:
                e["api"] = {"slug": v.api.slug, "version": v.version}
                key = (v.api.slug, v.version)
                ent = apis.setdefault(key, {
                    "slug": v.api.slug, "name": v.api.name, "version": v.version,
                    "status": v.status, "endpoints": len(v.operations or []),
                    "source": v.source or "", "connections": []})
                ent["connections"].append(slug)
        conns.append(e)

    # -- sign-in directories (the app's own sign-in page, tab Sign-in)
    pol = AS.policy_of(a)
    dirs = []
    for r in pol.get("rules") or []:
        cid = r.get("connection_id")
        if cid == "local":
            dirs.append({"local": True, "name": "Local accounts", "kind_label": "SATOM",
                         "enabled": True, "require_2fa": bool(r.get("require_2fa"))})
            continue
        conn = DC.get(cid)
        dirs.append({"local": False, "missing": conn is None,
                     "slug": conn.slug if conn else str(cid),
                     "name": conn.name if conn else str(cid),
                     "kind_label": DC.KIND_LABELS.get(conn.kind, conn.kind) if conn else "",
                     "enabled": bool(conn.enabled) if conn else False,
                     "require_2fa": bool(r.get("require_2fa"))})

    # -- other apps it opens / runs, and the apps that run it
    apps = []
    for slug in sorted(names["apps"] - {a.slug}):
        o = SA.get(slug)
        apps.append({"slug": slug, "name": o.name if o else slug, "missing": o is None,
                     "published": bool(o and o.version),
                     "where": _where(slug, d["apps"], p["apps"])})
    autos = [{"id": r.id, "name": r.name, "enabled": bool(r.enabled),
              "when": PA.describe(r.schedule_kind, r.schedule_dict)}
             for r in PA.linked(a.slug)]

    out = {"kind": a.kind, "stores": stores, "connections": conns,
           "apis": sorted(apis.values(), key=lambda x: (x["slug"], x["version"])),
           "signin": {"enabled": bool(pol.get("enabled")), "rules": dirs,
                      "problem": pol.get("problem") or ""},
           "scripts": scripts, "apps": apps, "automations": autos,
           "used_by": SA.used_by("app", a.slug)}
    out["counts"] = {k: len(out[k]) for k in ("stores", "connections", "apis", "scripts",
                                              "apps", "automations")}
    out["counts"]["signin"] = len(dirs)
    out["problems"] = problems(out)
    out["empty"] = not any(out["counts"].values()) and not out["used_by"]
    return out


def problems(deps: dict) -> list[str]:
    """What stops the app from running as it is here (English, for the tab)."""
    out = []
    for s in deps.get("stores") or []:
        if s["missing"]:
            out.append("data store %s does not exist on this server" % s["slug"])
    for c in deps.get("connections") or []:
        if c["missing"]:
            out.append("connection %s does not exist on this server" % c["slug"])
        elif not c.get("has_secret", True):
            out.append("connection %s has no secret yet" % c["slug"])
    for v in deps.get("apis") or []:
        if v["status"] != "published":
            out.append("API %s %s is %s, not published" % (v["slug"], v["version"], v["status"]))
    for s in deps.get("scripts") or []:
        if s["missing"]:
            out.append("script %s does not exist on this server" % s["slug"])
        elif not s["published"]:
            out.append("script %s has no published version" % s["slug"])
    for r in (deps.get("signin") or {}).get("rules") or []:
        if r.get("missing"):
            out.append("sign-in directory %s does not exist on this server" % r["slug"])
        elif not r["enabled"]:
            out.append("sign-in directory %s is switched off" % r["name"])
    for o in deps.get("apps") or []:
        if o["missing"]:
            out.append("app %s does not exist on this server" % o["slug"])
    return out
