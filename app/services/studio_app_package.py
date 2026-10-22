"""Plugin Studio app packages -- an app, and what it needs, as ONE plugin.

A Plugin Studio app is more than its diagram: it reads data stores, calls
HTTP connections pinned to API Catalog versions. An app moved alone lands on
a server where none of those exist, so its first run fails on step one. A
``kind: app`` package (``satom.plugin/1``, see :mod:`plugin_package`)
carries ``app.json``::

    {"app":         {slug, name, icon, description, fields, graph, actions},
     "stores":      [{slug, name, description, columns, rows}],
     "connections": [{slug, name, kind, base_url, auth, username, header_name,
                      token_url, verify_tls, timeout, api, api_version}],
     "apis":        [{slug, name, owner, docs_url, description,
                      version, base_path, operations}]}

INSTALL RULES -- what an import may and may not overwrite
---------------------------------------------------------
* **The app** is created, or its DRAFT replaced (form, diagram, actions).
  The published version, the ADOMs and who may run it are never touched:
  publishing is the administrator's act, on this server.
* **Data stores** are created with their columns and seed rows when missing.
  An existing store keeps its rows (they are this server's data -- the
  variables an administrator already set); columns the package adds are
  appended, none is removed.
* **Connections** are created when missing, WITHOUT a secret: the password
  or token is typed on this server (Plugin Studio › Connections). An existing
  connection is never changed -- its URL and credentials are this server's.
* **API Catalog versions** are created and published when missing; a version
  that exists is frozen by design and is kept.

Export writes the same file from a live app, minus every secret: a
connection's secret is never in the package, in either direction.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from . import plugin_package as P

MAX_SEED_ROWS = 500


class AppPackageError(P.PackageError):
    pass


def _refs(a) -> dict:
    from . import studio_flow as F
    r = F.references(a.graph)
    for f in a.fields:
        if f.get("type") == "store_select" and f.get("store"):
            r["stores"].add(f["store"])
        if f.get("type") == "api_select" and f.get("connection"):
            r["connections"].add(f["connection"])
    for act in a.actions:
        p = act.get("params") or {}
        if p.get("store"):
            r["stores"].add(p["store"])
        if p.get("connection"):
            r["connections"].add(p["connection"])
    return r


def build_body(a) -> dict:
    """``app.json`` for app ``a`` -- secrets excluded by construction."""
    from . import studio_connections as SC
    from . import studio_store as SS
    refs = _refs(a)
    stores = []
    for slug in sorted(refs["stores"]):
        st = SS.get(slug)
        if st is None:
            continue
        rows = SS.query(st, limit=MAX_SEED_ROWS)
        stores.append({"slug": st.slug, "name": st.name, "description": st.description,
                       "columns": st.columns,
                       "rows": [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]})
    conns, apis = [], {}
    for slug in sorted(refs["connections"]):
        c = SC.get(slug)
        if c is None or c.kind != "http":
            continue
        d = {"slug": c.slug, "name": c.name, "description": c.description, "kind": c.kind,
             "base_url": c.base_url, "auth": c.auth, "username": c.username,
             "header_name": c.header_name, "token_url": c.token_url, "scope": c.scope,
             "verify_tls": bool(c.verify_tls), "timeout": c.timeout}
        v = getattr(c, "api_version", None)
        if v is not None:
            d["api"], d["api_version"] = v.api.slug, v.version
            apis[(v.api.slug, v.version)] = {
                "slug": v.api.slug, "name": v.api.name, "owner": v.api.owner,
                "docs_url": v.api.docs_url, "description": v.api.description,
                "version": v.version, "base_path": v.base_path, "operations": v.operations}
        conns.append(d)
    return {"app": {"slug": a.slug, "name": a.name, "icon": a.icon,
                    "description": a.description, "fields": a.fields,
                    "graph": a.graph, "actions": a.actions},
            "stores": stores, "connections": conns, "apis": list(apis.values())}


def export_app(a, satom_version: str = "") -> tuple[str, bytes]:
    version = a.pkg_version or "1.0.0"
    slug = a.slug.replace("_", "-")
    manifest = {"slug": slug, "name": a.name, "version": version, "kind": "app",
                "icon": a.icon if P.ICON_RE.match(a.icon or "") else "bi-app-indicator",
                "description": (a.description or "")[:500], "datasets": [], "params": [],
                "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if P.VERSION_RE.match(satom_version or ""):
        manifest["min_satom"] = satom_version
    body = json.dumps(build_body(a), indent=1, sort_keys=True, ensure_ascii=False)
    return "%s-%s%s" % (slug, version, P.EXT), P.write_package(
        manifest, {P.APP_FILE: body.encode("utf-8")})


def _body(pk) -> dict:
    try:
        return json.loads(pk.files[P.APP_FILE].decode("utf-8"))
    except (KeyError, UnicodeDecodeError, ValueError):
        raise AppPackageError("%s is not valid JSON." % P.APP_FILE) from None


def install(pk, by: str, *, allow_downgrade: bool = False) -> dict:
    """Install an app package. ``{app, created, kept, todo, problems}``."""
    from ..extensions import db
    from . import studio_apis as SAPI
    from . import studio_apps as SA
    from . import studio_connections as SC
    from . import studio_store as SS
    if pk.kind != "app":
        raise AppPackageError("not an app package")
    body = _body(pk)
    spec = body.get("app") or {}
    slug = str(spec.get("slug") or "").strip()
    existing = SA.get(slug) if slug else None
    if existing is not None and existing.pkg_version and not allow_downgrade and \
            P.version_tuple(pk.version) < P.version_tuple(existing.pkg_version):
        raise AppPackageError("%s %s is installed and %s is older (tick Allow downgrade)"
                              % (slug, existing.pkg_version, pk.version))
    created, kept, todo = [], [], []
    try:
        for api in body.get("apis") or []:
            a = SAPI.get(str(api.get("slug") or ""))
            if a is None:
                a = SAPI.create(api["slug"], api.get("name") or api["slug"], by)
                SAPI.save(a, {"name": api.get("name"), "owner": api.get("owner"),
                              "docs_url": api.get("docs_url"),
                              "description": api.get("description")}, by)
                created.append("API %s" % a.slug)
            v = SAPI.get_version(a, str(api.get("version") or ""))
            if v is None:
                v = SAPI.create_version(a, str(api["version"]), by)
                SAPI.save_draft(v, operations=api.get("operations") or [],
                                base_path=api.get("base_path") or "", by=by)
                SAPI.publish(v, by)
                created.append("API %s %s (%d endpoints, published)"
                               % (a.slug, v.version, len(v.operations)))
            else:
                kept.append("API %s %s (exists, %s)" % (a.slug, v.version, v.status))
        for c in body.get("connections") or []:
            if SC.get(str(c.get("slug") or "")) is not None:
                kept.append("connection %s (exists: its URL and secret are this server's)"
                            % c["slug"])
                continue
            row = SC.create(c["slug"], c.get("name") or c["slug"], c.get("kind") or "http", by)
            form = {k: c.get(k) for k in ("name", "description", "base_url", "auth", "username",
                                          "header_name", "token_url", "scope", "timeout")}
            form["login_path"] = c.get("token_url") if c.get("auth") == "session" else ""
            form["verify_tls"] = "1" if c.get("verify_tls", True) else ""
            if c.get("api"):
                api = SAPI.get(c["api"])
                v = SAPI.get_version(api, c.get("api_version") or "") if api else None
                form["api_version_id"] = str(v.id) if v is not None else ""
            SC.save(row, form, by)
            created.append("connection %s" % row.slug)
            if SC.needs_secret(row):
                todo.append("set the secret of connection %s (Plugin Studio › Connections)"
                            % row.slug)
        for st_spec in body.get("stores") or []:
            st = SS.get(str(st_spec.get("slug") or ""))
            if st is None:
                st = SS.create(st_spec["slug"], st_spec.get("name") or st_spec["slug"], by)
                SS.save_schema(st, st_spec.get("name") or st.name,
                               st_spec.get("description") or "", st_spec.get("columns") or [], by)
                rows = (st_spec.get("rows") or [])[:MAX_SEED_ROWS]
                for r in rows:
                    SS.insert(st, r, by)
                created.append("data store %s (%d rows)" % (st.slug, len(rows)))
            else:
                have = {c["name"] for c in st.columns}
                more = [c for c in st_spec.get("columns") or [] if c.get("name") not in have]
                if more:
                    SS.save_schema(st, st.name, st.description, st.columns + more, by)
                kept.append("data store %s (exists: rows kept%s)" % (
                    st.slug, ", added " + ", ".join(c["name"] for c in more) if more else ""))
        a = existing
        if a is None:
            a = SA.create(slug, spec.get("name") or slug, by)
            created.append("app %s (draft)" % slug)
        else:
            kept.append("app %s: draft replaced, published version and access unchanged" % slug)
        a.name = (spec.get("name") or a.name)[:120]
        a.description = str(spec.get("description") or "")[:2000]
        icon = str(spec.get("icon") or "")
        if SA._ICON_RE.match(icon):
            a.icon = icon
        a.pkg_version = pk.version
        a.pkg_signer = pk.signer or ""
        problems = SA.save_draft(a, fields=spec.get("fields") or [],
                                 graph=spec.get("graph") or {},
                                 actions=spec.get("actions") or [], by=by)
    except (SA.AppError, SS.StoreError, SC.ConnectionError_, SAPI.ApiError, KeyError) as exc:
        db.session.rollback()
        raise AppPackageError("the app package could not be installed: %s" % exc) from None
    if a.status != "published":
        todo.append("review the diagram, test it and Publish (Plugin Studio › Apps › %s)" % slug)
    return {"app": a, "created": created, "kept": kept, "todo": todo,
            "problems": SA.problems(a) if problems is not None else []}
