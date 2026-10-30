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
                      version, base_path, operations[, source, notes]}],
     "automations": [{name, schedule_kind, schedule, inputs, description}]}

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
* **Automations** (``"automations"``, contract section 18): the app on a
  schedule, as ``plugin_app`` rows of Automations -- created SWITCHED OFF, run
  as the importing user once an administrator turns them on; one that exists
  (same app and name) keeps this server's schedule, inputs and on/off
  (:mod:`plugin_automations`).
* **Scripts** (``"scripts"``: the Script Library scripts the diagram's
  ``script`` steps run, with their published files and settings) are created
  when missing and published as version 1 for ``admins``. An existing script
  is kept, with a warning when its published files differ.

Nothing is written before the whole package passed the rules that need no
server state (``package_check.app_preflight``): a template (Plugin Studio >
Examples) is never replaced or created, a connection never carries a secret
and is never postgres, an API version has endpoints, every packaged script
passes the script rules. Nor before what ``save_draft`` would refuse on THIS
server (``_server_refusal``: the form, diagram, actions and design, with what
the package brings counted as present -- e.g. an action that opens an app the
server does not have). The import page applies the rest of
``package_check.check`` -- by policy -- before it calls :func:`install`.

Export writes the same file from a live app, minus every secret: a
connection's secret is never in the package, in either direction, and a
script travels without any credential value.
"""
from __future__ import annotations

import hashlib
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


def connection_form(c: dict) -> dict:
    """The connection form install applies for the package entry *c*
    (``studio_connections.save``; ``clean_definition`` checks the same)."""
    form = {k: "" if c.get(k) is None else str(c.get(k))
            for k in ("name", "description", "base_url", "auth", "username", "header_name",
                      "token_url", "scope", "timeout")}
    form["login_path"] = form["token_url"] if c.get("auth") == "session" else ""
    form["verify_tls"] = "1" if c.get("verify_tls", True) else ""
    return form


def _scripts(slugs) -> list[dict]:
    """The published version of each script, as a package carries it: its
    files and settings. Credential VALUES live in the vault and never come
    here; declared credentials and a network mode travel only so that the
    import can refuse them by name (a packaged script has neither)."""
    from . import script_library as SL
    out = []
    for slug in sorted(slugs):
        try:
            meta = SL.get(slug)
        except SL.ScriptError:
            meta = None
        if not meta or not meta.get("published"):
            continue                    # the diagram's problem says so on import
        v = SL.version(slug, int(meta["published"])) or {}
        settings = {"fields": v.get("fields") or [], "timeout": v.get("timeout") or SL.TIMEOUT_DEFAULT,
                    "audience": meta.get("audience") or "admins",
                    "connections": list(v.get("connections") or []),
                    "entry": v.get("entry") or SL.ENTRY}
        if (v.get("network") or "none") != "none":
            settings["network"] = v["network"]
        if v.get("credentials"):
            settings["credentials"] = [{"name": c.get("name"), "kind": c.get("kind")}
                                       for c in v["credentials"] if isinstance(c, dict)]
        out.append({"slug": slug, "name": v.get("name") or meta.get("name") or slug,
                    "description": meta.get("description") or "",
                    "files": dict(v.get("files") or {}), "settings": settings})
    return out


def _published_files(SL, slug: str) -> dict:
    meta = SL.get(slug) or {}
    v = SL.version(slug, int(meta["published"])) if meta.get("published") else None
    return dict((v or {}).get("files") or {})


def build_body(a) -> dict:
    """``app.json`` for app ``a`` -- secrets excluded by construction."""
    from . import studio_connections as SC
    from . import studio_store as SS
    refs = _refs(a)
    scripts = _scripts(refs["scripts"])
    for sc in scripts:              # what a script calls travels with it
        refs["connections"].update(sc["settings"]["connections"])
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
            if v.source == "library":
                apis[(v.api.slug, v.version)].update(source=v.source, notes=v.notes or "")
        conns.append(d)
    body = {"app": {"slug": a.slug, "name": a.name, "icon": a.icon,
                    "description": a.description, "fields": a.fields,
                    "graph": a.graph, "actions": a.actions, "design": a.design},
            "stores": stores, "connections": conns, "apis": list(apis.values())}
    if scripts:
        body["scripts"] = scripts
    from . import plugin_automations as PA
    autos = PA.export(a.slug)
    if autos:
        body["automations"] = autos
    return body


def export_app(a, satom_version: str = "") -> tuple[str, bytes]:
    version = a.pkg_version or "1.0.0"
    slug = a.slug.replace("_", "-")
    manifest = {"slug": slug, "name": a.name, "version": version, "kind": "app",
                "icon": a.icon if P.ICON_RE.match(a.icon or "") else "bi-app-indicator",
                "description": (a.description or "")[:500], "datasets": [], "params": [],
                "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if P.VERSION_RE.match(satom_version or ""):
        manifest["min_satom"] = satom_version
    from . import studio_design as D
    body = json.dumps(build_body(a), indent=1, sort_keys=True, ensure_ascii=False)
    files = {P.APP_FILE: body.encode("utf-8")}
    for row in D.assets_of(a.id):
        files["assets/%s.%s" % (row.sha256, D.EXT[row.mime])] = bytes(row.data)
    return "%s-%s%s" % (slug, version, P.EXT), P.write_package(manifest, files)


def _body(pk) -> dict:
    try:
        return json.loads(pk.files[P.APP_FILE].decode("utf-8"))
    except (KeyError, UnicodeDecodeError, ValueError):
        raise AppPackageError("%s is not valid JSON." % P.APP_FILE) from None


def _server_refusal(body: dict) -> None:
    """What ``save_draft`` would refuse ON THIS SERVER, checked before anything
    is written: the form, diagram, actions and design, with the data stores,
    HTTP connections and app the package itself brings counted as present.

    The helpers that create an app, a data store, a connection or an API
    version commit on their own, so a refusal raised halfway through
    ``install`` -- after them -- left what they created behind: importing
    ``dns-lb-lookup`` before ``dns-records`` (its *DNS Records* action opens
    that app) left an empty draft app ``dns-lb-lookup`` (2026-10-30).
    """
    from . import studio_apps as SA
    from . import studio_design as D
    spec = body.get("app") or {}
    slug = str(spec.get("slug") or "").strip()
    ch = SA.choices()
    ch["stores"] = sorted(set(ch.get("stores") or ())
                          | {str(s.get("slug") or "") for s in body.get("stores") or []})
    ch["http"] = sorted(set(ch.get("http") or ())
                        | {str(c.get("slug") or "") for c in body.get("connections") or []
                           if (c.get("kind") or "http") == "http"})
    ch["apps"] = sorted(set(ch.get("apps") or ()) | {slug})
    for act in spec.get("actions") or []:
        if not isinstance(act, dict) or act.get("kind") not in ("run_app", "open_app"):
            continue
        other = str((act.get("params") or {}).get("app") or "")
        if other and other not in ch["apps"]:
            raise AppPackageError(
                "the app package could not be installed: action %s opens the app %s, "
                "which this server does not have -- import its package first; nothing "
                "was written" % (act.get("key"), other))
    try:
        SA.clean_fields(spec.get("fields") or [], ch)
        SA.clean_graph(spec.get("graph") or {})
        SA.clean_actions(spec.get("actions") or [], ch)
        D.clean(spec.get("design") or {})
    except (SA.AppError, D.DesignError) as exc:
        raise AppPackageError("the app package could not be installed: %s; nothing was "
                              "written" % exc) from None


def install(pk, by: str, *, allow_downgrade: bool = False) -> dict:
    """Install an app package. ``{app, created, kept, todo, problems, warnings}``."""
    from ..extensions import db
    from . import package_check as PC
    from . import script_library as SL
    from . import studio_api_library as LIB
    from . import studio_apis as SAPI
    from . import studio_apps as SA
    from . import studio_connections as SC
    from . import studio_design as D
    from . import studio_examples as EX
    from . import studio_store as SS
    if pk.kind != "app":
        raise AppPackageError("not an app package")
    body = _body(pk)
    # Refused before anything is written (defence in depth: the import page
    # checks the whole package first).
    for kind, oslug in PC.objects(body):
        if EX.is_template(kind, oslug):
            raise AppPackageError("%s %s is a template (Plugin Studio > Examples): a package "
                                  "can never replace or create it" % (kind, oslug))
    refused = PC.app_preflight(body, pk.files)
    if refused:
        raise AppPackageError("the app package is refused: " + "; ".join(
            "%s: %s" % (p["where"], p["message"]) for p in refused))
    spec = body.get("app") or {}
    slug = str(spec.get("slug") or "").strip()
    existing = SA.get(slug) if slug else None
    if existing is not None and existing.kind == "script":
        raise AppPackageError("%s is a script app here; an app package cannot replace it" % slug)
    if existing is not None and existing.pkg_version and not allow_downgrade and \
            P.version_tuple(pk.version) < P.version_tuple(existing.pkg_version):
        raise AppPackageError("%s %s is installed and %s is older (tick Allow downgrade)"
                              % (slug, existing.pkg_version, pk.version))
    _server_refusal(body)
    created, kept, todo, warnings = [], [], [], []
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
                                base_path=api.get("base_path") or "",
                                notes=api.get("notes") if api.get("notes") else None, by=by)
                if api.get("source") == LIB.SOURCE and a.slug in LIB.STYLES:
                    v.source = LIB.SOURCE       # built from an API library (section 19)
                SAPI.publish(v, by)
                created.append("API %s %s (%d endpoints, published)"
                               % (a.slug, v.version, len(v.operations)))
            else:
                added = LIB.refresh(v, api, by) if (api.get("source") == LIB.SOURCE
                                                    and a.slug in LIB.STYLES) else 0
                kept.append("API %s %s (exists, %s%s)" % (
                    a.slug, v.version, v.status,
                    "; %d endpoint(s) added from SATOM's API library" % added if added else ""))
        for c in body.get("connections") or []:
            if SC.get(str(c.get("slug") or "")) is not None:
                kept.append("connection %s (exists: its URL and secret are this server's)"
                            % c["slug"])
                continue
            row = SC.create(c["slug"], c.get("name") or c["slug"], c.get("kind") or "http", by)
            form = connection_form(c)
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
        note = "installed from the package %s %s" % (pk.slug, pk.version)
        for sc in body.get("scripts") or []:
            sslug = str(sc["slug"])
            if SL.exists(sslug):
                kept.append("script %s (exists: kept as it is here)" % sslug)
                if _published_files(SL, sslug) != dict(sc.get("files") or {}):
                    warnings.append("script %s exists here and its published files differ from "
                                    "the package's: this server's are kept" % sslug)
                continue
            st = sc.get("settings") or {}
            SL.create(sslug, sc.get("name") or sslug, by)
            SL.save_draft(sslug, sc.get("files") or {},
                          {"name": sc.get("name") or sslug,
                           "description": sc.get("description") or "",
                           "fields": st.get("fields") or [], "timeout": st.get("timeout"),
                           "connections": st.get("connections") or [], "network": "none",
                           "audience": "admins", "credentials": []}, by, note=note)
            n = SL.publish(sslug, note, by).get("published")
            created.append("script %s v%s (published, for admins)" % (sslug, n))
        a = existing
        if a is None:
            a = SA.create(slug, spec.get("name") or slug, by)
            created.append("app %s (draft)" % slug)
        else:
            kept.append("app %s: draft replaced, published version and access unchanged" % slug)
        a.name = (spec.get("name") or a.name)[:120]
        a.description = str(spec.get("description") or "")[:2000]
        from . import bootstrap_icons
        here = a.icon if bootstrap_icons.is_known(a.icon) else "bi-app-indicator"
        if spec.get("icon"):                  # none in the package: this server's stays
            here, why = bootstrap_icons.or_default(spec.get("icon"), here)
            if why:
                warnings.append("app %s: %s" % (slug, why))
        a.icon = here
        a.pkg_version = pk.version
        a.pkg_signer = pk.signer or ""
        db.session.flush()
        for fname, data in sorted(pk.files.items()):
            if fname.startswith("assets/"):
                sha = fname.split("/", 1)[1].split(".", 1)[0]
                if hashlib.sha256(data).hexdigest() != sha:
                    raise SA.AppError("%s does not match its SHA-256 name" % fname)
                if D.get_asset(a.id, sha) is None:
                    D.add_asset(a.id, fname.split("/", 1)[1], data, by)
                    created.append("image %s" % fname.split("/", 1)[1])
        problems = SA.save_draft(a, fields=spec.get("fields") or [],
                                 graph=spec.get("graph") or {},
                                 actions=spec.get("actions") or [],
                                 design=spec.get("design") or {}, by=by)
        from . import plugin_automations as PA
        autos, _bad = PA.clean_entries(body.get("automations"))   # preflight refused bad ones
        got = PA.install(slug, autos, by=by)
        created += got["created"]
        kept += got["kept"]
        warnings += got["warnings"]
        db.session.commit()
    except (SA.AppError, SS.StoreError, SC.ConnectionError_, SAPI.ApiError, KeyError,
            D.DesignError, SL.ScriptError) as exc:
        db.session.rollback()
        raise AppPackageError("the app package could not be installed: %s" % exc) from None
    if a.status != "published":
        todo.append("review the diagram, test it and Publish (Plugin Studio › Apps › %s)" % slug)
    todo += got["todo"]
    return {"app": a, "created": created, "kept": kept, "todo": todo, "warnings": warnings,
            "problems": SA.problems(a) if problems is not None else []}
