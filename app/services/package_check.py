"""Package check -- every rule a ``satom.plugin/1`` package must pass, in one call.

``check(data, target, policy)`` answers, without writing anything, whether
this server (described by ``target``, the ``GET /api/v1/builder/target``
snapshot) would accept the package, and what an import would create and keep.
It is the ONE implementation of those rules: the import page and the Builder
API call it here, and the SATOM Builder runs the very same file from the
rules pack (``services.rules_pack``), so a rule can never drift between the
two sides.

PURE ON PURPOSE
---------------
No Flask, no database, no models: the rules pack runs this module in a plain
Python process with jinja2, markupsafe and cryptography only. Every rule is
REUSED from the module that owns it -- ``plugin_package.read_package``,
``studio_apps.clean_fields`` / ``clean_actions`` / ``clean_graph`` /
``form_ref_problems``, ``studio_flow.validate_graph``, ``studio_design``,
``studio_store``, ``studio_api_spec``, ``studio_connections.clean_definition``,
``script_library`` -- imported inside the functions that use them, and only
their database-free parts are called. What this module adds is the policy
(which rule refuses, under which policy) and the script scan (section 7 of
the contract): a packaged script may not use ``secret`` or ``tcp``, pass
``write=True``, open the network or declare credentials.

POLICIES
--------
``import`` for packages Vision EBC signed; ``builder`` for everything else
that arrives through the Builder API (the Builder always checks with it).
``RULES`` lists every rule with its scope: ``all`` refuses under both
policies, ``builder`` refuses under ``builder`` and warns under ``import``,
``warning`` never refuses.

A malformed package is a problem, never an exception: ``check`` does not
raise for anything the package holds.
"""
from __future__ import annotations

import ast
import base64
import binascii
import copy
import hashlib
import json

POLICIES = ("builder", "import")
#: Bumped when check()'s output shape changes.
CHECK_VERSION = 1

#: Connection keys that would carry a secret. A package never does: secrets
#: are typed into this server (import wizard, or the import call's secrets).
SECRET_KEYS = ("password", "secret", "token", "api_key", "client_secret")
#: What a packaged script may not reach in the SDK, in any spelling.
SCRIPT_FORBIDDEN = ("secret", "tcp")
SDK_MODULES = ("satom_script", "satom_sdk")
#: What a packaged script may use from the SDK.
SCRIPT_SDK = ("inputs", "result", "log", "connection")
#: The kinds a package may hold, and what of an app package travels.
OBJECT_KINDS = ("app", "store", "connection", "script")

ALL, BUILDER, WARNING = "all", "builder", "warning"

#: id -> (scope, rule). The author guide and the user guide are written from
#: this table; every id has a test in tests/test_package_check.py.
RULES = (
    ("package.format", ALL, "The file is a readable satom.plugin/1 package: only the members "
     "plugin.json lists, each matching its sha256, sizes capped, and a signature (when there "
     "is one) by a key this server trusts."),
    ("package.min_satom", ALL, "min_satom is not newer than this server's version."),
    ("code.builder", BUILDER, "A code plugin is refused, whoever signed it: custom logic is a "
     "script app."),
    ("code.signature", ALL, "A code plugin is signed by Vision EBC; unsigned code is never "
     "installed and a publisher can never sign code."),
    ("view.template", BUILDER, "body.jinja parses in SATOM's plugin sandbox."),
    ("view.datasets", WARNING, "Datasets this server does not offer are dropped on import."),
    ("view.params", WARNING, "Input parameters that are malformed or repeated are dropped on "
     "import."),
    ("css.lint", BUILDER, "style.css passes the plugin CSS rules (its errors)."),
    ("css.warning", WARNING, "style.css warnings of the plugin CSS rules."),
    ("app.definition", ALL, "app.json is well formed: the app id, the form, the actions, the "
     "diagram (an object of at most 512 KiB) and the design are valid -- what install would "
     "otherwise fail on."),
    ("app.template", ALL, "A package never replaces or creates a template (Plugin Studio > "
     "Examples, ex-*): app, data store, connection or script."),
    ("app.script_app", ALL, "A package never replaces a script app."),
    ("app.downgrade", WARNING, "A package older than the installed app needs Allow downgrade."),
    ("app.diagram", BUILDER, "The diagram has no problem (studio_flow.validate_graph), with the "
     "data stores, connections and scripts this server has plus those the package creates."),
    ("app.form_refs", BUILDER, "Every form.<field> the diagram reads is a field of the form."),
    ("app.design", BUILDER, "The design places existing fields, Output steps and images."),
    ("design.contrast", WARNING, "Colour pairs of the design that are hard to read."),
    ("asset.name", ALL, "Every assets/* image matches its SHA-256 name."),
    ("asset.image", ALL, "Every assets/* member is a PNG, JPEG, GIF or WebP image within the "
     "size and count limits."),
    ("store.definition", ALL, "A data store has a valid id and valid columns (at least one)."),
    ("store.rows", ALL, "Every seed row fits the store's columns and the size limits."),
    ("store.seed_limit", BUILDER, "A data store carries at most 500 seed rows (import installs "
     "the first 500)."),
    ("store.columns", WARNING, "A column that exists here with another type keeps this "
     "server's type."),
    ("connection.secret", ALL, "A connection never carries a secret (non-empty password, "
     "secret, token, api_key or client_secret)."),
    ("connection.postgres", ALL, "A postgres connection never travels in an app package."),
    ("connection.definition", ALL, "A connection has a valid id, base URL and authentication."),
    ("connection.pin", ALL, "A connection is pinned to an API version that the package carries "
     "or that is published on this server."),
    ("connection.pin_missing", WARNING, "A connection pinned to an API version nobody has is "
     "created without a pin."),
    ("api.definition", ALL, "An API version has a valid id, version and endpoint list."),
    ("api.empty", ALL, "An API version has at least one endpoint."),
    ("script.definition", ALL, "A packaged script has a valid id, files and settings "
     "(script_library limits); its entry is main.py."),
    ("script.syntax", ALL, "Every .py file of a packaged script compiles."),
    ("script.network", ALL, "A packaged script has no network (network absent or none)."),
    ("script.credentials", ALL, "A packaged script declares no credentials."),
    ("script.sdk", ALL, "No source file uses secret or tcp from satom_script / satom_sdk "
     "(imports, attribute access and bare names)."),
    ("script.write", ALL, "No call in a packaged script passes write=True."),
    ("script.db_fields", ALL, "A packaged script has no database fields (lookup, "
     "lookup_multi, dataset): they query this server's database."),
    ("script.connections", ALL, "A packaged script declares only HTTP connections that exist "
     "on this server or that the package creates."),
    ("script.audience", WARNING, "An installed script is for admins until an administrator "
     "changes it."),
    ("script.kept", WARNING, "A script that exists here is kept as it is; a step runs its "
     "published version."),
    ("check.internal", ALL, "The check itself failed on this package."),
)
_SCOPE = {rid: scope for rid, scope, _t in RULES}


class _Report:
    def __init__(self, policy: str):
        self.policy = policy
        self.problems: list[dict] = []
        self.warnings: list[dict] = []

    def add(self, rule: str, where: str, message: str) -> None:
        scope = _SCOPE[rule]
        refuses = scope == ALL or (scope == BUILDER and self.policy == "builder")
        item = {"where": where, "message": str(message), "rule": rule}
        dest = self.problems if refuses else self.warnings
        if item not in dest:
            dest.append(item)

    def result(self, summary: dict) -> dict:
        return {"ok": not self.problems, "problems": self.problems,
                "warnings": self.warnings, "summary": summary}


def _summary() -> dict:
    return {"kind": "", "slug": "", "version": "", "signer": "", "signed_by": "none",
            "creates": [], "keeps": [], "needs_secrets": [], "lands_in": "draft"}


def _keys(target: dict) -> dict:
    """The keys a signature may come from: TRUSTED_KEYS plus the target's
    enabled publishers (``{"key_id", "public_key": base64}``)."""
    from . import plugin_package as P
    keys = P.trusted_keys()
    for p in target.get("publishers") or []:
        if not isinstance(p, dict) or p.get("enabled") is False:
            continue
        try:
            raw = base64.b64decode(str(p.get("public_key") or ""), validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(raw) == 32 and hashlib.sha256(raw).hexdigest() == p.get("key_id"):
            keys.setdefault(p["key_id"], raw)
    return keys


# --------------------------------------------------------------------------- #
#  the entry points                                                            #
# --------------------------------------------------------------------------- #
def check(data: bytes, target: dict, policy: str = "builder") -> dict:
    """``{ok, problems, warnings, summary}`` for package *data* on the server
    *target* describes. See the module doc and contract section 3.2."""
    if policy not in POLICIES:
        raise ValueError("policy must be one of %s" % ", ".join(POLICIES))
    from . import plugin_package as P
    target = target if isinstance(target, dict) else {}
    r, summary = _Report(policy), _summary()
    try:
        pk = P.read_package(data, _keys(target))
    except P.PackageError as exc:
        r.add("package.format", "package", str(exc))
        return r.result(summary)
    except Exception as exc:  # noqa: BLE001 -- a broken zip member, a bad type
        r.add("package.format", "package", "the package cannot be read: %s" % exc)
        return r.result(summary)
    _check_package(pk, target, r, summary)
    return r.result(summary)


def install_guard(pk_or_bytes, target: dict, policy: str) -> list[dict]:
    """The problems that refuse an import -- what the importer asks before
    it installs. Takes the package bytes, or a ``plugin_package.Package``
    already read (and its signature already checked) by the caller."""
    if isinstance(pk_or_bytes, (bytes, bytearray)):
        return check(bytes(pk_or_bytes), target, policy)["problems"]
    if policy not in POLICIES:
        raise ValueError("policy must be one of %s" % ", ".join(POLICIES))
    r = _Report(policy)
    _check_package(pk_or_bytes, target if isinstance(target, dict) else {}, r, _summary())
    return r.problems


def app_preflight(body: dict, files: dict | None = None) -> list[dict]:
    """The problems of an app package that need no server state -- what
    ``studio_app_package.install`` refuses before it writes anything."""
    r = _Report("import")
    try:
        _app_rules(body, files or {}, None, r, None)
    except Exception as exc:  # noqa: BLE001
        r.add("check.internal", "app.json", "the package could not be checked: %s" % exc)
    return r.problems


def objects(body: dict) -> list[tuple[str, str]]:
    """``[(kind, slug)]`` of everything an app package installs: the app,
    its data stores, connections and scripts."""
    out = []
    spec = body.get("app") if isinstance(body, dict) else None
    if isinstance(spec, dict) and spec.get("slug"):
        out.append(("app", str(spec["slug"]).strip()))
    for kind, key in (("store", "stores"), ("connection", "connections"),
                      ("script", "scripts")):
        items = body.get(key) if isinstance(body, dict) else None
        for it in items if isinstance(items, list) else []:
            if isinstance(it, dict) and it.get("slug"):
                out.append((kind, str(it["slug"])))
    return out


# --------------------------------------------------------------------------- #
#  per kind                                                                    #
# --------------------------------------------------------------------------- #
def _check_package(pk, target: dict, r: _Report, summary: dict) -> None:
    from . import plugin_package as P
    summary.update(kind=pk.kind, slug=pk.slug, version=pk.version, signer=pk.signer or "",
                   signed_by=("vision-ebc" if pk.signer in P.TRUSTED_KEYS
                              else "publisher" if pk.signer else "none"))
    try:
        need = pk.manifest.get("min_satom")
        have = str(target.get("satom_version") or "")
        if need and P.version_tuple(need) > P.version_tuple(have):
            r.add("package.min_satom", "manifest",
                  "%s %s needs SATOM %s or newer (this server runs %s)"
                  % (pk.slug, pk.version, need, have or "an unknown version"))
        if pk.kind == "code":
            _check_code(pk, summary, r)
        elif pk.kind == "app":
            summary["lands_in"] = "draft"
            body = json.loads(pk.files[P.APP_FILE].decode("utf-8"))
            _app_rules(body, pk.files, target, r, summary)
        else:
            _check_view(pk, target, r, summary)
    except Exception as exc:  # noqa: BLE001 -- problems never raise
        r.add("check.internal", "package", "the package could not be checked: %s" % exc)


def _check_code(pk, summary: dict, r: _Report) -> None:
    r.add("code.builder", "manifest", "a code plugin is refused: build a script app instead")
    if summary["signed_by"] != "vision-ebc":
        r.add("code.signature", "manifest",
              "a code plugin must be signed by Vision EBC: unsigned code is never installed "
              "and a publisher can never sign code")


def _check_view(pk, target: dict, r: _Report, summary: dict) -> None:
    from . import plugin_sandbox as PS
    summary["lands_in"] = "testing" if pk.signer else "draft"
    summary["creates"] = ["%s %s (or the same slug updated in place)" % (pk.kind, pk.slug)]
    try:
        PS._SANDBOX.parse(pk.text("body.jinja"))
    except Exception as exc:  # noqa: BLE001 -- TemplateSyntaxError and kin
        line = getattr(exc, "lineno", None)
        r.add("view.template", "body.jinja", ("line %s: %s" % (line, exc)) if line else str(exc))
    known = set((target.get("choices") or {}).get("datasets") or [])
    for k in pk.manifest.get("datasets") or []:
        if str(k) not in known:
            r.add("view.datasets", "datasets",
                  "dataset %s is not offered by this server: the import drops it" % k)
    raw = pk.manifest.get("params") or []
    kept = {p["name"] for p in PS.clean_param_defs(raw)}
    seen = set()
    for item in raw:
        name = PS.slugify(str(item.get("name") or "")).replace("-", "_")[:40] \
            if isinstance(item, dict) else ""
        if not name or name not in kept or name in seen:
            r.add("view.params", "params",
                  "parameter %r is malformed or repeated: the import drops it"
                  % ((item or {}).get("name") if isinstance(item, dict) else item))
        seen.add(name)
    from . import plugin_css
    for it in plugin_css.lint(pk.text("style.css")) or []:
        where = "style.css:%s" % it.get("line") if it.get("line") else "style.css"
        r.add("css.lint" if it.get("level") == "error" else "css.warning", where,
              it.get("message") or "")


# --------------------------------------------------------------------------- #
#  app packages                                                                #
# --------------------------------------------------------------------------- #
def _list(body: dict, key: str, r: _Report) -> list[dict]:
    v = body.get(key)
    if v in (None, ""):
        return []
    if not isinstance(v, list):
        r.add("app.definition", key, "%s must be a list" % key)
        return []
    out = []
    for i, it in enumerate(v):
        if isinstance(it, dict):
            out.append(it)
        else:
            r.add("app.definition", "%s[%d]" % (key, i), "each entry is an object")
    return out


def _twice(items: list[dict], key: str, r: _Report, what: str) -> None:
    seen = set()
    for it in items:
        k = it.get("slug") if key == "slug" else (it.get("slug"), it.get("version"))
        if k in seen:
            r.add("app.definition", what, "%s %s is listed twice" % (what, k))
        seen.add(k)


def _app_rules(body, files: dict, target: dict | None, r: _Report, summary: dict | None) -> None:
    """Every rule of an app package. ``target`` None = the server-free rules
    only (install's preflight); then nothing is added to a summary."""
    from . import studio_api_spec as S
    from . import studio_apis as SAPI
    from . import studio_app_package as SAP
    from . import studio_apps as SA
    from . import studio_connections as SC
    from . import studio_store as SS

    if not isinstance(body, dict) or not isinstance(body.get("app"), dict):
        r.add("app.definition", "app.json", "app.json has no 'app' object")
        return
    creates, keeps, secrets = [], [], []
    ex = (target or {}).get("existing") or {}
    ex_apps, ex_stores = ex.get("apps") or {}, ex.get("stores") or {}
    ex_conns, ex_scripts = ex.get("connections") or {}, ex.get("scripts") or {}
    ex_versions = {(str(v[0]), str(v[1])): str(v[2]) for v in ex.get("api_versions") or []
                   if isinstance(v, (list, tuple)) and len(v) >= 3}

    if target is not None:
        tmpl = target.get("templates") or {}
        for kind, slug in objects(body):
            if slug in (tmpl.get(kind + "s") or []):
                r.add("app.template", "%ss[%s]" % (kind, slug) if kind != "app" else "app",
                      "%s %s is a template (Plugin Studio > Examples): a package can never "
                      "replace or create it" % (kind, slug))

    # API Catalog versions ---------------------------------------------------
    apis = _list(body, "apis", r)
    _twice(apis, "version", r, "API")
    pkg_ops = {}
    for api in apis:
        slug, ver = str(api.get("slug") or ""), str(api.get("version") or "")
        where = "apis[%s %s]" % (slug, ver)
        if not SAPI._SLUG_RE.match(slug.strip()):
            r.add("api.definition", where, "API id %r: lowercase letters, digits, - and _, "
                  "2 to 48 characters" % slug)
            continue
        if not SAPI._VERSION_RE.match(ver.strip()):
            r.add("api.definition", where, "version %r: letters, digits and . _ + -, up to 32 "
                  "characters" % ver)
            continue
        try:
            SAPI.clean_docs_url(api.get("docs_url"))
            ops = S.clean_operations(api.get("operations") or [])
            if str(api.get("base_path") or "").strip().rstrip("/"):
                S.clean_path(str(api["base_path"]).strip().rstrip("/"))
        except (S.SpecError, SAPI.ApiError) as exc:
            r.add("api.definition", where, str(exc))
            continue
        if not ops:
            r.add("api.empty", where, "API %s %s has no endpoints: a version is published with "
                  "its endpoints, so it cannot be empty" % (slug, ver))
            continue
        pkg_ops[(slug, ver)] = ops
        if (slug, ver) in ex_versions:
            keeps.append("API %s %s (exists, %s)" % (slug, ver, ex_versions[(slug, ver)]))
        else:
            creates.append("API %s %s (%d endpoints, published)" % (slug, ver, len(ops)))

    # connections -------------------------------------------------------------
    conns = _list(body, "connections", r)
    _twice(conns, "slug", r, "connection")
    created_http, catalog, pkg_conn_kind = [], {}, {}
    for c in conns:
        slug = str(c.get("slug") or "")
        where = "connections[%s]" % slug
        kind = c.get("kind") or "http"
        pkg_conn_kind[slug] = kind
        if not SC._SLUG_RE.match(slug.strip()):
            r.add("connection.definition", where, "connection id %r: lowercase letters, digits, "
                  "- and _, 2 to 48 characters" % slug)
            continue
        if kind == "postgres":
            r.add("connection.postgres", where, "connection %s is a postgres connection: an app "
                  "package carries HTTP connections only (external databases are this "
                  "server's own connections)" % slug)
            continue
        carried = [k for k in SECRET_KEYS if c.get(k) not in (None, "")]
        if carried:
            r.add("connection.secret", where, "connection %s carries a secret (%s): a package "
                  "never holds one -- it is typed on the server that imports it"
                  % (slug, ", ".join(carried)))
        try:
            d = SC.clean_definition({**SAP.connection_form(c), "kind": kind})
        except SC.ConnectionError_ as exc:
            r.add("connection.definition", where, str(exc))
            continue
        exists = slug in ex_conns
        if c.get("api"):
            key = (str(c.get("api")), str(c.get("api_version") or ""))
            if target is not None and not exists and ex_versions.get(key) == "draft":
                r.add("connection.pin", where, "connection %s is pinned to API %s %s, a draft "
                      "on this server: publish it there first" % ((slug,) + key))
            elif key in pkg_ops:
                catalog[slug] = {"api": key[0], "version": key[1],
                                 "ops": [{k: o[k] for k in ("id", "method", "path", "summary")}
                                         for o in pkg_ops[key]]}
            elif target is not None and not exists and key not in ex_versions:
                r.add("connection.pin_missing", where, "API %s %s is neither in the package nor "
                      "on this server: connection %s is created without a pin" % (key + (slug,)))
        if target is None:
            continue
        if exists:
            keeps.append("connection %s (exists: its URL and secret are this server's)" % slug)
        else:
            creates.append("connection %s" % slug)
            created_http.append(slug)
            if d["auth"] != "none":
                secrets.append(slug)

    # data stores ---------------------------------------------------------------
    stores = _list(body, "stores", r)
    _twice(stores, "slug", r, "data store")
    created_stores = []
    for st in stores:
        slug = str(st.get("slug") or "")
        where = "stores[%s]" % slug
        try:
            SS.validate_slug(slug)
            cols = SS.clean_columns(st.get("columns") or [])
            if not cols:
                raise SS.StoreError("a data store needs at least one column")
        except SS.StoreError as exc:
            r.add("store.definition", where, str(exc))
            continue
        rows = st.get("rows") or []
        if not isinstance(rows, list):
            r.add("store.rows", where, "the seed rows are a list")
            rows = []
        if len(rows) > SAP.MAX_SEED_ROWS:
            r.add("store.seed_limit", where, "%d seed rows: a package carries at most %d (the "
                  "import installs the first %d)" % (len(rows), SAP.MAX_SEED_ROWS,
                                                    SAP.MAX_SEED_ROWS))
        total = 0
        for i, row in enumerate(rows[:SAP.MAX_SEED_ROWS], 1):
            try:
                total += len(SS._encoded(SS.clean_row(cols, row)))
            except SS.StoreError as exc:
                r.add("store.rows", where, "row %d: %s" % (i, exc))
        if total > SS.MAX_STORE_BYTES:
            r.add("store.rows", where, "the seed rows are larger than %d MiB"
                  % (SS.MAX_STORE_BYTES // 1024 // 1024))
        if target is None:
            continue
        if slug in ex_stores:
            have = [c for c in (ex_stores[slug] or {}).get("columns") or [] if isinstance(c, dict)]
            names = {c.get("name"): c.get("type") for c in have}
            more = [c for c in cols if c["name"] not in names]
            for c in cols:
                if c["name"] in names and names[c["name"]] != c["type"]:
                    r.add("store.columns", where, "column %s is %s here and %s in the package: "
                          "this server's type is kept" % (c["name"], names[c["name"]], c["type"]))
            try:
                SS.clean_columns(have + more)
            except SS.StoreError as exc:
                r.add("store.definition", where, "adding the package's columns: %s" % exc)
            keeps.append("data store %s (exists: rows kept%s)" % (
                slug, ", adds " + ", ".join(c["name"] for c in more) if more else ""))
        else:
            creates.append("data store %s (%d rows)" % (slug, min(len(rows), SAP.MAX_SEED_ROWS)))
            created_stores.append(slug)

    # scripts ---------------------------------------------------------------------
    scripts = _list(body, "scripts", r)
    _twice(scripts, "slug", r, "script")
    created_scripts = []
    for sc in scripts:
        ok = _script_rules(sc, r, target, ex_conns, pkg_conn_kind)
        slug = str(sc.get("slug") or "")
        if target is None or not ok:
            continue
        if slug in ex_scripts:
            keeps.append("script %s (exists: kept as it is here)" % slug)
            if not (ex_scripts[slug] or {}).get("published"):
                r.add("script.kept", "scripts[%s]" % slug, "script %s exists here but is not "
                      "published: the step that runs it waits for that" % slug)
        else:
            creates.append("script %s v1 (published, for admins)" % slug)
            created_scripts.append(slug)

    # images -------------------------------------------------------------------------
    from . import studio_design as D
    assets = set()
    for name in sorted(n for n in files if n.startswith("assets/")):
        data = files[name]
        sha = name.split("/", 1)[1].split(".", 1)[0]
        if hashlib.sha256(data).hexdigest() != sha:
            r.add("asset.name", name, "%s does not match its SHA-256 name" % name)
            continue
        if not D.sniff(data):
            r.add("asset.image", name, "%s is not a PNG, JPEG, GIF or WebP image" % name)
        elif len(data) > D.ASSET_MAX:
            r.add("asset.image", name, "%s is larger than %d KiB" % (name, D.ASSET_MAX // 1024))
        assets.add(sha)
    if len(assets) > D.MAX_ASSETS:
        r.add("asset.image", "assets", "an app holds at most %d images" % D.MAX_ASSETS)

    # the app ---------------------------------------------------------------------------
    spec = body["app"]
    slug = str(spec.get("slug") or "").strip()
    if not SA._SLUG_RE.match(slug):
        r.add("app.definition", "app", "app id %r: lowercase letters, digits, - and _, 2 to 48 "
              "characters" % slug)
    if target is not None and slug in ex_apps:
        cur = ex_apps[slug] or {}
        if cur.get("kind") == "script":
            r.add("app.script_app", "app", "%s is a script app here: a package can never "
                  "replace it" % slug)
        from . import plugin_package as P
        if summary and cur.get("pkg_version") and \
                P.version_tuple(summary["version"]) < P.version_tuple(cur["pkg_version"]):
            r.add("app.downgrade", "app", "%s %s is installed and %s is older: the import needs "
                  "Allow downgrade" % (slug, cur["pkg_version"], summary["version"]))
        keeps.append("app %s: draft replaced, published version and access unchanged" % slug)
    elif target is not None:
        creates.append("app %s (draft)" % slug)

    ch = None
    if target is not None:
        ch = copy.deepcopy(target.get("choices") or {})
        for key, more in (("stores", created_stores), ("http", created_http),
                          ("scripts", created_scripts), ("apps", [slug])):
            ch[key] = list(ch.get(key) or []) + [x for x in more if x not in (ch.get(key) or [])]
        ch["catalog"] = {**(ch.get("catalog") or {}), **catalog}
    fields = []
    try:
        fields = SA.clean_fields(spec.get("fields") or [], ch)
    except SA.AppError as exc:
        r.add("app.definition", "app.fields", str(exc))
    try:
        SA.clean_actions(spec.get("actions") or [], ch)
    except SA.AppError as exc:
        r.add("app.definition", "app.actions", str(exc))
    graph = None
    try:
        graph = SA.clean_graph(spec.get("graph") or {})
    except SA.AppError as exc:
        r.add("app.definition", "app.graph", str(exc))
    design = None
    try:
        design = D.clean(spec.get("design") or {})
    except D.DesignError as exc:
        r.add("app.definition", "app.design", "design: %s" % exc)
    if target is not None and graph is not None:
        from . import studio_flow as F
        for p in F.validate_graph(graph, ch):
            r.add("app.diagram", "app.graph", p)
        for p in SA.form_ref_problems(fields, graph):
            r.add("app.form_refs", "app.graph", p)
        if design is not None:
            for p in D.problems(design, fields, graph, assets):
                r.add("app.design", "app.design", p)
            for w in D.warnings(design):
                r.add("design.contrast", "app.design", w)
    if summary is not None:
        creates += ["image %s" % n.split("/", 1)[1] for n in sorted(files)
                    if n.startswith("assets/")]
        summary.update(creates=creates, keeps=keeps, needs_secrets=secrets)


# --------------------------------------------------------------------------- #
#  scripts (contract section 7)                                                #
# --------------------------------------------------------------------------- #
def _script_rules(sc: dict, r: _Report, target, ex_conns: dict, pkg_conn_kind: dict) -> bool:
    """The rules of one packaged script. False when it is unusable."""
    from . import script_library as SL
    slug = str(sc.get("slug") or "")
    where = "scripts[%s]" % slug
    try:
        SL.validate_slug(slug)
        files = SL.validate_files(sc.get("files"))
    except SL.ScriptError as exc:
        r.add("script.definition", where, str(exc))
        return False
    settings = sc.get("settings") if isinstance(sc.get("settings"), dict) else {}
    ok = True
    if str(settings.get("network") or "none") != "none":
        r.add("script.network", where, "script %s asks for network %r: a packaged script runs "
              "with no network" % (slug, settings.get("network")))
        ok = False
    if settings.get("credentials"):
        r.add("script.credentials", where, "script %s declares credentials: a packaged script "
              "reaches an API only through its declared connections" % slug)
        ok = False
    if settings.get("entry") not in (None, "", SL.ENTRY):
        r.add("script.definition", where, "the entry of a script is %s" % SL.ENTRY)
        ok = False
    fields = settings.get("fields") or []
    db_fields = [f.get("name") for f in fields if isinstance(f, dict)
                 and f.get("type") in SL.DB_FIELD_TYPES] if isinstance(fields, list) else []
    if db_fields:
        r.add("script.db_fields", where, "script %s has database fields (%s): they query this "
              "server's database and cannot travel in a package" % (slug, ", ".join(
                  str(x) for x in db_fields)))
        ok = False
    else:
        try:
            clean = SL.clean_settings({"name": sc.get("name") or slug,
                                       "description": sc.get("description") or "",
                                       "fields": fields, "timeout": settings.get("timeout"),
                                       "connections": settings.get("connections"),
                                       "network": "none", "audience": "admins"})
        except SL.ScriptError as exc:
            r.add("script.definition", where, str(exc))
            return False
        for cs in clean["connections"]:
            if cs in pkg_conn_kind:
                good = pkg_conn_kind[cs] == "http"
            elif target is not None:
                good = (ex_conns.get(cs) or {}).get("kind") == "http"
            else:
                good = True             # install: the server's own are checked at run time
            if not good:
                r.add("script.connections", where, "script %s declares connection %s, which is "
                      "neither an HTTP connection of the package nor of this server" % (slug, cs))
                ok = False
    if settings.get("audience") not in (None, "", "admins"):
        r.add("script.audience", where, "script %s is installed for admins (the package says "
              "%s): an administrator widens it" % (slug, settings.get("audience")))
    for p in SL.syntax_problems(files):
        r.add("script.syntax", "%s.files[%s]" % (where, p["file"]),
              "line %s: %s" % (p["line"], p["message"]))
        ok = False
    for path in sorted(files):
        if not path.endswith(".py"):
            continue
        for rule, line, msg in scan_script(files[path]):
            r.add(rule, "%s.files[%s]" % (where, path), "line %d: %s" % (line, msg))
            ok = False
    return ok


def scan_script(src: str) -> list[tuple[str, int, str]]:
    """``[(rule, line, message)]``: what a packaged script's source may not
    do. Checked on the syntax tree, so a comment or a string never counts and
    every spelling does: ``from satom_sdk import tcp``, ``import satom_script
    as s; s.secret(...)``, a bare ``secret``, ``getattr(sdk, "tcp")``, a star
    import (which would hide the name), and any call passing ``write=`` other
    than ``False``. Source that does not parse returns nothing (the syntax
    rule reports it)."""
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return []
    out = []
    bad = set(SCRIPT_FORBIDDEN)
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0) or 0
        if isinstance(node, ast.ImportFrom) and node.level == 0 and \
                (node.module or "").split(".")[0] in SDK_MODULES:
            for a in node.names:
                if a.name == "*":
                    out.append(("script.sdk", line, "from %s import * is refused: import the "
                                "names you use (%s)" % (node.module, ", ".join(SCRIPT_SDK))))
                elif a.name in bad:
                    out.append(("script.sdk", line, "%s() is not available to a packaged "
                                "script" % a.name))
        elif isinstance(node, ast.Attribute) and node.attr in bad:
            out.append(("script.sdk", line, "%s is not available to a packaged script" % node.attr))
        elif isinstance(node, ast.Name) and node.id in bad:
            out.append(("script.sdk", line, "%s is not available to a packaged script" % node.id))
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in ("getattr", "hasattr") and \
                    len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and \
                    node.args[1].value in bad:
                out.append(("script.sdk", line, "%s is not available to a packaged script"
                            % node.args[1].value))
            for kw in node.keywords:
                if kw.arg == "write" and not (isinstance(kw.value, ast.Constant)
                                              and kw.value.value is False):
                    out.append(("script.write", line, "write= is refused: a packaged script "
                                "reads, it never writes through a connection"))
    return sorted(set(out), key=lambda x: (x[1], x[0], x[2]))


# --------------------------------------------------------------------------- #
#  schema and author guide                                                     #
# --------------------------------------------------------------------------- #
def limits() -> dict:
    """Every numeric limit a package meets, by name."""
    from . import plugin_package as P
    from . import script_library as SL
    from . import studio_api_spec as S
    from . import studio_app_package as SAP
    from . import studio_apps as SA
    from . import studio_connections as SC
    from . import studio_design as D
    from . import studio_flow as F
    from . import studio_store as SS
    return {
        "package_bytes": P.MAX_PACKAGE, "package_member_bytes": P.MAX_FILE,
        "package_expanded_bytes": P.MAX_TOTAL, "package_members": P.MAX_FILES,
        "form_fields": SA.MAX_FIELDS, "actions": SA.MAX_ACTIONS, "select_options": SA.MAX_OPTIONS,
        "diagram_bytes": SA.MAX_GRAPH_BYTES, "run_steps": F.MAX_STEPS,
        "run_seconds": F.RUN_TIMEOUT, "value_bytes": F.MAX_VALUE_BYTES,
        "store_columns": SS.MAX_COLUMNS, "store_rows": SS.MAX_ROWS,
        "store_value_chars": SS.MAX_VALUE_CHARS, "store_row_bytes": SS.MAX_ROW_BYTES,
        "store_bytes": SS.MAX_STORE_BYTES, "seed_rows": SAP.MAX_SEED_ROWS,
        "connection_timeout": SC.MAX_TIMEOUT, "api_endpoints": S.MAX_OPERATIONS,
        "design_blocks": D.MAX_BLOCKS, "design_depth": D.MAX_DEPTH, "design_columns": D.MAX_COLUMNS,
        "design_tabs": D.MAX_TABS, "design_bytes": D.MAX_JSON, "images": D.MAX_ASSETS,
        "image_bytes": D.ASSET_MAX,
        "script_files": SL.MAX_FILES, "script_file_bytes": SL.MAX_FILE_BYTES,
        "script_bytes": SL.MAX_TOTAL_BYTES, "script_depth": SL.MAX_DEPTH,
        "script_fields": SL.MAX_FIELDS, "script_connections": SL.MAX_CONNECTIONS,
        "script_timeout_min": SL.TIMEOUT_MIN, "script_timeout_max": SL.TIMEOUT_MAX,
    }


def schema(target: dict) -> dict:
    """What an editor (or a model) builds from: contract section 3.2,
    computed with the target server's choices."""
    from . import plugin_sandbox as PS
    from . import script_library as SL
    from . import studio_apps as SA
    from . import studio_connections as SC
    from . import studio_design as D
    from . import studio_flow as F
    from . import studio_satom as SAT
    from . import studio_store as SS
    target = target if isinstance(target, dict) else {}
    ch = target.get("choices") or {}
    sources = ch.get("satom_sources") or [{"key": k, "label": lab} for k, lab in SAT.SOURCES]
    return {
        "field_types": list(SA.FIELD_TYPES), "list_types": list(SA.LIST_TYPES),
        "satom_sources": sources,
        "step_kinds": json.loads(json.dumps(F.kinds_json(ch), default=list)),
        "branches": [dict(b) for b in F.BRANCHES],
        "action_kinds": json.loads(json.dumps(SA.action_schema(ch), default=list)),
        "column_types": list(SS.COLUMN_TYPES),
        "connection": {"kinds": ["http"], "auth": list(SC.HTTP_AUTH)},
        "design": json.loads(json.dumps(D.schema(), default=list)),
        "datasets": list(ch.get("datasets") or []),
        "param_types": list(PS._PARAM_TYPES),
        "script": {"field_types": [t for t in SL.FIELD_TYPES if t not in SL.DB_FIELD_TYPES],
                   "sdk": list(SCRIPT_SDK), "max_timeout": SL.TIMEOUT_MAX},
        "limits": limits(),
    }


def author_guide(target: dict) -> str:
    """Markdown generated FROM the rules and limits above, never written by
    hand: the fixed part of every AI prompt the Builder sends."""
    target = target if isinstance(target, dict) else {}
    sc = schema(target)
    ch = target.get("choices") or {}
    L = []
    w = L.append
    w("# Building a SATOM plugin for SATOM %s" % (target.get("satom_version") or "?"))
    w("")
    w("A package is a `satom.plugin/1` zip: `plugin.json` (format, slug, name, version X.Y.Z, "
      "kind, icon bi-*, description, datasets, params, min_satom, files {member: sha256}) and "
      "the members it lists. Kinds: `view` and `widget` (body.jinja, style.css, script.js) "
      "and `app` (app.json plus assets/<sha256>.<png|jpg|gif|webp>). `code` is refused.")
    w("")
    w("## Rules the importer applies")
    w("")
    w("| Rule | Refuses | What it requires |")
    w("|---|---|---|")
    scope = {ALL: "always", BUILDER: "Builder packages", WARNING: "never (warning)"}
    for rid, sc_, text in RULES:
        if rid != "check.internal":
            w("| `%s` | %s | %s |" % (rid, scope[sc_], text))
    w("")
    w("## Views and widgets")
    w("")
    w("- body.jinja renders in an immutable Jinja sandbox with autoescape and StrictUndefined; "
      "each dataset is a variable `{{ <dataset>.rows }}` / `.columns`, input values are "
      "`{{ params.<name> }}`.")
    w("- Datasets on this server: %s." % (", ".join("`%s`" % d for d in sc["datasets"]) or "none"))
    w("- Parameter types: %s." % ", ".join("`%s`" % t for t in sc["param_types"]))
    w("- style.css follows the plugin CSS rules; script.js runs in a sandboxed frame.")
    w("")
    w("## Apps (app.json)")
    w("")
    w("`{\"app\": {slug, name, icon, description, fields, graph, actions, design}, "
      "\"stores\": [...], \"connections\": [...], \"apis\": [...], \"scripts\": [...]}`")
    w("")
    w("### Form fields")
    w("")
    w("Types: %s. List types (`search` allowed): %s. `satom_select` sources: %s." % (
        ", ".join("`%s`" % t for t in sc["field_types"]),
        ", ".join("`%s`" % t for t in sc["list_types"]),
        ", ".join("`%s`" % s["key"] for s in sc["satom_sources"])))
    w("")
    w("### Diagram")
    w("")
    w("`graph = {\"nodes\": [{key, kind, label, params, x, y}], \"edges\": [{src, dst, "
      "branch}]}`; exactly one `start`. Branches: %s. Templates are Jinja in a sandbox with "
      "StrictUndefined over `form`, `vars`, every saved variable by name and `run`."
      % ", ".join("`%s`" % b["key"] for b in sc["branches"]))
    w("")
    for k in sc["step_kinds"]:
        w("- `%s` -- %s (%s%s). %s" % (k["key"], k["label"], k["group"],
                                       ", writes" if k["writes"] else "", k["summary"]))
        for p in k["params"]:
            extra = []
            if p.get("required"):
                extra.append("required")
            if p.get("choices"):
                extra.append("one of " + ", ".join("`%s`" % c for c in p["choices"]))
            if p.get("default"):
                extra.append("default `%s`" % p["default"])
            w("  - `%s` (%s%s)" % (p["name"], p["kind"], "; " + "; ".join(extra) if extra else ""))
    w("")
    w("### Actions on the output")
    w("")
    for a in sc["action_kinds"]:
        w("- `%s` -- %s: %s" % (a["key"], a["label"],
                                 ", ".join("`%s`" % p["name"] for p in a["params"])))
    w("")
    w("### Data stores, connections, API versions")
    w("")
    w("- Store: `{slug, name, description, columns: [{name, label, type, required}], rows}`; "
      "column types %s." % ", ".join("`%s`" % t for t in sc["column_types"]))
    w("- Connection: `{slug, name, kind: \"http\", base_url, auth, username, header_name, "
      "token_url, scope, verify_tls, timeout, api, api_version}`; auth %s. Never a secret."
      % ", ".join("`%s`" % t for t in sc["connection"]["auth"]))
    w("- API version: `{slug, name, owner, docs_url, description, version, base_path, "
      "operations: [{id, method, path, summary, params, body}]}`, at least one endpoint.")
    w("")
    w("### Scripts")
    w("")
    w("`{slug, name, description, files: {\"main.py\": ...}, settings: {fields, timeout, "
      "audience, connections, entry}}`. Field types: %s. The SDK: `from satom_script import "
      "%s`. No `secret`, no `tcp`, no `write=True`, no network, no credentials; timeout at "
      "most %d s." % (", ".join("`%s`" % t for t in sc["script"]["field_types"]),
                      ", ".join(SCRIPT_SDK), sc["script"]["max_timeout"]))
    w("")
    w("## On this server")
    w("")
    for key, label in (("stores", "Data stores"), ("http", "HTTP connections"),
                       ("scripts", "Published scripts"), ("apps", "Apps")):
        w("- %s: %s" % (label, ", ".join("`%s`" % x for x in ch.get(key) or []) or "none"))
    for conn, cat in sorted((ch.get("catalog") or {}).items()):
        w("- `%s` is pinned to API %s %s: %s" % (conn, cat.get("api"), cat.get("version"), ", ".join(
            "`%s` %s %s" % (o.get("id"), o.get("method"), o.get("path"))
            for o in cat.get("ops") or [])))
    w("")
    w("## Limits")
    w("")
    for k, v in sorted(sc["limits"].items()):
        w("- `%s`: %s" % (k, v))
    return "\n".join(L) + "\n"
