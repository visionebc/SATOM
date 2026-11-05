"""Python Studio > Connections -- named external APIs and databases.

Three kinds:

* ``http`` -- a base URL plus an authentication. Every call stays under that
  base URL: a path is joined to it, an absolute URL in a path is refused, and
  redirects are NOT followed (a 3xx comes back as the answer). So an app step
  that says "call the CRM" cannot be steered to another host by a value a user
  typed into the form.
* ``postgres`` -- an external PostgreSQL database (a customer's CMDB, a
  reporting database). Queries are parameterised (``%(name)s``); a step reads
  in a READ ONLY transaction unless the administrator ticked "allow writes"
  on it.
* ``server`` -- a Linux web server prepared with ``hostctl/install-satom-webctl.sh``
  (services/studio_server.py): SSH to an unprivileged account whose key can
  run ``satom-webctl`` and nothing else. The secret is SATOM's SSH private
  key (generated here, never typed, never shown); the host key is pinned by
  an explicit "Fetch and trust"; writes need "allow writes". Both live in
  ``app_settings`` ``studio.connection.server.<slug>`` (no schema change).

The secret (password, token, API key, client secret) is never a column of
``studio_connections``: it is the ``app_settings`` row
``studio.connection.secret.<slug>`` (Fernet) or the vault path
``studio/connections/<slug>``, by the vault mode, like every other setting
secret -- and ``secret_backend`` migrates and scrubs it with them. It is
write-only from the UI and is redacted out of every error text.

Calls are made by SATOM, never with the credential in a script's hands: an
app step and the Test button call from the web worker, and a Script Library
script that DECLARES a connection calls through the runner's broker
(``studio_broker``): the script sends the request, the runner — outside the
jail — adds the credential, which reaches the runner only as a single-use
wrapped vault token. Every one of those calls goes through the same core
(``studio_http``): base-URL lock, no redirects, redaction, and a destination
check that refuses loopback, link-local (cloud metadata), multicast, reserved
and this node's own addresses.
"""
from __future__ import annotations

import json
import re
import time
from urllib.parse import urlsplit, urlunsplit

from ..extensions import db
from ..models_studio import StudioConnection
from . import prefixed_secret as PS
from . import studio_http as H

KINDS = ("http", "postgres", "server")
#: ``session`` = log in with user + password at a path under the base URL
#: and reuse the session cookie (the DDI API, FA-0007).
HTTP_AUTH = ("none", "basic", "bearer", "api_key", "oauth2", "session")
PG_AUTH = ("password",)
SERVER_OPTS_PREFIX = "studio.connection.server."
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
SECRET_PREFIX = "studio.connection.secret."
VAULT_FIELD = "value"
MAX_BODY = 2 * 1024 * 1024
MAX_SQL_ROWS = 5000
MAX_TIMEOUT = 120

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,47}$")
_HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


#: One exception for the whole connection layer, raised by studio_http too.
ConnectionError_ = H.ConnectionError_


def vault_path(slug: str) -> str:
    return "studio/connections/%s" % slug


def _key(slug: str) -> str:
    return SECRET_PREFIX + slug


# --------------------------------------------------------------------------- #
#  CRUD                                                                        #
# --------------------------------------------------------------------------- #
def get(slug: str) -> StudioConnection | None:
    return StudioConnection.query.filter_by(slug=slug).first()


def list_connections(kind: str | None = None) -> list[StudioConnection]:
    q = StudioConnection.query
    if kind:
        q = q.filter_by(kind=kind)
    return q.order_by(StudioConnection.name).all()


def _clean_base_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ConnectionError_("a base URL is required")
    if _CTRL.search(url) or len(url) > 500:
        raise ConnectionError_("the base URL has control characters or is too long")
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ConnectionError_("the base URL must be http(s)://host[/path]")
    if p.username or p.password:
        raise ConnectionError_("put credentials in the authentication fields, not in the URL")
    if p.query or p.fragment:
        raise ConnectionError_("the base URL cannot carry a query or a fragment")
    return urlunsplit((p.scheme, p.netloc, p.path.rstrip("/"), "", ""))


def create(slug: str, name: str, kind: str, by: str) -> StudioConnection:
    slug = (slug or "").strip()
    if not _SLUG_RE.match(slug):
        raise ConnectionError_("Id: lowercase letters, digits, - and _, 2 to 48 characters.")
    if get(slug) is not None:
        raise ConnectionError_("a connection with id %s already exists" % slug)
    if kind not in KINDS:
        raise ConnectionError_("unknown kind %r" % kind)
    name = (name or "").strip()[:120]
    if not name:
        raise ConnectionError_("a name is required")
    c = StudioConnection(slug=slug, name=name, kind=kind,
                         auth={"http": "none", "postgres": "password"}.get(kind, "key"),
                         port={"postgres": 5432, "server": 22}.get(kind),
                         username="satom-mon" if kind == "server" else "",
                         created_by=by, updated_by=by)
    db.session.add(c)
    db.session.commit()
    return c


def destination(c: StudioConnection) -> tuple:
    """Where the secret goes and how. The stored secret belongs to THIS
    tuple: change any part of it and the secret is dropped (``save``), so
    whoever may edit a connection cannot point it at a server of their own and
    press Test to receive the token, the password or the client secret
    (finding 2026-10-20). The path under the host is not part of it: the
    credential is the host's to begin with."""
    if c.kind == "http":
        p = urlsplit(c.base_url or "")
        return ("http", (p.scheme or "").lower(), (p.netloc or "").lower(), c.auth or "none",
                (c.header_name or "").lower(), c.token_url or "", c.username or "",
                bool(c.verify_tls))
    if c.kind == "server":
        return ("server", (c.host or "").lower(), int(c.port or 22), c.username or "")
    return ("postgres", (c.host or "").lower(), int(c.port or 5432), c.database or "",
            c.username or "", bool(c.verify_tls))


#: What clean_definition returns per kind, besides name/description/timeout/
#: verify_tls/username -- the columns save() writes.
_HTTP_KEYS = ("base_url", "auth", "header_name", "token_url", "scope")
_PG_KEYS = ("host", "port", "database", "auth")
_SERVER_KEYS = ("host", "port", "auth")


def clean_definition(form: dict) -> dict:
    """The form of a connection, checked and normalised -- no database, no
    secret. ``form["kind"]`` is ``http`` (default), ``postgres`` or ``server``. Raises
    ``ConnectionError_`` with what is wrong. ``save`` applies the result; the
    rules pack (``package_check``) checks the connections of an app package
    with it before anything is created."""
    kind = form.get("kind") or "http"
    if kind not in KINDS:
        raise ConnectionError_("unknown kind %r" % kind)
    out = {"kind": kind, "name": (form.get("name") or "").strip()[:120],
           "description": (form.get("description") or "").strip()[:2000]}
    try:
        out["timeout"] = max(1, min(int(form.get("timeout") or 20), MAX_TIMEOUT))
    except ValueError:
        raise ConnectionError_("timeout must be a number of seconds") from None
    out["verify_tls"] = bool(form.get("verify_tls", True)) and \
        str(form.get("verify_tls")) not in ("0", "false", "")
    user = out["username"] = (form.get("username") or "").strip()[:255]
    if kind == "http":
        out["base_url"] = _clean_base_url(form.get("base_url") or "")
        auth = form.get("auth") or "none"
        if auth not in HTTP_AUTH:
            raise ConnectionError_("unknown authentication %r" % auth)
        out["auth"] = auth
        hn = (form.get("header_name") or "").strip()
        if auth == "api_key" and not _HEADER_RE.match(hn):
            raise ConnectionError_("an API key needs a header name (letters, digits and -)")
        out["header_name"] = hn if auth == "api_key" else ""
        if auth == "oauth2":
            tu = (form.get("token_url") or "").strip()
            p = urlsplit(tu)
            if p.scheme != "https" or not p.hostname or p.username:
                # https only: the client secret travels in this request's body.
                raise ConnectionError_("OAuth2 needs a token URL https://host/path")
            out["token_url"] = tu[:500]
            out["scope"] = (form.get("scope") or "").strip()[:500]
            if not user:
                raise ConnectionError_("OAuth2 needs the client id (in the user field)")
        elif auth == "session":
            lp = (form.get("login_path") or form.get("token_url") or "").strip() \
                or "/api/auth/login"
            if not lp.startswith("/") or "://" in lp or _CTRL.search(lp) or ".." in lp:
                # Relative on purpose: the password only ever goes to the
                # host of the base URL.
                raise ConnectionError_("the login path is a path under the base URL, "
                                       "e.g. /api/auth/login")
            out["token_url"], out["scope"] = lp[:500], ""
            if not user:
                raise ConnectionError_("session login needs a user")
        else:
            out["token_url"], out["scope"] = "", ""
        if auth == "basic" and not user:
            raise ConnectionError_("basic authentication needs a user")
    elif kind == "server":
        host = (form.get("host") or "").strip()
        if not host or _CTRL.search(host) or "/" in host or " " in host or len(host) > 255:
            raise ConnectionError_("a host name or address is required")
        out["host"] = host
        try:
            out["port"] = int(form.get("port") or 22)
        except ValueError:
            raise ConnectionError_("port must be a number") from None
        if not 1 <= out["port"] <= 65535:
            raise ConnectionError_("port must be 1-65535")
        out["username"] = user or "satom-mon"
        if not _USER_RE.match(out["username"]):
            raise ConnectionError_("the user is a Linux account name (satom-mon by default)")
        out["auth"] = "key"
        out["allow_writes"] = str(form.get("allow_writes")).lower() in ("1", "true", "yes", "on")
    else:
        host = (form.get("host") or "").strip()
        if not host or _CTRL.search(host) or "/" in host or len(host) > 255:
            raise ConnectionError_("a host name or address is required")
        out["host"] = host
        try:
            out["port"] = int(form.get("port") or 5432)
        except ValueError:
            raise ConnectionError_("port must be a number") from None
        if not 1 <= out["port"] <= 65535:
            raise ConnectionError_("port must be 1-65535")
        out["database"] = (form.get("database") or "").strip()[:128]
        if not out["database"] or not user:
            raise ConnectionError_("a database and a user are required")
        out["auth"] = "password"
    return out


def save(c: StudioConnection, form: dict, by: str) -> bool:
    """Apply the form. True when the stored secret was dropped because the
    destination changed (the caller says so; the secret is entered again)."""
    before = destination(c) if (c.base_url or c.host) else None
    d = clean_definition({**form, "kind": c.kind})
    c.name = d["name"] or c.name
    c.description = d["description"]
    c.timeout, c.verify_tls, c.username = d["timeout"], d["verify_tls"], d["username"]
    for k in {"http": _HTTP_KEYS, "server": _SERVER_KEYS}.get(c.kind, _PG_KEYS):
        setattr(c, k, d[k])
    if c.kind == "http" and "api_version_id" in form:
        from . import studio_apis as SA
        try:
            v = SA.resolve_binding(form.get("api_version_id"))
        except SA.ApiError as exc:
            raise ConnectionError_(str(exc)) from None
        c.api_version_id = v.id if v else None
    c.updated_by = by
    _forget_token(c.slug)
    dropped = False
    if c.kind == "server":
        # SATOM's private key is not sent anywhere (SSH proves it with a
        # signature), so it stays; the trusted host key belongs to the old
        # destination and is forgotten -- the new one is trusted explicitly.
        opts = server_opts(c.slug)
        if before is not None and destination(c) != before:
            opts["host_key"] = ""
            dropped = bool(server_opts(c.slug).get("host_key"))
        opts["allow_writes"] = bool(d["allow_writes"])
        _set_server_opts(c.slug, opts)
    elif before is not None and destination(c) != before and has_secret(c.slug):
        set_secret(c.slug, "")
        dropped = True
    db.session.commit()
    if c.kind == "server":
        _hostguard_changed()
    return dropped


def delete(c: StudioConnection) -> None:
    set_secret(c.slug, "")
    was_server = c.kind == "server"
    if was_server:
        from .settings_store import set_str
        set_str(SERVER_OPTS_PREFIX + c.slug, "")
    db.session.delete(c)
    db.session.commit()
    if was_server:
        _hostguard_changed()


# --------------------------------------------------------------------------- #
#  server connections: options, SSH key, host key                              #
# --------------------------------------------------------------------------- #
def server_opts(slug: str) -> dict:
    """``{"host_key": str, "allow_writes": bool}``. A row that cannot be read
    counts as no trusted key and no writes -- a security decision never falls
    back to "allowed"."""
    from . import settings_store as ST
    raw = ST.get_json_checked(SERVER_OPTS_PREFIX + slug, {}, dict)
    if raw is ST.MALFORMED or not isinstance(raw, dict):
        raw = {}
    return {"host_key": str(raw.get("host_key") or ""),
            "allow_writes": raw.get("allow_writes") is True}


def _set_server_opts(slug: str, opts: dict) -> None:
    from . import settings_store as ST
    ST.set_json(SERVER_OPTS_PREFIX + slug, {"host_key": str(opts.get("host_key") or ""),
                                            "allow_writes": bool(opts.get("allow_writes"))})


def _server(c: StudioConnection) -> None:
    if c.kind != "server":
        raise ConnectionError_("%s is not a server connection" % c.slug)


def generate_server_key(c: StudioConnection) -> str:
    """A NEW key pair for this connection; the private key goes to the secret
    store (vault or Fernet), the public line is returned for the installer.
    The previous key stops working on every server that trusted it."""
    from . import studio_server as SV
    _server(c)
    pem, pub = SV.generate_key("satom-%s" % c.slug)
    set_secret(c.slug, pem)
    return pub


def server_public_key(c: StudioConnection) -> str:
    from . import studio_server as SV
    _server(c)
    secret, _problem = secret_state(c.slug)
    return SV.public_key(secret, "satom-%s" % c.slug)


def trust_host_key(c: StudioConnection) -> str:
    """Fetch the key the server presents NOW and pin it. Explicit, from the
    connection page: no call ever trusts a key by itself."""
    from . import studio_server as SV
    _server(c)
    if not c.host:
        raise ConnectionError_("save a host first")
    key = SV.clean_host_key(SV.fetch_host_key(c.host, int(c.port or 22),
                                              timeout=min(int(c.timeout or 20), 30)))
    opts = server_opts(c.slug)
    opts["host_key"] = key
    _set_server_opts(c.slug, opts)
    db.session.commit()
    return key


def forget_host_key(c: StudioConnection) -> None:
    _server(c)
    opts = server_opts(c.slug)
    opts["host_key"] = ""
    _set_server_opts(c.slug, opts)
    db.session.commit()


def server_call(c: StudioConnection, op: str, args: dict | None = None) -> dict:
    """One satom-webctl operation on a server connection: its ``result``."""
    from . import studio_server as SV
    _server(c)
    secret, problem = secret_state(c.slug)
    if not secret:
        raise ConnectionError_(problem or "connection %s has no SSH key: generate one" % c.slug)
    return SV.call(definition(c), secret, op, args or {}, timeout=c.timeout)


def _hostguard_changed() -> None:
    """The managed servers changed: tell hostguard (both nodes drop new
    connections FROM a managed server). Never blocks a save."""
    try:
        from flask import current_app, has_app_context
        if has_app_context() and current_app.config.get("TESTING") and \
                not current_app.config.get("HOSTGUARD_PUBLISH"):
            return          # a test that wants it says so; none writes data/ by accident
        from . import hostguard
        hostguard.publish()
    except Exception:  # noqa: BLE001 -- reported by hostguard's own health check
        pass


# --------------------------------------------------------------------------- #
#  the secret                                                                  #
# --------------------------------------------------------------------------- #
def has_secret(slug: str) -> bool:
    return PS.present(_key(slug))


def secret_state(slug: str) -> tuple[str, str]:
    """``(secret, problem)``; vault first, then the local copy
    (services/prefixed_secret.py)."""
    return PS.state(_key(slug), vault_path(slug), VAULT_FIELD)


def set_secret(slug: str, value: str) -> None:
    _forget_token(slug)
    try:
        PS.store(_key(slug), vault_path(slug), value, VAULT_FIELD)
    except PS.SecretStoreError as exc:
        raise ConnectionError_(str(exc)) from None


def _redactor(*secrets):
    return H.redactor(*secrets)


# --------------------------------------------------------------------------- #
#  HTTP and PostgreSQL — the wire part lives in services.studio_http, which    #
#  the database-free Script Library runner uses too (studio_broker).           #
# --------------------------------------------------------------------------- #
#: Test seam: an ``httpx.MockTransport`` in tests, ``None`` (the network) here.
#: With a transport nothing reaches the network, so the destination check
#: (studio_http.resolve) does not run either.
_transport = None

_TOKENS: dict[str, tuple[str, float]] = {}


def _forget_token(slug: str) -> None:
    with H._LOCK:
        _TOKENS.pop(slug, None)
        _TOKENS.pop(slug + "#session", None)


def _verify(c: StudioConnection):
    if not c.verify_tls:
        return False
    from . import trust_store
    return trust_store.verify_param()


def definition(c: StudioConnection) -> dict:
    """The connection as ``studio_http`` reads it — everything but the secret.
    ``catalog`` (the pinned API Catalog version's endpoints, or None) is what
    the script broker checks every request against."""
    from . import studio_apis as SA
    out = {"slug": c.slug, "kind": c.kind, "base_url": c.base_url, "host": c.host,
           "port": c.port, "database": c.database, "auth": c.auth,
           "username": c.username, "header_name": c.header_name,
           "token_url": c.token_url, "scope": c.scope,
           "verify_tls": bool(c.verify_tls), "timeout": c.timeout,
           "catalog": SA.catalog_of(c) if c.kind == "http" else None}
    if c.kind == "server":
        out.update(server_opts(c.slug))
    return out


def build_url(c: StudioConnection, path: str) -> str:
    """*path* joined under the base URL. Refuses anything that would leave it."""
    return H.build_url(c.base_url, path)


def http_call(c: StudioConnection, method: str = "GET", path: str = "", *,
              query: dict | None = None, body=None, headers: dict | None = None) -> dict:
    """One call. ``{status, ok, json|text, headers, ms, url}``. Raises
    ``ConnectionError_`` (secrets redacted) when no answer came back."""
    if c.kind != "http":
        raise ConnectionError_("%s is not an HTTP connection" % c.slug)
    secret, problem = secret_state(c.slug)
    if c.auth != "none" and not secret:
        raise ConnectionError_(problem or "no secret is stored for %s" % c.slug)
    return H.http_request(definition(c), secret, method, path, query=query, body=body,
                          headers=headers, verify=_verify(c), transport=_transport,
                          tokens=_TOKENS)


def pg_query(c: StudioConnection, sql: str, params: dict | None = None, *,
             write: bool = False, limit: int = 1000) -> dict:
    """``{columns, rows, rowcount, ms}``. READ ONLY unless *write*."""
    if c.kind != "postgres":
        raise ConnectionError_("%s is not a PostgreSQL connection" % c.slug)
    if not str(sql or "").strip():
        raise ConnectionError_("the SQL is empty")
    secret, problem = secret_state(c.slug)
    if not secret:
        raise ConnectionError_(problem or "no password is stored for %s" % c.slug)
    return H.pg_request(definition(c), secret, sql, params, write=write, limit=limit,
                        ca=_ca_path(c))


def _ca_path(c: StudioConnection) -> str:
    """The trust bundle FILE for a verified PostgreSQL connection ('' = the
    public roots, studio_http picks them)."""
    v = _verify(c)
    return v if isinstance(v, str) else ""


# --------------------------------------------------------------------------- #
#  JSON path                                                                   #
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(r"\[(\d+|\*)\]|\.?([^.\[\]]+)")


def json_path(obj, path: str):
    """``a.b[0].c``, ``items[*].name`` (``[*]`` maps over a list). ``""`` or
    ``$`` is the whole document. A missing key gives ``None``."""
    path = (path or "").strip()
    if path in ("", "$"):
        return obj
    if path.startswith("$."):
        path = path[2:]
    elif path.startswith("$"):
        path = path[1:]
    toks = [(m.group(1), m.group(2)) for m in _TOKEN_RE.finditer(path)]
    if not toks:
        raise ConnectionError_("bad JSON path %r" % path)

    def walk(cur, i):
        if i == len(toks):
            return cur
        idx, key = toks[i]
        if idx == "*":
            if not isinstance(cur, list):
                return None
            return [walk(x, i + 1) for x in cur]
        if idx is not None:
            n = int(idx)
            if isinstance(cur, list) and -len(cur) <= n < len(cur):
                return walk(cur[n], i + 1)
            return None
        if isinstance(cur, dict):
            return walk(cur.get(key), i + 1) if key in cur else None
        return None
    return walk(obj, 0)


def test(c: StudioConnection, method: str = "GET", path: str = "", sql: str = "",
         extract: str = "") -> dict:
    """What the Test button shows. Never raises."""
    try:
        if c.kind == "server":
            t0 = time.monotonic()
            info = server_call(c, "info")
            vh = server_call(c, "vhosts.list")["vhosts"]
            return {"ok": True, "status": "connected", "ms": int((time.monotonic() - t0) * 1000),
                    "body": {"satom_webctl": info, "vhosts": len(vh),
                             "names": [v["server"] + ":" + v["name"] for v in vh][:50]}}
        if c.kind == "http":
            r = http_call(c, method if method in ("GET", "HEAD") else "GET", path)
            body = r.get("json") if "json" in r else r.get("text", "")
            res = {"ok": r["ok"], "status": r["status"], "ms": r["ms"], "url": r["url"],
                   "body": body}
            if extract:
                res["extract"] = json_path(body, extract)
            return res
        r = pg_query(c, sql or "SELECT 1 AS ok", limit=20)
        return {"ok": True, "status": "connected", "ms": r["ms"], "body": r}
    except ConnectionError_ as exc:
        return {"ok": False, "error": str(exc)}


# --------------------------------------------------------------------------- #
#  for the Script Library runner (studio_broker)                               #
# --------------------------------------------------------------------------- #
def needs_secret(c: StudioConnection) -> bool:
    return c.kind in ("postgres", "server") or (c.auth or "none") != "none"


def for_runner(slugs: list[str]) -> tuple[dict, list[str]]:
    """``({slug: {"def", "wrapped"?, "vault"?}}, [missing slugs])`` for the
    connections a script declares.

    The secret NEVER goes into the queued request file: when a connection has
    one, the vault answers a wrapped read and the request carries only that
    single-use token (``script_vault``'s rule for script credentials), which
    the runner unwraps outside the jail. Without a vault holding the secret
    the run is refused, saying why. A connection without authentication needs
    no token."""
    from . import secret_backend as sb
    from . import script_vault as sv
    out, missing = {}, []
    for slug in slugs or []:
        c = get(slug)
        if c is None:
            missing.append(slug)
            continue
        entry: dict = {"def": definition(c)}
        if needs_secret(c):
            if not has_secret(slug):
                raise ConnectionError_("connection %s has no secret stored" % slug)
            if not sb.active():
                raise ConnectionError_(
                    "connection %s has a secret, and a script receives connection "
                    "secrets only from the vault (single-use wrapped tokens, never "
                    "written to disk): configure Settings > Vault" % slug)
            cfg = sb.config(reveal=False)
            try:
                token = sv._wrapped_read(cfg, sb._token(cfg), vault_path(slug))
            except Exception as exc:  # noqa: BLE001
                raise ConnectionError_("connection %s: the vault refused the wrapped "
                                       "read (%s)" % (slug, exc))
            if not token:
                raise ConnectionError_(
                    "connection %s: its secret is not in the vault (the vault mode "
                    "keeps it in SATOM only — run Settings > Vault > migrate)" % slug)
            entry["wrapped"] = token
            entry["vault"] = sv._vault_info(cfg)
        out[slug] = entry
    return out, missing


def used_by_scripts(slug: str) -> list[str]:
    """Script Library scripts whose draft or published version declares
    connection ``slug``."""
    from . import script_library as SL
    out = []
    for s in SL.list_scripts():
        meta = SL.get(s["slug"]) or {}
        if slug in (meta.get("connections") or []):
            out.append(s["slug"])
    return out
