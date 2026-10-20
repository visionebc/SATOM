"""Python Studio > Connections -- named external APIs and databases.

Two kinds:

* ``http`` -- a base URL plus an authentication. Every call stays under that
  base URL: a path is joined to it, an absolute URL in a path is refused, and
  redirects are NOT followed (a 3xx comes back as the answer). So an app step
  that says "call the CRM" cannot be steered to another host by a value a user
  typed into the form.
* ``postgres`` -- an external PostgreSQL database (a customer's CMDB, a
  reporting database). Queries are parameterised (``%(name)s``); a step reads
  in a READ ONLY transaction unless the administrator ticked "allow writes"
  on it.

The secret (password, token, API key, client secret) is never a column of
``studio_connections``: it is the ``app_settings`` row
``studio.connection.secret.<slug>`` (Fernet) or the vault path
``studio/connections/<slug>``, by the vault mode, like every other setting
secret -- and ``secret_backend`` migrates and scrubs it with them. It is
write-only from the UI and is redacted out of every error text.

Calls are made by SATOM itself (an app step, the Test button), never by a
Script Library script: a script gets the RESULT as an input, so script code
never holds the credential.
"""
from __future__ import annotations

import json
import re
import threading
import time
from urllib.parse import urlsplit, urlunsplit, quote

from ..extensions import db
from ..models import AppSetting
from ..models_studio import StudioConnection

KINDS = ("http", "postgres")
HTTP_AUTH = ("none", "basic", "bearer", "api_key", "oauth2")
PG_AUTH = ("password",)
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
SECRET_PREFIX = "studio.connection.secret."
VAULT_FIELD = "value"
MAX_BODY = 2 * 1024 * 1024
MAX_SQL_ROWS = 5000
MAX_TIMEOUT = 120

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,47}$")
_HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class ConnectionError_(ValueError):
    pass


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
                         auth="none" if kind == "http" else "password",
                         port=5432 if kind == "postgres" else None,
                         created_by=by, updated_by=by)
    db.session.add(c)
    db.session.commit()
    return c


def save(c: StudioConnection, form: dict, by: str) -> None:
    c.name = (form.get("name") or c.name).strip()[:120] or c.name
    c.description = (form.get("description") or "").strip()[:2000]
    try:
        c.timeout = max(1, min(int(form.get("timeout") or 20), MAX_TIMEOUT))
    except ValueError:
        raise ConnectionError_("timeout must be a number of seconds") from None
    c.verify_tls = bool(form.get("verify_tls", True)) and str(form.get("verify_tls")) not in ("0", "false", "")
    c.username = (form.get("username") or "").strip()[:255]
    if c.kind == "http":
        c.base_url = _clean_base_url(form.get("base_url") or "")
        auth = form.get("auth") or "none"
        if auth not in HTTP_AUTH:
            raise ConnectionError_("unknown authentication %r" % auth)
        c.auth = auth
        hn = (form.get("header_name") or "").strip()
        if auth == "api_key" and not _HEADER_RE.match(hn):
            raise ConnectionError_("an API key needs a header name (letters, digits and -)")
        c.header_name = hn if auth == "api_key" else ""
        if auth == "oauth2":
            tu = (form.get("token_url") or "").strip()
            p = urlsplit(tu)
            if p.scheme not in ("http", "https") or not p.hostname or p.username:
                raise ConnectionError_("OAuth2 needs a token URL http(s)://host/path")
            c.token_url = tu[:500]
            c.scope = (form.get("scope") or "").strip()[:500]
            if not c.username:
                raise ConnectionError_("OAuth2 needs the client id (in the user field)")
        else:
            c.token_url, c.scope = "", ""
        if auth == "basic" and not c.username:
            raise ConnectionError_("basic authentication needs a user")
    else:
        host = (form.get("host") or "").strip()
        if not host or _CTRL.search(host) or "/" in host or len(host) > 255:
            raise ConnectionError_("a host name or address is required")
        c.host = host
        try:
            c.port = int(form.get("port") or 5432)
        except ValueError:
            raise ConnectionError_("port must be a number") from None
        if not 1 <= c.port <= 65535:
            raise ConnectionError_("port must be 1-65535")
        c.database = (form.get("database") or "").strip()[:128]
        if not c.database or not c.username:
            raise ConnectionError_("a database and a user are required")
        c.auth = "password"
    c.updated_by = by
    _forget_token(c.slug)
    db.session.commit()


def delete(c: StudioConnection) -> None:
    set_secret(c.slug, "")
    db.session.delete(c)
    db.session.commit()


# --------------------------------------------------------------------------- #
#  the secret                                                                  #
# --------------------------------------------------------------------------- #
def has_secret(slug: str) -> bool:
    return bool((AppSetting.get(_key(slug)) or "").strip())


def secret_state(slug: str) -> tuple[str, str]:
    """``(secret, problem)``; vault first, then the local copy."""
    raw = (AppSetting.get(_key(slug)) or "").strip()
    if not raw:
        return "", ""
    from . import secret_backend as sb
    vault_err = ""
    try:
        vaulted = sb.get_field(vault_path(slug), VAULT_FIELD)
    except Exception as exc:  # noqa: BLE001
        vaulted, vault_err = "", str(exc) or exc.__class__.__name__
    if vaulted:
        return vaulted, ""
    try:
        from .encryption import decrypt
        local = decrypt(raw) or ""
    except Exception:  # noqa: BLE001
        return "", "the local copy of the secret could not be decrypted (FERNET_KEY changed?)"
    if local == sb.VAULT_SENTINEL:
        return "", ("the secret is stored in the vault, which could not be read: %s"
                    % (vault_err or "no value at %s" % vault_path(slug)))
    return local, ""


def set_secret(slug: str, value: str) -> None:
    from .encryption import encrypt
    from . import secret_backend as sb
    key, path = _key(slug), vault_path(slug)
    _forget_token(slug)
    if not value:
        AppSetting.set(key, "")
        try:
            if sb.active():
                sb.delete(path)
        except Exception:  # noqa: BLE001
            pass
        return
    if len(value) > 8192:
        raise ConnectionError_("the secret is longer than 8192 characters")
    stored = False
    try:
        stored = sb.put_field(path, VAULT_FIELD, value)
    except Exception:  # noqa: BLE001
        if sb.authoritative():
            raise ConnectionError_("the vault is the only secret store and refused the "
                                   "write; the secret was not saved")
    if stored and sb.authoritative():
        AppSetting.set(key, encrypt(sb.VAULT_SENTINEL))
    else:
        AppSetting.set(key, encrypt(value))


def _redactor(*secrets):
    vals = sorted({s for s in secrets if s and len(s) >= 3}, key=len, reverse=True)

    def red(text) -> str:
        t = str(text)
        for v in vals:
            t = t.replace(v, "********")
        return t
    return red


# --------------------------------------------------------------------------- #
#  HTTP                                                                        #
# --------------------------------------------------------------------------- #
#: Test seam: an ``httpx.MockTransport`` in tests, ``None`` (the network) here.
_transport = None

_TOKENS: dict[str, tuple[str, float]] = {}
_TOK_LOCK = threading.Lock()


def _forget_token(slug: str) -> None:
    with _TOK_LOCK:
        _TOKENS.pop(slug, None)


def _verify(c: StudioConnection):
    if not c.verify_tls:
        return False
    from . import trust_store
    return trust_store.verify_param()


def build_url(c: StudioConnection, path: str) -> str:
    """*path* joined under the base URL. Refuses anything that would leave it."""
    path = str(path or "")
    if _CTRL.search(path):
        raise ConnectionError_("the path has control characters")
    if "://" in path or path.startswith("//") or "\\" in path:
        raise ConnectionError_("a path is relative to the connection's base URL; "
                               "an absolute URL is refused")
    base = urlsplit(c.base_url)
    rel, _, qs = path.partition("?")
    segs = [s for s in rel.split("/") if s not in ("", ".")]
    if ".." in segs:
        raise ConnectionError_("a path cannot climb above the base URL (..)")
    full = base.path.rstrip("/") + ("/" + "/".join(quote(s, safe="@:+,;=%-._~!$&'()*")
                                                   for s in segs) if segs else "")
    return urlunsplit((base.scheme, base.netloc, full or "/", qs, ""))


def _oauth_token(c: StudioConnection, secret: str, client) -> str:
    with _TOK_LOCK:
        cached = _TOKENS.get(c.slug)
        if cached and cached[1] > time.time():
            return cached[0]
    data = {"grant_type": "client_credentials", "client_id": c.username,
            "client_secret": secret}
    if c.scope:
        data["scope"] = c.scope
    r = client.post(c.token_url, data=data, follow_redirects=False)
    if r.status_code >= 400:
        raise ConnectionError_("the token endpoint answered HTTP %d" % r.status_code)
    try:
        j = r.json()
        tok = str(j["access_token"])
        ttl = float(j.get("expires_in") or 300)
    except (ValueError, KeyError, TypeError):
        raise ConnectionError_("the token endpoint did not return an access_token") from None
    with _TOK_LOCK:
        _TOKENS[c.slug] = (tok, time.time() + max(30.0, ttl - 30.0))
    return tok


def _headers(c: StudioConnection, secret: str, client) -> dict:
    h = {"Accept": "application/json", "User-Agent": "SATOM-Studio"}
    if c.auth == "basic":
        import base64
        h["Authorization"] = "Basic " + base64.b64encode(
            ("%s:%s" % (c.username, secret)).encode()).decode()
    elif c.auth == "bearer":
        h["Authorization"] = "Bearer " + secret
    elif c.auth == "api_key":
        h[c.header_name] = secret
    elif c.auth == "oauth2":
        h["Authorization"] = "Bearer " + _oauth_token(c, secret, client)
    return h


def http_call(c: StudioConnection, method: str = "GET", path: str = "", *,
              query: dict | None = None, body=None, headers: dict | None = None) -> dict:
    """One call. ``{status, ok, json|text, headers, ms, url}``. Raises
    ``ConnectionError_`` (secrets redacted) when no answer came back."""
    import httpx
    if c.kind != "http":
        raise ConnectionError_("%s is not an HTTP connection" % c.slug)
    method = (method or "GET").upper()
    if method not in METHODS:
        raise ConnectionError_("unknown method %r" % method)
    secret, problem = secret_state(c.slug)
    if c.auth != "none" and not secret:
        raise ConnectionError_(problem or "no secret is stored for %s" % c.slug)
    red = _redactor(secret)
    url = build_url(c, path)
    extra = {}
    for k, v in (headers or {}).items():
        k = str(k)
        if not _HEADER_RE.match(k) or k.lower() in ("authorization", "host", "cookie") \
                or (c.header_name and k.lower() == c.header_name.lower()):
            raise ConnectionError_("header %r cannot be set by a step" % k)
        extra[k] = str(v)
    t0 = time.monotonic()
    try:
        with httpx.Client(timeout=c.timeout, verify=_verify(c), follow_redirects=False,
                          transport=_transport) as cl:
            h = _headers(c, secret, cl)
            h.update(extra)
            kw = {"params": {str(k): str(v) for k, v in (query or {}).items()} or None,
                  "headers": h}
            if body is not None and method != "GET":
                if isinstance(body, (dict, list)):
                    kw["json"] = body
                else:
                    kw["content"] = str(body).encode()
            with cl.stream(method, url, **kw) as r:
                chunks, size = [], 0
                for chunk in r.iter_bytes():
                    size += len(chunk)
                    if size > MAX_BODY:
                        raise ConnectionError_("the answer is larger than %d MiB"
                                               % (MAX_BODY // 1024 // 1024))
                    chunks.append(chunk)
                raw = b"".join(chunks)
                status, ctype = r.status_code, r.headers.get("content-type", "")
                loc = r.headers.get("location", "")
    except ConnectionError_:
        raise
    except Exception as exc:  # noqa: BLE001 -- transport
        raise ConnectionError_(red("%s: %s" % (exc.__class__.__name__, exc))) from None
    ms = int((time.monotonic() - t0) * 1000)
    text = raw.decode("utf-8", "replace")
    out = {"status": status, "ok": 200 <= status < 300, "ms": ms, "url": url,
           "content_type": ctype}
    if loc:
        out["location"] = loc
    try:
        out["json"] = json.loads(text) if text.strip() else None
    except ValueError:
        out["text"] = red(text[:200_000])
    return out


# --------------------------------------------------------------------------- #
#  PostgreSQL                                                                  #
# --------------------------------------------------------------------------- #
def pg_query(c: StudioConnection, sql: str, params: dict | None = None, *,
             write: bool = False, limit: int = 1000) -> dict:
    """``{columns, rows, rowcount, ms}``. READ ONLY unless *write*."""
    import psycopg
    if c.kind != "postgres":
        raise ConnectionError_("%s is not a PostgreSQL connection" % c.slug)
    sql = str(sql or "").strip()
    if not sql:
        raise ConnectionError_("the SQL is empty")
    secret, problem = secret_state(c.slug)
    if not secret:
        raise ConnectionError_(problem or "no password is stored for %s" % c.slug)
    red = _redactor(secret)
    limit = max(1, min(int(limit or 1000), MAX_SQL_ROWS))
    t0 = time.monotonic()
    try:
        with psycopg.connect(host=c.host, port=c.port or 5432, dbname=c.database,
                             user=c.username, password=secret,
                             connect_timeout=min(c.timeout, 30),
                             sslmode="prefer",
                             options="-c statement_timeout=%d" % (c.timeout * 1000),
                             application_name="satom-studio") as conn:
            conn.read_only = not write
            with conn.cursor() as cur:
                cur.execute(sql, params or None)
                cols = [d.name for d in cur.description] if cur.description else []
                rows = []
                if cols:
                    for rec in cur.fetchmany(limit):
                        rows.append({k: (v if isinstance(v, (int, float, str, bool, type(None)))
                                         else str(v)) for k, v in zip(cols, rec)})
                rowcount = cur.rowcount
            if write:
                conn.commit()
    except Exception as exc:  # noqa: BLE001
        raise ConnectionError_(red("%s: %s" % (exc.__class__.__name__, exc))) from None
    return {"columns": cols, "rows": rows, "rowcount": rowcount,
            "truncated": len(rows) >= limit, "ms": int((time.monotonic() - t0) * 1000)}


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
