"""The request core of a Studio connection — DATABASE-FREE.

``studio_connections`` owns connections (rows, secrets, the vault) and calls
this module for the wire part; the Script Library runner (``script_runner``,
no database by design) calls it too, through ``studio_broker``, so a script
reaches a connection with exactly the same rules as an app step:

* every call stays under the base URL (``build_url``); redirects come back as
  the answer, never followed; a step cannot set the credential header;
* the secret goes where the authentication says and is redacted out of every
  error text;
* **the address that is dialled is checked first** (2026-10-20): the host is
  resolved once, every address must pass :func:`denial` — no loopback (this
  node's VictoriaMetrics, Redis and gunicorn listen there without
  authentication), no link-local (cloud metadata), no multicast, unspecified
  or reserved address, and no address of THIS node, on any interface — and the
  request goes to that checked IP with the original name as ``Host`` and TLS
  server name, so a DNS answer that changes between the check and the connect
  changes nothing. The same holds for the OAuth2 token URL and for a
  PostgreSQL host (``hostaddr``). Internal (RFC 1918) APIs stay reachable: a
  customer's CMDB is the point of a connection.

``transport`` is the test seam (an ``httpx.MockTransport``): with one, nothing
reaches the network, so neither resolution nor the address check runs.

A connection definition is a plain dict (``studio_connections.definition``):
slug, kind, base_url, host, port, database, auth, username, header_name,
token_url, scope, verify_tls, timeout.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import threading
import time
from urllib.parse import quote, urlsplit, urlunsplit

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
MAX_BODY = 2 * 1024 * 1024
MAX_SQL_ROWS = 5000
HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class ConnectionError_(ValueError):
    """A call refused or failed; the message is safe to show."""


# --------------------------------------------------------------------------- #
#  where SATOM may connect                                                     #
# --------------------------------------------------------------------------- #
def _is_this_node(ip: str) -> bool:
    """True when ``ip`` is an address of this host: binding to it succeeds
    only for an address of one of our own interfaces."""
    s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((ip, 0))
        return True
    except OSError:
        return False
    finally:
        s.close()


def denial(ip: str) -> str:
    """Why a connection never dials ``ip``, or ''."""
    try:
        addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return "not an IP address"
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    if addr.is_loopback:
        return "a loopback address of this node"
    if addr.is_link_local:
        return "a link-local address (cloud metadata services live there)"
    if addr.is_multicast:
        return "a multicast address"
    if addr.is_unspecified:
        return "an unspecified address"
    if addr.is_reserved:
        return "a reserved address"
    if _is_this_node(str(addr)):
        return "an address of this node"
    return ""


def resolve(host: str, port: int) -> str:
    """The one checked IP to dial for ``host``. EVERY resolved address must
    pass: a name answering with one good and one forbidden address is refused,
    because the next answer may be the forbidden one."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as exc:
        raise ConnectionError_("%s does not resolve from this node (%s)"
                               % (host, getattr(exc, "strerror", "") or exc)) from None
    ips: list[str] = []
    for info in infos:
        if str(info[4][0]) not in ips:
            ips.append(str(info[4][0]))
    if not ips:
        raise ConnectionError_("%s does not resolve from this node" % host)
    for ip in ips:
        why = denial(ip)
        if why:
            raise ConnectionError_("%s resolves to %s, %s; a connection never dials it"
                                   % (host, ip, why))
    return ips[0]


def _pinned(url: str) -> tuple[str, dict, dict]:
    """(url with the checked IP, Host header, httpx extensions)."""
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    port = p.port or (443 if p.scheme == "https" else 80)
    ip = resolve(host, port)
    netloc = ("[%s]" % ip if ":" in ip else ip) + (":%d" % p.port if p.port else "")
    hosthdr = ("[%s]" % host if ":" in host else host) + (":%d" % p.port if p.port else "")
    ext = {"sni_hostname": host} if p.scheme == "https" else {}
    return urlunsplit((p.scheme, netloc, p.path or "/", p.query, "")), {"Host": hosthdr}, ext


# --------------------------------------------------------------------------- #
#  URLs and secrets                                                            #
# --------------------------------------------------------------------------- #
def redactor(*secrets):
    vals = sorted({s for s in secrets if s and len(s) >= 3}, key=len, reverse=True)

    def red(text) -> str:
        t = str(text)
        for v in vals:
            t = t.replace(v, "********")
        return t
    return red


def build_url(base_url: str, path: str) -> str:
    """*path* joined under *base_url*. Refuses anything that would leave it."""
    path = str(path or "")
    if _CTRL.search(path):
        raise ConnectionError_("the path has control characters")
    if "://" in path or path.startswith("//") or "\\" in path:
        raise ConnectionError_("a path is relative to the connection's base URL; "
                               "an absolute URL is refused")
    base = urlsplit(base_url)
    rel, _, qs = path.partition("?")
    segs = [s for s in rel.split("/") if s not in ("", ".")]
    if ".." in segs:
        raise ConnectionError_("a path cannot climb above the base URL (..)")
    full = base.path.rstrip("/") + ("/" + "/".join(quote(s, safe="@:+,;=%-._~!$&'()*")
                                                   for s in segs) if segs else "")
    return urlunsplit((base.scheme, base.netloc, full or "/", qs, ""))


_LOCK = threading.Lock()


def _oauth_token(d: dict, secret: str, client, tokens: dict, guarded: bool) -> str:
    slug = d.get("slug") or ""
    with _LOCK:
        cached = tokens.get(slug)
        if cached and cached[1] > time.time():
            return cached[0]
    data = {"grant_type": "client_credentials", "client_id": d.get("username") or "",
            "client_secret": secret}
    if d.get("scope"):
        data["scope"] = d["scope"]
    url, headers, ext = d.get("token_url") or "", {}, {}
    if guarded:
        url, headers, ext = _pinned(url)
    r = client.post(url, data=data, headers=headers, extensions=ext, follow_redirects=False)
    if r.status_code >= 400:
        raise ConnectionError_("the token endpoint answered HTTP %d" % r.status_code)
    try:
        j = r.json()
        tok = str(j["access_token"])
        ttl = float(j.get("expires_in") or 300)
    except (ValueError, KeyError, TypeError):
        raise ConnectionError_("the token endpoint did not return an access_token") from None
    with _LOCK:
        tokens[slug] = (tok, time.time() + max(30.0, ttl - 30.0))
    return tok


def _auth_headers(d: dict, secret: str, client, tokens: dict, guarded: bool) -> dict:
    h = {"Accept": "application/json", "User-Agent": "SATOM-Studio"}
    auth = d.get("auth") or "none"
    if auth == "basic":
        import base64
        h["Authorization"] = "Basic " + base64.b64encode(
            ("%s:%s" % (d.get("username") or "", secret)).encode()).decode()
    elif auth == "bearer":
        h["Authorization"] = "Bearer " + secret
    elif auth == "api_key":
        h[d.get("header_name") or "X-API-Key"] = secret
    elif auth == "oauth2":
        h["Authorization"] = "Bearer " + _oauth_token(d, secret, client, tokens, guarded)
    return h


# --------------------------------------------------------------------------- #
#  HTTP                                                                        #
# --------------------------------------------------------------------------- #
def http_request(d: dict, secret: str, method: str = "GET", path: str = "", *,
                 query: dict | None = None, body=None, headers: dict | None = None,
                 verify=True, transport=None, tokens: dict | None = None) -> dict:
    """One call. ``{status, ok, json|text, headers?, ms, url}``. Raises
    ``ConnectionError_`` (secrets redacted) when no answer came back."""
    import httpx
    if d.get("kind") != "http":
        raise ConnectionError_("%s is not an HTTP connection" % d.get("slug"))
    method = (method or "GET").upper()
    if method not in METHODS:
        raise ConnectionError_("unknown method %r" % method)
    auth = d.get("auth") or "none"
    if auth != "none" and not secret:
        raise ConnectionError_("no secret is stored for %s" % d.get("slug"))
    red = redactor(secret)
    url = build_url(d.get("base_url") or "", path)
    hn = (d.get("header_name") or "").lower()
    extra = {}
    for k, v in (headers or {}).items():
        k = str(k)
        if not HEADER_RE.match(k) or k.lower() in ("authorization", "host", "cookie") \
                or (hn and k.lower() == hn):
            raise ConnectionError_("header %r cannot be set by a step" % k)
        extra[k] = str(v)
    guarded = transport is None
    tokens = tokens if tokens is not None else {}
    timeout = max(1, min(int(d.get("timeout") or 20), 120))
    t0 = time.monotonic()
    try:
        with httpx.Client(timeout=timeout, verify=verify, follow_redirects=False,
                          transport=transport, trust_env=False) as cl:
            h = _auth_headers(d, secret, cl, tokens, guarded)
            h.update(extra)
            target, ext = url, {}
            if guarded:
                target, host_hdr, ext = _pinned(url)
                h.update(host_hdr)
            kw = {"params": {str(k): str(v) for k, v in (query or {}).items()} or None,
                  "headers": h, "extensions": ext}
            if body is not None and method != "GET":
                if isinstance(body, (dict, list)):
                    kw["json"] = body
                else:
                    kw["content"] = str(body).encode()
            with cl.stream(method, target, **kw) as r:
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
    except ConnectionError_ as exc:
        raise ConnectionError_(red(str(exc))) from None
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
def _pg_connect(**kw):     # the seam tests replace
    import psycopg
    return psycopg.connect(**kw)


def pg_sslmode(d: dict, ca: str = "") -> dict:
    """libpq TLS settings. Never ``prefer`` or ``disable``: those send the
    password in clear to a server without TLS. TLS verification on →
    ``verify-full`` against the node's trust bundle (Settings › Trust store;
    the public roots when it has no private CA); off → ``require`` (encrypted,
    certificate not checked)."""
    if not d.get("verify_tls", True):
        return {"sslmode": "require"}
    if not ca:
        import certifi
        ca = certifi.where()
    return {"sslmode": "verify-full", "sslrootcert": ca}


def pg_request(d: dict, secret: str, sql: str, params=None, *, write: bool = False,
               limit: int = 1000, guarded: bool = True, ca: str = "") -> dict:
    """``{columns, rows, rowcount, truncated, ms}``. READ ONLY unless *write*."""
    if d.get("kind") != "postgres":
        raise ConnectionError_("%s is not a PostgreSQL connection" % d.get("slug"))
    sql = str(sql or "").strip()
    if not sql:
        raise ConnectionError_("the SQL is empty")
    if not secret:
        raise ConnectionError_("no password is stored for %s" % d.get("slug"))
    red = redactor(secret)
    limit = max(1, min(int(limit or 1000), MAX_SQL_ROWS))
    timeout = max(1, min(int(d.get("timeout") or 20), 120))
    host, port = d.get("host") or "", int(d.get("port") or 5432)
    kw = {"host": host, "port": port, "dbname": d.get("database") or "",
          "user": d.get("username") or "", "password": secret,
          "connect_timeout": min(timeout, 30),
          "options": "-c statement_timeout=%d" % (timeout * 1000),
          "application_name": "satom-studio", **pg_sslmode(d, ca)}
    t0 = time.monotonic()
    try:
        if guarded:
            kw["hostaddr"] = resolve(host, port)
        with _pg_connect(**kw) as conn:
            conn.read_only = not write
            with conn.cursor() as cur:
                cur.execute(sql, params or None)
                cols = [c.name for c in cur.description] if cur.description else []
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
