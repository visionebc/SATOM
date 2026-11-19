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
import os
import re
import socket
import threading
import time
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
MAX_BODY = 2 * 1024 * 1024
#: The most one call may raise its limit to (``max_body``): a Script Library
#: script's call with ``max_mb`` -- the answer is held in memory.
MAX_BODY_LARGE = 64 * 1024 * 1024
MAX_SQL_ROWS = 5000
#: A query result stops here, whatever its row count: one wide column
#: (``repeat('x', 1e8)``) must not fill the web worker's memory.
MAX_SQL_BYTES = 8 * 1024 * 1024
#: The whole HTTP call ends within timeout × 2 + DEADLINE_EXTRA seconds.
DEADLINE_EXTRA = 5
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


#: The SATOM HA registry: a connection never dials the other node of the
#: pair (its Postgres replica, its nginx, its loopback-only services exposed
#: by nothing but trust in the peer).
HA_NODES_FILE = Path(os.environ.get("FM_APP_DIR") or Path(__file__).resolve().parents[2]) \
    / "data" / "ha_nodes.json"
_HA_CACHE: dict = {"at": 0.0, "ips": frozenset()}
_HA_TTL = 60.0


def ha_node_ips() -> frozenset:
    """Every address the HA nodes in ``data/ha_nodes.json`` resolve to,
    cached for a minute. Empty when the registry is absent (a single node)."""
    now = time.monotonic()
    if now - _HA_CACHE["at"] < _HA_TTL and _HA_CACHE["at"]:
        return _HA_CACHE["ips"]
    ips: set[str] = set()
    try:
        nodes = json.loads(HA_NODES_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        nodes = []
    for n in nodes if isinstance(nodes, list) else []:
        host = str((n or {}).get("host") or "").strip() if isinstance(n, dict) else ""
        if not host:
            continue
        try:
            for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
                ips.add(_plain_ip(str(info[4][0])))
        except (OSError, UnicodeError, ValueError):
            continue
    _HA_CACHE.update(at=now, ips=frozenset(ips))
    return _HA_CACHE["ips"]


def _plain_ip(ip: str) -> str:
    addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
    mapped = getattr(addr, "ipv4_mapped", None)
    return str(mapped or addr)


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
    if str(addr) in ha_node_ips():
        return "an address of a SATOM HA node (data/ha_nodes.json)"
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
    """A function that blanks every secret out of a text -- also in its
    JSON-escaped spelling, because an API that echoes the request (a debug
    endpoint, a hostile server) returns it inside a JSON string."""
    base = {s for s in secrets if s and len(s) >= 3}
    for s in list(base):
        esc = json.dumps(s)[1:-1]
        if esc != s:
            base.add(esc)
    vals = sorted(base, key=len, reverse=True)

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
    qs = qs.split("#", 1)[0]
    segs = [s for s in rel.split("/") if s not in ("", ".")]
    if ".." in segs:
        raise ConnectionError_("a path cannot climb above the base URL (..)")
    if any(_ENCODED_ESCAPE.search(s) for s in segs):
        # %2e%2e/ and %2f are ".." and "/" to most servers: the same climb,
        # spelt so that the check above does not see it.
        raise ConnectionError_("a path cannot carry an encoded . / or \\ (%2e %2f %5c)")
    full = base.path.rstrip("/") + ("/" + "/".join(quote(s, safe="@:+,;=%-._~!$&'()*")
                                                   for s in segs) if segs else "")
    if qs:
        # Re-encoded pair by pair: the query that leaves is exactly the
        # pairs that were written, with no raw space, quote or fragment.
        qs = urlencode(parse_qsl(qs, keep_blank_values=True))
    return urlunsplit((base.scheme, base.netloc, full or "/", qs, ""))


_ENCODED_ESCAPE = re.compile(r"%(2e|2f|5c)", re.I)


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


#: Default login path of a ``session`` connection (the DDI API's).
SESSION_LOGIN_PATH = "/api/auth/login"
#: How long a session cookie is reused before logging in again.
SESSION_TTL_S = 240.0
#: Where a login answer may carry its token, in this order (FA-0016: the
#: customer's inventory API script looks in the same keys), at the top level
#: or under one of LOGIN_WRAPPERS.
LOGIN_TOKEN_KEYS = ("access_token", "token", "accessToken", "jwt", "id_token")
LOGIN_WRAPPERS = ("data", "result", "response")
#: A plain-text login answer is a token only when it looks like one: one
#: word, no markup (an HTML error page is not a credential).
_PLAIN_TOKEN = re.compile(r"^[A-Za-z0-9._~+/=-]{8,4096}$")


def login_token(payload, _depth: int = 0) -> str:
    """The token in a login answer, or ``""``. *payload* is the parsed JSON
    (or the raw text when the answer was not JSON)."""
    if isinstance(payload, str):
        s = payload.strip()
        return s if _PLAIN_TOKEN.match(s) else ""
    if not isinstance(payload, dict) or _depth > 2:
        return ""
    for key in LOGIN_TOKEN_KEYS:
        v = payload.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for key in LOGIN_WRAPPERS:
        v = payload.get(key)
        if isinstance(v, dict):
            tok = login_token(v, _depth + 1)
            if tok:
                return tok
    return ""


#: A form login answered with one of these may be a server that reads only
#: JSON (FastAPI 422, others 400/415, some 401/403 for "no credentials"):
#: the same credentials are sent once more as JSON.
_FORM_REFUSED = (400, 401, 403, 415, 422)


def _session_cookie(d: dict, secret: str, client, tokens: dict, guarded: bool,
                    fresh: bool = False) -> dict:
    """Log in with user + password: ``{"cookie": <Cookie header>, "bearer":
    <token>}`` -- either may be empty, never both.

    The login path is UNDER the base URL (``build_url``), so the password
    goes to the same host as every other call. The body is a form first (the
    FastAPI ``OAuth2PasswordRequestForm`` shape), then JSON when the server
    refuses the form (``_FORM_REFUSED``) -- the DDI API's Swagger does not
    expand its login body, Policy Clone measured that both shapes exist in
    the field, and a JSON-only token API (FA-0016) may answer 400 or 401 to a
    form. The shape that worked is remembered (``<slug>#login``), so a wrong
    password costs one failed attempt per login, not two.

    The token is found by :func:`login_token` (``access_token``, ``token``,
    ``jwt`` ... at the top or under ``data``/``result``/``response``). When
    the answer has BOTH cookies and a token, both are sent: an API behind a
    load balancer sets a persistence cookie and still wants its bearer."""
    slug = d.get("slug") or ""
    key, shape_key = slug + "#session", slug + "#login"
    if not fresh:
        with _LOCK:
            cached = tokens.get(key)
            if cached and cached[1] > time.time():
                return cached[0]
    url = build_url(d.get("base_url") or "", d.get("token_url") or SESSION_LOGIN_PATH)
    headers, ext = {"Accept": "application/json", "User-Agent": "SATOM-Studio"}, {}
    target = url
    if guarded:
        target, host_hdr, ext = _pinned(url)
        headers.update(host_hdr)
    creds = {"username": d.get("username") or "", "password": secret}
    with _LOCK:
        known = (tokens.get(shape_key) or ("", 0))[0]
    shapes = [known] if known in ("form", "json") else ["form", "json"]
    r, used = None, ""
    for shape in shapes:
        kw = {"data": creds} if shape == "form" else {"json": creds}
        r = client.post(target, headers=headers, extensions=ext, follow_redirects=False, **kw)
        used = shape
        if r.status_code not in _FORM_REFUSED or shape != "form":
            break
    if r.status_code >= 400:
        raise ConnectionError_("the login endpoint answered HTTP %d" % r.status_code)
    pairs = ["%s=%s" % (c.name, c.value) for c in r.cookies.jar]
    try:
        payload = r.json()
    except ValueError:
        payload = r.text
    tok = login_token(payload)
    if not pairs and not tok:
        raise ConnectionError_("the login endpoint returned no session cookie or token")
    value = {"cookie": "; ".join(pairs), "bearer": tok}
    with _LOCK:
        tokens[key] = (value, time.time() + SESSION_TTL_S)
        tokens[shape_key] = (used, float("inf"))
    return value


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
    elif auth == "session":
        value = _session_cookie(d, secret, client, tokens, guarded)
        if value.get("cookie"):
            h["Cookie"] = value["cookie"]
        if value.get("bearer"):
            h["Authorization"] = "Bearer " + value["bearer"]
    return h


# --------------------------------------------------------------------------- #
#  HTTP                                                                        #
# --------------------------------------------------------------------------- #
def _credential_values(d: dict, secret: str, headers: dict) -> list[str]:
    """Every spelling of the credential that could come back in an answer:
    the secret, the Basic header value (base64 of user:secret), the OAuth2
    access token, the API key header."""
    vals = [secret]
    hn = (d.get("header_name") or "").lower()
    for k, v in headers.items():
        if k.lower() == "authorization" or (hn and k.lower() == hn):
            vals.append(str(v))
            vals.append(str(v).split(" ", 1)[-1])
        if k.lower() == "cookie":
            # A session cookie IS the credential while it lives.
            vals.append(str(v))
            vals.extend(p.split("=", 1)[-1] for p in str(v).split("; ") if "=" in p)
    return vals


def http_request(d: dict, secret: str, method: str = "GET", path: str = "", *,
                 query: dict | None = None, body=None, headers: dict | None = None,
                 verify=True, transport=None, tokens: dict | None = None,
                 max_body: int | None = None, deadline: float | None = None,
                 _relogged: bool = False) -> dict:
    """One call. ``{status, ok, json|text, headers?, ms, url}``. Raises
    ``ConnectionError_`` (secrets redacted) when no answer came back.

    The whole call has ONE deadline (``timeout`` × 2 + DEADLINE_EXTRA s): httpx's timeout
    is per read, so a server that trickles a byte at a time would otherwise
    hold the caller -- a web worker -- for as long as it likes.

    *max_body* raises the answer's size limit for ONE call (default
    :data:`MAX_BODY`, at most :data:`MAX_BODY_LARGE`): a Script Library
    script's connection call asks for it with ``max_mb`` (studio_broker);
    nothing else does.

    *deadline* replaces that total, in seconds, for ONE call that does not
    hold a web worker -- a Script Library script's call through the broker
    passes what is left of the script's own time limit, so a big answer that
    keeps arriving is read to the end the way ``requests(timeout=60)`` reads
    it: the connection's timeout is the wait for the next piece, not for the
    whole answer."""
    import httpx
    if d.get("kind") != "http":
        raise ConnectionError_("%s is not an HTTP connection" % d.get("slug"))
    method = (method or "GET").upper()
    if method not in METHODS:
        raise ConnectionError_("unknown method %r" % method)
    auth = d.get("auth") or "none"
    if auth != "none" and not secret:
        raise ConnectionError_("no secret is stored for %s" % d.get("slug"))
    url = build_url(d.get("base_url") or "", path)
    hn = (d.get("header_name") or "").lower()
    extra = {}
    for k, v in (headers or {}).items():
        k = str(k)
        if not HEADER_RE.match(k) or k.lower() in ("authorization", "host", "cookie") \
                or (hn and k.lower() == hn):
            raise ConnectionError_("header %r cannot be set by a step" % k)
        v = str(v)
        if _CTRL.search(v):
            raise ConnectionError_("header %r has control characters" % k)
        extra[k] = v
    guarded = transport is None
    tokens = tokens if tokens is not None else {}
    limit = max(1, min(int(max_body or MAX_BODY), MAX_BODY_LARGE))
    timeout = max(1, min(int(d.get("timeout") or 20), 120))
    deadline_s = timeout * 2 + DEADLINE_EXTRA
    if deadline is not None:
        deadline_s = max(1, int(deadline))
    state: dict = {"red": redactor(secret), "phase": "login", "bytes": 0, "total": 0}

    def call():
        t0 = time.monotonic()
        with httpx.Client(timeout=timeout, verify=verify, follow_redirects=False,
                          transport=transport, trust_env=False) as cl:
            had = set(tokens)
            h = _auth_headers(d, secret, cl, tokens, guarded)
            state["signed_in"] = set(tokens) != had
            state["login_ms"] = int((time.monotonic() - t0) * 1000)
            state["phase"] = "waiting"
            state["red"] = redactor(*_credential_values(d, secret, h))
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
                state["first_byte_ms"] = int((time.monotonic() - t0) * 1000)
                try:
                    state["total"] = int(r.headers.get("content-length") or 0)
                except ValueError:
                    state["total"] = 0
                state["phase"] = "download"
                chunks, size = [], 0
                for chunk in r.iter_bytes():
                    size += len(chunk)
                    state["bytes"] = size
                    if size > limit:
                        raise ConnectionError_("the answer is larger than %d MiB"
                                               % (limit // 1024 // 1024))
                    if time.monotonic() - t0 > deadline_s:
                        raise ConnectionError_("no complete answer within %d s" % deadline_s)
                    chunks.append(chunk)
                state["download_ms"] = int((time.monotonic() - t0) * 1000) - state["first_byte_ms"]
                state["res"] = (b"".join(chunks), r.status_code,
                                r.headers.get("content-type", ""), r.headers.get("location", ""))

    def runner():
        try:
            call()
        except BaseException as exc:  # noqa: BLE001 -- handed to the caller
            state["exc"] = exc

    t0 = time.monotonic()
    th = threading.Thread(target=runner, daemon=True, name="studio-http")
    th.start()
    end = t0 + deadline_s + 1
    while th.is_alive() and time.monotonic() < end:
        th.join(max(0.0, min(1.0, end - time.monotonic())))
    red = state["red"]
    if th.is_alive():
        # The thread is abandoned; its socket dies with its own read timeout.
        raise ConnectionError_("no complete answer within %d s" % deadline_s)
    exc = state.get("exc")
    if isinstance(exc, ConnectionError_):
        raise ConnectionError_(red(str(exc))) from None
    if exc is not None:
        raise ConnectionError_(red("%s: %s" % (exc.__class__.__name__, exc))) from None
    raw, status, ctype, loc = state["res"]
    ms = int((time.monotonic() - t0) * 1000)
    # Redacted BEFORE it is parsed: an answer that echoes the credential
    # (inside JSON or not) never hands it to a script or to an operator.
    text = red(raw.decode("utf-8", "replace"))
    out = {"status": status, "ok": 200 <= status < 300, "ms": ms, "url": url,
           "content_type": ctype}
    if loc:
        out["location"] = red(loc)
    try:
        out["json"] = json.loads(text) if text.strip() else None
    except ValueError:
        out["text"] = text[:200_000]
    if auth == "session" and status == 401 and not _relogged:
        # The reused session expired on the server before our TTL: log in
        # again once, never in a loop.
        with _LOCK:
            tokens.pop((d.get("slug") or "") + "#session", None)
        return http_request(d, secret, method, path, query=query, body=body,
                            headers=headers, verify=verify, transport=transport,
                            tokens=tokens, max_body=max_body,
                            deadline=deadline, _relogged=True)
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


def _libpq_version() -> int:
    try:
        import psycopg
        return int(psycopg.pq.version())
    except Exception:  # noqa: BLE001
        return 0


def pg_request(d: dict, secret: str, sql: str, params=None, *, write: bool = False,
               limit: int = 1000, guarded: bool = True, ca: str = "") -> dict:
    """``{columns, rows, rowcount, truncated, ms}``. READ ONLY unless *write*.

    * ONE statement: the query goes through the extended protocol
      (``cursor.stream``), which refuses ``SELECT 1; COMMIT; ...`` -- the
      simple protocol would run every statement, and ``COMMIT; SET
      default_transaction_read_only=off; COMMIT; DELETE ...`` would walk out
      of the read-only transaction.
    * read-only twice: the transaction (``conn.read_only``) and the session
      default (``default_transaction_read_only=on``).
    * bounded: rows arrive one at a time and stop at *limit* rows or
      :data:`MAX_SQL_BYTES`; the server stops the statement at the
      connection's timeout and a watchdog cancels it from here if it does not.
    * libpq ≥ 16: ``require_auth=!password`` -- a server that asks for the
      password in clear is refused before the password is sent.

    A read-only ROLE on the remote database stays the real boundary: a
    function with side effects is still a single SELECT."""
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
    opts = "-c statement_timeout=%d -c idle_in_transaction_session_timeout=%d" % (
        timeout * 1000, (timeout + 30) * 1000)
    if not write:
        opts += " -c default_transaction_read_only=on"
    kw = {"host": host, "port": port, "dbname": d.get("database") or "",
          "user": d.get("username") or "", "password": secret,
          "connect_timeout": min(timeout, 30), "options": opts,
          "application_name": "satom-studio", **pg_sslmode(d, ca)}
    if _libpq_version() >= 160000:
        kw["require_auth"] = "!password"
    t0 = time.monotonic()
    cols: list = []
    rows: list = []
    rowcount, truncated, size = -1, False, 0
    try:
        if guarded:
            kw["hostaddr"] = resolve(host, port)
        with _pg_connect(**kw) as conn:
            conn.read_only = not write
            dog = threading.Timer(timeout + 5, _pg_cancel, (conn,))
            dog.daemon = True
            dog.start()
            try:
                with conn.cursor() as cur:
                    for rec in cur.stream(sql, params or None):
                        if not cols and cur.description:
                            cols = [c.name for c in cur.description]
                        if len(rows) >= limit:
                            truncated = True
                            break
                        row = {k: (v if isinstance(v, (int, float, str, bool, type(None)))
                                   else str(v)) for k, v in zip(cols, rec)}
                        size += sum(len(str(v)) for v in row.values()) + 16
                        if size > MAX_SQL_BYTES:
                            truncated = True
                            break
                        rows.append(row)
                    if not cols and cur.description:
                        cols = [c.name for c in cur.description]
                    rowcount = cur.rowcount if not truncated else len(rows)
                if write and not truncated:
                    conn.commit()
                elif truncated:
                    _pg_cancel(conn)
            finally:
                dog.cancel()
    except Exception as exc:  # noqa: BLE001
        raise ConnectionError_(red("%s: %s" % (exc.__class__.__name__, exc))) from None
    if truncated and write:
        raise ConnectionError_("the statement returned more than %d rows / %d MiB; "
                               "it was rolled back" % (limit, MAX_SQL_BYTES // 1024 // 1024))
    return {"columns": cols, "rows": rows, "rowcount": rowcount,
            "truncated": truncated, "ms": int((time.monotonic() - t0) * 1000)}


def _pg_cancel(conn) -> None:
    for name in ("cancel_safe", "cancel"):
        fn = getattr(conn, name, None)
        if fn is None:
            continue
        try:
            fn()
            return
        except Exception:  # noqa: BLE001
            continue
