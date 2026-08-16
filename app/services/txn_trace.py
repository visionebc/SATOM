# app/services/txn_trace.py
"""Three-leg transaction tracer: client → WAF/ADC → backend.

The question this answers is the one every WAF incident starts with and no
single tool could answer here: **is it the WAF or is it the application?**

Three legs, and they are not three requests:

* **Leg A — SATOM → the VIP.** A real request through the appliance.
* **Leg B — what the appliance FORWARDS.** *Derived from the device's own
  configuration*, never measured. SATOM is not in that path and cannot observe
  it; presenting a derivation as an observation would be the most damaging
  thing this module could do, so every row of leg B names the configuration
  object and field it came from, and a field this firmware does not carry is
  listed as **not present** rather than assumed to be off.
* **Leg C — SATOM → the backend directly**, bypassing the appliance entirely.

The diff of A against C is the answer. Same status, same body, different
headers → the WAF is transforming. Different status → the WAF is deciding.
Both identical → the appliance is not your problem.

Safety, because this module makes the SERVER issue requests:

* Destinations come from :mod:`app.services.net_guard` — free targets are
  allowed (a backend not yet in a pool is exactly the destination that matters
  during an incident) but they are permissioned, resolved once, and dialled by
  address.
* ``GET``/``HEAD``/``OPTIONS`` are free. **A mutating method is a real write to
  someone's application**, issued from inside the management network with no
  browser involved, so it requires an explicit opt-in per call and is audited.
  Replaying a ``POST`` "to see what happens" is how a trace creates the ticket
  it was opened to close.
* Redirects are NOT followed. Following them would silently trace a different
  request from the one the operator asked about — and the redirect itself is
  frequently the finding.
"""
from __future__ import annotations

import hashlib
import http.client
import io
import json
import socket
import ssl
import time
from urllib.parse import quote

LEG_A = "a"
LEG_C = "c"

#: Methods any operator may send. They do not change server state.
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
#: Methods that DO. Gated per call, never by default.
MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE")

#: Response body read cap. Enough to compare and to show; not enough to make a
#: trace a download.
MAX_BODY = 256 * 1024
#: Body preview handed to the panel.
PREVIEW = 2000
#: Request body cap.
MAX_REQ_BODY = 64 * 1024

DEFAULT_TIMEOUT = 8.0

#: Headers whose value is a credential. Recorded as present, never echoed —
#: the trace is rendered in a browser and stored in an audit extra.
REDACT = ("authorization", "proxy-authorization", "cookie", "set-cookie",
          "x-api-key", "x-auth-token", "api-key")


def _redact(name: str, value: str) -> str:
    if name.lower() in REDACT:
        return "<%d bytes, redacted>" % len(value or "")
    return value


# --------------------------------------------------------------------------- #
#  One leg                                                                     #
# --------------------------------------------------------------------------- #
def send(ip: str, port: int, *, host: str, path: str = "/", scheme: str = "https",
         method: str = "GET", headers: dict | None = None, body: bytes = b"",
         sni: str = "", timeout: float = DEFAULT_TIMEOUT, leg: str = LEG_A,
         label: str = "") -> dict:
    """Issue one request and measure it, phase by phase.

    Connects to *ip* (already authorised by :mod:`net_guard`) and sends *host*
    as ``Host`` and SNI. Those are separate on purpose: pointing the same
    ``Host`` at two different addresses is exactly how leg A and leg C are made
    comparable, and it is also how the ``proxy_set_header Host`` class of bug
    becomes visible.
    """
    method = (method or "GET").upper()
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    hdrs = {str(k): str(v) for k, v in (headers or {}).items()}
    body = (body or b"")[:MAX_REQ_BODY]

    out = {
        "leg": leg, "label": label, "ok": False, "error": "",
        "request": {"method": method, "scheme": scheme, "host": host,
                    "ip": ip, "port": int(port), "path": path,
                    "headers": [[k, _redact(k, v)] for k, v in hdrs.items()],
                    "body_bytes": len(body)},
        "status": None, "reason": "", "http_version": "",
        "headers": [], "set_cookie": [], "location": "",
        "body_bytes": 0, "body_sha256": "", "body_preview": "",
        "truncated": False, "tls": None,
        "timing": {"tcp_ms": None, "tls_ms": None, "ttfb_ms": None,
                   "total_ms": None},
    }

    t_start = time.perf_counter()
    sock = None
    try:
        try:
            sock = socket.create_connection((ip, int(port)), timeout=timeout)
        except OSError as exc:
            out["error"] = "TCP connect failed: %s" % exc
            return out
        t_tcp = time.perf_counter()
        out["timing"]["tcp_ms"] = round((t_tcp - t_start) * 1000, 1)

        if scheme == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Read-only inspection, never a trust decision — the same stance
            # cert_probe takes, and the reason the certificate inspector exists
            # as a SEPARATE tool: this one measures behaviour, that one judges
            # the chain.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(sock, server_hostname=sni or host)
            except (ssl.SSLError, OSError) as exc:
                out["error"] = "TLS handshake failed: %s" % exc
                return out
            t_tls = time.perf_counter()
            out["timing"]["tls_ms"] = round((t_tls - t_tcp) * 1000, 1)
            cipher = sock.cipher() or ("", "", 0)
            out["tls"] = {"protocol": sock.version() or "",
                          "cipher": cipher[0], "sni": sni or host}
            try:
                der = sock.getpeercert(binary_form=True)
                if der:
                    from cryptography import x509
                    from cryptography.hazmat.primitives import serialization
                    from . import cert_inspect
                    pem = x509.load_der_x509_certificate(der).public_bytes(
                        serialization.Encoding.PEM).decode()
                    info = cert_inspect.cert_info(pem)
                    out["tls"]["cn"] = info["cn"]
                    out["tls"]["issuer_cn"] = info["issuer_cn"]
                    out["tls"]["days_left"] = info["days_left"]
                    out["tls"]["sans"] = info["sans"][:20]
            except Exception:  # noqa: BLE001 — certificate detail is a bonus
                pass
        else:
            t_tls = t_tcp

        conn = http.client.HTTPConnection(host, int(port), timeout=timeout)
        conn.sock = sock                      # already connected (and wrapped)
        send_headers = dict(hdrs)
        # http.client adds its own Host from ``conn.host`` unless one is given.
        # Giving it explicitly is the point: leg C must carry the SAME Host as
        # leg A even though it dials a different address.
        send_headers.setdefault("Host", _host_header(host, port, scheme))
        send_headers.setdefault("Accept", "*/*")
        send_headers.setdefault("User-Agent", "SATOM-tracer/1")
        try:
            conn.request(method, path, body=body or None, headers=send_headers)
            resp = conn.getresponse()
        except Exception as exc:  # noqa: BLE001
            out["error"] = "HTTP exchange failed: %s: %s" % (type(exc).__name__, exc)
            return out
        t_first = time.perf_counter()
        out["timing"]["ttfb_ms"] = round((t_first - t_tls) * 1000, 1)

        out["status"] = resp.status
        out["reason"] = resp.reason or ""
        out["http_version"] = {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(
            resp.version, str(resp.version))
        for k, v in resp.getheaders():
            out["headers"].append([k, _redact(k, v)])
            if k.lower() == "set-cookie":
                out["set_cookie"].append(_cookie_shape(v))
            elif k.lower() == "location":
                out["location"] = v
        raw = resp.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raw = raw[:MAX_BODY]
            out["truncated"] = True
        out["body_bytes"] = len(raw)
        out["body_sha256"] = hashlib.sha256(raw).hexdigest()
        out["body_preview"] = raw[:PREVIEW].decode("utf-8", "replace")
        out["ok"] = True
    finally:
        out["timing"]["total_ms"] = round(
            (time.perf_counter() - t_start) * 1000, 1)
        try:
            if sock is not None:
                sock.close()
        except Exception:  # noqa: BLE001
            pass
    return out


def _host_header(host: str, port: int, scheme: str) -> str:
    """``Host`` as a browser would send it.

    The default port is OMITTED and a non-default port is INCLUDED. That is not
    cosmetic: an nginx in front that passes ``$host`` instead of ``$http_host``
    drops the port, and every POST behind a non-standard port then fails its
    CSRF referer check. This tracer exists partly to make that visible, so it
    has to send what a browser sends.
    """
    default = 443 if scheme == "https" else 80
    if ":" in host and not host.startswith("["):
        host = "[%s]" % host
    return host if int(port) == default else "%s:%d" % (host, int(port))


def _cookie_shape(value: str) -> dict:
    """A Set-Cookie described by its FLAGS, without its value.

    The flags are the finding (a cookie the WAF adds, a ``Secure`` the backend
    omits); the value is a session credential rendered into a browser panel."""
    parts = [p.strip() for p in str(value or "").split(";")]
    name = parts[0].split("=", 1)[0] if parts else ""
    attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else True)
             for p in parts[1:] if p}
    return {"name": name, "secure": "secure" in attrs,
            "httponly": "httponly" in attrs,
            "samesite": attrs.get("samesite", ""),
            "path": attrs.get("path", ""), "domain": attrs.get("domain", "")}


# --------------------------------------------------------------------------- #
#  Leg B — derived, never measured                                             #
# --------------------------------------------------------------------------- #
#: ``(object, field, applies_to, when_on, when_off)``.
#:
#: Field names verified against a LIVE FortiWeb 7.6.8 object (fortiweb09,
#: ``pol-shop-cms`` and ``wpp-int``), not recalled. A field this firmware does
#: not carry is reported as *not present on this object* — never as "disabled",
#: because those two look identical in a table and mean opposite things.
DERIVATIONS: tuple[tuple[str, str, str, str, str], ...] = (
    ("policy", "status", "routing",
     "The policy is enabled, so traffic to this VIP is served.",
     "THE POLICY IS DISABLED — nothing is served on this VIP at all, and leg A "
     "will not reflect any protection setting below."),
    ("policy", "monitor-mode", "routing",
     "MONITOR MODE: every WAF verdict is logged and NOTHING is blocked, "
     "whatever the profile's actions say. A request that 'got through' proves "
     "nothing while this is on.",
     "Blocking verdicts are enforced."),
    ("policy", "deployment-mode", "routing",
     "Deployment mode decides whether the appliance proxies to a pool, "
     "to a single server, or bridges transparently.", ""),
    ("policy", "protocol", "routing", "Front-end protocol.", ""),
    ("policy", "ssl", "tls",
     "TLS is TERMINATED on the appliance: leg C's TLS is a different session "
     "from leg A's, and a backend certificate problem is invisible to clients.",
     "TLS is not terminated here."),
    ("policy", "http-to-https", "request",
     "Plain HTTP is answered with a redirect to HTTPS — leg A on port 80 will "
     "return 30x and never reach the backend.", ""),
    ("policy", "redirect-naked-domain", "request",
     "A request for the apex is redirected to www.", ""),
    ("policy", "client-real-ip", "request",
     "The appliance connects to the backend USING THE CLIENT'S ADDRESS as "
     "source, so the backend sees the real client and NOT the appliance.",
     "The backend sees the appliance's address as the source; the client "
     "address survives only in a header."),
    ("policy", "real-ip-addr", "request",
     "The address range used when client-real-ip is on.", ""),
    ("policy", "client-certificate-forwarding", "request",
     "The client certificate is forwarded to the backend in a header — a "
     "header that exists on leg A's path and CANNOT exist on leg C's.", ""),
    ("policy", "client-certificate-forwarding-cert-header", "request",
     "Header name carrying the forwarded certificate.", ""),
    ("policy", "case-sensitive", "request",
     "URL matching is case-sensitive.",
     "URLs are matched case-insensitively — a pattern that looks exact is not."),
    ("policy", "url-normalize-backslash", "request",
     "Backslashes in the URL are normalised before matching, so the backend "
     "may receive a different path from the one sent.", ""),
    ("policy", "chunk-encoding", "request",
     "Chunked transfer encoding is passed through.", ""),
    ("policy", "http2", "request", "HTTP/2 is offered to clients; the backend "
     "leg is HTTP/1.1 regardless.", ""),
    ("policy", "proxy-protocol", "request",
     "PROXY protocol is expected IN FRONT of this policy — the source address "
     "the appliance believes comes from that header, not from the socket.", ""),
    ("policy", "hsts-header", "response",
     "Strict-Transport-Security is ADDED by the appliance. It will be present "
     "on leg A and absent on leg C, and that difference is not a backend bug.",
     ""),
    ("policy", "hpkp-header", "response", "Public-Key-Pins is added.", ""),
    ("policy", "internal-cookie-secure", "response",
     "The appliance's OWN session cookie is marked Secure.", ""),
    ("policy", "internal-cookie-httponly", "response",
     "The appliance's own session cookie is marked HttpOnly.", ""),
    ("policy", "internal-cookie-samesite", "response",
     "SameSite policy applied to the appliance's own cookie.", ""),
    ("policy", "scripting", "request",
     "LUA SCRIPTING IS ACTIVE on this policy. A script can rewrite anything in "
     "the request or the response, so the rest of this table is a floor, not a "
     "complete account.", ""),
    ("policy", "sz_http-content-routing-list", "routing",
     "CONTENT ROUTING is configured: the pool this request reaches depends on "
     "the request itself, so leg C may be dialling a different backend from "
     "the one leg A ended up on.", ""),
    ("policy", "web-cache", "response",
     "Web cache is on — a response on leg A may not have come from the backend "
     "at all.", ""),
    ("policy", "replacemsg-on-connect-failure", "response",
     "A backend connect failure is answered with a replacement page, so leg A "
     "can return 200 while the backend is down.", ""),
    ("policy", "retry-on", "routing",
     "Failed requests are retried, possibly against a different pool member.", ""),

    ("pool", "lb-algo", "routing",
     "Load-balancing algorithm — which member a given request lands on.", ""),
    ("pool", "server-balance", "routing", "Balancing across pool members.",
     "Single-server pool: every request goes to the same member."),
    ("pool", "persistence", "routing",
     "Session persistence pins a client to one member.", ""),
    ("pool", "health", "routing",
     "Health check governing which members are eligible. A member the check "
     "has marked down is silently skipped — the most common 'the WAF is "
     "broken' that is not the WAF.", ""),
    # Value-descriptive, NOT an assertion. This field's values are an enum
    # (``never``/``always``/``safe``…), and the first draft of this row said
    # "backend connections are reused between clients" for EVERY non-empty
    # value — including ``never``, which means the opposite. A row that states
    # a behaviour has to be a row whose field is binary.
    ("pool", "http-reuse", "request",
     "Backend connection-reuse policy toward the pool members.", ""),
    ("pool", "type", "routing", "Pool member addressing (IP or domain).", ""),

    ("xff", "x-forwarded-for-support", "request",
     "X-Forwarded-For is MAINTAINED toward the backend — the backend's idea of "
     "the client address comes from this header, and leg C carries whatever "
     "SATOM sends instead.",
     "X-Forwarded-For is NOT maintained: the backend sees only the "
     "appliance's address."),
    ("xff", "original-ip-header", "request",
     "The header the appliance READS the original client address from. If "
     "something upstream can set it, it can set the address the WAF blocks on.",
     ""),
    ("xff", "x-real-ip", "request", "X-Real-IP is added toward the backend.", ""),
    ("xff", "x-forwarded-proto", "request",
     "X-Forwarded-Proto is added, so the backend can tell the client's scheme "
     "apart from the backend leg's.", ""),
    ("xff", "add-source-port", "request",
     "The client's source PORT is appended.", ""),
    ("xff", "merge-headers", "request",
     "Existing X-Forwarded-For values are merged rather than replaced.", ""),
    ("xff", "delete-headers", "request",
     "Listed headers are DELETED before forwarding — a header the backend "
     "never sees, and its absence looks like a client bug.", ""),
    ("xff", "ip-location-add", "request",
     "Geo-location header placement toward the backend.", ""),

    ("wpp", "url-rewrite-policy", "request",
     "A URL-REWRITE POLICY is bound: the path and headers the backend receives "
     "are not necessarily the ones sent.", ""),
    ("wpp", "http-session-cookie", "response",
     "The appliance issues its own session cookie.", ""),
    ("wpp", "signature-rule", "request", "Signature set enforced on this path.", ""),
    ("wpp", "x-forwarded-for-rule", "request",
     "The X-Forwarded-For object this profile applies.", ""),
)

#: Values that mean "off" across FortiWeb's cmdb. An empty string is the third
#: state — a reference to nothing — and is treated as off but reported as
#: unset, because "disable" and "no object bound" are different fixes.
#:
#: ``never``/``none``/``no`` are here because FortiWeb spells "off" four ways
#: depending on the field, and the first version of this table read
#: ``http-reuse: never`` as ENABLED and printed a sentence claiming connections
#: were reused. Measured against the live fortiweb09 object, not recalled.
_OFF = ("disable", "disabled", "0", "off", "no", "none", "never", "")


def _state(value) -> str:
    s = "" if value is None else str(value).strip()
    if s == "":
        return "unset"
    return "off" if s.lower() in _OFF else "on"


def derive_forwarded(policy_full: dict) -> dict:
    """What the appliance forwards, derived from its configuration.

    Returns ``{rows, backends, absent, sources}``. ``absent`` lists spec entries
    whose field this firmware's object does not carry — a distinction that
    matters because a table showing "disabled" for a field that does not exist
    is a claim SATOM never measured.
    """
    pf = policy_full or {}
    objects = {
        "policy": pf.get("policy") or {},
        "pool": pf.get("pool") or {},
        "wpp": pf.get("wpp") or {},
        "xff": pf.get("xff") or {},
        "vserver": pf.get("vserver") or {},
    }
    rows: list[dict] = []
    absent: list[dict] = []
    for obj, field, applies, on_note, off_note in DERIVATIONS:
        src = objects.get(obj) or {}
        if not src:
            absent.append({"object": obj, "field": field,
                           "why": "the %s object was not read" % obj})
            continue
        if field not in src:
            absent.append({"object": obj, "field": field,
                           "why": "not present on this firmware's %s object" % obj})
            continue
        value = src.get(field)
        st = _state(value)
        note = on_note if st == "on" else (off_note if st == "off" else "")
        rows.append({"object": obj, "field": field, "value": ("" if value is None
                                                              else str(value)),
                     "state": st, "applies_to": applies, "effect": note})

    backends = []
    for b in (pf.get("backends") or []):
        if not isinstance(b, dict):
            continue
        backends.append({
            "ip": b.get("ip") or b.get("server-name") or b.get("domain") or "",
            "port": b.get("port") or "",
            "status": b.get("status") or "",
            "ssl": b.get("ssl") or "",
            "weight": b.get("weight") or "",
            "backup": b.get("backup-server") or "",
            "hlck": b.get("hlck-inherit") or b.get("health-check") or "",
        })
    vips = [v for v in (pf.get("vips") or []) if v]
    return {"rows": rows, "backends": backends, "absent": absent,
            "vips": vips,
            "sources": sorted(k for k, v in objects.items() if v),
            "measured": False,
            "note": ("Leg B is DERIVED from the appliance's configuration. "
                     "SATOM is not in the path between the appliance and the "
                     "backend and cannot observe it — every row below names "
                     "the object and field it came from.")}


# --------------------------------------------------------------------------- #
#  Diff                                                                        #
# --------------------------------------------------------------------------- #
#: Headers that differ on every pair of responses and mean nothing when they do.
VOLATILE_HEADERS = ("date", "age", "expires", "etag", "last-modified",
                    "content-length", "keep-alive", "connection",
                    "x-request-id", "x-correlation-id", "x-trace-id",
                    "cf-ray", "x-amz-request-id", "x-served-by")


def diff(a: dict, c: dict) -> dict:
    """A vs C — the answer to *is it the WAF or is it the app?*

    Volatile headers are separated out rather than dropped. Excluding them
    silently makes ``Content-Length`` invisible, and a length that differs while
    the body hash matches is a real finding about transfer encoding.
    """
    if not (a or {}).get("ok") or not (c or {}).get("ok"):
        return {"comparable": False,
                "why": "Both legs must have completed. %s" % _leg_errors(a, c)}
    ha = {k.lower(): v for k, v in a["headers"]}
    hc = {k.lower(): v for k, v in c["headers"]}
    only_a, only_c, changed, volatile = [], [], [], []
    for k in sorted(set(ha) | set(hc)):
        va, vc = ha.get(k), hc.get(k)
        if k in VOLATILE_HEADERS:
            if va != vc:
                volatile.append({"header": k, "a": va, "c": vc})
            continue
        if va is not None and vc is None:
            only_a.append({"header": k, "value": va})
        elif vc is not None and va is None:
            only_c.append({"header": k, "value": vc})
        elif va != vc:
            changed.append({"header": k, "a": va, "c": vc})

    verdict = _verdict(a, c, only_a, only_c, changed)
    return {
        "comparable": True,
        "status": {"a": a["status"], "c": c["status"],
                   "same": a["status"] == c["status"]},
        "body": {"same": a["body_sha256"] == c["body_sha256"],
                 "a_bytes": a["body_bytes"], "c_bytes": c["body_bytes"],
                 "truncated": a["truncated"] or c["truncated"]},
        "headers": {"added_by_appliance": only_a, "dropped_before_client": only_c,
                    "changed": changed, "volatile": volatile},
        "cookies": {"a": a["set_cookie"], "c": c["set_cookie"]},
        "redirect": {"a": a["location"], "c": c["location"],
                     "same": a["location"] == c["location"]},
        "timing": {"a": a["timing"], "c": c["timing"]},
        "verdict": verdict,
    }


def _leg_errors(a: dict, c: dict) -> str:
    bits = []
    for leg, name in ((a, "Leg A (via the appliance)"),
                      (c, "Leg C (direct to the backend)")):
        if leg and not leg.get("ok"):
            bits.append("%s: %s" % (name, leg.get("error") or "did not complete"))
    return " ".join(bits)


def _verdict(a, c, only_a, only_c, changed) -> dict:
    """A sentence, not a colour. The operator came for this one line."""
    if a["status"] != c["status"]:
        return {"key": "appliance_decides",
                "text": "The appliance answered %s where the backend answered "
                        "%s. THE APPLIANCE IS DECIDING this request — look at "
                        "the attack log for this window before touching the "
                        "application." % (a["status"], c["status"])}
    if a["body_sha256"] != c["body_sha256"]:
        return {"key": "body_differs",
                "text": "Same status, different body. Something is rewriting "
                        "the response, or the two legs did not reach the same "
                        "application (content routing, a different pool member, "
                        "or a cache)."}
    if only_a or only_c or changed:
        return {"key": "appliance_transforms",
                "text": "Same status and same body; only headers differ. The "
                        "appliance is transforming, not blocking — the table "
                        "below says which configuration object does it."}
    return {"key": "transparent",
            "text": "Status, body and headers are identical on both legs. The "
                    "appliance is not altering this transaction, so a fault "
                    "reproduced here is the application's."}


# --------------------------------------------------------------------------- #
#  Attack-log correlation                                                      #
# --------------------------------------------------------------------------- #
def correlate(entries, started_at: float, ended_at: float, src_ips=()) -> dict:
    """Attack-log entries that could belong to this trace.

    Deliberately returns CANDIDATES, not matches. An attack-log timestamp has
    one-second resolution and no request id, so "this entry is your request" is
    a claim the data cannot support — and an operator who builds an exception
    for the wrong entry has widened their WAF for nothing.
    """
    ips = {str(i) for i in (src_ips or []) if i}
    lo, hi = min(started_at, ended_at) - 2, max(started_at, ended_at) + 2
    out = []
    for row in (entries or []):
        if not isinstance(row, dict):
            continue
        ts = _row_epoch(row)
        if ts is not None and not (lo <= ts <= hi):
            continue
        score = 0
        if ts is not None:
            score += 1
        if ips and str(row.get("src") or "") in ips:
            score += 2
        out.append({"row": row, "score": score,
                    "why": _why(ts is not None, bool(ips) and
                                str(row.get("src") or "") in ips)})
    out.sort(key=lambda d: -d["score"])
    return {"candidates": out[:20], "window": [lo, hi],
            "source_ips": sorted(ips),
            "note": ("Candidates, not matches. The attack log has second "
                     "resolution and carries no request id, so nothing here "
                     "proves an entry is this request.")}


def _why(in_window: bool, ip_match: bool) -> str:
    bits = []
    if in_window:
        bits.append("timestamp falls in the trace window")
    if ip_match:
        bits.append("source address matches the tracer's egress address")
    return "; ".join(bits) or "listed for review only"


def _row_epoch(row: dict):
    import datetime as _dt
    for key in ("rel_time", "date_time", "timestamp", "time"):
        v = row.get(key)
        if not v:
            continue
        if isinstance(v, (int, float)):
            return float(v)
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S"):
            try:
                return _dt.datetime.strptime(str(v)[:19], fmt).timestamp()
            except ValueError:
                continue
    return None


# --------------------------------------------------------------------------- #
#  Export                                                                      #
# --------------------------------------------------------------------------- #
def to_curl(leg: dict) -> str:
    """A curl line that reproduces this leg on any shell.

    ``--resolve`` rather than a bare URL, because the whole point of leg C is
    the same ``Host`` against a different address. A curl that drops that is a
    reproduction of a different request.
    """
    req = (leg or {}).get("request") or {}
    scheme = req.get("scheme", "https")
    host = req.get("host", "")
    port = int(req.get("port") or (443 if scheme == "https" else 80))
    url = "%s://%s%s%s" % (scheme, host,
                           "" if port in (80, 443) else ":%d" % port,
                           req.get("path", "/"))
    bits = ["curl", "-sS", "-D", "-", "-o", "/dev/null"]
    if scheme == "https":
        bits.append("-k")            # matches the tracer: inspection, not trust
    bits += ["--resolve", "%s:%d:%s" % (host, port, req.get("ip", ""))]
    if (req.get("method") or "GET") != "GET":
        bits += ["-X", req["method"]]
    for k, v in (req.get("headers") or []):
        if k.lower() == "host":
            continue
        bits += ["-H", "%s: %s" % (k, v)]
    bits.append(url)
    return " ".join(_shq(b) for b in bits)


def _shq(s: str) -> str:
    s = str(s)
    if s and all(c.isalnum() or c in "-_./:@=+," for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def to_har(legs: list[dict]) -> dict:
    """A HAR 1.2 log the operator can open in any browser devtools."""
    entries = []
    for leg in (legs or []):
        if not leg or not leg.get("ok"):
            continue
        req = leg["request"]
        scheme = req.get("scheme", "https")
        port = int(req.get("port") or 443)
        url = "%s://%s%s%s" % (scheme, req.get("host", ""),
                               "" if port in (80, 443) else ":%d" % port,
                               req.get("path", "/"))
        t = leg["timing"]
        entries.append({
            "startedDateTime": "1970-01-01T00:00:00.000Z",
            "time": t.get("total_ms") or 0,
            "comment": leg.get("label") or leg.get("leg"),
            "request": {"method": req["method"], "url": url,
                        "httpVersion": "HTTP/1.1",
                        "headers": [{"name": k, "value": v}
                                    for k, v in req.get("headers") or []],
                        "queryString": [], "cookies": [], "headersSize": -1,
                        "bodySize": req.get("body_bytes", 0)},
            "response": {"status": leg["status"], "statusText": leg["reason"],
                         "httpVersion": leg["http_version"] or "HTTP/1.1",
                         "headers": [{"name": k, "value": v}
                                     for k, v in leg["headers"]],
                         "cookies": [], "content": {
                             "size": leg["body_bytes"], "mimeType": "",
                             "comment": "body not captured in HAR; sha256=%s"
                                        % leg["body_sha256"]},
                         "redirectURL": leg["location"], "headersSize": -1,
                         "bodySize": leg["body_bytes"]},
            "cache": {},
            "timings": {"blocked": -1, "dns": -1,
                        "connect": t.get("tcp_ms") if t.get("tcp_ms") is not None else -1,
                        "ssl": t.get("tls_ms") if t.get("tls_ms") is not None else -1,
                        "send": 0,
                        "wait": t.get("ttfb_ms") if t.get("ttfb_ms") is not None else -1,
                        "receive": 0},
        })
    return {"log": {"version": "1.2",
                    "creator": {"name": "SATOM transaction tracer",
                                "version": "1"},
                    "entries": entries}}


def to_har_text(legs: list[dict]) -> str:
    buf = io.StringIO()
    json.dump(to_har(legs), buf, indent=1)
    return buf.getvalue()


__all__ = [
    "LEG_A", "LEG_C", "SAFE_METHODS", "MUTATING_METHODS", "MAX_BODY",
    "REDACT", "DERIVATIONS", "VOLATILE_HEADERS",
    "send", "derive_forwarded", "diff", "correlate", "to_curl", "to_har",
    "to_har_text",
]
