# app/services/observatory_scan.py
"""Fetch what a published site sends, the way the HTTP Observatory fetches it,
and grade it with :mod:`app.services.header_observatory`.

**Only sites the appliances publish are scanned** (operator decision,
2026-10-16): a target is a FortiWeb server policy or a FortiADC virtual
server, read from the device, and the address dialled is always that policy's
VIP. The operator may name the site (``Host`` / SNI) but never the address, so
this is not a free-form scanner and needs no free-target permission:
:func:`_authorise` runs every dial through :mod:`app.services.net_guard` in
inventory mode with exactly the (VIP, port) pairs the policy serves, loopback
refused.

What is fetched, per site — the Observatory's own sequence:

1. ``https://<host>/`` and ``http://<host>/`` on the policy's ports, each
   following redirects (up to 10). A redirect is followed only while it stays
   on this policy (same name or the VIP, a port the policy serves); a hop
   anywhere else ends the chain and is recorded, not fetched: SATOM never
   dials a destination the policy does not publish, and the page there is not
   this policy's to grade anyway.
2. ``/robots.txt`` and an ``OPTIONS`` CORS preflight (``Origin:``
   :data:`CORS_ORIGIN`) on the session the header tests read.

Every request goes through :func:`app.services.txn_trace.send` — one HTTP
emitter for the tracer and the observatory, with certificate trust asked
separately (``verify_tls``) so an untrusted certificate is a graded finding
and not a scan failure. Cookie values travel only inside the scan (to send
them back on the next hop, as a browser would) and are dropped before
anything is stored or returned: results carry cookie FLAGS, never values.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlsplit

from . import header_observatory as ho
from . import net_guard, txn_trace

#: Origin sent with the CORS preflight. ``.invalid`` can never be a real site,
#: so a backend that answers it with credentials reflects ANY origin.
CORS_ORIGIN = "https://observatory.satom.invalid"
USER_AGENT = "Mozilla/5.0 (compatible; SATOM-Observatory/1)"
ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
REDIRECT_STATUS = (301, 302, 303, 307, 308)
MAX_REDIRECTS = 10
TIMEOUT = 6.0
#: Wall-clock budget of one site: a slow site with a long redirect chain stops
#: here (named in the result) instead of holding a worker for minutes.
SCAN_BUDGET = 90.0


@dataclass
class Target:
    """One published site: where it listens and what it is called."""
    appliance_id: int
    appliance: str
    product: str
    policy: str
    vip: str = ""
    http_port: int | None = None
    https_port: int | None = None
    #: Names the policy is configured to serve (Protected Hostnames on
    #: FortiWeb). The first one is the default site name; the VIP otherwise.
    hosts: list[str] = field(default_factory=list)
    enabled: bool = True
    note: str = ""

    @property
    def default_host(self) -> str:
        return (self.hosts[0] if self.hosts else "") or self.vip

    @property
    def scannable(self) -> bool:
        return bool(self.enabled and self.vip and (self.http_port or self.https_port))

    def as_dict(self) -> dict:
        d = asdict(self)
        d["default_host"] = self.default_host
        d["scannable"] = self.scannable
        return d


# --------------------------------------------------------------------------- #
#  Targets                                                                     #
# --------------------------------------------------------------------------- #
def _protected_hosts(client, policy_row: dict) -> list[str]:
    """Plain (non-wildcard, non-regex) names of the policy's Protected
    Hostnames group, in order. An unreadable group is no names, not an error:
    the VIP still identifies the site."""
    group = str(policy_row.get("allow-hosts") or "").strip()
    if not group:
        return []
    from urllib.parse import quote
    rows = client._safe_list(
        "/api/v2.0/cmdb/server-policy/allow-hosts/host-list?mkey=%s" % quote(group, safe=""))
    out = []
    for r in rows:
        h = str(r.get("host") or "").strip().lower()
        if h and not any(ch in h for ch in "*?^$[](){}\\|+") and h not in out:
            out.append(h)
    return out


def fortiweb_targets(appliance, client) -> list[Target]:
    """One :class:`Target` per FortiWeb server policy."""
    from . import service_probe
    rows = {str(r.get("name") or ""): r
            for r in client._results_list(client.list_server_policies())}
    out = []
    for t in service_probe.resolve_targets_from_client(client):
        row = rows.get(t.policy) or {}
        enabled = str(row.get("status") or "enable").lower() != "disable"
        try:
            hosts = _protected_hosts(client, row)
        except Exception:  # noqa: BLE001 — names are a convenience
            hosts = []
        note = t.note
        if not enabled:
            note = "the policy is disabled"
        out.append(Target(appliance_id=appliance.id, appliance=appliance.name,
                          product="fortiweb", policy=t.policy, vip=t.host or "",
                          http_port=t.http_port, https_port=t.https_port,
                          hosts=hosts, enabled=enabled, note=note))
    return out


def fortiadc_targets(appliance, client) -> list[Target]:
    """One :class:`Target` per FortiADC virtual server. A FortiADC publishes
    HTTP and HTTPS of one site as two virtual servers on the same address, so
    each gets its sibling's port too — that is what the redirect test needs."""
    from . import adc_ops
    vs = adc_ops.resolve_targets(client)
    by_addr: dict[str, dict] = {}
    for t in vs:
        if t.host and t.port:
            slot = by_addr.setdefault(t.host, {})
            slot.setdefault(t.scheme, t.port)
    out = []
    for t in vs:
        sib = by_addr.get(t.host) or {}
        out.append(Target(appliance_id=appliance.id, appliance=appliance.name,
                          product="fortiadc", policy=t.policy, vip=t.host or "",
                          http_port=(t.port if t.scheme == "http" else sib.get("http")),
                          https_port=(t.port if t.scheme == "https" else sib.get("https")),
                          note=t.note))
    return out


#: Products whose published sites can be scanned.
PRODUCTS = ("fortiweb", "fortiadc")


#: How long a listing is reused by :func:`find_target`. Listing a FortiWeb
#: reads every policy and its linked objects — 22 s for 50 policies on
#: fortiweb17 (measured) — and "Grade all" asks for one site at a time.
TARGETS_TTL = 300
_TARGETS: dict[int, tuple[float, list[Target]]] = {}


def targets_for(appliance) -> list[Target]:
    """Every published site of one appliance (reads the device, always)."""
    from ..clients import client_for
    client = client_for(appliance)
    if appliance.kind == "fortiadc":
        out = fortiadc_targets(appliance, client)
    elif appliance.kind == "fortiweb":
        out = fortiweb_targets(appliance, client)
    else:
        out = []
    _TARGETS[appliance.id] = (time.time(), out)
    return out


def find_target(appliance, policy: str) -> Target | None:
    """One site by policy name: from the listing read in the last
    :data:`TARGETS_TTL` seconds, re-read once when it is older or does not
    have that policy (a policy created since)."""
    cached = _TARGETS.get(appliance.id)
    if cached is not None and time.time() - cached[0] < TARGETS_TTL:
        hit = next((t for t in cached[1] if t.policy == policy), None)
        if hit is not None:
            return hit
    return next((t for t in targets_for(appliance) if t.policy == policy), None)


# --------------------------------------------------------------------------- #
#  Fetching                                                                    #
# --------------------------------------------------------------------------- #
def _authorise(target: Target, port: int) -> str:
    """The address to dial for ``port`` — the policy's VIP, through net_guard.
    Raises :class:`net_guard.TargetError`."""
    pairs = [(target.vip, p) for p in (target.http_port, target.https_port) if p]
    dest = net_guard.resolve_target(target.vip, port, mode=net_guard.MODE_INVENTORY,
                                    inventory_hosts=pairs, allow_loopback=False)
    return dest["ip"]


def _url(scheme: str, host: str, port: int, path: str) -> str:
    h = "[%s]" % host if ":" in host and not host.startswith("[") else host
    default = 443 if scheme == "https" else 80
    return "%s://%s%s%s" % (scheme, h, "" if port == default else ":%d" % port, path or "/")


def _on_policy(target: Target, host: str, url: str):
    """``(scheme, port, path)`` when *url* is still this policy, else None."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        return None
    name = (parts.hostname or "").lower()
    if name not in (host.lower(), target.vip.lower()):
        return None
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        return None
    if port != (target.https_port if scheme == "https" else target.http_port):
        return None
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return scheme, port, path


class _Session:
    """A cookie jar and the shapes of every Set-Cookie seen, like the
    Observatory's per-scheme session. Values live here only."""

    def __init__(self):
        self.jar: dict[str, str] = {}
        self.cookies: list[dict] = []

    def headers(self, extra: dict | None = None) -> dict:
        h = {"Accept": ACCEPT, "User-Agent": USER_AGENT}
        if self.jar:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in self.jar.items())
        h.update(extra or {})
        return h

    def absorb(self, leg: dict) -> None:
        shapes = leg.get("set_cookie") or []
        values = ((leg.get("secrets") or {}).get("set_cookie_values")) or []
        for i, shape in enumerate(shapes):
            name = shape.get("name") or ""
            if not name:
                continue
            # Last one wins, as in a jar.
            self.cookies = [c for c in self.cookies
                            if (c.get("name"), c.get("path")) != (name, shape.get("path"))]
            self.cookies.append(dict(shape))
            if i < len(values):
                self.jar[name] = values[i]


def _response(leg: dict, verified: bool, url: str) -> dict:
    """The engine's view of one leg — no secrets."""
    return {"url": url, "status": leg.get("status"),
            "headers": [list(h) for h in leg.get("headers") or []],
            "set_cookie": [dict(c) for c in leg.get("set_cookie") or []],
            "verified": verified, "body": leg.get("body_text") or ""}


def _send(target, ip, host, scheme, port, path, session, method="GET", extra=None):
    return txn_trace.send(ip, port, host=host, path=path, scheme=scheme,
                          method=method, headers=session.headers(extra),
                          timeout=TIMEOUT, label="observatory", reveal=True,
                          verify_tls=(scheme == "https"),
                          keep_body=(method == "GET"))


def _chain(target: Target, host: str, scheme: str, port: int, session: _Session,
           deadline: float = 0.0) -> dict:
    """Follow one scheme's redirects. Returns ``{response, route, last,
    error, verified}`` — ``response`` None when nothing answered."""
    route: list[dict] = []
    verified = True
    path = "/"
    url = _url(scheme, host, port, path)
    final = None
    last = None
    for hop in range(MAX_REDIRECTS + 1):
        if deadline and time.time() > deadline:
            return {"response": None, "route": route, "verified": verified,
                    "error": "stopped: the %d s budget of one site ran out" % SCAN_BUDGET,
                    "last": last}
        try:
            ip = _authorise(target, port)
        except net_guard.TargetError as exc:
            return {"response": None, "route": route, "verified": verified,
                    "error": "refused: %s" % exc, "last": last}
        leg = _send(target, ip, host, scheme, port, path, session)
        if not leg.get("ok"):
            # The Observatory's session fails as a whole when a hop fails.
            return {"response": None, "route": route, "verified": verified,
                    "error": leg.get("error") or "no response", "last": last}
        if scheme == "https" and not (leg.get("tls") or {}).get("verified", True):
            verified = False
        session.absorb(leg)
        route.append({"url": url, "status": leg.get("status"), "followed": True})
        last = {"scheme": scheme, "port": port, "path": path, "url": url,
                "tls": leg.get("tls")}
        final = leg
        loc = leg.get("location") or ""
        if leg.get("status") in REDIRECT_STATUS and loc and hop < MAX_REDIRECTS:
            nxt = urljoin(url, loc)
            on = _on_policy(target, host, nxt)
            if on is None:
                route.append({"url": nxt, "status": None, "followed": False})
                break
            scheme, port, path = on
            url = nxt
            continue
        break
    return {"response": _response(final, verified, last["url"]),
            "route": route, "verified": verified, "error": "", "last": last}


def retrieve(target: Target, host: str | None = None) -> dict:
    """Everything :func:`header_observatory.analyze` reads, for one site."""
    host = (host or target.default_host or target.vip).strip().lower()
    req: dict = {"host": host, "https": None, "http": None, "http_route": [],
                 "https_route": [], "auto": None, "auto_url": "", "cors": None,
                 "cors_origin": CORS_ORIGIN, "cookies": [], "errors": {},
                 "tls": None}
    sessions = {}
    chains = {}
    deadline = time.time() + SCAN_BUDGET
    for scheme, port in (("https", target.https_port), ("http", target.http_port)):
        if not port:
            continue
        sessions[scheme] = _Session()
        ch = _chain(target, host, scheme, port, sessions[scheme], deadline)
        chains[scheme] = ch
        req[scheme] = ch["response"]
        req[scheme + "_route"] = ch["route"]
        if ch["error"]:
            req["errors"][scheme] = ch["error"]
    pick = "https" if req["https"] else ("http" if req["http"] else "")
    if not pick:
        return req
    req["auto"] = req[pick]
    req["auto_url"] = req[pick]["url"]
    session = sessions[pick]
    last = chains[pick]["last"] or {}
    req["tls"] = ((chains.get("https") or {}).get("last") or {}).get("tls")
    start_port = target.https_port if pick == "https" else target.http_port
    try:
        ip = _authorise(target, start_port)
        robots = _send(target, ip, host, pick, start_port, "/robots.txt", session,
                       extra={"Accept": "text/plain,*/*;q=0.8"})
        if robots.get("ok"):
            session.absorb(robots)
    except net_guard.TargetError:
        pass
    try:
        lport = last.get("port") or start_port
        ip = _authorise(target, lport)
        cors = _send(target, ip, host, last.get("scheme") or pick, lport,
                     last.get("path") or "/", session, method="OPTIONS",
                     extra={"Access-Control-Request-Method": "GET",
                            "Origin": CORS_ORIGIN})
        if cors.get("ok"):
            req["cors"] = _response(cors, chains[pick]["verified"], req["auto_url"])
            session.absorb(cors)
    except net_guard.TargetError:
        pass
    req["cookies"] = list(session.cookies)
    return req


def _strip_bodies(req: dict) -> dict:
    """What is kept: headers, statuses, routes, cookie flags — no bodies."""
    out = {k: v for k, v in req.items() if k not in ("https", "http", "auto", "cors")}
    for k in ("https", "http", "auto", "cors"):
        r = req.get(k)
        if r:
            out[k] = {kk: vv for kk, vv in r.items() if kk != "body"}
            out[k]["body_bytes"] = len((r.get("body") or "").encode("utf-8", "replace"))
    return out


def scan(target: Target, host: str | None = None) -> dict:
    """Retrieve and grade one site. Never raises for a network failure: a site
    that cannot be graded comes back with ``error`` and no grade."""
    started = time.time()
    host = (host or target.default_host or target.vip).strip().lower()
    base = {"target": target.as_dict(), "host": host,
            "started": started, "grade": None, "score": None, "error": ""}
    if not target.scannable:
        base["error"] = target.note or "nothing to scan: no VIP or no HTTP(S) service"
        base["finished"] = time.time()
        return base
    req = retrieve(target, host)
    base["retrieval"] = _strip_bodies(req)
    try:
        analysis = ho.analyze(req)
    except ho.SiteDown as exc:
        errs = "; ".join("%s: %s" % kv for kv in (req.get("errors") or {}).items())
        base["error"] = str(exc) + (" (%s)" % errs if errs else "")
        base["finished"] = time.time()
        return base
    base.update(grade=analysis["grade"], score=analysis["score"], analysis=analysis)
    base["finished"] = time.time()
    return base
