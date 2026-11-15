# app/services/net_guard.py
"""Where SATOM is allowed to open a socket on the operator's behalf.

Two tools take a destination from the browser and connect to it FROM THE SERVER:
the certificate inspector and the transaction tracer. That is server-side
request forgery by construction — the request leaves from inside the management
network, with this host's network reach, and the operator's browser never
touches it. So the destination is a security decision, not a form field.

The product answer (decided 2026-08-17, by the user, explicitly) is BOTH modes:

* ``inventory`` — the destination is the management address of an appliance
  SATOM already manages (the callers build the inventory from the visible
  appliances' hosts; pool members are not included). Only a host already in
  that list can be dialled, so there is no forgery surface. Default, one click.
* ``free`` — an arbitrary ``host:port`` typed by the operator. Deliberately
  allowed: the destinations that matter during an incident (a backend not in a
  pool yet, an edge proxy, a partner endpoint) are by definition NOT in the
  inventory, and a tool that cannot reach them sends the operator back to
  ``curl`` on a jump host — where nothing is audited at all. Free mode is gated
  on its own permission and every call is written to the audit trail.

What ``free`` is still not allowed to be:

* **Cloud instance-metadata addresses.** ``169.254.169.254`` and its siblings
  hand credentials to anything that can reach them and have no legitimate use
  from this application. This denial is not configurable.
* **Protocol-reserved space** (unspecified, multicast, reserved). Not a security
  boundary — a correctness one: a probe of ``0.0.0.0`` reports a failure that
  means nothing, and the operator reads it as evidence about their backend.

RFC1918, loopback and link-local ARE allowed on purpose. This whole fleet is
RFC1918, the appliances are RFC1918, and SATOM probing its own node is a
legitimate diagnostic. "Block private ranges" is the standard SSRF advice and it
would block this product's actual job; the inventory/free split plus the
metadata denial is what carries the weight instead.

Two limits on that, in EVERY mode:

* **The node's own unauthenticated services.** The metrics store
  (VictoriaMetrics, no auth, admin endpoints that delete series), the database
  and the bare application server listen on loopback precisely because nothing
  but this process may talk to them. :data:`NODE_INTERNAL_PORTS` on a loopback
  address, and the configured metrics-store endpoint wherever it lives (the
  container stack runs it as a sibling service), are never dialled.
* **Probes that run unattended or for read-only users** (monitor probes, the
  network-architecture live view, process HTTP checks) pass
  ``allow_loopback=False``: a probe of the node itself has no diagnostic value
  there and every request it can make is one an operator never sees.

Inventory mode matches ``(host, port)`` pairs when the caller supplies them: a
managed appliance's address is an authorisation to reach ITS management port,
not every port on that machine.

**The name is resolved ONCE here and the caller connects to the RESOLVED
ADDRESS**, carrying the hostname separately as SNI/Host. A guard that resolves a
name, approves it, and hands the NAME back is checking a different request from
the one that gets sent: the second lookup can answer differently (DNS
rebinding). Returning the address is what makes the check binding — every caller
in this codebase connects to ``result['ip']``.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

#: Modes. ``inventory`` needs no extra permission; ``free`` does.
MODE_INVENTORY = "inventory"
MODE_FREE = "free"
MODES = (MODE_INVENTORY, MODE_FREE)

#: The permission a caller must hold to use :data:`MODE_FREE`.
FREE_PERMISSION = "monitoring.probe_free"

#: Instance-metadata endpoints. Reachable from a VM, credential-bearing, and
#: never a legitimate SATOM destination. Not configurable, by design.
METADATA_ADDRS = (
    "169.254.169.254",      # AWS / Azure / GCP / DO / OpenStack
    "169.254.170.2",        # AWS ECS task role
    "100.100.100.200",      # Alibaba Cloud
    "192.0.0.192",          # Oracle Cloud (legacy)
    "fd00:ec2::254",        # AWS IMDS over IPv6
)

#: Ports SATOM will never dial, in any mode. These are not HTTP/TLS and a
#: "probe" of them is either a protocol-confusion attack against an internal
#: service or a mistake that produces a meaningless error.
DENIED_PORTS = (0, 22, 25, 465, 587, 6379, 11211)

#: Ports this node serves on loopback for itself only: PostgreSQL, the
#: application server behind nginx, and the unauthenticated metrics store
#: (``deploy/satom.service``, ``deploy/satom-metrics.service``). Refused on any
#: loopback address in every mode.
NODE_INTERNAL_PORTS = (5432, 8000, 8428)

_MAX_PORT = 65535


class TargetError(ValueError):
    """A destination that will not be dialled, with an operator-readable why."""


# --------------------------------------------------------------------------- #
#  Parsing                                                                     #
# --------------------------------------------------------------------------- #
_BRACKET_RX = re.compile(r"^\[(?P<h>[^\]]+)\](?::(?P<p>\d+))?$")


def parse_target(text: str, default_port: int = 443) -> dict:
    """Split operator input into ``{scheme, host, port, path}``.

    Accepts the four shapes an operator actually pastes: a bare host, a
    ``host:port``, a ``[v6]:port``, and a full URL (which is what they copy out
    of a browser or a ticket). Returning the path matters for the tracer — an
    operator who pastes ``https://shop/checkout`` means that path, and dropping
    it silently makes the tool trace the wrong request.
    """
    raw = str(text or "").strip()
    if not raw:
        raise TargetError("empty target")
    scheme = ""
    path = ""
    if "://" in raw:
        parts = urlsplit(raw)
        scheme = (parts.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise TargetError("only http:// and https:// targets are supported")
        netloc = parts.netloc
        path = parts.path or "/"
        if parts.query:
            path = path + "?" + parts.query
        if "@" in netloc:
            # Credentials in the authority are how a URL is made to LOOK like it
            # points at one host while dialling another. Refuse rather than pick.
            raise TargetError("credentials in the URL authority are not accepted")
        raw = netloc
    if not raw:
        raise TargetError("no host in target")

    m = _BRACKET_RX.match(raw)
    if m:
        host = m.group("h")
        port_s = m.group("p")
    elif raw.count(":") > 1:
        # A bare IPv6 literal with no brackets: no port can be present.
        host, port_s = raw, None
    elif ":" in raw:
        host, port_s = raw.rsplit(":", 1)
    else:
        host, port_s = raw, None

    host = host.strip().rstrip(".")
    if not host:
        raise TargetError("no host in target")
    if port_s:
        if not port_s.isdigit():
            raise TargetError("port %r is not a number" % port_s)
        port = int(port_s)
    elif scheme == "http":
        port = 80
    else:
        port = int(default_port)
    if port < 1 or port > _MAX_PORT:
        raise TargetError("port %d is out of range" % port)
    return {"scheme": scheme or ("http" if port == 80 else "https"),
            "host": host, "port": port, "path": path}


# --------------------------------------------------------------------------- #
#  Address policy                                                              #
# --------------------------------------------------------------------------- #
def denial_reason(ip: str) -> str:
    """Why this ADDRESS will not be dialled, or ``''`` when it is acceptable.

    Takes an address, never a name: this is the check that runs after
    resolution, on the thing that will actually be connected to.
    """
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return "not an IP address"
    # ``ipv4_mapped`` exists only on IPv6Address. An IPv4-mapped v6 literal
    # (``::ffff:169.254.169.254``) is the same destination wearing a different
    # spelling, so it has to be unwrapped before the comparison — checking only
    # the literal text is a denial one ``::ffff:`` prefix wide.
    mapped = getattr(addr, "ipv4_mapped", None)
    if str(addr) in METADATA_ADDRS or (mapped is not None
                                       and str(mapped) in METADATA_ADDRS):
        return ("cloud instance-metadata address — it serves credentials to "
                "anything that can reach it, so SATOM never dials it")
    if addr.is_unspecified:
        return "unspecified address (0.0.0.0/::) is not a destination"
    if addr.is_multicast:
        return "multicast address is not a destination"
    # Loopback and link-local are checked BEFORE ``is_reserved`` and allowed.
    # In Python's IPv6 tables ``::1`` sits inside the reserved ``::/8`` block,
    # so an is_reserved test placed first refuses IPv6 loopback — and probing
    # this node's own listener is a first-class use of both tools. Measured:
    # ``ipaddress.ip_address('::1').is_reserved`` is True on 3.11.
    if addr.is_loopback or addr.is_link_local:
        return ""
    if addr.is_reserved:
        return "reserved address is not a destination"
    return ""


def port_denial_reason(port: int) -> str:
    try:
        p = int(port)
    except (TypeError, ValueError):
        return "port is not a number"
    if p in DENIED_PORTS:
        return ("port %d is not an HTTP/TLS port — dialling it from the server "
                "cannot produce a meaningful result" % p)
    return ""


def _metrics_store_endpoints() -> set[tuple[str, int]]:
    """``(address, port)`` of the configured metrics store, resolved.

    On a host install this is ``127.0.0.1:8428`` and the loopback rule already
    covers it; in the container stack it is a sibling service on the bridge
    network, which the loopback rule cannot see. Best effort: a store that
    cannot be named or resolved here cannot be reached through it either.
    """
    out: set[tuple[str, int]] = set()
    try:
        from . import vm_store
        parts = urlsplit(vm_store.base_url())
        host = (parts.hostname or "").rstrip(".").lower()
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except Exception:  # noqa: BLE001 — no store configured, nothing to protect
        return out
    if not host:
        return out
    out.add((host, port))
    try:
        ipaddress.ip_address(host)
        return out
    except ValueError:
        pass
    try:
        for *_rest, sa in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP):
            out.add((str(sa[0]).lower(), port))
    except (OSError, UnicodeError):
        pass
    return out


def node_denial_reason(ip: str, port: int, *, allow_loopback: bool = True) -> str:
    """Why this ADDRESS and PORT reach this node's own services, or ``''``.

    Applies in every mode. ``allow_loopback=False`` refuses loopback outright
    (probe-type callers); otherwise only :data:`NODE_INTERNAL_PORTS` on
    loopback and the configured metrics-store endpoint are refused.
    """
    try:
        addr = ipaddress.ip_address(str(ip))
        p = int(port)
    except (TypeError, ValueError):
        return "not an IP address"
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    if addr.is_loopback:
        if not allow_loopback:
            return ("loopback address — this probe never dials the SATOM node "
                    "itself")
        if p in NODE_INTERNAL_PORTS:
            return ("port %d on loopback is one of this node's internal "
                    "services — SATOM never dials it on an operator's behalf" % p)
    if (str(addr).lower(), p) in _metrics_store_endpoints():
        return ("this node's metrics store — it has no authentication of its "
                "own, so SATOM never dials it on an operator's behalf")
    return ""


# --------------------------------------------------------------------------- #
#  Resolution (the binding step)                                               #
# --------------------------------------------------------------------------- #
def _lookup(host: str, port: int) -> list[tuple[int, str]]:
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetError("cannot resolve %s (%s)" % (host, exc.strerror or exc)) from None
    out: list[tuple[int, str]] = []
    seen: set[str] = set()
    for fam, _st, _pr, _cn, sa in infos:
        ip = sa[0]
        if ip not in seen:
            seen.add(ip)
            out.append((fam, ip))
    return out


def _inventory_allows(host: str, port: int, inventory_hosts) -> bool:
    """``inventory_hosts`` holds bare hosts (any port) and/or ``(host, port)``
    pairs (that port only)."""
    key = host.lower()
    for entry in inventory_hosts or ():
        if isinstance(entry, (tuple, list)):
            if len(entry) != 2 or not entry[0]:
                continue
            try:
                pair = (str(entry[0]).strip().lower().rstrip("."), int(entry[1]))
            except (TypeError, ValueError):
                continue
            if pair == (key, port):
                return True
        elif entry and str(entry).strip().lower().rstrip(".") == key:
            return True
    return False


def resolve_target(host: str, port: int, *, mode: str = MODE_INVENTORY,
                   inventory_hosts=(), allow_loopback: bool = True) -> dict:
    """Resolve and authorise one destination.

    Returns ``{host, port, ip, family, mode, addresses}``. ``ip`` is what the
    caller MUST connect to; ``host`` is what it must send as SNI / ``Host``.

    ``inventory_hosts`` entries are bare hosts or ``(host, port)`` pairs; a
    pair authorises that port only. ``allow_loopback=False`` refuses every
    loopback answer (see :func:`node_denial_reason`).

    Raises :class:`TargetError` — the caller turns it into a 400 with the text
    verbatim, because "why did SATOM refuse this" is a question the operator
    can only answer if the refusal says so.
    """
    if mode not in MODES:
        raise TargetError("unknown target mode %r" % mode)
    host = str(host or "").strip().rstrip(".")
    if not host:
        raise TargetError("empty host")
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise TargetError("port is not a number") from None

    if mode == MODE_INVENTORY and not _inventory_allows(host, port, inventory_hosts):
        raise TargetError(
            "%s:%d is not in the inventory for this request. Switch the tool to "
            "free-target mode to dial a host or port SATOM does not manage."
            % (host, port))

    perr = port_denial_reason(port)
    if perr:
        raise TargetError(perr)

    addresses = _lookup(host, port)
    if not addresses:
        raise TargetError("cannot resolve %s" % host)

    # EVERY answer must be acceptable, not just the one we pick. A name that
    # resolves to a metadata address and a real one is a rebinding attempt, and
    # taking the first acceptable answer is exactly the bug the attempt targets.
    for _fam, ip in addresses:
        why = denial_reason(ip) or node_denial_reason(
            ip, port, allow_loopback=allow_loopback)
        if why:
            raise TargetError("%s resolves to %s — %s" % (host, ip, why))

    fam, ip = addresses[0]
    return {"host": host, "port": port, "ip": ip, "family": fam,
            "mode": mode, "addresses": [a for _f, a in addresses]}


__all__ = [
    "MODE_INVENTORY", "MODE_FREE", "MODES", "FREE_PERMISSION",
    "METADATA_ADDRS", "DENIED_PORTS", "NODE_INTERNAL_PORTS", "TargetError",
    "parse_target", "denial_reason", "port_denial_reason", "node_denial_reason",
    "resolve_target",
]
