"""hostguard -- a server SATOM manages can never open a connection TO SATOM.

Plugin Studio "server" connections are always dialled by SATOM (SSH to
satom-webctl). The other direction must not exist: a script that goes wrong
on a managed web server -- or whoever controls that server -- must not be able
to reach the SATOM console, its API or its SSH. Nothing on the server holds a
credential of SATOM's, and on top of that both nodes DROP every new
connection coming from a managed server (replies to the connections SATOM
opens are established traffic and still pass).

Who does what:

* this module (the app, unprivileged) resolves the hosts of every server
  connection and writes ``data/hostguard/desired.json`` -- on every
  create/save/delete of a server connection, and once after a boot;
* ``satom-hostguard.path`` sees the file change and starts the privileged
  runner (``satom-updater.service``), which validates the list, never blocks
  this node, the HA peer, the default gateway or the trusted proxies, and
  loads it into its own nftables table ``inet satom_hostguard``;
* the runner reports what it applied in ``/run/satom-hostguard.json``
  (``status()``). /run is emptied by a reboot -- exactly when the kernel rules
  are gone too -- so a missing status file is the signal to publish again.

A reverse proxy in front of SATOM is another source address, so the same
list is enforced at the HTTP layer too (:func:`install_http_gate`): a
request whose forwarded client is a managed server is refused before any
other gate.

On the standby, ``data/`` arrives from the primary every 5 minutes
(satom-ha-datasync), the same path unit fires, and the standby blocks the same
servers.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path

APP_DIR = Path(os.environ.get("FM_APP_DIR") or Path(__file__).resolve().parents[2])
DESIRED = APP_DIR / "data" / "hostguard" / "desired.json"
STATUS = Path(os.environ.get("SATOM_HOSTGUARD_STATUS", "/run/satom-hostguard.json"))
MAX_ADDRESSES = 4096


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    out = []
    for info in infos:
        ip = str(info[4][0]).split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        mapped = getattr(addr, "ipv4_mapped", None)
        ip = str(mapped or addr)
        if ip not in out:
            out.append(ip)
    return out


def desired() -> dict:
    """``{"addresses": [...], "unresolved": [...], "servers": n}`` from the
    server connections in the database. The runner re-checks everything; this
    only says which servers SATOM manages."""
    from . import studio_connections as SC
    addrs, unresolved = [], []
    conns = SC.list_connections("server")
    for c in conns:
        host = (c.host or "").strip()
        if not host:
            continue
        ips = _resolve(host)
        if not ips:
            unresolved.append(c.slug)
        for ip in ips:
            if ip not in addrs:
                addrs.append(ip)
    return {"addresses": sorted(addrs)[:MAX_ADDRESSES], "unresolved": sorted(unresolved),
            "servers": len(conns)}


def _read(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def publish(force: bool = False) -> bool:
    """Write the desired list when it changed (or ``force``). True when the
    file was written -- which is what wakes the runner."""
    want = desired()
    cur = _read(DESIRED)
    if (not force and isinstance(cur, dict) and cur.get("addresses") == want["addresses"]
            and cur.get("unresolved") == want["unresolved"]):
        return False
    body = dict(want, version=1,
                at=datetime.now(timezone.utc).replace(microsecond=0).isoformat())
    DESIRED.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".desired-", dir=str(DESIRED.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(body, fh, sort_keys=True, indent=1)
        os.chmod(tmp, 0o644)
        os.replace(tmp, DESIRED)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def status() -> dict:
    """What the runner applied on THIS node, as it reported it; ``{}`` when it
    has not run since boot."""
    st = _read(STATUS)
    return st if isinstance(st, dict) else {}


def boot_publish() -> None:
    """After a reboot /run is empty and the kernel table is gone: write the
    desired list once so the runner reloads it. Cheap when nothing to do."""
    try:
        if STATUS.exists():
            return
        from . import studio_connections as SC
        if not SC.list_connections("server") and not DESIRED.exists():
            return
        publish(force=True)
    except Exception:  # noqa: BLE001 -- never blocks the app from starting
        pass


def summary() -> dict:
    """For the connection page and health: desired vs applied here."""
    want = _read(DESIRED) or {}
    st = status()
    applied = set(st.get("applied") or [])
    missing = [a for a in (want.get("addresses") or []) if a not in applied
               and a not in {e.get("ip") for e in st.get("excluded") or []}]
    return {"desired": want.get("addresses") or [], "unresolved": want.get("unresolved") or [],
            "applied": sorted(applied), "excluded": st.get("excluded") or [],
            "ok": bool(st.get("ok")) and not missing, "missing": missing,
            "at": st.get("at") or "", "detail": st.get("detail") or "",
            "ran": bool(st)}


# --------------------------------------------------------------------------- #
#  the same rule at the HTTP layer                                             #
# --------------------------------------------------------------------------- #
# The kernel rules stop a managed server from opening a connection to a SATOM
# node. A reverse proxy in front of SATOM (the fleet edge, a customer's load
# balancer) is a different source address -- and must stay reachable for
# everyone else -- so a request a managed server sends THROUGH it reaches the
# app. Here it stops: the client address the trusted proxies forwarded
# (extensions.real_client_ip) is compared with the same list, and the request
# is refused before any other gate runs -- no login page, no API, nothing.
_HTTP_CACHE: dict = {"mtime": None, "ips": frozenset()}


def blocked_addresses() -> frozenset:
    """The managed servers' addresses from desired.json, re-read when it
    changes."""
    try:
        mtime = DESIRED.stat().st_mtime
    except OSError:
        _HTTP_CACHE.update(mtime=None, ips=frozenset())
        return frozenset()
    if mtime != _HTTP_CACHE["mtime"]:
        body = _read(DESIRED)
        ips = set()
        for raw in (body.get("addresses") if isinstance(body, dict) else None) or []:
            try:
                addr = ipaddress.ip_address(str(raw))
            except ValueError:
                continue
            ips.add(str(getattr(addr, "ipv4_mapped", None) or addr))
        _HTTP_CACHE.update(mtime=mtime, ips=frozenset(ips))
    return _HTTP_CACHE["ips"]


def http_refused(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return False
    return str(getattr(addr, "ipv4_mapped", None) or addr) in blocked_addresses()


_LAST_LOG: dict = {}


def install_http_gate(app) -> None:
    """Refuse every request whose client is a managed server -- FIRST, before
    the session, the login page or any other gate."""
    import time
    from flask import Response

    def _hostguard_gate():
        if app.config.get("TESTING") and not app.config.get("HOSTGUARD_PUBLISH"):
            return None
        from ..extensions import real_client_ip
        ip = real_client_ip()
        if not ip or not http_refused(ip):
            return None
        now = time.monotonic()
        if now - _LAST_LOG.get(ip, -1e9) > 60:
            _LAST_LOG[ip] = now
            app.logger.warning("hostguard: refused a request from managed server %s", ip)
        return Response("Forbidden\n", status=403, mimetype="text/plain")

    app.before_request_funcs.setdefault(None, []).insert(0, _hostguard_gate)
