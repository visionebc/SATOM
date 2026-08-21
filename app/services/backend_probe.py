"""Backend reachability — does the cloned policy actually reach its servers?

A cloned policy can be perfect and still serve nothing, because the real servers
behind it sit on a network the NEW appliance cannot reach. Every other check in
:mod:`clone` asks "did the configuration arrive?"; this one asks the only
question the operator has after that, and it is a different question.

TWO VANTAGES, NEVER MERGED INTO ONE WORD
    * The DESTINATION APPLIANCE, over the CLI (``execute ping``) — the only
      vantage whose answer decides whether the copied policy serves anything,
      and the only one that needs SSH credentials.
    * THIS NODE, over TCP to the member's real port — always available, and the
      only probe that tells "host up, port shut" apart from "host unreachable".

They are reported side by side and never collapsed. ICMP being blocked is not a
backend being down, and a refused TCP connection proves the host is UP.

A backend nobody could probe is reported ``not probed``. It is NEVER reported
reachable and never reported down: a probe that failed, rendered as an outage,
is how a reachability check manufactures a false alarm — and rendered as health
it is how a real outage gets signed off.

READ BACK FROM THE BOX, NOT FROM THE PLAN
    :func:`dst_pool_targets` asks the DESTINATION which servers it has. The plan
    says what was asked for; the appliance says what is there. A reachability
    report built on the plan would happily describe a backend that the write
    silently dropped.
"""
from __future__ import annotations

import re
import socket
import time
from typing import Iterable

from urllib.parse import quote

#: A backend address safe to interpolate into a CLI command. Deliberately NOT
#: the certificate-name validator: that one rejects ``:``, which every IPv6
#: address contains, and its refusal reads "invalid certificate name" — a
#: message that sends the reader looking in entirely the wrong place.
_PROBE_TARGET_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:\-]{0,252})$")


class ProbeRefused(Exception):
    """An address that will not be interpolated into a command."""


def assert_probe_target(target: str) -> str:
    """Return ``target`` if it is a hostname / IPv4 / IPv6, else raise."""
    target = (target or "").strip()
    if not _PROBE_TARGET_RE.match(target) or ".." in target:
        raise ProbeRefused(
            "refusing to probe %r — a backend address here is a hostname, an "
            "IPv4 or an IPv6 address" % target)
    return target


# --------------------------------------------------------------------------- #
#  Pure parsing — testable without an appliance                                 #
# --------------------------------------------------------------------------- #
def parse_ping(text: str) -> dict:
    """Read ``execute ping`` output → ``{replied, loss, rtt_ms, verdict, detail}``.

    ``verdict`` is one of ``alive`` | ``no reply`` | ``unresolved`` |
    ``cli error`` | ``no answer``.

    The last one is NOT ``no reply``. Output this parser could not read means the
    PROBE failed, and a probe that failed must never be rendered as a backend
    that is down.
    """
    body = (text or "").replace("\r", "")
    if re.search(r"Parsing error|Command fail|Unknown action|not permitted",
                 body, re.I):
        return {"replied": False, "loss": None, "rtt_ms": None,
                "verdict": "cli error",
                "detail": "the appliance refused the ping command"}
    if re.search(r"unknown host|cannot resolve|Name or service not known",
                 body, re.I):
        return {"replied": False, "loss": None, "rtt_ms": None,
                "verdict": "unresolved",
                "detail": "the appliance could not resolve the name"}
    loss = None
    m = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", body, re.I)
    if m:
        loss = float(m.group(1))
    rtt = None
    m = re.search(r"round-trip min/avg/max\s*=\s*[\d.]+/([\d.]+)/", body, re.I)
    if m:
        rtt = float(m.group(1))
    else:
        m = re.search(r"time[=<]\s*([\d.]+)\s*ms", body, re.I)
        if m:
            rtt = float(m.group(1))
    if loss is None:
        return {"replied": False, "loss": None, "rtt_ms": rtt,
                "verdict": "no answer",
                "detail": "the ping produced no statistics line — timed out, or "
                          "the output was cut. This is NOT evidence the backend "
                          "is down"}
    if loss >= 100:
        return {"replied": False, "loss": loss, "rtt_ms": rtt,
                "verdict": "no reply",
                "detail": "100% packet loss from the appliance"}
    return {"replied": True, "loss": loss, "rtt_ms": rtt, "verdict": "alive",
            "detail": "%g%% loss%s" % (loss, ", %.1f ms" % rtt if rtt else "")}


def tcp_check(host: str, port, timeout: float = 3.0) -> dict:
    """One TCP handshake from THIS node → ``{ok, verdict, detail}``.

    ``refused`` is kept apart from ``timeout`` on purpose: a refusal PROVES the
    host is up and answering, which is a completely different operational
    problem from a host that is not there at all.
    """
    try:
        port = int(port)
    except (TypeError, ValueError):
        return {"ok": False, "verdict": "no port",
                "detail": "the member row carries no usable port"}
    host = (host or "").strip()
    if not host or port <= 0 or port > 65535:
        return {"ok": False, "verdict": "no port",
                "detail": "no address/port to connect to"}
    t0 = time.time()
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return {"ok": True, "verdict": "open",
                "detail": "TCP connect in %d ms" % int((time.time() - t0) * 1000)}
    except ConnectionRefusedError:
        return {"ok": False, "verdict": "refused",
                "detail": "the host answered and refused the port — it is UP"}
    except socket.timeout:
        return {"ok": False, "verdict": "timeout",
                "detail": "no answer within %gs" % timeout}
    except OSError as exc:  # noqa: BLE001 — DNS, no route, address family
        return {"ok": False, "verdict": "unreachable", "detail": str(exc)}


def backend_ports(row: dict) -> list:
    """Which port(s) a real-server row actually listens on.

    Measured on 7.6.8: a member always carries ``port`` PLUS ``http-port`` and
    ``https-port``, and the last two only mean anything when
    ``http-https-adaptive`` is enabled. Probing all three unconditionally would
    report a perfectly healthy member as two-thirds unreachable.
    """
    if str(row.get("http-https-adaptive") or "").strip().lower() == "enable":
        ports: list = []
        for key in ("http-port", "https-port"):
            try:
                val = int(row.get(key) or 0)
            except (TypeError, ValueError):
                continue
            if 0 < val <= 65535 and val not in ports:
                ports.append(val)
        if ports:
            return ports
    try:
        val = int(row.get("port") or 0)
    except (TypeError, ValueError):
        val = 0
    return [val] if 0 < val <= 65535 else []


def backend_targets(rows: Iterable[dict], *, policy: str = "",
                    pool: str = "") -> list:
    """Real-server rows → probe targets. Pure, so it is testable without a box.

    A member with ``status: disable`` is carried through as ``enabled: False``
    rather than dropped. A pool whose every member is disabled is a FINDING, and
    a silently shorter list looks like a pool with fewer servers.
    """
    out: list = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        stype = str(row.get("server-type") or "").strip().lower()
        addr = (str(row.get("domain") or "").strip() if stype == "domain"
                else str(row.get("ip") or "").strip())
        if not addr:
            addr = (str(row.get("ip") or "").strip()
                    or str(row.get("domain") or "").strip())
        for port in (backend_ports(row) or [0]):
            out.append({
                "policy": policy, "pool": pool,
                "seq": str(row.get("seq") or row.get("_id") or row.get("id") or ""),
                "type": stype or "physical",
                "address": addr, "port": port,
                "ssl": str(row.get("ssl") or "").strip().lower() == "enable",
                "enabled": (str(row.get("status") or "enable").strip().lower()
                            != "disable"),
            })
    return out


_PREFIX = "/api/v2.0/cmdb/"


def _rows(client, path: str) -> list:
    raw = client.get(_PREFIX + path).json()
    res = raw.get("results") if isinstance(raw, dict) else None
    if isinstance(res, list):
        return [r for r in res if isinstance(r, dict)]
    return [res] if isinstance(res, dict) else []


def dst_pool_targets(client, policies: Iterable[str]) -> list:
    """Read the named policies' pools FROM THE DESTINATION, flattened to targets.

    A policy or pool that cannot be read yields a row carrying ``error`` rather
    than being omitted: a shorter list reads as "fewer backends to worry about",
    which is the opposite of what a failed read means.
    """
    out: list = []
    try:
        pols = {str(p.get("name") or ""): p
                for p in _rows(client, "server-policy/policy")}
    except Exception as exc:  # noqa: BLE001
        raise ProbeRefused("could not read the destination's policies: %s" % exc)
    for name in policies:
        name = str(name)
        blank = {"policy": name, "pool": "", "seq": "", "type": "",
                 "address": "", "port": 0, "ssl": False, "enabled": True}
        pol = pols.get(name)
        if pol is None:
            out.append(dict(blank,
                            error="the destination does not list this policy"))
            continue
        pool = str(pol.get("server-pool") or "").strip()
        if not pool:
            out.append(dict(blank, error=(
                "the policy names no server pool (deployment mode %r)"
                % str(pol.get("deployment-mode") or ""))))
            continue
        try:
            rows = _rows(client, "server-policy/server-pool/pserver-list?mkey=%s"
                                 % quote(pool, safe=""))
        except Exception as exc:  # noqa: BLE001
            out.append(dict(blank, pool=pool,
                            error="could not read the pool members: %s" % exc))
            continue
        found = backend_targets(rows, policy=name, pool=pool)
        if not found:
            out.append(dict(blank, pool=pool,
                            error="the pool has no real servers"))
            continue
        out.extend(found)
    return out


# --------------------------------------------------------------------------- #
#  Running the probes                                                           #
# --------------------------------------------------------------------------- #
_NOT_PROBED = {"replied": False, "loss": None, "rtt_ms": None,
               "verdict": "not probed",
               "detail": "no vantage was able to test this backend"}


def probe_targets(targets: Iterable[dict], *, ssh_session=None,
                  tcp_timeout: float = 3.0) -> list:
    """Probe every target from both vantages available. Returns enriched rows.

    ``ssh_session`` is an OPEN :class:`ssh_ops.FortiWebReadonlySSH` on the
    DESTINATION, or ``None`` when the operator did not supply SSH — in which
    case the appliance vantage is reported ``not probed``, not assumed.

    Each appliance address is pinged ONCE however many ports it exposes: the
    route to a host does not vary per port, and re-pinging is seconds of an
    operator's wall-clock per duplicate.
    """
    out: list = []
    seen_ping: dict = {}
    for t in targets or []:
        row = dict(t)
        addr = str(row.get("address") or "").strip()
        if row.get("error"):
            row["appliance"] = dict(_NOT_PROBED)
            row["local"] = {"ok": False, "verdict": "not probed",
                            "detail": row["error"]}
            out.append(row)
            continue
        # -- vantage 1: the destination appliance ---------------------------
        if ssh_session is None or not addr:
            row["appliance"] = dict(_NOT_PROBED)
        elif addr in seen_ping:
            row["appliance"] = dict(seen_ping[addr])
        else:
            try:
                raw = ssh_session.run_probe("execute ping %s"
                                            % assert_probe_target(addr))
                res = parse_ping(raw)
            except Exception as exc:  # noqa: BLE001
                res = {"replied": False, "loss": None, "rtt_ms": None,
                       "verdict": "cli error", "detail": str(exc)}
            seen_ping[addr] = res
            row["appliance"] = dict(res)
        # -- vantage 2: this node -------------------------------------------
        row["local"] = (tcp_check(addr, row.get("port"), tcp_timeout) if addr
                        else {"ok": False, "verdict": "not probed",
                              "detail": "the member row carries no address"})
        out.append(row)
    return out


def summarise(rows: Iterable[dict]) -> dict:
    """Counts an operator can act on. ``unknown`` is its own bucket.

    Folding "we could not tell" into either "ok" or "down" is the whole failure
    mode this module exists to avoid, so the summary refuses to do it too.
    """
    total = ok = down = unknown = disabled = 0
    for r in rows or []:
        total += 1
        if not r.get("enabled", True):
            disabled += 1
        app_v = str((r.get("appliance") or {}).get("verdict") or "not probed")
        loc = r.get("local") or {}
        if app_v == "alive" or loc.get("ok"):
            ok += 1
        elif app_v == "no reply" or loc.get("verdict") in ("timeout",
                                                           "unreachable"):
            down += 1
        else:
            unknown += 1
    return {"total": total, "reachable": ok, "unreachable": down,
            "unknown": unknown, "disabled": disabled}
