"""The syslog / CEF feed — the alert engine's *record*, not a recipient.

Why this is a first-class sink and not a hook
---------------------------------------------
The integration-hook runner would happily open a socket, but then every
operator writes their own RFC 5424 header and their own CEF escaping, and gets
one of them wrong.  Wire framing is a property of the product, not of the
customer's script: an unescaped ``|`` inside an alert title truncates the CEF
header at the collector and the event lands mangled or not at all.

Why it does NOT carry the cooldown
-----------------------------------
``alerts.run`` suppresses a repeated finding for ``alerts.cooldown_hours`` so a
persistent condition does not mail every quarter hour.  That is right for a
*notification* and wrong for a *record*.  A FortiAnalyzer is queried after the
fact: "was fw08 unreachable at 03:10?".  If the feed inherits a 6-hour
cooldown, the answer is a hole, and a hole reads exactly like "it was fine".
Correlation, retention and audit all assume a complete series, so this sink
emits **every evaluation, for every matching finding** — repetition included.

Consequences worth stating out loud, because they are visible in the field:

* A standing warning produces one event per engine run.  That is what a device
  syslog stream does too; collectors deduplicate, gaps cannot be reconstructed.
* This sink runs on a **read-only standby as well**.  It writes no state, so
  the replica guard that (correctly) stops email and the bell does not apply —
  and without it the standby's own cert, host and reachability findings would
  never leave the node at all.  Both nodes stamp their hostname, so a two-node
  fleet reads as two sources rather than as duplicates.

Not implemented, deliberately
-----------------------------
TLS transport (``syslog-tls``) and the LEEF encoding.  Both are real asks; both
need configuration surface of their own and neither blocks a FortiAnalyzer,
which ingests UDP/TCP syslog and CEF as shipped here.
"""
from __future__ import annotations

import socket
from datetime import datetime, timezone

from ..models import AppSetting
from ..version import app_version
from . import alert_routing as routing

K_HOST = "alerts.syslog.host"
K_PORT = "alerts.syslog.port"
K_PROTO = "alerts.syslog.proto"        # "udp" | "tcp"
K_FORMAT = "alerts.syslog.format"      # "rfc5424" | "cef"
K_FACILITY = "alerts.syslog.facility"  # local0..local7

PROTOCOLS = ("udp", "tcp")
FORMATS = ("rfc5424", "cef")
FACILITIES = {
    "user": 1, "daemon": 3, "auth": 4, "syslog": 5, "authpriv": 10,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

# RFC 5424 numeric severities.  A SATOM "critical" is an operational error, not
# a machine-is-on-fire emergency — err(3) is the honest level; claiming
# emerg(0) trains a NOC to ignore the field.
_SYSLOG_SEV = {routing.SEV_CRITICAL: 3, routing.SEV_WARNING: 4,
               routing.SEV_INFO: 6}
# ArcSight CEF uses 0-10.
_CEF_SEV = {routing.SEV_CRITICAL: 9, routing.SEV_WARNING: 6,
            routing.SEV_INFO: 3}

# IANA-reserved "for documentation/example use" private enterprise number.
# Vision EBC holds no registered PEN; inventing someone else's would make the
# structured-data block a false claim about who defined these fields.
_PEN = "32473"

_VENDOR = "Vision EBC"
_PRODUCT = "SATOM"
_TIMEOUT = 3.0


def _get(key: str, default: str = "") -> str:
    v = AppSetting.get(key)
    return default if v is None else str(v).strip()


def config() -> dict:
    proto = _get(K_PROTO, "udp").lower()
    fmt = _get(K_FORMAT, "rfc5424").lower()
    fac = _get(K_FACILITY, "local0").lower()
    try:
        port = int(_get(K_PORT, "514") or 514)
    except ValueError:
        port = 514
    return {
        "host": _get(K_HOST),
        "port": max(1, min(65535, port)),
        "proto": proto if proto in PROTOCOLS else "udp",
        "format": fmt if fmt in FORMATS else "rfc5424",
        "facility": fac if fac in FACILITIES else "local0",
    }


def save(form) -> None:
    def g(key, default=""):
        try:
            return (form.get(key, default) or "").strip()
        except AttributeError:
            return str(form.get(key, default) or "").strip()

    AppSetting.set(K_HOST, g("syslog_host"))
    try:
        port = int(g("syslog_port") or 514)
    except ValueError:
        port = 514
    AppSetting.set(K_PORT, str(max(1, min(65535, port))))
    proto = g("syslog_proto").lower()
    AppSetting.set(K_PROTO, proto if proto in PROTOCOLS else "udp")
    fmt = g("syslog_format").lower()
    AppSetting.set(K_FORMAT, fmt if fmt in FORMATS else "rfc5424")
    fac = g("syslog_facility").lower()
    AppSetting.set(K_FACILITY, fac if fac in FACILITIES else "local0")


# ---- framing --------------------------------------------------------------
def _one_line(value) -> str:
    """Collapse a finding's detail onto one line.

    Both encodings are line-delimited on the wire: an embedded newline does not
    produce a prettier event, it produces a second, headerless, unparseable
    one.
    """
    return " ".join(str(value or "").split())


def _sd_escape(value: str) -> str:
    """RFC 5424 §6.3.3 — escape ``\\``, ``"`` and ``]`` inside PARAM-VALUE."""
    out = str(value or "")
    for ch in ("\\", '"', "]"):
        out = out.replace(ch, "\\" + ch)
    return out


def _cef_header_escape(value: str) -> str:
    """CEF header fields: ``\\`` and ``|`` are the separators."""
    return str(value or "").replace("\\", "\\\\").replace("|", "\\|")


def _cef_ext_escape(value: str) -> str:
    """CEF extension values: ``\\`` and ``=`` end a key/value pair."""
    return str(value or "").replace("\\", "\\\\").replace("=", "\\=")


def _rfc5424(finding: dict, cfg: dict, node: str, ts: datetime) -> str:
    sev = finding.get("severity") or routing.SEV_INFO
    pri = FACILITIES[cfg["facility"]] * 8 + _SYSLOG_SEV.get(sev, 6)
    family = routing.family_of(finding.get("key", ""))
    stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    sd = ('[satom@%s key="%s" severity="%s" family="%s" node="%s"]'
          % (_PEN, _sd_escape(finding.get("key", "")), _sd_escape(sev),
             _sd_escape(family), _sd_escape(node)))
    body = _one_line(finding.get("title"))
    detail = _one_line(finding.get("detail"))
    if detail:
        body = "%s - %s" % (body, detail)
    # MSGID is the family: <= 32 printable ASCII, and it is the field a
    # collector can filter on without parsing structured data.
    return "<%d>1 %s %s %s - %s %s %s" % (
        pri, stamp, node or "-", _PRODUCT, family, sd, body)


def _cef(finding: dict, cfg: dict, node: str, ts: datetime) -> str:
    sev = finding.get("severity") or routing.SEV_INFO
    pri = FACILITIES[cfg["facility"]] * 8 + _SYSLOG_SEV.get(sev, 6)
    family = routing.family_of(finding.get("key", ""))
    # CEF is carried over syslog; a bare "CEF:0|..." with no header is accepted
    # by some collectors and silently dropped by others.
    # The RFC 3164 header CEF rides on has NO timezone field. A collector
    # reads it as the sender's local time, so emitting UTC files every event
    # at the wrong hour — silently, and only for installs that are not on UTC.
    # Local time here, and an unambiguous epoch in ``rt`` for anything that
    # prefers to be told rather than to assume.
    local = ts.astimezone()
    header = "<%d>%s%2d %s %s " % (pri, local.strftime("%b "), local.day,
                                   local.strftime("%H:%M:%S"), node or "-")
    cef = "CEF:0|%s|%s|%s|%s|%s|%d|" % (
        _cef_header_escape(_VENDOR), _cef_header_escape(_PRODUCT),
        _cef_header_escape(app_version()),
        _cef_header_escape(finding.get("key", "")),
        _cef_header_escape(_one_line(finding.get("title"))),
        _CEF_SEV.get(sev, 3))
    ext = "rt=%d dvchost=%s cat=%s msg=%s" % (
        int(ts.timestamp() * 1000), _cef_ext_escape(node),
        _cef_ext_escape(family), _cef_ext_escape(_one_line(finding.get("detail"))))
    return header + cef + ext


def format_line(finding: dict, cfg: dict, node: str,
                ts: datetime | None = None) -> str:
    ts = ts or datetime.now(timezone.utc)
    if cfg.get("format") == "cef":
        return _cef(finding, cfg, node, ts)
    return _rfc5424(finding, cfg, node, ts)


# ---- transport ------------------------------------------------------------
def _send(lines: list, cfg: dict) -> dict:
    """Best-effort delivery.  Never raises: a collector that is down must not
    take the email path down with it."""
    sent = 0
    try:
        if cfg["proto"] == "tcp":
            with socket.create_connection((cfg["host"], cfg["port"]),
                                          timeout=_TIMEOUT) as sock:
                # RFC 6587 non-transparent framing — the LF-delimited form
                # every syslog collector in this fleet already accepts.
                for line in lines:
                    sock.sendall((line + "\n").encode("utf-8"))
                    sent += 1
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(_TIMEOUT)
            try:
                for line in lines:
                    sock.sendto(line.encode("utf-8"),
                                (cfg["host"], cfg["port"]))
                    sent += 1
            finally:
                sock.close()
    except Exception as exc:  # noqa: BLE001 — reported, never propagated
        return {"ok": False, "sent": sent, "target": _target(cfg),
                "detail": "%s: %s" % (type(exc).__name__, exc)}
    return {"ok": True, "sent": sent, "target": _target(cfg)}


def _target(cfg: dict) -> str:
    return "%s:%s/%s %s" % (cfg.get("host") or "-", cfg.get("port"),
                            cfg.get("proto"), cfg.get("format"))


def emit(findings: list, node: str, *, dry_run: bool = False) -> dict | None:
    """Push every matching finding to the collector.

    Returns ``None`` when the sink is off — a caller must be able to tell
    "disabled" from "enabled and delivered nothing", because only the second
    one is a problem.
    """
    if not routing.is_enabled(routing.SINK_SYSLOG):
        return None
    cfg = config()
    selected = routing.route(findings, routing.SINK_SYSLOG)
    if not cfg["host"]:
        return {"ok": False, "sent": 0, "matched": len(selected),
                "target": _target(cfg),
                "detail": "sink enabled but no collector host configured"}
    lines = [format_line(f, cfg, node) for f in selected]
    if dry_run:
        return {"ok": True, "sent": 0, "matched": len(selected),
                "target": _target(cfg), "dry_run": True, "sample": lines[:3]}
    if not lines:
        return {"ok": True, "sent": 0, "matched": 0, "target": _target(cfg),
                "detail": "nothing matched this sink's filter"}
    res = _send(lines, cfg)
    res["matched"] = len(selected)
    return res


__all__ = ["config", "save", "emit", "format_line", "FORMATS", "PROTOCOLS",
           "FACILITIES"]
