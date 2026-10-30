"""Syslog receiver — the appliances' own event stream, taken in directly.

Until this module, every log SATOM could reason about arrived through a
FortiAnalyzer (``faz_logs``). A FortiAnalyzer is the right collector for log
*bodies* at scale; what it cannot give a SATOM node is the appliance talking
to it directly — a reboot notice, a failed login, an HA state change — with
no intermediary to be down. This receiver listens for syslog (UDP and TCP,
RFC 3164 and RFC 5424 framing) and turns it into the same two things every
collector produces: series in the metrics store and a status an operator can
read on Monitoring -> Collection.

Rules that are load-bearing:

* **Off by default.** A port that accepts datagrams from the network is a
  decision, not a side effect of an upgrade. ``collector.syslog.enabled`` must
  be switched on, and the page says what it will bind.
* **Only known senders.** A message is attributed to the appliance whose
  management host resolves to the source address; anything else is dropped
  and COUNTED (``satom_syslog_dropped_total{reason="unknown_source"}``) —
  unless the operator listed its network under ``extra_sources``, in which
  case it is kept under its address. Absence of a drop counter is never
  proof of nothing dropped.
* **Never on a standby.** The standby's database is read-only and its
  address is not where appliances send; the listener runs where the role is
  not ``standby`` (a stand-alone install has no role at all and listens).
* **Never blocks the scheduler tick.** The listener is one thread with a
  ``selectors`` loop; the tick only drains counters (:func:`service_tick`),
  it does not wait on the network.
* **What reaches a page is redacted.** The last messages are kept in a
  bounded ring (500) and every line goes through
  :func:`secret_scan.redact` before it is stored — a device that logs a
  secret must not put it on a screen.
* **The web workers never see the socket.** They read the journal this
  module writes (``state/syslog-receiver.json``), the way the metrics peer
  state is read: the listener lives in the scheduler sidecar, not in
  gunicorn's four workers.
* **Port 514 is not this module's to take.** The default is 5514 (no
  privilege needed). Binding 514 needs a port redirect or
  ``AmbientCapabilities=CAP_NET_BIND_SERVICE`` on ``satom-scheduler.service``,
  which lives under ``deploy/`` and is a signed-release change; the user
  guide says so.
"""
from __future__ import annotations

import collections
import ipaddress
import json
import os
import re
import selectors
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

K_ENABLED = "collector.syslog.enabled"
K_BIND_HOST = "collector.syslog.bind_host"
K_BIND_PORT = "collector.syslog.bind_port"
K_TCP = "collector.syslog.tcp"
K_EXTRA = "collector.syslog.extra_sources"

DEFAULTS = {K_ENABLED: "0", K_BIND_HOST: "0.0.0.0", K_BIND_PORT: "5514",
            K_TCP: "1", K_EXTRA: ""}
_TRUE = ("1", "true", "on", "yes", "enabled")

RING_MAX = 500
MAX_MESSAGE = 8192          # RFC 5424 §6.1 recommends ≥ 2048; 8 KiB is generous
MAX_TCP_BUFFER = 1 << 20    # a peer that never frames gets cut off, not grown
MAX_CONNECTIONS = 64
QUEUE_MAX = 20000           # messages waiting for the next tick
SOURCE_REFRESH_S = 300
TEXT_MAX = 300
#: Distinct unknown senders remembered by address. A count without an address
#: answers nothing: on 2026-10-30 the page said "1185 unknown_source" for days
#: while the sender was a device de-registered a week earlier and still pointed
#: at this receiver. Bounded so a scan of the port cannot grow it.
STRANGERS_MAX = 32

SEVERITIES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
FACILITIES = ("kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
              "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
              "local0", "local1", "local2", "local3", "local4", "local5", "local6",
              "local7")

METRIC_UP = "satom_syslog_up"
METRIC_MESSAGES = "satom_syslog_messages_total"
METRIC_DROPPED = "satom_syslog_dropped_total"
METRIC_RECEIVER = "satom_syslog_receiver_up"

STATE_DIR = Path(os.environ.get("SATOM_STATE_DIR") or "/opt/satom/state")
STATE_FILE = STATE_DIR / "syslog-receiver.json"

_PRI = re.compile(r"^<(\d{1,3})>")
_RFC5424 = re.compile(r"^(\d) (\S+) (\S+) (\S+) (\S+) (\S+) (.*)$", re.S)
_RFC3164 = re.compile(r"^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d\d:\d\d:\d\d) (\S+) ?(.*)$", re.S)
_DEVNAME = re.compile(r'\b(?:devname|device_id|devid)="?([^"\s]+)"?')   # FGT: devname, FWB: device_id
_TAG = re.compile(r"^([A-Za-z0-9_./-]+)(?:\[\d+\])?:\s?(.*)$", re.S)
_OCTET_COUNT = re.compile(rb"^(\d{1,5}) ")


# ── configuration ────────────────────────────────────────────────────────────

def _setting(key: str) -> str:
    try:
        from ..models import AppSetting
        v = AppSetting.get(key)
        if v is None or str(v).strip() == "":
            return DEFAULTS[key]
        return str(v).strip()
    except Exception:  # noqa: BLE001 - no DB (or no app context) = defaults
        return DEFAULTS[key]


def parse_sources(raw: str) -> tuple[list, list[str]]:
    """``extra_sources`` text -> (networks, rejected tokens)."""
    nets, bad = [], []
    for tok in re.split(r"[,\s]+", str(raw or "")):
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            bad.append(tok)
    return nets, bad


def config() -> dict:
    enabled = _setting(K_ENABLED).lower() in _TRUE
    try:
        port = int(_setting(K_BIND_PORT))
    except ValueError:
        port = int(DEFAULTS[K_BIND_PORT])
    port = port if 1 <= port <= 65535 else int(DEFAULTS[K_BIND_PORT])
    extra_raw = _setting(K_EXTRA)
    nets, bad = parse_sources(extra_raw)
    return {"enabled": enabled, "bind_host": _setting(K_BIND_HOST) or "0.0.0.0",
            "bind_port": port, "tcp": _setting(K_TCP).lower() in _TRUE,
            "extra_sources": extra_raw, "extra_networks": [str(n) for n in nets],
            "extra_rejected": bad, "privileged_port": port < 1024}


def save_config(form: dict) -> dict:
    """Validate + persist the receiver settings. Returns the new config; raises
    ``ValueError`` with the reason when a value is unusable."""
    from ..models import AppSetting, db
    enabled = str(form.get("enabled", "")).lower() in _TRUE
    host = str(form.get("bind_host", "") or "0.0.0.0").strip()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("bind address must be an IP address (0.0.0.0 = every interface)")
    try:
        port = int(str(form.get("bind_port", "") or DEFAULTS[K_BIND_PORT]).strip())
    except ValueError:
        raise ValueError("port must be a number")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    extra = str(form.get("extra_sources", "") or "").strip()
    _nets, bad = parse_sources(extra)
    if bad:
        raise ValueError("not a network: %s" % ", ".join(bad[:5]))
    tcp = str(form.get("tcp", "")).lower() in _TRUE
    AppSetting.set(K_ENABLED, "1" if enabled else "0")
    AppSetting.set(K_BIND_HOST, host)
    AppSetting.set(K_BIND_PORT, str(port))
    AppSetting.set(K_TCP, "1" if tcp else "0")
    AppSetting.set(K_EXTRA, extra)
    db.session.commit()
    return config()


# ── parsing ──────────────────────────────────────────────────────────────────

def parse_message(raw: bytes) -> dict | None:
    """One syslog message -> ``{facility, severity, host, app, text, ts}``.

    RFC 5424 (``<PRI>1 TS HOST APP PROCID MSGID [SD] MSG``), RFC 3164
    (``<PRI>Mmm dd hh:mm:ss HOST TAG: MSG``) and the Fortinet key=value body
    with or without either header (``devname=`` names the sender). ``None``
    when the bytes are not a syslog message at all.
    """
    if not raw:
        return None
    if len(raw) > MAX_MESSAGE:
        raw = raw[:MAX_MESSAGE]
    text = raw.decode("utf-8", "replace").strip("\x00\r\n ")
    m = _PRI.match(text)
    if not m:
        return None
    pri = int(m.group(1))
    if pri > 191:
        return None
    facility, severity = pri >> 3, pri & 7
    body = text[m.end():]
    host, app, ts = "", "", ""
    m5 = _RFC5424.match(body)
    m3 = _RFC3164.match(body) if not m5 else None
    if m5 and m5.group(1) == "1":
        ts = m5.group(2) if m5.group(2) != "-" else ""
        host = m5.group(3) if m5.group(3) != "-" else ""
        app = m5.group(4) if m5.group(4) != "-" else ""
        msg = m5.group(7)
        # Structured data: skip the bracketed element(s) in front of MSG.
        while msg.startswith("["):
            end = msg.find("]")
            if end < 0:
                break
            msg = msg[end + 1:].lstrip()
        if msg.startswith("- "):
            msg = msg[2:]
        body = msg
    elif m3:
        ts = "%s %s %s" % (m3.group(1), m3.group(2), m3.group(3))
        host = m3.group(4)
        rest = m3.group(5)
        mt = _TAG.match(rest)
        if mt and not rest.startswith(("date=", "time=")):
            app, body = mt.group(1), mt.group(2)
        else:
            body = rest
    dn = _DEVNAME.search(body)
    if dn:
        host = host or dn.group(1)
        app = app or "fortinet"
    return {"facility": FACILITIES[facility] if facility < len(FACILITIES) else str(facility),
            "severity": SEVERITIES[severity], "host": host, "app": app,
            "ts": ts, "text": body.strip()}


def frame_tcp(buf: bytes) -> tuple[list[bytes], bytes]:
    """Split a TCP buffer into complete messages: RFC 6587 octet counting
    (``123 <PRI>...``) or newline framing. Returns ``(messages, remainder)``."""
    out: list[bytes] = []
    while buf:
        m = _OCTET_COUNT.match(buf)
        if m:
            n = int(m.group(1))
            start = m.end()
            if n <= 0 or n > MAX_MESSAGE:
                # Not a sane count: treat the line as newline-framed instead.
                m = None
            elif len(buf) - start < n:
                break
            else:
                out.append(buf[start:start + n])
                buf = buf[start + n:]
                continue
        nl = buf.find(b"\n")
        if nl < 0:
            if len(buf) > MAX_MESSAGE:
                out.append(buf[:MAX_MESSAGE])
                buf = buf[MAX_MESSAGE:]
                continue
            break
        out.append(buf[:nl].rstrip(b"\r"))
        buf = buf[nl + 1:]
    return [m for m in out if m.strip()], buf


# ── the listener ─────────────────────────────────────────────────────────────

class Receiver:
    """UDP + TCP listener on one thread; counters drained by :meth:`flush`."""

    def __init__(self, bind_host: str, bind_port: int, *, tcp: bool = True,
                 sources: dict | None = None, extra_networks=None):
        self.bind_host, self.bind_port, self.tcp = bind_host, int(bind_port), bool(tcp)
        self.sources: dict[str, dict] = dict(sources or {})   # ip -> {name, kind}
        self.extra_networks = list(extra_networks or [])
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sel: selectors.DefaultSelector | None = None
        self._udp = self._tcp_srv = None
        self._conns: dict = {}
        self.started_at = ""
        self.error = ""
        self.counts: dict[tuple, int] = collections.Counter()
        self.dropped: dict[str, int] = collections.Counter()
        self.per_device: dict[str, dict] = {}
        self.ring: collections.deque = collections.deque(maxlen=RING_MAX)
        self.strangers: dict[str, dict] = {}
        self.received = 0
        self._since_flush: set[str] = set()

    # -- lifecycle ---------------------------------------------------------
    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        self._sel = selectors.DefaultSelector()
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._udp.bind((self.bind_host, self.bind_port))
            self._udp.setblocking(False)
            self._sel.register(self._udp, selectors.EVENT_READ, "udp")
            if self.tcp:
                self._tcp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._tcp_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._tcp_srv.bind((self.bind_host, self.bind_port))
                self._tcp_srv.listen(16)
                self._tcp_srv.setblocking(False)
                self._sel.register(self._tcp_srv, selectors.EVENT_READ, "tcp")
        except OSError as exc:
            self._close_all()
            raise RuntimeError("cannot bind %s:%d: %s" % (self.bind_host, self.bind_port,
                                                          exc.strerror or exc)) from None
        self.started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="satom-syslog", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)
        self._close_all()

    def _close_all(self) -> None:
        for s in list(self._conns):
            try:
                s.close()
            except OSError:
                pass
        self._conns.clear()
        for s in (self._udp, self._tcp_srv):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        self._udp = self._tcp_srv = None
        if self._sel is not None:
            try:
                self._sel.close()
            except Exception:  # noqa: BLE001
                pass
            self._sel = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                events = self._sel.select(timeout=0.5) if self._sel else []
            except Exception:  # noqa: BLE001 - selector torn down under us
                break
            for key, _mask in events:
                try:
                    if key.data == "udp":
                        self._read_udp()
                    elif key.data == "tcp":
                        self._accept()
                    else:
                        self._read_conn(key.fileobj)
                except Exception as exc:  # noqa: BLE001 - one bad peer, not the loop
                    self.error = "%s: %s" % (exc.__class__.__name__, str(exc)[:120])

    def _read_udp(self) -> None:
        for _ in range(256):   # drain a burst, then yield to the selector
            try:
                data, peer = self._udp.recvfrom(MAX_MESSAGE)
            except (BlockingIOError, InterruptedError):
                return
            self.handle(peer[0], data)

    def _accept(self) -> None:
        try:
            conn, peer = self._tcp_srv.accept()
        except (BlockingIOError, InterruptedError):
            return
        if len(self._conns) >= MAX_CONNECTIONS or not self._allowed(peer[0]):
            # A sender we would drop every message from does not get a socket.
            with self._lock:
                if self._allowed(peer[0]) is None:
                    self.dropped["unknown_source"] += 1
                    self._note_stranger(peer[0])
                else:
                    self.dropped["too_many_connections"] += 1
            conn.close()
            return
        conn.setblocking(False)
        self._conns[conn] = {"peer": peer[0], "buf": b""}
        self._sel.register(conn, selectors.EVENT_READ, "conn")

    def _read_conn(self, conn) -> None:
        st = self._conns.get(conn)
        if st is None:
            return
        try:
            data = conn.recv(65536)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            data = b""
        if not data:
            self._drop_conn(conn)
            return
        st["buf"] += data
        if len(st["buf"]) > MAX_TCP_BUFFER:
            with self._lock:
                self.dropped["oversize"] += 1
            self._drop_conn(conn)
            return
        msgs, st["buf"] = frame_tcp(st["buf"])
        for m in msgs:
            self.handle(st["peer"], m)

    def _drop_conn(self, conn) -> None:
        try:
            self._sel.unregister(conn)
        except Exception:  # noqa: BLE001
            pass
        try:
            conn.close()
        except OSError:
            pass
        self._conns.pop(conn, None)

    def _note_stranger(self, ip: str) -> None:
        """Count a dropped sender by address (caller holds the lock). When the
        table is full the least recently seen address makes room, so a sender
        that is still sending always stays listed."""
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        st = self.strangers.get(ip)
        if st is None:
            if len(self.strangers) >= STRANGERS_MAX:
                oldest = min(self.strangers, key=lambda k: self.strangers[k]["last_at"])
                self.strangers.pop(oldest, None)
            st = self.strangers[ip] = {"count": 0, "first_at": now, "last_at": now}
        st["count"] += 1
        st["last_at"] = now

    # -- attribution -------------------------------------------------------
    def _allowed(self, ip: str):
        """``(name, kind)`` for a known appliance, ``(ip, "unregistered")``
        for an extra network, ``None`` for a stranger."""
        src = self.sources.get(ip)
        if src:
            return src.get("name") or ip, src.get("kind") or ""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net in self.extra_networks:
            if addr in net:
                return ip, "unregistered"
        return None

    def handle(self, ip: str, raw: bytes) -> bool:
        """Attribute, parse, count. Returns True when the message was kept."""
        who = self._allowed(ip)
        if who is None:
            with self._lock:
                self.dropped["unknown_source"] += 1
                self._note_stranger(ip)
            return False
        if len(raw) > MAX_MESSAGE:
            with self._lock:
                self.dropped["oversize"] += 1
            return False
        msg = parse_message(raw)
        if msg is None:
            with self._lock:
                self.dropped["unparseable"] += 1
            return False
        name, kind = who
        from .secret_scan import redact
        text = redact(msg["text"])[:TEXT_MAX]
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            self.received += 1
            self.counts[(name, kind, msg["facility"], msg["severity"])] += 1
            d = self.per_device.setdefault(name, {"kind": kind, "count": 0,
                                                  "last_at": "", "last_severity": ""})
            d["count"] += 1
            d["last_at"] = now
            d["last_severity"] = msg["severity"]
            self._since_flush.add(name)
            self.ring.append({"at": now, "device": name, "severity": msg["severity"],
                              "facility": msg["facility"], "app": msg["app"][:40],
                              "text": text})
        return True

    # -- draining ----------------------------------------------------------
    def flush_lines(self, ts_ms: int | None = None) -> list[str]:
        """Exposition lines for the store: cumulative counters, the per-device
        ``up`` (1 = a message arrived since the previous flush, 0 = silence, for
        EVERY known appliance), the drop counters and the receiver's own up."""
        from .vm_store import line
        ts = ts_ms if ts_ms is not None else int(time.time() * 1000)
        out = [line(METRIC_RECEIVER, {"port": self.bind_port}, 1 if self.running else 0, ts)]
        with self._lock:
            for (name, kind, fac, sev), n in self.counts.items():
                out.append(line(METRIC_MESSAGES,
                                {"device": name, "kind": kind, "facility": fac, "severity": sev},
                                n, ts))
            for reason, n in self.dropped.items():
                out.append(line(METRIC_DROPPED, {"reason": reason}, n, ts))
            known = {s.get("name"): s.get("kind") for s in self.sources.values() if s.get("name")}
            for name, kind in known.items():
                out.append(line(METRIC_UP, {"device": name, "kind": kind or ""},
                                1 if name in self._since_flush else 0, ts))
            self._since_flush = set()
        return [l for l in out if l]

    def snapshot(self) -> dict:
        with self._lock:
            return {"running": self.running, "bind": "%s:%d" % (self.bind_host, self.bind_port),
                    "tcp": self.tcp, "started_at": self.started_at, "error": self.error,
                    "received": self.received, "dropped": dict(self.dropped),
                    "strangers": [dict(v, ip=k) for k, v in sorted(
                        self.strangers.items(), key=lambda kv: -kv[1]["count"])],
                    "per_device": {k: dict(v) for k, v in self.per_device.items()},
                    "known_sources": len(self.sources),
                    # The deque is the bound (maxlen); nothing re-slices here,
                    # so a ring that stopped being bounded would show.
                    "recent": list(self.ring)}


# ── service glue (scheduler sidecar) ─────────────────────────────────────────

_RECEIVER: Receiver | None = None
_SOURCES_AT = 0.0
_last_flush: dict = {}


def known_sources() -> dict[str, dict]:
    """Management addresses of every live appliance -> ``{name, kind}``.
    Hostnames are resolved here (every address a name has)."""
    out: dict[str, dict] = {}
    try:
        from ..models import Appliance
        rows = Appliance.query.all()
    except Exception:  # noqa: BLE001
        return out
    for a in rows:
        host = (a.host or "").strip()
        if not host or host.endswith(".invalid"):
            continue
        for h in {host, (a.ha_vip or "").strip()} - {""}:
            try:
                ipaddress.ip_address(h)
                addrs = [h]
            except ValueError:
                try:
                    addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(h, None, socket.AF_INET)})
                except OSError:
                    addrs = []
            for ip in addrs:
                out[ip] = {"name": a.name, "kind": a.kind}
    return out


def name_strangers(strangers: list[dict]) -> list[dict]:
    """Say which retired device an unknown sender used to be.

    A live appliance's address is never a stranger (it is on the allow-list),
    so an address here that matches a RETIRED identity is almost always a
    device that was de-registered and still has this receiver as its syslog
    target -- the fix is on the device, not here. Addresses are reused, so the
    most recently retired identity with that host wins. Never raises."""
    if not strangers:
        return strangers
    try:
        from ..models_identity import DeviceIdentity
        rows = (DeviceIdentity.query
                .filter(DeviceIdentity.retired_at.isnot(None),
                        DeviceIdentity.host.in_([s["ip"] for s in strangers]))
                .order_by(DeviceIdentity.retired_at.asc()).all())
    except Exception:  # noqa: BLE001
        return strangers
    by_host = {r.host: r for r in rows}       # ascending: the newest wins
    for s in strangers:
        r = by_host.get(s["ip"])
        if r is not None:
            s["retired_name"] = r.name or r.slug
            s["retired_at"] = r.retired_at.isoformat(timespec="seconds")
    return strangers


def node_role() -> str:
    try:
        from . import self_update
        return self_update.node_role()
    except Exception:  # noqa: BLE001
        return "unknown"


def should_listen(cfg: dict | None = None, role: str | None = None) -> tuple[bool, str]:
    cfg = cfg or config()
    role = role if role is not None else node_role()
    if not cfg["enabled"]:
        return False, "disabled"
    if role == "standby":
        return False, "standby node — the primary listens"
    return True, ""


def _write_state(payload: dict) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, default=str), encoding="utf-8")
        os.replace(tmp, STATE_FILE)
    except OSError:
        pass


def read_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def service_tick(flush=None) -> dict:
    """Called from the scheduler tick (inside an app context). Starts or stops
    the listener to match the setting and the node role, refreshes the
    allow-list, drains the counters into the store (local + peer) and writes
    the journal the page reads. Never raises; never waits on the network."""
    global _RECEIVER, _SOURCES_AT, _last_flush
    cfg = config()
    listen, reason = should_listen(cfg)
    state: dict = {"enabled": cfg["enabled"], "bind": "%s:%d" % (cfg["bind_host"], cfg["bind_port"]),
                   "reason": reason, "running": False,
                   "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    try:
        if _RECEIVER is not None and (not listen
                                      or _RECEIVER.bind_host != cfg["bind_host"]
                                      or _RECEIVER.bind_port != cfg["bind_port"]
                                      or _RECEIVER.tcp != cfg["tcp"]):
            _RECEIVER.stop()
            _RECEIVER = None
        if listen and _RECEIVER is None:
            nets, _bad = parse_sources(cfg["extra_sources"])
            r = Receiver(cfg["bind_host"], cfg["bind_port"], tcp=cfg["tcp"],
                         sources=known_sources(), extra_networks=nets)
            try:
                r.start()
                _RECEIVER = r
                _SOURCES_AT = time.monotonic()
            except RuntimeError as exc:
                state["error"] = str(exc)
        if _RECEIVER is not None:
            if time.monotonic() - _SOURCES_AT >= SOURCE_REFRESH_S:
                nets, _bad = parse_sources(cfg["extra_sources"])
                with _RECEIVER._lock:
                    _RECEIVER.sources = known_sources()
                    _RECEIVER.extra_networks = nets
                _SOURCES_AT = time.monotonic()
            lines = _RECEIVER.flush_lines()
            fl = flush or _default_flush
            _last_flush = fl(lines)
            state.update(_RECEIVER.snapshot())
            state["strangers"] = name_strangers(state.get("strangers") or [])
            state["flush"] = _last_flush
        else:
            state["running"] = False
    except Exception as exc:  # noqa: BLE001 - the tick must go on
        state["error"] = "%s: %s" % (exc.__class__.__name__, str(exc)[:160])
    _write_state(state)
    return state


def _default_flush(lines: list[str]) -> dict:
    from . import metrics_collect as mc
    from . import vm_store
    local = vm_store.ingest(lines)
    try:
        peer = mc.peer_write(lines)
    except Exception as exc:  # noqa: BLE001
        peer = {"ok": False, "detail": str(exc)[:120]}
    return {"local_ok": bool(local.get("ok")), "local_detail": local.get("detail", ""),
            "series": len(lines), "peer_state": peer.get("state"), "peer_ok": peer.get("ok")}


def shutdown() -> None:
    global _RECEIVER
    if _RECEIVER is not None:
        _RECEIVER.stop()
        _RECEIVER = None


def status() -> dict:
    """What the page shows: the setting plus the sidecar's last journal."""
    cfg = config()
    st = read_state()
    st.setdefault("running", False)
    st["config"] = cfg
    return st
