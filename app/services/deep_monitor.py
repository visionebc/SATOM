"""Deep service + server monitors — the third Monitoring view.

Fleet health answers *is the box up and does it have headroom*. Metrics answers
*how many objects does it hold*. Neither answers the question an operator
actually asks at 03:00: **is the service still serving?**

Three probe families, each persisted as a time series, because the interesting
signal is almost never the current value — it is the value CHANGING:

``https``      Synthetic request against a server policy's published front-end.
               A 200 back from the VIP proves the whole chain at once: the
               interface is up, the policy is enabled, ``proxyd`` is listening
               and a backend answered. Records HTTP status, latency and the
               days left on the served TLS certificate.
``interface``  Fingerprint of every interface's ``name → ip/status``. You do not
               chart an IP address; you detect it moving. A sample whose
               fingerprint differs from its predecessor IS the event.
``proxyd``     FortiWeb's HTTP proxy daemon, read over the read-only CLI
               (``diagnose system top``). Records worker count, aggregate CPU%
               and MEM%, and the PID set — a changed PID set is a silent
               restart, the failure mode a plain health check never surfaces.

**Parsing is deliberately separated from I/O.** ``parse_top``,
``iface_fingerprint``, ``classify_*`` and ``prune`` are network-free and unit
tested, because the appliances are frequently unreachable when this code is
edited (all four were down the day it was written) and a monitor that can only
be validated against a live box is a monitor that ships unvalidated.

Source-of-truth notes:

* ``interface`` reads the DEVICE CACHE (``device_objects``, refreshed by the
  hourly ``device_sync``), never the appliance. That keeps the page's contract —
  a page load never touches a device — and means drift is detected at harvest
  cadence. The sample carries the cache age so the operator can see the lag.
* ``proxyd`` is the only family that opens a socket to the appliance, and it
  does so through :mod:`app.services.ssh_ops`, whose ``assert_readonly`` refuses
  anything that is not ``get``/``show``/``diagnose``.
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import time
from datetime import datetime, timedelta
from typing import Any

# Status vocabulary shared with the UI (worst-first ordering).
STATUS_ORDER = {"crit": 0, "error": 1, "warn": 2, "ok": 3, "unknown": 4}

KINDS = ("https", "interface", "proxyd")

KIND_LABEL = {
    "https": "Service policy (HTTPS)",
    "interface": "Interface IP / link",
    "proxyd": "proxyd process",
}

# How many samples to keep per probe before the oldest are dropped.
DEFAULT_RETENTION = 500

# `diagnose system top` on FortiWeb 7.6 is BusyBox top — VERIFIED against fw6
# and fw7 (2026-07-27), not assumed:
#
#     Mem: 2274272K used, 1542012K free, 18004K shrd, 12380K buff, 263320K cached
#     CPU:  0.0% usr  0.0% sys  0.0% nic  100% idle  0.0% io  0.0% irq  0.0% sirq
#     Load average: 1.33 1.04 0.65 1/367 23435
#       PID  PPID USER     STAT   VSZ %VSZ CPU %CPU COMMAND
#      3460     1 root     S    2232m 59.7   0  0.0 /bin/proxyd
#
# COMMAND is a full path with arguments, so the process name is the basename of
# its first token. Note "100% idle" has no decimal — the percent patterns must
# not require one.
_TOP_ROW = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<ppid>\d+)\s+(?P<user>\S+)\s+(?P<state>\S+)\s+"
    r"(?P<vsz>[\d.]+[kmgKMG]?)\s+(?P<mem>[\d.]+)\s+(?P<core>\d+)\s+"
    r"(?P<cpu>[\d.]+)\s+(?P<cmd>\S.*?)\s*$"
)
_TOP_MEM = re.compile(r"^\s*Mem:\s*(?P<used>\d+)K\s+used,\s*(?P<free>\d+)K\s+free", re.I)
_TOP_CPU = re.compile(r"^\s*CPU:.*?(?P<idle>[\d.]+)\s*%\s*idle", re.I)
_TOP_LOAD = re.compile(r"^\s*Load average:\s*(?P<load>[\d.]+\s+[\d.]+\s+[\d.]+)", re.I)

# Fallback for the FortiOS-style layout ("name pid state cpu mem"), kept so a
# different firmware build does not silently read as "daemon not running".
_TOP_PROC_LEGACY = re.compile(
    r"^\s*(?P<name>[A-Za-z][\w.\-]*)\s+(?P<pid>\d+)\s+(?P<state>[A-Za-z<>]+)\s+"
    r"(?P<cpu>\d+(?:\.\d+)?)\s+(?P<mem>\d+(?:\.\d+)?)\s*$"
)
_TOP_SUMMARY_LEGACY = re.compile(
    r"(?P<user>\d+)U,\s*(?P<nice>\d+)N,\s*(?P<sys>\d+)S,\s*(?P<idle>\d+)I"
    r".*?(?P<total>\d+)T,\s*(?P<free>\d+)F"
)

# The CLI battery for the process monitor. `diagnose system top` is the metric
# source; `get system performance` is context (box-wide CPU/mem/uptime) and is
# best-effort — a firmware that lacks it must not fail the check.
TOP_CMD = "diagnose system top"
PERF_CMD = "get system performance"

# `get system performance` on FortiWeb 7.6 — VERIFIED on fw6 (2026-07-27):
#     CPU states:    5% used, 95% idle
#     Memory states: 52% used
#     Up:            0 days,  0 hours,  18 minutes.
# This is the AUTHORITATIVE box CPU. The `CPU:` line inside `diagnose system
# top` is a first-iteration BusyBox artefact: four consecutive reads of an idle
# fw6 returned 100% idle, 100% idle, 90.9% idle and 0% idle. Thresholding on
# that would page the operator at random.
_PERF_CPU = re.compile(r"CPU states:\s*(?P<used>[\d.]+)\s*%\s*used", re.I)
_PERF_MEM = re.compile(r"Memory states:\s*(?P<used>[\d.]+)\s*%\s*used", re.I)
_PERF_UP = re.compile(r"Up:\s*(?P<up>.+?)\.?\s*$", re.I | re.M)

# Default name of the daemon we watch. Kept configurable per probe because a
# FortiWeb build may name it `proxyd`, and the same machinery is useful for
# `httpsd` / `updated` without touching code.
DEFAULT_PROCESS = "proxyd"


# ---------------------------------------------------------------------------
# Pure parsing / classification (network-free — this is the tested surface)
# ---------------------------------------------------------------------------

def _f(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def sha8(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()[:8]


def _vsz_mb(raw: str) -> float | None:
    """``2232m`` / ``998m`` / ``4096`` (KiB, BusyBox default) → MB."""
    raw = (raw or "").strip()
    if not raw:
        return None
    unit = raw[-1].lower()
    if unit.isdigit():
        return round(_f(raw) / 1024.0, 1)          # bare number is KiB
    num = _f(raw[:-1])
    return {"k": num / 1024.0, "m": num, "g": num * 1024.0}.get(unit, num)


def _proc_name(cmd: str) -> str:
    """``/bin/filebeat -c /data/etc/…`` → ``filebeat``."""
    first = (cmd or "").strip().split()[0] if (cmd or "").strip() else ""
    return first.rsplit("/", 1)[-1]


def parse_top(raw: str) -> dict:
    """Parse ``diagnose system top`` into processes + box summary.

    Returns ``{"processes": [{name,pid,state,cpu,mem,vsz_mb,cmd}],
    "summary": {...}, "parsed": bool, "cpu_per_process_reliable": bool}``.

    ``parsed`` is False when not one process line matched. That distinction
    matters: reporting "0 workers" for output we simply could not read looks
    exactly like a dead daemon, and a monitor that cries wolf gets muted.

    ``cpu_per_process_reliable`` is False for BusyBox top — its FIRST iteration
    has no previous sample to diff against, so every process reports 0.0% CPU.
    Verified live on fw6/fw7: a box under load still printed 0.0% on every row.
    Per-process CPU from a single shot is therefore NOT a usable metric; the
    box-level ``CPU: … idle`` line is, and is what the grader thresholds on.
    """
    procs: list[dict] = []
    summary: dict = {}
    load = ""
    legacy = False

    for line in (raw or "").splitlines():
        m = _TOP_ROW.match(line)
        if m:
            procs.append({
                "name": _proc_name(m.group("cmd")),
                "pid": int(m.group("pid")),
                "ppid": int(m.group("ppid")),
                "state": m.group("state"),
                "cpu": _f(m.group("cpu")),
                "mem": _f(m.group("mem")),
                "vsz_mb": _vsz_mb(m.group("vsz")),
                "cmd": m.group("cmd").strip()[:160],
            })
            continue
        mm = _TOP_MEM.match(line)
        if mm:
            used, free = _f(mm.group("used")) / 1024.0, _f(mm.group("free")) / 1024.0
            total = used + free
            summary.update(mem_total_mb=round(total, 1), mem_free_mb=round(free, 1),
                           mem_used_pct=round(100.0 * used / total, 1) if total else None)
            continue
        mc = _TOP_CPU.match(line)
        if mc:
            idle = _f(mc.group("idle"))
            summary.update(cpu_idle=idle, cpu_busy=round(100.0 - idle, 1))
            continue
        ml = _TOP_LOAD.match(line)
        if ml:
            load = ml.group("load")

    if not procs:
        # Fall back to the FortiOS-style layout before declaring defeat.
        for line in (raw or "").splitlines():
            m = _TOP_PROC_LEGACY.match(line)
            if m:
                legacy = True
                procs.append({"name": m.group("name"), "pid": int(m.group("pid")),
                              "ppid": None, "state": m.group("state"),
                              "cpu": _f(m.group("cpu")), "mem": _f(m.group("mem")),
                              "vsz_mb": None, "cmd": m.group("name")})
                continue
            ms = _TOP_SUMMARY_LEGACY.search(line)
            if ms and not summary:
                total, free = _f(ms.group("total")), _f(ms.group("free"))
                idle = _f(ms.group("idle"))
                summary = {"cpu_idle": idle, "cpu_busy": round(100.0 - idle, 1),
                           "mem_total_mb": total, "mem_free_mb": free,
                           "mem_used_pct": round(100.0 * (total - free) / total, 1)
                                           if total else None}

    return {"processes": procs, "summary": summary, "load": load,
            "parsed": bool(procs), "cpu_per_process_reliable": legacy}


def parse_performance(raw: str) -> dict:
    """Parse ``get system performance`` — the trustworthy box CPU/memory."""
    out: dict = {}
    m = _PERF_CPU.search(raw or "")
    if m:
        out["cpu_busy"] = _f(m.group("used"))
        out["cpu_idle"] = round(100.0 - out["cpu_busy"], 1)
    m = _PERF_MEM.search(raw or "")
    if m:
        out["mem_used_pct"] = _f(m.group("used"))
    m = _PERF_UP.search(raw or "")
    if m:
        out["uptime"] = m.group("up").strip()
    return out


def select_process(parsed: dict, name: str) -> dict:
    """Aggregate every worker of ``name`` from a :func:`parse_top` result.

    Matches on the command BASENAME, so ``proxyd`` finds ``/bin/proxyd`` and an
    operator never has to know the on-disk path.
    """
    want = (name or DEFAULT_PROCESS).strip().lower().rsplit("/", 1)[-1]
    rows = [p for p in parsed.get("processes") or []
            if p["name"].lower() == want]
    pids = sorted(p["pid"] for p in rows)
    vsz = [p["vsz_mb"] for p in rows if p.get("vsz_mb") is not None]
    return {
        "process": want,
        "count": len(rows),
        "cpu": round(sum(p["cpu"] for p in rows), 1),
        "mem": round(sum(p["mem"] for p in rows), 1),
        "vsz_mb": round(sum(vsz), 1) if vsz else None,
        "pids": pids,
        "pid_fingerprint": sha8(",".join(str(p) for p in pids)) if pids else "",
        "workers": rows,
    }


def iface_rows_fingerprint(rows: list[dict]) -> tuple[str, list[dict]]:
    """Canonical ``name → ip/status`` fingerprint for a set of interfaces.

    Only the fields whose change is operationally meaningful go into the hash:
    the address and the admin/link status. MTU or a description edit must not
    read as "the network moved".
    """
    slim = []
    for r in sorted(rows or [], key=lambda x: str(x.get("name") or "")):
        name = str(r.get("name") or "").strip()
        if not name:
            continue
        slim.append({
            "name": name,
            "ip": str(r.get("ip_address") or "").strip(),
            "status": str(r.get("status") or "").strip().lower(),
        })
    canon = ";".join(f"{s['name']}={s['ip']}/{s['status']}" for s in slim)
    return sha8(canon), slim


def diff_ifaces(prev: list[dict], cur: list[dict]) -> list[str]:
    """Human-readable delta between two :func:`iface_rows_fingerprint` slims."""
    pmap = {r["name"]: r for r in prev or []}
    cmap = {r["name"]: r for r in cur or []}
    out: list[str] = []
    for name in sorted(set(pmap) | set(cmap)):
        a, b = pmap.get(name), cmap.get(name)
        if a and not b:
            out.append(f"{name}: disappeared from the harvest")
        elif b and not a:
            out.append(f"{name}: new ({b['ip'] or 'no IP'})")
        else:
            if a["ip"] != b["ip"]:
                out.append(f"{name}: IP {a['ip'] or '—'} → {b['ip'] or '—'}")
            if a["status"] != b["status"]:
                out.append(f"{name}: status {a['status'] or '—'} → {b['status'] or '—'}")
    return out


def classify_https(res: dict, *, expect_status: int, warn_ms: int,
                   tls_days: int | None, tls_warn_days: int) -> tuple[str, str]:
    """Grade an HTTPS probe result. Returns ``(status, detail)``."""
    if res.get("error"):
        return "crit", f"unreachable: {res['error']}"
    code = res.get("status")
    if code is None:
        return "crit", "no HTTP status returned"
    if expect_status:
        if int(code) != int(expect_status):
            return "crit", f"HTTP {code} (expected {expect_status})"
    elif int(code) >= 400:
        return "crit", f"HTTP {code}"
    elapsed = res.get("elapsed_ms")
    parts = [f"HTTP {code}"]
    if elapsed is not None:
        parts.append(f"{elapsed} ms")
    status = "ok"
    if tls_days is not None:
        parts.append(f"TLS {tls_days}d left")
        if tls_days <= 0:
            return "crit", ", ".join(parts) + " — certificate EXPIRED"
        if tls_days <= tls_warn_days:
            status = "warn"
    if warn_ms and elapsed is not None and elapsed > warn_ms:
        status = "warn"
        parts.append(f"slower than {warn_ms} ms")
    return status, ", ".join(parts)


def classify_interface(fingerprint: str, prev_fingerprint: str,
                       slim: list[dict], prev_slim: list[dict],
                       *, cache_age_h: float | None,
                       stale_after_h: float) -> tuple[str, str]:
    """Grade an interface snapshot: drift is a warn, a lost IP is critical."""
    if not slim:
        return "error", "no interfaces in the device cache — run a device sync"
    no_ip = [s["name"] for s in slim
             if not s["ip"] and s["status"] in ("up", "1", "enable", "")]
    down = [s["name"] for s in slim if s["status"] == "down"]
    changes = diff_ifaces(prev_slim, slim) if prev_fingerprint else []

    bits = [f"{len(slim)} interfaces"]
    if cache_age_h is not None:
        bits.append(f"cache {cache_age_h:.1f} h old")
    status = "ok"
    if cache_age_h is not None and stale_after_h and cache_age_h > stale_after_h:
        status = "warn"
        bits.append("harvest is stale — device_sync may be failing")
    if down:
        status = "warn"
        bits.append(f"down: {', '.join(down[:6])}")
    if changes:
        # Drift against the previous sample is the whole point of this probe.
        status = "crit" if any("IP" in c for c in changes) else "warn"
        bits.append("CHANGED — " + "; ".join(changes[:6]))
    elif prev_fingerprint and prev_fingerprint == fingerprint:
        bits.append("unchanged")
    if no_ip and not changes:
        bits.append(f"no address: {', '.join(no_ip[:6])}")
    return status, "; ".join(bits)


def classify_proxyd(agg: dict, parsed: dict, prev_fingerprint: str,
                    *, warn_cpu: float, warn_mem: float) -> tuple[str, str]:
    """Grade a process snapshot: absent = critical, new PIDs = restart.

    ``warn_mem`` thresholds the DAEMON's memory share (``%VSZ``, meaningful in a
    single shot). ``warn_cpu`` thresholds the BOX's busy CPU, not the process's
    — BusyBox top reports 0.0% per process on its first iteration, so a
    per-process CPU threshold would never fire and would read as "healthy" on a
    pegged appliance. Grading on a number that cannot move is worse than not
    grading at all.
    """
    if not parsed.get("parsed"):
        return "error", (f"could not parse `{TOP_CMD}` output — raw response "
                         "captured in the sample payload")
    if agg["count"] == 0:
        return "crit", f"{agg['process']} is NOT running"
    summary = parsed.get("summary") or {}
    box_cpu = summary.get("cpu_busy")

    bits = [f"{agg['count']} worker" + ("s" if agg["count"] != 1 else ""),
            f"MEM {agg['mem']}%"
            + (f" ({agg['vsz_mb']:.0f} MB)" if agg.get("vsz_mb") else "")]
    if box_cpu is not None:
        bits.append(f"box CPU {box_cpu}%")
    if summary.get("mem_used_pct") is not None:
        bits.append(f"box mem {summary['mem_used_pct']}%")

    status = "ok"
    if prev_fingerprint and prev_fingerprint != agg["pid_fingerprint"]:
        status = "warn"
        bits.append(f"PIDs CHANGED — {agg['process']} restarted since last check")
    if warn_mem and agg["mem"] >= warn_mem:
        status = "warn"
        bits.append(f"MEM over {warn_mem}%")
    if warn_cpu and box_cpu is not None and box_cpu >= warn_cpu:
        status = "warn"
        bits.append(f"box CPU over {warn_cpu}%")
    return status, "; ".join(bits)


def worst(statuses: list[str]) -> str:
    """Worst status in a list, using :data:`STATUS_ORDER`."""
    if not statuses:
        return "unknown"
    return sorted(statuses, key=lambda s: STATUS_ORDER.get(s, 9))[0]


# ---------------------------------------------------------------------------
# Live probes (I/O)
# ---------------------------------------------------------------------------

def tls_days_left(host: str, port: int, *, timeout: float = 6.0) -> int | None:
    """Days until the certificate served on ``host:port`` expires.

    Deliberately does NOT verify the chain — a VIP commonly serves a cert for a
    public hostname while we connect by IP, and refusing to read the expiry of a
    cert we could not validate would blind the check for exactly the cert that
    matters most.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                # MUST be binary_form: with verify_mode=CERT_NONE the dict form
                # of getpeercert() comes back EMPTY (CPython only populates the
                # parsed fields when it validated the chain). Reading the dict
                # here silently reported "no TLS data" for every probe — caught
                # live on 2026-07-27 against a VIP that plainly served a cert.
                der = tls.getpeercert(binary_form=True)
    except Exception:  # noqa: BLE001 — no cert readable is not an error here
        return None
    if not der:
        return None
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
        try:
            exp = cert.not_valid_after_utc            # cryptography >= 42
            now = datetime.now(exp.tzinfo)
        except AttributeError:                        # pragma: no cover
            exp = cert.not_valid_after                # naive UTC on older libs
            now = datetime.utcnow()
    except Exception:  # noqa: BLE001
        return None
    return (exp - now).days


def _split_url(url: str) -> tuple[str, str, int]:
    """``https://1.2.3.4:8443/x`` → ``(scheme, host, port)``."""
    scheme, _, rest = (url or "").partition("://")
    if not rest:
        scheme, rest = "https", scheme
    hostport = rest.split("/", 1)[0]
    if hostport.startswith("["):                    # IPv6 literal
        host, _, tail = hostport[1:].partition("]")
        port = int(tail.lstrip(":") or 0) or (443 if scheme == "https" else 80)
    elif ":" in hostport:
        host, _, p = hostport.rpartition(":")
        port = int(p) if p.isdigit() else (443 if scheme == "https" else 80)
    else:
        host = hostport
        port = 443 if scheme == "https" else 80
    return scheme or "https", host, port


def run_https(probe) -> dict:
    """Execute one HTTPS/HTTP service probe. Never raises."""
    from . import service_probe

    url = (probe.url or "").strip()
    if not url:
        return {"status": "error", "detail": "probe has no URL", "payload": {}}
    started = time.time()
    res = service_probe.probe_url(url, timeout=float(probe.timeout_s or 10))
    data = res if isinstance(res, dict) else res.__dict__
    scheme, host, port = _split_url(url)
    tls = tls_days_left(host, port) if scheme == "https" else None
    status, detail = classify_https(
        data, expect_status=int(probe.expect_status or 0),
        warn_ms=int(probe.warn_ms or 0), tls_days=tls,
        tls_warn_days=int(probe.tls_warn_days or 21))
    return {
        "status": status,
        "detail": detail,
        "value_num": data.get("elapsed_ms"),
        "value2_num": tls,
        "fingerprint": str(data.get("body_sha8") or ""),
        "payload": {
            "url": url, "http_status": data.get("status"),
            "elapsed_ms": data.get("elapsed_ms"),
            "tls_days_left": tls, "headers": data.get("headers") or {},
            "body_len": data.get("body_len"), "error": data.get("error") or "",
            "took_ms": int((time.time() - started) * 1000),
        },
    }


def run_interface(probe, prev) -> dict:
    """Snapshot the interface table from the device cache and diff it."""
    from . import interface_inventory

    if probe.appliance is None:
        return {"status": "error", "detail": "probe has no device", "payload": {}}
    try:
        data = interface_inventory.merged(probe.appliance)
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "detail": f"cache read failed: {exc}",
                "payload": {}}
    rows = data.get("interfaces") or []
    fingerprint, slim = iface_rows_fingerprint(rows)

    cache = data.get("cache") or {}
    age_h = None
    fetched = cache.get("fetched_at") or cache.get("captured_at") or ""
    if fetched:
        try:
            ts = datetime.fromisoformat(str(fetched).replace("Z", ""))
            age_h = max(0.0, (datetime.utcnow() - ts).total_seconds() / 3600.0)
        except (ValueError, TypeError):
            age_h = None

    prev_slim = []
    prev_fp = ""
    if prev is not None:
        prev_fp = prev.fingerprint or ""
        try:
            prev_slim = (json.loads(prev.payload or "{}") or {}).get("interfaces") or []
        except (ValueError, TypeError):
            prev_slim = []

    status, detail = classify_interface(
        fingerprint, prev_fp, slim, prev_slim,
        cache_age_h=age_h, stale_after_h=float(probe.stale_after_h or 6))
    with_ip = sum(1 for s in slim if s["ip"])
    return {
        "status": status, "detail": detail,
        "value_num": with_ip, "value2_num": len(slim),
        "fingerprint": fingerprint,
        "payload": {"interfaces": slim, "cache_age_h": age_h,
                    "changes": diff_ifaces(prev_slim, slim) if prev_fp else []},
    }


def run_proxyd(probe, prev) -> dict:
    """Read ``diagnose system top`` over the read-only CLI and grade it."""
    from . import ssh_ops

    if probe.appliance is None:
        return {"status": "error", "detail": "probe has no device", "payload": {}}
    if (probe.appliance.kind or "fortiweb") != "fortiweb":
        return {"status": "error",
                "detail": "process monitoring is FortiWeb-only "
                          "(FortiADC/FortiAnalyzer expose no equivalent read)",
                "payload": {}}
    try:
        raw = ssh_ops.run_command(probe.appliance, TOP_CMD,
                                  timeout=float(probe.timeout_s or 15))
    except Exception as exc:  # noqa: BLE001 — box down is a result, not a crash
        return {"status": "crit", "detail": f"CLI unreachable: {exc}",
                "payload": {"command": TOP_CMD, "error": str(exc)}}
    parsed = parse_top(raw)

    # Overlay the trustworthy box figures from `get system performance` before
    # grading. Best-effort: a firmware without the command keeps top's noisy
    # numbers, which is why `box_cpu_source` is recorded in the payload — an
    # operator must be able to tell which number a warning was based on.
    perf = ""
    try:
        perf = ssh_ops.run_command(probe.appliance, PERF_CMD, timeout=10.0)
    except Exception:  # noqa: BLE001 — context only, never fails the check
        perf = ""
    perf_vals = parse_performance(perf)
    summary = dict(parsed.get("summary") or {})
    summary["top_cpu_busy"] = summary.get("cpu_busy")
    summary.update(perf_vals)
    summary["box_cpu_source"] = PERF_CMD if "cpu_busy" in perf_vals else TOP_CMD
    parsed["summary"] = summary

    agg = select_process(parsed, probe.process_name or DEFAULT_PROCESS)
    prev_fp = (prev.fingerprint or "") if prev is not None else ""
    status, detail = classify_proxyd(
        agg, parsed, prev_fp,
        warn_cpu=float(probe.warn_cpu or 0), warn_mem=float(probe.warn_mem or 0))
    # The trended value is the daemon's MEMORY share: it is the one per-process
    # number a single BusyBox top shot reports honestly. Box CPU rides along as
    # the secondary series.
    return {
        "status": status, "detail": detail,
        "value_num": agg["mem"],
        "value2_num": (parsed.get("summary") or {}).get("cpu_busy"),
        "fingerprint": agg["pid_fingerprint"],
        "payload": {"command": TOP_CMD, "process": agg["process"],
                    "count": agg["count"], "pids": agg["pids"],
                    "vsz_mb": agg.get("vsz_mb"),
                    "workers": agg["workers"][:12],
                    "box": parsed.get("summary") or {},
                    "load": parsed.get("load") or "",
                    "parsed": parsed.get("parsed"),
                    "cpu_per_process_reliable": parsed.get("cpu_per_process_reliable"),
                    "raw": (raw or "")[:4000],
                    "performance": (perf or "")[:2000]},
    }


# ---------------------------------------------------------------------------
# Orchestration + persistence
# ---------------------------------------------------------------------------

def latest_sample(probe, *, session=None):
    from ..models import MonitorSample, db

    session = session or db.session
    return (session.query(MonitorSample)
            .filter(MonitorSample.probe_id == probe.id)
            .order_by(MonitorSample.ts.desc()).first())


def prune(probe_id: int, keep: int = DEFAULT_RETENTION, *, session=None) -> int:
    """Drop all but the newest ``keep`` samples of a probe. Returns rows removed."""
    from ..models import MonitorSample, db

    session = session or db.session
    ids = [row.id for row in
           session.query(MonitorSample.id)
           .filter(MonitorSample.probe_id == probe_id)
           .order_by(MonitorSample.ts.desc()).offset(keep).all()]
    if not ids:
        return 0
    (session.query(MonitorSample)
     .filter(MonitorSample.id.in_(ids))
     .delete(synchronize_session=False))
    return len(ids)


def run_probe(probe, *, session=None) -> dict:
    """Execute one probe, persist a sample, update the probe row.

    Never raises: an exception inside a probe becomes an ``error`` sample, so
    one broken target can never sink a scheduled sweep over the whole fleet.
    """
    from ..models import MonitorSample, db

    session = session or db.session
    prev = latest_sample(probe, session=session)
    try:
        if probe.kind == "https":
            out = run_https(probe)
        elif probe.kind == "interface":
            out = run_interface(probe, prev)
        elif probe.kind == "proxyd":
            out = run_proxyd(probe, prev)
        else:
            out = {"status": "error",
                   "detail": f"unknown probe kind {probe.kind!r}", "payload": {}}
    except Exception as exc:  # noqa: BLE001
        out = {"status": "error", "detail": f"probe crashed: {exc}", "payload": {}}

    sample = MonitorSample(
        probe_id=probe.id, ts=datetime.utcnow(),
        status=out["status"], ok=(out["status"] == "ok"),
        value_num=out.get("value_num"), value2_num=out.get("value2_num"),
        fingerprint=(out.get("fingerprint") or "")[:64],
        detail=(out.get("detail") or "")[:1000],
        payload=json.dumps(out.get("payload") or {})[:60000],
    )
    session.add(sample)
    probe.last_run_at = sample.ts
    probe.last_status = sample.status
    probe.last_detail = sample.detail
    prune(probe.id, int(probe.retention or DEFAULT_RETENTION), session=session)
    session.commit()
    return {"probe": probe.name, "status": sample.status, "detail": sample.detail}


def due_probes(*, session=None, force: bool = False) -> list:
    """Enabled probes whose ``interval_min`` has elapsed (all of them if forced)."""
    from ..models import MonitorProbe, db

    session = session or db.session
    rows = (session.query(MonitorProbe)
            .filter(MonitorProbe.enabled.is_(True))
            .order_by(MonitorProbe.name).all())
    if force:
        return rows
    now = datetime.utcnow()
    out = []
    for p in rows:
        if p.last_run_at is None:
            out.append(p)
            continue
        if now - p.last_run_at >= timedelta(minutes=max(1, int(p.interval_min or 5))):
            out.append(p)
    return out


def sweep(*, ids: list[int] | None = None, force: bool = False,
          session=None) -> dict:
    """Run every due probe (or an explicit id list). The scheduled entry point."""
    from ..models import MonitorProbe, db

    session = session or db.session
    if ids:
        probes = (session.query(MonitorProbe)
                  .filter(MonitorProbe.id.in_(ids)).all())
    else:
        probes = due_probes(session=session, force=force)
    results = [run_probe(p, session=session) for p in probes]
    counts: dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {"ran": len(results), "counts": counts, "results": results,
            "worst": worst([r["status"] for r in results])}


# ---------------------------------------------------------------------------
# Discovery — turn a device's server policies into ready-made HTTPS probes
# ---------------------------------------------------------------------------

_VSERVER_REF = re.compile(r"vserver\(([^)]+)\)")


def resolve_targets_from_cache(appliance, *, session=None) -> list[dict]:
    """Resolve each cached server policy to a probe URL, WITHOUT calling the box.

    Chain, all from the harvest: ``device_server_policies`` gives the policy's
    ``vserver`` and its HTTP/HTTPS service; the cached ``vip`` objects carry the
    address plus a ``q_ref_string`` of the form ``vserver(vs-shop) --> …`` that
    names the vserver they belong to.

    Cache-first is deliberate. The live REST call is not equivalent: on fw6
    (2026-07-27) ``list_server_policies()`` returned ZERO while the harvest held
    12 — a live-only resolver silently discovers nothing, which is
    indistinguishable from "this device has no policies". Reading the cache also
    means discovery works while the appliance is down.
    """
    from ..models_cache import DeviceObject, DeviceServerPolicy
    from ..models import db
    from . import service_probe

    session = session or db.session

    # vserver name -> VIP address
    vserver_ip: dict[str, str] = {}
    vips = (session.query(DeviceObject)
            .filter(DeviceObject.appliance_id == appliance.id,
                    DeviceObject.logical_name == "vip",
                    DeviceObject.layer == "config").all())
    for obj in vips:
        payload = obj.payload or {}
        ip = str(payload.get("vip") or "").split("/", 1)[0].strip()
        if not ip or ip in ("0.0.0.0", "::"):
            continue
        for vs in _VSERVER_REF.findall(str(payload.get("q_ref_string") or "")):
            vserver_ip.setdefault(vs.strip(), ip)

    # custom service objects (name -> port), if the harvest captured them
    custom_ports: dict[str, int] = {}
    for obj in (session.query(DeviceObject)
                .filter(DeviceObject.appliance_id == appliance.id,
                        DeviceObject.logical_name.like("%service-custom%")).all()):
        payload = obj.payload or {}
        port = str(payload.get("port") or "").split("-")[0].strip()
        if obj.mkey and port.isdigit():
            custom_ports[obj.mkey] = int(port)

    out: list[dict] = []
    seen: set[str] = set()
    for pol in (session.query(DeviceServerPolicy)
                .filter(DeviceServerPolicy.appliance_id == appliance.id)
                .order_by(DeviceServerPolicy.name).all()):
        # The projection carries one row per harvest LAYER (config + deep), so
        # every policy shows up twice. Verified on fw6: 12 rows / 6 policies.
        key = (pol.name or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        https_svc = (pol.https_service or "").strip()
        http_svc = (pol.http_service or "").strip()
        service = https_svc or http_svc
        if not service:
            continue
        is_https = bool(https_svc)
        ip = vserver_ip.get((pol.vserver or "").strip(), "")
        if not ip:
            continue
        port = service_probe._port_for(service, custom_ports, is_https)
        scheme = "https" if is_https else "http"
        default = 443 if is_https else 80
        host = f"{ip}:{port}" if port != default else ip
        out.append({
            "policy": pol.name or "",
            "url": f"{scheme}://{host}/",
            "vserver": pol.vserver or "",
            "service": service,
            # A disabled policy is still worth a probe row (created disabled):
            # "the policy I turned off is now answering" is also a finding.
            "enabled": (pol.status or "").strip().lower() != "disable",
            "note": f"{scheme.upper()} · vserver {pol.vserver or '?'} · {service}",
        })
    return out


def discover_https_probes(appliance, *, session=None) -> dict:
    """Create one HTTP(S) probe per resolvable server policy on ``appliance``.

    Idempotent: an existing probe with the same URL is left alone, so re-running
    after adding a policy only adds the new one.
    """
    from ..models import MonitorProbe, db

    session = session or db.session
    if (appliance.kind or "fortiweb") != "fortiweb":
        return {"created": 0, "skipped": 0, "total_targets": 0,
                "error": "policy discovery is FortiWeb-only"}
    targets = resolve_targets_from_cache(appliance, session=session)
    have = {(p.url or "").strip() for p in
            session.query(MonitorProbe)
            .filter(MonitorProbe.appliance_id == appliance.id).all()}
    created, skipped = 0, 0
    for t in targets:
        url = t["url"]
        if not url or url in have:
            skipped += 1
            continue
        session.add(MonitorProbe(
            appliance_id=appliance.id, kind="https",
            name=f"{appliance.name} · {t['policy']}"[:120],
            target=t["policy"], url=url, enabled=t["enabled"], interval_min=5,
            note=t["note"][:250]))
        have.add(url)
        created += 1
    session.commit()
    return {"created": created, "skipped": skipped,
            "total_targets": len(targets)}


def ensure_baseline(appliance, *, session=None) -> dict:
    """Create the two device-level probes (interface watch + proxyd) if absent."""
    from ..models import MonitorProbe, db

    session = session or db.session
    made = []
    wanted = [("interface", f"{appliance.name} · interfaces", 15)]
    if (appliance.kind or "fortiweb") == "fortiweb":
        wanted.append(("proxyd", f"{appliance.name} · proxyd", 5))
    for kind, name, interval in wanted:
        exists = (session.query(MonitorProbe)
                  .filter(MonitorProbe.appliance_id == appliance.id,
                          MonitorProbe.kind == kind).first())
        if exists:
            continue
        session.add(MonitorProbe(appliance_id=appliance.id, kind=kind,
                                 name=name[:120], enabled=True,
                                 interval_min=interval))
        made.append(kind)
    session.commit()
    return {"created": made}
