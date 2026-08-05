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
               (``diagnose system top``). Grades the daemon ALONE — running or
               not, and whether its PID set changed, which is a silent restart
               no plain health check surfaces. The trended numbers are the
               megabytes of memory consumed and free, read from the ``Mem:``
               header of the same output; the daemon's own ``%VSZ`` is virtual
               size and is NOT reported as consumption (on fw6 the top eight
               processes sum to 240 % of RAM, because shared mappings are
               counted once per process).

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

KINDS = ("https", "interface", "cpu", "memory", "proxyd",
         "sessions", "policy_sessions", "throughput", "transactions",
         "licence", "tokens")

KIND_LABEL = {
    "https": "Service policy (HTTPS)",
    "interface": "Interface IP / link",
    "cpu": "Processor load",
    "memory": "Memory usage",
    "proxyd": "proxyd process",
    "sessions": "Concurrent sessions (box)",
    "policy_sessions": "Server-policy sessions & latency",
    "throughput": "HTTP throughput",
    "transactions": "HTTP transactions",
    "licence": "Licence headroom",
    "tokens": "FortiToken pool",
}

#: Which products each kind can actually measure. ONE map, consulted by the
#: runner, by discovery, by the baseline builder and by the form validator.
#:
#: This replaces four independent hardcodes (``API_PRODUCTS``, the "FortiWeb
#: only" branch in ``ensure_baseline``, the implicit fortiweb+fortiadc reach of
#: ``run_box``, and the absence of any check at all in ``apply_form``). Four
#: copies of a product rule is four chances to add a fifth product and cover it
#: in three places -- exactly how a probe ends up creatable from the form,
#: refused by the runner, and permanently red on the page.
#:
#: An EMPTY tuple means product-agnostic: ``https`` fires a synthetic request at
#: a URL and never speaks the appliance's API, so it works against anything that
#: serves HTTP -- including a device SATOM cannot otherwise read.
KIND_PRODUCTS = {
    # URL-based; touches no device API.
    "https":           (),
    # Reads the harvest cache. FortiAuthenticator is absent on purpose: its
    # REST surface (58 resources, censused 2026-08-05) exposes NO interface
    # resource, so there is nothing to cache and nothing to diff.
    "interface":       ("fortiweb", "fortiadc", "fortianalyzer"),
    # CPU/memory. FortiWeb and FortiADC answer `get system performance` over
    # the read-only CLI; FortiAuthenticator does NOT -- VERIFIED live on fac01
    # (v8.0.3 build0099, 2026-08-05): the CLI replies with the literal string
    # "No such command.", which parses to nothing and would have graded a
    # missing reading rather than erroring. FAC therefore reads REST instead
    # (see :func:`run_box`).
    # FortiAnalyzer is listed because it was ALREADY in scope before this map
    # existed: run_box had no product gate at all and ensure_baseline created
    # cpu/memory rows on every product. Whether that firmware answers
    # `get system performance` is UNVERIFIED (faz01 has been unreachable since
    # July), and dropping it here would have removed working coverage on the
    # strength of an assumption. Narrowing it is a separate decision, with a
    # live device to test against.
    "cpu":             ("fortiweb", "fortiadc", "fortianalyzer",
                        "fortiauthenticator"),
    "memory":          ("fortiweb", "fortiadc", "fortianalyzer",
                        "fortiauthenticator"),
    # `diagnose system top` -- FortiWeb only (also "No such command." on fac01).
    "proxyd":          ("fortiweb",),
    # FortiWeb runtime telemetry.
    "sessions":        ("fortiweb",),
    "policy_sessions": ("fortiweb",),
    "throughput":      ("fortiweb",),
    "transactions":    ("fortiweb",),
    # FortiAuthenticator runtime telemetry. An identity appliance has no
    # throughput to measure; what bounds it is how much of its LICENCE and its
    # token pool are consumed. Both come from one `systeminfo` call.
    "licence":         ("fortiauthenticator",),
    "tokens":          ("fortiauthenticator",),
}


def supports(kind: str, product: str | None) -> bool:
    """Can ``kind`` be measured on ``product``? Unknown kind -> False.

    An empty product tuple means "any device"; an unknown *product* is refused
    rather than assumed compatible, because a silently-attempted probe against
    the wrong product reports zeroes and a refusal reports the truth.
    """
    prods = KIND_PRODUCTS.get(kind)
    if prods is None:
        return False
    return (not prods) or ((product or "") in prods)


def kinds_for(product: str | None) -> tuple:
    """The kinds measurable on one product, in :data:`KINDS` order."""
    return tuple(k for k in KINDS if supports(k, product))


def products_for(kind: str) -> tuple:
    """Products supporting ``kind`` (empty tuple == every product)."""
    return tuple(KIND_PRODUCTS.get(kind) or ())

# Kinds that read the appliance's REST monitor API and never open an SSH
# session. Two consequences worth knowing:
#
#  * They keep reporting on an appliance whose *cmdb* is licence-locked.
#    VERIFIED on fw7 (2026-07-28): every cmdb read returns HTTP 423
#    ``-20010 The license of peer VM FortiWeb is not valid``, yet
#    ``status.systemresource``, ``policystatus`` and ``policytraffic`` all
#    answer 200. So these probes cover exactly the devices whose hourly
#    ``device_sync`` has been failing for days.
#  * They are FortiWeb-only. FortiADC and FortiAnalyzer expose runtime
#    telemetry under entirely different paths; a shared implementation would
#    have produced silent zeroes on those products rather than an error, so
#    discovery refuses to create them and the runner reports ``error``.
API_KINDS = ("sessions", "policy_sessions", "throughput", "transactions",
             "licence", "tokens")

#: Default cadence for a newly discovered probe, in minutes.
#:
#: MUST stay a multiple of the sweep action's interval. ``due_probes`` only
#: fires a probe when the whole interval has elapsed *and* a sweep tick
#: happens, so a probe whose interval is not a multiple of the tick runs
#: slower than its own configuration claims -- a 5-minute probe under a
#: 3-minute sweep is really a 6-minute probe, and nothing in the UI says so.
DEFAULT_PROBE_INTERVAL_MIN = 3

#: Endpoints that aggregate over hours are sampled coarsely on purpose.
SLOW_PROBE_INTERVAL_MIN = 15

#: Every product that owns at least one REST-telemetry kind. Derived, not
#: listed: adding a kind to :data:`KIND_PRODUCTS` enrols its product here in the
#: same edit, so the Service Monitor page cannot end up offering a product it
#: has no kinds for (or hiding one it does).
API_PRODUCTS = tuple(dict.fromkeys(
    prod for kind in API_KINDS for prod in KIND_PRODUCTS.get(kind, ())))

# The aggregate pseudo-policies ``policytraffic`` accepts in place of a real
# policy name (read out of the GUI's throughput widget). In VDOM mode the
# appliance renames them to "Administrative Domain <X> Traffic".
TOTAL_HTTP = "Total HTTP Throughput"
TRAFFIC_AGGREGATES = (
    TOTAL_HTTP, "Total ADFS Throughput", "Total FTP Throughput",
    "Administrative Domain HTTP Traffic", "Administrative Domain ADFS Traffic",
    "Administrative Domain FTP Traffic",
)

# ``policytraffic`` returns 60 one-second samples, so a 5-minute probe interval
# sees 60s of every 300s. That is a sampling window, not full coverage, and the
# payload records it so a flat chart is not mistaken for a flat link.
TRAFFIC_WINDOW_S = 60

# Units of the numeric thresholds, per kind. ``warn_num``/``crit_num`` are
# deliberately unit-less columns reused across kinds (same shape as
# ``warn_pct``/``crit_pct``); 0 disables that level.
NUM_UNIT = {
    "sessions": "sessions",
    "policy_sessions": "sessions",
    "throughput": "Mbps",
    "transactions": "transactions",
    # Both FortiAuthenticator kinds grade on PERCENT CONSUMED, not on units
    # remaining, so the threshold direction matches every other probe in the
    # product ("at or above is bad"). Grading tokens on "free remaining" would
    # have inverted the comparison for exactly one row on one page -- a trap for
    # whoever sets the next threshold. The absolute counts still appear in the
    # detail line and in the payload.
    "licence": "% consumed",
    "tokens": "% consumed",
}

# Box-level metrics, each its OWN probe kind. They used to ride along inside the
# proxyd check, which printed "MEM 59.7%" (the daemon's %VSZ) next to "box mem
# 52%" (the appliance's RAM) — two unrelated numbers with near-identical labels,
# and no way to give either its own threshold or interval. A pegged appliance
# and a restarted daemon are different incidents; they get different rows.
# The value indexes :func:`parse_performance` output.
BOX_METRICS = {
    "cpu": {"key": "cpu_busy", "label": "CPU"},
    "memory": {"key": "mem_used_pct", "label": "memory"},
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
# FortiADC answers the SAME command with different wording — VERIFIED live on
# fadc (2026-07-28): "CPU usage:  2% used, 98% idle" / "Memory usage: 62% used".
# One pattern covers both products; a FortiWeb-only pattern would have meant the
# CPU and memory probes silently produced nothing on FortiADC.
_PERF_CPU = re.compile(r"CPU\s+(?:states|usage)\s*:\s*(?P<used>[\d.]+)\s*%\s*used", re.I)
_PERF_MEM = re.compile(r"Memory\s+(?:states|usage)\s*:\s*(?P<used>[\d.]+)\s*%\s*used", re.I)
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
            summary.update(mem_total_mb=round(total, 1),
                           mem_used_mb=round(used, 1),
                           mem_free_mb=round(free, 1),
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
                           "mem_used_mb": round(total - free, 1),
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


def parse_ports(target: str | None) -> list[str]:
    """Ports an interface probe watches. Empty list = every port on the device."""
    raw = (target or "").replace(";", ",").replace("\n", ",")
    return [p.strip() for p in raw.split(",") if p.strip()]


def select_ports(rows: list[dict],
                 ports: list[str]) -> tuple[list[dict], list[str]]:
    """Filter harvested rows down to ``ports``. Returns ``(kept, missing)``.

    ``missing`` is returned rather than quietly ignored: a watched port that is
    no longer in the harvest is precisely the drift this probe exists to catch,
    and silently shortening the list would make the check read "all good".
    """
    if not ports:
        return list(rows or []), []
    want = {p.lower(): p for p in ports}
    kept = [r for r in (rows or [])
            if str(r.get("name") or "").strip().lower() in want]
    seen = {str(r.get("name") or "").strip().lower() for r in kept}
    return kept, sorted(orig for low, orig in want.items() if low not in seen)


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
                       stale_after_h: float,
                       missing: list[str] | None = None) -> tuple[str, str]:
    """Grade an interface snapshot: drift is a warn, a lost IP is critical.

    ``missing`` names watched ports the harvest no longer holds. That is graded
    critical: a port the operator explicitly selected disappearing is the
    loudest drift there is, and it must not degrade into "fewer interfaces".
    """
    if missing:
        return "crit", ("watched port(s) absent from the device cache: "
                        + ", ".join(missing))
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


def classify_box(kind: str, perf: dict, *, warn_pct: float,
                 crit_pct: float) -> tuple[str, str]:
    """Grade ONE box metric (CPU or memory) from ``get system performance``.

    Deliberately separate from :func:`classify_proxyd`. The source is the same
    command, but the question is not: "is the appliance under load" and "is the
    proxy daemon healthy" have different thresholds, different intervals and
    different owners. Two thresholds are exposed rather than one so a warning
    does not have to escalate to a page — ``crit_pct`` is the paging line.
    A threshold of 0 disables that level.
    """
    meta = BOX_METRICS.get(kind)
    if not meta:
        return "error", f"unknown box metric {kind!r}"
    val = perf.get(meta["key"])
    if val is None:
        return "error", (f"`{PERF_CMD}` returned no {meta['label']} reading — "
                         "raw output captured in the sample payload")
    bits = [f"{meta['label']} {val}%"]
    if kind == "cpu" and perf.get("cpu_idle") is not None:
        bits.append(f"{perf['cpu_idle']}% idle")
    if perf.get("uptime"):
        bits.append(f"up {perf['uptime']}")
    status = "ok"
    if crit_pct and val >= crit_pct:
        status = "crit"
        bits.append(f"at or over the critical threshold ({crit_pct}%)")
    elif warn_pct and val >= warn_pct:
        status = "warn"
        bits.append(f"over the warning threshold ({warn_pct}%)")
    return status, "; ".join(bits)


def fmt_memory(summary: dict) -> str:
    """``2328 MB used · 1398 MB free`` from a :func:`parse_top` summary."""
    used, free = summary.get("mem_used_mb"), summary.get("mem_free_mb")
    if used is None or free is None:
        return ""
    return f"{used:,.0f} MB used · {free:,.0f} MB free"


def classify_proxyd(agg: dict, parsed: dict, prev_fingerprint: str,
                    *, memory: dict | None = None) -> tuple[str, str]:
    """Grade the DAEMON alone: absent = critical, a new PID set = silent restart.

    Memory is REPORTED here, never graded, and it is reported as megabytes
    consumed and megabytes free — not as the daemon's ``%VSZ``. %VSZ is
    *virtual* size: measured live on fw6, the top eight processes sum to 240 %
    of installed RAM because every shared mapping is counted once per process.
    A number that can exceed 100 % is not "memory consumed" and must not be
    displayed as though it were.

    ``used``/``free`` come from the ``Mem:`` header of the SAME ``diagnose
    system top`` output — real, box-wide, and free of an extra round trip.

    There is deliberately NO memory threshold on this probe. Box memory belongs
    to the ``memory`` probe, which has warn *and* crit levels and already covers
    every appliance; thresholding it here as well would re-merge precisely what
    was split apart on 2026-07-28. Nor is there a per-process CPU threshold:
    BusyBox top reports 0.0 % on its first iteration, so it could never fire,
    and a threshold that cannot fire reads as health that was never measured.
    """
    if not parsed.get("parsed"):
        return "error", (f"could not parse `{TOP_CMD}` output — raw response "
                         "captured in the sample payload")
    if agg["count"] == 0:
        return "crit", f"{agg['process']} is NOT running"

    bits = [f"{agg['count']} worker" + ("s" if agg["count"] != 1 else "")]
    mem = fmt_memory(memory or {})
    bits.append(mem or "memory unreadable")
    status = "ok"
    if prev_fingerprint and prev_fingerprint != agg["pid_fingerprint"]:
        status = "warn"
        bits.append(f"PIDs CHANGED — {agg['process']} restarted since last check")
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
    ports = parse_ports(probe.target)
    rows, missing = select_ports(data.get("interfaces") or [], ports)
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
        cache_age_h=age_h, stale_after_h=float(probe.stale_after_h or 6),
        missing=missing)
    with_ip = sum(1 for s in slim if s["ip"])
    return {
        "status": status, "detail": detail,
        "value_num": with_ip, "value2_num": len(slim),
        "fingerprint": fingerprint,
        "payload": {"interfaces": slim, "cache_age_h": age_h,
                    "watching": ports or "all ports", "missing": missing,
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
    agg = select_process(parsed, probe.process_name or DEFAULT_PROCESS)
    mem = parsed.get("summary") or {}
    prev_fp = (prev.fingerprint or "") if prev is not None else ""
    status, detail = classify_proxyd(agg, parsed, prev_fp, memory=mem)
    # ONE SSH round trip: the `Mem:` header of `diagnose system top` already
    # carries real consumption, so no second command is needed for it.
    #
    # The trended pair is MEMORY CONSUMED and MEMORY FREE, both in MB. It used
    # to be the daemon's %VSZ and its worker count; %VSZ is virtual size and
    # overstates consumption by design, and the worker count survives in the
    # detail line, the payload and the PID fingerprint — which is what actually
    # detects a worker dying, since a restart changes the PID set whether or not
    # the count moves.
    return {
        "status": status, "detail": detail,
        "value_num": mem.get("mem_used_mb"),
        "value2_num": mem.get("mem_free_mb"),
        "fingerprint": agg["pid_fingerprint"],
        "payload": {"command": TOP_CMD, "process": agg["process"],
                    "count": agg["count"], "pids": agg["pids"],
                    "memory": mem,
                    "daemon_vsz_mb": agg.get("vsz_mb"),
                    "daemon_vsz_pct": agg.get("mem"),
                    "workers": agg["workers"][:12],
                    "load": parsed.get("load") or "",
                    "parsed": parsed.get("parsed"),
                    "cpu_per_process_reliable": parsed.get("cpu_per_process_reliable"),
                    "raw": (raw or "")[:4000]},
    }


def run_box(probe, kind: str) -> dict:
    """Read ``get system performance`` and grade ONE box metric. Never raises.

    Works on FortiWeb *and* FortiADC (both verified live). No product gate: a
    firmware that answers in either wording is covered, and one that does not
    returns ``error`` with the raw text rather than a fabricated number.
    """
    from . import ssh_ops

    meta = BOX_METRICS.get(kind)
    if not meta:
        return {"status": "error", "detail": f"unknown box metric {kind!r}",
                "payload": {}}
    if probe.appliance is None:
        return {"status": "error", "detail": "probe has no device", "payload": {}}
    # FortiAuthenticator has no `get system performance` -- VERIFIED live on
    # fac01 (v8.0.3 build0099): the CLI answers with the literal string
    # "No such command.", which is a successful SSH round trip carrying no
    # reading. Parsing it yields None and would have graded a device we simply
    # asked in the wrong language. Its CPU and memory come over REST instead.
    if (probe.appliance.kind or "") == "fortiauthenticator":
        return _run_box_rest(probe, kind)
    try:
        raw = ssh_ops.run_command(probe.appliance, PERF_CMD,
                                  timeout=float(probe.timeout_s or 15))
    except Exception as exc:  # noqa: BLE001 — an unreachable box is a result
        return {"status": "crit", "detail": f"CLI unreachable: {exc}",
                "payload": {"command": PERF_CMD, "error": str(exc)}}
    perf = parse_performance(raw)
    status, detail = classify_box(
        kind, perf, warn_pct=float(probe.warn_pct or 0),
        crit_pct=float(probe.crit_pct or 0))
    return {
        "status": status, "detail": detail,
        "value_num": perf.get(meta["key"]),
        "value2_num": perf.get("cpu_idle") if kind == "cpu" else None,
        "fingerprint": "",
        "payload": {"command": PERF_CMD, "metric": kind, "performance": perf,
                    "raw": (raw or "")[:2000]},
    }



# ---------------------------------------------------------------------------
# REST monitor API — pure parsing / classification
# ---------------------------------------------------------------------------

def _i(v: Any, default: int = 0) -> int:
    """Coerce to int. The appliance mixes ints and numeric STRINGS in the same
    payload (``policytraffic`` returns ``["0","0",...]``), so every read of a
    monitor field goes through this."""
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def parse_system_resource(res: Any) -> dict:
    """Normalise ``system/status.systemresource``.

    Live shape on fortiweb08 7.6.8::

        {"cpu": 5, "mem": 51, "logDisk": "Available", "dbStatus": "Available",
         "diskUsage": 1, "sessionCount": 0, "connCntPerSec": 0}
    """
    if not isinstance(res, dict):
        return {}
    return {
        "cpu_pct": _i(res.get("cpu")),
        "mem_pct": _i(res.get("mem")),
        "disk_pct": _i(res.get("diskUsage")),
        "sessions": _i(res.get("sessionCount")),
        "conn_per_sec": _i(res.get("connCntPerSec")),
        "log_disk": str(res.get("logDisk") or "").strip(),
        "db_status": str(res.get("dbStatus") or "").strip(),
    }


def classify_sessions(box: dict, *, warn_num: float, crit_num: float) -> tuple[str, str]:
    """Grade the box-wide concurrent session count.

    The subsystem strings are graded too: ``logDisk``/``dbStatus`` turning
    anything other than *Available* means the appliance is still passing traffic
    while losing its own telemetry, which no session count would reveal.
    """
    if not box:
        return "error", "device returned no resource data"
    bits = ["%d sessions" % box["sessions"], "%d conn/s" % box["conn_per_sec"]]
    status = "ok"
    for label, value in (("log disk", box["log_disk"]), ("DB", box["db_status"])):
        if value and value.lower() != "available":
            bits.append("%s %s" % (label, value))
            status = "warn"
    n = box["sessions"]
    if crit_num and n >= crit_num:
        status = "crit"
        bits.append(">= crit %g" % crit_num)
    elif warn_num and n >= warn_num:
        status = worst([status, "warn"])
        bits.append(">= warn %g" % warn_num)
    return status, "; ".join(bits)


def parse_policy_rows(rows: Any) -> list[dict]:
    """Normalise ``policy/policystatus``.

    ``policy`` is the appliance's RUNTIME handle for the policy (1488, 1489 …),
    distinct from the display ``id``. It is carried into the fingerprint: see
    :func:`policy_fingerprint`.
    """
    out = []
    for r in (rows or []):
        if not isinstance(r, dict):
            continue
        out.append({
            "name": str(r.get("name") or r.get("_id") or "").strip(),
            "handle": _i(r.get("policy"), -1),
            "status": str(r.get("status") or "").strip(),
            "protocol": str(r.get("protocol") or "").strip(),
            "vserver": str(r.get("vserver") or "").strip(),
            "port": str(r.get("httpPort") or "").strip(),
            "sessions": _i(r.get("sessionCount")),
            "conn_per_sec": _i(r.get("connCntPerSec")),
            "client_rtt": _i(r.get("client_rtt")),
            "server_rtt": _i(r.get("server_rtt")),
            "app_response_time": _i(r.get("app_response_time")),
        })
    return out


def parse_pool_members(rows: Any) -> list[dict]:
    """Normalise ``policy/policystatus.detail`` (one row per pool member)."""
    out = []
    for r in (rows or []):
        if not isinstance(r, dict):
            continue
        out.append({
            "pool": str(r.get("pool") or "").strip(),
            "server": str(r.get("ipDomainName") or "").strip(),
            "port": _i(r.get("port")),
            "health": str(r.get("healthCheckStatus") or "").strip() or "N/A",
            "sessions": _i(r.get("sessionCount")),
            "up": _i(r.get("status")) == 1,
            "server_rtt": _i(r.get("server_rtt")),
            "app_response_time": _i(r.get("app_response_time")),
        })
    return out


def policy_fingerprint(row: dict, members: list[dict]) -> str:
    """Fingerprint the policy's *shape*, not its load.

    Covers the administrative status, the runtime ``policy`` handle and each
    pool member's up/health — so a policy being disabled, a backend flapping, or
    the appliance reassigning handles all register as an event even while the
    session count sits at zero.

    NOTE on the handle: a proxyd restart re-creating its policy table would
    change these numbers, which would make this an API-only restart signal.
    That is inference, NOT verified — confirming it requires restarting proxyd
    on a live appliance. The CLI ``proxyd`` probe watches the actual PID set and
    remains the authoritative restart check.
    """
    parts = ["%s=%s@%d" % (row.get("name"), row.get("status"), row.get("handle", -1))]
    for m in sorted(members, key=lambda x: (x["server"], x["port"])):
        parts.append("%s:%d=%s/%s" % (m["server"], m["port"],
                                      "up" if m["up"] else "down", m["health"]))
    return sha8("|".join(parts))


def classify_policy_sessions(row: dict, members: list[dict], *,
                             warn_num: float, crit_num: float,
                             warn_ms: int, fingerprint: str,
                             prev_fingerprint: str) -> tuple[str, str]:
    """Grade one server policy.

    A *disabled* policy is reported ``warn``, never ``ok``: a policy that is not
    admitting traffic is the outage, and grading it green because it has no
    sessions would hide exactly the failure this page exists to show.
    """
    if not row:
        return "error", "policy not present in policystatus"
    bits = ["%d sessions" % row["sessions"], "%d conn/s" % row["conn_per_sec"]]
    status = "ok"
    if row["status"].lower() != "enable":
        status = "warn"
        bits.append("policy %s" % (row["status"] or "unknown"))
    art = row["app_response_time"]
    if art:
        bits.append("app %d ms" % art)
        if warn_ms and art >= warn_ms:
            status = worst([status, "warn"])
            bits.append(">= %d ms" % warn_ms)
    down = [m for m in members if not m["up"] or m["health"].lower() == "disable"]
    if members:
        bits.append("%d/%d backends up" % (len(members) - len(down), len(members)))
    if down and len(down) == len(members):
        status = "crit"
        bits.append("ALL backends down")
    elif down:
        status = worst([status, "warn"])
        bits.append("down: " + ", ".join("%s:%d" % (m["server"], m["port"])
                                        for m in down[:4]))
    n = row["sessions"]
    if crit_num and n >= crit_num:
        status = "crit"
        bits.append(">= crit %g" % crit_num)
    elif warn_num and n >= warn_num:
        status = worst([status, "warn"])
        bits.append(">= warn %g" % warn_num)
    if prev_fingerprint and fingerprint != prev_fingerprint:
        status = worst([status, "warn"])
        bits.append("shape changed since last sample")
    return status, "; ".join(bits)


def parse_traffic(res: Any) -> dict:
    """Normalise ``policy/policytraffic``.

    Two shapes, both live-verified: a bare list for the aggregate
    pseudo-policies, and ``{throughput, cache_enabled, cache_tp}`` for a named
    policy. Values are **bytes per second**, oldest sample first — the GUI
    renders ``value * 8 / 1024`` as Kb/s.
    """
    cache_enabled = False
    cache: list[int] | None = None
    if isinstance(res, dict):
        series = res.get("throughput") or []
        cache_enabled = bool(res.get("cache_enabled"))
        if cache_enabled:
            cache = [_i(v) for v in (res.get("cache_tp") or [])]
    elif isinstance(res, list):
        series = res
    else:
        return {}
    return {"bps": [_i(v) for v in series],
            "cache_enabled": cache_enabled, "cache_bps": cache}


def traffic_stats(bps: list[int]) -> dict:
    """Average / peak / latest throughput over the returned window.

    Peak is kept alongside the average because a four-second burst vanishes into
    a 60-point mean, and the burst is usually what the operator opened the chart
    to find.
    """
    if not bps:
        return {"samples": 0, "avg_bps": 0.0, "peak_bps": 0.0, "last_bps": 0.0,
                "avg_mbps": 0.0, "peak_mbps": 0.0, "last_mbps": 0.0}
    avg = sum(bps) / float(len(bps))
    peak = float(max(bps))
    last = float(bps[-1])
    mb = lambda v: round(v * 8.0 / 1_000_000.0, 4)  # noqa: E731
    return {"samples": len(bps), "avg_bps": avg, "peak_bps": peak,
            "last_bps": last, "avg_mbps": mb(avg), "peak_mbps": mb(peak),
            "last_mbps": mb(last)}


def fmt_mbps(v: float) -> str:
    if v >= 1.0:
        return "%.2f Mbps" % v
    return "%.0f Kbps" % (v * 1000.0)


def classify_throughput(stats: dict, *, warn_num: float,
                        crit_num: float) -> tuple[str, str]:
    """Grade throughput on the PEAK of the window, in Mbps.

    Peak rather than average: a link saturating for part of the window is the
    event, and averaging it away is how a saturation alert gets missed.
    """
    if not stats or not stats.get("samples"):
        return "error", "device returned no traffic samples"
    bits = ["avg %s" % fmt_mbps(stats["avg_mbps"]),
            "peak %s" % fmt_mbps(stats["peak_mbps"]),
            "%ds window" % stats["samples"]]
    status = "ok"
    peak = stats["peak_mbps"]
    if crit_num and peak >= crit_num:
        status = "crit"
        bits.append(">= crit %g Mbps" % crit_num)
    elif warn_num and peak >= warn_num:
        status = "warn"
        bits.append(">= warn %g Mbps" % warn_num)
    return status, "; ".join(bits)


def parse_transactions(rows: Any) -> dict:
    """Normalise ``system/status.httptransactions`` (``[{time, count}, ...]``)."""
    buckets = []
    for r in (rows or []):
        if not isinstance(r, dict):
            continue
        buckets.append({"time": str(r.get("time") or ""), "count": _i(r.get("count"))})
    total = sum(b["count"] for b in buckets)
    return {"buckets": buckets, "total": total,
            "last": buckets[-1]["count"] if buckets else 0,
            "peak": max((b["count"] for b in buckets), default=0)}


def classify_transactions(tx: dict, *, warn_num: float, crit_num: float,
                          carrying: dict | None = None) -> tuple[str, str]:
    """Grade HTTP transaction volume over the window.

    An empty bucket list is ``error``, not ``ok``: the appliance answers
    ``errcode 0`` with no rows when the policy name is unknown, so "no buckets"
    means the probe is misconfigured rather than idle.

    An all-zero bucket list is ``warn`` when ``policystatus`` says the policy is
    carrying traffic. VERIFIED on fortiweb08, 2026-07-28: a policy handling
    ~2 700 req/s over a measured six-minute load test reported **0**
    transactions in every bucket, and the same policy reported **417 059** the
    moment a ``web-protection-profile`` was attached to it — nothing else
    changed, and enabling the global traffic log beforehand had made no
    difference. [Probable] the per-policy counter is keyed off the protection
    profile, so a policy without one is invisible to this endpoint.

    Whatever the mechanism, the failure mode is the one this codebase refuses to
    ship: a silent zero that grades ``ok`` on a saturated service. ``carrying``
    is the policy's row from ``policystatus`` (sessions / conn-per-sec); it is
    only ever fetched when the count is zero, so the normal path costs nothing.
    """
    if not tx or not tx["buckets"]:
        return "error", "no transaction buckets returned (unknown policy name?)"
    if not tx["total"] and carrying:
        live = max(_i(carrying.get("sessions")), _i(carrying.get("conn_per_sec")))
        if live > 0:
            return "warn", (
                "0 transactions reported, but the policy is carrying traffic "
                "right now (%d session(s), %d conn/s) — this endpoint reports "
                "nothing for a policy with no web-protection-profile attached"
                % (_i(carrying.get("sessions")),
                   _i(carrying.get("conn_per_sec"))))
    bits = ["%d transactions" % tx["total"],
            "peak %d/bucket" % tx["peak"],
            "%d buckets" % len(tx["buckets"])]
    status = "ok"
    if crit_num and tx["total"] >= crit_num:
        status = "crit"
        bits.append(">= crit %g" % crit_num)
    elif warn_num and tx["total"] >= warn_num:
        status = "warn"
        bits.append(">= warn %g" % warn_num)
    return status, "; ".join(bits)


# ---------------------------------------------------------------------------
# REST monitor API — runners (network I/O)
# ---------------------------------------------------------------------------

def _api_client(probe):
    """Build the monitor-API client this probe needs, or explain why we cannot.

    Returns ``(client, error_dict)``. The gate is per KIND, not per page: a
    FortiAuthenticator supports ``licence``/``tokens`` and nothing else, a
    FortiWeb the four traffic kinds and nothing else, and the refusal names both
    the kind and the product. Falling through to a shared client would have
    reported zeroes on a device that merely answers different paths -- and a
    zero on a monitoring page reads as "idle", not as "asked the wrong box".
    """
    ap = getattr(probe, "appliance", None)
    if ap is None:
        return None, {"status": "error", "detail": "probe has no device",
                      "payload": {}}
    kind = getattr(probe, "kind", "") or ""
    product = ap.kind or ""
    if not supports(kind, product):
        allowed = products_for(kind) or ("any product",)
        return None, {"status": "error",
                      "detail": "%s probes support %s only (device is %s)"
                                % (KIND_LABEL.get(kind, kind or "monitor API"),
                                   "/".join(allowed), product or "unknown"),
                      "payload": {"product": product, "kind": kind}}
    if product == "fortiauthenticator":
        from ..clients.fortiauthenticator import FortiAuthenticatorClient
        return (FortiAuthenticatorClient(ap, timeout=float(probe.timeout_s or 15)),
                None)
    from ..clients.fortiweb import FortiWebClient
    return FortiWebClient(ap, timeout=float(probe.timeout_s or 15)), None


def run_sessions(probe) -> dict:
    """Box-wide concurrent sessions + connection rate, over REST."""
    client, err = _api_client(probe)
    if err:
        return err
    res, error = client.system_resource()
    if error:
        return {"status": "crit", "detail": "API unreachable: %s" % error,
                "payload": {"endpoint": "system/status.systemresource",
                            "error": error}}
    box = parse_system_resource(res)
    status, detail = classify_sessions(
        box, warn_num=float(probe.warn_num or 0),
        crit_num=float(probe.crit_num or 0))
    return {
        "status": status, "detail": detail,
        "value_num": box.get("sessions"),
        "value2_num": box.get("conn_per_sec"),
        "fingerprint": sha8("%s|%s" % (box.get("log_disk"), box.get("db_status"))),
        "payload": {"endpoint": "system/status.systemresource", "box": box,
                    "raw": res},
    }


def run_policy_sessions(probe, prev) -> dict:
    """Sessions, connection rate and latency for ONE server policy.

    Two calls: ``policystatus`` for the policy row and ``policystatus.detail``
    for its pool members. The member call is best-effort — losing backend health
    must degrade the detail, not void the session count.
    """
    client, err = _api_client(probe)
    if err:
        return err
    name = (probe.target or "").strip()
    if not name:
        return {"status": "error", "detail": "probe has no policy name",
                "payload": {}}
    rows, error = client.policy_status()
    if error:
        return {"status": "crit", "detail": "API unreachable: %s" % error,
                "payload": {"endpoint": "policy/policystatus", "error": error}}
    parsed = parse_policy_rows(rows)
    row = next((r for r in parsed if r["name"] == name), None)
    if row is None:
        return {"status": "crit",
                "detail": "policy %r not reported by the device (deleted?)" % name,
                "payload": {"endpoint": "policy/policystatus",
                            "known": [r["name"] for r in parsed]}}
    members, m_err = client.policy_health(name)
    parsed_members = parse_pool_members(members)
    fp = policy_fingerprint(row, parsed_members)
    status, detail = classify_policy_sessions(
        row, parsed_members,
        warn_num=float(probe.warn_num or 0), crit_num=float(probe.crit_num or 0),
        warn_ms=int(probe.warn_ms or 0), fingerprint=fp,
        prev_fingerprint=(prev.fingerprint if prev else ""))
    if m_err:
        detail = "%s; backend health unavailable: %s" % (detail, m_err)
    return {
        "status": status, "detail": detail,
        "value_num": row["sessions"], "value2_num": row["app_response_time"],
        "fingerprint": fp,
        "payload": {"endpoint": "policy/policystatus(+.detail)", "policy": row,
                    "members": parsed_members, "members_error": m_err},
    }


def run_throughput(probe) -> dict:
    """HTTP throughput for one policy, or for the ``Total HTTP Throughput``
    aggregate when the probe targets it."""
    client, err = _api_client(probe)
    if err:
        return err
    name = (probe.target or "").strip() or TOTAL_HTTP
    res, error = client.policy_traffic(name)
    if error:
        return {"status": "crit", "detail": "API unreachable: %s" % error,
                "payload": {"endpoint": "policy/policytraffic", "target": name,
                            "error": error}}
    tr = parse_traffic(res)
    stats = traffic_stats(tr.get("bps") or [])
    status, detail = classify_throughput(
        stats, warn_num=float(probe.warn_num or 0),
        crit_num=float(probe.crit_num or 0))
    if tr.get("cache_enabled"):
        c = traffic_stats(tr.get("cache_bps") or [])
        detail = "%s; cached avg %s" % (detail, fmt_mbps(c["avg_mbps"]))
    return {
        "status": status, "detail": detail,
        "value_num": stats["avg_mbps"], "value2_num": stats["peak_mbps"],
        "fingerprint": "",
        "payload": {"endpoint": "policy/policytraffic", "target": name,
                    "stats": stats, "cache_enabled": tr.get("cache_enabled"),
                    "window_s": stats["samples"], "unit": "Mbps",
                    "note": "device returns %ds of 1s samples in bytes/s"
                            % TRAFFIC_WINDOW_S},
    }


def run_transactions(probe) -> dict:
    """HTTP transaction counts for one policy over ``stale_after_h`` hours."""
    client, err = _api_client(probe)
    if err:
        return err
    name = (probe.target or "").strip()
    if not name:
        return {"status": "error", "detail": "probe has no policy name",
                "payload": {}}
    if name in TRAFFIC_AGGREGATES:
        return {"status": "error",
                "detail": "httptransactions needs a real policy name, not %r" % name,
                "payload": {"target": name}}
    hours = max(1, int(probe.stale_after_h or 1))
    rows, error = client.http_transactions(name, hours)
    if error:
        return {"status": "crit", "detail": "API unreachable: %s" % error,
                "payload": {"endpoint": "system/status.httptransactions",
                            "target": name, "error": error}}
    tx = parse_transactions(rows)
    # Only when the answer is zero do we pay for a second call, to tell "idle"
    # apart from "cannot report" (see classify_transactions). A failure here is
    # swallowed on purpose: the cross-check is a refinement of the grade, and
    # losing it must not turn a working probe into an error.
    carrying = None
    if not tx["total"]:
        try:
            rows2, err2 = client.policy_status()
            if not err2:
                carrying = next((p for p in parse_policy_rows(rows2)
                                 if p["name"] == name), None)
        except Exception:  # noqa: BLE001
            carrying = None
    status, detail = classify_transactions(
        tx, warn_num=float(probe.warn_num or 0),
        crit_num=float(probe.crit_num or 0), carrying=carrying)
    return {
        "status": status, "detail": "%s over %dh" % (detail, hours),
        "value_num": tx["total"], "value2_num": tx["last"],
        "fingerprint": "",
        "payload": {"endpoint": "system/status.httptransactions",
                    "target": name, "hours": hours, "total": tx["total"],
                    "peak": tx["peak"], "buckets": tx["buckets"][-24:],
                    "live_sessions": (carrying or {}).get("sessions"),
                    "live_conn_per_sec": (carrying or {}).get("conn_per_sec")},
    }

# ---------------------------------------------------------------------------
# FortiAuthenticator monitor API — pure parsing / classification
# ---------------------------------------------------------------------------
#
# Everything below reads ONE call: ``GET /api/v1/systeminfo/``. Measured on
# fac01 at 15-50 ms, and it carries the whole picture -- cpu, memory, disk, the
# per-feature licence counters, the FortiToken pools and the HA peer serial. A
# probe per counter would have multiplied round trips for data that is free in
# aggregate (the lesson already paid for in ``metrics_collect``).
#
# Live shape, VERIFIED 2026-08-05 (fac01, FACVMKVM v8.0.3 build0099):
#
#     {"cpu": "0%", "memory": "64%", "disk": "0%",
#      "memory_usage_detail": {"available": "1427344.0 KB",
#                              "total": "4032452.0 KB",
#                              "used": "2605108.0 KB"},
#      "disk_usage_detail":   {"total": "59768832.0 KB", "used": "0.0 KB"},
#      "users_usage_detail":  {"max": 5, "used": 2},
#      "groups_usage_detail": {"max": 3, "used": 0},
#      "fsso_usage_detail":   {"max": 5, "used": 0},
#      "ssoma_usage_detail":  {"max": 5, "used": 0},
#      "ftk_usage_detail":    {"populated": 0, "used": 0},
#      "ftm_usage_detail":    {"populated": 0, "used": 0},
#      "ha_sn": "", "sn": "FAC-VM0000000000",
#      "firmware": "FACVMKVM v8.0.3, build0099 (GA)"}
#
# Note the two spellings of "how much of it exists": the licence counters use
# ``max``, the token pools use ``populated``. They are NOT interchangeable --
# ``max`` is what the licence permits, ``populated`` is what has actually been
# imported -- so they are read by name, never by position.

#: Licence counters graded by the ``licence`` kind: target -> (field, label).
FAC_CAPACITY = {
    "users":  ("users_usage_detail",  "licensed users"),
    "groups": ("groups_usage_detail", "user groups"),
    "fsso":   ("fsso_usage_detail",   "FSSO users"),
    "ssoma":  ("ssoma_usage_detail",  "SSO mobility agents"),
}

#: Token pools graded by the ``tokens`` kind: target -> (field, label).
FAC_TOKENS = {
    "ftm": ("ftm_usage_detail", "FortiToken Mobile"),
    "ftk": ("ftk_usage_detail", "hardware FortiTokens"),
}

DEFAULT_FAC_RESOURCE = "users"
DEFAULT_FAC_TOKEN = "ftm"

_PCT_TEXT = re.compile(r"(?P<v>\d+(?:\.\d+)?)")
_KB_TEXT = re.compile(r"(?P<v>\d+(?:\.\d+)?)\s*(?P<unit>[KMGT]?B)?", re.I)
_KB_MULT = {"B": 1, "KB": 1024, "MB": 1024 ** 2,
            "GB": 1024 ** 3, "TB": 1024 ** 4}


def fac_pct(value: Any) -> float | None:
    """``"64%"`` / ``64`` / ``"64"`` -> ``64.0``; anything else -> ``None``.

    The device sends percentages as SUFFIXED STRINGS. ``float("64%")`` raises,
    so a naive coercion would have turned every reading into an exception and
    every exception into an ``error`` sample on a healthy box.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    m = _PCT_TEXT.search(str(value))
    return float(m.group("v")) if m else None


def fac_bytes(value: Any) -> int | None:
    """``"4032452.0 KB"`` -> bytes. Unit-less numbers are assumed KB, which is
    what every ``*_usage_detail`` field on this firmware uses."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(float(value) * 1024)
    m = _KB_TEXT.search(str(value))
    if not m:
        return None
    unit = (m.group("unit") or "KB").upper()
    return int(float(m.group("v")) * _KB_MULT.get(unit, 1024))


def _usage(block: Any, total_key: str) -> dict | None:
    """Normalise one ``*_usage_detail`` block to ``{used, total, pct}``.

    ``total`` may legitimately be 0 (an unlicensed feature, or a token pool
    with nothing imported). ``pct`` is then ``None`` -- NOT 0 -- because "none
    of an empty pool is consumed" and "this feature has no ceiling" are both
    true and neither is a health reading.
    """
    if not isinstance(block, dict):
        return None
    used = _i(block.get("used"))
    total = _i(block.get(total_key))
    pct = round(used / total * 100.0, 1) if total > 0 else None
    return {"used": used, "total": total, "pct": pct}


def parse_fac_systeminfo(info: Any) -> dict:
    """``GET /api/v1/systeminfo/`` -> one flat dict every FAC reader shares.

    Single parser on purpose: the ``cpu``/``memory`` probes, the ``licence``
    and ``tokens`` probes and the ``box``/``capacity`` scrape collectors all
    consume this. Two parsers would be two places for the vendor's next field
    rename to be half-fixed.

    The client already unwraps the singleton, but a *collection* shape is
    tolerated here (first row) so a firmware that starts wrapping this resource
    degrades to correct rather than to empty.
    """
    if isinstance(info, list):
        info = info[0] if info and isinstance(info[0], dict) else {}
    if not isinstance(info, dict):
        info = {}
    out: dict = {
        "cpu_busy": fac_pct(info.get("cpu")),
        "mem_used_pct": fac_pct(info.get("memory")),
        "disk_used_pct": fac_pct(info.get("disk")),
        "firmware": str(info.get("firmware") or ""),
        "sn": str(info.get("sn") or ""),
        "ha_peer_sn": str(info.get("ha_sn") or ""),
    }
    mem = info.get("memory_usage_detail") or {}
    disk = info.get("disk_usage_detail") or {}
    out["mem_used_bytes"] = fac_bytes(mem.get("used"))
    out["mem_total_bytes"] = fac_bytes(mem.get("total"))
    out["mem_available_bytes"] = fac_bytes(mem.get("available"))
    out["disk_used_bytes"] = fac_bytes(disk.get("used"))
    out["disk_total_bytes"] = fac_bytes(disk.get("total"))
    out["capacity"] = {key: _usage(info.get(field), "max")
                       for key, (field, _lbl) in FAC_CAPACITY.items()}
    out["tokens"] = {key: _usage(info.get(field), "populated")
                     for key, (field, _lbl) in FAC_TOKENS.items()}
    return out


def _grade_pct(pct: float, *, warn_num: float, crit_num: float) -> tuple[str, str]:
    """Shared threshold ladder for the two FAC kinds. Direction is the same as
    every other probe in the product: at or above the line is bad. 0 disables."""
    if crit_num and pct >= crit_num:
        return "crit", "at or over the critical threshold (%g%%)" % crit_num
    if warn_num and pct >= warn_num:
        return "warn", "over the warning threshold (%g%%)" % warn_num
    return "ok", ""


def classify_licence(resource: str, cap: dict | None, *,
                     warn_num: float, crit_num: float) -> tuple[str, str]:
    """Grade one licence counter on PERCENT CONSUMED.

    This is the FortiAuthenticator's throughput gauge. An identity appliance
    does not run out of bandwidth, it runs out of *entitlement*: fac01 ships
    ``users_usage_detail {max: 5}`` unlicensed, and the 6th user is simply
    refused authentication.

    A ceiling of 0 is ``unknown``, never ``ok``. It means the device declared
    no limit for this feature, and reporting an unmeasured feature as healthy
    is the exact failure the Fleet health badge was rebuilt to stop.
    """
    label = FAC_CAPACITY.get(resource, (None, resource))[1]
    if cap is None:
        return "error", "device did not report %s usage" % label
    if cap["total"] <= 0:
        return "unknown", ("%s: no ceiling reported (%d in use) -- feature "
                           "unlicensed, or unlimited on this model"
                           % (label, cap["used"]))
    pct = cap["pct"] or 0.0
    status, note = _grade_pct(pct, warn_num=warn_num, crit_num=crit_num)
    bits = ["%d of %d %s (%.1f%%)" % (cap["used"], cap["total"], label, pct),
            "%d free" % max(0, cap["total"] - cap["used"])]
    if note:
        bits.append(note)
    return status, "; ".join(bits)


def classify_tokens(ttype: str, tok: dict | None, *,
                    warn_num: float, crit_num: float) -> tuple[str, str]:
    """Grade one FortiToken pool on PERCENT ASSIGNED.

    Graded in the same direction as everything else even though the operator's
    worry is the opposite one ("am I running OUT of tokens"): a page where one
    row's threshold means "at or below" is a page where the next threshold gets
    set backwards. The free count is in the detail line and in ``value2_num``.

    An empty pool is ``unknown``. Zero imported tokens is a legitimate state on
    a device that does not use MFA, and 0 % of nothing is not health.
    """
    label = FAC_TOKENS.get(ttype, (None, ttype))[1]
    if tok is None:
        return "error", "device did not report %s inventory" % label
    if tok["total"] <= 0:
        return "unknown", ("no %s loaded on this device -- nothing to assign, "
                           "so nothing to grade" % label)
    pct = tok["pct"] or 0.0
    status, note = _grade_pct(pct, warn_num=warn_num, crit_num=crit_num)
    bits = ["%d of %d %s assigned (%.1f%%)"
            % (tok["used"], tok["total"], label, pct),
            "%d free" % max(0, tok["total"] - tok["used"])]
    if note:
        bits.append(note)
    return status, "; ".join(bits)


def _fac_systeminfo(probe):
    """``(parsed, error_dict)`` -- one systeminfo read, shared by three kinds."""
    client, err = _api_client(probe)
    if err:
        return None, err
    try:
        info = client.sys_status()
    except Exception as exc:  # noqa: BLE001 -- an unreachable box is a result
        return None, {"status": "crit",
                      "detail": "monitor API unreachable: %s" % exc,
                      "payload": {"endpoint": "/api/v1/systeminfo/",
                                  "error": str(exc)}}
    return parse_fac_systeminfo(info), None


def _run_box_rest(probe, kind: str) -> dict:
    """CPU / memory for a FortiAuthenticator, read over REST."""
    meta = BOX_METRICS.get(kind)
    if not meta:
        return {"status": "error", "detail": "unknown box metric %r" % kind,
                "payload": {}}
    parsed, err = _fac_systeminfo(probe)
    if err:
        return err
    val = parsed.get(meta["key"])
    if val is None:
        return {"status": "error",
                "detail": ("/api/v1/systeminfo/ returned no %s reading -- "
                           "parsed fields captured in the sample payload"
                           % meta["label"]),
                "payload": {"endpoint": "/api/v1/systeminfo/",
                            "metric": kind, "parsed": parsed}}
    status, note = _grade_pct(float(val), warn_num=float(probe.warn_pct or 0),
                              crit_num=float(probe.crit_pct or 0))
    bits = ["%s %g%%" % (meta["label"], val)]
    if kind == "memory" and parsed.get("mem_used_bytes"):
        bits.append("%d MB used of %d MB"
                    % (parsed["mem_used_bytes"] // (1024 ** 2),
                       (parsed.get("mem_total_bytes") or 0) // (1024 ** 2)))
    if note:
        bits.append(note)
    return {
        "status": status, "detail": "; ".join(bits),
        "value_num": float(val),
        "value2_num": (parsed.get("disk_used_pct") if kind == "memory" else None),
        "fingerprint": "",
        "payload": {"endpoint": "/api/v1/systeminfo/", "metric": kind,
                    "transport": "rest", "parsed": parsed},
    }


def run_licence(probe) -> dict:
    """Licence headroom for one counter (users / groups / fsso / ssoma)."""
    resource = ((probe.target or "").strip().lower() or DEFAULT_FAC_RESOURCE)
    if resource not in FAC_CAPACITY:
        return {"status": "error",
                "detail": "unknown licence counter %r -- pick one of %s"
                          % (resource, ", ".join(sorted(FAC_CAPACITY))),
                "payload": {"target": resource,
                            "choices": sorted(FAC_CAPACITY)}}
    parsed, err = _fac_systeminfo(probe)
    if err:
        return err
    cap = (parsed.get("capacity") or {}).get(resource)
    status, detail = classify_licence(
        resource, cap, warn_num=float(probe.warn_num or 0),
        crit_num=float(probe.crit_num or 0))
    return {
        "status": status, "detail": detail,
        "value_num": (cap or {}).get("pct"),
        "value2_num": (cap or {}).get("used"),
        # The CEILING is in the fingerprint, not just the usage: a relicensing
        # (5 -> 500 users) is an event worth surfacing in the change strip, and
        # a percentage alone would show it as a sudden drop in consumption.
        "fingerprint": sha8("%s:%s" % (resource, (cap or {}).get("total"))),
        "payload": {"endpoint": "/api/v1/systeminfo/", "target": resource,
                    "capacity": parsed.get("capacity"),
                    "sn": parsed.get("sn"), "firmware": parsed.get("firmware")},
    }


def run_tokens(probe) -> dict:
    """FortiToken pool consumption (ftm / ftk)."""
    ttype = ((probe.target or "").strip().lower() or DEFAULT_FAC_TOKEN)
    if ttype not in FAC_TOKENS:
        return {"status": "error",
                "detail": "unknown token pool %r -- pick one of %s"
                          % (ttype, ", ".join(sorted(FAC_TOKENS))),
                "payload": {"target": ttype, "choices": sorted(FAC_TOKENS)}}
    parsed, err = _fac_systeminfo(probe)
    if err:
        return err
    tok = (parsed.get("tokens") or {}).get(ttype)
    status, detail = classify_tokens(
        ttype, tok, warn_num=float(probe.warn_num or 0),
        crit_num=float(probe.crit_num or 0))
    free = (max(0, tok["total"] - tok["used"]) if tok else None)
    return {
        "status": status, "detail": detail,
        "value_num": (tok or {}).get("pct"), "value2_num": free,
        "fingerprint": sha8("%s:%s" % (ttype, (tok or {}).get("total"))),
        "payload": {"endpoint": "/api/v1/systeminfo/", "target": ttype,
                    "tokens": parsed.get("tokens"), "free": free},
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
    product = getattr(getattr(probe, "appliance", None), "kind", "") or ""
    try:
        if probe.kind not in KINDS:
            out = {"status": "error",
                   "detail": f"unknown probe kind {probe.kind!r}", "payload": {}}
        # One gate for every kind, before any transport is opened. Without it a
        # probe the form let you create is a probe the runner answers with a
        # transport-level exception -- "CLI unreachable", "API unreachable" --
        # which reads as a broken device rather than an inapplicable check.
        elif not supports(probe.kind, product):
            out = {"status": "error",
                   "detail": "%s is not measurable on %s (supported: %s)"
                             % (KIND_LABEL.get(probe.kind, probe.kind),
                                product or "an unknown product",
                                "/".join(products_for(probe.kind) or ("any",))),
                   "payload": {"kind": probe.kind, "product": product}}
        elif probe.kind == "https":
            out = run_https(probe)
        elif probe.kind == "interface":
            out = run_interface(probe, prev)
        elif probe.kind in BOX_METRICS:
            out = run_box(probe, probe.kind)
        elif probe.kind == "proxyd":
            out = run_proxyd(probe, prev)
        elif probe.kind == "sessions":
            out = run_sessions(probe)
        elif probe.kind == "policy_sessions":
            out = run_policy_sessions(probe, prev)
        elif probe.kind == "throughput":
            out = run_throughput(probe)
        elif probe.kind == "transactions":
            out = run_transactions(probe)
        elif probe.kind == "licence":
            out = run_licence(probe)
        elif probe.kind == "tokens":
            out = run_tokens(probe)
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
    session.commit()
    # Roll up BEFORE pruning. The buckets have to see the samples the retention
    # cap is about to delete, or a probe with a short retention would lose the
    # very history the 7/30-day charts exist to keep. History is never worth
    # failing a probe over, so a rollup error is swallowed after the sample is
    # already durable.
    try:
        rollup_probe(probe.id, session=session)
        session.commit()
    except Exception:  # noqa: BLE001
        session.rollback()
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


def discover_api_probes(appliance, *, session=None) -> dict:
    """Create the REST-monitor probes for ``appliance``: box sessions, the
    ``Total HTTP Throughput`` aggregate, and per-policy sessions + throughput.

    Policies come from the LIVE ``policystatus`` call, NOT from the harvest
    cache, for one concrete reason: on a licence-locked appliance every cmdb
    read fails with ``-20010`` while ``policystatus`` still answers 200
    (verified on fw7, 2026-07-28). Discovering from the cache would create zero
    probes on exactly the devices that most need them.

    ``transactions`` probes are NOT created here. That endpoint aggregates over
    hours, so a fast probe would resample the same window over and over; add
    those by hand at ``SLOW_PROBE_INTERVAL_MIN`` when a policy needs
    request-volume history. Idempotent by (device, kind, target).
    """
    from ..models import MonitorProbe, db

    session = session or db.session
    product = appliance.kind or "fortiweb"
    if product not in API_PRODUCTS:
        return {"created": 0, "skipped": 0, "total_targets": 0,
                "error": "monitor API discovery is %s-only (device is %s)"
                         % ("/".join(API_PRODUCTS), product)}
    if product == "fortiauthenticator":
        return _discover_fac_probes(appliance, session=session)
    from ..clients.fortiweb import FortiWebClient
    try:
        rows, error = FortiWebClient(appliance).policy_status()
    except Exception as exc:  # noqa: BLE001
        return {"created": 0, "skipped": 0, "total_targets": 0,
                "error": "policystatus failed: %s" % exc}
    if error:
        return {"created": 0, "skipped": 0, "total_targets": 0,
                "error": "policystatus failed: %s" % error}
    policies = parse_policy_rows(rows)

    have = {(p.kind, (p.target or "").strip().lower()) for p in
            session.query(MonitorProbe)
            .filter(MonitorProbe.appliance_id == appliance.id).all()}
    created, skipped = 0, 0

    def add(kind: str, target: str, label: str, note: str,
            interval: int = DEFAULT_PROBE_INTERVAL_MIN,
            enabled: bool = True) -> None:
        nonlocal created, skipped
        key = (kind, target.strip().lower())
        if key in have:
            skipped += 1
            return
        session.add(MonitorProbe(
            appliance_id=appliance.id, kind=kind, target=target[:120],
            name=("%s · %s" % (appliance.name, label))[:120],
            enabled=enabled, interval_min=interval, note=note[:250]))
        have.add(key)
        created += 1

    add("sessions", "", "sessions",
        "Box-wide concurrent sessions + connection rate over REST")
    add("throughput", TOTAL_HTTP, "total throughput",
        "Aggregate HTTP throughput across every policy")
    for p in policies:
        if p["protocol"].upper() not in ("HTTP", "HTTPS"):
            continue
        add("policy_sessions", p["name"], "%s sessions" % p["name"],
            "Sessions, conn/s, app latency and backend health for %s" % p["name"])
        add("throughput", p["name"], "%s throughput" % p["name"],
            "HTTP throughput for policy %s" % p["name"])
    session.commit()
    return {"created": created, "skipped": skipped,
            "total_targets": len(policies)}


#: Thresholds stamped on a freshly discovered FAC probe, in percent consumed.
#: A licence probe created with both levels at 0 is a row that can never say
#: anything -- and "discovery created 6 probes" would then read as coverage.
FAC_WARN_PCT = 80.0
FAC_CRIT_PCT = 95.0


def _discover_fac_probes(appliance, *, session=None) -> dict:
    """Create the FortiAuthenticator monitor probes from ONE live read.

    What gets a probe is decided by what the device actually declares, not by
    the static list of counters:

    * a licence counter with **no ceiling** (``max == 0``) gets none. It would
      grade ``unknown`` on every single run, and a permanently non-ok row is
      how a page teaches its reader to stop looking at it.
    * a token pool with **nothing imported** gets none, for the same reason --
      a device that does not use MFA is not a device with a token problem.

    Both exclusions are counted and named in the result, because "we created no
    probe for FSSO" and "FSSO is fine" are different statements.
    """
    from ..models import MonitorProbe, db

    session = session or db.session

    class _P:  # minimal probe-shaped object for the shared client factory
        kind = "licence"
        appliance = None
        timeout_s = 15

    shim = _P()
    shim.appliance = appliance
    parsed, err = _fac_systeminfo(shim)
    if err:
        return {"created": 0, "skipped": 0, "total_targets": 0,
                "error": err.get("detail") or "systeminfo read failed"}

    have = {(pr.kind, (pr.target or "").strip().lower()) for pr in
            session.query(MonitorProbe)
            .filter(MonitorProbe.appliance_id == appliance.id).all()}
    created, skipped, absent = 0, 0, []

    def add(kind: str, target: str, label: str, note: str) -> None:
        nonlocal created, skipped
        key = (kind, target.strip().lower())
        if key in have:
            skipped += 1
            return
        session.add(MonitorProbe(
            appliance_id=appliance.id, kind=kind, target=target[:120],
            name=("%s · %s" % (appliance.name, label))[:120],
            enabled=True, interval_min=DEFAULT_PROBE_INTERVAL_MIN,
            warn_num=FAC_WARN_PCT, crit_num=FAC_CRIT_PCT, note=note[:250]))
        have.add(key)
        created += 1

    capacity = parsed.get("capacity") or {}
    for key, (_field, label) in sorted(FAC_CAPACITY.items()):
        cap = capacity.get(key)
        if not cap or cap["total"] <= 0:
            absent.append("%s (no ceiling reported)" % label)
            continue
        add("licence", key, "%s licence" % label,
            "Percent of the %s entitlement consumed (%d licensed)"
            % (label, cap["total"]))

    tokens = parsed.get("tokens") or {}
    for key, (_field, label) in sorted(FAC_TOKENS.items()):
        tok = tokens.get(key)
        if not tok or tok["total"] <= 0:
            absent.append("%s (none imported)" % label)
            continue
        add("tokens", key, "%s pool" % label,
            "Percent of the %s pool assigned (%d imported)"
            % (label, tok["total"]))

    session.commit()
    return {"created": created, "skipped": skipped,
            "total_targets": created + skipped + len(absent),
            "not_applicable": absent,
            "detail": ("no probe created for: %s" % "; ".join(absent))
                      if absent else ""}


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


def discover_interface_probes(appliance, *, session=None) -> dict:
    """One interface probe PER PORT, from the cache.

    The granular alternative to the single whole-device watch: each port gets
    its own series, its own interval and its own history. Both shapes exist
    because they answer different questions — "did anything on this box move?"
    versus "chart me port3". Idempotent by (device, port).
    """
    from . import interface_inventory
    from ..models import MonitorProbe, db

    session = session or db.session
    # Refuse before reading the cache. An empty cache and "this product has no
    # interface resource at all" both yield zero rows, and only one of them is
    # worth an operator's time.
    if not supports("interface", appliance.kind or "fortiweb"):
        return {"created": 0, "skipped": 0, "total_targets": 0,
                "error": ("interface probes support %s only (device is %s) -- "
                          "this product exposes no interface resource to watch"
                          % ("/".join(products_for("interface")),
                             appliance.kind or "unknown"))}
    try:
        rows = (interface_inventory.merged(appliance, session=session)
                .get("interfaces") or [])
    except Exception as exc:  # noqa: BLE001
        return {"created": 0, "skipped": 0, "total_targets": 0,
                "error": f"cache read failed: {exc}"}
    have = {(p.target or "").strip().lower() for p in
            session.query(MonitorProbe)
            .filter(MonitorProbe.appliance_id == appliance.id,
                    MonitorProbe.kind == "interface").all()}
    created, skipped = 0, 0
    for r in sorted(rows, key=lambda x: str(x.get("name") or "")):
        name = str(r.get("name") or "").strip()
        if not name:
            continue
        if name.lower() in have:
            skipped += 1
            continue
        session.add(MonitorProbe(
            appliance_id=appliance.id, kind="interface",
            name=f"{appliance.name} · {name}"[:120], target=name[:120],
            enabled=True, interval_min=15,
            note=f"IP / link watch for {name} only"[:250]))
        have.add(name.lower())
        created += 1
    session.commit()
    return {"created": created, "skipped": skipped, "total_targets": len(rows)}


def ensure_baseline(appliance, *, session=None) -> dict:
    """Create the device-level probes if absent: interfaces, CPU, memory, and —
    FortiWeb only — the proxyd daemon.

    CPU and memory are separate rows on purpose (see :func:`classify_box`), and
    both work on FortiADC as well as FortiWeb; only the process monitor is
    FortiWeb-specific, because FortiADC exposes no ``diagnose system top``.
    """
    from ..models import MonitorProbe, db

    session = session or db.session
    product = appliance.kind or "fortiweb"
    made = []
    # Derived from KIND_PRODUCTS, not from a second product list. The old code
    # carried its own "fortiweb only" branch for proxyd and silently assumed
    # every other product could answer interfaces, CPU and memory -- which put
    # three permanently-erroring rows on a FortiAuthenticator the moment one
    # was onboarded.
    wanted = [(kind, f"{appliance.name} · {label}", interval)
              for kind, label, interval in (
                  ("interface", "interfaces", SLOW_PROBE_INTERVAL_MIN),
                  ("cpu", "CPU", DEFAULT_PROBE_INTERVAL_MIN),
                  ("memory", "memory", DEFAULT_PROBE_INTERVAL_MIN),
                  ("proxyd", "proxyd", DEFAULT_PROBE_INTERVAL_MIN))
              if supports(kind, product)]
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


def split_legacy_proxyd(*, session=None) -> dict:
    """One-shot: give every pre-existing proxyd probe its cpu/memory siblings.

    Until 2026-07-28 a proxyd probe also thresholded box CPU and box memory.
    Removing that from it without creating the replacements would silently
    DELETE coverage from an appliance that had it, so the migration adds the two
    rows instead of leaving the operator to notice the gap. Idempotent; the
    inherited CPU warn level comes from the old ``warn_cpu`` so a tuned
    threshold survives the split.
    """
    from ..models import MonitorProbe, db

    session = session or db.session
    created = []
    for p in (session.query(MonitorProbe)
              .filter(MonitorProbe.kind == "proxyd").all()):
        if not p.appliance_id:
            continue
        dev = getattr(p.appliance, "name", "") or f"device {p.appliance_id}"
        for kind, label in (("cpu", "CPU"), ("memory", "memory")):
            if (session.query(MonitorProbe)
                    .filter(MonitorProbe.appliance_id == p.appliance_id,
                            MonitorProbe.kind == kind).first()):
                continue
            session.add(MonitorProbe(
                appliance_id=p.appliance_id, kind=kind,
                name=f"{dev} · {label}"[:120], enabled=bool(p.enabled),
                interval_min=int(p.interval_min or 5),
                warn_pct=int(p.warn_cpu or 80) if kind == "cpu" else 80,
                crit_pct=95,
                note="split out of the proxyd probe (2026-07-28)"[:250]))
            created.append(f"{dev}:{kind}")
    session.commit()
    return {"created": created}


# ---------------------------------------------------------------------------
# Rollups — depth without volume
# ---------------------------------------------------------------------------
# Raw samples answer "what happened in the last two days" and are capped per
# probe (``retention``, 500 by default = ~41 h at a 5 min interval). Keeping a
# month of raw would mean 8 640 rows AND 8 640 payload blobs per probe — the
# payload, not the row, is what would actually cost disk (each carries up to
# 4 KB of raw CLI output).
#
# So the depth is bought with pre-aggregated buckets instead:
#
#   raw     capped at ``probe.retention``      ~2 days   full fidelity + payload
#   hour    90 days                            2 160 rows/probe, ~100 B each
#   day     730 days                             730 rows/probe
#
# Under 400 KB per probe for two years of history. The rollup runs inside the
# sweep (see :func:`run_probe`) rather than as a separate scheduled action **on
# purpose**: nothing in this product seeds a ``ScheduledAction`` row, so a
# feature that depends on the operator remembering to create one is a feature
# that silently does not exist on a fresh install.

ROLLUP_SPANS = ("hour", "day")
HOURLY_KEEP_DAYS = 90
DAILY_KEEP_DAYS = 730

# Chart source selection. A span wider than this reads the next coarser table.
RAW_MAX_SPAN_H = 48
HOURLY_MAX_SPAN_D = 45
MAX_RANGE_DAYS = 731

# What the trended numbers MEAN, per kind. The chart is unreadable without it:
# 2328 and 59.7 look alike until one is labelled MB and the other a percentage.
METRIC_META = {
    "https": {"label": "Response time", "unit": "ms",
              "v2_label": "TLS days left", "v2_unit": "d"},
    "interface": {"label": "Ports with an IP", "unit": "",
                  "v2_label": "Ports watched", "v2_unit": ""},
    "cpu": {"label": "CPU used", "unit": "%",
            "v2_label": "CPU idle", "v2_unit": "%"},
    "memory": {"label": "Memory used", "unit": "%",
               "v2_label": "", "v2_unit": ""},
    "proxyd": {"label": "Memory consumed", "unit": "MB",
               "v2_label": "Memory free", "v2_unit": "MB"},
    "sessions": {"label": "Concurrent sessions", "unit": "",
                 "v2_label": "New connections", "v2_unit": "/s"},
    "policy_sessions": {"label": "Concurrent sessions", "unit": "",
                        "v2_label": "App response time", "v2_unit": "ms"},
    # Average on the primary axis, peak on the secondary: they share a unit, so
    # they can share a chart — which is the whole point of keeping both.
    "throughput": {"label": "Throughput (avg)", "unit": "Mbps",
                   "v2_label": "Throughput (peak)", "v2_unit": "Mbps"},
    "transactions": {"label": "Transactions in window", "unit": "",
                     "v2_label": "Latest bucket", "v2_unit": ""},
    # Percent on the primary axis, the ABSOLUTE count on the secondary: "80 %
    # consumed" answers "should I worry", "4 of 5" answers "of what". They do
    # not share a unit, so they do not share an axis.
    "licence": {"label": "Licence consumed", "unit": "%",
                "v2_label": "In use", "v2_unit": ""},
    "tokens": {"label": "Pool assigned", "unit": "%",
               "v2_label": "Tokens free", "v2_unit": ""},
}


def bucket_key(ts: datetime, span: str) -> datetime:
    """Floor ``ts`` to the start of its ``hour`` / ``day`` bucket (UTC-naive)."""
    if span == "day":
        return ts.replace(hour=0, minute=0, second=0, microsecond=0)
    return ts.replace(minute=0, second=0, microsecond=0)


def _stats(values: list[float]) -> tuple[float | None, float | None, float | None]:
    if not values:
        return None, None, None
    return min(values), round(sum(values) / len(values), 3), max(values)


def aggregate_samples(rows: list[dict]) -> dict:
    """Fold raw samples into one bucket. Pure — this is the tested surface.

    ``changes`` counts fingerprint transitions INSIDE the bucket, so a chart can
    show "three restarts that hour" without keeping the raw rows. Transitions
    across a bucket boundary are not counted; the raw sample and its detail line
    still carry them for as long as raw retention holds.
    """
    out = {"samples": 0, "ok_n": 0, "warn_n": 0, "crit_n": 0, "error_n": 0,
           "v_min": None, "v_avg": None, "v_max": None,
           "v2_min": None, "v2_avg": None, "v2_max": None, "changes": 0}
    v: list[float] = []
    v2: list[float] = []
    prev_fp = None
    for r in rows:
        out["samples"] += 1
        key = f"{(r.get('status') or 'unknown')}_n"
        if key in out:
            out[key] += 1
        for src, dst in ((r.get("value_num"), v), (r.get("value2_num"), v2)):
            if isinstance(src, (int, float)) and not isinstance(src, bool):
                dst.append(float(src))
        fp = r.get("fingerprint") or ""
        if fp:
            if prev_fp is not None and fp != prev_fp:
                out["changes"] += 1
            prev_fp = fp
    out["v_min"], out["v_avg"], out["v_max"] = _stats(v)
    out["v2_min"], out["v2_avg"], out["v2_max"] = _stats(v2)
    return out


def aggregate_rollups(rows: list[dict]) -> dict:
    """Fold hourly buckets into a daily one.

    Averages are weighted by ``samples``: an hour with 12 readings must not
    count the same as an hour with 1, which is exactly what a naive mean of
    means would do after an outage.
    """
    out = {"samples": 0, "ok_n": 0, "warn_n": 0, "crit_n": 0, "error_n": 0,
           "v_min": None, "v_avg": None, "v_max": None,
           "v2_min": None, "v2_avg": None, "v2_max": None, "changes": 0}
    acc = {"v": [0.0, 0], "v2": [0.0, 0]}
    for r in rows:
        n = int(r.get("samples") or 0)
        out["samples"] += n
        out["changes"] += int(r.get("changes") or 0)
        for k in ("ok_n", "warn_n", "crit_n", "error_n"):
            out[k] += int(r.get(k) or 0)
        for pre, bag in (("v", "v"), ("v2", "v2")):
            lo, hi = r.get(f"{pre}_min"), r.get(f"{pre}_max")
            if lo is not None:
                out[f"{pre}_min"] = lo if out[f"{pre}_min"] is None else min(out[f"{pre}_min"], lo)
            if hi is not None:
                out[f"{pre}_max"] = hi if out[f"{pre}_max"] is None else max(out[f"{pre}_max"], hi)
            av = r.get(f"{pre}_avg")
            if av is not None and n:
                acc[bag][0] += float(av) * n
                acc[bag][1] += n
    for pre, bag in (("v", "v"), ("v2", "v2")):
        total, weight = acc[bag]
        if weight:
            out[f"{pre}_avg"] = round(total / weight, 3)
    return out


def _write_buckets(probe_id: int, span: str, buckets: dict, *, session) -> int:
    """Replace ``buckets`` for one probe/span. Delete-then-insert = idempotent."""
    from ..models import MonitorRollup

    if not buckets:
        return 0
    keys = list(buckets.keys())
    (session.query(MonitorRollup)
     .filter(MonitorRollup.probe_id == probe_id,
             MonitorRollup.span == span,
             MonitorRollup.bucket.in_(keys))
     .delete(synchronize_session=False))
    for key, agg in buckets.items():
        session.add(MonitorRollup(probe_id=probe_id, span=span, bucket=key, **agg))
    return len(buckets)


def rollup_probe(probe_id: int, *, now: datetime | None = None, session=None) -> dict:
    """Rebuild the recent hourly buckets from raw, then the daily ones from hourly.

    The rebuild window starts at the LAST stored bucket (which is normally still
    partial and must be recomputed), not at a fixed "last 3 hours". A scheduler
    that was dead for a day therefore still gets every bucket its raw samples
    can still prove — and the window is bounded anyway, because raw is capped by
    ``probe.retention``.
    """
    from ..models import MonitorRollup, MonitorSample, db
    from sqlalchemy import func

    session = session or db.session
    now = now or datetime.utcnow()
    written = {"hour": 0, "day": 0}

    last_hour = (session.query(func.max(MonitorRollup.bucket))
                 .filter(MonitorRollup.probe_id == probe_id,
                         MonitorRollup.span == "hour").scalar())
    q = (session.query(MonitorSample)
         .filter(MonitorSample.probe_id == probe_id))
    if last_hour is not None:
        q = q.filter(MonitorSample.ts >= last_hour)
    raw = q.order_by(MonitorSample.ts.asc()).all()
    hourly: dict[datetime, list[dict]] = {}
    for s in raw:
        hourly.setdefault(bucket_key(s.ts, "hour"), []).append(
            {"status": s.status, "value_num": s.value_num,
             "value2_num": s.value2_num, "fingerprint": s.fingerprint})
    written["hour"] = _write_buckets(
        probe_id, "hour", {k: aggregate_samples(v) for k, v in hourly.items()},
        session=session)

    last_day = (session.query(func.max(MonitorRollup.bucket))
                .filter(MonitorRollup.probe_id == probe_id,
                        MonitorRollup.span == "day").scalar())
    q = (session.query(MonitorRollup)
         .filter(MonitorRollup.probe_id == probe_id, MonitorRollup.span == "hour"))
    if last_day is not None:
        q = q.filter(MonitorRollup.bucket >= last_day)
    daily: dict[datetime, list[dict]] = {}
    for r in q.order_by(MonitorRollup.bucket.asc()).all():
        daily.setdefault(bucket_key(r.bucket, "day"), []).append(r.to_dict())
    written["day"] = _write_buckets(
        probe_id, "day", {k: aggregate_rollups(v) for k, v in daily.items()},
        session=session)

    written["pruned"] = prune_rollups(probe_id, session=session, now=now)
    return written


def prune_rollups(probe_id: int, *, session=None,
                  now: datetime | None = None) -> int:
    """Drop buckets past their horizon. Returns rows removed."""
    from ..models import MonitorRollup, db

    session = session or db.session
    now = now or datetime.utcnow()
    removed = 0
    for span, days in (("hour", HOURLY_KEEP_DAYS), ("day", DAILY_KEEP_DAYS)):
        removed += (session.query(MonitorRollup)
                    .filter(MonitorRollup.probe_id == probe_id,
                            MonitorRollup.span == span,
                            MonitorRollup.bucket < now - timedelta(days=days))
                    .delete(synchronize_session=False))
    return removed


def pick_source(start: datetime, end: datetime,
                earliest_raw: datetime | None,
                earliest_hour: datetime | None = None) -> str:
    """Which table answers this window: ``raw`` / ``hour`` / ``day``.

    Span alone is not enough. A probe running every minute holds only ~8 h of
    raw at the default retention, so a 24 h chart drawn from raw would show 8 h
    and look like the device went silent before that.

    But falling back is only worth it when the buckets genuinely reach FURTHER
    BACK than the raw rows. On a young probe they do not — every bucket was
    built from the very samples still on disk — and downgrading there would
    coarsen the chart and label it "hourly average" while showing exactly the
    same readings. Raw wins unless hourly can prove more history.
    """
    span = end - start
    if span > timedelta(days=HOURLY_MAX_SPAN_D):
        return "day"
    if span > timedelta(hours=RAW_MAX_SPAN_H):
        return "hour"
    if earliest_raw is None:
        return "hour" if earliest_hour is not None else "raw"
    if earliest_raw <= start:
        return "raw"
    # Compare BUCKETS, not instants: the hour bucket holding the oldest raw
    # sample always starts before that sample, so a naive < would send every
    # young probe to the coarse table.
    if earliest_hour is not None and earliest_hour < bucket_key(earliest_raw, "hour"):
        return "hour"
    return "raw"


def _worst_of_counts(row: dict) -> str:
    if row.get("crit_n"):
        return "crit"
    if row.get("error_n"):
        return "error"
    if row.get("warn_n"):
        return "warn"
    if row.get("ok_n"):
        return "ok"
    return "unknown"


def source_for(probe_id: int, start: datetime, end: datetime, *,
               session=None) -> str:
    """Which table WOULD answer this window for this probe.

    Split out of :func:`series` so a caller drawing several probes on ONE chart
    can ask each of them first and then pin the coarsest answer for all of them
    (``monitor_analytics.panel_source``). Two lines on one axis at two
    resolutions is a lie no label repairs: the raw line shows spikes the hourly
    line averaged away, and the operator reads that as a difference between the
    two devices rather than between the two queries.
    """
    from ..models import MonitorRollup, MonitorSample, db
    from sqlalchemy import func

    session = session or db.session
    earliest_raw = (session.query(func.min(MonitorSample.ts))
                    .filter(MonitorSample.probe_id == probe_id).scalar())
    earliest_hour = (session.query(func.min(MonitorRollup.bucket))
                     .filter(MonitorRollup.probe_id == probe_id,
                             MonitorRollup.span == "hour").scalar())
    return pick_source(start, end, earliest_raw, earliest_hour)


def series(probe_id: int, start: datetime, end: datetime, *, session=None,
           force_source: str | None = None) -> dict:
    """Points for the drill-down chart, at whatever resolution the window needs.

    ``force_source`` pins the table instead of choosing one. Only the multi-
    series panel builder passes it; the single-probe drill-down keeps choosing
    per probe, which is correct when there is nothing to compare against.
    """
    from ..models import MonitorRollup, MonitorSample, db
    from sqlalchemy import func

    session = session or db.session
    earliest_raw = (session.query(func.min(MonitorSample.ts))
                    .filter(MonitorSample.probe_id == probe_id).scalar())
    earliest_hour = (session.query(func.min(MonitorRollup.bucket))
                     .filter(MonitorRollup.probe_id == probe_id,
                             MonitorRollup.span == "hour").scalar())
    source = (force_source if force_source in ("raw", "hour", "day")
              else pick_source(start, end, earliest_raw, earliest_hour))

    points: list[dict] = []
    if source == "raw":
        rows = (session.query(MonitorSample)
                .filter(MonitorSample.probe_id == probe_id,
                        MonitorSample.ts >= start, MonitorSample.ts <= end)
                .order_by(MonitorSample.ts.asc()).all())
        for s in rows:
            points.append({"t": s.ts.isoformat(timespec="seconds"),
                           "min": s.value_num, "avg": s.value_num,
                           "max": s.value_num, "v2": s.value2_num,
                           "n": 1, "status": s.status, "changes": 0})
        totals = aggregate_samples([{"status": s.status, "value_num": s.value_num,
                                     "value2_num": s.value2_num,
                                     "fingerprint": s.fingerprint} for s in rows])
    else:
        rows = (session.query(MonitorRollup)
                .filter(MonitorRollup.probe_id == probe_id,
                        MonitorRollup.span == source,
                        MonitorRollup.bucket >= start,
                        MonitorRollup.bucket <= end)
                .order_by(MonitorRollup.bucket.asc()).all())
        dicts = [r.to_dict() for r in rows]
        for r in dicts:
            points.append({"t": r["bucket"], "min": r["v_min"], "avg": r["v_avg"],
                           "max": r["v_max"], "v2": r["v2_avg"], "n": r["samples"],
                           "status": _worst_of_counts(r), "changes": r["changes"]})
        totals = aggregate_rollups(dicts)

    graded = totals["ok_n"] + totals["warn_n"] + totals["crit_n"] + totals["error_n"]
    return {
        "source": source,
        "bucket_seconds": {"raw": 0, "hour": 3600, "day": 86400}[source],
        "from": start.isoformat(timespec="seconds"),
        "to": end.isoformat(timespec="seconds"),
        "points": points,
        "totals": totals,
        "healthy_pct": round(100.0 * totals["ok_n"] / graded, 1) if graded else None,
        "earliest": earliest_raw.isoformat(timespec="seconds") if earliest_raw else "",
        "retention": {"raw_samples": None, "hourly_days": HOURLY_KEEP_DAYS,
                      "daily_days": DAILY_KEEP_DAYS},
    }


def backfill_rollups(*, session=None) -> dict:
    """Build rollups for every probe from whatever raw history exists.

    One-shot for an upgrade: without it the 7/30-day views are empty until the
    hourly buckets accumulate, which reads exactly like "the feature is broken".
    """
    from ..models import MonitorProbe, db

    session = session or db.session
    out: dict[str, Any] = {"probes": 0, "hour": 0, "day": 0}
    for p in session.query(MonitorProbe).all():
        res = rollup_probe(p.id, session=session)
        out["probes"] += 1
        out["hour"] += res["hour"]
        out["day"] += res["day"]
    session.commit()
    return out


def reset_series(kind: str, *, session=None) -> dict:
    """Delete every sample and bucket of one probe kind.

    Used when the MEANING of ``value_num`` changes — ``proxyd`` moved from the
    daemon's %VSZ to megabytes consumed on 2026-07-28. Charting both on one axis
    would draw 59.7 next to 2328 and call them the same series, which is a lie
    that no axis label can fix. Deliberately NOT run at boot: destructive
    migrations are an operator action, not a side effect of a restart.
    """
    from ..models import MonitorProbe, MonitorRollup, MonitorSample, db

    session = session or db.session
    ids = [p.id for p in session.query(MonitorProbe)
           .filter(MonitorProbe.kind == kind).all()]
    if not ids:
        return {"probes": 0, "samples": 0, "rollups": 0}
    n_s = (session.query(MonitorSample)
           .filter(MonitorSample.probe_id.in_(ids))
           .delete(synchronize_session=False))
    n_r = (session.query(MonitorRollup)
           .filter(MonitorRollup.probe_id.in_(ids))
           .delete(synchronize_session=False))
    session.commit()
    return {"probes": len(ids), "samples": n_s, "rollups": n_r}
