"""Test Connection: what THIS SATOM node can reach of an appliance.

Four methods (SA-0017), all from this server to the address SATOM uses:

* ``api``        -- the product's REST status call, the real thing every
                    sync and write depends on (TLS verified as configured).
* ``tcp``        -- one TCP handshake to the management port. This is what
                    ``telnet <host> <port>`` is used for, done in-process, so
                    no telnet client has to be installed on the server.
* ``ping``       -- ICMP echo via the system ``ping``.
* ``traceroute`` -- the path, via the system ``traceroute`` (UDP probes, no
                    privilege needed).

Clusters (SA-0016/SA-0018): a per-node cluster is tested member by member --
node 0 has no connection of its own. A VIP cluster is tested on the VIP AND on
every member: when the VIP does not answer from here but the members do, the
answer says so and how to switch, instead of a bare "connection failed".

Every run leaves a job whose title names the method and with one step per
target and its verdict (services/device_jobs, job_progress.probe): TCP, ping
and traceroute do not go through a product client, so without those steps a
fast test left no trace at all.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from . import backend_probe, job_progress

METHODS = ("api", "tcp", "ping", "traceroute")
METHOD_LABELS = {"api": "API (HTTPS)", "tcp": "TCP port (telnet)",
                 "ping": "Ping", "traceroute": "Traceroute"}

PING_COUNT = 3
PING_TIMEOUT_S = 15
TRACE_MAX_HOPS = 20
TRACE_TIMEOUT_S = 75
TCP_TIMEOUT_S = 5.0

_BIN_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")
_PACKAGES = {"ping": "iputils (Debian: iputils-ping)", "traceroute": "traceroute"}


def clean_method(raw) -> str:
    m = (raw or "api").strip().lower()
    return m if m in METHODS else "api"


# --------------------------------------------------------------------------- #
#  Targets                                                                      #
# --------------------------------------------------------------------------- #
def targets_for(appliance) -> list[dict]:
    """``[{label, row, host, port}]`` -- what Test Connection reaches for."""
    def one(label, row, host=None):
        return {"label": label, "row": row, "host": (host or row.host or "").strip(),
                "port": int(row.port or 443)}

    if not appliance.is_cluster:
        return [one(appliance.name, appliance)]
    out = []
    if (appliance.ha_mode or "").lower() == "vip":
        out.append(one("VIP", appliance, appliance.host or appliance.ha_vip))
    out.extend(one(m.name, m) for m in appliance.cluster_members())
    return out


# --------------------------------------------------------------------------- #
#  Hints -- the next step, not just the error                                   #
# --------------------------------------------------------------------------- #
def tls_hint(detail: str, row) -> str:
    """What to do about a TLS failure, or ''."""
    text = detail or ""
    owner = row.parent if getattr(row, "verify_ssl_inherited", False) else row
    if "IP address mismatch" in text or "Hostname mismatch" in text:
        if getattr(row, "tls_name", None):
            return ("The certificate is trusted but does not carry %r either: "
                    "check 'TLS certificate name' on %s against the certificate's "
                    "CN / SAN." % (row.tls_name, owner.name))
        return ("The certificate chain is trusted, but the certificate does not "
                "name %s (an HA pair presents one synced certificate). Set "
                "'TLS certificate name' on %s (Edit) to a name the certificate "
                "carries (its CN or a SAN entry), or add this address to the "
                "certificate's SAN." % (row.host, owner.name))
    if ("unable to get local issuer" in text or "self-signed" in text
            or "self signed" in text):
        return ("SATOM does not trust the CA that signed this certificate: "
                "import it in Settings › Trust store, then test again.")
    return ""


def vip_hint(results: list[dict]) -> str:
    vip = next((r for r in results if r["label"] == "VIP"), None)
    members_ok = [r["label"] for r in results if r["label"] != "VIP" and r["ok"]]
    if vip is not None and not vip["ok"] and members_ok:
        return ("The VIP does not answer from this server, but %s %s: switch the "
                "cluster to per-node mode (Edit › HA mode) so SATOM connects to "
                "the members directly — writes then go to the live primary."
                % (", ".join(members_ok), "does" if len(members_ok) == 1 else "do"))
    return ""


# --------------------------------------------------------------------------- #
#  Methods                                                                      #
# --------------------------------------------------------------------------- #
def _api(target, client_for) -> dict:
    row = target["row"]
    try:
        client_for(row).status_check()
        return {"ok": True, "verdict": "ok", "detail": "REST status call answered"}
    except Exception as exc:  # noqa: BLE001 -- reported per target
        detail = str(exc) or type(exc).__name__
        return {"ok": False, "verdict": "failed", "detail": detail,
                "hint": tls_hint(detail, row), "exc": exc}


def _which(name: str):
    found = shutil.which(name)
    if found:
        return found
    for d in _BIN_DIRS:
        p = "%s/%s" % (d, name)
        if shutil.which(p):
            return p
    return None


def _run(argv, timeout):
    try:
        cp = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                            check=False)
        return cp.returncode, (cp.stdout or "") + (cp.stderr or ""), False
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return None, out, True


_PING_STATS = re.compile(r"(\d+) packets transmitted, (\d+) (?:packets )?received")
_PING_RTT = re.compile(r"= [\d.]+/([\d.]+)/")
_NOT_PERMITTED = ("Operation not permitted", "missing cap_net_raw", "Permission denied")


def parse_ping_output(text: str) -> dict:
    """System ``ping`` output -> ``{ok, verdict, detail}``."""
    if any(s in text for s in _NOT_PERMITTED):
        return {"ok": False, "verdict": "not permitted",
                "detail": "ICMP is not permitted for the SATOM service user on this "
                          "server",
                "hint": "As root on this server: echo 'net.ipv4.ping_group_range = 0 "
                        "2147483647' > /etc/sysctl.d/90-satom-ping.conf && sysctl "
                        "--system -- lets unprivileged users send ICMP echo (no "
                        "setuid, no capability on ping). TCP and Traceroute do not "
                        "need it."}
    m = _PING_STATS.search(text)
    if not m:
        return {"ok": False, "verdict": "no answer",
                "detail": "ping printed no statistics line"}
    sent, got = int(m.group(1)), int(m.group(2))
    if got == 0:
        return {"ok": False, "verdict": "no reply",
                "detail": "0/%d echo replies — ICMP may simply be filtered on the "
                          "path; TCP shows whether the port answers" % sent}
    rtt = _PING_RTT.search(text)
    return {"ok": True, "verdict": "alive",
            "detail": "%d/%d replies%s" % (got, sent,
                                           ", avg %s ms" % rtt.group(1) if rtt else "")}


def _ping(target) -> dict:
    exe = _which("ping")
    if not exe:
        return {"ok": False, "verdict": "not installed",
                "detail": "no ping on this server",
                "hint": "Install the %s package." % _PACKAGES["ping"]}
    rc, out, timed_out = _run([exe, "-n", "-c", str(PING_COUNT), "-W", "2",
                               target["host"]], PING_TIMEOUT_S)
    res = parse_ping_output(out)
    if timed_out and not res["ok"]:
        res["detail"] = "ping did not finish within %ds" % PING_TIMEOUT_S
    res["output"] = out.strip()[-4000:]
    return res


def parse_traceroute_output(text: str, host: str) -> dict:
    hops = [ln for ln in text.splitlines() if re.match(r"\s*\d+\s", ln)]
    if not hops:
        return {"ok": False, "verdict": "no path", "detail": "traceroute printed no hop"}
    last = hops[-1]
    reached = re.search(r"(?<![\d.])%s(?![\d.])" % re.escape(host), last) is not None
    if reached:
        return {"ok": True, "verdict": "reached",
                "detail": "reached in %d hop%s" % (len(hops), "" if len(hops) == 1 else "s")}
    answered = [ln.split() for ln in hops if len(ln.split()) > 1 and ln.split()[1] != "*"]
    return {"ok": False, "verdict": "not reached",
            "detail": ("last hop that answered: %s (hop %s)" % (answered[-1][1], answered[-1][0])
                       if answered else "no hop answered")}


def _traceroute(target) -> dict:
    exe = _which("traceroute")
    if not exe:
        return {"ok": False, "verdict": "not installed",
                "detail": "no traceroute on this server",
                "hint": "Install the %s package." % _PACKAGES["traceroute"]}
    rc, out, timed_out = _run([exe, "-n", "-q", "1", "-w", "2", "-m", str(TRACE_MAX_HOPS),
                               target["host"]], TRACE_TIMEOUT_S)
    res = parse_traceroute_output(out, target["host"])
    if timed_out and not res["ok"]:
        res["detail"] += " (stopped after %ds)" % TRACE_TIMEOUT_S
    res["output"] = out.strip()[-6000:]
    return res


def _tcp(target) -> dict:
    res = backend_probe.tcp_check(target["host"], target["port"], timeout=TCP_TIMEOUT_S)
    return {"ok": bool(res.get("ok")), "verdict": res.get("verdict", ""),
            "detail": "%s:%s — %s" % (target["host"], target["port"], res.get("detail", ""))}


def _timed(fn, target):
    t0 = time.monotonic()
    out = fn(target)
    out["_secs"] = time.monotonic() - t0
    return out


def _probe_target(method: str, t: dict) -> str:
    if method == "tcp":
        return "tcp://%s:%s" % (t["host"], t["port"])
    if method == "api":
        return "https://%s:%s" % (t["host"], t["port"])
    return "icmp://%s" % t["host"]


def _record_steps(method: str, results: list[dict]) -> None:
    """One job step per target: what was tried, where, and the verdict."""
    label = METHOD_LABELS[method]
    for r in results:
        where = r["host"] or "(no address)"
        if method in ("tcp", "api"):
            where = "%s:%s" % (where, r["port"])
        outcome = ("OK" if r["ok"] else "FAILED") + (
            " · %s" % r["verdict"] if r.get("verdict") else "")
        if not r["ok"] and r.get("detail"):
            outcome += " — %s" % r["detail"]
        # The API test's REST calls are already steps of the job: its verdict
        # is recorded, not counted again. The others reach the device here.
        reached = method != "api" and r.get("verdict") not in (
            "refused", "no address", "not installed", "not permitted")
        job_progress.probe(_probe_target(method, r), "%s · %s %s" % (label, r["label"], where),
                           outcome, r.get("_secs"), ok=r["ok"], counts=reached)


def run(appliance, method: str, *, client_for) -> dict:
    """Test ``appliance`` with ``method`` -> the JSON Test Connection returns.

    ``client_for`` is passed in (clients.client_for) so this module never
    imports a product client (tests/test_product_separation.py)."""
    method = clean_method(method)
    label = METHOD_LABELS[method]
    # A test is kept in the Jobs ledger even when it never reached the device
    # (refused address, no members): the operator ran it and looks for it.
    job_progress.keep()
    targets = targets_for(appliance)
    if not targets:
        status = "this cluster has no member nodes yet"
        job_progress.step("%s · %s" % (label, status))
        return {"ok": False, "method": method, "label": label, "members": True,
                "results": [], "status": status, "message": "%s: %s" % (label, status),
                "hint": ""}
    results = []
    for t in targets:
        if method != "api":
            try:
                backend_probe.assert_probe_target(t["host"])
            except backend_probe.ProbeRefused as exc:
                t["refused"] = str(exc)
    if method == "api":
        # Sequential, in the request's app context: reading a credential may
        # hit the database (secret_backend).
        outs = [_timed(lambda x: _api(x, client_for), t) for t in targets]
    else:
        fn = {"tcp": _tcp, "ping": _ping, "traceroute": _traceroute}[method]

        def guarded(t):
            if t.get("refused"):
                return {"ok": False, "verdict": "refused", "detail": t["refused"]}
            if not t["host"]:
                return {"ok": False, "verdict": "no address",
                        "detail": "this row has no host to reach"}
            return _timed(fn, t)
        with ThreadPoolExecutor(max_workers=min(4, len(targets))) as pool:
            outs = list(pool.map(guarded, targets))
    for t, o in zip(targets, outs):
        results.append(dict(o, label=t["label"], host=t["host"], port=t["port"],
                            id=t["row"].id))
    _record_steps(method, results)
    for r in results:
        r.pop("_secs", None)
    ok_all = all(r["ok"] for r in results)
    multi = len(results) > 1 or appliance.is_cluster
    status = " · ".join(
        ("%s: %s" % (r["label"], "OK" if r["ok"] else r["detail"])) if multi
        else ("OK" if r["ok"] else r["detail"]) for r in results)
    hint = vip_hint(results) or next((r.get("hint") for r in results if r.get("hint")), "")
    return {"ok": ok_all, "method": method, "label": label, "members": multi,
            "status": status, "message": "%s: %s" % (label, status),
            "results": results, "hint": hint}
