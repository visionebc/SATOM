"""Why an alert is open: the evidence that raised it, the cause derived from
that evidence and what fixes it. Built when the alert page is opened, from
the facts already stored — nothing here talks to a device.

Every cause says how it is known: ``measured`` (a value the device or SATOM
reported) or ``inferred`` (a conclusion from several measured values; the
page lists them). Nothing is guessed: what the platform cannot see is said."""
from __future__ import annotations

from . import insights, topology
from .extensions import db
from .models import EndpointStatus, Fact, Source

#: FortiWeb pool health-check names -> what the check does.
HEALTH_CHECKS = {
    "HLTHCK_ICMP": "ICMP ping",
    "HLTHCK_TCP": "TCP connect",
    "HLTHCK_TCP_HALF": "TCP half-open (SYN)",
    "HLTHCK_TCP_SSL": "TCP + TLS handshake",
    "HLTHCK_HTTP": "HTTP request",
    "HLTHCK_HTTPS": "HTTPS request",
}


def _facts(sid, ref=None):
    q = Fact.query.filter_by(source_id=sid)
    if ref:
        q = q.filter_by(object_ref=ref)
    return q.all()


def _ev(what, value, where="", at=None):
    return {"what": what, "value": value, "where": where, "at": at}


def _check_label(name):
    if not name:
        return "no health check configured"
    return "%s (%s)" % (name, HEALTH_CHECKS.get(name, "custom check"))


def _path_summary(t) -> str:
    hops = t.get("hops") or []
    first = hops[0] if hops else {}
    route = ("route %s via %s on %s" % (first.get("route"), first.get("via"), first.get("out"))
             if first.get("route") else "")
    return "; ".join(x for x in (route, t.get("end", "")) if x)


def explain(alert) -> dict:
    """``{"evidence": [...], "rows": [...], "cause": {...}, "fix": [...],
    "impact": str}`` for one alert (keys absent when not applicable)."""
    src = db.session.get(Source, alert.source_id) if alert.source_id else None
    fn = {"policy": _policy, "licence": _licence, "read": _read, "source": _source,
          "snapshot": _snapshot, "resource": _resource, "interface": _interface}.get(alert.kind)
    if src is None or fn is None:
        return {"evidence": [], "cause": {"text": alert.detail, "how": "measured"}, "fix": []}
    out = fn(alert, src)
    out.setdefault("evidence", [])
    out.setdefault("fix", [])
    return out


# ── server policy back-ends ──────────────────────────────────────────────────

def _policy(alert, src):
    pname = alert.key.split(":", 2)[2]
    ref = "policy:%s" % pname
    kv = {f.key: f for f in _facts(src.id, ref)}
    pool = (kv.get("server_pool").value if kv.get("server_pool") else "") or ""
    pool_kv = {f.key: f for f in _facts(src.id, "pool:%s" % pool)} if pool else {}
    check = (pool_kv.get("health_check").value if pool_kv.get("health_check") else "") or ""
    bk = kv.get("backends")
    backends = [b for b in (bk.value if bk else []) or [] if isinstance(b, dict)]
    sessions = kv.get("sessions").value if kv.get("sessions") else None
    evidence = [
        _ev("Policy status", kv["status"].value if "status" in kv else "not read",
            kv["status"].endpoint if "status" in kv else "", kv["status"].read_at if "status" in kv else None),
        _ev("Server pool", pool or "none", kv["server_pool"].endpoint if "server_pool" in kv else ""),
        _ev("Health check of the pool", _check_label(check),
            pool_kv["health_check"].endpoint if "health_check" in pool_kv else ""),
        _ev("Back-end health", "%d of %d failing the check" % (
            sum(1 for b in backends if insights.backend_health(b.get("health")) == "down"), len(backends)),
            bk.endpoint if bk else "", bk.read_at if bk else None),
        _ev("Client sessions now", sessions if sessions is not None else "not read",
            kv["sessions"].endpoint if "sessions" in kv else ""),
    ]
    m = topology.build()
    rows, paths = [], []
    for b in backends:
        addr, port = str(b.get("address") or ""), b.get("port")
        ip = topology._ip(addr)
        t = topology.trace(m, src.id, addr, port=port, proto="tcp") if ip else {"status": "invalid", "end": "not an IP (domain back-end)", "hops": []}
        seen = (topology.owner(m, ip) or topology.endpoint_at(m, ip)) if ip else None
        paths.append((t, seen))
        rows.append({"address": addr, "port": port, "pool": b.get("pool") or pool,
                     "raw": b.get("health_raw", b.get("health")), "health": insights.backend_health(b.get("health")),
                     "path_status": t["status"], "path": _path_summary(t), "seen": bool(seen),
                     "analyze": {"from": src.id, "ip": addr, "port": port or ""} if ip else None})
    idx = [i for i, r in enumerate(rows) if r["health"] == "down"]
    down = [rows[i] for i in idx]
    down_paths = [paths[i] for i in idx]
    chk = HEALTH_CHECKS.get(check, check or "health")
    gws = sorted({(t["hops"][0].get("via") or "") for t, _ in down_paths if t.get("hops")})
    if down and all(t["status"] == "leaves" and not seen for t, seen in down_paths):
        cause = {"how": "inferred", "text": (
            "%s sends every failing back-end out of the monitored network (%s) and its %s check gets no "
            "answer. No monitored device has these addresses on a connected network or has seen them as "
            "hosts, so the servers are most likely not there: switched off, removed, or never created "
            "(test back-ends), or something past %s drops the check." % (
                src.name, "via " + ", ".join(gws) if gws else "default route", chk, " / ".join(gws) or "the gateway")),
            "from": ["the device reports the check failing (raw value in the table)",
                     "the route the device uses for each back-end (its own routing table)",
                     "no monitored interface or detected host holds those addresses"]}
    elif any(t["status"] == "denied" for t, _ in down_paths):
        t = next(t for t, _ in down_paths if t["status"] == "denied")
        cause = {"how": "measured", "text": "A monitored firewall blocks the health check: %s." % t["end"],
                 "from": ["the firewall policies of the device on the path, evaluated in order"]}
    elif any(t["status"] == "no_route" for t, _ in down_paths):
        cause = {"how": "measured", "text": "%s has no usable route to the failing back-ends." % src.name,
                 "from": ["the device's routing table"]}
    elif down:
        cause = {"how": "inferred", "text": (
            "The path to the back-ends is open as far as the monitored devices show, yet the servers fail "
            "the %s check: the service is down or not listening on that port, or it answers differently "
            "from what the check expects." % chk),
            "from": ["the device reports the check failing", "the path trace finds no block"]}
    else:
        cause = {"how": "measured", "text": alert.detail}
    fix = [
        "On %s, test one back-end from the device itself (CLI): execute ping %s · execute traceroute %s"
        % (src.name, down[0]["address"] if down else "<ip>", down[0]["address"] if down else "<ip>"),
        "If the servers exist: start the service on the port in the table, or fix the route / firewall shown "
        "in the path.",
        "If they do not exist (test objects): point pool %s at the real servers, or delete / disable policy %s. "
        "The alert clears by itself on the next collection." % (pool or "?", pname),
        "Do not disable the health check to silence the alert: FortiWeb would keep sending clients to "
        "servers that do not answer.",
    ]
    impact = ("No client sessions on this policy right now, so nobody is affected at this moment."
              if sessions == 0 else
              "%s client sessions are on this policy and every back-end fails — clients get errors." % sessions
              if isinstance(sessions, (int, float)) and sessions else "")
    return {"evidence": evidence, "rows": rows, "cause": cause, "fix": fix, "impact": impact}


# ── licence ──────────────────────────────────────────────────────────────────

def _licence(alert, src):
    dev = {f.key: f for f in _facts(src.id, "device")}
    evidence = [_ev(label, dev[k].value, dev[k].endpoint, dev[k].read_at)
                for k, label in (("vm_licence", "VM licence (vmLicense)"), ("licence_valid", "Licence valid"),
                                 ("licence_status", "Licence status"), ("serial", "Serial number"),
                                 ("firmware", "Firmware")) if k in dev]
    refused = [st for st in EndpointStatus.query.filter_by(source_id=src.id, ok=False)
               if insights.is_licence_error(st.error)]
    for st in refused:
        evidence.append(_ev("Read refused · %s" % st.endpoint, st.error, "", st.read_at))
    serial = str(dev["serial"].value) if "serial" in dev else ""
    if "UNLICENSED" in serial.upper():
        text = ("The VM runs without a licence file: its serial is %s, the placeholder Fortinet VMs show "
                "until a licence is loaded." % serial)
        how = "measured"
    elif refused:
        ok = [st.endpoint for st in EndpointStatus.query.filter_by(source_id=src.id, ok=True)
              if not st.absent and st.endpoint.startswith("SATOM collector")]
        text = ("The device answers its API reads with a licence refusal instead of data: \"%s\" (%d %s "
                "refused: %s). What those reads carry stays unknown — for SATOM too — until the device has a "
                "valid licence.%s" % (
                    insights.device_words(refused[0].error), len(refused), "read" if len(refused) == 1 else "reads",
                    ", ".join(st.endpoint for st in refused),
                    (" Reads the licence does not block still arrive (%s)." % ", ".join(ok)) if ok else ""))
        how = "measured"
    else:
        text = "The device reports its licence as not valid."
        how = "measured"
    fix = ["Load a valid VM licence (or a new evaluation) on %s: the .lic file from the Fortinet support "
           "portal, on the device's licence page (menu path unverified on this build)." % src.name,
           "Once the device has applied it (VMs usually reboot), the alert clears on the next collection."]
    impact = ("FortiWeb without a licence: signatures and other FortiGuard features are inactive, and its "
              "REST API may lock reads (HTTP 423)." if src.kind == "fortiweb" else
              "Configuration changes, virtual-server state and back-end health cannot be read: SATOM keeps "
              "showing its last snapshot." if refused else "Features that need a licence are inactive.")
    return {"evidence": evidence, "cause": {"how": how, "text": text,
                                            "from": ["the device's own status / its answer to each read"]},
            "fix": fix, "impact": impact}


# ── reads, sources, snapshots ────────────────────────────────────────────────

def _read_cause(err: str) -> str:
    e = (err or "").lower()
    if insights.is_licence_error(e):
        return "The device refuses the read because of its licence."
    if "401" in e or "credential" in e:
        return "The device rejects SATOM's credentials (wrong password, trusted hosts or a lockout)."
    if "timeout" in e or "timed out" in e:
        return "The device did not answer in time (overloaded, or a firewall drops the traffic)."
    if "connect" in e or "unreachable" in e or "connection refused" in e:
        return "The device cannot be reached on its management address/port."
    if "satom's collector" in e:
        return "SATOM's own collector for this device fails; the reason SATOM recorded is in the evidence."
    return "The device or SATOM answered with an error (see the evidence)."


def _read(alert, src):
    ep = alert.key.split(":", 2)[2]
    st = EndpointStatus.query.filter_by(source_id=src.id, endpoint=ep).first()
    err = st.error if st else alert.detail
    evidence = [_ev("Read", ep, st.layers if st else ""),
                _ev("Error", err, "", st.read_at if st else None)]
    return {"evidence": evidence, "cause": {"how": "measured", "text": _read_cause(err),
                                            "from": ["the error text of the read"]},
            "fix": ["Open the source and run a collection: the job shows the read step with the full answer.",
                    "Fix what the error names (credentials, licence, reachability); the alert clears on the "
                    "next successful read."]}


def _source(alert, src):
    evidence = [_ev("Last collection", src.last_status or "never", "", src.last_run_at),
                _ev("Error", src.last_error or "—"), _ev("Interval", "%d s" % src.interval_s)]
    stale = "stale" in alert.title
    return {"evidence": evidence, "cause": {"how": "measured", "text": (
        "No collection has finished for more than 3 intervals: the collector is not running or a "
        "collection hangs." if stale else _read_cause(src.last_error))},
        "fix": ["Open the source and run a collection; the job lists every step and its answer."]}


def _snapshot(alert, src):
    dev = {f.key: f for f in _facts(src.id, "device")}
    evidence = [_ev("SATOM configuration snapshot", "%s UTC" % dev["config_snapshot_at"].value)] \
        if "config_snapshot_at" in dev else []
    refused = [st for st in EndpointStatus.query.filter_by(source_id=src.id, ok=False)]
    for st in refused:
        evidence.append(_ev("Failing · %s" % st.endpoint, st.error, "", st.read_at))
    lic = any(insights.is_licence_error(st.error) for st in refused)
    return {"evidence": evidence, "cause": {"how": "measured" if lic else "inferred", "text": (
        "SATOM cannot refresh this device's configuration because the device refuses every read for its "
        "licence, so the last snapshot keeps ageing." if lic else
        "SATOM has not captured this device's configuration since that date (device sync failing in SATOM).")},
        "fix": ["Fix what blocks SATOM's device sync (see SATOM › the appliance › sync status); the next "
                "nightly snapshot clears this alert."]}


def _resource(alert, src):
    key = alert.key.split(":", 2)[2]
    dev = {f.key: f for f in _facts(src.id, "device")}
    label, warn, crit = insights.RESOURCE_RULES.get(key, (key, 0, 0))
    f = dev.get(key)
    evidence = [_ev(label, "%s %%" % f.value if f else "not read", f.endpoint if f else "", f.read_at if f else None),
                _ev("Thresholds", "%d %% warning · %d %% critical" % (warn, crit))]
    return {"evidence": evidence, "cause": {"how": "measured", "text": "%s use is over the threshold." % label},
            "fix": ["See Analytics for the trend; find the process / traffic driving it on the device."]}


def _interface(alert, src):
    name = alert.key.split(":", 2)[2]
    kv = {f.key: f for f in _facts(src.id, "if:%s" % name)}
    evidence = [_ev(k, kv[k].value, kv[k].endpoint, kv[k].read_at) for k in ("admin_status", "link", "address")
                if k in kv]
    return {"evidence": evidence, "cause": {"how": "measured", "text": (
        "The interface is enabled but has no link: cable, switch port or the virtual NIC is down.")},
        "fix": ["Check the cable / switch port / hypervisor NIC; or set the interface administratively down "
                "if it is not used."]}
