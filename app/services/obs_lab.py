"""Observability (lab) — the satom-observability views, built on SATOM's own data.

A trial (operator request 2026-11-05): "integrate what Observability has into
SATOM, as a separate URL so nothing of SATOM changes; inventory and everything
comes from the SATOM database". So this module is READ-ONLY by construction:

* it never talks to a device — every value comes from what the collectors
  already left behind (cache first): ``appliances``, the device cache
  (``device_objects`` / ``device_snapshots``) and VictoriaMetrics;
* it writes nothing — no table, no setting, no metric;
* it adds no schema and no menu entry. Removing the trial = deleting the
  blueprint, this module and the templates.

Layers follow the satom-observability contract: L1 (link), L2 (VLAN), L3
(addresses, routes), L4 (VIPs, virtual servers, firewall policies) and L7
(server policies -> pools -> back-ends). Anything SATOM does not collect yet is
said, per device, in :func:`gaps` — never shown as empty or healthy.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta

from ..extensions import db
from ..models import Appliance, visible_appliances
from ..models_cache import DeviceObject, DeviceSnapshot
from . import vm_store

#: A config snapshot older than this is shown as stale.
STALE_AFTER = timedelta(hours=26)

KIND_LABEL = {
    "fortiweb": "FortiWeb", "fortiadc": "FortiADC", "fortigate": "FortiGate",
    "fortianalyzer": "FortiAnalyzer", "fortiauthenticator": "FortiAuthenticator",
}


# ── metrics (VictoriaMetrics, instant) ───────────────────────────────────────

def _instant(expr: str) -> tuple[list, str]:
    """``(rows, error)`` for an instant query. ``rows`` = ``[(labels, float)]``.
    A failed query is an ERROR the page prints, never an empty result."""
    res = vm_store.query(expr)
    if not isinstance(res, dict) or res.get("status") != "success":
        return [], str((res or {}).get("error") or "query failed")[:200]
    out = []
    for r in (res.get("data") or {}).get("result") or []:
        try:
            out.append((r.get("metric") or {}, float(r["value"][1])))
        except (KeyError, IndexError, TypeError, ValueError):
            continue
    return out, ""


def _last(metric: str, window: str = "15m") -> tuple[list, str]:
    # last_over_time: a raw instant query can come back empty right after a
    # scrape (measured on satom-observability, 2026-11-05).
    return _instant("last_over_time(%s[%s])" % (metric, window))


def _by_device(rows, *keys) -> dict:
    out: dict = {}
    for labels, value in rows:
        k = tuple([labels.get("device", "")] + [labels.get(x, "") for x in keys])
        out[k if keys else k[0]] = value
    return out


# ── device cache helpers ─────────────────────────────────────────────────────

def _snapshots(ids) -> dict:
    """``{appliance_id: {layer: generated_at}}`` — newest capture per layer."""
    if not ids:
        return {}
    rows = (db.session.query(DeviceSnapshot.appliance_id, DeviceSnapshot.layer,
                             db.func.max(DeviceSnapshot.generated_at))
            .filter(DeviceSnapshot.appliance_id.in_(ids))
            .group_by(DeviceSnapshot.appliance_id, DeviceSnapshot.layer).all())
    out: dict = {}
    for aid, layer, at in rows:
        out.setdefault(aid, {})[layer] = at
    return out


def _objects(aid: int, logical: str, layer: str | None = None) -> list:
    q = DeviceObject.query.filter_by(appliance_id=aid, logical_name=logical)
    if layer:
        q = q.filter_by(layer=layer)
    return q.order_by(DeviceObject.idx, DeviceObject.id).all()


def _children(parent_ids, logical: str) -> dict:
    """``{parent_id: [DeviceObject]}`` for one child logical name."""
    if not parent_ids:
        return {}
    out: dict = {}
    for o in (DeviceObject.query.filter(DeviceObject.parent_id.in_(list(parent_ids)),
                                        DeviceObject.logical_name == logical)
              .order_by(DeviceObject.idx, DeviceObject.id)):
        out.setdefault(o.parent_id, []).append(o)
    return out


def _p(o) -> dict:
    return o.payload if isinstance(getattr(o, "payload", None), dict) else {}


def _cidr(raw) -> str:
    """``192.0.2.14 255.255.255.0`` / ``192.0.2.82/24`` -> ``192.0.2.14/24``;
    ``""`` for unset (0.0.0.0) or unparsable."""
    s = str(raw or "").strip()
    if not s:
        return ""
    if " " in s:
        ip, _, mask = s.partition(" ")
        s = "%s/%s" % (ip, mask.strip())
    try:
        iface = ipaddress.ip_interface(s)
    except ValueError:
        return ""
    if iface.ip.is_unspecified:
        return ""
    return str(iface)


def _net(raw) -> str:
    c = _cidr(raw) if raw not in ("0.0.0.0 0.0.0.0", "0.0.0.0/0") else "0.0.0.0/0"
    if not c:
        return ""
    try:
        return str(ipaddress.ip_interface(c).network)
    except ValueError:
        return ""


def _names(children) -> list:
    return [str(_p(c).get("name") or c.mkey or "") for c in children or []]


# ── inventory / overview ─────────────────────────────────────────────────────

def inventory() -> dict:
    """Every device the user may see, with what SATOM last measured on it."""
    appls = visible_appliances(Appliance.query).filter(
        Appliance.is_cluster.is_(False)).order_by(Appliance.name).all()
    snaps = _snapshots([a.id for a in appls])
    errors = []
    scrape, e1 = _last("satom_scrape_up")
    cpu, e2 = _last("satom_box_cpu_pct")
    mem, e3 = _last("satom_box_mem_pct")
    sess, e4 = _last("satom_box_sessions")
    pol, e5 = _last("satom_policy_up")
    ifc, e6 = _last("satom_iface_up")
    for e in (e1, e2, e3, e4, e5, e6):
        if e and e not in errors:
            errors.append(e)

    collectors: dict = {}
    for labels, v in scrape:
        collectors.setdefault(labels.get("device", ""), []).append(
            {"collector": labels.get("collector", ""), "up": v >= 1})
    cpu_d, mem_d, ses_d = _by_device(cpu), _by_device(mem), _by_device(sess)
    pol_d: dict = {}
    for labels, v in pol:
        d = pol_d.setdefault(labels.get("device", ""), [0, 0])
        d[0] += 1
        d[1] += 0 if v >= 1 else 1
    if_d: dict = {}
    for labels, v in ifc:
        d = if_d.setdefault(labels.get("device", ""), [0, 0])
        d[0] += 1
        d[1] += 0 if v >= 1 else 1

    now = datetime.utcnow()
    devices, problems = [], []
    for a in appls:
        cols = sorted(collectors.get(a.name, []), key=lambda c: c["collector"])
        down = [c["collector"] for c in cols if not c["up"]]
        cfg_at = (snaps.get(a.id) or {}).get("config")
        stale = cfg_at is None or (now - cfg_at) > STALE_AFTER
        pol_n, pol_off = pol_d.get(a.name, [0, 0])
        if_n, if_down = if_d.get(a.name, [0, 0])
        if not cols:
            state, why = "unknown", "no collector reports on this device"
        elif down:
            state, why = "critical", "collector failing: " + ", ".join(down)
        elif if_down:
            state, why = "critical", "%d interface(s) with link down" % if_down
        elif stale:
            state, why = "warning", "configuration snapshot is stale"
        else:
            state, why = "ok", ""
        devices.append({
            "id": a.id, "name": a.name, "kind": a.kind,
            "kind_label": KIND_LABEL.get(a.kind, a.kind), "host": a.host,
            "firmware": a.firmware or "", "model": a.model or "",
            "serial": a.serial or "", "maintenance": bool(a.maintenance),
            "collectors": cols, "collectors_down": down,
            "cpu": cpu_d.get(a.name), "mem": mem_d.get(a.name),
            "sessions": ses_d.get(a.name),
            "policies": pol_n, "policies_disabled": pol_off,
            "ifaces": if_n, "ifaces_down": if_down,
            "config_at": cfg_at, "deep_at": (snaps.get(a.id) or {}).get("deep"),
            "stale": stale, "state": state, "why": why,
        })
        if down:
            problems.append({"severity": "critical", "device": a.name, "id": a.id,
                             "text": "collector failing: " + ", ".join(down)})
        if if_down:
            problems.append({"severity": "critical", "device": a.name, "id": a.id,
                             "text": "%d interface(s) with link down" % if_down})
        if stale:
            problems.append({"severity": "warning", "device": a.name, "id": a.id,
                             "text": "configuration snapshot %s" % (
                                 "never taken" if cfg_at is None else
                                 "from %s UTC" % cfg_at.strftime("%Y-%m-%d %H:%M"))})
    order = {"critical": 0, "warning": 1}
    problems.sort(key=lambda p: (order.get(p["severity"], 2), p["device"]))
    counts = {s: sum(1 for d in devices if d["state"] == s)
              for s in ("ok", "warning", "critical", "unknown")}
    return {"devices": devices, "problems": problems, "counts": counts,
            "metric_errors": errors, "read_at": now}


# ── per-device layers ────────────────────────────────────────────────────────

def _iface_metrics(name: str) -> tuple[dict, str]:
    up, e1 = _last('satom_iface_up{device="%s"}' % _esc(name))
    rx, e2 = _instant('rate(satom_iface_rx_bytes_total{device="%s"}[10m]) * 8' % _esc(name))
    tx, e3 = _instant('rate(satom_iface_tx_bytes_total{device="%s"}[10m]) * 8' % _esc(name))
    out: dict = {}
    for rows, key in ((up, "up"), (rx, "rx_bps"), (tx, "tx_bps")):
        for labels, v in rows:
            out.setdefault(labels.get("iface", ""), {})[key] = v
    return out, (e1 or e2 or e3)


def _esc(s: str) -> str:
    return vm_store.escape_label(s)


def _layers_fortiweb(a) -> dict:
    ifm, err = _iface_metrics(a.name)
    l1 = []
    for o in _objects(a.id, "interface_2"):
        p = _p(o)
        name = p.get("name") or o.mkey
        m = ifm.get(name, {})
        l1.append({"name": name, "type": p.get("type", ""), "admin": p.get("status", ""),
                   "link": m.get("up"), "rx_bps": m.get("rx_bps"), "tx_bps": m.get("tx_bps"),
                   "vlan": p.get("vlanid") or "", "ip": _cidr(p.get("ip")),
                   "mtu": p.get("mtu", "")})
    routes = [{"dst": _net(_p(o).get("dst")) or _p(o).get("dst", ""),
               "gateway": _p(o).get("gateway", ""), "device": _p(o).get("device", "")}
              for o in _objects(a.id, "route")]
    vips = [{"name": _p(o).get("name") or o.mkey, "vip": _cidr(_p(o).get("vip")) or _p(o).get("vip", ""),
             "interface": _p(o).get("interface", "")} for o in _objects(a.id, "vip")]
    return {"l1": l1, "l3_routes": routes, "l4_vips": vips,
            "l7": fortiweb_policies(a), "metric_error": err}


def fortiweb_policies(a) -> list:
    """Server policy -> virtual server (VIPs) -> pool -> back-ends, from the
    deep snapshot (the only one that carries pool members) joined with the
    policy status and sessions SATOM's ``policies`` collector measured."""
    pols = _objects(a.id, "server_policy", "deep") or _objects(a.id, "server_policy", "config")
    by_id = {o.id: o for o in pols}
    vs = _children(by_id, "server_policy/vserver")
    pools = _children(by_id, "server_policy/server_pool")
    vlist = _children({o.id for rows in vs.values() for o in rows}, "server_policy/vserver/vip-list")
    vipobj = _children({o.id for rows in vlist.values() for o in rows},
                       "server_policy/vserver/vip-list/vip")
    members = _children({o.id for rows in pools.values() for o in rows},
                        "server_policy/server_pool/pserver-list")
    up, _ = _last('satom_policy_up{device="%s"}' % _esc(a.name))
    ses, _ = _last('satom_policy_sessions{device="%s"}' % _esc(a.name))
    up_d = {l.get("policy"): v for l, v in up}
    ses_d = {l.get("policy"): v for l, v in ses}
    out = []
    for o in pols:
        p = _p(o)
        name = p.get("name") or o.mkey
        vips = []
        for v in vs.get(o.id, []):
            for item in vlist.get(v.id, []):
                ip = p_ip = ""
                for vo in vipobj.get(item.id, []):
                    p_ip = _cidr(_p(vo).get("vip")) or _p(vo).get("vip", "")
                    ip = "%s (%s)" % (p_ip, _p(vo).get("interface", "")) if p_ip else ""
                if not ip and _p(item).get("use-interface-ip") == "enable":
                    ip = "interface IP of %s" % (_p(item).get("interface") or "?")
                vips.append(ip or (_p(item).get("vip") or "?"))
        pool_name, backends = p.get("server-pool", ""), []
        for po in pools.get(o.id, []):
            pool_name = _p(po).get("name") or po.mkey or pool_name
            for m in members.get(po.id, []):
                mp = _p(m)
                backends.append({"ip": mp.get("ip") or mp.get("domain") or "",
                                 "port": mp.get("port", ""),
                                 "status": mp.get("status", ""),
                                 "weight": mp.get("weight", "")})
        state = up_d.get(name)
        out.append({"name": name, "status": p.get("status", ""),
                    "mode": p.get("deployment-mode", ""),
                    "service": p.get("https-service") or p.get("service", ""),
                    "vserver": p.get("vserver", ""), "vips": vips, "pool": pool_name,
                    "backends": backends,
                    "measured_up": None if state is None else state >= 1,
                    "sessions": ses_d.get(name),
                    "wpp": p.get("web-protection-profile", "")})
    return out


def _layers_fortigate(a) -> dict:
    l1 = []
    for o in _objects(a.id, "system_interface"):
        p = _p(o)
        l1.append({"name": p.get("name") or o.mkey, "type": p.get("type", ""),
                   "admin": p.get("status", ""), "link": None, "rx_bps": None, "tx_bps": None,
                   "vlan": p.get("vlanid") or "", "ip": _cidr(p.get("ip")),
                   "mtu": p.get("mtu", ""), "role": p.get("role", ""),
                   "alias": p.get("alias", ""), "parent": p.get("interface", "")})
    routes = [{"dst": _net(_p(o).get("dst")), "gateway": _p(o).get("gateway", ""),
               "device": _p(o).get("device", "")} for o in _objects(a.id, "router_static")]
    pols = _objects(a.id, "firewall_policy")
    ids = {o.id for o in pols}
    kids = {k: _children(ids, "firewall_policy/" + k)
            for k in ("srcintf", "dstintf", "srcaddr", "dstaddr", "service")}
    fw = []
    for o in pols:
        p = _p(o)
        fw.append({"id": p.get("policyid", o.mkey), "name": p.get("name") or o.mkey,
                   "status": p.get("status", ""), "action": p.get("action", ""),
                   "nat": p.get("nat", ""),
                   **{k: _names(kids[k].get(o.id)) for k in kids}})
    addrs = [{"name": _p(o).get("name") or o.mkey, "type": _p(o).get("type", ""),
              "subnet": _net(_p(o).get("subnet")) if _p(o).get("type", "ipmask") == "ipmask" else
              (_p(o).get("fqdn") or "%s-%s" % (_p(o).get("start-ip", ""), _p(o).get("end-ip", "")))}
             for o in _objects(a.id, "firewall_address")]
    return {"l1": l1, "l3_routes": routes, "l4_fw": fw, "l4_addrs": addrs,
            "metric_error": ""}


def _layers_fortiadc(a) -> dict:
    ifm, err = _iface_metrics(a.name)
    l1 = []
    for o in _objects(a.id, "system_interface"):
        p = _p(o)
        name = p.get("name") or o.mkey
        m = ifm.get(name, {})
        l1.append({"name": name, "type": p.get("type", ""), "admin": p.get("status", ""),
                   "link": m.get("up"), "rx_bps": m.get("rx_bps"), "tx_bps": m.get("tx_bps"),
                   "vlan": p.get("vlanid") or "", "ip": _cidr(p.get("ip")), "mtu": p.get("mtu", "")})
    routes = [{"dst": _net(_p(o).get("dest") or _p(o).get("dst")),
               "gateway": _p(o).get("gw") or _p(o).get("gateway", ""),
               "device": _p(o).get("interface") or _p(o).get("device", "")}
              for o in _objects(a.id, "router_static")]
    vss = [{"name": _p(o).get("mkey") or o.mkey, "address": _p(o).get("address", ""),
            "port": _p(o).get("port", ""), "pool": _p(o).get("pool", ""),
            "status": _p(o).get("status", ""), "type": _p(o).get("type", "")}
           for o in _objects(a.id, "load_balance_virtual_server")]
    pools = _objects(a.id, "load_balance_pool")
    mem = _children({o.id for o in pools}, "load_balance_pool/pool_member")
    lb = [{"name": _p(o).get("mkey") or o.mkey,
           "members": [{"real_server": _p(m).get("real_server_id", ""), "port": _p(m).get("port", ""),
                        "status": _p(m).get("status", "")} for m in mem.get(o.id, [])]}
          for o in pools]
    return {"l1": l1, "l3_routes": routes, "l4_vs": vss, "l7_pools": lb, "metric_error": err}


def device_layers(a) -> dict:
    fn = {"fortiweb": _layers_fortiweb, "fortigate": _layers_fortigate,
          "fortiadc": _layers_fortiadc}.get(a.kind)
    data = fn(a) if fn else {"l1": [], "l3_routes": [], "metric_error": ""}
    snaps = _snapshots([a.id]).get(a.id) or {}
    sections = (db.session.query(DeviceObject.section, db.func.count(DeviceObject.id))
                .filter(DeviceObject.appliance_id == a.id)
                .group_by(DeviceObject.section).order_by(DeviceObject.section).all())
    data.update({"snapshots": snaps, "sections": sections, "gaps": gaps(a)})
    return data


# ── what SATOM does not collect yet ──────────────────────────────────────────

#: Measured 2026-11-05 against SATOM 4.10.1 (metrics_collect.COLLECTORS and the
#: device cache). Each entry is something satom-observability reads directly
#: from the device and SATOM has no collector for. Corte 2 fills them.
_GAPS = {
    "fortiweb": [
        "back-end health per server (UP/DOWN): SATOM's 'policies' collector "
        "measures the policy status, not each pool member's health check",
        "pool members come from the nightly deep snapshot, not from a live read",
    ],
    "fortigate": [
        "interface link state and traffic counters (no 'interfaces' collector for FortiGate)",
        "firewall policy hit / byte / session counters",
        "live routing table (only the configured static routes are cached)",
        "detected devices (MAC / IP per interface)",
    ],
    "fortiadc": [
        "real-server addresses of pool members are not joined (only the real-server id)",
    ],
}


def gaps(a) -> list:
    return list(_GAPS.get(a.kind, []))


# ── end-to-end flows ─────────────────────────────────────────────────────────

def _owners() -> list:
    """``[(network, device, iface)]`` for every interface subnet SATOM has
    cached, visible devices only — used to place an IP on the drawing."""
    out = []
    for a in visible_appliances(Appliance.query).filter(Appliance.is_cluster.is_(False)).all():
        logical = {"fortiweb": "interface_2"}.get(a.kind, "system_interface")
        for o in _objects(a.id, logical):
            c = _cidr(_p(o).get("ip"))
            if c:
                out.append((ipaddress.ip_interface(c).network, a.name,
                            _p(o).get("name") or o.mkey))
    return out


def _routes_of(a) -> list:
    """Static routes plus the CONNECTED subnet of every interface of the
    device (gateway ``""``): a back-end on the FortiWeb's own subnet leaves by
    that port, not by the default route."""
    logical = "route" if a.kind == "fortiweb" else "router_static"
    out = []
    for o in _objects(a.id, logical):
        n = _net(_p(o).get("dst"))
        if n:
            out.append((ipaddress.ip_network(n), _p(o).get("gateway", ""), _p(o).get("device", "")))
    for o in _objects(a.id, "interface_2" if a.kind == "fortiweb" else "system_interface"):
        c = _cidr(_p(o).get("ip"))
        if c:
            out.append((ipaddress.ip_interface(c).network, "", _p(o).get("name") or o.mkey))
    return out


def _longest(addr, rows) -> list:
    """Every row of the longest prefix holding ``addr`` (ties kept: several
    devices on one subnet are one segment, not a first-come winner)."""
    hits = [r for r in rows if addr in r[0]]
    if not hits:
        return []
    top = max(r[0].prefixlen for r in hits)
    return [r for r in hits if r[0].prefixlen == top]


def locate(ip: str, owners: list) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    best = _longest(addr, owners)
    if not best:
        return ""
    return "%s: %s" % (best[0][0], ", ".join("%s %s" % (dev, iface) for _, dev, iface in best))


def egress(ip: str, routes: list) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    best = _longest(addr, routes)
    if not best:
        return "no route"
    connected = [r for r in best if not r[1]]
    net, gw, dev = (connected or best)[0]
    if not gw:
        return "%s (connected %s)" % (dev or "?", net)
    return "%s via %s (%s)" % (dev or "?", gw, net)


def flows() -> list:
    """Client -> VIP -> FortiWeb policy -> pool -> back-end, each hop placed on
    the device and interface that owns its subnet (from cached config only)."""
    owners = _owners()
    out = []
    for a in (visible_appliances(Appliance.query)
              .filter(Appliance.kind == "fortiweb", Appliance.is_cluster.is_(False))
              .order_by(Appliance.name).all()):
        routes = _routes_of(a)
        for pol in fortiweb_policies(a):
            hops = []
            for b in pol["backends"]:
                hops.append({**b, "egress": egress(b["ip"], routes),
                             "segment": locate(b["ip"], owners)})
            out.append({"device": a.name, "device_id": a.id, **pol, "hops": hops})
    return out


# ── search ───────────────────────────────────────────────────────────────────

def search(q: str, limit: int = 60) -> list:
    """Devices, interfaces, policies, VIPs and back-ends whose name or address
    contains ``q`` — over the cache of the devices the user may see."""
    q = (q or "").strip()
    if len(q) < 2:
        return []
    needle = q.lower()
    appls = visible_appliances(Appliance.query).filter(Appliance.is_cluster.is_(False)).all()
    hits = []
    for a in appls:
        if needle in " ".join([a.name, a.host or "", a.serial or "", a.firmware or ""]).lower():
            hits.append({"type": "device", "device": a.name, "id": a.id,
                         "name": a.name, "detail": "%s %s" % (KIND_LABEL.get(a.kind, a.kind), a.host)})
    ids = {a.id: a for a in appls}
    if ids:
        logicals = ("interface_2", "system_interface", "server_policy", "vip", "firewall_policy",
                    "firewall_address", "server_policy/server_pool/pserver-list",
                    "load_balance_virtual_server")
        rows = (DeviceObject.query
                .filter(DeviceObject.appliance_id.in_(list(ids)),
                        DeviceObject.logical_name.in_(logicals),
                        db.or_(db.func.lower(DeviceObject.mkey).contains(needle),
                               db.func.lower(db.cast(DeviceObject.payload, db.Text)).contains(needle)))
                .limit(limit * 4).all())
        seen = set()
        for o in rows:
            p, a = _p(o), ids[o.appliance_id]
            name = p.get("name") or p.get("ip") or o.mkey or ""
            key = (a.id, o.logical_name, name)
            if key in seen:
                continue
            seen.add(key)
            detail = (_cidr(p.get("ip")) or _cidr(p.get("vip")) or p.get("ip") or
                      p.get("server-pool") or _net(p.get("subnet")) or p.get("address") or "")
            if needle not in (str(name) + " " + str(detail)).lower():
                continue  # matched an unrelated payload field: not a useful hit
            hits.append({"type": o.logical_name.split("/")[-1], "device": a.name, "id": a.id,
                         "name": name, "detail": detail})
            if len(hits) >= limit:
                break
    return hits[:limit]
