"""Network model over the stored facts (cache first — nothing here talks to a
device): segments (connected subnets and who sits on them), a route lookup per
device, a hop-by-hop trace between monitored devices, the end-to-end data
flows of the server policies, and the dependency index (what rides on what).

What the facts do not say is reported as such: a next hop that is not a
monitored device ends the trace there ("leaves via"), an address group whose
members are not collected makes a firewall match "unverified", never assumed."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from . import insights
from .models import Fact, Source

MAX_HOPS = 6


def _net(text):
    try:
        return ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        return None


def _ip(text):
    try:
        return ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None


def _iface(text):
    try:
        return ipaddress.ip_interface(str(text).strip())
    except ValueError:
        return None


DEFAULT_VDOM = "root"


@dataclass
class Route:
    net: object
    iface: str
    gateway: str | None  # None = connected
    kind: str
    distance: int = 0
    vdom: str = DEFAULT_VDOM


@dataclass
class Model:
    sources: dict = field(default_factory=dict)        # sid -> Source
    objs: dict = field(default_factory=dict)           # sid -> ref -> {key: value}
    addrs: list = field(default_factory=list)          # (iface_obj, sid, ifname)
    routes: dict = field(default_factory=dict)         # sid -> [Route] (every VDOM)
    endpoints: list = field(default_factory=list)      # (ip, sid, mac, ifname)
    ifvdom: dict = field(default_factory=dict)         # (sid, ifname) -> vdom
    ifdown: dict = field(default_factory=dict)         # (sid, ifname) -> why it is down
    notes: dict = field(default_factory=dict)          # sid -> [what the path analysis cannot evaluate]

    def name(self, sid):
        s = self.sources.get(sid)
        return s.name if s else "?"

    def kind(self, sid):
        s = self.sources.get(sid)
        return s.kind if s else ""

    def of(self, sid, prefix):
        return {r.split(":", 1)[1]: kv for r, kv in self.objs.get(sid, {}).items() if r.startswith(prefix + ":")}

    def vdoms(self, sid):
        return sorted({v for (s, _n), v in self.ifvdom.items() if s == sid} |
                      {r.vdom for r in self.routes.get(sid, [])} or {DEFAULT_VDOM})

    def label(self, dom):
        sid, vdom = dom
        multi = len(self.vdoms(sid)) > 1
        return "%s%s" % (self.name(sid), (" [%s]" % vdom) if multi or vdom != DEFAULT_VDOM else "")


def _split_vdom(key):
    """'2@dmz' -> ('2', 'dmz'); '2' -> ('2', 'root')."""
    base, _, vdom = str(key).partition("@")
    return base, (vdom or DEFAULT_VDOM)


def build(sources=None) -> Model:
    sources = Source.query.order_by(Source.name).all() if sources is None else sources
    m = Model(sources={s.id: s for s in sources})
    if not sources:
        return m
    for f in Fact.query.filter(Fact.source_id.in_(list(m.sources))):
        m.objs.setdefault(f.source_id, {}).setdefault(f.object_ref, {})[f.key] = f.value
    for sid in m.sources:
        rts, notes = [], []
        for name, kv in m.of(sid, "if").items():
            vdom = kv.get("vdom") or DEFAULT_VDOM
            m.ifvdom[(sid, name)] = vdom
            admin = str(kv.get("admin_status") or "").strip().lower()
            link = str(kv.get("link") or "").strip().lower()
            if admin == "down":
                m.ifdown[(sid, name)] = "administratively down"
            elif link == "down":
                m.ifdown[(sid, name)] = "link down"
            ifo = _iface(kv.get("address") or kv.get("configured_address") or "")
            if ifo is None or ifo.ip.is_unspecified:
                continue
            m.addrs.append((ifo, sid, name))
            rts.append(Route(ifo.network, name, None, "connected", 0, vdom))
        objs = m.objs.get(sid, {})
        for ref in [r for r in objs if r == "device" or r.startswith("device@")]:
            ref_vdom = _split_vdom(ref)[1] if "@" in ref else DEFAULT_VDOM
            for r in objs[ref].get("routes") or []:
                if not isinstance(r, dict):
                    continue
                net, gw = _net(r.get("dst")), str(r.get("gateway") or "")
                if net is None:
                    continue
                vdom = r.get("vdom") or ref_vdom
                dist = int(r["distance"]) if str(r.get("distance") or "").isdigit() else 0
                if r.get("type") == "connect" or gw in ("", "0.0.0.0"):
                    if not any(x.net == net and x.gateway is None and x.vdom == vdom for x in rts):
                        rts.append(Route(net, str(r.get("device") or ""), None, "connected", 0, vdom))
                    continue
                rts.append(Route(net, str(r.get("device") or ""), gw, str(r.get("type") or "static"), dist, vdom))
            pr = [x for x in (objs[ref].get("policy_routes") or []) if not isinstance(x, dict) or x.get("status") != "disable"]
            if pr:
                notes.append("%d policy route(s)%s are evaluated before the routing table and are NOT evaluated "
                             "here" % (len(pr), "" if ref == "device" else " in vdom " + ref_vdom))
        if str(objs.get("device", {}).get("sdwan") or "").lower() == "enable":
            notes.append("SD-WAN is enabled: its rules can override the routing table and are NOT evaluated here")
        if objs.get("device", {}).get("read_mode") == "SATOM cache only":
            notes.append("configuration from SATOM's snapshot of %s UTC; routes are the configured static ones "
                         "(no live routing table, no dynamic routes)" % objs["device"].get("config_snapshot_at", "?"))
        m.routes[sid] = rts
        m.notes[sid] = notes
        for mac, kv in m.of(sid, "endpoint").items():
            ip = _ip(kv.get("address") or "")
            if ip:
                m.endpoints.append((ip, sid, mac, kv.get("interface") or ""))
    return m


# ── lookups ──────────────────────────────────────────────────────────────────

def route_decision(m: Model, dom, ip) -> dict:
    """Every route of the routing domain that contains ``ip``, how it ranks,
    which are discarded (interface down) and the one chosen: longest prefix,
    then connected before static, then the lower distance; equal best = ECMP."""
    sid, vdom = dom
    cands = []
    for r in m.routes.get(sid, []):
        if r.vdom != vdom or r.net.version != ip.version or ip not in r.net:
            continue
        down = m.ifdown.get((sid, r.iface)) if r.iface else None
        cands.append({"route": r, "dst": str(r.net), "prefixlen": r.net.prefixlen,
                      "via": r.gateway or "connected", "iface": r.iface, "type": r.kind, "distance": r.distance,
                      "usable": not down, "why": ("interface %s %s" % (r.iface, down)) if down else ""})
    usable = [c for c in cands if c["usable"]]
    rank = lambda c: (c["prefixlen"], c["route"].gateway is None, -c["distance"])  # noqa: E731
    best = max((rank(c) for c in usable), default=None)
    chosen = [c for c in usable if rank(c) == best] if best else []
    for c in cands:
        if c in chosen:
            c["outcome"] = "chosen" if c is chosen[0] else "equal cost (ECMP)"
        elif not c["usable"]:
            c["outcome"] = "discarded"
        else:
            b = chosen[0]
            c["outcome"] = ("shorter prefix" if c["prefixlen"] < b["prefixlen"] else
                            "static loses to connected" if c["route"].gateway and b["route"].gateway is None else
                            "higher distance")
    cands.sort(key=lambda c: (-c["prefixlen"], c["distance"]))
    return {"route": chosen[0]["route"] if chosen else None, "candidates": cands, "ecmp": len(chosen) > 1}


def lookup(m: Model, sid: int, ip, vdom: str = DEFAULT_VDOM) -> Route | None:
    return route_decision(m, (sid, vdom), ip)["route"]


def owner(m: Model, ip, exclude_sid=None, exclude_dom=None):
    """(sid, ifname) of the monitored interface holding exactly this IP. An
    inter-VDOM link resolves to the SAME device in another VDOM."""
    for ifo, sid, name in m.addrs:
        if ifo.ip != ip or sid == exclude_sid:
            continue
        if exclude_dom and (sid, m.ifvdom.get((sid, name), DEFAULT_VDOM)) == exclude_dom:
            continue
        return sid, name
    return None


def endpoint_at(m: Model, ip):
    for eip, sid, mac, ifname in m.endpoints:
        if eip == ip:
            return {"source_id": sid, "source": m.name(sid), "mac": mac, "interface": ifname}
    return None


def iface_ip(m: Model, sid, ifname):
    for ifo, s, name in m.addrs:
        if s == sid and name == ifname:
            return ifo.ip
    return None


# ── firewall policy evaluation (FortiGate) ───────────────────────────────────

def _addresses(m: Model, sid, vdom):
    out = {}
    for key, kv in m.of(sid, "address").items():
        name, v = _split_vdom(key)
        if v == vdom:
            out[name] = kv
    return out


def _addr_match(m: Model, sid, names, ip, vdom=DEFAULT_VDOM):
    """(True / False / None, why). None = unknown: a group, a VIP, an FQDN or an
    object that is not collected."""
    if ip is None:
        return None, "address unknown (translated by an IP pool upstream)"
    addrs = _addresses(m, sid, vdom)
    unknown = []
    for n in names or []:
        if n == "all":
            return True, "all"
        sub = (addrs.get(n) or {}).get("subnet")
        if sub is None:
            unknown.append("%s (group / VIP / not collected)" % n)
            continue
        sub = str(sub)
        if "-" in sub:
            a, _, b = sub.partition("-")
            lo, hi = _ip(a), _ip(b)
            if lo and hi and lo.version == ip.version and lo <= ip <= hi:
                return True, "%s = %s" % (n, sub)
            if not (lo and hi):
                unknown.append("%s (%s)" % (n, sub))
            continue
        net = _net(sub)
        if net is None:
            unknown.append("%s (FQDN %s)" % (n, sub))
        elif net.version == ip.version and ip in net:
            return True, "%s = %s" % (n, sub)
    if unknown:
        return None, "cannot resolve " + ", ".join(unknown)
    return False, "%s not in %s" % (ip, ", ".join(names or ["(none)"]))


def _neg(result, negate):
    ok, why = result
    if str(negate or "").lower() != "enable" or ok is None:
        return ok, why
    return (not ok), "negated: " + why


def _policies(m: Model, sid, vdom):
    rows = []
    for key, kv in m.of(sid, "fwpolicy").items():
        pid, v = _split_vdom(key)
        if pid == "0" or (kv.get("vdom") or v) != vdom:
            continue
        rows.append((pid, kv))
    # Sequence order (as the device lists them); id order only when not collected.
    rows.sort(key=lambda x: (x[1].get("seq") if isinstance(x[1].get("seq"), int) else 10 ** 6,
                             int(x[0]) if x[0].isdigit() else 0))
    return rows


def fw_eval(m: Model, sid, vdom, in_if, out_if, src_ip, dst_ip) -> dict:
    """Walk the VDOM's policies in sequence order, criterion by criterion.
    First certain match decides; an uncertain one before it makes the verdict
    ``unverified``; nothing matching = implicit deny."""
    rows, decided, uncertain = [], None, []
    ordered = _policies(m, sid, vdom)
    for pid, kv in ordered:
        row = {"id": pid, "name": kv.get("name") or "", "action": kv.get("action") or "", "nat": kv.get("nat") or "",
               "seq": kv.get("seq"), "hits": kv.get("hit_count"), "bytes": kv.get("bytes"), "crit": []}
        rows.append(row)
        if kv.get("status") not in (None, "enable"):
            row["outcome"] = "disabled"
            continue
        si, di, svc = kv.get("srcintf") or [], kv.get("dstintf") or [], kv.get("service") or []
        crit = [("from interface", (in_if in si or "any" in si), "%s in %s" % (in_if, ", ".join(si) or "—")),
                ("to interface", (out_if in di or "any" in di), "%s in %s" % (out_if, ", ".join(di) or "—"))]
        crit.append(("source address",) + _neg(_addr_match(m, sid, kv.get("srcaddr"), src_ip, vdom), kv.get("srcaddr_negate")))
        crit.append(("destination address",) + _neg(_addr_match(m, sid, kv.get("dstaddr"), dst_ip, vdom), kv.get("dstaddr_negate")))
        svc_ok = True if ("ALL" in svc and str(kv.get("service_negate") or "") != "enable") else None
        crit.append(("service", svc_ok, "ALL" if svc_ok else "%s — service objects not collected" % (", ".join(svc) or "—")))
        row["crit"] = [{"name": c[0], "ok": c[1], "why": c[2]} for c in crit]
        vals = [c[1] for c in crit]
        if False in vals:
            row["outcome"] = "no match"
        elif None in vals:
            row["outcome"] = "possible match (unverified)"
            uncertain.append(row)
        else:
            row["outcome"] = "MATCH — decides"
            decided = row
            break
    if decided:
        verdict = "unverified" if uncertain else ("allowed" if decided["action"] == "accept" else "denied")
    elif uncertain:
        verdict = "unverified"
    else:
        verdict = "denied"
    nat = None
    if decided and decided["nat"] == "enable":
        kv = dict(ordered)[decided["id"]]
        nat = ("source translated to an IP pool (%s) — not resolved" % ", ".join(kv.get("poolname") or [])
               if str(kv.get("ippool") or "") == "enable" else "source translated to the egress interface address")
    return {"verdict": verdict, "decided": decided, "uncertain_before": uncertain, "rows": rows,
            "candidates": [dict(r, certain=(r is decided)) for r in uncertain + ([decided] if decided else [])],
            "implicit_deny": not decided and not uncertain, "nat": nat, "vdom": vdom}


def fw_match(m: Model, sid, in_if, out_if, src_ip, dst_ip, vdom=DEFAULT_VDOM) -> dict:
    """Back-compatible summary of :func:`fw_eval`."""
    return fw_eval(m, sid, vdom, in_if, out_if, src_ip, dst_ip)


# ── trace ────────────────────────────────────────────────────────────────────

def trace(m: Model, sid: int, dst, src_ip=None, vdom: str | None = None) -> dict:
    """Hop-by-hop path from a monitored device (routing domain = device +
    VDOM) to an IP, across monitored devices and VDOMs. Every hop keeps the
    full decision (routes considered, next-hop resolution, firewall policies
    walked, NAT) for the phased analysis. ``status``: reached, leaves,
    no_route, denied, loop, invalid."""
    dst = _ip(dst) if not hasattr(dst, "version") else dst
    if dst is None:
        return {"status": "invalid", "hops": [], "end": "not an IP address", "src_ip": ""}
    dom = (sid, vdom or (m.vdoms(sid)[0] if DEFAULT_VDOM not in m.vdoms(sid) else DEFAULT_VDOM))
    hops, seen, ingress = [], set(), None
    src = _ip(src_ip) if src_ip else None
    src_why = "given" if src else ""
    status, end = "no_route", ""
    for _ in range(MAX_HOPS):
        if dom in seen:
            status, end = "loop", "routing loop back to %s" % m.label(dom)
            break
        seen.add(dom)
        cur = dom[0]
        dec = route_decision(m, dom, dst)
        r = dec["route"]
        hop = {"source_id": cur, "source": m.name(cur), "label": m.label(dom), "vdom": dom[1], "kind": m.kind(cur),
               "in": ingress, "out": r.iface if r else None, "via": (r.gateway or "connected") if r else None,
               "route": str(r.net) if r else None, "decision": dec, "notes": list(m.notes.get(cur, [])),
               "src_ip": str(src) if src else ""}
        if src is None and r is not None and not hops:
            src = iface_ip(m, cur, r.iface)
            src_why = "address of the egress interface %s %s (the device opens the connection)" % (m.name(cur), r.iface)
            hop["src_ip"] = str(src) if src else ""
        if r is None:
            hops.append(hop)
            status, end = "no_route", "%s has no usable route to %s" % (m.label(dom), dst)
            break
        if m.kind(cur) == "fortigate" and ingress:
            fw = fw_eval(m, cur, dom[1], ingress, r.iface, src, dst)
            hop["fw"] = fw
            if fw["nat"]:
                hop["nat"] = fw["nat"]
                src = None if "IP pool" in fw["nat"] else iface_ip(m, cur, r.iface)
                src_why = fw["nat"]
        hops.append(hop)
        if hop.get("fw") and hop["fw"]["verdict"] == "denied":
            status = "denied"
            end = ("%s: no firewall policy matches %s → %s (implicit deny)" if hop["fw"]["implicit_deny"] else
                   "%s: policy denies %s → %s") % (m.label(dom), ingress, r.iface)
            break
        if r.gateway is None:
            dev = owner(m, dst)
            ep = endpoint_at(m, dst)
            status = "reached"
            hop["nexthop"] = "destination is on the connected subnet %s" % r.net
            end = ("%s %s" % (m.name(dev[0]), dev[1]) if dev else
                   "detected device %s on %s %s" % (ep["mac"], ep["source"], ep["interface"]) if ep else
                   "on %s (host not seen by any monitored device)" % r.net)
            break
        gw = _ip(r.gateway)
        nxt = owner(m, gw, exclude_dom=dom) if gw else None
        if nxt is None:
            hop["nexthop"] = "gateway %s is not an address of any monitored device" % r.gateway
            status, end = "leaves", "via %s (not a monitored device)" % r.gateway
            break
        nvdom = m.ifvdom.get(nxt, DEFAULT_VDOM)
        hop["nexthop"] = "gateway %s = %s %s%s" % (r.gateway, m.name(nxt[0]), nxt[1],
                                                    (" (vdom %s)" % nvdom) if len(m.vdoms(nxt[0])) > 1 else "")
        if nxt[0] == cur:
            hop["nexthop"] += " — inter-VDOM link"
        dom, ingress = (nxt[0], nvdom), nxt[1]
    return {"status": status, "hops": hops, "end": end, "src_ip": str(src) if src else "", "src_why": src_why,
            "dst": str(dst)}


# ── views ────────────────────────────────────────────────────────────────────

def segments(m: Model) -> list[dict]:
    """Connected subnets and every monitored interface / detected device on them."""
    nets: dict = {}
    for ifo, sid, name in m.addrs:
        n = nets.setdefault(ifo.network, {"cidr": str(ifo.network), "members": [], "endpoints": []})
        n["members"].append({"source_id": sid, "source": m.name(sid), "interface": name, "ip": str(ifo.ip)})
    for ip, sid, mac, ifname in m.endpoints:
        for net, n in nets.items():
            if ip.version == net.version and ip in net:
                n["endpoints"].append({"source_id": sid, "source": m.name(sid), "mac": mac,
                                       "interface": ifname, "ip": str(ip)})
    out = list(nets.values())
    for n in out:
        n["devices"] = len({x["source_id"] for x in n["members"]})
        n["shared"] = n["devices"] > 1
    out.sort(key=lambda n: (-n["devices"], ipaddress.ip_network(n["cidr"])))
    return out


def route_rows(m: Model) -> list[dict]:
    rows = []
    for sid, rts in m.routes.items():
        for r in rts:
            gw = _ip(r.gateway) if r.gateway else None
            nxt = owner(m, gw, exclude_dom=(sid, r.vdom)) if gw else None
            rows.append({"source_id": sid, "source": m.label((sid, r.vdom)), "vdom": r.vdom, "dst": str(r.net), "interface": r.iface,
                         "gateway": r.gateway or "", "type": r.kind, "distance": r.distance,
                         "next_device": "%s %s" % (m.name(nxt[0]), nxt[1]) if nxt else ""})
    rows.sort(key=lambda r: (r["source"], -ipaddress.ip_network(r["dst"]).prefixlen, r["dst"]))
    return rows


def _vip_ip(listen):
    host = str(listen or "").rsplit(":", 1)[0]
    return _ip(host)


def app_flows(m: Model, pols=None) -> list[dict]:
    """End-to-end flow of every server policy: clients → VIP on its interface →
    policy → pool → each back-end, with the network path from the device to
    the back-end across the monitored devices."""
    pols = insights.policies(list(m.sources.values())) if pols is None else pols
    cache: dict = {}
    out = []
    for p in pols:
        sid = p["source_id"]
        pkv = m.objs.get(sid, {}).get("policy:" + p["name"], {})
        vip_ip = _vip_ip(p.get("listen"))
        vip_if = ""
        for vname, kv in m.of(sid, "vip").items():
            if _iface(kv.get("vip") or "") and vip_ip and _iface(kv["vip"]).ip == vip_ip:
                vip_if = kv.get("vip_interface") or ""
        backends = []
        for b in pkv.get("backends") or []:
            if not isinstance(b, dict):
                continue
            key = (sid, str(b.get("address")))
            if key not in cache:
                cache[key] = trace(m, sid, b.get("address"))
            t = cache[key]
            backends.append({"address": b.get("address"), "port": b.get("port"), "pool": b.get("pool"),
                             "health": insights.backend_health(b.get("health")), "raw_health": b.get("health"),
                             "backup": bool(b.get("backup")), "path": t})
        upstream = []
        if vip_ip:
            for other in m.sources:
                if other == sid:
                    continue
                t = trace(m, other, vip_ip)
                if any(h["source_id"] == sid for h in t["hops"]) or (t["status"] == "reached" and owner(m, vip_ip) and owner(m, vip_ip)[0] == sid):
                    upstream.append({"source_id": other, "source": m.name(other), "path": t})
        paths = [b["path"]["status"] for b in backends]
        out.append(dict(p, vip_ip=str(vip_ip) if vip_ip else "", vip_interface=vip_if, backend_rows=backends,
                        upstream=upstream, path_issues=sum(1 for s in paths if s in ("no_route", "denied", "loop"))))
    return out


def fw_flows(m: Model) -> list[dict]:
    rows = []
    for sid in m.sources:
        if m.kind(sid) != "fortigate":
            continue
        for key, kv in m.of(sid, "fwpolicy").items():
            pid, vdom = _split_vdom(key)
            rows.append({"source_id": sid, "source": m.name(sid), "id": pid, "vdom": kv.get("vdom") or vdom, "seq": kv.get("seq"),
                         "name": kv.get("name") or ("implicit deny" if pid == "0" else ""),
                         "srcintf": kv.get("srcintf") or [], "dstintf": kv.get("dstintf") or [],
                         "srcaddr": kv.get("srcaddr") or [], "dstaddr": kv.get("dstaddr") or [],
                         "service": kv.get("service") or [], "action": kv.get("action") or ("deny" if pid == "0" else ""),
                         "nat": kv.get("nat") or "", "status": kv.get("status") or ("enable" if pid == "0" else ""),
                         "hits": kv.get("hit_count"), "bytes": kv.get("bytes"),
                         "sessions": kv.get("active_sessions"), "last_used": kv.get("last_used") or ""})
    rows.sort(key=lambda r: (r["source"], r["vdom"], r["seq"] if isinstance(r["seq"], int) else 10 ** 6,
                             int(r["id"]) if str(r["id"]).isdigit() else 0))
    return rows


def dependencies(m: Model, flows=None) -> dict:
    """What depends on what, for impact analysis: shared back-ends, pools,
    VIPs, interfaces, gateways and address objects, each with its dependents."""
    flows = app_flows(m) if flows is None else flows
    backends: dict = {}
    pools: dict = {}
    for f in flows:
        if f.get("server_pool"):
            pools.setdefault((f["source_id"], f["server_pool"]), {
                "source_id": f["source_id"], "source": f["source"], "pool": f["server_pool"],
                "policies": [], "members": 0})["policies"].append(f["name"])
        for b in f["backend_rows"]:
            k = (str(b["address"]), b["port"])
            row = backends.setdefault(k, {"address": str(b["address"]), "port": b["port"], "health": b["health"],
                                          "dependents": [], "path": b["path"]["status"]})
            row["dependents"].append({"source_id": f["source_id"], "source": f["source"], "policy": f["name"],
                                      "pool": b["pool"], "enabled": f.get("status") == "enable"})
            if b["health"] == "down" or row["health"] == "down":
                row["health"] = "down" if b["health"] == "down" else row["health"]
    for (sid, pool), row in pools.items():
        row["members"] = (m.objs.get(sid, {}).get("pool:" + pool, {}) or {}).get("members")
    # Interfaces: VIPs, routes, firewall policies, back-end egress, detected devices.
    ifs: dict = {}

    def ifrow(sid, name):
        return ifs.setdefault((sid, name), {"source_id": sid, "source": m.name(sid), "interface": name,
                                            "vips": [], "routes": [], "fwpolicies": [], "egress": set(),
                                            "endpoints": [], "state": ""})
    for i in insights.interfaces(list(m.sources.values())):
        ifrow(i["source_id"], i["name"])["state"] = i["state"]
    for sid in m.sources:
        for vname, kv in m.of(sid, "vip").items():
            if kv.get("vip_interface"):
                ifrow(sid, kv["vip_interface"])["vips"].append(vname)
        for r in m.routes.get(sid, []):
            if r.gateway and r.iface:
                ifrow(sid, r.iface)["routes"].append(str(r.net))
        for pid, kv in m.of(sid, "fwpolicy").items():
            for n in set((kv.get("srcintf") or []) + (kv.get("dstintf") or [])):
                if n != "any":
                    ifrow(sid, n)["fwpolicies"].append("#%s %s" % (pid, kv.get("name") or ""))
    for ip, sid, mac, ifname in m.endpoints:
        if ifname:
            ifrow(sid, ifname)["endpoints"].append(str(ip))
    for f in flows:
        for b in f["backend_rows"]:
            for h in b["path"]["hops"]:
                if h.get("out"):
                    ifrow(h["source_id"], h["out"])["egress"].add(f["name"])
    for row in ifs.values():
        row["egress"] = sorted(row["egress"])
        row["fwpolicies"] = sorted(set(row["fwpolicies"]))
        row["dependents"] = len(row["vips"]) + len(row["egress"]) + len(row["fwpolicies"]) + len(row["endpoints"])
    # Gateways: next hops the devices rely on.
    gws: dict = {}
    for sid, rts in m.routes.items():
        for r in rts:
            if r.gateway:
                g = gws.setdefault(r.gateway, {"gateway": r.gateway, "users": [], "device": ""})
                g["users"].append({"source_id": sid, "source": m.name(sid), "dst": str(r.net), "interface": r.iface})
                gw = _ip(r.gateway)
                o = owner(m, gw) if gw else None
                g["device"] = "%s %s" % (m.name(o[0]), o[1]) if o else ""
    # Address objects (FortiGate): which firewall policies use them.
    addrs = []
    for sid in m.sources:
        used: dict = {}
        for pid, kv in m.of(sid, "fwpolicy").items():
            for n in (kv.get("srcaddr") or []) + (kv.get("dstaddr") or []):
                used.setdefault(n, set()).add(pid)
        for name, kv in m.of(sid, "address").items():
            addrs.append({"source_id": sid, "source": m.name(sid), "name": name, "subnet": kv.get("subnet"),
                          "policies": sorted(used.get(name, ()), key=lambda x: int(x) if x.isdigit() else 0)})
    addrs.sort(key=lambda a: (-len(a["policies"]), a["source"], a["name"]))
    return {
        "backends": sorted(backends.values(), key=lambda b: (-len(b["dependents"]), b["address"])),
        "pools": sorted(pools.values(), key=lambda p: (-len(p["policies"]), p["pool"])),
        "interfaces": sorted(ifs.values(), key=lambda r: (-r["dependents"], r["source"], r["interface"])),
        "gateways": sorted(gws.values(), key=lambda g: -len(g["users"])),
        "addresses": addrs,
    }
