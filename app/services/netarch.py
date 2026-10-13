"""Fleet → Architecture: operator-drawn network diagrams with a live overlay.

The Service Diagram (``views/architecture.py``) is DERIVED: it draws what the
FortiWeb cache says. This one is DRAWN: the operator places the elements that
matter for a service path — the Internet, the LAN, each segment, the
firewalls, the ADCs/WAFs, the authenticator, the back-end servers — and links
them. SATOM then lays what the devices themselves say on top of it:

* a FortiGate node bound to an appliance shows its interfaces (address, link,
  counters) and its firewall policies with hit count, bytes and last use;
* every policy is mapped onto the drawing through the segments bound to the
  FortiGate interfaces, so "from where to where" is a line on the diagram and
  not a row to decode;
* a back-end node answers an HTTP probe (status, latency, one header).

WHAT IS STORED AND WHAT IS NOT
    Only the drawing (``ArchDiagram.layout``). Live data is read on request and
    never cached here: a counter shown from a cache would be a counter from
    another moment presented as now.

SCOPE
    A node bound to an appliance the current ADOM cannot see is drawn (the
    drawing belongs to whoever drew it) but never read and never linked —
    :func:`visible_appliances` decides, as everywhere else.
"""
from __future__ import annotations

import ipaddress
import re
import time
from typing import Any

#: Element types an operator can place, with the label the palette shows.
#: ``device`` types may be bound to an appliance of that kind.
NODE_TYPES: dict[str, dict[str, Any]] = {
    "internet": {"label": "Internet", "device": None},
    "lan": {"label": "LAN", "device": None},
    "segment": {"label": "Segment / VLAN", "device": None},
    "fortigate": {"label": "FortiGate", "device": "fortigate"},
    "fortiweb": {"label": "FortiWeb", "device": "fortiweb"},
    "fortiadc": {"label": "FortiADC", "device": "fortiadc"},
    "fortiauthenticator": {"label": "FortiAuthenticator",
                           "device": "fortiauthenticator"},
    "fortianalyzer": {"label": "FortiAnalyzer", "device": "fortianalyzer"},
    "backend": {"label": "Back-end server", "device": None},
    "management": {"label": "Management host", "device": None},
    "host": {"label": "Other host", "device": None},
}

MAX_NODES = 300
MAX_EDGES = 600
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_TEXT = {"label": 80, "note": 400, "cidr": 64, "ip": 64, "vlan": 16,
         "interface": 32, "url": 300, "header": 64}


def _clip(v: Any, n: int) -> str:
    return str(v if v is not None else "").strip()[:n]


def validate_layout(raw: Any) -> tuple[dict, list[str]]:
    """Normalise a posted drawing; return ``(layout, errors)``.

    Errors are reported, never silently repaired: an edge to a node that is not
    there, or two nodes with one id, is a drawing that does not say what the
    operator thinks it says. Unknown keys are dropped (the stored shape is the
    contract the page and :func:`policy_flows` read)."""
    errors: list[str] = []
    if not isinstance(raw, dict):
        return {"nodes": [], "edges": []}, ["layout must be an object"]
    nodes_in = raw.get("nodes") or []
    edges_in = raw.get("edges") or []
    if not isinstance(nodes_in, list) or not isinstance(edges_in, list):
        return {"nodes": [], "edges": []}, ["nodes and edges must be lists"]
    if len(nodes_in) > MAX_NODES:
        errors.append("too many elements (%d, max %d)" % (len(nodes_in), MAX_NODES))
    if len(edges_in) > MAX_EDGES:
        errors.append("too many links (%d, max %d)" % (len(edges_in), MAX_EDGES))

    nodes, seen = [], set()
    for i, n in enumerate(nodes_in[:MAX_NODES]):
        if not isinstance(n, dict):
            errors.append("element %d is not an object" % i)
            continue
        nid = str(n.get("id") or "")
        if not _ID.match(nid):
            errors.append("element %d has an invalid id" % i)
            continue
        if nid in seen:
            errors.append("duplicate element id %s" % nid)
            continue
        seen.add(nid)
        ntype = n.get("type")
        if ntype not in NODE_TYPES:
            errors.append("element %s has an unknown type %r" % (nid, ntype))
            continue
        try:
            x = max(-20000.0, min(20000.0, float(n.get("x") or 0)))
            y = max(-20000.0, min(20000.0, float(n.get("y") or 0)))
        except (TypeError, ValueError):
            errors.append("element %s has a non-numeric position" % nid)
            continue
        out = {"id": nid, "type": ntype, "x": round(x, 1), "y": round(y, 1)}
        for k, size in _TEXT.items():
            if n.get(k) not in (None, ""):
                out[k] = _clip(n.get(k), size)
        if out.get("cidr"):
            try:
                out["cidr"] = str(ipaddress.ip_network(out["cidr"], strict=False))
            except ValueError:
                errors.append("element %s: %r is not a network" % (nid, out["cidr"]))
        if out.get("ip"):
            try:
                ipaddress.ip_address(out["ip"])
            except ValueError:
                errors.append("element %s: %r is not an IP address" % (nid, out["ip"]))
        if out.get("url") and not re.match(r"^https?://", out["url"]):
            errors.append("element %s: probe URL must start with http:// or https://" % nid)
        aid = n.get("appliance_id")
        if aid not in (None, ""):
            if NODE_TYPES[ntype]["device"] is None:
                errors.append("element %s: a %s cannot be bound to an appliance"
                              % (nid, NODE_TYPES[ntype]["label"]))
            else:
                try:
                    out["appliance_id"] = int(aid)
                except (TypeError, ValueError):
                    errors.append("element %s: appliance id must be a number" % nid)
        # A segment says which firewall interface it hangs off: that binding
        # is what puts a firewall policy on the drawing.
        bind = n.get("gateway")
        if bind not in (None, ""):
            if ntype not in ("segment", "lan", "internet"):
                errors.append("element %s: only a network can sit behind a "
                              "firewall interface" % nid)
            elif bind not in {m.get("id") for m in nodes_in if isinstance(m, dict)}:
                errors.append("element %s: gateway %r is not an element" % (nid, bind))
            else:
                out["gateway"] = str(bind)
        nodes.append(out)

    ids = {n["id"] for n in nodes}
    edges, eseen = [], set()
    for i, e in enumerate(edges_in[:MAX_EDGES]):
        if not isinstance(e, dict):
            errors.append("link %d is not an object" % i)
            continue
        a, b = str(e.get("from") or ""), str(e.get("to") or "")
        if a not in ids or b not in ids:
            errors.append("link %d points at an element that is not there" % i)
            continue
        if a == b:
            errors.append("link %d connects an element to itself" % i)
            continue
        key = tuple(sorted((a, b)))
        if key in eseen:
            errors.append("link %s–%s is drawn twice" % key)
            continue
        eseen.add(key)
        out = {"from": a, "to": b}
        if e.get("label"):
            out["label"] = _clip(e.get("label"), 80)
        edges.append(out)

    for n in nodes:
        gw = n.get("gateway")
        if gw and next((m for m in nodes if m["id"] == gw), {}).get("type") != "fortigate":
            errors.append("element %s: gateway must be a FortiGate element" % n["id"])
    return {"nodes": nodes, "edges": edges}, errors


# --------------------------------------------------------------------------- #
#  Live reads                                                                  #
# --------------------------------------------------------------------------- #
def _names(rows) -> list[str]:
    return [str(r.get("name")) for r in (rows or []) if isinstance(r, dict) and r.get("name")]


def fortigate_snapshot(client) -> dict:
    """Interfaces and policies of ONE FortiGate, read now, read-only.

    Each read is reported on its own: a refused monitor call leaves the cmdb
    half standing and says which half is missing, instead of an empty table
    that reads as "no policies"."""
    out: dict[str, Any] = {"interfaces": [], "policies": [], "errors": [],
                           "read_at": int(time.time())}

    def get(path):
        payload, err = client.api_call("GET", path)
        if err:
            out["errors"].append("%s: %s" % (path, err))
            return None
        return (payload or {}).get("results") if isinstance(payload, dict) else None

    ifaces = get("/api/v2/cmdb/system/interface") or []
    ifmon = get("/api/v2/monitor/system/interface") or {}
    if isinstance(ifmon, list):
        ifmon = {r.get("name"): r for r in ifmon if isinstance(r, dict)}
    for i in ifaces:
        if not isinstance(i, dict) or i.get("type") not in (None, "physical", "vlan",
                                                             "aggregate", "redundant",
                                                             "loopback", "tunnel"):
            continue
        name = i.get("name") or ""
        raw_ip = str(i.get("ip") or "")
        ip_cidr = ""
        parts = raw_ip.split()
        if len(parts) == 2 and parts[0] != "0.0.0.0":
            try:
                ip_cidr = str(ipaddress.ip_interface("%s/%s" % tuple(parts)))
            except ValueError:
                ip_cidr = raw_ip
        mon = ifmon.get(name) or {}
        out["interfaces"].append({
            "name": name, "alias": i.get("alias") or "", "ip": ip_cidr,
            "role": i.get("role") or "", "vlanid": i.get("vlanid") or 0,
            "parent": i.get("interface") or "", "status": i.get("status") or "",
            "link": mon.get("link"), "rx_bytes": mon.get("rx_bytes"),
            "tx_bytes": mon.get("tx_bytes"), "mac": mon.get("mac") or "",
            "speed": mon.get("speed"), "rx_errors": mon.get("rx_errors"),
            "tx_errors": mon.get("tx_errors"),
        })

    # L2: who the firewall has seen on each port. L3: what it routes where.
    out["arp"] = [{"ip": a.get("ip"), "mac": a.get("mac"), "interface": a.get("interface"),
                   "age": a.get("age")}
                  for a in (get("/api/v2/monitor/network/arp") or []) if isinstance(a, dict)]
    out["routes"] = [{"dst": r.get("ip_mask"), "gateway": r.get("gateway"),
                      "interface": r.get("interface"), "type": r.get("type"),
                      "distance": r.get("distance")}
                     for r in (get("/api/v2/monitor/router/ipv4") or []) if isinstance(r, dict)]

    pols = get("/api/v2/cmdb/firewall/policy") or []
    mon = {r.get("policyid"): r for r in (get("/api/v2/monitor/firewall/policy") or [])
           if isinstance(r, dict)}
    for p in pols:
        if not isinstance(p, dict):
            continue
        pid = p.get("policyid")
        m = mon.get(pid) or {}
        out["policies"].append({
            "id": pid, "name": p.get("name") or "", "status": p.get("status") or "",
            "action": p.get("action") or "", "nat": p.get("nat") == "enable",
            "srcintf": _names(p.get("srcintf")), "dstintf": _names(p.get("dstintf")),
            "srcaddr": _names(p.get("srcaddr")), "dstaddr": _names(p.get("dstaddr")),
            "service": _names(p.get("service")),
            "hit_count": m.get("hit_count"), "bytes": m.get("bytes"),
            "packets": m.get("packets"), "last_used": m.get("last_used"),
            "active_sessions": m.get("active_sessions"),
        })
    # Policy 0 is the implicit deny: its counter is the traffic NO rule let in.
    if 0 in mon:
        m = mon[0]
        out["implicit_deny"] = {"hit_count": m.get("hit_count"), "bytes": m.get("bytes"),
                                "last_used": m.get("last_used")}
    return out


def _iface_nodes(layout: dict, fgt_node_id: str, snapshot: dict) -> dict[str, list[str]]:
    """FortiGate interface name → the network elements behind it.

    A network element hangs off an interface when its ``gateway`` is this
    FortiGate and either its ``interface`` names the port or its CIDR contains
    the port's address. Both are typed by the operator or read from the
    device; nothing is guessed from names."""
    by_if: dict[str, list[str]] = {}
    nets = [n for n in layout.get("nodes", []) if n.get("gateway") == fgt_node_id]
    for i in snapshot.get("interfaces", []):
        addr = None
        if i.get("ip"):
            try:
                addr = ipaddress.ip_interface(i["ip"]).ip
            except ValueError:
                addr = None
        for n in nets:
            hit = n.get("interface") == i["name"]
            if not hit and addr is not None and n.get("cidr"):
                try:
                    hit = addr in ipaddress.ip_network(n["cidr"], strict=False)
                except ValueError:
                    hit = False
            if hit:
                by_if.setdefault(i["name"], []).append(n["id"])
    return by_if


def policy_flows(layout: dict, fgt_node_id: str, snapshot: dict) -> list[dict]:
    """Every policy of the FortiGate as ``from elements → to elements``.

    A policy whose interface has no element behind it is still returned, with
    the unmapped interface named in ``unmapped``: the page must say "this rule
    goes somewhere you have not drawn", not drop the rule."""
    by_if = _iface_nodes(layout, fgt_node_id, snapshot)
    flows = []
    for p in snapshot.get("policies", []):
        src, dst, unmapped = [], [], []
        for side, acc in (("srcintf", src), ("dstintf", dst)):
            for ifn in p.get(side, []):
                ids = by_if.get(ifn)
                if ids:
                    acc.extend(x for x in ids if x not in acc)
                elif ifn not in unmapped:
                    unmapped.append(ifn)
        flows.append({"policy": p["id"], "name": p.get("name") or "",
                      "from": src, "to": dst, "unmapped": unmapped,
                      "action": p.get("action"), "status": p.get("status"),
                      "hit_count": p.get("hit_count"), "bytes": p.get("bytes")})
    return flows


PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1}


def locate(layout: dict, ip: str) -> tuple[dict | None, dict | None]:
    """Where an address sits on the drawing: ``(host element, network element)``.

    The host is an element whose IP is exactly *ip*; the network is the most
    specific drawn LAN/segment/Internet whose CIDR holds it. Either may be
    ``None``: an address nobody drew is answered as "not on the drawing", not
    pinned to the nearest box."""
    addr = ipaddress.ip_address(ip)
    host, net, best = None, None, -1
    for n in layout.get("nodes", []):
        if n.get("ip") and n["type"] not in ("lan", "segment", "internet"):
            try:
                if ipaddress.ip_address(n["ip"]) == addr and host is None:
                    host = n
            except ValueError:
                pass
        if n.get("cidr"):
            try:
                cidr = ipaddress.ip_network(n["cidr"], strict=False)
            except ValueError:
                continue
            if addr in cidr and cidr.prefixlen > best:
                net, best = n, cidr.prefixlen
    if net is None and addr.is_global:
        # A public address nobody drew a network for is the Internet, when
        # the drawing has one; a private one stays "not on the drawing".
        net = next((n for n in layout.get("nodes", []) if n["type"] == "internet"
                    and not n.get("cidr")), None)
    return host, net


def _net_on(layout, fgt_id, interfaces, ifname):
    by_if = _iface_nodes(layout, fgt_id, {"interfaces": interfaces})
    ids = by_if.get(ifname) or []
    return next((n for n in layout["nodes"] if ids and n["id"] == ids[0]), None)


def trace(layout: dict, call, src: str, dst: str, proto: str = "tcp",
          port: int | None = None, max_hops: int = 6) -> dict:
    """Walk *src* → *dst* through the drawn FortiGates, asking each one.

    ``call(fgt_node_id, path, **params) -> (results, error)`` reads ONE
    FortiGate (``None`` for an element not bound to a readable device). For
    every firewall on the way: the ingress interface is the one its routing
    table uses to reach *src*, the egress the one it uses to reach *dst*, and
    the verdict is the device's own ``policy-lookup`` — SATOM never evaluates a
    rule base itself, because a second evaluator could only disagree with the
    one that forwards the packet. The walk stops on a deny, at the destination
    network, or when the next network has no firewall drawn in front of it."""
    for a in (src, dst):
        ipaddress.ip_address(a)  # ValueError -> the route answers 400
    proto = (proto or "tcp").lower()
    if proto not in PROTOCOLS:
        raise ValueError("protocol must be tcp, udp or icmp")
    if proto != "icmp":
        if port is None or not 1 <= int(port) <= 65535:
            raise ValueError("a tcp/udp trace needs a destination port 1-65535")
    nodes = {n["id"]: n for n in layout.get("nodes", [])}
    src_host, src_net = locate(layout, src)
    dst_host, dst_net = locate(layout, dst)
    fgts = [n for n in layout.get("nodes", []) if n["type"] == "fortigate"]
    adj: dict[str, set] = {}
    for e in layout.get("edges", []):
        adj.setdefault(e["from"], set()).add(e["to"])
        adj.setdefault(e["to"], set()).add(e["from"])

    path = [x["id"] for x in (src_host, src_net) if x]
    hops, verdict, reason = [], "unknown", ""
    cur, seen = src_net, set()
    for _ in range(max_hops):
        if cur is not None:
            cands = [f for f in fgts if f["id"] not in seen
                     and (cur.get("gateway") == f["id"] or f["id"] in adj.get(cur["id"], ()))]
        else:
            cands = [f for f in fgts if f["id"] not in seen]
        hop = None
        for f in cands:
            rin, err = call(f["id"], "/api/v2/monitor/router/lookup", destination=src)
            if err is not None or rin is None:
                hops.append({"fgt": f["id"], "error": err or "not bound to a readable FortiGate"})
                seen.add(f["id"])
                continue
            rout, err = call(f["id"], "/api/v2/monitor/router/lookup", destination=dst)
            if err is not None:
                hops.append({"fgt": f["id"], "error": err})
                seen.add(f["id"])
                continue
            ein = ((rin or {}).get("entries") or [{}])[0] if isinstance(rin, dict) else {}
            eout = ((rout or {}).get("entries") or [{}])[0] if isinstance(rout, dict) else {}
            iin, iout = ein.get("interface"), eout.get("interface")
            if not iin or not iout:
                hops.append({"fgt": f["id"], "error": "no route to %s" % (src if not iin else dst)})
                seen.add(f["id"])
                continue
            if iin == iout and len(cands) > 1:
                continue  # this firewall is not between them
            params = {"srcintf": iin, "sourceip": src, "dest": dst,
                      "protocol": str(PROTOCOLS[proto])}
            if proto == "icmp":
                params.update(icmptype="8", icmpcode="0")
            else:
                params["destport"] = str(int(port))
            pl, err = call(f["id"], "/api/v2/monitor/firewall/policy-lookup", **params)
            if err is not None:
                hops.append({"fgt": f["id"], "srcintf": iin, "dstintf": iout, "error": err})
                seen.add(f["id"])
                continue
            pl = pl or {}
            hop = {"fgt": f["id"], "srcintf": iin, "dstintf": iout,
                   "gateway": eout.get("gateway") or "", "route": eout.get("ip_mask") or "",
                   "match": bool(pl.get("match")), "policy_id": pl.get("policy_id"),
                   "action": pl.get("policy_action") or (
                       pl.get("sec_default_action") if not pl.get("match") else "") or "deny"}
            break
        if hop is None:
            if any(h.get("action") == "accept" for h in hops):
                # Every firewall that could be asked let it through; past
                # this network no firewall is drawn, so the drawing says
                # nothing more about it.
                verdict = "allowed"
                reason = "accepted by every drawn firewall; past %s no firewall is drawn" % (
                    (cur or {}).get("label") or (cur or {}).get("id") or "here")
            else:
                reason = ("no drawn FortiGate sits between these addresses" if not hops
                          else "no FortiGate on the way could be read")
            break
        hops.append(hop)
        seen.add(hop["fgt"])
        if hop["fgt"] not in path:
            path.append(hop["fgt"])
        if hop["action"] != "accept":
            verdict = "denied"
            reason = ("implicit deny: no policy matches" if not hop["match"]
                      else "policy %s denies" % hop["policy_id"])
            break
        ifs, _err = call(hop["fgt"], "/api/v2/cmdb/system/interface")
        interfaces = []
        for i in (ifs or []):
            parts = str(i.get("ip") or "").split()
            if len(parts) == 2 and parts[0] != "0.0.0.0":
                try:
                    interfaces.append({"name": i.get("name"),
                                       "ip": str(ipaddress.ip_interface("%s/%s" % tuple(parts)))})
                except ValueError:
                    pass
        nxt = _net_on(layout, hop["fgt"], interfaces, hop["dstintf"])
        if nxt is not None and nxt["id"] not in path:
            path.append(nxt["id"])
        if nxt is None:
            verdict = "allowed"
            reason = "leaves %s on %s, where nothing is drawn" % (
                nodes[hop["fgt"]].get("label") or hop["fgt"], hop["dstintf"])
            break
        if dst_net is not None and nxt["id"] == dst_net["id"]:
            verdict = "allowed"
            break
        cur = nxt
    else:
        reason = "more than %d firewalls: stopped" % max_hops
    if verdict == "allowed":
        for x in (dst_net, dst_host):
            if x and x["id"] not in path:
                path.append(x["id"])
    return {"src": src, "dst": dst, "proto": proto, "port": port,
            "src_node": src_host and src_host["id"], "src_net": src_net and src_net["id"],
            "dst_node": dst_host and dst_host["id"], "dst_net": dst_net and dst_net["id"],
            "hops": hops, "path": path, "verdict": verdict, "reason": reason}


def probe_http(url: str, header: str = "", timeout: float = 4.0) -> dict:
    """One GET to a back-end, as SATOM sees it: status, latency, one header.

    TLS is not verified: a lab or internal back-end with a private certificate
    is the normal case and the question is "does it answer", not "is its
    certificate public". Redirects are not followed — a 302 is an answer.

    The URL is operator-set and the request fires for anyone who opens the
    live view, so it goes through :func:`service_probe.guarded_get`: refused by
    :mod:`net_guard` (loopback, metadata, this node's services) and pinned to
    the address that was checked."""
    import httpx

    from .net_guard import TargetError
    from .service_probe import guarded_get

    t0 = time.monotonic()
    try:
        r = guarded_get(url, timeout=timeout)
        out = {"ok": r.status_code < 500, "status": r.status_code,
               "ms": int((time.monotonic() - t0) * 1000)}
        if header:
            out["header"] = {header: r.headers.get(header, "")}
        return out
    except TargetError as exc:
        return {"ok": False, "status": None, "ms": int((time.monotonic() - t0) * 1000),
                "error": "target refused: %s" % str(exc)[:200]}
    except httpx.HTTPError as exc:
        return {"ok": False, "status": None, "ms": int((time.monotonic() - t0) * 1000),
                "error": "%s: %s" % (type(exc).__name__, str(exc)[:200])}
