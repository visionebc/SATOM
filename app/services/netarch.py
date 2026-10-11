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
            "tx_bytes": mon.get("tx_bytes"),
        })

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


def probe_http(url: str, header: str = "", timeout: float = 4.0) -> dict:
    """One GET to a back-end, as SATOM sees it: status, latency, one header.

    TLS is not verified: a lab or internal back-end with a private certificate
    is the normal case and the question is "does it answer", not "is its
    certificate public". Redirects are not followed — a 302 is an answer."""
    import httpx

    t0 = time.monotonic()
    try:
        with httpx.Client(verify=False, timeout=timeout, follow_redirects=False) as c:
            r = c.get(url)
        out = {"ok": r.status_code < 500, "status": r.status_code,
               "ms": int((time.monotonic() - t0) * 1000)}
        if header:
            out["header"] = {header: r.headers.get(header, "")}
        return out
    except httpx.HTTPError as exc:
        return {"ok": False, "status": None, "ms": int((time.monotonic() - t0) * 1000),
                "error": "%s: %s" % (type(exc).__name__, str(exc)[:200])}
