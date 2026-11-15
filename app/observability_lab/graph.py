"""The diagram: nodes and edges, same shape as SATOM Architecture
(``{"nodes": [...], "edges": [{"from", "to"}]}``) so its drawings import as-is,
plus bindings to sources (``source_id`` on a node, ``source_id`` +
``object_ref`` on an edge or a node)."""
from __future__ import annotations

import ipaddress
import re
from typing import Any

MAX_NODES, MAX_EDGES = 500, 1500
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_TEXT = {"label": 80, "note": 400, "ip": 64, "cidr": 64, "vlan": 16, "url": 300,
         "object_ref": 255}

#: Palette. ``icon`` = Bootstrap Icons name; ``kinds`` = source kinds a node of
#: this type can be bound to (empty = any).
NODE_TYPES: dict[str, dict[str, Any]] = {
    "internet": {"label": "Internet", "icon": "globe2"},
    "user": {"label": "Client / user", "icon": "person"},
    "lan": {"label": "LAN", "icon": "diagram-3"},
    "segment": {"label": "Segment / VLAN", "icon": "bezier2"},
    "router": {"label": "Router", "icon": "router"},
    "switch": {"label": "Switch", "icon": "hdd-network"},
    "firewall": {"label": "Firewall", "icon": "bricks"},
    "fortigate": {"label": "FortiGate", "icon": "shield-shaded"},
    "fortiweb": {"label": "FortiWeb", "icon": "shield-check"},
    "fortiadc": {"label": "FortiADC", "icon": "distribute-horizontal"},
    "fortiauthenticator": {"label": "FortiAuthenticator", "icon": "key"},
    "fortianalyzer": {"label": "FortiAnalyzer", "icon": "graph-up"},
    "load-balancer": {"label": "Load balancer", "icon": "distribute-vertical"},
    "dns": {"label": "DNS / DDI", "icon": "signpost-split"},
    "server": {"label": "Server", "icon": "server"},
    "database": {"label": "Database", "icon": "database"},
    "api": {"label": "API / service", "icon": "plug"},
    "cloud": {"label": "Cloud", "icon": "cloud"},
    "host": {"label": "Other host", "icon": "pc-display"},
}


def _clip(v, n):
    return str(v)[:n]


def validate_layout(raw: Any) -> tuple[dict, list[str]]:
    errors: list[str] = []
    if not isinstance(raw, dict):
        return {"nodes": [], "edges": []}, ["layout must be an object"]
    nodes_in, edges_in = raw.get("nodes") or [], raw.get("edges") or []
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
        if out.get("ip"):
            try:
                ipaddress.ip_address(out["ip"])
            except ValueError:
                errors.append("element %s: %r is not an IP address" % (nid, out["ip"]))
        if out.get("cidr"):
            try:
                out["cidr"] = str(ipaddress.ip_network(out["cidr"], strict=False))
            except ValueError:
                errors.append("element %s: %r is not a network" % (nid, out["cidr"]))
        sid = n.get("source_id")
        if sid not in (None, ""):
            try:
                out["source_id"] = int(sid)
            except (TypeError, ValueError):
                errors.append("element %s: source must be a number" % nid)
        # Expanded = its live children (policies, backends) are drawn. They are
        # derived from the facts on every render, never stored.
        if n.get("expand") is True:
            out["expand"] = True
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
        for k in ("label", "object_ref"):
            if e.get(k):
                out[k] = _clip(e.get(k), _TEXT[k])
        if e.get("source_id") not in (None, ""):
            try:
                out["source_id"] = int(e["source_id"])
            except (TypeError, ValueError):
                errors.append("link %s–%s: source must be a number" % key)
        edges.append(out)
    return {"nodes": nodes, "edges": edges}, errors


_GUESS = [
    ("fortigate", r"fortigate|\bfgt"), ("fortiweb", r"fortiweb|\bfwb"),
    ("fortiadc", r"fortiadc|\bfad"), ("fortiauthenticator", r"fortiauth|\bfac\b"),
    ("fortianalyzer", r"fortianalyzer|\bfaz"), ("firewall", r"firewall|\bfw\b|palo|checkpoint|asa\b"),
    ("load-balancer", r"load.?balanc|\blb\b|f5|big-?ip|haproxy|nginx"),
    ("router", r"router|\brtr|gateway|\bgw\b"), ("switch", r"switch|\bsw\b|nexus|catalyst"),
    ("internet", r"internet|\bwan\b"), ("cloud", r"cloud|aws|azure|gcp"),
    ("database", r"database|\bdb\b|sql|postgres|oracle|mongo"),
    ("dns", r"\bdns\b|\bddi\b|solidserver|infoblox|bluecat"),
    ("api", r"\bapi\b|service|microservice"), ("segment", r"vlan|segment|subnet|dmz"),
    ("lan", r"\blan\b"), ("user", r"user|client|browser"),
    ("server", r"server|\bsrv|backend|host|vm\b|web"),
]


def guess_type(*texts: str) -> str | None:
    t = " ".join(x for x in texts if x).lower()
    for ntype, rx in _GUESS:
        if re.search(rx, t):
            return ntype
    return None
