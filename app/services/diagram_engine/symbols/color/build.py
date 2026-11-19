"""Generator of the ``color`` symbol library (full-colour flat icons).

BUILD-TIME ONLY: SATOM never runs this at runtime. Re-run after editing::

    python3 app/services/diagram_engine/symbols/color/build.py

Every colour icon is the matching ``generic`` icon (same original artwork, so
both libraries stay in step) repainted with explicit fills from the family
palette in ``../palette.py`` (documented in ``PALETTE.md``): the outline and
glyph lines in the family *ink*, the main body in the family *light*, inner
panels in white or *tint*, status dots in the family *base*. No
``currentColor``, no gradients: the element colour never repaints them.

Deterministic; ``tests/test_diagram_symbols_variants.py`` re-runs it into a
temporary folder and requires byte-identical output. Stdlib only.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from xml.etree import ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PAL = _load("_satom_symbol_palette", os.path.join(ROOT, "palette.py"))
GEO = _load("_satom_symbol_geometry", os.path.join(ROOT, "..", "geometry.py"))

NS = "{http://www.w3.org/2000/svg}"
ATTR_ORDER = ("viewBox", "fill", "fill-rule", "stroke", "stroke-width", "stroke-linecap",
              "stroke-linejoin", "stroke-dasharray", "opacity", "transform", "d", "points",
              "x", "y", "width", "height", "rx", "ry", "cx", "cy", "r", "x1", "y1", "x2", "y2")
WHITE = "#FFFFFF"

#: The colour library: generic symbol ids, grouped by the palette family that paints them.
#: The palette follows FUNCTION (a firewall is red even though its category is network.firewall).
CONCEPTS = {
    "network": ["router", "switch-l2", "switch-l3", "core-switch", "access-switch", "distribution-switch",
                "poe-switch", "load-balancer", "access-point", "wireless-controller", "vpn-gateway", "proxy",
                "internet", "wan", "lan", "vlan", "subnet", "modem", "dns", "dhcp", "nat-gateway", "cdn", "vpc",
                "cell-tower", "satellite", "sdwan-edge", "antenna", "transit-gateway", "patch-panel", "cloud",
                "routing-domain", "mpls", "fibre"],
    "security": ["firewall", "ngfw", "utm", "waf", "ids-ips", "edr", "xdr", "nac", "pam", "hsm", "vault",
                 "mfa-token", "certificate-authority", "certificate", "ddos-protection", "email-security",
                 "web-gateway", "casb", "ztna", "siem", "soc", "identity", "authentication", "sso", "key",
                 "malware", "dlp", "honeypot", "security-zone", "dmz", "threat-intel", "vulnerability-scanner",
                 "policy", "directory"],
    "infra": ["server", "rack-server", "rack", "blade-chassis", "storage", "nas", "san", "tape-library", "ups",
              "pdu", "cooling", "generator", "gpu-server", "mainframe", "hypervisor", "virtual-machine",
              "container", "kubernetes", "pod", "datacenter", "edge-node", "object-storage", "file-share",
              "backup", "ha-cluster", "region", "availability-zone"],
    "devices": ["laptop", "desktop", "thin-client", "phone", "tablet", "printer", "scanner", "ip-phone",
                "ip-camera", "smart-tv", "iot-sensor", "plc", "badge-reader"],
    "data": ["database", "data-warehouse", "data-lake", "cache", "search-index", "etl", "bi-dashboard",
             "ml-model", "ai-agent", "llm", "event-stream", "graph-db", "time-series-db", "queue"],
    "software": ["application", "microservice", "api", "api-gateway", "function", "web-app", "mobile-app",
                 "browser", "message-bus", "ci-cd", "git-repo", "container-registry", "scheduler", "webhook",
                 "email", "chat", "sms", "terminal", "code", "document", "identity-provider"],
    "people": ["user", "admin", "team", "customer", "vendor", "soc-analyst", "on-call", "ticket", "incident",
               "alert", "building", "headquarters", "branch-office", "home-office", "runbook", "approval"],
}

#: Per-icon paint roles by leaf index, where the heuristic needs help:
#: "body" (light), "panel" (white), "tint", "accent" (base fill), "none" (stroke only), "ink" (solid ink).
OVERRIDES = {
    "user": {1: "body"}, "admin": {1: "body"}, "team": {1: "body", 3: "tint", 5: "tint"},
    "customer": {1: "body", 2: "accent"}, "vendor": {1: "body"}, "soc-analyst": {1: "body"},
    "on-call": {1: "body", 2: "accent"}, "identity-provider": {1: "body"}, "pam": {1: "body"},
    "alert": {0: "body"}, "incident": {1: "panel"}, "ddos-protection": {0: "body"},
    "cache": {}, "malware": {0: "body"}, "cloud": {0: "body"}, "casb": {0: "body"},
    "internet": {}, "ups": {2: "accent"}, "generator": {}, "honeypot": {2: "accent"},
    "threat-intel": {0: "body", 1: "panel", 2: "accent"},
}


def fmt(v: float) -> str:
    s = "%.2f" % v
    s = s.rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def _bbox(el):
    tag = el.tag.replace(NS, "")
    g = lambda k: float(el.get(k, "0"))
    if tag == "rect":
        return g("x"), g("y"), g("x") + g("width"), g("y") + g("height")
    if tag == "circle":
        return g("cx") - g("r"), g("cy") - g("r"), g("cx") + g("r"), g("cy") + g("r")
    if tag == "ellipse":
        return g("cx") - g("rx"), g("cy") - g("ry"), g("cx") + g("rx"), g("cy") + g("ry")
    if tag == "line":
        return min(g("x1"), g("x2")), min(g("y1"), g("y2")), max(g("x1"), g("x2")), max(g("y1"), g("y2"))
    if tag in ("polygon", "polyline"):
        v = [float(t) for t in el.get("points", "").split()]
        return min(v[0::2]), min(v[1::2]), max(v[0::2]), max(v[1::2])
    if tag == "path":
        pts = [p for sub, _closed_ in GEO.flatten(GEO.parse_path(el.get("d"))) for p in sub] if el.get("d") else []
        if not pts:
            return 0, 0, 0, 0
        xs, ys = [p[0] for p in pts], [p[1] for p in pts]
        return min(xs), min(ys), max(xs), max(ys)
    return 0, 0, 0, 0


def _closed(el) -> bool:
    tag = el.tag.replace(NS, "")
    if tag in ("rect", "circle", "ellipse", "polygon"):
        return True
    if tag == "path":
        d = el.get("d", "").strip()
        return d[-1:] in ("Z", "z") and d.count("M") + d.count("m") == 1
    return False


def _area(b):
    return max(0.0, b[2] - b[0]) * max(0.0, b[3] - b[1])


def _inside(a, b, slack=0.5):
    return a[0] >= b[0] - slack and a[1] >= b[1] - slack and a[2] <= b[2] + slack and a[3] <= b[3] + slack


def _attrs(d):
    return "".join(' %s="%s"' % (k, d[k]) for k in ATTR_ORDER if k in d)


def colourise(sid: str, svg_text: str, family: str) -> str:
    root = ET.fromstring(svg_text)
    ink, light, tint, base = (PAL.colour(family, s) for s in ("ink", "light", "tint", "base"))
    leaves = []

    def walk(node, parent_dash):
        for ch in node:
            tag = ch.tag.replace(NS, "")
            if tag == "g":
                walk(ch, ch.get("stroke-dasharray") or parent_dash)
            else:
                leaves.append((ch, parent_dash))
    walk(root, None)
    boxes = [_bbox(el) for el, _ in leaves]
    cands = [i for i, (el, _) in enumerate(leaves) if _closed(el) and el.get("fill") != "currentColor"]
    body = max(cands, key=lambda i: (_area(boxes[i]), -i)) if cands else None
    over = OVERRIDES.get(sid, {})
    roles = {}
    for i, (el, dash) in enumerate(leaves):
        if i in over:
            roles[i] = over[i]
        elif el.get("fill") == "currentColor":
            roles[i] = "ink"
        elif not _closed(el):
            roles[i] = "none"
        elif i == body:
            roles[i] = "tint" if dash else "body"
        elif body is not None and _inside(boxes[i], boxes[body]) and _area(boxes[i]) > 6:
            roles[i] = "panel"
        elif _area(boxes[i]) <= 30:
            roles[i] = "accent"
        else:
            roles[i] = "tint"
    paint = {"body": light, "panel": WHITE, "tint": tint, "accent": base, "ink": ink}

    def emit(node, idx_iter):
        out = []
        for ch in node:
            tag = ch.tag.replace(NS, "")
            if tag == "g":
                inner = emit(ch, idx_iter)
                out.append("<g%s>%s</g>" % (_attrs({k: v for k, v in ch.attrib.items()}), inner))
                continue
            i = next(idx_iter)
            a = {k: v for k, v in ch.attrib.items()}
            role = roles[i]
            if role == "ink":
                a["fill"] = ink
                a["stroke"] = "none"
            elif role != "none":
                a["fill"] = paint[role]
            a.pop("stroke", None) if a.get("stroke") == "currentColor" else None
            out.append("<%s%s/>" % (tag, _attrs(a)))
        return "".join(out)
    inner = emit(root, iter(range(len(leaves))))
    head = {"viewBox": root.get("viewBox"), "fill": "none", "stroke": ink, "stroke-width": root.get("stroke-width", "2"),
            "stroke-linecap": "round", "stroke-linejoin": "round"}
    out = '<svg xmlns="http://www.w3.org/2000/svg"%s>%s</svg>' % (_attrs(head), inner)
    assert "currentColor" not in out, sid
    return out


def _ids(path):
    try:
        with open(path, "rb") as fh:
            return {s["id"] for s in json.loads(fh.read().decode("utf-8")).get("symbols", [])}
    except (OSError, ValueError):
        return set()


def build(out_dir: str = HERE, siblings_dir: str | None = None) -> dict:
    siblings_dir = siblings_dir or ROOT
    with open(os.path.join(siblings_dir, "generic", "library.json"), "rb") as fh:
        gen = json.loads(fh.read().decode("utf-8"))
    by_id = {s["id"]: s for s in gen["symbols"]}
    iso_ids = _ids(os.path.join(siblings_dir, "iso3d", "library.json"))
    files: dict = {}
    syms, classes = [], {}
    for family in CONCEPTS:
        for sid in CONCEPTS[family]:
            g = by_id[sid]
            with open(os.path.join(siblings_dir, "generic", g["svg"]), "rb") as fh:
                text = colourise(sid, fh.read().decode("utf-8"), family)
            name = sid + ".svg"
            files[name] = text.encode("utf-8")
            fam, cls = g["category"].split(".")
            classes.setdefault(fam, {})[cls] = gen["families"].get(fam, {}).get("classes", {}).get(cls, g["label"])
            variants = {"generic": sid}
            if sid in iso_ids:
                variants["iso3d"] = sid
            syms.append({"id": sid, "label": g["label"], "category": g["category"], "shape": "symbol",
                         "w": 64, "h": 64, "ports": [{"id": "n", "x": 0.5, "y": 0}, {"id": "e", "x": 1, "y": 0.5},
                                                     {"id": "s", "x": 0.5, "y": 1}, {"id": "w", "x": 0, "y": 0.5}],
                         "keywords": list(g.get("keywords", [])) + ["colour", "color"], "aliases": {},
                         "style": {"fill": "none", "stroke": "none"}, "svg": name, "variants": variants})
    order = [f for f in ("network", "security", "infra", "devices", "data", "software", "people", "flow", "c4")
             if f in classes] + sorted(f for f in classes if f not in ("network", "security", "infra", "devices",
                                                                       "data", "software", "people", "flow", "c4"))
    fams = {f: {"label": gen["families"].get(f, {}).get("label", f.title()), "classes": dict(sorted(classes[f].items()))}
            for f in order}
    lib = {"schema": "satom.symbols/1", "id": "color", "label": "Full colour", "version": "1.0",
           "license": "ELv2 (original artwork, drawn for SATOM)", "variant": "color", "families": fams,
           "symbols": syms}
    files["library.json"] = (json.dumps(lib, indent=1, ensure_ascii=True) + "\n").encode("utf-8")
    os.makedirs(out_dir, exist_ok=True)
    for name in sorted(files):
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(files[name])
    return files


if __name__ == "__main__":
    out = build(sys.argv[1] if len(sys.argv) > 1 else HERE)
    print("%d icons, %d bytes" % (len(out) - 1, sum(len(v) for k, v in out.items() if k.endswith(".svg"))))
