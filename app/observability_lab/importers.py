"""Turn a draw.io file, a Mermaid flowchart or a SATOM Architecture layout
into a layout. Nothing is dropped silently: shapes whose type cannot be told
become "Other host" and are listed in the warnings for the operator to retype.
"""
from __future__ import annotations

import base64
import html
import json
import re
import zlib
from urllib.parse import unquote
from xml.etree import ElementTree as ET

from .graph import NODE_TYPES, guess_type, validate_layout

MAX_INPUT = 4 * 1024 * 1024


class ImportError_(ValueError):
    pass


def _plain(label: str) -> str:
    text = re.sub(r"<br\s*/?>", " ", label or "", flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    return " ".join(html.unescape(text).split())[:80]


def _safe_id(raw: str, used: set) -> str:
    base = re.sub(r"[^A-Za-z0-9_.:-]", "_", raw or "n")[:56] or "n"
    nid, i = base, 1
    while nid in used:
        i += 1
        nid = "%s_%d" % (base, i)
    used.add(nid)
    return nid


def _finish(nodes, edges, warnings):
    layout, errors = validate_layout({"nodes": nodes, "edges": edges})
    return layout, warnings + errors


# ---------------------------------------------------------------- draw.io
def _drawio_models(data: bytes):
    """Yield <mxGraphModel> elements; diagrams may be stored compressed
    (base64 + raw deflate + URL-encoding) inside <diagram>."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ImportError_("not a draw.io XML file: %s" % exc) from exc
    if root.tag == "mxGraphModel":
        yield root
        return
    for d in root.iter("diagram"):
        inner = d.find("mxGraphModel")
        if inner is not None:
            yield inner
            continue
        text = (d.text or "").strip()
        if not text:
            continue
        try:
            raw = zlib.decompress(base64.b64decode(text), -15)
            yield ET.fromstring(unquote(raw.decode("utf-8")))
        except Exception as exc:  # noqa: BLE001
            raise ImportError_("compressed draw.io page could not be decoded: %s" % exc) from exc


def from_drawio(data: bytes) -> tuple[dict, list[str]]:
    if len(data) > MAX_INPUT:
        raise ImportError_("file too large")
    models = list(_drawio_models(data))
    if not models:
        raise ImportError_("no diagram found in the file")
    warnings = []
    if len(models) > 1:
        warnings.append("file has %d pages; only the first was imported" % len(models))
    model = models[0]
    nodes, edges, used, idmap = [], [], set(), {}
    cells = list(model.iter("mxCell"))
    for c in cells:
        if c.get("vertex") != "1":
            continue
        style = c.get("style") or ""
        label = _plain(c.get("value") or "")
        if not label and ("text;" in style or style.startswith("text")):
            continue
        geo = c.find("mxGeometry")
        x = float(geo.get("x", 0)) if geo is not None else 0.0
        y = float(geo.get("y", 0)) if geo is not None else 0.0
        w = float(geo.get("width", 0)) if geo is not None else 0.0
        h = float(geo.get("height", 0)) if geo is not None else 0.0
        ntype = guess_type(label, style)
        if ntype is None:
            ntype = "host"
            warnings.append("'%s' typed as Other host — set its type" % (label or c.get("id")))
        nid = _safe_id(c.get("id"), used)
        idmap[c.get("id")] = nid
        node = {"id": nid, "type": ntype, "x": round(x + w / 2, 1), "y": round(y + h / 2, 1)}
        if label:
            node["label"] = label
        ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", label)
        if ip:
            node["ip"] = ip.group(1)
        nodes.append(node)
    for c in cells:
        if c.get("edge") != "1":
            continue
        a, b = idmap.get(c.get("source")), idmap.get(c.get("target"))
        if not a or not b:
            warnings.append("a link without both ends was skipped (id %s)" % c.get("id"))
            continue
        e = {"from": a, "to": b}
        if _plain(c.get("value") or ""):
            e["label"] = _plain(c.get("value"))
        edges.append(e)
    return _finish(nodes, _dedupe(edges, warnings), warnings)


def _dedupe(edges, warnings):
    out, seen = [], set()
    for e in edges:
        k = tuple(sorted((e["from"], e["to"])))
        if e["from"] == e["to"] or k in seen:
            warnings.append("duplicate or self link %s–%s merged" % k)
            continue
        seen.add(k)
        out.append(e)
    return out


# ---------------------------------------------------------------- Mermaid
_NODE = r"([A-Za-z0-9_.:-]+)\s*(\[\[?[^\]]*\]?\]|\(\(?[^)]*\)?\)|\{[^}]*\}|>[^\]]*\]|\[/[^\]]*/\])?"
_ARROW = r"\s*(?:--\s*([^-<>|][^>]*?)\s*-->|-->\|([^|]*)\||-\.->|-\.-|==>|---|-->|--o|--x|<-->)\s*(?:\|([^|]*)\|)?\s*"
_EDGE = re.compile(_NODE + _ARROW + _NODE)
_LONE = re.compile(r"^\s*" + _NODE + r"\s*;?\s*$")


def _shape_label(shape: str | None) -> str:
    if not shape:
        return ""
    return _plain(re.sub(r"^[\[\(\{>/]+|[\]\)\}/]+$", "", shape).strip().strip('"'))


def from_mermaid(text: str) -> tuple[dict, list[str]]:
    if len(text) > MAX_INPUT:
        raise ImportError_("file too large")
    lines = [ln.strip() for ln in text.splitlines()]
    head = next((ln for ln in lines if ln and not ln.startswith("%%")), "")
    m = re.match(r"^(flowchart|graph)\s*(TB|TD|BT|RL|LR)?", head, re.I)
    if not m:
        raise ImportError_("only Mermaid 'flowchart'/'graph' diagrams are supported")
    direction = (m.group(2) or "TD").upper()
    labels, order, raw_edges, warnings = {}, [], [], []

    def see(nid, shape):
        if nid not in labels:
            order.append(nid)
            labels[nid] = ""
        lab = _shape_label(shape)
        if lab:
            labels[nid] = lab

    for ln in lines[1:]:
        if not ln or ln.startswith("%%") or re.match(r"^(classDef|class|style|linkStyle|click|subgraph|end)\b", ln):
            continue
        for part in ln.split(";"):
            part = part.strip()
            if not part:
                continue
            rest = part
            matched = False
            while True:
                em = _EDGE.match(rest)
                if not em:
                    break
                matched = True
                a, ashape, l1, l2, l3, b, bshape = em.groups()
                see(a, ashape)
                see(b, bshape)
                raw_edges.append((a, b, _plain((l1 or l2 or l3 or "").strip())))
                # chained: A --> B --> C  continues from B
                rest = rest[em.start(6):]
            if not matched:
                lm = _LONE.match(part)
                if lm:
                    see(lm.group(1), lm.group(2))
                else:
                    warnings.append("line not understood: %s" % part[:80])

    used, idmap, nodes = set(), {}, []
    level = _levels(order, raw_edges)
    per_level: dict[int, int] = {}
    horizontal = direction in ("LR", "RL")
    for nid in order:
        lv = level.get(nid, 0)
        pos = per_level.get(lv, 0)
        per_level[lv] = pos + 1
        x, y = (lv * 320, pos * 150) if horizontal else (pos * 320, lv * 150)
        label = labels[nid] or nid
        ntype = guess_type(label, nid)
        if ntype is None:
            ntype = "host"
            warnings.append("'%s' typed as Other host — set its type" % label)
        sid = _safe_id(nid, used)
        idmap[nid] = sid
        nodes.append({"id": sid, "type": ntype, "label": label, "x": x + 80, "y": y + 80})
    edges = [{"from": idmap[a], "to": idmap[b], **({"label": lab} if lab else {})}
             for a, b, lab in raw_edges]
    return _finish(nodes, _dedupe(edges, warnings), warnings)


def _levels(order, edges):
    """Longest-path layering from the roots (ignores cycles)."""
    level = {n: 0 for n in order}
    for _ in range(len(order)):
        changed = False
        for a, b, _l in edges:
            if level.get(b, 0) < level.get(a, 0) + 1 and level.get(a, 0) + 1 < len(order):
                level[b] = level[a] + 1
                changed = True
        if not changed:
            break
    return level


# ---------------------------------------------------------------- SATOM JSON
def from_satom(data: bytes | str) -> tuple[dict, list[str]]:
    try:
        raw = json.loads(data)
    except ValueError as exc:
        raise ImportError_("not JSON: %s" % exc) from exc
    if isinstance(raw, dict) and "layout" in raw and "nodes" not in raw:
        raw = raw["layout"]
        if isinstance(raw, str):
            raw = json.loads(raw)
    if not isinstance(raw, dict) or "nodes" not in raw:
        raise ImportError_("expected a SATOM Architecture layout {nodes, edges}")
    warnings, nodes = [], []
    for n in raw.get("nodes") or []:
        if not isinstance(n, dict):
            continue
        n = dict(n)
        if n.pop("appliance_id", None) is not None:
            warnings.append("'%s' was bound to a SATOM appliance — bind it to a source here"
                            % (n.get("label") or n.get("id")))
        gw = n.pop("gateway", None)
        if gw:
            n["note"] = ((n.get("note") or "") + " (behind firewall element %s)" % gw).strip()
        if n.get("type") == "backend":
            n["type"] = "server"
        elif n.get("type") == "management":
            n["type"] = "host"
        if n.get("type") not in NODE_TYPES:
            warnings.append("'%s' had type %r — typed as Other host" % (n.get("id"), n.get("type")))
            n["type"] = "host"
        nodes.append(n)
    return _finish(nodes, list(raw.get("edges") or []), warnings)


def detect_and_parse(filename: str, data: bytes) -> tuple[dict, list[str], str]:
    name = (filename or "").lower()
    head = data[:200].lstrip()
    if name.endswith((".drawio", ".xml")) or head.startswith(b"<"):
        return (*from_drawio(data), "drawio")
    if name.endswith((".mmd", ".mermaid")) or re.match(rb"^\s*(%%.*\n\s*)*(flowchart|graph)\b", data[:400]):
        return (*from_mermaid(data.decode("utf-8", "replace")), "mermaid")
    if name.endswith(".json") or head.startswith(b"{"):
        return (*from_satom(data), "satom")
    raise ImportError_("unknown format: use .drawio, .mmd (Mermaid) or a SATOM layout .json")
