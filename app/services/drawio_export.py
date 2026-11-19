"""Write a diagram as a draw.io file (``.drawio``, uncompressed mxfile XML).

Every diagram in the console is drawn by its own script (plain SVG, no
library — see the header of ``static/js/process_editor.js``), so there is no
shared document model to export from. Each page therefore describes what it
has on screen in ONE neutral shape, and this module turns that shape into
draw.io cells:

    {"name": "…",
     "nodes": [{"id", "label", "sub"?, "x", "y", "w", "h",
                "shape"?: box|round|pill|ellipse|cloud|zone|diamond|table,
                "fill"?, "stroke"?, "font"?: "#RRGGBB", "dashed"?: bool,
                "kind"?: SATOM element type (kept as ``satomType=``),
                "rows"?: [{"id"?, "text", "bold"?}]}],
     "edges": [{"from", "to", "label"?, "dashed"?, "color"?,
                "ends"?: arrow|none|crowfoot}]}

``x``/``y`` are the TOP-LEFT corner in the page's own drawing units. A node
with ``rows`` becomes a draw.io table (a swimlane with one cell per row);
an edge may end on a row (``"from": "<row id>"``), which is how a foreign key
lands on its column.

What the file can and cannot carry, stated once: geometry, text, colours and
links. A live overlay, a trace or a step's parameters are SATOM state, not
drawing, and are not in the file — draw.io would show them as dead text.

Safety. The style string of a draw.io cell is ``key=value;`` text that
draw.io parses, so nothing the browser sent is ever copied into it: shapes
come from a fixed table, colours must be ``#RRGGBB``, numbers are clamped.
Labels go into ``value`` with ``html=0`` so draw.io shows them as text and
never interprets markup. ElementTree escapes every attribute.
"""
from __future__ import annotations

import math
import re
from typing import Any
from xml.etree import ElementTree as ET

MAX_NODES = 5000
MAX_EDGES = 10000
MAX_ROWS = 400            # rows of one table
MAX_LABEL = 300
MAX_COORD = 1_000_000.0
ROW_H = 22.0
HEADER_H = 30.0

MIME = "application/vnd.jgraph.mxfile"

_HEX = re.compile(r"^#[0-9A-Fa-f]{6}$")
#: A SATOM element type carried in the style as ``satomType=<kind>;`` so a
#: file imported back (Observability › Diagrams) keeps its types. draw.io
#: ignores style keys it does not know.
_KIND = re.compile(r"^[a-z][a-z0-9-]{0,39}$")

#: shape -> the draw.io style that draws it. Fixed text: never built from input.
SHAPES = {
    "box": "rounded=0;whiteSpace=wrap;html=0;",
    "round": "rounded=1;arcSize=12;whiteSpace=wrap;html=0;",
    "pill": "rounded=1;arcSize=50;whiteSpace=wrap;html=0;",
    "ellipse": "ellipse;whiteSpace=wrap;html=0;",
    "cloud": "ellipse;shape=cloud;whiteSpace=wrap;html=0;",
    "diamond": "rhombus;whiteSpace=wrap;html=0;",
    # A region drawn behind other elements (a zone, a group, a card frame).
    "zone": ("rounded=1;arcSize=4;whiteSpace=wrap;html=0;dashed=1;"
             "verticalAlign=top;align=left;spacingLeft=8;spacingTop=4;"
             "fontStyle=1;"),
    "table": ("swimlane;fontStyle=1;childLayout=stackLayout;horizontal=1;"
              "startSize=%d;horizontalStack=0;resizeParent=1;"
              "resizeParentMax=0;resizeLast=0;collapsible=1;"
              "marginBottom=0;html=0;" % HEADER_H),
}
ROW_STYLE = ("text;strokeColor=none;fillColor=none;align=left;"
             "verticalAlign=middle;spacingLeft=6;spacingRight=4;overflow=hidden;"
             "rotatable=0;points=[[0,0.5],[1,0.5]];portConstraint=eastwest;"
             "html=0;")
ENDS = {
    "arrow": "endArrow=classic;startArrow=none;",
    "none": "endArrow=none;startArrow=none;",
    "crowfoot": "endArrow=ERmandOne;startArrow=ERmany;endFill=0;startFill=0;",
}


class ExportError(ValueError):
    """The payload cannot be drawn; the message is safe to show."""


def _colour(v: Any) -> str | None:
    return v if isinstance(v, str) and _HEX.match(v) else None


def _num(v: Any, default: float = 0.0, lo: float = -MAX_COORD,
         hi: float = MAX_COORD) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(f):
        return default
    return round(max(lo, min(hi, f)), 1)


def _text(v: Any, n: int = MAX_LABEL) -> str:
    if v is None:
        return ""
    s = str(v).replace("\r", "")
    # Control characters other than newline/tab are not valid XML 1.0.
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", s)
    return s[:n]


def _fmt(f: float) -> str:
    return ("%d" % f) if float(f).is_integer() else ("%s" % f)


def _style(base: str, node: dict) -> str:
    out = base
    fill, stroke, font = (_colour(node.get("fill")), _colour(node.get("stroke")),
                          _colour(node.get("font")))
    if fill:
        out += "fillColor=%s;" % fill
        if node.get("shape") == "table":
            out += "swimlaneFillColor=#FFFFFF;"
    if stroke:
        out += "strokeColor=%s;" % stroke
    if font:
        out += "fontColor=%s;" % font
    if node.get("dashed") is True and "dashed=1;" not in out:
        out += "dashed=1;"
    if node.get("kind"):
        out += "satomType=%s;" % node["kind"]
    return out


def normalise(payload: Any) -> tuple[dict, list[str]]:
    """Validate the page's description. Returns (model, warnings): what can be
    drawn is kept; what cannot is listed, never dropped silently."""
    if not isinstance(payload, dict):
        raise ExportError("the diagram must be a JSON object")
    nodes_in, edges_in = payload.get("nodes"), payload.get("edges") or []
    if not isinstance(nodes_in, list) or not isinstance(edges_in, list):
        raise ExportError("nodes and edges must be lists")
    if not nodes_in:
        raise ExportError("the diagram has no elements to export")
    if len(nodes_in) > MAX_NODES:
        raise ExportError("too many elements (%d, max %d)" % (len(nodes_in), MAX_NODES))
    if len(edges_in) > MAX_EDGES:
        raise ExportError("too many links (%d, max %d)" % (len(edges_in), MAX_EDGES))

    warnings: list[str] = []
    nodes, ends = [], set()
    for i, n in enumerate(nodes_in):
        if not isinstance(n, dict):
            warnings.append("element %d is not an object and was skipped" % i)
            continue
        nid = _text(n.get("id"), 200)
        if not nid:
            warnings.append("element %d has no id and was skipped" % i)
            continue
        if nid in ends:
            warnings.append("duplicate element id %r skipped" % nid)
            continue
        shape = n.get("shape") if n.get("shape") in SHAPES else "round"
        rows_in = n.get("rows") if isinstance(n.get("rows"), list) else []
        if rows_in and shape != "table":
            shape = "table"
        out = {
            "id": nid, "shape": shape,
            "label": _text(n.get("label")), "sub": _text(n.get("sub")),
            "x": _num(n.get("x")), "y": _num(n.get("y")),
            "w": _num(n.get("w"), 160.0, 4.0, 20000.0),
            "h": _num(n.get("h"), 60.0, 4.0, 20000.0),
        }
        for k in ("fill", "stroke", "font"):
            if _colour(n.get(k)):
                out[k] = n[k]
        if n.get("dashed") is True:
            out["dashed"] = True
        if isinstance(n.get("kind"), str) and _KIND.match(n["kind"]):
            out["kind"] = n["kind"]
        ends.add(nid)
        if shape == "table":
            rows = []
            if len(rows_in) > MAX_ROWS:
                warnings.append("table %r: only the first %d of %d rows exported"
                                % (out["label"] or nid, MAX_ROWS, len(rows_in)))
            for j, r in enumerate(rows_in[:MAX_ROWS]):
                r = r if isinstance(r, dict) else {"text": r}
                rid = _text(r.get("id"), 200) or ""
                if rid and rid in ends:
                    warnings.append("duplicate row id %r: its links were dropped" % rid)
                    rid = ""
                if rid:
                    ends.add(rid)
                rows.append({"id": rid, "text": _text(r.get("text")),
                             "bold": r.get("bold") is True})
            out["rows"] = rows
            out["h"] = max(out["h"], HEADER_H + ROW_H * len(rows))
        nodes.append(out)

    edges = []
    for i, e in enumerate(edges_in):
        if not isinstance(e, dict):
            warnings.append("link %d is not an object and was skipped" % i)
            continue
        a, b = _text(e.get("from"), 200), _text(e.get("to"), 200)
        if a not in ends or b not in ends:
            warnings.append("link %s → %s has an end that is not drawn; skipped"
                            % (a or "?", b or "?"))
            continue
        out = {"from": a, "to": b, "label": _text(e.get("label")),
               "ends": e.get("ends") if e.get("ends") in ENDS else "arrow"}
        if e.get("dashed") is True:
            out["dashed"] = True
        if _colour(e.get("color")):
            out["color"] = e["color"]
        edges.append(out)
    if not nodes:
        raise ExportError("none of the elements could be exported")
    return {"name": _text(payload.get("name"), 120) or "SATOM diagram",
            "nodes": nodes, "edges": edges}, warnings


def build(payload: Any, *, agent: str = "SATOM") -> tuple[bytes, list[str]]:
    """The .drawio file for ``payload`` and the warnings about what was left
    out. Raises :class:`ExportError` when nothing can be drawn."""
    model, warnings = normalise(payload)
    mxfile = ET.Element("mxfile", {"host": "SATOM", "agent": _text(agent, 80),
                                   "type": "device"})
    diagram = ET.SubElement(mxfile, "diagram", {"id": "satom-export",
                                                "name": model["name"]})
    gm = ET.SubElement(diagram, "mxGraphModel", {
        "grid": "1", "gridSize": "10", "guides": "1", "tooltips": "1",
        "connect": "1", "arrows": "1", "fold": "1", "page": "0",
        "pageScale": "1", "math": "0", "shadow": "0"})
    root = ET.SubElement(gm, "root")
    ET.SubElement(root, "mxCell", {"id": "0"})
    ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})

    cell_of: dict[str, str] = {}
    # Zones first: draw.io paints in document order, so a region placed
    # after its members would cover them.
    ordered = ([n for n in model["nodes"] if n["shape"] == "zone"]
               + [n for n in model["nodes"] if n["shape"] != "zone"])
    for i, n in enumerate(ordered):
        cid = "n%d" % i
        cell_of[n["id"]] = cid
        label = n["label"] + ("\n" + n["sub"] if n["sub"] else "")
        c = ET.SubElement(root, "mxCell", {
            "id": cid, "value": label, "style": _style(SHAPES[n["shape"]], n),
            "vertex": "1", "parent": "1"})
        ET.SubElement(c, "mxGeometry", {
            "x": _fmt(n["x"]), "y": _fmt(n["y"]), "width": _fmt(n["w"]),
            "height": _fmt(n["h"]), "as": "geometry"})
        for j, r in enumerate(n.get("rows") or []):
            rid = "%sr%d" % (cid, j)
            if r["id"]:
                cell_of[r["id"]] = rid
            rc = ET.SubElement(root, "mxCell", {
                "id": rid, "value": r["text"],
                "style": ROW_STYLE + ("fontStyle=1;" if r["bold"] else ""),
                "vertex": "1", "parent": cid})
            ET.SubElement(rc, "mxGeometry", {
                "y": _fmt(HEADER_H + ROW_H * j), "width": _fmt(n["w"]),
                "height": _fmt(ROW_H), "as": "geometry"})

    for i, e in enumerate(model["edges"]):
        style = "edgeStyle=none;rounded=0;html=0;" + ENDS[e["ends"]]
        if e.get("color"):
            style += "strokeColor=%s;" % e["color"]
        if e.get("dashed"):
            style += "dashed=1;"
        c = ET.SubElement(root, "mxCell", {
            "id": "e%d" % i, "value": e["label"], "style": style, "edge": "1",
            "parent": "1", "source": cell_of[e["from"]],
            "target": cell_of[e["to"]]})
        ET.SubElement(c, "mxGeometry", {"relative": "1", "as": "geometry"})

    ET.indent(mxfile, space="  ")
    body = ET.tostring(mxfile, encoding="unicode")
    return ('<?xml version="1.0" encoding="UTF-8"?>\n' + body + "\n").encode("utf-8"), warnings


def filename(name: str) -> str:
    """A safe download name: ``<slug>.drawio``."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", _text(name, 120)).strip("-.") or "diagram"
    return slug[:80] + ".drawio"
