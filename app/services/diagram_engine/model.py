"""The native diagram model, ``satom.diagram/1`` -- the one contract of Diagram Studio.

Every importer produces it, the editor edits it, every exporter consumes it,
and the database stores it. No importer knows an exporter: a format is added
by writing one reader or one writer against THIS module, never against another
format.

STANDALONE BY DESIGN: this package (``app/services/diagram_engine``) imports
nothing from Flask, the ORM or the rest of SATOM, only the standard library and
its own modules (relative imports). The runner executes the importers inside
the bubblewrap jail with nothing but this directory and the venv mounted, so a
hostile PDF/VSDX/SVG never runs next to a database connection.

Shape of a document::

    {"schema": "satom.diagram/1", "name": str, "metadata": {..},
     "source": {"format", "filename", "sha256", "page"},
     "recognition": {"engine", "version", "warnings": [str], "stats": {..}},
     "pages": [{
        "id", "name", "width", "height", "background": "#RRGGBB" | "",
        "layers":   [{"id", "name", "visible": bool, "locked": bool}],
        "groups":   [{"id", "name", "members": [element ids], "layer"}],
        "elements": [ELEMENT], "connectors": [CONNECTOR]}]}

ELEMENT::

    {"id", "kind": shape|text|image|container,
     "shape": one of SHAPES, "symbol": "<library>/<symbol id>" | "",
     "category": "<family>.<class>" (e.g. "network.firewall") | "",
     "name", "description", "text",
     "x", "y", "w", "h"   -- top-left corner and size, px, y grows DOWN,
     "rotation"           -- degrees clockwise around the centre,
     "layer", "parent"    -- layer id; container element id or "",
     "style": {fill, stroke, stroke_width, dashed, opacity, rounded,
               font_color, font_size, font_family, bold, italic, align, valign,
               fill_opacity, stroke_opacity  -- 0..1, on top of opacity,
               dash_pattern       -- solid|dashed|dotted|dash-dot ("dashed" is derived),
               gradient: {type: none|linear|radial, color: "#RRGGBB", angle: 0..359}
                                  -- from fill to color; angle clockwise from east (y down),
               shadow: bool, shadow_color: "#RRGGBB"},
     "points": [[x, y], ...]   -- polygon, 0..1 of the box (shape == polygon),
     "path": "<svg path d>"    -- in box coordinates 0..w/0..h (shape == path),
     "image": "data:image/png;base64,..." (kind == image),
     "ports": [{"id", "x", "y"}]   -- anchors, 0..1 of the box,
     "rows": [{"id", "text", "bold"}]   -- shape == table,
     "properties": {str: str}   -- the operator's custom properties,
     "metadata": {str: str|int|float|bool}   -- what a reader learned (ip, vlan...),
     "source_ref": str   -- where in the source file (cell id, shape id, xpath, bbox),
     "confidence": 0..1,
     "native": {"format": str, "style": str}  -- untouched source style, for round trips}

CONNECTOR::

    {"id", "source", "target"  -- element ids, or "" when the end is free,
     "source_port", "target_port", "start": [x, y], "end": [x, y]  -- free ends,
     "points": [[x, y], ...]   -- waypoints, absolute,
     "routing": straight|orthogonal|curved,
     "start_arrow", "end_arrow": one of ARROWS,
     "direction": forward|backward|both|none   -- derived from the arrows,
     "label", "labels": [{"text", "pos": 0..1}],
     "kind": free class (ethernet, wireless, vpn, data_flow, yes, no ...),
     "style": {stroke, stroke_width, dashed, font_color, opacity,
               stroke_opacity, dash_pattern, shadow, shadow_color},
     "layer", "properties", "metadata", "source_ref", "confidence", "native"}

``normalise()`` is the only door: lenient on input (missing keys get their
default, numbers are coerced and clamped), strict on what it lets through
(ids, colours, enumerations, sizes, references), and it raises
:class:`ModelError` only when the document cannot be repaired. What it dropped
or repaired is returned as warnings, never hidden.
"""
from __future__ import annotations

import copy
import math
import re
import uuid

SCHEMA = "satom.diagram/1"

MAX_PAGES = 50
MAX_ELEMENTS = 5000          # per page
MAX_CONNECTORS = 10000       # per page
MAX_LAYERS = 64
MAX_GROUPS = 2000
MAX_TEXT = 4000
MAX_NAME = 200
MAX_DESC = 2000
MAX_PROPS = 64
MAX_PROP_VALUE = 1000
MAX_POINTS = 2000
MAX_PATH = 200_000
MAX_IMAGE = 2 * 1024 * 1024      # data: URI characters per image element
MAX_COORD = 1_000_000.0

KINDS = ("shape", "text", "image", "container")
SHAPES = ("rect", "round", "ellipse", "diamond", "hexagon", "parallelogram",
          "trapezoid", "triangle", "cylinder", "cloud", "document", "note",
          "process", "terminator", "actor", "pill", "zone", "swimlane", "table",
          "polygon", "path", "symbol", "line")
ARROWS = ("none", "arrow", "open", "diamond", "diamond_open", "circle",
          "circle_open", "crowfoot", "bar")
ROUTINGS = ("straight", "orthogonal", "curved")
DIRECTIONS = ("forward", "backward", "both", "none")
ALIGNS = ("left", "center", "right")
DASH_PATTERNS = ("solid", "dashed", "dotted", "dash-dot")
GRADIENT_TYPES = ("none", "linear", "radial")
VALIGNS = ("top", "middle", "bottom")

ID_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,64}$")
COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")
CATEGORY_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}(\.[a-z0-9_]{1,40}){0,3}$")
SYMBOL_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,47}/[A-Za-z0-9_.\-]{1,96}$")
KIND_RE = re.compile(r"^[a-z][a-z0-9_\-]{0,39}$")
FORMAT_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]{0,31}$")
FONT_RE = re.compile(r"^[A-Za-z0-9 ,'\-]{1,80}$")
PATH_RE = re.compile(r"^[MmLlHhVvCcSsQqTtAaZz0-9eE.,+\-\s]*$")
IMAGE_RE = re.compile(r"^data:image/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=\s]+$")

STYLE_DEFAULTS = {"fill": "#FFFFFF", "stroke": "#1F2937", "stroke_width": 1.0,
                  "dashed": False, "opacity": 1.0, "rounded": False,
                  "font_color": "#111827", "font_size": 12.0, "font_family": "",
                  "bold": False, "italic": False, "align": "center", "valign": "middle",
                  "fill_opacity": 1.0, "stroke_opacity": 1.0, "dash_pattern": "solid",
                  "gradient": {"type": "none", "color": "#FFFFFF", "angle": 90},
                  "shadow": False, "shadow_color": "#000000"}
CONNECTOR_STYLE_DEFAULTS = {"stroke": "#1F2937", "stroke_width": 1.0, "dashed": False,
                            "font_color": "#111827", "opacity": 1.0,
                            "stroke_opacity": 1.0, "dash_pattern": "solid",
                            "shadow": False, "shadow_color": "#000000"}


class ModelError(ValueError):
    """The document cannot be turned into a valid ``satom.diagram/1``."""


# --------------------------------------------------------------- primitives

def new_id(prefix: str = "e") -> str:
    return "%s%s" % (prefix, uuid.uuid4().hex[:12])


def _text(v, limit: int) -> str:
    if v is None:
        return ""
    s = str(v).replace("\x00", "")
    s = "".join(ch for ch in s if ch in "\n\t" or ord(ch) >= 32)
    return s[:limit]


def _num(v, default: float = 0.0, lo: float = -MAX_COORD, hi: float = MAX_COORD) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(f):
        return default
    return round(min(hi, max(lo, f)), 3)


def _bool(v) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)


def _color(v, default: str) -> str:
    """``#RRGGBB``, ``"none"`` (no paint) or the default."""
    if isinstance(v, str):
        s = v.strip()
        if s.lower() == "none":
            return "none"
        if re.fullmatch(r"#[0-9A-Fa-f]{3}", s):
            s = "#" + "".join(c * 2 for c in s[1:])
        if COLOR_RE.match(s):
            return s.upper()
    return default


def _enum(v, allowed, default):
    return v if v in allowed else default


def _scalar_map(v, limit_keys: int = MAX_PROPS, as_text: bool = False) -> dict:
    out: dict = {}
    if not isinstance(v, dict):
        return out
    for k, val in list(v.items())[:limit_keys]:
        key = _text(k, 64).strip()
        if not key:
            continue
        if as_text:
            out[key] = _text(val, MAX_PROP_VALUE)
        elif isinstance(val, bool) or (isinstance(val, (int, float)) and math.isfinite(float(val))):
            out[key] = val
        else:
            out[key] = _text(val, MAX_PROP_VALUE)
    return out


def _points(v, rel: bool = False, limit: int = MAX_POINTS) -> list:
    out = []
    if not isinstance(v, (list, tuple)):
        return out
    for p in v[:limit]:
        if isinstance(p, (list, tuple)) and len(p) >= 2:
            if rel:
                out.append([_num(p[0], 0, -10, 10), _num(p[1], 0, -10, 10)])
            else:
                out.append([_num(p[0]), _num(p[1])])
    return out


class _Ids:
    """Ids unique across one page; a bad or repeated id gets a fresh one."""

    def __init__(self, warnings: list, where: str):
        self.seen: set = set()
        self.remap: dict = {}
        self.w = warnings
        self.where = where

    def take(self, raw, prefix: str) -> str:
        rid = str(raw) if raw is not None else ""
        if ID_RE.match(rid) and rid not in self.seen:
            self.seen.add(rid)
            self.remap.setdefault(rid, rid)
            return rid
        nid = new_id(prefix)
        while nid in self.seen:
            nid = new_id(prefix)
        self.seen.add(nid)
        if rid:
            self.remap.setdefault(rid, nid)
            self.w.append("%s: id %r replaced by %s" % (self.where, rid[:40], nid))
        return nid


# ------------------------------------------------------------------ pieces

def strict_color(v):
    """``#RRGGBB`` (upper case) or None: the colours of the colour-styling keys
    (gradient, shadow) take nothing else -- no ``none``, no short form, no name."""
    if isinstance(v, str) and COLOR_RE.match(v.strip()):
        return v.strip().upper()
    return None


def _angle(v, default: int = 90) -> int:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(f):
        return default
    return int(round(f)) % 360


def _gradient(v, w: list | None, where: str) -> dict:
    out = {"type": "none", "color": "#FFFFFF", "angle": 90}
    if v is None:
        return out
    if not isinstance(v, dict):
        if w is not None:
            w.append("%s: gradient is not an object; dropped" % where)
        return out
    typ = v.get("type", "none")
    if typ not in GRADIENT_TYPES:
        if w is not None:
            w.append("%s: gradient type %r is not none/linear/radial; dropped" % (where, str(typ)[:20]))
        return out
    out["angle"] = _angle(v.get("angle", 90))
    col = strict_color(v.get("color"))
    if col is None and typ != "none":
        if w is not None:
            w.append("%s: gradient colour %r is not #RRGGBB; gradient dropped" % (where, str(v.get("color"))[:20]))
        return out
    out["color"] = col or "#FFFFFF"
    out["type"] = typ
    return out


def _style(v, defaults: dict, w: list | None = None, where: str = "") -> dict:
    v = v if isinstance(v, dict) else {}
    out = {}
    for k, d in defaults.items():
        val = v.get(k, d)
        if k in ("fill", "stroke", "font_color"):
            out[k] = _color(val, d)
        elif k == "stroke_width":
            out[k] = _num(val, d, 0, 50)
        elif k in ("opacity", "fill_opacity", "stroke_opacity"):
            out[k] = _num(val, d, 0, 1)
        elif k == "font_size":
            out[k] = _num(val, d, 4, 200)
        elif k == "font_family":
            s = _text(val, 80).strip()
            out[k] = s if (not s or FONT_RE.match(s)) else ""
        elif k == "align":
            out[k] = _enum(val, ALIGNS, d)
        elif k == "valign":
            out[k] = _enum(val, VALIGNS, d)
        elif k == "gradient":
            out[k] = _gradient(v.get(k), w, where or "style")
        elif k == "shadow_color":
            col = strict_color(val)
            if col is None and w is not None and val not in (None, ""):
                w.append("%s: shadow colour %r is not #RRGGBB; black used" % (where or "style", str(val)[:20]))
            out[k] = col or d
        elif k == "dash_pattern":
            continue                         # derived below, together with ``dashed``
        else:
            out[k] = _bool(val)
    if "dash_pattern" in defaults:
        # ``dashed`` (the pre-existing flag) decides on/off when the input has it, so a
        # client that only knows ``dashed`` can still switch a dotted line off; the
        # pattern only refines an "on". Without ``dashed`` the pattern decides alone.
        pat = v.get("dash_pattern")
        if pat is not None and pat not in DASH_PATTERNS:
            if w is not None:
                w.append("%s: dash pattern %r is not solid/dashed/dotted/dash-dot; ignored" % (where or "style", str(pat)[:20]))
            pat = None
        if "dashed" in v:
            on = out["dashed"]
            pat = (pat if pat not in (None, "solid") else "dashed") if on else "solid"
        else:
            pat = pat or "solid"
        out["dash_pattern"] = pat
        out["dashed"] = pat != "solid"
    return out


def _native(v) -> dict:
    if not isinstance(v, dict):
        return {}
    fmt = str(v.get("format") or "")
    if not FORMAT_RE.match(fmt):
        return {}
    return {"format": fmt, "style": _text(v.get("style"), 4000)}


def _element(raw: dict, ids: _Ids, layer_ids: set, default_layer: str, w: list) -> dict:
    kind = _enum(raw.get("kind"), KINDS, "shape")
    shape = _enum(raw.get("shape"), SHAPES, "rect")
    e = {
        "id": ids.take(raw.get("id"), "e"),
        "kind": kind,
        "shape": shape,
        "symbol": raw.get("symbol") if isinstance(raw.get("symbol"), str) and SYMBOL_RE.match(raw.get("symbol")) else "",
        "category": raw.get("category") if isinstance(raw.get("category"), str) and CATEGORY_RE.match(raw.get("category")) else "",
        "name": _text(raw.get("name"), MAX_NAME),
        "description": _text(raw.get("description"), MAX_DESC),
        "text": _text(raw.get("text"), MAX_TEXT),
        "x": _num(raw.get("x")), "y": _num(raw.get("y")),
        "w": _num(raw.get("w"), 120, 0, MAX_COORD), "h": _num(raw.get("h"), 60, 0, MAX_COORD),
        "rotation": _num(raw.get("rotation"), 0, -360, 360),
        "layer": raw.get("layer") if raw.get("layer") in layer_ids else default_layer,
        "parent": str(raw.get("parent") or ""),
        "style": _style(raw.get("style"), STYLE_DEFAULTS, w, "element %s" % str(raw.get("id"))[:40]),
        "points": _points(raw.get("points"), rel=True) if shape == "polygon" else [],
        "path": "",
        "image": "",
        "ports": [],
        "rows": [],
        "properties": _scalar_map(raw.get("properties"), as_text=True),
        "metadata": _scalar_map(raw.get("metadata")),
        "source_ref": _text(raw.get("source_ref"), 300),
        "confidence": _num(raw.get("confidence"), 1.0, 0, 1),
        "native": _native(raw.get("native")),
    }
    if shape == "path":
        d = str(raw.get("path") or "")[:MAX_PATH]
        if PATH_RE.match(d):
            e["path"] = d
        else:
            w.append("element %s: path data with foreign characters dropped" % e["id"])
            e["shape"] = "rect"
    if kind == "image":
        img = str(raw.get("image") or "")
        if len(img) <= MAX_IMAGE and IMAGE_RE.match(img):
            e["image"] = re.sub(r"\s+", "", img)
        else:
            w.append("element %s: image is not a png/jpeg/gif/webp data URI under %d KiB; dropped"
                     % (e["id"], MAX_IMAGE // 1024))
            e["kind"] = "shape"
    pids: set = set()
    for p in (raw.get("ports") or [])[:64] if isinstance(raw.get("ports"), list) else []:
        if not isinstance(p, dict):
            continue
        pid = str(p.get("id") or "")
        if not ID_RE.match(pid) or pid in pids:
            pid = "p%d" % len(pids)
        pids.add(pid)
        e["ports"].append({"id": pid, "x": _num(p.get("x"), 0.5, 0, 1), "y": _num(p.get("y"), 0.5, 0, 1)})
    if shape == "table":
        for i, r in enumerate((raw.get("rows") or [])[:500] if isinstance(raw.get("rows"), list) else []):
            if isinstance(r, dict):
                rid = str(r.get("id") or "")
                e["rows"].append({"id": rid if ID_RE.match(rid) else "r%d" % i,
                                  "text": _text(r.get("text"), 300), "bold": _bool(r.get("bold"))})
    return e


def _arrows_direction(start: str, end: str) -> str:
    s, t = start != "none", end != "none"
    return "both" if s and t else "forward" if t else "backward" if s else "none"


def _connector(raw: dict, ids: _Ids, el_ids: dict, layer_ids: set, default_layer: str, w: list) -> dict | None:
    def end(key):
        ref = raw.get(key)
        if ref in (None, ""):
            return ""
        ref = el_ids.get(str(ref), "")
        if not ref:
            w.append("connector %r: %s %r is not an element; the end is left free"
                     % (str(raw.get("id"))[:40], key, str(raw.get(key))[:40]))
        return ref
    src, tgt = end("source"), end("target")
    start = _points([raw.get("start")])
    finish = _points([raw.get("end")])
    pts = _points(raw.get("points"))
    # A free end needs coordinates: its own, else the nearest waypoint.
    if not src and not start and pts:
        start = [pts[0]]
    if not tgt and not finish and pts:
        finish = [pts[-1]]
    if (not src and not start) or (not tgt and not finish):
        w.append("connector %r has an end with neither element nor coordinates; dropped"
                 % str(raw.get("id"))[:40])
        return None
    sa = _enum(raw.get("start_arrow"), ARROWS, "none")
    ea = _enum(raw.get("end_arrow"), ARROWS, "arrow")
    labels = []
    for lab in (raw.get("labels") or [])[:16] if isinstance(raw.get("labels"), list) else []:
        if isinstance(lab, dict) and _text(lab.get("text"), MAX_NAME):
            labels.append({"text": _text(lab.get("text"), MAX_NAME), "pos": _num(lab.get("pos"), 0.5, 0, 1)})
    kind = raw.get("kind") if isinstance(raw.get("kind"), str) and KIND_RE.match(raw.get("kind")) else ""
    return {
        "id": ids.take(raw.get("id"), "c"),
        "source": src, "target": tgt,
        "source_port": str(raw.get("source_port") or "")[:64] if src else "",
        "target_port": str(raw.get("target_port") or "")[:64] if tgt else "",
        "start": start[0] if (start and not src) else [],
        "end": finish[0] if (finish and not tgt) else [],
        "points": _points(raw.get("points")),
        "routing": _enum(raw.get("routing"), ROUTINGS, "straight"),
        "start_arrow": sa, "end_arrow": ea,
        "direction": _arrows_direction(sa, ea),
        "label": _text(raw.get("label"), MAX_NAME),
        "labels": labels,
        "kind": kind,
        "style": _style(raw.get("style"), CONNECTOR_STYLE_DEFAULTS, w, "connector %s" % str(raw.get("id"))[:40]),
        "layer": raw.get("layer") if raw.get("layer") in layer_ids else default_layer,
        "properties": _scalar_map(raw.get("properties"), as_text=True),
        "metadata": _scalar_map(raw.get("metadata")),
        "source_ref": _text(raw.get("source_ref"), 300),
        "confidence": _num(raw.get("confidence"), 1.0, 0, 1),
        "native": _native(raw.get("native")),
    }


def _page(raw: dict, index: int, w: list) -> dict:
    where = "page %d" % (index + 1)
    ids = _Ids(w, where)
    layers = []
    for lr in (raw.get("layers") or [])[:MAX_LAYERS] if isinstance(raw.get("layers"), list) else []:
        if isinstance(lr, dict):
            layers.append({"id": ids.take(lr.get("id"), "l"),
                           "name": _text(lr.get("name"), MAX_NAME) or "Layer %d" % (len(layers) + 1),
                           "visible": _bool(lr.get("visible", True)),
                           "locked": _bool(lr.get("locked", False))})
    if not layers:
        layers = [{"id": ids.take("layer-1", "l"), "name": "Default", "visible": True, "locked": False}]
    layer_remap = {k: v for k, v in ids.remap.items()}
    layer_ids = {lr["id"] for lr in layers}
    default_layer = layers[0]["id"]

    raw_elements = raw.get("elements") if isinstance(raw.get("elements"), list) else []
    if len(raw_elements) > MAX_ELEMENTS:
        raise ModelError("%s has %d elements; the limit is %d" % (where, len(raw_elements), MAX_ELEMENTS))
    elements = []
    for r in raw_elements:
        if isinstance(r, dict):
            r = dict(r)
            if r.get("layer") in layer_remap:
                r["layer"] = layer_remap[r["layer"]]
            elements.append(_element(r, ids, layer_ids, default_layer, w))
    el_ids = {k: v for k, v in ids.remap.items() if v in {e["id"] for e in elements}}
    for e in elements:
        el_ids.setdefault(e["id"], e["id"])
    # parents must be containers on the same page; cycles are cut
    containers = {e["id"] for e in elements}
    for e in elements:
        p = el_ids.get(e["parent"], "") if e["parent"] else ""
        e["parent"] = p if (p in containers and p != e["id"]) else ""
    by_id = {e["id"]: e for e in elements}
    for e in elements:
        seen, cur = {e["id"]}, e["parent"]
        while cur:
            if cur in seen:
                w.append("element %s: parent cycle cut" % e["id"])
                e["parent"] = ""
                break
            seen.add(cur)
            cur = by_id[cur]["parent"] if cur in by_id else ""

    raw_conns = raw.get("connectors") if isinstance(raw.get("connectors"), list) else []
    if len(raw_conns) > MAX_CONNECTORS:
        raise ModelError("%s has %d connectors; the limit is %d" % (where, len(raw_conns), MAX_CONNECTORS))
    connectors = []
    for r in raw_conns:
        if isinstance(r, dict):
            r = dict(r)
            if r.get("layer") in layer_remap:
                r["layer"] = layer_remap[r["layer"]]
            c = _connector(r, ids, el_ids, layer_ids, default_layer, w)
            if c:
                connectors.append(c)

    groups = []
    member_ok = set(by_id) | {c["id"] for c in connectors}
    for g in (raw.get("groups") or [])[:MAX_GROUPS] if isinstance(raw.get("groups"), list) else []:
        if not isinstance(g, dict):
            continue
        members = []
        for m in g.get("members") or []:
            mid = el_ids.get(str(m), str(m))
            if mid in member_ok and mid not in members:
                members.append(mid)
        if len(members) < 1:
            continue
        groups.append({"id": ids.take(g.get("id"), "g"), "name": _text(g.get("name"), MAX_NAME),
                       "members": members,
                       "layer": g.get("layer") if g.get("layer") in layer_ids else default_layer})

    return {
        "id": _text(raw.get("id"), 64) if ID_RE.match(str(raw.get("id") or "")) else "page-%d" % (index + 1),
        "name": _text(raw.get("name"), MAX_NAME) or "Page %d" % (index + 1),
        "width": _num(raw.get("width"), 1600, 1, MAX_COORD),
        "height": _num(raw.get("height"), 1000, 1, MAX_COORD),
        "background": "" if not raw.get("background") else _color(raw.get("background"), ""),
        "layers": layers, "groups": groups, "elements": elements, "connectors": connectors,
    }


# ------------------------------------------------------------------- doors

def normalise(doc) -> tuple[dict, list[str]]:
    """``(document, warnings)``; raises :class:`ModelError` when unusable."""
    if not isinstance(doc, dict):
        raise ModelError("a diagram is a JSON object")
    schema = doc.get("schema", SCHEMA)
    if schema != SCHEMA:
        raise ModelError("unknown schema %r (expected %s)" % (str(schema)[:40], SCHEMA))
    pages = doc.get("pages")
    if not isinstance(pages, list) or not pages:
        raise ModelError("a diagram has at least one page")
    if len(pages) > MAX_PAGES:
        raise ModelError("%d pages; the limit is %d" % (len(pages), MAX_PAGES))
    w: list[str] = []
    out_pages = [_page(p if isinstance(p, dict) else {}, i, w) for i, p in enumerate(pages)]
    seen: set = set()
    for p in out_pages:
        if p["id"] in seen:
            p["id"] = new_id("page-")
        seen.add(p["id"])
    src = doc.get("source") if isinstance(doc.get("source"), dict) else {}
    rec = doc.get("recognition") if isinstance(doc.get("recognition"), dict) else {}
    fmt = str(src.get("format") or "")
    sha = str(src.get("sha256") or "")
    out = {
        "schema": SCHEMA,
        "name": _text(doc.get("name"), MAX_NAME) or "Untitled diagram",
        "metadata": _scalar_map(doc.get("metadata")),
        "source": {"format": fmt if FORMAT_RE.match(fmt) else "",
                   "filename": _text(src.get("filename"), 255),
                   "sha256": sha if re.fullmatch(r"[0-9a-f]{64}", sha) else "",
                   "page": _text(src.get("page"), 64)},
        "recognition": {"engine": _text(rec.get("engine"), 64),
                        "version": _text(rec.get("version"), 32),
                        "warnings": [_text(x, 500) for x in (rec.get("warnings") or [])[:500]
                                     if isinstance(rec.get("warnings"), list)],
                        "stats": _scalar_map(rec.get("stats"))},
        "pages": out_pages,
    }
    return out, w


def empty(name: str = "Untitled diagram") -> dict:
    return normalise({"schema": SCHEMA, "name": name, "pages": [{"name": "Page 1"}]})[0]


def stats(doc: dict) -> dict:
    """Counts the Recognition step shows."""
    els = [e for p in doc.get("pages", []) for e in p.get("elements", [])]
    cons = [c for p in doc.get("pages", []) for c in p.get("connectors", [])]
    low = sum(1 for e in els if e.get("confidence", 1) < LOW_CONFIDENCE)
    unknown = sum(1 for e in els if e.get("kind") == "shape" and not e.get("category"))
    cats: dict = {}
    for e in els:
        fam = (e.get("category") or "").split(".")[0]
        if fam:
            cats[fam] = cats.get(fam, 0) + 1
    return {"pages": len(doc.get("pages", [])), "elements": len(els), "connectors": len(cons),
            "connected": sum(1 for c in cons if c.get("source") and c.get("target")),
            "dangling": sum(1 for c in cons if not (c.get("source") and c.get("target"))),
            "low_confidence": low, "unclassified": unknown, "families": cats}


#: Below this, an element is flagged for the Review step.
LOW_CONFIDENCE = 0.6


def deep_copy(doc: dict) -> dict:
    return copy.deepcopy(doc)
