"""draw.io / diagrams.net reader (``.drawio``, ``.xml``, draw.io-embedded SVG).

Reads ``mxfile`` (one ``<diagram>`` per page, compressed or not) and a bare
``mxGraphModel``. Geometry is converted to ABSOLUTE page coordinates (draw.io
stores a child's position relative to its container); connector waypoints too.

Colour styling is read back: ``gradientColor``/``gradientDirection`` (north/
east/south/west/radial, ``satomGradAngle`` for SATOM's own in-between angles),
``shadow``/``shadowColor``, ``fillOpacity``/``strokeOpacity`` and
``dashed``/``dashPattern`` (dashed, dotted, dash-dot).

Approximations, reported once per kind in ``recognition.warnings``: sketch style, shapes without a native equivalent
(imported as rectangles with ``metadata.drawio_shape``), children of rotated
containers (positions are not rotated about the parent), arrowheads outside
the model's set.
"""
from __future__ import annotations

import base64
import binascii
import html as _html
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
import zlib

from .. import model, xmlsafe
from . import (ImportFailed, Warnings, doc_name, guarded, make_document,
               require_bytes, select_page)

ENGINE = "drawio-reader"
WRAPPERS = ("object", "UserObject", "XMLLabel")
_local = xmlsafe.local

SHAPE_MAP = {
    "ellipse": "ellipse", "doubleEllipse": "ellipse", "rhombus": "diamond", "hexagon": "hexagon",
    "parallelogram": "parallelogram", "trapezoid": "trapezoid", "triangle": "triangle",
    "cylinder": "cylinder", "cylinder2": "cylinder", "cylinder3": "cylinder",
    "datastore": "cylinder", "cloud": "cloud", "document": "document", "note": "note",
    "note2": "note", "process": "process", "umlActor": "actor", "actor": "actor",
    "swimlane": "swimlane", "table": "table", "line": "line",
}
EXACT_RECT = {"rectangle", "rect", "label", "image", ""}
NAMED_COLORS = {"white": "#FFFFFF", "black": "#000000", "red": "#FF0000", "green": "#008000",
                "blue": "#0000FF", "yellow": "#FFFF00", "gray": "#808080", "grey": "#808080",
                "orange": "#FFA500", "purple": "#800080"}
IMAGE_MIMES = {"png": "png", "jpeg": "jpeg", "jpg": "jpeg", "gif": "gif", "webp": "webp"}

_IMG_STYLE_RE = re.compile(r"(?:^|;)image=data:image/([A-Za-z0-9.+\-]+)(?:;base64)?,([^;]*)")
_HEX_RE = re.compile(r"^#(?:[0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$")


# ------------------------------------------------------------------ loading

def _decode_diagram(text: str | None):
    text = (text or "").strip()
    if not text:
        return None
    if text.startswith("<"):
        return xmlsafe.parse_xml(text)
    try:
        raw = base64.b64decode(text, validate=False)
        inflated = xmlsafe.inflate_raw(raw)
    except (binascii.Error, ValueError) as exc:
        if isinstance(exc, xmlsafe.UnsafeInput):
            raise
        raise ImportFailed("A draw.io page has damaged compressed content.") from None
    except zlib.error:
        raise ImportFailed("A draw.io page has damaged compressed content.") from None
    s = inflated.decode("utf-8", "replace")
    if not s.lstrip().startswith("<"):
        s = urllib.parse.unquote(s)
    return xmlsafe.parse_xml(s)


def _load(data: bytes):
    """``(source_format, [(page_id, page_name, mxGraphModel element)])``."""
    fmt, pages, _satom = _load_with_origin(data)
    return fmt, pages


def _load_with_origin(data: bytes):
    """Like :func:`_load`, plus whether SATOM itself wrote the file
    (``<mxfile host="SATOM">``): its elements already carry exactly the
    categories their author left, so the importer must not re-classify them."""
    root = xmlsafe.parse_xml(data)
    fmt = "drawio"
    tag = _local(root.tag)
    if tag == "svg":
        content = root.get("content") or ""
        if not content.lstrip().startswith("<"):
            raise ImportFailed("This SVG does not embed a draw.io diagram. Export from draw.io "
                               "with 'Include a copy of my diagram' or import the .drawio file.")
        root = xmlsafe.parse_xml(content)
        tag = _local(root.tag)
        fmt = "drawio-svg"
    if tag == "mxGraphModel":
        return fmt, [("page-1", "Page-1", root)], False
    if tag != "mxfile":
        raise ImportFailed("Not a draw.io file (root element %r)." % tag[:40])
    pages, seen = [], set()
    for i, d in enumerate(c for c in root if _local(c.tag) == "diagram"):
        pid = d.get("id") or ""
        if not model.ID_RE.match(pid) or pid in seen:
            pid = "page-%d" % (i + 1)
        seen.add(pid)
        gm = next((c for c in d if _local(c.tag) == "mxGraphModel"), None)
        if gm is None:
            gm = _decode_diagram(d.text)
        if gm is None:
            gm = ET.Element("mxGraphModel")
        if _local(gm.tag) != "mxGraphModel":
            raise ImportFailed("Page %d does not contain a draw.io graph model." % (i + 1))
        pages.append((pid, d.get("name") or "Page-%d" % (i + 1), gm))
    if not pages:
        raise ImportFailed("The draw.io file contains no diagram pages.")
    return fmt, pages, root.get("host") == "SATOM"


@guarded
def list_pages(data: bytes) -> list:
    _fmt, pages = _load(require_bytes(data))
    return [{"id": pid, "name": name} for pid, name, _ in pages]


# ------------------------------------------------------------------ helpers

def _num(v, default=0.0) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    return f if f == f and abs(f) != float("inf") else default


def parse_style(s: str):
    """``(dict, flags, embedded_image)``; an embedded ``data:`` image is lifted out
    first because its base64 payload may carry the ``;`` the style syntax splits on."""
    s = s or ""
    img = None
    m = _IMG_STYLE_RE.search(s)
    if m:
        img = (m.group(1).lower(), m.group(2))
        s = s[:m.start()] + (";" if m.start() else "") + s[m.end():]
    d, flags = {}, []
    for part in s.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            d[k.strip()] = v.strip()
        else:
            flags.append(part)
    return d, flags, img


def _color(v):
    """``#RRGGBB`` | ``"none"`` | None (unknown / unset)."""
    if not v:
        return None
    v = v.strip()
    m = re.match(r"light-dark\(\s*([^,\s)]+)", v)
    if m:
        v = m.group(1)
    if v.lower() == "none":
        return "none"
    if _HEX_RE.match(v):
        return v.upper() if len(v) == 7 else "#" + "".join(c * 2 for c in v[1:]).upper()
    return NAMED_COLORS.get(v.lower())


_BR_RE = re.compile(r"<\s*br\s*/?\s*>", re.I)
_BLOCK_END_RE = re.compile(r"<\s*/\s*(?:div|p|li|tr|h[1-6])\s*>", re.I)
_BLOCK_START_RE = re.compile(r"<\s*(?:div|p|li|tr|h[1-6])(?:\s[^>]*)?>", re.I)
_TAG_RE = re.compile(r"<[^<>]{0,2000}>")


def html_to_text(s: str) -> str:
    s = (s or "")[:200000]
    s = _BR_RE.sub("\n", s)
    s = _BLOCK_END_RE.sub("\x01", s)       # block boundaries: one newline however many tags meet
    s = _BLOCK_START_RE.sub("\x01", s)
    s = _TAG_RE.sub("", s)
    s = re.sub(r"(?:(?<=\n)|^)\x01+", "", s)
    s = re.sub(r"\x01+", "\n", s)
    s = _html.unescape(s).replace("\xa0", " ").replace("\r", "")
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip("\n").strip()


class _Rec:
    __slots__ = ("id", "parent", "vertex", "edge", "source", "target", "value", "style", "flags",
                 "img", "style_raw", "geo", "attrs", "visible")


def _records(root_el) -> dict:
    recs: dict = {}
    for n, el in enumerate(root_el):
        t = _local(el.tag)
        if t == "mxCell":
            cell, attrs, cid, value = el, {}, el.get("id"), el.get("value")
        elif t in WRAPPERS:
            cell = next((c for c in el if _local(c.tag) == "mxCell"), None)
            if cell is None:
                continue
            attrs = dict(el.attrib)
            cid = el.get("id") or cell.get("id")
            value = el.get("label") if "label" in el.attrib else cell.get("value")
        else:
            continue
        if cid is None or cid in recs:
            cid = "cell-%d" % n
            while cid in recs:
                cid += "x"
        r = _Rec()
        r.id = cid
        r.parent = cell.get("parent")
        r.vertex = cell.get("vertex") == "1"
        r.edge = cell.get("edge") == "1"
        r.source, r.target = cell.get("source"), cell.get("target")
        r.value = value or ""
        r.style_raw = cell.get("style") or ""
        r.style, r.flags, r.img = parse_style(r.style_raw)
        r.geo = next((c for c in cell if _local(c.tag) == "mxGeometry"), None)
        r.attrs = attrs
        r.visible = cell.get("visible") != "0"
        recs[cid] = r
    return recs


def _label(rec: _Rec) -> str:
    v = rec.value
    if rec.style.get("html") == "1" or (("<" in v and ">" in v) and rec.style.get("html") != "0"
                                         and re.search(r"<\s*/?\s*(?:br|div|p|b|i|u|span|font)\b", v, re.I)):
        return html_to_text(v)
    return v.replace("\r", "")


def _native_style(rec: _Rec) -> str:
    s = rec.style_raw
    return _IMG_STYLE_RE.sub(lambda m: (";" if m.start() else "") + "image=data:image/%s,<omitted>" % m.group(1), s)


def _geom(rec: _Rec):
    g = rec.geo
    if g is None:
        return 0.0, 0.0, 0.0, 0.0
    return (_num(g.get("x")), _num(g.get("y")), _num(g.get("width")), _num(g.get("height")))


def _origin(rid, recs, root_id) -> tuple:
    """Absolute top-left of vertex *rid* (walks up through vertex parents only)."""
    x = y = 0.0
    seen = set()
    cur = recs.get(rid)
    while cur is not None and cur.id not in seen and len(seen) < 256:
        seen.add(cur.id)
        gx, gy, _, _ = _geom(cur)
        x += gx
        y += gy
        par = recs.get(cur.parent) if cur.parent not in (None, root_id) else None
        cur = par if (par is not None and par.vertex) else None
    return x, y


def _parent_origin(rec, recs, root_id) -> tuple:
    par = recs.get(rec.parent) if rec.parent not in (None, root_id) else None
    if par is not None and par.vertex:
        return _origin(par.id, recs, root_id)
    return 0.0, 0.0


# ------------------------------------------- SATOM round-trip tags (exporters/drawio.py)

_SKIP_ATTRS = ("label", "placeholders", "id", "tooltip")


def _json_map(raw) -> dict:
    try:
        v = json.loads(raw) if raw else {}
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


def _typed(value: str, kind):
    try:
        if kind == "bool":
            return value == "true"
        if kind == "int":
            return int(value)
        if kind == "float":
            return float(value)
    except ValueError:
        pass
    return value


def split_attrs(attrs: dict) -> tuple:
    """``<object>`` attributes -> ``(properties, metadata)``; the private ``satom*``
    attributes never leak into properties, ``meta_<key>`` is metadata (typed by
    ``satomTypes``) and ``satomKeys`` restores keys that had to be renamed."""
    keymap, types = _json_map(attrs.get("satomKeys")), _json_map(attrs.get("satomTypes"))
    props, meta = {}, {}
    for k, v in attrs.items():
        if k in _SKIP_ATTRS or k.startswith("satom") or v is None:
            continue
        if k.startswith("meta_"):
            meta[str(keymap.get(k, k[5:]))] = _typed(v, types.get(k))
        else:
            props[str(keymap.get(k, k))] = v
    return props, meta


def _ports_from_style(spec) -> list:
    out = []
    for inner in re.findall(r"\[([^\[\]]+)\]", spec or "")[:60]:
        parts = inner.split(",")
        if len(parts) >= 2:
            x, y = _num(parts[0], -1.0), _num(parts[1], -1.0)
            if 0.0 <= x <= 1.0 and 0.0 <= y <= 1.0:
                out.append({"id": "p%d" % len(out), "x": x, "y": y})
    return out


def _fnum(v: float) -> str:
    s = ("%.3f" % v).rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def decode_stencil(value: str, shape: str, w: float, h: float):
    """Invert the exporter's ``stencil(<deflated xml>)`` for a polygon/path element:
    ``("points", [[x, y]..])`` / ``("path", d)`` or None."""
    m = re.fullmatch(r"stencil\(([A-Za-z0-9+/=]+)\)", value or "")
    if not m:
        return None
    try:
        raw = xmlsafe.inflate_raw(base64.b64decode(m.group(1)))
        root = xmlsafe.parse_xml(urllib.parse.unquote(raw.decode("utf-8", "replace")))
        sw, sh = max(_num(root.get("w"), w), 1.0), max(_num(root.get("h"), h), 1.0)
        d, pts = [], []
        for op in root.iter():
            t = _local(op.tag)
            a = lambda k: _num(op.get(k))
            if t in ("move", "line"):
                d.append("%s %s %s" % ("M" if t == "move" else "L", _fnum(a("x")), _fnum(a("y"))))
                pts.append([a("x") / sw, a("y") / sh])
            elif t == "curve":
                d.append("C " + " ".join(_fnum(a(k)) for k in ("x1", "y1", "x2", "y2", "x3", "y3")))
            elif t == "quad":
                d.append("Q " + " ".join(_fnum(a(k)) for k in ("x1", "y1", "x2", "y2")))
            elif t == "arc":
                d.append("A %s %s %s %d %d %s %s" % (_fnum(a("rx")), _fnum(a("ry")), _fnum(a("x-axis-rotation")),
                                                      int(a("large-arc-flag")), int(a("sweep-flag")),
                                                      _fnum(a("x")), _fnum(a("y"))))
            elif t == "close":
                d.append("Z")
    except xmlsafe.UnsafeInput:
        raise
    except (ValueError, TypeError, binascii.Error, zlib.error):
        return None
    if shape == "polygon" and len(pts) >= 2:
        return "points", pts
    if shape == "path" and d:
        return "path", " ".join(d)
    return None


# ------------------------------------------------------------------ vertices

def _vertex_style(rec: _Rec, kind: str, w: Warnings) -> dict:
    st, text_like = rec.style, kind == "text"
    fill = _color(st.get("fillColor"))
    stroke = _color(st.get("strokeColor"))
    if fill is None:
        fill = "none" if (text_like or "group" in rec.flags) else "#FFFFFF"
    if stroke is None:
        stroke = "none" if (text_like or "group" in rec.flags) else "#000000"
    if st.get("sketch") == "1" or st.get("comic") == "1":
        w.once("sketch", "Sketch/comic rendering style was not imported.")
    fs = int(_num(st.get("fontStyle"), 0))
    align = st.get("align") or ("left" if text_like and "align" not in st else "center")
    valign = st.get("verticalAlign") or ("top" if text_like and "verticalAlign" not in st else "middle")
    out = {"fill": fill, "stroke": stroke,
           "stroke_width": _num(st.get("strokeWidth"), 1.0),
           "opacity": min(1.0, max(0.0, _num(st.get("opacity"), 100.0) / 100.0)),
           "rounded": st.get("rounded") == "1",
           "font_color": _color(st.get("fontColor")) or "#000000",
           "font_size": _num(st.get("fontSize"), 12.0),
           "bold": bool(fs & 1), "italic": bool(fs & 2),
           "align": align if align in model.ALIGNS else "center",
           "valign": valign if valign in model.VALIGNS else "middle"}
    if st.get("fontFamily"):
        out["font_family"] = st["fontFamily"]
    out.update(_effects(st, fill, vertex=True))
    return out


# ------------------------------------------------------------ colour styling

DIRECTION_ANGLE = {"east": 0, "south": 90, "west": 180, "north": 270}


def _dash(st: dict) -> str:
    """draw.io ``dashed``/``dashPattern`` -> solid | dashed | dotted | dash-dot."""
    if st.get("dashed") != "1":
        return "solid"
    nums = [float(x) for x in re.findall(r"\d+(?:\.\d+)?", st.get("dashPattern") or "")][:16]
    if not nums or not any(nums):
        return "dashed"
    if len(nums) >= 4:
        return "dash-dot"
    return "dotted" if max(nums[0::2]) <= 1.5 else "dashed"


def _pct(v) -> float:
    return min(1.0, max(0.0, _num(v, 100.0) / 100.0))


def _effects(st: dict, fill, vertex: bool) -> dict:
    out = {"dash_pattern": _dash(st), "shadow": st.get("shadow") == "1",
           "stroke_opacity": _pct(st.get("strokeOpacity"))}
    out["dashed"] = out["dash_pattern"] != "solid"
    sc = _color(st.get("shadowColor"))
    out["shadow_color"] = sc if sc and sc != "none" else "#000000"
    if not vertex:
        return out
    out["fill_opacity"] = _pct(st.get("fillOpacity"))
    gc = _color(st.get("gradientColor"))
    if gc and gc != "none" and fill and fill != "none":
        direction = (st.get("gradientDirection") or "south").strip().lower()
        if direction == "radial":
            out["gradient"] = {"type": "radial", "color": gc, "angle": 90}
        else:
            angle = DIRECTION_ANGLE.get(direction, 90)
            own = st.get("satomGradAngle", "")
            if own.isdigit() and int(own) < 360:
                angle = int(own)
            out["gradient"] = {"type": "linear", "color": gc, "angle": angle}
    return out


def _image_from_style(rec: _Rec):
    """``(data_uri | "", other_image_reference | "")``."""
    if rec.img:
        mime, payload = rec.img
        m = IMAGE_MIMES.get(mime)
        if m:
            payload = urllib.parse.unquote(payload)
            padded = payload + "=" * (-len(payload) % 4)
            try:
                base64.b64decode(padded, validate=True)
            except (binascii.Error, ValueError):
                return "", "data:image/%s (invalid)" % mime
            uri = "data:image/%s;base64,%s" % (m, padded)
            if len(uri) <= model.MAX_IMAGE:
                return uri, ""
            return "", "data:image/%s (too large)" % mime
        return "", "data:image/%s" % mime
    return "", rec.style.get("image", "")[:300]


def _build_vertex(rec: _Rec, recs: dict, root_id: str, tables: dict, w: Warnings) -> dict:
    st, flags = rec.style, set(rec.flags)
    shape_key = st.get("shape", "")
    x, y, wd, ht = _geom(rec)
    ox, oy = _origin(rec.id, recs, root_id)
    kind, shape, symbol_meta = "shape", "rect", {}
    meta: dict = {}
    image_uri = ""
    has_image = bool(rec.img) or bool(st.get("image"))

    is_table = rec.id in tables
    container = ("group" in flags or "swimlane" in flags or shape_key == "swimlane"
                 or st.get("container") == "1")

    satom_shape = st.get("satomShape", "")
    decoded = None
    if shape_key.startswith("mxgraph.") or shape_key.startswith("stencil"):
        shape = "symbol"
        decoded = decode_stencil(shape_key, satom_shape, wd, ht) if satom_shape in ("polygon", "path") else None
        if decoded is None:
            meta["drawio_shape"] = "stencil" if shape_key.startswith("stencil") else shape_key[:200]
            if shape_key.startswith("stencil"):
                w.once("stencil", "Inline custom stencils were imported as generic symbols.")
    elif has_image and shape_key in ("", "image"):
        image_uri, other = _image_from_style(rec)
        if image_uri:
            kind = "image"
        else:
            shape = "symbol"
            if other:
                meta["drawio_image"] = other
    else:
        base = shape_key or next((f for f in rec.flags if f in SHAPE_MAP), "")
        if base in SHAPE_MAP:
            shape = SHAPE_MAP[base]
        elif base and base not in EXACT_RECT:
            meta["drawio_shape"] = base[:200]
            w.once("approx_shape", "Some draw.io shapes have no native equivalent and were imported "
                                   "as rectangles (the original name is kept in metadata.drawio_shape).")
        if has_image and not image_uri:
            _uri, other = _image_from_style(rec)
            if other:
                meta["drawio_image"] = other
    if is_table:
        shape = "table"
    if (kind == "shape" and "text" in flags and not shape_key) or shape_key == "text":
        kind = "text"
    if container and kind != "image":
        kind = "container"
    if "group" in flags and kind == "container" and not shape_key:
        shape = "rect"

    # SATOM's own exports say exactly what the element was.
    if st.get("satomKind") in model.KINDS and not (st["satomKind"] == "image" and not image_uri):
        kind = st["satomKind"]
    style = _vertex_style(rec, "text" if kind == "text" else kind, w)
    if shape == "rect" and kind in ("shape", "container") and style["rounded"]:
        arc = _num(st.get("arcSize"), 16.0)
        if st.get("absoluteArcSize") == "1":
            arc = 100.0 * arc / max(1.0, min(wd, ht)) * 2 if min(wd, ht) > 0 else arc
        shape = "pill" if arc >= 50 else "round"
    if satom_shape in model.SHAPES:        # SATOM's own export states the shape outright
        shape = satom_shape
        meta.pop("drawio_shape", None)

    label = _label(rec)
    text_first = label.split("\n", 1)[0].strip()
    tooltip = rec.attrs.get("tooltip", "")
    props, attr_meta = split_attrs(rec.attrs)
    if st.get("satomType"):
        meta["satom_type"] = st["satomType"][:40]
    meta.update(symbol_meta)
    meta.update(attr_meta)

    el = {"id": rec.id, "kind": kind, "shape": shape, "symbol": st.get("satomSymbol", ""),
          "category": st.get("satomCategory", ""), "name": rec.attrs.get("satomName") or text_first[:80],
          "description": tooltip, "text": label,
          "x": ox, "y": oy, "w": wd, "h": ht,
          "rotation": _num(st.get("rotation"), 0.0),
          "layer": "", "parent": "", "style": style,
          "properties": props, "metadata": meta, "source_ref": rec.id, "confidence": 1.0,
          "native": {"format": "drawio", "style": _native_style(rec)}}
    if kind == "image":
        el["image"] = image_uri
    if decoded and decoded[0] == "points":
        el["points"] = decoded[1]
    elif decoded:
        el["path"] = decoded[1]
    ports = _ports_from_style(st.get("points"))
    if ports:
        el["ports"] = ports
    return el


# --------------------------------------------------------------------- edges

def _arrow(name, fill: str, w: Warnings) -> str:
    n = name or "none"
    filled = fill != "0"
    if n == "none":
        return "none"
    if n in ("open", "openThin", "openAsync"):
        return "open"
    if n in ("classic", "classicThin", "block", "blockThin", "async", "doubleBlock", "box"):
        return "arrow" if filled else "open"
    if n == "oval":
        return "circle" if filled else "circle_open"
    if n in ("diamond", "diamondThin"):
        return "diamond" if filled else "diamond_open"
    if n in ("dash", "cross", "ERone", "ERmandOne"):
        return "bar"
    if n in ("ERmany", "ERoneToMany", "ERzeroToMany"):
        return "crowfoot"
    if n == "ERzeroToOne":
        return "circle_open"
    w.once("arrow", "Some arrowheads have no equivalent in the model and were approximated.")
    return "arrow" if filled else "open"


def _routing(st: dict) -> str:
    es = st.get("edgeStyle", "")
    if es in ("orthogonalEdgeStyle", "elbowEdgeStyle", "entityRelationEdgeStyle", "isometricEdgeStyle"):
        return "orthogonal"
    if st.get("curved") == "1":
        return "curved"
    return "straight"


def _edge_geometry(rec: _Rec, off: tuple):
    pts, sp, tp = [], None, None
    g = rec.geo
    if g is not None:
        for ch in g:
            t = _local(ch.tag)
            if t == "mxPoint" and ch.get("as") == "sourcePoint":
                sp = [_num(ch.get("x")) + off[0], _num(ch.get("y")) + off[1]]
            elif t == "mxPoint" and ch.get("as") == "targetPoint":
                tp = [_num(ch.get("x")) + off[0], _num(ch.get("y")) + off[1]]
            elif t == "Array" and ch.get("as") == "points":
                for p in ch:
                    if _local(p.tag) == "mxPoint":
                        pts.append([_num(p.get("x")) + off[0], _num(p.get("y")) + off[1]])
    return pts, sp, tp


def _build_edge(rec: _Rec, recs: dict, root_id: str, el_by_id: dict, endpoint: dict,
                labels: list, w: Warnings) -> dict:
    st = rec.style
    off = _parent_origin(rec, recs, root_id)
    pts, sp, tp = _edge_geometry(rec, off)
    ends = {}
    for key, raw in (("source", rec.source), ("target", rec.target)):
        eid, port = endpoint.get(raw, (raw, "")) if raw else ("", "")
        if eid not in el_by_id:
            if raw:
                w.once("edge_free", "Connectors attached to something other than a shape (another "
                                    "connector, a label) were imported with a free end.")
            eid, port = "", ""
        ends[key] = (eid, port)
    src, tgt = ends["source"][0], ends["target"][0]
    sport, tport = ends["source"][1], ends["target"][1]
    for key, eid, prefix in (("source", src, "exit"), ("target", tgt, "entry")):
        if eid and st.get(prefix + "X") not in (None, "") and st.get(prefix + "Y") not in (None, ""):
            px, py = min(1.0, max(0.0, _num(st[prefix + "X"]))), min(1.0, max(0.0, _num(st[prefix + "Y"])))
            ports = el_by_id[eid].setdefault("ports", [])
            hit = next((p for p in ports if abs(p["x"] - px) < 1e-3 and abs(p["y"] - py) < 1e-3), None)
            wanted = st.get("satomSrcPort" if key == "source" else "satomTgtPort", "")
            if hit is not None and wanted and model.ID_RE.match(wanted) and all(p["id"] != wanted for p in ports):
                hit["id"] = wanted
            if hit is None and len(ports) < 60:
                hit = {"id": wanted if (wanted and model.ID_RE.match(wanted) and all(p["id"] != wanted for p in ports))
                       else "p%d_%d" % (round(px * 100), round(py * 100)), "x": px, "y": py}
                ports.append(hit)
            pid = hit["id"] if hit is not None else ""
            if key == "source" and not sport:
                sport = pid
            elif key == "target" and not tport:
                tport = pid
    own = _label(rec).strip()
    labs = ([{"text": own, "pos": 0.5}] if own else []) + labels
    stroke = _color(st.get("strokeColor"))
    props, attr_meta = split_attrs(rec.attrs)
    c = {"id": rec.id, "kind": st.get("satomKind", ""), "source": src, "target": tgt, "source_port": sport, "target_port": tport,
         "points": pts, "routing": _routing(st),
         "start_arrow": _arrow(st.get("startArrow"), st.get("startFill", "1"), w),
         "end_arrow": _arrow(st.get("endArrow", "classic"), st.get("endFill", "1"), w),
         "label": labs[0]["text"] if labs else "", "labels": labs,
         "style": dict({"stroke": stroke or "#000000", "stroke_width": _num(st.get("strokeWidth"), 1.0),
                        "font_color": _color(st.get("fontColor")) or "#000000",
                        "opacity": min(1.0, max(0.0, _num(st.get("opacity"), 100.0) / 100.0))},
                       **_effects(st, None, vertex=False)),
         "layer": "", "properties": props, "metadata": attr_meta, "source_ref": rec.id,
         "confidence": 1.0, "native": {"format": "drawio", "style": _native_style(rec)}}
    if not src:
        c["start"] = sp or (pts[0] if pts else [0.0, 0.0])
    if not tgt:
        c["end"] = tp or (pts[-1] if pts else [0.0, 0.0])
    return c


# ---------------------------------------------------------------------- page

def _convert_page(pid: str, name: str, gm, w: Warnings) -> dict:
    root_el = next((c for c in gm if _local(c.tag) == "root"), None)
    recs = _records(root_el) if root_el is not None else {}
    root_id = next((r.id for r in recs.values() if r.parent is None and not r.vertex and not r.edge), "0")
    layers = [r for r in recs.values() if r.parent == root_id and not r.vertex and not r.edge]
    layer_ids = {r.id for r in layers}

    def layer_of(rec):
        cur, hops = rec, 0
        while cur is not None and hops < 256:
            if cur.parent in layer_ids:
                return cur.parent
            cur = recs.get(cur.parent)
            hops += 1
        return layers[0].id if layers else ""

    # tables: swimlane/table vertices whose children are rows; rows are folded into the table
    tables: dict = {}   # table id -> rows
    consumed: dict = {}  # row-ish cell id -> table id
    kids: dict = {}
    for r in recs.values():
        kids.setdefault(r.parent, []).append(r)
    for r in recs.values():
        if not r.vertex:
            continue
        rows_src = [k for k in kids.get(r.id, []) if k.vertex]
        is_tbl = r.style.get("shape") == "table"
        if (not is_tbl and ("swimlane" in r.flags or r.style.get("shape") == "swimlane")
                and r.style.get("childLayout") == "stackLayout" and rows_src
                and all("text" in k.flags or k.style.get("shape") == "text" for k in rows_src)):
            is_tbl = True
        if is_tbl and rows_src:
            rows = []
            for k in rows_src:
                if r.style.get("shape") == "table":   # tableRow -> cells
                    cells = [c for c in kids.get(k.id, []) if c.vertex]
                    text = " | ".join(_label(c).strip().replace("\n", " ") for c in cells)
                    for c in cells:
                        consumed[c.id] = r.id
                else:
                    text = _label(k).strip()
                consumed[k.id] = r.id
                rid = k.style.get("satomRow") or k.id
                rows.append({"id": rid if model.ID_RE.match(rid) else k.id, "text": text,
                             "bold": bool(int(_num(k.style.get("fontStyle"), 0)) & 1)})
            tables[r.id] = rows

    # a ``group`` cell is a model group (not an element) unless it is also a container
    group_cells = {r.id for r in recs.values() if r.vertex and "group" in r.flags
                   and r.style.get("container") != "1" and r.id not in consumed}
    elements, el_by_id, endpoint, label_children = [], {}, {}, {}
    for r in recs.values():
        if not r.vertex or r.id in consumed or r.id in group_cells:
            continue
        par = recs.get(r.parent)
        if par is not None and par.edge:
            label_children.setdefault(par.id, []).append(r)
            continue
        el = _build_vertex(r, recs, root_id, tables, w)
        el["layer"] = layer_of(r)
        if par is not None and par.vertex and par.id not in consumed and par.id not in group_cells:
            el["parent"] = par.id
            if par.style.get("rotation") not in (None, "", "0"):
                w.once("rot_parent", "Children of rotated containers keep their unrotated positions.")
        if r.id in tables:
            el["rows"] = tables[r.id]
        elements.append(el)
        el_by_id[r.id] = el
    for rid, tid in consumed.items():
        endpoint[rid] = (tid, next((x["id"] for x in tables[tid] if x["id"] == (recs[rid].style.get("satomRow") or rid)), rid))

    connectors = []
    for r in recs.values():
        if not r.edge:
            continue
        labs = []
        for lc in label_children.get(r.id, []):
            text = _label(lc).strip()
            if text:
                gx = _num(lc.geo.get("x")) if lc.geo is not None else 0.0
                labs.append({"text": text, "pos": min(1.0, max(0.0, (gx + 1.0) / 2.0))})
        c = _build_edge(r, recs, root_id, el_by_id, endpoint, labs, w)
        c["layer"] = layer_of(r)
        connectors.append(c)

    groups = []
    for gid in group_cells:
        g = recs[gid]
        members = [k.id for k in kids.get(gid, []) if k.id in el_by_id or k.edge]
        members += [m for m in (g.attrs.get("satomMembers") or "").split(",") if m]
        for r in recs.values():
            if gid in (r.attrs.get("satomGroup") or "").split(",") and (r.id in el_by_id or r.edge):
                members.append(r.id)
        members = list(dict.fromkeys(members))
        if members:
            groups.append({"id": gid, "name": g.attrs.get("satomName", ""), "members": members,
                           "layer": layer_of(g)})

    max_x = max_y = 0.0
    for e in elements:
        max_x, max_y = max(max_x, e["x"] + e["w"]), max(max_y, e["y"] + e["h"])
    for c in connectors:
        for px, py in c["points"] + [c.get("start") or [0, 0], c.get("end") or [0, 0]]:
            max_x, max_y = max(max_x, px), max(max_y, py)
    pw, ph = _num(gm.get("pageWidth")), _num(gm.get("pageHeight"))
    # the model's own page size wins; the content box is only a fallback
    width = pw if pw > 0 else (max_x + 40.0 if max_x else 1600.0)
    height = ph if ph > 0 else (max_y + 40.0 if max_y else 1000.0)
    bg = _color(gm.get("background"))
    return {"id": pid, "name": name,
            "width": width, "height": height,
            "background": bg if bg and bg != "none" else "",
            "layers": [{"id": r.id, "name": _label(r).strip() or "Layer", "visible": r.visible,
                        "locked": r.style.get("locked") == "1"} for r in layers],
            "groups": groups, "elements": elements, "connectors": connectors}


@guarded
def read(data: bytes, *, filename: str = "", page: str | None = None) -> dict:
    data = require_bytes(data)
    fmt, pages, satom = _load_with_origin(data)
    chosen = select_page([{"id": p, "name": n, "gm": g} for p, n, g in pages], page)
    w = Warnings()
    out_pages = [_convert_page(p["id"], p["name"], p["gm"], w) for p in chosen]
    return make_document(fmt=fmt, engine=ENGINE, data=data, filename=filename,
                         name=doc_name(filename, out_pages[0]["name"]), pages=out_pages,
                         warnings=w.items, page=page,
                         metadata={"satom_export": True} if satom else None)
