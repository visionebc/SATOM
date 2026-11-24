"""Native draw.io writer: ``satom.diagram/1`` -> uncompressed ``<mxfile>``.

Safety: a draw.io style is ``key=value;`` text that draw.io parses, so no
model string reaches it unchecked. Shapes come from fixed tables, colours must
be ``#RRGGBB``/``none``, numbers are formatted by us, and a native style
carried over from an import is filtered key by key (``;`` and ``=`` are
separators; values outside a conservative character set are dropped). Labels go
in ``value`` with ``html=0`` (plain text, never markup); ElementTree escapes
every attribute.

Round-trip tags (ignored by draw.io): ``satomCategory``, ``satomSymbol``,
``satomShape``, ``satomKind``, ``satomRow``, ``satomSrcPort``/``satomTgtPort``,
``satomGradAngle`` (a gradient angle draw.io's four directions cannot say) in styles; ``satomName``, ``satomGroup``, ``satomKeys``, ``meta_<key>`` and the
plain property names on the ``<object>`` wrapper.
"""
from __future__ import annotations

import base64
import json
import re
import zlib
from urllib.parse import quote
from xml.etree import ElementTree as ET

from .. import model
from . import _common as C

MIME = "application/vnd.jgraph.mxfile"
VERSION = "satom-ds/1"

SAFE_VALUE = re.compile(r"^[A-Za-z0-9#.,:_\-+ %/()]*$")
KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$")
ATTR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
IMAGE_STYLE_RE = re.compile(r"^data:image/(png|jpeg|gif|webp),[A-Za-z0-9+/=]+$")
STENCIL_RE = re.compile(r"^stencil\([A-Za-z0-9+/=]+\)$")
POINTS_RE = re.compile(r"^\[\[[0-9.,\[\]\- ]*\]\]$")

#: model shape -> fixed draw.io base style. Never built from input.
SHAPE_STYLES = {
    "rect": "rounded=0;whiteSpace=wrap;",
    "round": "rounded=1;arcSize=12;whiteSpace=wrap;",
    "ellipse": "ellipse;whiteSpace=wrap;",
    "diamond": "rhombus;whiteSpace=wrap;",
    "hexagon": "shape=hexagon;perimeter=hexagonPerimeter2;whiteSpace=wrap;",
    "parallelogram": "shape=parallelogram;perimeter=parallelogramPerimeter;whiteSpace=wrap;",
    "trapezoid": "shape=trapezoid;perimeter=trapezoidPerimeter;whiteSpace=wrap;",
    "triangle": "triangle;whiteSpace=wrap;",
    "cylinder": "shape=cylinder3;boundedLbl=1;backgroundOutline=1;size=15;whiteSpace=wrap;",
    "cloud": "ellipse;shape=cloud;whiteSpace=wrap;",
    "document": "shape=document;boundedLbl=1;whiteSpace=wrap;",
    "note": "shape=note;size=14;whiteSpace=wrap;",
    "process": "shape=process;whiteSpace=wrap;",
    "terminator": "rounded=1;arcSize=50;whiteSpace=wrap;",
    "actor": "shape=umlActor;whiteSpace=wrap;",
    "pill": "rounded=1;arcSize=50;whiteSpace=wrap;",
    "zone": "rounded=1;arcSize=4;whiteSpace=wrap;container=1;collapsible=0;",
    "swimlane": "swimlane;startSize=30;container=1;collapsible=0;whiteSpace=wrap;",
    "table": ("swimlane;childLayout=stackLayout;horizontal=1;startSize=30;horizontalStack=0;"
              "resizeParent=1;resizeParentMax=0;resizeLast=0;collapsible=0;marginBottom=0;"),
    "symbol": "rounded=0;whiteSpace=wrap;",
    "line": "line;",
}
TEXT_STYLE = "text;strokeColor=none;fillColor=none;whiteSpace=wrap;"
ROW_STYLE = ("text;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;spacingLeft=6;"
             "spacingRight=4;overflow=hidden;rotatable=0;portConstraint=eastwest;whiteSpace=wrap;")

#: model arrow -> (draw.io arrow name, fill flag)
ARROW_OUT = {"none": ("none", None), "arrow": ("classic", 1), "open": ("open", 0),
             "diamond": ("diamond", 1), "diamond_open": ("diamond", 0),
             "circle": ("oval", 1), "circle_open": ("oval", 0),
             "crowfoot": ("ERmany", 0), "bar": ("ERone", 0)}


def model_arrow(name: str | None, fill) -> str:
    """draw.io arrow (+fill flag) -> model arrow. Unknown names read as ``arrow``."""
    n = name or "none"
    if n == "none":
        return "none"
    if n in ("open", "openThin"):
        return "open"
    if n in ("diamond", "diamondThin"):
        return "diamond" if str(fill) != "0" else "diamond_open"
    if n == "oval":
        return "circle" if str(fill) != "0" else "circle_open"
    if n in ("ERmany", "ERoneToMany", "ERzeroToMany"):
        return "crowfoot"
    if n in ("ERone", "ERmandOne", "dash", "ERzeroToOne"):
        return "bar"
    return "arrow"


# ----------------------------------------------------------------- styles

def parse_style(style: str) -> list[list]:
    """``"a=b;c;"`` -> ``[["a","b"],["c",None]]`` (order kept)."""
    out = []
    for tok in (style or "").split(";"):
        tok = tok.strip()
        if not tok:
            continue
        k, eq, v = tok.partition("=")
        out.append([k, v if eq else None])
    return out


def sanitise_native(style: str) -> dict:
    """Ordered ``{key: value|None}`` keeping only keys and values that are safe."""
    out: dict = {}
    for k, v in parse_style(style):
        if not KEY_RE.match(k):
            continue
        if v is None:
            out[k] = None
        elif k == "image":
            if IMAGE_STYLE_RE.match(v):
                out[k] = v
        elif k == "shape" and STENCIL_RE.match(v):
            out[k] = v
        elif k == "points" and POINTS_RE.match(v):
            out[k] = v
        elif SAFE_VALUE.match(v):
            out[k] = v
    return out


def _fmt(f) -> str:
    f = round(float(f), 2)
    return "%d" % f if f == int(f) else ("%s" % f)


def _stencil(el: dict) -> str | None:
    """``stencil(<b64>)`` for a polygon/path element, or None when it cannot be drawn."""
    w, h = max(el["w"], 1.0), max(el["h"], 1.0)
    ops = []
    if el["shape"] == "polygon" and len(el["points"]) >= 2:
        pts = el["points"]
        ops.append('<move x="%s" y="%s"/>' % (_fmt(pts[0][0] * w), _fmt(pts[0][1] * h)))
        for p in pts[1:]:
            ops.append('<line x="%s" y="%s"/>' % (_fmt(p[0] * w), _fmt(p[1] * h)))
        ops.append("<close/>")
    elif el["shape"] == "path" and el["path"]:
        try:
            segs = C.parse_path(el["path"])
        except ValueError:
            return None
        for s in segs:
            t = s[0]
            if t == "M":
                ops.append('<move x="%s" y="%s"/>' % (_fmt(s[1]), _fmt(s[2])))
            elif t == "L":
                ops.append('<line x="%s" y="%s"/>' % (_fmt(s[1]), _fmt(s[2])))
            elif t == "C":
                ops.append('<curve x1="%s" y1="%s" x2="%s" y2="%s" x3="%s" y3="%s"/>' % tuple(_fmt(v) for v in s[1:]))
            elif t == "Q":
                ops.append('<quad x1="%s" y1="%s" x2="%s" y2="%s"/>' % tuple(_fmt(v) for v in s[1:]))
            elif t == "A":
                ops.append('<arc rx="%s" ry="%s" x-axis-rotation="%s" large-arc-flag="%d" sweep-flag="%d" x="%s" y="%s"/>'
                           % (_fmt(s[1]), _fmt(s[2]), _fmt(s[3]), s[4], s[5], _fmt(s[6]), _fmt(s[7])))
            else:
                ops.append("<close/>")
    if not ops:
        return None
    xml = ('<shape name="satom" w="%s" h="%s" aspect="variable" strokewidth="inherit"><foreground><path>%s</path>'
           "<fillstroke/></foreground></shape>") % (_fmt(w), _fmt(h), "".join(ops))
    # draw.io: base64(deflateRaw(encodeURIComponent(xml)))
    raw = quote(xml, safe="-_.!~*'()").encode("ascii")
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return "stencil(%s)" % base64.b64encode(co.compress(raw) + co.flush()).decode("ascii")


def _image_style_value(img: str) -> str | None:
    m = re.match(r"^data:image/(png|jpeg|gif|webp);base64,([A-Za-z0-9+/=]+)$", img or "")
    return "data:image/%s,%s" % (m.group(1), m.group(2)) if m else None


def _font_style(native: str | None, bold: bool, italic: bool) -> int:
    try:
        keep = int(native or 0) & ~3
    except ValueError:
        keep = 0
    return keep | (1 if bold else 0) | (2 if italic else 0)


def _set(d: dict, key: str, val) -> None:
    d[key] = val


# ------------------------------------------------- colour styling -> draw.io
#: gradient angle (clockwise from east) -> draw.io gradientDirection
DIRECTIONS = {0: "east", 90: "south", 180: "west", 270: "north"}
#: dash pattern -> draw.io dashPattern (units of the stroke width; "dashed" is draw.io's default 3 3)
DASH_OUT = {"dashed": None, "dotted": "1 2", "dash-dot": "6 3 1 3"}


def drawio_dash(d: dict) -> str:
    """The model dash pattern a draw.io style draws (the reader's rule)."""
    if d.get("dashed") != "1":
        return "solid"
    nums = [float(x) for x in re.findall(r"\d+(?:\.\d+)?", d.get("dashPattern") or "")][:16]
    if not nums or not any(nums):
        return "dashed"
    if len(nums) >= 4:
        return "dash-dot"
    return "dotted" if max(nums[0::2]) <= 1.5 else "dashed"


def _style_effects(d: dict, st: dict, vertex: bool) -> None:
    """gradient, shadow, fill/stroke opacity and dash pattern from the model,
    keeping a native value that already says the same thing."""
    pat = C.dash_pattern(st)
    if drawio_dash(d) != pat:
        if pat == "solid":
            d["dashed"] = "0"
            d.pop("dashPattern", None)
        else:
            d["dashed"] = "1"
            if DASH_OUT[pat]:
                d["dashPattern"] = DASH_OUT[pat]
            else:
                d.pop("dashPattern", None)
    if st.get("shadow"):
        d["shadow"] = "1"
        d["shadowColor"] = C.paint(st.get("shadow_color"), "#000000")
    else:
        if "shadow" in d:
            d["shadow"] = "0"
        d.pop("shadowColor", None)
    if st.get("stroke_opacity", 1) < 1:
        d["strokeOpacity"] = str(int(round(st["stroke_opacity"] * 100)))
    else:
        d.pop("strokeOpacity", None)
    if not vertex:
        return
    if st.get("fill_opacity", 1) < 1:
        d["fillOpacity"] = str(int(round(st["fill_opacity"] * 100)))
    else:
        d.pop("fillOpacity", None)
    for k in ("gradientColor", "gradientDirection", "satomGradAngle"):
        d.pop(k, None)
    g = C.gradient_of(st)
    if g is None:
        return
    typ, colour, angle = g
    d["gradientColor"] = colour
    if typ == "radial":
        d["gradientDirection"] = "radial"
        return
    snap = int(round(angle / 90.0)) * 90 % 360
    d["gradientDirection"] = DIRECTIONS[snap]
    if angle != snap:                 # draw.io draws the nearest of its four directions
        d["satomGradAngle"] = str(angle)


def _icon_image_value(ic: dict, stroke: str) -> str | None:
    """``data:image/svg+xml,<base64>`` of the sanitised icon, currentColor resolved (draw.io has no CSS colour)."""
    colour = stroke if C.is_hex(stroke) else "#1F2937"
    svg = ic["svg"].replace("currentColor", colour)
    w, h = ic["vb"][2], ic["vb"][3]
    svg = svg.replace("<svg ", '<svg width="%s" height="%s" ' % (_fmt(w), _fmt(h)), 1)
    return "data:image/svg+xml," + base64.b64encode(svg.encode("utf-8")).decode("ascii")


def vertex_style(el: dict, *, has_children: bool, icon: dict | None = None) -> str:
    st = el["style"]
    native = el.get("native") or {}
    if native.get("format") == "drawio" and native.get("style"):
        d = sanitise_native(native["style"])
        for k in ("satomCategory", "satomSymbol", "satomShape", "satomKind", "satomGradAngle"):
            d.pop(k, None)
    else:
        if el["kind"] == "text":
            base = TEXT_STYLE
        else:
            base = SHAPE_STYLES.get(el["shape"], SHAPE_STYLES["rect"])
        d = sanitise_native(base)
        if el["kind"] == "image" or (el["shape"] == "symbol" and el.get("image")):
            val = _image_style_value(el.get("image", ""))
            if val:
                d = {"shape": "image", "imageAspect": "0", "image": val}
        elif el["shape"] in ("polygon", "path"):
            sten = _stencil(el)
            if sten:
                d = {"shape": sten, "whiteSpace": "wrap"}
        if el["kind"] == "container":
            d["container"] = "1"
            d["collapsible"] = "0"
    if has_children:
        d["container"] = "1"
    if icon is not None and el["shape"] == "symbol":
        d.update({"shape": "image", "imageAspect": "0", "image": _icon_image_value(icon, el["style"]["stroke"]),
                  "verticalLabelPosition": "bottom", "verticalAlign": "top"})
    d["html"] = "0"
    d.setdefault("whiteSpace", "wrap")
    # Values the editor can change always come from the model.
    fill = C.paint(st["fill"], "#FFFFFF")
    d["fillColor"] = fill
    d["strokeColor"] = C.paint(st["stroke"], "#1F2937")
    d["strokeWidth"] = _fmt(st["stroke_width"])
    _style_effects(d, st, vertex=True)
    d["fontColor"] = C.paint(st["font_color"], "#111827")
    d["fontSize"] = _fmt(st["font_size"])
    fs = _font_style(d.get("fontStyle"), st["bold"], st["italic"])
    if fs or "fontStyle" in d:
        d["fontStyle"] = str(fs)
    d["align"] = st["align"]
    if not (icon is not None and el["shape"] == "symbol"):
        d["verticalAlign"] = st["valign"]
    if el["rotation"]:
        d["rotation"] = _fmt(el["rotation"])
    else:
        d.pop("rotation", None)
    if st["opacity"] < 1:
        d["opacity"] = str(int(round(st["opacity"] * 100)))
    else:
        d.pop("opacity", None)
    fam = re.sub(r"[^A-Za-z0-9 ]", "", st.get("font_family") or "").strip()
    if fam:
        d["fontFamily"] = fam
    if el.get("ports"):
        d["points"] = "[" + ",".join("[%s,%s]" % (_fmt(p["x"]), _fmt(p["y"])) for p in el["ports"]) + "]"
    if el["category"] and model.CATEGORY_RE.match(el["category"]):
        d["satomCategory"] = el["category"]
    if el["symbol"] and model.SYMBOL_RE.match(el["symbol"]):
        d["satomSymbol"] = el["symbol"]
    d["satomShape"] = el["shape"]
    d["satomKind"] = el["kind"]
    return _join(d)


def _join(d: dict) -> str:
    return "".join(("%s=%s;" % (k, v)) if v is not None else "%s;" % k for k, v in d.items())


def _routing_of(d: dict) -> str:
    es = d.get("edgeStyle") or ""
    if d.get("curved") == "1":
        return "curved"
    if es in ("orthogonalEdgeStyle", "elbowEdgeStyle", "entityRelationEdgeStyle", "isometricEdgeStyle", "segmentEdgeStyle"):
        return "orthogonal"
    return "straight"


def edge_style(c: dict, src: dict | None, tgt: dict | None, by_id: dict | None = None) -> str:
    st = c["style"]
    native = c.get("native") or {}
    if native.get("format") == "drawio" and native.get("style"):
        d = sanitise_native(native["style"])
        d.pop("satomSrcPort", None)
        d.pop("satomTgtPort", None)
    else:
        d = {"rounded": "0", "jettySize": "auto"}
    d["html"] = "0"
    if _routing_of(d) != c["routing"]:
        for k in ("edgeStyle", "curved", "elbow"):
            d.pop(k, None)
        if c["routing"] == "orthogonal":
            d["edgeStyle"] = "orthogonalEdgeStyle"
        elif c["routing"] == "curved":
            d["curved"] = "1"
        else:
            d["edgeStyle"] = "none"
    elif c["routing"] == "straight" and "edgeStyle" not in d:
        d["edgeStyle"] = "none"
    for side, key in (("start", "start_arrow"), ("end", "end_arrow")):
        cur = model_arrow(d.get(side + "Arrow"), d.get(side + "Fill"))
        if cur != c[key] or side + "Arrow" not in d:
            name, fill = ARROW_OUT[c[key]]
            d[side + "Arrow"] = name
            if fill is None:
                d.pop(side + "Fill", None)
            else:
                d[side + "Fill"] = str(fill)
    d["strokeColor"] = C.paint(st["stroke"], "#1F2937")
    d["strokeWidth"] = _fmt(st["stroke_width"])
    _style_effects(d, st, vertex=False)
    d["fontColor"] = C.paint(st["font_color"], "#111827")
    if st["opacity"] < 1:
        d["opacity"] = str(int(round(st["opacity"] * 100)))
    else:
        d.pop("opacity", None)
    for end, el, port, ex, ey in (("exit", src, c["source_port"], "exitX", "exitY"),
                                  ("entry", tgt, c["target_port"], "entryX", "entryY")):
        if el and port:
            for p in el.get("ports") or []:
                if p["id"] == port:
                    d[ex], d[ey] = _fmt(p["x"]), _fmt(p["y"])
                    d["satomSrcPort" if end == "exit" else "satomTgtPort"] = port
    if c["routing"] == "orthogonal" and by_id:
        # The editor attaches an orthogonal connector to the NEAREST side (or declared port) of the
        # element; say so, otherwise draw.io picks its own perimeter point. draw.io rotates the
        # constraint with the shape, so the unrotated local fractions are what it needs.
        ends = C.route_ends(c, by_id)
        for key, ex, ey in (("source", "exitX", "exitY"), ("target", "entryX", "entryY")):
            a = ends[key]
            if a and "lx" in a and ex not in d:
                d[ex], d[ey] = _fmt(a["lx"]), _fmt(a["ly"])
    if c["kind"] and model.KIND_RE.match(c["kind"]):
        d["satomKind"] = c["kind"]
    return _join(d)


# ---------------------------------------------------------------- attrs

_RESERVED = {"label", "tooltip", "id", "placeholders", "placeholder", "link", "style", "parent", "vertex", "edge",
             "source", "target", "value"}


def _attr_name(raw: str, used: set, prefix: str = "") -> str:
    base = re.sub(r"[^A-Za-z0-9_]", "_", prefix + str(raw))
    if not re.match(r"[A-Za-z_]", base):
        base = "_" + base
    base = base[:60]
    if base in _RESERVED or base.startswith("satom"):
        base = "p_" + base
    name, n = base, 1
    while name in used:
        name = "%s_%d" % (base, n)
        n += 1
    used.add(name)
    return name


def object_attrs(item: dict, *, extra: dict | None = None) -> tuple[dict, bool]:
    """Attributes of the ``<object>`` wrapper (without label/tooltip/id) and
    whether a wrapper is needed at all."""
    attrs: dict = {}
    used: set = set()
    keymap: dict = {}
    types: dict = {}
    for src_key, prefix, mp in (("properties", "", item.get("properties") or {}),
                                ("metadata", "meta_", item.get("metadata") or {})):
        for k, v in mp.items():
            nm = _attr_name(k, used, prefix)
            if nm != prefix + k:
                keymap[nm] = k
            attrs[nm] = C.xml_clean(v if isinstance(v, str) else ("true" if v is True else "false" if v is False else v))
            if prefix and not isinstance(v, str):
                types[nm] = "bool" if isinstance(v, bool) else "int" if isinstance(v, int) else "float"
    # Readers derive a name from the first line of the text; only a different one is worth recording.
    derived = (item.get("text") or "").split("\n", 1)[0].strip()[:80]
    if item.get("name") and item["name"] != derived:
        attrs["satomName"] = C.xml_clean(item["name"])
    if keymap:
        attrs["satomKeys"] = json.dumps(keymap, ensure_ascii=True, separators=(",", ":"))
    if types:
        attrs["satomTypes"] = json.dumps(types, ensure_ascii=True, separators=(",", ":"))
    for k, v in (extra or {}).items():
        attrs[k] = v
    return attrs, bool(attrs) or bool(item.get("description"))


# ----------------------------------------------------------------- writer

class _Ids:
    def __init__(self, page: dict):
        self.used = {"0"}
        self.map: dict = {}
        for lr in page["layers"]:
            self.take(lr["id"])

    def take(self, raw: str) -> str:
        cid = raw if raw not in self.used else "m-" + raw
        while cid in self.used:
            cid = "m-" + cid
        self.used.add(cid)
        self.map[raw] = cid
        return cid

    def fresh(self, base: str) -> str:
        cid, n = base, 1
        while cid in self.used:
            cid = "%s-%d" % (base, n)
            n += 1
        self.used.add(cid)
        return cid


def _geometry(parent, x, y, w, h):
    g = ET.SubElement(parent, "mxGeometry", {"x": _fmt(x), "y": _fmt(y), "width": _fmt(w), "height": _fmt(h),
                                             "as": "geometry"})
    return g


def _emit_cell(root, cid: str, value: str, style: str, parent_id: str, attrs: dict, tooltip: str,
               edge: bool, wrap: bool, extra_cell: dict | None = None):
    cell_attrs = {"style": style, ("edge" if edge else "vertex"): "1", "parent": parent_id}
    cell_attrs.update(extra_cell or {})
    if wrap:
        obj = ET.SubElement(root, "object", {"label": C.xml_clean(value), "id": cid})
        if tooltip:
            obj.set("tooltip", C.xml_clean(tooltip))
        for k, v in attrs.items():
            if ATTR_RE.match(k) and k not in ("label", "id", "tooltip"):
                obj.set(k, C.xml_clean(v))
        return ET.SubElement(obj, "mxCell", cell_attrs)
    return ET.SubElement(root, "mxCell", dict({"id": cid, "value": C.xml_clean(value)}, **cell_attrs))


def _page_xml(parent, page: dict, icons: C.Icons) -> None:
    ids = _Ids(page)
    diagram = ET.SubElement(parent, "diagram", {"id": C.xml_clean(page["id"]), "name": C.xml_clean(page["name"])})
    gm_attrs = {"dx": "0", "dy": "0", "grid": "1", "gridSize": "10", "guides": "1", "tooltips": "1", "connect": "1",
                "arrows": "1", "fold": "1", "page": "1", "pageScale": "1",
                "pageWidth": _fmt(page["width"]), "pageHeight": _fmt(page["height"]), "math": "0", "shadow": "0"}
    if page["background"]:
        gm_attrs["background"] = C.paint(page["background"], "none")
    gm = ET.SubElement(diagram, "mxGraphModel", gm_attrs)
    root = ET.SubElement(gm, "root")
    ET.SubElement(root, "mxCell", {"id": "0"})
    layer_cell = {}
    for lr in page["layers"]:
        cid = ids.map[lr["id"]]
        layer_cell[lr["id"]] = cid
        a = {"id": cid, "value": C.xml_clean(lr["name"]), "parent": "0"}
        if lr["locked"]:
            a["style"] = "locked=1;"
        if not lr["visible"]:
            a["visible"] = "0"
        ET.SubElement(root, "mxCell", a)

    els = page["elements"]
    by_id = {e["id"]: e for e in els}
    has_children = {e["parent"] for e in els if e["parent"]}
    # Ids: elements, then connectors, then groups (model ids are page-unique).
    for e in els:
        ids.take(e["id"])
    for c in page["connectors"]:
        ids.take(c["id"])
    for g in page["groups"]:
        ids.take(g["id"])
    eid = lambda raw: ids.map[raw]

    # Absolute origin of every container, to express children relatively.
    # Groups: re-parent only members without a container parent, in the group's layer,
    # and only into the first group that claims them.
    member_group: dict = {}
    recorded: dict = {}      # item id -> [group ids] kept as an attribute
    for g in page["groups"]:
        claimed = []
        for m in g["members"]:
            e = by_id.get(m)
            if e is not None and not e["parent"] and m not in member_group and e["layer"] == g["layer"]:
                member_group[m] = g["id"]
                claimed.append(m)
            else:
                recorded.setdefault(m, []).append(g["id"])
        g["_claimed"] = claimed

    group_box: dict = {}
    for g in page["groups"]:
        ms = [by_id[m] for m in g["_claimed"]]
        if ms:
            x0, y0 = min(e["x"] for e in ms), min(e["y"] for e in ms)
            x1, y1 = max(e["x"] + e["w"] for e in ms), max(e["y"] + e["h"] for e in ms)
            group_box[g["id"]] = (x0, y0, x1 - x0, y1 - y0)

    # Parents before children, otherwise model order (= z order).
    order, placed = [], set()
    def place(e):
        if e["id"] in placed:
            return
        chain = []
        cur = e
        while cur is not None and cur["id"] not in placed:
            chain.append(cur)
            cur = by_id.get(cur["parent"]) if cur["parent"] else None
        for x in reversed(chain):
            placed.add(x["id"])
            order.append(x)
    for e in els:
        place(e)

    emitted_groups: set = set()
    def emit_group(gid):
        if gid in emitted_groups or gid not in group_box:
            return
        emitted_groups.add(gid)
        g = next(x for x in page["groups"] if x["id"] == gid)
        b = group_box[gid]
        attrs, wrap = object_attrs({"name": g["name"]})
        cell = _emit_cell(root, eid(gid), "", "group;", layer_cell[g["layer"]], attrs, "", False, wrap,
                          {"connectable": "0"})
        _geometry(cell, *b)

    for e in order:
        gid = member_group.get(e["id"])
        if gid:
            emit_group(gid)
            gx, gy = group_box[gid][0], group_box[gid][1]
            parent_id, ox, oy = eid(gid), gx, gy
        elif e["parent"] and e["parent"] in by_id:
            p = by_id[e["parent"]]
            parent_id, ox, oy = eid(p["id"]), p["x"], p["y"]
        else:
            parent_id, ox, oy = layer_cell[e["layer"]], 0.0, 0.0
        cid = eid(e["id"])
        ic = icons.get(e["symbol"]) if (e["shape"] == "symbol" and e["symbol"] and e["kind"] != "image") else None
        style = vertex_style(e, has_children=e["id"] in has_children, icon=ic)
        extra = {}
        if e["id"] in recorded:
            extra["satomGroup"] = ",".join(recorded[e["id"]])
        attrs, wrap = object_attrs(e, extra=extra)
        cell = _emit_cell(root, cid, e["text"], style, parent_id, attrs, e["description"], False, wrap)
        _geometry(cell, e["x"] - ox, e["y"] - oy, e["w"], e["h"])
        if e["shape"] == "table":
            hh = min(30.0, e["h"])
            for j, r in enumerate(e["rows"]):
                rid = ids.fresh("%s.%s" % (cid, r["id"]))
                rs = ROW_STYLE + ("fontStyle=1;" if r["bold"] else "") + "html=0;satomRow=%s;" % r["id"]
                rs += "fontColor=%s;fontSize=%s;" % (C.paint(e["style"]["font_color"], "#111827"),
                                                      _fmt(e["style"]["font_size"]))
                rc = ET.SubElement(root, "mxCell", {"id": rid, "value": C.xml_clean(r["text"]), "style": rs,
                                                    "vertex": "1", "parent": cid})
                _geometry(rc, 0, hh + 22.0 * j, e["w"], 22.0)

    for g in page["groups"]:           # groups whose members were all recorded as attributes
        if g["id"] not in group_box:
            attrs, wrap = object_attrs({"name": g["name"]}, extra={"satomMembers": ",".join(g["members"])})
            cell = _emit_cell(root, eid(g["id"]), "", "group;", layer_cell[g["layer"]], attrs, "", False, True,
                              {"connectable": "0"})
            _geometry(cell, 0, 0, 1, 1)

    for c in page["connectors"]:
        cid = eid(c["id"])
        src, tgt = by_id.get(c["source"]), by_id.get(c["target"])
        extra = {}
        if c["id"] in recorded:
            extra["satomGroup"] = ",".join(recorded[c["id"]])
        attrs, wrap = object_attrs(c, extra=extra)
        cell = _emit_cell(root, cid, c["label"], edge_style(c, src, tgt, by_id), layer_cell[c["layer"]], attrs, "", True, wrap,
                          dict(({"source": eid(c["source"])} if c["source"] else {}),
                               **({"target": eid(c["target"])} if c["target"] else {})))
        geo = ET.SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})
        if c["points"]:
            arr = ET.SubElement(geo, "Array", {"as": "points"})
            for p in c["points"]:
                ET.SubElement(arr, "mxPoint", {"x": _fmt(p[0]), "y": _fmt(p[1])})
        if not c["source"] and len(c["start"]) == 2:
            ET.SubElement(geo, "mxPoint", {"x": _fmt(c["start"][0]), "y": _fmt(c["start"][1]), "as": "sourcePoint"})
        if not c["target"] and len(c["end"]) == 2:
            ET.SubElement(geo, "mxPoint", {"x": _fmt(c["end"][0]), "y": _fmt(c["end"][1]), "as": "targetPoint"})
        fc = C.paint(c["style"]["font_color"], "#111827")
        for i, lab in enumerate(c["labels"]):
            lid = ids.fresh("%s-lbl%d" % (cid, i))
            lc = ET.SubElement(root, "mxCell", {
                "id": lid, "value": C.xml_clean(lab["text"]), "parent": cid, "vertex": "1", "connectable": "0",
                "style": "edgeLabel;html=0;align=center;verticalAlign=middle;resizable=0;fontColor=%s;" % fc})
            g2 = ET.SubElement(lc, "mxGeometry", {"x": _fmt(lab["pos"] * 2 - 1), "relative": "1", "as": "geometry"})
            ET.SubElement(g2, "mxPoint", {"as": "offset"})


def export(doc, *, page=None, options=None) -> tuple[bytes, str, str]:
    icons = C.Icons(options)
    d = C.prepare(doc)
    pages = C.select_pages(d, page)
    mx = ET.Element("mxfile", {"host": "SATOM", "agent": "SATOM Diagram Studio", "version": VERSION,
                               "type": "device"})
    for p in pages:
        _page_xml(mx, p, icons)
    ET.indent(mx, space="  ")
    body = ET.tostring(mx, encoding="unicode")
    suffix = pages[0]["name"] if len(pages) == 1 and len(d["pages"]) > 1 else ""
    return (('<?xml version="1.0" encoding="UTF-8"?>\n' + body + "\n").encode("utf-8"), MIME,
            C.slug_filename(d["name"], "drawio", suffix))
