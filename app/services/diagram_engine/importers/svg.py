"""SVG reader (``.svg``): vector drawings -> ``satom.diagram/1``.

The SVG is treated as hostile. Only a whitelist of elements and properties is
interpreted (see ``_SHAPE_TAGS`` and ``_PROPS``); everything that could run
code or reach the network is dropped and reported once per kind in
``recognition.warnings``: ``script``, ``foreignObject``, ``iframe``/``object``/
``embed``, ``animate*``/``set``, ``on*`` attributes, ``javascript:`` and
external ``href``s, CSS ``@import`` and ``url()`` that does not point inside
the document. ``<!DOCTYPE>`` is refused by :mod:`..xmlsafe` before parsing.
Nothing is ever fetched, executed or written.

What is recognised
------------------
* geometry is made ABSOLUTE by composing every ``transform`` down the tree.
  rect/ellipse under a pure rotation/scale keep ``rotation``; under a skew
  they are baked into a polygon;
* rect -> rect/round/pill, circle/ellipse -> ellipse, polygon -> diamond/
  rect/triangle/polygon, closed path -> rect/round/ellipse/diamond/polygon/path;
* line/polyline/open path -> connector candidates; each end snaps to the
  nearest shape (tolerance ``max(6px, 1.5% of the page diagonal)``); arrows
  come from ``marker-start``/``marker-end`` or a small filled triangle at an
  end; ``confidence`` is 1.0 for an exact touch, down to 0.5 for a loose
  one and 0.4 when an end is free;
* ``<text>`` inside a shape's box becomes that shape's ``text`` (several
  texts keep their top-to-bottom order); a short text hugging a connector
  becomes its label; the rest stay text elements;
* Inkscape layers (``inkscape:groupmode="layer"``) become layers; any other
  ``<g>`` with two or more drawn children becomes a group; ``id``/``class``
  are kept in ``metadata.svg_id`` / ``svg_class`` (``svg_group`` is the
  nearest ancestor group id) for the classifier.

Colour styling: a ``linearGradient``/``radialGradient`` fill becomes ``fill``
(first stop) + ``gradient`` (last stop; the angle from x1/y1/x2/y2); a
``filter`` holding ``feDropShadow`` (or ``feOffset``) becomes ``shadow`` (+ its
``flood-color``); ``fill-opacity``/``stroke-opacity`` and the dash array
(dashed / dotted / dash-dot) are kept.

Approximations: text boxes are estimated from the font size (no font
metrics); stops between the first and the last are dropped; ``preserveAspectRatio``
slice, clip paths, masks, other filters and patterns are ignored; a ``use`` may only
point at ``symbol``/``g`` and is expanded at most 8 levels deep.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import re

from .. import geometry as geo
from .. import model, xmlsafe
from . import (ImportFailed, Warnings, doc_name, guarded, make_document,
               require_bytes)

ENGINE = "svg-reader"

SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"
INK_NS = "http://www.inkscape.org/namespaces/inkscape"
SODI_NS = "http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd"

MAX_NODES = 150_000          # element visits, `use` expansions included
MAX_TREE_NODES = 600_000     # elements in the file
MAX_DEPTH = 64
MAX_USE_DEPTH = 8
MAX_PRIMS = 30_000
MAX_CSS = 200_000
MAX_CSS_RULES = 2_000
MAX_POINTS = 20_000
MAX_TEXT_LEN = 4_000

_DANGEROUS = {
    "script": "script",
    "foreignobject": "foreignobject",
    "iframe": "embedded", "object": "embedded", "embed": "embedded",
    "audio": "embedded", "video": "embedded", "canvas": "embedded",
    "animate": "animation", "animatemotion": "animation", "animatetransform": "animation",
    "animatecolor": "animation", "set": "animation", "discard": "animation",
}
_MESSAGES = {
    "script": "Removed %d <script> element(s): scripts are never executed.",
    "foreignobject": "Removed %d <foreignObject> element(s): embedded HTML is not imported.",
    "embedded": "Removed %d embedded-content element(s) (iframe/object/embed/audio/video).",
    "animation": "Removed %d animation element(s) (animate*/set).",
    "event": "Removed %d event-handler attribute(s) (on*).",
    "js_url": "Removed %d javascript: URL(s).",
    "external_ref": "Removed %d external reference(s): links and remote resources are never fetched.",
    "css_import": "Removed %d CSS @import rule(s).",
    "css_url": "Removed %d CSS url() value(s) that do not point inside the document.",
    "css_atrule": "Ignored %d CSS at-rule block(s) (@media/@font-face/...).",
    "css_selector": "Ignored %d CSS rule(s) with selectors more complex than tag, .class and #id.",
    "image_type": "Dropped %d image(s) that are not an embedded png/jpeg/gif/webp data: URI.",
    "image_big": "Dropped %d embedded image(s) larger than %d KiB.",
    "use_cycle": "Skipped %d <use> reference(s) that point at themselves.",
    "use_depth": "Skipped %d <use> reference(s) nested deeper than %d levels.",
    "use_target": "Skipped %d <use> reference(s) that do not point at a <symbol> or <g> in this file.",
    "depth": "Skipped %d element(s) nested deeper than %d levels.",
    "path": "Skipped %d unreadable <path> element(s).",
    "prims": "Stopped reading after %d drawable objects.",
}

# elements that are known and deliberately not rendered (defs content is only
# reachable through `use`/marker/paint references)
_SKIP_TAGS = {"defs", "symbol", "marker", "style", "title", "desc", "metadata", "lineargradient",
              "radialgradient", "stop", "pattern", "clippath", "mask", "filter", "namedview",
              "tspan", "textpath", "view", "cursor", "font", "glyph", "missing-glyph", "font-face"}
_CONTAINER_TAGS = {"g", "a", "switch", "svg"}
_SHAPE_TAGS = {"rect", "circle", "ellipse", "line", "polyline", "polygon", "path"}

_INHERITED = {"fill", "stroke", "stroke-width", "stroke-dasharray", "font-size", "font-family",
              "font-weight", "font-style", "text-anchor", "marker-start", "marker-end", "color",
              "visibility", "fill-opacity", "stroke-opacity"}
_PROPS = _INHERITED | {"opacity", "display", "stop-color", "filter"}

_NUM = r"[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?"
_NUM_RE = re.compile(_NUM)
_LEN_RE = re.compile(r"^\s*(%s)\s*(px|pt|pc|mm|cm|in|em|ex|%%)?\s*$" % _NUM, re.I)
_URL_LOCAL_RE = re.compile(r"^\s*url\(\s*['\"]?#([^)'\"\s]+)['\"]?\s*\)\s*(.*)$", re.I)
_UNIT = {"": 1.0, "px": 1.0, "pt": 96.0 / 72.0, "pc": 16.0, "mm": 96.0 / 25.4,
         "cm": 96.0 / 2.54, "in": 96.0}

_NAMED = {
    "black": "#000000", "white": "#FFFFFF", "red": "#FF0000", "green": "#008000", "blue": "#0000FF",
    "yellow": "#FFFF00", "orange": "#FFA500", "purple": "#800080", "gray": "#808080", "grey": "#808080",
    "silver": "#C0C0C0", "maroon": "#800000", "navy": "#000080", "teal": "#008080", "lime": "#00FF00",
    "aqua": "#00FFFF", "cyan": "#00FFFF", "fuchsia": "#FF00FF", "magenta": "#FF00FF", "olive": "#808000",
    "brown": "#A52A2A", "pink": "#FFC0CB", "gold": "#FFD700", "lightgray": "#D3D3D3",
    "lightgrey": "#D3D3D3", "darkgray": "#A9A9A9", "darkgrey": "#A9A9A9", "darkgreen": "#006400",
    "darkblue": "#00008B", "darkred": "#8B0000", "lightblue": "#ADD8E6", "lightgreen": "#90EE90",
    "lightyellow": "#FFFFE0", "orangered": "#FF4500", "tomato": "#FF6347", "crimson": "#DC143C",
    "coral": "#FF7F50", "salmon": "#FA8072", "indigo": "#4B0082", "violet": "#EE82EE",
    "turquoise": "#40E0D0", "skyblue": "#87CEEB", "steelblue": "#4682B4", "royalblue": "#4169E1",
    "dodgerblue": "#1E90FF", "whitesmoke": "#F5F5F5", "gainsboro": "#DCDCDC", "beige": "#F5F5DC",
    "ivory": "#FFFFF0", "khaki": "#F0E68C", "dimgray": "#696969", "dimgrey": "#696969",
    "slategray": "#708090", "slategrey": "#708090", "firebrick": "#B22222", "forestgreen": "#228B22",
}

_IMG_RE = re.compile(r"^data:image/(png|jpeg|gif|webp);base64,([A-Za-z0-9+/=\s]+)$", re.I)
_MAGIC = {"png": b"\x89PNG", "jpeg": b"\xff\xd8\xff", "gif": b"GIF8"}


def _dash_pattern(dash: str, sw: float) -> str:
    """A dash array -> dashed | dotted | dash-dot (the writers' patterns, relative to the stroke width)."""
    nums = [float(x) for x in _NUM_RE.findall(dash)][:32]
    if len(nums) % 2:
        nums = nums * 2
    if len(nums) >= 4 and len(set(round(x, 2) for x in nums[0::2])) > 1:
        return "dash-dot"
    return "dotted" if nums and max(nums[0::2]) <= max(1.0, sw) * 1.5 else "dashed"


def _local(tag) -> str:
    return xmlsafe.local(tag) if isinstance(tag, str) else ""


def _ns(tag) -> str:
    if isinstance(tag, str) and tag.startswith("{"):
        return tag[1:].split("}", 1)[0]
    return ""


def _is_svg_ns(el) -> bool:
    return _ns(el.tag) in ("", SVG_NS)


def _href(el) -> str:
    return (el.get("href") or el.get("{%s}href" % XLINK_NS) or "").strip()


def _first_num(v, default=0.0):
    if v is None:
        return default
    mo = _NUM_RE.search(str(v))
    if not mo:
        return default
    try:
        f = float(mo.group(0))
    except ValueError:
        return default
    return f if math.isfinite(f) else default


def _length(v, default: float = 0.0, ref: float | None = None, fs: float = 16.0) -> float:
    if v is None:
        return default
    mo = _LEN_RE.match(str(v))
    if not mo:
        return default
    try:
        n = float(mo.group(1))
    except ValueError:
        return default
    unit = (mo.group(2) or "").lower()
    if unit == "%":
        return n * ref / 100.0 if ref else default
    if unit == "em":
        return n * fs
    if unit == "ex":
        return n * fs * 0.5
    out = n * _UNIT.get(unit, 1.0)
    return out if math.isfinite(out) else default


# ===================================================================== reader

class _Group:
    __slots__ = ("svg_id", "name", "parent", "prims", "layer")

    def __init__(self, svg_id, name, parent, layer):
        self.svg_id, self.name, self.parent, self.layer = svg_id, name, parent, layer
        self.prims: list = []


class _Ctx:
    __slots__ = ("m", "props", "opacity", "layer", "group", "use_stack", "depth")

    def __init__(self, m, props, opacity, layer, group, use_stack, depth):
        self.m, self.props, self.opacity = m, props, opacity
        self.layer, self.group, self.use_stack, self.depth = layer, group, use_stack, depth

    def child(self, **kw):
        d = {s: getattr(self, s) for s in self.__slots__}
        d.update(kw)
        return _Ctx(**d)


class _Reader:
    def __init__(self, root):
        self.root = root
        self.counts: dict = {}
        self.ids: dict = {}
        self.rules_by_tag: dict = {}
        self.rules_by_class: dict = {}
        self.rules_by_id: dict = {}
        self.rules_any: list = []
        self.nodes = 0
        self.order = 0
        self.prims: list = []
        self.layers: list = []
        self.groups: list = []
        self.tag_n: dict = {}

    # ---------------------------------------------------------- counters
    def hit(self, kind: str, n: int = 1) -> None:
        self.counts[kind] = self.counts.get(kind, 0) + n

    # ---------------------------------------------------------- pre-scan
    def prescan(self) -> None:
        n = 0
        for el in self.root.iter():
            n += 1
            if n > MAX_TREE_NODES:
                raise ImportFailed("The SVG has more than %d elements." % MAX_TREE_NODES)
            tag = _local(el.tag)
            low = tag.lower()
            kind = _DANGEROUS.get(low)
            if kind:
                self.hit(kind)
            ident = el.get("id")
            if ident and ident not in self.ids:
                self.ids[ident] = el
            for k in el.attrib:
                lk = _local(k).lower()
                if lk.startswith("on") and len(lk) > 2:
                    self.hit("event")
                elif lk == "href":
                    h = re.sub(r"[\x00-\x20]", "", el.attrib[k]).lower()
                    if h.startswith("#"):
                        continue
                    if h.startswith("data:") and low == "image":
                        continue
                    if h.startswith("javascript:") or h.startswith("vbscript:"):
                        self.hit("js_url")
                    elif h.startswith("data:"):
                        self.hit("external_ref")
                    else:
                        self.hit("external_ref")
            if low == "style" and _is_svg_ns(el):
                self.add_css("".join(el.itertext()))

    # ---------------------------------------------------------- CSS
    def safe_value(self, val: str):
        v = val.strip()
        v = re.sub(r"\s*!important\s*$", "", v, flags=re.I)
        low = v.lower()
        if not v or len(v) > 300:
            return None
        if "\\" in v or "expression(" in low or "@import" in low:
            self.hit("css_url")
            return None
        if "javascript:" in low or "vbscript:" in low:
            self.hit("js_url")
            return None
        if "url(" in low and not _URL_LOCAL_RE.match(v):
            self.hit("css_url")
            return None
        return v

    def declarations(self, text: str) -> dict:
        out = {}
        for part in text.split(";"):
            if ":" not in part:
                continue
            name, _, val = part.partition(":")
            name = name.strip().lower()
            if name not in _PROPS:
                continue
            v = self.safe_value(val)
            if v is not None:
                out[name] = v
        return out

    def add_css(self, text: str) -> None:
        text = re.sub(r"/\*.*?\*/", "", text[:MAX_CSS], flags=re.S)
        # at-rules: @import is counted and cut; blocks (@media, @font-face) are skipped whole
        out, i, n = [], 0, len(text)
        while i < n:
            if text[i] == "@":
                j = i
                while j < n and text[j] not in "{;":
                    j += 1
                head = text[i:j].lower()
                if j < n and text[j] == "{":
                    depth = 0
                    while j < n:
                        depth += text[j] == "{"
                        depth -= text[j] == "}"
                        j += 1
                        if depth == 0:
                            break
                    self.hit("css_atrule")
                else:
                    j += 1
                    if head.startswith("@import"):
                        self.hit("css_import")
                    else:
                        self.hit("css_atrule")
                i = j
            else:
                out.append(text[i])
                i += 1
        text = "".join(out)
        order = len(self.rules_any) + sum(len(v) for v in self.rules_by_tag.values()) \
            + sum(len(v) for v in self.rules_by_class.values()) + sum(len(v) for v in self.rules_by_id.values())
        for mo in re.finditer(r"([^{}]+)\{([^{}]*)\}", text):
            if order >= MAX_CSS_RULES:
                break
            decls = self.declarations(mo.group(2))
            if not decls:
                continue
            for sel in mo.group(1).split(","):
                sm = re.match(r"^\s*(\*|[A-Za-z][\w-]*)?((?:[.#][\w-]+)*)\s*$", sel)
                if not sm or not (sm.group(1) or sm.group(2)):
                    self.hit("css_selector")
                    continue
                tag = (sm.group(1) or "").lower()
                classes = re.findall(r"\.([\w-]+)", sm.group(2))
                ids = re.findall(r"#([\w-]+)", sm.group(2))
                if tag == "*":
                    tag = ""
                rule = {"tag": tag, "classes": classes, "id": ids[0] if ids else "",
                        "spec": (len(ids), len(classes), 1 if tag else 0), "order": order, "decls": decls}
                order += 1
                if rule["id"]:
                    self.rules_by_id.setdefault(rule["id"], []).append(rule)
                elif classes:
                    self.rules_by_class.setdefault(classes[0], []).append(rule)
                elif tag:
                    self.rules_by_tag.setdefault(tag, []).append(rule)
                else:
                    self.rules_any.append(rule)

    def css_for(self, el, tag: str, classes: list) -> dict:
        cands = list(self.rules_any)
        cands += self.rules_by_tag.get(tag.lower(), ())
        for c in classes:
            cands += self.rules_by_class.get(c, ())
        ident = el.get("id")
        if ident:
            cands += self.rules_by_id.get(ident, ())
        hits = []
        for r in cands:
            if r["tag"] and r["tag"] != tag.lower():
                continue
            if r["id"] and r["id"] != ident:
                continue
            if any(c not in classes for c in r["classes"]):
                continue
            hits.append(r)
        hits.sort(key=lambda r: (r["spec"], r["order"]))
        out: dict = {}
        for r in hits:
            out.update(r["decls"])
        return out

    # ---------------------------------------------------------- properties
    def props_of(self, el, tag: str, parent: dict) -> dict:
        """Inherited properties of *parent* overlaid with this element's own
        (presentation attributes < CSS rules < inline style)."""
        p = {k: v for k, v in parent.items() if k in _INHERITED}
        classes = (el.get("class") or "").split()
        for k in _PROPS:
            v = el.get(k)
            if v is not None:
                sv = self.safe_value(v)
                if sv is not None:
                    p[k] = sv
        if self.rules_any or self.rules_by_tag or self.rules_by_class or self.rules_by_id:
            p.update(self.css_for(el, tag, classes))
        st = el.get("style")
        if st:
            p.update(self.declarations(st[:4000]))
        return p

    def color(self, value, props: dict, depth: int = 0):
        """``#RRGGBB`` / ``"none"`` / ``None`` (not interpretable)."""
        if value is None:
            return None
        v = str(value).strip()
        low = v.lower()
        if low in ("none", "transparent"):
            return "none"
        if low == "currentcolor":
            return self.color(props.get("color", "#000000"), {}, depth + 1) if depth < 2 else None
        m = re.fullmatch(r"#([0-9a-f]{3,8})", low)
        if m:
            h = m.group(1)
            if len(h) in (3, 4):
                return "#" + "".join(c * 2 for c in h[:3]).upper()
            if len(h) in (6, 8):
                return "#" + h[:6].upper()
            return None
        m = re.fullmatch(r"rgba?\(([^)]*)\)", low)
        if m:
            parts = [x for x in re.split(r"[\s,/]+", m.group(1).strip()) if x]
            if len(parts) >= 3:
                rgb = []
                for x in parts[:3]:
                    try:
                        n = float(x[:-1]) * 2.55 if x.endswith("%") else float(x)
                    except ValueError:
                        return None
                    rgb.append(int(round(min(255.0, max(0.0, n)))))
                return "#%02X%02X%02X" % tuple(rgb)
            return None
        if low in _NAMED:
            return _NAMED[low]
        m = _URL_LOCAL_RE.match(v)
        if m and depth < 3:
            return self.paint_server_color(m.group(1), depth)
        return None

    def paint_server_color(self, ident: str, depth: int):
        el = self.ids.get(ident)
        if el is None:
            return None
        if _local(el.tag).lower() not in ("lineargradient", "radialgradient"):
            return None
        for st in el:
            if _local(st.tag).lower() == "stop":
                d = self.declarations(st.get("style") or "")
                val = st.get("stop-color") or d.get("stop-color")
                return self.color(val, {}, depth + 1) if val else "#000000"
        h = _href(el)
        if h.startswith("#") and depth < 3:
            return self.paint_server_color(h[1:], depth + 1)
        return None

    def gradient_info(self, value):
        """``{"type", "first", "last", "angle"}`` of a ``url(#gradient)`` paint, else None."""
        m = _URL_LOCAL_RE.match(str(value or ""))
        el = self.ids.get(m.group(1)) if m else None
        if el is None or _local(el.tag).lower() not in ("lineargradient", "radialgradient"):
            return None
        typ = "radial" if _local(el.tag).lower() == "radialgradient" else "linear"
        attrs, stops, cur, hops = {}, [], el, 0
        while cur is not None and hops < 4:             # xlink:href inherits stops and attributes
            for k in ("x1", "y1", "x2", "y2"):
                if k not in attrs and cur.get(k) is not None:
                    attrs[k] = cur.get(k)
            if not stops:
                stops = [st for st in cur if _local(st.tag).lower() == "stop"]
            h = _href(cur)
            cur = self.ids.get(h[1:]) if h.startswith("#") else None
            hops += 1
        if len(stops) < 2:
            return None

        def stop_colour(st):
            d = self.declarations(st.get("style") or "")
            return self.color(st.get("stop-color") or d.get("stop-color") or "#000000", {}, 1)

        first, last = stop_colour(stops[0]), stop_colour(stops[-1])
        if first in (None, "none") or last in (None, "none"):
            return None

        def frac(v, d):
            v = str(v if v is not None else d).strip()
            return _first_num(v, d) / (100.0 if v.endswith("%") else 1.0)

        angle = 90
        if typ == "linear":
            x1, y1 = frac(attrs.get("x1"), 0.0), frac(attrs.get("y1"), 0.0)
            x2, y2 = frac(attrs.get("x2"), 1.0), frac(attrs.get("y2"), 0.0)
            angle = 90 if (abs(x2 - x1) < 1e-9 and abs(y2 - y1) < 1e-9) else \
                int(round(math.degrees(math.atan2(y2 - y1, x2 - x1)))) % 360
        return {"type": typ, "first": first, "last": last, "angle": angle}

    def shadow_of(self, value):
        """``(True, colour)`` when ``filter: url(#f)`` is a drop shadow, else ``(False, "")``."""
        m = _URL_LOCAL_RE.match(str(value or ""))
        el = self.ids.get(m.group(1)) if m else None
        if el is None or _local(el.tag).lower() != "filter":
            return False, ""
        for ch in el.iter():
            t = _local(ch.tag).lower()
            if t == "fedropshadow":
                c = self.color(ch.get("flood-color") or "#000000", {}, 1)
                return True, c if c and c != "none" else "#000000"
            if t == "feoffset":
                flood = next((x for x in el.iter() if _local(x.tag).lower() == "feflood"), None)
                c = self.color(flood.get("flood-color"), {}, 1) if flood is not None else None
                return True, c if c and c != "none" else "#000000"
        return False, ""

    # ---------------------------------------------------------- walking
    def new_prim(self, kind: str, el, tag: str, ctx: _Ctx, **kw) -> dict:
        self.order += 1
        n = self.tag_n.get(tag, 0) + 1
        self.tag_n[tag] = n
        ident = el.get("id") or ""
        prim = {"kind": kind, "order": self.order, "tag": tag, "svg_id": ident[:100],
                "svg_class": (el.get("class") or "")[:200], "layer": ctx.layer, "group": ctx.group,
                "source_ref": ("#" + ident[:80]) if ident else "%s[%d]" % (tag, n)}
        for ch in el:
            lt = _local(ch.tag).lower()
            if lt == "title" and not prim.get("title"):
                prim["title"] = "".join(ch.itertext()).strip()[:200]
            elif lt == "desc" and not prim.get("desc"):
                prim["desc"] = "".join(ch.itertext()).strip()[:1000]
        prim.update(kw)
        if len(self.prims) >= MAX_PRIMS:
            self.counts["prims"] = MAX_PRIMS
            return prim
        self.prims.append(prim)
        ctx.group.prims.append(prim)
        return prim

    def tick(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise ImportFailed("The SVG expands to more than %d elements (a <use> chain that "
                               "multiplies itself?); it was refused." % MAX_NODES)

    def walk_children(self, el, ctx: _Ctx) -> None:
        for ch in list(el):
            if len(self.prims) >= MAX_PRIMS:
                self.counts["prims"] = MAX_PRIMS
                return
            self.visit(ch, ctx)

    def visit(self, el, ctx: _Ctx) -> None:
        self.tick()
        if not isinstance(el.tag, str) or not _is_svg_ns(el):
            return
        tag = _local(el.tag)
        low = tag.lower()
        if low in _DANGEROUS or low in _SKIP_TAGS:
            return
        if ctx.depth >= MAX_DEPTH:
            self.hit("depth")
            return
        props = self.props_of(el, tag, ctx.props)
        if props.get("display", "").lower() == "none":
            if not (low == "g" and el.get("{%s}groupmode" % INK_NS) == "layer"):
                return
        m = geo.compose(ctx.m, geo.parse_transform(el.get("transform")))
        opacity = ctx.opacity * min(1.0, max(0.0, _first_num(props.get("opacity"), 1.0)))
        if low in _CONTAINER_TAGS:
            self.container(el, tag, low, props, m, opacity, ctx)
        elif low == "use":
            self.use(el, props, m, opacity, ctx)
        elif low in _SHAPE_TAGS:
            if props.get("visibility", "").lower() in ("hidden", "collapse"):
                return
            self.shape(el, low, props, m, opacity, ctx)
        elif low == "text":
            if props.get("visibility", "").lower() in ("hidden", "collapse"):
                return
            self.text(el, props, m, opacity, ctx)
        elif low == "image":
            self.image(el, props, m, opacity, ctx)
        else:
            self.hit("unsupported:" + low[:30])

    def container(self, el, tag, low, props, m, opacity, ctx: _Ctx) -> None:
        layer, group = ctx.layer, ctx.group
        is_layer = low == "g" and el.get("{%s}groupmode" % INK_NS) == "layer"
        if low == "svg" and el is not self.root:
            m = geo.multiply(m, geo.translate(_length(el.get("x")), _length(el.get("y"))))
        if is_layer:
            lid = "L%d" % (len(self.layers) + 1)
            name = (el.get("{%s}label" % INK_NS) or el.get("id") or "").strip()[:100]
            self.layers.append({"id": lid, "name": name or "Layer %d" % (len(self.layers) + 1),
                                "visible": props.get("display", "").lower() != "none",
                                "locked": (el.get("{%s}insensitive" % SODI_NS) or "").lower() == "true"})
            layer = lid
        else:
            title = ""
            for ch in el:
                if _local(ch.tag).lower() == "title":
                    title = "".join(ch.itertext()).strip()[:100]
                    break
            group = _Group((el.get("id") or "")[:100], title or el.get("id") or "", ctx.group, layer)
            self.groups.append(group)
        sub = ctx.child(m=m, props=props, opacity=opacity, layer=layer, group=group, depth=ctx.depth + 1)
        self.walk_children(el, sub)

    def use(self, el, props, m, opacity, ctx: _Ctx) -> None:
        h = _href(el)
        if not h.startswith("#"):
            return                                   # external: already counted by the pre-scan
        target = self.ids.get(h[1:])
        tl = _local(target.tag).lower() if target is not None else ""
        if target is None or tl not in ("symbol", "g"):
            self.hit("use_target")
            return
        if h[1:] in ctx.use_stack:
            self.hit("use_cycle")
            return
        if len(ctx.use_stack) >= MAX_USE_DEPTH:
            self.hit("use_depth")
            return
        m = geo.multiply(m, geo.translate(_length(el.get("x")), _length(el.get("y"))))
        group = _Group((el.get("id") or "")[:100], el.get("id") or h[1:], ctx.group, ctx.layer)
        self.groups.append(group)
        sub = ctx.child(m=m, props=props, opacity=opacity, group=group, use_stack=ctx.use_stack + (h[1:],),
                        depth=ctx.depth + 1)
        if tl == "g":
            self.visit(target, sub)
        else:
            tprops = self.props_of(target, "symbol", props)
            self.walk_children(target, sub.child(props=tprops))

    # ---------------------------------------------------------- styles
    def style_of(self, props: dict, opacity: float, scale: float, text: bool = False) -> dict:
        fill = self.color(props.get("fill"), props)
        stroke = self.color(props.get("stroke"), props)
        st = {"fill": fill if fill else ("#000000" if "fill" not in props else "none"),
              "stroke": stroke if stroke else "none",
              "stroke_width": round(max(0.0, _length(props.get("stroke-width"), 1.0)) * scale, 3)
              if stroke not in (None, "none") else 0.0,
              "opacity": round(opacity, 3), "dashed": False}
        dash = props.get("stroke-dasharray", "").strip().lower()
        if dash and dash != "none":
            st["dashed"] = any(float(x) > 0 for x in _NUM_RE.findall(dash))
        st["dash_pattern"] = _dash_pattern(dash, _length(props.get("stroke-width"), 1.0)) if st["dashed"] else "solid"
        for k in ("fill-opacity", "stroke-opacity"):
            if props.get(k) is not None:
                st[k.replace("-", "_")] = round(min(1.0, max(0.0, _first_num(props[k], 1.0))), 3)
        g = self.gradient_info(props.get("fill"))
        if g is not None:
            st["fill"] = g["first"]
            st["gradient"] = {"type": g["type"], "color": g["last"], "angle": g["angle"]}
        on, colour = self.shadow_of(props.get("filter"))
        if on:
            st["shadow"], st["shadow_color"] = True, colour
        return st

    def font_of(self, props: dict, scale: float) -> dict:
        fs = _length(props.get("font-size"), 16.0, ref=16.0) * scale
        fam = props.get("font-family", "").split(",")[0].strip().strip("'\"")
        fam = re.sub(r"[^A-Za-z0-9 \-]", "", fam)[:60].strip()
        weight = props.get("font-weight", "").strip().lower()
        bold = weight in ("bold", "bolder") or (weight.isdigit() and int(weight) >= 600)
        anchor = props.get("text-anchor", "start").strip().lower()
        fill = self.color(props.get("fill"), props)
        return {"font_size": round(min(200.0, max(4.0, fs)), 2), "font_family": fam,
                "bold": bold, "italic": props.get("font-style", "").strip().lower() in ("italic", "oblique"),
                "font_color": fill if fill and fill != "none" else "#000000",
                "align": {"middle": "center", "end": "right"}.get(anchor, "left"), "anchor": anchor}

    # ---------------------------------------------------------- shapes
    def marker_arrow(self, props: dict, key: str) -> str:
        v = props.get(key, "")
        mo = _URL_LOCAL_RE.match(v)
        if not mo:
            return "none"
        mk = self.ids.get(mo.group(1))
        if mk is None or _local(mk.tag).lower() != "marker":
            return "none"
        name = mo.group(1).lower()
        mprops = self.props_of(mk, "marker", {})
        for ch in mk.iter():
            lt = _local(ch.tag).lower()
            if lt not in ("path", "polygon", "polyline", "circle", "ellipse", "rect"):
                continue
            cp = self.props_of(ch, lt, mprops)
            filled = self.color(cp.get("fill", "#000000"), cp) not in ("none", None) \
                and "open" not in name and "line" not in name
            if lt in ("circle", "ellipse") or "circle" in name or "dot" in name:
                return "circle" if filled else "circle_open"
            pts = []
            if lt == "polygon":
                nums = [float(x) for x in _NUM_RE.findall(ch.get("points") or "")]
                pts = list(zip(nums[0::2], nums[1::2]))
            elif lt == "path":
                for sub, _ in geo.flatten(geo.parse_path(ch.get("d"))):
                    pts.extend(sub)
            if len(geo.clean_polygon(pts)) == 4 and geo.is_diamond(pts) or "diamond" in name:
                return "diamond" if filled else "diamond_open"
            return "arrow" if filled else "open"
        return "arrow"

    def shape(self, el, low: str, props, m, opacity, ctx: _Ctx) -> None:
        scale = geo.mean_scale(m)
        style = self.style_of(props, opacity, scale)
        dec = geo.decompose(m)
        if low == "rect":
            x, y = _length(el.get("x")), _length(el.get("y"))
            w, h = _length(el.get("width")), _length(el.get("height"))
            if w <= 0 or h <= 0:
                return
            rx_raw, ry_raw = el.get("rx"), el.get("ry")
            rx = _length(rx_raw) if rx_raw is not None else None
            ry = _length(ry_raw) if ry_raw is not None else None
            if rx is None and ry is not None:
                rx = ry
            if ry is None and rx is not None:
                ry = rx
            rx = min(rx or 0.0, w / 2.0)
            ry = min(ry or 0.0, h / 2.0)
            self.box_prim(el, "rect", ctx, m, dec, x, y, w, h, style, rx, ry)
        elif low in ("circle", "ellipse"):
            cx, cy = _length(el.get("cx")), _length(el.get("cy"))
            if low == "circle":
                rx = ry = _length(el.get("r"))
            else:
                rx, ry = _length(el.get("rx")), _length(el.get("ry"))
            if rx <= 0 or ry <= 0:
                return
            self.box_prim(el, "ellipse", ctx, m, dec, cx - rx, cy - ry, 2 * rx, 2 * ry, style, 0, 0)
        elif low in ("line",):
            pts = [geo.apply(m, _length(el.get("x1")), _length(el.get("y1"))),
                   geo.apply(m, _length(el.get("x2")), _length(el.get("y2")))]
            self.line_prim(el, low, ctx, pts, False, props, style)
        elif low in ("polyline", "polygon"):
            nums = [float(x) for x in _NUM_RE.findall((el.get("points") or "")[:400_000])[:2 * MAX_POINTS]]
            pts = geo.apply_points(m, list(zip(nums[0::2], nums[1::2])))
            if len(pts) < 2:
                return
            if low == "polygon" or (len(pts) >= 3 and abs(pts[0][0] - pts[-1][0]) < 0.01
                                    and abs(pts[0][1] - pts[-1][1]) < 0.01 and style["fill"] != "none"
                                    and "fill" in props):
                self.outline_prim(el, "polygon", ctx, geo.polygon_segments(pts), style)
            else:
                self.line_prim(el, low, ctx, pts, False, props, style)
        elif low == "path":
            segs = geo.parse_path(el.get("d"))
            if not segs:
                if (el.get("d") or "").strip():
                    self.hit("path")
                return
            self.path_prims(el, ctx, geo.transform_segments(segs, m), props, style)

    def box_prim(self, el, kind, ctx, m, dec, x, y, w, h, style, rx, ry) -> None:
        if dec is not None:
            cx, cy = geo.apply(m, x + w / 2.0, y + h / 2.0)
            W, H = w * dec["sx"], h * dec["sy"]
            rot = dec["rotation"]
            rot = 0.0 if abs(rot) < 0.01 else rot
            shape = "ellipse" if kind == "ellipse" else "rect"
            st = dict(style)
            if kind == "rect" and (rx > 0 or ry > 0):
                st["rounded"] = True
                shape = "pill" if (rx * dec["sx"] >= 0.45 * min(W, H) and ry * dec["sy"] >= 0.45 * min(W, H)) else "round"
            self.new_prim("shape", el, kind, ctx, shape=shape, x=cx - W / 2.0, y=cy - H / 2.0, w=W, h=H,
                          rotation=rot, style=st, poly=None, filled=True, confidence=1.0)
            return
        # skewed / sheared: bake the outline into points
        if kind == "ellipse":
            pts = [geo.apply(m, x + w / 2.0 + w / 2.0 * math.cos(2 * math.pi * k / 32),
                             y + h / 2.0 + h / 2.0 * math.sin(2 * math.pi * k / 32)) for k in range(32)]
        else:
            pts = geo.apply_points(m, [(x, y), (x + w, y), (x + w, y + h), (x, y + h)])
        self.outline_prim(el, "polygon", ctx, geo.polygon_segments(pts), style, baked=True)

    def outline_prim(self, el, tag, ctx, segs, style, baked: bool = False) -> None:
        """A closed outline -> the best shape (rect/round/ellipse/diamond/triangle/polygon/path)."""
        c = geo.classify_outline(segs)
        if c is None:
            return
        conf = min(c["confidence"], 0.9) if baked else c["confidence"]
        st = dict(style, rounded=True) if c["rounded"] else style
        self.new_prim("shape", el, tag, ctx, shape=c["shape"], x=c["x"], y=c["y"], w=c["w"], h=c["h"],
                      rotation=0.0, style=st, poly=c["poly"], rel=c["points"], path=c["path"],
                      filled=style["fill"] != "none", confidence=conf)

    def path_prims(self, el, ctx, segs, props, style) -> None:
        explicit_fill = style["fill"] != "none" and "fill" in props
        groups: list = []
        cur: list = []
        for s in segs:
            if s[0] == "M" and cur:
                groups.append(cur)
                cur = []
            cur.append(s)
        if cur:
            groups.append(cur)
        parts = []
        for g in groups:
            sub = geo.flatten(g)
            if not sub:
                continue
            pts, closed = sub[0]
            eff = closed or (explicit_fill and len(pts) >= 3 and geo.polygon_area(pts) > 1.0)
            parts.append((g, pts, eff))
        if parts and all(eff for _, _, eff in parts):
            allsegs = [s for g, _, _ in parts for s in g]
            self.outline_prim(el, "path", ctx, allsegs if len(parts) > 1 else parts[0][0], style)
            return
        # open subpaths are connector candidates, closed ones are shapes
        for g, pts, eff in parts:
            if eff:
                self.outline_prim(el, "path", ctx, g, style)
            else:
                self.line_prim(el, "path", ctx, pts, geo.has_curves(g), props, style)

    def line_prim(self, el, tag, ctx, pts, curved, props, style) -> None:
        pts = geo.dedupe_points(pts, 1e-3)
        if len(pts) < 2:
            return
        if curved and len(pts) > 3:
            pts = geo.simplify_polyline(pts, 0.75)
        if len(pts) > 200:
            pts = geo.simplify_polyline(pts, 1.5)[:200]
        self.new_prim("connector", el, tag, ctx, pts=pts, curved=curved, style=style,
                      start_arrow=self.marker_arrow(props, "marker-start"),
                      end_arrow=self.marker_arrow(props, "marker-end"))

    # ---------------------------------------------------------- images
    def image(self, el, props, m, opacity, ctx: _Ctx) -> None:
        h = _href(el)
        if not h:
            return
        mo = _IMG_RE.match(h)
        if not mo:
            if h.strip().lower().startswith("data:"):
                self.hit("image_type")          # other hrefs were counted by the pre-scan
            return
        kind = mo.group(1).lower()
        payload = re.sub(r"\s+", "", mo.group(2))
        if len(payload) + 30 > model.MAX_IMAGE:
            self.hit("image_big")
            return
        try:
            head = base64.b64decode(payload[:64] + "=" * (-len(payload[:64]) % 4))
        except (binascii.Error, ValueError):
            self.hit("image_type")
            return
        magic = _MAGIC.get(kind)
        if kind == "webp":
            ok = head[:4] == b"RIFF" and head[8:12] == b"WEBP"
        else:
            ok = magic is not None and head.startswith(magic)
        if not ok:
            self.hit("image_type")
            return
        x, y = _length(el.get("x")), _length(el.get("y"))
        w, hh = _length(el.get("width")), _length(el.get("height"))
        if w <= 0 or hh <= 0:
            return
        dec = geo.decompose(m)
        if dec is None:
            bb = geo.bbox_of_points(geo.apply_points(m, [(x, y), (x + w, y), (x + w, y + hh), (x, y + hh)]))
            X, Y, W, H, rot, conf = bb[0], bb[1], bb[2] - bb[0], bb[3] - bb[1], 0.0, 0.8
        else:
            cx, cy = geo.apply(m, x + w / 2.0, y + hh / 2.0)
            W, H = w * dec["sx"], hh * dec["sy"]
            X, Y, rot, conf = cx - W / 2.0, cy - H / 2.0, dec["rotation"], 1.0
            rot = 0.0 if abs(rot) < 0.01 else rot
        data = "data:image/%s;base64,%s" % (kind, payload)
        self.new_prim("image", el, "image", ctx, x=X, y=Y, w=W, h=H, rotation=rot, image=data,
                      style={"opacity": round(opacity, 3)}, confidence=conf)

    # ---------------------------------------------------------- text
    def text(self, el, props, m, opacity, ctx: _Ctx) -> None:
        font = self.font_of(props, 1.0)             # local size; scaled below
        runs: list = []

        def add(text, x, y, dx, dy):
            if text:
                runs.append((text, x, y, dx, dy))

        def first(v):
            if v is None:
                return None
            tok = re.split(r"[\s,]+", v.strip())[0] if v.strip() else ""
            mo = _LEN_RE.match(tok)
            return _length(tok, 0.0, fs=font["font_size"]) if mo else None

        def collect(node, inherit_props, top):
            np_ = self.props_of(node, _local(node.tag), inherit_props) if not top else inherit_props
            x, y = first(node.get("x")), first(node.get("y"))
            dx, dy = first(node.get("dx")) or 0.0, first(node.get("dy")) or 0.0
            add(node.text or "", x, y, dx, dy)
            for ch in node:
                if _local(ch.tag).lower() in ("tspan", "a") and _is_svg_ns(ch):
                    collect(ch, np_, False)
                add(ch.tail or "", None, None, 0.0, 0.0)

        collect(el, props, True)
        lines: list = []       # [text, x, y]
        cur_x = cur_y = 0.0
        for text, x, y, dx, dy in runs:
            new = False
            if not lines:
                cur_x = x if x is not None else 0.0
                cur_y = (y if y is not None else 0.0) + dy
                cur_x += dx
                lines.append([text, cur_x, cur_y])
                continue
            if y is not None and abs(y - cur_y) > 0.5:
                new, ny = True, y + dy
            elif dy and abs(dy) > 0.01:
                new, ny = True, cur_y + dy
            else:
                ny = cur_y
            if new:
                cur_y = ny
                cur_x = (x if x is not None else lines[0][1]) + dx
                lines.append([text, cur_x, cur_y])
            else:
                lines[-1][0] += text
        out = []
        for t, lx, ly in lines:
            t = re.sub(r"\s+", " ", t).strip()
            if t:
                out.append((t, lx, ly))
        if not out:
            return
        fs = font["font_size"]
        anchor = font["anchor"]
        rects = []
        for t, lx, ly in out:
            wid = len(t) * fs * 0.55
            x0 = lx - wid / 2.0 if anchor == "middle" else lx - wid if anchor == "end" else lx
            rects.append((x0, ly - fs * 0.85, x0 + wid, ly + fs * 0.25))
        lx0 = min(r[0] for r in rects)
        ly0 = min(r[1] for r in rects)
        lx1 = max(r[2] for r in rects)
        ly1 = max(r[3] for r in rects)
        dec = geo.decompose(m)
        if dec is not None:
            cx, cy = geo.apply(m, (lx0 + lx1) / 2.0, (ly0 + ly1) / 2.0)
            W, H = (lx1 - lx0) * dec["sx"], (ly1 - ly0) * dec["sy"]
            X, Y, rot = cx - W / 2.0, cy - H / 2.0, dec["rotation"]
            rot = 0.0 if abs(rot) < 0.01 else rot
        else:
            bb = geo.bbox_of_points(geo.apply_points(m, [(lx0, ly0), (lx1, ly0), (lx1, ly1), (lx0, ly1)]))
            X, Y, W, H, rot = bb[0], bb[1], bb[2] - bb[0], bb[3] - bb[1], 0.0
        scale = geo.mean_scale(m)
        font = dict(font, font_size=round(min(200.0, max(4.0, fs * scale)), 2))
        text = "\n".join(t for t, _, _ in out)[:MAX_TEXT_LEN]
        self.new_prim("text", el, "text", ctx, text=text, x=X, y=Y, w=max(W, 1.0), h=max(H, 1.0), rotation=rot,
                      font=font, opacity=round(opacity, 3), cx=X + W / 2.0, cy=Y + H / 2.0)


# ===================================================================== page size

def _root_geometry(root) -> tuple:
    """``(root matrix, width, height)``; width/height 0 when the file does not say.

    A SATOM export draws in the model's own coordinates and moves its viewBox to show
    content beyond the page (a negative origin); it names the page size in
    ``data-page-width`` / ``data-page-height``. Such a file is read in those
    coordinates, at that page size, so nothing shifts on re-import."""
    vb = [float(x) for x in _NUM_RE.findall(root.get("viewBox") or "")]
    if (root.get("data-schema") or "").startswith("satom.diagram/"):
        pw0 = _length(root.get("data-page-width"), 0.0)
        ph0 = _length(root.get("data-page-height"), 0.0)
        if pw0 > 0 and ph0 > 0:
            return geo.IDENTITY, pw0, ph0
    wpx = _length(root.get("width"), 0.0) if "%" not in (root.get("width") or "") else 0.0
    hpx = _length(root.get("height"), 0.0) if "%" not in (root.get("height") or "") else 0.0
    if len(vb) == 4 and vb[2] > 0 and vb[3] > 0:
        vx, vy, vw, vh = vb
        if wpx <= 0 and hpx <= 0:
            wpx, hpx = vw, vh
        elif wpx <= 0:
            wpx = hpx * vw / vh
        elif hpx <= 0:
            hpx = wpx * vh / vw
        s = min(wpx / vw, hpx / vh)                    # preserveAspectRatio meet, xMidYMid
        ox, oy = (wpx - vw * s) / 2.0, (hpx - vh * s) / 2.0
        return geo.multiply(geo.translate(ox, oy), geo.multiply(geo.scale(s), geo.translate(-vx, -vy))), wpx, hpx
    return geo.IDENTITY, wpx, hpx


# ===================================================================== assembly

def _build(rd: _Reader, root, w: Warnings, name: str) -> dict:
    m0, pw, ph = _root_geometry(root)
    pw, ph = min(pw, 100_000.0), min(ph, 100_000.0)
    props0 = rd.props_of(root, "svg", {})
    top = _Group("", "", None, None)
    ctx = _Ctx(m0, props0, min(1.0, max(0.0, _first_num(props0.get("opacity"), 1.0))), None, top, (), 0)
    rd.walk_children(root, ctx)

    prims = rd.prims
    shapes = [p for p in prims if p["kind"] == "shape"]
    conns = [p for p in prims if p["kind"] == "connector"]
    texts = [p for p in prims if p["kind"] == "text"]
    images = [p for p in prims if p["kind"] == "image"]

    # page size
    if pw <= 0 or ph <= 0:
        ext = geo.rect_union([(p["x"], p["y"], p["w"], p["h"]) for p in shapes + texts + images]
                             + [_bb_rect(p["pts"]) for p in conns])
        pw = max(100.0, (ext[0] + ext[2] + 20.0) if ext else 1600.0)
        ph = max(100.0, (ext[1] + ext[3] + 20.0) if ext else 1000.0)
    diag = math.hypot(pw, ph)

    # ---- shapes and images -> element dicts
    ids = iter("e%d" % i for i in range(1, 10 ** 7))
    out_el: dict = {}                 # prim id() -> element or connector dict
    elements: list = []
    for p in sorted(shapes + images, key=lambda q: q["order"]):
        e = _element_of(p, next(ids))
        elements.append(e)
        out_el[id(p)] = e
    cprims = sorted(conns, key=lambda q: q["order"])
    cdicts = [{"pts": c["pts"], "curved": c["curved"], "style": c["style"], "start_arrow": c["start_arrow"],
               "end_arrow": c["end_arrow"], "order": c["order"], "layer": c["layer"], "metadata": _meta(c),
               "source_ref": c["source_ref"], "key": c} for c in cprims]

    # ---- arrowheads: small filled triangles at a connector end
    heads = geo.extract_arrowheads(cdicts, elements, diag)
    if heads:
        gone = {id(h) for h in heads}
        elements = [e for e in elements if id(e) not in gone]
        w.once("arrowheads", "Merged %d small filled triangle(s) into connector arrowheads." % len(heads))

    # ---- texts: inside a shape -> its text; hugging a connector -> label; else a text element
    assigned, left = geo.assign_texts(elements, [dict(t, id=id(t)) for t in texts], pw * ph)
    by_id = {e["id"]: e for e in elements}
    for eid, ts in assigned.items():
        ts.sort(key=lambda q: (round(q["cy"] / 4.0), q["cx"]))
        e = by_id[eid]
        e["text"] = "\n".join(t["text"] for t in ts)[:model.MAX_TEXT]
        f = ts[0]["font"]
        e["style"].update({"font_color": f["font_color"], "font_size": f["font_size"], "font_family": f["font_family"],
                           "bold": f["bold"], "italic": f["italic"], "align": "center", "valign": "middle"})
        for t in ts:
            out_el[t["id"]] = e
    if assigned:
        w.once("text_in_shape", "Assigned %d text run(s) to the shape that contains them."
               % sum(len(v) for v in assigned.values()))
    labels, free_texts = geo.label_connectors(left, cdicts)
    for i, labs in labels.items():
        cdicts[i]["labels"] = labs
    if labels:
        w.once("labels", "Used %d short text(s) next to a line as connector labels."
               % sum(len(v) for v in labels.values()))
    for t in free_texts:
        e = _text_element(t, next(ids))
        out_el[t["id"]] = e
        elements.append(e)

    # ---- model limits
    elements.sort(key=lambda e: e["_order"])
    if len(elements) > model.MAX_ELEMENTS:
        w.add("The drawing has %d elements; only the first %d were kept." % (len(elements), model.MAX_ELEMENTS))
        elements = elements[:model.MAX_ELEMENTS]

    # ---- connectors
    connectors, dropped = geo.model_connectors(cdicts, elements, pw, ph, model.MAX_CONNECTORS)
    if dropped:
        w.add("The drawing has more than %d lines; the rest were dropped." % model.MAX_CONNECTORS)
    for c in connectors:
        out_el[id(c["_key"])] = c
    for i, labs in labels.items():
        for t, _ in labs:
            out_el[t["id"]] = connectors[i] if i < len(connectors) else None

    # ---- layers
    layers = [dict(l) for l in rd.layers]
    unlayered = any(not (e["layer"]) for e in elements) or any(not c["layer"] for c in connectors)
    if layers and unlayered:
        layers.insert(0, {"id": "L0", "name": "Default", "visible": True, "locked": False})
    for o in elements + connectors:
        o["layer"] = o["layer"] or (layers[0]["id"] if layers else "")

    # ---- groups: <g>/<use> with >= 2 drawn direct children; never the one wrapper of everything
    everything = {e["id"] for e in elements} | {c["id"] for c in connectors}
    groups = []
    for g in rd.groups:
        members, seen = [], set()
        for p in g.prims:
            o = out_el.get(id(p))
            if o is not None and o["id"] not in seen and o["id"] in everything:
                seen.add(o["id"])
                members.append(o["id"])
        if len(members) < 2 or set(members) == everything:
            continue
        groups.append({"id": "g%d" % (len(groups) + 1), "name": g.name[:100], "members": members,
                       "layer": g.layer or (layers[0]["id"] if layers else "")})
    gid_of = {}
    for g in rd.groups:
        for p in g.prims:
            o = out_el.get(id(p))
            if o is not None:
                gid_of.setdefault(o["id"], g)
    for o in elements + connectors:
        g = gid_of.get(o["id"])
        while g is not None and not g.svg_id:
            g = g.parent
        if g is not None and g.svg_id:
            o["metadata"]["svg_group"] = g.svg_id
    for o in elements + connectors:
        for k in ("_order", "_key", "poly", "filled"):
            o.pop(k, None)

    page = {"id": "page-1", "name": "Page 1", "width": round(pw, 3), "height": round(ph, 3), "background": "",
            "layers": layers, "groups": groups, "elements": elements, "connectors": connectors}
    return page


def _bb_rect(pts) -> tuple:
    bb = geo.bbox_of_points(pts)
    return (bb[0], bb[1], bb[2] - bb[0], bb[3] - bb[1])


def _meta(p: dict) -> dict:
    md = {}
    if p.get("svg_id"):
        md["svg_id"] = p["svg_id"]
    if p.get("svg_class"):
        md["svg_class"] = p["svg_class"]
    return md


def _element_of(p: dict, eid: str) -> dict:
    e = {"id": eid, "kind": "shape", "shape": p.get("shape", "rect"), "name": p.get("title", ""),
         "description": p.get("desc", ""), "text": "",
         "x": round(p["x"], 3), "y": round(p["y"], 3), "w": round(p["w"], 3), "h": round(p["h"], 3),
         "rotation": round(p.get("rotation", 0.0), 3), "layer": p["layer"] or "", "ports": [],
         "metadata": _meta(p), "source_ref": p["source_ref"], "confidence": p.get("confidence", 1.0),
         "_order": p["order"], "poly": p.get("poly"), "filled": p.get("filled", True)}
    if p["kind"] == "image":
        e["kind"] = "image"
        e["shape"] = "rect"
        e["image"] = p["image"]
        e["style"] = {"fill": "none", "stroke": "none", "stroke_width": 0, "opacity": p["style"]["opacity"]}
        return e
    st = dict(p["style"])
    e["style"] = st
    if e["shape"] == "polygon":
        e["points"] = p["rel"] if p.get("rel") else geo.normalise_points(p["poly"])
    elif e["shape"] == "path":
        e["path"] = p["path"]
    return e


def _text_element(t: dict, eid: str) -> dict:
    f = t["font"]
    return {"id": eid, "kind": "text", "shape": "rect", "text": t["text"], "x": round(t["x"], 3),
            "y": round(t["y"], 3), "w": round(t["w"], 3), "h": round(t["h"], 3),
            "rotation": round(t["rotation"], 3), "layer": t["layer"] or "", "ports": [],
            "style": {"fill": "none", "stroke": "none", "stroke_width": 0, "opacity": t["opacity"],
                      "font_color": f["font_color"], "font_size": f["font_size"], "font_family": f["font_family"],
                      "bold": f["bold"], "italic": f["italic"], "align": f["align"], "valign": "top"},
            "metadata": _meta(t), "source_ref": t["source_ref"], "confidence": 1.0, "_order": t["order"]}


def _report(rd: _Reader, w: Warnings) -> None:
    unsup = []
    for k, n in rd.counts.items():
        if k.startswith("unsupported:"):
            unsup.append("<%s> x%d" % (k.split(":", 1)[1], n))
            continue
        msg = _MESSAGES.get(k)
        if not msg:
            continue
        if k in ("image_big",):
            w.once(k, msg % (n, model.MAX_IMAGE // 1024))
        elif k in ("use_depth", "depth"):
            w.once(k, msg % (n, MAX_USE_DEPTH if k == "use_depth" else MAX_DEPTH))
        else:
            w.once(k, msg % n)
    if unsup:
        w.once("unsupported", "Ignored unsupported element(s): %s." % ", ".join(sorted(unsup)[:12]))


def _parse(data: bytes):
    try:
        root = xmlsafe.parse_xml(data)
    except xmlsafe.UnsafeInput as exc:
        if str(exc).startswith("not well-formed"):
            raise ImportFailed("This is not a valid SVG file (%s)." % str(exc)[:160]) from None
        raise
    if _local(root.tag).lower() != "svg":
        raise ImportFailed("This XML file is not an SVG (root element <%s>)." % _local(root.tag)[:40])
    return root


MAX_EMBEDDED_BYTES = 32 * 1024 * 1024


def _embedded_model(root, data: bytes, filename: str, w: Warnings):
    """The document SATOM embedded in ``<metadata id="satom-diagram">``, or ``None``.

    The JSON is untrusted: size-capped, schema-checked and passed through
    ``model.normalise`` and nothing else. It is used only when the visible SVG
    still agrees with it (one ``ds-el`` group per element of the exported
    page); otherwise the SVG was edited outside SATOM, a warning is added and
    the DOM is read instead.
    """
    meta = None
    for ch in root:
        if _local(ch.tag).lower() == "metadata" and ch.get("id") == "satom-diagram":
            meta = ch
            break
    if meta is None:
        return None
    text = "".join(meta.itertext()).strip()
    if not text:
        return None
    if len(text) > MAX_EMBEDDED_BYTES:
        w.add("The embedded SATOM model is larger than %d MiB; the drawing was read from the SVG instead."
              % (MAX_EMBEDDED_BYTES // 1048576))
        return None
    try:
        raw = json.loads(text)
        if not isinstance(raw, dict) or raw.get("schema") != model.SCHEMA:
            raise ValueError("schema")
        doc, _ = model.normalise(raw)
    except (ValueError, RecursionError, TypeError, MemoryError):    # JSONDecodeError and ModelError are ValueErrors
        w.add("The embedded SATOM model is not a valid satom.diagram/1 document; "
              "the drawing was read from the SVG instead.")
        return None
    want = meta.get("data-page") or root.get("data-page-id") or ""
    pages = [p for p in doc["pages"] if p["id"] == want] or (doc["pages"] if len(doc["pages"]) == 1 else [])
    if len(pages) != 1:
        w.add("The embedded SATOM model does not match this SVG's page; the drawing was read from the SVG instead.")
        return None
    shown = sum(1 for el in root.iter() if _local(el.tag).lower() == "g" and "ds-el" in (el.get("class") or "").split())
    if shown != len(pages[0]["elements"]):
        w.add("The SVG was edited outside SATOM (%d drawn elements, %d in the embedded model); "
              "the drawing was read from the SVG instead." % (shown, len(pages[0]["elements"])))
        return None
    return doc, pages[0]


@guarded
def read(data: bytes, *, filename: str = "", page: str | None = None) -> dict:
    data = require_bytes(data)
    root = _parse(data)
    w = Warnings()
    emb = _embedded_model(root, data, filename, w)
    if emb is not None:
        doc, pg = emb
        w.add("Restored the exact diagram from the model embedded by SATOM.")
        return make_document(fmt="svg", engine=ENGINE, data=data, filename=filename,
                             name=doc["name"] or doc_name(filename, "SVG drawing"), pages=[pg],
                             warnings=w.items, page=None,
                             metadata=dict(doc.get("metadata") or {}, satom_export=True))
    rd = _Reader(root)
    rd.prescan()
    title = ""
    for ch in root:
        if _local(ch.tag).lower() == "title":
            title = "".join(ch.itertext()).strip()[:100]
            break
    name = doc_name(filename, title or "SVG drawing")
    pg = _build(rd, root, w, name)
    if title:
        pg["name"] = title
    _report(rd, w)
    # dropped items first: they matter most to the operator
    w.items.sort(key=lambda s: 0 if s.startswith(("Removed", "Skipped", "Dropped")) else 1)
    return make_document(fmt="svg", engine=ENGINE, data=data, filename=filename, name=name,
                         pages=[pg], warnings=w.items, page=None)


@guarded
def list_pages(data: bytes) -> list:
    _parse(require_bytes(data))
    return [{"id": "page-1", "name": "Page 1"}]
