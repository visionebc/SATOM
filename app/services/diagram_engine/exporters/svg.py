"""Structured, editable SVG 1.1 writer: ``satom.diagram/1`` -> one page as SVG.

Layers are ``<g inkscape:groupmode="layer">`` groups, every element is a
``<g class="ds-el">`` holding plain SVG primitives and real ``<text>``;
connectors are ``<path>`` with ``<marker>`` arrowheads. The full normalised
model is embedded in ``<metadata id="satom-diagram">`` as JSON so a re-import
of a SATOM-exported SVG is exact; everything else is for humans, Inkscape,
Illustrator and browsers.

Safe by construction: the file is built from fixed templates, every attribute
and text node is escaped, colours are ``#RRGGBB``/``none``, numbers are
formatted here, images are only ``data:image/*`` URIs inside their element.
There is no script, no event attribute and no external reference.
"""
from __future__ import annotations

import json
import math
import re

from .. import model
from . import _common as C

MIME = "image/svg+xml"
NS = "http://www.w3.org/2000/svg"
DEFAULT_FONT = "Helvetica, Arial, sans-serif"
PROP_KEY = re.compile(r"[^A-Za-z0-9_-]")


def _n(v) -> str:
    f = round(float(v), 2)
    return "%d" % f if f == int(f) else repr(f)


def _attrs(**kw) -> str:
    out = []
    for k, v in kw.items():
        if v is None or v is False or v == "":
            continue
        out.append(' %s="%s"' % (k.replace("_", "-") if not k.startswith("x_") else k[2:].replace("_", ":"), C.esc(v)))
    return "".join(out)


def _data_attrs(prefix: str, mp: dict, used: set) -> str:
    out = []
    for k, v in mp.items():
        key = PROP_KEY.sub("-", str(k)).strip("-").lower()[:48]
        if not key:
            continue
        name, i = "data-%s-%s" % (prefix, key), 1
        while name in used:
            i += 1
            name = "data-%s-%s%d" % (prefix, key, i)
        used.add(name)
        out.append(' %s="%s"' % (name, C.esc("true" if v is True else "false" if v is False else v)))
    return "".join(out)


def _font_family(st: dict) -> str:
    fam = st.get("font_family") or ""
    return fam if fam and model.FONT_RE.match(fam) else DEFAULT_FONT


def _measure(fs: float, bold: bool):
    k = 0.58 if bold else 0.54
    return lambda s: len(s) * fs * k


class _Markers:
    def __init__(self):
        self.defs: dict[str, str] = {}

    def ref(self, kind: str, colour: str, start: bool) -> str:
        if kind == "none" or kind not in C.ARROW_GLYPHS:
            return ""
        mid = "ds-mk-%s-%s-%s" % (kind, "s" if start else "e", colour.lstrip("#") if colour != "none" else "none")
        if mid not in self.defs:
            stroke = colour if colour != "none" else "#1F2937"
            body = []
            for g in C.ARROW_GLYPHS[kind]:
                fill = stroke if g["fill"] == "stroke" else "#FFFFFF" if g["fill"] == "white" else "none"
                common = 'fill="%s" stroke="%s" stroke-width="1.2" stroke-linejoin="miter"' % (fill, stroke)
                if g["t"] == "poly":
                    body.append('<polygon points="%s" %s/>' % (" ".join("%s,%s" % (_n(x), _n(y)) for x, y in g["pts"]), common))
                elif g["t"] == "line":
                    body.append('<polyline points="%s" %s/>' % (" ".join("%s,%s" % (_n(x), _n(y)) for x, y in g["pts"]), common))
                else:
                    body.append('<circle cx="%s" cy="%s" r="%s" %s/>' % (_n(g["c"][0]), _n(g["c"][1]), _n(g["r"]), common))
            inner = "".join(body)
            if start:
                inner = '<g transform="scale(-1,1)">%s</g>' % inner
                vb = "-2 -8 18 16"
            else:
                vb = "-16 -8 18 16"
            self.defs[mid] = ('<marker id="%s" viewBox="%s" markerWidth="18" markerHeight="16" refX="0" refY="0" '
                              'markerUnits="userSpaceOnUse" orient="auto" overflow="visible">%s</marker>' % (mid, vb, inner))
        return "url(#%s)" % mid


class _Paints:
    """Gradients and drop-shadow filters of one document: one ``<defs>`` entry
    per distinct paint, ids unique in the file (never equal to a model id) and
    only ever referenced as ``url(#id)`` -- no external reference."""

    def __init__(self, taken: set):
        self.taken = set(taken)
        self.defs: dict = {}            # key -> (id, markup)
        self.n = 0

    def _id(self, prefix: str) -> str:
        while True:
            self.n += 1
            i = "ds-%s-%d" % (prefix, self.n)
            if i not in self.taken:
                self.taken.add(i)
                return i

    def gradient(self, st: dict) -> str:
        g = C.gradient_of(st)
        if g is None:
            return ""
        typ, colour, angle = g
        key = ("g", typ, st["fill"].upper(), colour, angle if typ == "linear" else 0)
        if key not in self.defs:
            gid = self._id("grad")
            stops = '<stop offset="0" stop-color="%s"/><stop offset="1" stop-color="%s"/>' % (st["fill"].upper(), colour)
            if typ == "radial":
                body = '<radialGradient id="%s" cx="0.5" cy="0.5" r="0.5" fx="0.5" fy="0.5">%s</radialGradient>' % (gid, stops)
            else:
                x1, y1, x2, y2 = C.gradient_vector(angle)
                body = ('<linearGradient id="%s" x1="%s" y1="%s" x2="%s" y2="%s" data-angle="%d">%s</linearGradient>'
                        % (gid, _n(x1), _n(y1), _n(x2), _n(y2), angle, stops))
            self.defs[key] = (gid, body)
        return "url(#%s)" % self.defs[key][0]

    def shadow(self, colour: str, page_box=None) -> str:
        """``page_box`` (x, y, w, h): a filter region in user space (connectors,
        whose box can be zero-height); otherwise a margin around the shape's box."""
        colour = colour if C.is_hex(colour) else "#000000"
        key = ("s", colour.upper(), page_box)
        if key not in self.defs:
            fid = self._id("shadow")
            if page_box:
                region = 'filterUnits="userSpaceOnUse" x="%s" y="%s" width="%s" height="%s"' % tuple(_n(v) for v in page_box)
            else:
                region = 'x="-0.5" y="-0.5" width="2" height="2"'
            body = ('<filter id="%s" %s color-interpolation-filters="sRGB"><feDropShadow dx="%s" dy="%s" '
                    'stdDeviation="%s" flood-color="%s" flood-opacity="%s"/></filter>'
                    % (fid, region, _n(C.SHADOW_DX), _n(C.SHADOW_DY), _n(C.SHADOW_BLUR), colour.upper(), _n(C.SHADOW_ALPHA)))
            self.defs[key] = (fid, body)
        return "url(#%s)" % self.defs[key][0]

    def markup(self) -> list:
        return [v[1] for v in self.defs.values()]


def _effects(st: dict, paints: "_Paints") -> tuple[str, str, str]:
    """``(fill paint, attributes of filled primitives, attributes of stroke-only ones)``."""
    fill = paints.gradient(st) or C.paint(st["fill"], "#FFFFFF")
    filled, lines = "", ""
    if st.get("fill_opacity", 1) < 1:
        filled += ' fill-opacity="%s"' % _n(st["fill_opacity"])
    if st.get("stroke_opacity", 1) < 1:
        so = ' stroke-opacity="%s"' % _n(st["stroke_opacity"])
        filled += so
        lines += so
    if st.get("shadow") and st["fill"] != "none":
        filled += ' filter="%s"' % paints.shadow(st.get("shadow_color") or "#000000")
    return fill, filled, lines


def _prim(p: dict, st: dict, w: float, h: float, fx=None) -> str:
    fill_default = C.paint(st["fill"], "#FFFFFF")
    stroke = C.paint(st["stroke"], "#1F2937")
    filled = p.get("fill", True)
    extra = ""
    if fx is not None:                   # (fill paint, filled attrs, stroke-only attrs)
        fill_default = fx[0]
        extra = fx[1] if (filled and p["t"] != "line") else fx[2]
    f = fill_default if filled else "none"
    if p.get("stroke") is False:
        stroke = "none"
    t = p["t"]
    common = ' fill="%s" stroke="%s"%s' % (f, stroke, extra)
    if t == "rect":
        rx = p.get("rx", 0)
        return '<rect x="0" y="0" width="%s" height="%s"%s%s/>' % (_n(w), _n(h), (' rx="%s"' % _n(rx)) if rx else "", common)
    if t == "ellipse":
        return '<ellipse cx="%s" cy="%s" rx="%s" ry="%s"%s/>' % (_n(p["cx"]), _n(p["cy"]), _n(p["rx"]), _n(p["ry"]), common)
    if t == "poly":
        return '<polygon points="%s"%s/>' % (" ".join("%s,%s" % (_n(x), _n(y)) for x, y in p["pts"]), common)
    if t == "line":
        return '<polyline points="%s" fill="none" stroke="%s"%s/>' % (" ".join("%s,%s" % (_n(x), _n(y)) for x, y in p["pts"]), stroke,
                                                                      fx[2] if fx is not None else "")
    if t == "path":
        return '<path d="%s"%s/>' % (C.esc(p["d"]), common)
    return ""


def _text_el(b: dict, el: dict) -> str:
    st = el["style"]
    fs = st["font_size"]
    bold = bool(b["bold"])
    lines = C.wrap_lines(b["text"], b["w"], _measure(fs, bold))
    if not lines:
        return ""
    lh = fs * 1.2
    total = lh * len(lines)
    align = b["align"]
    if align == "left":
        x, anchor = b["x"], "start"
    elif align == "right":
        x, anchor = b["x"] + b["w"], "end"
    else:
        x, anchor = b["x"] + b["w"] / 2, "middle"
    if b["valign"] == "top":
        y0 = b["y"]
    elif b["valign"] == "bottom":
        y0 = b["y"] + b["h"] - total
    else:
        y0 = b["y"] + (b["h"] - total) / 2
    y0 += fs * 0.95
    tspans = "".join('<tspan x="%s" y="%s">%s</tspan>' % (_n(x), _n(y0 + i * lh), C.esc_text(ln)) for i, ln in enumerate(lines))
    halo = ' stroke="#FFFFFF" stroke-width="3" paint-order="stroke"' if b.get("below") else ""
    return ('<text font-family="%s" font-size="%s" font-weight="%s" font-style="%s" text-anchor="%s" fill="%s"%s '
            'xml:space="preserve">%s</text>' % (C.esc(_font_family(st)), _n(fs), "bold" if bold else "normal",
                                               "italic" if st["italic"] else "normal", anchor,
                                               C.paint(st["font_color"], "#111827"), halo, tspans))


def _symbol_def(ic: dict) -> str:
    """``<symbol>`` built from the sanitised icon: root presentation attributes move onto it."""
    attrs = "".join(' %s="%s"' % (k, C.esc(v)) for k, v in ic["root"].items() if k != "xmlns")
    vb = " ".join(_n(v) for v in ic["vb"])
    return '<symbol id="%s" viewBox="%s"%s>%s</symbol>' % (ic["id"], vb, attrs, ic["inner"])


def _image_ok(img: str) -> bool:
    return bool(img) and model.IMAGE_RE.match(img) is not None


def _element(e: dict, member_of: dict, icons: C.Icons, syms: dict, paints: "_Paints") -> str:
    st = e["style"]
    attrs = {"id": e["id"], "class": "ds-el ds-%s" % e["shape"], "data_kind": e["kind"], "data_shape": e["shape"],
             "data_category": e["category"], "data_symbol": e["symbol"], "data_name": e["name"],
             "data_parent": e["parent"], "data_group": ",".join(member_of.get(e["id"], []))}
    if e["rotation"]:
        attrs["transform"] = "rotate(%s %s %s)" % (_n(e["rotation"]), _n(e["x"] + e["w"] / 2), _n(e["y"] + e["h"] / 2))
    used: set = set()
    extra = _data_attrs("prop", e["properties"], used) + _data_attrs("meta", e["metadata"], used)
    body = []
    if e["name"] or e["description"]:
        body.append("<title>%s</title>" % C.esc_text(e["name"] or e["description"][:80]))
    if e["description"]:
        body.append("<desc>%s</desc>" % C.esc_text(e["description"]))
    inner = []
    sty = [' stroke-width="%s"' % _n(st["stroke_width"])]
    dashes = C.dash_array(st)
    if dashes:
        sty.append(' stroke-dasharray="%s"' % " ".join(_n(v) for v in dashes))
    if st["opacity"] < 1:
        sty.append(' opacity="%s"' % _n(st["opacity"]))
    inner.append('<g transform="translate(%s %s)"%s stroke-linejoin="round">' % (_n(e["x"]), _n(e["y"]), "".join(sty)))
    if e["kind"] == "image" or (e["shape"] == "symbol" and e.get("image")):
        if _image_ok(e["image"]):
            inner.append('<image x="0" y="0" width="%s" height="%s" preserveAspectRatio="none" xlink:href="%s"/>'
                         % (_n(e["w"]), _n(e["h"]), C.esc(e["image"])))
        else:
            inner.append(_prim({"t": "rect", "rx": 0.0}, st, e["w"], e["h"]))
    else:
        fx = _effects(st, paints)
        for p in C.outline(e):
            inner.append(_prim(p, st, e["w"], e["h"], fx))
    ic = icons.get(e["symbol"]) if C.icon_box(e) else None
    if ic:
        x, y, size, _big = C.icon_box(e)
        k = size / max(ic["vb"][2], ic["vb"][3])
        syms.setdefault(ic["id"], _symbol_def(ic))
        colour = C.paint(st["stroke"], "#1F2937")
        colour = colour if colour != "none" else "#1F2937"
        inner.append('<g class="ds-icon" transform="translate(%s %s)" color="%s" stroke-dasharray="none">'
                     '<g transform="scale(%s) translate(%s %s)"><use href="#%s" xlink:href="#%s" x="0" y="0" width="%s" height="%s"/></g></g>'
                     % (_n(x), _n(y), colour, repr(round(k, 5)), _n(-ic["vb"][0]), _n(-ic["vb"][1]), ic["id"], ic["id"],
                        _n(ic["vb"][2]), _n(ic["vb"][3])))
    for b in C.text_blocks(e):
        inner.append(_text_el(b, e))
    inner.append("</g>")
    return "<g%s%s>%s%s</g>" % (_attrs(**attrs), extra, "".join(body), "".join(inner))


def _connector(c: dict, by_id: dict, mk: _Markers, member_of: dict, paints: "_Paints") -> str:
    st = c["style"]
    stroke = C.paint(st["stroke"], "#1F2937")
    segs, poly = C.route_segments(c, by_id)
    d = " ".join("%s%s" % (s[0], " ".join(_n(v) for v in s[1:])) for s in segs)
    flat = C.flatten(segs)
    attrs = {"id": c["id"], "class": "ds-conn", "data_source": c["source"], "data_target": c["target"],
             "data_source_port": c["source_port"], "data_target_port": c["target_port"], "data_kind": c["kind"],
             "data_routing": c["routing"], "data_start_arrow": c["start_arrow"], "data_end_arrow": c["end_arrow"],
             "data_group": ",".join(member_of.get(c["id"], []))}
    used: set = set()
    extra = _data_attrs("prop", c["properties"], used) + _data_attrs("meta", c["metadata"], used)
    path = ['<path d="%s" fill="none" stroke="%s" stroke-width="%s"' % (C.esc(d), stroke, _n(st["stroke_width"]))]
    dashes = C.dash_array(st)
    if dashes:
        path.append(' stroke-dasharray="%s"' % " ".join(_n(v) for v in dashes))
    if st["opacity"] < 1:
        path.append(' opacity="%s"' % _n(st["opacity"]))
    if st.get("stroke_opacity", 1) < 1:
        path.append(' stroke-opacity="%s"' % _n(st["stroke_opacity"]))
    if st.get("shadow"):
        # the box of a straight line has no height: the filter region is the line's box in user space
        xs, ys = [p[0] for p in flat], [p[1] for p in flat]
        m = 20.0 + st["stroke_width"]
        box = (math.floor(min(xs) - m), math.floor(min(ys) - m),
               math.ceil(max(xs) - min(xs) + 2 * m), math.ceil(max(ys) - min(ys) + 2 * m))
        path.append(' filter="%s"' % paints.shadow(st.get("shadow_color") or "#000000", box))
    ms, me = mk.ref(c["start_arrow"], stroke, True), mk.ref(c["end_arrow"], stroke, False)
    if ms:
        path.append(' marker-start="%s"' % ms)
    if me:
        path.append(' marker-end="%s"' % me)
    path.append("/>")
    labels = []
    texts = []
    if c["label"]:
        texts.append((c["label"], 0.5))
    texts += [(lb["text"], lb["pos"]) for lb in c["labels"]]
    fs = 11.0
    for text, pos in texts:
        x, y = C.point_along(flat, pos)
        labels.append('<text x="%s" y="%s" font-family="%s" font-size="%s" text-anchor="middle" fill="%s" stroke="#FFFFFF" '
                      'stroke-width="3" paint-order="stroke" xml:space="preserve" class="ds-conn-label" data-pos="%s">%s</text>'
                      % (_n(x), _n(y - 4), DEFAULT_FONT, _n(fs), C.paint(st["font_color"], "#111827"), _n(pos), C.esc_text(text)))
    return "<g%s%s>%s%s</g>" % (_attrs(**attrs), extra, "".join(path), "".join(labels))


def export(doc, *, page=None, options=None) -> tuple[bytes, str, str]:
    options = options or {}
    d = C.prepare(doc)
    if page == "all":
        raise C.ExportFailed("an SVG file holds one page; choose a page")
    pages = C.select_pages(d, page if page is not None else 0)
    pg = pages[0]
    by_id = {e["id"]: e for e in pg["elements"]}
    member_of: dict = {}
    for g in pg["groups"]:
        for m in g["members"]:
            member_of.setdefault(m, []).append(g["id"])
    mk = _Markers()
    icons = C.Icons(options)
    syms: dict = {}
    taken = {e["id"] for e in pg["elements"]} | {c["id"] for c in pg["connectors"]} | \
        {"layer-" + lr["id"] for lr in pg["layers"]} | {"satom-diagram", "ds-background"}
    paints = _Paints(taken)
    layers_xml = []
    for lr in pg["layers"]:
        els = [e for e in pg["elements"] if e["layer"] == lr["id"]]
        cons = [c for c in pg["connectors"] if c["layer"] == lr["id"]]
        a = {"id": "layer-" + lr["id"], "x_inkscape_groupmode": "layer", "x_inkscape_label": lr["name"],
             "data_layer_name": lr["name"], "data_layer_id": lr["id"],
             "data_visible": "true" if lr["visible"] else "false", "data_locked": "true" if lr["locked"] else "false",
             "style": None if lr["visible"] else "display:none", "x_sodipodi_insensitive": "true" if lr["locked"] else None}
        parts = ([_element(e, member_of, icons, syms, paints) for e in els]
                 + [_connector(c, by_id, mk, member_of, paints) for c in cons])
        layers_xml.append("<g%s>%s</g>" % (_attrs(**a), "".join(parts)))
    # the picture: the page, grown to whatever is drawn beyond it (negative x/y, past the
    # right or bottom edge); the model's coordinates stay as they are, the viewBox moves
    bx, by, w, h = C.export_box(pg, _measure, visible_only=True)
    head = ['<?xml version="1.0" encoding="UTF-8"?>\n',
            '<svg xmlns="%s" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape" '
            'xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd" version="1.1" viewBox="%s %s %s %s" width="%s" '
            'height="%s" data-schema="%s" data-page-id="%s" data-page-name="%s" data-page-width="%s" data-page-height="%s">\n' % (
                NS, _n(bx), _n(by), _n(w), _n(h), _n(w), _n(h), model.SCHEMA, C.esc(pg["id"]), C.esc(pg["name"]),
                _n(pg["width"]), _n(pg["height"])),
            "<title>%s</title>\n" % C.esc_text(d["name"] if len(d["pages"]) == 1 else "%s - %s" % (d["name"], pg["name"]))]
    if options.get("embed_model", True):
        blob = json.dumps(d, ensure_ascii=True, separators=(",", ":"))
        head.append('<metadata id="satom-diagram" data-page="%s">%s</metadata>\n' % (C.esc(pg["id"]), C.esc_text(blob)))
    head.append("<defs>%s</defs>\n" % "".join(list(mk.defs.values()) + paints.markup() + list(syms.values())))
    if pg["background"]:
        head.append('<rect id="ds-background" x="%s" y="%s" width="%s" height="%s" fill="%s"/>\n'
                    % (_n(bx), _n(by), _n(w), _n(h), C.paint(pg["background"], "none")))
    out = "".join(head) + "\n".join(layers_xml) + "\n</svg>\n"
    suffix = pg["name"] if len(d["pages"]) > 1 else ""
    return out.encode("utf-8"), MIME, C.slug_filename(d["name"], "svg", suffix)
