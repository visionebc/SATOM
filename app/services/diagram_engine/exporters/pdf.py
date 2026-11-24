"""Vector PDF writer (reportlab, imported lazily).

One PDF page per diagram page, sized to the diagram (1 px = 0.75 pt) or, with
``options["paper"]`` (``A4``/``A3``/``Letter``), fitted into that sheet.
Shapes are vector paths, text is real text, connectors carry arrowheads and
images are drawn from their data URIs. Layers: reportlab has no optional
content groups, so hidden layers are simply not drawn (only visible layers
are exported) -- stated in the file's subject.
"""
from __future__ import annotations

import base64
import io
import math
import os
import re
import unicodedata

from .. import geometry, model
from . import _common as C

MIME = "application/pdf"
PX = 0.75                       # CSS px -> PDF pt
MAX_PT = 14400.0                # PDF 1.4 page limit
PAPERS = {"A4": (595.2756, 841.8898), "A3": (841.8898, 1190.5512), "Letter": (612.0, 792.0)}
FONT_CANDIDATES = ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans.ttf",
                   "/usr/share/fonts/TTF/DejaVuSans.ttf")
_font_cache: dict = {}


def _rgb(c: str, default=(0.0, 0.0, 0.0)):
    if isinstance(c, str) and re.fullmatch(r"#[0-9A-Fa-f]{6}", c):
        return tuple(int(c[i:i + 2], 16) / 255 for i in (1, 3, 5))
    return default


def _fonts(canvas_mod, pdfmetrics, option_font: str | None):
    """(regular, bold, italic, bold-italic, unicode?) font names."""
    key = option_font or ""
    if key in _font_cache:
        return _font_cache[key]
    res = ("Helvetica", "Helvetica-Bold", "Helvetica-Oblique", "Helvetica-BoldOblique", False)
    if option_font and option_font in pdfmetrics.getRegisteredFontNames():
        res = (option_font,) * 4 + (True,)
    else:
        for path in FONT_CANDIDATES:
            if os.path.exists(path):
                try:
                    from reportlab.pdfbase.ttfonts import TTFont
                    pdfmetrics.registerFont(TTFont("DSDejaVu", path))
                    res = ("DSDejaVu",) * 4 + (True,)
                except Exception:
                    pass
                break
    _font_cache[key] = res
    return res


def _latin(s: str) -> str:
    """Make text safe for the standard (WinAnsi) fonts: keep Latin-1, transliterate the rest."""
    out = []
    for ch in s:
        if ord(ch) < 256:
            out.append(ch)
        else:
            t = unicodedata.normalize("NFKD", ch).encode("ascii", "ignore").decode("ascii")
            out.append(t or "?")
    return "".join(out)


def _page_size(pg: dict, options: dict, box=None):
    """``(page w, page h, scale, ox, oy)`` in points for the picture ``box`` (x, y, w, h px):
    the page grown to what is drawn beyond it (``C.export_box``)."""
    box = box or (0.0, 0.0, pg["width"], pg["height"])
    w, h = box[2] * PX, box[3] * PX
    paper = options.get("paper")
    if paper:
        if paper not in PAPERS:
            raise C.ExportFailed("unknown paper %r (use A4, A3 or Letter)" % str(paper)[:20])
        pw, ph = PAPERS[paper]
        orient = options.get("orientation", "auto")
        if orient == "auto":
            orient = "landscape" if w >= h else "portrait"
        if orient not in ("landscape", "portrait"):
            raise C.ExportFailed("orientation must be landscape, portrait or auto")
        if orient == "landscape":
            pw, ph = max(pw, ph), min(pw, ph)
        else:
            pw, ph = min(pw, ph), max(pw, ph)
        margin = 24.0
        s = min((pw - 2 * margin) / w, (ph - 2 * margin) / h)
        return pw, ph, s, (pw - w * s) / 2, (ph - h * s) / 2
    s = min(1.0, MAX_PT / max(w, h))
    return w * s, h * s, s, 0.0, 0.0


def export(doc, *, page=None, options=None) -> tuple[bytes, str, str]:
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfgen import canvas
    except ImportError as exc:                              # pragma: no cover
        raise C.ExportFailed("PDF export needs the reportlab package") from exc
    options = options or {}
    d = C.prepare(doc)
    pages = C.select_pages(d, page)
    f_reg, f_bold, f_it, f_bi, uni = _fonts(canvas, pdfmetrics, options.get("font"))
    buf = io.BytesIO()
    cv = canvas.Canvas(buf, invariant=1, pageCompression=1)
    cv.setTitle(C.xml_clean(d["name"])[:200])
    cv.setCreator("SATOM Diagram Studio")
    cv.setSubject("Visible layers only")
    skipped_images = 0
    icons = C.Icons(options)
    for pg in pages:
        box = C.export_box(pg, visible_only=True)       # hidden layers are not drawn
        pw, ph, s, ox, oy = _page_size(pg, options, box)
        cv.setPageSize((pw, ph))
        # Model space: x right, y DOWN, px. Map into PDF points with y up; the box's
        # origin (negative when content sits above or left of the page) maps to the corner.
        cv.saveState()
        cv.translate(ox, ph - oy)
        cv.scale(s * PX, -s * PX)
        cv.translate(-box[0], -box[1])
        if pg["background"]:
            cv.setFillColorRGB(*_rgb(pg["background"], (1, 1, 1)))
            cv.rect(box[0], box[1], box[2], box[3], stroke=0, fill=1)
        visible = {lr["id"] for lr in pg["layers"] if lr["visible"]}
        by_id = {e["id"]: e for e in pg["elements"]}
        for lr in pg["layers"]:
            if lr["id"] not in visible:
                continue
            for e in pg["elements"]:
                if e["layer"] == lr["id"]:
                    skipped_images += _draw_element(cv, e, (f_reg, f_bold, f_it, f_bi), uni, icons)
            for c in pg["connectors"]:
                if c["layer"] == lr["id"]:
                    _draw_connector(cv, c, by_id, (f_reg, f_bold, f_it, f_bi), uni)
        cv.restoreState()
        cv.showPage()
    cv.save()
    suffix = pages[0]["name"] if len(pages) == 1 and len(d["pages"]) > 1 else ""
    return buf.getvalue(), MIME, C.slug_filename(d["name"], "pdf", suffix)


def _font_for(fonts, bold, italic):
    return fonts[3] if bold and italic else fonts[1] if bold else fonts[2] if italic else fonts[0]


def _path(cv, segs):
    p = cv.beginPath()
    cx = cy = sx = sy = 0.0
    for s in segs:
        t = s[0]
        if t == "M":
            p.moveTo(s[1], s[2])
            cx, cy = sx, sy = s[1], s[2]
        elif t == "L":
            p.lineTo(s[1], s[2])
            cx, cy = s[1], s[2]
        elif t == "C":
            p.curveTo(*s[1:])
            cx, cy = s[5], s[6]
        elif t == "Q":
            c1x, c1y = cx + 2 / 3 * (s[1] - cx), cy + 2 / 3 * (s[2] - cy)
            c2x, c2y = s[3] + 2 / 3 * (s[1] - s[3]), s[4] + 2 / 3 * (s[2] - s[4])
            p.curveTo(c1x, c1y, c2x, c2y, s[3], s[4])
            cx, cy = s[3], s[4]
        elif t == "A":
            for seg in C.arc_to_beziers(cx, cy, s[1], s[2], s[3], s[4], s[5], s[6], s[7]):
                p.curveTo(*seg)
            cx, cy = s[6], s[7]
        elif t == "Z":
            p.close()
            cx, cy = sx, sy
    return p


def _apply_stroke(cv, st: dict):
    cv.setLineWidth(max(0.0, st["stroke_width"]))
    cv.setLineJoin(1)
    cv.setDash(C.dash_array(st) or [])
    if st["opacity"] < 1:
        cv.setStrokeAlpha(st["opacity"])
        cv.setFillAlpha(st["opacity"])


def _draw_element(cv, e: dict, fonts, uni: bool, icons=None) -> int:
    st = e["style"]
    cv.saveState()
    if e["rotation"]:
        cx, cy = e["x"] + e["w"] / 2, e["y"] + e["h"] / 2
        cv.translate(cx, cy)
        cv.rotate(e["rotation"])          # y axis is flipped, so this is clockwise on the page
        cv.translate(-cx, -cy)
    cv.translate(e["x"], e["y"])
    _apply_stroke(cv, st)
    fill, stroke = st["fill"], st["stroke"]
    missed = 0
    if e["kind"] == "image" or (e["shape"] == "symbol" and e.get("image")):
        ok = False
        m = re.match(r"^data:image/(?:png|jpeg|gif|webp);base64,([A-Za-z0-9+/=]+)$", e.get("image") or "")
        if m:
            try:
                from reportlab.lib.utils import ImageReader
                img = ImageReader(io.BytesIO(base64.b64decode(m.group(1))))
                cv.saveState()
                cv.translate(0, e["h"])
                cv.scale(1, -1)
                cv.drawImage(img, 0, 0, e["w"], e["h"], mask="auto", preserveAspectRatio=False)
                cv.restoreState()
                ok = True
            except Exception:
                ok = False
        if not ok:
            missed = 1
            cv.setStrokeColorRGB(*_rgb(stroke, (0.1, 0.1, 0.1)))
            cv.rect(0, 0, e["w"], e["h"], stroke=1, fill=0)
    else:
        _draw_outline(cv, e, st)
    ic = icons.get(e["symbol"]) if (icons is not None and C.icon_box(e)) else None
    if ic:
        x, y, size, _big = C.icon_box(e)
        _draw_icon(cv, ic, x, y, size, e)
    for b in C.text_blocks(e):
        _draw_text(cv, b, st, fonts, uni)
    cv.restoreState()
    return missed


def _prim_path(cv, p: dict, e: dict):
    """A reportlab path of one outline primitive (local coordinates), or None."""
    path = cv.beginPath()
    if p["t"] == "rect":
        if p.get("rx"):
            path.roundRect(0, 0, e["w"], e["h"], min(p["rx"], e["w"] / 2, e["h"] / 2))
        else:
            path.rect(0, 0, e["w"], e["h"])
        return path
    if p["t"] == "ellipse":
        path.ellipse(p["cx"] - p["rx"], p["cy"] - p["ry"], 2 * p["rx"], 2 * p["ry"])
        return path
    if p["t"] in ("poly", "line"):
        segs = [("M",) + tuple(p["pts"][0])] + [("L",) + tuple(q) for q in p["pts"][1:]]
        if p["t"] == "poly":
            segs.append(("Z",))
        return _path(cv, segs)
    if p["t"] == "path":
        try:
            return _path(cv, C.parse_path(p["d"]))
        except ValueError:
            return None
    return None


def _paint_gradient(cv, path, grad, fill: str, e: dict):
    """Fill *path* with the element's gradient: clip, then a PDF shading over the box."""
    from reportlab.lib.colors import Color
    typ, colour, angle = grad
    c0, c1 = Color(*_rgb(fill, (1, 1, 1))), Color(*_rgb(colour, (1, 1, 1)))
    w, h = max(e["w"], 1e-6), max(e["h"], 1e-6)
    cv.saveState()
    cv.clipPath(path, stroke=0, fill=0)
    if typ == "radial":
        cv.translate(w / 2, h / 2)
        cv.scale(w / 2, h / 2)              # the radial gradient is an ellipse filling the box
        cv.radialGradient(0, 0, 1, (c0, c1), extend=True)
    else:
        x1, y1, x2, y2 = C.gradient_vector(angle)
        cv.linearGradient(x1 * w, y1 * h, x2 * w, y2 * h, (c0, c1), extend=True)
    cv.restoreState()


#: (offset factor, share of SHADOW_ALPHA) of the shadow copies
SHADOW_STEPS = ((1.4, 0.35), (1.0, 0.4), (0.6, 0.45))


def _draw_outline(cv, e: dict, st: dict):
    """The element's shape: shadow pass, fill (flat or gradient) and stroke,
    with ``fill_opacity``/``stroke_opacity`` on top of the element's opacity."""
    fill, stroke = st["fill"], st["stroke"]
    op = st["opacity"]
    grad = C.gradient_of(st)
    prims = [p for p in C.outline(e)]
    if st.get("shadow") and fill != "none":
        # PDF has no blur: three offset copies at low alpha read as a soft shadow
        for k, share in SHADOW_STEPS:
            cv.saveState()
            cv.translate(C.SHADOW_DX * k, C.SHADOW_DY * k)
            cv.setFillColorRGB(*_rgb(st.get("shadow_color"), (0, 0, 0)))
            cv.setFillAlpha(op * C.SHADOW_ALPHA * share * st.get("fill_opacity", 1.0) ** 0.5)
            for p in prims:
                if p.get("fill", True) and p["t"] != "line":
                    path = _prim_path(cv, p, e)
                    if path is not None:
                        cv.drawPath(path, stroke=0, fill=1)
            cv.restoreState()
    cv.saveState()
    cv.setFillAlpha(op * st.get("fill_opacity", 1.0))
    cv.setStrokeAlpha(op * st.get("stroke_opacity", 1.0))
    cv.setFillColorRGB(*_rgb(fill, (1, 1, 1)))
    cv.setStrokeColorRGB(*_rgb(stroke, (0.1, 0.1, 0.1)))
    for p in prims:
        filled = p.get("fill", True) and fill != "none" and p["t"] != "line"
        stroked = p.get("stroke", True) and stroke != "none" and st["stroke_width"] > 0
        if not (filled or stroked):
            continue
        path = _prim_path(cv, p, e)
        if path is None:
            continue
        if filled and grad is not None:
            _paint_gradient(cv, path, grad, fill, e)
            if stroked:
                cv.drawPath(_prim_path(cv, p, e), stroke=1, fill=0)
        else:
            cv.drawPath(path, stroke=int(stroked), fill=int(filled))
    cv.restoreState()


_ICON_SHAPES = ("path", "rect", "circle", "ellipse", "line", "polyline", "polygon")
_NAMED = {"black": "#000000", "white": "#FFFFFF", "red": "#FF0000", "green": "#008000", "blue": "#0000FF",
          "gray": "#808080", "grey": "#808080", "yellow": "#FFFF00", "orange": "#FFA500", "purple": "#800080"}
_INHERIT = ("fill", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin", "stroke-dasharray", "fill-rule")


def _paint_rgb(v, current):
    """RGB tuple or None for ``none``."""
    if v is None or v == "none":
        return None
    if v == "currentColor":
        return _rgb(current)
    v = _NAMED.get(v.lower(), v)
    if re.fullmatch(r"#[0-9A-Fa-f]{3}", v):
        v = "#" + "".join(c * 2 for c in v[1:])
    if re.fullmatch(r"#[0-9A-Fa-f]{8}", v):
        v = v[:7]
    return _rgb(v) if re.fullmatch(r"#[0-9A-Fa-f]{6}", v) else (0.0, 0.0, 0.0)


def _icon_segments(node, tag):
    g = lambda k, d=0.0: _f(node.get(k), d)
    if tag == "path":
        return geometry.parse_path(node.get("d")), True
    if tag == "rect":
        x, y, w, h = g("x"), g("y"), g("width"), g("height")
        rx, ry = g("rx", None), g("ry", None)
        rx = ry if rx is None else rx
        ry = rx if ry is None else ry
        if w <= 0 or h <= 0:
            return [], True
        if rx and ry:
            rx, ry = min(rx, w / 2), min(ry, h / 2)
            k = 0.5523
            return [("M", x + rx, y), ("L", x + w - rx, y), ("C", x + w - rx + rx * k, y, x + w, y + ry - ry * k, x + w, y + ry),
                    ("L", x + w, y + h - ry), ("C", x + w, y + h - ry + ry * k, x + w - rx + rx * k, y + h, x + w - rx, y + h),
                    ("L", x + rx, y + h), ("C", x + rx - rx * k, y + h, x, y + h - ry + ry * k, x, y + h - ry),
                    ("L", x, y + ry), ("C", x, y + ry - ry * k, x + rx - rx * k, y, x + rx, y), ("Z",)], True
        return [("M", x, y), ("L", x + w, y), ("L", x + w, y + h), ("L", x, y + h), ("Z",)], True
    if tag in ("circle", "ellipse"):
        cx, cy = g("cx"), g("cy")
        rx = g("r") if tag == "circle" else g("rx")
        ry = rx if tag == "circle" else g("ry")
        if rx <= 0 or ry <= 0:
            return [], True
        k = 0.5523
        return [("M", cx + rx, cy), ("C", cx + rx, cy + ry * k, cx + rx * k, cy + ry, cx, cy + ry),
                ("C", cx - rx * k, cy + ry, cx - rx, cy + ry * k, cx - rx, cy),
                ("C", cx - rx, cy - ry * k, cx - rx * k, cy - ry, cx, cy - ry),
                ("C", cx + rx * k, cy - ry, cx + rx, cy - ry * k, cx + rx, cy), ("Z",)], True
    if tag == "line":
        return [("M", g("x1"), g("y1")), ("L", g("x2"), g("y2"))], False
    nums = [_f(t, None) for t in re.split(r"[\s,]+", (node.get("points") or "").strip()) if t]
    nums = [n for n in nums if n is not None]
    pts = list(zip(nums[0::2], nums[1::2]))
    if len(pts) < 2:
        return [], True
    segs = [("M",) + pts[0]] + [("L",) + q for q in pts[1:]]
    if tag == "polygon":
        segs.append(("Z",))
    return segs, tag == "polygon"


def _f(v, d):
    try:
        v = re.sub(r"(px|%)$", "", str(v)) if v is not None else None
        return float(v) if v is not None else d
    except ValueError:
        return d


def _walk_icon(cv, node, props, current, el_style, depth=0):
    from reportlab.pdfgen import canvas as _cv
    tag = node.tag.rsplit("}", 1)[-1]
    if depth > 12 or (tag not in ("g", "svg") and tag not in _ICON_SHAPES):
        return
    props = dict(props)
    for k in _INHERIT:
        if node.get(k) is not None:
            props[k] = node.get(k)
    cv.saveState()
    if node.get("transform"):
        cv.transform(*geometry.parse_transform(node.get("transform")))
    op = _f(node.get("opacity"), 1.0)
    if tag in ("g", "svg"):
        for ch in node:
            _walk_icon(cv, ch, props, current, el_style, depth + 1)
        cv.restoreState()
        return
    segs, closed_fill = _icon_segments(node, tag)
    fill = _paint_rgb(props.get("fill", "#000000"), current)
    stroke = _paint_rgb(props.get("stroke", "none"), current)
    if tag == "line":
        fill = None
    if segs and (fill or stroke):
        alpha = el_style["opacity"] * op
        cv.setFillAlpha(alpha)
        cv.setStrokeAlpha(alpha)
        if fill:
            cv.setFillColorRGB(*fill)
        if stroke:
            cv.setStrokeColorRGB(*stroke)
        cv.setLineWidth(_f(props.get("stroke-width"), el_style["stroke_width"]))
        cv.setLineCap({"round": 1, "square": 2}.get(props.get("stroke-linecap"), 0))
        cv.setLineJoin({"round": 1, "bevel": 2}.get(props.get("stroke-linejoin"), 0))
        dash = [_f(t, 0.0) for t in re.split(r"[\s,]+", props.get("stroke-dasharray") or "") if t and t != "none"]
        cv.setDash(dash if dash and any(dash) else [])      # dashed outlines of zone/tile icons
        cv.drawPath(_path(cv, segs), stroke=int(bool(stroke)), fill=int(bool(fill)),
                    fillMode=_cv.FILL_EVEN_ODD if props.get("fill-rule") == "evenodd" else _cv.FILL_NON_ZERO)
    cv.restoreState()


def _draw_icon(cv, ic: dict, x: float, y: float, size: float, e: dict):
    """Vector icon from the sanitised markup, scaled like the editor does (max side -> size)."""
    k = size / max(ic["vb"][2], ic["vb"][3])
    cur = C.paint(e["style"]["stroke"], "#1F2937")
    cur = cur if cur != "none" else "#1F2937"
    cv.saveState()
    cv.translate(x, y)
    cv.scale(k, k)
    cv.translate(-ic["vb"][0], -ic["vb"][1])
    try:
        _walk_icon(cv, ic["tree"], {}, cur, e["style"])
    finally:
        cv.restoreState()


def _draw_text(cv, b: dict, st: dict, fonts, uni: bool):
    from reportlab.pdfbase.pdfmetrics import stringWidth
    fs = st["font_size"]
    font = _font_for(fonts, b["bold"], st["italic"])
    txt = b["text"] if uni else _latin(b["text"])
    lines = C.wrap_lines(txt, b["w"], lambda s: stringWidth(s, font, fs))
    if not lines:
        return
    lh = fs * 1.2
    total = lh * len(lines)
    if b["valign"] == "top":
        y0 = b["y"]
    elif b["valign"] == "bottom":
        y0 = b["y"] + b["h"] - total
    else:
        y0 = b["y"] + (b["h"] - total) / 2
    cv.saveState()
    cv.setFillColorRGB(*_rgb(st["font_color"], (0.07, 0.09, 0.15)))
    # The page is y-flipped; flip back locally so glyphs are upright.
    for i, ln in enumerate(lines):
        base = y0 + i * lh + fs * 0.95
        wdt = stringWidth(ln, font, fs)
        x = b["x"] if b["align"] == "left" else b["x"] + b["w"] - wdt if b["align"] == "right" else b["x"] + (b["w"] - wdt) / 2
        cv.saveState()
        cv.translate(x, base)
        cv.scale(1, -1)
        if b.get("below"):           # white plate behind the label (the SVG uses a stroked halo)
            cv.saveState()
            cv.setFillColorRGB(1, 1, 1)
            cv.setFillAlpha(0.85)
            cv.rect(0, -fs * 0.25, wdt, lh, stroke=0, fill=1)
            cv.restoreState()
        t = cv.beginText(0, 0)
        t.setFont(font, fs)
        t.textOut(ln)
        cv.drawText(t)
        cv.restoreState()
    cv.restoreState()


def _draw_connector(cv, c: dict, by_id: dict, fonts, uni: bool):
    st = c["style"]
    segs, poly = C.route_segments(c, by_id)
    flat = C.flatten(segs)
    cv.saveState()
    _apply_stroke(cv, st)
    stroke = st["stroke"]
    if st.get("shadow"):
        # no blur in PDF: a wide faint stroke under a narrower one reads as a soft line shadow
        sw = max(0.5, st["stroke_width"])
        for extra, share in ((sw * 2 + 2, 0.25), (sw + 1, 0.35)):
            cv.saveState()
            cv.translate(C.SHADOW_DX, C.SHADOW_DY)
            cv.setLineWidth(extra)
            cv.setLineCap(1)
            cv.setStrokeColorRGB(*_rgb(st.get("shadow_color"), (0, 0, 0)))
            cv.setStrokeAlpha(st["opacity"] * C.SHADOW_ALPHA * share)
            cv.drawPath(_path(cv, segs), stroke=1, fill=0)
            cv.restoreState()
    if st.get("stroke_opacity", 1.0) < 1:
        cv.setStrokeAlpha(st["opacity"] * st["stroke_opacity"])
        cv.setFillAlpha(st["opacity"] * st["stroke_opacity"])
    cv.setStrokeColorRGB(*_rgb(stroke, (0.1, 0.1, 0.1)))
    cv.drawPath(_path(cv, segs), stroke=1, fill=0)
    cv.setDash([])
    for kind, at_end in ((c["start_arrow"], False), (c["end_arrow"], True)):
        if kind == "none" or kind not in C.ARROW_GLYPHS:
            continue
        tip = flat[-1] if at_end else flat[0]
        ang = C.end_angle(flat, at_end)
        cv.saveState()
        cv.translate(*tip)
        cv.rotate(math.degrees(ang))
        cv.setLineWidth(1.2)
        for g in C.ARROW_GLYPHS[kind]:
            fillmode = g["fill"]
            if fillmode == "stroke":
                cv.setFillColorRGB(*_rgb(stroke, (0.1, 0.1, 0.1)))
            else:
                cv.setFillColorRGB(1, 1, 1)
            f = 1 if fillmode else 0
            if g["t"] == "circle":
                cv.circle(g["c"][0], g["c"][1], g["r"], stroke=1, fill=f)
            else:
                pts = g["pts"]
                segs2 = [("M",) + tuple(pts[0])] + [("L",) + tuple(q) for q in pts[1:]]
                if g["t"] == "poly":
                    segs2.append(("Z",))
                cv.drawPath(_path(cv, segs2), stroke=1, fill=f)
        cv.restoreState()
    texts = ([(c["label"], 0.5)] if c["label"] else []) + [(lb["text"], lb["pos"]) for lb in c["labels"]]
    lst = {"font_size": 11.0, "font_color": st["font_color"], "italic": False}
    for text, pos in texts:
        x, y = C.point_along(flat, pos)
        _draw_text(cv, {"x": x - 120, "y": y - 16, "w": 240, "h": 14, "text": text, "bold": False,
                        "align": "center", "valign": "middle"}, lst, fonts, uni)
    cv.restoreState()
