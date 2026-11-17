"""Helpers shared by the exporters: page selection, text layout, shape
outlines, connector routing and arrow glyphs. Standard library only."""
from __future__ import annotations

import math
import re

from .. import model


class ExportFailed(ValueError):
    """The document cannot be written in the requested format (message is safe to show)."""


# ------------------------------------------------------------------- text

_XML_BAD = re.compile("[^\x09\x0a\x0d\x20-퟿-�\U00010000-\U0010ffff]")


def xml_clean(v) -> str:
    """Text with everything XML 1.0 cannot carry removed (control chars, lone surrogates)."""
    if v is None:
        return ""
    return _XML_BAD.sub("", str(v).replace("\r", ""))


_ESC = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "\n": "&#10;", "\t": "&#9;"}


def esc(v) -> str:
    """Escape for an XML attribute value or text node."""
    return "".join(_ESC.get(ch, ch) for ch in xml_clean(v))


def esc_text(v) -> str:
    """Escape for an XML text node (quotes and newlines stay literal)."""
    return xml_clean(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slug_filename(name: str, ext: str, suffix: str = "") -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", xml_clean(name)[:120]).strip("-.") or "diagram"
    if suffix:
        slug += "-" + re.sub(r"[^A-Za-z0-9._-]+", "-", xml_clean(suffix)[:60]).strip("-.")
    return slug[:100] + "." + ext


def prepare(doc) -> dict:
    """Normalise defensively; an unusable document becomes :class:`ExportFailed`."""
    try:
        out, _warn = model.normalise(doc)
    except model.ModelError as exc:
        raise ExportFailed(str(exc)) from None
    return out


def select_pages(doc: dict, page) -> list[dict]:
    """``None`` -> every page for multi-page formats is decided by the caller;
    here: ``"all"`` -> all, an int -> that 0-based index, a str -> page id."""
    pages = doc["pages"]
    if page in (None, "all"):
        return list(pages)
    if isinstance(page, bool):
        raise ExportFailed("bad page selector")
    if isinstance(page, int):
        if 0 <= page < len(pages):
            return [pages[page]]
        raise ExportFailed("page %d does not exist" % page)
    if isinstance(page, str):
        for p in pages:
            if p["id"] == page:
                return [p]
        if page.isdigit() and int(page) < len(pages):
            return [pages[int(page)]]
    raise ExportFailed("page %r does not exist" % str(page)[:40])


def is_hex(c) -> bool:
    return isinstance(c, str) and re.fullmatch(r"#[0-9A-Fa-f]{6}", c) is not None


def paint(c, default: str = "none") -> str:
    """``#RRGGBB`` or ``none``; anything else becomes the default."""
    if c == "none":
        return "none"
    return c if is_hex(c) else default


# ---------------------------------------------------------- colour styling
# One definition of dash patterns, gradients and shadows for every writer and
# for the editor (diagram_studio_render.js mirrors these numbers).

#: drop shadow: offset (px, down-right), blur (SVG stdDeviation) and strength
SHADOW_DX, SHADOW_DY, SHADOW_BLUR, SHADOW_ALPHA = 2.0, 3.0, 2.5, 0.3


def dash_pattern(st: dict) -> str:
    """The style's dash pattern (``dash_pattern``, else the legacy ``dashed`` flag)."""
    pat = st.get("dash_pattern")
    if pat in model.DASH_PATTERNS:
        return pat
    return "dashed" if st.get("dashed") else "solid"


def dash_array(st: dict) -> list[float]:
    """Dash lengths in px for the stroke width; ``[]`` = solid."""
    pat, sw = dash_pattern(st), max(0.0, float(st.get("stroke_width") or 0.0))
    if pat == "dashed":
        return [max(4.0, sw * 4), max(3.0, sw * 3)]
    if pat == "dotted":
        return [max(1.0, sw), max(2.0, sw * 2)]
    if pat == "dash-dot":
        return [max(6.0, sw * 6), max(3.0, sw * 3), max(1.0, sw), max(3.0, sw * 3)]
    return []


def gradient_of(st: dict):
    """``(type, colour, angle)`` of a drawable gradient, else None."""
    g = st.get("gradient") or {}
    if g.get("type") in ("linear", "radial") and is_hex(g.get("color")) and is_hex(st.get("fill")):
        return g["type"], g["color"].upper(), int(g.get("angle", 90)) % 360
    return None


def gradient_vector(angle: float) -> tuple[float, float, float, float]:
    """``(x1, y1, x2, y2)`` in bounding-box fractions: the gradient line of
    *angle* (degrees clockwise from east, y down) spans the box corner to corner."""
    a = math.radians(angle)
    c, s = math.cos(a), math.sin(a)
    k = (abs(c) + abs(s)) / 2.0
    r = lambda v: round(v, 4) + 0.0
    return r(0.5 - c * k), r(0.5 - s * k), r(0.5 + c * k), r(0.5 + s * k)


def vector_angle(x1: float, y1: float, x2: float, y2: float) -> int:
    """The inverse of :func:`gradient_vector` (any vector, y down)."""
    if abs(x2 - x1) < 1e-9 and abs(y2 - y1) < 1e-9:
        return 90
    return int(round(math.degrees(math.atan2(y2 - y1, x2 - x1)))) % 360


def wrap_lines(text: str, width: float, measure) -> list[str]:
    """Split on newlines, then wrap words to *width* using ``measure(str) -> float``."""
    out: list[str] = []
    for raw in xml_clean(text).split("\n"):
        if not raw.strip() or width <= 0 or measure(raw) <= width:
            out.append(raw)
            continue
        cur = ""
        for word in raw.split(" "):
            cand = word if not cur else cur + " " + word
            if measure(cand) <= width or not cur:
                cur = cand
                # a single over-long word is hard-broken
                while measure(cur) > width and len(cur) > 1:
                    k = len(cur)
                    while k > 1 and measure(cur[:k]) > width:
                        k -= 1
                    out.append(cur[:k])
                    cur = cur[k:]
            else:
                out.append(cur)
                cur = word
        out.append(cur)
    return out


# ------------------------------------------------------------ SVG paths

_NUM = re.compile(r"[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?")


def parse_path(d: str, limit: int = 50000) -> list[tuple]:
    """SVG path data -> absolute segments ``("M",x,y) ("L",x,y) ("C",x1,y1,x2,y2,x,y)
    ("Q",x1,y1,x,y) ("A",rx,ry,rot,large,sweep,x,y) ("Z",)``. Raises ValueError."""
    segs: list[tuple] = []
    i, n = 0, len(d)
    cmd = ""
    cx = cy = sx = sy = 0.0
    pc = ""                 # previous command (upper case) for S/T reflection
    lx = ly = 0.0           # last control point

    def ws():
        nonlocal i
        while i < n and d[i] in " \t\r\n,":
            i += 1

    def num() -> float:
        nonlocal i
        ws()
        m = _NUM.match(d, i)
        if not m:
            raise ValueError("bad number in path at %d" % i)
        i = m.end()
        return float(m.group())

    def flag() -> int:
        nonlocal i
        ws()
        if i < n and d[i] in "01":
            i += 1
            return int(d[i - 1])
        raise ValueError("bad arc flag")

    while True:
        ws()
        if i >= n:
            break
        if len(segs) > limit:
            raise ValueError("path too long")
        ch = d[i]
        if ch.isalpha():
            if ch not in "MmLlHhVvCcSsQqTtAaZz":
                raise ValueError("bad command %r" % ch)
            cmd = ch
            i += 1
        elif not cmd:
            raise ValueError("path must start with a command")
        up, rel = cmd.upper(), cmd.islower()
        ox, oy = (cx, cy) if rel else (0.0, 0.0)
        if up == "Z":
            segs.append(("Z",))
            cx, cy = sx, sy
            pc = "Z"
            cmd = ""
            continue
        if up == "M":
            x, y = num() + ox, num() + oy
            segs.append(("M", x, y))
            cx, cy, sx, sy = x, y, x, y
            cmd = "l" if rel else "L"
        elif up == "L":
            x, y = num() + ox, num() + oy
            segs.append(("L", x, y))
            cx, cy = x, y
        elif up == "H":
            x = num() + (cx if rel else 0.0)
            segs.append(("L", x, cy))
            cx = x
        elif up == "V":
            y = num() + (cy if rel else 0.0)
            segs.append(("L", cx, y))
            cy = y
        elif up == "C":
            x1, y1, x2, y2, x, y = (num() + (ox if k % 2 == 0 else oy) for k in range(6))
            segs.append(("C", x1, y1, x2, y2, x, y))
            lx, ly, cx, cy = x2, y2, x, y
        elif up == "S":
            x2, y2, x, y = (num() + (ox if k % 2 == 0 else oy) for k in range(4))
            x1, y1 = (2 * cx - lx, 2 * cy - ly) if pc in ("C", "S") else (cx, cy)
            segs.append(("C", x1, y1, x2, y2, x, y))
            lx, ly, cx, cy = x2, y2, x, y
        elif up == "Q":
            x1, y1, x, y = (num() + (ox if k % 2 == 0 else oy) for k in range(4))
            segs.append(("Q", x1, y1, x, y))
            lx, ly, cx, cy = x1, y1, x, y
        elif up == "T":
            x, y = num() + ox, num() + oy
            x1, y1 = (2 * cx - lx, 2 * cy - ly) if pc in ("Q", "T") else (cx, cy)
            segs.append(("Q", x1, y1, x, y))
            lx, ly, cx, cy = x1, y1, x, y
        else:  # A
            rx, ry, rot = num(), num(), num()
            la, sw = flag(), flag()
            x, y = num() + ox, num() + oy
            segs.append(("A", rx, ry, rot, la, sw, x, y))
            cx, cy = x, y
        pc = up
    return segs


def arc_to_beziers(x0, y0, rx, ry, rot, large, sweep, x, y) -> list[tuple]:
    """SVG elliptical arc -> list of ``(x1,y1,x2,y2,x,y)`` cubic segments."""
    if (x0, y0) == (x, y):
        return []
    rx, ry = abs(rx), abs(ry)
    if rx == 0 or ry == 0:
        return [(x0, y0, x, y, x, y)]
    phi = math.radians(rot)
    cp, sp = math.cos(phi), math.sin(phi)
    dx, dy = (x0 - x) / 2, (y0 - y) / 2
    x1p, y1p = cp * dx + sp * dy, -sp * dx + cp * dy
    lam = (x1p ** 2) / (rx ** 2) + (y1p ** 2) / (ry ** 2)
    if lam > 1:
        s = math.sqrt(lam)
        rx, ry = rx * s, ry * s
    num_ = rx ** 2 * ry ** 2 - rx ** 2 * y1p ** 2 - ry ** 2 * x1p ** 2
    den = rx ** 2 * y1p ** 2 + ry ** 2 * x1p ** 2
    co = math.sqrt(max(0.0, num_ / den)) if den else 0.0
    if bool(large) == bool(sweep):
        co = -co
    cxp, cyp = co * rx * y1p / ry, -co * ry * x1p / rx
    cx = cp * cxp - sp * cyp + (x0 + x) / 2
    cy = sp * cxp + cp * cyp + (y0 + y) / 2

    def ang(ux, uy, vx, vy):
        a = math.atan2(ux * vy - uy * vx, ux * vx + uy * vy)
        return a

    t1 = ang(1, 0, (x1p - cxp) / rx, (y1p - cyp) / ry)
    dt = ang((x1p - cxp) / rx, (y1p - cyp) / ry, (-x1p - cxp) / rx, (-y1p - cyp) / ry)
    if not sweep and dt > 0:
        dt -= 2 * math.pi
    elif sweep and dt < 0:
        dt += 2 * math.pi
    n = max(1, int(math.ceil(abs(dt) / (math.pi / 2) - 1e-9)))
    step = dt / n
    out = []
    k = 4 / 3 * math.tan(step / 4)
    t = t1
    for _ in range(n):
        c1, s1 = math.cos(t), math.sin(t)
        c2, s2 = math.cos(t + step), math.sin(t + step)
        p = [(c1 - k * s1, s1 + k * c1), (c2 + k * s2, s2 - k * c2), (c2, s2)]
        pts = []
        for ux, uy in p:
            ux, uy = ux * rx, uy * ry
            pts += [cp * ux - sp * uy + cx, sp * ux + cp * uy + cy]
        out.append(tuple(pts))
        t += step
    return out


# --------------------------------------------------------- shape outlines

ROW_H = 22.0
HEADER_H = 30.0


def _poly(fracs, w, h):
    return [(a * w, b * h) for a, b in fracs]


def outline(el: dict) -> list[dict]:
    """Drawing primitives of an element in LOCAL coordinates (0..w, 0..h).
    Items: ``{"t": "rect", "rx"}``, ``{"t": "ellipse", "cx","cy","rx","ry"}``,
    ``{"t": "poly", "pts"}``, ``{"t": "path", "d"}``, ``{"t": "line", "pts"}``;
    ``"fill": False`` marks stroke-only items."""
    shape, w, h = el["shape"], max(el["w"], 0.0), max(el["h"], 0.0)
    rx_style = min(w, h) * 0.12 if el["style"].get("rounded") else 0.0
    full = {"t": "ellipse", "cx": w / 2, "cy": h / 2, "rx": w / 2, "ry": h / 2}
    if el["kind"] == "image":
        return [{"t": "rect", "rx": 0.0, "fill": False, "stroke": False}]
    if shape == "round":
        return [{"t": "rect", "rx": min(w, h) * 0.12}]
    if shape == "symbol":
        return [{"t": "rect", "rx": min(8.0, min(w, h) * 0.12)}]
    if shape in ("terminator", "pill"):
        return [{"t": "rect", "rx": min(w, h) / 2}]
    if shape == "ellipse":
        return [full]
    if shape == "diamond":
        return [{"t": "poly", "pts": _poly([(.5, 0), (1, .5), (.5, 1), (0, .5)], w, h)}]
    if shape == "hexagon":
        return [{"t": "poly", "pts": _poly([(.25, 0), (.75, 0), (1, .5), (.75, 1), (.25, 1), (0, .5)], w, h)}]
    if shape == "parallelogram":
        return [{"t": "poly", "pts": _poly([(.2, 0), (1, 0), (.8, 1), (0, 1)], w, h)}]
    if shape == "trapezoid":
        return [{"t": "poly", "pts": _poly([(.2, 0), (.8, 0), (1, 1), (0, 1)], w, h)}]
    if shape == "triangle":
        return [{"t": "poly", "pts": _poly([(.5, 0), (1, 1), (0, 1)], w, h)}]
    if shape == "cylinder":
        ry = max(1.0, min(h * 0.15, h / 2 - 0.5))
        hw = w / 2
        body = "M0,%g A%g,%g 0 0 1 %g,%g L%g,%g A%g,%g 0 0 1 0,%g Z" % (ry, hw, ry, w, ry, w, h - ry, hw, ry, h - ry)
        rim = "M0,%g A%g,%g 0 0 0 %g,%g" % (ry, hw, ry, w, ry)
        return [{"t": "path", "d": body}, {"t": "path", "d": rim, "fill": False}]
    if shape == "cloud":
        c = [(.25, .8), (.05, .8, .0, .55, .15, .45), (.1, .25, .3, .1, .45, .2), (.55, .0, .8, .05, .82, .28),
             (1.0, .3, 1.02, .6, .88, .72), (.9, .88, .75, .95, .65, .82), (.55, .98, .35, .95, .25, .8)]
        d = "M%g,%g" % (c[0][0] * w, c[0][1] * h)
        for seg in c[1:]:
            d += " C" + " ".join("%g,%g" % (seg[k] * w, seg[k + 1] * h) for k in (0, 2, 4))
        return [{"t": "path", "d": d + " Z"}]
    if shape == "document":
        d = "M0,0 L%g,0 L%g,%g C%g,%g %g,%g %g,%g C%g,%g %g,%g 0,%g Z" % (
            w, w, .88 * h, .75 * w, .76 * h, .65 * w, .76 * h, .5 * w, .88 * h,
            .35 * w, h, .25 * w, h, .88 * h)
        return [{"t": "path", "d": d}]
    if shape == "note":
        f = max(0.0, min(14.0, w / 3, h / 3))
        return [{"t": "poly", "pts": [(0, 0), (w - f, 0), (w, f), (w, h), (0, h)]},
                {"t": "path", "d": "M%g,0 L%g,%g L%g,%g" % (w - f, w - f, f, w, f), "fill": False}]
    if shape == "process":
        f = min(w * 0.1, 20.0)
        return [{"t": "rect", "rx": 0.0},
                {"t": "path", "d": "M%g,0 L%g,%g M%g,0 L%g,%g" % (f, f, h, w - f, w - f, h), "fill": False}]
    if shape == "actor":
        r = max(1.0, min(w * 0.2, h * 0.12))
        d = ("M%g,%g L%g,%g M%g,%g L%g,%g M%g,%g L%g,%g M%g,%g L%g,%g" % (
            w / 2, .27 * h, w / 2, .62 * h, .1 * w, .4 * h, .9 * w, .4 * h,
            w / 2, .62 * h, .15 * w, h, w / 2, .62 * h, .85 * w, h))
        return [{"t": "ellipse", "cx": w / 2, "cy": .15 * h, "rx": r, "ry": r},
                {"t": "path", "d": d, "fill": False}]
    if shape == "swimlane":
        hh = min(HEADER_H, h)
        return [{"t": "rect", "rx": 0.0}, {"t": "line", "pts": [(0, hh), (w, hh)]}]
    if shape == "table":
        hh = min(HEADER_H, h)
        items = [{"t": "rect", "rx": 0.0}, {"t": "line", "pts": [(0, hh), (w, hh)]}]
        for j in range(len(el.get("rows") or [])):
            y = hh + ROW_H * (j + 1)
            if y < h - 0.5:
                items.append({"t": "line", "pts": [(0, y), (w, y)]})
        return items
    if shape == "polygon" and len(el.get("points") or []) >= 2:
        return [{"t": "poly", "pts": [(p[0] * w, p[1] * h) for p in el["points"]]}]
    if shape == "path" and el.get("path"):
        return [{"t": "path", "d": el["path"]}]
    if shape == "line":
        return [{"t": "line", "pts": [(0, h / 2), (w, h / 2)]}]
    return [{"t": "rect", "rx": rx_style}]


def text_blocks(el: dict) -> list[dict]:
    """Where the element's text goes: ``[{x, y, w, h, text, bold, align, valign}]`` in local
    coords, kept clear of a corner icon (:func:`make_room_for_icon`)."""
    return make_room_for_icon(el, _text_blocks(el))


def _text_blocks(el: dict) -> list[dict]:
    st = el["style"]
    w, h = el["w"], el["h"]
    if el["shape"] == "table":
        hh = min(HEADER_H, h)
        blocks = [{"x": 0, "y": 0, "w": w, "h": hh, "text": el["text"], "bold": True,
                   "align": st["align"], "valign": "middle"}]
        for j, r in enumerate(el.get("rows") or []):
            if hh + ROW_H * j >= h:
                break
            blocks.append({"x": 6, "y": hh + ROW_H * j, "w": max(0, w - 10), "h": ROW_H, "text": r["text"],
                           "bold": bool(r["bold"]), "align": "left", "valign": "middle"})
        return [b for b in blocks if b["text"]]
    if el["shape"] == "swimlane":
        return [{"x": 0, "y": 0, "w": w, "h": min(HEADER_H, h), "text": el["text"], "bold": st["bold"],
                 "align": st["align"], "valign": "middle"}] if el["text"] else []
    if not el["text"]:
        return []
    if el["shape"] == "symbol":     # the editor's rule: the label sits BELOW a symbol, with a white halo
        return [{"x": -40, "y": h + 2, "w": w + 80, "h": 0, "text": el["text"], "bold": st["bold"],
                 "align": "center", "valign": "top", "below": True}]
    return [{"x": 4, "y": 2, "w": max(0, w - 8), "h": max(0, h - 4), "text": el["text"],
             "bold": st["bold"], "align": st["align"], "valign": st["valign"]}]


# -------------------------------------------------------------- connectors

STUB = 16.0
SIDES = (("n", 0.5, 0.0, 0.0, -1.0), ("e", 1.0, 0.5, 1.0, 0.0), ("s", 0.5, 1.0, 0.0, 1.0), ("w", 0.0, 0.5, -1.0, 0.0))


def _center(el: dict) -> tuple[float, float]:
    return el["x"] + el["w"] / 2, el["y"] + el["h"] / 2


def _rot(px: float, py: float, cx: float, cy: float, deg: float) -> tuple[float, float]:
    """Rotate a point clockwise (y down) about (cx, cy); the editor's ``G.rotate``."""
    if not deg:
        return px, py
    a = math.radians(deg)
    c, s = math.cos(a), math.sin(a)
    dx, dy = px - cx, py - cy
    return cx + dx * c - dy * s, cy + dx * s + dy * c


def _clip(el: dict, qx: float, qy: float) -> tuple[float, float]:
    """Where the ray from the centre toward (qx, qy) leaves the ROTATED outline
    (the editor's ``R.clip``): the point is taken into the element's frame, the
    unrotated outline is intersected, and the hit is rotated back."""
    cx, cy = _center(el)
    rot = el.get("rotation") or 0
    qx, qy = _rot(qx, qy, cx, cy, -rot)
    a, b = max(el["w"] / 2, 1e-6), max(el["h"] / 2, 1e-6)
    dx, dy = qx - cx, qy - cy
    if abs(dx) < 1e-9 and abs(dy) < 1e-9:
        return cx, cy
    if el["shape"] in ("ellipse", "cloud"):
        t = 1 / math.sqrt((dx / a) ** 2 + (dy / b) ** 2)
    elif el["shape"] == "diamond":
        t = 1 / (abs(dx) / a + abs(dy) / b)
    else:
        t = min(a / abs(dx) if dx else float("inf"), b / abs(dy) if dy else float("inf"))
    return _rot(cx + dx * t, cy + dy * t, cx, cy, rot)


def _port_local(el: dict, port_id: str):
    for p in el.get("ports") or []:
        if p["id"] == port_id:
            return p["x"], p["y"]
    for sid, x, y, _dx, _dy in SIDES:
        if sid == port_id:
            return x, y
    return None


def _port_xy(el: dict, port_id: str):
    loc = _port_local(el, port_id)
    if loc is None:
        return None
    cx, cy = _center(el)
    return _rot(el["x"] + loc[0] * el["w"], el["y"] + loc[1] * el["h"], cx, cy, el.get("rotation") or 0)


def anchors(el: dict) -> list[dict]:
    """Declared ports, else the four side midpoints, rotated (the editor's ``R.anchors``)."""
    cx, cy = _center(el)
    rot = el.get("rotation") or 0
    if el.get("ports"):
        base = []
        for p in el["ports"]:
            dx, dy = p["x"] - 0.5, p["y"] - 0.5
            ax = (1.0 if dx >= 0 else -1.0) if abs(dx) >= abs(dy) else 0.0
            ay = 0.0 if ax else (1.0 if dy >= 0 else -1.0)
            base.append((p["id"], p["x"], p["y"], ax, ay, True))
    else:
        base = [(sid, x, y, dx, dy, False) for sid, x, y, dx, dy in SIDES]
    out = []
    for pid, x, y, dx, dy, declared in base:
        px, py = _rot(el["x"] + x * el["w"], el["y"] + y * el["h"], cx, cy, rot)
        ox, oy = _rot(dx, dy, 0.0, 0.0, rot)
        # the stub leaves along the dominant axis, never diagonally (the editor's rule)
        if abs(ox) >= abs(oy) or abs(abs(ox) - abs(oy)) < 1e-9:
            ox, oy = (1.0 if ox >= 0 else -1.0), 0.0
        else:
            ox, oy = 0.0, (1.0 if oy >= 0 else -1.0)
        out.append({"id": pid, "x": px, "y": py, "dx": ox, "dy": oy, "lx": x, "ly": y, "declared": declared})
    return out


def _nearest_anchor(el: dict, toward) -> dict:
    return min(anchors(el), key=lambda a: (a["x"] - toward[0]) ** 2 + (a["y"] - toward[1]) ** 2)


def _anchor_by_id(el: dict, pid: str):
    for a in anchors(el):
        if a["id"] == pid:
            return a
    xy = _port_xy(el, pid)
    if not xy:
        return None
    cx, cy = _center(el)
    dx, dy = xy[0] - cx, xy[1] - cy
    loc = _port_local(el, pid)
    if abs(dx) / max(el["w"], 1e-6) >= abs(dy) / max(el["h"], 1e-6):
        return {"x": xy[0], "y": xy[1], "dx": 1.0 if dx >= 0 else -1.0, "dy": 0.0, "lx": loc[0], "ly": loc[1]}
    return {"x": xy[0], "y": xy[1], "dx": 0.0, "dy": 1.0 if dy >= 0 else -1.0, "lx": loc[0], "ly": loc[1]}


def _free_anchor(p, toward) -> dict:
    dx, dy = toward[0] - p[0], toward[1] - p[1]
    h = abs(dx) >= abs(dy)
    return {"x": p[0], "y": p[1], "dx": (1.0 if dx >= 0 else -1.0) if h else 0.0,
            "dy": 0.0 if h else (1.0 if dy >= 0 else -1.0), "free": True}


def _orthogonalise(pts: list) -> list:
    out = [pts[0]]
    for q in pts[1:]:
        p = out[-1]
        if abs(p[0] - q[0]) > 0.5 and abs(p[1] - q[1]) > 0.5:
            prev_h = len(out) > 1 and abs(out[-2][1] - p[1]) < 0.5
            out.append((p[0], q[1]) if prev_h else (q[0], p[1]))
        out.append(q)
    return out


SIMPLIFY_TOL = 0.5


def _same_axis(a, b, p) -> bool:
    t = SIMPLIFY_TOL
    return (abs(a[1] - b[1]) <= t and abs(b[1] - p[1]) <= t) or (abs(a[0] - b[0]) <= t and abs(b[0] - p[0]) <= t)


def _simplify(pts: list) -> list:
    """The editor's ``R.simplify``: drop duplicates (the last point replaces a duplicate previous one)
    and any middle point that shares an axis with its neighbours. The two end points always stay."""
    out: list = []
    last = len(pts) - 1
    for i, p in enumerate(pts):
        dup = False
        while True:
            n = len(out)
            if n and abs(out[-1][0] - p[0]) <= SIMPLIFY_TOL and abs(out[-1][1] - p[1]) <= SIMPLIFY_TOL:
                if i == last and n > 1:
                    out.pop()
                    continue
                dup = True
                break
            if n < 2 or not _same_axis(out[-2], out[-1], p):
                break
            out.pop()
        if not dup:
            out.append(p)
    return out


def _elbow(a: dict, b: dict) -> list:
    sa = (a["x"] + a["dx"] * STUB, a["y"] + a["dy"] * STUB)
    sb = (b["x"] + b["dx"] * STUB, b["y"] + b["dy"] * STUB)
    if abs(a["dx"]) > 0.5:
        mx = (sa[0] + sb[0]) / 2
        mid = [(mx, sa[1]), (mx, sb[1])] if abs(b["dx"]) > 0.5 else [(sb[0], sa[1])]
    else:
        my = (sa[1] + sb[1]) / 2
        mid = [(sa[0], my), (sb[0], my)] if abs(b["dy"]) > 0.5 else [(sa[0], sb[1])]
    return _simplify(_orthogonalise([(a["x"], a["y"]), sa] + mid + [sb, (b["x"], b["y"])]))


def route_ends(c: dict, by_id: dict) -> dict:
    """The chosen anchors of an orthogonal connector (None for a free end or a
    non-orthogonal one): ``{"source": anchor|None, "target": anchor|None}``."""
    src, tgt = by_id.get(c["source"]), by_id.get(c["target"])
    pts = [tuple(p) for p in c["points"]]
    sc = _center(src) if src else None
    tc = _center(tgt) if tgt else None
    s_free = tuple(c["start"]) if len(c["start"]) == 2 else None
    e_free = tuple(c["end"]) if len(c["end"]) == 2 else None
    after_start = pts[0] if pts else (tc or e_free or sc or (0.0, 0.0))
    before_end = pts[-1] if pts else (sc or s_free or tc or (0.0, 0.0))
    if c["routing"] != "orthogonal":
        return {"source": None, "target": None}
    a_s = ((c["source_port"] and _anchor_by_id(src, c["source_port"])) or _nearest_anchor(src, after_start)
           ) if src else _free_anchor(s_free or after_start, after_start)
    a_e = ((c["target_port"] and _anchor_by_id(tgt, c["target_port"])) or _nearest_anchor(tgt, before_end)
           ) if tgt else _free_anchor(e_free or before_end, before_end)
    return {"source": a_s, "target": a_e}


def route_points(c: dict, by_id: dict) -> list[tuple[float, float]]:
    """The polyline's vertices (start, bends, end), computed exactly like the
    editor's ``R.route`` (without its obstacle search: the editor bakes those
    bends into ``points`` before export)."""
    src, tgt = by_id.get(c["source"]), by_id.get(c["target"])
    pts = [tuple(p) for p in c["points"]]
    if src is tgt and src is not None and not pts:
        lx, ly = src["x"] + src["w"], src["y"] + src["h"] / 2
        pts = [(lx + 40, ly - src["h"] / 4), (lx + 40, ly + src["h"] / 4)]
    sc = _center(src) if src else None
    tc = _center(tgt) if tgt else None
    s_free = tuple(c["start"]) if len(c["start"]) == 2 else None
    e_free = tuple(c["end"]) if len(c["end"]) == 2 else None
    after_start = pts[0] if pts else (tc or e_free or sc or (0.0, 0.0))
    before_end = pts[-1] if pts else (sc or s_free or tc or (0.0, 0.0))
    if c["routing"] == "orthogonal":
        a_s = ((c["source_port"] and _anchor_by_id(src, c["source_port"])) or _nearest_anchor(src, after_start)
               ) if src else _free_anchor(s_free or after_start, after_start)
        a_e = ((c["target_port"] and _anchor_by_id(tgt, c["target_port"])) or _nearest_anchor(tgt, before_end)
               ) if tgt else _free_anchor(e_free or before_end, before_end)
        if not pts:
            return _elbow(a_s, a_e)
        body = [(a_s["x"], a_s["y"])]
        if not a_s.get("free"):
            body.append((a_s["x"] + a_s["dx"] * STUB, a_s["y"] + a_s["dy"] * STUB))
        body += pts
        if not a_e.get("free"):
            body.append((a_e["x"] + a_e["dx"] * STUB, a_e["y"] + a_e["dy"] * STUB))
        body.append((a_e["x"], a_e["y"]))
        return _simplify(_orthogonalise(body))
    if src:
        start = (_port_xy(src, c["source_port"]) if c["source_port"] else None) or _clip(src, after_start[0], after_start[1])
    else:
        start = s_free or (pts[0] if pts else (0.0, 0.0))
    if tgt:
        end = (_port_xy(tgt, c["target_port"]) if c["target_port"] else None) or _clip(tgt, before_end[0], before_end[1])
    else:
        end = e_free or (pts[-1] if pts else start)
    return [start] + pts + [end]


def route_segments(c: dict, by_id: dict) -> tuple[list[tuple], list[tuple[float, float]]]:
    """``(segments, polyline)``: ``M/L/C`` segments to draw and the vertices."""
    pts = route_points(c, by_id)
    if len(pts) == 1:
        pts = pts * 2
    segs: list[tuple] = [("M", pts[0][0], pts[0][1])]
    if c["routing"] == "curved":
        if len(pts) == 2:
            (x0, y0), (x1, y1) = pts
            if abs(x1 - x0) >= abs(y1 - y0):
                segs.append(("C", (x0 + x1) / 2, y0, (x0 + x1) / 2, y1, x1, y1))
            else:
                segs.append(("C", x0, (y0 + y1) / 2, x1, (y0 + y1) / 2, x1, y1))
        else:
            for i in range(len(pts) - 1):
                p0 = pts[i - 1] if i > 0 else pts[i]
                p1, p2 = pts[i], pts[i + 1]
                p3 = pts[i + 2] if i + 2 < len(pts) else pts[i + 1]
                segs.append(("C", p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6,
                             p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6, p2[0], p2[1]))
    else:
        for p in pts[1:]:
            segs.append(("L", p[0], p[1]))
    return segs, pts


def flatten(segs: list[tuple], steps: int = 12) -> list[tuple[float, float]]:
    out: list[tuple[float, float]] = []
    cx = cy = 0.0
    for s in segs:
        if s[0] in ("M", "L"):
            cx, cy = s[1], s[2]
            out.append((cx, cy))
        elif s[0] == "C":
            for k in range(1, steps + 1):
                t = k / steps
                u = 1 - t
                out.append((u ** 3 * cx + 3 * u * u * t * s[1] + 3 * u * t * t * s[3] + t ** 3 * s[5],
                            u ** 3 * cy + 3 * u * u * t * s[2] + 3 * u * t * t * s[4] + t ** 3 * s[6]))
            cx, cy = s[5], s[6]
    return out


def point_along(poly: list[tuple[float, float]], pos: float) -> tuple[float, float]:
    if len(poly) == 1:
        return poly[0]
    lens = [math.hypot(poly[i + 1][0] - poly[i][0], poly[i + 1][1] - poly[i][1]) for i in range(len(poly) - 1)]
    total = sum(lens)
    if total <= 0:
        return poly[0]
    goal, acc = pos * total, 0.0
    for i, ln in enumerate(lens):
        if acc + ln >= goal and ln > 0:
            t = (goal - acc) / ln
            return (poly[i][0] + (poly[i + 1][0] - poly[i][0]) * t, poly[i][1] + (poly[i + 1][1] - poly[i][1]) * t)
        acc += ln
    return poly[-1]


def end_angle(poly: list[tuple[float, float]], at_end: bool) -> float:
    """Direction (radians, y down) of the line AT the end, pointing out of the line."""
    pts = poly[::-1] if at_end else poly
    a = pts[0]
    for b in pts[1:]:
        if abs(b[0] - a[0]) > 1e-6 or abs(b[1] - a[1]) > 1e-6:
            # outward direction at `a` is away from b
            return math.atan2(a[1] - b[1], a[0] - b[0])
    return 0.0


# Arrow glyphs in a local frame: the tip is at the origin and the glyph points
# along +x (it extends toward -x). ``fill``: "stroke" | "white" | None.
ARROW_GLYPHS = {
    "arrow": [{"t": "poly", "pts": [(0, 0), (-11, -4.5), (-11, 4.5)], "fill": "stroke"}],
    "open": [{"t": "line", "pts": [(-11, -5), (0, 0), (-11, 5)], "fill": None}],
    "diamond": [{"t": "poly", "pts": [(0, 0), (-7, -4.5), (-14, 0), (-7, 4.5)], "fill": "stroke"}],
    "diamond_open": [{"t": "poly", "pts": [(0, 0), (-7, -4.5), (-14, 0), (-7, 4.5)], "fill": "white"}],
    "circle": [{"t": "circle", "c": (-4.5, 0), "r": 4.5, "fill": "stroke"}],
    "circle_open": [{"t": "circle", "c": (-4.5, 0), "r": 4.5, "fill": "white"}],
    "crowfoot": [{"t": "line", "pts": [(0, -6), (-11, 0), (0, 6)], "fill": None},
                 {"t": "line", "pts": [(0, 0), (-11, 0)], "fill": None}],
    "bar": [{"t": "line", "pts": [(-4, -6), (-4, 6)], "fill": None}],
}


# ------------------------------------------------------------------ icons

class Icons:
    """Resolves ``<library>/<id>`` symbols to SANITISED icon markup.

    ``options["libraries"]`` ({lib: {symbol id: svg text}}) wins; otherwise the
    built-in library (``symbols.load_builtin``) is used. Whatever the source,
    the markup is re-sanitised with ``symbols.sanitize_svg`` (operator
    libraries come from the database). Problems are appended to
    ``options["warnings"]`` when the caller passed a list.
    """

    def __init__(self, options: dict | None):
        self.options = options or {}
        self.libs = self.options.get("libraries") if isinstance(self.options.get("libraries"), dict) else {}
        self.cache: dict = {}
        self.warned: set = set()
        self._builtin = None

    def warn(self, msg: str) -> None:
        w = self.options.get("warnings")
        if isinstance(w, list) and msg not in self.warned:
            self.warned.add(msg)
            w.append(msg)

    def _raw(self, lib: str, sid: str):
        mine = self.libs.get(lib)
        if isinstance(mine, dict) and sid in mine:
            return mine[sid]
        if self._builtin is None:
            try:
                from .. import symbols
                self._builtin = symbols.load_builtin()
            except Exception:
                self._builtin = {}
        for s in (self._builtin.get(lib) or {}).get("symbols", []):
            if s["id"] == sid:
                return s.get("svg_text")
        return None

    def get(self, symbol: str):
        """``{id, vb, root, inner, svg}`` or None (with a warning) when unusable."""
        if not symbol or "/" not in symbol:
            return None
        if symbol in self.cache:
            return self.cache[symbol]
        out = None
        lib, _, sid = symbol.partition("/")
        raw = self._raw(lib, sid)
        if raw is None:
            self.warn("symbol %s is not in any library; drawn as a plain shape" % symbol)
        else:
            try:
                from .. import symbols
                clean = symbols.sanitize_svg(raw)
                from xml.etree import ElementTree as ET
                root = ET.fromstring(clean)
                vb = [float(v) for v in root.get("viewBox", "").split()]
                if len(vb) != 4 or vb[2] <= 0 or vb[3] <= 0:
                    raise ValueError("bad viewBox")
                head, _, rest = clean.partition(">")
                inner = rest[:-len("</svg>")]
                attrs = {k: v for k, v in root.attrib.items() if k != "viewBox"}
                out = {"id": "sym-%s-%s" % (lib, sid), "vb": tuple(vb), "root": attrs, "inner": inner,
                       "svg": clean, "tree": root, "head": head}
            except Exception as exc:                     # SvgRejected, parse errors, missing module
                self.warn("symbol %s was refused (%s); drawn as a plain shape" % (symbol, str(exc)[:80]))
        self.cache[symbol] = out
        return out


ICON_MAX = 18.0
ICON_PAD = 4.0
_SQRT_HALF = 0.7071067811865476
# Inner "safe" rectangles of the fraction-based outlines, as (x0, y0, x1, y1) of w and h:
# the largest convenient axis-aligned box that lies inside the outline at ANY w and h
# (the outlines scale x and y independently). Kept equal to SAFE_FRACTIONS in
# diagram_studio_render.js; tests/_diagram_icon_table.py holds the editor's numbers.
SAFE_FRACTIONS = {
    "ellipse": ((1 - _SQRT_HALF) / 2, (1 - _SQRT_HALF) / 2, (1 + _SQRT_HALF) / 2, (1 + _SQRT_HALF) / 2),
    "diamond": (0.25, 0.25, 0.75, 0.75),
    "hexagon": (0.25, 0.0, 0.75, 1.0),
    "parallelogram": (0.2, 0.0, 0.8, 1.0),
    "trapezoid": (0.2, 0.0, 0.8, 1.0),
    "triangle": (0.25, 0.5, 0.75, 1.0),
    "cloud": (0.2, 0.3, 0.8, 0.7),
    "document": (0.0, 0.0, 1.0, 0.76),
}


def icon_safe_box(el: dict) -> tuple[float, float, float, float]:
    """``(x, y, w, h)``, element-local: the part of the box that is inside the outline,
    where a corner icon may go (rounded corners, the cylinder's rims, the note's fold
    and the process bands excluded). Free outlines (polygon, path) and outlines with
    no interior (actor, line) use the whole box."""
    shape, w, h = el["shape"], max(el["w"], 0.0), max(el["h"], 0.0)
    fr = SAFE_FRACTIONS.get(shape)
    if fr is not None:
        return fr[0] * w, fr[1] * h, (fr[2] - fr[0]) * w, (fr[3] - fr[1]) * h
    r = None
    if shape == "round":
        r = min(w, h) * 0.12
    elif shape in ("terminator", "pill"):
        r = min(w, h) / 2
    elif shape == "cylinder":
        ry = max(1.0, min(h * 0.15, h / 2 - 0.5))
        return 0.0, 2 * ry, w, max(0.0, h - 3 * ry)
    elif shape == "note":
        f = max(0.0, min(14.0, w / 3, h / 3))
        return 0.0, 0.0, max(0.0, w - f), h
    elif shape == "process":
        f = min(w * 0.1, 20.0)
        return f, 0.0, max(0.0, w - 2 * f), h
    elif shape not in ("table", "swimlane", "actor", "line", "polygon", "path") and el["style"].get("rounded"):
        r = min(w, h) * 0.12
    if r:
        i = r * (1 - _SQRT_HALF)            # the 45-degree point of the corner arc
        return i, i, max(0.0, w - 2 * i), max(0.0, h - 2 * i)
    return 0.0, 0.0, w, h


def icon_box(el: dict):
    """The editor's icon rule: ``(x, y, size, big)`` in element-local px, or None.

    A ``symbol`` shape shows a large centred icon (72 % of the short side) with the label below;
    any other element with a symbol shows a small icon (max 18 px) at the top-left of the
    shape's inner safe box (:func:`icon_safe_box`) with a 4 px pad, so it never sits outside
    a cloud, an ellipse, a diamond...; it shrinks to fit that box and is dropped under 8 px.
    """
    if not el.get("symbol") or el["kind"] == "image":
        return None
    big = el["shape"] == "symbol"
    short = min(el["w"], el["h"])
    if big:
        size = short * 0.72
        return (el["w"] - size) / 2, (el["h"] - size) / 2, size, True
    sx, sy, sw, sh = icon_safe_box(el)
    size = min(ICON_MAX, short * 0.4, sw - 2 * ICON_PAD, sh - 2 * ICON_PAD)
    if size < 8:
        return None
    return sx + ICON_PAD, sy + ICON_PAD, size, False


ICON_GAP = 2.0
MIN_TEXT_W = 24.0


def make_room_for_icon(el: dict, blocks: list[dict]) -> list[dict]:
    """Text that would run under a corner icon moves clear of it. The text is laid out
    as the editor lays it out (same wrapping, same approximate measure, 1.2 line height,
    alignment); if it already misses the icon the block is left alone. Otherwise it
    starts under the icon when it fits there at full width, else it is narrowed past
    the icon column (both sides for centred text, so it stays centred), and when that
    leaves under 24 px it starts under the icon anyway, top-aligned so text too tall
    for a tiny shape overflows downwards. Same rule as the editor's."""
    ib = icon_box(el)
    if not ib or ib[3]:
        return blocks
    ix, iy, s, _ = ib
    fs = float(el["style"].get("font_size") or 12)
    lh = fs * 1.2
    out = []
    for b in blocks:
        if b.get("below"):
            out.append(b)
            continue
        m = _plain_measure(fs, bool(b["bold"]))
        lines = wrap_lines(b["text"], b["w"], m)
        if not lines:
            out.append(b)
            continue
        total = lh * len(lines)
        lw = max(m(ln) for ln in lines)
        ty = b["y"] if b["valign"] == "top" else (b["y"] + b["h"] - total if b["valign"] == "bottom" else b["y"] + (b["h"] - total) / 2)
        tx = b["x"] if b["align"] == "left" else (b["x"] + b["w"] - lw if b["align"] == "right" else b["x"] + (b["w"] - lw) / 2)
        if ty >= iy + s + ICON_GAP or ty + total <= iy or tx >= ix + s + ICON_GAP or tx + lw <= ix:
            out.append(b)
            continue
        b = dict(b)
        top = iy + s + ICON_GAP
        inset = ix + s + ICON_GAP - b["x"]
        nw = b["w"] - (inset if b["align"] == "left" else 2 * inset)
        if b["y"] + b["h"] - top >= total or nw < MIN_TEXT_W:
            b["h"], b["y"] = max(0.0, b["y"] + b["h"] - top), top
            if b["h"] < total:
                b["valign"] = "top"           # too tall for what is left: overflow downwards, not over the icon
        else:
            b["x"], b["w"] = b["x"] + inset, nw
        out.append(b)
    return out


# ------------------------------------------------------------ export bounds

EXPORT_MARGIN = 10.0
EXPORT_TOLERANCE = 1.0
CONN_LABEL_FS = 11.0


def _plain_measure(fs: float, bold: bool):
    k = 0.58 if bold else 0.54
    return lambda s: len(s) * fs * k


def content_box(pg: dict, measure=None, visible_only: bool = False):
    """``(x0, y0, x1, y1)`` of everything drawn on the page, or None: rotated outlines with
    half their stroke, drop shadows (offset and blur), the label under a symbol, connector
    routes with waypoints and curves, arrowheads, connector labels and their halo."""
    measure = measure or _plain_measure
    vis = {lr["id"] for lr in pg["layers"] if lr["visible"]} if visible_only else None
    by_id = {e["id"]: e for e in pg["elements"]}
    xs: list[float] = []
    ys: list[float] = []

    def grow(pts, lo, hi=None):
        hi = lo if hi is None else hi
        for x, y in pts:
            xs.extend((x - lo[0], x + hi[0]))
            ys.extend((y - lo[1], y + hi[1]))

    blur = 3 * SHADOW_BLUR
    for e in pg["elements"]:
        if vis is not None and e["layer"] not in vis:
            continue
        st = e["style"]
        cx, cy = _center(e)
        rot = e.get("rotation") or 0.0

        def corners(x0, y0, x1, y1):
            return [_rot(e["x"] + px, e["y"] + py, cx, cy, rot) for px, py in ((x0, y0), (x1, y0), (x1, y1), (x0, y1))]
        sw = (st["stroke_width"] / 2.0) if st["stroke"] != "none" else 0.0
        box = corners(0.0, 0.0, e["w"], e["h"])
        grow(box, (sw, sw))
        if st.get("shadow") and st["fill"] != "none":
            grow(box, (max(0.0, blur - SHADOW_DX), max(0.0, blur - SHADOW_DY)), (SHADOW_DX + blur, SHADOW_DY + blur))
        for b in text_blocks(e):
            if not b.get("below"):
                continue
            fs = float(st["font_size"])
            m = measure(fs, bool(b["bold"]))
            lines = wrap_lines(b["text"], b["w"], m)
            if not lines:
                continue
            lw = max(m(ln) for ln in lines) + 3.0             # + the white halo
            mid = b["x"] + b["w"] / 2.0
            grow(corners(mid - lw / 2, b["y"] - 1.5, mid + lw / 2, b["y"] + fs * 1.2 * len(lines) + 1.5), (0.0, 0.0))
    for c in pg["connectors"]:
        if vis is not None and c["layer"] not in vis:
            continue
        st = c["style"]
        segs, pts = route_segments(c, by_id)
        flat = flatten(segs) or pts                        # curves bulge past their vertices
        if not flat:
            continue
        sw = st["stroke_width"]
        grow(flat, (sw / 2.0, sw / 2.0))
        for at, arrow in ((flat[0], c["start_arrow"]), (flat[-1], c["end_arrow"])):
            if arrow and arrow != "none":
                pad = 9.0 * max(1.0, sw) + 1.0
                grow([at], (pad, pad))
        if st.get("shadow"):
            grow(flat, (blur, blur), (SHADOW_DX + blur + sw, SHADOW_DY + blur + sw))
        texts = ([(c["label"], 0.5)] if c["label"] else []) + [(lb["text"], lb["pos"]) for lb in c["labels"]]
        m = measure(CONN_LABEL_FS, False)
        for text, pos in texts:
            x, y = point_along(flat, pos)
            half = max((m(ln) for ln in str(text).split("\n")), default=0.0) / 2 + 1.5
            xs.extend((x - half, x + half))
            ys.extend((y - 4 - CONN_LABEL_FS - 1.5, y - 4 + 3 + 1.5))
    if not xs:
        return None
    return min(xs), min(ys), max(xs), max(ys)


def export_box(pg: dict, measure=None, visible_only: bool = False) -> tuple[float, float, float, float]:
    """``(x, y, w, h)`` of the picture an SVG / PNG / PDF export draws: the page box,
    grown on each side where the content goes beyond it (by more than 1 px) to the
    content plus a 10 px margin, in whole px. Content inside the page leaves the
    page box exactly as it was. The model's geometry is never moved."""
    x0, y0, x1, y1 = 0.0, 0.0, float(pg["width"]), float(pg["height"])
    cb = content_box(pg, measure, visible_only)
    if cb is not None:
        if cb[0] < x0 - EXPORT_TOLERANCE:
            x0 = math.floor(cb[0] - EXPORT_MARGIN)
        if cb[1] < y0 - EXPORT_TOLERANCE:
            y0 = math.floor(cb[1] - EXPORT_MARGIN)
        if cb[2] > x1 + EXPORT_TOLERANCE:
            x1 = math.ceil(cb[2] + EXPORT_MARGIN)
        if cb[3] > y1 + EXPORT_TOLERANCE:
            y1 = math.ceil(cb[3] + EXPORT_MARGIN)
    return x0, y0, x1 - x0, y1 - y0
