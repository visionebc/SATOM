"""Geometry shared by the vector importers (SVG, PDF, and any reader that has
absolute coordinates): affine matrices, SVG path parsing, bounding boxes,
point/segment/rectangle distances, element snapping and arrowhead detection.

Pure Python, standard library only, no imports from the rest of SATOM.
Everything works in the y-DOWN pixel space of ``satom.diagram/1``; angles are
degrees, clockwise on screen (which is what ``atan2(b, a)`` gives in y-down
space).

Conventions
-----------
* A matrix is the SVG six-tuple ``(a, b, c, d, e, f)``:
  ``x' = a*x + c*y + e``, ``y' = b*x + d*y + f``.
* A rect is ``(x, y, w, h)`` (top-left corner and size).
* A path segment is one of ``("M", x, y)``, ``("L", x, y)``,
  ``("C", x1, y1, x2, y2, x, y)`` or ``("Z",)``, always ABSOLUTE.
"""
from __future__ import annotations

import math
import re

Matrix = tuple
IDENTITY: Matrix = (1.0, 0.0, 0.0, 1.0, 0.0, 0.0)

MAX_PATH_SEGMENTS = 50_000
MAX_TRANSFORM_ITEMS = 64
MAX_TRANSFORM_LEN = 4096

_EPS = 1e-9


# ===================================================================== matrices

def multiply(m1: Matrix, m2: Matrix) -> Matrix:
    """``m1 . m2``: apply *m2* first, then *m1* (parent . child)."""
    a1, b1, c1, d1, e1, f1 = m1
    a2, b2, c2, d2, e2, f2 = m2
    return (a1 * a2 + c1 * b2, b1 * a2 + d1 * b2,
            a1 * c2 + c1 * d2, b1 * c2 + d1 * d2,
            a1 * e2 + c1 * f2 + e1, b1 * e2 + d1 * f2 + f1)


def compose(*ms: Matrix) -> Matrix:
    """Left-to-right product: ``compose(parent, child)`` applies *child* first."""
    out = IDENTITY
    for m in ms:
        out = multiply(out, m)
    return out


def translate(tx: float, ty: float = 0.0) -> Matrix:
    return (1.0, 0.0, 0.0, 1.0, float(tx), float(ty))


def scale(sx: float, sy: float | None = None) -> Matrix:
    return (float(sx), 0.0, 0.0, float(sx if sy is None else sy), 0.0, 0.0)


def rotate(deg: float, cx: float = 0.0, cy: float = 0.0) -> Matrix:
    r = math.radians(deg)
    c, s = math.cos(r), math.sin(r)
    rot = (c, s, -s, c, 0.0, 0.0)
    if cx or cy:
        return compose(translate(cx, cy), rot, translate(-cx, -cy))
    return rot


def skew_x(deg: float) -> Matrix:
    return (1.0, 0.0, math.tan(math.radians(deg)), 1.0, 0.0, 0.0)


def skew_y(deg: float) -> Matrix:
    return (1.0, math.tan(math.radians(deg)), 0.0, 1.0, 0.0, 0.0)


_NUM = r"[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?"
_NUM_RE = re.compile(_NUM)
_TRANSFORM_ITEM_RE = re.compile(r"\s*,?\s*([A-Za-z]+)\s*\(([^()]*)\)")


def parse_transform(value: str | None) -> Matrix:
    """An SVG ``transform`` list -> one matrix.

    Supports matrix, translate, scale, rotate(a [cx cy]), skewX, skewY. An
    unknown or malformed item is skipped (the SVG error model would drop the
    whole attribute; being lenient here costs nothing and loses nothing a
    diagram needs). Non-finite results fall back to identity.
    """
    if not value or not isinstance(value, str):
        return IDENTITY
    value = value[:MAX_TRANSFORM_LEN]
    m = IDENTITY
    pos, n = 0, 0
    while pos < len(value) and n < MAX_TRANSFORM_ITEMS:
        mo = _TRANSFORM_ITEM_RE.match(value, pos)
        if not mo:
            break
        pos = mo.end()
        n += 1
        name = mo.group(1).lower()
        args = [float(x) for x in _NUM_RE.findall(mo.group(2))]
        item = None
        if name == "matrix" and len(args) == 6:
            item = tuple(args)
        elif name == "translate" and len(args) in (1, 2):
            item = translate(args[0], args[1] if len(args) == 2 else 0.0)
        elif name == "scale" and len(args) in (1, 2):
            item = scale(args[0], args[1] if len(args) == 2 else None)
        elif name == "rotate" and len(args) in (1, 3):
            item = rotate(*args)
        elif name == "skewx" and len(args) == 1:
            item = skew_x(args[0])
        elif name == "skewy" and len(args) == 1:
            item = skew_y(args[0])
        if item is not None:
            m = multiply(m, item)
    if not all(math.isfinite(v) for v in m):
        return IDENTITY
    return m


def apply(m: Matrix, x: float, y: float) -> tuple:
    return (m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5])


def apply_points(m: Matrix, pts) -> list:
    return [apply(m, p[0], p[1]) for p in pts]


def determinant(m: Matrix) -> float:
    return m[0] * m[3] - m[1] * m[2]


def mean_scale(m: Matrix) -> float:
    """sqrt(|det|): the factor an isotropic length (stroke width) scales by."""
    return math.sqrt(abs(determinant(m)))


def decompose(m: Matrix) -> dict | None:
    """``{"rotation", "sx", "sy", "tx", "ty"}`` when *m* is rotation + axis scale
    + translation (+ possibly a mirror); ``None`` when it carries a skew or is
    degenerate. A shape under such a matrix stays a rect/ellipse with
    ``rotation``; under any other matrix the caller must bake the points.
    """
    a, b, c, d, e, f = m
    sx = math.hypot(a, b)
    sy = math.hypot(c, d)
    if sx < _EPS or sy < _EPS:
        return None
    if abs(a * c + b * d) > 1e-3 * sx * sy:
        return None
    rot = math.degrees(math.atan2(b, a))
    if rot <= -180.0:
        rot += 360.0
    return {"rotation": rot, "sx": sx, "sy": sy, "tx": e, "ty": f}


# ===================================================================== path data

class _Scanner:
    """Hand scanner for path data (arc flags may be glued: ``a1 1 0 00 1 1``)."""

    def __init__(self, s: str):
        self.s = s
        self.i = 0
        self.n = len(s)

    def skip(self):
        while self.i < self.n and self.s[self.i] in " \t\r\n,":
            self.i += 1

    def eof(self) -> bool:
        self.skip()
        return self.i >= self.n

    def peek_cmd(self):
        self.skip()
        if self.i < self.n and self.s[self.i].isalpha():
            return self.s[self.i]
        return None

    def number(self):
        self.skip()
        mo = _NUM_RE.match(self.s, self.i)
        if not mo:
            return None
        self.i = mo.end()
        try:
            v = float(mo.group(0))
        except ValueError:
            return None
        return v if math.isfinite(v) else None

    def flag(self):
        self.skip()
        if self.i < self.n and self.s[self.i] in "01":
            v = float(self.s[self.i])
            self.i += 1
            return v
        return None


_ARGS = {"M": 2, "L": 2, "H": 1, "V": 1, "C": 6, "S": 4, "Q": 4, "T": 2, "A": 7, "Z": 0}


def _arc_to_cubics(x1, y1, rx, ry, phi_deg, fa, fs, x2, y2) -> list:
    """SVG arc (endpoint form) -> list of cubic segments (W3C implementation notes F.6)."""
    if abs(x1 - x2) < _EPS and abs(y1 - y2) < _EPS:
        return []
    rx, ry = abs(rx), abs(ry)
    if rx < _EPS or ry < _EPS:
        return [("L", x2, y2)]
    phi = math.radians(phi_deg % 360.0)
    cp, sp = math.cos(phi), math.sin(phi)
    dx2, dy2 = (x1 - x2) / 2.0, (y1 - y2) / 2.0
    x1p = cp * dx2 + sp * dy2
    y1p = -sp * dx2 + cp * dy2
    lam = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry)
    if lam > 1.0:
        k = math.sqrt(lam)
        rx, ry = rx * k, ry * k
    num = rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p
    den = rx * rx * y1p * y1p + ry * ry * x1p * x1p
    coef = math.sqrt(max(0.0, num / den)) if den > _EPS else 0.0
    if bool(fa) == bool(fs):
        coef = -coef
    cxp = coef * rx * y1p / ry
    cyp = -coef * ry * x1p / rx
    cx = cp * cxp - sp * cyp + (x1 + x2) / 2.0
    cy = sp * cxp + cp * cyp + (y1 + y2) / 2.0

    def ang(ux, uy, vx, vy):
        dot = ux * vx + uy * vy
        ln = math.hypot(ux, uy) * math.hypot(vx, vy)
        if ln < _EPS:
            return 0.0
        a = math.acos(max(-1.0, min(1.0, dot / ln)))
        return -a if ux * vy - uy * vx < 0 else a

    th1 = ang(1.0, 0.0, (x1p - cxp) / rx, (y1p - cyp) / ry)
    dth = ang((x1p - cxp) / rx, (y1p - cyp) / ry, (-x1p - cxp) / rx, (-y1p - cyp) / ry)
    if not fs and dth > 0:
        dth -= 2.0 * math.pi
    elif fs and dth < 0:
        dth += 2.0 * math.pi
    nseg = max(1, int(math.ceil(abs(dth) / (math.pi / 2.0) - 1e-9)))
    delta = dth / nseg
    t = 4.0 / 3.0 * math.tan(delta / 4.0)
    out = []
    a1 = th1
    for k in range(nseg):
        a2 = a1 + delta
        c1, s1 = math.cos(a1), math.sin(a1)
        c2, s2 = math.cos(a2), math.sin(a2)
        p = [(c1 - t * s1, s1 + t * c1), (c2 + t * s2, s2 - t * c2), (c2, s2)]
        pts = []
        for ux, uy in p:
            X = rx * ux
            Y = ry * uy
            pts.append((cp * X - sp * Y + cx, sp * X + cp * Y + cy))
        if k == nseg - 1:
            pts[2] = (x2, y2)
        out.append(("C", pts[0][0], pts[0][1], pts[1][0], pts[1][1], pts[2][0], pts[2][1]))
        a1 = a2
    return out


def parse_path(d: str | None) -> list:
    """SVG path data -> list of ABSOLUTE segments (M, L, C, Z).

    H/V/relative commands/S/Q/T/arcs are all normalised (quadratics are raised
    to cubics, arcs are split into cubics, <= 90 degrees each). Parsing stops
    at the first malformed command and keeps what came before, like a
    renderer. At most :data:`MAX_PATH_SEGMENTS` segments are produced.
    """
    if not d or not isinstance(d, str):
        return []
    sc = _Scanner(d[:2_000_000])
    segs: list = []
    cx = cy = sx = sy = 0.0           # current point, subpath start
    lcx = lcy = None                  # last cubic control (for S)
    lqx = lqy = None                  # last quad control (for T)
    cmd = None
    started = False
    while not sc.eof():
        if len(segs) > MAX_PATH_SEGMENTS:
            break
        c = sc.peek_cmd()
        if c is not None:
            if c.upper() not in _ARGS:
                break
            sc.i += 1
            cmd = c
            if not started and cmd.upper() != "M":
                break
            if cmd.upper() == "Z":
                if started:
                    segs.append(("Z",))
                    cx, cy = sx, sy
                lcx = lcy = lqx = lqy = None
                continue
        elif cmd is None or cmd.upper() == "Z":
            break
        up = cmd.upper()
        rel = cmd != up
        n = _ARGS[up]
        vals = []
        for k in range(n):
            if up == "A" and k in (3, 4):
                v = sc.flag()
            else:
                v = sc.number()
            if v is None:
                vals = None
                break
            vals.append(v)
        if vals is None:
            break
        ox, oy = (cx, cy) if rel else (0.0, 0.0)
        if up == "M":
            cx, cy = vals[0] + ox, vals[1] + oy
            sx, sy = cx, cy
            segs.append(("M", cx, cy))
            started = True
            cmd = "l" if rel else "L"          # implicit lineto after moveto
            lcx = lcy = lqx = lqy = None
        elif up == "L":
            cx, cy = vals[0] + ox, vals[1] + oy
            segs.append(("L", cx, cy))
            lcx = lcy = lqx = lqy = None
        elif up == "H":
            cx = vals[0] + (cx if rel else 0.0)
            segs.append(("L", cx, cy))
            lcx = lcy = lqx = lqy = None
        elif up == "V":
            cy = vals[0] + (cy if rel else 0.0)
            segs.append(("L", cx, cy))
            lcx = lcy = lqx = lqy = None
        elif up == "C":
            x1, y1 = vals[0] + ox, vals[1] + oy
            x2, y2 = vals[2] + ox, vals[3] + oy
            x, y = vals[4] + ox, vals[5] + oy
            segs.append(("C", x1, y1, x2, y2, x, y))
            lcx, lcy, lqx, lqy = x2, y2, None, None
            cx, cy = x, y
        elif up == "S":
            x1, y1 = (2 * cx - lcx, 2 * cy - lcy) if lcx is not None else (cx, cy)
            x2, y2 = vals[0] + ox, vals[1] + oy
            x, y = vals[2] + ox, vals[3] + oy
            segs.append(("C", x1, y1, x2, y2, x, y))
            lcx, lcy, lqx, lqy = x2, y2, None, None
            cx, cy = x, y
        elif up in ("Q", "T"):
            if up == "Q":
                qx, qy = vals[0] + ox, vals[1] + oy
                x, y = vals[2] + ox, vals[3] + oy
            else:
                qx, qy = (2 * cx - lqx, 2 * cy - lqy) if lqx is not None else (cx, cy)
                x, y = vals[0] + ox, vals[1] + oy
            segs.append(("C", cx + 2.0 / 3.0 * (qx - cx), cy + 2.0 / 3.0 * (qy - cy),
                         x + 2.0 / 3.0 * (qx - x), y + 2.0 / 3.0 * (qy - y), x, y))
            lqx, lqy, lcx, lcy = qx, qy, None, None
            cx, cy = x, y
        elif up == "A":
            x, y = vals[5] + ox, vals[6] + oy
            arcs = _arc_to_cubics(cx, cy, vals[0], vals[1], vals[2], vals[3], vals[4], x, y)
            segs.extend(arcs)
            lcx = lcy = lqx = lqy = None
            cx, cy = x, y
    return segs


def transform_segments(segs: list, m: Matrix) -> list:
    out = []
    for s in segs:
        if s[0] == "Z":
            out.append(s)
        else:
            vals = []
            for k in range(1, len(s), 2):
                x, y = apply(m, s[k], s[k + 1])
                vals.extend((x, y))
            out.append((s[0], *vals))
    return out


def _cubic_point(p0, p1, p2, p3, t):
    u = 1.0 - t
    a, b, c, d = u * u * u, 3 * u * u * t, 3 * u * t * t, t * t * t
    return (a * p0[0] + b * p1[0] + c * p2[0] + d * p3[0],
            a * p0[1] + b * p1[1] + c * p2[1] + d * p3[1])


def flatten(segs: list, steps: int | None = None) -> list:
    """Segments -> ``[(points, closed), ...]`` one entry per subpath.

    Cubics are sampled adaptively (4..48 points by control-polygon length) or
    with a fixed *steps*. A closed subpath does NOT repeat its first point.
    """
    subs: list = []
    pts: list = []
    closed = False
    cur = (0.0, 0.0)
    start = cur

    def flush():
        nonlocal pts, closed
        if pts:
            if closed and len(pts) > 1 and abs(pts[0][0] - pts[-1][0]) < 1e-6 and abs(pts[0][1] - pts[-1][1]) < 1e-6:
                pts = pts[:-1]
            subs.append((pts, closed))
        pts, closed = [], False

    for s in segs:
        k = s[0]
        if k == "M":
            flush()
            cur = start = (s[1], s[2])
            pts = [cur]
        elif k == "L":
            if not pts:
                pts = [cur]
            cur = (s[1], s[2])
            pts.append(cur)
        elif k == "C":
            if not pts:
                pts = [cur]
            p0, p1, p2, p3 = cur, (s[1], s[2]), (s[3], s[4]), (s[5], s[6])
            if steps:
                n = steps
            else:
                ln = (math.hypot(p1[0] - p0[0], p1[1] - p0[1]) + math.hypot(p2[0] - p1[0], p2[1] - p1[1])
                      + math.hypot(p3[0] - p2[0], p3[1] - p2[1]))
                n = max(4, min(48, int(ln / 4.0)))
            for i in range(1, n + 1):
                pts.append(_cubic_point(p0, p1, p2, p3, i / n))
            cur = p3
        elif k == "Z":
            if pts:
                closed = True
                flush()
                cur = start
    flush()
    return subs


def has_curves(segs: list) -> bool:
    return any(s[0] == "C" for s in segs)


def bbox_of_points(pts) -> tuple | None:
    """``(x0, y0, x1, y1)`` or ``None`` for an empty list."""
    if not pts:
        return None
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    return (min(xs), min(ys), max(xs), max(ys))


def path_bbox(segs: list) -> tuple | None:
    """Bounding box ``(x0, y0, x1, y1)`` of a path (curves sampled)."""
    pts = []
    for sub, _ in flatten(segs, steps=16):
        pts.extend(sub)
    return bbox_of_points(pts)


def _fmt(v: float) -> str:
    s = "%.3f" % v
    s = s.rstrip("0").rstrip(".") if "." in s else s
    return "0" if s in ("-0", "") else s


def segments_to_d(segs: list, ox: float = 0.0, oy: float = 0.0) -> str:
    """Absolute segments -> path data, shifted by ``(-ox, -oy)`` (box coordinates)."""
    out = []
    for s in segs:
        if s[0] == "Z":
            out.append("Z")
            continue
        vals = []
        for k in range(1, len(s), 2):
            vals.append(_fmt(s[k] - ox))
            vals.append(_fmt(s[k + 1] - oy))
        out.append(s[0] + " ".join(vals))
    return " ".join(out)


# ===================================================================== distances

def point_rect_distance(point, rect) -> float:
    """Distance from a point to a rect ``(x, y, w, h)``; 0 inside or on the edge."""
    px, py = point
    x, y, w, h = rect
    dx = max(x - px, 0.0, px - (x + w))
    dy = max(y - py, 0.0, py - (y + h))
    return math.hypot(dx, dy)


def boundary_distance(point, rect) -> float:
    """Distance to the OUTLINE of the rect (inside or outside)."""
    px, py = point
    x, y, w, h = rect
    d = point_rect_distance(point, rect)
    if d > 0:
        return d
    return max(0.0, min(px - x, x + w - px, py - y, y + h - py))


def snap_to_rect(point, rect) -> tuple:
    """Relative ``(rx, ry)`` (0..1 of the box) of the point snapped onto the
    rect outline: clamped when outside, moved to the nearest edge when inside."""
    px, py = point
    x, y, w, h = rect
    cx = min(max(px, x), x + w)
    cy = min(max(py, y), y + h)
    if x < px < x + w and y < py < y + h:
        dl, dr, dt, db = px - x, x + w - px, py - y, y + h - py
        m = min(dl, dr, dt, db)
        if m == dl:
            cx = x
        elif m == dr:
            cx = x + w
        elif m == dt:
            cy = y
        else:
            cy = y + h
    rx = (cx - x) / w if w > _EPS else 0.5
    ry = (cy - y) / h if h > _EPS else 0.5
    return (round(min(1.0, max(0.0, rx)), 4), round(min(1.0, max(0.0, ry)), 4))


def point_segment_distance(p, a, b) -> tuple:
    """``(distance, t)`` from point to segment a-b, t in 0..1 along it."""
    abx, aby = b[0] - a[0], b[1] - a[1]
    L2 = abx * abx + aby * aby
    if L2 < _EPS:
        return math.hypot(p[0] - a[0], p[1] - a[1]), 0.0
    t = max(0.0, min(1.0, ((p[0] - a[0]) * abx + (p[1] - a[1]) * aby) / L2))
    return math.hypot(p[0] - (a[0] + t * abx), p[1] - (a[1] + t * aby)), t


def polyline_length(pts) -> float:
    return sum(math.hypot(pts[i + 1][0] - pts[i][0], pts[i + 1][1] - pts[i][1]) for i in range(len(pts) - 1))


def point_polyline_distance(p, pts) -> tuple:
    """``(distance, t)``: distance to the polyline and the position 0..1 of the
    closest point measured along its length."""
    if not pts:
        return math.inf, 0.0
    if len(pts) == 1:
        return math.hypot(p[0] - pts[0][0], p[1] - pts[0][1]), 0.0
    total = polyline_length(pts) or 1.0
    best, best_t, run = math.inf, 0.0, 0.0
    for i in range(len(pts) - 1):
        a, b = pts[i], pts[i + 1]
        seg = math.hypot(b[0] - a[0], b[1] - a[1])
        d, t = point_segment_distance(p, a, b)
        if d < best:
            best, best_t = d, (run + t * seg) / total
        run += seg
    return best, best_t


def _segments_intersect(a, b, c, d) -> bool:
    def orient(p, q, r):
        return (q[0] - p[0]) * (r[1] - p[1]) - (q[1] - p[1]) * (r[0] - p[0])
    o1, o2, o3, o4 = orient(a, b, c), orient(a, b, d), orient(c, d, a), orient(c, d, b)
    return (o1 > 0) != (o2 > 0) and (o3 > 0) != (o4 > 0)


def polyline_rect_distance(pts, rect) -> tuple:
    """``(distance, t)`` between a polyline and a rect (0 when they overlap);
    t = position 0..1 along the polyline of the closest point."""
    if not pts:
        return math.inf, 0.0
    x, y, w, h = rect
    corners = [(x, y), (x + w, y), (x + w, y + h), (x, y + h)]
    edges = [(corners[i], corners[(i + 1) % 4]) for i in range(4)]
    total = polyline_length(pts) or 1.0
    best, best_t, run = math.inf, 0.0, 0.0
    for i in range(max(1, len(pts) - 1)):
        a = pts[i]
        b = pts[i + 1] if len(pts) > 1 else pts[i]
        seg = math.hypot(b[0] - a[0], b[1] - a[1])
        if point_rect_distance(a, rect) == 0.0 or point_rect_distance(b, rect) == 0.0:
            d, t = 0.0, 0.0
        elif any(_segments_intersect(a, b, e0, e1) for e0, e1 in edges):
            d, t = 0.0, 0.5
        else:
            d = min(point_rect_distance(a, rect), point_rect_distance(b, rect),
                    *(point_segment_distance(c, a, b)[0] for c in corners))
            t = 0.5
        if d < best:
            best, best_t = d, (run + t * seg) / total
        run += seg
    return best, best_t


def rect_union(rects) -> tuple | None:
    rs = [r for r in rects if r]
    if not rs:
        return None
    x0 = min(r[0] for r in rs)
    y0 = min(r[1] for r in rs)
    x1 = max(r[0] + r[2] for r in rs)
    y1 = max(r[1] + r[3] for r in rs)
    return (x0, y0, x1 - x0, y1 - y0)


def rotated_rect_bbox(rect, rotation: float) -> tuple:
    """Axis-aligned bbox ``(x, y, w, h)`` of a rect rotated around its centre."""
    x, y, w, h = rect
    if not rotation or abs(rotation % 360.0) < 1e-6:
        return rect
    cx, cy = x + w / 2.0, y + h / 2.0
    r = math.radians(rotation)
    c, s = abs(math.cos(r)), abs(math.sin(r))
    nw, nh = w * c + h * s, w * s + h * c
    return (cx - nw / 2.0, cy - nh / 2.0, nw, nh)


def element_rect(e: dict) -> tuple:
    """Rect of a model element, rotation included (bbox of the rotated box)."""
    r = (float(e.get("x", 0)), float(e.get("y", 0)), float(e.get("w", 0)), float(e.get("h", 0)))
    return rotated_rect_bbox(r, float(e.get("rotation", 0) or 0))


def simplify_polyline(pts: list, eps: float = 0.5) -> list:
    """Ramer-Douglas-Peucker (iterative); keeps both ends."""
    n = len(pts)
    if n < 3:
        return list(pts)
    keep = [False] * n
    keep[0] = keep[-1] = True
    stack = [(0, n - 1)]
    while stack:
        lo, hi = stack.pop()
        best, idx = 0.0, -1
        for i in range(lo + 1, hi):
            d = point_segment_distance(pts[i], pts[lo], pts[hi])[0]
            if d > best:
                best, idx = d, i
        if idx >= 0 and best > eps:
            keep[idx] = True
            stack.append((lo, idx))
            stack.append((idx, hi))
    return [p for p, k in zip(pts, keep) if k]


def dedupe_points(pts, eps: float = 1e-6) -> list:
    out: list = []
    for p in pts:
        if not out or abs(p[0] - out[-1][0]) > eps or abs(p[1] - out[-1][1]) > eps:
            out.append((p[0], p[1]))
    return out


def polygon_area(pts) -> float:
    n = len(pts)
    if n < 3:
        return 0.0
    s = 0.0
    for i in range(n):
        x0, y0 = pts[i]
        x1, y1 = pts[(i + 1) % n]
        s += x0 * y1 - x1 * y0
    return abs(s) / 2.0


def merge_collinear(a: list, b: list, tol: float = 1.0, angle_tol_deg: float = 3.0, join: float = 1.5):
    """Join two polylines when one's end touches the other's start/end (within
    *join*) so the merged line is straight at the joint (within *angle_tol_deg*).
    Returns the merged point list or ``None``. Used for PDFs that split a
    polyline into separate line objects."""
    if len(a) < 2 or len(b) < 2:
        return None
    for ra in (False, True):
        pa = a[::-1] if ra else a
        for rb in (False, True):
            pb = b[::-1] if rb else b
            if math.hypot(pa[-1][0] - pb[0][0], pa[-1][1] - pb[0][1]) <= join:
                v1 = (pa[-1][0] - pa[-2][0], pa[-1][1] - pa[-2][1])
                v2 = (pb[1][0] - pb[0][0], pb[1][1] - pb[0][1])
                l1, l2 = math.hypot(*v1), math.hypot(*v2)
                if l1 < _EPS or l2 < _EPS:
                    continue
                cos = (v1[0] * v2[0] + v1[1] * v2[1]) / (l1 * l2)
                if cos >= math.cos(math.radians(angle_tol_deg)):
                    return list(pa) + list(pb[1:])
    return None


# ===================================================================== shape tests

def clean_polygon(pts, eps: float = 1e-3) -> list:
    """Drop consecutive duplicates and a repeated closing point."""
    out = dedupe_points(pts, eps)
    if len(out) > 1 and abs(out[0][0] - out[-1][0]) <= eps and abs(out[0][1] - out[-1][1]) <= eps:
        out = out[:-1]
    return out


def is_axis_rect(pts, tol: float = 0.02) -> bool:
    """4 points forming an axis-aligned rectangle (any start/winding)."""
    p = clean_polygon(pts)
    if len(p) != 4:
        return False
    bb = bbox_of_points(p)
    w, h = bb[2] - bb[0], bb[3] - bb[1]
    if w < _EPS or h < _EPS:
        return False
    tx, ty = tol * w + 1e-6, tol * h + 1e-6
    corners = {(round((x - bb[0]) / w), round((y - bb[1]) / h)) for x, y in p}
    if len(corners) != 4:
        return False
    return all(min(abs(x - bb[0]), abs(x - bb[2])) <= tx and min(abs(y - bb[1]), abs(y - bb[3])) <= ty for x, y in p)


def is_diamond(pts, tol: float = 0.08) -> bool:
    """4 points at the edge midpoints of their bbox (an upright rhombus)."""
    p = clean_polygon(pts)
    if len(p) != 4:
        return False
    bb = bbox_of_points(p)
    w, h = bb[2] - bb[0], bb[3] - bb[1]
    if w < _EPS or h < _EPS:
        return False
    cx, cy = (bb[0] + bb[2]) / 2.0, (bb[1] + bb[3]) / 2.0
    want = [(cx, bb[1]), (bb[2], cy), (cx, bb[3]), (bb[0], cy)]
    used = set()
    for x, y in p:
        hit = None
        for i, (wx, wy) in enumerate(want):
            if i not in used and abs(x - wx) <= tol * w + 1e-6 and abs(y - wy) <= tol * h + 1e-6:
                hit = i
                break
        if hit is None:
            return False
        used.add(hit)
    return True


def is_upright_triangle(pts, tol: float = 0.12) -> bool:
    """3 points, apex on the top edge near the horizontal centre, base on the bottom."""
    p = clean_polygon(pts)
    if len(p) != 3:
        return False
    bb = bbox_of_points(p)
    w, h = bb[2] - bb[0], bb[3] - bb[1]
    if w < _EPS or h < _EPS:
        return False
    top = [q for q in p if abs(q[1] - bb[1]) <= tol * h + 1e-6]
    bottom = [q for q in p if abs(q[1] - bb[3]) <= tol * h + 1e-6]
    if len(top) != 1 or len(bottom) != 2:
        return False
    return abs(top[0][0] - (bb[0] + bb[2]) / 2.0) <= tol * w + 1e-6


def fits_ellipse(pts, tol: float = 0.07, min_points: int = 8) -> bool:
    """Do the points lie on the ellipse inscribed in their own bbox, all round?"""
    if len(pts) < min_points:
        return False
    bb = bbox_of_points(pts)
    w, h = bb[2] - bb[0], bb[3] - bb[1]
    if w < 1e-3 or h < 1e-3:
        return False
    cx, cy = (bb[0] + bb[2]) / 2.0, (bb[1] + bb[3]) / 2.0
    bins = set()
    for x, y in pts:
        u, v = (x - cx) / (w / 2.0), (y - cy) / (h / 2.0)
        if abs(math.hypot(u, v) - 1.0) > tol:
            return False
        bins.add(int(((math.atan2(v, u) + math.pi) / (2 * math.pi)) * 16) % 16)
    return len(bins) >= 12


def normalise_points(pts, bbox=None) -> list:
    """Points -> ``[[0..1, 0..1], ...]`` relative to *bbox* (default: their own)."""
    bb = bbox or bbox_of_points(pts)
    w, h = bb[2] - bb[0], bb[3] - bb[1]
    return [[round((x - bb[0]) / w, 4) if w > _EPS else 0.5,
             round((y - bb[1]) / h, 4) if h > _EPS else 0.5] for x, y in pts]


# ===================================================================== arrowheads

def detect_arrowhead(poly, line_end, line_dir, *, max_size: float = 30.0, tol: float = 4.0,
                     min_cos: float = 0.75) -> dict | None:
    """Is *poly* (a small closed, filled 3/4-point polygon) the arrowhead of a
    line that ends at *line_end* heading along the unit vector *line_dir*
    (pointing OUT of the line, i.e. in the direction the arrow would point)?

    Returns ``{"tip": (x, y), "dir": (ux, uy), "base": (x, y), "size": s,
    "kind": "arrow" | "diamond"}`` or ``None``. Accepts triangles and kites
    (stealth heads) with the tip within *min_cos* of the line direction, and
    rhombus heads (``kind == "diamond"``). The head must be at most *max_size*
    across and touch the line end within *tol*.
    """
    pts = clean_polygon(poly)
    if len(pts) not in (3, 4):
        return None
    bb = bbox_of_points(pts)
    w, h = bb[2] - bb[0], bb[3] - bb[1]
    size = max(w, h)
    if size > max_size or size < 1.0:
        return None
    if point_rect_distance(line_end, (bb[0], bb[1], w, h)) > tol:
        return None
    ux, uy = line_dir
    ul = math.hypot(ux, uy)
    if ul < _EPS:
        return None
    ux, uy = ux / ul, uy / ul

    def proj(p):
        return p[0] * ux + p[1] * uy

    if len(pts) == 4:
        sides = [math.hypot(pts[i][0] - pts[(i + 1) % 4][0], pts[i][1] - pts[(i + 1) % 4][1]) for i in range(4)]
        if min(sides) > _EPS and max(sides) / min(sides) < 1.25:
            # rhombus: tip = the vertex furthest along the line direction
            tip = max(pts, key=proj)
            others = [p for p in pts if p is not tip]
            base = (sum(p[0] for p in others) / 3.0, sum(p[1] for p in others) / 3.0)
            return {"tip": tip, "dir": (ux, uy), "base": base, "size": size, "kind": "diamond"}
    best = None
    for i, v in enumerate(pts):
        others = [p for j, p in enumerate(pts) if j != i]
        bx = sum(p[0] for p in others) / len(others)
        by = sum(p[1] for p in others) / len(others)
        dx, dy = v[0] - bx, v[1] - by
        L = math.hypot(dx, dy)
        if L < _EPS:
            continue
        cos = (dx * ux + dy * uy) / L
        if cos < min_cos:
            continue
        if proj(v) < max(proj(p) for p in others) - 0.5:
            continue
        if len(pts) == 3:
            base_w = math.hypot(others[0][0] - others[1][0], others[0][1] - others[1][1])
            if base_w < _EPS or not 0.3 <= L / base_w <= 4.0:
                continue
            s0 = math.hypot(v[0] - others[0][0], v[1] - others[0][1])
            s1 = math.hypot(v[0] - others[1][0], v[1] - others[1][1])
            if abs(s0 - s1) > 0.4 * max(s0, s1):
                continue
        score = cos
        if best is None or score > best[0]:
            best = (score, v, (bx, by), (dx / L, dy / L))
    if best is None:
        return None
    return {"tip": best[1], "dir": best[3], "base": best[2], "size": size, "kind": "arrow"}


def looks_like_arrowhead(poly, max_size: float = 30.0) -> bool:
    """Shape-only test (no line needed): a small 3/4-point pointy polygon."""
    pts = clean_polygon(poly)
    if len(pts) not in (3, 4):
        return False
    bb = bbox_of_points(pts)
    size = max(bb[2] - bb[0], bb[3] - bb[1])
    return 1.0 <= size <= max_size


# ===================================================================== snapping

class ElementIndex:
    """Uniform-grid index over model elements for snapping and containment.

    ``accept(element) -> bool`` chooses what is indexable (default: shapes,
    containers and images with a positive size; never text).
    """

    def __init__(self, elements, cell: float = 64.0, accept=None):
        self.cell = float(cell)
        self.items: list = []
        self.grid: dict = {}
        self.big: list = []
        for e in elements:
            if accept is not None:
                if not accept(e):
                    continue
            elif e.get("kind", "shape") not in ("shape", "container", "image") or e.get("shape") == "line":
                continue
            rect = element_rect(e)
            if rect[2] <= 0 or rect[3] <= 0:
                continue
            idx = len(self.items)
            self.items.append({"id": e.get("id"), "rect": rect, "area": rect[2] * rect[3], "element": e})
            c0x, c0y = int(rect[0] // self.cell), int(rect[1] // self.cell)
            c1x, c1y = int((rect[0] + rect[2]) // self.cell), int((rect[1] + rect[3]) // self.cell)
            if (c1x - c0x + 1) * (c1y - c0y + 1) > 400:
                self.big.append(idx)
                continue
            for cx in range(c0x, c1x + 1):
                for cy in range(c0y, c1y + 1):
                    self.grid.setdefault((cx, cy), []).append(idx)

    def _near(self, point, radius: float) -> list:
        px, py = point
        seen = set(self.big)
        for cx in range(int((px - radius) // self.cell), int((px + radius) // self.cell) + 1):
            for cy in range(int((py - radius) // self.cell), int((py + radius) // self.cell) + 1):
                seen.update(self.grid.get((cx, cy), ()))
        return [self.items[i] for i in seen]

    def near(self, point, radius: float = 0.0) -> list:
        """Items whose grid cells touch the disc around *point* (a superset; filter yourself)."""
        return self._near(point, radius)

    def containing(self, point, margin: float = 0.0) -> list:
        """Items whose rect (grown by *margin*) contains the point, smallest area first."""
        hits = [it for it in self._near(point, margin)
                if point_rect_distance(point, it["rect"]) <= margin]
        hits.sort(key=lambda it: it["area"])
        return hits

    def nearest(self, point, tolerance: float, *, inside_max_area: float | None = None,
                exclude=()) -> dict | None:
        """Best element within *tolerance* of the point.

        ``{"id", "port": (rx, ry), "distance", "inside", "boundary_distance"}``.
        Ranking: elements the point touches (<= 1px, or is inside) tie and the
        SMALLEST area wins (so a box inside a zone beats the zone); otherwise
        the nearer element wins. A point strictly inside an element larger than
        *inside_max_area* only counts when it is within *tolerance* of that
        element's outline (a free end drawn inside a big zone is not attached).
        """
        best = None
        for it in self._near(point, tolerance):
            if it["id"] in exclude:
                continue
            d = point_rect_distance(point, it["rect"])
            if d > tolerance:
                continue
            b = boundary_distance(point, it["rect"])
            inside = d == 0.0 and b > 0.0
            if inside and inside_max_area is not None and it["area"] > inside_max_area and b > tolerance:
                continue
            key = (0.0 if d <= 1.0 else d, it["area"])
            if best is None or key < best[0]:
                best = (key, it, d, b, inside)
        if best is None:
            return None
        _, it, d, b, inside = best
        return {"id": it["id"], "port": snap_to_rect(point, it["rect"]), "distance": d,
                "inside": inside, "boundary_distance": b}


def nearest_element(point, elements, tolerance: float):
    """``(element id, (rx, ry))`` of the element nearest to *point* within
    *tolerance*, or ``None``. ``(rx, ry)`` is the port position, 0..1 of the
    element's box, snapped onto its outline. For many lookups build an
    :class:`ElementIndex` once and call ``.nearest``."""
    hit = ElementIndex(elements).nearest(point, tolerance)
    return (hit["id"], hit["port"]) if hit else None


# ===================================================================== outline recognition

def is_round_rect(segs: list, bb) -> bool:
    """A closed path whose four sides are straight runs flush with its bbox
    joined by curves: a rounded rectangle exported as a path."""
    x0, y0, x1, y1 = bb
    w, h = x1 - x0, y1 - y0
    if w < 1 or h < 1:
        return False
    tol = max(0.75, 0.01 * max(w, h))
    seen = set()
    cur = None
    for s in segs:
        if s[0] == "L" and cur is not None:
            ax, ay, bx, by = cur[0], cur[1], s[1], s[2]
            if abs(ay - by) <= tol and abs(bx - ax) >= 0.3 * w:
                if abs(ay - y0) <= tol:
                    seen.add("t")
                elif abs(ay - y1) <= tol:
                    seen.add("b")
            if abs(ax - bx) <= tol and abs(by - ay) >= 0.3 * h:
                if abs(ax - x0) <= tol:
                    seen.add("l")
                elif abs(ax - x1) <= tol:
                    seen.add("r")
        if s[0] != "Z":
            cur = (s[-2], s[-1])
    return len(seen) == 4


def classify_outline(segs: list) -> dict | None:
    """Recognise a CLOSED outline given as absolute segments.

    ``{"shape": rect|round|ellipse|diamond|triangle|polygon|path, "x", "y",
    "w", "h", "rounded", "points" (polygon, 0..1 of the box), "path" (path, box
    coordinates), "poly" (cleaned corner points of a straight outline),
    "confidence"}`` or ``None`` for a degenerate outline. Several subpaths
    give a compound ``path``.
    """
    subs = flatten(segs)
    if not subs:
        return None
    allp = [p for sub, _ in subs for p in sub]
    bb = bbox_of_points(allp)
    w, h = bb[2] - bb[0], bb[3] - bb[1]
    if w < 1e-6 and h < 1e-6:
        return None
    out = {"shape": "path", "x": bb[0], "y": bb[1], "w": max(w, 0.5), "h": max(h, 0.5), "rounded": False,
           "points": None, "path": None, "poly": None, "confidence": 0.9}
    if len(subs) == 1:
        pts = clean_polygon(subs[0][0])
        if len(pts) < 3:
            return None
        if not has_curves(segs):
            out.update(poly=pts, confidence=1.0)
            if is_axis_rect(pts):
                out["shape"] = "rect"
            elif is_diamond(pts):
                out["shape"] = "diamond"
            elif is_upright_triangle(pts):
                out["shape"] = "triangle"
            else:
                out["shape"] = "polygon"
                out["points"] = normalise_points(pts, bb)
            return out
        if fits_ellipse(subs[0][0]):
            out.update(shape="ellipse", confidence=0.95)
            return out
        if is_round_rect(segs, bb):
            out.update(shape="round", rounded=True, confidence=0.95)
            return out
    out["path"] = segments_to_d(segs, bb[0], bb[1])
    return out


def polygon_segments(pts) -> list:
    """Corner points -> closed absolute segments."""
    pts = list(pts)
    if not pts:
        return []
    return [("M", pts[0][0], pts[0][1])] + [("L", x, y) for x, y in pts[1:]] + [("Z",)]


# ===================================================================== vector page assembly
# Shared by every reader that produces absolute geometry (SVG, PDF, ...).
#   shapes     model-element dicts ({"id","kind":"shape","shape","x","y","w","h","rotation",...});
#              the optional "poly" (corner points) and "filled" keys feed arrowhead detection
#   texts      {"text","x","y","w","h","cx","cy","order","font":{...},...}
#   connectors {"pts": [(x, y), ...], "curved": bool, "start_arrow", "end_arrow",
#               "style": {"stroke","stroke_width","dashed","opacity"}, "order", "layer",
#               "metadata", "source_ref", "labels": [(text, t)], "key": any}

def end_direction(pts, at_start: bool):
    """Unit vector pointing OUT of a polyline at one end (looking back >= 2 units)."""
    if len(pts) < 2:
        return None
    a, rest = (pts[0], pts[1:]) if at_start else (pts[-1], pts[-2::-1])
    for q in rest:
        dx, dy = a[0] - q[0], a[1] - q[1]
        L = math.hypot(dx, dy)
        if L >= 2.0:
            return (dx / L, dy / L)
    q = rest[-1]
    dx, dy = a[0] - q[0], a[1] - q[1]
    L = math.hypot(dx, dy)
    return (dx / L, dy / L) if L > _EPS else None


def snap_tolerance(page_w: float, page_h: float) -> float:
    """How far a connector end may be from a shape and still attach: max(6, 1.5% of the diagonal)."""
    return max(6.0, 0.015 * math.hypot(page_w, page_h))


def extract_arrowheads(connectors: list, shapes: list, diag: float) -> list:
    """Find small filled triangles/rhombi at connector ends.

    A connector end whose arrow is still ``"none"`` takes the best head within
    reach: its arrow becomes ``arrow``/``diamond`` and the polyline is
    extended to the head's tip. Returns the shape dicts consumed as heads (the
    caller drops them from the shapes).
    """
    max_head = max(16.0, min(36.0, 0.02 * diag))
    tol = max(6.0, 0.015 * diag)
    cands = [s for s in shapes if s.get("poly") and s.get("filled", True) and 3 <= len(s["poly"]) <= 4
             and s.get("shape") in ("polygon", "triangle", "diamond") and max(s["w"], s["h"]) <= max_head]
    if not cands or not connectors:
        return []
    index = ElementIndex([{"id": i, "x": s["x"], "y": s["y"], "w": max(s["w"], 0.5), "h": max(s["h"], 0.5),
                           "kind": "shape"} for i, s in enumerate(cands)])
    used: set = set()
    for c in connectors:
        pts = c["pts"]
        sw = float((c.get("style") or {}).get("stroke_width") or 0.0)
        for at_start in (True, False):
            key = "start_arrow" if at_start else "end_arrow"
            ep = pts[0] if at_start else pts[-1]
            d = end_direction(pts, at_start)
            if c.get(key, "none") != "none" or d is None:
                continue
            best = None
            for it in index.near(ep, tol + 2.0):
                if it["id"] in used:
                    continue
                s = cands[it["id"]]
                r = detect_arrowhead(s["poly"], ep, d, max_size=max_head, tol=tol / 2.0 + sw)
                if r:
                    dist = point_rect_distance(ep, it["rect"])
                    if best is None or dist < best[0]:
                        best = (dist, it["id"], r)
            if best:
                used.add(best[1])
                c[key] = "arrow" if best[2]["kind"] == "arrow" else "diamond"
                tip = best[2]["tip"]
                if math.hypot(tip[0] - ep[0], tip[1] - ep[1]) > 0.5:
                    if at_start:
                        pts.insert(0, tip)
                    else:
                        pts.append(tip)
    return [cands[i] for i in sorted(used)]


def assign_texts(shapes: list, texts: list, page_area: float) -> tuple:
    """Texts -> the shape that contains their centre.

    Returns ``({shape id: [text, ...]}, [texts not placed])``. The smallest
    containing shape wins; a page-sized backdrop (>= 85% of the page) owns
    nothing; a zone that holds other shapes keeps at most one text (its
    title) because the rest are annotations lying on it.
    """
    index = ElementIndex([s for s in shapes if s.get("kind") == "shape"])
    assigned: dict = {}
    left: list = []
    for t in sorted(texts, key=lambda q: q.get("order", 0)):
        hits = [h for h in index.containing((t["cx"], t["cy"]), margin=2.0) if h["area"] < 0.85 * page_area]
        if hits:
            assigned.setdefault(hits[0]["id"], []).append(t)
        else:
            left.append(t)
    holders = set()
    for s in shapes:
        if s.get("kind") != "shape" or s["w"] <= 0 or s["h"] <= 0:
            continue
        for h in index.containing((s["x"] + s["w"] / 2.0, s["y"] + s["h"] / 2.0)):
            if h["id"] != s["id"] and h["area"] > s["w"] * s["h"]:
                holders.add(h["id"])
    for sid in list(assigned):
        if sid in holders and len(assigned[sid]) > 1:
            left.extend(assigned.pop(sid))
    left.sort(key=lambda q: q.get("order", 0))
    return assigned, left


def label_connectors(texts: list, connectors: list) -> tuple:
    """Short texts hugging a connector -> ``({connector index: [(text, t)]}, [free texts])``
    (t = 0..1 along the line)."""
    labels: dict = {}
    free: list = []
    boxes = []
    for c in connectors:
        bb = bbox_of_points(c["pts"])
        boxes.append((bb[0] - 60, bb[1] - 60, bb[2] - bb[0] + 120, bb[3] - bb[1] + 120))
    for t in texts:
        best = None
        if len(t["text"]) <= 40 and t["text"].count("\n") <= 1:
            rect = (t["x"], t["y"], t["w"], t["h"])
            slack = max(4.0, 0.4 * float((t.get("font") or {}).get("font_size", 12.0)))
            for i, c in enumerate(connectors):
                if point_rect_distance((t["cx"], t["cy"]), boxes[i]) > 0:
                    continue
                d, tt = polyline_rect_distance(c["pts"], rect)
                if d <= slack and (best is None or d < best[0]):
                    best = (d, i, tt)
        if best:
            labels.setdefault(best[1], []).append((t, best[2]))
        else:
            free.append(t)
    return labels, free


def end_confidence(info: dict | None, tol: float) -> float:
    """1.0 exact touch, 0.85 an end lying inside the shape, 1.0 -> 0.5 as a gap grows to *tol*, 0.4 free."""
    if info is None:
        return 0.4
    if info["distance"] <= 1.0 and (not info["inside"] or info["boundary_distance"] <= 1.0):
        return 1.0
    if info["inside"]:
        return 0.85
    return round(1.0 - 0.5 * min(1.0, info["distance"] / max(tol, _EPS)), 3)


def ensure_port(element: dict, rel) -> str:
    """The id of the element port at *rel* (0..1 of its box), adding it when new."""
    ports = element.setdefault("ports", [])
    for p in ports:
        if abs(p["x"] - rel[0]) < 0.02 and abs(p["y"] - rel[1]) < 0.02:
            return p["id"]
    if len(ports) >= 64:
        return ""
    pid = "p%d" % len(ports)
    ports.append({"id": pid, "x": rel[0], "y": rel[1]})
    return pid


def routing_of(pts, curved: bool) -> str:
    if curved:
        return "curved"
    if len(pts) >= 3 and all(abs(pts[i][0] - pts[i + 1][0]) < 0.5 or abs(pts[i][1] - pts[i + 1][1]) < 0.5
                             for i in range(len(pts) - 1)):
        return "orthogonal"
    return "straight"


def model_connectors(connectors: list, elements: list, page_w: float, page_h: float, limit: int = 10000) -> tuple:
    """Attach connector ends to *elements* and build model connector dicts.

    Returns ``(connectors, dropped)``. Each dict carries ``_key`` (the input's
    ``key``) and ``_order`` for the caller to use and pop. Ports are added to
    the elements. Ids are ``c1, c2, ...`` in input order.
    """
    tol = snap_tolerance(page_w, page_h)
    big_area = 0.25 * page_w * page_h
    index = ElementIndex([e for e in elements if e.get("kind") in ("shape", "image")])
    by_id = {e["id"]: e for e in elements}
    out = []
    for c in sorted(connectors, key=lambda q: q.get("order", 0)):
        if len(out) >= limit:
            break
        pts = c["pts"]
        ends = [index.nearest(pts[0], tol, inside_max_area=big_area),
                index.nearest(pts[-1], tol, inside_max_area=big_area)]
        if ends[0] and ends[1] and ends[0]["id"] == ends[1]["id"] and polyline_length(pts) < 3 * tol:
            ends = [None, None]                      # a short stroke on a shape's own border
        conf = [end_confidence(ends[0], tol), end_confidence(ends[1], tol)]
        src = tgt = sp = tp = ""
        if ends[0]:
            src, sp = ends[0]["id"], ensure_port(by_id[ends[0]["id"]], ends[0]["port"])
        if ends[1]:
            tgt, tp = ends[1]["id"], ensure_port(by_id[ends[1]["id"]], ends[1]["port"])
        st = c.get("style") or {}
        labs = sorted(c.get("labels") or [], key=lambda x: x[1])
        conn = {
            "id": "c%d" % (len(out) + 1), "source": src, "target": tgt, "source_port": sp, "target_port": tp,
            "start": [] if src else [round(pts[0][0], 3), round(pts[0][1], 3)],
            "end": [] if tgt else [round(pts[-1][0], 3), round(pts[-1][1], 3)],
            "points": [[round(x, 3), round(y, 3)] for x, y in pts],
            "routing": routing_of(pts, bool(c.get("curved"))),
            "start_arrow": c.get("start_arrow", "none"), "end_arrow": c.get("end_arrow", "none"),
            "style": {"stroke": st.get("stroke") if st.get("stroke") not in (None, "none") else "#000000",
                      "stroke_width": st.get("stroke_width") or 1.0, "dashed": bool(st.get("dashed")),
                      "opacity": st.get("opacity", 1.0),
                      **{k: st[k] for k in ("dash_pattern", "stroke_opacity", "shadow", "shadow_color") if k in st}},
            "layer": c.get("layer") or "", "metadata": dict(c.get("metadata") or {}),
            "source_ref": c.get("source_ref", ""), "confidence": min(conf),
            "_order": c.get("order", 0), "_key": c.get("key"),
        }
        if labs:
            conn["label"] = " ".join(t["text"].replace("\n", " ") for t, _ in labs)[:200]
            conn["labels"] = [{"text": t["text"].replace("\n", " ")[:200], "pos": round(tt, 3)} for t, tt in labs]
            conn["style"]["font_color"] = (labs[0][0].get("font") or {}).get("font_color", "#111827")
        out.append(conn)
    return out, max(0, len(connectors) - len(out))
