"""Procedural generator of the ``iso3d`` symbol library (isometric 3D icons).

BUILD-TIME ONLY: SATOM never runs this at runtime; it reads the committed
``*.svg`` and ``library.json``. Re-run after editing a recipe::

    python3 app/services/diagram_engine/symbols/iso3d/build.py

The output is deterministic (fixed rounding, sorted output, no clocks, no
randomness); ``tests/test_diagram_symbols_variants.py`` re-runs the generator
into a temporary folder and requires byte-identical files, so the committed
icons can never drift from this source.

Geometry: one 2:1 isometric projection for every icon. World units: a full
floor tile is ``x, y in [-0.5, 0.5]``; ``z`` is up. The tile centre projects to
the library ``anchor`` (0.5, 0.71875 of the 64x64 viewBox), so every icon
stands on the same point and icons stack on an isometric grid. Visible faces
use three shades of the object colour: light top, mid left, dark right.

Artwork: original, drawn for SATOM (ELv2). Stdlib only.
"""
from __future__ import annotations

import importlib.util
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PAL = _load("_satom_symbol_palette", os.path.join(HERE, "..", "palette.py"))
GEO = _load("_satom_symbol_geometry", os.path.join(HERE, "..", "..", "geometry.py"))

VB = 64
CX, CY = 32.0, 46.0            # projected tile centre
SX, SY, SZ = 28.0, 14.0, 31.0  # px per world unit along screen x / screen y (2:1) / height
ANCHOR = [0.5, CY / VB]
ATTR_ORDER = ("viewBox", "fill", "fill-rule", "stroke", "stroke-width", "stroke-linecap",
              "stroke-linejoin", "stroke-dasharray", "opacity", "transform", "d", "points",
              "x", "y", "width", "height", "rx", "ry", "cx", "cy", "r", "x1", "y1", "x2", "y2")
WHITE, BLACK = "#FFFFFF", "#000000"
A = PAL.ACCENTS


def fmt(v: float) -> str:
    s = "%.2f" % v
    s = s.rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def P(x: float, y: float, z: float = 0.0):
    return (CX + (x - y) * SX, CY + (x + y) * SY - z * SZ)


def pts(seq) -> str:
    return " ".join("%s %s" % (fmt(a), fmt(b)) for a, b in seq)


def shades(base: str):
    """(top, left, right) faces of a solid of colour *base*."""
    return PAL.mix(base, WHITE, 0.30), base, PAL.mix(base, BLACK, 0.24)


def fam(f: str, step: str) -> str:
    return PAL.colour(f, step)


# ----------------------------------------------------------------- canvas

class Icon:
    def __init__(self):
        self.items: list = []

    def el(self, tag: str, **attrs):
        self.items.append((tag, {k.replace("_", "-"): v for k, v in attrs.items() if v is not None}, None))

    def group(self, transform: str, children: list):
        self.items.append(("g", {"transform": transform}, children))

    def poly(self, points, fill, **kw):
        self.el("polygon", points=pts(points), fill=fill, **kw)

    def line(self, a, b, stroke, width=0.8, **kw):
        self.el("line", x1=fmt(a[0]), y1=fmt(a[1]), x2=fmt(b[0]), y2=fmt(b[1]), stroke=stroke,
                stroke_width=fmt(width), stroke_linecap="round", **kw)

    def polyline(self, points, stroke, width=0.8, **kw):
        self.el("polyline", points=pts(points), fill="none", stroke=stroke, stroke_width=fmt(width),
                stroke_linecap="round", stroke_linejoin="round", **kw)

    def path(self, d, fill, **kw):
        self.el("path", d=d, fill=fill, **kw)

    def ellipse(self, c, rx, ry, fill, **kw):
        self.el("ellipse", cx=fmt(c[0]), cy=fmt(c[1]), rx=fmt(rx), ry=fmt(ry), fill=fill, **kw)

    def circle(self, c, r, fill, **kw):
        self.el("circle", cx=fmt(c[0]), cy=fmt(c[1]), r=fmt(r), fill=fill, **kw)

    def svg(self) -> str:
        def attrs(d):
            return "".join(' %s="%s"' % (k, d[k]) for k in ATTR_ORDER if k in d)

        def emit(item):
            tag, d, kids = item
            if tag == "g":
                return "<g%s>%s</g>" % (attrs(d), "".join(emit(k) for k in kids))
            return "<%s%s/>" % (tag, attrs(d))
        body = "".join(emit(i) for i in self.items)
        return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" fill="none" stroke="none" '
                'stroke-linejoin="round">%s</svg>' % (VB, VB, body))


# ------------------------------------------------------------- primitives

class Box:
    """Axis-aligned solid; faces ``T`` (top), ``L`` (front-left, y = y1), ``R`` (front-right, x = x1)."""

    def __init__(self, x0, y0, z0, dx, dy, dz):
        self.x0, self.y0, self.z0 = x0, y0, z0
        self.x1, self.y1, self.z1 = x0 + dx, y0 + dy, z0 + dz
        self.dx, self.dy, self.dz = dx, dy, dz

    def fp(self, face: str, u: float, v: float):
        """Point of a face from fractions: u left->right on screen, v top->bottom (T: back->front)."""
        if face == "L":
            return P(self.x0 + u * self.dx, self.y1, self.z1 - v * self.dz)
        if face == "R":
            return P(self.x1, self.y1 - u * self.dy, self.z1 - v * self.dz)
        return P(self.x0 + u * self.dx, self.y0 + v * self.dy, self.z1)

    def size(self, face: str):
        """World (width, height) of a face."""
        return {"L": (self.dx, self.dz), "R": (self.dy, self.dz), "T": (self.dx, self.dy)}[face]

    def quad(self, face, u0, v0, u1, v1):
        return [self.fp(face, u0, v0), self.fp(face, u1, v0), self.fp(face, u1, v1), self.fp(face, u0, v1)]

    def matrix(self, face, cu, cv, size, aspect=1.0):
        """SVG matrix mapping a 0..10 emblem box onto the face, centred at (cu, cv), *size* world units wide."""
        w, h = self.size(face)
        hu = size / w / 2.0
        hv = size * aspect / h / 2.0
        o = self.fp(face, cu - hu, cv - hv)
        a = self.fp(face, cu - hu + 2 * hu / 10.0, cv - hv)
        b = self.fp(face, cu - hu, cv - hv + 2 * hv / 10.0)
        return "matrix(%s %s %s %s %s %s)" % (fmt(a[0] - o[0]), fmt(a[1] - o[1]), fmt(b[0] - o[0]),
                                                fmt(b[1] - o[1]), fmt(o[0]), fmt(o[1]))


def shadow(ic: Icon, x0, y0, dx, dy, grow=0.06, opacity=0.13):
    ic.poly([P(x0 - grow, y0 - grow), P(x0 + dx + grow, y0 - grow), P(x0 + dx + grow, y0 + dy + grow),
             P(x0 - grow, y0 + dy + grow)], A["shadow"], opacity=str(opacity))


def box(ic: Icon, x0, y0, z0, dx, dy, dz, base, top=None, edges=True) -> Box:
    b = Box(x0, y0, z0, dx, dy, dz)
    t, l, r = shades(base)
    if top:
        t = top
    ic.poly([P(b.x0, b.y1, b.z0), P(b.x1, b.y1, b.z0), P(b.x1, b.y1, b.z1), P(b.x0, b.y1, b.z1)], l)
    ic.poly([P(b.x1, b.y0, b.z0), P(b.x1, b.y1, b.z0), P(b.x1, b.y1, b.z1), P(b.x1, b.y0, b.z1)], r)
    ic.poly([P(b.x0, b.y0, b.z1), P(b.x1, b.y0, b.z1), P(b.x1, b.y1, b.z1), P(b.x0, b.y1, b.z1)], t)
    if edges:
        hi = PAL.mix(t, WHITE, 0.55)
        ic.polyline([P(b.x0, b.y1, b.z1), P(b.x1, b.y1, b.z1), P(b.x1, b.y0, b.z1)], hi, 0.6)
        ic.line(P(b.x1, b.y1, b.z1), P(b.x1, b.y1, b.z0), PAL.mix(l, WHITE, 0.25), 0.5)
    return b


def face_rect(ic, b: Box, face, u0, v0, u1, v1, fill, **kw):
    ic.poly(b.quad(face, u0, v0, u1, v1), fill, **kw)


def ports(ic, b: Box, face, n, v0, v1, u0=0.1, u1=0.9, fill=A["port"], gap=0.35):
    step = (u1 - u0) / n
    for i in range(n):
        a = u0 + i * step
        face_rect(ic, b, face, a, v0, a + step * (1 - gap), v1, fill)


def leds(ic, b: Box, face, us, v, colours, size=0.05):
    w, h = b.size(face)
    du, dv = size / w / 2, size / h / 2
    for u, c in zip(us, colours):
        face_rect(ic, b, face, u - du, v - dv, u + du, v + dv, c)


def vents(ic, b: Box, face, n, u0, u1, v0, v1, colour):
    for i in range(n):
        v = v0 + (v1 - v0) * i / max(1, n - 1)
        ic.line(b.fp(face, u0, v), b.fp(face, u1, v), colour, 0.55)


class Cyl:
    def __init__(self, cx, cy, z0, r, h):
        self.c, self.z0, self.r, self.h = (cx, cy), z0, r, h
        self.rx, self.ry = r * SX * math.sqrt(2), r * SY * math.sqrt(2)
        self.bot = P(cx, cy, z0)
        self.top = P(cx, cy, z0 + h)


def cylinder(ic: Icon, cx, cy, z0, r, h, base, top=None, bands=()) -> Cyl:
    c = Cyl(cx, cy, z0, r, h)
    t, l, rr = shades(base)
    if top:
        t = top
    (bx, by), (tx, ty), rx, ry = c.bot, c.top, c.rx, c.ry
    ic.path("M%s %s V%s A%s %s 0 0 0 %s %s V%s A%s %s 0 0 1 %s %s Z" % (
        fmt(bx - rx), fmt(ty), fmt(by), fmt(rx), fmt(ry), fmt(bx), fmt(by + ry), fmt(ty + ry),
        fmt(rx), fmt(ry), fmt(bx - rx), fmt(ty)), l)
    ic.path("M%s %s V%s A%s %s 0 0 1 %s %s V%s A%s %s 0 0 0 %s %s Z" % (
        fmt(bx + rx), fmt(ty), fmt(by), fmt(rx), fmt(ry), fmt(bx), fmt(by + ry), fmt(ty + ry),
        fmt(rx), fmt(ry), fmt(bx + rx), fmt(ty)), rr)
    for z in bands:
        y = by - (z - z0) * SZ
        ic.path("M%s %s A%s %s 0 0 0 %s %s" % (fmt(bx - rx), fmt(y), fmt(rx), fmt(ry), fmt(bx + rx), fmt(y)),
                "none", stroke=PAL.mix(t, WHITE, 0.4), stroke_width="0.9")
    ic.ellipse(c.top, rx, ry, t)
    return c


def sphere(ic: Icon, c, r, base):
    t, l, rr = shades(base)
    ic.circle(c, r, l)
    ic.path("M%s %s A%s %s 0 0 1 %s %s A%s %s 0 0 0 %s %s Z" % (
        fmt(c[0]), fmt(c[1] - r), fmt(r), fmt(r), fmt(c[0]), fmt(c[1] + r), fmt(r * 0.62), fmt(r), fmt(c[0]),
        fmt(c[1] - r)), rr)
    ic.circle((c[0] - r * 0.38, c[1] - r * 0.4), r * 0.28, PAL.mix(t, WHITE, 0.35), opacity="0.7")


def tile(ic: Icon, base, dz=0.07, inset=0.0, dashed=False, border=None) -> Box:
    b = box(ic, -0.5 + inset, -0.5 + inset, 0, 1 - 2 * inset, 1 - 2 * inset, dz, base)
    if border or dashed:
        q = [b.fp("T", 0.08, 0.08), b.fp("T", 0.92, 0.08), b.fp("T", 0.92, 0.92), b.fp("T", 0.08, 0.92)]
        ic.el("polygon", points=pts(q), fill="none", stroke=border or WHITE, stroke_width="0.9",
              stroke_dasharray="2.2 1.6" if dashed else None)
    return b


def roof(ic: Icon, b: Box, rh, base):
    """Gable roof along x on top of *b*."""
    t, l, r = shades(base)
    ym = (b.y0 + b.y1) / 2
    r0, r1 = P(b.x0, ym, b.z1 + rh), P(b.x1, ym, b.z1 + rh)
    ic.poly([P(b.x0, b.y0, b.z1), P(b.x1, b.y0, b.z1), r1, r0], PAL.mix(t, BLACK, 0.1))
    ic.poly([P(b.x0, b.y1, b.z1), P(b.x1, b.y1, b.z1), r1, r0], t)
    ic.poly([P(b.x1, b.y0, b.z1), P(b.x1, b.y1, b.z1), r1], r)
    ic.line(r0, r1, PAL.mix(t, WHITE, 0.5), 0.6)


def screen_slab(ic, x0, y0, z0, dx, dz, base, glass=A["glass"], thick=0.06, bezel=0.07) -> Box:
    """Upright panel facing front-left (a monitor, a TV, a laptop lid)."""
    b = box(ic, x0, y0, z0, dx, thick, dz, base)
    bu, bv = bezel / dx, bezel / dz
    face_rect(ic, b, "L", bu, bv, 1 - bu, 1 - bv, glass)
    ic.poly([b.fp("L", bu, bv), b.fp("L", 0.55, bv), b.fp("L", 0.25, 1 - bv), b.fp("L", bu, 1 - bv)],
            A["glass_hi"], opacity="0.45")
    return b


# --------------------------------------------------------------- emblems
# Flat 2D glyphs in a 0..10 box; placed on a face through an SVG matrix.

def _gear(n=8, ro=4.6, ri=3.5, hole=1.6):
    p = []
    for i in range(n * 2):
        a0 = math.pi * 2 * i / (n * 2)
        r = ro if i % 2 == 0 else ri
        for da in (-0.17, 0.17):
            a = a0 + da
            p.append((5 + r * math.cos(a), 5 + r * math.sin(a)))
    d = "M" + " L".join("%s %s" % (fmt(x), fmt(y)) for x, y in p) + " Z"
    d += " M%s 5 A%s %s 0 1 0 %s 5 A%s %s 0 1 0 %s 5 Z" % (fmt(5 + hole), fmt(hole), fmt(hole), fmt(5 - hole),
                                                         fmt(hole), fmt(hole), fmt(5 + hole))
    return d


EMBLEMS = {
    "shield": [("path", {"d": "M5 0.4 L9.2 2 V5 C9.2 7.6 7.3 9.2 5 9.9 C2.7 9.2 0.8 7.6 0.8 5 V2 Z"}, "fg"),
               ("path", {"d": "M3.2 5.1 L4.5 6.4 L7 3.8", "stroke-width": "1.1"}, "line2")],
    "flame": [("path", {"d": "M5 0.4 C6.2 2.6 8.6 3.9 8.6 6.5 C8.6 8.5 7 9.8 5 9.8 C3 9.8 1.4 8.5 1.4 6.5 "
                             "C1.4 5 2.3 4 3.1 3.3 C3.2 4.6 3.9 5.4 4.6 5.5 C4.1 3.6 4.4 1.9 5 0.4 Z"}, "fg"),
              ("path", {"d": "M5 5.6 C5.9 6.6 6.6 7.2 6.6 8.1 C6.6 9 5.9 9.6 5 9.6 C4.1 9.6 3.4 9 3.4 8.1 "
                             "C3.4 7.2 4.2 6.6 5 5.6 Z"}, "fg2")],
    "globe": [("circle", {"cx": "5", "cy": "5", "r": "4.5"}, "fg"),
              ("path", {"d": "M0.5 5 H9.5 M5 0.5 C2.4 3 2.4 7 5 9.5 C7.6 7 7.6 3 5 0.5 M1.3 2.8 H8.7 M1.3 7.2 H8.7",
                        "stroke-width": "0.7"}, "line2")],
    "cloud": [("path", {"d": "M2.6 8.2 A2.1 2.1 0 0 1 2.3 4 A2.9 2.9 0 0 1 7.7 3.6 A2.3 2.3 0 0 1 7.8 8.2 Z"}, "fg")],
    "lock": [("path", {"d": "M3.2 4.6 V3.2 A1.8 1.8 0 0 1 6.8 3.2 V4.6", "stroke-width": "1.2"}, "line"),
             ("rect", {"x": "2", "y": "4.4", "width": "6", "height": "5.2", "rx": "0.8"}, "fg"),
             ("path", {"d": "M5 6 V7.8", "stroke-width": "1.1"}, "line2")],
    "gear": [("path", {"d": _gear(), "fill-rule": "evenodd"}, "fg")],
    "chart": [("rect", {"x": "1", "y": "6", "width": "2.2", "height": "3.6"}, "fg"),
              ("rect", {"x": "3.9", "y": "3.6", "width": "2.2", "height": "6"}, "fg"),
              ("rect", {"x": "6.8", "y": "1", "width": "2.2", "height": "8.6"}, "fg2")],
    "swap": [("path", {"d": "M1 3.4 H8 M6 1.4 L8.4 3.4 L6 5.4 M9 6.8 H2 M4 4.8 L1.6 6.8 L4 8.8",
                       "stroke-width": "1.3"}, "line")],
    "split": [("path", {"d": "M0.8 5 H4 M4 5 L8.6 1.6 M4 5 H8.8 M4 5 L8.6 8.4 M7 1.4 L8.8 1.5 L8.6 3.2 "
                             "M7.4 3.6 L9 5 L7.4 6.4 M7 8.6 L8.8 8.5 L8.6 6.8", "stroke-width": "1.1"}, "line")],
    "bolt": [("path", {"d": "M6 0.4 L1.8 5.6 H4.8 L3.8 9.6 L8.2 4.2 H5.2 Z"}, "fg")],
    "key": [("circle", {"cx": "3.2", "cy": "5", "r": "2.4"}, "fg"),
            ("path", {"d": "M5 5 H9.4 M8 5 V6.9 M6.6 5 V6.4", "stroke-width": "1.2"}, "line"),
            ("circle", {"cx": "3.2", "cy": "5", "r": "0.9"}, "fg2")],
    "eye": [("path", {"d": "M0.4 5 C2.4 1.8 7.6 1.8 9.6 5 C7.6 8.2 2.4 8.2 0.4 5 Z"}, "fg"),
            ("circle", {"cx": "5", "cy": "5", "r": "1.8"}, "fg2")],
    "person": [("circle", {"cx": "5", "cy": "3", "r": "2.2"}, "fg"),
               ("path", {"d": "M1 9.8 C1 6.6 3 5.6 5 5.6 C7 5.6 9 6.6 9 9.8 Z"}, "fg")],
    "envelope": [("rect", {"x": "0.6", "y": "1.8", "width": "8.8", "height": "6.4", "rx": "0.6"}, "fg"),
                 ("path", {"d": "M1 2.4 L5 5.6 L9 2.4", "stroke-width": "0.9"}, "line2")],
    "clock": [("circle", {"cx": "5", "cy": "5", "r": "4.5"}, "fg"),
              ("path", {"d": "M5 2.2 V5 L7 6.4", "stroke-width": "1.1"}, "line2")],
    "brackets": [("path", {"d": "M3.4 1.6 L0.8 5 L3.4 8.4 M6.6 1.6 L9.2 5 L6.6 8.4 M5.8 1.2 L4.2 8.8",
                           "stroke-width": "1.2"}, "line")],
    "check": [("circle", {"cx": "5", "cy": "5", "r": "4.5"}, "fg"),
              ("path", {"d": "M2.8 5.2 L4.4 6.8 L7.4 3.6", "stroke-width": "1.2"}, "line2")],
    "hook": [("path", {"d": "M6.4 0.8 V6.2 A2.6 2.6 0 0 1 1.2 6.2 V4.8 M0.2 5.8 L1.2 4.4 L2.2 5.8",
                       "stroke-width": "1.3"}, "line")],
    "branch": [("path", {"d": "M2.6 1.6 V8.4 M2.6 6 C2.6 4 7.4 5 7.4 3", "stroke-width": "1.1"}, "line"),
               ("circle", {"cx": "2.6", "cy": "1.6", "r": "1.2"}, "fg"),
               ("circle", {"cx": "2.6", "cy": "8.4", "r": "1.2"}, "fg"),
               ("circle", {"cx": "7.4", "cy": "2.6", "r": "1.2"}, "fg")],
    "nodes": [("path", {"d": "M2 2.4 L5 5 L8 2.4 M5 5 L2 7.8 M5 5 L8 7.8", "stroke-width": "0.9"}, "line"),
              ("circle", {"cx": "5", "cy": "5", "r": "1.6"}, "fg2"),
              ("circle", {"cx": "2", "cy": "2.4", "r": "1.2"}, "fg"), ("circle", {"cx": "8", "cy": "2.4", "r": "1.2"}, "fg"),
              ("circle", {"cx": "2", "cy": "7.8", "r": "1.2"}, "fg"), ("circle", {"cx": "8", "cy": "7.8", "r": "1.2"}, "fg")],
    "bubble": [("path", {"d": "M1.4 1.2 H8.6 A1 1 0 0 1 9.6 2.2 V6.4 A1 1 0 0 1 8.6 7.4 H4.4 L2.2 9.4 V7.4 H1.4 "
                              "A1 1 0 0 1 0.4 6.4 V2.2 A1 1 0 0 1 1.4 1.2 Z"}, "fg"),
               ("path", {"d": "M2.6 3.6 H7.4 M2.6 5.2 H6", "stroke-width": "0.9"}, "line2")],
    "magnifier": [("circle", {"cx": "4.2", "cy": "4.2", "r": "3.1", "stroke-width": "1.3"}, "ring"),
                  ("path", {"d": "M6.5 6.5 L9.2 9.2", "stroke-width": "1.6"}, "line")],
    "refresh": [("path", {"d": "M8.4 4 A3.6 3.6 0 1 0 8.6 6.2", "stroke-width": "1.2"}, "line"),
                ("path", {"d": "M9.4 1.6 L8.8 4.6 L5.9 3.8 Z"}, "fg")],
    "seal": [("circle", {"cx": "5", "cy": "4", "r": "3.4"}, "fg"),
             ("path", {"d": "M3 6.6 L2.2 9.8 L3.8 9 L4.6 10 L5 7.4 M7 6.6 L7.8 9.8 L6.2 9 L5.4 10 L5 7.4"}, "fg2"),
             ("circle", {"cx": "5", "cy": "4", "r": "1.6"}, "fg2")],
    "fan": [("circle", {"cx": "5", "cy": "5", "r": "4.6"}, "fg2"),
            ("path", {"d": "M5 5 C3.4 3.8 3.6 1.2 5.4 0.9 C6.2 2.2 6 4 5 5 Z M5 5 C6.6 3.8 9 4.6 9 6.4 "
                           "C7.6 7 5.8 6.2 5 5 Z M5 5 C5 7 3 8.6 1.6 7.6 C1.8 6.2 3.4 5.2 5 5 Z"}, "fg")],
    "chip": [("rect", {"x": "2.2", "y": "2.2", "width": "5.6", "height": "5.6", "rx": "0.5"}, "fg"),
             ("rect", {"x": "3.8", "y": "3.8", "width": "2.4", "height": "2.4"}, "fg2"),
             ("path", {"d": "M3.6 0.6 V2.2 M5 0.6 V2.2 M6.4 0.6 V2.2 M3.6 7.8 V9.4 M5 7.8 V9.4 M6.4 7.8 V9.4 "
                            "M0.6 3.6 H2.2 M0.6 5 H2.2 M0.6 6.4 H2.2 M7.8 3.6 H9.4 M7.8 5 H9.4 M7.8 6.4 H9.4",
                       "stroke-width": "0.7"}, "line")],
    "wifi": [("path", {"d": "M1 4.4 A5.6 5.6 0 0 1 9 4.4 M2.6 6 A3.4 3.4 0 0 1 7.4 6", "stroke-width": "1.2"}, "line"),
             ("circle", {"cx": "5", "cy": "8", "r": "1"}, "fg")],
    "dial": [("circle", {"cx": "5", "cy": "5", "r": "4.4"}, "fg"),
             ("circle", {"cx": "5", "cy": "5", "r": "2.4"}, "fg2"),
             ("path", {"d": "M5 0.6 V2 M5 8 V9.4 M0.6 5 H2 M8 5 H9.4", "stroke-width": "0.8"}, "line2")],
    "list": [("path", {"d": "M1 2 H9 M1 5 H9 M1 8 H6", "stroke-width": "1.2"}, "line")],
    "star": [("path", {"d": "M5 0.6 L6.3 3.6 L9.6 3.9 L7.1 6.1 L7.9 9.4 L5 7.6 L2.1 9.4 L2.9 6.1 L0.4 3.9 "
                            "L3.7 3.6 Z"}, "fg")],
    "bug": [("ellipse", {"cx": "5", "cy": "5.8", "rx": "2.8", "ry": "3.6"}, "fg"),
            ("path", {"d": "M5 2.4 V9.2 M2.4 4.4 L0.6 3.4 M7.6 4.4 L9.4 3.4 M2.2 6.4 H0.4 M7.8 6.4 H9.6 "
                           "M2.4 8.2 L0.8 9.4 M7.6 8.2 L9.2 9.4", "stroke-width": "0.8"}, "line")],
    "stack": [("path", {"d": "M5 1 L9.4 3.2 L5 5.4 L0.6 3.2 Z"}, "fg"),
              ("path", {"d": "M0.6 5.2 L5 7.4 L9.4 5.2 M0.6 7.2 L5 9.4 L9.4 7.2", "stroke-width": "1"}, "line")],
    "x": [("path", {"d": "M2 2 L8 8 M8 2 L2 8", "stroke-width": "1.6"}, "line")],
    "doc": [("path", {"d": "M2 0.6 H6.4 L8.6 2.8 V9.4 H2 Z"}, "fg"),
            ("path", {"d": "M3.4 4.4 H7.2 M3.4 6 H7.2 M3.4 7.6 H6", "stroke-width": "0.7"}, "line2")],
    "funnel": [("path", {"d": "M0.6 1 H9.4 L6 5.2 V9 L4 9.8 V5.2 Z"}, "fg")],
    "robot": [("rect", {"x": "1.4", "y": "2.6", "width": "7.2", "height": "6.2", "rx": "1.4"}, "fg"),
              ("circle", {"cx": "3.6", "cy": "5.4", "r": "1"}, "fg2"), ("circle", {"cx": "6.4", "cy": "5.4", "r": "1"}, "fg2"),
              ("path", {"d": "M5 2.6 V0.8", "stroke-width": "0.9"}, "line")],
    "sparkle": [("path", {"d": "M5 0.4 C5.4 3.4 6.6 4.6 9.6 5 C6.6 5.4 5.4 6.6 5 9.6 C4.6 6.6 3.4 5.4 0.4 5 "
                               "C3.4 4.6 4.6 3.4 5 0.4 Z"}, "fg")],
}


def emblem(ic: Icon, b: Box, face: str, name: str, cu=0.5, cv=0.5, size=0.3, fg=WHITE, fg2=None,
           line=None, line2=None, aspect=1.0):
    fg2 = fg2 or fg
    line = line or fg
    line2 = line2 or PAL.mix(fg, BLACK, 0.55)
    kids = []
    for tag, attrs, role in EMBLEMS[name]:
        d = {k: v for k, v in attrs.items()}
        if role in ("fg", "fg2"):
            d["fill"] = fg if role == "fg" else fg2
        else:
            d["fill"] = "none"
            d["stroke"] = {"line": line, "line2": line2, "ring": line}[role]
            d.setdefault("stroke-width", "1")
            d["stroke-linecap"] = "round"
            d["stroke-linejoin"] = "round"
        kids.append((tag, d, None))
    ic.group(b.matrix(face, cu, cv, size, aspect), kids)


# ------------------------------------------------------------ recipes

RECIPES: list = []


def icon(sid, label, category, palette, keywords=(), concept=None):
    def deco(fn):
        RECIPES.append({"id": sid, "label": label, "category": category, "palette": palette,
                        "keywords": list(keywords), "concept": concept or sid, "draw": fn})
        return fn
    return deco


def appliance(ic, f, dz=0.26, dx=0.86, dy=0.62, base_step="base", top_emblem=None, front_emblem=None,
              nports=6, emb_fg=WHITE):
    x0, y0 = -dx / 2, -dy / 2
    shadow(ic, x0, y0, dx, dy)
    b = box(ic, x0, y0, 0, dx, dy, dz, fam(f, base_step))
    if nports:
        ports(ic, b, "L", nports, 0.52, 0.78, u0=0.36, u1=0.94)
        leds(ic, b, "L", (0.1, 0.17, 0.24), 0.62, (A["ok"], A["ok"], A["warn"]))
    if front_emblem:
        emblem(ic, b, "L", front_emblem, cu=0.17 if nports else 0.5, cv=0.32 if nports else 0.5,
               size=min(0.15, dz * 0.6), fg=emb_fg)
    if top_emblem:
        emblem(ic, b, "T", top_emblem, size=min(dx, dy) * 0.62, fg=emb_fg, line=emb_fg)
    return b


def antenna(ic, x, y, z0, h, colour):
    a = P(x, y, z0)
    t = P(x, y, z0 + h)
    ic.line(a, t, colour, 1.3)
    ic.circle(t, 0.9, colour)


# --- network -------------------------------------------------------------

@icon("router", "Router", "network.router", "network", ("gateway", "routing", "layer 3"))
def _router(ic):
    f = "network"
    antenna(ic, -0.32, -0.24, 0.2, 0.55, fam(f, "dark"))
    antenna(ic, 0.3, -0.24, 0.2, 0.55, fam(f, "dark"))
    appliance(ic, f, dz=0.24, top_emblem="swap")


@icon("switch-l2", "Switch (L2)", "network.switch_l2", "network", ("switch", "ethernet", "access switch"))
def _switch(ic):
    f = "network"
    shadow(ic, -0.48, -0.32, 0.96, 0.64)
    b = box(ic, -0.48, -0.32, 0, 0.96, 0.64, 0.2, fam(f, "base"))
    ports(ic, b, "L", 8, 0.22, 0.48, u0=0.12, u1=0.96)
    ports(ic, b, "L", 8, 0.58, 0.84, u0=0.12, u1=0.96)
    leds(ic, b, "L", (0.06,), 0.5, (A["ok"],))
    emblem(ic, b, "T", "swap", size=0.34, fg=fam(f, "light"), line=fam(f, "light"))


@icon("switch-l3", "Switch (L3)", "network.switch_l3", "network", ("core switch", "layer 3 switch", "multilayer"))
def _switch3(ic):
    f = "network"
    shadow(ic, -0.46, -0.34, 0.92, 0.68)
    b = box(ic, -0.46, -0.34, 0, 0.92, 0.68, 0.48, fam(f, "base"))
    for i, (v0, v1) in enumerate(((0.1, 0.3), (0.4, 0.6), (0.7, 0.9))):
        face_rect(ic, b, "L", 0.05, v0 - 0.04, 0.95, v1 + 0.04, fam(f, "dark"))
        ports(ic, b, "L", 8, v0 + 0.03, v1 - 0.03, u0=0.2, u1=0.93)
        leds(ic, b, "L", (0.11,), (v0 + v1) / 2, (A["ok"] if i < 2 else A["warn"],))
    vents(ic, b, "R", 6, 0.2, 0.8, 0.2, 0.8, fam(f, "ink"))
    emblem(ic, b, "T", "swap", size=0.36, fg=fam(f, "light"), line=fam(f, "light"))


@icon("core-switch", "Core Switch", "network.core_switch", "network", ("core", "chassis", "backbone"))
def _core(ic):
    f = "network"
    shadow(ic, -0.42, -0.38, 0.84, 0.76)
    b = box(ic, -0.42, -0.38, 0, 0.84, 0.76, 0.86, fam(f, "dark"))
    for i in range(5):
        v0 = 0.08 + i * 0.17
        face_rect(ic, b, "L", 0.06, v0, 0.94, v0 + 0.13, fam(f, "base"))
        ports(ic, b, "L", 6, v0 + 0.03, v0 + 0.1, u0=0.3, u1=0.92)
        leds(ic, b, "L", (0.15,), v0 + 0.065, (A["ok"],))
    vents(ic, b, "R", 10, 0.15, 0.85, 0.1, 0.9, fam(f, "ink"))


@icon("poe-switch", "PoE Switch", "network.poe_switch", "network", ("power over ethernet", "poe"))
def _poe(ic):
    f = "network"
    shadow(ic, -0.48, -0.32, 0.96, 0.64)
    b = box(ic, -0.48, -0.32, 0, 0.96, 0.64, 0.2, fam(f, "base"))
    ports(ic, b, "L", 8, 0.3, 0.75, u0=0.22, u1=0.96)
    emblem(ic, b, "L", "bolt", cu=0.1, cv=0.52, size=0.13, fg=A["warn"])
    emblem(ic, b, "T", "bolt", size=0.34, fg=A["warn"])


@icon("firewall", "Firewall", "network.firewall", "security", ("security", "packet filter", "fw"))
def _firewall(ic):
    f = "security"
    shadow(ic, -0.42, -0.26, 0.84, 0.52)
    b = box(ic, -0.42, -0.26, 0, 0.84, 0.52, 0.62, fam(f, "base"))
    mortar = PAL.mix(fam(f, "base"), WHITE, 0.55)
    rows = 5
    for r in range(rows + 1):
        v = r / rows
        ic.line(b.fp("L", 0, v), b.fp("L", 1, v), mortar, 0.7)
        ic.line(b.fp("R", 0, v), b.fp("R", 1, v), PAL.mix(fam(f, "dark"), WHITE, 0.35), 0.6)
    for r in range(rows):
        off = 0.0 if r % 2 == 0 else 0.125
        u = off + 0.25
        while u < 1:
            ic.line(b.fp("L", u, r / rows), b.fp("L", u, (r + 1) / rows), mortar, 0.7)
            u += 0.25
        u = (0.0 if r % 2 else 0.17) + 0.33
        while u < 1:
            ic.line(b.fp("R", u, r / rows), b.fp("R", u, (r + 1) / rows), PAL.mix(fam(f, "dark"), WHITE, 0.35), 0.6)
            u += 0.33
    emblem(ic, b, "T", "flame", size=0.36, fg=A["warn"], fg2="#FDE68A")


@icon("ngfw", "Next-Gen Firewall", "security.ngfw", "security", ("ngfw", "next generation firewall", "utm"))
def _ngfw(ic):
    f = "security"
    shadow(ic, -0.44, -0.32, 0.88, 0.64)
    b = box(ic, -0.44, -0.32, 0, 0.88, 0.64, 0.42, fam(f, "base"))
    face_rect(ic, b, "L", 0.05, 0.1, 0.36, 0.9, fam(f, "dark"))
    emblem(ic, b, "L", "shield", cu=0.205, cv=0.5, size=0.2, fg=WHITE, line2=fam(f, "dark"))
    ports(ic, b, "L", 6, 0.55, 0.78, u0=0.44, u1=0.96)
    leds(ic, b, "L", (0.47, 0.54, 0.61), 0.3, (A["ok"], A["ok"], A["warn"]))
    vents(ic, b, "R", 5, 0.2, 0.8, 0.25, 0.75, fam(f, "ink"))
    emblem(ic, b, "T", "flame", size=0.3, fg=A["warn"], fg2="#FDE68A")


@icon("utm", "UTM Appliance", "security.utm", "security", ("unified threat management", "utm"))
def _utm(ic):
    f = "security"
    b = appliance(ic, f, dz=0.3, nports=5)
    emblem(ic, b, "T", "shield", size=0.36, fg=WHITE, line2=fam(f, "base"))


@icon("waf", "Web Application Firewall", "network.waf", "security", ("waf", "web firewall", "application firewall"))
def _waf(ic):
    f = "security"
    shadow(ic, -0.42, -0.3, 0.84, 0.6)
    b = box(ic, -0.42, -0.3, 0, 0.84, 0.6, 0.48, fam(f, "base"))
    emblem(ic, b, "L", "shield", cu=0.5, cv=0.5, size=0.34, fg=WHITE, line2=fam(f, "base"))
    vents(ic, b, "R", 5, 0.2, 0.8, 0.25, 0.75, fam(f, "ink"))
    emblem(ic, b, "T", "globe", size=0.36, fg=fam("network", "base"), line2=WHITE)


@icon("load-balancer", "Load Balancer / ADC", "network.load_balancer", "network", ("lb", "adc", "balancer"))
def _lb(ic):
    appliance(ic, "network", dz=0.26, top_emblem="split")


@icon("access-point", "Access Point", "network.access_point", "network", ("wifi", "wireless", "wlan"))
def _ap(ic):
    f = "network"
    shadow(ic, -0.36, -0.36, 0.72, 0.72)
    cylinder(ic, 0, 0, 0, 0.36, 0.1, fam(f, "light"), top=PAL.mix(fam(f, "tint"), WHITE, 0.3))
    ic.circle(P(0, 0, 0.1), 1.6, A["ok"])
    for r, w in ((9, 1.6), (15, 1.6)):
        c = P(0, 0, 0.55)
        ic.path("M%s %s A%s %s 0 0 1 %s %s" % (fmt(c[0] - r * 0.75), fmt(c[1] - r * 0.25), fmt(r), fmt(r),
                                              fmt(c[0] + r * 0.75), fmt(c[1] - r * 0.25)), "none",
                stroke=fam(f, "base"), stroke_width=fmt(w), stroke_linecap="round")
    ic.circle(P(0, 0, 0.55), 1.7, fam(f, "base"))


@icon("wireless-controller", "Wireless Controller", "network.wireless_controller", "network", ("wlc", "wifi controller"))
def _wlc(ic):
    appliance(ic, "network", dz=0.26, top_emblem="wifi")


@icon("vpn-gateway", "VPN Gateway", "network.vpn_gateway", "network", ("vpn", "ipsec", "tunnel"))
def _vpn(ic):
    f = "network"
    b = appliance(ic, f, dz=0.3, nports=4)
    emblem(ic, b, "T", "lock", size=0.36, fg=A["warn"], line=A["warn"], line2=fam("people", "ink"))


@icon("ids-ips", "IDS / IPS", "network.ids_ips", "security", ("intrusion detection", "intrusion prevention", "ids", "ips"))
def _ids(ic):
    f = "security"
    b = appliance(ic, f, dz=0.3, nports=5)
    emblem(ic, b, "T", "eye", size=0.4, fg=WHITE, fg2=fam(f, "dark"))


@icon("proxy", "Proxy", "network.proxy", "network", ("forward proxy", "reverse proxy"))
def _proxy(ic):
    f = "network"
    b = appliance(ic, f, dz=0.3, nports=4)
    emblem(ic, b, "T", "swap", size=0.36, fg=WHITE, line=WHITE)


@icon("modem", "Modem", "network.modem", "network", ("dsl", "cable modem", "ont", "fibre terminal"))
def _modem(ic):
    f = "network"
    shadow(ic, -0.16, -0.36, 0.32, 0.72)
    b = box(ic, -0.16, -0.36, 0, 0.32, 0.72, 0.56, fam(f, "light"), top=PAL.mix(fam(f, "tint"), WHITE, 0.2))
    leds(ic, b, "R", (0.2, 0.35, 0.5, 0.65), 0.2, (A["ok"], A["ok"], A["info"], A["warn"]), size=0.05)
    vents(ic, b, "R", 4, 0.2, 0.8, 0.55, 0.85, fam(f, "dark"))


@icon("internet", "Internet", "network.internet", "network", ("web", "public network", "www"))
def _internet(ic):
    f = "network"
    shadow(ic, -0.3, -0.3, 0.6, 0.6)
    box(ic, -0.22, -0.22, 0, 0.44, 0.44, 0.08, fam("infra", "light"))
    c = P(0, 0, 0.62)
    sphere(ic, c, 15.5, fam(f, "base"))
    lc = PAL.mix(fam(f, "light"), WHITE, 0.3)
    ic.ellipse(c, 15.5, 5.5, "none", stroke=lc, stroke_width="0.8")
    ic.ellipse(c, 6.5, 15.5, "none", stroke=lc, stroke_width="0.8")
    ic.line((c[0] - 15.5, c[1]), (c[0] + 15.5, c[1]), lc, 0.8)
    ic.line((c[0], c[1] - 15.5), (c[0], c[1] + 15.5), lc, 0.8)


def cloud_shape(ic, cx, cy, s, top, side):
    d = ("M%s %s A%s %s 0 0 1 %s %s A%s %s 0 0 1 %s %s A%s %s 0 0 1 %s %s A%s %s 0 0 1 %s %s Z")
    pts_ = [(-12, 6), (-12.6, -2.6), (-4.6, -9), (8.4, -5), (12, 6)]
    radii = [4.6, 7.2, 8.2, 6]

    def path(dy):
        args = [fmt(cx + pts_[0][0] * s), fmt(cy + pts_[0][1] * s + dy)]
        for (x, y), r in zip(pts_[1:], radii):
            args += [fmt(r * s), fmt(r * s), fmt(cx + x * s), fmt(cy + y * s + dy)]
        return d % tuple(args)
    ic.path(path(4.2), side)
    ic.path(path(0), top)


@icon("cloud", "Cloud", "infra.cloud", "network", ("cloud", "public cloud", "iaas"))
def _cloud(ic):
    f = "network"
    shadow(ic, -0.4, -0.4, 0.8, 0.8, opacity=0.1)
    t, l, r = shades(fam(f, "light"))
    cloud_shape(ic, 32, 34, 1.45, PAL.mix(t, WHITE, 0.25), fam(f, "base"))


@icon("cell-tower", "Cell Tower", "network.cell_tower", "network", ("cellular", "lte", "5g", "mobile network"))
def _tower(ic):
    f = "network"
    shadow(ic, -0.26, -0.26, 0.52, 0.52)
    col = fam("infra", "dark")
    base_pts = [P(-0.22, 0.22), P(0.22, 0.22), P(0.22, -0.22)]
    top_ = P(0, 0, 1.15)
    for p in base_pts:
        ic.line(p, top_, col, 1.1)
    for z in (0.28, 0.56, 0.8):
        k = 1 - z / 1.15
        a, b2, c = (P(-0.22 * k, 0.22 * k, z), P(0.22 * k, 0.22 * k, z), P(0.22 * k, -0.22 * k, z))
        ic.polyline([a, b2, c], col, 0.8)
    for z0, z1 in ((0, 0.28), (0.28, 0.56), (0.56, 0.8)):
        k0, k1 = 1 - z0 / 1.15, 1 - z1 / 1.15
        ic.line(P(-0.22 * k0, 0.22 * k0, z0), P(0.22 * k1, 0.22 * k1, z1), col, 0.6)
        ic.line(P(0.22 * k0, 0.22 * k0, z0), P(0.22 * k1, -0.22 * k1, z1), col, 0.6)
    for dx, dy in ((-0.1, 0.1), (0.1, 0.1), (0.1, -0.1)):
        box(ic, dx - 0.03, dy - 0.03, 0.82, 0.06, 0.06, 0.22, fam(f, "light"), edges=False)
    for r in (5, 9):
        c = P(0, 0, 1.2)
        ic.path("M%s %s A%s %s 0 0 1 %s %s" % (fmt(c[0] - r * 0.7), fmt(c[1] - r * 0.35), fmt(r), fmt(r),
                                              fmt(c[0] + r * 0.7), fmt(c[1] - r * 0.35)), "none",
                stroke=fam(f, "base"), stroke_width="1.3", stroke_linecap="round")


@icon("satellite", "Satellite", "network.satellite", "network", ("satcom", "vsat", "orbit"))
def _sat(ic):
    f = "network"
    shadow(ic, -0.2, -0.2, 0.4, 0.4, opacity=0.08)
    panel = fam(f, "dark")
    for x0 in (-0.86, 0.22):
        b = box(ic, x0, -0.12, 0.62, 0.64, 0.24, 0.03, panel, top=fam(f, "base"), edges=False)
        for i in range(1, 4):
            ic.line(b.fp("T", i / 4, 0), b.fp("T", i / 4, 1), fam(f, "light"), 0.5)
    b = box(ic, -0.17, -0.17, 0.46, 0.34, 0.34, 0.34, fam("infra", "light"))
    emblem(ic, b, "L", "dial", size=0.22, fg=fam("people", "base"), fg2=fam("people", "dark"), line2=WHITE)


@icon("antenna", "Antenna", "network.antenna", "network", ("antenna", "radio", "mast"))
def _antenna(ic):
    f = "network"
    shadow(ic, -0.2, -0.2, 0.4, 0.4)
    box(ic, -0.18, -0.18, 0, 0.36, 0.36, 0.06, fam("infra", "light"))
    cylinder(ic, 0, 0, 0.06, 0.035, 1.0, fam("infra", "base"))
    box(ic, -0.12, 0.02, 0.55, 0.24, 0.07, 0.48, fam(f, "light"))
    for r in (5, 9):
        c = P(0, 0, 1.12)
        ic.path("M%s %s A%s %s 0 0 1 %s %s" % (fmt(c[0] - r * 0.7), fmt(c[1] - r * 0.35), fmt(r), fmt(r),
                                              fmt(c[0] + r * 0.7), fmt(c[1] - r * 0.35)), "none",
                stroke=fam(f, "base"), stroke_width="1.3", stroke_linecap="round")


@icon("patch-panel", "Patch Panel", "network.patch_panel", "network", ("patch panel", "cabling", "keystone"))
def _patch(ic):
    f = "infra"
    shadow(ic, -0.5, -0.12, 1.0, 0.24)
    b = box(ic, -0.5, -0.12, 0, 1.0, 0.24, 0.3, fam(f, "light"))
    ports(ic, b, "L", 10, 0.18, 0.42, u0=0.06, u1=0.97)
    ports(ic, b, "L", 10, 0.58, 0.82, u0=0.06, u1=0.97)


@icon("sdwan-edge", "SD-WAN Edge", "network.sdwan_edge", "network", ("sd-wan", "sdwan", "branch edge"))
def _sdwan(ic):
    f = "network"
    b = appliance(ic, f, dz=0.26)
    emblem(ic, b, "T", "cloud", size=0.42, fg=WHITE)


@icon("dns", "DNS", "network.dns", "network", ("dns", "name server", "resolver"))
def _dns(ic):
    f = "network"
    b = appliance(ic, f, dz=0.3, nports=4)
    emblem(ic, b, "T", "globe", size=0.4, fg=WHITE, line2=fam(f, "base"))


@icon("nat-gateway", "NAT Gateway", "network.nat_gateway", "network", ("nat", "pat", "masquerade"))
def _nat(ic):
    f = "network"
    b = appliance(ic, f, dz=0.26, nports=4)
    emblem(ic, b, "T", "split", size=0.38, fg=WHITE, line=WHITE)


@icon("transit-gateway", "Transit Gateway", "network.transit_gateway", "network", ("transit", "hub", "tgw"))
def _tgw(ic):
    f = "network"
    shadow(ic, -0.46, -0.46, 0.92, 0.92, opacity=0.08)
    hubc = P(0, 0, 0.12)
    for x, y in ((-0.34, -0.34), (0.34, -0.34), (-0.34, 0.34), (0.34, 0.34)):
        ic.line(hubc, P(x, y, 0.08), fam(f, "dark"), 1.4)
    for x, y in ((-0.34, -0.34), (0.34, -0.34), (-0.34, 0.34), (0.34, 0.34)):
        box(ic, x - 0.1, y - 0.1, 0, 0.2, 0.2, 0.16, fam(f, "light"))
    cylinder(ic, 0, 0, 0, 0.2, 0.22, fam(f, "base"))


@icon("cdn", "CDN", "network.cdn", "network", ("content delivery", "edge cache", "cdn"))
def _cdn(ic):
    f = "network"
    shadow(ic, -0.46, -0.46, 0.92, 0.92, opacity=0.08)
    c = P(0, 0, 0.5)
    for x, y in ((-0.38, 0.1), (0.1, 0.38), (0.36, -0.2)):
        ic.line(c, P(x, y, 0.1), fam(f, "dark"), 1.1)
        box(ic, x - 0.08, y - 0.08, 0, 0.16, 0.16, 0.16, fam(f, "light"))
    sphere(ic, c, 11, fam(f, "base"))
    lc = PAL.mix(fam(f, "light"), WHITE, 0.3)
    ic.ellipse(c, 11, 4, "none", stroke=lc, stroke_width="0.7")
    ic.ellipse(c, 4.5, 11, "none", stroke=lc, stroke_width="0.7")


@icon("wireless-bridge", "Wireless Bridge", "network.wireless_bridge", "network", ("point to point", "ptp", "radio link"))
def _bridge(ic):
    f = "network"
    for x in (-0.3, 0.3):
        shadow(ic, x - 0.08, x * -1 - 0.08, 0.16, 0.16)
    for x, y in ((-0.3, 0.3), (0.3, -0.3)):
        cylinder(ic, x, y, 0, 0.03, 0.7, fam("infra", "base"))
        box(ic, x - 0.1, y - 0.03, 0.55, 0.2, 0.06, 0.28, fam(f, "light"))
    a, b = P(-0.3, 0.3, 0.75), P(0.3, -0.3, 0.75)
    ic.el("line", x1=fmt(a[0]), y1=fmt(a[1]), x2=fmt(b[0]), y2=fmt(b[1]), stroke=fam(f, "base"),
          stroke_width="1.2", stroke_linecap="round", stroke_dasharray="2 2")


# --- security --------------------------------------------------------------

@icon("siem", "SIEM / Logging", "security.siem", "security", ("siem", "log management", "splunk", "elastic"))
def _siem(ic):
    f = "security"
    shadow(ic, -0.3, -0.42, 0.6, 0.84)
    b = box(ic, -0.3, -0.42, 0, 0.6, 0.84, 0.7, fam("infra", "dark"))
    for i in range(4):
        v0 = 0.08 + i * 0.22
        face_rect(ic, b, "L", 0.08, v0, 0.92, v0 + 0.16, fam("infra", "base"))
        leds(ic, b, "L", (0.2,), v0 + 0.08, (A["ok"],))
    emblem(ic, b, "R", "chart", size=0.36, fg=fam(f, "light"), fg2=A["warn"])


@icon("soc", "SOC", "security.soc", "security", ("security operations centre", "noc", "monitoring"))
def _soc(ic):
    f = "security"
    shadow(ic, -0.5, -0.3, 1.0, 0.6)
    box(ic, -0.5, -0.06, 0, 1.0, 0.36, 0.3, fam("infra", "light"))
    for x0, ch in ((-0.48, "chart"), (-0.16, "shield"), (0.16, "eye")):
        s = screen_slab(ic, x0, -0.2, 0.36, 0.3, 0.32, fam("infra", "dark"))
        emblem(ic, s, "L", ch, size=0.14, fg=fam(f, "light"), fg2=A["warn"], line2=A["glass"])


@icon("hsm", "HSM", "security.hsm", "security", ("hardware security module", "key store", "crypto"))
def _hsm(ic):
    f = "security"
    shadow(ic, -0.44, -0.3, 0.88, 0.6)
    b = box(ic, -0.44, -0.3, 0, 0.88, 0.6, 0.32, fam("infra", "dark"))
    face_rect(ic, b, "L", 0.05, 0.15, 0.4, 0.85, fam(f, "base"))
    emblem(ic, b, "L", "key", cu=0.225, cv=0.5, size=0.2, fg=WHITE, line=WHITE, fg2=fam(f, "base"))
    leds(ic, b, "L", (0.5, 0.58), 0.5, (A["ok"], A["alert"]))
    emblem(ic, b, "T", "lock", size=0.3, fg=fam(f, "light"), line=fam(f, "light"), line2=fam("infra", "dark"))


@icon("vault", "Secrets Vault", "security.vault", "security", ("secrets", "vault", "key vault", "password manager"))
def _vault(ic):
    f = "security"
    shadow(ic, -0.38, -0.38, 0.76, 0.76)
    b = box(ic, -0.38, -0.38, 0, 0.76, 0.76, 0.7, fam("infra", "base"))
    face_rect(ic, b, "L", 0.07, 0.07, 0.93, 0.93, fam("infra", "dark"))
    emblem(ic, b, "L", "dial", size=0.36, fg=fam(f, "base"), fg2=fam(f, "light"), line2=WHITE)
    for v in (0.25, 0.75):
        face_rect(ic, b, "L", 0.86, v - 0.06, 0.93, v + 0.06, fam("infra", "light"))


@icon("mfa-token", "MFA Token", "security.mfa_token", "security", ("mfa", "2fa", "otp", "authenticator", "yubikey"))
def _mfa(ic):
    f = "security"
    shadow(ic, -0.2, -0.08, 0.4, 0.16)
    b = box(ic, -0.17, -0.05, 0, 0.34, 0.08, 0.82, fam("infra", "dark"))
    face_rect(ic, b, "L", 0.12, 0.14, 0.88, 0.44, A["glass"])
    for i in range(3):
        face_rect(ic, b, "L", 0.2 + i * 0.22, 0.24, 0.32 + i * 0.22, 0.34, A["ok"])
    ic.circle(b.fp("L", 0.5, 0.72), 4.4, fam(f, "base"))
    ic.circle(b.fp("L", 0.5, 0.72), 2.2, fam(f, "light"))


@icon("certificate-authority", "Certificate Authority", "security.certificate_authority", "security",
      ("ca", "pki", "issuing ca", "root ca"))
def _ca(ic):
    f = "security"
    b = appliance(ic, f, dz=0.42, nports=0, base_step="base")
    emblem(ic, b, "L", "seal", size=0.3, fg=A["warn"], fg2=fam("people", "dark"))
    emblem(ic, b, "T", "key", size=0.34, fg=WHITE, line=WHITE, fg2=fam(f, "base"))


@icon("certificate", "Certificate", "security.certificate", "security", ("tls", "ssl", "x509", "pki"))
def _cert(ic):
    f = "security"
    shadow(ic, -0.4, -0.3, 0.8, 0.6)
    b = box(ic, -0.4, -0.3, 0, 0.8, 0.6, 0.04, "#F8FAFC", top="#FFFFFF")
    for v in (0.2, 0.35, 0.5):
        ic.line(b.fp("T", 0.15, v), b.fp("T", 0.7, v), fam("infra", "light"), 0.9)
    emblem(ic, b, "T", "seal", cu=0.72, cv=0.66, size=0.3, fg=fam(f, "base"), fg2=fam(f, "dark"))


@icon("ddos-protection", "DDoS Protection", "security.ddos_protection", "security", ("ddos", "scrubbing", "anti ddos"))
def _ddos(ic):
    f = "security"
    shadow(ic, -0.46, -0.46, 0.92, 0.92, opacity=0.08)
    for x, y in ((-0.38, 0.0), (0.0, 0.38), (-0.3, 0.3)):
        a = P(x, y, 0.1)
        ic.line(a, P(x + 0.18, y - 0.18, 0.1), fam(f, "light"), 1.2)
    b = box(ic, -0.06, -0.4, 0, 0.12, 0.8, 0.62, fam(f, "base"))
    emblem(ic, b, "R", "shield", size=0.42, fg=WHITE, line2=fam(f, "base"))


@icon("email-security", "Email Security", "security.email_security", "security", ("mail gateway", "anti spam", "seg"))
def _mailsec(ic):
    f = "security"
    shadow(ic, -0.42, -0.3, 0.84, 0.6)
    b = box(ic, -0.42, -0.3, 0, 0.84, 0.6, 0.34, fam(f, "base"))
    emblem(ic, b, "L", "envelope", cu=0.36, size=0.3, fg=WHITE, line2=fam(f, "base"))
    emblem(ic, b, "L", "shield", cu=0.8, cv=0.55, size=0.18, fg=A["warn"], line2=fam(f, "dark"))
    vents(ic, b, "R", 4, 0.2, 0.8, 0.3, 0.7, fam(f, "ink"))


@icon("web-gateway", "Secure Web Gateway", "security.web_gateway", "security", ("swg", "web filter", "url filtering"))
def _swg(ic):
    f = "security"
    b = appliance(ic, f, dz=0.3, nports=5)
    emblem(ic, b, "T", "globe", size=0.38, fg=WHITE, line2=fam(f, "base"))


@icon("ztna", "ZTNA Broker", "security.ztna", "security", ("zero trust", "ztna", "access broker", "sdp"))
def _ztna(ic):
    f = "security"
    shadow(ic, -0.46, -0.3, 0.92, 0.6)
    b = box(ic, -0.46, -0.3, 0, 0.92, 0.6, 0.12, fam(f, "light"))
    for x0 in (-0.36, 0.2):
        box(ic, x0, -0.06, 0.12, 0.16, 0.12, 0.52, fam(f, "base"))
    bb = box(ic, -0.36, -0.06, 0.64, 0.72, 0.12, 0.12, fam(f, "dark"))
    emblem(ic, bb, "L", "lock", size=0.1, fg=A["warn"], line=A["warn"], line2=fam("people", "ink"))


@icon("casb", "CASB", "security.casb", "security", ("cloud access security broker", "casb", "saas security"))
def _casb(ic):
    f = "security"
    t, l, r = shades(fam("network", "light"))
    shadow(ic, -0.4, -0.4, 0.8, 0.8, opacity=0.1)
    cloud_shape(ic, 32, 34, 1.35, PAL.mix(t, WHITE, 0.25), fam("network", "base"))
    ic.group("translate(25 25) scale(1.4)", [(t_, dict(a, fill=(WHITE if ro == "fg" else "none"),
                                                         **({} if ro == "fg" else {"stroke": fam(f, "base") if ro == "line" else fam(f, "dark"),
                                                                                  "stroke-width": a.get("stroke-width", "1"),
                                                                                  "stroke-linecap": "round"})), None)
                                             for t_, a, ro in EMBLEMS["shield"]])


@icon("edr", "EDR / XDR", "security.edr", "security", ("endpoint detection", "edr", "xdr", "antivirus"))
def _edr(ic):
    f = "security"
    _laptop_body(ic)
    ic.circle(P(0.34, 0.1, 0.18), 7.5, fam(f, "base"))
    ic.group("translate(%s %s) scale(1)" % (fmt(P(0.34, 0.1, 0.18)[0] - 5), fmt(P(0.34, 0.1, 0.18)[1] - 5)),
             [(t_, dict(a, fill=(WHITE if ro == "fg" else "none"),
                        **({} if ro == "fg" else {"stroke": fam(f, "base"), "stroke-width": a.get("stroke-width", "1"),
                                                  "stroke-linecap": "round"})), None)
              for t_, a, ro in EMBLEMS["shield"]])


@icon("nac", "NAC", "security.nac", "security", ("network access control", "802.1x", "posture"))
def _nac(ic):
    f = "security"
    shadow(ic, -0.48, -0.32, 0.96, 0.64)
    b = box(ic, -0.48, -0.32, 0, 0.96, 0.64, 0.2, fam("network", "base"))
    ports(ic, b, "L", 8, 0.3, 0.75, u0=0.12, u1=0.96)
    emblem(ic, b, "T", "check", size=0.36, fg=fam(f, "base"), line2=WHITE)


@icon("pam", "PAM", "security.pam", "security", ("privileged access", "pam", "jump host", "bastion"))
def _pam(ic):
    f = "security"
    b = appliance(ic, f, dz=0.32, nports=4)
    emblem(ic, b, "T", "key", size=0.36, fg=A["warn"], line=A["warn"], fg2=fam(f, "base"))


@icon("honeypot", "Honeypot", "security.honeypot", "security", ("honeypot", "deception", "decoy"))
def _honey(ic):
    f = "people"
    shadow(ic, -0.3, -0.3, 0.6, 0.6)
    cylinder(ic, 0, 0, 0, 0.3, 0.55, fam(f, "base"), bands=(0.18,))
    cylinder(ic, 0, 0, 0.55, 0.22, 0.08, fam(f, "dark"))
    c = P(0, 0, 0.63)
    ic.path("M%s %s c0 4 -2 6 -2 8 a2 2 0 0 0 4 0 c0 -2 -2 -4 -2 -8 Z" % (fmt(c[0] + 6), fmt(c[1] + 2)),
            fam(f, "light"))
    emblem(ic, Box(-0.21, 0.21, 0.05, 0.42, 0.0, 0.3), "L", "bug", size=0.18, fg=fam("security", "dark"),
           line=fam("security", "dark"))


@icon("dlp", "DLP", "security.dlp", "security", ("data loss prevention", "dlp", "exfiltration"))
def _dlp(ic):
    f = "security"
    shadow(ic, -0.32, -0.4, 0.64, 0.8)
    for i, z in enumerate((0.0, 0.05, 0.1)):
        b = box(ic, -0.32 + i * 0.03, -0.4 + i * 0.03, z, 0.6, 0.76, 0.04, "#F1F5F9", top="#FFFFFF")
    for v in (0.2, 0.34, 0.48):
        ic.line(b.fp("T", 0.15, v), b.fp("T", 0.8, v), fam("infra", "light"), 0.9)
    bb = box(ic, -0.06, -0.06, 0.14, 0.3, 0.3, 0.34, fam(f, "base"))
    emblem(ic, bb, "L", "lock", size=0.22, fg=WHITE, line=WHITE, line2=fam(f, "base"))


@icon("security-zone", "Security Zone", "security.zone", "security", ("zone", "segment", "trust zone"))
def _szone(ic):
    f = "security"
    b = tile(ic, fam(f, "light"), dz=0.08, dashed=True, border=fam(f, "dark"))
    emblem(ic, b, "T", "shield", cu=0.28, cv=0.72, size=0.16, fg=fam(f, "base"), line2=WHITE)


@icon("trust-boundary", "Trust Boundary", "security.trust_boundary", "security", ("trust boundary", "boundary"))
def _tb(ic):
    f = "security"
    b = tile(ic, PAL.mix(fam(f, "tint"), WHITE, 0.3), dz=0.05, dashed=True, border=fam(f, "base"))
    emblem(ic, b, "T", "lock", cu=0.28, cv=0.72, size=0.16, fg=fam(f, "base"), line=fam(f, "base"), line2=WHITE)


@icon("identity", "Identity Provider", "security.identity", "security", ("idp", "iam", "identity", "directory"))
def _idp(ic):
    f = "security"
    shadow(ic, -0.3, -0.42, 0.6, 0.84)
    b = box(ic, -0.3, -0.42, 0, 0.6, 0.84, 0.72, fam("infra", "light"))
    face_rect(ic, b, "L", 0.1, 0.1, 0.9, 0.9, fam(f, "base"))
    emblem(ic, b, "L", "person", size=0.32, fg=WHITE)
    vents(ic, b, "R", 6, 0.2, 0.8, 0.15, 0.85, fam("infra", "dark"))


# --- infrastructure ------------------------------------------------------------

@icon("server", "Server", "infra.server", "infra", ("host", "bare metal", "tower"))
def _server(ic):
    f = "infra"
    shadow(ic, -0.22, -0.42, 0.44, 0.84)
    b = box(ic, -0.22, -0.42, 0, 0.44, 0.84, 0.86, fam(f, "light"))
    face_rect(ic, b, "L", 0.1, 0.06, 0.9, 0.94, fam(f, "dark"))
    for i in range(3):
        v0 = 0.12 + i * 0.13
        face_rect(ic, b, "L", 0.18, v0, 0.82, v0 + 0.09, fam(f, "base"))
        leds(ic, b, "L", (0.72,), v0 + 0.045, (A["ok"],), size=0.04)
    vents(ic, b, "L", 5, 0.25, 0.75, 0.62, 0.86, fam(f, "light"))
    vents(ic, b, "R", 3, 0.6, 0.9, 0.1, 0.25, fam(f, "base"))


@icon("rack-server", "Rack Server", "infra.rack_server", "infra", ("1u", "2u", "rack mount"))
def _rserver(ic):
    f = "infra"
    shadow(ic, -0.44, -0.4, 0.88, 0.8)
    for i in range(3):
        b = box(ic, -0.44, -0.4, i * 0.2, 0.88, 0.8, 0.18, fam(f, "light"))
        face_rect(ic, b, "L", 0.04, 0.15, 0.96, 0.85, fam(f, "dark"))
        ports(ic, b, "L", 6, 0.32, 0.7, u0=0.3, u1=0.9, fill=fam(f, "base"), gap=0.2)
        leds(ic, b, "L", (0.1, 0.17), 0.5, (A["ok"], A["info"]), size=0.035)


@icon("rack", "Rack", "infra.rack", "infra", ("cabinet", "42u", "rack"))
def _rack(ic):
    f = "infra"
    shadow(ic, -0.3, -0.36, 0.6, 0.72)
    b = box(ic, -0.3, -0.36, 0, 0.6, 0.72, 1.12, fam(f, "dark"))
    face_rect(ic, b, "L", 0.08, 0.04, 0.92, 0.96, fam(f, "ink"))
    for i in range(7):
        v0 = 0.06 + i * 0.13
        face_rect(ic, b, "L", 0.12, v0, 0.88, v0 + 0.1, fam(f, "light") if i % 3 else fam(f, "base"))
        leds(ic, b, "L", (0.22, 0.32), v0 + 0.05, (A["ok"], A["ok"] if i % 2 else A["info"]), size=0.035)
    vents(ic, b, "R", 12, 0.15, 0.85, 0.06, 0.94, fam(f, "ink"))


@icon("blade-chassis", "Blade Chassis", "infra.blade_chassis", "infra", ("blade", "chassis", "enclosure"))
def _blade(ic):
    f = "infra"
    shadow(ic, -0.42, -0.36, 0.84, 0.72)
    b = box(ic, -0.42, -0.36, 0, 0.84, 0.72, 0.7, fam(f, "dark"))
    for i in range(8):
        u0 = 0.06 + i * 0.111
        face_rect(ic, b, "L", u0, 0.08, u0 + 0.085, 0.92, fam(f, "light"))
        leds(ic, b, "L", (u0 + 0.0425,), 0.16, (A["ok"] if i % 3 else A["info"],), size=0.03)
    vents(ic, b, "R", 8, 0.15, 0.85, 0.15, 0.85, fam(f, "ink"))


@icon("storage-array", "Storage Array", "infra.storage", "infra", ("storage", "disk array", "san array"), concept="storage")
def _storage(ic):
    f = "infra"
    shadow(ic, -0.42, -0.36, 0.84, 0.72)
    b = box(ic, -0.42, -0.36, 0, 0.84, 0.72, 0.56, fam(f, "light"))
    for r in range(3):
        for c in range(4):
            u0, v0 = 0.06 + c * 0.235, 0.08 + r * 0.3
            face_rect(ic, b, "L", u0, v0, u0 + 0.2, v0 + 0.24, fam(f, "dark"))
            leds(ic, b, "L", (u0 + 0.16,), v0 + 0.06, (A["ok"],), size=0.03)
    emblem(ic, b, "T", "stack", size=0.34, fg=fam("devices", "base"), line=fam("devices", "base"))


@icon("nas", "NAS", "infra.nas", "infra", ("network attached storage", "file server", "nas"))
def _nas(ic):
    f = "infra"
    shadow(ic, -0.28, -0.3, 0.56, 0.6)
    b = box(ic, -0.28, -0.3, 0, 0.56, 0.6, 0.52, fam(f, "dark"))
    for c in range(4):
        u0 = 0.08 + c * 0.215
        face_rect(ic, b, "L", u0, 0.12, u0 + 0.17, 0.78, fam(f, "light"))
        leds(ic, b, "L", (u0 + 0.085,), 0.86, (A["ok"],), size=0.03)


@icon("san", "SAN", "infra.san", "infra", ("storage area network", "fibre channel", "fc"))
def _san(ic):
    f = "infra"
    shadow(ic, -0.46, -0.46, 0.92, 0.92, opacity=0.08)
    for x, y in ((-0.3, 0.12), (0.12, -0.3)):
        b = box(ic, x - 0.17, y - 0.17, 0, 0.34, 0.34, 0.42, fam(f, "light"))
        for r in range(3):
            face_rect(ic, b, "L", 0.1, 0.12 + r * 0.28, 0.9, 0.3 + r * 0.28, fam(f, "dark"))
    sw = box(ic, 0.12, 0.12, 0, 0.32, 0.26, 0.12, fam("devices", "base"))
    ports(ic, sw, "L", 4, 0.3, 0.75, u0=0.15, u1=0.9)


@icon("tape-library", "Tape Library", "infra.tape_library", "infra", ("tape", "lto", "archive"))
def _tape(ic):
    f = "infra"
    shadow(ic, -0.34, -0.38, 0.68, 0.76)
    b = box(ic, -0.34, -0.38, 0, 0.68, 0.76, 1.0, fam(f, "light"))
    face_rect(ic, b, "L", 0.08, 0.06, 0.92, 0.6, fam(f, "dark"))
    for r in range(4):
        for c in range(5):
            u0, v0 = 0.12 + c * 0.16, 0.1 + r * 0.12
            face_rect(ic, b, "L", u0, v0, u0 + 0.12, v0 + 0.08, fam("devices", "light") if (r + c) % 3 else fam("people", "light"))
    face_rect(ic, b, "L", 0.1, 0.7, 0.6, 0.82, A["glass"])
    leds(ic, b, "L", (0.72, 0.8), 0.76, (A["ok"], A["warn"]))


@icon("ups", "UPS", "infra.ups", "infra", ("uninterruptible power supply", "battery", "power"))
def _ups(ic):
    f = "infra"
    shadow(ic, -0.24, -0.4, 0.48, 0.8)
    b = box(ic, -0.24, -0.4, 0, 0.48, 0.8, 0.72, fam(f, "dark"))
    face_rect(ic, b, "L", 0.15, 0.1, 0.85, 0.3, A["glass"])
    face_rect(ic, b, "L", 0.22, 0.16, 0.6, 0.24, A["ok"])
    emblem(ic, b, "L", "bolt", cv=0.62, size=0.24, fg=A["warn"])
    vents(ic, b, "R", 6, 0.2, 0.8, 0.2, 0.8, fam(f, "ink"))


@icon("pdu", "PDU", "infra.pdu", "infra", ("power distribution", "power strip", "pdu"))
def _pdu(ic):
    f = "infra"
    shadow(ic, -0.06, -0.08, 0.12, 0.16)
    b = box(ic, -0.06, -0.06, 0, 0.12, 0.12, 1.2, fam(f, "dark"))
    for i in range(7):
        v = 0.12 + i * 0.12
        face_rect(ic, b, "L", 0.25, v, 0.75, v + 0.06, fam(f, "light"))
    face_rect(ic, b, "L", 0.2, 0.02, 0.8, 0.07, A["ok"])


@icon("cooling", "Cooling Unit", "infra.cooling", "infra", ("crac", "hvac", "air conditioning", "chiller"))
def _cooling(ic):
    f = "infra"
    shadow(ic, -0.4, -0.4, 0.8, 0.8)
    b = box(ic, -0.4, -0.4, 0, 0.8, 0.8, 0.44, fam(f, "light"))
    emblem(ic, b, "T", "fan", size=0.58, fg=fam("network", "light"), fg2=fam(f, "dark"))
    vents(ic, b, "L", 6, 0.1, 0.9, 0.2, 0.8, fam(f, "dark"))
    vents(ic, b, "R", 6, 0.1, 0.9, 0.2, 0.8, fam(f, "ink"))


@icon("generator", "Generator", "infra.generator", "infra", ("diesel generator", "genset", "backup power"))
def _gen(ic):
    f = "infra"
    shadow(ic, -0.46, -0.3, 0.92, 0.6)
    b = box(ic, -0.46, -0.3, 0, 0.92, 0.6, 0.5, fam("people", "base"))
    vents(ic, b, "L", 5, 0.45, 0.92, 0.2, 0.8, fam("people", "dark"))
    face_rect(ic, b, "L", 0.08, 0.2, 0.36, 0.8, fam("people", "dark"))
    emblem(ic, b, "L", "bolt", cu=0.22, size=0.18, fg=WHITE)
    cylinder(ic, 0.25, -0.15, 0.5, 0.05, 0.25, fam(f, "dark"))


@icon("gpu-server", "GPU Server", "infra.gpu_server", "infra", ("gpu", "accelerator", "ai server", "cuda"))
def _gpu(ic):
    f = "infra"
    shadow(ic, -0.44, -0.4, 0.88, 0.8)
    b = box(ic, -0.44, -0.4, 0, 0.88, 0.8, 0.4, fam(f, "dark"))
    for c in range(3):
        emblem(ic, b, "L", "fan", cu=0.2 + c * 0.3, size=0.24, fg=fam(f, "light"), fg2=fam(f, "ink"))
    emblem(ic, b, "T", "chip", size=0.42, fg=fam("software", "base"), fg2=fam("software", "dark"),
           line=fam("software", "light"))


@icon("mainframe", "Mainframe", "infra.mainframe", "infra", ("mainframe", "z series", "big iron"))
def _mainframe(ic):
    f = "infra"
    shadow(ic, -0.46, -0.36, 0.92, 0.72)
    for x0 in (-0.46, 0.02):
        b = box(ic, x0, -0.36, 0, 0.44, 0.72, 1.02, fam(f, "ink"))
        face_rect(ic, b, "L", 0.1, 0.05, 0.9, 0.95, fam(f, "dark"))
        for i in range(8):
            face_rect(ic, b, "L", 0.16, 0.08 + i * 0.11, 0.84, 0.11 + i * 0.11, fam("network", "base"))
        leds(ic, b, "L", (0.3, 0.5, 0.7), 0.04, (A["ok"], A["ok"], A["info"]), size=0.04)


@icon("hypervisor", "Hypervisor", "infra.hypervisor", "infra", ("esxi", "kvm", "proxmox", "hyper-v"))
def _hyp(ic):
    f = "infra"
    shadow(ic, -0.44, -0.44, 0.88, 0.88)
    b = box(ic, -0.44, -0.44, 0, 0.88, 0.88, 0.22, fam(f, "base"))
    ports(ic, b, "L", 5, 0.35, 0.7, u0=0.3, u1=0.9)
    for x, y in ((-0.3, -0.3), (0.06, -0.3), (-0.3, 0.06), (0.06, 0.06)):
        box(ic, x, y, 0.22, 0.24, 0.24, 0.24, fam("devices", "light"))


@icon("virtual-machine", "Virtual Machine", "infra.virtual_machine", "infra", ("vm", "guest", "instance", "ec2"))
def _vm(ic):
    f = "devices"
    shadow(ic, -0.34, -0.34, 0.68, 0.68)
    b = box(ic, -0.34, -0.34, 0, 0.68, 0.68, 0.6, fam(f, "light"))
    for face in ("L", "R"):
        q = b.quad(face, 0.12, 0.12, 0.88, 0.88)
        ic.el("polygon", points=pts(q), fill="none", stroke=WHITE, stroke_width="0.9", stroke_dasharray="2 1.6")
    q = b.quad("T", 0.12, 0.12, 0.88, 0.88)
    ic.el("polygon", points=pts(q), fill="none", stroke=fam(f, "dark"), stroke_width="0.9", stroke_dasharray="2 1.6")


@icon("container", "Container", "infra.container", "infra", ("docker", "oci", "container"))
def _container(ic):
    f = "devices"
    shadow(ic, -0.48, -0.24, 0.96, 0.48)
    b = box(ic, -0.48, -0.24, 0, 0.96, 0.48, 0.46, fam(f, "base"))
    for i in range(1, 9):
        u = i / 9
        ic.line(b.fp("L", u, 0.06), b.fp("L", u, 0.94), fam(f, "dark"), 0.7)
    for i in range(1, 5):
        u = i / 5
        ic.line(b.fp("R", u, 0.06), b.fp("R", u, 0.94), fam(f, "ink"), 0.7)
    ic.line(b.fp("R", 0.5, 0.06), b.fp("R", 0.5, 0.94), fam(f, "light"), 0.9)


@icon("kubernetes", "Kubernetes Cluster", "infra.kubernetes", "infra", ("k8s", "cluster", "orchestration", "openshift"))
def _k8s(ic):
    f = "devices"
    b = tile(ic, fam("infra", "light"), dz=0.07)
    for x, y in ((-0.34, -0.34), (0.04, -0.34), (-0.34, 0.04), (0.04, 0.04)):
        cb = box(ic, x, y, 0.07, 0.3, 0.3, 0.3, fam(f, "base"))
        emblem(ic, cb, "T", "stack", size=0.16, fg=WHITE, line=WHITE)


@icon("pod", "Pod", "infra.pod", "infra", ("pod", "replica", "workload"))
def _pod(ic):
    f = "devices"
    shadow(ic, -0.36, -0.36, 0.72, 0.72)
    box(ic, -0.3, -0.3, 0, 0.26, 0.26, 0.26, fam(f, "light"))
    box(ic, 0.04, -0.3, 0, 0.26, 0.26, 0.26, fam(f, "base"))
    box(ic, -0.3, 0.04, 0, 0.26, 0.26, 0.26, fam(f, "base"))
    box(ic, -0.13, -0.13, 0.26, 0.26, 0.26, 0.26, fam(f, "dark"))


@icon("datacenter", "Data Center", "infra.datacenter", "infra", ("dc", "colocation", "facility"))
def _dc(ic):
    f = "infra"
    shadow(ic, -0.48, -0.42, 0.96, 0.84)
    b = box(ic, -0.48, -0.42, 0, 0.96, 0.84, 0.56, fam(f, "light"))
    face_rect(ic, b, "L", 0.06, 0.62, 0.22, 1.0, fam(f, "dark"))
    for i in range(4):
        face_rect(ic, b, "L", 0.3 + i * 0.17, 0.2, 0.42 + i * 0.17, 0.5, fam("network", "dark"))
    for i in range(3):
        face_rect(ic, b, "R", 0.12 + i * 0.28, 0.2, 0.3 + i * 0.28, 0.5, fam("network", "ink"))
    for x in (-0.3, 0.0, 0.26):
        cb = box(ic, x, -0.3, 0.56, 0.18, 0.18, 0.1, fam(f, "base"), edges=False)
        emblem(ic, cb, "T", "fan", size=0.14, fg=fam(f, "light"), fg2=fam(f, "dark"))


@icon("edge-node", "Edge Node", "infra.edge_node", "infra", ("edge", "mec", "branch compute"))
def _edge(ic):
    f = "infra"
    antenna(ic, 0.12, -0.2, 0.3, 0.5, fam("network", "dark"))
    shadow(ic, -0.3, -0.26, 0.6, 0.52)
    b = box(ic, -0.3, -0.26, 0, 0.6, 0.52, 0.3, fam(f, "base"))
    ports(ic, b, "L", 3, 0.4, 0.7, u0=0.45, u1=0.92)
    leds(ic, b, "L", (0.15, 0.25), 0.55, (A["ok"], A["info"]))
    emblem(ic, b, "T", "chip", size=0.26, fg=fam(f, "light"), fg2=fam(f, "dark"), line=fam(f, "light"))


@icon("object-storage", "Object Storage", "infra.object_storage", "infra", ("s3", "bucket", "blob", "object store"))
def _obj(ic):
    f = "devices"
    shadow(ic, -0.36, -0.36, 0.72, 0.72)
    t, l, r = shades(fam(f, "base"))
    c0, c1 = P(0, 0, 0), P(0, 0, 0.75)
    r0, r1 = 0.26, 0.36
    rx0, ry0 = r0 * SX * math.sqrt(2), r0 * SY * math.sqrt(2)
    rx1, ry1 = r1 * SX * math.sqrt(2), r1 * SY * math.sqrt(2)
    ic.path("M%s %s L%s %s A%s %s 0 0 0 %s %s L%s %s A%s %s 0 0 1 %s %s Z" % (
        fmt(c1[0] - rx1), fmt(c1[1]), fmt(c0[0] - rx0), fmt(c0[1]), fmt(rx0), fmt(ry0), fmt(c0[0]), fmt(c0[1] + ry0),
        fmt(c1[0]), fmt(c1[1] + ry1), fmt(rx1), fmt(ry1), fmt(c1[0] - rx1), fmt(c1[1])), l)
    ic.path("M%s %s L%s %s A%s %s 0 0 1 %s %s L%s %s A%s %s 0 0 0 %s %s Z" % (
        fmt(c1[0] + rx1), fmt(c1[1]), fmt(c0[0] + rx0), fmt(c0[1]), fmt(rx0), fmt(ry0), fmt(c0[0]), fmt(c0[1] + ry0),
        fmt(c1[0]), fmt(c1[1] + ry1), fmt(rx1), fmt(ry1), fmt(c1[0] + rx1), fmt(c1[1])), r)
    ic.ellipse(c1, rx1, ry1, t)
    ic.ellipse(c1, rx1 * 0.82, ry1 * 0.82, fam(f, "dark"))
    for i, col in enumerate((fam("people", "light"), fam("data", "light"), fam("network", "light"))):
        ic.circle((c1[0] - 5 + i * 5, c1[1] - 1 + (i % 2) * 2), 2.6, col)


@icon("file-share", "File Share", "infra.file_share", "infra", ("smb", "nfs", "cifs", "share"))
def _share(ic):
    f = "people"
    shadow(ic, -0.42, -0.32, 0.84, 0.64)
    b = box(ic, -0.42, -0.32, 0, 0.84, 0.64, 0.42, fam(f, "base"), top=fam(f, "light"))
    tab = box(ic, -0.42, -0.32, 0.42, 0.34, 0.64, 0.06, fam(f, "base"), top=fam(f, "light"), edges=False)
    face_rect(ic, b, "L", 0.1, 0.18, 0.9, 0.24, fam(f, "dark"))
    emblem(ic, b, "L", "nodes", cv=0.6, size=0.22, fg=WHITE, fg2=WHITE, line=WHITE)


@icon("backup", "Backup", "infra.backup", "infra", ("backup", "snapshot", "restore", "dr"))
def _backup(ic):
    f = "infra"
    shadow(ic, -0.38, -0.32, 0.76, 0.64)
    b = box(ic, -0.38, -0.32, 0, 0.76, 0.64, 0.4, fam(f, "light"))
    face_rect(ic, b, "L", 0.06, 0.15, 0.94, 0.85, fam(f, "dark"))
    emblem(ic, b, "L", "refresh", size=0.26, fg=A["ok"], line=A["ok"])
    emblem(ic, b, "T", "clock", size=0.36, fg=WHITE, line2=fam(f, "dark"))


@icon("ha-cluster", "Cluster / HA Pair", "infra.ha_cluster", "infra", ("ha", "failover", "cluster", "active passive"))
def _ha(ic):
    f = "infra"
    shadow(ic, -0.48, -0.42, 0.96, 0.84)
    for x0 in (-0.46, 0.06):
        b = box(ic, x0, -0.4, 0, 0.38, 0.8, 0.7, fam(f, "light"))
        face_rect(ic, b, "L", 0.1, 0.08, 0.9, 0.92, fam(f, "dark"))
        for i in range(3):
            face_rect(ic, b, "L", 0.2, 0.15 + i * 0.15, 0.8, 0.24 + i * 0.15, fam(f, "base"))
        leds(ic, b, "L", (0.5,), 0.8, (A["ok"] if x0 < 0 else A["warn"],))


def _platform(ic, f, base, dashed, border, emb):
    b = tile(ic, base, dz=0.06, dashed=dashed, border=border)
    if emb:
        emblem(ic, b, "T", emb, cu=0.28, cv=0.72, size=0.16, fg=border, line=border, line2=WHITE)
    return b


@icon("region", "Region", "infra.region", "infra", ("region", "geography", "location"))
def _region(ic):
    _platform(ic, "infra", fam("infra", "light"), False, fam("infra", "dark"), "globe")


@icon("availability-zone", "Availability Zone", "infra.availability_zone", "infra", ("az", "zone", "fault domain"))
def _az(ic):
    _platform(ic, "infra", fam("devices", "light"), True, fam("devices", "ink"), "stack")


@icon("vpc", "VPC / VNet", "network.vpc", "network", ("vpc", "vnet", "virtual network", "vcn"))
def _vpc(ic):
    _platform(ic, "network", fam("network", "light"), True, fam("network", "ink"), "cloud")


@icon("subnet", "Subnet", "network.subnet", "network", ("subnet", "cidr", "prefix"))
def _subnet(ic):
    b = tile(ic, fam("network", "tint"), dz=0.04, dashed=True, border=fam("network", "base"))
    for x, y in ((-0.25, -0.25), (0.1, -0.25), (-0.25, 0.1), (0.1, 0.1)):
        box(ic, x, y, 0.04, 0.14, 0.14, 0.1, fam("network", "base"))


@icon("dmz", "DMZ", "network.dmz", "security", ("dmz", "perimeter", "demilitarized zone"))
def _dmz(ic):
    f = "security"
    b = tile(ic, fam("people", "light"), dz=0.06, dashed=True, border=fam(f, "dark"))
    for x0 in (-0.42, 0.34):
        box(ic, x0, -0.42, 0.06, 0.08, 0.84, 0.3, fam(f, "base"))


@icon("lan", "LAN", "network.lan", "network", ("lan", "local network", "internal network"))
def _lan(ic):
    f = "network"
    tile(ic, fam(f, "tint"), dz=0.04)
    hub = P(0, 0, 0.14)
    for x, y in ((-0.3, -0.3), (0.3, -0.3), (-0.3, 0.3), (0.3, 0.3)):
        ic.line(hub, P(x, y, 0.12), fam(f, "dark"), 1.1)
    for x, y in ((-0.3, -0.3), (0.3, -0.3), (-0.3, 0.3), (0.3, 0.3)):
        box(ic, x - 0.08, y - 0.08, 0.04, 0.16, 0.16, 0.14, fam(f, "light"))
    box(ic, -0.16, -0.1, 0.04, 0.32, 0.2, 0.1, fam(f, "base"))


# --- data --------------------------------------------------------------------

@icon("database", "Database", "infra.database", "data", ("db", "sql", "rdbms", "postgres", "mysql"))
def _db(ic):
    f = "data"
    shadow(ic, -0.36, -0.36, 0.72, 0.72)
    cylinder(ic, 0, 0, 0, 0.34, 0.86, fam(f, "base"), bands=(0.29, 0.57))


@icon("data-warehouse", "Data Warehouse", "data.warehouse", "data", ("warehouse", "olap", "dwh", "snowflake", "bigquery"))
def _dwh(ic):
    f = "data"
    shadow(ic, -0.46, -0.46, 0.92, 0.92, opacity=0.08)
    for i, (x, y) in enumerate(((-0.22, -0.22), (0.22, -0.22), (-0.22, 0.22), (0.22, 0.22))):
        cylinder(ic, x, y, 0, 0.2, 0.62 if i in (0, 3) else 0.46, fam(f, "base") if i != 3 else fam(f, "dark"),
                 bands=(0.22,))


@icon("data-lake", "Data Lake", "data.lake", "data", ("lake", "lakehouse", "raw data"))
def _lake(ic):
    f = "data"
    b = tile(ic, fam("infra", "light"), dz=0.12)
    q = b.quad("T", 0.1, 0.1, 0.9, 0.9)
    ic.poly(q, fam(f, "base"))
    for v in (0.35, 0.55, 0.75):
        a, c = b.fp("T", 0.25, v), b.fp("T", 0.75, v)
        mx, my = (a[0] + c[0]) / 2, (a[1] + c[1]) / 2
        ic.path("M%s %s Q%s %s %s %s" % (fmt(a[0]), fmt(a[1]), fmt(mx), fmt(my - 3), fmt(c[0]), fmt(c[1])),
                "none", stroke=fam(f, "light"), stroke_width="0.9", stroke_linecap="round")
    cylinder(ic, -0.25, -0.25, 0.12, 0.08, 0.3, fam(f, "dark"))


@icon("cache", "Cache", "data.cache", "data", ("redis", "memcached", "in memory", "cache"))
def _cache(ic):
    f = "data"
    shadow(ic, -0.36, -0.36, 0.72, 0.72)
    c = cylinder(ic, 0, 0, 0, 0.34, 0.4, fam(f, "light"), bands=(0.2,))
    ic.group("translate(%s %s) scale(1.3 0.75)" % (fmt(c.top[0] - 6.5), fmt(c.top[1] - 3.75)),
             [(t_, dict(a, fill=A["warn"]), None) for t_, a, ro in EMBLEMS["bolt"]])


@icon("queue", "Queue", "software.queue", "data", ("mq", "message queue", "sqs", "rabbitmq"))
def _queue(ic):
    f = "data"
    shadow(ic, -0.5, -0.18, 1.0, 0.36)
    box(ic, -0.5, -0.16, 0, 1.0, 0.32, 0.06, fam("infra", "light"))
    for i in range(4):
        box(ic, -0.44 + i * 0.24, -0.1, 0.06, 0.2, 0.2, 0.2, fam(f, "base") if i < 3 else fam(f, "light"))


@icon("event-stream", "Event Stream", "data.event_stream", "data", ("kafka", "kinesis", "pubsub", "stream"))
def _stream(ic):
    f = "data"
    shadow(ic, -0.5, -0.12, 1.0, 0.24, opacity=0.1)
    _pipe(ic, fam(f, "base"))
    for i, u in enumerate((-0.3, 0.0, 0.3)):
        box(ic, u - 0.06, -0.06, 0.2, 0.12, 0.12, 0.12, fam("people", "light") if i == 1 else fam(f, "light"))


def _pipe(ic, colour, z=0.0, r=0.12):
    """Horizontal pipe along x (a lying cylinder)."""
    t, l, rr = shades(colour)
    a0, a1 = P(-0.5, 0, z + r), P(0.5, 0, z + r)
    # rim ellipse of a circle in the y-z plane: axes along y (-28, 14) and z (0, -31)
    ey = (-SX * r, SY * r)
    ez = (0, -SZ * r)
    def ring(c, n=24):
        return [(c[0] + ey[0] * math.cos(t_) + ez[0] * math.sin(t_), c[1] + ey[1] * math.cos(t_) + ez[1] * math.sin(t_))
                for t_ in (2 * math.pi * i / n for i in range(n))]
    r0, r1 = ring(a0), ring(a1)
    ic.poly([r0[i] for i in range(0, 13)] + [r1[i] for i in range(12, -1, -1)], rr)
    ic.poly([r0[i] for i in list(range(12, 24)) + [0]] + [r1[i] for i in [0] + list(range(23, 11, -1))], l)
    ic.poly(r1, t)
    ic.poly([(a1[0] + (p[0] - a1[0]) * 0.6, a1[1] + (p[1] - a1[1]) * 0.6) for p in r1], rr)


@icon("pipe", "Pipe", "generic.pipe", "infra", ("pipe", "connector", "link", "trunk"))
def _pipe_icon(ic):
    shadow(ic, -0.5, -0.12, 1.0, 0.24, opacity=0.1)
    _pipe(ic, fam("infra", "light"))


@icon("search-index", "Search Index", "data.search_index", "data", ("elasticsearch", "opensearch", "solr", "index"))
def _search(ic):
    f = "data"
    shadow(ic, -0.36, -0.36, 0.72, 0.72)
    c = cylinder(ic, 0, 0, 0, 0.32, 0.62, fam(f, "base"), bands=(0.31,))
    ic.group("translate(%s %s) scale(1.5)" % (fmt(c.top[0] - 7.5), fmt(c.top[1] - 2)),
             [(t_, dict(a, fill="none", stroke=WHITE, **{"stroke-width": a.get("stroke-width", "1"),
                                                           "stroke-linecap": "round"}), None)
              for t_, a, ro in EMBLEMS["magnifier"]])


@icon("etl", "ETL / Pipeline", "data.etl", "data", ("etl", "elt", "data pipeline", "airflow", "dbt"))
def _etl(ic):
    f = "data"
    shadow(ic, -0.42, -0.42, 0.84, 0.84)
    t, l, r = shades(fam(f, "base"))
    c0, c1 = P(0, 0, 0.12), P(0, 0, 0.8)
    r0, r1 = 0.1, 0.4
    rx0, ry0 = r0 * SX * math.sqrt(2), r0 * SY * math.sqrt(2)
    rx1, ry1 = r1 * SX * math.sqrt(2), r1 * SY * math.sqrt(2)
    cylinder(ic, 0, 0, 0, 0.1, 0.14, fam(f, "dark"))
    ic.path("M%s %s L%s %s A%s %s 0 0 0 %s %s L%s %s A%s %s 0 0 1 %s %s Z" % (
        fmt(c1[0] - rx1), fmt(c1[1]), fmt(c0[0] - rx0), fmt(c0[1]), fmt(rx0), fmt(ry0), fmt(c0[0]), fmt(c0[1] + ry0),
        fmt(c1[0]), fmt(c1[1] + ry1), fmt(rx1), fmt(ry1), fmt(c1[0] - rx1), fmt(c1[1])), l)
    ic.path("M%s %s L%s %s A%s %s 0 0 1 %s %s L%s %s A%s %s 0 0 0 %s %s Z" % (
        fmt(c1[0] + rx1), fmt(c1[1]), fmt(c0[0] + rx0), fmt(c0[1]), fmt(rx0), fmt(ry0), fmt(c0[0]), fmt(c0[1] + ry0),
        fmt(c1[0]), fmt(c1[1] + ry1), fmt(rx1), fmt(ry1), fmt(c1[0] + rx1), fmt(c1[1])), r)
    ic.ellipse(c1, rx1, ry1, t)
    ic.ellipse(c1, rx1 * 0.8, ry1 * 0.8, fam(f, "dark"))
    for i, col in enumerate((fam("network", "light"), fam("people", "light"), fam("software", "light"))):
        box(ic, -0.16 + i * 0.1, -0.06 - i * 0.04, 0.72, 0.1, 0.1, 0.1, col, edges=False)


@icon("bi-dashboard", "BI Dashboard", "data.bi_dashboard", "data", ("dashboard", "bi", "reporting", "grafana", "power bi"))
def _bi(ic):
    f = "data"
    shadow(ic, -0.42, -0.2, 0.84, 0.4)
    box(ic, -0.06, -0.06, 0, 0.12, 0.12, 0.2, fam("infra", "dark"))
    s = screen_slab(ic, -0.46, -0.04, 0.18, 0.92, 0.66, fam("infra", "dark"), glass="#F8FAFC")
    emblem(ic, s, "L", "chart", cu=0.3, size=0.3, fg=fam(f, "light"), fg2=fam(f, "base"))
    for i, col in enumerate((fam(f, "base"), fam("people", "base"), fam("software", "base"))):
        face_rect(ic, s, "L", 0.6, 0.2 + i * 0.2, 0.6 + 0.08 + i * 0.07, 0.3 + i * 0.2, col)


@icon("ml-model", "ML Model", "data.ml_model", "data", ("machine learning", "model", "inference", "neural network"))
def _ml(ic):
    f = "data"
    shadow(ic, -0.34, -0.34, 0.68, 0.68)
    b = box(ic, -0.34, -0.34, 0, 0.68, 0.68, 0.62, fam(f, "base"))
    emblem(ic, b, "L", "nodes", size=0.42, fg=WHITE, fg2=A["warn"], line=fam(f, "light"))
    emblem(ic, b, "R", "nodes", size=0.42, fg=fam(f, "light"), fg2=fam(f, "light"), line=fam(f, "base"))
    emblem(ic, b, "T", "sparkle", size=0.36, fg=WHITE)


@icon("llm", "LLM", "data.llm", "data", ("large language model", "llm", "gpt", "foundation model", "genai"))
def _llm(ic):
    f = "data"
    shadow(ic, -0.34, -0.34, 0.68, 0.68)
    b = box(ic, -0.34, -0.34, 0, 0.68, 0.68, 0.62, fam(f, "dark"))
    emblem(ic, b, "L", "bubble", size=0.44, fg=WHITE, line2=fam(f, "dark"))
    emblem(ic, b, "R", "sparkle", size=0.32, fg=fam(f, "light"))
    emblem(ic, b, "T", "sparkle", size=0.36, fg=A["warn"])


@icon("ai-agent", "AI Agent", "data.ai_agent", "data", ("agent", "assistant", "bot", "copilot"))
def _agent(ic):
    f = "data"
    shadow(ic, -0.3, -0.3, 0.6, 0.6)
    box(ic, -0.18, -0.18, 0, 0.36, 0.36, 0.34, fam(f, "dark"))
    b = box(ic, -0.3, -0.3, 0.34, 0.6, 0.6, 0.5, fam(f, "light"))
    face_rect(ic, b, "L", 0.1, 0.15, 0.9, 0.75, A["glass"])
    for u in (0.32, 0.68):
        face_rect(ic, b, "L", u - 0.09, 0.32, u + 0.09, 0.52, A["info"])
    antenna(ic, 0, 0, 0.84, 0.22, fam(f, "dark"))
    face_rect(ic, b, "R", 0.3, 0.3, 0.7, 0.6, fam(f, "base"))


# --- software ----------------------------------------------------------------

def _window(ic, f, emb=None, emb_kw=None):
    shadow(ic, -0.44, -0.12, 0.88, 0.24)
    s = box(ic, -0.44, -0.04, 0, 0.88, 0.08, 0.86, fam("infra", "light"))
    face_rect(ic, s, "L", 0.04, 0.04, 0.96, 0.18, fam(f, "base"))
    for i, col in enumerate((A["alert"], A["warn"], A["ok"])):
        face_rect(ic, s, "L", 0.07 + i * 0.07, 0.08, 0.11 + i * 0.07, 0.14, col)
    face_rect(ic, s, "L", 0.04, 0.2, 0.96, 0.96, "#FFFFFF")
    if emb:
        emblem(ic, s, "L", emb, cv=0.58, **(emb_kw or {}))
    return s


@icon("application", "Application", "software.application", "software", ("app", "software", "program"))
def _app(ic):
    f = "software"
    s = _window(ic, f)
    for i, w in enumerate((0.7, 0.5, 0.6)):
        face_rect(ic, s, "L", 0.12, 0.32 + i * 0.16, 0.12 + w * 0.8, 0.4 + i * 0.16, fam(f, "light"))


@icon("web-app", "Web App", "software.web_app", "software", ("web application", "site", "portal", "frontend"))
def _webapp(ic):
    f = "software"
    _window(ic, f, "globe", {"size": 0.4, "fg": fam(f, "base"), "line2": WHITE})


@icon("browser", "Browser", "software.browser", "software", ("browser", "web client", "chrome", "firefox"))
def _browser(ic):
    f = "network"
    s = _window(ic, f)
    face_rect(ic, s, "L", 0.25, 0.07, 0.9, 0.15, fam(f, "light"))
    for i in range(3):
        face_rect(ic, s, "L", 0.1, 0.3 + i * 0.2, 0.9, 0.42 + i * 0.2, fam("infra", "tint"))


@icon("microservice", "Microservice", "software.microservice", "software", ("service", "microservice", "svc"))
def _micro(ic):
    f = "software"
    shadow(ic, -0.42, -0.42, 0.84, 0.84, opacity=0.1)
    for x, y, c in ((-0.36, -0.36, "light"), (0.06, -0.36, "base"), (-0.36, 0.06, "base"), (0.06, 0.06, "dark")):
        box(ic, x, y, 0, 0.3, 0.3, 0.3, fam(f, c))


@icon("api", "API", "software.api", "software", ("rest", "graphql", "endpoint", "openapi"))
def _api(ic):
    f = "software"
    shadow(ic, -0.38, -0.3, 0.76, 0.6)
    b = box(ic, -0.38, -0.3, 0, 0.76, 0.6, 0.48, fam(f, "base"))
    emblem(ic, b, "L", "brackets", size=0.36, fg=WHITE, line=WHITE)
    vents(ic, b, "R", 4, 0.2, 0.8, 0.3, 0.7, fam(f, "ink"))


@icon("api-gateway", "API Gateway", "software.api_gateway", "software", ("api gateway", "apim", "kong", "ingress"))
def _apigw(ic):
    f = "software"
    shadow(ic, -0.46, -0.24, 0.92, 0.48)
    box(ic, -0.46, -0.2, 0, 0.18, 0.4, 0.7, fam(f, "base"))
    box(ic, 0.28, -0.2, 0, 0.18, 0.4, 0.7, fam(f, "base"))
    bb = box(ic, -0.46, -0.2, 0.7, 0.92, 0.4, 0.18, fam(f, "dark"))
    emblem(ic, bb, "L", "brackets", size=0.16, fg=WHITE, line=WHITE)
    for i in range(3):
        box(ic, -0.2 + i * 0.16, -0.05, 0, 0.08, 0.08, 0.08, fam("people", "light"), edges=False)


@icon("function", "Function", "software.function", "software", ("serverless", "faas", "function", "lambda"))
def _func(ic):
    f = "software"
    shadow(ic, -0.3, -0.3, 0.6, 0.6)
    b = box(ic, -0.3, -0.3, 0, 0.6, 0.6, 0.54, fam(f, "light"))
    emblem(ic, b, "L", "bolt", size=0.3, fg=fam(f, "dark"))
    emblem(ic, b, "T", "brackets", size=0.32, fg=fam(f, "dark"), line=fam(f, "dark"))


@icon("message-bus", "Message Bus", "software.message_bus", "software", ("esb", "bus", "event bus", "integration"))
def _bus(ic):
    f = "software"
    shadow(ic, -0.5, -0.5, 1.0, 1.0, opacity=0.08)
    box(ic, -0.5, -0.08, 0, 1.0, 0.16, 0.1, fam(f, "dark"))
    for x in (-0.36, 0.0, 0.32):
        ic.line(P(x, -0.3, 0.12), P(x, 0, 0.1), fam(f, "dark"), 1.0)
        ic.line(P(x + 0.04, 0.08, 0.1), P(x + 0.04, 0.34, 0.12), fam(f, "dark"), 1.0)
    for x in (-0.36, 0.0, 0.32):
        box(ic, x - 0.07, -0.44, 0, 0.14, 0.14, 0.14, fam(f, "light"))
    for x in (-0.36, 0.0, 0.32):
        box(ic, x - 0.03, 0.3, 0, 0.14, 0.14, 0.14, fam(f, "base"))


@icon("ci-cd", "CI/CD Pipeline", "software.ci_cd", "software", ("ci", "cd", "pipeline", "jenkins", "github actions", "gitlab ci"))
def _cicd(ic):
    f = "software"
    shadow(ic, -0.5, -0.14, 1.0, 0.28)
    box(ic, -0.5, -0.12, 0, 1.0, 0.24, 0.05, fam("infra", "light"))
    cols = (fam("network", "base"), fam("people", "base"), fam(f, "base"))
    for i, c in enumerate(cols):
        b = box(ic, -0.44 + i * 0.32, -0.1, 0.05, 0.22, 0.2, 0.22, c)
    for i in range(2):
        a = P(-0.22 + i * 0.32, 0.1, 0.16)
        c = P(-0.12 + i * 0.32, 0.1, 0.16)
        ic.line(a, c, fam("infra", "dark"), 1.2)
    emblem(ic, b, "T", "check", size=0.16, fg=WHITE, line2=fam(f, "base"))


@icon("git-repo", "Git Repository", "software.git_repo", "software", ("git", "repository", "source control", "gitea", "github"))
def _git(ic):
    f = "software"
    shadow(ic, -0.34, -0.4, 0.68, 0.8)
    b = box(ic, -0.34, -0.4, 0, 0.68, 0.8, 0.3, fam(f, "base"))
    face_rect(ic, b, "L", 0, 0.1, 1, 0.3, fam(f, "dark"))
    emblem(ic, b, "T", "branch", size=0.44, fg=WHITE, line=WHITE)


@icon("container-registry", "Container Registry", "software.container_registry", "software",
      ("registry", "harbor", "docker hub", "image registry"))
def _registry(ic):
    f = "devices"
    shadow(ic, -0.46, -0.3, 0.92, 0.6)
    box(ic, -0.46, -0.3, 0, 0.92, 0.6, 0.06, fam("infra", "light"))
    for i, (x, z, c) in enumerate(((-0.42, 0.06, "base"), (0.02, 0.06, "dark"), (-0.2, 0.36, "light"))):
        b = box(ic, x, -0.22, z, 0.42, 0.42, 0.3, fam(f, c))
        for k in range(1, 5):
            ic.line(b.fp("L", k / 5, 0.1), b.fp("L", k / 5, 0.9), fam(f, "ink"), 0.6)


@icon("artifact-store", "Artifact Store", "software.artifact_store", "software", ("artifactory", "nexus", "packages", "artifacts"))
def _artifacts(ic):
    f = "software"
    shadow(ic, -0.4, -0.4, 0.8, 0.8)
    for i, (x, y, z) in enumerate(((-0.36, -0.36, 0), (0.02, -0.36, 0), (-0.36, 0.02, 0), (-0.17, -0.17, 0.34))):
        b = box(ic, x, y, z, 0.34, 0.34, 0.34, fam(f, "base") if i < 3 else fam("people", "base"))
        ic.line(b.fp("T", 0.5, 0), b.fp("T", 0.5, 1), PAL.mix(fam(f, "light"), WHITE, 0.3), 0.9)


@icon("scheduler", "Scheduler / Cron", "software.scheduler", "software", ("cron", "scheduler", "job", "timer"))
def _sched(ic):
    f = "software"
    shadow(ic, -0.34, -0.3, 0.68, 0.6)
    b = box(ic, -0.34, -0.3, 0, 0.68, 0.6, 0.5, fam(f, "base"))
    emblem(ic, b, "L", "clock", size=0.36, fg=WHITE, line2=fam(f, "dark"))
    emblem(ic, b, "T", "refresh", size=0.3, fg=WHITE, line=WHITE)


@icon("webhook", "Webhook", "software.webhook", "software", ("webhook", "callback", "http hook"))
def _webhook(ic):
    f = "software"
    shadow(ic, -0.3, -0.3, 0.6, 0.6)
    b = box(ic, -0.3, -0.3, 0, 0.6, 0.6, 0.18, fam(f, "light"))
    c = P(0, 0, 0.18)
    ic.group("translate(%s %s) scale(2.4)" % (fmt(c[0] - 10), fmt(c[1] - 24)),
             [(t_, dict(a, fill="none", stroke=fam(f, "dark"), **{"stroke-width": "1.1", "stroke-linecap": "round"}), None)
              for t_, a, ro in EMBLEMS["hook"]])


@icon("email", "Email", "software.email", "software", ("mail", "smtp", "imap", "exchange"))
def _email(ic):
    f = "software"
    shadow(ic, -0.42, -0.1, 0.84, 0.2)
    b = box(ic, -0.42, -0.06, 0, 0.84, 0.12, 0.6, fam(f, "light"), top=fam(f, "tint"))
    ic.poly([b.fp("L", 0, 0), b.fp("L", 0.5, 0.58), b.fp("L", 1, 0)], fam(f, "base"))
    ic.polyline([b.fp("L", 0.02, 0.98), b.fp("L", 0.4, 0.5)], WHITE, 0.9)
    ic.polyline([b.fp("L", 0.98, 0.98), b.fp("L", 0.6, 0.5)], WHITE, 0.9)
    ic.circle(b.fp("L", 0.94, 0.06), 4, A["alert"])


@icon("sms", "SMS", "software.sms", "software", ("sms", "text message", "notification"))
def _sms(ic):
    f = "software"
    _phone(ic)
    c = P(0.15, -0.3, 0.9)
    ic.group("translate(%s %s) scale(1.7)" % (fmt(c[0] - 4), fmt(c[1] - 12)),
             [(t_, dict(a, fill=(fam(f, "base") if ro == "fg" else "none"),
                        **({} if ro == "fg" else {"stroke": WHITE, "stroke-width": a.get("stroke-width", "1"),
                                                  "stroke-linecap": "round"})), None)
              for t_, a, ro in EMBLEMS["bubble"]])


@icon("chat", "Chat", "software.chat", "software", ("chat", "slack", "teams", "messaging", "im"))
def _chat(ic):
    f = "software"
    shadow(ic, -0.36, -0.12, 0.72, 0.24)
    b = box(ic, -0.36, -0.04, 0.08, 0.72, 0.1, 0.62, fam(f, "base"))
    ic.poly([b.fp("L", 0.18, 1), b.fp("L", 0.4, 1), P(-0.3, 0.06, 0.0)], fam(f, "base"))
    for i, w in enumerate((0.7, 0.5)):
        face_rect(ic, b, "L", 0.14, 0.3 + i * 0.24, 0.14 + w * 0.8, 0.42 + i * 0.24, WHITE)


@icon("document", "Document", "flow.document", "software", ("file", "report", "doc", "paper"))
def _doc(ic):
    f = "software"
    shadow(ic, -0.3, -0.12, 0.6, 0.24)
    b = box(ic, -0.3, -0.04, 0, 0.6, 0.06, 0.82, "#F8FAFC", top="#FFFFFF")
    ic.poly([b.fp("L", 0.72, 0), b.fp("L", 1, 0), b.fp("L", 1, 0.2)], fam("infra", "light"))
    for i in range(5):
        face_rect(ic, b, "L", 0.14, 0.28 + i * 0.13, 0.86 - (0.3 if i == 4 else 0), 0.33 + i * 0.13, fam(f, "light"))


@icon("identity-provider", "Identity Provider", "software.identity_provider", "security", ("sso", "saml", "oidc", "oauth", "idp"))
def _sso(ic):
    f = "security"
    shadow(ic, -0.4, -0.3, 0.8, 0.6)
    b = box(ic, -0.4, -0.3, 0, 0.8, 0.6, 0.36, fam("infra", "light"))
    face_rect(ic, b, "L", 0.06, 0.12, 0.94, 0.88, fam(f, "base"))
    emblem(ic, b, "L", "key", cu=0.3, size=0.2, fg=WHITE, line=WHITE, fg2=fam(f, "base"))
    emblem(ic, b, "L", "person", cu=0.72, size=0.2, fg=WHITE)
    emblem(ic, b, "T", "check", size=0.3, fg=A["ok"], line2=WHITE)


# --- people & places -----------------------------------------------------------

def person(ic, x, y, colour, z=0.0, scale=1.0, shadow_=True):
    if shadow_:
        shadow(ic, x - 0.13 * scale, y - 0.13 * scale, 0.26 * scale, 0.26 * scale, grow=0.02)
    t, l, r = shades(colour)
    c = cylinder(ic, x, y, z, 0.13 * scale, 0.42 * scale, colour)
    hc = P(x, y, z + 0.66 * scale)
    sphere(ic, hc, 5.4 * scale, fam("people", "light"))
    return c


@icon("user", "User", "security.user", "people", ("person", "employee", "end user", "human"))
def _user(ic):
    person(ic, 0, 0, fam("people", "base"), scale=1.25)


@icon("admin", "Administrator", "security.admin", "people", ("admin", "operator", "root", "sysadmin"))
def _admin(ic):
    person(ic, -0.05, 0.05, fam("infra", "dark"), scale=1.25)
    c = P(0.28, -0.12, 0.3)
    ic.circle(c, 6, fam("people", "base"))
    ic.group("translate(%s %s) scale(1)" % (fmt(c[0] - 5), fmt(c[1] - 5)),
             [("path", {"d": _gear(8, 4.4, 3.3, 1.5), "fill": WHITE, "fill-rule": "evenodd"}, None)])


@icon("team", "Team", "people.team", "people", ("group", "team", "department", "squad"))
def _team(ic):
    person(ic, -0.25, -0.25, fam("people", "dark"), scale=0.95)
    person(ic, 0.25, -0.12, fam("people", "base"), scale=0.95)
    person(ic, -0.12, 0.25, fam("people", "base"), scale=0.95)


@icon("customer", "Customer", "people.customer", "people", ("client", "buyer", "consumer", "customer"))
def _customer(ic):
    person(ic, -0.04, 0.04, fam("software", "base"), scale=1.2)
    c = P(0.3, -0.16, 0.25)
    ic.circle(c, 5.5, fam("people", "base"))
    ic.group("translate(%s %s) scale(0.9)" % (fmt(c[0] - 4.5), fmt(c[1] - 4.5)),
             [("path", dict(EMBLEMS["star"][0][1], fill=WHITE), None)])


@icon("vendor", "Vendor / Partner", "people.vendor", "people", ("supplier", "partner", "third party", "vendor"))
def _vendor(ic):
    shadow(ic, -0.46, -0.46, 0.4, 0.4)
    b = box(ic, -0.46, -0.46, 0, 0.4, 0.4, 0.8, fam("infra", "light"))
    for i in range(4):
        face_rect(ic, b, "L", 0.15, 0.1 + i * 0.22, 0.85, 0.22 + i * 0.22, fam("network", "dark"))
        face_rect(ic, b, "R", 0.15, 0.1 + i * 0.22, 0.85, 0.22 + i * 0.22, fam("network", "ink"))
    person(ic, 0.16, 0.16, fam("software", "dark"), scale=1.1)


@icon("soc-analyst", "SOC Analyst", "people.soc_analyst", "people", ("analyst", "security analyst", "blue team"))
def _analyst(ic):
    box(ic, -0.42, -0.12, 0, 0.84, 0.34, 0.3, fam("infra", "light"))
    s = screen_slab(ic, -0.3, -0.2, 0.36, 0.6, 0.36, fam("infra", "dark"))
    emblem(ic, s, "L", "shield", size=0.16, fg=fam("security", "light"), line2=A["glass"])
    person(ic, 0.0, 0.42, fam("security", "base"), scale=0.9, shadow_=False)


@icon("on-call", "On-call Engineer", "people.on_call", "people", ("pager", "on call", "sre", "duty"))
def _oncall(ic):
    person(ic, -0.06, 0.06, fam("network", "base"), scale=1.2)
    c = P(0.3, -0.18, 0.62)
    ic.circle(c, 6, A["alert"])
    ic.group("translate(%s %s) scale(0.9)" % (fmt(c[0] - 4.5), fmt(c[1] - 4.5)),
             [("path", {"d": "M5 1 C3 1 2.4 2.6 2.4 4.4 V6.4 L1.4 7.6 H8.6 L7.6 6.4 V4.4 C7.6 2.6 7 1 5 1 Z M4 8.4 "
                             "A1 1 0 0 0 6 8.4 Z", "fill": WHITE}, None)])


@icon("building", "Building / Site", "people.site", "people", ("office", "site", "branch", "campus", "location"))
def _building(ic):
    f = "infra"
    shadow(ic, -0.38, -0.32, 0.76, 0.64)
    b = box(ic, -0.38, -0.32, 0, 0.76, 0.64, 1.0, fam(f, "light"))
    for r in range(5):
        for c in range(4):
            face_rect(ic, b, "L", 0.1 + c * 0.22, 0.08 + r * 0.17, 0.24 + c * 0.22, 0.18 + r * 0.17, fam("network", "dark"))
        for c in range(3):
            face_rect(ic, b, "R", 0.12 + c * 0.28, 0.08 + r * 0.17, 0.3 + c * 0.28, 0.18 + r * 0.17, fam("network", "ink"))
    face_rect(ic, b, "L", 0.4, 0.88, 0.6, 1, fam(f, "ink"))


@icon("headquarters", "Headquarters", "people.headquarters", "people", ("hq", "head office", "headquarters"))
def _hq(ic):
    f = "infra"
    shadow(ic, -0.46, -0.42, 0.92, 0.84)
    b2 = box(ic, -0.46, -0.42, 0, 0.36, 0.84, 0.6, fam(f, "base"))
    b = box(ic, -0.06, -0.3, 0, 0.5, 0.6, 1.12, fam(f, "light"))
    for r in range(7):
        for c in range(3):
            face_rect(ic, b, "L", 0.12 + c * 0.28, 0.06 + r * 0.13, 0.3 + c * 0.28, 0.14 + r * 0.13, fam("network", "dark"))
        face_rect(ic, b, "R", 0.15, 0.06 + r * 0.13, 0.85, 0.14 + r * 0.13, fam("network", "ink"))
    for r in range(4):
        face_rect(ic, b2, "L", 0.15, 0.1 + r * 0.2, 0.85, 0.2 + r * 0.2, fam("network", "dark"))


@icon("branch-office", "Branch Office", "people.branch", "people", ("branch", "store", "remote office"))
def _branch(ic):
    f = "people"
    shadow(ic, -0.42, -0.32, 0.84, 0.64)
    b = box(ic, -0.42, -0.32, 0, 0.84, 0.64, 0.42, fam("infra", "light"))
    roof(ic, b, 0.3, fam(f, "dark"))
    face_rect(ic, b, "L", 0.1, 0.3, 0.32, 0.6, fam("network", "dark"))
    face_rect(ic, b, "L", 0.42, 0.4, 0.58, 1, fam(f, "dark"))
    face_rect(ic, b, "L", 0.68, 0.3, 0.9, 0.6, fam("network", "dark"))


@icon("home-office", "Home Office", "people.home_office", "people", ("home", "remote worker", "telework", "house"))
def _home(ic):
    f = "people"
    shadow(ic, -0.34, -0.34, 0.68, 0.68)
    b = box(ic, -0.34, -0.34, 0, 0.68, 0.68, 0.4, PAL.mix(fam(f, "tint"), WHITE, 0.2))
    roof(ic, b, 0.36, fam("security", "base"))
    face_rect(ic, b, "L", 0.18, 0.35, 0.42, 1, fam(f, "dark"))
    face_rect(ic, b, "L", 0.58, 0.3, 0.84, 0.62, fam("network", "dark"))
    face_rect(ic, b, "R", 0.3, 0.3, 0.7, 0.62, fam("network", "ink"))


# --- devices -------------------------------------------------------------------

def _laptop_body(ic):
    f = "devices"
    shadow(ic, -0.4, -0.3, 0.8, 0.62)
    base = box(ic, -0.4, -0.3, 0, 0.8, 0.6, 0.05, fam("infra", "light"))
    kb = base.quad("T", 0.08, 0.15, 0.92, 0.62)
    ic.poly(kb, fam("infra", "base"))
    ic.poly(base.quad("T", 0.38, 0.7, 0.62, 0.9), fam("infra", "tint"))
    s = screen_slab(ic, -0.4, -0.34, 0.05, 0.8, 0.52, fam("infra", "dark"), thick=0.04, bezel=0.05)
    return s


@icon("laptop", "Laptop", "devices.laptop", "devices", ("notebook", "laptop", "workstation", "client"))
def _laptop(ic):
    s = _laptop_body(ic)
    emblem(ic, s, "L", "cloud", size=0.2, fg=fam("devices", "light"))


@icon("desktop", "Desktop", "devices.desktop", "devices", ("pc", "workstation", "desktop", "monitor"))
def _desktop(ic):
    f = "devices"
    shadow(ic, -0.46, -0.3, 0.92, 0.62)
    box(ic, 0.2, -0.36, 0, 0.24, 0.6, 0.62, fam("infra", "dark"))
    box(ic, -0.26, -0.12, 0, 0.3, 0.2, 0.03, fam("infra", "light"))
    box(ic, -0.15, -0.06, 0.03, 0.08, 0.06, 0.2, fam("infra", "base"))
    s = screen_slab(ic, -0.44, -0.12, 0.2, 0.66, 0.44, fam("infra", "dark"))
    emblem(ic, s, "L", "chart", size=0.18, fg=fam(f, "light"), fg2=fam(f, "base"))
    box(ic, -0.44, 0.18, 0, 0.56, 0.16, 0.03, fam("infra", "light"))


@icon("thin-client", "Thin Client", "devices.thin_client", "devices", ("vdi", "thin client", "zero client"))
def _thin(ic):
    f = "devices"
    shadow(ic, -0.46, -0.3, 0.92, 0.62)
    b = box(ic, 0.24, -0.16, 0, 0.1, 0.36, 0.36, fam(f, "base"))
    leds(ic, b, "R", (0.2,), 0.15, (A["ok"],), size=0.04)
    box(ic, -0.2, -0.1, 0, 0.2, 0.16, 0.03, fam("infra", "light"))
    box(ic, -0.13, -0.05, 0.03, 0.06, 0.05, 0.16, fam("infra", "base"))
    s = screen_slab(ic, -0.44, -0.1, 0.16, 0.6, 0.42, fam("infra", "dark"))
    emblem(ic, s, "L", "cloud", size=0.18, fg=fam(f, "light"))


def _phone(ic, w=0.34, h=0.72, f="devices"):
    shadow(ic, -w / 2, -0.06, w, 0.12)
    b = box(ic, -w / 2, -0.03, 0, w, 0.05, h, fam("infra", "ink"))
    face_rect(ic, b, "L", 0.08, 0.06, 0.92, 0.9, PAL.mix(fam(f, "base"), BLACK, 0.1))
    face_rect(ic, b, "L", 0.08, 0.06, 0.92, 0.3, fam(f, "light"))
    for r in range(2):
        for c in range(3):
            face_rect(ic, b, "L", 0.18 + c * 0.24, 0.38 + r * 0.17, 0.34 + c * 0.24, 0.5 + r * 0.17, WHITE, opacity="0.85")
    face_rect(ic, b, "L", 0.4, 0.93, 0.6, 0.96, fam("infra", "base"))
    return b


@icon("phone", "Phone", "devices.phone", "devices", ("smartphone", "mobile", "cell phone", "iphone", "android"))
def _phone_icon(ic):
    _phone(ic)


@icon("mobile-app", "Mobile App", "software.mobile_app", "software", ("mobile app", "ios app", "android app"))
def _mapp(ic):
    _phone(ic, f="software")


@icon("tablet", "Tablet", "devices.tablet", "devices", ("tablet", "ipad", "slate"))
def _tablet(ic):
    f = "devices"
    shadow(ic, -0.36, -0.06, 0.72, 0.12)
    b = box(ic, -0.36, -0.03, 0, 0.72, 0.05, 0.86, fam("infra", "ink"))
    face_rect(ic, b, "L", 0.06, 0.05, 0.94, 0.93, PAL.mix(fam(f, "base"), BLACK, 0.1))
    face_rect(ic, b, "L", 0.06, 0.05, 0.94, 0.3, fam(f, "light"))
    for r in range(2):
        for c in range(4):
            face_rect(ic, b, "L", 0.14 + c * 0.2, 0.4 + r * 0.2, 0.26 + c * 0.2, 0.52 + r * 0.2, WHITE, opacity="0.85")


@icon("printer", "Printer", "devices.printer", "devices", ("printer", "mfp", "copier", "print server"))
def _printer(ic):
    f = "devices"
    shadow(ic, -0.42, -0.36, 0.84, 0.72)
    paper = box(ic, -0.22, -0.3, 0.4, 0.44, 0.2, 0.2, "#F8FAFC", top="#FFFFFF", edges=False)
    b = box(ic, -0.42, -0.36, 0, 0.84, 0.72, 0.42, fam("infra", "light"))
    face_rect(ic, b, "L", 0.15, 0.35, 0.85, 0.5, fam("infra", "ink"))
    box(ic, -0.26, 0.36, 0.1, 0.52, 0.12, 0.02, "#F8FAFC", top="#FFFFFF", edges=False)
    face_rect(ic, b, "R", 0.12, 0.12, 0.42, 0.3, A["glass"])
    leds(ic, b, "R", (0.55, 0.65), 0.2, (A["ok"], A["info"]))


@icon("scanner", "Scanner", "devices.scanner", "devices", ("scanner", "document scanner", "flatbed"))
def _scanner(ic):
    f = "devices"
    shadow(ic, -0.44, -0.32, 0.88, 0.64)
    b = box(ic, -0.44, -0.32, 0, 0.88, 0.64, 0.16, fam("infra", "light"))
    ic.poly(b.quad("T", 0.06, 0.08, 0.94, 0.92), fam("infra", "ink"))
    ic.poly(b.quad("T", 0.06, 0.55, 0.94, 0.62), A["info"], opacity="0.85")
    leds(ic, b, "L", (0.9,), 0.5, (A["ok"],))


@icon("ip-phone", "IP Phone", "devices.ip_phone", "devices", ("voip", "sip phone", "desk phone"))
def _ipphone(ic):
    f = "devices"
    shadow(ic, -0.34, -0.3, 0.68, 0.6)
    t, l, r = shades(fam("infra", "dark"))
    b = Box(-0.34, -0.3, 0, 0.68, 0.6, 0.3)
    # wedge body: high at the back, low at the front
    hb, hf = 0.32, 0.1
    ic.poly([P(b.x0, b.y1, 0), P(b.x1, b.y1, 0), P(b.x1, b.y1, hf), P(b.x0, b.y1, hf)], l)
    ic.poly([P(b.x1, b.y0, 0), P(b.x1, b.y1, 0), P(b.x1, b.y1, hf), P(b.x1, b.y0, hb)], r)
    top = [P(b.x0, b.y0, hb), P(b.x1, b.y0, hb), P(b.x1, b.y1, hf), P(b.x0, b.y1, hf)]
    ic.poly(top, t)

    def tp(u, v):
        return P(b.x0 + u * 0.68, b.y0 + v * 0.6, hb + (hf - hb) * v)
    ic.poly([tp(0.05, 0.1), tp(0.25, 0.1), tp(0.25, 0.9), tp(0.05, 0.9)], fam("infra", "ink"))
    ic.poly([tp(0.35, 0.1), tp(0.9, 0.1), tp(0.9, 0.4), tp(0.35, 0.4)], fam(f, "light"))
    for rr in range(3):
        for c in range(3):
            u, v = 0.4 + c * 0.17, 0.5 + rr * 0.14
            ic.poly([tp(u, v), tp(u + 0.1, v), tp(u + 0.1, v + 0.08), tp(u, v + 0.08)], fam("infra", "tint"))


@icon("ip-camera", "IP Camera", "devices.ip_camera", "devices", ("cctv", "camera", "surveillance", "nvr"))
def _cam(ic):
    f = "devices"
    shadow(ic, -0.14, -0.14, 0.28, 0.28)
    box(ic, -0.05, -0.05, 0, 0.1, 0.1, 0.5, fam("infra", "base"))
    b = box(ic, -0.42, -0.14, 0.5, 0.62, 0.28, 0.26, fam("infra", "tint"))
    # lens on the front-left end (x0 face is hidden, so put the lens on the L face near u=0)
    ic.circle(b.fp("L", 0.18, 0.5), 5.4, fam("infra", "ink"))
    ic.circle(b.fp("L", 0.18, 0.5), 3, fam(f, "base"))
    ic.circle(b.fp("L", 0.18, 0.5), 1.1, "#FFFFFF", opacity="0.8")
    leds(ic, b, "L", (0.85,), 0.3, (A["alert"],))


@icon("smart-tv", "Smart TV / Display", "devices.smart_tv", "devices", ("tv", "display", "signage", "screen"))
def _tv(ic):
    f = "devices"
    shadow(ic, -0.46, -0.16, 0.92, 0.32)
    box(ic, -0.3, -0.12, 0, 0.6, 0.24, 0.03, fam("infra", "dark"))
    box(ic, -0.04, -0.03, 0.03, 0.08, 0.06, 0.14, fam("infra", "dark"))
    s = screen_slab(ic, -0.5, -0.04, 0.17, 1.0, 0.62, fam("infra", "ink"), thick=0.04, bezel=0.04)
    emblem(ic, s, "L", "star", size=0.2, fg=fam(f, "light"))


@icon("iot-sensor", "IoT Sensor", "devices.iot_sensor", "devices", ("iot", "sensor", "thermostat", "smart device"))
def _iot(ic):
    f = "devices"
    shadow(ic, -0.28, -0.28, 0.56, 0.56)
    cylinder(ic, 0, 0, 0, 0.26, 0.2, fam("infra", "tint"))
    cylinder(ic, 0, 0, 0.2, 0.14, 0.05, fam(f, "base"))
    for r in (7, 11):
        c = P(0, 0, 0.55)
        ic.path("M%s %s A%s %s 0 0 1 %s %s" % (fmt(c[0] - r * 0.7), fmt(c[1] - r * 0.3), fmt(r), fmt(r),
                                              fmt(c[0] + r * 0.7), fmt(c[1] - r * 0.3)), "none",
                stroke=fam(f, "dark"), stroke_width="1.3", stroke_linecap="round")


@icon("plc", "PLC / OT Controller", "devices.plc", "devices", ("plc", "ot", "scada", "ics", "industrial"))
def _plc(ic):
    f = "devices"
    shadow(ic, -0.5, -0.22, 1.0, 0.44)
    rail = box(ic, -0.5, 0.0, 0.1, 1.0, 0.04, 0.12, fam("infra", "base"), edges=False)
    for i in range(5):
        c = fam(f, "base") if i == 0 else fam("infra", "light")
        b = box(ic, -0.46 + i * 0.18, -0.16, 0, 0.16, 0.32, 0.6, c)
        leds(ic, b, "L", (0.3, 0.7), 0.15, (A["ok"], A["warn"] if i % 2 else A["ok"]), size=0.03)
        for k in range(4):
            face_rect(ic, b, "L", 0.2, 0.35 + k * 0.14, 0.8, 0.42 + k * 0.14, fam("infra", "ink"))


@icon("badge-reader", "Badge Reader", "devices.badge_reader", "devices", ("access control", "rfid", "card reader", "door"))
def _badge(ic):
    f = "devices"
    shadow(ic, -0.42, -0.1, 0.84, 0.2)
    wall = box(ic, -0.46, -0.08, 0, 0.5, 0.06, 1.0, fam("infra", "tint"))
    face_rect(ic, wall, "L", 0.15, 0.25, 0.85, 1, fam("people", "dark"))
    b = box(ic, 0.12, -0.06, 0.4, 0.2, 0.06, 0.32, fam("infra", "ink"))
    face_rect(ic, b, "L", 0.15, 0.1, 0.85, 0.5, fam(f, "base"))
    leds(ic, b, "L", (0.5,), 0.75, (A["ok"],), size=0.04)


# ----------------------------------------------------------------- output

FAMILIES = {
    "network": {"label": "Network"}, "security": {"label": "Security"}, "infra": {"label": "Infrastructure"},
    "devices": {"label": "End-user devices"}, "data": {"label": "Data & AI"}, "software": {"label": "Software"},
    "people": {"label": "People & places"}, "flow": {"label": "Flow / Decision"}, "generic": {"label": "Generic"},
}


def _extent(svg_text: str):
    """(xs, ys) of every drawn point outside the emblem groups (those use local 0..10 coordinates)."""
    import re
    xs, ys = [], []
    body = re.sub(r"<g transform=.*?</g>", "", svg_text)
    for m in re.finditer(r'points="([^"]+)"', body):
        nums = [float(v) for v in m.group(1).split()]
        xs += nums[0::2]
        ys += nums[1::2]
    for m in re.finditer(r'<(circle|ellipse)\b([^>]*)/>', body):
        a = dict(re.findall(r'([a-z]+)="([-0-9.]+)"', m.group(2)))
        cx, cy = float(a["cx"]), float(a["cy"])
        rx, ry = (float(a["r"]), float(a["r"])) if m.group(1) == "circle" else (float(a["rx"]), float(a["ry"]))
        xs += [cx - rx, cx + rx]
        ys += [cy - ry, cy + ry]
    for m in re.finditer(r'<line\b[^>]*?x1="([-0-9.]+)" y1="([-0-9.]+)" x2="([-0-9.]+)" y2="([-0-9.]+)"', body):
        xs += [float(m.group(1)), float(m.group(3))]
        ys += [float(m.group(2)), float(m.group(4))]
    for m in re.finditer(r' d="([^"]+)"', body):
        for sub, _closed in GEO.flatten(GEO.parse_path(m.group(1))):
            xs += [p[0] for p in sub]
            ys += [p[1] for p in sub]
    return xs, ys


def _check_bounds(sid: str, svg_text: str):
    """Every shape stays inside the viewBox (nothing clipped)."""
    xs, ys = _extent(svg_text)
    if xs and (min(xs) < 0.5 or max(xs) > VB - 0.5 or min(ys) < 0.5 or max(ys) > VB - 0.5):
        raise ValueError("%s leaves the viewBox: x %.1f..%.1f y %.1f..%.1f" % (sid, min(xs), max(xs), min(ys), max(ys)))


def _frac(v):
    return round(0.14 + 0.72 * v / VB, 4)


def ports_for(svg_text: str):
    """Ports on the RIM of the symbol box (the interior is the move zone): west/east
    at the height of the floor tile's side corners, south below the front corner,
    north above the drawing (the back corner hides behind every solid, so it and
    the top-most point are one port). Same ids as the flat library, so a connector
    pinned to a port survives a Flat <-> 3D switch."""
    inset = 0.08
    side_y = _frac(P(-0.5, 0.5)[1])
    return [{"id": "n", "x": 0.5, "y": inset}, {"id": "e", "x": 1 - inset, "y": side_y},
            {"id": "s", "x": 0.5, "y": 1 - inset}, {"id": "w", "x": inset, "y": side_y}]


def _ids(path):
    try:
        with open(path, "rb") as fh:
            return {s["id"] for s in json.loads(fh.read().decode("utf-8")).get("symbols", [])}
    except (OSError, ValueError):
        return set()


def build(out_dir: str = HERE, siblings_dir: str | None = None) -> dict:
    """Write every icon and ``library.json`` into *out_dir*; returns ``{file name: bytes}``.

    *siblings_dir* holds the ``generic`` and ``color`` libraries (for the variant links).
    """
    siblings_dir = siblings_dir or os.path.dirname(HERE)
    gen_ids = _ids(os.path.join(siblings_dir, "generic", "library.json"))
    col_ids = _ids(os.path.join(siblings_dir, "color", "library.json"))
    files: dict = {}
    syms = []
    seen = set()
    classes: dict = {}
    for r in RECIPES:
        assert r["id"] not in seen, r["id"]
        seen.add(r["id"])
        ic = Icon()
        r["draw"](ic)
        text = ic.svg()
        _check_bounds(r["id"], text)
        name = r["id"] + ".svg"
        files[name] = text.encode("utf-8")
        famid, cls = r["category"].split(".")
        classes.setdefault(famid, {})[cls] = r["label"]
        variants = {}
        if r["concept"] in gen_ids:
            variants["generic"] = r["concept"]
        if r["concept"] in col_ids:
            variants["color"] = r["concept"]
        syms.append({"id": r["id"], "label": r["label"], "category": r["category"], "shape": "symbol",
                     "w": 96, "h": 96, "ports": ports_for(text), "keywords": r["keywords"] + ["3d", "isometric"],
                     "aliases": {}, "style": {"fill": "none", "stroke": "none"}, "svg": name,
                     "variants": variants})
    fams = {f: {"label": FAMILIES[f]["label"], "classes": dict(sorted(classes[f].items()))}
            for f in FAMILIES if f in classes}
    lib = {"schema": "satom.symbols/1", "id": "iso3d", "label": "Isometric 3D", "version": "1.0",
           "license": "ELv2 (original artwork, drawn for SATOM)", "variant": "iso3d", "anchor": ANCHOR,
           "families": fams, "symbols": syms}
    files["library.json"] = (json.dumps(lib, indent=1, sort_keys=False, ensure_ascii=True) + "\n").encode("utf-8")
    os.makedirs(out_dir, exist_ok=True)
    for name in sorted(files):
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(files[name])
    return files


if __name__ == "__main__":
    out = build(sys.argv[1] if len(sys.argv) > 1 else HERE)
    print("%d icons, %d bytes" % (len(out) - 1, sum(len(v) for k, v in out.items() if k.endswith(".svg"))))
