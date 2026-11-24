"""Visio reader: ``.vsdx`` (OPC ZIP) and ``.vdx`` (Visio XML Drawing).

Both formats describe the same Shape/Cell/Section model; ``.vsdx`` writes cells
as ``<Cell N= V=>``, the older ``.vdx`` as named elements (``<XForm><PinX>``).
Both are loaded into one internal form (:class:`VShape`) first.

Geometry: lengths are inches (x96 -> px); the Visio Y axis points UP from the
page bottom, so every point is flipped with ``PageHeight``. Each shape has a
local frame (origin bottom-left of its box); a child's PinX/PinY is in its
parent's frame, so absolute positions are composed through an affine transform
(translation, rotation about the pin, flips) down the group tree. Elements
carry the unrotated box plus ``rotation`` (degrees clockwise) about its centre.

Inheritance: missing cells, geometry (scaled to the instance size), text and
Shape Data come from the Master (``Master``/``MasterShape``) and then from the
document stylesheets (``LineStyle``/``FillStyle``/``TextStyle``).

Connectors: ``<Connects>`` are the truth for glue; the connector's own geometry
supplies waypoints. 1-D shapes without Connects become free-ended connectors.

Colour styling: a gradient fill (``FillGradientEnabled`` with its
``FillGradient`` stops, or a legacy gradient ``FillPattern`` 25-40) becomes
``style.gradient`` (first stop -> ``fill``, last stop -> ``gradient.color``,
``FillGradientAngle`` -> angle); a shadow (``ShdwPattern``) becomes
``style.shadow`` + ``ShdwForegnd``; ``LinePattern`` 2/3/4 -> dashed/dotted/dash-dot.

Approximated (reported once per kind): themes, gradients with more than two
stops or a rectangular/path direction (drawn as radial), arcs (SVG arcs / quadratic curves), NURBS/splines (straight lines),
custom text-block positions, vector pictures (EMF/WMF, skipped), background
pages (skipped), multi-layer membership (first layer only), arrowhead styles.
"""
from __future__ import annotations

import base64
import io
import math
import posixpath
import re

from .. import model, xmlsafe
from . import (ImportFailed, Warnings, doc_name, guarded, make_document,
               require_bytes, select_page)

ENGINE = "visio-reader"
PX = 96.0
MAX_NODES = 20000
MAX_DEPTH = 40
ROW_TYPES = {"MoveTo", "LineTo", "ArcTo", "EllipticalArcTo", "Ellipse", "NURBSTo", "PolylineTo",
             "SplineStart", "SplineKnot", "InfiniteLine", "RelMoveTo", "RelLineTo", "RelCubBezTo",
             "RelQuadBezTo", "CubBezTo", "QuadBezTo", "RelEllipticalArcTo"}
SEC_ALIASES = {"Char": "Character", "Para": "Paragraph", "Prop": "Property"}
NON_CELL_TAGS = {"Shapes", "Text", "ForeignData", "Geom", "Char", "Para", "Prop", "User", "Connection",
                 "Layer", "LayerMem", "Section", "Cell", "Row", "Tabs", "Hyperlink", "Scratch",
                 "Control", "Field", "Action", "Event"}
PALETTE = ["#000000", "#FFFFFF", "#FF0000", "#00FF00", "#0000FF", "#FFFF00", "#FF00FF", "#00FFFF",
           "#800000", "#008000", "#000080", "#808000", "#800080", "#008080", "#C0C0C0", "#E6E6E6",
           "#CDCDCD", "#B3B3B3", "#9A9A9A", "#808080", "#666666", "#4D4D4D", "#333333", "#1A1A1A"]
# Visio arrowhead index (1..45) -> model arrow; best effort, the rest fall back to "arrow".
ARROWS = {1: "open", 2: "arrow", 3: "arrow", 4: "arrow", 5: "arrow", 6: "open", 7: "open", 8: "arrow",
          9: "arrow", 10: "arrow", 11: "arrow", 12: "open", 13: "arrow", 14: "arrow", 15: "arrow",
          16: "circle", 17: "circle_open", 18: "diamond", 19: "diamond_open", 20: "diamond",
          21: "diamond_open", 22: "arrow", 23: "arrow", 24: "arrow", 25: "arrow", 26: "bar",
          27: "crowfoot", 28: "crowfoot", 29: "bar", 30: "crowfoot", 31: "crowfoot", 32: "bar",
          33: "bar"}
IDENTITY = (1.0, 0.0, 0.0, 1.0, 0.0, 0.0)


def _fnum(s, default=0.0) -> float:
    try:
        f = float(str(s).strip())
    except (TypeError, ValueError):
        return default
    return f if math.isfinite(f) else default


def _strip_ns(root) -> None:
    for e in root.iter():
        if isinstance(e.tag, str) and "}" in e.tag:
            e.tag = e.tag.rsplit("}", 1)[1]


def _rid(el) -> str:
    for k, v in el.attrib.items():
        if k.endswith("}id") or k in ("r:id", "id"):
            return v
    return ""


# ------------------------------------------------------------------- loading

class Sec:
    __slots__ = ("name", "ix", "cells", "rows")

    def __init__(self, name, ix=None):
        self.name, self.ix, self.cells, self.rows = name, ix, {}, []


class Row:
    __slots__ = ("t", "name", "ix", "cells")

    def __init__(self, t, name, ix):
        self.t, self.name, self.ix, self.cells = t, name, ix, {}


class VShape:
    __slots__ = ("id", "type", "name", "nameu", "master", "mshape", "attrs", "deleted", "cells",
                 "secs", "text", "children", "foreign")

    def __init__(self):
        self.cells, self.secs, self.children, self.attrs = {}, [], [], {}
        self.text = None
        self.foreign = None


def _leaf_cells(el, into: dict) -> None:
    for c in el:
        if len(c) == 0:
            into[c.tag] = c.get("V") if c.get("V") is not None else (c.text or "").strip()


def _text_of(el) -> str:
    parts = [el.text or ""]
    for ch in el:
        if ch.tag == "fld":
            parts.append(ch.text or "")
        parts.append(ch.tail or "")
    s = "".join(parts).replace("\r\n", "\n").replace("\r", "\n").replace(" ", "\n").replace(" ", "\n")
    return s.strip("\n").strip()


def _parse_shape(el, doc: "Doc", depth: int = 0) -> VShape:
    if depth > MAX_DEPTH:
        raise ImportFailed("Visio shapes are nested more than %d levels deep." % MAX_DEPTH)
    doc.count += 1
    if doc.count > MAX_NODES * 4:
        raise ImportFailed("The Visio drawing has too many shapes.")
    v = VShape()
    v.id = el.get("ID") or ""
    v.type = el.get("Type") or "Shape"
    v.name, v.nameu = el.get("Name") or "", el.get("NameU") or ""
    v.master, v.mshape = el.get("Master"), el.get("MasterShape")
    v.attrs = {k: el.get(k) for k in ("LineStyle", "FillStyle", "TextStyle") if el.get(k) is not None}
    v.deleted = el.get("Del") == "1"
    merged: dict = {}

    def merged_sec(name):
        s = merged.get(name)
        if s is None:
            s = merged[name] = Sec(name)
            v.secs.append(s)
        return s

    for ch in el:
        t = ch.tag
        if t == "Cell":
            n = ch.get("N")
            if n:
                v.cells[n] = ch.get("V") or ""
                if "THEME" in (ch.get("F") or ""):
                    doc.warn.once("theme", "Theme-based colours and effects were resolved to flat colours.")
        elif t == "Section":
            s = Sec(SEC_ALIASES.get(ch.get("N") or "", ch.get("N") or ""), ch.get("IX"))
            for c in ch:
                if c.tag == "Cell" and c.get("N"):
                    s.cells[c.get("N")] = c.get("V") or ""
                elif c.tag == "Row":
                    r = Row(c.get("T"), c.get("N"), c.get("IX"))
                    for cc in c:
                        if cc.tag == "Cell" and cc.get("N"):
                            r.cells[cc.get("N")] = cc.get("V") or ""
                    s.rows.append(r)
                    if len(s.rows) > 5000:
                        raise ImportFailed("A Visio section has too many rows.")
            v.secs.append(s)
        elif t == "Text":
            v.text = _text_of(ch)
        elif t == "Shapes":
            for c in ch:
                if c.tag == "Shape":
                    v.children.append(_parse_shape(c, doc, depth + 1))
        elif t == "ForeignData":
            v.foreign = {"type": ch.get("ForeignType") or "", "rid": _rid(ch), "data": (ch.text or "").strip()}
        elif t == "Geom":
            s = Sec("Geometry", ch.get("IX"))
            for c in ch:
                if c.tag in ROW_TYPES:
                    r = Row(c.tag, None, c.get("IX"))
                    _leaf_cells(c, r.cells)
                    s.rows.append(r)
                elif len(c) == 0:
                    s.cells[c.tag] = (c.text or "").strip()
            v.secs.append(s)
        elif t in ("Char", "Para", "Prop", "User", "Connection", "Layer"):
            name = {"Char": "Character", "Para": "Paragraph", "Prop": "Property"}.get(t, t)
            r = Row(None, ch.get("NameU") or ch.get("N"), ch.get("IX"))
            _leaf_cells(ch, r.cells)
            merged_sec(name).rows.append(r)
        elif t == "LayerMem":
            lm = next((c for c in ch if c.tag == "LayerMember"), None)
            if lm is not None:
                v.cells["LayerMember"] = (lm.text or "").strip()
        elif t not in NON_CELL_TAGS and len(ch) and all(len(c) == 0 for c in ch):
            _leaf_cells(ch, v.cells)
    return v


class Doc:
    """Everything loaded from the file apart from page contents."""

    def __init__(self):
        self.count = 0
        self.warn = Warnings()
        self.styles: dict = {}
        self.masters: dict = {}
        self.pages: list = []
        self.zf = None
        self.master_cache: dict = {}

    def master(self, mid):
        if mid is None or mid not in self.masters:
            return None
        if mid in self.master_cache:
            return self.master_cache[mid]
        m = self.masters[mid]
        shapes = m["shapes"]() if callable(m["shapes"]) else m["shapes"]
        by_id: dict = {}

        def idx(v):
            by_id.setdefault(v.id, v)
            for c in v.children:
                idx(c)
        for s in shapes:
            idx(s)
        out = {"name": m["name"], "nameu": m["nameu"], "root": shapes[0] if shapes else None, "by_id": by_id}
        self.master_cache[mid] = out
        return out


def _rels(zf, part: str) -> dict:
    """Relationship id -> normalised ZIP member name for *part*."""
    d, f = posixpath.split(part)
    rel = posixpath.join(d, "_rels", f + ".rels")
    if rel not in zf.namelist():
        return {}
    root = xmlsafe.parse_xml(xmlsafe.read_member(zf, rel, 8 * 1024 * 1024))
    _strip_ns(root)
    out = {}
    for r in root:
        tgt = r.get("Target") or ""
        if r.get("TargetMode") == "External" or not tgt:
            continue
        full = tgt.lstrip("/") if tgt.startswith("/") else posixpath.normpath(posixpath.join(d, tgt))
        if full.startswith("..") or full.startswith("/"):
            continue
        out[r.get("Id")] = full
    return out


def _load_styles(root, doc: Doc) -> None:
    for ss in root.iter("StyleSheet"):
        v = _parse_shape(ss, doc)
        doc.styles[v.id] = v


def _page_def(p_el, doc: Doc, load) -> dict:
    sheet = next((c for c in p_el if c.tag == "PageSheet"), None)
    return {"id": p_el.get("ID") or "", "name": p_el.get("Name") or p_el.get("NameU") or "",
            "background": p_el.get("Background") == "1",
            "sheet": _parse_shape(sheet, doc) if sheet is not None else VShape(), "load": load}


def _shapes_of(parent, doc: Doc) -> list:
    sh = next((c for c in parent if c.tag == "Shapes"), None)
    return [_parse_shape(c, doc) for c in (sh if sh is not None else []) if c.tag == "Shape"]


def _load_vsdx(data: bytes) -> Doc:
    doc = Doc()
    zf = doc.zf = xmlsafe.open_zip(io.BytesIO(data))
    names = set(zf.namelist())
    if "visio/document.xml" not in names:
        raise ImportFailed("This ZIP is not a Visio drawing (visio/document.xml is missing).")
    droot = xmlsafe.parse_xml(xmlsafe.read_member(zf, "visio/document.xml", 16 * 1024 * 1024))
    _strip_ns(droot)
    _load_styles(droot, doc)
    drels = _rels(zf, "visio/document.xml")

    mpart = next((p for p in drels.values() if p.endswith("masters/masters.xml")), None) \
        or ("visio/masters/masters.xml" if "visio/masters/masters.xml" in names else None)
    if mpart and mpart in names:
        mroot = xmlsafe.parse_xml(xmlsafe.read_member(zf, mpart, 16 * 1024 * 1024))
        _strip_ns(mroot)
        mrels = _rels(zf, mpart)
        for m in mroot.iter("Master"):
            rel = next((c for c in m if c.tag == "Rel"), None)
            target = mrels.get(_rid(rel)) if rel is not None else None

            def loader(target=target):
                if not target or target not in names:
                    return []
                r = xmlsafe.parse_xml(xmlsafe.read_member(zf, target))
                _strip_ns(r)
                return _shapes_of(r, doc)
            doc.masters[m.get("ID")] = {"name": m.get("Name") or "", "nameu": m.get("NameU") or "",
                                        "shapes": loader}

    ppart = next((p for p in drels.values() if p.endswith("pages/pages.xml")), None) \
        or ("visio/pages/pages.xml" if "visio/pages/pages.xml" in names else None)
    if not ppart or ppart not in names:
        raise ImportFailed("The Visio file has no pages (visio/pages/pages.xml is missing).")
    proot = xmlsafe.parse_xml(xmlsafe.read_member(zf, ppart, 16 * 1024 * 1024))
    _strip_ns(proot)
    prels = _rels(zf, ppart)
    for p in proot.iter("Page"):
        rel = next((c for c in p if c.tag == "Rel"), None)
        target = prels.get(_rid(rel)) if rel is not None else None

        def load(target=target):
            if not target or target not in names:
                return [], [], {}
            r = xmlsafe.parse_xml(xmlsafe.read_member(zf, target))
            _strip_ns(r)
            cn = next((c for c in r if c.tag == "Connects"), None)
            return (_shapes_of(r, doc), [c.attrib for c in (cn if cn is not None else []) if c.tag == "Connect"],
                    _rels(zf, target))
        doc.pages.append(_page_def(p, doc, load))
    if not doc.pages:
        raise ImportFailed("The Visio file has no pages.")
    return doc


def _load_vdx(data: bytes) -> Doc:
    doc = Doc()
    root = xmlsafe.parse_xml(data)
    _strip_ns(root)
    if root.tag != "VisioDocument":
        raise ImportFailed("Not a Visio XML drawing (root element %r)." % str(root.tag)[:40])
    _load_styles(root, doc)
    for m in root.iter("Master"):
        if m.get("ID") is not None:
            doc.masters[m.get("ID")] = {"name": m.get("Name") or "", "nameu": m.get("NameU") or "",
                                        "shapes": _shapes_of(m, doc)}
    pages = next((c for c in root if c.tag == "Pages"), None)
    for p in (pages if pages is not None else []):
        if p.tag != "Page":
            continue

        def load(p=p):
            cn = next((c for c in p if c.tag == "Connects"), None)
            return (_shapes_of(p, doc), [c.attrib for c in (cn if cn is not None else []) if c.tag == "Connect"], {})
        doc.pages.append(_page_def(p, doc, load))
    if not doc.pages:
        raise ImportFailed("The Visio file has no pages.")
    return doc


def _load(data: bytes) -> tuple:
    if data[:2] == b"PK":
        return "vsdx", _load_vsdx(data)
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        raise ImportFailed("Legacy binary Visio (.vsd) cannot be read; save it as .vsdx in Visio and import that.")
    return "vdx", _load_vdx(data)


def _usable_pages(doc: Doc) -> list:
    out = [p for p in doc.pages if not p["background"]]
    for i, p in enumerate(out):
        if not model.ID_RE.match(p["id"] or ""):
            p["id"] = "page-%d" % (i + 1)
        p["name"] = p["name"] or "Page-%d" % (i + 1)
    return out


@guarded
def list_pages(data: bytes) -> list:
    _fmt, doc = _load(require_bytes(data))
    return [{"id": p["id"], "name": p["name"]} for p in _usable_pages(doc)]


# ---------------------------------------------------------------- inheritance

class Node:
    """A shape instance: its own cells, its master shape and its stylesheet chain."""
    __slots__ = ("v", "base", "master", "eid", "doc")

    def __init__(self, v, base, master, eid, doc):
        self.v, self.base, self.master, self.eid, self.doc = v, base, master, eid, doc

    @property
    def own_master(self):
        """The master this shape is an instance of (not an ancestor's)."""
        m = self.master if self.v.master is not None else None
        return m if (m and (m.get("nameu") or m.get("name"))) else None

    def style_id(self, cat):
        for sh in (self.v, self.base):
            if sh is not None and sh.attrs.get(cat) is not None:
                return sh.attrs[cat]
        return None

    def cell(self, name, default=None):
        v = self.v.cells.get(name)
        if v is None and self.base is not None:
            v = self.base.cells.get(name)
        if v is None:
            cat = ("LineStyle" if (name.startswith("Line") or name in ("Rounding", "BeginArrow", "EndArrow"))
                   else "FillStyle" if name.startswith(("Fill", "Shdw")) else "TextStyle")
            sid, hops = self.style_id(cat), 0
            while sid is not None and hops < 12 and v is None:
                st = self.doc.styles.get(sid)
                if st is None:
                    break
                v = st.cells.get(name)
                sid = st.attrs.get(cat)
                hops += 1
        return default if v is None else v

    def num(self, name, default=0.0):
        return _fnum(self.cell(name), default)

    def has_cell(self, name):
        return name in self.v.cells or (self.base is not None and name in self.base.cells)

    def sections(self, name) -> list:
        mine = [s for s in self.v.secs if s.name == name]
        if mine or self.base is None:
            return mine
        return [s for s in self.base.secs if s.name == name]

    def first_row_cell(self, sec, cell):
        for s in self.sections(sec):
            for r in s.rows:
                if cell in r.cells:
                    return r.cells[cell]
        return None

    def text(self):
        if self.v.text is not None:
            return self.v.text
        return self.base.text if (self.base is not None and self.base.text) else ""

    def master_name(self):
        m = self.own_master
        return (m.get("nameu") or m["name"])[:120] if m else ""


def _color(v):
    if v is None:
        return None
    v = str(v).strip()
    if re.fullmatch(r"#[0-9A-Fa-f]{6}", v):
        return v.upper()
    if re.fullmatch(r"\d{1,3}", v) and int(v) < len(PALETTE):
        return PALETTE[int(v)]
    return None


# ------------------------------------------------------------------ geometry

def _arc_seg(cx, cy, x, y, a, fx, fy):
    c = math.hypot(x - cx, y - cy)
    if c < 1e-9 or abs(a) < 1e-6 * max(c, 1e-9):
        return ("L", x, y)
    r = (c * c / 4.0 + a * a) / (2.0 * abs(a))
    sweep = 1 if ((a > 0) != (fx != fy)) else 0
    return ("A", r, r, 1 if abs(a) > r else 0, sweep, x, y)


def _geometry(node: Node, W: float, H: float, fx: bool, fy: bool) -> list:
    """``[{"nofill","noline","segs":[...],"pts":[(x,y)...]}]`` in local inches (y up)."""
    local = [s for s in node.v.secs if s.name == "Geometry"]
    secs = local or ([s for s in node.base.secs if s.name == "Geometry"] if node.base is not None else [])
    sx = sy = 1.0
    if not local and node.base is not None:
        bw, bh = _fnum(node.base.cells.get("Width")), _fnum(node.base.cells.get("Height"))
        sx = W / bw if bw > 1e-9 else 1.0
        sy = H / bh if bh > 1e-9 else 1.0
    out = []

    def px(x):
        return (W - x) if fx else x

    def py(y):
        return (H - y) if fy else y

    for s in secs:
        if s.cells.get("NoShow") == "1":
            continue
        segs, pts, cur = [], [], None
        for r in s.rows:
            c, t = r.cells, r.t or ""
            rel = t.startswith("Rel")
            kx, ky = (W, H) if rel else (sx, sy)
            x, y = px(_fnum(c.get("X")) * kx), py(_fnum(c.get("Y")) * ky)
            if t in ("MoveTo", "RelMoveTo"):
                segs.append(("M", x, y)); pts.append((x, y)); cur = (x, y)
            elif t in ("LineTo", "RelLineTo", "NURBSTo", "PolylineTo", "SplineStart", "SplineKnot"):
                segs.append(("L" if cur is not None else "M", x, y)); pts.append((x, y)); cur = (x, y)
            elif t == "ArcTo" and cur is not None:
                bow = _fnum(c.get("A")) * (sx if abs(sx - sy) < 1e-6 else 1.0)
                segs.append(_arc_seg(cur[0], cur[1], x, y, bow, fx, fy)); pts.append((x, y)); cur = (x, y)
            elif t in ("EllipticalArcTo", "RelEllipticalArcTo") and cur is not None:
                ax, ay = px(_fnum(c.get("A")) * kx), py(_fnum(c.get("B")) * ky)
                segs.append(("Q", 2 * ax - 0.5 * (cur[0] + x), 2 * ay - 0.5 * (cur[1] + y), x, y))
                pts.append((x, y)); cur = (x, y)
            elif t in ("RelCubBezTo", "CubBezTo") and cur is not None:
                segs.append(("C", px(_fnum(c.get("A")) * kx), py(_fnum(c.get("B")) * ky),
                             px(_fnum(c.get("C")) * kx), py(_fnum(c.get("D")) * ky), x, y))
                pts.append((x, y)); cur = (x, y)
            elif t in ("RelQuadBezTo", "QuadBezTo") and cur is not None:
                segs.append(("Q", px(_fnum(c.get("A")) * kx), py(_fnum(c.get("B")) * ky), x, y))
                pts.append((x, y)); cur = (x, y)
            elif t == "Ellipse":
                ax, ay = px(_fnum(c.get("A")) * sx), py(_fnum(c.get("B")) * sy)
                bx, by = px(_fnum(c.get("C")) * sx), py(_fnum(c.get("D")) * sy)
                segs.append(("E", x, y, math.hypot(ax - x, ay - y), math.hypot(bx - x, by - y)))
                pts.append((x, y))
        if segs:
            out.append({"nofill": s.cells.get("NoFill") == "1", "noline": s.cells.get("NoLine") == "1",
                        "segs": segs, "pts": pts})
    return out


def _matches_corners(sp, want, W, H) -> bool:
    segs = sp["segs"]
    if not segs or segs[0][0] != "M" or any(s[0] != "L" for s in segs[1:]) or len(segs) not in (4, 5):
        return False
    pts = [(s[1], s[2]) for s in segs]
    tol = 0.02 + 0.01 * max(W, H)
    if len(pts) == 5 and math.hypot(pts[4][0] - pts[0][0], pts[4][1] - pts[0][1]) > tol:
        return False
    return all(any(abs(p[0] - w[0]) <= tol and abs(p[1] - w[1]) <= tol for p in pts[:4]) for w in want)


def _f2(v: float) -> str:
    s = ("%.2f" % v).rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def _path_d(subs, H: float) -> str:
    def P(x, y):
        return "%s %s" % (_f2(x * PX), _f2((H - y) * PX))
    d = []
    for sp in subs:
        for seg in sp["segs"]:
            k = seg[0]
            if k in ("M", "L"):
                d.append("%s%s" % (k, P(seg[1], seg[2])))
            elif k == "Q":
                d.append("Q%s %s" % (P(seg[1], seg[2]), P(seg[3], seg[4])))
            elif k == "C":
                d.append("C%s %s %s" % (P(seg[1], seg[2]), P(seg[3], seg[4]), P(seg[5], seg[6])))
            elif k == "A":
                d.append("A%s %s 0 %d %d %s" % (_f2(seg[1] * PX), _f2(seg[2] * PX), seg[3], seg[4], P(seg[5], seg[6])))
            elif k == "E":
                cx, cy, rx, ry = seg[1], seg[2], seg[3], seg[4]
                d.append("M%s A%s %s 0 1 0 %s A%s %s 0 1 0 %s Z" % (
                    P(cx - rx, cy), _f2(rx * PX), _f2(ry * PX), P(cx + rx, cy),
                    _f2(rx * PX), _f2(ry * PX), P(cx - rx, cy)))
        pts = sp["pts"]
        if (len(pts) >= 3 and math.hypot(pts[0][0] - pts[-1][0], pts[0][1] - pts[-1][1]) < 1e-3
                and sp["segs"][-1][0] != "E"):
            d.append("Z")
    return " ".join(d)


# ----------------------------------------------------------------- transform

def _transform(node: Node, W, H, fx, fy) -> tuple:
    """Local frame -> parent frame (y up): flip, rotate about the pin, translate."""
    lx, ly = node.num("LocPinX", W / 2.0), node.num("LocPinY", H / 2.0)
    th = node.num("Angle")
    ca, sa = math.cos(th), math.sin(th)
    a, b, c, d = ca, sa, -sa, ca
    e = node.num("PinX") - (lx * ca - ly * sa)
    f = node.num("PinY") - (lx * sa + ly * ca)
    if fx or fy:
        sx, sy = (-1.0 if fx else 1.0), (-1.0 if fy else 1.0)
        tx, ty = (W if fx else 0.0), (H if fy else 0.0)
        a, b, c, d, e, f = a * sx, b * sx, c * sy, d * sy, a * tx + c * ty + e, b * tx + d * ty + f
    return (a, b, c, d, e, f)


def _compose(p, m) -> tuple:
    return (p[0] * m[0] + p[2] * m[1], p[1] * m[0] + p[3] * m[1],
            p[0] * m[2] + p[2] * m[3], p[1] * m[2] + p[3] * m[3],
            p[0] * m[4] + p[2] * m[5] + p[4], p[1] * m[4] + p[3] * m[5] + p[5])


def _apply(t, x, y) -> tuple:
    return t[0] * x + t[2] * y + t[4], t[1] * x + t[3] * y + t[5]


# --------------------------------------------------------------------- style

#: legacy (Visio 2003) gradient FillPattern -> (type, angle)
LEGACY_GRADIENTS = {25: ("linear", 0), 26: ("linear", 0), 27: ("linear", 180), 28: ("linear", 90),
                    29: ("linear", 90), 30: ("linear", 270), 31: ("linear", 45), 32: ("linear", 135),
                    33: ("linear", 315), 34: ("linear", 225)}
#: LinePattern -> dash pattern (1 solid; 2 dash; 3 dot; 4 dash-dot; others: dashed)
LINE_PATTERNS = {1: "solid", 2: "dashed", 3: "dotted", 4: "dash-dot", 5: "dash-dot", 9: "dotted", 10: "dotted"}


def dash_of(lp: int) -> str:
    return "solid" if lp <= 1 else LINE_PATTERNS.get(lp, "dashed")


def _gradient(node: Node, w: Warnings, pattern: int):
    """``(first colour, gradient dict)`` of a gradient fill, else None."""
    if node.cell("FillGradientEnabled", "0") in ("1", "TRUE", "true"):
        stops = []
        for sec in node.sections("FillGradient"):
            for r in sec.rows:
                col = _color(r.cells.get("GradientStopColor"))
                if col:
                    stops.append((_fnum(r.cells.get("GradientStopPosition"), len(stops)), col))
        if len(stops) < 2:
            return None
        stops.sort(key=lambda t: t[0])
        if len(stops) > 2:
            w.once("gradient_stops", "Gradients with more than two stops keep their first and last colour.")
        direction = int(node.num("FillGradientDir", 0))
        if direction == 0:
            angle = int(round(math.degrees(node.num("FillGradientAngle", math.pi / 2)))) % 360
            return stops[0][1], {"type": "linear", "color": stops[-1][1], "angle": angle}
        if direction > 7:
            w.once("gradient_shape", "Rectangular and path gradients were drawn as radial gradients.")
        return stops[0][1], {"type": "radial", "color": stops[-1][1], "angle": 90}
    if 25 <= pattern <= 40:
        first, last = _color(node.cell("FillForegnd")) or "#FFFFFF", _color(node.cell("FillBkgnd")) or "#FFFFFF"
        typ, angle = LEGACY_GRADIENTS.get(pattern, ("radial", 90))
        return first, {"type": typ, "color": last, "angle": angle}
    return None


def _fill_line(node: Node, w: Warnings, nofill: bool, noline: bool) -> dict:
    pattern = int(node.num("FillPattern", 1))
    fill = "none" if (pattern == 0 or nofill) else (_color(node.cell("FillForegnd")) or "#FFFFFF")
    lp = int(node.num("LinePattern", 1))
    stroke = "none" if (lp == 0 or noline) else (_color(node.cell("LineColor")) or "#000000")
    lw = node.num("LineWeight", 0.01)
    out = {"fill": fill, "stroke": stroke, "stroke_width": min(50.0, max(1.0, lw * PX)),
           "dashed": lp > 1, "dash_pattern": dash_of(lp) if stroke != "none" else "solid",
           "rounded": node.num("Rounding", 0.0) > 0}
    if fill != "none":
        g = _gradient(node, w, pattern)
        if g is not None:
            out["fill"], out["gradient"] = g
    if node.num("ShdwPattern", 0) > 0:
        out["shadow"] = True
        out["shadow_color"] = _color(node.cell("ShdwForegnd")) or "#000000"
    trans = node.num("FillForegndTrans", 0.0)
    if 0 < trans <= 1:
        out["opacity"] = 1.0 - trans
    return out


def _font(node: Node) -> dict:
    out = {}
    col = _color(node.first_row_cell("Character", "Color"))
    if col:
        out["font_color"] = col
    size = _fnum(node.first_row_cell("Character", "Size"))
    if size > 0:
        out["font_size"] = size * PX
    style = int(_fnum(node.first_row_cell("Character", "Style"), 0))
    out["bold"], out["italic"] = bool(style & 1), bool(style & 2)
    out["align"] = {0: "left", 2: "right"}.get(int(_fnum(node.first_row_cell("Paragraph", "HorzAlign"), 1)), "center")
    out["valign"] = {0: "top", 2: "bottom"}.get(int(node.num("VerticalAlign", 1)), "middle")
    return out


def _properties(node: Node) -> dict:
    rows: dict = {}
    for sh in (node.base, node.v):
        if sh is None:
            continue
        for s in sh.secs:
            if s.name == "Property":
                for i, r in enumerate(s.rows):
                    rows[r.name or r.ix or str(i)] = r.cells
    out = {}
    for key, c in rows.items():
        label = (c.get("Label") or "").strip() or str(key)
        val = (c.get("Value") or "").strip()
        if val:
            out[label[:64]] = val[:model.MAX_PROP_VALUE]
    return out


def _user_meta(node: Node) -> dict:
    out = {}
    for s in node.v.secs:
        if s.name == "User":
            for r in s.rows:
                val = (r.cells.get("Value") or "").strip()
                if r.name and val and len(val) <= 100 and len(out) < 8:
                    out["visio_user_" + re.sub(r"[^A-Za-z0-9_]", "_", r.name)[:40]] = val
    return out


def _native(node: Node) -> dict:
    parts = []
    if node.master_name():
        parts.append("master=" + node.master_name())
    for k in ("FillForegnd", "FillPattern", "LineColor", "LinePattern", "LineWeight", "Rounding",
              "FillGradientEnabled", "ShdwPattern"):
        if node.has_cell(k):
            parts.append("%s=%s" % (k, node.cell(k)))
    return {"format": "visio", "style": ";".join(parts)[:1000]}


# ---------------------------------------------------------------------- page

class _Page:
    def __init__(self, doc: Doc, pd: dict):
        self.doc, self.w, self.pd = doc, doc.warn, pd
        self.shapes, self.connects, self.rels = pd["load"]()
        sheet = Node(pd["sheet"], None, None, "", doc)
        self.pw, self.ph = sheet.num("PageWidth", 8.5), sheet.num("PageHeight", 11.0)
        self.layers = []
        for s in pd["sheet"].secs:
            if s.name == "Layer":
                for i, r in enumerate(s.rows):
                    ix = r.ix if r.ix is not None else str(i)
                    self.layers.append({"id": "L%s" % ix,
                                        "name": (r.cells.get("Name") or "").strip() or "Layer %s" % ix,
                                        "visible": r.cells.get("Visible", "1") != "0",
                                        "locked": r.cells.get("Lock", "0") == "1"})
        self.layer_ids = {l["id"] for l in self.layers}
        self.elements, self.one_d = [], []
        self.by_shape: dict = {}     # page shape id -> element dict (glue targets)
        self.n = 0

    def node(self, v: VShape, ctx_master, eid: str | None) -> Node:
        master = self.doc.master(v.master) if v.master is not None else ctx_master
        base = None
        if master is not None:
            if v.mshape is not None:
                base = master["by_id"].get(v.mshape)
            elif v.master is not None:
                base = master["root"]
        return Node(v, base, master, eid or ("s" + v.id), self.doc)

    def layer_of(self, node: Node, inherited: str) -> str:
        for part in (node.v.cells.get("LayerMember") or "").split(";"):
            if "L%s" % part.strip() in self.layer_ids:
                return "L%s" % part.strip()
        return inherited

    def walk(self, v, tf, parent_eid, layer, ctx_master, depth, eid=None):
        if v.deleted or v.type == "Guide":
            return
        self.n += 1
        if self.n > MAX_NODES:
            raise ImportFailed("The Visio page has more than %d shapes." % MAX_NODES)
        node = self.node(v, ctx_master, eid)
        lay = self.layer_of(node, layer)
        if node.has_cell("BeginX") or node.has_cell("EndX") or node.cell("ObjType") == "2":
            self.one_d.append((node, tf, lay))
        else:
            self.element(node, tf, parent_eid, lay, depth, virtual=eid is not None)

    def element(self, node: Node, tf, parent_eid, layer, depth, virtual):
        v = node.v
        W, H = node.num("Width"), node.num("Height")
        fx, fy = node.cell("FlipX") == "1", node.cell("FlipY") == "1"
        is_group = v.type == "Group"
        is_foreign = v.type == "Foreign" or (node.base is not None and node.base.type == "Foreign")
        t = _compose(tf, _transform(node, W, H, fx, fy))
        subs = _geometry(node, W, H, fx, fy)
        text = node.text()
        kids = list(v.children)
        kids_virtual = False
        if is_group and not kids and node.base is not None and node.base.children:
            kids, kids_virtual = list(node.base.children), True

        nofill = bool(subs) and all(s["nofill"] for s in subs)
        noline = bool(subs) and all(s["noline"] for s in subs)
        style = _fill_line(node, self.w, nofill, noline)
        style.update(_font(node))
        meta = {}
        if node.master_name():
            meta["visio_master"] = node.master_name()
        if v.nameu or v.name:
            meta["visio_name"] = (v.nameu or v.name)[:120]
        meta.update(_user_meta(node))

        kind, shape, path, image = "shape", "rect", "", ""
        if is_foreign:
            image = self.foreign_image(node)
            if image:
                kind = "image"
            else:
                meta["visio_foreign"] = ((v.foreign or {}).get("type") or "picture")[:40]
        elif not subs:
            if is_group:
                kind = "container"
                style["fill"] = style["stroke"] = "none"
            elif text:
                kind = "text"
                style["fill"] = style["stroke"] = "none"
            else:
                return    # no geometry, no text: nothing visible
        else:
            if is_group:
                kind = "container"
            if style["fill"] == "none" and style["stroke"] == "none" and text and not is_group:
                kind = "text"
            if kind != "text":
                sp = subs[0] if len(subs) == 1 else None
                if sp and len(sp["segs"]) == 1 and sp["segs"][0][0] == "E" \
                        and abs(sp["segs"][0][3] - W / 2) < 0.03 + 0.01 * W \
                        and abs(sp["segs"][0][4] - H / 2) < 0.03 + 0.01 * H:
                    shape = "ellipse"
                elif sp and _matches_corners(sp, [(0, 0), (W, 0), (W, H), (0, H)], W, H):
                    shape = "round" if style["rounded"] else "rect"
                elif sp and _matches_corners(sp, [(W / 2, 0), (W, H / 2), (W / 2, H), (0, H / 2)], W, H):
                    shape = "diamond"
                else:
                    shape, path = "path", _path_d(subs, H)
        if shape == "path" and not path:
            shape = "rect"

        cx, cy = _apply(t, W / 2.0, H / 2.0)
        rot = (-math.degrees(math.atan2(t[1], t[0]))) % 360.0
        if rot > 180.0:
            rot -= 360.0
        el = {"id": node.eid, "kind": kind, "shape": shape, "symbol": "",
              "name": (text.split("\n")[0] if text else "")[:80], "description": "", "text": text,
              "x": cx * PX - W * PX / 2.0, "y": (self.ph - cy) * PX - H * PX / 2.0,
              "w": W * PX, "h": H * PX, "rotation": rot, "layer": layer, "parent": parent_eid,
              "style": style, "properties": _properties(node), "metadata": meta,
              "source_ref": node.eid[1:] if virtual else v.id, "confidence": 1.0, "native": _native(node)}
        if path:
            el["path"] = path
        if image:
            el["image"] = image
        ports = []
        for s in node.sections("Connection"):
            for i, r in enumerate(s.rows):
                if W > 0 and H > 0 and len(ports) < 60:
                    ports.append({"id": "c%s" % (r.ix if r.ix is not None else i),
                                  "x": min(1.0, max(0.0, _fnum(r.cells.get("X")) / W)),
                                  "y": min(1.0, max(0.0, 1.0 - _fnum(r.cells.get("Y")) / H))})
        el["ports"] = ports
        if node.has_cell("TxtPinX") or node.has_cell("TxtWidth"):
            self.w.once("txtblock", "Custom text-block positions were ignored (text is centred in the shape).")
        self.elements.append(el)
        if not virtual:
            self.by_shape[v.id] = el
        for c in kids:
            self.walk(c, t, node.eid, layer, node.master, depth + 1,
                      ("%s_%s" % (node.eid, c.id)) if kids_virtual else None)

    def foreign_image(self, node: Node) -> str:
        f = node.v.foreign or (node.base.foreign if node.base is not None else None)
        if not f:
            return ""
        raw = b""
        if f["data"]:
            try:
                raw = base64.b64decode(f["data"], validate=False)
            except ValueError:
                raw = b""
        elif f["rid"] and self.rels.get(f["rid"]) and self.doc.zf is not None:
            raw = xmlsafe.read_member(self.doc.zf, self.rels[f["rid"]], 8 * 1024 * 1024)
        mime = ("png" if raw.startswith(b"\x89PNG") else "jpeg" if raw.startswith(b"\xff\xd8") else
                "gif" if raw.startswith(b"GIF8") else "")
        if not mime:
            self.w.once("foreign", "Pictures that are not PNG/JPEG/GIF (for example EMF/WMF) were not imported.")
            return ""
        uri = "data:image/%s;base64,%s" % (mime, base64.b64encode(raw).decode())
        if len(uri) > model.MAX_IMAGE:
            self.w.once("foreign_big", "Pictures larger than 2 MiB were not imported.")
            return ""
        return uri

    def connectors(self) -> list:
        glue: dict = {}
        for c in self.connects:
            frm, to, cell = c.get("FromSheet"), c.get("ToSheet"), c.get("FromCell") or ""
            side = "begin" if cell.startswith("Begin") else "end" if cell.startswith("End") else None
            if frm and to and side:
                glue.setdefault(frm, {})[side] = (to, c.get("ToCell") or "")
        out = []

        def P(p):
            return [p[0] * PX, (self.ph - p[1]) * PX]
        for node, tf, layer in self.one_d:
            v = node.v
            W, H = node.num("Width"), node.num("Height")
            fx, fy = node.cell("FlipX") == "1", node.cell("FlipY") == "1"
            m = _compose(tf, _transform(node, W, H, fx, fy))
            verts = [_apply(m, x, y) for s in _geometry(node, W, H, fx, fy) for (x, y) in s["pts"]]
            if node.has_cell("BeginX") and node.has_cell("EndX"):
                b, e = _apply(tf, node.num("BeginX"), node.num("BeginY")), _apply(tf, node.num("EndX"), node.num("EndY"))
            elif len(verts) >= 2:
                b, e = verts[0], verts[-1]
            else:
                b, e = _apply(m, 0.0, H / 2.0), _apply(m, W, H / 2.0)
            bp, ep = P(b), P(e)
            inner = []
            for q in (P(p) for p in verts[1:-1]):
                if (math.hypot(q[0] - bp[0], q[1] - bp[1]) > 0.5 and math.hypot(q[0] - ep[0], q[1] - ep[1]) > 0.5
                        and (not inner or math.hypot(q[0] - inner[-1][0], q[1] - inner[-1][1]) > 0.5)):
                    inner.append(q)
            g = glue.get(v.id, {})
            ends, ports = {}, {}
            for side in ("begin", "end"):
                to, tocell = g.get(side, (None, ""))
                tgt = self.by_shape.get(to) if to else None
                ends[side], ports[side] = (tgt["id"] if tgt else ""), ""
                mm = re.search(r"Connections\.[XY]?(?:Row_)?(\d+)", tocell)
                if tgt and mm and any(p["id"] == "c%d" % (int(mm.group(1)) - 1) for p in tgt["ports"]):
                    ports[side] = "c%d" % (int(mm.group(1)) - 1)
            ext, rs = int(node.num("ConLineRouteExt", 0)), int(node.num("ShapeRouteStyle", 0))
            aligned = abs(bp[0] - ep[0]) < 0.5 or abs(bp[1] - ep[1]) < 0.5
            chain = [bp] + inner + [ep]
            if ext == 3:
                routing = "curved"
            elif ext == 2:
                routing = "orthogonal"
            elif ext == 1 or rs in (2, 7):
                routing = "straight"
            elif rs in (1, 3, 4, 5, 6) or rs >= 8:
                routing = "orthogonal" if (inner or aligned) else "straight"
            else:
                routing = "orthogonal" if (inner and all(abs(a[0] - b2[0]) < 0.5 or abs(a[1] - b2[1]) < 0.5
                                                         for a, b2 in zip(chain, chain[1:]))) else "straight"
            ba, ea = int(node.num("BeginArrow", 0)), int(node.num("EndArrow", 0))
            if any(a and a not in ARROWS for a in (ba, ea)):
                self.w.once("arrow", "Some arrowheads were approximated.")
            text = node.text()
            c = {"id": node.eid, "source": ends["begin"], "target": ends["end"],
                 "source_port": ports["begin"], "target_port": ports["end"],
                 "points": inner, "routing": routing,
                 "start_arrow": ARROWS.get(ba, "arrow") if ba else "none",
                 "end_arrow": ARROWS.get(ea, "arrow") if ea else "none",
                 "label": text, "labels": [{"text": text, "pos": 0.5}] if text else [],
                 "style": {"stroke": _color(node.cell("LineColor")) or "#000000",
                           "stroke_width": min(50.0, max(1.0, node.num("LineWeight", 0.01) * PX)),
                           "dashed": int(node.num("LinePattern", 1)) > 1,
                           "dash_pattern": dash_of(int(node.num("LinePattern", 1))),
                           "shadow": node.num("ShdwPattern", 0) > 0,
                           "shadow_color": _color(node.cell("ShdwForegnd")) or "#000000",
                           "font_color": _color(node.first_row_cell("Character", "Color")) or "#000000"},
                 "layer": layer, "properties": _properties(node),
                 "metadata": {"visio_master": node.master_name()} if node.master_name() else {},
                 "source_ref": v.id, "confidence": 1.0, "native": _native(node)}
            if not ends["begin"]:
                c["start"] = bp
            if not ends["end"]:
                c["end"] = ep
            out.append(c)
        return out

    def build(self) -> dict:
        for v in self.shapes:
            self.walk(v, IDENTITY, "", "", None, 0)
        conns = self.connectors()
        children: dict = {}
        for e in self.elements:
            if e["parent"]:
                children.setdefault(e["parent"], []).append(e["id"])
        groups = [{"id": ("g" + e["id"])[:64], "name": e["name"], "members": children[e["id"]], "layer": e["layer"]}
                  for e in self.elements if e["kind"] == "container" and e["id"] in children]
        max_x = max((e["x"] + e["w"] for e in self.elements), default=0.0)
        max_y = max((e["y"] + e["h"] for e in self.elements), default=0.0)
        for c in conns:
            for p in c["points"] + [c.get("start") or [0, 0], c.get("end") or [0, 0]]:
                max_x, max_y = max(max_x, p[0]), max(max_y, p[1])
        return {"id": self.pd["id"], "name": self.pd["name"],
                "width": max(self.pw * PX, max_x + 40.0), "height": max(self.ph * PX, max_y + 40.0),
                "layers": self.layers, "groups": groups, "elements": self.elements, "connectors": conns}


@guarded
def read(data: bytes, *, filename: str = "", page: str | None = None) -> dict:
    data = require_bytes(data)
    _fmt, doc = _load(data)
    usable = _usable_pages(doc)
    if len(usable) != len(doc.pages):
        doc.warn.once("background", "Background pages were skipped.")
    if not usable:
        raise ImportFailed("The Visio file has no drawing pages (only background pages).")
    pages = [_Page(doc, pd).build() for pd in select_page(usable, page)]
    return make_document(fmt=_fmt, engine=ENGINE, data=data, filename=filename,
                         name=doc_name(filename, pages[0]["name"]), pages=pages,
                         warnings=doc.warn.items, page=page)
