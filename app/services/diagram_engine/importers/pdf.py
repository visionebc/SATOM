"""Vector PDF reader: pages of drawn boxes, lines and text -> ``satom.diagram/1``.

``pdfplumber`` (pdfminer.six) is imported lazily inside the functions, so the
rest of the engine runs without it. The PDF is never rendered to be read: its
own drawing operators are. A PDF is hostile input like any other: encrypted
files are refused with a clear message, every library error becomes
:class:`ImportFailed`, and a page is capped at ``MAX_OBJECTS`` graphic objects.

Per page (coordinates are pdfplumber's top-based points, scaled x96/72 to px):

* ``rects`` -> rect shapes; very thin filled rects are lines;
* ``curves`` (closed or filled paths) -> rect / round / ellipse / diamond /
  triangle / polygon / path shapes, by the same recogniser the SVG reader uses;
* ``lines`` and open ``curves`` -> connector candidates. Segments that touch end
  to end (same colour and width, not meeting on a shape) are merged, because
  Visio/draw.io PDFs split polylines. Ends snap to the nearest shape; a small
  filled triangle at an end is an arrowhead;
* ``chars`` -> words -> lines -> text blocks (lines close vertically, same
  column). A block inside a shape is that shape's text; one hugging a
  connector is its label; the rest are text elements.

Pages: ``page`` is a 1-based index (or the page id) or ``"all"``/``None``.
At most 50 pages are read. Scanned pages (no vector paths, almost no text,
one big image) raise :class:`ImportFailed` unless a ``raster_reader`` hook
``callable(png_bytes, filename) -> document`` is given: the page is then
rendered at 200 dpi with pypdfium2 and handed to it, and the result is scaled
back to the page's px space.

Approximations: clipping paths, soft masks, patterns/shadings (a pattern fill
keeps no colour), text on a path and rotated text boxes are not interpreted;
fonts are named, not measured.
"""
from __future__ import annotations

import io
import math
import re
import statistics

from .. import geometry as geo
from .. import model, xmlsafe  # noqa: F401  (xmlsafe re-exported for callers' except clauses)
from . import (ImportFailed, Warnings, doc_name, guarded, make_document,
               require_bytes)

ENGINE = "pdf-reader"
PT = 96.0 / 72.0
MAX_PDF_PAGES = 50
MAX_OBJECTS = 5000          # graphic objects per page
MAX_CHARS = 120_000
MAX_SEGMENTS_PER_PATH = 4000
RASTER_DPI = 200.0
RASTER_MAX_SIDE = 6000


# ===================================================================== opening

def _open(data: bytes):
    """Open with pdfplumber; every failure is an :class:`ImportFailed`."""
    if b"%PDF-" not in data[:2048]:
        raise ImportFailed("This file is not a PDF (no %PDF header).")
    try:
        import pdfplumber
    except ImportError:
        raise ImportFailed("PDF import is not available in this build (pdfplumber is not installed).") from None
    try:
        pdf = pdfplumber.open(io.BytesIO(data))
        _ = len(pdf.pages)
    except ImportFailed:
        raise
    except Exception as exc:  # noqa: BLE001
        _raise_open_error(exc)
    return pdf


def _raise_open_error(exc: Exception):
    # pdfplumber wraps pdfminer's errors in PdfminerException(<original>)
    chain = [exc] + [x for x in getattr(exc, "args", ()) if isinstance(x, BaseException)]
    cause = exc.__cause__ or exc.__context__
    if cause is not None:
        chain.append(cause)
    text = " ".join("%s %s" % (type(x).__name__, x) for x in chain).lower()
    if "password" in text or "encrypt" in text:
        raise ImportFailed("The PDF is encrypted or password-protected. Remove the protection "
                           "(or export an unprotected copy) and import it again.") from None
    raise ImportFailed("The file could not be read as a PDF (%s). It may be damaged or truncated."
                       % type(chain[-1]).__name__) from None


def list_pages(data: bytes) -> list:
    """``[{"id": "1", "name": "Page 1"}, ...]`` (at most 50)."""
    data = require_bytes(data)
    pdf = _open(data)
    try:
        n = min(len(pdf.pages), MAX_PDF_PAGES)
    finally:
        pdf.close()
    return [{"id": str(i + 1), "name": "Page %d" % (i + 1)} for i in range(n)]


def thumbnail(data: bytes, page_index: int, max_px: int = 480) -> bytes:
    """PNG thumbnail of one page (``page_index`` is 0-based), longest side <= *max_px*."""
    data = require_bytes(data)
    max_px = int(min(2000, max(32, max_px)))
    pdf = _open(data)
    try:
        n = len(pdf.pages)
    finally:
        pdf.close()
    if not 0 <= int(page_index) < n:
        raise ImportFailed("Page %s not found; the PDF has %d page(s)." % (page_index, n))
    return _render_png(data, int(page_index), max_side=max_px)


def _render_png(data: bytes, index: int, dpi: float | None = None, max_side: float | None = None) -> bytes:
    try:
        import pypdfium2 as pdfium
    except ImportError:
        raise ImportFailed("Page rendering is not available in this build (pypdfium2 is not installed).") from None
    try:
        doc = pdfium.PdfDocument(data)
        try:
            pg = doc[index]
            w_pt, h_pt = pg.get_size()
            side = max(w_pt, h_pt, 1.0)
            if dpi is not None:
                scale = min(dpi / 72.0, RASTER_MAX_SIDE / side)
            else:
                scale = (max_side or 480) / side
            img = pg.render(scale=scale).to_pil().convert("RGB")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()
        finally:
            doc.close()
    except ImportFailed:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ImportFailed("The page could not be rendered (%s)." % type(exc).__name__) from None


# ===================================================================== scanned pages

def page_is_scanned(page_or_data, page_index: int | None = None) -> bool:
    """A page with no vector paths and fewer than 5 characters that holds one
    big image (>= 50% of the page). Accepts a pdfplumber page, or PDF bytes
    plus a 0-based *page_index*."""
    if isinstance(page_or_data, (bytes, bytearray)):
        pdf = _open(bytes(page_or_data))
        try:
            idx = int(page_index or 0)
            if not 0 <= idx < len(pdf.pages):
                raise ImportFailed("Page %d not found." % (idx + 1))
            return _scanned(pdf.pages[idx])
        finally:
            pdf.close()
    return _scanned(page_or_data)


def _scanned(page) -> bool:
    try:
        if len(page.rects) + len(page.curves) + len(page.lines) > 0:
            return False
        if len(page.chars) >= 5:
            return False
        area = float(page.width) * float(page.height)
        if area <= 0:
            return False
        for im in page.images:
            if (float(im["x1"]) - float(im["x0"])) * (float(im["bottom"]) - float(im["top"])) >= 0.5 * area:
                return True
    except Exception:  # noqa: BLE001
        return False
    return False


# ===================================================================== colours / styles

def _hex(c):
    """pdfplumber colour (gray / RGB / CMYK tuple) -> ``#RRGGBB`` or ``None``."""
    if c is None or isinstance(c, str):
        return None
    if isinstance(c, (int, float)):
        c = (c,)
    try:
        v = [min(1.0, max(0.0, float(x))) for x in c]
    except (TypeError, ValueError):
        return None
    if len(v) == 1:
        r = g = b = v[0]
    elif len(v) == 3:
        r, g, b = v
    elif len(v) == 4:
        cc, m, y, k = v
        r, g, b = (1 - cc) * (1 - k), (1 - m) * (1 - k), (1 - y) * (1 - k)
    else:
        return None
    return "#%02X%02X%02X" % (round(r * 255), round(g * 255), round(b * 255))


def _style(o: dict) -> dict:
    fill = _hex(o.get("non_stroking_color")) or "#000000" if o.get("fill") else "none"
    if o.get("fill") and isinstance(o.get("non_stroking_color"), str):
        fill = "#808080"                       # pattern/shading fill: colour unknown
    stroke = (_hex(o.get("stroking_color")) or "#000000") if o.get("stroke") else "none"
    lw = float(o.get("linewidth") or 0.0) * PT
    dash = o.get("dash")
    dashed = False
    try:
        dashed = bool(dash and dash[0])
    except (TypeError, IndexError):
        dashed = False
    return {"fill": fill, "stroke": stroke, "stroke_width": round(lw if lw > 0 else 1.0, 3) if stroke != "none" else 0.0,
            "dashed": dashed, "opacity": 1.0}


def _pt(p) -> tuple:
    return (float(p[0]) * PT, float(p[1]) * PT)


def _segs(o: dict) -> list:
    """pdfplumber path -> absolute M/L/C/Z segments in px."""
    path = o.get("path")
    segs: list = []
    if path:
        cur = start = None
        for item in path[:MAX_SEGMENTS_PER_PATH]:
            op = item[0]
            if op == "m":
                cur = start = _pt(item[1])
                segs.append(("M", *cur))
            elif op == "l":
                p = _pt(item[1])
                if cur is None:
                    cur = start = p
                    segs.append(("M", *p))
                else:
                    segs.append(("L", *p))
                    cur = p
            elif op in ("c", "v", "y") and cur is not None:
                if op == "c":
                    p1, p2, p3 = _pt(item[1]), _pt(item[2]), _pt(item[3])
                elif op == "v":
                    p1, p2, p3 = cur, _pt(item[1]), _pt(item[2])
                else:
                    p1, p3 = _pt(item[1]), _pt(item[2])
                    p2 = p3
                segs.append(("C", p1[0], p1[1], p2[0], p2[1], p3[0], p3[1]))
                cur = p3
            elif op == "h" and cur is not None:
                segs.append(("Z",))
                cur = start
        if segs:
            return segs
    pts = o.get("pts") or []
    if len(pts) >= 2:
        p0 = _pt(pts[0])
        segs = [("M", *p0)] + [("L", *_pt(p)) for p in pts[1:MAX_SEGMENTS_PER_PATH]]
    return segs


def _split_subpaths(segs: list) -> list:
    out, cur = [], []
    for s in segs:
        if s[0] == "M" and cur:
            out.append(cur)
            cur = []
        cur.append(s)
    if cur:
        out.append(cur)
    return out


# ===================================================================== text

def _clean_text(t: str) -> str:
    t = re.sub(r"\(cid:\d+\)", "", t or "")
    return re.sub(r"[\x00-\x08\x0b-\x1f�]", "", t).strip()


def _font_props(word: dict) -> dict:
    name = re.sub(r"^[A-Z]{6}\+", "", str(word.get("fontname") or ""))
    fam = re.split(r"[-,]", name)[0]
    fam = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", fam)
    fam = re.sub(r"[^A-Za-z0-9 ]", "", fam).strip()[:60]
    return {"font_size": round(min(200.0, max(4.0, float(word.get("size") or 10.0) * PT)), 2),
            "font_family": fam,
            "bold": bool(re.search(r"bold|black|heavy|semibold|demi", name, re.I)),
            "italic": bool(re.search(r"italic|oblique", name, re.I)),
            "font_color": _hex(word.get("non_stroking_color")) or "#000000", "align": "left"}


def _words(page, w: Warnings) -> list:
    chars = page.chars
    if len(chars) > MAX_CHARS:
        w.once("chars", "The page has %d characters; only the first %d were read." % (len(chars), MAX_CHARS))
        chars = chars[:MAX_CHARS]
    try:
        from pdfplumber.utils import extract_words
        words = extract_words(chars, keep_blank_chars=False, use_text_flow=True, x_tolerance=3, y_tolerance=3,
                              extra_attrs=["size", "fontname", "non_stroking_color"])
    except Exception:  # noqa: BLE001 -- a font oddity must not fail the whole page
        words = []
    out, seen = [], set()
    for wd in words:
        t = _clean_text(wd.get("text"))
        if not t:
            continue
        key = (t, round(float(wd["x0"]) / 0.6), round(float(wd["top"]) / 0.6))
        if key in seen:                               # text drawn twice (fake bold / shadow)
            continue
        seen.add(key)
        out.append({"text": t, "x0": float(wd["x0"]) * PT, "x1": float(wd["x1"]) * PT,
                    "top": float(wd["top"]) * PT, "bottom": float(wd["bottom"]) * PT,
                    "size": float(wd.get("size") or 10.0) * PT, "src": wd})
    return out


def _text_blocks(words: list) -> list:
    """Words -> lines (same row, near each other) -> blocks (stacked lines of one column)."""
    lines: list = []
    buckets: dict = {}
    for wd in sorted(words, key=lambda q: ((q["top"] + q["bottom"]) / 2.0, q["x0"])):
        cy = (wd["top"] + wd["bottom"]) / 2.0
        size = max(wd["size"], 1.0)
        target = None
        b = int(cy // 6.0)
        for bb in range(b - 3, b + 4):
            for ln in buckets.get(bb, ()):
                if abs(ln["cy"] - cy) > 0.5 * max(ln["h"], wd["bottom"] - wd["top"], 1.0):
                    continue
                gap_r, gap_l = wd["x0"] - ln["x1"], ln["x0"] - wd["x1"]
                reach = 1.2 * max(size, ln["size"])
                if -2.0 <= gap_r <= reach or -2.0 <= gap_l <= reach:
                    target = ln
                    break
            if target:
                break
        if target is None:
            target = {"words": [], "x0": wd["x0"], "x1": wd["x1"], "top": wd["top"], "bottom": wd["bottom"],
                      "cy": cy, "h": wd["bottom"] - wd["top"], "size": size}
            lines.append(target)
            buckets.setdefault(b, []).append(target)
        target["words"].append(wd)
        target["x0"], target["x1"] = min(target["x0"], wd["x0"]), max(target["x1"], wd["x1"])
        target["top"], target["bottom"] = min(target["top"], wd["top"]), max(target["bottom"], wd["bottom"])
        target["size"] = max(target["size"], size)
    for ln in lines:
        ln["words"].sort(key=lambda q: q["x0"])
        ln["text"] = " ".join(q["text"] for q in ln["words"])
    blocks: list = []
    for ln in sorted(lines, key=lambda q: (q["top"], q["x0"])):
        placed = None
        for bl in reversed(blocks[-60:]):
            last = bl["lines"][-1]
            dy = ln["cy"] - last["cy"]
            size = max(ln["size"], last["size"])
            if not 0.6 * size <= dy <= 1.9 * size:
                continue
            if max(ln["size"], last["size"]) / max(min(ln["size"], last["size"]), 1.0) > 1.4:
                continue
            ov = min(ln["x1"], bl["x1"]) - max(ln["x0"], bl["x0"])
            narrow = min(ln["x1"] - ln["x0"], bl["x1"] - bl["x0"])
            aligned = (abs(ln["x0"] - last["x0"]) <= 3.0 or abs((ln["x0"] + ln["x1"]) / 2.0 - (last["x0"] + last["x1"]) / 2.0)
                       <= 0.4 * size or abs(ln["x1"] - last["x1"]) <= 3.0)
            if ov >= 0.3 * max(narrow, 1.0) or aligned:
                placed = bl
                break
        if placed is None:
            placed = {"lines": [], "x0": ln["x0"], "x1": ln["x1"], "top": ln["top"], "bottom": ln["bottom"]}
            blocks.append(placed)
        placed["lines"].append(ln)
        placed["x0"], placed["x1"] = min(placed["x0"], ln["x0"]), max(placed["x1"], ln["x1"])
        placed["top"], placed["bottom"] = min(placed["top"], ln["top"]), max(placed["bottom"], ln["bottom"])
    out = []
    for bl in blocks:
        first = bl["lines"][0]["words"][0]["src"]
        font = _font_props(first)
        sizes = [q["size"] for ln in bl["lines"] for q in ln["words"]]
        font["font_size"] = round(min(200.0, max(4.0, statistics.median(sizes))), 2)
        text = "\n".join(ln["text"] for ln in bl["lines"])[:model.MAX_TEXT]
        x, y, wd, hh = bl["x0"], bl["top"], max(bl["x1"] - bl["x0"], 1.0), max(bl["bottom"] - bl["top"], 1.0)
        out.append({"text": text, "x": x, "y": y, "w": wd, "h": hh, "rotation": 0.0,
                    "cx": x + wd / 2.0, "cy": y + hh / 2.0, "font": font})
    return out


# ===================================================================== page

def _style_key(st: dict) -> tuple:
    return (st["stroke"], round(st["stroke_width"], 1), st["dashed"])


def _merge_lines(lines: list, blockers: "geo.ElementIndex", join: float) -> list:
    """Join segments that meet end to end (exactly two ends at the joint, same
    style, joint not on a shape) into polylines."""
    cell = max(join * 2.0, 4.0)
    for _ in range(200):
        grid: dict = {}
        for i, ln in enumerate(lines):
            if ln is None:
                continue
            for e, p in ((0, ln["pts"][0]), (1, ln["pts"][-1])):
                grid.setdefault((int(p[0] // cell), int(p[1] // cell)), []).append((i, e, p))
        merged_any = False
        for i, ln in enumerate(lines):
            if ln is None:
                continue
            for e, p in ((0, ln["pts"][0]), (1, ln["pts"][-1])):
                near = []
                cx, cy = int(p[0] // cell), int(p[1] // cell)
                for gx in (cx - 1, cx, cx + 1):
                    for gy in (cy - 1, cy, cy + 1):
                        for j, ej, q in grid.get((gx, gy), ()):
                            if (j, ej) != (i, e) and math.hypot(p[0] - q[0], p[1] - q[1]) <= join:
                                near.append((j, ej))
                if len(near) != 1 or near[0][0] == i:
                    continue
                j = near[0][0]
                other = lines[j]
                if other is None or _style_key(other["style"]) != _style_key(ln["style"]):
                    continue
                if blockers.nearest(p, 1.5, inside_max_area=0.0) is not None:
                    continue
                joined = geo.merge_collinear(ln["pts"], other["pts"], join=join, angle_tol_deg=100.0)
                if joined is None:
                    continue
                ln["pts"] = joined
                ln["order"] = min(ln["order"], other["order"])
                lines[j] = None
                merged_any = True
                break
        lines = [l for l in lines if l is not None] if merged_any else lines
        if not merged_any:
            break
    out = [l for l in lines if l is not None]
    for ln in out:
        if len(ln["pts"]) > 2:
            ln["pts"] = geo.simplify_polyline(ln["pts"], 0.3)      # drop collinear joints
    return out


def _shape_element(eid: str, shape: str, x, y, w, h, style: dict, order: int, ref: str, **extra) -> dict:
    e = {"id": eid, "kind": "shape", "shape": shape, "name": "", "description": "", "text": "",
         "x": round(x, 3), "y": round(y, 3), "w": round(max(w, 0.5), 3), "h": round(max(h, 0.5), 3),
         "rotation": 0.0, "layer": "", "ports": [], "style": style, "metadata": {"pdf_object": ref.split(":")[1].split("#")[0]},
         "source_ref": ref, "confidence": 1.0, "_order": order, "poly": None, "filled": style["fill"] != "none"}
    e.update(extra)
    return e


def _read_page(page, pno: int, w: Warnings) -> dict | None:
    pw, ph = float(page.width) * PT, float(page.height) * PT
    page_area = pw * ph
    rects = list(page.rects)
    curves = list(page.curves)
    lines_in = list(page.lines)
    total = len(rects) + len(curves) + len(lines_in)
    if total > MAX_OBJECTS:
        w.once("objects", "Page %d has %d graphic objects; only the first %d were read." % (pno, total, MAX_OBJECTS))
        rects = rects[:MAX_OBJECTS]
        curves = curves[:max(0, MAX_OBJECTS - len(rects))]
        lines_in = lines_in[:max(0, MAX_OBJECTS - len(rects) - len(curves))]

    def inside(o) -> bool:
        return not (float(o["x1"]) < -5 or float(o["x0"]) > float(page.width) + 5
                    or float(o["bottom"]) < -5 or float(o["top"]) > float(page.height) + 5)

    ids = iter("e%d" % i for i in range(1, 10 ** 7))
    shapes: list = []
    conns: list = []
    background = ""
    dropped_white = 0
    order = 0

    def add_line(pts, st, ref):
        nonlocal order
        pts = geo.dedupe_points(pts, 1e-3)
        if len(pts) < 2 or st["stroke"] == "none":
            return
        order += 1
        conns.append({"pts": pts, "curved": False, "style": st, "start_arrow": "none", "end_arrow": "none",
                      "order": order, "layer": "", "metadata": {"pdf_object": ref.split(":")[1].split("#")[0]},
                      "source_ref": ref})

    for i, o in enumerate(rects):
        if not inside(o) or not (o.get("fill") or o.get("stroke")):
            continue
        x0, x1 = float(o["x0"]) * PT, float(o["x1"]) * PT
        top, bot = float(o["top"]) * PT, float(o["bottom"]) * PT
        rw, rh = x1 - x0, bot - top
        st = _style(o)
        ref = "p%d:rect#%d" % (pno, i)
        if rw * rh >= 0.9 * page_area:
            if st["fill"] != "none":
                background = st["fill"]
            continue
        if o.get("fill") and not o.get("stroke") and min(rw, rh) <= 1.6 * PT and max(rw, rh) >= 4.0:
            col = dict(st, stroke=st["fill"], fill="none", stroke_width=round(max(min(rw, rh), 1.0), 3))
            if rw >= rh:
                add_line([(x0, (top + bot) / 2.0), (x1, (top + bot) / 2.0)], col, ref)
            else:
                add_line([((x0 + x1) / 2.0, top), ((x0 + x1) / 2.0, bot)], col, ref)
            continue
        if o.get("fill") and not o.get("stroke") and st["fill"] == "#FFFFFF":
            dropped_white += 1
            continue
        order += 1
        shapes.append(_shape_element(next(ids), "rect", x0, top, rw, rh, st, order, ref))

    for i, o in enumerate(curves):
        if not inside(o):
            continue
        st = _style(o)
        if not (o.get("fill") or o.get("stroke")):
            continue
        segs = _segs(o)
        if len(segs) < 2:
            continue
        ref = "p%d:curve#%d" % (pno, i)
        parts = []
        for g in _split_subpaths(segs):
            sub = geo.flatten(g)
            if not sub:
                continue
            pts, closed = sub[0]
            eff = closed or (bool(o.get("fill")) and len(pts) >= 3 and geo.polygon_area(pts) > 1.0)
            parts.append((g, pts, eff))
        if not parts:
            continue
        outlines = []
        if all(eff for _, _, eff in parts):
            outlines.append([s for g, _, _ in parts for s in g])
        else:
            for g, pts, eff in parts:
                if eff:
                    outlines.append(g)
                else:
                    curved = geo.has_curves(g)
                    if curved and len(pts) > 3:
                        pts = geo.simplify_polyline(pts, 0.75)
                    pts = geo.dedupe_points(pts, 1e-3)
                    if len(pts) >= 2 and st["stroke"] != "none":
                        order += 1
                        conns.append({"pts": pts, "curved": curved, "style": st, "start_arrow": "none",
                                      "end_arrow": "none", "order": order, "layer": "",
                                      "metadata": {"pdf_object": "curve"}, "source_ref": ref})
        for g in outlines:
            c = geo.classify_outline(g)
            if c is None:
                continue
            order += 1
            style = dict(st, rounded=True) if c["rounded"] else st
            e = _shape_element(next(ids), c["shape"], c["x"], c["y"], c["w"], c["h"], style, order, ref,
                               poly=c["poly"], confidence=c["confidence"])
            if c["shape"] == "polygon":
                e["points"] = c["points"]
            elif c["shape"] == "path":
                e["path"] = c["path"]
            shapes.append(e)

    for i, o in enumerate(lines_in):
        if not inside(o):
            continue
        pts = [_pt(p) for p in (o.get("pts") or [])]
        if len(pts) < 2:
            pts = [(float(o["x0"]) * PT, float(o["top"]) * PT), (float(o["x1"]) * PT, float(o["bottom"]) * PT)]
        st = _style(dict(o, stroke=True))
        add_line(pts, st, "p%d:line#%d" % (pno, i))

    if dropped_white:
        w.once("white", "Ignored %d invisible white fill(s) without an outline." % dropped_white)

    # words -> text blocks
    texts = _text_blocks(_words(page, w))
    for k, t in enumerate(texts):
        t["order"] = k
        t["id"] = "t%d" % k

    # segments that meet end to end -> polylines
    if conns:
        before = len(conns)
        blockers = geo.ElementIndex(shapes)
        conns = _merge_lines(conns, blockers, join=1.5 * PT)
        if len(conns) < before:
            w.once("merged", "Merged split line segments into polylines (%d -> %d lines)." % (before, len(conns)))

    return {"w": pw, "h": ph, "shapes": shapes, "conns": conns, "texts": texts, "background": background}


def _assemble(raw: dict, pno: int, w: Warnings) -> dict:
    pw, ph = raw["w"], raw["h"]
    shapes, conns, texts = raw["shapes"], raw["conns"], raw["texts"]
    elements = list(shapes)
    for k, c in enumerate(conns):
        c["key"] = k
    heads = geo.extract_arrowheads(conns, elements, math.hypot(pw, ph))
    if heads:
        gone = {id(h) for h in heads}
        elements = [e for e in elements if id(e) not in gone]
        w.once("arrowheads", "Merged %d small filled triangle(s) into connector arrowheads." % len(heads))
    assigned, left = geo.assign_texts(elements, texts, pw * ph)
    by_id = {e["id"]: e for e in elements}
    for eid, ts in assigned.items():
        ts.sort(key=lambda q: (round(q["cy"] / 4.0), q["cx"]))
        e = by_id[eid]
        e["text"] = "\n".join(t["text"] for t in ts)[:model.MAX_TEXT]
        f = ts[0]["font"]
        e["style"] = dict(e["style"], font_color=f["font_color"], font_size=f["font_size"],
                          font_family=f["font_family"], bold=f["bold"], italic=f["italic"],
                          align="center", valign="middle")
    if assigned:
        w.once("text_in_shape", "Assigned %d text block(s) to the shape that contains them."
               % sum(len(v) for v in assigned.values()))
    labels, free = geo.label_connectors(left, conns)
    for i, labs in labels.items():
        conns[i]["labels"] = labs
    if labels:
        w.once("labels", "Used %d short text block(s) next to a line as connector labels."
               % sum(len(v) for v in labels.values()))
    for t in free:
        f = t["font"]
        elements.append({"id": "x%d" % len(elements), "kind": "text", "shape": "rect", "text": t["text"],
                         "x": round(t["x"], 3), "y": round(t["y"], 3), "w": round(t["w"], 3), "h": round(t["h"], 3),
                         "rotation": 0.0, "layer": "", "ports": [],
                         "style": {"fill": "none", "stroke": "none", "stroke_width": 0, "opacity": 1.0,
                                   "font_color": f["font_color"], "font_size": f["font_size"],
                                   "font_family": f["font_family"], "bold": f["bold"], "italic": f["italic"],
                                   "align": "left", "valign": "top"},
                         "metadata": {"pdf_object": "text"}, "source_ref": "p%d:text" % pno, "confidence": 1.0,
                         "_order": 10 ** 6 + t["order"], "poly": None, "filled": False})
    elements.sort(key=lambda e: e["_order"])
    if len(elements) > model.MAX_ELEMENTS:
        w.once("elements", "The page has %d elements; only the first %d were kept." % (len(elements), model.MAX_ELEMENTS))
        elements = elements[:model.MAX_ELEMENTS]
    for n, e in enumerate(elements, 1):                      # stable, readable ids
        e["id"] = "e%d" % n
    # the connector attach step needs the final ids
    connectors, dropped = geo.model_connectors(conns, elements, pw, ph, model.MAX_CONNECTORS)
    if dropped:
        w.once("connectors", "The page has more than %d lines; the rest were dropped." % model.MAX_CONNECTORS)
    for o in elements + connectors:
        for k in ("_order", "_key", "poly", "filled"):
            o.pop(k, None)
    return {"id": str(pno), "name": "Page %d" % pno, "width": round(pw, 3), "height": round(ph, 3),
            "background": raw["background"], "layers": [], "groups": [], "elements": elements,
            "connectors": connectors}


# ===================================================================== raster hook

_NUM_IN_PATH = re.compile(r"[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")


def _scale_page(pg: dict, s: float, pw: float, ph: float, pno: int) -> dict:
    """Scale a raster-recognised page into the PDF page's px space."""
    for e in pg.get("elements", []):
        for k in ("x", "y", "w", "h"):
            e[k] = round(float(e.get(k, 0)) * s, 3)
        st = e.get("style") or {}
        for k in ("stroke_width", "font_size"):
            if k in st:
                st[k] = round(float(st[k]) * s, 3)
        if e.get("shape") == "path" and e.get("path"):
            d = e["path"]
            if re.search(r"[Aa]", d):
                e["shape"], e["path"] = "rect", ""
            else:
                e["path"] = _NUM_IN_PATH.sub(lambda m: repr(round(float(m.group(0)) * s, 3)), d)
    for c in pg.get("connectors", []):
        for k in ("start", "end"):
            if c.get(k):
                c[k] = [round(float(c[k][0]) * s, 3), round(float(c[k][1]) * s, 3)]
        c["points"] = [[round(float(x) * s, 3), round(float(y) * s, 3)] for x, y in c.get("points", [])]
        st = c.get("style") or {}
        if "stroke_width" in st:
            st["stroke_width"] = round(float(st["stroke_width"]) * s, 3)
    pg["width"], pg["height"] = round(pw, 3), round(ph, 3)
    pg["id"], pg["name"] = str(pno), "Page %d" % pno
    return pg


def _raster_page(data: bytes, index: int, pw: float, ph: float, hook, filename: str, w: Warnings) -> dict:
    png = _render_png(data, index, dpi=RASTER_DPI)
    doc = hook(png, filename)
    if not isinstance(doc, dict) or not doc.get("pages"):
        raise ImportFailed("Page %d is a scanned image and the image recogniser returned nothing." % (index + 1))
    doc, norm_w = model.normalise(doc)
    pg = doc["pages"][0]
    s = pw / float(pg["width"]) if pg.get("width") else 1.0
    for msg in (doc.get("recognition") or {}).get("warnings", []):
        w.add("Page %d (image recognition): %s" % (index + 1, msg))
    w.once("scanned%d" % index, "Page %d is a scanned image; its content was recognised from a %d dpi render."
           % (index + 1, int(RASTER_DPI)))
    return _scale_page(pg, s, pw, ph, index + 1)


# ===================================================================== entry point

def _wanted(page, n: int) -> list:
    if page in (None, "", "all"):
        return list(range(min(n, MAX_PDF_PAGES)))
    want = str(page).strip()
    if want.isdigit() and 1 <= int(want) <= n:
        return [int(want) - 1]
    raise ImportFailed("Page %r not found; the PDF has %d page(s)." % (want[:40], n))


@guarded
def read(data: bytes, *, filename: str = "", page: str | None = None, raster_reader=None) -> dict:
    data = require_bytes(data)
    pdf = _open(data)
    w = Warnings()
    pages: list = []
    try:
        n = len(pdf.pages)
        if n == 0:
            raise ImportFailed("The PDF has no pages.")
        if n > MAX_PDF_PAGES and page in (None, "", "all"):
            w.add("The PDF has %d pages; only the first %d were read." % (n, MAX_PDF_PAGES))
        wanted = _wanted(page, n)
        single = len(wanted) == 1
        for idx in wanted:
            pg = pdf.pages[idx]
            pno = idx + 1
            try:
                if _scanned(pg):
                    if raster_reader is None:
                        if single:
                            raise ImportFailed("Page %d is a scanned image (it has no vector drawing or text). "
                                               "Import it as an image (PNG/JPEG) so it can be recognised, "
                                               "or export the page from the original drawing tool." % pno)
                        w.add("Page %d is a scanned image and was skipped." % pno)
                        continue
                    pw, ph = float(pg.width) * PT, float(pg.height) * PT
                    pages.append(_raster_page(data, idx, pw, ph, raster_reader, filename, w))
                    continue
                raw = _read_page(pg, pno, w)
                out = _assemble(raw, pno, w)
            except ImportFailed:
                raise
            except Exception as exc:  # noqa: BLE001
                raise ImportFailed("Page %d could not be read (%s)." % (pno, type(exc).__name__)) from None
            finally:
                try:
                    pg.flush_cache()
                except Exception:  # noqa: BLE001
                    pass
            if not out["elements"] and not out["connectors"]:
                w.add("Page %d has no vector drawing or text." % pno)
                if not single:
                    continue
            pages.append(out)
    finally:
        pdf.close()
    if not pages or not any(p["elements"] or p["connectors"] for p in pages):
        raise ImportFailed("The PDF has no vector drawing or text to import.")
    name = doc_name(filename, "PDF drawing")
    return make_document(fmt="pdf", engine=ENGINE, data=data, filename=filename, name=name, pages=pages,
                         warnings=w.items, page=page if page not in ("all",) else None)
