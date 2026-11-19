"""Raster recogniser (engine ``raster-cv``): PNG, JPEG, GIF, WEBP, BMP and TIFF
pictures of diagrams turned into editable ``satom.diagram/1`` documents.

The pipeline is a chain of small functions, each testable on its own::

    decode_image -> preprocess -> run_ocr -> detect_shapes -> detect_arrowheads
      -> extract_line_mask -> detect_symbols -> trace_connectors
      -> attach_connectors -> assign_text -> build_page

* preprocess: grayscale, light denoise, background normalisation (a morphological
  closing estimates the paper and the large fills, so a coloured fill is not
  mistaken for ink), threshold, and deskew of small rotations (+-5 degrees)
  measured on the long straight strokes.
* shapes: the INTERIOR of every closed outline is a hole contour of the ink
  mask, which connectors touching the outline do not disturb. Each hole is
  compared (IoU) with rendered templates -- rect, rounded rect, pill, ellipse,
  circle, diamond, triangle, hexagon, parallelogram -- and a flat ellipse
  sitting on a body is merged into a cylinder. Holes that are not convex,
  fit no template, or are bounded mostly by other shapes' outlines and
  connector strokes (the "loop" regions enclosed by connectors) are refused.
* connectors: shape outlines, text and arrowheads are removed from the ink,
  what remains is thinned to a one-pixel skeleton, turned into a graph and
  traced end to end (straight through junctions); polylines are simplified
  and snapped to orthogonal routing when every segment is axis-aligned.
  Collinear pieces split by a label or by dashes are bridged.
* arrowheads: a morphological opening keeps solid blobs; triangles give the
  direction from their apex, and are bound to the connector end they sit on.
* unknown dense blobs (icons) become ``kind: image`` / ``shape: symbol``
  elements carrying their own cropped PNG, low confidence and
  ``needs_review``; the page itself is never turned into a background image.

Coordinates in the document are pixels of the (deskewed) source image.
Heavy dependencies (numpy, OpenCV, Pillow, the OCR runtime) are imported
inside the functions.
"""
from __future__ import annotations

import base64
import io
import math
import time
import warnings as _warnings

from .. import model

from . import ImportFailed, Warnings, doc_name, guarded, make_document, require_bytes

ENGINE = "raster-cv"
VERSION = "1.0"

MAX_PIXELS = 50_000_000          # per frame; bigger is refused (decompression bomb)
MAX_BYTES = 64 * 1024 * 1024
MAX_TIFF_PAGES = 20
FORMATS = {"PNG": "png", "JPEG": "jpeg", "MPO": "jpeg", "GIF": "gif", "WEBP": "webp",
           "BMP": "bmp", "DIB": "bmp", "TIFF": "tiff"}

WORK_MIN_SIDE = 1200             # smaller pictures are upscaled for the CV stages
WORK_TARGET = 1600
WORK_MAX_SIDE = 3600             # bigger pictures are downscaled
MAX_UPSCALE = 3.0
MAX_SKEW_DEG = 5.0
HYSTERESIS = 0.75                # weak-pixel threshold as a fraction of the ink threshold
SLANT_MARGIN = 0.03              # IoU a slanted template must beat the rectangle by
SYMBOL_MAX_URI = 256 * 1024      # data-URI characters per symbol crop
MAX_CANDIDATE_HOLES = 4000
MAX_INK_DENSITY = 0.35           # more ink than this is not a line drawing
MAX_SKELETON_PX = 3_000_000      # connector tracing budget (skeleton pixels)
MAX_SINGLE_REMOVALS = 300        # loop-region refusals measured one at a time
MAX_TOTAL_PIXELS = 200_000_000   # across the pages of one multi-page TIFF

#: An element whose confidence is under model.LOW_CONFIDENCE goes to Review.
SYMBOL_CONFIDENCE = 0.3
#: Connectors whose direction cues disagree or are missing get at most this.
UNCERTAIN_CONFIDENCE = 0.45
#: A connector with a free (unattached) end gets at most this.
DANGLING_CONFIDENCE = 0.4
#: An end attached only by following the line across a gap (quality 0.45)
#: is loose; the connector then gets at most LOOSE_CONFIDENCE.
LOOSE_ATTACH_QUALITY = 0.5
LOOSE_CONFIDENCE = 0.5
FREE_END_QUALITY = 0.3
assert max(UNCERTAIN_CONFIDENCE, DANGLING_CONFIDENCE, LOOSE_CONFIDENCE) < model.LOW_CONFIDENCE


# ============================================================== decoding

def _pil():
    from PIL import Image, ImageOps

    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    return Image, ImageOps


def open_image(data: bytes):
    """Open with Pillow, refusing unknown formats and decompression bombs.
    -> ``(PIL image, format key)``; nothing is decoded yet."""
    Image, _ = _pil()
    if len(data) > MAX_BYTES:
        raise ImportFailed("The image is larger than %d MB." % (MAX_BYTES // (1024 * 1024)))
    try:
        with _warnings.catch_warnings():
            _warnings.simplefilter("error", Image.DecompressionBombWarning)
            im = Image.open(io.BytesIO(data))
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise ImportFailed("The image has more than %d megapixels and was refused "
                           "(possible decompression bomb)." % (MAX_PIXELS // 1_000_000)) from None
    except Exception:
        raise ImportFailed("The file is not a readable PNG, JPEG, GIF, WEBP, BMP or TIFF image.") from None
    fmt = FORMATS.get(str(im.format or "").upper())
    if not fmt:
        raise ImportFailed("Unsupported image format %r; use PNG, JPEG, GIF, WEBP, BMP or TIFF."
                           % str(im.format)[:20])
    _check_size(im.size)
    return im, fmt


def _check_size(size) -> None:
    w, h = int(size[0]), int(size[1])
    if w < 8 or h < 8:
        raise ImportFailed("The image is too small (%dx%d) to hold a diagram." % (w, h))
    if w * h > MAX_PIXELS:
        raise ImportFailed("The image has %.1f megapixels; the limit is %d (possible "
                           "decompression bomb)." % (w * h / 1e6, MAX_PIXELS // 1_000_000))


def frame_count(im, fmt: str) -> int:
    """Pages to read: TIFF pages (capped), first frame for animations."""
    if fmt != "tiff":
        return 1
    return max(1, min(int(getattr(im, "n_frames", 1) or 1), MAX_TIFF_PAGES))


def frame_bgr(im, index: int):
    """Decode frame *index* to a BGR uint8 array (alpha composed on white)."""
    import numpy as np

    Image, ImageOps = _pil()
    im.seek(index)
    _check_size(im.size)
    with _warnings.catch_warnings():
        _warnings.simplefilter("error", Image.DecompressionBombWarning)
        fr = im.copy() if index else im
        try:
            fr = ImageOps.exif_transpose(fr)
        except Exception:  # noqa: BLE001 -- a broken EXIF block must not stop the import
            pass
        _check_size(fr.size)
        if fr.mode in ("RGBA", "LA", "PA") or (fr.mode == "P" and "transparency" in fr.info):
            rgba = fr.convert("RGBA")
            bg = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
            bg.alpha_composite(rgba)
            fr = bg.convert("RGB")
        elif fr.mode in ("I;16", "I;16B", "I;16L", "I", "F"):
            arr = np.asarray(fr, dtype=np.float64)
            lo, hi = float(arr.min()), float(arr.max())
            arr = (arr - lo) / max(hi - lo, 1e-9) * 255.0
            fr = Image.fromarray(arr.astype(np.uint8)).convert("RGB")
        else:
            fr = fr.convert("RGB")
    rgb = np.asarray(fr, dtype=np.uint8)
    return np.ascontiguousarray(rgb[:, :, ::-1])


def decode_image(data: bytes, page=None) -> tuple:
    """-> ``(format, total_pages, iterator of (page_number, bgr))`` honouring
    *page* (1-based or ``page-N``). Frames are decoded one at a time, so a
    multi-page TIFF never holds more than one page in memory."""
    im, fmt = open_image(data)
    n = frame_count(im, fmt)
    total = int(getattr(im, "n_frames", 1) or 1) if fmt == "tiff" else 1
    wanted = list(range(n))
    if page not in (None, ""):
        p = str(page).strip()
        if p.startswith("page-"):
            p = p[5:]
        if not p.isdigit() or not 1 <= int(p) <= n:
            raise ImportFailed("Page %r not found; the image has %d page(s)." % (str(page)[:40], n))
        wanted = [int(p) - 1]

    def frames():
        budget = MAX_TOTAL_PIXELS
        for i in wanted:
            try:
                im.seek(i)
            except EOFError:
                return
            budget -= im.size[0] * im.size[1]
            if budget < 0:
                raise ImportFailed("The pages of this TIFF exceed %d megapixels in total."
                                   % (MAX_TOTAL_PIXELS // 1_000_000))
            try:
                bgr = frame_bgr(im, i)
            except ImportFailed:
                raise
            except (OSError, ValueError, EOFError, SyntaxError):
                raise ImportFailed("The image data is damaged or truncated.") from None
            yield i + 1, bgr

    return fmt, total, frames()


# ============================================================ preprocess

class Prep:
    """Working-scale state shared by the stages."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def _odd(v: float) -> int:
    v = int(round(v))
    return v if v % 2 else v + 1


def work_scale(w: int, h: int) -> float:
    m = max(w, h)
    if m < WORK_MIN_SIDE:
        return min(MAX_UPSCALE, WORK_TARGET / float(m))
    if m > WORK_MAX_SIDE:
        return WORK_MAX_SIDE / float(m)
    return 1.0


def ink_mask(gray, hysteresis: bool = True):
    """Background-normalised threshold: ``(ink, strong)`` uint8 0/255 masks --
    *ink* with hysteresis (faint pixels joined to strong ones), *strong* without.

    A closing with a kernel wider than any stroke estimates the paper AND the
    large fills, so a pastel fill is background while its dark outline is ink."""
    import cv2
    import numpy as np

    h, w = gray.shape
    k = _odd(max(21, 0.025 * max(h, w)))
    bg = cv2.morphologyEx(gray, cv2.MORPH_CLOSE, cv2.getStructuringElement(cv2.MORPH_RECT, (k, k)))
    dark = 1.0 - gray.astype(np.float32) / np.maximum(bg.astype(np.float32), 1.0)
    dark = np.clip(dark, 0.0, 1.0)
    d8 = (dark * 255).astype(np.uint8)
    t, _ = cv2.threshold(d8, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    t = float(min(max(t, 0.15 * 255), 0.5 * 255))
    strong = d8 > t
    # hysteresis: fainter pixels count when they connect to strong ink, so a
    # thin anti-aliased or JPEG-softened diagonal stays one unbroken line
    weak = d8 > (max(0.12 * 255, HYSTERESIS * t) if hysteresis else t)
    n, lab = cv2.connectedComponents(weak.astype(np.uint8), connectivity=8)
    keep = np.zeros(n, bool)
    keep[np.unique(lab[strong])] = True
    keep[0] = False
    ink = keep[lab].astype(np.uint8) * 255
    return ink, strong.astype(np.uint8) * 255


def estimate_skew(ink) -> float:
    """Degrees (OpenCV convention, positive = counter-clockwise correction) that
    straighten the long strokes; 0 when there is no evidence."""
    import cv2
    import numpy as np

    h, w = ink.shape
    min_len = max(60, int(0.04 * min(h, w)))
    segs = cv2.HoughLinesP(ink, 1, np.pi / 720, threshold=max(60, min_len),
                           minLineLength=min_len, maxLineGap=2)
    if segs is None:
        return 0.0
    angs, wts = [], []
    for x1, y1, x2, y2 in segs.reshape(-1, 4):
        a = math.degrees(math.atan2(y2 - y1, x2 - x1))
        a = ((a + 45.0) % 90.0) - 45.0
        if abs(a) <= MAX_SKEW_DEG + 0.5:
            angs.append(a)
            wts.append(math.hypot(x2 - x1, y2 - y1))
    if len(angs) < 3:
        return 0.0
    # Mode of a length-weighted angle density (0.05 degree bins, smoothed):
    # long strokes of shapes and orthogonal connectors agree on the tilt,
    # while glyph strokes and diagonal connectors scatter and must not drag a
    # median around. Refined as the weighted mean around the peak.
    a = np.asarray(angs)
    wt = np.asarray(wts) ** 2
    bins = np.arange(-MAX_SKEW_DEG - 0.5, MAX_SKEW_DEG + 0.55, 0.05)
    hist, _ = np.histogram(a, bins=bins, weights=wt)
    k = np.exp(-0.5 * (np.arange(-12, 13) * 0.05 / 0.2) ** 2)
    dens = np.convolve(hist, k, mode="same")
    peak = float(bins[int(np.argmax(dens))] + 0.025)
    near = np.abs(a - peak) <= 0.4
    est = float(np.average(a[near], weights=wt[near])) if near.any() else peak
    if abs(est) < 0.2 or abs(est) > MAX_SKEW_DEG:
        return 0.0
    return est


def page_background(bgr):
    import numpy as np

    h, w = bgr.shape[:2]
    b = max(2, min(h, w) // 100)
    border = np.concatenate([bgr[:b].reshape(-1, 3), bgr[-b:].reshape(-1, 3),
                             bgr[:, :b].reshape(-1, 3), bgr[:, -b:].reshape(-1, 3)])
    return tuple(int(v) for v in np.median(border, axis=0))


def preprocess(bgr) -> Prep:
    """Scale to working size, denoise, threshold, deskew."""
    import cv2
    import numpy as np

    h0, w0 = bgr.shape[:2]
    s = work_scale(w0, h0)
    work = bgr if s == 1.0 else cv2.resize(bgr, (int(round(w0 * s)), int(round(h0 * s))),
                                           interpolation=cv2.INTER_CUBIC if s > 1 else cv2.INTER_AREA)
    bgcol = page_background(work)
    # dark-mode diagrams (light strokes on a dark page) are analysed inverted
    dark = (0.114 * bgcol[0] + 0.587 * bgcol[1] + 0.299 * bgcol[2]) < 110

    def analyse(img):
        g = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        if dark:
            g = 255 - g
        g = cv2.GaussianBlur(g, (3, 3), 0)
        # no hysteresis on pictures we upscaled: interpolation halos would join
        return (g,) + ink_mask(g, hysteresis=s <= 1.0)

    gray, ink, strong = analyse(work)
    angle = estimate_skew(strong)
    if angle:
        h, w = gray.shape
        m = cv2.getRotationMatrix2D((w / 2.0, h / 2.0), angle, 1.0)
        work = cv2.warpAffine(work, m, (w, h), flags=cv2.INTER_LINEAR,
                              borderMode=cv2.BORDER_CONSTANT, borderValue=bgcol)
        gray, ink, strong = analyse(work)
    density = float(np.count_nonzero(ink)) / ink.size
    if density > MAX_INK_DENSITY:
        raise ImportFailed("The picture does not look like a line diagram (%d%% of it is ink); "
                           "photographs and dense screenshots cannot be recognised." % round(100 * density))
    stroke = stroke_width(ink)
    return Prep(src_w=w0, src_h=h0, scale=s, work=work, gray=gray, ink=ink, angle=angle,
                bg=bgcol, stroke=stroke, h=gray.shape[0], w=gray.shape[1], dark=dark,
                ink_density=density)


def stroke_width(ink) -> float:
    """Typical line width: the mode of short horizontal+vertical ink runs."""
    import numpy as np

    b = ink > 0
    counts = np.zeros(32, dtype=np.int64)
    for arr in (b, b.T):
        # subsample ROWS: runs are measured along each row, so columns must stay whole
        a = arr[::max(1, arr.shape[0] // 800)] if arr.shape[0] > 1600 else arr
        a = a.astype(np.int8)
        d = np.diff(np.pad(a, ((0, 0), (1, 1))), axis=1)
        starts = np.where(d == 1)
        ends = np.where(d == -1)
        lens = ends[1] - starts[1]
        lens = lens[(lens > 0) & (lens < 32)]
        counts += np.bincount(lens, minlength=32)[:32]
    if counts.sum() == 0:
        return 2.0
    return float(max(1, int(np.argmax(counts))))


# =================================================================== OCR

def run_ocr(prep: Prep, warn) -> list:
    """OCR lines on the working image: ``[{"text", "box", "confidence"}]``."""
    from .. import ocr

    ok, why = ocr.available()
    if not ok:
        warn("OCR is not available on this host (%s); text was not read." % why)
        return []
    import cv2

    img = 255 - prep.work if getattr(prep, "dark", False) else prep.work
    f = 1.0
    if prep.scale > 1.0:
        # small pictures: OCR reads the deskewed picture at its own resolution
        # (measured: upscaled JPEG artefacts cost more than they help), the
        # detector does its own resizing; boxes come back in working pixels
        img = cv2.resize(img, (prep.src_w, prep.src_h), interpolation=cv2.INTER_AREA)
        f = prep.scale
    lines = ocr.recognise(img)
    out = []
    for ln in lines:
        if ln["text"].strip():
            ln["box"] = [v * f for v in ln["box"]]
            out.append(ln)
    return out


# ================================================================ shapes

def _template(kind: str, w: int, h: int, param: float = 0.0):
    """Filled template mask (uint8 0/1) of a shape kind in a w x h box."""
    import cv2
    import numpy as np

    m = np.zeros((h, w), np.uint8)
    W, H = w - 1, h - 1
    if kind == "rect":
        m[:] = 1
    elif kind in ("round", "pill"):
        r = int(round(param))
        r = max(1, min(r, min(w, h) // 2))
        cv2.rectangle(m, (r, 0), (W - r, H), 1, -1)
        cv2.rectangle(m, (0, r), (W, H - r), 1, -1)
        for cx, cy in ((r, r), (W - r, r), (r, H - r), (W - r, H - r)):
            cv2.circle(m, (cx, cy), r, 1, -1)
    elif kind == "ellipse":
        cv2.ellipse(m, (int(round(W / 2.0)), int(round(H / 2.0))),
                    (max(1, int(round(W / 2.0))), max(1, int(round(H / 2.0)))), 0, 0, 360, 1, -1)
    else:
        pts = _template_points(kind, param)
        if pts is None:
            return None
        poly = np.array([[round(x * W), round(y * H)] for x, y in pts], np.int32)
        cv2.fillPoly(m, [poly], 1)
    return m


def _template_points(kind: str, param: float = 0.0):
    """Polygon of a template in 0..1 box coordinates."""
    q = param
    return {
        "diamond": [(0.5, 0), (1, 0.5), (0.5, 1), (0, 0.5)],
        "triangle": [(0.5, 0), (1, 1), (0, 1)],
        "triangle_down": [(0, 0), (1, 0), (0.5, 1)],
        "triangle_left": [(0, 0.5), (1, 0), (1, 1)],
        "triangle_right": [(0, 0), (1, 0.5), (0, 1)],
        "hexagon": [(0, 0.5), (q, 0), (1 - q, 0), (1, 0.5), (1 - q, 1), (q, 1)],
        "hexagon_v": [(0.5, 0), (1, q), (1, 1 - q), (0.5, 1), (0, 1 - q), (0, q)],
        "parallelogram": [(q, 0), (1, 0), (1 - q, 1), (0, 1)],
        "parallelogram_l": [(0, 0), (1 - q, 0), (1, 1), (q, 1)],
    }.get(kind)


def _iou(a, b) -> float:
    import numpy as np

    inter = np.count_nonzero(a & b)
    union = np.count_nonzero(a | b)
    return inter / float(union) if union else 0.0


def classify_mask(mask) -> tuple:
    """Best template for a filled shape mask (cropped to its bounding box).
    -> ``(kind, iou, param)`` where kind is one of rect, round, pill, ellipse,
    diamond, triangle*, hexagon*, parallelogram*."""
    import cv2
    import numpy as np

    h, w = mask.shape
    f = 96.0 / max(h, w)
    if f < 1.0:
        mask = cv2.resize(mask, (max(4, int(round(w * f))), max(4, int(round(h * f)))),
                          interpolation=cv2.INTER_NEAREST)
    else:
        f = 1.0
    h, w = mask.shape
    m = (mask > 0).astype(np.uint8)
    area = float(m.sum())
    best = ("rect", 0.0, 0.0)

    def consider(kind, param=0.0):
        nonlocal best
        t = _template(kind, w, h, param)
        if t is not None:
            v = _iou(m, t)
            if v > best[1]:
                best = (kind, v, param)

    consider("rect")
    rect_iou = best[1]
    deficit = max(0.0, w * h - area)
    r = math.sqrt(deficit / (4.0 - math.pi)) if deficit > 0 else 0.0
    if r >= 0.06 * min(w, h):
        for rr in (r * 0.85, r, r * 1.15):
            consider("round", min(rr, min(w, h) / 2.0))
    consider("pill", min(w, h) / 2.0)
    consider("ellipse")
    consider("diamond")
    for k in ("triangle", "triangle_down", "triangle_left", "triangle_right"):
        consider(k)
    for q in (0.12, 0.18, 0.24, 0.3):
        consider("hexagon", q)
        consider("hexagon_v", q)
    for q in (0.1, 0.15, 0.2, 0.25, 0.32):
        consider("parallelogram", q)
        consider("parallelogram_l", q)
    kind, v, param = best
    if kind.startswith(("parallelogram", "hexagon", "triangle", "diamond")) and rect_iou >= 0.85 \
            and v - rect_iou < SLANT_MARGIN:
        # blur, JPEG or scan softening of a rectangle's corners must not make
        # a slight-skew template win: slanted kinds need a clear margin
        kind, v, param = "rect", rect_iou, 0.0
    if kind == "round" and v - rect_iou < 0.004:
        kind, v, param = "rect", rect_iou, 0.0     # a corner radius too small to tell from blur
    if kind in ("round", "pill"):
        # fully rounded ends read as a pill / terminator
        kind = "pill" if param >= 0.38 * min(w, h) else "round"
        param = param / f
    return kind, v, param


def _contour_mask(contour, x, y, w, h):
    import cv2
    import numpy as np

    m = np.zeros((h, w), np.uint8)
    cv2.drawContours(m, [contour - [x, y]], -1, 1, -1)
    return m


def _outward_run(ink, contour, cx, cy, samples: int = 16, limit: int = 40) -> float:
    """Median ink run marching outward (away from the centre) from contour points:
    the outline's stroke width."""
    import numpy as np

    pts = contour.reshape(-1, 2)
    if len(pts) == 0:
        return 1.0
    h, w = ink.shape
    runs = []
    for i in np.linspace(0, len(pts) - 1, samples).astype(int):
        px, py = float(pts[i][0]), float(pts[i][1])
        dx, dy = px - cx, py - cy
        n = math.hypot(dx, dy) or 1.0
        dx, dy = dx / n, dy / n
        run = 0
        started = False
        for step in range(1, limit):
            x, y = int(round(px + dx * step)), int(round(py + dy * step))
            if not (0 <= x < w and 0 <= y < h):
                break
            if ink[y, x]:
                started = True
                run += 1
            elif started or step > 3:
                break
        if run:
            runs.append(run)
    if not runs:
        return 1.0
    # lower quartile: touching connectors and tangent lines only ever lengthen a run
    return float(sorted(runs)[len(runs) // 4])


class Shape:
    """A recognised geometric shape in working coordinates."""

    def __init__(self, **kw):
        self.texts: list = []
        self.children: list = []
        self.parent = None
        self.label_id = 0
        self.__dict__.update(kw)

    @property
    def box(self):
        e = self.stroke / 2.0
        return (self.hx - e, self.hy - e, self.hx + self.hw + e, self.hy + self.hh + e)


def _inside_any(box, boxes, pad=3.0) -> bool:
    x0, y0, x1, y1 = box
    for b in boxes:
        if x0 >= b[0] - pad and y0 >= b[1] - pad and x1 <= b[2] + pad and y1 <= b[3] + pad:
            return True
    return False


def detect_shapes(prep: Prep, text_boxes: list, warn) -> list:
    """Closed outlines -> :class:`Shape` list (working coordinates)."""
    import cv2
    import numpy as np

    ink = prep.ink
    H, W = ink.shape
    contours, hier = cv2.findContours(ink, cv2.RETR_CCOMP, cv2.CHAIN_APPROX_NONE)
    if hier is None:
        return []
    min_side = max(12, int(0.012 * min(H, W)))
    min_area = max(300.0, (0.02 * min(H, W)) ** 2)
    cands = []
    for i, c in enumerate(contours):
        if hier[0][i][3] == -1:
            continue
        x, y, w, h = cv2.boundingRect(c)
        if w < min_side or h < min_side:
            continue
        area = cv2.contourArea(c)
        if area < min_area or area > 0.9 * W * H:
            continue
        if _inside_any((x, y, x + w, y + h), text_boxes):
            continue
        cands.append((i, c, x, y, w, h, area))
        if len(cands) > MAX_CANDIDATE_HOLES:
            warn("The picture has too many closed regions to be a diagram; only the first %d were "
                 "examined." % MAX_CANDIDATE_HOLES)
            break
    # interior label map (bigger first so nested holes overwrite their parent)
    labels = np.zeros((H, W), np.int32)
    cands.sort(key=lambda t: -t[6])
    for k, (i, c, *_r) in enumerate(cands, start=1):
        cv2.drawContours(labels, [c], -1, k, -1)

    infos = []
    for k, (i, c, x, y, w, h, area) in enumerate(cands, start=1):
        hull = cv2.convexHull(c)
        solidity = area / max(cv2.contourArea(hull), 1.0)
        kind, iou, param = classify_mask(_contour_mask(c, x, y, w, h))
        cx, cy = x + w / 2.0, y + h / 2.0
        stroke = max(1.0, min(_outward_run(ink, c, cx, cy), 4 * prep.stroke + 4))
        infos.append(dict(k=k, c=c, x=x, y=y, w=w, h=h, area=area, solidity=solidity,
                          kind=kind, iou=iou, param=param, stroke=stroke))

    by_k = {d["k"]: d for d in infos}
    _merge_cylinders(infos, by_k)
    for d in infos:
        d["shape_like"] = d["kind"] == "cylinder" or (d["iou"] >= 0.86 and d["solidity"] >= 0.9)

    # Candidates that look like shapes; then iteratively drop the regions that
    # are enclosed by OTHER candidates' outlines and connector strokes (the
    # "loop" regions), worst first, re-measuring after every drop.
    alive = [d for d in infos if not d.get("merged") and d["shape_like"]]
    for d in alive:
        d["has_text"] = any(_own_text(d, tb) for tb in text_boxes)
    live = {d["k"]: d for d in alive}
    for d in alive:
        d["shared"], d["hits"] = _shared_border(d, labels, live)
    areas = sorted(d["area"] for d in alive)
    typical = areas[len(areas) // 2] if areas else 0.0

    def priority(d):
        # textless first; then the poorer fit, the more enclosed, the bigger
        return (not d["has_text"], d["shared"] + 3.0 * (1.0 - d["iou"])
                + 0.05 * min(10.0, d["area"] / max(typical, 1.0)))

    singles = 0
    while True:
        offenders = [d for d in live.values() if _enclosed_region(d, typical)]
        if not offenders:
            break
        if singles >= MAX_SINGLE_REMOVALS:
            for d in offenders:          # pathological picture: drop the rest at once
                live.pop(d["k"], None)
            break
        worst = max(offenders, key=priority)
        live.pop(worst["k"])
        singles += 1
        for d in live.values():          # only its neighbours need re-measuring
            if worst["k"] in d["hits"]:
                d["shared"], d["hits"] = _shared_border(d, labels, live)
    alive = [d for d in alive if d["k"] in live]
    shapes = []
    for d in alive:
        kind = d["kind"]
        shape, extra = _model_shape(kind, d)
        fit = max(0.0, min(1.0, (d["iou"] - 0.75) / 0.23))
        shapes.append(Shape(contour=d["c"], hx=float(d["x"]), hy=float(d["y"]),
                            hw=float(d["w"]), hh=float(d["h"]), kind=kind, shape=shape,
                            extra=extra, iou=d["iou"], fit=fit, stroke=d["stroke"],
                            label_id=d["k"], area=d["area"]))
    _nest(shapes)
    return shapes


def _enclosed_region(d: dict, typical: float) -> bool:
    """A hole bounded largely by other shapes' outlines is a region enclosed by
    connectors, not a shape -- unless it carries its own centred text and is
    of ordinary size (adjacent cells of a table, swimlane neighbours)."""
    if d["has_text"]:
        return d["shared"] >= 0.75 or (d["shared"] >= 0.25 and typical > 0 and d["area"] > 4 * typical)
    return d["shared"] >= 0.25


def _own_text(d: dict, tb) -> bool:
    """Text centred in the hole (central 60% of its box, inside its outline):
    a shape's own label, not a connector label that happens to sit in a loop."""
    import cv2

    cx, cy = (tb[0] + tb[2]) / 2.0, (tb[1] + tb[3]) / 2.0
    if not (d["x"] + 0.2 * d["w"] <= cx <= d["x"] + 0.8 * d["w"]
            and d["y"] + 0.2 * d["h"] <= cy <= d["y"] + 0.8 * d["h"]):
        return False
    return cv2.pointPolygonTest(d["c"], (float(cx), float(cy)), False) >= 0


def _model_shape(kind: str, d: dict) -> tuple:
    """Detector kind -> (model shape, extra element fields)."""
    if kind == "rect":
        return "rect", {}
    if kind == "round":
        return "round", {"rounded": True}
    if kind == "pill":
        return "pill", {"rounded": True}
    if kind == "ellipse":
        circle = abs(d["w"] - d["h"]) <= 0.08 * max(d["w"], d["h"])
        return "ellipse", {"detected": "circle" if circle else "ellipse"}
    if kind == "diamond":
        return "diamond", {}
    if kind == "cylinder":
        return "cylinder", {}
    if kind.startswith("hexagon"):
        return "hexagon", {"detected": kind}
    if kind.startswith("parallelogram"):
        return "parallelogram", {"detected": kind}
    if kind.startswith("triangle"):
        if kind == "triangle":
            return "triangle", {}
        pts = _template_points(kind)
        return "polygon", {"detected": kind, "points": [list(p) for p in pts]}
    return "rect", {}


def _merge_cylinders(infos: list, by_k: dict) -> None:
    """A flat ellipse whose lower half caps a body of the same width -> cylinder."""
    import cv2
    import numpy as np

    for e in infos:
        if e["kind"] != "ellipse" or e["iou"] < 0.85 or e["w"] < 2.0 * e["h"] or e.get("merged"):
            continue
        tol = 0.08 * e["w"] + 2 * e["stroke"]
        for b in infos:
            if b is e or b.get("merged") or b["kind"] == "cylinder":
                continue
            if abs(b["x"] - e["x"]) > tol or abs((b["x"] + b["w"]) - (e["x"] + e["w"])) > tol:
                continue
            if not (e["y"] + 0.3 * e["h"] <= b["y"] <= e["y"] + e["h"] + 3 * e["stroke"] + 2):
                continue
            if b["h"] < 0.5 * e["h"] or b["solidity"] < 0.8:
                continue
            x0, y0 = min(e["x"], b["x"]), e["y"]
            x1, y1 = max(e["x"] + e["w"], b["x"] + b["w"]), b["y"] + b["h"]
            fill_ratio = (e["area"] + b["area"]) / float((x1 - x0) * (y1 - y0))
            if fill_ratio < 0.75:
                continue
            b["merged"] = True
            hull = cv2.convexHull(np.concatenate([e["c"], b["c"]]))
            e.update(kind="cylinder", x=x0, y=y0, w=x1 - x0, h=y1 - y0, c=hull,
                     area=e["area"] + b["area"], iou=min(e["iou"], 0.97),
                     body=b["k"], solidity=1.0)
            break


def _shared_border(d: dict, labels, by_k: dict) -> tuple:
    """Fraction of the outline whose far side is the interior of another live
    candidate that does not enclose this one -> ``(fraction, {labels hit})``."""
    import numpy as np

    H, W = labels.shape
    pts = d["c"].reshape(-1, 2)
    if len(pts) < 8:
        return 0.0, set()
    cx, cy = d["x"] + d["w"] / 2.0, d["y"] + d["h"] / 2.0
    step = d["stroke"] + 3.0
    hits = total = 0
    seen = set()
    own = {d["k"], d.get("body")}
    for i in np.linspace(0, len(pts) - 1, 48).astype(int):
        p0 = pts[max(0, i - 3)]
        p1 = pts[min(len(pts) - 1, i + 3)]
        tx, ty = float(p1[0] - p0[0]), float(p1[1] - p0[1])
        n = math.hypot(tx, ty)
        if n == 0:
            continue
        nx, ny = ty / n, -tx / n
        px, py = float(pts[i][0]), float(pts[i][1])
        if (px + nx - cx) * nx + (py + ny - cy) * ny < 0:   # make the normal point outward
            nx, ny = -nx, -ny
        qx, qy = int(round(px + nx * step)), int(round(py + ny * step))
        total += 1
        if not (0 <= qx < W and 0 <= qy < H):
            continue
        lab = int(labels[qy, qx])
        if lab == 0 or lab in own:
            continue
        o = by_k.get(lab)
        if o is None:
            continue    # not a live candidate (junk region, refused loop)
        encloses = (o["x"] <= d["x"] and o["y"] <= d["y"] and o["x"] + o["w"] >= d["x"] + d["w"]
                    and o["y"] + o["h"] >= d["y"] + d["h"])
        if not encloses:
            hits += 1
            seen.add(lab)
    return (hits / float(total) if total else 0.0), seen


def _nest(shapes: list) -> None:
    """Shapes fully inside another accepted shape become its children."""
    order = sorted(shapes, key=lambda s: s.hw * s.hh)
    for i, s in enumerate(order):
        for big in order[i + 1:]:
            if (big.hx <= s.hx and big.hy <= s.hy and big.hx + big.hw >= s.hx + s.hw
                    and big.hy + big.hh >= s.hy + s.hh):
                s.parent = big
                big.children.append(s)
                break


# ============================================================ arrowheads

class Arrowhead:
    def __init__(self, **kw):
        self.used = False
        self.__dict__.update(kw)


def detect_arrowheads(prep: Prep, shapes: list, text_boxes: list, mask=None, st=None) -> list:
    """Solid triangles (and diamonds) that survive a morphological opening.

    The opening runs on the CONNECTOR ink only (*mask*: ink minus shape
    outlines, interiors and text, see :func:`extract_line_mask`) with a disc
    just wider than the connector stroke *st*: thick shape outlines and the
    joints where a line leaves an outline can no longer pass for heads, and
    the narrow heads of thin diagonal arrows are not eroded away."""
    import cv2
    import numpy as np

    if mask is None:
        mask = extract_line_mask(prep, shapes, text_boxes, [])
    if st is None:
        st = connector_stroke(mask, prep.stroke)
    # opening by a disc of radius r (any real r): keep the discs that fit in
    # the ink, i.e. dilate the pixels at least r from the background. r is
    # just over half the connector width, so lines vanish and heads stay.
    r = max(2.0, 0.5 * st + 0.9)
    dt = cv2.distanceTransform((mask > 0).astype(np.uint8), cv2.DIST_L2, 5)
    core = (dt >= r).astype(np.uint8)
    d = 2 * int(round(r)) + 1
    opened = cv2.dilate(core, cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (d, d))) & (mask > 0)
    opened = opened.astype(np.uint8) * 255
    k = 2 * r + 1
    contours, _ = cv2.findContours(opened, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    # a head is several discs big; a lone disc is a bulge of a noisy line
    lo, hi = 2.2 * math.pi * r * r, (9.0 * k) ** 2
    heads = []
    for c in contours:
        area = cv2.contourArea(c)
        if not lo <= area <= hi:
            continue
        x, y, w, h = cv2.boundingRect(c)
        if _inside_any((x, y, x + w, y + h), text_boxes, pad=2):
            continue
        cx, cy = x + w / 2.0, y + h / 2.0
        if any(s.hx < cx < s.hx + s.hw and s.hy < cy < s.hy + s.hh
               and cv2.pointPolygonTest(s.contour, (cx, cy), True) > s.stroke + 2 for s in shapes):
            continue          # solid marks inside a shape (bullets, icons) are not arrowheads
        tri_area, tri = cv2.minEnclosingTriangle(c.astype(np.float32))
        if tri is None or tri_area <= 0:
            continue
        tri = tri.reshape(3, 2)
        if area / tri_area >= 0.6:
            # apex direction: where the blob's mass has its long tail (maximum
            # third central moment over all directions). An arrowhead narrower
            # than equilateral has a single maximum, at its apex; it uses every
            # pixel, so a blunted or blurred tip does not mislead it.
            gx, gy = _centroid(c)
            ux, uy = _skew_direction(c, x, y, w, h)
            far = max(c.reshape(-1, 2).astype(np.float64), key=lambda q: (q[0] - gx) * ux + (q[1] - gy) * uy)
            n = max(1.0, (far[0] - gx) * ux + (far[1] - gy) * uy)
            v = np.array([ux * n, uy * n])
            apex = np.array([gx, gy]) + v
            base = np.array([gx, gy]) - v * 0.5         # centroid is 1/3 of the length from the base
            heads.append(Arrowhead(kind="arrow", tip=(float(apex[0]), float(apex[1])),
                                   base=(float(base[0]), float(base[1])),
                                   dir=(float(v[0] / n), float(v[1] / n)), length=1.5 * n,
                                   box=(x, y, x + w, y + h), contour=c, centroid=_centroid(c),
                                   clipped=_clipped(c, prep.ink, mask, r)))
            continue
        approx = cv2.approxPolyDP(c, 0.08 * cv2.arcLength(c, True), True)
        if len(approx) == 4 and area / max(cv2.contourArea(cv2.convexHull(c)), 1) > 0.9:
            rect = cv2.minAreaRect(c)
            (rw, rh) = rect[1]
            if min(rw, rh) > 0 and 1.4 <= max(rw, rh) / min(rw, rh) <= 3.5:
                pts = approx.reshape(4, 2).astype(np.float32)
                d02 = np.linalg.norm(pts[0] - pts[2])
                d13 = np.linalg.norm(pts[1] - pts[3])
                a, b = (pts[0], pts[2]) if d02 >= d13 else (pts[1], pts[3])
                v = b - a
                n = float(np.linalg.norm(v)) or 1.0
                heads.append(Arrowhead(kind="diamond", tip=(float(b[0]), float(b[1])),
                                       base=(float(a[0]), float(a[1])), dir=(float(v[0] / n), float(v[1] / n)),
                                       length=n, box=(x, y, x + w, y + h), contour=c, axis=True,
                                       centroid=_centroid(c)))
    return heads


def _clipped(c, ink, mask, r) -> bool:
    """True when the head touches ink that the line mask removed (a shape's
    outline band): its tip was cut off, so its own shape no longer tells its
    direction reliably."""
    import cv2
    import numpy as np

    x, y, w, h = cv2.boundingRect(c)
    p = int(r) + 3
    H, W = ink.shape
    X0, Y0, X1, Y1 = max(0, x - p), max(0, y - p), min(W, x + w + p), min(H, y + h + p)
    m = np.zeros((Y1 - Y0, X1 - X0), np.uint8)
    cv2.drawContours(m, [c - [X0, Y0]], -1, 1, -1)
    m = cv2.dilate(m, np.ones((5, 5), np.uint8))
    removed = (ink[Y0:Y1, X0:X1] > 0) & (mask[Y0:Y1, X0:X1] == 0)
    return int(np.count_nonzero(removed & (m > 0))) >= max(3, int(r))


def _skew_direction(c, x, y, w, h) -> tuple:
    """Unit direction of maximal third central moment of the filled contour."""
    import cv2
    import numpy as np

    m = np.zeros((h, w), np.uint8)
    cv2.drawContours(m, [c - [x, y]], -1, 1, -1)
    ys, xs = np.nonzero(m)
    if len(xs) < 3:
        return 1.0, 0.0
    X = xs - xs.mean()
    Y = ys - ys.mean()
    sxxx, sxxy, sxyy, syyy = (X ** 3).sum(), (X * X * Y).sum(), (X * Y * Y).sum(), (Y ** 3).sum()
    th = np.radians(np.arange(0, 360, 2.0))
    co, si = np.cos(th), np.sin(th)
    m3 = co ** 3 * sxxx + 3 * co * co * si * sxxy + 3 * co * si * si * sxyy + si ** 3 * syyy
    k = int(np.argmax(m3))
    return float(co[k]), float(si[k])


def connector_stroke(line_mask, default: float) -> float:
    """Typical connector width, measured on the connector ink alone (shape
    outlines are often drawn thicker than the lines between them)."""
    import numpy as np

    if int(np.count_nonzero(line_mask)) < 200:
        return default
    return stroke_width(line_mask)


def _centroid(c) -> tuple:
    import cv2

    m = cv2.moments(c)
    if m["m00"]:
        return (m["m10"] / m["m00"], m["m01"] / m["m00"])
    x, y, w, h = cv2.boundingRect(c)
    return (x + w / 2.0, y + h / 2.0)


# ============================================================ line mask

def extract_line_mask(prep: Prep, shapes: list, text_boxes: list, heads: list):
    """Ink minus shape outlines/interiors, text glyphs and arrowheads."""
    import cv2
    import numpy as np

    line = prep.ink.copy()
    for s in shapes:
        cv2.drawContours(line, [s.contour], -1, 0, -1)
        t = int(round(2 * (s.stroke + 2))) + 1
        cv2.drawContours(line, [s.contour], -1, 0, t)
    for hd in heads:
        cv2.drawContours(line, [hd.contour], -1, 0, -1)
        cv2.drawContours(line, [hd.contour], -1, 0, int(prep.stroke) + 3)
    if text_boxes:
        n, lab, stats, _ = cv2.connectedComponentsWithStats(line, connectivity=8)
        kill = np.zeros(n, bool)
        for j in range(1, n):
            x, y, w, h, _a = stats[j]
            if _inside_any((x, y, x + w, y + h), text_boxes, pad=3):
                kill[j] = True
        line[kill[lab]] = 0
    return line


def erase_heads(line_mask, heads: list, st: float):
    import cv2

    out = line_mask.copy()
    for hd in heads:
        cv2.drawContours(out, [hd.contour], -1, 0, -1)
        cv2.drawContours(out, [hd.contour], -1, 0, int(st) + 3)
    return out


# ================================================================ skeleton

def thin(mask):
    """Zhang-Suen thinning (vectorised): binary mask -> one-pixel skeleton (0/1)."""
    import numpy as np

    ys, xs = np.nonzero(mask)
    out = np.zeros(mask.shape, np.uint8)
    if len(ys) == 0:
        return out
    y0, y1, x0, x1 = ys.min(), ys.max() + 1, xs.min(), xs.max() + 1
    img = np.pad((mask[y0:y1, x0:x1] > 0).astype(np.uint8), 1)
    for _ in range(200):
        changed = False
        for step in (0, 1):
            p2, p3, p4 = img[:-2, 1:-1], img[:-2, 2:], img[1:-1, 2:]
            p5, p6, p7 = img[2:, 2:], img[2:, 1:-1], img[2:, :-2]
            p8, p9 = img[1:-1, :-2], img[:-2, :-2]
            c = img[1:-1, 1:-1]
            b = p2 + p3 + p4 + p5 + p6 + p7 + p8 + p9
            seq = (p2, p3, p4, p5, p6, p7, p8, p9, p2)
            a = np.zeros_like(b)
            for i in range(8):
                a += (seq[i] == 0) & (seq[i + 1] == 1)
            if step == 0:
                m = ((p2 & p4 & p6) == 0) & ((p4 & p6 & p8) == 0)
            else:
                m = ((p2 & p4 & p8) == 0) & ((p2 & p6 & p8) == 0)
            rem = (c == 1) & (b >= 2) & (b <= 6) & (a == 1) & m
            if rem.any():
                c[rem] = 0
                changed = True
        if not changed:
            break
    out[y0:y1, x0:x1] = img[1:-1, 1:-1]
    return out


_NB = ((-1, 0), (0, 1), (1, 0), (0, -1), (-1, 1), (1, 1), (1, -1), (-1, -1))   # 4-neighbours first


class Graph:
    """Skeleton graph: nodes (endpoints, junction clusters) and pixel-path edges."""

    def __init__(self):
        self.nodes: dict = {}      # id -> {"kind": "end"|"junction", "pt": (x, y), "edges": [eid]}
        self.edges: dict = {}      # id -> {"a": nid, "b": nid, "path": [(x, y), ...]}
        self.next_edge = 0


def skeleton_graph(skel) -> Graph:
    """One-pixel skeleton -> :class:`Graph`. Endpoints have one neighbour (or a
    crossing number of 1); junction pixels a crossing number >= 3, and adjacent
    junction pixels form one node."""
    import cv2
    import numpy as np

    sk = (skel > 0).astype(np.uint8)
    kernel = np.ones((3, 3), np.float32)
    kernel[1, 1] = 0
    deg = cv2.filter2D(sk, cv2.CV_16S, kernel, borderType=cv2.BORDER_CONSTANT) * sk
    p = np.pad(sk, 1)
    ring = [p[:-2, 1:-1], p[:-2, 2:], p[1:-1, 2:], p[2:, 2:], p[2:, 1:-1], p[2:, :-2], p[1:-1, :-2], p[:-2, :-2]]
    cross = np.zeros(sk.shape, np.int16)
    for i in range(8):
        cross += ((ring[i] == 0) & (ring[(i + 1) % 8] == 1))
    cross *= sk
    junction = (sk == 1) & (cross >= 3)
    endpoint = (sk == 1) & ~junction & ((deg == 1) | ((cross == 1) & (deg <= 2)))

    g = Graph()
    node_of = -np.ones(sk.shape, np.int32)
    node_pix: dict = {}
    nj, jl = cv2.connectedComponents(junction.astype(np.uint8), connectivity=8)
    groups: dict = {}
    ys, xs = np.nonzero(junction)
    for y, x in zip(ys.tolist(), xs.tolist()):
        groups.setdefault(int(jl[y, x]), []).append((y, x))
    for j in sorted(groups):
        pix = groups[j]
        nid = len(g.nodes)
        g.nodes[nid] = {"kind": "junction", "edges": [],
                        "pt": (sum(x for _, x in pix) / len(pix), sum(y for y, _ in pix) / len(pix))}
        for y, x in pix:
            node_of[y, x] = nid
        node_pix[nid] = pix
    ys, xs = np.nonzero(endpoint)
    for y, x in zip(ys.tolist(), xs.tolist()):
        nid = len(g.nodes)
        g.nodes[nid] = {"kind": "end", "pt": (float(x), float(y)), "edges": []}
        node_of[y, x] = nid
        node_pix[nid] = [(y, x)]

    H, W = sk.shape
    visited = np.zeros(sk.shape, bool)

    def walk(y, x, start):
        """Follow plain skeleton pixels from (y, x) until a node is reached."""
        path = [(x, y)]
        visited[y, x] = True
        prev = None
        while True:
            hit = -1
            nxt = None
            for dy, dx in _NB:
                ny, nx = y + dy, x + dx
                if not (0 <= ny < H and 0 <= nx < W) or not sk[ny, nx] or (ny, nx) == prev:
                    continue
                nid = int(node_of[ny, nx])
                if nid >= 0:
                    if nid != start or len(path) > 2:
                        hit = nid
                        break
                    continue
                if nxt is None and not visited[ny, nx]:
                    nxt = (ny, nx)
            if hit >= 0:
                return path, hit
            if nxt is None:
                return path, -1
            prev = (y, x)
            y, x = nxt
            visited[y, x] = True
            path.append((x, y))

    extra = 1_000_000
    for nid in list(g.nodes):
        nd = g.nodes[nid]
        for y0, x0 in node_pix.get(nid, []):
            for dy, dx in _NB:
                y, x = y0 + dy, x0 + dx
                if not (0 <= y < H and 0 <= x < W) or not sk[y, x] or visited[y, x]:
                    continue
                other = int(node_of[y, x])
                if other >= 0:
                    if other != nid and not _has_edge(g, nid, other):
                        _add_edge(g, nid, other, [nd["pt"], g.nodes[other]["pt"]])
                    continue
                path, end = walk(y, x, nid)
                full = [nd["pt"]] + [(float(a), float(b)) for a, b in path]
                if end >= 0:
                    full.append(g.nodes[end]["pt"])
                    _add_edge(g, nid, end, full)
                else:
                    extra += 1
                    g.nodes[extra] = {"kind": "end", "pt": full[-1], "edges": []}
                    _add_edge(g, nid, extra, full)
    return g


def _has_edge(g: Graph, a: int, b: int) -> bool:
    return any({g.edges[e]["a"], g.edges[e]["b"]} == {a, b} for e in g.nodes[a]["edges"])


def _add_edge(g: Graph, a: int, b: int, path: list) -> None:
    eid = g.next_edge
    g.next_edge += 1
    g.edges[eid] = {"a": a, "b": b, "path": path}
    g.nodes[a]["edges"].append(eid)
    if b != a:
        g.nodes[b]["edges"].append(eid)


def _path_len(path) -> float:
    return sum(math.hypot(path[i][0] - path[i - 1][0], path[i][1] - path[i - 1][1])
               for i in range(1, len(path)))


def prune_spurs(g: Graph, min_len: float) -> None:
    """Drop short endpoint-to-junction branches (glyph remnants, stroke burrs)."""
    for _ in range(3):
        removed = False
        for eid in list(g.edges):
            e = g.edges.get(eid)
            if e is None:
                continue
            na, nb = g.nodes[e["a"]], g.nodes[e["b"]]
            kinds = (na["kind"], nb["kind"])
            if "end" in kinds and "junction" in kinds and _path_len(e["path"]) < min_len:
                j = e["a"] if na["kind"] == "junction" else e["b"]
                if len(g.nodes[j]["edges"]) >= 3:
                    end = e["b"] if j == e["a"] else e["a"]
                    _drop_edge(g, eid)
                    g.nodes.pop(end, None)
                    removed = True
        for nid in list(g.nodes):
            nd = g.nodes.get(nid)
            if nd and nd["kind"] == "junction" and len(nd["edges"]) == 2:
                _splice(g, nid)
        if not removed:
            break


def _drop_edge(g: Graph, eid: int) -> None:
    e = g.edges.pop(eid)
    for n in (e["a"], e["b"]):
        if n in g.nodes and eid in g.nodes[n]["edges"]:
            g.nodes[n]["edges"].remove(eid)


def _splice(g: Graph, nid: int) -> None:
    """Merge the two edges of a degree-2 junction into one."""
    e1, e2 = g.nodes[nid]["edges"]
    if e1 == e2:
        return
    a, b = g.edges[e1], g.edges[e2]
    pa = a["path"] if a["b"] == nid else list(reversed(a["path"]))
    pb = b["path"] if b["a"] == nid else list(reversed(b["path"]))
    oa = a["a"] if a["b"] == nid else a["b"]
    ob = b["b"] if b["a"] == nid else b["a"]
    if nid in (oa, ob) or oa not in g.nodes or ob not in g.nodes:
        return   # part of a closed loop: leave it
    _drop_edge(g, e1)
    _drop_edge(g, e2)
    g.nodes.pop(nid, None)
    _add_edge(g, oa, ob, pa + pb[1:])


def _dir_at(path, from_start: bool, span: float):
    """Unit direction of a path near one end, pointing INTO the path."""
    pts = path if from_start else list(reversed(path))
    x0, y0 = pts[0]
    acc = 0.0
    xe, ye = pts[-1]
    for i in range(1, len(pts)):
        acc += math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1])
        if acc >= span:
            xe, ye = pts[i]
            break
    dx, dy = xe - x0, ye - y0
    n = math.hypot(dx, dy) or 1.0
    return dx / n, dy / n


def trace_paths(g: Graph, span: float) -> list:
    """Endpoint-to-endpoint pixel paths, going straight through junctions."""
    paths = []
    used_end: set = set()
    used_edge: set = set()
    for nid in sorted(g.nodes, key=lambda n: g.nodes[n]["pt"]):
        nd = g.nodes[nid]
        if nd["kind"] != "end" or nid in used_end or not nd["edges"]:
            continue
        cur, path, seen = nid, [], set()
        eid = nd["edges"][0]
        while True:
            e = g.edges[eid]
            seen.add(eid)
            used_edge.add(eid)
            seg = e["path"] if e["a"] == cur else list(reversed(e["path"]))
            path.extend(seg if not path else seg[1:])
            cur = e["b"] if e["a"] == cur else e["a"]
            node = g.nodes[cur]
            if node["kind"] == "end" or len(seen) > 64:
                break
            inc = _dir_at(seg, False, span)          # pointing back along where we came from
            best, best_score = None, None
            for oe in node["edges"]:
                if oe in seen:
                    continue
                o = g.edges[oe]
                oseg = o["path"] if o["a"] == cur else list(reversed(o["path"]))
                out = _dir_at(oseg, True, span)
                straight = -(inc[0] * out[0] + inc[1] * out[1])   # 1 = straight on
                score = straight + (0.0 if oe not in used_edge else -0.6)
                if best_score is None or score > best_score:
                    best, best_score = oe, score
            if best is None:
                break
            eid = best
        used_end.add(nid)
        if g.nodes[cur]["kind"] == "end":
            used_end.add(cur)
        if len(path) >= 2:
            paths.append(path)
    # closed loops of edges without endpoints are not connectors
    return paths


# ============================================================ polylines

def simplify(path, eps: float) -> list:
    import cv2
    import numpy as np

    if len(path) < 3:
        return [list(p) for p in path]
    arr = np.array(path, np.float32).reshape(-1, 1, 2)
    ap = cv2.approxPolyDP(arr, eps, False).reshape(-1, 2)
    return [[float(x), float(y)] for x, y in ap]


def orthogonalise(pts: list, tol_deg: float = 5.0) -> tuple:
    """Snap near-horizontal/vertical segments exactly onto the axes, merging
    runs of segments with the same orientation. -> (points, all_axis_aligned)."""
    pts = [[float(p[0]), float(p[1])] for p in pts]
    # drop zero-length steps
    clean = [pts[0]] if pts else []
    for p in pts[1:]:
        if math.hypot(p[0] - clean[-1][0], p[1] - clean[-1][1]) > 0.5:
            clean.append(p)
    pts = clean
    if len(pts) < 2:
        return pts, False
    # drop points where the polyline barely turns (< 4 degrees)
    keep = [pts[0]]
    for i in range(1, len(pts) - 1):
        a, b, c = keep[-1], pts[i], pts[i + 1]
        t1 = math.atan2(b[1] - a[1], b[0] - a[0])
        t2 = math.atan2(c[1] - b[1], c[0] - b[0])
        turn = abs((math.degrees(t2 - t1) + 180.0) % 360.0 - 180.0)
        if turn >= 4.0:
            keep.append(b)
    keep.append(pts[-1])
    pts = keep

    def orient(a, b):
        ang = abs(math.degrees(math.atan2(b[1] - a[1], b[0] - a[0]))) % 180
        if min(ang, 180 - ang) <= tol_deg:
            return "h"
        if abs(ang - 90) <= tol_deg:
            return "v"
        return "o"

    # merge consecutive H/H or V/V segments (drop the shared point)
    merged = [pts[0]]
    for i in range(1, len(pts)):
        if len(merged) >= 2 and i < len(pts):
            o1 = orient(merged[-2], merged[-1])
            o2 = orient(merged[-1], pts[i])
            if o1 == o2 and o1 != "o":
                merged[-1] = pts[i]
                continue
        merged.append(pts[i])
    pts = merged
    segs = [orient(pts[i - 1], pts[i]) for i in range(1, len(pts))]
    lines = []
    for i, o in enumerate(segs):
        a, b = pts[i], pts[i + 1]
        lines.append((o, (a[1] + b[1]) / 2.0 if o == "h" else (a[0] + b[0]) / 2.0 if o == "v" else None))
    out = []
    for i, p in enumerate(pts):
        x, y = p
        for j in (i - 1, i):
            if 0 <= j < len(lines):
                o, v = lines[j]
                if o == "h":
                    y = v
                elif o == "v":
                    x = v
        out.append([round(x, 2), round(y, 2)])
    return out, all(o != "o" for o in segs)


class Conn:
    def __init__(self, pts, **kw):
        self.pts = pts
        self.arrows = ["none", "none"]
        self.ends = [None, None]          # attached Shape per end
        self.quality = [0.0, 0.0]
        self.gaps = 0
        self.label_ids: list = []
        self.dashed = False
        self.head_agree = [True, True]
        self.blob_end = [False, False]    # solid blob at an end without a head
        self.__dict__.update(kw)

    def end_dir(self, i: int):
        """Unit vector pointing OUT of the connector at end i."""
        if i == 0:
            a, b = self.pts[1], self.pts[0]
        else:
            a, b = self.pts[-2], self.pts[-1]
        dx, dy = b[0] - a[0], b[1] - a[1]
        n = math.hypot(dx, dy) or 1.0
        return dx / n, dy / n

    def length(self) -> float:
        return _path_len(self.pts)


def trace_connectors(prep: Prep, line_mask, warn=None) -> list:
    """Line mask -> :class:`Conn` polylines (working coordinates). Short pieces
    are kept: :func:`bridge_gaps` may chain them into a dashed connector, and
    whatever stays short and unbound is dropped as noise afterwards."""
    import numpy as np

    st = prep.stroke
    skel = thin(line_mask)
    if int(np.count_nonzero(skel)) > MAX_SKELETON_PX:
        if warn:
            warn("Too many strokes to trace connectors; only shapes and text were recognised.")
        return []
    g = skeleton_graph(skel)
    prune_spurs(g, max(10.0, 3.0 * st + 4))
    span = max(8.0, 4 * st)
    paths = trace_paths(g, span)
    min_len = max(6.0, 2 * st)
    conns = []
    for p in paths:
        if _path_len(p) < min_len:
            continue
        pts = simplify(p, max(2.0, 0.9 * st))
        pts, _ = orthogonalise(pts)
        if len(pts) >= 2:
            conns.append(Conn(pts))
    return conns


class _End:
    __slots__ = ("conn", "side", "pt", "dir", "used")

    def __init__(self, conn, side):
        self.conn, self.side = conn, side
        self.pt = conn.pts[0] if side == 0 else conn.pts[-1]
        self.dir = conn.end_dir(side)
        self.used = False


def bridge_gaps(conns: list, text_boxes: list, st: float) -> list:
    """Join collinear pieces that face each other across a small gap (dashes)
    or across a text label sitting on the line. Candidate pairs are found once
    (sorted sweep), then merged greedily, shortest gap first."""
    import bisect

    dash_gap = max(8 * st, 24.0)
    tb_reach = max([(tb[2] - tb[0]) + (tb[3] - tb[1]) for tb in text_boxes] or [0.0]) + 6 * st
    reach = max(dash_gap, tb_reach)
    ends = [_End(c, i) for c in conns for i in (0, 1)
            if c.ends[i] is None and c.arrows[i] == "none" and len(c.pts) >= 2]
    ends.sort(key=lambda e: e.pt[0])
    xs = [e.pt[0] for e in ends]
    cands = []
    for ia, ea in enumerate(ends):
        lo = bisect.bisect_left(xs, ea.pt[0] - reach)
        hi = bisect.bisect_right(xs, ea.pt[0] + reach)
        for ib in range(lo, hi):
            if ib <= ia:
                continue
            eb = ends[ib]
            if eb.conn is ea.conn:
                continue
            gx, gy = eb.pt[0] - ea.pt[0], eb.pt[1] - ea.pt[1]
            dist = math.hypot(gx, gy)
            if dist < 1e-6 or dist > reach:
                continue
            ux, uy = gx / dist, gy / dist
            # the pieces must point at each other and lie on one line: the far
            # end within a stroke or two of the near end's axis (a gap of a few
            # pixels has no reliable direction of its own)
            lateral = abs(gx * ea.dir[1] - gy * ea.dir[0])
            if ea.dir[0] * eb.dir[0] + ea.dir[1] * eb.dir[1] > -0.95 or \
                    gx * ea.dir[0] + gy * ea.dir[1] < -st or \
                    lateral > max(2.0, 1.5 * st) + 0.03 * dist:
                continue
            if dist > 3 * st and (ea.dir[0] * ux + ea.dir[1] * uy < 0.97 or -(eb.dir[0] * ux + eb.dir[1] * uy) < 0.97):
                continue
            lab = None
            if dist > dash_gap:
                mx, my = (ea.pt[0] + eb.pt[0]) / 2.0, (ea.pt[1] + eb.pt[1]) / 2.0
                for k, tb in enumerate(text_boxes):
                    if tb[0] - 4 <= mx <= tb[2] + 4 and tb[1] - 4 <= my <= tb[3] + 4 and \
                            dist <= (tb[2] - tb[0]) + (tb[3] - tb[1]) + 6 * st:
                        lab = k
                        break
                if lab is None:
                    continue
            cands.append((dist, ea, eb, lab))
    cands.sort(key=lambda t: t[0])
    owner = {}          # id(_End) -> (current Conn, side)
    for e in ends:
        owner[id(e)] = (e.conn, e.side)
    alive = {id(c): c for c in conns}
    for dist, ea, eb, lab in cands:
        if ea.used or eb.used:
            continue
        ca, sa = owner[id(ea)]
        cb, sb = owner[id(eb)]
        if ca is cb:
            continue                     # would close a ring
        pa = ca.pts if sa == 1 else list(reversed(ca.pts))
        pb = cb.pts if sb == 0 else list(reversed(cb.pts))
        merged = Conn(orthogonalise(pa + pb)[0])
        merged.arrows = [ca.arrows[1 - sa], cb.arrows[1 - sb]]
        merged.ends = [ca.ends[1 - sa], cb.ends[1 - sb]]
        merged.quality = [ca.quality[1 - sa], cb.quality[1 - sb]]
        merged.head_agree = [ca.head_agree[1 - sa], cb.head_agree[1 - sb]]
        merged.gaps = ca.gaps + cb.gaps + 1
        merged.dash_gaps = getattr(ca, "dash_gaps", 0) + getattr(cb, "dash_gaps", 0) + (lab is None)
        merged.label_ids = ca.label_ids + cb.label_ids + ([lab] if lab is not None else [])
        ea.used = eb.used = True
        alive.pop(id(ca), None)
        alive.pop(id(cb), None)
        alive[id(merged)] = merged
        # the two outer ends now belong to the merged connector
        for e in ends:
            if e.used:
                continue
            c, side = owner[id(e)]
            if c is ca:
                owner[id(e)] = (merged, 0 if side == 1 - sa else 1)
            elif c is cb:
                owner[id(e)] = (merged, 1 if side == 1 - sb else 0)
    out = list(alive.values())
    for c in out:
        c.dashed = getattr(c, "dash_gaps", 0) >= 2
    return out


# ============================================================ attachment

def bind_arrowheads(conns: list, heads: list, st: float, ink=None) -> None:
    """Give connector ends the arrowheads they run into, and move each such end
    to the head's tip.

    A head belongs to the end it lies IN FRONT OF: its centroid is beyond the
    end along the line's outward direction and close to the line's axis. That
    position fixes the arrow's direction; the triangle's own apex (measured in
    detect_arrowheads) is a cross-check -- the morphological opening blunts the
    apex of small or blurred heads -- and a disagreement lowers confidence."""
    import bisect

    ends = [((c.pts[0] if i == 0 else c.pts[-1]), i, c, c.end_dir(i)) for c in conns for i in (0, 1)]
    ends.sort(key=lambda t: t[0][0])
    xs = [e[0][0] for e in ends]
    pairs = []
    for hi, hd in enumerate(heads):
        gx, gy = hd.centroid
        x0, y0, x1, y1 = hd.box
        size = max(x1 - x0, y1 - y0)
        reach = size + 3 * st + 8
        lo = bisect.bisect_left(xs, gx - reach)
        up = bisect.bisect_right(xs, gx + reach)
        for p, i, c, od in ends[lo:up]:
            vx, vy = gx - p[0], gy - p[1]
            fwd = vx * od[0] + vy * od[1]
            lat = abs(vx * od[1] - vy * od[0])
            if fwd <= 0 or fwd > reach or lat > 0.6 * size + st:
                continue
            pairs.append((fwd + 2.0 * lat, hi, c, i))
    pairs.sort(key=lambda t: t[0])
    taken_heads, taken_ends = set(), set()
    for _score, hi, c, i in pairs:
        if hi in taken_heads or (id(c), i) in taken_ends:
            continue
        taken_heads.add(hi)
        taken_ends.add((id(c), i))
        hd = heads[hi]
        hd.used = True
        c.arrows[i] = hd.kind
        p = c.pts[0] if i == 0 else c.pts[-1]
        od = c.end_dir(i)
        pts = hd.contour.reshape(-1, 2)
        far = max(float((q[0] - p[0]) * od[0] + (q[1] - p[1]) * od[1]) for q in pts)
        tip = [p[0] + od[0] * far, p[1] + od[1] * far]
        if ink is not None:
            # the opening blunted the apex: follow the original ink a little further
            h, w = ink.shape
            for _ in range(int(2 * st + 6)):
                nx, ny = tip[0] + od[0], tip[1] + od[1]
                xi, yi = int(round(nx)), int(round(ny))
                if not (0 <= xi < w and 0 <= yi < h) or not ink[yi, xi]:
                    break
                tip = [nx, ny]
        if hd.kind == "arrow" and not getattr(hd, "clipped", False):
            # cross-check with the head's own apex -- unless its tip was cut off
            # at a shape outline, where it no longer shows a reliable apex
            c.head_agree[i] = (hd.dir[0] * od[0] + hd.dir[1] * od[1]) > 0.3
        if i == 0:
            c.pts.insert(0, tip)
        else:
            c.pts.append(tip)
        c.pts = orthogonalise(c.pts)[0]


def flag_unexplained_blobs(conns: list, line_mask, st: float) -> None:
    """Mark ends WITHOUT a recognised arrowhead where the connector ink still
    swells into a solid blob (thicker than the line: an arrowhead the detector
    missed). The direction of such a connector is uncertain."""
    import cv2

    if not conns:
        return
    dt = cv2.distanceTransform((line_mask > 0).astype("uint8"), cv2.DIST_L2, 3)
    h, w = dt.shape
    r = int(3 * st + 4)
    limit = 0.5 * st + 1.5
    for c in conns:
        for i in (0, 1):
            if c.arrows[i] != "none":
                continue
            x, y = c.pts[0] if i == 0 else c.pts[-1]
            x, y = int(round(x)), int(round(y))
            win = dt[max(0, y - r):min(h, y + r + 1), max(0, x - r):min(w, x + r + 1)]
            if win.size and float(win.max()) >= limit:
                c.blob_end[i] = True


def attach_connectors(conns: list, nodes: list, st: float, ray: bool = True) -> None:
    """Bind every end to the nearest node (shape or symbol) within tolerance.
    With *ray*, an end still unbound may also reach a node a few tolerances
    further along its direction (faint or broken strokes) -- only once the
    gaps have been bridged, or a dash would bind to a far shape."""
    import cv2

    tol = max(10.0, 3 * st + 8)
    for c in conns:
        for i in (0, 1):
            p = c.pts[0] if i == 0 else c.pts[-1]
            best = None
            for nd in nodes:
                x0, y0, x1, y1 = nd.box
                if p[0] < x0 - 4 * tol or p[0] > x1 + 4 * tol or p[1] < y0 - 4 * tol or p[1] > y1 + 4 * tol:
                    continue
                if getattr(nd, "contour", None) is not None:
                    inside = cv2.pointPolygonTest(nd.contour, (float(p[0]), float(p[1])), True)
                    d = 0.0 if inside >= 0 else max(0.0, -inside - nd.stroke)
                else:
                    dx = max(x0 - p[0], 0.0, p[0] - x1)
                    dy = max(y0 - p[1], 0.0, p[1] - y1)
                    d = math.hypot(dx, dy)
                if d <= tol and (best is None or d < best[0]):
                    best = (d, nd, 1.0 - 0.5 * d / tol)
            if best is None and ray:
                # a short gap along the end's direction (faint or broken strokes)
                od = c.end_dir(i)
                for k in range(1, 4):
                    q = (p[0] + od[0] * tol * k, p[1] + od[1] * tol * k)
                    for nd in nodes:
                        x0, y0, x1, y1 = nd.box
                        if x0 - 2 <= q[0] <= x1 + 2 and y0 - 2 <= q[1] <= y1 + 2:
                            best = (tol * k, nd, 0.45)
                            break
                    if best:
                        break
            if best:
                c.ends[i] = best[1]
                c.quality[i] = best[2]


# ================================================================ symbols

class Symbol:
    def __init__(self, **kw):
        self.contour = None
        self.name = ""
        self.__dict__.update(kw)


def detect_symbols(prep: Prep, line_mask, shapes: list) -> tuple:
    """Dense or scribbly non-geometric blobs (icons). -> (symbols, line_mask without them)."""
    import cv2
    import numpy as np

    st = prep.stroke
    H, W = line_mask.shape
    n, lab, stats, _ = cv2.connectedComponentsWithStats(line_mask, connectivity=8)
    syms = []
    if n <= 1:
        return syms, line_mask
    keep = line_mask.copy()
    min_side = max(16.0, 5 * st)
    for j in range(1, n):
        x, y, w, h, area = stats[j]
        if min(w, h) < min_side or w * h > 0.25 * W * H:
            continue
        density = area / float(w * h)
        if density <= 0.08:
            continue          # a connector's sparse bounding box: no thinning needed
        comp = (lab[y:y + h, x:x + w] == j).astype(np.uint8)
        skel_len = float(thin(comp).sum())
        diag = math.hypot(w, h)
        thickness = area / max(skel_len, 1.0)
        dense = thickness > 2.4 * st and density > 0.15
        scribbly = skel_len > 3.2 * diag and density > 0.08
        if not (dense or scribbly):
            continue
        syms.append(Symbol(hx=float(x), hy=float(y), hw=float(w), hh=float(h), stroke=0.0,
                           box=(float(x), float(y), float(x + w), float(y + h)),
                           density=density))
        keep[lab == j] = 0
    return syms, keep


def symbol_data_uri(bgr, box, limit: int = SYMBOL_MAX_URI) -> str:
    """PNG data URI of a crop, downscaled until it fits *limit* characters."""
    import cv2

    x0, y0, x1, y1 = [int(round(v)) for v in box]
    h, w = bgr.shape[:2]
    x0, y0, x1, y1 = max(0, x0), max(0, y0), min(w, x1), min(h, y1)
    crop = bgr[y0:y1, x0:x1]
    if crop.size == 0:
        return ""
    for _ in range(12):
        ok, buf = cv2.imencode(".png", crop, [cv2.IMWRITE_PNG_COMPRESSION, 9])
        if not ok:
            return ""
        uri = "data:image/png;base64," + base64.b64encode(buf.tobytes()).decode("ascii")
        if len(uri) <= limit:
            return uri
        f = max(0.3, math.sqrt(limit / float(len(uri))) * 0.9)
        crop = cv2.resize(crop, (max(1, int(crop.shape[1] * f)), max(1, int(crop.shape[0] * f))),
                          interpolation=cv2.INTER_AREA)
    return ""


# ================================================================ text

def _group_lines(lines: list) -> list:
    """Stack OCR lines into blocks (multi-line labels)."""
    blocks = []
    for ln in sorted(lines, key=lambda l: (l["box"][1], l["box"][0])):
        x0, y0, x1, y1 = ln["box"]
        lh = y1 - y0
        cx = (x0 + x1) / 2.0
        placed = False
        for b in blocks:
            bx0, by0, bx1, by1 = b["box"]
            last = b["lines"][-1]["box"]
            gap = y0 - last[3]
            lcx = (last[0] + last[2]) / 2.0
            overlap = min(x1, last[2]) - max(x0, last[0])
            if -0.5 * lh <= gap <= 0.6 * lh and (abs(cx - lcx) <= 0.25 * max(x1 - x0, last[2] - last[0])
                                                 or overlap > 0.5 * min(x1 - x0, last[2] - last[0])):
                b["lines"].append(ln)
                b["box"] = [min(bx0, x0), min(by0, y0), max(bx1, x1), max(by1, y1)]
                placed = True
                break
        if not placed:
            blocks.append({"lines": [ln], "box": [x0, y0, x1, y1]})
    for b in blocks:
        b["text"] = _join_lines(b["lines"])
        b["confidence"] = sum(l["confidence"] for l in b["lines"]) / len(b["lines"])
        b["line_h"] = sum(l["box"][3] - l["box"][1] for l in b["lines"]) / len(b["lines"])
    return blocks


def _join_lines(lines: list) -> str:
    """Lines sorted top-down; pieces on the same row joined by a space."""
    rows = []
    for ln in sorted(lines, key=lambda l: ((l["box"][1] + l["box"][3]) / 2.0, l["box"][0])):
        cy = (ln["box"][1] + ln["box"][3]) / 2.0
        h = ln["box"][3] - ln["box"][1]
        if rows and abs(rows[-1][0] - cy) <= 0.5 * h:
            rows[-1][1].append(ln)
        else:
            rows.append([cy, [ln]])
    return "\n".join(" ".join(l["text"] for l in sorted(r[1], key=lambda l: l["box"][0])) for r in rows)


def assign_text(lines: list, shapes: list, symbols: list, conns: list, st: float) -> list:
    """Text inside a shape -> the shape; a block next to a connector -> its
    label; a block under a symbol -> the symbol's name. Returns free blocks."""
    import cv2

    rest = []
    for ln in lines:
        x0, y0, x1, y1 = ln["box"]
        cx, cy = (x0 + x1) / 2.0, (y0 + y1) / 2.0
        owner = None
        for s in sorted(shapes, key=lambda s: s.hw * s.hh):
            if s.hx <= cx <= s.hx + s.hw and s.hy <= cy <= s.hy + s.hh and \
                    cv2.pointPolygonTest(s.contour, (float(cx), float(cy)), False) >= 0:
                owner = s
                break
        if owner is not None:
            owner.texts.append(ln)
        else:
            rest.append(ln)
    blocks = _group_lines(rest)
    free = []
    for b in blocks:
        bx0, by0, bx1, by1 = b["box"]
        # labels the gap bridge already bound to a connector
        if any(id(l) in getattr(c, "label_lines", ()) for c in conns for l in b["lines"]):
            continue
        best = None
        limit = max(2.0 * b["line_h"], 3 * st + 10)
        for c in conns:
            d, pos = _rect_polyline(b["box"], c.pts)
            if d <= limit and 0.03 <= pos <= 0.97 and (best is None or d < best[0]):
                best = (d, c, pos)
        if best:
            c = best[1]
            c.labels = getattr(c, "labels", []) + [{"text": b["text"], "pos": round(best[2], 3),
                                                     "confidence": b["confidence"]}]
            continue
        sym = None
        for s in symbols:
            sx0, sy0, sx1, sy1 = s.box
            scx = (sx0 + sx1) / 2.0
            if sy1 - 4 <= by0 <= sy1 + 1.5 * b["line_h"] and bx0 - 4 <= scx <= bx1 + 4 and not s.name:
                sym = s
                break
        if sym is not None:
            sym.name = b["text"].replace("\n", " ")
        free.append(b)
    return free


def _seg_rect_dist(ax, ay, bx, by, box) -> float:
    """Distance between segment AB and an axis-aligned rectangle (0 if they meet)."""
    x0, y0, x1, y1 = box

    def pt_rect(px, py):
        return math.hypot(max(x0 - px, 0.0, px - x1), max(y0 - py, 0.0, py - y1))

    def pt_seg(px, py):
        dx, dy = bx - ax, by - ay
        L = dx * dx + dy * dy
        t = 0.0 if L == 0 else max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / L))
        return math.hypot(ax + dx * t - px, ay + dy * t - py)

    # Liang-Barsky clip: does the segment enter the rectangle?
    t0, t1 = 0.0, 1.0
    dx, dy = bx - ax, by - ay
    inside = True
    for p, q in ((-dx, ax - x0), (dx, x1 - ax), (-dy, ay - y0), (dy, y1 - ay)):
        if p == 0:
            if q < 0:
                inside = False
                break
        else:
            r = q / p
            if p < 0:
                t0 = max(t0, r)
            else:
                t1 = min(t1, r)
            if t0 > t1:
                inside = False
                break
    if inside:
        return 0.0
    return min(pt_rect(ax, ay), pt_rect(bx, by),
               *(pt_seg(cx, cy) for cx, cy in ((x0, y0), (x1, y0), (x1, y1), (x0, y1))))


def _rect_polyline(box, pts) -> tuple:
    """Distance from a rectangle to a polyline and the arc-length position (0..1)
    of the point nearest to the rectangle's centre."""
    total = _path_len(pts) or 1.0
    cx, cy = (box[0] + box[2]) / 2.0, (box[1] + box[3]) / 2.0
    best_d = float("inf")
    best_pos, best_c = 0.5, float("inf")
    acc = 0.0
    for i in range(1, len(pts)):
        ax, ay = pts[i - 1]
        bx, by = pts[i]
        seg = math.hypot(bx - ax, by - ay)
        best_d = min(best_d, _seg_rect_dist(ax, ay, bx, by, box))
        L = seg * seg
        t = 0.0 if L == 0 else max(0.0, min(1.0, ((cx - ax) * (bx - ax) + (cy - ay) * (by - ay)) / L))
        dc = math.hypot(ax + (bx - ax) * t - cx, ay + (by - ay) * t - cy)
        if dc < best_c:
            best_c, best_pos = dc, (acc + seg * t) / total
        acc += seg
    return best_d, best_pos


# ================================================================ colours

def _hex(bgr) -> str:
    b, g, r = [int(max(0, min(255, round(v)))) for v in bgr]
    return "#%02X%02X%02X" % (r, g, b)


def shape_colours(prep: Prep, s: Shape) -> tuple:
    """(fill, stroke) hex: median inside the outline excluding ink, median of the outline ink."""
    import cv2
    import numpy as np

    x, y, w, h = int(s.hx), int(s.hy), int(s.hw), int(s.hh)
    pad = int(s.stroke) + 3
    X0, Y0 = max(0, x - pad), max(0, y - pad)
    X1, Y1 = min(prep.w, x + w + pad + 1), min(prep.h, y + h + pad + 1)
    inner = np.zeros((Y1 - Y0, X1 - X0), np.uint8)
    cv2.drawContours(inner, [s.contour - [X0, Y0]], -1, 1, -1)
    ink = prep.ink[Y0:Y1, X0:X1] > 0
    roi = prep.work[Y0:Y1, X0:X1]
    er = cv2.erode(inner, np.ones((5, 5), np.uint8))
    fill_px = roi[(er > 0) & ~ink]
    band = cv2.dilate(inner, np.ones((2 * pad + 1, 2 * pad + 1), np.uint8)) & (1 - inner)
    stroke_px = roi[(band > 0) & ink]
    fill = _hex(np.median(fill_px, axis=0)) if len(fill_px) else "#FFFFFF"
    stroke = _hex(np.median(stroke_px, axis=0)) if len(stroke_px) else "#000000"
    return fill, stroke


def ink_colour(prep: Prep, box) -> str:
    import numpy as np

    x0, y0, x1, y1 = [int(round(v)) for v in box]
    x0, y0 = max(0, x0), max(0, y0)
    x1, y1 = min(prep.w, x1), min(prep.h, y1)
    if x1 <= x0 or y1 <= y0:
        return "#000000"
    m = prep.ink[y0:y1, x0:x1] > 0
    px = prep.work[y0:y1, x0:x1][m]
    return _hex(np.median(px, axis=0)) if len(px) else "#000000"


def line_colour(prep: Prep, pts) -> str:
    import numpy as np

    samples = []
    for i in range(1, len(pts)):
        ax, ay = pts[i - 1]
        bx, by = pts[i]
        n = max(2, int(math.hypot(bx - ax, by - ay) / 6))
        for k in range(n):
            t = k / float(n)
            x, y = int(round(ax + (bx - ax) * t)), int(round(ay + (by - ay) * t))
            if 0 <= x < prep.w and 0 <= y < prep.h and prep.ink[y, x]:
                samples.append(prep.work[y, x])
    return _hex(np.median(np.array(samples), axis=0)) if samples else "#000000"


# ================================================================ assembly

def _to_src(prep: Prep, v: float) -> float:
    return round(v / prep.scale, 2)


def build_page(prep: Prep, page_no: int, shapes: list, symbols: list, conns: list,
               free_blocks: list, warn) -> dict:
    """Recognised parts (working coords) -> a ``satom.diagram/1`` page (source px)."""
    S = lambda v: _to_src(prep, v)   # noqa: E731
    elements, connectors = [], []
    ids = {}
    for n, s in enumerate(sorted(shapes, key=lambda s: (s.hy, s.hx)), start=1):
        ids[id(s)] = "s%d" % n
    for s in sorted(shapes, key=lambda s: (s.hy, s.hx)):
        x0, y0, x1, y1 = s.box
        fill, stroke = shape_colours(prep, s)
        text = _join_lines(s.texts) if s.texts else ""
        tconf = (sum(t["confidence"] for t in s.texts) / len(s.texts)) if s.texts else 1.0
        conf = (0.35 + 0.65 * s.fit) * tconf
        font_color = ink_colour(prep, _union([t["box"] for t in s.texts])) if s.texts else "#111827"
        font = _font_size(prep, s.texts)
        el = {"id": ids[id(s)], "kind": "container" if s.children else "shape", "shape": s.shape,
              "name": text.split("\n")[0][:model.MAX_NAME] if text else "",
              "text": text, "x": S(x0), "y": S(y0), "w": S(x1 - x0), "h": S(y1 - y0),
              "parent": ids.get(id(s.parent), "") if s.parent else "",
              "style": {"fill": fill, "stroke": stroke, "stroke_width": round(max(1.0, s.stroke) / prep.scale, 2),
                        "rounded": bool(s.extra.get("rounded")), "font_color": font_color,
                        "font_size": font,
                        "valign": "top" if s.children and text else "middle"},
              "metadata": {"detected": s.extra.get("detected", s.kind), "fit_iou": round(s.iou, 3)},
              "source_ref": "bbox:%d,%d,%d,%d" % (S(x0), S(y0), S(x1), S(y1)),
              "confidence": round(conf, 3)}
        if "points" in s.extra:
            el["points"] = s.extra["points"]
        if s.texts:
            el["metadata"]["ocr_confidence"] = round(tconf, 3)
        elements.append(el)
    for n, sym in enumerate(sorted(symbols, key=lambda s: (s.hy, s.hx)), start=1):
        sid = "y%d" % n
        ids[id(sym)] = sid
        pad = max(2.0, prep.stroke)
        bx = (sym.box[0] - pad, sym.box[1] - pad, sym.box[2] + pad, sym.box[3] + pad)
        sx0, sy0, sx1, sy1 = S(bx[0]), S(bx[1]), S(bx[2]), S(bx[3])
        uri = symbol_data_uri(prep.work, bx)
        if not uri:
            warn("A symbol at %d,%d could not be cropped and was skipped." % (sx0, sy0))
            continue
        elements.append({"id": sid, "kind": "image", "shape": "symbol", "name": sym.name,
                         "x": sx0, "y": sy0, "w": sx1 - sx0, "h": sy1 - sy0, "image": uri,
                         "style": {"fill": "none", "stroke": "none"},
                         "metadata": {"needs_review": True, "detected": "symbol",
                                      "density": round(sym.density, 3)},
                         "source_ref": "bbox:%d,%d,%d,%d" % (sx0, sy0, sx1, sy1),
                         "confidence": SYMBOL_CONFIDENCE})
    for n, b in enumerate(sorted(free_blocks, key=lambda b: (b["box"][1], b["box"][0])), start=1):
        x0, y0, x1, y1 = b["box"]
        elements.append({"id": "t%d" % n, "kind": "text", "shape": "rect", "text": b["text"],
                         "name": b["text"].split("\n")[0][:model.MAX_NAME],
                         "x": S(x0), "y": S(y0), "w": S(x1 - x0), "h": S(y1 - y0),
                         "style": {"fill": "none", "stroke": "none",
                                   "font_color": ink_colour(prep, b["box"]),
                                   "font_size": _font_size(prep, b["lines"])},
                         "metadata": {"ocr_confidence": round(b["confidence"], 3)},
                         "source_ref": "bbox:%d,%d,%d,%d" % (S(x0), S(y0), S(x1), S(y1)),
                         "confidence": round(b["confidence"], 3)})
    for n, c in enumerate(conns, start=1):
        pts = [[S(x), S(y)] for x, y in c.pts]
        a0, a1 = c.arrows
        src, tgt = c.ends
        if a0 != "none" and a1 == "none":
            # canonical: the arrow is at the END (forward)
            pts.reverse()
            a0, a1 = a1, a0
            src, tgt = tgt, src
            q = list(reversed(c.quality))
            labels = [{"text": l["text"], "pos": round(1.0 - l["pos"], 3)} for l in getattr(c, "labels", [])]
        else:
            q = list(c.quality)
            labels = [{"text": l["text"], "pos": l["pos"]} for l in getattr(c, "labels", [])]
        ortho = len(pts) >= 3 and all(abs(pts[i][0] - pts[i - 1][0]) < 0.5 or abs(pts[i][1] - pts[i - 1][1]) < 0.5
                                      for i in range(1, len(pts)))
        qual = [q[0] if src is not None else FREE_END_QUALITY, q[1] if tgt is not None else FREE_END_QUALITY]
        conf = connector_confidence(qual, src is None or tgt is None, (not all(c.head_agree)) or any(c.blob_end),
                                    c.gaps and not c.dashed,
                                    [l.get("confidence", 1.0) for l in getattr(c, "labels", [])])
        uncertain = (not all(c.head_agree)) or any(c.blob_end)
        connectors.append({
            "id": "c%d" % n,
            "source": ids.get(id(src), "") if src is not None else "",
            "target": ids.get(id(tgt), "") if tgt is not None else "",
            "start": pts[0], "end": pts[-1],
            "points": pts[1:-1],
            "routing": "orthogonal" if ortho else "straight",
            "start_arrow": a0, "end_arrow": a1,
            "label": labels[0]["text"].replace("\n", " ")[:model.MAX_NAME] if labels else "",
            "labels": labels,
            "style": {"stroke": line_colour(prep, c.pts), "stroke_width": round(prep.stroke / prep.scale, 2),
                      "dashed": bool(c.dashed)},
            "metadata": dict({"attach_source": round(qual[0], 3), "attach_target": round(qual[1], 3)},
                             **({"direction_uncertain": True} if uncertain else {}),
                             **({"dangling": True} if src is None or tgt is None else {}),
                             **({"loose_attachment": True} if min(qual) < LOOSE_ATTACH_QUALITY
                                and src is not None and tgt is not None else {})),
            "confidence": round(conf, 3)})
    bg = prep.bg
    background = "" if min(bg) >= 245 else _hex(bg)
    return {"id": "page-%d" % page_no, "name": "Page %d" % page_no,
            "width": prep.src_w, "height": prep.src_h, "background": background,
            "elements": elements, "connectors": connectors}


def connector_confidence(qual, dangling: bool, uncertain: bool, bridged: bool, label_confs) -> float:
    """A connector's confidence, rounded as stored. Review flags anything
    under ``model.LOW_CONFIDENCE`` -- so every doubtful case is CAPPED strictly
    below it (an average could land exactly on 0.6, which Review would not
    flag): a free end (DANGLING_CONFIDENCE), an end bound only by the
    gap-following fallback (LOOSE_CONFIDENCE), unclear direction
    (UNCERTAIN_CONFIDENCE). Caps are applied last; nothing raises them."""
    conf = (qual[0] + qual[1]) / 2.0 * (0.9 if bridged else 1.0)
    if label_confs:
        conf *= min(1.0, 0.5 + 0.5 * min(label_confs))
    if dangling:
        conf = min(conf, DANGLING_CONFIDENCE)
    elif min(qual) < LOOSE_ATTACH_QUALITY:
        conf = min(conf, LOOSE_CONFIDENCE)
    if uncertain:
        conf = min(conf, UNCERTAIN_CONFIDENCE)
    return round(max(0.0, conf), 3)


def _union(boxes):
    return (min(b[0] for b in boxes), min(b[1] for b in boxes),
            max(b[2] for b in boxes), max(b[3] for b in boxes))


def _font_size(prep: Prep, lines) -> float:
    """Font size (px of the source) from OCR line boxes: the DB detector's box
    is ~1.25x the em size (measured on DejaVu renders)."""
    if not lines:
        return 12.0
    hs = sorted(l["box"][3] - l["box"][1] for l in lines)
    return round(max(4.0, min(200.0, hs[len(hs) // 2] / 1.25 / prep.scale)), 1)


# ================================================================ driver

def recognise_page(bgr, page_no: int = 1, *, use_ocr: bool = True, warn=None) -> tuple:
    """BGR image -> ``(page dict, stats)``."""
    warn = warn or (lambda m: None)
    t = {}
    t0 = time.perf_counter()
    prep = preprocess(bgr)
    t["preprocess"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    lines = run_ocr(prep, warn) if use_ocr else []
    t["ocr"] = time.perf_counter() - t0
    text_boxes = [tuple(l["box"]) for l in lines]

    t0 = time.perf_counter()
    shapes = detect_shapes(prep, text_boxes, warn)
    t["shapes"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    residual = extract_line_mask(prep, shapes, text_boxes, [])
    line_st = connector_stroke(residual, prep.stroke)
    heads = detect_arrowheads(prep, shapes, text_boxes, mask=residual, st=line_st)
    t["arrowheads"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    line_mask = erase_heads(residual, heads, line_st)
    symbols, line_mask = detect_symbols(prep, line_mask, shapes)
    t["symbols"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    conns = trace_connectors(prep, line_mask, warn)
    bind_arrowheads(conns, heads, line_st, prep.ink)
    nodes = list(shapes) + list(symbols)
    attach_connectors(conns, nodes, prep.stroke, ray=False)
    conns = bridge_gaps(conns, text_boxes, prep.stroke)
    for c in conns:
        c.label_lines = {id(lines[k]) for k in c.label_ids if k is not None and k < len(lines)}
        if c.label_ids:
            c.labels = [{"text": lines[k]["text"], "pos": 0.5, "confidence": lines[k]["confidence"]}
                        for k in c.label_ids if k is not None and k < len(lines)]
    attach_connectors([c for c in conns if c.ends[0] is None or c.ends[1] is None], nodes, prep.stroke)
    conns = [c for c in conns if not _is_noise(c, prep.stroke)]
    flag_unexplained_blobs(conns, residual, line_st)
    t["connectors"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    free = assign_text(lines, shapes, symbols, conns, prep.stroke)
    page = build_page(prep, page_no, shapes, symbols, conns, free, warn)
    t["assemble"] = time.perf_counter() - t0

    orphan = sum(1 for h in heads if not h.used)
    if orphan:
        warn("%d arrowhead(s) were not on any recognised connector." % orphan)
    stats = {"scale": round(prep.scale, 4), "skew_deg": round(prep.angle, 2),
             "stroke_px": round(prep.stroke / prep.scale, 2),
             "ocr_lines": len(lines), "shapes": len(shapes), "symbols": len(symbols),
             "arrowheads": len(heads), "connectors_found": len(conns)}
    for k, v in t.items():
        stats["ms_" + k] = int(round(v * 1000))
    return page, stats


def _is_noise(c: Conn, st: float) -> bool:
    """A short stroke that is not bound to anything (stray mark, glyph debris)."""
    ln = c.length()
    if c.ends[0] is None and c.ends[1] is None and c.arrows == ["none", "none"]:
        return ln < max(40.0, 12 * st)
    if (c.ends[0] is None) != (c.ends[1] is None) and c.arrows == ["none", "none"]:
        return ln < max(20.0, 6 * st)
    if c.ends[0] is not None and c.ends[0] is c.ends[1]:
        return ln < max(60.0, 20 * st)
    return False


def _read(data, *, filename="", page=None, options=None) -> dict:
    data = require_bytes(data)
    opts = dict(options or {})
    use_ocr = bool(opts.get("ocr", True))
    w = Warnings()
    t0 = time.perf_counter()
    fmt, total, frames = decode_image(data, page)
    if fmt == "tiff" and page in (None, "") and total > MAX_TIFF_PAGES:
        w.once("tiff-pages", "The TIFF has %d pages; only the first %d were read." % (total, MAX_TIFF_PAGES))
    if fmt in ("gif", "webp"):
        w.once("anim", "Only the first frame of an animated image is read.")
    pages, agg = [], {"ms_decode": 0}
    while True:
        td = time.perf_counter()
        try:
            no, bgr = next(frames)
        except StopIteration:
            break
        agg["ms_decode"] += int(round((time.perf_counter() - td) * 1000))
        pg, st = recognise_page(bgr, no, use_ocr=use_ocr, warn=w.add)
        del bgr
        pages.append(pg)
        for k, v in st.items():
            if k.startswith("ms_") or k in ("ocr_lines", "shapes", "symbols", "arrowheads", "connectors_found"):
                agg[k] = agg.get(k, 0) + v
            else:
                agg.setdefault(k, v)
    if not pages:
        raise ImportFailed("The image has no readable page.")
    agg["ms_total"] = int(round((time.perf_counter() - t0) * 1000))
    doc = make_document(fmt=fmt, engine=ENGINE, data=data, filename=filename,
                        name=doc_name(filename, "Recognised diagram"), pages=pages,
                        warnings=w.items, page=page,
                        metadata={"recognised_from": "raster", "ocr": use_ocr,
                                  "ocr_engine": _ocr_engine_name() if use_ocr else ""})
    doc["recognition"]["version"] = VERSION
    doc["recognition"]["stats"].update(agg)
    return doc


def _ocr_engine_name() -> str:
    from .. import ocr

    return ocr.ENGINE


def read(data, *, filename: str = "", page=None, options=None) -> dict:
    """Recognise a raster image -> normalised ``satom.diagram/1`` document.

    ``options``: ``{"ocr": bool}`` (default True). Raises ImportFailed only."""
    return guarded(_read)(data, filename=filename, page=page, options=options)


@guarded
def list_pages(data) -> list:
    im, fmt = open_image(require_bytes(data))
    return [{"id": "page-%d" % (i + 1), "name": "Page %d" % (i + 1)} for i in range(frame_count(im, fmt))]


def read_png_page(png_bytes: bytes, filename: str = "", *, options=None) -> dict:
    """For the PDF importer: recognise one rendered (scanned) page.
    -> a normalised single-page document; take ``doc["pages"][0]``."""
    return read(png_bytes, filename=filename, page=None, options=options)
