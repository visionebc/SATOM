# NOTICE: the OCR pipeline in this package is derived from rapidocr_onnxruntime
# 1.4.4 (https://github.com/RapidAI/RapidOCR, Apache-2.0) and PaddleOCR
# (Copyright (c) 2020 PaddlePaddle Authors, Apache-2.0); the recognition model
# is PaddleOCR latin_PP-OCRv5_mobile_rec (Apache-2.0). See LICENSE-rapidocr.
"""Vendored, offline OCR for Diagram Studio's raster recogniser.

PP-OCRv4 detection + PP-OCR direction classifier + PP-OCRv5 Latin recognition
on onnxruntime's CPU provider. The models ship in ``models/`` and are checked
against ``models/MANIFEST.json`` (sha256) before every load; a tampered or
missing model is refused, never loaded.

Importing this package needs only the standard library: numpy, OpenCV,
onnxruntime, pyclipper and shapely are imported inside the functions, so the
rest of the engine works (without OCR) on a host that lacks them. Ask
:func:`available` first.

Accented text (measured, see tests/test_diagram_raster.py): recognition uses
PaddleOCR's Latin PP-OCRv5 model, whose dictionary covers the Western European
letters (a/e/i/o/u with acute, grave, circumflex, diaeresis; n-tilde, c-cedilla,
sharp s, oe/ae ligatures), the inverted question mark and the euro sign (not
the inverted exclamation mark). On 46
rendered ES/DE/FR/IT samples it reads 44 exactly; the Chinese+English
PP-OCRv4 model it replaces read 3 (it drops most diacritics).
"""
from __future__ import annotations

import threading

from . import _runtime
from ._runtime import ModelIntegrityError  # noqa: F401  (re-export)

ENGINE = "PP-OCRv4 det + PP-OCRv5 Latin rec (PaddleOCR; pipeline from rapidocr_onnxruntime 1.4.4)"
MIN_CONFIDENCE = 0.5
#: Space re-insertion thresholds (see respace()): a blank column run is a
#: word space when >= SPACE_EM x the text line's height and >= SPACE_PITCH x
#: the line's median letter gap.
SPACE_EM = 0.21
SPACE_PITCH = 1.8

_engine = None
_engine_lock = threading.Lock()

_HEAVY = ("numpy", "cv2", "onnxruntime", "pyclipper", "shapely")


def available() -> tuple[bool, str]:
    """``(True, "")`` when OCR can run here, else ``(False, why)``."""
    for mod in _HEAVY:
        try:
            __import__(mod)
        except Exception as exc:  # ImportError, or a broken wheel raising anything
            return False, "%s is not installed or cannot be imported (%s)" % (mod, type(exc).__name__)
    try:
        _runtime.verify_all()
    except ModelIntegrityError as exc:
        return False, str(exc)
    except OSError as exc:
        return False, "OCR models unreadable: %s" % exc
    return True, ""


class _Engine:
    def __init__(self):
        from ._det import TextDetector
        from ._rec import TextClassifier, TextRecognizer

        self.det = TextDetector()
        self.cls = TextClassifier()
        self.rec = TextRecognizer()

    def __call__(self, img, min_confidence):
        import cv2

        boxes = _sorted_boxes(self.det(img))
        if not boxes:
            return []
        crops = [_crop(img, b) for b in boxes]
        flipped = self.cls(crops)
        rec = self.rec(crops)
        # a flip only stands if the rotated crop reads more confidently
        idx = [i for i, f in enumerate(flipped) if f]
        if idx:
            rot = [cv2.rotate(crops[i], cv2.ROTATE_180) for i in idx]
            for i, crop_r, r in zip(idx, rot, self.rec(rot)):
                if r[1] > rec[i][1]:
                    crops[i], rec[i] = crop_r, r
        out = []
        for box, crop, (text, conf, cols, frames) in zip(boxes, crops, rec):
            if frames > 0 and len(text) > 2:
                scale = crop.shape[1] / float(max(frames, 1e-6))
                _ink_h, runs = blank_runs(crop)
                text = respace(text, [(c + 0.5) * scale for c in cols], float(crop.shape[0]), runs)
            text = " ".join(text.split())
            if not text or conf < min_confidence:
                continue
            xs, ys = box[:, 0], box[:, 1]
            out.append({"text": text,
                        "box": [float(xs.min()), float(ys.min()), float(xs.max()), float(ys.max())],
                        "confidence": round(float(conf), 4)})
        return out


def engine():
    """The process-wide engine (sessions are loaded once, models verified)."""
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = _Engine()
        return _engine


def recognise(image_bgr, *, min_confidence: float = MIN_CONFIDENCE) -> list:
    """OCR an image (numpy ``HxWx3`` BGR uint8).

    -> ``[{"text", "box": [x0, y0, x1, y1], "confidence"}]`` in image pixels,
    top-to-bottom then left-to-right. Raises :class:`ModelIntegrityError` when
    a model fails verification and ImportError when the stack is missing."""
    import numpy as np

    img = np.asarray(image_bgr)
    if img.ndim == 2:
        img = np.repeat(img[:, :, None], 3, axis=2)
    if img.ndim != 3 or img.shape[2] not in (3, 4) or img.shape[0] < 4 or img.shape[1] < 4:
        raise ValueError("recognise() wants an HxWx3 BGR image")
    if img.shape[2] == 4:
        img = img[:, :, :3]
    img = np.ascontiguousarray(img, dtype=np.uint8)
    return engine()(img, float(min_confidence))


# ------------------------------------------------------------------ helpers

def blank_runs(crop):
    """Measure a text-line crop: ``(ink_height, [(centre_x, width), ...])`` of
    the ink-free column runs between its first and last inked column."""
    import cv2
    import numpy as np

    g = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY) if crop.ndim == 3 else crop
    _, bw = cv2.threshold(g, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
    ink = bw > 0
    # Otsu on a crop with almost no ink picks noise: no measurement then
    if ink.mean() > 0.6 or ink.mean() < 0.01:
        return 0, []
    rows = np.where(ink.any(axis=1))[0]
    colink = ink.any(axis=0)
    xs = np.where(colink)[0]
    if len(rows) == 0 or len(xs) == 0:
        return 0, []
    runs, start = [], None
    for x in range(int(xs[0]), int(xs[-1]) + 1):
        if not colink[x] and start is None:
            start = x
        elif colink[x] and start is not None:
            runs.append(((start + x) / 2.0, x - start))
            start = None
    return int(rows[-1] - rows[0] + 1), runs


def respace(text: str, xs: list, line_h: float, runs: list) -> str:
    """Put back word spaces the recogniser swallowed (``DMZVLAN20`` ->
    ``DMZ VLAN 20``), from a measurement of the crop, not from the letters.

    ``xs`` is the crop x of every character (from its CTC frame), ``line_h``
    the crop (text line) height, ``runs`` the blank column runs of the crop.
    A run is a word space when it is at least ``SPACE_EM`` x the line height
    AND ``SPACE_PITCH`` x the line's median letter gap. Measured on DejaVu
    renders, clean and degraded (half size, JPEG q40, blur): letter gaps
    <= 0.18 x line height, word gaps >= 0.23. The space goes at the character
    boundary nearest to the run, unless one is already there."""
    if len(text) < 2 or len(xs) != len(text) or line_h <= 0 or not runs:
        return text
    letter = sorted(w for _, w in runs if w < SPACE_EM * line_h)
    pitch = letter[len(letter) // 2] if letter else 0
    inserts = set()
    for centre, width in runs:
        if width < SPACE_EM * line_h or width < SPACE_PITCH * pitch:
            continue
        best, best_d = None, None
        for i in range(1, len(text)):
            lo, hi = xs[i - 1], xs[i]
            if not (lo - 0.5 * (hi - lo) <= centre <= hi + 0.5 * (hi - lo)):
                continue
            d = abs(centre - (lo + hi) / 2.0)
            if best_d is None or d < best_d:
                best, best_d = i, d
        if best is None or text[best] == " " or text[best - 1] == " ":
            continue
        inserts.add(best)
    out = list(text)
    for i in sorted(inserts, reverse=True):
        out.insert(i, " ")
    return "".join(out)


def _sorted_boxes(boxes):
    boxes = sorted(boxes, key=lambda b: (float(b[0][1]), float(b[0][0])))
    for i in range(len(boxes) - 1):
        for j in range(i, -1, -1):
            if abs(boxes[j + 1][0][1] - boxes[j][0][1]) < 10 and boxes[j + 1][0][0] < boxes[j][0][0]:
                boxes[j], boxes[j + 1] = boxes[j + 1], boxes[j]
            else:
                break
    return boxes


def _crop(img, points):
    import cv2
    import numpy as np

    pts = points.astype(np.float32)
    w = int(max(np.linalg.norm(pts[0] - pts[1]), np.linalg.norm(pts[2] - pts[3])))
    h = int(max(np.linalg.norm(pts[0] - pts[3]), np.linalg.norm(pts[1] - pts[2])))
    w, h = max(w, 2), max(h, 2)
    dst = np.array([[0, 0], [w, 0], [w, h], [0, h]], dtype=np.float32)
    m = cv2.getPerspectiveTransform(pts, dst)
    crop = cv2.warpPerspective(img, m, (w, h), borderMode=cv2.BORDER_REPLICATE, flags=cv2.INTER_CUBIC)
    if crop.shape[0] / float(crop.shape[1]) >= 1.5:
        crop = np.rot90(crop)
    return np.ascontiguousarray(crop)
