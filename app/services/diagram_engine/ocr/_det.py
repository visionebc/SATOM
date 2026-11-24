# NOTICE: derived from rapidocr_onnxruntime 1.4.4 (ch_ppocr_det/text_detect.py,
# ch_ppocr_det/utils.py), https://github.com/RapidAI/RapidOCR, Apache-2.0,
# itself based on PaddleOCR (Copyright (c) 2020 PaddlePaddle Authors,
# Apache-2.0) -- see LICENSE-rapidocr. Modified for SATOM: configuration
# hard-coded, numpy/cv2/pyclipper/shapely imported lazily by the caller.
"""Text detection: DB (Differentiable Binarization) network + post-process."""
from __future__ import annotations

from . import _runtime

LIMIT_SIDE_LEN = 736       # "min" mode: the shorter side is scaled UP to this
MAX_SIDE_LEN = 3200        # never feed the network more than this per side
THRESH = 0.3
BOX_THRESH = 0.5
MAX_CANDIDATES = 2000
UNCLIP_RATIO = 1.6
MIN_SIZE = 3
TILE_MAX = 640             # SATOM: larger pictures are detected in tiles (det memory:
TILE_OVERLAP = 192         # ~+160 MB per 640 px tile vs +660 MB for a whole 2400x1600 page)


def _tiles(h, w):
    """Even tiles of at most TILE_MAX (+ overlap) covering h x w."""
    import math

    ny, nx = max(1, math.ceil(h / TILE_MAX)), max(1, math.ceil(w / TILE_MAX))
    th, tw = math.ceil(h / ny), math.ceil(w / nx)
    out = []
    for j in range(ny):
        for i in range(nx):
            y0, x0 = max(0, j * th - TILE_OVERLAP // 2), max(0, i * tw - TILE_OVERLAP // 2)
            y1, x1 = min(h, (j + 1) * th + TILE_OVERLAP // 2), min(w, (i + 1) * tw + TILE_OVERLAP // 2)
            out.append((y0, y1, x0, x1))
    return out


def _merge_boxes(boxes):
    """Merge boxes of one text line split or duplicated by tile seams: boxes
    that overlap horizontally and share most of their height become their
    axis-aligned union."""
    import numpy as np

    rects = [[float(b[:, 0].min()), float(b[:, 1].min()), float(b[:, 0].max()), float(b[:, 1].max())]
             for b in boxes]
    changed = True
    while changed:
        changed = False
        out = []
        for r in rects:
            for o in out:
                vov = min(r[3], o[3]) - max(r[1], o[1])
                hov = min(r[2], o[2]) - max(r[0], o[0])
                if hov > -2 and vov >= 0.6 * min(r[3] - r[1], o[3] - o[1]):
                    o[0], o[1] = min(o[0], r[0]), min(o[1], r[1])
                    o[2], o[3] = max(o[2], r[2]), max(o[3], r[3])
                    changed = True
                    break
            else:
                out.append(list(r))
        rects = out
    return [np.array([[x0, y0], [x1, y0], [x1, y1], [x0, y1]], dtype=np.float32) for x0, y0, x1, y1 in rects]


class TextDetector:
    def __init__(self):
        self.sess = _runtime.session(_runtime.DET_MODEL)

    def __call__(self, img):
        """``img`` BGR uint8 -> list of 4x2 float32 boxes (clockwise from top-left).

        Pictures larger than TILE_MAX on a side are detected tile by tile (with
        TILE_OVERLAP) so peak memory does not grow with the picture; boxes cut
        or duplicated at tile seams are merged afterwards."""
        h, w = img.shape[:2]
        if max(h, w) <= TILE_MAX:
            return self._detect(img)
        import numpy as np

        boxes = []
        for y0, y1, x0, x1 in _tiles(h, w):
            for b in self._detect(np.ascontiguousarray(img[y0:y1, x0:x1]), upscale=False):
                b = b.copy()
                b[:, 0] += x0
                b[:, 1] += y0
                boxes.append(b)
        return _merge_boxes(boxes)

    def _detect(self, img, upscale=True):
        import numpy as np

        h, w = img.shape[:2]
        x, ratio_h, ratio_w = self._preprocess(img, upscale)
        if x is None:
            return []
        pred = _runtime.run(self.sess, x)[0]
        boxes = self._boxes_from_bitmap(pred[0, 0], (pred[0, 0] > THRESH).astype(np.uint8), w, h)
        out = []
        for box in boxes:
            box = _order_points_clockwise(box)
            box[:, 0] = np.clip(np.round(box[:, 0]), 0, w - 1)
            box[:, 1] = np.clip(np.round(box[:, 1]), 0, h - 1)
            if np.linalg.norm(box[0] - box[1]) <= 3 or np.linalg.norm(box[0] - box[3]) <= 3:
                continue
            out.append(box)
        return out

    @staticmethod
    def _preprocess(img, upscale=True):
        import cv2
        import numpy as np

        h, w = img.shape[:2]
        ratio = 1.0
        if upscale and min(h, w) < LIMIT_SIDE_LEN:
            ratio = float(LIMIT_SIDE_LEN) / min(h, w)
        if max(h, w) * ratio > MAX_SIDE_LEN:
            ratio = float(MAX_SIDE_LEN) / max(h, w)
        rh = max(32, int(round(h * ratio / 32) * 32))
        rw = max(32, int(round(w * ratio / 32) * 32))
        resized = cv2.resize(img, (rw, rh))
        x = (resized.astype(np.float32) / 255.0 - 0.5) / 0.5
        x = x.transpose((2, 0, 1))[np.newaxis, :].astype(np.float32)
        return x, rh / float(h), rw / float(w)

    @staticmethod
    def _boxes_from_bitmap(pred, bitmap, dest_w, dest_h):
        import cv2
        import numpy as np

        height, width = bitmap.shape
        bitmap = cv2.dilate(bitmap, np.ones((2, 2), np.uint8))
        contours, _ = cv2.findContours((bitmap * 255).astype(np.uint8), cv2.RETR_LIST,
                                       cv2.CHAIN_APPROX_SIMPLE)
        boxes = []
        for contour in contours[:MAX_CANDIDATES]:
            points, sside = _mini_box(contour)
            if sside < MIN_SIZE:
                continue
            if _box_score_fast(pred, points.reshape(-1, 2)) < BOX_THRESH:
                continue
            expanded = _unclip(points)
            if expanded is None:
                continue
            box, sside = _mini_box(expanded)
            if sside < MIN_SIZE + 2:
                continue
            box[:, 0] = np.clip(np.round(box[:, 0] / width * dest_w), 0, dest_w)
            box[:, 1] = np.clip(np.round(box[:, 1] / height * dest_h), 0, dest_h)
            boxes.append(box.astype(np.float32))
        return boxes


def _mini_box(contour):
    import cv2
    import numpy as np

    rect = cv2.minAreaRect(contour)
    points = sorted(list(cv2.boxPoints(rect)), key=lambda p: p[0])
    i1, i4 = (0, 1) if points[1][1] > points[0][1] else (1, 0)
    i2, i3 = (2, 3) if points[3][1] > points[2][1] else (3, 2)
    return np.array([points[i1], points[i2], points[i3], points[i4]]), min(rect[1])


def _box_score_fast(bitmap, box):
    import cv2
    import numpy as np

    h, w = bitmap.shape[:2]
    box = box.copy()
    xmin = int(np.clip(np.floor(box[:, 0].min()), 0, w - 1))
    xmax = int(np.clip(np.ceil(box[:, 0].max()), 0, w - 1))
    ymin = int(np.clip(np.floor(box[:, 1].min()), 0, h - 1))
    ymax = int(np.clip(np.ceil(box[:, 1].max()), 0, h - 1))
    mask = np.zeros((ymax - ymin + 1, xmax - xmin + 1), dtype=np.uint8)
    box[:, 0] -= xmin
    box[:, 1] -= ymin
    cv2.fillPoly(mask, box.reshape(1, -1, 2).astype(np.int32), 1)
    return cv2.mean(bitmap[ymin:ymax + 1, xmin:xmax + 1], mask)[0]


def _unclip(box):
    import numpy as np
    import pyclipper
    from shapely.geometry import Polygon

    poly = Polygon(box)
    if poly.length <= 0:
        return None
    distance = poly.area * UNCLIP_RATIO / poly.length
    offset = pyclipper.PyclipperOffset()
    offset.AddPath(box.tolist(), pyclipper.JT_ROUND, pyclipper.ET_CLOSEDPOLYGON)
    paths = offset.Execute(distance)
    if not paths:
        return None
    return np.array(paths[0], dtype=np.float32).reshape((-1, 1, 2))


def _order_points_clockwise(pts):
    import numpy as np

    xs = pts[np.argsort(pts[:, 0]), :]
    left, right = xs[:2, :], xs[2:, :]
    tl, bl = left[np.argsort(left[:, 1]), :]
    tr, br = right[np.argsort(right[:, 1]), :]
    return np.array([tl, tr, br, bl], dtype=np.float32)
