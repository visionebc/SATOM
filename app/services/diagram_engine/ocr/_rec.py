# NOTICE: derived from rapidocr_onnxruntime 1.4.4 (ch_ppocr_cls/text_cls.py,
# ch_ppocr_cls/utils.py, ch_ppocr_rec/text_recognize.py, ch_ppocr_rec/utils.py),
# https://github.com/RapidAI/RapidOCR, Apache-2.0, itself based on PaddleOCR
# (Copyright (c) 2020 PaddlePaddle Authors, Apache-2.0) -- see LICENSE-rapidocr.
# Modified for SATOM: configuration hard-coded, the CTC decoder also returns
# the frame column of every decoded character (used to measure letter gaps),
# the classifier reports flips instead of applying them, the recogniser checks
# that its dictionary matches the network's output classes.
"""Text-line direction classification (0/180) and recognition (CTC)."""
from __future__ import annotations

import math

from . import _runtime

CLS_SHAPE = (3, 48, 192)
CLS_BATCH = 6
CLS_THRESH = 0.9
REC_SHAPE = (3, 48, 320)
REC_BATCH = 6


class TextClassifier:
    def __init__(self):
        self.sess = _runtime.session(_runtime.CLS_MODEL)

    def __call__(self, crops):
        """-> ``[bool]``: True where the network reads the crop as upside-down
        (with confidence above CLS_THRESH). The crops are not modified; the
        engine recognises both orientations of a flagged crop and keeps the
        more confident reading (the classifier alone flips some short words)."""
        import numpy as np

        crops = list(crops)
        flipped = [False] * len(crops)
        order = sorted(range(len(crops)), key=lambda i: crops[i].shape[1] / float(crops[i].shape[0]))
        for beg in range(0, len(crops), CLS_BATCH):
            idx = order[beg:beg + CLS_BATCH]
            batch = np.concatenate([_resize_norm(crops[i], CLS_SHAPE, CLS_SHAPE[2] / CLS_SHAPE[1],
                                                 fixed_width=True)[np.newaxis] for i in idx])
            prob = _runtime.run(self.sess, batch.astype(np.float32))[0]
            for k, i in enumerate(idx):
                label = int(prob[k].argmax())
                if label == 1 and float(prob[k, label]) > CLS_THRESH:
                    flipped[i] = True
        return flipped


class TextRecognizer:
    def __init__(self, model: str = _runtime.REC_MODEL, dictionary: str = _runtime.DICTIONARY):
        self.sess = _runtime.session(model)
        chars = _runtime.load_dictionary(dictionary)
        classes = self.sess.get_outputs()[0].shape[-1]
        if isinstance(classes, int) and classes != len(chars) + 2:
            raise _runtime.ModelIntegrityError("%s: %d output classes for a %d-entry dictionary"
                                               % (model, classes, len(chars)))
        # index 0 is the CTC blank; the space is appended last (upstream layout)
        self.character = ["blank"] + chars + [" "]

    def __call__(self, crops):
        """-> list of (text, confidence, [frame column per char], frames)."""
        import numpy as np

        out = [("", 0.0, [], 0)] * len(crops)
        order = sorted(range(len(crops)), key=lambda i: crops[i].shape[1] / float(crops[i].shape[0]))
        for beg in range(0, len(crops), REC_BATCH):
            idx = order[beg:beg + REC_BATCH]
            max_ratio = REC_SHAPE[2] / REC_SHAPE[1]
            for i in idx:
                h, w = crops[i].shape[:2]
                max_ratio = max(max_ratio, w / float(h))
            batch = np.concatenate([_resize_norm(crops[i], REC_SHAPE, max_ratio)[np.newaxis] for i in idx])
            preds = _runtime.run(self.sess, batch.astype(np.float32))[0]
            for k, i in enumerate(idx):
                h, w = crops[i].shape[:2]
                # frames that actually cover this crop (the rest is padding)
                used = preds.shape[1] * min(1.0, (w / float(h)) / max_ratio)
                out[i] = self._decode(preds[k], used)
        return out

    def _decode(self, pred, used_frames):
        idx = pred.argmax(axis=1)
        prob = pred.max(axis=1)
        chars, confs, cols = [], [], []
        prev = -1
        for t, c in enumerate(idx.tolist()):
            if c != prev and c != 0:
                chars.append(self.character[c] if c < len(self.character) else "")
                confs.append(float(prob[t]))
                cols.append(t)
            prev = c
        text = "".join(chars)
        conf = float(sum(confs) / len(confs)) if confs else 0.0
        return text, conf, cols, used_frames


def _resize_norm(img, shape, max_wh_ratio, fixed_width=False):
    import cv2
    import numpy as np

    c, h, w = shape
    if not fixed_width:
        w = int(h * max_wh_ratio)
    ih, iw = img.shape[:2]
    ratio = iw / float(ih)
    rw = w if math.ceil(h * ratio) > w else int(math.ceil(h * ratio))
    rw = max(1, rw)
    resized = cv2.resize(img, (rw, h)).astype(np.float32)
    resized = resized.transpose((2, 0, 1)) / 255.0
    resized -= 0.5
    resized /= 0.5
    padded = np.zeros((c, h, w), dtype=np.float32)
    padded[:, :, :rw] = resized
    return padded
