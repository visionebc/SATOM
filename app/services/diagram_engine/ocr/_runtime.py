# NOTICE: derived from rapidocr_onnxruntime 1.4.4 (utils/infer_engine.py),
# https://github.com/RapidAI/RapidOCR, Apache-2.0 -- see LICENSE-rapidocr.
# Models: PaddleOCR (Apache-2.0), listed with their sources in models/MANIFEST.json.
# Modified for SATOM: CPU provider only, fixed thread counts, sha256-verified
# models listed in models/MANIFEST.json, lazy onnxruntime import.
"""Model integrity and ONNX Runtime sessions for the vendored OCR."""
from __future__ import annotations

import hashlib
import json
import os
import threading

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
MANIFEST = os.path.join(MODELS_DIR, "MANIFEST.json")

DET_MODEL = "ch_PP-OCRv4_det_infer.onnx"
CLS_MODEL = "ch_ppocr_mobile_v2.0_cls_infer.onnx"
#: Recognition: PaddleOCR's Latin PP-OCRv5 mobile model (Western European
#: accents, ligatures, currency signs). Chosen over the ch+en PP-OCRv4 model,
#: which drops most diacritics -- measured in tests/test_diagram_raster.py.
REC_MODEL = "latin_PP-OCRv5_mobile_rec.onnx"
DICTIONARY = "latin_dict.txt"
REQUIRED = (DET_MODEL, CLS_MODEL, REC_MODEL, DICTIONARY)


def required() -> tuple:
    """Every file this build needs (and the manifest must list)."""
    return REQUIRED


#: Threads per session. Fixed: letting onnxruntime pick pins threads to cores
#: and floods stderr with pthread_setaffinity_np errors inside containers.
INTRA_OP_THREADS = 2
INTER_OP_THREADS = 2

_verified: dict = {}
_lock = threading.Lock()


class ModelIntegrityError(RuntimeError):
    """A model file is missing, unlisted or does not match its manifest sha256."""


def _manifest() -> dict:
    try:
        with open(MANIFEST, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise ModelIntegrityError("OCR model manifest is missing (%s)" % MANIFEST) from None
    except ValueError as exc:
        raise ModelIntegrityError("OCR model manifest is not valid JSON: %s" % exc) from None
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict):
        raise ModelIntegrityError("OCR model manifest has no 'files' map")
    return files


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(name: str) -> str:
    """Return the absolute path of ``name`` after checking it against the
    manifest. The digest is recomputed whenever the file's size or mtime
    changes, so a model swapped after the first load is still refused."""
    files = _manifest()
    entry = files.get(name)
    if not isinstance(entry, dict) or not isinstance(entry.get("sha256"), str):
        raise ModelIntegrityError("%s is not listed in the OCR model manifest" % name)
    path = os.path.join(MODELS_DIR, name)
    try:
        st = os.stat(path)
    except FileNotFoundError:
        raise ModelIntegrityError("OCR model file %s is missing" % name) from None
    key = (path, st.st_size, st.st_mtime_ns, entry["sha256"])
    with _lock:
        if _verified.get(path) == key:
            return path
    digest = sha256_file(path)
    if digest != entry["sha256"].lower():
        raise ModelIntegrityError("OCR model %s failed its sha256 check (expected %s..., got %s...); "
                                  "refusing to load it" % (name, entry["sha256"][:12], digest[:12]))
    with _lock:
        _verified[path] = key
    return path


def verify_all() -> None:
    for name in required():
        verify(name)


def load_dictionary(name: str = DICTIONARY) -> list:
    path = verify(name)
    with open(path, "rb") as fh:
        data = fh.read().decode("utf-8")
    # splitlines(), exactly as upstream splits the model's metadata string, so
    # that indices line up with the network's output classes.
    return data.splitlines()


def session(name: str):
    """An onnxruntime InferenceSession on the CPU provider for a verified model.

    The model bytes that were hashed are the bytes handed to onnxruntime (no
    second read of the path), so the file cannot be swapped between check and
    load."""
    import onnxruntime as ort  # lazy: heavy, optional

    path = verify(name)
    with open(path, "rb") as fh:
        blob = fh.read()
    expected = _manifest()[name]["sha256"].lower()
    if hashlib.sha256(blob).hexdigest() != expected:
        raise ModelIntegrityError("OCR model %s changed while loading; refusing it" % name)
    opts = ort.SessionOptions()
    opts.log_severity_level = 4
    opts.enable_cpu_mem_arena = False
    opts.enable_mem_pattern = False      # input sizes vary (tiles, crops): no per-shape plans
    opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    opts.intra_op_num_threads = INTRA_OP_THREADS
    opts.inter_op_num_threads = INTER_OP_THREADS
    return ort.InferenceSession(blob, sess_options=opts, providers=["CPUExecutionProvider"])


def run(sess, x):
    inp = sess.get_inputs()[0].name
    return sess.run(None, {inp: x})
