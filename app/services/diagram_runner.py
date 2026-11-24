"""Runs Diagram Studio recognitions. Entry point of ``satom-diagrams.service``.

THE WEB WORKER NEVER PARSES AN UPLOADED FILE. A draw.io, Visio, SVG or PDF
file is hostile input: XML, ZIP and PDF parsers are where memory bombs and
parser bugs live, and the web worker holds the database connection and
``FERNET_KEY``. So the web side only:

* stores the bytes content-addressed in ``data/diagrams/sources/<sha256>``
  (0600, deduplicated) -- :func:`store_source`;
* writes a request atomically (dot-file, then rename) into
  ``data/diagrams/queue/<job>.json`` -- :func:`enqueue`;
* reads ``data/diagrams/status/<job>.json`` and
  ``data/diagrams/results/<job>.json.gz`` back -- :func:`read_status`,
  :func:`read_result`.

DATABASE-FREE BY DESIGN, like ``script_runner``. The unit has no
``EnvironmentFile`` and this module imports no ORM. Each request runs in the
bubblewrap jail of :mod:`app.services.sandbox` (no network, no SATOM files:
only the venv, the engine directory read-only and a private work directory)
through a small worker script that imports ``diagram_engine`` and writes
``result.json`` / ``meta.json``. Back in this process the result is size-capped
and passed through ``diagram_engine.model.normalise`` -- pure Python; the
heavy libraries (pdfplumber, OpenCV, the OCR runtime) are only ever imported
inside the jail.

At-most-once, like the scripts runner: a request is MOVED to ``claimed/``
before it runs, so a crash cannot replay it, and a claim left behind by a
stopped runner is reported as failed by the next start.

:func:`run_sync` is the same jail for the two quick, synchronous questions the
web worker needs answered while the operator waits (the page list of a file,
a PDF page thumbnail) and for checking an uploaded symbol library: at most
:data:`SYNC_SLOTS` at a time per node (a ``flock`` slot), each with an address
space limit and a short timeout.
"""
from __future__ import annotations

import fcntl
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import sandbox

ENGINE_DIR = Path(__file__).resolve().parent / "diagram_engine"
APP_DIR = Path(os.environ.get("FM_APP_DIR") or Path(__file__).resolve().parents[2])

UNIT = "satom-diagrams.service"

MAX_FILE = 50 * 1024 * 1024           # per uploaded file
MAX_FILES = 20                        # per import request
MAX_PAGES = 50                        # pages read per file
MAX_RESULT = 32 * 1024 * 1024         # result.json / doc JSON
MAX_META = 1024 * 1024
MAX_PNG = 8 * 1024 * 1024             # page picture handed to the vision model
MAX_THUMB = 4 * 1024 * 1024
MAX_LIBRARY_RESULT = 40 * 1024 * 1024
MAX_OUTPUT = 64 * 1024
TIMEOUT = 180                         # one recognition, in the jail
SYNC_TIMEOUT = 30
VISION_TIMEOUT = 60
SYNC_SLOTS = 2
SYNC_LOCK_WAIT = 5.0
#: Address-space cap of a synchronous run (it runs inside satom.service, whose
#: cgroup is the web's): pdfplumber and pypdfium2 only -- numpy and the OCR
#: runtime, which reserve far more address space than they use, never run here.
SYNC_RLIMIT_AS = 1024 * 1024 * 1024
MAX_DRAIN = 20
MAX_PARALLEL = 2
STALE_CLAIM_AFTER = TIMEOUT + VISION_TIMEOUT + 300
RETENTION = 7 * 24 * 3600

JOB_RE = re.compile(r"^[0-9a-f]{32}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
PAGES_RE = re.compile(r"^(?:all|\d{1,3}(?:-\d{1,3})?(?:,\d{1,3}(?:-\d{1,3})?)*)$")
SYNC_KINDS = ("pages", "thumbnail", "library")

KILLED_MESSAGE = ("The recognition was killed: memory limit of %s (MemoryMax) reached. "
                  "The file is too large or too complex to recognise on this node." % UNIT)
SYNC_KILLED_MESSAGE = "The file could not be read within the memory limit of a quick check."


class RunnerError(ValueError):
    """A request the runner refuses; the message is shown to the operator."""


# ---------------------------------------------------------------- the tree

def root() -> Path:
    """``data/diagrams`` of this install (``SATOM_DIAGRAMS_DIR`` overrides it)."""
    env = os.environ.get("SATOM_DIAGRAMS_DIR")
    return Path(env) if env else APP_DIR / "data" / "diagrams"


def _d(name: str) -> Path:
    return root() / name


def python() -> str:
    """The interpreter the jail runs: the install's venv, else this one."""
    venv = APP_DIR / "venv" / "bin" / "python"
    return str(venv) if venv.is_file() else sys.executable


def new_job_id() -> str:
    return uuid.uuid4().hex


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mkdir(path: Path, mode: int = 0o750) -> Path:
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    return path


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write *path* through a dot-file in the same directory, then rename: a
    reader (or the queue watcher) never sees half a file."""
    _mkdir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_capped(path: Path, cap: int) -> bytes | None:
    """The bytes of a REGULAR file of at most *cap* bytes, else None. Opened
    with O_NOFOLLOW: the jail wrote these files, a symlink is never followed."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        import stat as _stat
        if not _stat.S_ISREG(st.st_mode) or st.st_size > cap:
            return None
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            data = fh.read(cap + 1)
        return data if len(data) <= cap else None
    finally:
        if fd >= 0:
            os.close(fd)


def _read_json(path: Path, cap: int = MAX_META) -> dict:
    raw = _read_capped(path, cap)
    if raw is None:
        return {}
    try:
        d = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


def _dumps(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, default=str).encode("utf-8")


# ------------------------------------------------------------ web side API

class TooLarge(RunnerError):
    pass


def store_source(stream, limit: int = MAX_FILE) -> tuple[str, int]:
    """Copy *stream* into ``sources/<sha256>`` (0600) without reading it into
    memory and without interpreting a byte. ``(sha256, size)``; raises
    :class:`TooLarge` past *limit*. Identical uploads share one file."""
    d = _mkdir(_d("sources"), 0o700)
    fd, tmp = tempfile.mkstemp(prefix=".up-", dir=str(d))
    h = hashlib.sha256()
    n = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                n += len(chunk)
                if n > limit:
                    raise TooLarge("larger than %d MiB" % (limit // (1024 * 1024)))
                h.update(chunk)
                out.write(chunk)
        sha = h.hexdigest()
        dst = d / sha
        if dst.is_file() and not dst.is_symlink():
            os.unlink(tmp)
            os.utime(dst)                 # a fresh upload keeps it out of the prune
        else:
            os.chmod(tmp, 0o600)
            os.replace(tmp, dst)
        return sha, n
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def source_path(sha: str) -> Path | None:
    if not SHA_RE.match(str(sha or "")):
        return None
    p = _d("sources") / sha
    return p if p.is_file() and not p.is_symlink() else None


def write_status(job: str, **fields: Any) -> dict:
    if not JOB_RE.match(job):
        raise RunnerError("bad job id")
    p = _d("status") / (job + ".json")
    st = _read_json(p)
    st["id"] = job
    st.update(fields)
    _atomic_write(p, _dumps(st), 0o640)
    return st


def read_status(job: str) -> dict:
    if not JOB_RE.match(str(job or "")):
        return {}
    return _read_json(_d("status") / (job + ".json"))


def read_result(job: str) -> dict | None:
    """The normalised document of a finished job, or None."""
    if not JOB_RE.match(str(job or "")):
        return None
    raw = _read_capped(_d("results") / (job + ".json.gz"), MAX_RESULT)
    if raw is None:
        return None
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            data = gz.read(MAX_RESULT + 1)
        if len(data) > MAX_RESULT:
            return None
        doc = json.loads(data.decode("utf-8"))
    except (OSError, EOFError, ValueError, UnicodeDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def forget_job(job: str) -> int:
    """Remove a job's request (when still queued), status and result files.
    A request already claimed runs to its end; its files are pruned later."""
    if not JOB_RE.match(str(job or "")):
        return 0
    n = 0
    for p in (_d("queue") / (job + ".json"), _d("status") / (job + ".json"),
              _d("results") / (job + ".json.gz")):
        try:
            p.unlink()
            n += 1
        except OSError:
            pass
    return n


def remove_source(sha: str) -> bool:
    """Delete a stored source and its thumbnails (the caller checked that no
    import or diagram references it)."""
    p = source_path(sha)
    if p is None:
        return False
    try:
        p.unlink()
    except OSError:
        return False
    thumbs = _d("thumbs")
    if thumbs.is_dir():
        for t in thumbs.glob(sha + "-*.png"):
            try:
                t.unlink()
            except OSError:
                pass
    return True


def enqueue(job: str, *, sha: str, filename: str, pages: str = "all", ocr: bool = True,
            classify: bool = True, libraries: list | None = None,
            vision: dict | None = None, vision_requested: bool = False) -> dict:
    """Queue one recognition. The request names the source by its hash; the
    operator libraries travel without their SVGs (the classifier reads their
    categories and aliases only)."""
    if not JOB_RE.match(job):
        raise RunnerError("bad job id")
    if not SHA_RE.match(sha) or source_path(sha) is None:
        raise RunnerError("the uploaded file is no longer stored")
    if not PAGES_RE.match(pages or "all"):
        raise RunnerError("bad page selection")
    req = {"job_id": job, "source_sha256": sha, "filename": str(filename or "")[:255],
           "pages": pages or "all", "ocr": bool(ocr), "classify": bool(classify),
           "libraries": [_lib_for_classify(l) for l in (libraries or [])],
           "vision": vision if isinstance(vision, dict) else None,
           "vision_requested": bool(vision_requested), "queued_at": _utcnow()}
    st = write_status(job, status="queued", filename=req["filename"], queued_at=req["queued_at"],
                      error="")
    _atomic_write(_d("queue") / (job + ".json"), _dumps(req), 0o600)
    return st


def _lib_for_classify(lib: dict) -> dict:
    return {"id": lib.get("id"), "label": lib.get("label"),
            "families": lib.get("families") or {},
            "symbols": [{k: v for k, v in s.items() if k != "svg_text"}
                        for s in lib.get("symbols") or []]}


# --------------------------------------------------------- the jailed worker

#: Runs INSIDE the jail with nothing but the venv, the engine and its own work
#: directory. It reads ``request.json`` and ``source.bin`` and writes JSON (or
#: ``out.png``); every failure is ``error.json`` plus a non-zero exit code.
WORKER_SRC = r'''
import json, os, sys, time

def _out(name, obj):
    with open(name + ".tmp", "w", encoding="utf-8") as fh:
        json.dump(obj, fh, separators=(",", ":"))
    os.replace(name + ".tmp", name)

def _fail(msg, code, kind="failed"):
    _out("error.json", {"error": str(msg)[:1000], "kind": kind})
    sys.exit(code)

def _refuse(msg):
    """The file is refused (unsupported, legacy, encrypted, not a line
    drawing, a page that is not there...): status ``refused``, exit 2."""
    _fail(msg, 2, "refused")

# The sentences importers.guarded (and the PDF opener) give a reader that
# CRASHED: those are failures. Every other ImportFailed a reader raises is a
# deliberate refusal with a message the operator can act on.
CRASH_PREFIXES = ("The file could not be interpreted (", "The file could not be read as a PDF (",
                  "The diagram is nested too deeply", "The diagram is too large to be read",
                  "The diagram is not valid:")

with open("request.json", encoding="utf-8") as fh:
    REQ = json.load(fh)
if REQ.get("rlimit_as"):
    import resource
    lim = int(REQ["rlimit_as"])
    resource.setrlimit(resource.RLIMIT_AS, (lim, lim))
sys.path.insert(0, REQ["engine_parent"])
MAX_PAGES = int(REQ.get("max_pages") or 50)


def detect_or_refuse(data, filename):
    """``detect`` only ever refuses (unsupported or legacy format, a hostile
    container): any ImportFailed / UnsafeInput it raises is a refusal."""
    from diagram_engine import detect as D, importers as I, xmlsafe as X
    try:
        return D.detect(data, filename)
    except (I.ImportFailed, X.UnsafeInput) as exc:
        _refuse(exc)


def parse_spec(spec, n):
    if spec in (None, "", "all"):
        return list(range(min(n, MAX_PAGES)))
    out = []
    for part in str(spec).split(","):
        a, _, b = part.partition("-")
        lo, hi = int(a), int(b or a)
        if lo < 1 or hi < lo or hi > n:
            _refuse("Page selection %r is outside the file's %d page(s)." % (part, n))
        for i in range(lo - 1, hi):
            if i not in out:
                out.append(i)
    if len(out) > MAX_PAGES:
        _refuse("%d pages selected; at most %d are read per file." % (len(out), MAX_PAGES))
    return out


def page_png(data, fmt, first_page_id):
    import io
    if fmt == "pdf":
        from diagram_engine.importers import pdf as P
        idx = int(first_page_id) - 1 if str(first_page_id or "").isdigit() else 0
        return P.thumbnail(data, idx, max_px=1600)
    if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) <= 8 * 1024 * 1024:
        return data
    from diagram_engine.importers import raster as R
    im, _f = R.open_image(data)
    im.seek(0)
    im = im.convert("RGB")
    im.thumbnail((2000, 2000))
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    return buf.getvalue()


def run_import(data):
    from diagram_engine import detect as D, importers as I, model as M
    t = {}
    t0 = time.monotonic()
    filename = REQ.get("filename") or ""
    fmt = detect_or_refuse(data, filename)
    t["detect_ms"] = int((time.monotonic() - t0) * 1000)
    read, list_pages = I.get(fmt)
    ocr = bool(REQ.get("ocr", True))

    def call(page):
        if fmt == "raster":
            return read(data, filename=filename, page=page, options={"ocr": ocr})
        if fmt == "pdf":
            hook = None
            if ocr:
                from diagram_engine.importers import raster as R
                hook = lambda png, fn: R.read_png_page(png, fn, options={"ocr": True})
            return read(data, filename=filename, page=page, raster_reader=hook)
        return read(data, filename=filename, page=page)

    t1 = time.monotonic()
    spec = REQ.get("pages") or "all"
    first = None
    if spec == "all":
        doc = call(None)
    else:
        pages = list_pages(data)
        wanted = parse_spec(spec, len(pages))
        first = pages[wanted[0]]["id"] if wanted else None
        if len(wanted) == len(pages):
            doc = call(None)
        else:
            docs = [call(pages[i]["id"]) for i in wanted]
            doc = docs[0]
            warns = list(doc["recognition"].get("warnings") or [])
            for d in docs[1:]:
                warns += [w for w in d["recognition"].get("warnings") or [] if w not in warns]
            doc["pages"] = [p for d in docs for p in d["pages"]]
            doc["recognition"]["warnings"] = warns[:500]
            doc, _w = M.normalise(doc)
    t["read_ms"] = int((time.monotonic() - t1) * 1000)

    classification = {}
    libs = []
    if REQ.get("classify", True) or REQ.get("vision"):
        from diagram_engine import symbols as S
        libs = list(S.load_builtin().values()) + list(REQ.get("libraries") or [])
    own_export = bool((doc.get("metadata") or {}).get("satom_export"))
    if REQ.get("classify", True) and own_export:
        # SATOM wrote this file: every element already has exactly the
        # category its author left (or none, on purpose). Classifying again
        # would change the diagram on a plain export -> import round trip.
        classification = {"families": {}, "unknown": [], "conflicts": [], "classified": 0,
                          "by_source": {}, "connector_kinds": {},
                          "skipped": "exported by SATOM: categories kept as the author left them"}
    elif REQ.get("classify", True):
        from diagram_engine import classify as C
        t2 = time.monotonic()
        doc, rep = C.classify(doc, libs)
        t["classify_ms"] = int((time.monotonic() - t2) * 1000)
        classification = {"families": rep.get("by_family", {}), "unknown": rep.get("unknown", [])[:1000],
                          "conflicts": rep.get("conflicts", [])[:200],
                          "classified": rep.get("classified", 0), "by_source": rep.get("by_source", {}),
                          "connector_kinds": rep.get("connector_kinds", {})}
    meta = {"format": fmt, "classification": classification, "timings": t}
    if REQ.get("vision"):
        if fmt in ("raster", "pdf"):
            try:
                png = page_png(data, fmt, first if first is not None else "1")
                if png and len(png) <= 8 * 1024 * 1024:
                    with open("page.png", "wb") as fh:
                        fh.write(png)
            except Exception as exc:  # noqa: BLE001 -- refinement is optional
                meta["vision_note"] = "the page picture could not be made (%s)" % type(exc).__name__
            meta["categories"] = sorted({s["category"] for l in libs for s in l.get("symbols", [])})[:2000]
        else:
            meta["vision_note"] = "vision refinement applies to images and PDF pages only"
    t["total_ms"] = int((time.monotonic() - t0) * 1000)
    _out("result.json", doc)
    _out("meta.json", meta)


def run_pages(data):
    from diagram_engine import importers as I
    fmt = detect_or_refuse(data, REQ.get("filename") or "")
    _read, list_pages = I.get(fmt)
    pages = list_pages(data)[:500]
    _out("result.json", {"format": fmt,
                         "pages": [{"id": str(p.get("id"))[:64], "name": str(p.get("name"))[:200]}
                                   for p in pages]})


def run_thumbnail(data):
    from diagram_engine.importers import pdf as P
    if detect_or_refuse(data, REQ.get("filename") or "") != "pdf":
        _refuse("Thumbnails are made for PDF files only.")
    png = P.thumbnail(data, int(REQ.get("page_index") or 0), max_px=int(REQ.get("max_px") or 480))
    with open("out.png", "wb") as fh:
        fh.write(png)


def run_library(data):
    import io
    from diagram_engine import symbols as S, xmlsafe as X
    if data[:4] not in (b"PK\x03\x04", b"PK\x05\x06"):
        _fail("Upload a ZIP of SVG icons, or a ZIP holding library.json and its SVG files.", 2)
    try:
        zf = X.open_zip(io.BytesIO(data))
        members = [i.filename for i in zf.infolist() if not i.is_dir()]
        jl = [n for n in members if n.rsplit("/", 1)[-1] == "library.json"]
        if jl:
            obj = json.loads(X.read_member(zf, jl[0], 4 * 1024 * 1024).decode("utf-8"))
            if not isinstance(obj, dict):
                _fail("library.json is not a JSON object.", 2)
            if REQ.get("lib_id"):
                obj["id"] = REQ["lib_id"]
            if REQ.get("label"):
                obj["label"] = REQ["label"]
            by_name = {}
            for n in members:
                if n.lower().endswith(".svg"):
                    by_name.setdefault(n.rsplit("/", 1)[-1], n)
            svgs = {}
            for s in obj.get("symbols") or []:
                name = s.get("svg") if isinstance(s, dict) else None
                if isinstance(name, str) and name in by_name and name not in svgs:
                    svgs[name] = X.read_member(zf, by_name[name], S.MAX_SVG_BYTES)
            lib = S.load_library(obj, svgs)
        else:
            lib = S.import_svg_zip(data, REQ.get("lib_id") or "", REQ.get("label") or "",
                                   REQ.get("family") or "generic")
    except S.LibraryError as exc:
        _fail(exc, 2)
    except X.UnsafeInput as exc:
        _fail(exc, 2)
    except ValueError as exc:
        _fail("library.json is not valid JSON (%s)." % exc, 2)
    form = {"schema": S.SCHEMA, "id": lib["id"], "label": lib["label"], "version": lib.get("version", ""),
            "license": lib.get("license", ""), "families": lib.get("families", {}),
            # The style travels too: without it every operator library -- a
            # library.json that says "color", a colour SVG pack -- was stored flat.
            "variant": lib.get("variant") or "flat",
            "symbols": [{k: v for k, v in s.items() if k != "svg_text"} for s in lib["symbols"]]}
    if lib.get("anchor") is not None:
        form["anchor"] = lib["anchor"]
    _out("result.json", {"library": form,
                         "svgs": {s["svg"]: s["svg_text"] for s in lib["symbols"]},
                         "warnings": [str(w)[:300] for w in lib.get("warnings", [])][:50]})


def main():
    with open("source.bin", "rb") as fh:
        data = fh.read()
    from diagram_engine import importers as I, xmlsafe as X
    kind = REQ.get("kind")
    try:
        if kind == "import":
            run_import(data)
        elif kind == "pages":
            run_pages(data)
        elif kind == "thumbnail":
            run_thumbnail(data)
        elif kind == "library":
            run_library(data)
        else:
            _fail("unknown request kind", 2)
    except X.UnsafeInput as exc:
        _refuse(exc)
    except I.ImportFailed as exc:
        if str(exc).startswith(CRASH_PREFIXES):
            _fail(exc, 3)
        _refuse(exc)
    except MemoryError:
        _fail("The file is too large to be read within the memory limit.", 4)
    except RecursionError:
        _fail("The diagram is nested too deeply to be read.", 3)
    except Exception as exc:  # noqa: BLE001 -- the operator gets a sentence, never a traceback
        _fail("The file could not be interpreted (%s). It may be damaged or in an "
              "unsupported variant of the format." % type(exc).__name__, 3)


main()
'''


def _jail_env(workdir: str) -> dict[str, str]:
    """The COMPLETE environment of a jailed run, built from nothing."""
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": workdir,
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONIOENCODING": "utf-8",
            "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1",
            "OMP_NUM_THREADS": "2", "OPENBLAS_NUM_THREADS": "1", "MKL_NUM_THREADS": "1"}


def _prepare(src: Path, request: dict) -> str:
    """A fresh 0700 work directory holding the source, the worker and its request."""
    workdir = tempfile.mkdtemp(prefix="satom-diagram-")
    os.chmod(workdir, 0o700)
    shutil.copyfile(str(src), os.path.join(workdir, "source.bin"))
    with open(os.path.join(workdir, "worker.py"), "w", encoding="utf-8") as fh:
        fh.write(WORKER_SRC)
    req = dict(request, engine_parent=str(ENGINE_DIR.parent), max_pages=MAX_PAGES)
    with open(os.path.join(workdir, "request.json"), "w", encoding="utf-8") as fh:
        json.dump(req, fh)
    return workdir


def _execute(workdir: str, timeout: int, health=None) -> "sandbox.Outcome":
    return sandbox.execute(python(), "worker.py", workdir, env=_jail_env(workdir),
                           timeout=timeout, network="none", ro_binds=(str(ENGINE_DIR),),
                           max_output=MAX_OUTPUT, health=health)


def _error_kind(out, workdir: str) -> str:
    """``refused`` when the worker itself refused the file (exit 2 and
    ``kind: refused`` in error.json), else ``failed``."""
    if out.error or out.timed_out or out.exit_code != 2:
        return "failed"
    kind = _read_json(Path(workdir) / "error.json").get("kind")
    return "refused" if kind == "refused" else "failed"


def _outcome_error(out, workdir: str, timeout: int, killed: str) -> str | None:
    """None when the worker finished cleanly, else the operator's sentence."""
    if out.error:
        return out.error
    if out.timed_out:
        return "The recognition took longer than %d s and was stopped." % timeout
    if out.exit_code in (-9, 137):
        return killed
    if out.exit_code != 0:
        err = _read_json(Path(workdir) / "error.json").get("error")
        if isinstance(err, str) and err.strip():
            return err.strip()[:1000]
        return "The recogniser exited with code %s." % out.exit_code
    return None


# ------------------------------------------------------- result validation

def validate_result(workdir: str) -> tuple[dict, list[str]]:
    """``(normalised doc, normaliser warnings)`` of the jail's result.json.
    Refuses (RunnerError) a file larger than :data:`MAX_RESULT`, a symlink,
    invalid JSON or a document the model cannot repair."""
    from .diagram_engine import model
    p = Path(workdir) / "result.json"
    try:
        st = os.lstat(p)
    except OSError:
        raise RunnerError("The recogniser produced no result.") from None
    if not os.path.isfile(p) or os.path.islink(p):
        raise RunnerError("The recogniser's result is not a regular file.")
    if st.st_size > MAX_RESULT:
        raise RunnerError("The recognised diagram is larger than %d MiB and was refused."
                          % (MAX_RESULT // (1024 * 1024)))
    raw = _read_capped(p, MAX_RESULT)
    if raw is None:
        raise RunnerError("The recognised diagram is larger than %d MiB and was refused."
                          % (MAX_RESULT // (1024 * 1024)))
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise RunnerError("The recogniser's result is not valid JSON.") from None
    try:
        return model.normalise(doc)
    except model.ModelError as exc:
        raise RunnerError("The recognised diagram is not valid: %s" % exc) from None


def _str_list(v, limit: int, size: int = 64) -> list:
    return [str(x)[:size] for x in (v if isinstance(v, list) else [])[:limit]
            if isinstance(x, (str, int))]


def _num_map(v, limit: int = 64) -> dict:
    out = {}
    for k, x in (v.items() if isinstance(v, dict) else []):
        if len(out) >= limit:
            break
        if isinstance(x, (int, float)) and not isinstance(x, bool):
            out[str(k)[:64]] = x
    return out


def clean_meta(meta: dict) -> dict:
    """The jail's meta.json reduced to known keys and plain types."""
    cls = meta.get("classification") if isinstance(meta.get("classification"), dict) else {}
    conflicts = []
    for c in (cls.get("conflicts") if isinstance(cls.get("conflicts"), list) else [])[:200]:
        if not isinstance(c, dict):
            continue
        cands = []
        for k in (c.get("candidates") if isinstance(c.get("candidates"), list) else [])[:4]:
            if isinstance(k, dict):
                conf = k.get("confidence")
                cands.append({"category": str(k.get("category", ""))[:80],
                              "symbol": str(k.get("symbol", ""))[:150],
                              "source": str(k.get("source", ""))[:40],
                              "confidence": conf if isinstance(conf, (int, float)) else 0})
        conflicts.append({"element": str(c.get("element", ""))[:64],
                          "chosen": str(c.get("chosen", ""))[:80], "candidates": cands})
    classified = cls.get("classified")
    return {
        "format": str(meta.get("format") or "")[:32],
        "classification": {"families": _num_map(cls.get("families")),
                           "unknown": _str_list(cls.get("unknown"), 1000),
                           "conflicts": conflicts,
                           "classified": classified if isinstance(classified, int) else 0,
                           "by_source": _num_map(cls.get("by_source")),
                           "connector_kinds": _num_map(cls.get("connector_kinds")),
                           **({"skipped": str(cls["skipped"])[:200]}
                              if isinstance(cls.get("skipped"), str) and cls["skipped"] else {})},
        "timings": _num_map(meta.get("timings"), 20),
        "categories": [c for c in _str_list(meta.get("categories"), 2000, 80)
                       if re.match(r"^[a-z][a-z0-9_]{0,31}\.[a-z0-9_]{1,40}$", c)],
        "vision_note": str(meta.get("vision_note") or "")[:200],
    }


def _refine(doc: dict, png: bytes, vision: dict, categories: list) -> tuple[dict, str]:
    """``vision.refine`` OUTSIDE the jail (it only sends the page picture and
    the element list to the configured endpoint), bounded by a wall clock the
    socket timeout alone cannot give."""
    from .diagram_engine import model
    from .diagram_engine import vision as V
    box: dict = {}

    def go():
        try:
            box["doc"] = V.refine(doc, png, str(vision.get("endpoint") or ""),
                                  str(vision.get("model") or ""), timeout=VISION_TIMEOUT,
                                  categories=set(categories) or None)
        except Exception as exc:  # noqa: BLE001 -- refinement is optional
            box["error"] = "Vision refinement was not applied (%s)." % (
                str(exc)[:200] if isinstance(exc, ValueError) else type(exc).__name__)

    th = threading.Thread(target=go, daemon=True, name="satom-diagram-vision")
    th.start()
    th.join(VISION_TIMEOUT + 5)
    if th.is_alive():
        return doc, "Vision refinement timed out after %d s and was not applied." % VISION_TIMEOUT
    if "doc" not in box:
        return doc, box.get("error", "Vision refinement was not applied.")
    try:
        return model.normalise(box["doc"])[0], ""
    except model.ModelError:
        return doc, "Vision refinement returned an invalid document and was not applied."


# ------------------------------------------------------------ one request

def run_request(req: dict) -> dict:
    job = req["job_id"]
    t0 = time.monotonic()
    write_status(job, status="running", started_at=_utcnow())

    def fail(msg: str, status: str = "failed", **extra) -> dict:
        return write_status(job, status=status, error=msg, finished_at=_utcnow(),
                            duration_ms=int((time.monotonic() - t0) * 1000), **extra)

    src = source_path(str(req.get("source_sha256") or ""))
    if src is None:
        return fail("The uploaded file is no longer stored on this node.")
    pages = str(req.get("pages") or "all")
    if not PAGES_RE.match(pages):
        return fail("Bad page selection.")
    libs = req.get("libraries") if isinstance(req.get("libraries"), list) else []
    request = {"kind": "import", "filename": str(req.get("filename") or "")[:255],
               "pages": pages, "ocr": bool(req.get("ocr", True)),
               "classify": bool(req.get("classify", True)), "libraries": libs,
               "vision": bool(isinstance(req.get("vision"), dict)
                              and req["vision"].get("endpoint") and req["vision"].get("model"))}
    workdir = _prepare(src, request)
    try:
        out = _execute(workdir, TIMEOUT, health=str(root() / sandbox.HEALTH_NAME))
        err = _outcome_error(out, workdir, TIMEOUT, KILLED_MESSAGE)
        if err:
            if out.exit_code not in (0, 2) and out.output:
                sys.stderr.write("diagram_runner: %s exit %s: %s\n"
                                 % (job, out.exit_code, out.output[-300:].replace("\n", " | ")))
            return fail(err, _error_kind(out, workdir))
        try:
            doc, _w = validate_result(workdir)
        except RunnerError as exc:
            return fail(str(exc))
        meta = clean_meta(_read_json(Path(workdir) / "meta.json"))
        extra_warnings = []
        if request["vision"]:
            png = _read_capped(Path(workdir) / "page.png", MAX_PNG)
            if png:
                doc, note = _refine(doc, png, req["vision"], meta["categories"])
            else:
                note = "Vision refinement was not applied: %s." % (
                    meta["vision_note"] or "no page picture was made")
            if note:
                extra_warnings.append(note)
        elif req.get("vision_requested"):
            extra_warnings.append("Vision refinement is not configured on this node.")
        if extra_warnings:
            ws = doc["recognition"]["warnings"]
            doc["recognition"]["warnings"] = (ws + extra_warnings)[:500]
        from .diagram_engine import model
        _atomic_write(_d("results") / (job + ".json.gz"),
                      gzip.compress(_dumps(doc), compresslevel=6), 0o600)
        timings = dict(meta["timings"])
        timings["runner_ms"] = int((time.monotonic() - t0) * 1000)
        return write_status(job, status="ok", error="", format=meta["format"],
                            stats=model.stats(doc),
                            warnings=doc["recognition"]["warnings"][:500],
                            classification=meta["classification"], timings=timings,
                            finished_at=_utcnow(),
                            duration_ms=int((time.monotonic() - t0) * 1000))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def process_request_file(path: Path) -> dict | None:
    """Claim (move) one request, then run it. At most once: a request that
    another runner moved first, or that cannot be read, is not run here."""
    path = Path(path)
    claimed = _mkdir(_d("claimed"))
    claim = claimed / path.name
    try:
        os.replace(path, claim)
    except OSError:
        return None                       # another runner took it
    try:
        raw = _read_capped(claim, MAX_META)
        try:
            req = json.loads(raw.decode("utf-8")) if raw is not None else None
        except (UnicodeDecodeError, ValueError):
            req = None
        if not isinstance(req, dict) or not JOB_RE.match(str(req.get("job_id") or "")) \
                or req["job_id"] + ".json" != path.name:
            return None
        # The claim stays as the "running" marker.
        _atomic_write(claim, _dumps({"job_id": req["job_id"], "claimed_at": _utcnow()}), 0o600)
        try:
            return run_request(req)
        except Exception as exc:  # noqa: BLE001 -- never leave "running" behind
            return write_status(req["job_id"], status="failed", finished_at=_utcnow(),
                                error="runner error: %s" % type(exc).__name__)
    finally:
        try:
            claim.unlink()
        except OSError:
            pass


def reconcile_stale_claims(now: float | None = None) -> list[str]:
    d = _d("claimed")
    if not d.is_dir():
        return []
    now = time.time() if now is None else now
    out = []
    for p in sorted(d.glob("*.json")):
        try:
            if now - p.stat().st_mtime < STALE_CLAIM_AFTER:
                continue
        except OSError:
            continue
        if JOB_RE.match(p.stem):
            write_status(p.stem, status="failed", finished_at=_utcnow(),
                         error="The diagrams runner stopped while this recognition was in "
                               "progress (node restart?). Import the file again.")
        try:
            p.unlink()
        except OSError:
            pass
        out.append(p.stem)
    return out


def prune(now: float | None = None) -> int:
    """Forget what is older than :data:`RETENTION`: status records, results,
    thumbnails and rejected queue files. NOT the stored sources: they are
    shared by content and referenced from the database (imports, diagrams),
    which this process cannot read -- ``diagram_studio.purge_imports`` in the
    web removes the ones nothing references."""
    now = time.time() if now is None else now
    n = 0
    for name in ("status", "results", "thumbs", "rejected"):
        d = _d(name)
        if not d.is_dir():
            continue
        for p in d.iterdir():
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                if now - p.stat().st_mtime > RETENTION:
                    p.unlink()
                    n += 1
            except OSError:
                continue
    return n


def main() -> int:
    reconcile_stale_claims()
    try:
        prune()
    except OSError as exc:
        sys.stderr.write("diagram_runner: pruning failed: %s\n" % exc)
    queue = _d("queue")
    if not queue.is_dir():
        return 0
    stray = sandbox.sweep_queue(queue, _d("rejected"))
    if stray:
        sys.stderr.write("diagram_runner: moved out of the queue: %s\n" % ", ".join(stray))
    batch = sorted(p for p in queue.glob("*.json")
                   if not p.name.startswith(".") and p.is_file() and not p.is_symlink())[:MAX_DRAIN]
    if not batch:
        return 0

    def one(p):
        try:
            return process_request_file(p)
        except Exception as exc:  # noqa: BLE001 -- one bad request, not the queue
            sys.stderr.write("diagram_runner: %s failed: %s\n" % (p.name, type(exc).__name__))
            try:
                p.unlink()
            except OSError:
                pass
            return None

    with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
        list(pool.map(one, batch))
    return 0


# --------------------------------------------------- synchronous jailed help

class Busy(RunnerError):
    """Every synchronous slot of this node is taken."""


def _lock_path(i: int) -> str:
    return os.path.join(tempfile.gettempdir(), "satom-diagram-sync-%d.lock" % i)


def _acquire_slot(wait: float = SYNC_LOCK_WAIT):
    deadline = time.monotonic() + wait
    while True:
        for i in range(SYNC_SLOTS):
            fh = open(_lock_path(i), "a+")
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fh
            except OSError:
                fh.close()
        if time.monotonic() > deadline:
            return None
        time.sleep(0.2)


def run_sync(kind: str, src_path, args: dict | None = None, timeout: int = SYNC_TIMEOUT) -> dict:
    """One quick question about a stored upload, answered in the jail.

    ``kind``: ``pages`` -> ``{"format", "pages": [{id, name}]}``;
    ``thumbnail`` -> PNG bytes; ``library`` -> ``{"library", "svgs", "warnings"}``.
    Returns ``{"ok": True, "result": ...}`` or ``{"ok": False, "error": str,
    "busy": bool}``; never parses the file in this process."""
    if kind not in SYNC_KINDS:
        raise ValueError("unknown kind %r" % kind)
    src = Path(src_path)
    if not src.is_file() or src.is_symlink():
        return {"ok": False, "busy": False, "error": "The uploaded file is no longer stored."}
    slot = _acquire_slot(SYNC_LOCK_WAIT)
    if slot is None:
        return {"ok": False, "busy": True,
                "error": "Diagram Studio is busy reading other files on this node; try again "
                         "in a moment."}
    workdir = None
    try:
        request = dict(args or {}, kind=kind, rlimit_as=SYNC_RLIMIT_AS)
        workdir = _prepare(src, request)
        out = _execute(workdir, int(timeout))
        err = _outcome_error(out, workdir, int(timeout), SYNC_KILLED_MESSAGE)
        if err:
            return {"ok": False, "busy": False, "error": err,
                    "refused": _error_kind(out, workdir) == "refused"}
        if kind == "thumbnail":
            png = _read_capped(Path(workdir) / "out.png", MAX_THUMB)
            if not png or not png.startswith(b"\x89PNG\r\n\x1a\n"):
                return {"ok": False, "busy": False, "error": "No thumbnail was produced."}
            return {"ok": True, "result": png}
        cap = MAX_LIBRARY_RESULT if kind == "library" else MAX_META
        raw = _read_capped(Path(workdir) / "result.json", cap)
        try:
            res = json.loads(raw.decode("utf-8")) if raw is not None else None
        except (UnicodeDecodeError, ValueError):
            res = None
        if not isinstance(res, dict):
            return {"ok": False, "busy": False, "error": "The check produced no usable answer."}
        return {"ok": True, "result": res}
    finally:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)
        try:
            fcntl.flock(slot, fcntl.LOCK_UN)
        finally:
            slot.close()


if __name__ == "__main__":  # pragma: no cover -- exercised by the systemd unit
    raise SystemExit(main())
