"""Importers: one reader per source format, all producing ``satom.diagram/1``.

Every reader module exposes::

    read(data: bytes, *, filename: str = "", page: str | None = None) -> dict
    list_pages(data: bytes) -> list[{"id", "name"}]        (multi-page formats)

``read`` returns the NORMALISED document (``model.normalise`` has run) and
raises only :class:`ImportFailed` (bad or unsupported input, with a message an
operator can act on) or :class:`..xmlsafe.UnsafeInput` (hostile input refused).
Nothing else escapes: :func:`guarded` turns any unexpected exception into an
``ImportFailed`` so a malformed file can never surface as a traceback.

A page is selected by its id or, failing that, its 1-based index as a string.
"""
from __future__ import annotations

import functools
import hashlib
import importlib
import os
import re

from .. import model, xmlsafe


class ImportFailed(ValueError):
    """The file cannot be imported; the message is shown to the operator."""


#: format -> reader module (lazily imported)
READERS = {"drawio": "drawio", "drawio-svg": "drawio", "vsdx": "visio", "vdx": "visio",
           "mermaid": "textual", "dot": "textual", "svg": "svg", "pdf": "pdf",
           "raster": "raster"}


def _single_page(data: bytes) -> list:
    return [{"id": "page-1", "name": "Page 1"}]


def get(fmt: str):
    """``(read, list_pages)`` of the reader for *fmt* (imported on first use)."""
    name = READERS.get(fmt)
    if not name:
        raise ImportFailed("No reader for format %r." % str(fmt)[:40])
    try:
        mod = importlib.import_module("." + name, __name__)
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.endswith("." + name):
            raise ImportFailed("The %s reader is not installed in this build." % fmt) from None
        raise
    return mod.read, getattr(mod, "list_pages", _single_page)


def guarded(fn):
    """Turn every unexpected exception of a reader into :class:`ImportFailed`."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (xmlsafe.UnsafeInput, ImportFailed):
            raise
        except model.ModelError as exc:
            raise ImportFailed("The diagram is not valid: %s" % exc) from None
        except RecursionError:
            raise ImportFailed("The diagram is nested too deeply to be read.") from None
        except MemoryError:
            raise ImportFailed("The diagram is too large to be read.") from None
        except Exception as exc:  # noqa: BLE001 -- the contract: nothing else escapes
            raise ImportFailed("The file could not be interpreted (%s). It may be damaged or "
                               "in an unsupported variant of the format." % type(exc).__name__) from None
    return wrapper


def require_bytes(data) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, (bytes, bytearray)):
        raise ImportFailed("Expected the file content as bytes.")
    if not data.strip():
        raise ImportFailed("The file is empty.")
    return bytes(data)


def doc_name(filename: str, fallback: str) -> str:
    stem = os.path.splitext(os.path.basename(str(filename or "").replace("\\", "/")))[0]
    stem = re.sub(r"[\x00-\x1f]", "", stem).strip()
    return stem[:model.MAX_NAME] or fallback


def select_page(pages: list, page) -> list:
    """Keep the page named by *page* (id first, then 1-based index); all if None/''."""
    if page in (None, ""):
        return pages
    want = str(page)
    for p in pages:
        if str(p["id"]) == want:
            return [p]
    if want.isdigit() and 1 <= int(want) <= len(pages):
        return [pages[int(want) - 1]]
    raise ImportFailed("Page %r not found; the file has %d page(s)." % (want[:40], len(pages)))


class Warnings:
    """Warnings collected once per kind, in first-seen order."""

    def __init__(self):
        self.items: list = []
        self._seen: set = set()

    def once(self, kind: str, message: str) -> None:
        if kind not in self._seen:
            self._seen.add(kind)
            self.items.append(message)

    def add(self, message: str) -> None:
        if len(self.items) < 200:
            self.items.append(message)


def make_document(*, fmt: str, engine: str, data: bytes, filename: str, name: str,
                  pages: list, warnings: list, page=None, metadata: dict | None = None) -> dict:
    """Assemble, normalise and annotate the final document."""
    doc = {"schema": model.SCHEMA, "name": name, "metadata": metadata or {},
           "source": {"format": fmt, "filename": str(filename or "")[:255],
                      "sha256": hashlib.sha256(data).hexdigest(),
                      "page": "" if page in (None, "") else str(page)},
           "recognition": {"engine": engine, "version": "1", "warnings": [], "stats": {}},
           "pages": pages}
    out, norm_warnings = model.normalise(doc)
    merged = list(warnings)
    for w in norm_warnings:
        if w not in merged and len(merged) < 450:
            merged.append(w)
    out["recognition"]["warnings"] = [str(w)[:500] for w in merged[:500]]
    st = model.stats(out)
    out["recognition"]["stats"] = {k: v for k, v in st.items() if isinstance(v, (int, float))}
    return out
