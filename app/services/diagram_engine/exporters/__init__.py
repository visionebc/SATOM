"""Diagram Studio exporters: ``satom.diagram/1`` -> draw.io, SVG, PDF.

``EXPORTERS[fmt](doc, page=None | "all" | index | page_id, options=None)``
returns ``(bytes, mime, filename)`` and raises :class:`ExportFailed` (a
``ValueError`` whose message is safe to show) when the document cannot be
written. Writers are imported lazily; PDF needs reportlab only when used.
"""
from __future__ import annotations

from ._common import ExportFailed

__all__ = ["EXPORTERS", "ExportFailed", "export"]


def _lazy(name: str):
    def run(doc, *, page=None, options=None):
        from importlib import import_module
        return import_module("." + name, __name__).export(doc, page=page, options=options)
    run.__name__ = "export_" + name
    return run


EXPORTERS = {"drawio": _lazy("drawio"), "svg": _lazy("svg"), "pdf": _lazy("pdf")}


def export(fmt: str, doc, *, page=None, options=None):
    try:
        fn = EXPORTERS[fmt]
    except KeyError:
        raise ExportFailed("unknown export format %r" % str(fmt)[:20]) from None
    return fn(doc, page=page, options=options)
