"""GUI layout changes between two builds (Round 5 of the GUI-templates plan).

Thin layer over the vendored :func:`satom_guikit.diff`: for every page that has
a layout template, resolve the template of each build (:mod:`gui_store`) and
list what Fortinet changed on screen — a field added or removed, moved to
another section, shown under another condition, an option gained or lost, a
label renamed. Only layouts MEASURED on the build (``closeness`` ``build`` or
``version``) are compared: a build drawn from a neighbour's layout cannot say
what changed, and the result says so instead of reporting "no change".
"""
from __future__ import annotations

import logging

from ..vendor import satom_guikit as guikit

log = logging.getLogger(__name__)

MEASURED = ("build", "version")


def pages(product: str) -> list:
    from . import gui_store
    out = set()
    try:
        r = gui_store.root() / product
    except RuntimeError:            # no app context: no data dir, no layouts
        return []
    if r.is_dir():
        out.update(p.name for p in r.iterdir() if p.is_dir())
    return sorted(out)


def layout_of(product: str, page: str, firmware) -> tuple:
    """``(template | None, info)`` with ``info = {version, build, closeness, source}``."""
    from . import gui_store
    cand, _match, closeness = gui_store.resolve(product, page, firmware)
    if cand is None:
        return None, {"closeness": None}
    return gui_store.load(cand["path"]), {"version": cand["version"], "build": cand["build"],
                                          "closeness": closeness, "source": cand["source"]}


def between(product: str, source, target) -> dict:
    """``{"pages": [{page, source, target, measured, changes, summary, note}]}``."""
    out = []
    for page in pages(product):
        try:
            a, ia = layout_of(product, page, source)
            b, ib = layout_of(product, page, target)
        except Exception:  # noqa: BLE001 — a report never fails on the GUI block
            log.exception("gui_diff: %s %s", product, page)
            continue
        entry = {"page": page, "source": ia, "target": ib, "measured": False,
                 "changes": [], "summary": {}, "note": ""}
        if a is None or b is None:
            continue
        if ia["closeness"] not in MEASURED or ib["closeness"] not in MEASURED:
            miss = [str(v) for v, i in ((source, ia), (target, ib))
                    if i["closeness"] not in MEASURED]
            entry["note"] = ("no GUI layout was measured on %s: changes to this page cannot "
                             "be listed" % " / ".join(miss))
        else:
            entry["measured"] = True
            entry["changes"] = guikit.diff(a, b)
            from ..vendor.satom_guikit.diff import summary
            entry["summary"] = summary(entry["changes"])
        out.append(entry)
    return {"pages": out}


def not_in_gui_fields(product: str, endpoint: str, firmware, names) -> list | None:
    """Of ``names``, the ones the MEASURED layout of ``firmware`` does not place
    for ``endpoint``; None when no measured layout covers the endpoint."""
    from . import not_in_gui as nig
    page = nig.LAYOUT_PAGES.get((product, nig.endpoint_key(endpoint)))
    if not page:
        return None
    tpl, info = layout_of(product, page, firmware)
    if tpl is None or info["closeness"] not in MEASURED:
        return None
    placed = nig._template_keys(tpl, nig.endpoint_key(endpoint))
    return sorted(n for n in names if n not in placed and n != "name")
