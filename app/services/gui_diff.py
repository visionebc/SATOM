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


def _state(product: str, page: str, firmware) -> dict:
    """The page's state on one build (:func:`gui_pages.page_state`, the same
    answer the menu and the page banner give)."""
    from . import gui_pages
    try:
        return gui_pages.page_state(product, page, firmware)
    except Exception:  # noqa: BLE001 -- a report never fails on the GUI block
        log.exception("gui_diff: page_state %s %s", product, page)
        return {"present": "unknown", "checked": False}


def _note(states: dict) -> str:
    """Why a page's changes cannot be listed, per build whose layout was not
    measured: the object is absent there (measured), present there but with
    no layout of its own, or not known."""
    parts = []
    for fw, st in states.items():
        if st["present"] == "no":
            tail = ""
            if st.get("since"):
                tail = " (served from %s)" % st["since"]
            elif st.get("until"):
                tail = " (served up to %s)" % st["until"]
            parts.append("%s does not have this page's object (measured)%s" % (fw, tail))
        elif st["present"] == "yes":
            parts.append("the object exists on %s but no GUI layout was measured there" % fw)
        else:
            parts.append("no GUI layout was measured on %s and the library has no evidence "
                         "for its object there" % fw)
    return "; ".join(parts) + ": changes to this page cannot be listed"


def _title(tpl, dialog, *, fallback=False):
    from . import gui_pages
    return gui_pages.dialog_title(tpl, dialog, "edit", fallback=fallback)


def _with_titles(changes: list, a: dict, b: dict) -> list:
    """The changes of ``guikit.diff`` plus ``title``: the dialog's own title from
    the template that HAS the dialog (a removed dialog only exists in ``a``);
    a dialog neither template titles is named by ``gui_pages.dialog_title``
    (the label that opens it, the page's menu label, a humanised id) -- the
    raw template id is only ever the tooltip."""
    out = []
    for c in changes:
        c = dict(c)
        d = c["dialog"]
        if c["kind"] == "dialog_removed":
            # nothing names it any more but the entry that opened it; failing
            # that its id as words (the page's menu label would call a dialog
            # that is gone "<page> (new)")
            from . import gui_pages
            c["title"] = gui_pages.dialog_title(a, d, "edit", page_fallback=False)
        else:
            own = _title(b, d) or _title(a, d)
            c["title"] = own or _title(b, d, fallback=True)
        out.append(c)
    return out


def _label_of(tpl: dict | None, page: str) -> str:
    path = (tpl or {}).get("menu_path") or []
    return str(path[-1]) if path else page


def _twin_pairs(product: str, source, target) -> dict:
    """``{target_page: source_page}`` for the pages that are the SAME object
    under two names (Let's Encrypt / ACME, OCSP, Mobile API: the twin rule the
    menu and the page redirect use, :func:`gui_pages._twin_groups`) and whose
    layout is measured under one name on the source build and under the other
    on the target build. Compared by name they read "no layout measured there";
    compared as the same page they say what changed."""
    from . import gui_pages
    pairs: dict = {}
    try:
        groups = gui_pages._twin_groups(product)
    except Exception:  # noqa: BLE001 -- a report never fails on the GUI block
        log.exception("gui_diff: twin groups %s", product)
        return pairs
    for g in groups:
        close = {}
        for p in sorted(g):
            try:
                close[p] = (layout_of(product, p, source)[1]["closeness"],
                            layout_of(product, p, target)[1]["closeness"])
            except Exception:  # noqa: BLE001
                log.exception("gui_diff: twin %s %s", product, p)
        for s_page in sorted(close):
            for t_page in sorted(close):
                if s_page == t_page or t_page in pairs or s_page in pairs.values():
                    continue
                # measured under its own name on one side only, and the other
                # name measured on the other side only
                if close[s_page][0] in MEASURED and close[s_page][1] not in MEASURED \
                        and close[t_page][1] in MEASURED and close[t_page][0] not in MEASURED:
                    pairs[t_page] = s_page
    return pairs


def between(product: str, source, target) -> dict:
    """``{"pages": [{page, source, target, measured, changes, summary, note,
    twin}]}``. ``twin`` (``{source_page, source_label, target_page,
    target_label}``) is set when the page is the same object under two names
    and the two layouts are compared as ONE page."""
    out = []
    twins = _twin_pairs(product, source, target)
    covered = set(twins.values())
    for page in pages(product):
        if page in covered:
            continue            # reported once, under its target name
        try:
            a, ia = layout_of(product, page, source)
            b, ib = layout_of(product, page, target)
            twin = None
            if page in twins:
                a, ia = layout_of(product, twins[page], source)
                twin = {"source_page": twins[page], "source_label": _label_of(a, twins[page]),
                        "target_page": page, "target_label": _label_of(b, page)}
        except Exception:  # noqa: BLE001 — a report never fails on the GUI block
            log.exception("gui_diff: %s %s", product, page)
            continue
        entry = {"page": page, "source": ia, "target": ib, "measured": False,
                 "changes": [], "summary": {}, "note": "", "twin": twin}
        if a is None or b is None:
            continue
        if not twin and (ia["closeness"] not in MEASURED or ib["closeness"] not in MEASURED):
            sides = [(v, i) for v, i in ((source, ia), (target, ib)) if i["closeness"] not in MEASURED]
            states = {str(v): _state(product, page, v) for v, _i in sides}
            entry["presence"] = {k: s["present"] for k, s in states.items()}
            entry["note"] = _note(states)
        else:
            entry["measured"] = True
            entry["changes"] = _with_titles(guikit.diff(a, b), a, b)
            from ..vendor.satom_guikit.diff import summary
            entry["summary"] = summary(entry["changes"])
        out.append(entry)
    return {"pages": out}


def not_in_gui_fields(product: str, endpoint: str, firmware, names) -> list | None:
    """Of ``names``, the ones the MEASURED layout of ``firmware`` does not place
    for ``endpoint``; None when no measured layout covers the endpoint."""
    from . import not_in_gui as nig
    page = nig.layout_pages().get((product, nig.endpoint_key(endpoint)))
    if not page:
        return None
    tpl, info = layout_of(product, page, firmware)
    if tpl is None or info["closeness"] not in MEASURED:
        return None
    placed = nig._template_keys(tpl, nig.endpoint_key(endpoint))
    return sorted(n for n in names if n not in placed and n != "name")
