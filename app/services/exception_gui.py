"""The FortiWeb row dialog of an exception type, measured by the GUI crawl
(``gui_template``), for the Exceptions authoring form.

An exception type is a row of one device sub-table (``exception_inject``:
``item_logical`` -> collection). The GUI template of the page that edits that
table carries the dialog FortiWeb opens for one row -- its sections, labels,
order, choices, help and show/hide conditions. Serving that dialog to the form
makes every type look and behave as it does on the device, instead of a flat
grid of keys. A type whose row dialog no template measured keeps the curated
field list (``wpp_exceptions.fields_for``); nothing is invented.
"""
from __future__ import annotations

import os
import threading

#: Kinds the authoring form can draw and collect.
_FORM_KINDS = {"toggle", "check", "select", "radio", "checks", "text", "number",
               "textarea", "ref", "multiselect", "static"}

#: ``{firmware: (fingerprint, index)}``. Self-invalidating: the index is built
#: from the files under ``data/gui-templates/fortiweb`` and a knowledge-pack
#: import only writes those files, from ONE process while every web worker and
#: the scheduler hold their own copy. Clearing the importing process's cache
#: would leave the others stale until a restart, so each lookup compares a
#: fingerprint of the template files instead (names, sizes, mtimes: a few
#: hundred ``stat`` calls, no JSON read) and rebuilds when it moved.
_INDEX_CACHE: dict = {}
_INDEX_LOCK = threading.Lock()
_MAX_FIRMWARES = 8


def _fingerprint() -> int | None:
    """Digest of the FortiWeb template files; ``None`` without an app context."""
    from . import gui_store
    try:
        base = gui_store.root() / "fortiweb"
    except RuntimeError:
        return None
    seen = []
    try:
        pages = [e for e in os.scandir(base) if e.is_dir()]
    except OSError:
        return hash(())
    for page in pages:
        try:
            for f in os.scandir(page.path):
                if f.name.endswith(".json"):
                    st = f.stat()
                    seen.append((page.name, f.name, st.st_mtime_ns, st.st_size))
        except OSError:
            continue
    return hash(tuple(sorted(seen)))


def clear_cache() -> None:
    with _INDEX_LOCK:
        _INDEX_CACHE.clear()


def _index(firmware: str) -> dict:
    """``{collection: (page, main dialog, row dialog, sub-table)}`` over every
    FortiWeb page template for one firmware string (rebuilt when the template
    files change, see :data:`_INDEX_CACHE`)."""
    fp = _fingerprint()
    with _INDEX_LOCK:
        hit = _INDEX_CACHE.get(firmware)
    if fp is not None and hit is not None and hit[0] == fp:
        return hit[1]
    out = _build_index(firmware)
    if fp is not None:
        with _INDEX_LOCK:
            if len(_INDEX_CACHE) >= _MAX_FIRMWARES and firmware not in _INDEX_CACHE:
                _INDEX_CACHE.pop(next(iter(_INDEX_CACHE)))
            _INDEX_CACHE[firmware] = (fp, out)
    return out


_index.cache_clear = clear_cache  # type: ignore[attr-defined]  # the lru_cache API it replaces


def _build_index(firmware: str) -> dict:
    from . import gui_pages, gui_template
    out: dict = {}
    for page in gui_pages.page_ids("fortiweb"):
        tpl, _m = gui_pages.template(page, firmware)
        if not tpl:
            continue
        for main in tpl.get("dialogs") or {}:
            for rd, st in gui_template.row_dialogs(tpl, main).items():
                ep = gui_pages.table_endpoint(tpl, main, st)
                if ep:
                    out.setdefault(ep, (page, main, rd, st))
    return out


def collection_of(exc_type: str, version: str = "") -> str | None:
    from . import exception_inject as ei
    rest = ei.rest_for(exc_type)
    if rest is None:
        return None
    return ei.resolve_collection(rest.item_logical, version)


def row_dialog(appliance, exc_type: str) -> tuple | None:
    """``(template, row dialog key, page, collection)`` or None."""
    from . import gui_pages, gui_store
    fw = gui_store.firmware_of(appliance)
    coll = collection_of(exc_type, getattr(appliance, "fw_version", "") or "")
    if not coll:
        return None
    hit = _index(fw).get(coll)
    if hit is None:
        return None
    page, _main, rd, _st = hit
    tpl, _m = gui_pages.template(page, fw)
    if not tpl or rd not in (tpl.get("dialogs") or {}):
        return None
    return tpl, rd, page, coll


def _unplaced_block(exc_type: str, view: dict, row: dict) -> dict | None:
    """The keys of the carve-out type the measured row dialog does NOT carry,
    as one last block (rule 1.6, every field the device has is visible).

    A layout can be incomplete: the 8.0.8 Http Header Security exception row
    dialog came back with ``request-url-type`` alone, so the form drew one
    input for a four-field object and the operator could not set the client IP
    or the URL pattern. The device schema (``wpp_exceptions.fields_for``) names
    the missing keys; they are drawn from it, under a heading that says why."""
    from flask_babel import gettext as _
    from . import wpp_exceptions as store
    placed = {f.get("wkey") or f.get("key") for b in view.get("blocks") or []
              for f in b.get("fields") or []}
    fields = []
    for d in store.fields_for(exc_type):
        key = d.get("key")
        if not key or key in placed:
            continue
        w = d.get("widget")
        kind = {"toggle": "toggle", "enum": "select", "combo": "select",
                "number": "number"}.get(w, "text")
        labels = d.get("option_labels") or {}
        fields.append({
            "key": key, "label": d.get("label") or key, "kind": kind,
            "raw": row.get(key, ""), "on": "enable", "off": "disable",
            "opts": ([{"value": o, "label": labels.get(o, o)} for o in d.get("options") or []]
                     if kind == "select" else []),
            "ref": "", "cond": None, "help": d.get("hint") or "",
            "required": bool(d.get("required")), "text": "", "min": None, "max": None,
        })
    if not fields:
        return None
    return {"title": _("Not in this layout (REST fields)"), "cond": None, "fields": fields}


def form(appliance, exc_type: str, payload: dict | None, dev: dict) -> dict | None:
    """The row dialog as the form draws it, or None when none was measured.

    ``blocks``: ``[{title, cond, fields: [{key, label, kind, raw, on, off,
    opts, ref, cond, help, required, text}]}]`` -- conditions are bound to the
    device facts (``gui_template.bind_device``) so the browser re-evaluates
    them against the form alone, as the fwgui pages do."""
    from . import gui_template
    hit = row_dialog(appliance, exc_type)
    if hit is None:
        return None
    tpl, rd, page, coll = hit
    row = dict(payload or {})
    view = gui_template.dialog_view(tpl, rd, row, dev, live=True, new=not payload)
    blocks = []
    for b in view.get("blocks") or []:
        fields = []
        for f in b.get("fields") or []:
            kind = f.get("kind")
            if kind not in _FORM_KINDS or (kind != "static" and not f.get("editable")):
                continue
            fields.append({
                "key": f.get("wkey") or f.get("key"), "label": f.get("label") or "",
                "kind": kind, "raw": f.get("raw", ""), "on": f.get("on", "enable"),
                "off": f.get("off", "disable"), "opts": f.get("opts") or [],
                "ref": f.get("ref") or "", "cond": f.get("cond"),
                "help": f.get("help") or "", "required": bool(f.get("required")),
                "text": f.get("text") or "", "min": f.get("min"), "max": f.get("max"),
            })
        if fields:
            blocks.append({"title": b.get("title"), "cond": b.get("cond"), "fields": fields})
    if not blocks:
        return None
    rest = _unplaced_block(exc_type, view, row)
    if rest:
        blocks.append(rest)
    title = (tpl["dialogs"][rd].get("title") or {})
    based = tpl.get("based_on") or {}
    return {"blocks": blocks, "page": page, "collection": coll,
            "title": title.get("edit") if payload else title.get("new"),
            "measured": "%s %s build%s" % ("FortiWeb", based.get("version", "?"),
                                          based.get("build", "?"))}
