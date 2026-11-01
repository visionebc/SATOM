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

from functools import lru_cache

#: Kinds the authoring form can draw and collect.
_FORM_KINDS = {"toggle", "check", "select", "radio", "checks", "text", "number",
               "textarea", "ref", "multiselect", "static"}


@lru_cache(maxsize=8)
def _index(firmware: str) -> dict:
    """``{collection: (page, main dialog, row dialog, sub-table)}`` over every
    FortiWeb page template for one firmware string."""
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
    title = (tpl["dialogs"][rd].get("title") or {})
    based = tpl.get("based_on") or {}
    return {"blocks": blocks, "page": page, "collection": coll,
            "title": title.get("edit") if payload else title.get("new"),
            "measured": "%s %s build%s" % ("FortiWeb", based.get("version", "?"),
                                          based.get("build", "?"))}
