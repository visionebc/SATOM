"""The tables a FortiWeb dialog draws by hand, drawn by SATOM from its template.

Known Bots, Syntax Detection and Web Shell Detection (and HTTP Protocol
Constraints) are, for most of their content, a table FortiWeb draws outside
its field layout: categories of rows, each row a set of the object's OWN
fields (``dos-status``, ``dos-action``, ``dos-block-period``...). The
harvester resolves those rows off the dialog's code (``category_grid``,
``gui_extract_grid``); here each cell becomes the field it edits with the
object's current value, so the dialog saves them like any other field.

A cell whose key the build's CLI schema does not have (``unverified``) is
drawn read-only: shown, never written. A key the object does not carry is not
drawn (an absent value is not an empty one).
"""
from __future__ import annotations

GRID_KINDS = ("category_grid", "subtable_grid")
#: Cell kinds an operator edits; ``text`` / ``action`` are display only.
_EDIT = ("toggle", "select", "weight", "number", "ref")


def first(tpl: dict | None, dialog: str, kinds=GRID_KINDS):
    d = ((tpl or {}).get("dialogs") or {}).get(dialog) or {}
    return next((f for b in d.get("blocks") or [] for f in b.get("fields") or []
                 if f.get("kind") in kinds), None)


def find(page: str, dialog: str, kinds, firmware=None) -> tuple:
    """``(grid, template)`` of a dialog's hand-drawn table: from the template
    of the device's build (``firmware``; the newest when None), else from the
    newest template of the page that carries it -- a crawl that did not open
    that dialog on a build leaves its template without the table (8.0.6: the
    HTTP Constraint exception rule), and the table of the nearest build is
    the device's own GUI more closely than no table. ``template`` names the
    build the grid was measured on. ``(None, None)`` when none has it."""
    from . import gui_pages, gui_store
    tpl, _m = gui_pages.template(page, firmware)
    g = first(tpl, dialog, kinds)
    if g is not None:
        return g, tpl
    cands = sorted(gui_store.candidates("fortiweb", page),
                   key=lambda c: (gui_store._vkey(c["version"]), c["build"]), reverse=True)
    for c in cands:
        try:
            t = gui_store.view_template(c)
        except (OSError, ValueError):
            continue
        g = first(t, dialog, kinds)
        if g is not None:
            return g, t
    return None, None


def category_grids(tpl: dict, dialog: str) -> list:
    d = ((tpl or {}).get("dialogs") or {}).get(dialog) or {}
    return [f for b in d.get("blocks") or [] for f in b.get("fields") or []
            if f.get("kind") == "category_grid"]


def _cell(x: dict | None, row: dict, can_edit: bool, keys: set) -> dict | None:
    if not x:
        return None
    kind = x.get("kind")
    if kind not in _EDIT:
        return {"kind": "text", "text": x.get("text") or ""} if x.get("text") else None
    key = x.get("key")
    if not key or key not in row:
        return None
    keys.add(key)
    v = row.get(key)
    out = {"kind": "select" if kind == "weight" else kind, "key": key,
           "raw": "" if v is None else str(v),
           "editable": bool(can_edit) and not x.get("unverified"),
           "unverified": bool(x.get("unverified"))}
    if kind == "toggle":
        out.update(on=str(x.get("on", "enable")), off=str(x.get("off", "disable")))
    if kind in ("select", "weight"):
        out["opts"] = [[str(o["value"]), o.get("label") or str(o["value"])]
                       for o in x.get("options") or []]
    if kind == "number":
        out.update(min=x.get("min"), max=x.get("max"), unit=x.get("unit") or "")
    if kind == "ref":
        out.update(ref=x.get("ref_coll") or "", create_new=bool(x.get("create_new")),
                   inline_edit=bool(x.get("inline_edit")))
    if x.get("enabled_when"):
        out["enabled_when"] = x["enabled_when"]
    if x.get("warn_on"):
        out["warn_on"] = x["warn_on"]
    return out


def category_view(grid: dict, row: dict | None, can_edit: bool) -> dict:
    """``{"columns", "categories": [{"title", "rows": [{"label", "tip",
    "cells"}]}], "keys"}``: the grid with the object's values. A row none of
    whose cells the object carries is left out (another build's row)."""
    row = row or {}
    keys: set = set()
    cats = []
    for c in grid.get("categories") or []:
        rows = []
        for r in c.get("rows") or []:
            cells = [_cell(x, row, can_edit, keys) for x in r.get("cells") or []]
            if not any(x and x.get("key") for x in cells):
                continue
            rows.append({"id": r.get("id"), "label": r.get("label") or r.get("id"),
                         "tip": r.get("tip") or "", "cells": cells})
        if rows:
            cats.append({"title": c.get("label") or "", "rows": rows})
    return {"columns": grid.get("columns") or [], "categories": cats, "keys": sorted(keys)}
