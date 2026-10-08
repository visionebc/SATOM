"""Schema versions, identity and the keys a layout places.

``satom.gui-template/1`` is what ``gui extract`` writes: one page of one GUI,
``applies_to`` = the firmware TRAIN (``"7.6"``). ``/2`` is what travels in a
pack: the same layout, identified by the EXACT build it was measured on
(``applies_to = {"product", "version", "build", "train"}``), with the list of
REST fields the layout does not place (``not_in_gui``) and the dialogs that
edit another endpoint (``subtable_dialogs``) made explicit.
"""
from __future__ import annotations

import copy
import hashlib
import json

SCHEMA_V1 = "satom.gui-template/1"
SCHEMA_V2 = "satom.gui-template/2"
SCHEMAS = (SCHEMA_V1, SCHEMA_V2)

#: Parts of a template that describe the measurement, not the layout: they
#: never enter the content hash (a re-fetch of the same build is the same layout).
VOLATILE = frozenset({"based_on", "extractor", "sources", "rest_check", "unresolved",
                      "applies_to", "schema", "not_in_gui"})


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def content_hash(tpl: dict) -> str:
    """sha256 of the layout STRUCTURE (texts and measurement metadata excluded):
    two builds with the same layout share it; a different language does not
    change it."""
    from .strings import split
    structure, _ = split(tpl)
    body = {k: v for k, v in structure.items() if k not in VOLATILE}
    return hashlib.sha256(_canonical(body)).hexdigest()


def identity(tpl: dict) -> dict:
    """``{"product", "page", "version", "build", "train"}`` of a /1 or /2 template."""
    based = tpl.get("based_on") or {}
    at = tpl.get("applies_to")
    if isinstance(at, dict):
        version, build, train = at.get("version"), at.get("build"), at.get("train")
    else:
        version, build, train = based.get("version"), based.get("build"), at or based.get("train")
    return {"product": tpl.get("product") or "", "page": tpl.get("page") or "",
            "version": str(version or ""), "build": str(build or ""), "train": str(train or "")}


def _subtable_dialogs(tpl: dict) -> set:
    if "subtable_dialogs" in tpl:
        return set(tpl.get("subtable_dialogs") or ())
    # /1 without the list: a dialog with operation-mode contexts edits the
    # page's object; one without is a sub-table row dialog
    return {k for k, d in (tpl.get("dialogs") or {}).items() if "contexts" not in d}


def layout_keys(tpl: dict) -> set:
    """REST field keys of the page's OWN object that the layout places: every
    dialog field (sub-table dialogs excluded), the REST fields a GUI-only control
    is derived from, the REST field an aliased control writes, and the list
    columns (a column the list shows and toggles, e.g. Status, is in the GUI)."""
    sub = _subtable_dialogs(tpl)
    keys: set = {c["id"] for c in ((tpl.get("list") or {}).get("columns") or [])
                 if isinstance(c, dict) and c.get("id")}
    for name, d in (tpl.get("dialogs") or {}).items():
        if name in sub:
            continue
        for b in d.get("blocks") or []:
            for f in b.get("fields") or []:
                if f.get("key"):
                    keys.add(f["key"])
                # a toggle group (Supported SSL Protocols) sets one key per row
                for r in f.get("rows") or []:
                    if isinstance(r, dict) and r.get("key"):
                        keys.add(r["key"])
        for rules in (d.get("derived") or {}).values():
            for r in rules or []:
                if isinstance(r, dict) and r.get("field"):
                    keys.add(r["field"])
        keys.update(str(v) for v in (d.get("aliases") or {}).values())
    return keys


def not_in_gui(tpl: dict, rest_keys) -> list:
    """REST keys of the witness the layout does not place (sorted). ``_val``,
    ``q_*``, ``can_*``, ``sz_*`` and ``sub_table_*`` bookkeeping excluded."""
    placed = layout_keys(tpl)
    out = []
    for k in rest_keys or ():
        if (k in placed or k == "name" or k.endswith("_val") or k.startswith(("q_", "can_", "sz_", "sub_table_"))
                or k in ("id", "_id", "seq")):
            continue
        out.append(k)
    return sorted(set(out))


def to_v2(tpl: dict, rest_keys=None) -> dict:
    """A /1 template as /2: exact-build identity, explicit sub-table dialogs and
    (when the witness REST keys are known) ``not_in_gui``. A /2 is returned as a copy."""
    out = copy.deepcopy(tpl)
    if out.get("schema") not in SCHEMAS:
        raise ValueError("not a GUI template: schema %r" % out.get("schema"))
    ident = identity(tpl)
    out["schema"] = SCHEMA_V2
    out["applies_to"] = {k: ident[k] for k in ("product", "version", "build", "train")}
    out["subtable_dialogs"] = sorted(_subtable_dialogs(tpl))
    if rest_keys is None:
        rest_keys = ((tpl.get("rest_check") or {}).get("rest_keys"))
    if rest_keys is not None:
        out["not_in_gui"] = not_in_gui(out, rest_keys)
    return out
