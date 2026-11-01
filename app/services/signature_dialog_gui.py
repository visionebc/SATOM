"""FortiWeb's Edit Signature Policy dialog, MEASURED in the device GUI
(``registry/data/fortiweb_signature_dialog_gui.json`` -- ``measured`` says
where and how).

The GUI layout crawl carries the dialog's four fields (Name, Custom Signature
Group, Sensitivity Level, Comments) but not the table FortiWeb draws under
them by hand: one row per signature main class (``main_class_list``) with
Status, False Positive Mitigation (SQL Injection rows only), Action (its own
choices for Information Disclosure and for PII), Block Period (only for a
block-period action), Severity and Trigger Policy, and the PII row's
Detection Threshold. Without it the pencil on a Web Protection Profile's
Signatures opened a form FortiWeb never shows.

Each cell names the sub-table row it edits: ``^main_class_list|<id>#<field>``
(the dialog saves each changed row through the object editor's save-row).

Pure data -- never the device.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache

_DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "registry", "data",
                     "fortiweb_signature_dialog_gui.json")
PAGE = "signature"
DIALOG = "signature_dialog"


@lru_cache(maxsize=1)
def data() -> dict:
    with open(_DATA, encoding="utf-8") as fh:
        return json.load(fh)


def row_key(subtable: str, row_id: str, field: str) -> str:
    return "^%s|%s#%s" % (subtable, row_id, field)


def class_table(rows, obj: dict | None) -> dict | None:
    """The main-class table of one signature policy as FortiWeb draws it, or
    None when its rows are unknown (device unreachable and nothing cached --
    never drawn as an empty table). Rows in FortiWeb's order; a class the
    object lacks is not invented."""
    if rows is None:
        return None
    d = data()
    st = d["subtable"]
    by_id = {str(r.get("id") or r.get("main_class_id") or ""): r for r in rows if isinstance(r, dict)}
    order = [i for i in d["order"] if i in by_id] + sorted(i for i in by_id if i not in d["order"])
    opts = d["options"]
    out = []
    for cid in order:
        r = by_id[cid]

        def cell(field, _r=r, _cid=cid):
            v = _r.get(field)
            return {"key": row_key(st, _cid, field), "raw": "" if v is None else str(v)}

        if cid == d["info_id"]:
            actions = opts["info_action"]
        elif cid == d["ident_id"]:
            actions = opts["ident_action"]
        else:
            actions = opts["action"]
        status = cell("status")
        action = cell("action")
        out.append({
            "id": cid,
            "name": d["names"].get(cid, cid),
            "off": status["raw"] != "enable",
            "status": status,
            "fpm": cell("fpm-status") if cid in d["fpm_ids"] else None,
            "action": action, "actions": actions,
            "block_period": cell("block-period"),
            "block_on": action["raw"] in d["block_actions"],
            "severity": cell("severity"),
            "trigger": cell("trigger"),
            "ident": cid == d["ident_id"],
        })
    thr = d["threshold"]
    obj = obj or {}
    threshold = None
    if thr["key"] in obj:
        v = obj.get(thr["key"])
        threshold = dict(thr, raw="" if v is None else str(v))
    return {"subtable": st, "rows": out, "options": opts, "columns": d["columns"],
            "threshold": threshold, "block_actions": d["block_actions"],
            "client_id_warning": d["client_id_warning"],
            "keys": [thr["key"]] if threshold else []}


def ref_for(key: str) -> str:
    """The collection FortiWeb's selector lists for a field of this dialog
    (with its Edit entry shortcut), when the crawl left it unbound."""
    return data().get("refs", {}).get(key, "")


def help_for(key: str) -> str:
    """FortiWeb's own tip for a field of this dialog (the crawl missed the
    f-tip inside the label)."""
    return data()["help"].get(key, "")
