"""FortiWeb's Edit Signature Policy dialog: the table it draws by hand.

The four fields of the dialog (Name, Custom Signature Group, Sensitivity
Level, Comments) are ordinary layout fields. Under them FortiWeb draws one
row per signature main class (``main_class_list``) with Status, False
Positive Mitigation (SQL Injection rows only), Action (its own choices for
Information Disclosure and for PII), Block Period (only for a block-period
action), Severity and Trigger Policy, and the PII row's Detection Threshold.

That table comes from the GUI template of the device's build: the harvester
reads it off the dialog's own code (``subtable_grid``: the classes in the
code's order with their defaults, each cell's field and choices, the values
an absent class is added with, the extra Detection Threshold row; harvester
``gui_extract_grid``, 2026-11-01). Until then it was a JSON measured by hand.

Each cell names the sub-table row it edits: ``^main_class_list|<id>#<field>``
(the dialog saves each changed row through the object editor's save-row).

Pure data -- never the device.
"""
from __future__ import annotations

from collections import Counter

PAGE = "signature"
DIALOG = "signature_dialog"


def grid(firmware=None) -> dict | None:
    """The ``subtable_grid`` of the dialog for that firmware (newest template
    when None; the closest that carries it otherwise, ``gui_grid.find``), or
    None when no template carries it."""
    from . import gui_grid
    return gui_grid.find(PAGE, DIALOG, ("subtable_grid",), firmware)[0]


def _cells(r: dict) -> dict:
    return {c["key"]: c for c in r.get("cells") or [] if c and c.get("key")}


def _cmdb_key(key: str) -> str:
    """A GUI API name the alias table measured (``creditCardDetectionThreshold``
    -> ``credit-card-detection-threshold``); the name itself otherwise."""
    from . import gui_alias
    keys = ((gui_alias.table()["aliases"].get("waf/signatures") or {}).get("keys")) or {}
    return keys.get(key, key)


def data(firmware=None) -> dict:
    """The table's facts for one build, read from its template (``{}`` when
    no template of that build carries the table)."""
    g = grid(firmware)
    if not g or not g.get("rows"):
        return {}
    rows = g["rows"]
    per = {r["id"]: [(o["value"], o["label"]) for o in (_cells(r).get("action") or {}).get("options") or []]
           for r in rows}
    common = Counter(tuple(v) for v in per.values()).most_common(1)[0][0]
    extras = g.get("extras") or []
    ident_id = next((x["after"] for x in extras), "")
    info_id = next((i for i, v in per.items() if tuple(v) != common and i != ident_id), "")
    first = _cells(rows[0])
    act = first.get("action") or {}
    bp = first.get("block-period") or {}
    thr = (extras[0] if extras else {}).get("cell") or {}
    trig = first.get("trigger") or {}
    absent = g.get("absent_row") or {}
    return {
        "subtable": g["subtable"],
        "order": [r["id"] for r in rows],
        "names": {r["id"]: r.get("label") or r["id"] for r in rows},
        "fpm_ids": [r["id"] for r in rows if "fpm-status" in _cells(r)
                    and not _cells(r)["fpm-status"].get("row_if")],
        # 8.0.6: False Positive Mitigation where the DEVICE's row carries this
        # field (``fpm_cap``), not on a fixed list of classes
        "fpm_if": next((_cells(r)["fpm-status"]["row_if"] for r in rows
                        if (_cells(r).get("fpm-status") or {}).get("row_if")), ""),
        "info_id": info_id,
        "ident_id": ident_id,
        "block_actions": list((bp.get("enabled_when") or {}).get("values") or []),
        "options": {
            "action": list(common),
            "info_action": per.get(info_id, list(common)),
            "ident_action": per.get(ident_id, list(common)),
            "severity": [(o["value"], o["label"]) for o in
                         (first.get("severity") or {}).get("options") or []],
        },
        "row_options": per,
        "columns": g.get("columns") or [],
        # a class the policy lacks: its defaults, then what the code sets
        "missing_rows": {r["id"]: dict({k: v for k, v in (r.get("defaults") or {}).items()
                                        if k not in ("id", "main_class_id", "name")}, **absent)
                         for r in rows},
        "threshold": ({"key": _cmdb_key(thr["key"]), "label": extras[0].get("label") or thr["key"],
                       "min": thr.get("min"), "max": thr.get("max")} if thr.get("key") else None),
        "client_id_warning": (act.get("warn_on") or {}).get("text", ""),
        "trigger_create": bool(trig.get("create_new")),
    }


def row_key(subtable: str, row_id: str, field: str) -> str:
    return "^%s|%s#%s" % (subtable, row_id, field)


def _cid(r: dict) -> str:
    return str(r.get("main_class_id") or r.get("id") or "")


def fill_classes(rows, firmware=None):
    """The policy's main classes as FortiWeb's dialog edits them: every class
    of the code's order, in that order. A class the policy has no row for (a
    policy created over REST has none) is drawn as FortiWeb adds it -- its
    defaults, then Alert, High, disabled, FPM disabled -- and marked
    ``_missing``: saving it CREATES the row; it is never written unchanged.
    None (rows unknown) stays None; no table for the build leaves the rows as
    they are."""
    if rows is None:
        return None
    d = data(firmware)
    by_id = {}
    for r in rows:
        if isinstance(r, dict) and _cid(r):
            by_id[_cid(r)] = r
    if not d:
        return [dict(by_id[i]) for i in sorted(by_id)]
    out = []
    for cid in d["order"]:
        if cid in by_id:
            out.append(dict(by_id[cid]))
        else:
            out.append(dict(d["missing_rows"].get(cid) or {}, id=cid, main_class_id=cid,
                            _missing=True))
    out += [dict(by_id[i]) for i in sorted(by_id) if i not in d["order"]]
    return out


def class_table(rows, obj: dict | None, firmware=None) -> dict | None:
    """The main-class table of one signature policy as FortiWeb draws it, or
    None when its rows are unknown (device refused or unreachable and nothing
    cached -- never drawn as an empty table) or the build's template carries
    no such table. All classes in FortiWeb's order (:func:`fill_classes`); a
    row the device lacks is ``new``."""
    d = data(firmware)
    if not d:
        return None
    filled = fill_classes(rows, firmware)
    if filled is None:
        return None
    st = d["subtable"]
    opts = d["options"]
    out = []
    for r in filled:
        cid = _cid(r)

        def cell(field, _r=r, _cid=cid):
            v = _r.get(field)
            return {"key": row_key(st, _cid, field), "raw": "" if v is None else str(v)}

        actions = d["row_options"].get(cid) or opts["action"]
        status = cell("status")
        action = cell("action")
        out.append({
            "id": cid,
            "name": d["names"].get(cid, cid),
            "off": status["raw"] != "enable",
            "status": status,
            "fpm": cell("fpm-status") if (cid in d["fpm_ids"] or (
                d["fpm_if"] and str(r.get(d["fpm_if"], "")).lower() not in ("", "0", "false", "none")))
            else None,
            "action": action, "actions": actions,
            "block_period": cell("block-period"),
            "block_on": action["raw"] in d["block_actions"],
            "severity": cell("severity"),
            "trigger": cell("trigger"),
            "ident": cid == d["ident_id"],
            "new": bool(r.get("_missing")),
        })
    thr = d["threshold"]
    obj = obj or {}
    threshold = None
    if thr and thr["key"] in obj:
        v = obj.get(thr["key"])
        threshold = dict(thr, raw="" if v is None else str(v))
    return {"subtable": st, "rows": out, "options": opts, "columns": d["columns"],
            "threshold": threshold, "block_actions": d["block_actions"],
            "client_id_warning": d["client_id_warning"],
            "trigger_create": d["trigger_create"],
            "keys": [thr["key"]] if threshold else []}
