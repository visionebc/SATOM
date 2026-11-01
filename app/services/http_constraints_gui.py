"""FortiWeb's own layout of HTTP Protocol Constraints and of an HTTP Constraint
Exception rule: the categorised tables its dialogs draw by hand.

The generated WAF catalog knows the 44 exception keys but not how FortiWeb
presents them: seven collapsible categories, the device's own names and a
one-line description per constraint, Host and Source IP only while their
status is on. Without that the form was a flat grid of 50 toggles in another
order, and nothing told the operator that an exception only matters for a
constraint that is ON in the profile the Web Protection Profile binds.

Both tables come from the GUI template of the device's build: the harvester
reads them off the dialogs' own code (``category_grid`` of the Edit HTTP
Protocol Constraints dialog and of the exception rule row; harvester
``gui_extract_grid``, 2026-11-01). Until then they were a JSON measured by
hand over CDP.

Pure data + a cache read (``gui_pages.rows``) -- never the device.
"""
from __future__ import annotations

EXC_TYPE = "http_constraint_exception_item"
WPP_COLL = "waf/web-protection-profile.inline-protection"
HPPR_COLL = "waf/http-protocol-parameter-restriction"
WPP_REF = "http-protocol-parameter-restriction"
CONSTRAINTS_PAGE = "http-protocol"
CONSTRAINTS_DIALOG = "http_constraints_dialog"
EXCEPTION_DIALOG = "http_constraints_exceptions_dialog-row1"


def _grid(d: dict | None):
    return next((f for b in (d or {}).get("blocks") or [] for f in b.get("fields") or []
                 if f.get("kind") == "category_grid"), None)


def _pairs(c) -> list:
    return [[o["value"], o["label"]] for o in (c or {}).get("options") or []]


def data(firmware=None) -> dict:
    """The two tables' facts for one build (newest template when None), read
    from its template; ``{}`` when no template carries them."""
    from . import gui_grid
    hg, tpl = gui_grid.find(CONSTRAINTS_PAGE, CONSTRAINTS_DIALOG, ("category_grid",), firmware)
    eg, etpl = gui_grid.find(CONSTRAINTS_PAGE, EXCEPTION_DIALOG, ("category_grid",), firmware)
    if not hg:
        return {}
    dialogs = dict((etpl or {}).get("dialogs") or {}, **((tpl or {}).get("dialogs") or {}))
    if etpl is not None:
        dialogs[EXCEPTION_DIALOG] = (etpl.get("dialogs") or {}).get(EXCEPTION_DIALOG)
    constraints, first = [], None
    for c in hg["categories"]:
        rows = []
        for r in c["rows"]:
            cells = [x for x in r.get("cells") or [] if x]
            by_kind = {}
            for x in cells:
                by_kind.setdefault(x["kind"], x)
            texts = [x["text"] for x in (r.get("cells") or [])[2:] if x and x["kind"] == "text"]
            first = first or {x["key"]: x for x in cells if x.get("key")}
            rows.append({"label": r.get("label") or r["id"], "id": r["id"],
                         "check": (by_kind.get("toggle") or {}).get("key"),
                         "weight": (by_kind.get("weight") or {}).get("key"),
                         "desc": (r.get("tip") or "").strip(),
                         "proto": texts[-1] if texts else "",
                         "has_length": any(x["kind"] == "number" and x["key"] == r["id"] for x in cells)})
        constraints.append({"title": c["label"], "rows": rows})
    one = next(iter(constraints[0]["rows"]))
    pick = lambda suffix: next((x for k, x in (first or {}).items() if k == one["id"] + suffix), None)  # noqa: E731
    # the exception rule names a constraint by its check key or its id, not
    # always in the same case (Illegal-byte-in-url-check / illegal-byte-in-url)
    by_check = {r["check"].lower(): r for c in constraints for r in c["rows"] if r["check"]}
    by_id = {r["id"].lower(): r for c in constraints for r in c["rows"]}
    exception = {"head": [], "head_labels": {}, "categories": []}
    ed = dialogs.get(EXCEPTION_DIALOG) or {}
    for b in ed.get("blocks") or []:
        for f in b.get("fields") or []:
            if f.get("key") and f.get("kind") not in ("display", "category_grid"):
                exception["head"].append(f["key"])
                exception["head_labels"][f["key"]] = f.get("label") or f["key"]
    for c in (eg or {}).get("categories") or []:
        rows = []
        for r in c["rows"]:
            k = r["id"]
            lk = k.lower()
            cons = by_check.get(lk) or by_id.get(lk) or by_id.get(lk[:-6] if lk.endswith("-check") else lk) or {}
            rows.append({"label": r.get("label") or k, "key": k,
                         "constraint": cons.get("id", k), "check": cons.get("check", k)})
        exception["categories"].append({"title": c["label"], "rows": rows})
    return {
        "constraints": constraints,
        "exception": exception,
        "options": {"action": _pairs(pick("-action")), "severity": _pairs(pick("-severity")),
                    "threat_weight": _pairs(pick("-threat-weight"))},
        "measured": {"source": "GUI template %s %s (harvester gui_extract_grid)" % (
            ((tpl or {}).get("exact") or {}).get("version", ""),
            ((tpl or {}).get("exact") or {}).get("build", "")),
                     "exception_source": "GUI template %s %s" % (
            ((etpl or {}).get("exact") or {}).get("version", ""),
            ((etpl or {}).get("exact") or {}).get("build", ""))},
    }


def _constraints_by_id(firmware=None) -> dict:
    return {r["id"]: r for c in (data(firmware).get("constraints") or []) for r in c["rows"]}


def exception_layout(fields: list[dict], firmware=None) -> dict:
    """The exception rule as FortiWeb draws it, for the authoring form.

    ``not_in_gui``: keys the device schema carries that the GUI does not show
    (``Internal-resource-limits-check`` on 7.6.8) -- shown in their own
    section, never dropped (regla "Not in GUI, but in CLI")."""
    d = data(firmware)
    exc = d.get("exception") or {"head": [], "head_labels": {}, "categories": []}
    cons = _constraints_by_id(firmware)
    cats = []
    placed = set(exc["head"])
    for c in exc["categories"]:
        rows = []
        for r in c["rows"]:
            placed.add(r["key"])
            k = cons.get(r["constraint"], {})
            rows.append({"key": r["key"], "label": r["label"], "constraint": r["constraint"],
                         "desc": k.get("desc", ""), "proto": k.get("proto", "")})
        cats.append({"title": c["title"], "rows": rows})
    labels = {f["key"]: f.get("label") or f["key"] for f in fields}
    return {
        "kind": "http_constraint_exception",
        "head": exc["head"], "head_labels": exc["head_labels"],
        "categories": cats,
        "not_in_gui": [{"key": k, "label": labels[k]} for k in labels if k not in placed],
        "measured": d.get("measured") or {},
    }



def constraint_table(row: dict, firmware=None) -> dict:
    """The constraints of one HTTP Protocol Constraints profile as FortiWeb's
    Edit dialog draws them: seven collapsible categories, a row per constraint
    with Status, Length (where the constraint has one), Action, Block Period,
    Severity, Threat Weight, Trigger Policy and protocol support. Each cell is
    the REST key it edits (``key``) and its current value (``raw``); a key the
    object does not carry is not drawn. ``keys``: every key placed here."""
    d = data(firmware)
    row = row or {}
    keys: set = set()

    def cell(k):
        if not k or k not in row:
            return None
        keys.add(k)
        v = row.get(k)
        return {"key": k, "raw": "" if v is None else str(v)}

    cats = []
    for c in d.get("constraints") or []:
        rows = []
        for r in c["rows"]:
            cid = r["id"]
            rows.append({
                "label": r["label"], "desc": r.get("desc", ""), "proto": r.get("proto", ""),
                "status": cell(r.get("check") or cid),
                "length": cell(cid) if r.get("has_length") else None,
                "action": cell(cid + "-action"),
                "block_period": cell(cid + "-block-period"),
                "severity": cell(cid + "-severity"),
                "threat_weight": cell(r.get("weight")),
                "trigger": cell(cid + "-trigger"),
            })
        cats.append({"title": c["title"], "rows": rows})
    return {"categories": cats, "options": d.get("options") or {}, "keys": sorted(keys)}


def profile_state(appliance_id: int, wpp: str, firmware=None) -> dict:
    """Which constraints are ON in the HTTP Protocol Constraints profile the
    WPP binds, read from the SATOM cache. ``read`` False = could not tell
    (no cache / no such WPP) -- never painted as "all off"."""
    from . import gui_pages
    out = {"wpp": wpp or "", "profile": "", "exception_name": "", "read": False, "on": {}}
    if not wpp:
        return out
    wrows, _m = gui_pages.rows(appliance_id, WPP_COLL)
    w = next((r for r in wrows if str(r.get("name")) == wpp), None)
    if w is None:
        return out
    prof = str(w.get(WPP_REF) or "")
    out["profile"] = prof
    if not prof:
        out["read"] = True          # the WPP binds no constraints profile
        return out
    hrows, _m = gui_pages.rows(appliance_id, HPPR_COLL)
    h = next((r for r in hrows if str(r.get("name")) == prof), None)
    if h is None:
        return out
    out["exception_name"] = str(h.get("exception_name") or "")
    cons = _constraints_by_id(firmware)
    for c in (data(firmware).get("exception") or {}).get("categories") or []:
        for r in c["rows"]:
            check = cons.get(r["constraint"], {}).get("check") or r.get("check")
            out["on"][r["key"]] = str(h.get(check, "")).lower() == "enable"
    out["read"] = True
    return out
