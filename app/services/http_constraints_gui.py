"""FortiWeb's own layout of HTTP Protocol Constraints and of an HTTP Constraint
Exception rule, MEASURED in the device GUI (``registry/data/
fortiweb_http_constraints_gui.json`` -- ``measured`` says where and how).

The generated WAF catalog knows the 44 exception keys but not how FortiWeb
presents them: seven collapsible categories, the device's own names and a
one-line description per constraint, Host and Source IP only while their
status is on. Without that the form was a flat grid of 50 toggles in another
order, and nothing told the operator that an exception only matters for a
constraint that is ON in the profile the Web Protection Profile binds.

Pure data + a cache read (``gui_pages.rows``) -- never the device.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache

_DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "registry", "data",
                     "fortiweb_http_constraints_gui.json")
EXC_TYPE = "http_constraint_exception_item"
WPP_COLL = "waf/web-protection-profile.inline-protection"
HPPR_COLL = "waf/http-protocol-parameter-restriction"
WPP_REF = "http-protocol-parameter-restriction"


@lru_cache(maxsize=1)
def data() -> dict:
    with open(_DATA, encoding="utf-8") as fh:
        return json.load(fh)


def _constraints_by_id() -> dict:
    return {r["id"]: r for c in data()["constraints"] for r in c["rows"]}


def exception_layout(fields: list[dict]) -> dict:
    """The exception rule as FortiWeb draws it, for the authoring form.

    ``not_in_gui``: keys the device schema carries that the GUI does not show
    (``Internal-resource-limits-check`` on 7.6.8) -- shown in their own
    section, never dropped (regla "Not in GUI, but in CLI")."""
    exc = data()["exception"]
    cons = _constraints_by_id()
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
        "measured": data()["measured"],
    }


def profile_state(appliance_id: int, wpp: str) -> dict:
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
    cons = _constraints_by_id()
    for c in data()["exception"]["categories"]:
        for r in c["rows"]:
            check = cons.get(r["constraint"], {}).get("check") or r.get("check")
            out["on"][r["key"]] = str(h.get(check, "")).lower() == "enable"
    out["read"] = True
    return out
