"""FortiWeb GUI pages tied to the collection that holds their objects.

The GUI crawl records the collection a page READS. For ~20 pages FortiWeb's GUI
reads its own API (``/api/v2.0/system/certificate.tslca``, ``waf/signatures``),
which cmdb answers 500 and the registry does not know, while the same objects
live in a cmdb collection SATOM caches, edits and audits
(``system/certificate.tsl-ca``, ``waf/signature``). Those pages were drawn
empty and could not be edited.

``app/registry/data/gui_endpoint_alias.json`` is the measured table (GETs on
the lab, evidence per entry):

* ``aliases`` -- GUI endpoint -> cmdb collection, with the GUI keys renamed to
  the cmdb keys measured equal (``keys``) and the columns FortiWeb computes
  (``computed``: drawn as such, never a guessed field);
* ``pages`` -- the same for one view of one page (``<page>/<view index>``), when
  the endpoint is shared or the crawl bound none;
* ``live`` -- GUI API lists with no cmdb twin (FortiWeb's predefined entries):
  read live, read-only, only through ``gui_bound.safe_api``.

:func:`apply` rewrites a template accordingly; ``gui_pages.template`` calls it,
so the grid, the dialog, the save path, the sidebar coverage
(``gui_classic``) and the "Not in GUI, but in CLI" rule all see the cmdb
collection. The GUI endpoint stays on the view as ``gui_endpoint``.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "registry" / "data" / "gui_endpoint_alias.json"

_table: dict | None = None
_cache: dict = {}


def table() -> dict:
    """The alias table ({} when the file is missing or unreadable)."""
    global _table
    if _table is None:
        try:
            doc = json.loads(DATA.read_text())
        except (OSError, ValueError):
            doc = {}
        _table = {"aliases": doc.get("aliases") or {}, "pages": doc.get("pages") or {},
                  "live": doc.get("live") or {}}
    return _table


def _bare(ep: str) -> str:
    return ep[4:] if ep.startswith("api:") else ep


def _rename(fields, km: dict, ep: str) -> None:
    """GUI keys -> cmdb keys; a ``bind`` to the aliased GUI endpoint itself is
    dropped: the field now lives in the cmdb object and is saved with it."""
    gui = {ep, _bare(ep), "api:" + _bare(ep)}
    for f in fields or []:
        b = f.get("bind")
        if isinstance(b, dict) and b.get("endpoint") in gui:
            f.pop("bind")
            if b.get("key") in km and f.get("key") == b.get("key"):
                f["key"] = km[b["key"]]
        if f.get("key") in km:
            f["key"] = km[f["key"]]


def _apply_alias(out: dict, v: dict, ep: str, al: dict) -> None:
    cmdb = al["cmdb"]
    km = dict(al.get("keys") or {})
    computed = set(al.get("computed") or ())
    v["gui_endpoint"] = ep
    v["endpoint"] = cmdb
    v["alias"] = {"confidence": al.get("confidence") or "named",
                  "evidence": al.get("evidence") or ""}
    for col in v.get("columns") or []:
        if col.get("id") in computed:
            col["unmatched"] = True
        elif col.get("id") in km:
            col["id"] = km[col["id"]]
            col.pop("unmatched", None)
    for rule in v.get("dialogs") or []:
        dd = (out.get("dialogs") or {}).get(rule.get("dialog"))
        if not dd:
            continue
        if (dd.get("endpoint") or "") in ("", ep, _bare(ep)):
            dd["endpoint"] = cmdb
        for b in dd.get("blocks") or []:
            _rename(b.get("fields"), km, ep)
    if (out.get("endpoint") or "") in (ep, _bare(ep)):
        out["endpoint"] = cmdb


def apply(page: str, tpl):
    """``tpl`` with every aliased view / dialog naming its cmdb collection (a
    copy; the loaded template is never touched). Unchanged when nothing
    applies."""
    if not tpl:
        return tpl
    t = table()
    if not (t["aliases"] or t["pages"] or t["live"]):
        return tpl
    hit = _cache.get((page, id(tpl)))
    if hit is not None and hit[0] is tpl:
        return hit[1]
    out, changed = copy.deepcopy(tpl), False
    for i, v in enumerate(out.get("views") or []):
        ep = v.get("endpoint") or ""
        al = t["pages"].get("%s/%d" % (page, i)) or t["aliases"].get(_bare(ep))
        if al and al.get("cmdb"):
            _apply_alias(out, v, ep, al)
            changed = True
        elif ep and _bare(ep) in t["live"]:
            v["gui_endpoint"] = ep
            v["endpoint"] = "api:" + _bare(ep)
            v["read_live"] = True
            changed = True
    res = out if changed else tpl
    if len(_cache) > 512:
        _cache.clear()
    _cache[(page, id(tpl))] = (tpl, res)
    return res


__all__ = ["DATA", "table", "apply"]
