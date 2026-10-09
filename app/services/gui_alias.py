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


def _rename(fields, km: dict, ep: str, cmdb: str = "") -> None:
    """GUI keys -> cmdb keys; a ``bind`` to the aliased GUI endpoint itself, or
    to the cmdb collection the view now edits, is dropped: the field lives in
    that object and is saved with it."""
    gui = {ep, _bare(ep), "api:" + _bare(ep)} | ({cmdb} if cmdb else set())
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
            _rename(b.get("fields"), km, ep, cmdb)
    if (out.get("endpoint") or "") in (ep, _bare(ep)):
        out["endpoint"] = cmdb
    _patch_fields(out, al.get("fields") or [])


def _matches(f: dict, m: dict) -> bool:
    return all(f.get(k) == v for k, v in m.items() if k != "nth")


def _patch_fields(out: dict, patches: list) -> None:
    """Per-field corrections of a page entry (``fields``), each measured on
    the lab: ``{"dialog", "match": {key|label|kind..., "nth"}, "set": {...}}``
    or ``"drop": true``. Targets are found before anything is dropped, so
    ``nth`` counts the fields as the layout has them. ``pad`` zero-fills the
    choice values (FortiWeb's GUI lists time zone ``4``, cmdb holds ``04``);
    a ``set`` value of null removes that attribute."""
    plan = []
    for p in patches:
        dd = (out.get("dialogs") or {}).get(p.get("dialog"))
        if not dd:
            continue
        m = p.get("match") or {}
        hits = [(b, f) for b in dd.get("blocks") or [] for f in b.get("fields") or []
                if _matches(f, m)]
        nth = m.get("nth", 0)
        if nth < len(hits):
            plan.append((p, hits[nth]))
    for p, (b, f) in plan:
        if p.get("drop"):
            b["fields"] = [x for x in b["fields"] if x is not f]
            continue
        for k, v in (p.get("set") or {}).items():
            if k == "pad":
                f["options"] = [dict(o, value=str(o.get("value")).zfill(int(v)))
                                if o.get("value") is not None else o
                                for o in f.get("options") or []]
            elif v is None:
                f.pop(k, None)
            else:
                f[k] = copy.deepcopy(v)


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
