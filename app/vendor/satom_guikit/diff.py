"""What changed between the GUI layouts of two builds of one page.

``diff(a, b)`` -> a sorted list of changes, each
``{"kind", "dialog", "field", "from", "to"}`` with kind one of:

* ``added`` / ``removed`` — a field the other build's dialog does not have;
* ``moved_section`` — the field sits under another section title;
* ``condition_changed`` — what shows or hides it changed;
* ``options_added`` / ``options_removed`` — select values gained or lost;
* ``label_changed`` — Fortinet renamed it on screen (*Let's Encrypt* -> *ACME*);
* ``dialog_added`` / ``dialog_removed``.

A field is identified by its REST ``key``, else its ``label_key``, else its label.
"""
from __future__ import annotations

import json

KINDS = ("dialog_added", "dialog_removed", "added", "removed", "moved_section",
         "condition_changed", "options_added", "options_removed", "label_changed")


def _fid(f: dict) -> str:
    return f.get("key") or f.get("label_key") or f.get("label") or ""


def _values(f: dict) -> set:
    vals = set()
    for o in f.get("options") or []:
        vals.add(str(o.get("value") if isinstance(o, dict) else o))
    for opts in (f.get("options_by") or {}).values():
        for o in opts or []:
            vals.add(str(o.get("value") if isinstance(o, dict) else o))
    # an unresolved template binding ({{ ::opt.value }}) is not a value
    return {v for v in vals if "{{" not in v}


def _section(b: dict) -> str:
    return b.get("title_key") or b.get("title") or ""


def _index(tpl: dict) -> dict:
    out = {}
    for dname, d in (tpl.get("dialogs") or {}).items():
        fields = {}
        for b in d.get("blocks") or []:
            for f in b.get("fields") or []:
                fid = _fid(f)
                if fid and fid not in fields:
                    fields[fid] = (f, _section(b))
        out[dname] = fields
    return out


def _j(x) -> str:
    return json.dumps(x, sort_keys=True)


def diff(a: dict, b: dict) -> list:
    ia, ib = _index(a), _index(b)
    out = []
    for d in sorted(set(ia) | set(ib)):
        if d not in ib:
            out.append({"kind": "dialog_removed", "dialog": d, "field": "", "from": d, "to": None})
            continue
        if d not in ia:
            out.append({"kind": "dialog_added", "dialog": d, "field": "", "from": None, "to": d})
            continue
        fa, fb = ia[d], ib[d]
        for fid in sorted(set(fa) | set(fb)):
            if fid not in fb:
                out.append({"kind": "removed", "dialog": d, "field": fid,
                            "from": fa[fid][0].get("label") or fid, "to": None})
                continue
            if fid not in fa:
                out.append({"kind": "added", "dialog": d, "field": fid, "from": None,
                            "to": fb[fid][0].get("label") or fid})
                continue
            (x, sx), (y, sy) = fa[fid], fb[fid]
            if sx != sy:
                out.append({"kind": "moved_section", "dialog": d, "field": fid,
                            "from": sx, "to": sy})
            if _j(x.get("cond")) != _j(y.get("cond")):
                out.append({"kind": "condition_changed", "dialog": d, "field": fid,
                            "from": x.get("cond"), "to": y.get("cond")})
            va, vb = _values(x), _values(y)
            if vb - va:
                out.append({"kind": "options_added", "dialog": d, "field": fid,
                            "from": None, "to": sorted(vb - va)})
            if va - vb:
                out.append({"kind": "options_removed", "dialog": d, "field": fid,
                            "from": sorted(va - vb), "to": None})
            if (x.get("label") or "") != (y.get("label") or ""):
                out.append({"kind": "label_changed", "dialog": d, "field": fid,
                            "from": x.get("label"), "to": y.get("label")})
    return out


def summary(changes: list) -> dict:
    out = {k: 0 for k in KINDS}
    for c in changes:
        out[c["kind"]] = out.get(c["kind"], 0) + 1
    return out
