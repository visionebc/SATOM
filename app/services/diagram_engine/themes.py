"""Colour themes of Diagram Studio (``themes.json`` next to this file).

A theme colours a diagram by meaning: each element takes the entry of its
category FAMILY (``network.firewall`` -> ``families.network``), else of its
shape (``shapes.diamond``), else ``families.generic``; text elements take
``text.font``; containers (zones, swimlanes) take the tint of their layer
(``layers[i % n]``) with ``container`` outline and text; connectors take
``connectors[kind]`` (else ``connectors.default``). ``gradient`` fills from
``fill`` to ``fill2``; ``shadow`` adds a drop shadow to shapes.

The editor applies themes (diagram_studio_style.js); this module only loads
and checks the file, so a broken theme can never reach an operator. The
shipped themes are read-only; operators keep their own themes in the browser
and exchange them as JSON files.

Standard library only (the package runs inside the import jail too).
"""
from __future__ import annotations

import json
import os
import re

SCHEMA = "satom.diagram.themes/1"
PATH = os.path.join(os.path.dirname(__file__), "themes.json")
COLOR_RE = re.compile(r"^#[0-9A-F]{6}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,39}$")
MIN_CONTRAST = 4.5
ENTRY_KEYS = ("fill", "fill2", "stroke", "font")

_cache: dict = {}


def load() -> dict:
    """The shipped themes (parsed once per process)."""
    if "doc" not in _cache:
        with open(PATH, encoding="utf-8") as fh:
            _cache["doc"] = json.load(fh)
    return _cache["doc"]


def _lin(c: int) -> float:
    c = c / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def luminance(hex_colour: str) -> float:
    r, g, b = (int(hex_colour[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)


def contrast(a: str, b: str) -> float:
    """WCAG 2.x contrast ratio of two ``#RRGGBB`` colours (1..21)."""
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def validate(doc: dict) -> list[str]:
    """Problems of a themes document (empty = valid): structure, ``#RRGGBB``
    colours, and text contrast >= 4.5:1 on every fill it can sit on."""
    errs: list[str] = []
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return ["not a %s document" % SCHEMA]
    fams, shapes, kinds = doc.get("families") or [], doc.get("shapes") or [], doc.get("connector_kinds") or []
    themes = doc.get("themes")
    if not isinstance(themes, list) or not themes:
        return ["no themes"]
    seen: set = set()

    def colour(where, v):
        if not (isinstance(v, str) and COLOR_RE.match(v)):
            errs.append("%s: %r is not #RRGGBB" % (where, v))
            return False
        return True

    for t in themes:
        tid = t.get("id") if isinstance(t, dict) else None
        if not isinstance(tid, str) or not ID_RE.match(tid) or tid in seen:
            errs.append("theme id %r is missing, malformed or repeated" % (tid,))
            continue
        seen.add(tid)
        if not isinstance(t.get("name"), str) or not t["name"].strip():
            errs.append("%s: no name" % tid)
        for k in ("gradient", "shadow"):
            if not isinstance(t.get(k), bool):
                errs.append("%s: %s must be true or false" % (tid, k))
        entries = [("families." + f, (t.get("families") or {}).get(f)) for f in fams]
        entries += [("shapes." + s, (t.get("shapes") or {}).get(s)) for s in shapes]
        for where, e in entries:
            where = "%s.%s" % (tid, where)
            if not isinstance(e, dict):
                errs.append("%s: missing" % where)
                continue
            if all(colour("%s.%s" % (where, k), e.get(k)) for k in ENTRY_KEYS):
                for k in ("fill", "fill2"):
                    c = contrast(e["font"], e[k])
                    if c < MIN_CONTRAST:
                        errs.append("%s: text on %s is %.2f:1 (< %.1f:1)" % (where, k, c, MIN_CONTRAST))
        txt = (t.get("text") or {}).get("font")
        colour("%s.text.font" % tid, txt)
        cont = t.get("container") or {}
        okc = colour("%s.container.stroke" % tid, cont.get("stroke")) & colour("%s.container.font" % tid, cont.get("font"))
        layers = t.get("layers")
        if not isinstance(layers, list) or not layers:
            errs.append("%s.layers: at least one tint" % tid)
        else:
            for i, tint in enumerate(layers):
                if colour("%s.layers[%d]" % (tid, i), tint) and okc and contrast(cont["font"], tint) < MIN_CONTRAST:
                    errs.append("%s.layers[%d]: container text is %.2f:1" % (tid, i, contrast(cont["font"], tint)))
        conns = t.get("connectors") or {}
        if "default" not in conns:
            errs.append("%s.connectors: no default" % tid)
        for k in set(kinds) | set(conns):
            e = conns.get(k)
            if not isinstance(e, dict):
                errs.append("%s.connectors.%s: missing" % (tid, k))
                continue
            colour("%s.connectors.%s.stroke" % (tid, k), e.get("stroke"))
            if colour("%s.connectors.%s.font" % (tid, k), e.get("font")) and contrast(e["font"], "#FFFFFF") < MIN_CONTRAST:
                # connector labels sit on a white halo
                errs.append("%s.connectors.%s: label text on white is %.2f:1" % (tid, k, contrast(e["font"], "#FFFFFF")))
    return errs
