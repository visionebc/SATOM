"""GUI layout templates per EXACT build: where they come from and which one a device gets.

Two sources, one resolver:

* **packs** (knowledge lane, section ``gui-templates``): ``satom.gui-template/2``
  items the harvester measured on a lab device, imported into
  ``data/gui-templates/<product>/<page>/<version>-<build>.json`` (each file
  records its pack provenance). They follow the knowledge feed: a new build
  needs no SATOM release;
* **shipped** (``app/registry/gui_templates/<product>/<page>/<train>.json``,
  ``/1``): the templates a release carries, used when no pack has the page.

:func:`resolve` picks, for one device firmware, the closest measured layout:
same version (exact build first), else same train, else the closest older
train, else the oldest; a pack beats a shipped template of the same version.
The caller is told how close it is (``origin``) so the page can say so.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from ..vendor import satom_guikit as guikit
from . import firmware_versions as fv

_BUILD_RE = re.compile(r"build\s*0*(\d+)", re.I)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,80}$")


def root() -> Path:
    """``GUI_TEMPLATE_DIR`` when configured (tests), else ``data/gui-templates``
    (under ``data/``, so the standby's datasync carries it)."""
    from flask import current_app
    from .api_pack import data_root
    conf = current_app.config.get("GUI_TEMPLATE_DIR")
    return Path(conf) if conf else data_root() / "gui-templates"


def shipped_root() -> Path:
    from . import gui_template
    return Path(gui_template.ROOT)


def file_for(product: str, page: str, version: str, build: str) -> Path:
    for t in (product, page, version, build):
        if not _TOKEN_RE.match(str(t or "")):
            raise ValueError("bad template identity token %r" % (t,))
    return root() / product / page / ("%s-%s.json" % (version, build))


def build_of(firmware) -> str:
    m = _BUILD_RE.search(str(firmware or ""))
    return m.group(1) if m else ""


def _vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3]) or (0,)


@lru_cache(maxsize=64)
def _read(path: str, mtime: float) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load(path: Path) -> dict:
    return _read(str(path), path.stat().st_mtime)


def candidates(product: str, page: str) -> list:
    """Every template of a page: ``{"version", "build", "train", "source", "path"}``."""
    out = []
    try:
        d = root() / product / page
    except RuntimeError:            # no app context (a bare script): shipped only
        d = None
    for p in sorted(d.glob("*.json")) if d is not None and d.is_dir() else []:
        try:
            ident = guikit.identity(load(p))
        except (OSError, ValueError):
            continue
        out.append({**ident, "source": "pack", "path": p})
    s = shipped_root() / product / page
    for p in sorted(s.glob("*.json")) if s.is_dir() else []:
        try:
            ident = guikit.identity(load(p))
        except (OSError, ValueError):
            continue
        out.append({**ident, "source": "shipped", "path": p})
    return out


def view_template(c: dict) -> dict:
    """The template as the views read it (``applies_to`` = train string, the
    exact identity and the origin alongside)."""
    tpl = dict(load(c["path"]))
    tpl["applies_to"] = c["train"]
    tpl["exact"] = {k: c[k] for k in ("version", "build", "train")}
    tpl["origin"] = {"source": c["source"], "version": c["version"], "build": c["build"],
                     "provenance": (tpl.get("_import") or {}).get("provenance", "")}
    return tpl


def resolve(product: str, page: str, firmware) -> tuple:
    """``(candidate, match, closeness)`` for one device firmware.

    ``match`` keeps the train-level vocabulary the pages use (``exact`` = same
    train, ``older``, ``newer``, ``unknown``); ``closeness`` is finer:
    ``build`` (same version and build) · ``version`` · ``train`` · ``older`` ·
    ``newer`` · ``unknown``. ``(None, None, None)`` when the page has none."""
    cands = candidates(product, page)
    if not cands:
        return None, None, None
    ver = fv.normalize(firmware)
    build = build_of(firmware)
    rank = lambda c: (_vkey(c["version"]), c["source"] == "pack", c["build"])  # noqa: E731
    if not ver or len(_vkey(ver)) < 2:
        return max(cands, key=rank), "unknown", "unknown"
    train = fv.line_of(ver)
    same_ver = [c for c in cands if c["version"] == ver]
    if same_ver:
        exact = [c for c in same_ver if build and c["build"] == build]
        if exact:
            return max(exact, key=lambda c: c["source"] == "pack"), "exact", "build"
        return max(same_ver, key=rank), "exact", "version"
    same_train = [c for c in cands if c["train"] == train]
    if same_train:
        below = [c for c in same_train if _vkey(c["version"]) < _vkey(ver)]
        pick = max(below, key=rank) if below else min(same_train, key=rank)
        return pick, "exact", "train"
    older = [c for c in cands if _vkey(c["train"]) < _vkey(train)]
    if older:
        return max(older, key=rank), "older", "older"
    return min(cands, key=rank), "newer", "newer"


__all__ = ["root", "file_for", "build_of", "candidates", "resolve", "view_template", "load"]
