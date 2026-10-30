"""The one icon set Plugin Studio, Report Studio and the SATOM Builder share.

An icon is a Bootstrap Icons class name (``bi-...``). The pattern alone is not
enough: ``bi-shield-search`` matches it and the font draws nothing. The names
here are read from the font SATOM itself vendors
(``static/vendor/bootstrap-icons``, 1.11.3) and filtered by the package
pattern, which is exactly how the Builder builds its picker list from the same
font file -- so an icon picked in the Builder always exists here, and the other
way round.

The pickers (``static/js/icon_picker.js``) read :func:`names` from
``GET /studio/icons.json``; saves call :func:`is_known`; imports call
:func:`or_default` so a package with an unknown icon still installs.
"""
from __future__ import annotations

import functools
import re
from pathlib import Path

from .plugin_package import ICON_RE

#: the vendored font's stylesheet, the only source of icon names
CSS = (Path(__file__).resolve().parent.parent / "static" / "vendor" / "bootstrap-icons"
       / "bootstrap-icons.min.css")


@functools.lru_cache(maxsize=1)
def names() -> tuple[str, ...]:
    """Every icon the vendored font draws that a plugin or app may use, sorted."""
    css = CSS.read_text(encoding="utf-8")
    found = set(re.findall(r"\.(bi-[a-z0-9-]+)::?before", css))
    return tuple(sorted(n for n in found if ICON_RE.match(n)))


def is_known(name: str | None) -> bool:
    return bool(name) and name in _known()


@functools.lru_cache(maxsize=1)
def _known() -> frozenset:
    return frozenset(names())


def or_default(name: str | None, default: str) -> tuple[str, str]:
    """``(icon, warning)``: the name when the font draws it, else ``default``
    and a sentence for the import report (empty when nothing changed)."""
    name = str(name or "")
    if is_known(name):
        return name, ""
    return default, ("the icon %s is not in this server's icon set, so it shows as %s "
                     "(pick another in the icon picker)" % (name or "(none)", default))
