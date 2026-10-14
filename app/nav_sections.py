"""Sort the Administrator group into alphabetical sections.

Operator, 2026-10-14: "group the Administrator section and sort the groups and
the entries of each group alphabetically". The order is alphabetical in the
language the console is drawn in, so it is computed from the RENDERED labels
here, not typed into the template: an order written by hand in English is a
random order in German, Spanish, French or Italian.

The template captures each section as one HTML chunk, built from the same
partials and the same permission and ADOM conditions as before. This module
splits a chunk into its entries (live links and the disabled entries drawn by
``partials/_nav_off.html``), sorts them by label and drops sections with no
entry left, so a profile never sees an empty toggle. Which section is open is
still derived from the markup by :mod:`app.nav_state`.
"""
from __future__ import annotations

import re
import unicodedata

from markupsafe import Markup

#: Start of one sidebar entry: a live link or a disabled ``<span>``. The
#: label inside a disabled entry is a bare ``<span>`` with no class, so it is
#: never taken for the start of another entry.
_ENTRY = re.compile(r'<(?:a|span)\s+class="fw-nav-item[\s"]')
_LABEL = re.compile(r"<span>([^<]+)</span>")


def sort_key(label: str) -> str:
    """Case- and accent-insensitive key: "Über" sorts with "U", not after "Z"."""
    text = Markup(label).unescape()
    text = unicodedata.normalize("NFKD", text)
    return "".join(c for c in text if not unicodedata.combining(c)).casefold()


def split_entries(html: str) -> list[str]:
    """The entries of *html*, one string each, in their original order."""
    html = str(html or "")
    starts = [m.start() for m in _ENTRY.finditer(html)]
    return [html[a:b].strip() for a, b in zip(starts, starts[1:] + [len(html)])]


def label_of(entry: str) -> str:
    m = _LABEL.search(entry)
    return m.group(1).strip() if m else ""


def sections(specs) -> list[dict]:
    """``[(title, icon, key, html), ...]`` → the non-empty sections, sorted.

    ``key`` is the stable ``data-nav-subgroup`` name (English): the sidebar
    script remembers open subgroups under it, so it must not change with the
    language the way ``title`` does.
    """
    out = []
    for title, icon, key, html in specs:
        entries = sorted(split_entries(html), key=lambda e: sort_key(label_of(e)))
        if entries:
            out.append({"title": title, "icon": icon, "key": key,
                        "items": [Markup(e) for e in entries]})
    return sorted(out, key=lambda s: sort_key(str(s["title"])))
