"""Derive the sidebar's open sections from the sidebar itself.

Every ``.fw-nav-group`` in ``base.html`` renders ``open`` from a hand-written
blueprint list::

    <div class="fw-nav-group {{ 'open' if request.blueprint in
         ['appliances','audit','users','templates','naming','capacity','database'] }}"
         data-nav-group="Administrator">

That list is a SECOND author for a fact the group body already states — the
body marks exactly one ``.fw-nav-item`` ``active``. Two authors for one fact is
how this repo has been bitten before (``asset()`` vs a bare ``url_for``, the
licence footer template vs the curated pages), and it drifted here too: adding
a page to a group means remembering to add its blueprint to the list, and
nothing fails when you don't. The page just renders with its OWN section
collapsed, so the operator lands on ``/administration/change-types/`` and the
Administrator section they just clicked through folds shut behind them.

Measured on 2026-09-14 against the live route map: five Administrator blocks
(one per ADOM) name none of ``cr_types``, ``adom_assets``, ``console``,
``process`` or ``metrics_admin``, all five of which are rendered INTO those
blocks by ``partials/nav_*.html``. The partial contributes the item; the list
lives in the caller; neither knows about the other.

:func:`autoopen` closes that by deriving the state instead of declaring it:
the markup is scanned once, and any group (or subgroup) whose extent contains
an active item is marked ``open``. It only ever ADDS the class, so a group the
template opened for its own reasons — ``ADOMs`` is unconditionally open, and
pages that mark no item active still rely on the blueprint list — keeps that
state. The blueprint lists therefore stop being "which section holds this
page" (derived here) and become only "which section to open when nothing is
active", which is a fact they can actually state on their own.

Done server-side ON PURPOSE rather than in ``main.js``: the sidebar is painted
by the server precisely so a page load shows the right state with no flash
(see the accordion block in ``main.js``). A JS pass that opened the section
after paint would fix the state and introduce a visible fold-then-unfold on
every one of these pages.
"""
from __future__ import annotations

import re

from markupsafe import Markup

#: Any ``<div>`` opening tag, captured with its attribute blob.
_DIV_OPEN = re.compile(r"<div\b([^>]*)>", re.I)
_DIV_ANY = re.compile(r"<div\b[^>]*>|</div\s*>", re.I)
_CLASS = re.compile(r'class\s*=\s*"([^"]*)"', re.I)

#: A group header; the accordion toggles these. ``fw-nav-group-body`` and
#: ``fw-nav-subgroup-body`` are deliberately NOT matched — token equality, not
#: a substring test, because ``"fw-nav-group" in "fw-nav-group-body"`` is true
#: and would make every body its own group.
_GROUP_TOKENS = ("fw-nav-group", "fw-nav-subgroup")

#: Classes that mark a clickable destination in the sidebar. The section
#: headers also carry ``fw-nav-item`` (``.fw-nav-subtoggle`` is one), but a
#: header is never ``active``, so requiring BOTH tokens is enough.
_ITEM_TOKENS = ("fw-nav-item", "fw-nav-subitem")


def _tokens(attrs: str) -> list[str]:
    m = _CLASS.search(attrs)
    return m.group(1).split() if m else []


def _has_active_item(fragment: str) -> bool:
    """True if *fragment* contains a sidebar item rendered ``active``."""
    for m in _CLASS.finditer(fragment):
        cls = m.group(1).split()
        if "active" in cls and any(t in cls for t in _ITEM_TOKENS):
            return True
    return False


def _extent(html: str, open_end: int) -> int:
    """Return the offset just past the ``</div>`` closing the tag that ends at
    *open_end*, by counting nested ``<div>``s. Falls back to end-of-string on
    malformed markup rather than raising — a broken sidebar must still render.
    """
    depth = 1
    for m in _DIV_ANY.finditer(html, open_end):
        depth += 1 if m.group(0)[1] != "/" else -1
        if depth == 0:
            return m.end()
    return len(html)


def autoopen(html: str) -> Markup:
    """Mark every nav group holding an active item ``open``.

    Idempotent, and a no-op on markup with no groups or no active item.
    """
    edits: list[tuple[int, int, str]] = []
    for m in _DIV_OPEN.finditer(html):
        attrs = m.group(1)
        cls = _tokens(attrs)
        if not any(t in cls for t in _GROUP_TOKENS):
            continue
        if "open" in cls:
            continue
        if not _has_active_item(html[m.end():_extent(html, m.end())]):
            continue
        cm = _CLASS.search(attrs)
        # Offsets are relative to the attribute blob; rebase onto `html`.
        base = m.start(1)
        edits.append((base + cm.end(1), base + cm.end(1), " open"))

    # Apply back-to-front so earlier offsets stay valid.
    for start, end, text in reversed(edits):
        html = html[:start] + text + html[end:]
    return Markup(html)
