"""Turn the flat web endpoint registry into a navigable section tree.

This is the web port of the desktop ``app/registry/tree.py`` "API Menu" builder.
The desktop version walks a :class:`Registry` of :class:`Endpoint` objects and
nests them by URN segments; the web app instead consumes the display dicts
produced by :func:`app.registry.loader.get_all_endpoints` — each shaped as
``{name, urn, path, section, methods, method}`` — and groups them one level deep:

    section  >  endpoint leaf

The grouping key is the precomputed ``section`` field (already derived from each
URN by :func:`app.registry.categories.category_for`); sections are ranked by
``categories.SECTION_ORDER`` so the web menu mirrors the desktop layout, and the
endpoints keep the loader's name ordering inside each section.

The module is pure Python — no Qt, no Flask, no network, and no import side
effects — so it is fully testable headless and safe to import anywhere.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

# URN segment separators: path slashes *and* the dotted FortiWeb sub-resources
# (``status.systemstatus``, ``custom-access.policy``).  ``-`` stays intact.
_SEP = re.compile(r"[./]+")

# Bucket for endpoints whose section could not be derived (loader yields None).
_FALLBACK_SECTION = "Other"


def split_urn(urn: str) -> List[str]:
    """``/api/v2.0/cmdb/server-policy/policy`` -> the ordered segment labels.

    Query strings (``?...``), fragments and leading/trailing slashes are dropped.
    Mirrors the desktop ``split_urn`` so deeper URN-based nesting stays possible.
    """
    u = (urn or "").strip()
    for cut in ("?", "#"):
        i = u.find(cut)
        if i != -1:
            u = u[:i]
    return [seg for seg in _SEP.split(u.strip().strip("/")) if seg]


@dataclass
class NavNode:
    """One node of the API menu.

    A node is either a *section* folder (has ``children``), an *endpoint* leaf
    (has ``endpoints``), or both at once.  ``endpoints`` is a list because two
    friendly keys can occasionally share a URN.  The endpoints stored here are
    the loader display *dicts*, not ORM objects, so a template can read
    ``ep.name`` / ``ep.urn`` / ``ep.method`` directly.
    """

    label: str
    path: str = ""            # stable id: the section name (or dotted URN id)
    order: int = 0            # display rank; lower sorts first, ties broken by label
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    children: Dict[str, "NavNode"] = field(default_factory=dict)

    @property
    def is_endpoint(self) -> bool:
        return bool(self.endpoints)

    @property
    def is_section(self) -> bool:
        return bool(self.children)

    def child_nodes(self) -> List["NavNode"]:
        """Children in stable order: explicit ``order`` first, then alphabetical."""
        return sorted(self.children.values(), key=lambda n: (n.order, n.label.lower()))

    def descendant_count(self) -> int:
        """Total endpoints at and below this node (used for section badges)."""
        n = len(self.endpoints)
        for child in self.children.values():
            n += child.descendant_count()
        return n


def _section_order() -> Dict[str, int]:
    """Map each known section name to its rank in ``SECTION_ORDER``.

    Imported lazily so this module stays import-side-effect-free and only couples
    to :mod:`app.registry.categories` when a tree is actually built.
    """
    try:
        from .categories import SECTION_ORDER
    except Exception:
        return {}
    return {name: i for i, name in enumerate(SECTION_ORDER)}


def build_category_tree(
    endpoints: List[Dict[str, Any]], *, root_label: str = "API"
) -> NavNode:
    """Group loader endpoint dicts into a ``section > endpoint`` :class:`NavNode` tree.

    ``endpoints`` is the list returned by
    :func:`app.registry.loader.get_all_endpoints`.  Each endpoint is filed under
    its ``section`` field (falling back to ``"Other"``); sections are ranked by
    ``categories.SECTION_ORDER`` and endpoints keep the loader's name ordering.
    The returned root's :meth:`NavNode.child_nodes` yields the ordered sections.
    """
    order_of = _section_order()
    root = NavNode(label=root_label)
    for ep in endpoints or []:
        if not isinstance(ep, dict):
            continue
        section = ep.get("section") or _FALLBACK_SECTION
        node = root.children.get(section)
        if node is None:
            node = NavNode(
                label=section,
                path=section,
                order=order_of.get(section, 999),
            )
            root.children[section] = node
        node.endpoints.append(ep)
    return root


def build_tree(
    endpoints: List[Dict[str, Any]], *, root_label: str = "API"
) -> NavNode:
    """Group endpoints into a *deep* tree keyed by their raw URN segments.

    Faithful to the desktop ``build_tree``.  Not used by the API Explorer sidebar
    (which is section-grouped via :func:`build_category_tree`) but kept for parity
    and possible future URN drill-down views.
    """
    root = NavNode(label=root_label)
    for ep in endpoints or []:
        if not isinstance(ep, dict):
            continue
        segments = split_urn(ep.get("urn") or ep.get("path") or "")
        if not segments:
            continue
        node = root
        acc: List[str] = []
        for seg in segments:
            acc.append(seg)
            child = node.children.get(seg)
            if child is None:
                child = NavNode(label=seg, path=".".join(acc))
                node.children[seg] = child
            node = child
        node.endpoints.append(ep)
    return root


__all__ = ["NavNode", "split_urn", "build_category_tree", "build_tree"]
