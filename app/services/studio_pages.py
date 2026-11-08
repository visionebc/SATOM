"""Plugin Studio > Apps -- the SATOM pages a ``page`` plugin may open.

A ``page`` app (``StudioApp.kind``) is a plugin whose menu entry opens a page
of SATOM itself, drawn exactly as SATOM draws it: no form, no diagram, no
run. It exists for the pages an app form cannot draw (operator, 2026-11-08:
"make everything of DNS Lookup a plugin; lose no function and no view, all
must be exactly the same"). The page, its routes and its code stay in SATOM;
the plugin decides WHETHER the entry is drawn (installed and enabled) and
WHERE (its ADOMs and its folder's). WHO is the page's own permission (the
``require_permission`` stamp of its endpoint): the app's access list is not
read, so a plugin never widens nor narrows who opens the page.

The pages are a CLOSED list, :data:`PAGES`, keyed by a short id the package
names (``app.page``). A package can never point a menu entry at an arbitrary
URL or endpoint: an id not listed here is refused on import.

Pure data on purpose: ``package_check`` reads it, and the rules pack the
Builder runs carries it verbatim (no Flask there). The permission check is
:func:`studio_apps.page_allowed`.
"""
from __future__ import annotations

#: id -> {endpoint (the menu link), blueprint (what draws the entry active),
#: not_active (endpoints of that blueprint that are other entries), name}
PAGES: dict[str, dict] = {
    "dns-lookup": {"endpoint": "dns_tool.index", "blueprint": "dns_tool",
                   "not_active": ("dns_tool.resolvers",), "name": "DNS & LB Lookup"},
}


def get(key) -> dict | None:
    return PAGES.get(str(key or "").strip())


def problem(key) -> str:
    """Why *key* cannot be a page plugin's page ("" = it can)."""
    if not str(key or "").strip():
        return "a page app names the SATOM page it opens (app.page)"
    if get(key) is None:
        return "page %r is not a SATOM page a plugin may open (known: %s)" % (
            key, ", ".join(sorted(PAGES)))
    return ""
