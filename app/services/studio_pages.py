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
#: not_active (endpoints of that blueprint that are other entries), name,
#: files (path under the source root, what it is): the code the page is made
#: of, shown read-only in Plugin Studio (operator, 2026-11-08: "it is a
#: plugin, it must be possible to see how it is made")}
PAGES: dict[str, dict] = {
    "dns-lookup": {"endpoint": "dns_tool.index", "blueprint": "dns_tool",
                   "not_active": ("dns_tool.resolvers",), "name": "DNS & LB Lookup",
                   "files": (
                       ("app/views/dns_tool.py",
                        "Routes: the lookup, SPO Regex, records, decommission"),
                       ("app/services/dns_tool.py",
                        "The lookup: resolvers, the fleet's LB cache, matching, SPO Regex"),
                       ("app/services/dns_decommission.py",
                        "Decommission: the plan and its apply"),
                       ("app/templates/dns_lookup/index.html",
                        "The page: layout, tables, dialogs and its script"),
                       ("app/services/studio_dns.py",
                        "The same code as Plugin Studio steps (DNS: look names up, ...)"),
                   )},
}

#: A source file larger than this is not shown (none of the listed ones is).
SOURCE_MAX_BYTES = 512 * 1024


class SourceError(ValueError):
    """A source file that is not one of the page's own, or unreadable."""


def get(key) -> dict | None:
    return PAGES.get(str(key or "").strip())


def files(key) -> list[dict]:
    page = get(key) or {}
    return [{"path": p, "role": r} for p, r in page.get("files") or ()]


def read_source(key, path, root) -> str:
    """The text of *path*, one of the files page *key* lists, under *root*
    (the directory that holds ``app/``). Anything else is refused: the list is
    closed, a package never names a file, and no path is joined from input."""
    wanted = str(path or "")
    listed = {p for p, _r in (get(key) or {}).get("files") or ()}
    if wanted not in listed:
        raise SourceError("%r is not a source file of page %r" % (wanted, key))
    import os
    full = os.path.realpath(os.path.join(str(root), wanted))
    if not full.startswith(os.path.realpath(str(root)) + os.sep):
        raise SourceError("%r is outside the source root" % wanted)
    try:
        if os.path.getsize(full) > SOURCE_MAX_BYTES:
            raise SourceError("%s is larger than %d bytes" % (wanted, SOURCE_MAX_BYTES))
        with open(full, encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        raise SourceError("%s cannot be read: %s" % (wanted, exc.strerror)) from None


def problem(key) -> str:
    """Why *key* cannot be a page plugin's page ("" = it can)."""
    if not str(key or "").strip():
        return "a page app names the SATOM page it opens (app.page)"
    if get(key) is None:
        return "page %r is not a SATOM page a plugin may open (known: %s)" % (
            key, ", ".join(sorted(PAGES)))
    return ""
