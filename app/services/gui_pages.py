"""Every FortiWeb GUI page SATOM has a layout for, drawn the way FortiWeb draws it.

Server Policy has its own hand-tuned views (``workspace.gui_*``). Every other
page comes from a *generic* template (``"generic": true``) that
``satom-harvester gui crawl`` + ``gui_extract_generic`` measured on a lab
device with a real browser, and that reached this node through the knowledge
feed like the Server Policy layout. A generic template carries:

* ``menu_path`` / ``menu_order`` -- where the page sits in FortiWeb's menu;
* ``views`` -- the page's grids (one per tab), each with its REST collection,
  its columns (REST key + FortiWeb's title), its Create New menu and the rules
  that pick the dialog a row opens (a variant dialog by ``key`` + ``prefix``,
  e.g. protocol FTP -> the FTP pool dialog);
* ``dialogs`` -- the same block / field structure as Server Policy, drawn by
  ``gui_template.dialog_view`` (conditions tri-state, live show / hide).

This module is the read side: the menu tree, the view of a page, the rows of a
view (SATOM cache only, never the device), and which dialog edits a row.
"""
from __future__ import annotations

import time

from . import gui_store, gui_template

PRODUCT = "fortiweb"
#: The hand-tuned page (its own routes); listed in the menu, never generic.
SPECIAL = {"server-policy": "workspace.gui_list"}

_nav_cache: dict = {}


def page_ids(product: str = PRODUCT) -> list:
    try:
        d = gui_store.root() / product
    except RuntimeError:
        return []
    return sorted(p.name for p in d.iterdir() if p.is_dir()) if d.is_dir() else []


def template(page: str, firmware, product: str = PRODUCT):
    """(template, match) of one page for a firmware, or (None, None). A view
    the GUI reads through its own API is tied to the cmdb collection holding
    the same objects (``gui_alias``, measured)."""
    try:
        tpl, match = gui_template.select(product, page, firmware)
    except (OSError, ValueError):
        return None, None
    if tpl is not None and product == PRODUCT:
        from . import gui_alias
        tpl = gui_alias.apply(page, tpl)
    return tpl, match


def entries(firmware, product: str = PRODUCT) -> list:
    """[{page, path, order, endpoint, special}] of every page with a layout,
    in the product's own menu order (FortiWeb, FortiGate, FortiAuthenticator,
    FortiADC: ``gui_products``)."""
    out = []
    special = SPECIAL if product == PRODUCT else {}
    got = [(page,) + tuple(template(page, firmware, product)) for page in page_ids(product)]
    crawled = any(_kind(m) == "exact" for _p, t, m in got if t)
    for page, tpl, m in got:
        if tpl is None:
            continue
        if product == PRODUCT and crawled and _kind(m) != "exact" and page not in special \
                and not _served(tpl, firmware):
            # a page of another build's menu (MCP, Custom Tracking on 7.6.8)
            # whose collections this build was never measured serving: the
            # device's own menu has no such page (its REST answers 500)
            continue
        out.append({"page": page, "path": list(tpl.get("menu_path") or [page]),
                    "order": tpl.get("menu_order"), "endpoint": tpl.get("endpoint") or "",
                    "special": special.get(page),
                    # what each tab of the page is (Settings -> ADOM Menus)
                    "kinds": page_kinds(product, tpl)})
    # a page without a measured position (the hand-tuned Server Policy) sits
    # just before the first page of its own menu group
    first: dict = {}
    for e in out:
        if e["order"] is not None:
            g = e["path"][0]
            first[g] = min(first.get(g, e["order"]), e["order"])
    for e in out:
        if e["order"] is None:
            e["order"] = first.get(e["path"][0], 10_000) - 0.5
    return sorted(out, key=lambda e: (e["order"], e["path"]))


def _kind(match) -> str:
    return (match or {}).get("kind") if isinstance(match, dict) else str(match or "")


def _served(tpl: dict, firmware) -> bool:
    """True when the build of ``firmware`` was measured serving one of the
    collections the page lists or edits (api_library: measured / blind).
    A build nobody measured answers False for all; :func:`entries` asks only
    for a build whose own GUI was crawled."""
    import re as _re
    from . import api_library
    m = _re.search(r"(\d+\.\d+\.\d+)", firmware or "")
    if not m:
        return True
    eps = {v.get("endpoint") for v in views(tpl)} | {
        f.get("endpoint") for d in (tpl.get("dialogs") or {}).values()
        for b in d.get("blocks") or [] for f in b.get("fields") or [] if f.get("kind") == "table"} | {
        d.get("endpoint") for d in (tpl.get("dialogs") or {}).values()}
    for ep in sorted(e for e in eps if e and not e.startswith(("api:", "gui:"))):
        try:
            if api_library.fields_at(PRODUCT, ep, m.group(1)).get("status") in ("measured", "blind"):
                return True
        except Exception:  # noqa: BLE001 -- the library never hides a page by failing
            return True
    return False


def tree(items: list) -> list:
    """Nested menu: [{label, children: [...]}] / [{label, entry}] in order."""
    root: list = []
    for e in items:
        level = root
        for depth, label in enumerate(e["path"]):
            leaf = depth == len(e["path"]) - 1
            node = next((n for n in level if n["label"] == label and ("entry" in n) == leaf), None)
            if node is None:
                node = {"label": label, "entry": e} if leaf else {"label": label, "children": []}
                level.append(node)
            if not leaf:
                level = node["children"]
    return root


# --------------------------------------------------------------------------- #
# Settings -> ADOM Menus: page classes an administrator can keep out of menus
# --------------------------------------------------------------------------- #
#: A tab SATOM does not draw as configuration, by the banner the page shows:
#: ``monitor`` "Live monitor" (the device draws it from live data),
#: ``device_managed`` "Managed on the device" (the GUI edits it through its own
#: private calls), ``gui_only`` "No API on this build (GUI only)". Every other
#: tab is ``config`` and is never hidden.
KINDS = ("monitor", "device_managed", "gui_only")
#: app_settings key of each switch ('1' = the class leaves every ADOM menu)
KIND_KEYS = {"monitor": "gui.hide_monitor_pages",
             "device_managed": "gui.hide_device_managed_pages",
             "gui_only": "gui.hide_gui_only_pages"}


def view_kind(view: dict) -> str:
    """The class of one tab (a view as the page renders it)."""
    from . import gui_products
    if view.get("monitor"):
        return "monitor"
    if view.get("device_managed"):
        return "device_managed"
    if gui_products.is_gui_only(view.get("endpoint")):
        return "gui_only"
    return "config"


def page_kinds(product: str, tpl: dict) -> tuple:
    """The sorted classes of a page's tabs. A "Not in GUI, but in CLI" page
    is configuration whatever its tabs say; a FortiAnalyzer page is read the
    way it renders (``gui_products.faz_template`` marks its views)."""
    if tpl.get("gui_absent"):
        return ("config",)
    if product == "fortianalyzer":
        from . import gui_products
        tpl = gui_products.faz_template(tpl)
    return tuple(sorted({view_kind(v) for v in views(tpl) if isinstance(v, dict)} or {"config"}))


def hidden_kinds() -> frozenset:
    """The classes kept out of the ADOM menus (empty on any error: a menu
    never loses pages because the setting is unreadable)."""
    try:
        from ..models import AppSetting
        return frozenset(k for k in KINDS if AppSetting.get(KIND_KEYS[k]) == "1")
    except Exception:  # noqa: BLE001
        return frozenset()


def set_hidden_kinds(kinds) -> None:
    from ..models import AppSetting
    on = set(kinds or ())
    for k in KINDS:
        AppSetting.set(KIND_KEYS[k], "1" if k in on else "0")


def is_hidden_entry(entry: dict, hidden) -> bool:
    """True when every tab of the page is of a hidden class (a page with one
    configuration tab always stays)."""
    kinds = set(entry.get("kinds") or ("config",))
    return bool(hidden) and kinds <= set(hidden)


def kind_counts(appliances) -> dict:
    """{product: {kind: pages}} over the first device of each product (its
    build's menu): what each switch takes out of that ADOM. A page counts
    under a class only when every tab is of it."""
    from . import gui_products
    out: dict = {}
    for a in appliances:
        product = gui_products.product_of(a)
        if product is None or product in out:
            continue
        counts = {k: 0 for k in KINDS}
        for e in entries(gui_store.firmware_of(a), product):
            if len(e["kinds"]) == 1 and e["kinds"][0] in counts:
                counts[e["kinds"][0]] += 1
        out[product] = counts
    return out


def nav_for(appliance) -> list:
    """The product menu (FortiWeb / FortiGate / FortiAuthenticator /
    FortiADC / FortiAnalyzer) of the pages SATOM can draw for this device,
    from the layouts of its exact build, else the nearest measured one
    (``gui_store.resolve``); ``[]`` when the product has no layout at all.
    Pages whose every tab is of a class Settings -> ADOM Menus hides are
    left out (60 s cache per product, firmware and those switches: the
    sidebar renders on every page)."""
    from . import gui_products
    product = gui_products.product_of(appliance)
    if product is None:
        return []
    fw = gui_store.firmware_of(appliance)
    hide = hidden_kinds()
    try:
        key = (str(gui_store.root()), product, fw, hide)
    except RuntimeError:
        return []
    hit = _nav_cache.get(key)
    if hit and time.monotonic() - hit[0] < 60:
        return hit[1]
    t = tree([e for e in entries(fw, product) if not is_hidden_entry(e, hide)])
    _nav_cache[key] = (time.monotonic(), t)
    return t


def contains(node: dict, page: str | None) -> bool:
    if "entry" in node:
        return node["entry"]["page"] == page
    return any(contains(c, page) for c in node.get("children") or [])


# --------------------------------------------------------------------------- #
# Views, rows, cells
# --------------------------------------------------------------------------- #
def views(tpl: dict) -> list:
    v = tpl.get("views")
    if v:
        return v
    lst = tpl.get("list") or {}
    return [{"endpoint": tpl.get("endpoint") or "", "columns": lst.get("columns") or [],
             "create_menu": [], "dialogs": []}]


def view_of(tpl: dict, idx) -> tuple:
    vs = views(tpl)
    try:
        i = max(0, min(int(idx or 0), len(vs) - 1))
    except (TypeError, ValueError):
        i = 0
    return i, vs[i]


def tab_label(tpl: dict, view: dict, i: int) -> str:
    """A tab's title: its own label, else the last word of its collection
    (``service.custom`` -> Custom)."""
    if view.get("label"):
        return view["label"]
    ep = view.get("endpoint") or ""
    tail = ep.rsplit("/", 1)[-1]
    tail = tail.split(".", 1)[1] if "." in tail else tail
    return tail.replace("-", " ").title() or str(i + 1)


def rows(appliance_id: int, endpoint: str) -> tuple:
    """(rows, meta) of a REST collection from the SATOM cache; ([], None) when
    no registry logical of the collection is cached."""
    from . import read_layer
    if not endpoint:
        return [], None
    first = None
    for ln in read_layer.registry_logicals(endpoint):
        got, meta = read_layer.read_objects(appliance_id, ln)
        got = [r for r in got or [] if isinstance(r, dict)]
        if got:
            return got, meta
        first = first or meta
    return [], first


def live_rows(appliance, endpoint: str) -> tuple:
    """(rows, meta) of a GUI API list with no cmdb twin (FortiWeb's predefined
    entries, ``gui_alias`` ``live``), read from the device: never cached, only
    through ``gui_bound.safe_api``. ([], None) when refused or unreachable."""
    from . import gui_bound
    got = gui_bound.read_rows(appliance, endpoint)
    if got is None:
        return [], None
    return got, {"generated_at": None, "source": "live", "cached": False}


def value_labels(tpl: dict) -> dict:
    """{REST key: {value: label}} from the choices the page's own dialogs offer
    (type reverse-proxy -> "Reverse Proxy"): the text FortiWeb's grid shows."""
    out: dict = {}
    sub = set(tpl.get("subtable_dialogs") or ())
    for name, d in (tpl.get("dialogs") or {}).items():
        if name in sub:
            continue
        for b in d.get("blocks") or []:
            for f in b.get("fields") or []:
                k = f.get("key")
                if not k:
                    continue
                opts = list(f.get("options") or [])
                for more in (f.get("options_by") or {}).values():
                    opts += list(more or [])
                from .gui_template import split_labels
                for o in split_labels(opts):
                    if isinstance(o, dict) and o.get("label"):
                        out.setdefault(k, {}).setdefault(str(o.get("value")), o["label"])
    return out


def cell(row: dict, col: dict, labels: dict | None = None):
    """The text of one grid cell: the REST value, shown with the label the
    page's dialogs give it (``labels``, :func:`value_labels`), enable / disable
    title-cased as FortiWeb's grids do, lists joined. A column the crawl could
    not tie to a REST key (``unmatched``) stays empty rather than guessing.
    ``<key>_val`` is not used: on some collections it is an index."""
    if col.get("unmatched"):
        return ""
    k = col.get("id")
    v = row.get(k)
    lab = (labels or {}).get(k) or {}
    if not isinstance(v, (list, dict)) and str(v) in lab:
        return lab[str(v)]
    if v in ("enable", "disable"):
        return v.title()
    if isinstance(v, list):
        return ", ".join(str(x.get("name", x)) if isinstance(x, dict) else str(x) for x in v)
    if isinstance(v, dict):
        return str(v.get("name") or v.get("value") or "")
    return "" if v is None else v


def dialog_for(view: dict, row: dict | None) -> str | None:
    """The dialog a row opens: the first variant rule whose field starts with
    its prefix (case-insensitive), else the plain dialog."""
    rules = view.get("dialogs") or []
    for r in rules:
        if "key" in r and row is not None and \
                str(row.get(r["key"]) or "").lower().startswith(str(r["prefix"]).lower()):
            return r["dialog"]
    plain = [r for r in rules if "key" not in r]
    if plain:
        return plain[0]["dialog"]
    return rules[0]["dialog"] if rules else None


def view_for_dialog(tpl: dict, dialog: str) -> tuple:
    for i, v in enumerate(views(tpl)):
        if any(r["dialog"] == dialog for r in v.get("dialogs") or []):
            return i, v
    return view_of(tpl, 0)


def table_endpoint(tpl: dict, dialog: str, subtable: str) -> str:
    for b in tpl["dialogs"][dialog]["blocks"]:
        for f in b["fields"]:
            if f.get("kind") == "table" and f.get("subtable") == subtable:
                return f.get("endpoint") or ""
    return ""


__all__ = ["PRODUCT", "SPECIAL", "page_ids", "template", "entries", "tree", "nav_for",
           "contains", "views", "view_of", "tab_label", "rows", "live_rows", "cell", "value_labels", "dialog_for",
           "view_for_dialog", "table_endpoint"]
