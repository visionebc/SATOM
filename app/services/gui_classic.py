"""Which of SATOM's own pages a measured device GUI page replaces.

SATOM drew device objects in its own pages before the GUI crawl existed:
FortiWeb Server Objects (``server_objects.overview?type=``), Web Protection
(``web_protection.menu_page``) and the configuration / WAF sections
(``section_config.section?type=``); the FortiGate / FortiAuthenticator /
FortiADC ``fgt_menu`` / ``fac_menu`` / ``adc_menu`` leaves. Since 2026-10-11 the sidebar of those ADOMs
draws only the device's own menu (``gui_pages``); what is left here:

* an old URL for a collection a measured page draws redirects there
  (:func:`redirect_for`, :func:`redirect_item`) -- unless ``?classic=1``, which
  the new screens still use for the actions the old pages host;
* :func:`classic_leaf` names the old menu leaf of a collection, so a FortiWeb
  page offers the SATOM tools that leaf had (config templates, artifacts...).

The coverage comes from the layouts of the device's firmware.
"""
from __future__ import annotations

import time

from . import gui_pages, gui_store

_map_cache: dict = {}


def page_map(appliance) -> dict:
    """{key: {"page", "v"}} of every collection a measured GUI page of this
    device's firmware draws (60 s cache per product and firmware, like the
    menu). The key is what the product's old SATOM menu names a collection
    by: FortiWeb a registry logical, FortiGate the cmdb path, FortiAuthenticator
    the registry logical (and the REST resource name)."""
    from . import gui_products
    product = gui_products.product_of(appliance)
    if product is None:
        return {}
    from . import read_layer
    fw = gui_store.firmware_of(appliance)
    try:
        key = (str(gui_store.root()), product, fw)
    except RuntimeError:
        return {}
    hit = _map_cache.get(key)
    if hit and time.monotonic() - hit[0] < 60:
        return hit[1]
    out: dict = {}
    fac = gui_products.adapter(gui_products.FORTIAUTH)
    ents = gui_pages.entries(fw, product)
    if product == gui_products.FORTIADC:
        # FortiView (``view.*``) comes first in FortiADC's menu and its
        # dashboards read configuration entities too: without this,
        # ``system_global`` would move to the Threat Map, not System > Settings
        ents = sorted(ents, key=lambda e: e["page"].startswith("view."))
    def names_for(ep):
        if product == gui_pages.PRODUCT:
            names = list(read_layer.registry_logicals(ep))
            if ep.count("/") >= 2:
                # a sub-table drawn as its own list (Firewall Admin Policy's
                # match list) is where its parent object lives
                names += [n for n in read_layer.registry_logicals(ep.rsplit("/", 1)[0])
                          if n not in names]
            return names
        if gui_products.read_only_endpoint(ep) and not gui_products.is_monitor(ep):
            return []
        if product == gui_products.FORTIAUTH:
            lg, _path = fac.resolve(appliance, ep)
            return [n for n in (lg, gui_products.lib_key(product, ep)) if n]
        names = [ep]
        if product == gui_products.FORTIADC and gui_products.ADC_CHILD in ep:
            # a list of a settings object's child table (BFD interfaces,
            # Connection Limit rules) is where that settings object lives:
            # it has no fields of its own
            names.append(ep.split(gui_products.ADC_CHILD)[0])
        return names

    inside = []
    for e in ents:
        if e["special"]:
            continue
        tpl, _m = gui_pages.template(e["page"], fw, product)
        if tpl is None:
            continue
        views = gui_pages.views(tpl)
        for i, v in enumerate(views):
            # ``covers``: the cmdb objects a FortiWeb GUI API settings page
            # edits (Global Log Settings is log/disk, log/syslogd...)
            for ep in [v.get("endpoint") or ""] + [c for c in v.get("covers") or ()
                                                    if isinstance(c, str)]:
                for ln in names_for(ep):
                    out.setdefault(ln, {"page": e["page"], "v": i})
        for dk, ep in dialog_endpoints(tpl):
            inside.append((ep, e["page"], view_of_dialog(views, dk)))
    # what a page draws INSIDE a dialog (SNMP communities as a table of the
    # SNMP form, NTP written by the Settings form) is drawn there too -- after
    # every page's own lists, which stay where a collection moves first
    for ep, page, i in inside:
        for ln in names_for(ep):
            out.setdefault(ln, {"page": page, "v": i})
    _map_cache[key] = (time.monotonic(), out)
    return out


def dialog_endpoints(tpl: dict) -> list:
    """``[(dialog key, endpoint)]`` a page's dialogs draw or write besides
    their own object: an inline table, a ``write`` / ``writes`` target, a
    field ``bind``. A reference selector names a source, not something the
    page draws, and is left out."""
    out = []
    for dk, d in (tpl.get("dialogs") or {}).items():
        if not isinstance(d, dict):
            continue
        eps = [d.get("endpoint"), (d.get("write") or {}).get("endpoint")]
        eps += [(w or {}).get("endpoint") for w in d.get("writes") or []]
        for b in d.get("blocks") or []:
            for f in (b.get("fields") or []) if isinstance(b, dict) else []:
                if f.get("kind") == "table":
                    eps.append(f.get("endpoint"))
                eps.append((f.get("bind") or {}).get("endpoint"))
        out.extend((dk, ep) for ep in eps if isinstance(ep, str) and ep)
    return out


def view_of_dialog(views: list, dk: str) -> int:
    """The index of the view that opens dialog ``dk`` (0 when none says)."""
    for i, v in enumerate(views):
        refs = {x.get("dialog") if isinstance(x, dict) else x
                for k in ("dialogs", "create_menu") for x in v.get(k) or []}
        if dk in refs or v.get("form") == dk:
            return i
    return 0


def item_keys(item) -> list:
    """The collections an old FortiGate / FortiAuthenticator / FortiADC menu
    leaf reads: ``fgt_menu`` tabs are (cmdb path, label), ``fac_menu`` logicals
    are (registry logical, label), ``adc_menu`` tabs carry ``.logical`` (the
    REST entity name)."""
    pairs = getattr(item, "tabs", None) or getattr(item, "logicals", None) or ()
    return [p[0] if isinstance(p, (tuple, list)) else getattr(p, "logical", p) for p in pairs]


def product_covered(item, pmap: dict, appliance=None) -> bool:
    """Every collection of an old menu leaf is drawn by a measured page. A
    collection the device's exact build is measured NOT serving (the old
    FortiADC menu names 8.0 entities a 7.6.7 answers 404 for) is not
    waited for: there is nothing to draw."""
    keys = item_keys(item)
    drawn = [k for k in keys if k in pmap]
    return bool(drawn) and all(k in pmap or not_served(appliance, k) for k in keys)


def not_served(appliance, key: str) -> bool:
    """Is ``key`` measured as NOT served by the appliance's build (registry
    sweep evidence)? Unknown is "served": never skipped on a guess."""
    if appliance is None:
        return False
    from . import gui_products
    product = gui_products.product_of(appliance)
    if product != gui_products.FORTIADC:
        return False
    try:
        from ..registry import loader
    except Exception:  # noqa: BLE001
        return False
    try:
        loader.resolve_for(product, key, loader.version_of(appliance))
    except loader.EndpointNotServed:
        return True
    except Exception:  # noqa: BLE001 -- not in the registry: unknown
        return False
    return False




def redirect_item(appliance, item, tab=None, args=None):
    """The GUI page URL an old FortiGate / FortiAuthenticator / FortiADC leaf moves to
    (the requested tab's page, else the first), or None: ``?classic=1``, no
    device, or a leaf with a tab no measured page draws."""
    from flask import url_for
    if appliance is None or item is None or (args is not None and args.get("classic")):
        return None
    pmap = page_map(appliance)
    if not product_covered(item, pmap, appliance):
        return None
    keys = [k for k in item_keys(item) if k in pmap]
    t = pmap.get(tab) if tab in keys else pmap.get(keys[0])
    return url_for("workspace.fwgui_list", appliance_id=appliance.id, page=t["page"],
                   v=t["v"] or None)












def item_links(appliance, groups, endpoint: str) -> dict:
    """``{item key: URL}`` for a dashboard's menu map: the measured page an
    old FortiGate / FortiAuthenticator leaf moves to (:func:`redirect_item`),
    else the classic page ``endpoint`` still draws for it. A card links where
    the item lives instead of through a redirect."""
    from flask import url_for
    out = {}
    for g in groups or []:
        for it in getattr(g, "items", None) or []:
            try:
                moved = redirect_item(appliance, it)
            except Exception:  # noqa: BLE001 -- the classic page always renders
                moved = None
            out[it.key] = moved or url_for(endpoint, item_key=it.key)
    return out


def target(appliance, logical: str):
    """{"page", "v"} of the FortiWeb page drawing ``logical``, or None."""
    if not logical:
        return None
    return page_map(appliance).get(logical)


def redirect_for(appliance, logical: str, args=None):
    """The FortiWeb page URL an old page of ``logical`` moves to, or None
    (not a FortiWeb, no measured page, or ``?classic=1``)."""
    from flask import url_for
    if args is not None and args.get("classic"):
        return None
    t = target(appliance, logical)
    if t is None:
        return None
    return url_for("workspace.fwgui_list", appliance_id=appliance.id, page=t["page"],
                   v=t["v"] or None)




def classic_leaf(endpoint: str) -> dict | None:
    """The old SATOM menu leaf of a FortiWeb page's collection, for the SATOM
    tools a FortiWeb page carries over from it: ``{"area": "server_objects" |
    "section", "section": <config section key> | "", "logical", "label",
    "collection", "read_only"}``, or None. The same menus, in the same order,
    the old pages read, so a template saved from a FortiWeb page is filed
    under the section whose library the old page lists."""
    from . import read_layer
    lns = set(read_layer.registry_logicals(endpoint or ""))
    if not lns:
        return None

    def leaf(area, section, it):
        return {"area": area, "section": section, "logical": it.logical, "label": it.label,
                "collection": it.collection, "read_only": bool(it.read_only)}
    try:
        from . import server_objects as so
        for g in so.server_objects_menu(hidden=frozenset()):
            for it in g.items:
                for t in it.tabs:
                    if t.logical in lns:
                        return leaf("server_objects", "", t)
    except Exception:  # noqa: BLE001 -- a missing menu only loses the tools
        pass
    try:
        from . import config_catalog as cc, config_sections as cs
        for s in cc.CONFIG_SECTIONS:
            if not cs.has_menu(s.key):
                continue
            for g in cs.section_menu(s.key, complete=False, hidden=frozenset()):
                for it in g.items:
                    if it.logical in lns:
                        return leaf("section", s.key, it)
    except Exception:  # noqa: BLE001
        pass
    return None


__all__ = ["page_map", "target", "classic_leaf", "redirect_for", "item_keys",
           "product_covered", "redirect_item"]
