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
    for e in ents:
        if e["special"]:
            continue
        tpl, _m = gui_pages.template(e["page"], fw, product)
        if tpl is None:
            continue
        for i, v in enumerate(gui_pages.views(tpl)):
            ep = v.get("endpoint") or ""
            if product == gui_pages.PRODUCT:
                names = read_layer.registry_logicals(ep)
            elif gui_products.read_only_endpoint(ep) and not gui_products.is_monitor(ep):
                names = []
            elif product == gui_products.FORTIAUTH:
                lg, _path = fac.resolve(appliance, ep)
                names = [n for n in (lg, gui_products.lib_key(product, ep)) if n]
            else:
                names = [ep]
            for ln in names:
                out.setdefault(ln, {"page": e["page"], "v": i})
    _map_cache[key] = (time.monotonic(), out)
    return out


def item_keys(item) -> list:
    """The collections an old FortiGate / FortiAuthenticator / FortiADC menu
    leaf reads: ``fgt_menu`` tabs are (cmdb path, label), ``fac_menu`` logicals
    are (registry logical, label), ``adc_menu`` tabs carry ``.logical`` (the
    REST entity name)."""
    pairs = getattr(item, "tabs", None) or getattr(item, "logicals", None) or ()
    return [p[0] if isinstance(p, (tuple, list)) else getattr(p, "logical", p) for p in pairs]


def product_covered(item, pmap: dict) -> bool:
    keys = item_keys(item)
    return bool(keys) and all(k in pmap for k in keys)




def redirect_item(appliance, item, tab=None, args=None):
    """The GUI page URL an old FortiGate / FortiAuthenticator / FortiADC leaf moves to
    (the requested tab's page, else the first), or None: ``?classic=1``, no
    device, or a leaf with a tab no measured page draws."""
    from flask import url_for
    if appliance is None or item is None or (args is not None and args.get("classic")):
        return None
    pmap = page_map(appliance)
    if not product_covered(item, pmap):
        return None
    keys = item_keys(item)
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
