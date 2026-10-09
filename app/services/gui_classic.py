"""Which of SATOM's own FortiWeb pages a measured FortiWeb GUI page replaces.

SATOM drew FortiWeb objects in its own pages before the GUI crawl existed:
Server Objects (``server_objects.overview?type=``), Web Protection
(``web_protection.menu_page``) and the configuration / WAF sections
(``section_config.section?type=``). The FortiWeb menu (``gui_pages``) now draws
the same collections with FortiWeb's own structure, so on a FortiWeb device:

* the sidebar drops every old entry whose collections ALL have a FortiWeb page
  for the device's firmware (:func:`filter_groups`, :func:`filter_sections`);
* an old URL for such a collection redirects to its FortiWeb page
  (:func:`redirect_for`) -- unless ``?classic=1``;
* each FortiWeb page links back to the old page (:func:`classic_url`), which
  keeps what only SATOM has there (Clone, the signature editor, config
  templates, artifacts, certificate import).

An entry with ``special`` set (the Signatures policy editor) is never replaced.
The coverage comes from the layouts of the device's firmware, so a build with
fewer measured pages keeps more of the old menu.
"""
from __future__ import annotations

import dataclasses
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
    for e in gui_pages.entries(fw, product):
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
    """The collections an old FortiGate / FortiAuthenticator menu leaf reads:
    ``fgt_menu`` tabs are (cmdb path, label), ``fac_menu`` logicals are
    (registry logical, label)."""
    pairs = getattr(item, "tabs", None) or getattr(item, "logicals", None) or ()
    return [p[0] if isinstance(p, (tuple, list)) else getattr(p, "logical", p) for p in pairs]


def product_covered(item, pmap: dict) -> bool:
    keys = item_keys(item)
    return bool(keys) and all(k in pmap for k in keys)


def filter_product_groups(groups, pmap: dict) -> list:
    """The FortiGate / FortiAuthenticator sidebar without the leaves whose
    every tab now has a measured GUI page (an emptied group drops)."""
    if not pmap:
        return list(groups or [])
    out = []
    for g in groups or []:
        keep = tuple(it for it in g.items if not product_covered(it, pmap))
        if keep:
            out.append(dataclasses.replace(g, items=keep) if len(keep) != len(g.items) else g)
    return out


def redirect_item(appliance, item, tab=None, args=None):
    """The GUI page URL an old FortiGate / FortiAuthenticator leaf moves to
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


def classic_item_url(appliance, endpoint: str):
    """The old FortiGate / FortiAuthenticator menu leaf (``?classic=1``) that
    lists the same collection, or None."""
    from flask import url_for
    from . import gui_products
    product = gui_products.product_of(appliance)
    try:
        if product == gui_products.FORTIGATE:
            from . import fgt_menu
            for g in fgt_menu.visible_menu():
                for it in g.items:
                    if endpoint in item_keys(it):
                        return url_for("fgt.menu_page", item_key=it.key, tab=endpoint, classic=1)
        elif product == gui_products.FORTIAUTH:
            from . import fac_menu
            lg, _p = gui_products.adapter(product).resolve(appliance, endpoint)
            for g in fac_menu.visible_menu():
                for it in g.items:
                    if lg and lg in item_keys(it):
                        return url_for("fac.menu_page", item_key=it.key, tab=lg, classic=1)
    except Exception:  # noqa: BLE001 -- a missing menu only loses the link
        return None
    return None


def _logicals(item) -> list:
    tabs = getattr(item, "tabs", None)
    if tabs:
        return [t.logical for t in tabs]
    lg = getattr(item, "logicals", None)
    if lg:
        return list(lg)
    return [item.logical]


def covered(item, pmap: dict) -> bool:
    """True when every collection of a menu entry has a FortiWeb page."""
    if getattr(item, "special", ""):
        return False
    lg = _logicals(item)
    return bool(lg) and all(ln in pmap for ln in lg)


def filter_groups(groups, pmap: dict) -> list:
    """A menu of groups -> items without the covered items; an emptied group
    drops. Groups / items are dataclasses (server_objects, wp_menu,
    config_sections)."""
    if not pmap:
        return list(groups or [])
    out = []
    for g in groups or []:
        keep = tuple(it for it in g.items if not covered(it, pmap))
        if keep:
            out.append(dataclasses.replace(g, items=keep) if len(keep) != len(g.items) else g)
    return out


def filter_sections(sections, pmap: dict) -> list:
    """The sidebar's section list ([{key, label, menu: groups}]) filtered the
    same way; a section left with no group drops."""
    if not pmap:
        return list(sections or [])
    out = []
    for s in sections or []:
        menu = filter_groups(s.get("menu") or [], pmap)
        if menu:
            out.append(dict(s, menu=menu))
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


def classic_url(appliance, endpoint: str):
    """The old SATOM page of a FortiWeb page's collection (``?classic=1``), or
    None when SATOM never had one."""
    from flask import url_for
    from . import read_layer
    lns = set(read_layer.registry_logicals(endpoint or ""))
    if not lns:
        return None
    if "webprotection_profile_inline" in lns:
        return url_for("web_protection.overview", id=appliance.id, classic=1)
    try:
        from . import server_objects as so
        for g in so.server_objects_menu(hidden=frozenset()):
            for it in g.items:
                hit = lns.intersection(_logicals(it))
                if hit:
                    return url_for("server_objects.overview", id=appliance.id,
                                   type=sorted(hit)[0], classic=1)
    except Exception:  # noqa: BLE001 -- a missing menu only loses the link
        pass
    try:
        from . import wp_menu
        for g in wp_menu.menu(frozenset()):
            for it in g.items:
                for t in it.tabs:
                    if t.logical in lns:
                        return url_for("web_protection.menu_page", id=appliance.id,
                                       item_key=it.key, tab=t.logical, classic=1)
    except Exception:  # noqa: BLE001
        pass
    try:
        from . import config_catalog as cc, config_sections as cs
        keys = [s.key for s in cc.CONFIG_SECTIONS if cs.has_menu(s.key)]
        for k in keys:
            for g in cs.section_menu(k, complete=False, hidden=frozenset()):
                for it in g.items:
                    if it.logical in lns:
                        return url_for("section_config.section", section_key=k,
                                       type=it.logical, classic=1)
    except Exception:  # noqa: BLE001
        pass
    return None


__all__ = ["page_map", "covered", "filter_groups", "filter_sections", "target",
           "redirect_for", "classic_url", "item_keys", "product_covered",
           "filter_product_groups", "redirect_item", "classic_item_url"]
