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

import re
import time

from . import firmware_versions as fv
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


# --------------------------------------------------------------------------- #
# Page state: does this build have the page, and which layout draws it
# --------------------------------------------------------------------------- #
#: How close a layout is to the device's build, nearest first.
CLOSENESS_RANK = {"build": 0, "version": 1, "train": 2, "older": 3, "newer": 3, "unknown": 4}
#: Badge of the layout-origin line, from the existing ``.fw-badge-*`` set.
CLOSENESS_BADGE = {"build": "success", "version": "info", "train": "info",
                   "older": "warning", "newer": "warning", "unknown": "warning"}


def closeness_phrase(closeness) -> str:
    """The words every surface uses for how close a layout is."""
    from flask_babel import gettext as _
    return {"build": _("same build"),
            "version": _("same version, other build"),
            "train": _("same train"),
            "older": _("layout from an older train"),
            "newer": _("layout from a newer train"),
            "unknown": _("firmware not known")}.get(closeness) or ""


def _closeness_consequence(closeness, label: str, dv: str) -> str:
    from flask_babel import gettext as _
    if closeness in ("version", "train"):
        return _('No layout was measured on %(p)s %(dv)s itself; this one is the closest build of the '
                 'same train. Fields this device has and the layout does not place are listed under '
                 '"Not in GUI, but in CLI".', p=label, dv=dv or "?")
    if closeness == "older":
        return _('This layout comes from an older train than the device. Newer firmware adds or renames '
                 'fields in this GUI; those are not drawn from this layout (the ones the device has '
                 'are listed under "Not in GUI, but in CLI").')
    if closeness == "newer":
        return _('This layout comes from a newer train than the device. Some fields shown may not exist '
                 'on this firmware.')
    if closeness == "unknown":
        return _('The firmware of this device is not known yet, so the newest layout is shown. '
                 'Run a firmware check.')
    return ""


def layout_origin(label: str, layout_version, layout_build, firmware, closeness,
                  fw_read: bool = True) -> dict:
    """The ONE statement of where a layout comes from, for every surface (page
    banner, dialogs, "Not in GUI, but in CLI", exception forms): both builds
    named, builds zero padded as the devices report them, and how close the
    layout is. ``text`` is the sentence; ``badge`` the ``.fw-badge-*`` suffix."""
    from flask_babel import gettext as _
    dv = fv.normalize(firmware)
    db = gui_store.pad_build(gui_store.build_of(firmware))
    lb = gui_store.pad_build(layout_build)
    phrase = closeness_phrase(closeness)
    layout = ("%s build%s" % (layout_version, lb)) if lb else str(layout_version or "?")
    if dv:
        device = ("%s build%s" % (dv, db)) if db else _("%(v)s (build not read)", v=dv)
    else:
        device = _("firmware not known")
    head = _("Layout measured on %(p)s %(layout)s · this device runs %(device)s",
             p=label, layout=layout, device=device)
    return {"text": "%s · %s" % (head, phrase), "head": head, "phrase": phrase, "badge": CLOSENESS_BADGE.get(closeness, "warning"),
            "closeness": closeness, "label": label, "badge_label": phrase,
            "layout": {"version": layout_version, "build": lb},
            "device": {"version": dv, "build": db},
            "consequence": _closeness_consequence(closeness, label, dv), "fw_read": bool(fw_read)}


def origin_of(appliance, tpl: dict, label: str = "FortiWeb") -> dict:
    """:func:`layout_origin` of a resolved template (``select`` / ``template``)
    for a device."""
    o = tpl.get("origin") or {}
    based = tpl.get("based_on") or {}
    out = layout_origin(label, o.get("version") or based.get("version") or tpl.get("applies_to"),
                        o.get("build") or based.get("build"), gui_store.firmware_of(appliance),
                        tpl.get("closeness") or "unknown",
                        fw_read=bool(getattr(appliance, "firmware", None)))
    if (tpl.get("page_notice") or {}).get("kind") == "absent":
        # the page's object is not on this build: how close the layout is says
        # nothing the one statement below the line does not say better
        out = absent_origin(out)
    return out


def absent_origin(o: dict) -> dict:
    """A layout origin of a page the build does not have: the sentence keeps both
    builds; the badge says "not on this build", not "layout from an older train"."""
    from flask_babel import gettext as _
    phrase = _("not on this build")
    o = dict(o, phrase=phrase, badge="secondary", closeness="absent", badge_label=phrase,
             consequence="")
    o["text"] = "%s · %s" % (o.get("head", ""), phrase)
    return o


def _page_endpoints(tpl: dict) -> list:
    """The library endpoints a page lists or edits itself (its tabs and
    dialogs; not the sub-tables inside a dialog): a ``gui:`` / ``api:`` source
    is no REST collection."""
    eps = {v.get("endpoint") for v in views(tpl) if isinstance(v, dict)}
    eps |= {d.get("endpoint") for d in (tpl.get("dialogs") or {}).values() if isinstance(d, dict)}
    return sorted(e for e in eps if e and not str(e).startswith(("api:", "gui:")))


def _presence(product: str, endpoints, version: str) -> str:
    """``yes`` / ``no`` / ``unknown``: does the build serve the page's
    object(s)? The API library's own answer for that build (the evidence the
    save gate and the build-compat views read): ``no`` only when the build was
    measured and the object is absent from it."""
    if not endpoints or not version:
        return "unknown"
    from . import build_compat as bc
    view = bc.build_view(product, version)
    if not view.get("known"):
        return "unknown"
    seen = []
    for ep in endpoints:
        e = view["endpoints"].get(bc.key_for(product, ep, view))
        if e is None:
            seen.append("no" if view.get("tree_measured") and view.get("path_rule") == "verified"
                        else "unknown")
        else:
            seen.append(e["present"])
    if "yes" in seen:
        return "yes"
    return "no" if seen and all(x == "no" for x in seen) else "unknown"


def _span(product: str, endpoints) -> dict:
    """The measured versions of the library that serve the page's object(s):
    ``{"since": lowest, "until": highest}`` (either may be missing)."""
    from . import api_library as lib
    vs = []
    for b in lib.builds(product):
        v = b.get("version") or ""
        if b.get("line_only") or not b.get("measured") or b.get("vendor_only") \
                or len(v.split(".")) < 3:
            continue
        try:
            if _presence(product, endpoints, v) == "yes":
                vs.append(v)
        except Exception:  # noqa: BLE001 -- a span never sinks a page
            continue
    vs.sort(key=gui_store._vkey)
    return {"since": vs[0], "until": vs[-1]} if vs else {}


def page_state(product: str, page: str, firmware, tpl: dict | None = None,
               closeness=None) -> dict:
    """What the page is on this device's build, in one place (menu, route,
    banner and the build-diff note all read it, so they cannot disagree):

    ``{"present": yes|no|unknown, "closeness": build|version|train|older|newer|
    unknown|None, "layout": {version, build} | None, "since"/"until": versions
    the library measured the object on (only when ``present`` is ``no``),
    "checked": bool (the library was asked), "evidence": layout|library|none}``.

    ``present`` is the API library's answer for the device's exact build. A
    layout MEASURED on this build or version is evidence of its own: the
    device's GUI drew the page. ``no`` is only ever a measurement."""
    none = {"present": "unknown", "closeness": None, "layout": None, "checked": False,
            "evidence": "none"}
    if tpl is None:
        tpl, _m = template(page, firmware, product)
        if tpl is None:
            return none
    closeness = closeness or tpl.get("closeness")
    o = tpl.get("origin") or {}
    st = {"present": "unknown", "closeness": closeness,
          "layout": {"version": o.get("version"), "build": gui_store.pad_build(o.get("build"))},
          "checked": False, "evidence": "none"}
    if closeness in ("build", "version"):
        st.update(present="yes", evidence="layout")
        return st
    if product != PRODUCT:
        return st           # the other products' libraries do not gate their pages
    ver = fv.normalize(firmware)
    eps = _page_endpoints(tpl)
    if not ver or not eps:
        return st
    try:
        st["checked"] = True
        st["present"] = _presence(product, eps, ver)
        st["evidence"] = "library"
    except Exception:  # noqa: BLE001 -- the library never hides a page by failing
        st.update(present="unknown", checked=False, evidence="none")
        return st
    if st["present"] == "no":
        try:
            st.update(_span(product, eps))
        except Exception:  # noqa: BLE001 -- the span only words the notice
            pass
    return st


def state_notice(state: dict, label: str, firmware) -> dict | None:
    """The sentence a page says about its own presence (None when the build
    has it): ``{"kind": "absent"|"unknown", "text"}``."""
    from flask_babel import gettext as _
    dv = fv.normalize(firmware) or "?"
    if state.get("present") == "no":
        since, until = state.get("since"), state.get("until")
        if since and gui_store._vkey(since) > gui_store._vkey(dv):
            tail = _("The page exists from %(v)s on.", v=since)
        elif until:
            tail = _("The page was removed after %(v)s.", v=until)
        else:
            tail = ""
        return {"kind": "absent", "text": (_("%(p)s %(dv)s does not have this object (measured).",
                                             p=label, dv=dv) + " " + tail).strip()}
    if state.get("present") == "unknown" and state.get("checked"):
        return {"kind": "unknown",
                "text": _("Not measured on this build yet: SATOM has no evidence that %(p)s %(dv)s "
                          "serves this object, so the page is drawn from the layout above and may "
                          "not apply to this device.", p=label, dv=dv)}
    return None


def _rank(state: dict) -> int:
    return CLOSENESS_RANK.get(state.get("closeness"), 5)


_twin_cache: dict = {}


def _twin_groups(product: str) -> list:
    """Sets of pages that are the SAME object under two names across builds
    (Let's Encrypt -> ACME, Mobile API, OCSP): they list a collection in
    common and no version has a layout of both. Derived from the
    templates' endpoints, never from a list of names. 60 s cache."""
    try:
        ck = str(gui_store.root()) + "|" + product
    except RuntimeError:
        return []
    hit = _twin_cache.get(ck)
    if hit and time.monotonic() - hit[0] < 60:
        return hit[1]
    info = {}
    for page in page_ids(product):
        mains, vers = set(), set()
        for c in gui_store.candidates(product, page):
            vers.add(c["version"])
            try:
                t = gui_store.view_template(c)
            except (OSError, ValueError):
                continue
            mains |= {v.get("endpoint") for v in views(t) if isinstance(v, dict)
                      and v.get("endpoint") and not str(v["endpoint"]).startswith(("api:", "gui:"))}
        if mains:
            info[page] = (mains, vers)
    parent = {p: p for p in info}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    names = sorted(info)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if info[a][0] & info[b][0] and not (info[a][1] & info[b][1]):
                parent[find(a)] = find(b)
    groups: dict = {}
    for p in names:
        groups.setdefault(find(p), set()).add(p)
    out = [g for g in groups.values() if len(g) > 1]
    _twin_cache[ck] = (time.monotonic(), out)
    return out


def _twin_pick(states: dict, group) -> str | None:
    """The member a device's menu shows: the one whose layout is measured
    closest to its build (members the build does not have never win); a tie
    goes to the newer layout, then the name."""
    live = [p for p in sorted(group) if p in states and states[p]["present"] != "no"]
    if not live:
        return None
    return min(live, key=lambda p: (_rank(states[p]),
                                    tuple(-x for x in gui_store._vkey(
                                        (states[p].get("layout") or {}).get("version") or "")),
                                    p))


def renamed_to(product: str, page: str, firmware, state: dict) -> str | None:
    """For a page that is one name of an object this build shows under
    another name: that other page (else None)."""
    for g in _twin_groups(product):
        if page not in g:
            continue
        states = {page: state}
        for p in g - {page}:
            tpl, _m = template(p, firmware, product)
            if tpl is not None:
                states[p] = page_state(product, p, firmware, tpl=tpl)
        pick = _twin_pick(states, g)
        return pick if pick and pick != page else None
    return None


def entries(firmware, product: str = PRODUCT) -> list:
    """[{page, path, order, endpoint, special}] of every page with a layout,
    in the product's own menu order (FortiWeb, FortiGate, FortiAuthenticator,
    FortiADC: ``gui_products``).

    A FortiWeb page the device's build does not have (:func:`page_state`
    ``present == "no"``, measured) is left out, and so is the other name of an
    object the build shows under a newer or older one (Let's Encrypt / ACME:
    the page whose layout is measured closest to the build stays)."""
    out = []
    special = SPECIAL if product == PRODUCT else {}
    got = [(page,) + tuple(template(page, firmware, product)) for page in page_ids(product)]
    states = {}
    for page, tpl, m in got:
        if tpl is None:
            continue
        if product == PRODUCT and page not in special:
            states[page] = page_state(product, page, firmware, tpl=tpl)
            if states[page]["present"] == "no":
                continue
        out.append({"page": page, "path": list(tpl.get("menu_path") or [page]),
                    "order": tpl.get("menu_order"), "endpoint": tpl.get("endpoint") or "",
                    "special": special.get(page),
                    # what each tab of the page is (Settings -> ADOM Menus)
                    "kinds": page_kinds(product, tpl)})
    if product == PRODUCT:
        drop: set = set()
        for g in _twin_groups(product):
            here = {p for p in g if p in states}
            if len(here) > 1:
                drop |= here - {_twin_pick(states, here)}
        out = [e for e in out if e["page"] not in drop]
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


#: SATOM's own flow for what the device does on a device-managed page: page
#: -> (endpoint, label). Firmware upload and boot-alternate are the device's;
#: the staged firmware upgrade is SATOM's Upgrade Flow.
DEVICE_FLOWS = {"maintenance": ("upgrade_flow.index", "Upgrade Flow")}


def view_stub(view: dict) -> dict | None:
    """A tab the device draws from live data (``monitor``) or manages through
    its own GUI calls (``device_managed``) and that has no collection to read:
    there is nothing to list, so the page draws one sentence and no grid.
    ``{"kind", "gui_href"}``; None for every other tab."""
    if not isinstance(view, dict) or view.get("endpoint") or view.get("form"):
        return None
    kind = "monitor" if view.get("monitor") else ("device_managed" if view.get("device_managed") else "")
    if not kind:
        return None
    return {"kind": kind, "gui_href": view.get("gui_href") or ""}


def form_editable(coll: str, obj, *, writer: bool, absent: bool = False) -> bool:
    """May a settings form offer Save? Only when the user may write, the page
    exists on this build, the object was READ (a non-empty object: a blind body
    is never sent) and SATOM can write it: a cmdb collection its object editor
    knows, or a GUI API endpoint ``gui_bound.safe_api`` allows."""
    from . import gui_bound, objform
    if not writer or absent or not coll or not isinstance(obj, dict) or not obj:
        return False
    if gui_bound.is_api(coll):
        return gui_bound.safe_api(coll)
    return objform.is_known_collection(coll)


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


#: A Create New item label that names no dialog ("Create New" opens every one).
_GENERIC_LABELS = frozenset({"create new", "create", "new", "add", "add new"})


def dialog_action(tpl: dict | None, dialog: str) -> dict | None:
    """What a dialog the layout marks as an ACTION the device performs is
    (``action: import``): ``{"kind", "label"}``; None for an ordinary dialog.
    SATOM draws such a dialog as what it is, never as a Create form."""
    d = ((tpl or {}).get("dialogs") or {}).get(dialog) or {}
    kind = str(d.get("action") or "").strip().lower()
    if not kind:
        return None
    return {"kind": kind, "label": str(d.get("action_label") or "").strip() or kind.title()}


def humanise_id(dialog: str) -> str:
    """A template id as words (``fwb_wvs_integration_import`` -> Wvs Integration
    Import): the last resort of :func:`dialog_title`."""
    s = str(dialog or "").strip()
    for pre in ("fwb_", "dialog_"):
        if s.startswith(pre) and len(s) > len(pre):
            s = s[len(pre):]
    if s.endswith("_dialog") and len(s) > len("_dialog"):
        s = s[:-len("_dialog")]
    return re.sub(r"[_\-]+", " ", s).strip().title() or str(dialog or "")


_ACRONYMS = frozenset({"url", "uri", "ip", "dns", "ssl", "tls", "api", "ca", "crl", "ocsp", "http",
                       "https", "waf", "id", "ldap", "radius", "sso", "snmp", "ntp", "smtp"})


def _words(name: str) -> str:
    """A REST sub-table name as words (``url-list`` -> URL List)."""
    return " ".join(w.upper() if w.lower() in _ACRONYMS else w.capitalize()
                    for w in re.split(r"[_\-\s]+", str(name or "").strip()) if w)


def row_dialog_title(tpl: dict | None, dialog: str, kind: str = "edit") -> str:
    """The name of a sub-table ROW dialog from what the template knows about who
    opens it: ``<table label> row``, prefixed by the parent dialog's title where
    the parent has one (``URL Encryption Rule › Exceptions row``). The table's
    label is the field's own, else its sub-table name as words. '' when no table
    field of any dialog opens it."""
    from flask_babel import gettext as _
    dialogs = (tpl or {}).get("dialogs") or {}
    for pk, pd in dialogs.items():
        if pk == dialog or not isinstance(pd, dict):
            continue
        for blk in pd.get("blocks") or []:
            for f in (blk or {}).get("fields") or []:
                if not isinstance(f, dict) or f.get("row_dialog") != dialog:
                    continue
                table = str(f.get("label") or "").strip() or _words(f.get("subtable"))
                if not table:
                    continue
                parent = dialog_title(tpl, pk, kind, fallback=False)
                parent = re.sub(r"^(?:Edit|New)\s+", "", parent).strip()
                if parent and parent.lower() != table.lower():
                    return _("%(parent)s › %(table)s row", parent=parent, table=table)
                return _("%(table)s row", table=table)
    return ""


def dialog_title(tpl: dict | None, dialog: str, kind: str = "new", *, fallback: bool = True,
                 page_fallback: bool = True) -> str:
    """The title of a dialog on every surface (dialog header, build diff,
    breadcrumbs). In order: the title the template gives it (``{"edit", "new"}``
    or a plain string; ``kind`` picks which first); the label of the Create New
    item / action / tab that opens it; the page's menu label + "(new)" /
    "(edit)"; a humanised id. ``fallback=False`` stops after the template's own
    title and returns '' when it has none."""
    from flask_babel import gettext as _
    d = ((tpl or {}).get("dialogs") or {}).get(dialog) or {}
    t = d.get("title")
    if isinstance(t, dict):
        order = ("new", "edit") if kind == "new" else ("edit", "new")
        t = next((t.get(k) for k in order if isinstance(t.get(k), str) and t.get(k).strip()), None)
    t = str(t).strip() if isinstance(t, str) else ""
    if t or not fallback:
        return t
    act = dialog_action(tpl, dialog)
    if act and d.get("action_label"):
        return act["label"]
    vs = [v for v in views(tpl or {}) if isinstance(v, dict)]
    for v in vs:
        for it in v.get("create_menu") or []:
            lab = str((it or {}).get("label") or "").strip() if isinstance(it, dict) else ""
            if isinstance(it, dict) and it.get("dialog") == dialog and lab \
                    and lab.lower() not in _GENERIC_LABELS:
                return lab
    for v in vs:
        opens = {x.get("dialog") for x in v.get("dialogs") or [] if isinstance(x, dict)}
        if v.get("form"):
            opens.add(v["form"])
        if dialog in opens and str(v.get("label") or "").strip():
            return str(v["label"]).strip()
    row = row_dialog_title(tpl, dialog, kind)
    if row:
        return row
    path = (tpl or {}).get("menu_path") or []
    if page_fallback and path and str(path[-1]).strip():
        return "%s (%s)" % (str(path[-1]).strip(), _("new") if kind == "new" else _("edit"))
    return humanise_id(dialog)


def tab_label(tpl: dict, view: dict, i: int) -> str:
    """A tab's title: its own label, else the title of the dialog it opens (a
    tab the crawl drew no caption for: FortiClient EMS Settings), else the last
    word of its collection made readable (``service.custom`` -> Custom,
    ``endpoint-control/fctems`` -> Fctems)."""
    if view.get("label"):
        return view["label"]
    dialogs = {d.get("dialog") for d in view.get("dialogs") or [] if isinstance(d, dict)}
    if view.get("form"):
        dialogs.add(view["form"])
    dialogs.discard(None)
    if len(dialogs) == 1:
        t = dialog_title(tpl, next(iter(dialogs)), fallback=False)
        # a row dialog's title ("X row") names the row, not the tab
        if t and not t.endswith(" row") and "/" not in t:
            return t
    path = tpl.get("menu_path") or []
    if i == 0 and path and str(path[-1]).strip():
        # the first tab of a page is the page: its menu label, not the last
        # word of its collection (waf/api-learning-rule -> "Api Learning Rule")
        return str(path[-1]).strip()
    ep = view.get("endpoint") or ""
    tail = ep.rsplit("/", 1)[-1]
    tail = tail.split(".", 1)[1] if "." in tail else tail
    return tail.replace("-", " ").replace("_", " ").title() or str(i + 1)


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
        # A GUI-only column (FortiAuthenticator pages with no API): the sweep
        # keeps the text the device's own change list shows (``_list``) and
        # the form value; anything else stays empty rather than guessed.
        name = col.get("gui_name")
        if col.get("key_from") != "gui-only" or not name:
            return ""
        shown = (row.get("_list") or {}).get(name)
        if shown not in (None, ""):
            return shown
        v = row.get(name)
        lab = (row.get("_labels") or {}).get(name)
        if lab not in (None, "") and not isinstance(v, bool):
            return lab
        if isinstance(v, bool):
            return "Yes" if v else "No"
        if isinstance(v, list):
            return ", ".join(str(x) for x in v)
        return "" if v is None else v
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


def unbound_columns(view: dict, rows) -> set:
    """Ids of the columns that are bound to nothing: the layout names a column
    id the rows of this list never carry (the template columns of FortiWeb
    8.0.8 Network > Interface say ``ipv4Netmask`` / ``ipv4Access`` / ``col4``
    where the rows have ``ip`` / ``allowaccess`` / ``status``). Drawn as cells
    they read as "no IP address"; the page marks the HEADER instead. Judged
    only when there are rows (an empty list proves nothing), and never for a
    column the sweep kept a GUI text for. A column the crawl tied to no REST key
    (``unmatched``) is unbound too: its cell is blank whatever the row holds."""
    rows = [r for r in rows or [] if isinstance(r, dict)]
    if not rows:
        return set()
    have = set()
    for r in rows:
        have.update(r)
    out = set()
    for c in view.get("columns") or []:
        if c.get("unmatched"):
            # tied to no REST key: blank unless it is a GUI-only column whose
            # text the sweep kept (``cell`` draws that one)
            if c.get("key_from") == "gui-only" and c.get("gui_name"):
                continue
            out.add(c.get("id"))
        elif c.get("id") and c["id"] not in have:
            out.add(c["id"])
    return out


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


_coll_pages: dict = {}


def page_for_collection(collection: str, firmware, product: str = PRODUCT):
    """(page, view index) of the GUI page that lists ``collection`` for this
    firmware, or None. What the "Edit entry" pencil opens: the object in the
    dialog the device draws for it, not the generic object editor. The
    "Not in GUI" catalogue pages and the bespoke pages (SPECIAL) are never
    the answer."""
    try:
        ck = (str(gui_store.root()), product, str(firmware or ""))
    except RuntimeError:
        return None
    hit = _coll_pages.get(ck)
    m = hit[1] if hit and time.monotonic() - hit[0] < 300 else None
    if m is None:
        m = {}
        special = SPECIAL if product == PRODUCT else {}
        # only the pages this build has (not an absent object's page, not the
        # older name of a renamed one): a "+ Create" must open a page the menu shows
        shown = {e["page"] for e in entries(firmware, product)} if product == PRODUCT else None
        for page in page_ids(product):
            if page.startswith("not-in-gui") or page in special:
                continue
            if shown is not None and page not in shown:
                continue
            tpl, _match = template(page, firmware, product)
            if tpl is None:
                continue
            for i, v in enumerate(views(tpl)):
                ep = v.get("endpoint") or ""
                if ep and ep not in m and dialog_for(v, None) in (tpl.get("dialogs") or {}):
                    m[ep] = (page, i)
        _coll_pages[ck] = (time.monotonic(), m)
    return m.get(collection)


def adom_scope(appliance) -> dict | None:
    """What an ADOM-enabled FortiWeb row shows: when the device reports ADOMs
    enabled (``system/global`` ``adom-admin = enable``, from the SATOM cache)
    and the row is bound to the root ADOM (empty ``vdom``), its lists and its
    capacity count the root ADOM only -- the other ADOMs are rows of their own
    (one row per ADOM, same host, ADOM (vdom) = the ADOM's name; the name
    ``<device>@<adom>`` is the operators' convention). ``{"text", "others"}`` or
    None. Never reads the device."""
    from flask_babel import gettext as _
    if getattr(appliance, "kind", "") != "fortiweb":
        return None
    from ..models import DEVICE_SCOPE_ADOMS, chassis_siblings
    if (getattr(appliance, "vdom", "") or "").strip().lower() not in DEVICE_SCOPE_ADOMS:
        return None
    try:
        got, _meta = rows(appliance.id, "system/global")
    except Exception:  # noqa: BLE001 -- an unreadable cache says nothing about ADOMs
        return None
    if not got or str(got[0].get("adom-admin") or "").lower() != "enable":
        return None
    others = [{"id": r.id, "name": r.name, "vdom": r.vdom or ""}
              for r in chassis_siblings(appliance, include_self=False)]
    text = _("ADOMs are enabled on this device: this row shows the root ADOM only. The objects of the "
             "other ADOMs belong to rows of their own: register this device again with ADOM (vdom) "
             "set to the ADOM's name (Appliances > Add, named <device>@<adom>).")
    if others:
        text += " " + _("Registered ADOMs of this device: %(names)s.",
                        names=", ".join("%s (%s)" % (o["name"], o["vdom"] or "root") for o in others))
    return {"text": text, "others": others}


def table_endpoint(tpl: dict, dialog: str, subtable: str) -> str:
    for b in tpl["dialogs"][dialog]["blocks"]:
        for f in b["fields"]:
            if f.get("kind") == "table" and f.get("subtable") == subtable:
                return f.get("endpoint") or ""
    return ""


__all__ = ["PRODUCT", "SPECIAL", "page_ids", "template", "entries", "page_state", "state_notice",
           "renamed_to", "adom_scope", "layout_origin", "origin_of", "closeness_phrase", "tree", "nav_for",
           "contains", "views", "view_of", "dialog_title", "row_dialog_title", "dialog_action", "humanise_id", "view_stub", "form_editable", "absent_origin", "DEVICE_FLOWS", "unbound_columns", "tab_label", "rows", "live_rows", "cell", "value_labels", "dialog_for",
           "view_for_dialog", "table_endpoint"]
