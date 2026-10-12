"""The "Not in GUI, but in CLI" section — one rule for every object of every product.

Permanent rule (user, 2026-10-08): SATOM shows EVERY field a device has on its
exact build. A field the Fortinet GUI does not show is not dropped and not
merged into another section: it goes to a section titled
:data:`SECTION_TITLE`, and each field there says how SATOM writes it:

* ``REST`` — the device's REST API serves it (FortiWeb: everything the GUI
  hides is still in REST), so a normal Save writes it;
* ``CLI``  — the API library measured it ``cli_only`` or ``hidden`` on this
  build, so the Save routes it through ``cli_writer`` over SSH (the split the
  editors already do);
* ``unverified`` — no source measured the field on this build (channel
  ``unknown``); it is shown and marked, never hidden.

Two kinds of evidence decide what is "not in the GUI":

1. the **API library** (:func:`api_library.channels_at` of the device's exact
   build) — a field the CLI has and REST does not is never in the GUI;
2. the **GUI layout** of the page, when the harvester measured it for the
   object (FortiWeb Server Policy today) — a REST field the layout does not
   place is not in the GUI either. Without a measured layout SATOM cannot tell
   a GUI field from a REST-only one, so those stay in their usual groups and
   the section says the layout was not measured.

A whole object can be outside the GUI too: the knowledge pack ships a page
marked ``gui_absent`` for the objects no page of the device's GUI reads
(FortiADC 7.6.7: VDOM, per-VDOM syslog, alert targets…, measured by the
crawl), and on FortiADC the registry names what the build serves that no
measured page reads at all. :func:`absent_objects` lists both for the
per-device page; their rows are read on demand (:func:`absent_rows`).

Nothing here touches a device: the section is built from the library and the
layout; values of CLI fields are read on demand by :func:`cli_values`.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

SECTION_TITLE = "Not in GUI, but in CLI"
CH_REST, CH_CLI, CH_UNVERIFIED = "REST", "CLI", "unverified"

_LIB_CLI = frozenset({"cli_only", "hidden"})
_LIB_REST = frozenset({"both", "rest_only"})

#: GUI page per (product, endpoint) whose layout is measured. The layout comes
#: from :mod:`gui_template` (the device's build first, see its resolver).
LAYOUT_PAGES = {("fortiweb", "server-policy/policy"): "server-policy"}

_pages_cache: dict = {}


def layout_pages() -> dict:
    """``{(product, endpoint key): page}`` of every page whose layout is
    measured: Server Policy (:data:`LAYOUT_PAGES`) plus every generic page the
    knowledge feed brought (``gui crawl``), each by the collections its grids
    and dialogs edit. Cached 60 s (read on every object view)."""
    import time
    out = dict(LAYOUT_PAGES)
    try:
        from . import gui_pages, gui_store
        root = str(gui_store.root())
    except Exception:  # noqa: BLE001 — no app context / data dir: Server Policy only
        return out
    hit = _pages_cache.get(root)
    if hit and time.monotonic() - hit[0] < 60:
        return {**hit[1], **out}
    gen: dict = {}
    from . import gui_products
    for product in gui_products.PRODUCTS:
        for page in gui_pages.page_ids(product):
            if product == "fortiweb" and page in gui_pages.SPECIAL:
                continue
            tpl, _m = gui_pages.template(page, None, product)
            if not tpl:
                continue
            eps = [tpl.get("endpoint")] + [v.get("endpoint") for v in gui_pages.views(tpl)]
            for ep in eps:
                # a GUI-only page (``gui:``) or a FortiGate monitor view edits
                # no REST object: it places no field of one
                if ep and not gui_products.read_only_endpoint(ep):
                    gen.setdefault((product, endpoint_key(gui_products.lib_key(product, ep))),
                                   page)
    _pages_cache[root] = (time.monotonic(), gen)
    return {**gen, **out}


#: Products whose GUI layout no lab device had measured when SATOM shipped: no
#: GUI/REST split is possible, every field is listed and the section says why
#: -- until the knowledge feed brings a layout for the product
#: (:func:`unmeasured`): FortiADC and FortiAnalyzer are measured once a
#: template exists for them (both are GUI products, ``gui_products.PRODUCTS``).
UNMEASURED_PRODUCTS = frozenset({"fortiadc", "fortianalyzer"})


def unmeasured(product: str | None) -> bool:
    """True while no GUI layout of ``product`` is on this node: one of
    :data:`UNMEASURED_PRODUCTS` with no imported template at all. A product
    with a layout resolves every build to its closest measured one (the
    menu's own rule), so the "not measured" message would be false."""
    if product not in UNMEASURED_PRODUCTS:
        return False
    return not any(p == product for p, _ep in layout_pages())


def endpoint_key(endpoint: str) -> str:
    """The library key of a REST path / URN / template endpoint
    (``cmdb/server-policy/policy`` -> ``server-policy/policy``)."""
    from . import api_library as lib
    key = lib.urn_key(endpoint) if "/" in (endpoint or "") else (endpoint or "")
    return key[5:] if key.startswith("cmdb/") else key


def _build_of(appliance) -> tuple[str, str]:
    from . import api_library as lib
    info = lib.resolve_appliance(appliance)
    return info.get("product") or "", info.get("version") or ""


def _channels(product: str, version: str, key: str) -> dict:
    """The library's view of ONE endpoint on one build (cached with the CLI
    writer's own cache, so a Save right after the render reads the same view)."""
    from . import cli_writer
    try:
        view = cli_writer._channels(product, version, key)
    except Exception:  # noqa: BLE001 — the library never sinks a render
        log.exception("not_in_gui: channels_at(%s, %s, %s) failed", product, version, key)
        return {}
    eps = view.get("endpoints") or {}
    # a registry logical name (FortiAuthenticator / FortiADC / FortiAnalyzer)
    # resolves to ONE library endpoint whose key is the REST path
    return eps.get(key) or (next(iter(eps.values())) if len(eps) == 1 else {})


def layout_keys(product: str, endpoint: str, version: str) -> tuple[set | None, dict]:
    """``(keys, info)``: the field keys the Fortinet GUI places for *endpoint*
    on *version*, or ``(None, info)`` when no layout was measured for it.

    Keys = every dialog field of the page's dialogs that edit the object
    itself, plus the REST fields a GUI-only control is derived from and the
    REST field an aliased control writes."""
    page = layout_pages().get((product, endpoint_key(endpoint)))
    if not page:
        return None, {}
    try:
        from . import gui_template
        tpl, match = gui_template.select(product, page, version)
    except Exception:  # noqa: BLE001
        log.exception("not_in_gui: layout of %s/%s", product, page)
        return None, {}
    if not tpl:
        return None, {}
    if product == "fortiweb":
        # the page as SATOM draws it: GUI API endpoints tied to their cmdb
        # collection, the per-field corrections applied (gui_alias) -- the
        # raw crawl names an endpoint SATOM does not edit
        from . import gui_alias
        tpl = gui_alias.apply(page, tpl)
    keys = set(_template_keys(tpl, endpoint_key(endpoint)))
    based = tpl.get("based_on") or {}
    # a ``gui_absent`` page is SATOM's, built from the device's schema: what
    # it places is what SATOM draws, and the device's GUI draws none of it
    return keys, {"page": page, "match": match, "gui_absent": bool(tpl.get("gui_absent")),
                  "based_on": based.get("version") or tpl.get("applies_to") or ""}


def _template_keys(tpl: dict, endpoint: str) -> set:
    """Field keys a template's dialogs place for *endpoint* (the page's object).

    A dialog names its endpoint when the extractor knew it; otherwise a dialog
    with operation-mode ``contexts`` edits the page's object and one without
    is a sub-table row dialog (content routing, public IP), which belongs to
    another endpoint."""
    from .gui_products import lib_key
    prod = str(tpl.get("product") or "fortiweb")
    _k = (lambda ep: endpoint_key(lib_key(prod, str(ep or ""))))  # noqa: E731
    own = _k(tpl.get("endpoint"))
    keys: set = set()
    if own == endpoint:
        # a list column (Status, Protocol) is shown and set from the GUI list
        keys.update(c["id"] for c in ((tpl.get("list") or {}).get("columns") or [])
                    if isinstance(c, dict) and c.get("id"))
    sub = set(tpl.get("subtable_dialogs") or ())
    for name, d in (tpl.get("dialogs") or {}).items():
        if "subtable_dialogs" in tpl:
            dep = _k(d.get("endpoint")) or ("" if name in sub else own)
        else:
            dep = _k(d.get("endpoint")) or (own if "contexts" in d else "")
        if dep != endpoint:
            continue
        for b in d.get("blocks") or []:
            for f in b.get("fields") or []:
                if f.get("key"):
                    keys.add(f["key"])
                # FortiAuthenticator: a control showing the negation of a key
                # (Disabled = not ``active``) places that key; the other
                # controls of one field (``more``) place theirs
                if f.get("inverse_of"):
                    keys.add(str(f["inverse_of"]))
                for m in f.get("more") or []:
                    if isinstance(m, dict) and m.get("key"):
                        keys.add(m["key"])
                # a toggle group (Supported SSL Protocols) sets one key per row
                for r in f.get("rows") or []:
                    if isinstance(r, dict) and r.get("key"):
                        keys.add(r["key"])
        for rules in (d.get("derived") or {}).values():
            for r in rules or []:
                if isinstance(r, dict) and r.get("field"):
                    keys.add(r["field"])
        keys.update(str(v) for v in (d.get("aliases") or {}).values())
    return keys


def classify(appliance, endpoint: str, obj_keys, *, product: str | None = None,
             version: str | None = None, noise=None) -> dict:
    """Which fields of one object go to the section, and by which channel.

    ``obj_keys`` are the keys the device returned for the object (REST read
    or cache). Returns::

        {"title", "product", "version", "endpoint", "layout_measured",
         "evidence" (the library measured this endpoint on this build),
         "layout": {...}, "fields": [{"key", "channel", "lib_channel",
         "in_object", "attrs"}], "moved": set(keys taken out of the groups),
         "note": str}

    ``fields`` is sorted by key; ``moved`` are REST keys of the object that a
    measured layout does not place (they leave their usual group)."""
    if product is None or version is None:
        product, version = _build_of(appliance)
    key = endpoint_key(endpoint)
    noise = noise or (lambda k: False)
    obj_keys = [k for k in (obj_keys or []) if not noise(k)]
    have = set(obj_keys)
    have_lower = {k.lower() for k in have}
    ep = _channels(product, version, key) if version else {}
    lib_fields = ep.get("fields") or {}
    layout, linfo = layout_keys(product, key, version) if version else (None, {})

    out: dict = {}
    moved: set = set()
    # 1. the library: CLI-only / hidden fields are never in the GUI.
    for name, spec in lib_fields.items():
        ch = spec.get("channel")
        if noise(name) or ch == "meta":
            continue
        if name not in have and name.lower() in have_lower:
            continue  # a documentation spelling of a field the device returned
        attrs = spec.get("attrs") or {}
        if ch in _LIB_CLI:
            out[name] = {"key": name, "channel": CH_CLI, "lib_channel": ch,
                         "in_object": name in have, "attrs": attrs}
        elif name in have:
            continue  # served by REST and returned: handled with the object keys
        elif ch in _LIB_REST:
            if layout is not None and name not in layout:
                out[name] = {"key": name, "channel": CH_REST, "lib_channel": ch,
                             "in_object": False, "attrs": attrs}
        elif ch == "unknown" and spec.get("cli") != "no" and not spec.get("doc_conflict"):
            if layout is None or name not in layout:
                out[name] = {"key": name, "channel": CH_UNVERIFIED, "lib_channel": ch,
                             "in_object": False, "attrs": attrs}
    # 2. the layout: a REST field the GUI does not place.
    if layout is not None:
        for name in obj_keys:
            if name in out or name in layout or name == "name":
                continue
            spec = lib_fields.get(name) or {}
            if spec.get("channel") == "meta":
                continue
            out[name] = {"key": name, "channel": CH_REST,
                         "lib_channel": spec.get("channel") or "unknown",
                         "in_object": True, "attrs": spec.get("attrs") or {}}
            moved.add(name)
    for name, f in out.items():
        if f["channel"] == CH_CLI and f["in_object"]:
            moved.add(name)

    if not version:
        note = ("The running build of this appliance is unknown, so SATOM cannot tell "
                "which fields it has outside the GUI. Run a firmware check.")
    elif layout is None and unmeasured(product):
        note = ("GUI layout not measured for this product (no lab device): fields the "
                "REST API returns stay in their groups; nothing is hidden.")
    elif layout is None:
        note = ("GUI layout not measured for this page on %s %s: this section lists the "
                "fields the device has outside its REST API." % (product, version))
    elif linfo.get("gui_absent"):
        from . import gui_products
        note = ("No page of the %s %s GUI reads this object (measured): SATOM draws it "
                "from the device's schema. The fields its page does not place are listed "
                "here with the channel SATOM writes them by."
                % (gui_products.label(product) or product, linfo.get("based_on") or "?"))
    else:
        from . import gui_products
        note = ("GUI layout of %s %s (%s): fields the Fortinet GUI does not show "
                "are listed here with the channel SATOM writes them by."
                % (gui_products.label(product) or "FortiWeb", linfo.get("based_on") or "?",
                   linfo.get("match") or "?"))
    if version and not ep:
        note += " The API library has no evidence for this endpoint on this build."
    return {"title": SECTION_TITLE, "product": product, "version": version,
            "endpoint": key, "layout_measured": layout is not None, "layout": linfo,
            "evidence": bool(ep),
            "fields": [out[k] for k in sorted(out)], "moved": moved, "note": note}


def apply_to_groups(appliance, endpoint: str, obj: dict, groups: list, *, describe,
                    noise=None, product: str | None = None,
                    version: str | None = None) -> tuple[list, dict]:
    """Take the section's fields out of *groups* and return ``(groups, section)``.

    ``describe(key, value)`` builds the editor's field descriptor (each product
    has its own). A field the object did not return has no value yet: it is
    rendered as a text input (never a toggle that would claim "disabled") and
    marked ``unread`` so the page can offer the CLI read."""
    obj = obj or {}
    cls = classify(appliance, endpoint, list(obj), product=product, version=version,
                   noise=noise)
    moved = cls["moved"]
    kept = []
    for g in groups or []:
        fields = [f for f in g.get("fields") or [] if f.get("key") not in moved]
        if fields:
            kept.append({**g, "fields": fields})
    fields = []
    for f in cls["fields"]:
        if f["in_object"]:
            d = dict(describe(f["key"], obj.get(f["key"])))
        else:
            d = dict(describe(f["key"], None))
            d.update(widget="text", value="", unread=True)
            d.pop("on", None)
        d.update(channel=f["channel"], lib_channel=f["lib_channel"],
                 cli_type=(f.get("attrs") or {}).get("type") or "",
                 cli_options=list((f.get("attrs") or {}).get("options") or []))
        d["group"] = SECTION_TITLE
        fields.append(d)
    section = {k: v for k, v in cls.items() if k != "moved"}
    section["fields"] = fields
    section["moved"] = sorted(moved)
    section["has_cli"] = any(f["channel"] == CH_CLI for f in fields)
    return kept, section


def _editor_info(sec: dict, rows) -> None:
    """Add what the section's CLI editor needs: the CLI object (path, kind,
    row-key field, parent), the row keys a table view returned, and whether
    SATOM has a CLI writer for the product at all."""
    from . import cli_writer
    ep = _channels(sec.get("product") or "", sec.get("version") or "",
                   sec.get("endpoint") or "") if sec.get("version") else {}
    attrs = ep.get("attrs") or {}
    obj = {"cli_path": attrs.get("cli_path") or "", "kind": attrs.get("kind") or "",
           "mkey": attrs.get("mkey") or "", "parent": attrs.get("parent") or ""}
    sec["object"] = obj
    keys: list = []
    if obj["kind"] != "singleton" and obj["mkey"]:
        for r in rows or []:
            if isinstance(r, dict) and r.get(obj["mkey"]) not in (None, ""):
                keys.append(str(r[obj["mkey"]]))
    sec["row_keys"] = sorted(set(keys))[:500]
    product = sec.get("product") or ""
    dialect = cli_writer.DIALECTS.get(product)
    sec["writable"] = bool(dialect) and bool(obj["cli_path"])
    sec["dialect_verified"] = (dialect or {}).get("verified") or ""
    if not dialect:
        sec["write_note"] = "SATOM has no CLI writer for %s." % (product or "this product")
    elif not obj["cli_path"]:
        sec["write_note"] = ("The API library does not name the CLI path of this object on "
                             "this build, so SATOM cannot write it by CLI.")
    else:
        sec["write_note"] = ""


def for_view(appliance, endpoint: str, data, *, noise=None) -> dict | None:
    """The section for a product view without its own editor (FortiGate,
    FortiAuthenticator, FortiADC, FortiAnalyzer tabs, the per-device page):
    *data* is what REST returned for the endpoint (a list of rows or one
    settings object; ``[]`` for an object only the CLI serves). Returns the
    section — with what its CLI editor needs, see :func:`_editor_info` — or
    None when it cannot be built (the view renders as before)."""
    if isinstance(data, dict):
        keys, rows = list(data), [data]
    else:
        rows = [r for r in (data or []) if isinstance(r, dict)]
        keys = sorted({k for r in rows for k in r})
    try:
        _, sec = apply_to_groups(appliance, endpoint, {k: None for k in keys}, [],
                                 describe=lambda k, v: {"key": k, "label": k, "value": ""},
                                 noise=noise)
        _editor_info(sec, rows)
    except Exception:  # noqa: BLE001 — never sinks a view
        log.exception("not_in_gui: section for %s", endpoint)
        return None
    return sec


def save(appliance, endpoint: str, mkey: str | None, fields: dict, *, parent_mkeys=(),
         apply: bool = False, writer=None) -> dict:
    """Write the CLI-only fields of ONE object from the section's editor.

    Only fields the library classifies ``cli_only``/``hidden`` on the
    appliance's exact build are accepted (``cli_writer.split_payload``, the
    same gate every editor uses). A REST field is refused with "edit it in the
    object's own form", a field no source measured is refused with the reason
    — and a write with ANY refused field sends nothing, so a half-applied
    change can never happen. ``apply=False`` returns the rendered script.

    ``{"ok", "dry_run", "cli": CliWriteResult dict | None, "refused", "error"}``."""
    from . import cli_writer
    fields = {str(k): ("" if v is None else v) for k, v in (fields or {}).items() if k}
    out = {"ok": False, "dry_run": not apply, "cli": None, "refused": {}, "error": ""}
    if not fields:
        out["error"] = "no changes to save"
        return out
    split = cli_writer.split_payload(appliance, endpoint, fields)
    refused = dict(split.get("refused") or {})
    for k in split.get("rest") or {}:
        refused[k] = ("served by the REST API on this build: edit it in the object's own "
                      "form, not by CLI")
    out["refused"] = refused
    if refused:
        out["error"] = "nothing was sent: " + "; ".join(
            "%s — %s" % (k, why) for k, why in sorted(refused.items()))
        return out
    try:
        plan = cli_writer.plan_for(appliance, split, mkey or None, parent_mkeys=parent_mkeys)
        w = writer or cli_writer.CliWriter(appliance)
        res = (w.apply(plan) if apply else w.render(plan)).as_dict()
    except cli_writer.CliWriteRefused as exc:
        out["error"] = str(exc)
        return out
    out["cli"] = res
    out["ok"] = bool(res.get("ok"))
    if not out["ok"]:
        err = res.get("error") or {}
        if err:
            out["error"] = "CLI: %s" % (err.get("line") or err.get("pattern") or "failed")
        elif res.get("diff"):
            out["error"] = "CLI: readback differs for %s" % ", ".join(
                str(d.get("field", "?")) for d in res["diff"])
        else:
            out["error"] = "CLI write failed"
    return out


def _cli_section(appliance, endpoint: str) -> dict | None:
    """The editable section of ONE object for the per-device page and for a
    menu page that hosts an object only the CLI serves: its CLI-only fields
    (no REST read behind it, so REST fields are not listed here)."""
    sec = for_view(appliance, endpoint, [])
    if sec is not None:
        sec["fields"] = [f for f in sec["fields"] if f["channel"] == CH_CLI]
        sec["has_cli"] = bool(sec["fields"])
    return sec


def cli_objects_for(appliance, endpoints) -> list:
    """Sections for the objects only the CLI serves that a menu page hosts
    (FortiAuthenticator Network: ``system/dns``, ``system/interface``…). An
    endpoint this build does not have as a CLI-only object is skipped."""
    from . import api_library as lib
    product, version = _build_of(appliance)
    if not version or not endpoints:
        return []
    eps = (lib.channels_at(product, version).get("endpoints") or {})
    out = []
    for key in endpoints:
        ep = eps.get(key) or {}
        if ep.get("channel") != "cli_only":
            continue
        sec = _cli_section(appliance, key)
        if sec is not None:
            out.append(sec)
    return out


def device_inventory(appliance) -> dict:
    """Every field the device has outside its GUI, for the whole build — the
    per-device page. Two lists:

    * ``objects`` — whole objects only the CLI serves (REST does not have the
      endpoint at all: FortiAuthenticator ``system/dns``, ``system/interface``…);
    * ``fields`` — objects REST serves that carry CLI-only / hidden fields.

    Plus the layout-measured pages (FortiWeb Server Policy) and a note for
    products no lab device measured."""
    from . import api_library as lib
    product, version = _build_of(appliance)
    out = {"title": SECTION_TITLE, "product": product, "version": version,
           "objects": [], "fields": [], "layout_pages": [], "absent": [], "note": "",
           "complete": False}
    if not version:
        out["note"] = ("The running build of this appliance is unknown: run a firmware check "
                       "so SATOM can name the fields it has outside the GUI.")
        return out
    view = lib.channels_at(product, version)
    summ = view.get("summary") or {}
    out["complete"] = bool(summ.get("complete"))
    out["tree_measured"] = bool(summ.get("tree_measured"))
    for key, ep in sorted((view.get("endpoints") or {}).items()):
        attrs = ep.get("attrs") or {}
        cli = [{"key": n, "channel": CH_CLI, "lib_channel": f.get("channel"),
                "cli_type": (f.get("attrs") or {}).get("type") or "",
                "cli_options": list((f.get("attrs") or {}).get("options") or [])}
               for n, f in sorted((ep.get("fields") or {}).items())
               if f.get("channel") in _LIB_CLI]
        if ep.get("channel") == "cli_only":
            out["objects"].append({"endpoint": key, "cli_path": attrs.get("cli_path") or "",
                                   "kind": attrs.get("kind") or "", "fields": cli,
                                   "section": _cli_section(appliance, key)})
        elif cli:
            out["fields"].append({"endpoint": key, "cli_path": attrs.get("cli_path") or "",
                                  "fields": cli, "section": _cli_section(appliance, key)})
    for (prod, ep_key), page in sorted(layout_pages().items()):
        if prod != product:
            continue
        keys, info = layout_keys(product, ep_key, version)
        if keys is None or info.get("gui_absent"):
            continue  # a page of objects the GUI does not draw: ``absent`` below
        rest = sorted(n for n, f in ((view.get("endpoints") or {}).get(ep_key, {})
                                     .get("fields") or {}).items()
                      if f.get("channel") in _LIB_REST and n not in keys)
        out["layout_pages"].append({"endpoint": ep_key, "page": page, "layout": info,
                                    "rest_not_in_gui": rest})
    out["absent"] = absent_objects(appliance)
    if unmeasured(product):
        out["note"] = ("GUI layout not measured for this product (no lab device), and its CLI "
                       "tree is not measured either: SATOM cannot split GUI from CLI-only "
                       "fields yet. Every field the REST API returns is shown in the object "
                       "views; nothing is hidden.")
    elif not out["tree_measured"]:
        out["note"] = ("The CLI tree of %s %s is not measured: CLI-only fields cannot be named "
                       "until it is (satom-harvester)." % (product, version))
    return out


WHY_GUI_ABSENT, WHY_NO_PAGE = "gui_absent", "no_page"


def absent_objects(appliance) -> list:
    """Whole objects the device has that its own GUI does not draw, in its
    menu order: ``[{"endpoint", "label", "group", "page", "v", "columns",
    "why"}]``.

    * ``gui_absent`` -- every view of a page the knowledge pack marks
      ``gui_absent`` for the device's firmware (the crawl opened every menu
      entry and recorded every read; these objects were read by none). SATOM
      draws them from the device's schema at ``page`` / view ``v``.
    * ``no_page`` -- FortiADC only: an entity of the registry the build serves
      that no measured page of the build reads at all (7.6.7: ``system_auto_backup``,
      whose GUI tab is an action and was pruned from the layout). ``page`` is
      None: this list is the only place SATOM shows it. The registry is the
      FortiADC entity catalog; on FortiWeb / FortiGate / FortiAuthenticator a
      collection without a page is a mapping gap of the crawl, not an absence,
      so it is not claimed here.

    Nothing here reads the device; :func:`absent_rows` does, one object at a
    time."""
    from . import gui_pages, gui_products, gui_store
    product = gui_products.product_of(appliance)
    if product is None:
        return []
    fw = gui_store.firmware_of(appliance)
    out: list = []
    seen: set = set()
    for e in gui_pages.entries(fw, product):
        if e.get("special"):
            continue
        tpl, _m = gui_pages.template(e["page"], fw, product)
        if not tpl or not tpl.get("gui_absent"):
            continue
        group = " / ".join(str(p) for p in (e.get("path") or [])[1:]) or e["page"]
        for i, v in enumerate(gui_pages.views(tpl)):
            ep = v.get("endpoint") or ""
            if not ep or ep in seen or gui_products.read_only_endpoint(ep):
                continue
            seen.add(ep)
            out.append({"endpoint": ep, "label": gui_pages.tab_label(tpl, v, i),
                        "group": group, "page": e["page"], "v": i,
                        "columns": [c for c in v.get("columns") or []
                                    if isinstance(c, dict) and c.get("id")],
                        "why": WHY_GUI_ABSENT})
    if product == gui_products.FORTIADC:
        out.extend(_adc_unplaced(appliance, seen))
    return out


def _adc_unplaced(appliance, seen: set) -> list:
    """FortiADC registry entities the device's build serves that no measured
    page reads (:func:`gui_classic.page_map`, which already holds every
    ``gui_absent`` view). A child table lives in its parent's page; an entity
    the build is measured NOT serving (the 8.0 App Portal / SSO admin a 7.6.7
    answers 404 for) is not the device's. No page at all for the build = no
    layout to compare with: nothing is claimed."""
    from . import gui_classic, gui_products
    try:
        from ..registry import loader
        reg = loader.load_adc_registry()
    except Exception:  # noqa: BLE001 -- no registry: nothing to compare
        log.exception("not_in_gui: FortiADC registry")
        return []
    pmap = gui_classic.page_map(appliance)
    if not pmap:
        return []
    labels: dict = {}
    try:
        from . import adc_menu
        labels = {t.logical: t.label for g in adc_menu.menu() for it in g.items for t in it.tabs}
    except Exception:  # noqa: BLE001 -- the entity name is label enough
        pass
    out = []
    for key in sorted(reg):
        if key in pmap or key in seen:
            continue
        if gui_products.ADC_CHILD in key and key.split(gui_products.ADC_CHILD)[0] in pmap:
            continue
        if gui_classic.not_served(appliance, key):
            continue
        out.append({"endpoint": key, "label": labels.get(key) or key, "group": "",
                    "page": None, "v": 0, "columns": [], "why": WHY_NO_PAGE})
    return out


def absent_rows(appliance, endpoint: str) -> dict | None:
    """The rows of ONE object of :func:`absent_objects`, read through the
    product's GUI adapter (FortiADC: ``GET /api/<entity>``, a few seconds of
    cache, secrets scrubbed). None when *endpoint* is not one of them -- this
    never reads an arbitrary path. ``{"object", "rows", "columns",
    "singleton", "error"}``; a settings object lists every field."""
    obj = next((o for o in absent_objects(appliance) if o["endpoint"] == endpoint), None)
    if obj is None:
        return None
    from . import gui_products
    try:
        rows, meta = gui_products.adapter(appliance).rows(appliance, endpoint)
    except Exception as exc:  # noqa: BLE001 -- drawn as unreadable
        rows, meta = [], {"error": "%s: %s" % (type(exc).__name__, exc)}
    meta = meta or {}
    rows = [r for r in rows or [] if isinstance(r, dict)]
    columns = list(obj["columns"])
    if not columns:
        keys: list = []
        for r in rows:
            keys.extend(k for k in r if k not in keys)
        columns = [{"id": k, "label": k} for k in keys]
    return {"object": obj, "rows": rows, "columns": columns,
            "singleton": bool(meta.get("singleton")), "error": meta.get("error") or ""}


def cli_values(appliance, endpoint: str, mkey: str | None, names, *,
               parent_mkeys=(), writer=None) -> dict:
    """Read the current values of *names* over the CLI (``show
    full-configuration``, read-only session). Secrets are never returned.

    ``{"ok", "values": {name: str|None}, "unset": [...], "error"}``."""
    from . import cli_writer
    names = [n for n in (names or []) if n]
    split = cli_writer.split_payload(appliance, endpoint, {n: "" for n in names})
    try:
        plan = cli_writer.plan_for(appliance, {**split, "cli": {}}, mkey,
                                   parent_mkeys=parent_mkeys)
    except cli_writer.CliWriteRefused as exc:
        return {"ok": False, "values": {}, "unset": [], "error": str(exc)}
    w = writer or cli_writer.CliWriter(appliance, audit=False)
    _, chain = w._show_command(plan)
    try:
        read = w._read_object(plan)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "values": {}, "unset": [], "error": "CLI read failed: %s" % exc}
    if read.get("not_found") or chain not in (read.get("rows") or {}):
        return {"ok": False, "values": {}, "unset": [],
                "error": "the CLI does not show this object"}
    vals = cli_writer.row_values(read["rows"][chain], plan.cli_path)
    lib = _channels(split.get("product") or "", split.get("version") or "",
                    split.get("endpoint") or endpoint_key(endpoint)).get("fields") or {}
    values, secret = {}, []
    for n in names:
        if cli_writer.is_secret(n, (lib.get(n) or {}).get("attrs")):
            secret.append(n)
            continue
        values[n] = vals["values"].get(n)
    return {"ok": True, "values": values, "secret": secret,
            "unset": sorted(set(vals["unset"]) & set(names)), "error": ""}


__all__ = ["SECTION_TITLE", "CH_REST", "CH_CLI", "CH_UNVERIFIED", "LAYOUT_PAGES", "layout_pages",
           "classify", "apply_to_groups", "for_view", "device_inventory", "layout_keys",
           "cli_values", "endpoint_key", "save", "cli_objects_for", "absent_objects",
           "absent_rows"]
