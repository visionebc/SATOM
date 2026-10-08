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

#: Products whose GUI layout no lab device has measured: no GUI/REST split is
#: possible, every field is listed and the section says why.
UNMEASURED_PRODUCTS = frozenset({"fortiadc", "fortianalyzer"})


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
    page = LAYOUT_PAGES.get((product, endpoint_key(endpoint)))
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
    keys = set(_template_keys(tpl, endpoint_key(endpoint)))
    based = tpl.get("based_on") or {}
    return keys, {"page": page, "match": match,
                  "based_on": based.get("version") or tpl.get("applies_to") or ""}


def _template_keys(tpl: dict, endpoint: str) -> set:
    """Field keys a template's dialogs place for *endpoint* (the page's object).

    A dialog names its endpoint when the extractor knew it; otherwise a dialog
    with operation-mode ``contexts`` edits the page's object and one without
    is a sub-table row dialog (content routing, public IP), which belongs to
    another endpoint."""
    own = endpoint_key(str(tpl.get("endpoint") or ""))
    keys: set = set()
    for d in (tpl.get("dialogs") or {}).values():
        dep = endpoint_key(str(d.get("endpoint") or "")) or (own if "contexts" in d else "")
        if dep != endpoint:
            continue
        for b in d.get("blocks") or []:
            for f in b.get("fields") or []:
                if f.get("key"):
                    keys.add(f["key"])
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
    elif product in UNMEASURED_PRODUCTS and layout is None:
        note = ("GUI layout not measured for this product (no lab device): fields the "
                "REST API returns stay in their groups; nothing is hidden.")
    elif layout is None:
        note = ("GUI layout not measured for this page on %s %s: this section lists the "
                "fields the device has outside its REST API." % (product, version))
    else:
        note = ("GUI layout of FortiWeb %s (%s): fields the Fortinet GUI does not show "
                "are listed here with the channel SATOM writes them by."
                % (linfo.get("based_on") or "?", linfo.get("match") or "?"))
    if version and not ep:
        note += " The API library has no evidence for this endpoint on this build."
    return {"title": SECTION_TITLE, "product": product, "version": version,
            "endpoint": key, "layout_measured": layout is not None, "layout": linfo,
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


def for_view(appliance, endpoint: str, data, *, noise=None) -> dict | None:
    """The section for a READ-ONLY product view (FortiGate, FortiAuthenticator,
    FortiADC, FortiAnalyzer): *data* is what REST returned for the endpoint (a
    list of rows or one settings object). Returns the section, or None when it
    cannot be built (the view renders as before)."""
    if isinstance(data, dict):
        keys = list(data)
    else:
        keys = sorted({k for r in (data or []) if isinstance(r, dict) for k in r})
    try:
        _, sec = apply_to_groups(appliance, endpoint, {k: None for k in keys}, [],
                                 describe=lambda k, v: {"key": k, "label": k, "value": ""},
                                 noise=noise)
    except Exception:  # noqa: BLE001 — never sinks a view
        log.exception("not_in_gui: section for %s", endpoint)
        return None
    return sec


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
           "objects": [], "fields": [], "layout_pages": [], "note": "", "complete": False}
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
                                   "kind": attrs.get("kind") or "", "fields": cli})
        elif cli:
            out["fields"].append({"endpoint": key, "cli_path": attrs.get("cli_path") or "",
                                  "fields": cli})
    for (prod, ep_key), page in sorted(LAYOUT_PAGES.items()):
        if prod != product:
            continue
        keys, info = layout_keys(product, ep_key, version)
        if keys is None:
            continue
        rest = sorted(n for n, f in ((view.get("endpoints") or {}).get(ep_key, {})
                                     .get("fields") or {}).items()
                      if f.get("channel") in _LIB_REST and n not in keys)
        out["layout_pages"].append({"endpoint": ep_key, "page": page, "layout": info,
                                    "rest_not_in_gui": rest})
    if product in UNMEASURED_PRODUCTS:
        out["note"] = ("GUI layout not measured for this product (no lab device), and its CLI "
                       "tree is not measured either: SATOM cannot split GUI from CLI-only "
                       "fields yet. Every field the REST API returns is shown in the object "
                       "views; nothing is hidden.")
    elif not out["tree_measured"]:
        out["note"] = ("The CLI tree of %s %s is not measured: CLI-only fields cannot be named "
                       "until it is (satom-harvester)." % (product, version))
    return out


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


__all__ = ["SECTION_TITLE", "CH_REST", "CH_CLI", "CH_UNVERIFIED", "LAYOUT_PAGES",
           "classify", "apply_to_groups", "for_view", "device_inventory", "layout_keys", "cli_values", "endpoint_key"]
