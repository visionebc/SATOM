"""FortiWeb GUI page templates (``satom.gui-template/1``) — layout as data, per build.

A template is the layout of ONE FortiWeb GUI page, read off the GUI a FortiWeb
serves to its own admin by ``satom-harvester gui fetch|extract`` (it is never
hand-written): list columns and the per-operation-mode default column set, the
Create New menu, every dialog with its section titles, field order, labels,
control types, options and the condition that shows or hides each field.

Templates arrive through the knowledge feed, one per EXACT build, and are
resolved per device by :mod:`gui_store` (the release ships none). The form is
a property of the firmware: 8.0.6 renamed *Let's Encrypt* to *ACME* and added
two fields to the HTTP Content Routing rule (measured 2026-10-08, fortiweb17
vs fortiweb18).

Selection is honest about the match: :func:`select` returns the template of the
device's own build / version / train when there is one; otherwise the closest
OLDER train, and the page says so ("built from FortiWeb 7.6.8 — this device
runs 8.0.6") so an operator never mistakes an older form for the device's.

Conditions are evaluated **tri-state** (True / False / None = cannot tell):
a field whose condition depends on something SATOM cannot read about the device
is SHOWN and marked, never silently hidden — hiding on absent evidence would
take a field away from the operator because of a gap in what we measured.
"""
from __future__ import annotations

import re

SCHEMA = "satom.gui-template/1"
SCHEMA_V2 = "satom.gui-template/2"


def select(product: str, page: str, fw_version: str | None):
    """(template, match) for a device firmware (``"7.6.8"`` or the full string
    ``"FortiWeb-KVM 7.6.8,build1128(GA.M)"``, whose build is then used too).

    match: ``exact`` (same train) · ``older`` (closest older train) ·
    ``newer`` (device older than every template) · ``unknown`` (no firmware
    known; newest template). ``(None, None)`` when the page has no template.

    Resolution is per EXACT build (:func:`gui_store.resolve`): a template the
    knowledge feed imported for the device's own build wins, then its version,
    its train, the closest older train. The template carries ``origin`` (the
    pack and the build it was measured on) and ``closeness`` so the page can
    say how close the layout is. Pass :func:`gui_store.firmware_of` of the
    device, not ``fw_version``: the bare version drops the build.
    """
    from . import gui_store
    cand, match, closeness = gui_store.resolve(product, page, fw_version)
    if cand is None:
        return None, None
    tpl = gui_store.view_template(cand)
    if tpl.get("schema") not in (SCHEMA, SCHEMA_V2):
        raise ValueError("%s: not a GUI template" % cand["path"])
    if product == "fortianalyzer":
        # the harvester names FortiAnalyzer endpoints relative and by kind
        # (JSON-RPC / the GUI's private calls): the engine's form of them
        from .gui_products import faz_template
        tpl = faz_template(tpl)
    tpl["closeness"] = closeness
    return tpl, match


# --------------------------------------------------------------------------- #
# Device context: what the conditions ask about the device
# --------------------------------------------------------------------------- #
def device_context(*, opmode: str | None, visibility: dict | None,
                   firmware: str | None, model: str | None = None,
                   cmdb=None) -> dict:
    """Facts a template's ``contexts`` resolve against.

    ``visibility`` is ``system feature-visibility`` (feature -> enable/disable).
    The platform word of ``FortiWeb-KVM 7.6.8…`` tells a container build
    (``HAVE_VIRT_DOCKER``) apart. It sits in the full status string, which the
    appliance row may hold as ``firmware`` or -- as on a1, where ``firmware`` is
    just ``7.6.8`` -- as ``model``; both are tried.
    """
    platform = None
    for src in (firmware, model):
        m = re.match(r"\s*FortiWeb-(\S+)\s", src or "")
        if m:
            platform = m.group(1)
            break
    from . import gui_store
    out = {"opmode": opmode or None, "visibility": dict(visibility or {}),
           "platform": platform,
           # the status string WITH its build, for what is looked up per build
           "firmware": next((x for x in (firmware, model) if gui_store.build_of(x)),
                            firmware or "")}
    if cmdb is not None:
        out["cmdb"] = cmdb      # callable(path) -> the cached object, or None
    return out


def _ctx_value(name: str, defs: dict, dev: dict):
    """Resolve one ``ctx`` reference to a value, or None when unknowable."""
    if name == "opmode":
        return dev.get("opmode")
    d = defs.get(name) or {}
    vis = dev.get("visibility") or {}
    parts = []
    if "opmode_is" in d:
        if dev.get("opmode") is None:
            return None
        parts.append(dev["opmode"] == d["opmode_is"])
    if "visibility" in d:
        v = vis.get(d["visibility"])
        parts.append(None if v is None else v == "enable")
    if "opmode_in" in d:
        # "reverse-proxy"==this.opMode||"transparent"==...?this.showWaitingRoom=!0
        if dev.get("opmode") is None:
            return None
        parts.append(dev["opmode"] in d["opmode_in"])
    if "model_not_in" in d:
        # this.showABP="FWB_100D"!==CONFIG_SYSTEM_MODEL&&... : the model token is
        # not in the status string, so only what the platform word settles is
        # answered (a KVM/VMware/Hyper-V/Xen VM is FWB_VM*, a container
        # FWB_DOCKER*, hardware FWB_<model>); a cloud image (on-demand vs BYOL)
        # stays unknown.
        plat = dev.get("platform") or ""
        bad = set(d["model_not_in"])
        if plat in ("KVM", "VMware", "HyperV", "XEN"):
            parts.append(not any(m.startswith("FWB_VM") for m in bad))
        elif plat.lower() == "docker":
            parts.append(not any(m.startswith("FWB_DOCKER") for m in bad))
        elif re.fullmatch(r"\d{3,4}[A-Z]{1,6}", plat):
            parts.append(("FWB_" + plat) not in bad)
        else:
            parts.append(None)
    if "cmdb" in d:
        # a field of a cmdb object the GUI reads when the dialog opens
        # (WPP: server-policy/pattern.threat-weight -> threat-score-profile),
        # from the SATOM cache. Its VALUE is the fact: conditions compare it.
        reader = dev.get("cmdb")
        obj = reader(d["cmdb"]) if callable(reader) else None
        if not isinstance(obj, dict) or d.get("field") not in obj:
            return None
        return obj.get(d["field"])
    if "device_config" in d:
        if d["device_config"] == "HAVE_VIRT_DOCKER" and dev.get("platform"):
            parts.append(dev["platform"].lower() == "docker")
        elif d["device_config"] == "CONFIG_SYSTEM_MODEL" and dev.get("platform"):
            # FWB_CMINTF is a hardware model family; a VM / container is not it
            parts.append(False if dev["platform"] in ("KVM", "VMware", "Docker", "HyperV",
                                                      "XEN", "AWS", "Azure", "GCP", "OCI")
                         else None)
        else:
            parts.append(None)
    if not parts:
        return None
    if False in parts:
        return False
    if None in parts:
        return None
    return True


def evaluate(ast, row: dict, defs: dict, dev: dict):
    """Tri-state value of a condition AST against a policy row + device facts.

    Mirrors AngularJS loosely-typed truthiness: a missing formData key is
    ``undefined`` (known, falsy), not unknown — the row IS the device's answer.
    """
    if ast is None:
        return True
    if "raw" in ast:
        return None
    if "lit" in ast:
        return ast["lit"]
    if "field" in ast:
        v = row.get(ast["field"])
        return "" if v is None else v
    if "ref_set" in ast:
        v = row.get(ast["ref_set"])
        return bool(v)
    if "ctx" in ast:
        if ast.get("undefined"):
            return None
        return _ctx_value(ast["ctx"], defs, dev)
    op, args = ast["op"], ast["args"]
    if op == "not":
        v = evaluate(args[0], row, defs, dev)
        return None if v is None else not _truthy(v)
    if op in ("eq", "ne"):
        a, b = (evaluate(x, row, defs, dev) for x in args)
        if a is None or b is None:
            return None
        if a == "" and b is None:
            same = True
        else:
            same = str(a) == str(b) if not isinstance(a, bool) and not isinstance(b, bool) \
                else a == b
        return same if op == "eq" else not same
    vals = [evaluate(x, row, defs, dev) for x in args]
    if op == "and":
        if any(v is not None and not _truthy(v) for v in vals):
            return False
        return None if any(v is None for v in vals) else True
    if op == "or":
        if any(v is not None and _truthy(v) for v in vals):
            return True
        return None if any(v is None for v in vals) else False
    return None


def _truthy(v) -> bool:
    return bool(v) and v not in ("", 0, "0")


def unknowns(ast, row: dict, defs: dict, dev: dict) -> list[str]:
    """Names of the facts that made a condition unknowable (for the hover)."""
    out = []

    def walk(n):
        if not isinstance(n, dict):
            return
        if "raw" in n:
            out.append(n["raw"])
        elif "ctx" in n and evaluate(n, row, defs, dev) is None:
            d = defs.get(n["ctx"]) or {}
            out.append(d.get("visibility") or d.get("device_config") or n["ctx"])
        for a in n.get("args", []):
            walk(a)
    walk(ast)
    return sorted(set(out))


# --------------------------------------------------------------------------- #
# View models
# --------------------------------------------------------------------------- #
def _with_derived(row: dict, dialog: dict) -> dict:
    """Add the GUI-only keys the dialog computes on load (cert-type, aliases)."""
    out = dict(row)
    for key, rules in (dialog.get("derived") or {}).items():
        for r in rules:
            if out.get(r["field"]) == r["eq"]:
                out[key] = r["value"]
                break
    for gui_key, rest_key in (dialog.get("aliases") or {}).items():
        out.setdefault(gui_key, out.get(rest_key))
    return out


def _real(opts) -> list:
    """The choices the crawl actually read: an option it could not read comes
    as ``{"value": null}`` and would be drawn (and saved) as the text "None"."""
    return split_labels([o for o in opts or [] if isinstance(o, dict) and o.get("value") is not None])


def split_labels(opts: list) -> list:
    """A radio group the crawl read as one text: every option carries the
    whole group's labels, one per line (``"NTP\nManual settings"`` on both
    Set Time choices). Line i is option i's label, in the order FortiWeb
    draws them; when the line count is not the option count nothing is
    guessed and the options are returned as they came."""
    labs = [str(o.get("label") or "") for o in opts]
    if len(opts) < 2 or len(set(labs)) != 1 or "\n" not in labs[0]:
        return opts
    parts = [p.strip() for p in labs[0].split("\n") if p.strip()]
    if len(parts) != len(opts):
        return opts
    return [dict(o, label=parts[i]) for i, o in enumerate(opts)]


def _options(field: dict, dev: dict) -> list:
    if _real(field.get("options")):
        return _real(field["options"])
    by = field.get("options_by") or {}
    if not by:
        return []
    mode = (dev.get("opmode") or "").replace("-", "_")
    suffix = {"reverse_proxy": "inline", "offline_protection": "offline",
              "transparent": "tp", "transparent_inspection": "tp", "wccp": "wccp"}.get(mode)
    for name, opts in by.items():
        if suffix and name.endswith("_" + suffix):
            return _real(opts)
    plain = [o for n, o in by.items() if "_" not in n]
    return _real(plain[0] if plain else next(iter(by.values())))


# --------------------------------------------------------------------------- #
# Choices a layout lost: never a bare text box
# --------------------------------------------------------------------------- #
def _dialog_endpoint(tpl: dict, dialog_key: str) -> str:
    """The collection a dialog edits: its own, else (a sub-table row dialog)
    the collection of the table that opens it, else the page's."""
    d = (tpl.get("dialogs") or {}).get(dialog_key) or {}
    if d.get("endpoint"):
        return d["endpoint"]
    for od in (tpl.get("dialogs") or {}).values():
        for b in od.get("blocks") or []:
            for f in b.get("fields") or []:
                if f.get("kind") == "table" and f.get("row_dialog") == dialog_key and f.get("endpoint"):
                    return f["endpoint"]
    return tpl.get("endpoint") or ""


def _layout_fallback(tpl: dict, dialog_key: str, field: dict, dev: dict):
    """``(options, version)`` of the same field of the same dialog in the
    nearest OTHER layout of the page, or ``([], "")``."""
    from . import gui_store
    product = tpl.get("product") or "fortiweb"
    page = tpl.get("page")
    here = (tpl.get("origin") or {}).get("version"), (tpl.get("origin") or {}).get("build")
    if not page:
        return [], ""
    fw = dev.get("firmware") or ""
    from . import firmware_versions as fv
    dv = gui_store._vkey(fv.normalize(fw))
    best = None
    for c in gui_store.candidates(product, page):
        if (c["version"], c["build"]) == here:
            continue
        try:
            t = gui_store.load(c["path"])
        except (OSError, ValueError):
            continue
        d2 = (t.get("dialogs") or {}).get(dialog_key)
        f2 = next((g for b in (d2 or {}).get("blocks") or [] for g in b.get("fields") or []
                   if g.get("key") == field.get("key") and g.get("kind") == field.get("kind")), None)
        opts = _options(f2, dev) if f2 else []
        if not opts:
            continue
        dist = (abs(gui_store._vkey(c["version"])[0] - dv[0]) if dv else 0,
                tuple(abs(a - b) for a, b in zip(gui_store._vkey(c["version"]), dv)),
                c["build"])
        if best is None or dist < best[0]:
            best = (dist, opts, c["version"])
    return (best[1], best[2]) if best else ([], "")


def fill_options(tpl: dict, dialog_key: str, field: dict, dialog: dict, dev: dict):
    """The choices of a select / radio / checks control whose resolved layout
    carries none (the layout of another build lost them, or the crawl could not
    read them): ``(options, mark)``.

    1. the enum options of that object.field in the device's EXACT build, from
       the API library (the CLI tree prints every option): authoritative, no
       mark;
    2. else the same field of the same dialog in the nearest other layout of
       the page, marked "options from <version>, not verified on <device>";
    3. else ``([], None)``: the caller draws a text box and says the choices
       are unknown. Never a made-up list."""
    from flask_babel import gettext as _
    from . import firmware_versions as fv
    key = field.get("key")
    wkey = (dialog.get("aliases") or {}).get(key, key)
    fw = dev.get("firmware") or ""
    dv = fv.normalize(fw)
    if wkey and dv:
        try:
            from . import api_library, build_compat
            product = tpl.get("product") or "fortiweb"
            ep = build_compat.key_for(product, _dialog_endpoint(tpl, dialog_key))
            vals = api_library.field_options_at(product, ep, dv, wkey) if ep else None
            if not vals and ep:
                # a layout that records the PARENT as the dialog's endpoint
                # (8.0.8 Content Routing match dialog: the policy, while its
                # fields live in ``content-routing-match-list``): the one
                # by-parent child of the endpoint whose CLI tree has this
                # field with choices; none or several = no answer
                found = []
                for ck in sorted(k for k in api_library._tree_specs(product, dv)[1]
                                 if k.startswith(ep + "/") and k.count("/") == ep.count("/") + 1):
                    got = api_library.field_options_at(product, ck, dv, wkey)
                    if got:
                        found.append(got)
                vals = found[0] if len(found) == 1 else None
        except Exception:  # noqa: BLE001 -- the library never breaks a dialog
            vals = None
        if vals:
            _fb, _v = _layout_fallback(tpl, dialog_key, field, dev)
            labels = {str(o.get("value")): o.get("label") for o in _fb}
            return [{"value": v, "label": labels.get(v) or v} for v in vals], None
    opts, ver = _layout_fallback(tpl, dialog_key, field, dev)
    if opts:
        return opts, {"source": "layout", "version": ver,
                      "text": _("options from %(v)s, not verified on %(dv)s", v=ver, dv=dv or "?")}
    return [], None


def _datasource_ref(tpl: dict, dialog_key: str, field: dict, dialog: dict, dev: dict) -> bool:
    """True when a select the layout drew with no choices is a REFERENCE to
    another collection, not an enum: the build's CLI tree types the field
    ``<datasource>`` (its values are the names of another table's rows) and
    SATOM knows which collection (``REF_ENDPOINTS`` / the layout's own
    ``ref_coll``). Such a control must be a reference selector; as a text box
    the operator types a name nothing checks."""
    from . import firmware_versions as fv
    from .fortiweb_field_schema import REF_ENDPOINTS
    key = field.get("key")
    wkey = (dialog.get("aliases") or {}).get(key, key)
    dv = fv.normalize(dev.get("firmware") or "")
    if not wkey or not dv or not (field.get("ref_coll") or wkey in REF_ENDPOINTS):
        return False
    try:
        from . import api_library, build_compat
        product = tpl.get("product") or "fortiweb"
        ep = build_compat.key_for(product, _dialog_endpoint(tpl, dialog_key))
        spec = (((api_library._tree_specs(product, dv)[1].get(ep) or {}).get("fields") or {})
                .get(wkey) or {}) if ep else {}
    except Exception:  # noqa: BLE001 -- the library never breaks a dialog
        return False
    return bool((spec.get("attrs") or {}).get("datasource"))


def _display(field: dict, row: dict, dev: dict):
    kind = field.get("kind")
    key = field.get("key")
    if kind == "toggle_rows":
        return [{"label": r["label"], "key": r["key"], "value": row.get(r["key"], "")}
                for r in field["rows"]]
    if key is None:
        # A control with no API on the build (FortiAuthenticator GUI-only
        # pages): since 2026-10-26 the sweep reads its form, so the row holds
        # the control's own value under its form name, and ``_labels`` what a
        # select shows for it.
        name = field.get("gui_name")
        if field.get("key_from") != "gui-only" or not name or name not in (row or {}):
            return None
        v = row.get(name)
        lab = (row.get("_labels") or {}).get(name)
        if lab not in (None, "") and not isinstance(v, bool):
            return lab
        if isinstance(v, list):
            return ", ".join(str(x) for x in v)
        return v
    v = row.get(key)
    if kind in ("select", "radio"):
        for o in _options(field, dev):
            if str(o.get("value")) == str(v):
                return o.get("label")
    if kind == "checks":
        return [c for c in str(v or "").split() if c]
    if kind == "multiselect":
        return [c for c in str(v or "").split() if c]
    return v


# The objects a sub-table column or a sub-dialog field reads through another
# table, by the name the template gives them (REST path or GUI data source) ->
# the SATOM cache logical that holds them.
REF_LOGICALS = {
    "server-policy/http-content-routing-policy": "http_content_routing",
    "server.http-content-routing-policy": "http_content_routing",
}


def needed_refs(tpl: dict, dialog_key: str) -> set[str]:
    """Cache logicals a dialog's sub-tables / from_ref fields join against."""
    d = tpl["dialogs"][dialog_key]
    out = set()
    for b in d["blocks"]:
        for f in b["fields"]:
            for c in f.get("columns") or []:
                lg = REF_LOGICALS.get((c.get("join") or {}).get("from"))
                if lg:
                    out.add(lg)
            if f.get("from_ref"):
                ref = next((g for bb in d["blocks"] for g in bb["fields"]
                            if g.get("key") == f["from_ref"]["key"]), {})
                lg = REF_LOGICALS.get(ref.get("source"))
                if lg:
                    out.add(lg)
    return out


def row_dialogs(tpl: dict, dialog_key: str) -> dict:
    """{row dialog key: sub-table name} for the sub-tables of a dialog."""
    return {f["row_dialog"]: f.get("subtable")
            for b in tpl["dialogs"][dialog_key]["blocks"] for f in b["fields"]
            if f.get("kind") == "table" and f.get("row_dialog")}


def _cell(col: dict, r: dict, refs: dict):
    bw = col.get("blank_when")
    if bw and r.get(bw["field"]) == bw["eq"]:
        return ""
    j = col.get("join")
    if j:
        obj = (refs.get(REF_LOGICALS.get(j.get("from"))) or {}).get(r.get(j["key"])) or {}
        return obj.get(j["field"]) or ""
    v = r.get(col["id"])
    if col.get("labels"):
        return col["labels"].get(v, v or "")
    # FortiWeb's grids title-case the enable / disable switches
    # (``<key>_val`` is no display twin: on some collections it is an index)
    if v in ("enable", "disable"):
        return v.title()
    return "" if v is None else v


def _from_ref(f: dict, d: dict, data: dict, refs: dict):
    """A display field showing a field of the object another selector names
    (content routing: the Server Pool of the chosen routing policy)."""
    fr = f["from_ref"]
    ref = next((g for b in d["blocks"] for g in b["fields"] if g.get("key") == fr["key"]), {})
    obj = (refs.get(REF_LOGICALS.get(ref.get("source"))) or {}).get(data.get(fr["key"])) or {}
    return obj.get(fr["field"]) or ""


def _table_view(f: dict, rows, refs: dict) -> dict:
    """A sub-table as FortiWeb draws it: toolbar, columns, formatted cells.
    ``rows`` None = the policy's sub-tables are not in the cache."""
    cols = f.get("columns") or []
    return {"columns": [{"id": c["id"], "label": c["label"]} for c in cols],
            "subtable": f.get("subtable"),
            "toolbar": f.get("toolbar") or [],
            "row_dialog": f.get("row_dialog"),
            "rows": None if rows is None else
            [{"id": r.get("id"), "cells": [_cell(c, r, refs) for c in cols]} for r in rows]}


# Controls the layout view can write back. Sub-tables, links, view switches and
# display-only fields are not values of the policy object; a derived key
# (cert-type) is computed by the GUI from other fields and has no REST twin.
_EDIT_KINDS = {"toggle", "check", "radio", "select", "text", "number", "textarea", "ref",
               "multiselect", "checks", "toggle_rows"}


def _api_twin(f: dict) -> str:
    """The cmdb collection of a selector whose GUI lists a GUI API path
    (ref_api: system/certificate.ocsp_sign_certs): only the twin the
    alias table measured or named (services.gui_alias), never a guess."""
    api = f.get("ref_api")
    if not api:
        return ""
    from .gui_alias import table
    return ((table()["aliases"].get(api) or {}).get("cmdb")) or ""


def _edit_spec(f: dict, d: dict, data: dict, dev: dict, *, new: bool = False) -> dict:
    """How the field is written: the REST key (aliases resolved), the raw value
    the input starts from, and the choices a select / radio / checks offers.
    ``name`` is the object's key: set once, on a new object only."""
    from .fortiweb_field_schema import REF_ENDPOINTS
    kind = f.get("kind")
    key = f.get("key")
    wkey = (d.get("aliases") or {}).get(key, key)
    editable = (kind in _EDIT_KINDS and not f.get("from_ref")
                and (key is not None or kind == "toggle_rows")
                and key not in (d.get("derived") or {}) and (key != "name" or new)
                # measured with no API on this build: shown, never saved
                and f.get("key_from") != "gui-only"
                # drawn read-only by the device's own GUI (FortiAuthenticator)
                and not f.get("readonly"))
    raw = data.get(wkey)
    return {
        "editable": editable,
        "wkey": wkey,
        "raw": "" if raw is None else str(raw),
        "off": f.get("off", "disable"),
        "opts": [{"value": str(o.get("value")), "label": o.get("label")}
                 for o in _options(f, dev)] if kind in ("select", "radio", "checks") else [],
        # the collection the GUI itself lists (measured: its Omniselect
        # source) over SATOMs per-key map, which cannot tell two dialogs
        # "service" apart (Firewall Policy lists system/firewall.service)
        "ref": (f.get("ref_coll") or REF_ENDPOINTS.get(wkey or "", "") or _api_twin(f) or "")
        if kind == "ref" else "",
        # the GUI lists only the source's rows that match (Certificate Group:
        # pkey_type 1/2/3; SNI: cert_type local): the list comes from the GUI
        # API that carries those fields (``ref_api``), never unfiltered
        "ref_filter": (f.get("source_filter") or None) if kind == "ref" and (
            f.get("ref_api") or f.get("ref_coll")) else None,
        "ref_api": (f.get("ref_api") or "") if kind == "ref" and f.get("source_filter") else "",
        "min": f.get("min"),
        "max": f.get("max"),
    }


def bind_device(ast, defs: dict, dev: dict):
    """The condition with every device fact resolved (opmode, feature
    visibility, platform) so the browser can re-evaluate it against the form
    alone: a known fact becomes ``{"lit": value}``, an unknowable one
    ``{"raw": name}`` (tri-state None, exactly as :func:`evaluate` treats it)."""
    if not isinstance(ast, dict):
        return ast
    if "ctx" in ast:
        v = None if ast.get("undefined") else _ctx_value(ast["ctx"], defs, dev)
        return {"raw": ast["ctx"]} if v is None else {"lit": v}
    if "args" in ast:
        return {**ast, "args": [bind_device(a, defs, dev) for a in ast["args"]]}
    return ast


#: Kinds the live view keeps (hidden) when their condition is false: the
#: controls the operator can change. A hidden sub-table, link or display field
#: has no value to edit; it appears after the save reloads the page.
_LIVE_KINDS = _EDIT_KINDS


def _shadowed_controls(fields: list) -> set:
    """Indexes of controls a block draws twice. A layout that lists the same
    label twice -- once as a choice control (radio / select / checks) with no
    field and no choices, once as a toggle or a check -- holds ONE setting: the
    choice control is an empty ghost of the toggle (FortiGate Security Fabric:
    "Security Fabric role"). Only a keyless, option-less choice control is
    dropped, and only when a toggle / check of the same label sits in the same
    block; two real fields with one label (two "Port"s) are both kept."""
    def label(f):
        return " ".join(str(f.get("label") or "").lower().split())
    solid = {label(f) for f in fields if f.get("kind") in ("toggle", "check") and label(f)}
    keyed = {label(f) for f in fields if f.get("key") and f.get("kind") != "display" and label(f)}
    return {i for i, f in enumerate(fields)
            if (f.get("kind") in ("radio", "select", "checks") and not f.get("key")
                and not f.get("options") and not f.get("candidates") and label(f) in solid)
            # a keyless, textless caption that repeats the label of the real
            # control beside it (HTTP Header Security: "Name" twice)
            or (f.get("kind") == "display" and not f.get("key") and not f.get("text")
                and not f.get("candidates") and label(f) in keyed)}


def dialog_view(tpl: dict, dialog_key: str, row: dict, dev: dict, *,
                subrows: dict | None = None, refs: dict | None = None,
                live: bool = False, new: bool = False) -> dict:
    """Blocks -> fields with ``state`` shown / unknown (hidden ones are dropped
    from ``blocks`` but counted, so the page can say how many the GUI hides).

    ``subrows`` {sub-table name: rows | None} fills the inline sub-tables;
    ``refs`` {cache logical: {name: payload}} serves their joins.

    ``live`` (the editable page): hidden CONTROLS stay in ``blocks`` with
    ``hidden: True``, and every field and block carries ``cond`` (its
    condition with the device facts bound, :func:`bind_device`), so the page
    shows and hides them as the operator edits, as FortiWeb's GUI does. The
    view then has ``live`` = the starting row and the dialog's derived /
    aliased keys. ``new``: the Create New form (``name`` is writable)."""
    refs = refs or {}
    d = tpl["dialogs"][dialog_key]
    defs = dict(d.get("contexts") or {})
    data = _with_derived(row, d)
    blocks, hidden = [], 0
    for b in d["blocks"]:
        bstate = evaluate(b.get("cond"), data, defs, dev)
        bhidden = bstate is not None and not _truthy(bstate)
        if bhidden:
            hidden += len(b["fields"])
            if not live:
                continue
        fields = []
        shadowed = _shadowed_controls(b["fields"])
        for fi, f in enumerate(b["fields"]):
            if f.get("kind") in ("spacer", "category_grid", "subtable_grid"):
                # a table the dialog draws by hand: drawn apart (gui_grid)
                continue
            if fi in shadowed:
                continue
            st = evaluate(f.get("cond"), data, defs, dev)
            fhidden = st is not None and not _truthy(st)
            if fhidden and not bhidden:
                hidden += 1
            if (fhidden or bhidden) and not (live and f.get("kind") in _LIVE_KINDS):
                continue
            unknown = bstate is None or st is None
            # a select / radio / checks whose layout carries no choices (the
            # crawl could not read them, or the layout of another build lost
            # them) gets them from the device's own build, else from the
            # nearest other layout (marked); only with neither is it a text
            # input over the current value -- never a made-up choice
            opts_mark = None
            if f.get("kind") in ("select", "radio", "checks") and not _options(f, dev):
                got, opts_mark = fill_options(tpl, dialog_key, f, d, dev)
                if got:
                    f = dict(f, options=got)
            unread = f.get("kind") in ("select", "radio") and not _options(f, dev)
            if unread and _datasource_ref(tpl, dialog_key, f, d, dev):
                f, unread = dict(f, kind="ref"), False
            if unread:
                f = dict(f, kind="text")
            fields.append({
                # a table headed by the section title it sits under says it once
                "label": "" if (f.get("kind") == "table" and b.get("title")
                                and " ".join(str(f.get("label") or "").lower().split())
                                == " ".join(str(b["title"]).lower().split()))
                else (f.get("label") or ""),
                "help": f.get("help") or "",
                "kind": f.get("kind"),
                "key": f.get("key"),
                "value": _from_ref(f, d, data, refs) if f.get("from_ref")
                else _display(f, data, dev),
                "on": f.get("on", "enable"),
                "suffix": f.get("suffix") or "",
                "required": bool(f.get("required")),
                "options": _options(f, dev) if f.get("kind") == "view_switch" else [],
                # a radio group shows every choice, the current one marked
                "choices": [{"label": o.get("label"),
                             "on": str(o.get("value")) == str(data.get(f.get("key")))}
                            for o in _options(f, dev)] if f.get("kind") == "radio" else [],
                "dialog": f.get("dialog"),
                "source": f.get("source"),
                "text": f.get("text") or "",
                "style": f.get("style") or "",
                "edit_shortcut": bool(f.get("edit_shortcut")),
                # FortiWeb's "+ Create" in the selector (source createNew)
                "create_new": bool(f.get("create_new")),
                # and its Edit pencil on each entry of the list (inlineEdit)
                "inline_edit": bool(f.get("inline_edit")),
                "table": _table_view(f, (subrows or {}).get(f.get("subtable")), refs)
                if f.get("kind") == "table" else None,
                "unknown": unknown,
                "unknown_why": (unknowns(b.get("cond"), data, defs, dev)
                                + unknowns(f.get("cond"), data, defs, dev)) if unknown else [],
                **_edit_spec(f, d, data, dev, new=new),
                # the other controls of the same field (Log Type: Event / Attack /
                # Traffic log), each a key of the same object
                "more": [{"key": m["key"], "label": m.get("label") or m["key"],
                          "kind": m.get("kind") or "check",
                          "raw": "" if data.get(m["key"]) is None else str(data.get(m["key"])),
                          "on": m.get("on", "enable"), "off": m.get("off", "disable")}
                         for m in f.get("more") or [] if m.get("key")],
                # a choice control with a key whose choices nobody measured; a
                # control with NO key is a different gap (``unbound``): nothing
                # to type a value into
                "options_unread": unread and bool(f.get("key")),
                "unbound": unread and not f.get("key") and not f.get("candidates")
                and f.get("key_from") != "gui-only",
                "options_mark": opts_mark,
                "bound_to": f.get("bound_to"),
                "bound_unread": bool(f.get("bound_unread")),
                "gui_only": f.get("key_from") == "gui-only",
                "readonly": bool(f.get("readonly")),
                # SATOM could not tell which REST key the control shows: the
                # keys still consistent with it (FortiAuthenticator crawl)
                "candidates": list(f.get("candidates") or [])
                if not f.get("key") and f.get("key_from") != "gui-only" else [],
            })
            if live:
                fields[-1]["hidden"] = fhidden
                fields[-1]["cond"] = bind_device(f.get("cond"), defs, dev)
        if fields:
            # A fold is FortiWeb's +/- section title. Its initial state when the
            # GUI computes it (raw JS, e.g. "any ML policy set") is not
            # evaluated here: closed, one click away -- nothing is hidden.
            fold = b.get("fold")
            blk = {"title": b.get("title"), "fields": fields,
                   "unknown": bstate is None,
                   "fold": bool(fold),
                   # ``fold: true`` (FortiAuthenticator: drawn folded) or
                   # ``{"open": ...}`` (FortiWeb)
                   "open": (fold.get("open") is True) if isinstance(fold, dict) else not fold,
                   # the dialog tab the section sits in (FortiGate dialogs)
                   "tab": b.get("tab") or ""}
            if live:
                blk["hidden"] = bhidden
                blk["cond"] = bind_device(b.get("cond"), defs, dev)
            blocks.append(blk)
    from . import gui_pages
    out = {"key": dialog_key,
           # a dialog the template gave no title is named as every surface names it
           "title": {k: gui_pages.dialog_title(tpl, dialog_key, k) for k in ("new", "edit")},
           "blocks": blocks,
           "hidden": hidden,
           # a page of FortiWeb's newer shell: read from what the browser drew
           # (no template to parse), so show / hide conditions are not known
           "rendered_only": bool(d.get("rendered_only"))}
    if live:
        out["live"] = {"row": data, "derived": d.get("derived") or {},
                       "aliases": d.get("aliases") or {}}
    out["build_marked"] = mark_build_fields(blocks, tpl, dialog_key, d, dev)
    return out


def _rename_text(hints) -> str:
    """The rename the library computed for a field the build lacks (an operator
    field map, else the same CLI attribute id): ``renamed to `x```."""
    for h in hints or []:
        to = str(h.get("to") or "")
        if to and "." not in to and "/" not in to:
            return "renamed to `%s`" % to
    for h in hints or []:
        if h.get("text"):
            return str(h["text"])
    return ""


def build_marks(tpl: dict, dialog_key: str, dev: dict, keys) -> dict:
    """``{field: (state, text)}`` for a layout of ANOTHER build: what the API
    library says about the device's exact build, for the REST keys of one
    dialog. ``state`` is ``missing`` (the build lacks the field; ``text`` says
    "not on 8.0.8", with "(renamed to `new-name`)" when the library knows the
    rename) or ``unknown`` ("not measured on 8.0.8"). ``{}`` when the layout is
    of the device's own build, outside FortiWeb, or the library cannot answer.
    Display only: the save gate is ``build_compat``'s."""
    from flask_babel import gettext as _
    from . import firmware_versions as fv
    product = tpl.get("product") or "fortiweb"
    dv = fv.normalize(dev.get("firmware") or "")
    if product != "fortiweb" or not dv or (tpl.get("closeness") or "unknown") in ("build", "version"):
        return {}
    keys = sorted({k for k in keys if k})
    ep = _dialog_endpoint(tpl, dialog_key)
    if not keys or not ep:
        return {}
    try:
        from . import build_compat as bc
        res = bc.check_object(product, dv, ep, keys)
    except Exception:  # noqa: BLE001 -- the library never breaks a dialog
        return {}
    out = {}
    for item in res.get("findings") or []:
        name = item.get("field")
        if name not in keys:
            continue
        if item.get("kind") == bc.F_MISSING:
            rn = _rename_text(item.get("hints"))
            out[name] = ("missing", _("not on %(dv)s", dv=dv) + ((" (%s)" % rn) if rn else ""))
        elif item.get("kind") == bc.F_UNKNOWN:
            out[name] = ("unknown", _("not measured on %(dv)s", dv=dv))
    return out


def mark_build_fields(blocks: list, tpl: dict, dialog_key: str, dialog: dict, dev: dict) -> int:
    """Display-only marks for a layout of ANOTHER build (see :func:`build_marks`):

    * a field the build lacks (library ``missing``) is drawn disabled, with
      "not on 8.0.8 (renamed to `new-name`)" when the library knows the rename;
    * a field whose state is ``unknown`` keeps working and carries "not
      measured on 8.0.8".

    Returns how many fields were marked."""
    wk = {}
    for b in blocks:
        for f in b["fields"]:
            if f.get("editable") and f.get("key") and not f.get("bound_to") and not f.get("gui_only") \
                    and not str(f["key"]).startswith("@") and f.get("wkey"):
                wk.setdefault(f["wkey"], []).append(f)
    marks = build_marks(tpl, dialog_key, dev, wk)
    n = 0
    for name, (state, text) in marks.items():
        for f in wk.get(name, ()):
            f["build_state"], f["build_note"] = state, text
            if state == "missing":
                f["editable"] = False
            n += 1
    return n


def list_view(tpl: dict, rows: list[dict], dev: dict) -> dict:
    """Columns in FortiWeb's default order for the device's operation mode,
    the optional ones after them, and the Create New menu items."""
    lst = tpl["list"]
    by_mode = lst["columns_by_opmode"]
    sets = by_mode.get(dev.get("opmode") or "") or by_mode.get("reverse-proxy") \
        or next(iter(by_mode.values()))
    cols = {c["id"]: c for c in lst["columns"]}
    defs = lst.get("contexts") or {}
    menu = []
    for it in lst.get("create_menu", []):
        st = evaluate(it.get("cond"), {}, defs, dev)
        if st is not None and not _truthy(st):
            continue
        menu.append({"dialog": it["dialog"], "label": it["label"], "unknown": st is None})
    return {"columns": [cols[c] for c in sets["default"]],
            "optional_columns": [cols[c] for c in sets["available"]],
            "create_menu": menu,
            "dialog_by_protocol": lst.get("edit_dialog_by_protocol", {}),
            "rows": rows}


# FortiWeb 7.6's default Server Policy columns (reverse proxy, measured on
# fortiweb17), for a node that has not imported a knowledge pack: the list
# still draws the device's columns instead of a page of its own.
FALLBACK_COLUMNS = (("id", "#"), ("name", "Policy Name"), ("vserver", "Virtual Server"),
                    ("vip", "VIP"), ("port", "Port"), ("protocol", "Protocol"),
                    ("server-pool", "Server Pool"),
                    ("web-protection-profile", "Web Protection Profile"),
                    ("status", "Status"))


def fallback_list_view(rows: list[dict]) -> dict:
    """``list_view`` without a layout: default columns, no Create New dialogs."""
    return {"columns": [{"id": i, "label": label} for i, label in FALLBACK_COLUMNS],
            "optional_columns": [], "create_menu": [], "dialog_by_protocol": {},
            "rows": rows}


def protocol_cell(row: dict) -> str:
    """The Protocol column as FortiWeb computes it (fwb-server-policy.js)."""
    proto = row.get("protocol") or ""
    if proto in ("ADFSPIP", "TCPPROXY"):
        return proto
    if proto == "FTP":
        return "FTPS" if row.get("ssl") == "enable" and row.get("implicit_ssl") == "enable" \
            else "FTP"
    have = [n for n, k in (("HTTP", "service"), ("HTTPS", "https-service"),
                           ("HTTP3", "http3-service")) if row.get(k)]
    return ", ".join(have)


def status_running(row: dict, opmode: str | None) -> bool:
    """FortiWeb's Status column: enabled AND the deployment mode fits the opmode."""
    if row.get("status") != "enable":
        return False
    dm = row.get("deployment-mode")
    if opmode == "offline-protection":
        return dm == "offline-protection"
    if opmode == "reverse-proxy":
        return dm != "offline-protection"
    return True
