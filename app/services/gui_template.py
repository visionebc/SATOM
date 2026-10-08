"""FortiWeb GUI page templates (``satom.gui-template/1``) — layout as data, per build.

A template is the layout of ONE FortiWeb GUI page, read off the GUI a FortiWeb
serves to its own admin by ``satom-harvester gui fetch|extract`` (it is never
hand-written): list columns and the per-operation-mode default column set, the
Create New menu, every dialog with its section titles, field order, labels,
control types, options and the condition that shows or hides each field.

Templates live in ``app/registry/gui_templates/<product>/<page>/<train>.json``,
one per firmware TRAIN (``7.6``, ``8.0``…) because the form is a property of
the firmware: 8.0.6 renamed *Let's Encrypt* to *ACME* and added two fields to
the HTTP Content Routing rule (measured 2026-10-08, fortiweb17 vs fortiweb18).

Selection is honest about the match: :func:`select` returns the template of the
device's own train when there is one; otherwise the closest OLDER train, and
the page says so ("built from FortiWeb 7.6.8 — this device runs 8.0.6") so an
operator never mistakes an older form for the device's.

Conditions are evaluated **tri-state** (True / False / None = cannot tell):
a field whose condition depends on something SATOM cannot read about the device
is SHOWN and marked, never silently hidden — hiding on absent evidence would
take a field away from the operator because of a gap in what we measured.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "registry" / "gui_templates"
SCHEMA = "satom.gui-template/1"


def _train_key(train: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", train or "")[:2]) or (0, 0)


@lru_cache(maxsize=32)
def _load(path: str) -> dict:
    tpl = json.loads(Path(path).read_text(encoding="utf-8"))
    if tpl.get("schema") != SCHEMA:
        raise ValueError("%s: not a %s template" % (path, SCHEMA))
    return tpl


def available(product: str, page: str) -> list[dict]:
    """Every shipped template of a page, oldest train first."""
    d = ROOT / product / page
    out = []
    for p in sorted(d.glob("*.json"), key=lambda p: _train_key(p.stem)):
        tpl = _load(str(p))
        out.append({"train": tpl["applies_to"], "based_on": tpl["based_on"], "path": str(p)})
    return out


def select(product: str, page: str, fw_version: str | None):
    """(template, match) for a device firmware ``X.Y.Z``.

    match: ``exact`` (same train) · ``older`` (closest older train) ·
    ``newer`` (device older than every template) · ``unknown`` (no firmware
    known; newest template). ``(None, None)`` when the page has no template.
    """
    avail = available(product, page)
    if not avail:
        return None, None
    want = _train_key(fw_version or "")
    if not fw_version or want == (0, 0):
        return _load(avail[-1]["path"]), "unknown"
    same = [a for a in avail if _train_key(a["train"]) == want]
    if same:
        return _load(same[0]["path"]), "exact"
    older = [a for a in avail if _train_key(a["train"]) < want]
    if older:
        return _load(older[-1]["path"]), "older"
    return _load(avail[0]["path"]), "newer"


# --------------------------------------------------------------------------- #
# Device context: what the conditions ask about the device
# --------------------------------------------------------------------------- #
def device_context(*, opmode: str | None, visibility: dict | None,
                   firmware: str | None, model: str | None = None) -> dict:
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
    return {"opmode": opmode or None, "visibility": dict(visibility or {}),
            "platform": platform}


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


def _options(field: dict, dev: dict) -> list:
    if field.get("options"):
        return field["options"]
    by = field.get("options_by") or {}
    if not by:
        return []
    mode = (dev.get("opmode") or "").replace("-", "_")
    suffix = {"reverse_proxy": "inline", "offline_protection": "offline",
              "transparent": "tp", "transparent_inspection": "tp", "wccp": "wccp"}.get(mode)
    for name, opts in by.items():
        if suffix and name.endswith("_" + suffix):
            return opts
    plain = [o for n, o in by.items() if "_" not in n]
    return plain[0] if plain else next(iter(by.values()))


def _display(field: dict, row: dict, dev: dict):
    kind = field.get("kind")
    key = field.get("key")
    if kind == "toggle_rows":
        return [{"label": r["label"], "value": row.get(r["key"], "")} for r in field["rows"]]
    if key is None:
        return None
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


def dialog_view(tpl: dict, dialog_key: str, row: dict, dev: dict) -> dict:
    """Blocks -> fields with ``state`` shown / unknown (hidden ones are dropped
    from ``blocks`` but counted, so the page can say how many the GUI hides)."""
    d = tpl["dialogs"][dialog_key]
    defs = dict(d.get("contexts") or {})
    data = _with_derived(row, d)
    blocks, hidden = [], 0
    for b in d["blocks"]:
        bstate = evaluate(b.get("cond"), data, defs, dev)
        if bstate is not None and not _truthy(bstate):
            hidden += len(b["fields"])
            continue
        fields = []
        for f in b["fields"]:
            if f.get("kind") == "spacer":
                continue
            st = evaluate(f.get("cond"), data, defs, dev)
            if st is not None and not _truthy(st):
                hidden += 1
                continue
            unknown = bstate is None or st is None
            fields.append({
                "label": f.get("label") or "",
                "help": f.get("help") or "",
                "kind": f.get("kind"),
                "key": f.get("key"),
                "value": _display(f, data, dev),
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
                "edit_shortcut": bool(f.get("edit_shortcut")),
                "unknown": unknown,
                "unknown_why": (unknowns(b.get("cond"), data, defs, dev)
                                + unknowns(f.get("cond"), data, defs, dev)) if unknown else [],
            })
        if fields:
            # A fold is FortiWeb's +/- section title. Its initial state when the
            # GUI computes it (raw JS, e.g. "any ML policy set") is not
            # evaluated here: closed, one click away -- nothing is hidden.
            fold = b.get("fold")
            blocks.append({"title": b.get("title"), "fields": fields,
                           "unknown": bstate is None,
                           "fold": bool(fold),
                           "open": fold.get("open") is True if fold else True})
    return {"key": dialog_key, "title": d.get("title", {}), "blocks": blocks,
            "hidden": hidden}


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
