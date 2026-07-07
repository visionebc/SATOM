"""FortiADC object-editor engine — the ADC counterpart of :mod:`objform`.

Same logic as the FortiWeb editor, adapted to FortiADC's REST conventions:

* **Identity is ``mkey``** (FortiWeb uses ``name``). It renders read-only in the
  header on edit, editable on create — exactly like ``name`` on FortiWeb.
* **Child tables are derived from the registry.** FortiADC exposes a child
  table as its own endpoint named ``<parent>_child_<segment>`` (terraform-SDK
  convention, live-verified on fadc 8.0.3:
  ``system_certificate_local_cert_group_child_group_member?pkey=<group>``).
  So a parent logical owns every registry logical shaped ``<parent>_child_*``
  — no hand-maintained sub-table map to drift, same contract as objform's
  slash-derived index.
* **Widgets are inferred from device truth** (there is no curated ADC field
  catalog yet): ``enable``/``disable`` → toggle, numeric → number, everything
  else → text. A list/dict value (inline arrays like a cert's ``extension``)
  is NOT form-editable — it renders read-only with the raw-JSON editor as the
  escape hatch, so nothing is ever silently dropped from a save.
* **Noise filter**: ``_``-prefixed keys (``_nondeletable``/``_noneditable``…)
  are device-internal flags, never editable.

Pure structure only — no Flask, no device. The view supplies the live object
and child rows through :class:`FortiADCClient`; writes go through the audited
ADC save endpoints (dry-run preview default, like every FortiWeb write path).
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any

_TOGGLE_VALS = {"enable", "disable"}


# --------------------------------------------------------------------------- #
#  Registry allow-list + child-table derivation                                #
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def known_logicals() -> frozenset:
    """Every fortiadc registry logical (objects AND child tables) — the
    security allow-list: the editor may only touch a logical in this set."""
    from ..registry import loader
    return frozenset(loader.load_adc_registry())


def is_known(logical: str) -> bool:
    return (logical or "").strip() in known_logicals()


@lru_cache(maxsize=1)
def _child_index() -> dict[str, tuple[dict, ...]]:
    """``parent logical -> (child-table descriptor, ...)`` from the registry.

    A logical ``P_child_S`` is a child table of ``P`` only when ``P`` is itself
    a registered logical (so a phantom prefix never masquerades as a parent).
    """
    reg = known_logicals()
    idx: dict[str, list[dict]] = {}
    for logical in reg:
        if "_child_" not in logical:
            continue
        parent, seg = logical.split("_child_", 1)
        if parent not in reg:
            continue
        idx.setdefault(parent, []).append({
            "logical": logical,
            "seg": seg,
            "label": _seg_label(seg),
        })
    return {k: tuple(sorted(v, key=lambda c: c["label"].lower()))
            for k, v in idx.items()}


_SEG_LABEL = {
    "pool_member": "Pool Members",
    "group_member": "Group Members",
    "match_condition": "Match Conditions",
    "neighbor": "BGP Neighbors",
    "rule": "Rules",
}


def _seg_label(seg: str) -> str:
    if seg in _SEG_LABEL:
        return _SEG_LABEL[seg]
    return (seg or "").replace("_", " ").strip().title() or seg


def subtables_for(logical: str) -> list[dict]:
    """The child tables an object owns (``[]`` if none)."""
    return list(_child_index().get((logical or "").strip(), ()))


def invalidate() -> None:
    """Drop the cached registry views (after a registry edit)."""
    known_logicals.cache_clear()
    _child_index.cache_clear()


# --------------------------------------------------------------------------- #
#  Field descriptors (widget inference from device values)                     #
# --------------------------------------------------------------------------- #
def is_noise(key: str) -> bool:
    """Device-internal keys that must never render as editable fields."""
    return not key or key.startswith("_")


def _prettify(key: str) -> str:
    return key.replace("_", " ").replace("-", " ").strip().title()


def descriptor(key: str, value) -> dict:
    """Resolve one device key into a form-field descriptor (the same shape the
    ``fld`` macro renders for FortiWeb, so the two editors share the UI)."""
    sval = str(value).strip().lower() if not isinstance(value, (list, dict)) else ""
    if isinstance(value, (list, dict)):
        widget = "complex"           # inline array/object → raw-JSON territory
    elif sval in _TOGGLE_VALS or isinstance(value, bool):
        widget = "toggle"
    elif isinstance(value, int) or (sval and sval.lstrip("-").isdigit()):
        widget = "number"
    else:
        widget = "text"
    d = {
        "key": key, "label": _prettify(key), "group": "Settings",
        "widget": widget, "value": "" if value is None else value,
        "options": [],
    }
    if widget == "toggle":
        d["on"] = (sval == "enable") or value is True
        d["value"] = "enable" if d["on"] else "disable"
    if widget == "complex":
        import json
        d["value"] = json.dumps(value, ensure_ascii=False)
    return d


def field_groups(obj: dict, keep_mkey: bool = False) -> list[dict]:
    """All editable fields of an ADC object, as one ordered group.

    ``keep_mkey`` keeps ``mkey`` as an editable attribute — correct for a child
    ROW create form (the row's mkey may be a real field), wrong for a top-level
    object whose mkey is the read-only identity shown in the header.
    """
    fields, complex_fields = [], []
    for key in sorted(obj or {}):
        if is_noise(key) or (key == "mkey" and not keep_mkey):
            continue
        d = descriptor(key, obj[key])
        (complex_fields if d["widget"] == "complex" else fields).append(d)
    out = []
    if fields:
        out.append({"title": "Settings", "fields": fields})
    if complex_fields:
        out.append({"title": "Structured values (read-only — edit via Raw JSON)",
                    "fields": complex_fields})
    return out


def row_label(row: dict) -> str:
    if not isinstance(row, dict):
        return str(row)
    return str(row.get("mkey") or row.get("name") or row.get("id") or "")


def blank_row_sample(rows: list | None = None) -> dict:
    """A blank add-row template: union of scalar keys across existing rows."""
    sample: dict = {}
    for r in rows or []:
        if isinstance(r, dict):
            for k, v in r.items():
                if not is_noise(k) and not isinstance(v, (list, dict)):
                    sample.setdefault(k, "")
    return sample


def object_form(logical: str, obj: dict) -> dict[str, Any]:
    """Structure for editing one ADC object: grouped fields + child tables."""
    return {
        "logical": logical,
        "groups": field_groups(obj),
        "subtables": subtables_for(logical),
    }


__all__ = [
    "known_logicals", "is_known", "subtables_for", "invalidate", "is_noise",
    "descriptor", "field_groups", "row_label", "blank_row_sample", "object_form",
]
