"""Field-schema catalog for guided provisioning.

Schemas live on disk under ``data/field_schemas/<product>/<line>/<object>.json``
(object file-name == the provisioning catalog *key*). They declare each config
object's fields (type, label, required, default, help, group, options) so the
provisioning UI can render typed inputs instead of raw JSON. Resolution falls
back to ``<product>/_default/<object>.json`` so a new firmware line only needs
schemas where it diverges. Pure + filesystem-only — no device contact, no app
context required (safe to unit-test and to call from a request).
"""
from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field as dc_field
from typing import Any

# data/field_schemas (repo_root/data/field_schemas); this file is app/services/…
SCHEMA_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "field_schemas")
)

_FIELD_TYPES = {"text", "number", "bool", "select", "password", "ip", "csv", "json"}


@dataclass
class FieldSpec:
    name: str
    label: str = ""
    type: str = "text"
    required: bool = False
    default: Any = ""
    help: str = ""
    group: str = "Basic"
    options: list = dc_field(default_factory=list)     # select: [{"value","label"}]
    true_value: Any = "enable"                          # bool on
    false_value: Any = "disable"                         # bool off

    @classmethod
    def from_dict(cls, d: dict) -> "FieldSpec":
        t = (d.get("type") or "text").strip()
        return cls(
            name=d["name"], label=d.get("label") or d["name"],
            type=t if t in _FIELD_TYPES else "text",
            required=bool(d.get("required", False)), default=d.get("default", ""),
            help=d.get("help", ""), group=d.get("group", "Basic"),
            options=list(d.get("options") or []),
            true_value=d.get("true_value", "enable"),
            false_value=d.get("false_value", "disable"),
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name, "label": self.label, "type": self.type,
            "required": self.required, "default": self.default, "help": self.help,
            "group": self.group, "options": self.options,
            "true_value": self.true_value, "false_value": self.false_value,
        }


@dataclass
class ObjectSchema:
    object: str
    endpoint: str
    label: str
    product: str
    line: str
    singleton: bool = False
    fields: list = dc_field(default_factory=list)       # list[FieldSpec]
    readonly: list = dc_field(default_factory=list)
    source: str = ""

    def field(self, name: str) -> "FieldSpec | None":
        for f in self.fields:
            if f.name == name:
                return f
        return None

    @classmethod
    def from_dict(cls, d: dict) -> "ObjectSchema":
        return cls(
            object=d["object"], endpoint=d.get("endpoint", d["object"]),
            label=d.get("label", d["object"]), product=d.get("product", "fortiweb"),
            line=d.get("line", "_default"), singleton=bool(d.get("singleton", False)),
            fields=[FieldSpec.from_dict(f) for f in d.get("fields", [])],
            readonly=list(d.get("readonly") or []), source=d.get("source", ""),
        )

    def to_dict(self) -> dict:
        return {
            "object": self.object, "endpoint": self.endpoint, "label": self.label,
            "product": self.product, "line": self.line, "singleton": self.singleton,
            "readonly": self.readonly, "source": self.source,
            "fields": [f.to_dict() for f in self.fields],
        }


def _read(path: str) -> "ObjectSchema | None":
    try:
        with open(path) as fh:
            return ObjectSchema.from_dict(json.load(fh))
    except (FileNotFoundError, ValueError, KeyError):
        return None


def load_object_schema(product: str, line: str, obj: str) -> "ObjectSchema | None":
    """Resolve a schema: line-specific first, then the product ``_default``."""
    for lin in (line, "_default"):
        s = _read(os.path.join(SCHEMA_ROOT, product, lin, f"{obj}.json"))
        if s is not None:
            return s
    return None


def available_lines(product: str = "fortiweb") -> list:
    """Firmware lines that have a schema folder (``_default`` excluded), newest first."""
    base = os.path.join(SCHEMA_ROOT, product)
    if not os.path.isdir(base):
        return []
    lines = [d for d in os.listdir(base)
             if d != "_default" and os.path.isdir(os.path.join(base, d))]
    return sorted(lines, reverse=True)


def schemas_for_line(product: str, line: str, objects: list) -> dict:
    """``{object_key: schema.to_dict() | None}`` for embedding in a page."""
    out: dict = {}
    for obj in objects:
        s = load_object_schema(product, line, obj)
        out[obj] = s.to_dict() if s else None
    return out


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def coerce(schema: "ObjectSchema", raw: dict) -> dict:
    """Build a payload dict from raw form values, typed + validated.

    Only fields the operator actually set are included (partial update); empty
    optional fields are dropped. ``bool`` follows checkbox semantics: a key
    present in ``raw`` => ``true_value`` else ``false_value``. Raises
    ``ValueError`` (with the field label) on a missing required value or a bad
    type so the view can flash + re-render. Read-only fields are never emitted.
    """
    out: dict = {}
    readonly = set(schema.readonly)
    for fs in schema.fields:
        if fs.name in readonly:
            continue
        if fs.type == "bool":
            present = fs.name in raw and str(raw.get(fs.name)).lower() not in ("", "0", "off", "false")
            out[fs.name] = fs.true_value if present else fs.false_value
            continue
        val = raw.get(fs.name, None)
        sval = "" if val is None else str(val).strip()
        if sval == "":
            if fs.required:
                raise ValueError(f"{fs.label} is required")
            continue
        if fs.type == "number":
            try:
                out[fs.name] = int(sval) if sval.lstrip("-").isdigit() else float(sval)
            except ValueError as exc:
                raise ValueError(f"{fs.label}: not a number ({sval!r})") from exc
        elif fs.type == "ip":
            if not _is_ip(sval):
                raise ValueError(f"{fs.label}: not a valid IP address ({sval!r})")
            out[fs.name] = sval
        elif fs.type == "csv":
            out[fs.name] = [p.strip() for p in sval.split(",") if p.strip()]
        elif fs.type == "json":
            try:
                out[fs.name] = json.loads(sval)
            except ValueError as exc:
                raise ValueError(f"{fs.label}: invalid JSON ({exc})") from exc
        else:  # text | select | password
            out[fs.name] = sval
    return out


def infer_type(value: Any) -> str:
    """Best-effort field type from a live JSON value (used by the harvester)."""
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        v = value.strip()
        if v.lower() in ("enable", "disable", "enabled", "disabled"):
            return "bool"
        if _is_ip(v):
            return "ip"
    return "text"
