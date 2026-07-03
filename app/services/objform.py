"""Recursive object-editor engine — the web port of the desktop ``objform``.

A FortiWeb cmdb object is edited as **its own scalar fields** (grouped like the
GUI, via :mod:`fortiweb_field_schema`) **plus a list of by-parent SUB-TABLES**
(``pserver-list``, ``vip-list``, ``members``, ``content-routing-match-list`` …),
each a collection of rows that are themselves editable objects — so the editor
recurses N levels deep (pool → members; SNI → members; content-routing policy →
match conditions → ip-group → members …).

Two structural facts make this generic and drift-free:

* **Sub-tables are derived from the registry.** A collection ``U`` owns every
  registry urn shaped ``U/<segment>`` (slash = by-parent child; a ``.`` is a
  sub-TYPE, its own object). Verified live: ``server-pool/pserver-list``,
  ``vserver/vip-list``, ``health/health-list``, ``certificate.sni/members``,
  ``ip-group/members``, ``http-content-routing-policy/content-routing-match-list``.
  No hand-maintained sub-table map drifts out of date.

* **A sub-table is read SCOPED to its parent** with ``?mkey=<parent>`` — NEVER
  path-style, which (a documented FortiWeb quirk, ``server_policy.md`` §0) echoes
  the WHOLE parent collection when the row set is empty, so one pool's members
  would list every pool's. ``scoped_rows`` enforces this.

Pure structure only — no Flask, no device. The view supplies the live object and
the row reads (through :class:`FortiWebClient`); writes go through
:class:`fortiweb_ops.FortiWebOps` exactly like every other config mutation.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any

from . import waf_specs
from .fortiweb_field_schema import KIND_SPECS, build_groups

_PREFIX = "/api/v2.0/cmdb/"


# --------------------------------------------------------------------------- #
#  Path / collection normalisation                                             #
# --------------------------------------------------------------------------- #
def collection_of(urn_or_path: str) -> str:
    """The bare cmdb collection, e.g. ``server-policy/server-pool``.

    Accepts a full REST path (``/api/v2.0/cmdb/server-policy/server-pool``), a
    ``cmdb/...`` urn (as ``dependencies.py`` spells them), or an already-bare
    collection. Any ``?mkey=`` suffix is dropped.
    """
    s = (urn_or_path or "").strip().split("?")[0]
    for pre in (_PREFIX, "api/v2.0/cmdb/", "/cmdb/", "cmdb/"):
        i = s.find(pre)
        if i != -1:
            return s[i + len(pre):].strip("/")
    return s.strip("/")


def rest_path(urn_or_coll: str) -> str:
    """Full REST cmdb path for ``api_call`` from any of the accepted forms."""
    return _PREFIX + collection_of(urn_or_coll)


def scoped_path(sub_urn: str, parent_mkey: str, sub_mkey: str | None = None) -> str:
    """REST path for a by-parent sub-table, scoped with ``?mkey=<parent>``.

    Reading/writing a by-parent row ALWAYS carries the parent name as ``mkey``;
    an existing row additionally carries ``&sub_mkey=<id>``. This is the only
    correct way to read a sub-table (path-style leaks the parent collection).
    """
    from urllib.parse import quote

    path = "%s?mkey=%s" % (rest_path(sub_urn), quote(str(parent_mkey), safe=""))
    if sub_mkey not in (None, ""):
        path += "&sub_mkey=%s" % quote(str(sub_mkey), safe="")
    return path


# --------------------------------------------------------------------------- #
#  Sub-table derivation (registry-driven, drift-free)                          #
# --------------------------------------------------------------------------- #
# Friendly labels for the common sub-table segments (else humanised from seg).
_SUBTABLE_LABEL: dict[str, str] = {
    "pserver-list": "Real Servers", "vip-list": "Virtual IPs",
    "health-list": "Health Check Rules", "members": "Members",
    "host-list": "Protected Hostnames", "allow-list-items": "Allow List Items",
    "content-routing-match-list": "Match Conditions", "san-list": "SAN List",
    "list": "Entries", "filter-list": "Signature Exceptions",
    "ntpserver": "NTP Servers",
}


@lru_cache(maxsize=1)
def _child_index() -> dict[str, tuple[dict, ...]]:
    """``parent collection -> (by-parent sub-table dict, ...)`` from the registry.

    A registry urn ``parent/<seg>`` is a by-parent sub-table of ``parent`` only
    when ``parent`` is itself a registered object collection (so namespace
    prefixes like ``server-policy`` never masquerade as a parent object) and the
    edge is a SLASH (a ``.`` is a sub-type, its own top-level object).
    """
    from ..registry import loader

    endpoints = loader.get_all_endpoints()
    parents = {collection_of(ep.get("urn") or "") for ep in endpoints}
    idx: dict[str, list[dict]] = {}
    for ep in endpoints:
        coll = collection_of(ep.get("urn") or "")
        if "/" not in coll:
            continue
        parent, seg = coll.rsplit("/", 1)
        if parent not in parents:          # parent isn't a real object → skip
            continue
        idx.setdefault(parent, []).append({
            "key": ep.get("name"),
            "urn": ep.get("urn"),
            "collection": coll,
            "seg": seg,
            "label": subtable_label(ep.get("name"), seg, coll),
        })
    return {k: tuple(sorted(v, key=lambda c: c["label"].lower())) for k, v in idx.items()}


def subtable_label(key: str | None, seg: str, coll: str | None = None) -> str:
    # The desktop-validated WAF catalog carries the FortiWeb GUI title for its
    # sub-tables ("Signature Exceptions", "Rule List"…) — most specific first.
    if coll:
        t = waf_specs.subtable_titles().get(coll)
        if t:
            return t
    if seg in _SUBTABLE_LABEL:
        return _SUBTABLE_LABEL[seg]
    base = (seg or key or "").replace("-", " ").replace("_", " ").strip().title()
    return base or (key or seg)


def subtables_for(urn_or_coll: str) -> list[dict]:
    """The by-parent sub-tables an object owns (``[]`` if none)."""
    return list(_child_index().get(collection_of(urn_or_coll), ()))


@lru_cache(maxsize=1)
def known_collections() -> frozenset:
    """Every cmdb collection present in the registry (objects AND their by-parent
    sub-tables, since sub-tables are registry entries too). The security
    allow-list: the generic editor may only read/write a collection in this set,
    so it can never be pointed at an arbitrary REST path."""
    from ..registry import loader

    out = {collection_of(ep.get("urn") or "") for ep in loader.get_all_endpoints()}
    return frozenset(c for c in out if c)


def is_known_collection(urn_or_coll: str) -> bool:
    return collection_of(urn_or_coll) in known_collections()


# --------------------------------------------------------------------------- #
#  Field-schema kind (curated vocabulary per object)                           #
# --------------------------------------------------------------------------- #
# Map known collections to a ``fortiweb_field_schema`` KIND so the curated
# per-object enum/ref/toggle vocabulary is applied; everything else uses the
# generic ``ref`` path (auto-resolves widgets from the device values).
_KIND_BY_COLL: dict[str, str] = {
    "server-policy/policy": "policy",
    "server-policy/server-pool": "pool",
    "server-policy/server-pool/pserver-list": "pserver",
    "server-policy/vserver": "vserver",
    "server-policy/vserver/vip-list": "vip",
    "server-policy/http-content-routing-policy/content-routing-match-list": "crmatch",
}

# Merge the desktop-ported WAF catalog (165 curated kinds — the WPP, its ~40
# sub-policies, their named rules and every sub-table row) into the engine:
# KIND_SPECS gains the per-kind vocabularies, _KIND_BY_COLL the coll → kind map.
waf_specs.register(KIND_SPECS, _KIND_BY_COLL)


def object_kind(urn_or_coll: str) -> str:
    return _KIND_BY_COLL.get(collection_of(urn_or_coll), "ref")


def field_groups(urn_or_coll: str, obj: dict, keep_name: bool = False) -> list[dict]:
    """GUI-grouped editable field descriptors for *obj* at *urn*."""
    return build_groups(object_kind(urn_or_coll), obj or {}, keep_name=keep_name)


def row_label(row: dict) -> str:
    """Best display label for a sub-table row (name → id → blank)."""
    if not isinstance(row, dict):
        return str(row)
    return str(row.get("name") or row.get("id") or row.get("_id") or "")


# --------------------------------------------------------------------------- #
#  Form assembly (structure only — the view fills live rows)                   #
# --------------------------------------------------------------------------- #
def blank_row_sample(urn_or_coll: str, rows: list | None = None) -> dict:
    """A blank add-row template for a by-parent sub-table.

    Seeds EVERY curated key for the sub-table's kind so a curated sub-table (e.g.
    content-routing Match Conditions) renders a full add-row form even when the
    parent has ZERO existing rows — the generic union-of-existing-keys yields an
    empty form (and a dead "Create row" button) in that case. Unions in any keys
    seen in existing rows so an un-curated sub-table still works as before.
    """
    from .fortiweb_field_schema import kind_keys

    sample = {k: "" for k in kind_keys(object_kind(urn_or_coll))}
    for r in rows or []:
        if isinstance(r, dict):
            for k in r:
                sample.setdefault(k, "")
    return sample


def object_form(urn_or_coll: str, obj: dict) -> dict[str, Any]:
    """Structure for editing one object: its grouped fields + its sub-tables.

    ``subtables`` carries only the STRUCTURE (urn/label); the view fetches each
    sub-table's live rows with :func:`scoped_path` so the read is parent-scoped.
    """
    coll = collection_of(urn_or_coll)
    kind = object_kind(coll)
    return {
        "collection": coll,
        "rest_path": rest_path(coll),
        "kind": kind,
        "kind_label": KIND_SPECS.get(kind, {}).get("kind_label", ""),
        "help": waf_specs.section_help(kind),
        "groups": field_groups(coll, obj),
        "subtables": subtables_for(coll),
    }


__all__ = [
    "collection_of", "rest_path", "scoped_path", "subtables_for",
    "subtable_label", "object_kind", "field_groups", "row_label", "blank_row_sample", "object_form",
]
