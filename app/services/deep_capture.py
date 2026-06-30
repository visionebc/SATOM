"""Deep capture — walk a device's Server Policy + WPP dependency trees doing
reliable scoped reads, emitting an enriched snapshot where by-parent sub-tables
AND named-rule objects are NESTED inline under a synthetic ``_deep`` key. The
existing ``device_store`` decomposer then lands the whole tree into
``device_objects`` at depth (``parent_id``) with NO schema change.

Captures customization DELTAS only — it follows the dependency tree's ``via``
edges (named references) and by-parent sub-tables (members, rule-lists, disabled
signatures, exceptions). It never enumerates the predefined signature/catalog
universe.

Pure: talks to the box only through a duck-typed reader exposing
``get_raw(urn, mkey)`` (path-style list) and ``get_object(logical, mkey)`` (the
reliable registry ``?mkey=`` read) — exactly the Reader the clone engine uses
(``clone.ClientReader``). Top-level object types are listed once via
``get_raw(urn, "")`` (cached per sweep) and filtered by mkey in Python; by-parent
sub-tables go through ``clone.scoped_rows`` (the leak-proof scoped read).
"""
from __future__ import annotations

from typing import Any

from ..registry.dependencies import (DepNode, SERVER_POLICY,
                                      WEB_PROTECTION_PROFILE)
from . import clone

# A nested object/sub-table is carried under this synthetic key so the
# device_store decomposer can split each entry out as a child row.
DEEP_KEY = "_deep"

_MKEY_FIELDS = ("name", "mkey", "id")

# The offline WPP shares the inline tree shape.
_WPP_OFFLINE_URN = "cmdb/waf/web-protection-profile.offline-protection"


def _lg(urn: str) -> str | None:
    """Registry logical name for a urn (matched on the normalised collection),
    or None when the urn is not a registry endpoint."""
    return clone.registry_urn_index().get(
        __import__("app.services.objform", fromlist=["collection_of"]).collection_of(urn)
    )


def _deep_key(urn: str) -> str:
    """The key a nested child is stored under: its registry logical name when it
    has one (e.g. ``server_pool``), else the last urn segment (sub-tables like
    ``pserver-list``)."""
    return _lg(urn) or urn.rsplit("/", 1)[-1]


def _mkey_of(obj: dict) -> str:
    for k in _MKEY_FIELDS:
        v = obj.get(k)
        if v not in (None, ""):
            return str(v)
    return ""


def _collection(reader: Any, urn: str, cache: dict) -> list[dict]:
    """All rows of a top-level object type, listed once and cached for the sweep.
    Uses path-style ``get_raw(urn, "")`` — reliable for top-level types (the
    empty-sub-table leak only affects by-parent reads, handled via scoped_rows)."""
    if urn not in cache:
        try:
            rows = reader.get_raw(urn, "")
        except Exception:  # noqa: BLE001 — one bad read never sinks the walk
            rows = []
        cache[urn] = [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
    return cache[urn]


def _find(rows: list[dict], mkey: str) -> dict | None:
    for r in rows:
        if _mkey_of(r) == str(mkey):
            return r
    return None


def _named_subs(reader: Any, parent: dict, child: DepNode, seen: set, cache: dict):
    """Collect the object(s) ``parent`` references through ``child.via``. Returns
    a single dict for one ref, a list for several, or None for none."""
    collected = []
    for ref in clone.referenced_names(parent, child.via):
        sub = _collect_node(reader, clone._rich(child), ref, seen, cache)
        if sub is not None:
            collected.append(sub)
    if not collected:
        return None
    return collected[0] if len(collected) == 1 else collected


def _collect_node(reader: Any, node: DepNode, mkey: str, seen: set,
                  cache: dict) -> dict | None:
    """Read object ``mkey`` for ``node`` and recurse its named-ref children +
    by-parent sub-tables, nesting everything under DEEP_KEY (deepest-first via
    the visited set, mirroring clone.ClonePlanner._visit)."""
    if not mkey or (node.urn, mkey) in seen:
        return None
    seen.add((node.urn, mkey))
    obj = _find(_collection(reader, node.urn, cache), mkey)
    if obj is None:
        return None

    deep: dict = {}

    # 1) named references (the dependency edges): a separate object named by a field
    for child in node.children:
        if clone._is_named_ref(child):
            sub = _named_subs(reader, obj, child, seen, cache)
            if sub is not None:
                deep[_deep_key(child.urn)] = sub

    # 2) by-parent sub-tables (members, rule-lists, disabled sigs, exceptions),
    #    each row may itself name deeper objects (the grandchildren).
    for child in node.children:
        if clone._is_named_ref(child) or not child.urn:
            continue
        rows = clone.scoped_rows(reader, child.urn, _lg(child.urn), mkey) or []
        out_rows: list[dict] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            row_deep: dict = {}
            for g in child.children:
                if clone._is_named_ref(g):
                    sub = _named_subs(reader, row, g, seen, cache)
                    if sub is not None:
                        row_deep[_deep_key(g.urn)] = sub
            out_rows.append({**row, DEEP_KEY: row_deep} if row_deep else row)
        if out_rows:
            deep[child.urn.rsplit("/", 1)[-1]] = out_rows

    return {**obj, DEEP_KEY: deep} if deep else obj


def collect_server_policy(reader: Any, mkey: str) -> dict | None:
    """Full dependency graph for one server policy, nested under DEEP_KEY."""
    return _collect_node(reader, SERVER_POLICY, mkey, set(), {})


def collect_wpp(reader: Any, mkey: str) -> dict | None:
    """Full subtree for one Web Protection Profile, nested under DEEP_KEY."""
    return _collect_node(reader, WEB_PROTECTION_PROFILE, mkey, set(), {})


import dataclasses as _dc

# Offline WPPs share the inline tree's children but live under their own urn.
_WPP_OFFLINE_NODE = _dc.replace(WEB_PROTECTION_PROFILE, urn=_WPP_OFFLINE_URN)


def _list_names(reader: Any, urn: str, cache: dict) -> list[str]:
    return [m for m in (_mkey_of(r) for r in _collection(reader, urn, cache)) if m]


def deep_sections(reader: Any) -> dict:
    """Walk every server policy + every WPP (inline + offline), returning the
    enriched ``{section: {logical_name: [obj-with-_deep, ...]}}`` snapshot shape
    that ``device_store.ingest_sections`` consumes. A single shared collection
    cache keeps the sweep box-gentle (each top-level object type is listed once);
    each object gets its OWN visited set so an object shared by two policies is
    captured in full under each."""
    cache: dict = {}

    policies: list[dict] = []
    for nm in _list_names(reader, SERVER_POLICY.urn, cache):
        g = _collect_node(reader, SERVER_POLICY, nm, set(), cache)
        if g:
            policies.append(g)

    wpps: list[dict] = []
    for nm in _list_names(reader, WEB_PROTECTION_PROFILE.urn, cache):
        w = _collect_node(reader, WEB_PROTECTION_PROFILE, nm, set(), cache)
        if w:
            wpps.append(w)
    for nm in _list_names(reader, _WPP_OFFLINE_URN, cache):
        w = _collect_node(reader, _WPP_OFFLINE_NODE, nm, set(), cache)
        if w:
            wpps.append(w)

    return {
        "Server Policy": {"server_policy": policies},
        "Web Protection": {"web_protection_profile": wpps},
    }
