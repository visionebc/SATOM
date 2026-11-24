"""Detect live per-signature exceptions off a FortiWeb and bind each to its
Server Policy — the "detect on device" path.

A per-signature exception (FortiWeb: *Signature Details → <id> → Exception*) is a
row of the signature SET's ``filter_list`` (``cmdb/waf/signature/filter_list``).
The set is SHARED — a WPP ``signature-rule`` bound to one or more Server Policies
— so the box can't say which policy needed a carve-out. The walk
``server policy → WPP → signature set → filter_list`` re-creates that missing
binding, attributing every row to the policy whose WPP names the set.

Reads go through a duck-typed reader (``get_object`` / ``get_rows``) so the walk
is pure + headless-testable; :class:`ClientReader` adapts a ``FortiWebClient``
(its sub-table reads are parent-scoped — with the error-envelope fix, an empty
``filter_list`` now correctly yields no rows instead of leaking the parent set).
Mirrors the desktop ``exception_detect``.
"""
from __future__ import annotations

import json
from urllib.parse import quote

from . import objform

WPP_COLL = "waf/web-protection-profile.inline-protection"
SIGNATURE_SET_FIELD = "signature-rule"
FILTER_LIST_COLL = "waf/signature/filter_list"

_NOISE_PREFIXES = ("q_", "_")
_NOISE_KEYS = {"id", "can_view", "can_clone", "is_default", "flag", "seq"}


def _clean_row(row: dict) -> dict:
    """Drop server-managed/noise keys, keeping the authored carve-out fields."""
    return {k: v for k, v in row.items()
            if k not in _NOISE_KEYS and not any(k.startswith(p) for p in _NOISE_PREFIXES)}


# --------------------------------------------------------------------------- #
#  Reader adapter over FortiWebClient                                          #
# --------------------------------------------------------------------------- #
class ClientReader:
    def __init__(self, client):
        self.c = client

    def get_object(self, coll: str, mkey: str) -> dict:
        if not mkey:
            return {}
        path = "%s?mkey=%s" % (objform.rest_path(coll), quote(str(mkey), safe=""))
        return self.c._safe_one(path) or {}

    def get_rows(self, sub_coll: str, parent: str) -> list:
        if not parent:
            return []
        return self.c._safe_list(objform.scoped_path(sub_coll, parent)) or []


# --------------------------------------------------------------------------- #
#  Detect (pure walk over the duck-typed reader)                              #
# --------------------------------------------------------------------------- #
def detect_signature_exceptions(reader, bindings: dict[str, str]) -> list[dict]:
    """Walk ``policy → WPP → signature set → filter_list`` for each live binding.

    *bindings* = ``{server_policy: wpp_name}``. Returns one record per
    ``(policy, filter-list row)`` — a shared set is read only once and its rows
    attributed to every policy that binds it.
    """
    out: list[dict] = []
    set_cache: dict[str, list] = {}
    for policy, wpp in (bindings or {}).items():
        wpp = (wpp or "").strip()
        if not wpp:
            continue
        profile = reader.get_object(WPP_COLL, wpp) or {}
        sig_set = (profile.get(SIGNATURE_SET_FIELD) or "").strip()
        if not sig_set:
            continue
        if sig_set not in set_cache:
            set_cache[sig_set] = reader.get_rows(FILTER_LIST_COLL, sig_set) or []
        for row in set_cache[sig_set]:
            if not isinstance(row, dict):
                continue
            payload = _clean_row(row)
            out.append({
                "policy": policy,
                "wpp": wpp,
                "signature_set": sig_set,
                "signature_id": str(row.get("signature_id") or row.get("name") or "").strip(),
                "row_id": row.get("id"),
                "payload": payload,
            })
    return out


# --------------------------------------------------------------------------- #
#  Import detected → desired-state (dedup by content)                          #
# --------------------------------------------------------------------------- #
def content_key(d: dict) -> tuple:
    """Stable identity of a detected carve-out for idempotent re-import."""
    return (
        d.get("wpp", ""), d.get("signature_set", ""), d.get("signature_id", ""),
        json.dumps(d.get("payload") or {}, sort_keys=True), d.get("policy", ""),
    )


def import_detected_signature_exceptions(detected, *, add, existing_keys=()) -> int:
    """Persist chosen detected carve-outs via *add* (the store ``add`` callable),
    de-duplicated by :func:`content_key`. Returns how many were written."""
    seen = set(existing_keys)
    written = 0
    for d in detected:
        key = content_key(d)
        if key in seen:
            continue
        seen.add(key)
        add(
            wpp_mkey=d.get("wpp", ""),
            exc_type="signature_filter_item",
            payload=d.get("payload") or {},
            policies=[d["policy"]] if d.get("policy") else [],
            category="signature",
            reason="detected on device",
        )
        written += 1
    return written


__all__ = [
    "ClientReader", "detect_signature_exceptions",
    "import_detected_signature_exceptions", "content_key",
    "WPP_COLL", "FILTER_LIST_COLL", "SIGNATURE_SET_FIELD",
]
