"""Fleet-wide inventory of authored carve-outs: what exists, and WHO HAS IT.

The page ``/exceptions/<device>`` answers "what has this box been given". This
module answers the question that had no home in the product: *this carve-out —
which appliances carry it, and which do not?* Until :mod:`models_exceptions`
gave a placement an identity, that question was not merely unanswered, it was
unrepresentable: the same carve-out on two FortiWebs was two unrelated rows.

**Two placements are "the same carve-out" when they agree on CONTENT**, and the
content is ``exc_type`` + payload — deliberately NOT the profile or the server
policies. A carve-out for signature 010000001 on ``wpp-shop`` and the same one
on ``wpp-blog`` is one intent placed twice; folding the profile into the
identity would make every placement unique and the whole page would report a
fleet of singletons.

An explicit ``library_uid`` WINS over the content fingerprint. Two operators
can author byte-identical carve-outs for unrelated reasons, and a library link
is somebody stating they are the same thing; a fingerprint is this module
inferring it. Where both exist, the statement is the better answer — and the
inference is still what keeps the pre-library rows groupable at all.

**Device-free.** Like every other ``/waf/*`` page, opening this contacts no
appliance: carve-outs are desired state authored HERE, so the manager DB is
their source of truth and there is nothing to harvest. The consequence is
stated on the page rather than hidden: SATOM knows what was *authored*, not
what is *on the box*, and the two are the same only where somebody pushed.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ..models import WppException, db
from ..models_exceptions import ExceptionVersion
from . import waf_fleet, wpp_exceptions as catalog

#: A placement whose appliance no longer exists. Not dropped: a page that
#: quietly omits orphans answers a narrower question than the one it is
#: labelled with (the /waf banner rule, applied to rows instead of devices).
ORPHAN_SCOPE = "(appliance removed)"


def fingerprint(exc_type: str, payload: dict) -> str:
    """Content identity of a carve-out, independent of where it is placed.

    ``sort_keys`` for the same reason :func:`models_exceptions.sha_of` needs it:
    without it two identical payloads built in a different order fingerprint
    differently, and the fleet view reports one intent as two.
    """
    raw = json.dumps({"t": catalog.canonical_type(exc_type),
                      "p": payload or {}},
                     sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def group_key(exc) -> tuple[str, str]:
    """``(kind, key)`` — ``('library', uid)`` or ``('content', sha)``.

    The kind travels with the key so the page can say WHY two placements were
    grouped. Rendering both as an opaque id would leave an operator unable to
    tell a declared relationship from an inferred one, and only one of those is
    safe to act on.
    """
    uid = (getattr(exc, "library_uid", "") or "").strip()
    if uid:
        return ("library", uid)
    return ("content", fingerprint(exc.exc_type, exc.payload_dict))


def scopes(user=None) -> list:
    """Every FortiWeb (device, ADOM) scope this session may see.

    Delegates to :mod:`waf_fleet` so this page's denominator and the other five
    ``/waf`` pages' denominator have ONE author.
    """
    return waf_fleet.fortiweb_scopes(user)


def collect(user=None) -> dict[str, Any]:
    """The whole fleet inventory, in one pass over the store.

    Returns ``{scopes, groups, rows, orphans, stats}``. ``scopes`` is the
    DENOMINATOR — a scope with zero carve-outs is carried, because "nobody
    authored anything here" and "this box is not in the list" look identical
    once the empty rows are dropped, and they mean opposite things.
    """
    appliances = scopes(user)
    by_id = {a.id: a for a in appliances}
    scope_rows = []
    for appl in appliances:
        scope_rows.append({
            "id": appl.id,
            "scope": waf_fleet.scope_label(appl),
            "device": waf_fleet.device_name(appl),
            "adom": (getattr(appl, "vdom", "") or "").strip(),
            "count": 0, "stale": 0, "disabled": 0,
        })
    scope_by_id = {s["id"]: s for s in scope_rows}

    placements = []
    if by_id:
        placements = (WppException.query
                      .filter(WppException.appliance_id.in_(list(by_id)))
                      .order_by(WppException.id)
                      .all())

    # Orphans are queried SEPARATELY and never folded into the scope tally:
    # counting a carve-out whose appliance is gone against a live scope would
    # inflate exactly the box somebody is about to trust.
    orphan_rows: list[dict] = []
    for exc in WppException.query.order_by(WppException.id).all():
        if exc.appliance_id in by_id:
            continue
        if _appliance_still_exists(exc):
            # Out of THIS console's scope, not orphaned. Reporting the second
            # as the first puts a fabricated data-loss warning on a healthy
            # install — a FortiADC session sees no FortiWeb at all.
            continue
        orphan_rows.append(_row(exc, ORPHAN_SCOPE))

    groups: dict[tuple[str, str], dict] = {}
    rows: list[dict] = []
    for exc in placements:
        appl = by_id[exc.appliance_id]
        label = waf_fleet.scope_label(appl)
        row = _row(exc, label)
        rows.append(row)
        s = scope_by_id[exc.appliance_id]
        s["count"] += 1
        s["stale"] += 1 if exc.stale else 0
        s["disabled"] += 0 if exc.enabled else 1

        kind, key = group_key(exc)
        g = groups.setdefault((kind, key), {
            "kind": kind, "key": key, "short": key[:12],
            "exc_type": catalog.canonical_type(exc.exc_type),
            "type_label": _type_label(exc.exc_type),
            "category": exc.category or catalog.category_for(exc.exc_type),
            "name": exc.name or "",
            "payload": exc.payload_dict,
            "placements": [], "scopes": [], "profiles": [], "policies": [],
            "authors": [], "stale": 0, "disabled": 0, "versioned": 0,
        })
        g["placements"].append(row)
        if label not in g["scopes"]:
            g["scopes"].append(label)
        if exc.wpp_mkey and exc.wpp_mkey not in g["profiles"]:
            g["profiles"].append(exc.wpp_mkey)
        for p in exc.policy_names:
            if p not in g["policies"]:
                g["policies"].append(p)
        if exc.author and exc.author not in g["authors"]:
            g["authors"].append(exc.author)
        g["stale"] += 1 if exc.stale else 0
        g["disabled"] += 0 if exc.enabled else 1
        g["versioned"] += 1 if exc.lineage else 0
        # A group's display name is the first non-empty one any placement
        # carries. An unnamed carve-out is common and a group labelled "" is
        # unusable in a picker.
        if not g["name"] and exc.name:
            g["name"] = exc.name

    out_groups = []
    total_scopes = len(scope_rows)
    for g in groups.values():
        held = len(g["scopes"])
        g["held_by"] = held
        g["missing_from"] = max(0, total_scopes - held)
        # "everywhere" is a claim about the DENOMINATOR, so it is computed from
        # the visible scope list rather than from a count of placements: two
        # placements on the SAME box are not two boxes.
        g["everywhere"] = bool(total_scopes) and held == total_scopes
        g["unique"] = held == 1
        out_groups.append(g)
    out_groups.sort(key=lambda g: (-g["held_by"], g["type_label"], g["name"]))

    return {
        "scopes": scope_rows,
        "groups": out_groups,
        "rows": rows,
        "orphans": orphan_rows,
        "stats": stats(scope_rows, out_groups, rows, orphan_rows),
    }


def _appliance_still_exists(exc) -> bool:
    """Does the appliance this placement names still exist AT ALL?

    Orphan means "its appliance is gone", not "this console cannot see it".
    The two look identical from inside a product console and mean opposite
    things — one is data loss, the other is scoping working as designed.
    """
    if exc.appliance_id is None:
        return False
    from ..models import Appliance
    return db.session.get(Appliance, exc.appliance_id) is not None


def _type_label(exc_type: str) -> str:
    t = catalog.type_for(exc_type)
    return t["label"] if t else (exc_type or "(unknown type)")


def _row(exc, scope_label: str) -> dict:
    return {
        "id": exc.id,
        "appliance_id": exc.appliance_id,
        "scope": scope_label,
        "name": exc.name or "",
        "exc_type": catalog.canonical_type(exc.exc_type),
        "raw_type": exc.exc_type or "",
        "type_label": _type_label(exc.exc_type),
        "category": exc.category or catalog.category_for(exc.exc_type),
        "wpp_mkey": exc.wpp_mkey or "",
        "policies": exc.policy_names,
        "policy_count": len(exc.policy_names),
        "enabled": bool(exc.enabled),
        "stale": bool(exc.stale),
        "stale_reason": exc.stale_reason or "",
        "author": exc.author or "",
        "reason": exc.reason or "",
        "payload": exc.payload_dict,
        "lineage": exc.lineage or "",
        "library_uid": exc.library_uid or "",
        "versioned": bool(exc.lineage),
        "created_at": exc.created_at.isoformat(timespec="seconds")
                      if exc.created_at else "",
        "updated_at": exc.updated_at.isoformat(timespec="seconds")
                      if exc.updated_at else "",
    }


def stats(scope_rows, groups, rows, orphans) -> dict[str, Any]:
    """Fleet tallies. Every denominator here is the VISIBLE scope list."""
    by_type: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for r in rows:
        by_type[r["type_label"]] = by_type.get(r["type_label"], 0) + 1
        by_category[r["category"]] = by_category.get(r["category"], 0) + 1

    spread: dict[str, int] = {}
    for g in groups:
        bucket = ("everywhere" if g["everywhere"]
                  else "one scope" if g["unique"] else "some scopes")
        spread[bucket] = spread.get(bucket, 0) + 1

    return {
        "scopes": len(scope_rows),
        "scopes_with_any": sum(1 for s in scope_rows if s["count"]),
        # NOT a redundancy with the line above: a scope with zero carve-outs is
        # the normal state of a freshly-added box, and reading "0 of 7" as a
        # fault is the mistake the number exists to prevent.
        "placements": len(rows),
        "distinct": len(groups),
        "shared": sum(1 for g in groups if g["held_by"] > 1),
        "unique": sum(1 for g in groups if g["unique"]),
        "everywhere": sum(1 for g in groups if g["everywhere"]),
        "stale": sum(1 for r in rows if r["stale"]),
        "disabled": sum(1 for r in rows if not r["enabled"]),
        # A placement with no lineage predates the versioner and CANNOT be
        # rolled back. Printed as its own figure because "13 carve-outs, 0
        # recoverable" is the fact an operator needs before trusting the undo.
        "unversioned": sum(1 for r in rows if not r["versioned"]),
        "orphans": len(orphans),
        "by_type": by_type,
        "by_category": by_category,
        "spread": spread,
        "versions": ExceptionVersion.query.count(),
    }


def filter_rows(rows: list[dict], *, exc_type: str = "", category: str = "",
                scope: str = "", state: str = "", q: str = "") -> list[dict]:
    """Server-side row filter. The page never ships a hidden superset.

    A client-side overlay would make the CSV export and the visible table
    disagree about what "filtered" means, which is the drift a filter is
    supposed to prevent.
    """
    out = rows
    if exc_type:
        out = [r for r in out if r["exc_type"] == exc_type]
    if category:
        out = [r for r in out if r["category"] == category]
    if scope:
        out = [r for r in out if r["scope"] == scope]
    if state == "stale":
        out = [r for r in out if r["stale"]]
    elif state == "disabled":
        out = [r for r in out if not r["enabled"]]
    elif state == "unversioned":
        out = [r for r in out if not r["versioned"]]
    elif state == "active":
        out = [r for r in out if r["enabled"] and not r["stale"]]
    if q:
        needle = q.strip().lower()
        out = [r for r in out
               if needle in (r["name"] or "").lower()
               or needle in (r["wpp_mkey"] or "").lower()
               or needle in " ".join(r["policies"]).lower()
               or needle in json.dumps(r["payload"]).lower()]
    return out


def type_choices(rows: list[dict]) -> list[tuple[str, str]]:
    """``(key, label)`` for the types actually PRESENT.

    Offering the whole catalog would let an operator pick a filter that can
    only ever return nothing — and an empty table under a valid-looking filter
    reads as data loss.
    """
    seen: dict[str, str] = {}
    for r in rows:
        seen.setdefault(r["exc_type"], r["type_label"])
    return sorted(seen.items(), key=lambda kv: kv[1])


def scope_choices(rows: list[dict]) -> list[str]:
    return sorted({r["scope"] for r in rows})


__all__ = [
    "ORPHAN_SCOPE", "fingerprint", "group_key", "scopes", "collect", "stats",
    "filter_rows", "type_choices", "scope_choices",
]
