"""Fleet-wide ARTIFACTS — the file-backed WAF objects, across every scope.

WHY THIS PAGE HAS TO EXIST SOMEWHERE ELSE THAN ``/artifacts/*``
--------------------------------------------------------------
``/artifacts/*`` is pinned to the (device, ADOM) the operator is standing on —
deliberately, and enforced by six guards (safeguards §121–§123). That was the
right call for the page an operator opens while working on ONE box, and it left
the fleet question with no home at all: *which artifacts does this estate need,
which of them does SATOM actually hold, and which policies could therefore not
be migrated today.* This module answers exactly that, for every FortiWeb the
console may see.

WHERE THE NUMBERS COME FROM, AND WHAT THAT COSTS
------------------------------------------------
Two indexes, no appliance:

* **demand** — ``WafArtifactRef`` / ``WafArtifactScan``: what the artifact sweep
  found each server policy referencing. Assembled by
  :func:`services.artifact_stats.fleet_stats`, which is fed the SAME appliance
  rows and the SAME preloaded tables this module reads, so the per-scope
  breakdown here and the ``/artifacts`` pages cannot disagree about a verdict.
* **supply** — ``WafArtifact``: the versions SATOM keeps, including the
  library-wide bucket that belongs to no device.

Rendering contacts NO device, like the rest of ``/waf/*``. The cost is that a
server policy created since the last sweep is in NO figure on this page — which
is why the sweep's own blind spot is a NUMBER here (``unwalked``) and not a
sentence at the bottom. The configuration snapshot knows how many server
policies each scope really has; the sweep knows how many it walked. The
difference is the part of the fleet nobody has looked at, and it is the one
figure a migration plan copied off this page would otherwise silently inherit.

THE STATES, AND WHY "ORPHAN" IS NOT A FIFTH VERDICT
---------------------------------------------------
The four verdicts (``blocked`` / ``at-risk`` / ``borrowed`` / ``ok``) are
:func:`services.artifact_refs.verdict_of` — one author, shared with
``device_audit`` and ``artifact_stats``, because two pages that disagree about
the word "blocked" are worse than either page alone.

A copy that is HELD and that no walked policy names is not a verdict about a
need — there is no need. It is ``orphan``, a separate state, and it is on this
page because a fleet is where dead copies accumulate.

``empty`` is a FLAG, not a state: a held copy can be ``ok`` for every "do we
have it?" check in the codebase and still carry nothing (see
``waf_artifacts.is_empty`` and safeguards §124). Emptiness is decided on the
LATEST version's byte count only — the same rule, for the same reason, as
``/artifacts/inventory``: catching whitespace-only content means decompressing
every blob on every render, and here the listing spans the whole estate. The
whitespace case is refused at all three doors and caught again at migration
time, where the bytes are read anyway.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from . import waf_artifacts as wa
from .artifact_refs import is_stale, verdict_of

#: Worst first — the order an operator should read them, byte-identical to
#: :data:`services.artifact_stats.VERDICTS`.
VERDICTS: tuple[str, ...] = ("blocked", "at-risk", "borrowed", "ok")

#: Every state a row on this page can be in. The first four are verdicts about
#: a NEED; the last two are facts about a HOLDING and have no need behind them.
STATES: tuple[str, ...] = VERDICTS + ("orphan", "library")

STATE_LABELS: dict[str, str] = {
    "blocked": "Blocked",
    "at-risk": "At risk",
    "borrowed": "Borrowed",
    "ok": "Held",
    "orphan": "Orphan copy",
    "library": "Library copy",
}

#: What to DO about a row. Kept beside the verdict rather than in the template
#: because "at-risk" and "blocked" send an operator to opposite places and a
#: colour does not say which.
STATE_REMEDY: dict[str, str] = {
    "blocked": "No copy anywhere and the device will never hand it back — "
               "upload the file to SATOM or this policy cannot be migrated.",
    "at-risk": "No copy yet, but the device still allows the read — capture it "
               "while the box is alive.",
    "borrowed": "No copy for THIS scope; a clone would fall back to another "
                "scope's bytes. That is a guess, not a copy.",
    "ok": "A copy scoped to this device (or library-wide) is held.",
    "orphan": "Held, and named by no walked policy — either the sweep is stale "
              "or the copy is dead weight.",
    "library": "Shared copy, owned by no device; resolve() serves it to any "
               "scope that has no copy of its own.",
}

#: The library bucket is not a device and must never be filtered as one.
LIBRARY_SCOPE = "SATOM library (shared)"

#: Store growth window, in days.
GROWTH_DAYS: int = 30


def _newest_first(rows):
    """The store's own ordering — ``waf_artifacts.latest`` and
    ``artifact_files.object_index`` both resolve a version this way, and a third
    answer here would make this page name a copy neither of them would serve."""
    return sorted(rows, key=lambda r: (r.created_at or datetime.min, r.id),
                  reverse=True)


# ---------------------------------------------------------------------------
# collection — ONE universe, ONE load
# ---------------------------------------------------------------------------
def collect(user=None) -> dict:
    """Every artifact fact for every visible FortiWeb scope.

    The universe comes from :func:`services.waf_fleet.fortiweb_scopes` — the
    same single narrowing every other ``/waf/*`` page is a function of. This
    module must not re-derive it: six call sites each forgetting the filter
    separately is what §121 had to retrofit onto the artifacts pages.
    """
    from ..models_artifact_refs import WafArtifactRef, WafArtifactScan
    from ..models_artifacts import WafArtifact
    from . import artifact_stats as ast_
    from . import waf_fleet

    now = datetime.utcnow()
    appliances = waf_fleet.fortiweb_scopes(user=user)
    ids = {a.id for a in appliances}

    try:
        refs = [r for r in WafArtifactRef.query.all() if r.appliance_id in ids]
        scans = [s for s in WafArtifactScan.query.all() if s.appliance_id in ids]
        # NOT filtered by the universe, on purpose: `borrowed` is by definition
        # a statement about a copy that lives somewhere else, and the library
        # bucket belongs to no appliance at all.
        stored = WafArtifact.query.all()
    except Exception:  # noqa: BLE001 — the tables may not exist yet
        refs, scans, stored = [], [], []

    fleet = ast_.fleet_stats(appliances, now=now, data=(refs, scans, stored))

    ref_by: dict[int, list] = {}
    for r in refs:
        ref_by.setdefault(r.appliance_id, []).append(r)
    stored_by: dict[int | None, list] = {}
    for o in stored:
        stored_by.setdefault(o.appliance_id, []).append(o)

    held_any = {(o.kind, o.name) for o in stored}
    held_lib = {(o.kind, o.name) for o in stored if o.appliance_id is None}

    # How many VISIBLE scopes would resolve to the library copy: they name it
    # and hold no copy of their own. That count is the blast radius of editing
    # the shared file, which is the only question its row has to answer.
    lib_serves: dict[tuple[str, str], int] = {}
    for appl in appliances:
        mine = {(o.kind, o.name) for o in stored_by.get(appl.id, [])}
        for key in {(r.kind, r.name) for r in ref_by.get(appl.id, [])}:
            if key in held_lib and key not in mine:
                lib_serves[key] = lib_serves.get(key, 0) + 1

    scope_of = {s["appliance_id"]: s for s in fleet["scopes"]}
    rows: list[dict] = []
    for appl in appliances:
        label = waf_fleet.scope_label(appl)
        info = scope_of.get(appl.id, {})
        needed: dict[tuple[str, str], dict] = {}
        for r in ref_by.get(appl.id, []):
            key = (r.kind, r.name)
            rec = needed.get(key)
            if rec is None:
                rec = needed[key] = {"policies": set(), "profiles": set(),
                                     "stale": True}
            rec["policies"].add(r.policy_mkey)
            if r.wpp_mkey:
                rec["profiles"].add(r.wpp_mkey)
            if not is_stale(r.seen_at, now=now):
                rec["stale"] = False

        mine = stored_by.get(appl.id, [])
        by_key: dict[tuple[str, str], list] = {}
        for o in mine:
            by_key.setdefault((o.kind, o.name), []).append(o)

        for key in sorted(set(needed) | set(by_key)):
            kind, name = key
            versions = _newest_first(by_key.get(key, []))
            latest = versions[0] if versions else None
            rec = needed.get(key)
            held_here = bool(versions)
            state = (verdict_of(wa.is_readable(kind), held_here,
                                key in held_any)
                     if rec is not None else "orphan")
            rows.append(_row(
                scope=label, appliance_id=appl.id,
                device=waf_fleet.device_name(appl),
                adom=(getattr(appl, "vdom", "") or "").strip(),
                kind=kind, name=name, state=state, latest=latest,
                versions=versions, needed=rec is not None,
                held_here=held_here, held_anywhere=key in held_any,
                library_only=(not held_here) and key in held_lib,
                policies=len(rec["policies"]) if rec else 0,
                profiles=len(rec["profiles"]) if rec else 0,
                policy_names=sorted(rec["policies"]) if rec else [],
                stale=bool(rec and rec["stale"]),
                swept=bool(info.get("swept")),
                serves=0,
            ))

    for key in sorted({(o.kind, o.name) for o in stored_by.get(None, [])}):
        versions = _newest_first([o for o in stored_by.get(None, [])
                                  if (o.kind, o.name) == key])
        rows.append(_row(
            scope=LIBRARY_SCOPE, appliance_id=None, device="", adom="",
            kind=key[0], name=key[1], state="library",
            latest=versions[0] if versions else None, versions=versions,
            needed=False, held_here=True, held_anywhere=True,
            library_only=False, policies=0, profiles=0, policy_names=[],
            stale=False, swept=True, serves=lib_serves.get(key, 0),
        ))

    # Server policies the CONFIGURATION has, against the ones the sweep walked.
    # A scope with no snapshot contributes ``None`` — unknown, never zero.
    config = waf_fleet.collect(user=user)
    config_by = {d["appliance_id"]: d for d in config["devices"]}

    per_scope = []
    for appl in appliances:
        info = scope_of.get(appl.id, {})
        totals = info.get("totals", {})
        dev = config_by.get(appl.id, {})
        in_config = None if dev.get("missing", True) else int(dev.get("policies") or 0)
        walked = int(totals.get("policies_walked", 0))
        per_scope.append({
            "scope": waf_fleet.scope_label(appl),
            "appliance_id": appl.id,
            "swept": bool(info.get("swept")),
            "last_scan_at": info.get("last_scan_at", ""),
            "edges": int(totals.get("edges", 0)),
            "objects": int(totals.get("objects", 0)),
            "walked": walked,
            "in_config": in_config,
            # max(0, …) because a policy can be deleted between the sweep and
            # the harvest; a negative "unwalked" is a timing artefact, not a
            # backlog, and printing it would send someone hunting for policies
            # that no longer exist.
            "unwalked": (None if in_config is None else max(0, in_config - walked)),
            "walk_failed": int(totals.get("walk_failed", 0)),
            "stale_edges": int(totals.get("stale_edges", 0)),
            "orphans": int(totals.get("orphans", 0)),
            **{v: int(totals.get(v, 0)) for v in VERDICTS},
        })

    return {
        "rows": rows,
        "scopes": per_scope,
        "fleet": fleet,
        # The configuration universe, carried so the shared page header renders
        # the SAME freshness banner as the other four /waf pages without a
        # second collect() — and so "never harvested" means the same thing on
        # both. It is why ``unwalked`` can be None here at all.
        "devices": config["devices"],
        "appliance_count": len(appliances),
        "generated_at": now.isoformat(timespec="seconds"),
    }


def kind_choices() -> list[tuple[str, str]]:
    """``(key, label)`` for every object type the store supports, in catalogue
    order — the filter offers all of them, including the ones this fleet does
    not use, because "no XML DTD anywhere" is an answer."""
    return [(k, wa.label(k)) for k in wa.KINDS]


def _row(**kw) -> dict:
    latest = kw.pop("latest", None)
    versions = kw.pop("versions", []) or []
    state = kw["state"]
    size = int(getattr(latest, "size", 0) or 0) if latest is not None else 0
    row = dict(kw)
    # A `borrowed` row served by the LIBRARY is not the same risk as one served
    # by whichever box happens to hold the name, and telling an operator to go
    # and find "another appliance's bytes" when the file is a deliberate shared
    # copy sends them looking for a device that is not in the story.
    # resolve() prefers the library over any other appliance, so the two are
    # genuinely different branches and get different sentences.
    remedy = STATE_REMEDY.get(state, "")
    if state == "borrowed" and kw.get("library_only"):
        remedy = ("No copy of its own — resolve() serves the shared library "
                  "copy. Deliberate sharing, not a guess; but editing that one "
                  "file changes every scope that reads it.")
    row.update({
        "label": wa.label(kw["kind"]),
        "readable": wa.is_readable(kw["kind"]),
        "state_label": STATE_LABELS.get(state, state),
        "remedy": remedy,
        "versions": len(versions),
        "bytes": sum(int(o.size or 0) for o in versions),
        "size": size,
        # Byte count of the NEWEST version, which is the one resolve() serves.
        # An older non-empty version is not what a clone would carry.
        "empty": bool(latest is not None and size == 0),
        "source": getattr(latest, "source", "") if latest is not None else "",
        "sha": (getattr(latest, "sha256", "") or "")[:12] if latest is not None else "",
        "created_at": (latest.created_at.isoformat(timespec="seconds")
                       if latest is not None and latest.created_at else ""),
        "last_seen_at": (latest.last_seen_at.isoformat(timespec="seconds")
                         if latest is not None and latest.last_seen_at else ""),
    })
    return row


# ---------------------------------------------------------------------------
# statistics — every figure the page prints, from the rows it prints
# ---------------------------------------------------------------------------
def stats(universe: dict) -> dict:
    """Headline figures, derived from :func:`collect`'s own rows.

    Deliberately re-derived from ``rows`` rather than read out of
    ``fleet['totals']``: the tiles and the table then have ONE author, which is
    the drift §119 documents (a header contradicting the table under it). The
    two are cross-checked by a guard instead — if they ever disagree, that is a
    bug in one of them and the guard says which.
    """
    rows = universe["rows"]
    scopes = universe["scopes"]
    fleet = universe["fleet"]
    totals = fleet["totals"]

    device_rows = [r for r in rows if r["state"] != "library"]
    needed = [r for r in device_rows if r["needed"]]

    by_state = {s: 0 for s in STATES}
    for r in rows:
        by_state[r["state"]] += 1

    known = [s for s in scopes if s["unwalked"] is not None]
    out = {
        "scopes": len(scopes),
        "swept": sum(1 for s in scopes if s["swept"]),
        "unswept": sum(1 for s in scopes if not s["swept"]),
        "rows": len(rows),
        # (scope, kind, name) — the migration unit. The distinct FILE count is
        # smaller and answers a different question, so both are published.
        "needed": len(needed),
        "distinct": len({(r["kind"], r["name"]) for r in needed}),
        "by_state": by_state,
        "empty": sum(1 for r in rows if r["empty"]),
        "stale_rows": sum(1 for r in needed if r["stale"]),
        "unreadable_needed": sum(1 for r in needed if not r["readable"]),
        # Published beside `borrowed` rather than folded into it: a shared
        # library copy is a deliberate arrangement, and reading N borrowed as
        # "N guesses" overstates the risk by exactly this number.
        "library_backed": sum(1 for r in needed if r["library_only"]),
        "library_objects": sum(1 for r in rows if r["state"] == "library"),
        "library_serving": sum(1 for r in rows
                               if r["state"] == "library" and r["serves"]),
        "store_versions": sum(r["versions"] for r in rows),
        "store_bytes": sum(r["bytes"] for r in rows),
        "edges": int(totals.get("edges", 0)),
        "policies_with_artifacts": int(totals.get("policies_with_artifacts", 0)),
        "walk_failed": int(totals.get("walk_failed", 0)),
        "unattributed": int(totals.get("unattributed_edges", 0)),
        "policy_level": int(totals.get("policy_level_edges", 0)),
        "profiles_with_files": int(totals.get("profiles_with_files", 0)),
        # The sweep's blind spot, as a number. Scopes with no snapshot cannot
        # contribute one and are counted separately rather than as zero.
        "walked": sum(s["walked"] for s in known),
        "in_config": sum(s["in_config"] for s in known),
        "unwalked": sum(s["unwalked"] for s in known),
        "unknown_scopes": len(scopes) - len(known),
        "caveat": fleet.get("caveat", ""),
        "generated_at": universe["generated_at"],
    }
    out.update({v: by_state[v] for v in VERDICTS})
    return out


def by_kind(universe: dict) -> list[dict]:
    """Per object TYPE, over the rows this page shows.

    ``fleet['by_kind']`` counts the same things per scope; this one is what the
    table and the chart are drawn from, so a type with nothing in it still
    appears — an object type SATOM supports and the fleet does not use is a
    fact, and an absent row reads as an unsupported type.
    """
    seed = {k: {"kind": k, "label": wa.label(k), "readable": wa.is_readable(k),
                "needed": 0, "held": 0, "unheld": 0, "orphan": 0, "library": 0,
                "empty": 0, "versions": 0, "bytes": 0,
                **{v: 0 for v in VERDICTS}}
            for k in wa.KINDS}
    for r in universe["rows"]:
        row = seed.get(r["kind"])
        if row is None:
            row = seed[r["kind"]] = {
                "kind": r["kind"], "label": r["label"],
                "readable": r["readable"], "needed": 0, "held": 0, "unheld": 0,
                "orphan": 0, "library": 0, "empty": 0, "versions": 0,
                "bytes": 0, **{v: 0 for v in VERDICTS}}
        row["versions"] += r["versions"]
        row["bytes"] += r["bytes"]
        if r["empty"]:
            row["empty"] += 1
        if r["state"] in VERDICTS:
            row["needed"] += 1
            row[r["state"]] += 1
            if r["state"] == "ok":
                row["held"] += 1
            else:
                row["unheld"] += 1
        else:
            row[r["state"]] += 1
    return [seed[k] for k in wa.KINDS] + \
           [v for k, v in seed.items() if k not in wa.KINDS]


def growth_series(universe: dict, days: int = GROWTH_DAYS) -> dict:
    """Artifact VERSIONS minted per day, over the visible scopes + the library.

    Reads the index only. A flat zero means the store is stable, not that the
    sweep stopped — the ``swept`` column is what answers that.
    """
    from ..models_artifacts import WafArtifact

    days = max(1, days)
    labels: list[str] = []
    day = datetime.utcnow().date() - timedelta(days=days - 1)
    while len(labels) < days:
        labels.append(day.isoformat())
        day += timedelta(days=1)

    ids = {s["appliance_id"] for s in universe["scopes"]}
    counts = {lbl: 0 for lbl in labels}
    try:
        since = datetime.utcnow() - timedelta(days=days)
        for row in WafArtifact.query.filter(WafArtifact.created_at >= since).all():
            if row.appliance_id is not None and row.appliance_id not in ids:
                continue
            key = row.created_at.date().isoformat() if row.created_at else ""
            if key in counts:
                counts[key] += 1
    except Exception:  # noqa: BLE001
        pass
    return {"labels": labels, "values": [counts[lbl] for lbl in labels]}
