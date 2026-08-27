"""Every artifact statistic SATOM can compute, cut by **(device, ADOM)**.

Why the scope is (device, ADOM) and never just "device"
-------------------------------------------------------
SATOM registers ONE appliance record per administrative domain. The lab holds
``fortiweb12`` (ADOM ``root``) next to ``fortiweb12@adom_prod``, ``@adom_dmz``
and ``@adom_dev`` — **four records, one chassis at 192.0.2.13**. They are four
independent configurations: a profile called ``wpp-a`` in ``adom_prod`` and a
profile called ``wpp-a`` in ``adom_dev`` are DIFFERENT profiles that may bind
different files under the same name.

So every count here is computed per appliance record and only then rolled up to
the chassis. Counting per chassis first would add four ADOMs' profiles together
and print a device that owns four times the objects it actually has — and,
worse, would make one ADOM's uploaded copy look like coverage for another
ADOM's identically-named object.

The ADOM itself is read from ``Appliance.vdom``. That column name is a
long-standing trap in this repo: **the FortiWeb concept is the ADOM, the column
is called vdom.** An empty value is not a third state — ``models`` already
settled that with :data:`models.DEVICE_SCOPE_ADOMS`: a row with no ADOM is a
device registered before ADOMs were switched on, and that is the same thing as
``root``. :func:`adom_of` defers to that set rather than inventing a second
answer, because two modules disagreeing about what "no ADOM" means is how one
of them starts printing a partition that does not exist.

Chassis grouping likewise defers to :func:`models.chassis_key`. Grouping by
``host`` here would have been a second author for that rule and would have got
it wrong in one specific way the existing helper is careful about: the helper
returns ``None`` for an HA cluster container, and bucketing every ``None``
together merges unrelated clusters into one imaginary box.

What "counted" means, and the three states that must never merge
---------------------------------------------------------------
``wpp_mkey`` on an edge has three distinct values and this module reports each
one separately:

``"wpp-a"``  the artifact travels through that Web Protection Profile. Only
            these count towards *profiles that carry files* — the headline
            number this page exists to answer.
``""``      walked, and the artifact hangs off the SERVER POLICY itself. Lua
            scripting does exactly this and never passes a profile. It is a
            FINDING, not a blank, and folding it into the profile count would
            invent a profile that does not mention the file.
``None``    NOT ATTRIBUTED — nobody walked it for a profile. Reported as its
            own number, because "no profile" and "no answer" send an operator
            to opposite places.

Likewise a scope with **no scan row at all** reports ``swept=False`` rather
than a tidy row of zeros: "nobody has looked at this ADOM" and "we looked and
it carries nothing" are the two answers this page most has to keep apart.
"""
from __future__ import annotations

from datetime import datetime

from . import waf_artifacts as wa
from .artifact_refs import is_stale, verdict_of

#: Verdict keys, in the order an operator should read them (worst first). Kept
#: byte-identical to :func:`services.artifact_refs.device_audit` — two pages
#: that disagree about the word "blocked" are worse than either page alone.
VERDICTS = ("blocked", "at-risk", "borrowed", "ok")


def adom_of(appl) -> tuple[str, bool]:
    """``(label, is_device_scope)`` for an appliance record.

    ``label`` is what the page prints — an empty ``vdom`` renders as ``root``
    rather than as a blank, because :data:`models.DEVICE_SCOPE_ADOMS` already
    decided those are the same domain and a blank cell would read as missing
    data. ``is_device_scope`` marks the row that administers the BOX rather
    than a partition of it.
    """
    from ..models import DEVICE_SCOPE_ADOMS

    text = str(getattr(appl, "vdom", None) or "").strip()
    device_scope = text.lower() in DEVICE_SCOPE_ADOMS
    return (text or "root", device_scope)


def _blank_kind_row(kind: str) -> dict:
    return {
        "kind": kind,
        "label": wa.label(kind),
        "readable": wa.is_readable(kind),
        "edges": 0,
        "objects": 0,
        "policies": 0,
        "profiles": 0,
        "policy_level": 0,
        "unattributed": 0,
        "held": 0,
        "unheld": 0,
        "versions": 0,
        "bytes": 0,
        "blocked": 0,
        "at-risk": 0,
        "borrowed": 0,
        "ok": 0,
    }


def _empty_totals() -> dict:
    return {
        "policies_walked": 0, "walk_ok": 0, "walk_failed": 0,
        "policies_with_artifacts": 0, "policies_clean": 0,
        "edges": 0, "objects": 0,
        "profiles_with_files": 0, "policy_level_edges": 0,
        "policy_level_policies": 0, "unattributed_edges": 0,
        "blocked": 0, "at-risk": 0, "borrowed": 0, "ok": 0,
        "library_only": 0,
        "readable_needed": 0, "unreadable_needed": 0,
        "stored_objects": 0, "stored_versions": 0, "stored_bytes": 0,
        "captured": 0, "uploaded": 0, "orphans": 0,
        "stale_edges": 0, "stale_scans": 0,
        "kinds_present": 0,
    }


def _load(appliance_ids: set[int] | None = None) -> tuple[list, list, list]:
    """Every row this module needs, read ONCE.

    Per-scope queries would re-scan the three tables for each of N ADOMs; with
    four ADOMs on one chassis that is four full scans to answer one page.
    """
    from ..models_artifact_refs import WafArtifactRef, WafArtifactScan
    from ..models_artifacts import WafArtifact

    refs = WafArtifactRef.query.all()
    scans = WafArtifactScan.query.all()
    stored = WafArtifact.query.all()
    if appliance_ids is not None:
        refs = [r for r in refs if r.appliance_id in appliance_ids]
        scans = [s for s in scans if s.appliance_id in appliance_ids]
    return refs, scans, stored


def scope_stats(appl, refs, scans, stored, *, held_any=None,
                held_lib=None, now=None) -> dict:
    """Every statistic for ONE (device, ADOM) scope.

    ``refs`` / ``scans`` are this scope's rows only; ``stored`` is the WHOLE
    artifact table, because the ``borrowed`` verdict is by definition a
    statement about copies that live somewhere else.
    """
    now = now or datetime.utcnow()
    adom, device_scope = adom_of(appl)
    aid = appl.id

    if held_any is None:
        held_any = {(o.kind, o.name) for o in stored}
    if held_lib is None:
        held_lib = {(o.kind, o.name) for o in stored if o.appliance_id is None}
    mine = [o for o in stored if o.appliance_id == aid]
    held_here = {(o.kind, o.name) for o in mine}

    # --- artifacts this scope NEEDS, one row per distinct (kind, name) ------
    needed: dict[tuple, dict] = {}
    for r in refs:
        key = (r.kind, r.name)
        rec = needed.get(key)
        if rec is None:
            here = key in held_here
            anywhere = key in held_any
            readable = wa.is_readable(r.kind)
            rec = needed[key] = {
                "kind": r.kind, "name": r.name, "readable": readable,
                # One author, shared with device_audit — see verdict_of.
                "verdict": verdict_of(readable, here, anywhere),
                # A subset of `borrowed`, named rather than hidden: resolve()
                # falls back to the library BEFORE it falls back to another
                # device, so "an operator uploaded this for everyone" and "some
                # other box happens to have the name" are not the same risk.
                "library_only": (not here) and (key in held_lib),
                "policies": set(), "profiles": set(),
            }
        rec["policies"].add(r.policy_mkey)
        if r.wpp_mkey:
            rec["profiles"].add(r.wpp_mkey)

    # --- per object type ----------------------------------------------------
    by_kind = {k: _blank_kind_row(k) for k in wa.KINDS}
    kind_objects: dict[str, set] = {k: set() for k in wa.KINDS}
    kind_policies: dict[str, set] = {k: set() for k in wa.KINDS}
    kind_profiles: dict[str, set] = {k: set() for k in wa.KINDS}
    for r in refs:
        row = by_kind.get(r.kind)
        if row is None:  # a kind retired from KINDS still has edges on disk
            row = by_kind[r.kind] = _blank_kind_row(r.kind)
            kind_objects[r.kind] = set()
            kind_policies[r.kind] = set()
            kind_profiles[r.kind] = set()
        row["edges"] += 1
        kind_objects[r.kind].add(r.name)
        kind_policies[r.kind].add(r.policy_mkey)
        if r.wpp_mkey:
            kind_profiles[r.kind].add(r.wpp_mkey)
        elif r.wpp_mkey == "":
            row["policy_level"] += 1
        else:
            row["unattributed"] += 1
    for key, rec in needed.items():
        row = by_kind[rec["kind"]]
        row[rec["verdict"]] += 1
        if rec["verdict"] == "ok":
            row["held"] += 1
        else:
            row["unheld"] += 1
    for o in mine:
        row = by_kind.get(o.kind) or by_kind.setdefault(o.kind,
                                                        _blank_kind_row(o.kind))
        row["versions"] += 1
        row["bytes"] += int(o.size or 0)
    for k, row in by_kind.items():
        row["objects"] = len(kind_objects.get(k, ()))
        row["policies"] = len(kind_policies.get(k, ()))
        row["profiles"] = len(kind_profiles.get(k, ()))

    # --- per Web Protection Profile ----------------------------------------
    #: Bucketed on the RAW value so ``None`` and ``""`` stay apart all the way
    #: to the template; collapsing them here would be the fabricated certainty
    #: the column's nullability exists to prevent.
    prof: dict = {}
    for r in refs:
        agg = prof.get(r.wpp_mkey)
        if agg is None:
            agg = prof[r.wpp_mkey] = {
                "wpp": r.wpp_mkey,
                "state": ("profile" if r.wpp_mkey else
                          ("policy-level" if r.wpp_mkey == "" else
                           "not-attributed")),
                "edges": 0, "objects": set(), "policies": set(),
                "kinds": set(), "unheld": 0,
            }
        agg["edges"] += 1
        agg["objects"].add((r.kind, r.name))
        agg["policies"].add(r.policy_mkey)
        agg["kinds"].add(r.kind)
    by_profile = []
    for agg in prof.values():
        unheld = sum(1 for key in agg["objects"]
                     if needed[key]["verdict"] != "ok")
        by_profile.append({
            "wpp": agg["wpp"], "state": agg["state"], "edges": agg["edges"],
            "objects": len(agg["objects"]), "policies": len(agg["policies"]),
            "kinds": sorted(wa.label(k) for k in agg["kinds"]),
            "unheld": unheld,
        })
    #: Worst first, then named profiles, then the two non-profile buckets last
    #: — they are findings about the walk, not profiles to go and open.
    by_profile.sort(key=lambda d: (d["state"] != "profile", -d["unheld"],
                                   -d["edges"], d["wpp"] or ""))

    # --- policies -----------------------------------------------------------
    scanned = {s.policy_mkey for s in scans}
    pol_with_refs = {r.policy_mkey for r in refs}
    # A policy with edges but no scan row is not a clean policy; it is a policy
    # whose walk record was lost. It has to be counted as walked-and-unknown,
    # never dropped, or the denominator quietly shrinks.
    all_policies = scanned | pol_with_refs

    #: What THIS scope's policies actually name. An object stored for this
    #: device that appears nowhere in here is an orphan — held, and used by no
    #: policy anyone has walked.
    linked_here = {(r.kind, r.name) for r in refs}

    last_scan = max((s.scanned_at for s in scans if s.scanned_at), default=None)
    totals = _empty_totals()
    totals.update({
        "policies_walked": len(all_policies),
        "walk_ok": sum(1 for s in scans if s.ok),
        "walk_failed": sum(1 for s in scans if not s.ok),
        "policies_with_artifacts": len(pol_with_refs),
        "policies_clean": len(scanned - pol_with_refs),
        "edges": len(refs),
        "objects": len(needed),
        "profiles_with_files": len({r.wpp_mkey for r in refs if r.wpp_mkey}),
        "policy_level_edges": sum(1 for r in refs if r.wpp_mkey == ""),
        "policy_level_policies": len({r.policy_mkey for r in refs
                                      if r.wpp_mkey == ""}),
        "unattributed_edges": sum(1 for r in refs if r.wpp_mkey is None),
        "library_only": sum(1 for rec in needed.values()
                            if rec["library_only"]),
        "readable_needed": sum(1 for rec in needed.values() if rec["readable"]),
        "unreadable_needed": sum(1 for rec in needed.values()
                                 if not rec["readable"]),
        "stored_objects": len(held_here),
        "stored_versions": len(mine),
        "stored_bytes": sum(int(o.size or 0) for o in mine),
        "captured": sum(1 for o in mine if o.source == "captured"),
        "uploaded": sum(1 for o in mine if o.source != "captured"),
        "orphans": len(held_here - linked_here),
        "stale_edges": sum(1 for r in refs if is_stale(r.seen_at, now=now)),
        "stale_scans": sum(1 for s in scans if is_stale(s.scanned_at, now=now)),
        "kinds_present": sum(1 for row in by_kind.values() if row["edges"]),
    })
    for rec in needed.values():
        totals[rec["verdict"]] += 1

    from ..models import appliance_name_parts

    return {
        "appliance_id": aid,
        "appliance": appl.name,
        #: The DEVICE name, with the ``@<adom>`` suffix stripped only when it
        #: matches this row's own ``vdom``. ``host`` stays available beside it,
        #: but it is an ADDRESS: one chassis carries four ADOM rows, so it
        #: names none of them. Printing it as the device is what was reported.
        "device": appliance_name_parts(appl)[0] or appl.name,
        "host": getattr(appl, "host", "") or "",
        "port": getattr(appl, "port", None),
        "adom": adom,
        "device_scope": device_scope,
        "maintenance": bool(getattr(appl, "maintenance", False)),
        # The load-bearing flag: no scan row and no edge means NOBODY HAS
        # LOOKED. Rendering that as a row of zeros would read as "swept, and
        # this ADOM carries nothing" — the false all-clear this whole subsystem
        # is built to withhold.
        "swept": bool(scans or refs),
        "last_scan_at": last_scan.isoformat(timespec="seconds")
                        if last_scan else "",
        "totals": totals,
        "by_kind": [by_kind[k] for k in wa.KINDS] +
                   [v for k, v in by_kind.items() if k not in wa.KINDS],
        "by_profile": by_profile,
    }


def library_stats(stored) -> dict:
    """The library-wide bucket (``appliance_id IS NULL``).

    It belongs to no device and no ADOM, so it cannot be folded into any scope
    — but omitting it would hide copies that ``resolve()`` really does serve to
    every device as its second-choice fallback.
    """
    lib = [o for o in stored if o.appliance_id is None]
    by_kind: dict[str, dict] = {}
    for o in lib:
        row = by_kind.setdefault(o.kind, {"kind": o.kind,
                                          "label": wa.label(o.kind),
                                          "objects": set(), "versions": 0,
                                          "bytes": 0})
        row["objects"].add(o.name)
        row["versions"] += 1
        row["bytes"] += int(o.size or 0)
    return {
        "objects": len({(o.kind, o.name) for o in lib}),
        "versions": len(lib),
        "bytes": sum(int(o.size or 0) for o in lib),
        "by_kind": sorted(({"kind": r["kind"], "label": r["label"],
                            "objects": len(r["objects"]),
                            "versions": r["versions"], "bytes": r["bytes"]}
                           for r in by_kind.values()),
                          key=lambda d: d["kind"]),
    }


def _roll_up(scopes: list[dict]) -> dict:
    """Sum the additive counters across scopes.

    Only counters that are genuinely additive are summed. Distinct-value
    counters (``objects``, ``profiles_with_files``, ``kinds_present``) are NOT
    quantities of anything once summed and every caller OVERWRITES them — see
    :func:`fleet_stats`. Summed, ``kinds_present`` reads 35 for five scopes
    that between them use seven object types.
    """
    out = _empty_totals()
    for s in scopes:
        for key, val in s["totals"].items():
            if isinstance(val, int):
                out[key] = out.get(key, 0) + val
    return out


def fleet_stats(appliances, *, now=None, data=None) -> dict:
    """Statistics for every FortiWeb scope, grouped chassis → ADOM.

    ``appliances`` is passed in rather than queried so the caller's visibility
    filter (maintenance mode) is the one that applies — this module must never
    widen what a read-only user can see.

    ``data`` is an optional ``(refs, scans, stored)`` triple a caller has
    already loaded, in exactly the shape :func:`_load` returns: ``refs`` and
    ``scans`` NARROWED to ``appliances``, ``stored`` deliberately whole (the
    ``borrowed`` verdict is a statement about copies that live elsewhere, and
    the library bucket belongs to no appliance). It exists so a page that reads
    those three tables itself does not scan them twice.
    """
    now = now or datetime.utcnow()
    appliances = list(appliances or [])
    ids = {a.id for a in appliances}
    if data is not None:
        refs, scans, stored = data
    else:
        try:
            refs, scans, stored = _load(ids)
        except Exception:  # noqa: BLE001 — tables may not exist yet
            refs, scans, stored = [], [], []

    held_any = {(o.kind, o.name) for o in stored}
    held_lib = {(o.kind, o.name) for o in stored if o.appliance_id is None}
    ref_by: dict[int, list] = {}
    scan_by: dict[int, list] = {}
    for r in refs:
        ref_by.setdefault(r.appliance_id, []).append(r)
    for s in scans:
        scan_by.setdefault(s.appliance_id, []).append(s)

    scopes = [scope_stats(a, ref_by.get(a.id, []), scan_by.get(a.id, []),
                          stored, held_any=held_any, held_lib=held_lib, now=now)
              for a in appliances]
    by_id = {s["appliance_id"]: s for s in scopes}

    # --- chassis rollup -----------------------------------------------------
    #: Grouped with :func:`models.chassis_key` — the repo's single answer to
    #: "which rows are one box". A row whose key is ``None`` (an HA cluster
    #: container) gets a bucket of its OWN, keyed by its id: the helper's
    #: docstring is explicit that lumping every keyless row together merges
    #: unrelated clusters, and a merged bucket would print one device that owns
    #: two clusters' artifacts.
    from ..models import appliance_name_parts, chassis_key

    devices: dict[str, dict] = {}
    for appl in appliances:
        key = chassis_key(appl) or ("row:%s" % appl.id)
        dev = devices.setdefault(key, {
            "host": (getattr(appl, "host", "") or "").strip() or "?",
            #: All the rows of one chassis normally share a device name; when
            #: they genuinely disagree the chassis has no single name and the
            #: address is the honest label, so the first name wins only if the
            #: rest agree with it.
            "devices": set(), "scopes": [], "appliance_ids": []})
        dev["devices"].add(appliance_name_parts(appl)[0] or appl.name)
        dev["scopes"].append(by_id[appl.id])
        dev["appliance_ids"].append(appl.id)
    device_rows = []
    for _key, dev in devices.items():
        host = dev["host"]
        member_ids = set(dev["appliance_ids"])
        d_refs = [r for r in refs if r.appliance_id in member_ids]
        totals = _roll_up(dev["scopes"])
        # Recomputed, not summed: a profile name is only unique WITHIN an ADOM,
        # so the chassis figure is "distinct (ADOM, profile)" pairs. Summing the
        # per-ADOM counts gives the same number here and stays correct if an
        # edge is ever attributed to two ADOMs at once; recomputing keeps it
        # honest either way.
        totals["profiles_with_files"] = len(
            {(r.appliance_id, r.wpp_mkey) for r in d_refs if r.wpp_mkey})
        totals["objects"] = len({(r.appliance_id, r.kind, r.name)
                                 for r in d_refs})
        totals["kinds_present"] = len({r.kind for r in d_refs})
        device_rows.append({
            "host": host,
            "device": (sorted(dev["devices"])[0]
                       if len(dev["devices"]) == 1 else host),
            "names": sorted(s["appliance"] for s in dev["scopes"]),
            "adoms": sorted(dev["scopes"],
                            key=lambda s: (not s["device_scope"],
                                           s["adom"] or "")),
            "swept_adoms": sum(1 for s in dev["scopes"] if s["swept"]),
            "adom_count": len(dev["scopes"]),
            "totals": totals,
        })
    device_rows.sort(key=lambda d: (-d["totals"]["blocked"],
                                    -d["totals"]["at-risk"],
                                    -d["totals"]["walk_failed"], d["host"]))

    fleet = _roll_up(scopes)
    fleet["profiles_with_files"] = len(
        {(r.appliance_id, r.wpp_mkey) for r in refs if r.wpp_mkey})
    fleet["objects"] = len({(r.appliance_id, r.kind, r.name) for r in refs})
    fleet["kinds_present"] = len({r.kind for r in refs})

    # --- fleet-wide per type ------------------------------------------------
    kinds = {k: _blank_kind_row(k) for k in wa.KINDS}
    for s in scopes:
        for row in s["by_kind"]:
            tgt = kinds.setdefault(row["kind"], _blank_kind_row(row["kind"]))
            for key in ("edges", "objects", "policies", "profiles",
                        "policy_level", "unattributed", "held", "unheld",
                        "versions", "bytes", "blocked", "at-risk", "borrowed",
                        "ok"):
                tgt[key] += row[key]

    return {
        "scopes": scopes,
        "devices": device_rows,
        "totals": fleet,
        "by_kind": [kinds[k] for k in wa.KINDS] +
                   [v for k, v in kinds.items() if k not in wa.KINDS],
        "library": library_stats(stored),
        "swept_scopes": sum(1 for s in scopes if s["swept"]),
        "scope_count": len(scopes),
        # Travels WITH the numbers, never as a note in the template: a policy
        # created since the last sweep is absent from every figure above, so a
        # reader who copies the totals into a migration plan copies the blind
        # spot too.
        "caveat": ("Assembled from SATOM's index without reading any device. A "
                   "server policy created after the last sweep is not counted "
                   "anywhere on this page — re-run the artifact sweep to close "
                   "that gap."),
    }
