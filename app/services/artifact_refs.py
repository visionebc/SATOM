"""Derive, persist and invert the *policy → artifact* link.

Three questions this module answers, and only the first one existed before:

1. *During a clone*, which file-backed objects does this plan carry?
   — :func:`services.waf_artifacts.plan_artifacts`, transient.
2. *Before choosing a destination*, which artifacts does policy P need and does
   SATOM hold each one? — :func:`policy_coverage`. This is the migration
   question, and it could previously only be answered by starting a clone
   pre-flight against a destination you had already picked.
3. *Looking at one artifact*, who uses it? — :func:`usage_index`. An artifact
   nobody references is an ORPHAN, which is information; before this module it
   was indistinguishable from an artifact whose users nobody had looked for.

Everything here is derived from the SAME dependency walk the clone planner
uses (``ClonePlanner.collect``), run with the source appliance on BOTH sides so
no destination is read and no device is written. Re-deriving rather than
copying the planner's logic would be a second author for one rule; the day one
is fixed the other keeps the bug.

**The refresh is incremental and says so.** A fleet of 60 boxes × 750 policies
is 45 000 dependency walks; a sweep that silently truncated to the first N
would report "scanned" over a fraction. Instead each run takes a bounded
BUDGET, oldest-scanned-first, and reports how many remain — a number that walks
down to zero across runs and is visible the whole way.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta

from . import waf_artifacts as wa

#: An edge re-observed more recently than this is presented as current. Longer
#: than the sweep's own cadence on purpose: a fleet mid-refresh must not paint
#: itself red. It is a PRESENTATION threshold — nothing is deleted for age.
STALE_AFTER = timedelta(days=7)

#: Walks per sweep run, per invocation. Bounded because one walk is a handful of
#: device reads and an unbounded sweep over a real fleet is an outage. The
#: remainder is always reported (see :func:`sync_appliance`).
DEFAULT_BUDGET = 25

#: Origin recorded on rows this module derives.
ORIGIN_WALK = "walk:server-policy"
#: Origin recorded when a clone pre-flight donates what it already computed.
ORIGIN_PREFLIGHT = "preflight:clone"


# --------------------------------------------------------------------------- #
#  Derivation                                                                   #
# --------------------------------------------------------------------------- #
def artifacts_of_policy(reader, policy_mkey: str) -> tuple[list[dict], int]:
    """Walk one policy on ONE appliance; return ``(artifact rows, items walked)``.

    Source-only: ``ClonePlanner(reader, reader)`` plus ``collect()``, which is
    the half of the planner that never touches the destination and never
    classifies. Raises nothing that the caller has not asked for — a device
    failure surfaces as an exception here and is turned into a recorded
    ``ok=False`` scan by :func:`derive_policy`, because "the walk failed" must
    reach the database rather than being smoothed into "no artifacts".
    """
    from . import artifact_wpp as aw
    from . import clone as _clone

    planner = _clone.ClonePlanner(reader, reader)
    items = planner.collect(_clone.ROOT_SERVER_POLICY, policy_mkey)
    arts = wa.plan_artifacts(items)
    # ``planner._refs`` is the referrer graph the walk just built. Passing it
    # (never ``{}``) is what lets the attribution distinguish "reaches the
    # policy without a profile" from "nobody looked" — see services.artifact_wpp.
    # ``getattr`` and not ``planner._refs``: a planner that exposes no
    # referrer graph must yield NOT-ATTRIBUTED edges, not an AttributeError and
    # not a fabricated "policy-level". The default is None for the same reason
    # ``attribute`` refuses to default it — {} and None mean opposite things.
    return (aw.expand(aw.attribute(arts, items, getattr(planner, "_refs", None))),
            len(items))


def derive_policy(reader, appliance_id: int, policy_mkey: str,
                  *, origin: str = ORIGIN_WALK) -> dict:
    """Walk one policy and persist the result. Never raises."""
    t0 = time.monotonic()
    try:
        arts, n_items = artifacts_of_policy(reader, policy_mkey)
    except Exception as exc:  # noqa: BLE001 — a dead device is a result
        record_failure(appliance_id, policy_mkey,
                       "%s: %s" % (type(exc).__name__, exc))
        return {"ok": False, "policy": policy_mkey, "refs": 0,
                "error": "%s: %s" % (type(exc).__name__, exc)}
    ms = int((time.monotonic() - t0) * 1000)
    record(appliance_id, policy_mkey, arts, origin=origin, items=n_items, ms=ms)
    return {"ok": True, "policy": policy_mkey, "refs": len(arts),
            "items": n_items, "ms": ms, "error": ""}


def record(appliance_id: int, policy_mkey: str, arts, *,
           origin: str = ORIGIN_WALK, items: int = 0, ms: int = 0) -> int:
    """Persist a SUCCESSFUL walk's edges for one (appliance, policy).

    Authoritative for that pair and only that pair: edges the walk did not
    produce are DELETED, because a successful walk that no longer names a
    schema is exactly how "this policy stopped using it" is observed. Anything
    weaker leaves the index monotonically growing and therefore useless — an
    artifact would look used forever after one historical reference.
    """
    from ..models import db
    from ..models_artifact_refs import WafArtifactRef

    now = datetime.utcnow()
    # Keyed by (kind, name, WPP): one artifact reached through two profiles is
    # two facts. Keying on (kind, name) alone would let the second profile
    # overwrite the first and the index would under-report exactly the policies
    # whose content routing makes them hardest to migrate.
    wanted = {(a["kind"], a["name"], a.get("wpp")): a for a in (arts or [])}
    existing = (WafArtifactRef.query
                .filter_by(appliance_id=appliance_id, policy_mkey=policy_mkey)
                .all())
    for row in existing:
        key = (row.kind, row.name, row.wpp_mkey)
        if key in wanted:
            row.seen_at = now
            row.derived_from = origin
            row.urn = wanted[key].get("urn") or row.urn
            wanted.pop(key)
        else:
            db.session.delete(row)
    for (kind, name, wpp), a in wanted.items():
        db.session.add(WafArtifactRef(
            appliance_id=appliance_id, policy_mkey=policy_mkey,
            kind=kind, name=name, urn=(a.get("urn") or "")[:128],
            wpp_mkey=(wpp[:255] if isinstance(wpp, str) else None),
            derived_from=origin, first_seen_at=now, seen_at=now))
    _touch_scan(appliance_id, policy_mkey, ok=True, error="",
                refs=len(arts or []), items=items, ms=ms, when=now)
    db.session.commit()
    return len(arts or [])


def record_failure(appliance_id: int, policy_mkey: str, error: str) -> None:
    """Record that the walk FAILED. Leaves every existing edge untouched.

    Deleting on failure would let one unreachable appliance answer "none of my
    policies need any artifact" — a clean bill of health manufactured out of an
    outage, and the single worst thing this index could do.
    """
    from ..models import db

    _touch_scan(appliance_id, policy_mkey, ok=False,
                error=(error or "")[:500], refs=0, items=0, ms=0,
                when=datetime.utcnow())
    db.session.commit()


def _touch_scan(appliance_id: int, policy_mkey: str, *, ok: bool, error: str,
                refs: int, items: int, ms: int, when: datetime) -> None:
    from ..models import db
    from ..models_artifact_refs import WafArtifactScan

    row = (WafArtifactScan.query
           .filter_by(appliance_id=appliance_id, policy_mkey=policy_mkey)
           .first())
    if row is None:
        row = WafArtifactScan(appliance_id=appliance_id, policy_mkey=policy_mkey)
        db.session.add(row)
    row.ok = bool(ok)
    row.error = error or ""
    row.refs = int(refs)
    row.items = int(items)
    row.ms = int(ms)
    row.scanned_at = when


def record_from_plan(appliance_id: int, policy_mkey: str, items,
                    refs=None) -> int:
    """Donate what a clone pre-flight already computed, instead of re-walking.

    The pre-flight's plan is a walk of the SOURCE with destination
    classification layered on; its artifact set is identical to what
    :func:`artifacts_of_policy` would produce, so consuming it is free
    freshness. Guarded: a caller with no appliance or no policy would write an
    edge nobody can attribute.
    """
    if not appliance_id or not policy_mkey:
        return 0
    try:
        from . import artifact_wpp as aw

        rows = list(items or [])
        # ``refs=None`` is passed straight through: a donor that has no
        # referrer graph must produce NOT-ATTRIBUTED edges, not edges claiming
        # the artifact hangs off the policy.
        arts = aw.expand(aw.attribute(wa.plan_artifacts(rows), rows, refs))
        return record(appliance_id, policy_mkey, arts,
                      origin=ORIGIN_PREFLIGHT, items=len(rows))
    except Exception:  # noqa: BLE001 — indexing must never sink a clone
        from ..models import db
        db.session.rollback()
        return 0


# --------------------------------------------------------------------------- #
#  Sweeps                                                                       #
# --------------------------------------------------------------------------- #
def policies_of(reader) -> tuple[list[str], str]:
    """Server-policy mkeys on the appliance behind ``reader`` — one API call."""
    try:
        rows, err = reader.client.list_with_error(
            "/api/v2.0/cmdb/server-policy/policy")
    except Exception as exc:  # noqa: BLE001
        return [], "%s: %s" % (type(exc).__name__, exc)
    if err:
        return [], str(err)
    return [r["name"] for r in (rows or [])
            if isinstance(r, dict) and r.get("name")], ""


def sync_appliance(appl, *, budget: int = DEFAULT_BUDGET,
                   reader=None) -> dict:
    """Refresh the index for one appliance, oldest-scanned policies first.

    Returns a summary that ALWAYS states the remainder. A sweep that stopped at
    its budget and did not say so reads exactly like a sweep that finished, and
    the difference is whether the operator's coverage report covers the fleet.
    """
    from ..models_artifact_refs import WafArtifactScan

    if reader is None:
        from . import clone as _clone
        from ..clients.fortiweb import FortiWebClient
        reader = _clone.ClientReader(FortiWebClient(appl))

    names, err = policies_of(reader)
    if err:
        return {"ok": False, "appliance": appl.name, "scanned": 0, "refs": 0,
                "remaining": 0, "errors": 1,
                "summary": "could not list policies on %s: %s" % (appl.name, err)}

    seen = {r.policy_mkey: r for r in
            WafArtifactScan.query.filter_by(appliance_id=appl.id).all()}
    _prune_scans(appl.id, set(names))

    def _age(n: str):
        row = seen.get(n)
        # Never-scanned first (they are the ones that are missing from every
        # report), then oldest, then failures ahead of successes of equal age.
        return (1 if row is not None else 0,
                row.scanned_at if row is not None else datetime.min,
                1 if (row is not None and row.ok) else 0)

    order = sorted(names, key=_age)
    take = order if budget <= 0 else order[:budget]
    refs = errors = 0
    for name in take:
        res = derive_policy(reader, appl.id, name)
        refs += res.get("refs", 0)
        errors += 0 if res.get("ok") else 1
    remaining = max(0, len(order) - len(take))
    return {
        "ok": True, "appliance": appl.name, "policies": len(names),
        "scanned": len(take), "refs": refs, "errors": errors,
        "remaining": remaining,
        "summary": ("%s: %d/%d polic%s walked, %d artifact edge(s), %d error(s)"
                    % (appl.name, len(take), len(names),
                       "y" if len(take) == 1 else "ies", refs, errors))
                   + (", %d still queued for the next run" % remaining
                      if remaining else ""),
    }


def _prune_scans(appliance_id: int, live_names: set) -> None:
    """Forget policies that no longer exist on the box.

    Their edges go with them: an index that keeps a deleted policy's
    requirements makes an artifact look used by something that is not there,
    which is the orphan report reading backwards.
    """
    from ..models import db
    from ..models_artifact_refs import WafArtifactRef, WafArtifactScan

    for row in WafArtifactScan.query.filter_by(appliance_id=appliance_id).all():
        if row.policy_mkey not in live_names:
            db.session.delete(row)
    for row in WafArtifactRef.query.filter_by(appliance_id=appliance_id).all():
        if row.policy_mkey not in live_names:
            db.session.delete(row)
    db.session.commit()


def sweep(*, budget: int = DEFAULT_BUDGET, appliances=None) -> dict:
    """Refresh every FortiWeb. Used by the ``artifact_refs`` scheduled action.

    ``ok`` means THE SWEEP RAN, matching every other sweep in this product: a
    single unreachable appliance must not turn the action permanently red, or
    the colour stops meaning anything.
    """
    from ..models import Appliance

    if appliances is None:
        appliances = (Appliance.query
                      .filter_by(kind="fortiweb", maintenance=False)
                      .order_by(Appliance.name).all())
    parts, scanned, refs, errors, remaining = [], 0, 0, 0, 0
    for appl in appliances:
        res = sync_appliance(appl, budget=budget)
        parts.append(res["summary"])
        scanned += res.get("scanned", 0)
        refs += res.get("refs", 0)
        errors += res.get("errors", 0) + (0 if res.get("ok") else 1)
        remaining += res.get("remaining", 0)
    return {"ok": True, "devices": len(list(appliances)), "scanned": scanned,
            "refs": refs, "errors": errors, "remaining": remaining,
            "log": "\n".join(parts)}


# --------------------------------------------------------------------------- #
#  Reads — the inverse views                                                    #
# --------------------------------------------------------------------------- #
def usage_index() -> dict:
    """``{(kind, name): [ref dicts]}`` for every edge, in ONE query.

    The inventory page renders one row per artifact and needs its users; doing
    that per row is N queries and the page is the place a fleet-sized index is
    actually read.
    """
    from ..models_artifact_refs import WafArtifactRef

    out: dict[tuple[str, str], list[dict]] = {}
    for row in WafArtifactRef.query.order_by(WafArtifactRef.policy_mkey).all():
        out.setdefault((row.kind, row.name), []).append(row.to_dict())
    return out


def refs_for(kind: str, name: str, appliance_id: int | None = None) -> list[dict]:
    from ..models_artifact_refs import WafArtifactRef

    q = WafArtifactRef.query.filter_by(kind=kind, name=name)
    if appliance_id is not None:
        q = q.filter_by(appliance_id=appliance_id)
    return [r.to_dict() for r in q.order_by(WafArtifactRef.policy_mkey).all()]


def is_stale(seen_at, *, now: datetime | None = None) -> bool:
    if not seen_at:
        return True
    return ((now or datetime.utcnow()) - seen_at) > STALE_AFTER


def policy_coverage(appliance_id: int, policy_mkey: str) -> dict:
    """*Can this policy be migrated?* — the answer this whole feature is for.

    Per artifact: does SATOM hold bytes for it, where would they come from, and
    is this one of the three kinds no FortiWeb will ever hand back (so a
    missing copy is UNRECOVERABLE from the device rather than merely absent).

    ``scanned`` is reported separately from the rows. An empty list from a
    policy that was walked means "carries no file-backed object" — a clean
    result. An empty list from a policy that was never walked means nobody
    looked, and presenting the two the same way is the failure mode this table
    was split in two to avoid.
    """
    from ..models_artifact_refs import WafArtifactRef, WafArtifactScan

    scan = (WafArtifactScan.query
            .filter_by(appliance_id=appliance_id, policy_mkey=policy_mkey)
            .first())
    rows = (WafArtifactRef.query
            .filter_by(appliance_id=appliance_id, policy_mkey=policy_mkey)
            .order_by(WafArtifactRef.kind, WafArtifactRef.name).all())
    out, missing, unrecoverable = [], 0, 0
    for r in rows:
        blob, origin, store_err = wa.resolve(r.kind, r.name, appliance_id)
        readable = wa.is_readable(r.kind)
        held = blob is not None
        if not held:
            missing += 1
            if not readable:
                unrecoverable += 1
        out.append({
            "kind": r.kind, "label": wa.label(r.kind), "name": r.name,
            "urn": r.urn, "readable": readable, "held": held,
            "size": len(blob) if blob is not None else 0,
            "origin": origin, "store_error": store_err,
            "seen_at": r.seen_at.isoformat(timespec="seconds") if r.seen_at else "",
            "stale": is_stale(r.seen_at),
            "reason": "" if held else (
                store_err or
                ("SATOM holds no copy, and %s cannot be read back from any "
                 "FortiWeb — this content cannot be recovered from the source "
                 "box" % wa.label(r.kind)) if not readable else
                "SATOM holds no copy; it can still be captured off the source "
                "device before the move"),
        })
    return {
        "appliance_id": appliance_id, "policy": policy_mkey,
        "scanned": scan is not None and bool(scan.ok),
        "scanned_at": scan.scanned_at.isoformat(timespec="seconds")
                      if scan is not None and scan.scanned_at else "",
        "scan_error": (scan.error if scan is not None and not scan.ok else ""),
        "stale": (scan is None or is_stale(scan.scanned_at)),
        "artifacts": out, "total": len(out),
        "missing": missing, "unrecoverable": unrecoverable,
        "ready": (scan is not None and bool(scan.ok) and missing == 0),
    }


def coverage_fleet(appliance_id: int | None = None) -> list[dict]:
    """One coverage row per scanned policy, worst first."""
    from ..models_artifact_refs import WafArtifactScan

    q = WafArtifactScan.query
    if appliance_id is not None:
        q = q.filter_by(appliance_id=appliance_id)
    out = []
    for scan in q.order_by(WafArtifactScan.appliance_id,
                           WafArtifactScan.policy_mkey).all():
        if not scan.ok:
            out.append({"appliance_id": scan.appliance_id,
                        "policy": scan.policy_mkey, "scanned": False,
                        "scan_error": scan.error, "total": 0, "missing": 0,
                        "unrecoverable": 0, "ready": False,
                        "stale": is_stale(scan.scanned_at), "artifacts": []})
            continue
        if not scan.refs:
            out.append({"appliance_id": scan.appliance_id,
                        "policy": scan.policy_mkey, "scanned": True,
                        "scan_error": "", "total": 0, "missing": 0,
                        "unrecoverable": 0, "ready": True,
                        "stale": is_stale(scan.scanned_at), "artifacts": []})
            continue
        out.append(policy_coverage(scan.appliance_id, scan.policy_mkey))
    out.sort(key=lambda r: (r["ready"], -r["unrecoverable"], -r["missing"],
                            r["policy"]))
    return out


def stats() -> dict:
    """Index health for the inventory page header."""
    from ..models_artifact_refs import WafArtifactRef, WafArtifactScan
    from ..models_artifacts import WafArtifact

    now = datetime.utcnow()
    try:
        refs = WafArtifactRef.query.all()
        scans = WafArtifactScan.query.all()
        held = {(r.kind, r.name) for r in WafArtifact.query.all()}
    except Exception:  # noqa: BLE001 — tables may not exist yet
        return {"edges": 0, "linked_objects": 0, "policies": 0, "devices": 0,
                "stale_edges": 0, "orphans": 0, "unheld": 0, "failed_scans": 0}
    linked = {(r.kind, r.name) for r in refs}
    return {
        "edges": len(refs),
        "linked_objects": len(linked),
        "policies": len({(r.appliance_id, r.policy_mkey) for r in refs}),
        "devices": len({r.appliance_id for r in refs}),
        "stale_edges": sum(1 for r in refs if is_stale(r.seen_at, now=now)),
        #: Held by SATOM but named by no policy anyone has walked.
        "orphans": len(held - linked),
        #: Named by a policy and NOT held — the migration blockers.
        "unheld": len(linked - held),
        "failed_scans": sum(1 for s in scans if not s.ok),
    }


# --------------------------------------------------------------------------- #
#  The audit — everything SATOM knows, per DEVICE                               #
# --------------------------------------------------------------------------- #
def content_divergence() -> list[dict]:
    """Artifact NAMES whose stored content differs between scopes.

    This is the report that makes :func:`services.waf_artifacts.resolve`'s last
    fallback readable. That fallback answers a missing copy with *"another
    appliance's stored copy of the same name"* — which is a GUESS, and exactly
    the drift a clone is supposed to carry rather than erase. Nothing warned
    about it before: the guess and a correct hit render identically.

    Divergence is judged on the LATEST version per scope. Comparing every
    version would flag any object that was ever edited, which is normal history
    and not a conflict.
    """
    from ..models_artifacts import WafArtifact

    latest: dict[tuple, tuple] = {}
    for row in (WafArtifact.query
                .order_by(WafArtifact.created_at.asc(), WafArtifact.id.asc())
                .all()):
        latest[(row.kind, row.name, row.appliance_id)] = (
            row.sha256, row.size, row.appliance_id, row.created_at)
    grouped: dict[tuple, list] = {}
    for (kind, name, _aid), val in latest.items():
        grouped.setdefault((kind, name), []).append(val)
    out = []
    for (kind, name), vals in sorted(grouped.items()):
        shas = {v[0] for v in vals}
        if len(shas) < 2:
            continue
        out.append({
            "kind": kind, "label": wa.label(kind), "name": name,
            "copies": [{"appliance_id": v[2], "sha256": (v[0] or "")[:12],
                        "size": v[1],
                        "at": v[3].isoformat(timespec="seconds") if v[3] else ""}
                       for v in sorted(vals, key=lambda v: (v[2] or 0))],
        })
    return out


def device_audit(appliance_id: int) -> dict:
    """Every fact SATOM holds about ONE appliance's file-backed objects.

    Deliberately assembled from the index alone — no device is read. That makes
    the page reproducible and safe to open during an incident, and it is why
    ``caveat`` is part of the return value rather than a note in the template:
    a policy CREATED since the last sweep is not in this table at all, so the
    page's own blind spot has to travel with its numbers.
    """
    from ..models_artifact_refs import WafArtifactRef, WafArtifactScan
    from ..models_artifacts import WafArtifact

    now = datetime.utcnow()
    scans = (WafArtifactScan.query.filter_by(appliance_id=appliance_id)
             .order_by(WafArtifactScan.policy_mkey).all())
    refs = (WafArtifactRef.query.filter_by(appliance_id=appliance_id)
            .order_by(WafArtifactRef.policy_mkey, WafArtifactRef.kind,
                      WafArtifactRef.name).all())
    stored = [r for r in WafArtifact.query
              .filter_by(appliance_id=appliance_id)
              .order_by(WafArtifact.kind, WafArtifact.name).all()]

    held_any = {(r.kind, r.name) for r in WafArtifact.query.all()}
    held_here = {(r.kind, r.name) for r in stored}

    # --- per referenced artifact -------------------------------------------
    needed: dict[tuple, dict] = {}
    for r in refs:
        key = (r.kind, r.name)
        rec = needed.get(key)
        if rec is None:
            readable = wa.is_readable(r.kind)
            here = key in held_here
            anywhere = key in held_any
            rec = needed[key] = {
                "kind": r.kind, "label": wa.label(r.kind), "name": r.name,
                "readable": readable,
                "held_here": here, "held_anywhere": anywhere,
                # The verdict, and the only one worth acting on:
                #   blocked  -> no copy anywhere AND the device will never hand
                #               it back. The policy cannot be migrated, full stop.
                #   at-risk  -> no copy, but it is still capturable off the box
                #               while the box is alive.
                #   borrowed -> no copy for THIS device; resolve() would fall
                #               back to some other appliance's bytes. That is a
                #               guess, not a copy (see content_divergence).
                #   ok       -> a copy scoped to this device (or library-wide).
                "verdict": ("ok" if here else
                            ("borrowed" if anywhere else
                             ("blocked" if not readable else "at-risk"))),
                "policies": [], "wpps": [], "stale": True,
            }
        if r.policy_mkey not in rec["policies"]:
            rec["policies"].append(r.policy_mkey)
        text = r.wpp_mkey
        if text not in rec["wpps"]:
            rec["wpps"].append(text)
        if not is_stale(r.seen_at, now=now):
            rec["stale"] = False
    needed_rows = sorted(needed.values(), key=lambda d: (d["kind"], d["name"]))

    # --- per policy ---------------------------------------------------------
    by_policy: dict[str, dict] = {}
    for s in scans:
        by_policy[s.policy_mkey] = {
            "policy": s.policy_mkey, "ok": bool(s.ok), "error": s.error,
            "refs": s.refs, "items": s.items, "ms": s.ms,
            "scanned_at": s.scanned_at.isoformat(timespec="seconds")
                          if s.scanned_at else "",
            "stale": is_stale(s.scanned_at, now=now),
            "artifacts": [], "wpps": [], "blocked": 0, "at_risk": 0,
        }
    for r in refs:
        p = by_policy.setdefault(r.policy_mkey, {
            "policy": r.policy_mkey, "ok": False,
            # An edge with no scan row is not a clean policy — it is a policy
            # whose walk record was lost. Saying so beats rendering a blank.
            "error": "edges exist but no scan row — re-walk this policy",
            "refs": 0, "items": 0, "ms": 0, "scanned_at": "", "stale": True,
            "artifacts": [], "wpps": [], "blocked": 0, "at_risk": 0})
        v = needed[(r.kind, r.name)]
        p["artifacts"].append({
            "kind": r.kind, "label": wa.label(r.kind), "name": r.name,
            "wpp": r.wpp_mkey, "verdict": v["verdict"],
            "seen_at": r.seen_at.isoformat(timespec="seconds")
                       if r.seen_at else "",
            "stale": is_stale(r.seen_at, now=now)})
        if r.wpp_mkey not in p["wpps"]:
            p["wpps"].append(r.wpp_mkey)
        if v["verdict"] == "blocked":
            p["blocked"] += 1
        elif v["verdict"] in ("at-risk", "borrowed"):
            p["at_risk"] += 1
    policies = sorted(by_policy.values(),
                      key=lambda d: (-d["blocked"], -d["at_risk"],
                                     d["ok"], d["policy"]))

    # --- profiles -----------------------------------------------------------
    wpps: dict = {}
    for r in refs:
        agg = wpps.setdefault(r.wpp_mkey, {"wpp": r.wpp_mkey, "artifacts": 0,
                                           "policies": set()})
        agg["artifacts"] += 1
        agg["policies"].add(r.policy_mkey)
    wpp_rows = sorted(
        ({"wpp": k, "artifacts": v["artifacts"],
          "policies": len(v["policies"])} for k, v in wpps.items()),
        key=lambda d: (d["wpp"] is None, d["wpp"] or ""))

    linked_here = {(r.kind, r.name) for r in refs}
    last_scan = max((s.scanned_at for s in scans if s.scanned_at),
                    default=None)
    return {
        "appliance_id": appliance_id,
        "policies": policies,
        "artifacts": needed_rows,
        "wpps": wpp_rows,
        "stored": [{"kind": o.kind, "label": wa.label(o.kind), "name": o.name,
                    "sha256": (o.sha256 or "")[:12], "size": o.size,
                    "source": o.source, "by": o.created_by,
                    "at": o.created_at.isoformat(timespec="seconds")
                          if o.created_at else "",
                    "orphan": (o.kind, o.name) not in linked_here}
                   for o in stored],
        "totals": {
            "policies": len(policies),
            "walk_ok": sum(1 for p in policies if p["ok"]),
            "walk_failed": sum(1 for p in policies if not p["ok"]),
            "stale_scans": sum(1 for p in policies if p["stale"]),
            "edges": len(refs),
            "artifacts": len(needed_rows),
            "blocked": sum(1 for a in needed_rows if a["verdict"] == "blocked"),
            "at_risk": sum(1 for a in needed_rows if a["verdict"] == "at-risk"),
            "borrowed": sum(1 for a in needed_rows if a["verdict"] == "borrowed"),
            "ok": sum(1 for a in needed_rows if a["verdict"] == "ok"),
            "stored": len(stored),
            "orphans": sum(1 for o in stored
                           if (o.kind, o.name) not in linked_here),
            "unattributed": sum(1 for r in refs if r.wpp_mkey is None),
            "profiles": sum(1 for w in wpp_rows if w["wpp"]),
        },
        "last_scan_at": last_scan.isoformat(timespec="seconds")
                        if last_scan else "",
        "caveat": ("Assembled from SATOM's index without reading the device. A "
                   "server policy created after the last sweep is not in this "
                   "report at all — re-run the sweep to close that gap."),
    }


def fleet_audit(appliances) -> list[dict]:
    """:func:`device_audit` for each appliance, worst first.

    Devices with NO index entry are included with zeroed totals on purpose: an
    audit that lists only the boxes it has data for reads as an audit of the
    fleet, and the boxes missing from it are the ones nobody has swept.
    """
    out = []
    for appl in appliances or []:
        rec = device_audit(appl.id)
        rec["appliance"] = appl.name
        rec["kind"] = getattr(appl, "kind", "")
        rec["maintenance"] = bool(getattr(appl, "maintenance", False))
        out.append(rec)
    out.sort(key=lambda d: (-d["totals"]["blocked"], -d["totals"]["at_risk"],
                            -d["totals"]["walk_failed"], d["appliance"]))
    return out
