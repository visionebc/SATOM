"""The hot path, end to end — one sweep.

    collect → normalize → dedup → store → route to incident → correlate →
    score → evidence → policy proposal        (AI, separately and optionally)

Contracts this sweep keeps, each of them paid for by an earlier bug in this
product:

* **A sweep that RAN is ``ok``, even when devices errored.** Per-device
  failures are carried in the result rows. A sweep that goes permanently red
  because one appliance is down teaches operators to ignore the colour.
* **Absence is never health.** Every sweep writes ``satom_sentinel_up`` and a
  per-stage count to the metrics store, so "the pipeline stopped running" and
  "the pipeline ran and found nothing" are different pictures on a graph
  instead of the same flat line.
* **Devices in maintenance are skipped** for collection, exactly as the metrics
  collector does — the deep monitors once probed recycled IPs every 3 minutes
  because that rule lived in a caller instead of in the sweep.
* **The AI stage cannot fail the sweep.** It runs last, per incident, inside
  its own try, and its failure is recorded on the incident.
* **Dedup happens before anything else is written.** Two sweeps reading the
  same appliance page must not double-count; identity is content, not arrival.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta

from ...models import Appliance, db
from ...models_sentinel import SentinelEvent, SentinelIncident
from . import ai, actions, baseline, config, correlate, incident, normalize
from .. import vm_store


def _visible_devices() -> list:
    """Appliances Sentinel may read. Maintenance and neutralised hosts out."""
    rows = Appliance.query.filter(Appliance.kind == "fortiweb").all()
    out = []
    for a in rows:
        if getattr(a, "maintenance", False):
            continue
        if str(getattr(a, "host", "") or "").endswith(".invalid"):
            continue
        out.append(a)
    return out


def collect_device(appliance, limit: int | None = None) -> dict:
    """Pull, normalise and store new attack-log entries from one appliance.

    Returns a row describing what happened — including the failure case, which
    is a first-class result rather than an exception the caller must guess at.
    """
    limit = int(limit or config.get("ingest_limit"))
    started = time.time()
    row = {"device": appliance.name, "read": 0, "new": 0, "duplicate": 0,
           "status": "ok", "detail": "", "ms": 0}
    try:
        from .. import attack_log
        entries = attack_log.recent(appliance, limit=limit)
    except Exception as exc:  # noqa: BLE001  (transport errors are data here)
        row["status"] = "error"
        row["detail"] = f"{type(exc).__name__}: {exc}"[:280]
        row["ms"] = int((time.time() - started) * 1000)
        return row

    row["read"] = len(entries)
    for entry in entries:
        event = normalize.from_attack_log(appliance, entry)
        if SentinelEvent.query.filter_by(dedup_key=event.dedup_key).first():
            row["duplicate"] += 1
            continue
        db.session.add(event)
        db.session.flush()
        incident.ingest_event(event)
        row["new"] += 1
    db.session.commit()
    row["ms"] = int((time.time() - started) * 1000)
    return row


def score_open_incidents(max_incidents: int = 50) -> list:
    """Re-correlate and re-score every live incident.

    Bounded on purpose: a flood must not turn one sweep into an unbounded
    correlation job that outlives its own scheduling interval and starts
    overlapping itself.
    """
    rows = (SentinelIncident.query
            .filter(SentinelIncident.status.in_([SentinelIncident.STATUS_OPEN,
                                                 SentinelIncident.STATUS_VERIFYING]))
            .order_by(SentinelIncident.last_event_at.desc())
            .limit(max_incidents).all())
    out = []
    for inc in rows:
        try:
            result = incident.rescore(inc)
            inc.similar = incident.similar(inc)
            proposal = actions.recommend(inc)
            if proposal in actions.CATALOG:
                # autoqueue is level 3 and is refused by evaluate() unless the
                # operator raised this action to it. Passing it unconditionally
                # is correct: the decision lives in the policy row, not here,
                # and duplicating that condition in two places is how the two
                # come to disagree.
                actions.propose(inc, proposal, autoqueue=True,
                                rationale=f"score {inc.score} → band {inc.band}")
            db.session.commit()
            out.append({"ref": inc.ref, "score": inc.score, "band": inc.band,
                        "recommend": proposal, "status": "ok"})
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            out.append({"ref": inc.ref, "status": "error",
                        "detail": f"{type(exc).__name__}: {exc}"[:200]})
    return out


def reason_incidents(max_incidents: int = 10) -> list:
    """The cold path. Optional, last, and structurally unable to break a sweep."""
    if not ai.enabled():
        return []
    floor = int(config.get("ai_min_score"))
    rows = (SentinelIncident.query
            .filter(SentinelIncident.status.in_([SentinelIncident.STATUS_OPEN,
                                                 SentinelIncident.STATUS_VERIFYING]),
                    SentinelIncident.score >= floor)
            .order_by(SentinelIncident.score.desc())
            .limit(max_incidents).all())
    out = []
    for inc in rows:
        existing = inc.ai or {}
        # One opinion per (incident, score). Re-asking an unchanged incident
        # burns a model call to receive the same answer.
        if existing.get("ok") and existing.get("scored_at") == inc.score:
            continue
        try:
            evidence = [e.to_dict() for e in inc.evidence]
            opinion = ai.reason(inc, evidence)
            opinion["scored_at"] = inc.score
            inc.ai = opinion
            incident.timeline_add(
                inc, "decision",
                f"AI assessment ({opinion.get('model', '?')}): "
                f"{opinion.get('assessment') or opinion.get('error', 'no answer')}")
            db.session.commit()
            out.append({"ref": inc.ref, "ok": opinion.get("ok"),
                        "assessment": opinion.get("assessment", ""),
                        "error": opinion.get("error", "")})
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            out.append({"ref": inc.ref, "ok": False,
                        "error": f"{type(exc).__name__}: {exc}"[:200]})
    return out


def expire_actions() -> int:
    """Retire proposals and applied actions whose TTL has passed.

    TTL expiry is the primary rollback. It runs every sweep and needs nothing
    to succeed beyond this row update — which is the entire argument for
    preferring it to an undo call against a device that may be unreachable
    precisely when the undo matters.
    """
    from ...models_sentinel import SentinelAction
    now = datetime.utcnow()
    rows = (SentinelAction.query
            .filter(SentinelAction.expires_at.isnot(None),
                    SentinelAction.expires_at <= now,
                    SentinelAction.status.in_([SentinelAction.STATUS_PROPOSED,
                                               SentinelAction.STATUS_APPLIED,
                                               SentinelAction.STATUS_QUEUED]))
            .all())
    for a in rows:
        a.status = SentinelAction.STATUS_EXPIRED
        a.detail = (a.detail or "") + " | TTL expired"
    if rows:
        db.session.commit()
    return len(rows)


def _report(result: dict) -> None:
    """Write the pipeline's own heartbeat. Absence is never health."""
    ts = int(time.time() * 1000)
    lines = [
        vm_store.line("satom_sentinel_up", {}, 1 if result["ok"] else 0, ts),
        vm_store.line("satom_sentinel_events_new", {}, result["new_events"], ts),
        vm_store.line("satom_sentinel_incidents_open", {},
                      result["open_incidents"], ts),
        vm_store.line("satom_sentinel_devices_error", {}, result["errors"], ts),
        vm_store.line("satom_sentinel_sweep_ms", {}, result["ms"], ts),
    ]
    try:
        vm_store.ingest(lines)
    except Exception:  # noqa: BLE001
        pass   # a store hiccup must not fail a sweep that already succeeded


def sweep(devices: list | None = None, on_device=None) -> dict:
    """One full pass of the hot path. The scheduled action calls this.

    ``devices`` — an optional list of appliance NAMES to restrict the
    collection to. ``None`` (the default, and what the scheduled action
    passes) means every eligible device, so the automatic sweep is unchanged
    by the picker the console grew. A name that is not eligible — in
    maintenance, or pointed at ``.invalid`` — is dropped here as well as in
    the caller: the rule that those hosts are never contacted belongs in the
    sweep, not in whoever calls it. That is the same mistake the deep monitors
    made when they probed recycled IPs every three minutes.

    ``on_device`` — an optional ``(done, total, name)`` callback, invoked
    BEFORE each device. It is how the job wrapper reports progress and where
    it takes its stop checkpoint; the scheduled action passes nothing and is
    byte-for-byte the sweep it always was.
    """
    started = time.time()
    if not config.get("enabled"):
        return {"ok": True, "skipped": True, "detail": "sentinel.enabled is off",
                "devices": [], "new_events": 0, "open_incidents": 0,
                "errors": 0, "ms": 0}

    actions.ensure_policies()
    eligible = _visible_devices()
    if devices:
        wanted = {str(n) for n in devices}
        eligible = [a for a in eligible if a.name in wanted]
    rows = []
    total = len(eligible)
    for i, a in enumerate(eligible):
        if on_device is not None:
            on_device(i, total, a.name)
        rows.append(collect_device(a))
    devices_swept = eligible
    new_events = sum(r["new"] for r in rows)
    errors = sum(1 for r in rows if r["status"] == "error")

    scored = score_open_incidents()
    reasoned = reason_incidents()
    expired = expire_actions()

    open_n = SentinelIncident.query.filter(
        SentinelIncident.status.in_([SentinelIncident.STATUS_OPEN,
                                     SentinelIncident.STATUS_VERIFYING])).count()

    result = {
        "ok": True,           # the sweep RAN; device failures live in rows
        "skipped": False,
        "devices": rows, "scored": scored, "reasoned": reasoned,
        "new_events": new_events, "open_incidents": open_n,
        "expired_actions": expired, "errors": errors,
        "ms": int((time.time() - started) * 1000),
    }
    result["detail"] = (f"{len(devices_swept)} device(s), {new_events} new "
                        f"event(s), {len(scored)} incident(s) scored, {errors} "
                        f"device error(s)")
    _report(result)
    return result


# --------------------------------------------------------------------------- #
#  Baseline recompute — the nightly job                                         #
# --------------------------------------------------------------------------- #
def recompute_baselines(days: int | None = None) -> dict:
    """Rebuild every behavioural baseline from the metrics store.

    Reads the TSDB only: zero appliance calls, so this is safe at any hour and
    its only budget is the node's own CPU. Samples inside a frozen maintenance
    window are DROPPED rather than folded in — the whole point of freezing is
    that an authorised pentest must not teach the detector that a flood is
    normal.
    """
    days = int(days or config.get("baseline_days"))
    end = datetime.utcnow()
    start = end - timedelta(days=days)
    out = {"series": 0, "buckets": 0, "skipped_frozen": 0, "errors": []}

    from . import enrich as enrich_mod
    for spec in correlate.LAYER_SERIES:
        metric, by = spec["metric"], spec["by"]
        # A spec with an ``expr`` template names its own underlying metrics;
        # ``match`` says which of them to enumerate label values from. Using
        # ``metric`` there would enumerate a series that is never ingested and
        # silently learn nothing.
        for value in vm_store.label_values(by, match=spec.get("match", metric)):
            expr = correlate._selector(
                spec, value if by == "device" else "",
                value if by == "node" else "")
            payload = vm_store.query_range(expr, start.timestamp(),
                                           end.timestamp(), step="5m",
                                           timeout=60.0)
            if (payload or {}).get("status") != "success":
                out["errors"].append(f"{metric}/{value}: "
                                     f"{(payload or {}).get('error', 'no data')}"[:200])
                continue
            samples = []
            for series in ((payload.get("data") or {}).get("result") or []):
                for point in (series.get("values") or []):
                    try:
                        when = datetime.utcfromtimestamp(float(point[0]))
                        val = float(point[1])
                    except (TypeError, ValueError, IndexError, OSError):
                        continue
                    device = value if by == "device" else ""
                    if enrich_mod.baseline_frozen(when, device):
                        out["skipped_frozen"] += 1
                        continue
                    samples.append((when, val))
            if not samples:
                continue
            out["buckets"] += baseline.recompute(metric, {by: value}, samples)
            out["series"] += 1
    db.session.commit()
    out["coverage"] = baseline.coverage()
    out["ok"] = True
    out["detail"] = (f"{out['series']} series, {out['buckets']} buckets, "
                     f"{out['coverage']['usable']} usable")
    return out
