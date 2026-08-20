"""Incident lifecycle — open, absorb, evidence, timeline, close.

Absorption is the design decision that makes this usable
--------------------------------------------------------
An incident is keyed on (device, source, attack family), not on time. While its
window is live it ABSORBS every matching event instead of opening a sibling.
Without that, a 60-second flood produces thousands of incidents and the console
becomes the log it was built to replace — which is precisely the failure mode
this product's own design brief names in its last section.

Evidence is rebuilt, never appended
-----------------------------------
Re-scoring an incident REPLACES its evidence rows. Appending would leave the
first correlation's numbers sitting beside the fifth's, and an operator reading
a mixed set has no way to know which sentence describes now. The timeline is
the opposite — append-only — because it is a history and a history that is
rewritten is not one.

``false_positive`` is a first-class ending
------------------------------------------
Not a flavour of ``closed``. Closing a real incident and dismissing a false one
are different facts about the detector, and folding them together destroys the
only signal available for tuning it. The reason is required, because "it was a
false positive" without a cause teaches nothing.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from ...models import db
from ...models_sentinel import (SentinelAnomaly, SentinelEvent,
                                SentinelEvidence, SentinelIncident,
                                SentinelIncidentEvent)
from . import config, correlate, scoring

FP_REASONS = [
    ("trusted_source", "Authorised source (scanner / monitor / integration)"),
    ("noisy_signature", "Signature is noisy for this application"),
    ("baseline_immature", "Baseline had not learned this behaviour yet"),
    ("expected_traffic", "Legitimate traffic pattern (campaign, batch, release)"),
    ("misclassified", "Correlated the wrong events together"),
    ("other", "Other — see the note"),
]


def next_ref(now: datetime | None = None) -> str:
    """``INC-<year>-<6 digits>``, sequential within the year.

    Derived from the highest existing ref rather than a counter row: a counter
    that drifts out of step with the table produces duplicate references, and
    a duplicate incident reference is a permanent ambiguity in an audit trail.
    """
    now = now or datetime.utcnow()
    prefix = f"INC-{now.year}-"
    last = (SentinelIncident.query
            .filter(SentinelIncident.ref.like(prefix + "%"))
            .order_by(SentinelIncident.ref.desc()).first())
    n = 0
    if last and last.ref:
        try:
            n = int(last.ref.rsplit("-", 1)[1])
        except (ValueError, IndexError):
            n = 0
    return f"{prefix}{n + 1:06d}"


def find_open(device: str, src_ip: str, attack_family: str,
              when: datetime | None = None) -> "SentinelIncident | None":
    """The live incident this event belongs to, if any."""
    when = when or datetime.utcnow()
    cutoff = when - timedelta(minutes=int(config.get("absorb_minutes")))
    return (SentinelIncident.query
            .filter(SentinelIncident.status.in_([SentinelIncident.STATUS_OPEN,
                                                 SentinelIncident.STATUS_VERIFYING]),
                    SentinelIncident.device == device,
                    SentinelIncident.src_ip == src_ip,
                    SentinelIncident.attack_family == attack_family,
                    SentinelIncident.last_event_at >= cutoff)
            .order_by(SentinelIncident.last_event_at.desc())
            .first())


def timeline_add(inc: "SentinelIncident", kind: str, text: str, *,
                 layer: str = "", ts: datetime | None = None,
                 ref_table: str = "", ref_id: int | None = None) -> None:
    db.session.add(SentinelIncidentEvent(
        incident_id=inc.id, ts=ts or datetime.utcnow(), kind=kind,
        layer=layer, text=text[:2000], ref_table=ref_table, ref_id=ref_id))


def open_incident(event: "SentinelEvent") -> "SentinelIncident":
    """Create an incident seeded from one event. Does not score it — scoring
    needs the window, and the window needs the incident to exist."""
    inc = SentinelIncident(
        ref=next_ref(event.ts), opened_at=event.ts or datetime.utcnow(),
        last_event_at=event.ts, status=SentinelIncident.STATUS_OPEN,
        appliance_id=event.appliance_id, device=event.device or "",
        policy=event.policy or "", src_ip=event.src_ip or "",
        src_country=event.country or "", attack_family=event.attack_family or "",
        severity=event.severity or "", event_count=0)
    db.session.add(inc)
    db.session.flush()      # need the id for the timeline row
    timeline_add(inc, "decision",
                 f"Incident opened from {event.signature or event.attack_family} "
                 f"on {event.device}", ts=event.ts)
    return inc


def attach(inc: "SentinelIncident", event: "SentinelEvent") -> None:
    """Bind one event to an incident and refresh the incident's counters."""
    event.incident_id = inc.id
    inc.last_event_at = max(filter(None, [inc.last_event_at, event.ts]))
    inc.event_count = (inc.event_count or 0) + (event.count or 1)
    if event.blocked:
        inc.blocked_count = (inc.blocked_count or 0) + (event.count or 1)
    else:
        inc.passed_count = (inc.passed_count or 0) + (event.count or 1)
    from ...models_sentinel import SentinelEvent as E
    if E.SEVERITY_RANK.get(event.severity or "", 0) > \
       E.SEVERITY_RANK.get(inc.severity or "", 0):
        inc.severity = event.severity


def _clear_evidence(inc: "SentinelIncident") -> None:
    """Drop the previous correlation's evidence THROUGH the session.

    A bulk ``delete(synchronize_session=False)`` leaves the deleted rows in
    SQLAlchemy's identity map, so the replacement rows written moments later
    reuse those primary keys and the flush warns that it is overwriting a live
    identity. It happens to work; it also means ``inc.evidence`` can serve a
    stale row to whatever reads it between the delete and the commit — and the
    thing that reads it is the AI prompt builder. Deleting through the
    relationship keeps the session's view of the incident true at every point.
    """
    for row in list(inc.evidence):
        db.session.delete(row)
    db.session.flush()


def _evidence_rows(inc: "SentinelIncident", ctx, verdict: dict) -> list:
    """Build the evidence table. Every row carries value AND baseline.

    "CPU is high" is an assertion. "CPU 91% against a Tuesday-12h median of
    22% (4.1x)" is evidence, and only the second can be disagreed with — which
    is the property that makes the console defensible in a review.
    """
    rows = []

    def ev(layer, claim, **kw):
        rows.append(SentinelEvidence(incident_id=inc.id, layer=layer,
                                     claim=claim[:2000], **kw))

    ev("attack",
       f"{ctx.event_count} event(s) of family '{ctx.attack_family}', worst "
       f"severity {ctx.worst_severity}; {ctx.blocked_count} stopped by the "
       f"appliance, {ctx.passed_count} not stopped",
       value=float(ctx.event_count),
       window=f"T-{config.get('window_pre_s')}s..T+{config.get('window_post_s')}s",
       weight_hint="supports" if ctx.passed_count else "undermines")

    http = ctx.http or {}
    if http.get("total"):
        ev("http_status",
           "response classes in the window: " +
           ", ".join(f"{k} {v}" for k, v in sorted(http["classes"].items()) if v),
           weight_hint="context")
        rows[-1].detail = {"classes": http["classes"], "codes": http["codes"]}
    if http.get("evasion_suspected"):
        ev("http_status",
           f"{http['success_on_attack']} request(s) carrying an attack "
           f"signature were answered 2xx and not blocked — the appliance did "
           f"not stop them",
           value=float(http["success_on_attack"]), weight_hint="supports")
    if http.get("enumeration_suspected"):
        ev("http_status",
           f"{http['distinct_uris']} distinct URIs probed with 4xx responses "
           f"— enumeration rather than exploitation",
           value=float(http["distinct_uris"]), weight_hint="context")
    if (http.get("server_error_pct") or 0) >= 20:
        ev("backend",
           f"{http['server_error_pct']}% of responses in the window were 5xx",
           value=float(http["server_error_pct"]), unit="%",
           weight_hint="supports")

    for reading in ctx.readings:
        if not reading.usable:
            continue
        if not reading.anomalous and abs(reading.deviation) < 1.0:
            continue
        ev(reading.layer,
           scoring._delta_text(reading),
           value=reading.peak, baseline=reading.median,
           deviation=round(reading.deviation, 2), unit=reading.unit,
           window=f"T0..T+{config.get('window_post_s')}s",
           weight_hint="supports" if reading.anomalous else "context")

    chain = ctx.causal_chain
    if len(chain) >= 2:
        ev("correlation",
           "layers moved in order after T0: " +
           " → ".join(f"{r.label} (+{r.lag_s:g}s)" for r in chain),
           weight_hint="supports")

    src = ctx.source or {}
    if src.get("trusted"):
        ev("context",
           f"source {src.get('ip')} is a registered "
           f"{src.get('trusted_kind') or 'trusted'} source"
           + (f" ({src['trusted_label']})" if src.get("trusted_label") else "")
           + (f", authorisation expires {src['trusted_expires']}"
              if src.get("trusted_expires") else " with NO expiry set"),
           weight_hint="undermines")
    if src.get("maintenance"):
        ev("context",
           "inside maintenance window: " +
           ", ".join(src.get("maintenance_labels") or []),
           weight_hint="undermines")
    if src.get("protected"):
        ev("context",
           f"source {src.get('ip')} is inside a protected network — no "
           f"blocking action may ever target it",
           weight_hint="context")

    v = ctx.vuln or {}
    for item in (v.get("cves") or []):
        bits = [item["cve"]]
        if item.get("cvss") is not None:
            bits.append(f"CVSS {item['cvss']}")
        if item.get("epss") is not None:
            bits.append(f"EPSS {item['epss']}")
        if item.get("in_kev"):
            bits.append("on the CISA KEV list")
        elif item.get("exploit_available"):
            bits.append("public exploit available")
        bits.append("affects this target" if item.get("cpe_matched")
                    else ("does NOT affect the recorded product"
                          if v.get("cpe_known") else
                          "applicability unknown (no product recorded)"))
        if item.get("stale"):
            bits.append("mirror entry is STALE")
        ev("vuln", " · ".join(bits),
           value=item.get("cvss"),
           weight_hint=("supports" if item.get("cpe_matched")
                        else "undermines" if v.get("cpe_known") else "context"))
        rows[-1].detail = item

    for note in (verdict.get("notes") or []):
        ev("caveat", note, weight_hint="context")
    return rows


def rescore(inc: "SentinelIncident", ctx=None) -> dict:
    """Recorrelate and re-score an incident from live data.

    Idempotent by construction: evidence is replaced, the score is recomputed
    from scratch, and the timeline gains exactly one entry recording that the
    re-score happened. Running it twice on unchanged data yields the same
    incident, which is the property that lets an operator press the button
    without wondering what it accumulated.
    """
    if ctx is None:
        ctx = correlate.build(inc.device, inc.src_ip, inc.attack_family,
                              inc.last_event_at or inc.opened_at,
                              appliance_id=inc.appliance_id)
    verdict = scoring.score_context(ctx)

    inc.score = verdict["score"]
    inc.confidence = verdict["confidence"]
    inc.score_factors = verdict["factors"]
    impact = verdict["impact"]
    inc.impact_fortinet = impact.get("box")
    inc.impact_vm = impact.get("vm")
    inc.impact_host = impact.get("host")
    inc.impact_backend = impact.get("backend")
    inc.window_start, inc.window_end = ctx.start, ctx.end
    inc.src_trusted = bool((ctx.source or {}).get("trusted"))
    inc.waf_blocked = bool(ctx.blocked_count and not ctx.passed_count)
    v = ctx.vuln or {}
    inc.exploit_available = bool(v.get("exploit_available"))
    inc.target_vulnerable = bool(v.get("target_vulnerable"))
    if (ctx.source or {}).get("trusted"):
        inc.src_trusted = True

    _clear_evidence(inc)
    for row in _evidence_rows(inc, ctx, verdict):
        db.session.add(row)

    for reading in ctx.readings:
        if reading.anomalous:
            db.session.add(SentinelAnomaly(
                ts=reading.peak_at or ctx.t0, series_key=reading.series_key,
                layer=reading.layer, device=inc.device, value=reading.peak,
                baseline=reading.median, deviation=round(reading.deviation, 2),
                ratio=round(reading.ratio, 2), incident_id=inc.id))

    timeline_add(inc, "decision",
                 f"Scored {verdict['score']}/100 ({scoring.band_of(verdict['score'])}) "
                 f"from {len(verdict['factors'])} factor(s)")
    return {"context": ctx, "verdict": verdict}


def ingest_event(event: "SentinelEvent") -> "SentinelIncident | None":
    """Route one normalised event to a new or existing incident.

    Returns ``None`` when the event is below the configured severity floor —
    the event is still stored, because "we saw it and chose not to escalate"
    must remain answerable months later.
    """
    from ...models_sentinel import SentinelEvent as E
    floor = E.SEVERITY_RANK.get(str(config.get("min_severity")).lower(), 0)
    if E.SEVERITY_RANK.get(event.severity or "", 0) < floor:
        return None

    inc = find_open(event.device or "", event.src_ip or "",
                    event.attack_family or "", event.ts)
    if inc is None:
        inc = open_incident(event)
    attach(inc, event)
    timeline_add(inc, "attack",
                 f"{event.signature or event.attack_family} from "
                 f"{event.src_ip} → {event.uri or event.dst_ip} "
                 f"[{event.action or 'no action'}]",
                 layer="attack", ts=event.ts,
                 ref_table="sentinel_event", ref_id=event.id)
    return inc


def close(inc: "SentinelIncident", status: str, *, by: str = "",
          note: str = "", fp_reason: str = "") -> "SentinelIncident":
    """Terminate an incident.

    ``false_positive`` REQUIRES a reason. A dismissal without a cause is a
    silent vote to keep generating the same alert forever — it removes the row
    and preserves the defect.
    """
    if status not in SentinelIncident.STATUSES:
        raise ValueError(f"unknown status {status!r}")
    if status == SentinelIncident.STATUS_FALSE_POSITIVE and not fp_reason:
        raise ValueError("a false positive must record why it was one")
    inc.status = status
    inc.closed_at = datetime.utcnow()
    inc.closed_by = by or ""
    inc.resolution_note = note or ""
    inc.fp_reason = fp_reason or ""
    timeline_add(inc, "decision",
                 f"Closed as {status}" + (f" ({fp_reason})" if fp_reason else "")
                 + (f" by {by}" if by else ""))
    return inc


def similar(inc: "SentinelIncident", limit: int = 5) -> list:
    """Historical incidents resembling this one.

    Structured similarity — same family, same source or same ASN or same
    target — rather than text similarity over an AI narrative. The narrative is
    a model's prose about the incident; matching on it would make history a
    function of what a model happened to write, which is not a property of the
    attack.
    """
    q = (SentinelIncident.query
         .filter(SentinelIncident.id != inc.id,
                 SentinelIncident.attack_family == inc.attack_family)
         .order_by(SentinelIncident.opened_at.desc())
         .limit(200).all())
    scored = []
    for other in q:
        s = 0.4                                     # same family is the floor
        if other.src_ip and other.src_ip == inc.src_ip:
            s += 0.35
        if other.device and other.device == inc.device:
            s += 0.15
        if other.policy and other.policy == inc.policy:
            s += 0.10
        scored.append((s, other))
    scored.sort(key=lambda p: (-p[0], p[1].opened_at and -p[1].opened_at.timestamp()))
    out = []
    for s, other in scored[:limit]:
        out.append({"ref": other.ref, "id": other.id,
                    "similarity": round(min(s, 1.0), 2),
                    "status": other.status, "score": other.score,
                    "opened_at": other.opened_at.isoformat(timespec="seconds")
                                 if other.opened_at else "",
                    "fp_reason": other.fp_reason or ""})
    return out


def stats(days: int = 7) -> dict:
    """Console headline numbers.

    ``false_positive_rate`` is computed over CLOSED incidents only. Including
    still-open ones would make the rate improve every time an operator falls
    behind, which is the opposite of what the number is for.
    """
    since = datetime.utcnow() - timedelta(days=max(1, days))
    rows = SentinelIncident.query.filter(SentinelIncident.opened_at >= since).all()
    closed = [r for r in rows if r.status in (SentinelIncident.STATUS_CLOSED,
                                              SentinelIncident.STATUS_MITIGATED,
                                              SentinelIncident.STATUS_FALSE_POSITIVE)]
    fps = [r for r in closed if r.status == SentinelIncident.STATUS_FALSE_POSITIVE]
    by_band: dict = {}
    by_family: dict = {}
    for r in rows:
        by_band[r.band] = by_band.get(r.band, 0) + 1
        by_family[r.attack_family or "other"] = \
            by_family.get(r.attack_family or "other", 0) + 1
    return {
        "days": days, "total": len(rows),
        "open": sum(1 for r in rows if r.open),
        "closed": len(closed), "false_positives": len(fps),
        "false_positive_rate": round(100.0 * len(fps) / len(closed), 1)
                               if closed else None,
        "by_band": by_band, "by_family": by_family,
        "max_score": max((r.score or 0 for r in rows), default=0),
    }
