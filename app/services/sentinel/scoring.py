"""Deterministic risk scoring. The number a model may never touch.

The rule
--------
The score is produced here, by ordinary arithmetic over measured evidence, and
nothing else in this system may change it. The AI layer may disagree with it in
prose; that disagreement is displayed, not resolved in the model's favour. The
reason is not distrust of models in general — it is that this number gates
changes to a production firewall, and a gate whose value depends on a sampled
distribution cannot be reproduced during the post-mortem that follows the one
time it was wrong.

Negative factors are half the value
-----------------------------------
Most of the industry's scoring designs only add. This one subtracts, and the
subtractions are what make the number usable:

* ``waf_blocked`` — the appliance stopped it. A thousand blocked SQLi attempts
  is a WAF doing its job, and paging someone for it teaches them to ignore the
  console.
* ``not_vulnerable`` — the CVE behind the signature does not affect what the
  backend actually runs. A perfectly executed exploit aimed at software nobody
  is running is noise.
* ``trusted_source`` / ``maintenance`` — the authorised scanner case, which
  produces a byte-identical attack log to a real intrusion. Only context can
  separate them, so context is worth more than any single positive factor.

Weights are data, not code
--------------------------
:data:`WEIGHTS` is a plain dict so it can be tuned against the scenario suite
rather than by argument, and so a change to it is a one-line diff a reviewer
can see. Every applied factor is recorded WITH its points on the incident, so
the score is self-explaining: there is no path by which an operator sees a
number without the reasons.
"""
from __future__ import annotations

WEIGHTS: dict[str, int] = {
    # ── positive: the attack itself ──────────────────────────────────────
    "severity_critical": 30,
    "severity_high": 24,
    "severity_medium": 14,
    "severity_low": 6,
    "volume_burst": 8,          # many events in one window
    # ── positive: behaviour ──────────────────────────────────────────────
    "traffic_anomaly": 15,
    # The strongest single signal in the model, and deliberately worth more
    # than the worst severity band: severity says how bad the attempt WOULD
    # be, evasion says the defence did not stop it. Raised from 20 to 25 after
    # scenario 3 (one unblocked SQLi answered 200, no measurable impact yet)
    # scored 39 and fell one point below the investigate floor — an evaded
    # attack that the console files under "observe" is the exact miss this
    # layer exists to prevent.
    "http_evasion": 25,         # 2xx on a request carrying an attack signature
    "http_enumeration": 6,
    "backend_errors": 10,       # 5xx surge behind the policy
    # ── positive: impact ─────────────────────────────────────────────────
    "box_anomaly": 10,
    "backend_anomaly": 10,
    "vm_anomaly": 10,
    "host_anomaly": 8,
    "causal_chain": 8,          # layers moved in a plausible order after T0
    # ── positive: corroboration at the border ────────────────────────────
    # The firewall in front logged the same source in the same window. Worth
    # more than a single internal layer because it is INDEPENDENT: every other
    # positive factor above is ultimately derived from the same appliance's
    # view of the same traffic. It also matters most where it is needed most —
    # an installation with no hypervisor access loses up to 18 points it can
    # never recover, and this is the layer such an installation usually DOES
    # have. There is no matching negative: see edge.py, silence at the border
    # is a fact about addressing, not about hostility.
    "edge_corroboration": 12,
    "edge_multi_target": 10,    # the border saw it reach many destinations
    # ── positive: vulnerability intelligence ─────────────────────────────
    "exploit_available": 15,
    "target_vulnerable": 15,
    "cve_known": 4,
    # ── negative ─────────────────────────────────────────────────────────
    "waf_blocked": -12,
    "not_vulnerable": -10,
    "trusted_source": -35,
    "maintenance_window": -15,
    "baseline_immature": -5,    # we could not judge behaviour; claim less
}

#: A factor may be applied at most once per incident. Enforced structurally by
#: building a dict, not by discipline: an "add points per matching event" loop
#: is how a flood scores 4,000 and every incident collapses into the same band.
MAX_SCORE = 100
MIN_SCORE = 0


def _sev_factor(sev: str) -> str | None:
    return {"critical": "severity_critical", "high": "severity_high",
            "medium": "severity_medium", "low": "severity_low"}.get(
                (sev or "").lower())


def score_context(ctx) -> dict:
    """Score one :class:`~app.services.sentinel.correlate.WindowContext`.

    Returns ``{score, confidence, factors, impact, notes}``. ``impact`` carries
    ``None`` for a layer that could not be judged — this function never turns
    "we could not look" into "no impact", because those two drive opposite
    operator decisions.
    """
    factors: list = []

    def add(name: str, detail: str = ""):
        pts = WEIGHTS.get(name, 0)
        if any(f["factor"] == name for f in factors):
            return
        factors.append({"factor": name, "points": pts, "detail": detail})

    # ── the attack ───────────────────────────────────────────────────────
    sev = ctx.worst_severity
    sev_factor = _sev_factor(sev)
    if sev_factor:
        add(sev_factor, f"worst event severity: {sev}")
    if ctx.event_count >= 50:
        add("volume_burst", f"{ctx.event_count} events in the window")

    # ── behaviour ────────────────────────────────────────────────────────
    http = ctx.http or {}
    if http.get("evasion_suspected"):
        add("http_evasion",
            f"{http.get('success_on_attack')} request(s) carrying an attack "
            f"signature answered 2xx and were not blocked")
    if http.get("enumeration_suspected"):
        add("http_enumeration",
            f"{http.get('distinct_uris')} distinct URIs with 4xx responses")
    if (http.get("server_error_pct") or 0) >= 20:
        add("backend_errors",
            f"{http.get('server_error_pct')}% of responses in the window were 5xx")

    traffic = ctx.layer_anomalous("traffic")
    if traffic:
        w = ctx.worst("traffic")
        add("traffic_anomaly", _delta_text(w))

    # ── impact per layer ─────────────────────────────────────────────────
    impact = {}
    for layer, factor in (("box", "box_anomaly"), ("backend", "backend_anomaly"),
                          ("vm", "vm_anomaly"), ("host", "host_anomaly")):
        verdict = ctx.layer_anomalous(layer)
        impact[layer] = verdict
        if verdict:
            add(factor, _delta_text(ctx.worst(layer)))

    chain = ctx.causal_chain
    if len(chain) >= 2:
        add("causal_chain",
            " → ".join(f"{r.label} (+{r.lag_s:g}s)" for r in chain[:5]))

    # ── corroboration at the border ──────────────────────────────────────
    edge = ctx.edge or {}
    if edge.get("corroborated"):
        add("edge_corroboration",
            f"the border logged {edge.get('hits')} entry/entries from this "
            f"source in the window ({edge.get('scope') or 'mapped collector'})")
        if edge.get("multi_target"):
            add("edge_multi_target",
                f"the same source reached {edge.get('distinct_dst')} distinct "
                f"destination(s) at the border in the window")

    # ── vulnerability intelligence ───────────────────────────────────────
    v = ctx.vuln or {}
    if v.get("enabled") and v.get("cves"):
        worst_cve = v.get("worst") or {}
        add("cve_known", f"{len(v['cves'])} CVE(s) resolved from the local mirror")
        if v.get("exploit_available"):
            add("exploit_available",
                f"{worst_cve.get('cve', '')} "
                f"{'is on the CISA KEV list' if worst_cve.get('in_kev') else 'has a public exploit'}")
        if v.get("target_vulnerable"):
            add("target_vulnerable",
                f"{worst_cve.get('cve', '')} affects the product recorded for "
                f"this target")
        elif v.get("cpe_known"):
            add("not_vulnerable",
                "no resolved CVE matches the product recorded for this target")

    # ── negatives ────────────────────────────────────────────────────────
    blocked, passed = ctx.blocked_count, ctx.passed_count
    if blocked and passed == 0:
        add("waf_blocked",
            f"every one of the {blocked} request(s) was stopped by the appliance")
    src = ctx.source or {}
    if src.get("trusted"):
        add("trusted_source",
            f"source is a registered {src.get('trusted_kind') or 'trusted'} "
            f"source ({src.get('trusted_label') or src.get('ip')})")
    if src.get("maintenance"):
        add("maintenance_window",
            "inside maintenance window: " +
            ", ".join(src.get("maintenance_labels") or []))
    if not any(r.usable for r in ctx.readings):
        add("baseline_immature",
            "no usable behavioural baseline in this window — behaviour could "
            "not be judged")

    raw = sum(f["points"] for f in factors)
    score = max(MIN_SCORE, min(MAX_SCORE, raw))
    return {
        "score": score, "raw": raw, "confidence": round(score / 100.0, 2),
        "factors": factors, "impact": impact,
        "notes": _notes(ctx, factors),
    }


def _delta_text(reading) -> str:
    if reading is None:
        return ""
    med = "?" if reading.median is None else f"{reading.median:g}"
    peak = "?" if reading.peak is None else f"{reading.peak:g}"
    return (f"{reading.label} {peak}{reading.unit} vs baseline {med}"
            f"{reading.unit} ({reading.ratio:.1f}x, z={reading.deviation:.1f})")


def _notes(ctx, factors) -> list:
    """Caveats that belong ON the score, not in a footnote nobody reads."""
    notes = []
    if ctx.layers_unknown:
        notes.append("layer(s) not evaluated (no topology mapping or store "
                     "unavailable): " + ", ".join(sorted(set(ctx.layers_unknown))))
    if not ctx.store_ok:
        notes.append("metrics store unreachable — every behavioural factor is "
                     "absent from this score, not zero")
    edge = getattr(ctx, "edge", None) or {}
    if edge.get("enabled") and not edge.get("checked"):
        notes.append("border layer not evaluated (" +
                     (edge.get("error") or edge.get("reason") or "no answer") +
                     ") — this is not the same as the border reporting nothing")
    elif edge.get("checked") and not edge.get("corroborated"):
        notes.append("the border never logged this address as a source; it is "
                     "most likely a client behind a proxy or CDN, so a border "
                     "blocklist entry would not act on the attacker")
    v = ctx.vuln or {}
    if v.get("stale"):
        notes.append("vulnerability mirror is stale; exploit data may be out of date")
    if v.get("missing"):
        notes.append(f"{len(v['missing'])} CVE(s) referenced by the device are "
                     f"not in the local mirror: " + ", ".join(v["missing"][:5]))
    if v.get("enabled") and v.get("cves") and not v.get("cpe_known"):
        notes.append("no product recorded for this target, so CVE applicability "
                     "could not be checked")
    return notes


def band_of(score: int) -> str:
    from ...models_sentinel import SentinelIncident as I
    if score >= I.BAND_SEMI_AUTO:
        return "semi_auto"
    if score >= I.BAND_RECOMMEND:
        return "recommend"
    if score >= I.BAND_OBSERVE:
        return "investigate"
    return "observe"


def explain() -> list:
    """The weight table, for the documentation page and the Settings console.

    Rendered from the same dict the scorer uses, so the published explanation
    cannot drift from the arithmetic — the class of staleness that let
    ``Version: 1.0`` survive four releases in this repo.
    """
    labels = {
        "severity_critical": "Attack severity — critical",
        "severity_high": "Attack severity — high",
        "severity_medium": "Attack severity — medium",
        "severity_low": "Attack severity — low",
        "volume_burst": "Event volume burst (50+ in the window)",
        "traffic_anomaly": "Traffic deviates from its hour-of-week baseline",
        "http_evasion": "2xx returned on a request carrying an attack signature",
        "http_enumeration": "Many distinct URIs answered 4xx (enumeration)",
        "backend_errors": "5xx surge behind the policy",
        "box_anomaly": "Appliance internals deviate (CPU / memory / sessions)",
        "backend_anomaly": "Backend round-trip time deviates",
        "vm_anomaly": "Virtual machine metrics deviate",
        "host_anomaly": "Hypervisor host metrics deviate",
        "causal_chain": "Two or more layers moved in order after T0",
        "edge_corroboration": "The firewall in front independently logged this "
                              "source in the window",
        "edge_multi_target": "The border saw this source reach many distinct "
                             "destinations (scanning)",
        "exploit_available": "A resolved CVE is exploited in the wild (KEV) or "
                             "has a public exploit",
        "target_vulnerable": "A resolved CVE affects the product this target runs",
        "cve_known": "At least one CVE resolved from the local mirror",
        "waf_blocked": "Every request in the window was stopped by the appliance",
        "not_vulnerable": "No resolved CVE affects the product this target runs",
        "trusted_source": "Source is a registered trusted source",
        "maintenance_window": "Window falls inside a maintenance window",
        "baseline_immature": "No usable baseline — behaviour could not be judged",
    }
    rows = [{"factor": k, "points": v, "label": labels.get(k, k),
             "sign": "positive" if v > 0 else "negative"}
            for k, v in WEIGHTS.items()]
    rows.sort(key=lambda r: (-r["points"], r["factor"]))
    return rows
