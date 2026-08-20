"""Sentinel — the ten scenarios, plus the guards that keep them honest.

Every scenario is a fixture: a set of events plus a stubbed correlation window,
run through the REAL scorer and the REAL incident engine. The assertions are on
BANDS and on which factors fired, not on exact totals — a weight tune must be
free to move a number without breaking the suite, but must never be free to
turn "the WAF blocked everything" into a high-confidence attack.

The three assertions that matter most, because each of them encodes a mistake
that is easy to make and expensive to ship:

1. ``test_scenario_06_authorised_scanner`` — identical attack evidence to a
   real intrusion, scored down to observe purely by context.
2. ``test_scenario_10_waf_blocked_is_not_an_emergency`` — a wall of blocked
   attacks does not page anyone.
3. ``test_evasion_outranks_volume`` — one 200 on an attack request outranks
   thousands of blocked ones.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.models import db
from app.models_sentinel import (SentinelEvent, SentinelIncident,
                                 SentinelMaintenanceWindow, SentinelPolicy,
                                 SentinelTrustedSource, SentinelVuln)
from app.services.sentinel import (actions, ai, baseline, config, correlate,
                                   enrich, incident, normalize, scoring)

T0 = datetime(2026, 8, 18, 12, 0, 0)          # a Tuesday, noon


# --------------------------------------------------------------------------- #
#  Builders                                                                     #
# --------------------------------------------------------------------------- #
def mk_event(**kw) -> SentinelEvent:
    base = dict(ts=T0, device="fortiweb12", source="attack_log",
                policy="pol-root-shop", src_ip="185.10.20.30", country="RU",
                http_method="GET", uri="/admin.php", http_status=403,
                signature_id="080200001", signature="SQL Injection",
                attack_family="sqli", severity="high", action="deny", count=1)
    base.update(kw)
    ev = SentinelEvent(**base)
    ev.dedup_key = f"k{id(ev)}"
    return ev


def mk_reading(layer, label, *, peak, median, unit="%", lag=None,
               anomalous=True, usable=True) -> correlate.LayerReading:
    r = correlate.LayerReading(layer=layer, metric=f"m_{layer}", label=label,
                               unit=unit, series_key=f"m_{layer}{{}}")
    r.peak, r.median, r.usable, r.anomalous = peak, median, usable, anomalous
    r.deviation = baseline.deviation(peak, median, max(median * 0.1, 0.1))
    r.ratio = baseline.ratio(peak, median)
    r.lag_s = lag
    r.peak_at = T0 + timedelta(seconds=lag or 0)
    return r


def mk_ctx(events, readings=(), *, source=None, vuln=None, unknown=(),
           store_ok=True) -> correlate.WindowContext:
    ctx = correlate.WindowContext(
        device="fortiweb12", src_ip="185.10.20.30", attack_family="sqli",
        t0=T0, start=T0 - timedelta(seconds=60), end=T0 + timedelta(seconds=300),
        events=list(events), readings=list(readings),
        layers_unknown=list(unknown), store_ok=store_ok)
    ctx.source = source if source is not None else {
        "ip": "185.10.20.30", "trusted": False, "protected": False,
        "maintenance": False, "maintenance_labels": [], "asn_known": False}
    ctx.http = correlate.http_picture(ctx.events)
    ctx.vuln = vuln if vuln is not None else {
        "enabled": True, "cves": [], "worst": None, "exploit_available": False,
        "target_vulnerable": False, "cpe_known": False, "stale": False,
        "missing": []}
    return ctx


def band(ctx) -> str:
    return scoring.band_of(scoring.score_context(ctx)["score"])


def fired(ctx) -> set:
    return {f["factor"] for f in scoring.score_context(ctx)["factors"]}


# --------------------------------------------------------------------------- #
#  The ten scenarios                                                            #
# --------------------------------------------------------------------------- #
def test_scenario_01_normal_traffic_opens_nothing(app):
    """No attack events at all — nothing to score, nothing to open."""
    with app.app_context():
        ctx = mk_ctx([])
        assert scoring.score_context(ctx)["score"] == 0
        assert band(ctx) == "observe"


def test_scenario_02_legitimate_spike_without_signatures(app):
    """Traffic far above baseline, appliance working harder, ZERO attack events.

    This must not become an incident: load is not an attack, and a detector
    that cannot tell them apart is a capacity alarm wearing a security badge.
    """
    with app.app_context():
        ctx = mk_ctx([], [mk_reading("traffic", "throughput", peak=4500,
                                     median=300, unit="Mbps", lag=1),
                          mk_reading("box", "appliance CPU", peak=70,
                                     median=25, lag=3)])
        result = scoring.score_context(ctx)
        assert not any(f["factor"].startswith("severity") for f in result["factors"])
        assert result["score"] < SentinelIncident.BAND_RECOMMEND


def test_scenario_03_sqli_no_impact(app):
    """A real signature, no measurable impact anywhere → investigate, not act."""
    with app.app_context():
        ctx = mk_ctx([mk_event(action="alert", http_status=200)])
        assert band(ctx) in ("investigate", "recommend")
        assert "http_evasion" in fired(ctx)


def test_scenario_04_high_rate_scanner(app):
    """Enumeration: many distinct URIs, 4xx answers, high volume."""
    with app.app_context():
        events = [mk_event(uri=f"/probe-{i}.php", http_status=404,
                           attack_family="scanner", severity="medium",
                           action="alert") for i in range(60)]
        ctx = mk_ctx(events)
        f = fired(ctx)
        assert "http_enumeration" in f and "volume_burst" in f


def test_scenario_05_dos_like_reaches_the_top_band(app):
    """Attack + traffic + appliance + VM + backend, in causal order."""
    with app.app_context():
        events = [mk_event(severity="critical", action="alert",
                           http_status=200) for _ in range(80)]
        readings = [
            mk_reading("traffic", "throughput", peak=4500, median=300,
                       unit="Mbps", lag=1),
            mk_reading("box", "appliance CPU", peak=91, median=22, lag=2),
            mk_reading("vm", "VM CPU", peak=88, median=30, lag=3),
            mk_reading("backend", "backend RTT", peak=528, median=120,
                       unit="ms", lag=8),
        ]
        ctx = mk_ctx(events, readings)
        result = scoring.score_context(ctx)
        assert result["score"] >= SentinelIncident.BAND_SEMI_AUTO
        assert "causal_chain" in {f["factor"] for f in result["factors"]}
        assert [r.layer for r in ctx.causal_chain] == \
               ["traffic", "box", "vm", "backend"]


def test_scenario_06_authorised_scanner(app):
    """THE false-positive case. Same evidence as an intrusion; different verdict.

    An authorised scanner inside its own maintenance window produces a
    byte-identical attack log to a real attacker. Only context separates them,
    which is why context outweighs every positive factor here.
    """
    with app.app_context():
        events = [mk_event(severity="critical", action="alert",
                           http_status=200) for _ in range(80)]
        readings = [mk_reading("traffic", "throughput", peak=4500, median=300,
                               unit="Mbps", lag=1)]
        hostile = mk_ctx(events, readings)
        friendly = mk_ctx(events, readings, source={
            "ip": "192.0.2.60", "trusted": True, "trusted_kind": "pentest",
            "trusted_label": "pentest LXC 213", "trusted_expires": "2026-09-01",
            "protected": True, "maintenance": True,
            "maintenance_labels": ["Q3 authorised pentest"], "asn_known": False})
        hostile_score = scoring.score_context(hostile)["score"]
        friendly_score = scoring.score_context(friendly)["score"]
        assert friendly_score < hostile_score - 40
        f = fired(friendly)
        assert "trusted_source" in f and "maintenance_window" in f


def test_scenario_07_attack_without_infrastructure_impact(app):
    """Infra layers measured and QUIET — that must lower, not raise, the score."""
    with app.app_context():
        quiet = [mk_reading("vm", "VM CPU", peak=31, median=30, anomalous=False),
                 mk_reading("host", "host CPU", peak=22, median=20,
                            anomalous=False)]
        ctx = mk_ctx([mk_event(action="alert", http_status=200)], quiet)
        f = fired(ctx)
        assert "vm_anomaly" not in f and "host_anomaly" not in f
        assert ctx.layer_anomalous("vm") is False


def test_scenario_08_appliance_cpu_saturation(app):
    with app.app_context():
        ctx = mk_ctx([mk_event(action="alert", http_status=200)],
                     [mk_reading("box", "appliance CPU", peak=97, median=22,
                                 lag=2)])
        assert "box_anomaly" in fired(ctx)
        assert scoring.score_context(ctx)["impact"]["box"] is True


def test_scenario_09_vm_exhaustion_visible_only_below_the_appliance(app):
    """The layer the appliance itself cannot see.

    The box looks fine; the VM it runs in is starved. Without the hypervisor
    layer this incident is invisible, which is the entire argument for the
    topology table.
    """
    with app.app_context():
        ctx = mk_ctx([mk_event(action="alert", http_status=200)],
                     [mk_reading("box", "appliance CPU", peak=26, median=25,
                                 anomalous=False),
                      mk_reading("vm", "VM CPU", peak=99, median=30, lag=4),
                      mk_reading("host", "host CPU", peak=95, median=35, lag=6)])
        impact = scoring.score_context(ctx)["impact"]
        assert impact["box"] is False
        assert impact["vm"] is True and impact["host"] is True


def test_scenario_10_waf_blocked_is_not_an_emergency(app):
    """A thousand attacks, every one stopped. This must not page anyone.

    Asserting only "score < 85" was not enough: a mutation flipping the weight
    from -12 to +12 still landed under the band and the test passed. So the
    claim is stated directly — the factor must SUBTRACT, and the identical
    attack that got through must score strictly higher.
    """
    with app.app_context():
        stopped = [mk_event(action="deny", http_status=403, severity="high")
                   for _ in range(200)]
        through = [mk_event(action="alert", http_status=403, severity="high")
                   for _ in range(200)]
        result = scoring.score_context(mk_ctx(stopped))
        factor = next(f for f in result["factors"] if f["factor"] == "waf_blocked")
        assert factor["points"] < 0, "blocking the attack must LOWER the score"
        assert result["score"] < SentinelIncident.BAND_SEMI_AUTO
        assert result["score"] < scoring.score_context(mk_ctx(through))["score"]


# --------------------------------------------------------------------------- #
#  The claims the scenarios rest on                                             #
# --------------------------------------------------------------------------- #
def test_evasion_outranks_volume(app):
    """One 200 on an attack request beats a flood of blocked ones.

    The first version of this compared a 200 against 500 DENIED requests, so
    it passed on the strength of ``waf_blocked`` alone — deleting the evasion
    weight entirely left it green. Both halves below are therefore
    ``action="alert"`` (neither is blocked, so ``waf_blocked`` fires in
    neither) and differ ONLY in the response code. That isolates the claim
    being made.
    """
    with app.app_context():
        refused = mk_ctx([mk_event(action="alert", http_status=403)
                          for _ in range(500)])
        evaded = mk_ctx([mk_event(action="alert", http_status=200)])
        names = lambda c: {f["factor"] for f in scoring.score_context(c)["factors"]}
        assert "waf_blocked" not in names(refused)
        assert "http_evasion" in names(evaded)
        assert "http_evasion" not in names(refused)
        assert scoring.score_context(evaded)["score"] > \
               scoring.score_context(refused)["score"], \
            "one evaded request must outrank a flood the origin refused"


def test_unknown_layer_is_not_no_impact(app):
    """``None`` must survive all the way to the incident's impact flags."""
    with app.app_context():
        ctx = mk_ctx([mk_event()], unknown=["vm", "host"])
        impact = scoring.score_context(ctx)["impact"]
        assert impact["vm"] is None and impact["host"] is None
        inc = SentinelIncident(ref="INC-T-1", device="fortiweb12",
                               impact_vm=None, impact_fortinet=True)
        assert inc.impact_dict()["vm"] == "unknown"
        assert inc.impact_dict()["fortinet"] is True


def test_learning_baseline_never_fires(app):
    """An immature bucket produces no deviation, whatever the sample."""
    with app.app_context():
        key = "satom_box_cpu_pct{device=fortiweb12}"
        baseline.upsert(key, baseline.dow_hour(T0), [20.0, 21.0])  # < MIN
        db.session.commit()
        verdict = baseline.evaluate(key, 99.0, T0)
        assert verdict["usable"] is False
        assert verdict["anomalous"] is False and verdict["deviation"] == 0.0


def test_mad_is_immune_to_a_past_spike(app):
    """The property the whole baseline choice rests on.

    With mean + sigma, one historical flood raises the centre and inflates the
    spread so the NEXT identical flood scores lower. Median + MAD must not do
    that — otherwise the detector desensitises itself with every incident.
    """
    with app.app_context():
        quiet = [20.0] * 40
        contaminated = quiet + [8000.0]
        assert baseline.median(contaminated) == baseline.median(quiet)
        dev_clean = baseline.deviation(
            8000.0, baseline.median(quiet), max(baseline.mad(quiet), 1.0))
        dev_dirty = baseline.deviation(
            8000.0, baseline.median(contaminated),
            max(baseline.mad(contaminated), 1.0))
        assert dev_dirty == pytest.approx(dev_clean)


def test_flat_series_cannot_produce_an_infinite_deviation(app):
    with app.app_context():
        assert baseline.deviation(5.0, 0.0, 0.0) == 5.0
        assert baseline.deviation(1e9, 0.0, 0.0) == 10.0     # capped
        assert baseline.deviation(0.0, 0.0, 0.0) == 0.0


def test_ratio_never_reports_infinity(app):
    with app.app_context():
        assert baseline.ratio(500.0, 0.0) == 0.0


# --------------------------------------------------------------------------- #
#  Incident lifecycle                                                           #
# --------------------------------------------------------------------------- #
def test_absorption_prevents_one_incident_per_request(app):
    """A flood must land in ONE incident, not one per event."""
    with app.app_context():
        for i in range(50):
            ev = mk_event(ts=T0 + timedelta(seconds=i))
            db.session.add(ev)
            db.session.flush()
            incident.ingest_event(ev)
        db.session.commit()
        assert SentinelIncident.query.count() == 1
        inc = SentinelIncident.query.one()
        assert inc.event_count == 50


def test_a_different_source_opens_its_own_incident(app):
    with app.app_context():
        for src in ("185.10.20.30", "185.10.20.31"):
            ev = mk_event(src_ip=src)
            db.session.add(ev)
            db.session.flush()
            incident.ingest_event(ev)
        db.session.commit()
        assert SentinelIncident.query.count() == 2


def test_below_the_severity_floor_the_event_is_kept_but_not_escalated(app):
    """Storing it matters: 'we saw it and chose not to escalate' must stay
    answerable months later."""
    with app.app_context():
        config.set_value("min_severity", "high")
        ev = mk_event(severity="low")
        db.session.add(ev)
        db.session.flush()
        assert incident.ingest_event(ev) is None
        db.session.commit()
        assert SentinelEvent.query.count() == 1
        assert SentinelIncident.query.count() == 0


def test_false_positive_requires_a_reason(app):
    with app.app_context():
        ev = mk_event()
        db.session.add(ev)
        db.session.flush()
        inc = incident.ingest_event(ev)
        db.session.commit()
        with pytest.raises(ValueError):
            incident.close(inc, SentinelIncident.STATUS_FALSE_POSITIVE)
        incident.close(inc, SentinelIncident.STATUS_FALSE_POSITIVE,
                       fp_reason="trusted_source", by="alice")
        db.session.commit()
        assert inc.status == "false_positive" and inc.fp_reason == "trusted_source"


def test_rescore_is_idempotent(app, monkeypatch):
    """Twice on unchanged data must give one incident, one evidence set."""
    with app.app_context():
        ev = mk_event()
        db.session.add(ev)
        db.session.flush()
        inc = incident.ingest_event(ev)
        db.session.commit()

        monkeypatch.setattr(correlate, "build",
                            lambda *a, **k: mk_ctx([ev]))
        incident.rescore(inc)
        db.session.commit()
        first = [e.claim for e in inc.evidence]
        incident.rescore(inc)
        db.session.commit()
        second = [e.claim for e in inc.evidence]
        assert sorted(first) == sorted(second)
        assert len(second) == len(set(second))


def test_incident_refs_are_sequential_and_unique(app):
    with app.app_context():
        refs = set()
        for i in range(5):
            ev = mk_event(src_ip=f"185.10.20.{i}")
            db.session.add(ev)
            db.session.flush()
            inc = incident.ingest_event(ev)
            db.session.commit()
            refs.add(inc.ref)
        assert len(refs) == 5
        assert all(r.startswith("INC-2026-") for r in refs)


def test_false_positive_rate_ignores_still_open_incidents(app):
    """Otherwise the metric improves whenever an operator falls behind."""
    with app.app_context():
        for i, status in enumerate(["open", "closed", "false_positive"]):
            db.session.add(SentinelIncident(
                ref=f"INC-2026-00000{i}", opened_at=datetime.utcnow(),
                status=status, device="fortiweb12", attack_family="sqli",
                fp_reason="noisy_signature" if status == "false_positive" else ""))
        db.session.commit()
        s = incident.stats(days=7)
        assert s["closed"] == 2 and s["false_positives"] == 1
        assert s["false_positive_rate"] == 50.0


# --------------------------------------------------------------------------- #
#  Vulnerability layer                                                          #
# --------------------------------------------------------------------------- #
def test_cve_not_matching_the_backend_lowers_the_score(app):
    """An exploit aimed at software nobody runs is noise."""
    with app.app_context():
        matched = mk_ctx([mk_event(action="alert", http_status=200)], vuln={
            "enabled": True, "cpe_known": True, "target_vulnerable": True,
            "exploit_available": True, "stale": False, "missing": [],
            "worst": {"cve": "CVE-2024-1234", "in_kev": True},
            "cves": [{"cve": "CVE-2024-1234", "in_kev": True,
                      "cpe_matched": True}]})
        unmatched = mk_ctx([mk_event(action="alert", http_status=200)], vuln={
            "enabled": True, "cpe_known": True, "target_vulnerable": False,
            "exploit_available": True, "stale": False, "missing": [],
            "worst": {"cve": "CVE-2024-1234", "in_kev": True},
            "cves": [{"cve": "CVE-2024-1234", "in_kev": True,
                      "cpe_matched": False}]})
        assert scoring.score_context(unmatched)["score"] < \
               scoring.score_context(matched)["score"]
        assert "not_vulnerable" in fired(unmatched)
        assert "target_vulnerable" in fired(matched)


def test_unknown_product_is_not_reported_as_not_vulnerable(app):
    """'We could not check' must never render as 'not affected'."""
    with app.app_context():
        ctx = mk_ctx([mk_event()], vuln={
            "enabled": True, "cpe_known": False, "target_vulnerable": False,
            "exploit_available": False, "stale": False, "missing": [],
            "worst": None, "cves": [{"cve": "CVE-2024-1234",
                                     "cpe_matched": False}]})
        f = fired(ctx)
        assert "not_vulnerable" not in f
        notes = scoring.score_context(ctx)["notes"]
        assert any("applicability" in n for n in notes)


def test_kev_outranks_a_higher_cvss(app):
    """Exploited-in-the-wild beats theoretical severity."""
    from app.services.sentinel import vuln as V
    with app.app_context():
        kev = {"cve": "CVE-2024-0002", "cvss": 7.5, "epss": 0.4, "in_kev": True,
               "exploit_available": True}
        scary = {"cve": "CVE-2024-0001", "cvss": 9.8, "epss": 0.01,
                 "in_kev": False, "exploit_available": False}
        assert V._rank(kev) > V._rank(scary)


def test_enrichment_never_leaves_the_node(app, monkeypatch):
    """The wall between the read path and the sync.

    Asserted rather than promised: any HTTP call from the enrichment path
    fails the test loudly.
    """
    from app.services.sentinel import vuln as V

    def explode(*a, **k):
        raise AssertionError("the incident path opened a network connection")

    with app.app_context():
        monkeypatch.setattr(V.urllib.request, "urlopen", explode)
        monkeypatch.setattr(V, "_fetch_json", explode)
        V.upsert("CVE-2024-1234", cvss=9.8, in_kev=True,
                 affected_cpe=["cpe:2.3:a:apache:http_server:2.4.49"])
        db.session.commit()
        out = V.enrich_cves(["CVE-2024-1234"],
                            cpe_hints=["apache:http_server"])
        assert out["target_vulnerable"] is True
        assert out["exploit_available"] is True


def test_sync_refuses_to_run_when_the_switch_is_off(app):
    from app.services.sentinel import vuln as V
    with app.app_context():
        config.set_value("vuln_sync_enabled", False)
        res = V.sync(["CVE-2024-1234"])
        assert res["ok"] is False and "disabled" in res["reason"]


def test_cpe_match_is_substring_both_ways(app):
    """A short asset hint must match a long version-qualified CPE."""
    from app.services.sentinel import vuln as V
    with app.app_context():
        assert V._cpe_match(
            ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
            ["apache:http_server"]) is True
        assert V._cpe_match(["cpe:2.3:a:nginx:nginx:1.24.0"],
                            ["apache:http_server"]) is False


# --------------------------------------------------------------------------- #
#  Trust and maintenance                                                        #
# --------------------------------------------------------------------------- #
def test_expired_trust_does_not_trust(app):
    """Expiry is enforced on read, not by a cleanup job that might not run."""
    with app.app_context():
        db.session.add(SentinelTrustedSource(
            cidr="203.0.113.0/24", kind="scanner", label="old pentest",
            expires_at=datetime.utcnow() - timedelta(days=1)))
        db.session.add(SentinelTrustedSource(
            cidr="198.51.100.0/24", kind="monitor", label="live monitor",
            expires_at=datetime.utcnow() + timedelta(days=1)))
        db.session.commit()
        assert enrich.trusted_match("203.0.113.5") is None
        assert enrich.trusted_match("198.51.100.5") is not None


def test_a_malformed_trust_entry_cannot_trust_everything(app):
    with app.app_context():
        db.session.add(SentinelTrustedSource(cidr="not-a-cidr", kind="scanner"))
        db.session.commit()
        assert enrich.trusted_match("185.10.20.30") is None


def test_maintenance_freezes_baseline_but_not_detection(app):
    with app.app_context():
        db.session.add(SentinelMaintenanceWindow(
            label="Q3 pentest", starts_at=T0 - timedelta(hours=1),
            ends_at=T0 + timedelta(hours=1), suppress_actions=True,
            freeze_baseline=True))
        db.session.commit()
        assert enrich.baseline_frozen(T0, "fortiweb12") is True
        assert enrich.actions_suppressed(T0, "fortiweb12") is True
        # detection is unaffected: an event still opens an incident
        ev = mk_event(ts=T0)
        db.session.add(ev)
        db.session.flush()
        assert incident.ingest_event(ev) is not None


def test_unparseable_source_is_treated_as_protected(app):
    """Cannot parse ⇒ cannot prove it is safe to block."""
    with app.app_context():
        assert enrich.is_protected("") is True
        assert enrich.is_protected("not-an-ip") is True


# --------------------------------------------------------------------------- #
#  Response gating                                                              #
# --------------------------------------------------------------------------- #
def _armed_policy(action_type="block_ip", level=SentinelPolicy.LEVEL_AUTONOMOUS):
    p = SentinelPolicy.query.filter_by(action_type=action_type).first()
    p.enabled, p.level, p.min_confidence = True, level, 50
    p.ttl_minutes, p.max_ttl_minutes = 30, 240
    return p


def _incident(score=95, **kw):
    fields = dict(ref="INC-2026-000999", opened_at=datetime.utcnow(),
                  device="fortiweb12", src_ip="185.10.20.30",
                  attack_family="sqli", score=score)
    fields.update(kw)
    inc = SentinelIncident(**fields)
    db.session.add(inc)
    db.session.flush()
    return inc


def test_kill_switch_beats_every_policy(app):
    with app.app_context():
        actions.ensure_policies()
        _armed_policy()
        config.set_value("response_enabled", False)
        db.session.commit()
        verdict = actions.evaluate(_incident(), "block_ip")
        assert verdict["allowed"] is False
        assert any(c["check"] == "kill_switch" and not c["ok"]
                   for c in verdict["checks"])


def test_protected_source_can_never_be_blocked(app):
    """Checked before confidence, on purpose: a correlation bug that decides
    our own monitoring host is an attacker must be unable to act on it."""
    with app.app_context():
        actions.ensure_policies()
        _armed_policy()
        config.set_value("response_enabled", True)
        db.session.commit()
        verdict = actions.evaluate(_incident(src_ip="192.0.2.60"), "block_ip")
        assert verdict["allowed"] is False and verdict["reason"] == "source is protected"


def test_unverified_mechanism_blocks_execution(app):
    """Every other gate passes and the action is STILL refused, because this
    transport has never been proved against a real appliance.

    Updated 2026-08-20: this used to assert it of ``block_ip``. That transport
    has since been captured from fortiweb12 and the gate correctly lets it
    through, so the guard moved to one that is still a specification. It has to
    keep testing SOMETHING unverified — the day the catalog is fully verified
    this assertion has no subject left, and that is the day to delete it rather
    than to weaken it.
    """
    with app.app_context():
        actions.ensure_policies()
        pol = SentinelPolicy.query.filter_by(action_type="raise_protection").first()
        pol.enabled = True
        pol.level = SentinelPolicy.LEVEL_SEMI_AUTO
        pol.min_confidence = 0
        config.set_value("response_enabled", True)
        db.session.commit()
        verdict = actions.evaluate(_incident(), "raise_protection")
        assert verdict["allowed"] is False
        assert verdict["reason"] == "mechanism unverified"
        assert all(c["ok"] for c in verdict["checks"]
                   if c["check"] != "mechanism_verified")


def test_only_proved_transports_are_marked_verified(app):
    """The honest state of this release, and it must be re-stated by hand.

    Whoever validates the next transport against fw12/fw13 has to change this
    number, which is the point: the count cannot drift upward by accident, and
    a claim of verification always has a person behind it.

    As of 2026-08-20: 1 of 4. ``block_ip`` was captured from fortiweb12 end to
    end (create, add member, re-read, delete member, delete list, zero residue).
    ``rate_limit_ip`` was REMOVED rather than counted — the route its mechanism
    named answers ``-20001 invalid URL`` on this firmware.
    """
    assert actions.verified_count() == (1, 4)
    from app.services.sentinel import transports
    assert set(transports.TRANSPORTS) == {
        k for k, spec in actions.CATALOG.items() if spec.verified}, \
        "a catalog entry claims verification with no executable transport " \
        "behind it, or a transport exists for an entry still marked unproved"


def test_block_country_can_never_be_autonomous(app):
    """One mis-attributed address would take a market offline."""
    assert actions.CATALOG["block_country"].max_level <= \
           SentinelPolicy.LEVEL_RECOMMEND


def test_every_blocking_action_requires_a_ttl(app):
    """TTL is the rollback. An action that never expires has none."""
    for key in ("block_ip", "block_country"):
        assert actions.CATALOG[key].requires_ttl is True
        assert actions.CATALOG[key].reversible is True


def test_a_trusted_source_is_never_answered_with_a_block(app):
    with app.app_context():
        inc = SentinelIncident(ref="INC-2026-000998", score=99,
                               src_trusted=True, attack_family="sqli",
                               opened_at=datetime.utcnow())
        assert actions.recommend(inc) == "investigate"


def test_a_fully_blocked_incident_needs_no_action(app):
    with app.app_context():
        inc = SentinelIncident(ref="INC-2026-000997", score=99,
                               waf_blocked=True, passed_count=0,
                               attack_family="sqli",
                               opened_at=datetime.utcnow())
        assert actions.recommend(inc) == "observe"


def test_proposal_is_recorded_even_when_refused(app):
    """'Sentinel wanted to do X and was refused because Y' is the record an
    operator needs when tuning autonomy — invisible if only permitted actions
    are stored."""
    with app.app_context():
        actions.ensure_policies()
        config.set_value("response_enabled", False)
        inc = _incident()
        db.session.commit()
        action = actions.propose(inc, "block_ip")
        db.session.commit()
        assert action.status == "proposed"
        assert "disarm" in action.detail


# --------------------------------------------------------------------------- #
#  The AI wall                                                                  #
# --------------------------------------------------------------------------- #
def test_model_recommendation_outside_the_enum_is_rejected(app):
    out = ai.validate({"assessment": "real_attack",
                       "recommended_action": "rm -rf the firewall",
                       "summary": "x"})
    assert out["recommended_action"] == "observe"
    assert out["rejected"]["recommended_action"] == "rm -rf the firewall"


def test_model_json_is_extracted_from_prose_and_fences(app):
    assert ai._extract_json('sure! ```json\n{"a": 1}\n```') == {"a": 1}
    assert ai._extract_json('here you go: {"a": {"b": 2}} hope that helps') == \
        {"a": {"b": 2}}
    assert ai._extract_json("no object here") is None


def test_ai_failure_never_raises(app):
    with app.app_context():
        config.set_value("ai_enabled", False)
        out = ai.reason(SentinelIncident(ref="INC-X"), [])
        assert out["ok"] is False


def test_ai_cannot_change_the_score(app):
    """Structural: the model's opinion lives in ai_json and the scorer never
    reads that field."""
    import inspect
    src = inspect.getsource(scoring)
    assert "ai_json" not in src and "import ai" not in src
    for name in ("ai.", "reason("):
        assert name not in src


def test_disagreement_is_surfaced_not_resolved(app):
    with app.app_context():
        inc = SentinelIncident(ref="INC-2026-000996", score=90,
                               attack_family="sqli")
        inc.ai = {"ok": True, "recommended_action": "close_false_positive"}
        d = ai.disagreement(inc, "block_ip")
        assert d["differs"] is True
        assert d["policy"] == "block_ip" and d["model"] == "close_false_positive"


# --------------------------------------------------------------------------- #
#  Normalisation                                                                #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("sub_type,expected", [
    ("SQL Injection", "sqli"),
    ("Cross Site Scripting", "xss"),
    ("Remote Command Execution", "rce"),
    ("Directory Traversal", "traversal"),
    ("Known Attack Tool / Scanner", "scanner"),
    ("HTTP Flood", "dos"),
    ("Brute Force Login", "bruteforce"),
    ("HTTP Protocol Constraints", "protocol"),
    ("Something Nobody Mapped", "other"),
])
def test_attack_family_classification(app, sub_type, expected):
    assert normalize.attack_family({"sub_type": sub_type}) == expected


def test_severity_takes_the_worse_of_word_and_threat_level(app):
    assert normalize.severity({"severity_level": "Low",
                               "threat_level": "95"}) == "critical"
    assert normalize.severity({"severity_level": "High",
                               "threat_level": "1"}) == "high"


def test_epoch_is_the_only_timestamp_trusted(app):
    """``date``/``time`` are in the APPLIANCE's timezone and disagree with
    every other clock in SATOM."""
    ts = normalize.parse_ts({"rel_time": "1786181039",
                             "date": "1999-01-01", "time": "00:00:00"})
    assert ts.year == 2026


def test_millisecond_epochs_are_handled(app):
    a = normalize.parse_ts({"rel_time": "1786181039"})
    b = normalize.parse_ts({"rel_time": "1786181039000"})
    assert abs((a - b).total_seconds()) < 1


def test_dedup_is_content_not_arrival(app):
    row = {"rel_time": "1786181039", "src": "1.2.3.4", "msg_id": "9",
           "sub_type": "SQL Injection", "action": "deny"}
    ts = normalize.parse_ts(row)
    assert normalize.dedup_key("fw", row, ts) == normalize.dedup_key("fw", row, ts)
    assert normalize.dedup_key("fw", row, ts) != \
           normalize.dedup_key("fw2", row, ts)


def test_blocked_reads_the_action_not_the_severity(app):
    for action, blocked in [("deny", True), ("block_period", True),
                            ("alert", False), ("monitor", False),
                            ("Deny (no log)", True)]:
        assert mk_event(action=action).blocked is blocked


# --------------------------------------------------------------------------- #
#  Collector guards                                                             #
# --------------------------------------------------------------------------- #
def test_collector_registration_keeps_runner_parity(app):
    from app.services import metrics_collect as mc
    from app.services.sentinel import collectors
    collectors.register()
    collectors.register()          # idempotent
    assert set(mc._RUNNERS) == set(mc.COLLECTORS)
    assert "http_status" in mc.COLLECTORS and "infra" in mc.COLLECTORS


def test_status_word_is_not_mistaken_for_a_code(app):
    """``status`` is a WORD on several Fortinet log types. Coercing it would
    classify every row as unknown while looking like it worked."""
    from app.services.sentinel import collectors as C
    assert C._status_of({"status": "accept"}) is None
    assert C._status_of({"status": "403"}) == 403
    assert C._status_of({"http_status": "200"}) == 200
    assert C._status_of({"http_status": "999"}) is None


def test_infra_without_topology_raises_rather_than_reporting_zero(app):
    """A layer nobody mapped must be UNKNOWN, never a published zero."""
    from app.services.sentinel import collectors as C
    with app.app_context():
        class A:
            id, name, kind = 4242, "unmapped", "fortiweb"
        with pytest.raises(RuntimeError) as exc:
            C.collect_infra(A(), {}, 0)
        assert "UNKNOWN" in str(exc.value)
