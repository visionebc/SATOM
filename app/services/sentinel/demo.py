"""Sentinel demo lab — the ten scenarios, runnable against the LIVE engine.

Settings → Sentinel renders what this module produces, so an operator can watch
an event travel the whole pipeline before trusting the pipeline with a real
one. Three properties hold, in order of importance:

* **The engine is real.** Every run goes through
  :func:`~app.services.sentinel.scoring.score_context`,
  :func:`~app.services.sentinel.scoring.band_of`,
  :func:`~app.services.sentinel.actions.recommend` and
  :func:`~app.services.sentinel.actions.evaluate` — the same code the 3-minute
  sweep uses. The only fabricated inputs are the events and the metric
  readings; the arithmetic, the bands, the gate chain and the per-action
  policies are the live ones. That is what makes the gate audit worth reading:
  it reflects *this installation's* kill switch, policy rows and hourly budget
  at the moment the button is pressed.

* **Nothing is written and no device is touched.** Events are constructed and
  never added to a session; the context lives and dies in this request.
  :func:`~app.services.sentinel.actions.evaluate` only READS (policy rows, the
  hourly action count, the protected-network list). A demo that inserted rows
  would poison the incident statistics it exists to explain.

* **The catalog mirrors ``tests/test_sentinel_scenarios.py``.** Same builders,
  same numbers, same expected bands — the suite is the contract and this is
  its visible half. ``expected_band`` is asserted by
  ``tests/test_sentinel_settings_page.py``, so a weight tune that moves a
  scenario out of its band breaks the build in the commit that tunes it,
  instead of leaving the Settings page demonstrating something false.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace

from ...models_sentinel import SentinelEvent, SentinelIncident
from . import actions, baseline, correlate, scoring

#: Fixed on purpose (a Tuesday, noon — the suite's T0). A demo that used
#: ``utcnow()`` would drift across maintenance windows and hour-of-week
#: baselines and stop reproducing; this one produces the same run forever.
T0 = datetime(2026, 8, 18, 12, 0, 0)

_HOSTILE_SOURCE = {
    "ip": "185.10.20.30", "trusted": False, "protected": False,
    "maintenance": False, "maintenance_labels": [], "asn_known": False,
}


def _event(**kw) -> SimpleNamespace:
    """One synthetic attack-log event, shaped like a ``SentinelEvent``.

    A namespace rather than the model class: the scorer and
    :func:`~app.services.sentinel.correlate.http_picture` only read attributes,
    and an unsaved model instance sitting in a request is one autoflush away
    from becoming a row. The two derived properties the scorer uses
    (``severity_rank``, ``blocked``) are computed with the model's own rules.
    """
    base = dict(ts=T0, device="fortiweb-demo", source="attack_log",
                policy="pol-demo-shop", src_ip="185.10.20.30", country="RU",
                http_method="GET", uri="/admin.php", http_status=403,
                signature_id="080200001", signature="SQL Injection",
                attack_family="sqli", severity="high", action="deny", count=1)
    base.update(kw)
    ev = SimpleNamespace(**base)
    ev.severity_rank = SentinelEvent.SEVERITY_RANK.get(
        (ev.severity or "").lower(), 0)
    # The model's own rule, applied to the namespace via the class property —
    # not a copy of it, so the two cannot drift.
    ev.blocked = SentinelEvent.blocked.fget(ev)
    return ev


def _reading(layer: str, label: str, *, peak: float, median: float,
             unit: str = "%", lag: float | None = None,
             anomalous: bool = True, usable: bool = True) -> correlate.LayerReading:
    r = correlate.LayerReading(layer=layer, metric=f"demo_{layer}", label=label,
                               unit=unit, series_key=f"demo_{layer}{{}}")
    r.peak, r.median, r.usable, r.anomalous = peak, median, usable, anomalous
    r.deviation = baseline.deviation(peak, median, max(median * 0.1, 0.1))
    r.ratio = baseline.ratio(peak, median)
    r.lag_s = lag
    r.peak_at = T0 + timedelta(seconds=lag or 0)
    return r


def _ctx(events, readings=(), *, source=None, vuln=None, unknown=(),
         store_ok=True) -> correlate.WindowContext:
    ctx = correlate.WindowContext(
        device="fortiweb-demo", src_ip="185.10.20.30", attack_family="sqli",
        t0=T0, start=T0 - timedelta(seconds=60), end=T0 + timedelta(seconds=300),
        events=list(events), readings=list(readings),
        layers_unknown=list(unknown), store_ok=store_ok)
    ctx.source = dict(source if source is not None else _HOSTILE_SOURCE)
    ctx.http = correlate.http_picture(ctx.events)
    ctx.vuln = dict(vuln) if vuln is not None else {
        "enabled": True, "cves": [], "worst": None, "exploit_available": False,
        "target_vulnerable": False, "cpe_known": False, "stale": False,
        "missing": []}
    return ctx


# --------------------------------------------------------------------------- #
#  The scenarios — same shapes, same numbers as the test suite                  #
# --------------------------------------------------------------------------- #
def _s01():
    return _ctx([])


def _s02():
    return _ctx([], [_reading("traffic", "throughput", peak=4500, median=300,
                              unit="Mbps", lag=1),
                     _reading("box", "appliance CPU", peak=70, median=25,
                              lag=3)])


def _s03():
    return _ctx([_event(action="alert", http_status=200)])


def _s04():
    return _ctx([_event(uri=f"/probe-{i}.php", http_status=404,
                        attack_family="scanner", severity="medium",
                        action="alert") for i in range(60)])


def _s05():
    return _ctx([_event(severity="critical", action="alert", http_status=200)
                 for _ in range(80)],
                [_reading("traffic", "throughput", peak=4500, median=300,
                          unit="Mbps", lag=1),
                 _reading("box", "appliance CPU", peak=91, median=22, lag=2),
                 _reading("vm", "VM CPU", peak=88, median=30, lag=3),
                 _reading("backend", "backend RTT", peak=528, median=120,
                          unit="ms", lag=8)])


def _s06():
    return _ctx([_event(severity="critical", action="alert", http_status=200)
                 for _ in range(80)],
                [_reading("traffic", "throughput", peak=4500, median=300,
                          unit="Mbps", lag=1)],
                source={"ip": "192.0.2.60", "trusted": True,
                        "trusted_kind": "pentest",
                        "trusted_label": "pentest LXC 213",
                        "trusted_expires": "2026-09-01", "protected": True,
                        "maintenance": True,
                        "maintenance_labels": ["Q3 authorised pentest"],
                        "asn_known": False})


def _s07():
    return _ctx([_event(action="alert", http_status=200)],
                [_reading("vm", "VM CPU", peak=31, median=30, anomalous=False),
                 _reading("host", "host CPU", peak=22, median=20,
                          anomalous=False)])


def _s08():
    return _ctx([_event(action="alert", http_status=200)],
                [_reading("box", "appliance CPU", peak=97, median=22, lag=2)])


def _s09():
    return _ctx([_event(action="alert", http_status=200)],
                [_reading("box", "appliance CPU", peak=26, median=25,
                          anomalous=False),
                 _reading("vm", "VM CPU", peak=99, median=30, lag=4),
                 _reading("host", "host CPU", peak=95, median=35, lag=6)])


def _s10():
    return _ctx([_event(action="deny", http_status=403, severity="high")
                 for _ in range(200)])


#: ``expected_band`` is a published claim, enforced by the test suite. The
#: stories say what an operator would have in front of them; ``lesson`` says
#: what the run demonstrates — the sentence worth keeping after the animation.
SCENARIOS: list[dict] = [
    {"slug": "normal-traffic", "build": _s01, "expected_band": "observe",
     "title": "Normal traffic",
     "story": "A quiet Tuesday. The attack log has nothing for this window.",
     "lesson": "No evidence scores zero. Sentinel never opens an incident "
               "just because it is running."},
    {"slug": "legitimate-spike", "build": _s02, "expected_band": "observe",
     "title": "Legitimate traffic spike",
     "story": "Throughput 15× its baseline and the appliance working harder — "
              "but zero attack signatures anywhere in the window.",
     "lesson": "Load is not an attack. Without a signature the behavioural "
               "factors alone must stay under the response bands: a detector "
               "that pages on traffic is a capacity alarm wearing a security "
               "badge."},
    {"slug": "sqli-evaded", "build": _s03, "expected_band": "investigate",
     "title": "One SQL injection answered 200",
     "story": "A single SQLi request. The WAF only alerted, and the origin "
              "answered 200 OK.",
     "lesson": "Evasion outranks volume: one request that got through scores "
               "higher than a flood the appliance refused, because severity "
               "says how bad the attempt WOULD be — evasion says the defence "
               "did not stop it."},
    {"slug": "scanner", "build": _s04, "expected_band": "observe",
     "title": "High-rate scanner",
     "story": "60 requests probing 60 different URIs, every one answered 404.",
     "lesson": "Enumeration and volume both fire — and the total still sits "
               "under the investigate floor: someone is mapping the site, and "
               "nothing has got in. Recorded, visible, and nobody is paged "
               "for a scan the origin answered 404."},
    {"slug": "dos-like", "build": _s05, "expected_band": "semi_auto",
     "title": "DoS-like flood with real impact",
     "story": "80 critical events answered 200, then throughput, appliance "
              "CPU, VM CPU and backend RTT all leave their baselines — in "
              "that order.",
     "lesson": "The causal chain is the strongest picture Sentinel can see: "
               "layers moving in a plausible order after T0. This is the only "
               "scenario in the catalog that reaches the semi-automatic band."},
    {"slug": "authorised-scanner", "build": _s06, "expected_band": "observe",
     "title": "The authorised scanner",
     "story": "BYTE-IDENTICAL evidence to a real intrusion — 80 critical "
              "events answered 200, traffic 15× baseline. But the source is "
              "the registered pentest box, inside its maintenance window.",
     "lesson": "The false-positive case the whole context page exists for. "
               "Only context separates this from scenario 5, which is why "
               "trusted-source and maintenance-window are worth more negative "
               "points than any single positive factor."},
    {"slug": "no-impact", "build": _s07, "expected_band": "investigate",
     "title": "Attack with quiet infrastructure",
     "story": "An evaded SQLi — and the VM and host layers were measured and "
              "stayed flat.",
     "lesson": "Measured-and-quiet lowers the picture; it is NOT the same as "
               "unmeasured. 'We looked and nothing moved' and 'we could not "
               "look' drive opposite operator decisions, and Sentinel keeps "
               "them apart."},
    {"slug": "box-saturation", "build": _s08, "expected_band": "investigate",
     "title": "Appliance CPU saturation",
     "story": "One evaded event, and the appliance's own CPU at 97% against a "
              "baseline of 22%.",
     "lesson": "The box layer fires on the appliance's internals — the WAF "
               "itself struggling is impact, whatever the backend says."},
    {"slug": "vm-exhaustion", "build": _s09, "expected_band": "recommend",
     "title": "VM starved below a healthy appliance",
     "story": "The appliance reports 26% CPU — fine. The VM it runs in is at "
              "99% and the hypervisor at 95%.",
     "lesson": "The layer the appliance cannot see. Without the topology map "
               "binding device → VM → host, this incident is invisible; that "
               "is the entire argument for filling in that table."},
    {"slug": "waf-wall", "build": _s10, "expected_band": "observe",
     "title": "200 attacks, every one stopped",
     "story": "A wall of high-severity SQLi — and the appliance denied every "
              "single request.",
     "lesson": "A WAF doing its job is a quiet night, not an emergency. "
               "Blocking SUBTRACTS points: paging a human for stopped attacks "
               "teaches them to ignore the console."},
]

_BY_SLUG = {s["slug"]: s for s in SCENARIOS}

#: The action the gate audit exercises. ``block_ip`` on purpose: it is the one
#: action that can reach autonomy, so its audit shows the longest live chain.
AUDIT_ACTION = "block_ip"


def catalog() -> list[dict]:
    """The scenario list for the template — everything except the builders."""
    return [{k: v for k, v in s.items() if k != "build"} for s in SCENARIOS]


def run(slug: str) -> dict:
    """Run one scenario through the live engine. Raises ``KeyError`` on an
    unknown slug — the route turns that into a 404 rather than guessing."""
    scen = _BY_SLUG[slug]                    # KeyError is the contract
    ctx = scen["build"]()
    verdict = scoring.score_context(ctx)
    band = scoring.band_of(verdict["score"])

    # The stand-in incident the policy engine judges. Only attributes the
    # engine reads; ``band`` matches SentinelIncident.band for this score by
    # construction (same thresholds, asserted by the page's test file).
    pseudo = SimpleNamespace(
        score=verdict["score"], src_ip=ctx.src_ip, device=ctx.device,
        src_trusted=bool((ctx.source or {}).get("trusted")),
        waf_blocked=bool(ctx.blocked_count and not ctx.passed_count),
        passed_count=ctx.passed_count, band=band)
    recommendation = actions.recommend(pseudo)
    gates = actions.evaluate(pseudo, AUDIT_ACTION)

    events = [{
        "ts": e.ts.strftime("%H:%M:%S"), "src_ip": e.src_ip,
        "country": e.country, "signature": e.signature,
        "attack_family": e.attack_family, "severity": e.severity,
        "action": e.action, "http_status": e.http_status, "uri": e.uri,
        "count": e.count or 1, "blocked": e.blocked,
    } for e in ctx.events[:8]]

    return {
        "slug": scen["slug"], "title": scen["title"], "story": scen["story"],
        "lesson": scen["lesson"], "expected_band": scen["expected_band"],
        "simulated": True,
        "events": events,
        "event_count": ctx.event_count,
        "blocked_count": ctx.blocked_count,
        "passed_count": ctx.passed_count,
        "http": ctx.http,
        "readings": [r.to_dict() | {"points": []} for r in ctx.readings],
        "layers_unknown": list(ctx.layers_unknown),
        "source": ctx.source,
        "chain": [{"layer": r.layer, "label": r.label, "lag_s": r.lag_s,
                   "ratio": round(r.ratio, 2)} for r in ctx.causal_chain],
        "score": verdict["score"], "raw": verdict["raw"],
        "factors": verdict["factors"], "notes": verdict["notes"],
        "band": band,
        "bands": {"observe": SentinelIncident.BAND_OBSERVE,
                  "recommend": SentinelIncident.BAND_RECOMMEND,
                  "semi_auto": SentinelIncident.BAND_SEMI_AUTO},
        "recommendation": recommendation,
        "audit_action": AUDIT_ACTION,
        "gates": gates,
    }
