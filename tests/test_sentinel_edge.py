"""Border corroboration — the layer that says whether a source is a real peer.

What is actually at risk here, and why each guard exists
--------------------------------------------------------
This layer does two jobs with one answer, and they fail in opposite
directions:

* As EVIDENCE it may only add points for an answer that came back. A lookup
  that timed out, hit the wrong ADOM or found a retired collector returns zero
  rows, and zero rows is byte-identical to "the border genuinely never saw
  this address". If either of those two ever scores, the number that gates a
  firewall change is being paid for by a failure.

* As a VETO it must refuse by default. ``edge_require`` on means an address
  the border never confirmed cannot enter a border blocklist — because
  FortiWeb reports the true client when the policy reads ``X-Forwarded-For``
  and the CDN's own address when it does not, and blocking the second one
  removes every legitimate client behind that egress. A veto that fails open
  is a veto that only exists in the documentation.

And a third, quieter one: there must be NO negative weight anywhere in this
layer. Silence at the border is a fact about addressing, not about hostility.
A negative would systematically under-score every customer who puts a CDN in
front of their applications, and it would do it invisibly — the incident would
still look complete.

Two things this file deliberately does NOT test
-----------------------------------------------
The JSON-RPC wire format, and whether a real FortiAnalyzer answers it. As of
2026-08-23 there is no live FAZ in this fleet to run it against (``faz01`` is
retired on a ``.invalid`` host), so the mechanism ships unverified and says so
on the page. Asserting the shape of a request nobody has ever had accepted
would only freeze a guess.
"""
from __future__ import annotations

import io
import re
from datetime import datetime, timedelta

import pytest
from conftest import admin_user_id, login

from app.services.sentinel import config as sn_config
from app.services.sentinel import edge, scoring

SECTION = "app/templates/sentinel/_context_section.html"
PANE = "app/templates/settings/index.html"
EDGE_SRC = "app/services/sentinel/edge.py"

EDGE_KEYS = ("edge_enabled", "edge_require", "edge_scan_dst", "edge_max_rows",
             "edge_timeout_s", "edge_slack_minutes", "edge_tz_offset_min")


#: A result payload as a PLAIN LITERAL. ``edge.blank()`` reads a setting, so
#: calling it at collection time (inside a parametrize decorator) would need an
#: app context that does not exist yet — and the failure would look like a
#: broken fixture rather than a test that asks for the wrong thing.
BLANK = {
    "enabled": True, "mapped": False, "checked": False, "corroborated": None,
    "verdict": "unknown", "multi_target": False, "reason": "", "error": "",
    "analyzer": "", "adom": "", "fortigate": "", "vdom": "", "scope": "",
    "hits": 0, "distinct_dst": 0, "distinct_dport": 0, "denied": 0, "rows": [],
}


def _p(**kw) -> dict:
    return dict(BLANK, **kw)


def _read(path: str) -> str:
    return io.open(path, encoding="utf-8").read()


def _uncommented(text: str) -> str:
    """Strip Jinja / HTML / Python comments before asserting on source.

    The ninth recurrence of the same defect in this repo: a guard whose
    expectation appears verbatim in the prose that EXPLAINS the guard passes
    against code that no longer satisfies it. Removing comments first is the
    only version of this check that means anything.
    """
    text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(r"^\s*#.*$", "", text, flags=re.M)
    return text


# --------------------------------------------------------------------------- #
#  The catalog                                                                  #
# --------------------------------------------------------------------------- #
def test_every_border_setting_is_in_the_catalog_with_a_hint():
    by_key = {s["key"]: s for s in sn_config.SPEC}
    for key in EDGE_KEYS:
        assert key in by_key, f"{key} missing from SPEC"
        spec = by_key[key]
        assert spec["group"] == "edge", f"{key} is not in the edge group"
        assert spec.get("label"), f"{key} has no label"
        assert len(spec.get("hint") or "") > 120, (
            f"{key} ships without a real hint — an unexplained knob on this "
            f"page is how the veto gets turned off by someone who thought "
            f"they were turning off a query")


def test_the_border_group_renders_and_is_explained(app):
    groups = dict(sn_config.GROUPS)
    assert groups.get("edge"), "no 'edge' group in GROUPS — the settings are unreachable"
    with app.app_context():
        rendered = [g for g, _label, rows in sn_config.form_groups() if rows]
    assert "edge" in rendered, "the edge group produced no form rows"
    assert len(sn_config.UI_HINTS.get("group.edge") or "") > 120


def test_the_veto_defaults_to_required():
    """Off-by-safe. Shipping this default as False would mean every fresh
    installation is willing to list an address it never confirmed."""
    spec = {s["key"]: s for s in sn_config.SPEC}["edge_require"]
    assert spec["default"] is True


# --------------------------------------------------------------------------- #
#  Weights                                                                      #
# --------------------------------------------------------------------------- #
def test_the_two_border_factors_are_positive_and_labelled():
    assert scoring.WEIGHTS["edge_corroboration"] > 0
    assert scoring.WEIGHTS["edge_multi_target"] > 0
    # NOT "is the factor listed": explain() builds its rows FROM WEIGHTS and
    # falls back to labels.get(key, key), so every weight is always listed —
    # a guard that derives its expectation from the thing under test always
    # passes. This mutation survived the first pass for exactly that reason.
    # What has to be true is that the row carries PROSE, not the key echoed
    # back at the reader.
    rows = {r["factor"]: r["label"] for r in scoring.explain()}
    for key in ("edge_corroboration", "edge_multi_target"):
        assert key in rows, f"{key} is not in the published weight table"
        assert rows[key] != key, (
            f"{key} has no label — explain() echoed the raw key, which is the "
            f"fallback, not an explanation")
        assert len(rows[key]) > 25 and " " in rows[key], (
            f"{key}: {rows[key]!r} is not an explanation. A weight the "
            f"published table does not explain is a weight nobody can audit "
            f"— the staleness class that let 'Version: 1.0' survive four "
            f"releases in this repo")


def test_no_negative_weight_exists_for_the_border_layer():
    bad = {k: v for k, v in scoring.WEIGHTS.items()
           if k.startswith("edge_") and v < 0}
    assert not bad, (
        f"{bad}: an attack behind a CDN is still an attack. Subtracting for "
        f"the border's silence under-scores exactly the customers who run a "
        f"CDN, and does it invisibly")


def test_corroboration_is_worth_more_than_a_single_internal_layer():
    """Independence is the whole value: every other positive factor is derived
    from the same appliance's view of the same traffic."""
    assert (scoring.WEIGHTS["edge_corroboration"]
            > scoring.WEIGHTS["host_anomaly"])


# --------------------------------------------------------------------------- #
#  Lookup — every failure is "unknown", never "no"                              #
# --------------------------------------------------------------------------- #
class _Ctx:
    """The smallest thing score_context needs. Not a WindowContext: building a
    real one drags in the metrics store, and this file is about one field."""

    def __init__(self, edge_payload):
        self.edge = edge_payload
        self.worst_severity = "info"
        self.event_count = 1
        self.http = {}
        self.vuln = {}
        self.source = {}
        self.readings = []
        self.layers_unknown = []
        self.store_ok = True
        self.blocked_count = 0
        self.passed_count = 1
        self.causal_chain = []

    def layer_anomalous(self, _layer):
        return None

    def worst(self, _layer):
        return None


def _factors(payload) -> dict:
    out = scoring.score_context(_Ctx(payload))
    return {f["factor"]: f["points"] for f in out["factors"]}, out


@pytest.mark.parametrize("payload,label", [
    (_p(), "a blank result"),
    (_p(mapped=True, error="timeout"), "a failed lookup"),
    (_p(mapped=True, checked=True, corroborated=False),
     "a completed lookup with no rows"),
    ({}, "no border data at all"),
])
def test_a_border_answer_that_did_not_confirm_scores_nothing(payload, label):
    factors, _ = _factors(payload)
    assert not [k for k in factors if k.startswith("edge_")], (
        f"{label} produced border points: {factors}")


def test_a_confirmed_source_scores_and_a_scanning_one_scores_more():
    one, _ = _factors(_p(mapped=True, checked=True,
                           corroborated=True, hits=4, distinct_dst=1))
    assert one.get("edge_corroboration") == scoring.WEIGHTS["edge_corroboration"]
    assert "edge_multi_target" not in one

    many, _ = _factors(_p(mapped=True, checked=True,
                            corroborated=True, hits=90, distinct_dst=40,
                            multi_target=True))
    assert many.get("edge_multi_target") == scoring.WEIGHTS["edge_multi_target"]
    assert sum(many.values()) > sum(one.values())


def test_the_notes_distinguish_not_looked_from_looked_and_found_nothing():
    """Two opposite operator decisions. Collapsing them is the defect this
    whole module's None-vs-False discipline exists to prevent."""
    _f, unchecked = _factors(_p(mapped=True,
                                  error="collector refused"))
    joined = " ".join(unchecked["notes"])
    assert "not evaluated" in joined and "collector refused" in joined

    _f2, absent = _factors(_p(mapped=True,
                                checked=True, corroborated=False))
    joined2 = " ".join(absent["notes"])
    assert "never logged" in joined2
    assert "not evaluated" not in joined2


def test_lookup_never_answers_no_when_it_could_not_ask(app):
    with app.app_context():
        for kwargs in ({"appliance_id": 0}, {"appliance_id": 999999}):
            out = edge.lookup("203.0.113.7", t0=datetime.utcnow(), **kwargs)
            assert out["corroborated"] is None
            assert out["verdict"] == edge.UNKNOWN
        bad = edge.lookup("nonsense", appliance_id=1, t0=datetime.utcnow())
        assert bad["corroborated"] is None


def test_a_retired_or_maintenance_collector_is_never_probed():
    """The eligibility filter lives in the service, not only in the route. The
    deep monitors probed recycled IPs for months because it lived in a caller
    and a second entry point simply did not have it."""
    class A:
        maintenance = True
        host = "192.0.2.9"
    ok, why = edge._reachable(A())
    assert ok is False and "maintenance" in why

    class B:
        maintenance = False
        host = "retired-faz01.invalid"
    ok2, why2 = edge._reachable(B())
    assert ok2 is False and "invalid" in why2

    class C:
        maintenance = False
        host = "192.0.2.9"
    assert edge._reachable(C())[0] is True


# --------------------------------------------------------------------------- #
#  The veto                                                                     #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("payload,why", [
    ({}, "no data"),
    (_p(enabled=False), "layer disabled"),
    (_p(mapped=False), "unmapped"),
    (_p(mapped=True, checked=True, error="boom"), "errored"),
    (_p(mapped=True, checked=False), "not consulted"),
    (_p(mapped=True, checked=True,
          corroborated=False), "confirmed absent"),
])
def test_the_veto_refuses_everything_short_of_a_confirmation(app, payload, why,
                                                             monkeypatch):
    with app.app_context():
        # edge_require is the only setting blockable() reads.
        monkeypatch.setattr(sn_config, "get", lambda k: True)
        ok, reason = edge.blockable(payload)
        assert ok is False, f"{why} was allowed through the veto"
        assert reason, "a refusal without a reason is 'Sentinel did nothing'"
        # And the reason has to be THE right one. Two mutations survived the
        # first pass because every payload also tripped a LATER branch: the
        # veto still refused, with a vaguer explanation. "Sentinel did nothing
        # because the border was not consulted" and "...because the lookup
        # failed with a device refusal" send an operator to different places,
        # so the branch is asserted by what it SAYS.
        for needle in EXPECTED_REASON.get(why, ()):
            assert needle in reason, (
                f"{why}: refused, but the reason given was {reason!r} — that "
                f"is a different branch answering for this one")


#: What each refusal has to be able to tell the operator.
EXPECTED_REASON = {
    "layer disabled": ("disabled",),
    "unmapped": ("no edge map",),
    "errored": ("lookup failed", "boom"),
    "confirmed absent": ("never logged",),
}


def test_the_veto_allows_a_confirmed_source(app, monkeypatch):
    with app.app_context():
        monkeypatch.setattr(sn_config, "get", lambda k: True)
        ok, reason = edge.blockable(
            _p(mapped=True, checked=True,
                 corroborated=True, hits=3, scope="faz01 · adom root"))
        assert ok is True
        assert "3" in reason


def test_turning_the_requirement_off_is_the_only_way_past_it(app, monkeypatch):
    with app.app_context():
        monkeypatch.setattr(sn_config, "get",
                            lambda k: False if k == "edge_require" else True)
        ok, _ = edge.blockable({})
        assert ok is True, ("with the requirement off the veto must not "
                            "second-guess the operator")


# --------------------------------------------------------------------------- #
#  Summarisation                                                                #
# --------------------------------------------------------------------------- #
def test_only_rows_where_the_address_is_the_SOURCE_corroborate_it(app):
    """A row where it is the destination proves the opposite of the question:
    something reached out TO it."""
    rows = [
        {"srcip": "203.0.113.7", "dstip": "192.0.2.1", "dstport": "443"},
        {"srcip": "203.0.113.7", "dstip": "192.0.2.2", "dstport": "443"},
        {"srcip": "198.51.100.9", "dstip": "203.0.113.7", "dstport": "80"},
    ]
    with app.app_context():
        out = edge._summarise(rows, "203.0.113.7")
    assert out["hits"] == 2, out
    assert out["distinct_dst"] == 2
    assert out["corroborated"] is True


def test_an_empty_result_is_absent_and_an_absent_result_explains_itself(app):
    with app.app_context():
        out = edge._summarise([], "203.0.113.7")
    assert out["corroborated"] is False
    assert out["verdict"] == edge.ABSENT
    assert "proxy" in out["reason"] or "CDN" in out["reason"]


def test_an_unset_fortigate_asks_about_every_device_not_about_no_device():
    """An entry with an empty ``devid`` asks the collector for a device called
    "" and returns nothing — which is indistinguishable from a source the
    border never saw, and would veto every block on that appliance forever."""
    class Row:
        fortigate = ""
        vdom = "root"
    assert edge._device_selector(Row()) == []

    class Row2:
        fortigate = "fgt-edge-01"
        vdom = ""
    assert edge._device_selector(Row2()) == [{"devid": "fgt-edge-01"}]

    class Row3:
        fortigate = "fgt-edge-01"
        vdom = "CUSTOMER_A"
    sel = edge._device_selector(Row3())
    assert sel == [{"devid": "fgt-edge-01", "vdom": "CUSTOMER_A"}]


def test_the_collector_clock_offset_is_actually_applied(app, monkeypatch):
    """Wrong here means zero rows forever, which reads as a permanent veto
    rather than as an error anyone ever sees."""
    with app.app_context():
        monkeypatch.setattr(sn_config, "get",
                            lambda k: 90 if k == "edge_tz_offset_min" else 0)
        base = datetime(2026, 8, 23, 12, 0, 0)
        assert edge._shift(base) == base + timedelta(minutes=90)


# --------------------------------------------------------------------------- #
#  Reads only                                                                   #
# --------------------------------------------------------------------------- #
def test_this_module_never_writes_to_a_device():
    """The user's instruction was explicit: the border receives a list, never
    a write from this engine.

    Precision matters here. FortiAnalyzer's logsearch is CREATED with the
    JSON-RPC verb ``add`` — a search task, not configuration — so a guard that
    simply banned the string ``add`` would either fail against the correct
    implementation or, written loosely enough to pass, stop catching anything.
    So: no ``set`` / ``update`` / ``delete`` verb at all, and every ``add``
    must target the logsearch route.
    """
    #  The transport moved to app/services/faz_logs.py on 2026-09-08, when
    #  Scout became a second caller of the same logview route. Scanning only
    #  edge.py after that move would leave this guard reading a file with no
    #  JSON-RPC calls in it — inert, and green. The tripwire below caught
    #  exactly that, which is why BOTH files are scanned now: the invariant is
    #  "this engine never writes to a device", and the engine is both halves.
    src = _uncommented(_read(EDGE_SRC)) + "\n" + _uncommented(
        _read("app/services/faz_logs.py"))
    calls = re.findall(r'\.(?:call|rpc)\(\s*["\'](\w+)["\']\s*,\s*([^,\n]+)',
                       src)
    assert calls, "no JSON-RPC calls found — the scanner is reading nothing"
    for verb, target in calls:
        assert verb not in ("set", "update", "delete"), (
            f"{verb} {target}: this module must never write to a device")
        if verb == "add":
            assert "SEARCH_URL" in target, (
                f"add against {target} is not a logsearch task")


# --------------------------------------------------------------------------- #
#  The two surfaces must be given the same context                              #
# --------------------------------------------------------------------------- #
def test_the_settings_pane_deploys_every_key_the_context_builder_returns(app):
    """The defect this caught, on the day it was written.

    ``context_context()`` is deliberately ONE builder for both surfaces — but
    the Admin Console pane re-lists its keys by hand in a ``{% with %}``,
    which is a second copy, which drifts. Adding a key to the builder and
    forgetting the pane 500s the whole Settings page today; a key read only
    inside an ``{% if %}`` would instead render a pane that quietly disagrees
    with the standalone page.
    """
    from app.views.sentinel import context_context
    with app.app_context():
        keys = set(context_context().keys())

    pane = _uncommented(_read(PANE))
    block = re.search(r'id="tab-sentinel-context".*?\{%\s*include', pane, re.S)
    assert block, "the sentinel-context pane disappeared"
    body = block.group(0)
    missing = sorted(k for k in keys
                     if not re.search(rf"\b{re.escape(k)}\s*=", body))
    assert not missing, (
        f"the pane does not deploy {missing} — the pane and the standalone "
        f"page are being given different context")


def test_every_post_form_in_the_section_returns_to_the_surface_it_came_from(app):
    """Read from the SOURCE, not from rendered output.

    The border map, the trust list and the topology map all draw one form PER
    ROW. On a fresh install those tables are empty, so a check that reads
    rendered HTML sees zero forms and reports a clean result while half of
    them are missing the marker.
    """
    body = _uncommented(_read(SECTION))
    forms = re.findall(r'<form[^>]*method="post"[^>]*>(.*?)</form>', body, re.S)
    assert len(forms) >= 8, f"only {len(forms)} POST forms scanned"
    missing = [f[:80] for f in forms if 'name="return_to"' not in f]
    assert not missing, missing


def test_both_surfaces_draw_the_border_map_and_admit_it_is_unverified(app, client):
    """Unverified and SAYS SO. A mechanism written from a reference manual and
    never run against a device is a specification; the console shows it as
    one, the way ``actions.CATALOG`` already does."""
    login(client, admin_user_id(app))
    for url in ("/sentinel/context", "/settings/"):
        r = client.get(url)
        assert r.status_code == 200, f"{url} -> {r.status_code}"
        body = r.get_data(as_text=True)
        assert "Border map" in body, f"{url} does not draw the border map"
        assert "Unverified mechanism" in body, (
            f"{url} presents an unproved mechanism as if it worked")
        assert "X-Forwarded-For" in body, (
            f"{url} does not explain WHY the border can disagree with the WAF")
