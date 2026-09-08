"""Guards for Scout — the fault-localisation ladder.

What is worth guarding here is NOT that the rungs run. It is the handful of
rules that decide whether the report can be trusted, every one of which fails
silently: a skipped rung rendered as a pass, a refusal rendered as absence, a
crash in Scout rendered as an outage in the customer's path. None of those
raises, none of them shows up in a smoke test, and each of them produces a
report that reads exactly like a correct one.
"""
from __future__ import annotations

import os
import re

import pytest

from app.services import faz_logs
from app.services import scout_ladder as sl

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_TPL = os.path.join(REPO, "app", "templates", "base.html")
SCOUT_TPL = os.path.join(REPO, "app", "templates", "scout", "index.html")
INIT_PY = os.path.join(REPO, "app", "__init__.py")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class Appl:
    def __init__(self, kind="fortiweb", name="fw", host="192.0.2.13", id=1):
        self.kind, self.name, self.host, self.id = kind, name, host, id
        self.maintenance = False
        self.firmware = "7.6.8"


def _layer(key, verdict, headline="x"):
    return sl.Layer(key, "T%s" % key, "q", sl.V_SATOM,
                    lambda ctx, _v=verdict: sl._r(_v, headline))


def _run(ladder, target=None, ports=None):
    return sl.run(target or sl.Target(appliance=Appl(), policy="pol"),
                  sl.Options(), ports or {}, ladder=ladder)


# --------------------------------------------------------------------------- #
#  Refusals                                                                     #
# --------------------------------------------------------------------------- #
def test_a_mutating_method_is_refused_before_anything_is_dialled():
    for m in ("POST", "PUT", "DELETE", "PATCH"):
        with pytest.raises(sl.ScoutRefused):
            sl.assert_safe_method(m)
    for m in ("GET", "head", "OPTIONS"):
        assert sl.assert_safe_method(m) == m.upper()


def test_run_refuses_a_product_whose_object_this_ladder_does_not_read():
    with pytest.raises(sl.ScoutRefused):
        sl.run(sl.Target(appliance=Appl(kind="fortianalyzer"), policy="p"))


def test_run_refuses_without_an_object_name():
    with pytest.raises(sl.ScoutRefused):
        sl.run(sl.Target(appliance=Appl(), policy="  "))


def test_run_refuses_a_mutating_method_through_the_public_entry_point():
    with pytest.raises(sl.ScoutRefused):
        sl.run(sl.Target(appliance=Appl(), policy="p", method="POST"))


# --------------------------------------------------------------------------- #
#  The stop condition — the rule a green badge under a red one would break      #
# --------------------------------------------------------------------------- #
def test_the_first_fail_stops_the_ladder_and_the_rest_are_skipped_not_passed():
    rep = _run((_layer("0", sl.PASS), _layer("1", sl.FAIL),
                _layer("2", sl.PASS), _layer("3", sl.PASS)))
    verdicts = [L["verdict"] for L in rep["layers"]]
    assert verdicts == [sl.PASS, sl.FAIL, sl.SKIPPED, sl.SKIPPED]
    assert sl.PASS not in verdicts[2:], (
        "a rung below a localised fault was never walked; rendering it as a "
        "pass is how the report gets read backwards")


def test_a_warn_does_not_stop_the_ladder():
    rep = _run((_layer("0", sl.WARN), _layer("1", sl.PASS)))
    assert [L["verdict"] for L in rep["layers"]] == [sl.WARN, sl.PASS]


def test_unknown_does_not_stop_the_ladder_and_never_becomes_a_pass():
    rep = _run((_layer("0", sl.UNKNOWN), _layer("1", sl.PASS)))
    assert [L["verdict"] for L in rep["layers"]] == [sl.UNKNOWN, sl.PASS]
    assert rep["verdict"]["blind_spots"] == ["0"]


def test_a_rung_that_raises_is_unknown_and_never_a_fault_in_their_path():
    def boom(ctx):
        raise RuntimeError("scout bug")
    rep = _run((sl.Layer("0", "T", "q", sl.V_SATOM, boom), _layer("1", sl.PASS)))
    assert rep["layers"][0]["verdict"] == sl.UNKNOWN
    assert rep["layers"][1]["verdict"] == sl.PASS, (
        "our own defect must not halt the walk, and must not be reported as "
        "their outage")


# --------------------------------------------------------------------------- #
#  The verdict                                                                  #
# --------------------------------------------------------------------------- #
def test_the_verdict_names_the_first_failing_layer_and_only_that_one():
    rep = _run((_layer("0", sl.PASS), _layer("1", sl.FAIL),
                _layer("2", sl.FAIL)))
    v = rep["verdict"]
    assert v["localised"] is True and v["layer"] == "1"


def test_a_clean_walk_with_blind_spots_is_not_reported_as_healthy():
    rep = _run((_layer("0", sl.PASS), _layer("1", sl.UNKNOWN)))
    v = rep["verdict"]
    assert v["localised"] is False
    assert "not a clean bill of health" in v["text"]
    assert v["blind_spots"] == ["1"]


def test_a_fully_probed_clean_walk_says_so_without_the_hedge():
    rep = _run((_layer("0", sl.PASS), _layer("1", sl.PASS)))
    assert "not a clean bill of health" not in rep["verdict"]["text"]


# --------------------------------------------------------------------------- #
#  Border logs — where firewall / reset / routing stop being one silence        #
# --------------------------------------------------------------------------- #
def test_an_empty_border_result_is_never_a_verdict():
    rep = sl.classify_path_rows([])
    assert rep["mode"] == "absent"
    assert sl.PATH_VERDICT["absent"][0] == sl.UNKNOWN, (
        "no rows reads identically to a wrong ADOM, a wrong device selector "
        "and logging switched off — none of which is a clean path")


def test_a_deny_outranks_a_reset_which_outranks_a_timeout():
    rows = [{"action": "timeout"}, {"action": "server-rst"}, {"action": "deny"}]
    assert sl.classify_path_rows(rows)["mode"] == "deny"
    assert sl.classify_path_rows(rows[:2])["mode"] == "reset"
    assert sl.classify_path_rows(rows[:1])["mode"] == "timeout"


def test_a_forwarded_flow_clears_the_path_rung_but_only_that_rung():
    rep = sl.classify_path_rows([{"action": "accept"}])
    assert rep["mode"] == "accept" and rep["mixed"] is False
    assert sl.PATH_VERDICT["accept"][0] == sl.PASS


def test_mixed_actions_report_the_worst_and_say_that_they_are_mixed():
    rep = sl.classify_path_rows([{"action": "accept"}, {"action": "deny"}])
    assert rep["mode"] == "deny" and rep["mixed"] is True
    assert rep["counts"]["accept"] == 1 and rep["counts"]["deny"] == 1


def test_an_unrecognised_action_is_counted_and_not_silently_dropped():
    rep = sl.classify_path_rows([{"action": "wibble"}])
    assert rep["mode"] == "absent" and rep["unknown_actions"] == 1
    assert rep["total"] == 1


# --------------------------------------------------------------------------- #
#  Timing decomposition — a localiser, not decoration                           #
# --------------------------------------------------------------------------- #
def test_a_phase_must_be_both_dominant_and_slow_to_be_blamed():
    fast = sl.read_timings({"tcp_ms": 1, "tls_ms": 2, "ttfb_ms": 10,
                            "total_ms": 13})
    assert fast["phase"] == "", (
        "a 10 ms TTFB that is 77 percent of a 13 ms request is not 'the "
        "backend thinking'; naming it sends someone to profile an application "
        "that answered instantly")
    slow = sl.read_timings({"tcp_ms": 5, "tls_ms": 10, "ttfb_ms": 3000,
                            "total_ms": 3020})
    assert slow["phase"] == "ttfb" and "thinking" in slow["note"]


def test_a_slow_connect_is_not_reported_as_a_slow_application():
    r = sl.read_timings({"tcp_ms": 2500, "tls_ms": 20, "ttfb_ms": 30,
                         "total_ms": 2560})
    assert r["phase"] == "tcp" and "backlog" in r["note"]


def test_missing_timings_say_so_rather_than_naming_a_phase():
    assert sl.read_timings(None)["phase"] == ""
    assert sl.read_timings({})["note"] == "no phase timings were captured"


def test_an_address_literal_is_not_a_name_to_resolve():
    assert sl.is_ip_literal("192.0.2.13") and sl.is_ip_literal("::1")
    assert not sl.is_ip_literal("vip.example.com")


# --------------------------------------------------------------------------- #
#  Individual rungs                                                             #
# --------------------------------------------------------------------------- #
def _ctx(ports=None, state=None, **topts):
    c = sl.Ctx(target=sl.Target(appliance=Appl(), policy="pol"),
               opts=sl.Options(**topts).clamped(), ports=ports or {})
    c.state.update(state or {})
    return c


def test_a_rung_whose_capability_is_unwired_is_unknown_not_pass():
    for fn in (sl.layer_device, sl.layer_policy, sl.layer_pool,
               sl.layer_backend, sl.layer_path, sl.layer_waf):
        assert fn(_ctx())["verdict"] == sl.UNKNOWN


def test_an_appliance_in_maintenance_is_warned_about_not_diagnosed():
    out = sl.layer_device(_ctx({"device_health": lambda a: {
        "status": "ok", "reasons": [], "maintenance": True}}))
    assert out["verdict"] == sl.WARN
    assert "maintenance" in out["headline"]


def test_a_stale_harvest_degrades_the_rung_but_never_stops_the_walk():
    out = sl.layer_device(_ctx({"device_health": lambda a: {
        "status": "crit", "maintenance": False, "reasons": [
            {"signal": "sync", "label": "Harvest", "status": "crit",
             "text": "harvest failing (5 runs in a row)"},
            {"signal": "cache", "label": "Cache", "status": "crit",
             "text": "cache 6 d old"}]}}))
    assert out["verdict"] == sl.WARN, (
        "harvest and cache critical mean SATOM could not COLLECT from the box; "
        "every FortiWeb in this fleet grades that way, so a rung that failed "
        "on it would stop every walk at rung 0 forever")


def test_an_exhausted_appliance_really_is_the_fault():
    out = sl.layer_device(_ctx({"device_health": lambda a: {
        "status": "crit", "maintenance": False, "reasons": [
            {"signal": "capacity", "label": "Capacity", "status": "crit",
             "text": "cpu 99%"}]}}))
    assert out["verdict"] == sl.FAIL and "cannot serve" in out["headline"]


def test_a_healthy_appliance_passes_rung_zero():
    out = sl.layer_device(_ctx({"device_health": lambda a: {
        "status": "ok", "maintenance": False, "reasons": []}}))
    assert out["verdict"] == sl.PASS


def test_an_uncached_object_is_looked_up_in_the_list_not_declared_missing():
    rows = [{"name": "other"}, {"name": "pol", "status": "enable"}]
    out = sl.layer_policy(_ctx({"read_policy": lambda a, n: None,
                                "object_list": lambda a: rows}))
    assert out["verdict"] == sl.PASS, (
        "policy_full_cached returns None for 'not cached', not for 'not "
        "present'; most of this fleet's policies are not deep-harvested")


def test_an_object_absent_from_a_populated_list_really_is_missing():
    out = sl.layer_policy(_ctx({"read_policy": lambda a, n: None,
                                "object_list": lambda a: [{"name": "other"}]}))
    assert out["verdict"] == sl.FAIL


def test_an_empty_harvest_cannot_say_the_object_is_missing():
    out = sl.layer_policy(_ctx({"read_policy": lambda a, n: None,
                                "object_list": lambda a: []}))
    assert out["verdict"] == sl.UNKNOWN


def test_an_unreadable_object_list_is_unknown_not_absence():
    out = sl.layer_policy(_ctx({"read_policy": lambda a, n: None,
                                "object_list": lambda a: None}))
    assert out["verdict"] == sl.UNKNOWN


def test_a_disabled_object_found_only_in_the_list_is_still_the_fault():
    out = sl.layer_policy(_ctx({"read_policy": lambda a, n: None,
                                "object_list": lambda a: [
                                    {"name": "pol", "status": "disable"}]}))
    assert out["verdict"] == sl.FAIL and "DISABLED" in out["headline"]


def test_a_disabled_object_is_the_fault_and_says_which_object():
    out = sl.layer_policy(_ctx({"read_policy": lambda a, n: {
        "status": "disable"}}))
    assert out["verdict"] == sl.FAIL and "DISABLED" in out["headline"]


def test_a_pool_whose_every_member_is_disabled_fails_instead_of_looking_empty():
    rows = [{"address": "1.1.1.1", "port": 80, "enabled": False, "pool": "p"},
            {"address": "1.1.1.2", "port": 80, "enabled": False, "pool": "p"}]
    out = sl.layer_pool(_ctx({"pool_targets": lambda a, p: rows}))
    assert out["verdict"] == sl.FAIL and "DISABLED" in out["headline"]


def test_every_backend_down_is_the_fault_not_a_warning():
    rows = [{"address": "1.1.1.1", "port": 80,
             "appliance": {"verdict": "no reply"}, "local": {"verdict": "timeout"}}]
    from app.services import backend_probe
    out = sl.layer_backend(_ctx(
        {"probe_backends": lambda t, **k: rows,
         "summarise_backends": backend_probe.summarise},
        state={"pool_rows": [{"address": "1.1.1.1", "port": 80}]}))
    assert out["verdict"] == sl.FAIL, (
        "a pool with nothing behind it IS the localisation; downgrading it to "
        "a warning sends the walk on to rungs that can only describe the "
        "consequence")


def test_some_backends_down_is_a_warning_because_the_service_still_serves():
    rows = [{"address": "1.1.1.1", "port": 80, "local": {"ok": True}},
            {"address": "1.1.1.2", "port": 80, "local": {"verdict": "timeout"}}]
    from app.services import backend_probe
    out = sl.layer_backend(_ctx(
        {"probe_backends": lambda t, **k: rows,
         "summarise_backends": backend_probe.summarise},
        state={"pool_rows": rows}))
    assert out["verdict"] == sl.WARN


def test_a_missing_object_on_a_box_that_listed_nothing_is_unknown_not_missing():
    rows = [{"policy": "p", "error_kind": "no_such_policy",
             "error": "the appliance does not list this policy"}]
    out = sl.layer_pool(_ctx({"pool_targets": lambda a, p: rows,
                              "object_count": lambda a: 0}))
    assert out["verdict"] == sl.UNKNOWN, (
        "an unlicensed FortiWeb answers 423 with no results key, which the "
        "reader turns into an empty list; calling that 'the object is missing' "
        "sends an operator hunting a policy that is sitting right there")


def test_a_missing_object_on_a_box_that_listed_others_really_is_missing():
    rows = [{"policy": "p", "error_kind": "no_such_policy", "error": "x"}]
    out = sl.layer_pool(_ctx({"pool_targets": lambda a, p: rows,
                              "object_count": lambda a: 12}))
    assert out["verdict"] == sl.FAIL


def test_an_uncountable_object_list_leaves_the_original_answer_standing():
    rows = [{"policy": "p", "error_kind": "no_such_policy", "error": "x"}]
    out = sl.layer_pool(_ctx({"pool_targets": lambda a, p: rows,
                              "object_count": lambda a: None}))
    assert out["verdict"] == sl.FAIL, (
        "'the count could not be taken' must not be spent as evidence; "
        "replacing one guess with another is not a safeguard")


def test_the_object_list_adapter_refuses_to_guess_the_adc_section_name():
    #  The reader must be MADE to answer, or this proves nothing: with no row
    #  in the database read_objects raises, the adapter swallows it and returns
    #  None anyway — so a version with no ADC branch at all would pass.
    import app.services.read_layer as rl
    orig = rl.read_objects
    rl.read_objects = lambda aid, logical, **k: ([{"name": "x"}], {})
    try:
        adc = sl.default_ports()["object_list"](Appl(kind="fortiadc"))
        web = sl.default_ports()["object_list"](Appl(kind="fortiweb"))
    finally:
        rl.read_objects = orig
    assert web == [{"name": "x"}], "the FortiWeb path must still read"
    assert adc is None, (
        "reading a FortiADC through the FortiWeb section name returns an EMPTY "
        "list, and an empty list reads as a device with no virtual servers — "
        "which layer 1 would then be entitled to call an absent object")


def test_the_policy_adapter_unpacks_the_tuple_read_layer_actually_returns():
    ports = sl.default_ports()
    import app.services.read_layer as rl
    orig = rl.policy_full_cached
    rl.policy_full_cached = lambda aid, name, **k: (
        {"policy": {"status": "disable", "server-pool": "sp"}}, [], {})
    try:
        out = ports["read_policy"](Appl(), "p")
    finally:
        rl.policy_full_cached = orig
    assert out["status"] == "disable", (
        "the adapter used to hand the raw 3-tuple to the rung; because a rung "
        "that raises is UNKNOWN by design, that broke as 'could not look' on "
        "a live device instead of as a crash")


def test_backends_that_no_vantage_could_test_are_unknown_not_reachable():
    rows = [{"address": "1.1.1.1", "port": 80,
             "appliance": {"verdict": "not probed"}, "local": {}}]
    from app.services import backend_probe
    out = sl.layer_backend(_ctx(
        {"probe_backends": lambda t, **k: rows,
         "summarise_backends": backend_probe.summarise},
        state={"pool_rows": [{"address": "1.1.1.1", "port": 80}]}))
    assert out["verdict"] == sl.UNKNOWN, (
        "'not probed' folded into health is the failure mode backend_probe "
        "exists to avoid; Scout must not undo it one layer up")


def test_waf_blocks_alone_are_normal_and_only_escalate_with_a_4xx_front_door():
    rows = [{"date": "d", "src": "1.2.3.4", "msg": "sig"}]
    quiet = sl.layer_waf(_ctx({"recent_attacks": lambda a, p, m: rows},
                              state={"leg_a": {"status": 200}}))
    assert quiet["verdict"] == sl.PASS
    loud = sl.layer_waf(_ctx({"recent_attacks": lambda a, p, m: rows},
                             state={"leg_a": {"status": 403}}))
    assert loud["verdict"] == sl.FAIL and "WAF is blocking" in loud["headline"]


def test_a_typed_front_end_wins_over_a_derived_one():
    ctx = sl.Ctx(target=sl.Target(appliance=Appl(), policy="p",
                                  hostname="typed.example", port=8443),
                 opts=sl.Options(), ports={
                     "front_end": lambda a, p: {"host": "derived.example",
                                                "port": 443}})
    ep = sl._endpoint(ctx)
    assert ep["host"] == "typed.example" and ep["port"] == 8443


def test_a_refused_front_end_target_is_reported_and_not_dialled_anyway():
    def guard(host, port):
        raise ValueError("metadata address")
    ctx = sl.Ctx(target=sl.Target(appliance=Appl(), policy="p",
                                  hostname="bad.example"),
                 opts=sl.Options(), ports={"authorise_target": guard})
    assert sl._endpoint(ctx) is None
    assert "metadata" in ctx.state["endpoint_error"]


# --------------------------------------------------------------------------- #
#  FortiAnalyzer transport                                                      #
# --------------------------------------------------------------------------- #
class FakeFaz:
    def __init__(self, add=None, get=None):
        self._add, self._get = add or ({"tid": 7}, None), get or ([], None)
        self.calls = []

    def call(self, verb, url, **params):
        self.calls.append((verb, url, params))
        return self._add if verb == "add" else self._get

    def logout(self):
        pass


def _dt():
    from datetime import datetime
    return datetime(2026, 1, 1, 0, 0, 0)


def test_a_collector_refusal_is_an_error_and_never_zero_rows():
    fake = FakeFaz(add=(None, "no permission"))
    rows, err = faz_logs.search(object(), start=_dt(), end=_dt(),
                                client_factory=lambda a, t: fake)
    assert rows == [] and "logsearch refused" in err, (
        "a refusal rendered as an empty result set is a refusal that gets read "
        "as evidence of absence")


def test_a_missing_task_id_is_an_error_too():
    rows, err = faz_logs.search(object(), start=_dt(), end=_dt(),
                                client_factory=lambda a, t: FakeFaz(add=({}, None)))
    assert rows == [] and "no task id" in err


def test_an_unset_fortigate_means_every_device_not_a_device_called_nothing():
    assert faz_logs.device_selector("") == []
    assert faz_logs.device_selector("  ") == []
    assert faz_logs.device_selector("fg1", "vd") == [{"devid": "fg1",
                                                      "vdom": "vd"}]


def test_a_neutralised_collector_is_ineligible_and_says_why():
    class A:
        kind, host, maintenance = "fortianalyzer", "retired-faz01.invalid", False
    ok, why = faz_logs.reachable(A())
    assert ok is False and ".invalid" in why
    assert faz_logs.reachable(None)[0] is False


def test_the_row_limit_is_clamped_not_trusted():
    fake = FakeFaz(get=({"data": []}, None))
    faz_logs.search(object(), start=_dt(), end=_dt(), limit=10 ** 9,
                    client_factory=lambda a, t: fake)
    assert fake.calls[-1][2]["limit"] == faz_logs.MAX_LIMIT


def test_sentinel_still_routes_its_border_lookup_through_this_one_transport():
    src = _read(os.path.join(REPO, "app", "services", "sentinel", "edge.py"))
    assert "faz_logs.search(" in src, (
        "two authors of the logview JSON-RPC route is how the second one stops "
        "being fixed when a firmware changes shape")


# --------------------------------------------------------------------------- #
#  Reachability of the page itself                                              #
# --------------------------------------------------------------------------- #
def test_scout_is_registered_as_a_blueprint():
    assert '("app.views.scout", "bp")' in _read(INIT_PY)


def test_scout_is_allowed_in_the_fortiadc_adom_it_is_drawn_in():
    src = _read(INIT_PY)
    adc = src[src.index("adc_bps = {"):src.index("adc_eps = {")]
    assert "'scout'" in adc, (
        "the ADC sidebar draws the entry; without the allowlist entry the "
        "click lands on /adc/ — a live link that goes nowhere"
    )


def test_the_operations_group_opens_on_scout():
    line = [ln for ln in _read(BASE_TPL).splitlines()
            if "set _g_ops" in ln][0]
    assert "'scout'" in line, (
        "landing on /scout/ with the menu that leads there collapsed is a page "
        "that works and a navigation that lies")


def test_scout_sits_inside_the_fortiweb_troubleshooting_subgroup():
    src = _read(BASE_TPL)
    i = src.index('data-nav-subgroup="Troubleshooting"')
    block = src[i:src.index("</div>", src.index("subgroup-body", i))]
    assert "url_for('scout.index')" in block
    assert "'scout'" in src[i - 200:i + 120], (
        "the subgroup must also OPEN on scout, or the entry is drawn folded "
        "under the group that leads to it")


def test_the_fortiweb_edit_landed_in_the_fortiweb_branch_not_another_one():
    #  The four <a> lines of this subgroup are byte-identical across branches
    #  and the Fleet anchor exists in FOUR of them.  On 2026-09-08 an edit
    #  anchored that way deleted the GLOBAL ADOM's entries instead, and a
    #  count-the-survivors assertion passed.  Anchor on the BRANCH MARKER.
    src = _read(BASE_TPL)
    #  NOT rindex("{% else %}"): the FortiWeb branch contains several nested
    #  {% else %} of its own, so the LAST one in the file sits far below this
    #  subgroup and the assertion would be false against a correct tree. The
    #  branch-level else is the one that follows the placeholder arm.
    fw_branch = src.index("{% else %}", src.index("{% elif product.placeholder %}"))
    global_branch = src.index("{% elif product.key == 'global' %}")
    scout = src.index("url_for('scout.index')", src.index(
        'data-nav-subgroup="Troubleshooting"'))
    assert scout > fw_branch > global_branch


def test_scout_is_also_reachable_from_the_fortiadc_sidebar():
    src = _read(BASE_TPL)
    adc = src.index("{% if product.key == 'fortiadc' %}")
    nxt = src.index("{% elif product.key == 'global' %}", adc)
    assert "url_for('scout.index')" in src[adc:nxt], (
        "FortiADC is the product whose virtual servers this ladder also walks; "
        "shipping the engine with no way in is shipping it off"
    )


# --------------------------------------------------------------------------- #
#  The template — the two defects that render a page silently broken            #
# --------------------------------------------------------------------------- #
def _no_jinja_comments(src: str) -> str:
    """Strip ``{# ... #}`` before asserting on markup.

    This template's header comment EXPLAINS the nonce rule, so it necessarily
    contains the literal ``<style``/``<script`` the guard hunts for. That is the
    NINTH substring assertion in this repository to match the comment that
    documents it, and the first version of this guard failed against a correct
    template for exactly that reason.
    """
    return re.sub(r"\{#.*?#\}", "", src, flags=re.S)


def test_the_template_carries_no_un_nonced_style_or_script():
    src = _no_jinja_comments(_read(SCOUT_TPL))
    for tag in ("<style", "<script"):
        for m in re.finditer(re.escape(tag), src):
            head = src[m.start():src.index(">", m.start())]
            assert "nonce" in head, (
                "%s without a nonce is dropped by this CSP: the page renders "
                "with no CSS, or the behaviour never binds" % tag)


def test_the_post_form_carries_a_csrf_token():
    src = _read(SCOUT_TPL)
    assert 'name="csrf_token"' in src, (
        "CSRFProtect rejects the submit and the operator reads 'your session "
        "expired' as if it were their session")


def test_the_template_uses_the_light_theme_badges_only():
    src = _read(SCOUT_TPL)
    for pastel in ("#6ee7b7", "#fcd34d", "#fca5a5", "#93c5fd", "#c4b5fd",
                   "rgba(30,41,59"):
        assert pastel not in src, (
            "dark-theme pills land at ~1.4:1 on this product's white cards")
