"""Threshold policy — declare once, inherit live, always say where it came from.

The defect these guard (measured on the live primary, 2026-08-06): **all 42
probes carried the identical pair 80 / 95**, the discovery literal, never once
edited — because there was no way to state a threshold anywhere except on an
individual probe row. ``warn_pct = 80`` was also stored on ``interface``,
``proxyd``, ``throughput`` and ``transactions`` probes, none of which grade on
a percentage.

Every assertion below is about one of four properties:

* the registry is DATA, and the form / validator / resolver read the SAME entry;
* ``NULL`` inherits and ``0`` disables, and they never collapse into each other;
* a resolved value always carries its ORIGIN (live inheritance is only safe
  because of this);
* silencing a binary fact changes its GRADE and never its VISIBILITY.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.models import Appliance, AppSetting, MonitorProbe, User, db
from app.services import alerts as alerts_svc
from app.services import deep_monitor as dm
from app.services import device_health as dh
from app.services import host_health as hh
from app.services import thresholds as th
from tests.conftest import login


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _appliance(app, kind="fortiweb", name="dev1"):
    a = Appliance(name=name, host="192.0.2.10", port=443, kind=kind,
                  username="admin")
    a.password = "pw"          # setter encrypts; the columns are NOT NULL
    db.session.add(a)
    db.session.commit()
    return a


def _probe(app, appliance=None, kind="cpu", **kw):
    p = MonitorProbe(kind=kind, name=f"{kind} probe",
                     appliance_id=(appliance.id if appliance else None), **kw)
    db.session.add(p)
    db.session.commit()
    return p


def _set(key, value):
    AppSetting.set(key, str(value))
    db.session.commit()
    th.invalidate()


# ---------------------------------------------------------------------------
# 1. the registry is DATA, and it is the only list
# ---------------------------------------------------------------------------

def test_every_measure_field_is_a_real_probe_column():
    """A field whose key is not a column resolves to nothing and grades on the
    shipped default for ever, silently. The key IS the column on purpose."""
    cols = {c.name for c in MonitorProbe.__table__.columns}
    assert th.MEASURE, "the measure registry must not be empty"
    for kind, fields in th.MEASURE.items():
        assert fields, f"{kind} declares no fields"
        for f in fields:
            assert f.key in cols, f"{kind}.{f.key} is not a MonitorProbe column"


def test_every_measure_kind_and_fact_kind_is_a_real_probe_kind():
    assert set(th.MEASURE) <= set(dm.KINDS)
    assert th.FACTS
    for fact in th.FACTS:
        assert fact.kinds, f"{fact.key} names no kind"
        assert set(fact.kinds) <= set(dm.KINDS), fact.key
        assert fact.default in th.SEVERITIES


def test_a_scope_is_only_offered_the_kinds_its_product_can_measure(app):
    """Offering a proxyd threshold on FortiADC is a control with nothing behind
    it — the runner refuses the kind on that product."""
    with app.app_context():
        fw = set(th.measurable_kinds("fortiweb"))
        adc = set(th.measurable_kinds("fortiadc"))
        assert "policy_sessions" in fw and "policy_sessions" not in adc
        assert "licence" in set(th.measurable_kinds("fortiauthenticator"))
        assert "licence" not in fw
        for scope in (s["key"] for s in th.all_scopes() if s["type"] == "product"):
            for kind in th.measurable_kinds(scope):
                assert dm.supports(kind, scope), (scope, kind)


def test_facts_are_only_offered_where_they_can_occur(app):
    with app.app_context():
        fw = {f.key for f in th.facts_for("fortiweb")}
        adc = {f.key for f in th.facts_for("fortiadc")}
        assert "proxyd_absent" in fw and "proxyd_absent" not in adc
        assert "iface_changed" in adc          # FortiADC does have interfaces
        # non-product scopes own no device facts at all
        assert th.facts_for("host") == () and th.facts_for("satom") == ()


def test_the_six_scopes_are_derived_from_the_adom_registry(app):
    with app.app_context():
        keys = [s["key"] for s in th.all_scopes()]
        assert keys[-2:] == ["satom", "host"]
        from app.services.product_scope import device_products
        assert keys[:-2] == [k for k, _ in device_products()]
        assert th.is_scope("fortiweb") and not th.is_scope("nope")


def test_manager_defaults_match_the_alert_engine(app):
    """A "factory default" printed on the form that is not what the engine uses
    when the key is unset is a lie nothing raises about. The two lists are
    duplicated (a NamedTuple default is evaluated at import, and importing the
    engine from the registry would be a cycle) so the equality is pinned here."""
    with app.app_context():
        checked = 0
        for f in th.SATOM:
            assert f.store, f"{f.key} must write an alerts.* key"
            engine_default = alerts_svc.DEFAULTS.get(f.store)
            assert engine_default is not None, f"{f.store} unknown to the engine"
            assert float(engine_default) == float(f.default), (
                f"{f.key}: form says {f.default}, engine ships {engine_default}")
            checked += 1
        assert checked >= 5, "anti-vacuity: the manager scope lost its fields"


# ---------------------------------------------------------------------------
# 2. NULL inherits, 0 disables — the rule everything else rests on
# ---------------------------------------------------------------------------

def test_null_inherits_from_the_product_scope(app):
    with app.app_context():
        a = _appliance(app)
        p = _probe(app, a, "cpu", warn_pct=None)
        assert th.for_probe(p, "warn_pct") == th.Resolved(80, "default")
        _set("thresholds.fortiweb.cpu.warn_pct", 70)
        r = th.for_probe(p, "warn_pct")
        assert (r.value, r.origin, r.scope) == (70.0, "scope", "fortiweb")
        assert "inherited from fortiweb" in r.explain


def test_zero_is_an_answer_and_is_never_inherited_over(app):
    """0 means "never page me for this level". Treating it as "unset" would
    switch paging back ON for a probe somebody deliberately silenced."""
    with app.app_context():
        a = _appliance(app)
        p = _probe(app, a, "cpu", warn_pct=0)
        _set("thresholds.fortiweb.cpu.warn_pct", 70)
        r = th.for_probe(p, "warn_pct")
        assert (r.value, r.origin) == (0, "probe")
        assert th.num(p, "warn_pct") == 0.0


def test_an_explicit_override_wins_over_the_scope(app):
    with app.app_context():
        a = _appliance(app)
        p = _probe(app, a, "cpu", warn_pct=91)
        _set("thresholds.fortiweb.cpu.warn_pct", 70)
        r = th.for_probe(p, "warn_pct")
        assert (r.value, r.origin) == (91, "probe")
        assert r.explain == "set on this probe"


def test_scopes_do_not_leak_into_each_other(app):
    with app.app_context():
        fw, adc = _appliance(app, "fortiweb", "fw"), _appliance(app, "fortiadc", "adc")
        pw, pa = _probe(app, fw, "cpu"), _probe(app, adc, "cpu")
        _set("thresholds.fortiweb.cpu.warn_pct", 55)
        assert th.for_probe(pw, "warn_pct").value == 55.0
        assert th.for_probe(pa, "warn_pct").origin == "default"


def test_a_probe_with_no_device_inherits_from_nothing(app):
    """A bare URL check belongs to no product. Guessing one would attach it to a
    fleet policy it is not part of."""
    with app.app_context():
        p = _probe(app, None, "https")
        _set("thresholds.fortiweb.https.warn_ms", 100)
        assert th.probe_scope(p) == ""
        assert th.for_probe(p, "warn_ms").origin == "default"


def test_the_legacy_global_key_sits_below_the_scope_and_above_the_default(app):
    with app.app_context():
        assert th.rollup("fortiweb", "stale_hours").value == 6.0
        _set("monitoring.stale_hours", 9)
        assert th.rollup("fortiweb", "stale_hours").value == 9.0
        _set("thresholds.fortiweb.stale_hours", 2)
        assert th.rollup("fortiweb", "stale_hours").value == 2.0
        # ...and the other product still sees the legacy value, not FortiWeb's
        assert th.rollup("fortiadc", "stale_hours").value == 9.0


# ---------------------------------------------------------------------------
# 3. origin is always reported
# ---------------------------------------------------------------------------

def test_every_tunable_of_a_probe_reports_an_origin(app):
    """Live inheritance is only safe because the page can say where a number
    came from. A field with no origin is a critical with no visible cause."""
    with app.app_context():
        a = _appliance(app)
        for kind, fields in th.MEASURE.items():
            if not dm.supports(kind, "fortiweb"):
                continue
            p = _probe(app, a, kind)
            rows = th.probe_origins(p)
            assert {r["key"] for r in rows} == {f.key for f in fields}, kind
            for r in rows:
                assert r["origin"] in ("probe", "scope", "default")
                assert r["explain"]
                assert r["inherited"] is (r["origin"] != "probe")


# ---------------------------------------------------------------------------
# 4. writes: blank clears, junk is refused, reset is a real escape hatch
# ---------------------------------------------------------------------------

def test_blank_clears_an_override_and_junk_is_refused(app):
    with app.app_context():
        res = th.save_scope("fortiweb", {"m__cpu__warn_pct": "70"})
        assert res["saved"] == 1 and not res["errors"]
        assert th.rollup("fortiweb", "stale_hours").origin == "default"
        assert th.resolve("fortiweb", th.MEASURE["cpu"][0], "cpu").value == 70.0

        res = th.save_scope("fortiweb", {"m__cpu__warn_pct": ""})
        assert res["cleared"] == 1
        assert th.resolve("fortiweb", th.MEASURE["cpu"][0], "cpu").origin == "default"

        res = th.save_scope("fortiweb", {"m__cpu__warn_pct": "abc"})
        assert res["errors"] and res["saved"] == 0
        res = th.save_scope("fortiweb", {"m__cpu__warn_pct": "500"})
        assert res["errors"], "a percentage above 100 must be refused"
        res = th.save_scope("fortiweb", {"m__cpu__warn_pct": "-1"})
        assert res["errors"], "a negative threshold must be refused"


def test_reset_scope_is_the_anti_lockout_path(app):
    """A scope tuned into permanent red has to be recoverable without psql."""
    with app.app_context():
        th.save_scope("fortiweb", {"m__cpu__warn_pct": "1", "r__stale_hours": "0.01",
                                   "f__policy_disabled": "off"})
        assert th.fact_severity("fortiweb", "policy_disabled") == "off"
        n = th.reset_scope("fortiweb")
        assert n >= 3
        assert th.resolve("fortiweb", th.MEASURE["cpu"][0], "cpu").origin == "default"
        assert th.fact_severity("fortiweb", "policy_disabled") == "warn"


def test_the_manager_scope_writes_the_engines_own_keys(app):
    """One number, two views. A ``thresholds.satom.*`` twin would drift the
    first time somebody edited the older Email tab."""
    with app.app_context():
        th.save_scope("satom", {"s__cert_days": "30"})
        assert AppSetting.get("alerts.cert_days") == "30"
        assert AppSetting.get("thresholds.satom.cert_days") is None
        assert alerts_svc.config()["cert_days"] == 30


# ---------------------------------------------------------------------------
# 5. binary facts — severity changes the GRADE, never the VISIBILITY
# ---------------------------------------------------------------------------

_POLICY_ROW = {"sessions": 1, "conn_per_sec": 2, "status": "enable",
               "app_response_time": 0}
_DOWN = [{"server": "192.0.2.20", "port": 80, "up": False, "health": "up"}]


def _classify(sev=None, row=None, members=None):
    return dm.classify_policy_sessions(
        row or dict(_POLICY_ROW), members if members is not None else _DOWN,
        warn_num=0, crit_num=0, warn_ms=0, fingerprint="a",
        prev_fingerprint="a", sev=sev)


def test_default_fact_severity_reproduces_the_pre_change_behaviour():
    assert _classify()[0] == "crit"                       # all backends down
    assert "ALL backends down" in _classify()[1]
    st, txt = _classify(row=dict(_POLICY_ROW, status="disable"), members=[])
    assert st == "warn" and "policy disable" in txt


def test_silencing_a_fact_lowers_the_grade_but_still_prints_it():
    off = {"backends_all_down": None}
    st, txt = _classify(off)
    assert st == "ok", "severity 'off' must not grade"
    assert "ALL backends down" in txt, "a silenced fact must STILL be printed"
    assert "severity: off" in txt, "and must say it was silenced"


def test_lowering_a_fact_grades_at_the_chosen_level():
    st, txt = _classify({"backends_all_down": "warn"})
    assert st == "warn" and "severity: warn" in txt


@pytest.mark.parametrize("key", [f.key for f in th.FACTS])
def test_every_fact_can_be_silenced_and_restored(app, key):
    with app.app_context():
        assert th.fact_status("fortiweb", key) == th.FACT_BY_KEY[key].default
        _set(th.fact_key("fortiweb", key), "off")
        assert th.fact_status("fortiweb", key) is None
        _set(th.fact_key("fortiweb", key), "garbage")
        assert th.fact_status("fortiweb", key) == th.FACT_BY_KEY[key].default, (
            "an unreadable severity must fall back to the shipped one, not to off")


def test_proxyd_and_interface_facts_are_wired_too():
    agg = {"count": 0, "process": "proxyd", "pid_fingerprint": "x"}
    parsed = {"parsed": True}
    assert dm.classify_proxyd(agg, parsed, "")[0] == "crit"
    st, txt = dm.classify_proxyd(agg, parsed, "", sev={"proxyd_absent": None})
    assert st == "ok" and "is NOT running" in txt

    st, txt = dm.classify_interface("f", "p", [{"name": "p1", "ip": "", "status": "up"}],
                                    [], cache_age_h=0, stale_after_h=6,
                                    missing=["port9"])
    assert st == "crit" and "port9" in txt
    st, txt = dm.classify_interface("f", "p", [{"name": "p1", "ip": "", "status": "up"}],
                                    [], cache_age_h=0, stale_after_h=6,
                                    missing=["port9"], sev={"iface_missing": "warn"})
    assert st == "warn" and "port9" in txt


# ---------------------------------------------------------------------------
# 6. the roll-up reads its own product
# ---------------------------------------------------------------------------

def test_device_rollup_constants_come_from_the_devices_product(app):
    with app.app_context():
        _set("thresholds.fortianalyzer.stale_hours", 48)
        _set("thresholds.fortianalyzer.error_streak_crit", 9)
        assert dh.limits("fortianalyzer")["stale_hours"] == 48.0
        assert dh.limits("fortianalyzer")["error_streak_crit"] == 9.0
        # a FortiWeb is untouched by a FortiAnalyzer decision
        assert dh.limits("fortiweb")["stale_hours"] == 6.0


def test_cache_signal_uses_the_supplied_multiplier():
    old = datetime.utcnow() - timedelta(hours=13)
    assert dh.cache_signal({"generated_at": old}, 6, 4.0)["status"] == "warn"
    assert dh.cache_signal({"generated_at": old}, 6, 2.0)["status"] == "crit"


def test_sync_streak_threshold_is_a_parameter():
    from app.models_cache import SyncRun  # noqa: F401 (import guard)
    assert dh.sync_signal.__defaults__ == (None,)


# ---------------------------------------------------------------------------
# 7. suppression: targeted, expiring, visible
# ---------------------------------------------------------------------------

def test_a_suppressed_probe_leaves_the_rollup_but_keeps_its_own_status(app):
    with app.app_context():
        a = _appliance(app)
        bad = _probe(app, a, "cpu", last_status="crit")
        good = _probe(app, a, "memory", last_status="ok")
        assert dh.probe_signal(a.id)["status"] == "crit"

        bad.suppress_until = datetime.utcnow() + timedelta(hours=2)
        bad.suppress_reason = "backends dead since July"
        db.session.commit()

        sig = dh.probe_signal(a.id)
        assert sig["status"] == "ok", "the muted probe must not raise the device"
        assert sig["suppressed"] == 1
        assert "suppressed" in sig["text"], "a chosen silence is still lost coverage"
        # the probe itself is untouched
        assert bad.last_status == "crit" and bad.suppressed
        assert "backends dead since July" in bad.suppress_note
        assert good.suppressed is False


def test_an_expired_suppression_is_inert(app):
    with app.app_context():
        a = _appliance(app)
        p = _probe(app, a, "cpu", last_status="crit")
        p.suppress_until = datetime.utcnow() - timedelta(minutes=1)
        p.suppress_reason = "yesterday"
        db.session.commit()
        assert p.suppressed is False
        assert dh.probe_signal(a.id)["status"] == "crit"


def test_muting_every_probe_reads_as_unknown_not_healthy(app):
    with app.app_context():
        a = _appliance(app)
        p = _probe(app, a, "cpu", last_status="ok")
        p.suppress_until = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()
        sig = dh.probe_signal(a.id)
        assert sig["status"] == "unknown"
        assert "no coverage" in sig["text"]


def test_the_mute_form_field_is_capped_and_clears_on_zero(app):
    from app.views.monitor_probes import MAX_SUPPRESS_HOURS, _apply_suppression
    with app.app_context():
        a = _appliance(app)
        p = _probe(app, a, "cpu")
        _apply_suppression(p, {"suppress_hours": "999999", "suppress_reason": "x"})
        assert p.suppress_until is not None
        span = (p.suppress_until - datetime.utcnow()).total_seconds() / 3600.0
        assert span <= MAX_SUPPRESS_HOURS + 1, "there must be no permanent mute"
        _apply_suppression(p, {"suppress_hours": "0"})
        assert p.suppress_until is None and p.suppress_reason == ""
        # a field that is not on the form must never clear a live mute
        p.suppress_until = datetime.utcnow() + timedelta(hours=1)
        _apply_suppression(p, {})
        assert p.suppress_until is not None


# ---------------------------------------------------------------------------
# 8. the form: blank clears, absent leaves alone
# ---------------------------------------------------------------------------

def test_the_probe_form_distinguishes_absent_from_blank(app, client):
    """Three inputs, three answers. Conflating blank with absent would make
    every edit of an HTTPS probe wipe the thresholds it does not render."""
    with app.app_context():
        u = User(username="a1", role="admin")
        u.set_password("x")
        db.session.add(u)
        a = _appliance(app)
        p = _probe(app, a, "cpu", warn_pct=90)
        db.session.commit()
        pid, aid, uid = p.id, a.id, u.id
    login(client, uid, "fortiweb")
    base = "/monitoring/deep/probe/%d" % pid
    common = {"kind": "cpu", "name": "cpu probe", "appliance_id": aid,
              "interval_min": 3, "timeout_s": 10}
    client.post(base, data=dict(common, warn_pct=""))
    with app.app_context():
        assert db.session.get(MonitorProbe, pid).warn_pct is None
    client.post(base, data=dict(common, warn_pct="77"))
    with app.app_context():
        assert db.session.get(MonitorProbe, pid).warn_pct == 77
    client.post(base, data=common)          # field absent entirely
    with app.app_context():
        assert db.session.get(MonitorProbe, pid).warn_pct == 77


# ---------------------------------------------------------------------------
# 9. the machine — the scope that could not deliver bad news
# ---------------------------------------------------------------------------

_LIM = {"disk_warn_pct": 80, "disk_crit_pct": 92, "mem_warn_pct": 85,
        "mem_crit_pct": 95, "load_warn_pct": 150, "load_crit_pct": 400}


def _stats(disk=10.0, mem=10.0, load=10.0):
    return {"hostname": "n1", "cpus": 4, "load": [0.4, 0.4, 0.4],
            "load_pct": load, "mem_total_mb": 4096,
            "mem_used_mb": int(4096 * mem / 100), "mem_pct": mem,
            "disks": [{"mount": "/", "total_gb": 20.0,
                       "used_gb": 20.0 * disk / 100, "pct": disk}]}


def test_a_node_we_could_not_read_is_unknown_never_ok():
    """The defect that made the device badge structurally unable to turn red."""
    g = hh.grade_stats(None, _LIM)
    assert g["status"] == "unknown"
    assert g["reasons"], "an unknown must still be explained"
    n = hh.grade_node({"name": "peer", "reachable": False}, _LIM)
    assert n["status"] == "unknown" and "unreachable" in n["reasons"][0]["text"]


@pytest.mark.parametrize("pct,expected", [(10, "ok"), (85, "warn"), (95, "crit")])
def test_disk_is_graded_and_the_incident_would_now_fire(pct, expected):
    """satom-node-1 hit 95 % on 2026-07-28 with every light green."""
    g = hh.grade_stats(_stats(disk=pct), _LIM)
    assert g["signals"]["disk"]["status"] == expected
    assert g["status"] == expected


def test_memory_and_load_are_graded_too():
    assert hh.grade_stats(_stats(mem=97), _LIM)["signals"]["memory"]["status"] == "crit"
    assert hh.grade_stats(_stats(load=200), _LIM)["signals"]["load"]["status"] == "warn"
    assert hh.grade_stats(_stats(load=500), _LIM)["signals"]["load"]["status"] == "crit"


def test_a_zero_host_level_is_off_not_a_limit_of_zero():
    lim = dict(_LIM, disk_warn_pct=0, disk_crit_pct=0)
    assert hh.grade_stats(_stats(disk=99), lim)["signals"]["disk"]["status"] == "ok"


def test_a_missing_reading_is_unknown_not_ok():
    s = _stats()
    s["mem_pct"] = None
    s["disks"] = []
    g = hh.grade_stats(s, _LIM)
    assert g["signals"]["memory"]["status"] == "unknown"
    assert g["signals"]["disk"]["status"] == "unknown"


def test_host_thresholds_come_from_the_host_scope(app):
    with app.app_context():
        assert hh.limits()["disk_crit_pct"] == 92
        th.save_scope("host", {"s__disk_crit_pct": "70"})
        assert hh.limits()["disk_crit_pct"] == 70.0
        assert hh.grade_stats(_stats(disk=75))["signals"]["disk"]["status"] == "crit"


def test_the_fleet_rollup_takes_the_worst_node():
    nodes = [{"name": "a", "reachable": True, "host_stats": _stats()},
             {"name": "b", "reachable": True, "host_stats": _stats(disk=99)}]
    f = hh.fleet(nodes)
    assert f["status"] == "crit"
    assert [n["name"] for n in f["nodes"]] == ["a", "b"]


# ---------------------------------------------------------------------------
# 10. the machine reaches the mailbox
# ---------------------------------------------------------------------------

def test_check_host_emits_one_finding_per_node_and_names_the_scope(app, monkeypatch):
    with app.app_context():
        monkeypatch.setattr(hh, "fleet", lambda nodes=None: {"status": "crit", "nodes": [
            hh.grade_node({"name": "n1", "reachable": True,
                           "host_stats": _stats(disk=99, mem=97)}, _LIM),
            hh.grade_node({"name": "n2", "reachable": True,
                           "host_stats": _stats()}, _LIM),
            hh.grade_node({"name": "n3", "reachable": False}, _LIM),
        ]})
        out = alerts_svc._check_host()
        assert len(out) == 1, "one finding per node, and only the failing one"
        f = out[0]
        assert f["severity"] == alerts_svc.SEV_CRITICAL
        assert f["key"].endswith(".crit"), "the status is in the cooldown key"
        assert "Filesystem" in f["detail"] and "Memory" in f["detail"]
        assert "Thresholds" in f["detail"], "the mail must name where to tune it"


def test_an_unreachable_node_is_not_mailed_about_here(app, monkeypatch):
    """The redundancy check already owns "the peer is gone"; two mails for one
    dead standby is how an operator learns to filter the sender."""
    with app.app_context():
        monkeypatch.setattr(hh, "fleet", lambda nodes=None: {"status": "unknown",
            "nodes": [hh.grade_node({"name": "n3", "reachable": False}, _LIM)]})
        assert alerts_svc._check_host() == []


def test_the_host_check_is_registered_and_on_by_default(app):
    with app.app_context():
        keys = [k for k, _ in alerts_svc._CHECKS]
        assert alerts_svc.K_CHK_HOST in keys
        assert alerts_svc.DEFAULTS[alerts_svc.K_CHK_HOST] == "1"
        assert alerts_svc.config()["checks"]["host"] is True


def test_device_findings_point_at_the_scope_that_governs_them(app, monkeypatch):
    with app.app_context():
        a = _appliance(app, "fortiadc", "adc1")
        monkeypatch.setattr(alerts_svc, "_reachable", lambda h, p: True)
        monkeypatch.setattr(dh, "collect_for", lambda ap: {
            "status": "crit", "signals": {},
            "reasons": [{"signal": "cache", "label": "Cache", "status": "crit",
                         "text": "cache 40 d old"}]})
        out = alerts_svc._check_devices()
        assert out and "fortiadc" in out[0]["detail"]
        assert "Thresholds" in out[0]["detail"]
