"""The monitor must not report things that are not true.

Four defects shipped together on 2026-08-11, all of the same shape: nothing
crashed, nothing was slow, no test failed — the console simply asserted
something false, and the operator learned to distrust it. Between them they
produced ~790 of the ~825 alerts of the preceding week.

1. ``sot_store`` hashed the appliance's own WALL CLOCK, so an unchanged
   FortiADC minted a fresh ~500 KB version every hour and raised a "config
   drift" alert for it. 194 of the 206 consecutive version pairs in the live
   store differed in nothing else.
2. ``system_health`` divided the HYPERVISOR's load average by the CONTAINER's
   core count and called the ratio this node's CPU: "220% of 3 cores" for a
   container whose every process was idle.
3. ``deep_monitor`` folded "no health check configured" into "backend down"
   and printed ``ALL backends down`` over servers the appliance reported UP —
   302 consecutive hourly buckets with not one ``ok`` sample.
4. ``alerts`` reported ``dispatched: 2`` on runs where the relay refused every
   recipient, and stamped the cooldown anyway, so the finding was counted as
   sent and then suppressed for six hours.

Each guard below asserts the true statement AND that the false one is no longer
reachable. Assertions run against comment-stripped source where they inspect
source, because a comment explaining a guard contains the string the guard
forbids — the trap this repo has now hit nine times.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from app.services import alerts
from app.services import deep_monitor as dm
from app.services import host_health as hh
from app.services import sot_store
from app.services import system_health as sh
from app.services import thresholds as th

APP_DIR = Path(__file__).resolve().parents[1] / "app"


def _strip_comments(src: str) -> str:
    """Source with '#' comments and docstrings removed."""
    out = []
    for line in src.splitlines():
        out.append(line.split("#", 1)[0])
    text = "\n".join(out)
    return re.sub(r'("""|\'\'\')(?:.|\n)*?\1', "", text)


# ---------------------------------------------------------------------------
# 1. SoT identity — the clock is not configuration
# ---------------------------------------------------------------------------

def _adc(hour: int, minute: int, tz: str = "4", ntp: str = "disable") -> dict:
    """A FortiADC-shaped snapshot. Matches the live blobs field for field."""
    return {
        "generated_at": "2026-08-11T00:00:00",
        "errors": [],
        "sections": {
            "System": {
                "system_time_manual": [{
                    "dst": "enable", "hour": hour, "mday": 6, "minute": minute,
                    "month": 8, "ntpsync": ntp, "second": 22,
                    "syncinterval": "60", "system_date": "2026-08-06",
                    "system_dateTime": "2026-08-06 %02d:%02d:22" % (hour, minute),
                    "tz": tz, "year": 2026,
                }],
            },
        },
    }


def test_clock_only_difference_is_not_a_config_change():
    assert sot_store.canonical_bytes(_adc(14, 35)) == \
        sot_store.canonical_bytes(_adc(15, 38))


def test_time_settings_in_the_same_object_are_still_configuration():
    """tz/ntpsync sit beside the clock. Stripping them too would silence a
    real change to how the appliance keeps time."""
    base = sot_store.canonical_bytes(_adc(14, 35))
    assert sot_store.canonical_bytes(_adc(14, 35, tz="1")) != base
    assert sot_store.canonical_bytes(_adc(14, 35, ntp="enable")) != base


def test_clock_field_names_outside_a_clock_object_are_still_hashed():
    """The rule keys off system_dateTime, not off the field name: a policy
    field called ``hour`` or ``month`` anywhere else is configuration."""
    a = {"sections": {"Web": {"sched": [{"name": "nightly", "hour": 2}]}}}
    b = {"sections": {"Web": {"sched": [{"name": "nightly", "hour": 3}]}}}
    assert sot_store.canonical_bytes(a) != sot_store.canonical_bytes(b)


def test_internal_handle_is_dropped_only_beside_the_name_it_resolves():
    """proxyd renumbers ``*_val`` handles on restart; the sibling name does
    not move. A standalone ``*_val`` has no name to fall back on and stays."""
    paired_a = {"s": [{"signature-rule": "sig-a", "signature-rule_val": 1379}]}
    paired_b = {"s": [{"signature-rule": "sig-a", "signature-rule_val": 1389}]}
    assert sot_store.canonical_bytes(paired_a) == sot_store.canonical_bytes(paired_b)

    lone_a = {"s": [{"orphan_val": 1379}]}
    lone_b = {"s": [{"orphan_val": 1389}]}
    assert sot_store.canonical_bytes(lone_a) != sot_store.canonical_bytes(lone_b)


def test_handle_change_that_accompanies_a_name_change_is_still_a_change():
    a = {"s": [{"signature-rule": "sig-a", "signature-rule_val": 1379}]}
    b = {"s": [{"signature-rule": "sig-b", "signature-rule_val": 1389}]}
    assert sot_store.canonical_bytes(a) != sot_store.canonical_bytes(b)


def test_reverse_reference_list_is_order_insensitive_but_not_content_blind():
    one = {"s": [{"q_ref_string": "inline(a)\ninline(b)\n"}]}
    same_set = {"s": [{"q_ref_string": "inline(b)\ninline(a)\n"}]}
    other = {"s": [{"q_ref_string": "inline(a)\ninline(c)\n"}]}
    assert sot_store.canonical_bytes(one) == sot_store.canonical_bytes(same_set)
    assert sot_store.canonical_bytes(one) != sot_store.canonical_bytes(other)


def test_rolling_allow_time_window_is_not_a_config_change():
    a = {"s": [{"name": "cs", "allow-time": "2026/08/08"}]}
    b = {"s": [{"name": "cs", "allow-time": "2026/08/16"}]}
    assert sot_store.canonical_bytes(a) == sot_store.canonical_bytes(b)


def test_a_real_config_change_still_changes_the_identity():
    """The whole point of the exclusions is that what remains is signal.
    Mirrors the fortiweb09 drift of 2026-08-09: a profile was deleted."""
    before = _adc(14, 35)
    before["sections"]["Web Protection"] = {
        "webprotection_profile_inline": [
            {"name": "wpp-pol-shop-cms"}, {"name": "wpp-full-lab"}]}
    after = _adc(15, 38)          # clock moved too — must not mask the removal
    after["sections"]["Web Protection"] = {
        "webprotection_profile_inline": [{"name": "wpp-full-lab"}]}
    assert sot_store.canonical_bytes(before) != sot_store.canonical_bytes(after)


def test_normalise_does_not_mutate_the_snapshot_it_is_given():
    """Identity is computed on the way to the hash; the blob is stored whole.
    A normaliser that edited its input in place would silently amputate the
    stored history — the one thing a source of truth may never do."""
    snap = _adc(14, 35)
    sot_store.canonical_bytes(snap)
    obj = snap["sections"]["System"]["system_time_manual"][0]
    assert obj["hour"] == 14 and obj["system_dateTime"]


# ---------------------------------------------------------------------------
# 2. CPU — the container's cgroup, never the hypervisor's load average
# ---------------------------------------------------------------------------

def test_host_stats_no_longer_exposes_the_host_over_container_ratio():
    stats = sh.host_stats()
    assert "load_pct" not in stats, (
        "load_pct divided the HOST's load average by the CONTAINER's core "
        "count. Removed rather than corrected so no caller can grade on it.")
    assert "cpu_pct" in stats and "load_scope" in stats


def test_cpu_pct_is_computed_from_the_cgroup_counter(monkeypatch, tmp_path):
    """A 60% busy 4-core container over a 10 s window: 24 core-seconds."""
    monkeypatch.setattr(sh, "_cpu_sample_path", lambda: tmp_path / "s.json")
    monkeypatch.setattr(sh.os, "cpu_count", lambda: 4)
    monkeypatch.setattr(sh, "_cgroup_cpu_usec", lambda: 1_000_000_000)
    monkeypatch.setattr(sh.time, "time", lambda: 1000.0)
    sh.cpu_pct()                                     # seeds the sample
    monkeypatch.setattr(sh, "_cgroup_cpu_usec", lambda: 1_024_000_000)
    monkeypatch.setattr(sh.time, "time", lambda: 1010.0)
    assert sh.cpu_pct() == pytest.approx(60.0, abs=0.2)


def test_cpu_pct_ignores_a_sample_written_by_another_node(monkeypatch, tmp_path):
    """data/ is rsynced between the HA pair; a peer's counter would produce a
    nonsense delta. Stamped and checked rather than assumed."""
    monkeypatch.setattr(sh, "_cpu_sample_path", lambda: tmp_path / "s.json")
    monkeypatch.setattr(sh, "_cgroup_cpu_usec", lambda: 5)
    monkeypatch.setattr(sh.socket, "gethostname", lambda: "satom-node-1")
    sh._write_cpu_sample(1000.0, 5)
    monkeypatch.setattr(sh.socket, "gethostname", lambda: "satom-node-2")
    assert sh._read_cpu_sample() is None


def test_cpu_pct_survives_a_counter_reset(monkeypatch, tmp_path):
    """Container restart recreates the cgroup and the counter starts over. A
    negative delta must not render as a negative or absurd percentage."""
    monkeypatch.setattr(sh, "_cpu_sample_path", lambda: tmp_path / "s.json")
    monkeypatch.setattr(sh.os, "cpu_count", lambda: 4)
    monkeypatch.setattr(sh, "_cgroup_cpu_usec", lambda: 9_000_000_000)
    monkeypatch.setattr(sh.time, "time", lambda: 1000.0)
    sh.cpu_pct()
    monkeypatch.setattr(sh, "_cgroup_cpu_usec", lambda: 1_000)
    monkeypatch.setattr(sh.time, "time", lambda: 1010.0)
    v = sh.cpu_pct()
    assert v is None or v >= 0


def test_is_container_probes_each_source_independently(monkeypatch):
    """/proc/1/environ is root-only. Chaining the probes inside one try made a
    PermissionError on the first swallow the second, and the LXC reported
    itself as bare metal."""
    real = Path.read_bytes

    def boom(self, *a, **k):
        if str(self) == "/proc/1/environ":
            raise PermissionError(13, "Permission denied")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "read_bytes", boom)
    monkeypatch.setattr(Path, "exists", lambda self: str(self) ==
                        "/run/systemd/container")
    assert sh.is_container() is True


def test_no_module_grades_cpu_from_getloadavg():
    """The derived guard. An allowlist of files would stop covering the moment
    someone adds a fifth — the way BRAND_SURFACES and the version-literal
    parametrize both quietly stopped covering."""
    offenders = []
    for py in APP_DIR.rglob("*.py"):
        src = _strip_comments(py.read_text())
        if "getloadavg" not in src:
            continue
        for line in src.splitlines():
            if "getloadavg" in line and ("cpu_count" in line or "cpus" in line):
                offenders.append("%s: %s" % (py.name, line.strip()))
    assert not offenders, (
        "load average is the HYPERVISOR's inside an LXC; dividing it by this "
        "container's core count is the 220%%-of-3-cores bug: %s" % offenders)


# ---------------------------------------------------------------------------
# 3. Host grading reads the CPU number, and refuses to guess
# ---------------------------------------------------------------------------

_LIM = {"disk_warn_pct": 80, "disk_crit_pct": 92, "mem_warn_pct": 85,
        "mem_crit_pct": 95, "load_warn_pct": 150, "load_crit_pct": 400}


def _stats(**kw):
    base = {"hostname": "n", "cpus": 4, "load": [6.6, 5.35, 3.65],
            "load_scope": "host", "cpu_pct": 2.0, "mem_total_mb": 4096,
            "mem_used_mb": 1024, "mem_pct": 25.0,
            "disks": [{"mount": "/", "total_gb": 20, "used_gb": 4, "pct": 20}]}
    base.update(kw)
    return base


def test_the_reported_incident_now_grades_ok():
    """load 6.6 on a 24-core hypervisor, 3-core container, everything idle.
    This exact payload alerted satom-node-2 as degraded on 2026-08-11."""
    g = hh.grade_stats(_stats(cpus=3, cpu_pct=1.4), _LIM)
    assert g["signals"]["load"]["status"] == "ok"
    assert g["status"] == "ok"


def test_real_container_cpu_saturation_still_alerts():
    g = hh.grade_stats(_stats(cpu_pct=420.0), _LIM)
    assert g["signals"]["load"]["status"] == "crit"


def test_a_node_without_cpu_accounting_is_unknown_not_graded_on_load():
    """An older peer across a rolling upgrade sends load_pct and no cpu_pct.
    Falling back would restore the bug for the only node that still has it."""
    s = _stats()
    del s["cpu_pct"]
    s["load_pct"] = 220.0
    g = hh.grade_stats(s, _LIM)
    assert g["signals"]["load"]["status"] == "unknown"
    assert "older" in g["signals"]["load"]["text"]


def test_host_load_is_shown_but_labelled_as_the_hosts():
    text = hh.grade_stats(_stats(cpu_pct=420.0), _LIM)["signals"]["load"]["text"]
    assert "host load" in text and "6.6" in text
    assert "busy" in text


# ---------------------------------------------------------------------------
# 4. "not checked" is not "down"
# ---------------------------------------------------------------------------

_MEMBERS = [
    {"id": 1, "pool": "p", "type": 1, "ipDomainName": "192.0.2.211", "port": 80,
     "healthCheckStatus": "N/A", "sessionCount": 6, "backupServer": 0,
     "status": 1, "server_rtt": 9, "app_response_time": 21},
    {"id": 2, "pool": "p", "type": 1, "ipDomainName": "192.0.2.212", "port": 80,
     "healthCheckStatus": "N/A", "sessionCount": 6, "backupServer": 0,
     "status": 1, "server_rtt": 9, "app_response_time": 21},
]


def _row():
    return {"name": "pol-full-web", "status": "enable", "handle": 1488,
            "sessions": 12, "conn_per_sec": 3, "app_response_time": 21}


def _classify(members, **kw):
    kw.setdefault("warn_num", 0)
    kw.setdefault("crit_num", 0)
    kw.setdefault("warn_ms", 0)
    kw.setdefault("fingerprint", "a")
    kw.setdefault("prev_fingerprint", "a")
    return dm.classify_policy_sessions(_row(), dm.parse_pool_members(members), **kw)


def test_members_up_without_a_health_check_are_unverified_not_down():
    """The live payload from fortiweb08: status 1 (up) on every member,
    healthCheckStatus 'disable' meaning no check is configured."""
    status, detail = _classify(
        [dict(m, healthCheckStatus="disable") for m in _MEMBERS])
    assert "ALL backends down" not in detail
    assert "2/2 backends up" in detail
    assert "NO health check" in detail and "unverified" in detail
    assert status == "warn"


def test_an_unchecked_backend_is_still_not_ok():
    """Fail-closed is kept. The grade moved from crit to warn; it did not
    move to green, because an untested backend is a real gap."""
    assert _classify(
        [dict(m, healthCheckStatus="disable") for m in _MEMBERS])[0] != "ok"


def test_genuinely_down_backends_still_read_as_down():
    status, detail = _classify([dict(m, status=0) for m in _MEMBERS])
    assert status == "crit" and "ALL backends down" in detail


def test_one_down_one_unchecked_reports_both_facts():
    status, detail = _classify([
        dict(_MEMBERS[0], status=0),
        dict(_MEMBERS[1], healthCheckStatus="disable")])
    assert "down: 192.0.2.211:80" in detail
    assert "192.0.2.212:80" in detail and "NO health check" in detail
    assert status == "warn"


def test_the_unverified_fact_is_governable_like_every_other_fact():
    assert "backends_unverified" in th.FACT_BY_KEY
    f = th.FACT_BY_KEY["backends_unverified"]
    assert f.default == "warn" and "policy_sessions" in f.kinds
    # Silencing changes the grade, never the visibility.
    _, detail = _classify(
        [dict(m, healthCheckStatus="disable") for m in _MEMBERS],
        sev={"backends_unverified": "off"})
    assert "NO health check" in detail


def test_severity_off_actually_silences_the_grade():
    status, _ = _classify(
        [dict(m, healthCheckStatus="disable") for m in _MEMBERS],
        sev={"backends_unverified": "off"})
    assert status == "ok"


# ---------------------------------------------------------------------------
# 5. "dispatched" means delivered
# ---------------------------------------------------------------------------

@pytest.fixture()
def wired(app, monkeypatch):
    """Alert engine with both channels under test control."""
    saved = {}
    monkeypatch.setattr(alerts, "evaluate", lambda: [
        {"key": "k1", "severity": alerts.SEV_CRITICAL, "title": "t1",
         "detail": "d1", "product": ""}])
    monkeypatch.setattr(alerts, "_is_read_only_replica", lambda: False)
    monkeypatch.setattr(alerts, "_load_state", lambda: {})
    monkeypatch.setattr(alerts, "_save_state", lambda s: saved.update(s))
    monkeypatch.setattr(alerts, "is_enabled", lambda: True)
    monkeypatch.setattr(alerts, "recipients", lambda: ["ops@example.test"])
    return saved


def test_a_refused_relay_does_not_count_as_dispatched(app, wired, monkeypatch):
    """The reported incident: every run logged dispatched: 2 while the relay
    answered 454 4.7.1 Relay access denied to every recipient."""
    monkeypatch.setattr(alerts, "_admin_ids", lambda: [])
    monkeypatch.setattr(alerts.email_service, "send_email",
                        lambda *a, **k: {"ok": False,
                                         "detail": "454 4.7.1 Relay access denied"})
    with app.app_context():
        res = alerts.run()
    assert res["fresh"] == 1
    assert res["dispatched"] == 0
    assert res["channels"] == []
    assert any("Relay access denied" in x for x in res["delivery_failed"])


def test_nothing_delivered_leaves_the_cooldown_unstamped(app, wired, monkeypatch):
    """Stamping the cooldown after reaching nobody suppresses the finding for
    the whole window: counted as sent, never seen, then silenced."""
    monkeypatch.setattr(alerts, "_admin_ids", lambda: [])
    monkeypatch.setattr(alerts.email_service, "send_email",
                        lambda *a, **k: {"ok": False, "detail": "refused"})
    with app.app_context():
        alerts.run()
    assert wired == {}, "cooldown was stamped for an alert nobody received"


def test_a_working_bell_is_a_real_channel_even_when_email_fails(
        app, wired, monkeypatch):
    """The bell genuinely fired, so the finding WAS delivered — and the email
    failure is still named rather than folded into a single number."""
    monkeypatch.setattr(alerts, "_admin_ids", lambda: [7])
    monkeypatch.setattr(alerts.notify, "push_many", lambda *a, **k: None)
    monkeypatch.setattr(alerts.email_service, "send_email",
                        lambda *a, **k: {"ok": False, "detail": "refused"})
    with app.app_context():
        res = alerts.run()
    assert res["dispatched"] == 1 and res["channels"] == ["in-app"]
    assert any("email" in x for x in res["delivery_failed"])
    assert "k1" in wired


def test_both_channels_up_reports_both(app, wired, monkeypatch):
    monkeypatch.setattr(alerts, "_admin_ids", lambda: [7])
    monkeypatch.setattr(alerts.notify, "push_many", lambda *a, **k: None)
    monkeypatch.setattr(alerts.email_service, "send_email",
                        lambda *a, **k: {"ok": True})
    with app.app_context():
        res = alerts.run()
    assert res["dispatched"] == 1
    assert res["channels"] == ["in-app", "email"]
    assert res["delivery_failed"] == []


def test_nobody_holds_the_bell_is_itself_a_delivery_failure(
        app, wired, monkeypatch):
    monkeypatch.setattr(alerts, "_admin_ids", lambda: [])
    monkeypatch.setattr(alerts.email_service, "send_email",
                        lambda *a, **k: {"ok": True})
    with app.app_context():
        res = alerts.run()
    assert any("nobody holds the bell" in x for x in res["delivery_failed"])
    assert res["dispatched"] == 1 and res["channels"] == ["email"]


def test_the_cli_exits_non_zero_when_a_run_reaches_nobody():
    """A summary line nobody reads is how this survived for weeks. The unit
    goes ``failed`` so systemctl and the Monitoring page both show it."""
    # Parse the ORIGINAL source: ast.dump() carries no comments or docstrings,
    # so nothing needs stripping — and stripping first truncated a multi-line
    # string literal that legitimately contains a '#'.
    tree = ast.parse((APP_DIR / "__init__.py").read_text())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "alerts_run_cmd")
    body = ast.dump(fn)
    assert "SystemExit" in body, \
        "alerts-run must fail the unit when nothing was delivered"
    assert "channels" in body


# ---------------------------------------------------------------------------
# 6. Inventory counts objects, not cache rows
# ---------------------------------------------------------------------------

def _cached_policy(appliance_id: int, name: str, layer: str):
    """One policy as the cache holds it in ONE layer."""
    from app.models_cache import (DeviceObject, DeviceServerPolicy,
                                  DeviceSnapshot, DeviceWebProtectionProfile)
    from app.models import db
    snap = DeviceSnapshot(appliance_id=appliance_id, layer=layer,
                          section="Server Policy")
    db.session.add(snap)
    db.session.flush()
    obj = DeviceObject(appliance_id=appliance_id, snapshot_id=snap.id,
                       layer=layer, section="Server Policy",
                       logical_name="server_policy", mkey=name)
    db.session.add(obj)
    db.session.flush()
    db.session.add(DeviceServerPolicy(object_id=obj.id,
                                      appliance_id=appliance_id, name=name))
    db.session.add(DeviceWebProtectionProfile(object_id=obj.id,
                                              appliance_id=appliance_id,
                                              name="wpp-" + name, kind="inline"))
    db.session.commit()


def test_inventory_counts_objects_not_one_row_per_cache_layer(app):
    """The cache holds each device once per layer (config + deep) and the typed
    projections inherit that. Counting projection rows read 12 server policies
    for a device with 6 and 48 profiles for a device with 24 -- exactly double,
    on every appliance -- while ``advisor`` deduplicated and reported 6."""
    from app.services import inventory_metrics as im
    with app.app_context():
        for layer in ("config", "deep"):
            for name in ("pol-a", "pol-b", "pol-c"):
                _cached_policy(4242, name, layer)
        counts = im.current_counts()
    assert counts["server_policy"].get(4242) == 3, \
        "counted cache rows (6) instead of policies (3)"
    assert counts["wpp"].get(4242) == 3


def test_a_device_captured_in_only_one_layer_still_counts(app):
    """Why the fix deduplicates by name instead of filtering to ``config``:
    a device that has only ever been deep-captured has no config layer, and a
    layer filter would report it as holding nothing at all."""
    from app.services import inventory_metrics as im
    with app.app_context():
        for name in ("pol-x", "pol-y"):
            _cached_policy(4343, name, "deep")
        counts = im.current_counts()
    assert counts["server_policy"].get(4343) == 2
