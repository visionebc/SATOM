"""Fleet-health badge — the roll-up that replaced the capacity-only status.

The bug this guards against (2026-07-28): the badge was computed ONLY from
``capacity.fleet_headroom``. No appliance in the fleet has an ``effective_cap``,
so every headroom row scored ``nocap``, the loop could never reach warn/crit,
and an appliance that was powered off with zero cached data still rendered
``healthy``. Every assertion below is about the badge being ABLE to go red.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.models import Appliance, MonitorProbe, User, db
from app.models_cache import SyncRun
from app.services import device_health as dh
from tests.conftest import login


# --------------------------------------------------------------------------
# pure ladder
# --------------------------------------------------------------------------

def test_unknown_ranks_below_ok_but_is_not_ok():
    # A measured-good signal beats 'we know nothing'...
    assert dh.worst_of(["unknown", "ok"]) == "ok"
    # ...but nothing measured at all must NOT print as healthy.
    assert dh.worst_of(["unknown", "unknown"]) == "unknown"
    assert dh.worst_of(["ok", "warn"]) == "warn"
    assert dh.worst_of(["warn", "crit"]) == "crit"
    assert dh.worst_of([]) == "unknown"


# --------------------------------------------------------------------------
# cache freshness
# --------------------------------------------------------------------------

def test_cache_signal_grades_by_age():
    now = datetime.utcnow()
    assert dh.cache_signal({"generated_at": now}, 6)["status"] == "ok"
    assert dh.cache_signal(
        {"generated_at": now - timedelta(hours=7)}, 6)["status"] == "warn"
    # 4x the budget is critical
    assert dh.cache_signal(
        {"generated_at": now - timedelta(hours=25)}, 6)["status"] == "crit"


def test_cache_signal_no_data_is_a_warning_not_ok():
    """faz01's exact state: nothing cached at all."""
    sig = dh.cache_signal({}, 6)
    assert sig["status"] == "warn"
    assert "no cached" in sig["text"]
    assert dh.cache_signal(None, 6)["status"] == "warn"


def test_cache_signal_accepts_iso_strings():
    iso = (datetime.utcnow() - timedelta(hours=1)).isoformat()
    assert dh.cache_signal({"generated_at": iso}, 6)["status"] == "ok"
    # garbage timestamp must not crash the page — it degrades to 'no cache'
    assert dh.cache_signal({"generated_at": "not-a-date"}, 6)["status"] == "warn"


# --------------------------------------------------------------------------
# capacity: 'no cap' is not 'fine'
# --------------------------------------------------------------------------

def test_capacity_signal_without_caps_is_unknown_not_ok():
    caps = [{"label": "Server Policies", "status": "nocap", "used": 12},
            {"label": "Web Protection Profiles", "status": "nocap", "used": 0}]
    sig = dh.capacity_signal(caps)
    assert sig["status"] == "unknown"          # the original bug, asserted
    assert dh.capacity_signal([])["status"] == "unknown"


def test_capacity_signal_still_reports_real_breaches():
    caps = [{"label": "Server Policies", "status": "crit", "pct": 99.0},
            {"label": "Certificates", "status": "ok", "pct": 10.0}]
    sig = dh.capacity_signal(caps)
    assert sig["status"] == "crit" and "Server Policies" in sig["text"]


# --------------------------------------------------------------------------
# harvest history
# --------------------------------------------------------------------------

@pytest.fixture()
def dev(app):
    with app.app_context():
        a = Appliance(name="fwtest", host="192.0.2.99", kind="fortiweb",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        return a.id


def _sync(aid, status, minutes_ago, detail=""):
    db.session.add(SyncRun(
        appliance_id=aid, section="_all", status=status, detail=detail,
        started_at=datetime.utcnow() - timedelta(minutes=minutes_ago)))
    db.session.commit()


def test_sync_signal_never_harvested_is_unknown(app, dev):
    with app.app_context():
        assert dh.sync_signal(dev)["status"] == "unknown"


def test_sync_signal_one_failure_warns_streak_goes_critical(app, dev):
    with app.app_context():
        _sync(dev, "error", 10, "device error -20010: The license of peer VM "
                                "FortiWeb is not valid")
        sig = dh.sync_signal(dev)
        assert sig["status"] == "warn" and "license" in sig["text"]

        _sync(dev, "error", 9)
        _sync(dev, "error", 8)
        sig = dh.sync_signal(dev)
        assert sig["status"] == "crit" and sig["streak"] == 3


def test_sync_signal_recovery_clears_the_streak(app, dev):
    with app.app_context():
        for m in (30, 25, 20):
            _sync(dev, "error", m)
        assert dh.sync_signal(dev)["status"] == "crit"
        _sync(dev, "ok", 5)
        assert dh.sync_signal(dev)["status"] == "ok"


# --------------------------------------------------------------------------
# deep monitors
# --------------------------------------------------------------------------

def test_probe_signal_disabled_probes_are_lost_coverage(app, dev):
    """A probe switched off because it always fails is NOT a passing probe."""
    with app.app_context():
        db.session.add(MonitorProbe(appliance_id=dev, kind="cpu", name="cpu",
                                    enabled=False, last_status="error"))
        db.session.commit()
        sig = dh.probe_signal(dev)
        assert sig["status"] == "warn" and "disabled" in sig["text"]


def test_probe_signal_reports_worst_enabled(app, dev):
    with app.app_context():
        db.session.add(MonitorProbe(appliance_id=dev, kind="cpu", name="cpu",
                                    enabled=True, last_status="ok"))
        db.session.add(MonitorProbe(appliance_id=dev, kind="memory",
                                    name="mem", enabled=True,
                                    last_status="crit"))
        db.session.commit()
        sig = dh.probe_signal(dev)
        assert sig["status"] == "crit" and "mem" in sig["text"]


def test_probe_signal_execution_error_is_a_warning(app, dev):
    """'error' = the probe could not RUN (SSH refused). Reported, and the sync
    streak is what escalates a genuinely dead box to critical."""
    with app.app_context():
        db.session.add(MonitorProbe(appliance_id=dev, kind="cpu", name="cpu",
                                    enabled=True, last_status="error"))
        db.session.commit()
        assert dh.probe_signal(dev)["status"] == "warn"


def test_no_probes_configured_is_unknown(app, dev):
    with app.app_context():
        assert dh.probe_signal(dev)["status"] == "unknown"


# --------------------------------------------------------------------------
# roll-up + the page contract
# --------------------------------------------------------------------------

def test_collect_rolls_up_and_explains(app, dev):
    with app.app_context():
        _sync(dev, "error", 5, "no route to host")
        a = Appliance.query.get(dev)
        out = dh.collect(a, caps=[{"label": "x", "status": "nocap"}],
                         meta={}, hours=6)
        assert out["status"] == "warn"
        # every non-ok signal is explained — the badge is never unexplained
        signals = {r["signal"] for r in out["reasons"]}
        assert {"sync", "cache", "capacity"} <= signals
        assert all(r["text"] for r in out["reasons"])


def test_dead_device_cannot_render_healthy(app, dev):
    """The regression test: uncapped + unreachable + never cached."""
    with app.app_context():
        for m in (40, 30, 20):
            _sync(dev, "error", m, "No route to host")
        a = Appliance.query.get(dev)
        out = dh.collect(a, caps=[{"label": "Server Policies",
                                   "status": "nocap"}], meta={}, hours=6)
        assert out["status"] == "crit"


def test_monitoring_feed_carries_health(client, app, dev):
    with app.app_context():
        u = User.query.filter_by(role="admin").first()
        if u is None:
            u = User(username="mhadmin", role="admin", is_active=True)
            u.set_password("x" * 12)
            db.session.add(u)
            db.session.commit()
        uid = u.id
        _sync(dev, "error", 5, "No route to host")
    login(client, uid, product="global")
    d = client.get("/monitoring/data").get_json()
    assert "health_alerts" in d
    row = next(x for x in d["devices"] if x["id"] == dev)
    assert row["worst"] != "ok"
    assert row["health"]["status"] == row["worst"]
    assert row["health"]["reasons"]
