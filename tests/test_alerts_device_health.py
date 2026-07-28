"""Alert engine — device findings ride the Fleet-health ladder, not a socket.

The regression these guard (2026-07-28): ``alerts._check_devices`` opened a TCP
connection and nothing else. fw6 and fw7 accepted :443 for a week while their
REST harvest died on an invalid licence — the Monitoring page went red and not
one mail was ever sent, because "the port answers" was the whole test. The
badge and the mailbox now share :mod:`app.services.device_health`; a device that
renders red on the page must produce a finding here.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.models import Appliance, AppSetting, db
from app.models_cache import SyncRun
from app.services import alerts
from app.services import device_health as dh


@pytest.fixture()
def dev(app):
    with app.app_context():
        a = Appliance(name="fwtest", host="192.0.2.99", port=443,
                      kind="fortiweb", username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        return a.id


def _sync(aid, status, minutes_ago, detail=""):
    db.session.add(SyncRun(
        appliance_id=aid, section="_all", status=status, detail=detail,
        started_at=datetime.utcnow() - timedelta(minutes=minutes_ago)))
    db.session.commit()


def _fresh_cache(monkeypatch, minutes_old=5):
    """Pretend the harvest cache is *minutes_old* minutes old."""
    ts = (datetime.utcnow() - timedelta(minutes=minutes_old)).isoformat()
    monkeypatch.setattr(dh, "cache_meta", lambda a: {"generated_at": ts})


def _reachable(monkeypatch, value=True):
    monkeypatch.setattr(alerts, "_reachable", lambda host, port: value)


# ---------------------------------------------------------------- the regression
def test_port_answers_but_harvest_failing_still_alerts(app, dev, monkeypatch):
    """The exact fw6/fw7 case: TCP is fine, the device is not."""
    with app.app_context():
        _reachable(monkeypatch, True)
        _fresh_cache(monkeypatch)
        for i in range(3):
            _sync(dev, "error", 60 * (i + 1), "device error -20010: license invalid")

        out = alerts._check_devices()

    assert len(out) == 1, "a reachable-but-broken device must still alert"
    f = out[0]
    assert f["severity"] == alerts.SEV_CRITICAL      # 3 failures in a row
    assert "Harvest" in f["detail"]
    assert "license invalid" in f["detail"]
    # No reachability line: the socket was fine and the mail must not imply
    # otherwise, or the operator goes looking at the network.
    assert "Reachability" not in f["detail"]


def test_healthy_reachable_device_is_silent(app, dev, monkeypatch):
    with app.app_context():
        _reachable(monkeypatch, True)
        _fresh_cache(monkeypatch)
        _sync(dev, "ok", 30)
        assert alerts._check_devices() == []


def test_unreachable_device_still_reported(app, dev, monkeypatch):
    """The pre-existing TCP behaviour survives the merge — as one signal."""
    with app.app_context():
        _reachable(monkeypatch, False)
        _fresh_cache(monkeypatch)
        _sync(dev, "ok", 30)

        out = alerts._check_devices()

    assert len(out) == 1
    assert "Reachability" in out[0]["detail"]
    assert "192.0.2.99:443" in out[0]["detail"]
    # Unreachable alone stays a warning; the harvest streak is what escalates.
    assert out[0]["severity"] == alerts.SEV_WARNING


def test_one_finding_per_device_not_one_per_signal(app, dev, monkeypatch):
    """Every failing signal is a LINE, never a separate mail."""
    with app.app_context():
        _reachable(monkeypatch, False)
        monkeypatch.setattr(dh, "cache_meta", lambda a: {})   # no cache → warn
        for i in range(4):
            _sync(dev, "error", 60 * (i + 1), "boom")

        out = alerts._check_devices()

    assert len(out) == 1
    detail = out[0]["detail"]
    assert "Reachability" in detail and "Harvest" in detail and "Cache" in detail


# ---------------------------------------------------------------- cooldown key
def test_escalation_to_crit_uses_a_different_cooldown_key(app, dev, monkeypatch):
    """warn and crit are separate cooldown slots, so a device degrading inside
    the suppression window still reaches the operator."""
    with app.app_context():
        _reachable(monkeypatch, False)
        _fresh_cache(monkeypatch)
        _sync(dev, "ok", 30)
        warn_key = alerts._check_devices()[0]["key"]

        for i in range(3):
            _sync(dev, "error", 10 * (i + 1), "boom")
        crit = alerts._check_devices()[0]

    assert warn_key.endswith(".warn")
    assert crit["key"].endswith(".crit")
    assert crit["key"] != warn_key


# ---------------------------------------------------------------- operator knobs
def test_crit_floor_suppresses_degraded_devices(app, dev, monkeypatch):
    with app.app_context():
        _reachable(monkeypatch, False)
        _fresh_cache(monkeypatch)
        _sync(dev, "ok", 30)
        assert len(alerts._check_devices()) == 1        # default floor = warn

        AppSetting.set(alerts.K_DEV_MIN, "crit")
        assert alerts._check_devices() == []            # warn now suppressed

        for i in range(3):
            _sync(dev, "error", 10 * (i + 1), "boom")
        assert len(alerts._check_devices()) == 1        # crit still fires


def test_bad_floor_value_falls_back_to_warn(app, dev, monkeypatch):
    """A junk setting must not silence the check (fail loud, not open)."""
    with app.app_context():
        AppSetting.set(alerts.K_DEV_MIN, "banana")
        _reachable(monkeypatch, False)
        _fresh_cache(monkeypatch)
        _sync(dev, "ok", 30)
        assert len(alerts._check_devices()) == 1


def test_maintenance_device_is_skipped(app, dev, monkeypatch):
    with app.app_context():
        a = db.session.get(Appliance, dev)
        a.maintenance = True
        db.session.commit()
        _reachable(monkeypatch, False)
        monkeypatch.setattr(dh, "cache_meta", lambda x: {})
        assert alerts._check_devices() == []


def test_save_config_only_accepts_valid_floor(app):
    with app.app_context():
        alerts.save_config({"device_min_status": "crit"})
        assert alerts.config()["device_min_status"] == "crit"
        alerts.save_config({"device_min_status": "nonsense"})
        assert alerts.config()["device_min_status"] == "warn"


# ---------------------------------------------------------------- shared ladder
def test_alert_severity_tracks_the_badge(app, dev, monkeypatch):
    """The page and the mail must not disagree about the same box."""
    with app.app_context():
        _reachable(monkeypatch, True)
        _fresh_cache(monkeypatch)
        for i in range(3):
            _sync(dev, "error", 60 * (i + 1), "boom")

        a = db.session.get(Appliance, dev)
        badge = dh.collect_for(a)["status"]
        finding = alerts._check_devices()[0]

    assert badge == "crit"
    assert finding["severity"] == alerts.SEV_CRITICAL


def test_collect_for_gathers_without_a_view(app, dev):
    """collect_for is the entry point for callers outside Monitoring; it must
    not need caps/meta handed to it."""
    with app.app_context():
        a = db.session.get(Appliance, dev)
        health = dh.collect_for(a)
        assert set(health) >= {"status", "signals", "reasons"}
        assert set(health["signals"]) == {"sync", "cache", "probe", "capacity"}
