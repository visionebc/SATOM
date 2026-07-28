"""Device alerts belong to the DEVICE's ADOM, not to the worker's session.

The regression these guard (2026-07-28): the alert engine runs in a background
thread with no request context, so ``product_scope.stamp()`` returned '' for
every notification it raised. An unscoped row is visible in the FortiWeb ADOM by
construction, so the FortiWeb bell became the catch-all for fadc and faz01 too —
132 of 145 rows on the primary were unscoped. Alerts about a FortiADC box must
not land in the FortiWeb ADOM.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.models import Appliance, db
from app.models_cache import SyncRun
from app.services import alerts
from app.services import device_health as dh


def _mk(kind, name):
    a = Appliance(name=name, host="192.0.2.99", port=443, kind=kind,
                  username="admin")
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


def _broken(aid):
    """Three failed harvests -> crit on the Fleet-health ladder."""
    for i in range(3):
        db.session.add(SyncRun(
            appliance_id=aid, section="_all", status="error",
            detail="device error -20010: license invalid",
            started_at=datetime.utcnow() - timedelta(minutes=60 * (i + 1))))
    db.session.commit()


@pytest.mark.parametrize("kind", ["fortiweb", "fortiadc", "fortianalyzer"])
def test_device_finding_carries_the_device_adom(app, monkeypatch, kind):
    with app.app_context():
        a = _mk(kind, f"dev-{kind}")
        _broken(a.id)
        monkeypatch.setattr(alerts, "_reachable", lambda h, p: True)
        monkeypatch.setattr(dh, "cache_meta", lambda ap: {
            "generated_at": (datetime.utcnow() - timedelta(minutes=5)).isoformat()})

        out = alerts._check_devices()
        assert out, "a device with 3 failed harvests must produce a finding"
        assert all(f["product"] == kind for f in out), \
            f"finding must be stamped {kind}, got {[f.get('product') for f in out]}"


def test_unknown_kind_stays_unscoped(app, monkeypatch):
    """Fail open, never into the wrong ADOM: an unrecognised kind is ''."""
    with app.app_context():
        class Fake:
            kind = "somethingelse"
        assert alerts._product_of(Fake()) == ""
        assert alerts._product_of(object()) == ""


def test_bell_notification_inherits_the_finding_product(app, monkeypatch):
    """End to end: run() must hand the product to the notification layer.

    Without this the fix is cosmetic — the finding dict would carry the ADOM and
    the row written to ``notifications`` would still be unscoped.
    """
    with app.app_context():
        seen = {}

        monkeypatch.setattr(alerts, "evaluate", lambda: [
            {"key": "device.health.fadc.crit", "severity": alerts.SEV_CRITICAL,
             "title": "Device fadc is critical", "detail": "no cache",
             "product": "fortiadc"},
            {"key": "git.ahead_unpushed", "severity": alerts.SEV_WARNING,
             "title": "Unpushed commits", "detail": "6h"},
        ])
        monkeypatch.setattr(alerts, "_is_read_only_replica", lambda: False)
        monkeypatch.setattr(alerts, "_load_state", lambda: {})
        monkeypatch.setattr(alerts, "_save_state", lambda st: None)
        monkeypatch.setattr(alerts, "_admin_ids", lambda: [1])
        monkeypatch.setattr(alerts, "is_enabled", lambda: False)

        def fake_push_many(ids, title, **kw):
            seen[title] = kw.get("product")
            return len(ids)
        monkeypatch.setattr(alerts.notify, "push_many", fake_push_many)

        alerts.run(force=True)

        assert seen["Device fadc is critical"] == "fortiadc"
        # Manager-wide findings keep the old behaviour (None -> session stamp).
        assert seen["Unpushed commits"] is None
