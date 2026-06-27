"""Appliance ACTION routes must be permission-gated (they weren't before)."""
from __future__ import annotations

from tests.conftest import login, make_user, profile_id


def _make_appliance(app):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw1", kind="fortiweb", host="192.0.2.99",
                      port=443, username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a); db.session.commit()
        return a.id


def test_readonly_cannot_run_console(app, client):
    aid = _make_appliance(app)
    ro = make_user(app, "ro", role="readonly", profile_id=profile_id(app, "readonly"))
    login(client, ro)
    # 'set ...' is a write command, but the gate must fire FIRST -> 403
    r = client.post(f"/appliances/{aid}/console/run", data={"command": "set x y"})
    assert r.status_code == 403


def test_operator_passes_console_gate(app, client):
    aid = _make_appliance(app)
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, op)
    r = client.post(f"/appliances/{aid}/console/run", data={"command": "set x y"})
    # gate passes (not 403); the read-only validator then rejects the write -> 400
    assert r.status_code == 400


def test_readonly_cannot_start_rediscovery(app, client):
    aid = _make_appliance(app)
    ro = make_user(app, "ro", role="readonly", profile_id=profile_id(app, "readonly"))
    login(client, ro)
    r = client.post(f"/appliances/{aid}/rediscover/start")
    assert r.status_code == 403
