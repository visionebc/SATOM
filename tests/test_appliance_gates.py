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


def test_device_flash_and_failover_buttons_follow_appliances_apply(app, client):
    """The Upgrade, Boot Partition and HA Failover pages need appliances.apply;
    the buttons were drawn for any edit key, so a protection-only editor
    clicked into a 403 (Documentation Center docs pass, 2026-10-03)."""
    from tests.test_access_gates_audit import _zero_key_user
    from app.extensions import db
    from app.models import Appliance
    with app.app_context():
        a = Appliance(name="fw-btn", kind="fortiweb", host="192.0.2.7", port=443,
                      username="u", password_enc="x", verify_ssl=False)
        db.session.add(a)
        db.session.commit()
        aid = a.id
    login(client, _zero_key_user(app, "prot-editor",
                                 keys={"protection.edit", "appliances.view"}))
    html = client.get(f"/appliances/{aid}").get_data(as_text=True)
    assert f"/appliances/{aid}/upgrade" not in html
    assert f"/appliances/{aid}/downgrade" not in html
    client.get("/auth/logout")
    login(client, make_user(app, username="op-btn", role="operator"))
    html = client.get(f"/appliances/{aid}").get_data(as_text=True)
    assert f"/appliances/{aid}/upgrade" in html      # positive control
    assert f"/appliances/{aid}/downgrade" in html
