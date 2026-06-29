"""Phase 4 — lease-lock API route contracts (multi-user)."""
from __future__ import annotations

from tests.conftest import login, admin_user_id


def _appliance(app):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw1", kind="fortiweb", host="192.0.2.99",
                      port=443, username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a); db.session.commit()
        return a.id


def test_acquire_then_status_mine(client, app):
    aid = _appliance(app)
    login(client, admin_user_id(app))
    r = client.post("/api/locks/acquire",
                    json={"appliance_id": aid, "resource_key": "server_policy:p1"})
    assert r.status_code == 200 and r.get_json()["ok"] is True
    s = client.get(f"/api/locks/status?appliance_id={aid}&resource_key=server_policy:p1")
    j = s.get_json()
    assert j["locked"] is True and j["mine"] is True


def test_heartbeat_and_release(client, app):
    aid = _appliance(app)
    login(client, admin_user_id(app))
    client.post("/api/locks/acquire",
                json={"appliance_id": aid, "resource_key": "k"})
    hb = client.post("/api/locks/heartbeat",
                     json={"appliance_id": aid, "resource_key": "k"})
    assert hb.get_json()["ok"] is True
    rel = client.post("/api/locks/release",
                      json={"appliance_id": aid, "resource_key": "k"})
    assert rel.get_json()["ok"] is True
    s = client.get(f"/api/locks/status?appliance_id={aid}&resource_key=k")
    assert s.get_json()["locked"] is False


def test_bad_args_rejected(client, app):
    login(client, admin_user_id(app))
    r = client.post("/api/locks/acquire", json={"resource_key": "k"})
    assert r.status_code == 400
