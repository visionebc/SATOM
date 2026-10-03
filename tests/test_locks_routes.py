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


def test_readonly_cannot_take_or_hold_a_lease(client, app):
    """AU-23: acquire / heartbeat / steal need config_write."""
    from tests.conftest import make_user, profile_id
    from app.services import lock_service
    aid = _appliance(app)
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    with app.app_context():
        assert lock_service.acquire(aid, "k", user_id=op, owner_label="op")[0]
    ro = make_user(app, "ro", role="readonly", profile_id=profile_id(app, "readonly"))
    login(client, ro)
    for path in ("acquire", "heartbeat", "steal"):
        r = client.post(f"/api/locks/{path}",
                        json={"appliance_id": aid, "resource_key": "k"})
        assert r.status_code in (302, 403), (path, r.status_code)
    with app.app_context():
        assert lock_service.status(aid, "k")["owner_user_id"] == op
    # positive control: the operator can still steal and heartbeat
    login(client, op)
    assert client.post("/api/locks/heartbeat",
                       json={"appliance_id": aid, "resource_key": "k"}).get_json()["ok"]
    assert client.post("/api/locks/steal",
                       json={"appliance_id": aid, "resource_key": "k"}).get_json()["ok"]
