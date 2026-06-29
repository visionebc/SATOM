"""Inject + Detect device routes on the Exceptions page.

Dry-run inject is device-free (the preview is pure), so it's testable without a
box; detect against an unreachable appliance must degrade gracefully, and
detect-import must be idempotent against the store.
"""
from tests.conftest import login, admin_user_id


def _appliance(app):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw2", kind="fortiweb", host="192.0.2.250",
                      port=443, username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a); db.session.commit()
        return a.id


def _carveout(app, aid):
    from app.services import wpp_exceptions as s
    with app.app_context():
        exc = s.add(aid, wpp_mkey="WPP-x", exc_type="signature_filter_item",
                    payload={"signature_id": "010000001", "match-target": "URI"},
                    policies=["pol-a"])
        return exc.id


def test_inject_dry_run_returns_ready_plan(client, app):
    aid = _appliance(app)
    eid = _carveout(app, aid)
    login(client, admin_user_id(app))
    j = client.post(f"/exceptions/{aid}/inject",
                    json={"exc_id": eid, "target": "Extended Protection"}).get_json()
    assert j["ok"] is True and j["dry_run"] is True
    assert j["plan"]["status"] == "ready" and j["plan"]["method"] == "POST"
    assert any(s["step"] == "entry" for s in j["steps"])


def test_inject_no_target_is_not_ok(client, app):
    aid = _appliance(app)
    eid = _carveout(app, aid)
    login(client, admin_user_id(app))
    j = client.post(f"/exceptions/{aid}/inject", json={"exc_id": eid, "target": ""}).get_json()
    assert j["ok"] is False and j["plan"]["status"] == "no-target"


def test_inject_targets_unknown_type_is_400(client, app):
    aid = _appliance(app)
    login(client, admin_user_id(app))
    assert client.get(f"/exceptions/{aid}/inject-targets?type=bogus").status_code == 400


def test_detect_dead_device_is_graceful(client, app):
    aid = _appliance(app)
    login(client, admin_user_id(app))
    j = client.post(f"/exceptions/{aid}/detect").get_json()
    assert j["ok"] is False and j["found"] == []          # unreachable box → no crash


def test_detect_import_is_idempotent(client, app):
    from app.services import wpp_exceptions as s
    aid = _appliance(app)
    login(client, admin_user_id(app))
    found = [{"policy": "pol-a", "wpp": "WPP-x", "signature_set": "S",
              "signature_id": "010000001",
              "payload": {"signature_id": "010000001", "match-target": "URI"}}]
    j = client.post(f"/exceptions/{aid}/detect-import", json={"found": found}).get_json()
    assert j["ok"] and j["imported"] == 1
    with app.app_context():
        sigs = s.list_exceptions(aid, s.CAT_SIGNATURE)
        assert len(sigs) == 1 and sigs[0].policy_names == ["pol-a"]
    j2 = client.post(f"/exceptions/{aid}/detect-import", json={"found": found}).get_json()
    assert j2["imported"] == 0 and j2["skipped"] == 1     # already stored → skipped


def test_inject_button_and_detect_button_render(client, app):
    aid = _appliance(app)
    login(client, admin_user_id(app))
    h = client.get(f"/exceptions/{aid}").get_data(as_text=True)
    assert "Detect on device" in h and "injectExc(" in h
