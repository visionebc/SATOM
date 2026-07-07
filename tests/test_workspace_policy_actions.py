"""Route smoke tests for the Workspace Server-Policy actions (preview + apply
validation). No device: disable/enable/delete previews are pure (FortiWebOps
dry-run never contacts the box), so they exercise the full request→engine path
without a live appliance.
"""
from tests.conftest import login, admin_user_id


def _fw(app, name="fw1", host="192.0.2.99"):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name=name, kind="fortiweb", host=host, port=443,
                      username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a)
        db.session.commit()
        return a.id


def test_preview_disable_is_pure_and_ok(app, client):
    aid = _fw(app)
    login(client, admin_user_id(app))
    r = client.post(f"/workspace/{aid}/policy-action/preview",
                    json={"action": "disable", "policies": ["pol-a", "pol-b"]})
    assert r.status_code == 200
    j = r.get_json()
    assert j["ok"] and j["label"] == "Disable" and len(j["results"]) == 2
    # the dry-run request body is the exact status write
    body = j["results"][0]["detail"]["request"]["body"]
    assert body == {"data": {"status": "disable"}}


def test_preview_rejects_unknown_action(app, client):
    aid = _fw(app)
    login(client, admin_user_id(app))
    r = client.post(f"/workspace/{aid}/policy-action/preview",
                    json={"action": "nope", "policies": ["p"]})
    assert r.status_code == 400


def test_preview_requires_policies(app, client):
    aid = _fw(app)
    login(client, admin_user_id(app))
    r = client.post(f"/workspace/{aid}/policy-action/preview",
                    json={"action": "disable", "policies": []})
    assert r.status_code == 400


def test_clone_to_requires_destination(app, client):
    aid = _fw(app)
    login(client, admin_user_id(app))
    r = client.post(f"/workspace/{aid}/policy-action/preview",
                    json={"action": "clone_to", "policies": ["p"]})
    assert r.status_code == 400


def test_clone_to_rejects_same_destination(app, client):
    aid = _fw(app)
    login(client, admin_user_id(app))
    r = client.post(f"/workspace/{aid}/policy-action/preview",
                    json={"action": "clone_to", "policies": ["p"], "dest_id": aid})
    assert r.status_code == 400


def test_clone_here_single_requires_name(app, client):
    aid = _fw(app)
    login(client, admin_user_id(app))
    r = client.post(f"/workspace/{aid}/policy-action/preview",
                    json={"action": "clone_here", "policies": ["p"]})
    assert r.status_code == 400


def test_apply_disable_spawns_job(app, client):
    aid = _fw(app)
    login(client, admin_user_id(app))
    r = client.post(f"/workspace/{aid}/policy-action",
                    json={"action": "disable", "policies": ["pol-a"]})
    assert r.status_code == 200
    j = r.get_json()
    assert j["ok"] and j.get("job_id")
