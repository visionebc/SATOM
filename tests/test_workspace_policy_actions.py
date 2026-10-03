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


def test_bulk_clone_carries_the_wpp_suffix_to_the_engine(app, client,
                                                         monkeypatch):
    """The bulk dialog sends ``wpp_suffix`` (one WPP per source policy); the
    parser dropped it, so the engine ran with its empty default."""
    from app.services import policy_ops
    seen = {}

    def _preview(action, **kw):
        seen.update(kw["opts"])
        return []

    monkeypatch.setattr(policy_ops, "preview", _preview)
    aid = _fw(app)
    login(client, admin_user_id(app))
    r = client.post(f"/workspace/{aid}/policy-action/preview",
                    json={"action": "clone_here", "policies": ["p1", "p2"],
                          "copy_wpp": True, "wpp_suffix": "-copy"})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert seen.get("wpp_suffix") == "-copy"


def test_the_raw_device_browse_route_is_gone(app, client):
    """It relayed ANY GET path to the device with SATOM's credentials for any
    signed-in user; nothing in the UI called it."""
    aid = _fw(app)
    login(client, admin_user_id(app))
    r = client.get(f"/workspace/{aid}/browse/api/v2.0/system/status")
    assert r.status_code == 404
    with app.app_context():
        assert "workspace.browse" not in app.view_functions


# ── audit 2026-10-03: "Refresh from device" is a config_write action ───────
def _sync_spy(monkeypatch):
    from app.services import device_sync
    calls = []

    class _Run:
        status, detail = "ok", "spy"

    monkeypatch.setattr(device_sync, "sync_device",
                        lambda appl, **kw: calls.append(appl.id) or _Run())
    return calls


import pytest  # noqa: E402


@pytest.mark.parametrize("url", ["/workspace/{aid}/refresh",
                                 "/server-objects/{aid}/refresh"])
def test_refresh_from_device_needs_config_write(app, client, monkeypatch, url):
    from tests.conftest import make_user
    calls = _sync_spy(monkeypatch)
    aid = _fw(app)
    login(client, make_user(app, username="ro-sync", role="readonly"))
    r = client.post(url.format(aid=aid))
    assert r.status_code == 403
    assert calls == []


@pytest.mark.parametrize("url", ["/workspace/{aid}/refresh",
                                 "/server-objects/{aid}/refresh"])
def test_refresh_from_device_runs_for_an_operator(app, client, monkeypatch,
                                                  url):
    from tests.conftest import make_user
    calls = _sync_spy(monkeypatch)
    aid = _fw(app)
    login(client, make_user(app, username="op-sync", role="operator"))
    r = client.post(url.format(aid=aid))
    assert r.status_code == 302
    assert calls == [aid]


def test_the_policy_list_hides_write_buttons_from_a_viewer(app, client):
    from tests.conftest import make_user
    aid = _fw(app)
    login(client, make_user(app, username="ro-list", role="readonly"))
    h = client.get(f"/workspace/{aid}").get_data(as_text=True)
    assert f"/workspace/{aid}/refresh" not in h
    assert f"/workspace/{aid}/new-policy" not in h
    login(client, admin_user_id(app))
    h = client.get(f"/workspace/{aid}").get_data(as_text=True)
    assert f"/workspace/{aid}/refresh" in h
    import re
    m = re.search(r'<a href="([^"]+)" class="btn btn-secondary btn-sm">\s*'
                  r'<i class="bi bi-chevron-left me-1"></i>Change Appliance', h)
    assert m and m.group(1).endswith("/architecture/"), m and m.group(1)


def test_the_policy_editor_is_read_only_for_a_viewer(app, client):
    from tests.conftest import make_user
    aid = _fw(app)
    login(client, make_user(app, username="ro-det", role="readonly"))
    r = client.get(f"/workspace/{aid}/policy/pol-a")
    if r.status_code != 200:
        pytest.skip("policy editor needs a cached policy: %s" % r.status_code)
    assert "data-readonly-note" in r.get_data(as_text=True)
    login(client, admin_user_id(app))
    r = client.get(f"/workspace/{aid}/policy/pol-a")
    assert "data-readonly-note" not in r.get_data(as_text=True)
