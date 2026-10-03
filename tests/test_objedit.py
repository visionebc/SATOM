"""Generic recursive object editor — route contracts (dry-run, no device)."""
from __future__ import annotations

from tests.conftest import login, admin_user_id


def _make_appliance(app):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw1", kind="fortiweb", host="192.0.2.99",
                      port=443, username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a); db.session.commit()
        return a.id


def test_editor_renders_structure_offline(client, app):
    """The editor shows the object's fields + sub-tables from the registry even
    when the device is unreachable — a pool always offers its Real Servers."""
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    r = client.get(f"/objedit/{aid}/edit?collection=server-policy/server-pool&mkey=pool-x&title=Server+Pool")
    assert r.status_code == 200, r.status_code
    h = r.get_data(as_text=True)
    assert 'data-collection="server-policy/server-pool"' in h
    assert 'data-mkey="pool-x"' in h
    assert "Real Servers" in h            # the pserver-list sub-table card
    assert "Add Real Servers row" in h    # the create-row affordance
    assert "function saveObject" in h and "function saveRow" in h


def test_unknown_collection_rejected(client, app):
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    r = client.post(f"/objedit/{aid}/save-object",
                    json={"collection": "evil/path", "mkey": "x", "fields": {"a": 1}})
    assert r.status_code == 400


def test_save_object_dryrun_strips_ids(client, app):
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    r = client.post(f"/objedit/{aid}/save-object", json={
        "collection": "server-policy/server-pool", "mkey": "pool-x",
        "fields": {"comment": "hi", "server-pool-id": 9, "status_val": "enable"},
    })
    assert r.status_code == 200, r.status_code
    j = r.get_json()
    assert j["ok"] and j["dry_run"], j
    req = j["request"]
    assert req["method"] == "PUT"
    # FortiWebOps._path lstrips the leading slash (established convention)
    assert req["path"] == "api/v2.0/cmdb/server-policy/server-pool?mkey=pool-x"
    body = req["body"]["data"]
    assert body["comment"] == "hi"
    # the errcode-10 killers are stripped by the shared sanitizer
    assert "server-pool-id" not in body and "status_val" not in body


def test_save_row_create_dryrun(client, app):
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    r = client.post(f"/objedit/{aid}/save-row", json={
        "collection": "server-policy/server-pool/pserver-list", "parent": "pool-x",
        "fields": {"ip": "192.0.2.5", "port": "80"},
    })
    j = r.get_json()
    assert j["ok"] and j["dry_run"], j
    assert j["request"]["method"] == "POST"
    assert j["request"]["path"] == "api/v2.0/cmdb/server-policy/server-pool/pserver-list?mkey=pool-x"
    assert j["request"]["body"]["data"]["ip"] == "192.0.2.5"


def test_save_row_update_uses_sub_mkey(client, app):
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    r = client.post(f"/objedit/{aid}/save-row", json={
        "collection": "server-policy/server-pool/pserver-list", "parent": "pool-x",
        "sub_id": 3, "fields": {"port": "8443"},
    })
    j = r.get_json()
    assert j["ok"] and j["dry_run"], j
    assert j["request"]["method"] == "PUT"
    assert j["request"]["path"].endswith("?mkey=pool-x&sub_mkey=3")


def test_wpp_collection_is_editable(app):
    """Web Protection's inline profile must resolve as a known editable object so
    the 'Edit profile' link reaches the generic editor."""
    from app.services import objform
    assert objform.is_known_collection("waf/web-protection-profile.inline-protection")


def test_ref_options_allow_list(client, app):
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    # a real ref collection → 200 (names empty, device unreachable, but allowed)
    ok = client.get(f"/objedit/{aid}/ref-options?endpoint=waf/signature")
    assert ok.status_code == 200, ok.status_code
    assert "names" in ok.get_json()
    # an arbitrary path is rejected
    bad = client.get(f"/objedit/{aid}/ref-options?endpoint=evil/path")
    assert bad.status_code == 400


def test_delete_row_dryrun(client, app):
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    r = client.post(f"/objedit/{aid}/delete-row", json={
        "collection": "server-policy/server-pool/pserver-list", "parent": "pool-x", "sub_id": 3,
    })
    j = r.get_json()
    assert j["ok"] and j["dry_run"], j
    assert j["request"]["method"] == "DELETE"
    assert j["request"]["path"].endswith("&sub_mkey=3")


# --------------------------------------------------------------------------- #
#  Edit lease enforced server-side (audit AU-22) and on the inline path (AU-25)  #
# --------------------------------------------------------------------------- #
def _hold(app, aid, key, owner="alice"):
    from tests.conftest import make_user
    from app.services import lock_service
    uid = make_user(app, owner, role="operator")
    with app.app_context():
        ok, _info = lock_service.acquire(aid, key, user_id=uid, owner_label=owner)
        assert ok


_WRITES = [
    ("save-object", {"collection": "server-policy/server-pool", "mkey": "pool-x",
                     "fields": {"comment": "hi"}}),
    ("delete-object", {"collection": "server-policy/server-pool", "mkey": "pool-x"}),
    ("save-row", {"collection": "server-policy/server-pool/pserver-list",
                  "parent": "pool-x", "fields": {"port": "80"}}),
    ("delete-row", {"collection": "server-policy/server-pool/pserver-list",
                    "parent": "pool-x", "sub_id": 3}),
]


import pytest  # noqa: E402


@pytest.mark.parametrize("route,body", _WRITES, ids=[w[0] for w in _WRITES])
def test_a_write_over_another_users_lease_is_refused(client, app, route, body):
    aid = _make_appliance(app)
    _hold(app, aid, "server-policy/server-pool:pool-x")
    login(client, admin_user_id(app))
    r = client.post(f"/objedit/{aid}/{route}", json=dict(body, apply=True))
    assert r.status_code == 409, (r.status_code, r.get_json())
    j = r.get_json()
    assert j["ok"] is False and "alice" in j["error"]


@pytest.mark.parametrize("route,body", _WRITES, ids=[w[0] for w in _WRITES])
def test_the_lease_holder_still_saves(client, app, route, body):
    from app.services import lock_service
    aid = _make_appliance(app)
    admin = admin_user_id(app)
    with app.app_context():
        assert lock_service.acquire(aid, "server-policy/server-pool:pool-x",
                                    user_id=admin, owner_label="admin")[0]
    login(client, admin)
    r = client.post(f"/objedit/{aid}/{route}", json=body)
    assert r.status_code == 200, (r.status_code, r.get_json())
    assert r.get_json()["dry_run"]


def test_a_lease_on_another_object_does_not_block(client, app):
    aid = _make_appliance(app)
    _hold(app, aid, "server-policy/server-pool:pool-other")
    login(client, admin_user_id(app))
    r = client.post(f"/objedit/{aid}/save-object", json=_WRITES[0][1])
    assert r.status_code == 200


def test_the_inline_editor_carries_the_lease_guard(client, app):
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    for extra in ("&partial=1", ""):
        r = client.get(f"/objedit/{aid}/edit?collection=server-policy/server-pool"
                       f"&mkey=pool-x&title=Pool{extra}")
        h = r.get_data(as_text=True)
        assert h.count('class="fw-lock-guard"') == 1, extra
        assert 'data-resource-key="server-policy/server-pool:pool-x"' in h
        assert "js/lock.js" in h
