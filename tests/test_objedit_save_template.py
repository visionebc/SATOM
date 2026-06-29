"""Save an EXISTING config object (+ its sub-tables) as a config template.

Covers the pure body-builder (parent-first / rows-after ordering, id stripping,
the {"data": …} write wrapper) and the route contract (lands PENDING under the
section kind, permission-gated, validates section/name).
"""
from __future__ import annotations

from tests.conftest import login, admin_user_id, make_user, profile_id


def _make_appliance(app):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw1", kind="fortiweb", host="192.0.2.99",
                      port=443, username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a); db.session.commit()
        return a.id


# ---- pure builder -------------------------------------------------------- #
def test_builder_parent_first_then_rows_and_strips_ids():
    from app.views.objedit import build_config_template_body
    from app.services.bulk import iter_push_items
    obj = {"name": "pool-x", "comment": "hi", "server-pool-id": 9, "q_type": "x"}
    subtables = [{"seg": "pserver-list",
                  "collection": "server-policy/server-pool/pserver-list",
                  "rows": [{"id": 1, "ip": "192.0.2.5", "port": "80"},
                           {"id": 2, "ip": "192.0.2.6", "port": "80"}]}]
    body = build_config_template_body("server-policy/server-pool", "pool-x", obj, subtables)
    items = iter_push_items(body)
    # parent first, then the two owned rows (owned children must come AFTER)
    assert [it["action"] for it in items] == ["create", "create", "create"]
    assert items[0]["endpoint"].endswith("server-policy/server-pool")
    assert items[0]["data"]["data"]["name"] == "pool-x"
    assert items[0]["data"]["data"]["comment"] == "hi"
    # errcode-10 killers + q_* metadata stripped on the parent
    assert "server-pool-id" not in items[0]["data"]["data"]
    assert "q_type" not in items[0]["data"]["data"]
    # rows scoped with ?mkey=parent, row id dropped
    assert items[1]["endpoint"].endswith("pserver-list?mkey=pool-x")
    assert items[1]["data"]["data"] == {"ip": "192.0.2.5", "port": "80"}
    assert items[2]["data"]["data"]["ip"] == "192.0.2.6"


def test_builder_singleton_is_update_no_name():
    from app.views.objedit import build_config_template_body
    from app.services.bulk import iter_push_items
    body = build_config_template_body("system/dns", "", {"primary": "8.8.8.8"}, [], singleton=True)
    items = iter_push_items(body)
    assert len(items) == 1
    assert items[0]["action"] == "update"
    assert items[0]["data"]["data"] == {"primary": "8.8.8.8"}
    assert "name" not in items[0]["data"]["data"]


# ---- route --------------------------------------------------------------- #
def _patch_reads(monkeypatch):
    from app.views import objedit
    monkeypatch.setattr(objedit, "_read_object",
                        lambda c, coll, mkey, singleton=False: {"name": mkey, "comment": "x", "server-pool-id": 5})
    monkeypatch.setattr(objedit, "_read_rows",
                        lambda c, sub, parent: [{"id": 1, "ip": "192.0.2.5", "port": "80"}] if "pserver-list" in sub else [])


def test_route_saves_pending_config_template(client, app, monkeypatch):
    aid = _make_appliance(app)
    _patch_reads(monkeypatch)
    login(client, admin_user_id(app))
    r = client.post(f"/objedit/{aid}/save-template", json={
        "collection": "server-policy/server-pool", "mkey": "pool-x",
        "section": "server_objects", "name": "baseline-pool", "note": "cap"})
    assert r.status_code == 200, r.get_data(as_text=True)
    j = r.get_json()
    assert j["ok"] and j["status"] == "pending", j
    assert j["kind"] == "config:server_objects"
    assert j["item_count"] >= 2  # pool + >=1 member
    from app.models import Template
    with app.app_context():
        t = Template.query.filter_by(name="baseline-pool").first()
        assert t is not None and t.status == "pending"
        assert t.kind == "config:server_objects"


def test_route_unknown_section_rejected(client, app, monkeypatch):
    aid = _make_appliance(app)
    _patch_reads(monkeypatch)
    login(client, admin_user_id(app))
    r = client.post(f"/objedit/{aid}/save-template", json={
        "collection": "server-policy/server-pool", "mkey": "pool-x",
        "section": "nope", "name": "x"})
    assert r.status_code == 400


def test_route_requires_name(client, app, monkeypatch):
    aid = _make_appliance(app)
    _patch_reads(monkeypatch)
    login(client, admin_user_id(app))
    r = client.post(f"/objedit/{aid}/save-template", json={
        "collection": "server-policy/server-pool", "mkey": "pool-x",
        "section": "server_objects", "name": ""})
    assert r.status_code == 400


def test_route_permission_gated(client, app, monkeypatch):
    """A user whose profile lacks operations.template_save cannot capture."""
    aid = _make_appliance(app)
    _patch_reads(monkeypatch)
    uid = make_user(app, username="ro", role="readonly", profile_id=profile_id(app, "readonly"))
    login(client, uid)
    r = client.post(f"/objedit/{aid}/save-template", json={
        "collection": "server-policy/server-pool", "mkey": "pool-x",
        "section": "server_objects", "name": "x"})
    assert r.status_code == 403


# ---- section page renders the button wiring ------------------------------ #
def test_section_page_has_save_as_template_wiring(client, app):
    """The Configuration section page ships the capture button + JS + new route
    so an opened object can be saved as a template (admin has the perm)."""
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    with client.session_transaction() as sess:
        sess["appliance_id"] = aid
    r = client.get("/configuration/server_objects")
    assert r.status_code == 200, r.status_code
    h = r.get_data(as_text=True)
    assert "function cfgSaveAsTemplate" in h
    assert "modalSaveAsTemplate" in h
    assert "/save-template" in h
    assert "const SECTION_KEY" in h
