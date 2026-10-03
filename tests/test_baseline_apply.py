from tests.conftest import login, admin_user_id


def _approved(app, name):
    from app.models import db, Template
    with app.app_context():
        t = Template(kind=Template.KIND_WEB_PROTECTION, name=name, version=1,
                     body='{"endpoint":"x","mkey":"m","data":{}}',
                     status=Template.STATUS_APPROVED)
        db.session.add(t); db.session.commit()
        return t.id


def _appliance(app, name, zone=""):
    from app.models import db, Appliance
    with app.app_context():
        a = Appliance(name=name, host="1.1.1.1", username="x", zone=zone)
        a.password = "pw"; db.session.add(a); db.session.commit()
        return a.id


def test_apply_preview_lists_matching_devices(client, app):
    from app.services import baselines as B
    tid = _approved(app, "wpp-a")
    _appliance(app, "fw1", zone="DMZ")
    _appliance(app, "fw2", zone="LAN")
    with app.app_context():
        b = B.create_baseline("Edge", zone="DMZ", template_ids=[tid])
        bid = b.id
    login(client, admin_user_id(app))
    r = client.post(f"/provisioning/baselines/{bid}/apply", data={}, follow_redirects=True)
    assert r.status_code == 200
    assert b"fw1" in r.data        # in scope
    assert b"fw2" not in r.data    # out of scope


def test_a_combo_of_system_profiles_pushes_their_items(app):
    """A system-profile body is {"items": [...]}; the generic walker read it as
    a node without an endpoint and the combo pushed nothing."""
    import json
    from app.models import db, Template
    from app.services import baselines as B
    from app.services import provisioning as prov
    body = {"line": "8.0", "items": [
        {"key": "dns", "endpoint": "/api/v2.0/cmdb/system/dns",
         "data": {"primary": "192.0.2.2"}, "singleton": True},
        {"key": "ntp", "endpoint": "/api/v2.0/cmdb/system/ntp",
         "data": {"server": "pool"}, "mkey": "1"},
    ]}
    with app.app_context():
        t = Template(kind=Template.KIND_SYSTEM, name="sys-combo", version=1,
                     body=json.dumps(body), status=Template.STATUS_APPROVED)
        db.session.add(t); db.session.commit()
        b = B.create_baseline("Sys", template_ids=[t.id])
        items = B.baseline_push_items(b)
        assert [i["endpoint"] for i in items] == ["/api/v2.0/cmdb/system/dns",
                                                  "/api/v2.0/cmdb/system/ntp"]
        assert [i["action"] for i in items] == ["update", "update"]
        assert items == prov.push_items(prov.SystemProfile.from_template(t))
