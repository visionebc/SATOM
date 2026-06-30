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
