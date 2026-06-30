from tests.conftest import login, admin_user_id


def _approved(app, name):
    from app.models import db, Template
    with app.app_context():
        t = Template(kind=Template.KIND_WEB_PROTECTION, name=name, version=1,
                     body="{}", status=Template.STATUS_APPROVED)
        db.session.add(t); db.session.commit()
        return t.id


def test_baselines_list_requires_login(client):
    assert client.get("/provisioning/baselines").status_code in (301, 302)


def test_create_and_list_baseline(client, app):
    tid = _approved(app, "wpp-a")
    login(client, admin_user_id(app))
    r = client.post("/provisioning/baselines/new", data={
        "name": "Edge-North", "zone": "DMZ", "line": "8.0", "department": "",
        "template_ids": [str(tid)],
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"Edge-North" in r.data
    from app.models import Baseline
    with app.app_context():
        b = Baseline.query.filter_by(name="Edge-North").first()
        assert b is not None and b.zone == "DMZ"
        assert len(b.items) == 1


def test_create_rejects_blank_name(client, app):
    tid = _approved(app, "wpp-a")
    login(client, admin_user_id(app))
    r = client.post("/provisioning/baselines/new", data={
        "name": "", "template_ids": [str(tid)]}, follow_redirects=True)
    assert b"name is required" in r.data.lower() or b"Baseline name" in r.data


def test_delete_baseline_route(client, app):
    from app.services import baselines as B
    tid = _approved(app, "wpp-a")
    with app.app_context():
        b = B.create_baseline("Tmp", template_ids=[tid])
        bid = b.id
    login(client, admin_user_id(app))
    r = client.post(f"/provisioning/baselines/{bid}/delete", follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        assert B.get_baseline(bid) is None
