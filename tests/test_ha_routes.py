"""HA registration routes: mark a cluster, attach/detach member nodes."""
from __future__ import annotations

from tests.conftest import login, make_user, profile_id


def _operator(app, client):
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, op)
    return op


def _node0(app, mode="per_node", **kw):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name=kw.pop("name", "fw100p0"), kind="fortiweb",
                      host=kw.pop("host", ""), port=443, username="admin",
                      verify_ssl=False, is_cluster=True, ha_mode=mode, **kw)
        a.password = "secret"
        db.session.add(a); db.session.commit()
        return a.id


def test_create_cluster_node0(app, client):
    _operator(app, client)
    r = client.post("/appliances/", data={
        "name": "fw200p0", "kind": "fortiweb", "host": "", "username": "admin",
        "password": "x", "is_cluster": "on", "ha_mode": "per_node",
    }, follow_redirects=False)
    assert r.status_code in (302, 303)
    from app.models import Appliance
    with app.app_context():
        a = Appliance.query.filter_by(name="fw200p0").one()
        assert a.is_cluster is True
        assert a.ha_mode == "per_node"
        assert a.is_cluster_member is False


def test_create_vip_cluster_stores_vip(app, client):
    _operator(app, client)
    r = client.post("/appliances/", data={
        "name": "fw201p0", "kind": "fortiweb", "host": "", "username": "admin",
        "password": "x", "is_cluster": "on", "ha_mode": "vip", "ha_vip": "192.0.2.50",
    }, follow_redirects=False)
    assert r.status_code in (302, 303)
    from app.models import Appliance
    with app.app_context():
        a = Appliance.query.filter_by(name="fw201p0").one()
        assert a.ha_mode == "vip"
        assert a.ha_vip == "192.0.2.50"
        assert a.host == "192.0.2.50"   # VIP becomes the connection target


def test_add_member_creates_member(app, client):
    _operator(app, client)
    nid = _node0(app, name="fw202p0")
    r = client.post(f"/appliances/{nid}/members", data={
        "member_name": "fw202p1", "member_host": "192.0.2.41",
        "member_username": "admin", "member_password": "secret",
        "ha_role_hint": "primary",
    }, follow_redirects=False)
    assert r.status_code in (302, 303)
    from app.models import Appliance
    with app.app_context():
        node0 = Appliance.query.get(nid)
        assert len(node0.members) == 1
        m = node0.members[0]
        assert m.name == "fw202p1"
        assert m.is_cluster_member is True
        assert m.parent_id == nid
        assert m.kind == "fortiweb"   # inherited from node 0
        assert m.ha_role_hint == "primary"


def test_detach_member_makes_standalone(app, client):
    _operator(app, client)
    nid = _node0(app, name="fw203p0")
    client.post(f"/appliances/{nid}/members", data={
        "member_name": "fw203p1", "member_host": "192.0.2.42",
        "member_username": "admin", "member_password": "secret",
    })
    from app.models import Appliance
    with app.app_context():
        mid = Appliance.query.filter_by(name="fw203p1").one().id
    r = client.post(f"/appliances/{nid}/members/{mid}/detach", follow_redirects=False)
    assert r.status_code in (302, 303)
    with app.app_context():
        m = Appliance.query.get(mid)
        assert m is not None
        assert m.parent_id is None
        assert m.is_cluster_member is False
        assert m.is_standalone is True


def test_add_member_rejects_non_cluster(app, client):
    _operator(app, client)
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw-solo2", kind="fortiweb", host="192.0.2.7",
                      port=443, username="admin", verify_ssl=False)
        a.password = "x"; db.session.add(a); db.session.commit()
        sid = a.id
    r = client.post(f"/appliances/{sid}/members", data={
        "member_name": "x", "member_host": "1.2.3.4"}, follow_redirects=False)
    # redirect back with a flash; the member is NOT created
    assert r.status_code in (302, 303)
    with app.app_context():
        assert Appliance.query.filter_by(name="x").count() == 0
