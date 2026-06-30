"""HA cluster data model: self-referential Appliance (node 0 + members)."""
from __future__ import annotations


def _mk(session, name, **kw):
    from app.models import Appliance
    a = Appliance(
        name=name,
        kind=kw.pop("kind", "fortiweb"),
        host=kw.pop("host", "192.0.2.9"),
        username=kw.pop("username", "admin"),
        password_enc="placeholder",
        **kw,
    )
    a.set_password("secret")
    session.add(a)
    return a


def test_cluster_node_and_members_wiring(session):
    node0 = _mk(session, "fw001p0", is_cluster=True, ha_mode="per_node", host="")
    session.flush()
    p1 = _mk(session, "fw001p1", is_cluster_member=True, parent_id=node0.id,
             ha_role_hint="primary", host="192.0.2.41")
    p2 = _mk(session, "fw001p2", is_cluster_member=True, parent_id=node0.id,
             ha_role_hint="secondary", host="192.0.2.42")
    session.flush()

    assert {m.name for m in node0.members} == {"fw001p1", "fw001p2"}
    assert p1.parent is node0
    assert p2.parent is node0
    assert [m.name for m in node0.cluster_members()] == ["fw001p1", "fw001p2"]


def test_is_standalone_semantics(session):
    standalone = _mk(session, "fw-solo")
    node0 = _mk(session, "fw002p0", is_cluster=True, ha_mode="vip", ha_vip="192.0.2.50", host="192.0.2.50")
    session.flush()
    member = _mk(session, "fw002p1", is_cluster_member=True, parent_id=node0.id, host="192.0.2.43")
    session.flush()

    assert standalone.is_standalone is True
    assert node0.is_standalone is False
    assert member.is_standalone is False


def test_delete_node0_cascades_members(session):
    from app.models import Appliance
    node0 = _mk(session, "fw003p0", is_cluster=True, ha_mode="per_node", host="")
    session.flush()
    _mk(session, "fw003p1", is_cluster_member=True, parent_id=node0.id, host="192.0.2.44")
    _mk(session, "fw003p2", is_cluster_member=True, parent_id=node0.id, host="192.0.2.45")
    session.flush()

    session.delete(node0)
    session.flush()

    assert Appliance.query.filter(Appliance.name.like("fw003%")).count() == 0


def test_to_dict_carries_ha_fields(session):
    node0 = _mk(session, "fw004p0", is_cluster=True, ha_mode="vip", ha_vip="192.0.2.60", host="192.0.2.60")
    session.flush()
    d = node0.to_dict()
    assert d["is_cluster"] is True
    assert d["is_cluster_member"] is False
    assert d["ha_mode"] == "vip"
    assert d["ha_vip"] == "192.0.2.60"
    assert d["parent_id"] is None
    assert d["ha_role_hint"] is None
