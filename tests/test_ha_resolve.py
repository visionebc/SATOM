"""HA connection resolution: build_client routes a cluster node 0 to the
live write target (primary member, or the VIP)."""
from __future__ import annotations

import pytest

from app.services import ha


def _mk(session, name, **kw):
    from app.models import Appliance
    a = Appliance(
        name=name, kind=kw.pop("kind", "fortiweb"),
        host=kw.pop("host", "192.0.2.9"), username="admin",
        password_enc="placeholder", **kw,
    )
    a.set_password("secret")
    session.add(a)
    return a


# --- parse_ha_role (pure) ---------------------------------------------------

@pytest.mark.parametrize("status,expected", [
    ({"ha_role": "primary"}, "primary"),
    ({"role": "master"}, "primary"),
    ({"ha-role": "active"}, "primary"),
    ({"ha_role": "secondary"}, "secondary"),
    ({"role": "slave"}, "secondary"),
    ({"is_master": True}, "primary"),
    ({"is_master": "0"}, "secondary"),
    ({"ha_mode": "standalone"}, "standalone"),
    ({"mode": ""}, "standalone"),
    ({"something": "else"}, "standalone"),   # no HA fields at all -> treat as standalone
    ({"ha_mode": "weird-mode"}, "unknown"),  # a non-empty, unrecognized mode
    ("not a dict", "unknown"),
])
def test_parse_ha_role(status, expected):
    assert ha.parse_ha_role(status) == expected


# --- resolve_write_target ---------------------------------------------------

def test_resolve_vip_returns_node0(session):
    node0 = _mk(session, "fwv0", is_cluster=True, ha_mode="vip",
                ha_vip="192.0.2.50", host="192.0.2.50")
    session.flush()
    assert ha.resolve_write_target(node0) is node0


def test_resolve_per_node_returns_primary(session, monkeypatch):
    node0 = _mk(session, "fwp0", is_cluster=True, ha_mode="per_node", host="")
    session.flush()
    p1 = _mk(session, "fwp1", is_cluster_member=True, parent_id=node0.id,
             ha_role_hint="primary", host="192.0.2.41")
    p2 = _mk(session, "fwp2", is_cluster_member=True, parent_id=node0.id,
             ha_role_hint="secondary", host="192.0.2.42")
    session.flush()

    roles = {"fwp1": "secondary", "fwp2": "primary"}  # live role != hint on purpose
    monkeypatch.setattr(ha, "member_role", lambda m, timeout=6.0: roles[m.name])

    assert ha.resolve_write_target(node0) is p2


def test_resolve_no_primary_raises(session, monkeypatch):
    node0 = _mk(session, "fwn0", is_cluster=True, ha_mode="per_node", host="")
    session.flush()
    _mk(session, "fwn1", is_cluster_member=True, parent_id=node0.id, host="192.0.2.43")
    _mk(session, "fwn2", is_cluster_member=True, parent_id=node0.id, host="192.0.2.44")
    session.flush()

    monkeypatch.setattr(ha, "member_role", lambda m, timeout=6.0: "standalone")
    with pytest.raises(ha.HAError):
        ha.resolve_write_target(node0)


def test_resolve_no_members_raises(session):
    node0 = _mk(session, "fwe0", is_cluster=True, ha_mode="per_node", host="")
    session.flush()
    with pytest.raises(ha.HAError):
        ha.resolve_write_target(node0)


# --- build_client delegation ------------------------------------------------

def test_build_client_standalone_unchanged(session):
    a = _mk(session, "fw-solo", host="192.0.2.7")
    session.flush()
    client = a.build_client()
    from app.clients.fortiweb import FortiWebClient
    assert isinstance(client, FortiWebClient)
    assert "192.0.2.7" in client.base_url


def test_build_client_cluster_resolves_primary(session, monkeypatch):
    node0 = _mk(session, "fwc0", is_cluster=True, ha_mode="per_node", host="")
    session.flush()
    _mk(session, "fwc1", is_cluster_member=True, parent_id=node0.id,
        ha_role_hint="primary", host="192.0.2.81")
    session.flush()
    monkeypatch.setattr(ha, "member_role", lambda m, timeout=6.0: "primary")
    client = node0.build_client()
    assert "192.0.2.81" in client.base_url
