"""Fleet list: cluster members are nested under node 0, not shown as
standalone top-level rows; the live-role JSON endpoint works."""
from __future__ import annotations

from tests.conftest import login, make_user, profile_id
from app.services import ha


def _cluster_with_member(app):
    from app.models import Appliance, db
    with app.app_context():
        node0 = Appliance(name="fwf0", kind="fortiweb", host="", port=443,
                          username="admin", verify_ssl=False, is_cluster=True,
                          ha_mode="per_node")
        node0.password = "x"; db.session.add(node0); db.session.flush()
        m = Appliance(name="fwf1", kind="fortiweb", host="192.0.2.41", port=443,
                      username="admin", verify_ssl=False, is_cluster_member=True,
                      parent_id=node0.id, ha_role_hint="primary")
        m.password = "x"; db.session.add(m); db.session.commit()
        return node0.id, m.id


def test_index_nests_member_not_standalone(app, client):
    nid, mid = _cluster_with_member(app)
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, op)
    body = client.get("/appliances/").get_data(as_text=True)
    # node 0 is a top-level row with a status indicator
    assert f'data-status-id="{nid}"' in body
    # the member is rendered as a nested sub-row, NOT a standalone top-level row
    assert f'data-member-of="{nid}"' in body
    assert f'data-test-id="{mid}"' not in body
    assert "fwf1" in body  # member still visible (nested)


def test_member_roles_endpoint(app, client, monkeypatch):
    nid, mid = _cluster_with_member(app)
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, op)
    monkeypatch.setattr(ha, "member_role", lambda m, timeout=5.0: "primary")
    r = client.get(f"/appliances/{nid}/members/roles")
    assert r.status_code == 200
    assert r.get_json() == {str(mid): "primary"}


def test_index_standalone_still_top_level(app, client):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw-solo3", kind="fortiweb", host="192.0.2.7",
                      port=443, username="admin", verify_ssl=False)
        a.password = "x"; db.session.add(a); db.session.commit()
        sid = a.id
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, op)
    body = client.get("/appliances/").get_data(as_text=True)
    assert f'data-status-id="{sid}"' in body
    assert f'data-test-id="{sid}"' in body  # standalone keeps its action buttons
