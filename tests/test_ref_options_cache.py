"""Reference dropdowns are DB-first resilient: when the box is offline or
license-locked (live cmdb_names → []), /objedit/ref-options and
/workspace/cmdb-options serve the CACHED object names instead of an empty list
(the blank-dropdown regression on the locked fleet)."""
from __future__ import annotations

from unittest.mock import patch

from tests.conftest import login


def _appliance(session, name="fw-refs"):
    from app.models import Appliance
    a = Appliance(name=name, kind="fortiweb", host="192.0.2.9", port=443,
                  username="admin", password_enc="x", verify_ssl=False)
    session.add(a); session.commit()
    return a


def _admin(session):
    from app.models import User
    u = User.query.filter_by(username="admin").first()
    if u:
        return u
    u = User(username="admin", role="admin")
    if hasattr(u, "set_password"):
        u.set_password("x")
    session.add(u); session.commit()
    return u


SECTIONS = {
    "Server Pool": {"server_pool": [
        {"name": "pool-a", "type": "reverse-proxy"},
        {"name": "pool-b", "type": "reverse-proxy"},
    ]},
    "Server Objects": {"vip": [{"name": "vip-1", "vip": "192.0.2.50/24"}]},
}


def _seed(session, appliance_id):
    from app.services import device_store as ds
    ds.ingest_sections(appliance_id, SECTIONS, source="test", session=session)


def test_cached_ref_names_reads_config_layer(app, session):
    a = _appliance(session)
    _seed(session, a.id)
    from app.services import read_layer
    names = read_layer.cached_ref_names(a.id, "server-policy/server-pool")
    assert names == ["pool-a", "pool-b"]
    assert read_layer.cached_ref_names(a.id, "system/vip") == ["vip-1"]


def test_cached_ref_names_multi_source_and_unknown(app, session):
    a = _appliance(session)
    _seed(session, a.id)
    from app.services import read_layer
    # multi-source 'a|b' form merges; an unknown collection yields []
    assert "pool-a" in read_layer.cached_ref_names(
        a.id, "server-policy/server-pool|server-policy/ssl-ciphers.custom")
    assert read_layer.cached_ref_names(a.id, "waf/does-not-exist") == []


def test_objedit_ref_options_falls_back_to_cache(app, client, session):
    a = _appliance(session)
    _seed(session, a.id)
    u = _admin(session)
    login(client, u.id)
    with patch("app.clients.fortiweb.FortiWebClient.cmdb_names", return_value=[]):
        r = client.get(f"/objedit/{a.id}/ref-options?endpoint=server-policy/server-pool")
    assert r.status_code == 200
    j = r.get_json()
    assert j["names"] == ["pool-a", "pool-b"]
    assert j["source"] == "cache"


def test_workspace_cmdb_options_falls_back_to_cache(app, client, session):
    a = _appliance(session)
    _seed(session, a.id)
    u = _admin(session)
    login(client, u.id)
    with patch("app.clients.fortiweb.FortiWebClient.cmdb_names", return_value=[]):
        r = client.get(f"/workspace/{a.id}/cmdb-options?endpoint=server-policy/server-pool")
    assert r.status_code == 200
    j = r.get_json()
    assert j["names"] == ["pool-a", "pool-b"]
    assert j["source"] == "cache"


def test_live_names_win_over_cache(app, client, session):
    from unittest.mock import MagicMock
    a = _appliance(session)
    _seed(session, a.id)
    u = _admin(session)
    login(client, u.id)
    fake = MagicMock()
    fake.return_value.cmdb_names.return_value = ["live-pool"]
    with patch("app.views.objedit.FortiWebClient", fake):
        r = client.get(f"/objedit/{a.id}/ref-options?endpoint=server-policy/server-pool")
    j = r.get_json()
    assert j["names"] == ["live-pool"]
    assert j["source"] == "live"
