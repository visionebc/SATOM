"""Global Search honours its two filters (Appliance, Object Type).

The form submits ``appliance_id`` and ``obj_type``; the results view used to
read neither (it read ``appliances``), so every search swept every visible
device and every collection. These tests record which device / endpoint the
view actually queries.
"""
from __future__ import annotations

import pytest

from app.models import Appliance, User, db
from app.views import search as search_view
from tests.conftest import login


@pytest.fixture()
def admin_id(app):
    with app.app_context():
        return User.query.filter_by(username="admin").first().id


@pytest.fixture()
def two_fwb(app):
    ids = []
    with app.app_context():
        for name in ("fwb-a", "fwb-b"):
            a = Appliance(name=name, host="192.0.2.%d" % (len(ids) + 10),
                          kind="fortiweb", username="admin")
            a.password = "pw"
            db.session.add(a)
            db.session.flush()
            ids.append(a.id)
        db.session.commit()
    return ids


@pytest.fixture()
def calls(monkeypatch):
    seen: list[tuple[str, str]] = []

    class _Resp:
        def __init__(self, name):
            self._name = name

        def json(self):
            return {"data": [{"name": "shop-" + self._name}]}

    class _Client:
        def __init__(self, appliance):
            self.appliance = appliance

        def api_call(self, method, endpoint):
            seen.append((self.appliance.name, endpoint))
            return _Resp(self.appliance.name)

    monkeypatch.setattr(search_view, "FortiWebClient", _Client)
    return seen


def test_appliance_filter_limits_the_sweep(client, admin_id, two_fwb, calls):
    login(client, admin_id)
    r = client.get("/search/results?q=shop&appliance_id=%d" % two_fwb[1])
    assert r.status_code == 200
    assert calls, "the search never reached a device"
    assert {name for name, _ in calls} == {"fwb-b"}
    assert "shop-fwb-b" in r.get_data(as_text=True)


def test_no_appliance_filter_sweeps_all_visible(client, admin_id, two_fwb, calls):
    login(client, admin_id)
    r = client.get("/search/results?q=shop&appliance_id=")
    assert r.status_code == 200
    assert {name for name, _ in calls} == {"fwb-a", "fwb-b"}


def test_obj_type_filter_limits_the_endpoints(client, admin_id, two_fwb, calls):
    login(client, admin_id)
    r = client.get("/search/results?q=shop&obj_type=pool&appliance_id=%d"
                   % two_fwb[0])
    assert r.status_code == 200
    assert calls == [("fwb-a", "/ServerObjects/Server/ServerPool")]
    body = r.get_data(as_text=True)
    # the refine form keeps both filters
    assert 'name="obj_type" value="pool"' in body
    assert 'name="appliance_id" value="%d"' % two_fwb[0] in body


def test_no_obj_type_queries_every_endpoint(client, admin_id, two_fwb, calls):
    login(client, admin_id)
    client.get("/search/results?q=shop&obj_type=&appliance_id=%d" % two_fwb[0])
    assert [e for _, e in calls] == search_view.SEARCH_ENDPOINTS


def test_adc_obj_type_maps_to_registry_collections(app, monkeypatch):
    seen = []

    class _Adc:
        def list_with_error(self, logical):
            seen.append(logical)
            return [], None

    monkeypatch.setattr(search_view, "client_for", lambda a: _Adc())
    with app.app_context():
        search_view._adc_hits(object(), "x",
                              search_view.OBJ_TYPE_ADC_LOGICALS["pool"])
        assert seen == ["load_balance_pool", "load_balance_real_server"]
        seen.clear()
        assert search_view._adc_hits(object(), "x", []) == []
        assert seen == []


def test_adc_obj_type_filter_reaches_the_view(app, client, admin_id, monkeypatch):
    seen = []

    class _Adc:
        def list_with_error(self, logical):
            seen.append(logical)
            return [{"name": "shop-" + logical}], None

    with app.app_context():
        a = Appliance(name="adc-a", host="192.0.2.30", kind="fortiadc",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        aid = a.id
    monkeypatch.setattr(search_view, "client_for", lambda ap: _Adc())
    login(client, admin_id, product="global")
    r = client.get("/search/results?q=shop&obj_type=wpp&appliance_id=%d" % aid,
                   headers={"X-ADOM": "global"})
    assert r.status_code == 200
    assert seen == ["security_waf_profile"]
