"""FortiADC area: registry seed, menu build, routes, product gate."""
from __future__ import annotations

from tests.conftest import admin_user_id, login


def _fresh_menu(app):
    from app.services import adc_menu
    adc_menu.invalidate()
    with app.app_context():
        return adc_menu.menu()


def test_adc_registry_seeded(app):
    from app.models import RegistryEndpoint
    with app.app_context():
        n = RegistryEndpoint.query.filter_by(product="fortiadc", enabled=True).count()
    assert n > 150, f"expected the fortiadc seed to land, got {n} rows"


def test_adc_menu_builds_and_resolves(app):
    groups = _fresh_menu(app)
    labels = [g.label for g in groups]
    assert "Server Load Balance" in labels
    assert "Link Load Balance" in labels
    assert "Global Load Balance" in labels
    assert "Web Application Firewall" in labels
    for g in groups:
        for item in g.items:
            assert item.tabs, f"{item.key} lost all its tabs"
            for t in item.tabs:
                assert t.urn.startswith("/api/"), (item.key, t.logical, t.urn)


def test_adc_menu_item_keys_unique(app):
    groups = _fresh_menu(app)
    keys = [i.key for g in groups for i in g.items]
    assert len(keys) == len(set(keys))


def test_adc_dashboard_and_section_render(app, client):
    _fresh_menu(app)
    login(client, admin_user_id(app), product="fortiadc")
    r = client.get("/adc/")
    assert r.status_code == 200
    assert b"FortiADC" in r.data
    # a section page renders without a device (guidance banner, no crash)
    r = client.get("/adc/m/virtual-server")
    assert r.status_code == 200
    assert b"Virtual Server" in r.data
    # tabs switch
    r = client.get("/adc/m/real-server-pool?tab=load_balance_real_server")
    assert r.status_code == 200
    # unknown item → 404
    assert client.get("/adc/m/nope").status_code == 404


def test_product_gate_scopes_fortiadc(app, client):
    login(client, admin_user_id(app), product="fortiadc")
    # a FortiWeb-only page bounces back into the ADC area
    r = client.get("/workspace/")
    assert r.status_code == 302
    assert "/adc" in r.headers["Location"]
    # shared admin pages stay reachable
    assert client.get("/appliances/").status_code in (200, 302)


def test_adc_write_endpoints_need_device(app, client):
    login(client, admin_user_id(app), product="fortiadc")
    r = client.post("/adc/obj/load_balance_pool/save",
                    json={"mkey": "x", "data": "{\"a\": 1}"})
    assert r.status_code == 400
    assert "no FortiADC selected" in r.get_json()["error"]


def test_resolve_adc_unknown_raises(app):
    from app.registry import loader
    with app.app_context():
        try:
            loader.resolve_adc("definitely_not_a_thing")
            raise AssertionError("expected KeyError")
        except KeyError:
            pass
