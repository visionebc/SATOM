"""Monitoring lives in EVERY ADOM, scoped to that ADOM's devices.

Until 2026-07-28 Fleet health and Deep monitors were reachable only from the
Global ADOM (the product gate bounced both blueprints) while Metrics was a bare
item in each ADOM's Fleet group. These tests pin the three properties the
restructure has to keep true:

1. the three pages answer inside FortiWeb / FortiADC / FortiAnalyzer;
2. each ADOM sees ONLY its own devices and their probes;
3. something created from the Global ADOM against a device of that product
   shows up in the product's ADOM with no extra bookkeeping (scoping is by
   device KIND, not by who created the row).
"""
from __future__ import annotations

import pytest

from app.models import Appliance, MonitorProbe, User, db
from tests.conftest import login

ADOMS = ["fortiweb", "fortiadc", "fortianalyzer"]


@pytest.fixture()
def admin_id(app):
    with app.app_context():
        u = User.query.filter_by(role="admin").first()
        if u is None:
            u = User(username="adomadmin", role="admin", is_active=True)
            u.set_password("x" * 12)
            db.session.add(u)
            db.session.commit()
        return u.id


@pytest.fixture()
def fleet(app):
    """One device per product, each with one deep monitor."""
    ids = {}
    with app.app_context():
        for kind, host in (("fortiweb", "192.0.2.75"),
                           ("fortiadc", "192.0.2.76"),
                           ("fortianalyzer", "192.0.2.12")):
            a = Appliance(name=kind + "-box", host=host, kind=kind,
                          username="admin")
            a.password = "pw"
            db.session.add(a)
            db.session.flush()
            db.session.add(MonitorProbe(appliance_id=a.id, kind="cpu",
                                        name=kind + "-cpu", enabled=True,
                                        last_status="ok"))
            ids[kind] = a.id
        db.session.commit()
    return ids


# --------------------------------------------------------------------------
# 1. reachable in every ADOM
# --------------------------------------------------------------------------

@pytest.mark.parametrize("adom", ADOMS)
@pytest.mark.parametrize("path", ["/monitoring/", "/monitoring/deep/",
                                  "/monitoring/data", "/monitoring/deep/data"])
def test_monitoring_answers_inside_every_adom(client, admin_id, adom, path):
    login(client, admin_id, product=adom)
    r = client.get(path, headers={"X-ADOM": adom})
    # 200, not the 302 bounce back to /adc/ or /faz/ the gate used to send.
    assert r.status_code == 200, f"{adom} {path} -> {r.status_code}"


@pytest.mark.parametrize("adom", ADOMS + ["global"])
def test_monitoring_submenu_renders_in_every_adom(client, admin_id, adom):
    """One partial, four call sites — the group cannot exist in Global only."""
    login(client, admin_id, product=adom)
    body = client.get("/monitoring/",
                      headers={"X-ADOM": adom}).get_data(as_text=True)
    assert 'data-nav-subgroup="Monitoring"' in body
    for label in ("Fleet health", "Metrics", "Deep monitors"):
        assert ">" + label + "<" in body, f"{label} missing in {adom}"


# --------------------------------------------------------------------------
# 2. each ADOM sees only its own
# --------------------------------------------------------------------------

@pytest.mark.parametrize("adom", ADOMS)
def test_fleet_health_lists_only_this_adoms_devices(client, admin_id, fleet, adom):
    login(client, admin_id, product=adom)
    d = client.get("/monitoring/data", headers={"X-ADOM": adom}).get_json()
    kinds = {x["kind"] for x in d["devices"]}
    assert kinds == {adom}, f"{adom} saw {kinds}"


@pytest.mark.parametrize("adom", ADOMS)
def test_deep_monitors_list_only_this_adoms_probes(client, admin_id, fleet, adom):
    login(client, admin_id, product=adom)
    d = client.get("/monitoring/deep/data", headers={"X-ADOM": adom}).get_json()
    names = {p["name"] for p in d["probes"]}
    assert names == {adom + "-cpu"}, f"{adom} saw {names}"


def test_global_sees_everything(client, admin_id, fleet):
    login(client, admin_id, product="global")
    d = client.get("/monitoring/data", headers={"X-ADOM": "global"}).get_json()
    assert {x["kind"] for x in d["devices"]} == set(ADOMS)


# --------------------------------------------------------------------------
# 3. created in Global -> visible in the product's ADOM
# --------------------------------------------------------------------------

@pytest.mark.parametrize("adom", ADOMS)
def test_probe_added_from_global_appears_in_the_product_adom(
        client, admin_id, fleet, adom):
    login(client, admin_id, product="global")
    r = client.post("/monitoring/deep/probe",
                    headers={"X-ADOM": "global"},
                    data={"kind": "cpu", "name": "from-global-" + adom,
                          "appliance_id": fleet[adom]})
    assert r.status_code == 200, r.get_data(as_text=True)

    login(client, admin_id, product=adom)
    d = client.get("/monitoring/deep/data", headers={"X-ADOM": adom}).get_json()
    assert "from-global-" + adom in {p["name"] for p in d["probes"]}


def test_a_probe_from_another_product_stays_invisible(client, admin_id, fleet):
    """The converse: the ADC ADOM must not inherit a FortiWeb probe."""
    login(client, admin_id, product="fortiadc")
    d = client.get("/monitoring/deep/data",
                   headers={"X-ADOM": "fortiadc"}).get_json()
    assert "fortiweb-cpu" not in {p["name"] for p in d["probes"]}
