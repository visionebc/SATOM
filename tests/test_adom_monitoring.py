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


# --------------------------------------------------------------------------
# 4. manager self-health is GLOBAL-only (2026-07-28)
#
# Fleet health used to render the Infrastructure health + Encryption sections
# (HA peers, Gitea, the backup-server server, the local DB and systemd units) in
# every ADOM. Those describe the SATOM installation, not a product, and they
# leak node names and infrastructure IPs into a product view. The template is
# NOT the enforcement point -- the JSON endpoints refuse too.
# --------------------------------------------------------------------------

MANAGER_ONLY_KEYS = ("system", "services", "db", "redundancy")


@pytest.mark.parametrize("adom", ADOMS)
@pytest.mark.parametrize("path", ["/monitoring/infra", "/monitoring/encryption"])
def test_manager_infra_endpoints_refuse_inside_an_adom(client, admin_id, adom, path):
    login(client, admin_id, product=adom)
    r = client.get(path, headers={"X-ADOM": adom})
    assert r.status_code == 403, f"{adom} {path} -> {r.status_code}"


@pytest.mark.parametrize("path", ["/monitoring/infra", "/monitoring/encryption"])
def test_manager_infra_endpoints_answer_in_global(client, admin_id, path):
    login(client, admin_id, product="global")
    r = client.get(path, headers={"X-ADOM": "global"})
    assert r.status_code == 200


@pytest.mark.parametrize("adom", ADOMS)
def test_fleet_health_payload_drops_manager_keys_in_an_adom(client, admin_id,
                                                            fleet, adom):
    login(client, admin_id, product=adom)
    d = client.get("/monitoring/data", headers={"X-ADOM": adom}).get_json()
    assert d["scope"] == adom
    for k in MANAGER_ONLY_KEYS:
        assert k not in d, f"{adom} payload still carries {k}"
    assert d["devices"], "device cards must still render in an ADOM"


def test_fleet_health_payload_keeps_manager_keys_in_global(client, admin_id, fleet):
    login(client, admin_id, product="global")
    d = client.get("/monitoring/data", headers={"X-ADOM": "global"}).get_json()
    assert d["scope"] == "global"
    for k in MANAGER_ONLY_KEYS:
        assert k in d, f"global payload lost {k}"


@pytest.mark.parametrize("adom", ADOMS)
def test_fleet_health_page_hides_manager_sections_in_an_adom(client, admin_id, adom):
    login(client, admin_id, product=adom)
    body = client.get("/monitoring/", headers={"X-ADOM": adom}).get_data(as_text=True)
    assert "Infrastructure health" not in body
    assert "Encryption in transit" not in body
    assert 'id="monDevices"' in body          # the device grid still renders


def test_fleet_health_page_keeps_manager_sections_in_global(client, admin_id):
    login(client, admin_id, product="global")
    body = client.get("/monitoring/",
                      headers={"X-ADOM": "global"}).get_data(as_text=True)
    assert "Infrastructure health" in body
    assert "Encryption in transit" in body


# --------------------------------------------------------------------------
# 5. fleet-wide ACTIONS respect the ADOM too
#
# Both of these default to "everything" when the operator selects nothing, and
# both then open an SSH session per device. Unscoped, "Scan hardware" from the
# FortiWeb ADOM logs into the FortiADC and FortiAnalyzer boxes.
# --------------------------------------------------------------------------

def _capture_job(monkeypatch, module):
    """Record the job meta and never start the worker thread."""
    captured = {}
    real = module.jobsvc.create_job

    def fake(type_, title, **kw):
        captured["meta"] = kw.get("meta")
        return real(type_, title, **kw)

    monkeypatch.setattr(module.jobsvc, "create_job", fake)
    monkeypatch.setattr(module.jobsvc, "run_async", lambda *a, **k: None)
    return captured


@pytest.mark.parametrize("adom", ADOMS)
def test_hardware_scan_targets_only_this_adom(client, admin_id, fleet, adom,
                                              monkeypatch):
    from app.views import monitoring as mon
    captured = _capture_job(monkeypatch, mon)
    login(client, admin_id, product=adom)
    r = client.post("/monitoring/hw-scan", headers={"X-ADOM": adom})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert captured["meta"]["ids"] == [fleet[adom]]


def test_hardware_scan_covers_the_fleet_in_global(client, admin_id, fleet,
                                                  monkeypatch):
    from app.views import monitoring as mon
    captured = _capture_job(monkeypatch, mon)
    login(client, admin_id, product="global")
    r = client.post("/monitoring/hw-scan", headers={"X-ADOM": "global"})
    assert r.status_code == 200
    assert set(captured["meta"]["ids"]) >= set(fleet.values())


@pytest.mark.parametrize("adom", ADOMS)
def test_probe_now_without_a_selection_stays_inside_the_adom(
        client, admin_id, fleet, adom, monkeypatch, app):
    from app.views import deep_monitor as dmv
    from app.models import MonitorProbe
    captured = _capture_job(monkeypatch, dmv)
    login(client, admin_id, product=adom)
    r = client.post("/monitoring/deep/run", headers={"X-ADOM": adom})
    assert r.status_code == 200, r.get_data(as_text=True)
    ids = captured["meta"]["ids"]
    assert ids and ids != "all"
    with app.app_context():
        kinds = {MonitorProbe.query.get(i).appliance.kind for i in ids}
    assert kinds == {adom}, f"{adom} would have probed {kinds}"


def test_probe_now_in_global_still_means_every_due_probe(client, admin_id, fleet,
                                                         monkeypatch):
    """Global keeps ids=None so the scheduler's due/force semantics are intact."""
    from app.views import deep_monitor as dmv
    captured = _capture_job(monkeypatch, dmv)
    login(client, admin_id, product="global")
    r = client.post("/monitoring/deep/run", headers={"X-ADOM": "global"})
    assert r.status_code == 200
    assert captured["meta"]["ids"] == "all"
