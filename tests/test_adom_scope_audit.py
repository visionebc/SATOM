"""By-id routes and fleet reads that skipped the visibility boundary.

Documentation Center audit, 2026-10-03. Every list in the console is cut by
``visible_appliances()`` (maintenance devices hidden from whoever lacks
``appliances.view_maintenance``, other ADOMs hidden by the active ADOM) or by
``scope_query`` on a product column. These routes served the same rows one URL
away -- or wrote to them. Ids: FW-06, FW-19, FW-28, FW-34, FW-39, DV-19,
DV-21, DV-26, DV-42, DV-48, MO-11, MO-12, MO-13, MO-25, AU-19, AU-20, AU-21,
AU-24, TL-02, TL-03, TL-22, TL-24, TL-25, TL-26, TL-27, TL-28, TL-29, TR-09.

The probe is the seeded **operator**: it holds every write key these routes
need but not ``appliances.view_maintenance``, so a device in maintenance is
the "device you cannot see" without touching ADOM plumbing. Product-stamped
rows (plugins, Lua, firmware, registry) are probed from the FortiWeb ADOM
against a FortiADC row.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from conftest import admin_user_id, login, make_user, profile_id


def _dev(app, name, *, maintenance=False, kind="fortiweb"):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name=name, kind=kind, host="10.0.0.%d" % (50 + len(name)),
                      port=443, username="admin", verify_ssl=False,
                      maintenance=maintenance)
        a.password = "secret"
        db.session.add(a)
        db.session.commit()
        return a.id


@pytest.fixture()
def op(app, client):
    uid = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, uid)
    return uid


@pytest.fixture()
def devs(app):
    return {"seen": _dev(app, "seen-fw"), "hidden": _dev(app, "hidden-fw", maintenance=True)}


# --- FortiWeb ---------------------------------------------------------------

def test_fw06_a_carve_out_is_not_deletable_through_another_device(app, client, op, devs):
    from app.services import wpp_exceptions as s
    other = _dev(app, "other-fw")
    with app.app_context():
        exc = s.add(devs["seen"], wpp_mkey="wpp-x", exc_type="signature_filter_item",
                    payload={"signature_id": "010000001"})
        eid = exc.id
    r = client.post(f"/exceptions/{other}/guarded-delete",
                    json={"exc_id": eid, "acknowledge": True})
    assert r.status_code == 404
    with app.app_context():
        assert s.get(eid) is not None, "a carve-out was deleted through a foreign URL"


def test_fw06_a_carve_out_is_not_editable_through_another_device(app, client, op, devs):
    from app.services import wpp_exceptions as s
    other = _dev(app, "other-fw")
    with app.app_context():
        eid = s.add(devs["seen"], wpp_mkey="wpp-x", exc_type="signature_filter_item",
                    payload={"signature_id": "010000001"}).id
    r = client.post(f"/exceptions/{other}/save", json={
        "exc_id": eid, "exc_type": "signature_filter_item", "wpp_mkey": "wpp-x",
        "fields": {"signature_id": "010000002"}, "reason": "hijack"})
    assert r.status_code == 404


def test_fw19_template_apply_refuses_a_hidden_device(app, client, op, devs):
    from app.models import Template, db
    with app.app_context():
        t = Template(kind=Template.KIND_WEB_PROTECTION, name="t1", version=1,
                     body='{"endpoint":"x","mkey":"m","data":{}}',
                     status=Template.STATUS_APPROVED)
        db.session.add(t)
        db.session.commit()
        tid = t.id
    r = client.post(f"/templates/{tid}/apply",
                    data={"device_ids": [str(devs["hidden"])], "format": "json"})
    assert r.status_code == 404


def test_fw28_a_proposal_for_a_hidden_device_cannot_be_dismissed(app, client, op, devs):
    from app.models import db
    from app.models_advisor import AdvisorConversation, AdvisorProposal
    with app.app_context():
        conv = AdvisorConversation(username="op", title="t")
        db.session.add(conv)
        db.session.commit()
        p = AdvisorProposal(conversation_id=conv.id, kind="waf_exception", title="x",
                            payload="{}", rationale="", status="pending",
                            created_by="model", appliance_id=devs["hidden"])
        db.session.add(p)
        db.session.commit()
        pid = p.id
    assert client.post(f"/waf/attack-search/proposal/{pid}/dismiss").status_code == 404
    with app.app_context():
        assert AdvisorProposal.query.get(pid).status == "pending"


def _custom_admin(app, client, keys, product="fortiweb"):
    from app.extensions import db
    from app.models import Profile, User
    with app.app_context():
        p = Profile(name="noshow", is_system=False)
        p.permission_set = set(keys)
        db.session.add(p)
        db.session.commit()
        u = User(username="adm2", role="readonly", is_active=True, profile_id=p.id)
        u.set_password("pw")
        db.session.add(u)
        db.session.commit()
        uid = u.id
    login(client, uid, product=product)


def test_fw34_appids_never_offers_or_assigns_a_hidden_device(app, client, devs):
    # users.manage without appliances.view_maintenance
    _custom_admin(app, client, {"users.manage", "profiles.manage", "monitoring.view"})
    r = client.get("/web/appids/")
    page = r.get_data(as_text=True)
    assert r.status_code == 200 and "seen-fw" in page, "control: the picker renders"
    assert "hidden-fw" not in page
    r = client.post("/web/appids/assign", data={"app_id_pk": "1",
                                            "appliance_id": str(devs["hidden"]),
                                            "server_policy": "pol"})
    assert r.status_code == 404


def test_fw39_stored_assets_delete_stays_inside_the_adom(app, client, monkeypatch):
    from app.services import backup_server, device_identity

    class _M:
        def __init__(self, slug):
            self.slug = slug
    monkeypatch.setattr(device_identity, "chassis_groups",
                        lambda product="": [{"primary": _M("fw-a"), "rows": [_M("fw-a")]}])
    calls = []
    monkeypatch.setattr(backup_server, "delete_device_file",
                        lambda d, f: calls.append((d, f)) or {"ok": True, "detail": "x"})
    login(client, admin_user_id(app), product="fortiweb")
    r = client.post("/adom-assets/delete-backup?_adom=fortiweb",
                    data={"device": "adc-b", "filename": "c.conf", "confirm": "DELETE"})
    assert r.status_code == 404 and calls == []
    client.post("/adom-assets/delete-backup?_adom=fortiweb",
                data={"device": "fw-a", "filename": "c.conf", "confirm": "DELETE"})
    assert calls == [("fw-a", "c.conf")]


# --- Devices ----------------------------------------------------------------

def test_dv19_firmware_reports_hide_devices_out_of_sight(app, client, op, devs, monkeypatch):
    from app.services import flash_report as fr
    base = {"kind": "upgrade", "firmware_before": "7.4.1", "firmware_after": "7.4.2",
            "image": "", "by": "op", "downtime_s": 10, "backup": None,
            "reachable_after": True, "verdict": "ok", "service_changes": 0,
            "has_report": True}
    rows = [dict(base, job_id="j1", appliance="hidden-fw", appliance_id=devs["hidden"],
                 generated_at="2026-10-01"),
            dict(base, job_id="j2", appliance="seen-fw", appliance_id=devs["seen"],
                 generated_at="2026-10-02")]
    monkeypatch.setattr(fr, "list_reports", lambda appliance_id=None: list(rows))
    monkeypatch.setattr(fr, "report_meta", lambda jid: next(r for r in rows if r["job_id"] == jid))
    monkeypatch.setattr(fr, "read_report", lambda jid: "<html>report</html>")
    r = client.get("/appliances/flash-reports")
    page = r.get_data(as_text=True)
    assert r.status_code == 200 and "seen-fw" in page, "control: the list renders"
    assert "hidden-fw" not in page
    assert client.get("/appliances/flash-report/j1").status_code == 404
    assert client.get("/appliances/flash-report/j2").status_code == 200
    assert client.get(f"/appliances/flash-reports?appliance_id={devs['hidden']}").status_code == 404


def test_dv21_firmware_by_id_respects_the_adom(app, client):
    from app.models import db
    from app.models_firmware import FirmwareImage
    with app.app_context():
        img = FirmwareImage(product="fortiadc", version="7.4.0", image_kind="upgrade",
                            filename="adc.out", stored_path="/tmp/none-adc.out", size_bytes=1)
        db.session.add(img)
        db.session.commit()
        iid = img.id
    login(client, admin_user_id(app), product="fortiweb")
    assert client.post(f"/firmware/{iid}/delete?_adom=fortiweb").status_code == 404
    with app.app_context():
        assert FirmwareImage.query.get(iid) is not None


def test_dv26_rest_create_refuses_a_kind_from_another_adom(app, client, op):
    login(client, make_user(app, "op2", role="operator",
                            profile_id=profile_id(app, "operator")), product="fortiweb")
    r = client.post("/api/appliances?_adom=fortiweb",
                    json={"name": "x-adc", "kind": "fortiadc", "host": "192.0.2.9"})
    assert r.status_code == 400


def test_dv42_an_empty_id_list_is_no_device_not_every_device(app, devs):
    from app.services.bulk import BulkRunner
    with app.app_context():
        assert BulkRunner([])._appliances([]) == []


def test_dv42_baseline_matching_honours_the_visible_query(app, client, op, devs):
    from app.models import Appliance
    from app.services import baselines as B

    class _B:
        zone = line = department = ""
    with app.test_request_context():
        from flask_login import login_user
        from app.models import User, visible_appliances
        login_user(User.query.filter_by(username="op").one())
        names = {a.name for a in B.matching_devices(_B(), visible_appliances())}
    assert "hidden-fw" not in names and "seen-fw" in names


def test_dv48_waves_of_hidden_changes_are_not_listed(app, client, op, devs, monkeypatch):
    from app.models import db
    from app.models import ChangeRequest
    from app.views import upgrade_flow as uf
    with app.app_context():
        cr = ChangeRequest(title="w", wave_group="WAVE-SECRET-1", wave_total=2,
                           requested_by="x")
        db.session.add(cr)
        db.session.commit()
    r = client.get("/web/upgrade-flow/")
    assert r.status_code == 200 and "WAVE-SECRET-1" in r.get_data(as_text=True), \
        "control: a device-less wave is visible and rendered"
    monkeypatch.setattr(uf, "_visible_to_me", lambda cr: False)
    page = client.get("/web/upgrade-flow/").get_data(as_text=True)
    assert "WAVE-SECRET-1" not in page


# --- Monitoring -------------------------------------------------------------

def test_mo11_deep_reads_are_cut_to_visible_devices(app, client, op, devs, monkeypatch):
    from app.services import analysis_deep
    seen = {}
    monkeypatch.setattr(analysis_deep, "wpp_feature_matrix",
                        lambda device_ids=None: seen.setdefault("ids", device_ids) or {})
    client.get(f"/analysis/wpp-matrix?device_id={devs['hidden']}")
    assert seen["ids"] is not None and devs["hidden"] not in seen["ids"]
    seen.clear()
    client.get("/analysis/wpp-matrix")
    assert seen["ids"] == [devs["seen"]], "no filter must mean 'what I can see', not 'all'"


def test_mo12_deep_drilldowns_404_on_a_hidden_device(app, client, op, devs):
    assert client.get(f"/analysis/deep/wpp/{devs['hidden']}/w1").status_code == 404
    assert client.get(f"/analysis/deep/policy/{devs['hidden']}/p1").status_code == 404


def test_mo13_deep_run_never_captures_a_hidden_device(app, client, op, devs, monkeypatch):
    from app.services import deep_jobs
    started = []
    monkeypatch.setattr(deep_jobs, "start_fleet_job",
                        lambda app_, ids, **k: started.append(ids) or {"job_id": "x"})
    r = client.post("/analysis/deep/run", data={"device_id": str(devs["hidden"])})
    assert r.status_code == 400 and started == []


def test_mo25_log_history_and_files_hide_devices_out_of_sight(app, client, op, devs, monkeypatch):
    from app.services import logcollect
    files = [{"name": f"{devs['hidden']}_logs_x_1.txt", "device_id": str(devs["hidden"])},
             {"name": f"{devs['seen']}_logs_x_1.txt", "device_id": str(devs["seen"])}]
    monkeypatch.setattr(logcollect, "history", lambda: list(files))
    monkeypatch.setattr(logcollect, "read_log", lambda n: "log text")
    got = client.get("/logs/history").get_json()["files"]
    assert [f["device_id"] for f in got] == [str(devs["seen"])]
    assert client.get(f"/logs/file/{devs['hidden']}_logs_x_1.txt").status_code == 404
    assert client.get(f"/logs/file/{devs['seen']}_logs_x_1.txt").status_code == 200


# --- Automation -------------------------------------------------------------

def test_au19_au20_runs_follow_their_process_adom(app, client, op, monkeypatch):
    from app.models import db
    from app.models_process import Process, ProcessRun
    from app.views import process as pv
    with app.app_context():
        p = Process(key="adc-only", name="ADC only")
        db.session.add(p)
        db.session.commit()
        r = ProcessRun(process_id=p.id, process_key="adc-only", process_name="RUN-SECRET",
                       graph={}, status="done", verdict="ok")
        db.session.add(r)
        db.session.commit()
        rid = r.id
    monkeypatch.setattr(pv.engine, "may_run_here", lambda proc: False)
    monkeypatch.setattr(pv.engine, "visible_processes", lambda: [])
    assert client.get(f"/process/runs/{rid}").status_code == 404
    assert client.post(f"/process/runs/{rid}/resume", data={"answer": "y"}).status_code == 404
    assert "RUN-SECRET" not in client.get("/process/").get_data(as_text=True)


def test_au21_calendar_history_stays_in_the_adom(app, client):
    from app.models import ScheduledAction, ScheduledActionRun, db
    with app.app_context():
        a = ScheduledAction(name="ADC-ONLY-ACTION", action="device_sync", product="fortiadc",
                            schedule_kind="interval", enabled=True,
                            next_run=datetime.utcnow() + timedelta(hours=1))
        db.session.add(a)
        db.session.commit()
        db.session.add(ScheduledActionRun(action_id=a.id, status="ok", trigger="schedule",
                                          summary="", started_at=datetime.utcnow()))
        db.session.commit()
    login(client, admin_user_id(app), product="fortiweb")
    page = client.get("/calendar/?_adom=fortiweb").get_data(as_text=True)
    assert "ADC-ONLY-ACTION" not in page


def test_au24_a_lease_cannot_be_taken_on_a_hidden_device(app, client, op, devs):
    r = client.post("/api/locks/steal",
                    json={"appliance_id": devs["hidden"], "resource_key": "server_policy:p"})
    assert r.status_code == 404
    r = client.get(f"/api/locks/status?appliance_id={devs['hidden']}&resource_key=k")
    assert r.status_code == 404


# --- Tools ------------------------------------------------------------------

def _plugin(app, product, status="published"):
    from app.models import Plugin, db
    with app.app_context():
        p = Plugin(name="adc-view", slug=f"adc-view-{product}", status=status,
                   jinja="<p>x</p>", product=product)
        db.session.add(p)
        db.session.commit()
        return p.id, p.slug


def test_tl02_tl25_plugins_stay_in_their_adom(app, client):
    pid, slug = _plugin(app, "fortiadc")
    login(client, admin_user_id(app), product="fortiweb")
    assert client.get(f"/plugins/{pid}/edit?_adom=fortiweb").status_code == 404
    assert client.get(f"/plugins/view/{slug}?_adom=fortiweb").status_code == 404
    assert client.get(f"/plugins/{pid}/frame?_adom=fortiweb").status_code == 404


def test_tl03_the_plugin_frame_allows_no_external_images(app, client):
    pid, _ = _plugin(app, "fortiweb")
    login(client, admin_user_id(app), product="fortiweb")
    r = client.get(f"/plugins/{pid}/frame?_adom=fortiweb")
    assert r.status_code == 200
    csp = r.headers.get("Content-Security-Policy", "")
    assert "img-src data:;" in csp and "https:" not in csp


def test_tl22_tl24_datasets_are_cut_per_viewer(app, client, op, devs):
    from app.models import AuditLog, Profile, User, db
    from app.services import plugin_sandbox as sb
    with app.app_context():
        db.session.add(AuditLog(username="admin", action="secret.thing", target="t"))
        db.session.commit()
    with app.test_request_context():
        from flask_login import login_user
        login_user(User.query.filter_by(username="op").one())
        got = sb.load_datasets(["fleet_appliances"])["fleet_appliances"]["rows"]
        assert {r["name"] for r in got} == {"seen-fw"}
        assert sb.load_datasets(["audit_recent"])["audit_recent"]["rows"], \
            "control: audit.view sees the audit dataset"
    with app.app_context():
        p = Profile(name="noaudit", is_system=False)
        p.permission_set = {"monitoring.view"}
        db.session.add(p)
        db.session.commit()
        u = User(username="na", role="readonly", is_active=True, profile_id=p.id)
        u.set_password("pw")
        db.session.add(u)
        db.session.commit()
    with app.test_request_context():
        from flask_login import login_user
        login_user(User.query.filter_by(username="na").one())
        assert sb.load_datasets(["audit_recent"])["audit_recent"]["rows"] == []


def test_tl26_tl27_lua_stays_in_scope(app, client, devs):
    from app.models import LuaScript, db
    with app.app_context():
        s = LuaScript(name="adc", target="fortiadc", product="fortiadc", code="return true")
        db.session.add(s)
        db.session.commit()
        sid = s.id
    login(client, admin_user_id(app), product="fortiweb")
    assert client.get(f"/lua/{sid}/edit?_adom=fortiweb").status_code == 404
    # admin sees maintenance devices; another ADOM's device is the hidden one here
    adc = _dev(app, "adc-box", kind="fortiadc")
    r = client.post("/lua/save?_adom=fortiweb",
                    data={"name": "x", "target": "fortiweb", "code": "return true",
                          "appliance_id": str(adc)})
    assert r.status_code == 404


def test_tl28_tl29_sentinel_hides_incidents_of_hidden_devices(app, client, op, devs):
    from app.models_sentinel import SentinelIncident
    from app.models import db
    with app.app_context():
        inc = SentinelIncident(ref="INC-HID-1", status=SentinelIncident.STATUS_OPEN,
                               device="hidden-fw", policy="p", src_ip="185.10.20.30",
                               attack_family="sqli", severity="high", score=95,
                               src_trusted=False, waf_blocked=False, passed_count=1,
                               opened_at=datetime.utcnow())
        db.session.add(inc)
        db.session.commit()
        iid = inc.id
    data = client.get("/sentinel/data").get_json()
    assert all(i.get("device") != "hidden-fw" for i in data["incidents"])
    assert client.get(f"/sentinel/incident/{iid}").status_code == 404


# --- Registry ---------------------------------------------------------------

def test_tr09_registry_toggle_is_fortiweb_only(app, client):
    from app.models import RegistryEndpoint, db
    with app.app_context():
        row = RegistryEndpoint(product="fortiadc", api_version="v2", name="adc-x",
                               urn="/api/adc/x")
        db.session.add(row)
        db.session.commit()
        rid = row.id
    login(client, admin_user_id(app))
    assert client.post(f"/registry/toggle/{rid}").status_code == 404
    with app.app_context():
        assert RegistryEndpoint.query.get(rid).enabled is not False
