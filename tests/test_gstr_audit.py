"""Directed guards for the Getting-started / Technical-reference fixes of the
Documentation Center audit (2026-10-03).

Each test fails on the code before the fix and passes after it.
"""
from __future__ import annotations

import importlib.util
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tests.conftest import admin_user_id, login, make_user, profile_id

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "deploy" / "self_update_runner.py"


def _keys_user(app, name, keys):
    from app.extensions import db
    from app.models import Profile, User
    with app.app_context():
        p = Profile(name=f"p-{name}", is_system=False)
        p.permission_set = set(keys)
        db.session.add(p)
        db.session.commit()
        u = User(username=name, role="readonly", is_active=True, profile_id=p.id)
        u.set_password("pw")
        db.session.add(u)
        db.session.commit()
        return u.id


def _appliance(app, kind="fortiweb", name="fw1"):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name=name, kind=kind, host="192.0.2.99", port=443,
                      username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a)
        db.session.commit()
        return a.id


# --------------------------------------------------------------------------
# Notifications: "Clear all"
# --------------------------------------------------------------------------
def test_the_notifications_page_offers_clear_all_and_it_clears(app, client):
    from app.models_notifications import Notification
    from app.services import notifications as notify
    uid = admin_user_id(app)
    login(client, uid)
    with app.app_context():
        notify.push(uid, "job finished", product="fortiweb")
    html = client.get("/notifications/").get_data(as_text=True)
    assert 'action="/notifications/clear"' in html
    assert 'name="csrf_token"' in html
    assert "data-confirm=" in html and "Clear all" in html
    r = client.post("/notifications/clear")
    assert r.status_code in (302, 303)
    with app.app_context():
        assert Notification.query.filter_by(user_id=uid).count() == 0
    # Nothing to clear -> no button.
    assert 'action="/notifications/clear"' not in client.get("/notifications/").get_data(as_text=True)


# --------------------------------------------------------------------------
# Top bar: the "/" the search button advertises works on every page
# --------------------------------------------------------------------------
def test_the_slash_shortcut_is_global_not_only_on_the_search_page(app, client):
    login(client, admin_user_id(app), product="global")
    html = client.get("/notifications/").get_data(as_text=True)
    assert 'id="fwTopbarSearch"' in html
    assert "__fwSlashSearch" in html
    assert "getElementById('fwTopbarSearch')" in html


# --------------------------------------------------------------------------
# Infra card: no internal host names, the right settings path
# --------------------------------------------------------------------------
def test_the_infra_card_names_no_internal_hosts_and_the_real_settings_path(app, client):
    login(client, admin_user_id(app), product="global")
    html = client.get("/").get_data(as_text=True)
    assert "Infrastructure health" in html  # the partial was rendered
    assert "backup-server" not in html
    assert "Gitea" not in html
    assert "SoT &amp; Backup" not in html
    assert "Source of Truth \\u0026 Backup" in html or "Source of Truth & Backup" in html
    assert "#tab-backupsrv" in html


# --------------------------------------------------------------------------
# Sidebar: Appliances is reachable by appliances.view holders
# --------------------------------------------------------------------------
@pytest.mark.parametrize("adom", ["fortiweb", "global", "fortiadc"])
def test_operator_sees_the_appliances_entry(app, client, adom):
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, op, product=adom)
    html = client.get("/notifications/?_adom=%s" % adom).get_data(as_text=True)
    assert 'href="/appliances/"' in html
    assert client.get("/appliances/").status_code == 200


def test_the_appliances_entry_needs_appliances_view(app, client):
    uid = _keys_user(app, "noapp", {"registry.view"})
    login(client, uid, product="fortiweb")
    html = client.get("/notifications/").get_data(as_text=True)
    assert 'href="/appliances/"' not in html


# --------------------------------------------------------------------------
# Concept Map: Global-only pages are linked into the Global ADOM
# --------------------------------------------------------------------------
def test_the_map_links_global_only_pages_into_the_global_adom(app, client):
    login(client, admin_user_id(app), product="fortiweb")
    data = client.get("/map/data").get_json()
    hrefs = {p["endpoint"]: p["href"] for c in data["clusters"] for p in c["pages"]}
    href = hrefs["monitoring.satom"]
    assert "_adom=global" in href
    assert "_adom" not in hrefs["monitoring.index"]
    # Followed from the product ADOM, it opens instead of bouncing.
    r = client.get(href)
    assert r.status_code == 200


# --------------------------------------------------------------------------
# Profile: GET only
# --------------------------------------------------------------------------
def test_profile_is_get_only(app, client):
    login(client, admin_user_id(app))
    assert client.post("/auth/profile", data={}).status_code == 405


# --------------------------------------------------------------------------
# Internal proxy: raw writes need registry.execute_write
# --------------------------------------------------------------------------
class _Resp:
    status_code = 200
    headers = {"content-type": "application/json"}
    content = b"{}"

    def json(self):
        return {"ok": True}


class _Client:
    calls: list = []

    def api_call(self, method, path, body):
        _Client.calls.append((method, path))
        return _Resp()


@pytest.mark.parametrize("prefix", ["fw", "adc"])
def test_proxy_writes_need_registry_execute_write(app, client, monkeypatch, prefix):
    import app.api.proxy as proxy
    from app.models import AuditLog
    monkeypatch.setattr(proxy, "client_for", lambda a: _Client())
    _Client.calls = []
    aid = _appliance(app, kind="fortiweb" if prefix == "fw" else "fortiadc")
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, op, product="global")
    with app.app_context():
        from app.models import User
        from app.extensions import db
        u = db.session.get(User, op)
        assert u.can("config_write") and not u.can("registry.execute_write")
    r = client.post(f"/api/{prefix}/{aid}/proxy/cmdb/x", json={"a": 1})
    assert r.status_code == 403
    assert _Client.calls == []
    # Positive control: the key holder reaches the device and is audited.
    login(client, admin_user_id(app), product="global")
    r = client.post(f"/api/{prefix}/{aid}/proxy/cmdb/x", json={"a": 1})
    assert r.status_code == 200
    assert _Client.calls == [("POST", "/cmdb/x")]
    with app.app_context():
        assert AuditLog.query.filter(AuditLog.action == f"api.proxy.{prefix}").count() == 1


# --------------------------------------------------------------------------
# Scheduled actions: "missed" badge, "running" from the lease
# --------------------------------------------------------------------------
def test_scheduled_actions_show_missed_and_running(app, client):
    from app.models import ScheduledAction, db
    with app.app_context():
        for name, status, running in (("MISSED-ROW", "missed", None),
                                      ("RUNNING-ROW", "ok", datetime.utcnow())):
            db.session.add(ScheduledAction(
                name=name, scope="admin", product="fortiweb", action="device_sync",
                targets="[]", params="{}", schedule_kind="interval",
                schedule=json.dumps({"every": 60, "unit": "minutes"}), enabled=True,
                next_run=datetime.utcnow() + timedelta(hours=1),
                last_status=status, running_at=running))
        db.session.commit()
    login(client, admin_user_id(app), product="fortiweb")
    html = client.get("/scheduled-actions/").get_data(as_text=True)
    assert "MISSED-ROW" in html and "RUNNING-ROW" in html
    missed_row = html[html.index("MISSED-ROW"):html.index("MISSED-ROW") + 4000]
    assert "fw-badge-warning" in missed_row and ">missed<" in missed_row
    running_row = html[html.index("RUNNING-ROW"):html.index("RUNNING-ROW") + 4000]
    assert ">running<" in running_row


# --------------------------------------------------------------------------
# Change requests: approve only drafts, never cancel a closed one
# --------------------------------------------------------------------------
def _cr(app, status):
    from app.models import ChangeRequest, db
    with app.app_context():
        cr = ChangeRequest(title="CR-%s" % status, status=status, action="upgrade")
        db.session.add(cr)
        db.session.commit()
        return cr.id


@pytest.mark.parametrize("status", ["completed", "failed", "cancelled", "approved"])
def test_a_non_draft_change_request_cannot_be_approved(app, status):
    from app.models import ChangeRequest, db
    from app.services import change_requests as svc
    cid = _cr(app, status)
    with app.app_context():
        with pytest.raises(ValueError):
            svc.approve(cid, by="admin")
        assert db.session.get(ChangeRequest, cid).status == status


def test_a_draft_is_still_approved(app):
    from app.models import ChangeRequest, db
    from app.services import change_requests as svc
    cid = _cr(app, "draft")
    with app.app_context():
        svc.approve(cid, by="admin")
        assert db.session.get(ChangeRequest, cid).status == "approved"


@pytest.mark.parametrize("status", ["completed", "failed", "cancelled"])
def test_a_closed_change_request_cannot_be_cancelled(app, status):
    from app.models import ChangeRequest, db
    from app.services import change_requests as svc
    cid = _cr(app, status)
    with app.app_context():
        with pytest.raises(ValueError):
            svc.cancel(cid, by="admin")
        assert db.session.get(ChangeRequest, cid).status == status


@pytest.mark.parametrize("status", ["draft", "approved", "in_progress"])
def test_an_open_change_request_is_still_cancellable(app, status):
    from app.models import ChangeRequest, db
    from app.services import change_requests as svc
    cid = _cr(app, status)
    with app.app_context():
        svc.cancel(cid, by="admin")
        assert db.session.get(ChangeRequest, cid).status == "cancelled"


# --------------------------------------------------------------------------
# Postgres SSL: the unprivileged web hands the change to the root runner
# --------------------------------------------------------------------------
def test_pg_ssl_is_queued_for_the_root_runner_when_not_root(app, monkeypatch, tmp_path):
    from app.services import pg_ssl, self_update as su
    monkeypatch.setattr(su, "REQ_DIR", tmp_path / "req")
    monkeypatch.setattr(su, "STATUS_DIR", tmp_path / "sta")
    monkeypatch.setattr(pg_ssl, "_is_root", lambda: False)

    def _boom(*a, **k):
        raise AssertionError("the web process must not run psql itself")
    monkeypatch.setattr(pg_ssl, "_psql_as_postgres", _boom)
    with app.app_context():
        res = pg_ssl.apply_policy("TLSv1.3", "ECDHE+AESGCM:!aNULL", by="admin")
    assert res["queued"]
    req = json.loads((tmp_path / "req" / (res["queued"] + ".json")).read_text())
    assert req["kind"] == "pg_ssl"
    assert req["min_protocol"] == "TLSv1.3" and req["ciphers"] == "ECDHE+AESGCM:!aNULL"
    assert (tmp_path / "sta" / (res["queued"] + ".json")).exists()


def test_pg_ssl_as_root_still_applies_directly(app, monkeypatch, tmp_path):
    from app.services import pg_ssl, self_update as su
    monkeypatch.setattr(su, "REQ_DIR", tmp_path / "req")
    monkeypatch.setattr(pg_ssl, "_is_root", lambda: True)
    seen = []
    monkeypatch.setattr(pg_ssl, "_psql_as_postgres", lambda sql: seen.append(sql))
    with app.app_context():
        res = pg_ssl.apply_policy("TLSv1.2", "", by="admin")
    assert res["queued"] is None and seen
    assert not (tmp_path / "req").exists()


def _load_runner(app_dir: Path):
    os.environ["FM_APP_DIR"] = str(app_dir)
    spec = importlib.util.spec_from_file_location("_satom_runner_gstr", RUNNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_root_runner_applies_a_valid_pg_ssl_request(tmp_path, monkeypatch):
    runner = _load_runner(tmp_path)
    monkeypatch.setattr(runner, "STA", tmp_path / "sta")
    calls = []

    class _P:
        returncode = 0
        stdout = "ALTER SYSTEM"
        stderr = ""

    def _run(argv, **kw):
        calls.append((argv, Path(argv[-1]).read_text()))
        return _P()
    monkeypatch.setattr(runner.subprocess, "run", _run)
    rp = tmp_path / "r1.json"
    rp.write_text(json.dumps({"id": "r1", "kind": "pg_ssl", "min_protocol": "TLSv1.3",
                              "ciphers": "HIGH:!aNULL", "requested_by": "admin"}))
    monkeypatch.setattr(runner, "REQ", tmp_path)
    runner.main()
    assert not rp.exists()
    st = json.loads((tmp_path / "sta" / "r1.json").read_text())
    assert st["state"] == "success", st
    assert calls and calls[0][0][:4] == ["runuser", "-u", "postgres", "--"]
    assert "ssl_min_protocol_version = 'TLSv1.3'" in calls[0][1]
    assert "ssl_ciphers = 'HIGH:!aNULL'" in calls[0][1]


def test_the_root_runner_refuses_a_hostile_cipher_string(tmp_path, monkeypatch):
    runner = _load_runner(tmp_path)
    monkeypatch.setattr(runner, "STA", tmp_path / "sta")
    monkeypatch.setattr(runner.subprocess, "run",
                        lambda *a, **k: pytest.fail("must not reach psql"))
    rp = tmp_path / "r2.json"
    rp.write_text(json.dumps({"id": "r2", "kind": "pg_ssl", "min_protocol": "TLSv1.2",
                              "ciphers": "x'; DROP TABLE users; --"}))
    runner.pg_ssl_apply(str(rp))
    st = json.loads((tmp_path / "sta" / "r2.json").read_text())
    assert st["state"] == "failed"
