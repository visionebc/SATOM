"""Field reports SI-0004, SI-0005 and SI-0006 (2026-10-02 inbox).

* SI-0004 — the rediscovery page sat at 100 % saying "Deep capture (WPP +
  policy graph) running…" with no count, no current object, no percent. The
  deep walk now reports every server policy / WPP it starts, and the page and
  the job show "WPP 3/12: <name>".
* SI-0005 — job toasts can be minimised to one line and restored.
* SI-0006 — after a rediscovery, Device health still said "no cached
  configuration on this node" and "never harvested": the sweep never fed the
  local cache, and a fresh install seeds no harvest schedule. The sweep now
  ingests into the cache, and a signal with no schedule behind it says so,
  with the command.

No device is contacted.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from app.clients.fortiweb import FortiWebClient
from app.models import Appliance, ScheduledAction, db
from app.models_cache import SyncRun
from app.services import deep_capture, device_health as dh, rediscovery
from tests.test_deep_capture import FakeReader

ROOT = Path(__file__).resolve().parents[1]
STATUS = "/api/v2.0/system/status.systemstatus"
PLAN = [{"name": f"ep{i}", "urn": f"/api/v2.0/cmdb/x/ep{i}", "section": "System"}
        for i in range(3)]


# --- SI-0004: the deep walk says where it is --------------------------------

def _reader():
    return FakeReader({
        "cmdb/server-policy/policy": {"": [{"name": "pol-a"}, {"name": "pol-b"}]},
        "cmdb/waf/web-protection-profile.inline-protection":
            {"": [{"name": "wpp-1"}, {"name": "wpp-2"}, {"name": "wpp-3"}]},
        "cmdb/waf/web-protection-profile.offline-protection":
            {"": [{"name": "off-1"}]},
    })


def test_deep_walk_reports_every_object_with_its_place_in_the_list():
    ticks = []
    deep_capture.deep_sections(_reader(), progress=ticks.append)
    walked = [(t["phase"], t["index"], t["of"], t["current"]) for t in ticks
              if t["phase"] in ("server policy", "WPP", "offline WPP")]
    assert walked == [("server policy", 1, 2, "pol-a"), ("server policy", 2, 2, "pol-b"),
                      ("WPP", 1, 3, "wpp-1"), ("WPP", 2, 3, "wpp-2"),
                      ("WPP", 3, 3, "wpp-3"), ("offline WPP", 1, 1, "off-1")]
    # the total is known from the FIRST tick: 6 objects + the certificate step
    assert {t["total"] for t in ticks} == {7}
    assert ticks[0]["done"] == 0 and ticks[0]["policies"] == 2 and ticks[0]["wpps"] == 4
    assert [t["done"] for t in ticks] == sorted(t["done"] for t in ticks)
    assert ticks[-2]["phase"] == "certificates"
    assert ticks[-1] == {**ticks[-1], "phase": "done", "done": 7}


def test_a_broken_progress_callback_never_sinks_the_walk():
    def boom(_p):
        raise RuntimeError("ui gone")
    out = deep_capture.deep_sections(_reader(), progress=boom)
    assert len(out["Web Protection"]["web_protection_profile"]) == 4
    assert len(out["Server Policy"]["server_policy"]) == 2


def test_run_deep_writes_the_count_and_the_current_object_to_progress(app, monkeypatch, tmp_path):
    from app.services import device_sync
    monkeypatch.setattr(rediscovery, "_APP", app)
    seen = []
    pp = tmp_path / "progress.json"

    def fake_snapshot(appliance, progress=None, **kw):
        for p in [{"done": 0, "total": 3, "phase": "WPP", "index": 1, "of": 2,
                   "current": "wpp-1", "policies": 0, "wpps": 2},
                  {"done": 1, "total": 3, "phase": "WPP", "index": 2, "of": 2,
                   "current": "wpp-2", "policies": 0, "wpps": 2}]:
            progress(p)
            seen.append(json.loads(pp.read_text()))
        return {"total_objects": 2, "sections": {}}

    monkeypatch.setattr(device_sync, "deep_snapshot_from_device", fake_snapshot)
    monkeypatch.setattr(device_sync, "persist_deep_snapshot", lambda *a, **k: {})
    state = {"state": "done", "percent": 100}
    rediscovery._run_deep(SimpleNamespace(id=7, name="fw"), pp, state)

    assert seen[0]["state"] == "deep-running"
    assert (seen[1]["deep_done"], seen[1]["deep_total"], seen[1]["deep_percent"]) == (1, 3, 33)
    assert seen[1]["deep_current"] == "wpp-2"
    assert rediscovery.deep_line(seen[1]) == (
        "Deep capture 1/3 · 0 server policies, 2 WPPs · WPP 2/2: wpp-2")
    # the sweep's own percent is left alone: 'done' must still paint 100 %
    assert state["percent"] == 100 and state["state"] == "done"


def test_deep_line_before_the_lists_are_read_does_not_just_say_running():
    assert "listing" in rediscovery.deep_line({"deep_total": 0})


def test_job_mirror_carries_the_deep_percent_and_line(monkeypatch):
    from app.services import jobs
    got = {}
    monkeypatch.setattr(jobs, "set_progress",
                        lambda jid, pct, msg: got.update(pct=pct, msg=msg))
    rediscovery._mirror_job({"job_id": "j1", "state": "deep-running", "percent": 100,
                             "deep_total": 4, "deep_done": 1, "deep_percent": 25,
                             "deep_phase": "server policy", "deep_index": 2,
                             "deep_of": 2, "deep_current": "pol-b",
                             "deep_policies": 2, "deep_wpps": 1})
    assert got["pct"] == 25
    assert got["msg"].endswith("server policy 2/2: pol-b")


def test_rediscover_page_paints_the_deep_count():
    html = (ROOT / "app/templates/appliances/rediscover.html").read_text()
    assert "function deepLine(p)" in html
    assert "p.deep_percent" in html and "p.deep_current" in html
    assert "Deep capture (WPP + policy graph) running…" not in html


# --- SI-0006: a rediscovery fills the cache Device health reads -------------

@pytest.fixture()
def _stores(tmp_path, monkeypatch):
    monkeypatch.setenv("SATOM_JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("SATOM_REDISCOVERY_DIR", str(tmp_path / "rediscovery"))
    monkeypatch.setenv("FORTINET_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("SATOM_SOT_DIR", str(tmp_path / "sot"))
    monkeypatch.setattr(rediscovery, "_refresh_api_matrix", lambda *a, **k: None)
    monkeypatch.setattr(rediscovery, "_ingest_library", lambda *a, **k: {})
    monkeypatch.setattr(rediscovery, "_persist_firmware", lambda *a, **k: None)
    from app.registry import loader
    monkeypatch.setattr(loader, "version_of", lambda *_a, **_k: "7.6.8")

    def _request(self, method, path, **kwargs):
        if path == STATUS:
            return httpx.Response(200, json={"results": {"firmwareVersion": "7.6.8"}})
        return httpx.Response(200, json={"results": [{"name": path.rsplit("/", 1)[-1]}]})
    monkeypatch.setattr(FortiWebClient, "_request", _request)


@pytest.fixture()
def dev(app):
    with app.app_context():
        a = Appliance(name="fw-si6", host="fw-si6.test", kind="fortiweb", username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        return a.id


def _snap(aid):
    return SimpleNamespace(id=aid, name="fw-si6", host="fw-si6.test", port=443,
                           verify_ssl=False, username="admin", password="x",
                           vdom="", kind="fortiweb")


def test_a_rediscovery_is_recorded_as_a_harvest_and_fills_the_cache(app, dev, _stores):
    with app.app_context():
        rediscovery._run(_snap(dev), by="t", plan=PLAN)
        assert rediscovery.status(dev)["state"] == "done"
        assert "cache_error" not in rediscovery.status(dev)
        run = SyncRun.query.filter_by(appliance_id=dev).one()
        assert (run.status, run.trigger) == ("ok", "rediscovery")
        a = db.session.get(Appliance, dev)
        assert dh.cache_meta(a).get("cached")
        assert dh.sync_signal(dev)["status"] == "ok"


def test_the_cache_copy_carries_only_harvest_keys(app, dev, _stores, monkeypatch):
    from app.services import device_sync
    got = {}
    monkeypatch.setattr(device_sync, "persist_snapshot",
                        lambda ap, snap, **kw: got.update(snap=snap, kw=kw)
                        or SimpleNamespace(status="ok", detail=""))
    with app.app_context():
        rediscovery._run(_snap(dev), by="t", plan=PLAN)
    assert set(got["snap"]) == set(rediscovery._HARVEST_KEYS)
    assert got["kw"]["trigger"] == "rediscovery"


def test_a_cache_failure_is_reported_but_the_sweep_is_still_done(app, dev, _stores, monkeypatch):
    from app.services import device_sync

    def boom(*a, **k):
        raise RuntimeError("db gone")
    monkeypatch.setattr(device_sync, "persist_snapshot", boom)
    with app.app_context():
        rediscovery._run(_snap(dev), by="t", plan=PLAN)
        st = rediscovery.status(dev)
    assert st["state"] == "done"
    assert "db gone" in st["cache_error"]
    assert (rediscovery._dev_dir(dev) / "_config.json").exists()


def test_trigger_label_fits_its_column():
    assert len("rediscovery") <= SyncRun.trigger.type.length


# --- SI-0006: say WHY there is nothing --------------------------------------

def _sched(action, targets="[]", enabled=True):
    db.session.add(ScheduledAction(name=action, action=action, targets=targets,
                                   enabled=enabled, schedule_kind="interval",
                                   schedule='{"every": 60, "unit": "minutes"}'))
    db.session.commit()


def test_no_schedule_on_the_node_is_named_with_the_command(app, dev):
    with app.app_context():
        a = db.session.get(Appliance, dev)
        out = dh.collect(a, caps=[], meta={}, hours=6)
        sync = out["signals"]["sync"]
        assert sync["no_schedule"] == "device_sync"
        assert "never harvested" in sync["text"]
        assert dh.SEED_HINT in sync["text"]
        assert out["signals"]["cache"]["no_schedule"] == "device_sync"


def test_a_fleet_schedule_removes_the_hint(app, dev):
    with app.app_context():
        _sched("device_sync")
        a = db.session.get(Appliance, dev)
        out = dh.collect(a, caps=[], meta={}, hours=6)
        assert "no_schedule" not in out["signals"]["sync"]
        assert dh.SEED_HINT not in out["signals"]["sync"]["text"]


def test_a_disabled_or_other_device_schedule_does_not_count(app, dev):
    with app.app_context():
        _sched("device_sync", enabled=False)
        _sched("device_sync", targets=json.dumps([dev + 1000]))
        assert dh.has_schedule("device_sync", dev) is False
        _sched("device_sync", targets=json.dumps([dev]))
        assert dh.has_schedule("device_sync", dev) is True


def test_monitoring_hardware_note_names_the_button():
    html = (ROOT / "app/templates/monitoring/index.html").read_text()
    assert "Scan hardware (SSH)” above" in html


# --- SI-0005: minimise / restore a job toast ---------------------------------

def test_job_toasts_can_be_minimised_and_restored():
    js = (ROOT / "app/static/js/jobs.js").read_text()
    assert 'class="jt-min"' in js
    assert "function setMin(key, on)" in js
    assert ".job-toast.min .jt-msg,.job-toast.min .jt-stop{display:none}" in js
    # the state survives a reload, and a dismissed toast forgets it
    assert "sessionStorage.setItem(MIN_KEY" in js
    assert "if (minSet()[key]) setMin(key, true);" in js
    body = js[js.index("function removeToast(key)"):]
    assert "saveMin(key, false)" in body[:300]
    # restoring is one click on the button or on the title
    assert "setMin(key, !el.classList.contains('min'))" in js
    assert "if (el.classList.contains('min')) setMin(key, false);" in js
