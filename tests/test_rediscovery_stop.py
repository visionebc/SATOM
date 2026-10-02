"""Stop on the Discovery / Rediscovery page.

The properties that make a Stop safe rather than merely present:

* it reaches the sweep across gunicorn workers (a file flag, not a variable);
* a stopped sweep writes NO snapshot, so the last complete one survives —
  inventory, API matrix and library are all derived from ``_config.json``;
* it cannot leak into the next run, and it closes a ghost ``running`` whose
  worker is already gone instead of waiting forever for it to notice.

No device is contacted: the probe and the firmware read are replaced.
"""
from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from app.extensions import db
from app.models import Appliance
from app.services import rediscovery

PLAN = [{"name": f"ep{i}", "urn": f"/api/v2.0/cmdb/x/ep{i}", "section": "System"}
        for i in range(6)]


@pytest.fixture(autouse=True)
def _private_stores(tmp_path, monkeypatch):
    monkeypatch.setenv("SATOM_JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("SATOM_REDISCOVERY_DIR", str(tmp_path / "rediscovery"))
    monkeypatch.setattr(rediscovery, "_device_firmware", lambda *a, **k: "7.6.8")
    monkeypatch.setattr(rediscovery, "_refresh_api_matrix", lambda *a, **k: None)
    monkeypatch.setattr(rediscovery, "_ingest_library", lambda *a, **k: {})
    monkeypatch.setattr(rediscovery, "_persist_firmware", lambda *a, **k: None)


def _snap(aid=41):
    return SimpleNamespace(id=aid, name="fw-stop", host="fw-stop.test", port=443,
                           verify_ssl=False, username="admin", password="x",
                           vdom="", kind="fortiweb")


def _probe_stopping_at(n, aid=41, seen=None):
    """Answer every endpoint; press Stop while endpoint ``n`` is in flight."""
    def _probe(client, ep):
        idx = int(ep["name"][2:])
        if seen is not None:
            seen.append(idx)
        if idx == n:
            rediscovery.request_stop(aid, by="op")
        return [{"name": ep["name"]}], rediscovery.VERDICT_OK, ""
    return _probe


def test_stop_ends_the_sweep_and_keeps_the_previous_snapshot(app, monkeypatch):
    aid = 41
    prev = rediscovery._dev_dir(aid) / "_config.json"
    prev.write_text(json.dumps({"generated_at": "earlier", "total_objects": 99}))
    seen = []
    monkeypatch.setattr(rediscovery, "_probe_fortiweb", _probe_stopping_at(2, aid, seen))
    rediscovery._write_json(rediscovery._dev_dir(aid) / "progress.json",
                            {"state": "running", "pid": os.getpid(),
                             "host": rediscovery._HOST})
    rediscovery._run(_snap(aid), by="t", plan=PLAN)

    assert seen == [0, 1, 2], "the endpoint after the Stop must not be read"
    st = rediscovery.status(aid)
    assert st["state"] == rediscovery.STOPPED
    assert st["stopped_by"] == "op"
    assert "No snapshot" in st["error"]
    assert json.loads(prev.read_text())["generated_at"] == "earlier", (
        "a stopped sweep overwrote the last complete snapshot with a partial one")
    assert not (rediscovery._dev_dir(aid) / rediscovery._STOP_FILE).exists()


def test_a_leftover_flag_does_not_stop_the_next_run(app, monkeypatch):
    with app.app_context():
        a = Appliance(name="fw-stop", kind="fortiweb", host="fw-stop.test",
                      port=443, username="admin", verify_ssl=False)
        a.password = "x"
        db.session.add(a)
        db.session.commit()
        rediscovery._write_json(rediscovery._dev_dir(a.id) / rediscovery._STOP_FILE,
                                {"by": "old"})
        monkeypatch.setattr(rediscovery, "plan_for", lambda _a: PLAN)
        monkeypatch.setattr(rediscovery, "_APP", None)   # restored after the test
        started = []
        monkeypatch.setattr(rediscovery.threading, "Thread",
                            lambda target, args, daemon, kwargs=None: SimpleNamespace(
                                start=lambda: started.append(args)))
        assert rediscovery.start(a)["started"] is True
        assert started
        assert not (rediscovery._dev_dir(a.id) / rediscovery._STOP_FILE).exists()


def test_stop_before_the_deep_pass_keeps_the_snapshot(app, monkeypatch):
    aid = 42
    monkeypatch.setattr(rediscovery, "_probe_fortiweb", _probe_stopping_at(5, aid))
    ran = []
    monkeypatch.setattr(rediscovery, "_run_deep", lambda *a, **k: ran.append(1))
    rediscovery._run(_snap(aid), by="t", deep=True, plan=PLAN)
    st = rediscovery.status(aid)
    assert st["state"] == rediscovery.STOPPED
    assert ran == [], "the deep pass ran after Stop"
    assert (rediscovery._dev_dir(aid) / "_config.json").exists()
    assert "snapshot was saved" in st["error"]


def test_stop_closes_a_ghost_run_whose_worker_is_gone(app):
    aid = 43
    rediscovery._write_json(rediscovery._dev_dir(aid) / "progress.json",
                            {"state": "running", "pid": 2 ** 22 + 7,
                             "host": rediscovery._HOST})
    res = rediscovery.request_stop(aid, by="op")
    assert res["stopped"] is True and res["pending"] is False
    assert rediscovery.status(aid)["state"] == rediscovery.STOPPED


def test_stop_refuses_a_run_owned_by_the_peer_node(app):
    aid = 44
    rediscovery._write_json(rediscovery._dev_dir(aid) / "progress.json",
                            {"state": "running", "pid": 1, "host": "the-other-node"})
    res = rediscovery.request_stop(aid, by="op")
    assert res["stopped"] is False
    assert rediscovery.status(aid)["state"] == "running"
    assert not (rediscovery._dev_dir(aid) / rediscovery._STOP_FILE).exists()


def test_stop_with_nothing_running_is_refused(app):
    assert rediscovery.request_stop(45)["stopped"] is False


def test_the_page_offers_stop_wired_to_the_route(app):
    from app.views import appliances  # noqa: F401 — route registered
    rules = {r.rule for r in app.url_map.iter_rules()}
    assert "/appliances/<int:id>/rediscover/stop" in rules
    src = open(os.path.join(app.root_path, "templates", "appliances",
                            "rediscover.html"), encoding="utf-8").read()
    assert 'id="redisc-stop"' in src
    assert 'url_for("appliances.rediscover_stop"' in src
    assert "'stopped'" in src
