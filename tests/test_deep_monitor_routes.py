"""Deep monitors — route contract.

Renders the real page and exercises the JSON feeds against the test app, so the
template, the blueprint wiring and the permission gates are verified without a
live appliance (all four were down when this shipped).
"""
from __future__ import annotations

import pytest

from app.models import MonitorProbe, MonitorSample, User, db
from tests.conftest import login


@pytest.fixture()
def admin_id(app):
    with app.app_context():
        u = User.query.filter_by(role="admin").first()
        if u is None:
            u = User(username="dmadmin", role="admin", is_active=True)
            u.set_password("x" * 12)
            db.session.add(u)
            db.session.commit()
        return u.id


@pytest.fixture()
def viewer_id(app):
    with app.app_context():
        u = User.query.filter_by(username="dmviewer").first()
        if u is None:
            u = User(username="dmviewer", role="readonly", is_active=True)
            u.set_password("x" * 12)
            db.session.add(u)
            db.session.commit()
        return u.id


def test_page_renders(client, admin_id):
    login(client, admin_id, product="global")
    r = client.get("/monitoring/deep/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Deep monitors" in body
    # the three families must be offered in the editor
    assert "proxyd process" in body
    assert "Interface IP / link" in body


def test_data_feed_shape(client, admin_id):
    login(client, admin_id, product="global")
    d = client.get("/monitoring/deep/data").get_json()
    assert set(d) >= {"probes", "summary", "worst", "kinds", "devices"}
    assert [k["key"] for k in d["kinds"]] == ["https", "interface", "proxyd"]


def test_create_validates_kind_requirements(client, admin_id):
    login(client, admin_id, product="global")
    r = client.post("/monitoring/deep/probe",
                    data={"kind": "https", "name": "no url"})
    assert r.status_code == 400 and "URL" in r.get_json()["error"]
    r = client.post("/monitoring/deep/probe",
                    data={"kind": "proxyd", "name": "no device"})
    assert r.status_code == 400 and "device" in r.get_json()["error"]


def test_create_toggle_delete_roundtrip(client, admin_id, app):
    login(client, admin_id, product="global")
    r = client.post("/monitoring/deep/probe",
                    data={"kind": "https", "name": "vip", "url": "https://192.0.2.9/"})
    assert r.status_code == 200
    pid = r.get_json()["probe"]["id"]

    # a probe that has never run must read 'unknown', never 'ok'
    d = client.get("/monitoring/deep/data").get_json()
    row = [p for p in d["probes"] if p["id"] == pid][0]
    assert row["status"] == "unknown"

    assert client.post(f"/monitoring/deep/probe/{pid}/toggle").get_json()["enabled"] is False
    assert client.post(f"/monitoring/deep/probe/{pid}/delete").get_json()["ok"] is True
    with app.app_context():
        assert MonitorProbe.query.get(pid) is None


def test_readonly_user_cannot_mutate(client, viewer_id):
    login(client, viewer_id, product="global")
    assert client.get("/monitoring/deep/data").status_code == 200
    r = client.post("/monitoring/deep/probe",
                    data={"kind": "https", "name": "x", "url": "https://1.1.1.1/"})
    assert r.status_code in (302, 403)


def test_samples_cascade_and_prune(app, admin_id):
    """Deleting a probe takes its history with it, and retention is enforced."""
    from app.services import deep_monitor as dm
    with app.app_context():
        p = MonitorProbe(kind="https", name="prune", url="https://1.2.3.4/",
                         retention=5)
        db.session.add(p)
        db.session.commit()
        for i in range(12):
            db.session.add(MonitorSample(probe_id=p.id, status="ok", ok=True,
                                         value_num=i))
        db.session.commit()
        removed = dm.prune(p.id, keep=5)
        db.session.commit()
        assert removed == 7
        assert MonitorSample.query.filter_by(probe_id=p.id).count() == 5

        db.session.delete(p)
        db.session.commit()
        assert MonitorSample.query.filter_by(probe_id=p.id).count() == 0


def test_policy_discovery_dedupes_layers_and_resolves_the_vip(app):
    """Cache-first resolution: policy -> vserver -> VIP -> URL, with the
    config/deep duplicate rows collapsed. Shapes copied from fw6's real cache."""
    from app.models import Appliance
    from app.models_cache import DeviceObject, DeviceServerPolicy
    from app.services import deep_monitor as dm

    with app.app_context():
        a = Appliance(name="fwtest", host="192.0.2.9", kind="fortiweb", username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()

        vip = DeviceObject(
            appliance_id=a.id, layer="config", section="system",
            logical_name="vip", mkey="vip-shop", depth=0,
            payload={"name": "vip-shop", "vip": "192.0.2.90/32",
                     "interface": "port1",
                     "q_ref_string": "vserver(vs-shop) --> vip-list(1)\n"})
        db.session.add(vip)
        db.session.commit()

        # the SAME policy harvested twice (config + deep) — as fw6 really stores it
        for layer in ("config", "deep"):
            o = DeviceObject(appliance_id=a.id, layer=layer, section="policy",
                             logical_name="server_policy", mkey="pol-shop", depth=0,
                             payload={})
            db.session.add(o)
            db.session.flush()
            db.session.add(DeviceServerPolicy(
                object_id=o.id, appliance_id=a.id, name="pol-shop",
                vserver="vs-shop", https_service="HTTPS", status="enable"))
        db.session.commit()

        targets = dm.resolve_targets_from_cache(a)
        assert len(targets) == 1, "config+deep rows must collapse to one target"
        assert targets[0]["url"] == "https://192.0.2.90/"
        assert targets[0]["enabled"] is True

        res = dm.discover_https_probes(a)
        assert res == {"created": 1, "skipped": 0, "total_targets": 1}
        # idempotent
        assert dm.discover_https_probes(a)["created"] == 0


def test_policy_discovery_skips_a_vserver_with_no_vip(app):
    """No resolvable address must yield NO probe — never a probe pointed at a
    guess."""
    from app.models import Appliance
    from app.models_cache import DeviceObject, DeviceServerPolicy
    from app.services import deep_monitor as dm

    with app.app_context():
        a = Appliance(name="fwtest2", host="192.0.2.8", kind="fortiweb", username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        o = DeviceObject(appliance_id=a.id, layer="config", section="policy",
                         logical_name="server_policy", mkey="orphan", depth=0,
                         payload={})
        db.session.add(o)
        db.session.flush()
        db.session.add(DeviceServerPolicy(object_id=o.id, appliance_id=a.id,
                                          name="orphan", vserver="vs-missing",
                                          http_service="HTTP", status="enable"))
        db.session.commit()
        assert dm.resolve_targets_from_cache(a) == []


def test_policy_discovery_is_fortiweb_only(app):
    from app.models import Appliance
    from app.services import deep_monitor as dm

    with app.app_context():
        a = Appliance(name="adctest", host="192.0.2.7", kind="fortiadc", username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        assert "FortiWeb-only" in dm.discover_https_probes(a)["error"]
        # and the baseline must NOT create a proxyd probe for it
        assert dm.ensure_baseline(a)["created"] == ["interface"]


def test_scheduled_action_is_registered_and_dry_runs():
    from app.services import scheduled_actions as sa
    keys = {s.key for s in sa.ADMIN_ACTIONS}
    assert "deep_monitor" in keys
    spec = [s for s in sa.ADMIN_ACTIONS if s.key == "deep_monitor"][0]
    assert spec.needs_targets is False


def test_scheduled_action_dry_run_touches_no_device(app, admin_id):
    from app.services import scheduled_actions as sa
    with app.app_context():
        res = sa.run_action("deep_monitor", None, {}, dry_run=True)
        assert res["ok"] is True and "dry-run" in res["summary"]
