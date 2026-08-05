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
    # every family must be offered in the editor, each on its own
    for label in ("proxyd process", "Interface IP / link", "Processor load",
                  "Memory usage"):
        assert label in body
    assert 'data-act="edit"' in body            # probes are editable
    assert 'id="dpFports"' in body              # per-port picker exists


def test_data_feed_shape(client, admin_id):
    login(client, admin_id, product="global")
    d = client.get("/monitoring/deep/data").get_json()
    assert set(d) >= {"probes", "summary", "worst", "kinds", "devices"}
    # Since the Service Monitor split (2026-07-28) this page advertises only the
    # kinds it OWNS. The REST-telemetry four live at /monitoring/services; the
    # partition itself is pinned in tests/test_service_monitor.py.
    assert [k["key"] for k in d["kinds"]] == ["https", "interface", "cpu",
                                              "memory", "proxyd"]
    sm = client.get("/monitoring/services/data").get_json()
    # The four FortiWeb traffic kinds plus the two FortiAuthenticator identity
    # kinds (2026-08-06). Pinned as a literal on purpose: deriving it from
    # dm.API_KINDS would make this assertion agree with any future edit,
    # including one that drops a kind off both pages.
    assert [k["key"] for k in sm["kinds"]] == ["sessions", "policy_sessions",
                                               "throughput", "transactions",
                                               "licence", "tokens"]


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
        # The box metrics DO apply to FortiADC (`get system performance` works
        # there, verified live); only the process monitor is FortiWeb-specific.
        assert dm.ensure_baseline(a)["created"] == ["interface", "cpu", "memory"]
        assert dm.ensure_baseline(a)["created"] == []       # idempotent


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


def test_edit_keeps_the_https_policy_target(client, admin_id, app):
    """The edit form for an HTTPS probe renders no `target` field. A blind
    `form.get('target')` would blank the policy name on every save."""
    login(client, admin_id, product="global")
    pid = client.post("/monitoring/deep/probe",
                      data={"kind": "https", "name": "pol", "url": "https://192.0.2.8/",
                            "target": "pol-shop-main"}).get_json()["probe"]["id"]
    r = client.post(f"/monitoring/deep/probe/{pid}",
                    data={"kind": "https", "name": "pol renamed",
                          "url": "https://192.0.2.8/"})
    assert r.status_code == 200
    assert r.get_json()["probe"]["target"] == "pol-shop-main"
    assert r.get_json()["probe"]["name"] == "pol renamed"


def test_interface_probe_takes_a_port_selection(client, admin_id, app):
    from app.models import Appliance
    login(client, admin_id, product="global")
    with app.app_context():
        a = Appliance(name="fwports", host="192.0.2.20", kind="fortiweb",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        aid = a.id
    r = client.post("/monitoring/deep/probe",
                    data={"kind": "interface", "name": "two ports",
                          "appliance_id": str(aid),
                          "target": ["port1", "port3"]})
    assert r.status_code == 200
    assert r.get_json()["probe"]["target"] == "port1,port3"
    # no tick at all = the whole-device watch
    r = client.post("/monitoring/deep/probe",
                    data={"kind": "interface", "name": "all ports",
                          "appliance_id": str(aid)})
    assert r.get_json()["probe"]["target"] == ""


def test_box_probe_rejects_an_inverted_threshold(client, admin_id, app):
    from app.models import Appliance
    login(client, admin_id, product="global")
    with app.app_context():
        a = Appliance(name="fwbox", host="192.0.2.21", kind="fortiweb",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        aid = a.id
    r = client.post("/monitoring/deep/probe",
                    data={"kind": "cpu", "name": "bad", "appliance_id": str(aid),
                          "warn_pct": "90", "crit_pct": "70"})
    assert r.status_code == 400 and "critical" in r.get_json()["error"]
    r = client.post("/monitoring/deep/probe",
                    data={"kind": "memory", "name": "good", "appliance_id": str(aid),
                          "warn_pct": "70", "crit_pct": "90"})
    assert r.status_code == 200 and r.get_json()["probe"]["crit_pct"] == 90


def test_ports_endpoint_reads_the_cache_and_honours_visibility(client, admin_id, app):
    from app.models import Appliance
    login(client, admin_id, product="global")
    with app.app_context():
        a = Appliance(name="fwcache", host="192.0.2.22", kind="fortiweb",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        aid = a.id
    d = client.get(f"/monitoring/deep/device/{aid}/ports").get_json()
    assert "ports" in d and isinstance(d["ports"], list)   # empty cache is fine
    assert client.get("/monitoring/deep/device/99999/ports").status_code in (403, 404)


def test_split_legacy_proxyd_creates_the_siblings_once(app):
    """Dropping box CPU/mem from the proxyd probe must not delete coverage."""
    from app.models import Appliance
    from app.services import deep_monitor as dm
    with app.app_context():
        a = Appliance(name="fwsplit", host="192.0.2.23", kind="fortiweb",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        db.session.add(MonitorProbe(appliance_id=a.id, kind="proxyd",
                                    name="fwsplit · proxyd", warn_cpu=70))
        db.session.commit()
        made = dm.split_legacy_proxyd()["created"]
        assert made == ["fwsplit:cpu", "fwsplit:memory"]
        cpu = MonitorProbe.query.filter_by(appliance_id=a.id, kind="cpu").one()
        assert cpu.warn_pct == 70          # the tuned threshold survives
        assert dm.split_legacy_proxyd()["created"] == []       # idempotent


# --------------------------------------------------------------------------
# Drill-down chart: rollups + the /series feed
# --------------------------------------------------------------------------

from datetime import datetime, timedelta  # noqa: E402

from app.models import MonitorRollup  # noqa: E402
from app.services import deep_monitor as dm  # noqa: E402


def _probe_with_history(app, *, hours=100, every_min=30, kind="proxyd"):
    """A probe whose raw samples span `hours`, oldest first."""
    with app.app_context():
        p = MonitorProbe(kind=kind, name=f"hist-{kind}-{hours}", enabled=False,
                         interval_min=every_min, retention=10000)
        db.session.add(p)
        db.session.commit()
        now = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        start = now - timedelta(hours=hours)
        n = int(hours * 60 / every_min)
        for i in range(n):
            ts = start + timedelta(minutes=i * every_min)
            db.session.add(MonitorSample(
                probe_id=p.id, ts=ts, status="ok" if i % 10 else "warn",
                ok=bool(i % 10), value_num=100 + (i % 7), value2_num=50.0,
                fingerprint="fp" if i < n - 1 else "fp2"))
        db.session.commit()
        dm.rollup_probe(p.id)
        db.session.commit()
        return p.id


def test_rollup_builds_hourly_and_daily_buckets(app):
    pid = _probe_with_history(app, hours=100)
    with app.app_context():
        hours = MonitorRollup.query.filter_by(probe_id=pid, span="hour").count()
        days = MonitorRollup.query.filter_by(probe_id=pid, span="day").count()
        assert hours >= 95            # ~100 hourly buckets
        assert 4 <= days <= 6         # ~4 days of them
        one = (MonitorRollup.query.filter_by(probe_id=pid, span="hour")
               .order_by(MonitorRollup.bucket).first())
        assert one.samples == 2       # two 30-minute samples per hour
        assert one.v_min is not None and one.v_max is not None


def test_rollup_is_idempotent(app):
    """It runs on every probe execution; a second pass must not duplicate."""
    pid = _probe_with_history(app, hours=30)
    with app.app_context():
        before = MonitorRollup.query.filter_by(probe_id=pid).count()
        dm.rollup_probe(pid)
        db.session.commit()
        dm.rollup_probe(pid)
        db.session.commit()
        assert MonitorRollup.query.filter_by(probe_id=pid).count() == before


def test_rollups_survive_raw_pruning(app):
    """The whole point: depth outlives the retention cap."""
    pid = _probe_with_history(app, hours=100)
    with app.app_context():
        dm.prune(pid, keep=5)
        db.session.commit()
        assert MonitorSample.query.filter_by(probe_id=pid).count() == 5
        assert MonitorRollup.query.filter_by(probe_id=pid, span="hour").count() >= 95


def test_deleting_a_probe_takes_its_rollups(app):
    pid = _probe_with_history(app, hours=10)
    with app.app_context():
        db.session.delete(MonitorProbe.query.get(pid))
        db.session.commit()
        assert MonitorRollup.query.filter_by(probe_id=pid).count() == 0


def test_series_endpoint_ranges(client, admin_id, app):
    pid = _probe_with_history(app, hours=100)
    login(client, admin_id, product="global")

    d = client.get(f"/monitoring/deep/probe/{pid}/series?range=24h").get_json()
    assert d["source"] == "raw" and d["points"]
    assert d["meta"]["unit"] == "MB"           # proxyd trends megabytes now
    assert d["points"][0]["avg"] is not None

    d7 = client.get(f"/monitoring/deep/probe/{pid}/series?range=7d").get_json()
    assert d7["source"] == "hour" and d7["bucket_seconds"] == 3600
    assert d7["points"][0]["min"] is not None and d7["points"][0]["max"] is not None

    d30 = client.get(f"/monitoring/deep/probe/{pid}/series?range=30d").get_json()
    assert d30["source"] == "hour"
    assert d30["totals"]["samples"] >= d7["totals"]["samples"]


def test_series_custom_dates(client, admin_id, app):
    pid = _probe_with_history(app, hours=100)
    login(client, admin_id, product="global")
    end = datetime.utcnow()
    start = end - timedelta(days=3)
    d = client.get(f"/monitoring/deep/probe/{pid}/series?range=custom"
                   f"&from={start.isoformat(timespec='seconds')}"
                   f"&to={end.isoformat(timespec='seconds')}").get_json()
    assert d["points"] and d["range"] == "custom"


def test_series_rejects_a_backwards_or_oversized_range(client, admin_id, app):
    pid = _probe_with_history(app, hours=5)
    login(client, admin_id, product="global")
    now = datetime.utcnow()
    bad = client.get(f"/monitoring/deep/probe/{pid}/series?range=custom"
                     f"&from={now.isoformat()}&to={(now - timedelta(days=1)).isoformat()}")
    assert bad.status_code == 400
    huge = client.get(f"/monitoring/deep/probe/{pid}/series?range=custom"
                      f"&from={(now - timedelta(days=3000)).isoformat()}"
                      f"&to={now.isoformat()}")
    assert huge.status_code == 400
    assert client.get(f"/monitoring/deep/probe/{pid}/series?range=nope").status_code == 400


def test_series_reports_healthy_pct_and_changes(client, admin_id, app):
    pid = _probe_with_history(app, hours=100)
    login(client, admin_id, product="global")
    d = client.get(f"/monitoring/deep/probe/{pid}/series?range=7d").get_json()
    assert 0 <= d["healthy_pct"] <= 100
    assert d["totals"]["changes"] >= 0
    assert d["retention"]["hourly_days"] == dm.HOURLY_KEEP_DAYS


def test_reset_series_clears_samples_and_buckets(app):
    """Used when value_num changes UNITS — mixing % and MB on one axis is a lie
    no label can repair."""
    pid = _probe_with_history(app, hours=20, kind="proxyd")
    with app.app_context():
        out = dm.reset_series("proxyd")
        assert out["samples"] > 0 and out["rollups"] > 0
        assert MonitorSample.query.filter_by(probe_id=pid).count() == 0
        assert MonitorRollup.query.filter_by(probe_id=pid).count() == 0
