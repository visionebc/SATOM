"""Guards for the fleet metrics pipeline: scrape targets → store → panels.

The measurement that produced this design (2026-08-05, against the live node):
one probe row per series would have meant ~180,000 configuration rows,
~56 minutes of device I/O per 3-minute window and ~450 GB in Postgres at
100 devices x 750 policies. Every guard below protects one of the properties
that make those numbers go away — and each has a matching way to silently
regress.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _appliance(app, name="fwm", kind="fortiweb", host="192.0.2.5",
               maintenance=False):
    from app.models import Appliance, db
    a = Appliance(name=name, host=host, username="admin", kind=kind,
                  maintenance=maintenance)
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


# ── the unit of configuration ────────────────────────────────────────────────

def test_targets_are_per_collector_not_per_series(app):
    """The whole design: N policies cost ZERO extra configuration rows."""
    from app.services import metrics_collect as mc
    from app.models_metrics import ScrapeTarget
    with app.app_context():
        a = _appliance(app)
        mc.ensure_targets(a)
        rows = ScrapeTarget.query.filter_by(appliance_id=a.id).all()
        assert {r.collector for r in rows} == {
            k for k, v in mc.COLLECTORS.items() if "fortiweb" in v["products"]}
        assert len(rows) <= len(mc.COLLECTORS)


def test_ensure_targets_is_insert_only(app):
    """Operator edits (interval, enabled, top_n) must survive re-provisioning
    — the sweep calls this on EVERY run."""
    from app.services import metrics_collect as mc
    from app.models import db
    from app.models_metrics import ScrapeTarget
    with app.app_context():
        a = _appliance(app)
        mc.ensure_targets(a)
        t = ScrapeTarget.query.filter_by(appliance_id=a.id,
                                         collector="box").first()
        t.interval_min = 47
        t.enabled = False
        db.session.commit()
        assert mc.ensure_targets(a) == 0
        t2 = ScrapeTarget.query.get(t.id)
        assert t2.interval_min == 47 and t2.enabled is False


def test_products_gate_which_collectors_exist(app):
    from app.services import metrics_collect as mc
    from app.models_metrics import ScrapeTarget
    with app.app_context():
        adc = _appliance(app, name="adcm", kind="fortiadc", host="192.0.2.6")
        mc.ensure_targets(adc)
        got = {r.collector for r in
               ScrapeTarget.query.filter_by(appliance_id=adc.id).all()}
        # FortiADC has no server-policy monitor API; claiming otherwise would
        # produce a permanently failing target rather than an absent one.
        assert "policies" not in got and "box" in got


# ── scheduling ───────────────────────────────────────────────────────────────

def test_maintenance_device_is_never_scraped(app):
    from app.services import metrics_collect as mc
    from app.models import db
    with app.app_context():
        a = _appliance(app)
        mc.ensure_targets(a)
        assert mc.due_targets()
        a.maintenance = True
        db.session.commit()
        assert mc.due_targets() == []


def test_retired_invalid_host_is_never_scraped(app):
    """`.invalid` is how a decommissioned appliance is neutralised; the deep
    monitors once kept probing recycled IPs every three minutes."""
    from app.services import metrics_collect as mc
    from app.models import db
    with app.app_context():
        a = _appliance(app, host="retired-fwm.invalid")
        mc.ensure_targets(a)
        db.session.commit()
        assert mc.due_targets() == []


def test_interval_is_honoured_with_tick_slack(app):
    from app.services import metrics_collect as mc
    from app.models import db
    from app.models_metrics import ScrapeTarget
    with app.app_context():
        a = _appliance(app)
        mc.ensure_targets(a)
        t = ScrapeTarget.query.filter_by(appliance_id=a.id,
                                         collector="traffic").first()
        t.interval_min = 15
        now = datetime.utcnow()
        t.last_run_at = now - timedelta(minutes=5)
        db.session.commit()
        assert t.id not in {x.id for x in mc.due_targets(now)}
        # Just inside the tick slack: due, because waiting for the NEXT tick
        # would silently turn a 15-minute target into an 18-minute one.
        t.last_run_at = now - timedelta(minutes=15, seconds=-30)
        db.session.commit()
        assert t.id in {x.id for x in mc.due_targets(now)}


# ── exposition format ────────────────────────────────────────────────────────

def test_line_escapes_labels_and_skips_non_numeric():
    from app.services import vm_store
    assert vm_store.line("m", {"device": 'a"b'}, 1, 1000) == \
        'm{device="a\\"b"} 1 1000'
    assert vm_store.line("m", {"device": "x"}, None, 1000) == ""
    assert vm_store.line("m", {"device": "x"}, "n/a", 1000) == ""


def test_labels_carry_the_series_identity():
    """Series are identified by LABELS, not by a config row — that is what
    makes 67,500 policy series cost nothing to configure."""
    from app.services import metrics_collect as mc

    class A:
        name, kind = "fw1", "fortiweb"
    got = mc._labels(A(), policy="p1")
    assert got == {"device": "fw1", "kind": "fortiweb", "policy": "p1"}


# ── failure is recorded, not absent ──────────────────────────────────────────

def test_failed_collector_writes_scrape_up_zero(app, monkeypatch):
    """Absence of data is not health. A broken collector must be visible IN
    the store, not an absence someone has to notice."""
    from app.services import metrics_collect as mc
    from app.services import vm_store
    sent = {}

    def _boom(appliance, params, ts):
        raise RuntimeError("device refused")

    monkeypatch.setitem(mc._RUNNERS, "box", _boom)
    def _capture(lines):
        sent["lines"] = lines
        return {"ok": True, "count": len(lines), "detail": ""}

    monkeypatch.setattr(vm_store, "ingest", _capture)
    with app.app_context():
        a = _appliance(app)
        mc.ensure_targets(a)
        from app.models_metrics import ScrapeTarget
        t = ScrapeTarget.query.filter_by(appliance_id=a.id,
                                         collector="box").first()
        res = mc.run_target(t)
        assert res["ok"] is False and "refused" in res["detail"]
        assert any("satom_scrape_up" in l and l.rstrip().split()[-2] == "0"
                   for l in sent["lines"]), sent["lines"]
        assert t.last_status == "error"


def test_sweep_is_ok_even_when_devices_fail(app, monkeypatch):
    """`ok` means THE SWEEP RAN. A permanently-red scheduled action is one an
    operator learns to skip — the lesson already paid for in deep_monitor."""
    from app.services import metrics_collect as mc
    from app.services import scheduled_actions as sa
    monkeypatch.setattr(mc, "sweep", lambda: {
        "targets": 4, "ok": 0, "errors": 4, "created": 0, "series": 0, "ms": 12})
    with app.app_context():
        res = sa._do_metrics_scrape({}, dry_run=False)
        assert res["ok"] is True
        assert "4 error" in res["summary"]


# ── panels: the selector mode ────────────────────────────────────────────────

def test_metricsql_panel_reports_query_failure_as_an_error(app, monkeypatch):
    """A failed query and an empty result look identical on a canvas and mean
    opposite things."""
    from app.services import monitor_analytics as ma
    from app.services import vm_store
    monkeypatch.setattr(vm_store, "query_range",
                        lambda *a, **k: {"status": "error", "error": "boom"})

    class P:
        select_mode, vm_expr, vm_legend, vm_unit = "metricsql", "x", "", "%"
        stat_func = "last"

        def to_dict(self):
            return {"id": 1}
    end = datetime.utcnow()
    out = ma.vm_panel_payload(P(), end - timedelta(hours=1), end)
    assert out["error"] == "boom" and out["empty"] is True


def test_metricsql_panel_aligns_series_on_one_axis(app, monkeypatch):
    from app.services import monitor_analytics as ma
    from app.services import vm_store
    monkeypatch.setattr(vm_store, "query_range", lambda *a, **k: {
        "status": "success", "data": {"result": [
            {"metric": {"__name__": "m", "device": "fw1"},
             "values": [[100, "1"], [160, "2"]]},
            {"metric": {"__name__": "m", "device": "fw2"},
             "values": [[160, "5"]]},
        ]}})

    class P:
        select_mode, vm_expr, vm_legend, vm_unit = "metricsql", "m", "", "%"
        stat_func = "last"

        def to_dict(self):
            return {"id": 1}
    end = datetime.utcnow()
    out = ma.vm_panel_payload(P(), end - timedelta(hours=1), end)
    assert len(out["axis"]) == 2
    # fw2 has no sample at t=100 — that must stay a GAP, not be back-filled.
    fw2 = [s for s in out["series"] if s["device"] == "fw2"][0]
    assert fw2["avg"] == [None, 5.0]


def test_vm_step_bounds_the_point_count():
    from app.services import monitor_analytics as ma
    end = datetime.utcnow()
    for days in (1, 7, 30, 90):
        start = end - timedelta(days=days)
        step = int(ma.vm_step(start, end).rstrip("s"))
        assert (end - start).total_seconds() / step <= ma._MAX_POINTS + 1


def test_metricsql_expression_is_validated_by_the_store(app, monkeypatch):
    """Validated by EXECUTING it, not by pattern-matching: the store is the
    only authority on its own query language."""
    from app.views import monitor_analytics as view
    from app.services import vm_store
    monkeypatch.setattr(vm_store, "query",
                        lambda expr, **k: {"status": "error", "error": "bad"})

    class P:
        title = subtitle = ""
        viz = "line"
        select_mode = "metricsql"
        vm_expr = vm_legend = vm_unit = ""
        stat_func = "last"
        range_key = ""
    err = view._apply_panel(P(), {"select_mode": "metricsql",
                                  "vm_expr": "nonsense(("})
    assert "rejected" in err.lower()


# ── reports read the store, not only the probes ──────────────────────────────

def test_report_fleet_section_reports_unavailable_store_honestly(app, monkeypatch):
    from app.services import monitor_reports as mrep
    from app.services import vm_store
    monkeypatch.setattr(vm_store, "health",
                        lambda: {"up": False, "detail": "connection refused"})
    end = datetime.utcnow()
    out = mrep.fleet_section(end - timedelta(days=1), end)
    assert out["available"] is False and "refused" in out["detail"]
    assert out["metrics"] == []   # never zeros standing in for "unknown"


def test_report_body_carries_the_fleet_section(app, monkeypatch):
    from app.services import monitor_reports as mrep
    monkeypatch.setattr(mrep, "fleet_section",
                        lambda s, e, product=None: {"available": True, "metrics": [],
                                      "down_policies": [],
                                      "failed_collectors": [], "detail": ""})
    with app.app_context():
        body = mrep.build("daily")
        assert "fleet" in body and body["fleet"]["available"] is True


def test_report_push_targets_the_backup_server_reports_dir(app, monkeypatch):
    from app.services import monitor_reports as mrep
    from app.services import backup_server as bk
    calls = []
    monkeypatch.setattr(bk, "push_bundle",
                        lambda path, remote_name=None, remote_dir=None: (
                            calls.append((remote_name, remote_dir)) or
                            {"ok": True, "detail": "ok"}))

    class Row:
        period, product = "daily", ""
        period_start = datetime(2026, 8, 4)

        def body(self):
            # render_text parses these, so they must be real timestamps.
            return {"totals": {"probes": 0, "devices": 0, "samples": 0,
                               "healthy_pct": None, "worst": "unknown",
                               "incidents": 0, "changes": 0, "breaches": 0,
                               "silent": 0, "measured_probes": 0},
                    "devices": [], "probes": [], "incidents": [],
                    "silent": [], "period": "daily", "period_label": "Daily",
                    "from": "2026-08-04T00:00:00", "to": "2026-08-05T00:00:00",
                    "no_data": True}
    with app.app_context():
        res = mrep.push_to_backup_server(Row())
    assert res["ok"], res
    names = [n for n, _d in calls]
    assert names == ["satom-report-daily-20260804.json",
                     "satom-report-daily-20260804.txt"]
    assert all(d.endswith("/reports") for _n, d in calls)


def test_footer_no_data_note_keys_off_points_not_health():
    """Store panels carry no health concept, so a healthy_pct test printed
    "no data in this window" underneath seventeen plotted points — the footer
    contradicting the chart above it. Caught by rendering, not by reading."""
    js = (REPO / "app" / "static" / "js" / "analytics.js").read_text()
    i = js.index("function footNode")
    # Bound the window at the NEXT function, not by a character count: a fixed
    # window ran past footNode into code that mentions healthy_pct for good
    # reasons, and the guard failed on correct source.
    j = js.index("\n  function ", i + 1)
    # Strip comments before asserting: the comment that EXPLAINS this guard
    # names healthy_pct, so a raw substring test matches its own rationale and
    # fails on correct source. Assert against code, never against prose.
    body = "\n".join(l for l in js[i:j].splitlines()
                     if not l.strip().startswith("//"))
    assert "summary && s.summary.points" in body
    assert "healthy_pct" not in body


# ── the store is never exposed ───────────────────────────────────────────────

def test_metrics_unit_binds_loopback_only():
    """The store has NO auth. The unit is the only thing keeping it off the
    network; a bind address change there is a fleet-wide data exposure."""
    unit = (REPO / "deploy" / "satom-metrics.service").read_text()
    assert "-httpListenAddr=127.0.0.1:8428" in unit
    assert "0.0.0.0" not in unit


def test_metrics_unit_is_refreshed_by_updates():
    """A unit absent from UNIT_FILES is a unit that ages behind its own repo."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_satom_runner_probe_a", str(REPO / "deploy" / "self_update_runner.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Ask the runner what it covers rather than grepping for a literal: the
    # list is DERIVED from deploy/ now, which is the fix this guard protects.
    assert "satom-metrics.service" in set(mod.UNIT_FILES)


def test_seed_and_checks_agree_about_metrics_scrape():
    sys.path.insert(0, str(REPO / "deploy"))
    from satom_cli import cmd_checks, cmd_fix
    assert "metrics_scrape" in cmd_checks.MIN_ACTIONS
    assert "metrics_scrape" in {row[0] for row in cmd_fix.SEED_PLAN}


def test_the_seed_plan_records_the_daily_inventory_snapshot():
    """The Metrics page's daily inventory trend is fed ONLY by this action;
    it used to be left to the operator to schedule by hand."""
    sys.path.insert(0, str(REPO / "deploy"))
    from satom_cli import cmd_checks, cmd_fix
    rows = [r for r in cmd_fix.SEED_PLAN if r[0] == "inventory_snapshot"]
    assert len(rows) == 1
    _key, _name, kind, sched, params, product = rows[0]
    assert (kind, sched, params, product) == ("daily", {"time": "23:50"}, {}, "global")
    assert "inventory_snapshot" in cmd_checks.MIN_ACTIONS


def test_collection_page_renders(app, client):
    from conftest import admin_user_id, login
    from app.services import metrics_collect as mc
    with app.app_context():
        a = _appliance(app)
        mc.ensure_targets(a)
    login(client, admin_user_id(app))
    r = client.get("/monitoring/collection/")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "Scrape targets" in html and "fwm" in html


# ── the fleet section is RENDERED, not only stored ───────────────────────────

def _fleet_body(fleet):
    return {"totals": {"probes": 0, "devices": 0, "samples": 0,
                       "healthy_pct": None, "worst": "unknown",
                       "incidents": 0, "changes": 0, "breaches": 0,
                       "silent": 0, "measured_probes": 0},
            "devices": [], "probes": [], "incidents": [], "silent": [],
            "period": "daily", "period_label": "Daily",
            "from": "2026-10-01T00:00:00", "to": "2026-10-02T00:00:00",
            "no_data": True, "fleet": fleet}


_FLEET = {"available": True, "detail": "", "product": "", "policy_scope": True,
          "metrics": [{"key": "cpu", "label": "CPU", "unit": "%",
                       "rows": [{"series": "fwb1", "min": 3.0, "avg": 41.5,
                                 "max": 97.25}]}],
          "down_policies": [{"device": "fwb1", "policy": "shop-policy"}],
          "failed_collectors": [{"device": "fwb2", "collector": "traffic"}]}


def test_report_text_renders_the_fleet_section():
    from app.services import monitor_reports as mrep
    txt = mrep.render_text(_fleet_body(_FLEET))
    assert "Fleet metrics" in txt
    assert "fwb1" in txt and "41.5 %" in txt and "97.25 %" in txt
    assert "Policies down in the window: 1" in txt and "shop-policy" in txt
    assert "Failing collectors: 1" in txt and "fwb2 / traffic" in txt
    off = mrep.render_text(_fleet_body({"available": False,
                                        "detail": "connection refused"}))
    assert "NOT AVAILABLE" in off and "connection refused" in off


def test_report_csv_carries_the_fleet_rows():
    import csv
    import io
    from app.services import monitor_reports as mrep
    rows = list(csv.reader(io.StringIO(mrep.to_csv(_fleet_body(_FLEET)))))
    head = rows[0]
    fleet = [dict(zip(head, r)) for r in rows[1:]]
    cpu = [r for r in fleet if r["kind"] == "fleet"][0]
    assert (cpu["device"], cpu["metric"], cpu["min"], cpu["avg"], cpu["max"]) == (
        "fwb1", "cpu", "3.0", "41.5", "97.25")
    assert any(r["kind"] == "fleet_policy_down" and r["probe"] == "shop-policy"
               for r in fleet)
    assert any(r["kind"] == "fleet_collector_failed" and r["device"] == "fwb2"
               for r in fleet)
    assert all(len(r) == len(head) for r in rows)


def test_report_page_renders_the_fleet_section(app, client):
    import json as _json
    from app.extensions import db
    from app.models_analytics import MonitorReport
    from tests.conftest import admin_user_id, login
    with app.app_context():
        row = MonitorReport(period="daily", period_start=datetime(2026, 10, 1),
                            period_end=datetime(2026, 10, 2), product="",
                            title="Daily", worst_status="unknown",
                            payload=_json.dumps(_fleet_body(_FLEET)))
        db.session.add(row)
        db.session.commit()
        rid = row.id
    login(client, admin_user_id(app), product="global")
    r = client.get("/monitoring/reports/%d" % rid)
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert 'id="rep-fleet"' in html
    assert "97.25" in html and "shop-policy" in html and "traffic" in html


# ── FortiADC: device-level aggregates never borrow per-policy names ─────────

def test_adc_device_rtt_is_published_under_adc_names(monkeypatch):
    """``vs_status`` is a vdom aggregate with no ``policy`` label. Published as
    ``satom_policy_*_rtt_ms`` it sat under FortiWeb's per-policy names and the
    Service drill-down's ``policy=~"$policy"`` panels never matched it."""
    from app.clients import fortiadc
    from app.services import metrics_collect as mc

    class _Adc:
        def __init__(self, appliance, timeout=None):
            pass

        def login(self):
            pass

        def vs_status(self, vdom="root"):
            return {"current_sessions": 4, "client_rtt": 11, "server_rtt": 22,
                    "app_response": 33}

        def vs_list(self, vdom="root"):
            return [{"name": "vs-shop", "status": "up", "current_sessions": 2}]

        def pool_member_list(self, vdom="root"):
            return []

    class _Appl:
        name, kind = "adc1", "fortiadc"

    monkeypatch.setattr(fortiadc, "FortiADCClient", _Adc)
    lines = [l for l in mc._collect_vservers(_Appl(), {}, 1) if l]
    names = {l.split("{", 1)[0]: l for l in lines}
    assert names["satom_adc_client_rtt_ms"].split()[1] == "11"
    assert names["satom_adc_server_rtt_ms"].split()[1] == "22"
    assert names["satom_adc_app_response_ms"].split()[1] == "33"
    # every satom_policy_* series is per virtual server
    for l in lines:
        if l.startswith("satom_policy_") and not l.startswith("satom_policy_count"):
            assert 'policy="vs-shop"' in l, l
