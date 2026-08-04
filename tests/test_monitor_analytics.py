"""Guards for the analytics boards and the period reports.

Each test here anchors a property that, if it broke, would fail SILENTLY — the
page would still render, the report would still be produced, and the number it
showed would simply be wrong. That is the failure mode this whole subsystem is
exposed to: nothing raises when a chart draws a straight line through an outage
or a report prints 100 % for a week nobody measured.

The properties, and why each earns a test:

* One resolution per panel. Two series drawn from two tables on one axis is a
  lie no legend repairs.
* A page load never opens a device connection.
* ADOM scoping is enforced at the route, not by hiding rows.
* Missing buckets stay ``None`` and are never interpolated.
* Report periods are half-open, so no bucket is counted by two reports.
* Effective cadence matches what ``due_probes`` actually does.
* An empty window reports "no data", never a healthy zero.
* Built-in boards refuse writes at the endpoint, not just in the template.
* Deleting a board deletes its panels (SQLite ships with FKs OFF, so the ORM
  must issue the child deletes itself).
* Chart.js is served locally — this product installs into isolated networks.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from tests.conftest import admin_user_id, login

from app.services import monitor_analytics as ma
from app.services import monitor_reports as mr


# --------------------------------------------------------------------------- #
#  Fixtures                                                                    #
# --------------------------------------------------------------------------- #
def _appliance(app, name="fw-test", kind="fortiweb"):
    from app.extensions import db
    from app.models import Appliance

    with app.app_context():
        a = Appliance(name=name, host="%s.invalid" % name, kind=kind,
                      username="admin")
        # NOT NULL on password_enc — the setter encrypts, the constructor cannot.
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        return a.id


def _probe(app, appliance_id, *, kind="cpu", name="p", interval=3,
           enabled=True):
    from app.extensions import db
    from app.models import MonitorProbe

    with app.app_context():
        p = MonitorProbe(appliance_id=appliance_id, kind=kind, name=name,
                         enabled=enabled, interval_min=interval,
                         warn_pct=80, crit_pct=95)
        db.session.add(p)
        db.session.commit()
        return p.id


def _samples(app, probe_id, *, n=10, step_min=3, value=10.0,
             status="ok", end=None, gap_from=None, gap_to=None):
    """Write ``n`` samples ending at ``end``, optionally leaving a hole."""
    from app.extensions import db
    from app.models import MonitorSample

    end = end or datetime.utcnow()
    with app.app_context():
        for i in range(n):
            ts = end - timedelta(minutes=step_min * (n - 1 - i))
            if gap_from is not None and gap_from <= i <= (gap_to or gap_from):
                continue
            db.session.add(MonitorSample(
                probe_id=probe_id, ts=ts, status=status, ok=(status == "ok"),
                value_num=value, value2_num=None, fingerprint="fp"))
        db.session.commit()


def _board(app, *, builtin=False, slug="test-board", product=""):
    from app.extensions import db
    from app.models_analytics import MonitorDashboard

    with app.app_context():
        b = MonitorDashboard(slug=slug, title="Test board", builtin=builtin,
                             product=product)
        db.session.add(b)
        db.session.commit()
        return b.id


def _panel(app, board_id, **kw):
    from app.extensions import db
    from app.models_analytics import MonitorPanel

    with app.app_context():
        kw.setdefault("select_mode", "rule")
        kw.setdefault("rule_kind", "cpu")
        kw.setdefault("viz", "line")
        kw.setdefault("title", "Panel")
        p = MonitorPanel(dashboard_id=board_id, **kw)
        db.session.add(p)
        db.session.commit()
        return p.id


# --------------------------------------------------------------------------- #
#  1. One resolution per panel                                                 #
# --------------------------------------------------------------------------- #
def test_panel_takes_the_coarsest_source_any_series_needs(app, monkeypatch):
    """A young probe forces its neighbours onto the coarse table, not vice versa.

    Two lines on one axis at two resolutions is the failure this prevents: the
    raw line shows spikes the hourly line averaged away, and an operator reads
    that as a difference between the two DEVICES.
    """
    with app.app_context():
        answers = {1: "raw", 2: "hour", 3: "raw"}
        monkeypatch.setattr(ma.dm, "source_for",
                            lambda pid, s, e, session=None: answers[pid])
        now = datetime.utcnow()
        assert ma.panel_source([1, 3], now - timedelta(hours=1), now) == "raw"
        # Adding the hourly-only probe must degrade the WHOLE panel.
        assert ma.panel_source([1, 2, 3], now - timedelta(hours=1), now) == "hour"

        answers[2] = "day"
        assert ma.panel_source([1, 2, 3], now - timedelta(hours=1), now) == "day"


def test_panel_source_of_an_empty_panel_is_stated_not_guessed(app):
    with app.app_context():
        now = datetime.utcnow()
        assert ma.panel_source([], now - timedelta(hours=1), now) == "hour"


def test_every_series_in_a_payload_is_read_from_the_same_table(app):
    """End-to-end: the payload names ONE source, and it is the coarsest."""
    aid = _appliance(app)
    p1 = _probe(app, aid, name="a")
    p2 = _probe(app, aid, name="b")
    _samples(app, p1, n=20)
    _samples(app, p2, n=20)
    bid = _board(app)
    pid = _panel(app, bid)
    with app.app_context():
        from app.models_analytics import MonitorPanel
        panel = MonitorPanel.query.get(pid)
        now = datetime.utcnow()
        out = ma.panel_payload(panel, now - timedelta(hours=2), now)
        assert out["source"] in ("raw", "hour", "day")
        assert len(out["series"]) == 2
        # One axis, and every series aligned to exactly its length.
        for s in out["series"]:
            assert len(s["avg"]) == len(out["axis"])


# --------------------------------------------------------------------------- #
#  2. A page load never touches an appliance                                   #
# --------------------------------------------------------------------------- #
def test_rendering_a_board_opens_no_device_connection(app, client, monkeypatch):
    """The whole Monitoring contract in one assertion.

    Every number on this page comes from stored rows, so a board must open with
    every appliance powered off. Any client constructed during a render is a
    regression, and the exception makes it loud instead of merely slow.
    """
    def _boom(*a, **kw):
        raise AssertionError("a page load tried to contact an appliance")

    import app.clients.fortiweb as fwmod
    monkeypatch.setattr(fwmod, "FortiWebClient", _boom)
    import app.services.ssh_ops as ssh_ops
    monkeypatch.setattr(ssh_ops, "run_command", _boom)

    aid = _appliance(app)
    pid = _probe(app, aid)
    _samples(app, pid, n=10)
    bid = _board(app)
    _panel(app, bid)

    login(client, admin_user_id(app), product=None)
    assert client.get("/monitoring/analytics/").status_code == 200
    assert client.get("/monitoring/analytics/data?board=test-board").status_code == 200
    assert client.get("/monitoring/reports/").status_code == 200


def test_building_a_report_opens_no_device_connection(app, monkeypatch):
    def _boom(*a, **kw):
        raise AssertionError("report generation tried to contact an appliance")

    import app.clients.fortiweb as fwmod
    monkeypatch.setattr(fwmod, "FortiWebClient", _boom)
    import app.services.ssh_ops as ssh_ops
    monkeypatch.setattr(ssh_ops, "run_command", _boom)

    aid = _appliance(app)
    pid = _probe(app, aid)
    _samples(app, pid, n=10)
    with app.app_context():
        body = mr.build("daily")
        assert body["totals"]["probes"] >= 1


# --------------------------------------------------------------------------- #
#  3. Gaps stay gaps                                                           #
# --------------------------------------------------------------------------- #
def test_a_missing_bucket_is_none_and_is_never_interpolated(app):
    """Joining across an outage draws a confident line through the hole.

    ``align`` must emit ``None`` for a bucket the series has no row for — the
    front end draws with spanGaps:false, so a None is a visible break and any
    other value is an invented reading.
    """
    axis = ["2026-08-01T00:00:00", "2026-08-01T01:00:00", "2026-08-01T02:00:00"]
    points = [{"t": "2026-08-01T00:00:00", "avg": 5.0},
              {"t": "2026-08-01T02:00:00", "avg": 9.0}]
    assert ma.align(axis, points, "avg") == [5.0, None, 9.0]


def test_a_generated_grid_shows_the_hole_rather_than_closing_it(app):
    """A silent series must not simply have fewer points than its neighbour."""
    start = datetime(2026, 8, 1, 0, 0)
    end = datetime(2026, 8, 1, 5, 0)
    axis = ma.grid(start, end, "hour", [[]])
    assert len(axis) >= 5
    sparse = [{"t": axis[0], "avg": 1.0}, {"t": axis[-1], "avg": 2.0}]
    row = ma.align(axis, sparse, "avg")
    assert row[0] == 1.0 and row[-1] == 2.0
    assert all(v is None for v in row[1:-1])
    assert len(row) == len(axis)


# --------------------------------------------------------------------------- #
#  4. Absence of data is never health                                          #
# --------------------------------------------------------------------------- #
def test_a_window_with_nothing_measured_reports_none_not_zero():
    """0 % says the service is down; 100 % says it is fine. Both are inventions."""
    assert ma.healthy_pct([]) is None
    assert ma.healthy_pct([{"status": "unknown"}, {"status": None}]) is None
    # And a genuinely measured window still reports a number.
    assert ma.healthy_pct([{"status": "ok"}, {"status": "crit"}]) == 50.0


def test_stat_of_skips_nulls_instead_of_counting_them_as_zero():
    """A probe that reported nothing did not report zero.

    Averaging a None in as 0 drags every headline figure toward the floor, which
    reads as a degradation that never happened.
    """
    pts = [{"avg": 10.0}, {"avg": None}, {"avg": 20.0}]
    assert ma.stat_of(pts, "avg") == 15.0
    assert ma.stat_of(pts, "min") == 10.0
    assert ma.stat_of(pts, "max") == 20.0
    assert ma.stat_of(pts, "last") == 20.0
    assert ma.stat_of([{"avg": None}], "avg") is None


def test_an_empty_report_says_no_data_and_does_not_roll_up_healthy(app):
    _appliance(app)
    with app.app_context():
        body = mr.build("daily")
        assert body["totals"]["healthy_pct"] is None
        assert body["no_data"] is True
        # unknown, never ok.
        assert body["totals"]["worst"] == "unknown"
        assert "NO DATA" in mr.render_text(body)


def test_unknown_ranks_below_ok_so_an_unmeasured_device_cannot_roll_up_green():
    """The Fleet-health §9b rule, applied to reports.

    A device that reported nothing beside one that reported healthy must not
    aggregate to healthy.
    """
    assert mr.worst_status(["ok", "unknown"]) == "unknown"
    assert mr.worst_status(["ok", "ok"]) == "ok"
    assert mr.worst_status(["ok", "warn"]) == "warn"
    assert mr.worst_status(["warn", "crit"]) == "crit"
    assert mr.worst_status([]) == "unknown"


def test_a_delta_against_nothing_is_not_a_percentage():
    """Growth from zero is not +100 %, and change from None is not a number."""
    assert mr._pct_delta(10, None) is None
    assert mr._pct_delta(None, 10) is None
    assert mr._pct_delta(10, 0) is None
    assert mr._pct_delta(15, 10) == 50.0


# --------------------------------------------------------------------------- #
#  5. Report periods are half-open                                             #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("period", ["daily", "weekly", "monthly"])
def test_adjacent_periods_share_a_boundary_without_overlapping(period):
    """``[start, end)``. Both sides claiming the boundary double-counts it."""
    ref = datetime(2026, 8, 5, 13, 45)
    older_start, older_end = mr.period_bounds(period, ref, offset=2)
    newer_start, newer_end = mr.period_bounds(period, ref, offset=1)
    assert older_end == newer_start
    assert older_start < older_end <= newer_start < newer_end


def test_a_period_never_includes_the_instant_it_ends_on(app):
    """The last bucket of one report must not also open the next one."""
    aid = _appliance(app)
    pid = _probe(app, aid)
    start, end = mr.period_bounds("daily", datetime(2026, 8, 5, 12, 0))
    # A sample sitting exactly on the closing boundary belongs to the NEXT day.
    _samples(app, pid, n=1, end=end, value=99.0)
    with app.app_context():
        body = mr.build("daily", start=start, end=end)
        rows = [r for r in body["probes"] if r["probe_id"] == pid]
        assert rows and rows[0]["samples"] == 0


def test_the_complete_period_is_used_not_the_one_still_running():
    """A report run at 02:00 must not describe a two-hour-old day.

    'Throughput fell 80 %' is meaningless when the period is still filling.
    """
    ref = datetime(2026, 8, 5, 2, 0)
    start, end = mr.period_bounds("daily", ref)
    assert end <= ref.replace(hour=0, minute=0, second=0, microsecond=0)
    assert start == datetime(2026, 8, 4)


def test_monthly_bounds_cross_a_year_without_arithmetic_error():
    start, end = mr.period_bounds("monthly", datetime(2026, 1, 15))
    assert (start, end) == (datetime(2025, 12, 1), datetime(2026, 1, 1))


# --------------------------------------------------------------------------- #
#  6. Effective cadence                                                        #
# --------------------------------------------------------------------------- #
def test_effective_cadence_matches_what_the_sweep_actually_does():
    """``tick * ceil(interval / tick)`` — the rounding the probe row hides.

    This is the arithmetic that silently turned the 5-minute proxyd check into a
    6-minute one when the sweep moved to 3, while its row still said 5.
    """
    assert ma.effective_interval(5, 3) == 6
    assert ma.effective_interval(3, 3) == 3
    assert ma.effective_interval(15, 3) == 15
    assert ma.effective_interval(1, 3) == 3
    assert ma.effective_interval(10, 4) == 12
    # A tick that divides the interval leaves it untouched.
    assert ma.effective_interval(30, 15) == 30


def test_no_scheduled_sweep_reports_zero_rather_than_a_plausible_default(app):
    """A fresh install seeds no ScheduledAction (safeguards §10).

    Substituting 3 here would print an effective cadence for a sweep that never
    runs — a page confidently describing collection that is not happening.
    """
    with app.app_context():
        assert ma.sweep_tick_minutes() == 0
        rep = ma.cadence_report()
        assert rep["sweep_configured"] is False
        assert rep["tick_min"] == 0


def test_cadence_report_flags_a_probe_that_does_not_divide_into_the_tick(app):
    from app.extensions import db
    from app.models import ScheduledAction

    aid = _appliance(app)
    _probe(app, aid, name="aligned", interval=3)
    _probe(app, aid, name="drifting", interval=5)
    with app.app_context():
        db.session.add(ScheduledAction(
            name="sweep", action="deep_monitor", schedule_kind="interval",
            schedule=json.dumps({"every": 3, "unit": "minutes"}),
            enabled=True, targets="[]", params="{}"))
        db.session.commit()

        rep = ma.cadence_report()
        assert rep["tick_min"] == 3
        by = {r["name"]: r for r in rep["probes"]}
        assert by["aligned"]["drift"] is False
        assert by["drifting"]["drift"] is True
        assert by["drifting"]["effective_min"] == 6
        assert rep["drifted"] == 1


def test_a_disabled_sweep_is_not_a_running_one(app):
    from app.extensions import db
    from app.models import ScheduledAction

    with app.app_context():
        db.session.add(ScheduledAction(
            name="sweep", action="deep_monitor", schedule_kind="interval",
            schedule=json.dumps({"every": 3, "unit": "minutes"}),
            enabled=False, targets="[]", params="{}"))
        db.session.commit()
        assert ma.sweep_tick_minutes() == 0


# --------------------------------------------------------------------------- #
#  7. Built-in boards are read-only at the ROUTE                               #
# --------------------------------------------------------------------------- #
def test_a_builtin_board_refuses_writes_at_the_endpoint(app, client):
    """A hidden Save button is hidden, not read-only.

    The template stops offering the control; this stops the control working.
    """
    bid = _board(app, builtin=True, slug="builtin-board")
    pid = _panel(app, bid)
    login(client, admin_user_id(app), product=None)

    assert client.post("/monitoring/analytics/board/%d" % bid,
                       data={"title": "hijacked"}).status_code == 403
    assert client.post("/monitoring/analytics/board/%d/delete" % bid
                       ).status_code == 403
    assert client.post("/monitoring/analytics/board/%d/panel" % bid,
                       data={"title": "x", "rule_kind": "cpu"}).status_code == 403
    assert client.post("/monitoring/analytics/panel/%d" % pid,
                       data={"title": "x"}).status_code == 403
    assert client.post("/monitoring/analytics/panel/%d/delete" % pid
                       ).status_code == 403

    with app.app_context():
        from app.models_analytics import MonitorDashboard
        assert MonitorDashboard.query.get(bid).title == "Test board"


def test_a_builtin_board_can_be_duplicated_into_an_editable_copy(app, client):
    """Read-only has to come with an escape hatch or it is merely frustrating."""
    bid = _board(app, builtin=True, slug="builtin-board")
    _panel(app, bid, title="P1")
    _panel(app, bid, title="P2")
    login(client, admin_user_id(app), product=None)

    res = client.post("/monitoring/analytics/board/%d/duplicate" % bid)
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] and body["board"]["builtin"] is False

    with app.app_context():
        from app.models_analytics import MonitorDashboard
        copy = MonitorDashboard.query.filter_by(slug=body["board"]["slug"]).first()
        assert copy.panels.count() == 2


# --------------------------------------------------------------------------- #
#  8. Cascade                                                                  #
# --------------------------------------------------------------------------- #
def test_deleting_a_board_deletes_its_panels(app):
    """SQLite ships with foreign keys OFF.

    Leaning on ON DELETE CASCADE would leak orphan panels on every non-Postgres
    deployment and throughout this suite, so the relationship must issue the
    child deletes itself.
    """
    from app.extensions import db
    from app.models_analytics import MonitorDashboard, MonitorPanel

    bid = _board(app)
    _panel(app, bid)
    _panel(app, bid)
    with app.app_context():
        assert MonitorPanel.query.filter_by(dashboard_id=bid).count() == 2
        db.session.delete(MonitorDashboard.query.get(bid))
        db.session.commit()
        assert MonitorPanel.query.filter_by(dashboard_id=bid).count() == 0


# --------------------------------------------------------------------------- #
#  9. Selection rules                                                          #
# --------------------------------------------------------------------------- #
def test_a_rule_panel_picks_up_a_probe_created_after_the_panel(app):
    """The reason rules exist.

    A frozen id list is how a board silently narrows over time: it keeps drawing
    with fewer lines than the operator believes they are watching.
    """
    from app.models_analytics import MonitorPanel

    aid = _appliance(app)
    _probe(app, aid, name="first")
    bid = _board(app)
    pid = _panel(app, bid, select_mode="rule", rule_kind="cpu")

    with app.app_context():
        assert len(ma.resolve_panel_probes(MonitorPanel.query.get(pid))) == 1
    _probe(app, aid, name="second")          # e.g. Discover recreates a probe
    with app.app_context():
        assert len(ma.resolve_panel_probes(MonitorPanel.query.get(pid))) == 2


def test_an_explicit_list_keeps_a_paused_probe_but_a_rule_drops_it(app):
    """A rule describes a shape; a pause takes the probe out of that shape.

    An explicit pick is a deliberate request for THAT probe, and dropping it
    silently would remove a legend entry for no stated reason.
    """
    from app.models_analytics import MonitorPanel

    aid = _appliance(app)
    live = _probe(app, aid, name="live")
    paused = _probe(app, aid, name="paused", enabled=False)
    bid = _board(app)

    rule = _panel(app, bid, select_mode="rule", rule_kind="cpu")
    explicit = _panel(app, bid, select_mode="probes",
                      probe_ids="%d,%d" % (live, paused))
    with app.app_context():
        assert len(ma.resolve_panel_probes(MonitorPanel.query.get(rule))) == 1
        assert len(ma.resolve_panel_probes(MonitorPanel.query.get(explicit))) == 2


def test_an_explicit_list_is_capped_before_it_can_be_truncated(app, client):
    """``probe_ids`` is a 500-char column.

    A list silently cut at the column width leaves a panel watching fewer series
    than its author selected while its title still claims all of them.
    """
    from app.views.monitor_analytics import _csv_ids

    raw = ",".join(str(i) for i in range(1, 400))
    out = _csv_ids(raw)
    assert len(out) <= 500
    assert out.split(",")[0] == "1"
    # Every surviving entry is whole — no half-written id at the tail.
    assert all(chunk.isdigit() for chunk in out.split(","))


# --------------------------------------------------------------------------- #
# 10. Chart.js is local                                                        #
# --------------------------------------------------------------------------- #
def test_the_analytics_page_never_pulls_charting_from_a_cdn(app, client):
    """This product installs into isolated management networks.

    A chart that only renders with public internet does not render where it
    matters. Chart.js is vendored; the page must reference the vendored copy.
    """
    _board(app)
    login(client, admin_user_id(app), product=None)
    html = client.get("/monitoring/analytics/").get_data(as_text=True)
    assert "/static/vendor/chart/" in html
    for bad in ("cdn.jsdelivr.net/npm/chart", "unpkg.com/chart", "cdnjs.", "chart.js@"):
        assert bad not in html.lower()


def test_the_analytics_assets_carry_no_cdn_reference():
    """The JS and CSS themselves, not just the page that includes them."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    for rel in ("app/static/js/analytics.js", "app/static/css/analytics.css",
                "app/templates/monitoring/analytics.html",
                "app/templates/monitoring/reports.html",
                "app/templates/monitoring/report_detail.html"):
        text = (root / rel).read_text(encoding="utf-8").lower()
        for bad in ("jsdelivr", "unpkg", "cdnjs"):
            assert bad not in text, "%s references %s" % (rel, bad)


# --------------------------------------------------------------------------- #
# 11. Reports carry their product                                              #
# --------------------------------------------------------------------------- #
def test_a_report_built_in_one_adom_does_not_surface_in_another(app, client):
    from app.extensions import db
    from app.models_analytics import MonitorReport

    with app.app_context():
        start = datetime(2026, 8, 1)
        for product in ("fortiweb", "fortiadc"):
            db.session.add(MonitorReport(
                period="daily", period_start=start,
                period_end=start + timedelta(days=1),
                product=product, title="%s report" % product,
                worst_status="ok"))
        db.session.commit()

    login(client, admin_user_id(app), product="fortiweb")
    rows = client.get("/monitoring/reports/data").get_json()["reports"]
    assert [r["product"] for r in rows] == ["fortiweb"]

    login(client, admin_user_id(app), product="fortiadc")
    rows = client.get("/monitoring/reports/data").get_json()["reports"]
    assert [r["product"] for r in rows] == ["fortiadc"]


def test_a_panel_on_another_adoms_board_is_a_404_not_a_403(app, client):
    """From this page's point of view the panel does not exist."""
    bid = _board(app, slug="adc-board", product="fortiadc")
    pid = _panel(app, bid)
    login(client, admin_user_id(app), product="fortiweb")
    assert client.get("/monitoring/analytics/panel/%d/data" % pid).status_code == 404
    assert client.post("/monitoring/analytics/panel/%d/delete" % pid
                       ).status_code == 404


# --------------------------------------------------------------------------- #
# 12. The scheduled action                                                     #
# --------------------------------------------------------------------------- #
def test_the_report_action_is_in_the_catalog_and_needs_no_targets(app):
    from app.services import scheduled_actions as sa

    spec = next((s for s in sa.ADMIN_ACTIONS if s.key == "monitor_report"), None)
    assert spec is not None, "monitor_report missing from the action catalog"
    # It reads stored rows only, so it must not demand appliance targets —
    # otherwise it cannot be scheduled on an installation whose devices are off.
    assert spec.needs_targets is False


def test_the_report_action_rejects_an_unknown_period(app):
    from app.services import scheduled_actions as sa

    with app.app_context():
        res = sa.run_action("monitor_report", None, {"period": "fortnightly"})
        assert res["ok"] is False
        assert "fortnightly" in res["summary"]


def test_a_failed_email_does_not_fail_the_whole_action(app, monkeypatch):
    """The report is already stored and readable in the console.

    Reporting the run as failed would put the scheduled action into a permanent
    red state over an SMTP outage — and a check that is always red is one the
    operator learns to skip.
    """
    from app.services import scheduled_actions as sa

    _appliance(app)
    monkeypatch.setattr(mr, "email_report",
                        lambda row, **kw: {"ok": False, "detail": "smtp down",
                                           "to": ["a@b.c"]})
    with app.app_context():
        res = sa.run_action("monitor_report", None,
                            {"period": "daily", "email": "1"})
        assert res["ok"] is True
        assert "FAILED" in res["summary"]


def test_regenerating_a_period_replaces_it_instead_of_duplicating(app):
    """Keyed by (period, start, product): a retry updates, never accumulates."""
    from app.models_analytics import MonitorReport

    _appliance(app)
    with app.app_context():
        first = mr.generate("daily", by="one")
        second = mr.generate("daily", by="two")
        assert first.id == second.id
        assert MonitorReport.query.count() == 1
        assert second.generated_by == "two"


def test_prune_keeps_the_newest_reports(app):
    from app.extensions import db
    from app.models_analytics import MonitorReport

    with app.app_context():
        for day in range(1, 8):
            start = datetime(2026, 8, day)
            db.session.add(MonitorReport(
                period="daily", period_start=start,
                period_end=start + timedelta(days=1),
                product="", title="d%d" % day, worst_status="ok"))
        db.session.commit()
        assert mr.prune("daily", 3) == 4
        left = [r.title for r in MonitorReport.query
                .order_by(MonitorReport.period_start).all()]
        assert left == ["d5", "d6", "d7"]


# --------------------------------------------------------------------------- #
# 12b. Every rendered control is actually wired                                #
# --------------------------------------------------------------------------- #
def _asset(rel: str) -> str:
    import pathlib
    return (pathlib.Path(__file__).resolve().parent.parent / rel
            ).read_text(encoding="utf-8")


def test_every_data_act_control_on_the_page_is_inside_the_delegated_scope(app, client):
    """A button that renders, looks enabled and does nothing is worse than none.

    The click handler is delegated from ``document`` and deliberately scoped, so
    this page cannot hijack a ``data-act`` click elsewhere in the console. But
    the page header and the cadence modal are SIBLINGS of ``#an-root``, not
    descendants — their controls were dead until they opted in with
    ``data-an-scope``. This walks the real DOM and fails on any control that is
    in neither container.
    """
    from html.parser import HTMLParser

    _board(app)
    login(client, admin_user_id(app), product=None)
    html = client.get("/monitoring/analytics/").get_data(as_text=True)

    class Walk(HTMLParser):
        def __init__(self):
            super().__init__()
            self.depth_root = None      # depth at which #an-root opened
            self.depth_scope = []       # stack of depths of open data-an-scope
            self.depth = 0
            self.orphans = []

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            self.depth += 1
            if a.get("id") == "an-root":
                self.depth_root = self.depth
            if "data-an-scope" in a:
                self.depth_scope.append(self.depth)
            if "data-act" in a:
                inside_root = (self.depth_root is not None
                               and self.depth >= self.depth_root)
                if not inside_root and not self.depth_scope:
                    self.orphans.append(a["data-act"])

        def handle_endtag(self, tag):
            if self.depth_root == self.depth:
                self.depth_root = None
            if self.depth_scope and self.depth_scope[-1] == self.depth:
                self.depth_scope.pop()
            self.depth -= 1

    w = Walk()
    w.feed(html)
    assert not w.orphans, (
        "these controls render but no handler can ever fire for them: %s"
        % sorted(set(w.orphans)))
    # And the page really does offer the two header controls, so the walk above
    # is not passing merely because it found nothing to check.
    assert 'data-act="cadence"' in html
    assert 'data-act="refresh"' in html


def test_the_delegated_handlers_honour_the_opt_in_marker():
    """Both handlers must use the shared scope test, not a bare containment."""
    js = _asset("app/static/js/analytics.js")
    assert "function inScope(node)" in js
    assert "data-an-scope" in js
    # A bare `root.contains(t)` gate in either handler is the regression.
    assert "if (!t || !root.contains(t)) { return; }" not in js
    assert js.count("inScope(") >= 3   # definition + click + change


# --------------------------------------------------------------------------- #
# 13. The CLI seed plan                                                        #
# --------------------------------------------------------------------------- #
def _cmd_fix():
    """Import the CLI module as a PACKAGE.

    ``cmd_fix`` uses relative imports, so ``spec_from_file_location`` on the
    bare file raises ImportError. ``deploy/`` has to be on the path and the
    module imported as ``satom_cli.cmd_fix``.
    """
    import pathlib
    import sys

    root = pathlib.Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root / "deploy"))
    try:
        from satom_cli import cmd_fix
        return cmd_fix
    finally:
        sys.path.remove(str(root / "deploy"))


def test_the_seed_plan_arms_all_three_report_periods():
    """The Reports page tells the operator this command will arm them.

    If the plan does not carry them, that instruction is a lie — the page would
    keep saying "not scheduled" after the operator did exactly what it asked.
    """
    plan = _cmd_fix().SEED_PLAN
    reports = [row for row in plan if row[0] == "monitor_report"]
    assert {row[2] for row in reports} == {"daily", "weekly", "monthly"}
    assert {row[4]["period"] for row in reports} == {"daily", "weekly", "monthly"}
    # Every report schedule must bound its own history, or a daily row
    # accumulates one report a day forever.
    assert all(row[4].get("keep") for row in reports)


def test_the_seed_plan_identity_distinguishes_rows_of_the_same_action():
    """Three monitor_report rows differ ONLY by schedule.

    The seeder used to key on the action alone. That would arm one period and
    report the other two as already present — the page would still show two
    "not scheduled" chips after a successful seed, with nothing to explain it.
    """
    src = _cmd_fix_source()
    assert "{(row.action, row.schedule_kind) for row in" in src, \
        "seed identity is not (action, schedule_kind)"
    assert "if (key, kind) in have:" in src
    # Newly planned rows must join the set inside the loop, or two rows that
    # share an (action, kind) would both be created.
    assert "have.add((key, kind))" in src


def _cmd_fix_source() -> str:
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    return (root / "deploy" / "satom_cli" / "cmd_fix.py").read_text(encoding="utf-8")


def test_report_schedules_fire_after_their_period_closes():
    """A daily report at 23:00 would summarise a day still an hour from ending.

    All three are scheduled in the small hours, after the window they describe
    has actually closed.
    """
    for key, name, kind, sched, params, product in _cmd_fix().SEED_PLAN:
        if key != "monitor_report":
            continue
        hour = int(sched["time"].split(":")[0])
        assert 0 <= hour <= 5, "%s fires at %s, inside the period it reports" % (
            name, sched["time"])
    # Weekly on Monday, monthly on the 1st: the first day AFTER the period ends.
    rows = {r[2]: r[3] for r in _cmd_fix().SEED_PLAN if r[0] == "monitor_report"}
    assert rows["weekly"]["weekday"] == 0
    assert rows["monthly"]["day"] == 1


# --------------------------------------------------------------------------- #
# 14. Range handling                                                           #
# --------------------------------------------------------------------------- #
def test_an_unknown_range_key_opens_the_board_instead_of_erroring():
    """A stale bookmark should render a dashboard, not an error page."""
    now = datetime(2026, 8, 5, 12, 0)
    start, end, key = ma.range_bounds("nonsense", now=now)
    assert key == ma.DEFAULT_RANGE
    assert end == now and start < end


def test_a_custom_window_is_clamped_to_the_retention_ceiling():
    """Asking for ten years must not build a ten-year axis."""
    frm = datetime(2000, 1, 1)
    to = datetime(2026, 8, 5)
    start, end, key = ma.range_bounds("custom", frm=frm, to=to)
    assert key == "custom"
    assert (end - start).days <= ma.dm.MAX_RANGE_DAYS


def test_the_bucket_grid_is_capped_so_a_bad_range_cannot_exhaust_memory():
    start = datetime(2020, 1, 1)
    end = datetime(2026, 1, 1)
    assert len(ma.grid(start, end, "hour", [[]])) <= 5000
