"""Guards for auto-provisioning scrape targets when a device is added.

Before this, targets appeared only on the next ``metrics_scrape`` sweep — so a
freshly added appliance was silently uncollected for up to a full tick, and on
an install where no scheduled action had been seeded, forever. The failure is
quiet by construction: the Collection page renders ``ScrapeTarget`` rows, so a
device with none is not shown as broken, it is not shown at all.

Each guard below has a matching way to regress silently:
  * drop the call from one creation path (three exist) — the other two still work
  * let the guard drift per caller — a parked/retired device starts collecting
  * let a provisioning error abort the save — the operator loses the device row
  * stop naming uncovered devices — absence reads as coverage
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VIEW = REPO / "app" / "views" / "appliances.py"


def _appliance(name="fwp", kind="fortiweb", host="192.0.2.9",
               maintenance=False):
    from app.models import Appliance, db
    a = Appliance(name=name, host=host, username="admin", kind=kind,
                  maintenance=maintenance)
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


# ── the eligibility rule lives in ONE place ──────────────────────────────────

def test_a_parked_device_gets_no_targets(app):
    """maintenance already suppresses scheduled runs and alerts; provisioning
    must agree, or the page grows rows for a device nobody expects to answer."""
    from app.services import metrics_collect as mc
    with app.app_context():
        a = _appliance(name="parked", maintenance=True)
        assert mc.provisionable(a) is False
        assert mc.ensure_targets(a) == 0


def test_a_retired_device_gets_no_targets(app):
    """A retired row keeps its history but has its host neutralised to
    ``*.invalid`` so nothing can reach the machine that now owns that IP."""
    from app.services import metrics_collect as mc
    with app.app_context():
        a = _appliance(name="gone", host="retired-gone.invalid")
        assert mc.provisionable(a) is False
        assert mc.ensure_targets(a) == 0


def test_a_device_without_a_host_gets_no_targets(app):
    from app.services import metrics_collect as mc
    with app.app_context():
        a = _appliance(name="hostless", host="")
        assert mc.provisionable(a) is False
        assert mc.ensure_targets(a) == 0


def test_a_live_device_is_provisioned(app):
    from app.services import metrics_collect as mc
    with app.app_context():
        a = _appliance(name="live")
        assert mc.provisionable(a) is True
        assert mc.ensure_targets(a) == len(mc.collectors_for("fortiweb"))


def test_clearing_maintenance_makes_a_device_collectable(app):
    """The edit path re-provisions: a device parked at creation and released
    later must not need a sweep (or a human) to start being collected."""
    from app.models import db
    from app.services import metrics_collect as mc
    with app.app_context():
        a = _appliance(name="released", maintenance=True)
        assert mc.ensure_targets(a) == 0
        a.maintenance = False
        db.session.commit()
        assert mc.ensure_targets(a) > 0


# ── every appliance-creation path provisions ─────────────────────────────────

def _calls_in(func_name: str) -> list:
    """Names called inside a top-level function of the appliances view."""
    tree = ast.parse(VIEW.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return [n.func.id for n in ast.walk(node)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
    raise AssertionError("no function %r in %s" % (func_name, VIEW))


def test_create_provisions_monitoring():
    assert "_provision_monitoring" in _calls_in("create")


def test_edit_provisions_monitoring():
    assert "_provision_monitoring" in _calls_in("edit_save")


def test_cluster_member_add_provisions_metrics():
    """A member node is a real appliance with its own host and credentials —
    it is collected like any other device, not through its node 0."""
    tree = ast.parse(VIEW.read_text())
    names = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    member = [n for n in names if "member" in n and "add" in n]
    assert member, "no cluster-member-add function found in %s" % VIEW
    assert any("_provision_monitoring" in _calls_in(n) for n in member)


def test_provisioning_failure_cannot_lose_the_device(app):
    """Monitoring is downstream of inventory. If provisioning raises, the
    helper swallows it — the appliance the operator just typed in must
    survive.

    Since 2026-08-06 the helper returns a DICT of both halves, and a failure in
    one half is reported in ``errors`` rather than silently returning zero:
    a half-monitored device looks exactly like a monitored one.
    """
    from app.views import appliances as av
    from app.services import metrics_collect as mc
    with app.app_context():
        a = _appliance(name="survivor")
        orig = mc.ensure_targets
        mc.ensure_targets = lambda _a: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            out = av._provision_monitoring(a)        # no exception escapes
            assert out["targets"] == 0
            assert out["errors"], "the failure was swallowed silently"
        finally:
            mc.ensure_targets = orig


# ── a device that yields nothing is NAMED, not omitted ───────────────────────

def test_a_product_with_no_collectors_is_reported_not_hidden(app):
    """A no-op that shows up nowhere is indistinguishable from success.

    Originally written against FortiAnalyzer, which had no collectors. It has
    one since 2026-08-06, so the guard now uses a product the registry does not
    know: the rule being protected is the MECHANISM — any device that yields
    no targets must be NAMED with the reason — not the coverage status of one
    particular product, which is expected to change.
    """
    from app.services import metrics_collect as mc
    with app.app_context():
        unknown = "fortiproxy"
        assert mc.collectors_for(unknown) == [], (
            "%s gained collectors; pick another uncovered kind" % unknown)
        dev = _appliance(name="ghost", kind=unknown, host="192.0.2.12")
        assert mc.ensure_targets(dev) == 0
        gaps = {g["name"]: g["reason"] for g in mc.coverage_gaps([dev])}
        assert "ghost" in gaps and unknown in gaps["ghost"]


def test_every_real_product_now_has_at_least_one_collector(app):
    """The counterpart of the guard above: FortiAnalyzer used to yield nothing
    at all, which meant a log collector could sit in the fleet completely
    unmeasured. Every product the ADOM registry ships must now produce targets."""
    from app.services import metrics_collect as mc
    from app.services.product_scope import concrete_products
    for key in concrete_products():
        assert mc.collectors_for(key), (
            "product %r has no collectors — a device of that kind would be "
            "onboarded and never measured" % key)


def test_a_provisioned_device_is_not_a_gap(app):
    from app.services import metrics_collect as mc
    with app.app_context():
        a = _appliance(name="covered")
        mc.ensure_targets(a)
        assert mc.coverage_gaps([a]) == []


def test_gap_reasons_distinguish_parked_from_unprovisioned(app):
    """"Nothing to collect" and "nothing is being collected" are different
    operator actions — one reason string for both would hide that."""
    from app.services import metrics_collect as mc
    with app.app_context():
        parked = _appliance(name="gp", maintenance=True)
        fresh = _appliance(name="gf", host="192.0.2.13")
        reasons = {g["name"]: g["reason"] for g in mc.coverage_gaps([parked, fresh])}
        assert reasons["gp"] != reasons["gf"]
        assert "maintenance" in reasons["gp"]


def test_collection_page_exposes_the_gaps(app, client):
    """Guarded at the payload, not only in the template: the JSON feed is what
    the auto-refresh re-renders from."""
    from tests.conftest import admin_user_id, login
    with app.app_context():
        _appliance(name="uncovered-faz", kind="fortianalyzer",
                   host="192.0.2.14")
    login(client, admin_user_id(app), product=None)
    r = client.get("/monitoring/collection/data")
    assert r.status_code == 200
    body = r.get_json()
    assert "gaps" in body
    assert any(g["name"] == "uncovered-faz" for g in body["gaps"])
