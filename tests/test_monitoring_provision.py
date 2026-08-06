"""Guards for the single provisioning seam (Fase 1).

The failure these prevent is not a crash. It is a device that looks monitored
on every page while half its monitoring was never created — and its mirror
image, a baseline that silently grows per *policy* instead of per *device*.
"""
import ast
import inspect
from pathlib import Path

import pytest

from app.models import Appliance, MonitorProbe, db
from app.models_metrics import ScrapeTarget
from app.services import deep_monitor as dm
from app.services import metrics_collect as mc
from app.services.monitoring_provision import provision_monitoring

ROOT = Path(__file__).resolve().parent.parent


def _mk(session, name="dev1", kind="fortiweb", host="192.0.2.10",
        maintenance=False):
    a = Appliance(name=name, kind=kind, host=host, username="u",
                  maintenance=maintenance)
    a.password = "pw"          # setter encrypts; password_enc is NOT NULL
    session.add(a)
    session.commit()
    return a


# ── the scale rule ───────────────────────────────────────────────────────────

def _baseline_kinds():
    """Kinds ensure_baseline can create, read from its source, not a copy."""
    src = inspect.getsource(dm.ensure_baseline)
    tree = ast.parse(src.lstrip())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Tuple) and node.elts:
            first = node.elts[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                found.add(first.value)
    return found & set(dm.KIND_PRODUCTS)


def test_the_baseline_never_creates_a_per_policy_probe():
    """A per-policy kind in the baseline is the 40 000-row failure.

    ``API_KINDS`` are per *server policy*: at 10 000 policies one of these in
    the baseline is 10 000 rows and 10 000 device calls per sweep. They are
    created deliberately, from Discover, by an operator who picked the
    policies. Per-DEVICE kinds are fine — fifty devices cost two hundred rows.
    """
    leaked = _baseline_kinds() & set(dm.API_KINDS)
    assert not leaked, (
        "ensure_baseline would auto-create per-policy probe kind(s) %s — "
        "that is one row per policy, not per device" % sorted(leaked))


def test_the_baseline_guard_is_not_vacuous():
    """If the extractor stops seeing kinds, the guard above passes for free."""
    assert _baseline_kinds(), "extractor found no baseline kinds at all"


# ── the seam ─────────────────────────────────────────────────────────────────

def test_provisioning_creates_both_halves(app):
    with app.app_context():
        a = _mk(db.session)
        out = provision_monitoring(a)
        targets = ScrapeTarget.query.filter_by(appliance_id=a.id).count()
        probes = MonitorProbe.query.filter_by(appliance_id=a.id).count()
        assert targets > 0, "no scrape targets — the time-series half is missing"
        assert probes > 0, "no baseline probes — the THRESHOLD half is missing"
        assert out["targets"] == targets
        assert not out["errors"]


def test_provisioning_is_idempotent(app):
    with app.app_context():
        a = _mk(db.session, name="dev2")
        provision_monitoring(a)
        t1 = ScrapeTarget.query.filter_by(appliance_id=a.id).count()
        p1 = MonitorProbe.query.filter_by(appliance_id=a.id).count()
        second = provision_monitoring(a)
        assert second["targets"] == 0 and second["probes"] == []
        assert ScrapeTarget.query.filter_by(appliance_id=a.id).count() == t1
        assert MonitorProbe.query.filter_by(appliance_id=a.id).count() == p1


@pytest.mark.parametrize("host,maint,why", [
    ("192.0.2.11", True, "parked"),
    ("retired-x.invalid", False, "retired"),
])
def test_a_parked_or_retired_device_provisions_nothing(app, host, maint, why):
    """Same guard the sweep applies. Provisioning a parked device would put
    permanently-red rows on the page and teach the operator to ignore it."""
    with app.app_context():
        a = _mk(db.session, name="dev-" + why, host=host, maintenance=maint)
        out = provision_monitoring(a)
        assert out["targets"] == 0 and out["probes"] == []
        assert ScrapeTarget.query.filter_by(appliance_id=a.id).count() == 0
        assert MonitorProbe.query.filter_by(appliance_id=a.id).count() == 0


def test_one_half_failing_still_provisions_the_other(app, monkeypatch):
    """A device that is half-monitored looks exactly like one that is fully
    monitored, so the surviving half must still be created AND the failure
    must be reported rather than swallowed."""
    with app.app_context():
        a = _mk(db.session, name="dev-half")
        monkeypatch.setattr(mc, "ensure_targets",
                            lambda ap: (_ for _ in ()).throw(RuntimeError("boom")))
        out = provision_monitoring(a)
        assert out["errors"], "the failure was swallowed"
        assert MonitorProbe.query.filter_by(appliance_id=a.id).count() > 0, (
            "the healthy half was not provisioned")


# ── the wiring ───────────────────────────────────────────────────────────────

def test_every_appliance_creation_path_provisions_monitoring():
    """Three creation paths. Until 2026-08-06 they called a metrics-only
    helper, so a device added through the form had no thresholds at all."""
    src = (ROOT / "app" / "views" / "appliances.py").read_text()
    # def + three call sites
    assert src.count("_provision_monitoring(") >= 4, src.count(
        "_provision_monitoring(")

    # Not the NAME — the BEHAVIOUR. A helper that keeps the name and calls the
    # metrics half only is precisely the regression being guarded against, and
    # a name check passes straight through it (caught by mutation, 2026-08-06).
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef)
              and n.name == "_provision_monitoring")
    calls = {n.func.id for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "provision_monitoring" in calls, (
        "_provision_monitoring does not reach the shared seam — it is "
        "provisioning one subsystem behind the other's name")
    attr_calls = {n.func.attr for n in ast.walk(fn)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert "ensure_targets" not in attr_calls, (
        "the view calls a subsystem directly, bypassing the seam")


def test_the_seam_calls_both_subsystems():
    """Grepping the name is not enough: the seam must actually invoke both."""
    tree = ast.parse(inspect.getsource(provision_monitoring).lstrip())
    called = {n.func.attr for n in ast.walk(tree)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert "ensure_targets" in called, "time-series half not called"
    assert "ensure_baseline" in called, "threshold half not called"
