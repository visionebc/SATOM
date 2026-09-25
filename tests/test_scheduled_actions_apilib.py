"""The ``apilib_harvest`` scheduled action: declared, dispatched, NOT seeded.

It is the safety net behind the firmware probe's trigger. Declared like its
fleet-sweep peers (admin scope, no targets, ok = the round ran), dry-run
capable, and deliberately absent from the install seed plan: enabling it on a
production node is an operator decision, not a side effect of an upgrade.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Appliance
from app.services import api_library as lib
from app.services import apilib_harvest as ah
from app.services import scheduled_actions as sa

KEY = "apilib_harvest"


@pytest.fixture(autouse=True)
def _private_stores(tmp_path, monkeypatch):
    """A job ledger and a rediscovery tree per TEST. The session-wide ones
    outlive each test's database, and appliance ids restart at 1 in every
    fresh DB: a pending harvest left by one test would dedup the next."""
    monkeypatch.setenv("SATOM_JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("SATOM_REDISCOVERY_DIR", str(tmp_path / "rediscovery"))


@pytest.fixture()
def ctx(app):
    with app.app_context():
        yield app


def _ap(name, kind="fortiweb", firmware="FortiWeb-KVM 7.6.8,build1128", maintenance=False):
    a = Appliance(name=name, kind=kind, host=f"{name}.test", port=443,
                  username="admin", verify_ssl=False, firmware=firmware,
                  maintenance=maintenance)
    a.password = "secret"
    db.session.add(a)
    db.session.commit()
    return a


def _measure(product, version, source="sweep"):
    lib.ingest({"product": product, "source": source,
                "captured_at": "2026-09-01T00:00:00", "origin_ref": "t:%s" % version,
                "device": None, "scope": {"kind": "build", "version": version, "build": ""},
                "healthy": True, "skip_reason": "",
                "endpoints": {"admin": {"urn": "/x", "section": "s", "verdict": "ok",
                                        "rows": 0, "fields": None}}})


# --------------------------------------------------------------------------
# declaration
# --------------------------------------------------------------------------

def test_the_action_is_declared_like_its_fleet_sweep_peers():
    spec = sa.get_spec(KEY)
    assert spec is not None
    assert spec in sa.ADMIN_ACTIONS and spec not in sa.USER_ACTIONS
    assert spec.scope == "admin"
    assert spec.label == "API library — harvest appliances whose build has no evidence"
    assert spec.needs_targets is False
    assert spec.danger is False and spec.requires_change_request is False
    assert spec.forced_schedule_kind == ""
    # Offered only in the ADOMs it can harvest; FAZ has no live harvester.
    assert set(spec.products) == set(ah.LIVE_SOURCE)
    assert spec.summary


def test_it_is_dispatched_by_run_action(ctx, monkeypatch):
    seen = []
    monkeypatch.setattr(sa, "_do_apilib_harvest",
                        lambda params, dry_run=False: seen.append((params, dry_run))
                        or {"ok": True, "summary": "s", "log": ""})
    out = sa.run_action(KEY, None, {"x": 1}, dry_run=True)
    assert out["ok"] is True
    assert seen == [({"x": 1}, True)]


def test_it_is_declared_but_not_seeded_into_production():
    """Declared only. The installer's seed plan and its check list must not
    carry it — that would schedule device reads on every node that upgrades."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
    from satom_cli import cmd_checks, cmd_fix
    assert KEY not in {row[0] for row in cmd_fix.SEED_PLAN}
    assert KEY not in set(cmd_checks.MIN_ACTIONS)


def test_it_is_an_admin_action_to_the_views(ctx):
    from app.models import ScheduledAction
    from app.views import scheduled_actions as v
    assert v.effective_scope(ScheduledAction(name="x", action=KEY, scope="")) == "admin"


# --------------------------------------------------------------------------
# behaviour
# --------------------------------------------------------------------------

@pytest.fixture()
def fleet(ctx):
    """One box per case the round must tell apart."""
    _measure("fortiweb", "7.6.8")
    return {
        "measured": _ap("fw-measured"),                                   # has evidence
        "fresh": _ap("fw-fresh", firmware="FortiWeb-KVM 8.0.3,build0093"),
        "adc": _ap("adc-fresh", kind="fortiadc", firmware="8.0.3"),
        "fac": _ap("fac-fresh", kind="fortiauthenticator",
                   firmware="FACVMKVM v6.6.1, build1234 (GA)"),
        "parked": _ap("fw-parked", firmware="FortiWeb 8.0.5,build1", maintenance=True),
        "faz": _ap("faz-1", kind="fortianalyzer", firmware="v7.4.2-build2100"),
        "unknown": _ap("fw-unknown", firmware=None),
    }


def test_dry_run_lists_what_would_be_harvested_and_contacts_nothing(ctx, fleet, monkeypatch):
    monkeypatch.setattr(ah, "run", lambda aid: pytest.fail("dry-run harvested %s" % aid))
    out = sa.run_action(KEY, None, {}, dry_run=True)
    assert out["ok"] is True, out
    assert out["summary"].startswith("[dry-run] would harvest 3 appliance(s)")
    assert "in maintenance, skipped: fw-parked" in out["summary"]
    names = [line.split(" ")[0] for line in out["log"].splitlines()]
    assert names == ["fw-fresh", "adc-fresh", "fac-fresh"]


def test_a_round_harvests_only_the_unmeasured_builds(ctx, fleet, monkeypatch):
    ran = []

    def _run(aid):
        ran.append(aid)
        ok = aid != fleet["adc"].id
        return {"ok": ok, "msg": "harvested" if ok else "device refused"}

    monkeypatch.setattr(ah, "run", _run)
    out = sa.run_action(KEY, None, {}, dry_run=False)
    assert ran == [fleet["fresh"].id, fleet["adc"].id, fleet["fac"].id]
    # ok = THE ROUND RAN; the failure is named, not a red action.
    assert out["ok"] is True
    assert out["summary"].startswith("2/3 appliance(s) harvested (failed: adc-fresh)")
    assert "in maintenance, skipped: fw-parked" in out["summary"]
    assert "[FAIL] adc-fresh: device refused" in out["log"]
    assert "[ok] fw-fresh: harvested" in out["log"]


def test_a_queued_harvest_is_not_run_twice(ctx, fleet, monkeypatch):
    ctx.config[ah.DISPATCH_CONFIG] = True
    monkeypatch.setattr(ah, "_dispatch", lambda *a: None)   # stays pending
    assert ah.enqueue(fleet["fresh"].id, "firmware_change:7.6.8->8.0.3")["queued"]
    ran = []
    monkeypatch.setattr(ah, "run", lambda aid: ran.append(aid) or {"ok": True, "msg": ""})
    out = sa.run_action(KEY, None, {}, dry_run=False)
    assert fleet["fresh"].id not in ran
    assert "harvest already queued: fw-fresh" in out["summary"]


def test_nothing_to_do_is_ok_and_says_so(ctx, monkeypatch):
    _measure("fortiweb", "7.6.8")
    _ap("fw-done")
    monkeypatch.setattr(ah, "run", lambda aid: pytest.fail("nothing to harvest"))
    out = sa.run_action(KEY, None, {}, dry_run=False)
    assert out["ok"] is True
    assert out["summary"].startswith("Nothing to harvest")
