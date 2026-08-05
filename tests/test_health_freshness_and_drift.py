"""Two false-alert engines: cache freshness and config drift.

Both bugs shipped in the same week and share one shape — a check that CANNOT
report the truth, so it settles on a permanent complaint. This repo has already
had to delete three of those (``satom-ha-datasync`` inert on the primary, the
status-word colouring, ``diagnose nginx`` on standalone). A check that always
complains is a check the operator learns to skip, and then the one that matters
is skipped with it.

Bug 1 -- ``device_health.cache_meta`` (2026-08-05). The loop read

    for layer in ("deep", "config"):
        meta = read_layer._layer_meta(appliance.id, layer=layer) or {}
        if meta:
            return meta

but ``_layer_meta`` ALWAYS returns a four-key dict (``cached: False`` when there
is no snapshot), and a dict with keys is truthy -- so ``config`` was
unreachable. Consequences, both false:
  * FortiWeb graded its ``deep`` layer, refreshed once a night by
    ``deep_capture`` (03:30), against ``monitoring.stale_hours`` (6 h), which is
    the cadence of the HOURLY sync. That counter is red 18 hours out of every
    24 on a perfectly healthy box.
  * FortiADC / FortiAnalyzer / FortiAuthenticator have no ``deep`` layer AT ALL
    (``deep_capture`` is FortiWeb-only by design), so they reported "no cached
    configuration" forever while holding a config snapshot minutes old.

Bug 2 -- ``alerts._check_drift`` (same day). It diffed the last two git commits
of ``reports/<slug>/_config.json``. The source of truth left git that morning
(``data/sot``, content-addressed), so git saw a DELETION and the check read it
as "somebody edited the device" -- 15 alerts from one refactor commit. It also
never filtered ``maintenance``, so retired boxes whose host is ``*.invalid``
kept alerting.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.models import Appliance, db
from app.models_cache import DeviceSnapshot
from app.models_sot import SotVersion
from app.services import alerts
from app.services import device_health as dh


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _mk(name="dev1", kind="fortiweb", maintenance=False):
    a = Appliance(name=name, host="192.0.2.99", port=443, kind=kind,
                  username="admin", maintenance=maintenance)
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


def _snap(aid, layer, minutes_ago):
    db.session.add(DeviceSnapshot(
        appliance_id=aid, layer=layer, section="_all", source="live",
        generated_at=datetime.utcnow() - timedelta(minutes=minutes_ago)))
    db.session.commit()


def _sot(device, minutes_ago, sha):
    ts = datetime.utcnow() - timedelta(minutes=minutes_ago)
    db.session.add(SotVersion(device=device, sha256=sha, size_raw=10,
                              size_gz=5, total_objects=1, section_count=1,
                              source="harvest", taken_at=ts, last_seen_at=ts))
    db.session.commit()


# --------------------------------------------------------------------------
# Bug 1 -- cache freshness
# --------------------------------------------------------------------------

def test_a_device_with_only_a_config_layer_is_not_reported_uncached(app):
    """FortiADC/FAZ/FAC never get a deep layer. Fresh config must still count."""
    with app.app_context():
        a = _mk("fac01", kind="fortiauthenticator")
        _snap(a.id, "config", minutes_ago=5)

        meta = dh.cache_meta(a)
        assert meta.get("cached") is True, \
            "config-only device must report cached, got %r" % (meta,)
        assert dh.cache_signal(meta, 6)["status"] == "ok"


def test_the_newest_layer_wins_not_merely_the_deep_one(app):
    """Nightly deep + hourly config: freshness is the NEWEST thing we hold."""
    with app.app_context():
        a = _mk("fortiweb08")
        _snap(a.id, "deep", minutes_ago=18 * 60)     # last night's sweep
        _snap(a.id, "config", minutes_ago=56)        # this hour's sync

        meta = dh.cache_meta(a)
        age_min = (datetime.utcnow() - meta["generated_at"]).total_seconds() / 60
        assert age_min < 90, \
            "graded the nightly deep layer (%.0f min) instead of the hourly " \
            "config layer" % age_min
        assert dh.cache_signal(meta, 6)["status"] == "ok"


def test_nothing_cached_still_reports_uncached(app):
    """The warn path must survive the fix -- absence is never health."""
    with app.app_context():
        a = _mk("dark-box")
        assert dh.cache_meta(a).get("cached") is not True
        assert dh.cache_signal(dh.cache_meta(a), 6)["status"] == "warn"


def test_a_genuinely_stale_device_still_grades_stale(app):
    with app.app_context():
        a = _mk("old-box")
        _snap(a.id, "config", minutes_ago=40 * 60)
        assert dh.cache_signal(dh.cache_meta(a), 6)["status"] == "crit"


# --------------------------------------------------------------------------
# Bug 2 -- config drift
# --------------------------------------------------------------------------

def test_drift_never_shells_out_to_git(app, monkeypatch):
    """The source of truth left git. A drift check that still reads git
    history reports refactors as device edits -- which is exactly what
    produced 15 alerts from one commit."""
    with app.app_context():
        import subprocess

        def boom(*a, **kw):  # noqa: ANN001
            raise AssertionError("drift must not read git history")

        monkeypatch.setattr(subprocess, "run", boom)
        a = _mk("dev-git")
        _sot("dev-git", minutes_ago=200, sha="a" * 64)
        _sot("dev-git", minutes_ago=5, sha="b" * 64)

        out = alerts._check_drift()
        assert any("dev-git" in f["key"] for f in out)


def test_a_new_sot_version_inside_the_window_is_drift(app):
    with app.app_context():
        _mk("dev-drift")
        _sot("dev-drift", minutes_ago=200, sha="c" * 64)
        _sot("dev-drift", minutes_ago=5, sha="d" * 64)

        out = alerts._check_drift()
        hits = [f for f in out if "dev-drift" in f["key"]]
        assert len(hits) == 1
        # keyed by content hash so each distinct drift fires exactly once
        assert "d" * 12 in hits[0]["key"]
        assert hits[0]["product"] == "fortiweb"


def test_the_first_ever_version_is_not_drift(app):
    """Onboarding a device is not somebody editing it behind our back."""
    with app.app_context():
        _mk("dev-new")
        _sot("dev-new", minutes_ago=5, sha="e" * 64)
        assert not [f for f in alerts._check_drift() if "dev-new" in f["key"]]


def test_a_change_older_than_the_window_does_not_alert(app):
    with app.app_context():
        _mk("dev-old")
        _sot("dev-old", minutes_ago=5000, sha="f" * 64)
        _sot("dev-old", minutes_ago=4000, sha="0" * 64)
        assert not [f for f in alerts._check_drift() if "dev-old" in f["key"]]


def test_maintenance_suppresses_drift(app):
    """``maintenance`` is the documented lever for parking a broken box. It
    already suppresses scheduled runs and device health; drift ignored it, so
    the four retired appliances (host ``*.invalid``) kept alerting."""
    with app.app_context():
        _mk("dev-parked", maintenance=True)
        _sot("dev-parked", minutes_ago=200, sha="1" * 64)
        _sot("dev-parked", minutes_ago=5, sha="2" * 64)
        assert not [f for f in alerts._check_drift() if "dev-parked" in f["key"]]


def test_the_exclude_list_still_works(app):
    """faz01 is excluded by default -- that lever must survive the rewrite."""
    with app.app_context():
        _mk("faz01", kind="fortianalyzer")
        _sot("faz01", minutes_ago=200, sha="3" * 64)
        _sot("faz01", minutes_ago=5, sha="4" * 64)
        assert not [f for f in alerts._check_drift() if "faz01" in f["key"]]


def test_a_device_with_no_sot_rows_is_silent(app):
    with app.app_context():
        _mk("dev-empty")
        assert not [f for f in alerts._check_drift() if "dev-empty" in f["key"]]
