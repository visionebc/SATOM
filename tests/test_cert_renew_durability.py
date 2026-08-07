"""Durability of the certificate-renewal journal.

The journal itself is node-local ON PURPOSE (a standby's Postgres is read-only,
and ``data/`` is pulled by the datasync with ``rsync --delete``, so anything the
STANDBY writes under ``data/`` is erased within 5 minutes). That gives
visibility but no durability: lose the standby's disk and its journal is gone.

These tests pin the archiver that closes that gap — the PRIMARY pulls the peer's
journal over the existing authenticated peer channel and appends it under
``data/`` (which the primary owns, so the datasync propagates it *to* the
standby instead of deleting it).

Everything here is behavioural: fake peer, real files in tmp, assert on what the
API answers. Nothing asserts on source text.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.services import cert_renew_log as jrn
from app.services import self_update as su
from tests.conftest import login, make_user, profile_id

NOW = datetime(2026, 8, 7, 12, 0, 0, tzinfo=timezone.utc)
PEER_HOST = "192.0.2.249"


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _at(**delta) -> str:
    return _iso(NOW - timedelta(**delta))


def _run(at, status=None, error="", summary="nightly pass"):
    return {"at": at, "node": "peer-b", "role": "standby", "channel": jrn.CH_TIMER,
            "status": status or jrn.OK_SKIPPED, "summary": summary, "error": error,
            "by": "timer", "days_left": 40, "not_after": "2026-11-01T00:00:00+00:00"}


@pytest.fixture()
def arch(tmp_path, monkeypatch):
    """Redirect the archive AND the node-local journal into tmp, and freeze the
    clock. Without this the suite would append to the live archive under
    /opt/satom/data (the job-ledger contamination lesson)."""
    d = tmp_path / "cert-renew-archive"
    monkeypatch.setattr(jrn, "ARCHIVE_DIR", d)
    monkeypatch.setattr(jrn, "STATE", tmp_path / "state")
    monkeypatch.setattr(jrn, "JOURNAL", tmp_path / "state" / "cert-renew.jsonl")
    monkeypatch.setattr(jrn, "_utcnow", lambda: NOW)
    return d


def _peer(monkeypatch, runs, reachable=True, error="peer answered nothing (unreachable)"):
    """Stand in for the HTTPS peer probe. ``runs`` newest-first, like the real
    /healthz/cert-renewals payload."""
    def _pv(host, limit=100, timeout=2.5):
        if not reachable:
            return {"reachable": False, "is_self": False, "secure": False,
                    "host": host, "cert": {}, "summary": {}, "runs": [], "error": error}
        return {"reachable": True, "is_self": False, "secure": True, "host": host,
                "cert": {"days_left": 40}, "summary": {"node": "peer-b"},
                "runs": [dict(r) for r in runs], "error": ""}
    monkeypatch.setattr(jrn, "peer_view", _pv)


def _clock(monkeypatch, when):
    monkeypatch.setattr(jrn, "_utcnow", lambda: when)


# --------------------------------------------------------------------------- #
# 1) the pull itself                                                          #
# --------------------------------------------------------------------------- #
def test_pull_archives_the_peer_journal(arch, monkeypatch):
    runs = [_run(_at(minutes=10)), _run(_at(minutes=70)), _run(_at(minutes=130))]
    _peer(monkeypatch, runs)

    res = jrn.pull_peer(PEER_HOST, "peer-b", force=True)

    assert res["ok"] is True
    assert res["added"] == 3
    hist = jrn.archived_history("peer-b")
    assert len(hist) == 3
    assert hist[0]["at"] == runs[0]["at"]          # newest first, like history()
    assert arch.exists()                            # it landed under the archive dir


def test_second_pull_of_the_same_attempts_does_not_duplicate(arch, monkeypatch):
    runs = [_run(_at(minutes=10)), _run(_at(minutes=70)), _run(_at(minutes=130))]
    _peer(monkeypatch, runs)
    jrn.pull_peer(PEER_HOST, "peer-b", force=True)

    again = jrn.pull_peer(PEER_HOST, "peer-b", force=True)
    assert again["added"] == 0
    assert len(jrn.archived_history("peer-b")) == 3

    # A new attempt shifts every old one to a new position in the payload. An
    # identity derived from position/order would re-append all of them.
    newer = _run(_at(minutes=1), summary="fresh pass")
    _peer(monkeypatch, [newer] + runs)
    third = jrn.pull_peer(PEER_HOST, "peer-b", force=True)
    assert third["added"] == 1
    assert len(jrn.archived_history("peer-b")) == 4


def test_attempts_differing_only_in_error_text_are_both_kept(arch, monkeypatch):
    a = _run(_at(minutes=5), status=jrn.OK_ERROR, error="connection refused")
    b = dict(a, error="certificate has expired")
    _peer(monkeypatch, [a, b])

    jrn.pull_peer(PEER_HOST, "peer-b", force=True)

    errs = sorted(h["error"] for h in jrn.archived_history("peer-b"))
    assert errs == ["certificate has expired", "connection refused"]


# --------------------------------------------------------------------------- #
# 2) a failed pull must read as a failed pull                                 #
# --------------------------------------------------------------------------- #
def test_failed_pull_is_recorded_and_does_not_erase_history(arch, monkeypatch):
    _peer(monkeypatch, [_run(_at(minutes=10)), _run(_at(minutes=70))])
    jrn.pull_peer(PEER_HOST, "peer-b", force=True)

    fail_at = NOW + timedelta(minutes=30)
    _clock(monkeypatch, fail_at)
    _peer(monkeypatch, [], reachable=False)
    res = jrn.pull_peer(PEER_HOST, "peer-b", force=True)

    assert res["ok"] is False
    assert res["error"]
    st = jrn.archive_status("peer-b")
    assert st["entries"] == 2                       # archived history preserved
    assert st["ok"] is False
    assert st["state"] == "failing"
    assert st["fail_streak"] == 1
    assert st["unreachable_since"] == _iso(fail_at)
    assert st["last_success_at"] == _iso(NOW)
    assert st["last_success_age_s"] == 1800


def test_unreachable_peer_never_pulled_is_not_reported_as_no_failures(arch, monkeypatch):
    _peer(monkeypatch, [], reachable=False)

    res = jrn.pull_peer(PEER_HOST, "peer-b", force=True)

    assert res["ok"] is False
    st = jrn.archive_status("peer-b")
    assert st["entries"] == 0
    # "I have no records" must NOT be answerable as "the peer has no failures".
    assert st["ok"] is False
    assert st["state"] == "failing"
    assert st["last_success_at"] is None
    assert st["last_success_age_s"] is None


def test_status_of_a_peer_never_pulled_is_unknown_not_ok(arch):
    st = jrn.archive_status("peer-b")
    assert st["ok"] is False
    assert st["state"] == "never"
    assert st["entries"] == 0
    assert st["last_success_at"] is None


def test_unreachable_since_is_the_first_failure_of_the_streak(arch, monkeypatch):
    _peer(monkeypatch, [_run(_at(hours=2))])
    jrn.pull_peer(PEER_HOST, "peer-b", force=True)

    _peer(monkeypatch, [], reachable=False)
    stamps = [NOW + timedelta(minutes=m) for m in (10, 20, 30)]
    for t in stamps:
        _clock(monkeypatch, t)
        jrn.pull_peer(PEER_HOST, "peer-b", force=True)

    st = jrn.archive_status("peer-b")
    assert st["fail_streak"] == 3
    assert st["unreachable_since"] == _iso(stamps[0])     # since the FIRST, not the last


def test_a_success_after_failures_clears_the_streak(arch, monkeypatch):
    _peer(monkeypatch, [], reachable=False)
    _clock(monkeypatch, NOW)
    jrn.pull_peer(PEER_HOST, "peer-b", force=True)

    back = NOW + timedelta(minutes=15)
    _clock(monkeypatch, back)
    _peer(monkeypatch, [_run(_at(hours=1))])
    jrn.pull_peer(PEER_HOST, "peer-b", force=True)

    st = jrn.archive_status("peer-b")
    assert st["fail_streak"] == 0
    assert st["unreachable_since"] is None
    assert st["state"] == "ok"


# --------------------------------------------------------------------------- #
# 3) counterweight — a healthy pair must stay quiet                           #
# --------------------------------------------------------------------------- #
def test_healthy_pair_stays_quiet(arch, monkeypatch):
    _peer(monkeypatch, [_run(_at(hours=1), status=jrn.OK_RENEWED), _run(_at(days=1))])
    jrn.pull_peer(PEER_HOST, "peer-b", force=True)

    st = jrn.archive_status("peer-b")
    assert st["state"] == "ok"
    assert st["ok"] is True
    assert st["stale"] is False
    assert st["fail_streak"] == 0
    assert st["unreachable_since"] is None
    assert jrn.durability_alerts([{"name": "peer-b", "archive": st}], role="primary") == []


def test_a_stale_archive_is_reported_stale(arch, monkeypatch):
    _peer(monkeypatch, [_run(_at(hours=1))])
    jrn.pull_peer(PEER_HOST, "peer-b", force=True)

    _clock(monkeypatch, NOW + timedelta(days=2))
    st = jrn.archive_status("peer-b")
    assert st["stale"] is True
    assert st["state"] == "stale"
    assert st["ok"] is False
    assert st["last_success_age_s"] >= 2 * 86400
    assert jrn.durability_alerts([{"name": "peer-b", "archive": st}], role="primary")


# --------------------------------------------------------------------------- #
# 4) retention — the archive must be bounded, and stay bounded                #
# --------------------------------------------------------------------------- #
def test_archive_is_capped_by_entry_count(arch, monkeypatch):
    monkeypatch.setattr(jrn, "ARCHIVE_MAX_ENTRIES", 10)
    runs = [_run(_at(minutes=i), summary="run-%d" % i) for i in range(1, 26)]
    _peer(monkeypatch, runs)

    jrn.pull_peer(PEER_HOST, "peer-b", force=True)

    hist = jrn.archived_history("peer-b", limit=100)
    assert len(hist) == 10
    kept = {h["summary"] for h in hist}
    assert "run-1" in kept                          # newest survives
    assert "run-25" not in kept                     # oldest is dropped
    assert jrn.archive_status("peer-b")["entries"] == 10


def test_records_older_than_the_age_bound_are_dropped(arch, monkeypatch):
    monkeypatch.setattr(jrn, "ARCHIVE_MAX_AGE_DAYS", 30)
    _peer(monkeypatch, [_run(_at(days=1), summary="fresh"),
                        _run(_at(days=90), summary="ancient")])

    res = jrn.pull_peer(PEER_HOST, "peer-b", force=True)
    assert res["added"] == 1
    assert res["skipped_old"] == 1
    assert [h["summary"] for h in jrn.archived_history("peer-b")] == ["fresh"]

    # ...and an already-archived record ages out on a later pull.
    later = NOW + timedelta(days=60)
    _clock(monkeypatch, later)
    _peer(monkeypatch, [_run(_iso(later - timedelta(days=1)), summary="newer")])
    jrn.pull_peer(PEER_HOST, "peer-b", force=True)
    assert [h["summary"] for h in jrn.archived_history("peer-b")] == ["newer"]


def test_trimmed_records_are_not_resurrected_by_a_later_pull(arch, monkeypatch):
    monkeypatch.setattr(jrn, "ARCHIVE_MAX_ENTRIES", 5)
    runs = [_run(_at(minutes=i), summary="run-%d" % i) for i in range(1, 9)]
    _peer(monkeypatch, runs)
    jrn.pull_peer(PEER_HOST, "peer-b", force=True)
    assert len(jrn.archived_history("peer-b", limit=50)) == 5

    again = jrn.pull_peer(PEER_HOST, "peer-b", force=True)   # peer still serves all 8

    assert again["added"] == 0
    hist = jrn.archived_history("peer-b", limit=50)
    assert len(hist) == 5
    assert {h["summary"] for h in hist} == {"run-1", "run-2", "run-3", "run-4", "run-5"}


def test_retention_policy_is_reported(arch):
    pol = jrn.retention_policy()
    assert pol["max_entries"] == jrn.ARCHIVE_MAX_ENTRIES
    assert pol["max_age_days"] == jrn.ARCHIVE_MAX_AGE_DAYS
    assert pol["rule"]


# --------------------------------------------------------------------------- #
# 5) the refresh loop                                                         #
# --------------------------------------------------------------------------- #
def _registry(monkeypatch, role="primary"):
    monkeypatch.setattr(su, "node_role", lambda: role)
    monkeypatch.setattr(su, "this_node_name", lambda: "node-a")
    monkeypatch.setattr(su, "load_nodes", lambda: [
        {"name": "node-a", "host": "127.0.0.1", "self": True},
        {"name": "node-b", "host": PEER_HOST},
    ])


def test_archive_refresh_is_inert_on_the_standby(arch, monkeypatch):
    _registry(monkeypatch, role="standby")
    probes = []

    def _pv(host, limit=100, timeout=2.5):
        probes.append(host)
        return {"reachable": True, "runs": [], "summary": {}, "cert": {}, "error": ""}
    monkeypatch.setattr(jrn, "peer_view", _pv)

    res = jrn.archive_refresh(force=True)

    assert res["role"] == "standby"
    assert res["skipped"] == "standby"
    assert probes == []
    assert not arch.exists()          # nothing written into data/ from the standby


def test_archive_refresh_archives_peer_and_local_journal(arch, monkeypatch):
    _registry(monkeypatch, role="primary")
    jrn.JOURNAL.parent.mkdir(parents=True, exist_ok=True)
    jrn.JOURNAL.write_text(json.dumps(_run(_at(minutes=3), summary="local pass")) + "\n",
                           encoding="utf-8")
    _peer(monkeypatch, [_run(_at(minutes=5))])

    res = jrn.archive_refresh(force=True)

    assert res["role"] == "primary"
    assert res.get("skipped") is None
    assert jrn.archive_status("node-b")["state"] == "ok"
    assert jrn.archive_status("node-b")["entries"] == 1
    # the primary's OWN journal is equally node-local -> archived too
    assert jrn.archive_status("node-a")["entries"] == 1
    assert jrn.archive_status("node-a")["state"] == "ok"


def test_pulls_are_throttled_but_force_overrides(arch, monkeypatch):
    _peer(monkeypatch, [_run(_at(minutes=5))])
    assert jrn.pull_peer(PEER_HOST, "peer-b")["ok"] is True

    throttled = jrn.pull_peer(PEER_HOST, "peer-b")
    assert throttled.get("skipped") == "throttled"
    # a throttled pull is not a pull -- it must not be recorded as one
    assert jrn.archive_status("peer-b")["state"] == "ok"
    assert len(jrn.pull_history("peer-b")) == 1

    forced = jrn.pull_peer(PEER_HOST, "peer-b", force=True)
    assert forced["ok"] is True
    assert forced.get("skipped") is None


# --------------------------------------------------------------------------- #
# 6) surfacing                                                                #
# --------------------------------------------------------------------------- #
def test_fleet_view_reports_archive_state_per_node(arch, monkeypatch):
    _registry(monkeypatch, role="primary")
    monkeypatch.setattr(jrn, "local_view", lambda limit=100: {
        "reachable": True, "is_self": True, "secure": None, "host": "127.0.0.1",
        "cert": {}, "summary": {}, "runs": []})
    _peer(monkeypatch, [_run(_at(minutes=5)), _run(_at(minutes=65))])
    jrn.pull_peer(PEER_HOST, "node-b", force=True)

    nodes = {n["name"]: n for n in jrn.fleet_view(limit=50)}

    assert nodes["node-b"]["archive"]["state"] == "ok"
    assert nodes["node-b"]["archive"]["last_success_age_s"] == 0
    assert len(nodes["node-b"]["archived"]) == 2
    # the local node has never been archived in this test -> unknown, not "fine"
    assert nodes["node-a"]["archive"]["state"] == "never"
    assert nodes["node-a"]["archive"]["ok"] is False


def _admin(app):
    return make_user(app, "certdur_admin", role="admin", profile_id=profile_id(app, "admin"))


def _readonly(app):
    return make_user(app, "certdur_ro", role="readonly", profile_id=profile_id(app, "readonly"))


def test_renewals_page_renders_with_the_archive_wired_in(app, client, arch, monkeypatch):
    monkeypatch.setattr(su, "node_role", lambda: "primary")
    monkeypatch.setattr(su, "this_node_name", lambda: "node-a")
    monkeypatch.setattr(su, "load_nodes", lambda: [
        {"name": "node-a", "host": "127.0.0.1", "self": True}])
    login(client, _admin(app))

    assert client.get("/cert-manager/renewals").status_code == 200


def test_durability_json_reports_per_node_archive(app, client, arch, monkeypatch):
    monkeypatch.setattr(su, "node_role", lambda: "primary")
    monkeypatch.setattr(su, "this_node_name", lambda: "node-a")
    monkeypatch.setattr(su, "load_nodes", lambda: [
        {"name": "node-a", "host": "127.0.0.1", "self": True}])
    login(client, _admin(app))

    resp = client.get("/cert-manager/renewals/durability.json")

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["retention"]["max_entries"] == jrn.ARCHIVE_MAX_ENTRIES
    node = next(n for n in data["nodes"] if n["name"] == "node-a")
    assert "last_success_age_s" in node["archive"]
    assert node["archive"]["state"] == "ok"          # the page refresh archived it
    assert data["alerts"] == []                       # healthy -> quiet


def test_durability_json_is_admin_only(app, client, arch):
    login(client, _readonly(app))
    assert client.get("/cert-manager/renewals/durability.json").status_code == 403
