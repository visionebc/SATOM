"""Tests for the self-update service — pure logic (no Flask app, no DB, no git).

The privileged runner (deploy/self_update_runner.py) is exercised live on the
node, not here; these lock the app-side contract: revision parsing, the enqueue
file format, and the staged-rollout interlock gate.
"""
import json
import types

import pytest

from app.services import self_update as su


# --------------------------------------------------------------------------
# check_remote parsing (git mocked)
# --------------------------------------------------------------------------
def _fake_git(mapping):
    """Return a fake _git that dispatches on the first arg."""
    def _g(*args, timeout=120):
        key = args[0]
        out = mapping.get(key, "")
        return types.SimpleNamespace(returncode=0, stdout=out, stderr="")
    return _g


def test_current_revision_parses(monkeypatch):
    line = "abc123def456\x1fabc123d\x1fsnapshot before HA\x1f2026-07-07T00:00:00Z"
    monkeypatch.setattr(su, "_git", _fake_git({
        "log": line, "rev-parse": "main"}))
    rev = su.current_revision()
    assert rev["sha"] == "abc123def456"
    assert rev["short"] == "abc123d"
    assert rev["subject"] == "snapshot before HA"
    assert rev["branch"] == "main"


def test_check_remote_behind(monkeypatch):
    monkeypatch.setattr(su, "_git", _fake_git({
        "fetch": "",
        "log": "deadbee new feature (2 hours ago)",   # HEAD..origin log
        "rev-parse": "deadbeef0000",
        "rev-list": "3",
    }))
    # current_revision also calls _git('log'...) — acceptable for this shape.
    info = su.check_remote(fetch=True)
    assert info["behind"] == 3
    assert info["target_sha"] == "deadbeef0000"
    assert info["commits"] == ["deadbee new feature (2 hours ago)"]
    assert info["error"] == ""


# --------------------------------------------------------------------------
# request_update file format (filesystem)
# --------------------------------------------------------------------------
def test_request_update_writes_queue_and_status(tmp_path, monkeypatch):
    monkeypatch.setattr(su, "REQ_DIR", tmp_path / "req")
    monkeypatch.setattr(su, "STATUS_DIR", tmp_path / "sta")
    monkeypatch.setattr(su, "this_node_name", lambda: "node-a")
    monkeypatch.setattr(su, "node_role", lambda: "standby")

    uid = su.request_update("deadbeef", by="admin", do_pip=True, do_migrate=False)

    reqs = list((tmp_path / "req").glob("*.json"))
    assert len(reqs) == 1
    req = json.loads(reqs[0].read_text())
    assert req["target"] == "deadbeef"
    assert req["do_pip"] is True and req["do_migrate"] is False
    assert req["requested_by"] == "admin"
    assert req["node"] == "node-a" and req["role"] == "standby"
    # temp trigger file must not linger
    assert not list((tmp_path / "req").glob(".*"))

    st = su.update_status(uid)
    assert st and st["state"] == "queued" and st["id"] == uid


# --------------------------------------------------------------------------
# the staged-rollout interlock (the "seguro")
# --------------------------------------------------------------------------
def test_primary_blocked_until_standby_validates(monkeypatch):
    state = {}
    monkeypatch.setattr(su, "validated_state", lambda: state)
    # nothing validated → primary cannot apply
    assert su.can_apply_to_primary("v2sha") is False
    # standby validated a DIFFERENT revision → still blocked
    state.update({"target": "OTHER"})
    assert su.can_apply_to_primary("v2sha") is False
    # standby validated THIS exact revision → unlocked
    state.update({"target": "v2sha"})
    assert su.can_apply_to_primary("v2sha") is True
    # empty target never unlocks
    assert su.can_apply_to_primary("") is False


def test_reconcile_marks_validated_only_for_standby_success(monkeypatch):
    calls = []
    monkeypatch.setattr(su, "mark_validated", lambda t, n: calls.append((t, n)))

    su.reconcile_interlock({"state": "success", "role": "standby",
                            "result_sha": "v2sha", "node": "node-b"})
    assert calls == [("v2sha", "node-b")]

    calls.clear()
    # a PRIMARY success must NOT self-validate the interlock
    su.reconcile_interlock({"state": "success", "role": "primary",
                            "result_sha": "v2sha", "node": "node-a"})
    assert calls == []
    # a failure never validates
    su.reconcile_interlock({"state": "failed", "role": "standby",
                            "result_sha": "v2sha"})
    assert calls == []


def test_load_nodes_defaults_to_self(tmp_path, monkeypatch):
    monkeypatch.setattr(su, "NODES_FILE", tmp_path / "missing.json")
    monkeypatch.setattr(su, "this_node_name", lambda: "solo")
    nodes = su.load_nodes()
    assert len(nodes) == 1 and nodes[0]["name"] == "solo"
