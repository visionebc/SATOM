"""System Backup / Software Update gates.

Documentation Center audit, 2026-10-03 (AD-35, AD-36, AD-37, AD-43).
"""
from __future__ import annotations

import pytest

from conftest import admin_user_id, login


def _rollback_env(monkeypatch, *, role="primary", nodes=None, can_apply=False,
                  request_update=None):
    from app.services import self_update as su
    calls = []
    monkeypatch.setattr(su, "current_revision", lambda: {"sha": "aaaaaaaaaaaa"})
    monkeypatch.setattr(su, "node_role", lambda: role)
    monkeypatch.setattr(su, "this_node_name", lambda: "node-a")
    monkeypatch.setattr(su, "load_nodes", lambda: nodes if nodes is not None
                        else [{"name": "node-a"}, {"name": "node-b"}])
    monkeypatch.setattr(su, "can_apply_to_primary", lambda target: can_apply)

    def _req(*a, **k):
        calls.append((a, k))
        return "upd-1"
    monkeypatch.setattr(su, "request_update", request_update or _req)
    return calls


def _post_rollback(client):
    return client.post("/system-backup/code-rollback",
                       data={"target": "bbbbbbb", "confirm": "ROLLBACK"})


def test_rollback_on_a_primary_honours_the_staged_rollout_safeguard(app, client, monkeypatch):
    calls = _rollback_env(monkeypatch, can_apply=False)
    login(client, admin_user_id(app))
    r = _post_rollback(client)
    assert r.status_code == 302
    assert calls == [], "rollback queued on the primary before the standby"
    calls = _rollback_env(monkeypatch, can_apply=True)
    _post_rollback(client)
    assert len(calls) == 1, "control: an unlocked primary still queues"


def test_rollback_on_a_standalone_node_is_not_blocked(app, client, monkeypatch):
    calls = _rollback_env(monkeypatch, role="standalone", nodes=[], can_apply=False)
    login(client, admin_user_id(app))
    _post_rollback(client)
    assert len(calls) == 1


def test_rollback_on_a_container_runtime_flashes_instead_of_500(app, client, monkeypatch):
    from app import runtime

    def _raise(*a, **k):
        raise runtime.CapabilityUnavailable("self_update", "deploy a new image tag")
    _rollback_env(monkeypatch, role="standalone", nodes=[], request_update=_raise)
    login(client, admin_user_id(app))
    r = _post_rollback(client)
    assert r.status_code == 302
    html = client.get("/system-backup/").get_data(as_text=True)
    assert "deploy a new image tag" in html


def test_offline_package_apply_refuses_on_a_container_runtime(app, monkeypatch):
    from app import runtime
    from app.services import update_package_service as upkg
    monkeypatch.setenv("SATOM_RUNTIME", "container")
    with app.app_context():
        with pytest.raises(runtime.CapabilityUnavailable):
            upkg.request_package_apply("satom-update-9.9.9.tar.gz", "admin")
    monkeypatch.delenv("SATOM_RUNTIME", raising=False)
    with app.app_context():
        # control: on a host the call gets past the gate (and fails on staging)
        with pytest.raises(upkg.PackageError):
            upkg.request_package_apply("satom-update-9.9.9.tar.gz", "admin")


@pytest.mark.parametrize("form, expected", [({"push_server": "on"}, True), ({}, False)])
def test_manual_backup_pushes_off_box_when_ticked(app, client, monkeypatch, form, expected):
    from app.services import system_backup
    seen = {}

    def _create(**k):
        seen.update(k)
        return {"ok": True, "name": "fmw-backup-x.tgz", "size": 2048, "detail": "done"}
    monkeypatch.setattr(system_backup, "create_backup", _create)
    login(client, admin_user_id(app))
    client.post("/system-backup/create", data=dict(form, include_reports="on"))
    assert seen.get("push_server") is expected


def test_the_push_checkbox_is_offered_when_a_backup_server_is_configured(app, client, monkeypatch):
    from app.services import backup_server as bksrv
    monkeypatch.setattr(bksrv, "system_inventory",
                        lambda *a, **k: {"configured": True, "reachable": True, "files": []})
    login(client, admin_user_id(app))
    html = client.get("/system-backup/").get_data(as_text=True)
    assert 'name="push_server" id="bkpush" checked' in html
