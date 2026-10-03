"""Privileged actions that left no row in the audit trail.

Documentation Center audit, 2026-10-03 (AD-14, AD-38, AD-39, AD-40, AD-41,
AD-42, TR-20). System backup create/restore/delete, git bundles, firmware
pull, code rollback, software update, deploy mode, HA mode, promotion and the
HA node registry all changed the node without an AuditLog row; so did root-CLI
password resets and unlocks, and every failed local sign-in below the lockout
threshold. Each test performs the action with its service stubbed and reads
the row back.
"""
from __future__ import annotations

import io
import json
import sys

import pytest

from conftest import admin_user_id, login, make_user


def _rows(app, action):
    from app.models import AuditLog
    with app.app_context():
        return [(r.username, r.target, r.extra)
                for r in AuditLog.query.filter_by(action=action).all()]


_OK = {"ok": True, "detail": "done", "name": "fmw-backup-x.tgz", "size": 2048,
       "safety": "safety.sql"}


@pytest.mark.parametrize("url, form, service, func, action", [
    ("/system-backup/create", {}, "system_backup", "create_backup", "system_backup.create"),
    ("/system-backup/delete", {"name": "fmw-backup-x.tgz"}, "system_backup",
     "delete_backup", "system_backup.delete"),
    ("/system-backup/restore", {"name": "fmw-backup-x.tgz", "confirm": "RESTORE"},
     "system_backup", "restore_backup", "system_backup.restore"),
    ("/system-backup/firmware-pull", {"name": "img.out"}, "backup_server",
     "pull_firmware", "system_backup.firmware_pull"),
    ("/system-backup/git-bundle/create", {}, "git_backup", "create_bundle",
     "system_backup.git_bundle_create"),
    ("/system-backup/git-bundle/delete", {"name": "b.bundle"}, "git_backup",
     "delete_bundle", "system_backup.git_bundle_delete"),
])
def test_system_backup_actions_are_audited(app, client, monkeypatch, url, form,
                                           service, func, action):
    import importlib
    mod = importlib.import_module(f"app.services.{service}")
    monkeypatch.setattr(mod, func, lambda *a, **k: dict(_OK))
    from app.services import self_update as su
    monkeypatch.setattr(su, "node_role", lambda: "primary")
    login(client, admin_user_id(app))
    client.post(url, data=form)
    assert _rows(app, action), f"{action} left no audit row"


def test_git_bundle_settings_are_audited(app, client, monkeypatch):
    from app.services import git_backup
    monkeypatch.setattr(git_backup, "save_config", lambda form: {"keep": 5, "push_server": True})
    login(client, admin_user_id(app))
    client.post("/system-backup/git-bundle/config", data={"keep": "5"})
    assert _rows(app, "system_backup.git_bundle_config")


def test_code_rollback_is_audited(app, client, monkeypatch):
    from app.services import self_update as su
    monkeypatch.setattr(su, "current_revision", lambda: {"sha": "aaaaaaaaaaaa"})
    monkeypatch.setattr(su, "request_update", lambda *a, **k: "upd-1")
    login(client, admin_user_id(app))
    client.post("/system-backup/code-rollback", data={"target": "bbbbbbb", "confirm": "ROLLBACK"})
    rows = _rows(app, "system.code_rollback")
    assert rows and rows[0][1] == "bbbbbbb"


def test_software_update_apply_is_audited(app, client, monkeypatch):
    from app.services import self_update as su
    monkeypatch.setattr(su, "check_remote", lambda fetch=True: {
        "target_sha": "ccccccc", "behind": 1, "current": {"sha": "aaaaaaa"}})
    monkeypatch.setattr(su, "node_role", lambda: "standalone")
    monkeypatch.setattr(su, "load_nodes", lambda: [])
    monkeypatch.setattr(su, "request_update", lambda *a, **k: "upd-2")
    login(client, admin_user_id(app))
    client.post("/self-update/apply", data={"target": "ccccccc"})
    rows = _rows(app, "self_update.apply")
    assert rows and rows[0][1] == "ccccccc"


def test_deploy_mode_and_ha_mode_are_audited(app, client, monkeypatch):
    from app.services import reconciler
    from app.services import self_update as su
    monkeypatch.setattr(su, "node_role", lambda: "primary")
    monkeypatch.setattr(su, "set_ha_mode", lambda mode: None)
    monkeypatch.setattr(reconciler, "set_deploy_mode", lambda mode: None)
    login(client, admin_user_id(app))
    client.post("/self-update/deploy-mode", data={"mode": "manual"})
    client.post("/self-update/ha-mode", data={"mode": "ha"})
    assert _rows(app, "self_update.deploy_mode")[0][1] == "manual"
    assert _rows(app, "ha.mode")[0][1] == "ha"


def test_promotion_is_audited(app, client, monkeypatch):
    from app.services import cluster
    from app.services import self_update as su
    monkeypatch.setattr(su, "this_node_name", lambda: "node-b")
    monkeypatch.setattr(cluster, "promote_eligible", lambda: True)
    monkeypatch.setattr(cluster, "request_promote", lambda by="?": "prom-1")
    login(client, admin_user_id(app))
    client.post("/self-update/promote", data={"confirm_host": "node-b"})
    assert _rows(app, "ha.promote")[0][1] == "node-b"


def test_node_registry_changes_are_audited(app, client, monkeypatch):
    from app.services import self_update as su
    monkeypatch.setattr(su, "this_node_name", lambda: "node-a")
    monkeypatch.setattr(su, "upsert_node", lambda *a: None)
    monkeypatch.setattr(su, "remove_node", lambda *a: None)
    login(client, admin_user_id(app))
    client.post("/self-update/nodes", data={"name": "node-b", "host": "192.0.2.2"})
    client.post("/self-update/nodes/delete", data={"name": "node-b"})
    assert _rows(app, "ha.node.save")[0][1] == "node-b"
    assert _rows(app, "ha.node.delete")[0][1] == "node-b"


def test_every_failed_local_sign_in_is_audited(app, client):
    make_user(app, "victim")
    client.post("/auth/login", data={"username": "victim", "password": "wrong"})
    client.post("/auth/login", data={"username": "nobody-here", "password": "x"})
    rows = _rows(app, "login.fail")
    targets = sorted(r[1] for r in rows)
    assert targets == ["nobody-here", "victim"], rows


def test_a_cli_password_reset_is_audited(app, monkeypatch):
    """Runs the exact script the CLI pipes into the app, against the test app."""
    import app as app_pkg
    from deploy.satom_cli import cmd_fix
    make_user(app, "locked", active=False)
    monkeypatch.setattr(app_pkg, "create_app", lambda *a, **k: app)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(
        {"user": "locked", "password": "N3w-Passw0rd!"})))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    exec(compile(cmd_fix._PW_CODE, "<cli>", "exec"), {})
    rows = _rows(app, "cli.reset_password")
    assert rows and rows[0][0] == "cli/root" and rows[0][1] == "locked"
    assert json.loads(rows[0][2])["reactivated"] is True
