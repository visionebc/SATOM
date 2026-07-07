"""SSH fallback for device backups — fetch_device_backup_auto + ssh_config_backup.

No network: the REST path and the SSH dump are monkeypatched. What IS real:
the vault write (store_bytes → file + ConfigBackup row) and the combined-error
contract when both paths fail.
"""
from __future__ import annotations

import pytest


class _FakeAppliance:
    id = 42
    name = "fwX"
    host = "fwX.example"
    username = "admin"
    ssh_port = 22

    def build_client(self, timeout=None):
        raise RuntimeError("device refused the backup (errcode -20010): "
                           "The license of peer VM FortiWeb is not valid.")


def test_auto_falls_back_to_ssh_and_stores(app, monkeypatch):
    from app.services import backup

    cfg = "config global\n  config system settings\n  end\nend" + ("\n# pad" * 200) + "\nend"
    monkeypatch.setattr(backup, "ssh_config_backup", lambda a: cfg.encode())
    with app.app_context():
        cb = backup.fetch_device_backup_auto(_FakeAppliance(), created_by="tester")
        assert cb.id and cb.source == "device"
        assert cb.filename.endswith("_cli.conf")
        assert "Captured over SSH" in (cb.note or "")
        assert "-20010" in (cb.note or "")
        assert cb.size_bytes == len(cfg.encode())


def test_auto_raises_combined_error_when_both_fail(app, monkeypatch):
    from app.services import backup

    def _ssh_fail(a):
        raise RuntimeError("SSH auth failed")

    monkeypatch.setattr(backup, "ssh_config_backup", _ssh_fail)
    with app.app_context():
        with pytest.raises(RuntimeError) as ei:
            backup.fetch_device_backup_auto(_FakeAppliance())
    msg = str(ei.value)
    assert "-20010" in msg and "SSH fallback also failed" in msg


def test_ssh_dump_validation_rejects_truncated_output(app, monkeypatch):
    from app.services import backup

    class _Sess:
        def __init__(self, appliance, timeout=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return None

        def run_readonly(self, cmd, **kw):
            assert cmd == "show full-configuration"
            return "config global\n" + ("set x y\n" * 200)  # no trailing 'end'

    import app.services.ssh_ops as ssh_ops
    monkeypatch.setattr(ssh_ops, "FortiWebReadonlySSH", _Sess)
    with app.app_context():
        with pytest.raises(RuntimeError, match="truncated"):
            backup.ssh_config_backup(_FakeAppliance())
