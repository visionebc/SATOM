"""Backup + Restore service — the config-backup vault and the FortiWeb
local-backup / restore REST calls.

All device paths are resolved from the endpoint registry
(``registry.loader.resolve``) — no hardcoded URLs (CLAUDE.md §4a). The real
FortiWeb endpoints were confirmed live on fw3 (7.6.8):

* ``local_backup_list``   → ``system/maintenance.localbackup.list``   (GET, 200)
* ``local_backup_download``→ ``system/maintenance.localbackup.download``(GET + name)
* ``local_backup``        → ``system/maintenance.localbackup.backup``  (create)
* ``system_restore``      → ``system/maintenance.backuprestore``       (multipart)

The vault stores each backup's bytes on disk under ``<data>/backups/<id>/`` and
its metadata in the ``ConfigBackup`` table — mirroring the firmware repository.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import time
from typing import Any
from urllib.parse import quote

from flask import current_app

from ..extensions import db
from ..models_backup import ConfigBackup
from ..registry import loader

# The multipart field FortiWeb's config restore expects on
# ``maintenance.backuprestore``. Held as ONE constant so it is trivially
# correctable once a live restore round-trip confirms the exact wire name
# (see the Phase-0 spike note): the endpoint is verified, the field pending a
# gated live confirmation. Restore stays dry_run by default until then.
RESTORE_FILE_FIELD = "file"


# --------------------------------------------------------------------------- #
# Device REST calls (resolver-driven)                                          #
# --------------------------------------------------------------------------- #
def list_backups(client: Any) -> list[dict[str, Any]]:
    """On-device local backups (``maintenance.localbackup.list``)."""
    resp = client.get(loader.resolve("local_backup_list"))
    data = resp.json()
    if isinstance(data, dict):
        res = data.get("results", data.get("payload", []))
        return res if isinstance(res, list) else []
    return data if isinstance(data, list) else []


def download_backup(client: Any, backup_name: str) -> bytes:
    """Download a named on-device backup (``maintenance.localbackup.download``)."""
    path = loader.resolve("local_backup_download") + "?mkey=" + quote(backup_name, safe="")
    resp = client.get(path)
    if hasattr(resp, "raise_for_status"):
        resp.raise_for_status()
    return resp.content


def create_backup(client: Any, name: str | None = None) -> dict[str, Any]:
    """Trigger an on-device local backup (``maintenance.localbackup.backup``).

    Best-effort: the reliable way to fill the vault is an upload from a PC or a
    downloaded config — device-side create can return -901 depending on the
    box's backup-password state. Returns the raw response body.
    """
    payload: dict[str, Any] = {"name": name or f"backup_{time.strftime('%Y%m%d_%H%M%S')}"}
    resp = client.upload(loader.resolve("local_backup"), files={}, data=payload)
    try:
        return resp.json()
    except Exception:  # noqa: BLE001
        return {"status_code": getattr(resp, "status_code", None)}


def restore(client: Any, file_bytes: bytes, filename: str, *,
            password: str | None = None, dry_run: bool = True) -> dict[str, Any]:
    """Restore a FortiWeb configuration by uploading it to the box.

    DESTRUCTIVE on a real run: FortiWeb applies the config and reboots.
    ``dry_run=True`` (default) validates and returns the plan WITHOUT uploading.
    The multipart field name is :data:`RESTORE_FILE_FIELD` and the endpoint is
    resolved via the registry (``system_restore`` → ``maintenance.backuprestore``).
    """
    size = len(file_bytes or b"")
    plan: dict[str, Any] = {
        "dry_run": dry_run,
        "filename": filename,
        "size": size,
        "endpoint": loader.resolve("system_restore"),
        "encrypted": is_encrypted(file_bytes),
    }
    if size == 0:
        raise ValueError("configuration file is empty")

    if dry_run:
        plan["ok"] = True
        plan["message"] = (
            f"DRY-RUN — would upload {filename} ({size:,} bytes) to the appliance "
            f"and reboot. No file was sent.")
        return plan

    data: dict[str, Any] = {}
    if password:
        data["password"] = password
    files = {RESTORE_FILE_FIELD: (filename, file_bytes, "application/octet-stream")}
    resp = client.upload(plan["endpoint"], files=files, data=data or None, timeout=600.0)
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        body = {"status_code": getattr(resp, "status_code", None),
                "text": getattr(resp, "text", "")[:300]}
    plan["response"] = body
    status = getattr(resp, "status_code", 500)
    plan["ok"] = status < 400
    plan["message"] = (f"restore uploaded to the appliance (HTTP {status}) — it is applying "
                       f"the configuration and may reboot."
                       if plan["ok"] else f"restore upload failed (HTTP {status}).")
    return plan


# --------------------------------------------------------------------------- #
# The vault (on-disk store + ConfigBackup rows)                                #
# --------------------------------------------------------------------------- #
def is_encrypted(data: bytes) -> bool:
    """A FortiWeb plaintext config starts with ``#config``/``config``; anything
    else (a password-encrypted backup) is treated as encrypted → restore will
    prompt for the backup password."""
    head = (data or b"")[:64].lstrip()
    return not (head.startswith(b"#config") or head.startswith(b"config"))


def vault_root() -> str:
    """Directory holding per-appliance backup folders, next to ``fortinet.db``
    in ``data/`` (isolated per test — the test DB lives in a tmp dir)."""
    uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "") or ""
    if uri.startswith("sqlite:///"):
        base = os.path.dirname(uri[len("sqlite:///"):])
    else:
        base = os.path.join(os.path.dirname(current_app.root_path), "data")
    d = os.path.join(base, "backups")
    os.makedirs(d, exist_ok=True)
    return d


def store_bytes(*, appliance_id: int, appliance_name: str, data: bytes, filename: str,
                source: str = "upload", created_by: str = "", firmware: str | None = None,
                note: str | None = None) -> ConfigBackup:
    """Persist config bytes into the vault (file on disk + ConfigBackup row)."""
    safe_name = os.path.basename(filename) or "config.conf"
    cb = ConfigBackup(
        appliance_id=appliance_id, appliance_name=appliance_name or "",
        filename=safe_name, stored_path="", size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(), encrypted=is_encrypted(data),
        source=source if source in ("device", "upload") else "upload",
        firmware=firmware, note=note, created_by=created_by or "",
    )
    db.session.add(cb)
    db.session.flush()  # mint id
    dest_dir = os.path.join(vault_root(), str(cb.id))
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, safe_name)
    try:
        with open(dest_path, "wb") as fh:
            fh.write(data)
        cb.stored_path = dest_path
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
        shutil.rmtree(dest_dir, ignore_errors=True)
        raise
    return cb


def read_vault_bytes(cb: ConfigBackup) -> bytes:
    """Read a stored backup off disk, verifying its recorded sha256."""
    path = getattr(cb, "stored_path", "") or ""
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"backup file missing on disk for backup {getattr(cb, 'id', '?')}")
    with open(path, "rb") as fh:
        data = fh.read()
    recorded = (getattr(cb, "sha256", "") or "").strip()
    if recorded and hashlib.sha256(data).hexdigest() != recorded:
        raise ValueError(f"sha256 mismatch for {getattr(cb, 'filename', path)} — refusing to use")
    return data


def delete_vault(cb: ConfigBackup) -> None:
    """Remove a vault entry (row + on-disk folder)."""
    folder = os.path.dirname(cb.stored_path) if cb.stored_path else None
    db.session.delete(cb)
    db.session.commit()
    if folder and os.path.isdir(folder):
        shutil.rmtree(folder, ignore_errors=True)


def fetch_device_backup(client: Any, *, appliance_id: int, appliance_name: str,
                        created_by: str = "") -> ConfigBackup:
    """Create a backup on the device, download it, and store it in the vault.

    Best-effort convenience path (device-side create can fail with -901); the
    upload-from-PC path is the reliable one. Raises on any REST failure.
    """
    create_backup(client)
    rows = list_backups(client)
    name = ""
    for r in rows:
        if isinstance(r, dict):
            name = r.get("name") or r.get("filename") or r.get("mkey") or ""
            if name:
                break
    if not name:
        raise RuntimeError("device reported no backup to download")
    data = download_backup(client, name)
    fw = ""
    try:
        from . import upgrade as upg
        fw = upg.firmware_version(client)
    except Exception:  # noqa: BLE001
        pass
    return store_bytes(appliance_id=appliance_id, appliance_name=appliance_name,
                       data=data, filename=f"{name}.conf", source="device",
                       created_by=created_by, firmware=fw or None)


__all__ = ["RESTORE_FILE_FIELD", "list_backups", "download_backup", "create_backup",
           "restore", "is_encrypted", "vault_root", "store_bytes", "read_vault_bytes",
           "delete_vault", "fetch_device_backup"]
