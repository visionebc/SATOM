"""SFTP access to the external backup server (backup-server, LXC 251 @ hypervisor04).

The Fortinet appliances push their own scheduled config backups here
(``config system backup`` → SFTP, e.g. fw6 daily 02:00), and the firmware
``.out`` binaries referenced by the firmware SoT repo live here too. This
module is OFortMAut's read side: verify the box is reachable, inventory what
the devices have pushed, and pull a firmware image into the app's local
firmware store (``FirmwareImage``) so a restore/downgrade can be driven from
the console without re-uploading by hand.

Connection settings come from ``settings_store.backup_server()`` (Settings →
SoT & Backup); the password is Fernet-encrypted at rest. Paramiko is already
a dependency (``ssh_ops`` uses it for the FortiWeb CLI battery).
"""
from __future__ import annotations

import hashlib
import os
import posixpath
import stat as _stat
from datetime import datetime

from flask import current_app

from . import settings_store as store


def _connect(cfg: dict | None = None):
    """Open an SFTP session from the stored settings. Caller closes the
    returned transport. Raises on any failure — callers map to a friendly
    error."""
    import paramiko  # lazy, same convention as ssh_ops
    cfg = cfg or store.backup_server(reveal_secret=True)
    if not cfg.get("host") or not cfg.get("username"):
        raise RuntimeError("backup server not configured (Settings → SoT & Backup)")
    t = paramiko.Transport((cfg["host"], int(cfg.get("port") or 22)))
    t.connect(username=cfg["username"], password=cfg.get("password") or "")
    return t, paramiko.SFTPClient.from_transport(t)


def test_connection() -> dict:
    """Settings-page probe: connect, list both roots, report counts."""
    try:
        cfg = store.backup_server(reveal_secret=True)
        t, sftp = _connect(cfg)
        try:
            cdirs = sftp.listdir(cfg["config_path"])
            fw = sftp.listdir(cfg["firmware_path"])
        finally:
            t.close()
        return {"ok": True,
                "detail": (f"connected to {cfg['host']}:{cfg['port']} — "
                           f"{len(cdirs)} device folder(s) under {cfg['config_path']}, "
                           f"{len(fw)} file(s) under {cfg['firmware_path']}")}
    except Exception as exc:  # noqa: BLE001 — settings-page probe surfaces anything
        return {"ok": False, "detail": str(exc)}


def _listing(sftp, path: str) -> list[dict]:
    rows = []
    for att in sftp.listdir_attr(path):
        if _stat.S_ISDIR(att.st_mode or 0):
            continue
        rows.append({
            "name": att.filename,
            "size": int(att.st_size or 0),
            "mtime": datetime.utcfromtimestamp(att.st_mtime).strftime("%Y-%m-%d %H:%M")
            if att.st_mtime else "",
        })
    rows.sort(key=lambda r: r["mtime"], reverse=True)
    return rows


def inventory() -> dict:
    """What the backup server holds: device-pushed config backups (one folder
    per device under config_path) + firmware binaries. Never raises — the
    System Backup page renders the error state instead."""
    cfg = store.backup_server()
    out = {"configured": cfg["configured"], "reachable": False, "host": cfg["host"],
           "port": cfg["port"], "error": "", "devices": [], "firmware": []}
    if not cfg["configured"]:
        return out
    try:
        full = store.backup_server(reveal_secret=True)
        t, sftp = _connect(full)
        try:
            for entry in sorted(sftp.listdir_attr(full["config_path"]),
                                key=lambda a: a.filename):
                if not _stat.S_ISDIR(entry.st_mode or 0):
                    continue
                files = _listing(sftp, posixpath.join(full["config_path"], entry.filename))
                out["devices"].append({"device": entry.filename,
                                       "files": files[:10],
                                       "count": len(files),
                                       "latest": files[0]["mtime"] if files else ""})
            out["firmware"] = _listing(sftp, full["firmware_path"])
        finally:
            t.close()
        out["reachable"] = True
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)
    return out


def _firmware_root() -> str:
    """Same derivation as views/firmware.py: next to the data dir."""
    uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "") or ""
    if uri.startswith("sqlite:///"):
        base = os.path.dirname(uri[len("sqlite:///"):])
    else:
        base = os.path.join(os.path.dirname(current_app.root_path), "data")
    d = os.path.join(base, "firmware")
    os.makedirs(d, exist_ok=True)
    return d


def _guess_product(filename: str) -> str:
    low = filename.lower()
    if low.startswith("fad") or "fortiadc" in low:
        return "fortiadc"
    return "fortiweb"


def pull_firmware(filename: str, by: str = "") -> dict:
    """Download one ``.out`` image from the backup server's firmware folder
    into the local firmware store and register it as a ``FirmwareImage`` so
    the existing Upgrade/Downgrade actions can use it. Idempotent on
    filename: an already-pulled image is reported, not duplicated."""
    from ..extensions import db
    from ..models_firmware import FirmwareImage

    safe = posixpath.basename(filename or "")
    if not safe or not safe.lower().endswith(".out"):
        return {"ok": False, "detail": "only .out firmware images can be pulled"}
    existing = FirmwareImage.query.filter_by(filename=safe).first()
    if existing is not None:
        return {"ok": True, "detail": f"{safe} already in the local firmware store",
                "image_id": existing.id, "already": True}

    cfg = store.backup_server(reveal_secret=True)
    t, sftp = _connect(cfg)
    try:
        remote = posixpath.join(cfg["firmware_path"], safe)
        fw = FirmwareImage(product=_guess_product(safe), version="?",
                           filename=safe, stored_path="", size_bytes=0,
                           sha256="", uploaded_by=by or "backup-server",
                           notes=f"pulled from backup server {cfg['host']}:{remote}")
        db.session.add(fw)
        db.session.flush()
        dest_dir = os.path.join(_firmware_root(), str(fw.id))
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, safe)
        sftp.get(remote, dest)
        h = hashlib.sha256()
        with open(dest, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        fw.stored_path = dest
        fw.size_bytes = os.path.getsize(dest)
        fw.sha256 = h.hexdigest()
        db.session.commit()
        return {"ok": True, "image_id": fw.id,
                "detail": f"{safe} pulled — {fw.size_bytes // (1024*1024)} MB, sha256 {fw.sha256[:12]}…"}
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        return {"ok": False, "detail": str(exc)}
    finally:
        t.close()
