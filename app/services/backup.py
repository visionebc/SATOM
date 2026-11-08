"""Backup + Restore service — the config-backup vault and the FortiWeb
local-backup / restore REST calls.

All device paths are resolved from the endpoint registry
(``registry.loader.resolve_for``, per the box's build) — no hardcoded URLs
(docs/engineering.md §13). The real FortiWeb endpoints were confirmed live on fw3 (7.6.8):

* ``local_backup_list``   → ``system/maintenance.localbackup.list``   (GET, 200)
* ``local_backup_download``→ ``system/maintenance.localbackup.download``(GET + name)
* ``local_backup``        → ``system/maintenance.localbackup.backup``  (create)

Restore (measured on fortiweb20, 7.6.8 build1128, 2026-11-08 — the calls the
box's own GUI makes, ``fwb-backup-restore.js``):

* ``config_backup``  → ``GET system/maintenance.backupconfiguration?type=cli``
  — the box's CLI backup: a ZIP with ``fwb_system_no_defaults.conf``.
* ``config_restore`` → ``POST system/maintenance.restoreconfiguration``,
  multipart ``file`` + ``encryption`` (0/1) + ``password``. ``{"mode": "stand",
  "msg": "u_msg"}`` means "applying, rebooting"; any other ``mode`` is the HA
  configuration-update flow, which SATOM does not drive.

``system_restore`` (``maintenance.backuprestore``) is NOT a restore: it is the
partition/firmware READ the same GUI page loads. Until 2026-11-08 SATOM posted
the configuration there, the box answered 200 with its partition table, applied
nothing, and the page said the restore had run.

Only the box's own package format is restorable. A CLI dump captured over SSH
is converted first (:mod:`app.services.fwb_config_package`), with the header of
a backup the target writes at restore time.

The vault stores each backup's bytes on disk under ``<data>/backups/<id>/`` and
its metadata in the ``ConfigBackup`` table — mirroring the firmware repository.
"""
from __future__ import annotations

import hashlib
import os
import re

from werkzeug.utils import secure_filename
import shutil
import time
from typing import Any
from urllib.parse import quote

from flask import current_app

from ..extensions import db
from ..models_backup import ConfigBackup
from ..registry import loader
from . import fwb_config_package as pkg

#: The multipart field ``maintenance.restoreconfiguration`` reads the file
#: from (the GUI's ``formData.file``; measured 7.6.8).
RESTORE_FILE_FIELD = "file"

#: Registry names of the two calls a restore makes.
CONFIG_BACKUP = "config_backup"
CONFIG_RESTORE = "config_restore"

#: A CLI backup the box names itself; used when it sends no filename.
DEFAULT_PACKAGE_NAME = "config_system_no_defaults.conf.zip"


# --------------------------------------------------------------------------- #
# Device REST calls (resolver-driven)                                          #
# --------------------------------------------------------------------------- #
def _resolve(client: Any, name: str) -> str:
    """``name`` for the build the client's box runs (``loader.resolve_for``)."""
    return loader.resolve_for("fortiweb", name, loader.version_of(client))


def list_backups(client: Any) -> list[dict[str, Any]]:
    """On-device local backups (``maintenance.localbackup.list``)."""
    resp = client.get(_resolve(client, "local_backup_list"))
    data = resp.json()
    if isinstance(data, dict):
        res = data.get("results", data.get("payload", []))
        return res if isinstance(res, list) else []
    return data if isinstance(data, list) else []


def download_backup(client: Any, backup_name: str) -> bytes:
    """Download a named on-device backup (``maintenance.localbackup.download``)."""
    path = _resolve(client, "local_backup_download") + "?mkey=" + quote(backup_name, safe="")
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
    # FortiWeb triggers maintenance.localbackup.backup with a GET (verified
    # live on fw1: POST/PUT/multipart -> -20005 "invalid HTTP method"; GET
    # runs the backup, returning -901 only when a backup password blocks it).
    # The box auto-names the file, so `name` is kept for API compat but unused.
    _ = name
    resp = client.get(_resolve(client, "local_backup"))
    try:
        return resp.json()
    except Exception:  # noqa: BLE001
        return {"status_code": getattr(resp, "status_code", None)}


def _body_of(resp: Any) -> dict[str, Any]:
    try:
        body = resp.json()
        if isinstance(body, dict):
            return body
        return {"value": body}
    except Exception:  # noqa: BLE001
        return {"status_code": getattr(resp, "status_code", None),
                "text": (getattr(resp, "text", "") or "")[:300]}


def _attachment_name(resp: Any) -> str:
    cd = ((getattr(resp, "headers", None) or {}).get("content-disposition") or "")
    m = re.search(r'filename="?([^";]+)"?', cd)
    return (m.group(1).strip() if m else "") or DEFAULT_PACKAGE_NAME


def cli_backup(client: Any) -> tuple[bytes, str]:
    """The box's own CLI backup (``config_backup``, ``type=cli``) and the name
    it gives it. Raises ``RuntimeError`` unless the body really is a FortiWeb
    backup package — a 200 carrying a JSON error is a refusal, not a backup."""
    resp = client.get(_resolve(client, CONFIG_BACKUP) + "?type=cli&ml_backup=&password=")
    status = getattr(resp, "status_code", 0)
    data = getattr(resp, "content", b"") or b""
    if status != 200 or pkg.classify(data) != pkg.KIND_PACKAGE:
        hint = data[:200].decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"the device returned no configuration backup "
                           f"(HTTP {status}{': ' + hint if hint else ''})")
    return data, _attachment_name(resp)


def fetch_restore_point(client: Any, *, appliance_id: int, appliance_name: str,
                        created_by: str = "") -> tuple[ConfigBackup, bytes]:
    """Take the box's CLI backup and keep it in the vault: the rollback copy of
    a live restore, and the template a CLI dump is converted with."""
    data, name = cli_backup(client)
    fw = ""
    try:
        from . import upgrade as upg
        fw = upg.firmware_version(client)
    except Exception:  # noqa: BLE001 — firmware is optional metadata
        pass
    cb = store_bytes(appliance_id=appliance_id, appliance_name=appliance_name,
                     data=data, filename=name, source="device", created_by=created_by,
                     firmware=fw or None,
                     note="Pre-restore backup (the device's own CLI backup) — "
                          "the rollback copy of the restore that followed.")
    return cb, data


def capture_source(appliance, *, created_by: str = "") -> ConfigBackup:
    """A fresh copy of a migration SOURCE in its vault: the box's CLI backup
    over REST, or ``show full-configuration`` over SSH when REST cannot answer
    (the usual reason to migrate: an expired VM licence locks every REST route
    and leaves SSH up). Raises ``RuntimeError`` naming both reasons."""
    try:
        client = appliance.build_client(timeout=120)
        data, name = cli_backup(client)
        note = "Migration source — the device's own CLI backup (REST)."
    except Exception as exc:  # noqa: BLE001 — fall back to the SSH dump
        rest_err = f"{type(exc).__name__}: {exc}"[:200]
        try:
            data = ssh_config_backup(appliance)
        except Exception as ssh_exc:  # noqa: BLE001
            raise RuntimeError(f"REST backup failed ({rest_err}); SSH dump also failed "
                               f"({type(ssh_exc).__name__}: {ssh_exc})") from ssh_exc
        name = f"{(appliance.name or 'appliance')}_{time.strftime('%Y%m%d_%H%M%S')}_cli.conf"
        note = f"Migration source — captured over SSH (show full-configuration); REST: {rest_err}"
    return store_bytes(appliance_id=appliance.id, appliance_name=appliance.name or "",
                       data=data, filename=name, source="device", created_by=created_by,
                       note=note[:500])


def classify(data: bytes) -> str:
    """What a vault entry is — see :func:`fwb_config_package.classify`."""
    return pkg.classify(data)


def _restore_answer(status: int, body: dict[str, Any]) -> tuple[bool, str]:
    """Read the device's answer to ``config_restore``. Only the GUI's own
    "applying" acknowledgement counts; a bare 200 does not (it is what the
    partition-read endpoint returned for years while restoring nothing)."""
    if status >= 400:
        return False, f"the device refused the restore (HTTP {status})"
    res = body.get("results") if isinstance(body.get("results"), dict) else body
    err = res.get("errcode", body.get("errcode"))
    if err not in (None, 0, "0", ""):
        return False, f"the device refused the restore (errcode {err})"
    mode, msg = res.get("mode"), res.get("msg")
    if mode == "stand" and msg == "u_msg":
        return True, "the device accepted the configuration and is rebooting to apply it"
    if mode:
        return False, (f"the device answered in HA mode ({mode!r}): it hands the file to its "
                       "HA configuration-update flow, which SATOM does not drive — nothing "
                       "is confirmed; finish or cancel it in the FortiWeb GUI")
    return False, (f"the device sent no 'applying' acknowledgement (HTTP {status}) — "
                   "nothing is confirmed")


def restore(client: Any, file_bytes: bytes, filename: str, *,
            password: str | None = None, dry_run: bool = True,
            template: bytes | None = None) -> dict[str, Any]:
    """Restore a FortiWeb configuration by uploading it to the box.

    DESTRUCTIVE on a real run: FortiWeb applies the config and reboots.
    ``dry_run=True`` (default) validates and returns the plan WITHOUT uploading.

    What is sent depends on what the vault holds (:func:`classify`):
    a backup ZIP goes as is; a CLI dump is converted with ``template`` — a CLI
    backup the TARGET box just wrote (:func:`fetch_restore_point`); anything
    else is sent only with a password (``encryption=1``), the GUI's handling of
    a password-protected backup. ``ok`` is True only on the device's "applying"
    acknowledgement — :func:`verify_restore` then proves what it applied.
    """
    size = len(file_bytes or b"")
    if size == 0:
        raise ValueError("configuration file is empty")
    kind = pkg.classify(file_bytes)
    plan: dict[str, Any] = {
        "dry_run": dry_run,
        "filename": filename,
        "size": size,
        "endpoint": _resolve(client, CONFIG_RESTORE),
        "encrypted": kind == pkg.KIND_UNKNOWN,
        "kind": kind,
        "converted": False,
    }
    if kind == pkg.KIND_UNKNOWN and not password:
        raise ValueError(
            "this file is neither a FortiWeb configuration backup (.zip) nor a CLI dump "
            "(show full-configuration). If it is a password-protected backup, enter its "
            "password.")

    payload, send_name = file_bytes, filename
    pending = ""
    if kind == pkg.KIND_CLI_DUMP:
        if template is None:
            if not dry_run:
                raise ValueError("a CLI dump is converted with a backup taken from the "
                                 "target device, and none is available")
            pending = (" It is a CLI dump: it is converted with a backup the device writes "
                       "at restore time (not validated now: that backup could not be read).")
        else:
            payload = pkg.build_package(file_bytes, template)
            base = re.sub(r"\.(conf|txt|cfg)$", "", filename or "config", flags=re.I)
            send_name = f"{base}_restore.conf.zip"
            plan["converted"] = True
    plan["send_filename"], plan["send_size"] = send_name, len(payload)

    if dry_run:
        plan["ok"] = True
        how = (f"converted from a CLI dump to the device's package format ({len(payload):,} "
               f"bytes) and " if plan["converted"] else "")
        plan["message"] = (f"DRY-RUN — {filename} ({size:,} bytes) would be {how}sent to the "
                           f"appliance, which applies it and reboots. Nothing was sent."
                           + pending)
        return plan

    data = {"encryption": "1" if password else "0", "password": password or ""}
    files = {RESTORE_FILE_FIELD: (send_name, payload, "application/octet-stream")}
    resp = client.upload(plan["endpoint"], files=files, data=data, timeout=600.0)
    body = _body_of(resp)
    plan["response"] = body
    plan["ok"], plan["message"] = _restore_answer(getattr(resp, "status_code", 500), body)
    plan["accepted"] = plan["ok"]
    return plan


def _hostname_of(sections: dict[str, list[str]]) -> str:
    in_global = False
    for line in sections.get("global", []):
        if line == "config system global":
            in_global = True
        elif in_global and line == "end":
            break
        elif in_global and line.startswith("  set hostname "):
            return line.split(" ", 4)[-1].strip().strip('"')
    return ""


def verify_restore(appliance, sent: bytes, *, progress=None,
                   expected: dict[str, int] | None = None, readback: str | None = None,
                   hostname: str | None = None) -> dict[str, Any]:
    """After an accepted restore: wait for the reboot, read the configuration
    back and compare it with what was sent, object for object.

    The read-back uses the format that was sent, because the two do not
    compare across formats (a no-defaults backup omits whole predefined
    tables): a CLI dump is checked against a new ``show full-configuration``
    over SSH, a backup ZIP against a new CLI backup over REST. The comparison
    counts the entries of every configuration table
    (:func:`fwb_config_package.config_profile`) — re-salted secrets make the
    text differ even when the restore is exact. Never raises.

    A migration passes ``expected`` (only the tables it copied, in the
    format its source had), ``readback`` (``"ssh"`` or ``"rest"``, that
    format) and ``hostname`` (the target's own, which must survive)."""
    from . import upgrade as upg
    rec = upg.monitor_recovery(appliance, progress=progress,
                               down_timeout=240.0, up_timeout=900.0)
    out: dict[str, Any] = {**rec, "verified": False, "mismatches": [], "objects": 0}
    if not rec.get("recovered"):
        out["message"] = (f"the appliance did not answer again within "
                          f"{int(rec.get('elapsed_s') or 0)} s of the restore")
        return out
    kind = pkg.classify(sent)
    if readback is None:
        readback = {pkg.KIND_CLI_DUMP: "ssh", pkg.KIND_PACKAGE: "rest"}.get(kind)
    try:
        if readback == "ssh":
            out["readback"] = "show full-configuration (SSH)"
            after = ssh_config_backup(appliance)
        elif readback == "rest":
            out["readback"] = "CLI backup (REST)"
            after, _ = cli_backup(appliance.build_client(timeout=120))
        else:
            out["message"] = ("an encrypted backup cannot be read back by SATOM: the "
                              "restore was accepted and the appliance is back, but what it "
                              "applied is not verified")
            return out
        after_sections = pkg.package_sections(after)
        actual = pkg.config_profile(after_sections)
        if expected is None:
            expected = pkg.config_profile(pkg.package_sections(sent))
        else:
            actual = {k: actual.get(k, 0) for k in expected}
    except Exception as exc:  # noqa: BLE001
        out["message"] = (f"the appliance is back but its configuration could not be read "
                          f"back ({type(exc).__name__}: {exc})"[:300])
        return out
    out["objects"] = sum(expected.values())
    out["mismatches"] = pkg.profile_diff(expected, actual)
    if hostname is not None:
        got = _hostname_of(after_sections)
        out["hostname"] = got
        if got != hostname:
            out["mismatches"].append(f"global:system global hostname: expected {hostname!r}, "
                                     f"device has {got!r}")
    out["verified"] = not out["mismatches"]
    if not rec.get("went_down"):
        out["warning"] = "the appliance was never seen going down after the restore"
    out["message"] = (
        f"verified: {out['objects']:,} objects in {len(expected)} configuration tables "
        f"read back identical" if out["verified"] else
        f"the configuration read back differs in {len(out['mismatches'])} tables")
    return out


# --------------------------------------------------------------------------- #
# The vault (on-disk store + ConfigBackup rows)                                #
# --------------------------------------------------------------------------- #
def is_encrypted(data: bytes) -> bool:
    """A FortiWeb plaintext config starts with ``#config``/``config``, and the
    box's own backup is a ZIP package; anything else (a password-encrypted
    backup) is treated as encrypted → restore will prompt for the backup
    password."""
    if pkg.classify(data) == pkg.KIND_PACKAGE:
        return False
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
    os.makedirs(d, mode=0o700, exist_ok=True)
    _keep_private_dir(d)
    return d


# [SATOM-DATA-PERMS] Every vault entry is a FULL appliance configuration:
# encrypted secrets, private keys, the whole policy. The service runs with
# UMask=0022, so the vault used to be 0755 directories of 0644 files that any
# local account (www-data, postfix, redis) could read. Directories are kept
# 0700 and files are created 0600 -- from the first byte, not narrowed after.
def _keep_private_dir(d: str) -> None:
    """Narrow ``d`` to owner-only if it is looser. Never widens; best-effort
    (`satom diagnose data` reports what this process could not fix)."""
    try:
        mode = os.stat(d).st_mode & 0o7777
        if mode & 0o077:
            os.chmod(d, mode & ~0o077)
    except OSError:
        pass


def _write_private(path: str, data: bytes) -> None:
    """Write ``data`` to ``path`` with mode 0600 from creation. O_NOFOLLOW so
    a planted symlink is refused rather than written through; the fchmod
    covers a file that already existed."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(data)


def store_bytes(*, appliance_id: int, appliance_name: str, data: bytes, filename: str,
                source: str = "upload", created_by: str = "", firmware: str | None = None,
                note: str | None = None) -> ConfigBackup:
    """Persist config bytes into the vault (file on disk + ConfigBackup row)."""
    safe_name = secure_filename(filename or "") or "config.conf"
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
    os.makedirs(dest_dir, mode=0o700, exist_ok=True)
    _keep_private_dir(dest_dir)
    dest_path = os.path.join(dest_dir, safe_name)
    try:
        _write_private(dest_path, data)
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
    res = create_backup(client)
    if isinstance(res, dict) and str(res.get("errcode", "0")) not in ("0", "", "None"):
        raise RuntimeError(
            f"device refused the backup (errcode {res.get('errcode')}): "
            f"{res.get('message', 'no message')}")
    # The backup takes a moment to appear in the on-device list — bounded poll
    # (the desktop runbook does the same; a single immediate list races it).
    name = ""
    for _ in range(15):
        for r in list_backups(client):
            if isinstance(r, dict):
                name = r.get("name") or r.get("filename") or r.get("mkey") or ""
                if name:
                    break
        if name:
            break
        time.sleep(2)
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



# --------------------------------------------------------------------------- #
# SSH fallback — capture the running config over the CLI                       #
# --------------------------------------------------------------------------- #
def _ssh_capture_note(rest_err: str) -> str:
    """SUCCESS note for an SSH-captured backup: the device REST backup was
    unavailable but the CLI dump landed. Phrased positively so the vault row
    does not read like a crash; the REST reason is compacted to its errcode."""
    m = re.search(r"errcode (-?\d+)", rest_err or "")
    detail = f"errcode {m.group(1)}" if m else "REST backup unavailable"
    return (f"Captured over SSH (show full-configuration) — device REST "
            f"backup unavailable ({detail}).")


def ssh_config_backup(appliance) -> bytes:
    """Dump the FULL running configuration over SSH (``show full-configuration``).

    The management REST API can be unavailable while the CLI still works —
    live case: an expired FortiWeb-VM trial license locks EVERY ``/api/v2.0``
    route with HTTP 423 ``errcode -20010`` but leaves SSH management intact
    (verified on fw1 8.0.5, 2026-07-04: 677 KB dump, clean start/end). The
    dump is the same CLI text a plaintext backup carries. Read-only by
    construction (:mod:`app.services.ssh_ops`)."""
    from .ssh_ops import FortiWebReadonlySSH

    with FortiWebReadonlySSH(appliance, timeout=20.0) as sess:
        text = sess.run_readonly("show full-configuration", quiet=2.5, maxt=300.0)
    body = (text or "").strip()
    if len(body) < 500 or not body.startswith("config"):
        raise RuntimeError("SSH config dump looks invalid (unexpected header)")
    if not body.endswith("end"):
        raise RuntimeError("SSH config dump looks truncated (missing trailing 'end')")
    return (body + "\n").encode()


#: Appliance kinds fetch_device_backup_auto can actually back up: FortiWeb
#: (REST local-backup, SSH dump fallback) and FortiADC (SSH dump). Any other
#: kind would fall into the FortiWeb REST path and fail. The Device Backups
#: menu entry reads this (services/adom_menu.py), so a new transport added
#: below lights the entry up in that ADOM in the same commit.
CONFIG_BACKUP_KINDS = ("fortiweb", "fortiadc")


def fetch_device_backup_auto(appliance, *, created_by: str = "",
                             method: str = "auto") -> ConfigBackup:
    """Vault-fill orchestrator with a selectable transport.

    ``method``:
      * ``"auto"``  (default) — REST local-backup first, SSH CLI dump fallback.
      * ``"rest"``  — device REST backup ONLY; raise on REST failure (no
        fallback), so the caller learns the box refused it (e.g. -901 backup
        password, -20010 license lock).
      * ``"ssh"``   — SSH ``show full-configuration`` dump ONLY (skip REST).

    REST yields the device's own backup file, so it stays the first choice in
    ``auto``; on ANY REST failure the SSH capture is tried before giving up.
    Raises ``RuntimeError`` carrying the relevant reason(s) when the chosen
    path(s) fail."""
    method = (method or "auto").lower()
    if method not in ("auto", "rest", "ssh"):
        method = "auto"

    if getattr(appliance, "kind", "") == "fortiadc":
        # FortiADC: no REST local-backup family — the CLI dump IS the config
        # backup (``show full-configuration``, LIVE-VERIFIED on FortiADC-KVM
        # 8.0.3: same SSH session mechanics as FortiWeb, clean config…end).
        if method == "rest":
            raise RuntimeError(
                "FortiADC has no REST config-backup endpoint — use the SSH "
                "method (show full-configuration) or Auto.")
        data = ssh_config_backup(appliance)
        fw = ""
        try:
            from .adc_ops import firmware_string
            fw = firmware_string(appliance.build_client(timeout=15))
        except Exception:  # noqa: BLE001 — firmware is optional metadata
            pass
        fname = (f"{(appliance.name or 'appliance')}_"
                 f"{time.strftime('%Y%m%d_%H%M%S')}_cli.conf")
        return store_bytes(
            appliance_id=appliance.id, appliance_name=appliance.name or "",
            data=data, filename=fname, source="device", created_by=created_by,
            firmware=fw or None,
            note="FortiADC — captured over SSH (show full-configuration).")

    rest_err = ""
    if method in ("auto", "rest"):
        try:
            client = appliance.build_client(timeout=120)
            return fetch_device_backup(
                client, appliance_id=appliance.id,
                appliance_name=appliance.name or "", created_by=created_by)
        except Exception as exc:  # noqa: BLE001 — fall through to the SSH dump
            rest_err = f"{type(exc).__name__}: {exc}"
            if method == "rest":
                raise RuntimeError(f"REST backup failed ({rest_err})") from exc

    # SSH path: chosen explicitly, or the auto-fallback after a REST failure.
    try:
        data = ssh_config_backup(appliance)
    except Exception as ssh_exc:  # noqa: BLE001
        if method == "ssh":
            raise RuntimeError(
                f"SSH backup failed "
                f"({type(ssh_exc).__name__}: {ssh_exc})") from ssh_exc
        raise RuntimeError(
            f"REST backup failed ({rest_err}); SSH fallback also failed "
            f"({type(ssh_exc).__name__}: {ssh_exc})") from ssh_exc
    fw = ""
    try:
        from . import upgrade as upg
        fw = upg.firmware_version(appliance.build_client(timeout=15))
    except Exception:  # noqa: BLE001 — REST is likely locked; firmware is optional
        pass
    fname = f"{(appliance.name or 'appliance')}_{time.strftime('%Y%m%d_%H%M%S')}_cli.conf"
    if method == "ssh":
        note = "Captured over SSH (show full-configuration) — SSH method requested."
    else:
        note = _ssh_capture_note(rest_err)
    return store_bytes(
        appliance_id=appliance.id, appliance_name=appliance.name or "",
        data=data, filename=fname, source="device", created_by=created_by,
        firmware=fw or None,
        note=note)


__all__ = ["RESTORE_FILE_FIELD", "CONFIG_BACKUP", "CONFIG_RESTORE", "list_backups",
           "download_backup", "create_backup", "cli_backup", "fetch_restore_point",
           "classify", "capture_source", "restore", "verify_restore", "is_encrypted", "vault_root", "store_bytes", "read_vault_bytes",
           "delete_vault", "fetch_device_backup", "ssh_config_backup",
           "fetch_device_backup_auto"]
