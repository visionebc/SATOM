"""Firmware-upgrade runbook for the web app — preparation (safe) and the
firmware push (destructive, dry-run by default).

Web port of the desktop ``services/upgrade.py``, reimplemented on the web's
:class:`FortiWebClient` + the web :mod:`backup`, :mod:`ssh_ops` and
:mod:`service_probe` services:

* :func:`prepare` — READ-ONLY pre-flight: take a config backup, capture the SSH
  health battery, check the account's maintenance permission, read current
  firmware, and HTTP-validate every published service. Nothing is changed.
* :func:`push_firmware` — uploads a ``.out`` image to
  ``system/maintenance.firmwareupgradedowngrade`` (multipart field ``imageFile``,
  the same call the GUI's *Upload & Reboot* makes) and the box installs + reboots.
  **dry_run=True by default**: it validates the image + permission and returns the
  plan WITHOUT sending anything. A real push records a ``ChangeHistory`` row + an
  audit entry, and honours the appliance's mature<->feature confirmation prompt.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime
from typing import Any

from ..models import ChangeHistory, db
from . import backup, service_probe, ssh_ops
from .audit import log_action

FIRMWARE_ENDPOINT = "/api/v2.0/system/maintenance.firmwareupgradedowngrade"
PERMISSION_ENDPOINT = "/api/v2.0/monitor/permission-check?grp=maint"


def _current_username() -> str:
    try:
        from flask_login import current_user
        if current_user and current_user.is_authenticated:
            return current_user.username
    except Exception:  # noqa: BLE001
        pass
    return "system"


def firmware_version(client) -> str:
    """Best-effort current firmware string from system status."""
    try:
        res = client._results_one(client.status_check())
        for k in ("firmwareVersion", "firmware_version", "version", "firmware", "ver"):
            if res.get(k):
                return str(res[k])
    except Exception:  # noqa: BLE001
        pass
    return ""


def check_permission(client) -> bool | None:
    """Does this account hold maintenance (upgrade) permission? None if unknown."""
    try:
        res = client.get(PERMISSION_ENDPOINT).json()
        results = res.get("results", res) if isinstance(res, dict) else {}
        permitted = results.get("permitted") if isinstance(results, dict) else None
        return None if permitted is None else bool(permitted)
    except Exception:  # noqa: BLE001 — non-fatal; unknown
        return None


def prepare(appliance, *, do_backup: bool = True, do_health: bool = True,
            do_services: bool = True, progress=None, created_by: str = "") -> dict:
    """Read-only upgrade/downgrade pre-flight. Never changes the appliance.

    ``progress(pct, msg)`` (optional) announces each section so a background
    job can surface every step in the tasks/toast area."""
    def _say(pct, msg):
        if progress:
            try:
                progress(int(pct), msg)
            except Exception:  # noqa: BLE001
                pass

    client = appliance.build_client()
    out: dict[str, Any] = {
        "appliance": appliance.name,
        "generated_at": datetime.utcnow().isoformat(),
        "firmware": firmware_version(client),
        "permission": check_permission(client),
    }

    if do_backup:
        _say(6, "Pre-flight - backing up the appliance configuration into the vault...")
        try:
            cb = backup.fetch_device_backup_auto(
                appliance, created_by=created_by or "")
            out["backup"] = {"ok": True, "name": cb.filename, "stored": True,
                             "backup_id": cb.id, "size_bytes": cb.size_bytes}
        except Exception as exc:  # noqa: BLE001
            out["backup"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}

    if do_health:
        _say(10, "Pre-flight - capturing the system health baseline...")
        try:
            out["health"] = {"ok": True, "text": ssh_ops.health_text(appliance)}
        except Exception as exc:  # noqa: BLE001 — SSH may be closed; non-fatal
            out["health"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}

    if do_services:
        _say(14, "Pre-flight - probing published services (baseline)...")
        try:
            targets = service_probe.resolve_targets_from_client(client)
            out["services"] = {"ok": True, "probes": service_probe.probe_targets(targets)}
        except Exception as exc:  # noqa: BLE001
            out["services"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}

    return out


def _record(appliance, before: str, after: str, dry_run: bool, error: str = "") -> None:
    try:
        db.session.add(ChangeHistory(
            appliance_id=getattr(appliance, "id", None),
            endpoint="system/maintenance.firmwareupgradedowngrade", mkey="",
            action="upgrade", before=json.dumps({"firmware": before}),
            after=json.dumps({"image": after}), dry_run=dry_run,
            username=_current_username(), ts=datetime.utcnow(),
        ))
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
    try:  # audit logging must never break the upgrade itself
        log_action("appliance.upgrade", target=appliance.name,
                   extra={"image": after, "dry_run": dry_run, "from": before, "error": error})
    except Exception:  # noqa: BLE001
        pass


def push_firmware(appliance, image_bytes: bytes, filename: str, *,
                  dry_run: bool = True, confirm_maturity: bool = False,
                  confirm_downgrade: bool = False, device: int = 0,
                  part: int = 0, active: int = 0, timeout: float = 1800.0) -> dict:
    """Upload a firmware image and drive FortiWeb's upgrade/downgrade handshake.

    Mirrors the FortiWeb GUI Firmware page (``fwb-firmware-update``) EXACTLY: a
    multipart POST of ``{imageFile, device, active, part}`` to
    ``system/maintenance.firmwareupgradedowngrade``, then the confirmation
    handshake the box demands via ``results.type``:
      * ``confirm_maturity_M_to_F`` / ``_F_to_M`` -> POST ``{confirm_maturity_change:1}``
      * ``confirm_downgrade``                     -> POST ``{confirm_down:1, device, active, part}``

    ``part``/``active`` target a SPECIFIC partition (the GUI's "Upload and Reboot"
    on the ALTERNATE partition). WITHOUT them the box flashes the ACTIVE partition
    and refuses a cross-branch image (errcode -28 "invalid upgrade path"). A
    downgrade across the maturity boundary (8.0 Feature -> 7.6 Mature) needs BOTH
    ``confirm_maturity`` and ``confirm_downgrade``.

    DESTRUCTIVE on a real run (installs + reboots). ``dry_run=True`` (default) only
    validates image + permission. Caller must back up first + gate on confirmation.
    """
    client = appliance.build_client(timeout=timeout)
    size = len(image_bytes or b"")
    fw_before = firmware_version(client)
    tgt = f" -> partition {part}" if part else ""
    plan: dict[str, Any] = {
        "dry_run": dry_run, "image": filename, "size": size, "device": device,
        "part": part, "active": active, "firmware_before": fw_before,
    }
    if size == 0:
        raise ValueError("firmware image is empty")
    if not filename.lower().endswith(".out"):
        plan["warning"] = f"{filename} does not end in .out — uploading anyway"

    permitted = check_permission(client)
    plan["permitted"] = permitted
    if permitted is False:
        raise PermissionError(
            f"{appliance.username} lacks maintenance permission on {appliance.name}")

    if dry_run:
        plan["ok"] = True
        plan["message"] = (
            f"DRY-RUN — would upload {filename} ({size:,} bytes) to {appliance.name}"
            f"{tgt} (firmwareupgradedowngrade) and reboot. No image was sent.")
        _record(appliance, fw_before, filename, dry_run=True)
        return plan

    def _post(files, data=None):
        resp = client.upload(FIRMWARE_ENDPOINT, files=files, data=data, timeout=timeout)
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
            body = {"status_code": getattr(resp, "status_code", None),
                    "text": getattr(resp, "text", "")[:300]}
        results = body.get("results", body) if isinstance(body, dict) else {}
        rtype = results.get("type") if isinstance(results, dict) else None
        return resp, body, results, rtype

    # POST #1 -- upload the image, TARGETED at the chosen partition.
    files = {"imageFile": (filename, image_bytes, "application/octet-stream")}
    data = {"device": str(device), "active": str(active), "part": str(part)}
    resp, body, results, rtype = _post(files, data)
    plan["response"] = body
    plan["handshake"] = []

    # Drive the confirmation handshake the box asks for (maturity, then downgrade).
    id_fields = {"device": (None, str(device)), "active": (None, str(active)),
                 "part": (None, str(part))}
    for _step in range(4):
        if rtype in ("confirm_maturity_M_to_F", "confirm_maturity_F_to_M"):
            plan["maturity"] = rtype
            if not confirm_maturity:
                plan["ok"] = False
                plan["message"] = (
                    f"{appliance.name} staged the image but needs MATURITY confirmation "
                    f"({rtype}) — not installed, no reboot. Re-run confirming the change.")
                _record(appliance, fw_before, filename, dry_run=False, error=f"awaiting {rtype}")
                return plan
            resp, body, results, rtype = _post({"confirm_maturity_change": (None, "1")})
            plan["handshake"].append({"sent": "confirm_maturity_change", "response": body})
            continue
        if rtype == "confirm_downgrade":
            plan["downgrade_confirm"] = True
            if not confirm_downgrade:
                plan["ok"] = False
                plan["message"] = (
                    f"{appliance.name} staged the image but needs DOWNGRADE confirmation "
                    f"— not installed, no reboot. Re-run confirming the downgrade.")
                _record(appliance, fw_before, filename, dry_run=False,
                        error="awaiting confirm_downgrade")
                return plan
            fields = {"confirm_down": (None, "1")}
            fields.update(id_fields)
            resp, body, results, rtype = _post(fields)
            plan["handshake"].append({"sent": "confirm_down", "response": body})
            continue
        break

    # FortiWeb can answer HTTP 200 yet carry a NEGATIVE errcode when it rejects the
    # image / upgrade path (e.g. -28). Treat that as a FAILURE -- never monitor a
    # reboot that will not happen, never report a false success.
    def _body_errcode(*srcs):
        for s in srcs:
            if isinstance(s, dict) and s.get("errcode") not in (None, "", 0, "0"):
                try:
                    return int(str(s.get("errcode")).strip())
                except Exception:  # noqa: BLE001
                    return -1
        return 0

    err = _body_errcode(results, body)
    emsg = ""
    for s in (results, body):
        if isinstance(s, dict) and s.get("message"):
            emsg = str(s.get("message")).strip()
            break
    try:
        from flask import current_app
        current_app.logger.warning("firmware push %s: HTTP %s errcode=%s rtype=%s body=%s",
                                   appliance.name, getattr(resp, "status_code", "?"),
                                   err, rtype, json.dumps(body, default=str)[:600])
    except Exception:  # noqa: BLE001
        pass

    http_ok = getattr(resp, "status_code", 500) < 400
    plan["errcode"] = err
    if err < 0 or not http_ok:
        plan["ok"] = False
        detail = (f" (errcode {err}{': ' + emsg if emsg else ''})" if err < 0
                  else f" (HTTP {getattr(resp, 'status_code', '?')})")
        hint = ""
        if err == -28:
            hint = (" A cross-branch image was refused for the ACTIVE partition — target the "
                    "alternate partition (part/active) like the GUI's 'Upload and Reboot'.")
        plan["message"] = (
            f"{appliance.name} did NOT accept the flash{detail}. The image was uploaded but "
            f"not installed and the box will not reboot — firmware unchanged.{hint}")
        _record(appliance, fw_before, filename, dry_run=False, error=plan["message"][:200])
        return plan

    plan["ok"] = True
    plan["message"] = (f"firmware accepted — {appliance.name} is installing{tgt} and "
                       f"rebooting into the new image.")
    _record(appliance, fw_before, filename, dry_run=False)
    return plan



# --------------------------------------------------------------------------- #
#  Firmware-repository helpers (repo-driven upgrade — no upload at upgrade time) #
# --------------------------------------------------------------------------- #
def _version_key(v: str) -> tuple:
    """Sortable key from a version string ("7.6.4" -> (7, 6, 4)); blanks sort low."""
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts) if parts else (0,)


# Tokens that mark a *virtual* FortiWeb/FortiADC (KVM/VMware/cloud); anything
# else with a real model string is treated as hardware.
_VM_TOKENS = ("vm", "kvm", "hyper-v", "hyperv", "xen", "esxi", "vmware",
              "azure", "aws", "gcp", "oci", "docker", "virtual", "cloud")


def _platform_of(text: str) -> str:
    """Classify a model/version string as "vm", "hw", or "" (unknown)."""
    t = (text or "").strip().lower()
    if not t:
        return ""
    if any(tok in t for tok in _VM_TOKENS):
        return "vm"
    return "hw"


def _platform_matches(image_platform: str, appliance) -> bool:
    """A stored image fits an appliance when the image is platform-agnostic
    ("" = universal) or its platform (hw/vm) equals the appliance's. Detection
    is lenient: if either side is unknown the image is shown, never hidden -
    the only division that matters here is Hardware vs Virtual Machine."""
    ip = (image_platform or "").strip().lower()
    if ip not in ("hw", "vm"):
        return True                              # universal / unset image
    ap = _platform_of(getattr(appliance, "model", "") or "")
    if ap not in ("hw", "vm"):
        return True                              # appliance platform unknown
    return ip == ap


def compatible_images(appliance) -> list:
    """Stored :class:`FirmwareImage` rows that can upgrade ``appliance``.

    Matched by product (``kind``) and model (blank image model = universal),
    newest version first. Pure DB read — no device call.
    """
    from ..models_firmware import FirmwareImage
    kind = (getattr(appliance, "kind", "") or "fortiweb").strip().lower()
    rows = FirmwareImage.query.filter(FirmwareImage.product == kind).all()
    matches = [fw for fw in rows if _platform_matches(getattr(fw, "platform", "") or "", appliance)]
    matches.sort(key=lambda fw: _version_key(fw.version), reverse=True)
    return matches


def read_image_bytes(image) -> bytes:
    """Read a stored firmware image off disk, verifying its recorded sha256.

    Raises ``FileNotFoundError`` if the file is gone and ``ValueError`` on a
    checksum mismatch (a corrupted / swapped file must never reach the box).
    """
    path = getattr(image, "stored_path", "") or ""
    if not path or not os.path.exists(path):
        raise FileNotFoundError(
            f"firmware file missing on disk for image {getattr(image, 'id', '?')}")
    with open(path, "rb") as fh:
        data = fh.read()
    recorded = (getattr(image, "sha256", "") or "").strip()
    if recorded:
        actual = hashlib.sha256(data).hexdigest()
        if actual != recorded:
            raise ValueError(
                f"sha256 mismatch for {getattr(image, 'filename', path)}: "
                f"recorded {recorded[:12]}…, file {actual[:12]}…")
    return data


# --------------------------------------------------------------------------- #
#  Firmware PARTITION boot (rollback to an already-installed build)            #
#                                                                             #
#  FortiWeb keeps up to two firmware partitions. The correct rollback when the #
#  target build already sits on the inactive partition is to BOOT that         #
#  partition -- NOT to re-upload the image (a cross-branch upload, e.g.         #
#  8.0->7.6, is not a valid upgrade path and the box rejects it, errcode -28). #
#  Both endpoints are taken verbatim from the FortiWeb GUI's own Firmware      #
#  component (System > Maintenance > Firmware):                                 #
#    * READ  (safe GET):  system/maintenance.backuprestore                     #
#    * BOOT  (POST, NO body): system/maintenance.backuprestorefirmwareboot     #
#      -- the box boots the *inactive* partition; there is no partition arg.    #
# --------------------------------------------------------------------------- #
PARTITION_READ_ENDPOINT = "/api/v2.0/system/maintenance.backuprestore"


def _is_active(part: dict) -> bool:
    return str((part or {}).get("active")) in ("1", "true", "True")


def read_partitions(appliance) -> dict:
    """Read the firmware partition table (mirrors the GUI Firmware page). SAFE
    (GET). Returns {partitions:[{partition,active,version,lastUpgrade,upload}],
    active, alternate}. ``alternate`` is the inactive partition that a boot would
    switch into (the rollback/roll-forward target)."""
    client = appliance.build_client(timeout=15)
    raw = client.get(PARTITION_READ_ENDPOINT).json()
    res = raw.get("results", raw) if isinstance(raw, dict) else {}
    parts = res.get("firmware") or []
    active = next((p for p in parts if _is_active(p)), None)
    alternate = next((p for p in parts
                      if not _is_active(p) and (p.get("version") or "").strip()), None)
    _alt_upload = str((alternate or {}).get("upload")) in ("1", "True", "true")
    return {"partitions": parts, "active": active, "alternate": alternate,
            "needs_clean_install": _alt_upload,
            "last_backup": res.get("lastBackup")}


__all__ = ["prepare", "push_firmware", "check_permission", "firmware_version",
           "FIRMWARE_ENDPOINT", "compatible_images", "read_image_bytes", "read_partitions"]


# --------------------------------------------------------------------------- #
#  Reboot-recovery monitor + post-flash health (used by the async flash job)   #
# --------------------------------------------------------------------------- #
def _tcp_up(host: str, port: int, timeout: float = 4.0) -> bool:
    import socket
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:  # noqa: BLE001
        return False


def monitor_recovery(appliance, *, progress=None, expect_down: bool = True,
                     down_timeout: float = 180.0, up_timeout: float = 900.0,
                     poll: float = 6.0) -> dict:
    """Watch a rebooting appliance go DOWN then come back UP after a flash.
    Best-effort, never raises. ``progress(pct, msg)`` is an optional callback.
    Returns {went_down, recovered, firmware_after, elapsed_s}."""
    import time as _t
    host, port = appliance.host, appliance.port
    started = _t.monotonic()
    went_down = False

    def _say(pct, msg):
        if progress:
            try:
                progress(int(pct), msg)
            except Exception:  # noqa: BLE001
                pass

    # Phase 1 — wait for the box to drop (confirms the reboot actually began).
    if expect_down:
        deadline = started + down_timeout
        while _t.monotonic() < deadline:
            if not _tcp_up(host, port):
                went_down = True
                break
            _say(46, "Waiting for the appliance to reboot\u2026")
            _t.sleep(poll)

    # Phase 2 — wait for the management API to answer again.
    firmware_after, recovered = "", False
    deadline = _t.monotonic() + up_timeout
    while _t.monotonic() < deadline:
        if _tcp_up(host, port):
            try:
                fw = firmware_version(appliance.build_client(timeout=8))
            except Exception:  # noqa: BLE001
                fw = ""
            if fw:
                firmware_after, recovered = fw, True
                break
        elapsed = _t.monotonic() - started
        _say(min(88, 50 + int(elapsed / up_timeout * 38)),
             "Appliance rebooting \u2014 waiting for it to come back online\u2026")
        _t.sleep(poll)

    return {"went_down": went_down, "recovered": recovered,
            "firmware_after": firmware_after,
            "elapsed_s": round(_t.monotonic() - started, 1)}


def post_flash_checks(appliance) -> dict:
    """Basic post-flash system tests: management API reachable (firmware read) +
    service policies HTTP-probed (best-effort). Never raises."""
    out: dict[str, Any] = {"firmware": "", "api_ok": False, "services": None}
    try:
        client = appliance.build_client(timeout=12)
        fw = firmware_version(client)
        out["firmware"], out["api_ok"] = fw, bool(fw)
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"[:200]
        return out
    try:
        targets = service_probe.resolve_targets_from_client(client)
        probes = service_probe.probe_targets(targets)
        up = sum(1 for p in probes if (p.get("result") or {}).get("ok"))
        out["services"] = {"total": len(probes), "up": up}
    except Exception as exc:  # noqa: BLE001
        out["services"] = {"error": f"{type(exc).__name__}: {exc}"[:160]}
    return out


def postflight(appliance, before: dict | None = None, *, do_health: bool = True,
               do_services: bool = True, progress=None) -> dict:
    """Read-only POST-flash verification mirroring :func:`prepare` - re-probe the
    published services and re-capture the SSH health battery AFTER a flash, and
    diff the services against the pre-flight ``before`` snapshot. Never raises;
    ``progress(pct, msg)`` announces each section to the tasks area."""
    def _say(pct, msg):
        if progress:
            try:
                progress(int(pct), msg)
            except Exception:  # noqa: BLE001
                pass

    out: dict[str, Any] = {"generated_at": datetime.utcnow().isoformat()}
    client = None
    try:
        client = appliance.build_client(timeout=12)
        out["firmware"] = firmware_version(client)
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"[:200]

    if do_services and client is not None:
        _say(90, "Post-flight - re-probing published services...")
        try:
            targets = service_probe.resolve_targets_from_client(client)
            after = service_probe.probe_targets(targets)
            out["services"] = {"ok": True, "probes": after}
            b = (before or {}).get("services") or {}
            before_probes = b.get("probes") if isinstance(b, dict) else None
            if before_probes:
                out["services"]["diff"] = service_probe.diff_probes(before_probes, after)
        except Exception as exc:  # noqa: BLE001
            out["services"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}

    if do_health:
        _say(94, "Post-flight - re-capturing the system health battery...")
        try:
            out["health"] = {"ok": True, "text": ssh_ops.health_text(appliance)}
        except Exception as exc:  # noqa: BLE001 - SSH may be closed; non-fatal
            out["health"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}

    return out
