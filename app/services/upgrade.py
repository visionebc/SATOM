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
            do_services: bool = True) -> dict:
    """Read-only upgrade pre-flight. Never changes the appliance."""
    client = appliance.build_client()
    out: dict[str, Any] = {
        "appliance": appliance.name,
        "generated_at": datetime.utcnow().isoformat(),
        "firmware": firmware_version(client),
        "permission": check_permission(client),
    }

    if do_backup:
        try:
            res = backup.create_backup(client)
            name = ""
            if isinstance(res, dict):
                r = res.get("results", res)
                name = (r.get("name") if isinstance(r, dict) else "") or "backup created"
            out["backup"] = {"ok": True, "name": name or "backup created"}
        except Exception as exc:  # noqa: BLE001
            out["backup"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}

    if do_health:
        try:
            out["health"] = {"ok": True, "text": ssh_ops.health_text(appliance)}
        except Exception as exc:  # noqa: BLE001 — SSH may be closed; non-fatal
            out["health"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}

    if do_services:
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
                  device: int = 0, timeout: float = 1800.0) -> dict:
    """Upload a firmware image and trigger the upgrade + reboot.

    DESTRUCTIVE on a real run (the box installs the image and reboots).
    ``dry_run=True`` (default) validates image + permission and returns the plan
    WITHOUT uploading. Caller must take a backup first and gate on an explicit
    confirmation.
    """
    client = appliance.build_client(timeout=timeout)
    size = len(image_bytes or b"")
    fw_before = firmware_version(client)
    plan: dict[str, Any] = {
        "dry_run": dry_run, "image": filename, "size": size, "device": device,
        "firmware_before": fw_before,
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
            f"DRY-RUN — would upload {filename} ({size:,} bytes) to {appliance.name} "
            f"(firmwareupgradedowngrade) and reboot. No image was sent.")
        _record(appliance, fw_before, filename, dry_run=True)
        return plan

    files = {"imageFile": (filename, image_bytes, "application/octet-stream")}
    resp = client.upload(FIRMWARE_ENDPOINT, files=files, data={"device": str(device)},
                         timeout=timeout)
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        body = {"status_code": getattr(resp, "status_code", None), "text": getattr(resp, "text", "")[:300]}
    plan["response"] = body
    results = body.get("results", body) if isinstance(body, dict) else {}
    rtype = results.get("type") if isinstance(results, dict) else None

    if rtype in ("confirm_maturity_M_to_F", "confirm_maturity_F_to_M"):
        plan["maturity"] = rtype
        if not confirm_maturity:
            plan["ok"] = False
            plan["message"] = (
                f"appliance requested maturity confirmation ({rtype}) — the image is "
                f"staged but NOT installed (no reboot). Re-run with confirm checked.")
            _record(appliance, fw_before, filename, dry_run=False, error=f"awaiting {rtype}")
            return plan
        cresp = client.upload(FIRMWARE_ENDPOINT,
                              files={"confirm_maturity_change": (None, "1")}, timeout=timeout)
        try:
            plan["confirm_response"] = cresp.json()
        except Exception:  # noqa: BLE001
            plan["confirm_response"] = {"status_code": getattr(cresp, "status_code", None)}
        plan["ok"] = True
        plan["message"] = (f"maturity confirmed — {appliance.name} is installing the new "
                           f"firmware and rebooting.")
        _record(appliance, fw_before, filename, dry_run=False)
        return plan

    # FortiWeb can answer HTTP 200 yet carry a NEGATIVE errcode in the body when it
    # rejects the image or the upgrade path (e.g. -28 "Incorrect upgrade file. Please
    # validate image checksum and upgrade path."). Treat that as a FAILURE — never
    # monitor a reboot that will not happen, never report a false success.
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
        current_app.logger.warning("firmware push %s: HTTP %s errcode=%s body=%s",
                                   appliance.name, getattr(resp, "status_code", "?"),
                                   err, json.dumps(body, default=str)[:600])
    except Exception:  # noqa: BLE001
        pass

    http_ok = getattr(resp, "status_code", 500) < 400
    plan["errcode"] = err
    if err < 0 or not http_ok:
        plan["ok"] = False
        detail = (f" (errcode {err}{': ' + emsg if emsg else ''})" if err < 0
                  else f" (HTTP {getattr(resp, 'status_code', '?')})")
        plan["message"] = (
            f"{appliance.name} did NOT accept the flash{detail}. The image was uploaded "
            f"but not installed and the box will not reboot — firmware unchanged. A direct "
            f"cross-branch downgrade (e.g. 8.0→7.6) is usually not a valid upgrade path; "
            f"roll back by booting the partition that already holds the older build instead.")
        _record(appliance, fw_before, filename, dry_run=False, error=plan["message"][:200])
        return plan

    plan["ok"] = True
    plan["message"] = f"firmware uploaded — {appliance.name} is rebooting into the new image."
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
PARTITION_BOOT_ENDPOINT = "/api/v2.0/system/maintenance.backuprestorefirmwareboot"


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


def _record_boot(appliance, before: str, target: str, dry_run: bool, error: str = "") -> None:
    try:
        db.session.add(ChangeHistory(
            appliance_id=getattr(appliance, "id", None),
            endpoint="system/maintenance.backuprestorefirmwareboot", mkey="",
            action="partition_boot", before=json.dumps({"firmware": before}),
            after=json.dumps({"boot_into": target}), dry_run=dry_run,
            username=_current_username(), ts=datetime.utcnow(),
        ))
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
    try:
        log_action("appliance.partition_boot", target=appliance.name,
                   extra={"boot_into": target, "dry_run": dry_run,
                          "from": before, "error": error})
    except Exception:  # noqa: BLE001
        pass


def boot_partition(appliance, *, dry_run: bool = True, timeout: float = 60.0) -> dict:
    """Boot the ALTERNATE (inactive) firmware partition and reboot.

    DESTRUCTIVE on a real run (the box reboots into the other partition and every
    fronted service is interrupted). ``dry_run=True`` (default) reads the table
    and returns the plan WITHOUT sending anything. The POST carries NO payload --
    FortiWeb boots the inactive partition (exactly what the GUI's Firmware 'boot'
    button does)."""
    info = read_partitions(appliance)
    active, alt = info["active"], info["alternate"]
    plan: dict[str, Any] = {
        "dry_run": dry_run,
        "partitions": info["partitions"],
        "active": active, "alternate": alt,
        "firmware_before": (active or {}).get("version", ""),
        "target": (alt or {}).get("version", ""),
        "target_partition": (alt or {}).get("partition"),
    }
    if not alt or not (alt.get("version") or "").strip():
        plan["ok"] = False
        plan["message"] = (
            "No alternate firmware partition is installed, so there is nothing to "
            "boot into. Upload the rollback image to the second partition first "
            "(System > Maintenance > Firmware > Upload).")
        return plan

    _CLEAN = (
        "FortiWeb will not boot partition {p} ({v}) directly: it is flagged "
        "'Upload and Reboot' (upload=1), meaning this image needs a full "
        "re-image, not a partition swap. This happens on a cross-major change "
        "(e.g. 8.0 -> 7.6), where the two releases use a different system "
        "partition size. Per Fortinet's 'Restoring firmware (clean install)', "
        "it can ONLY be done from the LOCAL CONSOLE during a boot interrupt via "
        "TFTP -- NOT over REST/SSH/Web -- and it RESETS the config to factory "
        "defaults. Use the console + TFTP clean-install runbook instead."
    )
    if str((alt or {}).get("upload")) in ("1", "True", "true"):
        plan["ok"] = False
        plan["needs_clean_install"] = True
        plan["message"] = _CLEAN.format(p=alt.get("partition"), v=alt.get("version"))
        return plan

    if dry_run:
        plan["ok"] = True
        plan["message"] = (
            f"DRY-RUN - would boot partition {alt.get('partition')} "
            f"({alt.get('version')}) and reboot {appliance.name} (currently on "
            f"{plan['firmware_before'] or '?'}). Nothing was sent.")
        _record_boot(appliance, plan["firmware_before"], plan["target"], dry_run=True)
        return plan

    client = appliance.build_client(timeout=timeout)
    resp = client.post(PARTITION_BOOT_ENDPOINT)          # NO body, per the GUI
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        body = {"status_code": getattr(resp, "status_code", None),
                "text": getattr(resp, "text", "")[:300]}
    plan["response"] = body
    results = body.get("results", body) if isinstance(body, dict) else {}

    def _errcode(*srcs):
        for s in srcs:
            if isinstance(s, dict) and s.get("errcode") not in (None, "", 0, "0"):
                try:
                    return int(str(s.get("errcode")).strip())
                except Exception:  # noqa: BLE001
                    return -1
        return 0

    err = _errcode(results, body)
    try:
        from flask import current_app
        current_app.logger.warning("partition boot %s: HTTP %s errcode=%s body=%s",
                                   appliance.name, getattr(resp, "status_code", "?"),
                                   err, json.dumps(body, default=str)[:400])
    except Exception:  # noqa: BLE001
        pass

    http_ok = getattr(resp, "status_code", 500) < 400
    plan["errcode"] = err
    if err < 0 or not http_ok:
        detail = (f" (errcode {err})" if err < 0
                  else f" (HTTP {getattr(resp, 'status_code', '?')})")
        plan["ok"] = False
        plan["message"] = (
            f"{appliance.name} did NOT accept the partition boot{detail}. Firmware "
            f"unchanged - the box is still on {plan['firmware_before'] or '?'}.")
        if err == -20014:
            plan["needs_clean_install"] = True
            plan["message"] += (
                " FortiWeb refused it (errcode -20014): this image needs a console "
                "TFTP clean-install (config reset), not a partition boot -- see the "
                "clean-install runbook.")
        _record_boot(appliance, plan["firmware_before"], plan["target"],
                     dry_run=False, error=plan["message"][:200])
        return plan

    plan["ok"] = True
    plan["boot_msg"] = results.get("msg") if isinstance(results, dict) else None
    plan["message"] = (
        f"Boot triggered - {appliance.name} is rebooting into partition "
        f"{alt.get('partition')} ({alt.get('version')}).")
    _record_boot(appliance, plan["firmware_before"], plan["target"], dry_run=False)
    return plan

__all__ = ["prepare", "push_firmware", "check_permission", "firmware_version",
           "FIRMWARE_ENDPOINT", "compatible_images", "read_image_bytes", "read_partitions", "boot_partition"]


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
