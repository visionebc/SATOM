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

import json
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

    ok = getattr(resp, "status_code", 500) < 400
    plan["ok"] = ok
    plan["message"] = (f"firmware uploaded — {appliance.name} is rebooting into the new image."
                       if ok else f"upload failed (HTTP {getattr(resp, 'status_code', '?')}).")
    _record(appliance, fw_before, filename, dry_run=False, error="" if ok else plan["message"])
    return plan


__all__ = ["prepare", "push_firmware", "check_permission", "firmware_version",
           "FIRMWARE_ENDPOINT"]
