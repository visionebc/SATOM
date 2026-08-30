"""What one ADOM actually HAS: config backups, SoT history, firmware, identity.

The four things an operator asks about a device live in four different places —
the backup server's per-device folder, the ``sot_version`` index, the firmware
store, and the appliance row — and until now the only page that joined any two
of them was System Backup, which joins them for the whole console at once. At
one ADOM you could see what SATOM *does* to a device and never what it *holds*
for it.

Two rules this module exists to enforce:

* **An empty folder is an event, not a silence.** ``days_since_push`` and the
  state it grades are the entire point: a device with no backup for eleven days
  looks exactly like a device that has never been configured to push, and only
  one of those is normal. Both are reported by name.
* **Nothing is dropped for having no owner.** A backup folder whose device was
  de-registered still appears — under the identity record if there is one, in
  an explicit *unclaimed* bucket if there is not. Four FortiWebs' worth of
  history was invisible precisely because no page had a row to hang it on.

The assembly is here, not in the view, so it can be exercised against a
database without a request and without SFTP (an unreachable server degrades to
``reachable=False`` and every device reads "unknown", never "no backups").
"""
from __future__ import annotations

from datetime import datetime

#: Days since the last config push, graded. Deliberately generous at the top —
#: the appliances' own schedules are typically daily or weekly, so a red at 3
#: days would cry wolf on a correctly configured weekly job.
FRESH_DAYS = 8
STALE_DAYS = 31


def _parse_mtime(text: str):
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(str(text)[:19], fmt)
        except (TypeError, ValueError):
            continue
    return None


def grade(days: float | None, has_files: bool) -> tuple[str, str]:
    """(state, label). ``never`` is its own state: "this device has never
    pushed" and "this device stopped pushing" need different actions, and one
    orange badge for both hides which one you are looking at."""
    if not has_files:
        return "never", "never pushed"
    if days is None:
        return "unknown", "date unreadable"
    if days <= FRESH_DAYS:
        return "ok", "%d day(s) ago" % int(days)
    if days <= STALE_DAYS:
        return "warn", "%d day(s) ago" % int(days)
    return "crit", "%d day(s) ago" % int(days)


def collect(product: str = "", *, now: datetime | None = None) -> dict:
    """Everything one ADOM holds. Empty *product* means the whole console.

    One SFTP round trip for the entire fleet listing (``inventory``), never one
    per device: at 100 appliances a per-device call is 100 connections to
    render one page.
    """
    from . import backup_server, device_identity, sot_store

    now = now or datetime.utcnow()

    try:
        inv = backup_server.inventory()
    except Exception as exc:  # noqa: BLE001 — the page renders the error state
        inv = {"configured": False, "reachable": False, "error": str(exc),
               "devices": [], "firmware": []}
    folders = {str(d.get("device") or ""): d for d in (inv.get("devices") or [])}

    sot = {row["device"]: row for row in sot_store.devices_detail(product)}
    identities = device_identity.by_product(product)

    rows = []
    claimed = set()
    for ident in identities:
        folder = folders.get(ident.slug)
        claimed.add(ident.slug)
        last = _parse_mtime((folder or {}).get("latest") or "")
        days = ((now - last).total_seconds() / 86400.0) if last else None
        state, label = grade(days, bool(folder and folder.get("count")))
        s = sot.get(ident.slug, {})
        rows.append({
            "identity": ident,
            "slug": ident.slug,
            "name": ident.name,
            "serial": ident.serial or "",
            "retired": ident.retired,
            "backups": int((folder or {}).get("count") or 0),
            "backup_latest": (folder or {}).get("latest") or "",
            "backup_files": (folder or {}).get("files") or [],
            "days_since_push": days,
            "state": state,
            "state_label": label,
            "sot_versions": int(s.get("versions") or 0),
            "sot_local": int(s.get("local") or 0),
            "sot_evacuated": int(s.get("evacuated") or 0),
            "sot_last_change": s.get("last_change") or "",
            "sot_bytes": int(s.get("bytes_gz") or 0),
        })

    # Folders on the server that no identity claims. Never hidden: this bucket
    # is where a device renamed on the appliance but not in SATOM shows up, and
    # it is the only place a totally forgotten estate is visible at all.
    unclaimed = []
    if not product:
        for slug, folder in sorted(folders.items()):
            if slug in claimed:
                continue
            last = _parse_mtime(folder.get("latest") or "")
            days = ((now - last).total_seconds() / 86400.0) if last else None
            state, label = grade(days, bool(folder.get("count")))
            unclaimed.append({
                "slug": slug, "backups": int(folder.get("count") or 0),
                "backup_latest": folder.get("latest") or "",
                "backup_files": folder.get("files") or [],
                "days_since_push": days, "state": state, "state_label": label,
            })

    # SoT devices with no identity row at all — should be empty once
    # device_identity.reconcile() has run, and says so loudly if it is not.
    orphan_sot = sorted(set(sot) - claimed) if not product else []

    firmware = []
    try:
        from ..models_firmware import FirmwareImage
        q = FirmwareImage.query
        if product:
            q = q.filter_by(product=product)
        firmware = q.order_by(FirmwareImage.id.desc()).all()
    except Exception:  # noqa: BLE001
        firmware = []

    return {
        "product": product,
        "server": {"configured": bool(inv.get("configured")),
                   "reachable": bool(inv.get("reachable")),
                   "host": inv.get("host") or "",
                   "error": inv.get("error") or ""},
        "rows": rows,
        "unclaimed": unclaimed,
        "orphan_sot": orphan_sot,
        "firmware": firmware,
        "totals": {
            "devices": len(rows),
            "retired": sum(1 for r in rows if r["retired"]),
            "backups": sum(r["backups"] for r in rows),
            "no_backup": sum(1 for r in rows if r["state"] == "never"),
            "stale": sum(1 for r in rows if r["state"] in ("warn", "crit")),
            "sot_versions": sum(r["sot_versions"] for r in rows),
            "sot_evacuated": sum(r["sot_evacuated"] for r in rows),
        },
    }
