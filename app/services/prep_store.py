"""Pre-upgrade evidence store — persist a pre-flight run and the inventory of
published services it found, then export that inventory.

Before this module the pre-flight (:func:`app.services.upgrade.prepare`) was a
fire-and-forget REST call: it ran, its result was painted into the browser, and
it vanished with the tab. Nothing could be attached to a change request, nothing
could be cited in an approval, and "the pre-upgrade passed" was a claim with no
record behind it.

Two facts are stored per run and they are NOT the same thing:

* the **prepare() result** — backup, health battery, permission, service probes;
* the **inventory** — every server policy / virtual server the window takes
  offline, i.e. the customers to warn.

The inventory is FROZEN here on purpose. :func:`app.services.change_requests.
affected_policies` reads the appliances live, so a document rendered at approval
time and the same document rendered at execution time would describe different
fleets — and the approver signed the first one. Freezing costs a stale row when
somebody adds a policy mid-window; re-reading costs an approval that was never
given for what actually ran.

Import side-effect-free: importing this module touches no DB and contacts no
device.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from ..models import UpgradePrep, db

# --------------------------------------------------------------------------- #
#  The exportable inventory field catalog                                       #
# --------------------------------------------------------------------------- #
# (key, human label). The ORDER here is the column order of every export - the
# operator picks WHICH columns, never their order, because a report whose column
# order depends on checkbox click order is not comparable between two runs.
FIELDS: tuple[tuple[str, str], ...] = (
    ("device", "Device"),
    ("kind", "Product"),
    ("host", "Management host"),
    ("policy", "Policy / virtual server"),
    ("vserver", "Virtual server / interface"),
    ("service", "Service / port"),
    ("status", "Admin status"),
    ("url", "Probed URL"),
    ("probe_ok", "Reachable"),
    ("http_status", "HTTP status"),
    ("elapsed_ms", "Response (ms)"),
    ("pool", "Server pool"),
    ("backends", "Backends"),
    ("note", "Note"),
)
FIELD_KEYS: tuple[str, ...] = tuple(k for k, _ in FIELDS)
FIELD_LABELS: dict[str, str] = dict(FIELDS)

# What a fresh export offers when the operator has expressed no preference. The
# five columns that answer "which customer service goes down, on which box".
DEFAULT_FIELDS: tuple[str, ...] = (
    "device", "policy", "vserver", "service", "status")

_SUMMARY_MAX = 255


# --------------------------------------------------------------------------- #
#  Verdict                                                                      #
# --------------------------------------------------------------------------- #
def verdict(result: dict | None) -> tuple[bool, str]:
    """``(ok, summary)`` for one ``prepare()`` result.

    A section that was NOT REQUESTED cannot fail: ``do_backup=False`` means the
    operator chose not to take one, which is a decision, not a defect. Only
    sections actually present are graded — grading an absent section would mark
    every deliberately-narrow pre-flight as failed and train people to ignore
    the verdict.

    A failed **service probe** does not fail the run either: it is a BASELINE.
    Discovering that a policy is already unreachable before the change is the
    single most valuable thing this pre-flight produces, and burying it under a
    red verdict would push operators to re-run until it turns green.
    """
    result = result if isinstance(result, dict) else {}
    parts: list[str] = []
    ok = True
    for name in ("backup", "health"):
        section = result.get(name)
        if not isinstance(section, dict):
            continue
        if section.get("ok"):
            parts.append(f"{name} ok")
        else:
            ok = False
            parts.append(f"{name} FAILED")
    services = result.get("services")
    if isinstance(services, dict):
        if services.get("ok"):
            probes = services.get("probes") or []
            good = sum(1 for p in probes
                       if isinstance(p, dict)
                       and (p.get("result") or {}).get("ok"))
            parts.append(f"services {good}/{len(probes)} reachable")
        else:
            # The probe SWEEP itself failed (could not enumerate) - that is a
            # missing baseline, unlike an individual service answering badly.
            ok = False
            parts.append("service baseline FAILED")
    if result.get("permission") is False:
        ok = False
        parts.append("account lacks maintenance permission")
    if not parts:
        parts.append("no checks were requested")
        ok = False
    return ok, ", ".join(parts)[:_SUMMARY_MAX]


# --------------------------------------------------------------------------- #
#  Inventory                                                                    #
# --------------------------------------------------------------------------- #
def _probe_index(result: dict | None) -> dict[str, dict]:
    """policy name -> merged {target, result} row from the prepare() probes."""
    out: dict[str, dict] = {}
    services = (result or {}).get("services")
    if not isinstance(services, dict):
        return out
    for entry in services.get("probes") or []:
        if not isinstance(entry, dict):
            continue
        target = entry.get("target") or {}
        name = str(target.get("policy") or "").strip()
        if name:
            out[name] = entry
    return out


def build_inventory(policies, result: dict | None = None,
                    appliance=None) -> list[dict]:
    """Merge the affected-policy list with the pre-flight probe data into the
    rows this module exports.

    The policy list is the SPINE: a published service with no probe still has to
    appear, because "we could not probe it" and "it is not affected" are
    opposite statements and an export that drops the first one under-states the
    outage.
    """
    probes = _probe_index(result)
    kind = (getattr(appliance, "kind", "") or "") if appliance is not None else ""
    host = (getattr(appliance, "host", "") or "") if appliance is not None else ""
    rows: list[dict] = []
    for policy in policies or []:
        if not isinstance(policy, dict):
            continue
        name = str(policy.get("policy") or "")
        row = {
            "device": policy.get("device", ""),
            "device_id": policy.get("device_id"),
            "kind": policy.get("kind", "") or kind,
            "host": policy.get("host", "") or host,
            "policy": name,
            "vserver": policy.get("vserver", ""),
            "service": policy.get("service", ""),
            "status": policy.get("status", ""),
            "url": "",
            "probe_ok": "",
            "http_status": "",
            "elapsed_ms": "",
            "pool": "",
            "backends": "",
            "note": "",
        }
        entry = probes.get(name)
        if entry:
            target = entry.get("target") or {}
            probe = entry.get("result") or {}
            row["url"] = target.get("url", "")
            row["pool"] = target.get("pool", "")
            row["backends"] = ", ".join(target.get("backends") or [])
            row["note"] = target.get("note", "")
            # A probe that never ran and a probe that ran and failed must not
            # read alike: "" is unknown, False is a measured failure.
            row["probe_ok"] = bool(probe.get("ok"))
            row["http_status"] = probe.get("status")
            row["elapsed_ms"] = probe.get("elapsed_ms")
        rows.append(row)
    return rows


# --------------------------------------------------------------------------- #
#  Persistence (append-only)                                                    #
# --------------------------------------------------------------------------- #
def record(appliance, result: dict, *, inventory=None,
           created_by: str = "") -> UpgradePrep:
    """Store one pre-flight run. Always INSERTs — see :class:`UpgradePrep`."""
    ok, summary = verdict(result)
    rows = build_inventory(inventory or [], result, appliance)
    prep = UpgradePrep(
        appliance_id=getattr(appliance, "id", None),
        created_by=created_by or "",
        firmware=str((result or {}).get("firmware") or "")[:64],
        ok=ok,
        summary=summary,
        result=json.dumps(result or {}, default=str),
        inventory=json.dumps(rows, default=str),
        created_at=datetime.utcnow(),
    )
    db.session.add(prep)
    db.session.commit()
    return prep


def latest_for(appliance_id) -> UpgradePrep | None:
    """The most recent run for one appliance, or ``None``."""
    try:
        appliance_id = int(appliance_id)
    except (TypeError, ValueError):
        return None
    return (UpgradePrep.query
            .filter_by(appliance_id=appliance_id)
            .order_by(UpgradePrep.created_at.desc(), UpgradePrep.id.desc())
            .first())


def recent(appliance_id, limit: int = 10) -> list[UpgradePrep]:
    try:
        appliance_id = int(appliance_id)
    except (TypeError, ValueError):
        return []
    return (UpgradePrep.query
            .filter_by(appliance_id=appliance_id)
            .order_by(UpgradePrep.created_at.desc(), UpgradePrep.id.desc())
            .limit(max(1, min(200, int(limit or 10))))
            .all())


def get(prep_id) -> UpgradePrep | None:
    try:
        return db.session.get(UpgradePrep, int(prep_id))
    except (TypeError, ValueError):
        return None


def bind_change_request(prep, cr) -> None:
    """Record both directions of the pre-upgrade -> change link."""
    if prep is None or cr is None:
        return
    prep.cr_id = cr.id
    cr.prep_id = prep.id
    db.session.commit()


# --------------------------------------------------------------------------- #
#  Export                                                                       #
# --------------------------------------------------------------------------- #
def select_fields(keys) -> list[str]:
    """Validate an operator field selection.

    Unknown keys are DROPPED, and an empty/absent selection falls back to
    :data:`DEFAULT_FIELDS` — an export with zero columns is a corrupt file, not
    an expression of intent. The result is always in :data:`FIELDS` order.
    """
    wanted = {str(k).strip() for k in (keys or []) if str(k).strip()}
    picked = [k for k in FIELD_KEYS if k in wanted]
    return picked or list(DEFAULT_FIELDS)


def _cell(row: dict, key: str):
    value = row.get(key, "")
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value is None:
        return ""
    return value


def export_matrix(rows, keys) -> list[list]:
    """``[[header...], [cells...], ...]`` for the chosen fields."""
    picked = select_fields(keys)
    out: list[list] = [[FIELD_LABELS[k] for k in picked]]
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        out.append([_cell(row, k) for k in picked])
    return out


def export_csv(rows, keys) -> str:
    import csv
    import io
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    for line in export_matrix(rows, keys):
        writer.writerow(line)
    return buf.getvalue()


def export_xlsx(rows, keys, *, sheet_name: str = "Affected services") -> bytes:
    from . import xlsx_writer
    return xlsx_writer.write_sheet(export_matrix(rows, keys),
                                   sheet_name=sheet_name)


__all__ = [
    "FIELDS", "FIELD_KEYS", "FIELD_LABELS", "DEFAULT_FIELDS",
    "verdict", "build_inventory", "record", "latest_for", "recent", "get",
    "bind_change_request", "select_fields", "export_matrix", "export_csv",
    "export_xlsx",
]
