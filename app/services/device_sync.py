"""Sync orchestration — populate the local cache (source of truth) from a device
and keep a git-backable per-device JSON backup.

Three triggers converge here: manual ⟳, scheduled (Automation → Actions), and
write-through after an approved edit. Live reads are read-only REST sweeps.

The per-device JSON backup lives at ``data/reports/<slug>/_config.json``
(human-readable "latest" view; ``satom-ha-datasync`` replicates it to the
standby like the rest of ``data/``). Versioning/history moved from git to the
local content-addressed store (``services.sot_store``) on 2026-08-05 — a git
repo receiving the whole fleet's snapshots hourly grows without bound at
scale. ``publish=True`` now pushes the store's blobs to the external backup
server instead of committing to git. Override the reports root with
``FORTINET_REPORTS_DIR`` (tests).
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _reports_dir() -> Path:
    # data/reports, NOT the repo-root reports/: data/ rides the existing
    # standby rsync and the backup bundles; a repo-root path would need its
    # own replication channel now that git no longer carries it. A compat
    # symlink reports/ -> data/reports covers external readers.
    d = Path(os.environ.get("FORTINET_REPORTS_DIR")
             or (_repo_root() / "data" / "reports"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def slugify(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_.-]+", "-", (name or "").strip()).strip("-")
    return s or "device"


def device_json_path(appliance) -> Path:
    d = _reports_dir() / slugify(getattr(appliance, "name", str(appliance)))
    d.mkdir(parents=True, exist_ok=True)
    return d / "_config.json"


def write_device_json(appliance, snapshot: dict) -> Path:
    """Atomic write of the per-device JSON backup."""
    p = device_json_path(appliance)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, p)
    return p


_SWEEP_ABORT_AFTER = 8


def snapshot_from_device(appliance, *, timeout: float = 20.0) -> dict:
    """Live, read-only sweep of every top-level cmdb section -> snapshot dict."""
    from .rediscovery import sweep_plan
    from ..clients.fortiweb import FortiWebClient

    client = FortiWebClient(appliance, timeout=timeout)
    plan = sweep_plan()
    sections: dict = {}
    total = 0
    errors: list[dict] = []
    consecutive = 0
    for ep in plan:
        # list_with_error surfaces device-level refusals (license lock -20010,
        # auth, dead host) while the benign -20001/-3 (endpoint absent on this
        # firmware) still reads as empty — the registry is a superset.
        rows, err = client.list_with_error(ep["urn"])
        if err:
            errors.append({"endpoint": ep["name"], "error": str(err)[:160]})
            consecutive += 1
            if consecutive >= _SWEEP_ABORT_AFTER:
                # A dead/locked box fails EVERY endpoint; keep hammering it and a
                # ~470-endpoint sweep burns 20+ minutes to learn nothing.
                errors.append({"endpoint": "_sweep",
                               "error": f"aborted after {consecutive} consecutive "
                                        "device-level failures"})
                break
            continue
        consecutive = 0
        rows = [r for r in rows if isinstance(r, dict)]
        if rows:
            sections.setdefault(ep["section"], {})[ep["name"]] = rows
            total += len(rows)
    return {
        "device": appliance.name, "appliance_id": appliance.id,
        "generated_at": datetime.utcnow().isoformat(), "total_objects": total,
        "section_count": len(sections), "sections": sections, "errors": errors,
    }


def snapshot_from_adc(appliance, *, timeout: float = 20.0) -> dict:
    """Live, read-only sweep of a FortiADC appliance -> snapshot dict.

    The ADC counterpart of :func:`snapshot_from_device`: it reuses the ADC
    discovery plan (``services.adc_ops.discovery_plan`` — every enabled
    ``product='fortiadc'`` registry endpoint, child tables excluded) and a single
    authenticated ``FortiADCClient`` fetcher, and emits the SAME snapshot shape so
    ``device_store.ingest_snapshot`` and the ``reports/<slug>/_config.json`` writer
    are shared verbatim. Must run in an app context (the registry is DB-first)."""
    from . import adc_ops

    plan = adc_ops.discovery_plan()
    fetch = adc_ops.make_fetcher(appliance)
    sections: dict = {}
    total = 0
    errors: list[dict] = []
    consecutive = 0
    for ep in plan:
        try:
            rows = fetch(ep)
        except Exception as exc:  # noqa: BLE001 — device-level refusal / dead host
            errors.append({"endpoint": ep["name"], "error": str(exc)[:160]})
            consecutive += 1
            if consecutive >= _SWEEP_ABORT_AFTER:
                # A dead/locked box fails EVERY endpoint; don't burn the whole plan.
                errors.append({"endpoint": "_sweep",
                               "error": f"aborted after {consecutive} consecutive "
                                        "device-level failures"})
                break
            continue
        consecutive = 0
        rows = [r for r in rows if isinstance(r, dict)]
        if rows:
            sections.setdefault(ep["section"], {})[ep["name"]] = rows
            total += len(rows)
    return {
        "device": appliance.name, "appliance_id": appliance.id,
        "generated_at": datetime.utcnow().isoformat(), "total_objects": total,
        "section_count": len(sections), "sections": sections, "errors": errors,
    }


# FortiAnalyzer registry endpoints that are OPERATIONAL data (live alerts,
# log rates, clocks, task queues) — excluded from the config SoT harvest so
# reports/<faz>/_config.json only changes when the CONFIG changes (no hourly
# git churn from moving timestamps/counters).
_FAZ_SOT_EXCLUDE = {
    "sys_status", "sys_ha_status", "task_task",
    "eventmgmt_alerts", "eventmgmt_alertlogs", "incidentmgmt_incidents",
    "logview_logstats", "logview_logfields", "storage_info",
}


def snapshot_from_faz(appliance, *, timeout: float = 20.0) -> dict:
    """Live, read-only sweep of a FortiAnalyzer unit -> snapshot dict.

    The FAZ counterpart of :func:`snapshot_from_adc`: every enabled
    ``product='fortianalyzer'`` registry endpoint except the operational ones
    (``_FAZ_SOT_EXCLUDE``), fetched over one authenticated JSON-RPC session,
    emitting the SAME snapshot shape so ``device_store.ingest_snapshot`` + the
    ``reports/<slug>/_config.json`` writer + git publish are shared verbatim.
    Sections come from the FAZ menu groups; unmapped endpoints land in
    "Other". Must run in an app context (the registry is DB-first)."""
    from ..clients.fortianalyzer import FortiAnalyzerClient
    from ..registry import loader
    from . import faz_menu

    reg = loader.load_faz_registry()
    section_of: dict[str, str] = {}
    try:
        for g in faz_menu.menu():
            for item in g.items:
                for logical, _label in item.logicals:
                    section_of.setdefault(logical, g.label)
    except Exception:  # noqa: BLE001 — the menu is cosmetic for the sweep
        pass

    client = FortiAnalyzerClient(appliance, timeout=timeout)
    sections: dict = {}
    total = 0
    errors: list[dict] = []
    consecutive = 0
    for name in sorted(reg):
        if name in _FAZ_SOT_EXCLUDE:
            continue
        rows, err = client.list_with_error(name)
        if err:
            errors.append({"endpoint": name, "error": str(err)[:160]})
            consecutive += 1
            if consecutive >= _SWEEP_ABORT_AFTER:
                # A dead/locked box fails EVERY endpoint; don't burn the plan.
                errors.append({"endpoint": "_sweep",
                               "error": f"aborted after {consecutive} consecutive "
                                        "device-level failures"})
                break
            continue
        consecutive = 0
        rows = [r for r in rows if isinstance(r, dict)]
        if rows:
            sections.setdefault(section_of.get(name, "Other"), {})[name] = rows
            total += len(rows)
    try:
        client.logout()
    except Exception:  # noqa: BLE001 — best-effort session hygiene
        pass
    return {
        "device": appliance.name, "appliance_id": appliance.id,
        "generated_at": datetime.utcnow().isoformat(), "total_objects": total,
        "section_count": len(sections), "sections": sections, "errors": errors,
    }


# Operational endpoints — EXCLUDED from the configuration snapshot on purpose.
# Every one of them changes between two consecutive reads of an idle unit
# (CPU/memory percentages, SMS and token quotas, the pending SCEP queue), so
# harvesting them would make the content hash differ every hour and record pure
# churn as a configuration change — defeating the dedupe that keeps the SoT
# store small. Same reasoning as _FAZ_SOT_EXCLUDE.
_FAC_SOT_EXCLUDE = {
    "system_info", "token_fortiguard_messages", "token_ftm_licenses",
    "cert_scep_requests",
}


def snapshot_from_fac(appliance, *, timeout: float = 20.0) -> dict:
    """Live, read-only sweep of a FortiAuthenticator unit -> snapshot dict.

    The FAC counterpart of :func:`snapshot_from_faz`: every enabled
    ``product='fortiauthenticator'`` registry endpoint except the operational
    ones (``_FAC_SOT_EXCLUDE``), emitting the SAME snapshot shape so
    ``device_store.ingest_snapshot`` + the ``reports/<slug>/_config.json``
    writer + the SoT store are shared verbatim. Sections come from the FAC menu
    groups; unmapped endpoints land in "Other".

    Secrets cannot leak through here: a canary round-trip on 2026-08-05
    confirmed the device omits ``radiusclients.secret`` and
    ``localusers.password`` from every GET payload. That is a property of the
    device, so it is re-verified by ``tests/test_fac_sot.py`` rather than
    assumed forever.

    Must run in an app context (the registry is DB-first)."""
    from ..clients.fortiauthenticator import FortiAuthenticatorClient
    from ..registry import loader
    from . import fac_menu

    reg = loader.load_fac_registry()
    section_of: dict[str, str] = {}
    try:
        for g in fac_menu.visible_menu():
            for item in g.items:
                for logical, _label in item.logicals:
                    section_of.setdefault(logical, g.label)
    except Exception:  # noqa: BLE001 — the menu is cosmetic for the sweep
        pass

    client = FortiAuthenticatorClient(appliance, timeout=timeout)
    sections: dict = {}
    total = 0
    errors: list[dict] = []
    consecutive = 0
    for name in sorted(reg):
        if name in _FAC_SOT_EXCLUDE:
            continue
        rows, err = client.list_with_error(name)
        if err:
            errors.append({"endpoint": name, "error": str(err)[:160]})
            consecutive += 1
            if consecutive >= _SWEEP_ABORT_AFTER:
                # A dead box or a revoked API key fails EVERY endpoint; don't
                # burn the plan hammering it.
                errors.append({"endpoint": "_sweep",
                               "error": f"aborted after {consecutive} consecutive "
                                        "device-level failures"})
                break
            continue
        consecutive = 0
        rows = [r for r in rows if isinstance(r, dict)]
        if rows:
            sections.setdefault(section_of.get(name, "Other"), {})[name] = rows
            total += len(rows)
    # No logout: FortiAuthenticator authenticates each request with the API key
    # (HTTP Basic), so there is no session to release.
    return {
        "device": appliance.name, "appliance_id": appliance.id,
        "generated_at": datetime.utcnow().isoformat(), "total_objects": total,
        "section_count": len(sections), "sections": sections, "errors": errors,
    }


def snapshot_for(appliance, *, timeout: float = 20.0) -> dict:
    """Product-aware config sweep: dispatch to the FortiADC, FortiAnalyzer,
    FortiAuthenticator or FortiWeb sweep by ``appliance.kind``. All return the same snapshot dict
    shape, so every downstream (cache ingest, JSON backup, git publish) is
    product-agnostic."""
    kind = str(getattr(appliance, "kind", "") or "").lower()
    if kind == "fortiadc":
        return snapshot_from_adc(appliance, timeout=timeout)
    if kind == "fortianalyzer":
        return snapshot_from_faz(appliance, timeout=timeout)
    if kind == "fortiauthenticator":
        return snapshot_from_fac(appliance, timeout=timeout)
    return snapshot_from_device(appliance, timeout=timeout)


def persist_snapshot(appliance, snapshot: dict, *, source: str = "live",
                     trigger: str = "manual", user_label: str | None = None,
                     publish: bool = False, session=None):
    """Ingest into the cache, write the JSON backup, optionally git-publish it,
    and record a SyncRun. Returns the SyncRun (committed)."""
    from ..extensions import db
    from ..models_cache import SyncRun
    from . import device_store

    session = session or db.session
    run = SyncRun(appliance_id=getattr(appliance, "id", None), section="_all",
                  trigger=trigger, user_label=user_label, status="ok")
    session.add(run)
    session.flush()
    try:
        res = device_store.ingest_snapshot(appliance.id, snapshot, source=source,
                                           session=session)
        changed = sum(1 for v in res.values() if v.get("changed"))
        p = write_device_json(appliance, snapshot)
        run.changed = changed
        run.detail = (f"{snapshot.get('total_objects', 0)} objects, "
                      f"{len(res)} sections, json={p.name}")
        try:
            from . import sot_store
            sr = sot_store.record(slugify(appliance.name), snapshot)
            run.detail += (" | sot: new version" if sr.get("changed")
                           else " | sot: unchanged")
        except Exception as exc:  # noqa: BLE001 — the store never sinks the sync
            run.detail += f" | sot error: {type(exc).__name__}"
        if publish:
            from . import sot_store
            try:
                pr = sot_store.push_to_backup_server()
                run.detail += (" | off-box: pushed" if pr.get("ok")
                               else f" | off-box: {pr.get('detail', '')[:80]}")
            except Exception as exc:  # noqa: BLE001 — push never sinks the sync
                run.detail += f" | off-box error: {type(exc).__name__}"
        run.status = "ok"
    except Exception as exc:  # noqa: BLE001
        run.status = "error"
        run.detail = f"{type(exc).__name__}: {exc}"[:240]
    run.finished_at = datetime.utcnow()
    session.commit()
    return run


def sync_device(appliance, *, publish: bool = False, user_label: str | None = None,
                trigger: str = "manual", session=None):
    """Live sync one device: sweep -> ingest -> JSON -> (git) -> SyncRun.

    Product-aware: FortiWeb and FortiADC appliances both flow through here (the
    sweep is picked by ``kind`` in :func:`snapshot_for`)."""
    snapshot = snapshot_for(appliance)
    if not snapshot.get("total_objects"):
        # Device-level failure (license lock -20010, dead host, auth): EVERY
        # endpoint failed. Record an error run and do NOT ingest or overwrite
        # the JSON backup — the last good cache stays the source of truth.
        from ..extensions import db
        from ..models_cache import SyncRun
        session = session or db.session
        errs = snapshot.get("errors") or [{"error": "device returned no objects"}]
        run = SyncRun(appliance_id=getattr(appliance, "id", None), section="_all",
                      trigger=trigger, user_label=user_label, status="error",
                      detail=(f"device refused the sweep ({len(errs)} endpoints "
                              f"failed, 0 objects) — cache kept. First error: "
                              f"{errs[0].get('error', '')}")[:240])
        run.finished_at = datetime.utcnow()
        session.add(run)
        session.commit()
        return run
    return persist_snapshot(appliance, snapshot, source="live", trigger=trigger,
                            user_label=user_label, publish=publish, session=session)


def sync_fleet(appliances, *, publish: bool = False, user_label: str | None = None):
    """Sync several devices serially; one off-box blob push at the end if
    requested (the store dedups, so the push only carries what changed)."""
    runs = []
    for a in appliances:
        runs.append(sync_device(a, publish=False, user_label=user_label,
                                trigger="scheduled"))
    if publish:
        from . import sot_store
        try:
            sot_store.push_to_backup_server()
        except Exception:  # noqa: BLE001
            pass
    return runs


def backfill_from_git(*, session=None) -> dict:
    """Seed the cache from existing reports/<slug>/_config.json files (no box)."""
    from ..extensions import db
    from ..models import Appliance
    from . import device_store

    session = session or db.session
    out: dict = {}
    appliances = Appliance.query.all()
    by_slug = {slugify(a.name): a for a in appliances}
    by_id = {a.id: a for a in appliances}
    for cfg in sorted(_reports_dir().glob("*/_config.json")):
        try:
            snap = json.loads(cfg.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            out[cfg.parent.name] = "unreadable"
            continue
        aid = snap.get("appliance_id")
        appliance = by_id.get(aid) or by_slug.get(cfg.parent.name)
        if appliance is None:
            out[cfg.parent.name] = "no matching appliance"
            continue
        res = device_store.ingest_snapshot(appliance.id, snap, source="git",
                                           session=session)
        out[cfg.parent.name] = {"appliance_id": appliance.id, "sections": len(res)}
    return out


def deep_snapshot_from_device(appliance, *, timeout: float = 30.0) -> dict:
    """Deep, read-only walk of every server policy + WPP -> enriched snapshot
    (by-parent sub-tables + named-rule objects nested under ``_deep``). Serial
    per box by design (gentle on the appliance); device-level fan-out lives in
    services.deep_jobs."""
    from .deep_capture import deep_sections
    from ..clients.fortiweb import FortiWebClient
    from . import clone

    client = FortiWebClient(appliance, timeout=timeout)
    reader = clone.ClientReader(client)
    sections = deep_sections(reader)
    total = sum(len(rows) for sec in sections.values() for rows in sec.values())
    return {
        "device": appliance.name, "appliance_id": appliance.id,
        "generated_at": datetime.utcnow().isoformat(), "total_objects": total,
        "section_count": len(sections), "sections": sections, "errors": [],
    }


def persist_deep_snapshot(appliance, snapshot: dict, *, trigger: str = "deep",
                          user_label: str | None = None, session=None):
    """Atomic replace of the device's ``deep`` layer, then ingest the enriched
    snapshot under layer='deep' (per-device-per-layer freshness). Records a
    SyncRun. Returns the ingest result {section: {objects, changed}}."""
    from ..extensions import db
    from ..models_cache import SyncRun
    from . import device_store
    session = session or db.session
    run = SyncRun(appliance_id=getattr(appliance, "id", None), section="_deep",
                  trigger=trigger, user_label=user_label, status="ok")
    session.add(run)
    session.flush()
    try:
        device_store.wipe_layer(appliance.id, "deep", session=session)
        res = device_store.ingest_snapshot(appliance.id, snapshot, source="live",
                                           layer="deep", session=session)
        run.changed = sum(1 for v in res.values() if v.get("changed"))
        run.detail = (f"{snapshot.get('total_objects', 0)} deep objects, "
                      f"{len(res)} sections")
        run.status = "ok"
    except Exception as exc:  # noqa: BLE001
        res = {}
        run.status = "error"
        run.detail = f"{type(exc).__name__}: {exc}"[:240]
    run.finished_at = datetime.utcnow()
    session.commit()
    return res
