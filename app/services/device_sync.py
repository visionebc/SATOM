"""Sync orchestration — populate the local cache (source of truth) from a device
and keep a git-backable per-device JSON backup.

Three triggers converge here: manual ⟳, scheduled (Automation → Actions), and
write-through after an approved edit. Live reads are read-only REST sweeps.

The per-device JSON backup lives at ``reports/<slug>/_config.json`` (git-tracked,
human-readable). Pushing it to git is opt-in (``publish=True``). Override the
reports root with ``FORTINET_REPORTS_DIR`` (tests).
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
    d = Path(os.environ.get("FORTINET_REPORTS_DIR") or (_repo_root() / "reports"))
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
        if publish:
            from . import git_service
            rel = os.path.relpath(str(p), str(_repo_root()))
            try:
                git_service.git_publish(f"device sync: {appliance.name}", [rel])
                run.detail += " | git: published"
            except Exception as exc:  # noqa: BLE001 — git never sinks the sync
                run.detail += f" | git error: {type(exc).__name__}"
        run.status = "ok"
    except Exception as exc:  # noqa: BLE001
        run.status = "error"
        run.detail = f"{type(exc).__name__}: {exc}"[:240]
    run.finished_at = datetime.utcnow()
    session.commit()
    return run


def sync_device(appliance, *, publish: bool = False, user_label: str | None = None,
                trigger: str = "manual", session=None):
    """Live sync one device: sweep -> ingest -> JSON -> (git) -> SyncRun."""
    snapshot = snapshot_from_device(appliance)
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
    """Sync several devices serially; one git publish at the end if requested."""
    runs = []
    for a in appliances:
        runs.append(sync_device(a, publish=False, user_label=user_label,
                                trigger="scheduled"))
    if publish:
        from . import git_service
        try:
            git_service.git_publish("device sync: fleet", ["reports"])
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
