"""Local, versioned source-of-truth store for device configurations.

Replaces the git-backed ``reports/`` history (retired 2026-08-05). The flat
``reports/<slug>/_config.json`` files remain as the *latest* human-readable
view — every existing consumer keeps working — but versioning, history, diff
and off-box copies now go through this store instead of git commits.

Layout::

    data/sot/objects/<aa>/<sha256>.json.gz     # content-addressed blobs
    (index)  Postgres table sot_version        # models_sot.SotVersion

Design rules:

* **The hash is the identity.** ``record()`` canonicalises the snapshot
  (sorted keys, volatile fields stripped) and hashes it; an unchanged config
  writes zero bytes and mints no version row — it only advances
  ``last_seen_at``. At fleet scale ~95% of cycles are unchanged, so the store
  grows with *change*, not with *time*.
* **Volatile fields are excluded from the identity.** ``generated_at`` and the
  per-sweep ``errors`` list differ every harvest even when the device config
  is byte-identical; hashing them would defeat the dedup entirely and quietly
  reintroduce the unbounded growth this store exists to stop.
* **Blobs live under ``data/``** so the existing ``satom-ha-datasync`` rsync
  replicates them to the standby and the system-backup bundles include them.
  No new replication mechanism.
* **Retention is a policy, not "forever".** ``prune()`` keeps the newest
  ``sot.retention_versions`` per device and anything younger than
  ``sot.retention_days``; blobs no longer referenced by any row are deleted.
  Pruning runs inside ``record()`` (same pattern as the monitor rollups): a
  fresh install has no seeded ScheduledAction rows, so a function that only
  works when the operator creates one does not exist there.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

# Snapshot keys that change every sweep without the device config changing.
VOLATILE_KEYS = ("generated_at", "errors")

DEFAULT_KEEP_VERSIONS = 60
DEFAULT_KEEP_DAYS = 180


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def store_dir() -> Path:
    d = Path(os.environ.get("SATOM_SOT_DIR")
             or (_repo_root() / "data" / "sot"))
    (d / "objects").mkdir(parents=True, exist_ok=True)
    return d


def _blob_path(sha: str) -> Path:
    return store_dir() / "objects" / sha[:2] / f"{sha}.json.gz"


def canonical_bytes(snapshot: dict) -> bytes:
    """Deterministic JSON bytes of the snapshot minus volatile fields."""
    body = {k: v for k, v in snapshot.items() if k not in VOLATILE_KEYS}
    return json.dumps(body, sort_keys=True, default=str,
                      separators=(",", ":")).encode("utf-8")


def _retention() -> tuple[int, int]:
    try:
        from . import settings_store
        keep_v = int(settings_store.get("sot.retention_versions",
                                        DEFAULT_KEEP_VERSIONS) or 0)
        keep_d = int(settings_store.get("sot.retention_days",
                                        DEFAULT_KEEP_DAYS) or 0)
        return (keep_v or DEFAULT_KEEP_VERSIONS, keep_d or DEFAULT_KEEP_DAYS)
    except Exception:  # noqa: BLE001 — retention must never sink a harvest
        return (DEFAULT_KEEP_VERSIONS, DEFAULT_KEEP_DAYS)


def record(device: str, snapshot: dict, *, source: str = "harvest") -> dict:
    """Record one harvested snapshot. Returns
    ``{changed: bool, version_id: int|None, sha256: str}``.

    Unchanged config → no new row, no new blob, newest row's ``last_seen_at``
    advances. Changed config → gzip blob written (atomic rename) + new index
    row. Prune runs after a change only (an unchanged cycle cannot create
    anything to prune).
    """
    from ..models import db
    from ..models_sot import SotVersion

    raw = canonical_bytes(snapshot)
    sha = hashlib.sha256(raw).hexdigest()
    now = datetime.utcnow()

    latest = (SotVersion.query.filter_by(device=device)
              .order_by(SotVersion.taken_at.desc(), SotVersion.id.desc())
              .first())
    if latest and latest.sha256 == sha:
        latest.last_seen_at = now
        db.session.commit()
        return {"changed": False, "version_id": latest.id, "sha256": sha}

    blob = _blob_path(sha)
    if not blob.exists():
        blob.parent.mkdir(parents=True, exist_ok=True)
        tmp = blob.with_suffix(".tmp")
        with gzip.open(tmp, "wb", compresslevel=6) as fh:
            fh.write(raw)
        os.replace(tmp, blob)

    row = SotVersion(device=device, sha256=sha, size_raw=len(raw),
                     size_gz=blob.stat().st_size,
                     total_objects=int(snapshot.get("total_objects") or 0),
                     section_count=int(snapshot.get("section_count") or 0),
                     source=source, taken_at=now, last_seen_at=now)
    db.session.add(row)
    db.session.commit()
    try:
        prune(device)
    except Exception:  # noqa: BLE001 — retention must never sink a harvest
        pass
    return {"changed": True, "version_id": row.id, "sha256": sha}


def load(version_id: int) -> dict | None:
    """Load one version's snapshot body (config sections, no volatile keys)."""
    from ..models_sot import SotVersion
    row = db_get(version_id)
    if row is None:
        return None
    blob = _blob_path(row.sha256)
    if not blob.exists():
        return None
    with gzip.open(blob, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def db_get(version_id: int):
    from ..models_sot import SotVersion
    try:
        return SotVersion.query.get(int(version_id))
    except Exception:  # noqa: BLE001
        return None


def history(device: str = "", limit: int = 30) -> list[dict]:
    """Version rows, newest first; all devices when *device* is empty."""
    from ..models_sot import SotVersion
    q = SotVersion.query
    if device:
        q = q.filter_by(device=device)
    rows = (q.order_by(SotVersion.taken_at.desc(), SotVersion.id.desc())
            .limit(int(limit)).all())
    return [r.to_dict() for r in rows]


def devices_summary() -> list[dict]:
    """Per-device: version count, latest change, latest confirmation."""
    from ..models import db
    from ..models_sot import SotVersion
    rows = (db.session.query(
                SotVersion.device,
                db.func.count(SotVersion.id),
                db.func.max(SotVersion.taken_at),
                db.func.max(SotVersion.last_seen_at))
            .group_by(SotVersion.device)
            .order_by(SotVersion.device).all())
    out = []
    for device, n, changed, seen in rows:
        out.append({"device": device, "versions": int(n),
                    "last_change": changed.isoformat(timespec="seconds") if changed else "",
                    "last_seen": seen.isoformat(timespec="seconds") if seen else ""})
    return out


def _flatten(snapshot: dict) -> dict[str, str]:
    """section/endpoint/object-key → stable JSON string, for diffing."""
    flat: dict[str, str] = {}
    sections = (snapshot or {}).get("sections") or {}
    for sec, endpoints in sections.items():
        if not isinstance(endpoints, dict):
            continue
        for ep, rows in endpoints.items():
            if not isinstance(rows, list):
                continue
            for i, obj in enumerate(rows):
                if not isinstance(obj, dict):
                    continue
                key = str(obj.get("name") or obj.get("id")
                          or obj.get("mkey") or i)
                flat[f"{sec}/{ep}/{key}"] = json.dumps(
                    obj, sort_keys=True, default=str)
    return flat


def diff(id_a: int, id_b: int, *, max_entries: int = 400) -> dict:
    """Structural diff between two versions: added / removed / changed object
    paths, plus a capped unified-style detail for changed entries."""
    a_row, b_row = db_get(id_a), db_get(id_b)
    if not a_row or not b_row:
        return {"ok": False, "error": "unknown version"}
    a, b = load(id_a), load(id_b)
    if a is None or b is None:
        return {"ok": False, "error": "blob missing (pruned?)"}
    fa, fb = _flatten(a), _flatten(b)
    added = sorted(set(fb) - set(fa))
    removed = sorted(set(fa) - set(fb))
    changed = sorted(k for k in (set(fa) & set(fb)) if fa[k] != fb[k])
    detail = []
    for k in changed[:40]:
        try:
            oa = json.loads(fa[k]); ob = json.loads(fb[k])
            keys = sorted({*oa, *ob})
            fields = [{"field": f, "a": oa.get(f), "b": ob.get(f)}
                      for f in keys if oa.get(f) != ob.get(f)]
        except Exception:  # noqa: BLE001
            fields = []
        detail.append({"path": k, "fields": fields[:24]})
    trunc = (len(added) > max_entries or len(removed) > max_entries
             or len(changed) > max_entries)
    return {"ok": True,
            "a": a_row.to_dict(), "b": b_row.to_dict(),
            "added": added[:max_entries], "removed": removed[:max_entries],
            "changed": changed[:max_entries], "changed_detail": detail,
            "n_added": len(added), "n_removed": len(removed),
            "n_changed": len(changed),
            "identical": not (added or removed or changed),
            "truncated": trunc}


def prune(device: str = "") -> dict:
    """Apply retention: per device keep the newest N versions plus anything
    younger than D days; then delete blobs no version references."""
    from ..models import db
    from ..models_sot import SotVersion
    keep_v, keep_d = _retention()
    cutoff = datetime.utcnow() - timedelta(days=keep_d)
    removed_rows = 0
    devices = ([device] if device else
               [d["device"] for d in devices_summary()])
    for dev in devices:
        rows = (SotVersion.query.filter_by(device=dev)
                .order_by(SotVersion.taken_at.desc(), SotVersion.id.desc())
                .all())
        for row in rows[keep_v:]:
            if row.taken_at and row.taken_at >= cutoff:
                continue
            db.session.delete(row)
            removed_rows += 1
    db.session.commit()

    removed_blobs = 0
    live = {sha for (sha,) in db.session.query(SotVersion.sha256).distinct()}
    objects = store_dir() / "objects"
    for sub in objects.iterdir() if objects.exists() else []:
        if not sub.is_dir():
            continue
        for f in sub.glob("*.json.gz"):
            if f.name[:-8] not in live:
                f.unlink(missing_ok=True)
                removed_blobs += 1
    return {"rows": removed_rows, "blobs": removed_blobs}


def stats() -> dict:
    """Store totals for the System Backup page and the CLI."""
    from ..models import db
    from ..models_sot import SotVersion
    n_versions = db.session.query(db.func.count(SotVersion.id)).scalar() or 0
    n_devices = (db.session.query(
        db.func.count(db.func.distinct(SotVersion.device))).scalar() or 0)
    size = 0
    n_blobs = 0
    objects = store_dir() / "objects"
    if objects.exists():
        for sub in objects.iterdir():
            if sub.is_dir():
                for f in sub.glob("*.json.gz"):
                    size += f.stat().st_size
                    n_blobs += 1
    return {"versions": int(n_versions), "devices": int(n_devices),
            "blobs": n_blobs, "bytes": size}


def push_to_backup_server() -> dict:
    """Upload blobs the external backup server does not have yet (SFTP, same
    channel as the system bundles). Content-addressed names make this
    trivially idempotent and incremental. Best-effort by contract: the caller
    records the outcome, a failure never sinks the harvest."""
    try:
        from . import backup_server as _bk
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "detail": f"backup_server unavailable: {exc}"}
    objects = store_dir() / "objects"
    paths = sorted(str(p) for p in objects.glob("*/*.json.gz")) \
        if objects.exists() else []
    if not paths:
        return {"ok": True, "detail": "nothing to push", "pushed": 0}
    if not hasattr(_bk, "push_sot_blobs"):
        return {"ok": False, "detail": "backup server push not available"}
    return _bk.push_sot_blobs(paths)
