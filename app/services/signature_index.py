"""The local signature index — read from the signature source device, kept
version after version.

Every FortiWeb downloads its signature database from FortiGuard with its own
licence; nothing about signatures travels in a pack or through a SATOM
release. What SATOM does is read that database off ONE device the operator
chooses as the **signature source** (setting ``signatures.source.<product>``),
READ-ONLY over REST:

* the database version: ``GET /api/v2.0/system/config.fortiguard``
  (``signature_freshness``, with ``diagnose system update info`` over SSH as
  the fallback);
* the catalog: the ``waf/signature.advanced.*`` walk (``signature_catalog``).

:func:`record` turns one read into an index update:

1. canonical rows (sorted by id) -> sha256. Equal to the LATEST snapshot's hash
   -> ``unchanged``, nothing written.
2. otherwise a new ``signature_snapshots`` row, the delta against the previous
   snapshot in ``signature_changes`` (added / removed / changed), and the
   ``signature_entries`` index upserted (lineage: first seen, last seen,
   removed in). The first snapshot of a product is the BASELINE: its
   signatures are not reported as "new".
3. the content as ``data/signatures/objects/<hash>.json.gz`` and the legacy
   ``data/signatures.json`` (what the signature editor and the WPP views read)
   rewritten from the source — only the source writes it now.

An empty read is refused, never indexed: a device that answers 0 signatures
would otherwise mark the whole index removed.

Verified against the lab FortiWeb 7.6.8 and 8.0.6 (2026-10-08): both answer
``config.fortiguard`` and the ``waf/signature.advanced.*`` walk.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

PRODUCTS = ("fortiweb",)
K_SOURCE = "signatures.source.%s"
_FIELDS = ("id", "desc", "main_id", "sub_id", "main_name", "sub_name")


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------
def _data_root() -> Path:
    from flask import current_app
    return Path(current_app.root_path).parent / "data"


def objects_dir() -> Path:
    from flask import current_app
    base = current_app.config.get("SIGNATURE_DATA_DIR") or (_data_root() / "signatures")
    p = Path(base) / "objects"
    p.mkdir(parents=True, exist_ok=True)
    return p


def catalog_path() -> str:
    """``data/signatures.json`` — the catalog the signature views read."""
    from flask import current_app
    explicit = current_app.config.get("SIGNATURE_CATALOG_PATH")
    if explicit:
        return str(explicit)
    d = _data_root()
    d.mkdir(parents=True, exist_ok=True)
    return str(d / "signatures.json")


# ---------------------------------------------------------------------------
# the source device
# ---------------------------------------------------------------------------
def source_id(product: str = "fortiweb") -> int | None:
    from ..models import AppSetting
    try:
        n = int(str(AppSetting.get(K_SOURCE % product) or "").strip())
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def set_source(product: str, appliance_id: int | None) -> None:
    from ..models import AppSetting
    AppSetting.set(K_SOURCE % product, str(int(appliance_id)) if appliance_id else "")


def source_appliance(product: str = "fortiweb"):
    """The configured source, or ``None`` when unset, deleted or of another
    product (a stale id never silently reads the wrong kind of box)."""
    from ..models import Appliance
    aid = source_id(product)
    if aid is None:
        return None
    ap = Appliance.query.get(aid)
    return ap if ap is not None and (ap.kind or "") == product else None


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------
def canonical(sigdb) -> list[dict]:
    """The database as sorted, comparable rows (status / has_filter are the
    signature SET's state, not the database's, and stay out)."""
    rows = {}
    for s in getattr(sigdb, "signatures", None) or []:
        sid = str(getattr(s, "id", "") or "").strip()
        if not sid:
            continue
        rows[sid] = {"id": sid,
                     "desc": str(getattr(s, "desc", "") or ""),
                     "main_id": str(getattr(s, "main_id", "") or ""),
                     "sub_id": str(getattr(s, "sub_id", "") or ""),
                     "main_name": str(getattr(s, "main_name", "") or ""),
                     "sub_name": str(getattr(s, "sub_name", "") or "")}
    return [rows[k] for k in sorted(rows)]


def content_hash(rows: list[dict]) -> str:
    blob = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def diff(old: dict, new: dict) -> tuple[list[str], list[str], list[str]]:
    """``(added, removed, changed)`` signature ids between two ``{id: row}``
    maps. ``changed`` = same id, any indexed field different (a new
    description, or the signature moved class)."""
    added = sorted(k for k in new if k not in old)
    removed = sorted(k for k in old if k not in new)
    changed = sorted(k for k in new if k in old
                     and any(new[k].get(f) != old[k].get(f) for f in _FIELDS))
    return added, removed, changed


# ---------------------------------------------------------------------------
# objects
# ---------------------------------------------------------------------------
def _write_object(h: str, rows: list[dict]) -> None:
    p = objects_dir() / ("%s.json.gz" % h)
    if p.exists():
        return
    tmp = p.with_suffix(".tmp")
    with gzip.open(tmp, "wt", encoding="utf-8") as fh:
        json.dump(rows, fh, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, p)


def _read_object(h: str) -> list[dict] | None:
    try:
        with gzip.open(objects_dir() / ("%s.json.gz" % h), "rt", encoding="utf-8") as fh:
            rows = json.load(fh)
    except (OSError, ValueError):
        return None
    return rows if isinstance(rows, list) else None


def _previous_rows(product: str, prev) -> dict:
    """``{id: row}`` of the previous snapshot: its object, else the live
    (not removed) index entries — a lost object never makes everything 'new'."""
    from ..models_signatures import SignatureEntry as E
    rows = _read_object(prev.content_hash) if prev is not None else None
    if rows is not None:
        return {r["id"]: r for r in rows if isinstance(r, dict) and r.get("id")}
    out = {}
    for e in E.query.filter(E.product == product, E.removed_in_version.is_(None)):
        out[e.sig_id] = {"id": e.sig_id, "desc": e.description, "main_id": e.main_id,
                         "sub_id": e.sub_id, "main_name": e.main_name,
                         "sub_name": e.sub_name}
    return out


# ---------------------------------------------------------------------------
# queries
# ---------------------------------------------------------------------------
def latest(product: str = "fortiweb"):
    from ..models_signatures import SignatureSnapshot as S
    return (S.query.filter(S.product == product)
            .order_by(S.taken_at.desc(), S.id.desc()).first())


def needs_collect(product: str, db_version: str) -> bool:
    """True when the index has never been built or is at another version."""
    last = latest(product)
    return last is None or (db_version or "") != (last.db_version or "")


def snapshots(product: str = "fortiweb", limit: int = 20) -> list:
    from ..models_signatures import SignatureSnapshot as S
    return (S.query.filter(S.product == product)
            .order_by(S.taken_at.desc(), S.id.desc()).limit(limit).all())


def changes(snapshot_id: int, limit: int = 5000) -> list:
    from ..models_signatures import SignatureChange as C
    return (C.query.filter(C.snapshot_id == snapshot_id)
            .order_by(C.kind, C.sig_id).limit(limit).all())


def entry_count(product: str = "fortiweb") -> int:
    from ..models_signatures import SignatureEntry as E
    return E.query.filter(E.product == product, E.removed_in_version.is_(None)).count()


def search(product: str, needle: str, *, limit: int = 200,
           include_removed: bool = False) -> list:
    """Index rows whose id, description or class names contain ``needle``."""
    from ..models_signatures import SignatureEntry as E
    n = (needle or "").strip()
    if not n:
        return []
    like = "%" + n.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    q = E.query.filter(E.product == product).filter(
        E.sig_id.ilike(like, escape="\\") | E.description.ilike(like, escape="\\")
        | E.sub_name.ilike(like, escape="\\") | E.main_name.ilike(like, escape="\\"))
    if not include_removed:
        q = q.filter(E.removed_in_version.is_(None))
    return q.order_by(E.sig_id).limit(limit).all()


# ---------------------------------------------------------------------------
# record one read
# ---------------------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def record(product: str, sigdb, *, db_version: str, engine_version: str = "",
           source=None, taken_by: str = "", now: datetime | None = None) -> dict:
    """Index one database read. ``{"status": "new"|"unchanged", "snapshot_id",
    "db_version", "prev_version", "sig_count", "added", "removed", "changed",
    "baseline"}``. Raises ``ValueError`` on an empty read."""
    from ..extensions import db
    from ..models_signatures import (SignatureChange as C, SignatureEntry as E,
                                     SignatureSnapshot as S)
    from . import signature_catalog as sigcat
    now = now or _now()
    rows = canonical(sigdb)
    if not rows:
        raise ValueError("the source answered 0 signatures — not indexed (an empty "
                         "read would mark every signature removed)")
    h = content_hash(rows)
    prev = latest(product)
    base = {"db_version": db_version or "", "sig_count": len(rows),
            "prev_version": prev.db_version if prev is not None else ""}
    if prev is not None and prev.content_hash == h:
        if (db_version or "") and prev.db_version != db_version:
            # Same content under a new version string: follow the version.
            prev.db_version = db_version
            db.session.commit()
        return dict(base, status="unchanged", snapshot_id=prev.id, added=0,
                    removed=0, changed=0, baseline=False)

    new = {r["id"]: r for r in rows}
    old = _previous_rows(product, prev)
    added, removed, changed = diff(old, new)
    baseline = prev is None
    _write_object(h, rows)
    snap = S(product=product, db_version=db_version or "",
             engine_version=engine_version or "",
             firmware=getattr(sigdb, "firmware", "") or "",
             source_name=getattr(source, "name", "") or "",
             source_appliance_id=getattr(source, "id", None),
             signature_set=getattr(sigdb, "signature_set", "") or "",
             content_hash=h, sig_count=len(rows),
             subclass_count=len({(r["main_id"], r["sub_id"]) for r in rows}),
             added=0 if baseline else len(added), removed=len(removed),
             changed=len(changed), baseline=baseline,
             prev_snapshot_id=prev.id if prev is not None else None,
             taken_by=(taken_by or "")[:128], taken_at=now)
    db.session.add(snap)
    db.session.flush()
    if not baseline:
        for sid in added:
            db.session.add(C(snapshot_id=snap.id, product=product, sig_id=sid,
                             kind=C.KIND_ADDED, sub_name=new[sid]["sub_name"],
                             new_description=new[sid]["desc"]))
        for sid in changed:
            db.session.add(C(snapshot_id=snap.id, product=product, sig_id=sid,
                             kind=C.KIND_CHANGED, sub_name=new[sid]["sub_name"],
                             old_description=old[sid].get("desc", ""),
                             new_description=new[sid]["desc"]))
    for sid in removed:
        db.session.add(C(snapshot_id=snap.id, product=product, sig_id=sid,
                         kind=C.KIND_REMOVED, sub_name=old[sid].get("sub_name", ""),
                         old_description=old[sid].get("desc", "")))

    entries = {e.sig_id: e for e in E.query.filter(E.product == product)}
    for sid, r in new.items():
        e = entries.get(sid)
        if e is None:
            e = E(product=product, sig_id=sid, first_seen_version=db_version or "",
                  first_seen_at=now)
            db.session.add(e)
        e.main_id, e.sub_id = r["main_id"], r["sub_id"]
        e.main_name, e.sub_name, e.description = r["main_name"], r["sub_name"], r["desc"]
        e.last_seen_version, e.last_seen_at = db_version or "", now
        e.removed_in_version, e.removed_at = None, None
    for sid in removed:
        e = entries.get(sid)
        if e is not None:
            e.removed_in_version, e.removed_at = db_version or "", now
    db.session.commit()
    try:
        sigcat.save_signature_db(sigdb, catalog_path())
    except OSError:
        pass  # the index is the record; the legacy file is a convenience
    return dict(base, status="new", snapshot_id=snap.id,
                added=0 if baseline else len(added), removed=len(removed),
                changed=len(changed), baseline=baseline)


# ---------------------------------------------------------------------------
# collect from the source + tell the administrators
# ---------------------------------------------------------------------------
def collect(appliance, *, taken_by: str = "scheduled", progress=None) -> dict:
    """Read the version and the whole catalog off ``appliance`` (READ-ONLY)
    and :func:`record` it. Raises on a dead box / no signature set / an
    empty read — the caller reports it."""
    from . import signature_catalog as sigcat
    from . import signature_freshness as sf
    client = appliance.build_client()
    parsed, err = sf.read_version_rest(client)
    if err or not (parsed or {}).get("version"):
        parsed, err2 = sf.read_version_cli(appliance)
        if err2 or not (parsed or {}).get("version"):
            raise RuntimeError("signature DB version unreadable on %s: %s"
                               % (appliance.name, err2 or err or "no version"))
    sset = sigcat.pick_signature_set(client)
    if not sset:
        raise RuntimeError("no signature set on %s to read the catalog with"
                           % appliance.name)
    try:
        firmware = appliance.fw_version or ""
    except Exception:  # noqa: BLE001 — informational
        firmware = ""
    sigdb = sigcat.sync_signature_database(client, sset, firmware=firmware,
                                           progress=progress)
    product = appliance.kind or "fortiweb"
    return dict(record(product, sigdb, db_version=parsed["version"],
                       engine_version=parsed.get("engine", ""), source=appliance,
                       taken_by=taken_by),
                source=appliance.name, product=product)


def headline(res: dict) -> str:
    """One line for a log, a job and a notification."""
    if res.get("status") == "unchanged":
        return ("signature index unchanged at %s (%d signatures)"
                % (res.get("db_version") or "?", res.get("sig_count", 0)))
    if res.get("baseline"):
        return ("signature index created: %d signatures, DB %s"
                % (res.get("sig_count", 0), res.get("db_version") or "?"))
    return ("signatures %s -> %s: +%d new, %d changed, -%d removed"
            % (res.get("prev_version") or "?", res.get("db_version") or "?",
               res.get("added", 0), res.get("changed", 0), res.get("removed", 0)))


def announce(res: dict) -> int:
    """Bell notification to the administrators for a NEW snapshot. Returns the
    number of notifications pushed (0 when nothing changed)."""
    if res.get("status") != "new":
        return 0
    from . import notifications as notify
    from .alerts import _admin_ids
    product = res.get("product") or "fortiweb"
    title = ("FortiWeb " if product == "fortiweb" else product + " ") + headline(res)
    body = ("Read from %s. %d signatures indexed."
            % (res.get("source") or "the signature source", res.get("sig_count", 0)))
    return notify.push_many(_admin_ids(), title[:200], kind="info", body=body,
                            link="/web/signatures/snapshots/%s" % res.get("snapshot_id"))


__all__ = ["PRODUCTS", "K_SOURCE", "catalog_path", "objects_dir", "source_id",
           "set_source", "source_appliance", "canonical", "content_hash", "diff",
           "latest", "needs_collect", "snapshots", "changes", "entry_count",
           "search", "record", "collect", "headline", "announce"]
