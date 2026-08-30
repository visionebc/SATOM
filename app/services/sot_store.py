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
  reintroduce the unbounded growth this store exists to stop. The same is true
  of fields NESTED inside ``sections`` -- the appliance's own clock, its
  internal object handles, and its reverse-reference projections -- which is
  what :func:`normalise` strips. Stripping happens on the way to the HASH
  only; the stored blob keeps every field.
* **Blobs live under ``data/``** so the existing ``satom-ha-datasync`` rsync
  replicates them to the standby and the system-backup bundles include them.
  No new replication mechanism.
* **Two lifetimes, never one.** The INDEX (``sot_version`` rows) is the change
  log; the PAYLOAD (blobs) is what it points at. ``evacuate()`` moves payload
  off-box and leaves every row; ``archive_log()`` writes whole past months of
  ROWS to the backup server as JSONL and only then deletes them. Both obey the
  same order: confirm the server holds it, then delete locally — a listing
  that fails reads as "nothing is off-box", never as permission to delete.
  Payload retention runs inside ``record()`` (same pattern as the monitor
  rollups): a fresh install has no seeded ScheduledAction rows, so a function
  that only works when the operator creates one does not exist there.
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

# --- Nested volatility -----------------------------------------------------
# VOLATILE_KEYS is top-level only, and that was not enough: the fields that
# actually churn live INSIDE ``sections``, so they were hashed and every hourly
# harvest minted a new version of an unchanged device. Measured against the
# store on a1 (2026-08-11) over all 206 consecutive version pairs: 194 of them
# -- 94% -- differed ONLY in the appliance's own wall clock, and those pairs
# are ~640 of the last week's "config drift" alerts. The dedup this store
# exists to provide was switched off for FortiADC entirely, and a real drift
# would have been buried under the noise.
#
# Every rule below strips a field the APPLIANCE moves on its own. A field an
# operator can set is never stripped: ``tz``, ``ntpsync``, ``dst`` and
# ``syncinterval`` sit in the SAME object as the clock and are deliberately
# kept -- the goal is to stop reporting the clock, not to stop reporting time
# configuration.
#
# This governs IDENTITY only. ``record()`` still stores the snapshot whole, so
# history, diff and restore keep seeing exactly what the appliance returned.
# The rules decide when a version is MINTED, never what it contains.

#: Wall-clock readings. Dropped only inside an object that carries
#: ``CLOCK_MARKER``, so a configuration field that happens to be named
#: ``hour``/``month`` elsewhere in the tree keeps being hashed.
CLOCK_MARKER = "system_dateTime"
CLOCK_FIELDS = frozenset({
    "hour", "minute", "second", "mday", "month", "year",
    "system_date", "system_dateTime",
})

#: Reverse-reference projections: ``q_ref`` counts the objects pointing at this
#: one and ``q_ref_string`` lists them, newline separated and in an unstable
#: order. Sorted, NOT dropped -- a genuine reference change is still a change,
#: and dropping it would hide the consequence of an object being deleted.
REF_LIST_KEYS = frozenset({"q_ref_string"})

#: Windows the appliance re-bases forward by itself. FortiWeb cookie security
#: advances ``allow-time`` with no operator involvement.
ROLLING_KEYS = frozenset({"allow-time"})

#: Suffix of an internal numeric handle (``signature-rule_val`` next to
#: ``signature-rule``). The appliance renumbers handles when proxyd restarts --
#: that alone accounted for 109 differing leaves across a fortiweb08 reboot --
#: while the sibling NAME the handle resolves to does not move. Stripped only
#: when that sibling is present, so a standalone ``*_val`` field stays hashed.
HANDLE_SUFFIX = "_val"


def normalise(value):
    """Strip appliance-side churn so the identity tracks CONFIGURATION.

    Recursive and total: returns a structure of the same shape with the
    volatile leaves removed or canonicalised. Pure -- no I/O, no ORM -- so the
    rules can be tested against a literal snapshot.
    """
    if isinstance(value, list):
        return [normalise(v) for v in value]
    if not isinstance(value, dict):
        return value
    has_clock = CLOCK_MARKER in value
    out = {}
    for key, val in value.items():
        if has_clock and key in CLOCK_FIELDS:
            continue
        if key.endswith(HANDLE_SUFFIX) and key[:-len(HANDLE_SUFFIX)] in value:
            continue
        if key in ROLLING_KEYS:
            continue
        if key in REF_LIST_KEYS and isinstance(val, str):
            out[key] = "\n".join(sorted(p for p in val.split("\n") if p))
            continue
        out[key] = normalise(val)
    return out

# ── Retention: the INDEX and the PAYLOAD have different lifetimes ───────────
#
# The change log is permanent. ``prune()`` used to delete ``sot_version`` ROWS,
# and the row IS the log — the list an operator walks back through to find what
# a parameter used to be set to. With a one-day local policy that made the
# whole history disappear inside a day even though every byte was already
# safe on the backup server, because ``load()`` and ``diff()`` only ever
# opened the local file. There is deliberately NO knob to shorten the index:
# a setting whose only possible effect is to destroy the record this store
# exists to keep is not a policy, it is a footgun with a label.
#
# The payload is what costs disk, so the payload is what leaves. A version
# whose blob has been confirmed on the backup server is marked evacuated and
# its local file removed; :func:`load` fetches it back on demand.

#: Newest N blobs per device kept on local disk regardless of age. Two, not
#: one: a diff needs a version AND the one before it, and the overwhelmingly
#: common diff is "what changed in the last harvest". At one, the single most
#: used operation on this store would hit the network every time.
DEFAULT_LOCAL_VERSIONS = 2
#: …plus anything younger than this many days. One, as specified.
DEFAULT_LOCAL_DAYS = 1

# Kept as names because the on-disk store and its tests refer to them; they no
# longer govern row deletion, only how much payload stays local.
DEFAULT_KEEP_VERSIONS = DEFAULT_LOCAL_VERSIONS
DEFAULT_KEEP_DAYS = DEFAULT_LOCAL_DAYS

#: How long the change log stays in this node's database before whole past
#: months of it are written to the backup server and removed here.
#:
#: A year, and deliberately long. The log is not what fills a node: a row plus
#: its indexes costs ~875 B against ~62 KB for the gzipped snapshot it points
#: at, so a hundred devices changing daily add ~32 MB of rows a year against
#: ~2 GB of payload. Shortening this buys almost no disk and costs the one
#: thing the store exists for — being able to open a device's history in the
#: UI without going to the network. The knob exists so the table is bounded
#: and the log is provably off-box, not as a space measure.
#:
#: 0 disables trimming entirely: the log then stays here forever, which is
#: what this product did before the setting existed.
DEFAULT_LOG_KEEP_DAYS = 365

#: Folder under the backup server's ``system_path`` that holds the archive.
LOG_ARCHIVE_SUBDIR = "sot-log"


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
    return json.dumps(normalise(body), sort_keys=True, default=str,
                      separators=(",", ":")).encode("utf-8")


def _retention(product: str = "") -> tuple[int, int]:
    """The configured (local versions, local days) FOR ONE ADOM.

    Reads ``settings_store.sot_local_policy`` — the accessor that owns the
    keys. The call before that one was to ``settings_store.get``, a function
    this product has never defined: every harvest raised ``AttributeError``
    here, the blanket except swallowed it, and the operator's configured
    policy was discarded on every single run. The except stays (retention must
    never sink a harvest) but it is no longer the normal path.

    Per ADOM because the families are not comparable: a FortiAnalyzer snapshot
    measures 6 MB raw against a FortiWeb's 0.5 MB, so one number that suits
    both is a number that suits neither.
    """
    try:
        from . import settings_store
        cfg = settings_store.sot_local_policy(product)
        return (int(cfg["versions"]), int(cfg["days"]))
    except Exception:  # noqa: BLE001 — retention must never sink a harvest
        return (DEFAULT_LOCAL_VERSIONS, DEFAULT_LOCAL_DAYS)


def _log_retention(product: str = "") -> int:
    """Days of change log this node keeps, FOR ONE ADOM.

    Same three-deep resolution and same fail-safe as :func:`_retention`: any
    failure returns the product default rather than a number that would delete
    more. Zero is a real answer here (never trim) and is passed through.
    """
    try:
        from . import settings_store
        return int(settings_store.sot_local_policy(product)["log_days"])
    except Exception:  # noqa: BLE001 — retention must never sink a harvest
        return DEFAULT_LOG_KEEP_DAYS


def product_for_device(device: str) -> str:
    """Which ADOM a SoT device name belongs to.

    Live appliance first — a registered device is authoritative about its own
    family — then the identity record, which is the only thing that still
    knows for a device that has been de-registered. Never a guess from the
    name: ``fw7`` and ``fortiweb11`` are the same kind of box and neither
    name says so.
    """
    try:
        from ..models import Appliance
        from .device_sync import slugify
        for row in Appliance.query.all():
            if slugify(row.name or "") == device:
                return row.kind or ""
    except Exception:  # noqa: BLE001
        pass
    try:
        from . import device_identity
        return device_identity.product_for_slug(device)
    except Exception:  # noqa: BLE001
        return ""


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
        # A device that reverts to an older configuration re-writes a blob
        # that was evacuated. Every row on that sha is local again, and a row
        # still flagged evacuated would send the next read to the network for
        # a file lying on this disk.
        SotVersion.query.filter_by(sha256=sha).update({"evacuated_at": None})

    row = SotVersion(device=device, sha256=sha, size_raw=len(raw),
                     size_gz=blob.stat().st_size,
                     total_objects=int(snapshot.get("total_objects") or 0),
                     section_count=int(snapshot.get("section_count") or 0),
                     product=product_for_device(device),
                     source=source, taken_at=now, last_seen_at=now)
    db.session.add(row)
    db.session.commit()
    try:
        prune(device)
    except Exception:  # noqa: BLE001 — retention must never sink a harvest
        pass
    return {"changed": True, "version_id": row.id, "sha256": sha}


def fetch_blob(sha: str) -> bool:
    """Bring one evacuated blob back from the backup server. Never raises.

    Written to a temp file and renamed, exactly like :func:`record`: a
    half-downloaded blob under its content-addressed name would be indexed as
    present by every other function here and would then fail a hash it can no
    longer be checked against.
    """
    if not sha or len(sha) != 64 or not all(c in "0123456789abcdef" for c in sha):
        return False
    blob = _blob_path(sha)
    if blob.exists():
        return True
    try:
        from . import backup_server as _bk
        from . import settings_store as _store
        cfg = _store.backup_server()
        if not cfg.get("configured"):
            return False
        remote_dir = (cfg.get("system_path") or "/system").rstrip("/") + "/sot"
        data = _bk.fetch_file(remote_dir, f"{sha}.json.gz")
    except Exception:  # noqa: BLE001 — a missing off-box copy is not a crash
        return False
    if not data:
        return False
    # The name is the hash: verify before adopting it. A server that returned
    # the wrong bytes would otherwise poison the content-addressed store for
    # every version that shares this sha.
    try:
        if hashlib.sha256(gzip.decompress(data)).hexdigest() != sha:
            return False
    except Exception:  # noqa: BLE001
        return False
    blob.parent.mkdir(parents=True, exist_ok=True)
    tmp = blob.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, blob)
    return True


def load(version_id: int) -> dict | None:
    """Load one version's snapshot body (config sections, no volatile keys).

    A payload that has been evacuated is fetched back from the backup server
    on demand and re-cached locally. Without this the local retention policy
    would silently amputate history: the row would still list the version, the
    page would still offer to open it, and the answer would be nothing.
    """
    row = db_get(version_id)
    if row is None:
        return None
    blob = _blob_path(row.sha256)
    if not blob.exists():
        if not fetch_blob(row.sha256):
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


def remote_blob_names() -> set:
    """Blob filenames the backup server currently holds. Empty set on any
    failure — which is the whole point: an unreachable server must read as
    "nothing is off-box", so evacuation refuses to delete anything."""
    try:
        from . import backup_server as _bk
        from . import settings_store as _store
        cfg = _store.backup_server()
        if not cfg.get("configured"):
            return set()
        remote_dir = (cfg.get("system_path") or "/system").rstrip("/") + "/sot"
        inv = _bk.dir_inventory(remote_dir)
        if not inv.get("reachable"):
            return set()
        return {str(f.get("name") or "") for f in (inv.get("files") or [])}
    except Exception:  # noqa: BLE001
        return set()


def evacuate(device: str = "", *, dry_run: bool = False) -> dict:
    """Move payload off this node, keeping the index whole.

    Per device: the newest N blobs and anything younger than D days stay; every
    other version's blob is deleted locally **only after it has been seen on
    the backup server** and its row is stamped ``evacuated_at``. Rows are never
    deleted here — see the module notes on why the index has no retention knob.

    Confirm-then-delete, never delete-then-hope: an SFTP listing that fails
    yields an empty set, so an unreachable server evacuates nothing instead of
    quietly turning a retention policy into data loss. This ordering is the
    single line the whole feature rests on.
    """
    from ..models import db
    from ..models_sot import SotVersion

    devices = ([device] if device else
               [d["device"] for d in devices_summary()])

    # ONE authority for "this payload must stay local", derived once and then
    # used both to select candidates and to protect shared blobs. It was two
    # independent re-derivations of the same rule, and that redundancy meant
    # breaking either one changed nothing observable — so no test could tell
    # the difference between one intact layer and two. A rule with two authors
    # is the shape this codebase keeps retiring.
    #
    # It is computed across EVERY device, not only the ones being evacuated: a
    # sha can be shared by several devices (the same config recorded under a
    # chassis and its ADOM rows), and it may only leave when NO retained row
    # anywhere still wants it on disk.
    pinned: set = set()
    candidates: dict[str, list] = {}
    all_devices = [d["device"] for d in devices_summary()]
    now = datetime.utcnow()
    for dev in all_devices:
        keep_v, keep_d = _retention(product_for_device(dev))
        cutoff = now - timedelta(days=keep_d)
        rows = (SotVersion.query.filter_by(device=dev)
                .order_by(SotVersion.taken_at.desc(), SotVersion.id.desc())
                .all())
        for i, row in enumerate(rows):
            if i < keep_v or (row.taken_at and row.taken_at >= cutoff):
                pinned.add(row.sha256)
            elif dev in devices:
                if not _blob_path(row.sha256).exists():
                    # Already gone: stamp the row so the UI stops implying the
                    # payload is here. Costs no network and fixes rows
                    # evacuated by an older build.
                    if row.evacuated_at is None and not dry_run:
                        row.evacuated_at = now
                    continue
                candidates.setdefault(row.sha256, []).append(row)
    if not dry_run:
        db.session.commit()

    off_box = remote_blob_names()
    moved = skipped = 0
    freed = 0
    now = datetime.utcnow()
    for sha, rows in candidates.items():
        if sha in pinned:
            skipped += 1
            continue
        if f"{sha}.json.gz" not in off_box:
            skipped += 1
            continue
        blob = _blob_path(sha)
        size = blob.stat().st_size if blob.exists() else 0
        if not dry_run:
            blob.unlink(missing_ok=True)
            for row in SotVersion.query.filter_by(sha256=sha).all():
                row.evacuated_at = row.evacuated_at or now
        moved += 1
        freed += size
    if not dry_run:
        db.session.commit()
    return {"evacuated": moved, "kept": skipped, "bytes_freed": freed,
            "off_box_known": len(off_box), "dry_run": dry_run}


def _slug(device: str) -> str:
    """A device name that is safe as one path component of an archive file.

    Separators and dots are collapsed, not escaped: the archive lands in one
    flat folder on the backup server, so a device called ``../x`` must not be
    able to name a file outside it.
    """
    keep = [c if (c.isalnum() or c in "-_") else "_" for c in (device or "")]
    return ("".join(keep).strip("_") or "device")[:80]


def _month_bounds(when: datetime) -> tuple:
    """First instant of *when*'s calendar month and of the month after it."""
    start = datetime(when.year, when.month, 1)
    end = (datetime(when.year + 1, 1, 1) if when.month == 12
           else datetime(when.year, when.month + 1, 1))
    return start, end


def remote_log_archive() -> dict:
    """``{filename: size}`` of the change-log archive files the backup server
    holds. Empty on ANY failure, for the same reason
    :func:`remote_blob_names` is: an unreachable server must read as "nothing
    is archived", so a failed listing archives and deletes nothing."""
    try:
        from . import backup_server as _bk
        from . import settings_store as _store
        cfg = _store.backup_server()
        if not cfg.get("configured"):
            return {}
        remote = ((cfg.get("system_path") or "/system").rstrip("/")
                  + "/" + LOG_ARCHIVE_SUBDIR)
        inv = _bk.dir_inventory(remote)
        if not inv.get("reachable"):
            return {}
        return {str(f.get("name") or ""): int(f.get("size") or 0)
                for f in (inv.get("files") or [])}
    except Exception:  # noqa: BLE001
        return {}


def _archive_payload(rows: list) -> bytes:
    """The bytes of one archive file: one JSON object per row, oldest first.

    Deterministic on purpose — same rows in, same bytes out — because the
    delete step compares the size of what it would upload against the size of
    what the server already holds. A payload that varied between runs would
    make that comparison meaningless.
    """
    lines = [json.dumps(r.to_dict(), sort_keys=True, separators=(",", ":"))
             for r in sorted(rows, key=lambda r: (r.taken_at or datetime.min,
                                                  r.id))]
    return ("\n".join(lines) + "\n").encode("utf-8")


def archive_log(device: str = "", *, dry_run: bool = False) -> dict:
    """Write whole past months of the change log off-box, then delete those
    rows from this node.

    Three rules, and each one is load-bearing:

    * **Whole calendar months only.** A month is archived once it lies
      ENTIRELY beyond the retention window. Archiving the old half of a month
      would mean writing that month's file a second time later — with fewer
      rows in it — and the second write would replace a complete archive with
      a truncated one.
    * **The payload must already be off-box.** Deleting a row whose blob is
      still local-only orphans that blob, and the orphan sweep in
      :func:`prune` then deletes it: the archive would point at bytes that no
      longer exist anywhere. A month holding any such row is held whole.
    * **Confirm, then delete.** The file is uploaded, the folder is listed
      back, and the rows go only when the server reports the file at exactly
      the size that was written. A size that disagrees holds the month and
      says so rather than overwriting.
    """
    from ..models import db
    from ..models_sot import SotVersion

    now = datetime.utcnow()
    devices = ([device] if device else
               [d["device"] for d in devices_summary()])

    off_box = remote_blob_names()
    plan: dict = {}
    held_recent = 0
    held_local_payload = set()
    for dev in devices:
        keep_days = _log_retention(product_for_device(dev))
        if keep_days <= 0:
            continue
        cutoff = now - timedelta(days=keep_days)
        rows = SotVersion.query.filter_by(device=dev).all()
        for row in rows:
            taken = row.taken_at or now
            _, month_end = _month_bounds(taken)
            if month_end > cutoff:
                held_recent += 1
                continue
            key = (dev, taken.strftime("%Y-%m"))
            plan.setdefault(key, []).append(row)
            if row.evacuated_at is None and f"{row.sha256}.json.gz" not in off_box:
                held_local_payload.add(key)

    have = remote_log_archive()
    tmp_dir = store_dir() / "log-archive-out"
    to_push = []
    staged = {}
    frozen_mismatch = 0
    for key, rows in sorted(plan.items()):
        if key in held_local_payload:
            continue
        dev, month = key
        name = f"{_slug(dev)}-{month}.jsonl"
        data = _archive_payload(rows)
        if name in have:
            # Already off-box. Same size means the same rows: proceed to the
            # delete without re-uploading a frozen file. A DIFFERENT size is
            # not a no-op to pass over in silence — the server holds a file
            # for this month that is not what these rows would produce, so
            # the month is held AND said out loud. Dropping it quietly is how
            # a held month would read as an archived one.
            if have[name] == len(data):
                staged[key] = (name, rows, len(data))
            else:
                frozen_mismatch += 1
            continue
        if dry_run:
            staged[key] = (name, rows, len(data))
            continue
        tmp_dir.mkdir(parents=True, exist_ok=True)
        path = tmp_dir / name
        path.write_bytes(data)
        to_push.append(str(path))
        staged[key] = (name, rows, len(data))

    push = {"ok": True, "pushed": 0, "skipped": 0, "detail": "nothing to push"}
    if to_push and not dry_run:
        try:
            from . import backup_server as _bk
            push = _bk.push_log_archive(to_push)
        except Exception as exc:  # noqa: BLE001
            push = {"ok": False, "detail": str(exc)}
        for f in to_push:
            Path(f).unlink(missing_ok=True)
        if not push.get("ok"):
            return {"ok": False, "archived_rows": 0, "files": 0,
                    "held_months": len(held_local_payload),
                    "held_rows": held_recent, "mismatched": 0,
                    "detail": "archive upload failed, nothing deleted: "
                              + str(push.get("detail", ""))[:160]}

    # Re-list AFTER the upload: the delete is authorised by what the server
    # reports holding, never by the upload call returning without an error.
    confirmed = have if dry_run else remote_log_archive()
    deleted = files = 0
    mismatched = frozen_mismatch
    for key, (name, rows, size) in sorted(staged.items()):
        if dry_run:
            files += 1
            deleted += len(rows)
            continue
        if confirmed.get(name) != size:
            mismatched += 1
            continue
        for row in rows:
            db.session.delete(row)
        deleted += len(rows)
        files += 1
    if not dry_run:
        db.session.commit()

    detail = (f"change log: {deleted} row(s) in {files} monthly file(s) "
              f"archived off-box and removed locally")
    if mismatched:
        detail += f"; {mismatched} month(s) HELD (off-box size disagrees)"
    if held_local_payload:
        detail += (f"; {len(held_local_payload)} month(s) held "
                   f"(snapshot not off-box yet)")
    res = {"ok": True, "archived_rows": deleted, "files": files,
           "held_months": len(held_local_payload), "held_rows": held_recent,
           "mismatched": mismatched, "dry_run": dry_run, "detail": detail}
    if not dry_run:
        try:
            from . import settings_store as _store
            _store.set_str(_store.K_SOT_LOG_ARCHIVE_LAST, json.dumps({
                "at": now.isoformat(timespec="seconds"),
                "rows": deleted, "files": files,
                "held": len(held_local_payload), "mismatched": mismatched}))
        except Exception:  # noqa: BLE001 — reporting must not sink the sweep
            pass
    return res


def prune(device: str = "") -> dict:
    """Apply the local payload policy, then collect orphan blobs.

    Kept under its old name because ``record()`` and the CLI call it, but it no
    longer deletes a single index row: what it prunes is bytes on this node.
    """
    from ..models import db
    from ..models_sot import SotVersion

    ev = evacuate(device)

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
    # ``rows`` stays in the return shape and is always 0: callers (the CLI,
    # the System Backup page) print it, and dropping the key would 500 them
    # while printing a number would be a lie. Zero is the truth now.
    return {"rows": 0, "blobs": removed_blobs, "evacuated": ev["evacuated"],
            "bytes_freed": ev["bytes_freed"]}


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
    n_evac = (db.session.query(db.func.count(SotVersion.id))
              .filter(SotVersion.evacuated_at.isnot(None)).scalar() or 0)
    return {"versions": int(n_versions), "devices": int(n_devices),
            "blobs": n_blobs, "bytes": size,
            # How much of the permanent change log is retrievable only over
            # the network. A page that shows "1200 versions" and nothing else
            # hides the fact that most of them now depend on the backup
            # server being up.
            "evacuated": int(n_evac),
            "local": int(n_versions) - int(n_evac)}


def devices_detail(product: str = "") -> list[dict]:
    """Per-device SoT rollup for the ADOM pages: counts, local vs evacuated,
    first and last change. Empty *product* means every device."""
    from ..models import db
    from ..models_sot import SotVersion
    q = db.session.query(
        SotVersion.device,
        db.func.count(SotVersion.id),
        db.func.sum(db.case((SotVersion.evacuated_at.isnot(None), 1), else_=0)),
        db.func.min(SotVersion.taken_at),
        db.func.max(SotVersion.taken_at),
        db.func.max(SotVersion.last_seen_at),
        db.func.sum(SotVersion.size_gz))
    if product:
        q = q.filter(SotVersion.product == product)
    rows = q.group_by(SotVersion.device).order_by(SotVersion.device).all()
    out = []
    for dev, n, evac, first, last, seen, size in rows:
        out.append({
            "device": dev, "versions": int(n or 0),
            "evacuated": int(evac or 0), "local": int(n or 0) - int(evac or 0),
            "bytes_gz": int(size or 0),
            "first_change": first.isoformat(timespec="seconds") if first else "",
            "last_change": last.isoformat(timespec="seconds") if last else "",
            "last_seen": seen.isoformat(timespec="seconds") if seen else "",
        })
    return out


def backfill_products() -> dict:
    """Stamp ``product`` on rows recorded before the column existed.

    Runs off the same resolver as ``record()``, so a row and a fresh harvest
    of the same device can never disagree. Idempotent: only rows with an empty
    product are touched, so a device that genuinely cannot be identified is
    re-examined next time instead of being frozen wrong.
    """
    from ..models import db
    from ..models_sot import SotVersion
    devices = [d for (d,) in db.session.query(SotVersion.device)
               .filter(db.or_(SotVersion.product == "",
                              SotVersion.product.is_(None)))
               .distinct()]
    stamped = unresolved = 0
    for dev in devices:
        product = product_for_device(dev)
        if not product:
            unresolved += 1
            continue
        stamped += (SotVersion.query
                    .filter(SotVersion.device == dev)
                    .filter(db.or_(SotVersion.product == "",
                                   SotVersion.product.is_(None)))
                    .update({"product": product}, synchronize_session=False))
    db.session.commit()
    return {"stamped": stamped, "unresolved": unresolved,
            "devices": len(devices)}


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


def offload(device: str = "") -> dict:
    """Push new blobs off-box, THEN apply the local payload policy.

    One call because the two halves are one decision and the order between
    them is not free: evacuating first would delete a blob the server has not
    been offered yet, and running them on separate schedules leaves the node
    holding a day of payload it has already uploaded. ``evacuate`` still makes
    its own independent check against the server listing — this ordering is a
    convenience, never the thing that makes the delete safe.
    """
    push = push_to_backup_server()
    if not push.get("ok"):
        return {"ok": False, "push": push, "evacuate": None,
                "detail": "push failed, nothing evacuated: "
                          + str(push.get("detail", ""))[:160]}
    ev = evacuate(device)
    # The change log leaves LAST, and it has to: a month may only be deleted
    # once its snapshots are off-box, and this run is what puts them there.
    # Archiving first would hold exactly the months this call is about to make
    # eligible, so the trim would always lag a full cycle behind the policy.
    log = archive_log(device)
    return {"ok": True, "push": push, "evacuate": ev, "log": log,
            "detail": f"{push.get('detail', '')}; "
                      f"evacuated {ev['evacuated']} blob(s), "
                      f"{ev['bytes_freed'] // 1024} KB freed; "
                      f"{log.get('detail', '')}"}
