"""Phase 9 — whole-instance backup & restore.

Bundles a ``pg_dump`` (custom format) of the PostgreSQL source of truth + the
``reports/`` per-device JSON tree + a manifest into a single downloadable
``.tar.gz``. Restore extracts it and ``pg_restore --clean``s the DB, taking a
SAFETY dump first. Optionally publishes the per-device JSON to git (the "DB +
JSON in git" the operator asked for).

pg_dump/pg_restore are shelled out (the Postgres client tools); connection
params are parsed from ``SQLALCHEMY_DATABASE_URI`` and passed via ``PGPASSWORD``
so no secret hits the command line.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tarfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, unquote


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def backups_dir() -> Path:
    d = _repo_root() / "data" / "system_backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def reports_dir() -> Path:
    # Same resolver as device_sync._reports_dir (data/reports since the git
    # SoT retirement, 2026-08-05) — two resolvers already diverged once.
    from . import device_sync as _ds
    return _ds._reports_dir()


def sot_dir() -> Path:
    from . import sot_store as _ss
    return _ss.store_dir()


def parse_db_url(uri: str) -> dict:
    """Parse a SQLAlchemy Postgres URI into pg_dump connection params."""
    # strip the +driver (postgresql+psycopg -> postgresql)
    clean = re.sub(r"^postgresql\+\w+://", "postgresql://", uri or "")
    p = urlparse(clean)
    return {
        "host": p.hostname or "127.0.0.1",
        "port": str(p.port or 5432),
        "user": unquote(p.username or ""),
        "password": unquote(p.password or ""),
        "dbname": (p.path or "/").lstrip("/"),
    }


def _conn_from_app() -> dict:
    from flask import current_app
    return parse_db_url(current_app.config.get("SQLALCHEMY_DATABASE_URI", ""))


def pg_dump_cmd(conn: dict, out_path: str) -> list:
    return ["pg_dump", "-Fc", "-h", conn["host"], "-p", conn["port"],
            "-U", conn["user"], "-d", conn["dbname"], "-f", out_path]


def pg_restore_cmd(conn: dict, in_path: str) -> list:
    return ["pg_restore", "--clean", "--if-exists", "--no-owner", "-h", conn["host"],
            "-p", conn["port"], "-U", conn["user"], "-d", conn["dbname"], in_path]


def _env(conn: dict) -> dict:
    env = dict(os.environ)
    if conn.get("password"):
        env["PGPASSWORD"] = conn["password"]
    return env


def _run(cmd: list, conn: dict, timeout: int = 600):
    return subprocess.run(cmd, env=_env(conn), capture_output=True, text=True,
                          timeout=timeout)



def config_files() -> list[Path]:
    """Node-local configuration that no other mechanism carries.

    git ignores it on purpose (it names the estate), and the datasync only
    reaches the peer that is still up. A bundle is the only copy that survives
    losing both nodes, so total-loss recovery needs these in it.
    """
    from app.services import doc_publication as _pubdoc
    out = []
    for p in (_pubdoc.OVERLAY_PATH, _pubdoc.LEGACY_OVERLAY_PATH):
        if p.exists():
            out.append(p)
            break
    return out


def restore_config_files(src: Path, dest: Path) -> list[str]:
    """Place bundled config only where the node has none.

    A restore repairs a node that is still the authority on its own site
    rules; the copy frozen into an old bundle is by definition the older one.
    Overwriting would silently roll redaction back to whenever that bundle was
    taken.
    """
    placed = []
    if not src.exists():
        return placed
    for f in sorted(src.iterdir()):
        if not f.is_file():
            continue
        target = dest / f.name
        if target.exists():
            continue
        shutil.copy2(f, target)
        placed.append(f.name)
    return placed


def _pubdoc_root() -> Path:
    """Where config_files() reads from -- the same directory, so a restore
    puts the file back exactly where the loader looks for it."""
    from app.services import doc_publication as _pubdoc
    return _pubdoc.OVERLAY_PATH.parent

def create_backup(*, include_reports: bool = True, publish_git: bool = False,
                  push_server: bool = False, conn: dict | None = None,
                  label: str = "manual") -> dict:
    """Create a bundle: pg_dump + reports/ + manifest → one .tar.gz. Returns
    {ok, name, path, size, detail}.

    ``push_server`` also uploads the finished bundle to the external backup
    server (backup-server) so the DB backup lives off both racks — best-effort, a
    push failure is recorded in ``detail`` but does not fail the backup."""
    conn = conn or _conn_from_app()
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    stage = backups_dir() / f"_stage-{ts}"
    stage.mkdir(parents=True, exist_ok=True)
    detail = []
    try:
        dump_path = stage / "db.dump"
        res = _run(pg_dump_cmd(conn, str(dump_path)), conn)
        if res.returncode != 0:
            return {"ok": False, "name": "", "path": "",
                    "detail": f"pg_dump failed: {res.stderr[:300]}"}
        detail.append(f"db.dump={dump_path.stat().st_size}B")

        if include_reports and reports_dir().exists():
            shutil.copytree(reports_dir(), stage / "reports")
            detail.append("reports/ included")
        if include_reports and sot_dir().exists():
            # The versioned SoT blobs travel with the bundle: the pg_dump only
            # carries the sot_version INDEX — without the blobs a restored
            # instance would have history rows pointing at nothing.
            shutil.copytree(sot_dir(), stage / "sot")
            detail.append("sot/ included")

        cfgs = config_files()
        if cfgs:
            (stage / "config").mkdir(exist_ok=True)
            for src in cfgs:
                shutil.copy2(src, stage / "config" / src.name)
            detail.append(f"config/ included ({len(cfgs)})")

        # Recovery fingerprints, NOT the material. FERNET_KEY and the CA key
        # stay out of the bundle on purpose (a bundle is retained, mirrored to
        # the peer and pushed off-box over SFTP -- the one place the key that
        # opens the SFTP password must never travel). The fingerprint costs
        # nothing to carry and lets a restore NAME a key mismatch instead of
        # producing a database of unreadable secrets and no explanation.
        from . import recovery as _recovery
        manifest = (f"label: {label}\ncreated: {ts}\ndb: {conn['dbname']}\n"
                    f"host: {conn['host']}\nreports: {include_reports}\n"
                    + "\n".join(_recovery.manifest_lines()) + "\n")
        (stage / "manifest.txt").write_text(manifest)

        name = f"fmw-backup-{ts}.tar.gz"
        bundle = backups_dir() / name
        with tarfile.open(bundle, "w:gz") as tar:
            tar.add(stage, arcname=f"fmw-backup-{ts}")
        size = bundle.stat().st_size

        if publish_git:
            # Retired 2026-08-05: the reports/ history no longer lives in git
            # (services.sot_store is the versioned SoT). Kept as an accepted
            # no-op so old callers/action params do not crash.
            detail.append("git publish retired (sot_store is the SoT)")

        if push_server:
            try:
                from . import backup_server as _bk
                pr = _bk.push_bundle(str(bundle))
                detail.append("backup-server: " + (pr["detail"] if pr.get("ok")
                              else "push failed: " + pr.get("detail", "")))
            except Exception as exc:  # noqa: BLE001
                detail.append(f"backup-server push error: {type(exc).__name__}")
        return {"ok": True, "name": name, "path": str(bundle), "size": size,
                "detail": "; ".join(detail)}
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def delete_backup(name: str) -> dict:
    """Delete one bundle from this node's store. Primary-only by design: the
    standby re-syncs ``data/`` FROM the primary (rsync --delete), so a delete
    here propagates to the standby within 5 min, while a standby-side delete
    would just be undone by the next sync."""
    if not name.startswith("fmw-backup-") or "/" in name or ".." in name:
        return {"ok": False, "detail": "unknown backup"}
    path = backups_dir() / name
    if not path.exists():
        return {"ok": False, "detail": "unknown backup"}
    size = path.stat().st_size
    path.unlink()
    return {"ok": True, "detail": f"{name} deleted ({size // 1024} KB)"}


def list_backups() -> list:
    """Existing bundles, newest first."""
    out = []
    for f in sorted(backups_dir().glob("fmw-backup-*.tar.gz"), reverse=True):
        st = f.stat()
        out.append({"name": f.name, "size": st.st_size,
                    "created": datetime.utcfromtimestamp(st.st_mtime).isoformat(timespec="seconds")})
    return out


def _safe_member(member: tarfile.TarInfo, dest: Path) -> bool:
    target = (dest / member.name).resolve()
    return str(target).startswith(str(dest.resolve()))


def restore_backup(name: str, *, conn: dict | None = None,
                   restore_reports: bool = True) -> dict:
    """Restore a bundle. Takes a SAFETY dump first, then pg_restore --clean.
    DESTRUCTIVE — replaces the DB schema/data with the bundle's."""
    conn = conn or _conn_from_app()
    bundle = backups_dir() / name
    if not bundle.exists() or not name.startswith("fmw-backup-"):
        return {"ok": False, "detail": "unknown backup"}
    # 1) safety net
    safety = create_backup(include_reports=True, publish_git=False, conn=conn,
                           label="pre-restore-safety")
    # 2) extract
    work = backups_dir() / f"_restore-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    work.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(bundle, "r:gz") as tar:
            members = [m for m in tar.getmembers() if _safe_member(m, work)]
            tar.extractall(work, members=members)
        roots = list(work.glob("fmw-backup-*"))
        root = roots[0] if roots else work
        # Read the recovery fingerprints BEFORE touching the database: a
        # restore that fails halfway still leaves the operator needing to know
        # the bundle was taken under a different key.
        from . import recovery as _recovery
        try:
            _mtext = (root / "manifest.txt").read_text()
        except OSError:
            _mtext = ""
        key_findings = _recovery.compare_manifest(_mtext)
        dump_path = root / "db.dump"
        if not dump_path.exists():
            return {"ok": False, "detail": "bundle missing db.dump",
                    "safety": safety.get("name"),
                    "key_findings": key_findings,
                    "key_mismatch": bool(key_findings)}
        res = _run(pg_restore_cmd(conn, str(dump_path)), conn)
        # pg_restore can return non-zero on benign --clean DROP warnings; treat
        # a populated stderr without "error" as a warning.
        ok = res.returncode == 0 or ("error" not in (res.stderr or "").lower())
        detail = f"pg_restore rc={res.returncode}"
        if restore_reports and (root / "reports").exists():
            dst = reports_dir()
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(root / "reports", dst)
            detail += "; reports restored"
        if (root / "config").exists():
            names = restore_config_files(root / "config",
                                         _pubdoc_root())
            if names:
                detail += "; config restored: " + ", ".join(names)
        if restore_reports and (root / "sot").exists():
            dst = sot_dir()
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(root / "sot", dst)
            detail += "; sot restored"
        if key_findings:
            # Prepended, not appended: this outranks every pg_restore warning
            # above it. A restore that "succeeded" into an unreadable
            # credential store is the failure the operator must see first.
            detail = ("; ".join(f["detail"] for f in key_findings)
                      + " || " + detail)
        return {"ok": ok, "detail": detail, "safety": safety.get("name"),
                "key_findings": key_findings,
                "key_mismatch": bool(key_findings),
                "stderr": (res.stderr or "")[:300]}
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ── off-box inventory (System Backup & Restore page) ─────────────────────────

def vault_dir() -> Path:
    """Per-appliance config-backup vault (services/backup.py blobs)."""
    return _repo_root() / "data" / "backups"


def local_inventory() -> dict:
    """What THIS node holds: system bundles + the per-appliance vault. Used by
    the page and by the unauthenticated ``/healthz/backups`` probe so the peer
    can render a side-by-side comparison."""
    bundles = list_backups()
    vault = {"entries": 0, "latest": None}
    vd = vault_dir()
    if vd.exists():
        newest = 0.0
        for child in vd.iterdir():
            if child.is_dir():
                vault["entries"] += 1
                try:
                    newest = max(newest, child.stat().st_mtime)
                except OSError:
                    pass
        if newest:
            vault["latest"] = datetime.utcfromtimestamp(newest).isoformat(
                timespec="seconds")
    return {"bundles": bundles, "vault": vault}


def peer_inventory(host: str, timeout: float = 2.5) -> dict:
    """Probe the peer's ``/healthz/backups`` (same HTTP pattern as
    cluster._probe_peer) so the admin sees what the backup server / standby
    actually holds — no SSH needed. Best-effort: unreachable → reachable=False."""
    import json as _json
    import urllib.request
    out = {"reachable": False, "host": host, "bundles": [], "vault": None}
    if not host or host == "127.0.0.1":
        return out
    try:
        with urllib.request.urlopen(f"http://{host}:8000/healthz/backups",
                                    timeout=timeout) as r:
            data = _json.loads(r.read().decode("utf-8", "replace"))
        out.update(reachable=True,
                   bundles=data.get("bundles") or [],
                   vault=data.get("vault"))
    except Exception:
        pass
    return out


def compare_inventories(local: dict, peer: dict) -> list:
    """Union of bundle names, flagged present/missing on each side — the
    at-a-glance 'is my off-box copy complete?' table."""
    mine = {b["name"]: b for b in local.get("bundles", [])}
    theirs = {b["name"]: b for b in (peer.get("bundles") or [])}
    rows = []
    for name in sorted(set(mine) | set(theirs), reverse=True):
        a, b = mine.get(name), theirs.get(name)
        rows.append({"name": name,
                     "local": a, "peer": b,
                     "size_match": bool(a and b and a.get("size") == b.get("size"))})
    return rows
