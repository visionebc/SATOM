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
    return _repo_root() / "reports"


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


def create_backup(*, include_reports: bool = True, publish_git: bool = False,
                  conn: dict | None = None, label: str = "manual") -> dict:
    """Create a bundle: pg_dump + reports/ + manifest → one .tar.gz. Returns
    {ok, name, path, size, detail}."""
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

        manifest = (f"label: {label}\ncreated: {ts}\ndb: {conn['dbname']}\n"
                    f"host: {conn['host']}\nreports: {include_reports}\n")
        (stage / "manifest.txt").write_text(manifest)

        name = f"fmw-backup-{ts}.tar.gz"
        bundle = backups_dir() / name
        with tarfile.open(bundle, "w:gz") as tar:
            tar.add(stage, arcname=f"fmw-backup-{ts}")
        size = bundle.stat().st_size

        if publish_git and reports_dir().exists():
            try:
                from . import git_service
                git_service.git_publish(f"source-of-truth backup {ts}", ["reports"])
                detail.append("git: reports published")
            except Exception as exc:  # noqa: BLE001
                detail.append(f"git error: {type(exc).__name__}")
        return {"ok": True, "name": name, "path": str(bundle), "size": size,
                "detail": "; ".join(detail)}
    finally:
        shutil.rmtree(stage, ignore_errors=True)


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
        dump_path = root / "db.dump"
        if not dump_path.exists():
            return {"ok": False, "detail": "bundle missing db.dump",
                    "safety": safety.get("name")}
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
        return {"ok": ok, "detail": detail, "safety": safety.get("name"),
                "stderr": (res.stderr or "")[:300]}
    finally:
        shutil.rmtree(work, ignore_errors=True)
