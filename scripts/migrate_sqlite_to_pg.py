"""One-shot data migration: SQLite (fortinet.db) -> PostgreSQL.

Uses the app's own SQLAlchemy metadata so column types (Boolean, DateTime, …)
are adapted correctly for each dialect, and copies tables in FK-dependency
order (metadata.sorted_tables). Resets Postgres sequences afterwards.

Usage:
    FORTINET_SKIP_DB_BOOTSTRAP=1 python scripts/migrate_sqlite_to_pg.py \
        --sqlite sqlite:////opt/ofortmaut/data/fortinet.db \
        --pg "postgresql+psycopg://fortinet:***@127.0.0.1/fortinet_mgr" [--truncate]

Exit code 0 only if every table's source and destination row counts match.
"""
from __future__ import annotations
import argparse, os, sys

os.environ.setdefault("FORTINET_SKIP_DB_BOOTSTRAP", "1")

from sqlalchemy import create_engine, select, func, text
# Importing the models registers every table on db.metadata.
from app.extensions import db
import app.models  # noqa: F401
try:
    import app.models_firmware  # noqa: F401
except Exception:
    pass

md = db.metadata


def _count(conn, table) -> int:
    return conn.execute(select(func.count()).select_from(table)).scalar() or 0


def migrate(sqlite_url: str, pg_url: str, truncate: bool = False) -> dict[str, dict]:
    src = create_engine(sqlite_url)
    dst = create_engine(pg_url, future=True)
    report: dict[str, dict] = {}

    tables = list(md.sorted_tables)  # parents first
    with src.connect() as sc, dst.begin() as dc:
        # discover which tables actually exist in the source
        src_tables = set(
            r[0] for r in sc.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            )
        )
        if truncate:
            for t in reversed(tables):
                if t.name in src_tables:
                    dc.execute(text(f'TRUNCATE TABLE "{t.name}" RESTART IDENTITY CASCADE'))
        for t in tables:
            if t.name not in src_tables:
                report[t.name] = {"src": 0, "dst": 0, "skipped": "not in source"}
                continue
            src_n = _count(sc, t)
            rows = [dict(r._mapping) for r in sc.execute(select(t))]
            if rows:
                dc.execute(t.insert(), rows)
            dst_n = _count(dc, t)
            report[t.name] = {"src": src_n, "dst": dst_n,
                              "ok": src_n == dst_n}

    # reset sequences for integer PKs
    with dst.begin() as dc:
        for t in tables:
            if t.name not in src_tables:
                continue
            pk = [c for c in t.primary_key.columns]
            if len(pk) == 1 and str(pk[0].type).upper().startswith("INTEGER"):
                col = pk[0].name
                dc.execute(text(
                    f"SELECT setval(pg_get_serial_sequence('\"{t.name}\"', '{col}'), "
                    f"COALESCE((SELECT MAX(\"{col}\") FROM \"{t.name}\"), 1), true)"
                ))
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqlite", required=True)
    ap.add_argument("--pg", required=True)
    ap.add_argument("--truncate", action="store_true",
                    help="TRUNCATE destination tables first (idempotent re-run)")
    a = ap.parse_args()
    rep = migrate(a.sqlite, a.pg, truncate=a.truncate)
    ok = True
    print(f"{'table':28} {'src':>6} {'dst':>6}  status")
    for name, r in rep.items():
        if "skipped" in r:
            print(f"{name:28} {r['src']:>6} {r['dst']:>6}  skip ({r['skipped']})")
            continue
        status = "OK" if r["ok"] else "MISMATCH"
        if not r["ok"]:
            ok = False
        print(f"{name:28} {r['src']:>6} {r['dst']:>6}  {status}")
    print("RESULT:", "ALL MATCH" if ok else "COUNT MISMATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
