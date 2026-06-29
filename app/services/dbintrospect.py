"""Read-only SQLite introspection for the Settings → Database tab.

This is the web port of the desktop Settings → Database page (schema + data
browser), minus the Qt ER diagram. It exposes the local store's tables, their
schema (columns / types / PK / FK) and a capped, read-only sample of rows so an
admin can inspect what the app persists.

It is strictly read-only: it never issues anything but ``SELECT``, validates the
table name against the live table list before interpolating it into a query (so
there is no SQL injection surface), and masks any obviously sensitive column
(password hashes, encrypted credentials, tokens) so secrets are never rendered.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import inspect, text

from ..models import db

# Columns whose values are masked in the row preview — the local store never
# holds appliance secrets in the clear, but password hashes / Fernet ciphertext
# / session tokens still must not be surfaced in a browser table.
_SENSITIVE_TOKENS = ("password", "secret", "token", "_enc", "fernet", "private")

# Hard cap on rows returned to the browser per table.
_ROW_LIMIT = 200


def _is_sensitive(column: str) -> bool:
    name = (column or "").lower()
    return any(tok in name for tok in _SENSITIVE_TOKENS)


def list_tables() -> list[str]:
    """Every real table in the bound database, sorted."""
    return sorted(inspect(db.engine).get_table_names())


def table_info(name: str) -> dict[str, Any]:
    """Schema + row count + a capped sample of rows for ``name``.

    Returns an empty dict if ``name`` is not a real table (guards the raw-name
    interpolation below).
    """
    insp = inspect(db.engine)
    tables = set(insp.get_table_names())
    if name not in tables:
        return {}

    pk_cols = set(insp.get_pk_constraint(name).get("constrained_columns") or [])
    fks: dict[str, str] = {}
    for fk in insp.get_foreign_keys(name):
        target = fk.get("referred_table", "")
        for i, col in enumerate(fk.get("constrained_columns") or []):
            ref_cols = fk.get("referred_columns") or []
            ref = ref_cols[i] if i < len(ref_cols) else (ref_cols[0] if ref_cols else "")
            fks[col] = f"{target}.{ref}" if target else ""

    columns = []
    for col in insp.get_columns(name):
        cname = col["name"]
        columns.append({
            "name": cname,
            "type": str(col.get("type", "")),
            "nullable": bool(col.get("nullable", True)),
            "pk": cname in pk_cols,
            "fk": fks.get(cname, ""),
            "sensitive": _is_sensitive(cname),
        })

    # ``name`` is validated against the live table list above, so quoting it is
    # safe; the LIMIT is bound as a parameter.
    rows: list[list[str]] = []
    total = 0
    try:
        total = db.session.execute(
            text(f'SELECT COUNT(*) FROM "{name}"')).scalar() or 0
        result = db.session.execute(
            text(f'SELECT * FROM "{name}" LIMIT :lim'), {"lim": _ROW_LIMIT})
        keys = list(result.keys())
        sensitive_idx = {i for i, k in enumerate(keys) if _is_sensitive(k)}
        for record in result:
            cells = []
            for i, value in enumerate(record):
                if i in sensitive_idx and value not in (None, ""):
                    cells.append("••• (hidden)")
                elif value is None:
                    cells.append("")
                else:
                    text_val = str(value)
                    cells.append(text_val[:300] + "…" if len(text_val) > 300 else text_val)
            rows.append(cells)
    except Exception as exc:  # noqa: BLE001 — surface a readable message, never 500
        return {
            "name": name, "columns": columns, "rows": [], "row_count": total,
            "shown": 0, "limit": _ROW_LIMIT, "error": str(exc),
        }

    return {
        "name": name,
        "columns": columns,
        "rows": rows,
        "row_count": total,
        "shown": len(rows),
        "limit": _ROW_LIMIT,
        "error": "",
    }


_TYPE_ALIASES = {
    "character varying": "varchar", "timestamp without time zone": "timestamp",
    "timestamp with time zone": "timestamptz", "double precision": "double",
}


def _short_type(t: str) -> str:
    """Compact a SQLAlchemy column type for the diagram (VARCHAR(255) -> varchar)."""
    low = (t or "").strip().lower()
    if low in _TYPE_ALIASES:
        return _TYPE_ALIASES[low]
    base = low.split("(")[0].strip()
    return _TYPE_ALIASES.get(base, base or "?")


def relations() -> dict[str, Any]:
    """The full relational model for the ER diagram.

    Returns ``{tables: [{name, columns, cols:[{name,type,pk,fk,sensitive}], pk}],
    edges: [{from_table, from_col, to_table, to_col}]}``. Each table carries its
    real COLUMNS so the diagram can render a database SCHEMA (table header + a row
    per column with PK/FK markers), not just a labelled box. Schema introspection
    only — no row data is read.
    """
    insp = inspect(db.engine)
    tables: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    for name in sorted(insp.get_table_names()):
        pk_cols = set(insp.get_pk_constraint(name).get("constrained_columns") or [])
        fk_map: dict[str, str] = {}
        for fk in insp.get_foreign_keys(name):
            target = fk.get("referred_table", "")
            ccols = fk.get("constrained_columns") or []
            rcols = fk.get("referred_columns") or []
            for i, col in enumerate(ccols):
                ref = rcols[i] if i < len(rcols) else (rcols[0] if rcols else "")
                fk_map[col] = f"{target}.{ref}" if target else ""
                edges.append({
                    "from_table": name, "from_col": col,
                    "to_table": target, "to_col": ref,
                })
        cols = []
        for c in insp.get_columns(name):
            cname = c["name"]
            cols.append({
                "name": cname,
                "type": _short_type(str(c.get("type", ""))),
                "pk": cname in pk_cols,
                "fk": fk_map.get(cname, ""),
                "sensitive": _is_sensitive(cname),
            })
        tables.append({
            "name": name,
            "columns": len(cols),   # kept for the accessible row-fallback (a count)
            "cols": cols,           # the real schema, drives the ER diagram
            "pk": sorted(pk_cols),
        })
    return {"tables": tables, "edges": edges}


# --------------------------------------------------------------------------- #
#  Phase 8 — paginated browse + read-only SQL console                          #
# --------------------------------------------------------------------------- #
import re as _re

# Write / DDL keywords that must never appear, even buried in a CTE
# (e.g. ``WITH t AS (DELETE ... RETURNING *) SELECT * FROM t`` — Postgres allows
# data-modifying CTEs). Deliberately NARROW: only verbs that genuinely mutate, so
# legitimate column names like ``comment`` / ``set`` / ``do`` / ``replace`` (the
# REPLACE() function) are NOT false-rejected. Statement-leading writes (COPY,
# PRAGMA, VACUUM as the first token) are already blocked by ``_ALLOWED_START``,
# and run_query also pins a Postgres READ ONLY transaction as the hard guarantee.
_FORBIDDEN = _re.compile(
    r"\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|"
    r"merge|upsert|reindex|vacuum|attach)\b", _re.IGNORECASE)
_ALLOWED_START = ("select", "with", "explain", "table", "values", "show")
_CONSOLE_MAX = 1000


def table_page(name, page=1, per_page=50):
    """Paginated row browse for one table (sensitive columns masked)."""
    insp = inspect(db.engine)
    if name not in set(insp.get_table_names()):
        return {"name": name, "columns": [], "rows": [], "row_count": 0,
                "page": 1, "pages": 1, "error": "unknown table"}
    page = max(1, int(page or 1)); per_page = min(500, max(1, int(per_page or 50)))
    cols = [c["name"] for c in insp.get_columns(name)]
    sens = {i for i, k in enumerate(cols) if _is_sensitive(k)}
    total = db.session.execute(text(f'SELECT COUNT(*) FROM "{name}"')).scalar() or 0
    result = db.session.execute(
        text(f'SELECT * FROM "{name}" LIMIT :lim OFFSET :off'),
        {"lim": per_page, "off": (page - 1) * per_page})
    rows = []
    for record in result:
        cells = []
        for i, v in enumerate(record):
            if i in sens and v not in (None, ""):
                cells.append("••• (hidden)")
            elif v is None:
                cells.append("")
            else:
                t = str(v); cells.append(t[:300] + "…" if len(t) > 300 else t)
        rows.append(cells)
    pages = max(1, (total + per_page - 1) // per_page)
    return {"name": name, "columns": cols, "rows": rows, "row_count": total,
            "page": page, "pages": pages, "per_page": per_page, "error": ""}


def is_read_only(sql):
    """True if ``sql`` is a single read-only statement (SELECT/WITH/EXPLAIN…)."""
    q = (sql or "").strip().rstrip(";").strip()
    if not q:
        return False, "empty query"
    # collapse to detect multiple statements (a ';' with following non-space)
    if ";" in q:
        return False, "only a single statement is allowed"
    low = q.lower()
    if not low.startswith(_ALLOWED_START):
        return False, "only SELECT / WITH / EXPLAIN queries are allowed"
    if _FORBIDDEN.search(q):
        return False, "write/DDL keywords are not allowed in the read-only console"
    return True, ""


def run_query(sql, max_rows=_CONSOLE_MAX):
    """Execute a READ-ONLY query in a rolled-back transaction with a statement
    timeout. Returns {columns, rows, truncated, row_count, error}."""
    ok, why = is_read_only(sql)
    if not ok:
        return {"columns": [], "rows": [], "truncated": False, "error": why}
    q = (sql or "").strip().rstrip(";").strip()
    try:
        with db.engine.connect() as conn:
            trans = conn.begin()
            try:
                if db.engine.dialect.name == "postgresql":
                    # Hard, DB-enforced guarantee: any write (even a sneaky
                    # data-modifying CTE) errors out with "cannot execute ... in a
                    # read-only transaction"; the timeout caps runaway scans.
                    conn.execute(text("SET TRANSACTION READ ONLY"))
                    conn.execute(text("SET LOCAL statement_timeout = '8s'"))
                result = conn.execute(text(q))
                cols = list(result.keys())
                fetched = result.fetchmany(max_rows + 1)
                truncated = len(fetched) > max_rows
                data = fetched[:max_rows]
                sens = {i for i, k in enumerate(cols) if _is_sensitive(k)}
                rows = []
                for rec in data:
                    cells = []
                    for i, v in enumerate(rec):
                        if i in sens and v not in (None, ""):
                            cells.append("••• (hidden)")
                        else:
                            cells.append("" if v is None else str(v))
                    rows.append(cells)
            finally:
                trans.rollback()
        return {"columns": cols, "rows": rows, "truncated": truncated,
                "row_count": len(rows), "error": ""}
    except Exception as exc:  # noqa: BLE001
        return {"columns": [], "rows": [], "truncated": False,
                "error": str(exc)[:500]}
