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


def relations() -> dict[str, Any]:
    """Foreign-key edges across all tables, for the relational-model (ER) view.

    Returns ``{tables: [{name, columns, pk}], edges: [{from_table, from_col,
    to_table, to_col}]}``. Schema introspection only — no row data is read.
    """
    insp = inspect(db.engine)
    tables: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    for name in sorted(insp.get_table_names()):
        cols = insp.get_columns(name)
        pk = sorted(insp.get_pk_constraint(name).get("constrained_columns") or [])
        tables.append({"name": name, "columns": len(cols), "pk": pk})
        for fk in insp.get_foreign_keys(name):
            target = fk.get("referred_table", "")
            ccols = fk.get("constrained_columns") or []
            rcols = fk.get("referred_columns") or []
            for i, col in enumerate(ccols):
                ref = rcols[i] if i < len(rcols) else (rcols[0] if rcols else "")
                edges.append({
                    "from_table": name, "from_col": col,
                    "to_table": target, "to_col": ref,
                })
    return {"tables": tables, "edges": edges}
