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

import logging
from typing import Any

from sqlalchemy import inspect, text

from ..models import db

_log = logging.getLogger(__name__)

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
                "nullable": bool(c.get("nullable", True)),
            })
        # Row count for the diagram header badge — best-effort, never fatal.
        try:
            nrows = int(db.session.execute(
                text(f'SELECT COUNT(*) FROM "{name}"')).scalar() or 0)
        except Exception:
            db.session.rollback()
            nrows = -1
        tables.append({
            "name": name,
            "columns": len(cols),   # kept for the accessible row-fallback (a count)
            "cols": cols,           # the real schema, drives the ER diagram
            "pk": sorted(pk_cols),
            "rows": nrows,
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


#: Tables whose rows ARE credentials. Column masking keys on the result
#: column NAME, and SQL can expose a column without naming it
#: (``row_to_json(u)``, ``SELECT t.* FROM users t(a, b, c)``, an alias), so a
#: query that references one of these tables by identifier is refused before it
#: runs. Browse/masking stays as it was for every other table.
SENSITIVE_TABLES = frozenset({
    "users",               # password hashes, TOTP secrets, 2FA backup codes
    "api_tokens",          # API token hashes
    "app_settings",        # Fernet-encrypted directory/email/vault/hook secrets
    "hypervisor_targets",  # hypervisor passwords and API token secrets
    "dns_backends",        # DNS / IPAM provider credentials
    "provision_runs",      # first-boot administrator passwords
})

_SQL_IDENT = _re.compile(r'"((?:[^"]|"")+)"|([A-Za-z_][A-Za-z0-9_$]*)')
_DOLLAR_TAG = _re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")


def _is_ident_char(c: str) -> bool:
    return c.isalnum() or c in "_$"


def _blank_literals(sql: str) -> str:
    """``sql`` with string literals replaced by ``''`` and comments by a space,
    tokenised the way Postgres does it.

    A single ``'...'`` regex is not enough: it does not know ``E'\\''`` (a
    backslash-escaped quote), ``$$...$$`` or that a quote inside a comment is
    not a quote, so it can be made to "blank" real SQL and hide a table name.
    Anything unterminated is left as-is, which can only over-detect.
    """
    out = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j
            out.append(" ")
            continue
        if sql.startswith("/*", i):            # Postgres block comments nest
            depth, j = 1, i + 2
            while j < n and depth:
                if sql.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif sql.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            if depth:
                out.append(sql[i:])
                break
            out.append(" ")
            i = j
            continue
        if c == "'":
            escapes = (i > 0 and sql[i - 1] in "eE"
                       and (i < 2 or not _is_ident_char(sql[i - 2])))
            j = i + 1
            while j < n:
                if escapes and sql[j] == "\\":
                    j += 2
                    continue
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            if j >= n:
                out.append(sql[i:])
                break
            out.append("''")
            i = j + 1
            continue
        if c == "$" and (i == 0 or not _is_ident_char(sql[i - 1])):
            m = _DOLLAR_TAG.match(sql, i)
            if m:
                end = sql.find(m.group(0), m.end())
                if end < 0:
                    out.append(sql[i:])
                    break
                out.append("''")
                i = end + len(m.group(0))
                continue
        if c == '"':                           # identifiers are KEPT
            j = i + 1
            while j < n:
                if sql[j] == '"':
                    if j + 1 < n and sql[j + 1] == '"':
                        j += 2
                        continue
                    break
                j += 1
            out.append(sql[i:j + 1])
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def sensitive_tables_referenced(sql) -> list[str]:
    """Sensitive tables named anywhere in ``sql`` (quoted or bare, any case,
    schema-qualified or not). String literals and comments are ignored."""
    text_ = _blank_literals(sql or "")
    hits = []
    for m in _SQL_IDENT.finditer(text_):
        name = (m.group(1).replace('""', '"') if m.group(1) is not None
                else m.group(2)).lower()
        if name in SENSITIVE_TABLES and name not in hits:
            hits.append(name)
    return hits


#: Server functions the console refuses outright. The SENSITIVE_TABLES check
#: reads identifiers, and these functions take their target as a STRING
#: (``query_to_xml('select ... from users', ...)``, ``table_to_xml('users',
#: ...)``, ``ts_stat('select ...')``, ``dblink(...)``) or act outside the
#: rolled-back READ ONLY transaction: kill other sessions, read server files,
#: large objects, change settings that outlive the transaction on a pooled
#: connection. Matched on the RAW statement (string contents included), any
#: case, bare or as a quoted identifier, so no literal-parsing trick hides them.
#:
#: This is a denylist and therefore never complete. The structural control is
#: CONSOLE_ROLE below: on Postgres every query runs under a dedicated role
#: with SELECT on the non-credential tables only. The denylist stays as
#: defense in depth -- notably ``set_config('role', ...)``, which is the one
#: way a SELECT could switch back to the application role.
_DANGEROUS_FUNCS = _re.compile(
    r'(?<![A-Za-z0-9_$])('
    r'query_to_xml(?:_and_xmlschema)?|query_to_xmlschema|'
    r'table_to_xml\w*|cursor_to_xml\w*|database_to_xml\w*|schema_to_xml\w*|'
    r'ts_stat|ts_rewrite|'
    r'pg_terminate_backend|pg_cancel_backend|pg_reload_conf|set_config|'
    r'pg_read_file|pg_read_binary_file|pg_stat_file|pg_ls_\w+|'
    r'lo_\w+|loread|lowrite|dblink\w*'
    r')(?![A-Za-z0-9_$])', _re.IGNORECASE)
#: ``U&"\0075sers"`` spells an identifier with escapes no name check can see.
_UNICODE_IDENT = _re.compile(r'(?<![A-Za-z0-9_$])u&"', _re.IGNORECASE)


def dangerous_functions_referenced(sql) -> list[str]:
    """Refused server functions named anywhere in ``sql`` (see above)."""
    hits = []
    for m in _DANGEROUS_FUNCS.finditer(sql or ""):
        name = m.group(1).lower()
        if name not in hits:
            hits.append(name)
    if _UNICODE_IDENT.search(sql or ""):
        hits.append('U&"..." identifier')
    return hits


# --------------------------------------------------------------------------- #
#  [SATOM-CONSOLE-RO-ROLE] the console's own Postgres role                     #
# --------------------------------------------------------------------------- #
#: Every console / report-widget / plugin-dataset query runs under this role
#: (``SET LOCAL ROLE`` inside the rolled-back transaction), never under the
#: application's role. Privileges are checked against the CURRENT role, so a
#: function that executes SQL from a string -- the class the denylist above
#: keeps chasing -- runs with this role's rights too: no credential table, no
#: credential column, no pg_monitor statistics, no pg_authid on an install
#: whose application role is a superuser (the bundled Docker database).
#:
#: Provisioned by ``deploy/install-console-role.sh`` (root, primary only; the
#: role replicates to the standby) or, when the application role itself may
#: create roles, by ``ensure_console_role()`` at boot. Table grants are kept in
#: sync by ``ensure_console_role()`` because the credential list lives here.
CONSOLE_ROLE = "satom_console_ro"

#: Columns that hold credential material inside an otherwise readable table
#: (``appliances.password_enc``, ``managed_certificate.private_key_enc``). The
#: console role is granted every OTHER column of such a table, so an alias
#: (``SELECT password_enc AS x``) or a whole-row reference cannot surface them
#: past the name-based masking. Narrower than ``_SENSITIVE_TOKENS`` on purpose:
#: ``prompt_tokens`` / ``tokens_json`` are counters and theme data, and a
#: ``SELECT *`` on those tables keeps working.
_CREDENTIAL_COLUMN_TOKENS = ("password", "secret", "private", "fernet")


def is_credential_column(column: str) -> bool:
    name = (column or "").lower()
    return name.endswith("_enc") or any(t in name for t in _CREDENTIAL_COLUMN_TOKENS)


def _qi(name: str) -> str:
    """Quote a catalog identifier for DDL (names come from pg_catalog)."""
    return '"' + str(name).replace('"', '""') + '"'


def _is_postgres() -> bool:
    return db.engine.dialect.name == "postgresql"


def _console_role_problem(conn) -> str:
    """'' when CONSOLE_ROLE exists and is safe to switch to, else why not.

    Refuses a role that was created (or later altered) with any power beyond
    reading, or that was made a member of another role: switching to it would
    then give back what the switch exists to take away."""
    row = conn.execute(text(
        "SELECT r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, "
        "r.rolbypassrls, "
        "(SELECT count(*) FROM pg_auth_members m WHERE m.member = r.oid) "
        "FROM pg_roles r WHERE r.rolname = :r"), {"r": CONSOLE_ROLE}).first()
    if row is None:
        return "the role does not exist on this database"
    if any(bool(v) for v in row[:5]):
        return ("the role has privileges beyond reading (superuser, createrole, "
                "createdb, replication or bypassrls)")
    if int(row[5] or 0):
        return "the role is a member of another role"
    return ""


def _console_refusal(why: str) -> str:
    return ("refused: the read-only database role %s is not usable (%s). The "
            "database tools never fall back to the application's own role; "
            "provision it with 'sudo bash deploy/install-console-role.sh' on the "
            "primary node, then restart the application." % (CONSOLE_ROLE, why))


def _enter_console_role(conn) -> str:
    """Switch the CURRENT transaction to CONSOLE_ROLE. Returns '' on success or
    an English refusal. FAIL SAFE: on any doubt the caller must not run the
    query -- there is no fallback to the application role."""
    try:
        why = _console_role_problem(conn)
        if why:
            return _console_refusal(why)
        conn.execute(text("SET LOCAL ROLE " + _qi(CONSOLE_ROLE)))
        cur = conn.execute(text("SELECT current_user")).scalar()
    except Exception as exc:  # noqa: BLE001 - e.g. app role not a member
        return _console_refusal(str(exc).splitlines()[0][:200] if str(exc) else
                                type(exc).__name__)
    if cur != CONSOLE_ROLE:
        return _console_refusal("the role switch did not take effect")
    return ""


def ensure_console_role() -> dict:
    """Idempotent boot hook: create CONSOLE_ROLE when this application role may
    (superuser / createrole, e.g. the bundled Docker database) and keep its
    table grants in sync with SENSITIVE_TABLES / credential columns.

    Steady state issues NO DDL (every grant is checked first), so several
    workers booting at once do not contend. Never raises; returns a summary.
    Skipped on SQLite and on a standby (grants arrive by replication)."""
    out = {"ok": False, "created": False, "granted": [], "revoked": [],
           "skipped": "", "detail": ""}
    if not _is_postgres():
        out.update(ok=True, skipped="not postgresql")
        return out
    try:
        with db.engine.connect() as conn:
            with conn.begin():
                conn.execute(text("SET LOCAL lock_timeout = '5s'"))
                if conn.execute(text("SELECT pg_is_in_recovery()")).scalar():
                    out.update(ok=True, skipped="standby (grants replicate)")
                    return out
                exists = conn.execute(text(
                    "SELECT 1 FROM pg_roles WHERE rolname = :r"),
                    {"r": CONSOLE_ROLE}).first() is not None
                if not exists:
                    me = conn.execute(text(
                        "SELECT rolsuper, rolcreaterole FROM pg_roles "
                        "WHERE rolname = current_user")).first()
                    if not me or not (me[0] or me[1]):
                        out["detail"] = ("role %s missing and the application "
                                         "role cannot create roles; run "
                                         "deploy/install-console-role.sh as root"
                                         % CONSOLE_ROLE)
                        return out
                    conn.execute(text(
                        "CREATE ROLE %s NOLOGIN NOSUPERUSER NOCREATEDB "
                        "NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
                        % _qi(CONSOLE_ROLE)))
                    conn.execute(text("GRANT %s TO CURRENT_USER" % _qi(CONSOLE_ROLE)))
                    out["created"] = True
                why = _console_role_problem(conn)
                if why:
                    out["detail"] = why
                    return out
                _sync_console_grants(conn, out)
        out["ok"] = True
    except Exception as exc:  # noqa: BLE001 - a boot hook never blocks boot
        out["detail"] = str(exc)[:300]
    return out


def _sync_console_grants(conn, out: dict) -> None:
    """SELECT on every table of the application schema this role owns, except
    SENSITIVE_TABLES (nothing) and credential columns (column grants instead)."""
    r = _qi(CONSOLE_ROLE)
    schema = conn.execute(text("SELECT current_schema()")).scalar()
    if not conn.execute(text(
            "SELECT has_schema_privilege(:r, current_schema(), 'USAGE')"),
            {"r": CONSOLE_ROLE}).scalar():
        conn.execute(text("GRANT USAGE ON SCHEMA %s TO %s" % (_qi(schema), r)))
        out["granted"].append("USAGE ON SCHEMA %s" % schema)
    tables = conn.execute(text(
        "SELECT c.oid, c.relname, "
        "       has_table_privilege(:r, c.oid, 'SELECT'), "
        "       has_any_column_privilege(:r, c.oid, 'SELECT') "
        "FROM pg_class c "
        "WHERE c.relnamespace = (SELECT n.oid FROM pg_namespace n "
        "                        WHERE n.nspname = current_schema()) "
        "  AND c.relkind IN ('r', 'p', 'v', 'm', 'f') "
        "  AND pg_has_role(current_user, c.relowner, 'USAGE') "
        "ORDER BY c.relname"), {"r": CONSOLE_ROLE}).fetchall()
    for oid, name, tsel, anycol in tables:
        target = "%s.%s" % (_qi(schema), _qi(name))
        if name.lower() in SENSITIVE_TABLES:
            if tsel or anycol:
                conn.execute(text("REVOKE ALL ON TABLE %s FROM %s" % (target, r)))
                out["revoked"].append(name)
            continue
        cols = conn.execute(text(
            "SELECT a.attname, has_column_privilege(:r, a.attrelid, a.attnum, 'SELECT') "
            "FROM pg_attribute a WHERE a.attrelid = :oid AND a.attnum > 0 "
            "AND NOT a.attisdropped ORDER BY a.attnum"),
            {"r": CONSOLE_ROLE, "oid": oid}).fetchall()
        secret = [c for c, _ in cols if is_credential_column(c)]
        if not secret:
            if not tsel:
                conn.execute(text("GRANT SELECT ON TABLE %s TO %s" % (target, r)))
                out["granted"].append(name)
            continue
        if tsel:   # a table-level grant would cover the credential columns
            conn.execute(text("REVOKE SELECT ON TABLE %s FROM %s" % (target, r)))
            out["revoked"].append(name)
            cols = [(c, False) for c, _ in cols]
        leaked = [c for c, ok in cols if ok and c in secret]
        if leaked:
            conn.execute(text("REVOKE SELECT (%s) ON TABLE %s FROM %s" % (
                ", ".join(_qi(c) for c in leaked), target, r)))
            out["revoked"].append("%s(%s)" % (name, ",".join(leaked)))
        missing = [c for c, ok in cols if not ok and c not in secret]
        if missing:
            conn.execute(text("GRANT SELECT (%s) ON TABLE %s TO %s" % (
                ", ".join(_qi(c) for c in missing), target, r)))
            out["granted"].append("%s(%d columns)" % (name, len(missing)))


def run_query(sql, max_rows=_CONSOLE_MAX):
    """Execute a READ-ONLY query in a rolled-back transaction with a statement
    timeout, under CONSOLE_ROLE on Postgres (refused if that role is not
    usable). Returns {columns, rows, truncated, row_count, error}."""
    ok, why = is_read_only(sql)
    if not ok:
        return {"columns": [], "rows": [], "truncated": False, "error": why}
    hits = sensitive_tables_referenced(sql)
    if hits:
        try:
            from .audit import log_action
            log_action("database.query_refused", target=",".join(hits),
                       extra={"reason": "sensitive table", "sql": (sql or "")[:300]})
        except Exception:  # noqa: BLE001 - audit is best-effort
            pass
        return {"columns": [], "rows": [], "truncated": False,
                "error": "refused: the query references a credential table (%s); "
                         "those tables are not readable from the database tools"
                         % ", ".join(hits)}
    funcs = dangerous_functions_referenced(sql)
    if funcs:
        try:
            from .audit import log_action
            log_action("database.query_refused", target=",".join(funcs)[:128],
                       extra={"reason": "refused function", "sql": (sql or "")[:300]})
        except Exception:  # noqa: BLE001 - audit is best-effort
            pass
        return {"columns": [], "rows": [], "truncated": False,
                "error": "refused: the query calls %s, which the database tools "
                         "do not allow" % ", ".join(funcs)}
    q = (sql or "").strip().rstrip(";").strip()
    try:
        with db.engine.connect() as conn:
            trans = conn.begin()
            try:
                if _is_postgres():
                    # Hard, DB-enforced guarantee: any write (even a sneaky
                    # data-modifying CTE) errors out with "cannot execute ... in a
                    # read-only transaction"; the timeout caps runaway scans.
                    conn.execute(text("SET TRANSACTION READ ONLY"))
                    conn.execute(text("SET LOCAL statement_timeout = '8s'"))
                    # [SATOM-CONSOLE-RO-ROLE] Run as the console's own role.
                    # FAIL SAFE: if it cannot be entered the query does not
                    # run at all -- never under the application's role.
                    refusal = _enter_console_role(conn)
                    if refusal:
                        _log.warning("database console refused: %s", refusal)
                        return {"columns": [], "rows": [], "truncated": False,
                                "error": refusal}
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
        msg = str(exc)[:500]
        if "permission denied" in msg.lower():
            msg = ("%s -- the database tools run as the read-only role %s, which "
                   "cannot read credential tables or credential columns; select "
                   "the columns you need instead of * or a whole row."
                   % (msg.splitlines()[0][:300], CONSOLE_ROLE))
        return {"columns": [], "rows": [], "truncated": False, "error": msg}
