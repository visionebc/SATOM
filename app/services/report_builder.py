"""Report Builder — a curated catalog + safe visual SQL builder + builtin seeds.

This sits ON TOP of the read-only query layer (``dbintrospect``): everything it
emits is a single ``SELECT`` that must pass ``dbintrospect.is_read_only`` before
it is ever returned or persisted. It never mutates the DB except through
``seed_builtin_reports`` which is INSERT-only and idempotent.

Three concerns:
  * ``catalog()`` — a JSON-ready description of the live schema (tables, friendly
    labels, domains, non-sensitive columns, FK edges with human phrases) that
    drives the wizard front-end.
  * ``build_sql(spec)`` — turns a structured wizard spec into a safe, quoted,
    read-only SELECT (or a list of errors).
  * ``BUILTIN_REPORTS`` / ``seed_builtin_reports()`` — seven curated reports
    seeded once at boot, read-only templates the operator can clone.
"""
from __future__ import annotations

import json
import logging
from collections import OrderedDict, deque
from typing import Any

from . import dbintrospect
from ..models import db

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Domains + curated table catalog                                            #
# --------------------------------------------------------------------------- #

DOMAINS: "OrderedDict[str, str]" = OrderedDict([
    ("fleet", "Fleet & appliances"),
    ("device-cache", "Device configuration cache"),
    ("waf", "Web protection & carve-outs"),
    ("certs", "Certificates"),
    ("ops", "Operations & audit"),
    ("automation", "Automation & scheduling"),
    ("platform", "Platform & users"),
    ("other", "Other"),
])

# Curated {table: {label, domain, description}}. Tables not listed still work —
# they fall back to a table-name label and the "other" domain.
TABLE_CATALOG: dict[str, dict[str, str]] = {
    "appliances": {
        "label": "Appliances (fleet)", "domain": "fleet",
        "description": "Managed FortiWeb / FortiADC devices in the fleet.",
    },
    "device_server_policies": {
        "label": "Server Policies (device cache)", "domain": "device-cache",
        "description": "Cached server / virtual-server policies per appliance.",
    },
    "device_server_pools": {
        "label": "Server Pools (device cache)", "domain": "device-cache",
        "description": "Cached back-end server pools per appliance.",
    },
    "device_web_protection_profiles": {
        "label": "Web Protection Profiles (device cache)", "domain": "device-cache",
        "description": "Cached WPP definitions per appliance.",
    },
    "device_certificate": {
        "label": "Device Certificates", "domain": "certs",
        "description": "Certificates as stored on the device certificate store.",
    },
    "managed_certificate": {
        "label": "Managed Certificates", "domain": "certs",
        "description": "Certificates issued / tracked by the manager.",
    },
    "wpp_exceptions": {
        "label": "WPP Carve-outs", "domain": "waf",
        "description": "Web-protection-profile exceptions (carve-outs).",
    },
    "wpp_exception_policies": {
        "label": "Carve-out ↔ Server Policy links", "domain": "waf",
        "description": "Which server policies a carve-out applies to.",
    },
    "audit_logs": {
        "label": "Audit Log", "domain": "ops",
        "description": "User and system actions across the manager.",
    },
    "config_backups": {
        "label": "Config Backups", "domain": "ops",
        "description": "Device configuration backups captured by the manager.",
    },
    "device_snapshots": {
        "label": "Device Snapshots", "domain": "device-cache",
        "description": "Point-in-time captures of device configuration layers.",
    },
    "scheduled_action_run": {
        "label": "Scheduled Action Runs", "domain": "automation",
        "description": "Execution history of scheduled actions.",
    },
    "templates": {
        "label": "Config Templates", "domain": "automation",
        "description": "Reusable configuration templates.",
    },
    "notifications": {
        "label": "Notifications", "domain": "ops",
        "description": "Notifications raised by the manager.",
    },
    "change_request": {
        "label": "Change Requests", "domain": "ops",
        "description": "Change-request workflow records.",
    },
    "users": {
        "label": "Users", "domain": "platform",
        "description": "Manager user accounts.",
    },
}


def table_label(name: str) -> str:
    """Friendly label for a table (falls back to the raw name)."""
    entry = TABLE_CATALOG.get(name)
    return entry["label"] if entry else name


def table_domain(name: str) -> str:
    entry = TABLE_CATALOG.get(name)
    return entry["domain"] if entry else "other"


def table_description(name: str) -> str:
    entry = TABLE_CATALOG.get(name)
    return entry["description"] if entry else ""


# --------------------------------------------------------------------------- #
#  Live-schema helpers                                                         #
# --------------------------------------------------------------------------- #

def _relations() -> dict[str, Any]:
    return dbintrospect.relations()


def _live_tables() -> dict[str, dict[str, Any]]:
    """{table_name: table_dict} from the live relations()."""
    return {t["name"]: t for t in _relations()["tables"]}


def _non_sensitive_cols(table: dict[str, Any]) -> list[dict[str, str]]:
    return [{"name": c["name"], "type": c["type"]}
            for c in table.get("cols", [])
            if not c.get("sensitive")]


def _edges() -> list[dict[str, str]]:
    """FK edges with both endpoints on live tables and a non-empty target."""
    live = _live_tables()
    out = []
    for e in _relations()["edges"]:
        if (e.get("to_table") and e.get("from_table") in live
                and e.get("to_table") in live and e.get("to_col")):
            out.append(e)
    return out


def _edge_phrase(edge: dict[str, str]) -> str:
    frm = table_label(edge["from_table"])
    to = table_label(edge["to_table"])
    return (f"each {frm} row belongs to one {to} "
            f"({edge['from_col']} → {edge['to_col']})")


def catalog() -> dict[str, Any]:
    """JSON-ready payload for the wizard front-end."""
    live = _live_tables()
    tables = []
    for name in sorted(live):
        tables.append({
            "name": name,
            "label": table_label(name),
            "domain": table_domain(name),
            "description": table_description(name),
            "columns": _non_sensitive_cols(live[name]),
        })
    edges = [{
        "from_table": e["from_table"], "from_col": e["from_col"],
        "to_table": e["to_table"], "to_col": e["to_col"],
        "phrase": _edge_phrase(e),
    } for e in _edges()]
    domains = [{"key": k, "label": v} for k, v in DOMAINS.items()]
    return {"tables": tables, "edges": edges, "domains": domains}


# --------------------------------------------------------------------------- #
#  Join graph (undirected over FK edges)                                       #
# --------------------------------------------------------------------------- #

def join_graph() -> dict[str, list[dict[str, str]]]:
    """Adjacency list keyed by table → list of {to, from_table, from_col,
    to_table, to_col} usable as a join step in BOTH directions."""
    graph: dict[str, list[dict[str, str]]] = {}
    for e in _edges():
        a, b = e["from_table"], e["to_table"]
        graph.setdefault(a, []).append({
            "to": b, "from_table": a, "from_col": e["from_col"],
            "to_table": b, "to_col": e["to_col"],
        })
        graph.setdefault(b, []).append({
            "to": a, "from_table": b, "from_col": e["to_col"],
            "to_table": a, "to_col": e["from_col"],
        })
    return graph


def related_tables(base: str, max_hops: int = 2) -> list[dict[str, Any]]:
    """BFS over the join graph from ``base``; returns reachable tables with the
    shortest join path (list of edge dicts) up to ``max_hops`` hops."""
    graph = join_graph()
    if base not in graph:
        return []
    seen = {base}
    out: list[dict[str, Any]] = []
    queue: deque[tuple[str, list[dict[str, str]]]] = deque([(base, [])])
    while queue:
        node, path = queue.popleft()
        if len(path) >= max_hops:
            continue
        for step in graph.get(node, []):
            nxt = step["to"]
            if nxt in seen:
                continue
            seen.add(nxt)
            new_path = path + [step]
            out.append({
                "table": nxt, "label": table_label(nxt),
                "domain": table_domain(nxt),
                "path": new_path, "hops": len(new_path),
                "phrase": _edge_phrase({
                    "from_table": step["from_table"], "from_col": step["from_col"],
                    "to_table": step["to_table"], "to_col": step["to_col"]}),
            })
            queue.append((nxt, new_path))
    return out


# --------------------------------------------------------------------------- #
#  build_sql — structured spec → safe read-only SELECT                         #
# --------------------------------------------------------------------------- #

_OPS = {
    "=": "=", "!=": "!=", ">": ">", "<": "<", ">=": ">=", "<=": "<=",
    "like": "LIKE", "not-like": "NOT LIKE",
    "is-null": "IS NULL", "is-not-null": "IS NOT NULL", "in": "IN",
}
_NULLARY_OPS = {"is-null", "is-not-null"}
_AGGS = {
    "count": "COUNT", "sum": "SUM", "avg": "AVG", "min": "MIN",
    "max": "MAX", "count-distinct": "COUNT",
}
_LIMIT_MAX = 500
_LIMIT_DEFAULT = 100


def _quote_ident(table: str, col: str) -> str:
    return f'"{table}"."{col}"'


def _quote_str(val: str) -> str:
    return "'" + str(val).replace("'", "''") + "'"


def _col_meta(live: dict[str, dict[str, Any]]) -> dict[str, dict[str, dict]]:
    """{table: {col_name: col_dict}} for validation."""
    out: dict[str, dict[str, dict]] = {}
    for name, tbl in live.items():
        out[name] = {c["name"]: c for c in tbl.get("cols", [])}
    return out


def _valid_col(colmeta, table, col) -> tuple[bool, str]:
    if table not in colmeta:
        return False, f"unknown table '{table}'"
    cols = colmeta[table]
    if col not in cols:
        return False, f"unknown column '{table}.{col}'"
    if cols[col].get("sensitive"):
        return False, f"column '{table}.{col}' is sensitive and cannot be used"
    return True, ""


def _fmt_value(op: str, raw, col_type: str) -> tuple[str, str]:
    """Return (sql_fragment, error). ``col_type`` unused for now but kept for
    future numeric coercion decisions."""
    if op in _NULLARY_OPS:
        return "", ""
    if op == "in":
        if not isinstance(raw, (list, tuple)) or not raw:
            return "", "'in' needs a non-empty list of values"
        parts = []
        for v in raw:
            fv = _scalar_value(v)
            parts.append(fv)
        return "(" + ", ".join(parts) + ")", ""
    # single scalar
    if op in ("like", "not-like"):
        s = str(raw)
        if "%" not in s:
            s = f"%{s}%"
        return _quote_str(s), ""
    return _scalar_value(raw), ""


def _scalar_value(v) -> str:
    """Numbers pass through if they parse as float; everything else is a
    single-quoted, escaped string literal (keeping ';' inert)."""
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return repr(v)
    s = str(v)
    try:
        float(s)
        return s
    except ValueError:
        return _quote_str(s)


def build_sql(spec: Any) -> tuple[str, list[str]]:
    """Compile a wizard spec into (sql, errors). On any error, sql is ''."""
    errors: list[str] = []
    if isinstance(spec, str):
        try:
            spec = json.loads(spec or "{}")
        except Exception:
            return "", ["spec is not valid JSON"]
    if not isinstance(spec, dict):
        return "", ["spec must be an object"]

    live = _live_tables()
    colmeta = _col_meta(live)

    base = str(spec.get("base") or "").strip()
    if base not in live:
        return "", [f"unknown base table '{base}'"]

    # ---- joins ------------------------------------------------------------
    used_tables = {base}
    join_sql: list[str] = []
    for j in (spec.get("joins") or []):
        if not isinstance(j, dict):
            errors.append("each join must be an object")
            continue
        jt = str(j.get("table") or "").strip()
        ft = str(j.get("from_table") or base).strip()
        fc = str(j.get("from_col") or "").strip()
        tc = str(j.get("to_col") or "").strip()
        if jt not in live:
            errors.append(f"unknown join table '{jt}'")
            continue
        if ft not in live:
            errors.append(f"unknown join source '{ft}'")
            continue
        ok, why = _valid_col(colmeta, ft, fc)
        if not ok:
            errors.append(f"join: {why}")
            continue
        ok2, why2 = _valid_col(colmeta, jt, tc)
        if not ok2:
            errors.append(f"join: {why2}")
            continue
        join_sql.append(
            f'LEFT JOIN "{jt}" ON {_quote_ident(ft, fc)} = {_quote_ident(jt, tc)}')
        used_tables.add(jt)

    # ---- columns / select list -------------------------------------------
    select_parts: list[str] = []
    has_agg = False
    for c in (spec.get("columns") or []):
        if not isinstance(c, dict):
            errors.append("each column must be an object")
            continue
        ct = str(c.get("table") or base).strip()
        cc = str(c.get("col") or "").strip()
        ok, why = _valid_col(colmeta, ct, cc)
        if not ok:
            errors.append(why)
            continue
        if ct not in used_tables:
            errors.append(f"column '{ct}.{cc}' is not a selected/joined table")
            continue
        agg = c.get("agg")
        if agg:
            agg = str(agg).lower()
            if agg not in _AGGS:
                errors.append(f"unknown aggregate '{agg}'")
                continue
            has_agg = True
            fn = _AGGS[agg]
            inner = _quote_ident(ct, cc)
            if agg == "count-distinct":
                expr = f"COUNT(DISTINCT {inner})"
                alias = f"count_distinct_{cc}"
            elif agg == "count":
                expr = f"COUNT({inner})"
                alias = "n"
            else:
                expr = f"{fn}({inner})"
                alias = f"{agg}_{cc}"
            select_parts.append(f'{expr} AS "{alias}"')
        else:
            select_parts.append(_quote_ident(ct, cc))
    if not select_parts:
        errors.append("select at least one column")

    # ---- filters ----------------------------------------------------------
    where_parts: list[str] = []
    for f in (spec.get("filters") or []):
        if not isinstance(f, dict):
            errors.append("each filter must be an object")
            continue
        ft = str(f.get("table") or base).strip()
        fc = str(f.get("col") or "").strip()
        op = str(f.get("op") or "=").lower()
        ok, why = _valid_col(colmeta, ft, fc)
        if not ok:
            errors.append(f"filter: {why}")
            continue
        if ft not in used_tables:
            errors.append(f"filter '{ft}.{fc}' is not a selected/joined table")
            continue
        if op not in _OPS:
            errors.append(f"unknown operator '{op}'")
            continue
        ident = _quote_ident(ft, fc)
        if op in _NULLARY_OPS:
            where_parts.append(f"{ident} {_OPS[op]}")
            continue
        col_type = colmeta[ft][fc].get("type", "")
        frag, ferr = _fmt_value(op, f.get("value"), col_type)
        if ferr:
            errors.append(f"filter: {ferr}")
            continue
        where_parts.append(f"{ident} {_OPS[op]} {frag}")

    # ---- group by ---------------------------------------------------------
    group_parts: list[str] = []
    for g in (spec.get("group_by") or []):
        if not isinstance(g, dict):
            errors.append("each group_by must be an object")
            continue
        gt = str(g.get("table") or base).strip()
        gc = str(g.get("col") or "").strip()
        ok, why = _valid_col(colmeta, gt, gc)
        if not ok:
            errors.append(f"group by: {why}")
            continue
        if gt not in used_tables:
            errors.append(f"group by '{gt}.{gc}' is not a selected/joined table")
            continue
        group_parts.append(_quote_ident(gt, gc))

    # ---- order by ---------------------------------------------------------
    order_sql = ""
    ob = spec.get("order_by")
    if isinstance(ob, dict) and (ob.get("col") or "").strip():
        oc = str(ob.get("col")).strip()
        ot = ob.get("table")
        direction = "DESC" if str(ob.get("dir") or "asc").lower() == "desc" else "ASC"
        if ot:
            ot = str(ot).strip()
            ok, why = _valid_col(colmeta, ot, oc)
            if not ok:
                errors.append(f"order by: {why}")
            elif ot not in used_tables:
                errors.append(f"order by '{ot}.{oc}' is not a selected/joined table")
            else:
                order_sql = f" ORDER BY {_quote_ident(ot, oc)} {direction}"
        else:
            # alias-based ordering (e.g. the aggregate alias "n")
            order_sql = f' ORDER BY "{oc.replace(chr(34), "")}" {direction}'

    # ---- limit ------------------------------------------------------------
    try:
        limit = int(spec.get("limit") or _LIMIT_DEFAULT)
    except (TypeError, ValueError):
        limit = _LIMIT_DEFAULT
    limit = max(1, min(limit, _LIMIT_MAX))

    if errors:
        return "", errors

    sql = "SELECT " + ", ".join(select_parts) + f' FROM "{base}"'
    if join_sql:
        sql += " " + " ".join(join_sql)
    if where_parts:
        sql += " WHERE " + " AND ".join(where_parts)
    if group_parts:
        sql += " GROUP BY " + ", ".join(group_parts)
    sql += order_sql
    sql += f" LIMIT {limit}"

    ok, why = dbintrospect.is_read_only(sql)
    if not ok:  # belt and braces — should be unreachable
        return "", [f"generated query is not read-only: {why}"]
    return sql, []


# --------------------------------------------------------------------------- #
#  column_values — distinct values for filter dropdowns                        #
# --------------------------------------------------------------------------- #

def column_values(table: str, col: str, cap: int = 25) -> list[str]:
    """Distinct non-null values for a validated, non-sensitive column."""
    from sqlalchemy import text
    live = _live_tables()
    if table not in live:
        return []
    colmeta = {c["name"]: c for c in live[table].get("cols", [])}
    if col not in colmeta or colmeta[col].get("sensitive"):
        return []
    try:
        cap = max(1, min(int(cap or 25), 100))
    except (TypeError, ValueError):
        cap = 25
    ident = _quote_ident(table, col)
    sql = (f'SELECT DISTINCT {ident} FROM "{table}" '
           f'WHERE {ident} IS NOT NULL ORDER BY {ident} LIMIT :cap')
    try:
        result = db.session.execute(text(sql), {"cap": cap})
        return [str(r[0]) for r in result if r[0] is not None]
    except Exception:
        db.session.rollback()
        return []


# --------------------------------------------------------------------------- #
#  Builtin reports                                                             #
# --------------------------------------------------------------------------- #

BUILTIN_REPORTS: list[dict[str, Any]] = [
    {
        "name": "Server Policies by device",
        "description": "Server policies across the fleet, per appliance, with "
                       "counts and status distribution.",
        "widgets": [
            {"title": "Server policies", "viz": "table", "width": "full",
             "limit": 500,
             "sql": 'SELECT "appliances"."name" AS appliance, '
                    '"device_server_policies"."name" AS policy, '
                    '"device_server_policies"."deployment_mode" AS deployment_mode, '
                    '"device_server_policies"."vserver" AS vserver, '
                    '"device_server_policies"."server_pool" AS server_pool, '
                    '"device_server_policies"."web_protection_profile" AS web_protection_profile, '
                    '"device_server_policies"."status" AS status '
                    'FROM "device_server_policies" '
                    'LEFT JOIN "appliances" ON '
                    '"device_server_policies"."appliance_id" = "appliances"."id" '
                    'ORDER BY "appliances"."name" ASC'},
            {"title": "Policies per appliance", "viz": "bar", "width": "half",
             "x": "appliance", "y": "n", "limit": 100,
             "sql": 'SELECT "appliances"."name" AS appliance, '
                    'COUNT("device_server_policies"."object_id") AS n '
                    'FROM "device_server_policies" '
                    'LEFT JOIN "appliances" ON '
                    '"device_server_policies"."appliance_id" = "appliances"."id" '
                    'GROUP BY "appliances"."name" ORDER BY n DESC'},
            {"title": "Status distribution", "viz": "pie", "width": "half",
             "x": "status", "y": "n", "limit": 100,
             "sql": 'SELECT "device_server_policies"."status" AS status, '
                    'COUNT("device_server_policies"."object_id") AS n '
                    'FROM "device_server_policies" '
                    'GROUP BY "device_server_policies"."status" ORDER BY n DESC'},
        ],
    },
    {
        "name": "Certificates expiring",
        "description": "Device and managed certificates ordered by expiry.",
        "widgets": [
            {"title": "Device certificates by expiry", "viz": "table",
             "width": "full", "limit": 500,
             "sql": 'SELECT "appliances"."name" AS appliance, '
                    '"device_certificate"."store" AS store, '
                    '"device_certificate"."name" AS name, '
                    '"device_certificate"."cn" AS cn, '
                    '"device_certificate"."issuer_cn" AS issuer_cn, '
                    '"device_certificate"."not_after" AS not_after '
                    'FROM "device_certificate" '
                    'LEFT JOIN "appliances" ON '
                    '"device_certificate"."appliance_id" = "appliances"."id" '
                    'WHERE "device_certificate"."not_after" IS NOT NULL '
                    'ORDER BY "device_certificate"."not_after" ASC'},
            {"title": "Managed certificates by expiry", "viz": "table",
             "width": "full", "limit": 500,
             "sql": 'SELECT "managed_certificate"."name" AS name, '
                    '"managed_certificate"."cert_class" AS cert_class, '
                    '"managed_certificate"."status" AS status, '
                    '"managed_certificate"."expires_at" AS expires_at '
                    'FROM "managed_certificate" '
                    'ORDER BY "managed_certificate"."expires_at" ASC'},
        ],
    },
    {
        "name": "Carve-outs by server policy",
        "description": "WPP carve-outs and the server policies they apply to.",
        "widgets": [
            {"title": "Carve-outs", "viz": "table", "width": "full",
             "limit": 500,
             "sql": 'SELECT "wpp_exception_policies"."server_policy" AS server_policy, '
                    '"wpp_exceptions"."category" AS category, '
                    '"wpp_exceptions"."exc_type" AS exc_type, '
                    '"wpp_exceptions"."name" AS name, '
                    '"wpp_exceptions"."reason" AS reason, '
                    '"wpp_exceptions"."enabled" AS enabled, '
                    '"wpp_exceptions"."stale" AS stale '
                    'FROM "wpp_exceptions" '
                    'LEFT JOIN "wpp_exception_policies" ON '
                    '"wpp_exception_policies"."exception_id" = "wpp_exceptions"."id" '
                    'LEFT JOIN "appliances" ON '
                    '"wpp_exceptions"."appliance_id" = "appliances"."id" '
                    'ORDER BY "wpp_exception_policies"."server_policy" ASC'},
            {"title": "Carve-outs per server policy", "viz": "bar",
             "width": "full", "x": "server_policy", "y": "n", "limit": 100,
             "sql": 'SELECT "wpp_exception_policies"."server_policy" AS server_policy, '
                    'COUNT("wpp_exception_policies"."id") AS n '
                    'FROM "wpp_exception_policies" '
                    'GROUP BY "wpp_exception_policies"."server_policy" '
                    'ORDER BY n DESC'},
        ],
    },
    {
        "name": "Audit activity (30 days)",
        "description": "Audit-log activity by day and the most recent actions.",
        "widgets": [
            {"title": "Actions per day", "viz": "bar", "width": "full",
             "x": "day", "y": "n", "limit": 100,
             "sql": "SELECT substr(CAST(\"audit_logs\".\"timestamp\" AS TEXT),1,10) "
                    "AS day, COUNT(\"audit_logs\".\"id\") AS n "
                    "FROM \"audit_logs\" "
                    "GROUP BY substr(CAST(\"audit_logs\".\"timestamp\" AS TEXT),1,10) "
                    "ORDER BY day ASC"},
            {"title": "Most recent actions", "viz": "table", "width": "full",
             "limit": 100,
             "sql": 'SELECT "audit_logs"."timestamp" AS timestamp, '
                    '"audit_logs"."username" AS username, '
                    '"audit_logs"."action" AS action, '
                    '"audit_logs"."target" AS target, '
                    '"audit_logs"."product" AS product '
                    'FROM "audit_logs" '
                    'ORDER BY "audit_logs"."timestamp" DESC LIMIT 100'},
        ],
    },
    {
        "name": "Fleet inventory",
        "description": "The appliance fleet: kinds, models, firmware and status.",
        "widgets": [
            {"title": "Appliances", "viz": "table", "width": "full",
             "limit": 500,
             "sql": 'SELECT "appliances"."name" AS name, '
                    '"appliances"."kind" AS kind, '
                    '"appliances"."model" AS model, '
                    '"appliances"."firmware" AS firmware, '
                    '"appliances"."zone" AS zone, '
                    '"appliances"."line" AS line, '
                    '"appliances"."department" AS department, '
                    '"appliances"."last_status" AS last_status, '
                    '"appliances"."maintenance" AS maintenance '
                    'FROM "appliances" ORDER BY "appliances"."name" ASC'},
            {"title": "Appliances by kind", "viz": "pie", "width": "half",
             "x": "kind", "y": "n", "limit": 100,
             "sql": 'SELECT "appliances"."kind" AS kind, '
                    'COUNT("appliances"."id") AS n FROM "appliances" '
                    'GROUP BY "appliances"."kind" ORDER BY n DESC'},
            {"title": "Appliances by firmware", "viz": "bar", "width": "half",
             "x": "firmware", "y": "n", "limit": 100,
             "sql": 'SELECT "appliances"."firmware" AS firmware, '
                    'COUNT("appliances"."id") AS n FROM "appliances" '
                    'GROUP BY "appliances"."firmware" ORDER BY n DESC'},
        ],
    },
    {
        "name": "Backups by device",
        "description": "Configuration backups per appliance, most recent first.",
        "widgets": [
            {"title": "Backups", "viz": "table", "width": "full", "limit": 500,
             "sql": 'SELECT "config_backups"."appliance_name" AS appliance_name, '
                    '"config_backups"."filename" AS filename, '
                    '"config_backups"."size_bytes" AS size_bytes, '
                    '"config_backups"."source" AS source, '
                    '"config_backups"."firmware" AS firmware, '
                    '"config_backups"."created_at" AS created_at '
                    'FROM "config_backups" '
                    'ORDER BY "config_backups"."created_at" DESC'},
            {"title": "Total backups", "viz": "stat", "width": "half",
             "limit": 1,
             "sql": 'SELECT COUNT("config_backups"."id") AS total '
                    'FROM "config_backups"'},
        ],
    },
    {
        "name": "Scheduled action failures",
        "description": "Scheduled action runs that did not succeed.",
        "widgets": [
            {"title": "Failed runs", "viz": "table", "width": "full",
             "limit": 500,
             "sql": "SELECT \"scheduled_action_run\".\"started_at\" AS started_at, "
                    "\"scheduled_action_run\".\"status\" AS status, "
                    "\"scheduled_action_run\".\"trigger\" AS trigger, "
                    "\"scheduled_action_run\".\"summary\" AS summary "
                    "FROM \"scheduled_action_run\" "
                    "WHERE \"scheduled_action_run\".\"status\" "
                    "NOT IN ('success','ok') "
                    "ORDER BY \"scheduled_action_run\".\"started_at\" DESC"},
            {"title": "Runs per status", "viz": "bar", "width": "half",
             "x": "status", "y": "n", "limit": 100,
             "sql": 'SELECT "scheduled_action_run"."status" AS status, '
                    'COUNT("scheduled_action_run"."id") AS n '
                    'FROM "scheduled_action_run" '
                    'GROUP BY "scheduled_action_run"."status" ORDER BY n DESC'},
        ],
    },
]


def seed_builtin_reports() -> int:
    """INSERT-only, idempotent seed of the curated builtin reports.

    A widget whose SQL fails the read-only guard is skipped (logged), never
    fatal. Existing builtins (matched by name + builtin flag) are left intact —
    operator edits to clones survive, and the builtin itself is read-only.
    Returns the number of reports created.
    """
    from ..models import DbReport
    created = 0
    for entry in BUILTIN_REPORTS:
        name = entry["name"]
        exists = DbReport.query.filter_by(name=name, builtin=True).first()
        if exists:
            continue
        widgets = []
        for w in entry["widgets"]:
            ok, why = dbintrospect.is_read_only(w.get("sql", ""))
            if not ok:
                logger.warning("builtin report %r widget %r skipped: %s",
                               name, w.get("title"), why)
                continue
            widgets.append(w)
        if not widgets:
            logger.warning("builtin report %r has no valid widgets — skipped",
                           name)
            continue
        report = DbReport(
            name=name, description=entry.get("description", ""),
            definition=json.dumps({"widgets": widgets}),
            builtin=True, created_by="system")
        db.session.add(report)
        created += 1
    if created:
        db.session.commit()
    return created
