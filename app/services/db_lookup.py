"""Database lookups for Script Library forms (2026-10-15).

An administrator can give a script form field whose choices come from the
SATOM database: a query built with the Report Builder's catalogue (base table,
joins across tables, columns, filters, order, limit), plus which column is the
VALUE and which is the LABEL. Three field types:

* ``lookup``       — pick one row;
* ``lookup_multi`` — pick several rows;
* ``dataset``      — no pick: the whole result goes to the script.

The script never touches the database. Its sandbox has no route to Postgres on
purpose (services.sandbox). The SERVER runs the query and hands the script the
chosen rows, as JSON on stdin like every other input.

Two rules hold this together:

1. **One query path.** :func:`run` compiles through
   ``report_builder.build_sql`` (catalogue-checked identifiers, sensitive
   columns refused, SELECT only) and executes through
   ``dbintrospect.run_query`` (read-only role, rolled-back transaction,
   statement timeout, credential tables refused).
2. **The ADOM scope is added by the server, every time.** A profile confined
   to some ADOMs (``Profile.adoms``) only ever reads the rows of those ADOMs:
   each table in the query is filtered through its ``product`` column, its
   ``appliance_id`` or (for ``appliances``) its ``kind``. A table with none of
   those belongs to no ADOM, so a confined profile is refused it rather than
   shown every row. An unconfined profile reads everything, like the SQL
   console it may already open.

Forms carry only the chosen VALUE (a key). The rows are read when a run is
QUEUED (:func:`expand`), with the ADOMs of whoever queues it — the operator for
"Run now", the owner for a saved schedule. A schedule therefore never runs
on a month-old copy of a device row, and a value that has disappeared (or left
the owner's ADOMs) fails the run with a message instead of running anyway.
"""
from __future__ import annotations

import json
from typing import Any

from . import dbintrospect, report_builder

LOOKUP_TYPES = ("lookup", "lookup_multi", "dataset")
PICK_TYPES = ("lookup", "lookup_multi")
MAX_ROWS = 500          # report_builder caps LIMIT at 500 too
MAX_JOINS = 4
MAX_FILTERS = 10
MAX_PICKS = 100         # values one lookup_multi may carry
_SPEC_KEYS = ("base", "joins", "columns", "filters", "group_by", "order_by",
              "limit")


class LookupError_(ValueError):
    """A lookup the server refuses; the message is shown as is."""


# ---------------------------------------------------------------------------
#  definition
# ---------------------------------------------------------------------------
def column_names(spec: dict) -> list[str]:
    """Result column names, in SELECT order: ``table.col`` for a plain column,
    the aggregate alias otherwise (``n``, ``sum_x``…) — the names the script
    sees and the value/label pickers offer."""
    out = []
    base = spec.get("base") or ""
    for c in spec.get("columns") or []:
        t = str(c.get("table") or base)
        col = str(c.get("col") or "")
        agg = str(c.get("agg") or "").lower()
        if not agg:
            out.append("%s.%s" % (t, col))
        elif agg == "count":
            out.append("n")
        elif agg == "count-distinct":
            out.append("count_distinct_%s" % col)
        else:
            out.append("%s_%s" % (agg, col))
    return out


def clean_spec(spec: Any, *, allow_aggregates: bool) -> dict:
    """The query part of a field, normalised and compiled once (unscoped) to
    prove it is valid. Raises :class:`LookupError_`."""
    if isinstance(spec, str):
        try:
            spec = json.loads(spec or "{}")
        except ValueError:
            raise LookupError_("the query is not valid JSON")
    if not isinstance(spec, dict):
        raise LookupError_("the query must be an object")
    clean = {k: spec[k] for k in _SPEC_KEYS if k in spec}
    if len(clean.get("joins") or []) > MAX_JOINS:
        raise LookupError_("at most %d joined tables" % MAX_JOINS)
    if len(clean.get("filters") or []) > MAX_FILTERS:
        raise LookupError_("at most %d filters" % MAX_FILTERS)
    if not allow_aggregates and (
            clean.get("group_by")
            or any((c or {}).get("agg") for c in clean.get("columns") or [])):
        raise LookupError_("a pick list cannot group or aggregate: every row "
                           "must be one choice (use a Dataset field for totals)")
    sql, errors = report_builder.build_sql(clean)
    if errors:
        raise LookupError_("; ".join(errors))
    names = column_names(clean)
    if len(set(names)) != len(names):
        raise LookupError_("the same column is selected twice")
    return clean


def clean_field(field: dict, raw: dict) -> dict:
    """Add the lookup keys of ``raw`` to the already-cleaned ``field``.
    Raises :class:`LookupError_`."""
    ftype = field["type"]
    spec = clean_spec(raw.get("query"), allow_aggregates=(ftype == "dataset"))
    field["query"] = spec
    if ftype not in PICK_TYPES:
        return field
    names = column_names(spec)
    value_col = str(raw.get("value_col") or (names[0] if names else ""))
    label_col = str(raw.get("label_col") or value_col)
    if value_col not in names:
        raise LookupError_("the value column %r is not one of the selected "
                           "columns" % value_col)
    if label_col not in names:
        raise LookupError_("the label column %r is not one of the selected "
                           "columns" % label_col)
    field["value_col"] = value_col
    field["label_col"] = label_col
    return field


# ---------------------------------------------------------------------------
#  ADOM scope
# ---------------------------------------------------------------------------
def _tables(spec: dict) -> list[tuple[str, str | None]]:
    """``[(table, join_target_col)]``: the base (None) and each joined table
    with the column its LEFT JOIN matches on."""
    out = [(spec["base"], None)]
    for j in spec.get("joins") or []:
        out.append((str(j.get("table") or ""), str(j.get("to_col") or "")))
    return out


def _in_list(values) -> str:
    vals = sorted({str(v) for v in values})
    if not vals:
        return "(NULL)"
    return "(" + ", ".join(report_builder._quote_str(v) for v in vals) + ")"


def _product_cond(ident: str, adoms: frozenset[str]) -> str:
    from .product_scope import LEGACY_PRODUCT
    if not adoms:
        return "1 = 0"
    cond = "%s IN %s" % (ident, _in_list(adoms))
    if LEGACY_PRODUCT in adoms:
        # NULL/'' rows are the FortiWeb ADOM's (product_scope docstring).
        cond = "(%s OR %s IS NULL OR %s = '')" % (cond, ident, ident)
    return cond


def _appliance_ids(adoms: frozenset[str]) -> list[int]:
    from ..models import Appliance
    from .product_scope import _allowed_clause
    return [r[0] for r in Appliance.query.with_entities(Appliance.id)
            .filter(_allowed_clause(Appliance.kind, adoms)).all()]


def scope_conditions(spec: dict, adoms: frozenset[str] | None) -> list[str]:
    """SQL conditions confining ``spec`` to ``adoms`` (``None`` = none needed).
    Raises :class:`LookupError_` for a table that belongs to no ADOM."""
    if adoms is None:
        return []
    from .product_scope import LEGACY_PRODUCT
    live = report_builder._live_tables()
    conds: list[str] = []
    ids: list[int] | None = None
    for table, join_col in _tables(spec):
        cols = {c["name"] for c in live.get(table, {}).get("cols", [])}
        if table == "appliances":
            cond = _product_cond(report_builder._quote_ident(table, "kind"), adoms)
        elif "product" in cols:
            cond = _product_cond(report_builder._quote_ident(table, "product"), adoms)
        elif "appliance_id" in cols:
            if ids is None:
                ids = _appliance_ids(adoms)
            ident = report_builder._quote_ident(table, "appliance_id")
            cond = "%s IN %s" % (ident, "(" + ", ".join(str(int(i)) for i in ids) + ")"
                                 if ids else "(NULL)")
            if LEGACY_PRODUCT in adoms:
                cond = "(%s OR %s IS NULL)" % (cond, ident)
        else:
            raise LookupError_(
                "%s belongs to no ADOM, and your profile is confined to some "
                "ADOMs: it cannot read that table" % report_builder.table_label(table))
        if join_col and join_col not in cols:
            raise LookupError_("unknown join column %s.%s" % (table, join_col))
        if join_col:
            # LEFT JOIN with no match: the joined columns are all NULL. That row
            # is the base row's, already scoped — keep it.
            cond = "(%s OR %s IS NULL)" % (
                cond, report_builder._quote_ident(table, join_col))
        conds.append(cond)
    return conds


# ---------------------------------------------------------------------------
#  running
# ---------------------------------------------------------------------------
def run(spec: dict, adoms: frozenset[str] | None) -> dict:
    """Execute a cleaned query for someone confined to ``adoms``.

    Returns ``{"columns": [...], "rows": [{col: value}], "truncated": bool}``.
    Raises :class:`LookupError_` (with the database's message) on failure."""
    conds = scope_conditions(spec, adoms)
    sql, errors = report_builder.build_sql(spec, extra_where=conds)
    if errors:
        raise LookupError_("; ".join(errors))
    res = dbintrospect.run_query(sql, max_rows=MAX_ROWS, adom_scoped=True)
    if res.get("error"):
        raise LookupError_(res["error"])
    names = column_names(spec)
    if len(names) != len(res.get("columns") or []):
        raise LookupError_("the query returned %d columns, expected %d"
                           % (len(res.get("columns") or []), len(names)))
    rows = [dict(zip(names, r)) for r in res.get("rows") or []]
    return {"columns": names, "rows": rows, "truncated": bool(res.get("truncated"))}


def options(field: dict, adoms: frozenset[str] | None) -> list[dict]:
    """``[{"value", "label"}]`` for a pick field, first occurrence of each value."""
    data = run(field["query"], adoms)
    seen, out = set(), []
    for row in data["rows"]:
        v = row.get(field["value_col"], "")
        if v in seen or v == "":
            continue
        seen.add(v)
        out.append({"value": v, "label": row.get(field["label_col"], v) or v})
    return out


def coerce(field: dict, value: Any) -> Any:
    """What a form submitted for a lookup field, as stored: a string key
    (``lookup``) or a list of them (``lookup_multi``). Membership is checked
    when the run is queued (:func:`expand`), with the queuer's ADOMs."""
    if field["type"] == "lookup_multi":
        if isinstance(value, str):
            value = [v for v in value.split("\n")]
        if not isinstance(value, (list, tuple)):
            raise LookupError_("expected a list of values")
        vals = []
        for v in value:
            s = "" if v is None else str(v).strip()
            if s and s not in vals:
                vals.append(s)
        if len(vals) > MAX_PICKS:
            raise LookupError_("at most %d values" % MAX_PICKS)
        return vals
    return "" if value is None else str(value).strip()


def expand(fields: list[dict], inputs: dict, adoms: frozenset[str] | None) -> dict:
    """``{field_name: payload}`` for every lookup/dataset field — what the
    script receives in place of the stored key(s):

    * ``lookup``       → ``{"value", "label", "row": {column: value}}``
    * ``lookup_multi`` → a list of those
    * ``dataset``      → ``{"columns", "rows", "truncated"}``

    Raises :class:`LookupError_` when a chosen value is no longer in the
    result for these ADOMs."""
    out: dict[str, Any] = {}
    for f in fields:
        if f["type"] not in LOOKUP_TYPES:
            continue
        name = f["name"]
        if f["type"] == "dataset":
            out[name] = run(f["query"], adoms)
            continue
        chosen = inputs.get(name)
        keys = chosen if isinstance(chosen, list) else ([chosen] if chosen else [])
        if not keys:
            out[name] = [] if f["type"] == "lookup_multi" else None
            continue
        data = run(f["query"], adoms)
        by_value: dict[str, dict] = {}
        for row in data["rows"]:
            by_value.setdefault(row.get(f["value_col"], ""), row)
        picked = []
        for k in keys:
            row = by_value.get(str(k))
            if row is None:
                raise LookupError_(
                    "%s: %r is no longer available%s" % (
                        f.get("label") or name, k,
                        " for your ADOMs" if adoms is not None else ""))
            picked.append({"value": str(k),
                           "label": row.get(f["label_col"], k) or k,
                           "row": row})
        out[name] = picked if f["type"] == "lookup_multi" else picked[0]
    return out


def preview(field_raw: dict, adoms: frozenset[str] | None, limit: int = 20,
            *, as_options: bool = False) -> dict:
    """Designer preview: compile the field as it stands (saved or not) and show
    what the signed-in administrator's ADOMs return — the first ``limit``
    rows, or (``as_options``) the pick list the form would offer."""
    ftype = str(field_raw.get("type") or "lookup")
    if ftype not in LOOKUP_TYPES:
        raise LookupError_("not a database field")
    field = clean_field({"type": ftype, "name": "preview"}, field_raw)
    if as_options:
        if ftype not in PICK_TYPES:
            raise LookupError_("a dataset has no choices")
        return {"options": options(field, adoms)}
    data = run(field["query"], adoms)
    out = {"columns": data["columns"], "rows": data["rows"][:limit],
           "row_count": len(data["rows"]), "truncated": data["truncated"]}
    if ftype in PICK_TYPES:
        out["value_col"] = field["value_col"]
        out["label_col"] = field["label_col"]
    return out
