"""Python Studio > Data stores -- tables an administrator defines in the UI.

A data store is a column list plus rows. Rows are JSON documents in
``studio_rows``; every value is coerced to its column's type on the way in,
so what an app reads back has the type the administrator declared.

WHY NOT A REAL TABLE PER STORE
------------------------------
A table per store means DDL driven from a web form, and a database role that
may run DDL. Neither belongs next to the table that holds every device
credential. Rows as checked JSON documents give the same thing to the people
who use it -- typed columns, add/edit/delete, filters, CSV in and out -- with
no SQL and no DDL reachable from the UI, and the rows replicate to the standby
and travel in every backup with the rest of the configuration. The price is
that filtering happens here, in Python, over at most :data:`MAX_ROWS` rows.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import date, datetime

from ..extensions import db
from ..models_studio import StudioDataStore, StudioRow

COLUMN_TYPES = ("text", "number", "boolean", "date", "json")
MAX_COLUMNS = 40
MAX_ROWS = 20000
MAX_VALUE_CHARS = 64 * 1024
MAX_QUERY_LIMIT = 5000
FILTER_OPS = ("eq", "ne", "contains", "gt", "lt", "empty", "not_empty")

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,47}$")
_COL_RE = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")
#: Columns every row has without being declared.
SYSTEM_COLUMNS = ("_id", "_created_at", "_updated_at", "_by")


class StoreError(ValueError):
    pass


def validate_slug(slug: str) -> str:
    s = (slug or "").strip()
    if not _SLUG_RE.match(s):
        raise StoreError("Id: lowercase letters, digits, - and _, 2 to 48 characters.")
    return s


def clean_columns(cols) -> list[dict]:
    if not isinstance(cols, list):
        raise StoreError("columns must be a list")
    if len(cols) > MAX_COLUMNS:
        raise StoreError("at most %d columns" % MAX_COLUMNS)
    out, seen = [], set()
    for c in cols:
        if not isinstance(c, dict):
            raise StoreError("each column is an object")
        name = str(c.get("name") or "").strip()
        if not _COL_RE.match(name):
            raise StoreError("column %r: lowercase letters, digits and _, starting with a letter or _"
                             % name)
        if name.startswith("_"):
            raise StoreError("column %r: names starting with _ are reserved" % name)
        if name in seen:
            raise StoreError("column %r is listed twice" % name)
        seen.add(name)
        typ = str(c.get("type") or "text")
        if typ not in COLUMN_TYPES:
            raise StoreError("column %s: unknown type %r" % (name, typ))
        out.append({"name": name, "label": str(c.get("label") or name).strip()[:120] or name,
                    "type": typ, "required": bool(c.get("required"))})
    return out


def coerce(col: dict, value):
    """*value* as *col*'s type. ``None`` for an empty value."""
    typ = col["type"]
    if value is None or (isinstance(value, str) and value.strip() == "" and typ != "text"):
        return None
    if typ == "text":
        s = value if isinstance(value, str) else json.dumps(value) \
            if isinstance(value, (dict, list)) else str(value)
        if len(s) > MAX_VALUE_CHARS:
            raise StoreError("%s: longer than %d characters" % (col["name"], MAX_VALUE_CHARS))
        return s
    if typ == "number":
        if isinstance(value, bool):
            raise StoreError("%s: a number is expected, got true/false" % col["name"])
        if isinstance(value, (int, float)):
            return value
        try:
            f = float(str(value).strip())
        except ValueError:
            raise StoreError("%s: %r is not a number" % (col["name"], value)) from None
        return int(f) if f.is_integer() and "." not in str(value) else f
    if typ == "boolean":
        if isinstance(value, bool):
            return value
        s = str(value).strip().lower()
        if s in ("1", "true", "yes", "on", "y"):
            return True
        if s in ("0", "false", "no", "off", "n"):
            return False
        raise StoreError("%s: %r is not true/false" % (col["name"], value))
    if typ == "date":
        if isinstance(value, datetime):
            return value.date().isoformat()
        if isinstance(value, date):
            return value.isoformat()
        s = str(value).strip()[:10]
        try:
            return date.fromisoformat(s).isoformat()
        except ValueError:
            raise StoreError("%s: %r is not a date (YYYY-MM-DD)" % (col["name"], value)) from None
    # json
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            raise StoreError("%s: not valid JSON" % col["name"]) from None
    if len(json.dumps(value, default=str)) > MAX_VALUE_CHARS:
        raise StoreError("%s: larger than %d characters" % (col["name"], MAX_VALUE_CHARS))
    return value


def clean_row(columns: list[dict], values: dict, *, partial: bool = False) -> dict:
    """The row as stored. Unknown keys are refused, not dropped: a typo in an
    app's mapping must not silently write an empty column."""
    if not isinstance(values, dict):
        raise StoreError("a row is an object of column: value")
    known = {c["name"]: c for c in columns}
    unknown = [k for k in values if k not in known and k not in SYSTEM_COLUMNS]
    if unknown:
        raise StoreError("unknown column(s): %s" % ", ".join(sorted(map(str, unknown))))
    out = {}
    for name, col in known.items():
        if name not in values:
            if not partial and col["required"]:
                raise StoreError("%s is required" % name)
            continue
        v = coerce(col, values[name])
        if col["required"] and (v is None or (isinstance(v, str) and not v.strip())):
            raise StoreError("%s is required" % name)
        out[name] = v
    return out


# --------------------------------------------------------------------------- #
#  stores                                                                      #
# --------------------------------------------------------------------------- #
def get(slug: str) -> StudioDataStore | None:
    return StudioDataStore.query.filter_by(slug=slug).first()


def list_stores() -> list[dict]:
    counts = dict(db.session.query(StudioRow.store_id, db.func.count(StudioRow.id))
                  .group_by(StudioRow.store_id).all())
    return [{"slug": s.slug, "name": s.name, "description": s.description,
             "columns": len(s.columns), "rows": counts.get(s.id, 0),
             "updated_at": s.updated_at, "updated_by": s.updated_by}
            for s in StudioDataStore.query.order_by(StudioDataStore.name).all()]


def create(slug: str, name: str, by: str) -> StudioDataStore:
    slug = validate_slug(slug)
    name = (name or "").strip()[:120]
    if not name:
        raise StoreError("a name is required")
    if get(slug) is not None:
        raise StoreError("a data store with id %s already exists" % slug)
    s = StudioDataStore(slug=slug, name=name, columns_json=json.dumps(
        [{"name": "name", "label": "Name", "type": "text", "required": True}]),
        created_by=by, updated_by=by)
    db.session.add(s)
    db.session.commit()
    return s


def save_schema(store: StudioDataStore, name: str, description: str, columns, by: str) -> list[str]:
    """Replace the column list. Returns warnings: a column removed or retyped
    keeps its stored values (nothing is ever deleted by a schema change); they
    are simply not shown or are re-checked on the next write."""
    cols = clean_columns(columns)
    if not cols:
        raise StoreError("a data store needs at least one column")
    old = {c["name"]: c for c in store.columns}
    warnings = []
    for n, c in old.items():
        new = next((x for x in cols if x["name"] == n), None)
        if new is None:
            warnings.append("column %s removed from the list: its stored values are kept "
                            "and come back if you add it again" % n)
        elif new["type"] != c["type"]:
            warnings.append("column %s changed from %s to %s: existing values are not "
                            "converted" % (n, c["type"], new["type"]))
    store.name = (name or store.name).strip()[:120] or store.name
    store.description = (description or "").strip()[:2000]
    store.columns_json = json.dumps(cols)
    store.updated_by = by
    db.session.commit()
    return warnings


def delete_store(store: StudioDataStore) -> int:
    n = StudioRow.query.filter_by(store_id=store.id).count()
    db.session.delete(store)
    db.session.commit()
    return n


# --------------------------------------------------------------------------- #
#  rows                                                                        #
# --------------------------------------------------------------------------- #
def _shape(row: StudioRow) -> dict:
    d = dict(row.data)
    d["_id"] = row.id
    d["_created_at"] = row.created_at.isoformat(timespec="seconds") if row.created_at else ""
    d["_updated_at"] = row.updated_at.isoformat(timespec="seconds") if row.updated_at else ""
    d["_by"] = row.updated_by or row.created_by
    return d


def count(store: StudioDataStore) -> int:
    return StudioRow.query.filter_by(store_id=store.id).count()


def insert(store: StudioDataStore, values: dict, by: str) -> dict:
    if count(store) >= MAX_ROWS:
        raise StoreError("%s is full (%d rows)" % (store.slug, MAX_ROWS))
    data = clean_row(store.columns, values)
    row = StudioRow(store_id=store.id, data_json=json.dumps(data, default=str),
                    created_by=by, updated_by=by)
    db.session.add(row)
    db.session.commit()
    return _shape(row)


def update(store: StudioDataStore, row_id: int, values: dict, by: str) -> dict:
    row = StudioRow.query.filter_by(store_id=store.id, id=int(row_id)).first()
    if row is None:
        raise StoreError("row %s not found in %s" % (row_id, store.slug))
    data = row.data
    data.update(clean_row(store.columns, values, partial=True))
    for col in store.columns:
        v = data.get(col["name"])
        if col["required"] and (v is None or (isinstance(v, str) and not v.strip())):
            raise StoreError("%s is required" % col["name"])
    row.data_json = json.dumps(data, default=str)
    row.updated_by = by
    db.session.commit()
    return _shape(row)


def delete_row(store: StudioDataStore, row_id: int) -> bool:
    row = StudioRow.query.filter_by(store_id=store.id, id=int(row_id)).first()
    if row is None:
        return False
    db.session.delete(row)
    db.session.commit()
    return True


def _match(row: dict, flt: dict) -> bool:
    """``flt``: ``{col: value}`` (equality) or ``{col: {"op": .., "value": ..}}``."""
    for col, cond in flt.items():
        v = row.get(col)
        op, want = ("eq", cond)
        if isinstance(cond, dict) and "op" in cond:
            op, want = str(cond.get("op")), cond.get("value")
        if op not in FILTER_OPS:
            raise StoreError("unknown filter operator %r" % op)
        if op == "empty":
            if v not in (None, ""):
                return False
            continue
        if op == "not_empty":
            if v in (None, ""):
                return False
            continue
        if op in ("eq", "ne"):
            same = (v == want) or (v is not None and want is not None and str(v) == str(want))
            if same != (op == "eq"):
                return False
            continue
        if op == "contains":
            if want is None or str(want).lower() not in str(v if v is not None else "").lower():
                return False
            continue
        try:
            a, b = float(v), float(want)
        except (TypeError, ValueError):
            a, b = str(v if v is not None else ""), str(want if want is not None else "")
        if op == "gt" and not a > b:
            return False
        if op == "lt" and not a < b:
            return False
    return True


def query(store: StudioDataStore, flt: dict | None = None, *, limit: int = 500,
          order_by: str = "", desc: bool = False) -> list[dict]:
    flt = flt or {}
    if not isinstance(flt, dict):
        raise StoreError("a filter is an object of column: value")
    known = {c["name"] for c in store.columns} | set(SYSTEM_COLUMNS)
    bad = [k for k in flt if k not in known]
    if bad:
        raise StoreError("unknown column(s) in the filter: %s" % ", ".join(sorted(bad)))
    limit = max(1, min(int(limit or 500), MAX_QUERY_LIMIT))
    rows = [_shape(r) for r in StudioRow.query.filter_by(store_id=store.id)
            .order_by(StudioRow.id).all()]
    rows = [r for r in rows if _match(r, flt)]
    if order_by:
        if order_by not in known:
            raise StoreError("unknown column %r to order by" % order_by)
        rows.sort(key=lambda r: (r.get(order_by) is None, str(r.get(order_by))
                                 if not isinstance(r.get(order_by), (int, float))
                                 else r.get(order_by)), reverse=desc)
    return rows[:limit]


def upsert(store: StudioDataStore, match: dict, values: dict, by: str) -> dict:
    """Update the rows matching *match*, or insert one row when none does."""
    found = query(store, match, limit=MAX_QUERY_LIMIT)
    if not found:
        merged = dict(values)
        for k, v in (match or {}).items():
            if not isinstance(v, dict):
                merged.setdefault(k, v)
        return {"inserted": [insert(store, merged, by)], "updated": []}
    return {"inserted": [], "updated": [update(store, r["_id"], values, by) for r in found]}


def delete_where(store: StudioDataStore, match: dict) -> int:
    if not match:
        raise StoreError("deleting needs a filter; an empty one would delete every row")
    n = 0
    for r in query(store, match, limit=MAX_QUERY_LIMIT):
        n += 1 if delete_row(store, r["_id"]) else 0
    return n


# --------------------------------------------------------------------------- #
#  CSV                                                                         #
# --------------------------------------------------------------------------- #
def to_csv(store: StudioDataStore) -> str:
    from .csv_safe import spreadsheet_safe
    names = [c["name"] for c in store.columns]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["_id"] + names)
    for r in query(store, limit=MAX_QUERY_LIMIT):
        w.writerow([r["_id"]] + [spreadsheet_safe(json.dumps(r.get(n)) if isinstance(r.get(n), (dict, list))
                                                  else ("" if r.get(n) is None else r.get(n)))
                                 for n in names])
    return buf.getvalue()


def from_csv(store: StudioDataStore, text: str, by: str) -> dict:
    """Append the CSV rows (a header row names the columns). ``_id`` and other
    system columns are ignored. All rows are checked before any is written: a
    file with one bad line imports nothing."""
    reader = csv.DictReader(io.StringIO(text))
    names = {c["name"] for c in store.columns}
    header = [h for h in (reader.fieldnames or [])]
    unknown = [h for h in header if h not in names and h not in SYSTEM_COLUMNS]
    if unknown:
        raise StoreError("unknown column(s) in the CSV header: %s" % ", ".join(unknown))
    rows = []
    for i, raw in enumerate(reader, start=2):
        values = {k: v for k, v in raw.items() if k in names}
        try:
            rows.append(clean_row(store.columns, values))
        except StoreError as exc:
            raise StoreError("line %d: %s" % (i, exc)) from None
    if count(store) + len(rows) > MAX_ROWS:
        raise StoreError("the import would pass the %d-row limit" % MAX_ROWS)
    for data in rows:
        db.session.add(StudioRow(store_id=store.id, data_json=json.dumps(data, default=str),
                                 created_by=by, updated_by=by))
    db.session.commit()
    return {"imported": len(rows)}
