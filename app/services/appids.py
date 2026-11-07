"""AppID catalog — the billing + access-control authority for server policies.

An **AppID** is two things at once:

  * a **billing key** — which customer a FortiWeb Server Policy is charged to, and
  * an **access-control unit** — the scope an API token can be pinned to, so an
    external integrator may only touch the backends of *their* AppIDs.

Because it decides money AND permissions, the authority is ALWAYS these two
local tables (see :mod:`app.models`):

    ``app_ids``           the catalog (appid, customer, extra fields, active)
    ``app_id_policies``   the binding, ``UNIQUE(appliance, server_policy)`` so a
                          policy belongs to exactly **one** AppID.

…never a file, never a policy ``comment`` string. Files / URLs are *sources* that
feed the catalog through a saved **column→field mapping**; the import is strictly
**ADDITIVE** (insert / update + ``last_seen``). An AppID that disappears from a
feed is flagged ``stale`` for review — it is **never deleted or unassigned**,
because that would silently de-bill a customer or drop a token's scope.

This module is deliberately import-side-effect-free and its parsing/mapping core
is pure (no Flask, no network) so it is unit-testable without a device or a DB.
"""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..models import AppId, AppIdPolicy, Appliance, db
from . import settings_store
from .encryption import decrypt, encrypt

# --------------------------------------------------------------------------- #
#  Saved import configuration (per product, in AppSetting)                      #
# --------------------------------------------------------------------------- #
# The mapping is the "auto-adapt" the operator asked for: uploaded once, reused
# by every later upload AND by the nightly action, so they never re-map fields.

_MAPPING_KEY = "appid.import"          # product is folded into the key
_CORE_FIELDS = ("app_id", "customer", "label", "rate")  # app_id is required


def _key(product: str = "global") -> str:
    # AppIDs are a single GLOBAL catalog now -> one shared import config.
    return f"{_MAPPING_KEY}.global"


def get_mapping(product: str = "global") -> dict[str, Any]:
    """The saved import config for *product* (mapping + external source).

    Shape::

        {
          "has_header": true,
          "fields":  {"app_id": "AppID", "customer": "Client", ...},  # col refs
          "extra":   {"environment": "Env", ...},                      # extra cols
          "source":  {"type": "manual|url", "url": "...",
                      "auth": "none|basic|bearer",
                      "username": "...", "password_enc": "...", "token_enc": "..."}
        }

    Column references are header NAMES when ``has_header`` else index strings
    ("0","1",…). Secrets are stored Fernet-encrypted and never returned in clear.
    """
    data = settings_store.get_json(_key(product), {}) or {}
    if not data:
        # one-time fallback to the pre-global (per-product) mapping so a saved
        # import config survives the move to a single global catalog.
        data = settings_store.get_json(f"{_MAPPING_KEY}.fortiweb", {}) or {}
    if not isinstance(data, dict):
        return {}
    return data


def save_mapping(product: str = "global", mapping: dict[str, Any] | None = None) -> None:
    """Persist the import config. Any ``password``/``token`` in ``source`` is
    encrypted at rest; the clear value is dropped."""
    m = dict(mapping or {})
    src = dict(m.get("source") or {})
    if src.get("password"):
        src["password_enc"] = encrypt(str(src.pop("password")))
    else:
        src.pop("password", None)
    if src.get("token"):
        src["token_enc"] = encrypt(str(src.pop("token")))
    else:
        src.pop("token", None)
    m["source"] = src
    settings_store.set_json(_key(product), m)


# --------------------------------------------------------------------------- #
#  Parsing — every source normalizes to ONE table before mapping               #
# --------------------------------------------------------------------------- #
@dataclass
class ParsedTable:
    """A source file/response reduced to a rectangular table."""
    columns: list[str]                       # header cells (or col1..colN)
    rows: list[list[str]]                    # every row incl. the header row
    kind: str = "csv"                        # csv | tsv | pdf | text
    note: str = ""                           # best-effort caveats for the UI

    def preview(self, n: int = 8) -> dict[str, Any]:
        return {
            "columns": self.columns,
            "rows": [r for r in self.rows[:n]],
            "kind": self.kind,
            "note": self.note,
            "row_count": len(self.rows),
        }


def _decode(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _headerize(width: int) -> list[str]:
    return [f"col{i + 1}" for i in range(width)]


def _sniff_delimited(text: str) -> ParsedTable:
    sample = text[:4096]
    delim = ","
    kind = "csv"
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        delim = dialect.delimiter
    except csv.Error:
        # Fall back: tab if it dominates, else comma, else semicolon.
        counts = {d: sample.count(d) for d in ("\t", ",", ";", "|")}
        delim = max(counts, key=counts.get) if any(counts.values()) else ","
    if delim == "\t":
        kind = "tsv"
    rows = [r for r in csv.reader(io.StringIO(text), delimiter=delim) if any(c.strip() for c in r)]
    if not rows:
        return ParsedTable(columns=[], rows=[], kind=kind, note="empty file")
    width = max(len(r) for r in rows)
    rows = [r + [""] * (width - len(r)) for r in rows]  # pad ragged rows
    columns = [c.strip() for c in rows[0]]
    return ParsedTable(columns=columns, rows=rows, kind=kind)


def _parse_pdf(data: bytes) -> ParsedTable:
    """Tabular PDFs → columns+rows via pdfplumber; free-form → one text column.

    pdfplumber is imported lazily so the CSV/txt path never needs the dependency.
    """
    try:
        import pdfplumber  # noqa: PLC0415 — optional/heavy dep, lazy on purpose
    except Exception:  # noqa: BLE001
        raise ValueError(
            "PDF import needs the 'pdfplumber' package, which is not installed.")
    all_rows: list[list[str]] = []
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        for page in pdf.pages:
            for tbl in (page.extract_tables() or []):
                for r in tbl:
                    cells = [(c or "").strip() for c in r]
                    if any(cells):
                        all_rows.append(cells)
    if all_rows:
        width = max(len(r) for r in all_rows)
        all_rows = [r + [""] * (width - len(r)) for r in all_rows]
        return ParsedTable(columns=[c.strip() for c in all_rows[0]], rows=all_rows,
                           kind="pdf",
                           note="Extracted from a PDF table — verify the columns "
                                "line up before importing.")
    # No table detected → best-effort: every non-blank line is a single-col row.
    text = ""
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        text = "\n".join((p.extract_text() or "") for p in pdf.pages)
    lines = [[ln.strip()] for ln in text.splitlines() if ln.strip()]
    return ParsedTable(
        columns=["text"], rows=[["text"], *lines], kind="text",
        note="No table found in the PDF — free-form text, one line per row. "
             "Map the AppID column carefully; this source is best-effort.")


def parse_upload(filename: str, data: bytes) -> ParsedTable:
    """Normalize any supported upload to a :class:`ParsedTable`.

    Supported: ``.csv`` ``.tsv`` ``.txt`` (delimited) and ``.pdf`` (tabular →
    columns, else free-form text). Unknown extensions are treated as delimited.
    """
    ext = (filename or "").lower().rsplit(".", 1)[-1] if "." in (filename or "") else ""
    if ext == "pdf":
        return _parse_pdf(data)
    return _sniff_delimited(_decode(data))


# --------------------------------------------------------------------------- #
#  Mapping — resolve columns → records                                         #
# --------------------------------------------------------------------------- #
def _col_index(ref: str, columns: list[str], has_header: bool) -> int | None:
    """Resolve a mapping reference (header name or index string) to a col index."""
    if ref is None or ref == "":
        return None
    ref = str(ref)
    if has_header:
        for i, c in enumerate(columns):
            if c.strip().lower() == ref.strip().lower():
                return i
    # index reference ("0","1",...) — also the fallback when a header name misses
    if ref.isdigit():
        i = int(ref)
        return i if 0 <= i < len(columns) else None
    return None


def apply_mapping(table: ParsedTable, mapping: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn a parsed table + saved mapping into normalized AppID records.

    Each record is ``{app_id, customer, label, rate, extra{}}``; rows with a
    blank ``app_id`` are dropped (a record with no key can't be an authority).
    """
    has_header = bool(mapping.get("has_header", True))
    fields = dict(mapping.get("fields") or {})
    extra_map = dict(mapping.get("extra") or {})
    columns = table.columns

    field_idx = {k: _col_index(v, columns, has_header) for k, v in fields.items()}
    extra_idx = {k: _col_index(v, columns, has_header) for k, v in extra_map.items()}

    data_rows = table.rows[1:] if has_header else table.rows
    out: list[dict[str, Any]] = []
    for row in data_rows:
        def cell(i: int | None) -> str:
            return row[i].strip() if (i is not None and 0 <= i < len(row)) else ""
        app_id = cell(field_idx.get("app_id"))
        if not app_id:
            continue
        rec = {
            "app_id": app_id,
            "customer": cell(field_idx.get("customer")),
            "label": cell(field_idx.get("label")),
            "rate": cell(field_idx.get("rate")),
            "extra": {k: cell(i) for k, i in extra_idx.items() if cell(i)},
        }
        out.append(rec)
    return out


# --------------------------------------------------------------------------- #
#  Import — ADDITIVE upsert into the authority                                  #
# --------------------------------------------------------------------------- #
@dataclass
class ImportResult:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    kept: int = 0                # changed in the feed, change refused in review
    stale: int = 0
    skipped: int = 0
    seen: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "created": self.created, "updated": self.updated,
            "unchanged": self.unchanged, "kept": self.kept,
            "stale": self.stale, "skipped": self.skipped,
            "seen": len(self.seen), "errors": self.errors,
        }

    def summary(self) -> str:
        s = (f"{self.created} new, {self.updated} updated, "
             f"{self.unchanged} unchanged")
        if self.kept:
            s += f", {self.kept} kept as they were"
        return s + f", {self.stale} newly stale, {self.skipped} skipped"


def _changes(row: AppId, rec: dict[str, Any]) -> dict[str, list[str]]:
    """``field -> [old, new]`` for what importing *rec* would change on *row*,
    under the same additive rules as :func:`import_records` (an empty cell
    never blanks a value). Empty = the feed brings the same data."""
    out: dict[str, list[str]] = {}
    for f, limit in (("customer", 200), ("label", 200), ("rate", 64)):
        new = str(rec.get(f) or "")[:limit]
        old = getattr(row, f) or ""
        if new and new != old:
            out[f] = [old, new]
    cur = row.extra_dict
    for k, v in (rec.get("extra") or {}).items():
        if v and str(cur.get(k, "")) != str(v):
            out["extra." + k] = [str(cur.get(k, "")), str(v)]
    return out


def plan_import(records: list[dict[str, Any]]) -> dict[str, Any]:
    """What importing *records* would do, without doing it (FA-0014).

    ``new`` AppIDs, ``unchanged`` ones (same data: left exactly as they are),
    ``changed`` ones with their field-by-field differences -- the operator
    accepts those one by one or all at once -- and ``repeated``: AppIDs that
    appear more than once in the file (the last row wins, as on import)."""
    last: dict[str, dict[str, Any]] = {}
    repeated: set[str] = set()
    for rec in records:
        key = str(rec.get("app_id") or "").strip()
        if not key:
            continue
        if key.lower() in last:
            repeated.add(key)
        last[key.lower()] = rec
    existing = {a.app_id.lower(): a for a in AppId.query.all()}
    new, unchanged, changed = [], [], []
    for key, rec in last.items():
        row = existing.get(key)
        if row is None:
            new.append(str(rec["app_id"]).strip())
            continue
        diff = _changes(row, rec)
        if diff:
            changed.append({"app_id": row.app_id, "customer": row.customer,
                            "changes": diff})
        else:
            unchanged.append(row.app_id)
    return {"new": sorted(new), "unchanged": sorted(unchanged),
            "changed": sorted(changed, key=lambda c: c["app_id"].lower()),
            "repeated": sorted(repeated)}


def import_records(records: list[dict[str, Any]], *, product: str = "global",
                   source: str = "import", created_by: str = "",
                   accept: set[str] | None = None) -> ImportResult:
    """ADDITIVE upsert of normalized records into the ``app_ids`` catalog.

    Never deletes. An AppID present before but absent from THIS batch (and whose
    ``source`` is import, i.e. not hand-authored) is flagged ``stale`` for the
    operator — assignments and billing links are preserved untouched.

    *accept* is the review of the page (lower-case AppIDs whose changes the
    operator accepted): an existing AppID the feed changes but that is not in
    it keeps its data. ``None`` (the nightly action) accepts every change. An
    AppID the feed brings with the same data is not touched at all.
    """
    res = ImportResult()
    run_start = datetime.utcnow()
    seen_keys: set[str] = set()

    for rec in records:
        app_id = str(rec.get("app_id") or "").strip()
        if not app_id:
            res.skipped += 1
            continue
        seen_keys.add(app_id.lower())
        res.seen.append(app_id)
        row = (AppId.query
               .filter(db.func.lower(AppId.app_id) == app_id.lower()).first())
        extra = rec.get("extra") or {}
        apply = True
        if row is None:
            row = AppId(app_id=app_id, product="global", source=source,
                        created_by=created_by)
            db.session.add(row)
            res.created += 1
        elif not _changes(row, rec):
            res.unchanged += 1
            apply = False
        elif accept is not None and app_id.lower() not in accept:
            res.kept += 1
            apply = False
        else:
            res.updated += 1
        if apply:
            # Additive update: fill/refresh display fields, keep prior values if
            # the feed omits a column (don't blank an existing customer with "").
            if rec.get("customer"):
                row.customer = rec["customer"][:200]
            if rec.get("label"):
                row.label = rec["label"][:200]
            if rec.get("rate"):
                row.rate = rec["rate"][:64]
            if extra:
                merged = row.extra_dict
                merged.update({k: v for k, v in extra.items() if v})
                row.extra_json = json.dumps(merged)
            row.updated_at = run_start
        row.active = True
        row.stale = False
        row.stale_reason = ""
        row.last_seen = run_start

    # Stale pass — imported AppIDs not in this batch. Hand-authored (source
    # 'manual') rows are never auto-staled.
    if seen_keys:
        others = (AppId.query
                  .filter(AppId.source == "import",
                          AppId.stale.is_(False)).all())
        for row in others:
            if row.app_id.lower() not in seen_keys:
                row.stale = True
                row.stale_reason = f"absent from feed on {run_start.date().isoformat()}"
                res.stale += 1
    db.session.commit()
    return res


# --------------------------------------------------------------------------- #
#  External source fetch (for the nightly action)                              #
# --------------------------------------------------------------------------- #
def fetch_source(source: dict[str, Any]) -> tuple[str, bytes]:
    """Fetch the configured external catalog → ``(filename, bytes)``.

    ``source['type']`` == ``'url'`` → an authenticated HTTP GET (auth none /
    basic / bearer). A ``'manual'`` source has nothing to fetch and raises, so
    the nightly reports "no source configured" instead of pretending.
    """
    stype = (source or {}).get("type", "manual")
    if stype != "url":
        raise ValueError("no external URL source configured (upload is manual-only)")
    url = str(source.get("url") or "").strip()
    if not url:
        raise ValueError("external source URL is empty")
    import httpx  # lazy — keeps the import graph light for tests
    headers: dict[str, str] = {}
    auth = None
    kind = source.get("auth", "none")
    if kind == "bearer" and source.get("token_enc"):
        headers["Authorization"] = "Bearer " + decrypt(source["token_enc"])
    elif kind == "basic" and source.get("username"):
        pw = decrypt(source["password_enc"]) if source.get("password_enc") else ""
        auth = (source["username"], pw)
    from . import trust_store
    resp = httpx.get(url, headers=headers, auth=auth, timeout=30.0,
                     follow_redirects=True, verify=trust_store.verify_param())
    resp.raise_for_status()
    # filename from the URL tail so parse_upload picks the right parser.
    name = url.rsplit("/", 1)[-1].split("?", 1)[0] or "catalog.csv"
    return name, resp.content


# --------------------------------------------------------------------------- #
#  Authority CRUD + assignment                                                 #
# --------------------------------------------------------------------------- #
def catalog(product: str = "global") -> list[AppId]:
    # ONE global catalog spanning FortiWeb + FortiADC (product arg kept for
    # call-site compatibility, ignored).
    return (AppId.query.order_by(AppId.stale, AppId.app_id).all())


def get(app_id_pk: int) -> AppId | None:
    return db.session.get(AppId, app_id_pk)


def create_manual(*, app_id: str, product: str = "global", customer: str = "",
                  label: str = "", rate: str = "", extra: dict | None = None,
                  created_by: str = "") -> AppId:
    app_id = (app_id or "").strip()
    if not app_id:
        raise ValueError("AppID is required")
    dup = (AppId.query
           .filter(db.func.lower(AppId.app_id) == app_id.lower()).first())
    if dup is not None:
        raise ValueError(f"AppID {app_id!r} already exists")
    row = AppId(app_id=app_id, product="global", customer=customer[:200],
                label=label[:200], rate=rate[:64], source="manual",
                extra_json=json.dumps(extra or {}), created_by=created_by,
                active=True, last_seen=datetime.utcnow())
    db.session.add(row)
    db.session.commit()
    return row


def delete(app_id_pk: int) -> None:
    """Delete an AppID and (cascade) its policy bindings. Admin-only, explicit —
    unlike the nightly which never deletes."""
    row = db.session.get(AppId, app_id_pk)
    if row is not None:
        AppIdPolicy.query.filter_by(app_id_id=row.id).delete()
        db.session.delete(row)
        db.session.commit()


def delete_many(pks: list[int]) -> list[str]:
    """Delete several AppIDs (and their bindings) in one transaction. Returns
    the names deleted; unknown ids are ignored."""
    rows = AppId.query.filter(AppId.id.in_([int(p) for p in pks])).all() if pks else []
    names = [r.app_id for r in rows]
    for r in rows:
        AppIdPolicy.query.filter_by(app_id_id=r.id).delete()
        db.session.delete(r)
    db.session.commit()
    return names


# --------------------------------------------------------------------------- #
#  Catalog columns: which are shown and what they are called (FA-0014)        #
# --------------------------------------------------------------------------- #
_COLUMNS_KEY = "appid.catalog_columns"
BASE_COLUMNS = (("app_id", "AppID"), ("customer", "Customer"), ("label", "Label"),
                ("rate", "Rate"), ("source", "Source"), ("status", "Status"),
                ("policies", "Policies"))


def extra_keys() -> list[str]:
    keys: set[str] = set()
    for a in AppId.query.all():
        keys.update(str(k) for k in a.extra_dict)
    return sorted(keys, key=str.lower)


def columns() -> list[dict[str, Any]]:
    """The catalog's columns in order: the core ones, then every extra field an
    import brought. Each ``{key, default, label, visible}``; ``label`` is the
    operator's name for it (one for every admin, kept in the database)."""
    conf = settings_store.get_json(_COLUMNS_KEY, {}) or {}
    labels = conf.get("labels") if isinstance(conf.get("labels"), dict) else {}
    hidden = set(conf.get("hidden") or []) if isinstance(conf.get("hidden"), list) else set()
    out = [{"key": k, "default": d} for k, d in BASE_COLUMNS]
    out += [{"key": "extra." + k, "default": k} for k in extra_keys()]
    for c in out:
        c["label"] = str(labels.get(c["key"]) or c["default"])
        c["visible"] = c["key"] == "app_id" or c["key"] not in hidden
    return out


def save_columns(labels: dict, hidden: list) -> list[dict[str, Any]]:
    """Persist column names and visibility. Unknown keys are dropped, a blank
    name means the default, and the AppID column is always shown."""
    known = {c["key"]: c["default"] for c in columns()}
    clean_labels = {}
    for k, v in (labels or {}).items():
        v = " ".join(str(v or "").split())[:60]
        if k in known and v and v != known[k]:
            clean_labels[k] = v
    clean_hidden = sorted({str(k) for k in (hidden or []) if k in known and k != "app_id"})
    settings_store.set_json(_COLUMNS_KEY, {"labels": clean_labels, "hidden": clean_hidden})
    return columns()


# --------------------------------------------------------------------------- #
#  Bindings read from the server-policy comment (FA-0014)                      #
# --------------------------------------------------------------------------- #
def comment_bindings(appliances: list[Appliance]) -> list[dict[str, Any]]:
    """Every server policy of *appliances* (local store, last sync: no device
    call) with the AppID its ``comment`` names -- the same pattern as
    Analysis > AppID pattern -- the catalog AppID it matches and the binding
    saved today. The comment only PROPOSES: the binding table stays the
    authority, and nothing is saved until the operator saves it.

    ``state``: ``bound`` (saved = proposed), ``proposed`` (no binding yet, the
    comment names a catalog AppID), ``differs`` (saved to another AppID),
    ``not_in_catalog`` (the comment names an AppID the catalog lacks),
    ``no_appid`` (nothing in the comment), ``manual`` (bound, comment silent).
    """
    from . import read_layer
    from .analysis import appid_pattern, extract_appid
    pat = appid_pattern()
    every = AppId.query.all()
    cat = {a.app_id.lower(): a for a in every}
    by_pk = {a.id: a.app_id for a in every}
    # One query each, no lazy load per row: SA-0025 (thousands of policies).
    binds = {(b.appliance_id, b.server_policy): b for b in AppIdPolicy.query.all()}
    out: list[dict[str, Any]] = []
    for appl in appliances:
        try:
            payloads, _meta = read_layer.read_objects(appl.id, "server_policy")
        except Exception:  # noqa: BLE001 -- no cache for this device
            payloads = []
        for p in payloads or []:
            name = str(p.get("name") or "")
            if not name:
                continue
            comment = str(p.get("comment") or "")
            found = extract_appid(comment, pat) or ""
            match = cat.get(found) if found else None
            bound = binds.get((appl.id, name))
            if bound is not None and match is not None:
                state = "bound" if bound.app_id_id == match.id else "differs"
            elif bound is not None:
                state = "not_in_catalog" if found else "manual"
            elif match is not None:
                state = "proposed"
            else:
                state = "not_in_catalog" if found else "no_appid"
            out.append({
                "appliance_id": appl.id, "device": appl.name, "policy": name,
                "comment": comment[:300], "found": found,
                "found_pk": match.id if match else None,
                "bound_pk": bound.app_id_id if bound else None,
                "bound_app_id": by_pk.get(bound.app_id_id, "") if bound is not None else "",
                "state": state,
            })
    return out


#: Scheduled action that keeps the bindings in step with the comments.
RECONCILE_ACTION = "appid_reconcile"
RECONCILE_NAME = "AppIDs - bind server policies from their comments"
RECONCILE_SCHEDULE = {"time": "06:40"}
#: States the reconcile cannot settle by itself: an operator decides.
UNRESOLVED = ("differs", "not_in_catalog", "no_appid")
#: AppSetting: short hashes of the unresolved rows already rung, so the bell
#: rings for what is NEW, not for the same list every day.
_RINGED_KEY = "appid.reconcile.ringed"
#: AppSetting: the user who asked for a background run (rung when it ends).
REQUESTED_BY_KEY = "appid.reconcile.requested_by"
RESOLVE_LINK = "/web/appids/?review=unresolved#assign"


def _row_hash(r: dict[str, Any]) -> str:
    import hashlib
    raw = "%s|%s|%s|%s" % (r["appliance_id"], r["policy"], r["state"], r["found"])
    return hashlib.sha1(raw.encode()).hexdigest()[:10]


def reconcile(*, dry_run: bool = False, by: str = "scheduler",
              notify: bool = True) -> dict[str, Any]:
    """Compare every FortiWeb server policy (local store, no device call) with
    the AppID its comment names and settle what needs no judgement.

    * ``proposed`` (the comment names a catalog AppID, nothing saved yet) is
      SAVED -- the same binding the operator would save from Assign policies.
    * ``differs``, ``not_in_catalog`` and ``no_appid`` need a person: they are
      counted and, the first time each one shows up, rung to the
      administrators with a link to the review list (``RESOLVE_LINK``).
    * A saved binding is never moved: the binding table stays the authority.
    """
    from .audit import log_action
    appls = Appliance.query.filter_by(kind="fortiweb").order_by(Appliance.name).all()
    rows = comment_bindings(appls)
    saved, failed = [], []
    for r in rows:
        if r["state"] != "proposed" or not r["found_pk"]:
            continue
        if dry_run:
            saved.append(r)
            continue
        try:
            assign(app_id_pk=r["found_pk"], appliance_id=r["appliance_id"],
                   server_policy=r["policy"], by=by)
        except ValueError as exc:
            failed.append("%s/%s: %s" % (r["device"], r["policy"], exc))
            continue
        log_action("appid.assign", target=r["policy"],
                   extra={"app_id_pk": r["found_pk"], "appliance_id": r["appliance_id"],
                          "from": "comment", "by": by})
        saved.append(r)
    open_rows = [r for r in rows if r["state"] in UNRESOLVED]
    counts = {st: sum(1 for r in open_rows if r["state"] == st) for st in UNRESOLVED}
    out = {"devices": len(appls), "policies": len(rows), "saved": len(saved),
           "failed": failed, "unresolved": len(open_rows), "counts": counts,
           "new_unresolved": 0, "rung": 0, "dry_run": dry_run,
           "saved_rows": ["%s/%s -> %s" % (r["device"], r["policy"], r["found"])
                          for r in saved]}
    if dry_run:
        return out
    before = set(settings_store.get_json(_RINGED_KEY, []) or [])
    now = {_row_hash(r) for r in open_rows}
    fresh = now - before
    out["new_unresolved"] = len(fresh)
    # Keep only what is still open: a row that is settled and comes back
    # rings again.
    settings_store.set_json(_RINGED_KEY, sorted(now))
    if notify:
        from . import notifications as notify_svc
        from .alerts import _admin_ids
        body = ("%d different from the saved binding, %d naming an AppID the "
                "catalog lacks, %d without an AppID in the comment."
                % (counts["differs"], counts["not_in_catalog"], counts["no_appid"]))
        if fresh:
            out["rung"] = notify_svc.push_many(
                _admin_ids(), "AppIDs: %d server polic%s need%s you"
                % (len(fresh), "y" if len(fresh) == 1 else "ies",
                   "s" if len(fresh) == 1 else ""),
                kind="warning", body=body, link=RESOLVE_LINK, product="fortiweb")
        requester = settings_store.get_str(REQUESTED_BY_KEY)
        if requester:
            settings_store.set_str(REQUESTED_BY_KEY, "")
            try:
                notify_svc.push(int(requester), "AppIDs: background check finished",
                                kind="info", link=RESOLVE_LINK, product="fortiweb",
                                body="%d policies read, %d bindings saved from the "
                                     "comments, %d need a decision. %s"
                                     % (len(rows), len(saved), len(open_rows), body))
            except (TypeError, ValueError):
                pass
    return out


def reconcile_row():
    """The scheduled row of :data:`RECONCILE_ACTION`, or ``None``."""
    from ..models import ScheduledAction
    return (ScheduledAction.query.filter_by(action=RECONCILE_ACTION)
            .order_by(ScheduledAction.id).first())


def ensure_reconcile_schedule(by: str = "") -> tuple[Any, bool]:
    """The reconcile's scheduled row, created (daily) or re-enabled.
    Returns ``(row, created)``. Idempotent: never a second row."""
    from ..models import ScheduledAction
    from . import scheduled_actions as sa
    from .scheduler import compute_next_run
    row = reconcile_row()
    created = row is None
    if created:
        row = ScheduledAction(
            name=RECONCILE_NAME, scope="admin", product="fortiweb",
            action=RECONCILE_ACTION, targets="[]", params="{}",
            schedule_kind="daily", schedule=json.dumps(RECONCILE_SCHEDULE),
            enabled=True, catch_up=True, created_by=(by or "")[:64])
        db.session.add(row)
    if created or not row.enabled:
        row.enabled = True
        row.next_run = compute_next_run(row.schedule_kind,
                                        json.loads(row.schedule or "{}"),
                                        tz=sa._configured_tz())
    db.session.commit()
    return row, created


def queue_reconcile_now(user_id: int | None, by: str = "") -> tuple[Any, bool]:
    """Ask the scheduler to run the reconcile at its next tick (<= 1 min),
    off the request: the page answers at once. Returns ``(row, queued)``;
    ``queued`` is False while a run is already in progress."""
    row, _created = ensure_reconcile_schedule(by)
    if row.running_at is not None:
        return row, False
    row.next_run = datetime.utcnow()
    db.session.commit()
    if user_id:
        settings_store.set_str(REQUESTED_BY_KEY, str(int(user_id)))
    return row, True


def binding_for(appliance_id: int, server_policy: str) -> AppIdPolicy | None:
    return AppIdPolicy.query.filter_by(
        appliance_id=appliance_id, server_policy=server_policy).first()


def assign(*, app_id_pk: int, appliance_id: int, server_policy: str,
           by: str = "") -> AppIdPolicy:
    """Bind a Server Policy to an AppID. Enforces 1-AppID-per-policy: an existing
    binding for that (appliance, policy) is MOVED (re-billing), returned as the
    updated row. The caller audits."""
    server_policy = (server_policy or "").strip()
    if not server_policy:
        raise ValueError("server policy is required")
    if db.session.get(AppId, app_id_pk) is None:
        raise ValueError("no such AppID")
    row = binding_for(appliance_id, server_policy)
    if row is None:
        row = AppIdPolicy(app_id_id=app_id_pk, appliance_id=appliance_id,
                          server_policy=server_policy, assigned_by=by)
        db.session.add(row)
    else:
        row.app_id_id = app_id_pk
        row.assigned_by = by
        row.assigned_at = datetime.utcnow()
    db.session.commit()
    return row


def unassign(appliance_id: int, server_policy: str) -> bool:
    row = binding_for(appliance_id, server_policy)
    if row is None:
        return False
    db.session.delete(row)
    db.session.commit()
    return True


def policies_for(app_id_pk: int) -> list[AppIdPolicy]:
    return AppIdPolicy.query.filter_by(app_id_id=app_id_pk).all()


def unassigned_policies(product: str = "fortiweb") -> int:
    """Count of bound-vs-total is a UI concern; here we just expose the set of
    bindings so the page can flag policies with no AppID (= not billed)."""
    return AppIdPolicy.query.count()


def token_scope_targets(app_id_strings: list[str], product: str = ""
                        ) -> set[tuple[int, str]]:
    """Resolve a token's allowed AppID names → the set of ``(appliance_id,
    server_policy)`` it may act on. Phase 2 (token enforcement) consumes this.

    The catalog is GLOBAL but a token is product-scoped: when *product* is a real
    product ('fortiweb'/'fortiadc') the result is filtered to bindings on
    appliances of THAT kind, so a FortiWeb token can never reach an ADC policy
    (and vice-versa). An empty/other *product* returns every binding."""
    if not app_id_strings:
        return set()
    ids = (AppId.query
           .filter(db.func.lower(AppId.app_id).in_([s.lower() for s in app_id_strings]))
           .all())
    pks = [a.id for a in ids]
    if not pks:
        return set()
    q = AppIdPolicy.query.filter(AppIdPolicy.app_id_id.in_(pks))
    if product in ("fortiweb", "fortiadc"):
        q = (q.join(Appliance, Appliance.id == AppIdPolicy.appliance_id)
              .filter(Appliance.kind == product))
    binds = q.all()
    return {(b.appliance_id, b.server_policy) for b in binds}


def policies_using_pool(appliance_id: int, pool_name: str) -> set[str]:
    """Server policies on *appliance_id* whose main ``server-pool`` is *pool_name*.

    DB-first over the cached top-level policies (zero device calls). This covers
    single-server / server-balance policies — exactly the shape a backend
    drain/restore acts on. Content-routing-only pools are intentionally NOT
    resolved here (the deep-graph walk is fragile); the caller treats an empty
    result as "unprovable" and FAILS CLOSED, which is the safe default for a
    boundary that also gates billing.
    """
    pool_name = (pool_name or "").strip()
    if not pool_name:
        return set()
    from . import read_layer
    try:
        payloads, _ = read_layer.read_objects(appliance_id, "server_policy")
    except Exception:  # noqa: BLE001 — no cache ⇒ unprovable ⇒ empty ⇒ deny
        return set()
    out: set[str] = set()
    for p in payloads or []:
        if str(p.get("server-pool") or "").strip() == pool_name and p.get("name"):
            out.add(str(p["name"]))
    return out


def action_target_scope(action_row) -> set[tuple[int, str]]:
    """The set of ``(appliance_id, server_policy)`` a scheduled action would touch.

    Resolves the three AppID-scopable user ops:

      * ``policy_set_status`` / ``swap_certificate`` → params['policy'] directly;
      * ``backend_set_status`` → params['server_pool'] resolved to the policies
        that bind it (per target appliance).

    Returns an EMPTY set when the target can't be resolved — the caller denies
    (fail-closed). A non-scopable action also returns empty by construction.
    """
    key = getattr(action_row, "action", "") or ""
    params = action_row.params_dict if hasattr(action_row, "params_dict") else {}
    targets = action_row.targets_list if hasattr(action_row, "targets_list") else []
    aids = [int(t) for t in (targets or []) if str(t).strip().isdigit()]
    if not aids:
        return set()
    aid = aids[0]  # user ops are single_target — the first device
    if key in ("policy_set_status", "swap_certificate"):
        policy = str(params.get("policy") or "").strip()
        return {(aid, policy)} if policy else set()
    if key in ("backend_set_status", "backend_set_config"):
        pool = str(params.get("server_pool") or "").strip()
        if not pool:
            return set()
        return {(aid, p) for p in policies_using_pool(aid, pool)}
    return set()
