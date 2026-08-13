"""Firmware-keyed API matrix: what each firmware LINE actually serves.

The problem this exists for: FortiWeb 7.6 and 8.0 speak the **same API
version** (``v2.0``). The registry's ``api_version`` axis therefore cannot
express the difference between them — and the difference is real: measured on
this fleet's own artifacts, ``admin`` has 40 fields on 7.6 and **42** on 8.0,
``global`` 60 vs **63**, ``ntp`` 3 vs **4**. Code that builds a payload from
one line and writes it to a box running the other is the failure this module
is here to make visible BEFORE the write, not after the device rejects it.

So the unit of knowledge here is the **(product, firmware line, endpoint)**
triple, and the value is the set of field names that line was observed to
serve. ``line`` is ``major.minor`` — the same granularity ``CapacityLimit``
and ``data/field_schemas/<product>/<line>/`` already use, so a build number
does not mint a new line on every patch release.

Two evidence sources, both already on disk and both already replicated to the
standby by ``satom-ha-datasync``:

* **sweep** — ``data/rediscovery/<appliance_id>/_config.json``. The sweep
  already records a per-endpoint verdict (``endpoint_status``) *and* the
  objects it read back (``sections``); the keys of those objects ARE the
  fields that firmware serves. Nobody read them.
* **schema** — ``data/field_schemas/<product>/<line>/<object>.json``, the
  harvested field specs. This is the ONLY evidence for FortiWeb 8.0 today,
  because no 8.0 FortiWeb is left in the fleet — the 8.0 folder was harvested
  from ``fw1``, since retired.

Deliberately NOT a database table. Everything here is *derived*: throw the
file away and a rebuild reconstructs it exactly. Putting a derived view in
Postgres would also put it in a different backup path from the evidence it
summarises, which are already carried by the same rsync and the same bundle.

Three rules that the whole module is shaped around, each one a way this could
quietly lie instead of loudly not-knowing:

1. **``fields=None`` is not ``fields=[]``.** An endpoint that answered ``ok``
   with zero rows tells you the endpoint EXISTS and tells you NOTHING about
   its fields. Folding that into an empty set would make a line look like it
   "lost" every field of an empty collection — the diff against a populated
   line would invent dozens of removals that never happened.
2. **A line with no evidence is ``unmeasured``, never ``compatible``.** The
   preflight's default answer is "I don't know", because the caller's next
   action is a write to a real appliance.
3. **"Absent on the other line" requires the other line to have been
   measured.** Present-here/unknown-there is reported as unknown, never as
   removed.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime

# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
REDISCOVERY_ROOT = os.path.join(_ROOT, "data", "rediscovery")
SCHEMA_ROOT = os.path.join(_ROOT, "data", "field_schemas")
MATRIX_ROOT = os.path.join(_ROOT, "data", "api_matrix")

# Products that have a sweep plan (``rediscovery.plan_for``). FAZ and FAC have
# a catalog but no sweep, so their matrix can only ever be schema-derived —
# stated here rather than discovered as an empty page.
SWEPT_PRODUCTS = ("fortiweb", "fortiadc")

# Kind string on ``Appliance`` per product key.
_KIND_FOR = {"fortiweb": "fortiweb", "fortiadc": "fortiadc",
             "fortianalyzer": "fortianalyzer", "fortiauthenticator": "fortiauthenticator"}

# A ledger that is mostly errors is not evidence about the CATALOG, it is
# evidence about that appliance. Same threshold and same reason as
# ``registry_reconcile``: fortiweb08 answers -20010 (peer VM licence) to 283 of
# 321 CMDB reads while the inventory still calls it online, and reading it
# naively would attribute 283 phantom absences to the 7.6 line.
MAX_ERROR_RATIO = 0.25

VERDICT_OK = "ok"
VERDICT_ABSENT = "absent"
VERDICT_ERROR = "error"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def firmware_line(version: str | None) -> str:
    """``"7.6.8 build1128"`` → ``"7.6"``. Empty string when there is no version.

    Truncating to major.minor is the whole point: a patch release is not a new
    API surface, and keying by the full string would give every build its own
    column of one-device evidence that never accumulates.
    """
    if not version:
        return ""
    m = re.search(r"(\d+)\.(\d+)", str(version))
    return f"{m.group(1)}.{m.group(2)}" if m else ""


def _read_json(path: str):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write_json_atomic(path: str, payload) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(payload, fh, indent=1, sort_keys=True)
        # mkstemp hands back 0600. Every other artifact under data/ is 0644
        # and this one holds no secret — it is a derived summary of endpoint
        # names and field names. An inherited mode is an accident; a stated
        # one is a decision, and the decision here is "same as its siblings",
        # so a mode audit does not turn up one odd file with no reason.
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def matrix_path(product: str) -> str:
    return os.path.join(MATRIX_ROOT, f"{product}.json")


# ---------------------------------------------------------------------------
# witnesses — from the appliance TABLE, never from the snapshot directory
# ---------------------------------------------------------------------------

def _live_appliances(product: str) -> dict:
    """``{appliance_id: {"name","firmware","line"}}`` for appliances that exist.

    Half of ``data/rediscovery/`` belongs to appliances that were deleted, and
    four more are the retired ``*.invalid`` hosts. A firmware line justified by
    a device nobody can re-probe is a claim nobody can reproduce, so the
    witness list is built from the table and the snapshots are filtered by it.
    """
    from ..models import Appliance

    kind = _KIND_FOR.get(product, product)
    out: dict = {}
    for ap in Appliance.query.filter_by(kind=kind).all():
        if getattr(ap, "maintenance", False):
            continue
        if str(getattr(ap, "host", "") or "").endswith(".invalid"):
            continue
        out[ap.id] = {"name": ap.name, "firmware": ap.firmware or "",
                      "line": firmware_line(getattr(ap, "fw_version", "") or ap.firmware)}
    return out


# ---------------------------------------------------------------------------
# evidence 1 — the sweep
# ---------------------------------------------------------------------------

def _sweep_evidence(product: str, witnesses: dict) -> tuple[dict, list]:
    """``({line: {endpoint: record}}, [device_note, ...])`` from the snapshots.

    A record accumulates across every witness on that line:
    ``verdict`` (worst-case is never used — see below), ``fields`` (union of
    the keys of every object read back, or ``None`` if no witness ever saw a
    row) and the devices that contributed.
    """
    lines: dict = {}
    notes: list = []
    if not os.path.isdir(REDISCOVERY_ROOT):
        return lines, notes

    for entry in sorted(os.listdir(REDISCOVERY_ROOT)):
        try:
            aid = int(entry)
        except ValueError:
            continue
        wit = witnesses.get(aid)
        if wit is None:
            continue
        snap = _read_json(os.path.join(REDISCOVERY_ROOT, entry, "_config.json"))
        if not isinstance(snap, dict):
            continue
        ledger = snap.get("endpoint_status") or {}
        if not ledger:
            notes.append({"device": wit["name"], "skipped": "pre-ledger snapshot"})
            continue

        # The line comes from the SNAPSHOT, not from the appliance row: the
        # snapshot records the firmware the sweep actually measured against,
        # and the row can have been upgraded since.
        line = firmware_line(snap.get("firmware") or wit["firmware"])
        if not line:
            notes.append({"device": wit["name"], "skipped": "snapshot has no firmware"})
            continue

        errs = sum(1 for v in ledger.values() if v.get("verdict") == VERDICT_ERROR)
        if errs and errs / max(len(ledger), 1) > MAX_ERROR_RATIO:
            notes.append({"device": wit["name"], "line": line,
                          "skipped": "%d/%d endpoints errored — the device is "
                                     "unhealthy, not the catalog" % (errs, len(ledger))})
            continue

        at = str(snap.get("generated_at") or "")[:19]
        bucket = lines.setdefault(line, {})

        # field keys, per endpoint, out of the objects the sweep read back
        seen_fields: dict = {}
        for _section, eps in (snap.get("sections") or {}).items():
            if not isinstance(eps, dict):
                continue
            for ep_name, rows in eps.items():
                if not isinstance(rows, list):
                    continue
                keys: set = set()
                for row in rows:
                    if isinstance(row, dict):
                        keys.update(str(k) for k in row.keys())
                if keys:
                    seen_fields.setdefault(ep_name, set()).update(keys)

        for ep_name, info in ledger.items():
            verdict = info.get("verdict") or VERDICT_ERROR
            rec = bucket.setdefault(ep_name, {
                "endpoint": ep_name, "urn": info.get("urn") or "",
                "section": info.get("section") or "",
                "verdict": None, "fields": None, "origin": "sweep",
                "devices": [], "measured_at": at,
            })
            rec["devices"].append(wit["name"])
            if at > (rec["measured_at"] or ""):
                rec["measured_at"] = at

            # Verdict merge: OK from ANY healthy witness on the line wins.
            # Absence is a claim about the firmware, so one device that served
            # it disproves every device that did not. An error contributes
            # nothing either way — it is a statement about that box.
            if verdict == VERDICT_OK:
                rec["verdict"] = VERDICT_OK
            elif verdict == VERDICT_ABSENT and rec["verdict"] != VERDICT_OK:
                rec["verdict"] = VERDICT_ABSENT
            elif rec["verdict"] is None:
                rec["verdict"] = VERDICT_ERROR

            keys = seen_fields.get(ep_name)
            if keys:
                # RULE 1: only a row with keys creates a field set. ``ok`` with
                # zero rows leaves ``fields`` at None = "exists, contents
                # unknown" — the diff must not read that as "has no fields".
                rec["fields"] = sorted(set(rec["fields"] or []) | keys)

    return lines, notes


# ---------------------------------------------------------------------------
# evidence 2 — the harvested field schemas
# ---------------------------------------------------------------------------

def _schema_evidence(product: str) -> dict:
    """``{line: {object: record}}`` from ``data/field_schemas/<product>/<line>``.

    ``_default`` is excluded: it is the fallback for lines that have not
    diverged, so counting it as a line would invent a firmware that no
    appliance runs.
    """
    lines: dict = {}
    base = os.path.join(SCHEMA_ROOT, product)
    if not os.path.isdir(base):
        return lines
    for line in sorted(os.listdir(base)):
        if line == "_default" or not os.path.isdir(os.path.join(base, line)):
            continue
        bucket = lines.setdefault(line, {})
        for fname in sorted(os.listdir(os.path.join(base, line))):
            if not fname.endswith(".json"):
                continue
            doc = _read_json(os.path.join(base, line, fname))
            if not isinstance(doc, dict) or "object" not in doc:
                continue
            fields = [f.get("name") for f in (doc.get("fields") or [])
                      if isinstance(f, dict) and f.get("name")]
            bucket[doc["object"]] = {
                "endpoint": doc.get("endpoint") or doc["object"],
                "object": doc["object"],
                "fields": sorted(set(fields)) if fields else None,
                "origin": "schema",
                "source": doc.get("source") or "",
                "device_firmware": doc.get("device_firmware") or "",
                "measured_at": str(doc.get("generated_at") or "")[:19],
            }
    return lines


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def build(product: str) -> dict:
    """Derive the whole matrix for one product. Pure read — writes nothing."""
    witnesses = _live_appliances(product)
    sweep, notes = _sweep_evidence(product, witnesses)
    schema = _schema_evidence(product)

    fleet_lines = sorted({w["line"] for w in witnesses.values() if w["line"]})
    all_lines = sorted(set(sweep) | set(schema))

    lines: dict = {}
    for line in all_lines:
        eps = {}
        for name, rec in (sweep.get(line) or {}).items():
            eps[name] = dict(rec)
        objects = {}
        for obj, rec in (schema.get(line) or {}).items():
            objects[obj] = dict(rec)
        ok = sum(1 for r in eps.values() if r["verdict"] == VERDICT_OK)
        absent = sum(1 for r in eps.values() if r["verdict"] == VERDICT_ABSENT)
        with_fields = sum(1 for r in eps.values() if r["fields"])
        lines[line] = {
            "line": line,
            "in_fleet": line in fleet_lines,
            "devices": sorted({d for r in eps.values() for d in r["devices"]}),
            "endpoints": eps,
            "objects": objects,
            "counts": {
                "swept": len(eps), "ok": ok, "absent": absent,
                "error": len(eps) - ok - absent,
                "endpoints_with_fields": with_fields,
                "schema_objects": len(objects),
                "schema_fields": sum(len(r["fields"] or []) for r in objects.values()),
            },
        }

    return {
        "product": product,
        "built_at": datetime.utcnow().isoformat(timespec="seconds"),
        "sweepable": product in SWEPT_PRODUCTS,
        "fleet_lines": fleet_lines,
        "witnesses": [{"id": k, **v} for k, v in sorted(witnesses.items())],
        "notes": notes,
        "lines": lines,
    }


def rebuild(product: str) -> dict:
    """Build and persist. Returns the matrix."""
    matrix = build(product)
    _write_json_atomic(matrix_path(product), matrix)
    return matrix


def load(product: str, rebuild_if_missing: bool = True) -> dict | None:
    """The stored matrix, rebuilt on first access when absent."""
    doc = _read_json(matrix_path(product))
    if isinstance(doc, dict) and doc.get("product") == product:
        return doc
    if rebuild_if_missing:
        try:
            return rebuild(product)
        except Exception:  # noqa: BLE001 — a page must not 500 on a cold store
            return None
    return None


# ---------------------------------------------------------------------------
# diff — the answer to "what does 8.0 add?"
# ---------------------------------------------------------------------------

def diff(product: str, base_line: str, target_line: str, matrix: dict | None = None) -> dict:
    """What ``target_line`` adds/removes relative to ``base_line``.

    Every bucket here is separated by WHY, because "8.0 has a field 7.6 does
    not" and "nobody ever measured that endpoint on 7.6" look identical in a
    naive set difference and mean opposite things to whoever is about to write
    a payload.
    """
    matrix = matrix or load(product) or {"lines": {}}
    a = (matrix.get("lines") or {}).get(base_line) or {}
    b = (matrix.get("lines") or {}).get(target_line) or {}
    a_eps, b_eps = a.get("endpoints") or {}, b.get("endpoints") or {}
    a_obj, b_obj = a.get("objects") or {}, b.get("objects") or {}

    def _served(rec):
        return bool(rec) and rec.get("verdict") == VERDICT_OK

    endpoints_added, endpoints_removed, endpoints_unknown = [], [], []
    for name in sorted(set(a_eps) | set(b_eps)):
        ra, rb = a_eps.get(name), b_eps.get(name)
        if ra is None or rb is None:
            # RULE 3: not measured on one side is UNKNOWN, not a change.
            endpoints_unknown.append({"endpoint": name,
                                      "measured_on": base_line if ra else target_line})
            continue
        if _served(rb) and not _served(ra) and ra.get("verdict") == VERDICT_ABSENT:
            endpoints_added.append({"endpoint": name, "urn": rb.get("urn", "")})
        elif _served(ra) and not _served(rb) and rb.get("verdict") == VERDICT_ABSENT:
            endpoints_removed.append({"endpoint": name, "urn": ra.get("urn", "")})

    # --- field deltas, compared ONLY within one kind of evidence ------------
    fields_changed, fields_unknown, fields_incomparable = [], [], []

    def _field_map(line_doc):
        """``{key: {origin: fields}}`` — the two evidence kinds kept APART.

        Merging them was the first version of this function and it was wrong
        in a way that only real data showed: a sweep field set is the raw dict
        FortiWeb puts on the wire, which carries the ``_val`` companion of
        every enum, plus ``sz_``/``q_`` internals; the harvested schema
        deliberately strips exactly those (``fortiweb_field_schema._NOISE_*``)
        because they are not operator-settable fields. Comparing one against
        the other reported **56 removed fields** for 7.6 → 8.0 that are
        nothing but that filter — a page whose headline number is noise is a
        page the operator learns to ignore.

        So a delta is only ever computed sweep↔sweep or schema↔schema. A key
        known by different kinds on the two lines is *incomparable*, and says
        so.
        """
        out: dict = {}
        for obj, rec in (line_doc.get("objects") or {}).items():
            if rec.get("fields"):
                out.setdefault(obj, {})["schema"] = set(rec["fields"])
        for name, rec in (line_doc.get("endpoints") or {}).items():
            if rec.get("fields"):
                out.setdefault(name, {})["sweep"] = set(rec["fields"])
        return out

    fa, fb = _field_map(a), _field_map(b)
    for key in sorted(set(fa) | set(fb)):
        ia, ib = fa.get(key) or {}, fb.get(key) or {}
        shared = [o for o in ("schema", "sweep") if o in ia and o in ib]
        if not shared:
            if ia and ib:
                fields_incomparable.append({
                    "key": key,
                    "base_origin": sorted(ia)[0], "target_origin": sorted(ib)[0],
                    "base_count": len(next(iter(ia.values()))),
                    "target_count": len(next(iter(ib.values()))),
                })
            else:
                side = ia or ib
                fields_unknown.append({
                    "key": key, "known_on": base_line if ia else target_line,
                    "origin": sorted(side)[0], "count": len(next(iter(side.values()))),
                })
            continue
        for origin in shared:
            added = sorted(ib[origin] - ia[origin])
            removed = sorted(ia[origin] - ib[origin])
            if added or removed:
                fields_changed.append({
                    "key": key, "origin": origin,
                    "added": added, "removed": removed,
                    "base_count": len(ia[origin]), "target_count": len(ib[origin]),
                })

    return {
        "product": product, "base": base_line, "target": target_line,
        "base_known": bool(a), "target_known": bool(b),
        "endpoints_added": endpoints_added,
        "endpoints_removed": endpoints_removed,
        "endpoints_unknown": endpoints_unknown,
        "fields_changed": fields_changed,
        "fields_unknown": fields_unknown,
        "fields_incomparable": fields_incomparable,
        "totals": {
            "fields_added": sum(len(c["added"]) for c in fields_changed),
            "fields_removed": sum(len(c["removed"]) for c in fields_changed),
        },
    }


# ---------------------------------------------------------------------------
# preflight — the point of all of the above
# ---------------------------------------------------------------------------

STATUS_OK = "ok"
STATUS_UNMEASURED = "unmeasured"
STATUS_ABSENT = "absent"
STATUS_FIELDS_UNKNOWN = "fields_unknown"
STATUS_UNKNOWN_FIELDS = "unknown_fields"


def preflight(product: str, line: str, key: str, keys,
              matrix: dict | None = None) -> dict:
    """Would a payload of ``keys`` for ``key`` be understood on ``line``?

    ``key`` is an endpoint name (sweep evidence) or a provisioning object name
    (schema evidence) — the two namespaces overlap and both are consulted.

    RULE 2: the answer is never a bare boolean. ``unmeasured`` and ``ok`` are
    different answers and the caller must be able to tell them apart, because
    one of them means "go ahead" and the other means "you are about to write
    to a device on the basis of nothing".
    """
    keys = sorted({str(k) for k in (keys or [])})
    matrix = matrix or load(product) or {"lines": {}}
    doc = (matrix.get("lines") or {}).get(line)
    if not doc:
        return {"status": STATUS_UNMEASURED, "line": line, "key": key,
                "unknown": [], "known": [],
                "reason": "no evidence for %s line %s — sweep an appliance on "
                          "that line, or harvest its field schemas, before "
                          "trusting a payload built for another line"
                          % (product, line or "?")}

    ep = (doc.get("endpoints") or {}).get(key)
    obj = (doc.get("objects") or {}).get(key)
    if ep is None and obj is None:
        return {"status": STATUS_UNMEASURED, "line": line, "key": key,
                "unknown": [], "known": [],
                "reason": "%r was never measured on %s" % (key, line)}

    if ep is not None and ep.get("verdict") == VERDICT_ABSENT and not (obj and obj.get("fields")):
        return {"status": STATUS_ABSENT, "line": line, "key": key,
                "unknown": keys, "known": [],
                "reason": "%r is not served by %s (the appliance rejected the "
                          "URN)" % (key, line)}

    known: set = set()
    origins = []
    if obj and obj.get("fields"):
        known |= set(obj["fields"])
        origins.append("schema")
    if ep and ep.get("fields"):
        known |= set(ep["fields"])
        origins.append("sweep")
    if not known:
        return {"status": STATUS_FIELDS_UNKNOWN, "line": line, "key": key,
                "unknown": [], "known": [],
                "reason": "%r exists on %s but no evidence records its fields "
                          "(the endpoint answered with an empty collection)"
                          % (key, line)}

    unknown = [k for k in keys if k not in known]
    return {
        "status": STATUS_UNKNOWN_FIELDS if unknown else STATUS_OK,
        "line": line, "key": key, "origins": origins,
        "unknown": unknown, "known": [k for k in keys if k in known],
        "reason": ("%d field(s) not present on %s: %s"
                   % (len(unknown), line, ", ".join(unknown))) if unknown else "",
    }


def preflight_for_appliance(appliance, key: str, keys) -> dict:
    """``preflight`` with the line taken from the appliance's running firmware."""
    product = _KIND_FOR.get(getattr(appliance, "kind", ""), getattr(appliance, "kind", ""))
    line = firmware_line(getattr(appliance, "fw_version", "") or
                         getattr(appliance, "firmware", ""))
    if not line:
        return {"status": STATUS_UNMEASURED, "line": "", "key": key,
                "unknown": [], "known": [],
                "reason": "%s has no known firmware — SATOM cannot tell which "
                          "API surface it serves" % getattr(appliance, "name", "?")}
    return preflight(product, line, key, keys)


__all__ = [
    "firmware_line", "build", "rebuild", "load", "diff", "preflight",
    "preflight_for_appliance", "matrix_path", "MATRIX_ROOT", "SWEPT_PRODUCTS",
    "STATUS_OK", "STATUS_UNMEASURED", "STATUS_ABSENT", "STATUS_FIELDS_UNKNOWN",
    "STATUS_UNKNOWN_FIELDS",
]
