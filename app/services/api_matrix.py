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
SCHEMA_ROOT = os.path.join(_ROOT, "data", "field_schemas")

#: The in-tree locations, kept as their own names so documentation guards can
#: assert where this data lives WITHOUT reading whatever a test run redirected
#: it to.
REDISCOVERY_ROOT_DEFAULT = os.path.join(_ROOT, "data", "rediscovery")
MATRIX_ROOT_DEFAULT = os.path.join(_ROOT, "data", "api_matrix")

# Redirected by the same env vars ``rediscovery`` honours, resolved at IMPORT so
# the existing monkeypatch-the-constant tests keep working. This is the fix for
# a measured contamination: a sweep driven against the TEST database rebuilt the
# PRODUCTION matrix from the test tree and left ``swept: 0, devices: []`` where
# 326 endpoints and three witnesses had been (2026-09-15). The file is
# untracked, so git reported nothing, and an empty matrix renders as a page
# with no differences rather than as an error.
REDISCOVERY_ROOT = os.environ.get("SATOM_REDISCOVERY_DIR") or REDISCOVERY_ROOT_DEFAULT
MATRIX_ROOT = os.environ.get("SATOM_API_MATRIX_DIR") or MATRIX_ROOT_DEFAULT

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


def firmware_version(version: str | None) -> str:
    """``"8.0.3,build0123"`` → ``"8.0.3"``. The ATOMIC evidence key.

    Delegates to :func:`app.services.firmware_versions.normalize` so the app
    has exactly one definition of what a version string means. Two definitions
    is how ``8.0`` and ``8.0.0`` would end up as separate columns describing
    the same evidence.
    """
    from . import firmware_versions as fv
    return fv.normalize(version)


def resolve_scope(matrix: dict, scope: str) -> tuple:
    """``(doc, kind)`` for a version or line key. ``kind`` is the honest label.

    It NEVER falls back from one kind to the other. A caller that asked about
    ``8.0.3`` and silently got the ``8.0`` rollup is the bug this module spent
    a round removing: the rollup merges builds, and merging is what produced
    *"compatible"* for an endpoint the asking box does not serve.
    """
    if not scope:
        return None, None
    versions = matrix.get("versions") or {}
    lines = matrix.get("lines") or {}
    if scope in versions:
        return versions[scope], "version"
    if scope in lines:
        return lines[scope], "line"
    return None, None


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
    """``{appliance_id: {"name","firmware","version","line"}}`` for live boxes.

    Half of ``data/rediscovery/`` belongs to appliances that were deleted, and
    four more are the retired ``*.invalid`` hosts. A firmware line justified by
    a device nobody can re-probe is a claim nobody can reproduce, so the
    witness list is built from the table and the snapshots are filtered by it.

    ``version`` is the FULL string (``8.0.3``); ``line`` is its rollup. Both
    are carried because they answer different questions and collapsing them is
    what this round exists to undo.
    """
    from ..models import Appliance
    from . import firmware_versions as fv

    kind = _KIND_FOR.get(product, product)
    out: dict = {}
    for ap in Appliance.query.filter_by(kind=kind).all():
        if getattr(ap, "maintenance", False):
            continue
        if str(getattr(ap, "host", "") or "").endswith(".invalid"):
            continue
        raw = getattr(ap, "fw_version", "") or ap.firmware
        out[ap.id] = {"name": ap.name, "firmware": ap.firmware or "",
                      "version": fv.normalize(raw),
                      "line": firmware_line(raw)}
    return out


# ---------------------------------------------------------------------------
# evidence 1 — the sweep
# ---------------------------------------------------------------------------

def _sweep_evidence(product: str, witnesses: dict) -> tuple[dict, list]:
    """``({version: {endpoint: record}}, [note, ...])`` from the snapshot archive.

    The key changed from LINE to FULL VERSION, and that is the whole point of
    this round. Measured on this fleet on 2026-09-15: ``fortiweb16`` and
    ``fortiweb17`` report **8.0.3**, appliance 34 reports **8.0.5**, all three
    were folded into ``8.0``, and the merge rule below is *"OK from any healthy
    witness wins"* — so an endpoint served only by 8.0.5 was attributed to the
    line, and ``preflight`` answered **compatible** for a 8.0.3 box about
    something that box does not serve.

    Evidence is read from ``<id>/by-version/<version>.json`` (every version that
    device was ever swept at) and falls back to ``<id>/_config.json`` for a
    device whose archive has not been backfilled yet. The fallback is a
    fallback, never a merge: when the archive holds the same version, the
    archive wins, because ``_config.json`` is whatever the last sweep left and
    the archive entry is that version's own file.
    """
    from . import firmware_versions as fv

    versions: dict = {}
    notes: list = []
    if not os.path.isdir(REDISCOVERY_ROOT):
        return versions, notes

    for entry in sorted(os.listdir(REDISCOVERY_ROOT)):
        try:
            aid = int(entry)
        except ValueError:
            continue
        wit = witnesses.get(aid)
        if wit is None:
            continue

        snaps: dict = {}
        vdir = os.path.join(REDISCOVERY_ROOT, entry, "by-version")
        if os.path.isdir(vdir):
            for fname in sorted(os.listdir(vdir)):
                if not fname.endswith(".json"):
                    continue
                doc = _read_json(os.path.join(vdir, fname))
                if isinstance(doc, dict):
                    snaps[fname[:-5]] = doc
        latest = _read_json(os.path.join(REDISCOVERY_ROOT, entry, "_config.json"))
        if isinstance(latest, dict):
            v = fv.normalize(latest.get("firmware"))
            if v and v not in snaps:
                snaps[v] = latest
            elif not v and not snaps:
                # A snapshot that never recorded its firmware cannot be filed
                # under a version, and guessing one would credit this evidence
                # to a build nobody measured.
                notes.append({"device": wit["name"],
                              "skipped": "snapshot has no firmware"})

        for version, snap in sorted(snaps.items(), key=lambda kv: fv.sort_key(kv[0])):
            _absorb_snapshot(versions, notes, wit, version, snap)

    return versions, notes


def _absorb_snapshot(versions: dict, notes: list, wit: dict,
                     version: str, snap: dict) -> None:
    """Fold one device-at-one-version snapshot into the version bucket."""
    ledger = snap.get("endpoint_status") or {}
    if not ledger:
        notes.append({"device": wit["name"], "version": version,
                      "skipped": "pre-ledger snapshot"})
        return

    errs = sum(1 for v in ledger.values() if v.get("verdict") == VERDICT_ERROR)
    if errs and errs / max(len(ledger), 1) > MAX_ERROR_RATIO:
        notes.append({"device": wit["name"], "version": version,
                      "line": version.rsplit(".", 1)[0] if version.count(".") > 1 else version,
                      "skipped": "%d/%d endpoints errored — the device is "
                                 "unhealthy, not the catalog" % (errs, len(ledger))})
        return

    at = str(snap.get("generated_at") or "")[:19]
    bucket = versions.setdefault(version, {})

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
        if wit["name"] not in rec["devices"]:
            rec["devices"].append(wit["name"])
        if at > (rec["measured_at"] or ""):
            rec["measured_at"] = at

        # Verdict merge, now WITHIN one version. Two boxes running the same
        # build are genuinely interchangeable evidence; two boxes running
        # different builds are not, and that distinction is what this key
        # change buys.
        if verdict == VERDICT_OK:
            rec["verdict"] = VERDICT_OK
        elif verdict == VERDICT_ABSENT and rec["verdict"] != VERDICT_OK:
            rec["verdict"] = VERDICT_ABSENT
        elif rec["verdict"] is None:
            rec["verdict"] = VERDICT_ERROR

        keys = seen_fields.get(ep_name)
        if keys:
            # RULE 1: only a row with keys creates a field set.
            rec["fields"] = sorted(set(rec["fields"] or []) | keys)


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
    """Derive the whole matrix for one product. Pure read — writes nothing.

    Two axes come out of here and they are not the same kind of thing:

    * ``versions`` — the ATOMIC evidence, one bucket per full firmware version
      (``8.0.3``). Nothing is merged across builds.
    * ``lines`` — the ``major.minor`` ROLLUP. The aggregation argument that
      shaped the first version of this module is still right *for aggregating*;
      what was wrong was aggregating in silence. A rollup now always declares
      ``versions`` it is made of, ``heterogeneous``, and — per endpoint —
      ``attested_on`` / ``silent_on``, so "8.0 serves this" can never again be
      read as "every 8.0.x serves this".
    """
    from . import firmware_versions as fv

    witnesses = _live_appliances(product)
    sweep, notes = _sweep_evidence(product, witnesses)
    schema = _schema_evidence(product)

    # Declarations are NOT baked in here. The file this builds is DERIVED
    # evidence; a declaration is authored data in Postgres, and
    # ``firmware_versions.overlay`` merges the two on read. Persisting one into
    # the other was a measured defect: forgetting a declaration left its row on
    # the page forever, because the next ``load`` read it back out of the file
    # that had captured it. Two stores, one merge point, and the merge point is
    # the reader.
    fleet_versions = sorted({w["version"] for w in witnesses.values() if w["version"]},
                            key=fv.sort_key)
    fleet_lines = sorted({w["line"] for w in witnesses.values() if w["line"]})

    # --- the atomic axis ---------------------------------------------------
    versions: dict = {}
    for version in sorted(sweep, key=fv.sort_key):
        eps = {name: dict(rec) for name, rec in (sweep.get(version) or {}).items()}
        line = fv.line_of(version)
        # Schema evidence is harvested per LINE (``data/field_schemas/<product>/
        # <line>/``), so it cannot be attributed to one build. It is carried
        # here LABELLED ``granularity: line`` rather than dropped — dropping it
        # would make every version look field-blind — and never silently, so a
        # reader can tell a build-level measurement from a line-level one.
        objects = {}
        for obj, rec in (schema.get(line) or {}).items():
            objects[obj] = dict(rec, granularity="line", line=line)
        meta = {"version": version, "line": line,
                "line_only": fv.is_line_only(version),
                "sources": [fv.SOURCE_EVIDENCE], "manual": False,
                "declared": False, "measured": True}
        ok = sum(1 for r in eps.values() if r["verdict"] == VERDICT_OK)
        absent = sum(1 for r in eps.values() if r["verdict"] == VERDICT_ABSENT)
        versions[version] = {
            **meta,
            "version": version, "line": line,
            "in_fleet": version in fleet_versions,
            "measured": bool(eps),
            "devices": sorted({d for r in eps.values() for d in r["devices"]}),
            "endpoints": eps, "objects": objects,
            "counts": {
                "swept": len(eps), "ok": ok, "absent": absent,
                "error": len(eps) - ok - absent,
                "endpoints_with_fields": sum(1 for r in eps.values() if r["fields"]),
                "schema_objects": len(objects),
                "schema_fields": sum(len(r["fields"] or []) for r in objects.values()),
            },
        }

    # --- the rollup --------------------------------------------------------
    all_lines = sorted({fv.line_of(v) for v in versions if fv.line_of(v)} | set(schema))
    lines: dict = {}
    for line in all_lines:
        members = sorted([v for v in versions if fv.line_of(v) == line], key=fv.sort_key)
        measured_members = [v for v in members if versions[v]["measured"]]

        eps: dict = {}
        for version in measured_members:
            for name, rec in versions[version]["endpoints"].items():
                agg = eps.setdefault(name, {
                    "endpoint": name, "urn": rec.get("urn") or "",
                    "section": rec.get("section") or "",
                    "verdict": None, "fields": None, "origin": "sweep",
                    "devices": [], "measured_at": rec.get("measured_at") or "",
                    "attested_on": [], "silent_on": [],
                })
                for d in rec["devices"]:
                    if d not in agg["devices"]:
                        agg["devices"].append(d)
                if (rec.get("measured_at") or "") > (agg["measured_at"] or ""):
                    agg["measured_at"] = rec.get("measured_at") or ""
                if rec["verdict"] == VERDICT_OK:
                    agg["verdict"] = VERDICT_OK
                    agg["attested_on"].append(version)
                else:
                    agg["silent_on"].append(version)
                    if rec["verdict"] == VERDICT_ABSENT and agg["verdict"] != VERDICT_OK:
                        agg["verdict"] = VERDICT_ABSENT
                    elif agg["verdict"] is None:
                        agg["verdict"] = VERDICT_ERROR
                if rec.get("fields"):
                    agg["fields"] = sorted(set(agg["fields"] or []) | set(rec["fields"]))

        # An endpoint attested by SOME but not ALL measured builds of the line
        # is the exact shape of the false positive. It is counted and listed,
        # never folded into "the line serves it".
        partial = [
            {"endpoint": name, "attested_on": r["attested_on"],
             "silent_on": r["silent_on"], "urn": r.get("urn", "")}
            for name, r in sorted(eps.items())
            if r["attested_on"] and r["silent_on"]
        ]

        objects = {obj: dict(rec) for obj, rec in (schema.get(line) or {}).items()}
        ok = sum(1 for r in eps.values() if r["verdict"] == VERDICT_OK)
        absent = sum(1 for r in eps.values() if r["verdict"] == VERDICT_ABSENT)
        lines[line] = {
            "line": line,
            "in_fleet": line in fleet_lines,
            "versions": members,
            "measured_versions": measured_members,
            "declared_versions": [v for v in members if versions[v].get("declared")],
            # A line built from more than one measured build cannot speak for
            # any single one of them without saying so.
            "heterogeneous": len(measured_members) > 1,
            "measured": bool(eps) or bool(objects),
            "devices": sorted({d for r in eps.values() for d in r["devices"]}),
            "endpoints": eps,
            "objects": objects,
            "partial_endpoints": partial,
            "counts": {
                "swept": len(eps), "ok": ok, "absent": absent,
                "error": len(eps) - ok - absent,
                "endpoints_with_fields": sum(1 for r in eps.values() if r["fields"]),
                "schema_objects": len(objects),
                "schema_fields": sum(len(r["fields"] or []) for r in objects.values()),
                "versions": len(members),
                "measured_versions": len(measured_members),
                "partial": len(partial),
            },
        }

    return {
        "product": product,
        "built_at": datetime.utcnow().isoformat(timespec="seconds"),
        "sweepable": product in SWEPT_PRODUCTS,
        "fleet_lines": fleet_lines,
        "fleet_versions": fleet_versions,
        "witnesses": [{"id": k, **v} for k, v in sorted(witnesses.items())],
        "notes": notes,
        "versions": versions,
        "lines": lines,
    }


def rebuild(product: str) -> dict:
    """Build and persist. Returns the matrix."""
    matrix = build(product)
    _write_json_atomic(matrix_path(product), matrix)
    return matrix


def _adapt_pre_version(doc: dict) -> dict:
    """Make a line-only matrix (written before 2026-09-16) safe to read.

    It is deliberately NOT rebuilt here. ``build`` filters witnesses through
    the live appliance table, so a rebuild silently drops every line whose
    witnesses have since been deleted — ``fortiadc``'s whole 8.0 line is in
    that position today. Destroying evidence as a side effect of somebody
    opening a page is not an upgrade path.

    So the old document is served as-is, with an empty version axis and
    ``stale_format`` set. The page can then say "rebuild me" and
    :func:`preflight` can refuse to answer a BUILD-scoped question out of
    LINE-scoped data — which is the whole point of the round that introduced
    the axis.
    """
    doc = dict(doc, versions={}, fleet_versions=[], stale_format=True)
    for ln in (doc.get("lines") or {}).values():
        ln.setdefault("versions", [])
        ln.setdefault("measured_versions", [])
        ln.setdefault("declared_versions", [])
        ln.setdefault("heterogeneous", False)
        ln.setdefault("partial_endpoints", [])
        ln.setdefault("measured", True)
        counts = ln.setdefault("counts", {})
        counts.setdefault("partial", 0)
        counts.setdefault("versions", 0)
        counts.setdefault("measured_versions", 0)
    return doc


def load(product: str, rebuild_if_missing: bool = True) -> dict | None:
    """The stored matrix, rebuilt on first access when absent."""
    doc = _read_json(matrix_path(product))
    if isinstance(doc, dict) and doc.get("product") == product:
        if "versions" not in doc:
            return _adapt_pre_version(doc)
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

    Both arguments may name a full version (``8.0.3``) or a line (``8.0``);
    :func:`resolve_scope` decides which, and the answer reports ``base_kind`` /
    ``target_kind`` so a reader is never left guessing whether a difference was
    measured between two builds or between two merged rollups.

    Every bucket here is separated by WHY, because "8.0 has a field 7.6 does
    not" and "nobody ever measured that endpoint on 7.6" look identical in a
    naive set difference and mean opposite things to whoever is about to write
    a payload.
    """
    matrix = matrix or load(product) or {"lines": {}, "versions": {}}
    a, a_kind = resolve_scope(matrix, base_line)
    b, b_kind = resolve_scope(matrix, target_line)
    a = a or {}
    b = b or {}
    a_eps, b_eps = a.get("endpoints") or {}, b.get("endpoints") or {}
    a_obj, b_obj = a.get("objects") or {}, b.get("objects") or {}

    def _served(rec):
        return bool(rec) and rec.get("verdict") == VERDICT_OK

    def _urn(key):
        """The REST path for a key, or ``""`` when the key is not an endpoint.

        The comparison renders ONE table since 2026-09-16, so a field-delta row
        now sits beside an endpoint row and offers the same Test button. That
        button needs a URN and only ENDPOINT evidence carries one: a key that
        reached this function from the harvested OBJECT schemas has no REST
        path of its own. It gets an empty string, which renders no button at
        all — fabricating a plausible path would put a control on the page that
        cannot work and, worse, would assert that the path exists.

        The target side is asked first: it is the build being written to.
        """
        for src in (b_eps, a_eps):
            rec = src.get(key)
            if rec and rec.get("urn"):
                return rec["urn"]
        return ""

    def _origin(*recs):
        """The evidence kind a record was BUILT with, never one inferred here.

        The comparison grows an *Evidence* column on 2026-09-16 and it has to
        answer for endpoint rows too, not only for field rows. The template
        must not be the one to decide: hardcoding ``sweep`` in its endpoint
        loops would print a kind for a record that never carried one, which is
        the same class of fabrication as inventing a URN for a schema object.
        Every endpoint record gets ``origin`` at build time (``"sweep"``) and
        every object record gets ``"schema"``; a record from an older matrix
        that carries neither yields ``""`` and the page says so rather than
        guessing.
        """
        for rec in recs:
            if rec and rec.get("origin"):
                return rec["origin"]
        return ""

    endpoints_added, endpoints_removed, endpoints_unknown = [], [], []
    for name in sorted(set(a_eps) | set(b_eps)):
        ra, rb = a_eps.get(name), b_eps.get(name)
        if ra is None or rb is None:
            # RULE 3: not measured on one side is UNKNOWN, not a change.
            endpoints_unknown.append({"endpoint": name, "urn": _urn(name),
                                      "origin": _origin(ra, rb),
                                      "measured_on": base_line if ra else target_line})
            continue
        if _served(rb) and not _served(ra) and ra.get("verdict") == VERDICT_ABSENT:
            endpoints_added.append({"endpoint": name, "urn": rb.get("urn", ""),
                                    "origin": _origin(rb, ra),
                                    "attested_on": rb.get("attested_on") or [],
                                    "silent_on": rb.get("silent_on") or []})
        elif _served(ra) and not _served(rb) and rb.get("verdict") == VERDICT_ABSENT:
            endpoints_removed.append({"endpoint": name, "urn": ra.get("urn", ""),
                                      "origin": _origin(ra, rb),
                                      "attested_on": ra.get("attested_on") or [],
                                      "silent_on": ra.get("silent_on") or []})

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
                    "key": key, "urn": _urn(key),
                    "base_origin": sorted(ia)[0], "target_origin": sorted(ib)[0],
                    "base_count": len(next(iter(ia.values()))),
                    "target_count": len(next(iter(ib.values()))),
                })
            else:
                side = ia or ib
                fields_unknown.append({
                    "key": key, "urn": _urn(key),
                    "known_on": base_line if ia else target_line,
                    "origin": sorted(side)[0], "count": len(next(iter(side.values()))),
                })
            continue
        for origin in shared:
            added = sorted(ib[origin] - ia[origin])
            removed = sorted(ia[origin] - ib[origin])
            if added or removed:
                fields_changed.append({
                    "key": key, "urn": _urn(key), "origin": origin,
                    "added": added, "removed": removed,
                    "base_count": len(ia[origin]), "target_count": len(ib[origin]),
                })

    # A delta computed between two ROLLUPS carries every build each rollup
    # merged. Without it "8.0 adds X" is unfalsifiable: the reader cannot tell
    # whether X was seen on one build or on all of them.
    return {
        "product": product, "base": base_line, "target": target_line,
        "base_kind": a_kind, "target_kind": b_kind,
        "base_known": bool(a), "target_known": bool(b),
        "base_versions": a.get("measured_versions") or ([base_line] if a_kind == "version" else []),
        "target_versions": b.get("measured_versions") or ([target_line] if b_kind == "version" else []),
        "base_heterogeneous": bool(a.get("heterogeneous")),
        "target_heterogeneous": bool(b.get("heterogeneous")),
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
#: The caller asked about a BUILD nobody measured. Deliberately not folded into
#: ``unmeasured``: that word also covers "this product has no evidence at all",
#: and the two demand different next actions — one needs any sweep, the other
#: needs a sweep of THAT build while its siblings already have one.
STATUS_VERSION_UNMEASURED = "version_unmeasured"


def _answer(doc: dict, kind: str, scope: str, key: str, keys: list) -> dict:
    """The verdict for one already-resolved scope. Never resolves anything."""
    base = {"status": None, "line": scope, "scope": scope, "scope_kind": kind,
            "key": key, "unknown": [], "known": []}
    if kind == "line":
        base["rollup"] = True
        base["rollup_versions"] = doc.get("measured_versions") or []
        base["heterogeneous"] = bool(doc.get("heterogeneous"))

    ep = (doc.get("endpoints") or {}).get(key)
    obj = (doc.get("objects") or {}).get(key)
    if ep is None and obj is None:
        return {**base, "status": STATUS_UNMEASURED,
                "reason": "%r was never measured on %s" % (key, scope)}

    if ep is not None:
        # A rollup answer that rests on SOME of its builds says which. The
        # caller is about to write to one specific box, and "the line serves
        # it" is not the same claim as "the build you are writing to serves
        # it" — folding them is the false positive this module was rebuilt to
        # remove.
        if ep.get("attested_on") is not None:
            base["attested_on"] = ep.get("attested_on") or []
            base["silent_on"] = ep.get("silent_on") or []
            base["partial"] = bool(base["attested_on"] and base["silent_on"])

    if ep is not None and ep.get("verdict") == VERDICT_ABSENT and not (obj and obj.get("fields")):
        return {**base, "status": STATUS_ABSENT, "unknown": keys,
                "reason": "%r is not served by %s (the appliance rejected the "
                          "URN)" % (key, scope)}

    known: set = set()
    origins = []
    line_granular = []
    if obj and obj.get("fields"):
        known |= set(obj["fields"])
        origins.append("schema")
        # Field schemas are harvested per LINE, so on a VERSION scope they are
        # the weaker claim. Labelled rather than dropped: dropping would make
        # every build look field-blind, and silence would make a line-granular
        # fact read as a build-granular one.
        if kind == "version" and obj.get("granularity") == "line":
            line_granular.append("schema")
    if ep and ep.get("fields"):
        known |= set(ep["fields"])
        origins.append("sweep")
    if not known:
        return {**base, "status": STATUS_FIELDS_UNKNOWN, "origins": origins,
                "reason": "%r exists on %s but no evidence records its fields "
                          "(the endpoint answered with an empty collection)"
                          % (key, scope)}

    unknown = [k for k in keys if k not in known]
    return {
        **base,
        "status": STATUS_UNKNOWN_FIELDS if unknown else STATUS_OK,
        "origins": origins, "line_granular_origins": line_granular,
        "unknown": unknown, "known": [k for k in keys if k in known],
        "reason": ("%d field(s) not present on %s: %s"
                   % (len(unknown), scope, ", ".join(unknown))) if unknown else "",
    }


def preflight(product: str, line: str, key: str, keys,
              matrix: dict | None = None) -> dict:
    """Would a payload of ``keys`` for ``key`` be understood on ``line``?

    ``line`` may name a full firmware version (``8.0.3``) or a line (``8.0``).
    ``key`` is an endpoint name (sweep evidence) or a provisioning object name
    (schema evidence) — the two namespaces overlap and both are consulted.

    RULE 2: the answer is never a bare boolean. ``unmeasured`` and ``ok`` are
    different answers and the caller must be able to tell them apart, because
    one of them means "go ahead" and the other means "you are about to write
    to a device on the basis of nothing".

    RULE 4, added this round: **a version with no evidence is never answered
    from its line.** ``8.0.5`` is not ``8.0.3``, the fleet holds both, and the
    old code merged them — so an endpoint measured only on 8.0.3 came back
    ``ok`` for a 8.0.5 box. The new answer is ``version_unmeasured``, and it
    **carries the line-granular answer beside it, labelled**, rather than
    withholding it: a refusal that hides what IS known is how a correct guard
    gets routed around.
    """
    from . import firmware_versions as fv

    keys = sorted({str(k) for k in (keys or [])})
    matrix = matrix or load(product) or {"lines": {}, "versions": {}}
    doc, kind = resolve_scope(matrix, line)

    if doc is not None:
        return _answer(doc, kind, line, key, keys)

    if line and not fv.is_line_only(line):
        parent = fv.line_of(line)
        ldoc = (matrix.get("lines") or {}).get(parent)
        if ldoc:
            siblings = ldoc.get("measured_versions") or []
            stale = (" The stored matrix predates version indexing — rebuild "
                     "it before reading this as a fact about %s."
                     % parent) if matrix.get("stale_format") else ""
            return {
                "status": STATUS_VERSION_UNMEASURED, "line": line, "scope": line,
                "stale_format": bool(matrix.get("stale_format")),
                "scope_kind": "version", "key": key, "unknown": [], "known": [],
                "measured_siblings": siblings, "rollup_line": parent,
                "line_answer": _answer(ldoc, "line", parent, key, keys),
                "reason": "%s has no evidence of its own. The %s line was "
                          "measured on %s — what those builds serve is not "
                          "proof about this one. The line-granular answer is "
                          "reported beside this one, labelled."
                          % (line, parent, ", ".join(siblings) or "nothing") + stale,
            }

    return {"status": STATUS_UNMEASURED, "line": line, "scope": line,
            "scope_kind": None, "key": key, "unknown": [], "known": [],
            "reason": "no evidence for %s %s — sweep an appliance on "
                      "that version, or harvest its field schemas, before "
                      "trusting a payload built for another one"
                      % (product, line or "?")}


def preflight_for_appliance(appliance, key: str, keys) -> dict:
    """``preflight`` scoped to the appliance's EXACT running firmware.

    The full version, not the line. This is the call site the false positive
    came out of: the box reports ``8.0.3``, the line rollup held evidence from
    ``8.0.5``, and the merge answered ``ok``.
    """
    from . import firmware_versions as fv

    product = _KIND_FOR.get(getattr(appliance, "kind", ""), getattr(appliance, "kind", ""))
    raw = (getattr(appliance, "fw_version", "") or
           getattr(appliance, "firmware", ""))
    version = fv.normalize(raw)
    if not version:
        return {"status": STATUS_UNMEASURED, "line": "", "scope": "",
                "scope_kind": None, "key": key, "unknown": [], "known": [],
                "reason": "%s has no known firmware — SATOM cannot tell which "
                          "API surface it serves" % getattr(appliance, "name", "?")}
    return preflight(product, version, key, keys)


__all__ = [
    "firmware_line", "firmware_version", "resolve_scope", "build", "rebuild",
    "load", "diff", "preflight", "preflight_for_appliance", "matrix_path",
    "MATRIX_ROOT", "MATRIX_ROOT_DEFAULT", "REDISCOVERY_ROOT_DEFAULT",
    "SWEPT_PRODUCTS", "STATUS_OK", "STATUS_UNMEASURED", "STATUS_ABSENT",
    "STATUS_FIELDS_UNKNOWN", "STATUS_UNKNOWN_FIELDS",
    "STATUS_VERSION_UNMEASURED",
]
