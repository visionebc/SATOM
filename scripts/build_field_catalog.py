"""Offline harvester: build per-(product,line) field schemas for guided provisioning.

Authoritative source = a LIVE GET from a reference appliance of that line
(exact field names + value-inferred types). Enrichment = Firecrawl of the
FortiWeb CLI-reference docs (labels / help / enum options) — wired as the
extension hook, gated by ``FIRECRAWL_ENRICH=1`` and never fatal. Writes
``data/field_schemas/<product>/<line>/<object>.json`` plus a ``_default``
fallback. Idempotent and non-destructive: existing files are preserved (so
hand-curated seeds survive); pass ``--force`` to overwrite. NOT run at request
time.

Usage (on the primary node, repo root, venv):
    set -a && . ./.env && set +a
    PYTHONPATH=. venv/bin/python -m scripts.build_field_catalog --product fortiweb
    # add --force to regenerate existing schema files
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone

from app.services import field_catalog as fc
from app.services import provisioning as prov

# (line, appliance-name) reference sources, read from the environment because a
# reference appliance is an estate fact, not a property of the tool. Same rule as
# FIRECRAWL below: no default, so a checkout carries no one's device roster and a
# run against the wrong box is impossible rather than merely unlikely.
#   SATOM_FIELD_CATALOG_SOURCES="fortiweb=8.0:<appliance>,7.6:<appliance>"
def _sources_from_env() -> dict[str, list[tuple[str, str]]]:
    raw = os.environ.get("SATOM_FIELD_CATALOG_SOURCES", "").strip()
    out: dict[str, list[tuple[str, str]]] = {}
    for chunk in filter(None, (c.strip() for c in raw.split(";"))):
        product, _, rows = chunk.partition("=")
        pairs = []
        for row in filter(None, (r.strip() for r in rows.split(","))):
            line, _, name = row.partition(":")
            if line.strip() and name.strip():
                pairs.append((line.strip(), name.strip()))
        if product.strip() and pairs:
            out[product.strip()] = pairs
    return out


SOURCES = _sources_from_env()

# Firecrawl (optional, no auth). Enrichment is opt-in (gated) to keep the
# harvest fast, and the endpoint has no default: set FIRECRAWL_URL to use it.
FIRECRAWL = os.environ.get("FIRECRAWL_URL", "")

# Fields known to be mandatory that a bare GET can't tell us are required.
REQUIRED_HINTS = {"dns": {"primary"}, "ntp": {"mode"}}

_READONLY_EXACT = {"_id", "systemTime", "time"}


def is_readonly_name(name: str) -> bool:
    return name in _READONLY_EXACT or name.endswith("_val")


def fields_from_live_object(live: dict) -> list:
    """Field dicts from a live cmdb object: skip readonly/_val/_id; infer types.

    An int/str field that has a sibling ``<name>_val`` is an enum => ``bool``
    when the companion reads enable/disable, else ``select`` (options unknown
    here, filled by docs)."""
    out = []
    for name, value in live.items():
        if is_readonly_name(name):
            continue
        ftype = fc.infer_type(value)
        companion = live.get(f"{name}_val")
        if companion is not None and ftype in ("number", "text"):
            ftype = "bool" if str(companion).lower() in ("enable", "disable") else "select"
        out.append({
            "name": name, "label": name.replace("-", " ").replace("_", " ").title(),
            "type": ftype, "required": False, "default": "",
            "help": "", "group": "Basic", "options": [],
        })
    return out


def merge_doc(fields: list, doc: dict) -> list:
    """Overlay doc-sourced label/help/options onto live-derived fields."""
    for f in fields:
        d = doc.get(f["name"])
        if not d:
            continue
        if d.get("label"):
            f["label"] = d["label"]
        if d.get("help"):
            f["help"] = d["help"]
        if d.get("options"):
            f["options"] = d["options"]
            if f["type"] in ("text", "number"):
                f["type"] = "select"
    return fields


def firecrawl_doc(obj_key: str) -> dict:
    """Best-effort field metadata from FortiWeb docs. Returns {} on any failure.

    Gated by FIRECRAWL_ENRICH (off by default). The markdown->{field:{label,
    help,options}} parser is the documented extension point; today it returns {}
    so the live GET stays authoritative."""
    if not os.environ.get("FIRECRAWL_ENRICH"):
        return {}
    try:
        import httpx
        url = "https://docs.fortinet.com/document/fortiweb/8.0.0/cli-reference"
        r = httpx.post(f"{FIRECRAWL}/v1/scrape",
                       json={"url": url, "formats": ["markdown"]}, timeout=40)
        if r.status_code != 200:
            return {}
        # TODO: parse the object's field table out of the markdown. Live GET
        # already yields correct names+types, so {} still gives a usable schema.
        return {}
    except Exception:
        return {}


def _live_object(appliance, endpoint_urn: str) -> dict:
    return appliance.build_client()._safe_one(endpoint_urn)


#: What the last harvest managed for one object on one line. These are DATA,
#: not log lines, and that is the whole point of them: the comparison page
#: prints ``not measured on 8.0.5`` for an object with no schema, and an
#: operator who has just finished a sweep reads that as the sweep having
#: failed. It did not — schema evidence comes from a HARVEST, and until
#: 2026-09-17 the reason a harvest skipped an object was printed to a terminal
#: nobody kept and then thrown away. Recorded, every future line answers "why"
#: on the page instead of costing a session to rediscover.
STATUS_HARVESTED = "harvested"
STATUS_KEPT = "kept"
#: A schema file EXISTS but this run could not re-derive it — the reference box
#: has that table empty today, or rejected the URN. It is still coverage: the
#: page has fields to show. Folding it into ``kept`` would assert a freshness
#: this run did not establish; folding it into a hole would call an artefact
#: with five measured fields "not measured", which is the exact misreading this
#: whole record exists to end.
STATUS_KEPT_UNVERIFIED = "kept_unverified"
STATUS_EMPTY_TABLE = "empty_table"
STATUS_URN_REJECTED = "urn_rejected"
STATUS_TRANSPORT = "transport_error"
STATUS_NO_REGISTRY = "not_in_registry"
STATUS_UNRECOGNISED = "unrecognised_envelope"

#: One sentence per status, written for the OPERATOR reading the comparison
#: page rather than for whoever ran the harvest. Each says what the hole is
#: and, where it is fixable, what would fix it — a reason that stops at
#: "no schema" is the same dead end as no reason at all.
COVERAGE_REASON = {
    STATUS_KEPT_UNVERIFIED:
        "A schema for this object exists on this line, harvested on an earlier run "
        "(the file's own source and date are the truth about it). THIS run could not "
        "re-derive it: the current reference appliance has nothing to describe here.",
    STATUS_EMPTY_TABLE:
        "No schema harvested: the table is EMPTY on the reference appliance, so a "
        "live GET had no fields to describe. That is a fact about how that box is "
        "configured, NOT about the firmware — configure one row on a reference "
        "appliance of this line and re-run the harvest.",
    STATUS_URN_REJECTED:
        "No schema harvested: the reference appliance REJECTED the URN. Either this "
        "build does not serve the object, or the registry path is wrong for this "
        "line. The rejection on its own does not say which, and this file does not "
        "guess.",
    STATUS_TRANSPORT:
        "No schema harvested: the reference appliance could not be reached during "
        "the harvest. Nothing was learned about the object either way.",
    STATUS_NO_REGISTRY:
        "No schema harvested: this object has no endpoint in the registry, so there "
        "is no path to GET.",
    STATUS_UNRECOGNISED:
        "No schema harvested: the appliance answered in a shape this harvester does "
        "not recognise.",
}

#: Written into the line directory beside the schemas. Underscore-prefixed
#: because ``api_matrix._schema_evidence`` reads that directory as "one file per
#: object" — the prefix is the convention that keeps a bookkeeping file from
#: being read as an object, and that reader now enforces it rather than relying
#: on this file happening to lack an ``object`` key.
COVERAGE_FILENAME = "_coverage.json"


def classify_empty(appliance, endpoint_urn: str) -> tuple:
    """``(status, detail)`` for an empty harvest.

    ``_safe_one`` returns {} both for a table the operator has not populated and
    for a URN the device rejects — opposite situations: one is benign and
    self-healing, the other means this build does not answer under that path.
    Best-effort: never raises, and an unknown reason is treated as the benign
    case by the caller.

    It used to report a rejection as a defect in the registry entry. On
    2026-09-17 that turned out to over-claim in the other direction:
    ``user_group`` is rejected by 8.0.5 and served by 7.6.8 under the SAME path,
    which is equally consistent with the object having been dropped from the
    newer build. The rejection is reported; which of the two it is, is not
    invented here.
    """
    try:
        body = appliance.build_client().api_call("GET", endpoint_urn).json()
    except Exception as exc:  # noqa: BLE001 — diagnosis must not break the harvest
        return STATUS_TRANSPORT, "transport error (%s)" % type(exc).__name__
    if isinstance(body, dict) and body.get("errcode") not in (None, 0, "0"):
        return STATUS_URN_REJECTED, "errcode=%s %r" % (
            body.get("errcode"), str(body.get("message"))[:60])
    rows = body.get("results") if isinstance(body, dict) else body
    if isinstance(rows, list) and not rows:
        return STATUS_EMPTY_TABLE, "the table has no rows on this device"
    return STATUS_UNRECOGNISED, "envelope: %s" % (
        list(body)[:6] if isinstance(body, dict) else type(body).__name__)


def why_empty(appliance, endpoint_urn: str) -> str:
    """The one-line form of :func:`classify_empty`, for the run's stdout."""
    status, detail = classify_empty(appliance, endpoint_urn)
    return "%s — %s" % (status, detail)


def schema_path(product: str, line: str, key: str) -> str:
    return os.path.join(fc.SCHEMA_ROOT, product, line, f"{key}.json")


def _no_evidence(product: str, line: str, key: str, status: str, detail: str) -> dict:
    """Classify a skip against WHAT IS ON DISK, not against this run alone.

    An object this run could not harvest may still have a schema from an
    earlier one — line 7.6 holds five such files, harvested from a box that had
    those tables populated. Reporting them as holes would have the page print
    "no schema on 7.6" next to a row showing that schema's fields.
    """
    if os.path.exists(schema_path(product, line, key)):
        return {"status": STATUS_KEPT_UNVERIFIED,
                "detail": f"{status}: {detail} — the existing schema file stands"}
    return {"status": status, "detail": detail}


def write_coverage(product: str, line: str, payload: dict) -> str:
    """Record THIS run's coverage for one line. Always overwrites.

    Unlike a schema file, coverage is not an artefact to preserve: it is the
    report of the most recent harvest, and a kept-from-June coverage file
    describing a September run would assert holes that may no longer exist.
    A line whose harvest never ran writes nothing at all — "no record" and
    "recorded as complete" are the pair this file exists to keep apart.
    """
    path = os.path.join(fc.SCHEMA_ROOT, product, line, COVERAGE_FILENAME)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(payload, fh, indent=2)
    os.replace(tmp, path)
    return path


def device_firmware(appliance) -> str:
    """The firmware the device actually reports (e.g. "7.6.8"), or "" if unknown.

    Best-effort: an unreadable version must not block a harvest, it only means the
    line cannot be verified (and the caller says so out loud rather than assuming
    agreement)."""
    import re as _re
    try:
        status = appliance.build_client().status_check()
    except Exception:  # noqa: BLE001 — an unverifiable line is not a fatal one
        return ""
    m = _re.search(r"(\d+\.\d+\.\d+)", str(status))
    return m.group(1) if m else ""


def line_matches_firmware(line: str, firmware: str) -> bool:
    """Does ``firmware`` belong to catalog ``line``? ("7.6.8" -> "7.6" yes.)

    An unknown firmware matches everything: the harvest degrades to today's
    behaviour rather than refusing to run against a box it cannot interrogate."""
    if not firmware or not line:
        return True
    return firmware == line or firmware.startswith(line + ".")


def _write_if(path: str, payload: dict, force: bool) -> bool:
    if os.path.exists(path) and not force:
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)
    return True


def build(product: str = "fortiweb", force: bool = False,
          allow_mismatch: bool = False) -> None:
    from app.models import Appliance
    from app.registry import loader

    reg = loader.load_registry()
    # One instant for the whole run: objects harvested in the same pass
    # must not disagree about when the pass happened.
    harvested_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    specs = prov.PROVISION_CATALOG
    default_written: set = set()
    rows = SOURCES.get(product, [])
    if not rows:
        raise SystemExit(
            "no reference appliance for %r: set SATOM_FIELD_CATALOG_SOURCES, e.g.\n"
            '  SATOM_FIELD_CATALOG_SOURCES="%s=8.0:<appliance-name>"' % (product, product))
    for line, appliance_name in rows:
        appliance = Appliance.query.filter_by(name=appliance_name).first()
        if appliance is None:
            print(f"! {appliance_name} not registered — skipping line {line}")
            continue
        # Coverage for THIS line, filled per object below. Declared here so an
        # object that never reaches the write path cannot silently vanish from
        # the record: every spec in the catalog gets an entry or the run did
        # not happen for that line at all.
        coverage: dict = {}
        firmware = device_firmware(appliance)
        if not line_matches_firmware(line, firmware):
            print(f"!! line {line} via {appliance_name}: the device runs {firmware}, "
                  f"NOT a {line} build — refusing to file {firmware} fields as {line}. "
                  f"Use --allow-line-mismatch to override.")
            if not allow_mismatch:
                continue
            print(f"   (overridden: harvesting {firmware} data into line {line})")
        print(f"== line {line} via {appliance_name}"
              f"{f' [{firmware}]' if firmware else ' [firmware unknown]'} ==")
        for spec in specs:
            urn = reg.get(spec.endpoint or "")
            if not urn:
                print(f"  - {spec.key}: endpoint {spec.endpoint!r} not in registry, skip")
                coverage[spec.key] = _no_evidence(
                    product, line, spec.key, STATUS_NO_REGISTRY,
                    f"no endpoint {spec.endpoint!r} in the registry")
                continue
            try:
                live = _live_object(appliance, urn)
            except Exception as exc:
                print(f"  - {spec.key}@{line}: live GET failed ({type(exc).__name__}); skip")
                coverage[spec.key] = _no_evidence(
                    product, line, spec.key, STATUS_TRANSPORT,
                    f"live GET failed ({type(exc).__name__})")
                continue
            if not live:
                status, detail = classify_empty(appliance, urn)
                coverage[spec.key] = _no_evidence(product, line, spec.key, status, detail)
                print(f"  - {spec.key}@{line}: {coverage[spec.key]['status']} — {detail}; skip")
                continue
            fields = merge_doc(fields_from_live_object(live), firecrawl_doc(spec.key))
            req = REQUIRED_HINTS.get(spec.key, set())
            for f in fields:
                f["required"] = f["name"] in req
            readonly = [k for k in live if is_readonly_name(k)]
            schema = {
                "object": spec.key, "endpoint": spec.endpoint, "label": spec.label,
                "product": product, "line": line, "singleton": spec.singleton,
                "readonly": readonly, "fields": fields,
                "source": f"live:{appliance_name}@{line}", "generated_at": harvested_at,
                # What the box ACTUALLY runs, so a later reader can tell a
                # verified line from an asserted one.
                "device_firmware": firmware,
                "line_mismatch": not line_matches_firmware(line, firmware),
            }
            wrote = _write_if(os.path.join(fc.SCHEMA_ROOT, product, line, f"{spec.key}.json"),
                              schema, force)
            print(f"  {'+' if wrote else '=' } {spec.key}@{line} ({len(fields)} fields)"
                  f"{'' if wrote else ' [kept existing]'}")
            # A KEPT file is not the same claim as a harvested one: its fields
            # were measured on some earlier run, possibly against another box,
            # and the file's own ``source``/``generated_at`` remain the truth
            # about it. Flattening the two would let a coverage report assert a
            # freshness this run never established.
            coverage[spec.key] = {
                "status": STATUS_HARVESTED if wrote else STATUS_KEPT,
                "detail": f"{len(fields)} field(s)", "fields": len(fields)}
            if spec.key not in default_written:
                d = dict(schema, line="_default", source=f"default<-{appliance_name}@{line}")
                _write_if(os.path.join(fc.SCHEMA_ROOT, product, "_default", f"{spec.key}.json"),
                          d, force)
                default_written.add(spec.key)
        for key, rec in coverage.items():
            rec["reason"] = COVERAGE_REASON.get(rec["status"], "")
        missing = [k for k, r in coverage.items()
                   if r["status"] not in (STATUS_HARVESTED, STATUS_KEPT,
                                          STATUS_KEPT_UNVERIFIED)]
        path = write_coverage(product, line, {
            "product": product, "line": line, "appliance": appliance_name,
            "device_firmware": firmware,
            "line_mismatch": not line_matches_firmware(line, firmware),
            "harvested_at": harvested_at,
            "catalog_size": len(specs), "covered": len(specs) - len(missing),
            "objects": coverage,
        })
        print(f"  -> coverage: {len(specs) - len(missing)}/{len(specs)} object(s) "
              f"have a schema on {line}; wrote {os.path.relpath(path, os.getcwd())}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--product", default="fortiweb")
    ap.add_argument("--force", action="store_true", help="overwrite existing schema files")
    ap.add_argument("--allow-line-mismatch", action="store_true",
                    help="harvest even when the device firmware does not belong "
                         "to the declared line (recorded in the artefact)")
    args = ap.parse_args()
    from app import create_app
    app = create_app()
    with app.app_context():
        print(f"Building field catalog for product={args.product} (force={args.force}) …")
        build(args.product, force=args.force,
              allow_mismatch=args.allow_line_mismatch)
    print("Done.")


if __name__ == "__main__":
    main()
