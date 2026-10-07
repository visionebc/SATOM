"""Endpoint baselines — the registry's seed, pinned to a firmware build.

Until 2.3 the endpoint registry (``registry_endpoints``) was seeded at boot
from four hand-written files at the repository root (``endpoints.yaml``,
``endpoints_fortiadc.yaml``, ``endpoints_fortianalyzer.yaml``,
``endpoints_fortiauthenticator.yaml``). They said nothing about WHICH firmware
they described, nobody regenerated them from what the appliances actually
served, and the insert-only seed could add a name but never correct one. A seed
like that goes stale by construction.

A baseline replaces them. Contract (``docs/api-library.md`` §9):

* **Pinned to a build.** A baseline is "the endpoint catalog of FortiWeb
  7.6.8", not "the FortiWeb catalog". ``api_version`` is the protocol
  (``v2.0``/``v1``/``jsonrpc``) and is recorded separately.
* **Promoted from measurements.** :func:`plan_promotion` takes what the API
  library measured on that build: measured-and-served names come in with the
  URN the evidence carries, names the build measured ABSENT go out, and names
  the build has no evidence about are carried from the previous baseline and
  say so. A build nobody measured cannot be promoted.
* **Sealed and shipped.** The promoted baseline is exported to
  ``app/registry/baselines/<product>.json`` with a SHA-256 over its content.
  The app refuses an artifact whose seal does not match, so the file cannot be
  maintained by hand the way the YAML was.
* **Applied at boot.** A fresh installation builds its schema with
  ``db.create_all()`` and never runs alembic, so the data cannot travel as a
  migration. :func:`boot` inserts the shipped baseline (insert-only, keyed by
  its hash) and reconciles the registry to the active one.
* **Operators still win.** The registry keeps one row per name. A row the
  baseline wrote carries ``updated_by = "baseline:<product>@<version>"`` (or
  the legacy ``"seed"``); a row an operator edited or disabled carries their
  name, and no baseline ever touches it again.

:func:`resolve_at` answers the per-build question — which URN, and on what
authority, does ``name`` resolve to on build X — and :func:`check` runs it over
the live fleet so drift between the registry, the baseline and the evidence is
reported instead of discovered. The services resolve per build through
``registry.loader.resolve_for`` / ``registry_for`` (same authority order,
without the baseline-assumption step: the registry already serves it).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime

from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models_apilib import ApiLibBaseline, ApiLibBaselineEntry
from . import firmware_versions as fv

log = logging.getLogger(__name__)

FORMAT = 1

PROV_MEASURED = "measured"
PROV_CARRIED = "carried"
PROV_LEGACY = "legacy"
PROV_CONTRADICTED = "contradicted"
PROVENANCES = (PROV_MEASURED, PROV_CARRIED, PROV_LEGACY, PROV_CONTRADICTED)

METHOD_PROMOTED = "promoted"
METHOD_ADOPTED = "adopted"

#: ``updated_by`` of a registry row the baseline owns. Anything else is an
#: operator's row and is never touched.
OWNER_PREFIX = "baseline:"
#: What the retired YAML seeder wrote. Same ownership: those rows were the seed.
LEGACY_OWNER = "seed"

STATUS_OVERRIDE = "override"
STATUS_DISABLED = "disabled"
STATUS_MEASURED = "measured"
STATUS_ABSENT = "absent"
STATUS_BASELINE = "baseline"
STATUS_UNMEASURED = "unmeasured"

ARTIFACT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "registry", "baselines")


def products() -> tuple:
    """The products whose registry is built from a baseline.

    The loader's ``API_VERSION`` is the one list of registry products; a
    catalog-only product (FortiGate) has library data but no registry.
    """
    from ..registry.loader import API_VERSION
    return tuple(API_VERSION)


def api_version_of(product: str) -> str:
    from ..registry.loader import API_VERSION
    return API_VERSION[product]


def owner_tag(product: str, version: str) -> str:
    return "%s%s@%s" % (OWNER_PREFIX, product, version)


def is_owned(updated_by) -> bool:
    """True when the registry row was written by a seed, not by a person."""
    tag = updated_by or ""
    return tag == LEGACY_OWNER or tag.startswith(OWNER_PREFIX)


def _now() -> datetime:
    return datetime.utcnow().replace(microsecond=0)


# ---------------------------------------------------------------------------
# seal + artifact
# ---------------------------------------------------------------------------

def _entry_tuple(e) -> list:
    if isinstance(e, dict):
        return [e["name"], e["urn"], e.get("provenance") or PROV_MEASURED,
                e.get("measured_on") or ""]
    return [e.name, e.urn, e.provenance, e.measured_on or ""]


def seal(product: str, version: str, api_version: str, entries) -> str:
    """SHA-256 over what the baseline SAYS — not when or by whom it was said.

    Same content promoted twice is one row. The timestamps and the note are
    outside the hash on purpose (the ``VOLATILE_KEYS`` lesson from the SoT
    store: hash a timestamp and dedup is gone).
    """
    body = {
        "product": product, "version": version, "api_version": api_version,
        "entries": sorted(_entry_tuple(e) for e in entries),
    }
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def artifact_path(product: str, directory: str | None = None) -> str:
    return os.path.join(directory or ARTIFACT_DIR, "%s.json" % product)


def render_artifact(doc: dict) -> str:
    """One entry per line, so a promotion reads as a clean ``git diff``."""
    head = {k: doc[k] for k in ("format", "generated_by", "warning", "product",
                                "version", "api_version", "method", "promoted_at",
                                "promoted_by", "note", "sha256")}
    lines = ["{"]
    for k, v in head.items():
        lines.append("  %s: %s," % (json.dumps(k), json.dumps(v, ensure_ascii=False)))
    lines.append('  "entries": [')
    rows = sorted(doc["entries"], key=lambda e: e["name"])
    for i, e in enumerate(rows):
        item = {"name": e["name"], "urn": e["urn"], "provenance": e["provenance"],
                "measured_on": e.get("measured_on") or ""}
        sep = "," if i < len(rows) - 1 else ""
        lines.append("    %s%s" % (json.dumps(item, ensure_ascii=False), sep))
    lines.append("  ]")
    lines.append("}")
    return "\n".join(lines) + "\n"


def read_artifact(product: str, directory: str | None = None) -> dict | None:
    """The shipped baseline of ``product``, verified; ``None`` when absent.

    Raises ``ValueError`` when the file exists but is not a valid, correctly
    sealed baseline of ``product`` — a hand-edited artifact is refused, never
    half-applied.
    """
    path = artifact_path(product, directory)
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise ValueError("%s: unreadable baseline artifact (%s)" % (path, exc)) from exc
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise ValueError("%s: unsupported baseline format %r" % (path, (doc or {}).get("format")))
    if doc.get("product") != product:
        raise ValueError("%s: artifact is for %r, not %r" % (path, doc.get("product"), product))
    entries = doc.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("%s: baseline has no entries" % path)
    names = [e.get("name") for e in entries]
    if len(set(names)) != len(names):
        raise ValueError("%s: duplicate endpoint names" % path)
    for e in entries:
        if not e.get("name") or not str(e.get("urn") or "").startswith("/"):
            raise ValueError("%s: bad entry %r" % (path, e))
        if e.get("provenance") not in PROVENANCES:
            raise ValueError("%s: bad provenance in %r" % (path, e))
    want = seal(product, doc.get("version") or "", doc.get("api_version") or "", entries)
    if want != doc.get("sha256"):
        raise ValueError(
            "%s: seal mismatch (file says %s, content hashes to %s). The artifact is "
            "generated by `flask apilib baseline promote --export`; it is not edited "
            "by hand." % (path, doc.get("sha256"), want))
    return doc


def artifact_map(product: str, directory: str | None = None) -> dict:
    """``{name: urn}`` from the shipped artifact — the no-database fallback."""
    try:
        doc = read_artifact(product, directory)
    except ValueError:
        log.exception("baseline artifact of %s refused", product)
        return {}
    return {e["name"]: e["urn"] for e in (doc or {}).get("entries") or []}


def artifact_doc(product: str, version: str, api_version: str, entries, *,
                 method: str, promoted_at: datetime, promoted_by: str = "",
                 note: str = "") -> dict:
    """The artifact document for a baseline; the seal is computed here."""
    rows = [{"name": e["name"], "urn": e["urn"], "provenance": e["provenance"],
             "measured_on": e.get("measured_on") or ""} for e in entries]
    return {
        "format": FORMAT,
        "generated_by": "flask apilib baseline promote --export",
        "warning": "Generated file. Do not edit: sha256 seals the entries and "
                   "the application refuses a mismatch.",
        "product": product, "version": version, "api_version": api_version,
        "method": method,
        "promoted_at": promoted_at.replace(microsecond=0).isoformat() + "Z",
        "promoted_by": promoted_by or "", "note": note or "",
        "sha256": seal(product, version, api_version, rows),
        "entries": rows,
    }


def _artifact_doc(b: ApiLibBaseline, entries) -> dict:
    return artifact_doc(
        b.product, b.version, b.api_version,
        [{"name": e.name, "urn": e.urn, "provenance": e.provenance,
          "measured_on": e.measured_on or ""} for e in entries],
        method=b.method, promoted_at=b.promoted_at, promoted_by=b.promoted_by,
        note=b.note)


def export(product: str, directory: str | None = None) -> str:
    """Write the ACTIVE baseline of ``product`` as its shipped artifact."""
    b = active(product)
    if b is None:
        raise ValueError("%s has no baseline to export" % product)
    path = artifact_path(product, directory)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    text = render_artifact(_artifact_doc(b, entries_of(b)))
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)
    return path


# ---------------------------------------------------------------------------
# reading baselines
# ---------------------------------------------------------------------------

def active(product: str) -> ApiLibBaseline | None:
    """The baseline promoted last for ``product`` (``None`` before the first)."""
    return (ApiLibBaseline.query.filter_by(product=product)
            .order_by(ApiLibBaseline.promoted_at.desc(), ApiLibBaseline.id.desc())
            .first())


def entries_of(b: ApiLibBaseline) -> list:
    return (ApiLibBaselineEntry.query.filter_by(baseline_id=b.id)
            .order_by(ApiLibBaselineEntry.name).all())


def history(product: str) -> list:
    return (ApiLibBaseline.query.filter_by(product=product)
            .order_by(ApiLibBaseline.promoted_at.desc(), ApiLibBaseline.id.desc()).all())


def summary(b: ApiLibBaseline | None) -> dict | None:
    if b is None:
        return None
    counts: dict = {}
    for (prov,) in db.session.query(ApiLibBaselineEntry.provenance).filter_by(baseline_id=b.id):
        counts[prov] = counts.get(prov, 0) + 1
    return {
        "id": b.id, "product": b.product, "version": b.version,
        "api_version": b.api_version, "method": b.method, "sha256": b.sha256,
        "promoted_at": b.promoted_at.isoformat() if b.promoted_at else "",
        "promoted_by": b.promoted_by, "note": b.note,
        "applied_at": b.applied_at.isoformat() if b.applied_at else "",
        "entries": sum(counts.values()), "by_provenance": counts,
    }


# ---------------------------------------------------------------------------
# writing baselines
# ---------------------------------------------------------------------------

def _store(product: str, version: str, api_version: str, entries: list, *,
           method: str, actor: str, note: str, promoted_at=None) -> tuple:
    """Insert the baseline (or re-activate an identical one). ``(row, created)``."""
    sha = seal(product, version, api_version, entries)
    when = promoted_at or _now()
    row = ApiLibBaseline.query.filter_by(product=product, sha256=sha).first()
    if row is not None:
        # Same content promoted again (A -> B -> A): re-activate it. Rows are
        # never duplicated, so "promoted last" moves to the existing one.
        if promoted_at is None:
            row.promoted_at = when
            row.promoted_by = actor or row.promoted_by
            row.applied_at = None
        return row, False
    row = ApiLibBaseline(product=product, version=version, api_version=api_version,
                         sha256=sha, method=method, promoted_at=when,
                         promoted_by=(actor or "")[:64], note=(note or "")[:500])
    db.session.add(row)
    db.session.flush()
    db.session.add_all(ApiLibBaselineEntry(
        baseline_id=row.id, name=e["name"], urn=e["urn"],
        provenance=e["provenance"], measured_on=e.get("measured_on") or "")
        for e in entries)
    return row, True


def _measured_at(product: str, version: str) -> dict:
    """``{name: summary}`` from MEASURED sources only (vendor claims excluded)."""
    from . import api_library
    # A name holding "/" is a REST PATH (a schema harvest probes tree objects
    # under their path), not a registry name. Registering a path is
    # discovery_run's job, with the operator's confirmation, never a side
    # effect of promoting a baseline.
    return {n: e for n, e in api_library.endpoints_at(product, version).items()
            if not e.get("vendor_only") and "/" not in n}


def _measured_builds(product: str) -> list:
    from . import api_library
    return [b["version"] for b in api_library.builds(product)
            if b.get("measured") and not b.get("vendor_only")]


def _served_elsewhere(product: str, version: str) -> dict:
    """``{name: (build, urn)}`` served (``ok`` with a URN) on a measured build
    other than ``version``; the newest such build wins."""
    out: dict = {}
    for other in sorted(_measured_builds(product), key=fv.sort_key):
        if other == version:
            continue
        for name, e in _measured_at(product, other).items():
            if e["verdict"] == "ok" and e.get("urn"):
                out[name] = (other, e["urn"])
    return out


def plan_promotion(product: str, version) -> dict:
    """What promoting ``product`` at ``version`` would change. Writes nothing."""
    if product not in products():
        raise ValueError("%s has no endpoint registry (known: %s)"
                         % (product, ", ".join(products())))
    v = fv.normalize(version)
    if not v:
        raise ValueError("%r is not a firmware version" % (version,))
    measured = _measured_at(product, v)
    if not measured:
        raise ValueError(
            "%s %s has no measured evidence. A baseline is promoted from what an "
            "appliance (or a live schema read) proved; sweep a box on that build "
            "first. Measured builds: %s"
            % (product, v, ", ".join(_measured_builds(product)) or "none"))
    prev = active(product)
    prev_entries = {e.name: e for e in entries_of(prev)} if prev else {}
    elsewhere = _served_elsewhere(product, v)

    new: dict = {}
    for name, e in measured.items():
        if e["verdict"] != "ok":
            continue
        urn = e.get("urn") or (prev_entries[name].urn if name in prev_entries else "")
        if urn.startswith("/"):
            new[name] = {"name": name, "urn": urn, "provenance": PROV_MEASURED,
                         "measured_on": v}
    for name, pe in prev_entries.items():
        if name in new:
            continue
        me = measured.get(name)
        if me is not None and me["verdict"] == "absent":
            if name in elsewhere:
                # Not served on THIS build, but another measured build serves
                # it (an endpoint a newer firmware added). It stays, carried
                # from that build: dropping it would leave a fresh install with
                # no row to sweep, so its boxes on that build would never see
                # it. Per-build resolution keeps it off this build.
                other, eurn = elsewhere[name]
                new[name] = {"name": name, "urn": eurn, "provenance": PROV_CARRIED,
                             "measured_on": other}
            continue  # measured and not served on this build (nor any other): it leaves
        keep = pe.provenance if pe.provenance in (PROV_LEGACY, PROV_CONTRADICTED) \
            else PROV_CARRIED
        new[name] = {"name": name, "urn": pe.urn, "provenance": keep,
                     "measured_on": pe.measured_on or ""}

    entries = sorted(new.values(), key=lambda e: e["name"])
    api_version = api_version_of(product)
    sha = seal(product, v, api_version, entries)
    diff = {
        "added": sorted(set(new) - set(prev_entries)),
        "removed": sorted(set(prev_entries) - set(new)),
        "urn_changed": [
            {"name": n, "from": prev_entries[n].urn, "to": new[n]["urn"]}
            for n in sorted(set(new) & set(prev_entries))
            if new[n]["urn"] != prev_entries[n].urn],
    }
    counts: dict = {}
    for e in entries:
        counts[e["provenance"]] = counts.get(e["provenance"], 0) + 1
    return {
        "product": product, "version": v, "api_version": api_version,
        "sha256": sha, "entries": entries, "by_provenance": counts,
        "previous": summary(prev),
        "identical": bool(prev is not None and prev.sha256 == sha),
        "diff": diff,
    }


def promote(product: str, version, *, actor: str = "", note: str = "",
            apply_now: bool = True) -> dict:
    """Promote ``product`` at ``version`` and (by default) reconcile the registry."""
    plan = plan_promotion(product, version)
    row, created = _store(product, plan["version"], plan["api_version"], plan["entries"],
                          method=METHOD_PROMOTED, actor=actor, note=note)
    db.session.commit()
    out = {"baseline": summary(row), "created": created, "diff": plan["diff"]}
    if apply_now:
        out["applied"] = apply(row)
    return out


def adopt(product: str, version, mapping: dict, *, actor: str = "", note: str = "",
          promoted_at=None) -> dict:
    """One-time import of a legacy ``{name: urn}`` map as the first baseline.

    Nothing is dropped: adoption must not change what the registry serves. Each
    entry is labelled with what the evidence says about it — ``measured`` (the
    build served it), ``contradicted`` (the build measured it ABSENT),
    ``carried`` (another measured build served it) or ``legacy`` (no evidence
    at all) — so the next promotion knows what to drop and ``check`` can say
    what is unproven.
    """
    if product not in products():
        raise ValueError("%s has no endpoint registry" % product)
    if active(product) is not None:
        raise ValueError("%s already has a baseline; adoption is for the first one "
                         "only. Use `baseline promote`." % product)
    v, entries, conflicts = classify_legacy(product, version, mapping)
    row, created = _store(product, v, api_version_of(product), entries,
                          method=METHOD_ADOPTED, actor=actor, note=note,
                          promoted_at=promoted_at)
    db.session.commit()
    return {"baseline": summary(row), "created": created, "conflicts": conflicts}


def classify_legacy(product: str, version, mapping: dict) -> tuple:
    """``(version, entries, conflicts)`` — label a legacy map against the evidence.

    Read-only: this is what :func:`adopt` stores, and what generated the first
    shipped artifacts from the retired YAML seeds.
    """
    v = fv.normalize(version)
    if not v:
        raise ValueError("%r is not a firmware version" % (version,))
    here = _measured_at(product, v)
    elsewhere = _served_elsewhere(product, v)
    entries, conflicts = [], []
    for name, urn in sorted(mapping.items()):
        name, urn = str(name), str(urn or "")
        if not urn.startswith("/"):
            raise ValueError("%s: %r is not an absolute URN" % (name, urn))
        e = here.get(name)
        prov, on = PROV_LEGACY, ""
        if e is not None and e["verdict"] == "ok":
            prov, on = PROV_MEASURED, v
            if e.get("urn") and e["urn"] != urn:
                conflicts.append({"name": name, "map": urn, "evidence": e["urn"], "on": v})
                prov, on = PROV_LEGACY, ""
        elif e is not None and e["verdict"] == "absent":
            prov, on = PROV_CONTRADICTED, v
        elif name in elsewhere:
            other, eurn = elsewhere[name]
            if eurn == urn:
                prov, on = PROV_CARRIED, other
            else:
                conflicts.append({"name": name, "map": urn, "evidence": eurn, "on": other})
        entries.append({"name": name, "urn": urn, "provenance": prov, "measured_on": on})
    return v, entries, conflicts


def _ensure_shipped(product: str, directory: str | None = None) -> ApiLibBaseline | None:
    """Insert the shipped artifact of ``product`` if the DB does not have it."""
    doc = read_artifact(product, directory)
    if doc is None:
        return None
    row = ApiLibBaseline.query.filter_by(product=product, sha256=doc["sha256"]).first()
    if row is not None:
        return row
    when = None
    try:
        when = datetime.fromisoformat(str(doc.get("promoted_at") or "").rstrip("Z"))
    except ValueError:
        when = None
    row, _ = _store(product, doc["version"], doc["api_version"], doc["entries"],
                    method=doc.get("method") or METHOD_PROMOTED,
                    actor=doc.get("promoted_by") or "", note=doc.get("note") or "",
                    promoted_at=when or _now())
    db.session.commit()
    return row


# ---------------------------------------------------------------------------
# registry reconciliation
# ---------------------------------------------------------------------------

def _invalidate(product: str) -> None:
    from ..registry import loader
    {"fortiweb": loader.invalidate_cache, "fortiadc": loader.invalidate_adc_cache,
     "fortianalyzer": loader.invalidate_faz_cache,
     "fortiauthenticator": loader.invalidate_fac_cache}.get(product, lambda: None)()
    # The per-build views (``loader.registry_for`` / ``resolve_for``) and the
    # fleet view are derived from the rows this just rewrote.
    loader.invalidate_build_views(product)


def apply(b: ApiLibBaseline) -> dict:
    """Make ``registry_endpoints`` serve baseline ``b``, sparing operator rows.

    Owned rows (``seed`` / ``baseline:*``) are inserted, corrected, re-tagged or
    disabled to match. A row an operator edited or disabled is counted and left
    exactly as it is.
    """
    from ..models import RegistryEndpoint

    tag = owner_tag(b.product, b.version)
    want = {e.name: e.urn for e in entries_of(b)}
    rows = {r.name: r for r in RegistryEndpoint.query.filter_by(
        product=b.product, api_version=b.api_version).all()}
    out = {"added": 0, "corrected": 0, "retagged": 0, "removed": 0,
           "unchanged": 0, "operator_rows": 0}
    for name, urn in want.items():
        r = rows.get(name)
        if r is None:
            db.session.add(RegistryEndpoint(product=b.product, api_version=b.api_version,
                                            name=name, urn=urn, enabled=True,
                                            updated_by=tag))
            out["added"] += 1
        elif not is_owned(r.updated_by):
            out["operator_rows"] += 1
        elif r.urn != urn or not r.enabled:
            r.urn, r.enabled, r.updated_by = urn, True, tag
            out["corrected"] += 1
        elif r.updated_by != tag:
            r.updated_by = tag
            out["retagged"] += 1
        else:
            out["unchanged"] += 1
    for name, r in rows.items():
        if name in want:
            continue
        if not is_owned(r.updated_by):
            out["operator_rows"] += 1
        elif r.enabled:
            # Soft delete, like an operator's: the row stays so the history of
            # what was served is readable, and a later baseline can re-enable it.
            r.enabled, r.updated_by = False, tag
            out["removed"] += 1
    b.applied_at = _now()
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()  # another worker applied it first — same result
        out["raced"] = True
    _invalidate(b.product)
    return out


def boot(directory: str | None = None) -> dict:
    """Boot hook: insert shipped baselines, apply the active one if pending.

    Idempotent and cheap after the first boot: a shipped artifact already in
    the database is a single indexed lookup, and an applied baseline is not
    re-applied. Never raises — a boot that cannot seed must still serve the
    Registry page where the operator can see why.
    """
    out: dict = {}
    for product in products():
        try:
            _ensure_shipped(product, directory)
            b = active(product)
            if b is not None and b.applied_at is None:
                out[product] = apply(b)
        except Exception:  # noqa: BLE001 — never block boot on seeding
            db.session.rollback()
            log.exception("endpoint baseline of %s not applied", product)
    return out


# ---------------------------------------------------------------------------
# per-build resolution + drift check
# ---------------------------------------------------------------------------

def resolve_at(product: str, name: str, version=None) -> dict:
    """How ``name`` resolves on ``version`` of ``product``, and on what authority.

    Order: an operator's registry row wins (``override`` / ``disabled``); then
    the library's measurement of that exact build (``measured`` / ``absent``);
    then the active baseline (``baseline`` — an assumption, labelled as one);
    otherwise ``absent`` when a baseline exists and does not list the name, or
    ``unmeasured`` when there is no baseline at all. Never a guessed URN.
    """
    from ..models import RegistryEndpoint

    v = fv.normalize(version) if version else ""
    out = {"product": product, "name": name, "version": v, "urn": None,
           "status": STATUS_UNMEASURED, "authority": ""}
    row = RegistryEndpoint.query.filter_by(
        product=product, api_version=api_version_of(product), name=name).first()
    if row is not None and not is_owned(row.updated_by):
        out.update(urn=row.urn if row.enabled else None,
                   status=STATUS_OVERRIDE if row.enabled else STATUS_DISABLED,
                   authority="registry row by %s" % (row.updated_by or "unknown"))
        return out
    if v:
        e = _measured_at(product, v).get(name)
        if e is not None and e["verdict"] == "ok" and e.get("urn"):
            out.update(urn=e["urn"], status=STATUS_MEASURED,
                       authority="evidence: %s" % ", ".join(e.get("sources") or []))
            return out
        if e is not None and e["verdict"] == "absent":
            out.update(status=STATUS_ABSENT,
                       authority="evidence: %s" % ", ".join(e.get("sources") or []))
            return out
    b = active(product)
    if b is None:
        return out
    entry = ApiLibBaselineEntry.query.filter_by(baseline_id=b.id, name=name).first()
    if entry is None:
        out.update(status=STATUS_ABSENT, authority="not in baseline %s" % b.version)
        return out
    out.update(urn=entry.urn, status=STATUS_BASELINE,
               authority="baseline %s (%s)" % (b.version, entry.provenance))
    return out


def check(product: str) -> dict:
    """Drift report: registry vs baseline vs the evidence of every fleet build."""
    from ..models import RegistryEndpoint
    from . import api_library

    b = active(product)
    report = {"product": product, "baseline": summary(b), "registry": {}, "fleet": [],
              "contradicted": [], "ok": True}
    if b is None:
        report["ok"] = False
        report["problem"] = "no baseline"
        return report
    entries = {e.name: e for e in entries_of(b)}
    rows = {r.name: r for r in RegistryEndpoint.query.filter_by(
        product=product, api_version=b.api_version).all()}
    missing = sorted(n for n in entries if n not in rows)
    wrong = sorted(n for n, r in rows.items()
                   if n in entries and is_owned(r.updated_by)
                   and (r.urn != entries[n].urn or not r.enabled))
    stale = sorted(n for n, r in rows.items()
                   if n not in entries and is_owned(r.updated_by) and r.enabled)
    overrides = sorted(
        ({"name": n, "urn": r.urn, "enabled": r.enabled, "by": r.updated_by or ""}
         for n, r in rows.items() if not is_owned(r.updated_by)),
        key=lambda d: d["name"])
    report["registry"] = {"rows": len(rows), "missing": missing, "wrong_urn": wrong,
                          "stale_enabled": stale, "overrides": overrides,
                          "applied": bool(b.applied_at)}
    report["contradicted"] = sorted(n for n, e in entries.items()
                                    if e.provenance == PROV_CONTRADICTED)
    if missing or wrong or stale or not b.applied_at:
        report["ok"] = False

    versions = sorted({w["version"] for w in api_library._fleet(product).values()
                       if w.get("version")}, key=fv.sort_key)
    for v in versions:
        measured = _measured_at(product, v)
        row = {"version": v, "measured": bool(measured), "served": 0,
               "absent_on_build": [], "urn_mismatch": [], "by_baseline_only": 0}
        for name, e in entries.items():
            m = measured.get(name)
            if m is None or m["verdict"] not in ("ok", "absent"):
                row["by_baseline_only"] += 1
            elif m["verdict"] == "absent":
                row["absent_on_build"].append(name)
            else:
                row["served"] += 1
                if m.get("urn") and m["urn"] != e.urn:
                    row["urn_mismatch"].append({"name": name, "baseline": e.urn,
                                                "evidence": m["urn"]})
        if row["urn_mismatch"]:
            report["ok"] = False
        report["fleet"].append(row)
    return report
