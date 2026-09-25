"""API library — incremental harvest: one appliance, one build, one evidence row.

``api_library.backfill`` imports what is already on disk; this module is what
keeps the library growing afterwards. Three entry points:

* :func:`enqueue` — ask for a harvest in the background. Called by
  ``firmware_probe.refresh`` when a box changes build, so an upgrade adds
  evidence for the new build without anybody remembering to sweep.
* :func:`run` — do one harvest now, in the caller's app context (the job
  worker, the scheduled action).
* :func:`needs_harvest` — does this appliance's exact build lack healthy
  evidence from its product's live source?

WHY A JOB, NOT A THREAD. A harvest is a full read of the box (a rediscovery
sweep, or every FortiAuthenticator schema), far too long for the request that
noticed the version change. :mod:`app.services.jobs` already owns the
worker-proof state file, the Job Manager page, the failure bell and the
boot-time orphan sweep; a private thread would be a second, invisible answer
to "is a harvest running?".

WHICH PRODUCTS. Only products SATOM can read live: FortiWeb and FortiADC via
the rediscovery sweep, FortiAuthenticator via its Tastypie schema. FortiAnalyzer
and FortiGate have vendor evidence only, and every entry point says so BY NAME
("no live harvester for fortianalyzer") — a harvest that silently succeeds
without reading anything would read as "measured" on the next page.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from . import jobs

_log = logging.getLogger(__name__)

#: The job type. One string, referenced by the dedup check and the UI alike.
JOB_TYPE = "apilib_harvest"

#: The evidence source each product's live harvester writes. ``needs_harvest``
#: asks for evidence FROM THIS SOURCE: vendor or legacy data for a build is a
#: claim, and it must not stop the build from being measured.
LIVE_SOURCE = {"fortiweb": "sweep", "fortiadc": "sweep",
               "fortiauthenticator": "schema"}

#: A sweep whose progress file says ``running`` blocks a harvest only while it
#: is this young — the same 15-minute rule ``rediscovery.start`` uses, so a
#: ghost ``running`` left by a restart cannot block harvesting forever.
_SWEEP_LIVE_S = 900

#: Config switch for the background dispatch. Defaults to ON, except under
#: TESTING: an existing test that probes a fake appliance at a 10.0.0.x address
#: must never grow a background sweep against the real LAN. A test that wants
#: the dispatch sets it explicitly.
DISPATCH_CONFIG = "APILIB_HARVEST_DISPATCH"


def unsupported_msg(product: str) -> str:
    return "no live harvester for %s" % (product or "an appliance with no product")


def active_job(appliance_id: int) -> dict | None:
    """The pending/running harvest job for this appliance, if any."""
    for st in jobs.list_jobs(limit=500, active_only=True, type_=JOB_TYPE):
        try:
            if int((st.get("meta") or {}).get("appliance_id") or 0) == int(appliance_id):
                return st
        except (TypeError, ValueError):
            continue
    return None


def _dispatch_enabled(app) -> bool:
    val = app.config.get(DISPATCH_CONFIG)
    if val is None:
        return not app.config.get("TESTING")
    return bool(val)


# --------------------------------------------------------------------------- #
#  needs_harvest                                                               #
# --------------------------------------------------------------------------- #
def needs_harvest(appliance) -> bool:
    """True when the appliance's EXACT build has no healthy point evidence
    from its product's live source.

    False (nothing to do) when the product has no live harvester, or when the
    running build is unknown or line-only ("8.0"): a harvest cannot be judged
    missing for a build nobody has named, and ``firmware_probe`` establishes
    the build first — then asks again.
    """
    from sqlalchemy import select

    from ..extensions import db
    from ..models_apilib import ApiLibBuild, ApiLibEvidence
    from . import firmware_versions as fv

    product = getattr(appliance, "kind", "") or ""
    source = LIVE_SOURCE.get(product)
    if source is None:
        return False
    # Same read as api_library.resolve_appliance, so "needs a harvest" and
    # the Explorer's "unmeasured" can never disagree about which build it is.
    raw = getattr(appliance, "fw_version", "") or getattr(appliance, "firmware", "") or ""
    version = fv.normalize(raw)
    if not version or fv.is_line_only(version):
        return False
    build = ApiLibBuild.query.filter_by(product=product, version=version).first()
    if build is None:
        return True
    hit = db.session.execute(
        select(ApiLibEvidence.id).where(
            ApiLibEvidence.product == product,
            ApiLibEvidence.source == source,
            ApiLibEvidence.build_id == build.id,
            ApiLibEvidence.scope_kind == "build",
            ApiLibEvidence.healthy.is_(True)).limit(1)).first()
    return hit is None


# --------------------------------------------------------------------------- #
#  enqueue                                                                     #
# --------------------------------------------------------------------------- #
def enqueue(appliance_id: int, reason: str, *, by: str = "apilib") -> dict:
    """Queue ONE background harvest for an appliance. NEVER raises.

    Returns ``{"queued": bool, "msg": str, "job_id" | "reason": ...}``. At most
    one harvest is pending or running per appliance: a second request returns
    the first job's id with ``reason="duplicate"`` rather than a second full
    read of the same box. Appliances in maintenance are not queued — scheduled
    collection is suppressed there, and the ``apilib_harvest`` scheduled action
    picks the build up once the box is back.
    """
    try:
        from flask import current_app, has_app_context
        if not has_app_context():
            return {"queued": False, "reason": "no_app_context",
                    "msg": "no application context to queue a harvest from"}
        from ..extensions import db
        from ..models import Appliance

        ap = db.session.get(Appliance, int(appliance_id))
        if ap is None:
            return {"queued": False, "reason": "not_found",
                    "msg": "appliance %s does not exist" % appliance_id}
        product = ap.kind or ""
        if product not in LIVE_SOURCE:
            return {"queued": False, "reason": "unsupported", "product": product,
                    "msg": unsupported_msg(product)}
        if getattr(ap, "maintenance", False):
            return {"queued": False, "reason": "maintenance",
                    "msg": "%s is in maintenance; not harvested now" % ap.name}
        existing = active_job(ap.id)
        if existing is not None:
            return {"queued": False, "reason": "duplicate", "job_id": existing["id"],
                    "msg": "a harvest of %s is already pending" % ap.name}
        app = current_app._get_current_object()
        if not _dispatch_enabled(app):
            return {"queued": False, "reason": "disabled",
                    "msg": "background harvest is disabled (%s)" % DISPATCH_CONFIG}
        job = jobs.create_job(
            JOB_TYPE, "API library harvest - %s" % ap.name, by=by,
            # A sweep has no safe checkpoint to stop at; offering Stop would
            # promise something the worker cannot do.
            cancelable=False, reversible=False, background=True,
            meta={"product": product, "appliance_id": ap.id,
                  "appliance": ap.name, "reason": reason,
                  "firmware": ap.firmware or ""})
        _dispatch(app, job["id"], ap.id)
        return {"queued": True, "job_id": job["id"],
                "msg": "harvest of %s queued (%s)" % (ap.name, reason)}
    except Exception as exc:  # noqa: BLE001 — callers are probes and schedulers
        _log.warning("apilib_harvest: enqueue(%s) failed: %s", appliance_id, exc,
                     exc_info=True)
        return {"queued": False, "reason": "error",
                "msg": ("%s: %s" % (type(exc).__name__, exc))[:200]}


def _dispatch(app, job_id: str, appliance_id: int) -> None:
    """Run :func:`run` for one appliance through the job runner."""
    def _worker(flask_app, jid):
        with flask_app.app_context():
            jobs.set_progress(jid, 5, "harvesting")
            res = run(appliance_id)
        if res.get("ok"):
            jobs.finish_success(jid, message=res.get("msg") or "", result=res)
        else:
            jobs.update_job(jid, result=res)
            jobs.finish_error(jid, res.get("msg") or "harvest failed")
        return res

    jobs.run_async(app, job_id, _worker)


# --------------------------------------------------------------------------- #
#  run                                                                         #
# --------------------------------------------------------------------------- #
def _sweep_running(appliance_id: int) -> bool:
    from . import rediscovery
    cur = rediscovery.status(appliance_id) or {}
    if cur.get("state") != "running":
        return False
    try:
        started = datetime.fromisoformat(cur.get("started") or "")
    except (TypeError, ValueError):
        return False
    # The sweep stamps naive UTC (``utcnow``); read it as UTC, not local time.
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    return time.time() - started.timestamp() < _SWEEP_LIVE_S


def _run_sweep(ap) -> dict:
    """FortiWeb / FortiADC: a rediscovery sweep, which ingests its own snapshot.

    Through ``rediscovery._run`` — the entry point the post-upgrade sweep
    already uses synchronously — so the harvest writes the same files, the
    same progress state and the same library evidence as the operator's
    button, and there is one sweep implementation, not two.
    """
    from . import rediscovery
    if _sweep_running(ap.id):
        return {"ok": False, "reason": "busy", "product": ap.kind,
                "msg": "a rediscovery of %s is already running" % ap.name}
    snap = rediscovery._client_snapshot(ap)
    plan = rediscovery.plan_for(ap)   # resolved here: the registry reads the DB
    rediscovery._run(snap, by="apilib_harvest", deep=False, plan=plan)
    st = rediscovery.status(ap.id) or {}
    base = {"product": ap.kind, "harvester": "sweep", "appliance": ap.name,
            "sweep": st.get("summary") or ""}
    if st.get("apilib_error"):
        return {**base, "ok": False, "reason": "library_error",
                "msg": "sweep of %s done, but the library did not take it: %s"
                       % (ap.name, st["apilib_error"])}
    lib = st.get("apilib") or {}
    return _outcome(base, ap.name, lib)


def _run_fac(ap) -> dict:
    """FortiAuthenticator: the live Tastypie schema (GET-only) + ingest."""
    from . import api_library, apilib_fac
    raw: dict = {}
    doc = apilib_fac.harvest(ap, raw=raw)
    res = api_library.ingest(doc, raw=raw or None)
    base = {"product": ap.kind, "harvester": "schema", "appliance": ap.name}
    return _outcome(base, ap.name, {"evidence_id": res.get("evidence_id"),
                                    "created": bool(res.get("created")),
                                    "healthy": bool(doc.get("healthy")),
                                    "skip_reason": doc.get("skip_reason") or ""})


def _outcome(base: dict, name: str, lib: dict) -> dict:
    """``ok`` only for HEALTHY stored evidence. An unhealthy harvest is kept
    (the record of a failed read is evidence too) but it measured nothing, so
    the build still needs a harvest and the job must not read green."""
    out = {**base, "evidence_id": lib.get("evidence_id"),
           "created": bool(lib.get("created")), "healthy": bool(lib.get("healthy"))}
    if not lib.get("evidence_id"):
        return {**out, "ok": False, "reason": "no_evidence",
                "msg": "harvest of %s stored no evidence" % name}
    if not lib.get("healthy"):
        return {**out, "ok": False, "reason": "unhealthy",
                "msg": "harvest of %s stored as unhealthy: %s"
                       % (name, lib.get("skip_reason") or "unknown reason")}
    return {**out, "ok": True,
            "msg": "harvest of %s: evidence #%s %s"
                   % (name, lib["evidence_id"],
                      "created" if lib.get("created") else "confirmed")}


_HARVESTERS = {"fortiweb": _run_sweep, "fortiadc": _run_sweep,
               "fortiauthenticator": _run_fac}


def run(appliance_id: int) -> dict:
    """Harvest one appliance NOW, in the caller's app context. NEVER raises.

    Returns ``{"ok", "msg", "product", ...}``; ``reason`` names why when not
    ok (``not_found``, ``unsupported``, ``busy``, ``unhealthy``,
    ``library_error``, ``no_evidence``, ``error``).
    """
    from ..extensions import db
    from ..models import Appliance
    try:
        ap = db.session.get(Appliance, int(appliance_id))
        if ap is None:
            return {"ok": False, "reason": "not_found",
                    "msg": "appliance %s does not exist" % appliance_id}
        harvester = _HARVESTERS.get(ap.kind or "")
        if harvester is None:
            return {"ok": False, "reason": "unsupported", "product": ap.kind,
                    "msg": unsupported_msg(ap.kind)}
        return harvester(ap)
    except Exception as exc:  # noqa: BLE001 — one box must not stop a round
        try:
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        _log.warning("apilib_harvest: run(%s) failed: %s", appliance_id, exc,
                     exc_info=True)
        return {"ok": False, "reason": "error",
                "msg": ("%s: %s" % (type(exc).__name__, exc))[:200]}


__all__ = ["JOB_TYPE", "LIVE_SOURCE", "DISPATCH_CONFIG", "enqueue", "run",
           "needs_harvest", "active_job", "unsupported_msg"]
