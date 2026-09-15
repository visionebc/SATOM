"""The discovery probe, moved OFF the request thread.

WHY THIS MODULE EXISTS. ``views/_discovery.run_payload`` used to fire up to
``MAX_BUDGET`` GETs *inside* the HTTP request that asked for them. Three
measured numbers decided that this could not stay: nginx cuts a proxied request
at **120 s**, gunicorn kills a worker at **600 s**, and a run against a
*degraded* appliance — the case where the answer matters most — is exactly the
one whose GETs time out. Crossing nginx's limit returns a 504 to the browser
while the worker keeps asking the device for up to eight more minutes, and the
findings those GETs bought are then unreachable: they only ever existed in a
response body nobody received. With four gunicorn workers, one such run also
holds 25 % of the application for its whole duration.

So a run is a **job**. :mod:`app.services.jobs` already owns every property this
needs — worker-proof state files, the toast dock, the bell, cooperative Stop,
and the boot-time orphan sweep — and reusing it is what keeps *"is it
running?"* a question with ONE answer in this product instead of a third
private progress format.

WHAT IS PERSISTED, and why it is the findings rather than a summary: the
operator **registers** from that table. A result that lived only in the browser
meant closing the tab threw away the GETs that produced it, and re-running is
not free — it is the whole budget again, against a production appliance.

THE PLAN IS BUILT IN THE REQUEST, not here. Deriving candidates reads the
catalog and the CLI dump through the ADOM-scoped, request-bound services; doing
that in a daemon thread is how a background task quietly answers about the
wrong ADOM. The worker receives finished :class:`~app.services.discovery_run.Finding`
objects and only ever *asks the device* about them.
"""
from __future__ import annotations

from typing import Any

from . import discovery_run, jobs

#: The job type. One string, referenced by the UI and the guards alike.
JOB_TYPE = "discovery_probe"


def _progress_message(idx: int, total: int, spent: int, budget: int,
                      path: str) -> str:
    return ("asking about %s (block %d of %d, %d/%d GETs spent)"
            % (path or "?", idx, total, spent, budget))


def start(flask_app, *, product: str, appliance_id: int, appliance_name: str,
          rows, by_urn: dict, budget: int, evidence: dict,
          by: str = "") -> dict:
    """Create the job and dispatch its worker. Returns the job dict.

    ``rows`` are the findings the REQUEST already planned. ``evidence``
    is the chosen dump's descriptor, carried so the worker can compare firmware
    lines without recomputing which dump the page was showing — a second
    ``cli_coverage.report()`` would be a second answer to "which dump", which is
    the exact class of defect this card was fixed for on 2026-09-15.
    """
    rows = list(rows)
    job = jobs.create_job(
        JOB_TYPE,
        "Discovery run — %s (%d blocks, budget %d)"
        % (appliance_name, len(rows), budget),
        by=by,
        # Read-only against the device; it writes nothing to compensate, so it
        # never claims an undo it cannot deliver.
        cancelable=True, reversible=False,
        meta={"product": product, "appliance_id": appliance_id,
              "appliance": appliance_name, "budget": budget,
              "blocks": len(rows)})
    job_id = job["id"]

    def _worker(app, jid):
        with app.app_context():
            return _execute(jid, product=product, appliance_id=appliance_id,
                            appliance_name=appliance_name, rows=rows,
                            by_urn=by_urn, budget=budget, evidence=evidence,
                            by=by)

    jobs.run_async(flask_app, job_id, _worker)
    return job


def _execute(job_id: str, *, product: str, appliance_id: int,
             appliance_name: str, rows, by_urn: dict, budget: int,
             evidence: dict, by: str) -> dict[str, Any]:
    """The worker body. Runs inside an app context, never inside a request."""
    from ..models import Appliance
    from ..services import rediscovery
    from ..services.audit import log_action

    appliance = Appliance.query.get(appliance_id)
    if appliance is None:
        # Deleted between the click and the dispatch. An error, never an empty
        # result: "no findings" and "there was nothing to ask" read the same on
        # screen and mean opposite things.
        raise RuntimeError("appliance %s no longer exists" % appliance_id)

    jobs.set_progress(job_id, 1, "reading the running firmware version")
    version = discovery_run.version_check(appliance, evidence)
    provenance = {
        "evidence": evidence.get("appliance") or "",
        "evidence_line": evidence.get("line") or "",
        "evidence_captured": evidence.get("created_at") or "",
        "same_device": version.get("same_device"),
        "version": version,
    }

    total = len(rows)

    def _on_progress(idx, count, spent, path):
        # Cooperative Stop, checked between blocks: a GET already in flight is
        # never interrupted mid-call, and the blocks after the stop stay
        # NOT_PROBED — which is the honest state, not `absent`.
        jobs.checkpoint(job_id)
        pct = 1 + int((idx - 1) * 98 / count) if count else 99
        jobs.set_progress(job_id, min(pct, 99),
                          _progress_message(idx, count, spent, budget, path))

    def _probe(urn):
        return rediscovery.probe_endpoint(appliance, urn)

    try:
        result = discovery_run.run(rows, _probe, budget=budget, by_urn=by_urn,
                                   on_progress=_on_progress)
    except jobs.JobCancelled:
        # Stopped runs still hand back what they learned: the GETs were spent
        # against a production box and throwing the answers away would make
        # Stop more expensive than letting it finish.
        partial = _payload(rows, product, appliance_name, provenance,
                           budget=budget, stopped=True)
        log_action("discovery_run.probe", target=appliance_name,
                   extra={"product": product, "blocks": total, "by": by,
                          "job": job_id, "stopped": True,
                          "firmware": version.get("firmware") or "",
                          "line": version.get("line") or "",
                          "evidence": provenance["evidence"],
                          "evidence_line": provenance["evidence_line"],
                          "version_verdict": version.get("verdict"),
                          "summary": partial.get("summary") or ""})
        jobs.finish_cancelled(job_id, message=partial.get("summary") or "stopped",
                              result=partial)
        raise

    out = {k: v for k, v in result.items() if k != "findings"}
    out.update({"ok": True, "product": product, "device": appliance_name,
                "findings": [f.to_dict() for f in result["findings"]],
                "summary": discovery_run.summary_line(result),
                "stopped": False})
    out.update(provenance)

    # The firmware and the evidence ride into the audit row WITH the run. The
    # page can be closed; the question "which firmware were those verdicts
    # about?" outlives it, and re-deriving the answer later reads TODAY's
    # version off a box that may since have been upgraded. ``by`` is carried
    # explicitly because a worker thread has no ``current_user`` — without it
    # every async run would be attributed to "system".
    log_action("discovery_run.probe", target=appliance_name,
               extra={"product": product, "blocks": total, "by": by,
                      "job": job_id, "stopped": False,
                      "firmware": version.get("firmware") or "",
                      "line": version.get("line") or "",
                      "evidence": provenance["evidence"],
                      "evidence_line": provenance["evidence_line"],
                      "version_verdict": version.get("verdict"),
                      "summary": out["summary"]})
    jobs.finish_success(job_id, message=out["summary"], result=out)
    return out


def _payload(rows, product: str, device: str, provenance: dict, *,
             budget: int, stopped: bool) -> dict[str, Any]:
    """The same shape :func:`discovery_run.run` returns, rebuilt from findings.

    Used for the STOPPED path, where there is no result dict because the run
    raised out of the middle of itself. Counting from the findings keeps one
    author for those totals.
    """
    rows = list(rows)
    spent = sum(f.probed for f in rows)
    result = {
        "findings": rows, "spent": spent, "budget": budget,
        "exhausted": spent >= budget,
        "not_probed": sum(1 for f in rows if f.status == discovery_run.NOT_PROBED),
        "served": sum(1 for f in rows if f.status == discovery_run.SERVED),
        "absent": sum(1 for f in rows if f.status == discovery_run.ABSENT),
        "errors": sum(1 for f in rows if f.status == discovery_run.ERROR),
        "registerable": sum(1 for f in rows if f.registerable),
        "name_taken": sum(1 for f in rows if f.name_taken),
        "urn_known": sum(1 for f in rows if f.urn_known),
    }
    out = {k: v for k, v in result.items() if k != "findings"}
    out.update({"ok": True, "product": product, "device": device,
                "findings": [f.to_dict() for f in rows],
                "summary": discovery_run.summary_line(result),
                "stopped": bool(stopped)})
    out.update(provenance)
    return out


def active_for(appliance_id: int, *, by: str = "") -> dict | None:
    """The caller's live discovery job for this appliance, if any.

    Lets the page RECONNECT to a run after a navigation instead of offering a
    second one: two concurrent runs against one appliance is twice the budget
    for one answer.
    """
    for st in jobs.list_jobs(limit=50, by=by or None, active_only=True):
        if st.get("type") != JOB_TYPE:
            continue
        if int((st.get("meta") or {}).get("appliance_id") or 0) == int(appliance_id):
            return st
    return None


__all__ = ["JOB_TYPE", "start", "active_for"]
