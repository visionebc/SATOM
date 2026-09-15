"""Shared body of the **Discovery run** — the catalog's missing growth path.

Mounted per ADOM exactly like :mod:`app.views._clicoverage`, whose section this
one extends. Four routes, and the permission on each is an argument, not a
habit:

* ``load``     — runs the REST sweep AND the CLI capture in ONE action, because
                 the diff underneath is only as good as the older of its two
                 halves. It delegates to ``rediscovery.start(cli=True)``: the
                 same worker the Rediscover page drives, with the same
                 ``cli_capture_decision`` authority, so this page cannot
                 promise a dump the worker would decline.
                 Gated ``appliances.apply`` + ``Permission.BACKUP`` for the CLI
                 half — and the CLI half is DROPPED WITH ITS REASON RETURNED
                 rather than silently, mirroring ``appliances.rediscover_start``.
* ``run``      — STARTS A JOB that fires up to ``DEFAULT_BUDGET`` read-only
                 GETs at one appliance, and returns its id. It does NOT do the
                 asking itself: nginx cuts a proxied request at 120 s and
                 gunicorn at 600 s, so a run against a slow or degraded box —
                 the case whose answer matters most — returned a 504 while the
                 worker kept spending the budget for minutes more, and the
                 findings those GETs bought died with the response nobody
                 received. The work, the progress, the Stop and the persisted
                 result all live in :mod:`app.services.discovery_jobs`.
                 Gated ``REGISTRY_EDIT``, for the same reason the reconcile page
                 is: it exists to drive a catalog write, and it is a hundredfold
                 the single ``probe`` next to it. The single probe stays
                 ungated — one verdict is strictly less than the console on the
                 same page already gives.

                 The PLAN is still built here, in the request: deriving
                 candidates reads the catalog and the dump through ADOM-scoped,
                 request-bound services, and doing that in a daemon thread is
                 how a background task quietly answers about the wrong ADOM.
                 The worker only ever asks the device.
* ``register`` — the write. ``REGISTRY_EDIT``, through the ONE catalog writer
                 (:mod:`app.services.registry_write`), never a third copy of it.
* ``plan``     — what a run WOULD ask, with zero device contact, so the cost is
                 visible before it is spent.

WHAT CANNOT HAPPEN HERE: a URN reaching the catalog because this code derived
it. Registration re-probes every submitted pair against the device inside the
same request and drops anything the appliance does not serve. The browser is
not the authority on what exists — a checkbox list is trivially replayable, and
the catalog is what ``loader.resolve`` hands every other service.
"""
from __future__ import annotations

from flask import current_app, flash, jsonify, redirect, request, url_for
from flask_login import current_user

from ..models import Permission, visible_appliance_or_404
from ..services import (cli_coverage, discovery_jobs, discovery_run,
                        registry_write)
from ..services.audit import log_action

#: Hard ceiling the form may not exceed, whatever it posts. The form's own
#: field is clamped to this — a budget supplied by the client is a request,
#: never a permission.
MAX_BUDGET = discovery_run.DEFAULT_BUDGET * 4


def _int_arg(name: str, default: int) -> int:
    val = request.form.get(name, type=int)
    return default if val is None else val


def _truthy(name: str) -> bool:
    return (request.form.get(name) or "").strip().lower() in ("1", "true", "on", "yes")


def _findings_for(product: str, *, configured_only: bool, limit: int | None):
    """The plan rows, built from the SAME report the page is showing."""
    backup_id = request.form.get("dump", type=int)
    rep = cli_coverage.report(product, backup_id)
    by_name, by_urn = discovery_run.catalog_index(product)
    rows = discovery_run.plan(product, rep["diff"], configured_only=configured_only,
                             by_name=by_name, by_urn=by_urn, limit=limit)
    return rep, rows, by_name, by_urn


def plan_payload(product: str):
    """JSON: what a run would ask, and what it would cost. No device contact."""
    if product not in cli_coverage.SUPPORTED_PRODUCTS:
        return jsonify({"ok": False,
                        "error": cli_coverage.UNSUPPORTED_REASON.get(
                            product, "this product has no CLI configuration dump")}), 400
    limit = _int_arg("limit", 0) or None
    rep, rows, _n, _u = _findings_for(product, configured_only=_truthy("configured_only"),
                                      limit=limit)
    gets = sum(len(f.candidates) for f in rows)
    return jsonify({
        "ok": True, "product": product,
        "blocks": len(rows),
        # Worst case: every candidate asked. The run stops at the first served
        # path per block, so the real number is lower — but a COST shown to an
        # operator has to be the ceiling, not the hope.
        "max_gets": gets,
        "budget": min(_int_arg("budget", discovery_run.DEFAULT_BUDGET), MAX_BUDGET),
        # The plan names its evidence and STOPS there. No version read: this
        # route's whole contract is that it costs the device nothing, and
        # "one harmless status call" is how that contract stops being true.
        "evidence": (rep.get("chosen") or {}).get("appliance") or "",
        "evidence_line": (rep.get("chosen") or {}).get("line") or "",
        "captured": (rep.get("chosen") or {}).get("created_at") or "",
        "findings": [f.to_dict() for f in rows],
    })


def run_payload(product: str):
    """JSON: START a discovery run as a background job and return its id.

    This route does no device I/O beyond nothing at all. Everything it used to
    do inline -- the version read, the GETs, the audit outcome -- now happens in
    :func:`app.services.discovery_jobs.start`'s worker, because a run that
    outlives nginx's 120 s proxy timeout used to return a 504 while the GETs
    kept being spent, leaving the operator with a broken page and the appliance
    with the load.
    """
    if product not in cli_coverage.SUPPORTED_PRODUCTS:
        return jsonify({"ok": False,
                        "error": cli_coverage.UNSUPPORTED_REASON.get(
                            product, "this product has no CLI configuration dump")}), 400

    appliance_id = request.form.get("appliance_id", type=int)
    if not appliance_id:
        return jsonify({"ok": False, "error": "an appliance is required"}), 400
    appliance = visible_appliance_or_404(appliance_id)
    if getattr(appliance, "kind", "") != product:
        return jsonify({"ok": False, "error": "that appliance is not a %s" % product}), 403

    budget = max(1, min(_int_arg("budget", discovery_run.DEFAULT_BUDGET), MAX_BUDGET))
    limit = _int_arg("limit", 0) or None
    actor = getattr(current_user, "username", "")

    # Never a SECOND run against the same appliance: that is twice the budget
    # for one answer, and both runs then compete for the same device's session
    # limit. The caller is reconnected to the live one instead -- which is only
    # possible because the run is a job with a persisted result.
    live = discovery_jobs.active_for(appliance.id, by=actor)
    if live is not None:
        return jsonify({"ok": True, "started": False, "reconnected": True,
                        "job_id": live["id"], "product": product,
                        "device": appliance.name})

    rep, rows, _n, by_urn = _findings_for(
        product, configured_only=_truthy("configured_only"), limit=limit)
    chosen = rep.get("chosen") or {}
    if not rows:
        # Nothing to ask about is a COMPLETE answer that costs the device
        # nothing, so it is not a job -- and it reads no version, because a
        # status call here would be device contact on the one path whose entire
        # content is "there was nothing to ask". ``version`` is empty and
        # ``same_device`` is None, never False: "no comparison was made" is not
        # "the comparison disagreed".
        return jsonify({"ok": True, "started": False, "job_id": "",
                        "product": product, "findings": [],
                        "spent": 0, "budget": budget, "exhausted": False,
                        "served": 0, "absent": 0, "errors": 0,
                        "not_probed": 0, "registerable": 0,
                        "name_taken": 0, "urn_known": 0,
                        "device": appliance.name,
                        "evidence": chosen.get("appliance") or "",
                        "evidence_line": chosen.get("line") or "",
                        "evidence_captured": chosen.get("created_at") or "",
                        "same_device": None, "version": {},
                        "note": "no CLI-only block to ask about"})

    job = discovery_jobs.start(
        current_app._get_current_object(), product=product,
        appliance_id=appliance.id, appliance_name=appliance.name,
        rows=rows, by_urn=by_urn, budget=budget, evidence=chosen, by=actor)
    # Attribution belongs to the REQUEST. A worker thread has no
    # ``current_user``, so an audit row written there says "system"; the
    # dispatch is recorded here with the real operator, and the worker logs the
    # OUTCOME carrying ``by`` explicitly.
    log_action("discovery_run.start", target=appliance.name,
               extra={"product": product, "blocks": len(rows),
                      "budget": budget, "job": job["id"],
                      "evidence": chosen.get("appliance") or "",
                      "evidence_line": chosen.get("line") or ""})
    return jsonify({"ok": True, "started": True, "job_id": job["id"],
                    "product": product, "device": appliance.name,
                    "blocks": len(rows), "budget": budget})


def register_payload(product: str):
    """JSON: register the selected (name, urn) pairs — after re-asking the device.

    The re-probe is the whole point. Between the run and the submit the operator
    may have edited a name, and a POST is replayable regardless: without asking
    again, a crafted form writes any URL into the catalog under any key. The
    device stays the authority, in the same request that performs the write.
    """
    if product not in registry_write.WRITABLE_PRODUCTS:
        return jsonify({"ok": False, "error": "%s endpoints are not editable" % product}), 400

    appliance_id = request.form.get("appliance_id", type=int)
    if not appliance_id:
        return jsonify({"ok": False, "error": "an appliance is required"}), 400
    appliance = visible_appliance_or_404(appliance_id)
    if getattr(appliance, "kind", "") != product:
        return jsonify({"ok": False, "error": "that appliance is not a %s" % product}), 403

    names = request.form.getlist("name")
    urns = request.form.getlist("urn")
    if not names or len(names) != len(urns):
        return jsonify({"ok": False, "error": "name and urn must come in pairs"}), 400

    from ..services import rediscovery

    results, created = [], 0
    for name, urn in zip(names, urns):
        name, urn = (name or "").strip(), (urn or "").strip()
        bad = registry_write.validate(product, name, urn)
        if bad:
            results.append({"name": name, "urn": urn, "ok": False, "error": bad})
            continue
        try:
            rows, verdict, detail = rediscovery.probe_endpoint(appliance, urn)
        except Exception as exc:  # noqa: BLE001
            results.append({"name": name, "urn": urn, "ok": False,
                            "error": "could not ask %s: %s: %s"
                                     % (appliance.name, type(exc).__name__, exc)})
            continue
        if verdict != discovery_run.SERVED:
            # ``absent`` and ``error`` both stop the write, and they say so
            # differently: one is the device's answer, the other is our failure.
            results.append({"name": name, "urn": urn, "ok": False,
                            "error": ("%s does not serve that path (%s)"
                                      % (appliance.name, verdict)
                                      if verdict == discovery_run.ABSENT else
                                      "could not confirm the path (%s): %s"
                                      % (verdict, (detail or "")[:120]))})
            continue
        ok, msg, _row = registry_write.save_endpoint(
            product=product, name=name, urn=urn,
            actor=getattr(current_user, "username", ""), commit=False)
        results.append({"name": name, "urn": urn, "ok": ok,
                        "error": "" if ok else msg, "rows": len(rows or ())})
        if ok:
            created += 1

    if created:
        from ..extensions import db
        db.session.commit()
        registry_write.invalidate(product)
    else:
        # Nothing was written; drop whatever the loop staged so a later request
        # in the same session cannot flush a row this one decided against.
        from ..extensions import db
        db.session.rollback()

    log_action("discovery_run.register", target=appliance.name,
               extra={"product": product, "created": created,
                      "names": [r["name"] for r in results if r["ok"]],
                      "rejected": [r["name"] for r in results if not r["ok"]]})
    return jsonify({"ok": True, "created": created, "product": product,
                    "device": appliance.name, "results": results,
                    "rejected": sum(1 for r in results if not r["ok"])})


def load(product: str, page_endpoint: str):
    """Refresh BOTH halves of the diff: the REST sweep and the CLI dump.

    One action, because a diff between a catalog swept today and a dump
    captured in July is a report about two different afternoons. It delegates
    to ``rediscovery.start(cli=True)`` — the existing worker — so the CLI half
    is decided by ``cli_capture_decision`` and not by this page.
    """
    appliance_id = request.form.get("appliance_id", type=int)
    appliance = visible_appliance_or_404(appliance_id)
    if getattr(appliance, "kind", "") != product:
        flash("%s is not a %s." % (appliance.name, product), "danger")
        return redirect(url_for(page_endpoint))

    from ..services import rediscovery

    want_cli = not _truthy("api_only")
    refused = ""
    if want_cli and not current_user.can(Permission.BACKUP):
        want_cli, refused = False, rediscovery.CLI_SKIP_NO_PERMISSION

    res = rediscovery.start(appliance, by=getattr(current_user, "username", ""),
                            cli=want_cli)
    if not res.get("started"):
        flash("Could not start the sweep on %s: %s"
              % (appliance.name, res.get("reason") or "unknown reason"), "danger")
        return redirect(url_for(page_endpoint))

    # One status call, synchronous, AFTER the sweep is safely started: the
    # version is what dates everything the sweep is about to write, and the
    # worker's own inventory merge stores it WITHOUT stamping when it was
    # observed. A failure here is reported and costs the sweep nothing.
    ver = discovery_run.detect_version(appliance)
    log_action("discovery_run.load", target=appliance.name,
               extra={"product": product, "cli": bool(want_cli),
                      "firmware": ver.get("firmware") or "",
                      "firmware_error": ver.get("error") or ""})
    msg = ("Sweeping the API catalog on %s%s. The coverage diff below updates "
           "when it finishes." % (appliance.name,
                                  " and capturing its CLI configuration" if want_cli
                                  else " (API only)"))
    if ver.get("checked"):
        msg += (" Running version read and stored: %s%s."
                % (ver["firmware"],
                   " (was %s)" % ver["previous"] if ver.get("changed")
                   and ver.get("previous") else ""))
    else:
        # Named, never silent: an unread version leaves the stored one in
        # place, and a stale version that nobody flagged is the reason this
        # read exists at all.
        msg += (" The running version could NOT be read (%s), so the stored "
                "one is whatever it was before this sweep."
                % (ver.get("error") or "unknown"))
    if refused:
        msg += " The CLI capture was skipped: %s." % refused
    flash(msg, "warning" if (refused or not ver.get("checked")) else "success")
    # ``dr_watch`` is how the card attaches to the sweep it just started. The
    # sweep has ALWAYS been a background job with a status endpoint; this page
    # was simply never told which appliance to poll, so its only feedback was a
    # flash message and the operator had to guess when to reload.
    return redirect(url_for(page_endpoint, dr_watch=appliance.id))


def context(product: str, *, run_endpoint: str = "", plan_endpoint: str = "",
            register_endpoint: str = "", load_endpoint: str = "") -> dict:
    """Template context for ``partials/_discovery_run.html``.

    Empty endpoint names mean the section renders its reason and stops — the
    same contract ``_clicoverage.context`` uses for FortiAnalyzer and
    FortiAuthenticator, which have no configuration dump to diff at all.
    """
    can_edit = bool(current_user.is_authenticated
                    and current_user.can(Permission.REGISTRY_EDIT))
    return {
        "dr_supported": product in cli_coverage.SUPPORTED_PRODUCTS,
        "dr_reason": cli_coverage.UNSUPPORTED_REASON.get(product, ""),
        "dr_can_run": can_edit,
        "dr_can_load": bool(current_user.is_authenticated
                            and current_user.can("appliances.apply")),
        "dr_budget": discovery_run.DEFAULT_BUDGET,
        "dr_max_budget": MAX_BUDGET,
        "dr_run_endpoint": run_endpoint,
        "dr_plan_endpoint": plan_endpoint,
        "dr_register_endpoint": register_endpoint,
        "dr_load_endpoint": load_endpoint,
    }


__all__ = ["MAX_BUDGET", "context", "plan_payload", "run_payload",
           "register_payload", "load"]
