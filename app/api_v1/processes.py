"""/api/v1/processes — walk a Process from outside, and read what a walk did.

The NAF Orchestrator block asks that a flow be startable by machines, not
only by a button. This is that door, and it is as narrow as the button:

* ``GET /processes`` lists the processes the token's ADOM may see — the same
  rule the console applies (``process_engine.visible_processes``), never a
  second author of visibility.
* ``POST /processes/<id>/run`` starts a walk. ``armed`` defaults to **false**:
  a walk from the API is a REHEARSAL unless the caller says otherwise, and
  saying otherwise needs the explicit ``process_arm`` capability on top of the
  ``write`` scope (``models_api_token.EXPLICIT_ONLY_CAPABILITIES``) — a token
  minted before this surface existed can rehearse, and cannot write.
* ``GET /process-runs/<id>`` returns the run and its steps, so a caller can
  poll a walk that parked on a manual gate.

The walk runs INLINE in the request (like the Run button): the caller asked
for it and waits for the answer, which is the opposite of an event trigger,
where the thing that noticed the event must not wait (``process_triggers``).
"""
from __future__ import annotations

from flask import g, jsonify, request

from ..extensions import limiter
from ..models import db, visible_appliance_or_404
from ..models_process import TRIGGER_API, Process, ProcessRun
from ..services import process_engine as engine
from ..services import process_kinds as pk
from ..services.audit import log_action
from . import bp
from .auth import audit_extra, token_required


def _err(status: int, code: str, message: str, **extra):
    body = {"error": code, "message": message}
    body.update(extra)
    return jsonify(body), status


def _token():
    return getattr(g, "api_token", None)


def _visible(proc) -> bool:
    """The token's ADOM may see this process (same rule as the console)."""
    return engine.may_run_here(proc, product=getattr(g, "product", "") or "")


def _process_json(proc, *, with_graph: bool = False) -> dict:
    graph = proc.graph()
    out = {
        "id": proc.id, "key": proc.key, "name": proc.name,
        "description": proc.description or "",
        "products": list(proc.products or []),
        "enabled": bool(proc.enabled),
        "needs_appliance": pk.needs_appliance(graph),
        "writes": pk.writes(graph),
        "steps": len(graph.get("nodes", [])),
        "trigger_event": proc.trigger_event or "",
        "trigger_filter": proc.trigger_filter or {},
        "armed_on_trigger": bool(proc.armed_on_trigger),
        "trigger_rate_limit": int(proc.trigger_rate_limit or 0),
        "updated_at": proc.updated_at.isoformat() if proc.updated_at else None,
    }
    if with_graph:
        out["graph"] = graph
    return out


def _step_json(st) -> dict:
    output, undo = pk.decode_undo(st.output or "")
    return {
        "seq": st.seq, "key": st.node_key, "kind": st.kind, "label": st.label,
        "status": st.status, "detail": st.detail or "", "output": output,
        "dry_run": bool(st.dry_run), "undo_recorded": undo is not None,
        "started_at": st.started_at.isoformat() if st.started_at else None,
        "ended_at": st.ended_at.isoformat() if st.ended_at else None,
    }


def _run_json(run, *, with_steps: bool = True) -> dict:
    out = {
        "id": run.id, "process_id": run.process_id, "process_key": run.process_key,
        "process_name": run.process_name, "product": run.product or "",
        "appliance_id": run.appliance_id, "appliance": run.appliance_name or "",
        "armed": bool(run.armed), "status": run.status, "verdict": run.verdict or "",
        "summary": run.summary or "", "trigger": run.trigger,
        "trigger_key": run.trigger_key or "", "started_by": run.started_by or "",
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "ended_at": run.ended_at.isoformat() if run.ended_at else None,
        "waiting_node": run.waiting_node or "",
        "counts": run.counts(),
    }
    if with_steps:
        out["steps"] = [_step_json(s) for s in run.steps]
    return out


# --------------------------------------------------------------------------- #
#  Processes                                                                    #
# --------------------------------------------------------------------------- #
@bp.route("/processes", methods=["GET"])
@token_required("read")
def processes_list():
    """List the processes the token's ADOM may see.

    Responses: 200 ``{"processes": [...]}``.
    """
    rows = engine.visible_processes(getattr(g, "product", "") or "")
    return jsonify({"processes": [_process_json(p) for p in rows]})


@bp.route("/processes/<int:id>", methods=["GET"])
@token_required("read")
def processes_get(id):
    """One process, with its diagram.

    Responses: 200 the process; 404 when the token's ADOM cannot see it.
    """
    proc = db.session.get(Process, id)
    if proc is None or not _visible(proc):
        return _err(404, "not_found", "No such process.")
    return jsonify(_process_json(proc, with_graph=True))


@bp.route("/processes/<int:id>/run", methods=["POST"])
@limiter.limit("30/minute")
@token_required("write")
def processes_run(id):
    """Walk a process now. Body: ``{"appliance_id": int|null, "armed": bool}``.

    ``armed`` defaults to false (a rehearsal: every write step dry-runs).
    ``armed: true`` needs the explicit ``process_arm`` capability.
    Responses: 200 the run with its steps; 400 bad body / the diagram cannot
    run / a device is needed; 403 ``capability_denied``; 404; 409 disabled.
    """
    proc = db.session.get(Process, id)
    if proc is None or not _visible(proc):
        return _err(404, "not_found", "No such process.")
    if not proc.enabled:
        return _err(409, "disabled", "This process is disabled.")
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return _err(400, "bad_request", "The body must be a JSON object.")

    graph = proc.graph()
    problems = pk.validate_graph(graph)
    if problems:
        return _err(400, "invalid_diagram",
                    "This diagram cannot run yet: %s" % problems[0], problems=problems)

    appliance = None
    aid = body.get("appliance_id")
    if aid not in (None, ""):
        try:
            aid = int(aid)
        except (TypeError, ValueError):
            return _err(400, "bad_request", "'appliance_id' must be an integer.")
        appliance = visible_appliance_or_404(aid, user=getattr(g, "api_token_owner", None))
    if pk.needs_appliance(graph) and appliance is None:
        return _err(400, "appliance_required",
                    "This process has steps that act on a device — give 'appliance_id'.")

    armed = bool(body.get("armed", False))
    if armed:
        tok = _token()
        ok, code, msg = tok.authorize_object("process_arm")
        if not ok:
            return _err(403, code, msg)
        if not pk.writes(graph):
            armed = False  # same rule as the Run button: arming a read-only plan is noise

    tok = _token()
    run = engine.start_run(
        proc, appliance=appliance, armed=armed, trigger=TRIGGER_API,
        user=getattr(getattr(g, "api_token_owner", None), "username", "") or "",
        product=getattr(g, "product", "") or "",
        trigger_key="api-token:%s" % (tok.public_id if tok is not None else ""))
    log_action("process.run", target=proc.key,
               extra=audit_extra(run=run.id, armed=armed,
                                 appliance=run.appliance_name,
                                 status=run.status, verdict=run.verdict))
    return jsonify(_run_json(run))


@bp.route("/process-runs/<int:id>", methods=["GET"])
@token_required("read")
def process_runs_get(id):
    """One walk and its steps (poll a run parked on a manual gate here).

    Responses: 200 the run; 404 when the token's ADOM cannot see its process.
    """
    run = db.session.get(ProcessRun, id)
    if run is None:
        return _err(404, "not_found", "No such run.")
    proc = db.session.get(Process, run.process_id) if run.process_id else None
    if proc is None:
        # A run whose process is gone is shown only to a Global token — the
        # console applies the same rule (views.process._run_or_404).
        if (getattr(g, "product", "") or "") != "global":
            return _err(404, "not_found", "No such run.")
    elif not _visible(proc):
        return _err(404, "not_found", "No such run.")
    return jsonify(_run_json(run))
