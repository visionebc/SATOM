"""/api/v1 — the versioned, token-authenticated integration surface.

Deliberately NARROW and read-biased. What it exposes:

* ``GET  /api/v1/ping``                     — identity + scopes (any token)
* ``GET  /api/v1/appliances``               — device inventory + cached status
* ``GET  /api/v1/appliances/<id>``          — one device
* ``GET  /api/v1/actions``                  — the caller-created scheduled actions
* ``POST /api/v1/actions/<id>/run``         — trigger a NON-destructive action
* ``GET  /api/v1/actions/runs/<run_id>``    — poll a run's outcome

What it does NOT expose, by construction: firmware upgrade / flash / reboot and
any action flagged ``danger`` in the catalog — no scope can reach them.
"""
from __future__ import annotations

from flask import g, jsonify, request

from ..extensions import db, limiter
from ..models import Appliance, visible_appliance_or_404, visible_appliances
from ..models import ScheduledAction, ScheduledActionRun
from ..services import scheduled_actions as sa
from ..services.audit import log_action
from ..services.product_scope import scope_query
from . import bp
from .auth import audit_extra, token_required


def _owner():
    return getattr(g, "api_token_owner", None)


def _appliance_json(a: Appliance) -> dict:
    return {
        "id": a.id,
        "name": a.name,
        "kind": a.kind,
        "host": a.host,
        "port": a.port,
        "status": a.last_status or "unknown",
        "last_checked_at": a.last_checked_at.isoformat() if a.last_checked_at else None,
        "maintenance": bool(a.maintenance),
    }


def _token_can_touch_product(record_product: str) -> bool:
    """A token bound to a concrete ADOM may only act on that product; a
    ``global`` token may act on any."""
    tp = getattr(g.api_token, "product", "global")
    if tp == "global":
        return True
    return (record_product or "fortiweb") == tp


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

@bp.route("/ping", methods=["GET"])
@token_required("read")
def ping():
    tok = g.api_token
    return jsonify({
        "ok": True,
        "token": tok.public_id,
        "name": tok.name,
        "owner": getattr(tok.owner, "username", None),
        "scopes": tok.scope_list,
        "product": tok.product,
    })


# ---------------------------------------------------------------------------
# Appliances (read)
# ---------------------------------------------------------------------------

@bp.route("/appliances", methods=["GET"])
@token_required("read")
def list_appliances():
    q = visible_appliances(user=_owner()).order_by(Appliance.name)
    return jsonify({"appliances": [_appliance_json(a) for a in q.all()]})


@bp.route("/appliances/<int:id>", methods=["GET"])
@token_required("read")
def get_appliance(id):
    a = visible_appliance_or_404(id, user=_owner())
    return jsonify(_appliance_json(a))


# ---------------------------------------------------------------------------
# Scheduled actions (read + gated trigger)
# ---------------------------------------------------------------------------

def _action_json(row: ScheduledAction) -> dict:
    spec = sa.get_spec(row.action)
    danger = bool(spec and spec.danger)
    return {
        "id": row.id,
        "name": row.name,
        "action": row.action,
        "label": spec.label if spec else row.action,
        "scope": row.scope,
        "product": row.product,
        "enabled": bool(row.enabled),
        "schedule_kind": row.schedule_kind,
        "last_run": row.last_run.isoformat() if row.last_run else None,
        "last_status": row.last_status or "",
        "next_run": row.next_run.isoformat() if row.next_run else None,
        # Destructive actions are visible but NEVER API-runnable.
        "danger": danger,
        "api_runnable": (not danger),
    }


@bp.route("/actions", methods=["GET"])
@token_required("read")
def list_actions():
    q = scope_query(ScheduledAction.query, ScheduledAction.product)
    q = q.order_by(ScheduledAction.name)
    return jsonify({"actions": [_action_json(r) for r in q.all()]})


@bp.route("/actions/<int:id>/run", methods=["POST"])
@limiter.limit("30 per minute")
@token_required("write")
def run_action(id):
    row = db.session.get(ScheduledAction, id)
    if row is None:
        return jsonify({"error": "not_found", "message": "No such action."}), 404
    if not _token_can_touch_product(row.product):
        return jsonify({"error": "wrong_product",
                        "message": "This token's ADOM cannot run that action."}), 403

    spec = sa.get_spec(row.action)
    if spec is None:
        return jsonify({"error": "unknown_action",
                        "message": f"Action {row.action!r} is not in the catalog."}), 400
    # HARD BLOCK: destructive/firmware actions are never runnable via the API,
    # regardless of scope. They stay UI + Change-Request gated.
    if spec.danger:
        log_action("api.action_run_denied", target=f"action:{row.id}",
                   extra=audit_extra(action=row.action, reason="destructive"))
        return jsonify({
            "error": "destructive_blocked",
            "message": "Destructive actions (firmware upgrade/flash/reboot) "
                       "cannot be triggered via the API. Use the UI with an "
                       "approved Change Request.",
        }), 403
    if not row.enabled:
        return jsonify({"error": "disabled",
                        "message": "This action is disabled."}), 409

    run = sa.execute_and_record(row, trigger="api")
    if run is None:
        return jsonify({"error": "already_running",
                        "message": "This action is already running."}), 409

    log_action("api.action_run", target=f"action:{row.id}",
               extra=audit_extra(action=row.action, run_id=run.id, status=run.status))
    return jsonify({
        "ok": run.status in ("ok", "skipped"),
        "run_id": run.id,
        "action_id": row.id,
        "status": run.status,
        "summary": run.summary or "",
    })


@bp.route("/actions/runs/<int:run_id>", methods=["GET"])
@token_required("read")
def get_run(run_id):
    run = db.session.get(ScheduledActionRun, run_id)
    if run is None:
        return jsonify({"error": "not_found", "message": "No such run."}), 404
    parent = db.session.get(ScheduledAction, run.action_id)
    if parent is None or not _token_can_touch_product(parent.product):
        return jsonify({"error": "not_found", "message": "No such run."}), 404
    return jsonify({
        "run_id": run.id,
        "action_id": run.action_id,
        "status": run.status,
        "trigger": run.trigger,
        "summary": run.summary or "",
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
    })


# ---------------------------------------------------------------------------
# Errors — always JSON on this blueprint (never an HTML login redirect).
# ---------------------------------------------------------------------------

@bp.errorhandler(404)
def _404(_e):
    return jsonify({"error": "not_found"}), 404


@bp.errorhandler(429)
def _429(_e):
    return jsonify({"error": "rate_limited",
                    "message": "Too many requests."}), 429


@bp.errorhandler(500)
def _500(_e):
    return jsonify({"error": "server_error"}), 500
