"""/api/v1/events and /api/v1/triggers — outside systems start automations.

The orchestrator's external door (2026-10-22). A monitoring tool, a CI
pipeline or a ticketing system posts an event; every enabled trigger on
``api.event`` whose conditions match it starts its automations, exactly as an
alert would. The event is RECORDED like any other match, and its automations
run as jobs: the caller gets back what was queued, never waits for a walk.

* ``POST /events`` needs the ``write`` scope. The payload's ADOM is the
  token's; a Global token may name one. Nothing the caller sends can arm an
  automation: armed or not is a property of the automation, set in the
  console by somebody holding config_write.
* ``GET /triggers`` (``read``) lists the triggers, so a caller can see which
  ``type`` values anything listens to.
"""
from __future__ import annotations

from flask import g, jsonify, request

from ..extensions import limiter
from ..models_triggers import Trigger
from ..services import trigger_engine as TE
from ..services.audit import log_action
from . import bp
from .auth import audit_extra, token_required

_MAX_DATA = 32_000


def _err(status: int, code: str, message: str, **extra):
    body = {"error": code, "message": message}
    body.update(extra)
    return jsonify(body), status


@bp.route("/triggers", methods=["GET"])
@token_required("read")
def triggers_list():
    """Every trigger: key, name, event, enabled, conditions, automations bound."""
    rows = Trigger.query.order_by(Trigger.key.asc()).all()
    return jsonify({"triggers": [{
        "key": t.key, "name": t.name, "event": t.event, "enabled": bool(t.enabled),
        "conditions": t.conditions, "cooldown_minutes": t.cooldown_minutes,
        "rate_limit_per_hour": t.rate_limit_per_hour,
        "automations": [a.key for a in t.automations if a.enabled],
    } for t in rows]})


@bp.route("/events", methods=["POST"])
@limiter.limit("60/minute")
@token_required("write")
def events_post():
    """Post an ``api.event``. Body: ``{"type": str, "subject": str?,
    "appliance_id": int?, "product": str? (Global tokens only), "data": {}}``.

    Responses: 202 ``{event, matched, queued, rows}``; 400 bad body.
    """
    import json
    from ..services.product_scope import GLOBAL, concrete_products
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _err(400, "bad_request", "The body must be a JSON object.")
    etype = str(body.get("type") or "").strip()
    if not etype or len(etype) > 120:
        return _err(400, "bad_request", "'type' is required (at most 120 characters).")
    data = body.get("data") if body.get("data") is not None else {}
    if not isinstance(data, dict):
        return _err(400, "bad_request", "'data' must be a JSON object.")
    if len(json.dumps(data, default=str)) > _MAX_DATA:
        return _err(400, "too_large", "'data' is larger than %d bytes." % _MAX_DATA)
    aid = body.get("appliance_id")
    if aid not in (None, ""):
        try:
            aid = int(aid)
        except (TypeError, ValueError):
            return _err(400, "bad_request", "'appliance_id' must be an integer.")
    else:
        aid = None
    tok = getattr(g, "api_token", None)
    product = getattr(g, "product", "") or ""
    if product in ("", GLOBAL):
        want = str(body.get("product") or "").strip()
        if want and want not in concrete_products():
            return _err(400, "bad_request", "'product' %r is not an ADOM." % want)
        product = want
    payload = {"type": etype, "subject": str(body.get("subject") or "")[:200],
               "source": getattr(tok, "public_id", "") or "", "product": product,
               "appliance_id": aid, "data": data}
    rows = TE.emit("api.event", payload, by="api-token:%s" % payload["source"])
    log_action("trigger.api_event", target=etype,
               extra=audit_extra(subject=payload["subject"], rows=len(rows)))
    return jsonify({"event": "api.event", "type": etype,
                    "matched": len({r["trigger"] for r in rows}),
                    "queued": sum(1 for r in rows if r["status"] == "queued"),
                    "rows": rows}), 202
