"""Lease-lock API for safe multi-user editing (Phase 4).

JSON endpoints driven by a small JS heartbeat on every edit page. The CSRF
token is injected automatically by static/js/main.js, so these accept the
standard ``X-CSRFToken`` header.

resource_key convention: ``"<kind>:<name>"`` (e.g. ``server_policy:pol-x``),
scoped per appliance.
"""
from __future__ import annotations

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

from ..services import lock_service

bp = Blueprint("locks", __name__, url_prefix="/api/locks")


def _label():
    return getattr(current_user, "username", None) or "user"


def _uid():
    return getattr(current_user, "id", None)


def _args():
    data = request.get_json(silent=True) or request.form
    appliance_id = data.get("appliance_id")
    resource_key = data.get("resource_key")
    try:
        appliance_id = int(appliance_id)
    except (TypeError, ValueError):
        appliance_id = None
    return appliance_id, resource_key


@bp.route("/acquire", methods=["POST"])
@login_required
def acquire():
    appliance_id, key = _args()
    if appliance_id is None or not key:
        return jsonify(ok=False, error="appliance_id and resource_key required"), 400
    ok, info = lock_service.acquire(
        appliance_id, key, user_id=_uid(), owner_label=_label())
    return jsonify(ok=ok, mine=ok, lock=info)


@bp.route("/heartbeat", methods=["POST"])
@login_required
def heartbeat():
    appliance_id, key = _args()
    if appliance_id is None or not key:
        return jsonify(ok=False, error="bad args"), 400
    ok, info = lock_service.heartbeat(appliance_id, key, user_id=_uid())
    return jsonify(ok=ok, lock=info)


@bp.route("/release", methods=["POST"])
@login_required
def release():
    appliance_id, key = _args()
    if appliance_id is None or not key:
        return jsonify(ok=False, error="bad args"), 400
    ok = lock_service.release(appliance_id, key, user_id=_uid())
    return jsonify(ok=ok)


@bp.route("/steal", methods=["POST"])
@login_required
def steal():
    appliance_id, key = _args()
    if appliance_id is None or not key:
        return jsonify(ok=False, error="bad args"), 400
    ok, info = lock_service.steal(
        appliance_id, key, user_id=_uid(), owner_label=_label())
    return jsonify(ok=ok, lock=info)


@bp.route("/status", methods=["GET"])
@login_required
def status():
    try:
        appliance_id = int(request.args.get("appliance_id"))
    except (TypeError, ValueError):
        return jsonify(ok=False, error="appliance_id required"), 400
    key = request.args.get("resource_key")
    if not key:
        return jsonify(ok=False, error="resource_key required"), 400
    info = lock_service.status(appliance_id, key)
    mine = bool(info and info.get("owner_user_id") == _uid())
    return jsonify(ok=True, locked=bool(info), mine=mine, lock=info)
