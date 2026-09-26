"""Container operations -- the console for the Docker operations agent.

Admin-only (``user_manage``), like Software Update and Services, whose
container counterparts these are. Every write here is an ENQUEUE
(``app/services/container_ops``); the ``agent`` service does the work and
writes the status rows this page polls.

On a host install the page says so and offers nothing: the host has its own
pages for all four operations.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from .. import runtime
from ..auth.decorators import require_permission
from ..services import container_ops as co
from ..services import self_update as su
from ..services.audit import log_action

bp = Blueprint("container_ops", __name__, url_prefix="/system/container")


@bp.app_context_processor
def _satom_container_nav():
    # Named so it cannot shadow anything a view passes (§194: a render
    # argument called `products` once hid the layout's global of that name).
    return {"satom_container_runtime": runtime.is_container_runtime()}


def _who() -> str:
    return getattr(current_user, "username", "?")


@bp.route("/")
@login_required
@require_permission("user_manage")
def index():
    return render_template(
        "container_ops/index.html",
        is_container=runtime.is_container_runtime(),
        summary=runtime.summary(),
        agent=co.state(),
        services=co.service_rows() if runtime.delegated("service_control") else [],
        versions=co.versions(),
        history=co.recent(),
        watch=request.args.get("watch", ""),
    )


@bp.route("/state")
@login_required
@require_permission("user_manage")
def state():
    st = co.state()
    return jsonify({
        "agent": {k: st[k] for k in ("declared", "live", "age", "problem")},
        "services": co.service_rows() if runtime.delegated("service_control") else [],
        "summary": runtime.summary(),
    })


def _queued(uid: str, what: str):
    log_action("container_ops.%s" % what, detail="%s on %s" % (uid, su.this_node_name()))
    return jsonify({"uid": uid, "node": su.this_node_name()})


@bp.route("/service", methods=["POST"])
@login_required
@require_permission("user_manage")
def service_action():
    p = request.get_json(silent=True) or {}
    try:
        uid = co.request_restart(p.get("service", ""), p.get("action", ""), by=_who())
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except co.AgentUnavailable as exc:
        return jsonify({"error": str(exc)}), 409
    return _queued(uid, "service")


@bp.route("/update", methods=["POST"])
@login_required
@require_permission("user_manage")
def update():
    p = request.get_json(silent=True) or {}
    if (p.get("confirm") or "") != "UPDATE":
        return jsonify({"error": "type UPDATE to confirm"}), 400
    try:
        uid = co.request_update(p.get("version", ""), by=_who())
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except co.AgentUnavailable as exc:
        return jsonify({"error": str(exc)}), 409
    return _queued(uid, "update")


@bp.route("/cert", methods=["POST"])
@login_required
@require_permission("user_manage")
def cert():
    cert_f, key_f, chain_f = (request.files.get("cert"), request.files.get("key"),
                              request.files.get("chain"))
    if not cert_f or not key_f or not cert_f.filename or not key_f.filename:
        return jsonify({"error": "cert and key PEM files are required"}), 400
    from ..services import cert_service as cs
    try:
        chain = chain_f.read() if (chain_f and chain_f.filename) else None
        # Through cert_service on purpose: the same validation, journal and
        # audit as the Node certificate page, whose container branch this is.
        info = cs.import_pem(cert_f.read(), key_f.read(), chain, by=_who())
    except runtime.CapabilityUnavailable as exc:
        return jsonify({"error": exc.reason}), 409
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)[:300]}), 400
    log_action("container_ops.cert", "security", detail=info.get("subject"))
    return jsonify({"ok": True, "cert": {k: info.get(k) for k in
                                         ("subject", "issuer", "not_after", "days_left", "source")}})


@bp.route("/status/<uid>")
@login_required
@require_permission("user_manage")
def status(uid):
    st = su.update_status(uid)
    if st is None:
        return jsonify({"state": "unknown"}), 404
    return jsonify(st)
