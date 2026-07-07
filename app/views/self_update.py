"""Self-update admin page — update the manager's own code + Python deps,
staged across the HA nodes (standby first, primary after validation).

Admin-only (``user_manage``). The write path is an ENQUEUE only: the actual
privileged update runs in ``fortinet-manager-updater.service`` (root), so the
web worker is never the thing restarting itself.
"""
from __future__ import annotations

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, jsonify)
from flask_login import login_required, current_user

from ..auth.decorators import require_permission
from ..services import self_update as su

bp = Blueprint("self_update", __name__, url_prefix="/self-update")


@bp.route("/")
@login_required
@require_permission("user_manage")
def index():
    su.self_report()  # refresh this node's entry in the shared (replicated) state
    check = su.check_remote(fetch=False)  # cheap: no network on page load
    return render_template(
        "self_update/index.html",
        current=check["current"],
        nodes=su.node_reports(),
        this_node=su.this_node_name(),
        this_role=su.node_role(),
        validated=su.validated_state(),
        history=su.recent_updates(),
        branch=su.BRANCH,
        watch=request.args.get("watch", ""),
    )


@bp.route("/check", methods=["POST"])
@login_required
@require_permission("user_manage")
def check():
    return jsonify(su.check_remote(fetch=True))


@bp.route("/apply", methods=["POST"])
@login_required
@require_permission("user_manage")
def apply():
    info = su.check_remote(fetch=True)
    target = request.form.get("target") or info["target_sha"]
    role = su.node_role()

    # ---- the staged-rollout SEGURO ------------------------------------
    others = [n for n in su.load_nodes() if n.get("name") != su.this_node_name()]
    if role == "primary" and others and not su.can_apply_to_primary(target):
        flash("Blocked by the staged-rollout safeguard: update the STANDBY to "
              "this revision and let it pass its health check first, then the "
              "PRIMARY unlocks.", "warning")
        return redirect(url_for("self_update.index"))

    if info["behind"] == 0 and target == info["current"]["sha"]:
        flash("Already up to date — nothing to apply.", "info")
        return redirect(url_for("self_update.index"))

    uid = su.request_update(
        target,
        by=getattr(current_user, "username", "?"),
        do_pip="do_pip" in request.form,
        do_migrate="do_migrate" in request.form,
    )
    flash("Update queued (%s). The privileged runner is applying it — watch the "
          "live status below. The service will restart mid-update." % uid,
          "success")
    return redirect(url_for("self_update.index", watch=uid))


@bp.route("/status/<uid>")
@login_required
@require_permission("user_manage")
def status(uid):
    st = su.update_status(uid)
    if st:
        su.reconcile_interlock(st)  # unlock the primary once the standby validated
    return jsonify(st or {"state": "unknown"})
