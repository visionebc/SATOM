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
from ..services import cluster
from ..services import reconciler

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
        ha=cluster.full_state(),
        deploy_mode=reconciler.deploy_mode_orm(),
        reconcile=reconciler.last_status_orm(),
        watch_promote=request.args.get("watch_promote", ""),
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


@bp.route("/ha-mode", methods=["POST"])
@login_required
@require_permission("user_manage")
def set_mode():
    """Switch the deployment mode standalone <-> ha. The setting lives in
    the replicated app_settings table, so it can only be WRITTEN where
    Postgres is read-write: the primary."""
    mode = (request.form.get("mode") or "").strip().lower()
    if mode not in ("ha", "standalone"):
        flash("Invalid deployment mode.", "danger")
        return redirect(url_for("self_update.index"))
    if su.node_role() != "primary":
        flash("The deployment mode is stored in the replicated settings — "
              "change it on the PRIMARY node (this node's database is "
              "read-only).", "warning")
        return redirect(url_for("self_update.index"))
    su.set_ha_mode(mode)
    flash("Deployment mode set to %s." % mode.upper(), "success")
    return redirect(url_for("self_update.index"))


@bp.route("/deploy-mode", methods=["POST"])
@login_required
@require_permission("user_manage")
def set_deploy_mode():
    """Toggle deploy AUTOMATION: 'auto' (reconciler drives the staged rollout)
    or 'manual' (reconciler only observes; operator applies). Replicated
    setting -> writable on the PRIMARY only."""
    mode = (request.form.get("mode") or "").strip().lower()
    if mode not in ("auto", "manual"):
        flash("Invalid deploy mode.", "danger")
        return redirect(url_for("self_update.index"))
    if su.node_role() != "primary":
        flash("Deploy automation is a replicated setting \u2014 change it on the "
              "PRIMARY node (this node's database is read-only).", "warning")
        return redirect(url_for("self_update.index"))
    reconciler.set_deploy_mode(mode)
    flash("Deploy automation set to %s. In AUTO the reconciler drives the staged "
          "rollout (standby first, health-gated, then primary); in MANUAL it "
          "only observes and you apply by hand." % mode.upper(), "success")
    return redirect(url_for("self_update.index"))


@bp.route("/promote", methods=["POST"])
@login_required
@require_permission("user_manage")
def promote():
    """Guarded MANUAL failover: promote THIS node's Postgres to primary. Enqueue
    only — the privileged runner runs fm-promote.sh. Requires typing the node's
    hostname to confirm; only valid on a standby."""
    confirm = (request.form.get("confirm_host") or "").strip()
    this_node = su.this_node_name()
    if not cluster.promote_eligible():
        flash("This node is not a standby — promotion is only valid on the node "
              "currently in recovery.", "warning")
        return redirect(url_for("self_update.index"))
    if confirm != this_node:
        flash("Confirmation failed: type this node's hostname (%s) exactly to "
              "promote it." % this_node, "danger")
        return redirect(url_for("self_update.index"))
    uid = cluster.request_promote(by=getattr(current_user, "username", "?"))
    flash("Failover queued (%s). The privileged runner is promoting this node to "
          "PRIMARY and starting the app — watch the status below. Only promote "
          "when the old primary is confirmed DOWN." % uid, "success")
    return redirect(url_for("self_update.index", watch_promote=uid))


@bp.route("/promote-status/<uid>")
@login_required
@require_permission("user_manage")
def promote_status(uid):
    return jsonify(cluster.promote_status(uid) or {"state": "unknown"})


@bp.route("/nodes", methods=["POST"])
@login_required
@require_permission("user_manage")
def save_node():
    """Register / update the secondary HA node from the admin console (writes
    data/ha_nodes.json; rsync carries it to the peer on the next data sync)."""
    name = (request.form.get("name") or "").strip()
    host = (request.form.get("host") or "").strip()
    desc = (request.form.get("desc") or "").strip()
    if not name or not host:
        flash("Both a node name (hostname) and a host/IP are required.", "danger")
    else:
        su.upsert_node(name, host, desc)
        flash("HA node '%s' (%s) saved. It propagates to the peer on the next "
              "data sync; its live state is probed on this page." % (name, host),
              "success")
    return redirect(url_for("self_update.index"))


@bp.route("/nodes/delete", methods=["POST"])
@login_required
@require_permission("user_manage")
def delete_node():
    name = (request.form.get("name") or "").strip()
    if name == su.this_node_name():
        flash("Cannot remove this node (self) from the HA registry.", "warning")
    else:
        su.remove_node(name)
        flash("HA node '%s' removed from the registry." % name, "info")
    return redirect(url_for("self_update.index"))
