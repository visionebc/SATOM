"""High Availability admin page — the cluster's own view: the node architecture
graph, the deployment mode (HA/standalone), the HA node registry (add / update /
remove nodes), live Postgres streaming-replication state, and the guarded manual
failover.

Split out of the Software Update page (2026-07-12) so the two concerns each get
their own nav entry: *Software Update* (check/apply the manager's code) and
*High Availability* (the cluster topology and how the nodes are kept in sync).

Admin-only (``user_manage``). All reads are local (the app's own Postgres) plus
best-effort HTTP probes of the peer — a page load never touches a FortiWeb. The
mutating actions (mode, node registry, promote) live in the ``self_update``
blueprint and redirect back here; this view is read-only render + the graph.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request
from flask_login import login_required

from ..auth.decorators import require_permission
from ..services import self_update as su
from ..services import cluster
from ..services import reconciler

bp = Blueprint("ha", __name__, url_prefix="/high-availability")


@bp.route("/")
@login_required
@require_permission("user_manage")
def index():
    su.self_report()  # refresh this node's entry in the shared (replicated) state
    return render_template(
        "high_availability/index.html",
        nodes=su.node_reports(),
        this_node=su.this_node_name(),
        this_role=su.node_role(),
        validated=su.validated_state(),
        branch=su.BRANCH,
        ha=cluster.full_state(),
        deploy_mode=reconciler.deploy_mode_orm(),
        reconcile=reconciler.last_status_orm(),
        watch_promote=request.args.get("watch_promote", ""),
    )
