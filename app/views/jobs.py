"""Background-jobs API — the read side of the generic jobs framework.

Feature views START work via ``services.jobs`` (e.g. the firmware upload spawns a
sha256 finalize job); this blueprint only lets the global toast UI
(``static/js/jobs.js``) POLL a single job or LIST the caller's recent/active jobs
so a toast can reconnect after a page navigation. Read-only + login-gated; a user
only ever sees their OWN jobs (keyed by ``job.by`` == username).
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from ..services import jobs as jobsvc

bp = Blueprint("jobs", __name__, url_prefix="/jobs")


def _me() -> str:
    return getattr(current_user, "username", "") or ""


@bp.route("/<job_id>", methods=["GET"])
@login_required
def get(job_id):
    job = jobsvc.get_job(job_id)
    if job is None or (job.get("by") or "") != _me():
        return jsonify({"error": "not found"}), 404
    return jsonify(job)


@bp.route("/", methods=["GET"])
@login_required
def index():
    active = (request.args.get("active") or "").lower() in ("1", "true", "yes")
    jobs = jobsvc.list_jobs(limit=30, by=_me(), active_only=active)
    return jsonify({"jobs": jobs})
