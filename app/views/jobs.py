"""Background-jobs API + the Job Manager page.

Feature views START work via ``services.jobs`` (e.g. the firmware upload spawns a
sha256 finalize job); this blueprint lets the global toast UI
(``static/js/jobs.js``) POLL a single job or LIST the caller's recent/active jobs
(so a toast can reconnect after a page navigation), and hosts the **Job Manager**
(``/jobs/manager``, sidebar → Global → Jobs): every running + executed job with
owner / where / progress and Pause / Resume / Stop controls.

Scope: a regular user sees and controls their OWN jobs (keyed by ``job.by`` ==
username); an admin (``user_manage``) sees and controls EVERYONE's. All control
is cooperative and file-mediated — these endpoints only set flags; the worker
honours them at its next safe checkpoint (between devices / between items), so
an in-flight device write is never interrupted mid-call.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from ..services import jobs as jobsvc
from ..services.product_scope import visible_product

bp = Blueprint("jobs", __name__, url_prefix="/jobs")


def _me() -> str:
    return getattr(current_user, "username", "") or ""


def _is_admin() -> bool:
    can = getattr(current_user, "can", None)
    return bool(can and can("user_manage"))


def _own(job) -> bool:
    return job is not None and (job.get("by") or "") == _me()


def _can_see(job) -> bool:
    return job is not None and (_own(job) or _is_admin())


@bp.route("/manager", methods=["GET"])
@login_required
def manager():
    """The Job Manager page (Global → Jobs). Data arrives via /jobs/all polling."""
    return render_template("jobs/manager.html", is_admin=_is_admin())


@bp.route("/all", methods=["GET"])
@login_required
def all_jobs():
    """Job Manager feed. Admin → every user's jobs; others → own jobs only.
    Filters: ?status=running|paused|…  ?type=<job type>  ?limit=1..200."""
    status = (request.args.get("status") or "").strip() or None
    type_ = (request.args.get("type") or "").strip() or None
    try:
        limit = max(1, min(200, int(request.args.get("limit", 100))))
    except ValueError:
        limit = 100
    by = None if _is_admin() else _me()
    jobs = jobsvc.list_jobs(limit=limit, by=by, status=status, type_=type_)
    jobs = [j for j in jobs
            if visible_product((j.get("meta") or {}).get("product"))]
    return jsonify({"jobs": jobs, "admin": _is_admin(), "me": _me()})


@bp.route("/<job_id>", methods=["GET"])
@login_required
def get(job_id):
    job = jobsvc.get_job(job_id)
    if not _can_see(job):
        return jsonify({"error": "not found"}), 404
    return jsonify(job)


@bp.route("/", methods=["GET"])
@login_required
def index():
    active = (request.args.get("active") or "").lower() in ("1", "true", "yes")
    jobs = jobsvc.list_jobs(limit=30, by=_me(), active_only=active)
    jobs = [j for j in jobs
            if visible_product((j.get("meta") or {}).get("product"))]
    return jsonify({"jobs": jobs})


@bp.route("/<job_id>/cancel", methods=["POST"])
@login_required
def cancel(job_id):
    """Ask a running job to stop. Idempotent: cancelling an already-finished job
    just returns it. Refuses jobs flagged non-cancelable (e.g. a firmware flash
    already rebooting) — there is nothing to safely stop."""
    job = jobsvc.get_job(job_id)
    if not _can_see(job):
        return jsonify({"error": "not found"}), 404
    if not job.get("cancelable", True):
        return jsonify({"error": "This task cannot be stopped once started.",
                        "job": job}), 409
    updated = jobsvc.request_cancel(job_id)
    return jsonify({"ok": True, "job": updated or job})


@bp.route("/<job_id>/pause", methods=["POST"])
@login_required
def pause(job_id):
    """Ask a running job to pause at its next safe checkpoint. Gated by the same
    ``cancelable`` flag — work that can't be safely stopped (a firmware flash
    mid-reboot) can't be safely parked either."""
    job = jobsvc.get_job(job_id)
    if not _can_see(job):
        return jsonify({"error": "not found"}), 404
    if not job.get("cancelable", True):
        return jsonify({"error": "This task cannot be paused once started.",
                        "job": job}), 409
    if job.get("status") not in (jobsvc.PENDING, jobsvc.RUNNING):
        return jsonify({"error": "Only a running job can be paused.",
                        "job": job}), 409
    updated = jobsvc.request_pause(job_id)
    return jsonify({"ok": True, "job": updated or job})


@bp.route("/<job_id>/resume", methods=["POST"])
@login_required
def resume(job_id):
    job = jobsvc.get_job(job_id)
    if not _can_see(job):
        return jsonify({"error": "not found"}), 404
    if job.get("status") not in (jobsvc.PAUSING, jobsvc.PAUSED):
        return jsonify({"error": "This job is not paused.", "job": job}), 409
    updated = jobsvc.request_resume(job_id)
    return jsonify({"ok": True, "job": updated or job})
