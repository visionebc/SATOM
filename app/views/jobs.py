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

from flask import Blueprint, abort, jsonify, render_template, request
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
    try:
        appliance_id = int(request.args["appliance"]) if request.args.get("appliance") else None
    except ValueError:
        appliance_id = None
    by = None if _is_admin() else _me()
    jobsvc.maybe_sweep_orphans()
    jobs = jobsvc.list_jobs(limit=limit, by=by, status=status, type_=type_,
                            appliance_id=appliance_id)
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
    """The toast dock's feed — the ONE consumer of this endpoint.

    ``background`` jobs are filtered out here, not hidden in the client: a
    monitoring sweep is housekeeping nobody is waiting on, and a floating
    window with a Stop button for work the operator never asked to watch is
    noise that trains them to dismiss the dock. They remain in full on the Job
    Manager (``/jobs/all``), and a failure still reaches the bell.
    """
    active = (request.args.get("active") or "").lower() in ("1", "true", "yes")
    # Retire ghosts before answering: a job whose worker no longer exists would
    # otherwise reopen a toast on every navigation, forever.
    jobsvc.maybe_sweep_orphans()
    jobs = jobsvc.list_jobs(limit=30, by=_me(), active_only=active)
    jobs = [j for j in jobs
            if not j.get("background")
            and visible_product((j.get("meta") or {}).get("product"))]
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


# ── device actions running as jobs (services/device_jobs) ───────────────────
def _safe_back(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw.startswith("/") or raw.startswith("//") or "\\" in raw:
        return ""
    return raw


@bp.route("/<job_id>/wait", methods=["GET"])
@login_required
def wait(job_id):
    """Where a classic form lands when its device action outlives the inline
    window: live progress + steps, Stop while it is still safe, and the
    action's own response once it finishes. Leaving the page does not stop
    anything — the job keeps running and the dock keeps showing it."""
    job = jobsvc.get_job(job_id)
    if not _can_see(job):
        abort(404)
    return render_template("jobs/wait.html", job=job,
                           back=_safe_back(request.args.get("back", "")))


@bp.route("/<job_id>/response", methods=["GET"])
@login_required
def response(job_id):
    """Replay the response the device action produced (redirect, page, JSON
    or file), with its flash messages, exactly as if it had run inline. Owner
    only: the body can carry device configuration."""
    from ..services import device_jobs
    job = jobsvc.get_job(job_id)
    if not _own(job):
        return jsonify({"error": "not found"}), 404
    if job.get("status") not in ("success", "error", "cancelled"):
        return jsonify({"error": "still running", "job": job}), 409
    cap = device_jobs.load_response(job_id)
    if cap is None:
        return jsonify({"error": "this job has no stored response",
                        "message": job.get("message") or ""}), 404
    if cap.get("truncated"):
        return jsonify({"error": "the response was too large to keep",
                        "message": job.get("message") or ""}), 410
    device_jobs.apply_session(cap.get("session"))
    return device_jobs.build_response(cap)
