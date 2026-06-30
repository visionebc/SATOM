"""Analysis dashboard — DB-first fleet & per-device analytics.

Replaces the old live-FortiView page: every number comes from the local cache
(``services.analysis``), so the page never touches an appliance. Filters are
applied dynamically; the page fetches ``/analysis/data`` as JSON and (re)draws
all charts/tables client-side.
"""
import re

from flask import (Blueprint, render_template, request, jsonify, redirect,
                   url_for, flash)
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import analysis as ana
from ..services.audit import log_action

bp = Blueprint('analysis', __name__, url_prefix='/analysis')


def _parse_filters(args) -> dict:
    def _ids(raw_list):
        out = []
        for raw in raw_list:
            for part in str(raw).split(','):
                part = part.strip()
                if part.isdigit():
                    out.append(int(part))
        return out
    return {
        "device_ids": _ids(args.getlist('device_ids')),
        "platform": (args.get('platform') or '').strip(),
        "zone": (args.get('zone') or '').strip(),
        "line": (args.get('line') or '').strip(),
        "department": (args.get('department') or '').strip(),
        "date_from": (args.get('date_from') or '').strip(),
        "date_to": (args.get('date_to') or '').strip(),
    }


@bp.route('/')
@login_required
def index():
    return render_template('analysis/index.html', options=ana.filter_options())


@bp.route('/data')
@login_required
def data():
    return jsonify(ana.analyze(_parse_filters(request.args)))


@bp.route('/dashboard/<int:id>')
@login_required
def dashboard(id):
    # Back-compat: the device detail page links here. Open the dashboard scoped
    # to that one device.
    return redirect(url_for('analysis.index', device_ids=id))


@bp.route('/appid-regex', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_appid_regex():
    raw = (request.form.get('appid_regex') or '').strip()
    try:
        stored = ana.set_appid_regex(raw)
        log_action('analysis.appid_regex', detail=stored)
        flash(f'App ID pattern saved: {stored}', 'success')
    except re.error as exc:
        flash(f'Invalid regular expression: {exc}', 'danger')
    return redirect(url_for('analysis.index'))


# --------------------------------------------------------------------------- #
#  Deep analytics (the WPP subtree + Server-Policy graph captured at depth)     #
# --------------------------------------------------------------------------- #
from flask import current_app  # noqa: E402
from flask_login import current_user  # noqa: E402

from ..services import analysis_deep  # noqa: E402


def _deep_device_ids(args):
    """device_id (repeatable) + comma-separated device_ids -> list or None."""
    ids = list(args.getlist('device_id', type=int))
    ids += _parse_filters(args)["device_ids"]
    return sorted(set(ids)) or None


@bp.route('/wpp-matrix')
@login_required
def wpp_matrix():
    return jsonify(analysis_deep.wpp_feature_matrix(
        device_ids=_deep_device_ids(request.args)))


@bp.route('/subelements')
@login_required
def subelements():
    rows = analysis_deep.subelement_counts(device_ids=_deep_device_ids(request.args))
    top = request.args.get('top', type=int)
    return jsonify(rows[:top] if top else rows)


@bp.route('/orphans')
@login_required
def orphans():
    return jsonify(analysis_deep.orphan_objects(
        device_ids=_deep_device_ids(request.args)))


@bp.route('/freshness')
@login_required
def freshness():
    return jsonify(ana.deep_freshness(device_ids=_deep_device_ids(request.args)))


@bp.route('/wpp/<int:appliance_id>/<path:mkey>')
@login_required
def wpp_drill(appliance_id, mkey):
    return jsonify(analysis_deep.wpp_drilldown(appliance_id, mkey) or {})


@bp.route('/policy/<int:appliance_id>/<path:mkey>')
@login_required
def policy_drill(appliance_id, mkey):
    return jsonify(analysis_deep.server_policy_drilldown(appliance_id, mkey) or {})


@bp.route('/deep/run', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def deep_run():
    """Kick off a fleet deep-capture (bounded device-level pool, resumable). With
    no device_id given, sweeps every FortiWeb. Returns the job id to poll."""
    from ..models import Appliance
    from ..services import deep_jobs
    ids = _deep_device_ids(request.form) or _deep_device_ids(request.args)
    if not ids:
        ids = [a.id for a in Appliance.query.filter_by(kind='fortiweb').all()]
    if not ids:
        return jsonify({"started": False, "reason": "no devices"}), 400
    max_workers = request.form.get('max_workers', type=int) or 8
    job = deep_jobs.start_fleet_job(current_app._get_current_object(), ids,
                                    by=getattr(current_user, 'username', ''),
                                    max_workers=max_workers)
    log_action('analysis.deep_run', detail=f"{len(ids)} device(s), job={job['job_id']}")
    return jsonify({"started": True, "job": job})


@bp.route('/deep/objects')
@login_required
def deep_objects():
    kind = (request.args.get('kind') or 'wpp').lower()
    logical = 'server_policy' if kind in ('policy', 'server_policy') else 'web_protection_profile'
    return jsonify(analysis_deep.deep_objects(
        device_ids=_deep_device_ids(request.args), logical_name=logical))


@bp.route('/deep/job/<job_id>')
@login_required
def deep_job(job_id):
    from ..services import deep_jobs
    return jsonify(deep_jobs.load_job(job_id) or {"error": "not found"})
