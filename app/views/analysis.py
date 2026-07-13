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
from ..models import visible_appliances, visible_appliance_or_404
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
    from flask import g
    if getattr(g, 'product', None) == 'fortianalyzer':
        return render_template('analysis/faz.html', options=ana.filter_options())
    return render_template('analysis/index.html', options=ana.filter_options())


@bp.route('/data')
@login_required
def data():
    return jsonify(ana.analyze(_parse_filters(request.args)))


@bp.route('/faz-ops')
@login_required
def faz_ops():
    """LIVE FortiAnalyzer operational metrics: incoming log rate + per-ADOM
    storage/quota, read straight from the appliance via JSON-RPC. This is the
    ONE endpoint in the Analysis area that leaves the DB-first contract, on
    purpose (log rate / storage are excluded from the SoT harvest)."""
    from datetime import datetime
    from ..clients.fortianalyzer import FortiAnalyzerClient

    appls = visible_appliances().filter_by(kind='fortianalyzer').all()
    out = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "devices": [a.name for a in appls],
        "lograte": {"total": 0, "devs": []},
        "storage": {"adoms": [], "total": {"analytics_used": 0,
                    "analytics_max": 0, "archive_used": 0, "archive_max": 0}},
        "error": None,
    }
    if not appls:
        out["error"] = "No FortiAnalyzer appliance in scope"
        return jsonify(out)

    def _num(v):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return 0

    errors = []
    seen = set()
    for a in appls:
        c = FortiAnalyzerClient(a)
        try:
            c.login()
        except Exception as exc:  # noqa: BLE001 — transport/auth
            errors.append(f"{a.name}: login {type(exc).__name__}")
            continue
        try:
            rows, err = c.list_with_error('storage_info')
            if err:
                errors.append(f"{a.name}: storage {err}")
            for r in rows or []:
                if not isinstance(r, dict):
                    continue
                name = (str(r.get('adomname') or '').strip() or '(root)')
                key = (a.id, name)
                if key in seen:
                    continue
                seen.add(key)
                au, am = _num(r.get('analytics-storage-usage')), _num(r.get('analytics-storage-max'))
                ru, rm = _num(r.get('archive-storage-usage')), _num(r.get('archive-storage-max'))
                out["storage"]["adoms"].append({
                    "name": name,
                    "analytics_used": au, "analytics_max": am,
                    "archive_used": ru, "archive_max": rm,
                    "analytics_days_config": _num(r.get('analytics-config-days')),
                    "archive_days_config": _num(r.get('archive-config-days')),
                })
                t = out["storage"]["total"]
                t["analytics_used"] += au
                t["analytics_max"] += am
                t["archive_used"] += ru
                t["archive_max"] += rm

            lrows, lerr = c.list_with_error('logview_logstats')
            if lerr:
                errors.append(f"{a.name}: logstats {lerr}")
            for stat in lrows or []:
                if not isinstance(stat, dict):
                    continue
                for dev in (stat.get('devs') or []):
                    if not isinstance(dev, dict):
                        continue
                    rate = 0
                    for k in ('lograte', 'log-rate', 'rate', 'lograte_avg'):
                        if k in dev:
                            rate = _num(dev.get(k))
                            break
                    nm = dev.get('devname') or dev.get('name') or dev.get('devid') or '?'
                    out["lograte"]["devs"].append({"name": str(nm), "rate": rate})
                    out["lograte"]["total"] += rate
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{a.name}: {type(exc).__name__}: {exc}")
        finally:
            try:
                c.logout()
            except Exception:  # noqa: BLE001
                pass

    out["storage"]["adoms"].sort(key=lambda x: -x["analytics_used"])
    out["lograte"]["devs"].sort(key=lambda x: -x["rate"])
    if errors and not out["storage"]["adoms"] and not out["lograte"]["devs"]:
        out["error"] = "; ".join(errors)
    return jsonify(out)


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


@bp.route('/deep/inventory')
@login_required
def inventory():
    """Fleet cardinality: policies, distinct/unique pools, back-ends +
    ports, VIPs, SNI, certificates — over the deep cache."""
    return jsonify(analysis_deep.fleet_inventory(
        device_ids=_deep_device_ids(request.args)))


@bp.route('/freshness')
@login_required
def freshness():
    return jsonify(ana.deep_freshness(device_ids=_deep_device_ids(request.args)))


@bp.route('/deep/wpp/<int:appliance_id>/<path:mkey>')
@login_required
def wpp_drill(appliance_id, mkey):
    return jsonify(analysis_deep.wpp_drilldown(appliance_id, mkey) or {})


@bp.route('/deep/policy/<int:appliance_id>/<path:mkey>')
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
        ids = [a.id for a in visible_appliances().filter_by(kind='fortiweb').all()]
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
