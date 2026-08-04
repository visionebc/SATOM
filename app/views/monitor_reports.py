"""Reports — persisted daily / weekly / monthly summaries of the monitors.

A chart can be read to reach a conclusion. A report states one, keeps it, and
can be mailed to somebody who never opens the console. That is the whole
difference, and it is why these are stored rather than recomputed on view: raw
samples age out at ``probe.retention``, so a summary rebuilt six months later
would quietly answer from coarser data than the one the operator read at the
time — while looking identical.

Reads need VIEW. Generating, mailing and deleting need CONFIG_WRITE. Reports
carry the product that produced them, so a FortiADC report never surfaces in the
FortiWeb ADOM.
"""
from __future__ import annotations

from datetime import datetime

from flask import (Blueprint, Response, jsonify, render_template, request)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Permission, db
from ..models_analytics import MonitorReport
from ..services import monitor_reports as mr
from ..services.audit import log_action

bp = Blueprint('monitor_reports', __name__, url_prefix='/monitoring/reports')


def _product() -> str:
    from ..services.product_scope import GLOBAL, session_product
    p = session_product() or GLOBAL
    return "" if p == GLOBAL else p


def _scoped():
    """Reports this ADOM may read.

    Global sees everything — it is the ADOM that already sees every device. A
    product ADOM sees only its own, so a report built while scoped to FortiADC
    does not appear under FortiWeb.
    """
    prod = _product()
    q = MonitorReport.query
    if prod:
        q = q.filter(MonitorReport.product == prod)
    return q.order_by(MonitorReport.period_start.desc(),
                      MonitorReport.id.desc())


def _get(rid: int):
    return _scoped().filter(MonitorReport.id == rid).first()


@bp.route('/')
@login_required
def index():
    rows = _scoped().limit(200).all()
    return render_template(
        'monitoring/reports.html',
        reports=[r.to_dict() for r in rows],
        periods=list(mr.PERIODS),
        period_label=mr.PERIOD_LABEL,
        can_edit=current_user.can(Permission.CONFIG_WRITE),
        product_key=_product(),
        schedules=_schedule_state(),
    )


def _schedule_state() -> list[dict]:
    """Whether a recurring report is actually armed, per period.

    This product seeds no ``ScheduledAction`` (safeguards §10), so a fresh
    install has the capability and zero coverage. Saying so on the page is the
    difference between "reports are empty because nothing happened" and
    "reports are empty because nothing is scheduled".
    """
    import json as _json

    from ..models import ScheduledAction

    out = []
    rows = (ScheduledAction.query
            .filter(ScheduledAction.action == 'monitor_report').all())
    by_period: dict[str, object] = {}
    for row in rows:
        try:
            params = _json.loads(row.params or '{}')
        except (ValueError, TypeError):
            params = {}
        by_period.setdefault((params or {}).get('period', 'daily'), row)
    for period in mr.PERIODS:
        row = by_period.get(period)
        out.append({
            "period": period,
            "label": mr.PERIOD_LABEL[period],
            "armed": bool(row is not None and row.enabled),
            "exists": row is not None,
            "name": getattr(row, 'name', '') or '',
            "next_run": (row.next_run.isoformat(timespec='seconds')
                         if row is not None and row.next_run else ''),
            "last_status": getattr(row, 'last_status', '') or '',
        })
    return out


@bp.route('/data')
@login_required
def data():
    rows = _scoped().limit(200).all()
    return jsonify({"ok": True,
                    "reports": [r.to_dict() for r in rows],
                    "schedules": _schedule_state()})


@bp.route('/<int:rid>')
@login_required
def detail(rid: int):
    row = _get(rid)
    if row is None:
        return render_template('errors/404.html'), 404
    return render_template('monitoring/report_detail.html',
                           report=row.to_dict(with_body=True),
                           can_edit=current_user.can(Permission.CONFIG_WRITE),
                           product_key=_product())


@bp.route('/<int:rid>/json')
@login_required
def as_json(rid: int):
    row = _get(rid)
    if row is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, **row.to_dict(with_body=True)})


@bp.route('/<int:rid>/csv')
@login_required
def as_csv(rid: int):
    row = _get(rid)
    if row is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    csv = mr.to_csv(row.body())
    name = "satom-report-%s-%s.csv" % (row.period,
                                       row.period_start.strftime("%Y%m%d"))
    return Response(csv, mimetype='text/csv',
                    headers={'Content-Disposition':
                             'attachment; filename="%s"' % name})


@bp.route('/<int:rid>/text')
@login_required
def as_text(rid: int):
    row = _get(rid)
    if row is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    return Response(mr.render_text(row.body()), mimetype='text/plain')


@bp.route('/generate', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def generate():
    period = (request.form.get('period') or 'daily').strip()
    if period not in mr.PERIODS:
        return jsonify({"ok": False, "error": "unknown period"}), 400
    try:
        offset = max(0, min(60, int(request.form.get('offset') or 1)))
    except (TypeError, ValueError):
        offset = 1
    start, end = mr.period_bounds(period, offset=offset)
    row = mr.generate(period, product=_product(), start=start, end=end,
                      by=getattr(current_user, 'username', '') or '')
    log_action('report.generate', str(row.id),
               {"period": period, "from": start.isoformat()})
    return jsonify({"ok": True, "report": row.to_dict()})


@bp.route('/<int:rid>/email', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def email(rid: int):
    row = _get(rid)
    if row is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    res = mr.email_report(row)
    log_action('report.email', str(rid),
               {"ok": res["ok"], "to": ", ".join(res.get("to") or [])})
    return jsonify({"ok": res["ok"], "detail": res["detail"],
                    "to": res.get("to") or [],
                    "report": row.to_dict()})


@bp.route('/<int:rid>/delete', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def delete(rid: int):
    row = _get(rid)
    if row is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    db.session.delete(row)
    db.session.commit()
    log_action('report.delete', str(rid), {})
    return jsonify({"ok": True})


@bp.route('/preview')
@login_required
def preview():
    """Build a period WITHOUT storing it — the 'what would this say' button."""
    period = (request.args.get('period') or 'daily').strip()
    if period not in mr.PERIODS:
        return jsonify({"ok": False, "error": "unknown period"}), 400
    try:
        offset = max(0, min(60, int(request.args.get('offset') or 1)))
    except (TypeError, ValueError):
        offset = 1
    start, end = mr.period_bounds(period, offset=offset)
    body = mr.build(period, start=start, end=end, product=_product())
    return jsonify({"ok": True, "body": body,
                    "title": mr.period_title(period, start, end)})
