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
