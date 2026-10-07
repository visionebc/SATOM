"""Migration report pages: one appliance's configuration against a target build.

Read-only. The report itself is :mod:`app.services.migration_report`; this
blueprint picks the appliance and the target, renders the rows and serves the
JSON and CSV exports. Guarded by the permission that guards upgrade planning
reads (``Permission.BACKUP``, the Upgrade Flow's own gate), and every
appliance is loaded through ``visible_appliance_or_404`` so a device of
another ADOM (or in hidden maintenance) is a 404, never a report.
"""
from __future__ import annotations

from flask import Blueprint, Response, render_template, request
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Appliance, Permission, visible_appliance_or_404, visible_appliances
from ..services import firmware_versions as fv
from ..services import migration_report as mr

bp = Blueprint('migration_report', __name__, url_prefix='/migration-report')

#: Products whose CLI dump the vault parses (cli_coverage) and whose CLI path
#: rule the library knows.
PRODUCTS = ('fortiweb', 'fortiadc', 'fortigate')


def _target_arg() -> str:
    return fv.normalize((request.args.get('target') or '').strip())


def _backup_arg():
    raw = (request.args.get('backup') or '').strip()
    return int(raw) if raw.isdigit() else None


def _report(appliance, target):
    return mr.for_appliance(appliance, target, backup_id=_backup_arg())


@bp.route('/')
@login_required
@require_permission(Permission.BACKUP)
def index():
    """Pick an appliance and a target build."""
    devices = [a for a in visible_appliances().order_by(Appliance.name.asc()).all()
               if (a.kind or '') in PRODUCTS]
    targets = {p: mr.target_builds(p) for p in sorted({d.kind for d in devices})}
    return render_template('migration_report/index.html', devices=devices,
                           targets=targets)


@bp.route('/<int:id>')
@login_required
@require_permission(Permission.BACKUP)
def report(id):
    appliance = visible_appliance_or_404(id)
    target = _target_arg()
    targets = mr.target_builds(appliance.kind or '')
    rep = _report(appliance, target) if target else None
    dumps = mr.dumps_for(appliance.id)
    return render_template('migration_report/report.html', appliance=appliance,
                           target=target, targets=targets, rep=rep, dumps=dumps,
                           severities=mr.SEVERITIES)


@bp.route('/<int:id>/report.json')
@login_required
@require_permission(Permission.BACKUP)
def report_json(id):
    appliance = visible_appliance_or_404(id)
    rep = _report(appliance, _target_arg())
    return Response(mr.to_json(rep), mimetype='application/json')


@bp.route('/<int:id>/report.csv')
@login_required
@require_permission(Permission.BACKUP)
def report_csv(id):
    appliance = visible_appliance_or_404(id)
    target = _target_arg()
    rep = _report(appliance, target)
    name = 'migration-%s-%s-to-%s.csv' % (
        ''.join(c if c.isalnum() or c in '-_.' else '_' for c in appliance.name or 'appliance'),
        rep.get('source') or 'unknown', target or 'none')
    return Response(mr.to_csv(rep), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename="%s"' % name})
