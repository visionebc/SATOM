from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort, Response
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('backups', __name__, url_prefix='/backups')


@bp.route('/')
@login_required
@require_permission(Permission.BACKUP)
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    from flask import redirect as _redir, url_for as _ufor
    from ..services import device_context as _dc
    _cur = _dc.current_appliance()
    if _cur is None:
        return _redir(_ufor('architecture.index'))
    return _redir(_ufor('backups.list_backups', id=_cur.id))


@bp.route('/<int:id>')
@login_required
@require_permission(Permission.BACKUP)
def list_backups(id):
    appliance = Appliance.query.get_or_404(id)
    backups = []
    error = None
    try:
        client = FortiWebClient(appliance)
        resp = client.api_call('GET', '/System/Maintenance/Backup')
        backups = resp.json().get('data', [])
    except Exception as exc:
        error = str(exc)
    return render_template(
        'backups/list.html',
        appliance=appliance,
        backups=backups,
        error=error,
    )


@bp.route('/<int:id>/create', methods=['POST'])
@login_required
@require_permission(Permission.BACKUP)
def create_backup(id):
    appliance = Appliance.query.get_or_404(id)
    try:
        client = FortiWebClient(appliance)
        client.api_call('POST', '/System/Maintenance/Backup', {})
        log_action('backup.create', appliance_id=appliance.id, detail=f'Created backup on {appliance.name}')
        flash('Backup initiated successfully.', 'success')
    except Exception as exc:
        flash(f'Backup failed: {exc}', 'danger')
    return redirect(url_for('backups.list_backups', id=id))


@bp.route('/<int:id>/download/<name>')
@login_required
@require_permission(Permission.BACKUP)
def download_backup(id, name):
    appliance = Appliance.query.get_or_404(id)
    try:
        client = FortiWebClient(appliance)
        content = client.download_backup(name)
        log_action('backup.download', appliance_id=appliance.id, detail=f'Downloaded backup {name} from {appliance.name}')
        return Response(
            content,
            mimetype='application/octet-stream',
            headers={'Content-Disposition': f'attachment; filename="{name}"'},
        )
    except Exception as exc:
        flash(f'Download failed: {exc}', 'danger')
        return redirect(url_for('backups.list_backups', id=id))
