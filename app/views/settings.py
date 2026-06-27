from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('settings', __name__, url_prefix='/settings')


def _get_app_config():
    from flask import current_app
    return current_app.config


@bp.route('/')
@login_required
def index():
    config = _get_app_config()
    return render_template('settings/index.html', config=config)


@bp.route('/general', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def save_general():
    from flask import current_app
    app_title = request.form.get('app_title', '').strip()
    session_timeout = request.form.get('session_timeout', '').strip()
    default_page_size = request.form.get('default_page_size', '').strip()

    try:
        if app_title:
            current_app.config['APP_TITLE'] = app_title
        if session_timeout:
            current_app.config['PERMANENT_SESSION_LIFETIME'] = int(session_timeout)
        if default_page_size:
            current_app.config['DEFAULT_PAGE_SIZE'] = int(default_page_size)
        log_action('settings.general', detail='Updated general settings')
        flash('General settings saved.', 'success')
    except Exception as exc:
        flash(f'Failed to save settings: {exc}', 'danger')

    return redirect(url_for('settings.index'))


@bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not current_user.check_password(current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('settings.index'))

    if not new_password:
        flash('New password cannot be empty.', 'danger')
        return redirect(url_for('settings.index'))

    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('settings.index'))

    current_user.set_password(new_password)
    db.session.commit()
    log_action('settings.change_password', detail='Changed own password')
    flash('Password changed successfully.', 'success')
    return redirect(url_for('settings.index'))
