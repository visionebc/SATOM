from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('audit', __name__, url_prefix='/audit')


@bp.route('/')
@login_required
def index():
    from ..models import AuditLog, User

    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    filter_user = request.args.get('user', '').strip()
    filter_action = request.args.get('action', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()

    query = AuditLog.query

    if filter_user:
        user_obj = User.query.filter_by(username=filter_user).first()
        if user_obj:
            query = query.filter_by(user_id=user_obj.id)
        else:
            query = query.filter(False)

    if filter_action:
        query = query.filter(AuditLog.action.ilike(f'%{filter_action}%'))

    if date_from:
        from datetime import datetime
        try:
            dt_from = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(AuditLog.timestamp >= dt_from)
        except ValueError:
            pass

    if date_to:
        from datetime import datetime
        try:
            dt_to = datetime.strptime(date_to, '%Y-%m-%d')
            query = query.filter(AuditLog.timestamp <= dt_to)
        except ValueError:
            pass

    query = query.order_by(AuditLog.timestamp.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    users = User.query.order_by(User.username).all()

    return render_template(
        'audit/index.html',
        pagination=pagination,
        entries=pagination.items,
        users=users,
        filter_user=filter_user,
        filter_action=filter_action,
        date_from=date_from,
        date_to=date_to,
    )
