from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..services.audit import log_action

bp = Blueprint('audit', __name__, url_prefix='/audit')


@bp.route('/')
@login_required
def index():
    from ..models import AuditLog, User

    # Clamp paging inputs: a non-numeric value must not 500 and a huge
    # per_page must not let one request materialise the whole audit table.
    try:
        page = max(1, int(request.args.get('page', 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        per_page = min(200, max(10, int(request.args.get('per_page', 50))))
    except (TypeError, ValueError):
        per_page = 50
    filter_user = request.args.get('user', '').strip()
    filter_action = request.args.get('action', '').strip()
    filter_q = request.args.get('q', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()

    from ..services.product_scope import scope_query
    # ADOM scoping: fortiweb/fortiadc sessions see only their product's rows.
    query = scope_query(AuditLog.query, AuditLog.product)

    if filter_user:
        user_obj = User.query.filter_by(username=filter_user).first()
        if user_obj:
            query = query.filter_by(user_id=user_obj.id)
        else:
            query = query.filter(False)

    if filter_action:
        query = query.filter(AuditLog.action.ilike(f'%{filter_action}%'))

    if filter_q:
        from sqlalchemy import or_
        like = f'%{filter_q}%'
        query = query.filter(or_(
            AuditLog.username.ilike(like),
            AuditLog.action.ilike(like),
            AuditLog.target.ilike(like),
            AuditLog.extra.ilike(like),
        ))

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
        filter_q=filter_q,
        date_from=date_from,
        date_to=date_to,
    )
