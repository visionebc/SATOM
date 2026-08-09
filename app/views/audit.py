import re

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..services.audit import log_action

bp = Blueprint('audit', __name__, url_prefix='/audit')

# ``#4821`` (as the table renders it), ``4821`` (as the clipboard copies it) and
# ``AUD-004821`` (as a ticket tends to quote it) are the same entry.
_ENTRY_ID_RE = re.compile(r'^\s*(?:#|AUD-)?0*(\d{1,18})\s*$', re.IGNORECASE)


def parse_entry_id(raw: str):
    """Return the audit entry id encoded in *raw*, or ``None``.

    ``None`` — not an id — is the important half: it keeps an ordinary text
    search (a username, a target path) from being silently reinterpreted as a
    primary-key lookup.
    """
    if not raw:
        return None
    m = _ENTRY_ID_RE.match(raw)
    return int(m.group(1)) if m else None


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
        terms = [
            AuditLog.username.ilike(like),
            AuditLog.action.ilike(like),
            AuditLog.target.ilike(like),
            AuditLog.extra.ilike(like),
        ]
        # An entry ID pasted back from the table has to find its own row. None
        # of the LIKE terms above ever look at the primary key, so without this
        # the ID would be a label you can copy and then cannot use. It is OR-ed
        # in (never AND-ed, never a separate branch): a numeric query that also
        # appears in a target or a payload must keep matching those rows too.
        entry_id = parse_entry_id(filter_q)
        if entry_id is not None:
            terms.append(AuditLog.id == entry_id)
        query = query.filter(or_(*terms))

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

    # ``id`` breaks the tie. Rows written inside the same second (one apply
    # writes several) otherwise come back in an order the database is free
    # to change between two queries — so the same row can show up on page 1 and
    # again on page 2, or on neither. Paging is only well defined under a total
    # order, and the ID column now makes any such duplicate visible.
    query = query.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
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
