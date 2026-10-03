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


def _filtered_query():
    """The audit query narrowed by the page's filters (shared by the list and
    the CSV export, so the file holds exactly what the filters show)."""
    from ..models import AuditLog, User

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
        from datetime import datetime, timedelta
        try:
            # "To" is inclusive: everything before the NEXT midnight, not
            # before this day's first second.
            dt_to = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(AuditLog.timestamp < dt_to)
        except ValueError:
            pass

    # ``id`` breaks the tie. Rows written inside the same second (one apply
    # writes several) otherwise come back in an order the database is free
    # to change between two queries — so the same row can show up on page 1 and
    # again on page 2, or on neither. Paging is only well defined under a total
    # order, and the ID column now makes any such duplicate visible.
    query = query.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
    return query, dict(filter_user=filter_user, filter_action=filter_action,
                       filter_q=filter_q, date_from=date_from, date_to=date_to)


@bp.route('/')
@login_required
@require_permission('audit.view')
def index():
    from ..models import User

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
    query, filters = _filtered_query()
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    users = User.query.order_by(User.username).all()

    return render_template(
        'audit/index.html',
        pagination=pagination,
        entries=pagination.items,
        users=users,
        **filters,
    )


def _csv_cell(value) -> str:
    """A text cell that a spreadsheet will not evaluate as a formula (targets
    and payloads carry user-typed text)."""
    text = '' if value is None else str(value)
    return "'" + text if text[:1] in ('=', '+', '-', '@') else text


#: Upper bound on one export, so a click cannot stream the whole table.
EXPORT_MAX_ROWS = 50000


@bp.route('/export.csv')
@login_required
@require_permission('audit.view')
def export_csv():
    """The filtered audit trail as CSV (same filters as the page, newest first)."""
    import csv
    import io
    from flask import Response

    query, _filters = _filtered_query()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(['id', 'timestamp_utc', 'username', 'action', 'target',
                'ip_address', 'product', 'extra'])
    for e in query.limit(EXPORT_MAX_ROWS):
        w.writerow([e.id, e.timestamp.isoformat(sep=' ') if e.timestamp else ''] +
                   [_csv_cell(v) for v in (e.username, e.action, e.target,
                                           e.ip_address, e.product, e.extra)])
    return Response(buf.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=audit-log.csv'})
