"""Metrics — daily activity statistics with date comparison."""
from __future__ import annotations

from datetime import datetime, timedelta, date
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required


def _classify_endpoint(endpoint: str) -> str:
    """Map a change_history endpoint to a high-level object category."""
    e = endpoint.lower()
    if 'certificate' in e:
        return 'certificate'
    if 'web-protection-profile' in e:
        return 'wpp'
    # server-pool / pserver-list before server-policy/policy so pool rows don't match policy
    if 'server-pool' in e or 'pserver-list' in e:
        return 'backend'
    if 'server-policy/policy' in e or e.endswith('server-policy/policy'):
        return 'server_policy'
    return 'other'

bp = Blueprint('metrics', __name__, url_prefix='/metrics')


def _date_range(period, date_from_str, date_to_str):
    today = date.today()
    if period == '7d':
        d_from = today - timedelta(days=6)
        d_to = today
    elif period == '30d':
        d_from = today - timedelta(days=29)
        d_to = today
    elif period == '90d':
        d_from = today - timedelta(days=89)
        d_to = today
    elif period == 'custom' and date_from_str and date_to_str:
        try:
            d_from = datetime.strptime(date_from_str, '%Y-%m-%d').date()
            d_to = datetime.strptime(date_to_str, '%Y-%m-%d').date()
        except ValueError:
            d_from = today - timedelta(days=6)
            d_to = today
    else:
        d_from = today - timedelta(days=6)
        d_to = today
    return (
        datetime(d_from.year, d_from.month, d_from.day, 0, 0, 0),
        datetime(d_to.year, d_to.month, d_to.day, 23, 59, 59),
    )


def _prev_range(dt_from, dt_to):
    span = dt_to - dt_from
    prev_to = dt_from - timedelta(seconds=1)
    prev_from = prev_to - span
    return prev_from, prev_to


@bp.route('/')
@login_required
def index():
    period = request.args.get('period', '7d')
    date_from_str = request.args.get('date_from', '')
    date_to_str = request.args.get('date_to', '')
    compare = request.args.get('compare', '0') == '1'
    dt_from, dt_to = _date_range(period, date_from_str, date_to_str)
    # Server-side inventory totals so the cards show even if JS fails to run.
    try:
        from ..services import inventory_metrics
        inv_totals = inventory_metrics.current_totals()
    except Exception:
        inv_totals = None
    return render_template(
        'metrics/index.html',
        period=period,
        date_from=dt_from.strftime('%Y-%m-%d'),
        date_to=dt_to.strftime('%Y-%m-%d'),
        compare=compare,
        inv_totals=inv_totals,
    )


@bp.route('/api/data')
@login_required
def api_data():
    """Return JSON metrics for the selected date range."""
    from ..models import AuditLog, ChangeHistory, Appliance, db
    from sqlalchemy import func, cast, Date as SADate

    period = request.args.get('period', '7d')
    date_from_str = request.args.get('date_from', '')
    date_to_str = request.args.get('date_to', '')
    compare = request.args.get('compare', '0') == '1'

    dt_from, dt_to = _date_range(period, date_from_str, date_to_str)

    def compute_metrics(df, dt):
        total_actions = AuditLog.query.filter(
            AuditLog.timestamp >= df,
            AuditLog.timestamp <= dt,
        ).count()

        config_changes = ChangeHistory.query.filter(
            ChangeHistory.ts >= df,
            ChangeHistory.ts <= dt,
            ChangeHistory.dry_run == False,
        ).count()

        active_users = db.session.query(
            func.count(func.distinct(AuditLog.username))
        ).filter(
            AuditLog.timestamp >= df,
            AuditLog.timestamp <= dt,
        ).scalar() or 0

        appliances_touched = db.session.query(
            func.count(func.distinct(ChangeHistory.appliance_id))
        ).filter(
            ChangeHistory.ts >= df,
            ChangeHistory.ts <= dt,
            ChangeHistory.dry_run == False,
            ChangeHistory.appliance_id != None,
        ).scalar() or 0

        timeline_rows = db.session.query(
            cast(AuditLog.timestamp, SADate).label('day'),
            func.count().label('total'),
        ).filter(
            AuditLog.timestamp >= df,
            AuditLog.timestamp <= dt,
        ).group_by(
            cast(AuditLog.timestamp, SADate)
        ).order_by('day').all()

        timeline_changes_rows = db.session.query(
            cast(ChangeHistory.ts, SADate).label('day'),
            func.count().label('changes'),
        ).filter(
            ChangeHistory.ts >= df,
            ChangeHistory.ts <= dt,
            ChangeHistory.dry_run == False,
        ).group_by(
            cast(ChangeHistory.ts, SADate)
        ).order_by('day').all()

        all_days = []
        cur = df.date()
        while cur <= dt.date():
            all_days.append(str(cur))
            from datetime import timedelta as td
            cur += td(days=1)

        audit_by_day = {str(r.day): r.total for r in timeline_rows}
        changes_by_day = {str(r.day): r.changes for r in timeline_changes_rows}

        timeline = {
            'labels': all_days,
            'audit': [audit_by_day.get(d, 0) for d in all_days],
            'changes': [changes_by_day.get(d, 0) for d in all_days],
        }

        action_rows = db.session.query(
            AuditLog.action,
            func.count().label('cnt'),
        ).filter(
            AuditLog.timestamp >= df,
            AuditLog.timestamp <= dt,
        ).group_by(AuditLog.action).order_by(func.count().desc()).limit(10).all()

        by_action = {
            'labels': [r.action for r in action_rows],
            'values': [r.cnt for r in action_rows],
        }

        change_type_rows = db.session.query(
            ChangeHistory.action,
            func.count().label('cnt'),
        ).filter(
            ChangeHistory.ts >= df,
            ChangeHistory.ts <= dt,
            ChangeHistory.dry_run == False,
        ).group_by(ChangeHistory.action).order_by(func.count().desc()).all()

        by_change_type = {
            'labels': [r.action for r in change_type_rows],
            'values': [r.cnt for r in change_type_rows],
        }

        user_rows = db.session.query(
            AuditLog.username,
            func.count().label('cnt'),
        ).filter(
            AuditLog.timestamp >= df,
            AuditLog.timestamp <= dt,
        ).group_by(AuditLog.username).order_by(func.count().desc()).limit(10).all()

        by_user = {
            'labels': [r.username for r in user_rows],
            'values': [r.cnt for r in user_rows],
        }

        app_rows = db.session.query(
            Appliance.name,
            func.count().label('cnt'),
        ).join(ChangeHistory, ChangeHistory.appliance_id == Appliance.id).filter(
            ChangeHistory.ts >= df,
            ChangeHistory.ts <= dt,
            ChangeHistory.dry_run == False,
        ).group_by(Appliance.name).order_by(func.count().desc()).limit(10).all()

        by_appliance = {
            'labels': [r.name for r in app_rows],
            'values': [r.cnt for r in app_rows],
        }

        # ---- object-type breakdown per day ----
        obj_rows = db.session.query(
            cast(ChangeHistory.ts, SADate).label('day'),
            ChangeHistory.endpoint,
            func.count().label('cnt'),
        ).filter(
            ChangeHistory.ts >= df,
            ChangeHistory.ts <= dt,
            ChangeHistory.dry_run == False,
        ).group_by(
            cast(ChangeHistory.ts, SADate),
            ChangeHistory.endpoint,
        ).all()

        TYPES = ('server_policy', 'backend', 'wpp', 'certificate', 'other')
        obj_by_day: dict[str, dict[str, int]] = {d: {t: 0 for t in TYPES} for d in all_days}
        obj_totals: dict[str, int] = {t: 0 for t in TYPES}
        for r in obj_rows:
            day_str = str(r.day)
            cat = _classify_endpoint(r.endpoint)
            if day_str in obj_by_day:
                obj_by_day[day_str][cat] = obj_by_day[day_str].get(cat, 0) + r.cnt
            obj_totals[cat] = obj_totals.get(cat, 0) + r.cnt

        by_object_type = {
            'labels': all_days,
            'server_policy': [obj_by_day[d]['server_policy'] for d in all_days],
            'backend':        [obj_by_day[d]['backend']        for d in all_days],
            'wpp':            [obj_by_day[d]['wpp']            for d in all_days],
            'certificate':    [obj_by_day[d]['certificate']    for d in all_days],
            'totals': obj_totals,
        }

        table_rows = []
        for d in all_days:
            table_rows.append({
                'date': d,
                'actions': audit_by_day.get(d, 0),
                'changes': changes_by_day.get(d, 0),
                'server_policy': obj_by_day[d]['server_policy'],
                'backend':       obj_by_day[d]['backend'],
                'wpp':           obj_by_day[d]['wpp'],
                'certificate':   obj_by_day[d]['certificate'],
            })

        return {
            'summary': {
                'total_actions': total_actions,
                'config_changes': config_changes,
                'active_users': active_users,
                'appliances_touched': appliances_touched,
            },
            'timeline': timeline,
            'by_object_type': by_object_type,
            'by_action': by_action,
            'by_change_type': by_change_type,
            'by_user': by_user,
            'by_appliance': by_appliance,
            'table': table_rows,
        }

    current = compute_metrics(dt_from, dt_to)

    # --- fleet INVENTORY (how many exist), current totals + per-date trend ---
    from ..services import inventory_metrics
    inventory = {
        'totals': inventory_metrics.current_totals(),
        'series': inventory_metrics.series(dt_from.date(), dt_to.date()),
    }

    # Overlay INVENTORY (how many exist per day) onto the daily table's
    # per-type columns so they match the cards + trend chart, instead of
    # counting change-events (which left Certificate blank whenever no
    # certificate was edited). Days with no snapshot yet stay 0 ("—").
    _inv_s = inventory['series']
    _inv_by_date = {}
    for _i, _lbl in enumerate(_inv_s.get('labels', [])):
        _inv_by_date[_lbl] = {
            _t: _inv_s.get(_t, [])[_i]
            for _t in ('server_policy', 'backend', 'wpp', 'certificate')
        }
    for _row in current['table']:
        _d = _inv_by_date.get(_row['date'], {})
        _row['server_policy'] = _d.get('server_policy', 0)
        _row['backend'] = _d.get('backend', 0)
        _row['wpp'] = _d.get('wpp', 0)
        _row['certificate'] = _d.get('certificate', 0)

    result = {
        'current': current,
        'inventory': inventory,
        'date_from': dt_from.strftime('%Y-%m-%d'),
        'date_to': dt_to.strftime('%Y-%m-%d'),
    }

    if compare:
        prev_from, prev_to = _prev_range(dt_from, dt_to)
        previous = compute_metrics(prev_from, prev_to)
        result['previous'] = previous
        result['prev_date_from'] = prev_from.strftime('%Y-%m-%d')
        result['prev_date_to'] = prev_to.strftime('%Y-%m-%d')

    return jsonify(result)
