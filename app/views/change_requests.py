"""Change Requests — maintenance-window approval gating for risky changes.

Thin Flask blueprint over :mod:`app.services.change_requests` (the headless
status workflow, scheduling, maintenance notice and affected-policy discovery). A
Change Request is the control record for a windowed, risky change — above all a
firmware UPGRADE: which devices/policies are affected, when, an approval gate, and
the bound one-shot ``ScheduledAction`` that executes it inside the window.

The view layer only persists the ``draft`` record and drives the service-side
transitions (approve / schedule / cancel / mark-notified). The actual firing is
the scheduler sidecar's job, re-gated at fire time by ``cr_runnable``.

Import side-effect-free: importing this module touches no DB and contacts no
device.
"""
from __future__ import annotations

import json
from datetime import datetime

from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Appliance, ChangeRequest, ChangeRequestEvent, Permission, db
from ..services import change_requests as svc
from ..services.audit import log_action

bp = Blueprint('change_requests', __name__, url_prefix='/change-requests')

# The actions a CR may carry (the gated firmware flow + its safe prep).
CR_ACTIONS = [
    ("upgrade", "Firmware upgrade (gated, flashes + reboots)"),
    ("upgrade_prep", "Upgrade preparation (backup + health)"),
]
_CR_ACTION_KEYS = {a for a, _ in CR_ACTIONS}

# Bootstrap-ish badge class per status for the list / detail header.
_STATUS_BADGE = {
    "draft": "fw-badge-secondary",
    "approved": "fw-badge-info",
    "scheduled": "fw-badge-primary",
    "in_progress": "fw-badge-primary",
    "completed": "fw-badge-success",
    "failed": "fw-badge-danger",
    "cancelled": "fw-badge-secondary",
}
_RISK_BADGE = {
    "low": "fw-badge-success",
    "medium": "fw-badge-info",
    "high": "fw-badge-danger",
}


def _parse_dt(value: str | None):
    """A datetime-local form value -> naive UTC datetime, or None if blank/bad."""
    value = (value or '').strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- #
#  Routes                                                                       #
# --------------------------------------------------------------------------- #
@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    crs = (ChangeRequest.query
           .order_by(ChangeRequest.created_at.desc())
           .all())
    # Group by status, in the canonical lifecycle order, dropping empty buckets.
    groups = []
    for status in ChangeRequest.STATUSES:
        members = [c for c in crs if c.status == status]
        if members:
            groups.append({'status': status, 'items': members})
    return render_template('change_requests/index.html',
                           groups=groups,
                           total=len(crs),
                           status_badge=_STATUS_BADGE,
                           risk_badge=_RISK_BADGE)


@bp.route('/new', methods=['GET', 'POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def new():
    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()
        if not title:
            flash('A title is required.', 'danger')
            return redirect(url_for('change_requests.new'))

        action = (request.form.get('action') or 'upgrade').strip()
        if action not in _CR_ACTION_KEYS:
            action = 'upgrade'
        risk = (request.form.get('risk') or 'medium').strip()
        if risk not in svc.RISKS:
            risk = 'medium'
        device_ids = [n for n in
                      ((_to_int(x)) for x in request.form.getlist('device_ids'))
                      if n is not None]

        cr = ChangeRequest(
            title=title[:200],
            reason=(request.form.get('reason') or '').strip(),
            status='draft',
            action=action,
            device_ids=json.dumps(device_ids),
            window_start=_parse_dt(request.form.get('window_start')),
            window_end=_parse_dt(request.form.get('window_end')),
            risk=risk,
            rollback=(request.form.get('rollback') or '').strip(),
            requested_by=current_user.username,
        )
        db.session.add(cr)
        db.session.commit()
        log_action('change_request.create', target=cr.title,
                   detail=f'{action} / risk={risk}')
        flash(f'Change request "{cr.title}" created.', 'success')
        return redirect(url_for('change_requests.detail', id=cr.id))

    appliances = (Appliance.query
                  .filter_by(kind='fortiweb')
                  .order_by(Appliance.name)
                  .all())
    return render_template('change_requests/form.html',
                           appliances=appliances,
                           cr_actions=CR_ACTIONS,
                           risks=svc.RISKS)


@bp.route('/<int:id>')
@login_required
@require_permission(Permission.USER_MANAGE)
def detail(id):
    cr = ChangeRequest.query.get_or_404(id)
    events = (ChangeRequestEvent.query
              .filter_by(cr_id=cr.id)
              .order_by(ChangeRequestEvent.ts.asc())
              .all())
    device_ids = cr.device_ids_list
    devices = (Appliance.query.filter(Appliance.id.in_(device_ids)).all()
               if device_ids else [])
    runnable_ok, runnable_reason = svc.cr_runnable(cr)
    # Best-effort LIVE read of the affected policies (the clients to warn). With
    # no/unreachable devices this returns [] quickly rather than raising.
    policies = svc.affected_policies(device_ids)
    return render_template('change_requests/detail.html',
                           cr=cr,
                           events=events,
                           devices=devices,
                           notice=svc.maintenance_notice(cr),
                           runnable_ok=runnable_ok,
                           runnable_reason=runnable_reason,
                           policies=policies,
                           terminal=cr.status in ChangeRequest.TERMINAL,
                           status_badge=_STATUS_BADGE,
                           risk_badge=_RISK_BADGE)


@bp.route('/<int:id>/approve', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def approve(id):
    try:
        cr = svc.approve(id, current_user.username)
        log_action('change_request.approve', target=cr.title)
        flash('Change request approved.', 'success')
    except ValueError as exc:
        flash(str(exc), 'danger')
    return redirect(url_for('change_requests.detail', id=id))


@bp.route('/<int:id>/schedule', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def schedule(id):
    try:
        action_id = svc.schedule_change_request(id, current_user.username)
        log_action('change_request.schedule', target=str(id),
                   detail=f'scheduled_action={action_id}')
        flash(f'Change request scheduled — bound action #{action_id}.', 'success')
    except ValueError as exc:
        flash(str(exc), 'danger')
    return redirect(url_for('change_requests.detail', id=id))


@bp.route('/<int:id>/cancel', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def cancel(id):
    reason = (request.form.get('reason') or '').strip()
    try:
        cr = svc.cancel(id, current_user.username, reason)
        log_action('change_request.cancel', target=cr.title, detail=reason)
        flash('Change request cancelled.', 'success')
    except ValueError as exc:
        flash(str(exc), 'danger')
    return redirect(url_for('change_requests.detail', id=id))


@bp.route('/<int:id>/mark-notified', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def mark_notified(id):
    """Send the client maintenance notice by email when email is configured
    (Settings -> Email); otherwise just record it as sent. Best-effort: a send
    failure is reported and logged, never a 500."""
    from ..services import email_service as email
    cr = ChangeRequest.query.get_or_404(id)
    recipients = (request.form.get('recipients') or '').strip()
    stamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

    if email.is_configured():
        notice = svc.maintenance_notice(cr)
        subject = 'Scheduled maintenance window'
        body = notice
        lines = notice.splitlines()
        if lines and lines[0].lower().startswith('subject:'):
            subject = lines[0].split(':', 1)[1].strip() or subject
            body = '\n'.join(lines[1:]).lstrip('\n')
        result = email.send_email(recipients, subject, body)
        if result.get('ok'):
            cr.notify_status = 'sent'
            cr.notify_log = (cr.notify_log or '') + f"\n[{stamp}] sent: {result.get('detail', '')}"
            db.session.commit()
            log_action('change_request.notified', target=cr.title,
                       detail=result.get('detail', ''))
            flash('Maintenance notice emailed to the client(s).', 'success')
        else:
            cr.notify_log = (cr.notify_log or '') + f"\n[{stamp}] FAILED: {result.get('detail', '')}"
            db.session.commit()
            log_action('change_request.notify_failed', target=cr.title,
                       detail=result.get('detail', ''))
            flash(f"Email send failed: {result.get('detail', '')}", 'danger')
    else:
        cr.notify_status = 'sent'
        cr.notify_log = (cr.notify_log or '') + f"\n[{stamp}] marked sent (email not configured)"
        db.session.commit()
        log_action('change_request.notified', target=cr.title)
        flash('Notice marked as sent. Configure Settings -> Email to deliver it automatically.', 'info')
    return redirect(url_for('change_requests.detail', id=id))


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
