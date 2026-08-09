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
from ..models import visible_appliances, visible_appliance_or_404
from ..services import change_requests as svc
from ..services import scheduled_actions as sa
from ..services.audit import log_action

bp = Blueprint('change_requests', __name__, url_prefix='/change-requests')

# The actions a CR may carry are DERIVED from the automation catalog, never
# re-listed here by hand. A hand-kept list is exactly how 'upgrade_prep' came to
# be offered by this form while the executor's gate honoured only 'upgrade': the
# destructive action was on the menu and ungated. Eligible = it touches a device
# AND it is destructive (danger) or mutates objects (user scope) - so a newly
# registered dangerous action appears here the day it is registered.
def _cr_specs() -> list:
    return [s for s in sa.ALL_ACTIONS.values()
            if s.needs_targets and (s.danger or s.scope == 'user')]


def cr_actions() -> list[tuple[str, str]]:
    """[(key, label)] for the form's Action dropdown."""
    return [(s.key, s.label) for s in _cr_specs()]


def cr_action_keys() -> set[str]:
    return {s.key for s in _cr_specs()}


def cr_kinds() -> tuple[str, ...]:
    """Appliance kinds a CR may target: the union of the eligible actions'
    products. A maintenance window is a property of the DEVICE, not of one
    product - FortiWeb, FortiADC, FortiAnalyzer and FortiAuthenticator are all
    first-class here, and this form used to show only FortiWeb.
    """
    kinds: list[str] = []
    for spec in _cr_specs():
        for kind in spec.products:
            if kind not in kinds:
                kinds.append(kind)
    return tuple(kinds)

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
def _visible_appliance_ids() -> set[int]:
    """Appliance ids the ACTIVE ADOM may see."""
    return {row[0] for row in
            visible_appliances().with_entities(Appliance.id).all()}


def _cr_in_scope(cr, visible: set[int] | None = None) -> bool:
    """Is this change visible in the active ADOM?

    A CR is scoped by the devices it NAMES: the ADOM that owns a box owns the
    window that takes it down, and a change naming boxes in two products is
    legitimately visible in both. A CR naming NO device belongs to no product
    and stays visible everywhere - hiding it would make it unreachable from any
    console at all.
    """
    ids = cr.device_ids_list
    if not ids:
        return True
    vis = _visible_appliance_ids() if visible is None else visible
    return any(i in vis for i in ids)


def _cr_in_scope_or_404(id):
    """Load one CR by id, honouring the same scope as the list.

    Filtering the LIST while the by-id routes read the table raw is not scoping,
    it is decoration - the exact hole closed fleet-wide for appliances on
    2026-08-06. 404, never 403: do not confirm the row exists.
    """
    from flask import abort
    row = ChangeRequest.query.get_or_404(id)
    if not _cr_in_scope(row):
        abort(404)
    return row


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    visible = _visible_appliance_ids()
    crs = [c for c in (ChangeRequest.query
                       .order_by(ChangeRequest.created_at.desc())
                       .all())
           if _cr_in_scope(c, visible)]
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

        action = (request.form.get('action') or '').strip()
        spec = sa.get_spec(action)
        # An unrecognised action is REJECTED, never coerced. The old fallback
        # silently rewrote a glitched form into 'upgrade' - the most destructive
        # entry on the menu - which is the opposite of what a fallback is for.
        if spec is None or action not in cr_action_keys():
            flash(f'{action or "(none)"} is not a change-controlled action.',
                  'danger')
            return redirect(url_for('change_requests.new'))
        risk = (request.form.get('risk') or 'medium').strip()
        if risk not in svc.RISKS:
            risk = 'medium'
        device_ids = [n for n in
                      ((_to_int(x)) for x in request.form.getlist('device_ids'))
                      if n is not None]

        # The devices must exist, be visible to this user, and be a product the
        # chosen action actually runs against. Without this last check the CR
        # saves happily and the SCHEDULED RUN resolves to zero targets (targets
        # are filtered by spec.products), reporting 'skipped' - which closes the
        # change as failed long after anyone could act on it.
        picked = (visible_appliances().filter(Appliance.id.in_(device_ids)).all()
                  if device_ids else [])
        if len(picked) != len(set(device_ids)):
            flash('One or more selected devices do not exist or are not visible '
                  'to you.', 'danger')
            return redirect(url_for('change_requests.new'))
        wrong = [d for d in picked
                 if (d.kind or 'fortiweb') not in spec.products]
        if wrong:
            flash(f'{spec.label} does not run against '
                  + ', '.join(sorted({(d.kind or "?") for d in wrong}))
                  + ' (' + ', '.join(d.name for d in wrong) + '). It supports: '
                  + ', '.join(spec.products) + '.', 'danger')
            return redirect(url_for('change_requests.new'))
        if spec.single_target and len(device_ids) > 1:
            flash(f'{spec.label} acts on exactly one appliance; '
                  f'{len(device_ids)} were selected.', 'danger')
            return redirect(url_for('change_requests.new'))

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
            notify_to=(request.form.get('notify_to') or '').strip(),
            requested_by=current_user.username,
            # An unrecognised value falls back to 'manual', NOT to 'external':
            # a form glitch must not silently bind a change to an approver
            # nobody configured, which would strand it un-runnable forever.
            approval_mode=('external'
                           if (request.form.get('approval_mode') or '').strip()
                           == 'external' else 'manual'),
        )
        db.session.add(cr)
        db.session.commit()
        log_action('change_request.create', target=cr.title,
                   detail=f'{action} / risk={risk}')
        flash(f'Change request "{cr.title}" created.', 'success')
        return redirect(url_for('change_requests.detail', id=cr.id))

    appliances = (visible_appliances()
                  .filter(Appliance.kind.in_(cr_kinds()))
                  .order_by(Appliance.kind, Appliance.name)
                  .all())
    return render_template('change_requests/form.html',
                           appliances=appliances,
                           cr_actions=cr_actions(),
                           action_products={s.key: list(s.products)
                                            for s in _cr_specs()},
                           risks=svc.RISKS)


@bp.route('/<int:id>')
@login_required
@require_permission(Permission.USER_MANAGE)
def detail(id):
    cr = _cr_in_scope_or_404(id)
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
    _cr_in_scope_or_404(id)
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
    _cr_in_scope_or_404(id)
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
    _cr_in_scope_or_404(id)
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
    cr = _cr_in_scope_or_404(id)
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


@bp.route('/<int:id>/request-crq', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def request_crq(id):
    """Raise the external change ticket by queueing the ``change.requested``
    hooks.

    Returns immediately with a count of what was QUEUED, never with a ticket id:
    hooks run out of process, so the CRM's answer arrives later. Blocking this
    request until somebody else's CRM replies would hand a third party the
    ability to hang the console."""
    from ..services import cr_orchestrator as orch
    cr = _cr_in_scope_or_404(id)
    result = orch.request_crq(cr, by=current_user.username)
    log_action('change_request.crq_requested', target=cr.title,
               detail=f"dispatched={result.get('dispatched', 0)}")
    if result.get('dispatched'):
        flash(f"Queued {result['dispatched']} integration hook(s). The ticket "
              f"reference appears here once your system answers.", 'success')
    else:
        # An enabled-but-unbound integration silently doing nothing is the
        # failure mode this message exists to prevent.
        flash('No enabled hook is bound to change.requested — nothing was sent.',
              'warning')
    return redirect(url_for('change_requests.detail', id=id))


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
