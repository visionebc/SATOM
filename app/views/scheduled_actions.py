"""Scheduled Actions — the admin automation calendar (Automation subsystem).

Thin Flask blueprint over :mod:`app.services.scheduled_actions` (the headless
catalog + executor) and :mod:`app.services.scheduler` (pure schedule math). The
view layer only: builds/persists ``ScheduledAction`` rows, recomputes
``next_run`` whenever the schedule changes, and exposes a manual "Run now" plus a
per-action run history. It NEVER fires jobs on a timer — that is the dedicated
scheduler sidecar's job (the gunicorn web workers would each fire a job N times).

Import side-effect-free: importing this module touches no DB and contacts no
device.
"""
from __future__ import annotations

import json

from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import (Appliance, Permission, ScheduledAction,
                      ScheduledActionRun, db)
from ..services import scheduled_actions as sa
from ..services.audit import log_action
from ..services.scheduler import SCHEDULE_KINDS, compute_next_run
from ..registry.loader import get_all_endpoints

bp = Blueprint('scheduled_actions', __name__, url_prefix='/scheduled-actions')

# Mon=0 .. Sun=6 (matches scheduler.compute_next_run's weekday convention).
WEEKDAYS = [
    (0, "Monday"), (1, "Tuesday"), (2, "Wednesday"), (3, "Thursday"),
    (4, "Friday"), (5, "Saturday"), (6, "Sunday"),
]
_WEEKDAY_LABELS = dict(WEEKDAYS)


# --------------------------------------------------------------------------- #
#  Small helpers                                                                #
# --------------------------------------------------------------------------- #
def _to_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _build_targets() -> list[int]:
    """The selected appliance ids; an empty list means the whole FortiWeb fleet."""
    ids: list[int] = []
    for raw in request.form.getlist('targets'):
        n = _to_int(raw, -1)
        if n >= 0:
            ids.append(n)
    return ids


def _build_schedule(kind: str) -> dict:
    """Build the JSON schedule spec for ``kind`` from the posted form fields.

    Field names are prefixed per kind (``once_at``, ``interval_every`` ...) so the
    full set of inputs can live in the DOM at once without colliding on submit.
    """
    f = request.form
    if kind == 'once':
        return {"at": (f.get('once_at') or '').strip()}
    if kind == 'interval':
        return {"every": max(1, _to_int(f.get('interval_every'), 1)),
                "unit": f.get('interval_unit') or 'minutes'}
    if kind == 'daily':
        return {"time": f.get('daily_time') or '00:00'}
    if kind == 'weekly':
        return {"weekday": _to_int(f.get('weekly_weekday'), 0),
                "time": f.get('weekly_time') or '00:00'}
    if kind == 'monthly':
        return {"day": max(1, min(31, _to_int(f.get('monthly_day'), 1))),
                "time": f.get('monthly_time') or '00:00'}
    return {}


def _parse_params() -> dict:
    """Optional advanced JSON params (the user-scope ops read policy/member/etc.
    from here). Empty or invalid -> ``{}`` so the page never 500s on bad input."""
    raw = (request.form.get('params_json') or '').strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        flash('Advanced params were not valid JSON and were ignored.', 'warning')
        return {}


def _custom_rest_params() -> dict:
    """Assemble the params for a custom REST action from its dedicated form
    fields (method / endpoint / mkey / JSON body). The endpoint is required;
    the body must be a JSON object (POST/PUT) or it is ignored."""
    f = request.form
    method = (f.get('custom_method') or 'GET').strip().upper()
    endpoint = (f.get('custom_endpoint') or '').strip()
    mkey = (f.get('custom_mkey') or '').strip()
    label = (f.get('custom_label') or '').strip()
    raw_body = (f.get('custom_body') or '').strip()
    params = {'method': method, 'endpoint': endpoint}
    if mkey:
        params['mkey'] = mkey
    if label:
        params['label'] = label
    if raw_body:
        try:
            parsed = json.loads(raw_body)
        except (ValueError, TypeError):
            parsed = None
            flash('Custom REST body was not valid JSON and was ignored.', 'warning')
        if isinstance(parsed, dict):
            params['body'] = parsed
        elif parsed is not None:
            flash('Custom REST body must be a JSON object and was ignored.', 'warning')
    return params


def _schedule_summary(kind: str, spec: dict) -> str:
    """One-line, human description of a schedule for the list page."""
    spec = spec or {}
    if kind == 'once':
        return f"Once at {spec.get('at') or '—'}"
    if kind == 'interval':
        return f"Every {spec.get('every', 1)} {spec.get('unit', 'minutes')}"
    if kind == 'daily':
        return f"Daily at {spec.get('time', '00:00')}"
    if kind == 'weekly':
        wd = _WEEKDAY_LABELS.get(_to_int(spec.get('weekday'), 0), '?')
        return f"Weekly on {wd} at {spec.get('time', '00:00')}"
    if kind == 'monthly':
        return f"Monthly on day {spec.get('day', 1)} at {spec.get('time', '00:00')}"
    return kind or '—'


def _apply_form(action: ScheduledAction) -> bool:
    """Read the editor form onto ``action`` (no commit). Returns False (and
    flashes) on a validation miss so the caller can bounce back to the form."""
    name = (request.form.get('name') or '').strip()
    spec = sa.get_spec((request.form.get('action') or '').strip())
    if not name:
        flash('A name is required.', 'danger')
        return False
    if spec is None:
        flash('Select a valid action from the catalog.', 'danger')
        return False

    kind = (request.form.get('schedule_kind') or 'once').strip()
    if spec.forced_schedule_kind:          # e.g. 'upgrade' is locked to 'once'
        kind = spec.forced_schedule_kind
    if kind not in SCHEDULE_KINDS:
        kind = 'once'
    schedule = _build_schedule(kind)

    action.name = name[:128]
    action.action = spec.key
    action.scope = spec.scope              # scope is derived from the spec
    action.targets = json.dumps(_build_targets())
    if spec.key == 'custom_rest':
        custom = _custom_rest_params()
        if not custom.get('endpoint'):
            flash('Custom REST: an endpoint (registry key or /api/... path) is required.', 'danger')
            return False
        action.params = json.dumps(custom)
    else:
        action.params = json.dumps(_parse_params())
    action.schedule_kind = kind
    action.schedule = json.dumps(schedule)
    action.enabled = bool(request.form.get('enabled'))
    action.catch_up = bool(request.form.get('catch_up'))
    action.next_run = compute_next_run(kind, schedule)
    return True


def _form_context(action: ScheduledAction | None) -> dict:
    appliances = (Appliance.query
                  .filter_by(kind='fortiweb')
                  .order_by(Appliance.name)
                  .all())
    return dict(
        action=action,
        admin_actions=sa.ADMIN_ACTIONS,
        user_actions=sa.USER_ACTIONS,
        all_actions=sa.ALL_ACTIONS,
        appliances=appliances,
        selected_targets=set(action.targets_list) if action else set(),
        schedule_kinds=SCHEDULE_KINDS,
        schedule=action.schedule_dict if action else {},
        params_text=(json.dumps(action.params_dict, indent=2)
                     if action and action.params_dict
                     and action.action != 'custom_rest' else ''),
        weekdays=WEEKDAYS,
        registry_endpoints=get_all_endpoints(),
        custom_params=(action.params_dict
                       if action and action.action == 'custom_rest' else {}),
    )


# --------------------------------------------------------------------------- #
#  Routes                                                                       #
# --------------------------------------------------------------------------- #
@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    actions = ScheduledAction.query.order_by(ScheduledAction.name).all()
    rows = []
    for a in actions:
        spec = sa.get_spec(a.action)
        rows.append({
            'a': a,
            'action_label': spec.label if spec else a.action,
            'danger': bool(spec.danger) if spec else False,
            'schedule': _schedule_summary(a.schedule_kind, a.schedule_dict),
            'target_count': len(a.targets_list),
        })
    return render_template('scheduled_actions/index.html', rows=rows)


@bp.route('/new', methods=['GET', 'POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def new():
    if request.method == 'POST':
        action = ScheduledAction(created_by=current_user.username)
        if _apply_form(action):
            db.session.add(action)
            db.session.commit()
            log_action('scheduled_action.create', target=action.name,
                       detail=f'{action.action} / {action.schedule_kind}')
            flash(f'Scheduled action "{action.name}" created.', 'success')
            return redirect(url_for('scheduled_actions.index'))
        return redirect(url_for('scheduled_actions.new'))
    return render_template('scheduled_actions/form.html', **_form_context(None))


@bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def edit(id):
    action = ScheduledAction.query.get_or_404(id)
    if request.method == 'POST':
        if _apply_form(action):
            db.session.commit()
            log_action('scheduled_action.update', target=action.name,
                       detail=f'{action.action} / {action.schedule_kind}')
            flash(f'Scheduled action "{action.name}" updated.', 'success')
            return redirect(url_for('scheduled_actions.index'))
        return redirect(url_for('scheduled_actions.edit', id=id))
    return render_template('scheduled_actions/form.html', **_form_context(action))


@bp.route('/<int:id>/toggle', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def toggle(id):
    action = ScheduledAction.query.get_or_404(id)
    action.enabled = not action.enabled
    if action.enabled:
        # Re-arm: a freshly enabled action gets a fresh next_run from now.
        action.next_run = compute_next_run(action.schedule_kind, action.schedule_dict)
    db.session.commit()
    state = 'enabled' if action.enabled else 'disabled'
    log_action('scheduled_action.toggle', target=action.name, detail=state)
    flash(f'Scheduled action "{action.name}" {state}.', 'success')
    return redirect(url_for('scheduled_actions.index'))


@bp.route('/<int:id>/delete', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete(id):
    action = ScheduledAction.query.get_or_404(id)
    name = action.name
    # Remove run history first (FK is ON DELETE CASCADE at the DB level, but
    # SQLite does not enforce it unless PRAGMA foreign_keys is on).
    ScheduledActionRun.query.filter_by(action_id=action.id).delete()
    db.session.delete(action)
    db.session.commit()
    log_action('scheduled_action.delete', target=name)
    flash(f'Scheduled action "{name}" deleted.', 'success')
    return redirect(url_for('scheduled_actions.index'))


@bp.route('/<int:id>/run-now', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def run_now(id):
    action = ScheduledAction.query.get_or_404(id)
    # NOTE: this runs SYNCHRONOUSLY in the request thread — device calls inside
    # execute_and_record may block for the client timeout. That is acceptable for
    # a deliberate, manual admin trigger; the unattended timer path uses the very
    # same execute_and_record from the scheduler sidecar.
    run = sa.execute_and_record(action, trigger="manual")
    if run is None:
        flash('This action is already running — try again shortly.', 'warning')
    else:
        category = ('success' if run.status == 'ok'
                    else 'warning' if run.status == 'skipped' else 'danger')
        flash(f'Run finished ({run.status}): {run.summary or "no summary"}',
              category)
    log_action('scheduled_action.run_now', target=action.name)
    return redirect(url_for('scheduled_actions.index'))


@bp.route('/<int:id>/history')
@login_required
@require_permission(Permission.USER_MANAGE)
def history(id):
    action = ScheduledAction.query.get_or_404(id)
    runs = (ScheduledActionRun.query
            .filter_by(action_id=action.id)
            .order_by(ScheduledActionRun.started_at.desc())
            .all())
    spec = sa.get_spec(action.action)
    return render_template('scheduled_actions/history.html',
                           action=action, runs=runs,
                           action_label=spec.label if spec else action.action)
