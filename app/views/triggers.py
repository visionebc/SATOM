"""Administrator > Change Management > Triggers — the CONDITION half.

A trigger names an event (an alert fired, a change was approved, a window is
opening, an automation finished, an outside system posted an event…) and
narrows which occurrences count. What happens when it matches is NOT
configured here: that is an event automation, operated from Automation >
Automations > On a trigger (views/event_automations.py). The split is the
operator's (2026-10-22): the creation of triggers is administered, their
implementation is operated.

Gated on USER_MANAGE like every Administrator page. Deleting a trigger that
an automation still uses is refused by name — a dangling automation would be
a plan that silently never fires.
"""
from __future__ import annotations

import json

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Permission, db
from ..models_triggers import EventAutomationRun, Trigger, TriggerFire
from ..services import trigger_engine as TE
from ..services.audit import log_action

bp = Blueprint('triggers', __name__, url_prefix='/administration/triggers')

SEVERITIES = ('info', 'warning', 'critical')


def _gate(fn):
    return login_required(require_permission(Permission.USER_MANAGE)(fn))


def _username() -> str:
    return getattr(current_user, 'username', '') or ''


def _int(value, default: int, lo: int, hi: int) -> int:
    try:
        v = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def _trigger_or_404(id) -> Trigger:
    t = db.session.get(Trigger, id)
    if t is None:
        abort(404)
    return t


def _form_context(t: Trigger | None, problems=(), form=None) -> dict:
    from ..services.product_scope import concrete_products
    from ..services.alert_routing import FAMILIES
    from ..models_triggers import EventAutomation
    ev = TE.events()
    cond = (t.conditions if t is not None else {}) if form is None else form
    return {
        'trig': t, 'events': ev, 'event_names': sorted(ev),
        'cond': cond, 'problems': list(problems),
        'products': [p for p in concrete_products()],
        'families': list(FAMILIES), 'severities': SEVERITIES,
        'where_ops': TE.WHERE_OPS,
        'automation_keys': [a.key for a in EventAutomation.query.order_by(
            EventAutomation.key).all()],
    }


def _apply(t: Trigger) -> list[str]:
    f = request.form
    problems: list[str] = []
    t.name = (f.get('name') or '').strip()[:120]
    if not t.name:
        problems.append('the trigger needs a name')
    t.description = (f.get('description') or '').strip()[:2000]
    event = (f.get('event') or '').strip()
    if event not in TE.events():
        problems.append('choose an event')
    t.event = event
    t.enabled = bool(f.get('enabled'))
    t.cooldown_minutes = _int(f.get('cooldown_minutes'), 60, 0, 60 * 24 * 30)
    t.rate_limit_per_hour = _int(f.get('rate_limit_per_hour'), 20, 0, 10_000)
    raw = {k: f.getlist(k) if k in ('products', 'families') else f.get(k)
           for k in TE.CONDITION_KEYS}
    cond, cprobs = TE.clean_conditions(raw)
    problems.extend(cprobs)
    t.conditions = cond
    t.updated_by = _username()
    return problems


@bp.route('/')
@_gate
def index():
    rows = Trigger.query.order_by(Trigger.key.asc()).all()
    counts = {}
    for t in rows:
        counts[t.id] = {
            'automations': len(t.automations),
            'enabled_automations': sum(1 for a in t.automations if a.enabled),
        }
    fires = (TriggerFire.query.order_by(TriggerFire.id.desc()).limit(50).all())
    return render_template('triggers/index.html', rows=rows, counts=counts, fires=fires,
                           events=TE.events())


@bp.route('/new', methods=['GET', 'POST'])
@_gate
def new():
    if request.method == 'POST':
        t = Trigger(created_by=_username(), event='')
        try:
            t.key = TE.validate_key(request.form.get('key') or '')
        except ValueError as exc:
            return render_template('triggers/edit.html',
                                   **_form_context(None, [str(exc)], _cond_from_form())), 400
        if Trigger.query.filter_by(key=t.key).first() is not None:
            return render_template('triggers/edit.html', **_form_context(
                None, ['a trigger with key %r already exists' % t.key],
                _cond_from_form())), 400
        problems = _apply(t)
        if problems:
            return render_template('triggers/edit.html',
                                   **_form_context(None, problems, t.conditions)), 400
        db.session.add(t)
        db.session.commit()
        log_action('trigger.create', target=t.key,
                   extra={'event': t.event, 'conditions': t.conditions})
        flash('Trigger %s created. Bind what it does under Automation › Automations › '
              'On a trigger.' % t.name, 'success')
        return redirect(url_for('.edit', id=t.id))
    return render_template('triggers/edit.html', **_form_context(None))


def _cond_from_form() -> dict:
    cond, _ = TE.clean_conditions({k: request.form.getlist(k)
                                   if k in ('products', 'families') else request.form.get(k)
                                   for k in TE.CONDITION_KEYS})
    return cond


@bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@_gate
def edit(id):
    t = _trigger_or_404(id)
    if request.method == 'POST':
        problems = _apply(t)
        if problems:
            db.session.rollback()
            return render_template('triggers/edit.html',
                                   **_form_context(_trigger_or_404(id), problems,
                                                   _cond_from_form())), 400
        db.session.commit()
        log_action('trigger.update', target=t.key,
                   extra={'event': t.event, 'conditions': t.conditions,
                          'enabled': t.enabled})
        flash('Trigger saved.', 'success')
        return redirect(url_for('.edit', id=t.id))
    ctx = _form_context(t)
    ctx['fires'] = (TriggerFire.query.filter_by(trigger_id=t.id)
                    .order_by(TriggerFire.id.desc()).limit(50).all())
    ctx['runs_by_fire'] = _runs_by_fire([f.id for f in ctx['fires']])
    return render_template('triggers/edit.html', **ctx)


def _runs_by_fire(fire_ids) -> dict:
    out: dict = {}
    if not fire_ids:
        return out
    for r in EventAutomationRun.query.filter(EventAutomationRun.fire_id.in_(fire_ids)).all():
        out.setdefault(r.fire_id, []).append(r)
    return out


@bp.route('/<int:id>/toggle', methods=['POST'])
@_gate
def toggle(id):
    t = _trigger_or_404(id)
    t.enabled = not t.enabled
    t.updated_by = _username()
    db.session.commit()
    log_action('trigger.toggle', target=t.key, extra={'enabled': t.enabled})
    flash('Trigger %s %s.' % (t.name, 'enabled' if t.enabled else 'disabled'), 'success')
    return redirect(url_for('.index'))


@bp.route('/<int:id>/delete', methods=['POST'])
@_gate
def delete(id):
    t = _trigger_or_404(id)
    if t.automations:
        flash('Trigger %s is used by %s. Delete or re-point those automations first.'
              % (t.name, ', '.join(a.key for a in t.automations)), 'danger')
        return redirect(url_for('.edit', id=t.id))
    key = t.key
    db.session.delete(t)
    db.session.commit()
    log_action('trigger.delete', target=key)
    flash('Trigger %s deleted.' % key, 'success')
    return redirect(url_for('.index'))


@bp.route('/<int:id>/preview', methods=['POST'])
@_gate
def preview(id):
    """Which occurrences WOULD match — nothing is fired, nothing is queued.

    For ``alert.fired`` / ``intent.deviation`` the candidates are the alert
    engine's findings right now (``alerts.evaluate``, the Settings Preview);
    for every event the operator may paste a payload; with neither, the
    event's documented example."""
    from ..services import alerts
    t = _trigger_or_404(id)
    rows = []
    raw = (request.form.get('payload') or '').strip()
    if raw:
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError('the payload must be a JSON object')
        except ValueError as exc:
            flash('Payload: %s' % exc, 'danger')
            return redirect(url_for('.edit', id=t.id))
        ok, why = TE.matches(t.conditions, payload)
        rows.append({'label': 'pasted payload', 'ok': ok, 'why': why,
                     'subject': TE.subject_of(t.event, payload)})
    elif t.event in ('alert.fired', 'intent.deviation'):
        node = alerts._node()
        for f in alerts.evaluate():
            p = (alerts.alert_event_payload(f, node) if t.event == 'alert.fired'
                 else alerts.intent_event_payload(f, node))
            if p is None:
                continue
            ok, why = TE.matches(t.conditions, p)
            rows.append({'label': '[%s] %s' % (f.get('severity', ''), f.get('title', '')),
                         'ok': ok, 'why': why, 'subject': TE.subject_of(t.event, p)})
        if not rows:
            rows.append({'label': 'no finding right now', 'ok': False,
                         'why': 'the alert engine has nothing to report', 'subject': ''})
    else:
        p = dict(TE.events().get(t.event, {}).get('example') or {})
        ok, why = TE.matches(t.conditions, p)
        rows.append({'label': 'documented example', 'ok': ok, 'why': why,
                     'subject': TE.subject_of(t.event, p)})
    ctx = _form_context(t)
    ctx['preview'] = rows
    ctx['preview_payload'] = raw
    ctx['fires'] = (TriggerFire.query.filter_by(trigger_id=t.id)
                    .order_by(TriggerFire.id.desc()).limit(50).all())
    ctx['runs_by_fire'] = _runs_by_fire([f.id for f in ctx['fires']])
    return render_template('triggers/edit.html', **ctx)
