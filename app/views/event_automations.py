"""Automation > Automations > On a trigger — the IMPLEMENTATION half.

An event automation binds a trigger (Administrator > Triggers) to one thing
SATOM can already run: a Process walk, a published Python Studio app, a
Script Library script, a call through an HTTP connection (an API Catalog
endpoint when the connection is pinned to a version), SQL over a PostgreSQL
connection, a Studio data-store write, an integration hook, an existing
scheduled action, or a notification. The dispatch and the bounds live in
``services.trigger_engine``; this page only edits rows and shows history.

Gated on CONFIG_WRITE, the Automations page's own permission. Rows are scoped
to the ADOM they were created in (``product_scope.scope_query``), list AND
by-id, exactly like scheduled actions. An automation RUNS AS ITS OWNER — the
user who saved it last — so a Studio app it starts must be one that user may
use, and a script reads that user's vault entries.
"""
from __future__ import annotations

import json

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Permission, ScheduledAction, db
from ..models_triggers import EventAutomation, EventAutomationRun, Trigger
from ..services import trigger_engine as TE
from ..services.audit import log_action

bp = Blueprint('event_automations', __name__, url_prefix='/automations/on-trigger')

#: The form fields each kind keeps in ``params`` (posted as ``p_<kind>_<name>``).
KIND_PARAMS = {
    'process': ('appliance',),
    'app': ('inputs',),
    'script': ('inputs',),
    'api_call': ('operation', 'path_params', 'method', 'path', 'query', 'body', 'extract'),
    'sql_query': ('sql', 'params', 'allow_writes'),
    'store_write': ('mode', 'match', 'values'),
    'hook': (),
    'action': (),
    'notify': ('title', 'body', 'level', 'email_to'),
}
#: Checkbox params (posted as p_<kind>_<name>=1).
KIND_FLAGS = {'notify': ('bell', 'email_alerts')}


def _gate(fn):
    return login_required(require_permission(Permission.CONFIG_WRITE)(fn))


def _username() -> str:
    return getattr(current_user, 'username', '') or ''


def _scoped():
    from ..services.product_scope import scope_query
    return scope_query(EventAutomation.query, EventAutomation.product)


def _auto_or_404(id) -> EventAutomation:
    a = _scoped().filter(EventAutomation.id == id).first()
    if a is None:
        abort(404)
    return a


def _actions():
    """The scheduled actions this viewer may bind: the ADOM's own rows, user
    scope; System Automations too for an administrator."""
    from ..services.product_scope import scope_query
    from ..services import scheduled_actions as sa
    user_keys = {s.key for s in sa.USER_ACTIONS}
    rows = scope_query(ScheduledAction.query, ScheduledAction.product).order_by(
        ScheduledAction.name).all()
    admin = current_user.can('user_manage')
    return [r for r in rows if r.action in user_keys or admin]


def _choices() -> dict:
    from ..services import integration_hooks as ih
    from ..services import studio_apps as SA
    from ..services import studio_connections as SC
    from ..services import studio_store as SS
    from ..services import script_library as SL
    out = {
        'app': [(a.slug, '%s — %s' % (a.slug, a.name)) for a in
                SA.StudioApp.query.order_by(SA.StudioApp.slug).all()
                if a.published and a.kind != 'script'],  # a script app is the 'script' kind
        'script': [],
        'api_call': [(c.slug, c.slug) for c in SC.list_connections('http')],
        'sql_query': [(c.slug, c.slug) for c in SC.list_connections('postgres')],
        'store_write': [(s['slug'], s['slug']) for s in SS.list_stores()],
        'hook': [(h['slug'], '%s (%s)' % (h['slug'], h.get('event', '')))
                 for h in ih.list_hooks()],
        'action': [(str(r.id), '%s — %s' % (r.name, r.action)) for r in _actions()],
        'notify': [],
    }
    try:
        out['script'] = [(s['slug'], s['slug']) for s in SL.list_scripts()
                         if s.get('published')]
    except Exception:  # noqa: BLE001 -- a broken library dir must not break the page
        pass
    return out


def _form_context(a: EventAutomation | None, problems=()) -> dict:
    from ..services import studio_apis as SAPI
    return {
        'auto': a, 'problems': list(problems),
        'triggers': Trigger.query.order_by(Trigger.key).all(),
        'kinds': TE.KINDS, 'armable': TE.ARMABLE, 'choices': _choices(),
        'catalog': SAPI.choices(), 'kind_params': KIND_PARAMS,
        'params': (a.params if a is not None else {}),
    }


def _apply(a: EventAutomation) -> list[str]:
    from ..services import studio_apps as SA
    from ..services.product_scope import session_product, concrete_products
    f = request.form
    problems: list[str] = []
    a.name = (f.get('name') or '').strip()[:120]
    if not a.name:
        problems.append('the automation needs a name')
    a.description = (f.get('description') or '').strip()[:2000]
    a.enabled = bool(f.get('enabled'))
    try:
        tid = int(f.get('trigger_id') or 0)
    except ValueError:
        tid = 0
    trig = db.session.get(Trigger, tid) if tid else None
    if trig is None:
        problems.append('choose a trigger (Automations › Triggers)')
    else:
        a.trigger_id = trig.id
    kind = (f.get('kind') or '').strip()
    if kind not in TE.KINDS:
        problems.append('choose what it does')
        return problems
    a.kind = kind
    a.target = (f.get('target_' + kind) or '').strip()[:120]
    params = {}
    # Each kind's fields are posted as p_<kind>_<name>: two kinds share a
    # field name (app and script both take inputs), and the hidden section's
    # copy must never overwrite the visible one.
    for name in KIND_PARAMS[kind]:
        v = f.get('p_%s_%s' % (kind, name))
        if v not in (None, ''):
            params[name] = v
    for name in KIND_FLAGS.get(kind, ()):
        if f.get('p_%s_%s' % (kind, name)):
            params[name] = True
    a.params = params
    a.armed = bool(f.get('armed')) and kind in TE.ARMABLE
    a.owner = _username()
    a.updated_by = _username()
    if a.id is None:
        p = session_product()
        a.product = p if p in concrete_products() else ''
    if kind == 'action' and a.target and a.target not in {c[0] for c in _choices()['action']}:
        problems.append('that scheduled action is not one you may bind here')
    if kind == 'app' and a.target:
        app = SA.get(a.target)
        if app is not None and not SA.can_use(current_user, app):
            problems.append('you may not use app %r, so an automation you own may not '
                            'run it' % a.target)
    for name in ('inputs',):
        raw = params.get(name)
        if raw:
            try:
                if not isinstance(json.loads(raw), dict):
                    problems.append('inputs must be a JSON object of field: value')
            except ValueError as exc:
                problems.append('inputs are not valid JSON: %s' % exc)
    problems.extend(TE.problems(a))
    return problems


@bp.route('/')
@_gate
def index():
    rows = _scoped().order_by(EventAutomation.key.asc()).all()
    ids = [r.id for r in rows]
    runs = []
    if ids:
        runs = (EventAutomationRun.query.filter(EventAutomationRun.automation_id.in_(ids))
                .order_by(EventAutomationRun.id.desc()).limit(50).all())
    return render_template('event_automations/index.html', rows=rows, runs=runs,
                           kinds=TE.KINDS,
                           has_triggers=Trigger.query.count() > 0)


@bp.route('/new', methods=['GET', 'POST'])
@_gate
def new():
    if request.method == 'POST':
        a = EventAutomation()
        try:
            a.key = TE.validate_key(request.form.get('key') or '')
        except ValueError as exc:
            return render_template('event_automations/edit.html',
                                   **_form_context(None, [str(exc)])), 400
        if EventAutomation.query.filter_by(key=a.key).first() is not None:
            return render_template('event_automations/edit.html', **_form_context(
                None, ['an automation with key %r already exists' % a.key])), 400
        problems = _apply(a)
        if problems:
            return render_template('event_automations/edit.html',
                                   **_form_context(None, problems)), 400
        db.session.add(a)
        db.session.commit()
        log_action('event_automation.create', target=a.key,
                   extra={'trigger': a.trigger.key, 'kind': a.kind, 'target': a.target,
                          'armed': a.armed})
        flash('Automation %s created.' % a.name, 'success')
        return redirect(url_for('.edit', id=a.id))
    ctx = _form_context(None)
    ctx['preselect_trigger'] = request.args.get('trigger', type=int)
    return render_template('event_automations/edit.html', **ctx)


@bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@_gate
def edit(id):
    a = _auto_or_404(id)
    if request.method == 'POST':
        problems = _apply(a)
        if problems:
            db.session.rollback()
            return render_template('event_automations/edit.html',
                                   **_form_context(_auto_or_404(id), problems)), 400
        db.session.commit()
        log_action('event_automation.update', target=a.key,
                   extra={'trigger': a.trigger.key, 'kind': a.kind, 'target': a.target,
                          'armed': a.armed, 'enabled': a.enabled})
        flash('Automation saved. It runs as %s.' % a.owner, 'success')
        return redirect(url_for('.edit', id=a.id))
    ctx = _form_context(a)
    ctx['runs'] = (EventAutomationRun.query.filter_by(automation_id=a.id)
                   .order_by(EventAutomationRun.id.desc()).limit(50).all())
    ctx['current_problems'] = TE.problems(a)
    return render_template('event_automations/edit.html', **ctx)


@bp.route('/<int:id>/toggle', methods=['POST'])
@_gate
def toggle(id):
    a = _auto_or_404(id)
    a.enabled = not a.enabled
    a.updated_by = _username()
    db.session.commit()
    log_action('event_automation.toggle', target=a.key, extra={'enabled': a.enabled})
    flash('Automation %s %s.' % (a.name, 'enabled' if a.enabled else 'disabled'), 'success')
    return redirect(url_for('.index'))


@bp.route('/<int:id>/delete', methods=['POST'])
@_gate
def delete(id):
    a = _auto_or_404(id)
    key = a.key
    db.session.delete(a)
    db.session.commit()
    log_action('event_automation.delete', target=key)
    flash('Automation %s deleted.' % key, 'success')
    return redirect(url_for('.index'))


@bp.route('/<int:id>/test', methods=['POST'])
@_gate
def test(id):
    """Queue ONE rehearsal with the trigger event's documented example (or a
    pasted payload). Never armed, never chained."""
    a = _auto_or_404(id)
    raw = (request.form.get('payload') or '').strip()
    payload = None
    if raw:
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError('the payload must be a JSON object')
        except ValueError as exc:
            flash('Payload: %s' % exc, 'danger')
            return redirect(url_for('.edit', id=a.id))
    row = TE.test_run(a, payload, by=_username())
    log_action('event_automation.test', target=a.key, extra={'job': row['job_id']})
    flash('Rehearsal queued as job %s — its result appears in the history below.'
          % row['job_id'], 'info')
    return redirect(url_for('.edit', id=a.id) + '#history')
