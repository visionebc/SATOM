"""Automations — TWO surfaces over one table (Automation subsystem).

    /automations        Automations         scope 'user'   perm config_write
    /scheduled-actions  System Automations  scope 'admin'  perm user_manage

Until 2026-09-09 both lived in ONE list, sorted by name, behind ``user_manage``.
That is how "disable spo-tienda-mx at 02:00 on Saturday" — a cutover an operator
schedules, executed through FortiWebOps with snapshot + audit — came to sit
between "Nightly system backup" and "Sentinel — correlate and score", which are
SATOM maintaining ITSELF. The two are not the same object wearing two labels:
one is fleet work somebody planned, the other is the product's own housekeeping,
and the blast radius of a mistaken Delete differs by an order of magnitude.

Worse, the merge made the user half UNREACHABLE. ``USER_ACTIONS`` has existed in
the catalog since the beginning, but the only page that can create one was gated
on ``user_manage``, which the *operator* role does not hold — so the four
user-scope actions were offered to exactly the audience that does not schedule
cutovers. Every one of the 16 rows on the live node is admin scope; not one user
row was ever created.

THE PARTITION IS EXHAUSTIVE, AND THAT IS THE POINT. Splitting a list on a column
is how rows disappear: anything the filter does not claim is claimed by nobody,
keeps firing on its schedule, and is visible on no page. So the user surface
takes ``scope == 'user'`` and the system surface takes **everything else** —
NULL, a typo, a scope string from a future version. An unrecognised row lands in
front of the admin, who is the one who can fix it, and is flagged there.

THE SCOPE IS THE CATALOG'S, NOT THE COLUMN'S. ``ScheduledAction.scope`` is a
copy taken at write time (``_apply_form``), so re-scoping an ``ActionSpec``
would leave old rows stranded on the wrong page. ``effective_scope`` asks the
spec and falls back to the column only for a key the catalog no longer has.

ONE IMPLEMENTATION, TWO BINDINGS. The route bodies below are plain functions;
``_make_bp`` binds them to a blueprint with its own url_prefix and permission.
Two copies of this file would drift the first time either was fixed — the defect
this repo has already paid for in ``base.html`` and in the site footer.

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
                      ScheduledActionRun, db, visible_appliances,
                      visible_appliance_or_404)
from ..services import scheduled_actions as sa
from ..services.audit import log_action
from ..services.scheduler import SCHEDULE_KINDS, compute_next_run
from ..registry.loader import get_all_endpoints

# --------------------------------------------------------------------------- #
#  The two surfaces                                                             #
# --------------------------------------------------------------------------- #
USER_SCOPE = 'user'
ADMIN_SCOPE = 'admin'

#: blueprint name -> how that surface presents itself. ``other`` names the page
#: a rejected action belongs to: a refusal that does not say where the thing
#: lives is a dead end, and the operator cannot open the admin page to look.
SURFACES: dict[str, dict] = {
    'automations': {
        'scope': USER_SCOPE,
        'title': 'Automations',
        'icon': 'bi-calendar2-check',
        'blurb': ('Schedule work on the fleet — a cutover, a drained backend, '
                  'a certificate swap — to happen at a chosen time. Each one '
                  'changes ONE appliance through the same snapshot + audit + '
                  'change-history path as a manual edit.'),
        #: The permission this surface's routes are gated on. It lives
        #: HERE so the page that offers the cross-scope facet and the
        #: factory that binds the gate read ONE value: two copies drift
        #: the first time either moves, and the drift is silent.
        'permission': Permission.CONFIG_WRITE,
        'other': ('scheduled_actions', 'System Automations'),
    },
    'scheduled_actions': {
        'scope': ADMIN_SCOPE,
        'title': 'System Automations',
        'icon': 'bi-clock-history',
        'blurb': ('SATOM maintaining itself — backups, source-of-truth syncs, '
                  'probe sweeps, signature and CVE refreshes. These keep the '
                  'product\'s own data current; they are not fleet changes.'),
        'permission': Permission.USER_MANAGE,
        'other': ('automations', 'Automations'),
    },
}


def _surface() -> dict:
    """The surface this request is on.

    Falls back to the SYSTEM surface, never the user one: an unknown blueprint
    reaching here is a wiring bug, and defaulting it to the page with the lower
    permission would turn that bug into an access-control hole.
    """
    return SURFACES.get(request.blueprint or '', SURFACES['scheduled_actions'])


def effective_scope(action: ScheduledAction) -> str:
    """Which surface owns ``action`` — 'user' or 'admin', never anything else.

    Total by construction: only the catalog's literal ``'user'`` is user scope,
    everything else is admin. See the module docstring on why the partition may
    not have a hole.
    """
    spec = sa.get_spec(action.action)
    raw = spec.scope if spec is not None else (action.scope or '')
    return USER_SCOPE if raw == USER_SCOPE else ADMIN_SCOPE


def endpoint_for(action: ScheduledAction) -> str:
    """The blueprint name whose pages can open ``action``.

    Exported for the pages that LINK to an automation without owning it (the
    change calendar). A calendar entry that points at the page the row is not on
    is a 404 for the admin and a 403 for the operator — both read as "the thing
    is gone" rather than "this link is wrong".
    """
    return 'automations' if effective_scope(action) == USER_SCOPE else 'scheduled_actions'


def _scope_specs(scope: str) -> list:
    """The catalog half this surface may schedule."""
    return list(sa.USER_ACTIONS if scope == USER_SCOPE else sa.ADMIN_ACTIONS)

def _tz() -> str:
    """The timezone the wall-clock schedule fields on this page are expressed in.

    Read here and passed DOWN into the pure schedule math, never read inside it:
    ``services/scheduler`` is deliberately DB-free and stays testable."""
    from ..services import settings_store
    try:
        return settings_store.tz_name()
    except Exception:  # noqa: BLE001
        return "UTC"


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


def _action_or_404(id):
    """Load one scheduled action by id under the SAME ADOM scope as the list.

    Filtering the LIST while every by-id route reads the table raw is not
    scoping, it is decoration — the hole closed fleet-wide for appliances on
    2026-08-06 (``visible_appliance_or_404``) and for change requests in
    ``_cr_in_scope_or_404``. It did not matter here while Automation existed in
    one ADOM only; the moment the group renders in all of them, edit / toggle /
    delete / run-now are five cross-ADOM writes one URL away.

    404, never 403: do not confirm the row exists.
    """
    from flask import abort

    from ..services.product_scope import scope_query
    row = scope_query(
        ScheduledAction.query.filter(ScheduledAction.id == id),
        ScheduledAction.product).first()
    if row is None:
        abort(404)
    # ...and under the SAME SURFACE. Without this the split is decoration: the
    # user surface answers on ``config_write``, which the operator role holds,
    # so /automations/11/delete would remove the nightly system backup from a
    # page that never listed it. Same 404-not-403 reasoning as above.
    if effective_scope(row) != _surface()['scope']:
        abort(404)
    return row


def _adom_specs(specs):
    """The catalog entries the ACTIVE ADOM may schedule.

    An action declares the appliance KINDS it fires against (``spec.products``).
    Offering a FortiWeb-only action inside the FortiAnalyzer ADOM does not fail:
    it builds a job whose entire target set is invisible there, and a job that
    runs against nothing reports success. Global offers everything — it sees
    every product.
    """
    from ..services.product_scope import concrete_products, session_product
    p = session_product()
    if p not in concrete_products():
        return list(specs)
    return [s for s in specs if p in (s.products or ())]


def _rejected_targets(spec) -> list[str]:
    """Names of selected devices this action may not fire against.

    The form is a hint; this is the rule. Without it a posted ``targets`` field
    aims an action at a product it has no transport for — in the Global ADOM the
    picker legitimately lists every kind, so the mismatch is one click away.
    """
    ids = _build_targets()
    if not ids:
        return []
    kinds = set(spec.products or ())
    if not kinds:
        return []
    rows = visible_appliances().filter(Appliance.id.in_(ids)).all()
    return sorted(r.name for r in rows
                  if (r.kind or 'fortiweb').strip().lower() not in kinds)


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
    surface = _surface()
    if (USER_SCOPE if spec.scope == USER_SCOPE else ADMIN_SCOPE) != surface['scope']:
        # Known action, wrong surface. Silently accepting it would write a row
        # that vanishes from the page that created it and reappears on one the
        # author may not be allowed to open — the exact mixing this split exists
        # to end. Name the other page: a refusal without a destination is a dead
        # end (the rule /calendar/ already follows when it is switched off).
        flash('“%s” is a %s action. Create it on %s.'
              % (spec.label, spec.scope, surface['other'][1]), 'danger')
        return False
    if spec.key not in {s.key for s in _adom_specs(sa.ALL_ACTIONS.values())}:
        # Not "unknown" — known, and not this ADOM's to schedule. Saying so is
        # the difference between a typo and a permission answer.
        flash('That action does not apply to this ADOM.', 'danger')
        return False
    bad = _rejected_targets(spec)
    if bad:
        flash('This action cannot target %s.' % ', '.join(bad), 'danger')
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
    action.next_run = compute_next_run(kind, schedule, tz=_tz())
    return True


def _form_context(action: ScheduledAction | None) -> dict:
    # The roster follows the ADOM. The hardcoded ``kind='fortiweb'`` rendered an
    # EMPTY device list in every other ADOM — no error, no message, just a form
    # that silently could not target anything. ``visible_appliances`` already
    # applies the ADOM's kind filter (Global sees every product).
    appliances = visible_appliances().order_by(Appliance.name).all()
    return dict(
        action=action,
        # ONE catalog: this surface's half, cut again to the ADOM. Rendering
        # both halves and rejecting one on POST would advertise work the page
        # cannot do, which is how the merged list read in the first place.
        surface=_surface(),
        catalog=_adom_specs(_scope_specs(_surface()['scope'])),
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
#  Route bodies — plain functions, bound to BOTH blueprints by _make_bp         #
# --------------------------------------------------------------------------- #
def _index():
    """The surface's list, filtered by what this viewer asked to see.

    The filter is a VIEW preference persisted on the user's profile
    (``UserSetting``, ONE KEY PER SURFACE — see ``automation_filters.pref_key``
    for why a shared key would re-filter a page nobody was looking at). It never
    decides what anyone may DO: the cross-scope facet is offered only to a
    viewer who already holds the other surface's permission, and every row it
    reveals is drawn read-only and linked to the page that owns it.
    """
    from ..services.product_scope import scope_query
    from ..services import automation_filters as af
    from ..models import UserSetting

    surface = _surface()
    name = request.blueprint or 'scheduled_actions'
    other_name, other_title = surface['other']
    allow_cross = bool(getattr(current_user, 'is_authenticated', False)
                       and current_user.can(SURFACES[other_name]['permission']))

    uid = getattr(current_user, 'id', None)
    key = af.pref_key(name)
    saved_raw = UserSetting.get(uid, key) if uid is not None else None
    choices = {
        # Validated against the WHOLE catalog, not this surface's half: a key
        # from the other half is a filter that matches nothing here, which the
        # count and the filtered-empty state explain. Calling it "stale" would
        # blame the catalog for a value that is perfectly current.
        'action': {s.key for s in sa.ADMIN_ACTIONS} | {s.key for s in sa.USER_ACTIONS},
        'schedule': set(SCHEDULE_KINDS),
    }
    flt = af.resolve(request.args, saved_raw, choices=choices, allow_cross=allow_cross)

    # Persisted AFTER resolving, from the RESOLVED filter: a facet the resolver
    # dropped as stale must never be written back, or a value the catalog no
    # longer offers survives every future visit and hides the whole list.
    if uid is not None:
        if request.args.get('clear'):
            UserSetting.set(uid, key, '{}')
        elif flt.saved:
            UserSetting.set(uid, key, af.to_json(flt.filters))
        elif flt.from_query and saved_raw:
            # Submitted with "Remember for me" unticked while a saved filter
            # existed. Leaving it stored resurrects it on the next visit and
            # silently contradicts the box the user just cleared.
            UserSetting.set(uid, key, '{}')

    actions = (scope_query(ScheduledAction.query, ScheduledAction.product)
               .order_by(ScheduledAction.name).all())
    rows = []
    total = 0
    for a in actions:
        spec = sa.get_spec(a.action)
        row = {
            'a': a,
            'name': a.name,
            'scope': effective_scope(a),
            'action_key': a.action,
            'enabled': bool(a.enabled),
            'schedule_kind': a.schedule_kind,
            'action_label': spec.label if spec else a.action,
            'danger': bool(spec.danger) if spec else False,
            # A row whose key is no longer in the catalog still fires. It lands
            # here (see effective_scope) rather than nowhere, and says so —
            # an unlabelled orphan reads as a normal action.
            'orphan': spec is None,
            'schedule': _schedule_summary(a.schedule_kind, a.schedule_dict),
            'target_count': len(a.targets_list),
        }
        # The universe this page COULD draw, so "N of M" can never read N > M:
        # with the cross-scope facet on, the other half is part of M.
        if row['scope'] == surface['scope'] or flt.cross_scope:
            total += 1
        if not af.row_matches(row, flt.filters, surface_scope=surface['scope']):
            continue
        row['foreign'] = af.row_is_foreign(row, surface_scope=surface['scope'])
        row['owner_endpoint'] = endpoint_for(a)
        row['owner_title'] = other_title if row['foreign'] else surface['title']
        rows.append(row)

    # Only the specs a viewer can currently SEE are offered: a dropdown entry
    # that cannot match anything on this page is the mirror of a stale facet.
    visible_specs = list(_scope_specs(surface['scope']))
    if flt.cross_scope:
        visible_specs += list(_scope_specs(SURFACES[other_name]['scope']))

    return render_template(
        'scheduled_actions/index.html',
        rows=rows, surface=surface, flt=flt, total=total,
        allow_cross=allow_cross, other_title=other_title,
        action_choices=sorted({(s.key, s.label) for s in visible_specs},
                              key=lambda kv: kv[1]),
        schedule_choices=SCHEDULE_KINDS,
        status_choices=af.STATUS_CHOICES,
    )

def _new():
    if request.method == 'POST':
        from ..services.product_scope import stamp
        action = ScheduledAction(created_by=current_user.username,
                                 product=stamp() or 'fortiweb')
        if _apply_form(action):
            db.session.add(action)
            db.session.commit()
            log_action('scheduled_action.create', target=action.name,
                       detail=f'{action.action} / {action.schedule_kind}')
            flash(f'"{action.name}" created.', 'success')
            return redirect(url_for('.index'))
        return redirect(url_for('.new'))
    return render_template('scheduled_actions/form.html', **_form_context(None))


def _edit(id):
    action = _action_or_404(id)
    if request.method == 'POST':
        if _apply_form(action):
            db.session.commit()
            log_action('scheduled_action.update', target=action.name,
                       detail=f'{action.action} / {action.schedule_kind}')
            flash(f'"{action.name}" updated.', 'success')
            return redirect(url_for('.index'))
        return redirect(url_for('.edit', id=id))
    return render_template('scheduled_actions/form.html', **_form_context(action))


def _toggle(id):
    action = _action_or_404(id)
    action.enabled = not action.enabled
    if action.enabled:
        # Re-arm: a freshly enabled action gets a fresh next_run from now.
        action.next_run = compute_next_run(action.schedule_kind,
                                           action.schedule_dict, tz=_tz())
    db.session.commit()
    state = 'enabled' if action.enabled else 'disabled'
    log_action('scheduled_action.toggle', target=action.name, detail=state)
    flash(f'"{action.name}" {state}.', 'success')
    return redirect(url_for('.index'))


def _delete(id):
    action = _action_or_404(id)
    name = action.name
    # Remove run history first (FK is ON DELETE CASCADE at the DB level, but
    # SQLite does not enforce it unless PRAGMA foreign_keys is on).
    ScheduledActionRun.query.filter_by(action_id=action.id).delete()
    db.session.delete(action)
    db.session.commit()
    log_action('scheduled_action.delete', target=name)
    flash(f'"{name}" deleted.', 'success')
    return redirect(url_for('.index'))


def _run_now(id):
    action = _action_or_404(id)
    # NOTE: this runs SYNCHRONOUSLY in the request thread — device calls inside
    # execute_and_record may block for the client timeout. That is acceptable for
    # a deliberate, manual trigger; the unattended timer path uses the very same
    # execute_and_record from the scheduler sidecar.
    run = sa.execute_and_record(action, trigger="manual")
    if run is None:
        flash('This action is already running — try again shortly.', 'warning')
    else:
        category = ('success' if run.status == 'ok'
                    else 'warning' if run.status == 'skipped' else 'danger')
        flash(f'Run finished ({run.status}): {run.summary or "no summary"}',
              category)
    log_action('scheduled_action.run_now', target=action.name)
    return redirect(url_for('.index'))


def _history(id):
    action = _action_or_404(id)
    runs = (ScheduledActionRun.query
            .filter_by(action_id=action.id)
            .order_by(ScheduledActionRun.started_at.desc())
            .all())
    spec = sa.get_spec(action.action)
    return render_template('scheduled_actions/history.html',
                           action=action, runs=runs, surface=_surface(),
                           action_label=spec.label if spec else action.action)


# --------------------------------------------------------------------------- #
#  The two blueprints                                                           #
# --------------------------------------------------------------------------- #
def _make_bp(name: str, url_prefix: str) -> Blueprint:
    """Bind the route bodies above to one surface.

    The permission is the surface's, not the module's: ``config_write`` is what
    an operator holds and what every other page that mutates an appliance
    already asks for, while the product's own housekeeping stays on
    ``user_manage``. The by-id guard in ``_action_or_404`` is what makes that
    difference real rather than cosmetic.
    """
    permission = SURFACES[name]['permission']
    blueprint = Blueprint(name, __name__, url_prefix=url_prefix)

    def gate(fn):
        return login_required(require_permission(permission)(fn))

    blueprint.add_url_rule('/', 'index', gate(_index))
    blueprint.add_url_rule('/new', 'new', gate(_new), methods=['GET', 'POST'])
    blueprint.add_url_rule('/<int:id>/edit', 'edit', gate(_edit),
                           methods=['GET', 'POST'])
    blueprint.add_url_rule('/<int:id>/toggle', 'toggle', gate(_toggle),
                           methods=['POST'])
    blueprint.add_url_rule('/<int:id>/delete', 'delete', gate(_delete),
                           methods=['POST'])
    blueprint.add_url_rule('/<int:id>/run-now', 'run_now', gate(_run_now),
                           methods=['POST'])
    blueprint.add_url_rule('/<int:id>/history', 'history', gate(_history))
    return blueprint


#: System Automations. Keeps the historic name, URL and permission — every
#: existing row, bookmark, doc reference and test path lands here unchanged.
bp = _make_bp('scheduled_actions', '/scheduled-actions')

#: Automations. The new surface; the one an operator can actually reach.
user_bp = _make_bp('automations', '/automations')
