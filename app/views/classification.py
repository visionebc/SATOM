"""Device **Classification** — standalone admin page.

The zones / lines / departments catalogs that drive the appliance
Zone/Line/Department dropdowns, the Architecture grouping, the bookmarks lens
and every auto-generated baseline combo. Ported out of the Settings console
into its own page (Administrator section).

The page edits ONE ROW PER VALUE rather than three free-text blobs, because a
blob cannot express the difference between "rename this" and "delete this and
add that" -- and those two mean opposite things to the rows that reference a
value by string. All reference bookkeeping lives in
``services.classification_ops``; this module only translates the form.

Admin-only (USER_MANAGE), mirroring the desktop Settings console.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Permission, db
from ..services import classification_ops as ops
from ..services import settings_store as store
from ..services.audit import log_action

bp = Blueprint('classification', __name__, url_prefix='/classification')

#: What an untouched "what happens to the references?" dropdown submits. It is
#: NOT the empty string: empty means "clear them", which is a decision, and the
#: two must never collapse into one another.
UNDECIDED = '?'
CLEAR = '__clear__'


def _view_model(rows_by_kind=None):
    catalog = store.all_classification()
    return {
        'classification': catalog,
        'usage': {k: {v: u.as_dict() for v, u in ops.usage(k).items()}
                  for k in store.CLASSIFICATION_KINDS},
        'unregistered': {k: {v: u.as_dict() for v, u in ops.unregistered(k).items()}
                         for k in store.CLASSIFICATION_KINDS},
        # On a refused save the operator gets their OWN rows back, not the
        # stored catalog: re-rendering the database would silently discard the
        # very edits they were just told to correct.
        'rows': rows_by_kind or {k: [{'orig': v, 'value': v, 'action': 'keep'}
                                     for v in catalog[k]]
                                 for k in store.CLASSIFICATION_KINDS},
        'undecided': UNDECIDED,
        'clear_token': CLEAR,
    }


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    return render_template('classification/index.html', **_view_model())


def _parse(kind: str) -> list[ops.Row]:
    origs = request.form.getlist(f'{kind}_orig[]')
    values = request.form.getlist(f'{kind}_value[]')
    actions = request.form.getlist(f'{kind}_action[]')
    targets = request.form.getlist(f'{kind}_reassign[]')

    def at(seq, i, default=''):
        return seq[i] if i < len(seq) else default

    rows = []
    for i in range(max(len(origs), len(values))):
        raw = at(targets, i, UNDECIDED)
        rows.append(ops.Row(
            orig=at(origs, i).strip(),
            value=at(values, i).strip(),
            action=(at(actions, i, 'keep').strip() or 'keep'),
            reassign='' if raw in (UNDECIDED, CLEAR) else raw.strip(),
            decided=raw != UNDECIDED,
        ))
    return rows


def _reassign_token(row: ops.Row) -> str:
    """Round-trip a delete decision back into the form. "Clear them" and "not
    decided yet" both carry an empty target, so the flag -- not the string --
    is what picks the option."""
    if not row.decided:
        return UNDECIDED
    return row.reassign or CLEAR


@bp.route('/save', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save():
    submitted = {k: _parse(k) for k in store.CLASSIFICATION_KINDS}
    try:
        reports = ops.apply_all(submitted)
    except ops.ClassificationError as exc:
        # Refused before anything became durable. Roll back so the pending ORM
        # edits from a half-walked plan cannot ride out on somebody else's
        # commit later in this request.
        db.session.rollback()
        log_action('classification.refused', detail=str(exc))
        flash(str(exc), 'danger')
        return render_template(
            'classification/index.html',
            **_view_model(rows_by_kind={
                k: [{'orig': r.orig, 'value': r.value, 'action': r.action,
                     'reassign': _reassign_token(r)}
                    for r in submitted[k]]
                for k in store.CLASSIFICATION_KINDS}),
        ), 400

    details = []
    for kind, rep in reports.items():
        if rep.added or rep.renamed or rep.deleted or rep.touched:
            details.append(
                f"{kind}: +{len(rep.added)} ~{len(rep.renamed)} -{len(rep.deleted)} "
                f"(refs: {rep.appliances} appliance, {rep.baselines} baseline, "
                f"{rep.segments} segment)")
    log_action('classification.save', detail='; '.join(details) or 'no change')

    total_refs = sum(r.touched for r in reports.values())
    absorbed = sum(r.baselines_absorbed for r in reports.values())
    if total_refs or absorbed:
        msg = f'Classification saved. {total_refs} reference(s) updated'
        if absorbed:
            msg += f', {absorbed} duplicate combo(s) absorbed'
        flash(msg + '.', 'success')
    else:
        flash('Classification catalogs saved.', 'success')
    return redirect(url_for('classification.index'))
