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

from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
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


#: The sample site the Name scope examples are built for.
SAMPLE_VALUES = {"dns": "app1.example.com", "service": "app1_example_com", "extra": "",
                 "port": "443"}


def scope_examples(cfg: dict) -> list[dict]:
    """The Server Policy (plugins) name a ``render_names`` step would build
    for the sample site, per zone and for "More than one zone", under *cfg*
    (saved or not) -- the step's own code, so the example cannot drift."""
    from ..services import studio_flow as F
    from ..services.studio_satom import render_names
    zones = store.classification("zones")
    rows = [(z, [z]) for z in zones]
    rows.append((None, zones if len(zones) > 1 else ["zone-a", "zone-b"]))
    out = []
    for label, zs in rows:
        try:
            name = render_names("", dict(SAMPLE_VALUES), scheme="naming", zones=zs,
                                scope_cfg=cfg)["server_policy"]
        except F.FlowError as exc:
            name = str(exc)
        if label is None:
            value = cfg.get("multi", "")
        else:
            value = next((v for k, v in cfg.get("zones", {}).items()
                          if k.lower() == label.lower()), "")
        out.append({"zone": label, "value": value, "scope": store.scope_for(zs, cfg),
                    "name": name})
    return out


def _name_scope_posted() -> dict:
    names = request.form.getlist("ns_zone_name[]")
    values = request.form.getlist("ns_zone_value[]")
    return store.normalize_name_scope({
        "enabled": request.form.get("ns_enabled") == "1",
        "zones": {n: (values[i] if i < len(values) else "") for i, n in enumerate(names)},
        "multi": request.form.get("ns_multi", ""),
    })


def _view_model(rows_by_kind=None, name_scope=None):
    catalog = store.all_classification()
    ns = name_scope or store.name_scope()
    return {
        'name_scope': ns,
        'name_scope_examples': scope_examples(ns),
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


@bp.route('/name-scope', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_name_scope():
    """Administrator > Classification > Name scope: the ONLY place the
    ``{scope}`` of a name is written. A refusal writes nothing and hands the
    operator's own values back."""
    cfg = _name_scope_posted()
    problems = store.save_name_scope(cfg)
    if problems:
        log_action('classification.name_scope_refused', detail='; '.join(problems))
        for p in problems:
            flash(p, 'danger')
        return render_template('classification/index.html',
                               **_view_model(name_scope=cfg)), 400
    saved = store.name_scope()
    log_action('classification.name_scope', detail='%s; %s; more than one zone=%s' % (
        'on' if saved['enabled'] else 'off',
        ', '.join('%s=%s' % (z, v or '-') for z, v in saved['zones'].items()) or 'no zones',
        saved['multi'] or '-'))
    flash('Name scope saved.', 'success')
    return redirect(url_for('classification.index') + '#name-scope')


@bp.route('/name-scope/preview', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def preview_name_scope():
    """The examples for the values ON THE PAGE (saved or not)."""
    body = request.get_json(silent=True) or {}
    cfg = store.normalize_name_scope(body)
    cfg["enabled"] = body.get("enabled") is True
    return jsonify({'examples': scope_examples(cfg),
                    'problems': store.name_scope_problems(cfg)})


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
