"""Templates — desired-state library admin page (web port of the desktop
Administrator → Template Library console).

Gated per action, not admin-only: ``operations.view`` lists and opens
templates, ``operations.template_save`` creates / edits / clones / deletes them,
``operations.template_approve`` approves, rejects or withdraws approval, and
``operations.template_apply`` applies one to appliances (dry-run preview first,
live write only with ``confirm=1``; a multi-device rollout also needs
``operations.apply`` and an approved template).

Every template carries the firmware build its body was written for
(``services.template_compat``). Apply checks the body against each target's
running build and refuses fields the build would silently discard; an approver
may override with a reason (audited). Approval records the builds it was
validated for, and a fleet rollout to any other build must be revalidated.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

from flask import (Blueprint, render_template, request, jsonify, flash,
                   redirect, url_for, abort)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Appliance, Template
from ..models import visible_appliances, visible_appliance_or_404
from ..services import templates as lib
from ..services import template_compat as tc
from ..services import template_bindings as tb
from ..services.audit import log_action
from ..services.bulk import BulkRunner, iter_push_items
from ..extensions import db

bp = Blueprint('templates', __name__, url_prefix='/templates')


def _safe_next(fallback: str) -> str:
    """Return a same-origin ``next`` target if present, else the fallback.

    Lets the per-section configuration page reuse the templates routes and bounce
    back to itself, without opening an open-redirect (only local paths allowed).
    """
    nxt = request.values.get('next') or ''
    if nxt.startswith('/') and not nxt.startswith('//'):
        ref = urlparse(nxt)
        if not ref.scheme and not ref.netloc:
            return nxt
    return fallback


def _pretty_json(raw: str) -> str:
    """Best-effort pretty-print of a stored JSON blob (empty -> '')."""
    if not (raw or '').strip():
        return ''
    try:
        return json.dumps(json.loads(raw), indent=2, sort_keys=True)
    except (ValueError, TypeError):
        return raw


@bp.route('/')
@login_required
@require_permission('operations.view')
def index():
    kind = request.args.get('kind') or None
    if kind and kind not in Template.KINDS:
        kind = None
    status = request.args.get('status') or None
    if status not in (Template.STATUS_PENDING, Template.STATUS_APPROVED,
                      Template.STATUS_REJECTED):
        status = None
    rows = lib.list_templates(kind)
    if status:
        rows = [t for t in rows if t.status == status]
    return render_template(
        'templates/index.html',
        templates=rows,
        kinds=Template.KINDS,
        kind_labels=lib.KIND_LABELS,
        active_kind=kind,
        active_status=status,
        appliances=visible_appliances().order_by(Appliance.name).all(),
        edit_template_id=None,
        firmware_choices=tc.known_builds(tc.session_product()),
    )


@bp.route('/', methods=['POST'])
@login_required
@require_permission('operations.template_save')
def create():
    kind = request.form.get('kind', '')
    name = request.form.get('name', '')
    body = request.form.get('body', '{}')
    note = request.form.get('note', '')
    exceptions = request.form.get('exceptions', '')
    try:
        stamp = tc.stamp_from_form(request.form.get('source_firmware', ''))
        row = lib.save_template(kind, name, body, note=note, exceptions=exceptions,
                                author=current_user.username, stamp=stamp)
        log_action('template.create', target=f'{row.kind}/{row.name}',
                   detail=f'version {row.version} firmware {row.source_firmware}')
        flash(f'Template "{row.name}" saved (v{row.version}).', 'success')
    except ValueError as exc:
        flash(f'Could not save template: {exc}', 'danger')
    return redirect(_safe_next(
        url_for('templates.index', kind=kind if kind in Template.KINDS else None)))


@bp.route('/<int:template_id>')
@login_required
@require_permission('operations.view')
def detail(template_id: int):
    """Return a single template (incl. pretty-printed body) as JSON for the
    view/inspect modal."""
    row = lib.get_template(template_id)
    if row is None:
        abort(404)
    _visible = {a.id for a in visible_appliances().all()}
    history = [
        {'action': e.action, 'reviewer': e.reviewer or '',
         'reason': e.reason or '',
         'created_at': e.created_at.isoformat() if e.created_at else ''}
        for e in lib.review_history(template_id)
    ]
    # Backfill a synthetic entry for templates reviewed BEFORE the history log
    # existed, so an already approved/rejected template still shows who/when.
    if not history and row.reviewed_by and row.status != Template.STATUS_PENDING:
        history = [{
            'action': ('reject' if row.status == Template.STATUS_REJECTED
                       else 'approve'),
            'reviewer': row.reviewed_by or '',
            'reason': row.reject_reason or '',
            'created_at': row.reviewed_at.isoformat() if row.reviewed_at else '',
        }]
    return jsonify({
        'id': row.id, 'kind': row.kind, 'name': row.name, 'version': row.version,
        'note': row.note or '', 'author': row.author or '',
        'locked': bool(row.locked), 'status': row.status,
        'reviewed_by': row.reviewed_by or '',
        'reviewed_at': row.reviewed_at.isoformat() if row.reviewed_at else '',
        'reject_reason': row.reject_reason or '',
        'created_at': row.created_at.isoformat() if row.created_at else '',
        'body': json.dumps(row.body_dict, indent=2, sort_keys=True),
        'exceptions': _pretty_json(row.exceptions or ''),
        'history': history,
        'source_firmware': row.source_firmware or '',
        'api_version': row.api_version or '',
        'source_appliance': row.source_appliance or '',
        'provenance': row.provenance or '',
        'adapted_from_id': row.adapted_from_id,
        'compat_check': row.compat_check_dict,
        'validated_builds': row.validated_builds_dict,
        'field_decisions': row.field_decisions_dict,
        'product': row.product or 'fortiweb',
        'placeholders': tb.placeholders(row.body_dict),
        # Bindings on devices this session cannot see are not listed: their
        # names and variables are another ADOM's data.
        'bindings': [_binding_json(b) for b in tb.for_template(row)
                     if b.appliance_id in _visible],
        'versions': [{'id': t.id, 'version': t.version, 'status': t.status,
                      'source_firmware': t.source_firmware or ''}
                     for t in tb.family(row.kind, row.name)],
    })


def _binding_json(b) -> dict:
    appl = db.session.get(Appliance, b.appliance_id)
    try:
        st = tb.status(b, appl)
    except Exception as exc:  # noqa: BLE001 — one unreadable binding never hides the rest
        st = {'state': 'error', 'blocking': True,
              'reason': f'{type(exc).__name__}: {exc}'}
    # Compliance: the cached device objects against the rendered template
    # (services.intent_compliance). Local, no device call; one unreadable
    # binding reads as unmeasured rather than hiding the rest.
    try:
        from ..services import intent_compliance as ic
        comp = ic.binding_compliance(b, appl)
    except Exception as exc:  # noqa: BLE001
        comp = {'status': 'unmeasured', 'reason': f'{type(exc).__name__}: {exc}',
                'deviations': 0, 'compared': 0}
    return {'id': b.id, 'appliance_id': b.appliance_id,
            'compliance': comp.get('status') or 'unmeasured',
            'compliance_reason': comp.get('reason') or '',
            'compliance_deviations': int(comp.get('deviations') or 0),
            'compliance_compared': int(comp.get('compared') or 0),
            'appliance': getattr(appl, 'name', '') or f'device {b.appliance_id}',
            'pinned_version': b.pinned_version, 'variables': b.variables_dict,
            'note': b.note or '', 'created_by': b.created_by or '',
            'state': st.get('state'), 'blocking': bool(st.get('blocking')),
            'build': st.get('build') or '', 'version': st.get('version'),
            'reason': st.get('reason') or ''}


@bp.route('/<int:template_id>/delete', methods=['POST'])
@login_required
@require_permission('operations.template_save')
def delete(template_id: int):
    row = lib.get_template(template_id)
    label = f'{row.kind}/{row.name}' if row else str(template_id)
    if lib.delete_template(template_id):
        log_action('template.delete', target=label)
        flash('Template deleted.', 'success')
    else:
        flash('Template not found or locked.', 'warning')
    return redirect(_safe_next(url_for('templates.index')))


@bp.route('/<int:template_id>/clone', methods=['POST'])
@login_required
@require_permission('operations.template_save')
def clone(template_id: int):
    """Clone a template (body + exceptions) under a new name (default '<name>
    (copy)'). The clone is unlocked and versioned for its name."""
    new_name = (request.form.get('new_name') or '').strip() or None
    try:
        row = lib.clone_template(template_id, new_name)
        log_action('template.clone', target=f'{row.kind}/{row.name}',
                   detail=f'from={template_id} version {row.version}')
        flash(f'Cloned to "{row.name}" (v{row.version}).', 'success')
    except ValueError as exc:
        flash(f'Could not clone template: {exc}', 'danger')
    return redirect(_safe_next(url_for('templates.index')))


@bp.route('/<int:template_id>/edit', methods=['GET', 'POST'])
@login_required
@require_permission('operations.template_save')
def edit(template_id: int):
    """Load an existing template's body + exceptions into the editor and save a
    NEW version of the same kind/name (the original version is preserved)."""
    row = lib.get_template(template_id)
    if row is None:
        abort(404)
    if request.method == 'POST':
        name = request.form.get('name', row.name)
        body = request.form.get('body', '{}')
        note = request.form.get('note', '')
        exceptions = request.form.get('exceptions', '')
        try:
            stamp = tc.stamp_from_form(request.form.get('source_firmware', ''), row)
            new = lib.save_template(row.kind, name, body, note=note,
                                    exceptions=exceptions, new_version=True,
                                    author=current_user.username, stamp=stamp)
            log_action('template.edit', target=f'{new.kind}/{new.name}',
                       detail=f'version {new.version} (from {template_id})')
            flash(f'Template "{new.name}" saved as v{new.version}.', 'success')
        except ValueError as exc:
            flash(f'Could not save template: {exc}', 'danger')
        return redirect(_safe_next(url_for('templates.index')))
    # GET — render the library with the edit modal pre-opened for this template.
    return render_template(
        'templates/index.html',
        templates=lib.list_templates(),
        kinds=Template.KINDS,
        kind_labels=lib.KIND_LABELS,
        active_kind=None,
        active_status=None,
        appliances=visible_appliances().order_by(Appliance.name).all(),
        edit_template_id=row.id,
        firmware_choices=tc.known_builds(tc.session_product()),
    )


@bp.route('/<int:template_id>/apply', methods=['POST'])
@login_required
@require_permission('operations.template_apply')
def apply(template_id: int):
    """Apply a template to selected appliances.

    Two-step and gated: a POST WITHOUT ``confirm`` returns a JSON dry-run preview
    (no device is contacted for real); a POST WITH ``confirm=1`` performs the
    live write (canary device first, the rest only if the canary succeeds).
    """
    row = lib.get_template(template_id)
    if row is None:
        abort(404)

    device_ids: list[int] = []
    for value in request.form.getlist('device_ids'):
        try:
            device_ids.append(int(value))
        except (TypeError, ValueError):
            continue
    confirm = request.form.get('confirm') == '1'
    wants_json = (request.form.get('format') == 'json'
                  or 'application/json' in (request.headers.get('Accept') or ''))
    # The picker only offers visible devices; the POST is checked against the
    # same set, so a hand-made id (a maintenance device, another ADOM's) is
    # refused instead of reaching the bulk runner, which does not re-check.
    visible_ids = {a.id for a in visible_appliances().all()}
    if any(d not in visible_ids for d in device_ids):
        if wants_json:
            return jsonify({'ok': False, 'error': 'Unknown appliance.'}), 404
        abort(404)
    # Single-device apply works on any status (operations.template_apply, already
    # enforced above). Multi-device = fleet rollout: needs operations.apply AND an
    # APPROVED template. This is the "approved != deployed; fleet rollout is a
    # separate, gated action" rule.
    if len(device_ids) > 1:
        if not current_user.can('operations.apply'):
            if wants_json:
                return jsonify({'ok': False,
                                'error': 'Fleet rollout requires the Run operations '
                                         'permission.'}), 403
            abort(403)
        if row.status != Template.STATUS_APPROVED:
            if wants_json:
                return jsonify({'ok': False,
                                'error': 'Template must be APPROVED before a '
                                         'multi-device (fleet) rollout.'}), 403
            abort(403)
    items = iter_push_items(row.body_dict)

    if not device_ids:
        if wants_json:
            return jsonify({'ok': False, 'error': 'Select at least one device.'}), 400
        flash('Select at least one device to apply to.', 'warning')
        return redirect(_safe_next(url_for('templates.index')))

    targets = visible_appliances().filter(Appliance.id.in_(device_ids)).all()
    fleet = len(device_ids) > 1
    # A body with {{ variables }} is rendered per device from its binding; a
    # device whose binding leaves one unset is refused (a literal placeholder
    # would be written to the box). No override: there is no value to write.
    bodies, missing_vars = tb.render_for_devices(row, device_ids)
    items_by_device = {aid: iter_push_items(b) for aid, b in bodies.items()}
    var_blocks = ['%s: no value for %s (set it on the device binding)'
                  % (next((a.name for a in targets if a.id == aid), aid), ', '.join(m))
                  for aid, m in sorted(missing_vars.items())]

    if not confirm:
        # Dry-run preview only — pure, never contacts a device for real. The
        # firmware check rides along so the operator sees a refusal BEFORE
        # pressing confirm, not after.
        compat = tc.for_appliances(row, targets, require_validated=fleet)
        # Fields a target's build does not have are stripped per device and
        # shown in the preview (services.build_compat), never dropped silently.
        if var_blocks:
            compat['blocked'] = True
            compat['blocks'] = var_blocks + list(compat.get('blocks') or [])
        compat['variables_missing'] = {str(k): v for k, v in missing_vars.items()}
        preview = BulkRunner(items, skips=compat.get('skips'),
                             items_by_device=items_by_device).preview(device_ids)
        log_action('template.apply.preview', target=f'{row.kind}/{row.name}',
                   detail=f'devices={device_ids} items={len(items)} '
                          f'compat_blocked={compat["blocked"]}')
        return jsonify({
            'ok': True, 'mode': 'preview',
            'template': {'id': row.id, 'name': row.name,
                         'kind': row.kind, 'version': row.version},
            'item_count': len(items),
            'preview': preview,
            'compat': compat,
            'can_override': bool(current_user.can('operations.template_approve')),
        })

    if var_blocks:
        msg = 'Refused: ' + '; '.join(var_blocks)
        log_action('template.apply.refused', target=f'{row.kind}/{row.name}',
                   detail=msg[:1500])
        if wants_json:
            return jsonify({'ok': False, 'error': msg}), 409
        flash(msg, 'danger')
        return redirect(_safe_next(url_for('templates.index')))
    allowed, compat = tc.enforce(
        row, targets, user=current_user,
        override_reason=request.form.get('override_reason', ''),
        require_validated=fleet, action='template.apply')
    if not allowed:
        log_action('template.apply.refused', target=f'{row.kind}/{row.name}',
                   detail='firmware check: ' + ' | '.join(compat['blocks'])[:1500])
        msg = ('Refused by the firmware compatibility check: '
               + '; '.join(compat['blocks'][:4])
               + (' (+%d more)' % (len(compat['blocks']) - 4)
                  if len(compat['blocks']) > 4 else '')
               + ' — ' + compat.get('override_hint', ''))
        if wants_json:
            return jsonify({'ok': False, 'error': msg, 'compat': compat}), 409
        flash(msg, 'danger')
        return redirect(_safe_next(url_for('templates.index')))

    # Confirmed live apply — runs as a BACKGROUND JOB (a fleet rollout must
    # not live inside an HTTP request: with many devices it outlives the
    # gunicorn/proxy timeout and a dropped connection would kill it midway).
    # The job dock (static/js/jobs.js) picks it up and shows live progress;
    # the completion audit row is written by the job itself.
    from flask import current_app
    from ..services.bulk import start_apply_job
    job = start_apply_job(
        current_app._get_current_object(),
        title=f'Apply "{row.name}" v{row.version} to {len(device_ids)} device(s)',
        items=items, device_ids=device_ids,
        by=getattr(current_user, 'username', '') or '',
        meta={'template_id': row.id, 'kind': row.kind, 'name': row.name,
              'compat_overridden': compat['overridden']},
        audit_action='template.apply',
        audit_target=f'{row.kind}/{row.name}',
        skips=compat.get('skips'), items_by_device=items_by_device)
    log_action('template.apply.start', target=f'{row.kind}/{row.name}',
               detail=f'devices={device_ids} items={len(items)} job={job["id"]}')
    if wants_json:
        return jsonify({'ok': True, 'mode': 'apply', 'job_id': job['id']}), 202
    flash(f'Rollout of "{row.name}" v{row.version} started for '
          f'{len(device_ids)} device(s) — progress appears in the job dock '
          '(bottom right).', 'info')
    return redirect(_safe_next(url_for('templates.index')))


def _approval_builds(row: Template) -> list[str]:
    """The builds an approval of ``row`` is validated for."""
    q = visible_appliances()
    if row.product:
        q = q.filter(Appliance.kind == row.product)
    builds = tc.fleet_builds(q.all())
    if row.source_firmware and row.source_firmware not in builds:
        builds.insert(0, row.source_firmware)
    return builds


def _wpp_rollout_targets(row: Template | None = None) -> list[int]:
    """The devices an approved WPP template rolls out to.

    Visible FortiWebs: ``visible_appliances()`` in the Global or FortiWeb ADOM
    also returns FortiADC / FortiAnalyzer / FortiAuthenticator rows, which have
    no Web Protection Profile to receive.

    With ``row``, the scope is the one the WPP lock uses
    (:func:`template_bindings.locked_families`): a family with no binding
    governs every FortiWeb; a bound family governs only its bound devices, and
    of those only the ones whose binding FOLLOWS this version -- a device pinned
    to another version keeps it. The approval used to deploy to every FortiWeb
    whatever the bindings said.
    """
    ids = [a.id for a in visible_appliances()
           .filter(Appliance.kind == 'fortiweb').all()]
    if row is None:
        return ids
    binds = tb.for_template(row)
    if not binds:
        return ids
    follows = set()
    for b in binds:
        t = tb.resolve(b)
        if t is not None and t.id == row.id:
            follows.add(b.appliance_id)
    return [i for i in ids if i in follows]


@bp.route('/<int:template_id>/approve', methods=['POST'])
@login_required
@require_permission('operations.template_approve')
def approve(template_id: int):
    """Approve a pending template, making it eligible for fleet rollout.

    **Web Protection Profile templates deploy fleet-wide on approval** (the team
    rule: a template-managed WPP is read-only on the devices; a change edited +
    approved here is what lands on EVERY device). The rollout runs as the same
    audited background bulk job the Apply button uses (canary first).
    """
    try:
        row = lib.approve_template(template_id, reviewer=current_user.username)
    except ValueError as exc:
        flash(f'Could not approve template: {exc}', 'danger')
        return redirect(_safe_next(url_for('templates.index')))
    # The approval is FOR builds: the body's own build plus every build this
    # template's product runs in the visible fleet, each checked now.
    builds = _approval_builds(row)
    verdicts = tc.validate(row, builds, by=current_user.username)
    from ..extensions import db
    db.session.commit()
    bad = sorted(b for b, v in verdicts.items() if v.get('blocking'))
    log_action('template.approve', target=f'{row.kind}/{row.name}',
               detail=f'version {row.version} validated for '
                      f'{",".join(sorted(verdicts)) or "no build"}'
                      + (f'; does NOT fit {",".join(bad)}' if bad else ''))
    flash(f'Approved "{row.name}" v{row.version} — validated for '
          f'{", ".join(sorted(verdicts)) or "no known build"}.', 'success')
    if bad:
        flash(f'"{row.name}" v{row.version} does not fit {", ".join(bad)}: '
              'applying it there is refused until it is adapted (or an approver '
              'overrides with a reason).', 'warning')

    from flask import current_app
    if (row.kind == Template.KIND_WEB_PROTECTION
            and not current_app.config.get('TESTING')):
        device_ids = _wpp_rollout_targets(row)
        items = iter_push_items(row.body_dict)
        if items and not device_ids and tb.for_template(row):
            flash(f'"{row.name}" v{row.version} was not deployed: no bound device '
                  'follows this version (their bindings pin another one).', 'info')
        # {{ variables }} are rendered per device from its binding, as the Apply
        # button does. A device left without a value holds the whole deploy: a
        # literal placeholder must never reach a box, and there is no value to
        # override with.
        bodies, missing_vars = tb.render_for_devices(row, device_ids)
        if device_ids and items and missing_vars:
            names = {a.id: a.name for a in visible_appliances()
                     .filter(Appliance.id.in_(list(missing_vars))).all()}
            why = '; '.join('%s: no value for %s' % (names.get(aid, aid), ', '.join(m))
                            for aid, m in sorted(missing_vars.items()))
            log_action('template.approve.autodeploy.held',
                       target=f'{row.kind}/{row.name}',
                       detail=('variables unset: ' + why)[:1500])
            flash(f'Fleet deploy of "{row.name}" v{row.version} HELD — {why}. '
                  'Set the values on the device bindings, then apply.', 'danger')
            return redirect(_safe_next(url_for('templates.index')))
        items_by_device = {aid: iter_push_items(b) for aid, b in bodies.items()}
        if device_ids and items:
            allowed, compat = tc.enforce(
                row, visible_appliances().filter(Appliance.id.in_(device_ids)).all(),
                require_validated=True, action='template.approve.autodeploy')
            if not allowed:
                log_action('template.approve.autodeploy.held',
                           target=f'{row.kind}/{row.name}',
                           detail=' | '.join(compat['blocks'])[:1500])
                flash(f'Fleet deploy of "{row.name}" v{row.version} HELD by the '
                      f'firmware check: {"; ".join(compat["blocks"][:3])}. Adapt '
                      'the template or apply with an override reason.', 'danger')
                return redirect(_safe_next(url_for('templates.index')))
            from ..services.bulk import start_apply_job
            job = start_apply_job(
                current_app._get_current_object(),
                title=(f'Deploy WPP template "{row.name}" v{row.version} to '
                       f'{len(device_ids)} device(s)'),
                items=items, device_ids=device_ids,
                by=getattr(current_user, 'username', '') or '',
                meta={'template_id': row.id, 'kind': row.kind, 'name': row.name,
                      'trigger': 'approve'},
                audit_action='template.apply',
                audit_target=f'{row.kind}/{row.name}',
                skips=compat.get('skips'), items_by_device=items_by_device or None)
            log_action('template.approve.autodeploy',
                       target=f'{row.kind}/{row.name}',
                       detail=f'devices={device_ids} items={len(items)} '
                              f'job={job["id"]}')
            scope = 'the bound' if tb.for_template(row) else 'ALL'
            flash(f'Deploying "{row.name}" v{row.version} to {scope} '
                  f'{len(device_ids)} device(s) — progress in the job dock.',
                  'info')
    return redirect(_safe_next(url_for('templates.index')))


@bp.route('/<int:template_id>/reject', methods=['POST'])
@login_required
@require_permission('operations.template_approve')
def reject(template_id: int):
    """Reject a template with an author-visible reason."""
    reason = (request.form.get('reason') or '').strip()
    try:
        row = lib.reject_template(template_id, reviewer=current_user.username,
                                  reason=reason)
        log_action('template.reject', target=f'{row.kind}/{row.name}',
                   detail=f'version {row.version}: {reason[:120]}')
        flash(f'Rejected "{row.name}" v{row.version}.', 'warning')
    except ValueError as exc:
        flash(f'Could not reject template: {exc}', 'danger')
    return redirect(_safe_next(url_for('templates.index')))


@bp.route('/<int:template_id>/unapprove', methods=['POST'])
@login_required
@require_permission('operations.template_approve')
def unapprove(template_id: int):
    """Revoke approval — returns the template to pending status."""
    try:
        row = lib.unapprove_template(template_id, reviewer=current_user.username)
        log_action('template.unapprove', target=f'{row.kind}/{row.name}',
                   detail=f'version {row.version}')
        flash(f'Approval revoked for "{row.name}" v{row.version} — returned to pending.',
              'warning')
    except ValueError as exc:
        flash(f'Could not revoke approval: {exc}', 'danger')
    return redirect(_safe_next(url_for('templates.index')))


# ---------------------------------------------------------------------------
# Firmware compatibility (services.template_compat)
# ---------------------------------------------------------------------------

@bp.route('/<int:template_id>/check')
@login_required
@require_permission('operations.view')
def check(template_id: int):
    """The body against one build (``?build=``), or against every build of the
    visible fleet when none is named. Read-only: nothing is recorded."""
    row = lib.get_template(template_id)
    if row is None:
        abort(404)
    build = (request.args.get('build') or '').strip()
    builds = [build] if build else _approval_builds(row)
    reports = {}
    for b in builds:
        try:
            reports[b] = tc.summarize(tc.check(row, b))
        except Exception as exc:  # noqa: BLE001 — one bad build never hides the rest
            reports[b] = {'state': 'error', 'level': 'warn', 'blocking': False,
                          'reason': f'{type(exc).__name__}: {exc}'}
    return jsonify({'ok': True, 'template_id': row.id,
                    'source_firmware': row.source_firmware or '',
                    'provenance': row.provenance or '',
                    'self_check': row.compat_check_dict,
                    'validated_builds': row.validated_builds_dict,
                    'reports': reports})


@bp.route('/<int:template_id>/validate', methods=['POST'])
@login_required
@require_permission('operations.template_approve')
def validate(template_id: int):
    """Revalidate an approved version for a build (or every fleet build).

    This is how an approval "for 8.0.5" is extended to 8.2.0: the approver runs
    the check for that build and the verdict is recorded. A verdict that does
    not fit is recorded as well — the apply gate keeps refusing it.
    """
    row = lib.get_template(template_id)
    if row is None:
        abort(404)
    wants_json = 'application/json' in (request.headers.get('Accept') or '')
    if row.status != Template.STATUS_APPROVED:
        msg = 'Only an approved template is validated for builds; approve it first.'
        if wants_json:
            return jsonify({'ok': False, 'error': msg}), 409
        flash(msg, 'warning')
        return redirect(_safe_next(url_for('templates.index')))
    build = (request.form.get('build') or '').strip()
    builds = [build] if build else _approval_builds(row)
    verdicts = tc.validate(row, builds, by=current_user.username)
    from ..extensions import db
    db.session.commit()
    bad = sorted(b for b, v in verdicts.items() if v.get('blocking'))
    log_action('template.validate', target=f'{row.kind}/{row.name}',
               detail=f'version {row.version} builds={",".join(sorted(verdicts))}'
                      + (f' not-fitting={",".join(bad)}' if bad else ''))
    if wants_json:
        return jsonify({'ok': True, 'verdicts': verdicts, 'not_fitting': bad})
    if bad:
        flash(f'Validated "{row.name}" v{row.version}; it does NOT fit '
              f'{", ".join(bad)} — adapt it for those builds.', 'warning')
    else:
        flash(f'Validated "{row.name}" v{row.version} for '
              f'{", ".join(sorted(verdicts)) or "no build"}.', 'success')
    return redirect(_safe_next(url_for('templates.index')))


@bp.route('/<int:template_id>/adapt', methods=['POST'])
@login_required
@require_permission('operations.template_save')
def adapt(template_id: int):
    """Adapt the body to a build: preview without ``confirm``, save with it.

    The result is a NEW, PENDING version (renames carried, fields the build
    does not serve removed, both listed in its note) — never an edit of the
    approved one.
    """
    row = lib.get_template(template_id)
    if row is None:
        abort(404)
    build = (request.form.get('build') or '').strip()
    try:
        if request.form.get('confirm') != '1':
            return jsonify({'ok': True, 'mode': 'preview',
                            'plan': tc.adapt_plan(row, build)})
        new, plan = tc.adapt(row, build, author=current_user.username,
                             decisions=request.form.get('decisions') or '{}')
        from ..extensions import db
        db.session.commit()
    except ValueError as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400
    log_action('template.adapt', target=f'{row.kind}/{row.name}',
               detail=f'v{row.version} ({row.source_firmware or "no firmware"}) '
                      f'-> v{new.version} for {plan["target_version"]}; '
                      f'{plan["changes"]} change(s)')
    return jsonify({'ok': True, 'mode': 'saved', 'template_id': new.id,
                    'version': new.version, 'plan': plan, 'note': new.note})


# --------------------------------------------------------------------------- #
#  Legacy stamp · device bindings · compatibility matrix                        #
# --------------------------------------------------------------------------- #
@bp.route('/<int:template_id>/stamp', methods=['POST'])
@login_required
@require_permission('operations.template_approve')
def stamp(template_id: int):
    """Record the firmware a LEGACY template (no stamp) was written for.

    Without ``confirm`` returns every measured build, best fit first. With it,
    stamps ``build`` (or the best fit) — never a build the body does not fit.
    """
    row = lib.get_template(template_id)
    if row is None:
        abort(404)
    try:
        if request.form.get('confirm') != '1':
            return jsonify({'ok': True, 'mode': 'preview',
                            'candidates': tc.stamp_candidates(row)})
        res = tc.stamp_legacy(row, request.form.get('build') or '',
                              by=current_user.username)
        from ..extensions import db
        db.session.commit()
    except ValueError as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400
    log_action('template.stamp', target=f'{row.kind}/{row.name}',
               detail=f'v{row.version} legacy -> {res["build"]}; {res["note"]}'[:1500])
    return jsonify({'ok': True, 'mode': 'saved', 'build': res['build'],
                    'note': res['note'], 'compat_check': row.compat_check_dict})


@bp.route('/<int:template_id>/bindings', methods=['POST'])
@login_required
@require_permission('operations.template_save')
def bind(template_id: int):
    """Bind a device of the template's ADOM (create or update)."""
    row = lib.get_template(template_id)
    if row is None:
        abort(404)
    try:
        aid = int(request.form.get('appliance_id') or 0)
    except (TypeError, ValueError):
        aid = 0
    appl = visible_appliances().filter(Appliance.id == aid).first() if aid else None
    if appl is None:
        return jsonify({'ok': False, 'error': 'Unknown appliance.'}), 404
    try:
        b = tb.bind(appl, row, pinned_version=request.form.get('pinned_version') or None,
                    variables=request.form.get('variables') or '{}',
                    note=(request.form.get('note') or '').strip(),
                    by=current_user.username)
        from ..extensions import db
        db.session.commit()
    except ValueError as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400
    log_action('template.bind', target=f'{row.kind}/{row.name}', appliance_id=appl.id,
               detail=f'pinned={b.pinned_version or "latest approved"} '
                      f'variables={",".join(sorted(b.variables_dict))}')
    return jsonify({'ok': True, 'binding': _binding_json(b)})


@bp.route('/bindings/<int:binding_id>/delete', methods=['POST'])
@login_required
@require_permission('operations.template_save')
def unbind(binding_id: int):
    from ..models_tpl_binding import TemplateBinding
    b = db.session.get(TemplateBinding, binding_id)
    if b is None:
        abort(404)
    visible_appliance_or_404(b.appliance_id)
    tb.unbind(binding_id)
    db.session.commit()
    log_action('template.unbind', target=f'{b.kind}/{b.name}',
               appliance_id=b.appliance_id, detail='binding removed')
    return jsonify({'ok': True})


@bp.route('/matrix')
@login_required
@require_permission('operations.view')
def matrix():
    """Every template of the ADOM against every build the ADOM knows (+ ``?build=``
    a target being considered): fits / adapt / unmeasured / block per cell."""
    product = tc.session_product()
    from ..services import version_compat as vc
    rows = [t for t in lib.list_templates(None) if (t.product or 'fortiweb') == product]
    if request.args.get('all') != '1':
        latest = {}
        for t in rows:
            k = (t.kind, t.name)
            if k not in latest or t.version > latest[k].version:
                latest[k] = t
        rows = sorted(latest.values(), key=lambda t: (t.kind, t.name.lower()))
    extra = [b for b in request.args.getlist('build') if b]
    cols = tc.matrix_builds(product, extra)
    builds = [c['version'] for c in cols]
    grid = tc.matrix(rows, builds)
    fleet = {}
    for a in visible_appliances().filter(Appliance.kind == product).all():
        v = vc._resolved(a).get('version') or ''
        if v:
            fleet.setdefault(v, []).append(a.name)
    bound = {}
    for t in rows:
        bound[t.id] = [b.appliance_id for b in tb.for_template(t)]
    return render_template('templates/matrix.html', grid=grid, cols=cols,
                           fleet=fleet, bound=bound,
                           show_all=request.args.get('all') == '1',
                           extra=extra, firmware_choices=tc.known_builds(product))
