"""System Provisioning — author and apply baseline FortiWeb *system* config.

Web UI over :mod:`app.services.provisioning`. An operator composes a declarative
``SystemProfile`` (DNS, NTP, RADIUS, SNMP, admins…) once, versions it as a
``Template`` (kind ``system-profile``), then pushes it to a single device or the
whole fleet through the shared dry-run -> canary-apply machinery.

Discipline (mirrors the desktop): nothing touches a device until ``apply`` runs,
and even then the operator first sees a per-device dry-run preview and must
explicitly confirm the real write. Secrets are never persisted in the template
(``save_profile`` strips them) and are not pushed by an apply: the preview
names the sensitive elements so the operator sets them on the device after.

Every route requires an authenticated user holding ``CONFIG_WRITE``.
"""
from __future__ import annotations

import json

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Appliance, Permission, Template, UserSetting, db
from ..models import visible_appliances, visible_appliance_or_404
from ..services import provisioning as prov
from ..services.audit import log_action
from ..services.templates import delete_template, get_template, list_templates
from ..services import baselines as B
from ..services import settings_store
from ..services import template_compat as tc
from ..services import template_bindings as tb
from ..services.bulk import BulkRunner

bp = Blueprint('provisioning', __name__, url_prefix='/provisioning')


# --------------------------------------------------------------------------- #
#  Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _system_template_or_404(template_id: int) -> Template:
    """Fetch a ``system-profile`` template by id or abort 404."""
    template = get_template(template_id)
    if template is None or template.kind != Template.KIND_SYSTEM:
        abort(404)
    return template


def _render_form(*, profile_name: str = '', rows=None, template_id=None,
                 scope=None, source_firmware: str = ''):
    """Render the profile builder (shared by /new and /<id>/edit).

    Mirrors the desktop: the Element picker offers EVERY config (``cmdb``) object
    grouped by GUI section; the operator sets singleton/mkey and types the JSON
    values. No firmware-line / typed-schema layer — the standalone format.
    """
    from collections import OrderedDict
    from ..registry import loader

    specs = prov.all_specs()                       # all cmdb objects, section-ordered
    sec_by_name = {ep.get('name'): (ep.get('section') or 'Other')
                   for ep in loader.get_all_endpoints()}
    grouped = OrderedDict()
    for s in specs:
        section = sec_by_name.get(s.endpoint) or (s.note or 'Other')
        grouped.setdefault(section, []).append(s)
    cls = settings_store.all_classification()
    return render_template(
        'provisioning/form.html',
        grouped_specs=grouped,
        spec_keys=[s.key for s in specs],
        profile_name=profile_name,
        rows=rows or [],
        template_id=template_id,
        scope=scope or {},
        zones=cls.get('zones', []),
        lines=cls.get('lines', []),
        departments=cls.get('departments', []),
        firmware_choices=tc.known_builds(tc.session_product()),
        source_firmware=source_firmware,
    )


def _collect_rows():
    """Read the repeatable element editor into ``(name, scope, rows)``.

    Each row declares its index via a hidden ``rows`` input; per-field names are
    ``key_<i>``/``mkey_<i>``/``data_<i>``/``singleton_<i>``. Pure form-reading —
    never raises, so the builder can be re-rendered with the operator's input
    intact on an error. Order follows the submitted ``rows`` order (DOM order),
    so the up/down buttons reorder the steps.
    """
    name = (request.form.get('name') or '').strip()
    scope = {
        'zone': (request.form.get('scope_zone') or '').strip(),
        'line': (request.form.get('scope_line') or '').strip(),
        'department': (request.form.get('scope_department') or '').strip(),
    }
    rows = []
    for idx in request.form.getlist('rows'):
        rows.append({
            'key': (request.form.get(f'key_{idx}') or '').strip(),
            'mkey': (request.form.get(f'mkey_{idx}') or '').strip(),
            'data': request.form.get(f'data_{idx}') or '',
            'singleton': request.form.get(f'singleton_{idx}') is not None,
        })
    return name, scope, rows


def _build_items(rows):
    """Turn collected rows into ``ProvisionItem``s.

    The element key identifies a config object from the full catalog
    (``provisioning.all_specs`` — a curated baseline or any other cmdb object);
    its ``data`` is parsed as a JSON payload. Raises ``ValueError`` (unknown key
    / bad JSON) so the caller can flash and re-render with input kept.
    """
    catalog = {s.key: s for s in prov.all_specs()}
    items = []
    for row in rows:
        key = row['key']
        if not key:
            continue  # skip blank rows
        spec = prov.CATALOG_BY_KEY.get(key) or catalog.get(key)
        if spec is None:
            raise ValueError(f"Unknown provisioning element: {key}")
        try:
            data = json.loads(row['data'] or '{}')
        except ValueError as exc:
            raise ValueError(f"Element '{spec.label}': values are not valid JSON ({exc})") from exc
        if not isinstance(data, dict):
            raise ValueError(f"Element '{spec.label}': values must be a JSON object")
        item = prov.ProvisionItem.from_spec(spec, data, mkey=row['mkey'] or None)
        item.singleton = row['singleton']  # honour the explicit checkbox
        items.append(item)
    return items


def _save(*, template_id):
    """Validate + persist the builder form. On error re-renders with input kept."""
    name, scope, rows = _collect_rows()
    firmware = (request.form.get('source_firmware') or '').strip()
    try:
        if not name:
            raise ValueError("Profile name is required")
        items = _build_items(rows)
        if not items:
            raise ValueError("Add at least one provisioning element")
        previous = get_template(template_id) if template_id else None
        stamp = tc.stamp_from_form(firmware, previous)
        profile = prov.SystemProfile(name, items, scope=scope)
        row = prov.save_profile(profile, author=getattr(current_user, 'username', '') or '',
                                stamp=stamp)
    except ValueError as exc:
        flash(f"Could not save profile: {exc}", 'danger')
        return _render_form(profile_name=name, rows=rows, template_id=template_id,
                            scope=scope, source_firmware=firmware)
    log_action('provisioning.save', target=row.name,
               detail=f'v{row.version}, {len(items)} item(s)')
    flash(f'System profile "{row.name}" saved (v{row.version}).', 'success')
    return redirect(url_for('provisioning.index'))


# --------------------------------------------------------------------------- #
#  Routes                                                                       #
# --------------------------------------------------------------------------- #
@bp.route('/')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def index():
    """List existing system-profile templates with a 'New profile' action."""
    return render_template(
        'provisioning/index.html',
        profiles=B._latest_version_only(list_templates(Template.KIND_SYSTEM)),
        appliances=visible_appliances().order_by(Appliance.name).all(),
    )


@bp.route('/new', methods=['GET', 'POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def new():
    """Author a new system profile."""
    if request.method == 'POST':
        return _save(template_id=None)
    return _render_form()


@bp.route('/<int:template_id>/edit', methods=['GET', 'POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def edit(template_id: int):
    """Edit an existing profile (saving creates a new version)."""
    template = _system_template_or_404(template_id)
    if request.method == 'POST':
        return _save(template_id=template_id)
    profile = prov.SystemProfile.from_template(template)
    rows = [{
        'key': it.key,
        'mkey': it.mkey or '',
        'singleton': it.singleton,
        'data': json.dumps(it.data, indent=2, sort_keys=True) if it.data else '{}',
    } for it in profile.items]
    return _render_form(profile_name=profile.name, rows=rows,
                        template_id=template_id, scope=profile.scope,
                        source_firmware=template.source_firmware or '')


@bp.route('/<int:template_id>/apply', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def apply(template_id: int):
    """Two-phase apply: dry-run preview first, then a confirmed live write.

    The first POST (no ``confirm``) renders the per-device planned requests from
    ``apply(..., dry_run=True)``. A second POST carrying ``confirm=1`` runs
    ``apply(..., dry_run=False, canary=1)`` against live devices and shows the
    ``{canary, rest, aborted}`` outcome.
    """
    template = _system_template_or_404(template_id)
    profile = prov.SystemProfile.from_template(template)

    target_hostname = (request.form.get('target_hostname') or '').strip()
    change_id = (request.form.get('change_id') or '').strip()
    if not target_hostname or not change_id:
        flash('Hostname and Change ID are required.', 'warning')
        return redirect(url_for('provisioning.index'))

    mode = request.form.get('mode', 'selected')
    selected_ids = []
    for value in request.form.getlist('device_ids'):
        try:
            selected_ids.append(int(value))
        except (TypeError, ValueError):
            continue

    # Guard: 'selected' with nothing chosen must NOT silently target the fleet
    # (BulkRunner treats an empty id list as "all appliances").
    if mode != 'fleet' and not selected_ids:
        flash('Select at least one appliance, or choose "Entire fleet".', 'warning')
        return redirect(url_for('provisioning.index'))

    if mode == 'fleet':
        target_appliances = visible_appliances().order_by(Appliance.name).all()
        target_desc = 'Entire fleet (all appliances)'
    else:
        target_appliances = (visible_appliances()
                              .filter(Appliance.id.in_(selected_ids))
                              .order_by(Appliance.name).all())
        target_desc = ', '.join(a.name for a in target_appliances) or '(none)'
    # The runner gets exactly the devices this page counted: the visible set.
    # "Entire fleet" used to travel as an empty list, which the runner read as
    # every row in the table -- other ADOMs and maintenance devices included.
    device_ids = [a.id for a in target_appliances]
    if not device_ids:
        flash('No visible appliance matches this selection.', 'warning')
        return redirect(url_for('provisioning.index'))

    confirmed = request.form.get('confirm') == '1'
    # Their secret fields were stripped on save; say so before the push.
    secret_items = [it.label or it.endpoint for it in profile.items
                    if prov._item_is_sensitive(it)]

    # {{ variables }} render per device from its binding, as the template
    # Apply does: the preview shows the real values, and a device left without
    # one refuses the live push (a literal placeholder never reaches a box).
    items_by_device, missing_vars = tb.render_parts_for_devices(
        [(template, prov.push_items(profile))], device_ids)
    missing_why = tb.missing_text(missing_vars, {a.id: a.name for a in target_appliances})

    if not confirmed:
        compat = tc.for_appliances(template, target_appliances, require_validated=True)
        preview = prov.apply(profile, device_ids, dry_run=True, skips=compat.get('skips'),
                             items_by_device=items_by_device)
        if missing_vars:
            flash(f'The live deploy will be refused: {missing_why}. Set the values '
                  'on the device bindings first.', 'danger')
        log_action('provisioning.preview', target=profile.name,
                   detail=f'{mode}, {len(target_appliances)} device(s), host={target_hostname}, '
                          f'change={change_id}, compat_blocked={compat["blocked"]}')
        return render_template(
            'provisioning/apply.html',
            phase='preview', prof_name=profile.name, template_id=template_id,
            preview=preview, result=None, secret_items=secret_items,
            mode=mode, device_ids=device_ids,
            target_desc=target_desc, target_count=len(target_appliances),
            target_hostname=target_hostname, change_id=change_id,
            compat_reports=[compat],
            can_override=current_user.can('operations.template_approve'),
        )

    # Confirmed -> real canary-gated write to live devices. Only an APPROVED
    # profile is fleet-deployable (operations.template_approve); the dry-run
    # preview above stays available for a pending one.
    if template.status != Template.STATUS_APPROVED:
        log_action('provisioning.apply', target=profile.name,
                   detail=f'refused: profile is {template.status}, not approved; '
                          f'{mode}, host={target_hostname}, change={change_id}')
        flash(f'"{profile.name}" is {template.status}: only an approved system '
              f'profile can be deployed live. The preview stays available; ask an '
              f'administrator to approve it first.', 'danger')
        return redirect(url_for('provisioning.index'))
    if missing_vars:
        log_action('provisioning.apply', target=profile.name,
                   detail=('refused: variables unset: ' + missing_why)[:1500])
        flash(f'Deploy of "{profile.name}" refused — {missing_why}. Set the values '
              'on the device bindings, then apply.', 'danger')
        return redirect(url_for('provisioning.index'))
    allowed, compat = tc.enforce(
        template, target_appliances, user=current_user,
        override_reason=request.form.get('override_reason', ''),
        require_validated=True, action='provisioning.apply')
    if not allowed:
        log_action('provisioning.apply', target=profile.name,
                   detail='refused by the firmware check: '
                          + ' | '.join(compat['blocks'])[:1500])
        flash('Refused by the firmware compatibility check: '
              + '; '.join(compat['blocks'][:4]) + ' — '
              + compat.get('override_hint', ''), 'danger')
        return redirect(url_for('provisioning.index'))
    flash(f'Deploying [{change_id}] to {target_hostname} — canary device writes first.', 'warning')
    result = prov.apply(profile, device_ids, dry_run=False, canary=1,
                        skips=compat.get('skips'), items_by_device=items_by_device)
    log_action('provisioning.apply', target=profile.name,
               detail=f'{mode}, host={target_hostname}, change={change_id}, aborted={result.get("aborted")}')
    return render_template(
        'provisioning/apply.html',
        phase='result', prof_name=profile.name, template_id=template_id,
        preview=None, result=result,
        mode=mode, device_ids=device_ids,
        target_desc=target_desc, target_count=len(target_appliances),
        target_hostname=target_hostname, change_id=change_id,
    )


@bp.route('/<int:template_id>/delete', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def delete(template_id: int):
    """Delete a system profile template."""
    template = get_template(template_id)
    if template is not None and template.kind != Template.KIND_SYSTEM:
        abort(404)
    label = template.name if template else str(template_id)
    if delete_template(template_id):
        log_action('provisioning.delete', target=label)
        flash('System profile deleted.', 'success')
    else:
        flash('Profile not found or locked.', 'warning')
    return redirect(url_for('provisioning.index'))



@bp.route('/<int:template_id>/approve', methods=['POST'])
@login_required
@require_permission('operations.template_approve')
def approve_profile(template_id: int):
    """Approve a pending system-profile template."""
    from ..services.templates import approve_template, self_approval_allowed
    _system_template_or_404(template_id)
    try:
        row = approve_template(template_id, reviewer=current_user.username,
                               self_ok=self_approval_allowed(current_user))
        log_action('provisioning.approve', target=row.name,
                   detail=f'v{row.version}'
                          + ('; self-approved by its author'
                             if (row.author or '').strip() == current_user.username else ''))
        flash(f'Approved "{row.name}" v{row.version} — now selectable for baselines.', 'success')
    except ValueError as exc:
        flash(f'Could not approve: {exc}', 'danger')
    return redirect(url_for('provisioning.index'))


@bp.route('/<int:template_id>/reject', methods=['POST'])
@login_required
@require_permission('operations.template_approve')
def reject_profile(template_id: int):
    """Reject a pending system-profile template."""
    from ..services.templates import reject_template
    _system_template_or_404(template_id)
    reason = (request.form.get('reason') or '').strip()
    try:
        row = reject_template(template_id, reviewer=current_user.username,
                              reason=reason)
        log_action('provisioning.reject', target=row.name,
                   detail=f'v{row.version}: {reason[:120]}')
        flash(f'Rejected "{row.name}" v{row.version}.', 'warning')
    except ValueError as exc:
        flash(f'Could not reject: {exc}', 'danger')
    return redirect(url_for('provisioning.index'))


# --------------------------------------------------------------------------- #
#  Baselines — assembly of approved templates by zone / line / department       #
# --------------------------------------------------------------------------- #
def _baseline_form_ctx(*, baseline=None, zone: str = "", line: str = "",
                        department: str = ""):
    """Shared context for the baseline new/edit form."""
    cls = settings_store.all_classification()
    # Scope comes from the submitted form (new) or the saved baseline (edit).
    bz = zone or (baseline.zone if baseline else "") or ""
    bl = line or (baseline.line if baseline else "") or ""
    bd = department or (baseline.department if baseline else "") or ""
    return {
        'baseline': baseline,
        'approved': B.approved_templates_for_scope(bz, bl, bd),
        'zones': cls.get('zones', []),
        'lines': cls.get('lines', []),
        'departments': cls.get('departments', []),
        'selected_ids': [i.template_id for i in baseline.items] if baseline else [],
    }


@bp.route('/baselines')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def baselines():
    """Combo grid: one card per zone x line x department permutation, each with
    its assigned-template + matching-device counts, plus the catalog of approved
    templates ("things") that can be assigned, below.

    Filterable by zone / line / department / name. The active filter can be
    SAVED to the signed-in user's profile (``UserSetting`` key
    ``baselines.filters``) so it is restored on the next visit; ``?clear=1``
    forgets it.
    """
    uid = getattr(current_user, 'id', None)
    PREF_KEY = 'baselines.filters'
    arg_keys = ('zone', 'line', 'department', 'q')

    # Resolve the active filter from the query string, the saved pref, or blank.
    has_query = any(k in request.args for k in arg_keys) or 'save' in request.args
    blank = {'zone': '', 'line': '', 'department': '', 'q': ''}
    filters_saved = False
    if request.args.get('clear'):
        if uid is not None:
            UserSetting.set(uid, PREF_KEY, '{}')
        flt = dict(blank)
    elif has_query:
        flt = {k: (request.args.get(k) or '').strip() for k in arg_keys}
        if request.args.get('save') and uid is not None:
            UserSetting.set(uid, PREF_KEY, json.dumps(flt))
            filters_saved = True
    else:
        flt = dict(blank)
        if uid is not None:
            raw = UserSetting.get(uid, PREF_KEY)
            if raw:
                try:
                    data = json.loads(raw)
                except ValueError:
                    data = {}
                if isinstance(data, dict):
                    flt.update({k: (data.get(k) or '').strip() for k in arg_keys})
                    filters_saved = any(flt.values())

    rows = B.list_baselines()
    total = len(rows)

    def _match(b):
        # An empty facet ON THE COMBO means "Any" -> matches every filter value.
        if flt['zone'] and (b.zone or '') and b.zone != flt['zone']:
            return False
        if flt['line'] and (b.line or '') and b.line != flt['line']:
            return False
        if flt['department'] and (b.department or '') and b.department != flt['department']:
            return False
        if flt['q'] and flt['q'].lower() not in (b.name or '').lower():
            return False
        return True

    rows = [b for b in rows if _match(b)]
    device_counts = {b.id: len(B.matching_devices(b, visible_appliances())) for b in rows}
    assigned_counts = {b.id: len(b.items) for b in rows}
    approved = B.approved_templates()
    combo_chips = {t.id: B.combos_for_template(t.id) for t in approved}
    grouped = B.grouped_approved_templates()
    all_combos = B.list_baselines()
    template_combos = B.template_combo_id_map()
    cls = settings_store.all_classification()
    return render_template('provisioning/baselines.html',
                           baselines=rows, device_counts=device_counts,
                           assigned_counts=assigned_counts,
                           approved=approved, combo_chips=combo_chips,
                           grouped=grouped, all_combos=all_combos,
                           template_combos=template_combos,
                           missing_count=B.missing_combo_count(),
                           filters=flt, filters_saved=filters_saved,
                           filters_active=any(flt.values()),
                           filtered_total=total, shown_total=len(rows),
                           zones=cls.get('zones', []),
                           lines=cls.get('lines', []),
                           departments=cls.get('departments', []))


@bp.route('/baselines/generate', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def baseline_generate():
    """Create a combo for every missing zone x line x department permutation."""
    created = B.generate_missing_combos(
        author=getattr(current_user, 'username', '') or '')
    log_action('baseline.generate', target='combos', detail=f'created={created}')
    if created:
        flash(f'Generated {created} new combo(s).', 'success')
    else:
        flash('All combos already exist — nothing to generate.', 'info')
    return redirect(url_for('provisioning.baselines'))


@bp.route('/baselines/<int:baseline_id>')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def baseline_detail(baseline_id: int):
    """Open a combo: assigned templates (removable) + assignable approved ones."""
    row = B.get_baseline(baseline_id)
    if row is None:
        abort(404)
    devices = B.matching_devices(row, visible_appliances())
    assigned = B.assigned_templates(row)
    available = B.available_templates_for_combo(row)
    # Every visible device of the baseline's product: the picker for an
    # apply to chosen devices, in scope or not.
    candidates = [a for a in visible_appliances().order_by(Appliance.name).all()
                  if B.same_product(row, a)]
    return render_template('provisioning/baseline_detail.html',
                           baseline=row,
                           assigned=assigned,
                           available=available,
                           assigned_groups=B.group_by_section(assigned),
                           available_groups=B.group_by_section(available),
                           devices=devices, candidates=candidates,
                           in_scope={a.id for a in devices})


@bp.route('/baselines/<int:baseline_id>/assign', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def baseline_assign(baseline_id: int):
    """Assign one approved template to this combo."""
    try:
        tid = int(request.form.get('template_id', ''))
    except (TypeError, ValueError):
        flash('No template selected.', 'warning')
        return redirect(url_for('provisioning.baseline_detail', baseline_id=baseline_id))
    try:
        row = B.combo_assign(baseline_id, tid)
        log_action('baseline.assign', target=row.name, detail=f'template={tid}')
        flash('Template assigned to combo.', 'success')
    except ValueError as exc:
        flash(f'Could not assign: {exc}', 'danger')
    return redirect(url_for('provisioning.baseline_detail', baseline_id=baseline_id))


@bp.route('/baselines/<int:baseline_id>/unassign', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def baseline_unassign(baseline_id: int):
    """Remove a template from this combo."""
    try:
        tid = int(request.form.get('template_id', ''))
    except (TypeError, ValueError):
        flash('No template selected.', 'warning')
        return redirect(url_for('provisioning.baseline_detail', baseline_id=baseline_id))
    row = B.combo_unassign(baseline_id, tid)
    log_action('baseline.unassign', target=row.name, detail=f'template={tid}')
    flash('Template removed from combo.', 'success')
    return redirect(url_for('provisioning.baseline_detail', baseline_id=baseline_id))


@bp.route('/baselines/new', methods=['GET', 'POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def baseline_new():
    if request.method == 'POST':
        ids = [int(v) for v in request.form.getlist('template_ids') if v.isdigit()]
        try:
            row = B.create_baseline(
                request.form.get('name', ''),
                zone=request.form.get('zone', ''),
                line=request.form.get('line', ''),
                department=request.form.get('department', ''),
                template_ids=ids, note=request.form.get('note', ''),
                author=getattr(current_user, 'username', '') or '')
            log_action('baseline.create', target=row.name,
                       detail=f'{len(ids)} template(s), zone={row.zone} line={row.line}')
            flash(f'Baseline "{row.name}" created.', 'success')
            return redirect(url_for('provisioning.baselines'))
        except ValueError as exc:
            flash(f'Could not create baseline: {exc}', 'danger')
            return render_template('provisioning/baseline_form.html',
                                   **_baseline_form_ctx(
                                       zone=request.form.get('zone', ''),
                                       line=request.form.get('line', ''),
                                       department=request.form.get('department', '')))
    return render_template('provisioning/baseline_form.html', **_baseline_form_ctx())


@bp.route('/baselines/<int:baseline_id>/edit', methods=['GET', 'POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def baseline_edit(baseline_id: int):
    row = B.get_baseline(baseline_id)
    if row is None:
        abort(404)
    if request.method == 'POST':
        ids = [int(v) for v in request.form.getlist('template_ids') if v.isdigit()]
        try:
            B.update_baseline(
                baseline_id, name=request.form.get('name', ''),
                zone=request.form.get('zone', ''),
                line=request.form.get('line', ''),
                department=request.form.get('department', ''),
                template_ids=ids, note=request.form.get('note', ''))
            log_action('baseline.update', target=row.name)
            flash('Baseline updated.', 'success')
            return redirect(url_for('provisioning.baselines'))
        except ValueError as exc:
            flash(f'Could not update baseline: {exc}', 'danger')
    return render_template('provisioning/baseline_form.html',
                           **_baseline_form_ctx(baseline=row))


@bp.route('/baselines/<int:baseline_id>/delete', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def baseline_delete(baseline_id: int):
    row = B.get_baseline(baseline_id)
    label = row.name if row else str(baseline_id)
    if B.delete_baseline(baseline_id):
        log_action('baseline.delete', target=label)
        flash('Baseline deleted.', 'success')
    else:
        flash('Baseline not found.', 'warning')
    return redirect(url_for('provisioning.baselines'))


def _int_list(values) -> list[int]:
    out = []
    for value in values:
        try:
            out.append(int(value))
        except (TypeError, ValueError):
            continue
    return out


def _rollout(*, name: str, composing: list, devices: list, heading: str,
             scope_text: str, form_action: str, hidden: dict, back_url: str,
             meta: dict, warnings=(), on_done=None, after_start=None):
    """Two-phase rollout of ``composing`` templates to ``devices`` — the one
    path every baseline apply takes (a combo's scope, devices picked by hand,
    or one device's full baseline).

    First POST (no ``confirm``) -> dry-run preview. Second POST
    (``confirm=1``) -> the same guards as ever (unset variables, firmware
    check) and a canary-gated background job. ``hidden`` travels with the
    confirm form so the second POST targets exactly what was previewed."""
    device_ids = [a.id for a in devices]
    parts = B.template_push_parts(composing)
    items = [it for _t, its in parts for it in its]
    confirm = request.form.get('confirm') == '1'
    # each composing template renders its {{ variables }} from its own binding
    items_by_device, missing_vars = tb.render_parts_for_devices(parts, device_ids)
    missing_why = tb.missing_text(missing_vars, {a.id: a.name for a in devices})

    if not device_ids:
        flash(f'Baseline "{name}" matches no devices for its scope.', 'warning')
        return redirect(back_url)
    if not items:
        flash(f'Baseline "{name}" has no composing templates.', 'warning')
        return redirect(back_url)

    if not confirm:
        compat = [tc.for_appliances(t, devices, require_validated=True)
                  for t in composing]
        preview = BulkRunner(items, skips=tc.merge_skips(c.get('skips') for c in compat),
                             items_by_device=items_by_device).preview(device_ids)
        if missing_vars:
            flash(f'The live rollout will be refused: {missing_why}. Set the values '
                  'on the device bindings first.', 'danger')
        log_action('baseline.apply.preview', target=name,
                   detail=f'devices={device_ids} items={len(items)} '
                          f'compat_blocked={any(c["blocked"] for c in compat)}')
        return render_template('provisioning/baseline_apply.html',
                               phase='preview', name=name, heading=heading,
                               scope_text=scope_text, devices=devices,
                               composing=composing, form_action=form_action,
                               hidden=hidden, back_url=back_url,
                               warnings=list(warnings),
                               preview=preview, result=None, item_count=len(items),
                               compat_reports=compat,
                               can_override=current_user.can('operations.template_approve'))

    if missing_vars:
        log_action('baseline.apply.refused', target=name,
                   detail=('variables unset: ' + missing_why)[:1500])
        flash(f'Baseline rollout "{name}" refused — {missing_why}. Set the '
              'values on the device bindings, then apply.', 'danger')
        return redirect(back_url)
    # A baseline is a fleet rollout of approved templates: every composing
    # template must fit every target device's build (or be overridden).
    refused = []
    skips = []
    for t in composing:
        allowed, compat = tc.enforce(
            t, devices, user=current_user,
            override_reason=request.form.get('override_reason', ''),
            require_validated=True, action=f'baseline.apply:{name}')
        skips.append(compat.get('skips'))
        if not allowed:
            refused.extend(compat['blocks'])
    if refused:
        log_action('baseline.apply.refused', target=name,
                   detail='firmware check: ' + ' | '.join(refused)[:1500])
        flash('Baseline rollout refused by the firmware compatibility check: '
              + '; '.join(refused[:4]) + (' (+%d more)' % (len(refused) - 4)
                                          if len(refused) > 4 else ''), 'danger')
        return redirect(back_url)

    # Confirmed live apply — background job (same rationale as templates.apply:
    # a fleet rollout must not run inside an HTTP request). Progress + result
    # surface in the job dock; the completion audit row is the job's.
    from flask import current_app
    from ..services.bulk import start_apply_job
    job = start_apply_job(
        current_app._get_current_object(),
        title=f'Apply baseline "{name}" to {len(devices)} device(s)',
        items=items, device_ids=device_ids,
        by=getattr(current_user, 'username', '') or '',
        meta=meta, audit_action='baseline.apply', audit_target=name,
        skips=tc.merge_skips(skips), items_by_device=items_by_device or None,
        on_done=on_done)
    if after_start is not None:
        after_start(job)
    log_action('baseline.apply.start', target=name,
               detail=f'devices={device_ids} items={len(items)} job={job["id"]}')
    flash(f'Baseline rollout "{name}" started for {len(devices)} device(s) '
          '— progress appears in the job dock (bottom right).', 'info')
    return redirect(back_url)


@bp.route('/baselines/<int:baseline_id>/apply', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def baseline_apply(baseline_id: int):
    """Two-phase apply of a whole baseline.

    ``mode=scope`` (default): every visible device its zone / line /
    department matches. ``mode=selected`` + ``device_ids``: the devices the
    operator picked, classified into the combo or not — but never a device
    of another product, and never one this session cannot see."""
    row = B.get_baseline(baseline_id)
    if row is None:
        abort(404)
    detail_url = url_for('provisioning.baseline_detail', baseline_id=row.id)
    warnings = []
    if request.form.get('mode') == 'selected':
        ids = _int_list(request.form.getlist('device_ids'))
        if not ids:
            flash('Select at least one device.', 'warning')
            return redirect(detail_url)
        devices = (visible_appliances().filter(Appliance.id.in_(ids))
                   .order_by(Appliance.name).all())
        wrong = [a.name for a in devices if not B.same_product(row, a)]
        if wrong:
            flash(f'Baseline "{row.name}" is a {row.product or "fortiweb"} baseline; '
                  f'refused for {", ".join(wrong)}.', 'danger')
            return redirect(detail_url)
        outside = [a.name for a in devices if not B.baseline_covers(row, a)]
        if outside:
            warnings.append('Outside this combo\'s zone / line / department: '
                            + ', '.join(outside) + '. Their classification is '
                            'not changed by this apply.')
        hidden = {'mode': 'selected', 'device_ids': [a.id for a in devices]}
        back_url = detail_url
    else:
        devices = B.matching_devices(row, visible_appliances())
        hidden = {}
        back_url = url_for('provisioning.baselines')
    return _rollout(
        name=row.name, composing=B.assigned_templates(row), devices=devices,
        heading=f'Apply baseline — {row.name}',
        scope_text=(f'Scope: zone={row.zone or "any"} · line={row.line or "any"} · '
                    f'department={row.department or "any"}'),
        form_action=url_for('provisioning.baseline_apply', baseline_id=row.id),
        hidden=hidden, back_url=back_url, warnings=warnings,
        meta={'baseline_id': row.id, 'name': row.name})


def _provision_run_for(appliance, run_id):
    """The Device Provisioning run that onboarded ``appliance``, or None. A
    run of another ADOM, or of another machine, is never linked."""
    if not run_id:
        return None
    from ..models_provision import ProvisionRun
    from ..services import product_scope
    run = db.session.get(ProvisionRun, run_id)
    if (run is None or run.appliance_id != appliance.id
            or not product_scope.visible_product(run.product)):
        return None
    return run


@bp.route('/device/<int:appliance_id>/baseline', methods=['GET', 'POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def device_baseline(appliance_id: int):
    """Everything a device's baseline holds, applied to that one device.

    GET shows what will be pushed and why (every combo its classification
    falls into, or the one baseline picked). POST runs the shared two-phase
    rollout. With ``run_id`` the rollout closes that Device Provisioning
    run's ``profile_applied`` step when the job finishes."""
    ap = visible_appliance_or_404(appliance_id)
    baseline_id = _int_list([request.values.get('baseline_id')])
    baseline_id = baseline_id[0] if baseline_id else None
    run_ids = _int_list([request.values.get('run_id')])
    run = _provision_run_for(ap, run_ids[0] if run_ids else None)
    res = B.device_templates(ap, baseline_id)
    page_url = url_for('provisioning.device_baseline', appliance_id=ap.id,
                       baseline_id=baseline_id or None,
                       run_id=run.id if run else None)

    if request.method == 'GET':
        choices = [b for b in B.list_baselines() if B.same_product(b, ap)]
        return render_template('provisioning/device_baseline.html',
                               appliance=ap, res=res, run=run,
                               baseline_id=baseline_id, choices=choices,
                               groups=B.group_by_section(res['templates']))

    if res['error']:
        flash(res['error'], 'danger')
        return redirect(page_url)
    if not res['templates']:
        flash(f'Nothing to apply to {ap.name}: no baseline with approved templates '
              'covers its zone / line / department. Classify the device or pick '
              'a baseline.', 'warning')
        return redirect(page_url)
    if run is not None and run.status in ('done', 'aborted'):
        flash(f'Provisioning run "{run.name}" is {run.status}; the rollout is '
              'not linked to it.', 'warning')
        run = None

    names = ', '.join(b.name for b in res['baselines'])
    hidden = {}
    if baseline_id:
        hidden['baseline_id'] = baseline_id
    on_done = after_start = None
    if run is not None:
        from ..services import provision_runner as pr
        hidden['run_id'] = run.id
        run_id = run.id
        on_done = lambda job_id, summary: pr.baseline_finished(run_id, job_id, summary)  # noqa: E731
        after_start = lambda job: pr.baseline_started(run_id, job['id'])  # noqa: E731
    return _rollout(
        name=f'{ap.name} baseline', composing=res['templates'], devices=[ap],
        heading=f'Apply full baseline — {ap.name}',
        scope_text=(f'From: {names} · device zone={ap.zone or "none"} · '
                    f'line={ap.line or "none"} · department={ap.department or "none"}'),
        form_action=url_for('provisioning.device_baseline', appliance_id=ap.id),
        hidden=hidden, back_url=page_url,
        warnings=([f'Left out (no longer approved): {", ".join(res["skipped"])}']
                  if res['skipped'] else []),
        meta={'appliance_id': ap.id, 'baselines': [b.id for b in res['baselines']],
              'run_id': run.id if run else None},
        on_done=on_done, after_start=after_start)


@bp.route('/templates/<int:template_id>/combos', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def template_set_combos(template_id: int):
    """Assign ONE approved template to many combos at once (checkbox sync)."""
    ids = []
    for raw in request.form.getlist('combo_ids'):
        try:
            ids.append(int(raw))
        except (TypeError, ValueError):
            continue
    try:
        res = B.set_template_combos(template_id, ids)
    except ValueError as exc:
        flash(str(exc), 'danger')
        return redirect(url_for('provisioning.baselines'))
    log_action('baseline.template_combos', target=str(template_id),
               detail=f"added={res['added']} removed={res['removed']} total={res['total']}")
    flash(f"Updated combo assignments (+{res['added']} / -{res['removed']}).", 'success')
    return redirect(url_for('provisioning.baselines'))


# --------------------------------------------------------------------------- #
#  Compare: is a newer template a valid replacement on a build / a device?     #
# --------------------------------------------------------------------------- #
def _compare_choices(product: str):
    """Every template of the ADOM, grouped by family, newest version first."""
    fams: dict = {}
    for t in list_templates(None):
        if (t.product or 'fortiweb') != product:
            continue
        fams.setdefault((t.kind, t.name), []).append(t)
    out = []
    for (kind, name), rows in sorted(fams.items(), key=lambda kv: (kv[0][0], kv[0][1].lower())):
        out.append({'kind': kind, 'name': name,
                    'rows': sorted(rows, key=lambda t: t.version, reverse=True)})
    return out


def _default_newer(cur: Template):
    """The obvious "newer" template for ``cur``: the next version of its family,
    else the newest version adapted from it."""
    nxt = (Template.query.filter(Template.kind == cur.kind, Template.name == cur.name,
                                 Template.version > cur.version)
           .order_by(Template.version.desc()).first())
    if nxt is not None:
        return nxt
    return (Template.query.filter_by(adapted_from_id=cur.id)
            .order_by(Template.id.desc()).first())


@bp.route('/compare')
@login_required
@require_permission('operations.view')
def compare():
    """Compare the template a device has with a newer one, on a firmware build
    (or on one device's running build): field diff + the verdict whether the
    newer one is valid there. Read-only: nothing is recorded or pushed."""
    from ..services.templates import get_template as _get
    product = tc.session_product()
    choices = _compare_choices(product)

    def _int(name):
        try:
            return int(request.args.get(name) or 0) or None
        except (TypeError, ValueError):
            return None

    cur = _get(_int('a')) if _int('a') else None
    new = _get(_int('b')) if _int('b') else None
    if cur is not None and (cur.product or 'fortiweb') != product:
        abort(404)
    if new is not None and (new.product or 'fortiweb') != product:
        abort(404)
    if cur is not None and new is None and not request.args.get('b'):
        new = _default_newer(cur)
    appliance = None
    if _int('appliance_id'):
        appliance = visible_appliance_or_404(_int('appliance_id'))
    build = (request.args.get('build') or '').strip()
    result, error = None, ''
    if cur is not None and new is not None:
        if cur.id == new.id:
            error = 'Pick two different templates (or versions) to compare.'
        else:
            try:
                result = tc.compare(cur, new, build, appliance=appliance)
            except ValueError as exc:
                error = str(exc)
    if request.args.get('format') == 'json' or \
            'application/json' in (request.headers.get('Accept') or ''):
        if error or result is None:
            return {'ok': False, 'error': error or 'choose the two templates (a, b)'}, 400
        return {'ok': True, 'result': result}
    devices = visible_appliances().filter(Appliance.kind == product).order_by(Appliance.name).all()
    return render_template('provisioning/compare.html', choices=choices, cur=cur, new=new,
                           appliance=appliance, build=build, result=result, error=error,
                           devices=devices,
                           firmware_choices=tc.known_builds(product))
