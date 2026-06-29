"""System Provisioning — author and apply baseline FortiWeb *system* config.

Web UI over :mod:`app.services.provisioning`. An operator composes a declarative
``SystemProfile`` (DNS, NTP, RADIUS, SNMP, admins…) once, versions it as a
``Template`` (kind ``system-profile``), then pushes it to a single device or the
whole fleet through the shared dry-run -> canary-apply machinery.

Discipline (mirrors the desktop): nothing touches a device until ``apply`` runs,
and even then the operator first sees a per-device dry-run preview and must
explicitly confirm the real write. Secrets are entered at apply time and are
never persisted in the template (``save_profile`` strips them).

Every route requires an authenticated user holding ``CONFIG_WRITE``.
"""
from __future__ import annotations

import json

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Appliance, Permission, Template
from ..services import field_catalog as fc
from ..services import provisioning as prov
from ..services.audit import log_action
from ..services.templates import delete_template, get_template, list_templates

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


def _render_form(*, profile_name: str = '', rows=None, template_id=None, line: str = '8.0'):
    """Render the profile builder (shared by /new and /<id>/edit)."""
    specs = prov.available_specs()
    product = 'fortiweb'
    lines = fc.available_lines(product) or ['8.0']
    if line not in lines:
        line = lines[0]
    keys = [s.key for s in specs]
    schemas_by_line = {lin: fc.schemas_for_line(product, lin, keys) for lin in lines}
    return render_template(
        'provisioning/form.html',
        specs=specs,
        spec_keys=keys,
        profile_name=profile_name,
        rows=rows or [],
        template_id=template_id,
        line=line,
        available_lines=lines,
        schemas_by_line=schemas_by_line,
    )


def _collect_rows():
    """Read the repeatable item editor into ``(name, line, rows)``.

    Each row declares its index via a hidden ``rows`` input; per-field names are
    ``key_<i>``/``mkey_<i>``/``data_<i>``/``singleton_<i>`` plus typed schema
    inputs ``f_<i>_<fieldname>``. Pure form-reading — never raises, so the
    builder can be re-rendered with the operator's input intact on an error.
    """
    name = (request.form.get('name') or '').strip()
    line = (request.form.get('line') or '8.0').strip()
    rows = []
    for idx in request.form.getlist('rows'):
        prefix = f'f_{idx}_'
        fields = {k[len(prefix):]: v for k, v in request.form.items()
                  if k.startswith(prefix)}
        rows.append({
            'key': (request.form.get(f'key_{idx}') or '').strip(),
            'mkey': (request.form.get(f'mkey_{idx}') or '').strip(),
            'data': request.form.get(f'data_{idx}') or '',
            'singleton': request.form.get(f'singleton_{idx}') is not None,
            'fields': fields,
        })
    return name, line, rows


def _build_items(rows, line, product='fortiweb'):
    """Turn collected rows into ``ProvisionItem``s.

    If the row's object has a field schema for ``line`` AND the operator filled
    typed inputs, the payload is built + validated via ``field_catalog.coerce``;
    otherwise the raw ``data`` JSON is parsed (back-compat / schemaless objects).
    Raises ``ValueError`` (bad key / bad JSON / failed validation) so the caller
    can flash and re-render.
    """
    items = []
    for row in rows:
        key = row['key']
        if not key:
            continue  # skip blank rows
        spec = prov.CATALOG_BY_KEY.get(key)
        if spec is None:
            raise ValueError(f"Unknown provisioning item: {key}")
        schema = fc.load_object_schema(product, line, key)
        if schema is not None and row.get('fields'):
            data = fc.coerce(schema, row['fields'])        # typed + validated
        else:
            try:
                data = json.loads(row['data'] or '{}')
            except ValueError as exc:
                raise ValueError(f"Item '{spec.label}': data is not valid JSON ({exc})") from exc
            if not isinstance(data, dict):
                raise ValueError(f"Item '{spec.label}': data must be a JSON object")
        item = prov.ProvisionItem.from_spec(spec, data, mkey=row['mkey'] or None)
        item.singleton = row['singleton']  # honour the explicit checkbox
        items.append(item)
    return items


def _save(*, template_id):
    """Validate + persist the builder form. On error re-renders with input kept."""
    name, line, rows = _collect_rows()
    try:
        if not name:
            raise ValueError("Profile name is required")
        items = _build_items(rows, line)
        if not items:
            raise ValueError("Add at least one provisioning item")
        profile = prov.SystemProfile(name, items, line=line)
        row = prov.save_profile(profile, author=getattr(current_user, 'username', '') or '')
    except ValueError as exc:
        flash(f"Could not save profile: {exc}", 'danger')
        return _render_form(profile_name=name, rows=rows, template_id=template_id, line=line)
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
        profiles=list_templates(Template.KIND_SYSTEM),
        appliances=Appliance.query.order_by(Appliance.name).all(),
    )


@bp.route('/new', methods=['GET', 'POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def new():
    """Author a new system profile."""
    if request.method == 'POST':
        return _save(template_id=None)
    return _render_form(line=(request.args.get('line') or '8.0'))


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
                        template_id=template_id, line=profile.line)


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

    device_ids = [] if mode == 'fleet' else selected_ids

    if mode == 'fleet' or not device_ids:
        target_appliances = Appliance.query.order_by(Appliance.name).all()
        target_desc = 'Entire fleet (all appliances)'
    else:
        target_appliances = (Appliance.query
                              .filter(Appliance.id.in_(device_ids))
                              .order_by(Appliance.name).all())
        target_desc = ', '.join(a.name for a in target_appliances) or '(none)'

    confirmed = request.form.get('confirm') == '1'

    if not confirmed:
        preview = prov.apply(profile, device_ids, dry_run=True)
        log_action('provisioning.preview', target=profile.name,
                   detail=f'{mode}, {len(target_appliances)} device(s), host={target_hostname}, change={change_id}')
        return render_template(
            'provisioning/apply.html',
            phase='preview', prof_name=profile.name, template_id=template_id,
            preview=preview, result=None,
            mode=mode, device_ids=device_ids,
            target_desc=target_desc, target_count=len(target_appliances),
            target_hostname=target_hostname, change_id=change_id,
        )

    # Confirmed -> real canary-gated write to live devices.
    flash(f'Deploying [{change_id}] to {target_hostname} — canary device writes first.', 'warning')
    result = prov.apply(profile, device_ids, dry_run=False, canary=1)
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
