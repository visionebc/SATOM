"""Settings — the admin console (web port of the desktop Settings page).

Sections mirror the desktop ``settings_page.py`` admin console, scoped to what
makes sense for a multi-user web app:

* General        — app name, default platform, session lock, status-poll
                   interval, log levels, show-raw-config (persisted in the DB,
                   not per-worker ``current_app.config``).
* Naming         — the name-pattern editor (ported ``services.naming``), with a
                   live preview from one sample web address.
* Classification — the zones / lines / departments catalogs that drive the
                   appliance Zone/Line/Department dropdowns.
* Network Segments — named back-end networks (CIDR/interface/gateway) scoped to
                   a classification value.
* Security / Change Password / About — available to every user.

The config sections are admin-only (USER_MANAGE), exactly like the desktop
console; Security/About/Change-Password stay open to all authenticated users.
"""
from __future__ import annotations

import ipaddress

from flask import (Blueprint, render_template, request, flash, redirect, url_for)
from flask_login import login_required, current_user

from ..auth.decorators import require_permission
from ..models import db, Permission
from ..services import naming, settings_store as store
from ..services.audit import log_action

bp = Blueprint('settings', __name__, url_prefix='/settings')


def _is_admin() -> bool:
    return bool(current_user and current_user.can(Permission.USER_MANAGE))


@bp.route('/')
@login_required
def index():
    scheme = naming.effective_scheme(store.naming_overrides())
    return render_template(
        'settings/index.html',
        settings=store.general(),
        log_levels_all=store.LOG_LEVELS_ALL,
        naming_sections=naming.elements_by_section(),
        naming_scheme=scheme,
        classification=store.all_classification(),
        segments=store.segments(),
        is_admin=_is_admin(),
    )


@bp.route('/general', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_general():
    try:
        store.save_general(
            app_name=request.form.get('app_name', ''),
            default_kind=request.form.get('default_kind', 'FortiWeb'),
            session_timeout=request.form.get('session_timeout', 60),
            poll_interval=request.form.get('poll_interval', 30),
            show_raw_config=request.form.get('show_raw_config') == 'on',
            log_levels=request.form.getlist('log_levels'),
        )
        log_action('settings.general', detail='Updated general settings')
        flash('General settings saved.', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Failed to save settings: {exc}', 'danger')
    return redirect(url_for('settings.index') + '#tab-general')


@bp.route('/naming', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_naming():
    if request.form.get('action') == 'reset':
        store.reset_naming()
        log_action('settings.naming', detail='Reset naming to defaults')
        flash('Naming patterns restored to defaults.', 'success')
        return redirect(url_for('settings.index') + '#tab-naming')
    scheme = {e.key: request.form.get('nm_' + e.key, '') for e in naming.NAMING_ELEMENTS}
    store.save_naming(scheme)
    log_action('settings.naming',
               detail=f'{len([v for v in scheme.values() if v.strip()])} patterns')
    flash('Naming patterns saved.', 'success')
    return redirect(url_for('settings.index') + '#tab-naming')


@bp.route('/classification', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_classification():
    counts = {}
    for kind in store.CLASSIFICATION_KINDS:
        raw = request.form.get(kind, '')
        values = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        store.save_classification(kind, values)
        counts[kind] = len(store.classification(kind))
    log_action('settings.classification',
               detail=f"{counts.get('zones', 0)} zones, {counts.get('lines', 0)} lines, "
                      f"{counts.get('departments', 0)} departments")
    flash('Classification catalogs saved.', 'success')
    return redirect(url_for('settings.index') + '#tab-classification')


@bp.route('/segments', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_segments():
    names = request.form.getlist('seg_name[]')
    rows, bad_cidr = [], []
    for i, name in enumerate(names):
        def col(field):
            vals = request.form.getlist(f'seg_{field}[]')
            return vals[i] if i < len(vals) else ''
        cidr = (col('cidr') or '').strip()
        if not (name or '').strip() and not cidr:
            continue
        if cidr:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                bad_cidr.append(cidr)
                continue
        rows.append({
            'name': name, 'zone': col('zone'), 'line': col('line'),
            'department': col('department'), 'cidr': cidr,
            'interface': col('interface') or 'port1', 'gateway': col('gateway'),
            'note': col('note'),
        })
    store.save_segments(rows)
    log_action('settings.segments', detail=f'{len(rows)} segment(s)')
    if bad_cidr:
        flash(f"Skipped invalid CIDR(s): {', '.join(bad_cidr)}", 'warning')
    flash(f'{len(rows)} network segment(s) saved.', 'success')
    return redirect(url_for('settings.index') + '#tab-segments')


@bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not current_user.check_password(current_password):
        flash('Current password is incorrect.', 'danger')
    elif not new_password:
        flash('New password cannot be empty.', 'danger')
    elif new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
    else:
        current_user.set_password(new_password)
        db.session.commit()
        log_action('settings.change_password', detail='Changed own password')
        flash('Password changed successfully.', 'success')
    return redirect(url_for('settings.index') + '#tab-password')
