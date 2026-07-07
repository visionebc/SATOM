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

from flask import (Blueprint, render_template, request, flash, redirect, url_for,
                   jsonify, abort, session)
from flask_login import login_required, current_user

from ..auth.decorators import require_permission
from ..models import db, Permission, User, Role, Profile
from ..services import naming, settings_store as store
from ..services import email_service as email
from ..services import auth_store
from ..services import twofa
from ..services import git_service
from ..services import user_settings_store as user_store
from ..services import system_info
from ..services.audit import log_action

bp = Blueprint('settings', __name__, url_prefix='/settings')


def _is_admin() -> bool:
    return bool(current_user and current_user.can(Permission.USER_MANAGE))


@bp.route('/')
@login_required
def index():
    scheme = naming.effective_scheme(store.naming_overrides())
    all_users = []
    if _is_admin():
        for u in User.query.order_by(User.username).all():
            all_users.append({
                'username': u.username,
                'is_admin': u.role == Role.admin.value,
                'is_active': bool(u.is_active),
            })
    return render_template(
        'settings/index.html',
        settings=store.general(),
        log_levels_all=store.LOG_LEVELS_ALL,
        log_formats_all=store.LOG_FORMATS,
        timezones_all=store.timezones(),
        naming_sections=naming.elements_by_section(),
        naming_scheme=scheme,
        classification=store.all_classification(),
        segments=store.segments(),
        ip_whitelist=store.ip_whitelist(),
        allowed_users=store.allowed_users(),
        all_users=all_users,
        users=(User.query.order_by(User.username).all() if _is_admin() else []),
        profiles=(Profile.query.order_by(Profile.is_system.desc(), Profile.name).all() if _is_admin() else []),
        profiles_counts=({p.id: User.query.filter_by(profile_id=p.id).count()
                          for p in Profile.query.all()} if _is_admin() else {}),
        banner_templates=store.BANNER_TEMPLATES,
        banners=store.all_banners(),
        email_config=email.config(),
        auth_config=(auth_store.config() if _is_admin() else None),
        auth_backends=auth_store.BACKENDS,
        twofa_status={
            'enabled': bool(getattr(current_user, 'totp_enabled', False)),
            'is_local': bool(getattr(current_user, 'is_local', True)),
            'recovery_email': getattr(current_user, 'recovery_email', '') or '',
            'remaining_codes': twofa.remaining_backup_codes(getattr(current_user, 'backup_codes', None)),
        },
        backup_codes_once=session.pop('twofa_backup_codes_once', None),
        cert_adcs=(store.cert_manager_adcs() if _is_admin() else None),
        cert_classes=([(c, store.CERT_CLASS_LABELS[c], store.cert_class_config(c))
                       for c in store.CERT_CLASSES] if _is_admin() else []),
        cert_cmd_tokens=store.CERT_CMD_TOKENS,
        cert_protocol=(store.cert_manager_protocol() if _is_admin() else 'adcs'),
        cert_protocols=[(p, store.CERT_PROTOCOL_LABELS[p]) for p in store.CERT_PROTOCOLS],
        cert_acme=(store.cert_manager_acme() if _is_admin() else None),
        acme_cmd_tokens=store.ACME_CMD_TOKENS,
        cert_lifecycle=(store.cert_lifecycle_policy() if _is_admin() else None),
        system_info=system_info.collect(),
        is_admin=_is_admin(),
    )


# NOTE: the read-only Database browser (schema + relational model + SQL console)
# moved out of Settings into its own top-level section — see app/views/database.py
# (blueprint ``database``, /database). Its backend is app/services/dbintrospect.py.


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
            timezone=request.form.get('timezone', ''),
            log_format=request.form.get('log_format', 'plain'),
        )
        log_action('settings.general', detail='Updated general settings')
        flash('General settings saved.', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Failed to save settings: {exc}', 'danger')
    return redirect(url_for('settings.index') + '#tab-general')


@bp.route('/cert-manager', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_cert_manager():
    """Certificate Manager config — the ADCS connection + per-class command
    templates. Lives in the admin console (this tab); the Automation inventory
    only consumes what is saved here. Nothing hardcoded."""
    f = request.form
    store.save_cert_manager_adcs({
        'bin': f.get('adcs_bin', ''),
        'ca': f.get('adcs_ca', ''),
        'ca_name': f.get('adcs_ca_name', ''),
        'domain': f.get('adcs_domain', ''),
        'user': f.get('adcs_user', ''),
        'date_format': f.get('adcs_date_format', ''),
        'notify_to': f.get('adcs_notify_to', ''),
        'secret': f.get('adcs_secret', ''),
        'clear_secret': bool(f.get('adcs_clear_secret')),
    })
    for cls in store.CERT_CLASSES:
        store.save_cert_class_config(cls, {
            'template': f.get(f'{cls}_template', ''),
            'key_type': f.get(f'{cls}_key_type', 'rsa'),
            'key_size': f.get(f'{cls}_key_size', '2048'),
            'subject_format': f.get(f'{cls}_subject_format', ''),
            'san_format': f.get(f'{cls}_san_format', ''),
            'submit_cmd': f.get(f'{cls}_submit_cmd', ''),
            'revoke_cmd': f.get(f'{cls}_revoke_cmd', ''),
            'renew_before_days': f.get(f'{cls}_renew_before_days', '30'),
        })
    # Issuance protocol (pluggable CA backend) + ACME client config.
    store.save_cert_manager_protocol(f.get('cert_protocol', 'adcs'))
    store.save_cert_manager_acme({
        'bin': f.get('acme_bin', ''),
        'directory_url': f.get('acme_directory_url', ''),
        'account_email': f.get('acme_account_email', ''),
        'eab_kid': f.get('acme_eab_kid', ''),
        'challenge': f.get('acme_challenge', 'http-01'),
        'submit_cmd': f.get('acme_submit_cmd', ''),
        'revoke_cmd': f.get('acme_revoke_cmd', ''),
        'eab_hmac': f.get('acme_eab_hmac', ''),
        'clear_eab_hmac': bool(f.get('acme_clear_eab_hmac')),
    })
    # Lifecycle policy — when superseded certs get revoked and when material
    # is deleted off the devices.
    store.save_cert_lifecycle_policy({
        'revoke_on_supersede': f.get('lc_revoke_on_supersede') == 'on',
        'revoke_grace_days': f.get('lc_revoke_grace_days', 7),
        'delete_superseded_after_days': f.get('lc_delete_superseded_after_days', 14),
        'delete_expired_after_days': f.get('lc_delete_expired_after_days', 30),
        'delete_revoked_from_device': f.get('lc_delete_revoked_from_device') == 'on',
        'auto_apply': f.get('lc_auto_apply') == 'on',
    })
    log_action('settings.cert_manager',
               detail=f"protocol={f.get('cert_protocol', 'adcs')} + ADCS/ACME + lifecycle policy saved")
    flash('Certificate Manager settings saved.', 'success')
    return redirect(url_for('settings.index') + '#tab-certmgr')


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


@bp.route('/access', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_access():
    # IP whitelist — validate each entry as an IP or CIDR.
    ips = request.form.getlist('wl_ip[]')
    notes = request.form.getlist('wl_note[]')
    rows, bad = [], []
    for i, ip in enumerate(ips):
        ip = (ip or '').strip()
        if not ip:
            continue
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            bad.append(ip)
            continue
        rows.append({'ip': ip, 'note': notes[i] if i < len(notes) else ''})
    store.save_ip_whitelist(rows)

    # Allowed users — only persist usernames that actually exist and are non-admin
    # (admins are always allowed and never restricted).
    chosen = set(request.form.getlist('allowed_users[]'))
    valid = {u.username for u in User.query.filter(User.role != Role.admin.value).all()}
    store.save_allowed_users(sorted(chosen & valid))

    log_action('settings.access',
               detail=f'{len(rows)} whitelisted IP(s), {len(chosen & valid)} allowed user(s)')
    if bad:
        flash(f"Skipped invalid IP/CIDR(s): {', '.join(bad)}", 'warning')
    flash('Access control saved.', 'success')
    return redirect(url_for('settings.index') + '#tab-access')


@bp.route('/banners', methods=['POST'])
@login_required
def save_banners():
    # Branding is a PER-USER preference now: every authenticated user picks
    # their own banner, saved against their user_id in the DB (no cookie).
    mapping = {
        'fortiweb': request.form.get('banner_fortiweb', ''),
        'fortiadc': request.form.get('banner_fortiadc', ''),
    }
    user_store.save_banners(current_user.id, mapping)
    log_action('settings.banners',
               detail="fortiweb=" + mapping['fortiweb'] + ", fortiadc=" + mapping['fortiadc'])
    flash('Banner templates saved.', 'success')
    return redirect(url_for('auth.profile'))


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


# ── Git ───────────────────────────────────────────────────────────────────────

@bp.route("/git/info")
@login_required
@require_permission(Permission.USER_MANAGE)
def git_info():
    return jsonify(git_service.git_info())


@bp.route("/git/pull", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def git_pull():
    transcript = git_service.git_pull()
    log_action("settings.git_pull", detail="manual pull")
    return jsonify({"transcript": transcript})


@bp.route("/git/console", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def git_console():
    script = (request.get_json(silent=True) or {}).get("script", "")
    transcript = git_service.run_git_script(script)
    log_action("settings.git_console", detail=f"{len(script.splitlines())} line(s)")
    return jsonify({"transcript": transcript})


@bp.route("/git/configure", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def git_configure():
    data = request.get_json(silent=True) or {}
    remote_url = data.get("remote_url", "").strip()
    token = data.get("token", "").strip()
    branch = data.get("branch", "").strip()
    if not remote_url and not branch:
        return jsonify({"error": "Provide at least a remote URL or branch"}), 400
    transcript = git_service.git_configure(remote_url, token, branch)
    log_action("settings.git_configure", detail=f"remote={bool(remote_url)} branch={branch!r}")
    return jsonify({"transcript": transcript})


# ── Email / SMTP ──────────────────────────────────────────

@bp.route('/email', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_email():
    try:
        email.save_config(request.form)
        log_action('settings.email', detail='Updated email settings')
        flash('Email settings saved.', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Failed to save email settings: {exc}', 'danger')
    return redirect(url_for('settings.index') + '#tab-email')


@bp.route('/email/test', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def test_email():
    data = request.get_json(silent=True) or {}
    result = email.send_test(data.get('to', ''))
    log_action('settings.email_test',
               detail=('ok' if result.get('ok') else 'fail') + ': ' + str(result.get('detail', '')))
    return jsonify(result)


# ── Authentication backend (admin) ────────────────────────

@bp.route('/auth', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_auth():
    try:
        auth_store.save_config(request.form)
        log_action('settings.auth', detail=f'backend={auth_store.backend()}')
        flash('Authentication settings saved.', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Failed to save authentication settings: {exc}', 'danger')
    return redirect(url_for('settings.index') + '#tab-auth')


@bp.route('/auth/test', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def test_auth():
    result = auth_store.test_connection(request.form)
    log_action('settings.auth_test',
               detail=('ok' if result.get('ok') else 'fail') + ': ' + str(result.get('detail', '')))
    return jsonify(result)


@bp.route('/auth/sync', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def sync_auth():
    """Import directory users (scoped to the sync group/OU) into local rows so
    the admin can assign profiles / block access BEFORE first sign-in. New rows
    are created DISABLED (pending approval)."""
    result = auth_store.sync_directory_users(default_active=False)
    log_action('settings.auth_sync',
               detail=('ok' if result.get('ok') else 'fail') + ': '
               + str(result.get('detail', '')))
    flash(result.get('detail', 'Sync finished.'),
          'success' if result.get('ok') else 'danger')
    if result.get('ok'):
        return redirect(url_for('users.index'))
    return redirect(url_for('settings.index') + '#tab-auth')


# ── 2FA self-service (any local user) ───────────────────

@bp.route('/2fa/setup', methods=['POST'])
@login_required
def twofa_setup():
    if not current_user.is_local:
        return jsonify({'ok': False, 'error': 'Directory accounts manage MFA at the directory.'}), 400
    secret = twofa.generate_secret()
    session['twofa_setup_secret'] = secret
    uri = twofa.provisioning_uri(secret, current_user.username)
    return jsonify({'ok': True, 'secret': secret, 'uri': uri, 'qr': twofa.qr_svg(uri)})


@bp.route('/2fa/enable', methods=['POST'])
@login_required
def twofa_enable():
    if not current_user.is_local:
        flash('Directory accounts manage MFA at the directory.', 'danger')
        return redirect(url_for('settings.index') + '#tab-security')
    secret = session.get('twofa_setup_secret')
    code = (request.form.get('code', '') or '').strip()
    if not secret or not twofa.verify_totp(secret, code):
        flash('Invalid code — 2FA was not enabled. Re-scan the QR and try again.', 'danger')
        return redirect(url_for('settings.index') + '#tab-security')
    codes = twofa.generate_backup_codes()
    current_user.totp_secret = twofa.encrypt_secret(secret)
    current_user.totp_enabled = True
    current_user.backup_codes = twofa.encode_codes(codes)
    db.session.commit()
    session.pop('twofa_setup_secret', None)
    session['twofa_backup_codes_once'] = codes
    log_action('settings.2fa_enable', target=current_user.username)
    flash('Two-factor authentication enabled. Save your backup codes now — they are shown only once.', 'success')
    return redirect(url_for('settings.index') + '#tab-security')


@bp.route('/2fa/disable', methods=['POST'])
@login_required
def twofa_disable():
    if not current_user.totp_enabled:
        return redirect(url_for('settings.index') + '#tab-security')
    pw = request.form.get('current_password', '')
    if current_user.is_local and not current_user.check_password(pw):
        flash('Password incorrect — 2FA was not disabled.', 'danger')
        return redirect(url_for('settings.index') + '#tab-security')
    current_user.totp_enabled = False
    current_user.totp_secret = None
    current_user.backup_codes = None
    db.session.commit()
    log_action('settings.2fa_disable', target=current_user.username)
    flash('Two-factor authentication disabled.', 'warning')
    return redirect(url_for('settings.index') + '#tab-security')


@bp.route('/2fa/backup-codes', methods=['POST'])
@login_required
def twofa_regen_codes():
    if not (current_user.is_local and current_user.totp_enabled):
        flash('Enable two-factor authentication first.', 'danger')
        return redirect(url_for('settings.index') + '#tab-security')
    codes = twofa.generate_backup_codes()
    current_user.backup_codes = twofa.encode_codes(codes)
    db.session.commit()
    session['twofa_backup_codes_once'] = codes
    log_action('settings.2fa_backup_regen', target=current_user.username)
    flash('New backup codes generated. Save them now — the old ones no longer work.', 'success')
    return redirect(url_for('settings.index') + '#tab-security')


@bp.route('/recovery-email', methods=['POST'])
@login_required
def recovery_email():
    addr = (request.form.get('recovery_email', '') or '').strip()
    if addr and ('@' not in addr or '.' not in addr.split('@')[-1]):
        flash('Enter a valid email address.', 'danger')
        return redirect(url_for('settings.index') + '#tab-security')
    current_user.recovery_email = addr or None
    db.session.commit()
    log_action('settings.recovery_email', target=current_user.username)
    flash('Recovery email updated.' if addr else 'Recovery email cleared.', 'success')
    return redirect(url_for('settings.index') + '#tab-security')
