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
                   jsonify, abort, session, current_app)
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
from ..services import dns_tool as dns_tool_svc
from ..services import policy_links as policy_links_svc
from ..services import clone_rules as clone_rules_svc
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
        adoms=(branding.all_adoms() if _is_admin() else []),
        adom_caps=Adom.CAPS,
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
        dns_tool_servers=(dns_tool_svc.dns_servers() if _is_admin() else []),
        policy_links=(policy_links_svc.links() if _is_admin() else []),
        policy_link_tokens=policy_links_svc.TOKENS,
        clone_rules_cfg=(clone_rules_svc.config() if _is_admin() else None),
        sot_firmware_repo=(store.firmware_repo() if _is_admin() else None),
        sot_backup_server=(store.backup_server() if _is_admin() else None),
        system_info=system_info.collect(),
        is_admin=_is_admin(),
    )


@bp.route('/library-updates')
@login_required
@require_permission(Permission.USER_MANAGE)
def library_updates():
    """Best-effort 'update available?' check for the Settings → Libraries card.

    Kept out of the page render (see ``services.library_updates``): the PyPI
    lookup runs only here, is cached in-process, and never blocks the Settings
    page. ``?force=1`` bypasses the cache (the 'Check for updates' button).
    """
    from ..services import library_updates as libupd
    data = libupd.check(force=(request.args.get('force') == '1'))
    return jsonify(data)


@bp.route('/library-pip/state')
@login_required
@require_permission(Permission.USER_MANAGE)
def library_pip_state():
    """This node's identity + per-package rollback points for the Libraries
    card. Cheap, no network — safe to call on every card render."""
    from ..services import self_update as su
    return jsonify({
        'node': su.this_node_name(),
        'role': su.node_role(),
        'rollbacks': su.lib_versions(),
    })


@bp.route('/library-pip', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def library_pip():
    """Enqueue a curated-only per-package pip upgrade/rollback. The web worker
    NEVER runs pip — it writes a request the privileged updater service applies
    (curated allowlist enforced both here and in the runner). Node-local."""
    from ..services import self_update as su
    payload = request.get_json(silent=True) or {}
    package = (payload.get('package') or '').strip()
    version = (payload.get('version') or '').strip()
    action = (payload.get('action') or 'upgrade').strip()
    try:
        uid = su.request_pip_change(package, version,
                                    by=getattr(current_user, 'username', '?'),
                                    action=action)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({'error': 'could not queue: %s' % exc}), 500
    log_action('settings.library_pip',
               detail='%s %s==%s on %s' % (action, package, version, su.this_node_name()))
    return jsonify({'uid': uid, 'node': su.this_node_name()})


@bp.route('/library-pip/status/<uid>')
@login_required
@require_permission(Permission.USER_MANAGE)
def library_pip_status(uid):
    """Poll a queued pip change's live status (steps written by the runner)."""
    from ..services import self_update as su
    st = su.update_status(uid)
    if st is None:
        return jsonify({'state': 'unknown'}), 404
    return jsonify(st)


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
            env_mode=request.form.get('env_mode', ''),
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
    mapping = {p: request.form.get('banner_' + p, '')
               for p in store.BANNER_PRODUCTS}
    user_store.save_banners(current_user.id, mapping)
    log_action('settings.banners',
               detail=", ".join(f"{p}={v}" for p, v in mapping.items() if v))
    flash('Banner templates saved.', 'success')
    return redirect(url_for('auth.profile'))


# --------------------------------------------------------------------------- #
#  ADOM registry (Settings → ADOMs) — the data-driven product catalog.         #
#  Admin-only. The registry itself (branding.PRODUCTS + capability sequences)   #
#  reads the ``adoms`` table; these routes are the CRUD + logo upload for it.   #
# --------------------------------------------------------------------------- #
import os as _os
import re as _re

from ..models_adom import Adom
from .. import branding

_ADOM_KEY_RE = _re.compile(r'^[a-z][a-z0-9_-]{1,63}$')
# The three real ADOMs may be edited/deactivated but NOT deleted (their keys are
# wired into URL scoping and would orphan data). Custom/placeholder ADOMs are
# fully deletable.
_ADOM_UNDELETABLE = {'global', 'fortiweb', 'fortiadc'}
_LOGO_RASTER_EXT = {'.png', '.jpg', '.jpeg', '.webp', '.gif'}
_LOGO_MAX_PX = 256   # rasters are fit within this box (aspect preserved)


def _adom_form_caps():
    """Read the five capability checkboxes off the current request form."""
    return {c: (request.form.get('cap_' + c) in ('1', 'on', 'true'))
            for c in Adom.CAPS}


def _bump_registry():
    branding.invalidate()


def _save_logo(adom: Adom, file) -> str | None:
    """Persist an uploaded logo for ``adom``. Rasters are resized server-side to
    fit ``_LOGO_MAX_PX`` (aspect preserved, transparency kept); SVGs are
    sanitised (scripts/handlers stripped) rather than resized. Returns an error
    string on failure, else ``None`` and sets ``adom.mark``."""
    if not file or not file.filename:
        return None
    ext = _os.path.splitext(file.filename)[1].lower()
    img_dir = _os.path.join(current_app.static_folder, 'img')
    _os.makedirs(img_dir, exist_ok=True)

    if ext == '.svg':
        raw = file.read()
        if len(raw) > 512 * 1024:
            return 'SVG too large (max 512 KB).'
        try:
            text = raw.decode('utf-8', 'replace')
        except Exception:
            return 'SVG could not be decoded.'
        # Strip the obvious XSS vectors — third-party SVG goes into the DOM.
        text = _re.sub(r'(?is)<script.*?>.*?</script>', '', text)
        text = _re.sub(r'(?is)<foreignObject.*?>.*?</foreignObject>', '', text)
        text = _re.sub(r'(?i)\son\w+\s*=\s*"[^"]*"', '', text)
        text = _re.sub(r"(?i)\son\w+\s*=\s*'[^']*'", '', text)
        text = _re.sub(r'(?i)javascript:', '', text)
        if '<svg' not in text.lower():
            return 'Not a valid SVG file.'
        rel = 'img/adom-%s-mark.svg' % adom.key
        with open(_os.path.join(current_app.static_folder, rel), 'w',
                  encoding='utf-8') as fh:
            fh.write(text)
        adom.mark = rel
        return None

    if ext in _LOGO_RASTER_EXT:
        try:
            from PIL import Image
            img = Image.open(file.stream)
            img.load()
            if img.mode not in ('RGBA', 'RGB'):
                img = img.convert('RGBA')
            img.thumbnail((_LOGO_MAX_PX, _LOGO_MAX_PX), Image.LANCZOS)
            rel = 'img/adom-%s-mark.png' % adom.key
            img.save(_os.path.join(current_app.static_folder, rel), 'PNG')
            adom.mark = rel
            return None
        except Exception as exc:  # noqa: BLE001
            return 'Image could not be processed: %s' % exc

    return 'Unsupported logo type (use PNG, JPG, WEBP, GIF or SVG).'


@bp.route('/adoms', methods=['POST'])
@login_required
def create_adom():
    if not _is_admin():
        abort(403)
    key = (request.form.get('key') or '').strip().lower()
    if not _ADOM_KEY_RE.match(key):
        flash('Invalid ADOM key — use lowercase letters, digits, - and _ '
              '(2-64 chars, starting with a letter).', 'danger')
        return redirect(url_for('settings.index') + '#tab-adoms')
    if Adom.query.filter_by(key=key).first():
        flash('An ADOM with key %r already exists.' % key, 'danger')
        return redirect(url_for('settings.index') + '#tab-adoms')

    caps = _adom_form_caps()
    max_order = db.session.query(db.func.max(Adom.sort_order)).scalar() or 0
    adom = Adom(
        key=key,
        name=(request.form.get('name') or key).strip()[:128],
        title=(request.form.get('title') or 'OFortMAuT').strip()[:128],
        tagline=(request.form.get('tagline') or '').strip()[:200],
        description=(request.form.get('description') or '').strip(),
        active=(request.form.get('active') in ('1', 'on', 'true')),
        placeholder=(request.form.get('placeholder') in ('1', 'on', 'true')),
        sort_order=int(max_order) + 1,
        banner_default=(request.form.get('banner_default') or 'slate').strip()[:32],
        mark='img/global-mark.svg',
        cap_banner=caps['banner'], cap_tokens=caps['tokens'],
        cap_firmware=caps['firmware'], cap_naming=caps['naming'],
        cap_regex=caps['regex'],
    )
    db.session.add(adom)
    db.session.flush()
    err = _save_logo(adom, request.files.get('logo'))
    if err:
        db.session.rollback()
        flash(err, 'danger')
        return redirect(url_for('settings.index') + '#tab-adoms')
    db.session.commit()
    _bump_registry()
    log_action('settings.adom.create', detail='key=%s' % key)
    flash('ADOM %r created.' % key, 'success')
    return redirect(url_for('settings.index') + '#tab-adoms')


@bp.route('/adoms/<key>', methods=['POST'])
@login_required
def update_adom(key):
    if not _is_admin():
        abort(403)
    adom = Adom.query.filter_by(key=key).first_or_404()
    caps = _adom_form_caps()
    adom.name = (request.form.get('name') or adom.name).strip()[:128]
    adom.title = (request.form.get('title') or 'OFortMAuT').strip()[:128]
    adom.tagline = (request.form.get('tagline') or '').strip()[:200]
    adom.description = (request.form.get('description') or '').strip()
    adom.active = (request.form.get('active') in ('1', 'on', 'true'))
    adom.placeholder = (request.form.get('placeholder') in ('1', 'on', 'true'))
    adom.banner_default = (request.form.get('banner_default')
                           or adom.banner_default).strip()[:32]
    for c in Adom.CAPS:
        setattr(adom, 'cap_' + c, caps[c])
    if request.form.get('sort_order', '').strip().isdigit():
        adom.sort_order = int(request.form['sort_order'])
    err = _save_logo(adom, request.files.get('logo'))
    if err:
        db.session.rollback()
        flash(err, 'danger')
        return redirect(url_for('settings.index') + '#tab-adoms')
    db.session.commit()
    _bump_registry()
    log_action('settings.adom.update', detail='key=%s' % key)
    flash('ADOM %r updated.' % key, 'success')
    return redirect(url_for('settings.index') + '#tab-adoms')


@bp.route('/adoms/<key>/delete', methods=['POST'])
@login_required
def delete_adom(key):
    if not _is_admin():
        abort(403)
    if key in _ADOM_UNDELETABLE:
        flash('The %r ADOM is a core product and cannot be deleted — '
              'deactivate it instead.' % key, 'danger')
        return redirect(url_for('settings.index') + '#tab-adoms')
    adom = Adom.query.filter_by(key=key).first_or_404()
    db.session.delete(adom)
    db.session.commit()
    _bump_registry()
    log_action('settings.adom.delete', detail='key=%s' % key)
    flash('ADOM %r deleted.' % key, 'success')
    return redirect(url_for('settings.index') + '#tab-adoms')


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


# ── SoT & Backup server (firmware SoT repo + backup-server SFTP access) ──────────

@bp.route('/sot-backup', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_sot_backup():
    store.save_firmware_repo(request.form.get('fw_repo_url', ''),
                             request.form.get('fw_repo_branch', ''))
    store.save_backup_server(request.form)
    log_action("settings.sot_backup",
               detail=f"backup_server={request.form.get('host','')!r}")
    flash('SoT & Backup server settings saved.', 'success')
    return redirect(url_for('settings.index') + '#tab-sotbackup')


@bp.route('/sot-backup/test', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def test_sot_backup():
    from ..services import backup_server as bksrv
    return jsonify(bksrv.test_connection())


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
@bp.route('/dns-tool', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_dns_tool():
    """Persist the DNS & LB Lookup resolver list (AppSetting ``dnstool.servers``).

    The list is variable by design — rows are parallel ``dns_name[]`` /
    ``dns_server[]`` arrays plus ``dns_enabled`` checkboxes carrying the row
    index; blank rows are dropped, so removing a server = clearing its row."""
    names = request.form.getlist('dns_name')
    servers = request.form.getlist('dns_server')
    enabled = set(request.form.getlist('dns_enabled'))
    rows = [{'name': n, 'server': s, 'enabled': str(i) in enabled}
            for i, (n, s) in enumerate(zip(names, servers))]
    try:
        saved = dns_tool_svc.save_dns_servers(rows)
    except ValueError as exc:
        flash(str(exc), 'danger')
        return redirect(url_for('settings.index'))
    log_action('settings.dns_tool', target='dnstool.servers')
    flash(f'DNS server list saved ({len(saved)} servers).', 'success')
    return redirect(url_for('settings.index'))


@bp.route('/clone-rules', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_clone_rules():
    """Persist the Clone / Migrate policy (AppSetting ``clone.rules``): the
    dummy-IP transformation rules (leading-octet match → replace, e.g. 10 → 240),
    the fallback dummy IP, and whether a clone/migrate copies the Web Protection
    Profile by default. Variable-length rows like the DNS-tool list — blank rows
    are dropped, so clearing a row removes that rule."""
    matches = request.form.getlist('rule_match')
    replaces = request.form.getlist('rule_replace')
    rows = [{'match': m, 'replace': r} for m, r in zip(matches, replaces)]
    try:
        cfg = clone_rules_svc.save_config(
            rows,
            request.form.get('fallback_ip', ''),
            request.form.get('copy_wpp_default') == 'on')
    except ValueError as exc:
        flash('Clone/Migrate rules NOT saved: %s' % exc, 'danger')
        return redirect(url_for('settings.index') + '#tab-clonerules')
    log_action('settings.clone_rules', target=clone_rules_svc.SETTING_KEY,
               detail='rules=%d fallback=%s copy_wpp=%s' % (
                   len(cfg['ip_rules']), cfg['fallback_ip'], cfg['copy_wpp_default']))
    flash('Clone/Migrate rules saved (%d IP rule%s).'
          % (len(cfg['ip_rules']), '' if len(cfg['ip_rules']) == 1 else 's'), 'success')
    return redirect(url_for('settings.index') + '#tab-clonerules')


@bp.route('/policy-links', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_policy_links():
    """Persist the dynamic policy-link list (AppSetting ``policy.links``).

    Variable-length by design — rows are parallel ``link_label[]`` / ``link_url[]``
    arrays plus ``link_newtab`` / ``link_enabled`` checkboxes carrying the row
    index; blank rows are dropped, so clearing a row removes that link."""
    # Each row carries a stable per-row token (``link_row``) in a hidden input
    # plus its ``link_label`` / ``link_url`` (text inputs always submit, so the
    # three lists stay aligned). The enabled / new-tab checkboxes carry that
    # SAME token as their value — so we map state BY TOKEN, never by position
    # (robust to rows added/removed in any order in the browser).
    row_ids = request.form.getlist('link_row')
    labels = request.form.getlist('link_label')
    urls = request.form.getlist('link_url')
    enabled = set(request.form.getlist('link_enabled'))
    newtab = set(request.form.getlist('link_newtab'))
    if len(row_ids) != len(labels):  # fallback if a client omits link_row
        row_ids = [str(i) for i in range(len(labels))]
    rows = [{'label': lbl, 'url': u,
             'enabled': rid in enabled, 'new_tab': rid in newtab}
            for rid, lbl, u in zip(row_ids, labels, urls)]
    saved, errors = policy_links_svc.save_links(rows)
    log_action('settings.policy_links', target='policy.links')
    for msg in errors:
        flash(msg, 'warning')
    submitted = any((lbl.strip() or u.strip()) for lbl, u in zip(labels, urls))
    if saved:
        flash('Policy links saved (%d link%s).'
              % (len(saved), '' if len(saved) == 1 else 's'), 'success')
    elif submitted:
        flash('No links were saved — see the message(s) above. Each link '
              'needs both a label and a URL.', 'danger')
    else:
        flash('Policy links cleared.', 'success')
    return redirect(url_for('settings.index') + '#tab-policylinks')
