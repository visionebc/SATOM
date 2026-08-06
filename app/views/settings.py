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
from ..models import db, Permission, User, Role, Profile, Appliance
from ..services import naming, settings_store as store
from ..services import email_service as email
from ..services import auth_store
from ..services import twofa
from ..services import git_service
from ..services import user_settings_store as user_store
from ..services import system_info
from ..services import dns_tool as dns_tool_svc
from ..services import dns_providers
from ..services import acme_providers
from ..services import policy_links as policy_links_svc
from ..services import clone_rules as clone_rules_svc
from ..services import faz_menu
from ..services import alerts as alerts_svc
from ..services.audit import log_action

bp = Blueprint('settings', __name__, url_prefix='/settings')


def _theme_rows():
    """Every theme, built-ins first then alphabetical — for the Appearance tab."""
    try:
        from ..models_theme import UiTheme
        rows = UiTheme.query.order_by(UiTheme.builtin.desc(), UiTheme.name).all()
        return [t.to_dict() for t in rows]
    except Exception:  # noqa: BLE001
        return []


def _theme_groups():
    try:
        from ..services.theme_tokens import by_group
        return by_group()
    except Exception:  # noqa: BLE001
        return []


def _theme_defaults():
    try:
        from ..services.theme_tokens import DEFAULTS
        return DEFAULTS
    except Exception:  # noqa: BLE001
        return {}


def _is_admin() -> bool:
    return bool(current_user and current_user.can(Permission.USER_MANAGE))


def _acme_creds_state() -> dict:
    """Per provider: which env vars already have a stored value, and which
    REQUIRED ones are still missing. Secret VALUES never reach the template —
    only the fact that one is stored (same contract as every other secret)."""
    out = {}
    for p in acme_providers.catalog(enabled_only=False):
        stored = store.acme_provider_creds(p.slug, p.field_list, reveal=False)
        out[p.slug] = {
            'vals': {f['env']: ('' if f.get('secret') else stored.get(f['env'], ''))
                     for f in p.field_list},
            'secret_set': {f['env']: bool(stored.get(f['env'] + '__set'))
                           for f in p.field_list if f.get('secret')},
            'missing': acme_providers.missing_required(p.slug),
        }
    return out


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
        themes=(_theme_rows() if _is_admin() else []),
        theme_groups=_theme_groups(),
        theme_defaults=_theme_defaults(),
        adom_caps=Adom.CAPS,
        email_config=email.config(),
        alerts_config=alerts_svc.config(),
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
        acme_challenges=store.ACME_CHALLENGES,
        acme_key_types=store.ACME_KEY_TYPES,
        acme_directories=acme_providers.KNOWN_DIRECTORIES,
        acme_providers=([p.to_dict() for p in acme_providers.catalog(enabled_only=False)]
                        if _is_admin() else []),
        acme_provider_creds=(_acme_creds_state() if _is_admin() else {}),
        cert_lifecycle=(store.cert_lifecycle_policy() if _is_admin() else None),
        dns_tool_servers=(dns_tool_svc.dns_servers() if _is_admin() else []),
        dnsrec_cfg=(dns_providers.config_public() if _is_admin() else None),
        dnsrec_providers=([(k, dns_providers.PROVIDERS[k].label)
                           for k in ('none', 'efficientip', 'phpipam', 'netbox')]
                          if _is_admin() else []),
        dnsrec_field_specs=(dns_providers.FIELD_SPECS if _is_admin() else {}),
        dnsrec_secret_labels=(dns_providers.SECRET_LABELS if _is_admin() else {}),
        policy_links=(policy_links_svc.links() if _is_admin() else []),
        policy_link_tokens=policy_links_svc.TOKENS,
        clone_rules_cfg=(clone_rules_svc.config() if _is_admin() else None),
        sot_firmware_repo=(store.firmware_repo() if _is_admin() else None),
        sot_backup_server=(store.backup_server() if _is_admin() else None),
        system_info=system_info.collect(),
        faz_menu_groups=(faz_menu.menu() if _is_admin() else []),
        faz_menu_hidden=(sorted(faz_menu.hidden_keys()) if _is_admin() else []),
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


@bp.route('/faz-menu', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_faz_menu():
    """Hide/show FortiAnalyzer ADOM menu groups & leaves (cascade). Stored in
    the replicated app_settings table; takes effect on the next page render."""
    try:
        visible = set(request.form.getlist('visible'))
        hidden = [k for k in faz_menu.all_keys() if k not in visible]
        faz_menu.set_hidden_keys(hidden)
        log_action('settings.faz_menu', detail='Updated FAZ menu visibility')
        flash('FortiAnalyzer menu visibility saved.', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Failed to save FAZ menu visibility: {exc}', 'danger')
    return redirect(url_for('settings.index') + '#tab-fazmenu')


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
        'client': f.get('acme_client', 'lego'),
        'bin': f.get('acme_bin', ''),
        'helper': f.get('acme_helper', ''),
        'directory_url': f.get('acme_directory_url', ''),
        'account_email': f.get('acme_account_email', ''),
        'account_key_dir': f.get('acme_account_key_dir', ''),
        'tos_agreed': '1' if f.get('acme_tos_agreed') else '',
        'key_type': f.get('acme_key_type', 'EC256'),
        'eab_kid': f.get('acme_eab_kid', ''),
        'challenge': f.get('acme_challenge', 'http-01'),
        'http_mode': f.get('acme_http_mode', 'webroot'),
        'webroot_path': f.get('acme_webroot_path', ''),
        'http_port': f.get('acme_http_port', '80'),
        'dns_provider': f.get('acme_dns_provider', ''),
        'dns_resolvers': f.get('acme_dns_resolvers', ''),
        'dns_propagation_wait': f.get('acme_dns_propagation_wait', ''),
        'dns_disable_precheck': '1' if f.get('acme_dns_disable_precheck') else '',
        'template_mode': f.get('acme_template_mode', 'auto'),
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


# --------------------------------------------------------------------------- #
#  ACME DNS-01 providers — catalog + per-provider credentials                   #
#  The catalog is DATA (acme_dns_providers, seeded INSERT-ONLY from             #
#  acme_providers.yaml): adding a provider is a row, never a deploy. The form   #
#  is rendered FROM the provider's field list, so nothing here is hardcoded.    #
# --------------------------------------------------------------------------- #
@bp.route('/acme-provider/<slug>/creds', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_acme_provider_creds(slug):
    prov = acme_providers.get(slug)
    if prov is None:
        flash(f'Unknown DNS provider {slug!r}.', 'danger')
        return redirect(url_for('settings.index') + '#tab-certmgr')
    f = request.form
    values = {}
    for spec in prov.field_list:
        env = spec['env']
        values[env] = f.get(f'cred_{env}', '')
        values['clear__' + env] = bool(f.get(f'clear_{env}'))
    store.save_acme_provider_creds(slug, prov.field_list, values)
    # Never log values — only which variables were touched.
    log_action('settings.acme_provider_creds', target=slug,
               detail=f"{len(prov.field_list)} field(s) submitted")
    flash(f'Credentials for {prov.label} saved.', 'success')
    return redirect(url_for('settings.index') + '#tab-certmgr')


@bp.route('/acme-provider', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_acme_provider():
    """Create or edit a catalog entry. ``fields`` arrives as the JSON list the
    UI edits — that is what makes a brand-new provider possible without code."""
    f = request.form
    slug = (f.get('slug') or '').strip().lower()
    try:
        acme_providers.upsert(slug, {
            'label': f.get('label', ''),
            'flag': f.get('flag', ''),
            'doc_url': f.get('doc_url', ''),
            'fields': f.get('fields', '[]'),
            'enabled': f.get('enabled') == 'on',
            'sort': f.get('sort') or None,
        })
    except Exception as exc:  # noqa: BLE001 — a bad JSON blob must not 500
        flash(f'Provider not saved: {exc}', 'danger')
        return redirect(url_for('settings.index') + '#tab-certmgr')
    log_action('settings.acme_provider', target=slug, detail='catalog entry saved')
    flash(f'DNS provider {slug} saved.', 'success')
    return redirect(url_for('settings.index') + '#tab-certmgr')


@bp.route('/acme-provider/<slug>/delete', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete_acme_provider(slug):
    if acme_providers.delete(slug):
        log_action('settings.acme_provider_delete', target=slug)
        flash(f'DNS provider {slug} deleted.', 'success')
    else:
        flash('Built-in providers cannot be deleted — disable them instead.',
              'warning')
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
        title=(request.form.get('title') or 'SATOM').strip()[:128],
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
    adom.title = (request.form.get('title') or 'SATOM').strip()[:128]
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


@bp.route('/alerts', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_alerts():
    try:
        alerts_svc.save_config(request.form)
        log_action('settings.alerts', detail='Updated alert/notification settings')
        flash('Alert settings saved.', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Failed to save alert settings: {exc}', 'danger')
    return redirect(url_for('settings.index') + '#tab-email')


@bp.route('/alerts/preview')
@login_required
@require_permission(Permission.USER_MANAGE)
def preview_alerts():
    """Run every enabled check once WITHOUT dispatching — lets the admin see what
    would fire right now before turning alerts on."""
    try:
        findings = alerts_svc.evaluate()
        return jsonify({'ok': True, 'count': len(findings),
                        'recipients': alerts_svc.recipients(),
                        'findings': findings})
    except Exception as exc:  # noqa: BLE001
        return jsonify({'ok': False, 'detail': str(exc)}), 500


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


def _dnsrec_form_fields(provider):
    """Pull the non-secret fields for *provider* out of the request form."""
    fields = {'verify_ssl': bool(request.form.get('dnsrec_verify_ssl'))}
    for spec in dns_providers.FIELD_SPECS.get(provider, []):
        fields[spec['key']] = request.form.get('dnsrec_' + spec['key'], '')
    return fields


@bp.route('/dns-records', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_dns_records():
    """Persist the DNS Records / IPAM provider (AppSetting ``dnsrecords.*``).

    Provider selector + non-secret connection fields + one Fernet-encrypted
    secret. A blank secret leaves the stored one untouched; the explicit
    ``dnsrec_clear_secret`` checkbox wipes it (e.g. switching provider)."""
    provider = (request.form.get('dnsrec_provider') or 'none').strip()
    if provider not in dns_providers.PROVIDERS:
        provider = 'none'
    fields = _dnsrec_form_fields(provider)
    secret = (request.form.get('dnsrec_secret') or '').strip() or None
    dns_providers.save_config(provider, fields, secret)
    if request.form.get('dnsrec_clear_secret'):
        dns_providers.clear_secret()
    log_action('settings.dns_records', target=f'dnsrecords.provider={provider}')
    flash(f'DNS Records provider saved ({dns_providers.PROVIDERS[provider].label}).',
          'success')
    return redirect(url_for('settings.index') + '#tab-dnsrecords')


@bp.route('/dns-records/test', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def test_dns_records():
    """Test the connection using the CURRENT form values (unsaved). Falls back
    to the stored secret when the form leaves the secret blank."""
    data = request.get_json(silent=True) or {}
    provider = (data.get('provider') or 'none').strip()
    if provider == 'none' or provider not in dns_providers.PROVIDERS:
        return jsonify(ok=False, message='Select a provider first.'), 400
    fields = {'verify_ssl': bool(data.get('verify_ssl', True))}
    for spec in dns_providers.FIELD_SPECS.get(provider, []):
        fields[spec['key']] = data.get(spec['key'], '')
    secret = (data.get('secret') or '').strip() or None
    prov = dns_providers.provider_for_test(provider, fields, secret)
    try:
        ok, message = prov.test_connection()
    except Exception as exc:  # noqa: BLE001 — surface any client error to the UI
        ok, message = False, str(exc)
    return jsonify(ok=bool(ok), message=message)


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


# ---- Node TLS: the service's own cert + node-to-node SSL policy -----------
@bp.route('/node-cert/state')
@login_required
@require_permission(Permission.USER_MANAGE)
def node_cert_state():
    from ..services import cert_service as cs
    from ..services import encryption_health as eh
    from ..services import node_security as nsec
    return jsonify({
        'cert': cs.current(),
        'pg_ssl': eh.pg_ssl_policy(),
        'identity_key': nsec.configured(),
        'hostname': cs.node_hostname(),
        'renew_mode': cs.renew_mode(),
        'autopull': cs.autopull_config(),   # no secret revealed
    })


@bp.route('/node-cert/renew-mode', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def node_cert_renew_mode():
    """Choose how an IMPORTED cert is renewed: 'alert' (warn only) or 'autopull'
    (fetch+install from a source over SFTP). Saves the mode + connection."""
    from ..services import cert_service as cs
    data = request.form if request.form else (request.get_json(silent=True) or {})
    mode = (data.get('renew_mode') or 'alert').strip().lower()
    try:
        cs.save_autopull_config(dict(data), mode=mode)
        log_action('node_cert.renew_mode', 'security', detail=mode)
        return jsonify({'ok': True, 'renew_mode': cs.renew_mode(),
                        'autopull': cs.autopull_config()})
    except Exception as e:  # noqa: BLE001
        return jsonify({'ok': False, 'error': str(e)[:300]}), 400


@bp.route('/node-cert/autopull', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def node_cert_autopull():
    """Trigger a one-off autopull now (test button). Ignores the mode gate."""
    from ..services import cert_service as cs
    try:
        res = cs.autopull(by=getattr(current_user, 'username', ''), force=True)
        log_action('node_cert.autopull', 'security', detail=str(res))
        return jsonify({'ok': bool(res.get('pulled') or 'up to date' in (res.get('reason') or '')),
                        'result': res, 'cert': cs.current()})
    except Exception as e:  # noqa: BLE001
        return jsonify({'ok': False, 'error': str(e)[:300]}), 400


@bp.route('/node-cert/import', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def node_cert_import():
    from ..services import cert_service as cs
    cert = request.files.get('cert')
    key = request.files.get('key')
    chain = request.files.get('chain')
    if not cert or not key or not cert.filename or not key.filename:
        return jsonify({'ok': False, 'error': 'cert and key PEM files are required'}), 400
    try:
        chb = chain.read() if (chain and chain.filename) else None
        info = cs.import_pem(cert.read(), key.read(), chb,
                             by=getattr(current_user, 'username', ''))
        log_action('node_cert.import', 'security', detail=info.get('subject'))
        return jsonify({'ok': True, 'cert': info})
    except Exception as e:  # noqa: BLE001
        return jsonify({'ok': False, 'error': str(e)[:300]}), 400


@bp.route('/node-cert/issue', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def node_cert_issue():
    from ..services import cert_service as cs
    try:
        info = cs.issue_internal(by=getattr(current_user, 'username', ''))
        log_action('node_cert.issue', 'security', detail=info.get('subject'))
        return jsonify({'ok': True, 'cert': info})
    except Exception as e:  # noqa: BLE001
        return jsonify({'ok': False, 'error': str(e)[:300]}), 400


@bp.route('/node-cert/renew', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def node_cert_renew():
    from ..services import cert_service as cs
    try:
        res = cs.renew_if_needed(by=getattr(current_user, 'username', ''), force=True)
        log_action('node_cert.renew', 'security', detail=str(res))
        return jsonify({'ok': True, 'result': res, 'cert': cs.current()})
    except Exception as e:  # noqa: BLE001
        return jsonify({'ok': False, 'error': str(e)[:300]}), 400


# ---- TLS trust store: the CAs this node ACCEPTS from devices --------------
# Mirror of the Node TLS block above. That one is the certificate SATOM
# PRESENTS; this one is which issuers it BELIEVES when it dials an appliance.
# Before it existed, Appliance.verify_ssl=True meant "validate against the
# public root store", which no privately-signed device can satisfy — so every
# appliance in this fleet had verification switched off instead.
@bp.route('/trust-store/state')
@login_required
@require_permission(Permission.USER_MANAGE)
def trust_store_state():
    from ..services import trust_store as ts
    from ..models_trust import TrustedCa
    from ..models import visible_appliances
    rows = TrustedCa.query.order_by(TrustedCa.role.desc(), TrustedCa.name).all()
    target = ts.verify_param()
    # The probe picker is built from visible_appliances(), so a concrete ADOM
    # can only aim it at its own product's boxes.
    appls = [{'id': a.id, 'name': a.name, 'host': a.host, 'port': a.port,
              'kind': a.kind, 'verify_ssl': bool(a.verify_ssl)}
             for a in visible_appliances().order_by(Appliance.name).all()]
    return jsonify({
        'cas': [r.to_dict() for r in rows],
        'gaps': ts.chain_gaps(),
        # A path means the private bundle is live; True means public roots only.
        'bundle': (target if isinstance(target, str) else ''),
        'public_roots_only': target is True,
        'appliances': appls,
    })


@bp.route('/trust-store/import', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def trust_store_import():
    """Accept a pasted PEM or an uploaded file. A whole chain in one blob is
    the normal case (root + intermediate), so partial success is reported
    rather than rejecting the lot."""
    from ..services import trust_store as ts
    # Two labelled slots (root / intermediate) plus the original unlabelled
    # pair, concatenated into ONE blob. import_pem already splits a
    # multi-certificate PEM, so a single call keeps the whole submission in one
    # transaction, one dedupe pass and one bundle rebuild. Importing the slots
    # separately would let the root land while the intermediate failed, leaving
    # a chain gap the operator never asked for.
    #
    # THE SLOT LABEL IS A HINT, NEVER THE VERDICT. `role` is derived inside
    # trust_store from subject == issuer, so a root pasted into the
    # intermediate box is still recorded as a root. A form field must not be
    # able to relabel a trust anchor -- chain_gaps() would then report a
    # phantom gap, or worse, stay silent about a real one.
    #
    # Both the file and the text of a slot are taken (the old code let the file
    # win). Filling both is a stated intent, and a duplicate is harmless: the
    # fingerprint is the identity, so it lands as an update, not a second row.
    parts = []
    for f_field, t_field in (('pem_file', 'pem_text'),
                             ('pem_file_root', 'pem_text_root'),
                             ('pem_file_intermediate', 'pem_text_intermediate')):
        up = request.files.get(f_field)
        if up and up.filename:
            data = (up.read() or b'').strip()
            if data:
                parts.append(data)
        txt = (request.form.get(t_field) or '').strip()
        if txt:
            parts.append(txt.encode())
    blob = b'\n'.join(parts)
    try:
        res = ts.import_pem(blob,
                            actor=getattr(current_user, 'username', ''),
                            note=(request.form.get('note') or '').strip()[:500],
                            name_hint=(request.form.get('name') or '').strip()[:200])
        log_action('trust_store.import', 'security',
                   detail=f"imported={res['imported']} updated={res['updated']} "
                          f"rejected={len(res['rejected'])}")
        return jsonify({'ok': True, 'result': res})
    except Exception as e:  # noqa: BLE001
        return jsonify({'ok': False, 'error': str(e)[:500]}), 400


@bp.route('/trust-store/<int:ca_id>/toggle', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def trust_store_toggle(ca_id):
    from ..services import trust_store as ts
    from ..models_trust import TrustedCa
    row = TrustedCa.query.get_or_404(ca_id)
    row.enabled = not row.enabled
    db.session.commit()
    ts.invalidate()
    log_action('trust_store.toggle', 'security',
               detail=f"{row.name} enabled={row.enabled}")
    return jsonify({'ok': True, 'ca': row.to_dict()})


@bp.route('/trust-store/<int:ca_id>/delete', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def trust_store_delete(ca_id):
    from ..services import trust_store as ts
    from ..models_trust import TrustedCa
    row = TrustedCa.query.get_or_404(ca_id)
    name = row.name
    db.session.delete(row)
    db.session.commit()
    ts.invalidate()
    log_action('trust_store.delete', 'security', detail=name)
    return jsonify({'ok': True, 'deleted': name})


@bp.route('/trust-store/probe', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def trust_store_probe():
    """Diagnose one appliance's TLS against the CURRENT store.

    Answers the only question that matters after importing a CA: can this
    device now be verified, and if not, WHICH of the three causes is it? The
    appliance is resolved through visible_appliances(), so this cannot be used
    from one ADOM to probe another product's box."""
    from ..services import trust_store as ts
    from ..models import visible_appliances
    aid = request.form.get('appliance_id') or (request.get_json(silent=True) or {}).get('appliance_id')
    try:
        appl = visible_appliances().filter_by(id=int(aid)).first()
    except (TypeError, ValueError):
        appl = None
    if appl is None:
        return jsonify({'ok': False, 'error': 'unknown appliance'}), 404
    try:
        res = ts.probe(appl.host, appl.port or 443)
        res['appliance'] = {'id': appl.id, 'name': appl.name,
                            'kind': appl.kind, 'verify_ssl': bool(appl.verify_ssl)}
        return jsonify({'ok': True, 'result': res})
    except Exception as e:  # noqa: BLE001
        return jsonify({'ok': False, 'error': str(e)[:300]}), 400


@bp.route('/pg-ssl', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_pg_ssl():
    from ..services import pg_ssl as pgsvc
    try:
        res = pgsvc.apply_policy(request.form.get('min_protocol', 'TLSv1.2'),
                                 request.form.get('ciphers', ''),
                                 by=getattr(current_user, 'username', ''))
        log_action('pg_ssl.policy', 'security', detail=str(res))
        return jsonify({'ok': True, 'result': res})
    except Exception as e:  # noqa: BLE001
        return jsonify({'ok': False, 'error': str(e)[:300]}), 400


# --------------------------------------------------------------------------- #
#  Appearance — UI themes                                                      #
#                                                                              #
#  The console's look is a set of ``--fw-*`` design tokens (registry generated  #
#  from the stylesheet itself, see deploy/gen_theme_tokens.py). These routes    #
#  are the CRUD around named sets of them plus the brand logo/favicon.         #
#                                                                              #
#  Two things are load-bearing:                                                #
#   * every token value is allowlisted per KIND in theme_service before it can  #
#     reach the nonced <style> block — the DB is not a trust boundary;          #
#   * the built-in themes are immutable, so an operator who paints the console  #
#     unreadable always has a way back (Reset, or `satom execute reset theme`   #
#     on a node whose UI is unusable).                                          #
# --------------------------------------------------------------------------- #
from pathlib import Path as _Path

from flask import send_from_directory as _send_from_directory

from ..models_theme import UiTheme
from ..services import theme_service as theme_svc

_THEME_ASSET_KINDS = ('logo', 'favicon')
_THEME_RASTER_EXT = {'.png', '.jpg', '.jpeg', '.webp', '.gif', '.ico'}
_THEME_LOGO_MAX_PX = 256


def _theme_dir() -> _Path:
    """``data/branding`` — under ``data/`` on purpose.

    ``satom-ha-datasync`` replicates ``data/`` to the standby and the system
    backup bundles include it, so a custom logo survives a failover and a
    restore. ``static/img`` (where the per-ADOM marks live) is node-local and
    outside both.
    """
    d = _Path(__file__).resolve().parents[2] / 'data' / 'branding'
    d.mkdir(parents=True, exist_ok=True)
    return d


def _theme_slug(name: str, exclude_id: int | None = None) -> str:
    base = _re.sub(r'[^a-z0-9]+', '-', (name or '').lower()).strip('-')[:56] or 'theme'
    slug, n = base, 2
    while True:
        q = UiTheme.query.filter_by(slug=slug)
        if exclude_id:
            q = q.filter(UiTheme.id != exclude_id)
        if not q.first():
            return slug
        slug = '%s-%d' % (base, n)
        n += 1


def _form_tokens() -> dict:
    """Token overrides off the current request form (fields named ``tok_<name>``)."""
    out = {}
    for name in theme_svc.TOKEN_NAMES:
        val = request.form.get('tok_' + name)
        if val is not None and val.strip():
            out[name] = val.strip()
    return out


def _save_theme_asset(theme: UiTheme, file, kind: str) -> str | None:
    """Store an uploaded brand asset. Returns an error string, or ``None``.

    SVG is sanitised rather than resized (it goes into the DOM); rasters are
    re-encoded through Pillow, which is also what rejects a file that merely
    claims to be an image.
    """
    if not file or not file.filename:
        return None
    ext = _os.path.splitext(file.filename)[1].lower()
    dest = _theme_dir()
    if ext == '.svg':
        raw = file.read()
        if len(raw) > 512 * 1024:
            return 'SVG too large (max 512 KB).'
        text = raw.decode('utf-8', 'replace')
        text = _re.sub(r'(?is)<script.*?>.*?</script>', '', text)
        text = _re.sub(r'(?is)<foreignObject.*?>.*?</foreignObject>', '', text)
        text = _re.sub(r'(?i)\son\w+\s*=\s*"[^"]*"', '', text)
        text = _re.sub(r"(?i)\son\w+\s*=\s*'[^']*'", '', text)
        text = _re.sub(r'(?i)javascript:', '', text)
        if '<svg' not in text.lower():
            return 'Not a valid SVG file.'
        rel = 'theme-%d-%s.svg' % (theme.id, kind)
        (dest / rel).write_text(text, encoding='utf-8')
    elif ext in _THEME_RASTER_EXT:
        try:
            from PIL import Image
            img = Image.open(file.stream)
            img.load()
            if img.mode not in ('RGBA', 'RGB'):
                img = img.convert('RGBA')
            img.thumbnail((_THEME_LOGO_MAX_PX, _THEME_LOGO_MAX_PX), Image.LANCZOS)
            rel = 'theme-%d-%s.png' % (theme.id, kind)
            img.save(str(dest / rel), 'PNG')
        except Exception as exc:  # noqa: BLE001
            return 'Image could not be processed: %s' % exc
    else:
        return 'Unsupported %s type (use PNG, JPG, WEBP, GIF, ICO or SVG).' % kind
    setattr(theme, kind, rel)
    return None


def _theme_redirect():
    return redirect(url_for('settings.index') + '#tab-appearance')


@bp.route('/appearance/asset/<int:theme_id>/<kind>')
def theme_asset(theme_id, kind):
    """Serve a theme's brand asset. No auth gate on purpose: the logo/favicon
    now render on the login, forgot-password, reset-password and 2FA pages too
    (theme_service._inject_theme is a global context processor), so a session
    requirement here would 404 the icon on every page a signed-out visitor can
    reach. Not sensitive data — a PNG/SVG brand mark — and the filename comes
    from the DB row, never from the URL, so the path cannot be traversed."""
    if kind not in _THEME_ASSET_KINDS:
        abort(404)
    row = UiTheme.query.get_or_404(theme_id)
    rel = getattr(row, kind, '') or ''
    if not rel or '/' in rel or '\\' in rel:
        abort(404)
    return _send_from_directory(str(_theme_dir()), rel, max_age=300)


@bp.route('/appearance/preview', methods=['POST'])
@login_required
def theme_preview():
    """Validate a candidate palette without saving it.

    Powers the live preview and the contrast report. Returning the SAME css the
    server would emit (not something the browser assembled) means what the
    operator previews is what gets stored — a preview built client-side could
    show a value the validator would later reject.
    """
    if not _is_admin():
        abort(403)
    payload = request.get_json(silent=True) or {}
    tokens = payload.get('tokens') or {}
    clean, errors = theme_svc.validate_tokens(tokens)
    return jsonify(ok=not errors, errors=errors, css=theme_svc.css_for(clean),
                   overrides=clean, contrast=theme_svc.audit_contrast(clean))


def _apply_theme_form(theme: UiTheme) -> list[str]:
    """Name/description/tokens/assets from the request form. Returns errors."""
    errors: list[str] = []
    name = (request.form.get('name') or '').strip()[:128]
    if not name:
        errors.append('A theme name is required.')
    else:
        clash = UiTheme.query.filter(UiTheme.name == name,
                                     UiTheme.id != (theme.id or -1)).first()
        if clash:
            errors.append('A theme named %r already exists.' % name)
        else:
            theme.name = name
    theme.description = (request.form.get('description') or '').strip()[:300]
    clean, terrors = theme_svc.validate_tokens(_form_tokens())
    errors.extend(terrors)
    if not terrors:
        theme.tokens = clean
        if theme_svc.has_unreadable(clean) and \
                request.form.get('confirm_unreadable') not in ('1', 'on', 'true'):
            errors.append(
                'This palette drops text contrast below %.1f:1 in places — tick '
                '"apply anyway" to confirm.' % theme_svc.CONTRAST_FAIL)
    return errors


@bp.route('/appearance/themes', methods=['POST'])
@login_required
def create_theme():
    if not _is_admin():
        abort(403)
    theme = UiTheme(slug='pending', name='', builtin=False,
                    created_by=getattr(current_user, 'username', '') or '')
    errors = _apply_theme_form(theme)
    if errors:
        for e in errors:
            flash(e, 'danger')
        return _theme_redirect()
    theme.slug = _theme_slug(theme.name)
    db.session.add(theme)
    db.session.flush()          # need the id for the asset filenames
    for kind in _THEME_ASSET_KINDS:
        err = _save_theme_asset(theme, request.files.get(kind), kind)
        if err:
            db.session.rollback()
            flash(err, 'danger')
            return _theme_redirect()
    db.session.commit()
    theme_svc.invalidate()
    log_action('settings.theme.create', detail='name=%s' % theme.name)
    flash('Theme %r created.' % theme.name, 'success')
    return _theme_redirect()


@bp.route('/appearance/themes/<int:tid>', methods=['POST'])
@login_required
def update_theme(tid):
    if not _is_admin():
        abort(403)
    theme = UiTheme.query.get_or_404(tid)
    if theme.builtin:
        flash('Built-in themes cannot be edited — duplicate it first.', 'warning')
        return _theme_redirect()
    errors = _apply_theme_form(theme)
    if errors:
        db.session.rollback()
        for e in errors:
            flash(e, 'danger')
        return _theme_redirect()
    for kind in _THEME_ASSET_KINDS:
        if request.form.get('clear_' + kind) in ('1', 'on', 'true'):
            setattr(theme, kind, '')
        err = _save_theme_asset(theme, request.files.get(kind), kind)
        if err:
            db.session.rollback()
            flash(err, 'danger')
            return _theme_redirect()
    db.session.commit()
    theme_svc.invalidate()
    log_action('settings.theme.update', detail='name=%s' % theme.name)
    flash('Theme %r saved.' % theme.name, 'success')
    return _theme_redirect()


@bp.route('/appearance/themes/<int:tid>/duplicate', methods=['POST'])
@login_required
def duplicate_theme(tid):
    if not _is_admin():
        abort(403)
    src = UiTheme.query.get_or_404(tid)
    name = (request.form.get('name') or '').strip()[:128] or ('%s copy' % src.name)
    if UiTheme.query.filter_by(name=name).first():
        flash('A theme named %r already exists.' % name, 'danger')
        return _theme_redirect()
    dup = UiTheme(slug=_theme_slug(name), name=name,
                  description=src.description, builtin=False,
                  created_by=getattr(current_user, 'username', '') or '')
    dup.tokens = src.tokens
    db.session.add(dup)
    db.session.commit()
    theme_svc.invalidate()
    log_action('settings.theme.duplicate', detail='from=%s to=%s' % (src.name, name))
    flash('Theme %r created from %r — edit it below.' % (name, src.name), 'success')
    return _theme_redirect()


@bp.route('/appearance/themes/<int:tid>/activate', methods=['POST'])
@login_required
def activate_theme(tid):
    if not _is_admin():
        abort(403)
    err = theme_svc.set_active(tid)
    if err:
        flash(err, 'danger')
    else:
        row = UiTheme.query.get(tid)
        log_action('settings.theme.activate', detail='name=%s' % row.name)
        flash('Theme %r applied.' % row.name, 'success')
    return _theme_redirect()


@bp.route('/appearance/themes/<int:tid>/delete', methods=['POST'])
@login_required
def delete_theme(tid):
    if not _is_admin():
        abort(403)
    theme = UiTheme.query.get_or_404(tid)
    if theme.builtin:
        flash('Built-in themes cannot be deleted.', 'warning')
        return _theme_redirect()
    name, was_active = theme.name, theme.is_active
    for kind in _THEME_ASSET_KINDS:
        rel = getattr(theme, kind, '')
        if rel and '/' not in rel:
            try:
                (_theme_dir() / rel).unlink()
            except OSError:
                pass
    db.session.delete(theme)
    db.session.commit()
    if was_active:
        # Deleting the active theme must not leave the console with no theme
        # at all — fall back to the immutable built-in.
        theme_svc.reset_to_builtin()
    theme_svc.invalidate()
    log_action('settings.theme.delete', detail='name=%s' % name)
    flash('Theme %r deleted.' % name, 'success')
    return _theme_redirect()


@bp.route('/appearance/themes/<int:tid>/export')
@login_required
def export_theme(tid):
    """Portable JSON — token overrides only, no ids or node state, so it can be
    imported on any install regardless of its own theme list."""
    if not _is_admin():
        abort(403)
    row = UiTheme.query.get_or_404(tid)
    resp = jsonify({'schema': 'satom.ui-theme/1', 'name': row.name,
                    'description': row.description, 'tokens': row.tokens})
    resp.headers['Content-Disposition'] = \
        'attachment; filename="satom-theme-%s.json"' % row.slug
    return resp


@bp.route('/appearance/import', methods=['POST'])
@login_required
def import_theme():
    if not _is_admin():
        abort(403)
    import json as _json
    file = request.files.get('themefile')
    if not file or not file.filename:
        flash('Choose a theme JSON file to import.', 'warning')
        return _theme_redirect()
    try:
        payload = _json.loads(file.read().decode('utf-8', 'replace'))
    except Exception:
        flash('That file is not valid JSON.', 'danger')
        return _theme_redirect()
    if not isinstance(payload, dict) or payload.get('schema') != 'satom.ui-theme/1':
        flash('Not a SATOM theme file (expected schema satom.ui-theme/1).', 'danger')
        return _theme_redirect()
    clean, errors = theme_svc.validate_tokens(payload.get('tokens') or {})
    if errors:
        for e in errors[:8]:
            flash('Import rejected — %s' % e, 'danger')
        return _theme_redirect()
    name = (str(payload.get('name') or 'Imported theme')).strip()[:128]
    if UiTheme.query.filter_by(name=name).first():
        name = '%s (imported)' % name
    row = UiTheme(slug=_theme_slug(name), name=name,
                  description=str(payload.get('description') or '')[:300],
                  builtin=False,
                  created_by=getattr(current_user, 'username', '') or '')
    row.tokens = clean
    db.session.add(row)
    db.session.commit()
    theme_svc.invalidate()
    log_action('settings.theme.import', detail='name=%s' % name)
    flash('Theme %r imported.' % name, 'success')
    return _theme_redirect()


@bp.route('/appearance/reset', methods=['POST'])
@login_required
def reset_theme():
    """Back to the shipped look. Deliberately reachable with a single POST and
    no arguments — this is what an operator uses when a palette made the console
    hard to read, and it must not itself require reading fine print."""
    if not _is_admin():
        abort(403)
    name = theme_svc.reset_to_builtin()
    log_action('settings.theme.reset', detail='name=%s' % name)
    flash('Reverted to %r.' % name, 'success')
    return _theme_redirect()


# ---------------------------------------------------------------------------
# Hypervisors — where SATOM may build appliance virtual machines.
#
# Multi-target on purpose: a site commonly runs both Proxmox and ESXi, and
# more than one of each. That is why these live in a table rather than in an
# ``app_settings`` key like the DNS provider — a single-value setting cannot
# express "build this one on the lab Proxmox and that one on the DMZ ESXi".
#
# Three rules this section enforces:
#
# 1. **Secrets never cross back to the browser.** ``public()`` is the only
#    shape sent out; an empty password field on edit means "keep what is
#    stored", never "blank it".
# 2. **Capabilities are resolved against the live endpoint, not assumed.** The
#    Test button reports what the host will actually permit, including the
#    read-only-API case, so the operator learns the limit here rather than
#    three steps into a provisioning run that already reserved an address.
# 3. **Admin only.** These credentials can create and destroy machines.
# ---------------------------------------------------------------------------

def _hv_target_or_404(target_id: int):
    from ..models_provision import HypervisorTarget
    row = HypervisorTarget.query.get(target_id)
    if row is None:
        abort(404)
    return row


@bp.route('/hypervisors/state')
@login_required
@require_permission(Permission.USER_MANAGE)
def hypervisor_state():
    from ..services import hypervisors as hv
    from ..models_provision import HypervisorTarget, MODES
    rows = HypervisorTarget.query.order_by(HypervisorTarget.name.asc()).all()
    return jsonify({
        'targets': [r.public() for r in rows],
        'backends': [{'key': k, 'label': hv.BACKEND_LABELS.get(k, k),
                      'fields': hv.FIELD_SPECS.get(k, []),
                      'default_port': hv.DEFAULT_PORTS.get(k)}
                     for k in sorted(hv.BACKENDS)],
        'modes': MODES,
    })


@bp.route('/hypervisors/save', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def hypervisor_save():
    from ..services import hypervisors as hv
    from ..models_provision import HypervisorTarget
    f = request.form
    tid = (f.get('id') or '').strip()
    backend = (f.get('backend') or '').strip().lower()
    if not hv.is_valid(backend):
        return jsonify({'ok': False,
                        'error': 'unknown backend %r' % backend}), 400
    name = (f.get('name') or '').strip()
    if not name:
        return jsonify({'ok': False, 'error': 'a name is required'}), 400
    host = (f.get('host') or '').strip()
    if not host:
        return jsonify({'ok': False, 'error': 'a host is required'}), 400

    row = HypervisorTarget.query.get(int(tid)) if tid.isdigit() else None
    creating = row is None
    # Uniqueness is checked BEFORE the row joins the session. With the add()
    # first, SQLAlchemy's autoflush pushes the pending INSERT to satisfy the
    # very query that is looking for a duplicate, so the row collides with
    # itself and every first-time save is rejected as a name clash — while
    # leaving the half-written row behind for the transaction to commit later.
    clash = HypervisorTarget.query.filter(
        HypervisorTarget.name == name,
        HypervisorTarget.id != (row.id if row is not None else -1)).first()
    if clash is not None:
        db.session.rollback()
        return jsonify({'ok': False,
                        'error': 'another target is already called %r' % name}), 400
    if creating:
        row = HypervisorTarget(name=name, backend=backend, host=host)
        db.session.add(row)

    row.name, row.backend, row.host = name, backend, host
    try:
        row.port = int(f.get('port') or 0) or hv.DEFAULT_PORTS.get(backend)
    except ValueError:
        row.port = hv.DEFAULT_PORTS.get(backend)
    row.username = (f.get('username') or '').strip()
    row.verify_ssl = (f.get('verify_ssl') or '').lower() in ('1', 'on', 'true')
    row.enabled = (f.get('enabled') or '').lower() in ('1', 'on', 'true')
    row.notes = (f.get('notes') or '').strip()
    row.default_node = (f.get('default_node') or '').strip()
    row.default_datastore = (f.get('default_datastore') or '').strip()
    row.default_network = (f.get('default_network') or '').strip()
    row.token_id = (f.get('token_id') or '').strip()
    row.ssh_user = (f.get('ssh_user') or '').strip()
    try:
        row.ssh_port = int(f.get('ssh_port') or 22)
    except ValueError:
        row.ssh_port = 22

    # An empty secret field means "leave the stored one alone". Treating blank
    # as "erase" would silently break a working target every time somebody
    # edited its name, and the operator would have no way to tell why.
    for field, setter in (('password', 'password'),
                          ('token_secret', 'token_secret'),
                          ('ssh_password', 'ssh_password')):
        val = f.get(field)
        if val:
            setattr(row, setter, val)
    db.session.commit()
    log_action('settings.hypervisor.save',
               detail='name=%s backend=%s created=%s' % (name, backend, creating))
    return jsonify({'ok': True, 'target': row.public()})


@bp.route('/hypervisors/<int:target_id>/test', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def hypervisor_test(target_id: int):
    """Authenticate, then report what this host will actually permit.

    The capability probe is the point of this button. "Connected OK" alone
    would be a comfortable lie on a free-licensed ESXi, whose API answers
    every read and refuses every write.
    """
    from datetime import datetime
    from ..services.hypervisors import HypervisorError
    row = _hv_target_or_404(target_id)
    out = {'ok': False, 'target': row.public()}
    try:
        client = row.client()
        info = client.test_connection()
        caps = client.capabilities()
        out.update({
            'ok': True,
            'info': info,
            'capabilities': {
                'create_vm': caps.create_vm, 'delete_vm': caps.delete_vm,
                'power_control': caps.power_control,
                'upload_image': caps.upload_image,
                'ovf_import': caps.ovf_import,
                'disk_import': caps.disk_import,
                'serial_console': caps.serial_console,
                'notes': list(caps.notes),
                'blocking': caps.missing_for_full_provision(),
            },
        })
        row.last_status = 'online' if caps.create_vm else 'readonly'
        row.last_error = ''
    except HypervisorError as exc:
        row.last_status = 'error'
        row.last_error = '%s %s' % (exc, exc.detail or '')
        out['error'] = str(exc)
        out['detail'] = exc.detail
    except Exception as exc:  # noqa: BLE001 — never 500 a diagnostics button
        row.last_status = 'error'
        row.last_error = str(exc)
        out['error'] = str(exc)
    row.last_checked_at = datetime.utcnow()
    db.session.commit()
    out['target'] = row.public()
    log_action('settings.hypervisor.test',
               detail='name=%s status=%s' % (row.name, row.last_status))
    return jsonify(out)


@bp.route('/hypervisors/<int:target_id>/inventory')
@login_required
@require_permission(Permission.USER_MANAGE)
def hypervisor_inventory(target_id: int):
    """Nodes / networks / datastores, for the placement dropdowns."""
    from ..services.hypervisors import HypervisorError
    row = _hv_target_or_404(target_id)
    node = (request.args.get('node') or row.default_node or '').strip()
    try:
        client = row.client()
        nodes = client.list_nodes()
        if not node and nodes:
            node = nodes[0].get('node') or ''
        stores = client.list_datastores(node)
        return jsonify({
            'ok': True, 'node': node, 'nodes': nodes,
            'networks': client.list_networks(node),
            'datastores': stores,
            # Split by role: Proxmox keeps the disk and the uploaded image on
            # DIFFERENT storages and there is no rule that one does both.
            'disk_datastores': [s for s in stores if s.get('can_disk')],
            'import_datastores': [s for s in stores if s.get('can_import')],
        })
    except HypervisorError as exc:
        return jsonify({'ok': False, 'error': str(exc),
                        'detail': exc.detail}), 502


@bp.route('/hypervisors/<int:target_id>/toggle', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def hypervisor_toggle(target_id: int):
    row = _hv_target_or_404(target_id)
    row.enabled = not row.enabled
    db.session.commit()
    log_action('settings.hypervisor.toggle',
               detail='name=%s enabled=%s' % (row.name, row.enabled))
    return jsonify({'ok': True, 'target': row.public()})


@bp.route('/hypervisors/<int:target_id>/delete', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def hypervisor_delete(target_id: int):
    """Remove a target. Refused while runs still point at it.

    A provisioning run keeps the target id as its undo handle: deleting the
    target would leave a machine SATOM built with no way to reach it again.
    """
    from ..models_provision import ProvisionRun
    row = _hv_target_or_404(target_id)
    live = ProvisionRun.query.filter(
        ProvisionRun.target_id == row.id,
        ProvisionRun.status.notin_(('done', 'aborted'))).count()
    if live:
        return jsonify({
            'ok': False,
            'error': '%d provisioning run(s) still reference this target'
                     % live,
            'detail': 'Finish or abort them first — they hold the only handle '
                      'back to the machines SATOM created here.'}), 409
    name = row.name
    db.session.delete(row)
    db.session.commit()
    log_action('settings.hypervisor.delete', detail='name=%s' % name)
    return jsonify({'ok': True})
