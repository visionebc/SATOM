"""Authentication routes: sign-in (local + external directory), 2FA challenge,
sign-out, password recovery, and the per-user profile page.

Sign-in resolution (see ``services.auth_store`` / ``directory_auth``):

1. A **local** account proves its password against the DB. Local accounts never
   fall through to a directory (protects the seed admin from an AD same-name).
2. Otherwise — a brand-new username, or an existing **external** row — the
   configured directory backend (AD / LDAP / RADIUS) is asked to bind. On
   success the local row is just-in-time provisioned (operator profile).
3. Local accounts with **TOTP** enabled get a second-factor challenge before the
   session is established (directory accounts do MFA at the directory).
"""
from datetime import datetime

from flask import (render_template, redirect, url_for, flash, request, session,
                   current_app)
from flask_login import login_user, logout_user, login_required, current_user

from . import bp
from ..models import User, Permission
from ..extensions import db, limiter
from ..services.audit import log_action
from ..services import settings_store as store
from ..services import user_settings_store as user_store
from ..services import auth_store, twofa, email_service


# ---------------------------------------------------------------------------
# Sign-in
# ---------------------------------------------------------------------------
def _post_login(user: User, remember: bool):
    """Establish the session + stamp last_login + audit."""
    login_user(user, remember=remember)
    user.last_login = datetime.utcnow()
    db.session.commit()
    log_action('login', target=user.username,
               extra={'source': user.auth_source or 'local'})


def _safe_next() -> str:
    nxt = request.args.get('next') or request.form.get('next')
    if nxt and nxt.startswith('/') and not nxt.startswith('//'):
        return nxt
    return url_for('workspace.index')


@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit('5 per minute')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('workspace.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') in ('1', 'on', 'true')

        user = User.query.filter_by(username=username).first()

        if user and not user.is_active:
            flash('This account is disabled.', 'danger')
            return render_template('auth/login.html')

        authed = False
        # 1) Local account → local password only (never fall through to directory).
        if user and user.is_local:
            if user.check_password(password):
                authed = True
        # 2) New username OR existing external row → directory bind.
        elif auth_store.is_enabled():
            result = auth_store.authenticate_external(username, password)
            if result.get('ok'):
                user = auth_store.provision_external_user(username, result.get('source', 'ldap'))
                if user and not user.is_active:
                    flash('This account is disabled.', 'danger')
                    return render_template('auth/login.html')
                authed = bool(user)
            else:
                log_action('login.external_fail', target=username,
                           extra={'detail': result.get('detail', '')})

        if not authed:
            flash('Invalid username or password.', 'danger')
            return render_template('auth/login.html')

        # 3) Second factor for local accounts that enabled it.
        if user.is_local and user.totp_enabled:
            session['pending_2fa_user'] = user.id
            session['pending_2fa_remember'] = remember
            session['pending_2fa_next'] = _safe_next()
            return redirect(url_for('auth.two_factor'))

        _post_login(user, remember)
        return redirect(_safe_next())

    return render_template('auth/login.html')


@bp.route('/2fa', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def two_factor():
    uid = session.get('pending_2fa_user')
    if not uid:
        return redirect(url_for('auth.login'))
    user = db.session.get(User, uid)
    if user is None or not user.is_active or not user.totp_enabled:
        session.pop('pending_2fa_user', None)
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = (request.form.get('code', '') or '').strip()
        secret = twofa.decrypt_secret(user.totp_secret or '')
        ok = twofa.verify_totp(secret, code)
        used_backup = False
        if not ok and code:
            # Try a one-time backup code.
            consumed, new_store = twofa.consume_backup_code(user.backup_codes, code)
            if consumed:
                user.backup_codes = new_store
                db.session.commit()
                ok = True
                used_backup = True
        if ok:
            remember = bool(session.pop('pending_2fa_remember', False))
            nxt = session.pop('pending_2fa_next', None)
            session.pop('pending_2fa_user', None)
            _post_login(user, remember)
            log_action('login.2fa', target=user.username,
                       extra={'method': 'backup_code' if used_backup else 'totp'})
            if used_backup:
                flash('Backup code accepted. '
                      f'{twofa.remaining_backup_codes(user.backup_codes)} backup code(s) left.',
                      'warning')
            return redirect(nxt or url_for('workspace.index'))
        flash('Invalid authentication code.', 'danger')
        return redirect(url_for('auth.two_factor'))

    return render_template('auth/two_factor.html')


@bp.route('/logout')
@login_required
def logout():
    log_action('logout', target=current_user.username)
    logout_user()
    return redirect(url_for('auth.login'))


# ---------------------------------------------------------------------------
# Password recovery (local accounts only)
# ---------------------------------------------------------------------------
@bp.route('/forgot', methods=['GET', 'POST'])
@limiter.limit('5 per 15 minutes')
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('workspace.index'))

    sent_msg = ('If that account exists and has a recovery email on file, a '
                'password-reset link has been sent.')
    if request.method == 'POST':
        username = (request.form.get('username', '') or '').strip()
        user = User.query.filter_by(username=username).first()
        # Only local accounts with a recovery email can self-reset. Directory
        # accounts reset their password at the directory.
        if user and user.is_active and user.is_local and user.recovery_email:
            token = twofa.make_reset_token(user.id)
            link = url_for('auth.reset_password', token=token, _external=True)
            body = (f"Hello {user.username},\n\n"
                    f"A password reset was requested for your Fortinet Manager account.\n"
                    f"Open this link to choose a new password (valid for 1 hour):\n\n"
                    f"{link}\n\n"
                    f"If you did not request this, you can ignore this email.\n")
            if email_service.is_configured():
                email_service.send_email(user.recovery_email,
                                         "Fortinet Manager — password reset", body)
            log_action('password_reset.request', target=user.username)
        else:
            # Don't reveal whether the account/recovery email exists.
            log_action('password_reset.request_unknown', target=username)
        flash(sent_msg, 'info')
        return redirect(url_for('auth.login'))

    return render_template('auth/forgot.html',
                           email_configured=email_service.is_configured())


@bp.route('/reset/<token>', methods=['GET', 'POST'])
@limiter.limit('10 per 15 minutes')
def reset_password(token):
    uid = twofa.read_reset_token(token)
    user = db.session.get(User, uid) if uid else None
    if user is None or not user.is_active or not user.is_local:
        flash('This password-reset link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')
        if not new_password or len(new_password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
        elif new_password != confirm:
            flash('Passwords do not match.', 'danger')
        else:
            user.set_password(new_password)
            db.session.commit()
            log_action('password_reset.complete', target=user.username)
            flash('Your password has been reset. Please sign in.', 'success')
            return redirect(url_for('auth.login'))
        return render_template('auth/reset.html', token=token)

    return render_template('auth/reset.html', token=token)


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------
@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
        elif len(new_password) < 8:
            flash('New password must be at least 8 characters.', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
        else:
            current_user.set_password(new_password)
            db.session.commit()
            log_action('password_change', target=current_user.username)
            flash('Password updated successfully.', 'success')
            return redirect(url_for('auth.profile'))

    is_admin = bool(current_user and current_user.can(Permission.USER_MANAGE))
    return render_template(
        'auth/profile.html',
        is_admin=is_admin,
        settings=store.general(),
        banner_templates=store.BANNER_TEMPLATES,
        banners=user_store.all_banners(current_user.id),
    )
