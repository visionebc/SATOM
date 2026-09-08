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
from datetime import datetime, timedelta

from flask import (render_template, redirect, url_for, flash, request, session,
                   current_app)
from flask_login import login_user, logout_user, login_required, current_user

from . import bp
from ..models import User, Permission
from ..extensions import db, limiter, real_client_ip
from ..services.audit import log_action
from ..services import settings_store as store
from ..services import user_settings_store as user_store
from ..branding import PRODUCTS as _BRAND_PRODUCTS
from ..services import auth_store, twofa, email_service

# Per-account lockout policy (complements the per-IP rate limit).
LOCKOUT_THRESHOLD = 10
LOCKOUT_WINDOW = timedelta(minutes=15)


# ---------------------------------------------------------------------------
# Sign-in
# ---------------------------------------------------------------------------
def _commit_quiet():
    """Best-effort commit — on the read-only HA standby the write is skipped."""
    try:
        db.session.commit()
    except Exception:  # noqa: BLE001 — replica is read-only; login still proceeds
        db.session.rollback()


def _post_login(user: User, remember: bool):
    """Establish the session + stamp last_login + audit."""
    login_user(user, remember=remember)
    user.last_login = datetime.utcnow()
    _commit_quiet()
    log_action('login', target=user.username,
               extra={'source': user.auth_source or 'local'})


#: Endpoints a post-login redirect must never land on. ``logout`` gets here on
#: its own: hitting /auth/logout when the session is already gone bounces
#: through ``@login_required`` to /auth/login?next=/auth/logout, so honouring
#: ``next`` would sign the user out the instant they signed in - an infinite
#: door. Blocked by RESOLVED PATH, not by substring: a path that merely
#: contains "logout" may be a perfectly good page.
_NEXT_DENY_ENDPOINTS = ('auth.logout',)


def _inactive_message(user) -> str:
    if user.is_pending_approval:
        return ('Your account was imported from the directory but is still '
                'awaiting administrator approval.')
    return 'This account is disabled.'


def _safe_next() -> str:
    nxt = request.args.get('next') or request.form.get('next')
    if nxt and nxt.startswith('/') and not nxt.startswith('//'):
        denied = {url_for(ep) for ep in _NEXT_DENY_ENDPOINTS}
        if nxt.split('?', 1)[0].rstrip('/') not in {d.rstrip('/') for d in denied}:
            return nxt
    return url_for('index')


@bp.route('/login', methods=['GET', 'POST'])
# POST ONLY. Counting GETs rate-limited the *login page itself*: five renders a
# minute - a logout redirect, a couple of reloads, a failed attempt - and the
# user was locked out of the FORM, having guessed no password at all. Brute
# force is POST; the credential guard belongs on the verb that carries a
# credential. Per-account lockout below covers the distributed case.
@limiter.limit('5 per minute', methods=['POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') in ('1', 'on', 'true')

        user = User.query.filter_by(username=username).first()

        if user and not user.is_active:
            flash(_inactive_message(user), 'warning' if user.is_pending_approval else 'danger')
            return render_template('auth/login.html')

        # Per-account lockout: after LOCKOUT_THRESHOLD consecutive failures the
        # account rejects logins for LOCKOUT_MINUTES, regardless of source IP —
        # the IP rate-limit can't stop a distributed guess against one account.
        now = datetime.utcnow()
        if user and user.locked_until and user.locked_until > now:
            current_app.logger.warning(
                'SECURITY: LOCKED account login attempt user=%s ip=%s',
                username, real_client_ip())
            log_action('login.locked_attempt', target=username)
            flash('Too many failed attempts — account temporarily locked. '
                  'Try again later.', 'danger')
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
                    # The bind SUCCEEDED - this is an authorisation stop, so it
                    # is logged as such and never as a credential failure.
                    log_action('login.pending_approval' if user.is_pending_approval
                               else 'login.disabled', target=username)
                    flash(_inactive_message(user),
                          'warning' if user.is_pending_approval else 'danger')
                    return render_template('auth/login.html')
                authed = bool(user)
            else:
                log_action('login.external_fail', target=username,
                           extra={'detail': result.get('detail', '')})

        if not authed:
            if user is not None:
                user.failed_logins = (user.failed_logins or 0) + 1
                if user.failed_logins >= LOCKOUT_THRESHOLD:
                    user.locked_until = now + LOCKOUT_WINDOW
                    user.failed_logins = 0
                    current_app.logger.warning(
                        'SECURITY: account LOCKED user=%s ip=%s (%d failures)',
                        username, real_client_ip(), LOCKOUT_THRESHOLD)
                    log_action('login.lockout', target=username)
                _commit_quiet()
            flash('Invalid username or password.', 'danger')
            return render_template('auth/login.html')

        # Success clears any accumulated failure state.
        if user.failed_logins or user.locked_until:
            user.failed_logins = 0
            user.locked_until = None
            _commit_quiet()

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
            return redirect(nxt or url_for('index'))
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
        return redirect(url_for('index'))

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
                    f"A password reset was requested for your SATOM account.\n"
                    f"Open this link to choose a new password (valid for 1 hour):\n\n"
                    f"{link}\n\n"
                    f"If you did not request this, you can ignore this email.\n")
            if email_service.is_configured():
                email_service.send_email(user.recovery_email,
                                         "SATOM — password reset", body)
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

    from ..services import cr_document, lang_policy, langs as lang_registry
    from ..services import bookmarks as bookmarks_svc
    is_admin = bool(current_user and current_user.can(Permission.USER_MANAGE))
    _pref = user_store.language(current_user.id)
    return render_template(
        'auth/profile.html',
        is_admin=is_admin,
        pref_lang=_pref,
        bookmark_dims=bookmarks_svc.DIMENSIONS,
        bookmark_lens=bookmarks_svc.lens_for(current_user),
        bookmark_lens_title=bookmarks_svc.lens_title(
            bookmarks_svc.lens_for(current_user)),
        # What this INSTALL offers, not what the product speaks: an
        # administrator can withdraw a language in Settings, and a picker that
        # ignored that would keep offering a choice the chrome then refuses to
        # honour.
        lang_options=lang_policy.offered(),
        # A saved preference the install has since withdrawn. Reported instead
        # of quietly dropped: the option stays in the list, still selected, so
        # the user sees the answer they gave and learns why the page is not in
        # it -- and so pressing Save does not silently clear it.
        pref_withdrawn=bool(_pref and not lang_policy.is_offered(_pref)),
        pref_lang_label=(lang_registry.label(_pref) if _pref else ''),
        # Which languages a whole change document can actually be produced in.
        # Offered next to the picker rather than left implicit: a preference
        # the product cannot honour yet must SAY so on the page where it is
        # set, not fail to appear later on a form the operator is mid-way
        # through.
        doc_langs=[code for code, _label in cr_document.document_langs()],
        settings=store.general(),
        banner_templates=store.BANNER_TEMPLATES,
        banners=user_store.all_banners(current_user.id),
        banner_products=[(k, _BRAND_PRODUCTS[k]['name'])
                         for k in store.BANNER_PRODUCTS],
    )


@bp.route('/profile/language', methods=['POST'])
@login_required
def save_language():
    """Store (or clear) the signed-in user's language preference.

    Deliberately NOT part of the profile POST above: that handler validates the
    current password and flashes "Current password is incorrect" when it is
    absent. Saving a language through it would demand a password to change a
    display preference -- or, worse, tempt the next editor to relax the
    password check for everyone.
    """
    from ..services import lang_policy

    submitted = (request.form.get('lang') or '').strip()
    # A language this install does not offer is refused rather than stored.
    # The picker already omits it, so reaching here means a stale form or a
    # replayed post -- and storing it would create exactly the state the gate
    # exists to prevent: a preference the chrome will never honour, with
    # nothing on the page saying why.
    if submitted and not lang_policy.is_offered(submitted):
        flash('That language is not offered on this installation.', 'warning')
        return redirect(url_for('auth.profile') + '#language')
    code = user_store.save_language(current_user.id, submitted)
    log_action('profile.language', target=(code or 'none'))
    flash('Language preference saved.' if code else
          'Language preference cleared \u2014 you will be asked each time.',
          'success')
    return redirect(url_for('auth.profile') + '#language')


@bp.route('/profile/calendar', methods=['POST'])
@login_required
def save_calendar_pref():
    """Switch the Calendar page and its nav entry on or off, for this user only.

    Separate from the profile POST for the same reason as the language and
    bookmark forms: that handler validates the current password, so routing a
    display preference through it would demand a password to hide a menu entry.

    AN UNCHECKED CHECKBOX SENDS NOTHING. The value is therefore read as
    "present == on", never as a string compared against 'on'/'1'/'true' -- a
    comparison would make the OFF direction unreachable from a real browser,
    which is the half of this switch the user actually asked for.

    THIS HIDES A VIEW. It does not disable anything: the changes on that grid
    are Change Requests and Scheduled Actions, and they keep being approved and
    keep firing on their windows whether or not this user draws them. The page
    and the flash both say so, because "disable the calendar" is a sentence an
    operator can reasonably read as "stop the scheduled work".
    """
    on = 'calendar_on' in request.form
    now = user_store.save_calendar_enabled(current_user.id, on)
    log_action('profile.calendar', target=('on' if now else 'off'))
    flash('Calendar switched on for your account.' if now else
          'Calendar hidden from your account. Scheduled changes and automations '
          'are unaffected \u2014 they still run on their windows.',
          'success')
    return redirect(url_for('auth.profile') + '#calendar')


@bp.route('/profile/bookmark-view', methods=['POST'])
@login_required
def save_bookmark_view():
    """Store this user's bookmarks grouping order.

    Separate from the profile POST for the same reason as the language form:
    that handler validates the current password and flashes "Current password
    is incorrect" when it is absent, so routing a display preference through it
    would either demand a password to re-order a sidebar or tempt the next
    editor to weaken the password check for everybody.

    The submitted order is validated by the service, never trusted: an
    unchecked value would leave :func:`services.bookmarks.lens_for` — which is
    deliberately forgiving, because it runs on every page — as the only thing
    between a typo and a tree the operator cannot explain.
    """
    from ..services import bookmarks as bookmarks_svc

    try:
        stack = bookmarks_svc.save_lens(current_user, request.form.getlist('dim'))
    except bookmarks_svc.BookmarkDenied as exc:
        # The reason reaches the operator. A bare "invalid" at 03:00 is what
        # sends people looking for a way around a rule instead of a way to
        # satisfy it.
        flash(str(exc), 'warning')
        return redirect(url_for('auth.profile') + '#bookmark-view')
    log_action('profile.bookmark_view', target=','.join(stack))
    flash('Bookmark grouping order saved.', 'success')
    return redirect(url_for('auth.profile') + '#bookmark-view')
