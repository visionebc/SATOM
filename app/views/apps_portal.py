"""/a/ -- the portal of Apps-only accounts and every app's own sign-in page.

* ``/a/``                 My apps (an Apps-only account's home).
* ``/a/<slug>/``          The app's front door: the app when this session may
                          use it, its sign-in page otherwise.
* ``/a/<slug>/login``     The app's sign-in (services.app_signin), styled as
                          the app. Same hardening as /auth/login: POST rate
                          limit, per-account lockout checked BEFORE any
                          directory sees the password, the same generic
                          failure for every miss, the account's status only
                          after the credential is proven.
* ``/a/<slug>/2fa``       The SATOM authenticator code, when the account has
                          one or the rule that accepted it requires one
                          (``/2fa/enrol`` the first time).
* ``/a/account``          Own password (local accounts) and authenticator.

Reachable by Apps-only accounts (services.apps_only allows this blueprint);
every page that serves an app checks the app (``studio_apps.can_use``).
"""
from __future__ import annotations

import time
from datetime import datetime

from flask import (Blueprint, abort, current_app, flash, redirect, render_template,
                   request, session, url_for)
from flask_login import current_user, login_required, logout_user

from ..extensions import db, limiter, real_client_ip
from ..services import app_signin as AS
from ..services import studio_apps as SA
from ..services import twofa
from ..services.audit import log_action

bp = Blueprint("apps_portal", __name__, url_prefix="/a")

PENDING_KEY = "app_signin_pending"
PENDING_TTL = 300  # seconds, like the console's 2FA step


def _app_or_404(slug):
    a = SA.get(slug)
    if a is None:
        abort(404)
    return a


def _app_url(a) -> str:
    if a.kind == "script":
        return url_for("scripts.run_page", slug=a.script_slug)
    return url_for("apps.page", slug=a.slug)


def _design(a) -> str:
    """The app's look (Plugin Studio > Design) for its sign-in pages: the CSS
    custom properties of its theme (accent, surface, text...); the published
    design when there is one. "" = SATOM's standard look."""
    from ..services import studio_design as D
    try:
        d = D.clean((a.published or {}).get("design") or a.design or {})
        return D.theme_css(d.get("theme") or {})
    except Exception:  # noqa: BLE001 -- a design the vocabulary no longer takes
        return ""


# --------------------------------------------------------------------------- #
#  home                                                                        #
# --------------------------------------------------------------------------- #
@bp.route("/")
@login_required
def home():
    if not getattr(current_user, "is_apps_only", False):
        # A console user's apps are in the console (Plugins).
        return redirect(url_for("scripts.index") if current_user.can("operations.scripts_run")
                        else url_for("index"))
    return render_template("apps_portal/home.html", apps=SA.portal_apps(current_user))


@bp.route("/<slug>/")
def entry(slug):
    a = _app_or_404(slug)
    if current_user.is_authenticated and SA.can_use(current_user, a):
        return redirect(_app_url(a))
    if AS.is_open(a):
        return redirect(url_for("apps_portal.login", slug=slug))
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login", next=_app_url(a)))
    abort(404)


# --------------------------------------------------------------------------- #
#  sign-in                                                                     #
# --------------------------------------------------------------------------- #
def _render_login(a, status=200):
    return render_template("apps_portal/login.html", a=a, theme=_design(a)), status


def _fail(a, username, reason, tried=None):
    log_action("login.app.fail", target=(username or "")[:128],
               extra={"app": a.slug, "reason": reason, "tried": (tried or [])[:10]})
    flash("Invalid username or password.", "danger")
    return _render_login(a)


@bp.route("/<slug>/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login(slug):
    from ..auth import routes as R
    a = _app_or_404(slug)
    if not AS.is_open(a):
        abort(404)
    if current_user.is_authenticated and SA.can_use(current_user, a):
        return redirect(_app_url(a))
    if request.method == "GET":
        return _render_login(a)

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    now = datetime.utcnow()
    candidates = AS.candidate_accounts(a, username)
    if any(u.locked_until and u.locked_until > now for u in candidates):
        current_app.logger.warning("SECURITY: LOCKED account app sign-in user=%s app=%s ip=%s",
                                   username, slug, real_client_ip())
        log_action("login.locked_attempt", target=username, extra={"app": slug})
        flash("Too many failed attempts — account temporarily locked. Try again later.",
              "danger")
        return _render_login(a)

    res = AS.sign_in(a, username, password)
    if not res.ok:
        for u in res.accounts:
            R._record_failure(u, u.username, now)
        if not res.accounts:
            R._spend_dummy_password_check(password)
        if res.message:  # e.g. a new account on the read-only standby
            log_action("login.app.fail", target=username[:128],
                       extra={"app": slug, "reason": res.reason, "tried": res.tried[:10]})
            flash(res.message, "warning")
            return _render_login(a)
        return _fail(a, username, res.reason, res.tried)

    user = res.user
    if not user.is_active:
        log_action("login.pending_approval" if user.is_pending_approval else "login.disabled",
                   target=user.username, extra={"app": slug})
        flash(R._inactive_message(user), "warning" if user.is_pending_approval else "danger")
        return _render_login(a)
    if not user.is_app_account and not SA.can_use(user, a):
        # A local account proven by the password that the app is not given to.
        return _fail(a, username, "not in the app's access list", res.tried)

    session.pop(PENDING_KEY, None)
    pending = {"uid": user.id, "app": a.id, "at": int(time.time()),
               "conn": getattr(res.connection, "id", None),
               "need_2fa": bool((res.rule or {}).get("require_2fa"))}
    if user.totp_enabled:
        session[PENDING_KEY] = pending
        return redirect(url_for("apps_portal.two_factor", slug=slug))
    if pending["need_2fa"]:
        session[PENDING_KEY] = pending
        return redirect(url_for("apps_portal.enrol", slug=slug))
    return _finish(a, user, pending, "password")


def _finish(a, user, pending, method):
    from ..auth import routes as R
    session.pop(PENDING_KEY, None)
    R._clear_failures(user)
    R._post_login(user, False)
    AS.complete(a, user, pending.get("conn"))
    log_action("login.app.ok", target=user.username,
               extra={"app": a.slug, "connection": pending.get("conn") or "local",
                      "method": method})
    return redirect(_app_url(a))


def _pending_for(a):
    """(user, pending) of a password-proven sign-in waiting on its second
    factor for THIS app, or (None, None) -- expired, another app, gone."""
    from ..models import User
    p = session.get(PENDING_KEY)
    if not isinstance(p, dict) or p.get("app") != a.id:
        return None, None
    started = p.get("at")
    if not isinstance(started, (int, float)) or not 0 <= time.time() - started <= PENDING_TTL:
        session.pop(PENDING_KEY, None)
        flash("The sign-in attempt expired. Please sign in again.", "warning")
        return None, None
    user = db.session.get(User, p.get("uid"))
    if user is None or not user.is_active:
        session.pop(PENDING_KEY, None)
        return None, None
    return user, p


@bp.route("/<slug>/2fa", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def two_factor(slug):
    from ..auth import routes as R
    a = _app_or_404(slug)
    user, p = _pending_for(a)
    if user is None or not user.totp_enabled:
        return redirect(url_for("apps_portal.login", slug=slug))
    now = datetime.utcnow()
    if user.locked_until and user.locked_until > now:
        session.pop(PENDING_KEY, None)
        flash("Too many failed attempts — account temporarily locked. Try again later.",
              "danger")
        return redirect(url_for("apps_portal.login", slug=slug))
    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        secret = twofa.decrypt_secret(user.totp_secret or "")
        step = twofa.verify_totp_step(secret, code, last_step=user.totp_last_step)
        if step is not None:
            user.totp_last_step = step
            return _finish(a, user, p, "totp")
        consumed, new_store = twofa.consume_backup_code(user.backup_codes, code) if code else (False, None)
        if consumed:
            user.backup_codes = new_store
            db.session.commit()
            flash("Backup code accepted. %d backup code(s) left."
                  % twofa.remaining_backup_codes(user.backup_codes), "warning")
            return _finish(a, user, p, "backup_code")
        log_action("login.2fa_fail", target=user.username, extra={"app": slug})
        if R._record_failure(user, user.username, now):
            session.pop(PENDING_KEY, None)
            flash("Too many failed attempts — account temporarily locked. Try again later.",
                  "danger")
            return redirect(url_for("apps_portal.login", slug=slug))
        flash("Invalid authentication code.", "danger")
        return redirect(url_for("apps_portal.two_factor", slug=slug))
    return render_template("apps_portal/two_factor.html", a=a, theme=_design(a))


@bp.route("/<slug>/2fa/enrol", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def enrol(slug):
    """First sign-in through a rule that requires a second factor, for an
    account that has none yet: it sets up the SATOM authenticator before any
    session exists. The pending secret is kept Fernet-encrypted."""
    a = _app_or_404(slug)
    user, p = _pending_for(a)
    if user is None or user.totp_enabled or not p.get("need_2fa"):
        return redirect(url_for("apps_portal.login", slug=slug))
    enc = p.get("enrol_secret")
    if not enc:
        enc = twofa.encrypt_secret(twofa.generate_secret())
        p["enrol_secret"] = enc
        session[PENDING_KEY] = p
    secret = twofa.decrypt_secret(enc)
    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        if not secret or not twofa.verify_totp(secret, code):
            flash("Invalid code. Scan the QR again and enter the current code.", "danger")
            return redirect(url_for("apps_portal.enrol", slug=slug))
        codes = twofa.generate_backup_codes()
        user.totp_secret = twofa.encrypt_secret(secret)
        user.totp_enabled = True
        user.backup_codes = twofa.encode_codes(codes)
        try:
            db.session.commit()
        except Exception:  # noqa: BLE001 -- the read-only standby
            db.session.rollback()
            flash("Setting up the authenticator needs the primary node.", "warning")
            return redirect(url_for("apps_portal.login", slug=slug))
        log_action("login.app.2fa_enrol", target=user.username, extra={"app": slug})
        session["app_backup_codes_once"] = codes
        return _finish(a, user, p, "totp_enrol")
    uri = twofa.provisioning_uri(secret, user.username)
    return render_template("apps_portal/enrol.html", a=a, theme=_design(a),
                           qr=twofa.qr_svg(uri), secret=secret)


# --------------------------------------------------------------------------- #
#  account                                                                     #
# --------------------------------------------------------------------------- #
@bp.route("/account")
@login_required
def account():
    return render_template("apps_portal/account.html",
                           backup_codes_once=session.pop("app_backup_codes_once", None),
                           remaining=twofa.remaining_backup_codes(current_user.backup_codes))


@bp.route("/account/password", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def account_password():
    from ..auth.password_policy import password_problem
    if not current_user.is_local:
        flash("This account's password is kept by its directory.", "warning")
        return redirect(url_for("apps_portal.account"))
    cur = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    if not current_user.check_password(cur):
        flash("Current password is incorrect.", "danger")
    elif password_problem(new):
        flash(password_problem(new), "danger")
    elif new != request.form.get("confirm_password", ""):
        flash("New passwords do not match.", "danger")
    else:
        current_user.set_password(new)
        db.session.commit()
        log_action("settings.change_password", detail="Changed own password (apps portal)")
        flash("Password changed.", "success")
    return redirect(url_for("apps_portal.account"))


@bp.route("/logout")
def logout():
    """Out, and back to the sign-in page of the last app signed in to (an app
    account has no use for the console's form)."""
    from ..models_studio import StudioApp
    target = url_for("auth.login")
    last_id = AS.last_proven_app_id()
    last = db.session.get(StudioApp, last_id) if last_id else None
    if last is not None and AS.is_open(last):
        target = url_for("apps_portal.login", slug=last.slug)
    if current_user.is_authenticated:
        log_action("logout", target=current_user.username)
        logout_user()
    AS.forget_proofs()
    session.pop(PENDING_KEY, None)
    return redirect(target)


def login_redirect_for(next_path: str):
    """The app sign-in page for a console-login redirect whose ``next`` is an
    app with its own sign-in (an idle lock, an expired session on an app page),
    else None. Used by /auth/login so an app's people never land on a console
    form their account cannot use."""
    if not next_path or not isinstance(next_path, str):
        return None
    path = next_path.split("?", 1)[0]
    slug = None
    if path.startswith("/apps/"):
        rest = path[len("/apps/"):].split("/")
        if rest and rest[0] and rest[0] != "runs":
            slug = rest[0]
    elif path.startswith("/a/"):
        rest = path[len("/a/"):].split("/")
        slug = rest[0] if rest and rest[0] not in ("", "account", "logout") else None
    elif path.startswith("/automation/scripts/"):
        rest = path[len("/automation/scripts/"):].split("/")
        a = SA.script_app(rest[0]) if rest and rest[0] else None
        slug = a.slug if a is not None else None
    if not slug:
        return None
    a = SA.get(slug)
    if a is None or not AS.is_open(a):
        return None
    return url_for("apps_portal.login", slug=a.slug)
