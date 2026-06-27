"""Flask application factory."""
from __future__ import annotations

import ipaddress
import os
from datetime import datetime

from flask import Flask, g, request

from .config import get_config
from .extensions import csrf, db, limiter, login_manager


def _client_ip() -> str:
    """Real client IP — honour the first X-Forwarded-For hop (we sit behind the
    fleet reverse proxy), else the direct peer."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def _ip_allowed(ip: str, whitelist: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback:
        return True  # never lock out local/curl access
    for row in whitelist:
        try:
            if addr in ipaddress.ip_network((row or {}).get("ip", ""), strict=False):
                return True
        except ValueError:
            continue
    return False


def create_app(config_override: object | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=False)

    # -- configuration ----------------------------------------------------
    app.config.from_object(get_config())
    if config_override is not None:
        app.config.from_object(config_override)

    # propagate FERNET_KEY into environment so models.py can pick it up
    if app.config.get("FERNET_KEY"):
        os.environ.setdefault("FERNET_KEY", app.config["FERNET_KEY"])

    # -- extensions -------------------------------------------------------
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id: str):
        from .models import User
        return User.query.get(int(user_id))

    # -- blueprints -------------------------------------------------------
    _register_blueprints(app)

    @app.route('/')
    def index():
        from flask import redirect, url_for, session
        from flask_login import current_user
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        product = session.get('product')
        if product == 'fortiadc':
            return redirect(url_for('product.fortiadc_home'))
        if product == 'fortiweb':
            return redirect(url_for('workspace.index'))
        return redirect(url_for('product.select'))

    # -- product selection gate ------------------------------------------
    @app.before_request
    def _product_gate():
        from flask import session, redirect, url_for
        from flask_login import current_user
        if not current_user.is_authenticated:
            return None
        ep = request.endpoint or ''
        always = {
            'static', 'index',
            'product.select', 'product.set_product', 'product.switch',
            'product.fortiadc_home',
        }
        if ep in always or ep.startswith('auth.'):
            return None
        product = session.get('product')
        if product not in ('fortiweb', 'fortiadc'):
            return redirect(url_for('product.select'))
        if product == 'fortiadc':
            # FortiADC is a placeholder — restrict to its own + shared pages
            adc_allowed = {'product.fortiadc_home', 'settings.index'}
            if ep not in adc_allowed:
                return redirect(url_for('product.fortiadc_home'))
        return None

    # -- access control gate (IP whitelist + allowed users) --------------
    # Lockout-safe by design: empty lists = no restriction, loopback always
    # allowed, admins are NEVER restricted (so a typo can't lock out the people
    # who manage this), and auth/static endpoints stay reachable.
    @app.before_request
    def _access_gate():
        from flask import abort
        from flask_login import current_user
        if not current_user.is_authenticated:
            return None
        ep = request.endpoint or ''
        if ep == 'static' or ep.startswith('auth.'):
            return None
        from .models import Permission
        if current_user.can(Permission.USER_MANAGE):
            return None  # admins are exempt
        from .services import settings_store as _store
        allowed = _store.allowed_users()
        if allowed and current_user.username not in allowed:
            abort(403)
        wl = _store.ip_whitelist()
        if wl and not _ip_allowed(_client_ip(), wl):
            abort(403)
        return None

    # -- template globals -------------------------------------------------
    @app.context_processor
    def _inject_branding():
        from flask import session
        from .branding import get_product
        from .services import settings_store as _store
        prod = get_product(session.get('product'))
        try:
            _bg = _store.banner_bg(prod['key'])
        except Exception:
            _bg = '#162940'
        return {
            'product': prod,
            'banner_bg': _bg,
            'now': datetime.utcnow(),
        }

    # -- self-healing CSRF errors ----------------------------------------
    # A stale/expired login (or any) form submitted with an old token used to
    # dead-end on a raw 400 "CSRF tokens do not match". Instead, flash a hint
    # and bounce back to the same form page, which re-renders a fresh token so
    # the resubmit succeeds. (2026-06-27)
    from flask_wtf.csrf import CSRFError

    @app.errorhandler(CSRFError)
    def _handle_csrf_error(exc):  # noqa: ANN001
        from flask import flash, redirect, request, url_for
        flash("Your session expired or the form was stale \u2014 please try again.", "warning")
        ref = request.referrer or ""
        if ref.startswith(request.host_url):
            return redirect(ref)
        return redirect(url_for("auth.login"))

    # -- security headers -------------------------------------------------
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' data: https://cdn.jsdelivr.net;"
        )
        # Never serve authenticated HTML (e.g. the nav menu) from a stale
        # browser cache after a deploy. Static assets stay cacheable.
        if response.mimetype == "text/html":
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    # -- CLI commands -----------------------------------------------------
    @app.cli.command('create-db')
    def create_db_cmd():
        """Initialise database tables and seed the default admin user."""
        db.create_all()
        from .models import User
        if User.query.count() == 0:
            admin = User(username='admin', role='admin', is_active=True)
            admin.set_password('Sopas123.-')
            db.session.add(admin)
            db.session.commit()
            print('Admin user created: admin / Sopas123.-')
        else:
            print('Database already contains users — skipping seed.')

    # -- database & seed --------------------------------------------------
    with app.app_context():
        db.create_all()
        _seed_admin()

    return app


def _register_blueprints(app: Flask) -> None:
    """Import and register all blueprints. Missing blueprint modules are
    skipped with a warning so the core app still starts during scaffolding."""
    import importlib
    import logging

    logger = logging.getLogger(__name__)

    blueprints = [
        ("app.auth", "bp"),
        ("app.views.product", "bp"),
        ("app.views.appliances", "bp"),
        ("app.views.workspace", "bp"),
        ("app.views.server_objects", "bp"),
        ("app.views.web_protection", "bp"),
        ("app.views.exceptions", "bp"),
        ("app.views.architecture", "bp"),
        ("app.views.analysis", "bp"),
        ("app.views.backups", "bp"),
        ("app.views.logs", "bp"),
        ("app.views.search", "bp"),
        ("app.views.users", "bp"),
        ("app.views.audit", "bp"),
        ("app.views.registry", "bp"),
        ("app.views.api_explorer", "bp"),
        ("app.views.templates", "bp"),
        ("app.views.settings", "bp"),
        ("app.api", "bp"),
    ]

    for module_path, attr in blueprints:
        try:
            module = importlib.import_module(module_path)
            bp = getattr(module, attr)
            app.register_blueprint(bp)
        except ModuleNotFoundError:
            logger.debug("Blueprint module %r not found — skipping.", module_path)
        except AttributeError:
            logger.warning(
                "Blueprint attribute %r not found in %r — skipping.",
                attr,
                module_path,
            )


def _seed_admin() -> None:
    """Create a default admin user if the users table is empty."""
    from .models import Role, User
    from sqlalchemy.exc import IntegrityError

    if User.query.first() is not None:
        return

    admin = User(
        username="admin",
        role=Role.admin.value,
        created_at=datetime.utcnow(),
        is_active=True,
    )
    admin.set_password("Sopas123.-")
    db.session.add(admin)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return  # Another worker seeded first — that's fine
