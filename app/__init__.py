"""Flask application factory."""
from __future__ import annotations

import ipaddress
import os
from datetime import datetime

from flask import Flask, g, request

from .config import get_config
from .extensions import csrf, db, limiter, login_manager, migrate


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
    migrate.init_app(app, db)
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
            from .services import device_context
            if device_context.current_appliance() is not None:
                return redirect(url_for('workspace.index'))
            return redirect(url_for('architecture.index'))
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

    # -- device-first gate: per-device pages need a selected device ------
    @app.before_request
    def _device_gate():
        from flask import session, redirect, url_for
        from flask_login import current_user
        if not current_user.is_authenticated:
            return None
        if session.get('product') != 'fortiweb':
            return None
        ep = request.endpoint or ''
        bp_name = ep.split('.', 1)[0]
        device_bps = {'workspace', 'server_objects', 'web_protection',
                      'exceptions', 'backups'}
        if bp_name not in device_bps:
            return None
        from .services import device_context
        va = request.view_args or {}
        did = va.get('appliance_id', va.get('id'))
        if did is not None:
            try:
                device_context.set_current(did)
            except Exception:
                pass
            return None
        if device_context.current_appliance() is None:
            return redirect(url_for('architecture.index'))
        return None

    # -- template globals -------------------------------------------------
    @app.context_processor
    def _inject_branding():
        from flask import session
        from flask_login import current_user
        from .branding import get_product
        from .services import settings_store as _store
        from .services import user_settings_store as _ustore
        prod = get_product(session.get('product'))
        try:
            # Per-user banner (DB-backed) for a logged-in user; global/default
            # otherwise. No cookie is involved.
            if getattr(current_user, 'is_authenticated', False):
                _bg = _ustore.banner_bg(current_user.id, prod['key'])
            else:
                _bg = _store.banner_bg(prod['key'])
        except Exception:
            _bg = '#162940'
        # FortiWeb config sections for the sidebar (live browsers only). Sourced
        # from the catalog so it stays in sync; server_objects (own page) and the
        # read-only Monitor have no menu → excluded.
        try:
            from .services import config_catalog as _cc
            from .services import config_sections as _cs
            # These 5 WAF protection areas were promoted to the top-level
            # WAF group in the sidebar, so exclude them here to avoid showing
            # them twice (WAF group + admin Configuration submenu).
            _promoted = {'application_delivery', 'api_protection',
                         'bot_mitigation', 'dos_protection', 'ip_protection'}
            _cfg_nav = [
                {'key': s.key, 'label': s.label, 'emoji': s.emoji}
                for s in _cc.CONFIG_SECTIONS
                if _cs.has_menu(s.key) and s.key not in _promoted
            ]
        except Exception:
            _cfg_nav = []
        try:
            from .services import device_context as _dc
            _cur_appl = _dc.current_appliance()
        except Exception:
            _cur_appl = None
        try:
            from flask_login import current_user as _cu
            from .models import Template as _Tpl
            if getattr(_cu, 'is_authenticated', False) and _cu.can('user_manage'):
                _pending = _Tpl.query.filter_by(status=_Tpl.STATUS_PENDING).count()
            else:
                _pending = 0
        except Exception:
            _pending = 0
        # --- bug-report counts for the top-bar bell ---
        _open_reports = 0
        _my_resolved = 0
        _bug_notify = False
        try:
            from flask_login import current_user as _cu2
            if getattr(_cu2, "is_authenticated", False):
                from .services import bug_reports as _br
                if _cu2.can("user_manage"):
                    _bug_notify = _br.is_opted_in(_cu2.id)
                    if _bug_notify:
                        _open_reports = _br.open_count()
                _my_resolved = _br.unseen_resolved_count(_cu2.id)
        except Exception:
            _open_reports = 0
            _my_resolved = 0
            _bug_notify = False
        return {
            'product': prod,
            'current_appliance': _cur_appl,
            'banner_bg': _bg,
            'now': datetime.utcnow(),
            'config_sections_nav': _cfg_nav,
            'pending_template_count': _pending,
            'open_report_count': _open_reports,
            'bug_reports_notify': _bug_notify,
            'my_resolved_unseen_count': _my_resolved,
        }

    # -- timezone-aware timestamp filter ---------------------------------
    @app.template_filter('localtime')
    def _localtime(dt, fmt='%Y-%m-%d %H:%M:%S'):
        if not dt:
            return '—'
        try:
            from datetime import timezone as _utc
            from zoneinfo import ZoneInfo
            from .services import settings_store as _store
            tzname = _store.general().get('timezone') or 'UTC'
            aware = dt.replace(tzinfo=_utc.utc) if dt.tzinfo is None else dt
            return aware.astimezone(ZoneInfo(tzname)).strftime(fmt)
        except Exception:
            try:
                return dt.strftime(fmt)
            except Exception:
                return str(dt)

    # -- self-healing CSRF errors ----------------------------------------
    # A stale/expired login (or any) form submitted with an old token used to
    # dead-end on a raw 400 "CSRF tokens do not match". Instead, flash a hint
    # and bounce back to the same form page, which re-renders a fresh token so
    # the resubmit succeeds. (2026-06-27)
    from flask_wtf.csrf import CSRFError

    @app.errorhandler(CSRFError)
    def _handle_csrf_error(exc):  # noqa: ANN001
        from flask import flash, redirect, request, url_for, jsonify
        # JSON/XHR callers (the editor save/inject fetch calls) must get a JSON
        # error, not a 302 redirect they can't parse (which silently aborts the
        # save). Browsers carry the token via the global fetch wrapper; this is
        # the defense-in-depth so a miss surfaces loudly. (2026-06-28)
        wants_json = (request.is_json
                      or "application/json" in (request.headers.get("Accept") or "")
                      or request.headers.get("X-Requested-With") == "XMLHttpRequest")
        if wants_json:
            return jsonify(ok=False, error="CSRF token missing or expired \u2014 reload the page and retry"), 400
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

    # -- centralised logging + global error handlers ---------------------
    from .errors import (configure_logging, register_error_handlers,
                         register_selftest_routes)
    configure_logging(app)
    register_error_handlers(app)
    register_selftest_routes(app)

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

    def _ensure_columns():
        """Idempotently add columns introduced after a table already existed.

        ``db.create_all()`` never ALTERs existing tables, so a new column on a
        pre-existing table (e.g. ``templates.exceptions``) must be added here.
        Safe on every boot — a column that is already present is a no-op.
        """
        from sqlalchemy import inspect, text
        adds = {
            'templates': [
                ('exceptions', 'TEXT'),
                ('status', "VARCHAR(16) DEFAULT 'pending'"),
                ('reject_reason', 'TEXT'),
                ('reviewed_by', 'VARCHAR(64)'),
                ('reviewed_at', 'DATETIME'),
            ],
            'users': [
                ('profile_id', 'INTEGER'),
                ('auth_source', "VARCHAR(16) DEFAULT 'local'"),
                ('totp_secret', 'VARCHAR(512)'),
                ('totp_enabled', 'BOOLEAN DEFAULT FALSE'),
                ('recovery_email', 'VARCHAR(256)'),
                ('backup_codes', 'TEXT'),
            ],
            'appliances': [
                ('hw_type', "VARCHAR(16) DEFAULT 'unknown'"),
                ('model', 'VARCHAR(128)'),
                ('datasheet_filename', 'VARCHAR(256)'),
            ],
        }
        insp = inspect(db.engine)
        added: set[tuple[str, str]] = set()
        for table, cols in adds.items():
            try:
                if not insp.has_table(table):
                    continue
                existing = {c['name'] for c in insp.get_columns(table)}
                for col, ddl in cols:
                    if col not in existing:
                        db.session.execute(text(f'ALTER TABLE {table} ADD COLUMN {col} {ddl}'))
                        db.session.commit()
                        added.add((table, col))
            except Exception:  # noqa: BLE001 — never block boot on a migration
                db.session.rollback()

        # When the approval column is first introduced, existing templates
        # predate the workflow (admin-authored) -> treat them as APPROVED so the
        # fleet keeps working; new saves still default to 'pending'.
        if ('users', 'auth_source') in added:
            try:
                db.session.execute(text(
                    "UPDATE users SET auth_source='local' "
                    "WHERE auth_source IS NULL OR auth_source=''"))
                db.session.commit()
            except Exception:  # noqa: BLE001
                db.session.rollback()

        if ('templates', 'status') in added:
            try:
                db.session.execute(text(
                    "UPDATE templates SET status='approved' "
                    "WHERE status IS NULL OR status='' OR status='pending'"))
                db.session.commit()
            except Exception:  # noqa: BLE001
                db.session.rollback()

    # -- database & seed --------------------------------------------------
    # Skippable so Alembic migration commands (and CI that manages its own
    # schema) can import the app without create_all racing the migration.
    if not os.environ.get("FORTINET_SKIP_DB_BOOTSTRAP"):
        with app.app_context():
            db.create_all()
            _ensure_columns()
            _seed_profiles()
            _seed_admin()
            _assign_missing_profiles()

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
        ("app.views.firmware", "bp"),
        ("app.views.release_notes", "bp"),
        ("app.views.workspace", "bp"),
        ("app.views.objedit", "bp"),
        ("app.views.server_objects", "bp"),
        ("app.views.web_protection", "bp"),
        ("app.views.exceptions", "bp"),
        ("app.views.architecture", "bp"),
        ("app.views.analysis", "bp"),
        ("app.views.backups", "bp"),
        ("app.views.logs", "bp"),
        ("app.views.search", "bp"),
        ("app.views.users", "bp"),
        ("app.views.profiles", "bp"),
        ("app.views.metrics", "bp"),
        ("app.views.audit", "bp"),
        ("app.views.registry", "bp"),
        ("app.views.api_explorer", "bp"),
        ("app.views.templates", "bp"),
        ("app.views.signatures", "bp"),
        ("app.views.fleet_objects", "bp"),
        ("app.views.import_backup", "bp"),
        ("app.views.structure", "bp"),
        ("app.views.classification", "bp"),
        ("app.views.segments", "bp"),
        ("app.views.naming", "bp"),
        ("app.views.scheduled_actions", "bp"),
        ("app.views.cert_manager", "bp"),
        ("app.views.change_requests", "bp"),
        ("app.views.provisioning", "bp"),
        ("app.views.section_config", "bp"),
        ("app.views.section_catalog", "bp"),
        ("app.views.settings", "bp"),
        ("app.views.reports", "bp"),
        ("app.views.locks", "bp"),
        ("app.views.database", "bp"),
        ("app.views.system_backup", "bp"),
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


def _seed_profiles() -> None:
    """Upsert the three system profiles. Their permission sets are re-synced
    from code on every boot so adding a new granular key automatically extends
    the admin (and, where applicable, operator/readonly) system profiles."""
    from . import permissions as perm
    from .models import Profile

    try:
        for name, keys in perm.SYSTEM_PROFILES.items():
            p = Profile.query.filter_by(name=name).first()
            if p is None:
                p = Profile(name=name, is_system=True)
                db.session.add(p)
            p.is_system = True
            p.description = perm.SYSTEM_PROFILE_META.get(name, "")
            p.permission_set = set(keys)
        db.session.commit()
    except Exception:  # noqa: BLE001 — never block boot on seeding
        db.session.rollback()


def _assign_missing_profiles() -> None:
    """Give every user that still has no profile the system profile matching
    their legacy ``role`` (one-time migration; new users get a profile at
    creation time)."""
    from . import permissions as perm
    from .models import Profile, User

    try:
        by_name = {p.name: p for p in Profile.query.filter_by(is_system=True).all()}
        changed = False
        for u in User.query.filter(User.profile_id.is_(None)).all():
            target = by_name.get(perm.role_to_profile_name(u.role))
            if target is not None:
                u.profile_id = target.id
                changed = True
        if changed:
            db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()


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
