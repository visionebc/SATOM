"""Flask application factory."""
from __future__ import annotations

import os
from datetime import datetime

from flask import Flask, g, request

from .config import get_config
from .extensions import csrf, db, limiter, login_manager


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
