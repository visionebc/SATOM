"""Pytest fixtures: build the Flask app against a throwaway SQLite DB.

A fresh temp DB + Fernet key are created per test session so tests never touch
the live ``data/fortinet.db`` and never depend on the production FERNET_KEY.
"""
from __future__ import annotations

import os
import tempfile

import pytest

# --- environment MUST be set before the app package is imported -------------
_TMPDIR = tempfile.mkdtemp(prefix="fmw-test-")
os.environ["FLASK_ENV"] = "development"
os.environ["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{_TMPDIR}/test.db"
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-prod")
# A valid Fernet key so models.py encryption helpers import cleanly.
from cryptography.fernet import Fernet  # noqa: E402
os.environ.setdefault("FERNET_KEY", Fernet.generate_key().decode())


class _TestConfig:
    TESTING = True
    DEBUG = False
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = os.environ["SQLALCHEMY_DATABASE_URI"]
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ["SECRET_KEY"]
    FERNET_KEY = os.environ["FERNET_KEY"]
    SESSION_COOKIE_SECURE = False
    RATELIMIT_ENABLED = False


@pytest.fixture()
def app(tmp_path):
    # A UNIQUE DB file per test → full isolation (no state leaks across tests).
    uri = f"sqlite:///{tmp_path}/test.db"
    os.environ["SQLALCHEMY_DATABASE_URI"] = uri

    class _Cfg(_TestConfig):
        SQLALCHEMY_DATABASE_URI = uri

    from app import create_app
    from app.extensions import db

    application = create_app(_Cfg)
    application.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    yield application

    # tear the engine down so the next test's fresh file binds cleanly
    with application.app_context():
        db.session.remove()
        db.engine.dispose()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def session(app):
    """A live DB session bound to the app context."""
    from app.extensions import db

    with app.app_context():
        yield db.session


def login(client, user_id, product="fortiweb"):
    """Log a user in for the test client (bypasses the login form)."""
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True
        if product:
            sess["product"] = product


def profile_id(app, name):
    from app.models import Profile
    with app.app_context():
        return Profile.query.filter_by(name=name).first().id


def admin_user_id(app):
    from app.models import User
    with app.app_context():
        return User.query.filter_by(username="admin").first().id


def make_user(app, username="bob", role="readonly", profile_id=None, active=True):
    """Create + persist a user; returns its id (detached-safe)."""
    from app.extensions import db
    from app.models import User

    with app.app_context():
        u = User(username=username, role=role, is_active=active)
        if profile_id is not None:
            u.profile_id = profile_id
        u.set_password("pw")
        db.session.add(u)
        db.session.commit()
        return u.id
