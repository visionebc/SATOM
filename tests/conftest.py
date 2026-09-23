"""Pytest fixtures: build the Flask app against a throwaway SQLite DB.

A fresh temp DB + Fernet key are created per test session so tests never touch
the live ``data/fortinet.db`` and never depend on the production FERNET_KEY.
"""
from __future__ import annotations

import atexit
import os
import shutil
import tempfile

import pytest

# --- environment MUST be set before the app package is imported -------------
_TMPDIR = tempfile.mkdtemp(prefix="fmw-test-")


@atexit.register
def _remove_tmpdir() -> None:
    """Delete this process's temp root when the interpreter exits.

    Nothing used to do this. On 2026-08-17 the node carried 2837 orphaned
    ``/tmp/fmw-test-*`` directories left behind by a week of runs — an inode
    leak rather than a byte leak, but one that grows without bound, and that
    sharding the suite multiplies by the shard count.

    Registered here at IMPORT time rather than from a session fixture on
    purpose: the directory is created at import time, so a collection error
    that aborts before any fixture ever runs would still leak it.

    ``ignore_errors=True`` is also deliberate — a failed cleanup must never
    turn a green run red. The leak is the bug being fixed; a suite that fails
    while tidying up would be a new one.
    """
    shutil.rmtree(_TMPDIR, ignore_errors=True)

os.environ["FLASK_ENV"] = "development"
os.environ["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{_TMPDIR}/test.db"
# Isolate services that keep state on disk from the production tree (the logs
# status endpoint reads a _progress.json that real runs leave behind).
os.environ["FORTINET_DIAG_DIR"] = f"{_TMPDIR}/diagnostics"
# The job ledger too: without this the suite writes REAL job files into
# data/jobs/ that no worker ever finishes, and the toast dock replays them on
# every page load of the live app. Running the tests must not create UI noise.
os.environ["SATOM_JOBS_DIR"] = f"{_TMPDIR}/jobs"
# Same isolation for the versioned SoT store and the reports tree: every
# device sync now records a version, so an un-isolated suite would grow REAL
# blobs under data/sot/ on the production node (the jobs-ledger lesson).
os.environ["SATOM_SOT_DIR"] = f"{_TMPDIR}/sot"
# The system-bundle store and the per-appliance vault were the LAST two
# un-isolated on-disk stores, and they stopped being merely write-only on
# 2026-08-30: local bundle eviction DELETES from data/system_backups. An
# un-isolated suite could destroy production bundles, not just litter.
os.environ["SATOM_BACKUPS_DIR"] = f"{_TMPDIR}/system_backups"
os.environ["SATOM_VAULT_DIR"] = f"{_TMPDIR}/vault"
# The TLS trust bundle is a FILE the client layer feeds to OpenSSL.
# Without this redirect a test run rewrites the live installation's
# pki/trust bundle — the same contamination pytest caused in the job
# ledger on 2026-07-28.
os.environ["SATOM_TRUST_DIR"] = f"{_TMPDIR}/trust"
# The LAST two un-isolated stores, and the pair that caused measured damage on
# 2026-09-15: tests/test_rediscovery_* drive real sweeps against the TEST
# database while writing progress + _config.json into the PRODUCTION tree, and
# api_matrix rebuilds itself FROM that tree at the end of every sweep. The live
# data/api_matrix/fortiweb.json went from 326 swept endpoints and three
# witnesses to `swept: 0, devices: []`. Both files are untracked, so git
# reported nothing, and an empty matrix renders as a page with NO DIFFERENCES
# rather than as an error -- the failure mode that makes this worse than a
# crash.
os.environ["SATOM_REDISCOVERY_DIR"] = f"{_TMPDIR}/rediscovery"
os.environ["SATOM_API_MATRIX_DIR"] = f"{_TMPDIR}/api_matrix"
os.environ.setdefault("FORTINET_REPORTS_DIR", f"{_TMPDIR}/reports")
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


@pytest.fixture(autouse=True)
def _no_leaked_flask_context():
    """Fail the test that leaves a Flask app/request context pushed.

    pytest runs every test in ONE thread and ONE contextvars context, so a
    ``ctx.push()`` without its ``pop()`` does not end with the test: every
    later test in the run executes inside it. Release run 28 (2026-09-22)
    failed that way -- ``test_cert_share_freshness._wire`` pushed and never
    popped, and ``test_probe_thread_context`` (which asserts there is NO
    context) went red dozens of files later. Run on its own, each passed.

    Two jobs, in this order:
      1. pop whatever this test left above the stack it started with, so the
         NEXT test runs clean -- one leak must not become a cascade;
      2. fail THIS test, naming what leaked, so the red lands on the culprit
         instead of on an innocent test far away in collection order.

    Compared by identity against the stack at setup, so a context pushed by a
    wider-scoped fixture (and popped by it) is never reported.
    """
    from flask import globals as fg

    app_before = fg._cv_app.get(None)
    req_before = fg._cv_request.get(None)
    yield
    leaked = []
    for cv, before, kind in ((fg._cv_request, req_before, "request"),
                             (fg._cv_app, app_before, "app")):
        for _ in range(64):  # bounded: a pop() that raises must not spin
            top = cv.get(None)
            if top is None or top is before:
                break
            leaked.append(kind)
            try:
                top.pop()
            except Exception:  # noqa: BLE001 -- restore, then still fail
                cv.set(before)
                break
    if leaked:
        pytest.fail(
            "test left %d Flask context(s) pushed (%s); every later test in "
            "the run would execute inside them. Use `with app.app_context():` "
            "or pop what you push." % (len(leaked), ", ".join(leaked)),
            pytrace=False,
        )


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
