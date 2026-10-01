"""Alembic must reach head on a database the INSTALLER built.

The installer creates the schema with ``flask create-db`` (``db.create_all()``)
and, before 2.5.0, never recorded an Alembic revision. The first update then
ran ``flask db upgrade`` from the very first revision, whose unguarded
``op.create_table('app_settings', ...)`` died on a table that already existed.
The update runner logged that step as "best-effort" and carried on, so every
installed node finished its update green with no ``alembic_version`` at all —
and any later migration that transforms data would have been skipped in
silence on exactly the nodes customers run.

These tests drive the real commands in a subprocess (the same ``flask`` entry
points the installer and the runner call), against a fresh SQLite file:

* ``create-db`` then ``db upgrade`` — the path every installed node takes on
  its first package update. Every migration must be idempotent
  (``app.migration_guard``) for this to reach head.
* ``create-db`` then ``db stamp head`` — what the installer now does.
* ``db upgrade`` twice — the second run must be a no-op.

A subprocess, not ``flask_migrate.upgrade()`` in-process: ``migrations/env.py``
calls ``logging.config.fileConfig``, which disables every logger that already
exists and would break unrelated tests later in the same session.
"""
from __future__ import annotations

import os
import pathlib
import sqlite3
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _head() -> str:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    heads = ScriptDirectory.from_config(cfg).get_heads()
    assert len(heads) == 1, "the migration graph must have exactly one head: %s" % heads
    return heads[0]


def _flask(db: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["SQLALCHEMY_DATABASE_URI"] = "sqlite:///%s" % db
    env["FLASK_APP"] = "wsgi.py"
    env.pop("FORTINET_SKIP_DB_BOOTSTRAP", None)
    return subprocess.run([sys.executable, "-m", "flask", *args], cwd=str(ROOT),
                          env=env, capture_output=True, text=True, timeout=300)


def _version(db: pathlib.Path):
    con = sqlite3.connect(str(db))
    try:
        rows = con.execute("SELECT version_num FROM alembic_version").fetchall()
    except sqlite3.OperationalError:
        return None
    finally:
        con.close()
    return [r[0] for r in rows]


def _ok(proc: subprocess.CompletedProcess, what: str) -> None:
    assert proc.returncode == 0, "%s failed (rc=%s):\n%s" % (
        what, proc.returncode, (proc.stderr or proc.stdout)[-3000:])


@pytest.fixture()
def installed_db(tmp_path):
    """A database exactly as the installer leaves it: create-db, no revision."""
    db = tmp_path / "installed.db"
    _ok(_flask(db, "create-db"), "flask create-db")
    assert _version(db) is None, (
        "create-db wrote an alembic revision itself; this test models the "
        "installer path and must be revisited")
    return db


def test_upgrade_reaches_head_on_an_installed_database(installed_db):
    proc = _flask(installed_db, "db", "upgrade")
    _ok(proc, "flask db upgrade on a create_all database")
    assert _version(installed_db) == [_head()]


def test_a_second_upgrade_is_a_no_op(installed_db):
    _ok(_flask(installed_db, "db", "upgrade"), "first upgrade")
    _ok(_flask(installed_db, "db", "upgrade"), "second upgrade")
    assert _version(installed_db) == [_head()]


def test_stamp_head_records_the_revision(installed_db):
    _ok(_flask(installed_db, "db", "stamp", "head"), "flask db stamp head")
    assert _version(installed_db) == [_head()]


def test_installer_stamps_after_create_db():
    """The installer records the revision right after building the schema —
    otherwise every fresh install starts life in the unstamped state above."""
    text = (ROOT / "installers" / "install-satom.sh").read_text()
    create = text.find("flask create-db")
    assert create != -1, "the installer no longer runs create-db; revisit this guard"
    stamp = text.find("venv/bin/flask db stamp head >>", create)
    assert stamp != -1, "install-satom.sh must run 'flask db stamp head' after create-db"


def test_every_upgrade_goes_through_the_guard():
    """Static backstop for the behavioural tests: a new migration that calls
    op.create_table / add_column / create_index / create_foreign_key directly
    in upgrade() must at least check for the object first."""
    offenders = []
    for path in sorted((ROOT / "migrations" / "versions").glob("*.py")):
        src = path.read_text()
        body = src.split("def upgrade():", 1)[-1].split("\ndef downgrade():", 1)[0]
        direct = any(("op.%s(" % fn) in body.replace("batch_op.", "")
                     for fn in ("create_table", "add_column", "create_index",
                                "create_foreign_key"))
        checks = ("guard." in body or "inspect(" in body or "has_table" in body
                  or "get_columns" in body or "IF NOT EXISTS" in body)
        if direct and not checks:
            offenders.append(path.name)
    assert not offenders, (
        "migrations whose upgrade() creates schema without checking it exists "
        "(use app.migration_guard): %s" % ", ".join(offenders))


def test_the_runner_treats_a_failed_migration_as_fatal():
    """Both update paths (git and package) must abort -- and so roll back --
    when ``flask db upgrade`` fails. Logging it as best-effort is how every
    installed node finished its updates green with nothing migrated."""
    src = (ROOT / "deploy" / "self_update_runner.py").read_text()
    assert "db upgrade (best-effort)" not in src
    calls = src.count('"db", "upgrade"]')
    assert calls == 2, "expected the git and the package path, found %d" % calls
    assert src.count("raise RuntimeError(MIGRATION_FAILED)") == calls, (
        "every `flask db upgrade` in the runner must raise on failure")
    assert "restore db" in src.split("MIGRATION_FAILED = (", 1)[1].split('")\n', 1)[0], (
        "the failure message must tell the operator how to restore the database")


def test_the_container_migrates_the_primary_before_serving():
    text = (ROOT / "deploy" / "docker" / "entrypoint.sh").read_text()
    web = text.split("    web)\n", 1)[1].split(";;", 1)[0]
    assert web.index("migrate_primary") < web.index("exec gunicorn")
    body = text.split("migrate_primary() {", 1)[1].split("\n}\n", 1)[0]
    assert "flask db upgrade" in body and "exit 70" in body
