"""There is no default admin password, and the old one appears nowhere.

SATOM used to seed ``admin`` with one literal password, printed by the
installer and written into the README, the user guide and the seed itself.
The same string was in use elsewhere, so every copy of the tree published a
live credential. The first admin now gets the operator's password
($SATOM_ADMIN_PASSWORD) or a random one written only to a 0600 file.

The literal is assembled at runtime from its code points so this file is not
itself an occurrence of it.
"""
from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_OLD = bytes([83, 111, 112, 97, 115, 49, 50, 51, 46, 45])
_OLD_SHA256 = "1a2a9dab4506fdf885e4577dafd89fa1f8cad1c4b77714107d6746c152016d7c"
_SKIP_DIRS = {".git", "venv", ".venv", "node_modules", "__pycache__", "wheelhouse",
              "instance", "data", ".pytest_cache"}


def _tracked_files():
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"],
                             capture_output=True, check=True).stdout
        return [ROOT / p for p in out.decode().split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        # Not a git checkout (an exported tree): every file outside the
        # runtime/dependency directories.
        found = []
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            found.extend(Path(dirpath) / f for f in filenames)
        return found


def test_the_literal_is_the_one_that_shipped():
    """The code points above must still spell the retired password, or the
    scan below would pass while looking for the wrong string."""
    assert hashlib.sha256(_OLD).hexdigest() == _OLD_SHA256


def test_the_old_default_password_appears_nowhere_in_the_tree():
    hits = []
    for path in _tracked_files():
        try:
            if _OLD in path.read_bytes():
                hits.append(str(path.relative_to(ROOT)))
        except (IsADirectoryError, FileNotFoundError, PermissionError):
            continue
    assert not hits, "the retired default admin password is back in: %s" % hits


def test_the_generated_password_file_is_never_committed():
    ignore = (ROOT / ".gitignore").read_text()
    assert "/initial-admin-password\n" in ignore


# --------------------------------------------------------------------------- #
#  the seed                                                                   #
# --------------------------------------------------------------------------- #
def _empty_users(app):
    from app.extensions import db
    from app.models import User
    User.query.delete()
    db.session.commit()


def _admin(app):
    from app.models import User
    return User.query.filter_by(username="admin").first()


def test_without_a_supplied_password_one_is_generated_into_a_0600_file(app, tmp_path, monkeypatch):
    from app import _seed_admin

    target = tmp_path / "initial-admin-password"
    monkeypatch.delenv("SATOM_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("SATOM_ADMIN_PASSWORD_FILE", str(target))
    with app.app_context():
        _empty_users(app)
        assert _seed_admin() == str(target)
        pw = target.read_text().strip()
        assert len(pw) >= 20
        assert pw.encode() != _OLD
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        admin = _admin(app)
        assert admin is not None and admin.role == "admin"
        assert admin.check_password(pw)
        assert not admin.check_password(_OLD.decode())
    assert not [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")], \
        "the temp file was left behind"


def test_two_fresh_installs_do_not_share_a_password(app, tmp_path, monkeypatch):
    from app import _seed_admin

    monkeypatch.delenv("SATOM_ADMIN_PASSWORD", raising=False)
    seen = []
    with app.app_context():
        for n in (1, 2):
            target = tmp_path / ("pw%d" % n)
            monkeypatch.setenv("SATOM_ADMIN_PASSWORD_FILE", str(target))
            _empty_users(app)
            _seed_admin()
            seen.append(target.read_text())
    assert seen[0] != seen[1]


def test_a_supplied_password_is_used_and_no_file_is_written(app, tmp_path, monkeypatch):
    from app import _seed_admin

    target = tmp_path / "initial-admin-password"
    monkeypatch.setenv("SATOM_ADMIN_PASSWORD", "operator-chosen-1")
    monkeypatch.setenv("SATOM_ADMIN_PASSWORD_FILE", str(target))
    with app.app_context():
        _empty_users(app)
        assert _seed_admin() is None
        assert _admin(app).check_password("operator-chosen-1")
    assert not target.exists()


def test_an_existing_admin_is_never_touched(app, tmp_path, monkeypatch):
    from app import _seed_admin

    target = tmp_path / "initial-admin-password"
    monkeypatch.delenv("SATOM_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("SATOM_ADMIN_PASSWORD_FILE", str(target))
    with app.app_context():
        before = _admin(app).password_hash
        assert _seed_admin() is None
        assert _admin(app).password_hash == before
    assert not target.exists()


def test_no_admin_is_created_when_the_password_cannot_be_stored(app, tmp_path, monkeypatch):
    """An admin whose generated password nobody can read is a locked door."""
    from app import _seed_admin

    monkeypatch.delenv("SATOM_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("SATOM_ADMIN_PASSWORD_FILE",
                       str(tmp_path / "missing-dir" / "initial-admin-password"))
    with app.app_context():
        _empty_users(app)
        assert _seed_admin() is None
        assert _admin(app) is None


def test_create_db_prints_the_file_path_never_the_password(app, tmp_path, monkeypatch):
    """`flask create-db` is what the installers run to seed."""
    target = tmp_path / "initial-admin-password"
    monkeypatch.delenv("SATOM_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("SATOM_ADMIN_PASSWORD_FILE", str(target))
    with app.app_context():
        _empty_users(app)
    result = app.test_cli_runner().invoke(args=["create-db"])
    assert result.exit_code == 0, result.output
    assert str(target) in result.output
    assert target.read_text().strip() not in result.output
    with app.app_context():
        assert _admin(app).check_password(target.read_text().strip())


# --------------------------------------------------------------------------- #
#  the installers                                                             #
# --------------------------------------------------------------------------- #
def test_install_sh_seeds_before_start_and_locks_the_file_to_root():
    text = (ROOT / "scripts" / "install.sh").read_text()
    seed = text.index('SATOM_ADMIN_PASSWORD="$ADMIN_PASSWORD" SATOM_ADMIN_PASSWORD_FILE="$ADMIN_PW_FILE"')
    assert "venv/bin/flask create-db" in text[seed:seed + 200]
    assert seed < text.index('systemctl restart "$SERVICE"'), \
        "the service would seed first, with no file path and no root-only lock"
    assert 'chown root:root "$ADMIN_PW_FILE"' in text
    assert 'chmod 600 "$ADMIN_PW_FILE"' in text
    assert '--admin-password=*)' in text
    assert 'initial password in $ADMIN_PW_FILE' in text


def test_install_satom_sh_seeds_with_the_operators_password():
    text = (ROOT / "installers" / "install-satom.sh").read_text()
    assert 'SATOM_ADMIN_PASSWORD="$ADMIN_PASS" FLASK_APP=wsgi.py venv/bin/flask create-db' in text
