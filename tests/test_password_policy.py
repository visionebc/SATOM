"""The ONE password policy (Documentation Center audit, 2026-10-03: AD-06,
GS-03, TR-18): 12 to 1024 characters, length only, applied by the web forms,
the root CLI and both installer scripts."""
from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

from app.auth.password_policy import (MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH,
                                      password_problem)
from conftest import make_user

ROOT = Path(__file__).resolve().parent.parent


def test_the_policy_is_twelve_to_1024_characters_length_only():
    assert (MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH) == (12, 1024)
    assert password_problem("a" * 11)
    assert password_problem("a" * 12) == ""            # no class rule
    assert password_problem("a" * 1024) == ""
    assert password_problem("a" * 1025)
    assert password_problem("")


def _cli(app, monkeypatch, payload):
    import app as app_pkg
    from deploy.satom_cli import cmd_fix
    monkeypatch.setattr(app_pkg, "create_app", lambda *a, **k: app)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    exec(compile(cmd_fix._PW_CODE, "<cli>", "exec"), {})
    return json.loads(out.getvalue().strip().splitlines()[-1])


def test_the_cli_reset_applies_the_same_policy(app, monkeypatch):
    from app.models import User
    uid = make_user(app, "clipw")
    res = _cli(app, monkeypatch, {"user": "clipw", "password": "elevenchars"})
    assert res.get("policy") is True and "12" in res["error"]
    with app.app_context():
        assert User.query.get(uid).check_password("pw")
    res = _cli(app, monkeypatch, {"user": "clipw", "password": "twelve-chars"})
    assert res.get("ok") is True
    with app.app_context():
        assert User.query.get(uid).check_password("twelve-chars")


def test_cli_unlock_clears_the_lockout_but_keeps_a_disabled_account_disabled(app, monkeypatch):
    from datetime import datetime, timedelta
    from app.models import User, db
    uid = make_user(app, "frozen", active=False)
    with app.app_context():
        u = db.session.get(User, uid)
        u.failed_logins = 10
        u.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()
    assert _cli(app, monkeypatch, {"user": "frozen", "password": None}).get("ok")
    with app.app_context():
        u = db.session.get(User, uid)
        assert (u.failed_logins, u.locked_until) == (0, None)
        assert u.is_active is False, "unlock re-enabled a disabled account"
    # A password reset is the recovery path and does re-enable it.
    assert _cli(app, monkeypatch, {"user": "frozen", "password": "twelve-chars"}).get("ok")
    with app.app_context():
        assert db.session.get(User, uid).is_active is True


def test_both_installers_ask_for_twelve_characters_without_class_rules():
    plain = (ROOT / "installers" / "install-satom.sh").read_text()
    assert '"${#ADMIN_PASS}" -lt 12' in plain and '"${#ADMIN_PASS}" -gt 1024' in plain
    guided = (ROOT / "installers" / "satom-setup.sh").read_text()
    assert "PW_MIN=12; PW_MAX=1024" in guided
    body = guided[guided.index("password_ok() {"):]
    body = body[:body.index("\n}\n")]
    assert "[A-Z]" not in body and "[0-9]" not in body, "class rule is back"


def test_the_forms_hint_the_same_minimum():
    for rel in ("app/templates/users/_panel.html", "app/templates/auth/reset.html"):
        text = (ROOT / rel).read_text()
        assert 'minlength="12"' in text, rel
        assert not re.search(r"\b8 characters", text), rel
