"""Tests for the configurable email/SMTP service.

Two layers:
  * MOCKED smtplib — asserts the exact SMTP conversation (SSL vs STARTTLS vs
    plain, login when auth is on, send_message) for every mode/security/auth
    combination, deterministically and offline.
  * A REAL loopback send through a stdlib ``smtpd`` sink on 127.0.0.1 — proves
    the wire actually works end-to-end (mode=local, security=none, no auth).
"""
from __future__ import annotations

import asyncore  # noqa: F401  (imported by smtpd on 3.11)
import smtpd
import threading
from unittest import mock

import pytest

from app.services import email_service as es


# --------------------------------------------------------------------------- #
#  Config persistence                                                          #
# --------------------------------------------------------------------------- #
def test_local_mode_forces_simple_defaults(app):
    with app.app_context():
        es.save_config({"enabled": "on", "mode": "local", "from_addr": "ops@example.com"})
        cfg = es.config()
        assert cfg["mode"] == "local"
        assert cfg["host"] == "localhost"
        assert cfg["security"] == "none"
        assert cfg["auth"] is False
        assert cfg["enabled"] is True
        assert cfg["from_addr"] == "ops@example.com"


def test_password_encrypted_and_never_revealed(app):
    with app.app_context():
        es.save_config({
            "enabled": "on", "mode": "smtp", "host": "smtp.example.com",
            "security": "starttls", "auth": "on", "username": "u",
            "password": "s3cret", "from_addr": "ops@example.com",
        })
        from app.models import AppSetting
        token = AppSetting.get(es.K_PASSWORD_ENC)
        assert token and token != "s3cret"          # stored encrypted
        assert "password" not in es.config()         # template never sees it
        assert es.config()["has_password"] is True
        assert es.config(reveal_password=True)["password"] == "s3cret"


def test_blank_password_keeps_existing(app):
    with app.app_context():
        es.save_config({"enabled": "on", "mode": "smtp", "host": "h",
                        "security": "ssl", "auth": "on", "username": "u",
                        "password": "keepme", "from_addr": "a@b.com"})
        # Re-save with a blank password field → must keep the stored secret.
        es.save_config({"enabled": "on", "mode": "smtp", "host": "h",
                        "security": "ssl", "auth": "on", "username": "u",
                        "password": "", "from_addr": "a@b.com"})
        assert es.config(reveal_password=True)["password"] == "keepme"


def test_default_port_per_security(app):
    with app.app_context():
        for security, port in (("none", 25), ("starttls", 587), ("ssl", 465)):
            es.save_config({"enabled": "on", "mode": "smtp", "host": "h",
                            "security": security, "from_addr": "a@b.com"})
            assert es.config()["port"] == port


def test_parse_recipients():
    assert es.parse_recipients("a@x.com, b@y.com\nc@z.com;d@w.com") == [
        "a@x.com", "b@y.com", "c@z.com", "d@w.com"]
    assert es.parse_recipients("Ops <ops@x.com>") == ["ops@x.com"]
    assert es.parse_recipients("") == []


# --------------------------------------------------------------------------- #
#  Send paths (mocked smtplib)                                                  #
# --------------------------------------------------------------------------- #
def _cfg(**over):
    base = {"mode": "smtp", "host": "smtp.example.com", "port": 587,
            "security": "starttls", "tls_verify": True, "auth": True,
            "username": "user", "password": "pw", "from_addr": "ops@example.com",
            "from_name": "Ops", "default_to": "", "timeout": 10}
    base.update(over)
    return base


def test_send_starttls_with_auth():
    with mock.patch("smtplib.SMTP") as SMTP:
        server = SMTP.return_value
        res = es.send_email("to@example.com", "subj", "body", cfg=_cfg())
    assert res["ok"] is True
    server.starttls.assert_called_once()
    server.login.assert_called_once_with("user", "pw")
    server.send_message.assert_called_once()


def test_send_ssl_uses_smtp_ssl_no_starttls():
    with mock.patch("smtplib.SMTP_SSL") as SMTP_SSL, mock.patch("smtplib.SMTP") as SMTP:
        server = SMTP_SSL.return_value
        res = es.send_email("to@example.com", "subj", "body",
                            cfg=_cfg(security="ssl", port=465))
    assert res["ok"] is True
    SMTP_SSL.assert_called_once()
    SMTP.assert_not_called()
    server.starttls.assert_not_called()
    server.send_message.assert_called_once()


def test_send_plain_no_tls_no_auth():
    with mock.patch("smtplib.SMTP") as SMTP:
        server = SMTP.return_value
        res = es.send_email("to@example.com", "subj", "body",
                            cfg=_cfg(security="none", auth=False, port=25))
    assert res["ok"] is True
    server.starttls.assert_not_called()
    server.login.assert_not_called()
    server.send_message.assert_called_once()


def test_send_failure_is_caught_not_raised():
    with mock.patch("smtplib.SMTP", side_effect=OSError("connection refused")):
        res = es.send_email("to@example.com", "s", "b", cfg=_cfg(security="none"))
    assert res["ok"] is False
    assert "connection refused" in res["detail"]


def test_send_requires_recipient():
    res = es.send_email("", "s", "b", cfg=_cfg(default_to=""))
    assert res["ok"] is False


# --------------------------------------------------------------------------- #
#  Real loopback send through a stdlib SMTP sink                                #
# --------------------------------------------------------------------------- #
class _Sink(smtpd.SMTPServer):
    captured: list = []

    def process_message(self, peer, mailfrom, rcpttos, data, **kw):  # noqa: D401
        _Sink.captured.append((mailfrom, rcpttos, data))
        return None


def test_real_loopback_send():
    import asyncore as _asyncore
    _Sink.captured = []
    server = _Sink(("127.0.0.1", 0), None)
    port = server.socket.getsockname()[1]
    t = threading.Thread(target=lambda: _asyncore.loop(timeout=1, count=20), daemon=True)
    t.start()
    try:
        res = es.send_email(
            "client@example.com", "Maintenance window", "Service notice body.",
            cfg=_cfg(mode="local", host="127.0.0.1", port=port,
                     security="none", auth=False))
    finally:
        server.close()
        t.join(timeout=3)
    assert res["ok"] is True, res["detail"]
    assert _Sink.captured, "sink received no message"
    mailfrom, rcpttos, data = _Sink.captured[0]
    assert "client@example.com" in rcpttos
    assert b"Maintenance window" in data
    assert b"Service notice body." in data


# --------------------------------------------------------------------------- #
#  Settings page renders with the Email tab (Jinja validity)                    #
# --------------------------------------------------------------------------- #
def test_settings_page_renders_email_tab(app, client):
    from tests.conftest import login, admin_user_id
    login(client, admin_user_id(app))
    resp = client.get("/settings/", follow_redirects=True)
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert 'id="tab-email"' in html
    assert 'Email (SMTP) Configuration' in html
    assert 'url_for' not in html  # template fully rendered, no raw Jinja
