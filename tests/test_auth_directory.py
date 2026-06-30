"""Tests for the directory-auth + 2FA feature (Phase 1 & 2).

Covers the pure logic (TOTP, backup codes, secret round-trip, reset tokens),
the auth_store config persistence + dispatcher, JIT provisioning, and the login
flow integration (external bind, 2FA challenge gate, password recovery).
"""
from __future__ import annotations

import pyotp
import pytest

from tests.conftest import admin_user_id, login, make_user


# ---------------------------------------------------------------------------
# twofa — pure logic
# ---------------------------------------------------------------------------
def test_totp_roundtrip():
    from app.services import twofa
    secret = twofa.generate_secret()
    code = pyotp.TOTP(secret).now()
    assert twofa.verify_totp(secret, code) is True
    assert twofa.verify_totp(secret, "000000") in (True, False)  # almost always False
    assert twofa.verify_totp(secret, "notnum") is False
    assert twofa.verify_totp("", code) is False


def test_secret_encryption_roundtrip(app):
    from app.services import twofa
    with app.app_context():
        secret = twofa.generate_secret()
        token = twofa.encrypt_secret(secret)
        assert token != secret
        assert twofa.decrypt_secret(token) == secret
        assert twofa.decrypt_secret("") == ""
        assert twofa.decrypt_secret("garbage") == ""


def test_backup_codes():
    from app.services import twofa
    codes = twofa.generate_backup_codes(10)
    assert len(codes) == 10
    assert all("-" in c for c in codes)
    stored = twofa.encode_codes(codes)
    assert twofa.remaining_backup_codes(stored) == 10
    # plaintext is never in the stored blob
    assert codes[0] not in stored
    ok, stored2 = twofa.consume_backup_code(stored, codes[0].upper())  # case-insensitive
    assert ok is True
    assert twofa.remaining_backup_codes(stored2) == 9
    # used code can't be reused
    ok2, _ = twofa.consume_backup_code(stored2, codes[0])
    assert ok2 is False
    # wrong code
    assert twofa.consume_backup_code(stored2, "zzzz-zzzz")[0] is False


def test_reset_token_roundtrip(app):
    from app.services import twofa
    with app.app_context():
        tok = twofa.make_reset_token(42)
        assert twofa.read_reset_token(tok) == 42
        assert twofa.read_reset_token("bogus") is None
        assert twofa.read_reset_token(tok, max_age=-1) is None  # expired


# ---------------------------------------------------------------------------
# User model columns
# ---------------------------------------------------------------------------
def test_user_auth_source_columns(app):
    from app.models import User
    with app.app_context():
        u = User.query.filter_by(username="admin").first()
        assert u.auth_source == "local"
        assert u.is_local is True
        assert u.is_external is False
        u.auth_source = "ldap"
        assert u.is_local is False
        assert u.is_external is True


# ---------------------------------------------------------------------------
# auth_store — config + dispatch + provisioning
# ---------------------------------------------------------------------------
def test_auth_store_defaults(app):
    from app.services import auth_store
    with app.app_context():
        assert auth_store.backend() == "local"
        assert auth_store.is_enabled() is False
        assert auth_store.default_profile_name() == "operator"
        cfg = auth_store.config()
        assert cfg["backend"] == "local"
        assert cfg["ldap"]["has_bind_password"] is False
        assert cfg["radius"]["has_secret"] is False


def test_auth_store_save_and_secret_blank_keeps(app):
    from app.services import auth_store
    with app.app_context():
        form = {
            "backend": "ldap",
            "default_profile": "operator",
            "ldap_host": "ldap.example.com",
            "ldap_port": "636",
            "ldap_use_ssl": "on",
            "ldap_base_dn": "dc=example,dc=com",
            "ldap_bind_dn": "cn=svc,dc=example,dc=com",
            "ldap_bind_password": "s3cret",
            "ldap_user_attr": "uid",
            "ldap_tls_verify": "on",
        }
        auth_store.save_config(form)
        assert auth_store.backend() == "ldap"
        assert auth_store.is_enabled() is True
        cfg = auth_store.config(reveal_secrets=True)
        assert cfg["ldap"]["host"] == "ldap.example.com"
        assert cfg["ldap"]["use_ssl"] is True
        assert cfg["ldap"]["bind_password"] == "s3cret"
        assert cfg["ldap"]["has_bind_password"] is True

        # Re-save with blank password → keeps the stored one.
        form2 = dict(form)
        form2["ldap_bind_password"] = ""
        form2["ldap_host"] = "ldap2.example.com"
        auth_store.save_config(form2)
        cfg2 = auth_store.config(reveal_secrets=True)
        assert cfg2["ldap"]["host"] == "ldap2.example.com"
        assert cfg2["ldap"]["bind_password"] == "s3cret"


def test_test_connection_local(app):
    from app.services import auth_store
    with app.app_context():
        res = auth_store.test_connection({"backend": "local"})
        assert res["ok"] is True


def test_authenticate_external_local_disabled(app):
    from app.services import auth_store
    with app.app_context():
        res = auth_store.authenticate_external("bob", "pw")
        assert res["ok"] is False
        assert res["source"] == "local"


def test_authenticate_external_dispatch_ldap(app, monkeypatch):
    from app.services import auth_store, directory_auth
    with app.app_context():
        auth_store.save_config({"backend": "ad", "ldap_host": "dc.example.com",
                                "ldap_ad_domain": "example.com"})
        monkeypatch.setattr(directory_auth, "ldap_authenticate",
                            lambda cfg, u, p: (u == "alice" and p == "good", "test"))
        assert auth_store.authenticate_external("alice", "good")["ok"] is True
        assert auth_store.authenticate_external("alice", "bad")["ok"] is False
        assert auth_store.authenticate_external("alice", "good")["source"] == "ad"


def test_provision_external_creates_operator(app):
    from app.services import auth_store
    from app.models import User
    with app.app_context():
        u = auth_store.provision_external_user("newldapuser", "ldap")
        assert u.auth_source == "ldap"
        assert u.is_external is True
        assert u.profile is not None and u.profile.name == "operator"
        # unusable local password
        assert u.check_password("") is False
        # idempotent — second call returns same row, stays operator
        u2 = auth_store.provision_external_user("newldapuser", "ldap")
        assert u2.id == u.id


def test_provision_never_externalizes_local_admin(app):
    from app.services import auth_store
    from app.models import User
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        assert admin.is_local
        same = auth_store.provision_external_user("admin", "ldap")
        assert same.is_local is True       # untouched
        assert same.auth_source == "local"


# ---------------------------------------------------------------------------
# directory_auth — graceful failures (no live server)
# ---------------------------------------------------------------------------
def test_ldap_no_host():
    from app.services import directory_auth
    ok, detail = directory_auth.ldap_authenticate({"host": ""}, "u", "p")
    assert ok is False
    ok2, _ = directory_auth.ldap_authenticate({"host": "x"}, "u", "")
    assert ok2 is False  # empty password short-circuits


def test_radius_no_config():
    from app.services import directory_auth
    assert directory_auth.radius_authenticate({}, "u", "p")[0] is False
    assert directory_auth.radius_authenticate({"host": "x"}, "u", "p")[0] is False  # no secret


# ---------------------------------------------------------------------------
# Login flow integration
# ---------------------------------------------------------------------------
def test_login_local_still_works(client, app):
    r = client.post("/auth/login", data={"username": "admin", "password": "Sopas123.-"},
                    follow_redirects=False)
    assert r.status_code in (302, 303)
    assert "/auth/login" not in r.headers.get("Location", "")


def test_login_external_jit_provisions(client, app, monkeypatch):
    from app.services import auth_store, directory_auth
    with app.app_context():
        auth_store.save_config({"backend": "ldap", "ldap_host": "x", "ldap_base_dn": "dc=x"})
    monkeypatch.setattr(directory_auth, "ldap_authenticate",
                        lambda cfg, u, p: (p == "dirpass", "ok"))
    r = client.post("/auth/login", data={"username": "fromdir", "password": "dirpass"},
                    follow_redirects=False)
    assert r.status_code in (302, 303)
    assert "/auth/login" not in r.headers.get("Location", "")
    from app.models import User
    with app.app_context():
        u = User.query.filter_by(username="fromdir").first()
        assert u is not None and u.auth_source == "ldap"
        assert u.profile.name == "operator"


def test_login_2fa_challenge_gate(client, app):
    from app.services import twofa
    from app.extensions import db
    from app.models import User
    uid = make_user(app, username="totpuser")
    secret = twofa.generate_secret()
    with app.app_context():
        u = db.session.get(User, uid)
        u.totp_secret = twofa.encrypt_secret(secret)
        u.totp_enabled = True
        db.session.commit()
    # Correct password → NOT logged in yet, redirected to 2FA challenge.
    r = client.post("/auth/login", data={"username": "totpuser", "password": "pw"},
                    follow_redirects=False)
    assert r.status_code in (302, 303)
    assert "/auth/2fa" in r.headers.get("Location", "")
    # Wrong TOTP rejected.
    r2 = client.post("/auth/2fa", data={"code": "000000"}, follow_redirects=False)
    assert "/auth/2fa" in r2.headers.get("Location", "") or r2.status_code == 200
    # Correct TOTP → in.
    code = pyotp.TOTP(secret).now()
    r3 = client.post("/auth/2fa", data={"code": code}, follow_redirects=False)
    assert r3.status_code in (302, 303)
    assert "/auth/2fa" not in r3.headers.get("Location", "")


def test_password_reset_flow(client, app):
    from app.services import twofa
    from app.extensions import db
    from app.models import User
    uid = make_user(app, username="recover")
    with app.app_context():
        u = db.session.get(User, uid)
        u.recovery_email = "recover@example.com"
        db.session.commit()
        token = twofa.make_reset_token(uid)
    # Use the token to set a new password.
    r = client.post(f"/auth/reset/{token}",
                    data={"new_password": "BrandNew123", "confirm_password": "BrandNew123"},
                    follow_redirects=False)
    assert r.status_code in (302, 303)
    with app.app_context():
        u = db.session.get(User, uid)
        assert u.check_password("BrandNew123") is True
