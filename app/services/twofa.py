"""Two-factor authentication (TOTP) + account recovery primitives.

Local accounts can enable **TOTP** 2FA (Google Authenticator / Authy / FreeOTP …)
and are issued one-time **backup codes**. External (directory) accounts do their
MFA at the directory, so 2FA here is gated to ``auth_source == 'local'`` by the
callers.

Design mirrors the rest of the web app:

* The TOTP **secret** is the only long-lived secret → stored Fernet-encrypted
  (``services.encryption``) in ``users.totp_secret``, never returned to a
  template in plaintext (the enrollment QR is shown once, before enabling).
* **Backup codes** are stored only as salted SHA-256 hashes (JSON list) in
  ``users.backup_codes`` — like a password, the plaintext is shown once.
* The **password-reset token** is a stateless, signed, expiring
  ``itsdangerous`` token (no DB table needed), signed with ``SECRET_KEY``.

Pure-ish: every function is deterministic given its inputs except the few that
read ``current_app.config['SECRET_KEY']`` (recovery tokens) — those are skipped
by the unit tests, which exercise the TOTP / backup-code logic directly.
"""
from __future__ import annotations

import hashlib
import io
import json
import secrets

import pyotp

from . import encryption

ISSUER = "OFortMAut"
BACKUP_CODE_COUNT = 10
RESET_MAX_AGE = 3600  # seconds a password-reset link stays valid


# ---- TOTP -----------------------------------------------------------------
def generate_secret() -> str:
    """A fresh base32 TOTP secret (what the authenticator app stores)."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    """The ``otpauth://`` URI encoded in the enrollment QR code."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def qr_svg(uri: str) -> str:
    """Render *uri* as a self-contained SVG string (no native deps / no PIL).

    Returns ``""`` if the QR library is unavailable so enrollment can still
    proceed via the manual secret entry."""
    try:
        import qrcode
        import qrcode.image.svg

        img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgImage,
                          box_size=10, border=2)
        buf = io.BytesIO()
        img.save(buf)
        return buf.getvalue().decode("utf-8")
    except Exception:  # noqa: BLE001 — QR is a convenience; manual entry remains
        return ""


def verify_totp(secret: str, code: str) -> bool:
    """True if *code* is valid for *secret* now (±1 step for clock drift)."""
    if not secret or not code:
        return False
    code = str(code).strip().replace(" ", "")
    if not code.isdigit():
        return False
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:  # noqa: BLE001
        return False


# ---- secret storage (encrypted column round-trip) -------------------------
def encrypt_secret(secret_plain: str) -> str:
    return encryption.encrypt(secret_plain)


def decrypt_secret(token: str) -> str:
    """Decrypt the stored secret; ``""`` if missing/undecryptable."""
    if not token:
        return ""
    try:
        return encryption.decrypt(token)
    except Exception:  # noqa: BLE001
        return ""


# ---- backup codes ---------------------------------------------------------
_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no ambiguous chars


def _one_code() -> str:
    raw = "".join(secrets.choice(_ALPHABET) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


def generate_backup_codes(n: int = BACKUP_CODE_COUNT) -> list[str]:
    """A fresh list of human-friendly one-time codes (shown to the user once)."""
    return [_one_code() for _ in range(n)]


def _norm(code: str) -> str:
    return (code or "").strip().lower().replace(" ", "")


def hash_code(code: str) -> str:
    return hashlib.sha256(_norm(code).encode()).hexdigest()


def encode_codes(codes: list[str]) -> str:
    """JSON list of hashes to persist in ``users.backup_codes``."""
    return json.dumps([hash_code(c) for c in codes])


def _decode(stored_json: str | None) -> list[str]:
    if not stored_json:
        return []
    try:
        data = json.loads(stored_json)
        return [h for h in data if isinstance(h, str)]
    except (ValueError, TypeError):
        return []


def remaining_backup_codes(stored_json: str | None) -> int:
    return len(_decode(stored_json))


def consume_backup_code(stored_json: str | None, code: str) -> tuple[bool, str]:
    """Return ``(ok, new_stored_json)``. On a match the used hash is removed so
    each backup code works exactly once."""
    hashes = _decode(stored_json)
    target = hash_code(code)
    if target in hashes:
        hashes.remove(target)
        return True, json.dumps(hashes)
    return False, stored_json or "[]"


# ---- password-reset token (stateless, signed, expiring) -------------------
def _serializer():
    from flask import current_app
    from itsdangerous import URLSafeTimedSerializer

    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"],
                                  salt="fmw-password-recovery")


def make_reset_token(user_id: int) -> str:
    return _serializer().dumps({"uid": int(user_id)})


def read_reset_token(token: str, max_age: int = RESET_MAX_AGE) -> int | None:
    """Return the user id encoded in *token*, or ``None`` if invalid/expired."""
    from itsdangerous import BadSignature, SignatureExpired

    try:
        data = _serializer().loads(token, max_age=max_age)
        return int(data.get("uid"))
    except (BadSignature, SignatureExpired, ValueError, TypeError, KeyError):
        return None


__all__ = [
    "ISSUER", "BACKUP_CODE_COUNT", "RESET_MAX_AGE",
    "generate_secret", "provisioning_uri", "qr_svg", "verify_totp",
    "encrypt_secret", "decrypt_secret",
    "generate_backup_codes", "hash_code", "encode_codes",
    "remaining_backup_codes", "consume_backup_code",
    "make_reset_token", "read_reset_token",
]
