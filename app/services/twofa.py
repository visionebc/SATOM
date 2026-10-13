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
import time

import pyotp

from . import encryption

ISSUER = "SATOM"
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


def verify_totp_step(secret: str, code: str, last_step: int | None = None,
                     valid_window: int = 1) -> int | None:
    """Verify *code* and return the absolute TOTP timestep it matched, or
    ``None`` when it is invalid.

    Unlike :func:`verify_totp` this is replay-aware: a step that is not
    strictly newer than *last_step* is rejected even if the code is
    arithmetically correct, so a code already spent on this account cannot be
    used again inside its ``valid_window`` (~90 s). Callers persist the returned
    step on the user and pass it back as *last_step* next time.
    """
    if not secret or not code:
        return None
    code = str(code).strip().replace(" ", "")
    if not code.isdigit():
        return None
    try:
        totp = pyotp.TOTP(secret)
        current = int(time.time()) // totp.interval
        for offset in range(-valid_window, valid_window + 1):
            step = current + offset
            if last_step is not None and step <= last_step:
                continue
            if secrets.compare_digest(code, str(totp.generate_otp(step))):
                return step
        return None
    except Exception:  # noqa: BLE001
        return None


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


def _pw_fingerprint(password_hash: str | None) -> str:
    """A short, non-reversible fingerprint of the stored password hash.

    Embedded in the reset token so the link is bound to the password it was
    issued against: the hash (and therefore this fingerprint) changes the
    moment the password is reset, which both kills a stolen old link and makes
    a token single-use — replaying the same link after it set a new password
    fails because the hash it named is gone. A SHA-256 slice, not the hash
    itself: the token is signed, not encrypted, so its payload is readable."""
    if not password_hash:
        return ""
    return hashlib.sha256(password_hash.encode()).hexdigest()[:16]


def make_reset_token(user_id: int, password_hash: str | None = None) -> str:
    return _serializer().dumps({"uid": int(user_id),
                                "pw": _pw_fingerprint(password_hash)})


def _load_reset_token(token: str, max_age: int):
    from itsdangerous import BadSignature, SignatureExpired

    try:
        data = _serializer().loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired, ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def read_reset_token(token: str, max_age: int = RESET_MAX_AGE) -> int | None:
    """Return the user id encoded in *token*, or ``None`` if invalid/expired."""
    data = _load_reset_token(token, max_age)
    if data is None:
        return None
    try:
        return int(data["uid"])
    except (KeyError, ValueError, TypeError):
        return None


def reset_token_hash_ok(token: str, password_hash: str | None,
                        max_age: int = RESET_MAX_AGE) -> bool:
    """True when *token* is bound to a password hash that still matches.

    A token minted without a binding (no ``pw`` claim) is accepted so callers
    that do not pass the hash keep working; a bound token is rejected once the
    hash it names has changed, which is what makes the link die on first use."""
    data = _load_reset_token(token, max_age)
    if data is None:
        return False
    bound = data.get("pw") or ""
    if not bound:
        return True
    return secrets.compare_digest(bound, _pw_fingerprint(password_hash))


__all__ = [
    "ISSUER", "BACKUP_CODE_COUNT", "RESET_MAX_AGE",
    "generate_secret", "provisioning_uri", "qr_svg", "verify_totp",
    "verify_totp_step",
    "encrypt_secret", "decrypt_secret",
    "generate_backup_codes", "hash_code", "encode_codes",
    "remaining_backup_codes", "consume_backup_code",
    "make_reset_token", "read_reset_token", "reset_token_hash_ok",
]
