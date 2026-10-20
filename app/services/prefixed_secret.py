"""One secret per name, kept like every other SATOM secret: in the vault when
one is configured, else Fernet-encrypted in ``app_settings`` — the ONE copy of
that rule for the stores that keep a row per name (Studio connections, Wiki
Confluence targets; services/secret_backend._PREFIXED_SECRETS migrates and
scrubs them all).

* :func:`state` reads the vault first, then the local copy; a local copy that
  is only the vault sentinel and a vault that cannot be read gives a problem
  text, never an empty secret that looks like "no secret".
* :func:`store` writes the vault when it is active; when the vault is the only
  store (authoritative) the local row keeps just the sentinel, and a vault
  that refuses the write refuses the save. An empty value clears both.
"""
from __future__ import annotations

from ..models import AppSetting

MAX_LEN = 8192


class SecretStoreError(ValueError):
    """The secret was not saved; the message is safe to show."""


def present(key: str) -> bool:
    return bool((AppSetting.get(key) or "").strip())


def state(key: str, path: str, field: str = "value") -> tuple[str, str]:
    """``(secret, problem)``; vault first, then the local copy."""
    raw = (AppSetting.get(key) or "").strip()
    if not raw:
        return "", ""
    from . import secret_backend as sb
    vault_err = ""
    try:
        vaulted = sb.get_field(path, field)
    except Exception as exc:  # noqa: BLE001
        vaulted, vault_err = "", str(exc) or exc.__class__.__name__
    if vaulted:
        return vaulted, ""
    try:
        from .encryption import decrypt
        local = decrypt(raw) or ""
    except Exception:  # noqa: BLE001
        return "", "the local copy of the secret could not be decrypted (FERNET_KEY changed?)"
    if local == sb.VAULT_SENTINEL:
        return "", ("the secret is stored in the vault, which could not be read: %s"
                    % (vault_err or "no value at %s" % path))
    return local, ""


def store(key: str, path: str, value: str, field: str = "value") -> None:
    from .encryption import encrypt
    from . import secret_backend as sb
    if not value:
        AppSetting.set(key, "")
        try:
            if sb.active():
                sb.delete(path)
        except Exception:  # noqa: BLE001
            pass
        return
    if len(value) > MAX_LEN:
        raise SecretStoreError("the secret is longer than %d characters" % MAX_LEN)
    stored = False
    try:
        stored = sb.put_field(path, field, value)
    except Exception:  # noqa: BLE001
        if sb.authoritative():
            raise SecretStoreError("the vault is the only secret store and refused the "
                                   "write; the secret was not saved")
    if stored and sb.authoritative():
        AppSetting.set(key, encrypt(sb.VAULT_SENTINEL))
    else:
        AppSetting.set(key, encrypt(value))
