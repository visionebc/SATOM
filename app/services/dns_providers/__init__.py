"""DNS Records providers — registry, config store, and active-provider factory.

Config lives in ``AppSetting`` (global keys, mirrors ``email.*`` / ``auth.*``):

* ``dnsrecords.provider``   — active provider key (``none`` when off).
* ``dnsrecords.config``     — JSON of non-secret connection fields.
* ``dnsrecords.secret_enc`` — the single provider secret, Fernet-encrypted
  (SOLIDserver password / NetBox token / phpIPAM app token).

Only ``USER_MANAGE`` admins edit this (Settings -> DNS Records) and use the
CRUD endpoints; the secret is never returned to the browser.
"""
from __future__ import annotations

import json

from .base import Capabilities, DnsProvider, DnsRecord, ProviderError
from .none import NoneProvider
from .efficientip import EfficientIPProvider
from .phpipam import PhpIpamProvider
from .netbox import NetBoxProvider

PROVIDERS: dict[str, type[DnsProvider]] = {
    "none": NoneProvider,
    "efficientip": EfficientIPProvider,
    "phpipam": PhpIpamProvider,
    "netbox": NetBoxProvider,
}

K_PROVIDER = "dnsrecords.provider"
K_CONFIG = "dnsrecords.config"
K_SECRET = "dnsrecords.secret_enc"

# Per-provider non-secret field specs (key, label, placeholder, type) — drives
# the Settings form generically. The secret field is handled separately.
FIELD_SPECS: dict[str, list[dict]] = {
    "efficientip": [
        {"key": "base_url", "label": "Base URL", "ph": "https://solidserver.example.com"},
        {"key": "username", "label": "Username", "ph": "ipmadmin"},
        {"key": "dns_server", "label": "DNS server (smart/appliance name)", "ph": "dns.smart"},
        {"key": "default_view", "label": "Default DNS view (optional)", "ph": "external"},
        {"key": "default_zone", "label": "Default zone (optional)", "ph": "example.com"},
    ],
    "phpipam": [
        {"key": "base_url", "label": "Base URL", "ph": "https://phpipam.example.com"},
        {"key": "app_id", "label": "API app id", "ph": "fortinet"},
    ],
    "netbox": [
        {"key": "base_url", "label": "Base URL", "ph": "https://netbox.example.com"},
        {"key": "default_zone", "label": "Default zone (optional)", "ph": "example.com"},
    ],
}
SECRET_LABELS = {
    "efficientip": "Password", "phpipam": "API app token", "netbox": "API token",
}


# ---------------------------------------------------------------- config

def provider_key() -> str:
    from ...models import AppSetting
    return (AppSetting.get(K_PROVIDER) or "none").strip() or "none"


def _raw_config() -> dict:
    from ...models import AppSetting
    raw = AppSetting.get(K_CONFIG)
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def config_public() -> dict:
    """Non-secret config + a flag saying whether a secret is stored (never the
    secret itself). Safe to hand to the Settings template."""
    from ...models import AppSetting
    cfg = _raw_config()
    cfg["provider"] = provider_key()
    cfg["has_secret"] = bool(AppSetting.get(K_SECRET))
    cfg.setdefault("verify_ssl", True)
    return cfg


def _secret() -> str:
    from ...models import AppSetting
    from ..encryption import decrypt
    tok = AppSetting.get(K_SECRET)
    if not tok:
        return ""
    try:
        return decrypt(tok)
    except Exception:  # noqa: BLE001 — bad/rotated token -> treat as empty
        return ""


def save_config(provider: str, fields: dict, secret: str | None) -> None:
    """Persist provider selection + non-secret fields + (optional) secret.

    A blank ``secret`` LEAVES the stored one untouched (so admins can edit
    other fields without re-typing it); passing the sentinel ``\"\"`` via an
    explicit clear is handled by the caller. ``None`` means 'do not change'.
    """
    from ...models import AppSetting, db
    from ..encryption import encrypt

    provider = provider if provider in PROVIDERS else "none"
    clean = {"verify_ssl": bool(fields.get("verify_ssl", True))}
    for spec in FIELD_SPECS.get(provider, []):
        clean[spec["key"]] = str(fields.get(spec["key"]) or "").strip()[:512]

    AppSetting.set(K_PROVIDER, provider)
    AppSetting.set(K_CONFIG, json.dumps(clean))
    if secret:
        AppSetting.set(K_SECRET, encrypt(secret))
    db.session.commit()


def clear_secret() -> None:
    from ...models import AppSetting, db
    AppSetting.set(K_SECRET, "")
    db.session.commit()


# ---------------------------------------------------------------- factory

def _instance(key: str) -> DnsProvider:
    cls = PROVIDERS.get(key, NoneProvider)
    cfg = _raw_config()
    cfg["secret"] = _secret()
    return cls(cfg)


def active_provider() -> DnsProvider | None:
    """The configured provider instance, or None when off/unset."""
    key = provider_key()
    if key == "none" or key not in PROVIDERS:
        return None
    return _instance(key)


def provider_for_test(key: str, fields: dict, secret: str | None) -> DnsProvider:
    """Build a provider from UNSAVED form values for the Test button. Falls
    back to the stored secret when the form leaves it blank."""
    cfg = {"verify_ssl": bool(fields.get("verify_ssl", True))}
    for spec in FIELD_SPECS.get(key, []):
        cfg[spec["key"]] = str(fields.get(spec["key"]) or "").strip()
    cfg["secret"] = secret if secret else _secret()
    return PROVIDERS.get(key, NoneProvider)(cfg)


__all__ = [
    "Capabilities", "DnsProvider", "DnsRecord", "ProviderError",
    "PROVIDERS", "FIELD_SPECS", "SECRET_LABELS",
    "provider_key", "config_public", "save_config", "clear_secret",
    "active_provider", "provider_for_test",
]
