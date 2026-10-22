"""Certificate providers -- named CAs the person issuing a certificate picks.

Until now the Certificate Manager had ONE issuance protocol for everything
(``certmgr.protocol``: ADCS or ACME). Teams that buy some certificates from a
commercial provider and sign others with their internal CA had to choose one.
A provider is a NAME the user picks when issuing, plus the protocol it is
reached with and one rule:

* ``key``           stable slug, stored on every certificate it issued
                    (``managed_certificates.provider``) so a renewal and a
                    revoke go back to the SAME provider.
* ``name``          what the picker shows ("Class E", "Class C").
* ``protocol``      ``adcs`` | ``acme`` | ``""`` = the protocol configured in
                    Settings › Certificate Manager. The protocol's own settings
                    (CA, templates, commands) stay where they are.
* ``internal_only`` a certificate from this provider may serve an Internal
                    policy only (Class E). Checked where the zone is known --
                    the Plugin Studio certificate step -- and shown in the picker.

Which provider a domain gets is the USER's choice, never derived from a
suffix: an earlier draft mapped ``.mx`` to one class and ``.com`` to the
other, and the operator asked for the choice instead (2026-10-22).

The seed is the configured CA as "Class E" (internal only) plus "Class C";
the administrator renames, adds or removes them on the Certificate Manager
settings page. Removing every provider is refused: the picker would be empty.
"""
from __future__ import annotations

import re

from . import settings_store as store

K_PROVIDERS = "certmgr.providers"
PROTOCOLS = ("", "adcs", "acme")
MAX_PROVIDERS = 20
_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")

DEFAULT = [
    {"key": "class-e", "name": "Class E", "protocol": "", "internal_only": True,
     "note": "Internal CA. Internal policies only."},
    {"key": "class-c", "name": "Class C", "protocol": "", "internal_only": False,
     "note": "Another certificate provider. Internal and external policies."},
]


class ProviderError(ValueError):
    pass


def _clean(rows) -> list[dict]:
    if not isinstance(rows, list):
        raise ProviderError("the providers are a list")
    if not rows:
        raise ProviderError("keep at least one provider: the picker cannot be empty")
    if len(rows) > MAX_PROVIDERS:
        raise ProviderError("at most %d providers" % MAX_PROVIDERS)
    out, seen = [], set()
    for r in rows:
        if not isinstance(r, dict):
            raise ProviderError("each provider is an object")
        key = str(r.get("key") or "").strip().lower()
        if not _KEY_RE.match(key):
            raise ProviderError("provider key %r: lowercase letters, digits, - and _" % key)
        if key in seen:
            raise ProviderError("provider key %s is used twice" % key)
        seen.add(key)
        name = str(r.get("name") or "").strip()[:80]
        if not name:
            raise ProviderError("provider %s needs a name" % key)
        proto = str(r.get("protocol") or "").strip().lower()
        if proto not in PROTOCOLS:
            raise ProviderError("provider %s: unknown protocol %r" % (key, proto))
        out.append({"key": key, "name": name, "protocol": proto,
                    "internal_only": r.get("internal_only") in (True, "1", "true", "on", 1),
                    "note": str(r.get("note") or "").strip()[:300]})
    return out


def providers() -> list[dict]:
    rows = store.get_json(K_PROVIDERS, None)
    if not rows:
        return [dict(p) for p in DEFAULT]
    try:
        return _clean(rows)
    except ProviderError:
        return [dict(p) for p in DEFAULT]


def save(rows) -> list[dict]:
    clean = _clean(rows)
    store.set_json(K_PROVIDERS, clean)
    return clean


def get(key: str) -> dict | None:
    key = str(key or "").strip().lower()
    for p in providers():
        if p["key"] == key:
            return p
    return None


def default_key() -> str:
    return providers()[0]["key"]


def require(key: str) -> dict:
    """The provider ``key`` names; ``""`` = the first one."""
    if not str(key or "").strip():
        return providers()[0]
    p = get(key)
    if p is None:
        raise ProviderError("certificate provider %r does not exist "
                            "(Certificate Manager › Providers)" % key)
    return p


def protocol_of(key: str) -> str:
    """The protocol a certificate of provider ``key`` is issued and revoked
    with. A certificate issued before providers existed (``""``) and a
    provider that inherits both answer with the configured protocol."""
    p = get(key) if key else None
    proto = (p or {}).get("protocol") or ""
    return proto or store.cert_manager_protocol()


def label(key: str) -> str:
    p = get(key) if key else None
    return p["name"] if p else (key or "")


def zone_problem(key: str, zone: str) -> str:
    """Why a certificate of provider ``key`` may not serve a policy in
    ``zone`` ("" when it may, or when the zone is not known)."""
    if not str(zone or "").strip():
        return ""
    p = get(key) if key else providers()[0]
    if p and p["internal_only"] and str(zone).strip().lower() != "internal":
        return ("provider %s issues certificates for Internal policies only, and this "
                "policy is %s" % (p["name"], zone))
    return ""
