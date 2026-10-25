"""Trusted plugin publishers -- Ed25519 keys a super-admin registers.

``plugin_package.TRUSTED_KEYS`` pins the Vision EBC signing key in the code.
A customer's SATOM Builder signs its packages with a key created on the
Builder host; registering its PUBLIC half here makes this server read those
packages as signed (``plugin_package.trusted_keys_with_publishers``).

What a publisher's signature buys, and what it never buys:

* a view or widget signed by an enabled publisher lands in *testing*, like a
  Vision EBC-signed one (unsigned: *draft*);
* every publisher-signed package is checked with the ``builder`` policy
  (``services.plugin_import``), the strict one;
* ``kind: code`` is refused whoever signed it, unless the signer is a Vision
  EBC key -- enforced in ``plugin_import``, not left to a rule module;
* a disabled publisher is not trusted: its packages are refused as signed by
  an unknown key, exactly like any other key this server does not know.

Rows are never deleted from the UI: disabling keeps the audit trail readable
(which key signed what).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re

LABEL_MAX = 80
_KEY_ID_RE = re.compile(r"^[0-9a-f]{64}$")


class PublisherError(ValueError):
    """The publisher was refused; the message says why, in plain English."""


def raw_key(public_key_b64: str) -> bytes:
    """The raw 32-byte Ed25519 key from its base64 text, or PublisherError."""
    text = "".join(str(public_key_b64 or "").split())
    if not text:
        raise PublisherError("Paste the publisher's public key (base64).")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise PublisherError("The public key is not valid base64.") from None
    if len(raw) != 32:
        raise PublisherError("The public key must be the raw 32-byte Ed25519 key "
                             "(%d bytes given)." % len(raw))
    from cryptography.hazmat.primitives.asymmetric import ed25519
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(raw)
    except Exception:  # noqa: BLE001 -- any refusal of the curve is "not a key"
        raise PublisherError("The public key is not an Ed25519 key.") from None
    return raw


def key_id_of(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def clean_label(label: str) -> str:
    label = " ".join(str(label or "").split())
    if not label:
        raise PublisherError("A label is required.")
    if len(label) > LABEL_MAX:
        raise PublisherError("The label is longer than %d characters." % LABEL_MAX)
    return label


def list_publishers():
    from ..models import PluginPublisher
    return PluginPublisher.query.order_by(PluginPublisher.created_at.asc(),
                                          PluginPublisher.id.asc()).all()


def get(key_id: str):
    from ..models import PluginPublisher
    if not _KEY_ID_RE.match(str(key_id or "")):
        return None
    return PluginPublisher.query.filter_by(key_id=key_id).first()


def add(label: str, public_key_b64: str, by: str, adom_keys=None):
    """Register a key. ``(row, created)``: the same key twice returns the
    existing row with ``created=False`` and changes nothing."""
    from ..extensions import db
    from ..models import PluginPublisher
    from . import plugin_package as P
    raw = raw_key(public_key_b64)
    kid = key_id_of(raw)
    row = get(kid)
    if row is not None:
        return row, False
    label = clean_label(label)
    if kid in P.TRUSTED_KEYS:
        raise PublisherError("This key is already trusted as a Vision EBC key.")
    adoms = sorted({str(a) for a in (adom_keys or []) if str(a).strip()})
    row = PluginPublisher(key_id=kid, label=label,
                          public_key=base64.b64encode(raw).decode("ascii"),
                          enabled=True, adom_keys=json.dumps(adoms) if adoms else None,
                          created_by=str(by or "")[:64])
    db.session.add(row)
    db.session.commit()
    return row, True


def set_enabled(row, enabled: bool) -> None:
    from ..extensions import db
    row.enabled = bool(enabled)
    db.session.commit()


def applies_to(row, product: str | None) -> bool:
    """Whether *row* is trusted for an import into ADOM *product*
    (``None`` = no ADOM to check: every enabled key)."""
    adoms = row.adoms
    if not adoms or product is None:
        return True
    return (product or "global") in adoms or "*" in adoms


def keys(product: str | None = None) -> dict[str, bytes]:
    """``{key_id: raw key}`` of the ENABLED publishers that apply to
    *product*. A database that cannot answer (no table yet, a read-only
    standby mid-failover) trusts no publisher: failing closed costs a
    refused import, failing open would trust a disabled key."""
    try:
        rows = [r for r in list_publishers() if r.enabled and applies_to(r, product)]
    except Exception:  # noqa: BLE001
        try:
            from ..extensions import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return {}
    out = {}
    for r in rows:
        try:
            out[r.key_id] = base64.b64decode(r.public_key)
        except (binascii.Error, ValueError):
            continue
    return out


def label_of(key_id: str | None) -> str:
    """Who signed, for people: "Vision EBC", the publisher's label, or ""."""
    from . import plugin_package as P
    if not key_id:
        return ""
    if key_id in P.TRUSTED_KEYS:
        return "Vision EBC"
    row = None
    try:
        row = get(key_id)
    except Exception:  # noqa: BLE001
        row = None
    return row.label if row is not None else key_id[:16]


def as_json(row, *, with_key: bool = False) -> dict:
    out = {"key_id": row.key_id, "label": row.label, "enabled": bool(row.enabled),
           "created_at": row.created_at.isoformat(timespec="seconds") + "Z"
           if row.created_at else None}
    if row.adoms:
        out["adoms"] = row.adoms
    if with_key:
        out["public_key"] = row.public_key
    return out
