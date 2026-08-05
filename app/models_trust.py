"""TLS trust store — the CAs this installation trusts when it talks TO a device.

The mirror image of ``pki/`` and Settings -> Node TLS. Those hold the cert this
node PRESENTS; this table holds the certificate authorities it ACCEPTS.

Why it exists: every appliance in a private fleet is signed by the company's
own CA (or ships a self-signed factory cert), and Python's default trust list
is the PUBLIC root store. So ``Appliance.verify_ssl`` had exactly two settings
— *validate against public roots* (fails for every internal CA) or *validate
nothing*. Everyone picks the second, which is why "set verify_ssl=false" is the
recurring fix in this project's history: fadc (2026-07-12), fortiweb08
(2026-07-28), fac01 (2026-08-05). That is not a device quirk, it is a missing
feature — there was nowhere to put the company root.

Design notes that matter:

* **Postgres is the source of truth, not a file.** The PEM lives here so the
  streaming replica gets it for free and it rides the pg_dump bundles. The
  on-disk bundle each node feeds to OpenSSL is a derived cache, rebuilt from
  these rows (see ``services/trust_store.py``). ``pki/`` is node-local and
  gitignored, so a CA parked there would have to be installed twice, by hand,
  and would silently differ between the primary and the standby.
* **Public certificates only — no Fernet.** A CA certificate is public by
  definition; encrypting it would imply a secrecy this record does not have.
  The private key of that CA never comes near this table.
* **The fingerprint is the identity.** Two rows cannot hold the same
  certificate, and re-importing an existing CA updates it in place instead of
  quietly stacking duplicates into the bundle.
* **Disabled is not deleted.** ``enabled=False`` drops a CA out of the bundle
  while keeping the audit trail of what was trusted and when.
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db

#: What the certificate is, structurally. Shown in the UI because "root" and
#: "intermediate" behave differently: a chain that stops at an intermediate
#: whose issuer is absent will not validate, and the operator needs to see that
#: before the first device probe fails.
ROLE_ROOT = "root"                  # self-signed CA — a trust anchor
ROLE_INTERMEDIATE = "intermediate"  # CA signed by someone else
ROLES = (ROLE_ROOT, ROLE_INTERMEDIATE)


class TrustedCa(db.Model):
    __tablename__ = "trusted_cas"

    id = db.Column(db.Integer, primary_key=True)

    #: Operator-facing label. Defaults to the certificate's CN on import.
    name = db.Column(db.String(200), nullable=False, unique=True)

    #: The certificate itself, PEM. Public material.
    pem = db.Column(db.Text, nullable=False)

    #: Lowercase hex SHA-256 of the DER. The real identity of the row.
    fingerprint = db.Column(db.String(64), nullable=False, unique=True,
                            index=True)

    subject = db.Column(db.String(500), nullable=False, default="")
    issuer = db.Column(db.String(500), nullable=False, default="")
    serial = db.Column(db.String(80), nullable=False, default="")
    role = db.Column(db.String(16), nullable=False, default=ROLE_INTERMEDIATE)

    not_before = db.Column(db.DateTime, nullable=True)
    not_after = db.Column(db.DateTime, nullable=True)

    #: Out of the bundle without losing the record. See module docstring.
    enabled = db.Column(db.Boolean, nullable=False, default=True)

    note = db.Column(db.String(500), nullable=False, default="")
    added_by = db.Column(db.String(150), nullable=False, default="")
    added_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self) -> str:  # pragma: no cover — debugging aid
        return f"<TrustedCa {self.name!r} {self.role} {self.fingerprint[:16]}>"

    @property
    def expired(self) -> bool:
        return bool(self.not_after and self.not_after < datetime.utcnow())

    @property
    def days_left(self) -> int | None:
        if not self.not_after:
            return None
        return (self.not_after - datetime.utcnow()).days

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "fingerprint": self.fingerprint,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "role": self.role,
            "enabled": bool(self.enabled),
            "expired": self.expired,
            "days_left": self.days_left,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "note": self.note,
            "added_by": self.added_by,
            "added_at": self.added_at.isoformat() if self.added_at else None,
        }
