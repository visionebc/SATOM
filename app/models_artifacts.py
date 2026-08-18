"""Index of the WAF **artifact** store — the bytes FortiWeb will not give back.

Seven API-Protection object types are backed by an uploaded FILE (XML Schema,
XML DTD, WSDL, OpenAPI, gRPC IDL, JSON Schema) or by a script body (Lua
scripting). Their configuration record is *only a name*: ``GET`` on the cmdb
object returns ``{"name": …}`` and nothing else, and the device's own
``execute backup full-config`` emits ``edit "xsd-order"`` / ``next`` with no
content (measured on 7.6.8 — certificates DO travel whole in the same backup,
so the omission is deliberate, not an oversight).

Four of the seven have a private read endpoint outside ``/cmdb/`` and can be
copied device→device. **Three do not** — XML Schema, WSDL and gRPC IDL answer
``-20005 invalid HTTP method`` on every read shape, and their GUI tab offers
only *Create New | Delete*. For those, a clone can only ever be as complete as
what SATOM itself kept.

Hence this table: SATOM captures the artifact the first time it can see it
(pushed through SATOM, or read live off a device that allows it) and can then
push that copy to any destination. The bodies are NOT here — they are
content-addressed gzip blobs under ``data/artifacts/objects/`` (see
:mod:`services.waf_artifacts`), the same split, the same directory tree and the
same replication path (``satom-ha-datasync`` + system-backup bundles) that
:mod:`models_sot` already uses. Nothing new to back up.

Rows are VERSIONS, and the hash is the identity: re-capturing an unchanged
artifact advances ``last_seen_at`` and writes zero bytes.
"""
from __future__ import annotations

from datetime import datetime

from .models import db


class WafArtifact(db.Model):
    """One captured version of one file-backed WAF object's content."""

    __tablename__ = "waf_artifact"

    #: How the bytes reached us. ``captured`` = read live off a device;
    #: ``uploaded`` = an operator handed them to SATOM (the ONLY way the three
    #: unreadable kinds can ever enter the store).
    SOURCES = ("captured", "uploaded")

    id = db.Column(db.Integer, primary_key=True)
    #: Key into :data:`services.waf_artifacts.KINDS`.
    kind = db.Column(db.String(32), nullable=False, index=True)
    #: The object's mkey on the device (for OpenAPI this INCLUDES the
    #: extension — the firmware validates it and the name *is* the filename).
    name = db.Column(db.String(255), nullable=False, index=True)
    #: Appliance the artifact belongs to. NULL = library-wide, usable as the
    #: fallback for any device that needs this name.
    appliance_id = db.Column(db.Integer, nullable=True, index=True)
    sha256 = db.Column(db.String(64), nullable=False, index=True)
    size = db.Column(db.Integer, nullable=False, default=0)
    source = db.Column(db.String(16), nullable=False, default="uploaded")
    note = db.Column(db.String(500), nullable=False, default="")
    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           index=True)
    #: An unchanged re-capture does NOT mint a row — this advances instead.
    last_seen_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "name": self.name,
            "appliance_id": self.appliance_id, "sha256": self.sha256,
            "short_sha": (self.sha256 or "")[:12],
            "size": self.size, "source": self.source, "note": self.note,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(timespec="seconds")
                          if self.created_at else "",
            "last_seen_at": self.last_seen_at.isoformat(timespec="seconds")
                            if self.last_seen_at else "",
        }
