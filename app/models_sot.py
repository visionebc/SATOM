"""Index of the local, versioned device source-of-truth store.

One table. The snapshot *bodies* are NOT here: they live as content-addressed,
gzip-compressed blobs under ``data/sot/objects/`` (see
``services/sot_store.py``). Postgres holds only the version index — who, when,
which hash — so history queries never read a blob and the streaming replica
carries the index to the standby for free while ``satom-ha-datasync`` carries
the blobs (both ride mechanisms that already exist; no new replication path).

Why not a git repository (the previous engine): a repo that receives a
90+ MB fleet snapshot every hour grows without bound — git keeps every byte of
every revision forever, and at 100 devices the reports/ history outgrows the
node in weeks. A content-addressed store keeps ONE copy of each distinct
config (the hash is the identity, so an unchanged device costs zero bytes per
cycle) and prunes old versions by policy instead of never.
"""
from __future__ import annotations

from datetime import datetime

from .models import db


class SotVersion(db.Model):
    """One recorded version of one device's harvested configuration."""

    __tablename__ = "sot_version"

    id = db.Column(db.Integer, primary_key=True)
    device = db.Column(db.String(120), nullable=False, index=True)
    sha256 = db.Column(db.String(64), nullable=False, index=True)
    size_raw = db.Column(db.Integer, nullable=False, default=0)
    size_gz = db.Column(db.Integer, nullable=False, default=0)
    total_objects = db.Column(db.Integer, nullable=False, default=0)
    section_count = db.Column(db.Integer, nullable=False, default=0)
    source = db.Column(db.String(32), nullable=False, default="harvest")
    taken_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                         index=True)
    # An unchanged config does NOT mint a new row — the newest row's
    # last_seen_at advances instead. "How fresh is my SoT?" reads this;
    # "when did the config actually change?" reads taken_at.
    last_seen_at = db.Column(db.DateTime, nullable=False,
                             default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "device": self.device, "sha256": self.sha256,
            "size_raw": self.size_raw, "size_gz": self.size_gz,
            "total_objects": self.total_objects,
            "section_count": self.section_count, "source": self.source,
            "taken_at": self.taken_at.isoformat(timespec="seconds")
                        if self.taken_at else "",
            "last_seen_at": self.last_seen_at.isoformat(timespec="seconds")
                            if self.last_seen_at else "",
        }
