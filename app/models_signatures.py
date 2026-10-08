"""The local signature index — what the devices' own signature databases held,
version after version.

Signatures never travel in a pack: every FortiWeb downloads its database from
FortiGuard with its own licence. SATOM reads that database off ONE device the
operator chooses as the *signature source* (``services.signature_index``) and
keeps three things here:

* ``signature_snapshots`` — one row per distinct database content read from
  the source (product, DB version, content hash, counts and the delta against
  the previous snapshot). The content itself is a gzip object under
  ``data/signatures/objects/<hash>.json.gz``.
* ``signature_entries`` — THE index: one row per (product, signature id) with
  its current class, description and lineage (first seen, last seen, removed
  in). Every view that needs "what is signature X" reads here.
* ``signature_changes`` — what each snapshot added, removed or re-described,
  so "which signatures arrived this week" is a query, not a re-walk.
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db


class SignatureSnapshot(db.Model):
    """One distinct signature database content read from the source device."""

    # NOT unique on (product, content_hash): a database that goes A -> B -> A
    # (a FortiGuard rollback) is three transitions, and the index must follow
    # the third. Dedup is against the LATEST snapshot only; the gzip object is
    # shared by hash.
    __tablename__ = "signature_snapshots"

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False, index=True)
    db_version = db.Column(db.String(64), nullable=False, default="")
    engine_version = db.Column(db.String(64), nullable=False, default="")
    firmware = db.Column(db.String(64), nullable=False, default="")
    source_name = db.Column(db.String(128), nullable=False, default="")
    source_appliance_id = db.Column(db.Integer, nullable=True)
    signature_set = db.Column(db.String(128), nullable=False, default="")
    content_hash = db.Column(db.String(64), nullable=False, index=True)
    sig_count = db.Column(db.Integer, nullable=False, default=0)
    subclass_count = db.Column(db.Integer, nullable=False, default=0)
    added = db.Column(db.Integer, nullable=False, default=0)
    removed = db.Column(db.Integer, nullable=False, default=0)
    changed = db.Column(db.Integer, nullable=False, default=0)
    #: the first snapshot of a product: its signatures are the baseline, not "new"
    baseline = db.Column(db.Boolean, nullable=False, default=False)
    prev_snapshot_id = db.Column(db.Integer, nullable=True)
    taken_by = db.Column(db.String(128), nullable=False, default="")
    taken_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)


class SignatureEntry(db.Model):
    """The index: one signature id of one product, as last read."""

    __tablename__ = "signature_entries"
    __table_args__ = (
        db.UniqueConstraint("product", "sig_id", name="uq_signature_entry_product_sig"),
    )

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False, index=True)
    sig_id = db.Column(db.String(64), nullable=False, index=True)
    main_id = db.Column(db.String(32), nullable=False, default="")
    sub_id = db.Column(db.String(32), nullable=False, default="")
    main_name = db.Column(db.String(255), nullable=False, default="")
    sub_name = db.Column(db.String(255), nullable=False, default="")
    description = db.Column(db.Text, nullable=False, default="")
    first_seen_version = db.Column(db.String(64), nullable=False, default="")
    first_seen_at = db.Column(db.DateTime, nullable=True)
    last_seen_version = db.Column(db.String(64), nullable=False, default="")
    last_seen_at = db.Column(db.DateTime, nullable=True)
    #: set when a later snapshot no longer carries the id; cleared if it returns
    removed_in_version = db.Column(db.String(64), nullable=True)
    removed_at = db.Column(db.DateTime, nullable=True)


class SignatureChange(db.Model):
    """One signature a snapshot added, removed or re-described."""

    __tablename__ = "signature_changes"

    KIND_ADDED = "added"
    KIND_REMOVED = "removed"
    KIND_CHANGED = "changed"

    id = db.Column(db.Integer, primary_key=True)
    snapshot_id = db.Column(db.Integer, nullable=False, index=True)
    product = db.Column(db.String(32), nullable=False)
    sig_id = db.Column(db.String(64), nullable=False, index=True)
    kind = db.Column(db.String(16), nullable=False)
    sub_name = db.Column(db.String(255), nullable=False, default="")
    old_description = db.Column(db.Text, nullable=False, default="")
    new_description = db.Column(db.Text, nullable=False, default="")


__all__ = ["SignatureSnapshot", "SignatureEntry", "SignatureChange"]
