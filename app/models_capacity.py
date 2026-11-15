"""Factory capacity limits imported from signed packs.

``capacity_factory`` holds, per (product, exact firmware build), the document a
``capacity-limits`` pack item carries (docs section): Fortinet's published
ceilings per CLI table and hardware model, with their scope, and the
FortiWeb-VM rules on the VM's memory. ``services.capacity.factory_for`` reads
it; the admin's own limits stay in ``capacity_limits`` (models.CapacityLimit).

There is no local writer: the harvester reads docs.fortinet.com, a node never
does. ``origin`` = ``pack:<lane>:<pack>``; a newer snapshot replaces an older
one (``api_pack.outranks``).
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db


class CapacityFactory(db.Model):
    """Fortinet's published capacity limits for one build of one product."""

    __tablename__ = "capacity_factory"
    __table_args__ = (
        db.UniqueConstraint("product", "firmware", name="uq_capacity_factory_build"),
    )

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False)
    firmware = db.Column(db.String(32), nullable=False)      # exact X.Y.Z
    #: {"objects": {cli: {"scope", "values", "vm"?, "doubtful"?, "label",
    #: "source"}}, "models": {...}, "sources": [...], "warnings": [...]}
    document = db.Column(db.JSON, nullable=False)
    content_sha = db.Column(db.String(64), nullable=False, default="")
    origin = db.Column(db.String(128), nullable=False, default="")
    imported_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


__all__ = ["CapacityFactory"]
