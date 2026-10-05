"""Factory catalog — the vendor's predefined objects, stored once per build.

A FortiWeb ships ~20 predefined Web Protection Profiles (10 inline, 10
offline) and every appliance on the same firmware serves the same trees. The
deep pass used to walk all of them on every appliance, every sweep: up to ~125
device reads each, the bulk of a sweep's work, to re-read content the vendor
wrote. Design contract: ``services/factory_catalog.py``.

One row is one VARIANT of one predefined object on one exact surface:
(product, firmware, build number, REST API version, kind, name) plus the hash
of its normalised tree. Firmware AND API version are part of the key because
both change what a predefined object contains: a newer build adds fields
(fortiweb17 serves six more on "Inline Standard Protection" than 7.6.8 does),
and a body is only meaningful against the API surface it was read through.

More than one variant per key is allowed on purpose. A predefined object is
expected to be identical across appliances on one build; when two appliances
disagree, both trees are kept and the catalog stops trusting itself for that
object (``status = ambiguous``) instead of picking one.

``captured_from_id`` is a plain integer, not a foreign key: like the API
library's evidence, an entry outlives the appliance it was read from.
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db


class FactoryObject(db.Model):
    """One variant of one predefined object, read in full from an appliance."""

    __tablename__ = "factory_catalog"
    __table_args__ = (
        db.UniqueConstraint("product", "firmware", "build_no", "api_version",
                            "kind", "name", "content_sha",
                            name="uq_factory_catalog_variant"),
        db.Index("ix_factory_catalog_surface", "product", "firmware",
                 "build_no", "api_version"),
        db.Index("ix_factory_catalog_name", "product", "kind", "name"),
    )

    STATUS_OK = "ok"
    #: two variants share the top-level rows but not the tree: the catalog
    #: cannot tell which one an appliance has without reading it, so it reads.
    STATUS_AMBIGUOUS = "ambiguous"

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False, default="fortiweb")
    #: ``firmware_versions.normalize`` of the appliance's firmware (``7.6.8``).
    firmware = db.Column(db.String(32), nullable=False)
    #: the build number off the raw firmware string (``1128`` from
    #: ``7.6.8,build1128``); "" when the appliance did not report one.
    build_no = db.Column(db.String(16), nullable=False, default="")
    #: ``template_compat.api_version_for(product)`` — the same stamp a template
    #: carries, so a catalog entry and a template can be compared directly.
    api_version = db.Column(db.String(16), nullable=False, default="")
    #: ``wpp_inline`` | ``wpp_offline``
    kind = db.Column(db.String(32), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    urn = db.Column(db.String(255), nullable=False, default="")
    #: sha256 of the normalised tree (handles, clock and reverse-reference
    #: counters removed): what this variant IS.
    content_sha = db.Column(db.String(64), nullable=False)
    #: sha256 of the normalised top-level rows only: what an appliance can be
    #: checked against without reading a single sub-table.
    top_sha = db.Column(db.String(64), nullable=False)
    #: gzip(JSON) of {"tree", "top", "reads"} — the full nested tree as the
    #: deep pass built it, the top-level rows it found, and every scoped read
    #: it made, so the walk can be replayed without the appliance.
    payload = db.Column(db.LargeBinary, nullable=False)
    node_count = db.Column(db.Integer, nullable=False, default=0)
    read_count = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(16), nullable=False, default=STATUS_OK)
    status_reason = db.Column(db.String(255), nullable=False, default="")
    firmware_raw = db.Column(db.String(128), nullable=False, default="")
    captured_from_id = db.Column(db.Integer, nullable=True)
    captured_from = db.Column(db.String(128), nullable=False, default="")
    captured_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    #: the last full walk (by any appliance on this surface) that read exactly
    #: this variant. Older than the reverify window -> the next sweep walks it.
    last_verified_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_verified_from = db.Column(db.String(128), nullable=False, default="")
    verify_count = db.Column(db.Integer, nullable=False, default=1)
    reuse_count = db.Column(db.Integer, nullable=False, default=0)
    last_reused_at = db.Column(db.DateTime, nullable=True)
