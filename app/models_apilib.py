"""API library tables — versioned, append-only evidence about vendor APIs.

Design contract: ``docs/api-library.md``. The short version of why these are
tables and not the old ``data/api_matrix/*.json`` files: that store was derived
and rewritten wholesale on every rebuild, and evidence from appliances that
had been deleted was filtered out on the way. That is how the 8.0.3 evidence
disappeared. Here evidence is stored once, facts are keyed by
(thing, build, source) so they grow with the number of distinct builds rather
than with the number of sweeps, and no code path in the feature deletes a row.

Portable on purpose (``db.JSON``, ``db.LargeBinary``): production is
PostgreSQL, the test suite is SQLite, and both must build the same schema from
``db.create_all()`` at boot as well as from migration ``apilib01``.

``appliance_id`` on evidence is a plain integer, NOT a foreign key: the
appliance table is ON DELETE CASCADE all the way down, and evidence has to
outlive the device it was measured on.
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db


class ApiLibBuild(db.Model):
    """One firmware version of one product that the library knows about.

    ``version`` is ``firmware_versions.normalize`` output: ``8.0.5``, or
    ``8.0`` when only the line is known (``line_only``). ``sort_key`` is the
    zero-padded form (``00008.00000.00005``) so a vendor range can be resolved
    with a plain string comparison in SQL.
    """

    __tablename__ = "api_lib_build"
    __table_args__ = (
        db.UniqueConstraint("product", "version", name="uq_api_lib_build_product_version"),
        db.Index("ix_api_lib_build_product_sort", "product", "sort_key"),
    )

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False)
    version = db.Column(db.String(32), nullable=False)
    build = db.Column(db.String(32), nullable=False, default="")
    line = db.Column(db.String(16), nullable=False, default="")
    line_only = db.Column(db.Boolean, nullable=False, default=False)
    sort_key = db.Column(db.String(64), nullable=False, default="")
    #: 'evidence' | 'vendor' | 'declared' — the strongest reason the row
    #: exists. Upgraded (declared -> vendor -> evidence), never downgraded.
    origin = db.Column(db.String(16), nullable=False, default="evidence")
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class ApiLibEvidence(db.Model):
    """One harvest, stored once. Identical content only bumps confirmations."""

    __tablename__ = "api_lib_evidence"
    __table_args__ = (
        db.UniqueConstraint("product", "source", "sha256",
                            name="uq_api_lib_evidence_product_source_sha"),
        db.Index("ix_api_lib_evidence_product_source", "product", "source"),
    )

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False)
    source = db.Column(db.String(16), nullable=False)
    build_id = db.Column(db.Integer, db.ForeignKey("api_lib_build.id"),
                         nullable=True, index=True)
    scope_kind = db.Column(db.String(8), nullable=False, default="build")
    # Device identity is COPIED here, not referenced: see the module docstring.
    appliance_id = db.Column(db.Integer, nullable=True, index=True)
    device_name = db.Column(db.String(128), nullable=False, default="")
    device_serial = db.Column(db.String(64), nullable=False, default="")
    device_model = db.Column(db.String(128), nullable=False, default="")
    device_hw_type = db.Column(db.String(16), nullable=False, default="")
    firmware_raw = db.Column(db.String(128), nullable=False, default="")
    origin_ref = db.Column(db.String(255), nullable=False, default="")
    captured_at = db.Column(db.DateTime, nullable=True)
    ingested_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_confirmed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    confirmations = db.Column(db.Integer, nullable=False, default=1)
    sha256 = db.Column(db.String(64), nullable=False)
    #: False => stored for the record, never folded into facts.
    healthy = db.Column(db.Boolean, nullable=False, default=True)
    skip_reason = db.Column(db.String(500), nullable=False, default="")
    summary = db.Column(db.JSON, nullable=True)
    raw_gz = db.Column(db.LargeBinary, nullable=True)


class ApiLibEndpoint(db.Model):
    __tablename__ = "api_lib_endpoint"
    __table_args__ = (
        db.UniqueConstraint("product", "name", name="uq_api_lib_endpoint_product_name"),
    )

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False)
    name = db.Column(db.String(160), nullable=False)
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class ApiLibEndpointFact(db.Model):
    """What one source says about one endpoint on one build."""

    __tablename__ = "api_lib_endpoint_fact"
    __table_args__ = (
        db.UniqueConstraint("endpoint_id", "build_id", "source",
                            name="uq_api_lib_endpoint_fact_key"),
        db.Index("ix_api_lib_endpoint_fact_build", "build_id", "source"),
    )

    id = db.Column(db.Integer, primary_key=True)
    endpoint_id = db.Column(db.Integer, db.ForeignKey("api_lib_endpoint.id"),
                            nullable=False)
    build_id = db.Column(db.Integer, db.ForeignKey("api_lib_build.id"), nullable=False)
    source = db.Column(db.String(16), nullable=False)
    urn = db.Column(db.String(255), nullable=False, default="")
    section = db.Column(db.String(128), nullable=False, default="")
    verdict = db.Column(db.String(16), nullable=False, default="error")
    #: True once any healthy witness revealed the field set (possibly empty).
    #: False = blind: the endpoint answered, its fields are unknown.
    fields_known = db.Column(db.Boolean, nullable=False, default=False)
    witnesses = db.Column(db.JSON, nullable=True)
    first_evidence_id = db.Column(db.Integer, nullable=True)
    last_evidence_id = db.Column(db.Integer, nullable=True)
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class ApiLibField(db.Model):
    __tablename__ = "api_lib_field"
    __table_args__ = (
        db.UniqueConstraint("endpoint_id", "name", name="uq_api_lib_field_endpoint_name"),
    )

    id = db.Column(db.Integer, primary_key=True)
    endpoint_id = db.Column(db.Integer, db.ForeignKey("api_lib_endpoint.id"),
                            nullable=False)
    name = db.Column(db.String(160), nullable=False)
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class ApiLibFieldFact(db.Model):
    """What one source says about one field on one build."""

    __tablename__ = "api_lib_field_fact"
    __table_args__ = (
        db.UniqueConstraint("field_id", "build_id", "source",
                            name="uq_api_lib_field_fact_key"),
        db.Index("ix_api_lib_field_fact_build", "build_id", "source"),
    )

    id = db.Column(db.Integer, primary_key=True)
    field_id = db.Column(db.Integer, db.ForeignKey("api_lib_field.id"), nullable=False)
    build_id = db.Column(db.Integer, db.ForeignKey("api_lib_build.id"), nullable=False)
    source = db.Column(db.String(16), nullable=False)
    type = db.Column(db.String(32), nullable=True)
    options = db.Column(db.JSON, nullable=True)
    default = db.Column(db.JSON, nullable=True)
    required = db.Column(db.Boolean, nullable=True)
    children = db.Column(db.JSON, nullable=True)
    platforms = db.Column(db.JSON, nullable=True)
    first_evidence_id = db.Column(db.Integer, nullable=True)
    last_evidence_id = db.Column(db.Integer, nullable=True)
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class ApiLibSpan(db.Model):
    """A vendor-claimed version range, stored once and resolved per query.

    ``field_id`` NULL = the span of the endpoint itself. ``to_key`` NULL = open
    end, which the reader caps at the evidence's ``summary.max_version``.
    """

    __tablename__ = "api_lib_span"
    __table_args__ = (
        db.Index("ix_api_lib_span_evidence_endpoint", "evidence_id", "endpoint_id"),
        db.Index("ix_api_lib_span_field", "field_id"),
        db.Index("ix_api_lib_span_from", "from_key"),
    )

    id = db.Column(db.Integer, primary_key=True)
    endpoint_id = db.Column(db.Integer, db.ForeignKey("api_lib_endpoint.id"),
                            nullable=False)
    field_id = db.Column(db.Integer, db.ForeignKey("api_lib_field.id"), nullable=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey("api_lib_evidence.id"),
                            nullable=False)
    source = db.Column(db.String(16), nullable=False, default="vendor_doc")
    from_key = db.Column(db.String(64), nullable=False)
    to_key = db.Column(db.String(64), nullable=True)
    from_version = db.Column(db.String(32), nullable=False, default="")
    to_version = db.Column(db.String(32), nullable=False, default="")
    attrs = db.Column(db.JSON, nullable=True)


class ApiLibFieldMap(db.Model):
    """An operator-authored rename. Without it a rename reads as lost + added.

    Never deleted (rows are append-only like the rest of the library): a wrong
    or superseded mapping is RETIRED — ``retired_at`` set — and every reader
    skips it, while the audit trail keeps what was believed and when.
    """

    __tablename__ = "api_lib_field_map"
    __table_args__ = (
        db.Index("ix_api_lib_field_map_product_endpoint", "product", "endpoint"),
    )

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False)
    endpoint = db.Column(db.String(160), nullable=False)
    from_version = db.Column(db.String(32), nullable=False, default="")
    from_field = db.Column(db.String(160), nullable=False)
    to_version = db.Column(db.String(32), nullable=False, default="")
    to_field = db.Column(db.String(160), nullable=False)
    note = db.Column(db.String(500), nullable=False, default="")
    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    #: NULL = in force. Set once, never cleared: re-adding the mapping is a new row.
    retired_at = db.Column(db.DateTime, nullable=True)
    retired_by = db.Column(db.String(64), nullable=False, default="")


__all__ = [
    "ApiLibBuild", "ApiLibEvidence", "ApiLibEndpoint", "ApiLibEndpointFact",
    "ApiLibField", "ApiLibFieldFact", "ApiLibSpan", "ApiLibFieldMap",
]
