"""Device-structure cache models — the local *source of truth* substrate.

Firmware-agnostic: every object and sub-object lands in ``device_objects`` with
its own fields as a JSON(B) payload (children are separate rows linked by
``parent_id``). Hot object types are additionally denormalised into typed
projection tables for cheap list/table views. ``resource_locks`` provides
lease-based pessimistic locking; ``sync_runs`` records every refresh.

All tables are portable: JSON on SQLite (tests), JSONB on PostgreSQL (prod).
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB

from .extensions import db

# JSON on SQLite (tests/dev), JSONB on Postgres (prod GIN-indexable).
JSONType = JSON().with_variant(JSONB(), "postgresql")


class DeviceSnapshot(db.Model):
    """One row per (device, layer, section) capture."""
    __tablename__ = "device_snapshots"

    id = db.Column(db.BigInteger().with_variant(db.Integer, "sqlite"),
                   primary_key=True)
    appliance_id = db.Column(db.Integer,
                             db.ForeignKey("appliances.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    layer = db.Column(db.String(16), nullable=False, default="config")   # config|inventory|report
    section = db.Column(db.String(64), nullable=False, default="_all")
    source = db.Column(db.String(16), nullable=False, default="live")    # live|git|import
    generated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    blob_hash = db.Column(db.String(64), nullable=True)
    object_count = db.Column(db.Integer, nullable=False, default=0)

    __table_args__ = (
        db.Index("ix_device_snapshots_dev_section", "appliance_id", "section"),
    )


class DeviceObject(db.Model):
    """Every object AND sub-object at any depth (self-FK), payload as JSON(B)."""
    __tablename__ = "device_objects"

    id = db.Column(db.BigInteger().with_variant(db.Integer, "sqlite"),
                   primary_key=True)
    appliance_id = db.Column(db.Integer,
                             db.ForeignKey("appliances.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    snapshot_id = db.Column(db.BigInteger().with_variant(db.Integer, "sqlite"),
                            db.ForeignKey("device_snapshots.id", ondelete="CASCADE"),
                            nullable=True, index=True)
    parent_id = db.Column(db.BigInteger().with_variant(db.Integer, "sqlite"),
                          db.ForeignKey("device_objects.id", ondelete="CASCADE"),
                          nullable=True, index=True)
    layer = db.Column(db.String(16), nullable=False, default="config")
    section = db.Column(db.String(64), nullable=False, index=True)
    logical_name = db.Column(db.String(128), nullable=False)   # registry logical name / sub-path
    urn = db.Column(db.String(256), nullable=True)
    mkey = db.Column(db.String(256), nullable=True)            # object name / row id
    subtable = db.Column(db.String(128), nullable=True)        # parent field this row came from
    payload = db.Column(JSONType, nullable=True)               # own scalar fields (no children)
    content_hash = db.Column(db.String(64), nullable=True)
    depth = db.Column(db.Integer, nullable=False, default=0)
    idx = db.Column(db.Integer, nullable=False, default=0)

    __table_args__ = (
        db.Index("ix_device_objects_dev_section", "appliance_id", "section"),
        db.Index("ix_device_objects_dev_logical_mkey",
                 "appliance_id", "logical_name", "mkey"),
    )


# --- hot-type typed projections (denormalised, rebuilt each ingest) ---------

class DeviceServerPolicy(db.Model):
    __tablename__ = "device_server_policies"
    object_id = db.Column(db.BigInteger().with_variant(db.Integer, "sqlite"),
                          db.ForeignKey("device_objects.id", ondelete="CASCADE"),
                          primary_key=True)
    appliance_id = db.Column(db.Integer, index=True, nullable=False)
    name = db.Column(db.String(256), index=True)
    deployment_mode = db.Column(db.String(64))
    vserver = db.Column(db.String(256))
    server_pool = db.Column(db.String(256))
    web_protection_profile = db.Column(db.String(256))
    http_service = db.Column(db.String(64))
    https_service = db.Column(db.String(64))
    monitor_mode = db.Column(db.String(16))
    status = db.Column(db.String(16))


class DeviceServerPool(db.Model):
    __tablename__ = "device_server_pools"
    object_id = db.Column(db.BigInteger().with_variant(db.Integer, "sqlite"),
                          db.ForeignKey("device_objects.id", ondelete="CASCADE"),
                          primary_key=True)
    appliance_id = db.Column(db.Integer, index=True, nullable=False)
    name = db.Column(db.String(256), index=True)
    type = db.Column(db.String(64))
    protocol = db.Column(db.String(64))


class DeviceWebProtectionProfile(db.Model):
    __tablename__ = "device_web_protection_profiles"
    object_id = db.Column(db.BigInteger().with_variant(db.Integer, "sqlite"),
                          db.ForeignKey("device_objects.id", ondelete="CASCADE"),
                          primary_key=True)
    appliance_id = db.Column(db.Integer, index=True, nullable=False)
    name = db.Column(db.String(256), index=True)
    kind = db.Column(db.String(32))   # inline|offline
    signature_rule = db.Column(db.String(256))


# --- concurrency: lease-based pessimistic locks -----------------------------

class ResourceLock(db.Model):
    __tablename__ = "resource_locks"
    id = db.Column(db.BigInteger().with_variant(db.Integer, "sqlite"),
                   primary_key=True)
    appliance_id = db.Column(db.Integer, nullable=False)
    resource_key = db.Column(db.String(256), nullable=False)   # e.g. server_policy:pol-x
    owner_user_id = db.Column(db.Integer, nullable=True)
    owner_label = db.Column(db.String(64), nullable=True)
    acquired_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    heartbeat_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("appliance_id", "resource_key",
                            name="uq_resource_lock_dev_key"),
    )


# --- sync history -----------------------------------------------------------

class SyncRun(db.Model):
    __tablename__ = "sync_runs"
    id = db.Column(db.BigInteger().with_variant(db.Integer, "sqlite"),
                   primary_key=True)
    appliance_id = db.Column(db.Integer, nullable=True, index=True)
    section = db.Column(db.String(64), nullable=True)
    trigger = db.Column(db.String(24), nullable=True)   # manual|scheduled|write_through|backfill
    user_label = db.Column(db.String(64), nullable=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    finished_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(16), nullable=True)    # ok|error|skipped
    changed = db.Column(db.Integer, nullable=False, default=0)
    detail = db.Column(db.Text, nullable=True)


class InventorySnapshot(db.Model):
    """Daily count of how many of each object type EXIST per device (fleet
    inventory trend). One row per (snapshot_date, appliance_id, object_type),
    so counts can be compared across dates on the Metrics page."""
    __tablename__ = "inventory_snapshots"

    id = db.Column(db.BigInteger().with_variant(db.Integer, "sqlite"),
                   primary_key=True)
    snapshot_date = db.Column(db.Date, nullable=False, index=True)
    appliance_id = db.Column(db.Integer, nullable=True, index=True)
    object_type = db.Column(db.String(32), nullable=False)
    count = db.Column(db.Integer, nullable=False, default=0)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("snapshot_date", "appliance_id", "object_type",
                            name="uq_inventory_snapshot_day_dev_type"),
    )
