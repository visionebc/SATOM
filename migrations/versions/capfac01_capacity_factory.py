"""Capacity: factory limits from the packs + the catalog keyed by platform

Revision ID: capfac01
Revises: massdep01
Create Date: 2026-10-24

``capacity_factory`` (app/models_capacity.py) holds Fortinet's published
limits per exact build, imported from ``capacity-limits`` pack items.

``capacity_limits.model`` was the string ``get system status`` printed, which
on FortiWeb carries the firmware ("FortiWeb-KVM 7.6.8"): one catalog "model"
per patch release, and none of them a model Fortinet publishes limits for.
Rows are re-keyed to the platform (``FortiWeb-VM``, ``FortiWeb-1000F``); when
two rows collapse onto one key, the row the admin filled in wins and the empty
duplicates go. Idempotent (app.migration_guard).
"""
import re

from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'capfac01'
down_revision = 'massdep01'
branch_labels = None
depends_on = None

_VM = re.compile(r"\b(?:VM\d*|KVM|VMWARE|HYPERV|HYPER-V|XEN|AWS|AZURE|GCP|OCI|"
                 r"ALI(?:CLOUD)?|OPC|NUTANIX)\b", re.I)


def _platform(model, product):
    """Same rule as services.capacity.catalog_model (frozen copy: a migration
    must not import code that moves)."""
    s = str(model or "").strip()
    prefix = {"fortiweb": "FortiWeb", "fortiadc": "FortiADC",
              "fortigate": "FortiGate"}.get(product or "fortiweb", "")
    if not s or not ((prefix and s.lower().startswith(prefix.lower())) or _VM.search(s)):
        return s or None
    s = re.sub(r"\s+v?\d+\.\d+(?:\.\d+)?\b.*$", "", s)
    if prefix:
        s = re.sub(r"^%s" % prefix, "", s, flags=re.I)
    s = s.strip(" -_")
    if _VM.search(s) or s.upper().startswith("VM"):
        pid = "VM16" if s.upper() == "VM16" else "VM"
    else:
        pid = re.sub(r"[\s\-_]+", "", s).upper()
    if not pid:
        return None
    return "%s-%s" % (prefix or product, pid)


def upgrade():
    guard.create_table(
        'capacity_factory',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('product', sa.String(32), nullable=False),
        sa.Column('firmware', sa.String(32), nullable=False),
        sa.Column('document', sa.JSON(), nullable=False),
        sa.Column('content_sha', sa.String(64), nullable=False, server_default=''),
        sa.Column('origin', sa.String(128), nullable=False, server_default=''),
        sa.Column('imported_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('product', 'firmware', name='uq_capacity_factory_build'))

    conn = op.get_bind()
    rows = conn.execute(sa.text(
        "SELECT id, product, firmware_major, model, object_type, hard_max, "
        "operational_cap, cap_percent FROM capacity_limits ORDER BY id")).fetchall()
    keep = {}
    for r in rows:
        target = _platform(r.model, r.product) or r.model
        key = (r.product, r.firmware_major, target, r.object_type)
        filled = any(v is not None for v in (r.hard_max, r.operational_cap, r.cap_percent))
        if key not in keep:
            keep[key] = (r.id, filled)
            continue
        kid, kfilled = keep[key]
        drop = r.id if (kfilled or not filled) else kid
        if drop == kid:
            keep[key] = (r.id, filled)
        conn.execute(sa.text("DELETE FROM capacity_limits WHERE id = :i"), {"i": drop})
    for (product, fw, target, otype), (rid, _f) in keep.items():
        conn.execute(sa.text("UPDATE capacity_limits SET model = :m WHERE id = :i"),
                     {"m": target, "i": rid})


def downgrade():
    op.drop_table('capacity_factory')
