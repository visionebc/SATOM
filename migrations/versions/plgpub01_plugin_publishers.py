"""Trusted plugin publishers: Ed25519 keys a super-admin registers

Revision ID: plgpub01
Revises: procdrop01
Create Date: 2026-10-25

``plugin_publishers`` holds the public keys (besides the Vision EBC keys
pinned in ``plugin_package.TRUSTED_KEYS``) whose signature a plugin package
import trusts while the row is enabled: one row per key, ``key_id`` = sha256
hex of the raw 32-byte key, ``adom_keys`` an optional JSON list of ADOMs.
Idempotent (app.migration_guard).
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'plgpub01'
down_revision = 'procdrop01'
branch_labels = None
depends_on = None


def upgrade():
    guard.create_table(
        "plugin_publishers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("label", sa.String(80), nullable=False),
        sa.Column("public_key", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("adom_keys", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    guard.create_index(op.f("ix_plugin_publishers_key_id"), "plugin_publishers",
                       ["key_id"], unique=True)


def downgrade():
    op.drop_index(op.f("ix_plugin_publishers_key_id"), table_name="plugin_publishers")
    op.drop_table("plugin_publishers")
