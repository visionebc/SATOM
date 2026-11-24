"""Profiles: device scope (which devices / partitions inside the ADOMs)

Revision ID: ds01
Revises: wsm02
Create Date: 2026-11-07

``profiles.device_scope`` (JSON, '' = no scope). Every existing profile gets
'' so nothing changes on upgrade. Idempotent (app.migration_guard).
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'ds01'
down_revision = 'wsm02'
branch_labels = None
depends_on = None


def upgrade():
    if guard.has_table('profiles') and not guard.has_column('profiles', 'device_scope'):
        op.add_column('profiles', sa.Column('device_scope', sa.Text(), nullable=False,
                                            server_default=''))


def downgrade():
    if guard.has_column('profiles', 'device_scope'):
        op.drop_column('profiles', 'device_scope')
