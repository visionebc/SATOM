"""Edit leases: remember which editor (browser tab) holds one

Revision ID: leasetok01
Revises: notifkind01
Create Date: 2026-11-04

``resource_locks.owner_token`` names the tab that took the lease, so the same
operator with an object open in two tabs is told about it instead of the two
tabs overwriting each other. NULL (every existing lease, and every caller that
sends no token) keeps the old per-user behaviour. Idempotent
(app.migration_guard); the boot path adds the column too (_ensure_columns).
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'leasetok01'
down_revision = 'notifkind01'
branch_labels = None
depends_on = None


def upgrade():
    guard.add_column('resource_locks',
                     sa.Column('owner_token', sa.String(64), nullable=True))


def downgrade():
    op.drop_column('resource_locks', 'owner_token')
