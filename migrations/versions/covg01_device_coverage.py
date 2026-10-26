"""Device cache coverage and the author of API-created device objects

Revision ID: covg01
Revises: plgds01
Create Date: 2026-10-26

``device_coverage`` (which tables the last good sweep read, empty ones
included) and ``api_object_authors`` (who created a FortiADC rule through the
API, so a DELETE can prove ownership), app/models_cache.py.
Idempotent (app.migration_guard): create_all may already have made the tables.
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'covg01'
down_revision = 'plgds01'
branch_labels = None
depends_on = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), 'postgresql')


def upgrade():
    guard.create_table(
        'device_coverage',
        sa.Column('appliance_id', sa.Integer(),
                  sa.ForeignKey('appliances.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('layer', sa.String(16), nullable=False, server_default='config'),
        sa.Column('swept_at', sa.DateTime(), nullable=False),
        sa.Column('build', sa.String(32), nullable=False, server_default=''),
        sa.Column('tables', _JSON, nullable=False),
        sa.Column('failed', _JSON, nullable=False))
    if guard.create_table(
            'api_object_authors',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('appliance_id', sa.Integer(),
                      sa.ForeignKey('appliances.id', ondelete='CASCADE'), nullable=False),
            sa.Column('product', sa.String(32), nullable=False, server_default='fortiadc'),
            sa.Column('logical', sa.String(128), nullable=False),
            sa.Column('mkey', sa.String(256), nullable=False),
            sa.Column('author', sa.String(64), nullable=False),
            sa.Column('sent', _JSON, nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.UniqueConstraint('appliance_id', 'logical', 'mkey',
                                name='uq_api_object_author')):
        op.create_index('ix_api_object_authors_appliance_id', 'api_object_authors',
                        ['appliance_id'])


def downgrade():
    op.drop_table('api_object_authors')
    op.drop_table('device_coverage')
