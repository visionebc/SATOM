"""python studio: API Catalog (APIs, versions) and a connection's pinned version

Revision ID: studio02
Revises: coll01
Create Date: 2026-10-21

FA-0006. ``studio_apis`` and ``studio_api_versions`` (app/models_studio.py,
services/studio_apis.py) and ``studio_connections.api_version_id``.
Idempotent (app.migration_guard): create_all may already have made the tables.
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'studio02'
down_revision = 'coll01'
branch_labels = None
depends_on = None


def _stamps():
    return [
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('updated_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    ]


def upgrade():
    if guard.create_table(
            'studio_apis',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('slug', sa.String(48), nullable=False, unique=True),
            sa.Column('name', sa.String(120), nullable=False),
            sa.Column('owner', sa.String(120), nullable=False, server_default=''),
            sa.Column('docs_url', sa.String(500), nullable=False, server_default=''),
            sa.Column('description', sa.Text(), nullable=False, server_default=''),
            *_stamps()):
        op.create_index('ix_studio_apis_slug', 'studio_apis', ['slug'])
    if guard.create_table(
            'studio_api_versions',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('api_id', sa.Integer(),
                      sa.ForeignKey('studio_apis.id', ondelete='CASCADE'), nullable=False),
            sa.Column('version', sa.String(32), nullable=False),
            sa.Column('status', sa.String(16), nullable=False, server_default='draft'),
            sa.Column('source', sa.String(16), nullable=False, server_default='manual'),
            sa.Column('base_path', sa.String(200), nullable=False, server_default=''),
            sa.Column('spec_sha256', sa.String(64), nullable=False, server_default=''),
            sa.Column('operations_json', sa.Text(), nullable=False, server_default='[]'),
            sa.Column('notes', sa.Text(), nullable=False, server_default=''),
            *_stamps(),
            sa.Column('published_by', sa.String(64), nullable=False, server_default=''),
            sa.Column('published_at', sa.DateTime(), nullable=True),
            sa.UniqueConstraint('api_id', 'version', name='uq_studio_api_version')):
        op.create_index('ix_studio_api_versions_api_id', 'studio_api_versions', ['api_id'])
    guard.add_column('studio_connections',
                     sa.Column('api_version_id', sa.Integer(), nullable=True))
    guard.create_index('ix_studio_connections_api_version_id', 'studio_connections',
                       ['api_version_id'])
    guard.create_foreign_key('fk_studio_connections_api_version', 'studio_connections',
                             'studio_api_versions', ['api_version_id'], ['id'])


def downgrade():
    with op.batch_alter_table('studio_connections') as batch:
        batch.drop_column('api_version_id')
    op.drop_table('studio_api_versions')
    op.drop_table('studio_apis')
