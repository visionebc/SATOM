"""Diagram Studio: folders, diagrams, versions, imports, symbol libraries

Revision ID: diagstudio01
Revises: appview01
Create Date: 2026-11-17

The five tables of app/models_diagrams.py. Idempotent (app.migration_guard):
create_all may already have made every table and index.
"""
from alembic import op  # noqa: F401 -- alembic loads every revision with op in scope
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'diagstudio01'
down_revision = 'appview01'
branch_labels = None
depends_on = None


def upgrade():
    guard.create_table(
        'diagram_folders',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(64), nullable=False),
        sa.Column('parent_id', sa.Integer(),
                  sa.ForeignKey('diagram_folders.id', ondelete='RESTRICT'), nullable=True),
        sa.Column('position', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('adom', sa.String(32), nullable=False, server_default=''),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False))
    guard.create_index('ix_diagram_folders_parent_id', 'diagram_folders', ['parent_id'])
    guard.create_index('ix_diagram_folders_adom', 'diagram_folders', ['adom'])

    guard.create_table(
        'diagrams',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('folder_id', sa.Integer(),
                  sa.ForeignKey('diagram_folders.id', ondelete='SET NULL'), nullable=True),
        sa.Column('adom', sa.String(32), nullable=False, server_default=''),
        sa.Column('owner_id', sa.Integer(),
                  sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('published', sa.Boolean(), nullable=False),
        sa.Column('published_at', sa.DateTime(), nullable=True),
        sa.Column('published_version', sa.Integer(), nullable=True),
        sa.Column('current_version', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('source_format', sa.String(32), nullable=False, server_default=''),
        sa.Column('source_filename', sa.String(255), nullable=False, server_default=''),
        sa.Column('source_sha256', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('updated_at', sa.DateTime(), nullable=False))
    guard.create_index('ix_diagrams_folder_id', 'diagrams', ['folder_id'])
    guard.create_index('ix_diagrams_adom', 'diagrams', ['adom'])

    guard.create_table(
        'diagram_versions',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('diagram_id', sa.Integer(),
                  sa.ForeignKey('diagrams.id', ondelete='CASCADE'), nullable=False),
        sa.Column('number', sa.Integer(), nullable=False),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('doc_gz', sa.LargeBinary(), nullable=False),
        sa.Column('stats_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('note', sa.String(500), nullable=False, server_default=''),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('diagram_id', 'number', name='uq_diagram_versions_number'))
    guard.create_index('ix_diagram_versions_sha', 'diagram_versions', ['diagram_id', 'sha256'])

    guard.create_table(
        'diagram_imports',
        sa.Column('id', sa.String(40), primary_key=True),
        sa.Column('status', sa.String(16), nullable=False, server_default='queued'),
        sa.Column('filename', sa.String(255), nullable=False, server_default=''),
        sa.Column('format', sa.String(32), nullable=False, server_default=''),
        sa.Column('source_sha256', sa.String(64), nullable=False, server_default=''),
        sa.Column('options_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('error', sa.String(1000), nullable=False, server_default=''),
        sa.Column('adom', sa.String(32), nullable=False, server_default=''),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('diagram_id', sa.Integer(),
                  sa.ForeignKey('diagrams.id', ondelete='SET NULL'), nullable=True))
    guard.create_index('ix_diagram_imports_adom', 'diagram_imports', ['adom'])

    guard.create_table(
        'diagram_libraries',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('lib_id', sa.String(48), nullable=False, unique=True),
        sa.Column('label', sa.String(80), nullable=False),
        sa.Column('family', sa.String(32), nullable=False, server_default='generic'),
        sa.Column('library_json', sa.Text(), nullable=False),
        sa.Column('svgs_gz', sa.LargeBinary(), nullable=False),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False))


def downgrade():
    op.drop_table('diagram_libraries')
    op.drop_table('diagram_imports')
    op.drop_table('diagram_versions')
    op.drop_table('diagrams')
    op.drop_table('diagram_folders')
