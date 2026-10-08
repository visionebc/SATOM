"""signature index: snapshots, entries and changes read from the signature source

Revision ID: sigidx01_signature_index
Revises: apipack06_knowledge_lanes
Create Date: 2026-10-08

The operator chooses one FortiWeb as the *signature source*; SATOM reads its
signature database (REST, read-only) and indexes it locally
(``services/signature_index.py``):

* ``signature_snapshots`` — one row per distinct database content.
* ``signature_entries`` — one row per (product, signature id), with lineage.
* ``signature_changes`` — what each snapshot added, removed or re-described.

Idempotent (``app.migration_guard``): ``db.create_all()`` may have created the
tables before alembic reaches this revision.
"""
from alembic import op
import sqlalchemy as sa

from app import migration_guard as mg

revision = 'sigidx01_signature_index'
down_revision = 'apipack06_knowledge_lanes'
branch_labels = None
depends_on = None


def upgrade():
    mg.create_table(
        'signature_snapshots',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('product', sa.String(32), nullable=False),
        sa.Column('db_version', sa.String(64), nullable=False, server_default=''),
        sa.Column('engine_version', sa.String(64), nullable=False, server_default=''),
        sa.Column('firmware', sa.String(64), nullable=False, server_default=''),
        sa.Column('source_name', sa.String(128), nullable=False, server_default=''),
        sa.Column('source_appliance_id', sa.Integer(), nullable=True),
        sa.Column('signature_set', sa.String(128), nullable=False, server_default=''),
        sa.Column('content_hash', sa.String(64), nullable=False),
        sa.Column('sig_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('subclass_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('added', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('removed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('changed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('baseline', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('prev_snapshot_id', sa.Integer(), nullable=True),
        sa.Column('taken_by', sa.String(128), nullable=False, server_default=''),
        sa.Column('taken_at', sa.DateTime(), nullable=False,
                  server_default=sa.func.current_timestamp()),
    )
    mg.create_index('ix_signature_snapshots_product', 'signature_snapshots', ['product'])
    mg.create_index('ix_signature_snapshots_content_hash', 'signature_snapshots',
                    ['content_hash'])
    mg.create_index('ix_signature_snapshots_taken_at', 'signature_snapshots', ['taken_at'])

    mg.create_table(
        'signature_entries',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('product', sa.String(32), nullable=False),
        sa.Column('sig_id', sa.String(64), nullable=False),
        sa.Column('main_id', sa.String(32), nullable=False, server_default=''),
        sa.Column('sub_id', sa.String(32), nullable=False, server_default=''),
        sa.Column('main_name', sa.String(255), nullable=False, server_default=''),
        sa.Column('sub_name', sa.String(255), nullable=False, server_default=''),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('first_seen_version', sa.String(64), nullable=False, server_default=''),
        sa.Column('first_seen_at', sa.DateTime(), nullable=True),
        sa.Column('last_seen_version', sa.String(64), nullable=False, server_default=''),
        sa.Column('last_seen_at', sa.DateTime(), nullable=True),
        sa.Column('removed_in_version', sa.String(64), nullable=True),
        sa.Column('removed_at', sa.DateTime(), nullable=True),
        sa.UniqueConstraint('product', 'sig_id', name='uq_signature_entry_product_sig'),
    )
    mg.create_index('ix_signature_entries_product', 'signature_entries', ['product'])
    mg.create_index('ix_signature_entries_sig_id', 'signature_entries', ['sig_id'])

    mg.create_table(
        'signature_changes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('snapshot_id', sa.Integer(), nullable=False),
        sa.Column('product', sa.String(32), nullable=False),
        sa.Column('sig_id', sa.String(64), nullable=False),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('sub_name', sa.String(255), nullable=False, server_default=''),
        sa.Column('old_description', sa.Text(), nullable=False, server_default=''),
        sa.Column('new_description', sa.Text(), nullable=False, server_default=''),
    )
    mg.create_index('ix_signature_changes_snapshot_id', 'signature_changes', ['snapshot_id'])
    mg.create_index('ix_signature_changes_sig_id', 'signature_changes', ['sig_id'])


def downgrade():
    insp = sa.inspect(op.get_bind())
    for table in ('signature_changes', 'signature_entries', 'signature_snapshots'):
        if table in insp.get_table_names():
            op.drop_table(table)
