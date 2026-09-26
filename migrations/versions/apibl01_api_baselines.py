"""api_lib_baseline* — endpoint baselines pinned to a firmware build

Revision ID: apibl01
Revises: apilib01
Create Date: 2026-09-26

The endpoint registry used to be seeded from four hand-written
``endpoints*.yaml`` files that said nothing about which firmware they described.
A baseline is promoted from what the API library measured on one build, sealed
with a content hash, and shipped as a generated artifact
(``app/registry/baselines/<product>.json``). Design: ``docs/api-library.md`` §9.

Schema only. The baseline DATA does not travel through alembic: a fresh
installation builds its schema with ``db.create_all()`` and never runs
``flask db upgrade``, so a data migration would never reach it. The app applies
the shipped artifacts at boot (``api_baseline.boot``) on every install path.
"""
from alembic import op
import sqlalchemy as sa

revision = 'apibl01'
down_revision = 'apilib01'
branch_labels = None
depends_on = None

_NOW = sa.text('CURRENT_TIMESTAMP')


def upgrade():
    # Idempotent per table: db.create_all() at boot may have made them first.
    existing = set(sa.inspect(op.get_bind()).get_table_names())

    if 'api_lib_baseline' not in existing:
        op.create_table(
            'api_lib_baseline',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('product', sa.String(32), nullable=False),
            sa.Column('version', sa.String(32), nullable=False),
            sa.Column('api_version', sa.String(16), nullable=False, server_default=''),
            sa.Column('sha256', sa.String(64), nullable=False),
            sa.Column('method', sa.String(16), nullable=False, server_default='promoted'),
            sa.Column('promoted_at', sa.DateTime(), nullable=False, server_default=_NOW),
            sa.Column('promoted_by', sa.String(64), nullable=False, server_default=''),
            sa.Column('note', sa.String(500), nullable=False, server_default=''),
            sa.Column('applied_at', sa.DateTime(), nullable=True),
            sa.UniqueConstraint('product', 'sha256', name='uq_api_lib_baseline_product_sha'),
        )
        op.create_index('ix_api_lib_baseline_product_promoted', 'api_lib_baseline',
                        ['product', 'promoted_at'])

    if 'api_lib_baseline_entry' not in existing:
        op.create_table(
            'api_lib_baseline_entry',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('baseline_id', sa.Integer(), sa.ForeignKey('api_lib_baseline.id'),
                      nullable=False),
            sa.Column('name', sa.String(160), nullable=False),
            sa.Column('urn', sa.String(255), nullable=False),
            sa.Column('provenance', sa.String(16), nullable=False,
                      server_default='measured'),
            sa.Column('measured_on', sa.String(32), nullable=False, server_default=''),
            sa.UniqueConstraint('baseline_id', 'name',
                                name='uq_api_lib_baseline_entry_name'),
        )
        op.create_index('ix_api_lib_baseline_entry_baseline_id',
                        'api_lib_baseline_entry', ['baseline_id'])


def downgrade():
    op.drop_index('ix_api_lib_baseline_entry_baseline_id', 'api_lib_baseline_entry')
    op.drop_table('api_lib_baseline_entry')
    op.drop_index('ix_api_lib_baseline_product_promoted', 'api_lib_baseline')
    op.drop_table('api_lib_baseline')
