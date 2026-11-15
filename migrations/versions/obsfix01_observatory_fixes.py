"""observatory_fixes

Revision ID: obsfix01
Revises: obsrv01
Create Date: 2026-10-16

``observatory_fixes``: one row per applied set of HTTP Observatory fixes —
the writes in order, what each found before, the row ids they created — so
Troubleshooting → HTTP Observatory can revert them. Header values and cookie
flags only, never a secret.

Idempotent like the revisions before it: ``db.create_all()`` in
``app/__init__.py`` makes the same table on boot.
"""
from alembic import op
import sqlalchemy as sa

revision = 'obsfix01'
down_revision = 'obsrv01'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'observatory_fixes' in insp.get_table_names():
        return
    op.create_table(
        'observatory_fixes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('appliance_id', sa.Integer(),
                  sa.ForeignKey('appliances.id', ondelete='CASCADE'), nullable=False),
        sa.Column('policy', sa.String(128), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('after_scan_id', sa.Integer(), nullable=True),
        sa.Column('applied_at', sa.DateTime(), nullable=False),
        sa.Column('username', sa.String(64), nullable=True),
        sa.Column('fixes', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('steps', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('others', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('ok', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('reverted_at', sa.DateTime(), nullable=True),
        sa.Column('reverted_by', sa.String(64), nullable=True),
        sa.Column('revert_result', sa.Text(), nullable=True),
    )
    op.create_index('ix_observatory_fixes_appliance_id', 'observatory_fixes', ['appliance_id'])
    op.create_index('ix_observatory_fixes_site', 'observatory_fixes',
                    ['appliance_id', 'policy', 'applied_at'])


def downgrade():
    bind = op.get_bind()
    if 'observatory_fixes' in sa.inspect(bind).get_table_names():
        op.drop_table('observatory_fixes')
