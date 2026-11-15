"""observatory_scans

Revision ID: obsrv01
Revises: certrot01
Create Date: 2026-10-16

``observatory_scans``: one row per graded site per HTTP Observatory run
(Troubleshooting → HTTP Observatory, the ``observatory_scan`` scheduled
action and the re-scan after a fix). Keeps headers, statuses, redirect routes
and cookie flags — never cookie values or page bodies.

Idempotent like the revisions before it: ``db.create_all()`` in
``app/__init__.py`` makes the same table on boot, so a running node already
has it before alembic reaches this one.
"""
from alembic import op
import sqlalchemy as sa

revision = 'obsrv01'
down_revision = 'certrot01'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'observatory_scans' in insp.get_table_names():
        return
    op.create_table(
        'observatory_scans',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('appliance_id', sa.Integer(),
                  sa.ForeignKey('appliances.id', ondelete='CASCADE'), nullable=False),
        sa.Column('product', sa.String(32), nullable=False, server_default='fortiweb'),
        sa.Column('policy', sa.String(128), nullable=False),
        sa.Column('host', sa.String(255), nullable=False, server_default=''),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('grade', sa.String(3), nullable=True),
        sa.Column('score', sa.Integer(), nullable=True),
        sa.Column('tests_passed', sa.Integer(), nullable=True),
        sa.Column('tests_failed', sa.Integer(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('result', sa.Text(), nullable=True),
        sa.Column('trigger', sa.String(16), nullable=False, server_default='manual'),
        sa.Column('username', sa.String(64), nullable=True),
    )
    op.create_index('ix_observatory_scans_appliance_id', 'observatory_scans', ['appliance_id'])
    op.create_index('ix_observatory_scans_site', 'observatory_scans',
                    ['appliance_id', 'policy', 'started_at'])


def downgrade():
    bind = op.get_bind()
    if 'observatory_scans' in sa.inspect(bind).get_table_names():
        op.drop_table('observatory_scans')
