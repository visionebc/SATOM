"""diag_catalogs + diag_batteries + appliances.ssh_username

Revision ID: diagbat01
Revises: netarch01
Create Date: 2026-10-14

``diag_catalogs``: the ``diagnose`` commands each (product, build) answered
for in a discovery walk. ``diag_batteries``: the commands an administrator
picked per ADOM for Diagnose Log Collection. ``appliances.ssh_username``: the
CLI login when it is not the API user (a FortiGate registered with a REST
api-user cannot open SSH with it). NULL keeps the old behaviour (SSH logs in
as ``username``).

Idempotent like the revisions before it: ``_ensure_columns()`` and
``db.create_all()`` in ``app/__init__.py`` make the same column and tables on
boot, so a running node already has them before alembic reaches this one.
"""
from alembic import op
import sqlalchemy as sa

revision = 'diagbat01'
down_revision = 'netarch01'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()
    if 'appliances' in tables and 'ssh_username' not in {
            c['name'] for c in insp.get_columns('appliances')}:
        op.add_column('appliances', sa.Column('ssh_username', sa.String(64), nullable=True))
    if 'diag_catalogs' not in tables:
        op.create_table(
            'diag_catalogs',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('product', sa.String(32), nullable=False),
            sa.Column('build', sa.String(32), nullable=False),
            sa.Column('firmware', sa.String(128), nullable=True),
            sa.Column('appliance_name', sa.String(128), nullable=True),
            sa.Column('discovered_by', sa.String(64), nullable=True),
            sa.Column('discovered_at', sa.DateTime(), nullable=False),
            sa.Column('duration_s', sa.Integer(), nullable=True),
            sa.Column('probed', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('truncated', sa.Text(), nullable=True),
            sa.Column('nodes_json', sa.Text(), nullable=False),
            sa.UniqueConstraint('product', 'build', name='uq_diag_catalog_product_build'),
        )
        op.create_index('ix_diag_catalogs_product', 'diag_catalogs', ['product'])
    if 'diag_batteries' not in tables:
        op.create_table(
            'diag_batteries',
            sa.Column('adom_key', sa.String(64), primary_key=True),
            sa.Column('commands_json', sa.Text(), nullable=False),
            sa.Column('updated_by', sa.String(64), nullable=True),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
        )


def downgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()
    if 'diag_batteries' in tables:
        op.drop_table('diag_batteries')
    if 'diag_catalogs' in tables:
        op.drop_table('diag_catalogs')
    if 'ssh_username' in {c['name'] for c in insp.get_columns('appliances')}:
        op.drop_column('appliances', 'ssh_username')
