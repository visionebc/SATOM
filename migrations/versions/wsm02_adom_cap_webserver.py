"""ADOM capability: Web Server Manager on / off

Revision ID: wsm02
Revises: wsm01
Create Date: 2026-11-07

``adoms.cap_webserver`` (operator, 2026-11-07: "when the Linux ADOM is
switched on, choose whether this module is active"). The Linux ADOM, where
the manager already lives, gets it ON so nothing changes on upgrade; every
other ADOM starts without it. Idempotent (app.migration_guard).
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'wsm02'
down_revision = 'wsm01'
branch_labels = None
depends_on = None


def upgrade():
    if not guard.has_table('adoms'):
        return
    if not guard.has_column('adoms', 'cap_webserver'):
        op.add_column('adoms', sa.Column('cap_webserver', sa.Boolean(), nullable=False,
                                         server_default=sa.false()))
    op.get_bind().execute(sa.text(
        "UPDATE adoms SET cap_webserver = :t WHERE key = 'linux'"), {"t": True})


def downgrade():
    if guard.has_column('adoms', 'cap_webserver'):
        op.drop_column('adoms', 'cap_webserver')
