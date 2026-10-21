"""collector: SNMP v2c polling per appliance

Revision ID: coll01
Revises: wiki06
Create Date: 2026-10-21

Three columns on ``appliances`` for the opt-in SNMP collector
(services/snmp_collect.py): the switch, the UDP port and the Fernet-encrypted
community string (mirrored to the vault like the passwords). The syslog
receiver of the same change keeps its settings in ``app_settings`` and needs
no table. Idempotent (app.migration_guard).
"""
from alembic import op  # noqa: F401 - the guard wraps op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'coll01'
down_revision = 'wiki06'
branch_labels = None
depends_on = None


def upgrade():
    guard.add_column('appliances', sa.Column('snmp_enabled', sa.Boolean(),
                                             nullable=False, server_default=sa.false()))
    guard.add_column('appliances', sa.Column('snmp_port', sa.Integer(), nullable=True))
    guard.add_column('appliances', sa.Column('snmp_community_enc', sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table('appliances') as batch:
        batch.drop_column('snmp_community_enc')
        batch.drop_column('snmp_port')
        batch.drop_column('snmp_enabled')
