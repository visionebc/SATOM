"""appliances: TLS certificate name (SA-0015)

Revision ID: tlsname01
Revises: selopts01
Create Date: 2026-11-06

``appliances.tls_server_name``: the name the appliance's certificate is
checked against when it is not the address SATOM connects to. An HA pair
presents one synced certificate naming the cluster, so with verification on
every member failed with "IP address mismatch". Members follow their
cluster's value (Appliance.tls_name). Nullable, no data change. Idempotent
(app.migration_guard).
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'tlsname01'
down_revision = 'selopts01'
branch_labels = None
depends_on = None


def upgrade():
    guard.add_column('appliances', sa.Column('tls_server_name', sa.String(253), nullable=True))


def downgrade():
    op.drop_column('appliances', 'tls_server_name')
