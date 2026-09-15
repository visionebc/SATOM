"""firmware_version_decls — operator-authored firmware version declarations

Revision ID: fwverdecl01
Revises: clonelog06
Create Date: 2026-09-16

The API-versions page used to show only firmware lines it had stumbled over in
the evidence. A version an operator INTENDS to measure (8.0.5 is coming, its
image is not uploaded yet, no box runs it) had nowhere to be stated, so the
page could not distinguish "declared and unmeasured" from "does not exist".

Only the hand-authored declarations live here. Versions derived from a
``FirmwareImage`` row or an appliance's running firmware are computed on read
by ``services.firmware_versions.catalog``, so no upload path can forget to
register one.
"""
from alembic import op
import sqlalchemy as sa

revision = 'fwverdecl01'
down_revision = "clonelog2026"
branch_labels = None
depends_on = None


def upgrade():
    # Idempotent on purpose. This app also builds its schema with
    # ``db.create_all()`` at boot, so on an already-running node the table is
    # here before alembic ever reaches this revision. A migration that dies on
    # that is a migration that blocks every LATER one, on the node that is
    # actually in production.
    bind = op.get_bind()
    if 'firmware_version_decls' in sa.inspect(bind).get_table_names():
        return
    op.create_table(
        'firmware_version_decls',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('product', sa.String(length=32), nullable=False,
                  server_default='fortiweb'),
        sa.Column('version', sa.String(length=32), nullable=False),
        sa.Column('note', sa.String(length=500), nullable=True,
                  server_default=''),
        sa.Column('declared_by', sa.String(length=64), nullable=False,
                  server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False,
                  server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('product', 'version',
                            name='uq_fwverdecl_product_version'),
    )


def downgrade():
    bind = op.get_bind()
    if 'firmware_version_decls' in sa.inspect(bind).get_table_names():
        op.drop_table('firmware_version_decls')
