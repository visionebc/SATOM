"""adom registry (data-driven ADOM/product catalog)

Revision ID: adomreg2026
Revises: 3061f34de667
Create Date: 2026-07-12 09:40:00.000000

Creates the ``adoms`` table — the single source of truth for ADOMs/products and
their capability flags. Rows are seeded at boot by ``branding.seed_defaults``
(insert-only, keyed by ``key``), so this migration only creates the schema.
Idempotent: skips creation if the table already exists (``db.create_all`` may
have created it on a prior boot).
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'adomreg2026'
down_revision = '3061f34de667'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'adoms' in insp.get_table_names():
        return
    op.create_table(
        'adoms',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('key', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('title', sa.String(length=128), nullable=False),
        sa.Column('tagline', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('mark', sa.String(length=256), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False),
        sa.Column('placeholder', sa.Boolean(), nullable=False),
        sa.Column('sort_order', sa.Integer(), nullable=False),
        sa.Column('banner_default', sa.String(length=32), nullable=False),
        sa.Column('cap_banner', sa.Boolean(), nullable=False),
        sa.Column('cap_tokens', sa.Boolean(), nullable=False),
        sa.Column('cap_firmware', sa.Boolean(), nullable=False),
        sa.Column('cap_naming', sa.Boolean(), nullable=False),
        sa.Column('cap_regex', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key'),
    )
    op.create_index(op.f('ix_adoms_key'), 'adoms', ['key'], unique=True)


def downgrade():
    op.drop_index(op.f('ix_adoms_key'), table_name='adoms')
    op.drop_table('adoms')
