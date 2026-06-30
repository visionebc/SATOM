"""ha_cluster columns on appliances

Revision ID: ha01clusters1
Revises: 6a13b09b7e79
Create Date: 2026-06-30 16:55:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'ha01clusters1'
down_revision = '6a13b09b7e79'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('appliances', sa.Column('is_cluster', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('appliances', sa.Column('is_cluster_member', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('appliances', sa.Column('parent_id', sa.Integer(), nullable=True))
    op.add_column('appliances', sa.Column('ha_mode', sa.String(length=16), nullable=True))
    op.add_column('appliances', sa.Column('ha_role_hint', sa.String(length=16), nullable=True))
    op.add_column('appliances', sa.Column('ha_vip', sa.String(length=253), nullable=True))
    op.create_index('ix_appliances_parent_id', 'appliances', ['parent_id'])
    op.create_foreign_key(
        'fk_appliances_parent', 'appliances', 'appliances',
        ['parent_id'], ['id'], ondelete='CASCADE',
    )


def downgrade():
    op.drop_constraint('fk_appliances_parent', 'appliances', type_='foreignkey')
    op.drop_index('ix_appliances_parent_id', table_name='appliances')
    op.drop_column('appliances', 'ha_vip')
    op.drop_column('appliances', 'ha_role_hint')
    op.drop_column('appliances', 'ha_mode')
    op.drop_column('appliances', 'parent_id')
    op.drop_column('appliances', 'is_cluster_member')
    op.drop_column('appliances', 'is_cluster')
