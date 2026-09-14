"""policy_clone_events (durable clone/migrate registry per server policy)

Revision ID: clonelog2026
Revises: bkmk2026side
Create Date: 2026-09-14 22:10:00.000000

One table. Each row is one EXECUTED clone/migrate of one server policy, keyed
to the source by plain columns (never into ``device_server_policies``, which is
rebuilt on every ingest).

Asymmetric FKs on purpose: the SOURCE cascades (losing that device makes every
row unreachable by construction), the DESTINATION is SET NULL so the recorded
``dst_appliance`` name survives retiring the box it points at.

Idempotent: skips creation when the table already exists (``db.create_all()``
may have created it on a prior boot).
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'clonelog2026'
down_revision = 'bkmk2026side'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'policy_clone_events' in set(insp.get_table_names()):
        return
    op.create_table(
        'policy_clone_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('src_appliance_id', sa.Integer(), nullable=False),
        sa.Column('src_policy', sa.String(length=256), nullable=False),
        sa.Column('action', sa.String(length=32), nullable=False),
        sa.Column('dst_appliance_id', sa.Integer(), nullable=True),
        sa.Column('dst_appliance', sa.String(length=256), nullable=False,
                  server_default=''),
        sa.Column('dst_policy', sa.String(length=256), nullable=False,
                  server_default=''),
        sa.Column('ok', sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column('error', sa.String(length=512), nullable=False,
                  server_default=''),
        sa.Column('at', sa.DateTime(), nullable=False),
        sa.Column('by', sa.String(length=128), nullable=False,
                  server_default=''),
        sa.Column('job_id', sa.String(length=64), nullable=False,
                  server_default=''),
        sa.ForeignKeyConstraint(['src_appliance_id'], ['appliances.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['dst_appliance_id'], ['appliances.id'],
                                ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_policy_clone_events_src_appliance_id'),
                    'policy_clone_events', ['src_appliance_id'])
    op.create_index(op.f('ix_policy_clone_events_src_policy'),
                    'policy_clone_events', ['src_policy'])
    op.create_index(op.f('ix_policy_clone_events_at'),
                    'policy_clone_events', ['at'])
    # The composite the page render actually uses (appliance + name, one query
    # for every row on the page).
    op.create_index('ix_policy_clone_src', 'policy_clone_events',
                    ['src_appliance_id', 'src_policy'])


def downgrade():
    op.drop_index('ix_policy_clone_src', table_name='policy_clone_events')
    op.drop_index(op.f('ix_policy_clone_events_at'),
                  table_name='policy_clone_events')
    op.drop_index(op.f('ix_policy_clone_events_src_policy'),
                  table_name='policy_clone_events')
    op.drop_index(op.f('ix_policy_clone_events_src_appliance_id'),
                  table_name='policy_clone_events')
    op.drop_table('policy_clone_events')
