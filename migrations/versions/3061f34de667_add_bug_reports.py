"""add bug_reports

Revision ID: 3061f34de667
Revises: ha01clusters1
Create Date: 2026-07-01 18:54:47.757357

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3061f34de667'
down_revision = 'ha01clusters1'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'bug_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('reporter_id', sa.Integer(), nullable=True),
        sa.Column('reporter_username', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('page_url', sa.String(length=500), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('resolved_by_id', sa.Integer(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('resolution_note', sa.Text(), nullable=True),
        sa.Column('reporter_seen', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['reporter_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['resolved_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_bug_reports_reporter_id'), 'bug_reports', ['reporter_id'], unique=False)
    op.create_index(op.f('ix_bug_reports_status'), 'bug_reports', ['status'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_bug_reports_status'), table_name='bug_reports')
    op.drop_index(op.f('ix_bug_reports_reporter_id'), table_name='bug_reports')
    op.drop_table('bug_reports')
