"""Path Diagnostics: saved walk reports

Revision ID: pdiag01
Revises: appscope01
Create Date: 2026-10-30

``path_diag_reports`` (app/models_pathdiag.py): every walk's report as drawn,
its metrics panel and the job that carried the device calls.
Idempotent (app.migration_guard): create_all may already have made it.
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'pdiag01'
down_revision = 'appscope01'
branch_labels = None
depends_on = None


def upgrade():
    guard.create_table(
        'path_diag_reports',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('username', sa.String(64), nullable=False, server_default=''),
        sa.Column('product', sa.String(32), nullable=False, server_default=''),
        sa.Column('appliance_id', sa.Integer(), nullable=True),
        sa.Column('appliance_name', sa.String(128), nullable=False, server_default=''),
        sa.Column('kind', sa.String(32), nullable=False, server_default=''),
        sa.Column('policy', sa.String(256), nullable=False, server_default=''),
        sa.Column('localised', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('verdict_layer', sa.String(64), nullable=False, server_default=''),
        sa.Column('verdict_text', sa.String(400), nullable=False, server_default=''),
        sa.Column('metrics_status', sa.String(16), nullable=False, server_default=''),
        sa.Column('window_minutes', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('job_id', sa.String(64), nullable=False, server_default=''),
        sa.Column('report_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('metrics_json', sa.Text(), nullable=False, server_default='{}'),
    )
    guard.create_index('ix_path_diag_reports_created_at', 'path_diag_reports', ['created_at'])
    guard.create_index('ix_path_diag_reports_product', 'path_diag_reports', ['product'])
    guard.create_index('ix_path_diag_reports_appliance_id', 'path_diag_reports',
                       ['appliance_id'])


def downgrade():
    op.drop_table('path_diag_reports')
