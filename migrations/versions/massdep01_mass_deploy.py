"""Mass Deploy: deploy history and the rollout scope of a template family

Revision ID: massdep01
Revises: wiki07
Create Date: 2026-10-24

``mass_deploys`` (Operations > Automation > Mass Deploy history) and
``template_family_scope`` (fleet | selected), app/models_mass_deploy.py.
Idempotent (app.migration_guard): create_all may already have made the tables.
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'massdep01'
down_revision = 'wiki07'
branch_labels = None
depends_on = None


def upgrade():
    guard.create_table(
        'template_family_scope',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('product', sa.String(32), nullable=False, server_default='fortiweb'),
        sa.Column('kind', sa.String(64), nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('scope', sa.String(16), nullable=False, server_default='fleet'),
        sa.Column('set_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('set_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('kind', 'name', name='uq_template_family_scope'))
    if guard.create_table(
            'mass_deploys',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('product', sa.String(32), nullable=False, server_default='fortiweb'),
            sa.Column('template_id', sa.Integer(), nullable=True),
            sa.Column('kind', sa.String(64), nullable=False, server_default=''),
            sa.Column('name', sa.String(128), nullable=False, server_default=''),
            sa.Column('version', sa.Integer(), nullable=False, server_default='1'),
            sa.Column('devices', sa.Text(), nullable=False, server_default='[]'),
            sa.Column('secrets_supplied', sa.Text(), nullable=False, server_default='[]'),
            sa.Column('bound', sa.Text(), nullable=False, server_default='[]'),
            sa.Column('by', sa.String(64), nullable=False, server_default=''),
            sa.Column('job_id', sa.String(64), nullable=False, server_default=''),
            sa.Column('status', sa.String(16), nullable=False, server_default='running'),
            sa.Column('ok_count', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('total', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('result', sa.Text(), nullable=False, server_default='[]'),
            sa.Column('message', sa.Text(), nullable=False, server_default=''),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('finished_at', sa.DateTime(), nullable=True)):
        op.create_index('ix_mass_deploys_product', 'mass_deploys', ['product'])
        op.create_index('ix_mass_deploys_created_at', 'mass_deploys', ['created_at'])


def downgrade():
    op.drop_table('mass_deploys')
    op.drop_table('template_family_scope')
