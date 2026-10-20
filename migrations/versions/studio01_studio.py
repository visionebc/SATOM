"""python studio: data stores, connections, apps, app runs, user groups

Revision ID: studio01
Revises: wiki03
Create Date: 2026-10-20

Tables for Administrator > Studio > Python Studio (app/models_studio.py).
Idempotent (app.migration_guard): create_all may already have made them.
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'studio01'
down_revision = 'wiki03'
branch_labels = None
depends_on = None


def _stamps():
    return [
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('updated_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    ]


def upgrade():
    if guard.create_table(
            'studio_datastores',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('slug', sa.String(48), nullable=False, unique=True),
            sa.Column('name', sa.String(120), nullable=False),
            sa.Column('description', sa.Text(), nullable=False, server_default=''),
            sa.Column('columns_json', sa.Text(), nullable=False, server_default='[]'),
            *_stamps()):
        op.create_index('ix_studio_datastores_slug', 'studio_datastores', ['slug'])
    if guard.create_table(
            'studio_rows',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('store_id', sa.Integer(),
                      sa.ForeignKey('studio_datastores.id', ondelete='CASCADE'), nullable=False),
            sa.Column('data_json', sa.Text(), nullable=False, server_default='{}'),
            *_stamps()):
        op.create_index('ix_studio_rows_store_id', 'studio_rows', ['store_id'])
    if guard.create_table(
            'studio_connections',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('slug', sa.String(48), nullable=False, unique=True),
            sa.Column('name', sa.String(120), nullable=False),
            sa.Column('description', sa.Text(), nullable=False, server_default=''),
            sa.Column('kind', sa.String(16), nullable=False, server_default='http'),
            sa.Column('base_url', sa.String(500), nullable=False, server_default=''),
            sa.Column('host', sa.String(255), nullable=False, server_default=''),
            sa.Column('port', sa.Integer(), nullable=True),
            sa.Column('database', sa.String(128), nullable=False, server_default=''),
            sa.Column('auth', sa.String(16), nullable=False, server_default='none'),
            sa.Column('username', sa.String(255), nullable=False, server_default=''),
            sa.Column('header_name', sa.String(128), nullable=False, server_default=''),
            sa.Column('token_url', sa.String(500), nullable=False, server_default=''),
            sa.Column('scope', sa.String(500), nullable=False, server_default=''),
            sa.Column('verify_tls', sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column('timeout', sa.Integer(), nullable=False, server_default='20'),
            *_stamps()):
        op.create_index('ix_studio_connections_slug', 'studio_connections', ['slug'])
    guard.create_table(
        'user_groups',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(64), nullable=False, unique=True),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    guard.create_table(
        'user_group_members',
        sa.Column('group_id', sa.Integer(),
                  sa.ForeignKey('user_groups.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('user_id', sa.Integer(),
                  sa.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    )
    if guard.create_table(
            'studio_apps',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('slug', sa.String(48), nullable=False, unique=True),
            sa.Column('name', sa.String(120), nullable=False),
            sa.Column('icon', sa.String(32), nullable=False, server_default='bi-app-indicator'),
            sa.Column('description', sa.Text(), nullable=False, server_default=''),
            sa.Column('status', sa.String(16), nullable=False, server_default='draft'),
            sa.Column('adoms_json', sa.Text(), nullable=False, server_default='[]'),
            sa.Column('access_json', sa.Text(), nullable=False, server_default='{}'),
            sa.Column('fields_json', sa.Text(), nullable=False, server_default='[]'),
            sa.Column('graph_json', sa.Text(), nullable=False, server_default='{}'),
            sa.Column('actions_json', sa.Text(), nullable=False, server_default='[]'),
            sa.Column('published_json', sa.Text(), nullable=False, server_default='{}'),
            sa.Column('version', sa.Integer(), nullable=False, server_default='0'),
            *_stamps(),
            sa.Column('published_at', sa.DateTime(), nullable=True)):
        op.create_index('ix_studio_apps_slug', 'studio_apps', ['slug'])
    if guard.create_table(
            'studio_app_runs',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('app_id', sa.Integer(),
                      sa.ForeignKey('studio_apps.id', ondelete='CASCADE'), nullable=False),
            sa.Column('version', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('armed', sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column('status', sa.String(16), nullable=False, server_default='running'),
            sa.Column('user', sa.String(64), nullable=False, server_default=''),
            sa.Column('product', sa.String(32), nullable=False, server_default=''),
            sa.Column('inputs_json', sa.Text(), nullable=False, server_default='{}'),
            sa.Column('outputs_json', sa.Text(), nullable=False, server_default='[]'),
            sa.Column('vars_json', sa.Text(), nullable=False, server_default='{}'),
            sa.Column('steps_json', sa.Text(), nullable=False, server_default='[]'),
            sa.Column('error', sa.Text(), nullable=False, server_default=''),
            sa.Column('started_at', sa.DateTime(), nullable=False),
            sa.Column('finished_at', sa.DateTime(), nullable=True)):
        op.create_index('ix_studio_app_runs_app_id', 'studio_app_runs', ['app_id'])
        op.create_index('ix_studio_app_runs_user', 'studio_app_runs', ['user'])


def downgrade():
    for t in ('studio_app_runs', 'studio_apps', 'user_group_members', 'user_groups',
              'studio_connections', 'studio_rows', 'studio_datastores'):
        op.drop_table(t)
