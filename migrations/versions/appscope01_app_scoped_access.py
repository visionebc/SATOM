"""App-scoped access: Apps-only profiles, directory connections, app sign-in

Revision ID: appscope01
Revises: covg01
Create Date: 2026-10-30

``profiles.kind`` (console | apps), ``users.login_connection_id`` (the
directory connection an app account is pinned to), ``studio_apps.login_json``
(the app's own sign-in), ``directory_connections`` and ``studio_app_grants``
(app/models.py, app/models_studio.py; services.apps_only, services.app_signin).
Idempotent (app.migration_guard): create_all may already have made them.
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'appscope01'
down_revision = 'covg01'
branch_labels = None
depends_on = None


def upgrade():
    guard.add_column('profiles', sa.Column('kind', sa.String(16), nullable=False,
                                           server_default='console'))
    guard.add_column('users', sa.Column('login_connection_id', sa.Integer(), nullable=True))
    guard.create_index('ix_users_login_connection_id', 'users', ['login_connection_id'])
    guard.add_column('studio_apps', sa.Column('login_json', sa.Text(), nullable=False,
                                              server_default='{}'))
    if guard.create_table(
            'directory_connections',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('slug', sa.String(40), nullable=False),
            sa.Column('name', sa.String(120), nullable=False),
            sa.Column('kind', sa.String(16), nullable=False),
            sa.Column('cfg_json', sa.Text(), nullable=False, server_default='{}'),
            sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
            sa.Column('updated_by', sa.String(64), nullable=False, server_default=''),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False)):
        op.create_index('ix_directory_connections_slug', 'directory_connections', ['slug'],
                        unique=True)
    guard.create_table(
        'studio_app_grants',
        sa.Column('user_id', sa.Integer(),
                  sa.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('app_id', sa.Integer(),
                  sa.ForeignKey('studio_apps.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('connection_id', sa.Integer(), nullable=True),
        sa.Column('granted_at', sa.DateTime(), nullable=False))


def downgrade():
    op.drop_table('studio_app_grants')
    op.drop_table('directory_connections')
    with op.batch_alter_table('studio_apps') as b:
        b.drop_column('login_json')
    op.drop_index('ix_users_login_connection_id', table_name='users')
    with op.batch_alter_table('users') as b:
        b.drop_column('login_connection_id')
    with op.batch_alter_table('profiles') as b:
        b.drop_column('kind')
