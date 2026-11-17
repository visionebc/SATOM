"""Plugin Studio apps: a menu group

Revision ID: appgroup01
Revises: pdiag01
Create Date: 2026-10-30

``studio_apps.menu_group``: the group an app is filed under. The sidebar
draws every group as a submenu of Plugins, and Plugin Studio filters its
app list by it. "" = no group (the app is a plain entry of Plugins).
Idempotent (app.migration_guard): create_all may already have added it.
"""
from alembic import op  # noqa: F401 -- alembic loads every revision with op in scope
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'appgroup01'
down_revision = 'pdiag01'
branch_labels = None
depends_on = None


def upgrade():
    guard.add_column('studio_apps',
                     sa.Column('menu_group', sa.String(48), nullable=False,
                               server_default=''))


def downgrade():
    if guard.has_column('studio_apps', 'menu_group'):
        with op.batch_alter_table('studio_apps') as b:
            b.drop_column('menu_group')
