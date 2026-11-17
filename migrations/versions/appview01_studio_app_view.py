"""Plugin Studio apps: the app's own view

Revision ID: appview01
Revises: bmorder01
Create Date: 2026-11-09

``studio_apps.view_json``: a flow app's own page (services.studio_view) --
a sandboxed template, its CSS and JS, drawn in an isolated frame. "{}" for
every existing app (no view: the designed page as before). Idempotent
(app.migration_guard): create_all may already have added it.
"""
from alembic import op  # noqa: F401 -- alembic loads every revision with op in scope
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'appview01'
down_revision = 'bmorder01'
branch_labels = None
depends_on = None


def upgrade():
    guard.add_column('studio_apps', sa.Column('view_json', sa.Text(), nullable=False,
                                              server_default='{}'))


def downgrade():
    if guard.has_column('studio_apps', 'view_json'):
        with op.batch_alter_table('studio_apps') as b:
            b.drop_column('view_json')
