"""Plugin Studio apps: the SATOM page a page plugin opens

Revision ID: apppage01
Revises: inc01
Create Date: 2026-11-08

``studio_apps.page_key``: for an app of kind "page" (services.studio_pages),
the id of the SATOM page its menu entry opens; NULL for flow and script apps.
Nothing existing is touched. Idempotent (app.migration_guard): create_all may
already have added it.
"""
from alembic import op  # noqa: F401 -- alembic loads every revision with op in scope
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'apppage01'
down_revision = 'inc01'
branch_labels = None
depends_on = None


def upgrade():
    guard.add_column('studio_apps', sa.Column('page_key', sa.String(48), nullable=True))


def downgrade():
    if guard.has_column('studio_apps', 'page_key'):
        with op.batch_alter_table('studio_apps') as b:
            b.drop_column('page_key')
