"""Bookmarks: the user's own order of the Favourites root

Revision ID: bmorder01
Revises: apppage01
Create Date: 2026-11-08

``bookmark_favorites.position``: where the user dragged a star to in their
Favourites. Every existing star starts at 0, so the panel keeps its old
alphabetical look until somebody reorders. Idempotent (app.migration_guard):
create_all may already have added it.
"""
from alembic import op  # noqa: F401 -- alembic loads every revision with op in scope
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'bmorder01'
down_revision = 'apppage01'
branch_labels = None
depends_on = None


def upgrade():
    guard.add_column('bookmark_favorites',
                     sa.Column('position', sa.Integer(), nullable=False,
                               server_default='0'))


def downgrade():
    if guard.has_column('bookmark_favorites', 'position'):
        with op.batch_alter_table('bookmark_favorites') as b:
            b.drop_column('position')
