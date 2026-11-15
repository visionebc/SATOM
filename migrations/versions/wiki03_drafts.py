"""wiki drafts and versions

Revision ID: wiki03
Revises: wiki02
Create Date: 2026-10-16

Editing a Wiki article autosaves a shared draft (``wiki_articles.draft_*``)
and publishing it makes a new version; ``wiki_revisions.summary`` keeps the
description each version was released with. Idempotent
(app.migration_guard): create_all may already have added the columns.
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'wiki03'
down_revision = 'wiki02'
branch_labels = None
depends_on = None


def upgrade():
    guard.add_column('wiki_articles', sa.Column('draft_data', sa.Text(), nullable=True))
    guard.add_column('wiki_articles', sa.Column('draft_rev', sa.Integer(), nullable=False,
                                                server_default='0'))
    guard.add_column('wiki_articles', sa.Column('draft_saved_at', sa.DateTime(), nullable=True))
    guard.add_column('wiki_articles', sa.Column('draft_user_id', sa.Integer(), nullable=True))
    guard.create_foreign_key('fk_wiki_articles_draft_user', 'wiki_articles', 'users',
                             ['draft_user_id'], ['id'], ondelete='SET NULL')
    guard.add_column('wiki_revisions', sa.Column('summary', sa.String(300), nullable=False,
                                                 server_default=''))


def downgrade():
    op.drop_column('wiki_revisions', 'summary')
    op.drop_constraint('fk_wiki_articles_draft_user', 'wiki_articles', type_='foreignkey')
    op.drop_column('wiki_articles', 'draft_user_id')
    op.drop_column('wiki_articles', 'draft_saved_at')
    op.drop_column('wiki_articles', 'draft_rev')
    op.drop_column('wiki_articles', 'draft_data')
