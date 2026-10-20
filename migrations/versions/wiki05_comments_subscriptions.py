"""wiki comments and subscriptions

Revision ID: wiki05
Revises: wiki04
Create Date: 2026-10-20

``wiki_comments`` (threaded by ``parent_id``) and ``wiki_subscriptions``
(one user following an article, a topic, a tag, an ADOM or everything) —
app/models_wiki.py, services/wiki_social.py. Idempotent
(app.migration_guard): create_all may already have made them.
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'wiki05'
down_revision = 'wiki04'
branch_labels = None
depends_on = None


def upgrade():
    if guard.create_table(
            'wiki_comments',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('article_id', sa.Integer(),
                      sa.ForeignKey('wiki_articles.id', ondelete='CASCADE'), nullable=False),
            sa.Column('parent_id', sa.Integer(),
                      sa.ForeignKey('wiki_comments.id', ondelete='CASCADE'), nullable=True),
            sa.Column('author_id', sa.Integer(),
                      sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('body', sa.Text(), nullable=False, server_default=''),
            sa.Column('deleted', sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('edited_at', sa.DateTime(), nullable=True)):
        op.create_index('ix_wiki_comments_article_id', 'wiki_comments', ['article_id'])
        op.create_index('ix_wiki_comments_parent_id', 'wiki_comments', ['parent_id'])
        op.create_index('ix_wiki_comments_author_id', 'wiki_comments', ['author_id'])
    if guard.create_table(
            'wiki_subscriptions',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('user_id', sa.Integer(),
                      sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
            sa.Column('kind', sa.String(16), nullable=False),
            sa.Column('ref', sa.String(64), nullable=False, server_default=''),
            sa.Column('email', sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.UniqueConstraint('user_id', 'kind', 'ref', name='uq_wiki_subscription')):
        op.create_index('ix_wiki_subscriptions_user_id', 'wiki_subscriptions', ['user_id'])


def downgrade():
    op.drop_table('wiki_subscriptions')
    op.drop_table('wiki_comments')
