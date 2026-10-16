"""wiki

Revision ID: wiki01
Revises: obsfix01
Create Date: 2026-10-16

Operations › Wiki: articles (current text + revision history), the topic
tree, tags, the Wiki's own user groups, and the audience tables (ADOMs,
profiles, groups) that services/wiki_access.py reads.

Idempotent like the revisions before it: ``db.create_all()`` in
``app/__init__.py`` makes the same tables on boot.
"""
from alembic import op
import sqlalchemy as sa

revision = 'wiki01'
down_revision = 'obsfix01'
branch_labels = None
depends_on = None

_TABLES = ('wiki_article_tags', 'wiki_article_groups', 'wiki_article_profiles',
           'wiki_article_adoms', 'wiki_revisions', 'wiki_articles', 'wiki_tags',
           'wiki_group_members', 'wiki_groups', 'wiki_topics')


def upgrade():
    have = set(sa.inspect(op.get_bind()).get_table_names())
    if 'wiki_topics' not in have:
        op.create_table(
            'wiki_topics',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('parent_id', sa.Integer(),
                      sa.ForeignKey('wiki_topics.id', ondelete='CASCADE'), nullable=True),
            sa.Column('name', sa.String(80), nullable=False),
            sa.Column('description', sa.Text(), nullable=False, server_default=''),
            sa.UniqueConstraint('parent_id', 'name', name='uq_wiki_topic_name'),
        )
        op.create_index('ix_wiki_topics_parent_id', 'wiki_topics', ['parent_id'])
    if 'wiki_groups' not in have:
        op.create_table(
            'wiki_groups',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('name', sa.String(64), nullable=False, unique=True),
            sa.Column('description', sa.Text(), nullable=False, server_default=''),
            sa.Column('created_at', sa.DateTime(), nullable=False),
        )
    if 'wiki_group_members' not in have:
        op.create_table(
            'wiki_group_members',
            sa.Column('group_id', sa.Integer(),
                      sa.ForeignKey('wiki_groups.id', ondelete='CASCADE'), primary_key=True),
            sa.Column('user_id', sa.Integer(),
                      sa.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
        )
    if 'wiki_tags' not in have:
        op.create_table(
            'wiki_tags',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('name', sa.String(40), nullable=False, unique=True),
        )
    if 'wiki_articles' not in have:
        op.create_table(
            'wiki_articles',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('slug', sa.String(120), nullable=False, unique=True),
            sa.Column('title', sa.String(200), nullable=False),
            sa.Column('body', sa.Text(), nullable=False, server_default=''),
            sa.Column('status', sa.String(16), nullable=False, server_default='draft'),
            sa.Column('topic_id', sa.Integer(),
                      sa.ForeignKey('wiki_topics.id', ondelete='SET NULL'), nullable=True),
            sa.Column('author_id', sa.Integer(),
                      sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('audience_restricted', sa.Boolean(), nullable=False,
                      server_default=sa.false()),
            sa.Column('revision', sa.Integer(), nullable=False, server_default='1'),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('published_at', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_wiki_articles_status', 'wiki_articles', ['status'])
        op.create_index('ix_wiki_articles_topic_id', 'wiki_articles', ['topic_id'])
        op.create_index('ix_wiki_articles_author_id', 'wiki_articles', ['author_id'])
    if 'wiki_revisions' not in have:
        op.create_table(
            'wiki_revisions',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('article_id', sa.Integer(),
                      sa.ForeignKey('wiki_articles.id', ondelete='CASCADE'), nullable=False),
            sa.Column('number', sa.Integer(), nullable=False),
            sa.Column('title', sa.String(200), nullable=False),
            sa.Column('body', sa.Text(), nullable=False, server_default=''),
            sa.Column('note', sa.String(200), nullable=False, server_default=''),
            sa.Column('edited_by', sa.String(64), nullable=False, server_default=''),
            sa.Column('edited_at', sa.DateTime(), nullable=False),
            sa.UniqueConstraint('article_id', 'number', name='uq_wiki_revision'),
        )
        op.create_index('ix_wiki_revisions_article_id', 'wiki_revisions', ['article_id'])
    if 'wiki_article_adoms' not in have:
        op.create_table(
            'wiki_article_adoms',
            sa.Column('article_id', sa.Integer(),
                      sa.ForeignKey('wiki_articles.id', ondelete='CASCADE'), primary_key=True),
            sa.Column('adom', sa.String(32), primary_key=True),
        )
    if 'wiki_article_profiles' not in have:
        op.create_table(
            'wiki_article_profiles',
            sa.Column('article_id', sa.Integer(),
                      sa.ForeignKey('wiki_articles.id', ondelete='CASCADE'), primary_key=True),
            sa.Column('profile_id', sa.Integer(),
                      sa.ForeignKey('profiles.id', ondelete='CASCADE'), primary_key=True),
        )
    if 'wiki_article_groups' not in have:
        op.create_table(
            'wiki_article_groups',
            sa.Column('article_id', sa.Integer(),
                      sa.ForeignKey('wiki_articles.id', ondelete='CASCADE'), primary_key=True),
            sa.Column('group_id', sa.Integer(),
                      sa.ForeignKey('wiki_groups.id', ondelete='CASCADE'), primary_key=True),
        )
    if 'wiki_article_tags' not in have:
        op.create_table(
            'wiki_article_tags',
            sa.Column('article_id', sa.Integer(),
                      sa.ForeignKey('wiki_articles.id', ondelete='CASCADE'), primary_key=True),
            sa.Column('tag_id', sa.Integer(),
                      sa.ForeignKey('wiki_tags.id', ondelete='CASCADE'), primary_key=True),
        )


def downgrade():
    have = set(sa.inspect(op.get_bind()).get_table_names())
    for name in _TABLES:
        if name in have:
            op.drop_table(name)
