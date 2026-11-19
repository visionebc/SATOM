"""wiki: publish articles to Confluence

Revision ID: wiki06
Revises: wiki05
Create Date: 2026-10-20

``wiki_confluence_targets`` (a Confluence space and how to reach it; the
credential lives in app_settings / the vault, not here) and
``wiki_confluence_links`` (article -> page id and the version it holds).
services/wiki_confluence.py. Idempotent (app.migration_guard).
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'wiki06'
down_revision = 'wiki05'
branch_labels = None
depends_on = None


def upgrade():
    guard.create_table(
        'wiki_confluence_targets',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(80), nullable=False, unique=True),
        sa.Column('flavor', sa.String(16), nullable=False, server_default='cloud'),
        sa.Column('base_url', sa.String(500), nullable=False, server_default=''),
        sa.Column('space_key', sa.String(64), nullable=False, server_default=''),
        sa.Column('parent_page_id', sa.String(32), nullable=False, server_default=''),
        sa.Column('auth', sa.String(16), nullable=False, server_default='basic'),
        sa.Column('username', sa.String(255), nullable=False, server_default=''),
        sa.Column('verify_tls', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False))
    if guard.create_table(
            'wiki_confluence_links',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('article_id', sa.Integer(),
                      sa.ForeignKey('wiki_articles.id', ondelete='CASCADE'), nullable=False),
            sa.Column('target_id', sa.Integer(),
                      sa.ForeignKey('wiki_confluence_targets.id', ondelete='CASCADE'),
                      nullable=False),
            sa.Column('page_id', sa.String(32), nullable=False),
            sa.Column('page_url', sa.String(1000), nullable=False, server_default=''),
            sa.Column('published_revision', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('published_at', sa.DateTime(), nullable=True),
            sa.Column('published_by', sa.String(64), nullable=False, server_default=''),
            sa.UniqueConstraint('article_id', 'target_id', name='uq_wiki_confluence_link')):
        op.create_index('ix_wiki_confluence_links_article_id', 'wiki_confluence_links',
                        ['article_id'])
        op.create_index('ix_wiki_confluence_links_target_id', 'wiki_confluence_links',
                        ['target_id'])


def downgrade():
    op.drop_table('wiki_confluence_links')
    op.drop_table('wiki_confluence_targets')
