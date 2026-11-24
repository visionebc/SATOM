"""wiki: the Confluence space and parent page are picked per publication

Revision ID: wiki07
Revises: appdesign01
Create Date: 2026-10-23

``wiki_confluence_targets`` becomes a connection (Settings › Integrations ›
Confluence); its ``space_key`` / ``parent_page_id`` stay, unused, so a
downgrade finds them. ``wiki_confluence_links`` gains the space the page was
created in and the page it was created under, and is unique per article,
connection AND space (it was per article and connection). Existing links
take their space from their target. Idempotent (app.migration_guard).
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'wiki07'
down_revision = 'appdesign01'
branch_labels = None
depends_on = None

OLD, NEW = 'uq_wiki_confluence_link', 'uq_wiki_confluence_link_space'


def _uniques():
    return {u.get('name') for u in sa.inspect(op.get_bind())
            .get_unique_constraints('wiki_confluence_links')}


def upgrade():
    guard.add_column('wiki_confluence_links',
                     sa.Column('space_key', sa.String(64), nullable=False,
                               server_default=''))
    guard.add_column('wiki_confluence_links',
                     sa.Column('parent_page_id', sa.String(32), nullable=False,
                               server_default=''))
    # Every run, not only when the column was just added: a boot may have
    # added it first. Only rows still without a space are touched.
    op.execute("UPDATE wiki_confluence_links SET space_key = (SELECT t.space_key FROM "
               "wiki_confluence_targets t WHERE t.id = wiki_confluence_links.target_id) "
               "WHERE space_key = ''")
    if op.get_bind().dialect.name == 'sqlite':
        return      # SQLite cannot ALTER a constraint; create_all declared the new one
    have = _uniques()
    if OLD in have:
        op.drop_constraint(OLD, 'wiki_confluence_links', type_='unique')
    if NEW not in have:
        op.create_unique_constraint(NEW, 'wiki_confluence_links',
                                    ['article_id', 'target_id', 'space_key'])


def downgrade():
    op.drop_constraint(NEW, 'wiki_confluence_links', type_='unique')
    op.create_unique_constraint(OLD, 'wiki_confluence_links', ['article_id', 'target_id'])
    op.drop_column('wiki_confluence_links', 'parent_page_id')
    op.drop_column('wiki_confluence_links', 'space_key')
