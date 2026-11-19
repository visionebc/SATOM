"""wiki article description

Revision ID: wiki02
Revises: wiki01
Create Date: 2026-10-16

``wiki_articles.summary``: the short description shown under the title in
the article list and searched with the title, the text, the topic and the
tags. Idempotent like the revisions before it.
"""
from alembic import op
import sqlalchemy as sa

revision = 'wiki02'
down_revision = 'wiki01'
branch_labels = None
depends_on = None


def upgrade():
    cols = {c['name'] for c in sa.inspect(op.get_bind()).get_columns('wiki_articles')}
    if 'summary' not in cols:
        op.add_column('wiki_articles', sa.Column('summary', sa.String(300),
                                                 nullable=False, server_default=''))


def downgrade():
    cols = {c['name'] for c in sa.inspect(op.get_bind()).get_columns('wiki_articles')}
    if 'summary' in cols:
        op.drop_column('wiki_articles', 'summary')
