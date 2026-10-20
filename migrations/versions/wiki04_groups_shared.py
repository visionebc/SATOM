"""wiki: groups are Administrator > Access > Groups

Revision ID: wiki04
Revises: studio01
Create Date: 2026-10-20

The Wiki kept groups of its own (``wiki_groups``) while Python Studio apps
got ``user_groups`` (Administrator > Access > Groups): two lists of "the
network team" that drift apart. Every Wiki group is merged into
``user_groups`` (same name, case-insensitive, = same group: members are
added together), ``wiki_article_groups.group_id`` is re-pointed at it, and
``wiki_groups`` / ``wiki_group_members`` are dropped.

``wiki_article_groups`` is rebuilt rather than ALTERed: SQLite cannot change
a foreign key in place, and the table is tiny. Idempotent: with no
``wiki_groups`` table (create_all with the new models, or a second run)
there is nothing to do.
"""
from datetime import datetime

from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'wiki04'
down_revision = 'studio01'
branch_labels = None
depends_on = None


def _article_groups_table(target: str):
    return guard.create_table(
        'wiki_article_groups',
        sa.Column('article_id', sa.Integer(),
                  sa.ForeignKey('wiki_articles.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('group_id', sa.Integer(),
                  sa.ForeignKey('%s.id' % target, ondelete='CASCADE'), primary_key=True))


def upgrade():
    if not guard.has_table('wiki_groups'):
        return
    bind = op.get_bind()
    now = datetime.utcnow()
    mapping = {}
    for gid, name, desc, created in bind.execute(sa.text(
            'SELECT id, name, description, created_at FROM wiki_groups ORDER BY id')).fetchall():
        hit = bind.execute(sa.text('SELECT id FROM user_groups WHERE lower(name) = lower(:n)'),
                           {'n': name}).first()
        if hit is None:
            bind.execute(sa.text('INSERT INTO user_groups (name, description, created_at) '
                                 'VALUES (:n, :d, :c)'),
                         {'n': name[:64], 'd': desc or '', 'c': created or now})
            hit = bind.execute(sa.text('SELECT id FROM user_groups WHERE name = :n'),
                               {'n': name[:64]}).first()
        mapping[gid] = hit[0]
    for gid, uid in bind.execute(sa.text(
            'SELECT group_id, user_id FROM wiki_group_members')).fetchall():
        new = mapping.get(gid)
        if new is None:
            continue
        seen = bind.execute(sa.text('SELECT 1 FROM user_group_members '
                                    'WHERE group_id = :g AND user_id = :u'),
                            {'g': new, 'u': uid}).first()
        if seen is None:
            bind.execute(sa.text('INSERT INTO user_group_members (group_id, user_id) '
                                 'VALUES (:g, :u)'), {'g': new, 'u': uid})
    rows = []
    if guard.has_table('wiki_article_groups'):
        rows = sorted({(a, mapping[g]) for a, g in bind.execute(sa.text(
            'SELECT article_id, group_id FROM wiki_article_groups')).fetchall() if g in mapping})
        op.drop_table('wiki_article_groups')
    _article_groups_table('user_groups')
    for a, g in rows:
        bind.execute(sa.text('INSERT INTO wiki_article_groups (article_id, group_id) '
                             'VALUES (:a, :g)'), {'a': a, 'g': g})
    op.drop_table('wiki_group_members')
    op.drop_table('wiki_groups')


def downgrade():
    """Gives the Wiki its own groups back: one per Access group, same id."""
    bind = op.get_bind()
    guard.create_table(
        'wiki_groups',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(64), nullable=False, unique=True),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False))
    guard.create_table(
        'wiki_group_members',
        sa.Column('group_id', sa.Integer(),
                  sa.ForeignKey('wiki_groups.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('user_id', sa.Integer(),
                  sa.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True))
    bind.execute(sa.text('INSERT INTO wiki_groups (id, name, description, created_at) '
                         'SELECT id, name, description, created_at FROM user_groups'))
    bind.execute(sa.text('INSERT INTO wiki_group_members (group_id, user_id) '
                         'SELECT group_id, user_id FROM user_group_members'))
    rows = bind.execute(sa.text('SELECT article_id, group_id FROM wiki_article_groups')).fetchall()
    op.drop_table('wiki_article_groups')
    _article_groups_table('wiki_groups')
    for a, g in rows:
        bind.execute(sa.text('INSERT INTO wiki_article_groups (article_id, group_id) '
                             'VALUES (:a, :g)'), {'a': a, 'g': g})
