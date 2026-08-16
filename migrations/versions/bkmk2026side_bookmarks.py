"""bookmarks (right-hand panel: personal + team, per-user placement)

Revision ID: bkmk2026side
Revises: adomreg2026
Create Date: 2026-08-13 03:10:00.000000

Three tables. ``bookmarks`` holds one row per bookmark — including a shared
one, which exists ONCE no matter how many people file it. ``bookmark_placements``
and ``bookmark_favorites`` are per-user, composite-PK, and are what make a
shared row filable and starrable without any member's choice leaking into
anybody else's panel.

Idempotent: skips creation when the tables already exist (``db.create_all`` may
have created them on a prior boot).
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bkmk2026side'
down_revision = 'adomreg2026'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing = set(insp.get_table_names())
    if 'bookmarks' not in existing:
        op.create_table(
            'bookmarks',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('scope', sa.String(length=16), nullable=False,
                      server_default='personal'),
            sa.Column('owner_user_id', sa.Integer(), nullable=False),
            sa.Column('kind', sa.String(length=16), nullable=False,
                      server_default='appliance'),
            sa.Column('appliance_id', sa.Integer(), nullable=True),
            sa.Column('url', sa.Text(), nullable=True),
            sa.Column('view_query', sa.Text(), nullable=True),
            sa.Column('label', sa.String(length=160), nullable=True),
            sa.Column('product', sa.String(length=32), nullable=False,
                      server_default=''),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'],
                                    ondelete='CASCADE'),
            # A retired device must not leave bookmarks pointing at nothing on
            # every operator's panel.
            sa.ForeignKeyConstraint(['appliance_id'], ['appliances.id'],
                                    ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index(op.f('ix_bookmarks_scope'), 'bookmarks', ['scope'])
        op.create_index(op.f('ix_bookmarks_owner_user_id'), 'bookmarks',
                        ['owner_user_id'])
        op.create_index(op.f('ix_bookmarks_appliance_id'), 'bookmarks',
                        ['appliance_id'])
        op.create_index(op.f('ix_bookmarks_product'), 'bookmarks', ['product'])

    if 'bookmark_placements' not in existing:
        op.create_table(
            'bookmark_placements',
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('bookmark_id', sa.Integer(), nullable=False),
            sa.Column('parent_id', sa.Integer(), nullable=True),
            sa.Column('position', sa.Integer(), nullable=False,
                      server_default='0'),
            sa.Column('hidden', sa.Boolean(), nullable=False,
                      server_default=sa.false()),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['user_id'], ['users.id'],
                                    ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['bookmark_id'], ['bookmarks.id'],
                                    ondelete='CASCADE'),
            # Dropping a folder drops the PLACEMENT, never the bookmark: one
            # member's cleanup must not destroy a shared row.
            sa.ForeignKeyConstraint(['parent_id'], ['bookmarks.id'],
                                    ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('user_id', 'bookmark_id'),
        )
        op.create_index(op.f('ix_bookmark_placements_parent_id'),
                        'bookmark_placements', ['parent_id'])

    if 'bookmark_favorites' not in existing:
        op.create_table(
            'bookmark_favorites',
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('bookmark_id', sa.Integer(), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['user_id'], ['users.id'],
                                    ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['bookmark_id'], ['bookmarks.id'],
                                    ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('user_id', 'bookmark_id'),
        )


def downgrade():
    op.drop_table('bookmark_favorites')
    op.drop_index(op.f('ix_bookmark_placements_parent_id'),
                  table_name='bookmark_placements')
    op.drop_table('bookmark_placements')
    op.drop_index(op.f('ix_bookmarks_product'), table_name='bookmarks')
    op.drop_index(op.f('ix_bookmarks_appliance_id'), table_name='bookmarks')
    op.drop_index(op.f('ix_bookmarks_owner_user_id'), table_name='bookmarks')
    op.drop_index(op.f('ix_bookmarks_scope'), table_name='bookmarks')
    op.drop_table('bookmarks')
