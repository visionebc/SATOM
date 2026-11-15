"""Plugin Studio folders

Revision ID: studiofold01
Revises: tlsname01
Create Date: 2026-11-06

``studio_folders``: the menu groups of Plugin Studio as objects of their own
(models_studio.StudioFolder), so a whole folder can be given to ADOMs and
user groups. ``studio_apps.menu_group`` keeps the folder's name. One folder
is made for every group some app is already filed under, with no grants:
nobody sees anything they did not see before. Idempotent
(app.migration_guard): create_all may already have made the table.
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'studiofold01'
down_revision = 'tlsname01'
branch_labels = None
depends_on = None


def upgrade():
    guard.create_table(
        'studio_folders',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(48), nullable=False, unique=True),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('adoms_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('groups_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('updated_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    bind = op.get_bind()
    have = {r[0].lower() for r in bind.execute(sa.text("SELECT name FROM studio_folders"))}
    for (name,) in bind.execute(sa.text(
            "SELECT DISTINCT menu_group FROM studio_apps WHERE menu_group <> ''")).fetchall():
        if name.lower() in have:
            continue
        have.add(name.lower())
        # every column named: create_all may have made the table from the
        # model, whose defaults live in Python, not in the database
        bind.execute(sa.text(
            "INSERT INTO studio_folders (name, description, adoms_json, groups_json, "
            "created_by, updated_by, created_at, updated_at) VALUES (:n, '', '[]', '[]', "
            "'migration', 'migration', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"), {"n": name})


def downgrade():
    if guard.has_table('studio_folders'):
        op.drop_table('studio_folders')
