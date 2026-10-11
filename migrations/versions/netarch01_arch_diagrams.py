"""arch_diagrams (Fleet → Architecture drawings)

Revision ID: netarch01
Revises: tplbind01
Create Date: 2026-10-11

One row per operator-drawn network diagram; ``layout`` holds the validated
drawing JSON. Idempotent like the revisions before it: ``db.create_all()`` in
``app/__init__.py`` makes the same table on boot, so a running node already
has it before alembic reaches this one.
"""
from alembic import op
import sqlalchemy as sa

revision = 'netarch01'
down_revision = 'tplbind01'
branch_labels = None
depends_on = None


def upgrade():
    insp = sa.inspect(op.get_bind())
    if 'arch_diagrams' not in insp.get_table_names():
        op.create_table(
            'arch_diagrams',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('name', sa.String(120), nullable=False, unique=True),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('layout', sa.Text(), nullable=False),
            sa.Column('created_by', sa.String(64), nullable=True),
            sa.Column('updated_by', sa.String(64), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
        )


def downgrade():
    insp = sa.inspect(op.get_bind())
    if 'arch_diagrams' in insp.get_table_names():
        op.drop_table('arch_diagrams')
