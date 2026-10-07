"""api_lib_*_fact.attrs — channel metadata for the CLI evidence sources

Revision ID: apilib05_cli_channel
Revises: apibl01
Create Date: 2026-10-07

The API library learns two new evidence sources, ``cli_tree`` (the schema the
appliance's CLI ``tree`` command prints) and ``cli_full`` (the field names
``show full-configuration`` reveals, hidden fields included). What they know
beyond a field's type and options — the CLI attribute id, whether the field is
hidden from ``tree``, its range, the raw CLI type, whether it is a datasource —
goes into one JSON column per fact table, so the facts stay keyed by
(thing, build, source) and nothing else in the schema moves.
Design contract: ``docs/api-library.md`` ("CLI channel and hidden fields").

Idempotent like ``apilib01``: ``db.create_all()`` (fresh install) and
``_ensure_columns`` (boot of a running node) may have added the columns before
alembic reaches this revision.
"""
from alembic import op
import sqlalchemy as sa

revision = 'apilib05_cli_channel'
down_revision = 'apibl01'
branch_labels = None
depends_on = None

_TABLES = ('api_lib_endpoint_fact', 'api_lib_field_fact')


def upgrade():
    insp = sa.inspect(op.get_bind())
    existing = set(insp.get_table_names())
    for table in _TABLES:
        if table not in existing:
            continue
        have = {c['name'] for c in insp.get_columns(table)}
        if 'attrs' not in have:
            op.add_column(table, sa.Column('attrs', sa.JSON(), nullable=True))


def downgrade():
    insp = sa.inspect(op.get_bind())
    existing = set(insp.get_table_names())
    for table in _TABLES:
        if table not in existing:
            continue
        have = {c['name'] for c in insp.get_columns(table)}
        if 'attrs' in have:
            with op.batch_alter_table(table) as batch:
                batch.drop_column('attrs')
