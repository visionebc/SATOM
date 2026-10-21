"""process: event triggers, trigger budget, and the key a run was started by

Revision ID: orch01
Revises: wiki06
Create Date: 2026-10-21

``processes``: ``trigger_event`` (integration-hook event name or ''),
``trigger_filter_json`` (narrowing), ``armed_on_trigger`` (default false: a
triggered walk rehearses) and ``trigger_rate_limit`` (event-triggered runs per
hour, default 10). ``process_runs``: ``trigger_key`` (the finding/event key,
scheduled action or API token that asked for the walk).
services/process_triggers.py. Idempotent (app.migration_guard): a node whose
schema came from ``create-db`` already has the columns and this is a no-op.
"""
from alembic import op  # noqa: F401 — the guard wraps op; kept for symmetry
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'orch01'
down_revision = 'wiki06'
branch_labels = None
depends_on = None


def upgrade():
    guard.add_column('processes',
                     sa.Column('trigger_event', sa.String(64), nullable=False,
                               server_default=''))
    guard.add_column('processes',
                     sa.Column('trigger_filter_json', sa.Text(), nullable=False,
                               server_default='{}'))
    guard.add_column('processes',
                     sa.Column('armed_on_trigger', sa.Boolean(), nullable=False,
                               server_default=sa.false()))
    guard.add_column('processes',
                     sa.Column('trigger_rate_limit', sa.Integer(), nullable=False,
                               server_default='10'))
    guard.add_column('process_runs',
                     sa.Column('trigger_key', sa.String(200), nullable=False,
                               server_default=''))


def downgrade():
    with op.batch_alter_table('process_runs') as b:
        b.drop_column('trigger_key')
    with op.batch_alter_table('processes') as b:
        b.drop_column('trigger_rate_limit')
        b.drop_column('armed_on_trigger')
        b.drop_column('trigger_filter_json')
        b.drop_column('trigger_event')
