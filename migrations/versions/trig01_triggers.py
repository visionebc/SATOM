"""triggers + event automations (the orchestrator)

Revision ID: trig01
Revises: studio02
Create Date: 2026-10-22

Triggers are created under Administrator, their implementation lives under
Automation › Automations › On a trigger (app/models_triggers.py,
services/trigger_engine.py). Idempotent (app.migration_guard): create_all
may already have made the tables.
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'trig01'
down_revision = 'studio02'
branch_labels = None
depends_on = None


def upgrade():
    if guard.create_table(
            'triggers',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('key', sa.String(48), nullable=False, unique=True),
            sa.Column('name', sa.String(120), nullable=False),
            sa.Column('description', sa.Text(), nullable=False, server_default=''),
            sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column('event', sa.String(64), nullable=False),
            sa.Column('conditions_json', sa.Text(), nullable=False, server_default='{}'),
            sa.Column('cooldown_minutes', sa.Integer(), nullable=False, server_default='60'),
            sa.Column('rate_limit_per_hour', sa.Integer(), nullable=False, server_default='20'),
            sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
            sa.Column('updated_by', sa.String(64), nullable=False, server_default=''),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('last_fired_at', sa.DateTime(), nullable=True)):
        op.create_index('ix_triggers_key', 'triggers', ['key'])
        op.create_index('ix_triggers_event', 'triggers', ['event'])
    if guard.create_table(
            'trigger_fires',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('trigger_id', sa.Integer(),
                      sa.ForeignKey('triggers.id', ondelete='CASCADE'), nullable=False),
            sa.Column('event', sa.String(64), nullable=False),
            sa.Column('subject', sa.String(200), nullable=False, server_default=''),
            sa.Column('status', sa.String(16), nullable=False, server_default='matched'),
            sa.Column('reason', sa.Text(), nullable=False, server_default=''),
            sa.Column('depth', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('payload_json', sa.Text(), nullable=False, server_default='{}'),
            sa.Column('by', sa.String(64), nullable=False, server_default=''),
            sa.Column('fired_at', sa.DateTime(), nullable=False)):
        op.create_index('ix_trigger_fires_trigger_id', 'trigger_fires', ['trigger_id'])
        op.create_index('ix_trigger_fires_fired_at', 'trigger_fires', ['fired_at'])
    if guard.create_table(
            'event_automations',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('key', sa.String(48), nullable=False, unique=True),
            sa.Column('name', sa.String(120), nullable=False),
            sa.Column('description', sa.Text(), nullable=False, server_default=''),
            sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column('trigger_id', sa.Integer(), sa.ForeignKey('triggers.id'), nullable=False),
            sa.Column('kind', sa.String(24), nullable=False),
            sa.Column('target', sa.String(120), nullable=False, server_default=''),
            sa.Column('params_json', sa.Text(), nullable=False, server_default='{}'),
            sa.Column('armed', sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column('product', sa.String(32), nullable=False, server_default=''),
            sa.Column('owner', sa.String(64), nullable=False, server_default=''),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.Column('updated_by', sa.String(64), nullable=False, server_default=''),
            sa.Column('last_run_at', sa.DateTime(), nullable=True),
            sa.Column('last_status', sa.String(16), nullable=False, server_default='')):
        op.create_index('ix_event_automations_key', 'event_automations', ['key'])
        op.create_index('ix_event_automations_trigger_id', 'event_automations', ['trigger_id'])
    if guard.create_table(
            'event_automation_runs',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('automation_id', sa.Integer(),
                      sa.ForeignKey('event_automations.id', ondelete='CASCADE'),
                      nullable=False),
            sa.Column('fire_id', sa.Integer(),
                      sa.ForeignKey('trigger_fires.id', ondelete='SET NULL'), nullable=True),
            sa.Column('status', sa.String(16), nullable=False, server_default='queued'),
            sa.Column('armed', sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column('summary', sa.Text(), nullable=False, server_default=''),
            sa.Column('ref', sa.String(120), nullable=False, server_default=''),
            sa.Column('job_id', sa.String(64), nullable=False, server_default=''),
            sa.Column('test', sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column('started_at', sa.DateTime(), nullable=False),
            sa.Column('ended_at', sa.DateTime(), nullable=True)):
        op.create_index('ix_event_automation_runs_automation_id', 'event_automation_runs',
                        ['automation_id'])
        op.create_index('ix_event_automation_runs_fire_id', 'event_automation_runs',
                        ['fire_id'])
        op.create_index('ix_event_automation_runs_started_at', 'event_automation_runs',
                        ['started_at'])


def downgrade():
    op.drop_table('event_automation_runs')
    op.drop_table('event_automations')
    op.drop_table('trigger_fires')
    op.drop_table('triggers')
