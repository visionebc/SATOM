"""Web Server Manager (Linux ADOM)

Revision ID: wsm01
Revises: studiofold01
Create Date: 2026-11-06

The tables of models_wsm (credentials, audit, script library, schedules,
runs). The Web Server Manager replaces the twelve-plus-six "Web hosts" apps
of Plugin Studio > Examples in the Linux menu (operator, 2026-11-06: "if
something already exists, unify it into one"): the installed ``ex-web-*``
apps are switched off -- kept, not deleted; the example bundle stays
installable as a demonstration of the server step -- and the server
connection they used stays the server record, now reached through the
manager. Idempotent (app.migration_guard): create_all may already have made
the tables.
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'wsm01'
down_revision = 'studiofold01'
branch_labels = None
depends_on = None


def _ts(name, nullable=False):
    if nullable:
        return sa.Column(name, sa.DateTime(), nullable=True)
    return sa.Column(name, sa.DateTime(), nullable=False, server_default=sa.func.now())


def upgrade():
    guard.create_table(
        'wsm_credentials',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(64), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('connection_slug', sa.String(48), nullable=False, index=True),
        sa.Column('owner', sa.String(64), nullable=False, server_default=''),
        sa.Column('shared', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('ssh_user', sa.String(64), nullable=False, server_default=''),
        sa.Column('auth_type', sa.String(16), nullable=False, server_default='password'),
        sa.Column('escalation', sa.String(16), nullable=False, server_default='none'),
        sa.Column('sudo_password', sa.String(8), nullable=False, server_default='same'),
        sa.Column('store_secret', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('run_as', sa.String(8), nullable=False, server_default='auto'),
        sa.Column('modules_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('status', sa.String(12), nullable=False, server_default='active'),
        _ts('expires_at', True),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        _ts('created_at'), _ts('updated_at'), _ts('last_used_at', True), _ts('revoked_at', True),
        sa.Column('revoked_by', sa.String(64), nullable=False, server_default=''),
        sa.UniqueConstraint('connection_slug', 'name', name='uq_wsm_cred_name'),
    )
    guard.create_table(
        'wsm_audit',
        sa.Column('id', sa.Integer(), primary_key=True),
        _ts('at'),
        sa.Column('app_user', sa.String(64), nullable=False, server_default=''),
        sa.Column('ssh_user', sa.String(64), nullable=False, server_default=''),
        sa.Column('effective_user', sa.String(64), nullable=False, server_default=''),
        sa.Column('effective_uid', sa.Integer(), nullable=True),
        sa.Column('connection_slug', sa.String(48), nullable=False, server_default=''),
        sa.Column('host', sa.String(255), nullable=False, server_default=''),
        sa.Column('module', sa.String(16), nullable=False, server_default=''),
        sa.Column('op', sa.String(32), nullable=False, server_default=''),
        sa.Column('target', sa.String(500), nullable=False, server_default=''),
        sa.Column('ok', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('error', sa.String(32), nullable=False, server_default=''),
        sa.Column('detail', sa.String(600), nullable=False, server_default=''),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('sudo', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('credential_id', sa.Integer(), nullable=True),
        sa.Column('credential_name', sa.String(64), nullable=False, server_default=''),
        sa.Column('auth_mode', sa.String(12), nullable=False, server_default=''),
        sa.Column('session_id', sa.String(32), nullable=False, server_default=''),
        sa.Column('ms', sa.Integer(), nullable=True),
        sa.Column('ip', sa.String(45), nullable=False, server_default=''),
    )
    guard.create_table(
        'wsm_scripts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(120), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('interpreter', sa.String(12), nullable=False, server_default='bash'),
        sa.Column('content', sa.Text(), nullable=False, server_default=''),
        sa.Column('args_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('cwd', sa.String(1024), nullable=False, server_default=''),
        sa.Column('timeout', sa.Integer(), nullable=False, server_default='300'),
        sa.Column('owner', sa.String(64), nullable=False, server_default=''),
        sa.Column('shared', sa.Boolean(), nullable=False, server_default=sa.false()),
        _ts('created_at'), _ts('updated_at'),
    )
    guard.create_table(
        'wsm_schedules',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(120), nullable=False),
        sa.Column('connection_slug', sa.String(48), nullable=False, index=True),
        sa.Column('credential_id', sa.Integer(), nullable=True),
        sa.Column('script_id', sa.Integer(), nullable=True),
        sa.Column('run_as', sa.String(8), nullable=False, server_default='self'),
        sa.Column('cron', sa.String(120), nullable=False, server_default='0 2 * * *'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('state', sa.String(16), nullable=False, server_default='never'),
        sa.Column('state_detail', sa.String(500), nullable=False, server_default=''),
        sa.Column('notified_state', sa.String(16), nullable=False, server_default=''),
        _ts('last_run_at', True),
        sa.Column('last_exit', sa.Integer(), nullable=True),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        _ts('created_at'),
    )
    guard.create_table(
        'wsm_runs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('kind', sa.String(12), nullable=False, server_default='script'),
        sa.Column('title', sa.String(300), nullable=False, server_default=''),
        sa.Column('connection_slug', sa.String(48), nullable=False, server_default=''),
        sa.Column('script_id', sa.Integer(), nullable=True),
        sa.Column('schedule_id', sa.Integer(), nullable=True),
        sa.Column('credential_id', sa.Integer(), nullable=True),
        sa.Column('by', sa.String(64), nullable=False, server_default=''),
        sa.Column('ssh_user', sa.String(64), nullable=False, server_default=''),
        sa.Column('effective_user', sa.String(64), nullable=False, server_default=''),
        sa.Column('sudo', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('status', sa.String(12), nullable=False, server_default='running'),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('stdout', sa.Text(), nullable=False, server_default=''),
        sa.Column('stderr', sa.Text(), nullable=False, server_default=''),
        sa.Column('meta_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('job_id', sa.String(64), nullable=False, server_default=''),
        _ts('started_at'), _ts('finished_at', True),
    )
    if guard.has_table('studio_apps'):
        op.get_bind().execute(sa.text(
            "UPDATE studio_apps SET enabled = :f WHERE slug LIKE 'ex-web-%'"), {"f": False})


def downgrade():
    for t in ('wsm_runs', 'wsm_schedules', 'wsm_scripts', 'wsm_audit', 'wsm_credentials'):
        if guard.has_table(t):
            op.drop_table(t)
