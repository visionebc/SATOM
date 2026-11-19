"""Monitoring > Service checks

Revision ID: svc01
Revises: diagstudio01
Create Date: 2026-11-17

``service_checks`` and ``service_check_results`` (app/models_service_checks.py):
synthetic checks that a service answers at the protocol level (HTTP/S with a
screenshot, TLS, TCP, DNS, SSH, SMTP, SSL VPN, OpenVPN, IPsec, WireGuard) and
the certificate it presents. Idempotent (app.migration_guard): create_all may
already have made them.
"""
from alembic import op  # noqa: F401 -- alembic loads every revision with op in scope
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'svc01'
down_revision = 'diagstudio01'
branch_labels = None
depends_on = None


def upgrade():
    guard.create_table(
        'service_checks',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(120), nullable=False),
        sa.Column('kind', sa.String(24), nullable=False),
        sa.Column('target_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('secret_fields', sa.String(200), nullable=False, server_default=''),
        sa.Column('product', sa.String(32), nullable=False, server_default='global'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('interval_min', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('timeout_s', sa.Integer(), nullable=False, server_default='10'),
        sa.Column('cert_warn_days', sa.Integer(), nullable=False, server_default='21'),
        sa.Column('screenshot_every_min', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('fgt_appliance_id', sa.Integer(), nullable=True),
        sa.Column('fgt_tunnel', sa.String(120), nullable=False, server_default=''),
        sa.Column('muted', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('last_status', sa.String(16), nullable=False, server_default='unknown'),
        sa.Column('last_summary', sa.Text(), nullable=False, server_default=''),
        sa.Column('last_checked_at', sa.DateTime(), nullable=True),
        sa.Column('last_changed_at', sa.DateTime(), nullable=True),
        sa.Column('last_shot_at', sa.DateTime(), nullable=True),
        sa.Column('last_shot', sa.String(120), nullable=False, server_default=''),
        sa.Column('created_by', sa.String(80), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )
    guard.create_index('ix_service_checks_kind', 'service_checks', ['kind'])
    guard.create_index('ix_service_checks_product', 'service_checks', ['product'])
    guard.create_table(
        'service_check_results',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('check_id', sa.Integer(),
                  sa.ForeignKey('service_checks.id', ondelete='CASCADE'), nullable=False),
        sa.Column('at', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('latency_ms', sa.Float(), nullable=True),
        sa.Column('summary', sa.Text(), nullable=False, server_default=''),
        sa.Column('detail_json', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('cert_json', sa.Text(), nullable=False, server_default=''),
        sa.Column('cert_days_left', sa.Integer(), nullable=True),
        sa.Column('shot', sa.String(120), nullable=False, server_default=''),
    )
    guard.create_index('ix_svcres_check_at', 'service_check_results', ['check_id', 'at'])


def downgrade():
    for t in ('service_check_results', 'service_checks'):
        if guard.has_table(t):
            op.drop_table(t)
