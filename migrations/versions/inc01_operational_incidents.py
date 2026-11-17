"""Operational incidents (SAT-INC-) with vendor / L3 tickets

Revision ID: inc01
Revises: ds01
Create Date: 2026-11-08

The four tables of models_incidents: the incident, its history, the tickets
opened with a vendor or L3 and their history (FA-0008, operator 2026-11-08:
a runbook run ends by raising a local ticket). Nothing existing is touched.
Idempotent (app.migration_guard): create_all may already have made them.
"""
from alembic import op  # noqa: F401
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'inc01'
down_revision = 'ds01'
branch_labels = None
depends_on = None


def _ts(name, nullable=False):
    if nullable:
        return sa.Column(name, sa.DateTime(), nullable=True)
    return sa.Column(name, sa.DateTime(), nullable=False, server_default=sa.func.now())


def upgrade():
    guard.create_table(
        'op_incidents',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('ref', sa.String(24), nullable=True, unique=True, index=True),
        sa.Column('title', sa.String(200), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False, server_default=''),
        sa.Column('status', sa.String(16), nullable=False, server_default='open', index=True),
        sa.Column('severity', sa.String(4), nullable=False, server_default='P3'),
        sa.Column('owner', sa.String(64), nullable=False, server_default=''),
        sa.Column('appliance_id', sa.Integer(),
                  sa.ForeignKey('appliances.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('appliance_name', sa.String(128), nullable=False, server_default=''),
        sa.Column('source', sa.String(16), nullable=False, server_default='manual'),
        sa.Column('run_id', sa.Integer(),
                  sa.ForeignKey('studio_app_runs.id', ondelete='SET NULL'), nullable=True,
                  unique=True),
        sa.Column('app_slug', sa.String(64), nullable=False, server_default=''),
        sa.Column('itsm_system', sa.String(32), nullable=False, server_default=''),
        sa.Column('itsm_ref', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now(),
                  index=True),
        _ts('updated_at'), _ts('resolved_at', True), _ts('closed_at', True),
    )
    guard.create_table(
        'op_incident_entries',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('incident_id', sa.Integer(),
                  sa.ForeignKey('op_incidents.id', ondelete='CASCADE'), nullable=False,
                  index=True),
        _ts('at'),
        sa.Column('user', sa.String(64), nullable=False, server_default=''),
        sa.Column('kind', sa.String(12), nullable=False, server_default='note'),
        sa.Column('text', sa.Text(), nullable=False, server_default=''),
    )
    guard.create_table(
        'op_vendor_tickets',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('incident_id', sa.Integer(),
                  sa.ForeignKey('op_incidents.id', ondelete='CASCADE'), nullable=False,
                  index=True),
        sa.Column('vendor', sa.String(64), nullable=False),
        sa.Column('ticket_no', sa.String(64), nullable=False, server_default=''),
        sa.Column('url', sa.String(500), nullable=False, server_default=''),
        sa.Column('status', sa.String(16), nullable=False, server_default='open'),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        _ts('created_at'), _ts('updated_at'),
    )
    guard.create_table(
        'op_vendor_ticket_entries',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('ticket_id', sa.Integer(),
                  sa.ForeignKey('op_vendor_tickets.id', ondelete='CASCADE'), nullable=False,
                  index=True),
        _ts('at'),
        sa.Column('user', sa.String(64), nullable=False, server_default=''),
        sa.Column('text', sa.Text(), nullable=False, server_default=''),
    )


def downgrade():
    for t in ('op_vendor_ticket_entries', 'op_vendor_tickets', 'op_incident_entries',
              'op_incidents'):
        if guard.has_table(t):
            op.drop_table(t)
