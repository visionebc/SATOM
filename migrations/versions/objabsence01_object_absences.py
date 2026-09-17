"""object_absences — the ledger of corroborated disappearances

Revision ID: objabsence01
Revises: fwverdecl01
Create Date: 2026-09-17

The firmware comparison is derived and is rebuilt on every sweep, so a finding
it produced yesterday leaves no trace of when it was first proved, what each
source said at the time, or whether anybody reviewed it. A disappearance that
matters enough to alert on has to outlive the page.

See ``app.models_lifecycle`` for the column rationale and
``app.services.absence_record`` for who writes it.
"""
from alembic import op
import sqlalchemy as sa

revision = 'objabsence01'
down_revision = 'fwverdecl01'
branch_labels = None
depends_on = None


def upgrade():
    # Idempotent: this app also builds its schema with ``db.create_all()`` at
    # boot, so on a running node the table exists before alembic reaches this
    # revision. A migration that dies on that blocks every LATER one, on the
    # node that is actually in production.
    bind = op.get_bind()
    if 'object_absences' in sa.inspect(bind).get_table_names():
        return
    op.create_table(
        'object_absences',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('product', sa.String(length=32), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('urn', sa.String(length=255), nullable=False,
                  server_default=''),
        sa.Column('base_scope', sa.String(length=32), nullable=False),
        sa.Column('target_scope', sa.String(length=32), nullable=False),
        sa.Column('state', sa.String(length=24), nullable=False),
        sa.Column('api_detail', sa.Text(), nullable=False, server_default=''),
        sa.Column('cli_base', sa.String(length=24), nullable=False,
                  server_default=''),
        sa.Column('cli_target', sa.String(length=24), nullable=False,
                  server_default=''),
        sa.Column('cli_device', sa.String(length=64), nullable=False,
                  server_default=''),
        sa.Column('cli_captured_at', sa.String(length=32), nullable=False,
                  server_default=''),
        sa.Column('proposed_path', sa.String(length=255), nullable=False,
                  server_default=''),
        sa.Column('correction', sa.String(length=16), nullable=False,
                  server_default='none'),
        sa.Column('correction_note', sa.Text(), nullable=False,
                  server_default=''),
        sa.Column('previous_urn', sa.String(length=255), nullable=False,
                  server_default=''),
        sa.Column('reviewed_by', sa.String(length=64), nullable=False,
                  server_default=''),
        sa.Column('reviewed_at', sa.DateTime(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(), nullable=False),
        sa.Column('seen_count', sa.Integer(), nullable=False,
                  server_default='1'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('product', 'name', 'base_scope', 'target_scope',
                            name='uq_object_absence_key'),
    )
    op.create_index('ix_object_absences_product', 'object_absences',
                    ['product'])
    op.create_index('ix_object_absences_name', 'object_absences', ['name'])
    op.create_index('ix_object_absences_state', 'object_absences', ['state'])


def downgrade():
    op.drop_table('object_absences')
