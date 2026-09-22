"""upgrade_prep.target_version — the version a pre-flight was run TOWARDS

Revision ID: upgtgt01
Revises: objabsence01
Create Date: 2026-09-21

``UpgradePrep.firmware`` records the version the appliance was RUNNING when the
pre-flight ran. Nothing recorded where it was going. The consequence was not
cosmetic: the same green run was equally valid "evidence" for 7.6.4 -> 7.6.8
and for 7.6.4 -> 8.0.5, which are different moves with different release notes
and different breaking changes, and a change request citing that run could not
state which of them it had been pre-flighted for.

NULLABLE, no server default, no backfill. A run stored before this column was
taken without anybody declaring a destination; writing one in now — even '' —
would put a claim on evidence nobody made. Readers render NULL as
"not declared".
"""
from alembic import op
import sqlalchemy as sa

revision = 'upgtgt01'
down_revision = 'objabsence01'
branch_labels = None
depends_on = None


def upgrade():
    # Idempotent on purpose: this app's authoritative schema step is the
    # boot-time ``_ensure_columns()`` in ``app/__init__.py``, which adds the
    # same column with the same DDL. On an already-running node the column is
    # therefore here before alembic ever reaches this revision, and a
    # migration that dies on that blocks every LATER one — on the node that is
    # actually in production.
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'upgrade_prep' not in insp.get_table_names():
        return
    if 'target_version' in {c['name'] for c in insp.get_columns('upgrade_prep')}:
        return
    op.add_column('upgrade_prep',
                  sa.Column('target_version', sa.String(length=32),
                            nullable=True))


def downgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'upgrade_prep' not in insp.get_table_names():
        return
    if 'target_version' not in {c['name'] for c in insp.get_columns('upgrade_prep')}:
        return
    op.drop_column('upgrade_prep', 'target_version')
