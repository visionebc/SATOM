"""Drop the Process tables: the section was removed (operator, 2026-10-25)

Revision ID: procdrop01
Revises: tokgr01
Create Date: 2026-10-25

Runbooks are Plugin Studio apps (services.studio_checks). The one process
that existed (appliance-recovery) became the app of the same name, and every
process with its runs was written to data/process-backup-<stamp>.json on the
primary before this revision. ``api_tokens.process_grants`` stays, unread.
Idempotent: IF EXISTS.
"""
from alembic import op

revision = 'procdrop01'
down_revision = 'tokgr01'
branch_labels = None
depends_on = None

_TABLES = ("process_run_steps", "process_runs", "process_edges", "process_nodes",
           "processes")


def upgrade():
    for t in _TABLES:
        op.execute("DROP TABLE IF EXISTS %s" % t)


def downgrade():
    # The tables are not recreated: the models are gone. Restore from the
    # JSON backup into a Plugin Studio app instead.
    pass
