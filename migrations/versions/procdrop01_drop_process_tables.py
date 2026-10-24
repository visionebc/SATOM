"""Drop the Process tables: the section was removed (operator, 2026-10-25)

Revision ID: procdrop01
Revises: tokgr01
Create Date: 2026-10-25

Runbooks are Plugin Studio apps (services.studio_checks). Before a table is
dropped, every row of the five Process tables is written to
``data/process-backup-<UTC stamp>.json`` (0600) on the node that runs the
upgrade — a node that never had a process writes nothing. If that file cannot
be written the upgrade stops and nothing is dropped. ``api_tokens.process_grants``
stays, unread. Idempotent: a table that is already gone is skipped.
"""
import json
import os
import time
from pathlib import Path

import sqlalchemy as sa
from alembic import op

revision = 'procdrop01'
down_revision = 'tokgr01'
branch_labels = None
depends_on = None

# Children first, so a database with foreign keys drops cleanly.
_TABLES = ("process_run_steps", "process_runs", "process_edges", "process_nodes",
           "processes")


def _data_dir() -> Path:
    try:
        from flask import current_app
        return Path(current_app.root_path).parent / "data"
    except RuntimeError:
        return Path(__file__).resolve().parents[2] / "data"


def backup_and_drop(bind, data_dir: Path):
    """Write every Process row to a JSON file, then drop the tables.

    Returns the backup path, or None when there was nothing to keep. Raises
    (and drops nothing) when the backup cannot be written.
    """
    present = [t for t in _TABLES if sa.inspect(bind).has_table(t)]
    dump = {}
    for t in present:
        rows = bind.execute(sa.text("SELECT * FROM %s" % t)).mappings().all()
        dump[t] = [dict(r) for r in rows]
    path = None
    if any(dump.values()):
        data_dir.mkdir(parents=True, exist_ok=True)
        path = data_dir / ("process-backup-%s.json"
                           % time.strftime("%Y%m%d-%H%M%S", time.gmtime()))
        doc = {"kind": "satom.process-backup/1", "revision": revision,
               "written_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "tables": dump}
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(doc, fh, indent=1, default=str)
    for t in present:
        bind.execute(sa.text("DROP TABLE IF EXISTS %s" % t))
    return path


def upgrade():
    path = backup_and_drop(op.get_bind(), _data_dir())
    if path:
        print("procdrop01: Process tables saved to %s" % path)


def downgrade():
    # The tables are not recreated: the models are gone. Rebuild a runbook
    # from the JSON backup as a Plugin Studio app instead.
    pass
