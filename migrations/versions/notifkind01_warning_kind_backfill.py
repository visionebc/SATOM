"""Notifications: store warning findings as ``warning``, not ``error``

Revision ID: notifkind01
Revises: nscope01
Create Date: 2026-11-02

Until 2026-11-02 the alert engine stored every WARNING finding in the bell as
``kind='error'`` (``alerts.run`` mapped critical and warning to the same kind),
so the Notifications page drew a memory reading at its warning line with the
same red cross as a device that was down, and its Severity filter could not
separate them. New rows get the right kind (``alerts.bell_kind``); this
re-labels the existing ones, as data, ONLY for the titles whose severity the
engine fixes by construction — the list is frozen here on purpose rather than
read from ``notification_guide``, so a later edit of the guide never re-runs
history differently. Titles whose severity varies (a failing automation, an
unpushed commit, a certificate expiry) are left as they are. Only ``error``
rows are touched, so a row some other feature stored deliberately keeps its
kind. No schema change; the downgrade is a no-op (the old labels were wrong).
"""
from alembic import op
import sqlalchemy as sa

revision = 'notifkind01'
down_revision = 'nscope01'
branch_labels = None
depends_on = None

#: LIKE patterns (no ``_``: it is a wildcard) whose finding is always WARNING
#: in ``services.alerts`` / ``ha_link`` as of 2026-11-02.
WARNING_TITLES = (
    'Config drift on %',
    'Device % is degraded%',
    'Signature DB on % is stale',
    'Signature DB version unreadable on %',
    'No signature source configured',
    '% is running code older than the disk',
    'Host % is degraded%',
    '% commits behind origin',
    'Git status unreadable%',
    'Git push state unreadable%',
    'No database backup bundles present',
    'Newest DB backup is %h old',
    'Intent deviation on %',
)


def upgrade():
    bind = op.get_bind()
    if not sa.inspect(bind).has_table('notifications'):
        return
    for pattern in WARNING_TITLES:
        bind.execute(sa.text("UPDATE notifications SET kind = 'warning' "
                             "WHERE kind = 'error' AND title LIKE :p"),
                     {'p': pattern})


def downgrade():
    pass
