"""every plugin is an app: app kind, script apps, disable

Revision ID: appkind01
Revises: spoflow01
Create Date: 2026-10-23

studio_apps.kind         -- "flow" (form + diagram) or "script" (a Script
                            Library script; the app is its entry, the code
                            stays in data/scripts/ for the sandbox runner)
studio_apps.script_slug  -- the script of a "script" app
studio_apps.enabled      -- False = disabled: out of every menu, no runs
Existing scripts get their app on the next start (studio_apps.adopt_scripts),
not here: the library is on disk and a migration must not depend on it.
Idempotent.
"""
from alembic import op
import sqlalchemy as sa

revision = 'appkind01'
down_revision = 'spoflow01'
branch_labels = None
depends_on = None


def _cols(table):
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade():
    have = _cols("studio_apps")
    with op.batch_alter_table("studio_apps") as b:
        if "kind" not in have:
            b.add_column(sa.Column("kind", sa.String(16), nullable=False, server_default="flow"))
        if "script_slug" not in have:
            b.add_column(sa.Column("script_slug", sa.String(48), nullable=True))
        if "enabled" not in have:
            b.add_column(sa.Column("enabled", sa.Boolean(), nullable=False,
                                   server_default=sa.true()))


def downgrade():
    have = _cols("studio_apps")
    with op.batch_alter_table("studio_apps") as b:
        for c in ("enabled", "script_slug", "kind"):
            if c in have:
                b.drop_column(c)
