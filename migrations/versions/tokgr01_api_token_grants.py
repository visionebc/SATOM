"""API tokens: per-object grants (Processes, Plugin Studio apps)

Revision ID: tokgr01
Revises: capfac01
Create Date: 2026-10-24

``api_tokens.process_grants`` and ``api_tokens.studio_app_grants`` hold the
Processes and apps a token may run from /api/v1, each bound to the version an
administrator approved (app/services/token_grants.py). Both default to '[]',
which means NONE: no token issued before this revision gains anything.
Idempotent (app.migration_guard).
"""
from alembic import op  # noqa: F401  (alembic loads revisions that import it)
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'tokgr01'
down_revision = 'capfac01'
branch_labels = None
depends_on = None


def upgrade():
    for col in ("process_grants", "studio_app_grants"):
        guard.add_column("api_tokens", sa.Column(col, sa.Text(), nullable=False,
                                                 server_default="[]"))


def downgrade():
    with op.batch_alter_table("api_tokens") as batch:
        batch.drop_column("studio_app_grants")
        batch.drop_column("process_grants")
