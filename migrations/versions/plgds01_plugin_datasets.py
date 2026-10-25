"""Plugin datasets an administrator builds (Administrator › Database)

Revision ID: plgds01
Revises: plgpub01
Create Date: 2026-10-25

``plugin_datasets`` holds the datasets an administrator built with the
Report Builder's query builder for plugins, next to the built-in ones and the
device-object ones (``services.plugin_datasets``): one row per dataset,
``key`` = what a plugin declares (``admin.<slug>``), ``spec`` = the query
(JSON), ``product`` = the ADOM it belongs to ('' = every ADOM), ``status`` =
draft | published | pending (came in with an imported package, waits for an
administrator). Idempotent (app.migration_guard).
"""
from alembic import op
from app import migration_guard as guard
import sqlalchemy as sa

revision = 'plgds01'
down_revision = 'plgpub01'
branch_labels = None
depends_on = None


def upgrade():
    guard.create_table(
        "plugin_datasets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(80), nullable=False),
        sa.Column("label", sa.String(120), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("spec", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("product", sa.String(32), nullable=False, server_default=""),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("source", sa.String(120), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(64), nullable=False, server_default=""),
        sa.Column("updated_by", sa.String(64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    guard.create_index(op.f("ix_plugin_datasets_key"), "plugin_datasets", ["key"], unique=True)


def downgrade():
    op.drop_index(op.f("ix_plugin_datasets_key"), table_name="plugin_datasets")
    op.drop_table("plugin_datasets")
