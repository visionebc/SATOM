"""plugin packages: Plugin Studio rows remember the imported package

Revision ID: plgpkg01
Revises: trig02
Create Date: 2026-10-22

plugins.pkg_version -- version of the satom.plugin/1 package last imported
plugins.pkg_signer  -- trusted signer key id ("" = imported unsigned)
Both NULL for a plugin authored on this server. Idempotent.
"""
from alembic import op
import sqlalchemy as sa

revision = 'plgpkg01'
down_revision = 'trig02'
branch_labels = None
depends_on = None


def _cols():
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns("plugins")}


def upgrade():
    have = _cols()
    with op.batch_alter_table("plugins") as b:
        if "pkg_version" not in have:
            b.add_column(sa.Column("pkg_version", sa.String(32), nullable=True))
        if "pkg_signer" not in have:
            b.add_column(sa.Column("pkg_signer", sa.String(64), nullable=True))


def downgrade():
    have = _cols()
    with op.batch_alter_table("plugins") as b:
        if "pkg_signer" in have:
            b.drop_column("pkg_signer")
        if "pkg_version" in have:
            b.drop_column("pkg_version")
