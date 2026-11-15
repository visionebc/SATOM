"""certificate providers + Plugin Studio app packages

Revision ID: spoflow01
Revises: plgpkg01
Create Date: 2026-10-22

managed_certificate.provider  -- the certificate provider that issued it
                                 (services.cert_providers); "" before providers
studio_apps.pkg_version       -- version of the satom.plugin/1 app package
studio_apps.pkg_signer        -- its trusted signer key id ("" = unsigned)
Idempotent.
"""
from alembic import op
import sqlalchemy as sa

revision = 'spoflow01'
down_revision = 'plgpkg01'
branch_labels = None
depends_on = None


def _cols(table):
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade():
    if "provider" not in _cols("managed_certificate"):
        with op.batch_alter_table("managed_certificate") as b:
            b.add_column(sa.Column("provider", sa.String(64), nullable=True, server_default=""))
    have = _cols("studio_apps")
    with op.batch_alter_table("studio_apps") as b:
        if "pkg_version" not in have:
            b.add_column(sa.Column("pkg_version", sa.String(32), nullable=True))
        if "pkg_signer" not in have:
            b.add_column(sa.Column("pkg_signer", sa.String(64), nullable=True))


def downgrade():
    have = _cols("studio_apps")
    with op.batch_alter_table("studio_apps") as b:
        if "pkg_signer" in have:
            b.drop_column("pkg_signer")
        if "pkg_version" in have:
            b.drop_column("pkg_version")
    if "provider" in _cols("managed_certificate"):
        with op.batch_alter_table("managed_certificate") as b:
            b.drop_column("provider")
