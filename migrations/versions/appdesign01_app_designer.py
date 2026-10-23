"""app designer: the look of a Plugin Studio app, and its images

Revision ID: appdesign01
Revises: appkind01
Create Date: 2026-10-23

studio_apps.design_json -- {theme, page, result} (services.studio_design);
                           "{}" = SATOM's standard layout, so every existing
                           app looks exactly as before
studio_app_assets       -- images uploaded to a design (PNG/JPEG/GIF/WebP,
                           sniffed), in the database so they replicate to the
                           standby and travel in the app's package
Idempotent.
"""
from alembic import op
import sqlalchemy as sa

revision = 'appdesign01'
down_revision = 'appkind01'
branch_labels = None
depends_on = None


def _insp():
    return sa.inspect(op.get_bind())


def upgrade():
    have = {c["name"] for c in _insp().get_columns("studio_apps")}
    if "design_json" not in have:
        with op.batch_alter_table("studio_apps") as b:
            b.add_column(sa.Column("design_json", sa.Text(), nullable=False, server_default="{}"))
    if not _insp().has_table("studio_app_assets"):
        op.create_table(
            "studio_app_assets",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("app_id", sa.Integer(), sa.ForeignKey("studio_apps.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("sha256", sa.String(64), nullable=False),
            sa.Column("mime", sa.String(32), nullable=False),
            sa.Column("name", sa.String(120), nullable=False, server_default=""),
            sa.Column("size", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("data", sa.LargeBinary(), nullable=False),
            sa.Column("created_by", sa.String(64), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.UniqueConstraint("app_id", "sha256", name="uq_studio_app_asset"))
        op.create_index("ix_studio_app_assets_app_id", "studio_app_assets", ["app_id"])


def downgrade():
    if _insp().has_table("studio_app_assets"):
        op.drop_index("ix_studio_app_assets_app_id", table_name="studio_app_assets")
        op.drop_table("studio_app_assets")
    have = {c["name"] for c in _insp().get_columns("studio_apps")}
    if "design_json" in have:
        with op.batch_alter_table("studio_apps") as b:
            b.drop_column("design_json")
