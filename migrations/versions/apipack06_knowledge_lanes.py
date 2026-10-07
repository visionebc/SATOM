"""knowledge lanes: knowledge_signature_meta + provenance of pack field maps

Revision ID: apipack06_knowledge_lanes
Revises: apilib05_cli_channel
Create Date: 2026-10-08

SATOM 3.0 imports two pack lanes (``api_pack``, ``knowledge``) with new
sections (docs/api-library.md §12):

* ``knowledge_signature_meta`` — public FortiGuard metadata per (product,
  signature id), filled by the ``signature-meta`` section.
* ``api_lib_field_map.status`` / ``.origin`` — a rename a pack proposes is a
  ``candidate`` that no reader applies; an operator-authored map is
  ``active``. ``origin`` says who wrote the row (``local`` or
  ``pack:<lane>:<pack>``) so a pack never overrides a local row.

Idempotent (``app.migration_guard``): ``db.create_all()`` and
``_ensure_columns`` may have created both before alembic reaches this revision.
"""
from alembic import op
import sqlalchemy as sa

from app import migration_guard as mg

revision = 'apipack06_knowledge_lanes'
down_revision = 'apilib05_cli_channel'
branch_labels = None
depends_on = None


def upgrade():
    mg.create_table(
        'knowledge_signature_meta',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('product', sa.String(32), nullable=False),
        sa.Column('sig_id', sa.String(64), nullable=False),
        sa.Column('name', sa.String(255), nullable=False, server_default=''),
        sa.Column('severity', sa.String(32), nullable=False, server_default=''),
        sa.Column('category', sa.String(128), nullable=False, server_default=''),
        sa.Column('cve', sa.JSON(), nullable=True),
        sa.Column('references', sa.JSON(), nullable=True),
        sa.Column('url', sa.String(512), nullable=False, server_default=''),
        sa.Column('summary', sa.Text(), nullable=False, server_default=''),
        sa.Column('origin', sa.String(128), nullable=False, server_default='local'),
        sa.Column('imported_at', sa.DateTime(), nullable=False,
                  server_default=sa.func.current_timestamp()),
        sa.UniqueConstraint('product', 'sig_id', name='uq_knowledge_signature_meta_product_sig'),
    )
    if mg.has_table('api_lib_field_map'):
        mg.add_column('api_lib_field_map',
                      sa.Column('status', sa.String(16), nullable=False, server_default='active'))
        mg.add_column('api_lib_field_map',
                      sa.Column('origin', sa.String(128), nullable=False, server_default='local'))


def downgrade():
    insp = sa.inspect(op.get_bind())
    if 'api_lib_field_map' in insp.get_table_names():
        have = {c['name'] for c in insp.get_columns('api_lib_field_map')}
        with op.batch_alter_table('api_lib_field_map') as batch:
            for col in ('origin', 'status'):
                if col in have:
                    batch.drop_column(col)
    if 'knowledge_signature_meta' in insp.get_table_names():
        op.drop_table('knowledge_signature_meta')
