"""template_bindings + templates.field_decisions

Revision ID: tplbind01
Revises: sshpw01
Create Date: 2026-10-10

``template_bindings``: which device a template governs (family kind+name,
optionally pinned to a version) and the per-device values of its
``{{ variable }}`` placeholders. ``templates.field_decisions``: what the author
decided for each field a newer firmware build adds (keep the device default or
set a value). NULLABLE, no backfill: no template decided a new field before the
decision existed.

Idempotent like the revisions before it: ``_ensure_columns()`` and
``db.create_all()`` in ``app/__init__.py`` make the same column and table on
boot, so a running node already has both before alembic reaches this one.
"""
from alembic import op
import sqlalchemy as sa

revision = 'tplbind01'
down_revision = 'sshpw01'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()
    if 'templates' in tables and 'field_decisions' not in {
            c['name'] for c in insp.get_columns('templates')}:
        op.add_column('templates', sa.Column('field_decisions', sa.Text(), nullable=True))
    if 'template_bindings' not in tables:
        op.create_table(
            'template_bindings',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('appliance_id', sa.Integer(),
                      sa.ForeignKey('appliances.id', ondelete='CASCADE'), nullable=False),
            sa.Column('product', sa.String(32), nullable=False, server_default='fortiweb'),
            sa.Column('kind', sa.String(64), nullable=False),
            sa.Column('name', sa.String(128), nullable=False),
            sa.Column('pinned_version', sa.Integer(), nullable=True),
            sa.Column('variables', sa.Text(), nullable=True),
            sa.Column('note', sa.Text(), nullable=True),
            sa.Column('created_by', sa.String(64), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.UniqueConstraint('appliance_id', 'kind', 'name',
                                name='uq_template_binding_device_family'),
        )
        op.create_index('ix_template_bindings_appliance_id', 'template_bindings', ['appliance_id'])
        op.create_index('ix_template_bindings_kind', 'template_bindings', ['kind'])
        op.create_index('ix_template_bindings_name', 'template_bindings', ['name'])


def downgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'template_bindings' in insp.get_table_names():
        op.drop_table('template_bindings')
    if 'field_decisions' in {c['name'] for c in insp.get_columns('templates')}:
        op.drop_column('templates', 'field_decisions')
