"""api_lib_* — the versioned, append-only API library

Revision ID: apilib01
Revises: upgtgt01
Create Date: 2026-09-25

The file-based API matrix was derived and rewritten wholesale on every rebuild,
and evidence from deleted appliances was filtered out on the way — that is how
the 8.0.3 evidence was lost. These tables store every harvest once (with its
raw payload and a content hash) and keep facts keyed by (thing, build, source),
so knowledge accumulates and nothing is dropped when a device is retired.
Design contract: ``docs/api-library.md``.
"""
from alembic import op
import sqlalchemy as sa

revision = 'apilib01'
down_revision = 'upgtgt01'
branch_labels = None
depends_on = None

_NOW = sa.text('CURRENT_TIMESTAMP')

# Creation order matters for the foreign keys; downgrade walks it backwards.
_TABLES = (
    'api_lib_build', 'api_lib_evidence', 'api_lib_endpoint',
    'api_lib_endpoint_fact', 'api_lib_field', 'api_lib_field_fact',
    'api_lib_span', 'api_lib_field_map',
)


def _ts(name, nullable=False):
    if nullable:
        return sa.Column(name, sa.DateTime(), nullable=True)
    return sa.Column(name, sa.DateTime(), nullable=False, server_default=_NOW)


def _create(name, *cols, indexes=()):
    op.create_table(name, *cols)
    for ix_name, ix_cols in indexes:
        op.create_index(ix_name, name, list(ix_cols))


def upgrade():
    # Idempotent per table on purpose. This app also builds its schema with
    # ``db.create_all()`` at boot, so on an already-running node some or all of
    # these tables exist before alembic reaches this revision. A migration that
    # dies on that blocks every LATER one, on the node that is in production.
    existing = set(sa.inspect(op.get_bind()).get_table_names())

    if 'api_lib_build' not in existing:
        _create(
            'api_lib_build',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('product', sa.String(32), nullable=False),
            sa.Column('version', sa.String(32), nullable=False),
            sa.Column('build', sa.String(32), nullable=False, server_default=''),
            sa.Column('line', sa.String(16), nullable=False, server_default=''),
            sa.Column('line_only', sa.Boolean(), nullable=False,
                      server_default=sa.false()),
            sa.Column('sort_key', sa.String(64), nullable=False, server_default=''),
            sa.Column('origin', sa.String(16), nullable=False,
                      server_default='evidence'),
            _ts('first_seen'), _ts('last_seen'),
            sa.UniqueConstraint('product', 'version',
                                name='uq_api_lib_build_product_version'),
            indexes=(('ix_api_lib_build_product_sort', ('product', 'sort_key')),),
        )

    if 'api_lib_evidence' not in existing:
        _create(
            'api_lib_evidence',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('product', sa.String(32), nullable=False),
            sa.Column('source', sa.String(16), nullable=False),
            sa.Column('build_id', sa.Integer(), sa.ForeignKey('api_lib_build.id'),
                      nullable=True),
            sa.Column('scope_kind', sa.String(8), nullable=False,
                      server_default='build'),
            sa.Column('appliance_id', sa.Integer(), nullable=True),
            sa.Column('device_name', sa.String(128), nullable=False, server_default=''),
            sa.Column('device_serial', sa.String(64), nullable=False, server_default=''),
            sa.Column('device_model', sa.String(128), nullable=False, server_default=''),
            sa.Column('device_hw_type', sa.String(16), nullable=False, server_default=''),
            sa.Column('firmware_raw', sa.String(128), nullable=False, server_default=''),
            sa.Column('origin_ref', sa.String(255), nullable=False, server_default=''),
            _ts('captured_at', nullable=True),
            _ts('ingested_at'), _ts('last_confirmed_at'),
            sa.Column('confirmations', sa.Integer(), nullable=False, server_default='1'),
            sa.Column('sha256', sa.String(64), nullable=False),
            sa.Column('healthy', sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column('skip_reason', sa.String(500), nullable=False, server_default=''),
            sa.Column('summary', sa.JSON(), nullable=True),
            sa.Column('raw_gz', sa.LargeBinary(), nullable=True),
            sa.UniqueConstraint('product', 'source', 'sha256',
                                name='uq_api_lib_evidence_product_source_sha'),
            indexes=(('ix_api_lib_evidence_product_source', ('product', 'source')),
                     ('ix_api_lib_evidence_build_id', ('build_id',)),
                     ('ix_api_lib_evidence_appliance_id', ('appliance_id',))),
        )

    if 'api_lib_endpoint' not in existing:
        _create(
            'api_lib_endpoint',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('product', sa.String(32), nullable=False),
            sa.Column('name', sa.String(160), nullable=False),
            _ts('first_seen'), _ts('last_seen'),
            sa.UniqueConstraint('product', 'name',
                                name='uq_api_lib_endpoint_product_name'),
        )

    if 'api_lib_endpoint_fact' not in existing:
        _create(
            'api_lib_endpoint_fact',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('endpoint_id', sa.Integer(),
                      sa.ForeignKey('api_lib_endpoint.id'), nullable=False),
            sa.Column('build_id', sa.Integer(), sa.ForeignKey('api_lib_build.id'),
                      nullable=False),
            sa.Column('source', sa.String(16), nullable=False),
            sa.Column('urn', sa.String(255), nullable=False, server_default=''),
            sa.Column('section', sa.String(128), nullable=False, server_default=''),
            sa.Column('verdict', sa.String(16), nullable=False, server_default='error'),
            sa.Column('fields_known', sa.Boolean(), nullable=False,
                      server_default=sa.false()),
            sa.Column('witnesses', sa.JSON(), nullable=True),
            sa.Column('first_evidence_id', sa.Integer(), nullable=True),
            sa.Column('last_evidence_id', sa.Integer(), nullable=True),
            _ts('first_seen'), _ts('last_seen'),
            sa.UniqueConstraint('endpoint_id', 'build_id', 'source',
                                name='uq_api_lib_endpoint_fact_key'),
            indexes=(('ix_api_lib_endpoint_fact_build', ('build_id', 'source')),),
        )

    if 'api_lib_field' not in existing:
        _create(
            'api_lib_field',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('endpoint_id', sa.Integer(),
                      sa.ForeignKey('api_lib_endpoint.id'), nullable=False),
            sa.Column('name', sa.String(160), nullable=False),
            _ts('first_seen'), _ts('last_seen'),
            sa.UniqueConstraint('endpoint_id', 'name',
                                name='uq_api_lib_field_endpoint_name'),
        )

    if 'api_lib_field_fact' not in existing:
        _create(
            'api_lib_field_fact',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('field_id', sa.Integer(), sa.ForeignKey('api_lib_field.id'),
                      nullable=False),
            sa.Column('build_id', sa.Integer(), sa.ForeignKey('api_lib_build.id'),
                      nullable=False),
            sa.Column('source', sa.String(16), nullable=False),
            sa.Column('type', sa.String(32), nullable=True),
            sa.Column('options', sa.JSON(), nullable=True),
            sa.Column('default', sa.JSON(), nullable=True),
            sa.Column('required', sa.Boolean(), nullable=True),
            sa.Column('children', sa.JSON(), nullable=True),
            sa.Column('platforms', sa.JSON(), nullable=True),
            sa.Column('first_evidence_id', sa.Integer(), nullable=True),
            sa.Column('last_evidence_id', sa.Integer(), nullable=True),
            _ts('first_seen'), _ts('last_seen'),
            sa.UniqueConstraint('field_id', 'build_id', 'source',
                                name='uq_api_lib_field_fact_key'),
            indexes=(('ix_api_lib_field_fact_build', ('build_id', 'source')),),
        )

    if 'api_lib_span' not in existing:
        _create(
            'api_lib_span',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('endpoint_id', sa.Integer(),
                      sa.ForeignKey('api_lib_endpoint.id'), nullable=False),
            sa.Column('field_id', sa.Integer(), sa.ForeignKey('api_lib_field.id'),
                      nullable=True),
            sa.Column('evidence_id', sa.Integer(),
                      sa.ForeignKey('api_lib_evidence.id'), nullable=False),
            sa.Column('source', sa.String(16), nullable=False,
                      server_default='vendor_doc'),
            sa.Column('from_key', sa.String(64), nullable=False),
            sa.Column('to_key', sa.String(64), nullable=True),
            sa.Column('from_version', sa.String(32), nullable=False, server_default=''),
            sa.Column('to_version', sa.String(32), nullable=False, server_default=''),
            sa.Column('attrs', sa.JSON(), nullable=True),
            indexes=(('ix_api_lib_span_evidence_endpoint', ('evidence_id', 'endpoint_id')),
                     ('ix_api_lib_span_field', ('field_id',)),
                     ('ix_api_lib_span_from', ('from_key',))),
        )

    if 'api_lib_field_map' not in existing:
        _create(
            'api_lib_field_map',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('product', sa.String(32), nullable=False),
            sa.Column('endpoint', sa.String(160), nullable=False),
            sa.Column('from_version', sa.String(32), nullable=False, server_default=''),
            sa.Column('from_field', sa.String(160), nullable=False),
            sa.Column('to_version', sa.String(32), nullable=False, server_default=''),
            sa.Column('to_field', sa.String(160), nullable=False),
            sa.Column('note', sa.String(500), nullable=False, server_default=''),
            sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
            _ts('created_at'),
            indexes=(('ix_api_lib_field_map_product_endpoint', ('product', 'endpoint')),),
        )


def downgrade():
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    for name in reversed(_TABLES):
        if name in existing:
            op.drop_table(name)
