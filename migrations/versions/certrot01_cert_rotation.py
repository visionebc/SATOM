"""managed_certificate origin + per-cert rotation windows; cert_revocation

Revision ID: certrot01
Revises: diagbat01
Create Date: 2026-10-15

``managed_certificate`` learns where a certificate came from (``origin``:
signed by the configured CA, CSR signed by another CA, or certificate + key
imported) and its own rotation windows: renew N days before expiry, swap N
days after the renewal, take the old one off the device N days after the
swap, keep it in SATOM N days after that. NULL windows mean "the class /
lifecycle-policy default", which is what every existing row followed.
``status`` widens to 32 for ``awaiting_signature``.

``cert_revocation`` is the revocation register. It outlives the certificate
record (``cert_id`` goes NULL on delete) so what was revoked stays answerable.

Idempotent like the revisions before it: ``_ensure_columns()``,
``_ensure_widths()`` and ``db.create_all()`` in ``app/__init__.py`` make the
same columns, width and table on boot.
"""
from alembic import op
import sqlalchemy as sa

revision = 'certrot01'
down_revision = 'diagbat01'
branch_labels = None
depends_on = None

_COLUMNS = (
    ('origin', lambda: sa.Column('origin', sa.String(16), nullable=False,
                                 server_default='signer')),
    ('key_origin', lambda: sa.Column('key_origin', sa.String(16), nullable=False,
                                     server_default='satom')),
    ('auto_renew', lambda: sa.Column('auto_renew', sa.Boolean(), nullable=False,
                                     server_default=sa.true())),
    ('renew_before_days', lambda: sa.Column('renew_before_days', sa.Integer(), nullable=True)),
    ('swap_after_days', lambda: sa.Column('swap_after_days', sa.Integer(), nullable=True)),
    ('remove_after_days', lambda: sa.Column('remove_after_days', sa.Integer(), nullable=True)),
    ('retain_days', lambda: sa.Column('retain_days', sa.Integer(), nullable=True)),
    ('revoke_superseded', lambda: sa.Column('revoke_superseded', sa.Boolean(), nullable=True)),
    ('swap_due_at', lambda: sa.Column('swap_due_at', sa.DateTime(), nullable=True)),
    ('swapped_at', lambda: sa.Column('swapped_at', sa.DateTime(), nullable=True)),
    ('removed_at', lambda: sa.Column('removed_at', sa.DateTime(), nullable=True)),
    ('archived_at', lambda: sa.Column('archived_at', sa.DateTime(), nullable=True)),
)


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()
    if 'managed_certificate' in tables:
        have = {c['name']: c for c in insp.get_columns('managed_certificate')}
        for name, make in _COLUMNS:
            if name not in have:
                op.add_column('managed_certificate', make())
        status = have.get('status')
        length = getattr(status.get('type'), 'length', None) if status else None
        if bind.dialect.name != 'sqlite' and length is not None and length < 32:
            op.alter_column('managed_certificate', 'status',
                            type_=sa.String(32), existing_nullable=False)
    if 'cert_revocation' not in tables:
        op.create_table(
            'cert_revocation',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('cert_id', sa.Integer(),
                      sa.ForeignKey('managed_certificate.id', ondelete='SET NULL'),
                      nullable=True),
            sa.Column('cert_name', sa.String(128), nullable=False, server_default=''),
            sa.Column('serial', sa.String(128), nullable=True),
            sa.Column('fingerprint_sha256', sa.String(128), nullable=True),
            sa.Column('subject', sa.String(512), nullable=True),
            sa.Column('issuer', sa.String(512), nullable=True),
            sa.Column('ca_label', sa.String(256), nullable=True),
            sa.Column('reason', sa.String(32), nullable=False, server_default='unspecified'),
            sa.Column('result', sa.String(16), nullable=False, server_default='manual_pending'),
            sa.Column('detail', sa.Text(), nullable=True),
            sa.Column('requested_by', sa.String(64), nullable=True),
            sa.Column('requested_at', sa.DateTime(), nullable=False),
            sa.Column('confirmed_by', sa.String(64), nullable=True),
            sa.Column('confirmed_at', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_cert_revocation_cert_id', 'cert_revocation', ['cert_id'])
        op.create_index('ix_cert_revocation_result', 'cert_revocation', ['result'])
        op.create_index('ix_cert_revocation_requested_at', 'cert_revocation',
                        ['requested_at'])


def downgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()
    if 'cert_revocation' in tables:
        op.drop_table('cert_revocation')
    if 'managed_certificate' in tables:
        have = {c['name'] for c in insp.get_columns('managed_certificate')}
        for name, _make in reversed(_COLUMNS):
            if name in have:
                op.drop_column('managed_certificate', name)
