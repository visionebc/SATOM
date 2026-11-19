"""appliances.ssh_password_enc — a CLI login separate from the API credential

Revision ID: sshpw01
Revises: sigidx01_signature_index
Create Date: 2026-10-09

FortiAuthenticator's REST authenticates with an API key that its SSH refuses,
so the single ``password_enc`` cannot serve both channels on that product.
NULL keeps the old behaviour (SSH sends ``password``).
"""
from alembic import op
import sqlalchemy as sa

revision = 'sshpw01'
down_revision = 'sigidx01_signature_index'
branch_labels = None
depends_on = None


def upgrade():
    # Idempotent: ``_ensure_columns()`` in ``app/__init__.py`` adds the same
    # column at boot, so on a running node it exists before alembic gets here.
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'appliances' not in insp.get_table_names():
        return
    if 'ssh_password_enc' in {c['name'] for c in insp.get_columns('appliances')}:
        return
    op.add_column('appliances',
                  sa.Column('ssh_password_enc', sa.Text(), nullable=True))


def downgrade():
    op.drop_column('appliances', 'ssh_password_enc')
