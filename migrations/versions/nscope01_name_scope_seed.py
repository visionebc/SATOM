"""Name scope: the one-time values for an existing install

Revision ID: nscope01
Revises: appgroup01
Create Date: 2026-10-31

Administrator > Classification > Name scope (``app_settings`` key
``classification.name_scope``) is the only place the ``{scope}`` of a name is
written. An install that already runs spo-fortiweb named its objects with the
scope the plugin carried itself (``split`` -> ``ext``, ``internal-external``
-> ``all``, ``internal`` -> none); this writes those values ONCE, as data,
from the plugin's ``spo-fortiweb-rules`` data store
(``settings_store.seed_name_scope``), so no name changes. No store: on, no
values. A row that already exists is never touched. No schema change.
"""
import json

from alembic import op
import sqlalchemy as sa

revision = 'nscope01'
down_revision = 'appgroup01'
branch_labels = None
depends_on = None

KEY = 'classification.name_scope'


def upgrade():
    from app.services.settings_store import seed_name_scope
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table('app_settings'):
        return
    if bind.execute(sa.text('SELECT 1 FROM app_settings WHERE key = :k'),
                    {'k': KEY}).first():
        return
    rules = []
    if insp.has_table('studio_datastores') and insp.has_table('studio_rows'):
        rows = bind.execute(sa.text(
            'SELECT r.data_json FROM studio_rows r JOIN studio_datastores s '
            'ON s.id = r.store_id WHERE s.slug = :slug ORDER BY r.id'),
            {'slug': 'spo-fortiweb-rules'}).fetchall()
        for (raw,) in rows:
            try:
                d = json.loads(raw or '{}')
            except ValueError:
                continue
            if isinstance(d, dict):
                rules.append(d)
    cfg = seed_name_scope(rules)
    bind.execute(sa.text('INSERT INTO app_settings (key, value, updated_at) '
                         'VALUES (:k, :v, CURRENT_TIMESTAMP)'),
                 {'k': KEY, 'v': json.dumps(cfg)})


def downgrade():
    op.get_bind().execute(sa.text('DELETE FROM app_settings WHERE key = :k'), {'k': KEY})
