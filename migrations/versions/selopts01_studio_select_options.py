"""Plugin Studio: repair select options saved as a Python list literal

Revision ID: selopts01
Revises: leasetok01
Create Date: 2026-11-05

A select field's ``options`` is a text, one option per line. The Examples
(FortiGate policy finder, NetBox, Web hosts) passed a Python list, which
``clean_fields`` turned into the ONE option ``"['nginx', 'apache']"`` --
so the form refused every real value ("'nginx' is not one of the
choices"). ``clean_fields`` now joins a list; this repairs what was saved,
in the draft (``fields_json``) and the published version
(``published_json.fields``). Only a text that IS a list literal of strings
is changed; data only, idempotent.
"""
import ast
import json

from alembic import op
import sqlalchemy as sa

revision = 'selopts01'
down_revision = 'leasetok01'
branch_labels = None
depends_on = None


def _repair(fields):
    changed = False
    for f in fields if isinstance(fields, list) else []:
        if not isinstance(f, dict) or f.get("type") != "select":
            continue
        raw = f.get("options")
        if not isinstance(raw, str) or not raw.strip().startswith("["):
            continue
        try:
            val = ast.literal_eval(raw.strip())
        except (ValueError, SyntaxError):
            continue
        if isinstance(val, (list, tuple)) and val and all(isinstance(x, str) for x in val):
            f["options"] = "\n".join(x.strip() for x in val if x.strip())
            changed = True
    return changed


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if "studio_apps" not in insp.get_table_names():
        return
    rows = bind.execute(sa.text(
        "SELECT id, fields_json, published_json FROM studio_apps "
        "WHERE fields_json LIKE '%\"options\": \"[%' OR published_json LIKE '%\"options\": \"[%'"
    )).fetchall()
    for rid, fields_json, published_json in rows:
        try:
            fields = json.loads(fields_json or "[]")
            pub = json.loads(published_json or "{}")
        except ValueError:
            continue
        a = _repair(fields)
        b = _repair(pub.get("fields") if isinstance(pub, dict) else None)
        if a or b:
            bind.execute(sa.text("UPDATE studio_apps SET fields_json = :f, published_json = :p "
                                 "WHERE id = :i"),
                         {"f": json.dumps(fields), "p": json.dumps(pub), "i": rid})


def downgrade():
    pass
