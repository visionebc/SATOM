"""process triggers -> Administrator > Triggers (one way to start a process)

Revision ID: trig02
Revises: trig01
Create Date: 2026-10-22

Until 3.4.6 a process could carry its own trigger (processes.trigger_event,
trigger_filter_json, armed_on_trigger). Since 3.4.7 an event starts a process
ONLY through a trigger and a "Walk a process" automation, so each embedded
trigger becomes:

* a trigger ``process-<key>`` on the same event, with the same filter (the
  keys are the same: products, appliance_ids, families, min_severity), no
  cooldown and no hourly budget of its own -- the process's own budget
  (trigger_rate_limit) still applies to every event-triggered walk;
* an automation ``process-<key>`` that walks the process, armed exactly when
  the process was armed on trigger, enabled when the process was enabled;

and the process's trigger columns are cleared. Plain SQL, no ORM: a migration
must not depend on the models of a later version. Idempotent: a process
whose trigger was already converted has an empty trigger_event.
"""
import json
from datetime import datetime

from alembic import op
import sqlalchemy as sa

revision = 'trig02'
down_revision = 'trig01'
branch_labels = None
depends_on = None


def _free_key(bind, table, base):
    key, n = base[:48], 2
    while bind.execute(sa.text("SELECT 1 FROM %s WHERE key = :k" % table),
                       {"k": key}).first() is not None:
        suffix = "-%d" % n
        key, n = base[:48 - len(suffix)] + suffix, n + 1
    return key


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not {"processes", "triggers", "event_automations"} <= set(insp.get_table_names()):
        return
    rows = bind.execute(sa.text(
        "SELECT id, key, name, enabled, trigger_event, trigger_filter_json, "
        "armed_on_trigger, products_json, created_by FROM processes "
        "WHERE trigger_event IS NOT NULL AND trigger_event <> ''")).mappings().all()
    now = datetime.utcnow()
    for r in rows:
        try:
            cond = json.loads(r["trigger_filter_json"] or "{}") or {}
        except ValueError:
            cond = {}
        cond = {k: v for k, v in cond.items()
                if k in ("products", "appliance_ids", "families", "min_severity") and v}
        try:
            products = json.loads(r["products_json"] or "[]") or []
        except ValueError:
            products = []
        owner = (r["created_by"] or "").strip() or "admin"
        tkey = _free_key(bind, "triggers", "process-" + r["key"])
        bind.execute(sa.text(
            "INSERT INTO triggers (key, name, description, enabled, event, conditions_json, "
            "cooldown_minutes, rate_limit_per_hour, created_by, updated_by, created_at, "
            "updated_at) VALUES (:key, :name, :descr, :enabled, :event, :cond, 0, 0, "
            ":by, :by, :now, :now)"),
            {"key": tkey, "name": ("Process %s" % r["name"])[:120],
             "descr": "Moved from process %s's own trigger (3.4.7)." % r["key"],
             "enabled": bool(r["enabled"]), "event": r["trigger_event"],
             "cond": json.dumps(cond, sort_keys=True), "by": "migration:trig02", "now": now})
        tid = bind.execute(sa.text("SELECT id FROM triggers WHERE key = :k"),
                           {"k": tkey}).scalar()
        akey = _free_key(bind, "event_automations", "process-" + r["key"])
        bind.execute(sa.text(
            "INSERT INTO event_automations (key, name, description, enabled, trigger_id, kind, "
            "target, params_json, armed, product, owner, created_at, updated_at, updated_by, "
            "last_status) VALUES (:key, :name, :descr, :enabled, :tid, 'process', :target, "
            "'{}', :armed, :product, :owner, :now, :now, 'migration:trig02', '')"),
            {"key": akey, "name": ("Walk %s" % r["name"])[:120],
             "descr": "Moved from process %s's own trigger (3.4.7)." % r["key"],
             "enabled": bool(r["enabled"]), "tid": tid, "target": r["key"],
             "armed": bool(r["armed_on_trigger"]),
             "product": products[0] if len(products) == 1 else "", "owner": owner,
             "now": now})
        bind.execute(sa.text(
            "UPDATE processes SET trigger_event = '', trigger_filter_json = '{}', "
            "armed_on_trigger = :f WHERE id = :id"), {"f": False, "id": r["id"]})


def downgrade():
    # The conversion is not undone: the triggers and automations it made are
    # ordinary rows an operator may have edited since.
    pass
