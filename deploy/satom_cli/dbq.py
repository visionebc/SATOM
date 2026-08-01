"""Database-backed reads for the CLI. STDLIB ONLY (see context.py).

Every query here goes through ``psql`` with the APP's own credentials, never
``runuser -u postgres``: that only works as root, which is precisely the bug
that silently killed ``scheduler_guard.sh`` and ``satom-git-publish.sh`` when
the units dropped to the service account. A read that only works for root is a
read the operator cannot use.

Every function returns ``(rows, err)`` and NEVER raises. ``rows is None``
means "could not ask" — which the callers must render as *unknown*, never as
*fine*. Absence of data is not health; that rule is why the Fleet health badge
had to be rebuilt.
"""
import os

from .context import run

SEP = "\x1f"   # field separator that cannot appear in the text columns we read


def query(ctx, sql, timeout=20):
    """(rows, err). rows = list of list[str]."""
    parts = ctx.db_parts()
    if not parts:
        return None, ("database credentials unavailable — .env is not readable "
                      "as %s (it is 0640 root:%s on purpose)" % (ctx.user, ctx.app_user))
    user, pw, host, port, dbname = parts
    env = dict(os.environ, PGPASSWORD=pw)
    rc, out, err = run(["psql", "-h", host, "-p", port, "-U", user, "-d", dbname,
                        "-tA", "-F", SEP, "-c", sql], timeout=timeout, env=env)
    if rc != 0:
        tail = (err or out or "psql failed").strip().splitlines()
        return None, tail[-1] if tail else "psql failed"
    return [ln.split(SEP) for ln in out.splitlines() if ln.strip()], ""


def one(ctx, sql, timeout=20):
    rows, err = query(ctx, sql, timeout)
    if rows is None:
        return None, err
    return (rows[0] if rows else []), ""


# -- catalogue of the reads the CLI needs --------------------------------
# Kept here rather than inline in the handlers so that a schema change is one
# edit, and so `get` and `diagnose` can never disagree about what they read.

ACTIONS = """
SELECT id, name, action, enabled, COALESCE(last_status,''),
       COALESCE(to_char(last_run,'YYYY-MM-DD HH24:MI'),''),
       COALESCE(to_char(next_run,'YYYY-MM-DD HH24:MI'),''),
       COALESCE(product,''), schedule_kind, schedule,
       CASE WHEN next_run IS NULL THEN -1
            ELSE EXTRACT(EPOCH FROM (now() - next_run))::bigint END
  FROM scheduled_action ORDER BY id
"""

# Only trigger='schedule'. A manual run is already on the operator's screen,
# and mixing them hides exactly the 2026-07-28 case: the scheduled path failing
# with 'Unknown action' while the manual path succeeded in the freshly
# restarted web worker.
ACTION_RUNS = """
SELECT action_id, status FROM scheduled_action_run
 WHERE trigger = 'schedule' ORDER BY id DESC LIMIT 500
"""

APPLIANCES = """
SELECT id, name, kind, host, COALESCE(last_status,''),
       COALESCE(maintenance,false),
       COALESCE(to_char(last_checked_at,'YYYY-MM-DD HH24:MI'),''),
       COALESCE(firmware,''), verify_ssl
  FROM appliances ORDER BY kind, name
"""

# The appliance's maintenance flag is joined in on purpose: a probe against a
# box the operator parked ON PURPOSE must not raise the roll-up. Maintenance
# already suppresses automatic runs and their alerts; a monitor page that stays
# red anyway is the thing that teaches people to stop reading it.
PROBES = """
SELECT p.id, p.kind, p.name, p.enabled, COALESCE(p.last_status,''),
       COALESCE(to_char(p.last_run_at,'YYYY-MM-DD HH24:MI'),''),
       p.interval_min, COALESCE(p.last_detail,''),
       COALESCE(a.name,'-'), COALESCE(a.maintenance,false)
  FROM monitor_probe p LEFT JOIN appliances a ON a.id = p.appliance_id
 ORDER BY p.kind, p.name
"""

USERS = """
SELECT username, role, is_active, COALESCE(auth_source,'local'),
       COALESCE(failed_logins,0),
       COALESCE(to_char(locked_until,'YYYY-MM-DD HH24:MI'),''),
       COALESCE(to_char(last_login,'YYYY-MM-DD HH24:MI'),''),
       COALESCE(totp_enabled,false)
  FROM users ORDER BY role, username
"""

SETTINGS_ALERTS = """
SELECT key, COALESCE(value,'') FROM app_settings
 WHERE key LIKE 'alerts.%' OR key LIKE 'email.%' ORDER BY key
"""

SNAPSHOT_AGE = """
SELECT COALESCE((SELECT name FROM appliances a WHERE a.id = s.appliance_id),'?'),
       max(to_char(s.created_at,'YYYY-MM-DD HH24:MI'))
  FROM device_snapshots s GROUP BY 1 ORDER BY 1
"""

NOTIF_RECENT = """
SELECT kind, count(*) FROM notifications
 WHERE created_at > now() - interval '24 hours' GROUP BY kind ORDER BY 1
"""


def setting(ctx, key):
    """One app_settings value, or ''. Operator edits win over code defaults in
    this product, so the DB — not the source — is the truth for these."""
    row, err = one(ctx, "SELECT COALESCE(value,'') FROM app_settings "
                        "WHERE key = '%s'" % key.replace("'", "''"))
    if row is None:
        return None, err
    return (row[0] if row else ""), ""


def fail_streaks(ctx):
    """{action_id: consecutive scheduled failures}. Capped: see below.

    `skipped` CLEARS the streak, exactly like `ok`. The opposite rule has a
    worse failure mode — an action whose targets are all in maintenance reports
    `skipped` forever, so old failures would never age out and the alert would
    stay critical permanently on a node where nothing is wrong.
    """
    rows, err = query(ctx, ACTION_RUNS)
    if rows is None:
        return None, err
    streak, done = {}, set()
    for r in rows:
        try:
            aid, status = int(r[0]), r[1]
        except (ValueError, IndexError):
            continue
        if aid in done:
            continue
        if status in ("ok", "skipped"):
            done.add(aid)
            streak.setdefault(aid, 0)
        elif status in ("failed", "error"):
            streak[aid] = streak.get(aid, 0) + 1
        else:
            done.add(aid)
    return streak, ""


def bool_of(text):
    return str(text).strip().lower() in ("t", "true", "1", "yes", "on")
