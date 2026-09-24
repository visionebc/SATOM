#!/usr/bin/env bash
# HA data/ sync: pull shared filesystem state PRIMARY -> this standby.
#
# NO hardcoded peer: the peer host is discovered from data/ha_nodes.json —
# the registry the admin edits in the UI (Software Update -> HA nodes). It
# also honors the admin-set deployment mode (AppSetting ha.mode) and the live
# Postgres role, so it is inert in standalone mode and inert after this node
# is promoted (a fresh primary must never pull data from a dead peer).
#
# EXCLUDES: node-local operational dirs + self-update trigger/status (would
# spuriously fire the standby updater) + volatile job ledgers.
#
# PRIVILEGE MODEL (see docs/privilege-model.md)
#   This unit runs as the SATOM service account, not root. Two consequences:
#     * the role/mode probe uses the app's own DB credentials from .env
#       instead of `runuser -u postgres` (which would require root);
#     * the SSH identity lives in the service account's ~/.ssh and logs in to
#       the peer AS THE SERVICE ACCOUNT, pinned by a forced command to a
#       read-only rsync of data/. Compromising this channel yields the app
#       account on the peer, not root — which is what it used to yield.
set -u
APP=/opt/satom
# Derived from the tree's real owner, not hardcoded: that way it works the same
# on a fresh install (satom) and on a legacy one that adopted another name
# (fortinet). Hardcoding "satom" made the datasync try to log in as a
# non-existent user after nodes 248/249 were migrated.
APP_USER="${SATOM_APP_USER:-$(stat -c %U "$APP" 2>/dev/null || echo satom)}"
SSH_KEY="$APP/.ssh/id_ha_rsync"
KNOWN_HOSTS="$APP/.ssh/known_hosts"

# --- role / mode probe -----------------------------------------------------
# Reads .env for the app's DB URI. Prints "<in_recovery>|<ha.mode>".
PROBE=$("$APP/venv/bin/python" - <<'PYEOF' 2>/dev/null
import os, re, sys

env = {}
try:
    for line in open('/opt/satom/.env'):
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
except Exception:
    sys.exit(1)

uri = env.get('SQLALCHEMY_DATABASE_URI', '')
m = re.match(r'postgresql\+\w+://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/(\S+)', uri)
if not m:
    sys.exit(1)
user, pw, host, port, db = m.groups()

try:
    import psycopg
    conn = psycopg.connect(host=host, port=int(port or 5432), user=user,
                           password=pw, dbname=db, connect_timeout=10)
except Exception:
    sys.exit(1)

with conn:
    with conn.cursor() as cur:
        cur.execute('SELECT pg_is_in_recovery()')
        rec = 't' if cur.fetchone()[0] else 'f'
        cur.execute("SELECT value FROM app_settings WHERE key='ha.mode'")
        row = cur.fetchone()
        mode = (row[0] if row else '') or ''
print(f'{rec}|{mode.strip()}')
PYEOF
)
# A probe failure must be LOUD. Exiting 0 here would look identical to
# "correctly inert on the primary" and the standby could silently stop
# replicating for weeks.
[ -n "$PROBE" ] || { echo "datasync: could not query the role in Postgres" >&2; exit 1; }

ROLE="${PROBE%%|*}"
MODE="${PROBE##*|}"

# Only a STANDBY pulls. After a promote this becomes a no-op automatically.
[ "$ROLE" = "t" ] || exit 0
# Standalone mode (set in the admin UI, replicated via app_settings) => no-op.
[ "$MODE" = "standalone" ] && exit 0

# --- peer discovery --------------------------------------------------------
# The interpreter is the app venv's, same as the role probe above: it always
# exists on an installed node and does not depend on the distro providing a
# /usr/bin/python3 symlink (openSUSE does not).
PEER=$("$APP/venv/bin/python" - <<'PYEOF'
import json, socket, subprocess
# Peer discovery keys off THIS NODE'S OWN IP ADDRESSES, never its hostname.
# Hostname matching silently broke when the LXCs were renamed: ha_nodes.json
# carried satom-1/satom-2 while the hosts answered satom-node-1/satom-node-2,
# so every entry mismatched and the loop fell through to nodes[0] -- picking a
# peer by list order rather than by identity. Reordering the list in the UI
# would have made this standby rsync --delete against itself.
try:
    nodes = json.load(open('/opt/satom/data/ha_nodes.json'))
except Exception:
    raise SystemExit
local = {'127.0.0.1', '::1', 'localhost'}
try:
    local.update(subprocess.run(['hostname', '-I'], capture_output=True,
                                text=True, timeout=5).stdout.split())
except Exception:
    pass
me = socket.gethostname()
for n in nodes:
    h = (n.get('host') or '').strip()
    if not h or h in local:
        continue          # that entry is us -- authoritative check
    if n.get('name') == me:
        continue          # belt-and-braces for a same-IP-different-name entry
    print(h)
    break
PYEOF
)
PEER_RC=$?
# "could not evaluate" and "no peer configured" are NOT the same thing, and
# treating them alike is how this unit reported SUCCESS while syncing nothing.
if [ "$PEER_RC" -ne 0 ]; then
    echo "datasync: could not determine the peer from data/ha_nodes.json (rc=$PEER_RC)" >&2
    exit 1
fi
if [ -z "${PEER}" ]; then
    echo "datasync: ha_nodes.json lists no peer other than this node — nothing to sync" >&2
    exit 0
fi

[ -r "$SSH_KEY" ] || { echo "datasync: key $SSH_KEY is missing" >&2; exit 1; }

# StrictHostKeyChecking=yes, NOT accept-new: the peer's host key is seeded at
# install time (ssh-keyscan over the already-authenticated join step), so a
# first-contact substitution is no longer possible.
exec rsync -az --delete \
  --exclude 'jobs/' --exclude 'tmp/' \
  --exclude 'update-requests/' --exclude 'update-status/' \
  --exclude 'logs/' --exclude 'diagnostics/' --exclude 'deep_jobs/' \
  -e "ssh -i ${SSH_KEY} -o IdentitiesOnly=yes -o UserKnownHostsFile=${KNOWN_HOSTS} -o StrictHostKeyChecking=yes -o ConnectTimeout=10" \
  "${APP_USER}@${PEER}:${APP}/data/" "${APP}/data/"
