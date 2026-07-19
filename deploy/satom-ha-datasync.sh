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
set -u
APP=/opt/satom

# Only a STANDBY pulls. After a promote this becomes a no-op automatically.
ROLE=$(cd /tmp && runuser -u postgres -- psql -d fortinet_mgr -tAc \
  "SELECT pg_is_in_recovery()" 2>/dev/null | tr -d '[:space:]')
[ "$ROLE" = "t" ] || exit 0

# Standalone mode (set in the admin UI, replicated via app_settings) => no-op.
MODE=$(cd /tmp && runuser -u postgres -- psql -d fortinet_mgr -tAc \
  "SELECT value FROM app_settings WHERE key='ha.mode'" 2>/dev/null | tr -d '[:space:]')
[ "$MODE" = "standalone" ] && exit 0

# Peer discovery: first registered node that is not this host.
PEER=$(python3 - <<'PYEOF'
import json, socket
try:
    nodes = json.load(open('/opt/satom/data/ha_nodes.json'))
except Exception:
    raise SystemExit
me = socket.gethostname()
for n in nodes:
    h = (n.get('host') or '').strip()
    if n.get('name') != me and h and h != '127.0.0.1':
        print(h)
        break
PYEOF
)
[ -z "${PEER}" ] && exit 0

exec rsync -az --delete \
  --exclude 'jobs/' --exclude 'tmp/' \
  --exclude 'update-requests/' --exclude 'update-status/' \
  --exclude 'logs/' --exclude 'diagnostics/' --exclude 'deep_jobs/' \
  -e 'ssh -i /root/.ssh/id_ha_rsync -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10' \
  "root@${PEER}:${APP}/data/" "${APP}/data/"
