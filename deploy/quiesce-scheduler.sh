#!/usr/bin/env bash
# Stop the scheduler BEFORE an update runner restarts it.
#
# [SATOM-LEGACY-RESTART-QUIESCE]
#
# WHY THIS EXISTS (SA-0013, SA-0014). On SIGTERM the scheduler finishes the due
# actions it is running before it exits, so a stop can take most of the 90 s
# systemd allows it. Runners up to 4.11.0 restart it with a FIXED 60 s cap
# (`systemctl restart satom-scheduler.service`, timeout=60): a slow stop reads
# as a failed update and the whole update is rolled back. 4.11.1 sized the wait
# from the unit's own timeouts -- but an update is applied by the runner already
# INSTALLED on the node, so a <=4.11.0 node kept failing on the very update that
# carried the fix.
#
# The one root-side file every runner executes from the NEW tree is
# deploy/install-runner.sh, so that script calls this one when its parent is the
# update runner:
#   begin   ask systemd to stop the scheduler and return at once (--no-block),
#           so it winds down while the rest of the update runs;
#   wait S  wait at most S seconds for it to be down.
# The runner's later `restart` then only STARTS the unit (Type=simple: about a
# second), whatever the age of the runner. Under a current runner this is
# harmless: the restart waits as long as systemd may take anyway, and nothing
# fires actions against a tree that is being replaced.
#
# NEVER fails an update: every problem is a WARN line and the exit status is
# always 0. Nothing here leaves the scheduler down -- every runner restarts it
# right after (success) or in its rollback (failure).
set -uo pipefail

UNIT="satom-scheduler.service"
mode="${1:-}"

state() { systemctl is-active "$UNIT" 2>/dev/null || true; }

case "$mode" in
  begin)
    if systemctl stop --no-block "$UNIT" >/dev/null 2>&1; then
      echo "quiesce: scheduler stop requested (the update restarts it)"
    else
      echo "WARN quiesce: could not request a scheduler stop"
    fi
    ;;
  wait)
    budget="${2:-0}"
    case "$budget" in ''|*[!0-9]*) budget=0 ;; esac
    waited=0
    s="$(state)"
    while [ "$s" = active ] || [ "$s" = deactivating ] || [ "$s" = reloading ]; do
      if [ "$waited" -ge "$budget" ]; then
        echo "WARN quiesce: scheduler still ${s} after ${waited}s; the update restart waits for it"
        exit 0
      fi
      sleep 1
      waited=$((waited + 1))
      s="$(state)"
    done
    echo "quiesce: scheduler ${s:-stopped} after ${waited}s (the update restarts it)"
    ;;
  *)
    echo "usage: quiesce-scheduler.sh begin | wait <seconds>" >&2
    ;;
esac
exit 0
