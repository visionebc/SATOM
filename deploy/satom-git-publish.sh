#!/usr/bin/env bash
# Hourly auto-publish of the reports/ per-device JSON tree to git (Gitea) —
# the off-box VERSIONED source-of-truth copy (System Backup & Restore, copy 3).
#
# Mirror image of satom-ha-datasync.sh: only the PRIMARY publishes (a standby's
# reports/ is a synced copy — publishing from it would race the primary), and
# standalone-mode nodes publish too (they are their own primary). After a
# promote this activates on the new primary automatically via the role guard.
#
# Runs git as the app user (fortinet); origin already embeds the Gitea token
# (same as the in-app publish button), so a plain push authenticates.
set -u
APP=/opt/satom

# Only the PRIMARY publishes (pg_is_in_recovery: f=primary, t=standby).
ROLE=$(cd /tmp && runuser -u postgres -- psql -d fortinet_mgr -tAc \
  "SELECT pg_is_in_recovery()" 2>/dev/null | tr -d '[:space:]')
[ "$ROLE" = "f" ] || exit 0

# Stage everything under reports/ (including new devices), commit ONLY that
# pathspec (never other staged work), push. No-op when nothing changed.
runuser -u fortinet -- git -C "$APP" add -A reports 2>/dev/null || exit 0
if runuser -u fortinet -- git -C "$APP" diff --cached --quiet -- reports; then
  exit 0
fi
runuser -u fortinet -- git -C "$APP" commit -q \
  -m "source-of-truth: auto-publish device JSON ($(date -u '+%Y-%m-%d %H:%MZ'))" \
  -- reports || exit 0
BRANCH=$(runuser -u fortinet -- git -C "$APP" rev-parse --abbrev-ref HEAD)
exec runuser -u fortinet -- git -C "$APP" push -q origin "${BRANCH:-main}"
