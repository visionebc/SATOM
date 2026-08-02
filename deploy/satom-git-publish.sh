#!/usr/bin/env bash
# Hourly auto-publish of the reports/ per-device JSON tree to git (Gitea) —
# the off-box VERSIONED source-of-truth copy (System Backup & Restore, copy 3).
#
# Mirror image of satom-ha-datasync.sh: only the PRIMARY publishes (a standby's
# reports/ is a synced copy — publishing from it would race the primary), and
# standalone-mode nodes publish too (they are their own primary). After a
# promote this activates on the new primary automatically via the role guard.
#
# PRIVILEGE MODEL (see docs/privilege-model.md)
#   Since v1.2 the unit runs AS THE SERVICE ACCOUNT, not root. Two consequences
#   that this script must honour and that the previous version got wrong:
#     * `runuser` may not be used by non-root users — running git through it
#       failed silently every hour (the `|| exit 0` swallowed it) and copy 3 of
#       the backup architecture stopped being published without any alert;
#     * the role probe cannot use `runuser -u postgres -- psql`; it is factored
#       out into deploy/satom-node-role.sh, which connects with the app's own
#       credentials from .env (same reason satom-ha-datasync.sh does).
#
#   Neither the service account nor the database name is hardcoded: the account
#   is derived from the real owner of the app tree (a legacy install may still
#   be `fortinet` while a fresh one is `satom`) and the database comes from
#   SQLALCHEMY_DATABASE_URI. Hardcoding either one breaks every install whose
#   names differ from this one's.
set -u
APP=/opt/satom
APP_USER="${SATOM_APP_USER:-$(stat -c %U "$APP" 2>/dev/null || echo satom)}"

# --- run git as the app user, whatever privilege level we start from --------
# root  -> drop to the app account with runuser
# app   -> run directly (runuser would refuse)
# other -> refuse loudly instead of pretending to work
if [ "$(id -un)" = "$APP_USER" ]; then
  as_app() { "$@"; }
elif [ "$(id -u)" = "0" ]; then
  as_app() { runuser -u "$APP_USER" -- "$@"; }
else
  echo "satom-git-publish: must run as root or as $APP_USER (running as $(id -un))" >&2
  exit 1
fi

# --- role guard ------------------------------------------------------------
# "f" = primary/standalone, "t" = standby. El probe usa las credenciales de la
# propia app (satom-node-role.sh); `runuser -u postgres` exigiria root.
ROLE_PROBE="$APP/deploy/satom-node-role.sh"
[ -x "$ROLE_PROBE" ] || { echo "satom-git-publish: falta $ROLE_PROBE" >&2; exit 1; }
ROLE="$("$ROLE_PROBE" 2>/dev/null)"
[ "$ROLE" = "f" ] || exit 0

# --- publish ---------------------------------------------------------------
# Stage everything under reports/ (including new devices), commit ONLY that
# pathspec (never other staged work), push. No-op when nothing changed.
# origin already embeds the Gitea token (same as the in-app publish button),
# so a plain push authenticates.
# SATOM-REPORTS-GUARD: en una instalacion NUEVA reports/ aun no existe
# (lo crea el primer device_sync). `git add` sobre una ruta inexistente
# falla, y el `|| exit 1` convertia eso en FAILURE de la unidad: la
# COPIA 3 del respaldo (SoT versionado en git) nace reportando error en
# toda instalacion nueva. Sin devices todavia no hay nada que publicar.
[ -d "$APP/reports" ] || exit 0
as_app git -C "$APP" add -A reports || exit 1
if as_app git -C "$APP" diff --cached --quiet -- reports; then
  exit 0
fi
as_app git -C "$APP" commit -q \
  -m "source-of-truth: auto-publish device JSON ($(date -u '+%Y-%m-%d %H:%MZ'))" \
  -- reports || exit 1
BRANCH=$(as_app git -C "$APP" rev-parse --abbrev-ref HEAD)
as_app git -C "$APP" push -q origin "${BRANCH:-main}"
