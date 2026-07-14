#!/usr/bin/env bash
#
# migrate-rename-ofortmaut.sh — one-shot, node-local migration of an existing
# install from the legacy layout (fortinet-manager / fm-*) to the OFortMAuT
# layout (/opt/ofortmaut, ofortmaut-*.{service,timer,path}).
#
# Safe to re-run (idempotent-ish). Run as root, on ONE node at a time,
# standby first. The repo checkout must already contain the renamed
# deploy/ files (commit "rename: fortinet-manager -> ofortmaut").
#
#   NEW_HOSTNAME=ofortmaut-2 bash deploy/migrate-rename-ofortmaut.sh
#
set -euo pipefail

OLD_APP=/opt/fortinet-manager
NEW_APP=/opt/ofortmaut
OLD_LOG=/var/log/fortinet-manager
NEW_LOG=/var/log/ofortmaut
NEW_HOSTNAME="${NEW_HOSTNAME:-}"

say() { echo "== $*"; }

# ---------------------------------------------------------------- 0. sanity
[ -d "$NEW_APP" ] || [ -d "$OLD_APP" ] || { echo "no app dir found"; exit 1; }

# ------------------------------------------------- 1. stop + disable legacy
say "stopping legacy units"
LEGACY_UNITS="fortinet-manager-updater.path fm-alerts.timer fm-cert-renew.timer \
  fm-git-publish.timer fm-ha-datasync.timer fortinet-manager.service \
  fortinet-manager-scheduler.service fortinet-manager-reconciler.service \
  fortinet-manager-updater.service fm-alerts.service fm-cert-renew.service \
  fm-git-publish.service fm-ha-datasync.service"
for u in $LEGACY_UNITS; do systemctl stop "$u" 2>/dev/null || true; done
for u in $LEGACY_UNITS; do systemctl disable "$u" 2>/dev/null || true; done

# --------------------------------------------------------- 2. move the tree
if [ -d "$OLD_APP" ] && [ ! -L "$OLD_APP" ]; then
  say "moving $OLD_APP -> $NEW_APP"
  mv "$OLD_APP" "$NEW_APP"
  ln -s "$NEW_APP" "$OLD_APP"          # transitional symlink, removed in step 8
fi
mkdir -p "$NEW_LOG"
if [ -d "$OLD_LOG" ] && [ ! -L "$OLD_LOG" ]; then
  say "moving logs"
  mv "$OLD_LOG"/* "$NEW_LOG"/ 2>/dev/null || true
  rmdir "$OLD_LOG" 2>/dev/null || true
  ln -s "$NEW_LOG" "$OLD_LOG"
fi

# -------------------------------------------- 3. fix venv absolute shebangs
say "rewriting venv shebangs/paths"
grep -rl "$OLD_APP" "$NEW_APP/venv/bin" 2>/dev/null \
  | xargs -r sed -i "s|$OLD_APP|$NEW_APP|g"

# ------------------------------------------------------- 4. install units
say "installing renamed units"
rm -f /etc/systemd/system/fortinet-manager*.service \
      /etc/systemd/system/fortinet-manager*.path \
      /etc/systemd/system/fm-alerts.* /etc/systemd/system/fm-cert-renew.* \
      /etc/systemd/system/fm-git-publish.* 2>/dev/null || true
for f in "$NEW_APP"/deploy/ofortmaut*.service "$NEW_APP"/deploy/ofortmaut*.timer \
         "$NEW_APP"/deploy/ofortmaut*.path; do
  [ -e "$f" ] && cp "$f" /etc/systemd/system/
done
# datasync unit is node-written (standby only): rename in place if present
if [ -f /etc/systemd/system/fm-ha-datasync.service ]; then
  for e in service timer; do
    sed -e "s|$OLD_APP|$NEW_APP|g" -e "s/fm-ha-datasync/ofortmaut-ha-datasync/g" \
      /etc/systemd/system/fm-ha-datasync.$e > /etc/systemd/system/ofortmaut-ha-datasync.$e
    rm -f /etc/systemd/system/fm-ha-datasync.$e
  done
fi
# deployed script copies in /usr/local/sbin (git-publish, datasync, promote run
# from there, NOT from the repo checkout) — rename preserving any local drift
for f in /usr/local/sbin/fm-*.sh /usr/local/sbin/fm-*.txt; do
  [ -f "$f" ] || continue
  new="/usr/local/sbin/ofortmaut-${f##*/fm-}"
  sed -e "s|$OLD_APP|$NEW_APP|g" -e "s/fortinet-manager/ofortmaut/g" \
      -e "s/fm-ha-datasync/ofortmaut-ha-datasync/g" -e "s/fm-git-publish/ofortmaut-git-publish/g" \
      -e "s/fm-promote/ofortmaut-promote/g" "$f" > "$new"
  chmod --reference="$f" "$new"; rm -f "$f"
done
systemctl daemon-reload

# ------------------------------------------------------------- 5. nginx
say "updating nginx"
if [ -f /etc/nginx/sites-available/fm-tls.conf ]; then
  sed -e "s|$OLD_APP|$NEW_APP|g" \
    /etc/nginx/sites-available/fm-tls.conf > /etc/nginx/sites-available/ofortmaut-tls.conf
  rm -f /etc/nginx/sites-enabled/fm-tls.conf /etc/nginx/sites-available/fm-tls.conf
  ln -sf /etc/nginx/sites-available/ofortmaut-tls.conf /etc/nginx/sites-enabled/ofortmaut-tls.conf
fi
if [ -f /etc/nginx/sites-available/ofortmaut-pages.conf ]; then
  sed -i "s|$OLD_APP|$NEW_APP|g" /etc/nginx/sites-available/ofortmaut-pages.conf
fi
nginx -t && systemctl reload nginx

# ------------------------------------------------------------ 6. hostname
if [ -n "$NEW_HOSTNAME" ]; then
  say "hostname -> $NEW_HOSTNAME"
  OLDH=$(hostname)
  hostnamectl set-hostname "$NEW_HOSTNAME" 2>/dev/null || hostname "$NEW_HOSTNAME"
  echo "$NEW_HOSTNAME" > /etc/hostname
  sed -i "s/\b$OLDH\b/$NEW_HOSTNAME/g" /etc/hosts
fi

# ---------------------------------------------------------- 7. start stack
say "starting renamed stack"
systemctl enable --now ofortmaut.service ofortmaut-scheduler.service \
  ofortmaut-reconciler.service ofortmaut-updater.path \
  ofortmaut-alerts.timer ofortmaut-cert-renew.timer ofortmaut-git-publish.timer
[ -f /etc/systemd/system/ofortmaut-ha-datasync.timer ] && \
  systemctl enable --now ofortmaut-ha-datasync.timer

# -------------------------------------------------------------- 8. verify
say "health check"
timeout 45 bash -c 'until curl -sfo /dev/null http://127.0.0.1:8000/healthz; do sleep 2; done' \
  && echo "OK: healthz 200" \
  || { echo "FAIL: healthz"; systemctl status ofortmaut.service --no-pager -l | tail -20; exit 1; }
echo "MIGRATION DONE on $(hostname)"
