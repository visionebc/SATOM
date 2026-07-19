#!/usr/bin/env bash
#
# migrate-rename-satom.sh — one-shot, node-local migration of an existing
# install to the SATOM layout (/opt/satom, satom-*.{service,timer,path}).
#
# Handles BOTH legacy layouts:
#   /opt/fortinet-manager  (fm-* / fortinet-manager-* units)   [pre 2026-07-15]
#   /opt/ofortmaut         (ofortmaut-* units)                 [2026-07-15..20]
#
# Safe to re-run. Run as root, ONE node at a time, standby first.
# The repo checkout must already contain the renamed deploy/ files.
#
#   NEW_HOSTNAME=satom-2 bash deploy/migrate-rename-satom.sh
#
set -euo pipefail

NEW_APP=/opt/satom
NEW_LOG=/var/log/satom
LEGACY_APPS="/opt/ofortmaut /opt/fortinet-manager"
LEGACY_LOGS="/var/log/ofortmaut /var/log/fortinet-manager"
NEW_HOSTNAME="${NEW_HOSTNAME:-}"

say() { echo "== $*"; }

# ---------------------------------------------------------------- 0. sanity
FOUND=""
[ -d "$NEW_APP" ] && FOUND="$NEW_APP"
for d in $LEGACY_APPS; do [ -d "$d" ] && [ ! -L "$d" ] && FOUND="$d"; done
[ -n "$FOUND" ] || { echo "no app dir found"; exit 1; }

# ------------------------------------------------- 1. stop + disable legacy
say "stopping legacy units"
LEGACY_UNITS="ofortmaut-updater.path ofortmaut-alerts.timer ofortmaut-cert-renew.timer \
  ofortmaut-git-publish.timer ofortmaut-ha-datasync.timer ofortmaut.service \
  ofortmaut-scheduler.service ofortmaut-reconciler.service ofortmaut-updater.service \
  ofortmaut-alerts.service ofortmaut-cert-renew.service ofortmaut-git-publish.service \
  ofortmaut-ha-datasync.service \
  fortinet-manager-updater.path fm-alerts.timer fm-cert-renew.timer fm-git-publish.timer \
  fm-ha-datasync.timer fortinet-manager.service fortinet-manager-scheduler.service \
  fortinet-manager-reconciler.service fortinet-manager-updater.service fm-alerts.service \
  fm-cert-renew.service fm-git-publish.service fm-ha-datasync.service"
for u in $LEGACY_UNITS; do systemctl stop "$u" 2>/dev/null || true; done
for u in $LEGACY_UNITS; do systemctl disable "$u" 2>/dev/null || true; done

# --------------------------------------------------------- 2. move the tree
for OLD in $LEGACY_APPS; do
  if [ -d "$OLD" ] && [ ! -L "$OLD" ] && [ "$OLD" != "$NEW_APP" ]; then
    say "moving $OLD -> $NEW_APP"
    mv "$OLD" "$NEW_APP"
    ln -s "$NEW_APP" "$OLD"          # transitional symlink, drop after validation
  fi
done
mkdir -p "$NEW_LOG"
for OLDL in $LEGACY_LOGS; do
  if [ -d "$OLDL" ] && [ ! -L "$OLDL" ]; then
    say "moving logs from $OLDL"
    mv "$OLDL"/* "$NEW_LOG"/ 2>/dev/null || true
    rmdir "$OLDL" 2>/dev/null || true
    ln -s "$NEW_LOG" "$OLDL"
  fi
done

# -------------------------------------------- 3. fix venv absolute shebangs
say "rewriting venv shebangs/paths"
for OLD in $LEGACY_APPS; do
  grep -rl "$OLD" "$NEW_APP/venv/bin" 2>/dev/null | xargs -r sed -i "s|$OLD|$NEW_APP|g" || true
done

# ------------------------------------------------------- 4. install units
say "installing renamed units"
# datasync unit is node-written (standby only): rename in place if present
for legacy in ofortmaut-ha-datasync fm-ha-datasync; do
  if [ -f "/etc/systemd/system/$legacy.service" ]; then
    for e in service timer; do
      [ -f "/etc/systemd/system/$legacy.$e" ] || continue
      sed -e "s|/opt/ofortmaut|$NEW_APP|g" -e "s|/opt/fortinet-manager|$NEW_APP|g" \
          -e "s/$legacy/satom-ha-datasync/g" \
        "/etc/systemd/system/$legacy.$e" > "/etc/systemd/system/satom-ha-datasync.$e"
      rm -f "/etc/systemd/system/$legacy.$e"
    done
  fi
done
rm -f /etc/systemd/system/ofortmaut*.service /etc/systemd/system/ofortmaut*.timer \
      /etc/systemd/system/ofortmaut*.path \
      /etc/systemd/system/fortinet-manager*.service /etc/systemd/system/fortinet-manager*.path \
      /etc/systemd/system/fm-alerts.* /etc/systemd/system/fm-cert-renew.* \
      /etc/systemd/system/fm-git-publish.* 2>/dev/null || true
for f in "$NEW_APP"/deploy/satom*.service "$NEW_APP"/deploy/satom*.timer \
         "$NEW_APP"/deploy/satom*.path; do
  [ -e "$f" ] && cp "$f" /etc/systemd/system/
done
# deployed script copies in /usr/local/sbin run from there, NOT from the checkout
for f in /usr/local/sbin/ofortmaut-*.sh /usr/local/sbin/ofortmaut-*.txt \
         /usr/local/sbin/fm-*.sh /usr/local/sbin/fm-*.txt; do
  [ -f "$f" ] || continue
  base="${f##*/}"
  new="/usr/local/sbin/$(echo "$base" | sed -e 's/^ofortmaut-/satom-/' -e 's/^fm-/satom-/')"
  sed -e "s|/opt/ofortmaut|$NEW_APP|g" -e "s|/opt/fortinet-manager|$NEW_APP|g" \
      -e "s/ofortmaut/satom/g" -e "s/fortinet-manager/satom/g" \
      -e "s/fm-ha-datasync/satom-ha-datasync/g" -e "s/fm-git-publish/satom-git-publish/g" \
      -e "s/fm-promote/satom-promote/g" "$f" > "$new"
  chmod --reference="$f" "$new"; [ "$new" != "$f" ] && rm -f "$f"
done
systemctl daemon-reload

# ------------------------------------------------------------- 5. nginx
say "updating nginx"
for legacy in ofortmaut-tls fm-tls; do
  if [ -f "/etc/nginx/sites-available/$legacy.conf" ]; then
    sed -e "s|/opt/ofortmaut|$NEW_APP|g" -e "s|/opt/fortinet-manager|$NEW_APP|g" \
      "/etc/nginx/sites-available/$legacy.conf" > /etc/nginx/sites-available/satom-tls.conf
    rm -f "/etc/nginx/sites-enabled/$legacy.conf" "/etc/nginx/sites-available/$legacy.conf"
    ln -sf /etc/nginx/sites-available/satom-tls.conf /etc/nginx/sites-enabled/satom-tls.conf
  fi
done
for d in sites-available sites-enabled; do
  src="/etc/nginx/$d/ofortmaut-pages.conf"
  [ -f "$src" ] || continue
  sed -e "s|/opt/ofortmaut|$NEW_APP|g" "$src" > /etc/nginx/sites-available/satom-pages.conf
  rm -f /etc/nginx/sites-enabled/ofortmaut-pages.conf /etc/nginx/sites-available/ofortmaut-pages.conf
  ln -sf /etc/nginx/sites-available/satom-pages.conf /etc/nginx/sites-enabled/satom-pages.conf
done
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
systemctl enable --now satom.service satom-scheduler.service \
  satom-reconciler.service satom-updater.path \
  satom-alerts.timer satom-cert-renew.timer satom-git-publish.timer
[ -f /etc/systemd/system/satom-ha-datasync.timer ] && \
  systemctl enable --now satom-ha-datasync.timer

# -------------------------------------------------------------- 8. verify
say "health check"
timeout 45 bash -c 'until curl -sfo /dev/null http://127.0.0.1:8000/healthz; do sleep 2; done' \
  && echo "OK: healthz 200" \
  || { echo "FAIL: healthz"; systemctl status satom.service --no-pager -l | tail -20; exit 1; }
echo "MIGRATION DONE on $(hostname)"
