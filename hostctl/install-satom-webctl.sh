#!/bin/bash
# SPDX-License-Identifier: Elastic-2.0
# install-satom-webctl.sh -- prepare a web server for SATOM's "Web Hosts" app.
#
# Run ONCE, as root, on the server SATOM will manage. It creates the
# unprivileged account satom-mon, installs /usr/local/bin/satom-webctl and
# authorises SATOM's public key for that account with
#     restrict,command="/usr/local/bin/satom-webctl"[,from="<SATOM nodes>"]
# so the key can run that one program and nothing else: no shell, no
# forwarding, no pty.
#
# What it changes (and --uninstall removes):
#   * user satom-mon (no password, login only through the key above)
#   * /usr/local/bin/satom-webctl            root:root 0755
#   * /etc/satom-webctl.json                 root:root 0644
#   * /etc/sudoers.d/satom-webctl            exactly two commands per server:
#                                            the config test and the reload
#   * ACL entries u:satom-mon:rwX (and the default ACL) on the managed roots
#     and on the web server's site directories -- owners and modes untouched
#   * /var/lib/satom-webctl (backups), /var/log/satom-webctl (operation log)
#   * /etc/satom-webctl/certs                satom-mon 0700: the certificates
#                                            SATOM manages; their private keys
#                                            are made here and never leave
#                                            (--uninstall keeps it: sites may
#                                            use it; --purge removes it)
# Nothing on this server is given any way to reach SATOM.
#
# Usage:
#   install-satom-webctl.sh --pubkey "ssh-ed25519 AAAA... satom" \
#       [--from 192.0.2.248,192.0.2.249] [--roots /var/www,/srv/www] [--read-only]
#   install-satom-webctl.sh --uninstall [--purge]
set -euo pipefail

USER_NAME="satom-mon"
HOME_DIR="/var/lib/satom-webctl"
LOG_DIR="/var/log/satom-webctl"
BIN="/usr/local/bin/satom-webctl"
CONF="/etc/satom-webctl.json"
CERT_BASE="/etc/satom-webctl"
CERT_DIR="$CERT_BASE/certs"
SUDOERS="/etc/sudoers.d/satom-webctl"
HERE="$(cd "$(dirname "$0")" && pwd)"
PUBKEY="" FROM="" ROOTS="/var/www,/srv/www" READ_ONLY="false" MODE="install" PURGE="no"

die() { echo "install-satom-webctl: $*" >&2; exit 1; }
say() { echo "  - $*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --pubkey) PUBKEY="${2:-}"; shift 2 ;;
        --from) FROM="${2:-}"; shift 2 ;;
        --roots) ROOTS="${2:-}"; shift 2 ;;
        --read-only) READ_ONLY="true"; shift ;;
        --uninstall) MODE="uninstall"; shift ;;
        --purge) PURGE="yes"; shift ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root"

# ── distribution family ─────────────────────────────────────────────────────
. /etc/os-release
FAMILY=""
for id in ${ID:-} ${ID_LIKE:-}; do
    case "$id" in
        debian|ubuntu) FAMILY="debian"; break ;;
        rhel|centos|fedora|rocky|almalinux) FAMILY="rhel"; break ;;
        suse|sles|opensuse*) FAMILY="suse"; break ;;
    esac
done
[ -n "$FAMILY" ] || die "unsupported distribution: ${ID:-unknown}"

pkg_install() {
    case "$FAMILY" in
        debian) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null ;;
        rhel) dnf install -y -q "$@" >/dev/null ;;
        suse) zypper --non-interactive -q install "$@" >/dev/null ;;
    esac
}

# Every ACL path this installer may have set, for --uninstall as well.
acl_targets() {
    local IFS=','
    for r in $ROOTS; do [ -d "$r" ] && echo "$r"; done
    for d in /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/conf.d \
             /etc/nginx/vhosts.d /etc/apache2/sites-available /etc/apache2/sites-enabled \
             /etc/apache2/vhosts.d /etc/httpd/conf.d; do
        [ -d "$d" ] && echo "$d"
    done
    return 0
}

if [ "$MODE" = "uninstall" ]; then
    echo "Removing satom-webctl:"
    if command -v setfacl >/dev/null; then
        for t in $(acl_targets); do
            setfacl -R -x "u:$USER_NAME" "$t" 2>/dev/null || true
            setfacl -R -d -x "u:$USER_NAME" "$t" 2>/dev/null || true
        done
        say "ACL entries removed"
    fi
    rm -f "$SUDOERS" "$BIN" "$CONF" && say "binary, configuration and sudoers removed"
    if id "$USER_NAME" >/dev/null 2>&1; then
        userdel "$USER_NAME" 2>/dev/null || true
        say "user $USER_NAME removed"
    fi
    if [ "$PURGE" = "yes" ]; then
        if [ -d "$CERT_DIR" ] && grep -rqsF "$CERT_DIR/" /etc/nginx /etc/apache2 /etc/httpd 2>/dev/null; then
            echo "  ! a virtual host still uses a certificate in $CERT_DIR: kept it" \
                 "(point the site elsewhere, then --purge again)"
            rm -rf "$HOME_DIR" "$LOG_DIR" && say "backups and log removed (--purge)"
        else
            rm -rf "$HOME_DIR" "$LOG_DIR" "$CERT_BASE" \
                && say "backups, log and certificates removed (--purge)"
        fi
    else
        say "kept $HOME_DIR (backups), $LOG_DIR (log) and $CERT_DIR (certificates" \
            "sites may use); --purge removes them"
    fi
    exit 0
fi

# ── checks ──────────────────────────────────────────────────────────────────
[ -n "$PUBKEY" ] || die "--pubkey is required (copy it from SATOM: Plugin Studio > Connections)"
echo "$PUBKEY" | grep -Eq '^(ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ssh-rsa) [A-Za-z0-9+/=]+( [^"]*)?$' \
    || die "--pubkey does not look like an OpenSSH public key"
if [ -n "$FROM" ]; then
    echo "$FROM" | grep -Eq '^[0-9A-Fa-f:.,/]+$' || die "--from takes comma-separated addresses"
fi
[ -f "$HERE/satom-webctl.py" ] || die "satom-webctl.py must sit next to this script"
command -v python3 >/dev/null || die "python3 is required"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' \
    || die "python3 3.6 or newer is required"
command -v sshd >/dev/null || [ -x /usr/sbin/sshd ] || die "an SSH server (sshd) is required"

echo "Installing satom-webctl on a $FAMILY system:"
command -v sudo >/dev/null || { pkg_install sudo; say "installed sudo"; }
command -v setfacl >/dev/null || { pkg_install acl; say "installed acl"; }
command -v openssl >/dev/null || { pkg_install openssl; say "installed openssl"; }
SUDO_BIN="$(command -v sudo)"
SYSTEMCTL="$(command -v systemctl)"

# ── which web servers, which layout ─────────────────────────────────────────
SERVERS_JSON=""
SUDO_LINES=""
SITE_DIRS=""
add_server() {  # key layout available enabled test_cmd... -- unit
    local key="$1" layout="$2" avail="$3" enabled="$4" unit="$5" testcmd="$6"
    [ -d "$avail" ] || return 0
    local en_json="null"
    [ -n "$enabled" ] && en_json="\"$enabled\""
    local test_json
    test_json="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' \
        "$SUDO_BIN" -n $testcmd)"
    local reload_json
    reload_json="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' \
        "$SUDO_BIN" -n "$SYSTEMCTL" reload "$unit")"
    [ -n "$SERVERS_JSON" ] && SERVERS_JSON="$SERVERS_JSON,"
    SERVERS_JSON="$SERVERS_JSON\"$key\": {\"layout\": \"$layout\", \"available\": \"$avail\", \"enabled\": $en_json, \"test\": $test_json, \"reload\": $reload_json, \"unit\": \"$unit\"}"
    SUDO_LINES="$SUDO_LINES$USER_NAME ALL=(root) NOPASSWD: $testcmd, $SYSTEMCTL reload $unit
"
    SITE_DIRS="$SITE_DIRS$avail
"
    [ -n "$enabled" ] && SITE_DIRS="$SITE_DIRS$enabled
"
    say "$key: $layout layout in $avail"
}

if command -v nginx >/dev/null 2>&1; then
    NGINX="$(command -v nginx)"
    case "$FAMILY" in
        debian) add_server nginx debian /etc/nginx/sites-available /etc/nginx/sites-enabled nginx.service "$NGINX -t" ;;
        rhel) add_server nginx confd /etc/nginx/conf.d "" nginx.service "$NGINX -t" ;;
        suse) add_server nginx confd /etc/nginx/vhosts.d "" nginx.service "$NGINX -t" ;;
    esac
fi
APACHECTL="$(command -v apache2ctl 2>/dev/null || command -v apachectl 2>/dev/null || true)"
if [ -n "$APACHECTL" ]; then
    case "$FAMILY" in
        debian) add_server apache debian /etc/apache2/sites-available /etc/apache2/sites-enabled apache2.service "$APACHECTL configtest" ;;
        rhel) add_server apache confd /etc/httpd/conf.d "" httpd.service "$APACHECTL configtest" ;;
        suse) add_server apache confd /etc/apache2/vhosts.d "" apache2.service "$APACHECTL configtest" ;;
    esac
fi
[ -n "$SERVERS_JSON" ] || die "found neither nginx nor Apache with a known site directory"

# ── account, program, configuration ─────────────────────────────────────────
if ! id "$USER_NAME" >/dev/null 2>&1; then
    useradd --system --home-dir "$HOME_DIR" --create-home --shell /bin/sh \
        --comment "SATOM web host management" "$USER_NAME"
    say "created user $USER_NAME"
fi
usermod -L "$USER_NAME" 2>/dev/null || passwd -l "$USER_NAME" >/dev/null 2>&1 || true
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0750 "$HOME_DIR"
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$HOME_DIR/backups"
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0750 "$LOG_DIR"
install -d -o root -g root -m 0755 "$CERT_BASE"
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$CERT_DIR"
install -o root -g root -m 0755 "$HERE/satom-webctl.py" "$BIN"
say "installed $BIN ($("$BIN" --version))"

ROOTS_JSON="$(python3 -c 'import json,sys; print(json.dumps([r for r in sys.argv[1].split(",") if r]))' "$ROOTS")"
cat > "$CONF.tmp" <<EOF
{
  "servers": {$SERVERS_JSON},
  "roots": $ROOTS_JSON,
  "backup_dir": "$HOME_DIR/backups",
  "log": "$LOG_DIR/webctl.log",
  "cert_dir": "$CERT_DIR",
  "openssl": "$(command -v openssl)",
  "read_only": $READ_ONLY
}
EOF
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$CONF.tmp" || die "generated configuration is not valid JSON"
install -o root -g root -m 0644 "$CONF.tmp" "$CONF" && rm -f "$CONF.tmp"
say "wrote $CONF (read_only=$READ_ONLY)"

# ── sudoers: the config test and the reload, nothing else ───────────────────
{
    echo "# Managed by install-satom-webctl.sh -- SATOM web host management."
    echo "Defaults:$USER_NAME !requiretty"
    printf '%s' "$SUDO_LINES"
} > "$SUDOERS.tmp"
chmod 0440 "$SUDOERS.tmp"
visudo -cf "$SUDOERS.tmp" >/dev/null || { rm -f "$SUDOERS.tmp"; die "sudoers validation failed"; }
mv "$SUDOERS.tmp" "$SUDOERS"
say "sudoers: $(grep -c NOPASSWD "$SUDOERS") line(s), test + reload only"

# ── ACLs: write access to the managed roots and the configured site dirs ──
# Only the directories of the servers configured above -- not every web
# server directory that exists (on Debian, nginx's conf.d is global config,
# not a site directory, and SATOM gets no write access to it).
INSTALL_ACL="$(IFS=','; for r in $ROOTS; do [ -d "$r" ] && echo "$r"; done; printf '%s' "$SITE_DIRS")"
for t in $INSTALL_ACL; do
    setfacl -R -m "u:$USER_NAME:rwX" "$t"
    find "$t" -type d -exec setfacl -d -m "u:$USER_NAME:rwX" {} +
    say "ACL u:$USER_NAME:rwX on $t"
done

# ── the key: this program only ──────────────────────────────────────────────
OPTS="restrict,command=\"$BIN\""
[ -n "$FROM" ] && OPTS="$OPTS,from=\"$FROM\""
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$HOME_DIR/.ssh"
printf '%s %s\n' "$OPTS" "$PUBKEY" > "$HOME_DIR/.ssh/authorized_keys"
chown "$USER_NAME:$USER_NAME" "$HOME_DIR/.ssh/authorized_keys"
chmod 0600 "$HOME_DIR/.ssh/authorized_keys"
say "authorized SATOM's key: $OPTS"

if command -v sshd >/dev/null 2>&1; then
    ALLOW="$(sshd -T 2>/dev/null | awk 'tolower($1)=="allowusers"{ $1=""; print }')"
    if [ -n "$ALLOW" ] && ! echo " $ALLOW " | grep -q " $USER_NAME "; then
        echo "  ! sshd AllowUsers does not include $USER_NAME -- add it, or SATOM cannot connect"
    fi
fi

# ── self-test as the account SATOM will use ─────────────────────────────────
if "$SUDO_BIN" -u "$USER_NAME" "$BIN" --selftest >/dev/null; then
    say "self-test passed"
else
    die "self-test failed: run  sudo -u $USER_NAME $BIN --selftest"
fi
echo "Done. In SATOM, open the connection and press Test."
