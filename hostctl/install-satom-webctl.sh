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
#   * user satom-mon (no password, login only through the key above) and its
#     own group; --uninstall deletes the account only when this installer
#     created it (comment "SATOM web host management"), otherwise it removes
#     SATOM's key line and leaves the account alone
#   * ~satom-mon/.ssh/authorized_keys: SATOM's key, in the account's REAL home
#     (the one sshd reads), whatever that home is
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
#       [--from 192.0.2.248,192.0.2.249] [--client 192.0.2.248] [--roots /var/www,/srv/www]
#       [--read-only]
#       [--user <account>]
#   install-satom-webctl.sh --uninstall [--purge] [--user <account>]
# --client: the address SATOM connects from (sshd's Match blocks are checked
# for it); SATOM passes it, by hand it defaults to the first --from address.
# --user: the account SATOM's key signs in as (default satom-mon, created
# here). Name an EXISTING account where sshd only lets some users or groups
# in (AllowUsers / AllowGroups, SA-0031): the installer creates nothing then,
# leaves the account's password, shell and other keys alone, and the key it
# adds is restricted to satom-webctl exactly as for satom-mon -- the account's
# own logins are not affected. Never root. --uninstall needs the same --user.
set -euo pipefail
# sudo keeps the caller's PATH where secure_path is not set (SUSE's default
# sudoers): useradd, visudo, apache2ctl and sshd live in sbin and were "not
# found" there (SA-0028). The tools this script needs, wherever they live.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"

USER_NAME="satom-mon"
USER_COMMENT="SATOM web host management"
HOME_DIR="/var/lib/satom-webctl"
LOG_DIR="/var/log/satom-webctl"
BIN="/usr/local/bin/satom-webctl"
CONF="/etc/satom-webctl.json"
CERT_BASE="/etc/satom-webctl"
CERT_DIR="$CERT_BASE/certs"
SUDOERS="/etc/sudoers.d/satom-webctl"
HERE="$(cd "$(dirname "$0")" && pwd)"
PUBKEY="" FROM="" CLIENT="" ROOTS="/var/www,/srv/www" READ_ONLY="false" MODE="install" PURGE="no"
KEY_MARK="command=\"$BIN\""

die() { echo "install-satom-webctl: $*" >&2; exit 1; }
say() { echo "  - $*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --pubkey) PUBKEY="${2:-}"; shift 2 ;;
        --from) FROM="${2:-}"; shift 2 ;;
        --client) CLIENT="${2:-}"; shift 2 ;;
        --roots) ROOTS="${2:-}"; shift 2 ;;
        --read-only) READ_ONLY="true"; shift ;;
        --uninstall) MODE="uninstall"; shift ;;
        --purge) PURGE="yes"; shift ;;
        --user) USER_NAME="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,46p' "$0"; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

# a Linux account name (it goes into sudoers, ACLs and sshd -T -C as is)
echo "$USER_NAME" | grep -Eq '^[a-z_][a-z0-9_.-]{0,31}$' \
    || die "--user takes a Linux account name (lower case, digits, . _ -)"
# SATOM's key is never root's, whatever the account is called
if [ "$USER_NAME" = "root" ] || [ "$(id -u "$USER_NAME" 2>/dev/null || echo x)" = "0" ]; then
    die "--user $USER_NAME is root: the agent never signs in as root (pick satom-mon or an unprivileged account)"
fi
if [ "$USER_NAME" != "satom-mon" ] && [ "$MODE" = "install" ] && ! id "$USER_NAME" >/dev/null 2>&1; then
    die "--user $USER_NAME: no such account on this server (only satom-mon is created here)"
fi
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

# sshd's settings FOR the account from SATOM's address: Match blocks count
# (sshd -T alone ignores them -- SA-0030). One "key value" per line.
SSHD_T=""
sshd_eff() {
    command -v sshd >/dev/null 2>&1 || return 0
    local a="${CLIENT:-${FROM%%,*}}"
    a="${a%%/*}"; [ -n "$a" ] || a="127.0.0.1"
    SSHD_T="$(sshd -T -C "user=$USER_NAME,host=$a,addr=$a" 2>/dev/null || sshd -T 2>/dev/null || true)"
}
# The values of one sshd setting, space-separated on one line.
sshd_opt() { echo "$SSHD_T" | awk -v k="$1" 'tolower($1)==k{ $1=""; sub(/^ /, ""); printf "%s ", $0 }'; }
# Every file sshd reads the account's keys from (AuthorizedKeysFile expanded:
# %h %u %U %%; relative = under the home), one per line.
key_files() {
    local home="$1" e f uid
    uid="$(id -u "$USER_NAME" 2>/dev/null || true)"
    set -f
    for e in $(sshd_opt authorizedkeysfile); do
        [ "$e" = "none" ] && continue
        f="${e//"%%"/$'\001'}"; f="${f//"%h"/$home}"; f="${f//"%u"/$USER_NAME}"
        f="${f//"%U"/$uid}"; f="${f//$'\001'/%}"
        case "$f" in /*) ;; *) f="$home/$f" ;; esac
        echo "$f"
    done
    set +f
}
# Remove SATOM's line from a key file (the file goes when nothing else is in it).
drop_key_line() {
    local f="$1"
    [ -f "$f" ] || return 0
    grep -vF "$KEY_MARK" "$f" > "$f.tmp" || true
    if [ -s "$f.tmp" ]; then cat "$f.tmp" > "$f"; else rm -f "$f"; fi
    rm -f "$f.tmp"
}

# The account's home as sshd sees it ("" when there is no such account).
account_home() { getent passwd "$USER_NAME" | cut -d: -f6; }
# True when this installer created the account (its comment says so).
created_here() { [ "$(getent passwd "$USER_NAME" | cut -d: -f5)" = "$USER_COMMENT" ]; }

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
        HOME_NOW="$(account_home)"
        sshd_eff
        # only SATOM's line: whatever else the account trusts is not ours --
        # in every file sshd reads, not only ~/.ssh (SA-0030)
        for AK in $( (echo "$HOME_NOW/.ssh/authorized_keys"; key_files "$HOME_NOW") | sort -u); do
            if [ -f "$AK" ] && grep -qF "$KEY_MARK" "$AK"; then
                drop_key_line "$AK"
                say "SATOM's key removed from $AK"
            fi
        done
        if command -v semanage >/dev/null 2>&1 \
                && semanage fcontext -l -C 2>/dev/null | grep -qF "$HOME_NOW/.ssh(/.*)?"; then
            semanage fcontext -d "$HOME_NOW/.ssh(/.*)?" 2>/dev/null || true
            say "SELinux label rule for $HOME_NOW/.ssh removed"
        fi
        if created_here; then
            GRP="$(id -gn "$USER_NAME" 2>/dev/null || true)"
            # SATOM's last sign-in as the account left a systemd user manager
            # running for a few seconds, and userdel refused "currently used
            # by process" -- silently: a Reinstall followed by Remove left the
            # account (SA-0030). Close its sessions, then try for a while.
            if command -v loginctl >/dev/null 2>&1; then
                loginctl terminate-user "$USER_NAME" 2>/dev/null || true
            fi
            DEL_ERR=""
            for _ in 1 2 3 4 5 6 7 8 9 10; do
                if DEL_ERR="$(userdel "$USER_NAME" 2>&1)"; then DEL_ERR=""; break; fi
                id "$USER_NAME" >/dev/null 2>&1 || { DEL_ERR=""; break; }
                sleep 1
            done
            if [ -n "$DEL_ERR" ]; then
                echo "  ! could not remove user $USER_NAME: $DEL_ERR"
            else
                if [ "$GRP" = "$USER_NAME" ] && getent group "$GRP" >/dev/null; then
                    groupdel "$GRP" 2>/dev/null || true
                fi
                say "user $USER_NAME removed"
            fi
        else
            say "kept the account $USER_NAME: this installer did not create it"
        fi
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
    # --user-group: SUSE's useradd puts a new account in "users" unless asked
    useradd --system --user-group --home-dir "$HOME_DIR" --create-home --shell /bin/sh \
        --comment "$USER_COMMENT" "$USER_NAME"
    say "created user $USER_NAME"
fi
if created_here; then
    # '*' = no password can ever match, and NOT "locked": with UsePAM no, sshd
    # refuses a locked ('!') account even with a valid key (SA-0030). No
    # password ageing either: an aged-out password makes PAM refuse the key.
    usermod -p '*' "$USER_NAME"
    chage -I -1 -m 0 -M -1 -E -1 "$USER_NAME" 2>/dev/null || true
else
    say "kept $USER_NAME's password and ageing as they are (this installer did not create it)"
fi
# the account's primary group, whatever it is (an account that already existed
# may have no group of its own name)
GROUP_NAME="$(id -gn "$USER_NAME")"
ACCT_HOME="$(account_home)"
[ -n "$ACCT_HOME" ] || ACCT_HOME="$HOME_DIR"
install -d -o "$USER_NAME" -g "$GROUP_NAME" -m 0750 "$HOME_DIR"
install -d -o "$USER_NAME" -g "$GROUP_NAME" -m 0700 "$HOME_DIR/backups"
install -d -o "$USER_NAME" -g "$GROUP_NAME" -m 0750 "$LOG_DIR"
install -d -o root -g root -m 0755 "$CERT_BASE"
install -d -o "$USER_NAME" -g "$GROUP_NAME" -m 0700 "$CERT_DIR"
# the agent's own files (backups, log, certificates) belong to the account it
# runs as now: after a reinstall as another account (SA-0031) they were the
# old one's, and satom-webctl could not append its log or renew a certificate
chown -R "$USER_NAME:$GROUP_NAME" "$HOME_DIR/backups" "$LOG_DIR" "$CERT_DIR"
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
OPTS="restrict,$KEY_MARK"
[ -n "$FROM" ] && OPTS="$OPTS,from=\"$FROM\""
# sshd reads the key from the account's REAL home: an account that already
# existed with another home got its key where sshd never looked (SA-0028).
[ -d "$ACCT_HOME" ] || install -d -o "$USER_NAME" -g "$GROUP_NAME" -m 0750 "$ACCT_HOME"
if [ -n "$(find "$ACCT_HOME" -maxdepth 0 -perm /022)" ]; then
    echo "  ! $ACCT_HOME is writable by group or others: sshd (StrictModes) ignores its keys"
fi
HOME_OWNER="$(stat -c %U "$ACCT_HOME")"
if [ "$HOME_OWNER" != "$USER_NAME" ] && [ "$HOME_OWNER" != "root" ]; then
    echo "  ! $ACCT_HOME belongs to $HOME_OWNER: sshd (StrictModes) ignores keys under it"
fi
# Put SATOM's line in a key file and keep every other line in it: an account
# that already existed may trust other keys, and they stay (SA-0030).
put_key_line() {  # file owner group mode
    local f="$1" dmode=0700
    [ "$2" = root ] && dmode=0755
    [ -d "$(dirname "$f")" ] || install -d -o "$2" -g "$3" -m "$dmode" "$(dirname "$f")"
    { if [ -f "$f" ]; then grep -vF "$KEY_MARK" "$f" || true; fi
      printf '%s %s\n' "$OPTS" "$PUBKEY"; } > "$f.tmp"
    cat "$f.tmp" > "$f"
    rm -f "$f.tmp"
    chown "$2:$3" "$f"
    chmod "$4" "$f"
}
sshd_eff
AK="$ACCT_HOME/.ssh/authorized_keys"
install -d -o "$USER_NAME" -g "$GROUP_NAME" -m 0700 "$ACCT_HOME/.ssh"
put_key_line "$AK" "$USER_NAME" "$GROUP_NAME" 0600
say "authorized SATOM's key in $ACCT_HOME/.ssh: $OPTS"
# sshd may read keys from elsewhere (AuthorizedKeysFile /etc/ssh/keys/%u ...):
# the key goes there too, or sshd never sees it (SA-0030)
if [ -n "$SSHD_T" ] && ! key_files "$ACCT_HOME" | grep -qxF "$AK"; then
    KF="$(key_files "$ACCT_HOME" | head -n1)"
    if [ -n "$KF" ]; then
        case "$KF" in
            "$ACCT_HOME"/*) put_key_line "$KF" "$USER_NAME" "$GROUP_NAME" 0600 ;;
            *) put_key_line "$KF" root root 0644 ;;
        esac
        say "sshd reads keys from $KF: SATOM's key is there too"
    else
        echo "  ! sshd reads no AuthorizedKeysFile (AuthorizedKeysCommand only?): add SATOM's key where that command looks"
    fi
fi
# SELinux: sshd may only read keys labelled ssh_home_t, and a home outside
# /home ($ACCT_HOME) gets var_lib_t -- sshd refused the key (SA-0030)
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
    if command -v semanage >/dev/null 2>&1; then
        semanage fcontext -a -t ssh_home_t "$ACCT_HOME/.ssh(/.*)?" 2>/dev/null \
            || semanage fcontext -m -t ssh_home_t "$ACCT_HOME/.ssh(/.*)?" 2>/dev/null || true
        restorecon -R "$ACCT_HOME/.ssh"
        say "SELinux: $ACCT_HOME/.ssh labelled ssh_home_t (rule kept for relabels)"
    else
        chcon -R -t ssh_home_t "$ACCT_HOME/.ssh"
        echo "  ! SELinux: labelled $ACCT_HOME/.ssh ssh_home_t with chcon; a full relabel undoes it (install policycoreutils-python-utils and run the installer again)"
    fi
fi

# What would still keep the account out, for the address SATOM connects from
# (sshd -T -C: Match blocks included -- sshd -T alone missed them, SA-0030).
if [ -n "$SSHD_T" ]; then
    GROUPS_OF="$(id -Gn "$USER_NAME")"
    matches_user() {  # patterns...: true when one names $USER_NAME
        local p
        for p in "$@"; do
            # shellcheck disable=SC2254
            case "$USER_NAME" in ${p%%@*}) return 0 ;; esac
        done
        return 1
    }
    matches_group() {
        local p g
        for p in "$@"; do
            for g in $GROUPS_OF; do
                # shellcheck disable=SC2254
                case "$g" in $p) return 0 ;; esac
            done
        done
        return 1
    }
    set -f
    ALLOW="$(sshd_opt allowusers)"
    if [ -n "${ALLOW// /}" ] && ! matches_user $ALLOW; then
        echo "  ! sshd AllowUsers ($ALLOW) does not include $USER_NAME -- add it, or install the agent as an account sshd lets in (--user; in SATOM: Agent account), or SATOM cannot connect"
    fi
    if matches_user $(sshd_opt denyusers); then
        echo "  ! sshd DenyUsers names $USER_NAME -- SATOM cannot connect"
    fi
    ALLOWG="$(sshd_opt allowgroups)"
    if [ -n "${ALLOWG// /}" ] && ! matches_group $ALLOWG; then
        echo "  ! sshd AllowGroups ($ALLOWG) has no group of $USER_NAME ($GROUPS_OF) -- add one, or install the agent as an account sshd lets in (--user; in SATOM: Agent account), or SATOM cannot connect"
    fi
    if matches_group $(sshd_opt denygroups); then
        echo "  ! sshd DenyGroups names a group of $USER_NAME -- SATOM cannot connect"
    fi
    set +f
    if [ "$(sshd_opt pubkeyauthentication)" = "no " ]; then
        echo "  ! sshd has PubkeyAuthentication no for $USER_NAME -- SATOM cannot connect"
    fi
    METHODS="$(sshd_opt authenticationmethods)"
    if [ -n "${METHODS// /}" ] && ! echo " $METHODS " | grep -Eq ' (any|publickey) '; then
        echo "  ! sshd requires AuthenticationMethods $METHODS-- a key alone is not enough: add 'Match User $USER_NAME' with 'AuthenticationMethods publickey'"
    fi
    KTYPE="${PUBKEY%% *}"
    ACCEPTED="$(sshd_opt pubkeyacceptedalgorithms)$(sshd_opt pubkeyacceptedkeytypes)"
    if [ -n "${ACCEPTED// /}" ] && ! echo ",${ACCEPTED// /}," | grep -qF ",$KTYPE,"; then
        echo "  ! sshd does not accept $KTYPE keys (FIPS mode or a crypto policy) -- SATOM installs again with an ECDSA P-256 key"
    fi
    if [ "$(sshd_opt usepam)" = "no " ] && getent shadow "$USER_NAME" | cut -d: -f2 | grep -q '^!'; then
        echo "  ! $USER_NAME's password is locked ('!') and sshd runs with UsePAM no: sshd refuses the account -- usermod -p '*' $USER_NAME"
    fi
    case "$(getent passwd "$USER_NAME" | cut -d: -f7)" in
        */nologin|*/false)
            echo "  ! $USER_NAME's shell is $(getent passwd "$USER_NAME" | cut -d: -f7): satom-webctl cannot run -- usermod -s /bin/sh $USER_NAME" ;;
    esac
fi

# ── self-test as the account SATOM will use ─────────────────────────────────
if "$SUDO_BIN" -u "$USER_NAME" "$BIN" --selftest >/dev/null; then
    say "self-test passed"
else
    die "self-test failed: run  sudo -u $USER_NAME $BIN --selftest"
fi
echo "Done. In SATOM, open the connection and press Test."
