#!/usr/bin/env bash
# ============================================================================
# satom-setup.sh — SATOM guided installer (native or Docker)
#
#   Download:  https://github.com/visionebc/SATOM/releases/download/v<version>/satom-setup.sh
#              (also inside every offline bundle, next to install-satom.sh)
#   Installs THE RELEASE IT IS PUBLISHED WITH (SETUP_VERSION, below); another
#   one with --version X.Y.Z. See docs/INSTALL.md §2 (guided install).
#   Usage:     sudo bash satom-setup.sh              (interactive)
#              sudo bash satom-setup.sh --check      (checks only)
#              sudo bash satom-setup.sh --yes --answers answers.env
#              sudo bash satom-setup.sh --uninstall  (Docker install only)
#
# FLOW
#   1. Operating system + requirements (CPU, RAM, disk, ports, Internet).
#   2. Is there an existing install? (native or Docker) -> update / reinstall.
#   3. Native or Docker.
#      Native : uses the release's OFFICIAL install-satom.sh (online) or the
#               offline bundle for your distro; this script answers its
#               questions, so everything is asked ONCE, here. When run
#               INSIDE an offline bundle (satom-installer/), it uses the
#               install-satom.sh next to it and downloads nothing.
#      Docker : installs Docker + Compose if missing, builds the image from
#               the release's published code and brings the stack up.
#               - Database in the same stack, or an external PostgreSQL.
#               - Role: standalone / primary / standby.
#               - Operations agent (if the release ships it).
#   4. DNS name + certificate (the node's own, or imported).
#   5. Admin password (prompted and validated; if left empty one is generated
#      and saved to a 0600 file — there is never a default password).
#   6. Firewall (firewalld/ufw) and SELinux.
#   7. Summary: URL, where the password is, log, and how to uninstall.
#
# NON-INTERACTIVE MODE (--yes): every question takes its value from a SETUP_*
# variable (from the environment or the --answers file). List in --help.
# ============================================================================
set -Eeuo pipefail

# The release this script installs: the same one it is published with.
# deploy/stamp_site_assets.py stamps it from VERSION when the release is cut
# (like install-satom.sh's VERSION) and the release pipeline refuses to
# publish if it does not match. MUST be the first line matching ^(SATOM_|SETUP_)?VERSION=.
SETUP_VERSION="2.1.2"
GH_REPO="visionebc/SATOM"
GH_URL="https://github.com/${GH_REPO}"
LOG="/var/log/satom-setup.log"
DOCKER_HOME="/opt/satom-docker"
NATIVE_DIR="/opt/satom"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

c_b=$'\033[1m'; c_g=$'\033[32m'; c_y=$'\033[33m'; c_r=$'\033[31m'; c_d=$'\033[2m'; c_0=$'\033[0m'
[ -t 1 ] || { c_b=; c_g=; c_y=; c_r=; c_d=; c_0=; }

log_raw() { printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOG" 2>/dev/null || true; }
say()  { echo; echo "${c_b}==> $*${c_0}"; log_raw "==> $*"; }
ok()   { echo "    ${c_g}✓${c_0} $*"; log_raw "OK $*"; }
warn() { echo "    ${c_y}!${c_0} $*"; log_raw "WARN $*"; }
info() { echo "    ${c_d}·${c_0} $*"; log_raw "INFO $*"; }
die()  { echo; echo "${c_r}ERROR:${c_0} $*" >&2; log_raw "ERROR $*"; exit 1; }

CURRENT_STEP="start"
on_error() {
    local rc=$?
    echo
    echo "${c_r}The installation stopped at step: ${CURRENT_STEP} (exit code ${rc}).${c_0}" >&2
    echo "  Full log: ${LOG}" >&2
    echo "  You can run this script again: it resumes without undoing what is done" >&2
    echo "  (secrets already generated are kept)." >&2
    log_raw "FAILED at step '${CURRENT_STEP}' rc=${rc}"
    exit "$rc"
}
trap on_error ERR

usage() {
    cat <<'EOF'
satom-setup.sh — SATOM guided installer (native or Docker)

Options:
  --check              System checks only; installs nothing.
  --yes                No questions: uses SETUP_* variables / default values.
  --answers FILE       KEY=VALUE file with the answers (does nothing by itself; combine with --yes).
  --version X.Y.Z      SATOM version (default: this script's own, SETUP_VERSION;
                       'latest' = the latest release published on GitHub).
  --bundle FILE        Native offline bundle (satom-offline-<ver>-<distro>.tar.gz).
                       Not needed when run from inside an already extracted
                       bundle (satom-installer/, with bundle/ next to it).
  --force              Continue even if the distro is not supported.
  --uninstall          Uninstall the Docker install (keeps the data).
  --purge              With --uninstall: ALSO deletes the volumes (data). Irreversible.
  -h, --help           This help.

Variables for --yes (all optional unless stated otherwise):
  SETUP_MODE=native|docker            (required with --yes)
  SETUP_SOURCE=online|offline         (native; offline requires --bundle, the .tar.gz next
                                       to this script, or running from inside the extracted bundle)
  SETUP_GIT_URL                       (native online: repo to clone; empty = the public one.
                                       Any other repo = no prior check of the code)
  SETUP_ROLE=standalone|primary|secondary   (native)  | standalone|primary|standby (docker)
  SETUP_IP, SETUP_PORT (443), SETUP_NAMES ("fqdn other-name")
  SATOM_ADMIN_PASSWORD                (empty = generated and saved to a 0600 file)
  SETUP_DB=bundled|external           (docker)
  SETUP_DB_HOST, SETUP_DB_PORT (5432), SETUP_DB_NAME (satom), SETUP_DB_USER (satom), SETUP_DB_PASSWORD
  SETUP_AGENT=yes|no                  (docker; only if the release ships the agent)
  SETUP_CERT=self|import, SETUP_CERT_FILE, SETUP_KEY_FILE, SETUP_CHAIN_FILE
  SETUP_FIREWALL=yes|no               (open ports if firewalld/ufw is active)
  SETUP_INSTALL_DOCKER=yes|no         (install Docker if missing)
  SETUP_JOIN_KEY                      (native secondary: the primary's join key)
  SETUP_SECONDARY_IP                  (native primary)
  SETUP_JOIN_FILE                     (docker standby: join file generated on the primary)
  SETUP_EXISTING=update|reinstall|abort   (if there is already an install)
EOF
}

# ─────────────────────────────────────────────────────────────────────────────
# Arguments
# ─────────────────────────────────────────────────────────────────────────────
ASSUME_YES=0; CHECK_ONLY=0; FORCE=0; UNINSTALL=0; PURGE=0
WANT_VERSION=""; BUNDLE_FILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK_ONLY=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --answers) shift; [ -f "${1:-}" ] || die "--answers: '${1:-}' does not exist"
                   set -a; . "$1"; set +a ;;
        --version) shift; WANT_VERSION="${1#v}" ;;
        --bundle) shift; BUNDLE_FILE="${1:-}" ;;
        --force) FORCE=1 ;;
        --uninstall) UNINSTALL=1 ;;
        --purge) PURGE=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
    shift
done

[ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash $0"
mkdir -p "$(dirname "$LOG")"; touch "$LOG"; chmod 600 "$LOG"
log_raw "===== satom-setup ${SETUP_VERSION} — $(date -u +%FT%TZ) ====="

# ─────────────────────────────────────────────────────────────────────────────
# Questions. With --yes each one reads its SETUP_* variable; with no value it
# uses the default; if there is none either, it stops and names the missing variable.
# ─────────────────────────────────────────────────────────────────────────────
# ask VAR "question" "default" [PRESET_VAR]
ask() {
    local __var="$1" __q="$2" __def="${3:-}" __pre="${4:-}" __ans=""
    if [ -n "$__pre" ] && [ -n "${!__pre:-}" ]; then
        __ans="${!__pre}"; info "$__q ${__ans} (from ${__pre})"
    elif [ "$ASSUME_YES" -eq 1 ]; then
        [ -n "$__def" ] || die "--yes mode: ${__pre:-the answer} is missing for: $__q"
        __ans="$__def"; info "$__q ${__ans} (default)"
    else
        read -rp "    ${__q}${__def:+ [${__def}]}: " __ans </dev/tty || die "Input closed at: $__q"
        __ans="${__ans:-$__def}"
    fi
    printf -v "$__var" '%s' "$__ans"
    case "$__var" in join|*pw*|*PW*) log_raw "Q: $__q -> ***" ;; *) log_raw "Q: $__q -> $__ans" ;; esac
}
# ask_choice VAR "question" "opt1|opt2|opt3" "default" [PRESET_VAR]
ask_choice() {
    local __var="$1" __q="$2" __opts="$3" __def="$4" __pre="${5:-}" __a
    while :; do
        ask __a "$__q (${__opts//|/\/})" "$__def" "$__pre"
        __a="$(printf '%s' "$__a" | tr 'A-Z' 'a-z')"
        case "|$__opts|" in *"|$__a|"*) printf -v "$__var" '%s' "$__a"; return ;; esac
        [ "$ASSUME_YES" -eq 1 ] || [ -n "$__pre" -a -n "${!__pre:-}" ] && die "Invalid value '$__a' for: $__q (options: $__opts)"
        warn "Valid options: ${__opts//|/, }"
    done
}
ask_yn() {  # ask_yn "question" y|n [PRESET_VAR] -> rc 0 = yes
    local __a; ask __a "$1 (y/n)" "$2" "${3:-}"
    # s|si are still accepted, silently, for answer files written for <= 2.1.2.
    case "$(printf '%s' "$__a" | tr 'A-Z' 'a-z')" in y|yes|1|true|s|si) return 0 ;; *) return 1 ;; esac
}

# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────
have() { command -v "$1" >/dev/null 2>&1; }
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }   # ver_ge A B -> A >= B
port_owner() {
    have ss || { echo ""; return; }
    ss -Htlnp "sport = :$1" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -1
}
urlencode() {
    local s="$1" o="" c i
    for ((i=0; i<${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in [a-zA-Z0-9.~_-]) o+="$c" ;; *) o+="$(printf '%%%02X' "'$c")" ;; esac
    done
    printf '%s' "$o"
}
rand_hex() { openssl rand -hex "$1"; }
installer_version() {  # installer_version FILE -> its top-level VERSION="x.y.z"
    sed -n 's/^VERSION="\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -1
}
fetch() { curl -fsSL --retry 3 --connect-timeout 15 "$@"; }

password_ok() {  # >= 10 characters and at least 3 of: lowercase, uppercase, digits, symbols
    local p="$1" n=0
    [ "${#p}" -ge 10 ] || { warn "At least 10 characters."; return 1; }
    [[ "$p" =~ [a-z] ]] && n=$((n+1)); [[ "$p" =~ [A-Z] ]] && n=$((n+1))
    [[ "$p" =~ [0-9] ]] && n=$((n+1)); [[ "$p" =~ [^a-zA-Z0-9] ]] && n=$((n+1))
    [ "$n" -ge 3 ] || { warn "Use at least 3 kinds: lowercase, uppercase, digits, symbols."; return 1; }
    [[ "$p" == *"'"* ]] && { warn "The single quote (') is not allowed."; return 1; }
    return 0
}

ADMIN_PW=""; ADMIN_PW_GENERATED=0; ADMIN_PW_FILE="/root/satom-admin-password.txt"
ask_admin_password() {
    say "Password for the 'admin' user"
    if [ -n "${SATOM_ADMIN_PASSWORD:-}" ]; then
        password_ok "$SATOM_ADMIN_PASSWORD" || die "SATOM_ADMIN_PASSWORD does not meet the policy"
        ADMIN_PW="$SATOM_ADMIN_PASSWORD"; ok "Password taken from SATOM_ADMIN_PASSWORD"; return
    fi
    if [ "$ASSUME_YES" -eq 0 ]; then
        info "Empty Enter = generate a random password and save it to ${ADMIN_PW_FILE} (0600)."
        local a b
        while :; do
            read -rsp "    Password for 'admin': " a </dev/tty; echo
            [ -z "$a" ] && break
            password_ok "$a" || continue
            read -rsp "    Repeat the password: " b </dev/tty; echo
            [ "$a" = "$b" ] || { warn "They do not match."; continue; }
            ADMIN_PW="$a"; ok "Password accepted"; return
        done
    fi
    ADMIN_PW="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)Aa1!"
    ADMIN_PW_GENERATED=1
    ( umask 077; printf '%s\n' "$ADMIN_PW" > "$ADMIN_PW_FILE" )
    ok "Password generated and saved to ${ADMIN_PW_FILE} (readable by root only)"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Operating system and requirements
# ─────────────────────────────────────────────────────────────────────────────
OS_ID=""; OS_VER=""; OS_NAME=""; OS_FAMILY=""; OS_BUNDLE=""; PKG=""
detect_os() {
    CURRENT_STEP="1 · operating system"
    say "Step 1 · Operating system and requirements"
    [ -r /etc/os-release ] || die "/etc/os-release does not exist: unrecognisable distribution"
    # In a SUBSHELL: os-release defines VERSION (e.g. "15.6") and NAME, and
    # sourcing it here overwrote the SATOM version to install.
    local id="" id_like="" ver_id="" pretty=""
    { IFS= read -r id; IFS= read -r id_like; IFS= read -r ver_id; IFS= read -r pretty; } < <(
        # shellcheck disable=SC1091
        . /etc/os-release
        printf '%s\n' "${ID:-}" "${ID_LIKE:-}" "${VERSION_ID:-}" "${PRETTY_NAME:-}")
    OS_ID="${id:-?}"; OS_VER="${ver_id:-?}"; OS_NAME="${pretty:-$OS_ID $OS_VER}"
    local like=" ${id} ${id_like} " major="${ver_id%%.*}" support="no"
    case "$like" in
        *" debian "*|*" ubuntu "*)
            OS_FAMILY=debian; PKG=apt
            case "$OS_ID:$major" in
                debian:12) support=yes; OS_BUNDLE="debian12-amd64" ;;
                debian:13|ubuntu:22|ubuntu:24) support=yes ;;
                debian:11) support=warn ;;
            esac ;;
        *" rhel "*|*" centos "*|*" fedora "*|*" rocky "*|*" almalinux "*)
            OS_FAMILY=rhel; PKG=dnf; have dnf || PKG=yum
            case "$OS_ID:$major" in
                rhel:9|rocky:9|almalinux:9|centos:9) support=yes; OS_BUNDLE="rhel9-x86_64" ;;
                rhel:8|rocky:8|almalinux:8|fedora:*) support=warn ;;
            esac ;;
        *" suse "*|*" opensuse "*|*" sles "*)
            OS_FAMILY=suse; PKG=zypper
            case "$OS_ID:$major" in
                opensuse-leap:15|sles:15|sled:15) support=yes; OS_BUNDLE="suse15-x86_64" ;;
                opensuse-tumbleweed:*|opensuse-leap:16|sles:16) support=warn ;;
            esac ;;
    esac
    case "$support" in
        yes)  ok "System: ${OS_NAME} (${OS_FAMILY} family) — supported" ;;
        warn) warn "System: ${OS_NAME} — not on the tested list; it should work" ;;
        *)    if [ "$FORCE" -eq 1 ]; then warn "System: ${OS_NAME} — NOT supported (continuing because of --force)"
              else die "System ${OS_NAME} is not supported. Supported: Debian 12/13, Ubuntu 22.04/24.04, RHEL/Rocky/Alma 9, openSUSE Leap/SLES 15. (--force to try anyway)"; fi ;;
    esac
    [ "$(uname -m)" = "x86_64" ] || warn "Architecture $(uname -m): the offline bundles are x86_64 only"
    have systemctl && [ -d /run/systemd/system ] || die "systemd is required (not detected as init)"
    ok "systemd present"
}

NODE_IP=""; INTERNET=0
check_requirements() {
    CURRENT_STEP="1 · requirements"
    local cores mem_mb disk_mb
    cores=$(nproc 2>/dev/null || echo 1)
    mem_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
    disk_mb=$(df -Pm / | awk 'NR==2{print $4}')
    [ "$cores" -ge 2 ] && ok "CPU: ${cores} cores" || warn "CPU: ${cores} core(s) — 2 or more recommended"
    if   [ "$mem_mb" -ge 3800 ]; then ok "RAM: ${mem_mb} MB"
    elif [ "$mem_mb" -ge 1900 ]; then warn "RAM: ${mem_mb} MB — 4 GB minimum recommended (Docker uses more)"
    else die "RAM: ${mem_mb} MB — not enough (2 GB minimum, 4 GB recommended)"; fi
    if   [ "$disk_mb" -ge 15000 ]; then ok "Free disk on /: $((disk_mb/1024)) GB"
    elif [ "$disk_mb" -ge 8000 ];  then warn "Free disk on /: $((disk_mb/1024)) GB — Docker needs ~15 GB"
    else die "Free disk on /: ${disk_mb} MB — not enough (8 GB minimum)"; fi
    have curl || die "curl is missing (install it with the package manager: ${PKG} install curl)"
    have openssl || die "openssl is missing (${PKG} install openssl)"
    have tar || die "tar is missing"
    NODE_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)"
    [ -n "$NODE_IP" ] || NODE_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    ok "Primary IP: ${NODE_IP:-unknown}"
    local p o
    for p in 80 443; do
        o="$(port_owner "$p")"
        if [ -z "$o" ]; then ok "Port ${p} free"; else warn "Port ${p} in use by: ${o}"; fi
    done
    if curl -fsS -o /dev/null --connect-timeout 8 "${GH_URL}"; then
        INTERNET=1; ok "Internet access (github.com) OK"
    else
        warn "No access to github.com — only the OFFLINE native install is possible"
    fi
    if have getenforce; then info "SELinux: $(getenforce 2>/dev/null)"; fi
    if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then info "Firewall: firewalld active"
    elif have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then info "Firewall: ufw active"
    else info "Firewall: none active"; fi
}

# Version to install: this script's own unless --version. Pinned on purpose:
# "the latest published" made the same script install different things
# depending on the day, and made an offline bundle ask GitHub what it contains.
# Assigned HERE and not at the top: nothing earlier can overwrite it.
VERSION=""
resolve_version() {
    CURRENT_STEP="1 · version"
    VERSION="$SETUP_VERSION"
    if [ "$WANT_VERSION" = latest ]; then
        [ "$INTERNET" -eq 1 ] || die "--version latest needs Internet access (or give the version: --version X.Y.Z)"
        VERSION="$(curl -fsSI -o /dev/null -w '%{redirect_url}' "${GH_URL}/releases/latest" | sed -n 's|.*/tag/v\{0,1\}\([^/]*\)$|\1|p')"
        [ -n "$VERSION" ] || die "Could not determine the latest published version (use --version X.Y.Z)"
    elif [ -n "$WANT_VERSION" ]; then
        VERSION="$WANT_VERSION"
    fi
    [[ "$VERSION" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "Invalid version: '${VERSION}' (format X.Y.Z)"
    if [ "$VERSION" = "$SETUP_VERSION" ]; then
        ok "SATOM version to install: ${VERSION} (this installer's own)"
    else
        warn "SATOM version to install: ${VERSION} — differs from this installer's (${SETUP_VERSION})"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Is there an existing install?
# ─────────────────────────────────────────────────────────────────────────────
EXISTING=""   # native | docker | ""
detect_existing() {
    CURRENT_STEP="2 · existing install"
    say "Step 2 · Existing installs"
    if systemctl list-unit-files satom.service >/dev/null 2>&1 && systemctl cat satom.service >/dev/null 2>&1; then
        EXISTING=native
        warn "There is a NATIVE install ($(systemctl is-active satom.service 2>/dev/null || true)) — version $(cat "$NATIVE_DIR/VERSION" 2>/dev/null || echo '?')"
    elif [ -f "$DOCKER_HOME/.installed" ]; then
        EXISTING=docker
        warn "There is a DOCKER install in ${DOCKER_HOME} — version $(cat "$DOCKER_HOME/current/VERSION" 2>/dev/null || echo '?')"
    elif [ -f "$DOCKER_HOME/satom.env" ]; then
        warn "There is a HALF-FINISHED Docker install in ${DOCKER_HOME} (a previous attempt failed): it will be resumed with its secrets"
    else
        ok "No SATOM install on this machine"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Firewall
# ─────────────────────────────────────────────────────────────────────────────
open_firewall() {  # open_firewall port...
    local p
    if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        ask_yn "firewalld is active. Open ports $*/tcp?" y SETUP_FIREWALL || { warn "Ports NOT opened: open them yourself or the console will not be reachable"; return; }
        for p in "$@"; do firewall-cmd --permanent --add-port="${p}/tcp" >>"$LOG" 2>&1 || true; done
        firewall-cmd --reload >>"$LOG" 2>&1 || true
        ok "firewalld: opened $*/tcp"
    elif have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then
        ask_yn "ufw is active. Open ports $*/tcp?" y SETUP_FIREWALL || { warn "Ports NOT opened"; return; }
        for p in "$@"; do ufw allow "${p}/tcp" >>"$LOG" 2>&1 || true; done
        ok "ufw: opened $*/tcp"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# DNS name and port (shared by both modes)
# ─────────────────────────────────────────────────────────────────────────────
NAMES=""; WEB_PORT=443
ask_names_port() {
    say "Console name and port"
    local def_names; def_names="$(hostname -f 2>/dev/null || hostname)"
    ask NAMES "DNS name(s) the console will be reached at (space-separated)" "$def_names" SETUP_NAMES
    NAMES="$(printf '%s' "$NAMES" | tr ',;A-Z' '  a-z' | xargs)"
    local n; for n in $NAMES; do [[ "$n" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || die "Invalid DNS name: $n"; done
    ask NODE_IP "IP of this machine" "$NODE_IP" SETUP_IP
    [[ "$NODE_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Invalid IP: $NODE_IP"
    while :; do
        ask WEB_PORT "HTTPS port" "443" SETUP_PORT
        [[ "$WEB_PORT" =~ ^[0-9]+$ ]] && [ "$WEB_PORT" -ge 1 ] && [ "$WEB_PORT" -le 65535 ] || { warn "Invalid port"; [ "$ASSUME_YES" -eq 1 ] && die "Invalid SETUP_PORT"; continue; }
        local o; o="$(port_owner "$WEB_PORT")"
        if [ -n "$o" ] && [ "$o" != "nginx" ] && [ "$o" != "docker-proxy" ]; then
            warn "Port ${WEB_PORT} is used by '${o}'. Choose another one or stop that service."
            [ "$ASSUME_YES" -eq 1 ] && die "Port ${WEB_PORT} in use by ${o}"
            continue
        fi
        break
    done
}

# ═════════════════════════════════════════════════════════════════════════════
# NATIVE INSTALL
# ═════════════════════════════════════════════════════════════════════════════
install_native() {
    local src role join="" sec_ip="" work installer bundle=""
    CURRENT_STEP="3 · native: source"
    say "NATIVE install (systemd + PostgreSQL + nginx on this machine)"
    [ "$EXISTING" = docker ] && die "This machine already runs SATOM in Docker. Uninstall it first (--uninstall) or use another machine."

    # Is there an install-satom.sh NEXT TO this script, and is it for the
    # version being installed? That is the case of an extracted offline bundle
    # (satom-installer/, with bundle/ next to it) and of installers/ in a copy
    # of the code. Then that one is used and nothing is downloaded: it is the
    # one that came with this script.
    local sibling="" in_bundle=0
    if [ -f "$SCRIPT_DIR/install-satom.sh" ]; then
        if [ "$(installer_version "$SCRIPT_DIR/install-satom.sh")" = "$VERSION" ]; then
            sibling="$SCRIPT_DIR/install-satom.sh"
            [ -f "$SCRIPT_DIR/bundle/app.tar.gz" ] && in_bundle=1
        else
            warn "The install-satom.sh next to this script is not for version ${VERSION}: not used"
        fi
    fi

    # Source: online or offline bundle
    if [ "$in_bundle" -eq 0 ] && [ -z "$BUNDLE_FILE" ] && [ -n "$OS_BUNDLE" ]; then
        local cand; cand="$(ls -1 "$SCRIPT_DIR"/satom-offline-*-"${OS_BUNDLE}".tar.gz 2>/dev/null | sort -V | tail -1 || true)"
        [ -n "$cand" ] && BUNDLE_FILE="$cand"
    fi
    local def_src=online; { [ "$INTERNET" -eq 0 ] || [ "$in_bundle" -eq 1 ]; } && def_src=offline
    [ "$in_bundle" -eq 1 ] && info "Run from an offline bundle: its install-satom.sh is used (${SCRIPT_DIR})"
    ask_choice src "Install source?" "online|offline" "$def_src" SETUP_SOURCE
    if [ "$src" = offline ] && [ "$in_bundle" -eq 1 ]; then
        ok "Offline bundle: ${SCRIPT_DIR}/bundle"
    elif [ "$src" = offline ]; then
        if [ -z "$BUNDLE_FILE" ]; then
            [ -n "$OS_BUNDLE" ] || die "There is no offline bundle for ${OS_NAME}. Use online mode."
            if [ "$INTERNET" -eq 1 ] && [ -n "$VERSION" ]; then
                BUNDLE_FILE="$SCRIPT_DIR/satom-offline-${VERSION}-${OS_BUNDLE}.tar.gz"
                info "Downloading the ${OS_BUNDLE} offline bundle of release v${VERSION}…"
                fetch -o "$BUNDLE_FILE" "${GH_URL}/releases/download/v${VERSION}/$(basename "$BUNDLE_FILE")"
                fetch -o "${BUNDLE_FILE}.sha256" "${GH_URL}/releases/download/v${VERSION}/$(basename "$BUNDLE_FILE").sha256"
            else
                die "Offline mode: copy satom-offline-<version>-${OS_BUNDLE}.tar.gz next to this script or use --bundle PATH"
            fi
        fi
        [ -f "$BUNDLE_FILE" ] || die "The bundle does not exist: $BUNDLE_FILE"
        case "$BUNDLE_FILE" in *"$OS_BUNDLE"*) : ;; *) warn "The bundle does not look like one for ${OS_BUNDLE}: $(basename "$BUNDLE_FILE")" ;; esac
        if [ -f "${BUNDLE_FILE}.sha256" ]; then
            ( cd "$(dirname "$BUNDLE_FILE")" && sha256sum -c "$(basename "$BUNDLE_FILE").sha256" >>"$LOG" 2>&1 ) \
                || die "The bundle's SHA-256 checksum does NOT match: incomplete or tampered download"
            ok "Bundle verified (SHA-256)"
        else
            warn "No .sha256 file next to the bundle: its integrity cannot be verified"
        fi
    else
        [ "$INTERNET" -eq 1 ] || die "Without Internet access an online install is not possible. Use SETUP_SOURCE=offline."
    fi

    ask_names_port

    say "Node role"
    ask_choice role "Role?" "standalone|primary|secondary" "standalone" SETUP_ROLE
    if [ "$role" = secondary ]; then
        info "Paste the JOIN KEY the primary printed when its install finished."
        ask join "Join key" "" SETUP_JOIN_KEY
        [ -n "$join" ] || die "A secondary needs the primary's join key"
    else
        ask_admin_password
        if [ "$role" = primary ]; then
            ask sec_ip "Planned IP of the secondary (empty = the whole subnet)" "-" SETUP_SECONDARY_IP
            [ "$sec_ip" = "-" ] && sec_ip=""
        fi
    fi

    say "Summary before installing"
    info "Native mode · source ${src} · role ${role} · ${NAMES} · ${NODE_IP}:${WEB_PORT}"
    if [ "$EXISTING" = native ]; then
        local ex
        ask_choice ex "SATOM is already installed natively here. What should I do? (to update, use the Software Update page)" "reinstall|abort" "abort" SETUP_EXISTING
        [ "$ex" = reinstall ] || die "Cancelled: the existing install is kept"
        export SATOM_ALLOW_REINSTALL=1
    fi
    [ "$ASSUME_YES" -eq 1 ] || ask_yn "Continue?" y || die "Cancelled by the user"

    CURRENT_STEP="3 · native: prepare installer"
    work="/root/satom-setup-${VERSION:-local}"; mkdir -p "$work"; chmod 700 "$work"
    local git_url="${SETUP_GIT_URL:-}"
    if [ "$src" = offline ] && [ "$in_bundle" -eq 1 ]; then
        installer="$sibling"
        assert_sane_tarball "$SCRIPT_DIR/bundle/app.tar.gz" 0 "the offline bundle"
    elif [ "$src" = offline ]; then
        tar -xzf "$BUNDLE_FILE" -C "$work"
        installer="$(ls -1 "$work"/*/install-satom.sh 2>/dev/null | head -1)"
        [ -n "$installer" ] || die "The bundle does not contain install-satom.sh"
        ok "Bundle extracted to $(dirname "$installer")"
        assert_sane_tarball "$(dirname "$installer")/bundle/app.tar.gz" 0 "the offline bundle"
    else
        if [ -n "$sibling" ]; then
            # In $work, not where it is: with bundle/ next to it, install-satom.sh
            # would switch to offline mode even though online was chosen.
            installer="$work/install-satom.sh"
            cp "$sibling" "$installer"
            ok "install-satom.sh ${VERSION} taken from ${SCRIPT_DIR} (no download)"
        else
            installer="$work/install-satom.sh"
            fetch -o "$installer" "${GH_URL}/releases/download/v${VERSION}/install-satom.sh"
            ok "install-satom.sh v${VERSION} downloaded from the official release"
        fi
        # install-satom.sh clones the repo's main branch; THAT code is checked
        # before starting. With another repo (SETUP_GIT_URL) there is no way to see it first.
        if [ -z "$git_url" ]; then
            local tgz; tgz="$(mktemp /tmp/satom-src.XXXX.tar.gz)"
            fetch -o "$tgz" "https://codeload.github.com/${GH_REPO}/tar.gz/refs/heads/main" \
                || { rm -f "$tgz"; die "Could not download the code from ${GH_URL} to check it"; }
            assert_sane_tarball "$tgz" 1 "${GH_URL} (main branch)"
            rm -f "$tgz"
        else
            info "Custom repo (${git_url##*@}): the code is not checked before cloning it"
        fi
    fi
    bash -n "$installer" || die "install-satom.sh is not a valid script"

    # Answers in the SAME order install-satom.sh asks for them.
    # (The DNS name goes through SATOM_SERVED_NAMES and is not asked.)
    local answers="$work/.answers"
    ( umask 077
      {
        printf '%s\n' "$NODE_IP" "$WEB_PORT"
        if [ "$role" = standalone ]; then printf '%s\n' standalone
        else printf '%s\n' cluster "$role"; fi
        if [ "$role" = secondary ]; then printf '%s\n' "$join"
        else printf '%s\n' "$ADMIN_PW" "$ADMIN_PW"; fi
        [ "$role" = primary ] && printf '%s\n' "$sec_ip"
        printf '%s\n' y
        # Repo URL (online only): empty = the public default.
        [ "$src" = online ] && printf '%s\n' "$git_url"
        true
      } > "$answers" )

    CURRENT_STEP="3 · native: install-satom.sh"
    say "Running install-satom.sh (takes several minutes; log: /var/log/satom-install.log)"
    set +e
    SATOM_SERVED_NAMES="$NAMES" bash "$installer" < "$answers" 2>&1 | tee -a "$LOG"
    local rc=${PIPESTATUS[0]}
    set -e
    shred -u "$answers" 2>/dev/null || rm -f "$answers"
    [ "$rc" -eq 0 ] || { CURRENT_STEP="3 · native: install-satom.sh (rc=$rc)"; false; }

    CURRENT_STEP="4 · native: verification"
    say "Verification"
    local t=0
    until curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:${WEB_PORT}/healthz" | grep -q 200; do
        t=$((t+3)); [ "$t" -ge 180 ] && die "The console does not answer at https://127.0.0.1:${WEB_PORT}/healthz after 3 min"
        sleep 3
    done
    ok "healthz 200 on :${WEB_PORT}"
    # The firewall (firewalld or ufw) is opened by install-satom.sh [SATOM-FIREWALL].

    SUMMARY_MODE="native (${role})"
    SUMMARY_UNINSTALL="systemctl disable --now 'satom*' ; rm -rf ${NATIVE_DIR} ; ('satom' DB in PostgreSQL and vhost in /etc/nginx) — see docs/INSTALL.md"
    SUMMARY_LOGS="journalctl -u satom -f   ·   /var/log/satom-install.log"
}

# ═════════════════════════════════════════════════════════════════════════════
# DOCKER INSTALL
# ═════════════════════════════════════════════════════════════════════════════
COMPOSE_V=""
ensure_docker() {
    CURRENT_STEP="3 · docker: engine"
    if have docker && docker info >/dev/null 2>&1; then
        ok "Docker $(docker version -f '{{.Server.Version}}' 2>/dev/null) running"
    else
        if ! have docker; then
            ask_yn "Docker is not installed. Install it now (official packages from your distro/Docker)?" y SETUP_INSTALL_DOCKER \
                || die "Docker is required for this mode"
            install_docker_pkgs
        fi
        systemctl enable --now docker >>"$LOG" 2>&1 || die "Could not start the docker service (see: journalctl -u docker)"
        docker info >/dev/null 2>&1 || die "Docker is installed but does not respond (LXC container without nesting/keyctl?)"
        ok "Docker $(docker version -f '{{.Server.Version}}') running"
    fi
    if ! docker compose version >/dev/null 2>&1; then
        ask_yn "Docker Compose v2 is missing. Install it?" y SETUP_INSTALL_DOCKER || die "Compose v2 is required"
        install_compose_pkg
    fi
    COMPOSE_V="$(docker compose version --short 2>/dev/null | sed 's/^v//')"
    ver_ge "$COMPOSE_V" 2.20.0 || die "Docker Compose ${COMPOSE_V} is too old (2.20 minimum)"
    ok "Docker Compose ${COMPOSE_V}"
}
install_docker_pkgs() {
    CURRENT_STEP="3 · docker: install packages"
    info "Installing Docker (${OS_FAMILY})…"
    case "$OS_FAMILY" in
        suse)
            zypper -n --gpg-auto-import-keys refresh >>"$LOG" 2>&1 || true
            zypper -n install docker docker-compose >>"$LOG" 2>&1
            zypper -n install docker-buildx >>"$LOG" 2>&1 || true ;;
        debian)
            apt-get update >>"$LOG" 2>&1
            apt-get install -y ca-certificates curl gnupg >>"$LOG" 2>&1
            install -m 0755 -d /etc/apt/keyrings
            fetch "https://download.docker.com/linux/${OS_ID}/gpg" -o /etc/apt/keyrings/docker.asc
            chmod a+r /etc/apt/keyrings/docker.asc
            # shellcheck disable=SC1091
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${OS_ID} $(. /etc/os-release; echo "$VERSION_CODENAME") stable" \
                > /etc/apt/sources.list.d/docker.list
            apt-get update >>"$LOG" 2>&1
            apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >>"$LOG" 2>&1 ;;
        rhel)
            local repo=centos; [ "$OS_ID" = rhel ] && repo=rhel; [ "$OS_ID" = fedora ] && repo=fedora
            $PKG install -y dnf-plugins-core >>"$LOG" 2>&1 || true
            if $PKG config-manager --help >/dev/null 2>&1; then
                $PKG config-manager --add-repo "https://download.docker.com/linux/${repo}/docker-ce.repo" >>"$LOG" 2>&1 \
                  || $PKG config-manager addrepo --from-repofile="https://download.docker.com/linux/${repo}/docker-ce.repo" >>"$LOG" 2>&1
            else
                fetch -o /etc/yum.repos.d/docker-ce.repo "https://download.docker.com/linux/${repo}/docker-ce.repo"
            fi
            $PKG install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >>"$LOG" 2>&1 ;;
        *) die "I do not know how to install Docker on ${OS_NAME}. Install it by hand and run this again." ;;
    esac
    ok "Docker packages installed"
}
install_compose_pkg() {
    case "$OS_FAMILY" in
        suse)   zypper -n install docker-compose >>"$LOG" 2>&1 ;;
        debian) apt-get install -y docker-compose-plugin >>"$LOG" 2>&1 || apt-get install -y docker-compose-v2 >>"$LOG" 2>&1 ;;
        rhel)   $PKG install -y docker-compose-plugin >>"$LOG" 2>&1 ;;
    esac
    docker compose version >/dev/null 2>&1 || die "Could not install Docker Compose v2"
}

# [SATOM-NET-LITERALS] A code tree with an invalid NETWORK is not installed.
# The cleanup of the 2.1.1 public mirror rewrote private ranges as networks
# with host bits set (a private /8 became 192.0.2.0/8, the Docker network
# 203.0.113.0/16):
# Python raises ValueError on import, gunicorn does not start and Docker does
# not create the network. Since 2.1.2 the redactor leaves them alone; this
# repairs NOTHING — if a downloaded tree still carries one, it stops and names
# it, instead of installing something broken or silently "fixing" code.
# Runtime files only (*.py, *.yaml, *.yml) and only STRICTLY invalid networks
# ending in .0 (192.0.2.0/8). An interface's address/prefix notation
# (192.0.2.41/24) is legitimate and does not count.
bad_network_literals() {  # bad_network_literals DIR -> prints "file:line: network"
    local d="$1" sub roots=()
    for sub in app deploy migrations scripts; do [ -d "$d/$sub" ] && roots+=("$d/$sub"); done
    {
        [ "${#roots[@]}" -eq 0 ] || find "${roots[@]}" -type f \( -name '*.py' -o -name '*.yaml' -o -name '*.yml' \) -print0
        find "$d" -maxdepth 1 -type f \( -name '*.py' -o -name '*.yaml' -o -name '*.yml' \) -print0
    } 2>/dev/null | xargs -0 -r grep -HnoE '([0-9]{1,3}\.){3}0/[0-9]{1,2}' 2>/dev/null |
    awk -F: '{
        c = $NF; split(c, a, "/"); split(a[1], o, "."); p = a[2] + 0
        for (i = 1; i <= 4; i++) if (o[i] + 0 > 255) next
        if (p > 32) next
        ip = ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4]
        if ((ip % (2 ^ (32 - p))) != 0) print $1 ":" $2 ": " c
    }' | sed "s#^$d/##" || true   # grep with no matches = clean tree, not an error
}
assert_sane_tarball() {  # assert_sane_tarball TGZ STRIP "description"
    [ -f "$1" ] || die "$1 does not exist: the code of ${3} cannot be checked"
    local t bad; t="$(mktemp -d /tmp/satom-check.XXXX)"
    tar -xzf "$1" -C "$t" --strip-components="$2" >>"$LOG" 2>&1 \
        || { rm -rf "$t"; die "Could not read $1 (incomplete download?)"; }
    bad="$(bad_network_literals "$t")"; rm -rf "$t"
    refuse_bad_network_literals "$bad" "$3"
}
assert_sane_network_literals() {  # assert_sane_network_literals DIR "description"
    refuse_bad_network_literals "$(bad_network_literals "$1")" "$2"
}
refuse_bad_network_literals() {  # refuse_bad_network_literals "$findings" "description"
    local bad="$1"
    if [ -n "$bad" ]; then
        log_raw "invalid networks in $2: $(printf '%s' "$bad" | tr '\n' ' ')"
        die "The code of ${2} carries INVALID networks (host bits set), the mark of the
       SATOM 2.1.1 public mirror cleanup. With them the application does not start,
       so it is NOT installed. First occurrences:
$(printf '%s\n' "$bad" | head -5 | sed 's/^/         /')
       Install a fixed release (2.1.2 or later)."
    fi
    ok "Code of ${2}: no invalid networks"
}

ENVF="$DOCKER_HOME/satom.env"
env_get() { [ -f "$ENVF" ] && sed -n "s/^$1=//p" "$ENVF" | tail -1 | sed "s/^'\(.*\)'\$/\1/" || true; }
env_set() {  # env_set KEY VALUE  (replaces every occurrence or appends)
    local k="$1" v="$2" tmp
    tmp="$(mktemp "$DOCKER_HOME/.env.XXXX")"
    V="$v" awk -v k="$k" 'BEGIN{done=0}
        $0 ~ "^"k"=" { if (!done) { print k"="ENVIRON["V"]; done=1 } ; next }
        { print } END { if (!done) print k"="ENVIRON["V"] }' "$ENVF" > "$tmp"
    chmod 600 "$tmp"; mv -f "$tmp" "$ENVF"
}

fetch_source() {  # fetch_source VERSION -> $DOCKER_HOME/releases/<ver>
    local v="$1" dest="$DOCKER_HOME/releases/$1" tgz
    CURRENT_STEP="3 · docker: source code v$v"
    if [ -f "$dest/Dockerfile" ]; then ok "Code v${v} already downloaded"; return; fi
    [ "$INTERNET" -eq 1 ] || die "Without Internet access I cannot download the code of v${v} (offline Docker mode is not published yet)"
    mkdir -p "$DOCKER_HOME/releases"; tgz="$(mktemp /tmp/satom-src.XXXX.tar.gz)"
    info "Downloading code v${v} from GitHub (no git)…"
    fetch -o "$tgz" "https://codeload.github.com/${GH_REPO}/tar.gz/refs/tags/v${v}" \
        || die "Release v${v} does not exist in ${GH_URL}"
    rm -rf "$dest.tmp"; mkdir -p "$dest.tmp"; tar -xzf "$tgz" -C "$dest.tmp" --strip-components=1; rm -f "$tgz"
    [ -f "$dest.tmp/Dockerfile" ] && [ -f "$dest.tmp/deploy/docker/compose.yaml" ] || die "Release v${v} does not ship the Docker stack"
    # Checked BEFORE it counts as downloaded: a rejected tree stays in .tmp and
    # the next run downloads it again instead of reusing it.
    assert_sane_network_literals "$dest.tmp" "release v${v}"
    mv "$dest.tmp" "$dest"
    ok "Code v${v} in ${dest}"
}

build_image() {  # build_image VERSION
    CURRENT_STEP="3 · docker: build image satom:$1"
    if docker image inspect "satom:$1" >/dev/null 2>&1; then ok "Image satom:$1 already exists"; return; fi
    say "Building the satom:$1 image (5–15 min the first time)"
    ( cd "$DOCKER_HOME/releases/$1" && docker build -t "satom:$1" -f Dockerfile . ) >>"$LOG" 2>&1 \
        || die "The image build failed (details at the end of ${LOG})"
    ok "Image satom:$1 built ($(docker image inspect "satom:$1" -f '{{.Size}}' | awk '{printf "%.0f MB", $1/1048576}'))"
}

write_wrapper() {
    cat > /usr/local/sbin/satom-docker <<'WRAP'
#!/usr/bin/env bash
# satom-docker — docker compose with the right files for THIS install.
# Generated by satom-setup.sh. Examples:  satom-docker ps | logs -f web | restart web
set -euo pipefail
H=/opt/satom-docker; D="$H/current/deploy/docker"
set -a; . "$H/satom.env"; set +a
f=(-f "$D/compose.yaml")
[ "${SATOM_ENV:-dev}" = prod ] && f+=(-f "$D/compose.prod.yaml")
[ "${SATOM_NODE_ROLE:-primary}" = standby ] && f+=(-f "$D/compose.standby.yaml")
[ -f "$H/compose.setup.yaml" ] && f+=(-f "$H/compose.setup.yaml")
[ "${SATOM_SETUP_AGENT:-no}" = yes ] && [ -f "$D/compose.agent.yaml" ] && f+=(-f "$D/compose.agent.yaml")
exec docker compose -p satom --project-directory "$D" "${f[@]}" --env-file "$H/satom.env" "$@"
WRAP
    chmod 755 /usr/local/sbin/satom-docker
}

write_setup_overlay() {  # the installer's own override: initial password + external DB
    local db="$1"
    {
        echo "# Generated by satom-setup.sh — do NOT edit by hand; run the installer again."
        echo "# 1) The first admin's password reaches the process through its ENVIRONMENT on first"
        echo "#    start (SATOM_SETUP_ADMIN_PW); it is never written to disk. Empty afterwards: it"
        echo "#    does not affect an admin that already exists."
        [ "$db" = external ] && {
            echo "# 2) EXTERNAL PostgreSQL: the 'postgres' service does not run a database; it stays"
            echo "#    as a health probe for the external DB so that the start order is preserved."
        }
        echo "services:"
        local s
        for s in web scheduler cron; do
            echo "  $s:"
            echo "    environment:"
            echo "      SATOM_ADMIN_PASSWORD: \${SATOM_SETUP_ADMIN_PW:-}"
            [ "$db" = external ] && echo "      SQLALCHEMY_DATABASE_URI: \${SATOM_EXT_DB_URI:?}"
            [ "$db" = external ] && { echo "    extra_hosts:"; echo "      - \"host.docker.internal:host-gateway\""; }
        done
        if [ "$db" = external ]; then
            cat <<'EXT'
  postgres:
    image: postgres:15-bookworm
    entrypoint: ["sleep"]
    command: ["infinity"]
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      EXT_HOST: ${SATOM_EXT_DB_HOST:?}
      EXT_PORT: ${SATOM_EXT_DB_PORT:-5432}
      EXT_USER: ${SATOM_EXT_DB_USER:?}
      EXT_DB: ${SATOM_EXT_DB_NAME:?}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -h \"$$EXT_HOST\" -p \"$$EXT_PORT\" -U \"$$EXT_USER\" -d \"$$EXT_DB\" -q"]
      interval: 5s
      timeout: 5s
      retries: 24
      start_period: 5s
EXT
        fi
    } > "$DOCKER_HOME/compose.setup.yaml"
    chmod 600 "$DOCKER_HOME/compose.setup.yaml"
}

test_external_db() {
    local h="$1" p="$2" d="$3" u="$4" pw="$5"
    CURRENT_STEP="3 · docker: test external DB"
    info "Testing the connection to postgresql://${u}@${h}:${p}/${d} …"
    local out
    if out="$(docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD="$pw" -e PGCONNECT_TIMEOUT=8 \
        postgres:15-bookworm psql -h "$h" -p "$p" -U "$u" -d "$d" -v ON_ERROR_STOP=1 -tAc \
        'select version(); create table satom_setup_probe(i int); drop table satom_setup_probe;' 2>&1)"; then
        ok "External DB reachable, with permission to create tables ($(printf '%s' "$out" | head -1 | cut -c1-40)…)"
    else
        die "Cannot use the external DB: $(printf '%s' "$out" | tail -2 | tr '\n' ' ')
     Check: that database '${d}' exists and is owned by '${u}', listen_addresses and pg_hba.conf
     (it must admit the Docker networks: the stack's, SATOM_NETWORK_SUBNET in ${ENVF},
     and the docker0 bridge's), and the DB server's firewall."
    fi
}

install_docker() {
    local role db="bundled" agent="no" cert="self" certf="" keyf="" chainf="" joinf="" upgrading=0
    local db_host="" db_port="" db_name="" db_user="" db_pw=""
    CURRENT_STEP="3 · docker"
    say "DOCKER install (all of SATOM in containers)"
    [ "$EXISTING" = native ] && die "This machine already runs SATOM natively: the two are not mixed on the same host (same ports). Use another machine."
    [ "$INTERNET" -eq 1 ] || die "Docker mode needs Internet access (it downloads the code and the base images). Offline Docker is not published yet."

    if [ "$EXISTING" = docker ]; then
        local ex cur; cur="$(cat "$DOCKER_HOME/current/VERSION" 2>/dev/null || echo '?')"
        ask_choice ex "SATOM Docker v${cur} is already installed. Update to v${VERSION}, or abort?" "update|abort" "update" SETUP_EXISTING
        [ "$ex" = update ] || die "Cancelled: the existing install is kept"
        upgrading=1
    fi
    ensure_docker

    if [ "$upgrading" -eq 1 ]; then
        fetch_source "$VERSION"; build_image "$VERSION"
        CURRENT_STEP="docker: update"
        ln -sfn "$DOCKER_HOME/releases/$VERSION" "$DOCKER_HOME/current"
        ln -sfn "$ENVF" "$DOCKER_HOME/current/deploy/docker/.env"
        env_set SATOM_IMAGE "satom:$VERSION"
        write_wrapper
        /usr/local/sbin/satom-docker up -d --remove-orphans >>"$LOG" 2>&1
        WEB_PORT="$(env_get SATOM_HTTPS_BIND | sed 's/.*://')"; NAMES="$(env_get SATOM_SERVED_NAMES)"
        wait_docker_healthy
        SUMMARY_MODE="docker — updated to v${VERSION}"
        SUMMARY_PW_NOTE="unchanged (the one from before the update)"
        SUMMARY_UNINSTALL="bash satom-setup.sh --uninstall   (add --purge to delete the data as well)"
        SUMMARY_LOGS="satom-docker ps   ·   satom-docker logs -f web"
        return
    fi

    ask_names_port

    say "Database"
    ask_choice db "PostgreSQL inside the stack (bundled) or one you already have (external)?" "bundled|external" "bundled" SETUP_DB
    if [ "$db" = external ]; then
        ask db_host "PostgreSQL server (localhost = this same machine)" "" SETUP_DB_HOST
        case "$db_host" in localhost|127.*|::1) db_host="host.docker.internal"
            warn "DB on this host: PostgreSQL must listen on the Docker bridge IP and pg_hba must admit the Docker networks (docker0 and SATOM_NETWORK_SUBNET)" ;; esac
        ask db_port "Port" "5432" SETUP_DB_PORT
        ask db_name "Database" "satom" SETUP_DB_NAME
        ask db_user "User" "satom" SETUP_DB_USER
        if [ -n "${SETUP_DB_PASSWORD:-}" ]; then db_pw="$SETUP_DB_PASSWORD"
        elif [ "$ASSUME_YES" -eq 1 ]; then die "--yes mode: SETUP_DB_PASSWORD is missing"
        else read -rsp "    Password for ${db_user}: " db_pw </dev/tty; echo; fi
        [[ "$db_pw" == *"'"* ]] && die "The DB password cannot contain a single quote (')"
    fi

    say "Node role"
    if [ "$db" = external ]; then
        role=standalone; info "With an external DB the role is standalone (high availability comes from your PostgreSQL)"
    else
        ask_choice role "Role?" "standalone|primary|standby" "standalone" SETUP_ROLE
    fi
    if [ "$role" = standby ]; then
        ver_ge "$COMPOSE_V" 2.24.4 || die "A standby needs Docker Compose >= 2.24.4 (you have ${COMPOSE_V}; the overlay uses '!reset'). On openSUSE: install docker-compose from Docker Inc. or use another distro for the standby."
        ask joinf "Path to the join file copied from the primary (satom-docker-join.env)" "" SETUP_JOIN_FILE
        [ -f "$joinf" ] || die "The join file does not exist: $joinf"
    fi

    say "Operations agent (update / restart / certificates from the web UI)"
    fetch_source "$VERSION"
    if [ -f "$DOCKER_HOME/releases/$VERSION/deploy/docker/compose.agent.yaml" ]; then
        info "Risk: the agent mounts /var/run/docker.sock (whoever controls it is root on the host)."
        info "The web UI only drops requests into a volume; the agent accepts a closed list of actions."
        ask_yn "Enable the agent?" n SETUP_AGENT && agent=yes
    else
        warn "SATOM v${VERSION} does not include the Docker agent yet."
        info "Without it, those 4 functions are done with 'satom-docker' (e.g. satom-docker restart web)."
        info "When a release ships it, run this script again in update mode."
        [ "${SETUP_AGENT:-no}" = yes ] && warn "SETUP_AGENT=yes ignored: not available in this version"
    fi

    say "HTTPS certificate"
    ask_choice cert "The node's own certificate (self) or import yours (import)?" "self|import" "self" SETUP_CERT
    if [ "$cert" = import ]; then
        ask certf "Certificate file (PEM)" "" SETUP_CERT_FILE; [ -f "$certf" ] || die "$certf does not exist"
        ask keyf "Private key file (PEM)" "" SETUP_KEY_FILE; [ -f "$keyf" ] || die "$keyf does not exist"
        ask chainf "Intermediate chain (empty = none)" "-" SETUP_CHAIN_FILE; [ "$chainf" = "-" ] && chainf=""
        [ -z "$chainf" ] || [ -f "$chainf" ] || die "$chainf does not exist"
        [ "$(openssl x509 -in "$certf" -noout -pubkey | openssl sha256)" = "$(openssl pkey -in "$keyf" -pubout | openssl sha256)" ] \
            || die "The certificate and the key do NOT match"
        ok "Certificate and key match (CN=$(openssl x509 -in "$certf" -noout -subject | sed 's/.*CN *= *//'))"
    fi

    [ "$role" = standby ] || ask_admin_password

    say "Summary before installing"
    info "Docker · v${VERSION} · DB ${db} · role ${role} · agent ${agent} · cert ${cert}"
    info "Console: https://$(echo "$NAMES" | awk '{print $1}')$([ "$WEB_PORT" = 443 ] || echo ":$WEB_PORT")/   (IP ${NODE_IP})"
    [ "$ASSUME_YES" -eq 1 ] || ask_yn "Continue?" y || die "Cancelled by the user"

    # ── Installation ─────────────────────────────────────────────────────────
    build_image "$VERSION"
    CURRENT_STEP="docker: configuration"
    mkdir -p "$DOCKER_HOME"; chmod 700 "$DOCKER_HOME"
    ln -sfn "$DOCKER_HOME/releases/$VERSION" "$DOCKER_HOME/current"
    local D="$DOCKER_HOME/current/deploy/docker"
    if [ ! -f "$ENVF" ]; then
        cp "$D/env.example" "$ENVF"; chmod 600 "$ENVF"
        env_set SECRET_KEY "$(rand_hex 32)"
        env_set FERNET_KEY "$(openssl rand 32 | base64 | tr '+/' '-_')"
        env_set POSTGRES_PASSWORD "$(rand_hex 24)"
        env_set SATOM_REPL_PASSWORD "$(rand_hex 24)"
        ok "Secrets generated in ${ENVF} (0600)"
    else
        ok "Reusing the existing secrets in ${ENVF} (they are never regenerated)"
    fi
    if [ "$role" = standby ]; then
        local k
        for k in SECRET_KEY FERNET_KEY POSTGRES_USER POSTGRES_DB POSTGRES_PASSWORD SATOM_REPL_USER SATOM_REPL_PASSWORD SATOM_PRIMARY_HOST SATOM_PRIMARY_PORT; do
            local v; v="$(sed -n "s/^$k=//p" "$joinf" | tail -1)"
            [ -n "$v" ] || [ "$k" = SATOM_PRIMARY_PORT ] || die "The join file does not contain $k"
            [ -n "$v" ] && env_set "$k" "$v"
        done
        ok "The primary's secrets and settings imported from the join file"
    fi
    env_set SATOM_ENV prod
    env_set SATOM_NODE_ROLE "$([ "$role" = standby ] && echo standby || echo primary)"
    env_set SATOM_IMAGE "satom:$VERSION"
    env_set SATOM_SERVED_NAMES "'$NAMES'"
    env_set SATOM_HTTPS_BIND "0.0.0.0:$WEB_PORT"
    env_set SATOM_REDIRECT_BIND "0.0.0.0:80"
    env_set TZ "$(timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"
    env_set SATOM_SETUP_AGENT "$agent"
    case "$role" in
        primary) env_set SATOM_PG_BIND "${NODE_IP}:5432" ;;
        *)       env_set SATOM_PG_BIND "127.0.0.1:$([ "$db" = external ] && echo 55432 || echo 5432)" ;;
    esac
    if [ "$db" = external ]; then
        env_set SATOM_EXT_DB_HOST "$db_host"; env_set SATOM_EXT_DB_PORT "$db_port"
        env_set SATOM_EXT_DB_NAME "$db_name"; env_set SATOM_EXT_DB_USER "$db_user"
        env_set SATOM_EXT_DB_URI "'postgresql+psycopg://$(urlencode "$db_user"):$(urlencode "$db_pw")@${db_host}:${db_port}/$(urlencode "$db_name")'"
    fi
    ln -sfn "$ENVF" "$D/.env"
    write_setup_overlay "$db"
    write_wrapper
    /usr/local/sbin/satom-docker config -q >>"$LOG" 2>&1 || die "The Compose configuration is not valid (details in ${LOG})"
    ok "Configuration validated (docker compose config)"

    [ "$db" = external ] && test_external_db "$db_host" "$db_port" "$db_name" "$db_user" "$db_pw"

    CURRENT_STEP="docker: pull base images"
    info "Downloading base images (postgres, redis, victoria-metrics, nginx)…"
    # Base images only: 'compose pull' would also try to fetch satom:<ver> from
    # Docker Hub, which is a LOCAL image and must not be replaced by a foreign one.
    local img
    for img in $(/usr/local/sbin/satom-docker config --images 2>>"$LOG" | sort -u | grep -v '^satom:'); do
        docker pull -q "$img" >>"$LOG" 2>&1 || die "Could not download base image $img"
    done
    ok "Base images downloaded"

    if [ "$cert" = import ]; then
        CURRENT_STEP="docker: import certificate"
        local tmpd; tmpd="$(mktemp -d)"; cp "$certf" "$tmpd/cert.pem"; cp "$keyf" "$tmpd/key.pem"
        [ -n "$chainf" ] && cp "$chainf" "$tmpd/chain.pem"
        chmod 644 "$tmpd"/*.pem
        /usr/local/sbin/satom-docker run --rm --no-deps -v "$tmpd:/import:ro" --entrypoint /opt/satom/deploy/tls-bootstrap.sh \
            tls-init import-cert --cert /import/cert.pem --key /import/key.pem \
            $([ -n "$chainf" ] && echo "--chain /import/chain.pem") --pki /opt/satom/pki >>"$LOG" 2>&1 \
            || { rm -rf "$tmpd"; die "Could not import the certificate (details in ${LOG})"; }
        rm -rf "$tmpd"; ok "Certificate imported into the satom-pki volume"
    fi

    CURRENT_STEP="docker: start the stack"
    say "Starting the stack"
    SATOM_SETUP_ADMIN_PW="$ADMIN_PW" /usr/local/sbin/satom-docker up -d >>"$LOG" 2>&1 \
        || die "docker compose up failed (details in ${LOG}; status: satom-docker ps)"
    wait_docker_healthy

    if [ "$role" != standby ]; then
        CURRENT_STEP="docker: check admin"
        # The password goes through stdin: with 'exec -e' it would show in the process list.
        if printf '%s\n' "$ADMIN_PW" | /usr/local/sbin/satom-docker exec -T web python -c '
import sys, logging; logging.disable(logging.CRITICAL)
pw = sys.stdin.readline().rstrip("\n")
from app import create_app
from app.models import User
a = create_app()
with a.app_context():
    u = User.query.filter_by(username="admin").first()
    raise SystemExit(0 if u and u.check_password(pw) else 3)' >>"$LOG" 2>&1; then
            ok "User 'admin' created and the chosen password works"
        else
            warn "Could not confirm the admin password (did the DB already have users from a previous install?)"
        fi
    fi

    if [ "$role" = primary ]; then
        local jf=/root/satom-docker-join.env
        ( umask 077; {
            echo "# SATOM Docker join file — copy it to the standby (scp) and delete it afterwards."
            for k in SECRET_KEY FERNET_KEY POSTGRES_USER POSTGRES_DB POSTGRES_PASSWORD SATOM_REPL_USER SATOM_REPL_PASSWORD; do
                echo "$k=$(env_get "$k")"; done
            echo "SATOM_PRIMARY_HOST=${NODE_IP}"; echo "SATOM_PRIMARY_PORT=5432"
        } > "$jf" )
        ok "Join file for the standby: ${jf} (0600)"
        open_firewall 80 "$WEB_PORT" 5432
    else
        open_firewall 80 "$WEB_PORT"
    fi

    touch "$DOCKER_HOME/.installed"
    SUMMARY_MODE="docker (${role}, DB ${db}, agent ${agent})"
    SUMMARY_UNINSTALL="bash satom-setup.sh --uninstall   (add --purge to delete the data as well)"
    SUMMARY_LOGS="satom-docker ps   ·   satom-docker logs -f web"
}

wait_docker_healthy() {
    CURRENT_STEP="docker: wait for health"
    info "Waiting for the console to answer (first start creates the DB, 1–3 min)…"
    local t=0 code=""
    while :; do
        code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "https://127.0.0.1:${WEB_PORT}/healthz" || true)"
        [ "$code" = 200 ] && break
        t=$((t+5))
        if [ "$t" -ge 420 ]; then
            /usr/local/sbin/satom-docker ps 2>&1 | tee -a "$LOG"
            /usr/local/sbin/satom-docker logs --tail=40 web 2>&1 | tee -a "$LOG"
            die "The console did not answer within 7 min (last code: ${code:-no answer})"
        fi
        sleep 5
    done
    ok "healthz 200 at https://127.0.0.1:${WEB_PORT}/healthz"
    local bad; bad="$(/usr/local/sbin/satom-docker ps --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null | awk '$2!="running" || $3=="unhealthy"' || true)"
    [ -z "$bad" ] && ok "All containers running" || warn "Containers with problems: ${bad}"
}

uninstall_docker() {
    CURRENT_STEP="uninstall"
    [ -f "$ENVF" ] || die "There is no SATOM Docker install in ${DOCKER_HOME}"
    [ -x /usr/local/sbin/satom-docker ] || write_wrapper
    say "Uninstall SATOM Docker"
    if [ "$PURGE" -eq 1 ]; then
        warn "--purge DELETES the database, the device vault and the certificates. There is no way back."
        local c=""; [ "$ASSUME_YES" -eq 1 ] && c=DELETE || { read -rp "    Type DELETE to confirm: " c </dev/tty; }
        [ "$c" = DELETE ] || die "Cancelled"
        /usr/local/sbin/satom-docker down -v --remove-orphans >>"$LOG" 2>&1
        rm -rf "$DOCKER_HOME" /usr/local/sbin/satom-docker
        docker image ls --format '{{.Repository}}:{{.Tag}}' | grep '^satom:' | xargs -r docker image rm >>"$LOG" 2>&1 || true
        ok "Containers, volumes, satom:* images and ${DOCKER_HOME} removed"
    else
        /usr/local/sbin/satom-docker down --remove-orphans >>"$LOG" 2>&1
        ok "Containers stopped and removed. Data KEPT (satom_* volumes and ${ENVF})."
        info "To bring it back up: satom-docker up -d  ·  to delete everything: --uninstall --purge"
    fi
    exit 0
}

# ═════════════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════════════
SUMMARY_MODE=""; SUMMARY_UNINSTALL=""; SUMMARY_LOGS=""

echo "${c_b}SATOM ${SETUP_VERSION} — guided installer${c_0}   (log: ${LOG})"
[ "$UNINSTALL" -eq 1 ] && uninstall_docker

detect_os
check_requirements
resolve_version
detect_existing

if [ "$CHECK_ONLY" -eq 1 ]; then
    say "Check only (--check): nothing has been installed."
    exit 0
fi

CURRENT_STEP="3 · mode"
say "Step 3 · Install type"
info "native : SATOM directly on this machine (systemd). One-click updates from the web UI."
info "docker : SATOM in containers. Updated by running this script again."
DEF_MODE=native; [ "$EXISTING" = docker ] && DEF_MODE=docker
ask_choice MODE "Native or Docker?" "native|docker" "$DEF_MODE" SETUP_MODE
[ "$MODE" = native ] || [ -n "$VERSION" ] || die "No known version (no Internet access): use --version"

if [ "$MODE" = native ]; then install_native; else install_docker; fi

# ─────────────────────────────────────────────────────────────────────────────
# Final summary
# ─────────────────────────────────────────────────────────────────────────────
CURRENT_STEP="summary"
FIRST_NAME="$(echo "$NAMES" | awk '{print $1}')"
PORT_SFX="$([ "$WEB_PORT" = 443 ] || echo ":$WEB_PORT")"
SUMMARY="/root/satom-setup-summary.txt"
{
    echo "SATOM ${VERSION} installed — $(date '+%F %T')"
    echo "  Mode ............ ${SUMMARY_MODE}"
    echo "  Console ......... https://${FIRST_NAME}${PORT_SFX}/   (or https://${NODE_IP}${PORT_SFX}/)"
    echo "  User ............ admin"
    if [ -n "${SUMMARY_PW_NOTE:-}" ]; then
        echo "  Password ........ ${SUMMARY_PW_NOTE}"
    elif [ "$ADMIN_PW_GENERATED" -eq 1 ]; then
        echo "  Password ........ in ${ADMIN_PW_FILE} (0600) — change it at first login and delete the file"
    elif [ -n "$ADMIN_PW" ]; then
        echo "  Password ........ the one you typed during the install"
    else
        echo "  Password ........ the primary's (it is replicated)"
    fi
    echo "  Install log ..... ${LOG}"
    echo "  Logs / status ... ${SUMMARY_LOGS}"
    [ "$MODE" = docker ] && echo "  Secrets ......... ${ENVF}  ← BACK IT UP (FERNET_KEY cannot be regenerated)"
    echo "  Uninstall ....... ${SUMMARY_UNINSTALL}"
    echo "  If the name ${FIRST_NAME} does not resolve yet, create it in your DNS pointing to ${NODE_IP}."
} | tee "$SUMMARY"
chmod 600 "$SUMMARY"
echo
echo "${c_g}${c_b}Installation finished.${c_0} Summary saved to ${SUMMARY}"
log_raw "END OK"
