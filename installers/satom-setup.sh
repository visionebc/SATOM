#!/usr/bin/env bash
# ============================================================================
# satom-setup.sh — Instalador guiado de SATOM (nativo o Docker)
#
#   Descarga:  https://github.com/visionebc/SATOM/releases/download/v<versión>/satom-setup.sh
#              (también en cada paquete offline, junto a install-satom.sh)
#   Instala LA RELEASE CON LA QUE SE PUBLICA (SETUP_VERSION, abajo); otra con
#   --version X.Y.Z. Ver docs/INSTALL.md §2 (guided install).
#   Uso:       sudo bash satom-setup.sh              (interactivo)
#              sudo bash satom-setup.sh --check      (solo comprobaciones)
#              sudo bash satom-setup.sh --yes --answers respuestas.env
#              sudo bash satom-setup.sh --uninstall  (solo instalación Docker)
#
# FLUJO
#   1. Sistema operativo + requisitos (CPU, RAM, disco, puertos, Internet).
#   2. ¿Ya hay una instalación? (nativa o Docker) -> actualizar / reinstalar.
#   3. Nativo o Docker.
#      Nativo : usa el install-satom.sh OFICIAL de la release (online) o el
#               paquete offline de tu distro; este script le contesta las
#               preguntas, así que se pregunta todo UNA vez y aquí. Ejecutado
#               DENTRO de un paquete offline (satom-installer/), usa el
#               install-satom.sh de al lado y no descarga nada.
#      Docker : instala Docker + Compose si faltan, construye la imagen desde
#               el código publicado de la release y levanta el stack.
#               - Base de datos en el mismo stack, o PostgreSQL externo.
#               - Rol: standalone / primary / standby.
#               - Agente de operaciones (si la release lo trae).
#   4. Nombre DNS + certificado (propio del nodo, o importado).
#   5. Clave del admin (se pide y se valida; si se deja vacía se genera y se
#      guarda en un fichero 0600 — nunca hay clave por defecto).
#   6. Cortafuegos (firewalld/ufw) y SELinux.
#   7. Resumen: URL, dónde está la clave, log y cómo desinstalar.
#
# MODO SIN PREGUNTAS (--yes): cada pregunta toma su valor de una variable
# SETUP_* (del entorno o del fichero --answers). Lista en --help.
# ============================================================================
set -Eeuo pipefail

# La release que este script instala: la misma con la que se publica. La
# estampa deploy/stamp_site_assets.py desde VERSION al cortar la versión (igual
# que el VERSION de install-satom.sh) y el pipeline de release se niega a
# publicar si no coincide. DEBE ser la primera línea ^(SATOM_|SETUP_)?VERSION=.
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

CURRENT_STEP="inicio"
on_error() {
    local rc=$?
    echo
    echo "${c_r}La instalación se detuvo en el paso: ${CURRENT_STEP} (código ${rc}).${c_0}" >&2
    echo "  Log completo: ${LOG}" >&2
    echo "  Puedes volver a ejecutar este script: retoma sin borrar lo ya hecho" >&2
    echo "  (los secretos ya generados se conservan)." >&2
    log_raw "FALLO en paso '${CURRENT_STEP}' rc=${rc}"
    exit "$rc"
}
trap on_error ERR

usage() {
    cat <<'EOF'
satom-setup.sh — instalador guiado de SATOM (nativo o Docker)

Opciones:
  --check              Solo comprobaciones de sistema; no instala nada.
  --yes                Sin preguntas: usa variables SETUP_* / valores por defecto.
  --answers FICHERO    Fichero KEY=VALOR con las respuestas (implica nada; combínalo con --yes).
  --version X.Y.Z      Versión de SATOM (por defecto: la de este script, SETUP_VERSION;
                       'latest' = la última release publicada en GitHub).
  --bundle FICHERO     Paquete offline nativo (satom-offline-<ver>-<distro>.tar.gz).
                       Ejecutado desde dentro de un paquete ya extraído
                       (satom-installer/, con bundle/ al lado) no hace falta.
  --force              Continuar aunque la distro no esté soportada.
  --uninstall          Desinstalar la instalación Docker (conserva los datos).
  --purge              Con --uninstall: borra TAMBIÉN los volúmenes (datos). Irreversible.
  -h, --help           Esta ayuda.

Variables para --yes (todas opcionales salvo donde se indique):
  SETUP_MODE=native|docker            (obligatoria con --yes)
  SETUP_SOURCE=online|offline         (nativo; offline requiere --bundle, el .tar.gz al lado
                                       o ejecutar desde dentro del paquete extraído)
  SETUP_GIT_URL                       (nativo online: repo a clonar; vacío = el público.
                                       Otro repo = sin comprobación previa del código)
  SETUP_ROLE=standalone|primary|secondary   (nativo)  | standalone|primary|standby (docker)
  SETUP_IP, SETUP_PORT (443), SETUP_NAMES ("fqdn otro-nombre")
  SATOM_ADMIN_PASSWORD                (vacía = se genera y se guarda en fichero 0600)
  SETUP_DB=bundled|external           (docker)
  SETUP_DB_HOST, SETUP_DB_PORT (5432), SETUP_DB_NAME (satom), SETUP_DB_USER (satom), SETUP_DB_PASSWORD
  SETUP_AGENT=yes|no                  (docker; solo si la release trae el agente)
  SETUP_CERT=self|import, SETUP_CERT_FILE, SETUP_KEY_FILE, SETUP_CHAIN_FILE
  SETUP_FIREWALL=yes|no               (abrir puertos si hay firewalld/ufw activo)
  SETUP_INSTALL_DOCKER=yes|no         (instalar Docker si falta)
  SETUP_JOIN_KEY                      (nativo secondary: la clave de unión del primary)
  SETUP_SECONDARY_IP                  (nativo primary)
  SETUP_JOIN_FILE                     (docker standby: fichero de unión generado en el primary)
  SETUP_EXISTING=update|reinstall|abort   (si ya hay una instalación)
EOF
}

# ─────────────────────────────────────────────────────────────────────────────
# Argumentos
# ─────────────────────────────────────────────────────────────────────────────
ASSUME_YES=0; CHECK_ONLY=0; FORCE=0; UNINSTALL=0; PURGE=0
WANT_VERSION=""; BUNDLE_FILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK_ONLY=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --answers) shift; [ -f "${1:-}" ] || die "--answers: no existe '${1:-}'"
                   set -a; . "$1"; set +a ;;
        --version) shift; WANT_VERSION="${1#v}" ;;
        --bundle) shift; BUNDLE_FILE="${1:-}" ;;
        --force) FORCE=1 ;;
        --uninstall) UNINSTALL=1 ;;
        --purge) PURGE=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "Opción desconocida: $1 (usa --help)" ;;
    esac
    shift
done

[ "$(id -u)" -eq 0 ] || die "Ejecuta como root: sudo bash $0"
mkdir -p "$(dirname "$LOG")"; touch "$LOG"; chmod 600 "$LOG"
log_raw "===== satom-setup ${SETUP_VERSION} — $(date -u +%FT%TZ) ====="

# ─────────────────────────────────────────────────────────────────────────────
# Preguntas. Con --yes cada una lee su variable SETUP_*; sin valor usa el
# valor por defecto; si tampoco lo hay, se detiene y dice qué variable falta.
# ─────────────────────────────────────────────────────────────────────────────
# ask VAR "pregunta" "defecto" [PRESET_VAR]
ask() {
    local __var="$1" __q="$2" __def="${3:-}" __pre="${4:-}" __ans=""
    if [ -n "$__pre" ] && [ -n "${!__pre:-}" ]; then
        __ans="${!__pre}"; info "$__q ${__ans} (de ${__pre})"
    elif [ "$ASSUME_YES" -eq 1 ]; then
        [ -n "$__def" ] || die "Modo --yes: falta ${__pre:-la respuesta} para: $__q"
        __ans="$__def"; info "$__q ${__ans} (por defecto)"
    else
        read -rp "    ${__q}${__def:+ [${__def}]}: " __ans </dev/tty || die "Entrada cerrada en: $__q"
        __ans="${__ans:-$__def}"
    fi
    printf -v "$__var" '%s' "$__ans"
    case "$__var" in join|*pw*|*PW*) log_raw "Q: $__q -> ***" ;; *) log_raw "Q: $__q -> $__ans" ;; esac
}
# ask_choice VAR "pregunta" "op1|op2|op3" "defecto" [PRESET_VAR]
ask_choice() {
    local __var="$1" __q="$2" __opts="$3" __def="$4" __pre="${5:-}" __a
    while :; do
        ask __a "$__q (${__opts//|/\/})" "$__def" "$__pre"
        __a="$(printf '%s' "$__a" | tr 'A-Z' 'a-z')"
        case "|$__opts|" in *"|$__a|"*) printf -v "$__var" '%s' "$__a"; return ;; esac
        [ "$ASSUME_YES" -eq 1 ] || [ -n "$__pre" -a -n "${!__pre:-}" ] && die "Valor no válido '$__a' para: $__q (opciones: $__opts)"
        warn "Opciones válidas: ${__opts//|/, }"
    done
}
ask_yn() {  # ask_yn "pregunta" s|n [PRESET_VAR] -> rc 0 = sí
    local __a; ask __a "$1 (s/n)" "$2" "${3:-}"
    case "$(printf '%s' "$__a" | tr 'A-Z' 'a-z')" in s|si|sí|y|yes|1|true) return 0 ;; *) return 1 ;; esac
}

# ─────────────────────────────────────────────────────────────────────────────
# Utilidades
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
installer_version() {  # installer_version FICHERO -> el VERSION="x.y.z" de primer nivel
    sed -n 's/^VERSION="\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -1
}
fetch() { curl -fsSL --retry 3 --connect-timeout 15 "$@"; }

password_ok() {  # >=10 caracteres y al menos 3 de: minúsculas, mayúsculas, dígitos, símbolos
    local p="$1" n=0
    [ "${#p}" -ge 10 ] || { warn "Mínimo 10 caracteres."; return 1; }
    [[ "$p" =~ [a-z] ]] && n=$((n+1)); [[ "$p" =~ [A-Z] ]] && n=$((n+1))
    [[ "$p" =~ [0-9] ]] && n=$((n+1)); [[ "$p" =~ [^a-zA-Z0-9] ]] && n=$((n+1))
    [ "$n" -ge 3 ] || { warn "Usa al menos 3 tipos: minúsculas, mayúsculas, números, símbolos."; return 1; }
    [[ "$p" == *"'"* ]] && { warn "La comilla simple (') no está permitida."; return 1; }
    return 0
}

ADMIN_PW=""; ADMIN_PW_GENERATED=0; ADMIN_PW_FILE="/root/satom-admin-password.txt"
ask_admin_password() {
    say "Clave del usuario 'admin'"
    if [ -n "${SATOM_ADMIN_PASSWORD:-}" ]; then
        password_ok "$SATOM_ADMIN_PASSWORD" || die "SATOM_ADMIN_PASSWORD no cumple la política"
        ADMIN_PW="$SATOM_ADMIN_PASSWORD"; ok "Clave tomada de SATOM_ADMIN_PASSWORD"; return
    fi
    if [ "$ASSUME_YES" -eq 0 ]; then
        info "Enter vacío = generar una clave aleatoria y guardarla en ${ADMIN_PW_FILE} (0600)."
        local a b
        while :; do
            read -rsp "    Clave para 'admin': " a </dev/tty; echo
            [ -z "$a" ] && break
            password_ok "$a" || continue
            read -rsp "    Repite la clave: " b </dev/tty; echo
            [ "$a" = "$b" ] || { warn "No coinciden."; continue; }
            ADMIN_PW="$a"; ok "Clave aceptada"; return
        done
    fi
    ADMIN_PW="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)Aa1!"
    ADMIN_PW_GENERATED=1
    ( umask 077; printf '%s\n' "$ADMIN_PW" > "$ADMIN_PW_FILE" )
    ok "Clave generada y guardada en ${ADMIN_PW_FILE} (solo root puede leerla)"
}

# ─────────────────────────────────────────────────────────────────────────────
# PASO 1 — Sistema operativo y requisitos
# ─────────────────────────────────────────────────────────────────────────────
OS_ID=""; OS_VER=""; OS_NAME=""; OS_FAMILY=""; OS_BUNDLE=""; PKG=""
detect_os() {
    CURRENT_STEP="1 · sistema operativo"
    say "Paso 1 · Sistema operativo y requisitos"
    [ -r /etc/os-release ] || die "No existe /etc/os-release: distribución no reconocible"
    # En un SUBSHELL: os-release define VERSION (p.ej. "15.6") y NAME, y
    # cargarlo aquí pisaba la versión de SATOM a instalar.
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
        yes)  ok "Sistema: ${OS_NAME} (familia ${OS_FAMILY}) — soportado" ;;
        warn) warn "Sistema: ${OS_NAME} — no está en la lista probada; debería funcionar" ;;
        *)    if [ "$FORCE" -eq 1 ]; then warn "Sistema: ${OS_NAME} — NO soportado (sigo por --force)"
              else die "Sistema ${OS_NAME} no soportado. Soportados: Debian 12/13, Ubuntu 22.04/24.04, RHEL/Rocky/Alma 9, openSUSE Leap/SLES 15. (--force para intentarlo)"; fi ;;
    esac
    [ "$(uname -m)" = "x86_64" ] || warn "Arquitectura $(uname -m): los paquetes offline son solo x86_64"
    have systemctl && [ -d /run/systemd/system ] || die "Hace falta systemd (no se detecta como init)"
    ok "systemd presente"
}

NODE_IP=""; INTERNET=0
check_requirements() {
    CURRENT_STEP="1 · requisitos"
    local cores mem_mb disk_mb
    cores=$(nproc 2>/dev/null || echo 1)
    mem_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
    disk_mb=$(df -Pm / | awk 'NR==2{print $4}')
    [ "$cores" -ge 2 ] && ok "CPU: ${cores} núcleos" || warn "CPU: ${cores} núcleo(s) — se recomiendan 2 o más"
    if   [ "$mem_mb" -ge 3800 ]; then ok "RAM: ${mem_mb} MB"
    elif [ "$mem_mb" -ge 1900 ]; then warn "RAM: ${mem_mb} MB — mínimo 4 GB recomendado (Docker usa más)"
    else die "RAM: ${mem_mb} MB — insuficiente (mínimo 2 GB, recomendado 4 GB)"; fi
    if   [ "$disk_mb" -ge 15000 ]; then ok "Disco libre en /: $((disk_mb/1024)) GB"
    elif [ "$disk_mb" -ge 8000 ];  then warn "Disco libre en /: $((disk_mb/1024)) GB — Docker necesita ~15 GB"
    else die "Disco libre en /: ${disk_mb} MB — insuficiente (mínimo 8 GB)"; fi
    have curl || die "Falta curl (instálalo con el gestor de paquetes: ${PKG} install curl)"
    have openssl || die "Falta openssl (${PKG} install openssl)"
    have tar || die "Falta tar"
    NODE_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)"
    [ -n "$NODE_IP" ] || NODE_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    ok "IP principal: ${NODE_IP:-desconocida}"
    local p o
    for p in 80 443; do
        o="$(port_owner "$p")"
        if [ -z "$o" ]; then ok "Puerto ${p} libre"; else warn "Puerto ${p} ocupado por: ${o}"; fi
    done
    if curl -fsS -o /dev/null --connect-timeout 8 "${GH_URL}"; then
        INTERNET=1; ok "Salida a Internet (github.com) OK"
    else
        warn "Sin acceso a github.com — solo será posible la instalación nativa OFFLINE"
    fi
    if have getenforce; then info "SELinux: $(getenforce 2>/dev/null)"; fi
    if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then info "Cortafuegos: firewalld activo"
    elif have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then info "Cortafuegos: ufw activo"
    else info "Cortafuegos: ninguno activo"; fi
}

# Versión a instalar: la de este script salvo --version. Fijada a propósito:
# "la última publicada" hacía que el mismo script instalase cosas distintas
# según el día, y que un paquete offline preguntase a GitHub qué contiene.
# Se asigna AQUÍ y no arriba: nada anterior puede pisarla.
VERSION=""
resolve_version() {
    CURRENT_STEP="1 · versión"
    VERSION="$SETUP_VERSION"
    if [ "$WANT_VERSION" = latest ]; then
        [ "$INTERNET" -eq 1 ] || die "--version latest necesita Internet (o indica la versión: --version X.Y.Z)"
        VERSION="$(curl -fsSI -o /dev/null -w '%{redirect_url}' "${GH_URL}/releases/latest" | sed -n 's|.*/tag/v\{0,1\}\([^/]*\)$|\1|p')"
        [ -n "$VERSION" ] || die "No pude averiguar la última versión publicada (usa --version X.Y.Z)"
    elif [ -n "$WANT_VERSION" ]; then
        VERSION="$WANT_VERSION"
    fi
    [[ "$VERSION" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "Versión inválida: '${VERSION}' (formato X.Y.Z)"
    if [ "$VERSION" = "$SETUP_VERSION" ]; then
        ok "Versión de SATOM a instalar: ${VERSION} (la de este instalador)"
    else
        warn "Versión de SATOM a instalar: ${VERSION} — distinta de la de este instalador (${SETUP_VERSION})"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# PASO 2 — ¿Ya hay una instalación?
# ─────────────────────────────────────────────────────────────────────────────
EXISTING=""   # native | docker | ""
detect_existing() {
    CURRENT_STEP="2 · instalación existente"
    say "Paso 2 · Instalaciones existentes"
    if systemctl list-unit-files satom.service >/dev/null 2>&1 && systemctl cat satom.service >/dev/null 2>&1; then
        EXISTING=native
        warn "Hay una instalación NATIVA ($(systemctl is-active satom.service 2>/dev/null || true)) — versión $(cat "$NATIVE_DIR/VERSION" 2>/dev/null || echo '?')"
    elif [ -f "$DOCKER_HOME/.installed" ]; then
        EXISTING=docker
        warn "Hay una instalación DOCKER en ${DOCKER_HOME} — versión $(cat "$DOCKER_HOME/current/VERSION" 2>/dev/null || echo '?')"
    elif [ -f "$DOCKER_HOME/satom.env" ]; then
        warn "Hay una instalación Docker A MEDIAS en ${DOCKER_HOME} (un intento anterior falló): se retomará con sus secretos"
    else
        ok "No hay ninguna instalación de SATOM en esta máquina"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Cortafuegos
# ─────────────────────────────────────────────────────────────────────────────
open_firewall() {  # open_firewall puerto...
    local p
    if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        ask_yn "firewalld está activo. ¿Abrir los puertos $*/tcp?" s SETUP_FIREWALL || { warn "Puertos NO abiertos: ábrelos tú o la consola no será accesible"; return; }
        for p in "$@"; do firewall-cmd --permanent --add-port="${p}/tcp" >>"$LOG" 2>&1 || true; done
        firewall-cmd --reload >>"$LOG" 2>&1 || true
        ok "firewalld: abiertos $*/tcp"
    elif have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then
        ask_yn "ufw está activo. ¿Abrir los puertos $*/tcp?" s SETUP_FIREWALL || { warn "Puertos NO abiertos"; return; }
        for p in "$@"; do ufw allow "${p}/tcp" >>"$LOG" 2>&1 || true; done
        ok "ufw: abiertos $*/tcp"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Nombre DNS y puerto (comunes a los dos modos)
# ─────────────────────────────────────────────────────────────────────────────
NAMES=""; WEB_PORT=443
ask_names_port() {
    say "Nombre y puerto de la consola"
    local def_names; def_names="$(hostname -f 2>/dev/null || hostname)"
    ask NAMES "Nombre(s) DNS con los que se abrirá la consola (separados por espacio)" "$def_names" SETUP_NAMES
    NAMES="$(printf '%s' "$NAMES" | tr ',;A-Z' '  a-z' | xargs)"
    local n; for n in $NAMES; do [[ "$n" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || die "Nombre DNS inválido: $n"; done
    ask NODE_IP "IP de esta máquina" "$NODE_IP" SETUP_IP
    [[ "$NODE_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "IP inválida: $NODE_IP"
    while :; do
        ask WEB_PORT "Puerto HTTPS" "443" SETUP_PORT
        [[ "$WEB_PORT" =~ ^[0-9]+$ ]] && [ "$WEB_PORT" -ge 1 ] && [ "$WEB_PORT" -le 65535 ] || { warn "Puerto inválido"; [ "$ASSUME_YES" -eq 1 ] && die "SETUP_PORT inválido"; continue; }
        local o; o="$(port_owner "$WEB_PORT")"
        if [ -n "$o" ] && [ "$o" != "nginx" ] && [ "$o" != "docker-proxy" ]; then
            warn "El puerto ${WEB_PORT} lo usa '${o}'. Elige otro o para ese servicio."
            [ "$ASSUME_YES" -eq 1 ] && die "Puerto ${WEB_PORT} ocupado por ${o}"
            continue
        fi
        break
    done
}

# ═════════════════════════════════════════════════════════════════════════════
# INSTALACIÓN NATIVA
# ═════════════════════════════════════════════════════════════════════════════
install_native() {
    local src role join="" sec_ip="" work installer bundle=""
    CURRENT_STEP="3 · nativo: origen"
    say "Instalación NATIVA (systemd + PostgreSQL + nginx en esta máquina)"
    [ "$EXISTING" = docker ] && die "Esta máquina ya tiene SATOM en Docker. Desinstálalo primero (--uninstall) o usa otra máquina."

    # ¿Hay un install-satom.sh AL LADO de este script y es de la versión a
    # instalar? Es el caso de un paquete offline ya extraído (satom-installer/,
    # con bundle/ al lado) y el de installers/ en una copia del código. Entonces
    # se usa ése y no se descarga nada: es el que viene con este script.
    local sibling="" in_bundle=0
    if [ -f "$SCRIPT_DIR/install-satom.sh" ]; then
        if [ "$(installer_version "$SCRIPT_DIR/install-satom.sh")" = "$VERSION" ]; then
            sibling="$SCRIPT_DIR/install-satom.sh"
            [ -f "$SCRIPT_DIR/bundle/app.tar.gz" ] && in_bundle=1
        else
            warn "El install-satom.sh de al lado no es de la versión ${VERSION}: no se usa"
        fi
    fi

    # Origen: online o paquete offline
    if [ "$in_bundle" -eq 0 ] && [ -z "$BUNDLE_FILE" ] && [ -n "$OS_BUNDLE" ]; then
        local cand; cand="$(ls -1 "$SCRIPT_DIR"/satom-offline-*-"${OS_BUNDLE}".tar.gz 2>/dev/null | sort -V | tail -1 || true)"
        [ -n "$cand" ] && BUNDLE_FILE="$cand"
    fi
    local def_src=online; { [ "$INTERNET" -eq 0 ] || [ "$in_bundle" -eq 1 ]; } && def_src=offline
    [ "$in_bundle" -eq 1 ] && info "Ejecutado desde un paquete offline: se usa su install-satom.sh (${SCRIPT_DIR})"
    ask_choice src "¿Origen de la instalación?" "online|offline" "$def_src" SETUP_SOURCE
    if [ "$src" = offline ] && [ "$in_bundle" -eq 1 ]; then
        ok "Paquete offline: ${SCRIPT_DIR}/bundle"
    elif [ "$src" = offline ]; then
        if [ -z "$BUNDLE_FILE" ]; then
            [ -n "$OS_BUNDLE" ] || die "No hay paquete offline para ${OS_NAME}. Usa el modo online."
            if [ "$INTERNET" -eq 1 ] && [ -n "$VERSION" ]; then
                BUNDLE_FILE="$SCRIPT_DIR/satom-offline-${VERSION}-${OS_BUNDLE}.tar.gz"
                info "Descargando paquete offline ${OS_BUNDLE} de la release v${VERSION}…"
                fetch -o "$BUNDLE_FILE" "${GH_URL}/releases/download/v${VERSION}/$(basename "$BUNDLE_FILE")"
                fetch -o "${BUNDLE_FILE}.sha256" "${GH_URL}/releases/download/v${VERSION}/$(basename "$BUNDLE_FILE").sha256"
            else
                die "Modo offline: copia satom-offline-<versión>-${OS_BUNDLE}.tar.gz junto a este script o usa --bundle RUTA"
            fi
        fi
        [ -f "$BUNDLE_FILE" ] || die "No existe el paquete: $BUNDLE_FILE"
        case "$BUNDLE_FILE" in *"$OS_BUNDLE"*) : ;; *) warn "El paquete no parece ser para ${OS_BUNDLE}: $(basename "$BUNDLE_FILE")" ;; esac
        if [ -f "${BUNDLE_FILE}.sha256" ]; then
            ( cd "$(dirname "$BUNDLE_FILE")" && sha256sum -c "$(basename "$BUNDLE_FILE").sha256" >>"$LOG" 2>&1 ) \
                || die "La suma SHA-256 del paquete NO coincide: descarga incompleta o manipulada"
            ok "Paquete verificado (SHA-256)"
        else
            warn "Sin fichero .sha256 junto al paquete: no se puede verificar su integridad"
        fi
    else
        [ "$INTERNET" -eq 1 ] || die "Sin Internet no se puede instalar online. Usa SETUP_SOURCE=offline."
    fi

    ask_names_port

    say "Rol del nodo"
    ask_choice role "¿Rol?" "standalone|primary|secondary" "standalone" SETUP_ROLE
    if [ "$role" = secondary ]; then
        info "Pega la CLAVE DE UNIÓN que imprimió el primary al terminar su instalación."
        ask join "Clave de unión" "" SETUP_JOIN_KEY
        [ -n "$join" ] || die "Un secondary necesita la clave de unión del primary"
    else
        ask_admin_password
        if [ "$role" = primary ]; then
            ask sec_ip "IP prevista del secondary (vacío = toda la subred)" "-" SETUP_SECONDARY_IP
            [ "$sec_ip" = "-" ] && sec_ip=""
        fi
    fi

    say "Resumen antes de instalar"
    info "Modo nativo · origen ${src} · rol ${role} · ${NAMES} · ${NODE_IP}:${WEB_PORT}"
    if [ "$EXISTING" = native ]; then
        local ex
        ask_choice ex "Ya hay SATOM nativo aquí. ¿Qué hago? (para actualizar usa la página Software Update)" "reinstall|abort" "abort" SETUP_EXISTING
        [ "$ex" = reinstall ] || die "Cancelado: se conserva la instalación existente"
        export SATOM_ALLOW_REINSTALL=1
    fi
    [ "$ASSUME_YES" -eq 1 ] || ask_yn "¿Continuar?" s || die "Cancelado por el usuario"

    CURRENT_STEP="3 · nativo: preparar instalador"
    work="/root/satom-setup-${VERSION:-local}"; mkdir -p "$work"; chmod 700 "$work"
    local git_url="${SETUP_GIT_URL:-}"
    if [ "$src" = offline ] && [ "$in_bundle" -eq 1 ]; then
        installer="$sibling"
        assert_sane_tarball "$SCRIPT_DIR/bundle/app.tar.gz" 0 "el paquete offline"
    elif [ "$src" = offline ]; then
        tar -xzf "$BUNDLE_FILE" -C "$work"
        installer="$(ls -1 "$work"/*/install-satom.sh 2>/dev/null | head -1)"
        [ -n "$installer" ] || die "El paquete no contiene install-satom.sh"
        ok "Paquete extraído en $(dirname "$installer")"
        assert_sane_tarball "$(dirname "$installer")/bundle/app.tar.gz" 0 "el paquete offline"
    else
        if [ -n "$sibling" ]; then
            # En $work, no en su sitio: con bundle/ al lado se activaría el
            # modo offline de install-satom.sh aunque se haya elegido online.
            installer="$work/install-satom.sh"
            cp "$sibling" "$installer"
            ok "install-satom.sh ${VERSION} tomado de ${SCRIPT_DIR} (sin descargar)"
        else
            installer="$work/install-satom.sh"
            fetch -o "$installer" "${GH_URL}/releases/download/v${VERSION}/install-satom.sh"
            ok "install-satom.sh v${VERSION} descargado de la release oficial"
        fi
        # install-satom.sh clona la rama main del repo; se comprueba ESE código
        # antes de empezar. Con otro repo (SETUP_GIT_URL) no hay cómo verlo antes.
        if [ -z "$git_url" ]; then
            local tgz; tgz="$(mktemp /tmp/satom-src.XXXX.tar.gz)"
            fetch -o "$tgz" "https://codeload.github.com/${GH_REPO}/tar.gz/refs/heads/main" \
                || { rm -f "$tgz"; die "No pude descargar el código de ${GH_URL} para comprobarlo"; }
            assert_sane_tarball "$tgz" 1 "${GH_URL} (rama main)"
            rm -f "$tgz"
        else
            info "Repo propio (${git_url##*@}): el código no se comprueba antes de clonarlo"
        fi
    fi
    bash -n "$installer" || die "El install-satom.sh no es un script válido"

    # Respuestas en el MISMO orden en que install-satom.sh las pregunta.
    # (El nombre DNS va por SATOM_SERVED_NAMES y no se pregunta.)
    local answers="$work/.answers"
    ( umask 077
      {
        printf '%s\n' "$NODE_IP" "$WEB_PORT"
        if [ "$role" = standalone ]; then printf '%s\n' standalone
        else printf '%s\n' cluster "$role"; fi
        if [ "$role" = secondary ]; then printf '%s\n' "$join"
        else printf '%s\n' "$ADMIN_PW" "$ADMIN_PW"; fi
        [ "$role" = primary ] && printf '%s\n' "$sec_ip"
        printf '%s\n' s
        # URL del repo (solo online): vacía = la pública por defecto.
        [ "$src" = online ] && printf '%s\n' "$git_url"
        true
      } > "$answers" )

    CURRENT_STEP="3 · nativo: install-satom.sh"
    say "Ejecutando install-satom.sh (tarda varios minutos; log: /var/log/satom-install.log)"
    set +e
    SATOM_SERVED_NAMES="$NAMES" bash "$installer" < "$answers" 2>&1 | tee -a "$LOG"
    local rc=${PIPESTATUS[0]}
    set -e
    shred -u "$answers" 2>/dev/null || rm -f "$answers"
    [ "$rc" -eq 0 ] || { CURRENT_STEP="3 · nativo: install-satom.sh (rc=$rc)"; false; }

    CURRENT_STEP="4 · nativo: verificación"
    say "Verificación"
    local t=0
    until curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:${WEB_PORT}/healthz" | grep -q 200; do
        t=$((t+3)); [ "$t" -ge 180 ] && die "La consola no responde en https://127.0.0.1:${WEB_PORT}/healthz tras 3 min"
        sleep 3
    done
    ok "healthz 200 en :${WEB_PORT}"
    # El cortafuegos (firewalld o ufw) lo abre install-satom.sh [SATOM-FIREWALL].

    SUMMARY_MODE="nativo (${role})"
    SUMMARY_UNINSTALL="systemctl disable --now 'satom*' ; rm -rf ${NATIVE_DIR} ; (BD 'satom' en PostgreSQL y vhost en /etc/nginx) — ver docs/INSTALL.md"
    SUMMARY_LOGS="journalctl -u satom -f   ·   /var/log/satom-install.log"
}

# ═════════════════════════════════════════════════════════════════════════════
# INSTALACIÓN DOCKER
# ═════════════════════════════════════════════════════════════════════════════
COMPOSE_V=""
ensure_docker() {
    CURRENT_STEP="3 · docker: motor"
    if have docker && docker info >/dev/null 2>&1; then
        ok "Docker $(docker version -f '{{.Server.Version}}' 2>/dev/null) en marcha"
    else
        if ! have docker; then
            ask_yn "Docker no está instalado. ¿Lo instalo ahora (paquetes oficiales de tu distro/Docker)?" s SETUP_INSTALL_DOCKER \
                || die "Docker es necesario para este modo"
            install_docker_pkgs
        fi
        systemctl enable --now docker >>"$LOG" 2>&1 || die "No pude arrancar el servicio docker (mira: journalctl -u docker)"
        docker info >/dev/null 2>&1 || die "Docker instalado pero no responde (¿contenedor LXC sin nesting/keyctl?)"
        ok "Docker $(docker version -f '{{.Server.Version}}') en marcha"
    fi
    if ! docker compose version >/dev/null 2>&1; then
        ask_yn "Falta Docker Compose v2. ¿Lo instalo?" s SETUP_INSTALL_DOCKER || die "Compose v2 es necesario"
        install_compose_pkg
    fi
    COMPOSE_V="$(docker compose version --short 2>/dev/null | sed 's/^v//')"
    ver_ge "$COMPOSE_V" 2.20.0 || die "Docker Compose ${COMPOSE_V} es demasiado viejo (mínimo 2.20)"
    ok "Docker Compose ${COMPOSE_V}"
}
install_docker_pkgs() {
    CURRENT_STEP="3 · docker: instalar paquetes"
    info "Instalando Docker (${OS_FAMILY})…"
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
        *) die "No sé instalar Docker en ${OS_NAME}. Instálalo a mano y vuelve a ejecutar." ;;
    esac
    ok "Paquetes de Docker instalados"
}
install_compose_pkg() {
    case "$OS_FAMILY" in
        suse)   zypper -n install docker-compose >>"$LOG" 2>&1 ;;
        debian) apt-get install -y docker-compose-plugin >>"$LOG" 2>&1 || apt-get install -y docker-compose-v2 >>"$LOG" 2>&1 ;;
        rhel)   $PKG install -y docker-compose-plugin >>"$LOG" 2>&1 ;;
    esac
    docker compose version >/dev/null 2>&1 || die "No pude instalar Docker Compose v2"
}

# [SATOM-NET-LITERALS] Un árbol de código con una RED inválida no se instala.
# La limpieza del espejo público de 2.1.1 reescribió rangos privados como redes
# con bits de host (un /8 privado quedó como 192.0.2.0/8, la red Docker como
# 203.0.113.0/16):
# Python lanza ValueError al importar, gunicorn no arranca y Docker no crea la
# red. Desde 2.1.2 el redactor no las toca; esto NO repara nada — si un árbol
# descargado aún trae una, se detiene y dice cuál, en vez de instalar algo roto
# o de "arreglar" código en silencio.
# Solo ficheros de ejecución (*.py, *.yaml, *.yml) y solo redes ESTRICTAMENTE
# inválidas terminadas en .0 (192.0.2.0/8). La notación dirección/prefijo de
# una interfaz (192.0.2.41/24) es legítima y no cuenta.
bad_network_literals() {  # bad_network_literals DIR -> imprime "fichero:línea: red"
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
    }' | sed "s#^$d/##" || true   # grep sin coincidencias = árbol limpio, no un error
}
assert_sane_tarball() {  # assert_sane_tarball TGZ STRIP "descripción"
    [ -f "$1" ] || die "No existe $1: no se puede comprobar el código de ${3}"
    local t bad; t="$(mktemp -d /tmp/satom-check.XXXX)"
    tar -xzf "$1" -C "$t" --strip-components="$2" >>"$LOG" 2>&1 \
        || { rm -rf "$t"; die "No pude leer $1 (¿descarga incompleta?)"; }
    bad="$(bad_network_literals "$t")"; rm -rf "$t"
    refuse_bad_network_literals "$bad" "$3"
}
assert_sane_network_literals() {  # assert_sane_network_literals DIR "descripción"
    refuse_bad_network_literals "$(bad_network_literals "$1")" "$2"
}
refuse_bad_network_literals() {  # refuse_bad_network_literals "$hallazgos" "descripción"
    local bad="$1"
    if [ -n "$bad" ]; then
        log_raw "redes inválidas en $2: $(printf '%s' "$bad" | tr '\n' ' ')"
        die "El código de ${2} trae redes INVÁLIDAS (bits de host), la huella de la limpieza
       del espejo público de SATOM 2.1.1. Con ellas la aplicación no arranca, así que
       NO se instala. Primeras apariciones:
$(printf '%s\n' "$bad" | head -5 | sed 's/^/         /')
       Instala una release corregida (2.1.2 o posterior)."
    fi
    ok "Código de ${2}: sin redes inválidas"
}

ENVF="$DOCKER_HOME/satom.env"
env_get() { [ -f "$ENVF" ] && sed -n "s/^$1=//p" "$ENVF" | tail -1 | sed "s/^'\(.*\)'\$/\1/" || true; }
env_set() {  # env_set KEY VALOR  (reemplaza todas las apariciones o añade)
    local k="$1" v="$2" tmp
    tmp="$(mktemp "$DOCKER_HOME/.env.XXXX")"
    V="$v" awk -v k="$k" 'BEGIN{done=0}
        $0 ~ "^"k"=" { if (!done) { print k"="ENVIRON["V"]; done=1 } ; next }
        { print } END { if (!done) print k"="ENVIRON["V"] }' "$ENVF" > "$tmp"
    chmod 600 "$tmp"; mv -f "$tmp" "$ENVF"
}

fetch_source() {  # fetch_source VERSION -> $DOCKER_HOME/releases/<ver>
    local v="$1" dest="$DOCKER_HOME/releases/$1" tgz
    CURRENT_STEP="3 · docker: código fuente v$v"
    if [ -f "$dest/Dockerfile" ]; then ok "Código v${v} ya descargado"; return; fi
    [ "$INTERNET" -eq 1 ] || die "Sin Internet no puedo descargar el código de v${v} (el modo Docker offline aún no se publica)"
    mkdir -p "$DOCKER_HOME/releases"; tgz="$(mktemp /tmp/satom-src.XXXX.tar.gz)"
    info "Descargando código v${v} de GitHub (sin git)…"
    fetch -o "$tgz" "https://codeload.github.com/${GH_REPO}/tar.gz/refs/tags/v${v}" \
        || die "No existe la release v${v} en ${GH_URL}"
    rm -rf "$dest.tmp"; mkdir -p "$dest.tmp"; tar -xzf "$tgz" -C "$dest.tmp" --strip-components=1; rm -f "$tgz"
    [ -f "$dest.tmp/Dockerfile" ] && [ -f "$dest.tmp/deploy/docker/compose.yaml" ] || die "La release v${v} no trae el stack Docker"
    # Se comprueba ANTES de darlo por descargado: un árbol rechazado se queda en
    # .tmp y la próxima ejecución lo vuelve a bajar en vez de reutilizarlo.
    assert_sane_network_literals "$dest.tmp" "la release v${v}"
    mv "$dest.tmp" "$dest"
    ok "Código v${v} en ${dest}"
}

build_image() {  # build_image VERSION
    CURRENT_STEP="3 · docker: construir imagen satom:$1"
    if docker image inspect "satom:$1" >/dev/null 2>&1; then ok "Imagen satom:$1 ya existe"; return; fi
    say "Construyendo la imagen satom:$1 (5–15 min la primera vez)"
    ( cd "$DOCKER_HOME/releases/$1" && docker build -t "satom:$1" -f Dockerfile . ) >>"$LOG" 2>&1 \
        || die "Falló la construcción de la imagen (detalle al final de ${LOG})"
    ok "Imagen satom:$1 construida ($(docker image inspect "satom:$1" -f '{{.Size}}' | awk '{printf "%.0f MB", $1/1048576}'))"
}

write_wrapper() {
    cat > /usr/local/sbin/satom-docker <<'WRAP'
#!/usr/bin/env bash
# satom-docker — docker compose con los ficheros correctos de ESTA instalación.
# Generado por satom-setup.sh. Ejemplos:  satom-docker ps | logs -f web | restart web
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

write_setup_overlay() {  # override propio del instalador: clave inicial + BD externa
    local db="$1"
    {
        echo "# Generado por satom-setup.sh — NO editar a mano; vuelve a ejecutar el instalador."
        echo "# 1) La clave del primer admin llega por el ENTORNO del proceso en el primer arranque"
        echo "#    (SATOM_SETUP_ADMIN_PW); nunca se escribe en disco. Vacía después: no afecta"
        echo "#    a un admin que ya existe."
        [ "$db" = external ] && {
            echo "# 2) PostgreSQL EXTERNO: el servicio 'postgres' no ejecuta una base de datos; queda"
            echo "#    como sonda de salud de la BD externa para que el orden de arranque se mantenga."
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
    CURRENT_STEP="3 · docker: probar BD externa"
    info "Probando conexión a postgresql://${u}@${h}:${p}/${d} …"
    local out
    if out="$(docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD="$pw" -e PGCONNECT_TIMEOUT=8 \
        postgres:15-bookworm psql -h "$h" -p "$p" -U "$u" -d "$d" -v ON_ERROR_STOP=1 -tAc \
        'select version(); create table satom_setup_probe(i int); drop table satom_setup_probe;' 2>&1)"; then
        ok "BD externa accesible y con permiso de crear tablas ($(printf '%s' "$out" | head -1 | cut -c1-40)…)"
    else
        die "No puedo usar la BD externa: $(printf '%s' "$out" | tail -2 | tr '\n' ' ')
     Comprueba: que exista la base '${d}' con dueño '${u}', listen_addresses y pg_hba.conf
     (debe admitir las redes de Docker: la del stack, SATOM_NETWORK_SUBNET en ${ENVF},
     y la del puente docker0), y el cortafuegos del servidor de BD."
    fi
}

install_docker() {
    local role db="bundled" agent="no" cert="self" certf="" keyf="" chainf="" joinf="" upgrading=0
    local db_host="" db_port="" db_name="" db_user="" db_pw=""
    CURRENT_STEP="3 · docker"
    say "Instalación DOCKER (todo SATOM en contenedores)"
    [ "$EXISTING" = native ] && die "Esta máquina ya tiene SATOM nativo: no se mezclan los dos en el mismo host (mismos puertos). Usa otra máquina."
    [ "$INTERNET" -eq 1 ] || die "El modo Docker necesita Internet (descarga el código y las imágenes base). Docker offline aún no se publica."

    if [ "$EXISTING" = docker ]; then
        local ex cur; cur="$(cat "$DOCKER_HOME/current/VERSION" 2>/dev/null || echo '?')"
        ask_choice ex "Ya hay SATOM Docker v${cur}. ¿Actualizar a v${VERSION}, o cancelar?" "update|abort" "update" SETUP_EXISTING
        [ "$ex" = update ] || die "Cancelado: se conserva la instalación existente"
        upgrading=1
    fi
    ensure_docker

    if [ "$upgrading" -eq 1 ]; then
        fetch_source "$VERSION"; build_image "$VERSION"
        CURRENT_STEP="docker: actualizar"
        ln -sfn "$DOCKER_HOME/releases/$VERSION" "$DOCKER_HOME/current"
        ln -sfn "$ENVF" "$DOCKER_HOME/current/deploy/docker/.env"
        env_set SATOM_IMAGE "satom:$VERSION"
        write_wrapper
        /usr/local/sbin/satom-docker up -d --remove-orphans >>"$LOG" 2>&1
        WEB_PORT="$(env_get SATOM_HTTPS_BIND | sed 's/.*://')"; NAMES="$(env_get SATOM_SERVED_NAMES)"
        wait_docker_healthy
        SUMMARY_MODE="docker — actualizado a v${VERSION}"
        SUMMARY_PW_NOTE="sin cambios (la de antes de actualizar)"
        SUMMARY_UNINSTALL="bash satom-setup.sh --uninstall   (añade --purge para borrar también los datos)"
        SUMMARY_LOGS="satom-docker ps   ·   satom-docker logs -f web"
        return
    fi

    ask_names_port

    say "Base de datos"
    ask_choice db "¿PostgreSQL dentro del stack (bundled) o uno que ya tienes (external)?" "bundled|external" "bundled" SETUP_DB
    if [ "$db" = external ]; then
        ask db_host "Servidor PostgreSQL (localhost = esta misma máquina)" "" SETUP_DB_HOST
        case "$db_host" in localhost|127.*|::1) db_host="host.docker.internal"
            warn "BD en este host: PostgreSQL debe escuchar en la IP del puente Docker y pg_hba admitir las redes de Docker (docker0 y SATOM_NETWORK_SUBNET)" ;; esac
        ask db_port "Puerto" "5432" SETUP_DB_PORT
        ask db_name "Base de datos" "satom" SETUP_DB_NAME
        ask db_user "Usuario" "satom" SETUP_DB_USER
        if [ -n "${SETUP_DB_PASSWORD:-}" ]; then db_pw="$SETUP_DB_PASSWORD"
        elif [ "$ASSUME_YES" -eq 1 ]; then die "Modo --yes: falta SETUP_DB_PASSWORD"
        else read -rsp "    Clave de ${db_user}: " db_pw </dev/tty; echo; fi
        [[ "$db_pw" == *"'"* ]] && die "La clave de la BD no puede contener comilla simple (')"
    fi

    say "Rol del nodo"
    if [ "$db" = external ]; then
        role=standalone; info "Con BD externa el rol es standalone (la alta disponibilidad la da tu PostgreSQL)"
    else
        ask_choice role "¿Rol?" "standalone|primary|standby" "standalone" SETUP_ROLE
    fi
    if [ "$role" = standby ]; then
        ver_ge "$COMPOSE_V" 2.24.4 || die "Un standby necesita Docker Compose >= 2.24.4 (tienes ${COMPOSE_V}; el overlay usa '!reset'). En openSUSE: instala docker-compose de Docker Inc. o usa otra distro para el standby."
        ask joinf "Ruta del fichero de unión copiado del primary (satom-docker-join.env)" "" SETUP_JOIN_FILE
        [ -f "$joinf" ] || die "No existe el fichero de unión: $joinf"
    fi

    say "Agente de operaciones (actualizar / reiniciar / certificados desde la web)"
    fetch_source "$VERSION"
    if [ -f "$DOCKER_HOME/releases/$VERSION/deploy/docker/compose.agent.yaml" ]; then
        info "Riesgo: el agente monta /var/run/docker.sock (quien lo controla es root del host)."
        info "La web solo deja peticiones en un volumen; el agente acepta una lista cerrada de acciones."
        ask_yn "¿Activar el agente?" n SETUP_AGENT && agent=yes
    else
        warn "SATOM v${VERSION} todavía no incluye el agente Docker."
        info "Sin él, esas 4 funciones se hacen con 'satom-docker' (p.ej. satom-docker restart web)."
        info "Cuando una release lo traiga, vuelve a ejecutar este script en modo actualizar."
        [ "${SETUP_AGENT:-no}" = yes ] && warn "SETUP_AGENT=yes ignorado: no disponible en esta versión"
    fi

    say "Certificado HTTPS"
    ask_choice cert "¿Certificado propio del nodo (self) o importar el tuyo (import)?" "self|import" "self" SETUP_CERT
    if [ "$cert" = import ]; then
        ask certf "Fichero del certificado (PEM)" "" SETUP_CERT_FILE; [ -f "$certf" ] || die "No existe $certf"
        ask keyf "Fichero de la clave privada (PEM)" "" SETUP_KEY_FILE; [ -f "$keyf" ] || die "No existe $keyf"
        ask chainf "Cadena intermedia (vacío = ninguna)" "-" SETUP_CHAIN_FILE; [ "$chainf" = "-" ] && chainf=""
        [ -z "$chainf" ] || [ -f "$chainf" ] || die "No existe $chainf"
        [ "$(openssl x509 -in "$certf" -noout -pubkey | openssl sha256)" = "$(openssl pkey -in "$keyf" -pubout | openssl sha256)" ] \
            || die "El certificado y la clave NO son pareja"
        ok "Certificado y clave coinciden (CN=$(openssl x509 -in "$certf" -noout -subject | sed 's/.*CN *= *//'))"
    fi

    [ "$role" = standby ] || ask_admin_password

    say "Resumen antes de instalar"
    info "Docker · v${VERSION} · BD ${db} · rol ${role} · agente ${agent} · cert ${cert}"
    info "Consola: https://$(echo "$NAMES" | awk '{print $1}')$([ "$WEB_PORT" = 443 ] || echo ":$WEB_PORT")/   (IP ${NODE_IP})"
    [ "$ASSUME_YES" -eq 1 ] || ask_yn "¿Continuar?" s || die "Cancelado por el usuario"

    # ── Instalación ──────────────────────────────────────────────────────────
    build_image "$VERSION"
    CURRENT_STEP="docker: configuración"
    mkdir -p "$DOCKER_HOME"; chmod 700 "$DOCKER_HOME"
    ln -sfn "$DOCKER_HOME/releases/$VERSION" "$DOCKER_HOME/current"
    local D="$DOCKER_HOME/current/deploy/docker"
    if [ ! -f "$ENVF" ]; then
        cp "$D/env.example" "$ENVF"; chmod 600 "$ENVF"
        env_set SECRET_KEY "$(rand_hex 32)"
        env_set FERNET_KEY "$(openssl rand 32 | base64 | tr '+/' '-_')"
        env_set POSTGRES_PASSWORD "$(rand_hex 24)"
        env_set SATOM_REPL_PASSWORD "$(rand_hex 24)"
        ok "Secretos generados en ${ENVF} (0600)"
    else
        ok "Se reutilizan los secretos existentes de ${ENVF} (nunca se regeneran)"
    fi
    if [ "$role" = standby ]; then
        local k
        for k in SECRET_KEY FERNET_KEY POSTGRES_USER POSTGRES_DB POSTGRES_PASSWORD SATOM_REPL_USER SATOM_REPL_PASSWORD SATOM_PRIMARY_HOST SATOM_PRIMARY_PORT; do
            local v; v="$(sed -n "s/^$k=//p" "$joinf" | tail -1)"
            [ -n "$v" ] || [ "$k" = SATOM_PRIMARY_PORT ] || die "El fichero de unión no trae $k"
            [ -n "$v" ] && env_set "$k" "$v"
        done
        ok "Secretos y datos del primary importados del fichero de unión"
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
    /usr/local/sbin/satom-docker config -q >>"$LOG" 2>&1 || die "La configuración de Compose no es válida (detalle en ${LOG})"
    ok "Configuración validada (docker compose config)"

    [ "$db" = external ] && test_external_db "$db_host" "$db_port" "$db_name" "$db_user" "$db_pw"

    CURRENT_STEP="docker: descargar imágenes base"
    info "Descargando imágenes base (postgres, redis, victoria-metrics, nginx)…"
    # Solo las imágenes base: 'compose pull' intentaría bajar también satom:<ver> de
    # Docker Hub, que es una imagen LOCAL y no debe sustituirse por una ajena.
    local img
    for img in $(/usr/local/sbin/satom-docker config --images 2>>"$LOG" | sort -u | grep -v '^satom:'); do
        docker pull -q "$img" >>"$LOG" 2>&1 || die "No pude descargar la imagen base $img"
    done
    ok "Imágenes base descargadas"

    if [ "$cert" = import ]; then
        CURRENT_STEP="docker: importar certificado"
        local tmpd; tmpd="$(mktemp -d)"; cp "$certf" "$tmpd/cert.pem"; cp "$keyf" "$tmpd/key.pem"
        [ -n "$chainf" ] && cp "$chainf" "$tmpd/chain.pem"
        chmod 644 "$tmpd"/*.pem
        /usr/local/sbin/satom-docker run --rm --no-deps -v "$tmpd:/import:ro" --entrypoint /opt/satom/deploy/tls-bootstrap.sh \
            tls-init import-cert --cert /import/cert.pem --key /import/key.pem \
            $([ -n "$chainf" ] && echo "--chain /import/chain.pem") --pki /opt/satom/pki >>"$LOG" 2>&1 \
            || { rm -rf "$tmpd"; die "No pude importar el certificado (detalle en ${LOG})"; }
        rm -rf "$tmpd"; ok "Certificado importado en el volumen satom-pki"
    fi

    CURRENT_STEP="docker: arrancar el stack"
    say "Arrancando el stack"
    SATOM_SETUP_ADMIN_PW="$ADMIN_PW" /usr/local/sbin/satom-docker up -d >>"$LOG" 2>&1 \
        || die "docker compose up falló (detalle en ${LOG}; estado: satom-docker ps)"
    wait_docker_healthy

    if [ "$role" != standby ]; then
        CURRENT_STEP="docker: comprobar admin"
        # La clave va por stdin: con 'exec -e' quedaría visible en la lista de procesos.
        if printf '%s\n' "$ADMIN_PW" | /usr/local/sbin/satom-docker exec -T web python -c '
import sys, logging; logging.disable(logging.CRITICAL)
pw = sys.stdin.readline().rstrip("\n")
from app import create_app
from app.models import User
a = create_app()
with a.app_context():
    u = User.query.filter_by(username="admin").first()
    raise SystemExit(0 if u and u.check_password(pw) else 3)' >>"$LOG" 2>&1; then
            ok "Usuario 'admin' creado y la clave elegida funciona"
        else
            warn "No pude confirmar la clave del admin (¿la BD ya tenía usuarios de una instalación anterior?)"
        fi
    fi

    if [ "$role" = primary ]; then
        local jf=/root/satom-docker-join.env
        ( umask 077; {
            echo "# Fichero de unión SATOM Docker — cópialo al standby (scp) y bórralo después."
            for k in SECRET_KEY FERNET_KEY POSTGRES_USER POSTGRES_DB POSTGRES_PASSWORD SATOM_REPL_USER SATOM_REPL_PASSWORD; do
                echo "$k=$(env_get "$k")"; done
            echo "SATOM_PRIMARY_HOST=${NODE_IP}"; echo "SATOM_PRIMARY_PORT=5432"
        } > "$jf" )
        ok "Fichero de unión para el standby: ${jf} (0600)"
        open_firewall 80 "$WEB_PORT" 5432
    else
        open_firewall 80 "$WEB_PORT"
    fi

    touch "$DOCKER_HOME/.installed"
    SUMMARY_MODE="docker (${role}, BD ${db}, agente ${agent})"
    SUMMARY_UNINSTALL="bash satom-setup.sh --uninstall   (añade --purge para borrar también los datos)"
    SUMMARY_LOGS="satom-docker ps   ·   satom-docker logs -f web"
}

wait_docker_healthy() {
    CURRENT_STEP="docker: esperar salud"
    info "Esperando a que la consola responda (primer arranque: crea la BD, 1–3 min)…"
    local t=0 code=""
    while :; do
        code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "https://127.0.0.1:${WEB_PORT}/healthz" || true)"
        [ "$code" = 200 ] && break
        t=$((t+5))
        if [ "$t" -ge 420 ]; then
            /usr/local/sbin/satom-docker ps 2>&1 | tee -a "$LOG"
            /usr/local/sbin/satom-docker logs --tail=40 web 2>&1 | tee -a "$LOG"
            die "La consola no respondió en 7 min (último código: ${code:-sin respuesta})"
        fi
        sleep 5
    done
    ok "healthz 200 en https://127.0.0.1:${WEB_PORT}/healthz"
    local bad; bad="$(/usr/local/sbin/satom-docker ps --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null | awk '$2!="running" || $3=="unhealthy"' || true)"
    [ -z "$bad" ] && ok "Todos los contenedores en marcha" || warn "Contenedores con problemas: ${bad}"
}

uninstall_docker() {
    CURRENT_STEP="desinstalar"
    [ -f "$ENVF" ] || die "No hay instalación Docker de SATOM en ${DOCKER_HOME}"
    [ -x /usr/local/sbin/satom-docker ] || write_wrapper
    say "Desinstalar SATOM Docker"
    if [ "$PURGE" -eq 1 ]; then
        warn "--purge BORRA la base de datos, el vault de equipos y los certificados. No hay vuelta atrás."
        local c=""; [ "$ASSUME_YES" -eq 1 ] && c=BORRAR || { read -rp "    Escribe BORRAR para confirmar: " c </dev/tty; }
        [ "$c" = BORRAR ] || die "Cancelado"
        /usr/local/sbin/satom-docker down -v --remove-orphans >>"$LOG" 2>&1
        rm -rf "$DOCKER_HOME" /usr/local/sbin/satom-docker
        docker image ls --format '{{.Repository}}:{{.Tag}}' | grep '^satom:' | xargs -r docker image rm >>"$LOG" 2>&1 || true
        ok "Contenedores, volúmenes, imágenes satom:* y ${DOCKER_HOME} eliminados"
    else
        /usr/local/sbin/satom-docker down --remove-orphans >>"$LOG" 2>&1
        ok "Contenedores parados y eliminados. Datos CONSERVADOS (volúmenes satom_* y ${ENVF})."
        info "Para volver a levantarlo: satom-docker up -d  ·  para borrarlo todo: --uninstall --purge"
    fi
    exit 0
}

# ═════════════════════════════════════════════════════════════════════════════
# Principal
# ═════════════════════════════════════════════════════════════════════════════
SUMMARY_MODE=""; SUMMARY_UNINSTALL=""; SUMMARY_LOGS=""

echo "${c_b}SATOM ${SETUP_VERSION} — instalador guiado${c_0}   (log: ${LOG})"
[ "$UNINSTALL" -eq 1 ] && uninstall_docker

detect_os
check_requirements
resolve_version
detect_existing

if [ "$CHECK_ONLY" -eq 1 ]; then
    say "Solo comprobación (--check): no se ha instalado nada."
    exit 0
fi

CURRENT_STEP="3 · modo"
say "Paso 3 · Tipo de instalación"
info "native : SATOM directamente en esta máquina (systemd). Actualización con un clic desde la web."
info "docker : SATOM en contenedores. Se actualiza volviendo a ejecutar este script."
DEF_MODE=native; [ "$EXISTING" = docker ] && DEF_MODE=docker
ask_choice MODE "¿Nativo o Docker?" "native|docker" "$DEF_MODE" SETUP_MODE
[ "$MODE" = native ] || [ -n "$VERSION" ] || die "Sin versión conocida (sin Internet): usa --version"

if [ "$MODE" = native ]; then install_native; else install_docker; fi

# ─────────────────────────────────────────────────────────────────────────────
# Resumen final
# ─────────────────────────────────────────────────────────────────────────────
CURRENT_STEP="resumen"
FIRST_NAME="$(echo "$NAMES" | awk '{print $1}')"
PORT_SFX="$([ "$WEB_PORT" = 443 ] || echo ":$WEB_PORT")"
SUMMARY="/root/satom-setup-summary.txt"
{
    echo "SATOM ${VERSION} instalado — $(date '+%F %T')"
    echo "  Modo ............ ${SUMMARY_MODE}"
    echo "  Consola ......... https://${FIRST_NAME}${PORT_SFX}/   (o https://${NODE_IP}${PORT_SFX}/)"
    echo "  Usuario ......... admin"
    if [ -n "${SUMMARY_PW_NOTE:-}" ]; then
        echo "  Clave ........... ${SUMMARY_PW_NOTE}"
    elif [ "$ADMIN_PW_GENERATED" -eq 1 ]; then
        echo "  Clave ........... en ${ADMIN_PW_FILE} (0600) — cámbiala al entrar y borra el fichero"
    elif [ -n "$ADMIN_PW" ]; then
        echo "  Clave ........... la que escribiste durante la instalación"
    else
        echo "  Clave ........... la del primary (se replica)"
    fi
    echo "  Log instalación . ${LOG}"
    echo "  Logs / estado ... ${SUMMARY_LOGS}"
    [ "$MODE" = docker ] && echo "  Secretos ........ ${ENVF}  ← RESPÁLDALO (FERNET_KEY no se puede regenerar)"
    echo "  Desinstalar ..... ${SUMMARY_UNINSTALL}"
    echo "  Si el nombre ${FIRST_NAME} no resuelve aún, créalo en tu DNS apuntando a ${NODE_IP}."
} | tee "$SUMMARY"
chmod 600 "$SUMMARY"
echo
echo "${c_g}${c_b}Instalación terminada.${c_0} Resumen guardado en ${SUMMARY}"
log_raw "FIN OK"
