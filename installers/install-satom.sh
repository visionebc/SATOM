#!/usr/bin/env bash
# ============================================================================
# install-satom.sh — Instalador de SATOM (Open Fortinet Management
# Automation Tool) — GENÉRICO para distribuciones Linux con systemd.
#
#   Familias soportadas (detección automática del gestor de paquetes):
#     • Debian / Ubuntu ............. apt
#     • RHEL / Rocky / Alma / Fedora  dnf (o yum)
#     • openSUSE / SLES ............. zypper
#     • Arch ........................ pacman
#   Requisito duro: systemd (la app instala unidades systemd). Alpine/musl
#   no está soportado.
#
# MODOS DE OPERACIÓN
#   • ONLINE : descarga paquetes de los mirrors de la distro/PyPI y el código
#              del repo git de producción. Funciona en TODAS las familias.
#   • OFFLINE: 100% sin red. Se auto-activa cuando existe un directorio
#              `bundle/` junto a este script (generado por
#              build-offline-bundle.sh) con debs/, wheels/ y app.tar.gz.
#              El bundle trae paquetes .deb → SOLO familia Debian/Ubuntu;
#              para otras familias usa el modo online.
#
# TOPOLOGÍAS
#   • standalone            — un solo nodo, Postgres local.
#   • cluster / primary     — genera la CLAVE DE UNIÓN (join key) que se pega
#                             en el nodo secundario.
#   • cluster / secondary   — pide la join key; configura réplica streaming de
#                             Postgres + datasync de data/ y CREA SU PROPIO
#                             CERTIFICADO firmado por la CA interna del clúster.
#
# ORDEN DE EJECUCIÓN (coherente: primero se pregunta TODO, luego se instala)
#   1. Preguntas: IP, puerto HTTPS, clave admin, standalone/cluster,
#      primary/secondary (+join key si secondary).
#   2. Verificación de paquetes (instala faltantes / avisa si actualiza viejos).
#   3. Código de la aplicación + entorno virtual Python.
#   4. Postgres (BD local, o réplica si secondary).
#   5. PKI y certificados TLS.
#   6. Servicios systemd + nginx.
#   7. Comprobación de salud y resumen (join key en el primary).
#
# REQUIERE: root (o sudo). Ver docs/INSTALL.md para la lista exacta de
# comandos si el equipo de sistemas prefiere una regla sudoers granular.
# ============================================================================
set -euo pipefail

VERSION="1.0"
APP_DIR="/opt/satom"
LOG_DIR="/var/log/satom"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="${SCRIPT_DIR}/bundle"
GIT_URL_DEFAULT="https://git.example.net/satom-prod/SATOM.git"
DB_NAME="fortinet_mgr"
DB_USER="fortinet"
REPL_USER="fm_repl"
INSTALL_LOG="/var/log/satom-install.log"

c_bold=$'\033[1m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_red=$'\033[31m'; c_off=$'\033[0m'
say()  { echo "${c_bold}==>${c_off} $*" | tee -a "$INSTALL_LOG"; }
ok()   { echo "    ${c_grn}✓${c_off} $*" | tee -a "$INSTALL_LOG"; }
warn() { echo "    ${c_ylw}!${c_off} $*" | tee -a "$INSTALL_LOG"; }
die()  { echo "${c_red}ERROR:${c_off} $*" | tee -a "$INSTALL_LOG" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Ejecuta como root (o con sudo): sudo bash $0"
mkdir -p "$(dirname "$INSTALL_LOG")"; touch "$INSTALL_LOG"

# ─────────────────────────────────────────────────────────────────────────────
# CAPA DE ABSTRACCIÓN DE DISTRO — todo lo específico de familia vive aquí
# ─────────────────────────────────────────────────────────────────────────────
command -v systemctl >/dev/null 2>&1 || die "Se requiere systemd (Alpine/musl no está soportado)"

PKG_MGR=""
for m in apt-get dnf yum zypper pacman; do
    command -v "$m" >/dev/null 2>&1 && { PKG_MGR="${m/apt-get/apt}"; break; }
done
[ -n "$PKG_MGR" ] || die "Gestor de paquetes no soportado. Familias válidas: apt, dnf/yum, zypper, pacman"

# Nombres de paquete por familia (mismo orden de conceptos en todas)
case "$PKG_MGR" in
    apt)        REQUIRED_PKGS=(python3 python3-venv python3-pip postgresql nginx rsync openssl curl ca-certificates) ;;
    dnf|yum)    REQUIRED_PKGS=(python3.11 python3.11-pip postgresql-server postgresql nginx rsync openssl curl ca-certificates) ;;
    zypper)     REQUIRED_PKGS=(python311 python311-pip postgresql-server postgresql nginx rsync openssl curl ca-certificates) ;;
    pacman)     REQUIRED_PKGS=(python python-pip postgresql nginx rsync openssl curl ca-certificates) ;;
esac
ONLINE_EXTRA_PKGS=(git)

pkg_installed() {  # pkg_installed <pkg> → 0 si está
    case "$PKG_MGR" in
        apt)     dpkg -s "$1" >/dev/null 2>&1 ;;
        pacman)  pacman -Qi "$1" >/dev/null 2>&1 ;;
        *)       rpm -q "$1" >/dev/null 2>&1 ;;
    esac
}

pkg_version() {  # pkg_version <pkg> → versión instalada (o "?")
    case "$PKG_MGR" in
        apt)     dpkg-query -W -f='${Version}' "$1" 2>/dev/null || echo "?" ;;
        pacman)  pacman -Qi "$1" 2>/dev/null | awk -F': *' '/^Version/{print $2; exit}' || echo "?" ;;
        *)       rpm -q --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null || echo "?" ;;
    esac
}

pkg_install() {  # pkg_install <pkg...> → instala desde los mirrors de la distro
    case "$PKG_MGR" in
        apt)     export DEBIAN_FRONTEND=noninteractive
                 apt-get update -qq >>"$INSTALL_LOG" 2>&1
                 apt-get install -y -qq "$@" >>"$INSTALL_LOG" 2>&1 ;;
        # --allowerasing: EL9 minimal trae curl-minimal, que conflictúa con
        # curl completo — dnf debe poder hacer el swap.
        dnf)     dnf install -y -q --allowerasing "$@" >>"$INSTALL_LOG" 2>&1 ;;
        yum)     yum install -y -q "$@" >>"$INSTALL_LOG" 2>&1 ;;
        zypper)  zypper --non-interactive --quiet install "$@" >>"$INSTALL_LOG" 2>&1 ;;
        pacman)  pacman -Sy --noconfirm --needed "$@" >>"$INSTALL_LOG" 2>&1 ;;
    esac
}

pg_bootstrap() {  # arranca Postgres, inicializando el clúster de datos si hace falta
    systemctl enable postgresql >>"$INSTALL_LOG" 2>&1 || true
    if systemctl start postgresql >>"$INSTALL_LOG" 2>&1; then return 0; fi
    # RHEL/Fedora traen postgresql-setup; en el resto initdb directo en el
    # home del usuario postgres (Arch: /var/lib/postgres, SUSE: /var/lib/pgsql)
    if command -v postgresql-setup >/dev/null 2>&1; then
        postgresql-setup --initdb >>"$INSTALL_LOG" 2>&1 || true
    else
        local pghome; pghome=$(getent passwd postgres | cut -d: -f6)
        [ -s "$pghome/data/PG_VERSION" ] || \
            runuser -u postgres -- initdb -D "$pghome/data" >>"$INSTALL_LOG" 2>&1 || true
    fi
    systemctl start postgresql >>"$INSTALL_LOG" 2>&1 \
        || die "PostgreSQL no arrancó tras initdb (revisa $INSTALL_LOG)"
}

OFFLINE=0
if [ -d "$BUNDLE_DIR" ] && [ -d "$BUNDLE_DIR/debs" ]; then
    [ "$PKG_MGR" = "apt" ] || die "El bundle offline contiene paquetes .deb (familia Debian/Ubuntu) y esta máquina usa ${PKG_MGR}. Usa el instalador en modo ONLINE (borra o renombra bundle/) o genera el bundle para esta familia."
    OFFLINE=1
elif [ -d "$BUNDLE_DIR" ] && [ -d "$BUNDLE_DIR/rpms" ]; then
    case "$PKG_MGR" in
        dnf|yum) OFFLINE=1 ;;
        *) die "El bundle offline contiene paquetes .rpm (familia RHEL/Rocky/Alma) y esta máquina usa ${PKG_MGR}. Usa el instalador en modo ONLINE (borra o renombra bundle/) o genera el bundle para esta familia." ;;
    esac
fi

echo ""
echo "┌──────────────────────────────────────────────────────────┐"
echo "│  SATOM ${VERSION} — Instalador $( [ $OFFLINE -eq 1 ] && echo '(OFFLINE, bundle local)' || echo '(ONLINE)' )"
echo "└──────────────────────────────────────────────────────────┘"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PASO 1 — PREGUNTAS (todo por adelantado; nada se toca hasta terminar aquí)
# ─────────────────────────────────────────────────────────────────────────────

# 1a. IP de esta máquina
DETECTED_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
read -rp "IP de esta máquina [${DETECTED_IP}]: " NODE_IP
NODE_IP="${NODE_IP:-$DETECTED_IP}"
[[ "$NODE_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "IP inválida: $NODE_IP"

# 1b. Puerto HTTPS
read -rp "Puerto HTTPS de la consola web [443]: " WEB_PORT
WEB_PORT="${WEB_PORT:-443}"
[[ "$WEB_PORT" =~ ^[0-9]+$ ]] && [ "$WEB_PORT" -ge 1 ] && [ "$WEB_PORT" -le 65535 ] || die "Puerto inválido"

# 1c. Modo
MODE=""; ROLE="standalone"
while [ -z "$MODE" ]; do
    read -rp "¿Instalación standalone o cluster? [standalone/cluster]: " MODE
    case "${MODE,,}" in
        standalone|s) MODE="standalone" ;;
        cluster|c)    MODE="cluster" ;;
        *) warn "Responde 'standalone' o 'cluster'"; MODE="" ;;
    esac
done

JOIN_KEY_RAW=""
if [ "$MODE" = "cluster" ]; then
    ROLE=""
    while [ -z "$ROLE" ]; do
        read -rp "¿Este nodo es primary o secondary? [primary/secondary]: " ROLE
        case "${ROLE,,}" in
            primary|p)   ROLE="primary" ;;
            secondary|s) ROLE="secondary" ;;
            *) warn "Responde 'primary' o 'secondary'"; ROLE="" ;;
        esac
    done
fi

if [ "$ROLE" = "secondary" ]; then
    echo ""
    echo "Pega la CLAVE DE UNIÓN generada por el instalador del nodo primary"
    echo "(una sola línea, empieza por OFMJOIN1.):"
    read -rp "> " JOIN_KEY_RAW
    JOIN_KEY_RAW="${JOIN_KEY_RAW// /}"
    [[ "$JOIN_KEY_RAW" == OFMJOIN1.* ]] || die "La clave de unión no es válida (debe empezar por OFMJOIN1.)"
    JOIN_JSON=$(echo "${JOIN_KEY_RAW#OFMJOIN1.}" | base64 -d 2>/dev/null) || die "La clave de unión no se pudo decodificar"
    jget() { echo "$JOIN_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('$1',''))"; }
    PRIMARY_IP=$(jget primary_ip);   [ -n "$PRIMARY_IP" ]  || die "Join key sin primary_ip"
    PRIMARY_PORT=$(jget primary_port)
    FERNET_KEY=$(jget fernet_key);   [ -n "$FERNET_KEY" ]  || die "Join key sin fernet_key"
    SECRET_KEY=$(jget secret_key)
    DB_PASS=$(jget db_password)
    REPL_PASS=$(jget repl_password); [ -n "$REPL_PASS" ]   || die "Join key sin repl_password"
    CA_CRT=$(jget ca_crt);           [ -n "$CA_CRT" ]      || die "Join key sin ca_crt"
    CA_KEY=$(jget ca_key);           [ -n "$CA_KEY" ]      || die "Join key sin ca_key"
    RSYNC_PRIV=$(jget rsync_key)
    PRIMARY_NAME=$(jget primary_name)
    ok "Join key válida — primary en ${PRIMARY_IP}:${PRIMARY_PORT:-$WEB_PORT}"
    # Comprobar alcanzabilidad del primary ANTES de instalar nada
    if curl -skf --max-time 8 "https://${PRIMARY_IP}:${PRIMARY_PORT:-443}/healthz" >/dev/null 2>&1; then
        ok "Primary alcanzable (healthz 200)"
    else
        warn "No pude verificar https://${PRIMARY_IP}:${PRIMARY_PORT:-443}/healthz — continúo, pero la réplica fallará si el primary no está accesible"
    fi
else
    # 1d. Clave del administrador (solo standalone/primary; el secondary la hereda vía réplica)
    ADMIN_PASS=""
    while [ -z "$ADMIN_PASS" ]; do
        read -rsp "Clave para el usuario 'admin' de la consola: " ADMIN_PASS; echo
        read -rsp "Repite la clave: " ADMIN_PASS2; echo
        if [ "$ADMIN_PASS" != "$ADMIN_PASS2" ]; then warn "No coinciden"; ADMIN_PASS=""; continue; fi
        if [ "${#ADMIN_PASS}" -lt 8 ]; then warn "Mínimo 8 caracteres"; ADMIN_PASS=""; fi
    done
fi

SECONDARY_CIDR=""
if [ "$ROLE" = "primary" ]; then
    read -rp "IP prevista del nodo secondary (Enter = permitir toda la subred de ${NODE_IP}): " SECONDARY_IP_ANS
    if [ -n "$SECONDARY_IP_ANS" ]; then
        SECONDARY_CIDR="${SECONDARY_IP_ANS}/32"
    else
        SECONDARY_CIDR="$(echo "$NODE_IP" | cut -d. -f1-3).0/24"
    fi
fi

echo ""
say "Resumen: IP=${NODE_IP}  puerto=${WEB_PORT}  modo=${MODE}${ROLE:+/${ROLE}}  origen=$( [ $OFFLINE -eq 1 ] && echo offline || echo online )"
read -rp "¿Continuar con la instalación? [S/n]: " GO
[[ "${GO,,}" =~ ^(s|si|sí|y|yes|)$ ]] || die "Cancelado por el usuario"

# ─────────────────────────────────────────────────────────────────────────────
# PASO 2 — PAQUETES (verifica; instala faltantes; avisa de actualizaciones)
# ─────────────────────────────────────────────────────────────────────────────
say "Paso 2/7 — Verificando paquetería (gestor detectado: ${PKG_MGR})"

PKGS=("${REQUIRED_PKGS[@]}")
[ $OFFLINE -eq 0 ] && PKGS+=("${ONLINE_EXTRA_PKGS[@]}")

MISSING=()
for p in "${PKGS[@]}"; do
    if pkg_installed "$p"; then
        ok "$p ya instalado (versión $(pkg_version "$p"))"
    else
        MISSING+=("$p")
        warn "$p FALTA — se instalará"
    fi
done

# Python >= 3.10 exigido por las dependencias pinneadas (Flask-Limiter, psycopg 3.3, gunicorn 26).
# En RHEL/Rocky/Alma 9 el python3 del sistema es 3.9 → se usa python3.11 del AppStream.
pick_python() {
    PYBIN=""
    local c
    for c in python3.12 python3.11 python3; do
        command -v "$c" >/dev/null 2>&1 || continue
        "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null \
            && { PYBIN="$c"; return 0; }
    done
    return 1
}
if pick_python; then
    ok "$($PYBIN --version 2>&1) cumple el mínimo (3.10)"
else
    warn "No hay un Python >= 3.10 — se instalará el de la distro (${REQUIRED_PKGS[0]})"
    MISSING+=("${REQUIRED_PKGS[0]}")
fi

if [ ${#MISSING[@]} -gt 0 ]; then
    if [ $OFFLINE -eq 1 ]; then
        say "Instalando desde el bundle offline (${#MISSING[@]} paquetes + dependencias)"
        if [ -d "$BUNDLE_DIR/debs" ]; then
            # El bundle trae el cierre completo de dependencias; dpkg salta lo ya instalado.
            dpkg -i --skip-same-version "$BUNDLE_DIR"/debs/*.deb >>"$INSTALL_LOG" 2>&1 \
                || apt-get -y -f --no-download install >>"$INSTALL_LOG" 2>&1 \
                || die "Fallo instalando debs del bundle (revisa $INSTALL_LOG)"
        else
            # RPM: bundle/rpms es un repo dnf local (repodata generado en el
            # build) — dnf resuelve SOLO lo necesario, sin tocar el resto
            # del sistema y sin red.
            "$PKG_MGR" -y --disablerepo='*' \
                --repofrompath="satom-bundle,file://$BUNDLE_DIR/rpms" \
                --setopt=satom-bundle.gpgcheck=0 \
                --setopt=install_weak_deps=False \
                --allowerasing \
                install "${REQUIRED_PKGS[@]}" >>"$INSTALL_LOG" 2>&1 \
                || die "Fallo instalando rpms del bundle (revisa $INSTALL_LOG)"
            # Utilería SELinux (semanage) — best-effort, igual que en online
            "$PKG_MGR" -y --disablerepo='*' \
                --repofrompath="satom-bundle,file://$BUNDLE_DIR/rpms" \
                --setopt=satom-bundle.gpgcheck=0 \
                --setopt=install_weak_deps=False \
                install policycoreutils-python-utils >>"$INSTALL_LOG" 2>&1 || true
        fi
    else
        say "Instalando desde los mirrors (${PKG_MGR})"
        pkg_install "${MISSING[@]}" || die "La instalación de paquetes falló (revisa $INSTALL_LOG)"
    fi
    ok "Paquetes instalados"
else
    ok "Toda la paquetería requerida ya está presente"
fi

# Re-resuelve el intérprete tras instalar paquetes (puede haber llegado ahora)
pick_python || die "No hay un Python >= 3.10 disponible tras la instalación de paquetes"
# El módulo venv puede venir en paquete aparte (Debian) o integrado (resto)
"$PYBIN" -m venv --help >/dev/null 2>&1 || die "$PYBIN no trae el módulo venv — instala el paquete venv de tu distro"

# ─────────────────────────────────────────────────────────────────────────────
# PASO 3 — CÓDIGO DE LA APLICACIÓN + VENV
# ─────────────────────────────────────────────────────────────────────────────
say "Paso 3/7 — Desplegando la aplicación en ${APP_DIR}"

if [ -d "$APP_DIR/app" ]; then
    warn "$APP_DIR ya contiene una instalación — se conserva y solo se actualizan dependencias"
else
    mkdir -p "$APP_DIR"
    if [ $OFFLINE -eq 1 ]; then
        tar -xzf "$BUNDLE_DIR/app.tar.gz" -C "$APP_DIR"
        ok "Código extraído del bundle"
    else
        read -rp "URL del repo de producción [${GIT_URL_DEFAULT}]: " GIT_URL
        GIT_URL="${GIT_URL:-$GIT_URL_DEFAULT}"
        git clone --depth 1 --branch main "$GIT_URL" "$APP_DIR" >>"$INSTALL_LOG" 2>&1 || die "git clone falló"
        ok "Código clonado de $GIT_URL"
    fi
fi

mkdir -p "$APP_DIR/data" "$LOG_DIR"
cd "$APP_DIR"

"$PYBIN" -m venv venv
if [ $OFFLINE -eq 1 ]; then
    venv/bin/pip install --no-index --find-links "$BUNDLE_DIR/wheels" --upgrade pip >>"$INSTALL_LOG" 2>&1 || true
    venv/bin/pip install --no-index --find-links "$BUNDLE_DIR/wheels" -r requirements.txt >>"$INSTALL_LOG" 2>&1 \
        || die "pip offline falló (revisa $INSTALL_LOG)"
else
    venv/bin/pip install --quiet --upgrade pip >>"$INSTALL_LOG" 2>&1
    venv/bin/pip install --quiet -r requirements.txt >>"$INSTALL_LOG" 2>&1 || die "pip install falló (revisa $INSTALL_LOG)"
fi
ok "Entorno virtual listo ($(venv/bin/python --version 2>&1))"

# ─────────────────────────────────────────────────────────────────────────────
# PASO 4 — POSTGRES
# ─────────────────────────────────────────────────────────────────────────────
say "Paso 4/7 — Configurando PostgreSQL"

pg_bootstrap
# Rutas SIEMPRE preguntadas al propio Postgres (válido en cualquier distro:
# Debian /etc/postgresql/N/main, RHEL/SUSE /var/lib/pgsql/data, Arch /var/lib/postgres/data)
PGDATA=$(runuser -u postgres -- psql -tAc "SHOW data_directory" | xargs)
PGCONF_FILE=$(runuser -u postgres -- psql -tAc "SHOW config_file" | xargs)
PGHBA=$(runuser -u postgres -- psql -tAc "SHOW hba_file" | xargs)
PGCONF=$(dirname "$PGCONF_FILE")
PGHOME=$(getent passwd postgres | cut -d: -f6)
PGV=$(runuser -u postgres -- psql -tAc "SHOW server_version" | xargs)
[ -n "$PGDATA" ] && [ -n "$PGCONF_FILE" ] || die "No pude interrogar a PostgreSQL (SHOW data_directory/config_file)"
ok "PostgreSQL ${PGV} — data=${PGDATA} conf=${PGCONF}"

if [ "$ROLE" != "secondary" ]; then
    DB_PASS=$(openssl rand -hex 24)
    runuser -u postgres -- psql -qc "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='${DB_USER}') THEN CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}'; ELSE ALTER ROLE ${DB_USER} PASSWORD '${DB_PASS}'; END IF; END \$\$;"
    runuser -u postgres -- psql -qtc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 \
        || runuser -u postgres -- createdb -O "$DB_USER" "$DB_NAME"
    ok "BD ${DB_NAME} + rol ${DB_USER} listos"
fi

# ─────────────────────────────────────────────────────────────────────────────
# PASO 5 — PKI Y CERTIFICADOS
#   standalone/primary : CA interna nueva + certificado del nodo
#   secondary          : recibe la CA por la join key y CREA SU PROPIO cert
# ─────────────────────────────────────────────────────────────────────────────
say "Paso 5/7 — PKI y certificados TLS"

PKI="$APP_DIR/pki"; mkdir -p "$PKI/internal-ca" "$PKI/node" "$PKI/public"
HOSTN=$(hostname)

if [ "$ROLE" = "secondary" ]; then
    printf '%s\n' "$CA_CRT" > "$PKI/internal-ca/ca.crt"
    printf '%s\n' "$CA_KEY" > "$PKI/internal-ca/ca.key"
else
    if [ ! -f "$PKI/internal-ca/ca.key" ]; then
        openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
            -keyout "$PKI/internal-ca/ca.key" -out "$PKI/internal-ca/ca.crt" \
            -subj "/CN=SATOM Internal CA/O=${HOSTN}" >>"$INSTALL_LOG" 2>&1
        ok "CA interna creada (válida 10 años)"
    fi
fi
chmod 600 "$PKI/internal-ca/ca.key"

# Certificado propio del nodo (server+client), firmado por la CA — SIEMPRE
# se genera localmente en ESTE nodo (la llave privada nunca viaja).
openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "$PKI/node/leaf.key" -out "$PKI/node/leaf.csr" \
    -subj "/CN=${HOSTN}" >>"$INSTALL_LOG" 2>&1
cat > /tmp/ofm-ext.cnf <<EXT
subjectAltName=IP:${NODE_IP},DNS:${HOSTN}
extendedKeyUsage=serverAuth,clientAuth
EXT
openssl x509 -req -in "$PKI/node/leaf.csr" -CA "$PKI/internal-ca/ca.crt" \
    -CAkey "$PKI/internal-ca/ca.key" -CAcreateserial -days 825 -sha256 \
    -extfile /tmp/ofm-ext.cnf -out "$PKI/node/leaf.crt" >>"$INSTALL_LOG" 2>&1
rm -f /tmp/ofm-ext.cnf "$PKI/node/leaf.csr"
chmod 600 "$PKI/node/leaf.key"
cp "$PKI/node/leaf.crt" "$PKI/public/server.crt"
cp "$PKI/node/leaf.key" "$PKI/public/server.key"
cat > "$PKI/public/meta.json" <<META
{"source": "issued", "issued_by": "internal-ca", "cn": "${HOSTN}", "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
META
ok "Certificado del nodo emitido localmente (CN=${HOSTN}, SAN=IP:${NODE_IP})"

# Copia para Postgres (réplica TLS en clúster)
PGSSL="$PGCONF/fmssl"; mkdir -p "$PGSSL"
cp "$PKI/node/leaf.crt" "$PGSSL/server.crt"; cp "$PKI/node/leaf.key" "$PGSSL/server.key"
cp "$PKI/internal-ca/ca.crt" "$PGSSL/ca.crt"
chown -R postgres:postgres "$PGSSL"; chmod 600 "$PGSSL/server.key"

# ─────────────────────────────────────────────────────────────────────────────
# PASO 6 — .env, BD/RÉPLICA, SERVICIOS
# ─────────────────────────────────────────────────────────────────────────────
say "Paso 6/7 — Configuración, base de datos y servicios"

if [ "$ROLE" != "secondary" ]; then
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    FERNET_KEY=$(venv/bin/python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
fi

cat > "$APP_DIR/.env" <<ENV
# Generado por install-satom.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ)
SECRET_KEY=${SECRET_KEY}
FERNET_KEY=${FERNET_KEY}
SQLALCHEMY_DATABASE_URI=postgresql+psycopg://${DB_USER}:${DB_PASS}@127.0.0.1/${DB_NAME}
FLASK_ENV=production
NODE_IP=${NODE_IP}
WEB_PORT=${WEB_PORT}
ENV
chmod 600 "$APP_DIR/.env"
ok ".env escrito (secretos con permisos 600)"

if [ "$ROLE" = "primary" ]; then
    REPL_PASS=$(openssl rand -hex 24)
    runuser -u postgres -- psql -qc "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='${REPL_USER}') THEN CREATE ROLE ${REPL_USER} REPLICATION LOGIN PASSWORD '${REPL_PASS}'; ELSE ALTER ROLE ${REPL_USER} REPLICATION LOGIN PASSWORD '${REPL_PASS}'; END IF; END \$\$;"
    # TLS + réplica en postgresql.conf (idempotente vía conf.d)
    mkdir -p "$PGCONF/conf.d"
    cat > "$PGCONF/conf.d/satom.conf" <<PGC
listen_addresses = '*'
ssl = on
ssl_cert_file = '${PGSSL}/server.crt'
ssl_key_file  = '${PGSSL}/server.key'
ssl_ca_file   = '${PGSSL}/ca.crt'
wal_level = replica
max_wal_senders = 5
PGC
    grep -q "include_dir = 'conf.d'" "$PGCONF_FILE" || echo "include_dir = 'conf.d'" >> "$PGCONF_FILE"
    # pg_hba: réplica SOLO por TLS con cert de la CA del clúster + scram
    if ! grep -q "SATOM-HA" "$PGHBA"; then
        cat >> "$PGHBA" <<HBA
# SATOM-HA (añadido por install-satom.sh)
hostssl replication ${REPL_USER} ${SECONDARY_CIDR} scram-sha-256 clientcert=verify-ca
hostssl ${DB_NAME} ${DB_USER} ${SECONDARY_CIDR} scram-sha-256
HBA
    fi
    systemctl restart postgresql
    ok "Postgres primary: TLS forzado + rol de réplica (${REPL_USER}) listo"

    # Llave SSH dedicada para el datasync de data/ (el standby hace PULL)
    if [ ! -f /root/.ssh/id_ha_rsync ]; then
        ssh-keygen -t ed25519 -N "" -q -f /root/.ssh/id_ha_rsync -C "satom-ha-datasync"
    fi
    grep -qF "$(cat /root/.ssh/id_ha_rsync.pub)" /root/.ssh/authorized_keys 2>/dev/null \
        || cat /root/.ssh/id_ha_rsync.pub >> /root/.ssh/authorized_keys
fi

if [ "$ROLE" = "secondary" ]; then
    say "Configurando réplica streaming desde ${PRIMARY_IP}"
    systemctl stop postgresql
    # Certificado de cliente para la réplica (el que acabamos de emitir).
    # El home de postgres varía por distro — usamos el real ($PGHOME).
    mkdir -p "$PGHOME/.postgresql"
    cp "$PKI/node/leaf.crt" "$PGHOME/.postgresql/postgresql.crt"
    cp "$PKI/node/leaf.key" "$PGHOME/.postgresql/postgresql.key"
    cp "$PKI/internal-ca/ca.crt" "$PGHOME/.postgresql/root.crt"
    chown -R postgres:postgres "$PGHOME/.postgresql"
    chmod 600 "$PGHOME/.postgresql/postgresql.key"
    rm -rf "${PGDATA}"
    runuser -u postgres -- env PGPASSWORD="$REPL_PASS" pg_basebackup \
        -h "$PRIMARY_IP" -U "$REPL_USER" -D "$PGDATA" -R -X stream -C -S "ofm_$(hostname | tr -c 'a-z0-9' '_')" \
        -d "sslmode=verify-ca sslrootcert=$PGHOME/.postgresql/root.crt sslcert=$PGHOME/.postgresql/postgresql.crt sslkey=$PGHOME/.postgresql/postgresql.key" \
        >>"$INSTALL_LOG" 2>&1 || die "pg_basebackup falló — verifica que el primary permite réplica desde esta IP (revisa $INSTALL_LOG)"
    mkdir -p "$PGCONF/conf.d"
    cat > "$PGCONF/conf.d/satom.conf" <<PGC
listen_addresses = '*'
ssl = on
ssl_cert_file = '${PGSSL}/server.crt'
ssl_key_file  = '${PGSSL}/server.key'
ssl_ca_file   = '${PGSSL}/ca.crt'
PGC
    grep -q "include_dir = 'conf.d'" "$PGCONF_FILE" || echo "include_dir = 'conf.d'" >> "$PGCONF_FILE"
    systemctl start postgresql
    sleep 3
    REC=$(runuser -u postgres -- psql -tAc "SELECT pg_is_in_recovery()" | tr -d '[:space:]')
    [ "$REC" = "t" ] && ok "Réplica streaming ACTIVA (pg_is_in_recovery = t)" \
                     || die "La réplica no quedó en recovery — revisa $INSTALL_LOG"

    # Llave del datasync + registro de nodos
    if [ -n "$RSYNC_PRIV" ]; then
        printf '%s\n' "$RSYNC_PRIV" > /root/.ssh/id_ha_rsync
        chmod 600 /root/.ssh/id_ha_rsync
    fi
    python3 - <<PYNODES
import json
nodes = [
    {"name": "${PRIMARY_NAME}", "host": "${PRIMARY_IP}", "role": "primary"},
    {"name": "$(hostname)", "host": "${NODE_IP}", "role": "standby"},
]
json.dump(nodes, open("${APP_DIR}/data/ha_nodes.json", "w"), indent=2)
PYNODES
    ok "ha_nodes.json escrito (primary=${PRIMARY_IP}, standby=${NODE_IP})"
fi

# Inicialización de BD + clave admin (solo donde la BD es escribible)
if [ "$ROLE" != "secondary" ]; then
    set -a; . "$APP_DIR/.env"; set +a
    FLASK_APP=wsgi.py venv/bin/flask create-db >>"$INSTALL_LOG" 2>&1
    export OFM_ADMIN_PASS="$ADMIN_PASS"
    venv/bin/python - <<PYADM >>"$INSTALL_LOG" 2>&1
from wsgi import app
from app.extensions import db
from app.models import User
import os
with app.app_context():
    u = User.query.filter_by(username="admin").first()
    u.set_password(os.environ["OFM_ADMIN_PASS"])
    db.session.commit()
    print("admin password set")
PYADM
    ok "BD inicializada y clave de 'admin' establecida"
    unset OFM_ADMIN_PASS
fi

# systemd units
say "Instalando servicios systemd"
for unit in satom.service satom-scheduler.service \
            satom-updater.path satom-updater.service \
            satom-cert-renew.service satom-cert-renew.timer; do
    [ -f "$APP_DIR/deploy/$unit" ] && cp "$APP_DIR/deploy/$unit" /etc/systemd/system/
done
# gunicorn SOLO en loopback: nginx termina TLS en ${WEB_PORT}
sed -i 's#--bind 0\.0\.0\.0:8000#--bind 127.0.0.1:8000#' /etc/systemd/system/satom.service

if [ "$MODE" = "cluster" ]; then
    cat > /etc/systemd/system/satom-ha-datasync.service <<UNIT
[Unit]
Description=SATOM HA data/ sync (standby pulls from primary)
[Service]
Type=oneshot
ExecStart=${APP_DIR}/deploy/satom-ha-datasync.sh
UNIT
    cat > /etc/systemd/system/satom-ha-datasync.timer <<UNIT
[Unit]
Description=SATOM HA data/ sync every 5 min
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
UNIT
fi

systemctl daemon-reload
systemctl enable --now satom.service satom-scheduler.service >>"$INSTALL_LOG" 2>&1
systemctl enable --now satom-updater.path >>"$INSTALL_LOG" 2>&1 || true
systemctl enable --now satom-cert-renew.timer >>"$INSTALL_LOG" 2>&1 || true
[ "$MODE" = "cluster" ] && systemctl enable --now satom-ha-datasync.timer >>"$INSTALL_LOG" 2>&1

# nginx: TLS en el puerto elegido con el cert del nodo.
# Debian/Ubuntu usan sites-available/enabled; el resto de familias conf.d.
if [ -d /etc/nginx/sites-enabled ]; then
    NGXCONF=/etc/nginx/sites-available/satom.conf
else
    mkdir -p /etc/nginx/conf.d
    NGXCONF=/etc/nginx/conf.d/satom.conf
    # Arch no incluye conf.d de fábrica — lo enganchamos al bloque http
    grep -qE '^\s*include\s+/etc/nginx/conf\.d/\*\.conf' /etc/nginx/nginx.conf \
        || sed -i '0,/http\s*{/s//&\n    include \/etc\/nginx\/conf.d\/*.conf;/' /etc/nginx/nginx.conf
fi
cat > "$NGXCONF" <<NGX
server {
    listen ${WEB_PORT} ssl http2;
    server_name ${HOSTN} ${NODE_IP};
    ssl_certificate     ${PKI}/public/server.crt;
    ssl_certificate_key ${PKI}/public/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 200M;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 120s;
    }
}
NGX
if [ -d /etc/nginx/sites-enabled ]; then
    ln -sf /etc/nginx/sites-available/satom.conf /etc/nginx/sites-enabled/satom.conf
    rm -f /etc/nginx/sites-enabled/default
fi
# SELinux (RHEL/Fedora): permitir que nginx haga proxy al gunicorn local y
# escuche en un puerto no estándar — best-effort, nunca rompe la instalación
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
    setsebool -P httpd_can_network_connect 1 >>"$INSTALL_LOG" 2>&1 || warn "SELinux: no pude activar httpd_can_network_connect"
    if command -v semanage >/dev/null 2>&1; then
        semanage port -a -t http_port_t -p tcp "$WEB_PORT" >>"$INSTALL_LOG" 2>&1 \
            || semanage port -m -t http_port_t -p tcp "$WEB_PORT" >>"$INSTALL_LOG" 2>&1 || true
    fi
fi
# firewalld (RHEL/SUSE): abrir el puerto web (+5432 en primary de clúster)
if systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-port="${WEB_PORT}/tcp" >>"$INSTALL_LOG" 2>&1 || true
    [ "$ROLE" = "primary" ] && firewall-cmd --permanent --add-port=5432/tcp >>"$INSTALL_LOG" 2>&1 || true
    firewall-cmd --reload >>"$INSTALL_LOG" 2>&1 || true
    ok "firewalld: puerto ${WEB_PORT}/tcp abierto"
fi
nginx -t >>"$INSTALL_LOG" 2>&1 || die "nginx -t falló (revisa $INSTALL_LOG)"
systemctl enable --now nginx >>"$INSTALL_LOG" 2>&1; systemctl reload nginx
ok "nginx sirviendo HTTPS en ${NODE_IP}:${WEB_PORT}"

# ─────────────────────────────────────────────────────────────────────────────
# PASO 7 — COMPROBACIÓN DE SALUD + RESUMEN
# ─────────────────────────────────────────────────────────────────────────────
say "Paso 7/7 — Comprobación de salud"
HEALTH=fail
for i in $(seq 1 30); do
    if curl -skf --max-time 3 "https://127.0.0.1:${WEB_PORT}/healthz" >/dev/null 2>&1; then HEALTH=ok; break; fi
    sleep 1
done
if [ "$HEALTH" = ok ]; then
    ok "healthz responde 200 — instalación COMPLETA"
else
    warn "healthz no respondió en 30 s — revisa: journalctl -u satom -n 50"
fi

echo ""
echo "┌──────────────────────────────────────────────────────────┐"
echo "│  SATOM instalado                                     │"
echo "└──────────────────────────────────────────────────────────┘"
echo "  Consola web : https://${NODE_IP}:${WEB_PORT}/"
[ "$ROLE" != "secondary" ] && echo "  Usuario     : admin  (clave: la que definiste)"
echo "  Servicios   : satom, satom-scheduler$( [ "$MODE" = cluster ] && echo ', satom-ha-datasync.timer' )"
echo "  Logs        : ${LOG_DIR}/  ·  instalación: ${INSTALL_LOG}"

if [ "$ROLE" = "primary" ]; then
    # Registro de nodos del propio primary
    python3 - <<PYNODES
import json
json.dump([{"name": "$(hostname)", "host": "${NODE_IP}", "role": "primary"}],
          open("${APP_DIR}/data/ha_nodes.json", "w"), indent=2)
PYNODES
    JOIN_JSON=$(python3 - <<PYJOIN
import base64, json
blob = {
    "primary_ip": "${NODE_IP}",
    "primary_port": "${WEB_PORT}",
    "primary_name": "$(hostname)",
    "fernet_key": "${FERNET_KEY}",
    "secret_key": "${SECRET_KEY}",
    "db_password": "${DB_PASS}",
    "repl_password": "${REPL_PASS}",
    "ca_crt": open("${PKI}/internal-ca/ca.crt").read(),
    "ca_key": open("${PKI}/internal-ca/ca.key").read(),
    "rsync_key": open("/root/.ssh/id_ha_rsync").read(),
}
print("OFMJOIN1." + base64.b64encode(json.dumps(blob).encode()).decode())
PYJOIN
)
    echo ""
    echo "${c_bold}══════════ CLAVE DE UNIÓN DEL CLÚSTER (nodo secondary) ══════════${c_off}"
    echo ""
    echo "${JOIN_JSON}"
    echo ""
    echo "${c_ylw}⚠ TRÁTALA COMO UN SECRETO:${c_off} contiene la CA y las claves de"
    echo "  sincronización del clúster. Pégala en el instalador del nodo secondary"
    echo "  y BÓRRALA de cualquier chat/nota después de usarla."
    echo "═══════════════════════════════════════════════════════════════════"
fi

if [ "$ROLE" = "secondary" ]; then
    echo ""
    echo "  Nodo SECONDARY unido al clúster:"
    echo "   • Postgres réplica streaming de ${PRIMARY_IP} (TLS verify-ca)"
    echo "   • data/ se sincroniza cada 5 min (satom-ha-datasync.timer)"
    echo "   • Certificado TLS propio emitido por la CA del clúster"
    echo "   • El scheduler queda en espera (solo se activa si promueves este nodo)"
fi

echo ""
echo "Siguiente paso recomendado: cambia la clave de root del sistema y"
echo "deshabilita el acceso SSH por contraseña (ver docs/INSTALL.md §Hardening)."
