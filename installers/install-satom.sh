#!/usr/bin/env bash
# ============================================================================
# install-satom.sh — Instalador de SATOM (System Automation & Task
# Orchestration Manager) — GENÉRICO para distribuciones Linux con systemd.
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

VERSION="1.5.0"
APP_DIR="/opt/satom"
ACME_WEBROOT="/var/www/acme"
LEGO_VERSION="5.2.2"
VM_VERSION="1.148.0"
VM_SHA256="bde7ea38c7c9b341a0bb1f37294d6d619ff0318d70174008b57d83cd4f5698f3"   # victoria-metrics-prod, release checksums
LOG_DIR="/var/log/satom"
# Cuenta de servicio sin privilegios. La app NO corre como root: ver
# docs/privilege-model.md. Se puede sobreescribir para migrar una instalación
# heredada que ya use otro nombre (p.ej. SATOM_APP_USER=fortinet).
APP_USER="${SATOM_APP_USER:-satom}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="${SCRIPT_DIR}/bundle"
# Public source of record. The previous default pointed at a private Gitea
# that only resolves inside one company's network, so an unattended install
# anywhere else hung on a clone it could never complete.
GIT_URL_DEFAULT="https://github.com/visionebc/SATOM.git"
DB_NAME="satom"
DB_USER="satom"
REPL_USER="fm_repl"
INSTALL_LOG="/var/log/satom-install.log"

c_bold=$'\033[1m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_red=$'\033[31m'; c_off=$'\033[0m'
say()  { echo "${c_bold}==>${c_off} $*" | tee -a "$INSTALL_LOG"; }
ok()   { echo "    ${c_grn}✓${c_off} $*" | tee -a "$INSTALL_LOG"; }
warn() { echo "    ${c_ylw}!${c_off} $*" | tee -a "$INSTALL_LOG"; }
die()  { echo "${c_red}ERROR:${c_off} $*" | tee -a "$INSTALL_LOG" >&2; exit 1; }

# ── Lectura de prompts ─────────────────────────────────── [SATOM-LOUD-READ]
# `read` devuelve !=0 al recibir EOF. Con `set -euo pipefail` eso mata el
# instalador SIN IMPRIMIR NADA: la ultima linea que ve el operador es la del
# paso anterior y el rc=1 no dice donde murio. Ocurre siempre que se conduce
# por tuberia o here-doc y la secuencia de respuestas es mas corta que la de
# prompts — y los caminos ONLINE y OFFLINE NO tienen el mismo numero (el
# online pregunta ademas la URL del repo). Es la misma clase de fallo que
# [SATOM-LOUD-DB]: un fallo mudo es un fallo que nadie encuentra.
# TODO prompt del instalador pasa por aqui.
#   EOF con datos parciales (ultima linea sin salto) SI es respuesta valida y
#   se acepta — igual que un Ctrl-D despues de teclear en una terminal.
_ask_die() {
    die "No hay respuesta para el prompt: \"$1\"
    La entrada se agoto (EOF). Si conduces el instalador por tuberia o here-doc,
    la secuencia de respuestas es mas corta que la de prompts: el camino ONLINE
    pregunta la URL del repo y el OFFLINE no. Ejecutalo de forma interactiva, o
    anade la respuesta que falta."
}
ask() {                                  # ask VAR "prompt"  -> lee en $VAR
    local __v="$1" __p="$2" __rc=0
    read -rp "$__p" "$__v" || __rc=$?
    [ "$__rc" -eq 0 ] || [ -n "${!__v:-}" ] || _ask_die "$__p"
}
ask_secret() {                           # ask_secret VAR "prompt"  -> sin eco
    local __v="$1" __p="$2" __rc=0
    read -rsp "$__p" "$__v" || __rc=$?
    echo
    [ "$__rc" -eq 0 ] || [ -n "${!__v:-}" ] || _ask_die "$__p"
}

# ─────────────────────────────────────────────────────────────────────────────
# SUBCOMANDO: --print-sudoers  (NO requiere root — va antes del chequeo)
# Emite la regla sudoers de la CUENTA INSTALADORA, para entregarla a sistemas
# sin tener que enviarles el repositorio entero. Instalar SATOM es root; lo que
# esta regla evita es ENTREGAR LA CONTRASEÑA DE ROOT: se da una cuenta nominal
# que sólo puede lanzar un binario en una ruta fija. No confundir con
# /etc/sudoers.d/satom, que es la allowlist de dos comandos del RUNTIME.
#   sudo bash install-satom.sh --print-sudoers > /etc/sudoers.d/satom-installer
#   visudo -c
# ─────────────────────────────────────────────────────────────────────────────
if [ "${1:-}" = "--print-sudoers" ]; then
    INSTALLER_USER="${2:-satominstall}"
    cat <<SUDOEOF
# /etc/sudoers.d/satom-installer — permiso para EJECUTAR EL INSTALADOR.
# Generado por: install-satom.sh --print-sudoers ${INSTALLER_USER}
#
# Requisitos para que esto sea seguro:
#   install -d -m 0755 /opt/staging
#   install -m 0755 install-satom.sh /opt/staging/install-satom.sh
#   chown root:root /opt/staging/install-satom.sh   # el operador NO debe poder editarlo
# Si el operador pudiera escribir ese fichero, la regla equivale a NOPASSWD: ALL.
#
# Retirar al cerrar la ventana de instalación:
#   rm /etc/sudoers.d/satom-installer

Cmnd_Alias SATOM_INSTALL = /usr/bin/bash /opt/staging/install-satom.sh, \\
                           /usr/bin/bash /opt/staging/install-satom.sh --preflight, \\
                           /usr/bin/bash /opt/staging/install-satom.sh --check, \\
                           /usr/bin/bash /opt/staging/install-satom.sh --authorize-peer *

${INSTALLER_USER} ALL=(root) NOPASSWD: SATOM_INSTALL
SUDOEOF
    exit 0
fi

[ "$(id -u)" -eq 0 ] || die "Ejecuta como root (o con sudo): sudo bash $0"
mkdir -p "$(dirname "$INSTALL_LOG")"; touch "$INSTALL_LOG"

# ─────────────────────────────────────────────────────────────────────────────
# SUBCOMANDO: --authorize-peer <ip-del-standby> "<clave-publica-ssh>"
# Se ejecuta en el PRIMARY para confiar en un standby. Sustituye al viejo
# modelo donde el primary generaba el par y mandaba la PRIVADA dentro de la
# join key. Aquí sólo entra una clave PÚBLICA, y encima acotada:
#   from=      → sólo desde la IP del standby
#   restrict   → sin pty, sin agent/port/X11 forwarding, sin user-rc
#   command=   → sólo un rsync de SÓLO LECTURA de data/ (wrapper propio)
# ─────────────────────────────────────────────────────────────────────────────
if [ "${1:-}" = "--authorize-peer" ]; then
    PEER_IP="${2:-}"; PEER_PUBKEY="${3:-}"
    [ -n "$PEER_IP" ] && [ -n "$PEER_PUBKEY" ] \
        || die "Uso: $0 --authorize-peer <ip-del-standby> \"<clave-publica-ssh>\""
    [[ "$PEER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "La IP del standby no es válida: $PEER_IP"
    [[ "$PEER_PUBKEY" == ssh-ed25519\ * || "$PEER_PUBKEY" == ssh-rsa\ * ]] \
        || die "Eso no parece una clave pública SSH (debe empezar por ssh-ed25519 o ssh-rsa)"
    id -u "$APP_USER" >/dev/null 2>&1 || die "El usuario de servicio ${APP_USER} no existe — ¿instalaste este nodo?"

    # ---- SHELL PARA EL DATASYNC -----------------------------------------
    # La cuenta de servicio es 'nologin' por defecto, y eso es lo correcto
    # mientras no reciba SSH. Este subcomando es justo el punto donde
    # decidimos que SÍ lo recibe: sshd ejecuta el login shell para lanzar el
    # forced command, así que con nologin la conexión se rechaza siempre.
    # Abrimos el shell mínimo AQUÍ y no antes. Sigue acotado por:
    #   · contraseña bloqueada (la cuenta no tiene login interactivo)
    #   · from= + restrict + command= en authorized_keys
    CUR_SHELL="$(getent passwd "$APP_USER" | cut -d: -f7)"
    case "$CUR_SHELL" in
        */nologin|*/false)
            SH_BIN="$(command -v sh || echo /bin/sh)"
            usermod -s "$SH_BIN" "$APP_USER"
            warn "Shell de ${APP_USER}: ${CUR_SHELL} → ${SH_BIN} (sshd lo necesita para el forced command)"
            ;;
    esac
    # La contraseña DEBE seguir bloqueada: el shell no es una vía de entrada.
    passwd -l "$APP_USER" >/dev/null 2>&1 || true

    SHELL_WRAPPER=/usr/local/sbin/satom-ha-rsync-shell
    [ -x "$SHELL_WRAPPER" ] || die "Falta $SHELL_WRAPPER (reinstala o copia deploy/satom-ha-rsync-shell)"

    AK="$APP_DIR/.ssh/authorized_keys"
    install -d -m 700 -o "$APP_USER" -g "$APP_USER" "$APP_DIR/.ssh"
    touch "$AK"; chown "$APP_USER:$APP_USER" "$AK"; chmod 600 "$AK"
    KEYBODY="$(echo "$PEER_PUBKEY" | awk '{print $1" "$2}')"
    if grep -qF "$KEYBODY" "$AK"; then
        ok "Esa clave ya estaba autorizada — no se duplica"
    else
        printf 'from="%s",restrict,command="%s" %s\n' \
            "$PEER_IP" "$SHELL_WRAPPER" "$PEER_PUBKEY" >> "$AK"
        ok "Standby ${PEER_IP} autorizado (sólo rsync de lectura sobre data/)"
    fi
    # ---- SATOM-HANODES-MERGE --------------------------------------------
    # data/ se replica primary -> standby con `rsync --delete`, asi que
    # ha_nodes.json del PRIMARY es la copia autoritativa: la de dos entradas
    # que el instalador escribe en el secondary se borra en el primer sync.
    # Este es el punto donde el primary conoce la IP de su pareja.
    PEER_NAME="${4:-}"
    if [ -z "$PEER_NAME" ]; then
        PEER_NAME="$(getent hosts "$PEER_IP" 2>/dev/null | awk '{print $2}' | head -1)"
        PEER_NAME="${PEER_NAME%%.*}"
    fi
    [ -n "$PEER_NAME" ] || PEER_NAME="$PEER_IP"
    if [ -x "$APP_DIR/venv/bin/python" ]; then
        SATOM_PEER_IP="$PEER_IP" SATOM_PEER_NAME="$PEER_NAME" \
        SATOM_APP_DIR="$APP_DIR" "$APP_DIR/venv/bin/python" - <<'PYNODES' && \
            chown "$APP_USER:$APP_USER" "$APP_DIR/data/ha_nodes.json" 2>/dev/null || true
import json, os, socket

app = os.environ["SATOM_APP_DIR"]
ip = os.environ["SATOM_PEER_IP"]
name = os.environ["SATOM_PEER_NAME"]
path = os.path.join(app, "data", "ha_nodes.json")

try:
    nodes = json.load(open(path))
    if not isinstance(nodes, list):
        raise ValueError
except Exception:
    nodes = []

# Nunca se pisa una entrada que el operador haya editado en la UI: si la IP ya
# esta, se deja como esta.
if not any((n.get("host") or "").strip() == ip for n in nodes):
    if not any((n.get("role") or "") == "primary" for n in nodes):
        nodes.insert(0, {"name": socket.gethostname(), "host": "", "role": "primary"})
    nodes.append({"name": name, "host": ip, "role": "standby"})
    json.dump(nodes, open(path, "w"), indent=2)
    print("  ha_nodes.json: anadido %s (%s) como standby" % (name, ip))
else:
    print("  ha_nodes.json: %s ya estaba registrado" % ip)
PYNODES
    else:
        warn "No encuentro ${APP_DIR}/venv/bin/python — registra el standby a mano en Software Update → HA nodes"
    fi

    echo ""
    echo "Compruébalo desde el standby:"
    echo "  sudo -u ${APP_USER} ssh -i ${APP_DIR}/.ssh/id_ha_rsync ${APP_USER}@<ip-primary> true"
    echo "  → debe RECHAZAR la shell interactiva. Eso es correcto."
    exit 0
fi

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
    apt)        REQUIRED_PKGS=(python3 python3-venv python3-pip postgresql nginx rsync openssl curl ca-certificates sudo git) ;;
    dnf|yum)    REQUIRED_PKGS=(python3.11 python3.11-pip postgresql-server postgresql nginx rsync openssl curl ca-certificates sudo git) ;;
    zypper)     REQUIRED_PKGS=(python311 python311-pip postgresql-server postgresql nginx rsync openssl curl ca-certificates sudo git) ;;
    pacman)     REQUIRED_PKGS=(python python-pip postgresql nginx rsync openssl curl ca-certificates sudo git) ;;
esac
ONLINE_EXTRA_PKGS=(git)

# Paquetes de SSH: SÓLO se instalan en modo cluster (el canal de sincronización
# de data/ es rsync sobre SSH). Un nodo standalone no necesita sshd para el
# producto, así que no se le impone.                                    [PFSSH]
case "$PKG_MGR" in
    apt)        SSH_PKGS=(openssh-client openssh-server) ;;
    dnf|yum)    SSH_PKGS=(openssh-clients openssh-server) ;;
    zypper)     SSH_PKGS=(openssh) ;;
    pacman)     SSH_PKGS=(openssh) ;;
esac

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
elif [ -d "$BUNDLE_DIR" ] && [ -d "$BUNDLE_DIR/rpms-suse" ]; then
    # Directorio propio a proposito: los dos bundles son .rpm y NO son
    # intercambiables (python311 vs python3.11, librerias base distintas, y
    # zypper y dnf no leen los repos igual). Separarlos convierte "bundle
    # equivocado" en un error explicito aqui, en vez de una resolucion de
    # dependencias que revienta a mitad de la instalacion.
    case "$PKG_MGR" in
        zypper) OFFLINE=1 ;;
        *) die "El bundle offline contiene paquetes .rpm de openSUSE/SLES y esta máquina usa ${PKG_MGR}. Usa el instalador en modo ONLINE (borra o renombra bundle/) o genera el bundle para esta familia." ;;
    esac
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
# ─────────────────────────────────────────────────────────────────────────────
# PASO 0 — PREFLIGHT: ¿tenemos permisos y entorno para instalar?          [PF0]
#
# Corre ANTES de preguntar nada y ANTES de modificar el sistema. Acumula TODOS
# los problemas y los reporta juntos: quien pide una ventana de cambio necesita
# la lista completa, no el primer fallo. Se puede correr en seco:
#
#     sudo bash install-satom.sh --preflight
#
# Devuelve 0 si la máquina está lista, 1 con la lista de bloqueadores si no.
# ─────────────────────────────────────────────────────────────────────────────
PF_FAIL=(); PF_WARN=()
pf_bad()  { PF_FAIL+=("$1"); echo "    ${c_red}✗${c_off} $1" | tee -a "$INSTALL_LOG"; }
pf_warn() { PF_WARN+=("$1"); warn "$1"; }
pf_have() { command -v "$1" >/dev/null 2>&1; }
# ¿el bundle OFFLINE trae este paquete? Evita prometer "el paso 2 lo instala"
# cuando no hay red y el paquete no viaja en el medio.  [PFSUDO]
pf_bundle_has() {
    [ $OFFLINE -eq 1 ] || return 1
    ls "$BUNDLE_DIR"/debs/"$1"_*.deb  >/dev/null 2>&1 && return 0
    ls "$BUNDLE_DIR"/rpms/"$1"-[0-9]*.rpm >/dev/null 2>&1 && return 0
    ls "$BUNDLE_DIR"/rpms-suse/"$1"-[0-9]*.rpm >/dev/null 2>&1 && return 0
    return 1
}

pf_writable() {  # pf_writable <dir> → 0 si se puede escribir (sube al padre si no existe)
    local d="$1"
    while [ ! -d "$d" ] && [ "$d" != "/" ]; do d="$(dirname "$d")"; done
    local p="${d}/.satom-probe.$$"
    if ( : > "$p" ) 2>/dev/null; then rm -f "$p"; return 0; fi
    return 1
}

pf_free_mb() {   # pf_free_mb <ruta> → MB libres en su punto de montaje
    local d="$1"
    while [ ! -d "$d" ] && [ "$d" != "/" ]; do d="$(dirname "$d")"; done
    df -Pk "$d" 2>/dev/null | awk 'NR==2{printf "%d", $4/1024}'
}

pf_https_ok() {  # pf_https_ok <url> → 0 alcanzable · 1 no · 2 sin herramienta [PFHTTPS]
    if pf_have curl; then curl -fsSk -m 8 -o /dev/null "$1" 2>/dev/null; return $?; fi
    # Una imagen mínima puede no traer curl (se instala en el paso 2), pero
    # python3 sí está: sirve igual para comprobar la salida HTTPS.
    local py="" c
    for c in python3.12 python3.11 python3; do pf_have "$c" && { py="$c"; break; }; done
    [ -n "$py" ] || return 2
    "$py" - "$1" <<'PFPY' 2>/dev/null
import sys, ssl, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    urllib.request.urlopen(sys.argv[1], timeout=8, context=ctx)
except Exception:
    sys.exit(1)
PFPY
}

pf_git_probe() {  # pf_git_probe <url-repo> → imprime el codigo HTTP, o vacio
    # Sondea el endpoint REAL de git, no la raiz del host: un repositorio
    # privado devuelve 401/403 aqui mientras la raiz del servidor responde 200.
    local u="${1%.git}.git/info/refs?service=git-upload-pack"
    pf_have curl || return 2
    curl -sSk -m 8 -o /dev/null -w "%{http_code}" "$u" 2>/dev/null
}

pf_port_owner() {  # pf_port_owner <puerto> → nombre del proceso que escucha, o vacío
    local line="" name=""                                              # [PFOWNER]
    if pf_have ss; then
        line="$(ss -Hlntp "sport = :$1" 2>/dev/null | head -1)"
    elif pf_have netstat; then
        line="$(netstat -lntp 2>/dev/null | awk -v p=":$1\$" '$4 ~ p {print; exit}')"
    fi
    [ -n "$line" ] || return 0
    # ss/netstat imprimen users:(("nginx",pid=…)) — nos quedamos con el nombre.
    name="$(printf '%s' "$line" | grep -oE '"[^"]+"' | head -1 | tr -d '"')"
    [ -z "$name" ] && name="$(printf '%s' "$line" | awk '{print $NF}')"
    echo "$name"
}

preflight() {
    say "Paso 0/7 — Preflight: permisos y entorno (no se modifica nada)"

    # ---- 1. PRIVILEGIOS -----------------------------------------------------
    # Ser uid 0 no basta: un LXC no privilegiado, un / montado en ro o SELinux
    # pueden dejarte "root" y sin poder escribir donde hace falta.
    ok "Identidad: root (uid 0)"
    local d
    for d in /opt /etc /etc/systemd/system /var/log /usr/local/sbin; do
        if pf_writable "$d"; then ok "Escritura verificada en ${d}"
        else pf_bad "Sin escritura en ${d} — eres root pero el sistema de ficheros lo impide (montaje ro, LXC no privilegiado o SELinux)"; fi
    done

    # ---- 2. INIT ------------------------------------------------------------
    if [ -d /run/systemd/system ]; then ok "systemd es el init (PID 1)"
    else pf_bad "systemd no está corriendo como PID 1 (el binario systemctl existe pero no hay bus). Contenedores sin systemd no están soportados."; fi

    # ---- 3. PAQUETERÍA ------------------------------------------------------
    ok "Gestor de paquetes: ${PKG_MGR}$( [ $OFFLINE -eq 1 ] && echo ' (modo OFFLINE, bundle local)' )"

    # ---- 4. BINARIOS QUE DEBEN VENIR EN LA IMAGEN BASE ----------------------
    # Estos NO los instala el paso 2: si faltan, la imagen es demasiado mínima.
    local miss=() b
    for b in useradd usermod passwd getent install runuser tar awk sed grep hostname df; do
        pf_have "$b" || miss+=("$b")
    done
    if [ ${#miss[@]} -eq 0 ]; then ok "Utilidades base presentes (shadow, util-linux, coreutils)"
    else pf_bad "Faltan utilidades base: ${miss[*]} — instala los paquetes shadow/util-linux/coreutils de tu distro"; fi
    pf_have ss || pf_have netstat || pf_warn "Sin 'ss' ni 'netstat': no se puede comprobar si los puertos están libres"

    # ---- 4b. SUDO — el modelo de privilegio depende de él  [PFSUDO] ---------
    # El paso 6 escribe /etc/sudoers.d/satom y lo valida con 'visudo -cf'. Si sudo
    # no está, esa validación falla y el instalador aborta DESPUÉS de haber creado
    # el usuario y hecho chown -R del árbol. Se comprueba aquí para que sea un
    # bloqueador temprano y legible, no un fallo tardío a medio camino.
    local sudo_miss=() sb
    for sb in sudo visudo; do pf_have "$sb" || sudo_miss+=("$sb"); done
    if [ ${#sudo_miss[@]} -eq 0 ]; then
        ok "sudo y visudo presentes (allowlist del servicio: nginx -t, systemctl reload nginx)"
    elif [ $OFFLINE -eq 0 ]; then
        pf_warn "Faltan ${sudo_miss[*]} — el paso 2 instalará el paquete 'sudo'"
    elif pf_bundle_has sudo; then
        ok "Faltan ${sudo_miss[*]}, pero el bundle offline trae el paquete 'sudo'"
    else
        pf_bad "Faltan ${sudo_miss[*]} y el bundle OFFLINE no trae 'sudo'. Instálalo desde el medio de tu distro y repite (el paso 6 lo necesita para escribir /etc/sudoers.d)."
    fi

    # ---- 5. PYTHON ----------------------------------------------------------
    local pv="" c
    for c in python3.12 python3.11 python3; do
        pf_have "$c" || continue
        if "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
            pv="$($c --version 2>&1)"; break
        fi
    done
    if [ -n "$pv" ]; then ok "Python apto: ${pv} (mínimo 3.10)"
    else pf_warn "No hay Python >= 3.10 — se instalará el de la distro en el paso 2"; fi

    # ---- 6. DISCO Y MEMORIA -------------------------------------------------
    local opt_mb var_mb ram_mb
    opt_mb=$(pf_free_mb /opt); var_mb=$(pf_free_mb /var)
    if [ "${opt_mb:-0}" -lt 4000 ]; then pf_bad "Sólo ${opt_mb} MB libres en /opt — el código + venv + reportes necesitan bastante más (mínimo operable 4 GB, recomendado 15 GB)"
    elif [ "${opt_mb:-0}" -lt 15000 ]; then pf_warn "/opt tiene ${opt_mb} MB libres; se recomiendan 15 GB (crece con backups y reportes)"
    else ok "/opt: ${opt_mb} MB libres"; fi
    if [ "${var_mb:-0}" -lt 2000 ]; then pf_warn "/var tiene sólo ${var_mb} MB libres (ahí viven Postgres y los logs)"
    else ok "/var: ${var_mb} MB libres"; fi
    ram_mb=$(awk '/^MemTotal:/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
    if [ "${ram_mb:-0}" -lt 1800 ]; then pf_warn "RAM total ${ram_mb} MB — el mínimo soportado son 2 GB"
    else ok "RAM: ${ram_mb} MB"; fi

    # ---- 7. INSTALACIÓN YA EXISTENTE ---------------------------------------
    # Reinstalar encima de un nodo vivo reescribe .env y la configuración de
    # servicios. Es un bloqueador explícito, no un aviso.
    if systemctl is-active --quiet satom.service 2>/dev/null; then
        if [ "${SATOM_ALLOW_REINSTALL:-0}" = "1" ]; then
            pf_warn "satom.service está ACTIVO y SATOM_ALLOW_REINSTALL=1 — se reinstalará encima bajo tu responsabilidad"
        else
            pf_bad "satom.service ya está ACTIVO en esta máquina: reinstalar encima reescribe .env y las unidades. Para actualizar usa la página Software Update, o exporta SATOM_ALLOW_REINSTALL=1 si de verdad quieres reinstalar."
        fi
    elif [ -d "${APP_DIR}/app" ]; then
        pf_warn "${APP_DIR} ya contiene código (servicio parado) — se conservará y sólo se actualizarán dependencias"
    else
        ok "No hay instalación previa en ${APP_DIR}"
    fi

    # ---- 8. PUERTOS FIJOS DEL PRODUCTO -------------------------------------
    # El puerto de la consola se pregunta en el paso 1 y se comprueba allí.
    # 80 (redirección + challenge ACME) y 8443 (sondas entre nodos) son fijos.
    local o
    for p in 80 8443; do
        o="$(pf_port_owner "$p")"
        [ -n "$o" ] && pf_warn "El puerto ${p} ya está ocupado (${o}) — nginx lo necesita para $( [ "$p" = 80 ] && echo 'la redirección y el challenge ACME' || echo 'las sondas entre nodos' )"
    done

    # ---- 9. RELOJ -----------------------------------------------------------
    # Un reloj desviado rompe TLS, la validación ACME y la réplica con verify-ca.
    if pf_have timedatectl; then
        if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = "yes" ]; then
            ok "Reloj sincronizado por NTP ($(date -u '+%Y-%m-%dT%H:%M:%SZ'))"
        else
            pf_warn "El reloj NO está sincronizado por NTP — los certificados TLS y el challenge ACME fallarán si hay desviación"
        fi
    fi

    # ---- 10. RED (sólo modo ONLINE) ----------------------------------------
    if [ $OFFLINE -eq 0 ]; then
        local githost; githost="$(echo "$GIT_URL_DEFAULT" | awk -F/ '{print $3}')"
        if pf_have getent && ! getent hosts "$githost" >/dev/null 2>&1; then
            pf_warn "DNS no resuelve ${githost} (podrás indicar otra URL de repo en el paso 3)"
        fi
        pf_https_ok "https://pypi.org/simple/"; case $? in            # [PFNET2]
            0) ok "Salida a PyPI verificada (necesaria para el venv)" ;;
            1) pf_bad "Sin acceso a PyPI — el venv NO se puede construir. Usa el bundle OFFLINE o abre la salida HTTPS." ;;
            *) pf_warn "Sin curl ni python3: no se puede comprobar la salida a Internet" ;;
        esac
        pf_https_ok "https://${githost}/"; case $? in
            0) ok "Repositorio de código alcanzable (${githost})"
               # Alcanzable != clonable. Un repo privado responde 401 aqui.
               local _gitcode; _gitcode="$(pf_git_probe "$GIT_URL_DEFAULT")"
               case "$_gitcode" in
                   200|304) ok "Repositorio clonable sin credenciales" ;;
                   401|403) pf_warn "El repositorio ${GIT_URL_DEFAULT} es PRIVADO (HTTP ${_gitcode}). El paso 3 pedira usuario/contrasena; para instalar de forma desatendida da la URL con token: https://<usuario>:<token>@${githost}/..." ;;
                   404)     pf_warn "El repositorio ${GIT_URL_DEFAULT} devuelve 404 — ruta equivocada o sin permiso de lectura. Podras corregir la URL en el paso 3." ;;
                   "")      : ;;
                   *)       pf_warn "El repositorio respondio HTTP ${_gitcode} — el clon del paso 3 puede fallar" ;;
               esac ;;
            1) pf_warn "Sin acceso a https://${githost} — el clonado fallará (podrás indicar otra URL en el paso 3)" ;;
        esac
    fi

    # ---- 11. SELINUX / APPARMOR (informativo) ------------------------------
    if pf_have getenforce; then
        ok "SELinux: $(getenforce 2>/dev/null) $( [ "$(getenforce 2>/dev/null)" = "Enforcing" ] && echo '(el instalador aplicará los booleanos y puertos necesarios)' )"
    fi

    # ---- RESUMEN ------------------------------------------------------------
    echo ""
    if [ ${#PF_FAIL[@]} -gt 0 ]; then
        echo "${c_red}${c_bold}PREFLIGHT: ${#PF_FAIL[@]} bloqueador(es).${c_off} Nada se ha modificado." | tee -a "$INSTALL_LOG"
        local f; for f in "${PF_FAIL[@]}"; do echo "  ${c_red}✗${c_off} $f" | tee -a "$INSTALL_LOG"; done
        [ ${#PF_WARN[@]} -gt 0 ] && { echo "  — y ${#PF_WARN[@]} advertencia(s) —" ; for f in "${PF_WARN[@]}"; do echo "  ${c_ylw}!${c_off} $f"; done; }
        echo ""
        die "Corrige los bloqueadores y vuelve a ejecutar (o 'bash $0 --preflight' para re-verificar sin instalar)"
    fi
    if [ ${#PF_WARN[@]} -gt 0 ]; then
        echo "${c_ylw}${c_bold}PREFLIGHT OK con ${#PF_WARN[@]} advertencia(s):${c_off}" | tee -a "$INSTALL_LOG"
        local w; for w in "${PF_WARN[@]}"; do echo "  ${c_ylw}!${c_off} $w" | tee -a "$INSTALL_LOG"; done
    else
        echo "${c_grn}${c_bold}PREFLIGHT OK — la máquina cumple todos los requisitos.${c_off}" | tee -a "$INSTALL_LOG"
    fi
    echo ""
}

# Preflight específico de clúster. Se llama en cuanto se conoce el modo, que es
# lo antes posible: los binarios de SSH sólo hacen falta si hay un segundo nodo.
preflight_cluster() {
    say "Preflight de clúster — canal SSH entre nodos"
    local miss=() b
    for b in ssh ssh-keygen ssh-keyscan rsync; do pf_have "$b" || miss+=("$b"); done
    if [ ${#miss[@]} -eq 0 ]; then
        ok "Cliente SSH y rsync presentes"
    elif [ $OFFLINE -eq 1 ]; then
        # OFFLINE: sólo es fatal si el bundle tampoco los trae. Se comprueba el
        # paquete que corresponde a CADA binario que falta, no "alguno".  [PFSUDO]
        local nocover=() m sp covered
        for m in "${miss[@]}"; do
            covered=0
            if [ "$m" = "rsync" ]; then
                pf_bundle_has rsync && covered=1
            else
                for sp in "${SSH_PKGS[@]}"; do pf_bundle_has "$sp" && covered=1; done
            fi
            [ $covered -eq 1 ] || nocover+=("$m")
        done
        if [ ${#nocover[@]} -eq 0 ]; then
            ok "Faltan ${miss[*]}, pero el bundle offline trae sus paquetes"
        else
            die "Modo cluster: faltan ${nocover[*]}, estás en OFFLINE y el bundle no los trae (paquetes: ${SSH_PKGS[*]} rsync). Instálalos desde el medio de la distro y repite."
        fi
    else
        warn "Faltan ${miss[*]} — el paso 2 los instalará (${SSH_PKGS[*]} rsync)"
    fi
    # El PRIMARY debe tener sshd activo: el standby sincroniza data/ tirando (pull).
    if systemctl list-unit-files 2>/dev/null | grep -qE '^(ssh|sshd)\.service'; then
        if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
            ok "Servidor SSH instalado y activo"
        else
            warn "El servidor SSH está instalado pero no activo. En el PRIMARY debe estar arrancado: el standby sincroniza data/ por SSH."
        fi
    else
        warn "No hay servidor SSH instalado. Es obligatorio en el PRIMARY (el standby hace pull de data/ por SSH); se instalará ${SSH_PKGS[*]}."
    fi
}

if [ "${1:-}" = "--preflight" ] || [ "${1:-}" = "--check" ]; then
    echo ""
    echo "Modo verificación: sólo se comprueban permisos y requisitos. No se instala nada."
    preflight
    exit 0
fi

preflight

# ─────────────────────────────────────────────────────────────────────────────
# PASO 1 — PREGUNTAS (todo por adelantado; nada se toca hasta terminar aquí)
# ─────────────────────────────────────────────────────────────────────────────

# 1a. IP de esta máquina
DETECTED_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
ask NODE_IP "IP de esta máquina [${DETECTED_IP}]: "
NODE_IP="${NODE_IP:-$DETECTED_IP}"
[[ "$NODE_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "IP inválida: $NODE_IP"

# 1b. Puerto HTTPS
WEB_PORT=""
while [ -z "$WEB_PORT" ]; do                                            # [PFPORT]
    ask WEB_PORT "Puerto HTTPS de la consola web [443]: "
    WEB_PORT="${WEB_PORT:-443}"
    if ! [[ "$WEB_PORT" =~ ^[0-9]+$ ]] || [ "$WEB_PORT" -lt 1 ] || [ "$WEB_PORT" -gt 65535 ]; then
        warn "Puerto inválido: $WEB_PORT"; WEB_PORT=""; continue
    fi
    PORT_OWNER="$(pf_port_owner "$WEB_PORT")"
    if [ -n "$PORT_OWNER" ]; then
        # Si ya es nginx, es probablemente una reinstalación y se reutilizará.
        case "$PORT_OWNER" in
            *nginx*) warn "El puerto ${WEB_PORT} lo escucha nginx — se reutilizará su configuración" ;;
            *) warn "El puerto ${WEB_PORT} YA ESTÁ OCUPADO por: ${PORT_OWNER}"
               ask _pf_yes "  ¿Usarlo igualmente? nginx no podrá arrancar si el otro proceso sigue ahí [s/N]: "
               case "${_pf_yes,,}" in s|si|sí|y|yes) : ;; *) WEB_PORT=""; continue ;; esac ;;
        esac
    fi
done

# 1b2. Nombres DNS servidos                                   [SATOM-SERVED-NAMES]
# Los nombres por los que se ALCANZA este nodo tienen que conocerse AQUI, porque
# de ellos se acunan DOS cosas que despues no se arreglan sin volver a emitir:
# el server_name del vhost y la lista SAN del certificado del nodo.
# `hostname` a secas es el nombre CORTO. Un nodo alcanzado en consola.ejemplo.tld
# nacia con `server_name consola` -- que solo respondia porque el vhost ademas
# reclamaba default_server, o sea por accidente -- y con un certificado cuyo SAN
# decia DNS:consola, asi que TODO navegador que entraba por el FQDN recibia un
# aviso de nombre no coincidente sobre un certificado que el instalador acababa
# de reportar como bueno. El dato estaba disponible (`hostname -f`) y no se usaba.
DEFAULT_NAMES="$(hostname -f 2>/dev/null || true)"
if [ -z "$DEFAULT_NAMES" ]; then DEFAULT_NAMES="$(hostname)"; fi
if [ -n "${SATOM_SERVED_NAMES:-}" ]; then
    SERVED_NAMES="$SATOM_SERVED_NAMES"
else
    ask SERVED_NAMES "Nombre(s) DNS por los que se accede a esta consola [${DEFAULT_NAMES}]: "
fi
SERVED_NAMES="${SERVED_NAMES:-$DEFAULT_NAMES}"
# Normalizar: coma/punto-y-coma -> espacio, minusculas, sin duplicados.
_sn_norm=""
for _sn in $(printf '%s' "$SERVED_NAMES" | tr ',;' '  ' | tr 'A-Z' 'a-z'); do
    case " $_sn_norm " in *" $_sn "*) continue ;; esac
    _sn_norm="$_sn_norm $_sn"
done
SERVED_NAMES="${_sn_norm# }"
[ -n "$SERVED_NAMES" ] || die "Hace falta al menos un nombre DNS: de el salen el vhost y el certificado"
for _sn in $SERVED_NAMES; do
    [[ "$_sn" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || die "Nombre DNS invalido: $_sn"
done
# El nombre corto se sigue usando desde la propia maquina; entra tambien.
_sn_short="$(hostname | tr 'A-Z' 'a-z')"
case " $SERVED_NAMES " in
    *" $_sn_short "*) : ;;
    *) SERVED_NAMES="$SERVED_NAMES $_sn_short" ;;
esac

# 1c. Modo
MODE=""; ROLE="standalone"
while [ -z "$MODE" ]; do
    ask MODE "¿Instalación standalone o cluster? [standalone/cluster]: "
    case "${MODE,,}" in
        standalone|s) MODE="standalone" ;;
        cluster|c)    MODE="cluster" ;;
        *) warn "Responde 'standalone' o 'cluster'"; MODE="" ;;
    esac
done

if [ "$MODE" = "cluster" ]; then preflight_cluster; fi     # [PFCL]

JOIN_KEY_RAW=""
if [ "$MODE" = "cluster" ]; then
    ROLE=""
    while [ -z "$ROLE" ]; do
        ask ROLE "¿Este nodo es primary o secondary? [primary/secondary]: "
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
    echo "(una sola línea, empieza por SATOMJOIN1.):"
    ask JOIN_KEY_RAW "> "
    JOIN_KEY_RAW="${JOIN_KEY_RAW// /}"
    # Se acepta el prefijo heredado OFMJOIN1. para no invalidar claves ya
    # emitidas; las nuevas se emiten siempre como SATOMJOIN1.
    case "$JOIN_KEY_RAW" in
        SATOMJOIN1.*) JOIN_B64="${JOIN_KEY_RAW#SATOMJOIN1.}" ;;
        OFMJOIN1.*)   JOIN_B64="${JOIN_KEY_RAW#OFMJOIN1.}" ;;
        *) die "La clave de unión no es válida (debe empezar por SATOMJOIN1.)" ;;
    esac
    JOIN_JSON=$(echo "$JOIN_B64" | base64 -d 2>/dev/null) || die "La clave de unión no se pudo decodificar"
    # Extractor de JSON en shell. NO se puede usar Python aqui: estamos en el
    # paso 1 y el interprete se instala en el paso 2 — en una distro sin
    # symlink python3 esto moria con exit 127 nada mas pegar la clave. La
    # clave la genera este mismo instalador (json.dump de un diccionario plano
    # de cadenas: una linea, sin anidamiento, \n escapados dentro de los PEM).
    # Se usa SIEMPRE, no como rama de reserva: una segunda ruta que solo se
    # ejecuta en una familia de distros es codigo sin probar.
    _SATOM_JSON_AWK=$(cat <<'AWKJSON'
{ all = all $0 }
END {
    pat = "\"" k "\"[ ]*:[ ]*\""
    if (match(all, pat) == 0) exit 1
    i = RSTART + RLENGTH
    out = ""
    n = length(all)
    while (i <= n) {
        c = substr(all, i, 1)
        if (c == "\\") {
            e = substr(all, i + 1, 1)
            if (e == "n")      out = out "\n"
            else if (e == "t") out = out "\t"
            else if (e == "r") out = out "\r"
            else               out = out e
            i += 2
        } else if (c == "\"") {
            break
        } else {
            out = out c
            i++
        }
    }
    printf "%s", out
}
AWKJSON
)
    json_str_field() { awk -v k="$1" "$_SATOM_JSON_AWK"; }
    jget() { printf '%s' "$JOIN_JSON" | json_str_field "$1"; }
    PRIMARY_IP=$(jget primary_ip);   [ -n "$PRIMARY_IP" ]  || die "Join key sin primary_ip"
    PRIMARY_PORT=$(jget primary_port)
    FERNET_KEY=$(jget fernet_key);   [ -n "$FERNET_KEY" ]  || die "Join key sin fernet_key"
    SECRET_KEY=$(jget secret_key)
    DB_PASS=$(jget db_password)
    REPL_PASS=$(jget repl_password); [ -n "$REPL_PASS" ]   || die "Join key sin repl_password"
    CA_CRT=$(jget ca_crt);           [ -n "$CA_CRT" ]      || die "Join key sin ca_crt"
    CA_KEY=$(jget ca_key);           [ -n "$CA_KEY" ]      || die "Join key sin ca_key"
    # El extractor es propio: se comprueba la FORMA de lo extraido. Un parser
    # silenciosamente malo corromperia la CA interna y eso no se notaria hasta
    # la primera emision de certificado, semanas despues.
    case "$CA_CRT" in
        "-----BEGIN CERTIFICATE-----"*) : ;;
        *) die "El ca_crt de la clave de unión no es un PEM válido — clave corrupta o truncada" ;;
    esac
    case "$CA_KEY" in
        "-----BEGIN "*"PRIVATE KEY-----"*) : ;;
        *) die "El ca_key de la clave de unión no es un PEM válido — clave corrupta o truncada" ;;
    esac
    printf '%s' "$CA_CRT" | grep -q -- "-----END CERTIFICATE-----" \
        || die "El ca_crt de la clave de unión está truncado (falta la línea END)"
    printf '%s' "$CA_KEY" | grep -q -- "PRIVATE KEY-----" \
        || die "El ca_key de la clave de unión está truncado"
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
        ask_secret ADMIN_PASS "Clave para el usuario 'admin' de la consola: "
        ask_secret ADMIN_PASS2 "Repite la clave: "
        if [ "$ADMIN_PASS" != "$ADMIN_PASS2" ]; then warn "No coinciden"; ADMIN_PASS=""; continue; fi
        if [ "${#ADMIN_PASS}" -lt 8 ]; then warn "Mínimo 8 caracteres"; ADMIN_PASS=""; fi
    done
fi

SECONDARY_CIDR=""
if [ "$ROLE" = "primary" ]; then
    ask SECONDARY_IP_ANS "IP prevista del nodo secondary (Enter = permitir toda la subred de ${NODE_IP}): "
    if [ -n "$SECONDARY_IP_ANS" ]; then
        SECONDARY_CIDR="${SECONDARY_IP_ANS}/32"
    else
        SECONDARY_CIDR="$(echo "$NODE_IP" | cut -d. -f1-3).0/24"
    fi
fi

echo ""
say "Resumen: IP=${NODE_IP}  puerto=${WEB_PORT}  nombres=${SERVED_NAMES}  modo=${MODE}${ROLE:+/${ROLE}}  origen=$( [ $OFFLINE -eq 1 ] && echo offline || echo online )"
ask GO "¿Continuar con la instalación? [S/n]: "
[[ "${GO,,}" =~ ^(s|si|sí|y|yes|)$ ]] || die "Cancelado por el usuario"

# ─────────────────────────────────────────────────────────────────────────────
# PASO 2 — PAQUETES (verifica; instala faltantes; avisa de actualizaciones)
# ─────────────────────────────────────────────────────────────────────────────
say "Paso 2/7 — Verificando paquetería (gestor detectado: ${PKG_MGR})"

PKGS=("${REQUIRED_PKGS[@]}")
if [ $OFFLINE -eq 0 ]; then PKGS+=("${ONLINE_EXTRA_PKGS[@]}"); fi
# El canal de sincronización de data/ es rsync sobre SSH: sólo cluster.  [PFSSH2]
if [ "$MODE" = "cluster" ]; then PKGS+=("${SSH_PKGS[@]}"); fi

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
        elif [ -d "$BUNDLE_DIR/rpms-suse" ]; then
            # zypper: se le da un directorio de repos PROPIO (--reposd-dir) que
            # contiene UNICAMENTE el bundle. Equivalente al --repofrompath de
            # dnf: resuelve sin red y sin tocar los repos del sistema, y no deja
            # un repo dado de alta al terminar (que seria estado que nadie pidio).
            _zr="$(mktemp -d)"
            mkdir -p "$_zr/repos.d" "$_zr/cache"
            cat > "$_zr/repos.d/satom-bundle.repo" <<ZREPO
[satom-bundle]
name=SATOM offline bundle
baseurl=dir://$BUNDLE_DIR/rpms-suse
enabled=1
autorefresh=0
gpgcheck=0
keeppackages=0
ZREPO
            zypper --non-interactive --no-gpg-checks \
                   --reposd-dir "$_zr/repos.d" --cache-dir "$_zr/cache" \
                   install --no-recommends --auto-agree-with-licenses \
                   "${REQUIRED_PKGS[@]}" >>"$INSTALL_LOG" 2>&1 \
                || { rm -rf "$_zr"; die "Fallo instalando rpms del bundle SUSE (revisa $INSTALL_LOG)"; }
            # openssh sólo se necesita en cluster; si viaja en el bundle, se instala.
            if [ "${MODE:-}" = "cluster" ]; then
                zypper --non-interactive --no-gpg-checks \
                       --reposd-dir "$_zr/repos.d" --cache-dir "$_zr/cache" \
                       install --no-recommends --auto-agree-with-licenses \
                       "${SSH_PKGS[@]}" >>"$INSTALL_LOG" 2>&1 || true
            fi
            rm -rf "$_zr"
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

# --- SATOM-SSHD-ENABLE -----------------------------------------------------
# Instalar openssh NO es tener sshd corriendo. En Debian el .deb lo habilita
# por politica y el canal de datasync funciona por casualidad; en openSUSE el
# servicio queda disabled/inactive y nada escucha en el :22, asi que el standby
# no puede hacer pull de data/ jamas. Se habilita en LOS DOS nodos del cluster:
# tras un promote es el viejo standby quien tiene que servir el pull.
if [ "$MODE" = "cluster" ]; then
    SSHD_UNIT=""
    for u in sshd.service ssh.service; do
        systemctl list-unit-files "$u" >/dev/null 2>&1 \
            && systemctl cat "$u" >/dev/null 2>&1 && { SSHD_UNIT="$u"; break; }
    done
    if [ -z "$SSHD_UNIT" ]; then
        warn "No encuentro una unidad sshd/ssh — el datasync de data/ NO funcionará hasta que haya un servidor SSH activo"
    else
        systemctl enable --now "$SSHD_UNIT" >>"$INSTALL_LOG" 2>&1 || true
        if systemctl is-active --quiet "$SSHD_UNIT"; then
            ok "Servidor SSH activo (${SSHD_UNIT}) — canal de replicación de data/ disponible"
        else
            die "No se pudo arrancar ${SSHD_UNIT}. En modo cluster el pull de data/ va por SSH: sin él la réplica de ficheros no existe. Revisa ${INSTALL_LOG}."
        fi
    fi
fi

# Re-resuelve el intérprete tras instalar paquetes (puede haber llegado ahora)
pick_python || die "No hay un Python >= 3.10 disponible tras la instalación de paquetes"
# El módulo venv puede venir en paquete aparte (Debian) o integrado (resto)
"$PYBIN" -m venv --help >/dev/null 2>&1 || die "$PYBIN no trae el módulo venv — instala el paquete venv de tu distro"

# --- el intérprete tiene que FUNCIONAR, no sólo existir --------------------
# `--version` y `-m venv --help` no importan ninguna extensión C, así que no
# ven un desajuste de ABI entre el binario de Python y las librerías del
# sistema. Caso real (openSUSE Leap 15.6): el python311 de los mirrors está
# compilado contra libexpat 2.7.x, la imagen base trae 2.4.4 y `zypper install`
# NO actualiza una dependencia ya instalada -> `import pyexpat` falla con
# "undefined symbol" y la instalación muere en `ensurepip`, DESPUÉS de haber
# clonado el repo y creado la cuenta de servicio. Se comprueba aquí, se intenta
# remediar una vez, y si no se puede se muere nombrando el módulo y el comando.
# [SATOM-ABI-OFFLINE] Fuerza la actualizacion de las librerias del sistema
# contra las que se compilo el interprete, USANDO EL BUNDLE como unico origen.
# Se llama solo cuando ya sabemos que el interprete esta roto: no se toca
# libexpat/libssl de una maquina cuyo Python funciona.
bundle_upgrade_abi_libs() {
    local rc=0
    if [ -d "$BUNDLE_DIR/rpms-suse" ]; then
        local _zr; _zr="$(mktemp -d)"
        mkdir -p "$_zr/repos.d" "$_zr/cache"
        cat > "$_zr/repos.d/satom-bundle.repo" <<ZREPO
[satom-bundle]
name=SATOM offline bundle
baseurl=dir://$BUNDLE_DIR/rpms-suse
enabled=1
autorefresh=0
gpgcheck=0
keeppackages=0
ZREPO
        # `install` y no `update`: update solo mira los repos dados de alta en
        # el sistema. Con --force-resolution zypper acepta subir el paquete
        # aunque la dependencia por soname ya estuviera satisfecha.
        zypper --non-interactive --no-gpg-checks \
               --reposd-dir "$_zr/repos.d" --cache-dir "$_zr/cache" \
               install --no-recommends --auto-agree-with-licenses \
               --force-resolution \
               libexpat1 libopenssl3 libsqlite3-0 libz1 \
               >>"$INSTALL_LOG" 2>&1 || rc=1
        rm -rf "$_zr"
    elif [ -d "$BUNDLE_DIR/rpms" ]; then
        "$PKG_MGR" -y --disablerepo='*' \
            --repofrompath="satom-bundle,file://$BUNDLE_DIR/rpms" \
            --setopt=satom-bundle.gpgcheck=0 \
            --setopt=install_weak_deps=False \
            --allowerasing \
            upgrade expat openssl-libs sqlite-libs zlib \
            >>"$INSTALL_LOG" 2>&1 || rc=1
    elif [ -d "$BUNDLE_DIR/debs" ]; then
        # dpkg sobre el conjunto completo ya sube lo que este mas nuevo; se
        # repite acotado por si la pasada general se salto algo.
        dpkg -i --skip-same-version "$BUNDLE_DIR"/debs/*.deb \
            >>"$INSTALL_LOG" 2>&1 || rc=1
    fi
    return $rc
}

PY_C_EXTENSIONS="pyexpat ssl sqlite3 ctypes zlib _hashlib"
py_runtime_broken() {
    for m in $PY_C_EXTENSIONS; do
        "$PYBIN" -c "import $m" >/dev/null 2>&1 || { echo "$m"; return 0; }
    done
    return 1
}
BROKEN_MOD="$(py_runtime_broken || true)"
if [ -n "$BROKEN_MOD" ]; then
    # `|| true` NO es decorativo: con `set -o pipefail` el pipeline devuelve
    # el codigo de python, que falla A PROPOSITO (es justo lo que estamos
    # midiendo), y `set -e` mataria el script en esta asignacion — el
    # diagnostico matando el caso que existe para diagnosticar. Encontrado
    # ejecutando: `bash -n` no puede verlo.
    BROKEN_ERR="$("$PYBIN" -c "import $BROKEN_MOD" 2>&1 | tail -1 || true)"
    warn "El intérprete $PYBIN no puede importar '$BROKEN_MOD': $BROKEN_ERR"
    # Las librerías que con más frecuencia quedan atrás respecto al intérprete.
    if [ "$OFFLINE" = "1" ]; then
        # [SATOM-ABI-OFFLINE] Antes esto era un `die` seco: "actualiza las
        # librerías desde el mismo medio". Pero el medio ES el bundle, y el
        # bundle YA TRAE la version buena — llega arrastrada como dependencia
        # de python311 al resolver contra una raiz vacia. Lo que no ocurria era
        # INSTALARLA: zypper ve la dependencia satisfecha por soname
        # (libexpat.so.1 la provee tambien la 2.4.4 del template) y no
        # actualiza un paquete que ya esta. Resultado: instalacion offline
        # imposible en una imagen base con libexpat viejo, con el remedio
        # tumbado dentro del propio tarball.
        # Encontrado instalando de verdad en la plantilla LXC openSUSE 15.6
        # (libexpat1 2.4.4, de 2024-09); el contenedor docker opensuse/leap
        # con el que se valido el bundle traia 2.7.1 y por eso paso limpio:
        # EL ENTORNO DE VALIDACION ERA MAS NUEVO QUE EL DE DESPLIEGUE.
        say "Actualizando desde el bundle las librerías del sistema que usa el intérprete…"
        bundle_upgrade_abi_libs || true
    else
        say "Intentando actualizar las librerías del sistema que usa el intérprete…"
        case "$PKG_MGR" in
            zypper) zypper --non-interactive update libexpat1 libopenssl3 libsqlite3-0 libz1 >>"$INSTALL_LOG" 2>&1 || true ;;
            dnf)    dnf -y upgrade expat openssl-libs sqlite-libs zlib          >>"$INSTALL_LOG" 2>&1 || true ;;
            yum)    yum -y update expat openssl-libs sqlite zlib               >>"$INSTALL_LOG" 2>&1 || true ;;
            apt)    apt-get install -y --only-upgrade libexpat1 libssl3 libsqlite3-0 zlib1g >>"$INSTALL_LOG" 2>&1 || true ;;
            pacman) pacman -S --noconfirm expat openssl sqlite zlib            >>"$INSTALL_LOG" 2>&1 || true ;;
        esac
    fi
    STILL="$(py_runtime_broken || true)"
    if [ -n "$STILL" ]; then
        if [ "$OFFLINE" = "1" ]; then
            die "El Python de la distro sigue roto tras actualizar desde el bundle: 'import $STILL' falla.
       El bundle no trae una versión suficiente de las librerías del sistema para
       esta imagen base. Actualiza el sistema desde tu propio medio y vuelve a
       lanzar. No se ha modificado nada más. Detalle en $INSTALL_LOG"
        fi
        die "El Python de la distro sigue roto: 'import $STILL' falla. Actualiza el sistema completo (p.ej. 'zypper update' / 'dnf upgrade') y vuelve a lanzar el instalador. No se ha modificado nada más."
    fi
    ok "Librerías del sistema actualizadas — el intérprete importa sus extensiones C"
else
    ok "Intérprete verificado: importa sus extensiones C ($PY_C_EXTENSIONS)"
fi

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
        ask GIT_URL "URL del repo de producción [${GIT_URL_DEFAULT}]: "
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

# ---------------------------------------------------------------------------
# Cuenta de servicio + privilegios mínimos
# ---------------------------------------------------------------------------
say "Creando cuenta de servicio '${APP_USER}' y aplicando privilegios mínimos"
NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
[ -x "$NOLOGIN" ] || NOLOGIN=/bin/false
if ! id -u "$APP_USER" >/dev/null 2>&1; then
    useradd --system --user-group --home-dir "$APP_DIR" --shell "$NOLOGIN" \
            --comment "SATOM service account" "$APP_USER" \
        || die "No se pudo crear el usuario de servicio ${APP_USER}"
    ok "Usuario de servicio ${APP_USER} creado (sin shell, sin login)"
else
    ok "Usuario de servicio ${APP_USER} ya existe — se reutiliza"
fi

# La app escribe en todo el árbol salvo .env (que sólo LEE).
mkdir -p "$APP_DIR/data" "$APP_DIR/state" "$LOG_DIR" "$APP_DIR/.ssh"
chown -R "${APP_USER}:${APP_USER}" "$APP_DIR" "$LOG_DIR"
chmod 750 "$APP_DIR"
chmod 700 "$APP_DIR/state" "$APP_DIR/.ssh"
if [ -f "$APP_DIR/.env" ]; then
    chown root:"$APP_USER" "$APP_DIR/.env"; chmod 640 "$APP_DIR/.env"
fi

# ---- sudoers: allowlist DELIBERADAMENTE DIMINUTA -------------------------
# Sólo dos comandos. NO se concede instalación de paquetes (apt/dnf/pip) ni
# systemctl sin restringir: ambos son EQUIVALENTES A ROOT — un paquete
# ejecuta sus propios scripts postinst como root, y `systemctl` sin unidad
# fijada permite arrancar cualquier unidad. Todo lo que necesita privilegio
# real (instalar unidades, pip, reiniciar el propio servicio) pasa por el
# runner satom-updater.service, que es root por diseño y valida su entrada.
NGINX_BIN="$(command -v nginx || echo /usr/sbin/nginx)"
SYSTEMCTL_BIN="$(command -v systemctl || echo /usr/bin/systemctl)"
cat > /etc/sudoers.d/satom <<SUDOERS
# Generado por install-satom.sh — ver docs/privilege-model.md
# NO añadir aquí gestores de paquetes ni systemctl genérico: sería root.
Cmnd_Alias SATOM_CERT_RELOAD = ${NGINX_BIN} -t, ${SYSTEMCTL_BIN} reload nginx
${APP_USER} ALL=(root) NOPASSWD: SATOM_CERT_RELOAD
Defaults:${APP_USER} !requiretty
SUDOERS
chmod 440 /etc/sudoers.d/satom
visudo -cf /etc/sudoers.d/satom >>"$INSTALL_LOG" 2>&1 \
    || { rm -f /etc/sudoers.d/satom; die "La regla sudoers generada es inválida"; }
ok "sudoers: ${APP_USER} sólo puede 'nginx -t' y 'systemctl reload nginx'"

# ─────────────────────────────────────────────────────────────────────────────
# PASO 4 — POSTGRES
# ─────────────────────────────────────────────────────────────────────────────
# ---- ACME client (Certificate Manager, protocolo ACME/Let's Encrypt) -------
# lego = un único binario estático con ~150 proveedores DNS integrados. Se
# instala aquí para que "Settings → Certificate Manager → ACME" funcione sin
# pasos manuales. OFFLINE: viene en el bundle. ONLINE: se descarga y se
# VERIFICA el sha256 del release. Nunca aborta la instalación: sin lego el
# resto del producto (ADCS, PKI interna) sigue siendo plenamente funcional.
say "Instalando el cliente ACME (lego ${LEGO_VERSION})"
LEGO_BIN="/usr/local/bin/lego"
if command -v lego >/dev/null 2>&1 || [ -x "$LEGO_BIN" ]; then
    ok "lego ya presente: $(command -v lego >/dev/null 2>&1 && lego --version 2>&1 | head -1 || "$LEGO_BIN" --version 2>&1 | head -1)"
elif [ -f "${BUNDLE_DIR}/lego/lego" ]; then
    install -m 0755 "${BUNDLE_DIR}/lego/lego" "$LEGO_BIN" && ok "lego $("$LEGO_BIN" --version 2>&1 | head -1) instalado desde el bundle offline"
elif [ $OFFLINE -eq 0 ] && command -v curl >/dev/null 2>&1; then
    _lt="$(mktemp -d)"
    if curl -fsSLo "$_lt/lego.tgz" "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/lego_v${LEGO_VERSION}_linux_amd64.tar.gz" \
       && curl -fsSLo "$_lt/sums" "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/lego_${LEGO_VERSION}_checksums.txt"; then
        _exp="$(grep "lego_v${LEGO_VERSION}_linux_amd64.tar.gz$" "$_lt/sums" | awk '{print $1}')"
        _got="$(sha256sum "$_lt/lego.tgz" | awk '{print $1}')"
        if [ -n "$_exp" ] && [ "$_exp" = "$_got" ]; then
            tar xzf "$_lt/lego.tgz" -C "$_lt" lego && install -m 0755 "$_lt/lego" "$LEGO_BIN" \
                && ok "lego $("$LEGO_BIN" --version 2>&1 | head -1) instalado (sha256 verificado)"
        else
            warn "lego: sha256 no coincide — NO instalado. Instálalo a mano si vas a usar ACME."
        fi
    else
        warn "lego: descarga fallida — instálalo a mano si vas a usar ACME."
    fi
    rm -rf "$_lt"
else
    warn "lego no instalado (sin red y sin bundle). El protocolo ACME quedará inutilizable hasta instalarlo."
fi
# Directorio de la CUENTA ACME: debe PERSISTIR entre emisiones (los límites de
# registro del CA y la capacidad de revocar dependen de la misma clave).
mkdir -p "$APP_DIR/data/acme" && chmod 700 "$APP_DIR/data/acme"
chmod 0755 "$APP_DIR/deploy/acme-hooks"/*.sh 2>/dev/null || true

# --- Almacen de metricas: VictoriaMetrics single-node (OSS, Apache-2.0) -----
# [SATOM-METRICS-STORE]
# Un binario Go estatico sin dependencias, asi que entra en los bundles offline
# de las tres familias igual que lego. Es lo que sostiene /monitoring/analytics:
# a escala de flota Postgres no puede guardar la telemetria por policy (medido
# 2026-08-05, 100 equipos x 750 policies: ~450 GB en monitor_sample contra ~8 GB
# aqui). Sin el, la app arranca y todo lo demas funciona, pero los paneles del
# store devuelven error de consulta -> se AVISA, no se aborta.
#
# OJO: el mismo tag publica variantes -cluster y -enterprise. La enterprise NO
# es Apache-2.0. El nombre del artefacto esta fijado y el sha256 del binario
# esta anclado arriba: lo que no coincida NO se instala.
say "Instalando el almacen de metricas (VictoriaMetrics ${VM_VERSION})"
VM_BIN="/usr/local/bin/victoria-metrics"
VM_DATA="/var/lib/satom-metrics"
vm_sha_ok() { [ -f "$1" ] && [ "$(sha256sum "$1" | awk '{print $1}')" = "$VM_SHA256" ]; }

if vm_sha_ok "$VM_BIN"; then
    ok "victoria-metrics ${VM_VERSION} ya presente (sha256 verificado)"
elif [ -f "${BUNDLE_DIR}/victoria-metrics/victoria-metrics" ]; then
    if vm_sha_ok "${BUNDLE_DIR}/victoria-metrics/victoria-metrics"; then
        install -m 0755 "${BUNDLE_DIR}/victoria-metrics/victoria-metrics" "$VM_BIN" \
            && ok "victoria-metrics ${VM_VERSION} instalado desde el bundle offline (sha256 verificado)"
    else
        warn "victoria-metrics: el binario del bundle no coincide con el sha256 esperado - NO instalado."
    fi
elif [ "$OFFLINE" -eq 0 ]; then
    _vt="$(mktemp -d)"
    if curl -fsSLo "$_vt/vm.tgz" "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v${VM_VERSION}/victoria-metrics-linux-amd64-v${VM_VERSION}.tar.gz"; then
        if tar xzf "$_vt/vm.tgz" -C "$_vt" victoria-metrics-prod 2>/dev/null \
           && vm_sha_ok "$_vt/victoria-metrics-prod"; then
            install -m 0755 "$_vt/victoria-metrics-prod" "$VM_BIN" \
                && ok "victoria-metrics ${VM_VERSION} instalado (sha256 verificado)"
        else
            warn "victoria-metrics: sha256 no coincide - NO instalado. Los paneles del store quedaran sin datos."
        fi
    else
        warn "victoria-metrics: descarga fallida - los paneles del store quedaran sin datos."
    fi
    rm -rf "$_vt"
else
    warn "victoria-metrics no instalado (sin red y sin bundle). /monitoring/analytics quedara sin store."
fi

# El directorio de datos vive FUERA de data/ a proposito: satom-ha-datasync
# sincroniza data/ con rsync --delete y un TSDB no se rsyncea bajo un proceso
# vivo. Cada nodo mantiene el suyo.
if [ -x "$VM_BIN" ]; then
    install -d -m 0750 -o "$APP_USER" -g "$APP_USER" "$VM_DATA"
    install -m 0644 "$APP_DIR/deploy/satom-metrics.service" \
        /etc/systemd/system/satom-metrics.service
    systemctl daemon-reload >>"$INSTALL_LOG" 2>&1 || true
fi

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
# [SATOM-SERVED-NAMES] El SAN lleva TODOS los nombres servidos, no el corto.
# Un SAN que no cubre el nombre por el que se entra produce un aviso del
# navegador sobre un certificado recien emitido y reportado como bueno, y no hay
# forma de arreglarlo sin volver a emitir -- por eso se pregunta en el paso 1.
SAN_LIST="IP:${NODE_IP}"
for _sn in $SERVED_NAMES; do SAN_LIST="${SAN_LIST},DNS:${_sn}"; done
CERT_CN="${SERVED_NAMES%% *}"
openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "$PKI/node/leaf.key" -out "$PKI/node/leaf.csr" \
    -subj "/CN=${CERT_CN}" >>"$INSTALL_LOG" 2>&1
cat > /tmp/satom-ext.cnf <<EXT
subjectAltName=${SAN_LIST}
extendedKeyUsage=serverAuth,clientAuth
EXT
openssl x509 -req -in "$PKI/node/leaf.csr" -CA "$PKI/internal-ca/ca.crt" \
    -CAkey "$PKI/internal-ca/ca.key" -CAcreateserial -days 825 -sha256 \
    -extfile /tmp/satom-ext.cnf -out "$PKI/node/leaf.crt" >>"$INSTALL_LOG" 2>&1
rm -f /tmp/satom-ext.cnf "$PKI/node/leaf.csr"
chmod 600 "$PKI/node/leaf.key"
cp "$PKI/node/leaf.crt" "$PKI/public/server.crt"
cp "$PKI/node/leaf.key" "$PKI/public/server.key"
cat > "$PKI/public/meta.json" <<META
{"source": "issued", "issued_by": "internal-ca", "cn": "${CERT_CN}", "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
META
ok "Certificado del nodo emitido localmente (CN=${CERT_CN}, SAN=${SAN_LIST})"

# Copia para Postgres (réplica TLS en clúster)
PGSSL="$PGCONF/satomssl"; mkdir -p "$PGSSL"
cp "$PKI/node/leaf.crt" "$PGSSL/server.crt"; cp "$PKI/node/leaf.key" "$PGSSL/server.key"
cp "$PKI/internal-ca/ca.crt" "$PGSSL/ca.crt"
chown -R postgres:postgres "$PGSSL"; chmod 600 "$PGSSL/server.key"

# ─────────────────────────────────────────────────────────────────────────────
# PASO 6 — .env, BD/RÉPLICA, SERVICIOS
# ─────────────────────────────────────────────────────────────────────────────
say "Paso 6/7 — Configuración, base de datos y servicios"

if [ "$ROLE" != "secondary" ]; then
    SECRET_KEY=$("$PYBIN" -c "import secrets; print(secrets.token_hex(32))")
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
# 640 root:<cuenta>, NO 600. satom-alerts, satom-cert-renew,
# satom-git-publish, satom-ha-datasync y satom-node-role.sh hacen
# `source .env` COMO LA CUENTA DE SERVICIO: con 600 root:root nacen rotos
# y el motor de alertas nunca envia nada. root sigue siendo el DUENO (la
# app solo LEE el fichero, asi que un write primitive en el worker no
# puede reescribir sus propios secretos).
chown root:"$APP_USER" "$APP_DIR/.env"
chmod 640 "$APP_DIR/.env"
ok ".env escrito (640 root:${APP_USER} — legible por los timers)"

# ---- pg_hba: la conexion TCP local de la app ----------------------------
# NO se puede confiar en el default de la distro: Debian trae scram-sha-256
# para 127.0.0.1 pero openSUSE/SLES trae *ident*, que rechaza al usuario de
# la app con FATAL antes de mirar la contrasena. La regla va INSERTADA AL
# PRINCIPIO porque pg_hba es first-match: anadida al final quedaria detras
# de la generica de la distro y no se evaluaria nunca.
if ! grep -q "SATOM-LOCAL" "$PGHBA"; then
    TMPHBA=$(mktemp)
    {
        echo "# SATOM-LOCAL (install-satom.sh) — first-match: va arriba"
        echo "host    ${DB_NAME}   ${DB_USER}   127.0.0.1/32   scram-sha-256"
        echo "host    ${DB_NAME}   ${DB_USER}   ::1/128        scram-sha-256"
        cat "$PGHBA"
    } > "$TMPHBA"
    cat "$TMPHBA" > "$PGHBA"
    rm -f "$TMPHBA"
    ok "pg_hba: regla local scram para ${DB_USER}@${DB_NAME}"
fi

# ---- RECARGA: escribir pg_hba no basta -----------------------------------
# [SATOM-HBA-RELOAD] Postgres evalua pg_hba desde MEMORIA. Sin recarga, la
# regla que acabamos de escribir no existe para el servidor en marcha.
# El unico `systemctl restart postgresql` vivia dentro de la rama `primary`,
# asi que una instalacion STANDALONE escribia la regla correcta y el servidor
# seguia aplicando la generica de la distro. En Debian eso no se nota (su
# default para 127.0.0.1 ya es scram-sha-256); en openSUSE y RHEL el default
# es *ident* -> `flask create-db` moria con
#   FATAL: Ident authentication failed for user "satom"
# Va aqui, fuera de cualquier rama, para TODOS los modos.
systemctl reload postgresql >>"$INSTALL_LOG" 2>&1 \
    || systemctl restart postgresql >>"$INSTALL_LOG" 2>&1 \
    || die "No se pudo recargar PostgreSQL tras escribir pg_hba (revisa $INSTALL_LOG)"

# [SATOM-HBA-VERIFY] Comprobar la credencial AQUI, no 100 lineas mas abajo
# dentro de un traceback de SQLAlchemy. Este es el punto donde el error es
# accionable y el mensaje puede nombrar la causa.
if [ "$ROLE" != "secondary" ]; then
    if PGPASSWORD="$DB_PASS" psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" \
            -tAc 'SELECT 1' >>"$INSTALL_LOG" 2>&1; then
        ok "PostgreSQL recargado — la app puede autenticarse por TCP"
    else
        die "La cuenta '${DB_USER}' no puede conectar a 127.0.0.1/${DB_NAME}.
       Causa habitual: pg_hba no recargado o una regla previa mas generica
       (p.ej. 'host all all 127.0.0.1/32 ident') gana el first-match.
       Revisa: ${PGHBA} y ${INSTALL_LOG}"
    fi
else
    ok "PostgreSQL recargado — pg_hba en vigor"
fi

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

    # NOTA DE SEGURIDAD — el primary ya NO genera el par de llaves del
    # datasync. Antes lo hacía y metía la clave PRIVADA dentro de la join
    # key, que viaja por el portapapeles de un humano; además la entrada de
    # authorized_keys no llevaba from= ni command=, así que esa llave era una
    # shell de root desde cualquier IP. Ahora el SECONDARY genera su propio
    # par (la privada nunca sale de su disco) y el admin autoriza la pública
    # en el primary con:  install-satom.sh --authorize-peer <ip> "<pubkey>"
    install -d -m 700 -o "$APP_USER" -g "$APP_USER" "$APP_DIR/.ssh"
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
        -h "$PRIMARY_IP" -U "$REPL_USER" -D "$PGDATA" -R -X stream -C -S "satom_$(hostname | tr -c 'a-z0-9' '_')" \
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

    # Llave del datasync: se genera AQUÍ. La privada nunca viaja.
    install -d -m 700 -o "$APP_USER" -g "$APP_USER" "$APP_DIR/.ssh"
    HA_KEY="$APP_DIR/.ssh/id_ha_rsync"
    if [ ! -f "$HA_KEY" ]; then
        runuser -u "$APP_USER" -- ssh-keygen -t ed25519 -N "" -q -f "$HA_KEY" \
            -C "satom-ha-datasync@$(hostname)"
    fi
    chown "$APP_USER:$APP_USER" "$HA_KEY" "$HA_KEY.pub"; chmod 600 "$HA_KEY"

    # Sembrar la host key del primary AHORA, por SSH autenticado con la CA
    # que ya trae la join key. Así el primer rsync no depende de TOFU
    # (StrictHostKeyChecking=accept-new aceptaba lo que contestara esa IP).
    KNOWN="$APP_DIR/.ssh/known_hosts"
    ssh-keyscan -T 10 -t ed25519,rsa "$PRIMARY_IP" 2>/dev/null >> "$KNOWN" || true
    sort -u "$KNOWN" -o "$KNOWN" 2>/dev/null || true
    chown "$APP_USER:$APP_USER" "$KNOWN" 2>/dev/null || true
    # SATOM-KNOWNHOSTS-VERIFY — un keyscan vacio es indistinguible de uno bueno
    # si nadie mira. Con StrictHostKeyChecking=yes (el TOFU se quito a
    # proposito) un known_hosts sin la clave del primary rompe el datasync PARA
    # SIEMPRE, y la instalacion terminaria diciendo "COMPLETA". Causa habitual:
    # el sshd del primary no esta arrancado, o hay un firewall entre nodos.
    if grep -q "^${PRIMARY_IP} " "$KNOWN" 2>/dev/null; then
        ok "Host key del primary ${PRIMARY_IP} sembrada (sin TOFU)"
    else
        warn "NO se pudo obtener la host key SSH de ${PRIMARY_IP}."
        warn "  La réplica de FICHEROS (data/) no funcionará: rsync usa StrictHostKeyChecking=yes."
        warn "  La réplica de Postgres SÍ funciona — va por su propio canal TLS."
        warn "  Comprueba que el primary tiene sshd activo y el :22 alcanzable, y repite:"
        warn "    ssh-keyscan -t ed25519,rsa ${PRIMARY_IP} >> ${KNOWN}"
    fi

    PEER_PUB="$(cat "$HA_KEY.pub")"
    "$PYBIN" - <<PYNODES
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
    # [SATOM-LOUD-DB] Estos dos pasos NO llevaban `|| die`. Con `set -e` el
    # instalador terminaba con rc=1 y SIN IMPRIMIR NADA: la ultima linea que
    # veia el operador era "pg_hba: regla local scram" y la causa real vivia
    # 60 lineas de traceback dentro de $INSTALL_LOG. Un fallo mudo es un
    # fallo que nadie encuentra.
    FLASK_APP=wsgi.py venv/bin/flask create-db >>"$INSTALL_LOG" 2>&1 \
        || die "flask create-db fallo — no se pudo inicializar el esquema.
       Revisa el final de $INSTALL_LOG (causa habitual: la app no puede
       autenticarse contra PostgreSQL)"
    export SATOM_ADMIN_PASS="$ADMIN_PASS"
    venv/bin/python - <<PYADM >>"$INSTALL_LOG" 2>&1 \
        || die "No se pudo fijar la clave de 'admin' (revisa $INSTALL_LOG)"
from wsgi import app
from app.extensions import db
from app.models import User
import os
with app.app_context():
    u = User.query.filter_by(username="admin").first()
    if u is None:
        raise SystemExit("no existe el usuario 'admin' tras create-db")
    u.set_password(os.environ["SATOM_ADMIN_PASS"])
    db.session.commit()
    print("admin password set")
PYADM
    ok "BD inicializada y clave de 'admin' establecida"
    unset SATOM_ADMIN_PASS
fi

# systemd units
# Fija la cuenta de servicio por DROP-IN, no editando la unidad: las plantillas
# de deploy/ declaran User=root y el runner de self-update las recopia en cada
# actualización — sin el drop-in, el primer update devolvería la app a root.
satom_enforce_unit_user() {                                          # [PFDROPIN]
    local unit d
    for unit in satom.service satom-scheduler.service satom-reconciler.service \
                satom-alerts.service satom-cert-renew.service \
                satom-metrics.service satom-ha-datasync.service; do
        [ -f "/etc/systemd/system/$unit" ] || continue
        d="/etc/systemd/system/${unit}.d"
        install -d -m 0755 "$d"
        cat > "$d/10-app-user.conf" <<DROPIN
# Generado por install-satom.sh. Vive en un drop-in porque las plantillas de
# deploy/ declaran User=root y cada update las recopia. NO editar a mano.
[Service]
User=${APP_USER}
Group=${APP_USER}
DROPIN
    done
    systemctl daemon-reload
    ok "Cuenta de servicio fijada por drop-in (sobrevive a los updates)"
}

say "Instalando servicios systemd"
# satom-updater.{path,service} corre como ROOT a propósito (instala
# unidades y reinicia servicios). El resto baja a la cuenta de servicio.
# alerts / reconciler FALTABAN en su día: sin ellos una instalación nueva se
# queda sin correos de fallo de certificado, aunque la UI los prometa.
# satom-git-publish se retiró el 2026-08-05: el SoT de dispositivos ya no vive
# en git (services.sot_store lo versiona localmente).
for unit in satom.service satom-scheduler.service \
            satom-updater.path satom-updater.service \
            satom-cert-renew.service satom-cert-renew.timer \
            satom-reconciler.service \
            satom-alerts.service satom-alerts.timer; do
    [ -f "$APP_DIR/deploy/$unit" ] && cp "$APP_DIR/deploy/$unit" /etc/systemd/system/
done
# gunicorn SOLO en loopback: nginx termina TLS en ${WEB_PORT}
sed -i 's#--bind 0\.0\.0\.0:8000#--bind 127.0.0.1:8000#' /etc/systemd/system/satom.service

# Degradar a la cuenta de servicio todo lo que no necesite root.
for unit in satom.service satom-scheduler.service satom-reconciler.service \
            satom-alerts.service satom-cert-renew.service; do
    f="/etc/systemd/system/$unit"
    [ -f "$f" ] || continue
    if grep -qE '^User=' "$f"; then
        sed -i "s#^User=.*#User=${APP_USER}#" "$f"
    else
        sed -i "/^\[Service\]/a User=${APP_USER}" "$f"
    fi
    grep -qE '^Group=' "$f" || sed -i "/^User=/a Group=${APP_USER}" "$f"
done
# Los scripts auxiliares se ejecutan desde /usr/local/sbin en ambos nodos.
for s in satom-ha-datasync.sh satom-promote.sh \
         satom-ha-rsync-shell; do
    [ -f "$APP_DIR/deploy/$s" ] && install -m 0755 "$APP_DIR/deploy/$s" /usr/local/sbin/
done

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
# --- SATOM-OWNERSHIP-SWEEP -------------------------------------------------
# El chown -R del paso 5 ocurre ANTES de que el instalador escriba data/logs,
# data/acme, data/jobs y data/ha_nodes.json, que crea corriendo como root. Un
# directorio 0700 root-owned bajo data/ hace fallar el rsync del standby con
# Permission denied aunque la autenticacion sea correcta (paso en produccion
# con data/acme), y un arbol de propiedad mixta erosiona el modelo de
# privilegio: self_update_runner deriva la cuenta del DUENO DEL ARBOL para
# escribir el drop-in User=. .env se excluye a proposito: es root:<cuenta> 640
# porque la app solo lo LEE.
find "$APP_DIR" -path "$APP_DIR/venv" -prune -o -path "$APP_DIR/.env" -prune \
     -o ! -user "$APP_USER" -exec chown "$APP_USER:$APP_USER" {} + 2>/dev/null || true
chown -R "$APP_USER:$APP_USER" "$LOG_DIR" 2>/dev/null || true
chown root:"$APP_USER" "$APP_DIR/.env"; chmod 640 "$APP_DIR/.env"
ok "Propiedad del arbol consolidada en ${APP_USER} (.env sigue root:${APP_USER} 640)"

systemctl enable --now satom.service satom-scheduler.service >>"$INSTALL_LOG" 2>&1 \
    || die "satom.service / satom-scheduler.service no arrancaron.
       Revisa: systemctl status satom.service  y  $INSTALL_LOG"
# `enable --now` es enable+start, y `start` sobre algo YA VIVO es no-op. En
# una reinstalacion el .env se acaba de regenerar (contrasena de BD,
# SECRET_KEY y FERNET_KEY nuevos) y systemd lee EnvironmentFile UNA sola
# vez, al arrancar: sin este restart el proceso viejo se queda con los
# secretos anteriores y el login falla con "password authentication
# failed" mientras /healthz sigue dando 200 (no toca la BD).
systemctl restart satom.service satom-scheduler.service >>"$INSTALL_LOG" 2>&1 || true
systemctl enable --now satom-updater.path >>"$INSTALL_LOG" 2>&1 || true
systemctl enable --now satom-cert-renew.timer >>"$INSTALL_LOG" 2>&1 || true
# Ambos timers llevan guarda de rol interna (primary-only), así que se
# habilitan en los dos nodos: tras un promote el nodo nuevo ya está listo.
systemctl enable --now satom-alerts.timer >>"$INSTALL_LOG" 2>&1 || true
# satom-git-publish.timer retirado 2026-08-05 (SoT local, services.sot_store)
systemctl enable --now satom-reconciler.service >>"$INSTALL_LOG" 2>&1 || true
[ "$MODE" = "cluster" ] && systemctl enable --now satom-ha-datasync.timer >>"$INSTALL_LOG" 2>&1

# Todas las unidades ya existen: blinda la cuenta de servicio contra el próximo
# self-update, que recopia las plantillas de deploy/ (User=root).   [PFDROPCALL]
satom_enforce_unit_user

# El store se habilita DESPUES del drop-in: la plantilla declara User=satom y
# una instalacion que adoptara otra cuenta arrancaria con el usuario erroneo.
if [ -x /usr/local/bin/victoria-metrics ] && [ -f /etc/systemd/system/satom-metrics.service ]; then
    systemctl daemon-reload >>"$INSTALL_LOG" 2>&1 || true
    if systemctl enable --now satom-metrics.service >>"$INSTALL_LOG" 2>&1; then
        ok "satom-metrics.service activo (store local en 127.0.0.1:8428)"
    else
        warn "satom-metrics.service no arranco - revisa: journalctl -u satom-metrics"
    fi
fi

# CLI de operador: copia ROOT-OWNED fuera del arbol de la app.
# Vive en /usr/local/lib/satom-cli + /usr/local/sbin/satom a proposito: si el
# objetivo de sudo fuera escribible por la cuenta de servicio, un worker web
# comprometido podria reescribir lo que el operador ejecuta con sudo.
# Ver docs/cli.md y 'satom diagnose privilege'.
if [ -f "$APP_DIR/deploy/install-cli.sh" ]; then
    if bash "$APP_DIR/deploy/install-cli.sh" >>"$INSTALL_LOG" 2>&1; then
        ok "CLI de operador instalado: satom (prueba: satom get system health)"
    else
        warn "No se pudo instalar el CLI de operador — revisa $INSTALL_LOG"
    fi
fi

# [SATOM-RUNNER-ROOT-COPY] El runner privilegiado (satom-updater.service) corre
# como ROOT y su unidad apunta al arbol de la app, que pertenece a la cuenta de
# servicio: root ejecutando codigo que el worker web puede reescribir es una
# escalada completa. install-runner.sh instala una copia root-owned fuera del
# arbol, con interprete del sistema, y redirige la unidad por drop-in.
# Tambien crea el almacen de confianza de paquetes de actualizacion.
if [ -f "$APP_DIR/deploy/install-runner.sh" ]; then
    if bash "$APP_DIR/deploy/install-runner.sh" >>"$INSTALL_LOG" 2>&1; then
        ok "Runner de actualizacion endurecido (root-owned, fuera del arbol)"
    else
        warn "No se pudo endurecer el runner de actualizacion — revisa $INSTALL_LOG"
    fi
fi

# Claves publicas de firma que vienen con el release. Una clave PUBLICA solo
# puede VERIFICAR: publicarla es seguro, es la mitad privada la que nunca debe
# llegar a un nodo. Sin ninguna clave el nodo rechaza todo paquete subido, que
# es un default seguro pero no operativo.
if [ -d "$APP_DIR/deploy/update-keys" ]; then
    SEEDED=0
    for k in "$APP_DIR"/deploy/update-keys/*.pub; do
        [ -f "$k" ] || continue
        install -o root -g root -m 0644 "$k" /etc/satom/update-keys/ && SEEDED=$((SEEDED+1))
    done
    [ "$SEEDED" -gt 0 ] && ok "Almacen de confianza: $SEEDED clave(s) de release instalada(s)"
fi

# nginx: TLS en el puerto elegido con el cert del nodo.
# Debian/Ubuntu usan sites-available/enabled; el resto de familias conf.d.
if [ -d /etc/nginx/sites-enabled ]; then
    NGXCONF=/etc/nginx/sites-available/satom.conf
elif [ -d /etc/nginx/vhosts.d ]; then
    # openSUSE/SLES: vhosts.d se incluye UNA vez; conf.d aparece dos veces en el
    # nginx.conf de fabrica, asi que un fichero ahi se parsea duplicado.
    NGXCONF=/etc/nginx/vhosts.d/satom.conf
else
    mkdir -p /etc/nginx/conf.d
    NGXCONF=/etc/nginx/conf.d/satom.conf
    # Arch no incluye conf.d de fábrica — lo enganchamos al bloque http
    grep -qE '^\s*include\s+/etc/nginx/conf\.d/\*\.conf' /etc/nginx/nginx.conf \
        || sed -i '0,/http\s*{/s//&\n    include \/etc\/nginx\/conf.d\/*.conf;/' /etc/nginx/nginx.conf
fi
mkdir -p "$ACME_WEBROOT/.well-known/acme-challenge"
chmod 755 "$ACME_WEBROOT"
# [SATOM-NGINX-DEFAULT] El listener TLS tiene que reclamar default_server.
# Sin dueno explicito, nginx se lo concede al PRIMER server de :${WEB_PORT} en
# orden de parseo, que entre ficheros es el ALFABETICO. En cuanto convive un
# segundo vhost — p.ej. el del sitio estatico que documenta el manual — la
# consola deja de responder por hostname mientras el otro sitio sigue
# sirviendo, y eso se lee como fallo de DNS, no de nginx. Los nodos de
# produccion llevan `default_server` porque alguien lo sufrio y lo anadio a
# mano; el instalador seguia emitiendo la version PREVIA a esa correccion, asi
# que cada instalacion nueva nacia con el fallo latente y `satom diagnose
# nginx` la marcaba FAIL el dia cero.
# El :443 explicito en un redirect es valido pero se propaga a la barra de
# direcciones y a cualquier proxy de delante; se omite cuando es el puerto
# por defecto, igual que hace el navegador.
REDIR_PORT=""
if [ "$WEB_PORT" != "443" ]; then REDIR_PORT=":${WEB_PORT}"; fi
write_satom_vhost() {
    local dflt="$1"
cat > "$NGXCONF" <<NGX
server {
    listen ${WEB_PORT} ssl http2${dflt};
    server_name ${SERVED_NAMES} ${NODE_IP};
    ssl_certificate     ${PKI}/public/server.crt;
    ssl_certificate_key ${PKI}/public/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    # Debe ser >= MAX_UPLOAD_BYTES de update_package_service.py, o un
    # paquete de actualizacion valido muere con un 413 de nginx que la
    # app nunca ve y por tanto no puede explicar.
    client_max_body_size 400M;
    location / {
        proxy_pass http://127.0.0.1:8000;
        # [SATOM-VHOST-HOST] \$host DESCARTA el puerto; \$http_host pasa la
        # cabecera tal cual. Flask-WTF construye el origen esperado del token CSRF
        # con el host que la app cree tener y lo compara con el Referer del
        # navegador INCLUYENDO el puerto: detras de un NAT o un proxy en puerto no
        # estandar, TODO POST -- el login incluido -- moria con un error que
        # hablaba de la sesion caducada y no de la cabecera. En :443 son
        # identicos, porque el navegador omite el puerto por defecto.
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 120s;
    }
}
# ACME http-01 (webroot) — the Certificate Manager's "web authentication" mode.
# The CA ALWAYS validates over plain :80, so this listener exists even though the
# app is served over TLS. The redirect is scoped to "location /" on purpose: a
# server-level "return" runs before location selection and would swallow the
# challenge. Not needed if you validate with dns-01.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    location ^~ /.well-known/acme-challenge/ {
        root ${ACME_WEBROOT};
        default_type "text/plain";
        try_files \$uri =404;
    }
    location / { return 301 https://\$host${REDIR_PORT}\$request_uri; }
}
NGX
    if [ -d /etc/nginx/sites-enabled ]; then
        ln -sf /etc/nginx/sites-available/satom.conf /etc/nginx/sites-enabled/satom.conf
        rm -f /etc/nginx/sites-enabled/default
    fi
}

# Se escribe CON default_server. Si otro vhost ya lo reclamaba, nginx lo dice
# con "duplicate default server" y sólo ENTONCES se reescribe sin él. Es
# autocorrectivo y no depende de adivinar la config ajena con un regex. Un
# `nginx -t` que falle por CUALQUIER otro motivo NO retira default_server: se
# deja pasar al `nginx -t || die` de mas abajo, que reporta la causa real.
write_satom_vhost " default_server"
if ! nginx -t >>"$INSTALL_LOG" 2>&1; then
    if nginx -t 2>&1 | grep -qi "duplicate default server"; then
        warn "Otro vhost ya reclama default_server en :${WEB_PORT} — reescribo sin él"
        write_satom_vhost ""
    fi
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
# SATOM-NGINX-START: arrancar y ESPERAR a que nginx sirva de verdad. NO recargar aqui.
# openSUSE trae el unit como Type=simple con ExecStart='nginx -g "daemon off;"' y
# ExecReload='/bin/kill -s HUP $MAINPID'. systemd da el servicio por iniciado en cuanto
# exec(), ANTES de que nginx haya escrito /run/nginx.pid, asi que un 'systemctl reload'
# inmediato encuentra $MAINPID vacio: el kill sale con status 2, systemd tumba el
# servicio ENTERO y el instalador muere con la instalacion ya completa y correcta.
# Debian y RHEL no lo ven porque sus units son forking con PIDFile y systemd espera al
# pid antes de dar el arranque por bueno -> ahi la carrera es invisible. Y el reload era
# ademas redundante: nginx acaba de arrancar con esta misma config, validada por el
# 'nginx -t' de la linea anterior.
# Esperar al pid file no vacio no es cosmetico: es lo que hace seguro el
# 'systemctl reload nginx' que cert_service ejecuta en caliente via sudoers.
systemctl enable --now nginx >>"$INSTALL_LOG" 2>&1 \
    || die "nginx no arranco (diagnostico: systemctl status nginx)"
_nginx_ready=0
for _i in $(seq 1 30); do
    if systemctl is-active --quiet nginx && [ -s /run/nginx.pid ] \
       && (exec 3<>"/dev/tcp/127.0.0.1/${WEB_PORT}") 2>/dev/null; then
        _nginx_ready=1; break
    fi
    sleep 1
done
[ "$_nginx_ready" = 1 ] \
    || die "nginx arranco pero no acepta conexiones en ${WEB_PORT} tras 30s"
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
    "$PYBIN" - <<PYNODES
import json
json.dump([{"name": "$(hostname)", "host": "${NODE_IP}", "role": "primary"}],
          open("${APP_DIR}/data/ha_nodes.json", "w"), indent=2)
PYNODES
    JOIN_JSON=$("$PYBIN" - <<PYJOIN
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
    # rsync_key ELIMINADO a propósito: la clave privada del datasync ya no
    # viaja en la join key. El secondary genera la suya localmente.
}
print("SATOMJOIN1." + base64.b64encode(json.dumps(blob).encode()).decode())
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
    echo "${c_bold}════════════ AUTORIZA ESTE NODO EN EL PRIMARY ════════════${c_off}"
    echo ""
    echo "  Esta es una clave PÚBLICA: es seguro pegarla donde quieras."
    echo "  La privada NUNCA sale de este disco. Ejecuta en ${PRIMARY_IP}:"
    echo ""
    echo "    sudo ./install-satom.sh --authorize-peer ${NODE_IP} \\"
    echo "      \"${PEER_PUB}\""
    echo ""
    echo "  Hasta entonces el datasync de data/ fallará (Postgres SÍ replica ya)."
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Nodo SECONDARY unido al clúster:"
    echo "   • Postgres réplica streaming de ${PRIMARY_IP} (TLS verify-ca)"
    echo "   • data/ se sincroniza cada 5 min (satom-ha-datasync.timer)"
    echo "   • Certificado TLS propio emitido por la CA del clúster"
    echo "   • El scheduler queda en espera (solo se activa si promueves este nodo)"
fi

# [SATOM-ARM-BANNER] Ninguna ScheduledAction se siembra: son datos y gana la
# edicion del operador (docs/safeguards.md §10). Esa decision es deliberada,
# pero hasta ahora NADIE se lo decia al que acaba de instalar: el banner final
# hablaba solo del hardening de SSH. Resultado: un nodo recien instalado se
# queda sin respaldo de BD, sin refresco del SoT, sin bundle del repo y con las
# senales de alerta calculandose para nadie — y el operador solo se entera si
# por su cuenta ejecuta `satom diagnose`. El instalador no las crea; ahora al
# menos nombra el comando que las crea.
if [ "$ROLE" != "secondary" ]; then
    echo ""
    echo "IMPORTANTE — las protecciones NO quedan armadas por si solas:"
    echo "  Las tareas programadas (respaldo de BD, refresco del source-of-truth,"
    echo "  bundle del repositorio, barrido de sondas) son DATOS, no codigo, y no"
    echo "  se siembran para que tu configuracion mande. Sin ellas no hay copias."
    echo ""
    echo "    sudo satom execute seed actions          # muestra el plan"
    echo "    sudo satom execute seed actions --yes    # lo aplica"
    echo ""
    echo "  Y en Settings -> Alerts define un destinatario y un transporte, o cada"
    echo "  senal se calcula puntualmente y se entrega a nadie."
    echo ""
    echo "  Comprueba el estado completo en cualquier momento con:  satom diagnose all"
fi

echo ""
echo "Siguiente paso recomendado: cambia la clave de root del sistema y"
echo "deshabilita el acceso SSH por contraseña (ver docs/INSTALL.md §Hardening)."
