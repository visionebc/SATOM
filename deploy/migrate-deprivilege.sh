#!/usr/bin/env bash
# ============================================================================
# migrate-deprivilege.sh — mueve una instalación SATOM existente de
# "todo como root" al modelo de privilegio mínimo (docs/privilege-model.md).
#
# EJECUTAR UN NODO A LA VEZ, EL STANDBY PRIMERO. Idempotente.
#
# Qué hace:
#   1. Adopta el usuario de servicio existente (fortinet) o crea 'satom'.
#   2. Corrige la propiedad de state/ y /var/log/satom — root-owned en nodos
#      heredados justamente porque la app corría como root.
#   3. Instala /etc/sudoers.d/satom con DOS comandos y nada más.
#   4. Reescribe User=/Group= en las unidades que no necesitan root.
#      satom-updater.{path,service} se deja como root A PROPÓSITO.
#   5. daemon-reload + restart + comprobación de salud.
#
# Rollback: restaurar /root/satom-units.pre-deprivilege-<ts>/ y borrar
#           /etc/sudoers.d/satom.
# ============================================================================
set -euo pipefail

APP_DIR="/opt/satom"
LOG_DIR="/var/log/satom"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP="/root/satom-units.pre-deprivilege-${TS}"

c_bold=$'\033[1m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_red=$'\033[31m'; c_off=$'\033[0m'
say()  { echo "${c_bold}==>${c_off} $*"; }
ok()   { echo "    ${c_grn}✓${c_off} $*"; }
warn() { echo "    ${c_ylw}!${c_off} $*"; }
die()  { echo "${c_red}ERROR:${c_off} $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Ejecuta como root: sudo bash $0"
[ -d "$APP_DIR" ] || die "No existe $APP_DIR"

# --- 1. usuario de servicio -------------------------------------------------
# Preferimos adoptar el que ya posee el árbol: renombrarlo obligaría a tocar
# el rol de Postgres homónimo y no aporta nada de seguridad.
APP_USER="${SATOM_APP_USER:-}"
if [ -z "$APP_USER" ]; then
    OWNER="$(stat -c %U "$APP_DIR")"
    if [ "$OWNER" != "root" ] && id -u "$OWNER" >/dev/null 2>&1; then
        APP_USER="$OWNER"
    else
        APP_USER="satom"
    fi
fi

if ! id -u "$APP_USER" >/dev/null 2>&1; then
    NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
    [ -x "$NOLOGIN" ] || NOLOGIN=/bin/false
    useradd --system --home-dir "$APP_DIR" --shell "$NOLOGIN" \
            --comment "SATOM service account" "$APP_USER"
    ok "Usuario de servicio ${APP_USER} creado"
else
    ok "Usuario de servicio ${APP_USER} adoptado (uid $(id -u "$APP_USER"))"
fi
APP_GROUP="$(id -gn "$APP_USER")"

# --- 2. propiedad -----------------------------------------------------------
say "Corrigiendo propiedad de rutas escribibles"
mkdir -p "$APP_DIR/state" "$APP_DIR/.ssh" "$LOG_DIR"
# El árbol ENTERO, no sólo unos directorios: la app hace commits git sobre
# reports/ y escribe backups, así que cualquier fichero suelto que quedara
# root-owned (por haber corrido como root) rompe una operación más tarde.
# Caso real: data/acme quedó 0700 root y el rsync del standby fallaba con
# "Permission denied" pese a estar bien autenticado.
chown -R "${APP_USER}:${APP_GROUP}" "$APP_DIR" "$LOG_DIR"
chmod 700 "$APP_DIR/state" "$APP_DIR/.ssh"
[ -d "$APP_DIR/data/acme" ] && chmod 700 "$APP_DIR/data/acme"
if [ -f "$APP_DIR/.env" ]; then
    chown root:"$APP_GROUP" "$APP_DIR/.env"; chmod 640 "$APP_DIR/.env"
fi
# git necesita confiar en el árbol para el usuario que ahora lo usa
git config --global --add safe.directory "$APP_DIR" 2>/dev/null || true
ok "state/, .ssh/, ${LOG_DIR}, data/, pki/ → ${APP_USER}:${APP_GROUP}"

# --- 3. sudoers -------------------------------------------------------------
say "Instalando allowlist de sudo (2 comandos)"
command -v sudo >/dev/null 2>&1 || die "sudo no está instalado — instálalo antes de migrar"
NGINX_BIN="$(command -v nginx || echo /usr/sbin/nginx)"
SYSTEMCTL_BIN="$(command -v systemctl || echo /usr/bin/systemctl)"
cat > /etc/sudoers.d/satom <<SUDOERS
# Generado por migrate-deprivilege.sh — ver docs/privilege-model.md
# NO añadir aquí gestores de paquetes ni systemctl genérico: sería root.
Cmnd_Alias SATOM_CERT_RELOAD = ${NGINX_BIN} -t, ${SYSTEMCTL_BIN} reload nginx
${APP_USER} ALL=(root) NOPASSWD: SATOM_CERT_RELOAD
Defaults:${APP_USER} !requiretty
SUDOERS
chmod 440 /etc/sudoers.d/satom
visudo -cf /etc/sudoers.d/satom >/dev/null \
    || { rm -f /etc/sudoers.d/satom; die "La regla sudoers generada es inválida"; }
ok "${APP_USER} sólo puede: '${NGINX_BIN} -t' y '${SYSTEMCTL_BIN} reload nginx'"

# --- 4. wrapper del datasync ------------------------------------------------
if [ -f "$APP_DIR/deploy/satom-ha-rsync-shell" ]; then
    install -m 0755 "$APP_DIR/deploy/satom-ha-rsync-shell" /usr/local/sbin/
    ok "Forced command del datasync instalado"
fi
if [ -f "$APP_DIR/deploy/satom-ha-datasync.sh" ]; then
    install -m 0755 "$APP_DIR/deploy/satom-ha-datasync.sh" /usr/local/sbin/
    ok "satom-ha-datasync.sh desplegado (faltaba en el primary)"
fi

# --- 5. unidades ------------------------------------------------------------
say "Degradando unidades a ${APP_USER}"
mkdir -p "$BACKUP"
DEPRIV=(satom.service satom-scheduler.service satom-reconciler.service
        satom-alerts.service satom-cert-renew.service
        satom-git-publish.service satom-ha-datasync.service)
for unit in "${DEPRIV[@]}"; do
    f="/etc/systemd/system/$unit"
    [ -f "$f" ] || { warn "$unit no está instalada — se omite"; continue; }
    cp "$f" "$BACKUP/"
    if grep -qE '^User=' "$f"; then
        sed -i "s#^User=.*#User=${APP_USER}#" "$f"
    else
        sed -i "/^\[Service\]/a User=${APP_USER}" "$f"
    fi
    if grep -qE '^Group=' "$f"; then
        sed -i "s#^Group=.*#Group=${APP_GROUP}#" "$f"
    else
        sed -i "/^User=/a Group=${APP_GROUP}" "$f"
    fi
    # El sed de arriba deja la unidad coherente, pero NO es durable: cada
    # self-update recopia deploy/<unit> (User=root). El drop-in sí sobrevive.
    install -d -m 0755 "${f}.d"
    cat > "${f}.d/10-app-user.conf" <<DROPIN
# Generado por migrate-deprivilege.sh. Vive en un drop-in porque las plantillas
# de deploy/ declaran User=root y cada update las recopia. NO editar a mano.
[Service]
User=${APP_USER}
Group=${APP_GROUP}
DROPIN
    ok "$unit → User=${APP_USER} (unidad + drop-in)"
done
warn "satom-updater.{path,service} se dejan como ROOT a propósito (runner privilegiado)"
echo "    backup de las unidades: $BACKUP"

# --- 6. aplicar + verificar -------------------------------------------------
say "Recargando systemd y reiniciando"
systemctl daemon-reload
systemctl restart satom.service
for u in satom-scheduler satom-reconciler; do
    systemctl is-enabled "$u.service" >/dev/null 2>&1 && systemctl restart "$u.service" || true
done

PORT="$(grep -oP '(?<=--bind )[0-9.]+:\K[0-9]+' /etc/systemd/system/satom.service | head -1)"
PORT="${PORT:-8000}"
if timeout 45 bash -c "until curl -sfo /dev/null http://127.0.0.1:${PORT}/healthz; do sleep 1; done"; then
    ok "satom.service responde /healthz 200 como ${APP_USER}"
else
    echo ""
    systemctl status satom.service --no-pager -l | tail -20
    die "satom.service NO respondió tras el cambio. Restaura: cp $BACKUP/* /etc/systemd/system/ && systemctl daemon-reload && systemctl restart satom.service"
fi

RUNAS="$(ps -o user= -p "$(systemctl show satom.service -p MainPID --value)" 2>/dev/null | tr -d ' ')"
[ "$RUNAS" = "$APP_USER" ] && ok "Proceso confirmado corriendo como ${RUNAS}" \
                           || warn "El proceso corre como '${RUNAS}' (esperado ${APP_USER})"

echo ""
echo "${c_grn}Migración completada.${c_off} Siguiente nodo: repite este script allí."
echo "Recuerda re-autorizar el peer con --authorize-peer si cambias las llaves HA."
