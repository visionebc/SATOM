# SATOM — Manual de instalación

**Producto:** SATOM (System Automation & Task Orchestration Manager) — consola web de
gestión/automatización para FortiWeb, FortiADC y FortiAnalyzer.
**Versión del manual:** 1.2 · **Destino:** Debian 12 (bookworm) amd64 de referencia;
también RHEL/Rocky/Alma 9, openSUSE y Arch (ver §1.4).

Este documento está pensado para entregarse al **equipo de sistemas** junto con la
solicitud de permisos. Contiene todo lo que el instalador hace, qué necesita y cómo
revertirlo.

---

## 1. Requisitos

### 1.1 Hardware mínimo (por nodo)
| Recurso | Mínimo | Recomendado |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 2 GB | 4 GB |
| Disco | 15 GB | 30 GB (crece con backups/reportes) |

### 1.2 Software
- Distribución con **systemd como PID 1** (Alpine/musl no está soportado).
  Referencia: Debian 12 amd64. Soportadas también RHEL/Rocky/Alma 9, openSUSE
  y Arch — el instalador detecta el gestor de paquetes.
- Acceso **root** durante la instalación (ver §5). El instalador lo comprueba
  antes de nada y **verifica además que root pueda escribir de verdad** en
  `/opt`, `/etc`, `/etc/systemd/system`, `/var/log` y `/usr/local/sbin`: en un
  contenedor no privilegiado o con `/` en sólo lectura, ser uid 0 no basta.
- Python **>= 3.10** (lo exigen las dependencias pinneadas). Si no está, el
  instalador instala el de la distribución.
- **Online:** salida HTTPS a los mirrors de la distro + PyPI + el repositorio
  git del producto.
- **Offline:** ninguna salida a Internet — el bundle trae todo.

> Comprueba la máquina **sin instalar nada** con
> `sudo bash install-satom.sh --preflight` (ver §1.6).

### 1.3 Red / puertos
| Puerto | Uso | Quién debe alcanzarlo |
|---|---|---|
| `<puerto elegido>` (defecto 443) | Consola web HTTPS | operadores |
| 80/tcp | Redirección a HTTPS + challenge ACME (`/.well-known/acme-challenge/`) | operadores y, si se usa ACME público, la CA |
| 8443/tcp | Sondas de salud entre nodos (TLS + clave de identidad compartida) | el otro nodo (solo cluster) |
| 5432/tcp | Réplica Postgres (solo cluster, TLS `verify-ca` forzado) | el otro nodo |
| 22/tcp | Sync de `data/` por rsync/SSH (solo cluster) | el otro nodo |
| salida hacia los Fortinet | HTTPS/SSH de gestión | este nodo → appliances |

Los puertos 80 y 8443 son **fijos**; el de la consola se elige en la
instalación. El preflight avisa si alguno está ya ocupado y por qué proceso.

### 1.4 Paquetería que se instala (para aprobación previa de sistemas)

El instalador **no compila nada** y sólo usa los repositorios oficiales de la
distribución. Esta es la lista completa y exacta — el mismo contenido que las
listas `REQUIRED_PKGS` del script:

| Concepto | Debian / Ubuntu (`apt`) | RHEL / Rocky / Alma 9 (`dnf`,`yum`) | openSUSE (`zypper`) | Arch (`pacman`) | Para qué |
|---|---|---|---|---|---|
| Python >= 3.10 | `python3` `python3-venv` `python3-pip` | `python3.11` `python3.11-pip` | `python311` `python311-pip` | `python` `python-pip` | ejecutar la app en su propio venv |
| Base de datos | `postgresql` | `postgresql-server` `postgresql` | `postgresql-server` `postgresql` | `postgresql` | fuente de verdad (BD `fortinet_mgr`) |
| Servidor web | `nginx` | `nginx` | `nginx` | `nginx` | TLS y proxy inverso hacia gunicorn |
| Sincronización | `rsync` | `rsync` | `rsync` | `rsync` | copia de `data/` entre nodos |
| Criptografía | `openssl` `ca-certificates` | `openssl` `ca-certificates` | `openssl` `ca-certificates` | `openssl` `ca-certificates` | PKI interna, CSR, validación TLS |
| Descargas | `curl` | `curl` | `curl` | `curl` | cliente ACME, sondas HTTP |
| Privilegios | `sudo` | `sudo` | `sudo` | `sudo` | allowlist de **dos** comandos del runtime (§5) |
| Código — solo **ONLINE** | `git` | `git` | `git` | `git` | clonar el repositorio de producción |
| SSH — solo **CLUSTER** | `openssh-client` `openssh-server` | `openssh-clients` `openssh-server` | `openssh` | `openssh` | canal rsync/SSH entre nodos |

Notas que sistemas suele preguntar:

- **En modo OFFLINE no se descarga ninguno**: el bundle trae el cierre completo
  de dependencias (`.deb`, o un repositorio `dnf` local para EL9) y las `wheels`.
- Las dependencias de Python **no se instalan a nivel de sistema**: viven en
  `/opt/satom/venv`. `pip` nunca toca el Python del sistema.
- Un nodo **standalone no recibe `openssh-server`**: sólo se instala si eliges
  modo cluster, porque el standby sincroniza `data/` tirando por SSH del primary.
- **`lego`** (cliente ACME, opcional) no es un paquete de la distribución: es un
  binario estático que va a `/usr/local/bin/lego`, con `sha256` verificado, o se
  copia de `bundle/lego/` en modo offline.
- Al desinstalar **los paquetes se dejan instalados** a propósito (§6).

### 1.5 Lo que debe traer la imagen base (el instalador NO lo instala)

Si alguno falta, la imagen es demasiado mínima y el preflight lo dice por su
nombre en lugar de morir a mitad de instalación:

| Utilidad | Paquete habitual | Uso |
|---|---|---|
| `useradd` `usermod` `passwd` | `shadow` / `passwd` | crear la cuenta de servicio sin shell |
| `runuser` | `util-linux` | operaciones como `postgres` y como la cuenta de servicio |
| `install` `df` `tar` | `coreutils`, `tar` | despliegue de ficheros y comprobación de espacio |
| `awk` `sed` `grep` `hostname` | `gawk`/`busybox`, `sed`, `grep`, `hostname` | scripting del instalador |
| `ss` *(opcional)* | `iproute2` | comprobar puertos ocupados; sin él sólo se avisa |
| systemd como **PID 1** | — | todo el ciclo de vida de servicios |

### 1.6 Comprobación previa sin instalar nada (`--preflight`)

```bash
sudo bash install-satom.sh --preflight     # alias: --check
```

No pregunta nada, no modifica nada y **devuelve 0 si la máquina está lista** o
1 con la lista completa de bloqueadores. Acumula todos los problemas y los
reporta juntos, para que una petición de ventana de cambio lleve la lista
entera y no el primer fallo. Comprueba:

1. **Privilegios reales** — uid 0 *y* escritura efectiva en `/opt`, `/etc`,
   `/etc/systemd/system`, `/var/log`, `/usr/local/sbin`.
2. **systemd como PID 1** (no basta que exista el binario `systemctl`).
3. **Gestor de paquetes** soportado y modo online/offline detectado.
4. **Utilidades base** de §1.5.
5. **Python >= 3.10** presente, o aviso de que se instalará.
6. **Disco y memoria** — bloquea con menos de 4 GB libres en `/opt`, avisa por
   debajo de los 15 GB recomendados o de 2 GB de RAM.
7. **Instalación previa** — si `satom.service` está **activo**, es un
   **bloqueador**: reinstalar encima reescribe `.env` y las unidades. Para
   actualizar se usa la página *Software Update*; para forzar,
   `SATOM_ALLOW_REINSTALL=1`.
8. **Puertos 80 y 8443** libres (o quién los ocupa).
9. **Reloj sincronizado por NTP** — con desviación fallan TLS, el challenge
   ACME y la réplica `verify-ca`.
10. **Salida a Internet** en modo online (PyPI y el repositorio de código).
    Sin PyPI es bloqueador; usa el bundle offline.
11. **SELinux** (informativo; el instalador aplica booleanos y puertos).

En modo cluster, al elegir el modo se ejecuta una segunda comprobación:
cliente SSH (`ssh`, `ssh-keygen`, `ssh-keyscan`) y `rsync` disponibles, y si el
servidor SSH está instalado y activo — obligatorio en el **primary**.

---

## 2. Formas de instalar

### 2.1 Online (con red)
```bash
sudo bash install-satom.sh
```
Descarga paquetes de los mirrors y clona el repo de producción
(`https://git.example.net/satom-prod/SATOM.git`, configurable en el prompt).

### 2.2 Offline (sin red)
```bash
# Debian 12
tar xzf satom-offline-<ver>-debian12-amd64.tar.gz
# RHEL / Rocky / AlmaLinux 9
tar xzf satom-offline-<ver>-rhel9-x86_64.tar.gz

cd satom-installer
sudo bash install-satom.sh        # detecta bundle/ y no toca la red
```
Hay un bundle POR FAMILIA de distro — el instalador rechaza un bundle de la
familia equivocada con un mensaje claro:
- **Debian 12**: cierre completo de dependencias `.deb` + `wheels/` + `app.tar.gz`.
- **RHEL 9**: `bundle/rpms/` es un repositorio dnf local (con metadatos) — dnf
  resuelve solo lo que la máquina necesita; incluye `python3.11` (los pines de
  la app exigen Python >= 3.10 y el python3 del sistema en EL9 es 3.9) y las
  `wheels/` correspondientes (cp311).

Verifica la integridad con el `.sha256` que acompaña a cada tarball.
Los bundles se generan con `installers/build-offline-bundle.sh` (en un Debian 12
con red) y `installers/build-offline-bundle-rhel.sh` (en una máquina o contenedor
rockylinux:9 con red).

---

## 3. Qué pregunta el instalador (en este orden)

**Paso 0 — preflight.** Antes de la primera pregunta se verifica que la máquina
cumple todo lo de §1.6. Si algo falla, aborta sin haber tocado nada.

1. **IP de la máquina** — se autodetecta; se usa en el certificado TLS y en la
   configuración del clúster.
2. **Puerto HTTPS** de la consola (defecto 443).
3. **¿Standalone o cluster?**
4. Si cluster: **¿primary o secondary?**
   - *secondary*: pide **pegar la clave de unión** generada por el primary
     (formato `SATOMJOIN1.…`; se sigue aceptando el heredado `OFMJOIN1.…`).
     Se valida ANTES de instalar nada.
   - *primary*: pregunta la IP prevista del secondary (Enter = permite la subred).
5. **Clave del usuario `admin`** de la consola (solo standalone/primary; el
   secondary la hereda por la réplica de la base de datos).
6. Resumen y confirmación. **Hasta aquí no se ha modificado nada del sistema.**

Después ejecuta, en orden: paquetes → código+venv → PostgreSQL → PKI/certificados →
configuración+servicios → comprobación de salud.

- Si un paquete falta, **lo instala**; si hay una versión vieja (p. ej. Python < 3.9),
  **avisa que la actualizará** a la del repositorio antes de tocarla.

---

## 4. Modo cluster — cómo funciona la unión

1. Instala el **primary** (`cluster` → `primary`). Al final imprime la
   **CLAVE DE UNIÓN** (`SATOMJOIN1.` + blob base64). El prefijo heredado
   `OFMJOIN1.` se sigue aceptando en el secondary.
2. Instala el **secondary** en la otra máquina, elige `cluster` → `secondary` y
   **pega la clave**. Automáticamente:
   - hereda las claves de cifrado de la aplicación (`FERNET_KEY`/`SECRET_KEY`);
   - recibe la **CA interna** del clúster y **emite su PROPIO certificado
     localmente** (la llave privada del nodo nunca viaja por la red);
   - clona la base de datos con `pg_basebackup` y queda como **réplica
     streaming** con TLS `verify-ca` + certificado de cliente;
   - **genera localmente su propia llave SSH** para la sincronización de
     `data/` y muestra su parte **pública** con el comando exacto a ejecutar
     en el primary para autorizarla:

     ```bash
     sudo ./install-satom.sh --authorize-peer <ip-del-standby> "ssh-ed25519 AAAA..."
     ```

     Hasta que ejecutes ese comando, Postgres YA replica pero la
     sincronización de `data/` falla. Es intencionado: la llave privada
     nunca viaja, así que alguien tiene que aprobar la pública;
   - su scheduler queda **en espera**: solo se activa si el nodo se promueve
     (`deploy/satom-promote.sh`), de modo que dos nodos jamás disparan acciones
     a la vez.

> ⚠️ **La clave de unión es un secreto de alto valor**: contiene la clave
> privada de la CA interna, `FERNET_KEY`, `SECRET_KEY` y las contraseñas de
> base de datos. Pásala por un canal seguro, úsala una vez y bórrala.
>
> Desde v1.2 **ya no contiene la llave privada del datasync** — el secondary
> genera la suya y sólo su parte pública se autoriza en el primary, acotada con
> `from=`, `restrict` y un `command=` que sólo permite un rsync de **sólo
> lectura** de `data/`. Antes esa llave daba shell de root desde cualquier IP.

---

## 5. Permisos que hay que solicitar a sistemas

La instalación **requiere privilegios de root** (paquetes, systemd, Postgres,
nginx, certificados). Dos opciones:

**Opción A (recomendada): sesión root/sudo completa durante la ventana de
instalación** (~10–20 min por nodo):
```bash
sudo bash install-satom.sh
```

**Opción B: regla sudoers granular** si sistemas prefiere acotar. El instalador
ejecuta exactamente estas familias de comandos como root:

```
apt-get update / apt-get install / dpkg -i          (paquetería)
git clone | tar -x                                   (código en /opt/satom)
python3 -m venv | pip install                        (dentro de /opt/satom)
runuser -u postgres -- psql|createdb|pg_basebackup   (base de datos)
openssl req|x509 | ssh-keygen                        (certificados y llaves)
cp a /etc/systemd/system + systemctl daemon-reload/enable/start
escritura de /etc/nginx/sites-available/satom.conf + nginx -t + reload
escritura de /etc/postgresql/<v>/main/conf.d + pg_hba.conf (solo cluster)
```

Regla sudoers de ejemplo para un usuario instalador `satominstall`:
```
satominstall ALL=(root) NOPASSWD: /usr/bin/bash /opt/staging/install-satom.sh
```
(entregándole el script por ruta fija; auditar con `sudo journalctl` y el log
`/var/log/satom-install.log` que el instalador escribe siempre).

### Lo que la aplicación necesita en RUNTIME

**La aplicación NO corre como root.** Detalle completo y justificación en
[`privilege-model.md`](privilege-model.md). Resumen:

* Cuenta de servicio sin shell interactivo (`satom` por defecto; una
  instalación heredada puede conservar `fortinet` con `SATOM_APP_USER`). Posee
  `/opt/satom` y `/var/log/satom`.
* `sudo` acotado a **exactamente dos comandos**, en `/etc/sudoers.d/satom`:

  ```
  Cmnd_Alias SATOM_CERT_RELOAD = /usr/sbin/nginx -t, /usr/bin/systemctl reload nginx
  satom ALL=(root) NOPASSWD: SATOM_CERT_RELOAD
  ```

  Son los que necesita el gestor de certificados para validar y activar un
  cert nuevo. **No se concede instalación de paquetes ni `systemctl` genérico**:
  ambos son equivalentes a root (un `.deb` ejecuta sus propios scripts como
  root), no un subconjunto de él.
* Todo lo que sí requiere root —instalar unidades, `pip`, reiniciar el propio
  servicio— pasa por `satom-updater.service`, un runner oneshot que corre como
  root, se dispara por `satom-updater.path` y **re-valida** cada petición
  contra su propia allowlist.
* En cluster: rol de réplica `fm_repl`, y SSH entre nodos **de cuenta de
  servicio a cuenta de servicio** (ya no root→root) con forced command.

Para migrar un nodo instalado con v1.1 o anterior, **un nodo a la vez y el
standby primero**:

```bash
sudo bash /opt/satom/deploy/migrate-deprivilege.sh
```

---

## 6. Después de instalar

- Consola: `https://<IP>:<puerto>/` — usuario `admin` + la clave elegida.
- Salud: `curl -k https://<IP>:<puerto>/healthz` → `200`.
- Servicios: `systemctl status satom satom-scheduler`.
- Logs: `/var/log/satom/` y `journalctl -u satom`.

### Hardening obligatorio post-instalación
1. **Cambiar la clave de root** del sistema operativo si se entregó una
   temporal para la instalación.
2. Deshabilitar SSH por contraseña (`PasswordAuthentication no`) y dejar solo
   llaves.
3. Borrar la clave de unión de cualquier nota/chat.
4. Restringir el puerto de la consola por firewall a las redes de operación.
5. Comprobar que el modelo de privilegio quedó aplicado:

   ```bash
   # el proceso web NO debe ser root
   ps -o user= -p $(systemctl show satom.service -p MainPID --value)

   # la allowlist permite dos cosas y nada más
   sudo -u satom sudo -n nginx -t                  # permitido
   sudo -u satom sudo -n apt-get install hello     # DEBE fallar
   sudo -u satom sudo -n systemctl restart satom   # DEBE fallar
   ```
6. En cluster, comprobar que la llave del peer no da shell:

   ```bash
   # desde el standby — debe ser RECHAZADO
   sudo -u satom ssh -i /opt/satom/.ssh/id_ha_rsync satom@<ip-primary> id
   ```

### Desinstalar / revertir
```bash
systemctl disable --now satom satom-scheduler \
  satom-updater.path satom-cert-renew.timer satom-ha-datasync.timer 2>/dev/null
rm -f /etc/systemd/system/satom* /etc/systemd/system/fm-*
rm -f /etc/nginx/sites-enabled/satom.conf /etc/nginx/sites-available/satom.conf
systemctl daemon-reload && systemctl reload nginx
runuser -u postgres -- dropdb fortinet_mgr; runuser -u postgres -- dropuser fortinet
rm -rf /opt/satom /var/log/satom
```
Los paquetes de sistema (postgres, nginx…) se dejan instalados a propósito;
si hay que retirarlos lo decide sistemas (`apt-get remove`).

---

## 7. Soporte

- Log de instalación: `/var/log/satom-install.log` (siempre se escribe).
- Repositorio de producción: `satom-prod/SATOM` (Gitea interno).
- El catálogo de aplicaciones (apps.example.net → SATOM → plataforma web)
  publica este instalador y el bundle offline, y tiene los botones
  **Sync Prod with Git/GitHub** para promover código de desarrollo a producción.
