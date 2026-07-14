# OFortMAut — Manual de instalación

**Producto:** OFortMAut (Open Fortinet Management Automation Tool) — consola web de
gestión/automatización para FortiWeb, FortiADC y FortiAnalyzer.
**Versión del manual:** 1.0 · **Destino:** Debian 12 (bookworm), amd64.

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
- Debian 12 (bookworm) amd64, instalación base.
- Acceso **root** o sudo (ver §5).
- **Online:** salida a mirrors Debian + PyPI + el repositorio git del producto.
- **Offline:** ninguna salida a Internet — el bundle trae todo.

### 1.3 Red / puertos
| Puerto | Uso | Quién debe alcanzarlo |
|---|---|---|
| `<puerto elegido>` (defecto 443) | Consola web HTTPS | operadores |
| 5432/tcp | Réplica Postgres (solo modo cluster, TLS forzado) | el otro nodo |
| 22/tcp | Sync de `data/` por rsync/SSH (solo cluster) | el otro nodo |
| salida hacia los Fortinet | HTTPS/SSH de gestión | este nodo → appliances |

---

## 2. Formas de instalar

### 2.1 Online (con red)
```bash
sudo bash install-ofortmaut.sh
```
Descarga paquetes de los mirrors y clona el repo de producción
(`https://git.example.net/ofortmaut-prod/OFortMAut.git`, configurable en el prompt).

### 2.2 Offline (sin red)
```bash
# Debian 12
tar xzf ofortmaut-offline-<ver>-debian12-amd64.tar.gz
# RHEL / Rocky / AlmaLinux 9
tar xzf ofortmaut-offline-<ver>-rhel9-x86_64.tar.gz

cd ofortmaut-installer
sudo bash install-ofortmaut.sh        # detecta bundle/ y no toca la red
```
Hay un bundle POR FAMILIA de distро — el instalador rechaza un bundle de la
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

1. **IP de la máquina** — se autodetecta; se usa en el certificado TLS y en la
   configuración del clúster.
2. **Puerto HTTPS** de la consola (defecto 443).
3. **¿Standalone o cluster?**
4. Si cluster: **¿primary o secondary?**
   - *secondary*: pide **pegar la clave de unión** generada por el primary
     (formato `OFMJOIN1.…`). Se valida ANTES de instalar nada.
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
   **CLAVE DE UNIÓN** (`OFMJOIN1.` + blob base64).
2. Instala el **secondary** en la otra máquina, elige `cluster` → `secondary` y
   **pega la clave**. Automáticamente:
   - hereda las claves de cifrado de la aplicación (`FERNET_KEY`/`SECRET_KEY`);
   - recibe la **CA interna** del clúster y **emite su PROPIO certificado
     localmente** (la llave privada del nodo nunca viaja por la red);
   - clona la base de datos con `pg_basebackup` y queda como **réplica
     streaming** con TLS `verify-ca` + certificado de cliente;
   - programa la sincronización de `data/` (bundles, vault, estados) cada 5 min
     vía rsync/SSH con llave dedicada;
   - su scheduler queda **en espera**: solo se activa si el nodo se promueve
     (`deploy/fm-promote.sh`), de modo que dos nodos jamás disparan acciones
     a la vez.

> ⚠️ **La clave de unión es un secreto de alto valor** (contiene la CA y las
> credenciales de sincronización). Pásala por un canal seguro, úsala una vez y
> bórrala. Cualquiera con esa clave puede unirse al clúster.

---

## 5. Permisos que hay que solicitar a sistemas

La instalación **requiere privilegios de root** (paquetes, systemd, Postgres,
nginx, certificados). Dos opciones:

**Opción A (recomendada): sesión root/sudo completa durante la ventana de
instalación** (~10–20 min por nodo):
```bash
sudo bash install-ofortmaut.sh
```

**Opción B: regla sudoers granular** si sistemas prefiere acotar. El instalador
ejecuta exactamente estas familias de comandos como root:

```
apt-get update / apt-get install / dpkg -i          (paquetería)
git clone | tar -x                                   (código en /opt/fortinet-manager)
python3 -m venv | pip install                        (dentro de /opt/fortinet-manager)
runuser -u postgres -- psql|createdb|pg_basebackup   (base de datos)
openssl req|x509 | ssh-keygen                        (certificados y llaves)
cp a /etc/systemd/system + systemctl daemon-reload/enable/start
escritura de /etc/nginx/sites-available/ofortmaut.conf + nginx -t + reload
escritura de /etc/postgresql/<v>/main/conf.d + pg_hba.conf (solo cluster)
```

Regla sudoers de ejemplo para un usuario instalador `ofminstall`:
```
ofminstall ALL=(root) NOPASSWD: /usr/bin/bash /opt/staging/install-ofortmaut.sh
```
(entregándole el script por ruta fija; auditar con `sudo journalctl` y el log
`/var/log/ofortmaut-install.log` que el instalador escribe siempre).

**Lo que la aplicación necesita en runtime** (queda configurado): servicios
systemd `fortinet-manager*`, `fm-*`; usuario de BD `fortinet` (local);
en cluster el rol de réplica `fm_repl` y SSH root→root entre nodos con la llave
dedicada `id_ha_rsync` (se puede restringir con `command=` en authorized_keys).

---

## 6. Después de instalar

- Consola: `https://<IP>:<puerto>/` — usuario `admin` + la clave elegida.
- Salud: `curl -k https://<IP>:<puerto>/healthz` → `200`.
- Servicios: `systemctl status fortinet-manager fortinet-manager-scheduler`.
- Logs: `/var/log/fortinet-manager/` y `journalctl -u fortinet-manager`.

### Hardening obligatorio post-instalación
1. **Cambiar la clave de root** del sistema operativo si se entregó una
   temporal para la instalación.
2. Deshabilitar SSH por contraseña (`PasswordAuthentication no`) y dejar solo
   llaves.
3. Borrar la clave de unión de cualquier nota/chat.
4. Restringir el puerto de la consola por firewall a las redes de operación.

### Desinstalar / revertir
```bash
systemctl disable --now fortinet-manager fortinet-manager-scheduler \
  fortinet-manager-updater.path fm-cert-renew.timer fm-ha-datasync.timer 2>/dev/null
rm -f /etc/systemd/system/fortinet-manager* /etc/systemd/system/fm-*
rm -f /etc/nginx/sites-enabled/ofortmaut.conf /etc/nginx/sites-available/ofortmaut.conf
systemctl daemon-reload && systemctl reload nginx
runuser -u postgres -- dropdb fortinet_mgr; runuser -u postgres -- dropuser fortinet
rm -rf /opt/fortinet-manager /var/log/fortinet-manager
```
Los paquetes de sistema (postgres, nginx…) se dejan instalados a propósito;
si hay que retirarlos lo decide sistemas (`apt-get remove`).

---

## 7. Soporte

- Log de instalación: `/var/log/ofortmaut-install.log` (siempre se escribe).
- Repositorio de producción: `ofortmaut-prod/OFortMAut` (Gitea interno).
- El catálogo de aplicaciones (apps.example.net → OFortMAut → plataforma web)
  publica este instalador y el bundle offline, y tiene los botones
  **Sync Prod with Git/GitHub** para promover código de desarrollo a producción.
