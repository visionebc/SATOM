# Running SATOM with Docker Compose — operator manual

Status: **operator reference** for SATOM **2.1.2**. Every statement on this page
is taken from the files that implement the stack, which are listed in §15.
Where the code does not provide something, this page says so rather than
filling the gap. Paragraphs marked **Recommendation** or **Design requirement**
describe something the stack does *not* do today.

[`docker.md`](docker.md) explains *why* the container shape is built the way it
is. This page covers *how to run it*: installing, what each service is allowed
to do, configuring, operating and recovering. The two pages are meant to be
read together; this one does not repeat the rationale.

---

## 1. Scope — what the Compose deployment is, and what it is not

### 1.1 What it is

The SATOM application packaged as one image (`satom:<tag>`, built from the
repository's `Dockerfile`), plus its dependencies as stock images, started as
one Compose project named `satom` (`name: satom` in
`deploy/docker/compose.yaml`). The web worker, the scheduler and the periodic
jobs are **the same image**; the entrypoint selects the role from `SATOM_ROLE`.

The image declares `SATOM_RUNTIME=container`. That declaration makes
`app/runtime.py` deny four host-only capabilities (§7). Apart from those four,
[`docker.md`](docker.md) states that the product behaves as it does on a host
install.

### 1.2 What it is not

| Present on a host install | In the Compose stack | Source |
|---|---|---|
| `satom-updater.path` / `.service` (the root runner: self-update, pip, unit install, promotion) | **absent** | `compose.yaml` header, `entrypoint.sh` header, `app/runtime.py` |
| `satom-integrations.path` / `.service` | **absent** | same |
| `satom-reconciler.service` | **absent** | same |
| `satom-cert-renew.service` / `.timer` | **absent**; the self-issued certificate is only re-checked when `tls-init` runs, i.e. on `up` (§9.4) | same, `proxy-init.sh` |
| `satom-ha-datasync` (pulls the peer's `data/`) | **absent**; no compose file syncs the `satom-data` volume between nodes (§10.9) | no such service in any compose file |
| `satom-alerts.timer`, `satom-responder.timer` | replaced by the `cron` service | `cron-runner.sh` |
| The `satom` console CLI launcher (`/usr/local/sbin/satom`, installed by `deploy/install-cli.sh`) | **not installed in the image** (the image copies `deploy/`, but no step installs the launcher or its library) | `Dockerfile`, `deploy/satom-cli-launcher` |
| An ACME client for the node's own certificate | **not in the image** (the `Dockerfile` installs no ACME client) | `Dockerfile` (§9.5) |
| An offline (air-gapped) guided install | **not published**: `satom-setup.sh` stops in Docker mode without Internet access | `installers/satom-setup.sh` (§11.8 for the manual route) |
| An operations agent that performs the four renounced capabilities from the web UI | **not shipped** in any 2.1.2 file | §7 |

If you need in-place self-update, the in-product HA promotion or the certificate
activation button, use a host install ([`INSTALL.md`](INSTALL.md)).

### 1.3 Supported shapes

| Shape | Compose files applied | How to get it |
|---|---|---|
| **Development**, single node | `compose.yaml` | `deploy/docker/satom-docker.sh` with `SATOM_ENV` unset (§3.2) |
| **Production**, single node, bundled PostgreSQL | `compose.yaml` + `compose.prod.yaml` | `satom-setup.sh` role `standalone` (§2), or `SATOM_ENV=prod` with the manual route (§3.3) |
| **Production**, single node, **external PostgreSQL** | `compose.yaml` + `compose.prod.yaml` + the installer's `compose.setup.yaml` | `satom-setup.sh` only (`SETUP_DB=external`, §2.5). The role is forced to `standalone`. No manual equivalent ships. |
| **Production primary + standby** | primary: `compose.yaml` + `compose.prod.yaml`; standby: the same + `compose.standby.yaml` | `satom-setup.sh` roles `primary` / `standby` (§10.2), or manually (§10.3) |

### 1.4 Requirements

| Item | Requirement | Source |
|---|---|---|
| Docker Engine | **No minimum version is checked.** The external-database mode uses `extra_hosts: host.docker.internal:host-gateway`, and Docker only supports `host-gateway` from Engine 20.10. | `satom-setup.sh` (no check); Docker's documentation |
| Docker Compose | **v2 plugin** (`docker compose`). `satom-setup.sh` refuses anything older than **2.20.0**. | `ensure_docker()` in `satom-setup.sh` |
| Compose on a **standby** | **≥ 2.24.4.** `compose.standby.yaml` uses the `!reset` tag. `satom-setup.sh` checks this; `satom-docker.sh` does not. | `compose.standby.yaml`, `satom-setup.sh` |
| CPU | 2 or more cores recommended (the installer only warns below 2) | `check_requirements()` |
| RAM | ≥ 3800 MB passes; 1900–3799 MB warns (the installer recommends 4 GB and says Docker needs more); < 1900 MB is refused | `check_requirements()` |
| Free disk on `/` | ≥ 15000 MB passes; 8000–14999 MB warns (the installer says Docker needs about 15 GB); < 8000 MB is refused | `check_requirements()` |
| Memory ceilings in production | `postgres` 2 GB, `victoria-metrics` 2 GB, `web` 3 GB (`deploy.resources.limits.memory`). These are hard limits, not reservations. Other services are unlimited. | `compose.prod.yaml` |
| Ports on the host | `443` and `80` (the proxy); on a primary also `5432` on `SATOM_PG_BIND`. The installer reports whether 80 and 443 are free. | `compose.yaml`, `compose.prod.yaml`, `check_requirements()` |
| Internet access | `satom-setup.sh` Docker mode downloads the release source from GitHub, builds the image (the build runs `apt-get` and `pip`) and pulls the base images. **Without Internet access it stops.** | `install_docker()`, `fetch_source()` |
| Host tools for the installer | `curl`, `openssl`, `tar`; root | `check_requirements()` |

For fleet-dependent sizing see [`sizing.md`](sizing.md). That page describes
host installs; the container memory ceilings above apply on top of it.

---

## 2. Quick start A — `satom-setup.sh` (guided, recommended)

`installers/satom-setup.sh` installs, updates and uninstalls the Docker variant.
It must run as root.

### 2.1 Interactive

```bash
curl -fsSLO https://github.com/visionebc/SATOM/releases/download/v2.1.2/satom-setup.sh
sudo bash satom-setup.sh --check     # system checks only; installs nothing
sudo bash satom-setup.sh             # choose "docker" when asked for the mode
```

Yes/no questions take `y`/`n`. `--help` prints every option and every
`SETUP_*` variable.

### 2.2 Unattended (`--yes`)

With `--yes`, every question reads its `SETUP_*` variable from the environment
or from the `--answers` file. If a variable is unset, the question takes its
default. If there is no default either, the script stops and names the missing
variable. The `--answers` file is **sourced by bash** (`set -a; . FILE`), so
values that contain spaces must be quoted.

Single node, bundled PostgreSQL:

```bash
cat > /root/satom-answers.env <<'EOF'
SETUP_MODE=docker
SETUP_ROLE=standalone
SETUP_DB=bundled
SETUP_NAMES="satom.example.com"
SETUP_IP=192.0.2.10
SETUP_PORT=443
SETUP_CERT=self
SETUP_FIREWALL=yes
SETUP_INSTALL_DOCKER=yes
EOF
chmod 600 /root/satom-answers.env
sudo bash satom-setup.sh --yes --answers /root/satom-answers.env
```

**Always set `SETUP_MODE=docker`.** `--help` lists it as required, but the code
falls back to a default: `native`, or `docker` when an existing Docker install
is detected.

The `admin` password is taken from `SATOM_ADMIN_PASSWORD` if it is set. It must
be at least 10 characters, use at least three of the four character classes
(lower, upper, digit, symbol) and contain no single quote. If it is unset, the
script generates a password and writes it **only** to
`/root/satom-admin-password.txt` (mode 0600).

### 2.3 `SETUP_*` variables that apply to Docker mode

| Variable | Values / default | Notes |
|---|---|---|
| `SETUP_MODE` | `native` \| `docker` | Set it explicitly (see above). |
| `SETUP_ROLE` | `standalone` \| `primary` \| `standby`; default `standalone` | Ignored with `SETUP_DB=external` (the role is forced to `standalone`). |
| `SETUP_NAMES` | space-separated DNS names; default: `hostname -f` | Lower-cased. Becomes `SATOM_SERVED_NAMES`, i.e. the certificate SAN. |
| `SETUP_IP` | IPv4; default: the detected primary address | On a `primary` it becomes `SATOM_PG_BIND=<ip>:5432` and the `SATOM_PRIMARY_HOST` in the join file. **Not** added to the certificate. |
| `SETUP_PORT` | 1–65535; default `443` | Becomes `SATOM_HTTPS_BIND=0.0.0.0:<port>`. See §9.7 before changing it. |
| `SETUP_DB` | `bundled` \| `external`; default `bundled` | |
| `SETUP_DB_HOST` | no default (required for `external`) | `localhost`, `127.*` and `::1` are rewritten to `host.docker.internal`. |
| `SETUP_DB_PORT` / `SETUP_DB_NAME` / `SETUP_DB_USER` | `5432` / `satom` / `satom` | |
| `SETUP_DB_PASSWORD` | required for `external` with `--yes` | No single quote allowed. |
| `SETUP_JOIN_FILE` | path; required for `standby` | The file written by the primary (§10.2). |
| `SETUP_AGENT` | `yes` \| `no` | **Has no effect in 2.1.2** (§7.4). |
| `SETUP_CERT` | `self` \| `import`; default `self` | |
| `SETUP_CERT_FILE` / `SETUP_KEY_FILE` | PEM paths; required for `import` | The installer refuses a certificate and key that do not match. |
| `SETUP_CHAIN_FILE` | PEM path; default none | |
| `SETUP_FIREWALL` | `yes` \| `no`; default yes | Only consulted when firewalld or ufw is active. Opens `80`, the HTTPS port, and `5432` on a primary. See §13 about Docker and host firewalls. |
| `SETUP_INSTALL_DOCKER` | `yes` \| `no`; default yes | Installs Docker and/or the Compose v2 plugin if missing. |
| `SETUP_EXISTING` | `update` \| `abort`; default `update` | Used when a Docker install already exists (§11.1). `reinstall` is a native-mode answer only. |
| `SATOM_ADMIN_PASSWORD` | see §2.2 | Not asked on a standby. |

Command-line options: `--check`, `--yes`/`-y`, `--answers FILE`,
`--version X.Y.Z` (or `latest`), `--force` (continue on an unsupported
distribution), `--uninstall`, `--purge`, `-h`/`--help`. `--bundle` is for
native mode only.

### 2.4 What the installer does, in order (Docker mode)

1. Checks the OS, CPU, RAM, disk, ports 80/443 and Internet access, and
   resolves the version (its own `SETUP_VERSION`, 2.1.2, unless `--version` is
   given). Refuses if the machine already has a **native** install.
2. Ensures Docker is running and Compose v2 is at least 2.20.0, installing
   them if allowed.
3. Asks for the names, IP and port; the database; the role; the agent option;
   the certificate; and the `admin` password. The password is not asked on a
   standby.
4. Downloads the release source from GitHub into
   `/opt/satom-docker/releases/<ver>`. It **refuses** a tree that contains an
   invalid network literal (a network written with host bits set).
5. Builds `satom:<ver>` from that tree. The first build takes 5–15 minutes.
6. Writes `/opt/satom-docker/satom.env` from `env.example` with generated
   `SECRET_KEY`, `FERNET_KEY`, `POSTGRES_PASSWORD` and `SATOM_REPL_PASSWORD`.
   If the file already exists, its secrets are **reused and never
   regenerated**. On a standby, it imports the primary's secrets from the
   join file. It then sets `SATOM_ENV=prod`, `SATOM_NODE_ROLE`,
   `SATOM_IMAGE=satom:<ver>`, `SATOM_SERVED_NAMES`, `SATOM_HTTPS_BIND`,
   `SATOM_REDIRECT_BIND=0.0.0.0:80`, `TZ` (the host's time zone, else `UTC`),
   `SATOM_SETUP_AGENT`, `SATOM_PG_BIND` and, for an external database, the
   `SATOM_EXT_DB_*` variables.
7. Links `current/deploy/docker/.env` to `satom.env` and writes
   `/opt/satom-docker/compose.setup.yaml` (§5.10) and the
   `/usr/local/sbin/satom-docker` wrapper. It then validates the result with
   `satom-docker config -q`.
8. For an external database, tests connectivity and table-creation rights from
   a throwaway `postgres:15-bookworm` container.
9. Pulls the base images **by name**, excluding `satom:*`. It deliberately does
   not run `compose pull`, which would try to fetch `satom:<ver>` from Docker
   Hub.
10. If `SETUP_CERT=import`, imports the certificate into the `satom-pki`
    volume (the same command as §7.3.3).
11. Runs `satom-docker up -d`, passing the admin password in the process
    environment as `SATOM_SETUP_ADMIN_PW`. It then waits up to 7 minutes for
    `https://127.0.0.1:<port>/healthz` to return 200 and lists any container
    that is not running or is unhealthy.
12. On a non-standby node, confirms that the `admin` account accepts the chosen
    password. On a **primary**, writes the join file
    `/root/satom-docker-join.env` (0600). Offers to open the firewall ports.
13. Writes `/opt/satom-docker/.installed` and a summary to
    `/root/satom-setup-summary.txt` (0600). The installer's log is
    `/var/log/satom-setup.log` (0600).

A Docker install that failed half-way leaves `satom.env` behind without
`.installed`. The next run resumes with the same secrets.

### 2.5 External PostgreSQL (`SETUP_DB=external`)

```bash
cat > /root/satom-answers.env <<'EOF'
SETUP_MODE=docker
SETUP_DB=external
SETUP_DB_HOST=db.example.com
SETUP_DB_PORT=5432
SETUP_DB_NAME=satom
SETUP_DB_USER=satom
SETUP_DB_PASSWORD='use-a-real-password'
SETUP_NAMES="satom.example.com"
SETUP_CERT=self
EOF
chmod 600 /root/satom-answers.env
sudo bash satom-setup.sh --yes --answers /root/satom-answers.env
```

The database and its owner must already exist. The installer's own error
message lists what the database server must allow: `listen_addresses`, and a
`pg_hba.conf` entry that admits **both** the stack network
(`SATOM_NETWORK_SUBNET`, default `172.28.0.0/16`) and the `docker0` bridge
network.

What changes in this mode (from `compose.setup.yaml`):

* `web`, `scheduler` and `cron` receive
  `SQLALCHEMY_DATABASE_URI=${SATOM_EXT_DB_URI}`. The installer builds that URI
  with each component URL-encoded. It overrides the URI that `compose.yaml`
  composes from `POSTGRES_*`. The three services also get
  `host.docker.internal:host-gateway`.
* The `postgres` service **runs no database**. It becomes a probe: entrypoint
  `sleep infinity`, with a healthcheck that runs `pg_isready` against the
  external server. This keeps the `depends_on: service_healthy` ordering.
* `SATOM_PG_BIND` is set to `127.0.0.1:55432`. Because `compose.prod.yaml`
  still applies, that port is published, but nothing listens behind it.
* The role is `standalone`. The installer says high availability is your
  PostgreSQL's job in this mode.

**You back up the external database yourself.** The probe container is not a
database.

---

## 3. Quick start B — manual, without the installer

The manual route runs the stack from a source checkout with
`deploy/docker/satom-docker.sh` (or plain `docker compose`). It covers the
development, single-node production and primary/standby shapes. It does **not**
cover external PostgreSQL.

### 3.1 Get the source

```bash
mkdir -p /opt/satom-src && cd /opt/satom-src
curl -fsSL https://codeload.github.com/visionebc/SATOM/tar.gz/refs/tags/v2.1.2 \
  | tar -xz --strip-components=1
cd /opt/satom-src/deploy/docker
```

This is the same archive `satom-setup.sh` downloads. Keep the checkout
root-owned (§6.6): the compose files and two scripts bind-mounted into
`postgres` (§5.1) come from this tree.

### 3.2 Development node

```bash
cd /opt/satom-src/deploy/docker
./satom-docker.sh gen-secrets            # creates .env from env.example if missing, fills the four secrets, chmod 0600
./satom-docker.sh build satom:local      # context = repository root
./satom-docker.sh up
./satom-docker.sh ps
```

`gen-secrets` replaces only lines that still hold a `CHANGE_ME` placeholder
(`SECRET_KEY`, `FERNET_KEY`, `POSTGRES_PASSWORD`, `SATOM_REPL_PASSWORD`). It
refuses to run when no placeholder is left, so it can never overwrite a real
`FERNET_KEY`.

**First login.** Either put `SATOM_ADMIN_PASSWORD` in `.env` before the first
`up`, or read the generated password:

```bash
./satom-docker.sh exec web cat /opt/satom/instance/initial-admin-password
```

Change it after logging in, then delete the file:
`./satom-docker.sh exec web rm /opt/satom/instance/initial-admin-password`.

### 3.3 Production, single node

```bash
cd /opt/satom-src/deploy/docker
./satom-docker.sh gen-secrets
./satom-docker.sh build satom:2.1.2
```

Edit `.env`:

```ini
SATOM_ENV=prod                      # satom-docker.sh reads it from .env; see §3.4
SATOM_NODE_ROLE=primary
SATOM_IMAGE=satom:2.1.2             # compose.prod.yaml requires it to be set; it does NOT reject :local
SATOM_SERVED_NAMES="satom.example.com"   # quote it if it has spaces (§12)
SATOM_PG_BIND=127.0.0.1:5432        # required by compose.prod.yaml even on a single node
TZ=UTC
```

```bash
./satom-docker.sh config > /dev/null && echo config-ok   # the rendered config contains your secrets: do not paste it anywhere
./satom-docker.sh up
```

**Build or import the image before `up`.** If `SATOM_IMAGE` names an image the
engine does not have, Compose tries to pull it from a registry. For
`satom:<tag>` that registry is Docker Hub, which is the substitution
`satom-setup.sh` deliberately avoids. Check first:

```bash
docker image inspect satom:2.1.2 --format '{{.Id}}'
```

### 3.4 `deploy/docker/satom-docker.sh` — subcommand reference

The script reads `deploy/docker/.env` (it sources the file with `set -a`, so
the file must be valid shell). It picks the compose files like this:
`compose.yaml`; plus `compose.prod.yaml` when `SATOM_ENV=prod`; plus
`compose.standby.yaml` when additionally `SATOM_NODE_ROLE=standby`.
`SATOM_ENV` can live in `.env` or in the calling environment.

| Subcommand | Runs | Notes |
|---|---|---|
| `gen-secrets` | fills the four placeholders, `chmod 0600 .env` | see §3.2 |
| `build [TAG]` | `docker build -t TAG -f Dockerfile <repo root>` | default tag `satom:local` |
| `config` | `docker compose … config` | prints the merged configuration, **secrets included** |
| `up [args]` | `docker compose … up -d [args]` | |
| `down [args]` | `docker compose … down [args]` | `down -v` deletes the volumes |
| `ps` | `docker compose … ps` | |
| `logs [svc…]` | `docker compose … logs --tail=200 -f [svc…]` | always follows |
| `exec <svc> [cmd…]` | `docker compose … exec <svc> [cmd…]` (default `sh`) | allocates a TTY |
| `export <TAG> <out.tar.gz>` | `docker save \| gzip -9`, then writes `<out>.sha256` | §11.8 |
| `import <in.tar.gz>` | verifies `<in>.sha256` if present, then `docker load` | §11.8 |
| `health` | `ps`, node role, `/healthz`, runtime capabilities | **aborts at the `/healthz` step in 2.1.2** (§14) |

Before every compose command the script checks two things:

* It **refuses** if `SATOM_HTTP_BIND` is set (retired).
* It **refuses** if `TRUSTED_PROXIES` does not contain `SATOM_PROXY_IP`.

When `SATOM_ENV=prod` and `SATOM_NODE_ROLE=standby` it also refuses an empty
`SATOM_PRIMARY_HOST`. It does **not** check that `SATOM_PROXY_IP` lies inside
`SATOM_NETWORK_SUBNET`, although `env.example` says it does; Docker rejects the
mismatch at `up`. There is **no `restart` subcommand**.

For everything the script does not wrap, this manual uses a shell function
that applies the same file order. Define it in the shell you operate from:

```bash
cd /opt/satom-src/deploy/docker
# production primary / single node
dc() { docker compose -f compose.yaml -f compose.prod.yaml --env-file .env "$@"; }
# production standby: add the standby overlay LAST
# dc() { docker compose -f compose.yaml -f compose.prod.yaml -f compose.standby.yaml --env-file .env "$@"; }
dc ps
```

`dc` skips the two checks above. Order matters: Compose merges left to right,
and with the files reversed the development defaults win.

### 3.5 Do not mix the two entry points on an installer-managed node

`satom-setup.sh` links `/opt/satom-docker/current/deploy/docker/.env` to
`satom.env`, so `satom-docker.sh` appears to work there. It does not pass the
installer's `compose.setup.yaml` or `-p satom --project-directory`. On an
external-database node it would therefore start a real bundled PostgreSQL and
point the application at it. **On an installer-managed node, use only
`/usr/local/sbin/satom-docker`.** That wrapper passes all of its arguments to
`docker compose` (for example `satom-docker ps`, `satom-docker logs -f web`,
`satom-docker restart proxy`). It does **not** run `satom-docker.sh`'s
`TRUSTED_PROXIES` and `SATOM_HTTP_BIND` checks.

---

## 4. Host layout and volumes

### 4.1 Installer-managed node

| Path | Mode | Contents |
|---|---|---|
| `/opt/satom-docker/` | 0700 root | everything below |
| `/opt/satom-docker/satom.env` | 0600 root | **all secrets** and settings (§8). Back it up. |
| `/opt/satom-docker/compose.setup.yaml` | 0600 root | the installer's overlay (§5.10). Written at install; **not rewritten by an update**. |
| `/opt/satom-docker/releases/<ver>/` | root | the downloaded release source for each installed version |
| `/opt/satom-docker/current` | symlink | points to `releases/<ver>` |
| `/opt/satom-docker/current/deploy/docker/.env` | symlink | points to `satom.env` |
| `/opt/satom-docker/.installed` | — | marks a completed install |
| `/usr/local/sbin/satom-docker` | 0755 root | the wrapper |
| `/root/satom-docker-join.env` | 0600 root | **primary only**: the join file (§10.2). Delete it once the standby has joined. |
| `/root/satom-admin-password.txt` | 0600 root | only when the installer generated the `admin` password |
| `/root/satom-setup-summary.txt` | 0600 root | install summary |
| `/var/log/satom-setup.log` | 0600 root | installer log; answers to password questions are masked |

### 4.2 Manual node

| Path | Contents |
|---|---|
| `<checkout>/deploy/docker/.env` | secrets and settings; `gen-secrets` sets it to 0600, owned by whoever ran it |
| `<checkout>/deploy/docker/initdb.d/10-replication.sh` | bind-mounted read-only into `postgres` in production |
| `<checkout>/deploy/docker/pg-standby-entrypoint.sh` | bind-mounted read-only into `postgres` on a standby |

### 4.3 Named volumes

The Compose project name is `satom`, so on the host each volume is called
`satom_<name>` (for example `satom_satom-data`). The volumes live in the
engine's data root (`/var/lib/docker/volumes` by default).

| Volume | Mounted at (service, mode) | Contents | Irreplaceable? | Backup |
|---|---|---|---|---|
| `satom-data` | `/opt/satom/data` (web, scheduler, cron — rw) | the device vault, system-backup bundles, the SoT object store and `reports/` (per `compose.yaml`); `publication-rules.local.json` | **Yes.** `compose.yaml` calls it "the only thing in the tree that is irreplaceable". | **Required**, together with the database: the SoT index is in PostgreSQL and its blobs are here |
| `satom-pgdata` | `/var/lib/postgresql/data` (postgres — rw) | the PostgreSQL cluster | **Yes** | `pg_dump` (§11.2); copy the raw volume only with the stack stopped. Unused in external-DB mode. |
| `satom-instance` | `/opt/satom/instance` (web, scheduler, cron — rw) | the application's `instance/` directory; `initial-admin-password` when the password was generated (`SATOM_ADMIN_PASSWORD_FILE`) | small, but holds the generated first password | Recommended |
| `satom-state` | `/opt/satom/state` (web, scheduler, cron — rw) | node-local state (the host model describes `state/` as the cert-renew journal, [`privilege-model.md`](privilege-model.md) §2) | no | Optional |
| `satom-metrics` | `/victoria-metrics-data` (victoria-metrics — rw) | time series, kept for 396 days | the history is lost if it is deleted; nothing else depends on it | Optional |
| `satom-pki` | `/opt/satom/pki` (tls-init — rw; proxy — **ro**) | the internal CA (`internal-ca/`), the node leaf certificate, and `public/server.{crt,key}` plus `meta.json` | an **imported** certificate and key must be re-imported if this volume is lost; a self-issued one is reissued | Recommended when you imported a certificate |
| `satom-proxy-conf` | `/out` (tls-init — rw); `/etc/nginx/conf.d` (proxy — **ro**) | the generated `satom.conf` vhost | no; rewritten on every `up` | No |
| `satom-acme` | `/var/www/satom-acme` (tls-init — rw; proxy — **ro**) | the ACME http-01 webroot | no | No |

Redis has **no volume** (`--save "" --appendonly no`). Its contents are
rate-limit counters, and `compose.yaml` calls them derivable state.

Paths that are **not** on a volume live in the container's writable layer and
disappear when the container is recreated: `/opt/satom/reports` and
`/var/log/satom` (created by the `Dockerfile`), `/home/satom`, `/tmp`.

---

## 5. Service reference

`${VAR:-x}` means "`VAR`, or `x` if it is unset or empty". `${VAR:?}` means
"required: Compose refuses to render the file without it". "base" refers to
`compose.yaml`, "prod" to `compose.prod.yaml`, "standby" to
`compose.standby.yaml` and "setup" to the installer's `compose.setup.yaml`.

### 5.0 Summary

| Service | Image | Runs as | Restart (base → prod) | Published ports | Healthcheck |
|---|---|---|---|---|---|
| `postgres` | `postgres:15-bookworm` | stock image: the entrypoint starts as root and runs the server as the image's `postgres` user | `unless-stopped` → `always` | none → `${SATOM_PG_BIND}:5432` → none on standby | `pg_isready -U -d` |
| `redis` | `redis:7-alpine` | stock image defaults (see §6.1) | `unless-stopped` → `always` | none | none defined by the stack |
| `victoria-metrics` | `victoriametrics/victoria-metrics:v1.148.0` | stock image defaults (see §6.1) | `unless-stopped` → `always` | none | none defined by the stack |
| `tls-init` | `${SATOM_IMAGE:-satom:local}` | **root** (`user: "0:0"`) | `"no"` (not changed by prod) | none | image default; the container exits before it matters |
| `proxy` | `nginx:1.27-alpine` | nginx master as root, workers as `nginx` (stock `nginx.conf`) | `unless-stopped` (not changed by prod) | `${SATOM_HTTPS_BIND:-0.0.0.0:443}:443`, `${SATOM_REDIRECT_BIND:-0.0.0.0:80}:80` | `nginx -t` |
| `web` | `${SATOM_IMAGE}` | **uid 999 : gid 999** (`satom`) | `unless-stopped` → `always` | none (`expose: 8000` only) | image `HEALTHCHECK` (`curl /healthz`) |
| `scheduler` | `${SATOM_IMAGE}` | uid 999 : gid 999 | `unless-stopped` → `always` | none | **disabled** |
| `cron` | `${SATOM_IMAGE}` | uid 999 : gid 999 | `unless-stopped` → `always` | none | **disabled** |

No overlay shipped in 2.1.2 adds a service. `compose.agent.yaml`, which the
installer's wrapper would include, does not exist (§7.4).

All services join the single bridge network `satom` (on the host:
`satom_satom`), subnet `${SATOM_NETWORK_SUBNET:-172.28.0.0/16}`. Only `proxy`
has a fixed address (`${SATOM_PROXY_IP:-203.0.113.10}`); every other service
gets a dynamic one and is reached by its service name.

Production adds `logging: json-file, max-size 20m, max-file 5` to `postgres`,
`redis`, `victoria-metrics`, `web`, `scheduler` and `cron`. `proxy` and
`tls-init` keep the engine's default logging.

### 5.1 `postgres`

| Aspect | Value |
|---|---|
| Purpose | the application database; the replication source on a primary; a streaming replica on a standby |
| Environment | `POSTGRES_USER` (`satom`), `POSTGRES_PASSWORD` (**required**), `POSTGRES_DB` (`satom`), `TZ`. Prod adds `SATOM_REPL_USER` (`satom_repl`) and `SATOM_REPL_PASSWORD` (**required**). Standby adds `SATOM_PRIMARY_HOST` (**required**) and `SATOM_PRIMARY_PORT` (`5432`). The service has **no `env_file`**, so nothing else from `.env` reaches it. |
| Volumes | `satom-pgdata:/var/lib/postgresql/data` (rw). Prod: `./initdb.d:/docker-entrypoint-initdb.d:ro`. Standby: `./pg-standby-entrypoint.sh:/usr/local/bin/pg-standby-entrypoint.sh:ro`. |
| Command (prod) | `postgres -c wal_level=replica -c max_wal_senders=10 -c wal_keep_size=1024MB -c hot_standby=on`. The standby inherits the same command. |
| Entrypoint (standby) | `pg-standby-entrypoint.sh`, which wraps the stock entrypoint (§10.4) |
| Ports | base: none. prod: `${SATOM_PG_BIND:?}:5432`, which has no default and should always be an explicit address. standby: `!reset []`, i.e. none. |
| Healthcheck | `pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB} -q`; interval 5 s, timeout 5 s, 24 retries, start period 30 s |
| Limits (prod) | memory 2 GB |
| First-initdb hook (prod) | `initdb.d/10-replication.sh` creates the replication role and appends `host replication <role> 0.0.0.0/0 scram-sha-256` (and `::/0`) to `pg_hba.conf`. It runs **only when PGDATA is empty at first start**. |

### 5.2 `redis`

`command: redis-server --save "" --appendonly no`. There is no volume, no
published port and **no authentication**. The app reaches it at
`redis://redis:6379/0` (`RATELIMIT_STORAGE_URI`). It is a real service rather
than an optional one because Flask-Limiter falls back to per-worker in-memory
counters when Redis is unreachable, which silently multiplies the documented
limit by the worker count (`compose.yaml`).

### 5.3 `victoria-metrics`

Arguments: `--storageDataPath=/victoria-metrics-data --retentionPeriod=396d
--httpListenAddr=:8428`. Volume: `satom-metrics` (rw). **No published port, by
design: VictoriaMetrics has no authentication.** `tests/test_container_runtime.py`
asserts that the port stays unpublished and that the tag stays equal to
`VM_VERSION` in `deploy/metrics-store.env` (1.148.0). Limit (prod): memory
2 GB. The app reaches it at `http://victoria-metrics:8428`.

### 5.4 `tls-init`

A run-to-completion init container. It uses the SATOM image with
`entrypoint: /opt/satom/deploy/docker/proxy-init.sh` and runs as **root**
(`user: "0:0"`), with `restart: "no"`.

| Aspect | Value |
|---|---|
| Environment | `SATOM_SERVED_NAMES` (default empty), `SATOM_PROXY_UPSTREAM=web:8000`, `TZ`. No `env_file`, so no secrets. |
| Volumes (all rw) | `satom-pki:/opt/satom/pki`, `satom-proxy-conf:/out`, `satom-acme:/var/www/satom-acme` |
| What it does | `tls-bootstrap.sh ensure-pki` → `tls-bootstrap.sh write-vhost --port 443 --upstream web:8000 --default-server` → deletes the stock `default.conf` from the conf volume → `chmod 600` on `public/server.key` → prints `meta.json` |
| Why root | the volumes are created empty and root-owned on first `up`, and the app account (uid 999) could not create `pki/` there (`compose.yaml`, `proxy-init.sh`) |

It runs on every `up`. An existing valid certificate is reused, and an
imported one is never touched (§9).

### 5.5 `proxy`

The TLS terminator, using stock `nginx:1.27-alpine` with nothing added.
**Not optional** (§9.1).

| Aspect | Value |
|---|---|
| depends_on | `tls-init: service_completed_successfully`, `web: service_started` |
| Volumes (all **ro**) | `satom-pki:/opt/satom/pki`, `satom-proxy-conf:/etc/nginx/conf.d`, `satom-acme:/var/www/satom-acme` |
| Network | `satom`, fixed `ipv4_address: ${SATOM_PROXY_IP:-203.0.113.10}` |
| Ports | `${SATOM_HTTPS_BIND:-0.0.0.0:443}:443`, `${SATOM_REDIRECT_BIND:-0.0.0.0:80}:80` |
| Healthcheck | `nginx -t`; interval 30 s, timeout 5 s, 3 retries. This validates the configuration only; it does not probe the upstream. |
| vhost (generated) | `:443 ssl http2` for `SATOM_SERVED_NAMES`, TLSv1.2/1.3, `client_max_body_size 400M`, `proxy_read_timeout 120s`, `Host $http_host`, `X-Forwarded-Proto https`, `X-Forwarded-For`, `X-Real-IP`. `:80` serves `/.well-known/acme-challenge/` from `/var/www/satom-acme` and returns 301 to HTTPS for everything else. Both listeners claim `default_server`. |

### 5.6 `web`

| Aspect | Value |
|---|---|
| Image | `${SATOM_IMAGE:-satom:local}`; prod: `${SATOM_IMAGE:?}` |
| Runs as | `USER satom`, uid/gid 999 (`Dockerfile`); no `user:` override |
| Process | `entrypoint.sh` role `web`: seeds `data/publication-rules.local.json` with `{}` if it is absent; refuses placeholder secrets (exit 78); waits for PostgreSQL (`SATOM_DB_WAIT_SECONDS`, default 120, exit 69 on timeout); then `gunicorn --workers ${SATOM_WEB_WORKERS:-4} --bind 0.0.0.0:8000 --timeout ${SATOM_WEB_TIMEOUT:-600} wsgi:app` with access and error logs on stdout |
| Environment | `env_file: .env` (**everything** in `.env`), then `SQLALCHEMY_DATABASE_URI` (composed from `POSTGRES_*`, host `postgres:5432`), `RATELIMIT_STORAGE_URI=redis://redis:6379/0`, `SATOM_METRICS_URL=http://victoria-metrics:8428`, `TZ`, `SATOM_ROLE=web`, `TRUSTED_PROXIES` (base default `203.0.113.10`; prod: **required**). Service-level `environment` wins over `env_file`. |
| Ports | none; `expose: 8000` on the internal network only |
| Volumes (rw) | `satom-data`, `satom-state`, `satom-instance` |
| depends_on | `postgres: service_healthy`, `redis: service_started` |
| Healthcheck | image `HEALTHCHECK curl -fsS http://127.0.0.1:8000/healthz`; interval 30 s, timeout 5 s, start period 90 s, 3 retries |
| Limits (prod) | memory 3 GB |

### 5.7 `scheduler`

The same image, environment, volumes and dependencies as `web`, with
`SATOM_ROLE=scheduler` and the healthcheck **disabled**, because the image
check curls `:8000` and this role does not listen. The process refuses
placeholder secrets and waits for the database. It then loops on
`node-role.sh` every 30 s and only runs `exec python -m app.scheduler_runtime`
when the database answers `pg_is_in_recovery() = false` (primary). No memory
limit.

### 5.8 `cron`

The same as `scheduler`, with `SATOM_ROLE=cron` and the healthcheck disabled.
It runs `cron-runner.sh`, a single loop:

* **Every tick** (`SATOM_CRON_TICK_SECONDS`, default 60) it runs
  `python -m app.cli_sentinel responder-tick`.
* **Every `SATOM_CRON_ALERTS_TICKS` ticks** (default 15) it runs
  `flask alerts-run`.

Both jobs run **only on the primary**. A failing job is logged and the loop
continues. If `alerts-run` fails, the loop also logs the filesystem usage it
can see.

### 5.9 The `shell` role

`entrypoint.sh` also accepts `SATOM_ROLE=shell` (waits for the database, then
`exec /bin/sh`). No service uses it. For maintenance,
`satom-docker exec web sh` gives the same shell in the running `web`
container.

### 5.10 The installer overlay `compose.setup.yaml`

For both database modes, it adds
`SATOM_ADMIN_PASSWORD: ${SATOM_SETUP_ADMIN_PW:-}` to `web`, `scheduler` and
`cron`. At install time this carries the chosen password; later it is empty,
and an existing admin is never modified (`_seed_admin()` in
`app/__init__.py`). Because `environment` overrides `env_file`, a
`SATOM_ADMIN_PASSWORD` line in `satom.env` has no effect on an
installer-managed node. External-database mode also changes `postgres` and the
three app services as described in §2.5.

---

## 6. Permissions and privilege model

This section states what each container **can** do given the 2.1.2 files. It
is the container counterpart of [`privilege-model.md`](privilege-model.md).

### 6.1 Identities

| Service | Process identity | Why / source |
|---|---|---|
| `web`, `scheduler`, `cron` | **uid 999, gid 999** (`satom`), non-root | `Dockerfile`: `useradd -u 999 -g 999`, `USER satom`. It matches the host install's service account, so a `data/` tree copied from a host keeps its ownership. |
| `tls-init` | **root (0:0)** | `compose.yaml` `user: "0:0"`. It must create `pki/` in root-owned empty volumes and keep the private key at 0600. |
| `proxy` | nginx **master as root**, workers as `nginx` | Stock image behaviour. `proxy-init.sh` relies on it ("the proxy runs its master as root and reads the key directly"). |
| `postgres` | entrypoint starts as root, then runs the server as the image's `postgres` user | Stock image behaviour, kept on purpose by `pg-standby-entrypoint.sh`, which `exec`s the stock `docker-entrypoint.sh` |
| `postgres` in **external-DB mode** | **root** | The installer overrides the entrypoint with `sleep`, which bypasses the stock entrypoint's user switch |
| `redis` | the upstream image's default | The stack sets no `user:`. As far as this manual can tell, the stock entrypoint switches to the image's `redis` user when the command is `redis-server`. |
| `victoria-metrics` | the upstream image's default | The stack sets no `user:` |

To confirm the stock images on your engine, rather than relying on this table:

```bash
for i in postgres:15-bookworm redis:7-alpine victoriametrics/victoria-metrics:v1.148.0 nginx:1.27-alpine; do
  printf '%-45s USER=%s\n' "$i" "$(docker image inspect "$i" --format '{{.Config.User}}')"
done          # an empty USER means the container starts as root
satom-docker top web        # or: dc top web — shows the running processes and their users
```

### 6.2 Linux capabilities and kernel confinement

**No compose file in 2.1.2 sets any of** `cap_add`, `cap_drop`, `privileged`,
`security_opt` (and therefore no `no-new-privileges`), `read_only`, `tmpfs`,
`devices`, `network_mode`, `pid` or `ipc`, and **nothing mounts
`/var/run/docker.sock`**. The only `user:` key is `tls-init`'s `0:0`.

Every container therefore runs with:

* **The Docker default capability set**: `CHOWN`, `DAC_OVERRIDE`, `FOWNER`,
  `FSETID`, `KILL`, `SETGID`, `SETUID`, `SETPCAP`, `NET_BIND_SERVICE`,
  `NET_RAW`, `SYS_CHROOT`, `MKNOD`, `AUDIT_WRITE`, `SETFCAP`. Processes running
  as root inside a container (`tls-init`, the nginx master, the entrypoints
  before they drop privileges, any image that stays root) hold these
  capabilities. Non-root processes, such as the uid-999 app processes, do not
  hold them as effective capabilities.
* **The engine's default seccomp profile, and AppArmor/SELinux confinement if
  the host enables it.** The stack does not override either.
* **No `no-new-privileges`.** Set-uid binaries inside an image keep working.

### 6.3 Network reachability

Inside the stack:

| From ↓ / To → | `postgres:5432` | `redis:6379` | `victoria-metrics:8428` | `web:8000` | Outbound (NAT) |
|---|---|---|---|---|---|
| `web`, `scheduler`, `cron` | yes (password) | yes (**no auth**) | yes (**no auth**) | yes | yes; required to manage appliances |
| `proxy` | reachable (needs the password) | **yes, no auth** | **yes, no auth** | yes (its upstream) | yes |
| `tls-init` | reachable (holds no password) | yes | yes | yes | yes |
| `postgres`, `redis`, `victoria-metrics` | yes | yes | yes | yes | yes |

From the host and the LAN:

| Entry point | Published on | Notes |
|---|---|---|
| `proxy` | `SATOM_HTTPS_BIND` (→ 443) and `SATOM_REDIRECT_BIND` (→ 80) | the only published surface of the base stack (asserted by `tests/test_container_runtime.py`) |
| `postgres` | `SATOM_PG_BIND` (→ 5432), **production primary only** | `pg_hba` admits the replication role from any source (`0.0.0.0/0` and `::/0`, scram-sha-256), plus the stock image's password rule for other roles |
| `redis`, `victoria-metrics`, `web`, `scheduler`, `cron`, `tls-init` | nothing | |

The network is one flat bridge. It is not declared `internal`, and nothing
separates the front end (proxy ↔ web) from the back end (database, Redis,
metrics). **Any container on the network can read and write Redis and query or
write VictoriaMetrics without credentials.** Every container can open outbound
connections.

### 6.4 Filesystem write access

| Service | Can write | Read-only mounts | Notes |
|---|---|---|---|
| `web`, `scheduler`, `cron` | `satom-data`, `satom-state`, `satom-instance` (volumes, uid 999); its own writable layer where uid 999 owns the path (`/opt/satom/reports`, `/var/log/satom`, `/home/satom`, `/tmp`) | — | **The application code under `/opt/satom` (`app/`, `deploy/`, …) is copied as root and is not writable by uid 999**, so the web process cannot rewrite its own code. It cannot read `satom-pki`: no app service mounts it. |
| `tls-init` | `satom-pki`, `satom-proxy-conf`, `satom-acme` | — | root |
| `proxy` | nothing persistent | `satom-pki`, `satom-proxy-conf`, `satom-acme` | reads the private key as root |
| `postgres` | `satom-pgdata` | `initdb.d/` (prod), `pg-standby-entrypoint.sh` (standby) | these two host files run inside `postgres`, and the stock entrypoint starts as root: whoever can write them on the host controls code that runs as root in that container |
| `redis` | its writable layer only | — | |
| `victoria-metrics` | `satom-metrics` | — | |

### 6.5 Secrets: where they are visible

* **`env_file: .env` delivers the *whole* file to `web`, `scheduler` and
  `cron`.** That includes `SECRET_KEY`, `FERNET_KEY` and `POSTGRES_PASSWORD`,
  which the app needs, and also `SATOM_REPL_PASSWORD` and (installer) the
  `SATOM_EXT_DB_*` values, which the app does not need. Code execution inside
  `web` therefore yields every secret in `.env`.
* `postgres` receives only `POSTGRES_*` and the replication credentials.
  `tls-init` and `proxy` receive no environment secrets. The proxy reads the
  TLS private key from `satom-pki`.
* **Container environments are visible to anyone who can run
  `docker inspect`**, and the engine stores them in each container's
  configuration under its data root. This includes the installer's first
  `admin` password (`SATOM_SETUP_ADMIN_PW` → `SATOM_ADMIN_PASSWORD`), which
  stays in the `web`, `scheduler` and `cron` container configurations until
  those containers are recreated. The comment in `compose.setup.yaml` says
  that password "is never written to disk". That is true of the installer's
  own files but **not** of the engine's container metadata. See §13 for how to
  flush it.
* `satom-docker.sh config` and `docker compose config` print the fully
  interpolated configuration, secrets included.

### 6.6 Who is effectively root on the host

| Principal | Why |
|---|---|
| root | obviously |
| **Every member of the `docker` group**, and anyone allowed to run `docker` through sudo | Access to the engine API is root on the host: such a user can start a privileged container that mounts `/`. This is Docker's own documented position and it is not specific to SATOM. |
| Anyone who can write `/opt/satom-docker` (installer) or the manual checkout | They can change the compose files, the `initdb.d` script or the standby entrypoint, all of which run as root in containers at the next `up`. The installer creates `/opt/satom-docker` as 0700 root. |
| Anyone who can read `satom.env` / `.env` | holds `FERNET_KEY` (decrypts every stored device credential), `SECRET_KEY` (forges sessions) and the database passwords. The installer writes it 0600 root. `gen-secrets` writes 0600 owned by the invoking user. |
| Anyone who can read `/root/satom-docker-join.env` | the same secrets, plus the primary's address. 0600 root; delete it after the standby joins. |

`/usr/local/sbin/satom-docker` is 0755, but it sources the root-only
`satom.env` and calls `docker`, so in practice only root can use it.

---

## 7. The operations agent

### 7.1 What 2.1.2 ships: none

**SATOM 2.1.2 ships no operations agent for Docker.** No compose file mounts
the Docker socket, no service performs privileged actions on request, and the
web application has no code path that asks one to. The installer's
`SETUP_AGENT` option exists for a future release (§7.4).

What 2.1.2 ships instead is an explicit **renunciation**. The image declares
`ENV SATOM_RUNTIME=container`. `app/runtime.py` then denies four capabilities
through `capability()` / `require()`. It selects the container runtime only for
the exact value `container` (case-insensitive, whitespace stripped); any other
value means `host`. Do **not** set `SATOM_RUNTIME` in `.env`: `env_file`
values override the image's `ENV`.

### 7.2 The four renounced capabilities

Each reason string below is quoted verbatim from `_REASONS` in
`app/runtime.py`. The UI, the API error and the CLI all render this same
string.

| Capability | Where it is enforced | Operator reason (verbatim) |
|---|---|---|
| `self_update` | `app/services/self_update.py` — `request_update()` and the library (pip) upgrade path both call `runtime.require("self_update")` | "In-place self-update is not available in the container runtime. Update by deploying a new image tag and recreating the stack." |
| `service_control` | `app/services/service_control.py` — `runtime.require("service_control")` | "Service control is not available in the container runtime. Use the container engine (docker compose restart \<service\>) instead." |
| `cert_activation` | `app/services/cert_service.py` `_install()` — `runtime.require("cert_activation")` before anything is written | "Certificate activation is not available in the container runtime. This stack already serves TLS from its own proxy container; replace the certificate with 'deploy/tls-bootstrap.sh import-cert' and restart the proxy service." |
| `unit_health` | `app/services/system_health.py` — `runtime.capability("unit_health")` | "systemd unit health is not available in the container runtime. Container health is reported by the container engine." |

To see the live state on a node:

```bash
satom-docker exec -T web python -c "import json,app.runtime as r; print(json.dumps(r.summary(), indent=2))"
```

`capabilities` should show all four as `false`, and `reasons` should show the
strings above.

**A gap the gate does not cover.** The HA panel's *promote* action
(`app/views/self_update.py` `/promote` → `app/services/cluster.py`
`request_promote()`) is guarded only by `promote_eligible()`, not by
`app/runtime.py`. It enqueues a request file for the host's root runner, which
does not exist in the container stack, so **nothing would ever execute it**.
Do not use it on a container node. Failover is a manual PostgreSQL operation
(§10.6).

### 7.3 Operator procedures that replace them

#### 7.3.1 Instead of `self_update`: new image tag, recreate

* **Installer-managed:** run a newer `satom-setup.sh`, or the current one with
  `--version X.Y.Z`, and answer `update` (§11.1).
* **Manual:** build or import the new tag, set `SATOM_IMAGE` in `.env`, then
  run `./satom-docker.sh up` (or `dc up -d`). Compose recreates the services
  whose image changed.

The Settings → Libraries (pip) path is denied for the same reason: libraries
are part of the image.

#### 7.3.2 Instead of `service_control`: the container engine

```bash
satom-docker restart web          # installer-managed
dc restart web                    # manual (§3.4); satom-docker.sh has no restart subcommand
```

`restart` does **not** apply changes to `.env` or to the compose files. To
apply those, run `satom-docker up -d` (manual: `./satom-docker.sh up`), which
recreates the affected containers.

#### 7.3.3 Instead of `cert_activation`: `import-cert` in a one-off `tls-init` container, then restart `proxy`

`tls-init` exits after it runs, so you cannot `exec` into it. Start a one-off
container from the same service definition, which carries the `satom-pki`
mount and runs as root, and bind-mount the files in. This is the exact command
`satom-setup.sh` uses for `SETUP_CERT=import`:

```bash
d=$(mktemp -d)
cp /path/to/fullchain.pem "$d/cert.pem"
cp /path/to/privkey.pem   "$d/key.pem"
# optional: cp /path/to/chain.pem "$d/chain.pem"   and add  --chain /import/chain.pem  below
chmod 644 "$d"/*.pem
satom-docker run --rm --no-deps -v "$d:/import:ro" \
  --entrypoint /opt/satom/deploy/tls-bootstrap.sh \
  tls-init import-cert --cert /import/cert.pem --key /import/key.pem --pki /opt/satom/pki
rm -rf "$d"
satom-docker restart proxy
```

On a manual node, replace `satom-docker` with `dc`. `import-cert` refuses a
file that is not a certificate and a certificate/key pair that does not match.
It then writes `public/server.crt` (with the chain appended when given) and
`public/server.key` (0600), and records `"source": "imported"` in
`public/meta.json`. From then on, `tls-init` leaves the certificate untouched
on every `up`.

#### 7.3.4 Instead of `unit_health`: container health

```bash
satom-docker ps                                              # State and Health columns
docker inspect --format '{{json .State.Health}}' satom-node  # details of the last probes
```

Only `postgres`, `proxy` and `web` have healthchecks. `scheduler` and `cron`
are deliberately unchecked. The stack defines none for `redis` and
`victoria-metrics`. For what each check proves, see §11.5.

### 7.4 `SETUP_AGENT` / `compose.agent.yaml`

`satom-setup.sh` offers the agent **only if** the release tree contains
`deploy/docker/compose.agent.yaml`. The installer's wrapper includes that file
only when `SATOM_SETUP_AGENT=yes` *and* the file exists. **No release up to and
including 2.1.2 contains it.** The installer therefore reports that the agent
is not included in this version, sets `SATOM_SETUP_AGENT=no`, and ignores
`SETUP_AGENT=yes` with a warning. Its message points to the `satom-docker`
wrapper for the four operations.

The installer's own description of the future agent is the only specification
in the tree:

* it mounts `/var/run/docker.sock`, so whoever controls it is root on the host;
* the web application only drops requests into a volume;
* the agent accepts a closed list of actions.

### 7.5 Permission boundary any future agent must respect

> **Design requirement, not existing behaviour.** Nothing in this subsection is
> implemented in 2.1.2. It restates the host model of
> [`privilege-model.md`](privilege-model.md) §4 for a container agent, so that
> an agent can be reviewed against it.

1. **The web worker only enqueues.** As on a host, the process that parses
   appliance input and HTTP requests must not hold the privilege it asks for.
   `web` writes a request, for example a JSON file in a volume. It must never
   mount the Docker socket, never talk to the engine API, and never be given
   credentials to the agent.
2. **The privileged side re-validates against a closed allowlist.** The web
   worker's validation is a UX affordance. The agent's is the security
   boundary. Each request maps to one of a fixed set of actions (the natural
   set is the four in §7.2: recreate on a new *allowlisted* image tag, restart
   a *named* service of this project, import a certificate into `satom-pki`
   and restart `proxy`, and report container health). The agent must never
   accept free-form image names, compose arguments, bind-mount paths, commands
   or service names outside the project. A compromised web worker can enqueue
   whatever it likes and must still only get the curated set.
3. **Treat the Docker socket as host root.** An agent that mounts
   `/var/run/docker.sock` is equivalent to root on the host (§6.6), in the same
   way that `satom-updater.service` is root on a host install. It must be the
   *only* container with that mount. It must not be reachable over the network,
   so it should publish no port and listen on nothing the `satom` network can
   reach. It should also have the smallest footprint possible.
4. **Results travel back the same way.** The agent writes a status file that
   the UI polls, like `data/update-status/<uid>.json` on a host. It does not
   call back into the web process.
5. **The runtime gate must change deliberately.** In 2.1.2, `app/runtime.py`
   denies the four capabilities based only on `SATOM_RUNTIME`. An agent does
   not re-enable them by existing. A release that ships one has to change the
   gate and the enforcement points in §7.2, and `tests/test_container_runtime.py`
   requires every declared capability to keep a call site.

---

## 8. Configuration reference

### 8.1 How a value reaches a container

1. **Interpolation.** `${VAR}` in the compose files is resolved from the
   `--env-file` (`satom-docker.sh`: `deploy/docker/.env`; the installer:
   `satom.env`) and from the calling shell.
2. **`env_file: .env`**: only `web`, `scheduler` and `cron` receive the whole
   file as container environment.
3. **`environment:`** in the service overrides `env_file`. It in turn
   overrides the image `ENV`.

So `SQLALCHEMY_DATABASE_URI`, `RATELIMIT_STORAGE_URI`, `SATOM_METRICS_URL`,
`TZ`, `SATOM_ROLE` and (in `web`) `TRUSTED_PROXIES` always come from the
compose files, whatever `.env` says. That is deliberate: a `.env` copied from a
host install carries `127.0.0.1`, which inside a container is the container
itself.

### 8.2 Secrets

| Variable | Generated by | Required | Effect / warning |
|---|---|---|---|
| `SECRET_KEY` | `gen-secrets` / installer: `openssl rand -hex 32` | `web`, `scheduler` and `cron` exit 78 if it is empty or contains `CHANGE_ME`, `changeme`, `REPLACE` or `example` | signs sessions; if leaked, sessions can be forged |
| `FERNET_KEY` | 32 random bytes, URL-safe base64 | same refusal | **encrypts stored device credentials. It cannot be rotated once any are stored. Losing or changing it makes every stored device credential permanently undecryptable. It does not lock you out of SATOM.** Must be identical on primary and standby. Never copy it between development and production. |
| `POSTGRES_PASSWORD` | `openssl rand -hex 24` | `${…:?}` in `compose.yaml`: always | interpolated **raw** into `SQLALCHEMY_DATABASE_URI`, so it must be URL-safe (the generated hex value is). The entrypoint's and `node-role.sh`'s URI parsing also breaks on `@` in a password. |
| `SATOM_REPL_PASSWORD` | `openssl rand -hex 24` | `${…:?}` in prod and standby | password of the replication role; must match on both nodes |
| `admin` password | you (`SATOM_ADMIN_PASSWORD`) or generated | — | used only when the users table is empty. There is no default password. |

`gen-secrets` and the installer both **only fill placeholders or missing
files**. Neither will regenerate an existing `FERNET_KEY`.

### 8.3 Variables in `env.example` and the compose files

| Variable | Default | Required in | Effect |
|---|---|---|---|
| `POSTGRES_USER` | `satom` | — | database superuser created by the stock image at first init; also used in the URI |
| `POSTGRES_DB` | `satom` | — | database name |
| `FLASK_ENV` | `production` (image and `env.example`) | — | production sets `SESSION_COOKIE_SECURE=True` (per `compose.yaml`), which is why TLS is mandatory |
| `FLASK_APP` | `wsgi.py` | — | |
| `TZ` | `Europe/Zurich` (compose and `env.example`); installer: the host's zone, else `UTC` | — | passed to every service except `redis`, `victoria-metrics` and `proxy` |
| `SATOM_HTTPS_BIND` | `0.0.0.0:443` | — | host address:port published to proxy `:443` |
| `SATOM_REDIRECT_BIND` | `0.0.0.0:80` | — | host address:port published to proxy `:80` (ACME http-01 and 301 only; never point a reverse proxy at it) |
| `SATOM_SERVED_NAMES` | empty → the `tls-init` container's hostname (its container ID), "almost never right" | — | certificate SAN and `server_name`. Space-separated; **quote it in `.env`** |
| `SATOM_IMAGE` | `satom:local` (base default and `env.example`) | prod: must be non-empty for `web`, `scheduler` and `cron` | image for `tls-init`, `web`, `scheduler` and `cron`. Prod requires the variable to be set but **does not inspect its value**; set an immutable tag yourself. |
| `SATOM_NETWORK_SUBNET` | `172.28.0.0/16` | — | the stack network's subnet. Change it only on a collision, together with the next two. |
| `SATOM_PROXY_IP` | `203.0.113.10` | — | the proxy's fixed address; must lie inside the subnet |
| `TRUSTED_PROXIES` | `203.0.113.10` (base default and `env.example`) | prod: non-empty | comma-separated hops allowed to set `X-Forwarded-*`. It matches exact addresses and must contain `SATOM_PROXY_IP` first. Add any outer proxy after it (§9.6). Leaving it empty means "trust nothing". |
| `SATOM_NODE_ROLE` | `primary` | — | `standby` makes the wrapper(s) add `compose.standby.yaml` |
| `SATOM_PG_BIND` | `env.example`: `127.0.0.1:5432`; no compose default | prod: **always**, including the standby (which publishes nothing) | host address:port for the primary's PostgreSQL. Use an explicit address, never `0.0.0.0`. |
| `SATOM_REPL_USER` | `satom_repl` | — | replication role name |
| `SATOM_PRIMARY_HOST` | empty | standby | the primary's address, reachable from the standby |
| `SATOM_PRIMARY_PORT` | `5432` | — | |
| `SATOM_ENV` | not in `env.example`; means `dev` when unset | — | read by `satom-docker.sh` and the installer's wrapper only; `prod` adds `compose.prod.yaml` |
| `SATOM_HTTP_BIND` | — | **must be unset or empty** | retired; `satom-docker.sh` refuses to run while it is set |
| `SATOM_ADMIN_PASSWORD` | unset | — | first `admin` password (manual route; ignored on installer-managed nodes, §5.10) |

`env.example` lists `SATOM_IMAGE` twice with the same value; the last
occurrence wins.

### 8.4 Tunables read inside the containers

| Variable | Default | Read by | Reaches the container? |
|---|---|---|---|
| `SATOM_WEB_WORKERS` | `4` | `entrypoint.sh` (web) | yes, via `.env` |
| `SATOM_WEB_TIMEOUT` | `600` | `entrypoint.sh` (web) | yes. Note that the vhost's `proxy_read_timeout` is 120 s. |
| `SATOM_DB_WAIT_SECONDS` | `120` | `entrypoint.sh` | yes |
| `SATOM_CRON_TICK_SECONDS` | `60` | `cron-runner.sh` | yes |
| `SATOM_CRON_ALERTS_TICKS` | `15` | `cron-runner.sh` | yes |
| `SATOM_APP_DIR` | `/opt/satom` | `entrypoint.sh` | yes (leave it) |
| `SATOM_BASEBACKUP_WAIT_SECONDS` | `300` | `pg-standby-entrypoint.sh` | **no**: `postgres` has no `env_file` and the standby overlay does not pass it, so the default always applies |
| `SATOM_REPL_SLOT` | `satom_standby` | `pg-standby-entrypoint.sh` | **no**, for the same reason |
| `SATOM_PKI`, `SATOM_PROXY_CONF_OUT`, `SATOM_ACME_WEBROOT` | `/opt/satom/pki`, `/out/satom.conf`, `/var/www/satom-acme` | `proxy-init.sh` | **no** (`tls-init` receives only the three variables in §5.4) |

### 8.5 Set by the image (`Dockerfile`)

`SATOM_RUNTIME=container`, `FLASK_APP=wsgi.py`, `FLASK_ENV=production`,
`SATOM_ROLE=web`, `SATOM_ADMIN_PASSWORD_FILE=/opt/satom/instance/initial-admin-password`,
`PYTHONUNBUFFERED=1`, `PYTHONDONTWRITEBYTECODE=1`, and `PATH` with
`/opt/venv/bin` first.

### 8.6 Written only by the installer

`SATOM_ENV=prod` (every installer-managed node uses the production overlay),
`SATOM_SETUP_AGENT`, `SATOM_EXT_DB_HOST`, `SATOM_EXT_DB_PORT`,
`SATOM_EXT_DB_NAME`, `SATOM_EXT_DB_USER`, `SATOM_EXT_DB_URI`. The installer
writes values containing spaces or URI characters in single quotes.
`SATOM_SETUP_ADMIN_PW` exists only in the environment of the installer's `up`
command.

---

## 9. TLS

### 9.1 Why the proxy is mandatory

The image runs `FLASK_ENV=production`, which sets `SESSION_COOKIE_SECURE=True`.
Over plain HTTP the browser never returns the session cookie. The login POST
then arrives without a CSRF token and is rejected before the password is
compared. **Such a node answers `/healthz` with 200 and refuses every
credential** (`compose.yaml`). Never publish `web:8000` directly, and do not
work around this by setting `SESSION_COOKIE_SECURE=False` (see
[`docker.md`](docker.md)).

### 9.2 The default certificate

On every `up`, `tls-init` runs `tls-bootstrap.sh ensure-pki`:

* It creates an **internal CA** once: RSA 4096, 10 years, key 0600 in
  `internal-ca/` (directory 0700).
* It issues a **node certificate**: RSA 2048, valid 825 days, SAN = every name
  in `SATOM_SERVED_NAMES`, EKU serverAuth and clientAuth. It publishes the
  certificate as `public/server.crt` and `public/server.key` (0600), with
  `meta.json` `"source": "issued"`.
* It **reuses** an existing issued certificate when it is still valid for more
  than 30 days *and* its SAN covers every requested name. Otherwise it
  reissues.
* It **never touches** a certificate whose `meta.json` says
  `"source": "imported"`.

The Docker path passes no `--ip`, so the node's IP address is **not** in the
SAN. Browsers warn until you replace the certificate, and this is the
intended day-zero state.

### 9.3 Names

Set `SATOM_SERVED_NAMES` to the names operators type, **quoted** if there is
more than one:

```ini
SATOM_SERVED_NAMES="satom.example.com satom-a.example.com"
```

After a change, run `up -d` (manual: `./satom-docker.sh up`) so that `tls-init`
reissues, then `restart proxy` (§9.4).

### 9.4 Renewal and expiry

The stack has **no renewal job**; `satom-cert-renew` is not reproduced. The
self-issued leaf is only re-evaluated when `tls-init` runs, which happens on
`up`. A leaf reissued during `up` is written to the volume, but the running
nginx keeps what it loaded at start. **Restart `proxy` after any certificate
change.** An imported certificate is never renewed by the stack: replace it
with §7.3.3 before it expires.

### 9.5 ACME http-01

`:80` serves `/.well-known/acme-challenge/` from the `satom-acme` volume, and
answers everything else with a 301. That listener exists because http-01 is
always validated over plain `:80`.

**2.1.2 provides no ACME client for the stack's own certificate.** In detail:

* the image does not install one (no ACME client in the `Dockerfile`);
* only `tls-init` can write the `satom-acme` volume, and no app service
  mounts it;
* the Certificate Manager's activation step for the node certificate is
  `cert_activation`, which is denied.

To use ACME you need an external client that can write challenge files into
the `satom_satom-acme` volume (or that uses DNS-01 elsewhere). Import the
certificate it obtains with §7.3.3. Neither SATOM nor its tests cover such a
client.

### 9.6 A further proxy in front

An edge or DMZ load balancer in front of the stack should connect to `:443`.
It must pass `Host` **including the port** and declare the scheme, as
described in [`docker.md`](docker.md) "Putting a further proxy in front".
Then append the outer hop to `TRUSTED_PROXIES`, **after** the stack's own
proxy:

```ini
TRUSTED_PROXIES=203.0.113.10,198.51.100.4
```

The three settings are coupled:

* `SATOM_PROXY_IP` must lie inside `SATOM_NETWORK_SUBNET`, otherwise Docker
  refuses `up`.
* `TRUSTED_PROXIES` must contain `SATOM_PROXY_IP`, otherwise `satom-docker.sh`
  refuses to run.

If you change one of the three, change all three. A wrong `TRUSTED_PROXIES`
does not fail loudly. Every user shares one rate-limit bucket, and five failed
logins then lock out everyone (per `env.example`). Every audit entry also
records the proxy as the actor.

### 9.7 A non-default HTTPS port

`SATOM_HTTPS_BIND` (installer: `SETUP_PORT`) changes the port that is
published on the host. `tls-init`, however, always writes the vhost with
`--port 443`, and the `:80` redirect keeps the request's host name and **omits
the port when it is 443**. With `SATOM_HTTPS_BIND=0.0.0.0:8443`, a request to
`http://satom.example.com/` is therefore redirected to
`https://satom.example.com/` (port 443), not to `:8443`. Direct `https://…:8443/`
access works. If you need the redirect to be correct, keep 443 or put a proxy
in front.

---

## 10. High availability: primary + standby

### 10.1 Topology

Two nodes, each running the full stack:

* The **primary**'s PostgreSQL publishes `5432` on `SATOM_PG_BIND`.
* The **standby**'s PostgreSQL is built from a base backup of the primary and
  follows it by streaming replication.
* An external load balancer sends traffic to the standby only when the
  primary's `/healthz` stops answering. SATOM does not ship that load balancer
  configuration.

On each node, `SECRET_KEY`, `FERNET_KEY`, `POSTGRES_USER`, `POSTGRES_DB`,
`POSTGRES_PASSWORD`, `SATOM_REPL_USER` and `SATOM_REPL_PASSWORD` must be
identical. A standby with a different `FERNET_KEY` replicates ciphertext it
cannot read.

### 10.2 With the installer

On the primary:

```bash
cat > /root/satom-answers.env <<'EOF'
SETUP_MODE=docker
SETUP_ROLE=primary
SETUP_DB=bundled
SETUP_NAMES="satom-a.example.com satom.example.com"
SETUP_IP=192.0.2.10
EOF
sudo bash satom-setup.sh --yes --answers /root/satom-answers.env
```

This writes `/root/satom-docker-join.env` (0600). It contains `SECRET_KEY`,
`FERNET_KEY`, `POSTGRES_USER`, `POSTGRES_DB`, `POSTGRES_PASSWORD`,
`SATOM_REPL_USER`, `SATOM_REPL_PASSWORD`, `SATOM_PRIMARY_HOST=<SETUP_IP>` and
`SATOM_PRIMARY_PORT=5432`. Copy it to the standby over a secure channel,
for example `scp` as root, then delete it on both sides once the standby has
joined.

On the standby (Compose ≥ 2.24.4):

```bash
cat > /root/satom-answers.env <<'EOF'
SETUP_MODE=docker
SETUP_ROLE=standby
SETUP_DB=bundled
SETUP_JOIN_FILE=/root/satom-docker-join.env
SETUP_NAMES="satom-b.example.com satom.example.com"
SETUP_IP=192.0.2.11
EOF
sudo bash satom-setup.sh --yes --answers /root/satom-answers.env
```

The standby is not asked for an `admin` password, because users replicate from
the primary. Its `SATOM_PG_BIND` is set to `127.0.0.1:5432`, which the standby
overlay does not publish anyway.

### 10.3 Manually

The primary must run the **production overlay from its very first start**:
`initdb.d/10-replication.sh` only runs on an empty PGDATA (§12, "standby
cannot attach"). Primary `.env`:

```ini
SATOM_ENV=prod
SATOM_NODE_ROLE=primary
SATOM_IMAGE=satom:2.1.2
SATOM_PG_BIND=192.0.2.10:5432         # the address the standby reaches, never 0.0.0.0
```

Standby `.env`: a copy of the primary's, then:

```ini
SATOM_NODE_ROLE=standby
SATOM_PRIMARY_HOST=192.0.2.10
SATOM_PRIMARY_PORT=5432
SATOM_PG_BIND=127.0.0.1:5432          # must be non-empty; the standby publishes nothing
```

Run `./satom-docker.sh up` on each node, starting with the primary. The
standby needs the same image.

### 10.4 What happens on the standby

`pg-standby-entrypoint.sh` handles three cases:

| PGDATA | Action |
|---|---|
| already a standby (`standby.signal` present) | starts and follows the primary |
| **already a primary** (initialised, no `standby.signal`) | **refuses to start** and logs that the node was probably promoted |
| empty | waits up to 300 s for the primary (`pg_isready`), clears PGDATA, runs `pg_basebackup --wal-method=stream --create-slot --slot=satom_standby --write-recovery-conf --checkpoint=fast`, sets PGDATA to 0700, then starts |

It then `exec`s the stock `docker-entrypoint.sh` with the primary's `command:`.

The other services on the standby:

| Service | Behaviour |
|---|---|
| `web` | serves normally; reads work, and writes fail with PostgreSQL's read-only error |
| `scheduler` | probes `pg_is_in_recovery()` every 30 s and idles while it is true |
| `cron` | probes every tick and idles; it logs "standby or db not ready … idle" every 15 ticks |
| `proxy`, `tls-init` | as on the primary; the standby serves HTTPS with its own certificate |
| `redis`, `victoria-metrics` | local to the node and not replicated |

### 10.5 Verifying replication

The commands in this section and in §11 use the default `satom` role and
database; substitute your `POSTGRES_USER` / `POSTGRES_DB`. On a manual node,
use `dc` (§3.4) in place of `satom-docker`.

```bash
# on the primary
satom-docker exec -T postgres psql -U satom -c "SELECT client_addr, state, sync_state FROM pg_stat_replication;"
satom-docker exec -T postgres psql -U satom -c "SELECT slot_name, active FROM pg_replication_slots;"
# on the standby
satom-docker exec -T postgres psql -U satom -c "SELECT pg_is_in_recovery();"      # t
satom-docker exec -T web /opt/satom/deploy/docker/node-role.sh                      # t = standby, f = primary
```

The replication slot makes the primary keep every WAL segment the standby has
not consumed. The stack does not set `max_slot_wal_keep_size`, so a standby
that stays down lets WAL accumulate on the primary with no limit. If you retire
the standby, drop the slot on the primary:
`SELECT pg_drop_replication_slot('satom_standby');`.

### 10.6 Failover (promotion)

> SATOM ships **no container failover command**. The host's
> `deploy/satom-promote.sh` is run by the host's root runner, which does not
> exist here, and the UI's promote action is not executed in a container
> (§7.2). The procedure below is derived from the stack's code and standard
> PostgreSQL. It is not covered by tests.

1. Make sure the old primary is **really down**. Promotion is never automatic,
   because with two nodes and no quorum an automatic promotion invites split
   brain (`deploy/satom-promote.sh`).
2. On the standby, promote the database:

   ```bash
   satom-docker exec -T postgres psql -U satom -d satom -c "SELECT pg_promote();"
   ```

3. Within about 30 s (`scheduler`) and 60 s (`cron`), `node-role.sh` answers
   `f`, and both start working with no further action. Check with
   `satom-docker logs --tail=20 scheduler cron`.
4. **Before that PostgreSQL container restarts for any reason, turn the node
   into a primary in its configuration.** Otherwise the standby entrypoint
   finds a primary PGDATA and refuses to start. In `satom.env` (or `.env`), set
   `SATOM_NODE_ROLE=primary` and `SATOM_PG_BIND=<this node's address>:5432`,
   then run `satom-docker up -d` (manual: `./satom-docker.sh up`). This drops
   the standby overlay and publishes 5432.
5. Repoint the load balancer.

### 10.7 Rebuilding the old primary as the new standby

Do this only after deciding that the old primary's database can be discarded.
Any write it accepted that did not reach the new primary is lost.

```bash
satom-docker down                                   # on the OLD primary
# in satom.env: SATOM_NODE_ROLE=standby, SATOM_PRIMARY_HOST=<new primary address>
docker volume rm satom_satom-pgdata
satom-docker up -d                                  # base backup from the new primary, then follow it
```

The replication role and its `pg_hba` lines are already present on the new
primary, because they were copied by the original base backup.

### 10.8 The rule: never apply `compose.standby.yaml` to the primary

`compose.standby.yaml` swaps PostgreSQL's entrypoint for the rebuild-from-peer
wrapper. There are several guards, and none of them should be relied on as
permission:

1. `satom-docker.sh` and the installer's `satom-docker` add the standby overlay
   **only** when `SATOM_NODE_ROLE=standby`. `satom-docker.sh` also requires
   `SATOM_ENV=prod`. The installer's wrapper checks the role independently, but
   the installer always sets `SATOM_ENV=prod`.
2. `compose.standby.yaml` requires `SATOM_PRIMARY_HOST` (`${…:?}`), and
   `satom-docker.sh` refuses an empty value.
3. `pg-standby-entrypoint.sh` **refuses to start on an initialised PGDATA that
   has no `standby.signal`**, which is exactly a primary. It only clears PGDATA
   when `PG_VERSION` is absent or empty.

So on a primary with data, a mistaken standby overlay stops PostgreSQL and does
not wipe it. `compose.standby.yaml` and [`docker.md`](docker.md) describe the
outcome as a wipe; the entrypoint's refusal branch is what prevents that. The
danger that remains is procedural. The refusal message tells the operator how
to destroy the volume, and on a primary that is the database. **Do not follow
it on a primary.** Plain `docker compose -f … -f compose.standby.yaml` bypasses
guard 1 entirely.

### 10.9 What is not replicated

Only PostgreSQL. **The `satom-data` volume is not replicated**: the device
vault, system-backup bundles, SoT object blobs and reports stay on each node.
Neither are `satom-metrics`, `satom-pki`, `satom-instance` or `satom-state`.
After a failover, the promoted node holds only its own copy of those volumes.
The SoT index in PostgreSQL may reference blobs that exist only on the old
primary. Back up `satom-data` on the primary (§11.2) with that in mind.

---

## 11. Operations

### 11.1 Updating

| Install | How to update |
|---|---|
| **Native** (host) | in-product: Software Update (see [`INSTALL.md`](INSTALL.md)), or [offline update packages](offline-update-packages.md) |
| **Docker, installer-managed** | re-run `satom-setup.sh` |
| **Docker, manual** | new image tag + recreate |

Installer-managed:

```bash
curl -fsSLO https://github.com/visionebc/SATOM/releases/download/v<new>/satom-setup.sh
sudo bash satom-setup.sh --yes          # on an existing Docker install, the mode defaults to docker and the answer to update
```

The update path downloads and builds the new version, repoints
`/opt/satom-docker/current`, sets `SATOM_IMAGE=satom:<new>`, rewrites the
wrapper, runs `satom-docker up -d --remove-orphans`, and waits for `/healthz`.
It does **not**:

* take a backup first;
* rewrite `compose.setup.yaml`;
* offer a rollback.

Earlier `releases/<ver>` trees and `satom:<ver>` images are left in place. The
code makes no promise that an older image runs against a database a newer
version has already started on.

Manual:

```bash
cd /opt/satom-src && curl -fsSL https://codeload.github.com/visionebc/SATOM/tar.gz/refs/tags/v<new> | tar -xz --strip-components=1
cd deploy/docker && ./satom-docker.sh build satom:<new>
sed -i 's/^SATOM_IMAGE=.*/SATOM_IMAGE=satom:<new>/' .env      # both SATOM_IMAGE lines
./satom-docker.sh up
```

Extracting over the checkout replaces the tracked files and keeps `.env`,
because `.env` is not in the archive.

**HA order.** The code defines no update order for a container cluster. The
entrypoint notes that the app factory runs `db.create_all()` at start, and
schema work can only happen on the writable primary. **Recommendation:** back
up, update the primary, confirm `/healthz` and the scheduler, then update the
standby.

### 11.2 Backup

What to back up, in order of importance:

1. **`satom.env` / `.env`**: without `FERNET_KEY` the stored device
   credentials cannot be decrypted. Keep a copy off the node.
2. **The database**:

   ```bash
   satom-docker exec -T postgres pg_dump -U satom -Fc satom > /root/satom-db-$(date +%F).dump
   ```

3. **The `satom-data` volume**. Doing this in the same window as the dump
   matters: a `pg_dump` alone leaves SoT rows pointing at nothing.

   ```bash
   mkdir -p /root/satom-backup
   docker run --rm -u 0 --entrypoint tar \
     -v satom_satom-data:/d:ro -v /root/satom-backup:/out \
     satom:2.1.2 -czf /out/satom-data-$(date +%F).tar.gz -C /d .
   ```

   This uses the SATOM image with `-u 0` so that it needs no extra image;
   [`docker.md`](docker.md) shows the same with `alpine`.
4. `satom-pki` if you imported a certificate, and `satom-instance`. Back them up
   the same way (`satom_satom-pki`, `satom_satom-instance`).

In external-database mode, use your own tooling for step 2. Manual nodes: use
`dc exec -T postgres …` in place of `satom-docker exec -T postgres …`.

### 11.3 Restore

> Not a shipped or tested procedure. It is assembled from the backup commands
> above and standard `pg_restore` / `tar` usage. Rehearse it on a spare node.

```bash
# 1. same satom.env (FERNET_KEY!) in place; stack up so postgres is running
satom-docker stop web scheduler cron proxy
# 2. database
satom-docker exec -T postgres pg_restore -U satom -d satom --clean --if-exists < /root/satom-db-DATE.dump
# 3. data volume
docker run --rm -u 0 --entrypoint tar \
  -v satom_satom-data:/d -v /root/satom-backup:/in:ro \
  satom:2.1.2 -xzf /in/satom-data-DATE.tar.gz -C /d
# 4. start
satom-docker up -d
```

[`docker.md`](docker.md) states that the application's own system backup and
restore behave as on a host install.

### 11.4 Logs

```bash
satom-docker logs -f web                # gunicorn access and error log
satom-docker logs --tail=100 scheduler cron
satom-docker logs tls-init              # certificate decisions of the last up
satom-docker logs postgres              # includes [pg-standby] and [initdb] lines
./satom-docker.sh logs web              # manual: always --tail=200 -f
```

Production rotates the app, database, Redis and metrics logs at 20 MB × 5
files. `proxy` and `tls-init` use the engine's default logging driver settings.
`/var/log/satom` inside the app containers is not on a volume.

### 11.5 Health checks — what each proves

| Check | Proves | Does not prove |
|---|---|---|
| `satom-docker ps` → `web` healthy | gunicorn answers `/healthz` on `:8000` inside the container | that login works (see §9.1) or that the proxy is reachable |
| `proxy` healthy | `nginx -t` accepts the configuration | that the upstream is up or the certificate is valid for your name |
| `postgres` healthy | `pg_isready` for the app role and database | replication state |
| `curl -k https://127.0.0.1/healthz` | the full proxy → web path (the installer uses this, with its port) | the certificate's validity |
| `satom-docker exec -T web /opt/satom/deploy/docker/node-role.sh` | `f` primary / `t` standby / empty = database unreachable | |
| the runtime summary (§7.2) | the four capabilities are denied | |

`satom-docker.sh health` is meant to run the last four. In 2.1.2 it stops at
the `/healthz` step (§14), so run them individually.

### 11.6 Starting and stopping

```bash
satom-docker stop            # stop, keep containers
satom-docker start
satom-docker down            # remove containers, keep volumes
satom-docker up -d
```

On a manual node, use `./satom-docker.sh up|down` and `dc stop|start`.

### 11.7 Uninstall vs purge

| Command | Removes | Keeps |
|---|---|---|
| `sudo bash satom-setup.sh --uninstall` | containers and the network (`down --remove-orphans`) | **all volumes**, `/opt/satom-docker` including `satom.env`, images, the wrapper |
| `sudo bash satom-setup.sh --uninstall --purge` | containers, **all volumes** (`down -v`), `/opt/satom-docker`, `/usr/local/sbin/satom-docker`, all `satom:*` images | the base images, Docker itself, the `/root/satom-*` files (join file, generated password, summary), `/var/log/satom-setup.log`, and any firewall rules the installer opened |

`--purge` asks for a typed confirmation word. **With `--yes` it does not ask.**
It is irreversible: the database, the device vault and the certificates go.
`--uninstall` only applies to Docker installs.

Manual equivalents: `./satom-docker.sh down` (keeps volumes) and
`./satom-docker.sh down -v` (deletes them).

### 11.8 Air-gapped image delivery

`satom-setup.sh` Docker mode cannot run offline in 2.1.2. The manual route can
be used offline if you bring four things:

* the release source tree, which provides the compose files and the scripts
  that are bind-mounted;
* the SATOM image;
* the four stock images;
* an image built on a node with Internet access, because the build needs
  `apt-get` and `pip`.

On the connected build node:

```bash
./satom-docker.sh build satom:2.1.2
./satom-docker.sh export satom:2.1.2 /tmp/satom-2.1.2.tar.gz          # also writes /tmp/satom-2.1.2.tar.gz.sha256
docker pull postgres:15-bookworm; docker pull redis:7-alpine
docker pull victoriametrics/victoria-metrics:v1.148.0; docker pull nginx:1.27-alpine
docker save postgres:15-bookworm redis:7-alpine victoriametrics/victoria-metrics:v1.148.0 nginx:1.27-alpine \
  | gzip -9 > /tmp/satom-base-images.tar.gz
```

On the target, put the tarball and its `.sha256` **at the same path** as on
the build node, then:

```bash
./satom-docker.sh import /tmp/satom-2.1.2.tar.gz
gunzip -c /tmp/satom-base-images.tar.gz | docker load
```

`import` runs `sha256sum -c` **before** loading. The `.sha256` file records the
path that was given to `export`, so the check only finds the tarball at that
same path. Without the `.sha256` file, `import` warns and loads the tarball
unverified.

---

## 12. Troubleshooting

| Symptom | Cause (source) | Fix |
|---|---|---|
| Login page renders, `/healthz` is 200, **every password is refused** | reached over plain HTTP; the `Secure` session cookie is withheld and CSRF fails (`compose.yaml`, §9.1) | use `https://`; never publish `web:8000`; with an outer proxy, pass `Host $http_host` and `X-Forwarded-Proto https` |
| `http://` shows the **nginx welcome page** while `https://` works | the image's `default.conf` was copied into `satom-proxy-conf` and wins `:80` (`proxy-init.sh`) | `tls-init` deletes it on every `up`: run `up -d` again, then `restart proxy` |
| `up` fails creating the network / address pool overlaps | `SATOM_NETWORK_SUBNET` collides with a host network (`compose.yaml`) | change `SATOM_NETWORK_SUBNET`, `SATOM_PROXY_IP` and `TRUSTED_PROXIES` **together** |
| `satom-docker: TRUSTED_PROXIES (…) does not include the stack's own proxy …` | the coupling in §9.6 | put `SATOM_PROXY_IP` first in `TRUSTED_PROXIES` |
| Everyone shares one rate-limit bucket; audit entries show the proxy as actor; five failed logins lock everybody out | `TRUSTED_PROXIES` wrong or empty (`env.example`) | as above; include any outer proxy after it |
| `satom-docker: SATOM_HTTP_BIND is retired …` | old variable in `.env` | replace it with `SATOM_HTTPS_BIND` / `SATOM_REDIRECT_BIND` as the message says |
| `satom-docker.sh` dies with `…: command not found` right after starting | an unquoted value with spaces in `.env` (typically `SATOM_SERVED_NAMES=a b`); the script sources `.env` as shell | quote it: `SATOM_SERVED_NAMES="a b"` |
| An app container exits with code **78**: "`SECRET_KEY`/`FERNET_KEY` is unset or still the placeholder" | `entrypoint.sh` refuses placeholders | `./satom-docker.sh gen-secrets` (fresh `.env` only) |
| Exit **69**: "postgres host:port did not accept connections in 120s" | database not ready or unreachable | check `postgres` health/logs; raise `SATOM_DB_WAIT_SECONDS` if it is only slow |
| Exit **64**: "unknown SATOM_ROLE" or "SQLALCHEMY_DATABASE_URI is not set" | wrong role or environment | do not override `SATOM_ROLE` / the URI outside the compose files |
| App logs: "No admin user was created: the generated password could not be stored …" | the password file location is not writable | set `SATOM_ADMIN_PASSWORD` or fix the `satom-instance` volume, then restart `web` |
| App connects to nothing although `.env` looks right | a `.env` copied from a host carries `127.0.0.1` endpoints | the compose files override those for the bundled services; in external-DB mode, use the installer (`localhost` becomes `host.docker.internal`) |
| Standby: `no pg_hba.conf entry for replication connection` during base backup | the primary's PGDATA was initialised **without** `compose.prod.yaml`, so `initdb.d/10-replication.sh` never ran (it only runs on an empty PGDATA) | on the primary, run the SQL and the two `pg_hba.conf` lines from `initdb.d/10-replication.sh` by hand, then reload PostgreSQL; or rebuild the primary with the prod overlay from the start |
| Standby: "primary … never became ready" | the primary was not reachable within 300 s | check `SATOM_PRIMARY_HOST`, `SATOM_PG_BIND` on the primary, and the firewall; `up -d` again |
| Standby PostgreSQL: "REFUSING to start … PGDATA holds a PRIMARY" | the node was promoted (or the standby overlay was applied to a primary) | §10.6 step 4 or §10.7; **never** delete the volume of the node you want to keep |
| Compose error parsing `!reset` | Compose older than 2.24.4 on a standby | upgrade Compose. The installer notes that openSUSE's distribution package may be too old. |
| Installer: Docker installed but not responding | the host is an LXC container without nesting/keyctl (the installer's own hint) | enable nesting (and keyctl) for the container |
| Installer refuses the downloaded source: invalid network literals | a release tree carrying networks with host bits (the 2.1.1 mirror defect) | install 2.1.2 or later |
| External DB: connection refused / `pg_hba` rejection | the database does not listen on or admit the Docker networks | admit `SATOM_NETWORK_SUBNET` and the `docker0` network, and check `listen_addresses` and the firewall |
| Browser warns about the certificate name | SAN does not cover the typed name (§9.3) | set `SATOM_SERVED_NAMES`, `up -d`, `restart proxy` |
| `http://` redirects to the wrong port | non-443 `SATOM_HTTPS_BIND` (§9.7) | use 443, or use `https://host:port/` directly |
| Upload rejected with 413 | body larger than `client_max_body_size 400M` | — (limit of the generated vhost) |
| Long request ends with 504 after about 2 minutes | `proxy_read_timeout 120s` in the vhost, although gunicorn allows 600 s | — (the generated vhost is not configurable in 2.1.2) |
| `up` pulls or fails to pull `satom:<tag>` | the image is not present locally | build or import it first (§3.3) |
| `satom-docker.sh health` prints `SATOM_HTTP_BIND: unbound variable` | defect in 2.1.2 (§14) | run the checks individually (§11.5) |

---

## 13. Hardening recommendations (not applied by the stack)

> **Recommendations.** None of the following is configured in 2.1.2. They have
> not been tested against the stack by the project. Apply them in an override
> file of your own, validate with `config`, and test before production.

1. **`security_opt: ["no-new-privileges:true"]`** on every service.
2. **`cap_drop: [ALL]` on `web`, `scheduler` and `cron`.** They run as uid 999
   and listen on port 8000. For the root and stock-image services (`tls-init`,
   `proxy`, `postgres`, `redis`), drop capabilities only after checking which
   ones the upstream entrypoints need (for example `SETUID`/`SETGID` to switch
   user, `CHOWN`/`FOWNER` for volume ownership, `NET_BIND_SERVICE` for nginx's
   80/443).
3. **Split the network.** Put `postgres`, `redis` and `victoria-metrics` on a
   back-end network that `proxy` does not join, so the TLS terminator cannot
   reach unauthenticated Redis or VictoriaMetrics. `web` needs outbound access
   to appliances, so only a network without `web`'s egress can be `internal`.
4. **Give Redis a password** (`--requirepass`, and a matching
   `RATELIMIT_STORAGE_URI`). Note that the compose files hard-code the URI, so
   this needs an override of the service environment.
5. **Bind the published ports to one address.** Set
   `SATOM_HTTPS_BIND=<addr>:443` and `SATOM_REDIRECT_BIND=<addr>:80` rather
   than `0.0.0.0`, and keep `SATOM_PG_BIND` on the replication interface only.
6. **Filter Docker-published ports on the host.** The engine inserts its own
   packet-filter rules for published ports, and host firewall front ends such
   as ufw may not see that traffic. Filter it in the engine's `DOCKER-USER`
   chain, or upstream of the host. Narrow the replication `pg_hba` source
   (`0.0.0.0/0` in `initdb.d/10-replication.sh`) to the standby's address once
   it is known.
7. **Pin the stock images by digest** (`image: postgres:15-bookworm@sha256:…`).
8. **Limit what reaches the app containers.** Keep `SATOM_REPL_PASSWORD` and
   other values the app does not need out of the file used as `env_file`.
   Remember that `docker inspect` shows container environments.
9. **Flush the first admin password from the container metadata.** After the
   first login and a password change, run `satom-docker up -d` once without
   `SATOM_SETUP_ADMIN_PW` set, so that Compose recreates `web`, `scheduler` and
   `cron` with an empty value. Then delete `/root/satom-admin-password.txt` and
   the join file.
10. **`read_only: true`** for `web`, `scheduler` and `cron`, with `tmpfs` for
    `/tmp`, `/home/satom` and `/var/log/satom` and the three volumes rw.
    Validate carefully: the entrypoint and the application write under those
    paths.
11. **Resource limits** for `proxy`, `redis`, `scheduler` and `cron`, and log
    rotation for `proxy`/`tls-init` (engine `daemon.json` or a per-service
    `logging:`).
12. **Keep the `docker` group empty.** Consider rootless Docker or user
    namespace remapping only after testing them against the uid-999 volume
    ownership.

---

## 14. Known defects and gaps in 2.1.2

Found in the code while writing this page. Each one is also referenced where
it matters above.

| Item | Detail |
|---|---|
| `satom-docker.sh health` does not check the application | Its `/healthz` step builds the URL from the retired `SATOM_HTTP_BIND` (`http://127.0.0.1:${SATOM_HTTP_BIND##*:}/healthz`) under `set -u`, and `load_env` only lets that variable be unset or empty. Unset: bash stops with "unbound variable", so the runtime-capability step never runs either. Empty: the URL has no port and does not reach gunicorn or the HTTPS listener. |
| Redirect ignores a custom HTTPS port | `proxy-init.sh` always passes `--port 443` (§9.7). |
| Standby tunables not wired | `SATOM_BASEBACKUP_WAIT_SECONDS` and `SATOM_REPL_SLOT` never reach `postgres` (§8.4). |
| Production does not reject `:local` | `compose.prod.yaml` requires `SATOM_IMAGE` to be set, and `env.example` sets it to `satom:local` (§8.3). |
| `env.example` overstates a check | it says `satom-docker.sh` verifies that `SATOM_PROXY_IP` is inside `SATOM_NETWORK_SUBNET`; it does not (§3.4). |
| The promote action is not gated | `/promote` enqueues a request no container process executes (§7.2). |
| The first admin password persists in container metadata | §6.5, §13 item 9. |
| No `satom-data` replication, no certificate renewal job, no ACME client | §10.9, §9.4, §9.5. |

---

## 15. Source files

Everything above was taken from these files at release 2.1.2:

* `deploy/docker/compose.yaml`, `compose.prod.yaml`, `compose.standby.yaml`,
  `env.example`
* `deploy/docker/entrypoint.sh`, `cron-runner.sh`, `node-role.sh`,
  `pg-standby-entrypoint.sh`, `proxy-init.sh`, `satom-docker.sh`,
  `initdb.d/10-replication.sh`
* `Dockerfile`, `.dockerignore`
* `app/runtime.py`, and the enforcement points `app/services/self_update.py`,
  `service_control.py`, `cert_service.py`, `system_health.py`, `cluster.py`,
  `app/views/self_update.py`, and `_seed_admin()` in `app/__init__.py`
* `deploy/tls-bootstrap.sh`
* `installers/satom-setup.sh`
* `tests/test_container_runtime.py`, `tests/test_tls_by_default.py`,
  `tests/test_guided_installer.py`: the invariants they assert are the ones
  this page relies on as guaranteed

Related pages: [`docker.md`](docker.md) (design and rationale),
[`privilege-model.md`](privilege-model.md) (the host model this page mirrors),
[`INSTALL.md`](INSTALL.md) (host installs and the guided installer),
[`sizing.md`](sizing.md).
