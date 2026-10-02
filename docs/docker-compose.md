# Running SATOM with Docker Compose — operator manual

Status: **operator reference** for SATOM **2.3.0**. Every statement on this page
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
repository's `Dockerfile`; from 2.4.0 on every release also publishes it
prebuilt, §3.1), plus its dependencies as stock images, started as
one Compose project named `satom` (`name: satom` in
`deploy/docker/compose.yaml`). The web worker, the scheduler and the periodic
jobs are **the same image**; the entrypoint selects the role from `SATOM_ROLE`.

The image declares `SATOM_RUNTIME=container`. That declaration makes
`app/runtime.py` deny five host-only capabilities (§7.2). The optional
operations agent (§7) performs four of them on the web's behalf; the fifth,
HA promotion, stays manual. Apart from those,
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
| A root runner that performs the renounced capabilities from the web UI | **optional**: the operations agent (`compose.agent.yaml`, off by default) performs four of them — restart, release switch, certificate import, container health. It does **not** perform git/pip updates or HA promotion. | §7 |

If you need git or library (pip) updates in place, or the in-product HA
promotion, use a host install ([`INSTALL.md`](INSTALL.md)). Release switches,
service restarts and the certificate button are available in a container only
with the agent enabled.

### 1.3 Supported shapes

| Shape | Compose files applied | How to get it |
|---|---|---|
| **Development**, single node | `compose.yaml` | `deploy/docker/satom-docker.sh` with `SATOM_ENV` unset (§3.2) |
| **Production**, single node, bundled PostgreSQL | `compose.yaml` + `compose.prod.yaml` | `satom-setup.sh` role `standalone` (§2), or `SATOM_ENV=prod` with the manual route (§3.3) |
| **Production**, single node, **external PostgreSQL** | `compose.yaml` + `compose.prod.yaml` + the installer's `compose.setup.yaml` | `satom-setup.sh` only (`SETUP_DB=external`, §2.5). The role is forced to `standalone`. No manual equivalent ships. |
| **Production primary + standby** | primary: `compose.yaml` + `compose.prod.yaml`; standby: the same + `compose.standby.yaml` | `satom-setup.sh` roles `primary` / `standby` (§10.2), or manually (§10.3) |

Any of these shapes can add the optional operations agent: `compose.agent.yaml`
is then layered **last**, after every file above (§7.1).

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
| Internet access | `satom-setup.sh` Docker mode downloads the release source and the published image from GitHub, and pulls the base images. It builds the image itself (the build runs `apt-get` and `pip`) only when the release publishes none (§2.4 step 5). **Without Internet access it stops.** | `install_docker()`, `fetch_source()`, `get_image()` |
| Host tools for the installer | `curl`, `openssl`, `tar`; root | `check_requirements()` |

For fleet-dependent sizing see [`sizing.md`](sizing.md). That page describes
host installs; the container memory ceilings above apply on top of it.

---

## 2. Quick start A — `satom-setup.sh` (guided, recommended)

`installers/satom-setup.sh` installs, updates and uninstalls the Docker variant.
It must run as root.

### 2.1 Interactive

```bash
curl -fsSLO https://github.com/visionebc/SATOM/releases/download/v2.3.0/satom-setup.sh
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
| `SETUP_AGENT` | `yes` \| `no`; default `no` | Enables the operations agent when the release ships `compose.agent.yaml` (2.3.0 does); ignored with a warning on a release that does not. Also asked in update mode when the install runs without the agent (§7.1, §7.4). |
| `SETUP_CERT` | `self` \| `import`; default `self` | |
| `SETUP_CERT_FILE` / `SETUP_KEY_FILE` | PEM paths; required for `import` | The installer refuses a certificate and key that do not match. |
| `SETUP_CHAIN_FILE` | PEM path; default none | |
| `SETUP_FIREWALL` | `yes` \| `no`; default yes | Only consulted when firewalld or ufw is active. Opens `80`, the HTTPS port, and `5432` on a primary. See §13 about Docker and host firewalls. |
| `SETUP_INSTALL_DOCKER` | `yes` \| `no`; default yes | Installs Docker and/or the Compose v2 plugin if missing. |
| `SETUP_IMAGE` | `release` \| `build`; default `release` | `release` downloads the release's published image and builds only when there is none; `build` always builds from the source tree (§2.4 step 5). Installers newer than 2.4.0 only. |
| `SETUP_EXISTING` | `update` \| `abort`; default `update` | Used when a Docker install already exists (§11.1). `reinstall` is a native-mode answer only. |
| `SATOM_ADMIN_PASSWORD` | see §2.2 | Not asked on a standby. |

Command-line options: `--check`, `--yes`/`-y`, `--answers FILE`,
`--version X.Y.Z` (or `latest`), `--force` (continue on an unsupported
distribution), `--uninstall`, `--purge`, `-h`/`--help`. `--bundle` is for
native mode only.

### 2.4 What the installer does, in order (Docker mode)

1. Checks the OS, CPU, RAM, disk, ports 80/443 and Internet access, and
   resolves the version (its own `SETUP_VERSION`, 2.3.0, unless `--version` is
   given). Refuses if the machine already has a **native** install.
2. Ensures Docker is running and Compose v2 is at least 2.20.0, installing
   them if allowed.
3. Asks for the names, IP and port; the database; the role; the agent option
   (offered only when the release tree ships `compose.agent.yaml`, so the
   source is downloaded at this point); the certificate; and the `admin`
   password. The password is not asked on a standby.
4. Downloads the release source from GitHub into
   `/opt/satom-docker/releases/<ver>`. It **refuses** a tree that contains an
   invalid network literal (a network written with host bits set).
5. Gets `satom:<ver>`. It downloads `satom-image-<ver>-amd64.tar.gz` and its `.sha256` from
   the release, **stops** if the checksum does not match (it never falls back
   to a build after a bad download), and loads it with `docker load`. It builds
   from the tree instead — 5–15 minutes the first time — only when the release
   publishes no image (HTTP 404: releases before 2.4.0), when the host is not
   `x86_64` (the image is `linux/amd64`), or with `SETUP_IMAGE=build`. An image
   already in the engine is reused. The `satom-setup.sh` shipped *with* 2.4.0
   predates this step and always builds.
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
   Hub. With the agent enabled it also pulls `docker:27-cli`, the image the
   agent borrows to recreate the stack on an update (and to build the image
   when it has to, §7.6) (§7.4); a failed pull stops the install.
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
curl -fsSL https://codeload.github.com/visionebc/SATOM/tar.gz/refs/tags/v2.9.0 \
  | tar -xz --strip-components=1
cd /opt/satom-src/deploy/docker
```

This is the same archive `satom-setup.sh` downloads. Keep the checkout
root-owned (§6.6): the compose files and two scripts bind-mounted into
`postgres` (§5.1) come from this tree.

#### The published image (2.4.0 and later)

Every release from 2.4.0 on attaches the image to its GitHub release as
`satom-image-<ver>-amd64.tar.gz` with a `.sha256` next to it. It is built by the
release pipeline from the same code as that release's offline bundles, for
`linux/amd64`, and loads as `satom:<ver>`. Downloading it replaces the
`build` step below:

```bash
cd /tmp
curl -fLO https://github.com/visionebc/SATOM/releases/download/v2.9.0/satom-image-2.9.0-amd64.tar.gz
curl -fLO https://github.com/visionebc/SATOM/releases/download/v2.9.0/satom-image-2.9.0-amd64.tar.gz.sha256
sha256sum -c satom-image-2.9.0-amd64.tar.gz.sha256     # must print OK; stop if it does not
gunzip -c satom-image-2.9.0-amd64.tar.gz | docker load  # Loaded image: satom:2.9.0
docker image inspect satom:2.9.0 --format '{{index .Config.Labels "org.opencontainers.image.version"}}'   # 2.9.0
```

The `.sha256` names the file without a directory, so run `sha256sum -c` in
the directory that holds both files. Use the image of the **same** version as
the source tree: the compose files and the image are one release. Other
architectures build it (§3.2, §3.3).

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
./satom-docker.sh build satom:2.9.0     # or load the published image instead (§3.1)
```

Edit `.env`:

```ini
SATOM_ENV=prod                      # satom-docker.sh reads it from .env; see §3.4
SATOM_NODE_ROLE=primary
SATOM_IMAGE=satom:2.9.0             # compose.prod.yaml requires it to be set; it does NOT reject :local
SATOM_SERVED_NAMES="satom.example.com"   # quote it if it has spaces (§12)
SATOM_PG_BIND=127.0.0.1:5432        # required by compose.prod.yaml even on a single node
TZ=UTC
```

```bash
./satom-docker.sh config > /dev/null && echo config-ok   # the rendered config contains your secrets: do not paste it anywhere
./satom-docker.sh up
```

**Build, load (§3.1) or import the image before `up`.** If `SATOM_IMAGE` names an image the
engine does not have, Compose tries to pull it from a registry. For
`satom:<tag>` that registry is Docker Hub, which is the substitution
`satom-setup.sh` deliberately avoids. Check first:

```bash
docker image inspect satom:2.9.0 --format '{{.Id}}'
```

### 3.4 `deploy/docker/satom-docker.sh` — subcommand reference

The script reads `deploy/docker/.env` (it sources the file with `set -a`, so
the file must be valid shell). It picks the compose files like this:
`compose.yaml`; plus `compose.prod.yaml` when `SATOM_ENV=prod`; plus
`compose.standby.yaml` when additionally `SATOM_NODE_ROLE=standby`; plus, last,
`compose.agent.yaml` when `SATOM_SETUP_AGENT=yes` (in any shape, development
included). `SATOM_ENV` can live in `.env` or in the calling environment.

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
| `health` | `ps`, node role, `https://127.0.0.1:<port>/healthz` through the proxy (`-k`; the port is taken from `SATOM_HTTPS_BIND`, default 443), runtime summary (§7.2) | fixed in 2.3.0; earlier releases aborted at the `/healthz` step |

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
# with SATOM_SETUP_AGENT=yes: append  -f compose.agent.yaml  after every other file
dc ps
```

`dc` skips the two checks above. Order matters: Compose merges left to right,
and with the files reversed the development defaults win.

### 3.5 Do not mix the two entry points on an installer-managed node

`satom-setup.sh` links `/opt/satom-docker/current/deploy/docker/.env` to
`satom.env`, so `satom-docker.sh` appears to work there. It does not pass the
installer's `compose.setup.yaml` or `-p satom --project-directory`. On an
external-database node it would therefore start a real bundled PostgreSQL and
point the application at it; with the agent enabled it would recreate the
agent without `SATOM_AGENT_HOME`, so console updates would start being
refused. **On an installer-managed node, use only
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
| `/opt/satom-docker/compose.setup-agent.yaml` | 0600 root | only with the operations agent: its installer layout (§5.10). Layered only together with `compose.agent.yaml`. |
| `/opt/satom-docker/releases/<ver>/` | root | the downloaded release source for each installed version; with the agent, also every version switched to from the console (§7.6) |
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
| `satom-pki` | `/opt/satom/pki` (tls-init — rw; proxy — **ro**; agent — rw, overlay only) | the internal CA (`internal-ca/`), the node leaf certificate, and `public/server.{crt,key}` plus `meta.json` | an **imported** certificate and key must be re-imported if this volume is lost; a self-issued one is reissued | Recommended when you imported a certificate |
| `satom-proxy-conf` | `/out` (tls-init — rw); `/etc/nginx/conf.d` (proxy — **ro**) | the generated `satom.conf` vhost | no; rewritten on every `up` | No |
| `satom-acme` | `/var/www/satom-acme` (tls-init — rw; proxy — **ro**) | the ACME http-01 webroot | no | No |
| `satom-agent-requests` | **agent overlay only.** `/queue/requests` (agent — rw); `/opt/satom/data/update-requests` (web, scheduler, cron — rw) | request files waiting for the agent. A certificate request carries the private key until the agent consumes it (§7.6). | no | No |
| `satom-agent-status` | **agent overlay only.** `/queue/status` (agent — rw); `/opt/satom/data/update-status` (web, scheduler, cron — rw) | one `<uid>.json` status file per request, and `agent.heartbeat` | no; the request history is lost | No |

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
| `agent` (**optional**, `compose.agent.yaml`) | `${SATOM_IMAGE:-satom:local}` | **root** (`user: "0:0"`), all capabilities dropped but `CHOWN`, `DAC_OVERRIDE`, `FOWNER` | `unless-stopped` (not changed by prod) | none | heartbeat file younger than 60 s |

One overlay adds a service: `compose.agent.yaml` adds `agent` (§5.11, §7). No
other shipped overlay adds one.

All base services join the single bridge network `satom` (on the host:
`satom_satom`), subnet `${SATOM_NETWORK_SUBNET:-172.28.0.0/16}`. Only `proxy`
has a fixed address (`${SATOM_PROXY_IP:-172.28.0.10}`); every other service
gets a dynamic one and is reached by its service name. The `agent` is the
exception: it is **not** on `satom`, only on its own bridge `satom-agent`
(§6.3).

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
| What it does | `tls-bootstrap.sh ensure-pki` → `tls-bootstrap.sh write-vhost --port 443 --upstream web:8000 --resolver 127.0.0.11 --default-server` → deletes the stock `default.conf` from the conf volume → `chmod 600` on `public/server.key` → prints `meta.json` |
| Why root | the volumes are created empty and root-owned on first `up`, and the app account (uid 999) could not create `pki/` there (`compose.yaml`, `proxy-init.sh`) |

It runs on every `up`. An existing valid certificate is reused, and an
imported one is never touched (§9). It rewrites the vhost every time, but the
running `proxy` only reads it when it starts or reloads (§5.5).

### 5.5 `proxy`

The TLS terminator, using stock `nginx:1.27-alpine` with nothing added.
**Not optional** (§9.1).

| Aspect | Value |
|---|---|
| depends_on | `tls-init: service_completed_successfully`, `web: service_started` |
| Volumes (all **ro**) | `satom-pki:/opt/satom/pki`, `satom-proxy-conf:/etc/nginx/conf.d`, `satom-acme:/var/www/satom-acme` |
| Network | `satom`, fixed `ipv4_address: ${SATOM_PROXY_IP:-172.28.0.10}` |
| Ports | `${SATOM_HTTPS_BIND:-0.0.0.0:443}:443`, `${SATOM_REDIRECT_BIND:-0.0.0.0:80}:80` |
| Healthcheck | `nginx -t`; interval 30 s, timeout 5 s, 3 retries. This validates the configuration only; it does not probe the upstream. |
| vhost (generated) | `:443 ssl http2` for `SATOM_SERVED_NAMES`, TLSv1.2/1.3, `client_max_body_size 400M`, `proxy_read_timeout 120s`, `Host $http_host`, `X-Forwarded-Proto https`, `X-Forwarded-For`, `X-Real-IP`. `:80` serves `/.well-known/acme-challenge/` from `/var/www/satom-acme` and returns 301 to HTTPS for everything else. Both listeners claim `default_server`. The upstream is **re-resolved per request**: `resolver 127.0.0.11 valid=10s ipv6=off; set $satom_upstream http://web:8000; proxy_pass $satom_upstream;` (127.0.0.11 is Docker's embedded DNS). |

**Why the upstream is re-resolved (fixed in 2.3.0).** nginx resolves a literal
`proxy_pass` host once, at start, and then connects to that address forever.
Before 2.3.0 the vhost said `proxy_pass http://web:8000;`, so every time `web`
was recreated — any `satom-docker up -d` that recreated it, the installer's
update mode, a console update — it came back on a new address and the proxy
kept the old one: the console answered **502** until `proxy` was restarted.
This affected every Docker install. With a resolver the name is looked up per
request, with a 10 s cache. Host installs are unchanged: their vhost keeps the
literal `proxy_pass http://127.0.0.1:8000;`. `tls-bootstrap.sh` accepts only an
IPv4 address for `--resolver`.

**`proxy` is not recreated by an update.** It runs a stock image, so a new
`SATOM_IMAGE` does not recreate it, and the vhost `tls-init` rewrites on every
`up` was never loaded. Since 2.3.0 the installer's update mode (§11.1) and the
agent's update (§7.6) both **reload** it gracefully after recreating the stack
(SIGHUP to the nginx master: open connections survive). After a manual
`up -d`, reload it yourself when the vhost may have changed:
`satom-docker kill -s HUP proxy` (manual: `dc kill -s HUP proxy`), or
`restart proxy`.

### 5.6 `web`

| Aspect | Value |
|---|---|
| Image | `${SATOM_IMAGE:-satom:local}`; prod: `${SATOM_IMAGE:?}` |
| Runs as | `USER satom`, uid/gid 999 (`Dockerfile`); no `user:` override |
| Process | `entrypoint.sh` role `web`: seeds `data/publication-rules.local.json` with `{}` if it is absent; refuses placeholder secrets (exit 78); waits for PostgreSQL (`SATOM_DB_WAIT_SECONDS`, default 120, exit 69 on timeout); on the primary only, runs `flask db upgrade` and exits 70 if it fails, so the agent rolls the update back instead of serving new code on an unmigrated schema (a standby is skipped: its schema arrives by replication); then `gunicorn --workers ${SATOM_WEB_WORKERS:-4} --bind 0.0.0.0:8000 --timeout ${SATOM_WEB_TIMEOUT:-600} wsgi:app` with access and error logs on stdout |
| Environment | `env_file: .env` (**everything** in `.env`), then `SQLALCHEMY_DATABASE_URI` (composed from `POSTGRES_*`, host `postgres:5432`), `RATELIMIT_STORAGE_URI=redis://redis:6379/0`, `SATOM_METRICS_URL=http://victoria-metrics:8428`, `TZ`, `SATOM_ROLE=web`, `TRUSTED_PROXIES` (base default `172.28.0.10`; prod: **required**). Service-level `environment` wins over `env_file`. |
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

With the agent enabled, the installer writes a **second** overlay,
`/opt/satom-docker/compose.setup-agent.yaml`, that gives `agent` the installer
layout. It is a separate file on purpose: the wrappers layer it only together
with `compose.agent.yaml`, so turning `SATOM_SETUP_AGENT` back to `no` never
leaves a half `agent` service (no image) behind for Compose to reject. Written
with the agent, deleted by an install without it:

```yaml
services:
  agent:
    environment:
      SATOM_AGENT_HOME: /opt/satom-docker
    volumes:
      - /opt/satom-docker:/opt/satom-docker
```

The directory is mounted at the **same path** it has on the host, because an
update hands host paths to a helper container (§7.6) and a path that differed
inside the agent would point the engine at nothing. No other service receives
it, and the overlay never mounts the Docker socket
(`tests/test_docker_agent.py`).

### 5.11 `agent` (optional)

Defined in `deploy/docker/compose.agent.yaml`, which also adds the queue
volumes and `SATOM_AGENT=docker` to `web`, `scheduler` and `cron`. Present
only when `SATOM_SETUP_AGENT=yes` (§7.1).

| Aspect | Value |
|---|---|
| Purpose | performs, on request, four of the five capabilities the container runtime otherwise renounces (§7); HA promotion stays refused |
| Image | `${SATOM_IMAGE:-satom:local}` — the SATOM image, for the stdlib-only `satom_agent.py` and `tls-bootstrap.sh`. No `:?` guard, even in production. |
| Entrypoint | `python3 /opt/satom/deploy/docker/satom_agent.py` |
| Runs as | `user: "0:0"`; `cap_drop: [ALL]`, `cap_add: [CHOWN, DAC_OVERRIDE, FOWNER]`; `no-new-privileges:true`; `read_only: true` with a `tmpfs` on `/tmp` |
| Environment | `TZ` only. Installer overlay: `SATOM_AGENT_HOME=/opt/satom-docker`. **No `env_file`**, so none of the `.env` secrets reach its environment. |
| Volumes | `/var/run/docker.sock` (rw — the only mount of the engine socket in the stack); `satom-agent-requests:/queue/requests`; `satom-agent-status:/queue/status`; `satom-pki:/opt/satom/pki` (rw, for the certificate import). Installer overlay: `/opt/satom-docker` at the same path. |
| Network | `satom-agent` (a bridge of its own). **Not** `satom`. |
| Ports | none; it listens on nothing |
| Healthcheck | `python3` reads `/queue/status/agent.heartbeat` and fails if its `ts` is 60 s old or more; interval 30 s, timeout 10 s, 3 retries, start period 30 s. The image `HEALTHCHECK` (curl `:8000`) is replaced, because the agent serves nothing. |
| Logging | `json-file`, 10 MB × 3 |
| Exit code 78 at start | `/var/run/docker.sock` is not mounted |

---

## 6. Permissions and privilege model

This section states what each container **can** do given the 2.3.0 files. It
is the container counterpart of [`privilege-model.md`](privilege-model.md).
Rows marked *agent overlay* apply only when `compose.agent.yaml` is layered
(§7.1).

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
| `agent` (*agent overlay*) | **root (0:0)**, with a reduced capability set (§6.2) | `compose.agent.yaml` `user: "0:0"`. It must use the engine socket (root-owned on the host) and chown the queue volumes to uid 999. Files it writes into the queue volumes are chowned to 999:999 so the web can read them. |
| helper containers (*agent overlay*, during an update) | the `docker:27-cli` image's default (root) | Started by the agent with the engine socket and the installer directory bind-mounted, and removed when the command ends (§7.6). The compose helpers run with `NetworkMode: none`; only the `docker build` helper gets `bridge` (BuildKit needs it for the registry pull token). Any other value falls back to `none`. They carry the label `io.satom.agent.helper=1`. |

To confirm the stock images on your engine, rather than relying on this table:

```bash
for i in postgres:15-bookworm redis:7-alpine victoriametrics/victoria-metrics:v1.148.0 nginx:1.27-alpine; do
  printf '%-45s USER=%s\n' "$i" "$(docker image inspect "$i" --format '{{.Config.User}}')"
done          # an empty USER means the container starts as root
satom-docker top web        # or: dc top web — shows the running processes and their users
```

### 6.2 Linux capabilities and kernel confinement

**The base files (`compose.yaml`, `compose.prod.yaml`, `compose.standby.yaml`)
set none of** `cap_add`, `cap_drop`, `privileged`, `security_opt` (and
therefore no `no-new-privileges`), `read_only`, `tmpfs`, `devices`,
`network_mode`, `pid` or `ipc`, and **none of them mounts
`/var/run/docker.sock`**. Their only `user:` key is `tls-init`'s `0:0`.

**The agent overlay is the one exception, and only for `agent`:** `cap_drop:
[ALL]` then `cap_add: [CHOWN, DAC_OVERRIDE, FOWNER]` (chown the queue volumes
to uid 999 and write into them although it does not own them — nothing else),
`security_opt: [no-new-privileges:true]`, `read_only: true` with a `tmpfs` on
`/tmp`, and the only mount of `/var/run/docker.sock` in any compose file.
`tests/test_docker_agent.py` asserts each of these, and fails if any other
service in any compose file mounts the socket. None of it limits what the
agent can do **through the socket**: the engine API is root on the host
whatever the calling container's capabilities (§6.6).

Every other container therefore runs with:

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
| `agent` (*agent overlay*) | nothing | it listens on nothing; asserted by `tests/test_docker_agent.py` |

**The agent is not on the `satom` network.** It sits alone on the bridge
`satom-agent`, so no container of the stack can open a connection to it or
even resolve its name, and it can reach none of them over the network. The
bridge exists for one outbound purpose: downloading a release tree and its
published image from GitHub for an update (§7.6). Everything else it does goes through the socket. Its
only input is a file in the `satom-agent-requests` volume. The helper
containers it starts for an update run with `NetworkMode: none`, except the
one that runs `docker build`, which gets the default `bridge` network: BuildKit
fetches the registry pull token from the client, and with no network the first
`FROM` fails (measured). The helper code accepts only `none` and `bridge`, and
falls back to `none` for anything else.

The `satom` network is one flat bridge. It is not declared `internal`, and nothing
separates the front end (proxy ↔ web) from the back end (database, Redis,
metrics). **Any container on the network can read and write Redis and query or
write VictoriaMetrics without credentials.** Every container can open outbound
connections.

### 6.4 Filesystem write access

| Service | Can write | Read-only mounts | Notes |
|---|---|---|---|
| `web`, `scheduler`, `cron` | `satom-data`, `satom-state`, `satom-instance` (volumes, uid 999); its own writable layer where uid 999 owns the path (`/opt/satom/reports`, `/var/log/satom`, `/home/satom`, `/tmp`). *Agent overlay:* also `satom-agent-requests` and `satom-agent-status`, mounted over `data/update-requests` and `data/update-status`. | — | **The application code under `/opt/satom` (`app/`, `deploy/`, …) is copied as root and is not writable by uid 999**, so the web process cannot rewrite its own code. It cannot read `satom-pki`: no app service mounts it, with or without the agent (asserted by `tests/test_docker_agent.py`). |
| `agent` (*agent overlay*) | `satom-agent-requests`, `satom-agent-status`, `satom-pki`; installer: `/opt/satom-docker` (bind mount, including `satom.env`, `current` and `releases/`); `/tmp` (tmpfs). **Through the socket: anything the engine can do.** | its root filesystem (`read_only`) | Writes into the queue volumes go to an `O_EXCL` temporary that is renamed over the target, so a symlink the web plants is replaced, never followed. |
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
* *Agent overlay.* The agent has no `env_file`, so no secret reaches its
  environment. On an installer layout it can nevertheless **read and rewrite
  `satom.env`** through the `/opt/satom-docker` mount (an update rewrites the
  `SATOM_IMAGE` line), and through the socket it can read any container's
  configuration. A certificate request carries the **private key** in the
  request file, in the `satom-agent-requests` volume, until the agent picks it
  up; the agent deletes the file before acting on it, also when it refuses the
  request, and the status row it writes never contains the key.

### 6.6 Who is effectively root on the host

| Principal | Why |
|---|---|
| root | obviously |
| **Every member of the `docker` group**, and anyone allowed to run `docker` through sudo | Access to the engine API is root on the host: such a user can start a privileged container that mounts `/`. This is Docker's own documented position and it is not specific to SATOM. |
| Anyone who can write `/opt/satom-docker` (installer) or the manual checkout | They can change the compose files, the `initdb.d` script or the standby entrypoint, all of which run as root in containers at the next `up`. The installer creates `/opt/satom-docker` as 0700 root. |
| Anyone who can read `satom.env` / `.env` | holds `FERNET_KEY` (decrypts every stored device credential), `SECRET_KEY` (forges sessions) and the database passwords. The installer writes it 0600 root. `gen-secrets` writes 0600 owned by the invoking user. |
| Anyone who can read `/root/satom-docker-join.env` | the same secrets, plus the primary's address. 0600 root; delete it after the standby joins. |
| *Agent overlay:* **the `agent` container**, and anyone who can run code in it | it holds `/var/run/docker.sock`, which is root on the host (§7.8) |
| *Agent overlay:* anyone who can write the `satom-agent-requests` volume — in practice, code execution in `web`, `scheduler` or `cron`, or an admin of the console | **can ask, not act.** Such a principal can request only what the agent's closed list accepts (§7.6): restart a listed service, switch the stack to a release `X.Y.Z` (a `vX.Y.Z` tag of the public repository, or a tree already under `releases/`), replace the proxy certificate. It cannot name an image, a command, a path, a compose argument or a service outside the list. Only the agent acts. |

`/usr/local/sbin/satom-docker` is 0755, but it sources the root-only
`satom.env` and calls `docker`, so in practice only root can use it.

---

## 7. The operations agent

### 7.1 What ships, and how to enable it

A container administers no host, so by default the stack **renounces** what a
host's root runner does. The image declares `ENV SATOM_RUNTIME=container`, and
`app/runtime.py` then denies the host-only capabilities through
`capability()` / `require()`. It selects the container runtime only for the
exact value `container` (case-insensitive, whitespace stripped); any other
value means `host`. Do **not** set `SATOM_RUNTIME` in `.env`: `env_file`
values override the image's `ENV`.

**2.3.0 ships an optional operations agent, off by default,** that gives four
of those capabilities back to the console without giving the web the keys to
the host:

* `deploy/docker/satom_agent.py` — the agent. Stdlib-only Python, because the
  file is reviewed as a security boundary.
* `deploy/docker/compose.agent.yaml` — the overlay. It adds the `agent`
  service (§5.11), two volumes that it shares with `web`, `scheduler` and
  `cron`, and the declaration `SATOM_AGENT=docker` on those three.

The model is the host's (`privilege-model.md` §4b): the web only drops a JSON
request into a volume; the agent, the one container that holds
`/var/run/docker.sock`, re-validates it against a closed list and does the
work; the result comes back as a status file. **The socket is root on the
host.** Read §7.5 and §7.8 before enabling it.

| Route | How to enable |
|---|---|
| Installer, new install | answer `y` to "Enable the agent?" (default `n`), or `SETUP_AGENT=yes` with `--yes`. Offered only when the release tree ships `compose.agent.yaml`. |
| Installer, existing install | run the installer in update mode (§11.1). When the install runs without the agent and the new release ships it, the installer asks the same question (`SETUP_AGENT` with `--yes`). An install that already runs the agent keeps it without asking. |
| Manual checkout | set `SATOM_SETUP_AGENT=yes` in `deploy/docker/.env`, then `./satom-docker.sh up`. The agent runs in the **manual layout**: restart, certificate and health work; updates from the console are refused (§7.6). |

Check the result on the host with `satom-docker ps agent` (healthy after its
first heartbeat) and in the console under **System → Container operations**,
whose *Operations agent* card must say **live**.

### 7.2 The capabilities, without and with the agent

`app/runtime.py` names five host-only capabilities (`HOST_ONLY_CAPABILITIES`).
Four of them are delegable (`AGENT_DELEGABLE`); `ha_promote` never is. A
delegable capability is **delegated** — the enforcement point enqueues for the
agent instead of refusing — only when both hold:

* **declared:** `SATOM_AGENT=docker` in the app container's environment, set by
  the overlay. It means nothing on a host install. A heartbeat file alone,
  without the declaration, delegates nothing.
* **live:** `update-status/agent.heartbeat` has a timestamp at most 60 s old
  (`AGENT_MAX_SILENCE`, four missed beats). A timestamp more than 60 s in the
  future is a clock problem and does not count as life either.

Otherwise the capability is denied. Without the agent the reason is the
`_REASONS` string; with an agent that is declared but silent it is:

> "The operations agent is enabled but not answering (*problem*), so
> '*capability*' is unavailable until it is back. Check it with 'satom-docker
> ps agent' and 'satom-docker logs agent'."

where *problem* is one of "the agent has never reported (no heartbeat file)",
"unreadable heartbeat: …", "last heartbeat *N* s ago" or "heartbeat timestamp
is *N* s in the future". Nothing is queued behind a silent agent: accepting a
request nobody will execute is the failure this gate exists to prevent.

The reasons below are quoted verbatim from `_REASONS` in `app/runtime.py`. The
UI, the API error and the CLI all render this same string. The four delegable
ones end with the sentence "The optional operations agent
(deploy/docker/compose.agent.yaml) performs it from the console."

| Capability | Enforcement point | Without the agent (verbatim) | With a live agent |
|---|---|---|---|
| `self_update` | `app/services/self_update.py` — `request_update()` (git) and `request_pip_change()` (libraries) call `runtime.require("self_update")` | "In-place self-update is not available in the container runtime. Update by deploying a new image tag and recreating the stack. The optional operations agent (deploy/docker/compose.agent.yaml) performs it from the console." | The git and pip updaters **still refuse**, now with `CONTAINER_UPDATE_REDIRECT`: "In the container runtime the code is the image: the git and library updaters do not apply. Switch the stack to another release from System → Container operations." That page enqueues a `ctr-update` (§7.6). |
| `service_control` | `app/services/service_control.py` — `request_service_action()` calls `runtime.require("service_control")`; `states()` draws the Services card | "Service control is not available in the container runtime. Use the container engine (docker compose restart \<service\>) instead. The optional operations agent (deploy/docker/compose.agent.yaml) performs it from the console." `states()` returns no rows, and the Services card shows this reason instead. | `states()` returns the stack's containers as the heartbeat reports them; an action enqueues a `ctr-restart` for the service (§7.6). |
| `cert_activation` | `app/services/cert_service.py` `_install()` — `runtime.require("cert_activation")` before anything is written | "Certificate activation is not available in the container runtime. This stack already serves TLS from its own proxy container; replace the certificate with 'deploy/tls-bootstrap.sh import-cert' and restart the proxy service. The optional operations agent (deploy/docker/compose.agent.yaml) performs it from the console." | After the web's own validation, `_install()` enqueues a `ctr-cert` and **waits up to 90 s** for the verdict. The agent imports the pair and **reloads** `proxy` gracefully (`nginx -t`, then SIGHUP); it never restarts it (§7.6). A refusal reaches the caller as "the operations agent refused the certificate: …". `current()` reads the public certificate the agent forwards in its heartbeat — the web never mounts `satom-pki`. Issuing from the internal CA stays unavailable (`can_issue_internal` is `false`): the CA lives in `satom-pki`. |
| `unit_health` | `app/services/system_health.py` `service_status()` — `runtime.capability("unit_health")` | "systemd unit health is not available in the container runtime. Container health is reported by the container engine. The optional operations agent (deploy/docker/compose.agent.yaml) performs it from the console." The rows read "n/a (container runtime)". | One row per container of the stack, "*service* (container)", with the engine's state and health from the heartbeat. |
| `ha_promote` | `app/services/cluster.py` `request_promote()` — `runtime.require("ha_promote")`, reached from the HA panel's `/promote` | "Promotion is not available in the container runtime: no process in the stack executes it. Fail over by hand (docs/docker-compose.md §10.6)." | **The same refusal.** Never delegated, and the agent refuses any request kind but its own three. |

To see the live state on a node:

```bash
satom-docker exec -T web python -c "import json,app.runtime as r; print(json.dumps(r.summary(), indent=2))"
```

Besides `runtime`, the summary has four keys. `capabilities` lists all five
names: without the
agent all are `false`; with a live agent the four delegable ones are `true`
and `ha_promote` is `false`. `delegated` lists the four delegable names.
`reasons` holds the refusal string of every capability that is currently
denied. `agent` holds `declared`, `live`, `age` (seconds since the last
heartbeat), `problem` and `version` (the agent's own release).
`./satom-docker.sh health` prints the same summary.

Before 2.3.0 the HA panel's promote action was not gated by `app/runtime.py`:
in a container it enqueued a request no process would ever execute. It now
refuses, with or without the agent (`tests/test_container_ops.py`).

### 7.3 Operator procedures without the agent

These remain the path when the agent is not enabled or not answering, and for
updates on a manual checkout. They also keep working with the agent enabled:
the agent adds a way, it removes none.

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
`deploy/docker/compose.agent.yaml` (2.3.0 does). On a release that does not,
it says so, keeps `SATOM_SETUP_AGENT=no`, and ignores `SETUP_AGENT=yes` with a
warning; the four operations are then done with the `satom-docker` wrapper
(§7.3). Before the question it states the risk: the agent mounts
`/var/run/docker.sock`, so whoever controls it is root on the host; the web UI
only drops requests into a volume; the agent accepts a closed list of actions.

With the agent enabled, the installer:

1. writes `SATOM_SETUP_AGENT=yes` into `satom.env`;
2. writes `compose.setup-agent.yaml` — `SATOM_AGENT_HOME` and the
   `/opt/satom-docker` bind mount at the same path (§5.10). In update mode
   enabling the agent also regenerates `compose.setup.yaml` (same content);
3. writes the `satom-docker` wrapper, which layers `compose.agent.yaml` and
   then `compose.setup-agent.yaml` **last**, after `compose.setup.yaml`, and
   only when `SATOM_SETUP_AGENT=yes` *and* `compose.agent.yaml` exists in
   `current`;
4. pre-pulls `docker:27-cli`, the image the agent borrows to run `docker compose`
   (and `docker build`, when an update has to build the image) for an update
   (§7.6). A new install stops if the pull
   fails; update mode only warns, and the agent pulls it on first use. The tag
   is pinned by major so that Compose understands `!reset` (≥ 2.24.4, used by
   the standby overlay). The installer's `AGENT_CLI_IMAGE` and the agent's
   `CLI_IMAGE` must be equal (`tests/test_docker_agent.py`).

The install summary line reports `agent yes` or `agent no`.

On a manual checkout none of this applies: `satom-docker.sh` layers
`compose.agent.yaml` last when `SATOM_SETUP_AGENT=yes` (`env.example` ships
`SATOM_SETUP_AGENT=no`), and the agent runs without `SATOM_AGENT_HOME`.

### 7.5 The permission boundary, and how the agent implements it

These five requirements were written before the agent existed, as the host
model of [`privilege-model.md`](privilege-model.md) §4 restated for a
container. The agent was reviewed against them. Each is implemented as below,
and guarded by the named tests (all in `tests/test_docker_agent.py` unless
another file is named).

1. **The web worker only enqueues.** The process that parses appliance input
   and HTTP requests must not hold the privilege it asks for.
   *Implementation:* `app/services/container_ops.py` writes a `queued` status
   row, then the request (to a dot-temporary, renamed into place) into
   `data/update-requests/` — the same order and the same rename as the host
   enqueues. Nothing in the web talks to the engine. `web` never mounts the
   socket and holds no credential to the agent; there is none to hold.
   *Guarded by:* `test_only_the_agent_mounts_the_engine_socket_in_any_compose_file`,
   `test_the_installer_overlay_never_gives_the_socket_to_anyone`,
   `test_the_app_services_get_the_queue_and_the_declaration`, and in
   `tests/test_container_ops.py` `test_nothing_is_queued_without_a_live_agent`.
2. **The privileged side re-validates against a closed allowlist.** The web
   worker's validation is a UX affordance; the agent's is the security
   boundary. *Implementation:* `validate_request()` accepts a file only if its
   name is a request id, the `id` inside equals it, it is at most 64 KiB of
   UTF-8 JSON, its `kind` is one of three, it carries exactly the fields of
   that kind (an unexpected field is refused, not ignored) and every field is
   a string. Services come from a fixed table, versions must be `X.Y.Z`, PEMs
   are checked for shape and slot (§7.6). The checks run again at the point of
   use. No request field reaches an image name, a command, a path or a compose
   argument, except a version that already matched the regular expression:
   the compose command line is built from fixed paths, and the service list
   for `up` comes from `compose config --services`. The web keeps a copy of
   the allowlist so the UI offers only what the agent accepts; the two copies
   must be identical. *Guarded by:* the validator tests
   (`test_every_kind_outside_the_closed_list_is_refused`,
   `test_an_unexpected_field_is_refused_not_ignored`,
   `test_the_policy_matrix_is_exactly_what_is_accepted`,
   `test_anything_but_x_y_z_is_refused`, the PEM tests), and in
   `tests/test_container_ops.py` `test_web_and_agent_allowlists_are_identical`,
   `test_the_web_refuses_what_the_agent_would_refuse` and the round-trip tests,
   which feed every request the web writes through the agent's own validator.
3. **Treat the Docker socket as host root.** *Implementation:* `agent` is the
   only service in any compose file that mounts `/var/run/docker.sock`. It
   publishes no port, listens on nothing, and is not on the `satom` network
   (§6.3). Its footprint: `cap_drop: [ALL]` plus `CHOWN`, `DAC_OVERRIDE`,
   `FOWNER`; `no-new-privileges`; a read-only root filesystem; no `env_file`;
   stdlib-only code. *Guarded by:*
   `test_only_the_agent_mounts_the_engine_socket_in_any_compose_file`,
   `test_the_agent_listens_on_nothing_and_is_not_on_the_stack_network`,
   `test_the_agent_is_confined_as_far_as_its_job_allows`,
   `test_the_agent_is_stdlib_only`.
4. **Results travel back the same way.** *Implementation:* the agent writes
   `<uid>.json` into `satom-agent-status` in the host runner's shape, with
   `"runner": "container-agent"`, so the existing status polls render it. It
   never calls the web. Every write into a volume the web can also write is
   symlink-safe: a fresh `O_EXCL` temporary renamed over the target, so a
   symlink the web plants at `<uid>.json` is replaced, never followed as root.
   Requests are opened with `O_NOFOLLOW` and must be regular files.
   *Guarded by:* `test_a_valid_request_is_executed_consumed_and_reported`,
   `test_a_status_write_replaces_a_planted_symlink_instead_of_following_it`,
   `test_a_request_that_is_a_symlink_is_not_read`,
   `test_the_status_row_never_carries_the_key`,
   `test_the_agent_queue_paths_match_the_app_side`,
   `test_the_heartbeat_is_not_listed_as_an_update`.
5. **The runtime gate changes deliberately.** An agent does not re-enable the
   capabilities by existing. *Implementation:* `AGENT_DELEGABLE` names the
   four explicitly; delegation needs the declaration *and* a fresh heartbeat
   (§7.2); each enforcement point has an explicit agent branch; `ha_promote`
   is host-only and not delegable. *Guarded by* `tests/test_container_ops.py`:
   `test_a_live_agent_delegates_exactly_the_four`,
   `test_promotion_is_never_delegated`,
   `test_a_silent_agent_is_treated_as_absent_and_says_so`,
   `test_a_heartbeat_from_the_future_is_not_proof_of_life`,
   `test_a_heartbeat_without_the_declaration_delegates_nothing`,
   `test_the_declaration_means_nothing_on_a_host`; and
   `tests/test_container_runtime.py`
   `test_every_declared_capability_has_a_call_site`.

### 7.6 What the agent does, request by request

**The loop.** Every 2 s the agent lists `*.json` in `/queue/requests`, in name
order, and handles them one at a time:

1. It reads the file without following links; a file that is not a regular
   file, or is larger than 64 KiB, is deleted and logged with no status row.
2. It **deletes the request before acting on it**. A certificate request
   carries a private key, and a request that crashed the agent must not replay
   forever.
3. If the file name is a request id, it writes `<uid>.json` with
   `"state": "running"`.
4. It validates the request (§7.5 item 2). A request whose file is **older than
   600 s** at pickup is refused — "request expired: queued *N* s ago (limit
   600 s); it is not executed late" — so a restart queued while the agent was
   down cannot fire hours later on a stack the operator has since fixed by
   hand.
5. It executes it and finishes the status row with `"state": "success"` or
   `"failed"`, the steps it took and, on failure, `error`.

**Request files.** Name `<id>.json`, with `<id>` of the form
`YYYYMMDD-HHMMSS-xxxxxx` (six lowercase hex digits). Fields that any request may
carry, informational only and copied into the status row: `id` (must equal the
file name), `kind`, `requested_by`, `requested_at`, `node`, `role`, `origin`.

| `kind` | Required | Optional | Checks |
|---|---|---|---|
| `ctr-restart` | `service`, `action` | — | the service is in the table below and the action is allowed on it |
| `ctr-update` | `version` | — | `X.Y.Z`: three numbers of 1–4 digits, no leading zero, nothing before or after (not `v2.3.0`, not `2.3.0-rc1`, not `2.3.0\n`) |
| `ctr-cert` | `cert_pem`, `key_pem` | `chain_pem` | PEM blocks only; at most 32 KiB (certificate, chain) and 16 KiB (key); `key_pem` must contain a private key; `cert_pem` and `chain_pem` must **not** (a key in the certificate slot would be served to every client); an empty chain is accepted |

Any other kind is refused, naming the three accepted. A host-runner request
(git update, pip, unit install, promotion) lands here on purpose.

**The service table.** The same rule as the host's
(`app/services/service_control.py`): nothing that would remove the only way to
undo it is ever stoppable.

| Service | Allowed actions | Why |
|---|---|---|
| `web` | `restart` | a stop would take away the page that could start it again |
| `scheduler` | `start`, `stop`, `restart` | |
| `cron` | `start`, `stop`, `restart` | |
| `proxy` | `restart` | a stop ends the session with no way back except a shell |
| `postgres` | `restart` | never stopped from the console |
| `redis` | `restart` | derivable state; a restart resets rate-limit windows |
| `victoria-metrics` | `restart` | dashboards report query errors while it is down |
| `agent`, `tls-init` | **never** | stopping the agent bricks the queue that would start it again; `tls-init` is a run-once job. Refused even if a future edit listed them. |

**`ctr-restart`.** The agent finds the containers of the service in the
Compose project `satom` (one-off containers excluded); none is a refusal. It
calls the engine's start/stop/restart on each (20 s stop timeout). After a
`start` or `restart` it waits up to 180 s for every container of the service to
run and, where it has a healthcheck, to be healthy; otherwise the request
fails. A `stop` is not waited on.

**`ctr-update`** — installer layout only. Without `SATOM_AGENT_HOME` it is
refused: "updating from the console needs the installer layout
(/opt/satom-docker). On a manual checkout build the new tag and run
./satom-docker.sh up." A version whose image `satom.env` already names is
refused ("the stack already runs satom:*X.Y.Z*"). Then:

1. **Stage the release tree.** If `/opt/satom-docker/releases/X.Y.Z/Dockerfile`
   exists, the tree is reused as it is. Otherwise the agent downloads
   `https://codeload.github.com/visionebc/SATOM/tar.gz/refs/tags/vX.Y.Z`
   (at most 400 MB) into a temporary directory under `releases/` and extracts
   it with its own checks: the top directory is stripped; absolute paths,
   `..`, links pointing outside the tree and anything that is not a file,
   directory or link are refused; modes are masked to 0755 and owners set to
   root. Python's `tarfile` data filter is applied as a second layer where the
   interpreter has it. The tree must contain `Dockerfile` and
   `deploy/docker/compose.yaml`, and must carry no network literal with host
   bits set (the 2.1.1 mirror defect; the installer's rule). A tree without
   `compose.agent.yaml` (any release before 2.3.0) is then **refused**, before
   anything is built or switched: "release v*X.Y.Z* does not ship the
   operations agent; switch to it with satom-setup.sh --version *X.Y.Z* on the
   host" (§7.8).
2. **Get the image** `satom:X.Y.Z`, unless the engine already has it. The
   policy is the installer's (`get_image`, §2.4 step 5), chosen by
   `SATOM_AGENT_IMAGE` in `satom.env` (`release`, the default, or `build`;
   any other value refuses the update before anything is downloaded):
   * **The published image** (default). The agent downloads
     `https://github.com/visionebc/SATOM/releases/download/vX.Y.Z/satom-image-X.Y.Z-amd64.tar.gz`
     (at most 400 MB, 60 s per read, 30 minutes in all) and its `.sha256`
     into a private temporary directory under `releases/`, and compares the
     digest: the `.sha256` must be one `sha256sum` line naming that file.
     Before the engine sees the archive, its `manifest.json` must name exactly
     `satom:X.Y.Z` — `docker load` tags whatever the archive names, and an
     archive tagged `satom:<the running version>` would repoint the tag the
     rollback uses. The archive is loaded through the Engine API
     (`POST /images/load`, the gzip file as the body — no helper container),
     then proven to be the release: the label
     `org.opencontainers.image.version` must be `X.Y.Z`, the label
     `com.visionebc.satom.payload-sha256` (set only by the release pipeline)
     must be a digest, and `/opt/satom/VERSION` inside the image must read
     `X.Y.Z` — read through the engine's archive API from a container that is
     created and removed, never started. The step reads
     **`image: downloaded and verified (<sha256>)`**.
   * **Anything that goes wrong with an image that exists fails the update**:
     a digest that does not match, a missing `.sha256`, a download that
     breaks off, an HTTP error other than 404, an archive that names another
     tag, an image that is not `X.Y.Z` (its tag is removed again). It never
     falls back to a build, and nothing has been switched yet, so the stack
     keeps running as it was. `SATOM_AGENT_IMAGE=build` is the way to build
     on purpose.
   * **A local build** only when the release publishes no image (HTTP 404 —
     any release before 2.4.0), when the engine is not `x86_64` (the published
     image is `linux/amd64`), or with `SATOM_AGENT_IMAGE=build`: `docker build`
     in a throwaway `docker:27-cli` helper container (pulled if absent), with
     the socket and `/opt/satom-docker` bind-mounted at the same path. **This
     helper alone runs with `NetworkMode: bridge`:** BuildKit fetches the
     registry pull token from the client, and with no network the first `FROM`
     fails (measured). Up to 60 minutes; the first build takes 5–15. The step
     reads **`image: built here (<reason>)`**.
   An agent started from 2.4.1 or earlier always builds, as those releases
   did: an update does not refresh the agent (below), so the published image
   is used from the first update after `satom-docker up -d` has brought the
   agent itself to a release that has this step.
3. **Switch.** Repoint `current` to the new tree, link its
   `deploy/docker/.env` to `satom.env`, set `SATOM_IMAGE=satom:X.Y.Z` in
   `satom.env`, then, in a helper, run `docker compose config --services` and
   `docker compose up -d --remove-orphans` with **every service except
   `agent`**. The compose files are chosen exactly as the installer's wrapper
   chooses them. These compose helpers run with `NetworkMode: none`.
4. **Reload the proxy.** `proxy` runs a stock image, so the switch does not
   recreate it, and it would keep serving the old vhost while `tls-init` has
   just rewritten it. The agent runs `nginx -t` in every proxy container and,
   if all pass, sends SIGHUP to each nginx master: a graceful reload that also
   re-resolves the upstream (§5.5). A failed `nginx -t` fails the update.
5. **Verify.** Wait up to 420 s for `web` to be running and healthy.
6. **Roll back** if step 3, 4 or 5 fails: repoint `current` to the previous tree,
   restore `satom.env` exactly as it was, and recreate the stack (again
   without `agent`) on the previous image. The request then fails with "the
   update did not come up healthy; rolled back", and the rollback is a step
   of its own in the log. The rollback restores files and images, **not the
   database**.

No backup is taken first. **The agent never recreates itself**: it keeps
running the version it started with until an operator runs `satom-docker up
-d` (or the installer's update). An agent that replaced itself mid-request
would lose the status of the very request it was reporting, and a broken new
agent would take the console's only way back with it. The heartbeat reports
both versions, so the drift is visible (§7.7).

**`ctr-cert`.** The agent re-checks the PEMs, writes them to a private
temporary directory in its `tmpfs` `/tmp`, runs `tls-bootstrap.sh import-cert
--pki /opt/satom/pki --cert … --key … [--chain …]` (the §7.3.3 command, which
refuses a pair that does not match), and deletes the temporary files. It
then **reloads `proxy`, it never restarts it**: `nginx -t` in every proxy
container, then SIGHUP to the nginx master, a graceful reload in which open
connections survive. The reason was measured end to end: the operator's own
HTTP request travels through that proxy and is waiting for this answer, so a
restart cut it and the console reported a failure for an import that had
worked. (A host install does `systemctl reload nginx` for the same reason.)
If `nginx -t` fails, the previous `server.crt`, `server.key` and `meta.json`
are put back, nothing is reloaded, and the request fails with "the proxy
rejected the new certificate; nothing changed". A stack with no `proxy`
container is refused before anything is written. The web side validates the
pair first and waits up to 90 s for the agent's verdict.

**The heartbeat.** Every 15 s the agent rewrites
`/queue/status/agent.heartbeat` (seen by the web as
`data/update-status/agent.heartbeat`). It is not named `*.json` on purpose: the
UI lists `update-status/*.json` as request history. It is also rewritten
**after every successful request, before the request is reported done**: the
console answers from the heartbeat, so the page the operator lands on — and the
certificate details a successful import returns — describe the state after the
action, not a beat taken up to 15 s before it. It contains:

| Field | Meaning |
|---|---|
| `ts`, `at` | time of the beat (epoch seconds, UTC ISO) |
| `busy` | id of the request being executed, or empty |
| `agent_version` | the `VERSION` of the image the agent runs |
| `layout` | `installer` (with `SATOM_AGENT_HOME`) or `manual` |
| `project`, `policy` | `satom`, and the service table above |
| `containers` | per container of the project: service, name, state, status, image, health |
| `engine_ok`, `engine_error` | whether the engine API answered |
| `stack_image` | the image of the `web` container |
| `configured_image` | `SATOM_IMAGE` from `satom.env` (installer layout only) |
| `versions` | each `X.Y.Z` with a local `satom:` image and/or a tree under `releases/` |
| `cert` | the **public** certificate `proxy` serves (`public/server.crt`) and its `source` from `meta.json`. A file that contains key material is not forwarded; the entry then carries an `error`. |

### 7.7 Operating the agent

| What | How |
|---|---|
| Is it live? | **System → Container operations**, *Operations agent* card: **live** with the heartbeat age, **not answering** with the problem, or **not enabled** |
| Container state | `satom-docker ps agent` (manual: `dc ps agent`, or `./satom-docker.sh ps` for the whole stack) — healthy while the heartbeat is younger than 60 s |
| What it did | `satom-docker logs agent` (manual: `./satom-docker.sh logs agent`). Lines read `[satom-agent] <UTC time> <message>`; each step of a request is `<id> ok  <step>: <detail>` or `<id> ERR <step>: <detail>`. The same steps are in the request's status row and in the *Recent agent requests* card. |
| The heartbeat itself | `satom-docker exec -T web cat /opt/satom/data/update-status/agent.heartbeat` — rewritten every 15 s and after every successful request, before it is reported done (§7.6), so what the page shows after an action is the state after it |
| Restart it | `satom-docker restart agent`, on the host. The console cannot: `agent` is not in the service table. |
| Bring it to the stack's version | `satom-docker up -d` after a console update (the page shows **agent and stack differ** until then) |

**What a silent agent looks like.** After 60 s without a heartbeat the page
shows **not answering** and the problem, the *Services of this stack* card is
empty and shows the reason instead, the update and certificate controls are
disabled, and every action is refused (HTTP 409) with nothing queued. The same
reason appears on the Settings → Services card and in the runtime summary.
The container's own healthcheck turns `unhealthy` after three failed checks,
30 s apart. A request queued just before the agent went
silent is executed if the agent picks it up within 600 s, and refused as
expired after that.

An agent that is alive but cannot reach the engine keeps writing heartbeats
with `engine_ok: false` and no containers: the page says **live**, and every
service of the table shows **no container**. Read `engine_error` in the
heartbeat, or the agent's log.

**Disabling it.**

* **Installer layout.** In `/opt/satom-docker/satom.env` set
  `SATOM_SETUP_AGENT=no`. The wrapper then layers neither `compose.agent.yaml`
  nor `compose.setup-agent.yaml`; the latter can stay on disk. Then:

  ```bash
  satom-docker config -q && satom-docker up -d --remove-orphans
  ```

  `--remove-orphans` removes the `agent` container, which is no longer part of
  the project; `web`, `scheduler` and `cron` are recreated without
  `SATOM_AGENT` and without the queue volumes.
* **Manual checkout.** Set `SATOM_SETUP_AGENT=no` in `.env`, then
  `./satom-docker.sh up --remove-orphans`.

The volumes `satom_satom-agent-requests` and `satom_satom-agent-status` and the
network `satom_satom-agent` are left behind; remove them with
`docker volume rm` / `docker network rm` if you want them gone. From then on
the capabilities are denied with the plain reasons of §7.2, and §7.3 applies.

### 7.8 Residual risk

What the design does not remove, stated so it can be weighed before enabling:

* **Whoever controls the agent is root on the host.** It holds the engine
  socket, exactly as `satom-updater.service` holds root on a host install. Its
  capability drop, read-only root and missing network do not limit what it can
  ask the engine to do. Its code comes from the SATOM image, which the app
  account cannot rewrite (§6.4).
* **A compromised web — or any console admin — can ask for anything on the
  list, and nothing else.** That is: restart any listed service, as often as
  it likes (an availability attack, not an escalation); stop `scheduler` or
  `cron`; switch the stack to any `X.Y.Z` tag of the public repository,
  **older ones included**; replace the certificate `proxy` serves with any
  matching pair it holds. It cannot name an image, command, path, compose
  argument or service outside the table.
* **A downgrade is a database question.** The agent will switch to an older
  release, and its rollback restores files and images, not the database. The
  code makes no promise that an older image runs against a database a newer
  version has already started on (§11.1). Back up before any switch.
* **Downloads are not signature-verified.** The release tree is fetched over
  HTTPS from `codeload.github.com` and checked for structure and for invalid
  network literals, not for authenticity — the same trust as the installer's
  own download. The published image is checked against the `.sha256` beside
  it on the same release: that proves the file arrived whole, not who made it.
  What the agent adds is that the loaded image must say it is `X.Y.Z` (labels
  and `/opt/satom/VERSION`) and may carry no other tag. A tree already under `releases/X.Y.Z` is used as it is, so
  whoever can write `/opt/satom-docker` chooses what a console update builds
  (they are root on the host already, §6.6). The build helper has network
  access (`bridge`), as any `docker build` that pulls its base images must;
  the Dockerfile it builds is the release's own.
* **Agent and stack drift.** An update never recreates the agent, so after a
  console update the agent runs the previous release until `satom-docker up
  -d`. Fixes to the agent itself arrive only then. The page shows the drift;
  it does not correct it.
* **Switching to a release without the agent** (anything before 2.3.0) is
  **refused** before anything is built or changed: this install's overlays
  define the agent and such a release cannot, so the switch would fail
  half-way. Go back to it with `satom-setup.sh --version <ver>` on the host
  (`tests/test_docker_agent.py`).

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
| `SATOM_PROXY_IP` | `172.28.0.10` | — | the proxy's fixed address; must lie inside the subnet |
| `TRUSTED_PROXIES` | `172.28.0.10` (base default and `env.example`) | prod: non-empty | comma-separated hops allowed to set `X-Forwarded-*`. It matches exact addresses and must contain `SATOM_PROXY_IP` first. Add any outer proxy after it (§9.6). Leaving it empty means "trust nothing". |
| `SATOM_NODE_ROLE` | `primary` | — | `standby` makes the wrapper(s) add `compose.standby.yaml` |
| `SATOM_PG_BIND` | `env.example`: `127.0.0.1:5432`; no compose default | prod: **always**, including the standby (which publishes nothing) | host address:port for the primary's PostgreSQL. Use an explicit address, never `0.0.0.0`. |
| `SATOM_REPL_USER` | `satom_repl` | — | replication role name |
| `SATOM_PRIMARY_HOST` | empty | standby | the primary's address, reachable from the standby |
| `SATOM_PRIMARY_PORT` | `5432` | — | |
| `SATOM_ENV` | not in `env.example`; means `dev` when unset | — | read by `satom-docker.sh` and the installer's wrapper only; `prod` adds `compose.prod.yaml` |
| `SATOM_HTTP_BIND` | — | **must be unset or empty** | retired; `satom-docker.sh` refuses to run while it is set |
| `SATOM_ADMIN_PASSWORD` | unset | — | first `admin` password (manual route; ignored on installer-managed nodes, §5.10) |
| `SATOM_SETUP_AGENT` | `no` (`env.example`) | — | `yes` makes `satom-docker.sh` and the installer's wrapper layer `compose.agent.yaml` last (§7.1). The installer writes it too (§8.6). |
| `SATOM_AGENT` | unset | — | **set by `compose.agent.yaml` on `web`, `scheduler` and `cron`; do not set it by hand.** The declaration half of delegation (§7.2): `docker` means "this stack runs the agent". Honoured only in the container runtime, and only together with a fresh heartbeat, so setting it without the agent delegates nothing — the capabilities simply report "not answering". |

`env.example` lists `SATOM_IMAGE` twice with the same value; the last
occurrence wins. `SATOM_IMAGE` is also the `agent`'s image. A console update
rewrites the `SATOM_IMAGE` line of `satom.env` (every occurrence becomes one
line with the new tag).

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
| `SATOM_AGENT_QUEUE` | `/queue` | `satom_agent.py` | **no**: the overlay does not pass it, so the default always applies (the queue volumes are mounted under `/queue`) |
| `SATOM_AGENT_IMAGE` | `release` | `satom_agent.py` | yes: `compose.agent.yaml` passes it from `satom.env`. `release` or `build` (§7.6 step 2); any other value refuses console updates. The agent reads it when it starts, so after changing it run `satom-docker up -d agent`. |

### 8.5 Set by the image (`Dockerfile`)

`SATOM_RUNTIME=container`, `FLASK_APP=wsgi.py`, `FLASK_ENV=production`,
`SATOM_ROLE=web`, `SATOM_ADMIN_PASSWORD_FILE=/opt/satom/instance/initial-admin-password`,
`PYTHONUNBUFFERED=1`, `PYTHONDONTWRITEBYTECODE=1`, and `PATH` with
`/opt/venv/bin` first.

### 8.6 Written only by the installer

`SATOM_ENV=prod` (every installer-managed node uses the production overlay),
`SATOM_SETUP_AGENT` (`yes` or `no`; also in `env.example` since 2.3.0),
`SATOM_EXT_DB_HOST`, `SATOM_EXT_DB_PORT`, `SATOM_EXT_DB_NAME`,
`SATOM_EXT_DB_USER`, `SATOM_EXT_DB_URI`. The installer writes values containing
spaces or URI characters in single quotes.

`SATOM_AGENT_HOME=/opt/satom-docker` is not in `satom.env`: the installer puts
it in `compose.setup-agent.yaml` (§5.10). It tells the agent
where the installer layout lives; without it the agent runs in the manual
layout and refuses updates (§7.6). Do not set it on a manual checkout.
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
nginx keeps what it loaded at its last start or reload. **Restart or reload
`proxy` after any certificate change you make by hand** (`restart proxy`, or
`kill -s HUP proxy` for a graceful reload). An imported certificate is never
renewed by the stack: replace it with §7.3.3 (or, with the agent, from
System → Container operations, which reloads `proxy` gracefully for you and
puts the previous certificate back if nginx rejects the new one) before it
expires.

### 9.5 ACME http-01

`:80` serves `/.well-known/acme-challenge/` from the `satom-acme` volume, and
answers everything else with a 301. That listener exists because http-01 is
always validated over plain `:80`.

**2.3.0 provides no ACME client for the stack's own certificate.** In detail:

* the image does not install one (no ACME client in the `Dockerfile`);
* only `tls-init` can write the `satom-acme` volume, and no app service
  mounts it (neither does the agent);
* the Certificate Manager's activation step for the node certificate is
  `cert_activation`, which is denied unless the operations agent is enabled
  and answering (§7.2).

To use ACME you need an external client that can write challenge files into
the `satom_satom-acme` volume (or that uses DNS-01 elsewhere). Import the
certificate it obtains with §7.3.3, or from System → Container operations with
the agent. Neither SATOM nor its tests cover such a client.

### 9.6 A further proxy in front

An edge or DMZ load balancer in front of the stack should connect to `:443`.
It must pass `Host` **including the port** and declare the scheme, as
described in [`docker.md`](docker.md) "Putting a further proxy in front".
Then append the outer hop to `TRUSTED_PROXIES`, **after** the stack's own
proxy:

```ini
TRUSTED_PROXIES=172.28.0.10,198.51.100.4
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
SATOM_IMAGE=satom:2.3.0
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
> exist here. The UI's promote action refuses in a container, and the
> operations agent does not perform it either (§7.2). The procedure below is
> derived from the stack's code and standard PostgreSQL. It is not covered by
> tests.

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
| **Docker, installer-managed** | re-run `satom-setup.sh`; or, with the operations agent, **System → Container operations → Update** (§7.6) |
| **Docker, manual** | new image tag + recreate (the agent, if enabled, refuses updates on this layout) |

Installer-managed:

```bash
curl -fsSLO https://github.com/visionebc/SATOM/releases/download/v<new>/satom-setup.sh
sudo bash satom-setup.sh --yes          # on an existing Docker install, the mode defaults to docker and the answer to update
```

The update path downloads the new version's source and its published image
(building it only when the release publishes none, §2.4 step 5), repoints
`/opt/satom-docker/current`, sets `SATOM_IMAGE=satom:<new>`, rewrites the
wrapper, runs `satom-docker up -d --remove-orphans`, **reloads the proxy**
(`satom-docker kill -s HUP proxy`: a graceful reload, so the vhost `tls-init`
has just rewritten is actually served; a failure only warns and suggests
`satom-docker restart proxy`), and waits for `/healthz`. It also asks whether to enable the operations agent when the install runs
without it and the new release ships it (§7.1). It does **not**:

* take a backup first;
* rewrite `compose.setup.yaml`, except when you enable the agent (it is then
  regenerated, with `compose.setup-agent.yaml` beside it);
* offer a rollback.

**From the console, with the agent** (installer layout only): type the version
and `UPDATE` under System → Container operations → Update. The agent
downloads the release tree if it is not under `releases/` yet, gets
`satom:<new>` the way the installer does — the release's published image,
verified against its `.sha256` and proven to be `<new>` before anything is
switched, built only when the release publishes none —, recreates every
service except itself, reloads the proxy
(`nginx -t`, then SIGHUP), waits up to 420 s for `web` to be healthy, and rolls
back the tree, the image and `satom.env` if it
is not (§7.6). It takes no backup either, and its rollback does not touch the
database. Afterwards run `satom-docker up -d` on the host to bring the agent
itself to the new version.

Earlier `releases/<ver>` trees and `satom:<ver>` images are left in place. The
code makes no promise that an older image runs against a database a newer
version has already started on.

Manual:

```bash
cd /opt/satom-src && curl -fsSL https://codeload.github.com/visionebc/SATOM/tar.gz/refs/tags/v<new> | tar -xz --strip-components=1
cd deploy/docker && ./satom-docker.sh build satom:<new>      # or load the published image (§3.1)
sed -i 's/^SATOM_IMAGE=.*/SATOM_IMAGE=satom:<new>/' .env      # both SATOM_IMAGE lines
./satom-docker.sh up
dc kill -s HUP proxy          # load the vhost tls-init has just rewritten (§5.5); satom-docker.sh has no reload subcommand
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
     satom:2.3.0 -czf /out/satom-data-$(date +%F).tar.gz -C /d .
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
  satom:2.3.0 -xzf /in/satom-data-DATE.tar.gz -C /d
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
satom-docker logs agent                 # agent overlay: [satom-agent] lines, one per request step
./satom-docker.sh logs web              # manual: always --tail=200 -f
```

Production rotates the app, database, Redis and metrics logs at 20 MB × 5
files. The `agent` rotates at 10 MB × 3 in every shape. `proxy` and `tls-init`
use the engine's default logging driver settings.
`/var/log/satom` inside the app containers is not on a volume.

### 11.5 Health checks — what each proves

| Check | Proves | Does not prove |
|---|---|---|
| `satom-docker ps` → `web` healthy | gunicorn answers `/healthz` on `:8000` inside the container | that login works (see §9.1) or that the proxy is reachable |
| `proxy` healthy | `nginx -t` accepts the configuration | that the upstream is up or the certificate is valid for your name |
| `postgres` healthy | `pg_isready` for the app role and database | replication state |
| `curl -k https://127.0.0.1/healthz` | the full proxy → web path (the installer uses this, with its port) | the certificate's validity |
| `satom-docker exec -T web /opt/satom/deploy/docker/node-role.sh` | `f` primary / `t` standby / empty = database unreachable | |
| the runtime summary (§7.2) | which capabilities are denied or delegated, and whether the agent is declared and live | that the agent can reach the engine (read `engine_ok` in the heartbeat, §7.7) |
| `satom-docker ps agent` → healthy (*agent overlay*) | the heartbeat is younger than 60 s | that the last request succeeded |

`./satom-docker.sh health` runs `ps`, the node role, `/healthz` through the
proxy (`https://127.0.0.1:<port>/healthz` with `-k`, the port taken from
`SATOM_HTTPS_BIND`) and the runtime summary. The installer's `satom-docker`
wrapper has no `health` subcommand: run the checks individually there.

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

`satom-setup.sh` Docker mode cannot run offline. Neither can a console
update through the agent unless `releases/X.Y.Z` already holds the tree and the
engine already has `satom:X.Y.Z` (load the published image by hand, §3.1) and
`docker:27-cli`. The manual route can be
used offline if you bring three things:

* the release source tree, which provides the compose files and the scripts
  that are bind-mounted;
* the SATOM image — from 2.4.0 on, the release's published
  `satom-image-<ver>-amd64.tar.gz` and its `.sha256` (§3.1), downloaded on any connected
  machine. Building it yourself needs Internet access (`apt-get`, `pip`);
* the four stock images.

The published image needs no conversion: copy the two files, run
`sha256sum -c` next to them on the target, then `gunzip -c … | docker load`
(§3.1). For an image you built yourself, and for the stock images, on the
connected node:

```bash
./satom-docker.sh build satom:2.9.0
./satom-docker.sh export satom:2.9.0 /tmp/satom-2.9.0.tar.gz          # also writes /tmp/satom-2.9.0.tar.gz.sha256
docker pull postgres:15-bookworm; docker pull redis:7-alpine
docker pull victoriametrics/victoria-metrics:v1.148.0; docker pull nginx:1.27-alpine
docker save postgres:15-bookworm redis:7-alpine victoriametrics/victoria-metrics:v1.148.0 nginx:1.27-alpine \
  | gzip -9 > /tmp/satom-base-images.tar.gz
```

On the target, put the tarball and its `.sha256` **at the same path** as on
the build node, then:

```bash
./satom-docker.sh import /tmp/satom-2.9.0.tar.gz
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
| Long request ends with 504 after about 2 minutes | `proxy_read_timeout 120s` in the vhost, although gunicorn allows 600 s | — (the generated vhost is not configurable in 2.3.0) |
| `up` pulls or fails to pull `satom:<tag>` | the image is not present locally | build or import it first (§3.3) |
| The console answers **502** after `up -d` or an update, on a release before 2.3.0 | the proxy resolved `web` once at start; the recreated `web` has a new address and the proxy still connects to the old one (§5.5) | `satom-docker restart proxy`. Fixed in 2.3.0: the vhost re-resolves `web` per request, and updates reload the proxy. |
| `satom-docker.sh health` prints `SATOM_HTTP_BIND: unbound variable` | a script from a release before 2.3.0 | use the 2.3.0 script, or run the checks individually (§11.5) |
| Container operations says **not answering**; actions are refused with "The operations agent is enabled but not answering (…)" | no heartbeat for more than 60 s: the `agent` container is stopped, crash-looping, or cannot write its status volume; or the clocks disagree ("heartbeat timestamp is … in the future") (§7.2) | `satom-docker ps agent`, `satom-docker logs agent`; `satom-docker up -d` recreates it. Exit code 78 at start means the socket is not mounted. Requests queued meanwhile are refused as expired after 600 s, never executed late. |
| Container operations says **live** but every service shows **no container** | the agent cannot reach the engine (`engine_ok: false` in the heartbeat) | read `engine_error` in the heartbeat (§7.7) and the agent's log |
| Update refused: "updating from the console needs the installer layout (/opt/satom-docker) …" | a manual checkout: the agent has no `SATOM_AGENT_HOME` | update by hand (§7.3.1), or move the node to the installer |
| Update request **failed** with "the update did not come up healthy; rolled back" | the recreate failed, or `web` was not healthy within 420 s on the new image | read the steps in *Recent agent requests* (the build and recreate output is in the step details) and `satom-docker logs web`. The stack is back on the previous tree and image; the database was **not** rolled back (§7.6). |
| Update request **failed** with "… does NOT match its .sha256", "… but no .sha256", "… is labelled version …", "… contains /opt/satom/VERSION …" or "download of … failed" | the published image could not be downloaded or verified; the agent does not fall back to a build | nothing was switched: the stack still runs the previous image. Retry later for a network error; for a mismatch, check the release assets on GitHub. To build instead, set `SATOM_AGENT_IMAGE=build` in `satom.env`, run `satom-docker up -d agent`, and request the update again (§7.6 step 2). |
| Update refused: "release v… carries invalid networks" or "does not ship the Docker stack" | the downloaded tree failed the agent's checks (§7.6) | pick another release; do not place a hand-edited tree under `releases/` to get past it |
| The *Operations agent* card shows **agent and stack differ** | an update from the console never recreates the agent (§7.6) | `satom-docker up -d` on the host |

---

## 13. Hardening recommendations (not applied by the stack)

> **Recommendations.** None of the following is configured for the base
> services in 2.3.0 (the optional `agent` has its own confinement, §6.2). They have
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
13. **Leave the operations agent off where the console does not need it.** It
    adds a root-equivalent container (§7.8). Where you enable it, restrict the
    `user_manage` permission, which is what the Container operations page
    requires, to the people who may restart, update and re-certify the node.

---

## 14. Known defects and gaps in 2.3.0

Found in the code while writing this page. Each one is also referenced where
it matters above. Two items of the 2.1.2 list are fixed in 2.3.0 and no longer
appear: `satom-docker.sh health` now checks `/healthz` through the proxy, and
the promote action is gated in a container (§7.2).

**Fixed in 2.4.1 — the 2.4.0 source tree does not start.** In the public
source of 2.4.0 (and of the 2.x releases before it) the publication step
rewrote the proxy's fixed address in `compose.yaml`, `env.example` and
`satom-docker.sh` to `203.0.113.10` while leaving `SATOM_NETWORK_SUBNET` at
`172.28.0.0/16`, so `docker compose up` stopped with *"no configured subnet
contains IP address 203.0.113.10"*. The published image was not affected, and
neither was a native install. Install 2.4.1 or later; on an existing 2.4.0
checkout, set `SATOM_PROXY_IP=172.28.0.10` and `TRUSTED_PROXIES=172.28.0.10`
in `.env`.

| Item | Detail |
|---|---|
| Redirect ignores a custom HTTPS port | `proxy-init.sh` always passes `--port 443` (§9.7). |
| Standby tunables not wired | `SATOM_BASEBACKUP_WAIT_SECONDS` and `SATOM_REPL_SLOT` never reach `postgres` (§8.4). |
| Production does not reject `:local` | `compose.prod.yaml` requires `SATOM_IMAGE` to be set, and `env.example` sets it to `satom:local` (§8.3). |
| `env.example` overstates a check | it says `satom-docker.sh` verifies that `SATOM_PROXY_IP` is inside `SATOM_NETWORK_SUBNET`; it does not (§3.4). |
| The first admin password persists in container metadata | §6.5, §13 item 9. |
| No `satom-data` replication, no certificate renewal job, no ACME client | §10.9, §9.4, §9.5. |
| A console update takes no backup, and its rollback does not restore the database | §7.6, §7.8. |
| An update never refreshes the agent | by design; the drift is shown, not corrected (§7.8). |

---

## 15. Source files

Everything above was taken from these files at release 2.3.0:

* `deploy/docker/compose.yaml`, `compose.prod.yaml`, `compose.standby.yaml`,
  `compose.agent.yaml`, `env.example`
* `deploy/docker/entrypoint.sh`, `cron-runner.sh`, `node-role.sh`,
  `pg-standby-entrypoint.sh`, `proxy-init.sh`, `satom-docker.sh`,
  `satom_agent.py`, `initdb.d/10-replication.sh`
* `Dockerfile`, `.dockerignore`
* `app/runtime.py`, and the enforcement points `app/services/self_update.py`,
  `service_control.py`, `cert_service.py`, `system_health.py`, `cluster.py`,
  `app/views/self_update.py`, `app/views/settings.py` (the Services card), and
  `_seed_admin()` in `app/__init__.py`
* the web half of the agent: `app/services/container_ops.py`,
  `app/views/container_ops.py`, `app/templates/container_ops/index.html`
* `deploy/tls-bootstrap.sh`
* `installers/satom-setup.sh`
* `tests/test_container_runtime.py`, `tests/test_docker_agent.py`,
  `tests/test_container_ops.py`, `tests/test_tls_by_default.py`,
  `tests/test_guided_installer.py`: the invariants they assert are the ones
  this page relies on as guaranteed

Related pages: [`docker.md`](docker.md) (design and rationale),
[`privilege-model.md`](privilege-model.md) (the host model this page mirrors),
[`INSTALL.md`](INSTALL.md) (host installs and the guided installer),
[`sizing.md`](sizing.md).
