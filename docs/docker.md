# Running SATOM in containers

SATOM ships three installation shapes. This page covers the third.

| shape | what it is | where it is documented |
|---|---|---|
| full install | the installer provisions PostgreSQL, Redis, nginx, the metrics store and fourteen systemd units on a host it owns | [INSTALL.md](INSTALL.md) |
| package-only | the application on a host that already provides those services | [INSTALL.md](INSTALL.md) |
| **container** | the application as an image, with its dependencies as sibling containers | **this page** |

## Read this before you choose the container shape

**SATOM is an appliance that administers its own host.** A container controls
none of that host, so the container shape *renounces* four capabilities rather
than pretending to have them:

| capability | why it is gone | what to do instead |
|---|---|---|
| **Software Update & HA** (in-place self-update) | the updater installs unit files and restarts services as root | deploy a new image tag and recreate the stack |
| **Service control** (start/stop/restart of node units) | there is no systemd here | `docker compose restart <service>` |
| **Certificate activation** | it writes the node PKI and reloads the *host* nginx, which is a sibling container here | the stack already serves TLS; replace the certificate with `tls-bootstrap.sh import-cert` and restart `proxy` |
| **systemd unit health** | there are no units to read | container health comes from the container engine |

These are enforced in code (`app/runtime.py`), not by documentation. Each one
refuses with a message naming the alternative. Everything else — device
management, probes and monitors, the metrics store, backups and restore, the
SoT, reports, the CLI, RBAC and SSO — behaves identically to a host install.

**If you need in-place self-update, use a host install.** TLS is *not* on
that list any more: since 1.20.1 the container stack terminates it itself.

### The runtime is declared, never detected

The image sets `SATOM_RUNTIME=container`. Nothing infers it, and that is
deliberate: `system_health.is_container()` already returns **true on the
production HA nodes**, because they are LXC containers. Keying these
capabilities off a `/proc` probe would disable self-update on the two nodes
that most need it.

Only the exact value `container` selects the container runtime. A typo means
`host`, so a stray environment variable can never silently strip an appliance
of its updater.

## What the stack contains

```
web                gunicorn on :8000            (host: satom.service)
scheduler          fires scheduled actions       (host: satom-scheduler.service)
cron               alerts + sentinel responder   (host: the two systemd timers)
postgres           PostgreSQL 15
redis              rate-limit counters
victoria-metrics   the metrics store, v1.148.0 — same build as a host install
```

`web`, `scheduler` and `cron` are the **same image**, selected by `SATOM_ROLE`.
Three images would let the scheduler run code the web worker does not have, and
that difference is invisible until a scheduled action behaves differently from
the same action fired by hand.

Two invariants are worth stating because nothing fails when they break:

* **VictoriaMetrics publishes no port.** It has no authentication; on a host
  install the `127.0.0.1` bind is the only thing protecting the fleet's
  metrics. Here that job is done by the *absence* of a `ports:` entry.
* **`scheduler` and `cron` are primary-only.** They probe
  `pg_is_in_recovery()` in a loop and idle on a standby, so promoting the
  database starts them with no external coordination — and two nodes never both
  fire the same action. A double firmware-upgrade action means a double flash.

## TLS ships with the stack

**There is nothing to arrange before the first login.** `docker compose up`
brings up a `proxy` service that terminates TLS on `:443` with a certificate
the stack issues for itself, and redirects `:80` to it. The application
container publishes no port at all.

The certificate is **self-signed by a per-node internal CA**, so a browser
warns on the first visit. That is the intended day-zero state: the node is
usable immediately, and the operator replaces the certificate on their own
schedule.

### Why it is not optional

The image runs with `FLASK_ENV=production`, which marks session cookies
`Secure`. A browser withholds a `Secure` cookie from a plain-HTTP origin, so a
stack served over HTTP is one in which **no password works**: the login POST
arrives with no session, there is no CSRF token to match, and the request is
bounced back to the login form. Nothing about it looks broken — the container
is healthy, `/healthz` answers 200, the login page renders — and the account is
never locked out either, because the password is never compared. This is not
hypothetical: it is how the first development node shipped, on 2026-08-31, and
it is why the terminator is now part of the stack rather than a prerequisite
the operator has to remember.

If the misconfiguration does reach a running node anyway — someone publishes
the app container directly, or strips the proxy — SATOM says so out loud: a
CSRF rejection on a plain-HTTP request while `SESSION_COOKIE_SECURE` is on is
reported as a deployment problem, in the flash message, in the JSON error and
in the log, instead of as an expired session.

Do **not** answer any of this by setting `SESSION_COOKIE_SECURE=False`.
Without TLS the cookie already travels in clear text, so the flag protects
nothing extra — but turning it off normalises an insecure configuration inside
an image that also runs in production.

### Name the node before you build

The certificate's SAN must cover the name operators actually type. Set it in
`.env`:

```ini
SATOM_SERVED_NAMES=satom.example.com satom-a1.example.com
```

Left empty it falls back to the container's hostname, which is almost never
right — and a SAN that does not cover the name in the address bar produces a
browser warning on a certificate the install just reported as issued, with no
remedy but to reissue.

### Replacing the certificate

The install ships a working certificate; you replace it whenever you like.

```bash
docker compose exec -u 0 tls-init sh -c '
  /opt/satom/deploy/tls-bootstrap.sh import-cert \
    --cert /path/fullchain.pem --key /path/privkey.pem'
docker compose restart proxy
```

`import-cert` refuses a certificate and key that do not match — nginx would
accept the reload and fail on the first handshake, which reads as a network
fault rather than a configuration one. It then records `source: "imported"` in
`pki/public/meta.json`, and **`up` never reissues over an imported
certificate**: an operator's real certificate is not silently replaced by a
self-signed one at the next deploy.

The PKI lives in the `satom-pki` **volume**, not in the image, so changing the
image tag keeps the certificate.

### Putting a further proxy in front

A DMZ or edge load balancer in front of the stack talks HTTPS to `:443`
(certificate verification off, or trust the node's internal CA). Do **not**
point it at `:80` — that listener exists because ACME http-01 is always
validated over plain `:80`, and everything else on it is a 301.

Whatever the outer hop is, it must pass `Host` through **with its port** and
declare the client's scheme:

```nginx
proxy_set_header Host              $http_host;   # NOT $host
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
```

`$host` drops the port, and Flask-WTF's referer check compares scheme, host
*and* port — which is how login broke behind a non-standard-port NAT on
2026-08-04.

Then append the outer hop to `TRUSTED_PROXIES`, after the stack's own proxy:

```ini
TRUSTED_PROXIES=203.0.113.10,203.0.113.4
```

`TRUSTED_PROXIES` matches **exact addresses**, and container-to-container
traffic arrives from the proxy container's own address — not from the bridge
gateway, which is only the peer for traffic entering through a published port.
That is why the proxy has a static address (`SATOM_PROXY_IP`) inside a pinned
subnet (`SATOM_NETWORK_SUBNET`). Getting it wrong does not fail loudly: it
collapses rate limiting into one bucket for every user and records the proxy as
the actor in every audit entry. `satom-docker.sh` refuses to run if
`TRUSTED_PROXIES` does not contain `SATOM_PROXY_IP`.

> **`SATOM_HTTP_BIND` is retired.** It published gunicorn directly. The name is
> not reused for the redirect listener — an operator who set `127.0.0.1:8080`
> to keep the application off the network would otherwise have had the opposite
> of what their file said. `satom-docker.sh` stops with an explanation rather
> than ignoring it. Use `SATOM_HTTPS_BIND` and `SATOM_REDIRECT_BIND`.

## Development — a single node

```bash
git clone <repo> /opt/satom && cd /opt/satom/deploy/docker
cp env.example .env
./satom-docker.sh gen-secrets          # real SECRET_KEY / FERNET_KEY / passwords
./satom-docker.sh build satom:local
./satom-docker.sh up
./satom-docker.sh health
```

⚠ **`FERNET_KEY` cannot be rotated** once appliance passwords have been
encrypted with it. Changing it does not lock you out of SATOM — it makes every
stored device credential permanently undecryptable. Never copy a development
value into production or the reverse. The entrypoint refuses to start while
either secret still holds its `CHANGE_ME` placeholder.

## Production — a two-node cluster

The second node is a **standby**, not the other half of a load balancer: its
PostgreSQL is a streaming replica, its scheduler idles, and the reverse proxy
carries it as `backup`. It takes traffic when the primary stops answering
`/healthz`.

### Primary

```bash
cd /opt/satom-docker/deploy/docker
cp env.example .env && ./satom-docker.sh gen-secrets
# then edit .env:
#   SATOM_IMAGE=satom:2.0.0        immutable tag, never :local
#   SATOM_NODE_ROLE=primary
#   SATOM_PG_BIND=<this node's address>:5432
#   TRUSTED_PROXIES=<reverse proxy address>
SATOM_ENV=prod ./satom-docker.sh up
```

### Standby

Copy the **same** `.env` (`SECRET_KEY`, `FERNET_KEY`, `POSTGRES_PASSWORD` and
`SATOM_REPL_PASSWORD` must match the primary — a standby with a different
`FERNET_KEY` replicates ciphertext it cannot read), then change:

```
SATOM_NODE_ROLE=standby
SATOM_PRIMARY_HOST=<primary address>
```

```bash
SATOM_ENV=prod ./satom-docker.sh up
```

The standby takes a `pg_basebackup` from the primary on first boot, creates a
physical replication slot so the primary keeps WAL it has not consumed, and
then follows. Verify:

```bash
# on the primary
docker compose exec postgres psql -U satom -c "SELECT client_addr, state, sync_state FROM pg_stat_replication;"
# on the standby
docker compose exec postgres psql -U satom -c "SELECT pg_is_in_recovery();"   # t
```

> **Never apply the standby overlay to a primary.** It rebuilds `PGDATA` from
> the peer. `satom-docker.sh` refuses unless `SATOM_NODE_ROLE=standby`, and the
> standby's own entrypoint refuses to re-basebackup a *promoted* node — that
> node holds every write accepted since the failover, and rebuilding it would
> discard exactly those, quietly and successfully.

### After a failover

Promotion makes the standby a primary. Its container will then refuse to start
under the standby overlay, on purpose: recovering a cluster is an operator
decision. Either re-point the cluster at the promoted node and rebuild the old
primary as the new standby, or discard the promoted node's volume explicitly.

## Delivering an image to an air-gapped or DMZ node

A DMZ node cannot reach the LAN registry (measured 2026-08-31: the fleet
registry is unreachable from the DMZ subnet), and opening the firewall to buy
that convenience is a poor trade. Ship the image the same way the product
already ships installers — as an offline artifact:

```bash
# on the build node
./satom-docker.sh export satom:2.0.0 /tmp/satom-2.0.0.tar.gz
# copy the tarball AND its .sha256 to the target, then
./satom-docker.sh import /tmp/satom-2.0.0.tar.gz
```

`import` verifies the checksum **before** loading. A truncated transfer
otherwise surfaces as a layer error deep inside `docker load`, which reads like
a corrupt image rather than a short file.

## Backups

The image is disposable; `data/` is not. It carries the device vault, the
system-backup bundles, the SoT object store and `reports/`. It lives on the
`satom-data` volume, and it is what a backup must cover — together with the
database:

```bash
docker compose exec -T postgres pg_dump -U satom -Fc satom > satom-$(date +%F).dump
docker run --rm -v satom_satom-data:/d -v "$PWD":/out alpine \
    tar czf /out/satom-data-$(date +%F).tar.gz -C /d .
```

A `pg_dump` alone is **not** a backup: the SoT index lives in PostgreSQL while
its blobs live in `data/sot/objects/`, so restoring only the database leaves
rows pointing at nothing.

## Guards

`tests/test_container_runtime.py` asserts what nothing else would notice: that
the image declares its runtime, that the build context excludes `data/`, the
venv and `.env`, that the metrics store is unpublished, that its version equals
the host installs', that every app service actually receives the shared
environment, that production refuses a mutable image tag, and that the standby
overlay cannot be applied first.
