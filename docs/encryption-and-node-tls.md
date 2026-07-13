# Encryption in transit, node TLS & the service certificate

_Added 2026-07-13. Covers: the service's own TLS cert (import / issue / renew),
node-to-node encryption (HTTPS peer probes + identity key), enforced Postgres
replication SSL, and the Monitoring "Encryption in transit" cards._

## TL;DR

OFortMAut does **not** terminate its own public TLS today — the edge nginx
(`192.0.2.40`) does, with the fleet wildcard. This work gives the app its **own**
node-level TLS on `:8443` and makes every inter-node channel encrypted and
verifiable, surfaced honestly per-channel in Monitoring.

| Channel | State | Mechanism |
|---|---|---|
| DB replication (primary ⇄ standby) | **encrypted + enforced + mutual-CA** | Postgres `hostssl` + `clientcert=verify-ca`, TLS 1.3 |
| Inter-node app probes (`/healthz*`) | **encrypted + authenticated** | HTTPS `:8443` (node cert) + shared identity key |
| Data sync (`fm-ha-datasync`) | encrypted | rsync over SSH |
| Config SoT publish (Gitea) | ⚠️ **plaintext** | `http://192.0.2.53:3000` — see "Known gaps" |

## PKI layout (node-local, NEVER in git — see `.gitignore`)

`/opt/fortinet-manager/pki/` on each node:

- `internal-ca/` — the internal CA (`ca.crt` + `ca.key`). **Only the primary holds
  `ca.key`** — it is the sole issuer. The standby has `ca.crt` only.
- `node/` — the node's inter-node leaf (`serverAuth`+`clientAuth`, signed by the
  internal CA). Reused as the Postgres server/client cert for replication mTLS.
- `public/` — the cert nginx serves on `:8443` (`server.crt` [+chain] + `server.key`)
  plus `meta.json` (`source`: `bootstrap` | `imported` | `issued`).

`pki/` is outside `data/`, so `fm-ha-datasync` never replicates it (each node must
serve its own hostname's cert).

## The service certificate — Settings → **Node TLS** (admin)

`app/services/cert_service.py`; endpoints in `app/views/settings.py`
(`/settings/node-cert/{state,import,issue,renew}`), UI tab in
`settings/index.html`.

- **Import** a PEM cert (+ key, + optional chain): key/cert match is validated,
  nginx is `-t`-tested and **rolled back automatically** if the new cert is bad.
  Import is *import-only* — expiry is tracked and alerted, but not auto-renewed
  (we didn't issue it).
- **Issue from the internal CA** (primary only — it holds `ca.key`): mints a leaf
  for the node hostname, installs it, `source=issued`.
- **Renew**: CA-issued certs auto-renew via `fm-cert-renew.timer` →
  `flask cert-renew` → `cert_service.renew_if_needed()` (nightly 03:30, no-op
  until within 30 days of expiry, no-op for imported/bootstrap). The standby
  can't self-issue; give it a cert by **import** (or mint on the primary and
  import on the standby — done for `fortinet-manager-2`).

The web process runs as **root** on each node (verified in the unit), so it writes
`pki/public/` and reloads nginx directly — no privileged-runner hop for certs.
On a **standby**, the redundant `app_settings` write is best-effort (read-only
replica); `meta.json` is the source of record.

## Node-to-node encryption

### App probes → HTTPS + identity key
`app/services/node_security.py`. `peer_get()` prefers HTTPS `:8443` (node cert,
cert verification off — confidentiality from TLS, **authenticity from the identity
key**) and falls back to `:8000` only if TLS is unreachable. `infra_health` and
`cluster` peer probes both use it. A shared **identity key** (`secrets.token_urlsafe`,
Fernet-encrypted in `app_settings` `security.node_identity_key`, replicated via
Postgres since both nodes share `FERNET_KEY`) is sent as `X-FM-Node-Key`; `/healthz`
echoes `peer_authenticated`. nftables on 248 opens `:8443` from `192.0.2.249`.

### Postgres replication → enforced + mutual CA
- Primary serves the **internal-CA leaf** as its Postgres server cert
  (`ssl_cert_file`/`ssl_key_file` → `/etc/postgresql/15/main/fmssl/server.*`,
  `ssl_ca_file` → the internal CA).
- `pg_hba`: `hostssl replication replicator 192.0.2.249/32 ... clientcert=verify-ca`
  (mutual — the standby must present a CA-signed client cert), and
  `hostssl fortinet_mgr fortinet 192.0.2.249/32` (encryption enforced).
- Standby `primary_conninfo`: `sslmode=verify-ca` + `sslrootcert`/`sslcert`/`sslkey`
  (its own leaf, `/etc/postgresql/15/main/fmssl/client.*`).
- Verified: `sslmode=disable` → refused (`no encryption`); SSL-without-client-cert
  → refused. Live: TLS 1.3 / `TLS_AES_256_GCM_SHA384`.
- Operator tunes the floor from the UI (min TLS protocol + cipher list):
  `app/services/pg_ssl.py` → `ALTER SYSTEM` as `postgres` + reload. Policy stored
  in `app_settings` `security.pg_ssl` (`enforced`, `sslmode`, `mutual_tls`,
  `min_protocol`, `ciphers`).

**Backups before the change** (rollback): `/root/pg_hba.conf.pre-ssl-*` on 248,
`/root/postgresql.auto.conf.pre-ssl-*` on 249.

## Monitoring cards
`app/services/encryption_health.py` + `app/templates/_encryption_health.html`
(included by `monitoring/index.html`), endpoint `/monitoring/encryption`. Every
"encrypted" badge is backed by a **live probe** (`pg_stat_ssl`, a real TLS
handshake to `:8443`, git remote scheme) — never assumed. Shows, per channel:
encrypted? · protocol+cipher · how · enforced/authenticated, plus a node-cert
tile (subject/issuer/expiry/source).

## Known gaps / next steps
- **Gitea remote is plain HTTP** (`http://192.0.2.53:3000`) — the config-SoT push is
  unencrypted. Switch `origin` to `https://git.example.net/...` once the cert is
  trusted by the nodes. The card flags this red on purpose.
- **Cutover to option B** (gunicorn → `127.0.0.1`, nginx sole front on `:8443`,
  then move DNS to the node) is NOT done — `:8000` still serves the edge. Before
  moving DNS, open `:8443` to the client source range in nftables and import a
  **publicly-trusted** cert (the internal-CA/bootstrap cert triggers browser
  warnings).
