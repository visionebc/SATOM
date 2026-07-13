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
| Config SoT publish (Gitea) | **encrypted** | `git push` over HTTPS to `https://git.example.net` (edge wildcard cert) |

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
- ~~**Gitea remote is plain HTTP**~~ — RESOLVED 2026-07-13. `origin` on both nodes
  switched from `http://192.0.2.53:3000` to `https://git.example.net/ofortmaut-dev/ofortmaut.git`
  (embedded access token preserved; edge presents the trusted fleet wildcard, `ssl_verify=0`).
  Verified: `ls-remote`, `fetch`, and dry-run `push` all authenticate over TLS on 248 + 249;
  the encryption card now reports this channel encrypted. Rollback pointer saved at
  `/root/ofortmaut-origin.http.rollback` on each node.
- **Cutover to option B** — DONE 2026-07-13 (public `:443` path live; final gunicorn
  lockdown intentionally deferred). Each node now serves the app directly on **`:443`**
  via nginx with the **trusted fleet wildcard** `*.example.net` (copied from the edge
  `/etc/nginx/ssl/visionebc-wildcard.{crt,key}` into `pki/public/`, `source=imported`,
  valid to 2026-09-02 — zero browser warning). `:8443` (peer probes) and `:80`→301
  are also served from the same vhost (`fm-tls.conf`). nftables on 248 opens `:443`+`:80`
  from `192.0.2.0/24`; 249's input chain is `policy accept`. DNS
  `fortinet-manager{,-2}.example.net` resolves to `192.0.2.248/.249`; Power Panel DNS
  entries 269/275 reconciled to match (were stale at `.40`). Pre-change backups per node:
  `/root/fm-pub-server.{crt,key}.pre-b-cutover`, `/root/fm-tls.conf.pre-b-cutover`,
  `/root/fm-pub-meta.json.pre-b-cutover`.
  STILL OPEN (deliberate): (a) gunicorn stays on `0.0.0.0:8000` so the **edge remains a
  rollback** through the validation window (feedback_migration_policy) — bind to
  `127.0.0.1` only after the `:443` path is user-confirmed; (b) the wildcard is **not
  auto-renewable from the node** (it renews on the edge ~every 90d) — re-copy on renewal
  or wire a node-side sync. Internal-CA issue/auto-renew still exists for a self-managed
  cert if the fleet wildcard is ever not desired.
