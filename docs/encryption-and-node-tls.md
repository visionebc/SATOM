# Encryption in transit, node TLS & the service certificate

_Added 2026-07-13. Covers: the service's own TLS cert (import / issue / renew),
node-to-node encryption (HTTPS peer probes + identity key), enforced Postgres
replication SSL, and the Monitoring "Encryption in transit" cards._

## TL;DR

Since the **2026-07-13 Option-B cutover**, each node terminates its **own**
public TLS directly on `:443` with the trusted fleet wildcard `*.example.net`
— `satom{,-2}.example.net` now resolve straight to the nodes
(`192.0.2.248` / `192.0.2.249`); the edge `192.0.2.40` stays only as rollback. The
same nginx vhost also serves `:8443` for node-to-node peer probes and `:80`→301.
Every inter-node channel is encrypted and verifiable, surfaced honestly
per-channel in Monitoring.

| Channel | State | Mechanism |
|---|---|---|
| DB replication (primary ⇄ standby) | **encrypted + enforced + mutual-CA** | Postgres `hostssl` + `clientcert=verify-ca`, TLS 1.3 |
| Inter-node app probes (`/healthz*`) | **encrypted + authenticated** | HTTPS `:8443` (node cert) + shared identity key |
| Data sync (`satom-ha-datasync`) | encrypted | rsync over SSH |
| Config SoT publish (Gitea) | **encrypted** | `git push` over HTTPS to `https://git.example.net` (edge wildcard cert) |

## PKI layout (node-local, NEVER in git — see `.gitignore`)

`/opt/satom/pki/` on each node:

- `internal-ca/` — the internal CA (`ca.crt` + `ca.key`). **Both nodes are meant to
  hold the full pair.** The installer's node-join step writes `ca.key` onto a
  joining node from the **cluster join key** (`installers/install-satom.sh`), so a
  correctly joined secondary is an issuer too.
- `node/` — the node's inter-node leaf (`serverAuth`+`clientAuth`, signed by the
  internal CA). Reused as the Postgres server/client cert for replication mTLS.
  **Per node, forever.**
- `public/` — the cert nginx serves on `:443`/`:8443` (`server.crt` [+chain] +
  `server.key`) plus `meta.json` (`source`: `bootstrap` | `imported` | `issued`).
  **Shared between nodes** when — and only when — it is `imported`, via
  `data/pki-shared/` (below).

### Why these three do NOT share one rule

This is the part that keeps rotting, so here is the reason for each, not just the
rule. They differ because they answer three different questions:

| Artefact | Answers | Rule | Why |
|---|---|---|---|
| `internal-ca/ca.{crt,key}` | "may I mint certificates?" | on **both** nodes, delivered by the operator-driven join key | Issuance must survive a promote. A node holding only `ca.crt` verifies fine and looks healthy, but cannot renew its own leaf and cannot take over as issuer. |
| `node/leaf.{crt,key}` | "which node am I?" | **never leaves its node** | Its SAN is *this* hostname AND it is the Postgres replication **client** cert. Copying it to the peer breaks `clientcert=verify-ca` and produces a hostname mismatch — it is an identity, not a configuration. |
| `public/server.{crt,key}` | "what do browsers see?" | **shared, if `imported`** | Both nodes answer for names under one public certificate (the fleet wildcard), so keeping two copies in sync by hand was pure toil. But a **CA-issued** cert is per node by construction — its SAN is that node's name — so sharing it would be the leaf mistake all over again. Hence: imported only. |

`pki/` itself is outside `data/`, so `satom-ha-datasync` never replicates it and it
is never in a git push. The **served** cert is shared through `data/` instead, which
is exactly the tree the datasync (and the backup bundles) carry.

### The shared slot — `data/pki-shared/`

`cert_service.publish_shared_cert()` copies the currently-served
`server.crt` / `server.key` / `meta.json` into `data/pki-shared/` (dir `0700`, key
`0600`). `satom-ha-datasync` (standby pulls `data/` from the primary with
`rsync --delete`) carries it to the peer, so publishing is meaningful on the node
the sync reads **from**; running it on the other node is harmless but gets
overwritten within the sync interval. `data/` is gitignored, so no private key
reaches the repository.

`cert_service.install_shared_cert()` runs on **either** node and adopts the slot.
It is idempotent — a slot holding the bytes we already serve is a no-op with **no
nginx reload** — and it refuses, with the reason, when:

- the shared `meta.json` does not say `source: imported` (a `issued`/`bootstrap`
  cert names one node; an unreadable meta is treated the same — fail closed);
- the key does not match the certificate (same `validate_pem` check as import);
- the certificate does **not cover this node's served names** (`node_hostname()`,
  RFC 6125 matching — a `*.example` wildcard covers exactly one label). Installing
  a non-matching certificate would make the node serve something every browser
  rejects, immediately after the product reported the install as successful.

Installation goes through the ordinary `_install()` path — `nginx -t`, automatic
rollback to the previous cert/key if nginx refuses — so there is one, and only one,
implementation of "activate a certificate safely".

### CA custody — `cert_service.ca_custody()`

Reports, per node: `has_ca_cert`, `has_ca_key`, `can_issue`, `healthy`, `state`
(`issuer` | `trust-only` | `key-without-cert` | `absent`) and a `remedy` string.
A node in `trust-only` is **not** reported healthy: it cannot self-renew and cannot
become the issuer after a promote, and the remedy is to re-run the installer's
node-join step with the cluster join key. **No code moves `ca.key` between hosts** —
the join key is the sanctioned transport and it is operator-driven on purpose.

## The service certificate — Settings → **Node TLS** (admin)

`app/services/cert_service.py`; endpoints in `app/views/settings.py`
(`/settings/node-cert/{state,import,issue,renew}`), UI tab in
`settings/index.html`.

- **Import** a PEM cert (+ key, + optional chain): key/cert match is validated,
  nginx is `-t`-tested and **rolled back automatically** if the new cert is bad.
  Import is *import-only* — expiry is tracked and alerted, but not auto-renewed
  (we didn't issue it).
- **Issue from the internal CA** (any node that holds `ca.key` — see *CA custody*
  above; that is meant to be both of them): mints a leaf for the node hostname,
  installs it, `source=issued`. Issued certs are **per node** and are never
  published to `data/pki-shared/`.
- **Share** an imported cert with the peer: `publish_shared_cert()` on the node the
  datasync reads from, `install_shared_cert()` on each node. Replaces the manual
  copy that used to keep the fleet wildcard in sync.
- **Renew**: CA-issued certs auto-renew via `satom-cert-renew.timer` →
  `flask cert-renew` → `cert_service.renew_if_needed()` (nightly 03:30, no-op
  until within 30 days of expiry, no-op for imported/bootstrap). A node in
  `trust-only` custody cannot self-issue at all: fix custody (join key), or give
  it a cert by **import** / the shared slot.

### Hazard: the public wildcard renews OFF these nodes

The `imported` fleet wildcard is renewed on the **edge** host, not here — nothing
in this application can re-mint it, and `renew_if_needed()` deliberately no-ops on
`source != issued`. So on every edge renewal the new material must be brought back:
either the `autopull` renewal mode (SFTP from the edge, host-key pinned) or a manual
re-import — and then **`publish_shared_cert()` again**, or the peer keeps serving
the old certificate until it expires. `meta.json` carries this warning in its `note`
field on purpose. Two failure modes to expect:

1. **Expiry passes unnoticed** because "it renews automatically" — it does, on the
   edge. The alert engine's cert check (T-N days) is the only thing that catches it
   on the node side; do not silence it.
2. **Split expiry between the nodes** — one node re-imported, the peer not. The
   shared slot exists to remove exactly this: publish once, both nodes converge.

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
  (`ssl_cert_file`/`ssl_key_file` → `/etc/postgresql/15/main/satomssl/server.*`,
  `ssl_ca_file` → the internal CA).
- `pg_hba`: `hostssl replication replicator 192.0.2.249/32 ... clientcert=verify-ca`
  (mutual — the standby must present a CA-signed client cert), and
  `hostssl satom satom 192.0.2.249/32` (encryption enforced).
- Standby `primary_conninfo`: `sslmode=verify-ca` + `sslrootcert`/`sslcert`/`sslkey`
  (its own leaf, `/etc/postgresql/15/main/satomssl/client.*`).
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
(included by `monitoring/satom.html`), endpoint `/monitoring/encryption`. Every
"encrypted" badge is backed by a **live probe** (`pg_stat_ssl`, a real TLS
handshake to `:8443`, git remote scheme) — never assumed. Shows, per channel:
encrypted? · protocol+cipher · how · enforced/authenticated, plus a node-cert
tile (subject/issuer/expiry/source).

## Known gaps / next steps
- ~~**Gitea remote is plain HTTP**~~ — RESOLVED 2026-07-13. `origin` on both nodes
  switched from `http://192.0.2.53:3000` to `https://git.example.net/satom-dev/satom.git`
  (embedded access token preserved; edge presents the trusted fleet wildcard, `ssl_verify=0`).
  Verified: `ls-remote`, `fetch`, and dry-run `push` all authenticate over TLS on 248 + 249;
  the encryption card now reports this channel encrypted. Rollback pointer saved at
  `/root/satom-origin.http.rollback` on each node.
- **Cutover to option B** — DONE 2026-07-13 (public `:443` path live; final gunicorn
  lockdown intentionally deferred). Each node now serves the app directly on **`:443`**
  via nginx with the **trusted fleet wildcard** `*.example.net` (copied from the edge
  `/etc/nginx/ssl/visionebc-wildcard.{crt,key}` into `pki/public/`, `source=imported`,
  valid to 2026-09-02 — zero browser warning). `:8443` (peer probes) and `:80`→301
  are also served from the same vhost (`satom-tls.conf`). nftables on 248 opens `:443`+`:80`
  from `192.0.2.0/24`; 249's input chain is `policy accept`. DNS
  `satom{,-2}.example.net` resolves to `192.0.2.248/.249`; Power Panel DNS
  entries 269/275 reconciled to match (were stale at `.40`). Pre-change backups per node:
  `/root/fm-pub-server.{crt,key}.pre-b-cutover`, `/root/satom-tls.conf.pre-b-cutover`,
  `/root/fm-pub-meta.json.pre-b-cutover`.
  STILL OPEN (deliberate): (a) gunicorn stays on `0.0.0.0:8000` so the **edge remains a
  rollback** through the validation window (feedback_migration_policy) — bind to
  `127.0.0.1` only after the `:443` path is user-confirmed; (b) the wildcard is **not
  auto-renewable from the node** (it renews on the edge ~every 90d) — see *Hazard: the
  public wildcard renews off these nodes* above. The node→node half of that copy is no
  longer manual: `publish_shared_cert()` + `install_shared_cert()` via `data/pki-shared/`.
  The edge→node half still needs `autopull` or a re-import. Internal-CA issue/auto-renew
  still exists for a self-managed cert if the fleet wildcard is ever not desired.
