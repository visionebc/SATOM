# ACME / Let's Encrypt in the Certificate Manager

The Certificate Manager issues certificates through a **pluggable protocol**:

| Protocol | Backend | Where it is configured |
|---|---|---|
| `adcs`  | Microsoft ADCS / any enterprise CA driven by a command template | Settings → Certificate Manager → ADCS |
| `acme`  | Any RFC 8555 CA — Let's Encrypt, Buypass, ZeroSSL, Google Trust, a private ACME server | Settings → Certificate Manager → ACME |

Both share ONE pipeline: `generate CSR → sign → store → deploy → swap → revoke`.
Only the signing step differs, and it differs by **configuration**, not code.

---

## 1. Design rules

**Nothing is hardcoded, and nothing internal is assumed.** SATOM ships to third
parties, so every value an operator could need is a form field:

* the CA (directory URL, ToS, account email, EAB, key type, account directory),
* the validation method (`http-01` webroot/standalone, `dns-01`, `tls-alpn-01`),
* the DNS provider **and its credentials**,
* and — behind an explicit "Custom" switch — the raw commands themselves.

**The DNS provider catalog is data, not code.** Providers live in the
`acme_dns_providers` table, seeded INSERT-ONLY at boot from the git-tracked
`acme_providers.yaml` (same contract as the endpoint registry: an operator edit
always wins). Adding a provider — or fixing an environment variable an upstream
release renamed — is a row in Settings, never a release.

**Credentials never touch a command line.** Every ACME client takes DNS-provider
credentials from the **environment**. `cert_manager._build_env()` builds a
*minimal* environment for the signer: a curated passthrough (`PATH`, proxy vars,
locale) plus exactly the provider variables. The web process runs as root and
carries `FERNET_KEY` and `SQLALCHEMY_DATABASE_URI` — **those are not inherited**.
Every secret is masked from stdout, stderr and the stored log by `_redact_all()`.

---

## 2. Client: lego

Default client is [lego](https://go-acme.github.io/lego/): a single static Go
binary with ~150 DNS providers built in, all configured by environment. For a
product installed on Debian/RHEL/SUSE/Arch that beats certbot (a Python version
matrix plus a pip plugin per provider) and acme.sh (8k lines of bash run as
root). The installer places it at `/usr/local/bin/lego` (sha256-verified
download, or from the offline bundle).

`Client = other` disables the generator and hands the raw templates to the
operator; the pipeline itself is client-agnostic.

The generated commands (verified against **lego 5.2.2** — in v5 all flags live
on the subcommand, EAB is `--eab.kid/--eab.hmac`, the propagation flags are
`--dns.propagation.wait` / `--dns.propagation.disable-ans`, and the listeners are
`--http.address` / `--tls.address`):

```
{helper} {out} {bin} run --accept-tos --email {email} --server {directory} \
    --path {acme_path} --key-type {key_type} --dns {dns_flag} \
    --dns.resolvers {dns_resolvers} --dns.propagation.wait {dns_propagation_wait}s \
    --csr {csr}

{bin} certificates revoke --email {email} --server {directory} \
    --path {acme_path} --cert.name {cn} --reason 4
```

`{helper}` is `deploy/acme-hooks/satom-lego-run.sh`: lego writes into its own
`--path` tree and has no `--out`, so the helper copies the issued certificate to
the path the pipeline chose. It exists so the command template stays a **flat
argv** — no shell pipeline, no injection surface.

---

## 3. Validation

### Web authentication (`http-01`)

Default mode is **webroot**, not standalone: nginx already owns :80 on a SATOM
node, and standalone would require stopping it for every issuance. The installer
writes:

```nginx
server {
    listen 80 default_server;
    server_name _;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme;
        default_type "text/plain";
        try_files $uri =404;
    }
    location / { return 301 https://$host$request_uri; }
}
```

⚠️ The redirect **must** be inside `location /`. A server-level `return` runs in
the server-rewrite phase, *before* location selection, and silently swallows the
challenge — the symptom is a 301 on the challenge URL and an `invalid
authorization` from the CA.

The CA always connects on port 80 (or 443 for `tls-alpn-01`) from the public
internet. Changing the port field only moves the local listener.

### DNS (`dns-01`)

The only option for wildcards and for hosts with no inbound port. Pick a
provider, fill its fields, save. Required fields that are still empty are shown
as a badge on the provider and **fail the issuance early**, with a clear message
instead of a CA error.

`Resolvers` matters in a split-horizon fleet: point it at a public resolver
(`1.1.1.1:53`) or the propagation check will read your internal view and hang.

### Providers with no native support — the `exec` hook

`flag: exec` runs any script: `<script> present|cleanup <fqdn> <token> <keyauth>`.
This is how **EfficientIP SOLIDserver** is supported
(`deploy/acme-hooks/efficientip.sh`, stdlib-only, same REST verbs and Basic auth
as `app/services/dns_providers/efficientip.py`). The same lane covers any DDI or
in-house DNS API — add a catalog row with an `EXEC_PATH` field and go.

---

## 4. Two things a public product must get right

1. **Persist the account key.** `{acme_path}` (default `/opt/satom/data/acme`)
   holds `accounts/<directory>/<email>/…key`. A fresh registration per issuance
   burns the CA's new-account rate limit and loses the ability to revoke earlier
   certificates. It lives under `data/`, so HA datasync replicates it and the
   system backups include it.
2. **Test on staging.** Let's Encrypt allows ~5 failed validations per hostname
   per hour. The directory field offers staging shortcuts; use one until a full
   issuance succeeds, then switch to production.

---

## 5. Where the code lives

| Piece | File |
|---|---|
| Provider catalog + command generator + env builder | `app/services/acme_providers.py` |
| Catalog seed | `acme_providers.yaml` (repo root) |
| Catalog table | `AcmeDnsProvider` in `app/models.py` (`acme_dns_providers`) |
| ACME settings + per-provider credentials | `app/services/settings_store.py` (`certmgr.acme`, `certmgr.acme.creds.<slug>`) |
| Protocol dispatch, env injection, redaction | `app/services/cert_manager.py` (`_acme_common`, `_signing_context`, `_build_env`, `_redact_all`) |
| UI + routes | `app/templates/settings/index.html`, `app/views/settings.py` |
| Hooks | `deploy/acme-hooks/satom-lego-run.sh`, `deploy/acme-hooks/efficientip.sh` |

---

## 6. Security notes

* The catalog is curated by default; there is **no** "run any binary" flow in the
  normal path. Raw command templates require `USER_MANAGE`, are audited and are
  warned about in the UI — treat them as remote code execution and prefer the
  generated form. (Same reasoning as Settings → Libraries, where arbitrary
  `pip install` was rejected in favour of a curated allowlist.)
* Secret provider fields are Fernet-encrypted at rest, never returned to the
  browser, never logged, and passed only through the child environment.
* `_build_env()` is an allowlist, not a filter: adding a variable to the child
  environment is an explicit decision.
