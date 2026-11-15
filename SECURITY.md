# Security Policy

## Reporting a Vulnerability
If you discover a security vulnerability in SATOM, please report it
privately. **Do not open a public issue for security problems.**

- Email: **security@example.net**
- Please include: affected version/commit, a description, reproduction
  steps, and impact. A proof-of-concept is welcome but not required.
- We aim to acknowledge reports within **72 hours** and to provide a
  remediation plan or fix within **30 days**, severity permitting.
- Coordinated disclosure is appreciated: give us a reasonable window to
  ship a fix before public disclosure.

## Supported Versions
Only the latest released `main` line receives security fixes. Older tags
are provided as-is.

## AS-IS / No Warranty
SATOM is provided under the Elastic License 2.0 **without warranty of
any kind** (see LICENSE, "No Liability"). You run it at your own risk
and are responsible for securing your own deployment (network exposure,
credentials, TLS, OS hardening, and access control).

## Security Posture (how the app protects itself)
- **Secrets** (device passwords, RADIUS secrets, backup-server creds) are
  encrypted at rest with Fernet (`cryptography`). The `FERNET_KEY` is read
  from the environment (`.env`), never hardcoded, and never committed.
- **RBAC**: every route is authenticated and permission-gated
  (`@login_required` + `require_permission`); write proxying requires
  `CONFIG_WRITE`.
- **SSRF defence-in-depth**: the device API proxy refuses link-local /
  cloud-metadata (169.254.0.0/16, fe80::/10) and loopback targets.
- **SSH**: appliance connections use trust-on-first-use host keys
  persisted under `data/known_hosts` (not blind accept-every-time).
- **Transport**: node-to-node probes and Postgres replication run over
  mutually-authenticated TLS; the web UI is served over HTTPS.
- **Path safety**: uploaded/backup filenames pass through
  `werkzeug.secure_filename` and are confined to a per-record vault dir.

## Pre-publication security pipeline
Before any code reaches the public mirror it passes an automated gate:
sanitization -> secret scan -> internal AI vulnerability audit. See
[`docs/release-pipeline.md`](docs/release-pipeline.md) for the full
description. Findings are triaged and tracked before publish.
