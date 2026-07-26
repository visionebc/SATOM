# SATOM — Privilege model and HA trust

Status: **normative**. Applies to `install-satom.sh` v1.2 and later, and to any
node migrated with `deploy/migrate-deprivilege.sh`.

This document exists because every earlier version of SATOM ran the whole
product as `root`, and the HA pair trusted each other with an unrestricted
`root` SSH key. Both are fixed. Read this before changing a systemd unit, a
sudoers rule, or anything under `pki/`.

---

## 1. The one rule

> **The web worker never has a privilege it can be tricked into using.**

SATOM parses attacker-influenced input all day: REST payloads from FortiWeb,
FortiADC and FortiAnalyzer appliances, uploaded firmware, PEM blobs pasted into
the certificate manager, backup containers pulled off `backup-server`. The process
doing that parsing must not be able to install a package, write a unit file, or
open a shell on the peer node.

---

## 2. Accounts

| Account | Used by | Shell | Notes |
|---|---|---|---|
| `satom` (default; `SATOM_APP_USER` overrides) | web, scheduler, reconciler, alerts, cert-renew, git-publish, ha-datasync | `nologin` | Owns `/opt/satom` and `/var/log/satom` |
| `root` | `satom-updater.service` only | — | The single privileged runner |
| `fortinet` | Postgres role **only** | n/a | Legacy name, deliberately not renamed |

`fortinet` as a *Linux* user is a legacy artifact on nodes installed before
v1.2. It is unrelated to the Postgres role of the same name — the app connects
over TCP with a password, not peer auth. Migrated nodes may keep the name by
setting `SATOM_APP_USER=fortinet`; fresh installs get `satom`.

### Filesystem ownership

```
/opt/satom              satom:satom  0750
/opt/satom/.env         root:satom   0640   # app READS it, never writes it
/opt/satom/state        satom:satom  0700   # node-local cert-renew journal
/opt/satom/.ssh         satom:satom  0700   # HA datasync identity
/opt/satom/pki          satom:satom  0750   # 0700 on internal-ca/
/var/log/satom          satom:satom  0755
```

`.env` is root-owned on purpose: it holds `FERNET_KEY` and the DB password. The
app only ever needs to read it, so a write primitive in the web worker cannot
rewrite the app's own secrets.

---

## 3. sudo — and what is deliberately NOT granted

`/etc/sudoers.d/satom` grants **exactly two commands**:

```
Cmnd_Alias SATOM_CERT_RELOAD = /usr/sbin/nginx -t, /usr/bin/systemctl reload nginx
satom ALL=(root) NOPASSWD: SATOM_CERT_RELOAD
```

That is the complete list. It exists because `app/services/cert_service.py`
validates and activates a new TLS certificate: it needs `nginx -t` (which reads
private keys under `/etc/nginx/ssl`) and a reload. Nothing else in the web
worker needs root.

### Rejected: `sudo` for package installation

A rule like `satom ALL=(root) NOPASSWD: /usr/bin/apt install *` **is root**, not
a subset of it. A `.deb` runs its own `preinst`/`postinst` scripts as root, so
permission to install any package is permission to run any code as root. The
same holds for `dnf`, `zypper`, `pacman`, and for `pip install` into a venv the
service account owns.

Package installation happens in exactly two places, both correct:

1. **Install time** — `install-satom.sh` runs as root, once, driven by a human.
2. **Runtime library upgrades** — Settings → Libraries, via the enqueue →
   privileged-runner path in §4. Curated allowlist, never arbitrary names.

### Rejected: unrestricted `systemctl`

`satom ALL=(root) NOPASSWD: /usr/bin/systemctl` lets the worker start *any*
unit, including one it just wrote. Note that the allowlist above pins both the
verb and the unit: `systemctl reload nginx`, not `systemctl *`.

`systemctl is-active <unit>` (used by `app/services/system_health.py`) needs no
privilege at all and is not in the allowlist.

---

## 4. The privileged runner boundary

Anything that genuinely requires root goes through the pre-existing self-update
mechanism. Nothing about that design changed in v1.2 — it is simply now the
*only* path, instead of one path alongside a root web worker.

```
web worker (satom)                 privileged runner (root)
────────────────────               ─────────────────────────
writes JSON request        ──►     satom-updater.path notices
to data/update-requests/           └─► satom-updater.service
                                       · re-validates the request
                                       · pip / unit install / restart
                                       · health check + auto-rollback
                           ◄──     writes data/update-status/<uid>.json
```

The runner **re-validates** every request against its own allowlist. The web
worker's validation is a UX affordance; the runner's is the security boundary.
A compromised worker can enqueue whatever it likes and still only get the
curated set.

Units and their accounts:

| Unit | Runs as | Why |
|---|---|---|
| `satom.service` | `satom` | Web/gunicorn, `127.0.0.1:8000` behind nginx |
| `satom-scheduler.service` | `satom` | Fires scheduled actions (primary-only guard) |
| `satom-reconciler.service` | `satom` | Stages self-updates; enqueues only |
| `satom-alerts.service` | `satom` | Email/alert engine |
| `satom-cert-renew.service` | `satom` | Uses the two sudo commands above |
| `satom-git-publish.service` | `satom` | Pushes `reports/` SoT to Gitea |
| `satom-ha-datasync.service` | `satom` | Pulls peer `data/` (standby only) |
| **`satom-updater.service`** | **root** | **Installs units, runs pip, restarts services** |

`satom-updater.path` + `.service` are the only units that must stay root. If you
find yourself adding a second one, you are probably about to reintroduce this
whole problem.

---

## 5. HA trust between nodes

### What was wrong

Up to v1.1 the **primary** generated the datasync keypair and shipped the
**private half inside the join key** — a base64 blob that also carries the
internal CA private key, `FERNET_KEY`, `SECRET_KEY` and both DB passwords, and
that a human pastes between two terminals. The matching `authorized_keys` entry
on the primary had no `from=`, no `restrict` and no `command=`: whoever held
that join key had an interactive **root shell on the primary from any address**.

### What it is now

1. The **secondary generates its own keypair** during install. The private key
   is written once, to `/opt/satom/.ssh/id_ha_rsync`, and never leaves the disk.
2. `rsync_key` is **removed from the join key payload**.
3. The secondary prints its **public** key plus the exact command to run on the
   primary:

   ```
   sudo ./install-satom.sh --authorize-peer <standby-ip> "ssh-ed25519 AAAA..."
   ```

4. That subcommand appends a fully constrained entry to the *service account's*
   `authorized_keys` — not root's:

   ```
   from="192.0.2.249",restrict,command="/usr/local/sbin/satom-ha-rsync-shell" ssh-ed25519 AAAA...
   ```

   * `from=` — only from the standby's address.
   * `restrict` — no pty, no agent/port/X11 forwarding, no user-rc.
   * `command=` — the key cannot run anything else, ever.

5. `satom-ha-rsync-shell` accepts **only** `rsync --server --sender` rooted at
   `/opt/satom/data`, and rejects shell metacharacters. `--sender` is rsync's
   read side, so the key is structurally incapable of writing to the primary.
   SATOM ships this wrapper rather than depending on `rrsync`, which lives at
   different paths per distro and is absent on some.

6. The peer's host key is seeded with `ssh-keyscan` during the join, and the
   client uses `StrictHostKeyChecking=yes`. The previous `accept-new` meant the
   first connection trusted whatever answered on that IP.

### Verifying it

From the standby:

```bash
sudo -u satom ssh -i /opt/satom/.ssh/id_ha_rsync satom@<primary-ip> true
# MUST be refused. A shell here means the forced command is missing.

sudo systemctl start satom-ha-datasync.service
sudo systemctl show satom-ha-datasync.service -p Result --value   # => success
```

### Known gap: the reverse direction

After a promote, the old primary becomes a standby and needs to pull from the
new one — but only one direction is authorized at install time. Run
`--authorize-peer` on the *new* primary for the *old* one as part of the
promote runbook. `/usr/local/sbin/satom-ha-datasync.sh` must also be present on
both nodes; before v1.2 it was installed only on the standby.

---

## 6. Migrating an existing node

`deploy/migrate-deprivilege.sh`, one node at a time, **standby first**. It
creates the account (or adopts `fortinet`), fixes ownership of `state/` and
`/var/log/satom` (root-owned on legacy nodes because the app used to run as
root), installs the sudoers file, rewrites `User=` in the units, and restarts.

Roll back by restoring `/root/satom-units.pre-deprivilege-<ts>/` and removing
`/etc/sudoers.d/satom`.

The venv, PKI and `data/` are **not** touched: they are already owned by the
app account on legacy nodes.

---

## 7. Checklist when adding a feature

- Does it shell out? Then it does **not** run in the web worker. Enqueue it.
- Does it need a new sudo rule? Pin the verb *and* the operand. If you cannot,
  it belongs in the runner.
- Does it write outside `/opt/satom` or `/var/log/satom`? Then it needs the
  runner.
- Does it add a secret to the join key? Justify it in review — that blob is
  already the highest-value artifact in the product.
