# satom-webctl — managing nginx and Apache from SATOM

`satom-webctl` is the only program SATOM can run on a web server it manages
through **Plugin Studio › Connections › Server**. It is small (one Python file,
standard library only, Python 3.6 or newer), it is not a daemon, and it opens
no port. Its installer, `install-satom-webctl.sh`, prepares the server once.

This document is the complete reference: what is installed, what it can and
cannot do, how SATOM talks to it, and how to remove it.

---

## 1. How it works

```
SATOM node (a1 or a2)                         web server
───────────────────────                       ─────────────────────────────────
Plugin Studio app / script                    sshd
   │                                            │  authorized_keys of satom-mon:
   │  SSH as satom-mon, SATOM's key             │  restrict,command="/usr/local/bin/satom-webctl",
   ├───────────────────────────────────────────▶│  from="<SATOM node addresses>"
   │  stdin:  {"op": "...", "args": {...}}       │
   │                                            ▼
   │                                       satom-webctl (runs as satom-mon)
   │  stdout: {"ok": true, "result": {...}}      │  reads /etc/satom-webctl.json
   ◀────────────────────────────────────────────┤  nginx/Apache site files, document roots
   ▼                                            │  sudo: config test + reload only
ingestion gate (server_ingest):
size, strict JSON, closed schema per operation
```

* **SATOM always initiates.** Every call is one SSH session opened by SATOM,
  one request, one answer, then the session ends.
* **The server never connects to SATOM.** Nothing on the server holds a
  credential for SATOM: the server has only SATOM's *public* key. On both SATOM
  nodes, **hostguard** also drops every new connection that comes from a
  managed server (section 7).
* **The key opens no shell.** `restrict` disables the pty, agent forwarding,
  port forwarding and X11; `command=` makes sshd run `satom-webctl` whatever
  the client asks for. `from=` accepts the key only from the SATOM nodes.

## 2. Requirements

| | |
|---|---|
| Distributions | Debian / Ubuntu, RHEL / Rocky / Alma / Fedora, SUSE / openSUSE |
| Web servers | nginx and/or Apache (httpd / apache2) |
| Python | `python3` 3.6 or newer (standard library only) |
| SSH | `sshd` reachable from the SATOM nodes (port 22 by default) |
| Installed by the installer if missing | `sudo`, `acl` (`setfacl`) |
| Containers (LXC) | an unprivileged container with systemd 252+ needs `features: nesting=1`, or every SSH login waits 25 s for systemd-logind |

### Site directories per distribution

| Family | nginx | Apache | Layout |
|---|---|---|---|
| Debian / Ubuntu | `/etc/nginx/sites-available` + `sites-enabled` | `/etc/apache2/sites-available` + `sites-enabled` | `debian`: enabled = symlink in `*-enabled` |
| RHEL family | `/etc/nginx/conf.d` | `/etc/httpd/conf.d` | `confd`: enabled = `name.conf`, disabled = `name.conf.disabled` |
| SUSE | `/etc/nginx/vhosts.d` | `/etc/apache2/vhosts.d` | `confd` |

## 3. Installing

1. In SATOM, create the connection (**Plugin Studio › Connections › New ›
   Server**), enter the host, and press **Generate key**.
2. Press **Download satom-webctl** and copy the archive to the server.
3. On the server, as root, run the command the connection page shows, for
   example:

   ```bash
   tar xzf satom-webctl.tar.gz && cd satom-webctl
   sudo bash install-satom-webctl.sh --pubkey 'ssh-ed25519 AAAA... satom-web01' \
       --from 192.0.2.248,192.0.2.249
   ```

4. Back in SATOM: **Fetch and trust** the host key (compare the fingerprint
   with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server
   first), then **Test**.

### Installer options

| Option | Meaning |
|---|---|
| `--pubkey "<line>"` | SATOM's public key (required). |
| `--from a,b` | Addresses the key is accepted from (the SATOM nodes). Strongly recommended. |
| `--roots /var/www,/srv/www` | Directories whose document roots SATOM may manage (default `/var/www,/srv/www`). |
| `--read-only` | The server refuses every write, whatever SATOM's own setting says. |
| `--uninstall [--purge]` | Remove everything (section 9). |

Running the installer again is safe: it rewrites the configuration, the
sudoers file and the key line, and re-applies the ACLs.

## 4. What the installer changes

| Item | Details |
|---|---|
| User `satom-mon` | System account, home `/var/lib/satom-webctl`, shell `/bin/sh` (sshd needs one to run the forced command), password locked. |
| `/usr/local/bin/satom-webctl` | `root:root 0755`. The account that runs it cannot modify it. |
| `/etc/satom-webctl.json` | `root:root 0644`. Servers, layouts, roots, limits, `read_only`. |
| `/etc/sudoers.d/satom-webctl` | `0440`, validated with `visudo -cf`. Exactly two commands per web server — nothing else. |
| ACLs | `u:satom-mon:rwX` (plus the same default ACL on directories) on the managed roots and on the configured site directories only. Owners, groups and modes are not changed. |
| `~satom-mon/.ssh/authorized_keys` | One line: `restrict,command="/usr/local/bin/satom-webctl"[,from="..."] <SATOM's key>`. |
| `/var/lib/satom-webctl/backups` | `0700`, backups taken before every change. |
| `/var/log/satom-webctl/webctl.log` | One JSON line per operation. |

The sudoers file, for nginx on Debian, is exactly:

```
Defaults:satom-mon !requiretty
satom-mon ALL=(root) NOPASSWD: /usr/sbin/nginx -t, /usr/bin/systemctl reload nginx.service
```

For Apache the two commands are `apache2ctl configtest` / `apachectl configtest`
and `systemctl reload apache2.service` / `httpd.service`. The binary paths are
the ones `command -v` finds on that server.

## 5. Operations

Request: `{"op": "<operation>", "args": {...}}` on stdin (at most 16 MiB, read
within 30 s). Answer: `{"ok": true, "result": {...}}` or
`{"ok": false, "error": "<code>", "detail": "<text>"}` on stdout.

### Read

| Operation | Arguments | Result |
|---|---|---|
| `info` | — | version, servers and layouts, roots, `read_only`, `max_file_bytes` |
| `vhosts.list` | — | every virtual host: server, name, enabled, server names, document roots, listen, ssl, size, mtime, `managed_root` |
| `vhost.get` | `server`, `name` | the file's `content` and `sha256` |
| `files.list` | `server`, `name`, `path`, [`docroot`] | entries (name, type, size, mtime, mode), `truncated`, `skipped` |
| `files.read` | `server`, `name`, `path`, [`docroot`] | `content_b64`, `size`, `sha256` |

### Write (refused when SATOM's connection has *Allow writes* off, or the server is `--read-only`)

| Operation | Arguments | What happens |
|---|---|---|
| `vhost.put` | `server`, `name`, `content`, [`base_sha256`] | backup → write → config test → **restore if the test fails**, reload if it passes |
| `vhost.create` | `server`, `name`, `kind` (`static`/`php`), `server_names`, `docroot`, [`https`, `cert`, `key`, `php_socket`] | file from a template, document root created inside a managed root, enabled, tested, reloaded — or removed again |
| `vhost.enable` / `vhost.disable` | `server`, `name` | symlink or `.disabled` rename, tested, reloaded, undone on failure |
| `vhost.delete` | `server`, `name` | backup → remove → test → reload (restored if the test fails). The document root is kept. |
| `files.write` | `server`, `name`, `path`, `content_b64`, [`base_sha256`, `create_dirs`] | backup of the old file, atomic replace, mode kept |
| `files.mkdir` | `server`, `name`, `path` | new folder |
| `files.rename` | `server`, `name`, `path`, `to` | rename or move inside the document root |
| `files.delete` | `server`, `name`, `path`, [`recursive`] | backup (tar.gz), then delete |

`base_sha256` makes a write fail with `conflict` when the file changed since
it was read, so two people never overwrite each other silently.

### Error codes

`bad_request`, `unknown_op`, `read_only`, `timeout`, `too_large`, `config`,
`unknown_server`, `bad_name`, `not_found`, `exists`, `conflict`, `bad_path`,
`outside_docroot`, `root_not_managed`, `no_docroot`, `bad_docroot`,
`not_a_file`, `not_a_directory`, `not_empty`, `bad_content`,
`bad_server_names`, `bad_kind`, `bad_cert`, `bad_socket`, `os_error`,
`internal`. An error never contains the content of a file.

## 6. Guarantees on the server

* **Files stay inside the document root.** Every path is relative, `..` is
  refused, and the resolved path (symlinks followed) must be inside the
  document root of the named virtual host. That document root must itself be
  inside a managed root (`--roots`). A virtual host whose root is elsewhere is
  listed but its files are not reachable (`root_not_managed`).
* **No change without a backup, no broken configuration left behind.** Every
  configuration change is tested with the server's own test; a failing test
  restores the previous files and nothing is reloaded. Reload, never restart.
* **Hostile names do not break a listing.** A file name with control or
  Unicode bidi characters is left out of a listing and counted in `skipped`.
* **Limits.** Files up to `max_file_bytes` (4 MiB by default), listings up to
  `max_list` entries (5,000), 200 backups kept.

## 7. Guarantees on SATOM's side

* **Pinned host key.** A call is refused unless the server presents exactly
  the host key trusted on the connection page; it is taken only by an explicit
  *Fetch and trust*, never automatically.
* **Ingestion gate.** Every answer is checked before SATOM uses it: size cap
  before parsing, strict JSON, a closed schema per operation (types, ranges,
  lengths, character sets). One bad value rejects the whole answer.
* **Writes are opt-in** per connection (*Allow writes*).
* **Never packaged.** A server connection, its key and its host key never
  travel in an app package.
* **hostguard.** On both SATOM nodes, new connections coming from any managed
  server are dropped (nftables table `inet satom_hostguard`). The addresses of
  SATOM's own nodes, the default gateway, the trusted proxies and the name
  servers are never blocked.

## 8. Logs, backups, troubleshooting

* Operation log: `/var/log/satom-webctl/webctl.log` (time, peer address,
  operation, server, name, path, result).
* Backups: `/var/lib/satom-webctl/backups/<time>-<op>-<id>.tar.gz`, paths stored
  relative to `/`. Restore one with `tar xzf <file> -C /`.
* Self-test: `sudo -u satom-mon /usr/local/bin/satom-webctl --selftest`.
* Every login takes 25 s: an LXC container without `nesting=1` (section 2).
* `host key changed`: the server was rebuilt or its key replaced. Check it,
  then *Fetch and trust* again.
* `refused SATOM's key`: the installer ran with another public key (a new key
  was generated in SATOM). Run it again with the current one.
* `AllowUsers` in `sshd_config` must include `satom-mon`; the installer warns.

## 9. Uninstalling

```bash
sudo bash install-satom-webctl.sh --uninstall          # keeps backups and log
sudo bash install-satom-webctl.sh --uninstall --purge  # removes them too
```

It removes the ACL entries, the sudoers file, the program, its configuration
and the `satom-mon` account. Delete the connection in SATOM as well: hostguard
then stops blocking that server.
