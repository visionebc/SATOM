# Offline update packages

Update a node that has no route to the git remote: download a signed package,
upload it through the web console, apply it. No internet, no repository, no
package mirror.

This is not the offline **install** bundle. That one carries OS packages and
stands a node up from nothing; this carries only what an update needs — the
application code and every pinned Python wheel — so it is roughly a quarter of
the size.

---

## 1. The short version

```
# build (any machine with a checkout; holds no secret)
bash installers/build-update-package.sh
  -> dist/satom-update-<version>.tar.gz

# sign (the machine where the private key lives — never a managed node)
python3 deploy/sign_update_package.py sign dist/satom-update-<version>.tar.gz \
        --key release.key

# apply (on the node)
#   web : Settings -> Software Update -> Offline update package
#   cli : satom execute update package satom-update-<version>.tar.gz --yes
```

An **unsigned package is refused by every node**, so shipping one is a mistake
that fails closed rather than one that ships.

---

## 2. Why it is signed, and what that buys

Uploading code that a root process installs is, by construction, remote code
execution as root — unless something proves the code came from someone the node
already trusts. That proof is an Ed25519 signature checked against a **trust
store the web worker cannot write**.

Three properties hold the design together. Breaking any one of them makes the
other two decorative.

### The private key never touches the fleet

The build host holds no secret; signing is a separate step that runs wherever
the key is. The key is an encrypted PKCS#8 PEM, protected by a passphrase, kept
offline and backed up offline.

Signing is not part of the build on purpose: a build host is disposable, and a
disposable machine must not be able to mint packages.

### The public key is public, and that is not a weakness

A public key can only **verify**. Nobody can sign with it. That is why it ships
in the repository and gets installed on every node — exactly like an SSH
`authorized_keys` entry, which is world-readable and still lets nobody in.

### The trust store is root-owned and outside the application tree

`/etc/satom/update-keys/` is `root:root`, and so is every parent of it. The
application tree is owned by the service account, so a trust store inside it
would be a trust store the web worker could add its own key to — and a key it
chose is a package it can mint. `trust_store_problem()` walks the whole parent
chain and the runner treats any finding as fatal.

A node with an **empty** trust store accepts nothing. That is a safe default,
not a working one: install the release key before you need it.

---

## 3. What is in a package

```
satom-update-<version>/
    manifest.json      the signed document
    manifest.sig       base64 Ed25519 signature over manifest.json's BYTES
    app.tar.gz         the application tree at that revision
    wheels/*.whl       every pinned dependency
```

The signature covers the manifest's **exact bytes** — no canonicalisation, so
there is no re-serialisation ambiguity to exploit — and the manifest carries a
sha256 for every other file. Signing one small document therefore covers the
whole package, and any edit to the manifest invalidates the signature even if
the JSON stays semantically identical.

The manifest deliberately carries **no hostname, path or operator identity**.
Packages are published; a published artifact must not describe the estate that
built it.

`python_tags` says which interpreters the wheels fit. It is `["*"]` when every
wheel is pure Python and `["cpXY"]` when any of them is compiled. Getting this
wrong is the RHEL-9 trap — system Python 3.9 against cp311 wheels — where the
apply would otherwise die deep inside pip on a node with no network to fall
back on.

---

## 4. Managing the trust store

```
satom show trust                                  # what this node accepts
satom execute trust add-key release.pub           # install a key (root)
satom execute trust remove-key <name|fp> --yes    # stop accepting one (root)
satom diagnose updates                            # is the whole path sound?
```

Compare the fingerprint against the one published with the release **before**
trusting it. Installing a key is the moment the trust decision is made; every
check afterwards only enforces it.

Operators and forks can add their own keys and sign their own packages. Nothing
in the product contains a secret, so nothing about this depends on the vendor.

### Rotating a key

1. Generate the new pair where the new key will live.
2. Publish the new `.pub` and install it alongside the old one.
3. Sign the next release with the new key.
4. Once every node has the new key, `remove-key` the old one.

Both keys are trusted during the overlap, which is what makes the rotation
non-disruptive. Removing the old key first would strand every node that had not
yet installed the new one.

---

## 5. Preflight

The console verifies the package and reports what applying it would do, before
anything is applied. An update that cannot work should fail on a page that
explains why, not halfway through a privileged apply.

| Check | Blocks | What it catches |
|---|---|---|
| Trust store | yes | no keys, or a store that is not root-owned |
| Archive | yes | traversal, symlinks, device nodes |
| Signature & integrity | yes | unsigned, wrong key, altered payload, extra files |
| Version | no | downgrade, or reinstall of the same version |
| Upgrade path | yes | package needs a newer starting point |
| Python | yes | venv interpreter does not match the wheels |
| Dependencies | yes | a pinned change with no wheel in the package |
| Disk space | yes | not enough room for package, extraction and backup |
| This node | no | staging on a standby, which the data sync deletes |

Every one of these is **advisory**. The privileged runner re-verifies the
signature, the hashes and the version rules itself, as root, against a store
the worker cannot write. If the two disagree, the runner wins — the worker runs
in the process an attacker would already have if they had anything at all.

The server also re-runs preflight when Apply is pressed. The page an operator
looked at could be minutes old, and "the button was enabled" is not a safety
property.

---

## 6. Applying

The web worker only stages the file and writes a request. The privileged runner
(`satom-updater.service`) does everything else, in this order:

1. **Hardened?** — refuse if the runner's own code is writable by the service
   account
2. **Signature** — against the trust store
3. **Every hash** — against the signed manifest
4. **Version rules** — downgrade allowed only when the request says so
5. **Database backup** — refuse to replace code if it cannot be taken
6. **Dependency freeze** — so a rollback can restore the venv
7. **Park local commits** — anything not on the remote goes to `refs/backup/`
8. **Install the tree**, hand ownership back to the service account
9. **`pip install --no-index`** — strictly from the package's own wheels
10. **Migrations**, units, the operator CLI and the runner itself
11. **Restart**, then prove it works: HTTP 200 on `/healthz`
12. **Commit** the deployed revision

The order is not cosmetic. A writable runner makes the signature meaningless; an
unverified manifest makes the hashes meaningless; unchecked version rules let a
valid-but-wrong package through. Each stage only means something once the
previous one passed.

**On failure, anything at all**: the tree is reset to the pre-update commit,
files the package added are removed, the venv is restored from the freeze, the
services restart, and health is re-checked. The status log records every step.

### Rollback removes only what the package added

Not a blanket `git clean`. The untracked-file list is captured before the tree
is replaced and only the difference is deleted — destroying an operator's
unrelated work in order to undo ours is not a rollback.

### Why the apply commits

Without a commit the tree stays permanently dirty, `satom diagnose git` reports
drift for ever, and a reconciler in AUTO mode would reset the package away on
its next pass. The commit is made as the service account, never as root:
root-owned objects in `.git` break the git publish path.

---

## 7. Downgrades

Allowed, and they need saying out loud: **a downgrade does not reverse database
migrations.** A schema created by the newer version stays in place. The older
code may not know about it.

- The web console requires an explicit confirmation checkbox.
- The CLI requires `--allow-downgrade`.
- Either way a database backup is taken first, and that backup is the way back.

The honest limitation: signing prevents a *forged* package, not an operator
choosing to install a genuine older release with known bugs. That is a
downgrade attack in the classic sense and it is accepted deliberately, in
exchange for being able to get out of a bad release on an offline node. The
mitigations are the audit log, the explicit confirmation, and the backup.

---

## 8. HA

The apply is **node-local**: each node has its own venv, so each node applies
its own copy. Stage the upload on the **primary** — `data/` replicates to the
standby with `rsync --delete`, so a file uploaded on the standby is removed on
the next sync.

Apply to the standby first, as with any other update, then the primary.

---

## 9. The runner privilege boundary

`satom-updater.service` runs as **root**, and the unit it ships with points at
`/opt/satom/deploy/self_update_runner.py` — inside the tree the service account
owns. Root executing code the unprivileged worker can rewrite is a complete
escalation, and it would make signature checking pointless: a verifier the
attacker can edit verifies nothing.

`deploy/install-runner.sh` fixes this the same way the operator CLI is fixed:

- the runner **and its verifier** are copied to `/usr/local/lib/satom-runner`,
  `root:root`
- a **system** interpreter runs them, never the venv (which lives in the tree,
  and which may be the very thing being repaired)
- the unit is redirected with a **drop-in**, not an edit — the update runner
  re-copies `deploy/<unit>` on every update, so an edited unit silently reverts
- the verifier must pass a sign/verify self-test before it is installed

It runs from four places so the copy cannot drift: the installer, the
de-privilege migration, every code update, and `satom execute reinstall runner`.

`package_change()` refuses outright when the runner is not hardened. The git
update path is unaffected — it is gated by the remote, not by local trust.

Verify with:

```
satom diagnose updates
```

---

## 10. Building and signing

### Build

```
bash installers/build-update-package.sh
```

Uses `git archive HEAD`, never the working tree: the package must contain the
committed revision, not whatever happens to be lying around on the build host.
Set `MIN_FROM_VERSION` to raise the minimum version a node may apply it from.

### Create a signing key (once)

```
python3 deploy/sign_update_package.py genkey \
        --out release --comment "<who this key belongs to>"
```

Writes `release.key` (encrypted, **back this up offline**) and `release.pub`
(publish it). The fingerprint is printed; publish that too, so anyone
installing the key can compare it.

### Sign

```
python3 deploy/sign_update_package.py sign <package> --key release.key
python3 deploy/sign_update_package.py verify <package> --pub release.pub
```

The signer needs only Python and `cryptography`. The **verifier** needs neither
— it is pure standard library, because it has to run on a node whose venv is
broken.

---

## 11. Known limits

- **Not a rescue path for a node that will not boot.** It needs systemd, the
  runner and a working Postgres connection.
- **The package cannot change OS packages.** Same scope as every other update
  path here: application code and Python dependencies only.
- **A downgrade does not reverse migrations** (section 7).
- **`git archive` cannot carry untracked files.** Anything not committed is not
  in the package — which is the intent, but it means a node repaired this way
  matches the commit, not somebody's working tree.
