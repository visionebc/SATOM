# Safeguards — what stops SATOM from hurting itself

SATOM writes to production firewalls, rewrites its own checkout, installs its own
dependencies and reloads its own web server. Every one of those is a way to lose
data or lock yourself out. This document is the catalog of the guards that make
those operations survivable: **what each one prevents, where it lives, and how to
verify it is actually armed** on your install.

It is deliberately a single page. A protection nobody can find is a protection
nobody trusts, and the failure mode this project keeps hitting is not a missing
guard — it is a guard that silently took the wrong branch.

## The six rules the guards follow

1. **Fail loud.** A guard that cannot do its job aborts the operation. The one
   bug class that has bitten this product repeatedly is a step that returns
   success while doing nothing (`git push` failing inside a timer that exits 0;
   an HA guard answering "not primary" because its probe needed root).
2. **Snapshot before anything destructive**, and make the snapshot survivable
   without the thing that was destroyed.
3. **Verify, then commit — auto-revert on failure.** Every self-mutation
   (code, dependency, certificate) is followed by a real check, and the failure
   path restores the previous state instead of leaving a half-applied one.
4. **Allowlist, never free-form.** Package names, provider fields, doc slugs,
   remote filenames, CLI verbs — all validated against a closed set, and
   re-validated at the privileged end.
5. **One writer.** On a cluster the primary owns every write that replicates;
   the standby refuses rather than producing state its own sync will undo.
6. **Operator edits outrank seeds.** Anything the operator can tune lives in the
   database, seeded INSERT-ONLY, so an upgrade never resurrects what they removed.

---

## 1. Git history and the source of truth

Full treatment in [`git-backup-and-outage.md`](git-backup-and-outage.md). The guards:

| Guard | Prevents | Where |
|---|---|---|
| `preserve_local_commits()` before `git reset --hard` | Losing commits that exist only here (the whole `reports/` history of a Gitea outage). Parks them on `refs/backup/pre-reset-<stamp>`; a dirty tree via `git stash create`. **Aborts the update if it cannot park them.** | `deploy/self_update_runner.py` |
| `git.ahead_unpushed` alert | A push that has been failing for days while every UI stays green. Keys off the **age** of the oldest unpushed commit, not the count | `app/services/alerts.py::_check_git` |
| `git bundle --all` | Total loss of the repo. One verifiable, clonable file carrying every ref — including the `refs/backup/*` above — replicated to the standby, pushed off-rack to backup-server, downloadable | `app/services/git_backup.py` |
| Bundle delete is primary-only | Deleting on the standby, where `satom-ha-datasync --delete` would restore it within 5 min and make the UI look broken | `app/views/system_backup.py` |
| INSERT-ONLY registry seeds | A deploy overwriting endpoint/provider rows the operator corrected. A vendor moving a REST URI stays a row edit, not a release | `app/registry/loader.py`, `app/services/acme_providers.py` |

## 2. Updating code and dependencies

The web worker **never** mutates the installation. It writes a request file; the
root runner (`satom-updater.path` → `.service`) does the work. See
[`privilege-model.md`](privilege-model.md).

* **Code update** — records the current revision, applies, runs an **import
  smoke** on the new tree, restarts, health-checks. On any failure it rolls back
  to the recorded revision and re-verifies, and says so if the rollback itself
  did not recover.
* **Dependencies** — `pip` from the web is **curated-only**: the allowlist is the
  app's own `system_info._LIBRARIES`, validated at the enqueue *and* re-validated
  inside the root runner, with name and version regex checks. There is no
  `pip install <arbitrary>` path, on purpose — that would be remote code
  execution as the service account. The runner snapshots the installed version,
  installs, import-smokes, restarts, health-checks, and **auto-reverts** to the
  snapshot on failure. Restore points live per node in `data/lib-versions/`.
* **Node-local by design** — the virtualenv is not in git and not in the HA rsync,
  so the button applies to *that* node only; the card says so. The
  `requirements.txt` pin is bumped and pushed **only from the primary** (single
  git writer), so the next code update does not revert the library.

## 3. The privilege boundary

Detail in [`privilege-model.md`](privilege-model.md); the short version of what
protects you:

* The app runs as an unprivileged service account. Its `sudo` grants are an
  explicit allowlist (`nginx -t`, `systemctl reload nginx`, …) — not `ALL`.
* `User=` is pinned in a **systemd drop-in**, not in the shipped unit, so a
  self-update that replaces unit files cannot silently hand the app root again.
* The root runner is reached through a **request directory watched by a `.path`
  unit** — a queue, not a callable. The web process has no way to pass a command.
* The **operator CLI** (`/usr/local/sbin/satom`) is a root tool for a human,
  and it is installed as a `root:root` **copy** at `/usr/local/lib/satom-cli/`.
  It never executes from `/opt/satom`, because that tree is writable by the
  service account: a launcher reading code from there would let a compromised
  web worker rewrite what an operator is about to run under `sudo`. The
  installer verifies owner, mode and "not a symlink", and refuses otherwise.
  See [`cli.md`](cli.md).
* The CLI is **never** granted to the service account. `NOPASSWD` on that binary
  for the app user would equal `NOPASSWD: ALL`; `satom diagnose privilege`
  fails loudly if it finds such a line in `/etc/sudoers.d/satom`.
* `deploy/satom-node-role.sh` exists because the obvious role probe
  (`runuser -u postgres -- psql`) needs root: unprivileged, it returns empty and
  every HA guard quietly takes the "not primary" branch while systemd reports
  success. The probe now uses the app's own credentials over TCP, so it answers
  correctly at any privilege level.

## 3b. The operator console (`satom`)

The CLI is a root tool aimed at a broken node, which makes it the one place
where a careless guard does real damage. Four rules hold it.

| Guard | What it prevents | Where it lives |
|---|---|---|
| The installed CLI is a root-owned **copy** outside the app tree | A compromised web worker rewriting what the operator later runs under `sudo` — instant root, undoing the deprivilege | `deploy/install-cli.sh`, `diagnose privilege`, `test_cli.py` |
| **A read never writes** | Diagnostics creating the drift another diagnostic reports | `--no-optional-locks` on every git call; in-memory `compile()`; `PYTHONDONTWRITEBYTECODE=1` — `test_cli_ops.py` |
| **The checker and the fixer share one key set** | `diagnose install` demanding a protection `execute seed actions` never creates: a permanent red nobody can clear | `cmd_checks.MIN_ACTIONS` ≡ `cmd_fix.SEED_PLAN`, both ⊆ the real action catalogue — `test_cli_ops.py` |
| **Destructive verbs exit 2 without `--yes`** | A recovery tool becoming a footgun on a node that is already having a bad day | every `danger=True` node; enforced by `test_cli_ops.py` |

Two consequences worth stating plainly, because both were live defects found by
running the tool against a real node rather than by reading it:

* `git status` **rewrites** `.git/index`. Run as root in a tree owned by the
  service account it hands the index to root, so a *read-only* command broke
  the app's later writes. Same for `compileall`, which leaves root-owned
  `__pycache__`. Both are now side-effect free, and the guard is a count of
  `["git"` invocations against `["git", "--no-optional-locks"` — a plain
  substring test passed even after the flag was removed, because the comment
  explaining the rule contains the flag too. Mutation-tested.
* A probe against an appliance the operator **parked on purpose** must not
  raise the roll-up. Maintenance already suppresses automatic runs and their
  alerts; a console that stays red anyway teaches people to stop reading it.
  `dbq.PROBES` joins the maintenance flag and `get monitor status` reports
  those separately, under their own heading.

Nothing in the CLI is ever added to the service account's sudoers. A
`NOPASSWD: /usr/local/sbin/satom` for that account is equivalent to
`NOPASSWD: ALL`; `diagnose privilege` fails loudly if it finds one.

## 3c. The operator console's output path

The console is read on a broken node, and its output is then pasted into a
ticket. Both of those impose guards that are invisible while they hold.

| guard | what it prevents | where it lives |
|---|---|---|
| Decoration only on a TTY | escape sequences in a redirected file the operator cannot clean up | `render.Style`, gated on `isatty` + `NO_COLOR` + `TERM` |
| No truncation through a pipe | silently losing help text that has no width to be fitted to | `cmd_tree._fit` returns early when `style.width` is 0 |
| ASCII glyph fallback by stream ENCODING | unprintable box-drawing on a serial console | `render.Style.__init__` |
| ASCII fold table | a decorative em dash raising `UnicodeEncodeError` | `render._FOLD`, applied at the render boundary |
| `errors="replace"` on stdout | the same, for characters the table cannot know about (device names, cert subjects, journal lines) | `render.harden_stream`, called from `main()` |
| Verdict colours only | painting a by-design state (`inactive` datasync on the primary) as a failure | `render._V_OK/_V_WARN/_V_BAD` |
| `\001`/`\002` around prompt colour | readline miscounting the prompt width and putting the cursor in the wrong column | `main._prompt_color` |
| `show tree` renders the live registry | a documented command list drifting from the build | `cmd_tree`, plus a test that compares it to `tree.walk()` |

The second and fifth rows are two layers of the same defence on purpose: the
fold table handles what this code emits, the stream reconfigure handles what it
cannot predict. Removing either one alone still leaves the CLI standing, and
`tests/test_cli_render.py` has a mutation-verified test for each.

## 4. Two-node correctness

| Guard | Prevents |
|---|---|
| Self-update / promote endpoints refuse on the standby | Two nodes rewriting the checkout, or a split brain |
| Backup + bundle deletes refuse on the standby | Deletions that `rsync --delete` immediately undoes |
| `satom-ha-datasync` role guard | The sync running on the primary (it PULLS: it runs on the standby and is inert elsewhere) |
| Forced command on the peer SSH key | The sync key being usable as a shell |
| `data/ha_nodes.json` matched against the **hostname** | Falling back to the first entry and rsyncing the node against itself — a real incident after a hostname change |
| `_commit_quiet()` on login | A login failing on the read-only replica because it could not stamp `last_login` |
| Peer probes over HTTPS `:8443` + shared identity key | Cleartext and unauthenticated node-to-node calls (see [`encryption-and-node-tls.md`](encryption-and-node-tls.md)) |
| Postgres replication `hostssl … clientcert=verify-ca` | A downgraded or unauthenticated replication stream |

## 4b. The standby is the last live copy — do not reconcile it as a side effect

`satom-reconciler` runs in AUTO on both nodes and pulls on its own within about
a minute of a push. So a manual `git fetch && git reset --hard origin/main` on
the **standby** buys nothing that was not already going to happen, and it costs
the one thing the standby is uniquely holding.

The failure this encodes actually happened. An applied update package on the
primary reverted another session's **uncommitted** work — CSS and a template
that existed nowhere in git. It was recovered from the standby, which had not
yet been reconciled and was therefore the only surviving copy. A `reset --hard`
on the standby that day would have destroyed the recovery path, and it would
have looked like routine tidying while doing it.

The rule, in one line: **converging the standby is the reconciler's job, not an
operator's, and never a side effect of unrelated work.** Read the standby
freely — `/healthz`, `systemctl list-units --failed`, `git log`, `git status`.
Writing to it, restarting it, or resetting it is its own decision, taken on
purpose. If it has drifted, that drift *is* the finding: the reconciler should
have closed it, and the fact that it did not is what needs reporting.

| Guard | Prevents | Where |
|---|---|---|
| `diagnose git` reports **state that exists only here** — modified tracked files, commits absent from the upstream branch, parked `refs/backup/*`, untracked files | Discarding the only copy of work with an operation that looks routine. A node cannot be reset in ignorance of what it alone holds | `deploy/satom_cli/cmd_checks.py::git` |
| Only dirty tracked files and unpushed commits **grade**; untracked files are listed but do not | A permanent warn on the primary, which legitimately carries an untracked `reports` symlink. `reset --hard` does not delete untracked files, so grading them would be false as well as noisy — and the first thing a permanent warn teaches is that the check can be ignored | same |
| `preserve_local_commits()` parks local commits and the dirty tree before any update-driven reset, and **aborts** if it cannot | The automated path doing what this section forbids the manual one from doing | `deploy/self_update_runner.py` (§1) |

Two limits stated on purpose. This is a **read-out, not an interlock** — nothing
in the product refuses a `git reset --hard` typed by a root operator, and
nothing should: the operator is the authority on their own node. And an
unpushed-commit count needs an upstream branch to be meaningful, so a detached
HEAD or a branch with no upstream is reported as *cannot tell* rather than as
zero. Zero would be a comforting number the check has no basis for.

### Scratch that git can offer for staging is scratch that can be committed

The same loss has a second, quieter path into the tree. Sessions leave hidden
throwaway scripts at the repo root — `.patch_a.py`, `.smoke1.py`,
`.runsuite.sh`. Untracked and un-ignored, they are exactly what an unrelated
`git add -A` sweeps up, and that is how another session's work was swallowed by
a commit titled *apply update package*. They also bury the real signal: a
`git status` that lists thirty throwaways is one nobody reads closely enough to
notice the one modified file that mattered.

They are ignorable without judgement because a Python module name cannot begin
with a dot — a dot-prefixed file at the repo root is never importable code, so
it is always a throwaway. That is the same proof `diagnose code` uses to skip
them when deciding whether a process is stale (§24); here it decides whether
git may offer them for staging.

| Guard | Prevents | Where |
|---|---|---|
| `/.[!.]*.{py,sh,log,rc}` ignored, **anchored to the repo root** | An unrelated `git add -A` committing another session's scratch; `git status` too noisy to read | `.gitignore` |
| Guards assert through `git check-ignore --no-index`, never by grepping `.gitignore` | A rule that is present and wrong. The pattern syntax is git's, so only git can say whether a rule matches — and **without `--no-index` git refuses to report a tracked path as ignored**, which makes every "must not be ignored" assertion pass vacuously, even against a rule of `*` | `tests/test_template_staleness.py` |
| No tracked file may match any ignore rule | A tracked file that works until someone deletes and re-adds it, then silently does not come back. This found a real one: unanchored `backups/` shadowed the tracked templates under `app/templates/backups/` | same |

Verify the guards are armed:

```bash
cd /opt/satom
git --no-optional-locks check-ignore -q --no-index -- .patch_a.py   # rc 0
git --no-optional-locks check-ignore -q --no-index -- app/.probe.py # rc 1 (root-anchored)
git --no-optional-locks ls-files | \
  git --no-optional-locks check-ignore --no-index --stdin           # no output
```

## 5. Writing to the appliances

This is the part that can take a customer offline, so it has the most gates.

* **Read-only means read-only.** `ssh_ops.assert_readonly()` validates **every
  line** of a command, not just the first — a pasted `get x` / `set y` cannot
  sneak a write past a legitimate first line. Allowed verbs: `get`, `show`,
  `diagnose`/`diag`.
* **Dry-run → approval → apply.** Writes are computed as a minimal diff and shown
  before anything is sent; see [`source-of-truth-spec.md`](source-of-truth-spec.md).
* **Lease locks.** `lock_service` gives one operator a lease per (appliance,
  resource), refreshed by heartbeat, re-entrant for the same user and expiring on
  its own (default 120 s) if a tab is abandoned — so an abandoned browser never
  blocks the object permanently.
* **Change requests gate the dangerous ones.** A firmware upgrade refuses to
  flash unless its CR is approved/scheduled **and the clock is inside the
  window** — and that is re-checked at fire time by `cr_runnable()`, not only when
  the action was scheduled. Every transition stamps a timeline event.
* **Device config restore is still dry-run only** — stated here as a limit, not a
  feature.

## 6. Certificates

* **Import** parses the PEM, enforces that the **private key matches the
  certificate**, installs, runs `nginx -t`, and **rolls the files back and
  reloads** if nginx rejects them. A bad paste cannot take the web UI down.
* **ACME signing runs in a minimal environment.** The app's own environment
  carries `FERNET_KEY` and the database URI; the signer is built a curated
  passthrough instead of inheriting it. Provider credentials arrive as
  environment variables, never on the command line, and every secret is redacted
  from the stored log and from the command preview.
* **The command is a plain argv**, never a shell pipeline — no injection surface.
  Raw templates (`custom` mode) are admin-only and labelled.
* **The renewal journal is node-local** (`state/cert-renew.jsonl`, not Postgres,
  not `data/`) precisely because the node that fails to renew may be the one with
  a read-only database and a `--delete` rsync pointed at it. Each node publishes
  its own journal on `/healthz/cert-renewals`; `/cert-manager/renewals` shows both.
* `cert.renew_failed` is its own alert signal — **critical after 3 consecutive
  failures** — instead of waiting for the T-14-days expiry mail to imply it.

## 7. Files coming from outside

* Every external read/download resolves through `_safe_names()` — device and
  filename are validated, so path traversal and forged names return 404 rather
  than a file.
* Firmware pulled from the backup server is **sha256-verified** on arrival;
  bundles carry a sha256 sidecar so a copy can be trusted before it is used.
* **backup-server is a separate failure domain on purpose.** Gitea and the standby
  both live on hypervisor03; the primary on hypervisor06; the external backup server on hypervisor04.
  A single host loss can never take out every copy.

## 7b. Documentation leaving the building

Section 7 covers files arriving from outside. This one covers text going the
other way, which is the direction that cannot be undone: `site/` is pushed to
GitHub Pages by the release sync, and a published page is cached and indexed
whether or not it is deleted afterwards.

**What it prevents.** Two different rots, and one disclosure.

| Guard | Prevents | Where |
|---|---|---|
| Generated command reference | A manual that lists commands the build no longer has — read by the one person who cannot check, because their web interface is down | `deploy/gen_cli_reference.py`, markers in `docs/cli.md` |
| Generated site manual | A second, public copy of the documentation drifting from the Markdown the team actually edits | `deploy/gen_site_docs.py` → `site/docs/*.html`, `site/docs.html` |
| Redact-then-abort | Publishing internal addresses, management hostnames, hypervisor and node names, the backup server, an administrator's e-mail | `redact()` + `scan()` in `app/services/doc_publication.py`, shared by both published surfaces |
| Registry drift, reverse | Hand-written prose naming a command that does not exist | `tests/test_docs_publication.py` |

**Three rules hold it together.**

1. **Redact, then re-scan the OUTPUT, then abort.** Not warn — abort, naming
   pattern, file and line. A warning in a publication pipeline is a leak with a
   paper trail. This is the same posture as the release pipeline's secret scan,
   applied to inventory rather than credentials.
2. **Publication is opt-in.** A document absent from `PAGES` is simply not
   published. The safe default for anything describing internal topology is
   *not published*, not *published and hopefully redacted*.
3. **Product identifiers are deliberately NOT redacted.** `fadc`, `faz` and
   `fortiweb` are ADOM keys and URL segments of the product itself
   (`/fadc/api/`). Rewriting them would mangle route documentation while
   disclosing nothing — a label with no address is not an inventory. What is
   redacted is anything that helps someone *reach* a machine.

**Two failures this caught while being built**, both on real text rather than in
review:

- The hostname pattern was anchored on the leading label, so it matched
  `node-a.example.net` but not the **wildcard** `*.example.net` nor the
  **brace expansion** `satom{,-2}.example.net` — neither starts with an
  alphanumeric. The scanner refused to publish and named all four lines. It is
  now anchored on the domain.
- Placeholders written as `<ip>` were emitted as **raw HTML tags**: the browser
  silently swallows an unknown element, so 27 redactions rendered as *nothing*
  and the sentences simply lost a word. The redaction was invisible, which is
  worse than an obvious one. Placeholders are now `{braces}`, which have no
  meaning in Markdown or HTML — and match the `{helper}` / `{acme_path}`
  convention this project already uses.

**Limit, stated on purpose.** The scanner knows the identifier shapes this fleet
uses. It is a backstop against accident, not against someone who deliberately
publishes a paragraph describing the topology in prose. The opt-in `PAGES` list
is the real control; the scanner is what makes forgetting expensive instead of
silent.

## 7c. One published manual, and one that works with no network

**The application serves no documentation.** It used to serve three routes —
`/docs` behind a session, `/docs/public`, and `/docs/api` — and that was a
second rendered copy of the same Markdown standing on every management node.
It was also how the leak happened: the redact-then-scan pipeline lived inside
`deploy/gen_site_docs.py`, where the application could not reuse it, so the
application grew its own route and served `docs/api_v1.md` **verbatim** —
a management hostname and an RFC1918 address — to anyone who could load the
sign-in page.

Removed 2026-08-02. There is now exactly one published copy, on the public
site, and the sign-in page and the sidebar link straight to it.

**The trade, and what pays for it.** A management network is deliberately built
with no route to the public internet, so on the node that most needs the manual
the published copy is unreachable. That is what `satom show docs` is for: it
prints `docs/*.md` from the tree, unredacted, because whoever runs it is already
on the machine. Without that command this removal would be a regression against
the promise in `INSTALL.md` §2.2, and the offline bundle would ship a manual
nobody can open.

**What it prevents.**

| Guard | Prevents | Where |
|---|---|---|
| No in-app manual | A second rendered copy of the manual on every node, one decorator away from being public | routes removed; a test asserts `/docs*` is **404**, not a redirect |
| Shared registry | Publication rules living somewhere the rest of the code cannot reuse — which is how the unguarded route appeared | `app/services/doc_publication.py`; `deploy/gen_site_docs.py` imports it |
| Redact before render | Publishing an internal address, hostname, hypervisor, node, backup server or personal e-mail | `redact()`, applied by the generator |
| Fail-closed scan | A document whose *rendered* output still carries an identifier being published anyway | `scan()` over the OUTPUT; a finding aborts the whole build |
| Opt-in list | A document nobody reviewed becoming public by being added to `docs/` | absence from `PUBLIC_DOCS` |
| One address | The site moving and a template being left on a 404 | `pubdoc.SITE_BASE` + the `docs_url()` context processor; a test fails on a hardcoded URL in any template |
| Console catalogue derived from the tree | An isolated node having no manual because someone added a document and forgot a second list | `cmd_docs._doc_catalog()` lists `docs/`; a test compares it against the directory |

**Four rules.**

1. **The registry may exist once.** A second copy is the copy that rots. A
   structural test fails the suite if the generator re-declares the list, the
   redaction table or the scanner.
2. **Fail closed, never fail open.** A finding aborts the build. It does not
   warn and continue: a warning in a publication pipeline is a leak with a
   paper trail.
3. **Removing a web surface is only allowed with an offline replacement.** The
   console reader landed in the same commit that deleted the routes.
4. **`404`, not `302`.** A test asserts the removed paths are absent, not
   merely protected. A redirect would mean the second copy is still there.

**The test that carries the weight** is
`test_the_raw_source_really_does_carry_an_identifier`. Narrowing `redact()` and
`scan()` at the same time leaves a redact-then-scan round trip self-consistent
and green while publishing the identifier; that exact false negative was
reported as "does not bite" by an earlier mutation run in this repository. The
assertion is therefore about the **input**: `docs/api_v1.md` must still contain
something the scanner recognises, or the leak tests above have gone vacuous.

**Second-order property, easy to lose.** The four sign-in pages load their
stylesheet from `static/vendor/`, not from a CDN. This product ships offline
installers for isolated networks; a login screen that only lays itself out with
public internet does not lay itself out where it matters most.

## 7d. A cross-reference that renders is not a cross-reference that works

**What it prevents.** The manual is written as Markdown linking to Markdown —
`[the operator console](cli.md)`. That is correct in the repository and **dead
on every published surface**, because the published artefact is `cli.html` and
nothing serves the `.md`. Seventy-one such links across ten pages rendered
perfectly, sat on pages that returned `200`, and every one of them returned
`404` when followed. Consolidating the manual onto one published copy made this
worse, not better: that copy is now the only copy, so its internal navigation
being broken breaks navigation outright.

**Where it lives.** `doc_publication.relink()` — beside the registry that
decides what may be published, because the same filename → slug map answers both
questions. The site generator applies it immediately after the Markdown
conversion.

**The rule.** A link to a **published** document is rewritten to its slug, with
any `#fragment` preserved. A link to a document that is **not** published cannot
be made to work, so it is **unwrapped to its own text** rather than shipped as a
link that lies. `test_every_markdown_file_that_can_be_linked_is_published` keeps
that branch a backstop rather than the normal path.

**Both halves are required.** `test_no_published_page_offers_a_markdown_link` is
satisfied by a `relink()` that deletes every link, which would be silent
vandalism; `test_the_published_manual_actually_cross_references_itself` pins that
real cross-references survive **and** that each rewritten target exists on disk.
Rendering proves nothing here — this class of defect is only found by requesting
the target.

## 7e. What leaves the building is the MIRROR, not just the manual

Section 7b makes the published *manual* safe. It says nothing about the rest of
the repository, and for a long time nothing else did either: the public mirror
carried the internal network map in 107 files — RFC1918 addresses, management
hostnames, hypervisor and node names, the backup server — plus 25 commit
identities, two of them named after an AI assistant and three carrying a
personal e-mail address. Every one of those had passed the existing pipeline,
because that pipeline filtered **paths** (`CLAUDE.md`, `.env`, `reports/`) and
**commit messages**, and a path filter cannot see inside a file it keeps.

The redaction engine that already existed (`app/services/doc_publication.py`)
was the right mechanism applied at the wrong layer: it ran on documents on
their way to the site, not on the repository on its way to the world.

### Where the rules live, and why not here

The org-wide rules live in the **publisher** — `sync_prod.py`, on the internal
host that drives every mirror — and deliberately not in this repository.

Two reasons. They apply to every application in the catalogue, not just this
one; and a rule file inside a published repository is itself the disclosure it
exists to prevent, naming every hostname and every range it protects.

### Three layers, and the third is the one that counts

1. `--name-callback` / `--email-callback` collapse **every** author and
   committer in the whole history to one public identity. Not a hand-written
   map of known aliases: a list of identities goes stale the first time
   somebody commits under a new one.
2. `--replace-text` rewrites the **content** of every blob, across the whole
   history — not just the tip. The replacements are valid values from the RFC
   5737 documentation ranges and `example.net`, never `{placeholder}` tokens,
   so the mirror stays a repository that compiles, whose config files still
   parse and whose tests still run. A brace token inside a `.conf` produces a
   broken artefact instead of a redacted one.
3. `_scan_blobs()` re-checks the **output** and **aborts the push**.

The third layer is the point. Redacting without verifying is a hope, not a
guard: when a rule comes up short — and one did, on a live page, over a bare
`satom-node` prefix — the scan is the only thing that turns a silent
disclosure into a visible failure. A rewrite rule that is missing a case and a
rewrite rule that is working look identical until something checks.

Ordering matters inside layer 2. The shorthand pair `192.0.2.248/.249` must be
rewritten before the generic address rule, or the generic rule takes the first
address and leaves `/.249` — still an octet, and **invisible to the scan**,
because what remains is not a complete address.

### Two things the pipeline will not fix for you

**A shipped default is not a disclosure, it is a bug.** Seven values in this
repository were internal infrastructure the application actually *used* when
unconfigured: the trusted-proxy allowlist, two DNS resolvers, the certificate
domain suffix, two Firecrawl endpoints and the installer's clone URL. Redacting
those at publication time would have produced a mirror that leaked nothing and
still shipped somebody else's network as its factory settings — and in the
trusted-proxy case, granted an unrelated host on any overlapping `10/8` the
right to forge the client address used for rate limiting and audit. These are
fixed at the source. **A default that names infrastructure belongs to
configuration, and the deployment that relied on it gets a settings row.**

**A test that proves the scanner bites must contain what it detects.** The
adversarial corpus is the one thing here that cannot survive redaction and stay
meaningful, so it lives in `tests/fixtures/internal_identifier_samples.json`,
the publisher drops it by path, and the tests that read it **skip with a
reason** rather than failing on a mirror that correctly has nothing left to
find. Everything else in `tests/` is rewritten in place; where a fixture
happened to sit in a real range for no reason, it moved to the documentation
range instead — inert test data has no business naming a routable network.

### The rule table was the last file naming the estate

Everything above assumed the sanitiser itself was safe to publish. It was not,
and it hid behind its own escaping.

A rule written with a `\b` anchor contains, as TEXT, the letter `b`
immediately before the name it matches. So a `\b`-anchored rewrite rule cannot
match its own escaped form, and a `\b`-anchored scanner cannot flag it either.
Both agreed; both were wrong; and the node names rode out to the public mirror
inside the very module that exists to stop them. This is the same failure the
round-trip test was already known not to catch: narrowing `redact()` and
`scan()` together leaves them self-consistent and green.

So the site-specific names left the source. What stays in code is generic and
always fires -- address ranges and personal e-mail. What identifies THIS
deployment (node names, hypervisors, the backup host, the management domain)
is read from `publication-rules.local.json`, an untracked file beside the
application. On a published mirror it is simply absent, and there is nothing
site-specific left there to redact anyway.

The obvious risk is fail-open: absent the overlay, redaction weakens AND the
scanner stops flagging the same class, which is a matched pair that hides
itself. Two things bound it. The generic rules -- the addresses, the strongest
signal -- are still in code and unconditional. And the internal suite asserts
the overlay is present, so a node that loses it fails loudly instead of quietly
redacting less.

Two scripts are excluded outright rather than rewritten. They are wired to one
appliance by database id, to absolute paths on one host and to a local `.env`,
they take no arguments, and one carries a shared secret in clear text.
Rewriting their literals yields a script that still cannot run anywhere else —
so the honest treatment is removal, not redaction.

## 7f. The licence has to say the same thing on every surface

**What it prevents.** SATOM declares its licence in eight places: `LICENSE`,
`NOTICE`, `README.md`, `CONTRIBUTING.md`, `DISCLAIMER`, `SECURITY.md`, the six
hand-written pages under `site/`, and the footer template inside
`deploy/gen_site_docs.py` that stamps the generated documentation pages. Nothing
*fails* when one of them goes stale — the statement simply becomes false. That
is exactly how `Version: 1.0` survived four releases in the README while the
console, the pipeline and the public site all said something else. A licence
that disagrees with itself is worse than a stale version string: a reader who
acts on the wrong surface is relying on a grant that was never made.

**Where it lives.** `tests/test_license_consistency.py`, twenty-seven guards.

**The rules.**

- `LICENSE` must carry the **operative sentence** of the current licence, not
  merely its name — a header that says "Elastic License 2.0" over an Apache body
  passes a name check and fails a reader. The assertion runs against
  whitespace-collapsed text, because the licence body is hard-wrapped at ~80
  columns and any sentence spanning a line break silently fails against text
  that is perfectly correct.
- The markers unique to the **old** licence body must be gone. The scope header
  is still allowed to *reference* Apache-2.0 — it has to, to say which terms
  earlier copies were received under — so the guard pins the body markers, not
  the word.
- The five declaring files may not name the old licence at all, and may not
  **claim** SATOM is open source. ELv2 is source-available, not OSI open source.
  The guard matches affirmative claims (`open-source project`,
  `is free, open-source`, …) and deliberately **not** the bare phrase: matching
  that would ban the very sentence that sets the record straight ("not an OSI
  open-source license").
- Site pages are checked **through their footer**, never whole-page. The body of
  a generated page is rendered from Markdown that may legitimately discuss the
  old licence — the changelog entry announcing the change does exactly that.
- The generator's footer template and the hand-written pages must produce the
  **same string**. Two authors of one sentence is how `index.html` silently lost
  its Docs link once already.

**The published history is a surface too.** `main` saying ELv2 does not stop a
tag from offering Apache-2.0: a tag is itself a public offer of terms, and every
release tag kept handing out the old grant on the exact refs a downstream reader
is most likely to pin. Re-pointing a tag at the sanitised history is not enough —
that moves the ref, not the bytes. The publisher (`sync_prod.py`,
`_sanitized_mirror`) therefore rewrites the `LICENSE` blob and the five declaring
files across the **whole** published history, and `_scan_license` **aborts the
push** if any reachable `LICENSE` blob still carries the old body — once against
the mirror before pushing, and once against a fresh clone of the remote after.

Four things about that rewrite are deliberate:

- It is **not** a blanket substitution of the string `Apache-2.0`. `CHANGELOG.md`,
  `docs/` and `tests/` *record* the change rather than declare the current terms;
  a blind pass turns "changed from Apache-2.0 to the Elastic License 2.0" into a
  tautology and breaks the guards that pin the old markers on purpose. The
  boundary is the one this section already draws.
- The replacement text is lifted **verbatim from the relicensing commit**, so a
  rewritten tag says exactly what `main` says rather than a wording invented by
  the publisher. Variants for the project's earlier names are *derived* from that
  same table — a second hand-written copy goes stale the moment a sentence moves.
- The scan enumerates **blobs, not ref tips**. The mirror carries no tags at all
  (they are minted on the remote by the release API), so a ref-based scan would
  look at two branches, come back green, and leave the whole history in the old
  licence. It also reaches intermediate commits, which are just as checkoutable
  as a tag.
- The whole-file swap only fires on a `LICENSE` that really **is** the old body,
  so a repository that never left it — or that moves to a third licence later —
  is left alone instead of silently mis-stamped.

A caveat worth stating plainly: rewriting a tag changes what the repository
*shows*, not what a recipient already received. Anyone who fetched a release
before the change holds a copy under the terms they received, and keeps it.
`LICENSE` says so in its scope header.

**A trap this rewrite walks past.** `git-filter-repo` stops applying
`--replace-text` by itself once a `--file-info-callback` is present — it exports
with `--no-data`, so the callback owns the redaction. Dropping that one call
would silently switch off the entire internal-identifier filter while every log
line still read "OK". The blob scanner catches it, and the mutation harness
proves it does.

**Known limit, on purpose.** These guards pin what the project *says*. They
cannot pin what a recipient already holds: a copy distributed under an earlier
licence stays under the terms it was received under, and no test changes that.
`LICENSE` states it in the scope header rather than leaving it implied.

## 7g. The release notes are the changelog, split — never a second copy

`CHANGELOG.md` was published whole, as one page. It is a thousand lines, so the
question an operator actually asks — *what shipped in 1.3.3, and do I need it?*
— could only be answered by scrolling. The site now carries a **Release notes**
section with one page per version.

The obvious way to build that is to write the pages. That is also how a manual
starts lying: a second copy of something the repository already knows goes stale
silently, because nobody gets a stack trace from documentation. So every fact on
those pages is derived from the Markdown — the version list is the changelog's
own `## [x.y.z]` headings **in file order**, the dates are its own dates, the
teaser lines are the bold lead-ins of its own bullets, and the *current release*
badge is the repo-root `VERSION` file. Nothing is typed twice, so nothing can
disagree.

| Guard | What it prevents | Where |
|---|---|---|
| `--check` fails when a page differs from its section | editing the changelog and forgetting the site | `deploy/gen_release_notes.py` |
| orphan pages are deleted, and their presence fails `--check` | a version renamed in the changelog leaving its old page serving forever | same |
| the hub's link list must equal the heading list, in order | a version published but unreachable, or a link to a page that does not exist | `tests/test_release_notes_pages.py` |
| the *current release* badge is read from `VERSION` | the number that sat at `v1.0` for four releases | same |
| the unreleased section may not carry the *current* badge | merged-but-not-cut work presented as shipped | same |
| `redact()` then `scan()`, and a survivor **aborts** | publishing an internal identifier in a changelog entry | `gen_release_notes.main` |

Two further notes, both learned the hard way while writing this:

- **The two halves of the leak guard are both required.** A single test that
  plants an identifier and expects an abort passes trivially — `redact()`
  removes it first, which is the pipeline working. That test is satisfied by a
  `redact()`/`scan()` pair narrowed together until neither sees anything, which
  is exactly how identifiers have reached the public mirror before (§7e). So
  there is one test that redaction really removes each forbidden class, and one
  that neutralises redaction and requires the build to refuse.
- **A generator test must sandbox both ends.** Redirecting only the input still
  writes to the real destination: the first version of that test deleted the
  fourteen pages it existed to guard.

`docs/release_notes.md` is a **different document** — the vendor's known-issue
corpus behind the upgrade advisor. It no longer calls itself "Release notes" on
the site, and a test enforces that: two things with one name is how an operator
plans an upgrade from the wrong document.

---

## 8. Sessions and the web surface

| Guard | Detail |
|---|---|
| Content-Security-Policy | Per-request **nonce**; `script-src-attr 'none'` — inline `on*` handlers cannot run, so an injected attribute is inert |
| Frame / sniff / referrer | `X-Frame-Options: DENY`, `nosniff`, `strict-origin-when-cross-origin` |
| Authenticated HTML is `no-store` | A stale nav or page cannot survive a deploy in the browser cache |
| CSRF | `CSRFProtect` app-wide; JS reads the token from the meta tag |
| Per-IP rate limits | sign-in 5/min · 2FA challenge 10/min · password recovery 5 and 10 per 15 min · `/api/v1` 30/min |
| Per-account lockout | 10 failures → locked 15 min. Complements the IP limit, which cannot isolate a distributed attack on one account |
| Local accounts never fall through to the directory | An AD account with the same name cannot take over the seed admin |
| Anti-lockout on access admin | The guards refuse the change that would leave **zero** active admin-capable users |
| Docs / plugin routes | Slugs validated against an allowlist and the resolved path re-checked inside its directory |
| TOTP + backup codes | Second factor for local accounts; directory accounts do MFA at the directory |

## 8b. Operator-supplied theming

Settings → Appearance lets an admin repaint the console. That means operator
input reaches a `<style>` element carrying the app's own CSP nonce, and it means
an operator can make the console unreadable. Both are guarded.

| Guard | What it prevents | Where |
|---|---|---|
| Per-**kind** value allowlist (`color`/`length`/`shadow`/`transition`/`font`) | A token value escaping its declaration — `}` would close the rule and open a new one, nonce included | `theme_service.VALIDATORS` |
| Shared reject list (`;{}<>`, `url(`, `expression(`, `@import`, `javascript:`, newlines) | The wider kinds. A colour pattern stops everything alone, but `shadow`/`font` legitimately allow letters and parentheses, so `url(evil)` matches the shadow character class | `theme_service._FORBIDDEN` |
| `css_for()` re-validates on **emission** | A hostile row that never went through the form — restored backup, replica, hand-edited `psql` | `theme_service.css_for` |
| Only overrides are stored | A theme freezing a snapshot of an old palette and silently diverging from stylesheet improvements | `validate_tokens` drops values equal to the default |
| Registry generated from the stylesheet, `--check` in the suite | A new `--fw-*` variable leaving the editor silently missing a control | `deploy/gen_theme_tokens.py`, `tests/test_theme.py` |
| Contrast audit; below 3.0:1 needs explicit confirmation | Applying an unreadable palette **without being told**. It warns rather than blocks — an operator may accept a low-contrast accent | `theme_service.audit_contrast` |
| Built-ins immutable; deleting the active theme falls back | Locking yourself out of the page that would fix it | `settings.update_theme` / `delete_theme` |
| Brand assets: bare filename only, SVG sanitised, rasters re-encoded | A stored path escaping `data/branding/`, and script-carrying SVG in the DOM | `settings.theme_asset` / `_save_theme_asset` |

**Recovery, in order of how broken things are:** Settings → Appearance → *Revert
to the shipped look* · activate any built-in · `satom execute reset theme` from
a shell when the UI is unusable.

**Limits, stated on purpose.** Status badges and some decorative tints still
carry literal colours in the stylesheet, so a dark canvas is not offered — it
would leave those elements light. And the path-separator check on brand assets
is a *second* layer: werkzeug's `safe_join` refuses traversal on its own, so the
test asserts the 404 outcome rather than which layer fired.

## 8c. The public site's theme layer

The marketing site is static: no server, no database, no session. Its themes are
CSS custom properties plus one key in `localStorage`. That simplicity removes the
injection surface of section 8b entirely -- and introduces three different ways to
ship something broken, each of which has happened at least once.

| Guard | What it prevents | Where |
|---|---|---|
| Two accent slots: `--accent` (canvas) and `--accent-on-chrome` (nav/footer) | One "brand colour" painted on both a light and a dark background. The wordmark shipped at 1.65:1 -- rendered, and legible to nobody | `site/assets/site.css`; `test_canvas_accent_is_never_painted_on_the_chrome` |
| Every theme block must define the identical token set | A theme that omits a token silently inherits the previously applied theme's value, so "switch to dark" leaves light-canvas colours behind with no error | `test_every_theme_defines_the_same_tokens` |
| WCAG AA asserted per theme, per text pair | A palette that looks right in one theme and fails in another. Contrast is not a property of a colour, it is a property of a pair | `test_theme_passes_wcag_aa_on_every_text_pair` |
| Blocking theme read in `<head>`, before first paint | The stored theme applied after paint: the page flashes the default and flips. A deferred script cannot avoid this | `test_page_bootstraps_the_theme_before_paint` |
| `applyTheme` rejects unknown names | A value left in `localStorage` by an older release written straight into the DOM | `test_js_only_accepts_known_themes` |
| Gradient-valued tokens barred from `border-color`/`outline-color` | CSS drops the declaration silently; the border simply disappears. Hence `--cta-bg` (paint) and `--cta-edge` (solid) | `test_no_gradient_is_used_where_css_needs_a_solid` |
| Generator and hand-written pages asserted against the **same** expectations | The generator drifting: it kept emitting the company shield in its nav long after the product mark landed on the six curated pages | `test_generator_matches_the_hand_written_pages`, `test_page_uses_the_product_mark_not_the_company_shield` |
| Brand mark must keep an alpha channel with transparent corners | Flattening the mark re-adds the plate and frame it deliberately does not have | `test_brand_mark_keeps_its_transparency` |

**The generator is an f-string.** Its HTML template is interpolated, so a literal
`{` in emitted JavaScript must be doubled or the module will not even import. A
test asserts the escaping, because the failure is a hard `SyntaxError` in a file
nothing imports at collection time -- the exact shape of the defect that put a
broken `cert_service.py` into two published bundles.

**Default without JavaScript.** `:root` carries the default theme's values, not
just `html[data-theme="aurora"]`. With scripting disabled the site renders
correctly rather than unstyled.

**Not guarded, on purpose.** The stored preference is per browser; there is no
server to hold it. A visitor's choice does not follow them across devices, and
the console's theme (section 8b) is a separate setting with a separate store.

## 8d. The product icon, on every surface

A rebrand is only finished when the icon in the tab has changed. Three defects
found on 2026-08-02, after the palette and the logo were already live, show why
this needs guards rather than a sweep:

- The ADOM chooser -- the FIRST page after login -- still served the *vendor*
  mark as both its favicon and its header logo. No text sweep for the old
  project names could ever find it: the filename says neither.
- `/favicon.ico` returned 404 on all three hosts. Browsers request that path on
  their own, regardless of any `<link rel="icon">` tag, and they cache the
  ANSWER -- a 404 included. A missing route is exactly why a stale icon
  outlives a rebrand.
- The shipped fallback itself was the vendor logo, so any install with no theme
  asset served someone else's brand.

The rules:

- **No live template may reference the vendor mark.** Editor backups
  (`*.bak*`, `*.pre-*`) are excluded -- they are not surfaces.
- **The bare-root `/favicon.ico` must answer.** The active theme's favicon
  wins; the shipped product mark is the fallback, so a fresh install with no
  theme asset still gets the product icon.
- **The `.ico` carries 16/32/48 and keeps its alpha.** One opaque bitmap is why
  rebrands look half-done: the browser upscales it and the square plate fights
  every tab strip. The mark reads on light and dark tabs because 47% of its
  opaque pixels are bright (mean luminance 109 at 16px) -- measured, not
  assumed.
- **Every site page declares it, generated pages included.** The docs generator
  is a separate surface and has drifted from the curated pages before.

Guards: `tests/test_favicon.py`. Verified by mutation -- reverting the chooser,
deleting the route, flattening the `.ico` to one size, dropping the link from a
page, or reverting the generator each fails a test.

## 8e. Brand gradients, and assets a browser cannot keep stale

Two guards added together, because they failed together: the console could not
express a gradient at all, and the public site could serve a stale script that
made a working control look broken.

**Gradients are a token kind of their own** (`gradient`), validated by a
structural pattern — `linear-`/`radial-gradient` with an optional direction and
two to eight colour stops — not by a character allowlist. A character allowlist
would admit any CSS function name; the shared reject list only stops `url(`
because it happens to be listed. A companion test asserts the *pattern alone*
refuses every escape, so the guard cannot silently start depending on the list.

Three structural rules are enforced by tests rather than by review:

- a gradient is never fed to `border-color` / `outline-color` /
  `text-decoration-color` / `column-rule-color`, which discard it **silently** —
  the border disappears rather than changing colour;
- a gradient token never gets a contrast partner, because the auditor
  composites two flat colours and a ramp has neither;
- every non-default built-in states its own gradients and glows, since a theme
  stores only what it changes and would otherwise inherit the shipped ramp.

**Built-in themes are reconciled on boot**, while operator rows stay
insert-only. Built-ins are code — the UI refuses to edit or delete them — so a
drifted row has no intent worth preserving. Without this, an install created
before a palette change keeps the old built-in with `tokens = {}`, and "no
overrides" means "whatever the stylesheet is": the recovery theme would render
the very palette it exists to escape.

**Site assets carry a content hash.** The static site is served by nginx with no
`Cache-Control` and no `Expires`, so browsers fall back to heuristic freshness.
That is survivable for a stylesheet and fatal for behaviour: the theme picker is
markup in the HTML and handlers in `assets/site.js`, so a visitor with fresh
HTML and a cached script sees three swatches that do nothing — which reads as a
broken feature, not an old cache. `deploy/stamp_site_assets.py` rewrites every
reference to `site.css?v=<sha256[:10]>`; the generator emits the same hash, and
`tests/test_site_assets.py` fails on any bare or stale reference. The hash is
derived from content, never from a version constant a change can forget to bump.
No server configuration is involved, so it also holds on GitHub Pages, where the
headers are not ours.

## 8f. Content is never hidden by an animation

The public site fades sections in on scroll: `.reveal` starts transparent and an
`IntersectionObserver` adds `.in` when the section enters the viewport. Applied
to a documentation page this **blanked the manual**. The observer reports
`intersecting area / ELEMENT area`, so a section taller than the viewport can
never reach a fractional threshold — at `threshold: 0.12` a 35 000 px page in an
813 px viewport tops out at **2.3 %** and stays invisible however far you
scroll. The longer and more important the manual, the more certain the failure.
Nothing errored: the HTML was complete, the server returned 200, and every
published-content test passed, because the defect lived entirely in presentation.

Three independent guards, any one of which keeps the page readable:

- **Content is visible by default.** `.reveal` is `opacity: 1`. Only
  `html.js .reveal` hides, and that class is set by a blocking inline script in
  the head. A blocked, stale, or CSP-stripped `site.js` therefore cannot blank a
  page.
- **The flag is withdrawn if the un-hiding code never runs.** `site.js` sets
  `window.__satomReveal`; the head bootstrap removes `html.js` after 2.5 s if
  that flag is absent. This closes the inverse hole — the head arms the hiding,
  so a 404 on `site.js` would otherwise re-blank everything.
- **`threshold: 0`.** Any pixel on screen reveals the section, whatever its
  height.

Rule: an animation may change *how* content arrives, never *whether* it does.

### Verifying the guards are armed

### The installer does not reload nginx it just started

    grep -nE '^[[:space:]]*systemctl[[:space:]]+reload[[:space:]]+nginx' \
        installers/install-satom.sh     # must print nothing
    grep -c 'SATOM-NGINX-START' installers/install-satom.sh   # must be >= 1

On a freshly installed standalone node, `satom diagnose nginx` must report
`peer channel :8443  state  n/a - standalone, no peer` and the check must be
`[ok]`, not `[warn]`.


    pytest tests/test_site_reveal.py -q

and, against a served page, assert the section is actually opaque rather than
merely present in the markup — the original bug is invisible to any check that
only greps the HTML:

    chromium --headless=new --dump-dom <page-url>   # plus a probe reading
                                                    # getComputedStyle(...).opacity

### Sealed recovery custody (32)

```bash
# 1. Is there an envelope, and does it hold THIS node's current keys?
sudo satom diagnose recovery

# 2. The envelope must be under data/ -- the only directory both the HA
#    datasync and the backup bundle carry. Anywhere else is carried by neither.
ls -l /opt/satom/data/recovery/seal.json      # expect 0600

# 3. It must contain no plaintext. Neither secret may appear in it.
sudo grep -c "$(sudo grep '^FERNET_KEY=' /opt/satom/.env | cut -d= -f2)" \
     /opt/satom/data/recovery/seal.json       # expect 0

# 4. The bundle must actually carry it -- not merely mention it.
tar tzf /opt/satom/data/system_backups/$(ls -t /opt/satom/data/system_backups \
     | head -1) | grep recovery-seal.json

# 5. The passphrase must not be anywhere on disk. This must print nothing.
sudo grep -rl "$SEAL_PASSPHRASE" /opt/satom /var/log/satom 2>/dev/null

# 6. Round trip. Wrong passphrase must be refused.
SATOM_SEAL_PASSPHRASE='<yours>' sudo -E satom execute unseal recovery --yes
```


## 8g. A badge is pinned to the glyph, not to the padded hit area

The unread-count bubble on the topbar bell was positioned with Bootstrap's
`.top-0 .start-100 .translate-middle`. Those utilities anchor to the offset
parent's **border box** — which is the button's padded hit area, not the icon
inside it. The bell button measured 34x28 while the bell glyph measured 14x16,
so the bubble sat against the top edge of the bar, ~14 px clear of the bell it
was supposed to annotate, and 1 px inside the user menu next to it. Read as
"the bell moves up and loses its formatting" — the bell never moved.

The root cause was one line further down: `.fw-topbar-btn` declared no
`display`. The search button is a direct flex child of `.fw-topbar-actions` and
gets blockified by the flex container; the bell lives inside a `.dropdown`
wrapper, stays `display: inline`, and inherits a different box. Two buttons in
the same toolbar with different hit areas, and an absolutely positioned child
anchored to a box that does not match its glyph.

The guards (`tests/test_topbar_bell.py`):

- **The button declares its own box.** `display`, `align-items`,
  `justify-content` and `position` are asserted on `.fw-topbar-btn`, parametrized
  one test per property. Without them the bell silently reverts to
  `display: inline` and the bubble drifts again.
- **No positioning utility may anchor the bubble.** The markup between the bell
  anchor and its closing tag must not carry `translate-middle`, `top-0` or
  `start-100`. This is the exact mechanism that failed; a test asserting only
  "the bubble exists" would have passed throughout.
- **One definition, two consumers.** The bubble is styled once in the stylesheet
  and consumed by both the server-rendered markup and the live poller in
  `base.html`. A test counts the rule and fails on a second one, because two
  definitions drift.
- **The poller queries the class it creates.** A selector/className mismatch does
  not throw — it appends a *second* bubble on every poll, so the page degrades
  the longer it is left open.
- **Geometry stays in the stylesheet.** The poller may not inline `style` on the
  bubble: the theme engine owns `--fw-danger` and `--fw-topbar-bg`, and an inline
  literal is invisible to it.
- **End to end**, a rendered page with an unread notification must carry the
  dedicated class.

Rule: an absolutely positioned annotation is anchored to the thing it annotates.
If the offset parent is a padded hit area, the badge is describing the padding.

### Verifying the guards are armed

    pytest tests/test_topbar_bell.py -q

Markup alone cannot show this defect — the bubble is present and correct in the
HTML in both the broken and the fixed state. Measure it in a browser: mirror the
rendered page, then compare the bubble's box against the glyph's.

    chromium --headless=new --no-sandbox --ignore-certificate-errors \
      --window-size=1280,900 --dump-dom file:///tmp/page_probe.html
    # probe: getBoundingClientRect() of `.fw-notif-badge` and of the bell `i.bi`

The bubble must overlap the glyph's top-right corner, sit clear of the adjacent
menu, and every `.fw-topbar-btn` in the bar must report the same height.

## 9. The alert catalog

Everything above is only useful if silence means healthy. The signals that exist
today (`app/services/alerts.py`, thresholds under Settings → Alerts, per-signal
cooldown `alerts.cooldown_hours`):

| Signal | Fires when |
|---|---|
| `cert.expiry` / `cert.error` | The service certificate is inside `alerts.cert_days` / cannot be read |
| `cert.renew_failed` | A renewal attempt failed — critical from 3 consecutive |
| `git.ahead_unpushed` | Unpushed commits older than `alerts.git_ahead_max_hours` (critical at 8×) |
| `git.behind` / `git.diverged` / `git.error` | Behind past `alerts.git_behind_max`; both ahead and behind; repo unreadable |
| `backup.none` / `backup.stale` / `backup.error` | No bundle at all; none within `alerts.backup_max_hours`; the check itself failed |
| `device.health.<name>.<status>` | A device is degraded or critical on the Fleet-health ladder — one finding per device, every failing signal listed |
| `device.error` / `device.error.<name>` | The appliance list, or one device's health roll-up, could not be read |
| `action.broken.<id>.<status>` | A scheduled action is failing repeatedly (`alerts.action_fail_streak_crit`, default 3) or is overdue past `alerts.action_overdue_hours` — see §9l |
| `action.error` / `action.error.<id>` | The scheduled-action check itself, or one action's run history, could not be read |
| `drift.error` | The drift comparison could not run |
| `engine.error` | The alert engine itself failed — the guard on the guard |

### 9b. A health badge that can never go red is not a guard

**What it prevents.** Monitoring → Fleet health scored each appliance card
*only* from capacity headroom. No appliance in this fleet has an admin cap, so
every headroom row graded `nocap`, the roll-up loop could never reach
warn/crit, and a device that was powered off, whose hourly harvest had been
failing for days, and that had no cached configuration at all still rendered
**healthy** (found 2026-07-28 on an appliance that had been off the network for
weeks). A page that is structurally incapable of delivering bad news trains the
operator to stop reading it.

**Where it lives.** `app/services/device_health.py`. The badge is now the worst
of four signals, and every non-ok signal is printed on the card so the state is
never unexplained:

| Signal | Warns | Critical |
|---|---|---|
| `sync` — last `SyncRun` rows | one failed harvest | `ERROR_STREAK_CRIT` (3) in a row |
| `cache` — newest `DeviceSnapshot` | nothing cached, or older than `monitoring.stale_hours` (6 h) | older than 4× that |
| `probe` — enabled deep monitors | a probe alerting, or *all* probes disabled | a probe critical |
| `capacity` — headroom | over `capacity.warn_pct` | over `capacity.crit_pct` |

Two design rules carry the guard:

* **`unknown` is its own state**, ranked below `ok`. A device we have measured
  nothing about renders `unknown`, never `healthy`. Uncapped object types and a
  device that has never been harvested produce `unknown`, not a free pass.
* **A disabled probe is not a passing probe.** Switching off a monitor that
  always fails removes coverage, and the card says so.

**The badge and the mailbox share this ladder.** A guard that only paints a
page is a guard nobody is watching at 03:00. `alerts._check_devices` grades
every appliance with `device_health.collect_for()` — the same four signals,
the same thresholds — and adds a fifth that the page structurally cannot have:
a live TCP probe. Before 2026-07-28 that probe was the *whole* device check,
which is why fw6 and fw7 could answer `:443` for a week with a dead harvest and
never produce a single mail.

Three rules keep the two surfaces honest:

* **One device, one finding.** Every failing signal is a line in the message,
  never a separate mail. Five signals about one dead box is noise that gets
  filtered, and a filtered alert is a disabled alert.
* **The severity is the badge.** `crit` on the page is `critical` in the mail.
  If they can disagree, the operator learns to trust neither.
* **The status is part of the cooldown key** (`device.health.<name>.<status>`).
  A device that degrades from warn to crit inside `alerts.cooldown_hours` still
  reaches the operator; a fixed key would suppress exactly the escalation the
  alert exists for.

The floor is operator-tunable (`alerts.device_min_status`: `warn` default,
`crit` to mail only on critical) — a volume knob, not an off switch, because
silencing warnings is a decision that should be visible in Settings rather than
achieved by ignoring mail.

**How to check it is armed.** `GET /monitoring/data` and confirm each device
row carries a `health` block with `signals` and `reasons`, and that
`worst == health.status`. For the alert side, Settings → Alerts → *Preview now
(no send)*, or:

```bash
flask shell -c "from app.services import alerts; print(alerts._check_devices())"
```

A device that renders red on the page and returns nothing here means the two
ladders have diverged. `tests/test_device_health.py` asserts the badge
regression (uncapped + unreachable + never cached must not be `ok`) and
`tests/test_alerts_device_health.py` asserts the alert one (a device whose port
answers but whose harvest is failing must still produce a finding).

### 9c. An ADOM shows its own product, and nothing about the manager

Monitoring (Fleet health · Metrics · Deep monitors) lives in every ADOM. What an
ADOM must NOT inherit is the manager's own diagnostics — HA peers, the Git SoT,
the external backup server, the local database, the systemd units, the
encryption posture. Those describe the SATOM installation, not FortiWeb or
FortiADC or FortiAnalyzer, and rendering them inside a product view puts node
hostnames and infrastructure addresses on a page whose whole promise is "this is
your product".

Three rules:

* **The template is not the enforcement point.** `{% if is_global %}` hides the
  sections; `/monitoring/data` also *omits* `system`/`services`/`db`/
  `redundancy` outside Global (the collection is skipped, not filtered), and
  `/monitoring/infra` and `/monitoring/encryption` answer **403**. A hidden card
  whose endpoint still answers is a hidden card, not a scoped one.
* **Scoping is by device kind, never by who created the row.** Every page
  filters through `visible_appliances()`, so a probe created from Global against
  a FortiWeb box appears in the FortiWeb ADOM with no extra bookkeeping.
* **Fleet-wide ACTIONS are scoped too, not just the views.** Both "Scan
  hardware (SSH)" and Deep monitors' "Probe now" default to *everything* when
  nothing is selected, and both then open an SSH session per device. The target
  list is resolved in the request (where the ADOM exists) and passed to the
  worker thread; an unscoped `Appliance.query` inside the worker would log into
  the FortiADC and FortiAnalyzer boxes from the FortiWeb ADOM. Global keeps
  `ids=None` so the scheduler's own due/force semantics are untouched.

**How to check it is armed.** From a product ADOM:

```bash
curl -sk -H 'X-ADOM: fortiweb' https://<node>/monitoring/infra        # expect 403
curl -sk -H 'X-ADOM: fortiweb' https://<node>/monitoring/data | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["scope"], \
    [k for k in ("system","services","db","redundancy") if k in d])'  # fortiweb []
```

`tests/test_adom_monitoring.py` pins all of it: the pages answer in all three
ADOMs, each sees only its own devices and probes, the manager sections and their
endpoints are Global-only, and neither fleet-wide action can reach out of its
ADOM.

### 9c-bis. An alert about a device belongs to that device's ADOM

`alerts.run()` executes in a background thread (`satom-alerts.timer`), so there
is no request context and `product_scope.stamp()` returns `''` for everything it
raises. An unscoped notification is visible in the FortiWeb ADOM **by
construction** (§9c: `''` predates stamping and is FortiWeb-era). The result:
every alert about `fadc` and `faz01` rang the FortiWeb bell. On 2026-07-28 that
was 132 of 145 rows on the primary, and the operator reported the FortiWeb ADOM
as flooded.

The rule: **a device finding's ADOM is the DEVICE's `kind`, never the session's.**
`alerts._product_of(appliance)` maps the kind, and `run()` forwards
`finding["product"]` to `notifications.push_many`. Applies to every per-device
check — `_check_devices` (health + roll-up error) and `_check_drift`. Findings
about the manager itself (cert, git, backup) keep the old behaviour and stay
unscoped on purpose: they concern the installation, not a product.

An unrecognised kind maps to `''`, not to a guess — failing open into the
catch-all is recoverable, filing a FortiWeb alert under FortiADC is not.

**How to check it is armed.**

```bash
psql -h 127.0.0.1 -U <db-user> <db> -c \
  "select coalesce(nullif(product,''),'(unscoped)'), count(*) \
     from notifications where title like 'Device %' group by 1;"
# expect one bucket per device kind, no '(unscoped)' for new rows
```

`tests/test_alerts_product_scope.py` pins the three kinds, the unknown-kind
fallback, and the end-to-end hand-off into the notification layer (a finding
that carries the ADOM but writes an unscoped row is the same bug).

### 9d. A scheduled run says whether it RAN, not whether it liked what it found

`_do_deep_monitor` used to return `ok = worst in ("ok", "unknown")`. One server
policy with every backend down therefore marked the *Deep monitors — probe
sweep* scheduled action **failed**, and kept it failed until somebody repaired
the backend. Two things break at once when a run status carries a finding:

* a sweep that genuinely could not execute becomes indistinguishable from a
  healthy sweep that found something real, and
* the action sits permanently red, which is precisely how an operator learns to
  stop reading it — the same failure mode as a probe left pointing at a
  powered-off appliance.

`ok` is now `True` whenever the sweep completed; the worst status and the
per-status counts go in the summary, and every finding keeps its own probe row,
page badge and alert. A sweep that truly fails still raises and `run_action`
catches it.

**Where:** `app/services/scheduled_actions.py::_do_deep_monitor`.
**Tests:** `tests/test_deep_monitor_api.py::test_sweep_action_stays_ok_when_a_probe_is_critical`
(verified by mutation — reverting the flag fails it).

### 9e. Runtime telemetry survives a licence lock, and never invents a number

The four REST-monitor probe kinds (`sessions`, `policy_sessions`, `throughput`,
`transactions`) read the appliance's monitor API and open no SSH session. Three
rules hold them honest:

* **A licence-locked device is still measurable.** Every *cmdb* read on fw6/fw7
  returns HTTP 423 `-20010`, which is why their hourly `device_sync` has been
  failing for days — yet `system/status.systemresource`, `policy/policystatus`
  and `policy/policytraffic` all answer 200. Discovery therefore reads the LIVE
  `policystatus` rather than the harvest cache; discovering from the cache would
  have created zero probes on exactly the devices that most need them.
* **Wrong product fails loudly.** FortiADC and FortiAnalyzer publish runtime
  telemetry under entirely different paths. `_api_client` refuses any device
  whose `kind` is not FortiWeb and returns `error` with the product named,
  because a shared client would have reported a confident **0 Mbps** instead.
* **Absent data is never health.** A disabled policy grades `warn`, not `ok`
  (a policy admitting no traffic *is* the outage); an empty transaction bucket
  list grades `error`, not `ok`, because the appliance answers `errcode 0` with
  no rows when the policy name is unknown; and throughput is graded on the
  window **peak**, not the mean, so a four-second burst is not averaged away.

* **A zero that cannot be a zero is not a zero.** VERIFIED on fortiweb08 under
  a measured load test (2026-07-28): a policy carrying **~2 700 req/s** reported
  **0** transactions in every bucket of `system/status.httptransactions`, and
  reported **417 059** the instant a `web-protection-profile` was attached to
  it. Nothing else changed, and enabling the global traffic log beforehand made
  no difference. [Probable] the per-policy counter is keyed off the protection
  profile. Whatever the mechanism, an all-zero result on a policy that
  `policystatus` shows carrying sessions or connections now grades **warn** and
  names the likely cause. The cross-check call is made **only when the count is
  zero**, so the healthy path costs nothing, and a failure of the cross-check is
  swallowed — a refinement of the grade must never turn a working probe into an
  error.

Known limit, stated rather than hidden: no endpoint in the appliance's entire
non-cmdb API surface exposes daemon or process state. The runtime `policy`
handle is carried in the policy fingerprint and *would* change if proxyd
rebuilt its policy table, but that is inference and is **not verified**. The CLI
`proxyd` probe watches the actual PID set and remains the authoritative restart
check.

**Where:** `app/services/deep_monitor.py` (`API_KINDS`, `_api_client`,
`discover_api_probes`, the `classify_*` graders), `app/clients/fortiweb.py`
(the monitor endpoint block).
**Tests:** `tests/test_deep_monitor_api.py` — 48 cases over payloads captured
verbatim from a live appliance; `tests/test_service_monitor.py` for the
silent-zero guard (mutation-tested: neutralising the check fails the suite).

### 9f. Two probe pages, one subsystem — the partition is server-side

**Service Monitor** (`/monitoring/services`) and **Deep monitors**
(`/monitoring/deep`) are two *views* over one probe table, one runner and one
scheduled action. Splitting the storage or the runner would double-schedule
every device: two sweeps, two SSH sessions, two sets of samples for the same
box. What is split is the set of `deep_monitor.KINDS` each page owns — the five
that reach INTO the appliance versus the four REST-telemetry kinds.

The partition is enforced on **every route**, not by hiding rows in a template:

* each page's `/data` filters on its own kinds;
* `apply_form` refuses a kind belonging to the other page, on create AND on
  edit — otherwise the form's `<select>` would be the only thing between an
  operator and a probe its owner page cannot display;
* a probe id belonging to the other page answers **404** (not 403: from this
  page's point of view it does not exist) on history, series, update, toggle and
  delete;
* *Probe now* with no selection is pinned to this page's kinds and this ADOM's
  devices. A button whose scope is wider than the table under it is a button
  that lies — and in a product ADOM the previous fleet-wide sweep would have
  opened SSH sessions to appliances of other products;
* *Discover from device* only accepts the steps the page owns, so asking the
  Service Monitor page for `baseline` cannot create CPU/memory/proxyd probes it
  will never show.

A kind can therefore land on exactly one page. It cannot land on both, and it
cannot land on neither without `test_the_two_pages_partition_every_probe_kind`
failing — which matters because a kind owned by no page would still be run by
the sweep while being invisible and uneditable in the UI.

ADOM scoping (§9c) stacks on top and is unchanged: every query still runs
through `visible_appliances()`.

**Where:** `app/views/monitor_probes.py` (the shared route set + `PageSpec`),
`app/views/deep_monitor.py` and `app/views/service_monitor.py` (the two specs),
`app/templates/monitoring/_probe_page.html` (one page, two mount points).
**Tests:** `tests/test_service_monitor.py`.

### 9g. Housekeeping is silent unless it breaks

A background job used to look exactly like a job someone was waiting on: the
toast dock opened a floating window with a progress bar and a **Stop** button
for a monitoring sweep nobody asked to watch, and the sweep pushed a bell
notification on **every** successful run. Two different channels both spending
the operator's attention on "the thing you told me to do is happening".

`jobs.create_job(..., background=True)` marks work no human is waiting on. Three
rules follow from it:

* **The dock never sees it.** `GET /jobs/?active=1` — the toast dock's only
  feed — filters background jobs out *server-side*. Hiding them in the client
  would leave the noise one cached script away from coming back, so
  `jobs.js` drops them too: two locks, not one.
* **The Jobs page still sees all of it.** Silent is not invisible. Progress,
  message, log, Stop and the full history stay on `/jobs/manager`, which is
  where someone goes when they actually want to watch.
* **Only a failure is pushed.** A sweep that ran is not news — the table under
  the button reloads itself, and a probe that turned crit is already carried by
  the device badge (§9b) and the alert engine, which owns escalation and
  cooldown. A sweep that **failed** is the one outcome the page cannot show:
  the numbers simply stay stale and look current. That, and only that, reaches
  the bell — carrying the ADOM stamped on the job, because the worker thread
  has no request context of its own (§9c-bis).

**Default is foreground.** `background` defaults to `False`, so a new job type
cannot go quiet by accident; going quiet has to be a decision someone wrote
down. Today the flag is on the two probe sweeps and the fleet hardware scan.
*Discover from device* deliberately stays foreground: it creates rows and the
operator is waiting to read "created 12 probes".

**Where:** `app/services/jobs.py` (`create_job(background=…)`),
`app/views/jobs.py::index` (the feed filter), `app/static/js/jobs.js`
(`reconnectJobs`), `app/views/monitor_probes.py::_run_sweep`,
`app/views/monitoring.py::_run_hw_scan`.
**Tests:** `tests/test_background_jobs.py`.

### 9h. A consolidated view never invents a number it did not measure

The Service Monitor table shows one row per probe. Two consolidated views sit
on top of it — a traffic card per appliance, and a drill-down per server policy
— and consolidation is exactly where a monitoring page learns to lie: the
moment several probes are merged into one headline figure, the ones that are
missing, disabled or hours old vanish into the ones that answered.

Three rules, enforced in `app/services/service_rollup.py`:

* **Absence is never a zero.** A probe that is missing, disabled or has never
  run reports `measured: False` and `status: unknown`, and its numeric fields
  are set to `None` — not carried over from the last sample, not defaulted to
  `0`. On screen, `0 Mbps` from an idle service and `0 Mbps` from a probe
  nobody enabled are the same pixels, and only one of them is good news. The
  card prints *"not measured"* instead. This one was caught by its own test
  during development: a disabled probe was still serving its last reading.
* **A disabled probe is not a passing probe.** It counts as a coverage gap and
  is named in the card's `coverage.gaps`, so a device cannot look monitored
  because someone paused the one check that mattered.
* **Stale is stated, not hidden.** A sample older than
  `service_rollup.STALE_AFTER` (16 min — two missed five-minute sweeps, so
  jitter does not trip it) keeps its values and gains a `stale` flag plus its
  age. An old reading is still a reading; an old reading that renders like a
  fresh one is not.

**Deliberately not built: a single rolled-up status badge per device.**
`deep_monitor.worst` ranks `unknown` at the *tail* of `STATUS_ORDER`, i.e. less
severe than `ok`, so one healthy probe beside three missing ones would roll up
green — the same failure the Fleet health badge had before §9b. Rather than
fork the fleet-wide severity ordering for one card, the module returns each
block's own status plus an explicit coverage summary and the template renders
both.

**And the views never touch an appliance.** Both are built entirely from stored
samples, so they open instantly, they answer with the box powered off, and they
keep answering on a device whose cmdb API is licence-locked. The test proves it
by replacing `FortiWebClient` with a function that raises.

**One page owns the rollup.** `PageSpec.rollup` is off by default; the
collection does not run and the key is *omitted* from `/data` on a page that
does not own it, and the policy endpoint is not registered there at all (404,
not 403 — from that page it does not exist). A page whose kinds never produce a
`policy`/`stats` payload would otherwise render a strip of empty cards reading
as "no traffic" rather than "not applicable".

**Where:** `app/services/service_rollup.py`,
`app/views/monitor_probes.py` (`PageSpec.rollup`, `payload()`, `policy_detail`),
`app/views/service_monitor.py` (`rollup=True`),
`app/templates/monitoring/_probe_page.html`.
**Tests:** `tests/test_service_rollup.py`.

### 9i. A probe interval that is not a multiple of the sweep tick is a lie

`deep_monitor.due_probes` fires a probe only when its **whole** `interval_min`
has elapsed *and* a sweep tick happens. The sweep is a scheduled action, so the
effective cadence is `tick * ceil(interval / tick)` — a 5-minute probe under a
3-minute sweep is really a **6-minute** probe, and nothing on the page says so.
The row keeps claiming 5.

That is the quiet kind of failure this repo does not accept: the operator reads
a number that is not true, and the check they care about most (`proxyd`, whose
whole purpose is catching a silent daemon restart) gets slower without a single
warning. Lowering the sweep to 3 minutes for Service Monitor therefore came with
**aligning every other interval to a multiple of 3** rather than letting the
5-minute box probes drift to 6.

Two named constants carry the rule so a future discovery path cannot reintroduce
a bare literal:

* `deep_monitor.DEFAULT_PROBE_INTERVAL_MIN` (3) — every probe discovery creates.
* `deep_monitor.SLOW_PROBE_INTERVAL_MIN` (15) — endpoints that aggregate over
  hours (`transactions`) are sampled coarsely on purpose; 15 is a multiple of 3,
  so they still land on a tick instead of drifting.

**A residual offset remains, and it is the scheduler's, not the probe's.**
`scheduled_actions` computes `next_run = compute_next_run(...)` inside the
`finally` block, i.e. anchored to when the run *finished*, and the sidecar ticks
every `scheduler_runtime.TICK_SECONDS` (45 s). So a 3-minute sweep is observed
at roughly 3.4–3.7 min end to end: `interval + run duration + up to one tick`.
Measured, not assumed. Tightening it means anchoring `next_run` to the run start
and is a scheduler-wide change, deliberately out of scope here.

**Where:** `app/services/deep_monitor.py` (`DEFAULT_PROBE_INTERVAL_MIN`,
`SLOW_PROBE_INTERVAL_MIN`, `due_probes`, `discover_api_probes`,
`ensure_baseline`).
**Tests:** `tests/test_probe_cadence.py`.

### 9j. Collapse state cannot live in the DOM

The device cards on both probe pages are collapsible. `renderDevices()` replaces
the container's `innerHTML` on **every** poll (20 s), so a collapsed/expanded
flag held only in the DOM is wiped three times a minute — the operator collapses
a card, looks away, and it is open again with no explanation. The state is
persisted in `localStorage`, keyed by `PageSpec.base` so Deep monitors and
Service Monitor do not share it, and re-applied while the card markup is built.

Three supporting rules:

* **The store holds the OPEN set, not the closed one.** The default has to be
  *everything folded*: a fleet page that opens with ~100 expanded cards shows
  nothing at all. Persisting the open set gives that default from an empty set,
  with no first-run flag to keep in sync. The key is `…probecards.open.…`
  and must never go back to the old `…probecards.collapsed.…` — reusing the
  name would read a saved closed-set as an open-set and expand exactly the
  cards the operator had folded.
* **Folded cards tile, an open one takes the row.** The container is a dense
  grid of ~258 px tiles so a hundred folded devices stay inside one screenful;
  an expanded card gets `grid-column:1 / -1`, because a tall item inside a
  narrow column would stretch every tile beside it.
* **Collapsing is not hiding.** A collapsed card keeps its status badge and a
  headline chip (`avg throughput · N policies`) in the header, so a folded
  device still reports. Hiding the detail must not hide the finding.
* **No inline handlers.** The toggle binds through document-level delegation
  like the rest of the page — the CSP forbids `on*` attributes — and is
  keyboard-reachable (`role="button"`, `tabindex`, `aria-expanded`,
  Enter/Space).

**Where:** `app/templates/monitoring/_probe_page.html` (`OPEN_KEY`, `toggleDev`,
`.dp-dev-toggle`, `.dp-dev-body`).
**Tests:** `tests/test_probe_cadence.py`.

### 9m. This product is a light chrome — a borrowed dark palette is a bug

`static/css/fortiweb.css` is the whole theme: content background `#F4F5F7`,
`.fw-card` on `#FFFFFF`, accent `#EF5424`. There is **no dark mode**, no
`prefers-color-scheme` block and no `data-theme` hook anywhere in the app.

A page-local `<style>` block therefore has to pick its colours against **white**.
Dropping the wider fleet's dark-glassmorphism convention on this product does
not merely look different, it fails two ways at once:

* a card painted `rgba(30,41,59,.80)` over a light page renders as an opaque
  **grey slab** — reported by the operator on 2026-07-28;
* pastel status text (`#6ee7b7`, `#fcd34d`, `#93c5fd`, `#cbd5e1`) sits on a 12 %
  tint of its own hue and drops to roughly **1.4:1** contrast. The pill is still
  in the DOM, still says `crit`, and is unreadable. That is worse than the slab:
  the slab is obvious, an invisible badge is a silent loss of signal.

The rule: **new page CSS reuses `.fw-card` and the `--fw-*` custom properties**
rather than restating a palette. Where a page-local class is genuinely needed,
its colours come from the same variables, and status colours come from the
`.fw-badge-*` set (`#15692A`, `#7A5700`, `#8B1C2A`, …) which is already tuned
for this background. This applies to canvas drawing too — Chart.js grid lines at
7 % slate are invisible on a white modal.

**Where:** `app/templates/monitoring/_probe_page.html` (the whole `<style>`
block and the Chart.js `options`), against `app/static/css/fortiweb.css`.
**Tests:** `tests/test_probe_cadence.py::test_probe_page_uses_the_light_chrome`
asserts the card is built from `--fw-*` and that a list of dark-theme literals
is absent from the template.

### 9k. The job ledger is isolated, and a ghost does not haunt the dock

§9g made housekeeping silent, and the floating window came back anyway. Two
defects, neither of them in the background flag:

* **The tests wrote into the production ledger.** `jobs._state_dir()` resolved
  from `__file__` to the in-tree `data/jobs/`, and only one test module
  monkeypatched it. Every other suite run created REAL job files owned by
  `admin` that no worker would ever finish. Running the tests to verify a change
  was itself the thing that produced the noise the change removed. The path is
  now overridable with `SATOM_JOBS_DIR`, and `tests/conftest.py` points it at
  the throwaway temp tree — the same isolation `FORTINET_DIAG_DIR` already had.
* **`sweep_orphans` ran only at boot.** A job that went stale *afterwards* stayed
  active until the next restart, and the dock re-opened a toast for it on every
  single navigation — with a **Stop** button that could never work, because the
  worker it would signal never existed. The read paths (`/jobs/?active=1` and
  `/jobs/all`) now sweep before they answer, throttled to once every 120 s so
  the poll stays cheap.

And the threshold was wrong for the common case: a job with no pid was given an
hour. `run_async` stamps the pid the instant the worker thread starts, so a job
still missing one **ten minutes** later was never dispatched. A false positive
self-heals — if the worker does start, it rewrites status and pid.

The rule behind all of it: **a control the operator cannot act on is worse than
no control.** A toast offering Stop for work that is not running teaches them
that the dock lies, and then the toast that matters gets dismissed too.

**Where:** `app/services/jobs.py` (`_state_dir`, `sweep_orphans`,
`maybe_sweep_orphans`), `app/views/jobs.py` (both feeds),
`tests/conftest.py`.
**Tests:** `tests/test_job_ledger_isolation.py`.


### 9l. Silence on success is only safe if failure is loud

§9g made housekeeping silent — a sweep that ran is not news. That trade buys
back the operator's attention only if the run that BROKE reaches them, and it
did not. `scheduled_actions.py` contained no `notify` call and the alert engine
had no check for it, so both of the real outages went unannounced:

* **Failing** — on 2026-07-28 action 5 (`device_sync`) had failed **24
  consecutive scheduled runs**. The Monitoring page showed stale numbers that
  looked current. Nothing was sent.
* **Not firing at all** — on 2026-07-26 `scheduler_guard.sh` broke on `runuser`
  after the units dropped to the service account, and the sidecar fired
  *nothing* for hours while systemd still reported the unit `active (running)`.
  A streak-only check would have called that healthy: a dead scheduler produces
  no failed runs to count.

`alerts._check_actions` therefore grades two signals, not one, and follows the
rules the other device checks already follow:

* **One finding per action, never per run.** 24 failures are one broken
  automation. A mailbox that gets 24 mails about one thing stops being read.
* **Severity is in the cooldown key** (`action.broken.<id>.<warn|crit>`), so an
  escalation inside the 6 h window still gets out — same reason as §9b.
* **Only `trigger='schedule'` runs count.** A manual run is user-initiated and
  its result is already on the operator's screen; mixing the two would have
  hidden the 2026-07-28 case exactly, where the scheduled path failed on stale
  sidecar code (`Unknown action`) while the manual path succeeded in the
  freshly restarted web worker.
* **A capped streak is reported as `N+`.** The history window is bounded
  (`_RUN_WINDOW`); printing `50` when it may be 500 is a number the operator
  would use to judge how long this has been broken.
* **`skipped` clears the streak, same as `ok`.** The opposite rule looks safer
  and is not: an action whose whole target set is parked reports `skipped` on
  every future run, so old failures would never clear and the alert would sit
  critical forever — the always-red state this check exists to prevent. A skip
  is a legitimate outcome, not a fault; a genuinely broken action restarts the
  streak on its next real run.

**And the other half: maintenance had to start meaning something.**
`Appliance.maintenance` suppressed *alerts* but not *work*. The hourly sweep
kept reaching boxes the operator had explicitly parked and counted every one as
a failure, which pinned the action permanently `failed` — so the new alert would
have been permanently critical about machines nobody expects to answer. That is
the "always red, therefore ignored" mode this document exists to prevent.
`_resolve_targets` now drops parked appliances from an **automatic** run, and a
run whose whole target set is parked reports **skipped**, which does not feed the
streak. A **manual** run still reaches them: you park a box precisely to work
on it, and the default value of the kwarg is the safe one.

**And a third path it never reached: the probe sweep.** `_resolve_targets`
covers harvests. `deep_monitor.due_probes` filtered on `enabled` alone, so the
sweep kept opening SSH and REST connections to parked boxes every few minutes.
That stayed invisible while parked meant *broken*, and stopped being invisible
once retired appliance rows had their IPs recycled: the sweep was authenticating
against unrelated live hardware, which had a three-attempt admin lockout on the
other end. **Host-key verification is what stopped it, not design.** The
scheduled path now drops parked appliances; `force=True` — somebody pressing
*Probe now* — still reaches them, the same split drawn above. A probe with no
appliance row is a bare URL check and is never treated as parked: guessing the
other way stops collecting and reads as healthy.

The read-out had to follow. `get monitor status` counted every disabled probe
as lost coverage, including the ones disabled *because* their appliance was
parked — which is the correct response to parking it, not a loss. Fifteen such
probes held that check at a permanent `FAIL`, and the first thing a permanent
FAIL teaches is that the check can be ignored. They are now reported separately
and do not grade. What still grades is a live probe in `crit`, which is the
whole point: the exemption must not be able to mask a real failure.

**Where:** `app/services/alerts.py` (`_check_actions`, `_RUN_WINDOW`,
`K_CHK_ACTIONS`, `K_ACT_STREAK_CRIT`, `K_ACT_OVERDUE_H`),
`app/services/scheduled_actions.py` (`_resolve_targets`, `_run_targets`,
`_parked_targets`), Settings → Alerts.

**Verify it is armed:**

```bash
# 1. the check is registered and fires on the live history
cd /opt/satom && set -a && . ./.env && set +a && runuser -u satom -- \
  venv/bin/python3 -c "
from app import create_app; from app.services import alerts
with create_app().app_context():
    print([f['key'] for f in alerts._check_actions()])"

# 2. an automatic run does not touch a parked appliance -- harvest OR probe
runuser -u satom -- venv/bin/python3 -m pytest \
  tests/test_alerts_scheduled_actions.py tests/test_action_maintenance.py -q

# 3. a parked box's disabled probes are not reported as lost coverage
satom get monitor status | grep -i 'parked+disabled'
```

## 10. Fresh installs, and what an offline bundle can promise

The guards travel with the code. A node installed from the online path or from an
offline bundle has, from first boot, the anti-`reset` history guard, the pip
allowlist, the service-account drop-in, the peer forced command, the certificate
validate-and-rollback and the read-only assertion on appliance CLI.

What does **not** ship armed is everything that lives in the database — seeds are
INSERT-ONLY and operator edits outrank them (rule 6), so nothing is created on the
operator's behalf. A brand-new install has **no scheduled actions and no alert
recipient**, which means:

* no periodic device sync — the source of truth in `reports/` freezes at install day;
* no `git_bundle` run — none of the repository backup copies is ever produced;
* no database bundles;
* every signal in §9 is computed and delivered nowhere.

This is a deliberate trade (the product never invents schedules against live
appliances) but it is also the most common way an install ends up unprotected.
The install manual carries the recommended minimum set; arm it before calling the
install finished.

An offline bundle carries one extra caveat: it is a **snapshot of the repository
at build time**, so the guards inside it are the ones that existed then. Check the
version it contains before assuming a fix is present —

```bash
tar xzOf satom-offline-<ver>-*.tar.gz --wildcards '*/bundle/app.tar.gz' | tar xzO VERSION
```

The bundle also carries the ACME client and the `sudo` / OpenSSH packages, because
an air-gapped host has no way to fetch them and a missing `sudo` used to abort the
install after the service account had already been created — a half-applied state,
which rule 3 exists to prevent.

## 10b. The installer is only proven by installing it

Every defect in this section was found by running the published installer on a
blank machine and reading the result — not by reading the script. All four had
survived review, a test suite and an offline-bundle validation, because none of
those exercise a real install on a real distribution.

**A bundle that builds is not an installer that works.** The v1.2/v1.3 offline
bundles for RHEL and openSUSE were validated by checking that the packages
installed, the venv built and the pinned imports resolved. That is the
*packaging* proving itself. It says nothing about whether the install
*completes*, and on both families it did not.

### The guards

| Guard | Where | What it prevents |
|---|---|---|
| `SATOM-HBA-RELOAD` | `installers/install-satom.sh` | pg_hba written but never applied |
| `SATOM-HBA-VERIFY` | `installers/install-satom.sh` | the failure surfacing 60 lines into a SQLAlchemy traceback |
| `SATOM-LOUD-DB` | `installers/install-satom.sh` | the installer exiting non-zero and printing nothing |
| `SATOM-NGINX-DEFAULT` | `installers/install-satom.sh` | a fresh node that goes unreachable when a second vhost appears |
| `SATOM-NGINX-DIRS` | `deploy/satom_cli/cmd_checks.py` | the nginx check being blind on openSUSE |
| `SATOM-CLI-SHEBANG` | `deploy/install-cli.sh` | the operator CLI installing dead |
| `SATOM-ARM-BANNER` | `installers/install-satom.sh` | a node whose protections nobody was told to arm |

### Rules these encode

1. **Writing a config file is not applying it.** PostgreSQL evaluates `pg_hba`
   from memory. The rule was correct on disk and irrelevant in practice,
   because the only `systemctl restart postgresql` lived inside the `primary`
   branch — so *standalone* installs never reloaded. Any step that edits a
   running service's configuration reloads it **in the same step**, outside
   every conditional.

2. **Verify the credential where the error is actionable.** The failure
   presented as a SQLAlchemy traceback about connection pools. The named cause
   — `Ident authentication failed for user "satom"` — was one line at the very
   bottom of a separate log file. The check now runs immediately after the
   reload and names `pg_hba` and first-match ordering.

3. **A step with no `|| die` under `set -e` is a silent exit.** The installer
   died with `rc=1` after printing `pg_hba: regla local scram`. Nothing else.
   Three steps had this shape. The recurring lesson in this repo — *a failure
   that exits quietly is a failure nobody finds* — applies to the installer
   exactly as it applied to `scheduler_guard.sh` and `satom-git-publish.sh`.

4. **A distribution default is not a portable assumption.** Debian ships
   `scram-sha-256` for `host 127.0.0.1`; openSUSE and RHEL ship `ident`. Debian
   provides `/usr/bin/python3`; openSUSE Leap installs `python311` and creates
   **no** `python3` link, so `#!/usr/bin/env python3` resolves to nothing. The
   installer's own code comment already documented the first difference — it
   just never acted on it.

5. **A fix applied by hand in production must travel back into the installer.**
   The production vhost claims `default_server` on the TLS port because someone
   hit the outage it prevents and added it. The installer template was never
   updated, so every new install shipped the pre-fix configuration and
   `satom diagnose nginx` failed it on day zero.

6. **A check and the code it checks must agree on where things live.** The
   installer selects the vhost directory by family (`sites-enabled`,
   `vhosts.d`, `conf.d`). The nginx check knew two of the three, so on openSUSE
   it read zero files and reported `default_server holder NONE` for a correct
   config — an unclearable FAIL on the check whose job is warning you the
   console is about to disappear.

7. **A deliberate gap still has to be spoken aloud.** No `ScheduledAction` is
   seeded, on purpose. The final banner never said so, so a fresh node had no
   database bundle, no source-of-truth refresh and no repository bundle, and
   the operator only learned this by independently running `satom diagnose`.

### Verifying the guards are armed

```bash
# 1. pg_hba is applied, not merely written — the app's own credential works
sudo -u postgres psql -tAc "select 1" >/dev/null      # server is up
PGPASSWORD="$(sed -n 's|.*://satom:\([^@]*\)@.*|\1|p' /opt/satom/.env)" \
  psql -h 127.0.0.1 -U satom -d satom -tAc 'select 1' # must print 1

# 2. the TLS listener owns default_server, and the check can see it
grep -rh 'listen.*443' /etc/nginx/sites-enabled /etc/nginx/vhosts.d \
     /etc/nginx/conf.d 2>/dev/null | grep default_server
satom diagnose nginx        # must not say "holder NONE" on a healthy node

# 3. the operator CLI is alive, with a shebang that resolves on this distro
head -1 /usr/local/sbin/satom     # an interpreter that exists, not env python3
satom show version

# 4. the installer refuses to die quietly
grep -c 'SATOM-LOUD-DB' /opt/satom/installers/install-satom.sh   # 1
```

### A run that passes does not prove a race is absent

Installing v1.3.2 on two identical blank openSUSE Leap 15.6 machines, the
online node exited **1** and the offline node exited **0** -- same release,
same distribution, same answers. The difference was 38 milliseconds.

The installer started nginx and reloaded it on the same line:

    systemctl enable --now nginx >>"$INSTALL_LOG" 2>&1; systemctl reload nginx

openSUSE ships `nginx.service` as `Type=simple` with
`ExecStart=/usr/sbin/nginx -g "daemon off;"` and
`ExecReload=/bin/kill -s HUP $MAINPID`. systemd calls a `Type=simple` unit
started the instant it `exec()`s -- **before** nginx has written
`/run/nginx.pid`. The immediate reload therefore resolved `$MAINPID` to
nothing, `kill` exited 2, and systemd tore down the entire service. The
installation itself was complete and correct: a plain `systemctl restart
nginx` afterwards served `/healthz` 200 immediately.

Debian and RHEL never see it: their units are forking with `PIDFile=`, so
systemd waits for the pid before declaring the start successful.

Three rules came out of it:

- **Do not reload a service you just started.** The reload was redundant --
  nginx had come up seconds earlier on the very config `nginx -t` had just
  validated.
- **Wait on a condition, never on luck.** The start is now followed by a
  bounded poll on `systemctl is-active` **and** a non-empty `/run/nginx.pid`
  **and** an accepted TCP connection on the web port. The pid file is not
  cosmetic: it is what makes the `systemctl reload nginx` that `cert_service`
  runs at renewal time -- through the two-command sudoers rule -- safe.
- **An unguarded final command hides everything behind it.** With `set -e`,
  the failing reload killed the script before step 7, so the installer never
  ran its health check and never printed the banner telling the operator that
  the scheduled actions are not seeded. A working system reported failure and
  withheld the one instruction that mattered.

Guard: `tests/test_installer_nginx_start.py`, marker `SATOM-NGINX-START`.

### A standalone install has no peer channel

`satom diagnose nginx` probed `https://127.0.0.1:8443/healthz` unconditionally
and graded a non-answer as a finding. :8443 is the authenticated node-to-node
channel; a standalone install does not have one. So **every** fresh single-node
install opened with `[warn] nginx` forever, over a feature it deliberately does
not have -- the same chronic false positive already removed from `get system
health` for the datasync timer that is inert by design on a primary, and from
the CLI colouring for status words like `inactive`.

The row is still printed (`n/a - standalone, no peer`), so the channel is never
silently unreported; it just stops counting against the node. On any other role
it is graded exactly as before -- on a real pair, a dead :8443 means the peers
cannot probe each other, which is a genuine finding.

Selection lives in a pure helper, `cmd_checks.nginx_probes(has_peer)`, so the
guard is a behavioural test and not a grep over code that documents itself.

**The first attempt at this fix did not work, and the reason is worth keeping.**
It gated on `ctx.role == "standalone"` -- because that property's docstring
said it returns `primary | standby | standalone | unknown`. It cannot. `role`
is derived entirely from `pg_is_in_recovery()`: `t` is a standby, `f` is a
primary, an error is unknown. A standalone node's database is not in recovery,
so a standalone node reports **`primary`**, and the gate never fired. The tests
passed, because they tested the helper against the same wrong assumption the
helper encoded.

Two rules:

- **Read the implementation, not the docstring.** A property whose docstring
  promised a value it could never return sent an otherwise careful fix
  straight through review, a test suite and a bundle build. The docstring is
  now corrected in place, and it names the callers still carrying the dead
  `role in ("primary", "standalone")` branch -- they are correct only by
  accident, because `"primary"` already covers the lone node.
- **Ask the question you actually mean.** The check does not care about roles;
  it cares whether *something should be answering on :8443*. That is the peer
  registry, discovered exactly the way `get node status` does it: local IPs
  compared against `data/ha_nodes.json`. A standalone has no such file.

Verified against reality on both sides before shipping: a freshly installed
standalone reports `[ ok ] nginx` with `n/a - no peer configured`, and a real
cluster primary still probes its peer and still grades the answer.

Guard: `tests/test_installer_nginx_start.py`, marker `SATOM-NGINX-PEER`.

## 10c. A success message may not contain an error

The installer runs with the PATH inherited from container boot --
`/sbin:/bin:/usr/sbin:/usr/bin`. It does **not** include `/usr/local/bin`,
where the ACME client is installed. Any command substitution inside the *text*
of a status message that invokes such a binary by bare name expands to the
shell's own error, and that error is printed inside a line marked as success.

Verified live on two blank openSUSE Leap 15.6 nodes: the binary was installed
and working (`lego 5.2.2`, sha256 verified) while the installer had printed
`lego: command not found` in its success line.

**The rule.** A message that reports success may not contain the text of a
failure. Status messages resolve helper binaries through an absolute-path
variable (`$LEGO_BIN`), never by bare name -- except in a branch that has
already proven the binary is on the PATH via `command -v`.

**Why it is not merely cosmetic.** An operator who reads `command not found` on
a green-tick line learns that the installer's messages are unreliable. The next
message they skip is the one that matters -- and on a fresh install that is the
banner naming `satom execute seed actions`, without which no backup, no source
-of-truth refresh and no alert delivery is ever armed (section 10).

**Guards.** `tests/test_installer_nginx_start.py`, section C: the absolute-path
variable must be defined; no command substitution in a message may call the
binary by bare name; and `install(1)` must write to the same variable, so a
future path edit cannot separate the message from the file it describes.

## 10d. Only the offline path can prove the offline path

`git` was never in the installer's required-package list and never in any
offline builder's package list. Nothing broke online: the online path clones
the repository, so the package manager pulled git in as a dependency of the
clone and every online install had it. Only an air-gapped install was affected,
and the symptom was quiet -- `satom-git-publish.service` failed once an hour
and backup **copy 3** (the `reports/` source of truth versioned in git) simply
did not exist. The web console, `/healthz`, the login and every other check
stayed green.

This is the same shape as `sudo` and `openssh-*` missing from the 1.1 bundles:
two lists that must agree, kept in two files, compared by nobody -- except that
this one could not be caught by installing online, no matter how many times.

**The rule.** A dependency that the online path satisfies *incidentally* is
still a dependency. Every runtime binary the product shells out to belongs in
the required-package list for every family, which is what makes the offline
builders carry it.

**Guards.** `tests/test_offline_bundles.py`:

* the generic pair test (builder package list must cover the installer's
  required list) -- and, because dropping the entry from **both** lists would
  keep that test green, two tests that name `git` directly: it must be required
  on all four families, and every builder must package it;
* `satom diagnose git` must detect an absent binary. It previously reported
  "repository unusable", which is true and sends the operator to look at the
  repository instead of at the one missing package.

**Why the diagnosis matters as much as the package.** The node that cannot
publish its source of truth is the node whose evidence you will want later.

## 10f. A prompt may not die in silence

`read` returns non-zero on EOF. Under `set -euo pipefail` that killed the
installer **without printing anything**: the last line the operator saw was the
previous step, and `rc=1` said nothing about where it stopped. It happens
whenever the installer is driven by a pipe or here-doc and the answer sequence
is shorter than the prompt sequence -- and the ONLINE and OFFLINE paths do
**not** have the same number of prompts (online also asks for the repository
URL). Interactively it cannot happen; in automation it can.

Same class as 10c: a failure nobody can see is a failure nobody will find.

**What is armed**

- Every prompt goes through `ask` / `ask_secret`, which check `read`'s exit
  status and abort through `_ask_die`, naming the prompt that went unanswered
  and explaining the pipe/here-doc mismatch.
- EOF **with** partial data (a final line without a newline) is a valid answer
  and is accepted -- the same as Ctrl-D after typing in a terminal. Only EOF
  that produced nothing aborts.
- A structural guard rejects any raw prompt `read` outside those two helpers, so
  a prompt added later cannot reintroduce the silent death. It is evaluated over
  *executed* lines: the helper's own comment discusses `read`, and a naive
  substring check would match the prose.
- The guards anchor the opposite behaviour too
  (`test_raw_read_is_the_silent_failure_we_are_preventing`): narrowing the helper
  and the test together would otherwise leave them self-consistent and green.

**Verifying the guard is armed**

```bash
# 1. no prompt bypasses the helpers, and the helpers really abort
python3 -m pytest tests/test_installer_loud_read.py -q

# 2. the behaviour itself, against the real installer source
printf '' | bash -c 'set -euo pipefail
                     source <(sed -n "/^_ask_die() {/,/^}$/p;/^ask() {/,/^}$/p" \
                              installers/install-satom.sh)
                     die() { echo "ERROR: $*" >&2; exit 1; }
                     ask V "Question: "'
#    expected: non-zero exit AND a message naming "Question: "
#    the pre-fix behaviour was: exit 1, no output at all
```

## 10e. The node has to be told which names it answers to

Two defects with one root cause: the installer never learned which names the
node is actually reached by, so it guessed with `hostname` -- the SHORT name --
and two different things were minted from that guess.

**The proxied `Host` header dropped the port.** The generated vhost passed
`proxy_set_header Host $host`, and `$host` discards the port. Flask-WTF builds
the origin it expects a CSRF token to have come from out of the host the
application believes it is on, then compares it to the browser's `Referer`
*including the port*. Behind a NAT or a proxy on a non-standard port the two can
never agree, so **every POST -- the login included -- was rejected**, and the
error the operator saw said the session had expired. It pointed at the wrong
layer entirely: the credentials were right, the session was fine, and the header
was the fault. On `:443` the defect is invisible, because browsers omit the
default port from `Host`; it is latent on every standard-port install and arms
itself the moment the node is published anywhere else.

**`server_name` and the certificate SAN both came from the short name.** A node
reached at `node.example.tld` got `server_name node`, which answered only
because the same vhost also claimed `default_server` -- i.e. by accident, and it
would stop the day a second vhost appeared. Worse, the node certificate was
issued with `subjectAltName=DNS:node`, so a browser arriving by the FQDN got a
name-mismatch warning **on a certificate the installer had just reported as
good**. `hostname -f` had the right answer the whole time and was never asked.

### The rules

- **The served names are collected in step 1, before anything is written.** They
  are the input to two artefacts that cannot be corrected later without
  re-issuing: the vhost `server_name` and the certificate's SAN list. A prompt
  that runs after the certificate exists is a prompt that arrives too late.
- **`SATOM_SERVED_NAMES` overrides the prompt**, so an unattended install can
  set them. The default is `hostname -f`, and the short name is always appended
  -- it is still how the node is reached from its own shell.
- **`$http_host`, never `$host`, on anything that proxies.** Deleting the header
  is not a fix either; gunicorn would then see nginx's own `Host`.
- **A wildcard covers exactly ONE leftmost label** (RFC 6125). `*.example.tld`
  covers `node.example.tld` but not `a.b.example.tld` and not the bare apex.
  Treating it as "anything under the domain" turns the coverage check into a
  rubber stamp, so the matcher is written out and tested against all four cases.
- **Only FQDNs are graded against the certificate.** No public CA issues for a
  single-label name, so grading one would leave every node that imports a
  wildcard in a permanent warn -- the chronic false positive this codebase keeps
  having to delete. The name is still printed: not grading is not hiding.
- **A static vhost is never a finding.** `Host` is meaningless without
  `proxy_pass`, and flagging the site vhost trains the operator to skip the
  check.
- **The vhost is not in git.** A node updates its code and keeps serving
  whatever configuration its installer wrote, so fixing the installer alone
  reaches new installs only. `satom execute repair nginx` exists so an existing
  node can be brought forward through a supported path -- a hand edit is erased
  by the next reinstall, which is precisely how this defect survived being
  diagnosed twice.

### Verifying the guards are armed

```bash
# The live check names the offending vhost and fails.
satom diagnose nginx            # exit 1 while any proxying vhost passes $host

# Nothing shipped may emit the port-stripping form.
grep -rnE 'proxy_set_header[[:space:]]+Host[[:space:]]+\\?[$]host' \
     installers/ deploy/        # expect: no matches

# The certificate really covers what the vhost answers for.
satom diagnose nginx | sed -n '/certificate covers/,/^$/p'

# Discriminant probe: use a WRONG password, so a CSRF rejection ("stale form")
# separates from a credentials rejection. Same node, only the port varies.
#   Host: <fqdn>          -> CSRF-OK
#   Host: <fqdn>:<port>   -> CSRF-OK too, once repaired
```

## 13. A chart may not invent a reading

**[SATOM-ANALYTICS]**

Analytics boards and period reports summarise stored samples. Nothing in this
layer raises when it is wrong: the page still renders, the report is still
produced, and the number it shows is simply false. Every guard below exists
because the failure is silent by construction.

**One resolution per panel.** `deep_monitor.pick_source()` picks raw / hourly /
daily *per probe*, from how much history that probe has. Two series on one axis
read from two tables is a lie no legend repairs — the raw line shows spikes the
hourly line averaged away, and an operator reads that as a difference between
the two **devices**. `monitor_analytics.panel_source()` therefore asks every
member and pins the COARSEST answer for all of them; the panel footer names the
table it drew from. `deep_monitor.series()` grew `force_source` for this, and
`source_for()` was split out so the question can be asked without fetching. The
single-probe drill-down still chooses per probe, which is correct when there is
nothing to compare against.

**A gap stays a gap.** Missing buckets are `None` and the front end draws with
`spanGaps: false`. Carrying the last value forward — the obvious "tidier"
rendering — draws a confident straight line through the exact interval the chart
was opened to examine.

**Nothing measured is never a healthy zero.** `healthy_pct()` returns `None`,
not `0` and not `100`, when no bucket in the window was graded; stat panels
print *no data* and reports render a banner. Zero tells the operator the service
is down and a hundred tells them it is fine; both are inventions. The same rule
runs up the chain: `monitor_reports.worst_status()` ranks `unknown` **below**
`ok`, so a device that reported nothing cannot roll up green beside one that
reported healthy. This is §9b applied to summaries.

**A percentage needs something to divide by.** `_pct_delta()` returns `None`
when the previous period is zero or absent. Growth from nothing is not +100 %.

**Report periods are half-open**, `[start, end)`. Adjacent reports must not both
claim the boundary, or every total across it is quietly inflated. Reports are
also generated for the last COMPLETE period — "throughput fell 80 %" means
nothing about a day that is two hours old.

**Effective cadence is published.** A probe fires only once its interval has
elapsed *and* a sweep ticks, so its real cadence is `tick × ceil(interval ÷
tick)`. A 5-minute probe under a 3-minute sweep is a 6-minute probe and its own
row still says 5 — that silent rounding degraded `proxyd`, the check that exists
to catch a mute daemon restart. The cadence view shows declared vs effective and
flags every mismatch. With no sweep scheduled it reports `0`, never a plausible
default, because a fresh install seeds no `ScheduledAction` (§10) and inventing
a tick would describe collection that is not happening.

**Built-in boards refuse writes at the route**, not in the template. A board
whose Save button is hidden but whose endpoint still writes is hidden, not
read-only. Duplicate gives an editable copy, so read-only is not merely
frustrating.

**Panels select by rule, not by a frozen id list.** A rule (`kind` + devices +
name match) resolves at render time, so a probe recreated by Discover or a newly
registered appliance joins the panel. An id list is how a board silently narrows
while still looking complete.

**Charting is vendored.** Chart.js is served from `/static/vendor/chart/`. A
chart that only draws with public internet does not draw in an isolated
management network, which is where this product installs.

### Verifying these are armed

```bash
# every guard, and the mutation harness that proves each one bites
runuser -u satom -- venv/bin/python3 -m pytest tests/test_monitor_analytics.py -q

# a panel must name ONE source for all its series
curl -sk -b "$COOKIE" 'https://<node>/monitoring/analytics/data?range=30d' |
  python3 -c 'import json,sys; d=json.load(sys.stdin);
print([(p["panel"]["title"], p["source"]) for p in d["panels"]])'

# declared vs effective cadence; "drift" is a probe the sweep cannot honour
curl -sk -b "$COOKIE" https://<node>/monitoring/analytics/cadence |
  python3 -c 'import json,sys; d=json.load(sys.stdin);
print("tick", d["tick_min"], "drifted", d["drifted"], "of", d["total"])'

# no charting from a CDN, anywhere in the feature
grep -rn "jsdelivr\|unpkg\|cdnjs" app/static/js/analytics.js \
  app/static/css/analytics.css app/templates/monitoring/analytics.html   # → no hits
```

## 12. Uploaded code is code someone else chose to run

**[SATOM-UPDATE-PACKAGE] / [SATOM-RUNNER-ROOT-COPY]**

A web form that accepts an archive which a root process then installs is, in
plain terms, remote code execution as root. It is a legitimate feature — an
offline node has no other way to be updated — but only because three things
hold at once. Each is worthless without the other two.

Full reference: `docs/offline-update-packages.md`.

### The three rules

**1. The privileged runner must not execute code the service account can write.**

`satom-updater.service` runs as root and its shipped unit says

```
ExecStart=/opt/satom/venv/bin/python /opt/satom/deploy/self_update_runner.py
```

Both paths are inside the application tree, which the service account owns
after the de-privilege. So the unprivileged web worker could rewrite the script
root is about to execute, then enqueue a request — which it is *designed* to be
able to do — and the next trigger runs its code as root. That was a complete
escalation across the boundary section 5 exists to defend, and it was found
while building the package feature: a signature verified by a script the
attacker can edit verifies nothing.

`deploy/install-runner.sh` installs a `root:root` copy of the runner **and its
verifier** in `/usr/local/lib/satom-runner`, run by a **system** interpreter
(never the venv — that lives in the tree and may be the thing being repaired),
and redirects the unit with a **drop-in**. A drop-in and not an edit, because
the update runner re-copies `deploy/<unit>` on every update: that is exactly
how the standby silently reverted to `User=root` after the de-privilege.
It runs from four places so the copy cannot drift, and `package_change()`
refuses outright when the runner is not hardened.

The same reasoning removed `_pip_allowlist()`'s import of
`app.services.system_info`: that import executed the entire Flask package as
root, out of the same writable tree. The curated list is now local to the
runner, and a test asserts it still equals `system_info._LIBRARIES`.

**2. The trust store is root-owned, outside the tree, and empty by default.**

Whoever can add a key can mint packages the node accepts. `/etc/satom/update-keys`
and every parent of it must be `root:root` and not group/world writable;
`trust_store_problem()` walks the whole chain and any finding is fatal. It is
checked **before** the signature, not after — verifying first would mean a
package signed by a planted key had already been declared valid by the time the
store was questioned.

An empty store accepts nothing. Safe, not working: install the release key
before you need it.

**3. The verifier needs nothing but the standard library.**

The feature exists to repair nodes whose venv is broken. A verifier that needs
a pip-installed package cannot run in the situation it was built for, so
Ed25519 verification is implemented in `deploy/update_package.py` on top of
`hashlib` alone — checked against the RFC 8032 vectors *and* byte-for-byte
against `cryptography`'s implementation.

### Rules these encode

- **Sign the exact bytes.** The signature covers `manifest.json` verbatim, with
  no canonicalisation, so there is no re-serialisation ambiguity to exploit.
  The manifest carries a sha256 for every other file, so one small signed
  document covers the whole package.
- **A name crosses the privilege boundary, never a path.** The request JSON is
  written by the unprivileged worker; the runner pattern-checks the basename and
  joins it to its *own* staging directory. If it took a path, the worker would
  choose what root opens.
- **Verify once, in root-only space.** The package is copied into a root-owned
  temporary directory and verified there. Verifying it in the staging directory
  — which the service account can write — would leave a window to swap the file
  between the check and the use.
- **A link in an archive is rejected, never resolved.** A link that points
  inside the tree when it is checked can point outside it after a later member
  lands, and the ordering is the attacker's to choose.
- **The server re-runs preflight on apply.** The page an operator looked at
  could be minutes old; "the button was enabled" is not a safety property.
- **No backup, no apply.** A downgrade does not reverse migrations, so the
  database dump is the only honest way back. If it cannot be taken, nothing is
  replaced.
- **Rollback removes only what the package added.** The untracked-file set is
  captured before the tree is replaced and only the difference is deleted.
  A blanket `git clean -fd` would destroy an operator's unrelated work in order
  to undo ours.
- **The published manifest names no host, path or person.** Packages are
  published; a published artifact must not describe the estate that built it.

### The honest limits

- Signing prevents a *forged* package, not an operator installing a genuine
  older release with known bugs. Downgrades are permitted by policy; the
  mitigations are the confirmation, the audit entry and the backup.
- A downgrade does not reverse database migrations.
- This is not a rescue path for a node that will not boot: it needs systemd,
  the runner, and a working database connection.

### Verifying the guards are armed

```bash
# the runner is root-owned, on a system interpreter, and the unit agrees
satom diagnose updates                       # [ ok ] on every line
stat -c '%U %a %n' /usr/local/lib/satom-runner/*.py    # root 644
systemctl show -p ExecStart --value satom-updater.service | grep satom-runner

# the trust store is root-owned and its keys are known
satom show trust                             # compare fingerprints by eye

# the verifier needs no venv at all
/usr/bin/python3 -c "import importlib.util as i; \
  s=i.spec_from_file_location('u','/usr/local/lib/satom-runner/update_package.py'); \
  m=i.module_from_spec(s); s.loader.exec_module(m); \
  seed=bytes(range(32)); p=m.ed25519_public_from_seed(seed); \
  print(m.ed25519_verify(p, b'x', m.ed25519_sign(seed, b'x')))"   # True

# a package is refused for the right reason
satom show package /path/to/tampered.tar.gz  # [FAIL] with the reason named
```

The guards themselves are in `tests/test_update_package.py` and
`tests/test_update_package_service.py`: the stdlib-only rule and the
no-app-import rule are checked by AST, the crypto against published vectors,
and every refusal has a test that names the reason — because a package refused
for the wrong reason is a package that will be accepted once that reason
changes.

## 14. Operational data grows with change, not with time

Two stores were replaced on 2026-08-05 because the originals were correct for a
handful of appliances and structurally impossible for a hundred. The full
reasoning and the measurement are in
[`metrics-architecture.md`](metrics-architecture.md); the guards are here.

**The device source of truth (`services/sot_store.py`).** The hourly git commit
of `reports/` grew without bound — git keeps every byte of every revision, and
one FortiAnalyzer snapshot is ~8.4 MB. The replacement is content-addressed:

* the hash IS the identity, so an unchanged config writes zero bytes and mints
  no version row;
* `generated_at` and the per-sweep `errors` list are excluded from that hash —
  they differ every harvest even when the config is byte-identical, and hashing
  them would defeat the dedup entirely and quietly restore the growth;
* retention is a policy (newest N per device, plus anything younger than D
  days), and blobs no version references are deleted;
* blobs live under `data/`, so the existing standby rsync and the backup
  bundles carry them — no new replication path was introduced.

**Fleet metrics (`services/metrics_collect.py` + `services/vm_store.py`).**

* The unit of configuration is (device, collector), never (device, policy):
  `policy_status` returns every policy's counters in ONE 14 ms call, so
  per-policy probes multiply device round-trips by N for data that is free in
  aggregate.
* `maintenance` and a `*.invalid` host both suppress scheduled collection
  entirely — the deep monitors once kept probing recycled addresses because
  their sweep consulted neither.
* A failed collector writes `satom_scrape_up 0`. Absence of data is never
  health.
* The sweep action reports `ok` when it RAN. Device failures live on the target
  rows; an action permanently red over a dead appliance is an action the
  operator learns to skip.
* The metrics store has NO authentication, so the unit binds `127.0.0.1` only
  and every query goes through the console. Changing that bind address is a
  fleet-wide data exposure.
* A MetricsQL panel expression is validated by EXECUTING it against the store,
  not by pattern-matching: the store is the only authority on its own query
  language.
* A failed query renders as an ERROR, never as an empty chart — the two look
  identical on a canvas and mean opposite things — and gaps stay `null` rather
  than carrying the last value forward.

### Verifying (§14)

```bash
# collection honours maintenance and retired hosts, and records its own health
satom diagnose all | sed -n '/collection/,+6p'

# the store answers, and only on loopback
curl -s http://127.0.0.1:8428/health          # OK
ss -ltnp | grep 8428                          # 127.0.0.1:8428 ONLY

# an unchanged harvest must NOT mint a version
psql -c "SELECT device, count(*) FROM sot_version GROUP BY device"
# run a device sync twice; the count must not move the second time
```

## 15. A device that is not collected has to say so

Collection is provisioned, not configured by hand: a device gets one scrape
target per collector its product supports, and the operator then tunes interval,
top-N and enabled state on **Monitoring → Collection**. That only works if
provisioning actually happens for every device, and if the devices it *skips*
are visible.

**Provisioning runs at save time, from one rule.** `metrics_collect.ensure_targets`
is called by all three appliance-creation paths (create, edit, cluster-member
add) as well as by every sweep. It is INSERT-only, so operator edits always win,
and it is self-guarding: the eligibility rule lives in `provisionable()`, not in
each caller.

* A **parked** device (`maintenance`) and a **retired** row (host neutralised to
  `*.invalid`) get no targets — the same guard the sweep applies before touching
  a device. Four copies of that rule would have been four chances to drift.
* Provisioning **may not cost the operator the device row**. Metrics are
  downstream of inventory, so `_provision_metrics` swallows and logs a failure
  instead of aborting the save.
* Doing this only in the sweep was the original bug: a new device sat
  uncollected until the next tick, and on an installation where no scheduled
  action had been seeded (§10 — nothing seeds them), forever.

**Absence is not coverage.** The page lists `ScrapeTarget` rows, so a device that
yields none appears nowhere and reads as healthy. `coverage_gaps()` names every
such device *with the reason*, and the reasons are distinct on purpose —
"no collectors exist for this product yet", "in maintenance", "retired",
"no host", "not provisioned yet" are five different operator actions, and one
shared string would hide four of them. FortiAnalyzer is the live case: no
collector exists for that product today, so auto-provisioning is a legitimate
no-op — and a silent no-op is indistinguishable from success.

## 16. A dependency the product needs is a dependency the product ships

The metrics store (VictoriaMetrics, single node, loopback) was installed by
hand on the development pair and, for a day, existed nowhere else. Nothing
failed loudly. A freshly installed node got the analytics pages, the
`metrics_scrape` scheduled action, and the `satom-metrics.service` entry that
`diagnose all` checks -- and no store behind any of them. On an air-gapped
install it was worse than a warning: there was no route to the internet, so
the operator could not obtain the binary at all.

This is a recurring shape here, not a one-off:

| release | what shipped without it | how it surfaced |
|---|---|---|
| 1.1 | `sudo`, `openssh-*` | install died at step 6, after creating the service account |
| 1.2, 1.2.1 | `docs/safeguards.md` | the guards travelled, the document explaining them did not |
| 1.2, 1.3 (RHEL) | `lego` | ACME silently unusable |
| 1.3 (SUSE, offline) | `git` | backup copy 3 stopped, timer red every hour |

The rule: **anything the product needs at runtime is installed by
`install-satom.sh` and carried in every offline bundle, or it is not a
dependency the product may rely on.**

Three properties hold it up, and each has a guard in
`tests/test_metrics_store_install.py`:

1. **The installer installs it, bundle before network.** Offline is the case
   that cannot recover, so it is tried first; a network-first order spends its
   timeout before finding the copy already on disk.
2. **Every builder carries it, and aborts rather than ship without it.** The
   installer *warns* (the rest of the product works without a store); the
   builder *fails*. A bundle that is silently incomplete is exactly how the
   four rows above happened.
3. **One pinned digest, shared by installer and builders.** Drift means a
   bundle built with one pin is refused by an installer holding the other --
   and that failure only surfaces on an air-gapped node, which is the worst
   place to discover it.

Two details worth keeping:

* **The artefact name is pinned, and `-enterprise` / `-cluster` are refused.**
  The same upstream release tag publishes an enterprise build that is *not*
  Apache-2.0. A loosened URL would pull a differently-licensed binary into a
  product that redistributes it. The guard checks the string, in the installer
  and in all three builders.
* **The store is enabled *after* `satom_enforce_unit_user`.** The shipped unit
  declares a `User=`; an installation that adopted a different service account
  gets the right one only from the drop-in. Enabling first starts it as the
  template's account and nothing later restarts it. `satom-metrics.service` is
  also in the update runner's `NONROOT_UNITS`, so the drop-in survives updates
  -- without that it loses its `User=` on the first self-update, which is
  precisely how the standby reverted to `User=root` in 1.2.

Redistributing a third-party binary also means attributing it: `NOTICE`
carries VictoriaMetrics (Apache-2.0) and lego (MIT), plus the vendored browser
assets. SATOM is ELv2; those components are not, and their terms are not
superseded by it.

## 17. A panel that cannot report bad news is not a panel

Four defects in the same console shipped and survived review because none of
them crashes. Each one makes the page state something false and keep a straight
face.

**A monitored-unit list is a claim about what can break.** Until 2026-08-05
*Services & redundancy* watched five units and `satom-metrics` was not among
them. The Analytics boards and the Collection page read every number they draw
from that store, so it could be dead while every light on the panel stayed
green. The rule: **a unit whose death is visible to the operator elsewhere in
this console belongs on that list.** The converse matters just as much --
`satom-ha-datasync.timer` is role-guarded and inert on the primary, and
`satom-git-publish.timer` was retired with the git SoT. Listing either shows a
permanent red for correct behaviour, and a check that always complains is a
check the operator learns to skip. That false positive has had to be removed
from `get system health` twice; the guard now fails the suite if either unit is
added back.

**Missing is not failed.** `systemctl is-active` answers `inactive` for a unit
that does not exist, which is indistinguishable from a unit that exists and
stopped. A standalone install without an `nftables` package is fine; a node
whose metrics store died is not. `LoadState` separates them, and a unit that is
not installed is reported neutral (grey), never red.

**A panel may not read the documentation table when the sweep has the truth.**
*Device HA clusters* printed *"No HA clusters registered"* on a fleet whose
hourly harvest had `system_ha` cached for every appliance. It read
`Appliance.members`, which is written by exactly one thing -- the appliance form
-- so a box nobody had typed in by hand could not be reported at all. Worse, the
function computed a standalone count and then never rendered it. `ha_inventory`
derives the posture from the cache, which is where the answer already was. This
is the same defect and the same fix as the interface inventory (2026-07-20):
**if the harvest already fetched it, the view must not read the hand-entry
table instead.**

Three rules hold that panel honest:

* **Clustered requires peer evidence** -- a heartbeat device, a group name, a
  peer address, a node list longer than one -- and the panel prints the evidence
  next to the verdict. FortiWeb and FortiADC report `mode` as a string, which is
  unambiguous; FortiAnalyzer reports it as an **int** whose enum could not be
  verified against a live device. Guessing that mapping would label a standalone
  box "primary", so the verdict comes from evidence and the raw value is carried
  through verbatim for the operator to see. **An unverified enum is reported as
  unverified, never as a confident label.**
* **No harvest means `unknown`, never `standalone`.** "We have measured nothing"
  and "this box is standalone" are different statements; merging them is the
  Fleet-health-badge bug of 2026-07-28.
* **Retired placeholders are excluded outright.** A row whose host is parked on
  the reserved `.invalid` TLD names no real box; counting it as unknown keeps
  the panel permanently amber for rows kept only for their history.

**One page, one question.** Fleet health carried the appliances *and* the
manager's own health, and only the second is Global-only -- so the page had to
hide half of itself in every product ADOM. It is now **SATOM health** (this
installation: nodes, database, units, redundancy, encryption) and **Device
health** (the appliances). The split is enforced on the routes, not in the
template: `/monitoring/satom` redirects out of a product ADOM and
`/monitoring/satom-data` answers 403, because those sections name node
hostnames and infrastructure addresses. The manager feed also stops computing
the per-device capacity roll-up it never renders.

**A number is read as a claim about the page it sits on.** The split above left
the *device* HA counter on SATOM health. Nothing about it was wrong — one
appliance, standalone, verified against the box itself — and it was still a
false statement, because a page headed *"this installation"* reading
`0 clustered · 1 standalone` says the installation is a single node. It was a
two-node pair with live streaming replication. Right number, wrong page; and
the manager's own posture was a grey one-line note underneath it, so the page
answered the question it did not promise more loudly than the one it did.

Two rules came out of it:

* **Device rows live on the device page.** The posture now rides
  `/monitoring/data` and is built from `visible_appliances()`. That is not
  cosmetic: the old call site used an unscoped `Appliance.query`, so on a page
  every ADOM can reach it would have listed the FortiADCs to the FortiWeb ADOM
  — the leak §9c exists to prevent. The manager feed carries no device key at
  all, and the guard fails if one comes back.
* **Every page states its own subject in the same vocabulary.** SATOM health
  reports the installation as `clustered` / `standalone` / `unknown` with the
  same badge and the same evidence rule the appliances get, derived from peer
  facts rather than the `mode` switch — a node left on `standalone` while a
  replica streams is still a pair, and reading the switch would report it as
  single. A probe that could not count nodes is `unknown`, never `standalone`.

**Configuration is not a measurement.** Collection moved from Monitoring to
Administrator: the other six Monitoring pages display what was measured, this
one sets how measurement happens and needs `CONFIG_WRITE` to change anything.
It ships as `partials/nav_collection.html` and is included by all four
Administrator groups -- those groups have already drifted once (one of them is
still titled "Administration"), and a shared partial is the only thing that
stops an entry being added to Global and forgotten in the other three.

## 18. A check must read the source that holds the answer

Two alert engines were reading the wrong source on 2026-08-05. Neither crashed.
Both produced a permanent, confident, false complaint -- and this repo has now
had to delete four of those (`satom-ha-datasync` inert on the primary, the
status-word colouring, `diagnose nginx` on standalone, `get system health`
listing a retired unit). **A check that always complains is a check the
operator learns to skip, and the one that matters is skipped with it.**

**Freshness is measured against a clock, and the reading must name the same
clock as the budget.** `device_health.cache_meta` asked for the `deep` layer
first and returned the first dict it got. `read_layer._layer_meta` returns a
populated four-key dict even when there is no snapshot (`cached: False`), and a
dict with keys is truthy -- so the `config` layer was unreachable. The `deep`
layer is refreshed once a night by `deep_capture`; the budget it was graded
against, `monitoring.stale_hours`, is six hours, the cadence of the *hourly*
sync. That counter is red eighteen hours out of every twenty-four on a
perfectly healthy appliance. Worse, `deep_capture` is FortiWeb-only by design,
so FortiADC, FortiAnalyzer and FortiAuthenticator reported *"no cached
configuration"* forever while holding a snapshot minutes old. The rule:
**freshness is the age of the newest thing we hold**, and a layer that has no
snapshot is not a layer.

**A drift check must read the store that holds the baseline.** `_check_drift`
diffed the last two git commits of `reports/<slug>/_config.json`. The source of
truth left git that morning (section 14), so git saw a *deletion* of every one
of those files and the check reported one refactor commit as fifteen
device-side edits. It now reads `sot_version`: that store is content-addressed
with volatile fields excluded from the hash, so an unchanged device mints no
row at all and **a new row is, by the store's own definition, a real
configuration change**. There is no second normalisation pass to keep in sync
-- the git-era `_normalize_snapshot` helpers were deleted rather than left to
rot beside a rule they no longer enforce.

**`maintenance` means the box is parked, everywhere.** It already suppressed
scheduled runs, device-health alerts and appliance sweeps; drift ignored it, so
the four retired appliances -- whose host is deliberately `*.invalid` and which
therefore name no real hardware -- kept alerting. A lever that works in three
places out of four is a lever nobody trusts.

**The first version of a device is not drift.** Onboarding an appliance is not
somebody editing it behind our back, so a device with a single `sot_version`
row is silent.

Guards: `tests/test_health_freshness_and_drift.py`. Seven mutations bite. An
eighth -- removing the `cached` test while keeping newest-wins -- survives, and
that is reported rather than hidden: a row that is not cached carries
`generated_at = None`, which newest-wins already refuses to prefer, so the
`cached` test is defence in depth and the harness says so.

## 19. An ADOM shows its own product and nothing else

Adding a fourth product (FortiAuthenticator, 2026-08-05) fired two latent
defects at once. Neither raised anything; both were visible only by looking at
a page and counting rows.

**The exclusion filter.** `product_scope.scope_appliance_query` expressed the
FortiWeb ADOM as *"every device that is not a FortiADC and not a
FortiAnalyzer"*. A filter written as a list of what to EXCLUDE cannot know
about a product that did not exist when it was written, so the new appliance
appeared in the FortiWeb ADOM the moment it was created. The same shape had
already been written three more times — in the alert engine, in the Certificate
Manager, and in the plugin sandbox's device selector — and each one leaked the
same way.

**The hardcoded key set.** The same module recognised products from a literal
tuple. `'fortiauthenticator'` was not in it, so `session_product()` returned
`''` inside that ADOM — the value that also means *"a background worker, show
it everything"*. Every filter in the module became a no-op and the FAC ADOM
listed all six appliances and all 322 notifications. An unrecognised key does
not fail closed here; it disables scoping.

The rules that replace them:

* **The key set is DERIVED from the ADOM registry**, `branding.all_adoms()`,
  and that includes INACTIVE rows. A product declared in the registry is scoped
  the day it is declared, with no second edit anywhere. Deactivating an ADOM
  must not make its key unrecognised, or the deactivated product's rows become
  visible to every session still holding it.
* **Every filter names what it KEEPS.** A concrete ADOM sees rows stamped with
  its own key. Only FortiWeb additionally sees the NULL/`''` rows, because it is
  the one product that predates stamping. A device whose kind matches no
  registered ADOM is therefore visible in the Global ADOM only — deliberate, and
  Global is where it stays discoverable.
* **A caller must not re-declare the product list.** `alerts._product_of`,
  `cert_manager._product_kind` and `plugin_sandbox._appliance_options` all call
  `product_scope.concrete_products()`. A test asserts this over the AST, so a
  comment mentioning the old tuple cannot satisfy it.
* **An ADOM with no data pipeline reports NOTHING, never another product's
  numbers.** Metrics used to fall through to the FortiWeb inventory totals for
  any product it did not name, and printed them under that ADOM's own labels —
  figures that read as its own.

Guards: `tests/test_product_scope_isolation.py`, parametrised over
`concrete_products()` rather than a list written in the test, so the next
product is covered without an edit. An anti-vacuity test fails if that set ever
comes back empty.

### 19b. Hiding a row is not scoping it, and a form is not a rule

The same product raised three more (2026-08-06), all on the appliance
inventory, and all silent:

* **The platform roster was a hardcoded list.** "New appliance" offered exactly
  three platforms, written by hand in four places -- two selects and a filter on
  the index page, one more on the standalone edit page. FortiAuthenticator had
  been a real product for a day and was in none of them, so its ADOM could not
  onboard its own devices from the UI. Nothing failed; the option was simply
  absent.
* **Every ADOM offered every platform.** Choosing a foreign one saved a device
  the creating session could not see the moment it was saved -- the row landed
  in another ADOM and the operator read it as a save that did nothing.
* **The by-id loader had no product filter at all.** `visible_appliances()`
  scoped the LIST while `visible_appliance_or_404()` read the table directly, so
  detail, edit, delete, backups and console answered 200 for another product's
  device to anyone who knew the id.

The rules:

* **A page that hides a row and serves it one URL away is not scoped, it is
  decorated.** The list filter and the by-id loader must apply the SAME rule;
  the loader is the one that enforces it, because it is the one an URL reaches.
* **The roster is derived, never written.** An appliance's `kind` IS an ADOM
  key, so the platform roster is `product_scope.device_products()` read from the
  registry. A fifth product is offerable the day it is declared.
* **A concrete ADOM offers exactly one platform: its own.** Where there is only
  one, the kind filter is not rendered at all -- a control that can only ever be
  a no-op teaches the operator to ignore the toolbar.
* **The form is a hint; the server is the rule.** `may_assign_kind()` re-checks
  the posted `kind` on create and on edit. Without it the field is a one-field
  ADOM jump.
* **Guard the CHANGE, not the field.** An unchanged kind is always accepted, so
  a legacy row whose kind no ADOM claims stays editable from Global, and the
  edit form keeps the row's own platform selectable even where the active ADOM
  does not offer it -- otherwise saving any other field re-kinds the device.

Guards: `tests/test_appliance_adom_scope.py`, parametrised over the product
ADOMs, plus a structural test that no template emits a hardcoded platform
`<option>`. All five mutations bite.

## 20. Trusting a device means naming its CA, not disabling the check

`Appliance.verify_ssl` had exactly two settings: validate against the PUBLIC
root store, which no privately-signed appliance can ever satisfy, or validate
nothing. There was nowhere to put the company's own CA. So the fix in this
project's history is always the same one — `verify_ssl=false` for fadc
(2026-07-12), for fortiweb08 (2026-07-28), for fac01 (2026-08-05). That is not
a run of device quirks, it is a missing feature, and its cost is that TLS
verification is off everywhere including where it would have worked.

`services/trust_store.py` holds the CAs this installation accepts. Four rules
make it safe rather than merely present:

* **The bundle ADDS to the public roots, it does not replace them.** Handing
  OpenSSL a CA file replaces certifi wholesale. A real fleet is mixed — some
  appliances present the company CA, some present the public wildcard the edge
  renews. A bundle of private CAs alone would break verification for exactly
  the devices that were already verifiable, which reads as "the trust store
  broke my fleet".
* **A bundle that cannot be built falls back to the PUBLIC ROOTS, never to
  `False`.** A transient database failure must not silently turn off TLS
  verification fleet-wide. The failure has to stay visible; a downgrade to *no
  verification* is the one outcome nobody would ever notice.
* **`verify_ssl=False` is never overruled.** It is an operator decision, and
  the client layer is not the place to second-guess it.
* **Only CA certificates are accepted.** OpenSSL will not anchor a chain on a
  `basicConstraints CA:FALSE` certificate, so importing a device's self-signed
  *leaf* would appear to succeed and then fail every handshake with an
  unhelpful error. It is rejected at import, with the reason.
* **The form has two slots — Root CA and Intermediate CA — but the label is a
  hint, not a classification.** The role is derived from the certificate
  itself (`subject == issuer` makes it a root), so a root pasted into the
  intermediate box is still recorded as a root. If a form field could relabel a
  trust anchor, the incomplete-chain report below would either invent a gap or
  hide a real one, and the operator would spend the afternoon debugging the
  wrong end of the chain. The two slots exist because a single unlabelled
  textarea does not tell anyone the intermediate belongs there at all; the
  backend classified them correctly from the first commit, but nothing on the
  page said so.
* **Both slots are imported in ONE transaction.** They are concatenated into a
  single blob before `import_pem` runs, so a chain cannot land half-applied.
  Importing them one at a time allows the root to succeed and the intermediate
  to fail — leaving precisely the chain gap this page exists to prevent, with
  a success message on top of it.

Two things are surfaced rather than left to be discovered at handshake time.
An **incomplete chain** — an enabled intermediate whose issuer is in neither the
store nor the public roots — is reported on the page; without that, the device
fails with *"unable to get issuer certificate"*, a message that points at the
device rather than at the missing root. And the **per-device probe** separates
the three causes, because they need three different fixes: an untrusted issuer
(import a CA), a hostname mismatch (change the appliance Host, or re-issue with
that name in the SAN), and an expired leaf (re-issue — no CA can rescue it).
"Verification failed" on its own is not an answer.

Postgres is the source of truth, not a file: the PEM rides the streaming
replica and the pg_dump bundles. `pki/` is node-local and gitignored, so a CA
parked there would have to be installed twice by hand and could silently differ
between the primary and the standby. The on-disk bundle is a derived cache each
node rebuilds for itself.

Guards: `tests/test_trust_store.py`, including a real TLS listener so the three
diagnoses are proven against an actual handshake rather than a mocked one, and
a test that the request path really hands the bundle to httpx — resolving it
correctly is worthless if `_request` still passes the raw boolean. The label-is-a-hint rule is pinned by a
test that swaps the two boxes and asserts the stored roles are unchanged, and
the affordance itself by a test that renders the page and requires the
intermediate slot to be present — a backend that classifies correctly is no
use if the operator cannot see where to paste.

## 21. A page is read as a claim about the ADOM it is shown in

Section 19 stops an ADOM from *listing another product's devices*. This one
stops it from being shown another product's **questions**.

The three analytical surfaces — Analysis, Reports and Analytics — were all
built against FortiWeb first, and all three reached a fourth product by
accident rather than by decision:

* **Analysis** dispatched with `if product == 'fortianalyzer': faz else:
  index`. FortiADC, then FortiAuthenticator, inherited the FortiWeb WAF
  dashboard through the `else`. Scoped to a product with no server policies and
  no protection profiles, every panel on that page is empty.
* **Reports** stored a product on the report row and then computed its fleet
  section over the *whole* metrics store, with no `kind` matcher — so a
  FortiAuthenticator report carried FortiWeb's throughput, under a heading that
  named the identity ADOM.
* **Analytics** seeded its built-in boards with `product = ""`, which is
  visible in every ADOM. The `traffic` and `service-health` boards read probe
  kinds that only FortiWeb supports.

Nothing failed in any of the three. Every route returned 200, every template
rendered, every chart drew its axes. **An empty panel reads as "quiet", not as
"not applicable"** — which is the same failure the Fleet health badge had
before §9b, arriving through presentation instead of grading.

### The rules

**No product reaches a page through an `else`.** `views/analysis.py` holds an
explicit `ANALYSIS_PAGES` map with no fallthrough. A product with no entry gets
a page that says so. All four products now have their own page; the map exists
so the *next* one is a deliberate decision rather than a silent inheritance.

**A page written for one traffic device does not transfer to another.** This
was the trap in the FortiADC case, and it is subtler than the FortiAuthenticator
one. An authenticator is obviously not a WAF, so the mismatch was visible. An
ADC *is* a traffic device — same nouns at a distance, published services with
back-ends behind them — which made "close enough" tempting. It is not close
enough: `services.analysis` reads `server_policy` objects plus the
`DeviceServerPool` and `DeviceWebProtectionProfile` projections, and a FortiADC
harvest contains **none of the three**. It has `load_balance_virtual_server`,
`load_balance_pool`, `load_balance_real_server`, and a security model where
profiles do nothing until a virtual server references them. `analysis_adc`
answers the questions that model actually poses: what is published, whether a
pool has a health check, whether a published service has any inspection
attached at all, and which certificates and TLS profiles are past their time.

**Payload keys are transcribed from a live object, never from the reference.**
FortiADC mixes separators inside a single object — `waf-profile` and
`av-profile` are hyphenated while `ips_profile`, `dos_profile`, `auth_policy`
and `ztna_profile` are not — and it pads values with trailing spaces
(`"status": "up "`, `"port": "80 "`). A guessed key does not raise: it reads as
*nothing attached*, so the page reports a fleet with no protection anywhere,
confidently and wrongly. The IPS profile object goes further and ships an
**empty `mkey`**, with the real name in `ips_profile_name`; reading `mkey`
renders a table of blank rows. `tests/test_adc_analysis.py` pins the field
names against a fixture transcribed from a live FortiADC 8.0.3 unit.

**A profile that exists protects nothing.** "Profiles defined" and "profiles
applied" are different statements, and only the second one inspects traffic.
The security section counts virtual servers that *reference* each profile kind.
Factory objects (`_noneditable: 1`) are labelled rather than counted as work —
three WAF profiles that are all shipped defaults is a different sentence from
three somebody tuned, and rolling them together lets an untouched box look
configured.

**Findings come only from sections the sweep collected.** A missing-health-check
or dangling-pool warning derived from a section that was never harvested is a
fabricated outage. Each block reports `harvested` for its source and stays
silent when it is false — including the inverse case, where an empty member
section would otherwise make *every* real server look orphaned.

**Global and the empty scope resolve to the widest page, never to the
refusal.** `product_scope.GLOBAL` is the string `global`; `''` is the
no-context case (a worker thread, or a session stamped before the ADOM split).
Failing closed on an unrecognised scope would blind the one view meant to see
everything.

**A product-scoped document must be product-scoped in its queries too.** Half a
fix is worse than none here: `fleet_queries(product)` picks the metric set and
`_sel(base, product)` adds `{kind="<product>"}` to every expression. Every
series the collectors write carries `kind = appliance.kind`, and the ADOM key
*is* the appliance kind, so one label matcher does it — no device list to
rebuild as the fleet changes. Global still gets the **union**, not the
intersection: the manager-wide view must not shrink because one product has no
throughput.

**A roll-up that cannot apply is omitted, not zeroed.** "0 policies with every
backend down" on an identity product is a clean bill of health for a check that
never ran. `POLICY_PRODUCTS` gates it, and `fleet_section` reports
`policy_scope` so the renderer can say *not applicable* rather than *none*.

**A built-in board may not offer a panel its audience cannot fill.** A board
seeded Global appears in every ADOM, so each of its rule panels must name a
probe kind every concrete product supports. FortiWeb-only telemetry lives on
`product = "fortiweb"` boards; FortiAuthenticator has its own.

**Not harvested is not zero.** A counter the sweep never collected and a
counter that collected nothing render identically as `0` and demand opposite
actions — fix the harvest, or nothing at all. Every inventory row carries
`harvested`, and the template prints the two differently.

**Entitlement is reported, not re-graded.** The licence and token probes own
the thresholds, the history and the alerting. The Analysis page joins their
verdict instead of deriving a second one from the same numbers; a row with no
probe reads `unmonitored`, which is lost coverage, not health (§9b again). A
counter with no ceiling shows no percentage at all, because a fabricated `0 %`
looks like plenty of room.

### Why FortiAuthenticator needed its own page rather than a filtered one

An authenticator is not a traffic device. It has no throughput to plot and no
policy fan-out to map; what bounds it is **entitlement** — an unlicensed unit
reports `users {max: 5}` and refuses the sixth user outright, a cliff no CPU
series would ever show. So the identity page answers three different questions:
entitlement headroom, what identity objects actually exist, and the
authentication settings whose *absence* is the finding (no lockout, no
scheduled backup).

Its inventory rows are **derived from the endpoint registry**, not from a list
written in the page. A list would be a copy, and the first endpoint a release
adds would be missing with nothing failing to say so — the same contract as
`registry_endpoints`, `adoms` and `acme_dns_providers`.

Its posture readers **guard on key membership before they read**. A default
assumed for a missing field produces a confident verdict about a setting nobody
looked at, and that is worse than a gap: the operator stops checking.

And it keeps the DB-first contract of `services.analysis` — cache, manager
tables and the node-local metrics store only. The page opens with the unit
powered off. The guard monkeypatches the client to **raise**, not to return
empty: a stub that returned nothing would let a live call through looking like
a device with no data.

Guards: `tests/test_fac_analysis.py` (22 tests). Nine mutations were applied
and all nine bite, including reverting the dispatch to the `else`, dropping the
`kind` matcher, re-seeding the FortiWeb boards Global, collapsing `harvested`
to a constant, and defaulting an unprobed capacity row to `ok`.


## 22. A capability probe that guesses is worse than no probe

Device provisioning drives someone else's hypervisor, and the thing that
decides whether a run can finish is not SATOM's code — it is what that host
will permit. Every guard in this area exists because a wrong answer here is not
a wrong screen: it is a machine half-built, an address reserved, and a DNS row
nobody will clean up.

**The rule: a capability is reported only after it has been established, and
"unknown" resolves to unavailable.** `app/services/hypervisors/base.py` defaults
every flag in `Capabilities` to `False`; a backend opts in to what it proved.
An unreadable licence is treated as not-writable, because a run that dies at
`CreateVM_Task` after committing an address is worse than one that never
started. `EsxiShell.probe()` runs `vmware -v` — the shell is never claimed from
an open port.

**Preflight before state, always.** `provision_runner.preflight()` compares the
mode's `MODE_REQUIRES` against the live capabilities and the `/advance` route
**refuses with 409** rather than starting a run it cannot finish. Verified by
running it: `full` against a free-licensed ESXi is refused with three named
blockers and the run row is left at `step=draft`, `vm_ref=''`.

**Never narrow a list by one role while reporting on another.** Proxmox splits
`images` (can hold a disk) from `import` (can receive an upload) across
different storages. `list_datastores()` filtered on `images` first and only then
read `import`, so the stock `local` storage — which has `import` and not
`images` — was dropped before its flag was ever evaluated, and the probe told
the operator to add a content type the host already had.

**Never read a cache to answer "does this exist now".** `list_vms()` used
`/cluster/resources`, refreshed on `pvestatd`'s cycle; a machine SATOM had just
built was absent from it while the rollback that followed deleted the same
machine fine.

**Rollback is driven by recorded facts, not by inspecting the world.** An
address is released only when `ip_from_ipam` says SATOM took it; a machine is
deleted only when `vm_ref` says SATOM built it; an onboarded `Appliance` row is
left in place and named in the log. Inferring ownership from current state is
how a rollback deletes somebody else's machine.

**Stopping is not failing.** `semi` and `vm_only` end in `paused` with their
reason from `MODE_STOP_REASON`. Marking a designed handoff as `failed` teaches
operators to ignore the status column, and then they ignore the real failures.

**A durable change to someone else's security posture is never a side effect.**
SATOM detects that `TSM-SSH` is off on an ESXi host and prints the one line
that enables it. It does not enable it. A capability probe that silently opens
a remote root shell to make its own feature work is a surprise, not a feature.

Related bug this class already produced, fixed in the same commit: the
uniqueness check in `hypervisor_save` ran **after** `db.session.add()`, so
autoflush pushed the pending INSERT to satisfy the very query looking for a
duplicate. Every first-time save was rejected as a name clash *and* left a
credential-less row behind, which then failed its connection test with an
authentication error pointing at the wrong cause. Validate, then add.

## 23. A threshold is declared once, inherited live, and always explained

Measured on the live primary on 2026-08-06: **all 42 probes carried the
identical pair 80 / 95.** Not a fleet whose thresholds had been considered and
found to agree — a fleet with no way to *state* a threshold. The only two homes
a graded number had were a column on one probe row and the literal that stamped
it there at creation. Tuning the target fleet (60 FortiWeb + 30 FortiADC +
10 FortiAnalyzer) meant roughly two thousand individual form edits, so nobody
ever did one.

Part of the stored value was not even meaningful: `warn_pct = 80` sat on
`interface`, `proxyd`, `throughput` and `transactions` rows, none of which
grade on a percentage. Noise that reads as configuration.

`app/services/thresholds.py` is now the one place a limit is declared, resolved
and explained, over six scopes: the four product ADOMs (derived from the ADOM
registry, never listed), the manager application, and the machine.

**The registry is DATA.** A field is an entry in `MEASURE`, `ROLLUP`, `FACTS`,
`SATOM` or `HOST`; the form, the validator, the resolver and the origin report
all read that entry. Same contract as `registry_endpoints` / `adoms` /
`acme_dns_providers`. A `MEASURE` key IS the probe column it overrides, so the
override and its default cannot drift by being spelled differently.

**Resolution is live, not copy-on-create.** `NULL` on a probe column means
*inherit*; the scope value is read at grading time. Copy-on-create is what
already existed — it just spells the literal differently, and it freezes every
probe created before the edit. The cost is real and is accepted: a probe nobody
touched can change severity because somebody edited a product default. That is
the point, and it is why the next rule is not optional.

**Every resolved value carries its ORIGIN** — `probe`, `scope` or `default` —
and both probe pages print it. Without it a critical appears with no visible
cause and the operator is worse off than with the frozen literals.

**`0` disables a level; `NULL` inherits.** Different answers, kept different in
storage. This is why the migration may blank a column only when it still holds
the historical creation literal: a `0` somebody chose means "never page me for
this", and inheriting over it would start paging them.

**A binary fact has no threshold, only a volume.** "Every backend of this policy
is down" is not a number. What the operator governs is how loudly it lands —
`crit`, `warn`, or `off` — and only that. **A silenced fact is still printed on
the probe.** Silencing changes the grade, never the visibility; a fact that
stops being printed is an outage nobody can see.

**A mute is targeted, reasoned and expiring.** A probe may be suppressed for up
to 720 hours with a recorded reason. It keeps running, keeps storing samples and
keeps showing its own status; what it stops doing is raising the DEVICE roll-up
— the single roll-up that both the badge and the mail read, so the page and the
mailbox cannot disagree. It is reported as *lost coverage*, exactly like a
disabled probe: a silence somebody chose is still a silence. There is no
permanent mute, because a silence that never expires becomes permanent by
inattention.

**The manager scope writes the engine's own keys.** The `satom` fields store
into `alerts.*`, not into a parallel `thresholds.satom.*` namespace. One number,
two views; a twin would drift the first time somebody edited the older Email
tab. The shipped defaults are duplicated in the registry (a NamedTuple default
is evaluated at import, and importing the engine there would be a cycle) and
pinned by a test against `alerts.DEFAULTS` — a "factory default" printed on a
form that is not what the engine uses is a lie nothing raises about.

**Anti-lockout.** *Revert scope to shipped defaults* clears every override a
scope owns, including the `alerts.*`-backed ones. A scope tuned into permanent
red — or permanent silence — must be recoverable without a psql session.

### 23b. The machine had no signal at all

`system_health.host_stats()` reported the node's load, memory and filesystems
from the day the Monitoring page was written. Nothing ever **graded** it.

On 2026-07-28 the primary reached **95 % disk in six minutes**. Every unit
stayed active, `/healthz` stayed 200, the badge stayed green and the mailbox
stayed empty. It was found by a human running `df`.

`app/services/host_health.py` supplies the grade, on both nodes from one place —
the peer's numbers already ride its `/healthz` response, so the standby is
covered without SSH and without a second implementation. That matters because
the standby is the node *more* likely to fill: it holds the replicated `data/`
tree and the WAL.

Three rules it keeps:

* **A node we could not read is `unknown`, never `ok`.** An unreachable standby
  has told us nothing about its disk. This is the same defect that once made the
  Fleet health badge structurally incapable of turning red (§9b).
* **An unreachable node is not *mailed* about here.** The redundancy check
  already owns "the peer is gone"; two mails for one dead standby is how an
  operator learns to filter the sender.
* **`crit` for disk is 92, not 95.** A full filesystem stops Postgres writing
  WAL. The page has to arrive before the damage, not with it.

Load is normalised to **percent of cores**, not a raw load average: "load 6" is
a crisis on two cores and idle on thirty-two, so a fleet-wide number would mean
something different on every node.


## 24. A cached artifact is stale until the process restarts

`satom diagnose code` exists because a long-lived process can serve code that
no longer exists on disk while every other signal reports health. It compared
the newest `.py` against each process start time — which left out the artifact
gunicorn actually caches.

Jinja compiles a template the first time a process renders it and, with
auto-reload off (the production default), keeps that compiled copy for the life
of the worker. **The cache is per worker and filled lazily.** After a template
edit without a restart, the worker that already rendered the page keeps the old
markup forever while a worker rendering it for the first time picks up the new
one. The symptom is a navigation entry that appears, vanishes and comes back
depending on which worker answers — which reads as a front-end bug, not as a
missed restart.

The rules:

* **Each artifact is charged only to the processes that load it.** Templates go
  to the web worker alone: `render_template` appears nowhere outside the request
  path. Charging them to the sidecars would mark them stale for markup they
  never load, and a check that always complains is a check the operator learns
  to skip — the same failure already removed from `get system health` and from
  the status colouring.
* **Only artifacts a loader can actually read are scanned.** The template tree
  carries editor backups (`*.bak`, `*.pre-<stamp>`, `*.retired-*`) and the repo
  root collects hidden scratch scripts. A module name cannot begin with a dot,
  so a hidden `.py` is structurally unimportable. Neither is ever served, and
  naming one as the reason to restart a service is a false positive that costs
  the operator a restart and costs the check its credibility.
* **The read-out names which artifact moved**, not merely that one did — the
  remedy for a source change and the remedy for a template change are the same
  command, but the explanation an operator needs is not.
* **The template case names the per-worker cache and the false-green
  verification.** A `test_client` render is a fresh process reading from disk,
  so it reports the change present while the running service serves it to
  nobody. Without saying so, the next template edit gets debugged as a
  navigation bug all over again.

A template change is verified against the **running service**, never against a
`test_client`. That distinction is the whole reason this section exists.


## 25. Monitoring has two layers, and neither substitutes for the other

SATOM measures the same appliance twice, on purpose, and the two halves answer
different questions:

* **Collection** (`services/metrics_collect`) is the **time-series** layer.
  One scrape target per *collector*, so a device with 10 000 server policies
  still costs five rows and five calls. It publishes series. It grades nothing.
* **Deep monitors / Service Monitor** (`services/deep_monitor`) is the
  **threshold** layer. It carries warn/crit levels, produces a graded verdict,
  and feeds the `probe` signal of Fleet health and the device-health alert.

Confusing the two has already produced one outage-shaped gap and nearly
produced two more.

### 25a. Both halves are provisioned from one seam

Until 2026-08-06 only the metrics half ran when an appliance was saved:
`ensure_baseline` was reachable **only** from the *Discover* button. A device
added through the normal form collected metrics and carried **no thresholds**,
and neither page said so. The four appliances onboarded on 2026-08-05 had five
collectors and **zero** threshold probes.

Both now come from `services/monitoring_provision.provision_monitoring`, called
from all three appliance-creation paths. Each half is guarded separately, so a
failure in one still provisions the other — and the failure is *reported*,
because a half-monitored device looks exactly like a monitored one.

### 25b. The scale rule is a guard, not a comment

The rule is **not** "fewer probes". It is *per-device, never per-policy*:

| shape | at 50 devices x 750 policies |
|---|---|
| per-device probe (interface, cpu, memory, proxyd) | 200 rows |
| per-policy probe (sessions, throughput, transactions...) | **37 500 rows, 37 500 calls per sweep** |

`tests/test_monitoring_provision.py` fails if any kind in
`deep_monitor.API_KINDS` enters the baseline set. Those are created
deliberately, from *Discover*, by an operator who chose the policies.

**The obvious-looking saving is wrong.** "Collection already reads CPU and
memory, so drop those probes" deletes the only thresholds in the system from
devices that had them, while every page keeps showing data. That is the failure
`deep_monitor.split_legacy_proxyd` exists to prevent, in a new costume.

### 25c. Retiring the threshold layer is blocked, and the reason is written down

Service Monitor's four kinds (`sessions`, `policy_sessions`, `throughput`,
`transactions`) are each covered 1:1 by a scrape target, and the collector does
in ONE call what the probes do in N. That makes them look redundant. They are
not, yet:

* `services/alerts.py` contains **no reference to the store** — verified, zero
  matches for `vm_store` / `satom_`. Every alert check reads probes, actions,
  certificates, git or the host.
* Collection has **no grading layer at all**. It publishes numbers; nothing
  turns a number into warn/crit.

So retiring Service Monitor today removes the "every backend behind this policy
is down" signal from Fleet health and from the alert mail, and **nothing
replaces it**. The prerequisite is alert rules evaluated over the store, which
does not exist. Until it does, the duplication is the cheaper mistake.

### 25d. A value the store never produced is never interpolated

Dashboard variables resolve their options from `vm_store.label_values`. That
enumeration is also the **allowlist**: a selection that is not among the
store's own answers falls back to *All* rather than reaching a query. There are
two layers — `resolve` picks the value, `substitution` re-checks it — and the
second is reachable on its own, so it does not trust the `value` field handed
to it.

Escaping is **not** `re.escape`. Python escapes a hyphen as `\-`; RE2, the
engine VictoriaMetrics uses, rejects that as an *invalid escape* and answers
HTTP 422. Every device and policy name in this fleet contains a hyphen, so
`re.escape` broke the common case and left the rare one working. This was found
end-to-end against the live store — a unit test on the escaper alone cannot
see it, because the output is only invalid to the **engine**.

An expression referencing a variable that could not be resolved becomes a panel
**error**. Running it with the token still in makes the store reject a *parse*
error, which on screen is indistinguishable from the store being down.

### 25e. Endpoint families are censused, never guessed

FortiADC has no `monitor/` namespace: every guessed runtime path returns a flat
404. The real surface was read out of the appliance's own GUI bundle and
verified live — `/api/<entity>/<_method>`, a different shape from the
`/api/<object>` cmdb surface the registry drives.

Two traps worth keeping:

* `platform/resources` returns `"1 CPU/1 allowed"` and `" 3831 MB RAM"` —
  **installed hardware, not utilisation**. Parsing it as a percentage publishes
  a fabricated series. CPU and memory keep coming from the read-only CLI.
* `status_history/vs_status` is the analogue of FortiWeb's `policystatus`: ONE
  call carries the whole vdom, which is why virtual servers are a *collector*
  and not a probe-per-service.

Where a shape could not be verified against live hardware (FortiAnalyzer: none
reachable since July 2026), the payload is read **defensively** and an
unrecognised shape yields nothing. A plausible wrong number on a log collector
is worse than a gap.

## 11. Known gaps (kept honest, on purpose)

* Per-device configuration restore is dry-run gated — no live canary round-trip yet.
* The public wildcard certificate is not auto-renewable from the node; it is
  re-copied when the edge renews it. Internal-CA certificates *do* auto-renew.
* The firmware manifest in the SoT repository is maintained by hand.
* Gitea and the standby share a host (hypervisor03). The bundle to backup-server exists
  because of that, but it mitigates rather than fixes it.

### Capability probes and provisioning (22)

```sh
# Every capability flag defaults to False — a backend opts in to what it proved.
grep -n "= False" app/services/hypervisors/base.py | head

# The shell transport is claimed only after a command actually ran.
grep -n "def probe" -A8 app/services/hypervisors/esxi_shell.py

# Preflight gates /advance; a refused run must not reach a step function.
grep -n "preflight refused this run" -B6 app/views/device_provision.py

# The two Proxmox storage roles are asked separately.
grep -n "def disk_datastores\|def import_datastores" app/services/hypervisors/proxmox.py

# "Does it exist now" is answered from live node state, not the cluster cache.
grep -n "nodes/{node}/qemu" app/services/hypervisors/proxmox.py

# Rollback is guarded by recorded facts.
grep -n "ip_from_ipam\|run.ref()" app/services/provision_runner.py

# Uniqueness is checked BEFORE the row joins the session (autoflush self-clash).
grep -n "clash = HypervisorTarget" -A3 app/views/settings.py

# Device provisioning is NOT a FortiWeb area (0 expected).
sed -n '/fortiweb_scoped = {/,/}/p' app/__init__.py | grep -c device_provision
```

## 26. A model proposing a change is not the same as a change

The AI Advisor (`docs/ai-advisor.md`) can suggest a WAF exception or a Lua
script. It cannot create either on a device, and it cannot write SATOM's own
applied configuration. What it CAN do is emit a schema-validated
`AdvisorProposal` row, and an operator with the SAME permission the manual
form already requires can turn that into a DRAFT — a `WppException` row via
the guided-exceptions store, or a `LuaScript` row in `status: draft` — never
a device call. Applying still needs the guided flow (Exceptions page) or Lua
Studio's own dry-run deploy, exactly as if the operator had typed it in.

Two failure modes this guards against, both concrete:

- **A softer gate than the manual form.** `apply_proposal` is called with the
  SAME coarse/granular permission key the hand-typed endpoint checks
  (`config_write` for exceptions, `studio.lua_studio` — super-admin only —
  for Lua). Gating the AI path on anything looser would make it an easier
  route to a Lua draft than typing one in.
- **Untrusted device data steering the model.** A WAF log line is
  attacker-influenced text. It is wrapped in an explicit delimiter
  (`<<<UNTRUSTED>>> ... <<<END_UNTRUSTED>>>`) with a system-prompt
  instruction never to follow directives found inside it — but the write
  boundary above is what actually holds if that instruction is ignored: a
  successfully-injected model still cannot reach a device, only propose a
  draft a human reviews.

An external provider call is gated TWICE past having a key configured:
`ai.external_allowed` must be explicitly on, and the outbound text (message
+ attachments) is redacted with the SAME identifier table that protects the
public documentation site before it leaves the LAN, with the count and the
exact text shown to the operator in a pre-send preview
(`POST /advisor/<id>/preview`) before `/send` is ever called.


## 27. Config that only one node has is config that will drift

Three mechanisms move state between nodes, and each covers exactly one thing:

| mechanism | what it carries |
|---|---|
| git | the tracked source tree |
| HA datasync | `${APP}/data/`, minus a list of volatile subdirectories |
| backup bundle | `pg_dump` + `reports/` + the versioned SoT blobs + config |

Nothing else is carried by anything. A file that is untracked *and* outside
`data/` is replicated by nothing at all, and no error says so — each mechanism
is individually behaving correctly.

That is how the site-rules overlay drifted. It is untracked on purpose: it
names the estate this installation runs on, and shipping it to the public
mirror would be the disclosure the file exists to prevent. But it also sat
beside the application rather than inside `data/`, so the datasync never saw
it. The standby ran for days on a copy written before half the appliances it
was supposed to redact had been registered — and the primary, where the file
had been fixed, gave every appearance that the fleet was covered.

**The rule: state that must be identical on every node lives in `data/`.**
Untracked is a statement about git, not about replication. If the reason a
file is untracked is that it is sensitive, `data/` is already ignored — the
secrecy is preserved and the replication comes free.

### Absent, malformed and stale are three different answers

The loader gave all three the same one — an empty rule table — and an empty
rule table reads to every caller as *nothing to redact*. Output still looks
redacted. Nothing logs. The only thing that changes is which identifiers walk
through.

It gets narrower than a missing file: one unusable regex used to cost exactly
one rule, skipped with `continue`, while every other rule kept working.

- **Malformed** — a half-written or truncated file is never a legitimate empty
  overlay. Raise.
- **One unusable entry** — refuse the whole table rather than run a partial
  one. A rule table you cannot enumerate is not a rule table.
- **Absent** — this is the case that needs a signal, because the permissive
  answer is genuinely correct somewhere.

### Why absence alone cannot be the alarm

The published mirror has no overlay and **must not have one**, and there is
nothing site-specific left in that tree to redact anyway. So "file missing"
describes both the healthy mirror and the broken node. The code cannot pick a
side without another fact.

The fact it uses is `.env`: a mirror is a source tree, a deployment has
secrets. Missing overlay on a tree with no `.env` loads the generic rules and
proceeds. Missing overlay next to a live `.env` raises, and the process
refuses to come up rather than serve pages it cannot certify.

Refusing to boot over a config file is deliberate. This control has already
published internal identifiers once. A node that will not start is an
afternoon; a node that quietly redacts less is however long it takes someone
to notice, and by then it is on a CDN.

### The compatibility read is not politeness

An existing node has the file at the old path. Without the fallback, merging
the strict loader turns a routine code update into a boot failure on every
node that has not been migrated — a self-inflicted outage delivered by the
reconciler. The new location wins when both exist, because the copy the
datasync maintains is the live one and the other is by definition the one that
went stale.

### Guards

`tests/test_publication_overlay.py` — the overlay resolves under `data/`; no
datasync exclude shadows it; it is still ignored by git in its new home;
malformed JSON, an unusable rule and an unusable scanner entry each raise; a
deployment missing it raises; a bare checkout missing it does not; a
well-formed overlay still loads (the counterweight — a guard that raises on
everything is not a guard); the legacy path is still read and loses to the
replicated copy; the bundle carries the file and a restore never overwrites a
live one; and the module stays stdlib-only, because the site generator loads
it by path precisely so the site can be built from a tree whose application
code does not import.


## 28. The two secrets no backup carries

`app/services/recovery.py` · `app/services/system_backup.py` ·
`satom diagnose recovery` · `satom execute export recovery-key`

Two secrets gate recovery of an installation, and no mechanism replicates
either one:

| secret | where it lives | what it opens |
|---|---|---|
| `FERNET_KEY` | `.env`, node-local | every encrypted column in the database |
| `pki/internal-ca/ca.key` | primary only | the sole issuer for replication mTLS |

`.env` is gitignored, sits above `data/` so the datasync never reaches it, and
is not in a bundle. The CA key is excluded from replication deliberately — the
peer holds `ca.crt` only, because one issuer is the point. Between them that
left a gap nobody could see: **a bundle restored onto a rebuilt node is a
database of unreadable secrets**, and nothing anywhere said why.

### The decision: the key stays out of the bundle

The obvious fix — put `.env` in the bundle — was rejected, and the reason is
worth keeping because it will be proposed again.

A bundle is retained for weeks, mirrored to the peer, and pushed off-box over
SFTP using a password that itself lives in an encrypted column. A bundle
carrying the key that opens that password is not a backup of the estate; it
*is* the estate, in one file, in three places, on a host outside the
management network. Every property that makes a backup good — copies,
retention, off-site — is exactly what you do not want for this one secret.

So the bundle carries a **fingerprint** instead, and custody becomes an
explicit, audited operator action.

### The rules

1. **A fingerprint identifies a key; it must never disclose one.** It is
   SHA-256 over a domain tag, a separator byte, and the material, truncated to
   64 bits. Domain separation is not decoration: without it the same bytes
   under two roles collide, and a digest computed for one purpose could be
   replayed as proof for another.

2. **Absent material fingerprints to the empty string, never to a digest.**
   `""` must not collide with a real key's digest, and must stay falsy so a
   caller can tell "no material" from "material I hashed".

3. **A manifest emits a line per kind even when the value is empty.** An empty
   value and a missing line mean different things — *this node held no CA key*
   versus *this bundle predates fingerprinting* — and collapsing them makes an
   old bundle indistinguishable from a standby's.

4. **A key mismatch is reported, never enforced.** `compare_manifest` cannot
   raise and does not block. A restore is a recovery action; an operator
   mid-outage holding the right key must not be stopped by the check that
   exists to help them. It names both fingerprints and the remedy, and the
   finding is *prepended* to the detail so it outranks every pg_restore
   warning above it.

5. **The escrow ledger records a fingerprint and a timestamp — never the
   secret.** `app_settings` is dumped verbatim into every bundle, so a secret
   recorded there would defeat the entire reason it was kept out.

6. **Export returns; it never writes.** Choosing where a secret lands is the
   operator's decision. A default destination is how an untracked second copy
   gets created. `--out PATH` exists for when the operator wants that copy, and
   opens the file `0600` *before* any bytes land — creating it `0644` and
   chmod-ing after leaves a window where the key is world-readable.

7. **A node that does not hold the CA key is not nagged about escrowing it.**
   The standby holds `ca.crt` only, by design. Asking it to escrow an issuer it
   must not have is the permanent-false-positive shape this repo has removed
   three times; a check that fires on a healthy node is a check operators learn
   to scroll past.

8. **"I could not read `.env`" is not "there is no key."** `.env` is
   `640 root:<service account>`, so an unprivileged caller has learned nothing
   about custody. The CLI check exits 4 *cannot evaluate* rather than
   fabricating a verdict — the same fail-open shape this catalogue exists to
   remove.

### What it changed in practice

`satom diagnose recovery` on the primary reported, on the day it was written,
that **neither secret had ever been exported** — the fleet's Fernet key and its
sole CA issuer existed on exactly one disk each, and no bundle, no replica and
no document recorded that. The `restore` runbook actively said the opposite
("total loss is recovered from ... any one bundle copy"); it now says a bundle
alone does not recover a total loss, and points at the two commands.

### A test note that generalises

The first version of the guard for rule 8 pointed its fixture at a nonexistent
`app_dir`. The mutation *survived* — because a missing venv produces the same
"cannot evaluate" message from a different branch, so the test could not tell
which one answered. Fixing it meant substituting a double that **would** return
a confident verdict if reached. A test that cannot distinguish the two paths
proves nothing about either.

## 29. A probe that could not answer is not a healthy answer

This is the single defect this release exists to remove, found in nine places
at once. The shape is always the same: a probe fails, the failure is swallowed,
and the **default that replaces it is a value that means "fine"**.

| where | on failure it said | which downstream read as |
|---|---|---|
| `product_scope.session_product` | `""` | Global console - show every product row |
| `settings_store.get_json` (access rows) | `[]` | no restriction configured - admit everyone |
| `git_service.git_info` | `ahead=0 behind=0 dirty=False` | repo clean and in sync |
| `git_backup._out` | `""` | nothing ahead |
| `self_update.ha_mode` | `standalone` | staged-rollout interlock not required |
| `self_update_runner.preserve_local_commits` | `None` | nothing to preserve - proceed to a hard reset |
| `hypervisors/base._ssl_context` | `True` | verified (public roots only, never the operator CA) |
| `ssh_ops` known_hosts | empty pin set | first contact - accept any key |
| `theme_service.audit_contrast` | no finding | palette is readable |

None of these crash. None appear in a log. Each answers a *safety* question
with the reassuring value, which is why they survived so long: the system
reports health precisely when it has lost the ability to measure it.

### The rules

1. **Three states, not two.** Every probe that informs a safety decision
   distinguishes *it is fine*, *it is not fine*, and **I could not tell**. The
   third is not a variant of the first.

2. **The permissive default is usually legitimate - that is why it must not be
   reused.** `""` really does mean "Global console, show everything". An empty
   allowlist really does mean "no restriction", and it is lockout-safe by
   design. A genuinely single-node install really is standalone. Each of these
   is correct, and each was the wrong answer to *I could not evaluate*. The fix
   is never to make the empty case strict; it is to stop the failure case
   borrowing its value.

3. **Fail closed where the caller can recover, fail loud where it cannot.**
   Scoping filters to zero rows. The access gate returns **503, not 403** - the
   service could not evaluate policy, the user did not fail it - and admins are
   answered above the gate so whoever must fix the row can still reach the UI.
   A restore reports and continues, because blocking a recovery action during
   an outage is worse than the thing it warns about.

4. **A degraded fallback must announce itself.** `branding._refresh()`
   substitutes a hardcoded five-ADOM literal on any registry failure and
   returns it looking like a successful read - silently defeating the
   derivation that replaced that same literal. `is_fallback()` is what lets a
   caller tell an answer from a substitute.

5. **A defaulting helper may exist, but nothing deciding safety may call it.**
   `_git_out` still returns a default for display fields. `git_info` uses
   `_git_try`, which reports whether git answered at all. Mixing them is how a
   repository nobody could read reported itself clean.

### Verified redundancy is not the same as an untested guard

Several mutations here survive individually and bite in combination, because
two probes independently detect the same fault (`rev-parse` and `status` both
notice an unreadable repo). That is real redundancy and is recorded as such -
after checking, not instead of checking. The distinction matters: an untested
guard and a redundant one look identical in a mutation table until you remove
both halves.

## 30. Every SSH channel pins, and the rule has one implementation

Three places open SSH from this app. Each had its own answer and two of them
had none at all:

| channel | carries | pinning before |
|---|---|---|
| `ssh_ops` (appliance CLI) | appliance admin credentials | a store, loaded inside a bare except |
| `cert_service.autopull` | **the node TLS private key** | none |
| `hypervisors/esxi_shell` | root shell on a hypervisor | none |

`AutoAddPolicy` with no store is not weak pinning. It accepts whatever key
answers, every time, forever, and can never notice the answer changed.

This is not theoretical here. When this fleet recycled appliance IPs on
2026-08-03, host-key verification was the only thing that stopped SATOM from
presenting Fortinet admin credentials to an unrelated backup server - with an
admin lockout threshold of 3 on those devices, the admin accounts would have
been locked out permanently. The control worked on the one channel that had it.

### The rules

1. **An absent store is first contact - trust it and record the key. A store
   that exists and cannot be read in full is a BROKEN control, not a missing
   one - refuse, and name the file.** paramiko does not distinguish these:
   `load_host_keys` silently **skips** every line it cannot parse, so four of
   five pins can vanish while the load reports success. Every non-comment line
   is parsed first and any failure is fatal.

2. **An existing but empty store is refused.** A truncated store is not first
   contact; treating it as one silently re-pins to whatever answers next.

3. **Failing to persist a newly accepted key is fatal.** Swallowing it means
   every subsequent connect is first contact again - a control that looks armed
   and has never once been armed.

4. **Pinning must not make a fresh host unusable.** An ESXi host key
   legitimately changes on reinstall, which is why the original code chose
   AutoAdd. Trust-on-first-use satisfies both: absent stays trusted. What is
   refused is the case that reasoning did not consider - an unreadable store,
   where accepting a new key discards a pin that was protecting the connection
   yesterday.

5. **One implementation.** `app/services/ssh_pinning.py` is the only copy;
   `ssh_ops` delegates. A second copy of a security rule is a second copy that
   rots, which is exactly how two of these three channels ended up with no
   store at all.

The guard is written per-file over everything that hands paramiko a
missing-host-key policy, so it fails on the **fourth** channel somebody adds -
the one nobody will think to check. Its first version searched the source text
for `load_pins` and passed on a file whose only remaining mention was its own
unused import; the mutation caught it, and it now matches a *call* in the AST.
That is the thirteenth time a substring assertion in this repo has matched
something that was not its subject.

## 31. Shipping a file and distributing it are different problems

A file can be in git, correct, reviewed, and still not be what the node runs.
Three mechanisms move files here and each covers a different part of the tree:

| mechanism | reaches | misses |
|---|---|---|
| git / self-update | the app tree | anything outside the app directory |
| `satom-ha-datasync` | `data/` on the peer | everything above `data/` |
| backup bundle | db + `reports/` + `sot/` + config | the rest of the filesystem |

Everything in the gaps needs an explicit installer, invoked from every path
that updates a node - or it silently keeps whatever it was given the day it was
installed.

### What was actually stale

- **The out-of-tree `satom-ha-datasync.sh`** was three months behind its git
  source. The only thing that had ever installed it was a one-shot migration
  script. The running copy was missing the fix that separates *"I could not
  evaluate the peer"* from *"there is no peer configured"* - so the replicator
  itself could report SUCCESS while replicating nothing. That is this
  catalogue section 29 applied to the mechanism that carries section 29 fixes.
- **Four unit files were never refreshed** because `UNIT_FILES` was a
  hand-typed tuple that had fallen behind `deploy/`. Three installed units
  still declared a service account that no longer exists; they run only because
  a drop-in overrides them, and that drop-in is regenerated only when an update
  happens to run on that node.

### The rules

1. **Derive the list from the directory, never retype it.** `UNIT_FILES` and
   `NONROOT_UNITS` are now computed from the unit templates in `deploy/`. A
   hand-list is a copy, and this gap *is* what a rotted copy looks like.
2. **Refreshing a unit file is not arming it.** Nothing changes enable state;
   it is preserved. Cluster-only and retired units are named explicitly so the
   drop-in keeps covering them without arming them.
3. **Root-owned, outside the app tree, byte-verified.** The out-of-tree copies
   are installed root-owned 0755 and checked with `cmp` against their source. A
   sudo target writable by the service account is a root escalation - the
   reason the runner was moved out of the tree in the first place.
4. **A guard fails when `deploy/` ships a unit no mechanism distributes**, so
   the next unit added cannot repeat this silently.

### Retirement has to be finished, not just decided

The hourly git publisher was retired on 2026-08-05, and four operator-facing
surfaces still described it as live - including the install manual, which told
the operator to arm it on a fresh node, and the **High Availability page**,
which is precisely where someone goes to confirm their replication topology.
The script it named had no source in the repository at all.

A retired mechanism that still appears in the documentation is worse than one
that was never built: it is a copy the operator believes they have.

## 32. A secret that must not spread in the clear can still spread sealed

Section 28 argued that `FERNET_KEY` and the internal CA key must stay out of a
backup bundle, and that argument still holds: a bundle is retained, mirrored to
the peer and pushed off-box over SFTP with a password that lives in a column
`FERNET_KEY` opens. Plaintext there collapses the whole scheme into a single
file — lose one bundle, lose the estate.

But the argument was never *the material must not leave the node*. It was **the
material must not leave the node in the clear**. Reading it the stronger way
bought a real cost: a bundle restored onto a rebuilt node is a database of
unreadable secrets, and `diagnose recovery` kept reporting that nobody had ever
run the export that would have prevented it — because "print it and file it
somewhere" works exactly as well as the operator's filing.

The envelope inverts the asymmetry instead of choosing a side. Whoever steals a
bundle holds ciphertext. The operator, holding a passphrase and nothing else,
rebuilds the installation from **any** copy.

### The rules

1. **The envelope lives in `data/`, and nowhere else is acceptable.** `data/`
   is the one directory both mechanisms carry: the HA datasync rsyncs it to the
   peer and the bundle packages it. A file outside it is carried by neither —
   which is precisely how `publication-rules.local.json` sat stale on the
   standby for weeks (§27). `data/` is also gitignored, so no envelope can
   reach the published mirror.

2. **The passphrase is created at INSTALL, not at cluster join.** A standalone
   node never joins, and a standalone node is the one with no second copy of
   anything — it needs the envelope *more* than a pair does. A secondary
   inherits the passphrase through the join key so both nodes open the same
   envelope; that adds no new class of secret, because the join key already
   carries `fernet_key` and `ca_key` in the clear and is the most dangerous
   artefact in the whole process.

3. **The passphrase is never stored — not even hashed.** A verifier sitting
   beside the ciphertext is an offline cracking oracle, and *does it open* is
   the only check anyone ever actually needs. It is printed once and blanked if
   the seal fails, because telling an operator they hold custody they do not
   hold is worse than telling them nothing.

4. **The passphrase never enters argv.** `_app_call` runs `python3 -c
   <snippet>`, so a snippet with the passphrase interpolated into it *is* the
   child's command line — readable in `ps` by every user on the box — and any
   traceback echoes the offending source line into whatever the caller
   redirects. It travels in the environment, and the installer sends the seal
   call's output to `/dev/null` rather than to a log file that survives on disk
   beside the node.

5. **The fingerprints stay in the clear, and are authenticated.** Without them
   a restore cannot tell *this envelope holds the key I need* from *this holds a
   key from two rotations ago* without first spending a passphrase guess —
   exactly the moment an operator has none to spare. They are covered by the
   AEAD's associated data, so an envelope cannot be relabelled to claim a key it
   does not hold: otherwise the check that exists to prevent a forensic
   afternoon would cause one.

6. **An unreadable envelope reports "not sealed", never "sealed".** Corrupt must
   never render as fine — §29 in one more place. Likewise a bundle built without
   an envelope says so, because a bundle that cannot rebuild anything looks
   identical to one that can.

7. **A restore keeps the node's own envelope.** A live node is the authority on
   its own custody; the envelope frozen into an old bundle is by definition
   older. Overwriting would swap the passphrase the operator holds for one they
   rotated away from.

8. **Nothing re-seals itself.** An envelope silently re-wrapped under material
   the operator has not recorded is an envelope the operator cannot open. A key
   rotation makes the seal *stale* and says so; re-sealing is always explicit.

Sealing does not replace `execute export recovery-key`. That path hands the
operator the raw secrets for a vault they control; this one guarantees a copy
survives in places the fleet already replicates to. They fail differently, which
is the point of having both.


## 32b. A sealed envelope nothing can read is not custody

`satom execute seal recovery` needs root, because only root can read
`.env` and the CA key. Every mechanism that carries the envelope off the
disk — the HA datasync over SSH, the backup-bundle writer — runs as the
**service account**. So the command that creates the envelope and the
commands that copy it are two different users, and nothing in the seal
path said so.

On 2026-08-07 the first real seal produced `data/recovery/` as
`drwx------ root root` with a 0600 file inside. The envelope was
cryptographically perfect and structurally unreachable: the service
account got Permission denied on both the directory and the file, so the
datasync would have skipped it and the bundle writer would have logged
`recovery-seal ABSENT`. Meanwhile `diagnose recovery` **dropped** the
"no sealed envelope" finding and reported the durability problem solved.

That is worse than no envelope. No envelope tells the truth.

**The rules**

1. **Ownership, never a wider mode.** Reachability is bought by handing
   the envelope to the tree owner, not by making it group- or
   world-readable — that would "fix" the copy mechanisms by handing the
   envelope to every account on the box, which is the opposite of sealing.
2. **The owner is derived, never named.** The service account is `satom`
   on new installs and `fortinet` on nodes that adopted an existing tree.
   `_tree_owner()` stats the app root. Hardcoding either name is how the
   datasync broke once already.
3. **Hand it over before publishing it.** The chown lands on the temp
   file, so `os.replace` publishes an already-correctly-owned inode. A
   chown *after* the replace leaves a window in which a datasync would
   copy an unreadable file and record a success.
4. **Reachability is a stat comparison, not an open().** Root opening the
   envelope successfully is exactly how a root-owned envelope reported
   itself as custody. The probe must give the same answer whoever asks.
5. **An unreachable envelope is CRITICAL**, and deliberately worse than
   "not sealed at all" — because it makes the not-sealed finding go away.
6. **A live seal answers the escrow question; a dead one does not.**
   Sealing and escrow answer the same question — does a copy survive
   losing this disk — and sealing answers it better, so a sealed kind
   stops producing the "never exported" warning. `diagnose recovery`
   grades **any** finding as at-least-warn, so leaving it would mean a
   correctly configured node can never report ok, and a check that always
   complains is one operators learn to skip. Suppression requires all
   three of: parses, **reachable**, and fingerprint matches the live key.
   Cannot tell → stay noisy.
7. **Suppressing a warning without showing what replaced it** makes a
   quiet check an unexplained one. `diagnose recovery` prints the
   `sealed envelope` row next to the `exported` rows for exactly that
   reason.

**Related, same shape:** `Result.rows(heading, rows)` takes the heading
first, and a call that forgets it raises `TypeError` on the **success**
path — after the command has already changed the system. It bit
`seal recovery` (envelope written, `[FAIL]` printed) and was sitting
unexploded in `reset theme`, the anti-lockout command an operator reaches
for precisely when they cannot get into the console another way. Grepping
for the two known sites would not have found the third; the guard walks
the AST of every `deploy/satom_cli/*.py`.

## Verifying the guards are armed

### The AI Advisor write boundary (26)

```bash
# applying a proposal never touches a device — it only ever inserts into
# WppException or LuaScript, gated by the SAME permission the manual form uses
grep -n "wpp_exceptions.add\|LuaScript(" app/services/advisor.py

# external providers need BOTH a configured provider AND the explicit flag
python3 - <<'PY'
from app.services import advisor as svc
assert not svc.external_allowed()  # off by default on a fresh install
PY

# the guards themselves, and proof they bite: seven mutations, seven kills
# (write boundary, external switch, draft status, untrusted wrapping,
#  validation, shipped-on defaults, preview honesty)
venv/bin/python3 -m pytest tests/test_advisor.py -q
```

### Monitoring layers (25)

Both halves provisioned from one seam, and no per-policy kind in the baseline:

```bash
# a saved appliance gets BOTH collectors and threshold probes
satom get monitor coverage        # or, against the app:
#   provision_monitoring(a) -> {"targets": N, "probes": [...]}

# the scale guard: this must print nothing
python3 - <<'PY'
from app.services import deep_monitor as dm
import ast, inspect
src = inspect.getsource(dm.ensure_baseline)
kinds = {n.elts[0].value for n in ast.walk(ast.parse(src.lstrip()))
         if isinstance(n, ast.Tuple) and n.elts
         and isinstance(n.elts[0], ast.Constant)}
print(sorted(kinds & set(dm.API_KINDS)))   # must be []
PY
```

The store is still not an alerting source — if this stops printing 0, §25c has
been overtaken and Service Monitor may finally be retirable:

```bash
grep -c 'vm_store\|satom_' app/services/alerts.py     # 0 today
```

A variable never interpolates a value the store did not produce, and the
escaper does not escape a hyphen:

```bash
python3 -c "
from app.services.dashboard_vars import _escape_regex as e
assert e('pol-satom-lab') == 'pol-satom-lab'   # RE2 rejects a backslash-hyphen
assert '\\.' in e('fw.08')                     # but metacharacters ARE escaped
print('ok')"
```


### The freshness check sees what the process caches (24)

Two artifacts, charged to different processes. Both rows must be present:

    satom diagnose code
    # expect a "newest source" AND a "newest template" row

Neither scan may pick up something no loader reads. Plant a backup newer than
every template and a hidden scratch script newer than every module; the named
artifacts must not change:

    touch app/templates/base.html.bak .scratch.py
    satom diagnose code | grep -E 'newest (source|template)'
    # expect a real .html and a real .py -- never the .bak, never the dotfile

The sidecars must stay clean for a template-only edit:

    touch app/templates/base.html
    satom diagnose code | grep -E 'scheduler|reconciler'
    # expect "current" on both -- they do not render Jinja

And drop the suffix filter, the dot filter or the TEMPLATE_CONSUMERS tuple and
`tests/test_template_staleness.py` fails.


### Freshness and drift read the right source (18)

Freshness must follow the *newest* layer, not the nightly one. On a FortiWeb
(which has both layers) and on any non-FortiWeb device (which has only
`config`), both must read the hourly sync -- the Device health page grades
every non-parked appliance `ok` on the cache signal within the budget.

Drift must not shell out to git; the baseline left git in section 14. Read the
body of the check and confirm no git invocation survives inside it:

    sed -n '/^def _check_drift/,/^_CHECKS/p' app/services/alerts.py \
      | grep -c 'subprocess\|"git"'
    # expect 0 -- match on what EXECUTES, never on the prose that explains it

And a parked box must be silent: drop the `maintenance` test from the loop and
`tests/test_health_freshness_and_drift.py` fails.

### The appliance roster is per-ADOM, list AND by-id (19b)

No template may name a platform in an option value -- that list is derived:

    grep -rn 'option value="forti' app/templates/ | wc -l
    # expect 0

Then check the two halves separately, because the list was already correct
while the by-id route was not. Inside one product ADOM, the index must show
only that product, and another product's appliance id must answer 404:

    curl -sk -H 'X-ADOM: fortiweb' https://<node>/appliances/<a-fortiadc-id>
    # expect 404, not 200 and not 403

### An ADOM shows only its own product (19)

Every concrete ADOM must see its own devices and nothing else. Count them per
ADOM against the live database -- the numbers must partition, and only FortiWeb
may claim an unscoped row:

    for p in fortiweb fortiadc fortianalyzer fortiauthenticator; do
      curl -sk -H "X-ADOM: $p" https://<node>/monitoring/data \
        | python3 -c 'import json,sys; d=json.load(sys.stdin);
            print(sorted({x["kind"] for x in d.get("devices",[])}))'
    done
    # expect exactly one kind per ADOM, each matching the ADOM

The structural half: no caller may re-declare the product list. Reverting
`alerts._product_of`, `cert_manager._product_kind` or
`plugin_sandbox._appliance_options` to a literal tuple fails
`tests/test_product_scope_isolation.py`, and so does hardcoding the key set in
`product_scope.product_keys()`.

### The trust store adds to the public roots (20)

The bundle must be certifi PLUS the imported CAs -- never the imported CAs
alone, or every publicly-signed appliance stops verifying:

    python3 -c "import certifi; print(certifi.contents().count('BEGIN CERTIFICATE'))"
    grep -c 'BEGIN CERTIFICATE' /opt/satom/pki/trust/ca-bundle.pem
    # the second must exceed the first by exactly the number of enabled CAs

And the failure direction, which is the one that matters: make the bundle
unbuildable and confirm the answer is the public roots, not "no verification".
`verify_param()` returning `False` there would disable TLS checking fleet-wide
in silence -- `tests/test_trust_store.py` fails if it ever does.

### State that exists only here (4b)

A node has to say what it alone holds, *before* anyone resets it.

```bash
# 1. on a clean node the section is present and does not grade
satom diagnose git --json | python3 -c \
  "import json,sys; d=json.load(sys.stdin); \
   s=[x for x in d['sections'] if x['heading']=='state that exists only here']; \
   print('section present:', bool(s)); print('status:', d['status'])"

# 2. plant a real modification and confirm it is SEEN and NAMED
echo '# probe' >> app/version.py
satom diagnose git | grep -A3 'state that exists only here'
satom diagnose git | grep -q 'app/version.py' \
  && echo 'names the file' || echo 'GUARD BROKEN: modification not named'
git checkout -- app/version.py

# 3. an untracked file must NOT grade -- the primary carries one by design.
#    Compare BEFORE and AFTER: an absolute "expect ok" would fail on any tree
#    that is legitimately dirty, and blame the wrong half of the check.
st() { satom diagnose git --json \
       | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])'; }
BEFORE=$(st); touch .probe-untracked; AFTER=$(st); rm -f .probe-untracked
test "$BEFORE" = "$AFTER" \
  && echo "untracked does not grade ($BEFORE unchanged)" \
  || echo "GUARD TOO LOUD: $BEFORE -> $AFTER on an untracked file"
```

Step 3 is the half that is easy to lose. A check that flags every untracked file
warns permanently on the primary, and a permanent warn is indistinguishable from
no check at all. It is written as a before/after comparison on purpose: asserting
a bare `ok` only holds on a spotless tree, so on a working node it would report a
failure of the guard when what it actually found was uncommitted work — which is
the very thing the guard exists to surface.

### Metrics auto-provisioning (§15)

```bash
# 1. every creation path provisions — the call, not the comment
python3 - <<'PY'
import ast, pathlib
t = ast.parse(pathlib.Path('app/views/appliances.py').read_text())
for fn in ('create', 'edit_save'):
    f = next(n for n in ast.walk(t)
             if isinstance(n, ast.FunctionDef) and n.name == fn)
    calls = [c.func.id for c in ast.walk(f)
             if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)]
    print(fn, '_provision_metrics' in calls)
PY

# 2. no live device may be silently uncollected: every eligible device
#    owns targets, and the page names the ones that do not
curl -sk -b "$COOKIE" https://<node>/monitoring/collection/data | python3 -c \
  "import json,sys; d=json.load(sys.stdin); \
   print(len(d[\"targets\"]), \"targets;\", \
         [(g[\"name\"], g[\"reason\"]) for g in d[\"gaps\"]])"
```

### Published cross-references (§7d)

Rendering is not evidence — request the target. From a checkout:

```bash
# 1. nothing published may still point at Markdown
grep -o 'href="[^"]*\.md"' site/docs/*.html site/docs.html | wc -l     # expect 0

# 2. and the links that ARE there must resolve on the live site
for slug in $(grep -o 'href="[a-z0-9-]*\.html"' site/docs/readme.html \
              | cut -d'"' -f2); do
  printf '%s %s\n' "$(curl -s -o /dev/null -w '%{http_code}' \
    "https://satom.visionebc.com/docs/$slug")" "$slug"
done | grep -v '^200' || echo 'every cross-reference resolves'
```

A generator change that neuters the rewrite shows up as a non-zero count in
step 1; one that strips links instead of rewriting them shows up as an empty
list in step 2.

### Licence consistency (7f)

Every surface, one answer — from a checkout:

```bash
# 1. no declaring file may name the old licence
grep -l 'Apache' NOTICE README.md CONTRIBUTING.md DISCLAIMER SECURITY.md \
  2>/dev/null || echo 'declaring files are clean'

# 2. the LICENSE body must be the current grant, not just its name
grep -q 'hosted or managed' LICENSE && grep -q '## No Liability' LICENSE \
  && echo 'LICENSE carries the operative text'

# 3. every published footer agrees (curated + generated)
grep -ho 'Licensed under[^<]*<a[^>]*>[^<]*</a>' site/*.html site/docs/*.html \
  | sort -u        # expect exactly ONE distinct line

# 4. and the live site says the same thing
curl -s --resolve satom.visionebc.com:443:185.199.108.153 \
  https://satom.visionebc.com/ | grep -o 'Licensed under[^<]*<a[^>]*>[^<]*</a>'

# 5. no reachable commit still offers the old grant -- blobs, not ref tips,
#    because the published tags are not refs of the mirror that produced them
git rev-list --objects --all | awk '$2=="LICENSE"{print $1}' | sort -u \
  | while read -r s; do
      git cat-file blob "$s" | grep -q 'TERMS AND CONDITIONS FOR USE' \
        && echo "STILL OLD: $s"
    done; echo 'history scanned'
```

Step 3 is the one that catches drift: a second distinct line means the
generator and the hand-written pages have diverged. Step 4 is the only one that
proves the *published* mirror was refreshed — a force-push to `gh-pages` does
not always trigger a build (see 7e).

### 8e — brand gradients and asset stamps

```bash
# the gradient pattern refuses a declaration escape on its own
python3 - <<'EOF'
from app.services.theme_service import VALIDATORS
bad = "linear-gradient(135deg, #000 0%, #fff 100%); } body { display:none"
assert VALIDATORS["gradient"].match(bad) is None
print("gradient pattern: refuses")
EOF

# no page links a bare (uncacheable) site asset, and every stamp is current
python3 deploy/stamp_site_assets.py --check
grep -rl 'src="[^"]*site\.js"' site/ || echo "no bare asset references"
```


**Theming (§8b).** The registry must still match the stylesheet, and a hostile
value must be refused on the way in *and* on the way out:

```bash
cd /opt/satom
python3 deploy/gen_theme_tokens.py --check          # exits 1 on drift
set -a && . ./.env && set +a
venv/bin/python3 -c "
from app import create_app
from app.services import theme_service as t
with create_app().app_context():
    print('rejected on save :', bool(t.validate_tokens({'accent': '#fff; } html{}'})[1]))
    print('rejected on emit :', t.css_for({'accent': '#fff; } html{}'}) == '')
    print('unreadable caught:', t.has_unreadable({'text-primary': '#EDEDED'}))
    print('active theme     :', t.active_theme()['name'])
"
```

### The operator console

```bash
# 1. Everything, one exit code. 0 = clean, 1 = a real finding.
satom diagnose all

# 2. Is this node ARMED, not just installed? (fresh installs seed no actions)
satom diagnose install

# 3. A read must leave the tree byte-identical. Run the two that used to write,
#    as root, and prove nothing changed hands:
sudo satom get git status >/dev/null
sudo satom diagnose python >/dev/null
find /opt/satom -user root -not -name .env -not -path '*/venv*' \
     -not -path '*/.git*' -not -path '*/dist*' \
     -not -path '*/data/lib-versions*' | wc -l      # expect 0
stat -c %U /opt/satom/.git/index                     # expect the service account

# 4. Diagnostics must work WITHOUT privilege, and state must refuse WITH an
#    explanation rather than a traceback:
runuser -u nobody -- satom get scheduler status; echo $?   # expect 4 (degraded)
runuser -u <service-account> -- satom execute restart web; echo $?  # expect 3
```


**3 — the operator CLI cannot be turned into a privilege escalation.** The sudo
target must be a real, root-owned path outside the app tree, and the service
account must not have been granted it:

```bash
satom diagnose privilege          # expect [ ok ]; it checks all of the below
stat -c '%U %a %n' /usr/local/sbin/satom /usr/local/lib/satom-cli   # root 755
test -L /usr/local/sbin/satom && echo 'FAIL: symlinked sudo target'
grep -c '/usr/local/sbin/satom' /etc/sudoers.d/satom                # expect 0
```

And the CLI must still run when the venv does not — that is its whole purpose:

```bash
# no venv, no PYTHONPATH, from / : must print the command tree
cd / && env -u PYTHONPATH /usr/bin/python3 /usr/local/sbin/satom '?' >/dev/null \
  && echo 'ok: CLI runs on stdlib alone'
```

**9i — every probe interval is a multiple of the sweep tick.** A non-multiple
row runs slower than it claims:

```sql
-- tick = the sweep action's interval, in minutes (scheduled_action id for
-- action='deep_monitor'); every probe must divide evenly into it.
SELECT id, kind, name, interval_min
  FROM monitor_probe
 WHERE enabled AND interval_min % 3 <> 0;   -- expect: 0 rows
```

**9j — collapse state survives a refresh.** Collapse a device card on
`/monitoring/services`, wait past one auto-refresh (20 s), and confirm it is
still folded; reload the page and confirm it is still folded. Then check the
markup carries no inline handler:

```bash
grep -c 'localStorage.setItem(OPEN_KEY' app/templates/monitoring/_probe_page.html  # 1
grep -c 'onclick="' app/templates/monitoring/_probe_page.html                      # 0
```

Open the page in a fresh profile (or clear the key) and confirm **every** card
is folded, and that a hundred of them would tile rather than stack:

```bash
grep -c 'var collapsed = !OPEN.has' app/templates/monitoring/_probe_page.html   # 1
grep -c 'probecards.collapsed'      app/templates/monitoring/_probe_page.html   # 0
```

**9m — no dark palette leaks into a light page.** Nothing below may match:

```bash
grep -nE 'rgba\(30,41,59|rgba\(15,23,42|backdrop-filter|#cbd5e1|#93c5fd|#6ee7b7' \
  app/templates/monitoring/_probe_page.html
```

**9k — the ledger is isolated and ghosts get reaped.** Running the suite must
not add a single file to the live ledger:

```bash
B=$(ls -1 data/jobs/*.json | wc -l)
venv/bin/python3 -m pytest -q >/dev/null 2>&1
[ "$B" = "$(ls -1 data/jobs/*.json | wc -l)" ] && echo "ledger clean"

# no active job may sit without a pid for more than ~10 minutes
python3 - <<'EOF'
import json, glob, time, datetime
A = {'pending', 'running', 'cancelling', 'pausing', 'paused'}
for f in glob.glob('data/jobs/*.json'):
    d = json.load(open(f))
    if d.get('status') in A and not d.get('pid'):
        age = time.time() - datetime.datetime.fromisoformat(d['updated']).timestamp()
        print('GHOST', f, int(age // 60), 'min')   # expect: no output
EOF
```

### The REST monitor probes (§9d, §9e)

    # the sweep reports "ran", not "healthy" — a crit finding must not fail the run
    python3 - <<'PY'
    from app.services import scheduled_actions as sa, deep_monitor as dm
    dm.sweep = lambda **k: {"ran":1,"counts":{"crit":1},"worst":"crit","results":[]}
    assert sa._do_deep_monitor({}, False)["ok"] is True
    PY

    # the two pages partition every kind — none owned twice, none orphaned
    python3 -c "from app.views.deep_monitor import KINDS as D; \
      from app.views.service_monitor import KINDS as A; \
      from app.services.deep_monitor import KINDS as ALL; \
      assert not set(D)&set(A) and set(D)|set(A)==set(ALL); print('partition ok')"

    # a probe of the other page does not exist here (404, not 403)
    curl -sk -o /dev/null -w '%{http_code}\n' \
      https://<node>/monitoring/services/probe/<a-deep-probe-id>/history

    # a non-FortiWeb device is refused by name, never measured as zero
    python3 -c "from app.services import deep_monitor as dm; \
      print(dm._api_client(type('P',(),{'kind':'fortiadc','appliance':None})()))"

    # telemetry answers on a licence-locked box while its cmdb does not
    curl -sk -H "Authorization: $TOKEN" https://<fw>/api/v2.0/cmdb/system/interface   # 423 -20010
    curl -sk -H "Authorization: $TOKEN" https://<fw>/api/v2.0/policy/policystatus     # 200

### Consolidated views never invent a number (§9h)

    # a device with no throughput probe reports unknown, NOT 0 Mbps
    curl -sk -b <session> https://<node>/monitoring/services/data | python3 -c \
      'import json,sys; [print(d["name"], d["total_throughput"]["measured"], \
        d["total_throughput"]["avg_mbps"]) for d in json.load(sys.stdin)["device_rollup"]]'
    #   -> measured False must always come with avg_mbps None

    # the rollup belongs to ONE page
    curl -sk -b <session> https://<node>/monitoring/deep/data | grep -c device_rollup   # 0
    curl -sk -b <session> "https://<node>/monitoring/deep/policy/1?name=x"              # 404

    # an unmonitored policy is a 404, not an empty shell
    curl -sk -b <session> "https://<node>/monitoring/services/policy/<id>?name=ghost"   # 404

### Background jobs stay out of the dock (§9g)

    # the toast feed must not contain a background job; the Jobs page must
    curl -sk -b <session> https://<node>/jobs/?active=1 | python3 -c \
      'import json,sys; print([j["background"] for j in json.load(sys.stdin)["jobs"]])'   # all False
    curl -sk -b <session> https://<node>/jobs/all | python3 -c \
      'import json,sys; print(sum(1 for j in json.load(sys.stdin)["jobs"] if j.get("background")))'

    # a new job type is foreground unless it opts out
    python3 -c "from app.services import jobs; print(jobs.create_job('t','x')['background'])"   # False


```bash
# 1. HA guards answer correctly at the service account's privilege level
sudo -u <service-account> /usr/local/sbin/satom-node-role.sh   # f = primary, t = standby

# 2. The unit really runs as the service account (drop-in, not the shipped unit)
systemctl show satom.service -p User
systemctl cat satom.service | grep -A2 drop-in

# 3. The privileged runner is armed on BOTH nodes
systemctl is-enabled satom-updater.path && systemctl is-active satom-updater.path

# 4. Safety refs and bundles exist
git -C /opt/satom for-each-ref refs/backup/
ls -l /opt/satom/data/git-bundles/
git bundle verify /opt/satom/data/git-bundles/<latest>.bundle

# 5. Alerts are on and thresholds set — Settings → Alerts, or:
#    signals fire only if alerts.enabled is true and a recipient exists

# 6. The health badge is wired to reachability, not just capacity
curl -sk https://<node>/monitoring/data | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print([(x["name"],x["worst"]) for x in d["devices"]])'

# 7. A product ADOM cannot see the manager's own infrastructure
curl -sk -H 'X-ADOM: fortiweb' https://<node>/monitoring/infra -o /dev/null -w '%{http_code}\n'   # 403

# 8. The security headers are actually being sent
curl -sI https://<node>/ | grep -iE 'content-security-policy|x-frame|x-content-type'
```

### The operator console's output contract

```bash
# 1. Through a pipe there must be ZERO escape sequences.
satom show tree | grep -c $'\x1b\['            # expect 0
satom diagnose all | grep -c $'\x1b\['         # expect 0

# 2. And nothing may be truncated (no width to fit to).
satom show tree execute reinstall | grep -c 'roll back to\.'   # expect 1

# 3. An ASCII stdout must not kill the command (serial console).
PYTHONIOENCODING=ascii satom show tree >/dev/null; echo $?   # expect 0
LC_ALL=C satom diagnose all >/dev/null; echo $?              # 0 or 1, never 2+

# 4. NO_COLOR is honoured; --json is never decorated.
NO_COLOR=1 satom get system status | grep -c $'\x1b\['      # expect 0
satom show tree --json --color | python3 -m json.tool >/dev/null && echo ok

# 5. The tree cannot omit a command the build actually has.
diff <(satom show tree --commands | sed -n 's/^ *satom \([a-z-]* [a-z-]*\).*/\1/p' | sort) \
     <(satom show tree --commands | sed -n 's/^ *satom \([a-z-]* [a-z-]*\).*/\1/p' | sort)
# the authoritative version of this check is
# tests/test_cli_render.py::test_tree_lists_every_runnable_command_in_the_registry
```

### Documentation publication (§7b)

```bash
# 1. Is the published manual current? (0 = yes)
python3 deploy/gen_cli_reference.py --check
venv/bin/python3 deploy/gen_site_docs.py --check

# 2. Would anything internal be published? Independent of the generator's own
#    scanner - grep the tree directly. Expect zero.
#
#    SATOM_PRIVATE_RE holds YOUR site's private shapes: the management domain,
#    the hypervisor and node prefixes, the backup host. It is a variable rather
#    than an inline list on purpose - this page is itself published, and a
#    recipe that spells out the identifiers is both a disclosure and something
#    the redactor will rewrite, leaving a broken command in the manual. (That
#    is not hypothetical: it happened to this very block.)
export SATOM_PRIVATE_RE='\.corp\.example\.net|hv[0-9]+|node-prefix-'
grep -rnE "\b(10\.[0-9]{1,3}|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}\b|$SATOM_PRIVATE_RE" site/ | wc -l

# 3. Do the guards still bite? Break one on purpose and expect a failure.
printf '\nSee `satom show doc`.\n' >> docs/cli.md
venv/bin/python3 -m pytest tests/test_docs_publication.py -q ; echo "rc=$?"   # expect rc=1
git checkout -- docs/cli.md
```

The third step matters more than it looks: the assertion behind step 1 was once
a plain substring check, and the **comment explaining the rule contained the
substring**, so the test passed with the rule removed. Capture pytest's exit
code *before* any pipe - a pipeline ending in `tail` always exits 0.


### The public site's themes (section 8c)

```bash
cd /opt/satom
# every theme complete, AA on every pair, both surfaces switchable
venv/bin/python3 -m pytest tests/test_site_theme.py -q

# the served page really bootstraps before paint (not just the repo copy)
curl -sk -H "Host: <site-host>" https://127.0.0.1/index.html \
  | sed -n '1,/<\/head>/p' | grep -c 'satom.site.theme'      # expect 1

# the generated pages did not drift from the curated ones
venv/bin/python3 deploy/gen_site_docs.py --check
```

### The product icon is on every surface (8d)

```bash
# the bare-root path the browser asks for on its own -- must not be 404
curl -sk -o /dev/null -w '%{http_code}\n' https://<node>/favicon.ico

# no live template serves the vendor mark
cd /opt/satom && grep -rln 'img/favicon.svg' app/templates/ \
  | grep -v '\.bak\|\.pre-' || echo 'clean'

# the .ico carries several resolutions and stays transparent
venv/bin/python3 -c "from PIL import Image; i=Image.open('site/favicon.ico'); \
  print(sorted(i.info['sizes']))"
```

### One published manual, none in the app (§7c)

```bash
cd /opt/satom
venv/bin/python3 -m pytest tests/test_public_docs.py -q; echo "rc=$?"

# the application must not serve a manual at all -- 404, never 302
for p in /docs/ /docs/public /docs/api; do
  printf "%-14s " "$p"; curl -sk -o /dev/null -w "%{http_code}\n" "https://<node>$p"
done

# the console must be able to print every document that ships
satom show docs | tail -n +3 | wc -l
ls docs/*.md | wc -l

# and the published pages must be clean
for s in api install cli safeguards changelog readme; do
  curl -s "https://<site>/docs/$s.html" | grep -oE "$SATOM_PRIVATE_RE" && echo "LEAK: $s"
done
```

Set `SATOM_PRIVATE_RE` to the identifier shapes your fleet uses (addresses,
management domain, hypervisor and node prefixes). It is deliberately not
written out here: this file is itself published, and a grep pattern listing
every private form would be both the disclosure and its own victim — an earlier
revision had exactly that, and the redactor rewrote the command inside the
manual.

### The published mirror (7e)

The publisher runs on the internal catalogue host; these checks are run against
a clone of the PUBLIC repository, which is the artefact the guard is about.

```bash
git clone --bare https://github.com/visionebc/SATOM.git /tmp/pub.git
cd /tmp/pub.git

# 1. No identity may survive. Expect exactly one line.
git log --format='%an <%ae>' --all | sort -u

# 2. No internal identifier in any blob of any branch. Expect no output.
#    $SATOM_PRIVATE_RE is supplied by the reader -- the forms are deliberately
#    not written down in a published document (same reason as 7b).
git rev-list --objects --all | awk '{print $1}' | \
  git cat-file --batch-check='%(objectname) %(objecttype)' | awk '$2=="blob"{print $1}' | \
  while read -r sha; do git cat-file blob "$sha" 2>/dev/null | grep -lE "$SATOM_PRIVATE_RE" \
    && echo "LEAK in $sha"; done

# 3. The excluded paths are absent from the WHOLE history, not just the tip.
git log --all --name-only --format= | sort -u | \
  grep -E 'CLAUDE\.md|\.env|^reports/|seed_fw6|internal_identifier_samples'
```

A finding in check 2 means a rule is missing from `INTERNAL_REDACTIONS` in the
publisher. It should never be reachable: the same patterns abort the push, so
anything visible here means the scan was bypassed or a pattern disagrees with
its own redaction rule.

### The metrics store really ships (16)

```bash
# 1. the pin is one value across installer and all three builders
grep -h VM_SHA256 installers/install-satom.sh installers/build-offline-bundle*.sh \
  | grep -oE '[0-9a-f]{64}' | sort -u | wc -l          # expect: 1

# 2. no non-Apache artefact is referenced anywhere
grep -n 'victoria-metrics-linux-amd64' installers/*.sh \
  | grep -E 'enterprise|cluster'                        # expect: no output

# 3. a built bundle actually contains the binary, and it is the pinned one
tar tzf dist/satom-offline-*.tar.gz | grep victoria-metrics
tar xzOf dist/satom-offline-*.tar.gz --wildcards '*/bundle/victoria-metrics/victoria-metrics' \
  | sha256sum                                           # expect: the pin above

# 4. on a node: the store is up, on loopback, and nothing else can reach it
systemctl is-active satom-metrics                       # expect: active
ss -lntp | grep 8428                                    # expect: 127.0.0.1 only
satom diagnose all | grep -i metric
```

Step 3 is the one that matters. Steps 1 and 2 read the build scripts; only
step 3 reads the artefact the customer downloads, and every entry in the table
in 16 was a case where the scripts were fine and the artefact was not.


### A page is about its own ADOM (21)

Every ADOM must resolve to a page written for it, and no ADOM may be offered a
built-in board it cannot fill:

```bash
satom_check_adom_pages() {
  cd /opt/satom && set -a && . ./.env && set +a
  runuser -u "$(stat -c %U /opt/satom)" -- venv/bin/python3 - <<'PY'
from app import create_app
from app.views import analysis
from app.services.product_scope import concrete_products, GLOBAL
missing = [p for p in concrete_products() if p not in analysis.ANALYSIS_PAGES]
print("unmapped ADOMs:", missing or "none")
print("global ->", analysis.ANALYSIS_PAGES.get(GLOBAL))
PY
}
```

Then the report scoping — a product report must never ask an unscoped query:

```bash
# expect kind="<product>" on EVERY expression, and no satom_policy_up
# anywhere outside FortiWeb
grep -n 'def _sel' -A6 app/services/monitor_reports.py
```

And the board audience, which is the test that generalises to the next product:

```bash
runuser -u "$(stat -c %U /opt/satom)" -- venv/bin/python3 -m pytest \
  tests/test_fac_analysis.py::test_no_builtin_board_offers_a_panel_the_adom_cannot_produce -q
```

A failure names the board, the panel and the ADOM that cannot fill it.

### Config that only one node has (27)

The overlay must resolve inside `data/`, which is the only directory the
datasync carries:

```bash
cd "$APP" && venv/bin/python -c \
  "import app.services.doc_publication as p; print(p.OVERLAY_PATH.parent.name)"
# -> data
```

The loader must refuse rather than degrade. Point it at a scratch tree that
looks like a deployment and has no overlay:

```bash
t=$(mktemp -d); mkdir -p "$t/data"; : > "$t/.env"
cd "$APP" && venv/bin/python -c "
import sys, app.services.doc_publication as p
try:
    p._load_overlay('$t'); print('FAIL: degraded silently')
except p.OverlayError as e:
    print('ok, refused:', str(e)[:60])
"
rm -rf "$t"
```

Same tree without the `.env` marker must load the generic rules instead — that
is the published mirror, and it is allowed to have no overlay.

Confirm no datasync exclude shadows the file, and that it stayed ignored:

```bash
grep -o "\-\-exclude '[^']*'" /usr/local/sbin/satom-ha-datasync.sh
git --no-optional-locks check-ignore -v --no-index \
  data/publication-rules.local.json     # must report a rule
```

`--no-index` is required: git refuses to report a **tracked** path as ignored,
so the assertion passes vacuously without it.

### The two secrets no backup carries (28)

```bash
# Does anybody hold them? (exit 2 while either has never been exported)
satom diagnose recovery

# The fingerprint must identify the key without disclosing it.
cd /opt/satom && set -a && . ./.env && set +a
runuser -u satom -- venv/bin/python - <<'PY'
import os
from app import create_app
from app.services import recovery
with create_app().app_context():
    lines = "\n".join(recovery.manifest_lines())
    key = os.environ["FERNET_KEY"]
    assert key not in lines, "THE MANIFEST IS LEAKING THE KEY"
    assert recovery.compare_manifest(lines) == []            # matching key: silent
    assert recovery.compare_manifest("label: x") == []       # old bundle: still restorable
    print("fingerprints ok:", lines.replace(chr(10), " | "))
PY

# An unprivileged caller must say "cannot evaluate", never "no key".
setpriv --reuid=65534 --regid=65534 --clear-groups satom diagnose recovery; echo "exit=$?"   # 4
```

The last one is the guard that matters most: `.env` is `640 root:<service
account>`, so a caller who cannot read it has learned nothing. If that command
ever reports a *finding* instead of refusing to conclude, the check has started
fabricating verdicts about a key it never saw.

### Fail-open sweep (29, 30, 31)

```bash
cd /opt/satom && set -a && . ./.env && set +a

# A repo git cannot read must NOT report itself clean and in sync.
runuser -u satom -- venv/bin/python - <<'PY'
from pathlib import Path
from app import create_app
from app.services import git_service as gs, alerts
with create_app().app_context():
    assert gs.git_info()["unknown"] is False           # healthy: quiet
    gs._repo_root = lambda: Path("/tmp")               # not a repo
    assert gs.git_info()["unknown"] is True
    assert "git.unreadable" in [f["key"] for f in alerts._check_git()]
    print("git fail-open closed")
PY

# Every SSH channel pins. Fails on the FOURTH one somebody adds.
runuser -u satom -- venv/bin/python - <<'PY'
import ast, pathlib
bad = []
for f in pathlib.Path("app").rglob("*.py"):
    t = f.read_text()
    if "set_missing_host_key_policy" not in t:
        continue
    calls = {n.func.attr if isinstance(n.func, ast.Attribute) else
             getattr(n.func, "id", "") for n in ast.walk(ast.parse(t))
             if isinstance(n, ast.Call)}
    if not calls & {"load_pins", "_load_pins"}:
        bad.append(str(f))
assert not bad, bad
print("all SSH channels pinned")
PY

# Every unit template deploy/ ships is distributed by the update runner.
runuser -u satom -- venv/bin/python -m pytest tests/test_unit_distribution.py -q >/dev/null
echo "unit distribution exit=$?"
```

The SSH sweep is per-file on purpose. Asserting it for the three channels we
know about would pass forever; asserting it for everything that hands paramiko
a policy is what fails on the next one.

### A sealed envelope is actually reachable (32b)

```bash
# 1. The envelope must belong to whoever owns the tree, not to root.
stat -c '%U:%G %a' /opt/satom /opt/satom/data/recovery /opt/satom/data/recovery/seal.json

# 2. The load-bearing check: the account that copies it must be able to
#    read it. Root succeeding here proves nothing.
runuser -u "$(stat -c %U /opt/satom)" -- head -c 1 \
  /opt/satom/data/recovery/seal.json >/dev/null && echo reachable

# 3. The node must agree, and must SAY why it is quiet.
satom diagnose recovery      # expect [ ok ] plus a 'sealed envelope' row

# 4. The peer must have it, byte for byte, without anyone copying it by hand.
md5sum /opt/satom/data/recovery/seal.json
```

## Related

* [`privilege-model.md`](privilege-model.md) — accounts, sudo, the runner boundary, HA trust
* [`git-backup-and-outage.md`](git-backup-and-outage.md) — the Gitea-outage scenario end to end
* [`encryption-and-node-tls.md`](encryption-and-node-tls.md) — TLS, node identity, Postgres SSL
* [`source-of-truth-spec.md`](source-of-truth-spec.md) — the write path and the local persistence layer
* [`metrics-architecture.md`](metrics-architecture.md) — where operational data lives, and the fleet-scale measurement behind it
* [`INSTALL.md`](INSTALL.md) — what to request from systems, and the hardening checklist

### Thresholds are declared, inherited and explained (23)

```bash
# 1. Nothing is stamped at creation any more: a fresh probe inherits.
#    (Non-zero counts here are overrides somebody actually chose.)
psql -h 127.0.0.1 -U satom -d satom -tAc "
  select kind, count(*), count(warn_pct), count(crit_pct),
         count(warn_num), count(crit_num)
  from monitor_probe group by kind order by kind"

# 2. NULL inherits, 0 disables, and the origin is always reported.
satom show paths >/dev/null   # (app dir)
cd /opt/satom && set -a && . ./.env && set +a && runuser -u satom -- \
  venv/bin/python3 -c "
from app import create_app
from app.models import MonitorProbe
from app.services import thresholds as th
with create_app().app_context():
    p = MonitorProbe.query.filter_by(kind='cpu').first()
    for o in th.probe_origins(p):
        print(o['key'], o['value'], o['explain'])"

# 3. A silenced fact is still PRINTED. Expect 'ALL backends down' in BOTH,
#    and only the grade to change.
runuser -u satom -- venv/bin/python3 -c "
from app.services import deep_monitor as dm
row={'sessions':1,'conn_per_sec':2,'status':'enable','app_response_time':0}
mem=[{'server':'192.0.2.20','port':80,'up':False,'health':'up'}]
k=dict(warn_num=0,crit_num=0,warn_ms=0,fingerprint='a',prev_fingerprint='a')
print(dm.classify_policy_sessions(row,mem,**k))
print(dm.classify_policy_sessions(row,mem,sev={'backends_all_down':None},**k))"

# 4. The machine can now say something bad. Expect a non-ok status when the
#    threshold is dropped below the live reading, and 'unknown' -- never 'ok' --
#    for a node with no reading.
runuser -u satom -- venv/bin/python3 -c "
from app.services import host_health as hh
print(hh.local()['status'], [ (k,v['status']) for k,v in hh.local()['signals'].items() ])
print(hh.grade_stats(None)['status'])"
```


### The monitoring panels report bad news (17)

```bash
# 1. the store is watched, and units inactive BY DESIGN are not
python3 -c "from app.services.system_health import MONITORED_UNITS as U; \
  print('store watched:', 'satom-metrics.service' in U); \
  print('no role-guarded:', not any('datasync' in u or 'git-publish' in u for u in U))"

# 2. HA posture comes from the harvest, not the hand-entry table, and it rides
#    the DEVICE feed (expect one row per live appliance, each with its evidence)
curl -sk -b "$COOKIE" https://$NODE/monitoring/data | python3 -c \
  "import json,sys; h=json.load(sys.stdin)['ha']; print(h['counts']); \
   [print(' ', d['name'], d['status'], d['source'], d['evidence']) for d in h['posture']]"

# 2b. the installation page states ITS OWN posture, and carries no device rows
curl -sk -b "$COOKIE" https://$NODE/monitoring/satom-data | python3 -c \
  "import json,sys; r=json.load(sys.stdin)['redundancy']; \
   print(r['manager_posture']['status'], r['manager_posture']['evidence']); \
   assert not [k for k in r if k.startswith('device')], 'device data on the manager feed'"

# 3. the split is enforced on the ROUTE, not the template
curl -sk -o /dev/null -w '%{http_code}\n' -H 'X-ADOM: fortiweb' https://$NODE/monitoring/satom-data
curl -sk -o /dev/null -w '%{http_code}\n' -H 'X-ADOM: fortiweb' https://$NODE/monitoring/satom

# 4. every Administrator group offers Collection -- 4 means all of them
grep -c 'partials/nav_collection.html' app/templates/base.html
```
