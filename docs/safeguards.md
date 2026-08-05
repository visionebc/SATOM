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

# 2. an automatic run does not touch a parked appliance
runuser -u satom -- venv/bin/python3 -m pytest \
  tests/test_alerts_scheduled_actions.py tests/test_action_maintenance.py -q
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

## 11. Known gaps (kept honest, on purpose)

* Per-device configuration restore is dry-run gated — no live canary round-trip yet.
* The public wildcard certificate is not auto-renewable from the node; it is
  re-copied when the edge renews it. Internal-CA certificates *do* auto-renew.
* The firmware manifest in the SoT repository is maintained by hand.
* Gitea and the standby share a host (hypervisor03). The bundle to backup-server exists
  because of that, but it mitigates rather than fixes it.

## Verifying the guards are armed

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

## Related

* [`privilege-model.md`](privilege-model.md) — accounts, sudo, the runner boundary, HA trust
* [`git-backup-and-outage.md`](git-backup-and-outage.md) — the Gitea-outage scenario end to end
* [`encryption-and-node-tls.md`](encryption-and-node-tls.md) — TLS, node identity, Postgres SSL
* [`source-of-truth-spec.md`](source-of-truth-spec.md) — the write path and the local persistence layer
* [`metrics-architecture.md`](metrics-architecture.md) — where operational data lives, and the fleet-scale measurement behind it
* [`INSTALL.md`](INSTALL.md) — what to request from systems, and the hardening checklist
