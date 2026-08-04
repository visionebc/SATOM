# Changelog

All notable changes to SATOM are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/). This is a public,
source-available project — see [NOTICE](NOTICE) for the trademark disclaimer.

## [Unreleased]

### Changed

- **License changed from Apache-2.0 to the [Elastic License 2.0](LICENSE).**
  The change applies to the SATOM project as a whole, including the versions
  previously published in the public repository (v1.0 through v1.3.5). What it
  means in practice: you may still use, modify and run SATOM inside your own
  organisation — in production, for commercial purposes, on as many nodes as
  you like — at no cost. What is no longer permitted is providing SATOM to
  third parties as a hosted or managed service; that requires a commercial
  license (`licensing@visionebc.com`). ELv2 also forbids circumventing license
  key functionality and removing licensing notices. Note that copies obtained
  before this change carry the Apache-2.0 terms under which they were received;
  the new terms govern this repository and everything distributed from it going
  forward. SATOM is therefore **source-available**, not OSI open source — the
  wording in `README.md`, `NOTICE`, `CONTRIBUTING.md`, `DISCLAIMER`,
  `SECURITY.md` and the public site was corrected accordingly. Guarded by
  `tests/test_license_consistency.py` so no surface can drift back; see
  `docs/safeguards.md` 7f. [SATOM-LICENSE]

- **The published tags were restamped to match.** Changing `main` was not
  enough: a tag is itself a public offer of terms, so every release tag
  published before the change kept handing out the Apache-2.0 grant on the exact
  refs a reader is most likely to pin — and re-pointing a tag at the sanitised
  history moves the ref, not the bytes. The publisher now rewrites `LICENSE` and
  the five declaring files across the whole published history and refuses to
  push while any reachable commit still carries the Apache body. `CHANGELOG.md`,
  `docs/` and `tests/` are deliberately left untouched: they record the change
  rather than declare the current terms. This changes what the repository shows,
  not what anyone already holds — a copy fetched earlier stays under the terms
  it was received under, as `LICENSE` states. See `docs/safeguards.md` 7f.
  [SATOM-LICENSE-TAGS]

### Fixed

- **A prompt could kill the installer without printing anything.** `read`
  returns non-zero on EOF and, under `set -euo pipefail`, that aborted the run
  silently -- the last visible line was the previous step. It bites when the
  installer is driven by a pipe or here-doc whose answer sequence is shorter
  than the prompt sequence; the ONLINE path asks one question more than the
  OFFLINE one (the repository URL), so a driver written against one path dies
  mid-install on the other. All twelve prompts now go through `ask` /
  `ask_secret`, which abort with a message naming the unanswered prompt.
  EOF *with* partial data (a last line without a newline) remains a valid
  answer. Guarded structurally, so a prompt added later cannot bypass them.
  See `docs/safeguards.md` 10f. [SATOM-LOUD-READ]

## [1.3.5] - 2026-08-04

### The node was never told which names it answers to

Two defects, one root cause -- the installer guessed the served names from
`hostname` (the short name) and minted two artefacts from that guess.

- **`proxy_set_header Host $host` dropped the port.** Flask-WTF compares the
  browser's `Referer` -- port included -- against the origin the app believes it
  is on, so behind a NAT or a proxy on a non-standard port **every POST,
  including the login, failed CSRF** and reported an expired session. Invisible
  on `:443`, where browsers omit the default port. Now `$http_host`, in the
  installer and in `deploy/nginx-vhost.conf`.
- **`server_name` and the node certificate's SAN were both the short hostname.**
  A node reached by FQDN answered only because the vhost also claimed
  `default_server`, and its freshly issued certificate had no SAN for the name
  the browser used. The installer now asks for the served DNS names in step 1
  (default `hostname -f`, override `SATOM_SERVED_NAMES`) and feeds them to both.
- `satom diagnose nginx` gains two verifications: any proxying vhost passing
  `$host` is a failure, and the served certificate must cover every FQDN in
  `server_name` (RFC 6125 wildcard matching -- one label, no bare apex).
- New `satom execute repair nginx [--yes]` brings an already-installed node to
  the corrected shape, with backups, `nginx -t` and automatic rollback. The
  vhost is not in git, so a code update alone could never carry the fix.
- The HTTPS redirect no longer pins an explicit `:443`.

The vhost is not in git, so an update alone cannot carry this fix to an
installed node: run `satom execute repair nginx --yes`, or reinstall from
this release. Releases 1.3 through 1.3.4 all emit the defective vhost.

## [1.3.4] - 2026-08-04

### The offline bundles never carried git

Found the only way it could be found -- by looking at a node installed from a
bundle, with no network, days after it was built. `satom-git-publish.service`
had been failing every hour with `git: command not found`.

- **`git` is now a required package on every family**, and therefore in all
  three offline bundles. It was in none of them. The online path installs it as
  a side effect of cloning the repository, so every online install had it and
  every air-gapped install did not. Nothing else showed the fault: the console,
  `/healthz`, login and the rest of the diagnostics were green while backup
  **copy 3** -- the `reports/` source of truth versioned in git -- did not exist
  on the node at all.
- **`satom diagnose git` names the missing binary.** It reported
  "repository unusable", which is true and points the operator at the
  repository rather than at the one package that is absent.
- Rules and guards in [safeguards](docs/safeguards.md) section 10d. Three
  mutation-tested guards: `git` must be required on all four families, every
  builder must package it, and the diagnosis must detect its absence.

Rebuild-only for existing installations: `git` is a package, not application
code. An installed node is fixed by installing git from the distribution media
or from the bundle; nothing needs to be redeployed.


## [1.3.3] - 2026-08-04

### nginx came up, then the installer killed it (openSUSE)

Found the way the last three installer defects were found: by installing on a
blank machine. Two identical openSUSE Leap 15.6 nodes, same release, same
answers -- the online one exited **1**, the offline one exited **0**. A 38 ms
race, so v1.3.2 passing its own validation proved nothing. Rules in
[safeguards](docs/safeguards.md) section 11.

- **The installer reloaded nginx it had just started.**
  `systemctl enable --now nginx; systemctl reload nginx` on one line. openSUSE
  ships `nginx.service` as `Type=simple` (`daemon off;`) with
  `ExecReload=/bin/kill -s HUP $MAINPID`, so systemd reports the unit started
  before nginx has written `/run/nginx.pid`; the reload resolved `$MAINPID` to
  nothing, `kill` exited 2 and systemd tore down the whole service. Debian and
  RHEL use forking units with `PIDFile=` and never see it. The reload is gone;
  the start is now guarded with `|| die` and followed by a bounded poll on
  `is-active` + a non-empty pid file + an accepted TCP connection.
- **The failure hid the one instruction that mattered.** Being the last command
  on the line, its non-zero status killed the script under `set -e` before step
  7 -- so a correctly installed system reported failure and never printed the
  banner telling the operator to run `satom execute seed actions`.
- **`satom diagnose nginx` warned forever on every standalone install.** It
  probed the :8443 node-to-node channel unconditionally; a lone node has no
  peer. The row is still printed as `n/a - no peer configured (standalone)`,
  and a node that does have a peer is graded exactly as before. Same chronic
  false positive already removed from `get system health` and from the CLI
  status colouring.
- **A success line printed `command not found`.** The installer runs with the
  PATH it inherits from container boot -- `/sbin:/bin:/usr/sbin:/usr/bin`, with
  no `/usr/local/bin`, which is where `lego` lands. `$(lego --version)` inside
  the text of the success message expanded to
  `install-satom.sh: line 1107: lego: command not found`, printed *inside* the
  green-tick line, on an install where the binary was in fact present and its
  sha256 verified. `command -v lego` failed for the same reason, so a reinstall
  would not detect the existing binary and would download it again. The block
  now resolves `$LEGO_BIN` as an absolute path. Cosmetic in effect, not in
  consequence: a success message containing `command not found` teaches the
  operator to ignore the messages, and then the one that matters is ignored too.
- **`Context.role` could never return `standalone`, though its docstring said
  it could.** It comes from `pg_is_in_recovery()`, so a standalone node reports
  `primary`. The first version of the fix above gated on that value and
  therefore did nothing -- caught by installing, not by testing, because the
  tests encoded the same wrong assumption. Probe selection now asks the
  question it means (is a peer configured in `data/ha_nodes.json`?), and the
  docstring no longer promises a value the property cannot produce.


## [1.3.2] - 2026-08-04

### The installer had never completed on openSUSE or RHEL (2026-08-03)

Found by running the published v1.3.1 installer on a blank openSUSE Leap 15.6
machine, as an operator would. Details and the rules they encode:
[safeguards](docs/safeguards.md) section 10b.

- **`pg_hba` was written and never reloaded on standalone installs.** The only
  `systemctl restart postgresql` sat inside the `primary` branch. PostgreSQL
  evaluates `pg_hba` from memory, so the server kept applying the distribution
  default. Debian's default for `host 127.0.0.1` is `scram-sha-256` and hides
  this; openSUSE and RHEL default to `ident`, which rejects the application
  account before it ever looks at the password. `flask create-db` died with
  `FATAL: Ident authentication failed for user "satom"`. The reload now runs
  for every mode, and the credential is verified immediately afterwards.
- **The installer exited 1 and printed nothing.** `flask create-db`, the block
  that sets the admin password, and `systemctl enable --now satom.service` had
  no `|| die`, so under `set -e` they aborted silently. The operator's last
  line was `pg_hba: regla local scram`; the cause was a traceback in a
  different file. All three now fail loudly and name the next place to look.
- **The operator CLI installed dead outside Debian.** The launcher's
  `#!/usr/bin/env python3` does not resolve on openSUSE Leap, which installs
  `python311` and creates no `python3` link. `install-cli.sh` now stamps the
  shebang with a verified system interpreter (never the venv, never anything
  inside the application tree) and refuses to install a CLI that cannot run.
- **A fresh node failed its own nginx check.** The generated TLS vhost did not
  claim `default_server` — the production configuration does, because someone
  added it after the console became unreachable by hostname once a second vhost
  appeared. The installer now emits it and backs it out only if nginx reports a
  genuine duplicate.
- **`satom diagnose nginx` was blind on openSUSE.** It scanned
  `sites-enabled` and `conf.d`, but the installer writes to `vhosts.d` on that
  family, so it read no files and reported `default_server holder NONE` for a
  correct configuration. It now scans every directory the installer may use.
- **Nothing told the operator to arm the protections.** No `ScheduledAction` is
  seeded, by design. The closing banner now says so and names
  `satom execute seed actions`, instead of leaving a node with no database
  bundle, no source-of-truth refresh and no repository bundle.


## [1.3.1] - 2026-08-03

Bundle rebuild release. The v1.3 offline bundles were built **before** the
fixes below landed, so they ship the previous `install-satom.sh` whose default
clone URL pointed at a private Git server — an unattended install hangs on an
impossible clone. 1.3.1 rebuilds all three bundles (Debian 12, RHEL 9,
openSUSE 15) from this tree and publishes them alongside the changes below.


### The mirror published the network map and the team's names (2026-08-03)

- **The public mirror carried the internal network map and 25 commit
  identities.** The publication pipeline filtered **paths** (`CLAUDE.md`,
  `.env`, `reports/`) and **commit messages**, and a path filter cannot see
  inside a file it keeps: 107 files shipped internal addresses, management
  hostnames, hypervisor and node names, while the history shipped 25 author
  identities — two named after an AI assistant, three carrying a personal
  e-mail. The publisher now collapses **every** identity, redacts internal
  identifiers in **every blob across the whole history**, and **re-scans its
  own output, aborting the push on a finding**. Redaction without verification
  is a hope, not a guard. See `docs/safeguards.md` §7e.
- Ordering trap recorded: the shorthand pair `192.0.2.248/.249` has to be
  rewritten *before* the generic address rule, or the generic rule takes the
  first address and leaves `/.249` — still an octet, and invisible to the scan
  because what remains is not a complete address.

- **Seven runtime defaults named one company's infrastructure.** These are
  functional bugs, not disclosures: redacting them at publication time would
  have produced a mirror that leaked nothing and still shipped somebody else's
  network as its factory settings.
  - `TRUSTED_PROXIES` defaulted to an internal proxy address. Everywhere else
    that meant every user collapsed into a single rate-limit bucket; on any
    site whose LAN overlaps that range it meant an unrelated host inherited the
    right to forge the client IP feeding rate limiting and audit keys. Loopback
    only now.
  - The DNS Lookup tool defaulted to two internal resolvers while its own
    docstring promised the list is "never hardcoded". Empty now.
  - Node certificates appended a hard-coded domain the installation does not
    own. Only the *suffix* is configurable, and it is resolved per node: a
    stored FQDN is wrong on an HA pair, because the standby replicates the
    primary's settings row and would issue a certificate naming the primary.
  - Two Firecrawl endpoints (unauthenticated) and the installer's clone URL
    pointed at internal hosts. The installer now defaults to the public
    repository, so an unattended install no longer hangs on a clone it can
    never complete.
  - The About panel linked to an internal Git server on every profile view.
  - `deploy/nginx-vhost.conf` was one deployment's real vhost, upstream address
    included. It is now a generic sample proxying loopback — which is what the
    installer actually configures.

- **Tests.** Fixtures that sat in a routable range for no reason moved to the
  RFC 5737 documentation range; inert test data has no business naming a real
  network, and those literals were what made a redacted mirror ship a red
  suite. The adversarial corpus — the one fixture that must contain real
  identifiers to prove the scanner bites — moved to `tests/fixtures/`, is
  dropped by the publisher, and its tests now skip **with a reason** instead of
  failing on a mirror that correctly has nothing left to detect.
- Two lab seeder scripts are excluded from the mirror rather than redacted:
  wired to one appliance by database id and to absolute local paths, with a
  shared secret in clear text. Rewriting their literals yields a script that
  still cannot run anywhere else.

### The device API was never documented, and the manual's own links were dead (2026-08-03)

- **New manual: `docs/device-api.md`** (published as *Device APIs & the endpoint
  registry*). `api_v1.md` documents the five endpoints a third party uses to
  drive **this platform**; nothing documented the other direction — the three
  API consoles the platform uses to drive an **appliance**, or the
  `registry_endpoints` catalog behind them (826 seeded entries: 507 FortiWeb
  REST `v2.0`, 255 FortiADC REST `v1`, 64 FortiAnalyzer JSON-RPC). Covers the
  three transports, the insert-only seed and soft-delete rules that make an
  operator's correction survive every deployment, the four permissions, ADOM
  scoping, and the recipe the whole design exists for: a firmware upgrade that
  moves a URI is a row edit from the browser, not a release.
- **71 cross-references in the published manual were dead links.** The manual
  links Markdown to Markdown, which is right in the repository and 404s
  everywhere it is published. `doc_publication.relink()` now rewrites them to
  the published slugs (preserving `#fragments`) and unwraps any link to an
  unpublished document into plain text. `docs/safeguards.md` 7d, guarded by
  `tests/test_public_docs.py`.
- `docs/engineering.md` 5 was stale: it omitted the FortiAnalyzer catalog
  entirely, gave approximate row counts, listed `resolve_adc` without
  `resolve_faz`, and still described `/web/registry` as the editor — that page
  was folded into the API console in 2026-07 and only redirects.


### The published manual rendered blank (2026-08-03)

- **Every documentation page loaded at `opacity: 0`.** The generator wraps the
  document body in the site's `.reveal` scroll animation, whose
  `IntersectionObserver` used `threshold: 0.12`. That ratio is measured against
  the *element*, not the viewport, so a page taller than ~8 viewports could
  never reach it: the safeguards manual (34 957 px) topped out at 2.3 % and
  stayed invisible no matter how far you scrolled. Short pages appeared, long
  ones did not — which read as "most of the documentation is empty".
- **Fixed structurally, not by tuning the number.** Content is now visible by
  default and the animation arms itself only behind `html.js`, set by the head
  bootstrap; `site.js` announces that it ran, and the bootstrap withdraws the
  flag after 2.5 s if it did not, so a missing or stale script cannot blank a
  page either. `threshold` is 0. `docs/safeguards.md` 8f, guarded by
  `tests/test_site_reveal.py`.
- `tests/test_faz_adom.py` still required `/docs/` to answer 200 after the route
  was removed, and `tests/test_site_theme.py` pinned an exact byte sequence of
  the generator source. Both replaced with structural checks.
- The published callout no longer advertises the removed in-app `/docs`; it
  points at `satom show docs`.

### Documentation is published once (2026-08-02)

- **The application no longer serves documentation.** `/docs`, `/docs/public`
  and `/docs/api` are removed; the sign-in page and the sidebar link to the
  public site instead. One rendered copy, one place to update. The routes now
  return **404**, not a redirect — a redirect would mean the second copy still
  existed behind a decorator.
- **`satom show docs [<name>] [<section>]`** — the manual, from the tree, with
  no network. A management network has no route to the public site, so removing
  the in-app manual without this would break the offline bundle's promise. The
  catalogue is derived by listing `docs/`, so a new document appears there with
  no second edit.
- **`docs/README.md` is now published** — the reading map was the one document
  that existed in the application and not on the site.
- The published address has a single definition (`doc_publication.SITE_BASE`
  plus a `docs_url()` context processor); a test fails on a hardcoded URL in any
  template.
- The staging documentation node was retired: the public site is the only
  published copy.

## [1.3] - 2026-08-02

### Added
- **The manual is reachable from the sign-in screen.** The login page offered a
  link to the API manual and nothing else. The person who cannot get in is
  exactly the person who needs the installation guide, the operator-console
  reference and the recovery runbooks — and on an isolated management network
  there is no other copy to reach. `/docs/public` now publishes the whole
  manual without a session, grouped in reading order, and the sign-in page
  links to it beside the API manual.
- **The API manual is a destination on the public site, not a buried card.**
  It was reachable only by opening the documentation hub and scrolling to the
  fourth group. `API` is now a top-level entry in the navigation and the footer
  of all 27 site pages.
- **An offline bundle for openSUSE / SLES 15.** The distribution was validated
  online — a whole HA pair was installed on it — while the only way to install
  it stayed *fetch everything from the internet*, which is precisely what an
  isolated management network cannot do. `installers/build-offline-bundle-suse.sh`
  produces one, and the installer accepts it from `bundle/rpms-suse/`.
  A directory of its own, not `rpms/`: both bundles are RPM and they are **not**
  interchangeable (`python311` vs `python3.11`, different base library versions,
  and zypper and dnf do not read repositories the same way). Separating them
  turns "wrong bundle" into an explicit refusal before anything is touched,
  instead of a dependency resolution that fails halfway through an install.
  On the target, zypper is handed a repository directory of its own
  (`--reposd-dir`) containing only the bundle — no network, no change to the
  system's repositories, and no repository left registered afterwards.

- **One publication registry, shared by both published surfaces.**
  `app/services/doc_publication.py` owns the list of publishable documents, the
  redaction table and the scanner; `deploy/gen_site_docs.py` imports them
  instead of declaring them. It loads the module by path rather than importing
  the `app` package, because the site build has to keep working on a tree whose
  application code does not compile — that has happened. A structural test
  fails the suite if the generator ever re-declares any of it.

### Fixed
- **`/docs/api` was public and served the document unredacted.** The route
  needed no session and rendered `docs/api_v1.md` verbatim, so a management
  hostname and an RFC1918 address were readable by anyone who could load the
  login page. The redact-then-scan pipeline that guards the public web site
  existed only inside the site generator, where the application could not reuse
  it. Every publicly served document now goes through it, and the scan is
  fail-closed: a page whose rendered output still carries an internal
  identifier is not served at all. Refusing to answer is recoverable; an
  inventory disclosure is not.
- **The four sign-in pages and the public documentation needed public internet
  to lay themselves out.** They pulled Bootstrap from a CDN while the same
  files sat vendored in `static/vendor/`. This product ships offline installers
  for isolated management networks — an unstyled sign-in page is the first
  thing an operator sees there.
- **The five hand-written site pages had drifted from the generated chrome.**
  `index.html` had lost its `Docs` footer link entirely. Their navigation and
  footer are now rebuilt from the same single definition the generated pages
  use, so an added destination lands on every page at once.
- **The public documentation shell still showed the pre-rename `FM` placeholder
  box** in place of a logo and hard-coded the old chrome colours, so it ignored
  the theme engine — the same defect the sign-in pages carried until 2026-08-02.
- **The in-app manual inserted a line break at every source wrap.** `docs/*.md`
  is hard-wrapped at about 90 columns and the renderer had `nl2br` enabled, so
  every wrap became a visible break. The published renderer never had it.

### Fixed
- **A cluster on openSUSE never replicated files at all, and five more defects
  found by installing a real HA pair.** The first round fixed what stopped a
  single node from coming up; installing a *second* node exposed the rest.

  - **The cluster path needed Python before Python was installed.** Pasting a
    join key ran a `python3` one-liner in step 1; the interpreter arrives in
    step 2. On Debian this works by accident because the base image ships a
    `python3` symlink. On openSUSE a secondary install died with exit 127 the
    moment the operator pasted the key. The key is now parsed with an `awk`
    extractor and no Python at all — used on every distribution rather than as
    a fallback, because a second path that only runs on one family is untested
    code. Since the parser is ours, the shape of both PEMs is now verified: a
    silently wrong parse would corrupt the internal CA and stay invisible until
    the first certificate issuance weeks later.
  - **Installing a package is not running a service.** In cluster mode the
    installer added `openssh` and stopped. Debian's package enables and starts
    `sshd` by policy; openSUSE leaves it disabled, nothing listens on 22, and
    the standby can never pull `data/`. It is now enabled on *both* cluster
    nodes — after a promote it is the old standby that has to serve the pull.
  - **A failed host-key scan was swallowed.** `ssh-keyscan` ended in `|| true`,
    so an empty result looked exactly like a good one. With
    `StrictHostKeyChecking=yes` — TOFU was removed on purpose — that breaks
    file replication permanently while the installer still reports success.
    The result is now checked, and warns with the remedy rather than dying:
    PostgreSQL streaming replication rides its own TLS channel and is fine.
  - **The standby's datasync unit failed and systemd reported success.** Peer
    discovery ran a bare `python3`; with no such binary `PEER` came back empty
    and the next line treated that as "no peer configured" and exited zero. The
    role probe twenty lines above already used the application's own venv
    interpreter *and* already failed loudly; peer discovery did neither. It now
    does both, and distinguishes "could not evaluate" from "nothing to sync".
    `tests/test_deploy_scripts.py` is the structural guard: no deploy script may
    call a distribution Python, none may call `runuser` without branching on
    `id -u`, and the peer probe must keep both exits.
  - **The installer left root-owned files in a tree owned by the service
    account** — `data/logs/`, `data/ha_nodes.json`, `data/acme/`, `data/jobs/`
    and the whole of `pki/`, including the internal CA key. The only recursive
    ownership pass runs before those are written. This is not cosmetic: the
    standby rsyncs `data/` as the service account and a root-owned directory
    fails with permission denied even when authentication is fine (this already
    happened in production with `data/acme`), the application has not run as
    root since the deprivilege so it cannot write `pki/`, and the self-update
    runner derives the `User=` drop-in from the owner of the tree. A final
    sweep now runs just before services start.

- **Seven installer defects found by installing on a distribution nobody had
  tried.** The `zypper` code path had been written but never executed against a
  real openSUSE machine. Three of the seven were not SUSE-specific at all and
  affected **every** fresh installation:

  1. **`.env` was left `600 root:root`.** Everything that runs as the service
     account and sources it — the alert engine, certificate renewal, the git
     publisher, the HA datasync and the shared node-role probe — was born dead
     on a new installation. The two existing nodes only worked because the mode
     had been corrected by hand months earlier. It is now `640 root:<account>`:
     root still owns the file, so a write primitive in the web worker cannot
     rewrite its own secrets, but the timers can read it.
  2. **`satom-git-publish` reported FAILURE on every new installation.** It ran
     `git add reports` before any device sync had created that directory, and
     the `|| exit 1` turned a not-yet-existing path into a unit failure — so
     *copy three* of the backup architecture (the source-of-truth tree versioned
     in git) looked broken from day one. It now exits cleanly when there is
     nothing to publish yet.
  3. **A re-run left the running process holding stale secrets.**
     `systemctl enable --now` is enable+start, and start on an already-running
     unit is a no-op. A second run regenerates `.env` with a new database
     password, `SECRET_KEY` and `FERNET_KEY`, but systemd reads
     `EnvironmentFile` only at start — so the old process kept the old
     credentials and every login failed with *password authentication failed*
     while `/healthz` happily returned 200, because it does not touch the
     database. The units are now restarted explicitly.

  And four that only fire outside Debian:

  4. **The service account could land in a shared group.** `useradd --system`
     relies on `USERGROUPS_ENAB`, which openSUSE disables — the account would
     join `users` (gid 100) alongside every interactive user instead of getting
     a private group. Now forced with `--user-group`.
  5. **Bare `python3` calls** in five places that already had `$PYBIN` resolved.
     openSUSE ships `python3.11` with no `python3` symlink.
  6. **PostgreSQL rejected the application before checking its password.** The
     installer trusted the distribution default for the local TCP connection;
     openSUSE defaults to `ident`, which fails hard. It now writes its own
     `scram-sha-256` rule **at the top** of `pg_hba.conf` — the file is
     first-match, so appending would have been inert. This also closes a gap in
     *standalone* mode on every distribution, where the PostgreSQL block was
     skipped entirely because it lived inside the primary-only branch.
  7. **The nginx vhost went to a directory that is included twice.** openSUSE's
     stock `nginx.conf` includes `conf.d/*.conf` on two separate lines and ships
     its own port-80 server that collides with the `default_server` SATOM needs.
     The vhost now goes to `vhosts.d/` and the stock block is neutralised, the
     same way `sites-enabled/default` is removed on Debian.

### Changed
- **The last `fortinet` identifiers are gone from the platform itself.** The
  database, the PostgreSQL role, the Linux service account and the PostgreSQL
  TLS directory were the four names the 2026-07 rename deliberately left alone,
  because they are live state rather than files. They are now `satom`,
  `satom`, `satom` and `satomssl`. New installations are born with those names;
  existing ones migrate with `deploy/migrate-rename-satom-db.sh`, which takes a
  dump before the rename, keeps the account's numeric id (so no ownership sweep
  is needed) and verifies health before it reports success.

  Three names are kept on purpose and are **not** a leftover:
  the *vendor* product names (FortiWeb, FortiADC, FortiAnalyzer and their API
  fields) — the platform manages those appliances and has to be able to name
  them; the streaming replication slot, because PostgreSQL has no rename for
  one and dropping it under a live standby risks a full re-sync for an
  invisible internal string; and the external backup server, because the
  appliances push to it by name in their own configuration and renaming it
  from here would break the nightly push silently.

### Added
- **The changelog is published on all three surfaces.** The same file is now
  readable in the repository, inside the application under **Documentation**,
  and on the public documentation site. One source, three renderings — no copy
  to fall out of date. A test fails the suite if any surface stops carrying it.

### Fixed
- **The application reported version 1.0 through four releases.** The footer
  and Settings -> System Information each carried a hand-written literal that
  was correct exactly once, while the release pipeline published the real
  number everywhere else. Both now read the repo-root `VERSION` file, which is
  the same file the offline-bundle builders and the operator console already
  read. The public site's hero badge is derived from it too, by the same
  stamping pass that versions the stylesheet, so it cannot drift either. A
  test fails the suite if a version literal reappears in a template or a page.

### Added
- **The public site ships switchable colour themes.** Three palettes —
  **Aurora** (default, light canvas over navy chrome), **Abyss** (dark canvas
  with the blue/gold glow) and **Classic** (the palette SATOM originally
  shipped) — selectable from a swatch control in the nav and remembered per
  browser. The whole palette lives in custom properties; `:root` carries the
  default, so the site still renders correctly with scripting disabled, and a
  blocking read in `<head>` applies a stored choice before first paint instead
  of flashing the default and flipping.
- **Brand gradients and glows are first-class tokens** (`--grad-blue`,
  `--grad-gold`, `--glow-blue`, `--glow-gold`, `--glow-strength`), used by the
  hero headline, the primary button, the nav hairline and the brand mark. Glow
  intensity is per-theme, so the dark palette can lean on it without the light
  one looking neon.

### Fixed
- **The site wordmark was effectively invisible.** A single `--accent` served
  both the light canvas and the navy chrome, putting the bold half of the
  wordmark, the active-link underline and the nav button at **1.65:1** against
  the bar. Split into `--accent` (canvas) and `--accent-on-chrome`; the same
  pair now measures 8.92:1, and every text pair in all three themes passes
  WCAG AA. A test fails the suite if a canvas colour is painted on the chrome
  again.
- **The brand mark had gained a plate and a frame.** The source PNG is
  transparent; an earlier crop flattened it against its own vignette. Rebuilt
  from the original with the alpha channel intact, with a CSS halo so the
  emblem's deep-blue ring still separates from the navy chrome. A test asserts
  the corners stay transparent.
- **The documentation generator's nav had drifted** from the hand-written
  pages, still emitting the company shield rather than the product mark. Both
  surfaces are now asserted against the same expectations.

### Added
- **Operator CLI: `show tree` (alias `tree`) prints the whole command surface**
  — every command as a tree, with `*` for root-required and `!` for
  destructive, plus `--commands` (flat, fixed-column, `awk`-friendly),
  `--depth N`, `--root`, `--danger` and `--json`. It renders the LIVE registry,
  so it cannot drift from what the build supports; a test fails the suite if
  any runnable command is missing from it.
- **Output policy made explicit**: `--color` / `--no-color` / `--ascii` /
  `--width N`, plus `NO_COLOR` and `SATOM_CLI_COLOR`. The contract is
  *decoration is for a TTY, content is identical either way* — through a pipe
  there are no escape sequences and nothing is truncated.
- **The manual is now published, generated and redacted.** `docs/README.md`
  is the documentation index — every document, which of the four surfaces to
  read it on, and a reading path per role. The complete command table inside
  `docs/cli.md` is generated from the live registry, and the whole manual is
  rendered to the public site under `/docs/` from the same Markdown, so neither
  copy can drift from the source the team edits.
- **Publication redacts and then refuses.** Internal addresses, management
  hostnames, hypervisor and node names, the backup server and personal e-mail
  addresses are rewritten to `{placeholders}`; the generator then re-scans its
  own output and **aborts** on any survivor, naming pattern, file and line.
  Publication is opt-in: a document not listed is not published.

### Fixed
- **The CLI could crash while printing.** An em dash in a title raised
  `UnicodeEncodeError` on a stream with an ASCII encoding (a serial console,
  `PYTHONIOENCODING=ascii`), taking the whole command down. Fixed in two
  layers: a fold table for the typography this code emits, and
  `errors="replace"` on stdout for characters it cannot predict — a device
  name, a certificate subject, a journal line.
- Glyphs now follow the stream's **encoding**, so box-drawing degrades to
  `|-` instead of becoming unprintable.
- `show tree --commands` used a single separator space, which fused the path,
  the mark and the help into one unsplittable field on the widest row.
- Command listings dimmed both the command and its help, so nothing stood out;
  the key column's emphasis is now declared per section by the caller.
- Body lines that were meant to be blank carried two spaces of trailing
  whitespace into every ticket they were pasted into.
- The `?` listing ran its footer straight into the command table.
- `Ctrl-C` at the interactive prompt now abandons the line, like a shell,
  instead of leaving the console.

### Added
- **Operator CLI, second pass: the automated half now has a console.** 39 more
  commands, organised around the failure modes this product has actually had
  rather than around the code layout. Reads for the layer that has no UI of its
  own — `get backup status` (the four copies side by side), `get scheduler
  status`, `get timer status`, `get device status`, `get monitor status`,
  `get alerts status` (*is anyone actually told?*), `get job list`,
  `get git status`, `get user list`, `get update history`,
  `get system disk|time`, `get certificate list`. New probes: `diagnose
  install` (is the node ARMED, or merely installed?), `diagnose code` (is each
  process running the code on disk?), `diagnose scheduler`, `diagnose units`,
  `diagnose config`, `diagnose nginx`, `diagnose git`, `diagnose acme` —
  `diagnose all` now folds 24 checks into one exit code in ~3.5 s. New verbs:
  `execute seed actions`, `execute restore db`, `execute backup git`,
  `execute repair jobs|tmp`, `execute admin reset-password|unlock`,
  `execute scheduler run|enable|disable`, `execute maintenance`,
  `execute enable|disable`, `execute restart-all`, `execute support bundle`.
- **Twelve offline runbooks** in `satom show runbook` — web-down, db-down,
  scheduler-idle, update-stuck, cert-expired, disk-full, peer, promote,
  restore, fresh-install, locked-out, device-unreachable. They live in the
  binary, not in the wiki or on the public site, because the operator who needs
  them has no web UI, no browser and usually no route to the internet.
- **`execute seed actions`** closes the gap documented in `safeguards.md` §10:
  no `ScheduledAction` row is ever seeded, so a fresh node has every
  capability, zero coverage, and looks perfectly healthy while it takes no
  backups at all. It prints the plan and only applies with `--yes`, and it
  never touches an existing row — operator edits still win.

### Fixed
- **Two diagnostics were modifying the tree they diagnose.** `git status` run as
  root rewrites `.git/index` and takes it from the service account;
  `compileall` leaves root-owned `__pycache__`. So `get git status` and
  `diagnose python` were *creating* the ownership drift that `diagnose git`
  then correctly reported. Now `--no-optional-locks`, an in-memory `compile()`
  and `PYTHONDONTWRITEBYTECODE=1`, guarded by `tests/test_cli_ops.py` — with a
  guard that counts git invocations rather than grepping for the flag, because
  the first version of that test passed even after the flag was removed (the
  comment explaining the rule contains it too).
- **`execute backup db` wrote a format nothing could restore.** It hand-rolled a
  bare `pg_dump`, while the product's bundle is a `.tar.gz` of `db.dump` +
  `reports/` + manifest — the only thing the System Backup page, the retention
  policy, the external push and `restore_backup` understand. It now delegates
  to `app/services/system_backup.py`. The same wrong assumption made
  `get backup status` report "no bundles" with twenty of them on disk.
- **`execute reinstall venv` was flagged destructive but asked for nothing.** It
  moves the live venv aside and rebuilds over the network; on an isolated
  management network that fails *after* the old venv is gone, leaving the node
  worse off than before. Now gated behind `--yes`, and the suite fails if any
  command flagged destructive does not document its confirmation.
- Probes against an appliance in **maintenance** no longer raise the monitor
  roll-up. Maintenance already suppresses automatic runs and their alerts; a
  console that stays red on a box parked on purpose is a console people learn
  to skip. They are still listed, under their own heading.
- `diagnose all` no longer repeats design notes from checks that passed — eight
  lines of explanation attached to nothing buried the two that were findings.

### Added
- **An operator CLI (`satom`) for a node whose web UI is down.** Modelled on the
  appliance CLIs this product manages: `get` / `show` / `diagnose` / `execute`,
  `?` completion at any depth, one-shot for scripts and an interactive prompt on
  top of the *same* dispatcher. It wraps what already existed (the `flask`
  commands, the deploy scripts, the privileged update queue) behind one
  discoverable door rather than reimplementing any of it.

  Three properties are load-bearing and are enforced by `tests/test_cli.py`:

  * **Standard library only** at module level — no Flask, no SQLAlchemy, not even
    the app package. A tool that needs a healthy venv to report that the venv is
    broken is not a recovery tool. An AST check fails the suite on a stray
    module-level import; commands that genuinely need the app import it lazily
    and degrade with a stated reason.
  * **Degrades by privilege instead of failing.** `get`, `show` and `diagnose`
    work as any user; `execute` requires root and refuses with the full command
    echoed back and an exit code of `3` — never a traceback, at the one moment a
    traceback is least useful.
  * **Installed as a `root:root` copy outside the app tree**
    (`/usr/local/sbin/satom` + `/usr/local/lib/satom-cli/`). The app tree is
    writable by the service account, so a launcher executing from there would let
    a compromised web worker rewrite what an operator runs under `sudo`. The
    installer verifies owner, mode and "not a symlink"; `satom diagnose
    privilege` re-verifies on demand and also fails if the CLI has been granted
    to the service account (that grant would equal `NOPASSWD: ALL`).

  `deploy/install-cli.sh` is called from the installer, from
  `self_update_runner.py` after every code update (the CLI lives outside the app
  tree, so `git pull` does not reach it) and from `satom execute reinstall cli`.

  New command of note: **`diagnose python`** runs `compileall` over `app/` and
  `deploy/` *and* explicitly imports the modules the app only imports inside
  functions. That is the class of failure that shipped a hard `SyntaxError` in
  `cert_service.py` inside the 1.2 and 1.2.1 bundles while the app booted,
  `/healthz` returned 200 and the whole test suite stayed green.

  Reference: [`docs/cli.md`](docs/cli.md). Permissions to request:
  `docs/INSTALL.md` §5, *Cuenta de OPERADOR*.

### Fixed
- **The device cards on the probe pages were painted for a dark theme.** SATOM
  has no dark mode — `static/css/fortiweb.css` is a light chrome (`#F4F5F7`
  content, `#FFFFFF` cards, `#EF5424` accent) — but the rollup cards added on
  2026-07-28 used the wider fleet's dark-glassmorphism palette, so on a white
  page they rendered as a **grey slab**. The same leak had made the status
  pills unreadable across *both* probe pages: pastel text on a 12 % tint of its
  own hue is roughly 1.4:1 contrast, so a badge could say `crit` and be
  invisible. The whole page-local stylesheet, and the Chart.js grid/legend
  colours in the drill-down modal, now build from `.fw-card` and the `--fw-*`
  custom properties.

### Changed
- **Device cards start folded and tile densely.** Expanded-by-default is
  unusable past a handful of appliances: a hundred of them was a kilometre of
  scroll. The cards now open collapsed, tile in a dense ~258 px grid so a large
  fleet fits in one screenful, and an expanded card takes the full row (the
  policy table needs the width, and a tall item in a narrow column stretches
  every tile beside it). The persisted state is now the set of **open** cards,
  not the closed ones, under a new `localStorage` key — the old key held the
  inverse set, and reusing the name would have expanded exactly the cards an
  operator had folded.

### Added
- **A scheduled automation that breaks now raises its own alert.** Silencing
  successful housekeeping runs is only safe if the failing run is loud, and it
  was not: `scheduled_actions` held no notification path and the alert engine
  had no check for it, so `device_sync` had failed **24 consecutive scheduled
  runs** with nobody told, and the day the scheduler sidecar stopped firing
  entirely it stayed silent for hours while systemd still showed the unit
  `active`. `alerts._check_actions` grades two signals — a consecutive
  scheduled-failure streak, and an enabled action whose due time is long past
  (a dead scheduler produces no failed runs to count) — as **one finding per
  action**, with the severity in the cooldown key so a warn → crit escalation
  still gets through. Only `trigger='schedule'` runs count: a manual retry is
  already on the operator's screen, and mixing the two hides the exact case
  where the sidecar is running stale code. A streak that hits the history
  window is reported as `N+`, not as a count; a `skipped` run clears a streak
  just as `ok` does, so an action whose targets are all parked goes quiet
  instead of sitting critical forever. Two knobs in Settings → Alerts
  (*Automation fail streak → critical*, *Automation overdue (hours)*).

### Fixed
- **Maintenance mode suppressed alerts but not work.** An appliance parked with
  `maintenance = true` was still swept by every automatic scheduled run and
  still counted as a failure, which pinned the action permanently `failed` —
  and, with the alert above, permanently critical about machines nobody expects
  to answer. An automatic run now skips parked appliances, and a run whose whole
  target set is parked reports `skipped`, which does not feed the failure
  streak. A **manual** run still reaches them: you park a box precisely to work
  on it.

- **The probe toast came back, and the tests were making it.** The job ledger
  (`data/jobs/`) resolved from the source tree, so running the test suite wrote
  real, never-finished job files into the live app; the toast dock replayed them
  on every page load as a floating "Working…" window with a dead Stop button.
  `SATOM_JOBS_DIR` now isolates the ledger and `tests/conftest.py` uses it.
- **Orphaned jobs were only reaped at boot.** `sweep_orphans` now also runs on
  the job feeds (throttled to once every 120 s), and a job that never received a
  pid is considered dead after 10 minutes instead of an hour.


### Changed
- **Service Monitor (and every other probe) now sweeps every 3 minutes** instead
  of 5. The scheduled sweep action was retimed and *all* probe intervals were
  aligned to a multiple of the new tick: `due_probes` needs the whole interval
  to elapse before a tick can fire it, so a 5-minute probe under a 3-minute
  sweep silently becomes a 6-minute probe. `cpu`, `memory` and `proxyd` moved
  5 -> 3 rather than being allowed to drift to 6; `interface` and `transactions`
  stay at 15 (already a multiple of 3). New constants
  `deep_monitor.DEFAULT_PROBE_INTERVAL_MIN` / `SLOW_PROBE_INTERVAL_MIN` carry
  the rule into every discovery path so a bare literal cannot reintroduce it.
  Measured end-to-end cadence is ~3.4-3.7 min: the scheduler anchors `next_run`
  to run *completion* and ticks every 45 s. See `docs/safeguards.md` §9i.
- **Background work no longer opens a floating window.** A monitoring sweep used
  to raise the same toast — progress bar, **Stop** button — as a firmware flash
  someone was waiting on, and pushed a bell notification on *every* successful
  run. `jobs.create_job(..., background=True)` now marks work nobody is waiting
  on: the toast dock's feed (`GET /jobs/?active=1`) filters it out server-side
  (and `jobs.js` drops it too, so a cached script can't bring the noise back),
  the Job Manager still shows it in full, and the only thing pushed to the bell
  is a **failure** — the one outcome the page itself cannot show, because the
  numbers just stay stale and look current. A clean run says nothing; a probe
  that turned crit is already carried by the device badge and the alert engine.

  Applied to both probe sweeps and the fleet hardware scan. `background`
  defaults to `False`, so no new job type can go quiet by accident. *Discover
  from device* stays foreground on purpose — it creates rows and the operator is
  waiting to read the count. Notifications from these workers now also carry the
  ADOM stamped on the job (a worker thread has no request context, so they were
  landing unscoped, i.e. under FortiWeb). See `docs/safeguards.md` §9g.

### Added
- **Device traffic cards are collapsible** on Deep monitors and Service Monitor,
  with the state persisted in `localStorage` keyed per page — `renderDevices()`
  rewrites `innerHTML` on every 20 s poll, so DOM-only state would re-expand
  every card three times a minute. A collapsed card keeps its status badge and a
  headline chip (avg throughput / policy count) so folding hides the detail, not
  the finding. Keyboard reachable, no inline handlers (CSP).
  See `docs/safeguards.md` §9j.
- Device cards restyled to the fleet visual standard: layered gradient +
  glassmorphism surface, blue->violet accent rule, hover elevation.
- **Traffic per appliance, and a real drill-down per server policy.** Service
  Monitor was a flat table of probes: the box-wide `Total HTTP Throughput`
  reading was one row among twenty, and answering *"what is going on inside this
  policy"* meant reading four rows and joining them by eye. The page now opens
  with **one traffic card per FortiWeb** — total throughput (average, window
  peak and a sparkline), box sessions / connection rate / CPU / memory, and a
  table of that device's server policies with sessions, conn/s, throughput and
  backends-up. Clicking a policy opens the full view: sessions, conn/s, client
  RTT, server RTT and application response time as KPIs, every backend pool
  member with its health, and the sessions / throughput / transactions trends
  side by side.

  Both views are built **entirely from stored samples** — opening them never
  contacts an appliance, so they answer with the box powered off or its cmdb API
  licence-locked, which is the case on fw6 and fw7 today. And they refuse to
  invent numbers: a probe that is missing, disabled or has never run reports
  *not measured* rather than `0`, stale samples are flagged with their age, and
  there is deliberately no single rolled-up per-device badge, because `unknown`
  sorts as *less* severe than `ok` and one healthy probe would paint over three
  missing ones. See `docs/safeguards.md` §9h.

- **Service Monitor — runtime telemetry gets its own Monitoring page.** The four
  REST-telemetry probe kinds (`sessions`, `policy_sessions`, `throughput`,
  `transactions`) moved out of Deep monitors to **Monitoring → Service Monitor**
  (`/monitoring/services`), present in all four ADOMs. Deep monitors keeps the
  five kinds that reach into the appliance (`https`, `interface`, `cpu`,
  `memory`, `proxyd`).

  Storage, runner and the `deep_monitor` scheduled action are deliberately
  **not** split — two runners would double-schedule every device. What is split
  is the set of kinds each page owns, and the partition is enforced on every
  route: each `/data` filters on its own kinds, create/edit refuse the other
  page's kinds, a foreign probe id answers 404, *Probe now* is pinned to the
  page (and the ADOM), and *Discover from device* only offers the steps the page
  owns. A kind can land on exactly one page — neither on both nor on neither,
  or the partition test fails. See `docs/safeguards.md` §9f.

  Both pages render from ONE template (`monitoring/_probe_page.html`) driven by
  a `PageSpec`, so the drill-down chart, rollups, history drawer and port picker
  cannot drift apart.
- **Live server-policy picker** in the probe form: the policy name field is
  backed by a datalist filled from the appliance's LIVE `policystatus` (not the
  harvest cache, which is empty on a licence-locked box). A failure is printed
  in the form instead of degrading to an empty dropdown — "no policies" and
  "could not ask" look identical in a `<select>` and mean opposite things.

### Fixed
- **`transactions` could report a silent zero on a saturated policy.** Found by
  a real load test against fortiweb08 (2026-07-28): a policy carrying
  ~2 700 req/s reported **0** transactions in every bucket, and **417 059** the
  moment a `web-protection-profile` was attached to it — nothing else changed,
  and enabling the global traffic log beforehand made no difference. The probe
  now cross-checks `policystatus` **only when the count is zero**; if the policy
  is carrying sessions or connections it grades `warn` and names the likely
  cause, instead of a green row on a busy service. Mutation-tested.

### Changed
- *Probe now* with no selection no longer sweeps every probe in the fleet: it
  runs the current page's kinds for the current ADOM's devices. Coverage in the
  Global ADOM is unchanged (the whole fleet); what changed is that the Deep
  monitors button no longer also runs the Service Monitor probes.

- **Per-appliance runtime telemetry over the REST API — sessions, HTTP
  throughput and throughput per server policy.** Four new Deep monitor probe
  kinds that open **no SSH session**: `sessions` (box-wide concurrent sessions
  and connection rate), `policy_sessions` (per-policy sessions, conn/s, client
  and server RTT, application response time, plus each pool member's up/health),
  `throughput` (per-policy or `Total HTTP Throughput` aggregate, charted in
  Mbps) and `transactions` (bucketed HTTP transaction counts). Thresholds are
  absolute (`warn_num`/`crit_num`), with the unit shown per kind; the drill-down
  charts, rollups and 7/30-day history all work unchanged. *Discover from
  device* gained a **REST telemetry** option.

  FortiWeb 7.6 has no `/api/v2.0/monitor/<resource>` tree — that prefix serves
  only `monitor/permission-check`. The endpoints used here were enumerated from
  the appliance's own GUI bundle and verified live against FortiWeb 7.6.8
  build1128. Notably they keep answering on an appliance whose **cmdb is
  licence-locked**: fw7 returns HTTP 423 `-20010` for every config read while
  `policystatus` and `policytraffic` answer 200, so these probes cover exactly
  the devices whose hourly `device_sync` has been failing. FortiWeb only —
  FortiADC and FortiAnalyzer are refused by name rather than measured as zero.
  See `docs/safeguards.md` §9e.

### Changed
- **A scheduled deep-monitor sweep now reports whether it RAN, not whether it
  liked what it found.** `ok` was `worst in ("ok","unknown")`, so a single
  policy with every backend down marked the sweep *failed* and kept it failed
  until the backend was repaired — making a sweep that could not execute look
  identical to a healthy one that found something, and pinning the action
  permanently red. The worst status and per-status counts moved into the
  summary. See `docs/safeguards.md` §9d.

### Fixed
- **A product ADOM inherited the manager's own infrastructure.** Fleet health
  rendered *Infrastructure health — HA nodes · Git · backup server*, the
  Database / Services & redundancy cards and *Encryption in transit* inside the
  FortiWeb, FortiADC and FortiAnalyzer ADOMs, putting node hostnames and
  infrastructure addresses on a page scoped to a single product. Those sections
  are now Global-only, and not just visually: `/monitoring/data` omits the
  `system`/`services`/`db`/`redundancy` keys outside Global (the collection is
  skipped, not filtered) and `/monitoring/infra` and `/monitoring/encryption`
  answer **403**. The payload gained a `scope` field. See `docs/safeguards.md`
  §9c.
- **Two fleet-wide actions ignored the ADOM.** *Scan hardware (SSH)* on Fleet
  health and *Probe now* on Deep monitors both default to "everything" when
  nothing is selected, and both then open an SSH session per device — so from
  the FortiWeb ADOM they logged into the FortiADC and FortiAnalyzer boxes. The
  target list is now resolved in the request, where the ADOM exists, and passed
  to the worker thread. Global still means the whole fleet.
- **Fleet health badge could never go red.** Each appliance card was graded
  *only* by capacity headroom; with no `effective_cap` anywhere in the fleet
  every row scored `nocap` and the badge was structurally pinned to `healthy` —
  a powered-off appliance with no cached data at all still rendered green. The
  badge is now the roll-up of four signals (harvest history, cache age, enabled
  deep monitors, capacity) in the new `app/services/device_health.py`, with a
  distinct `unknown` state and the reasons printed under the badge. New
  `health_alerts` block on `/monitoring/data`. See `docs/safeguards.md` §9b.
- **The device alert was a TCP probe and nothing else, so a red badge never
  sent mail.** `alerts._check_devices` opened a socket to `host:port` and
  reported only a refused connection. Three of the four appliances in this
  fleet accepted `:443` while their REST harvest had been failing for a week on
  an invalid licence — the Monitoring page went red and the mailbox stayed
  empty. The check now grades each device with `device_health.collect_for()`,
  the same roll-up the page prints, and keeps the socket probe as one more
  signal (it remains the only network-touching check; the page is DB-first by
  contract). One device produces **one** finding listing every failing signal,
  the severity tracks the badge, and the roll-up status is part of the cooldown
  key so a device escalating from degraded to critical inside the suppression
  window still reaches the operator. New floor setting
  `alerts.device_min_status` (`warn` default, `crit` to mail only on critical)
  under Settings → Alerts.
- **`maintenance` flag on the Monitoring device card was always false.** The
  payload read a `maintenance_mode` attribute that has never existed on
  `Appliance`; the column is `maintenance`.

### Changed
- **Monitoring is now an ADOM-level submenu, not Global-only.** Fleet health,
  Metrics and Deep monitors appear in the FortiWeb, FortiADC and FortiAnalyzer
  ADOMs as well as Global, from a single shared partial
  (`app/templates/partials/nav_monitoring.html`) so the group cannot drift
  between ADOMs again. The `monitoring` and `deep_monitor` blueprints were
  added to the ADC/FAZ product gates; all three pages already scope their rows
  through `visible_appliances()`, so an ADOM sees only its own devices and
  probes and anything created from Global against a device of that product
  appears there automatically (scoping is by device **kind**, not by creator).
- **The `proxyd` probe reports memory CONSUMED and FREE, in megabytes**, instead
  of the daemon's `%VSZ`. `%VSZ` is *virtual* size: measured on fw6, the eight
  largest processes sum to 240 % of installed RAM, because every shared mapping
  is counted once per process. A figure that can exceed 100 % is not memory
  used and must not be displayed as though it were. The new numbers come from
  the `Mem:` header of the same `diagnose system top` output — real, box-wide,
  no extra round trip. The daemon is still graded alone (running? PID set
  changed?); thresholds on box memory remain the `memory` probe's job, which
  already covers every appliance. `%VSZ` is kept in the sample payload as
  `daemon_vsz_pct`.
  **Upgrade note:** `value_num` changed units, so `deep_monitor.reset_series(
  "proxyd")` clears the pre-existing samples of that kind. Charting `59.7` next
  to `2328` on one axis is a lie no axis label can repair.
- **Chart.js is served from `static/vendor` (4.4.4) instead of
  `cdn.jsdelivr.net`.** SATOM ships offline installers for air-gapped
  management networks; a chart that only renders with public internet access
  does not render where it matters. The vendored copy was already in the tree
  and unused.

### Added
- **Drill-down charts on the deep monitors.** Clicking any sparkline opens
  1 h / 24 h / 7 d / 30 d or an explicit date range, with min/average/max, the
  status strip, healthy-percentage and threshold lines.
- **`monitor_rollup` — pre-aggregated history.** Raw samples are capped per
  probe (~2 days at the default interval and retention), so depth is bought
  with buckets instead: hourly kept 90 days, daily kept 2 years, under 400 KB
  per probe for two years of history against roughly 35 MB if the raw rows and
  their CLI payloads were retained for the same window. Both extremes are
  stored, not just the mean — a four-minute spike is invisible in an average
  and is exactly what an operator opens a chart to find.
  The rollup runs **inside `run_probe`, before the retention prune**, rather
  than as its own scheduled action: nothing in this product seeds a
  `ScheduledAction` row, so a feature that depends on the operator creating one
  does not exist on a fresh install.
- **`GET /monitoring/deep/probe/<id>/series`** — chart data. The resolution
  (raw samples, hourly buckets, daily buckets) is chosen server-side and
  reported back in `source`, and the UI prints which one it drew: an hourly
  average and a five-minute reading are not the same claim about the device.

## [1.2.2] - 2026-07-27

### Fixed
- **`app/services/cert_service.py` did not parse.** An `import os` had been
  placed above `from __future__ import annotations`, which is a hard
  `SyntaxError`, so the module could not be imported at all. Introduced on
  2026-07-26 with the privilege-model work and shipped in the 1.2 and 1.2.1
  offline bundles. Consequences while it was live: the nightly
  `satom-cert-renew` service failed on both nodes, the Node TLS settings and
  Certificate Manager endpoints raised on import, and the cert alert degraded
  to reporting the import error instead of the certificate's real state.

### Added
- **`tests/test_every_module_imports.py`** — every shipped module under `app/`
  and `deploy/` must compile, and the modules that callers import *lazily*
  (inside functions) must actually import. The 757-test suite stayed green for
  a full day with a module that could not be parsed, because nothing imported
  it at collection time; the only signal was a timer failing where nobody
  looks. Verified by reintroducing the fault: both checks fail.

## [1.2.1] - 2026-07-27

Documentation release. No application code changed; the offline bundles were
rebuilt so that the shipped tree matches the documentation set.

### Added
- **`docs/safeguards.md`** — single catalog of every protection in the product:
  what it prevents, where it lives, and **how to verify it is armed**. Covers
  git history, self-update and dependencies, the privilege boundary, node-to-node
  correctness, appliance writes, certificates, external files, sessions and
  alerts. Ends with the limits that are deliberately not covered.
- **`docs/INSTALL.md` §6 "Protections you must arm"** — scheduled actions,
  alert recipients and per-node timers are **database state**, not code, so a
  fresh install starts with none of them. The minimum set is now spelled out
  (`device_sync`, `device_inspect`, `system_backup`, `git_bundle`).
- **`docs/INSTALL.md` §2.2** — what the offline bundle actually contains
  (manuals readable from the console without a network, the ACME client, and
  since 1.2 `sudo` / `openssh-*`), plus how to read a bundle's VERSION before
  installing it.
- **`docs/safeguards.md` §10 "Fresh installs"** — which guards arrive armed by
  code versus which are database state the operator must create.
- Public site: `site/safeguards.html` (linked from the nav and footer of every
  page) and the matching notes on `site/install.html`.

### Changed
- In-app **Documentation** index now curates a title, order and description for
  all 18 manuals; half of them previously fell through to an auto-generated
  title with no description, so they existed but were not discoverable.
- **Rule recorded in `docs/overview.md`**: a new safeguard lands in
  `docs/safeguards.md` in the same commit that introduces it.

### Fixed
- Offline bundle checksums used an absolute path, so `sha256sum -c` failed in
  the directory the file was downloaded to. Now basename-only, as the RHEL
  builder already did.
- RHEL offline bundle: the ACME client (`lego`) was staged inside the wrong
  branch of the builder, so the documented build path (a `rockylinux:9`
  container with no `.git`) produced a bundle with no ACME support.

### Known gap closed
- The 1.2 bundles were built three minutes before the safeguards catalog was
  committed, so they shipped the guards but not the document describing them.
  1.2.1 exists to close exactly that.

## [1.2] - 2026-07-27

### Changed — privilege model (action required for existing installs)
- **The application no longer runs as root.** Web, scheduler, reconciler,
  alerts, cert-renew, git-publish and HA datasync all run as an unprivileged
  service account. Only the update runner (`satom-updater`) stays root, by
  design — it installs units, runs pip and restarts services.
- The account is pinned with a systemd **drop-in**
  (`/etc/systemd/system/<unit>.d/10-app-user.conf`), not by editing the unit:
  the self-update runner recopies unit templates on every update, so an edited
  unit silently reverted to root.
- `sudo` is limited to exactly two commands (`nginx -t`, `systemctl reload
  nginx`). Package-manager and unrestricted `systemctl` rules were rejected on
  purpose: a `.deb` runs its maintainer scripts as root, so permission to
  install any package **is** root.
- Existing installs: `sudo bash deploy/migrate-deprivilege.sh`, one node at a
  time, standby first. Rollback material is written to
  `/root/satom-units.pre-deprivilege-<ts>/`.
- HA trust was inverted: the secondary now generates its own key pair, the
  private key never travels in the join key, and the authorized key is pinned
  with `from=`, `restrict` and a forced command that can only serve
  `rsync --sender` over the data directory.

### Added
- **ACME / Let's Encrypt certificate issuance** with a DNS-provider catalog
  (30 providers seeded as data, editable by the operator) and per-provider
  credentials encrypted at rest. The signer receives a minimal, purpose-built
  environment — it does not inherit the application's secrets.
- **Certificate renewal journal** and a Renewals page: every attempt is
  recorded with its outcome and error text, per node, and a failed renewal is
  now its own alert signal instead of surfacing only as an expiry warning.
- **Repository backup and git-outage survival**: `git bundle --all` artifacts
  across four failure domains (node, standby, external backup server,
  download), a guard that parks unpushed commits on `refs/backup/*` before
  `git reset --hard` — aborting the update if it cannot — and a
  `git.ahead_unpushed` alert keyed on the **age** of the oldest unpushed
  commit. Docs: `docs/git-backup-and-outage.md`.
- **Installer preflight** (`install-satom.sh --preflight`): every blocker is
  collected and reported together before anything is touched — effective write
  access, systemd, package manager, Python >= 3.10, disk and memory, an
  existing installation, port conflicts, clock and outbound reachability.
- Fleet map device card now shows the **real interfaces** harvested from the
  devices, with MAC addresses fetched on demand over read-only CLI and
  per-port role badges derived from cached configuration.
- Product renamed to **SATOM — System Automation & Task Orchestration
  Manager**. Vendor names (FortiWeb, FortiADC, FortiAnalyzer) are untouched:
  the product manages those appliances and has to name them.

### Fixed
- **Scheduler and git-publish were silently dead** after the privilege drop:
  both guard scripts used `runuser`, which only works as root. The scheduler
  took the standby branch on every loop, so no scheduled action fired; git-publish
  failed and still exited 0, so systemd reported success while the git copy of
  the source of truth stopped being published. Both now use a shared role probe
  that works at any privilege level, and git-publish exits non-zero on failure.
- Offline bundles did not ship `sudo` or `openssh-*`. On a minimal image the
  preflight passed and the install died at the sudoers step, after creating the
  service account and taking ownership of the tree.
- Seven CVEs flagged by `pip-audit` (setuptools, markdown, python-dotenv);
  `setuptools` was unpinned, so a fresh install reintroduced the vulnerable
  version.
- Three bugs in the rename migration script, found running it live on the
  standby — one of them deleted the node-written HA units and stopped
  replication.

### Security
- SSRF blocklist in the device API proxy now also refuses loopback targets.
- Triaged an internal AI security audit (14 findings): 1 real and fixed, 13
  verified false-positive or stale.

## [1.1] - 2026-07-15

### Renamed — service & filesystem layout (breaking for existing installs)
- Project fully renamed from the legacy internal name to **SATOM** at the
  infrastructure level: app dir `/opt/satom`, log dir `/var/log/satom`,
  and all systemd units (`satom.service`, `satom-scheduler.service`,
  `satom-reconciler.service`, `satom-updater.{path,service}`,
  `satom-alerts`, `satom-cert-renew`, `satom-git-publish`,
  `satom-ha-datasync` timers/services).
- Existing installs: run `deploy/migrate-rename-satom.sh` (root, one node
  at a time, standby first). It stops the legacy units, moves the tree, fixes
  venv shebangs, installs the renamed units, updates nginx and re-verifies
  `/healthz`.
- Installers (online + offline bundles) regenerated with the new layout.
- Unchanged on purpose: Postgres DB name/user, the `backup-server` external backup
  server (appliance-side push config points at it), and `FM_*` env var names.

## [1.0] - 2026-07-14
### Added
- **DNS Records management (IPAM/DDI)**: "+DNS Records" CRUD in the DNS & LB
  lookup tool, backed by pluggable providers (EfficientIP SOLIDserver,
  phpIPAM, NetBox).
- **Alerts engine**: cert-expiry, git-divergence, device-unreachable and
  backup-freshness alerts with in-app + email dispatch and admin thresholds.
- **Certificate auto-renewal** modes (alert-only default, or auto-pull from
  the edge) via a nightly renew timer.
- **Configuration drift detection** against the git source of truth, with
  recursive volatility normalisation.
- **Preflight/postflight health-snapshot harness** for upgrades and restores.
- **Gated canary restore** for per-device config recovery.
- **Firmware manifest auto-generation** on upload / pull / delete.
- **Production release line**: Linux installer (Debian + RHEL offline
  bundles), generic package-manager support, public site (GitHub Pages),
  package registry artifacts.
### Fixed
- Upgrade-event timestamps now render in local time (`| localtime`) instead
  of raw UTC.

## [0.9] - 2026-07-13
### Added
- **Node TLS + node-to-node encryption**: internal CA, per-node leaf certs,
  mutually-authenticated Postgres replication, HTTPS peer probes, and
  "encryption in transit" monitoring cards (every badge backed by a live probe).

## [0.8] - 2026-07-12
### Added
- **FortiAnalyzer** integration (JSON-RPC, dual dialect) as a full ADOM, with
  its endpoints in the DB registry and a git source-of-truth harvest.
- **FortiADC** configuration added to the git source of truth (hourly sync +
  nightly inspect), matching FortiWeb.
- **Backup coverage page**, external backup server (SFTP) with firmware SoT,
  library update indicator + per-package pip upgrade/rollback.
