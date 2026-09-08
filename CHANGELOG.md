# Changelog

All notable changes to SATOM are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/). This is a public,
source-available project — see [NOTICE](NOTICE) for the trademark disclaimer.

## [Unreleased]

### Added — Calendar: one grid for everything this fleet is scheduled to receive (2026-09-08)

A new **Fleet → Calendar** page (`/calendar/`), the first entry of the Fleet
menu in every ADOM. Month, week, 30-day agenda and whole-year views over the
three things that answer "what is happening to this fleet, and when":

- **Planned changes** — every Change Request, drawn across every day its window
  spans, with its type, risk, appliances and the person accountable for it.
- **Upcoming automations** — the recurring Scheduled Actions, projected forward
  from the scheduler itself.
- **What ran** — the recorded runs, so the same grid answers the retrospective
  question as well as the forward one.

**It invents no planning object.** A calendar with its own "planned item" would
be a second author of what a planned change is, and the two would disagree the
first time somebody approved one from the Change Requests page instead. Planning
from a day cell calls `change_requests.create_change_request` — the one
implementation, with its device-visibility, product and single-target checks
intact — and the page never writes anything else.

- **Plan against an ADOM, a group or named devices.** Groups are the dimensions
  the inventory already carries (tag, department, zone, line), and they are
  **resolved to a fixed list of appliances the moment the change is raised**,
  with both the selector and the resolved list recorded on the change. A live
  selector would let an approval for one set of boxes execute against another.
  A selector matching nothing is refused rather than saved as an empty change.
- **Overlapping-change warning.** Two windows that overlap *and* share an
  appliance are flagged. Sharing a device is the whole test: parallel work on
  different boxes is ordinary operations, and flagging it would put a warning on
  most Tuesdays until nobody read it.
- **Projection is future-only; the past is measured.** Schedule math can say
  when a job *would have* fired last Tuesday, not whether it did. Past days
  carry recorded runs and nothing else.
- **Nothing is dropped in silence.** A capped occurrence series, a disabled
  automation, a clipped run list and a window spanning more days than the grid
  paints each say so on the page.
- Days are bucketed in the timezone configured under Settings → General, not in
  UTC: a window at 23:30 UTC is tomorrow in Europe/Zurich.

### Fixed — a maintenance window that ends before it starts is refused (2026-09-08)

`create_change_request` accepted `window_end <= window_start`. Such a change can
never fire, because no instant lies inside its window — it simply sits in
`approved` looking healthy until somebody notices, the morning after, that
nothing ran. CR-0011 on the primary node was stored ending a **day** before it
began. The check lives in the one implementation of "raise a change", so the
form, the batched wave route and the new calendar all inherit it.

### Added — Device Console: a write-capable CLI, credential testing and TAC bundles (2026-09-08)

A new Administrator page, **Device Console** (`/console/`), present in **every
ADOM**. It does three things an operator needs when a box is misbehaving and
the REST API is not enough: run CLI commands against an appliance and read
every answer, test a single username and password directly against a FortiOS
device, and package the transcript for a Fortinet support ticket.

**This is the first SSH write path in SATOM, and it is deliberately confined.**
`app/services/ssh_ops` documents in its own docstring that the console "is
locked to read commands", and six services import it on that promise
(`cert_manager`, `backup`, `backend_probe`, `reach_batch`, `logcollect`,
`interface_inventory`). Adding a `write=True` flag there would have made that
sentence false for all of them at once. `assert_readonly` is therefore
untouched; the write path lives in the new `app/services/ssh_console.py` and is
reachable from exactly one blueprint.

- **The gate is a denylist, in three tiers.** An allowlist is right for
  `ssh_ops`, where the question is closed ("is this a pure read?"). Here the
  question is open — an operator recovering a box at 3 a.m. needs whatever
  FortiOS spells today, and a capability the authors did not foresee reads as a
  broken tool, which is how people end up SSHing from a laptop with no audit
  trail at all. What *is* closed is the set of commands that end an appliance,
  so that is what is enumerated.
  - **Forbidden, at every permission level, with no UI path:**
    `execute factoryreset`, `execute formatlogdisk`, disk erases and formats.
  - **Disruptive, sent only after the operator acknowledges the effect and
    types the appliance name:** reboot, shutdown, config/firmware restore, HA
    changes, clear-text config exports, and password writes.
  - Everything else, behind `config_write`.
- **The whole script is gated before the session opens.** A refusal discovered
  on line 40 after lines 1–39 already landed leaves the appliance in a state
  the page cannot describe; half a configuration change is worse than none.
- **A failed command halts the script by default.** The FortiOS CLI is modal:
  after a failed `config`, the `set` lines that follow land at the top level
  instead. Commands not reached are reported as `not_run`, never dropped.
- **Silence is success here**, unlike the reachability probes. A `set` that
  works prints nothing, so reading an empty answer as failure would mark every
  correct configuration line red.
- **Credential testing answers three questions, not one.** Reachable /
  authenticated / can-actually-read are separated because they send the
  operator to three different places — and an account that logs in and can read
  nothing is a real FortiOS state that anything checking only authentication
  calls a success. Write access is reported as the device's **raw words**, never
  as a flag: the only free evidence is whether the automatic pager-disable was
  accepted, and a box that refused it for an unrelated reason is
  indistinguishable from a read-only account. Throttled per operator and
  audited on every attempt; the password is never stored.
- **Nothing secret leaves in a bundle.** Transcripts are redacted before they
  are stored, audited or packaged. A diagnostic capture that fails does not
  lose the bundle — the transcript is what TAC asked for, and the failure is
  named inside the archive instead.

### Fixed — the Administrator group is now named and reachable in every ADOM (2026-09-08)

Two of the five administration blocks in `base.html` were titled
**Administration** rather than **Administrator**, so the FortiADC and
FortiAuthenticator sidebars carried a differently-named group holding the same
pages. They are one name now.

`console` was also added to the FortiADC / FortiAnalyzer / FortiAuthenticator
blueprint allowlists. Without it the shared nav partial drew a live-looking
entry that the product gate redirected to the ADOM home — the same defect
`advisor` and `adom_assets` had on 2026-08-30, and
`tests/test_adom_menu_reachability.py` is what caught it this time.

### Added — full source↔destination comparison of a service (2026-09-08)

A new Fleet page, **Config Compare** (`/compare/`), takes the SAME
`source;policy;destination` file the Backend Reachability page takes and
answers the next question about those services: **is this service configured
the same on both boxes, and if not, exactly what differs?** Every object behind
the policy is read on both appliances — virtual server, server pool and its
members, certificates, content routing, allow-lists, the web protection
profile — and subtracted. It needs no workspace tab open and no appliance
selected anywhere, and it **writes nothing**.

- **It is not a second clone planner.** The walk is
  `clone.ClonePlanner.collect` — the same one the clone dialog and the
  cascade-delete planner use, and the only thing in the product that knows
  which fields of a FortiWeb object are references. A second walk here would
  let this page and the clone report disagree about what a service even
  *consists of*. What `app/services/config_compare.py` owns is the
  subtraction: pairing, field diffing, the package rule for profiles, and the
  per-line verdict.
- **Counterparts are paired by ROLE, not by name.** A cross-box clone
  routinely lands the web protection profile under a derived name, and pool or
  virtual-server names drift too. Objects reached from the same parent through
  the same reference field are counterparts whatever they are called; the name
  difference is then reported as `renamed` — one finding — instead of
  "missing on the destination" plus "extra on the destination", two false
  findings that hide the answer. The parent's reference field is not allowed to
  repeat that rename as configuration drift.
- **A web protection profile is compared as ONE PACKAGE, never entry by
  entry.** An inline profile drags in a dozen sub-profiles and each can hold
  hundreds of rows. The package is reduced to a fingerprint plus which
  sub-profiles differ and by how much (`−removed ~changed +added`); the
  package's own name is excluded from that fingerprint, so a landed clone under
  a derived name still reads as `renamed`, not as five hundred differences.
- **The diff is symmetric.** `clone.subrow_diff` deliberately looks only at the
  fields the source carries, because it answers "what would I have to write?".
  This page answers "how do these two differ?", so a setting the DESTINATION
  carries alone is exactly as much of a difference as one the source carries
  alone. Reusing the write-shaped diff would have hidden every
  destination-only setting.
- **Per-box bookkeeping is never configuration.** A by-parent row's `id` is
  allocated by the appliance that created it, so identical rows on two boxes
  carry different ids; rows are matched by their declared unique key or by
  content instead. `enable`/`True` and `80`/`"80"` are one value, and an absent
  field and an empty one are the same field.
- **An absent policy is absent, not empty.** `collect()` answers a missing
  policy with its root item and an empty payload, never an empty list — so a
  service that is not on one box is reported `missing` (with the box named),
  and a service on neither is an error, never two empty trees declared
  identical.
- **Nothing is dropped silently.** Over-limit lines, the format header, lines
  the time budget never reached, a field list cut by its cap and a by-parent
  row whose owner could not be matched are each named or re-homed. A comparison
  that quietly covered less than it was asked to reads exactly like a clean
  run, which for this tool is the worst possible failure.
- Read-only, audited as `config.compare`, and registered in the Global ADOM and
  the FortiWeb ADOM only (it reads FortiWeb server policies). Export is
  tab-separated, one line per difference.
- `ClonePlanner` now also records the reference **edges** it already walks —
  `(parent, via, child)`. `_refs` answers "who names this?"; a comparison needs
  "what role does it play?", and only the field says that. Additive: one new
  list, written beside the two `_refs` writes that were already there.

### Added — batch backend reachability from a `source;policy;destination` list (2026-09-08)

A new Fleet page, **Backend Reachability** (`/reachability/`), takes a file or a
pasted list — one `source;policy;destination` per line — and answers one
question per line: **do the real servers behind this policy answer, on the
source box and then on the destination box?** It needs no workspace tab open
and no appliance selected anywhere, and it **writes nothing**: the only traffic
it emits is `execute ping` over the read-only CLI and TCP handshakes from this
node.

- **Read-only by construction.** No clone, no migrate, no config change. The
  page is still audited (`reachability.batch`), because "who made these boxes
  ping our customer's servers?" is a question that gets asked.
- **`app/services/reach_batch.py` re-implements none of the probing.** Reading
  a policy's pool members is `backend_probe.dst_pool_targets`, probing a target
  is `backend_probe.probe_targets`, and deciding whether a backend counts as
  reachable is the new `backend_probe.classify_row` — the same call `summarise`
  counts with. A second copy of any of those would let this page and the clone
  report disagree about the same backend.
- **Three answers, never two.** `reachable` / `unreachable` / `unknown`, all
  the way up to the line verdict (`ok` · `down` · `mismatch` · `unknown` ·
  `error`). A probe that could not run is never rendered as an outage and never
  as health.
- **A bad destination never voids the source answer.** An unknown destination
  name, an unreachable destination box or a policy that is not there still
  leave the source half read and reported — that half is the reference the
  operator is comparing against.
- **Nothing is dropped silently.** Over-limit lines, the format header, targets
  cut by the 2000-target cap and backends skipped when the time budget expired
  are each named in the report. A run that quietly covers less than it was
  asked to reads exactly like a clean run.
- **Source pools are compared against destination pools** by `(address, port)`
  — `missing_in_destination` / `extra_in_destination` name the member. When the
  destination does not have the policy at all and an SSH vantage is available,
  the source's backends are pinged **from the destination** instead (the
  pre-migration question); that side is flagged as a different measurement and
  the comparison is skipped **out loud**, never in silence.
- **One API read per appliance** however many lines name it, one ping per
  address per box, one TCP handshake per `(address, port)` for the whole run.
  The appliance ping cache is **never** shared between two boxes — reusing one
  box's answer for another is exactly the confusion the two-vantage design
  exists to prevent.
- Retired `*.invalid` registrations and non-FortiWeb devices are refused by
  name before a client is built, instead of spending a connect timeout per line.

### Fixed — `backend_probe` additions used by both callers (2026-09-08)

- `dst_pool_targets` rows now carry a stable `error_kind`
  (`no_such_policy` · `no_pool` · `pool_unreadable` · `empty_pool`) next to the
  operator-facing `error` prose. A caller that branched on the prose was a
  second author of it, and rewording a message would have silently changed what
  the caller decided.
- `probe_targets` accepts caller-owned `ping_cache` / `tcp_cache` dicts so a
  chunked batch can skip work it already did, and a cached TCP result is now
  **copied** into each row rather than shared.
- `classify_row` is extracted as the single author of "is this backend up?";
  `summarise` counts with it and the page's per-row badges are stamped from it.

### Added — decommission a service from the DNS & LB Lookup page (2026-09-08)

The operator finds a name in *DNS Lookup*, and the match that serves it now
carries a **Decommission** button: one guarded pass that retires the LB object
and its exclusively-owned dependencies, the SNI member, the certificate, the
WAF profile, the WPP carve-outs and the DNS records that point at the name.
Available in the FortiWeb and FortiADC ADOMs, `config_write` only, audited
either way it goes.

- **The preview is the feature.** `POST /dns-lookup/decommission/plan` only
  reads; `POST …/apply` re-plans, compares the fingerprint of what the operator
  confirmed against what the device says NOW, and refuses with the new plan
  attached when they differ. Between preview and confirmation another session
  can bind the certificate to a second policy — that binding is the whole
  question, so a stale confirmation is not "close enough".
- **`app/services/dns_decommission.py` is not a second delete engine.** Every
  destructive step is executed by the module that already owns it:
  `policy_graph` for the cascade, `cert_manager.remove_device_certificate` for
  a certificate (which re-runs its own fail-closed binder check), 
  `exception_lifecycle.on_server_policy_deleted` for carve-outs, and
  `FortiWebOps.delete` — hence `delete_guard` — for everything else.
- **Unverifiable means kept.** A binder read that fails, a firmware with no
  `q_ref`, an ADC table that will not answer: each leaves the object with
  `action=keep` and a reason that says so. Nothing is ever deleted because a
  box was unreachable while we asked who else uses it.
- **Warnings need acknowledging, and they name the dependency**: an SNI policy
  that still serves other domains through other certificates (the member is
  removed, the policy is kept), a certificate that also covers names this
  decommission does not account for, a CNAME that leaves the service.
- **DNS runs first**, before the VIP is freed. A record outliving its service
  is not cosmetic — the address gets reused and the old name lands on a
  stranger.

### Fixed — a real cascade delete crashed on its own report (2026-09-08)

`policy_graph.execute_delete_plan` unpacked `to_keep` as 4-tuples while the
planner has produced 5 (the `shared_with` list) since sharing was added. Every
non-dry-run cascade with any kept dependency — which is nearly all of them, a
bound certificate is enough — raised `ValueError` **after** the deletes had
already reached the box, so the operator got a 500 instead of the report of
what had just been removed. The dry-run path unpacked 5 and was correct, which
is why a preview never showed it.

### Fixed — the FortiADC Certificate column was always blank (2026-09-08)

`dns_tool._fortiadc_rows` read `ssl-certificate` off the virtual server. A
FortiADC virtual server has no such field: the chain is
`virtual server → client-SSL profile → local-cert group → certificate`. The
column now walks it (read-only, best-effort), which is also what the
decommission planner needs to decide the ADC certificate.

### Changed — every install shape provisions TLS for itself (2026-08-31)

The turnkey installer has always issued an internal CA and put nginx in front
of gunicorn. Three other install paths did not, and one of them is the quick
start in this repository's own README:

| path | before | now |
|---|---|---|
| `installers/install-satom.sh` (+ the three offline bundles) | TLS | unchanged |
| `scripts/install.sh` | gunicorn on `0.0.0.0:8000`, plain HTTP | loopback gunicorn behind nginx on `:443` |
| `deploy/install.sh` (legacy bootstrap) | plain HTTP | same |
| `deploy/docker/` | published `:80`, delegated TLS to a proxy the operator supplied | a `proxy` service in the stack terminates `:443` |

Nothing failed in the old shapes. They came up, answered `/healthz` 200 and
reported success — and could not accept a password, because the app runs
`FLASK_ENV=production`, session cookies are `Secure`, and a browser will not
return a `Secure` cookie to a plain-HTTP origin. The login POST arrived with no
session, therefore no CSRF token, and was rejected *before* the password was
compared.

- **`deploy/tls-bootstrap.sh`** is the one implementation: `ensure-pki`
  (internal CA, 10 years; node leaf, 825 days), `write-vhost`, `import-cert`.
  Idempotent, and it **refuses to reissue over a certificate an operator
  imported** — a re-run replacing a trusted certificate with a self-signed one
  is how a node lost its wildcard on 2026-08-04.
- The certificate is **self-signed and the browser warns**. That is the day-zero
  state on purpose: usable immediately, replaced on the operator's schedule.
  `import-cert` refuses a mismatched certificate/key pair, which nginx would
  otherwise accept and then fail on the first handshake.
- **Container stack**: `tls-init` (the SATOM image, run to completion) issues
  the material into a `satom-pki` volume; `proxy` (stock `nginx:alpine`) serves
  it. The volume means an image-tag change keeps the certificate. `web`,
  `scheduler` and `cron` publish nothing.
- `SATOM_HTTP_BIND` is **retired, not reused** — it published gunicorn
  directly. `satom-docker.sh` stops with an explanation rather than ignoring a
  stale value, because an operator who wrote `127.0.0.1:8080` to keep the app
  off the network would otherwise have had the opposite of what their file said.

### Fixed — the `:80` → `:443` redirect now actually fires on every path (2026-08-31)

Every install path already *wrote* a redirect. Whether nginx ever **selected**
it was another matter: the redirect block is matched by `server_name _`, so it
only ever serves requests that reach it as the **default server** for `:80` —
and nothing guaranteed it was.

- **`installers/install-satom.sh` hardcoded `default_server` on its `:80`
  listener** while the TLS listener took it from the self-correction switch. On
  a host where another vhost already claimed the default, nginx answered
  `duplicate default server`, the installer rewrote the vhost without the claim
  — and the `:80` listener kept it, so `nginx -t` failed again and the install
  died at its final step with the application already installed and healthy.
  Both listeners now take the claim from the same switch.
- **`scripts/install.sh` and `deploy/install.sh` never asked for
  `default_server` at all**, and cleared only Debian's enabled default site.
  They now claim it, fall back exactly like the turnkey installer when another
  vhost already holds it, and also remove the `conf.d/default.conf` shipped by
  the nginx.org and RHEL packages — which beats `satom.conf` on the alphabetical
  parse order between files.
- `tests/test_tls_by_default.py` grew guards for the redirect itself: that each
  vhost author emits it on `:80`, that it is scoped to `location /` so the ACME
  challenge survives, that neither author hardcodes `default_server` on that
  listener, and that every host installer asks for the claim, self-corrects on
  a conflict and clears the packaged default site.
  Replaced by `SATOM_HTTPS_BIND` / `SATOM_REDIRECT_BIND`.
- The proxy has a **static address** in a pinned subnet: `TRUSTED_PROXIES`
  matches exact addresses, and container-to-container traffic arrives from the
  proxy's own address, not the bridge gateway. `satom-docker.sh` refuses to run
  when the two disagree — the failure is otherwise invisible, collapsing rate
  limiting into one bucket and recording the proxy as the actor in every audit
  entry.
- The container proxy claims `default_server` on both listeners and deletes the
  nginx image's own `default.conf`. Docker copies that file into the conf volume
  when the proxy container is *created*, before `tls-init` runs; the leftover
  then wins `:80` on alphabetical parse order and answers the nginx welcome page
  while `:443` works perfectly — a node with nothing red anywhere and a
  `http://` that has silently stopped redirecting. Found by testing the
  redirect, not by reading the file.
- `tests/test_tls_by_default.py` (35 tests) asserts that every install path
  provisions TLS **and that they provision the same TLS** — `Host $http_host`
  (never `$host`), `X-Forwarded-Proto https`, `client_max_body_size 400M`. Each
  of those was learned once, in production; a second install path is exactly
  where they get re-learned.

### Fixed — a container served over plain HTTP could sign nobody in (2026-08-31)

The development node `satom-node-1-dock` served the stack over plain HTTP while
the image runs `FLASK_ENV=production`, which marks session cookies `Secure`. A
browser withholds a `Secure` cookie from a plain-HTTP origin, so every login
POST arrived with no session, no CSRF token could match, and the CSRF handler
redirected back to the login form. **No password could be accepted**, the
account was never locked out (the password is never compared) and every health
signal — container healthy, `/healthz` 200, login page rendering — stayed green.

- **The node**: TLS terminated by nginx on the node itself with the fleet
  wildcard, the container republished to `127.0.0.1:8080`, `:80` redirecting to
  HTTPS so plain HTTP cannot re-create the trap, and `TRUSTED_PROXIES` set to
  the Docker bridge gateway — empty meant "trust nothing", which collapsed rate
  limiting into a single bucket shared by every user.
- **The message**: `app.extensions.insecure_session_transport()` distinguishes
  the two causes of a CSRF failure. On a plain-HTTP request with
  `SESSION_COOKIE_SECURE` on, the flash, the JSON error and the log now name
  the deployment problem instead of claiming the session expired — which is how
  an operator ends up retyping a correct password forever. The client's scheme
  is read from `X-Forwarded-Proto`, so a healthy TLS-offloading proxy (measured:
  the DMZ HAProxy in front of the production cluster) does not trip it.
- **`SESSION_COOKIE_SECURE` was NOT turned off.** Without TLS the cookie
  already travels in clear; disabling the flag hides the symptom and normalises
  an insecure configuration in an image that also runs in production.
- Documented in `docs/docker.md` ("TLS is not optional") and
  `deploy/docker/env.example`; guarded by `tests/test_insecure_transport.py`.

### Documentation — the container shape reaches the manual, which it had not (2026-08-31)

`docs/docker.md` was written with the packaging work and then reachable from
nothing. It was absent from `PUBLIC_DOCS`, and **absence from that list is the
opt-out**, so the page was published on no surface and no link pointed at it.
Meanwhile section 2 of `INSTALL.md` — the canonical answer to "how do I install
this" — named two ways when there were three, and the pages of the user guide
that describe Software Update (§22) and High Availability (§24) described
behaviour the container shape deliberately does not have, with nothing telling
the reader so.

- **Published**: `docker.md` joins the registry under *Deploy & operate*, and
  the generator emits `site/docs/docker.html` with the rest (33 pages, 0 leaks).
- **`INSTALL.md` §2.3 — Containers (Docker)**: the third shape stated where an
  operator chooses one, with the four renounced capabilities and their
  alternatives, the declared-not-detected runtime, the two-node production
  cluster and the checksum-verified offline image transfer.
- **`user-guide.md`**: §22 now says the update page is unavailable on a
  container install *and why*; §24 points at the container cluster, whose
  standby is a database replica rather than the other half of a balancer.
- **`README.md`**: the manual's own index and its install reading path list the
  page, so the map is complete again.

**New guard `tests/test_install_shapes.py` (11 tests).** Four documents state
the SIZE of the capability set in words and two reproduce its CONTENTS as a
table, while `app/runtime.py` owns the fact. Nothing failed when those drifted —
the sentences merely became false, which is how `Version: 1.0` survived four
releases. The guard reads the documents and compares against
`HOST_ONLY_CAPABILITIES`; every pattern carries a minimum count, because a regex
that matches nothing reports a perfect document it never inspected. Two
mutations of the guard itself were needed before it was honest: the counting
phrase is **hard-wrapped**, so an anchor spanning the line break matched
nothing, and a whole-file substring check for `docker.md` passed while the
authoritative index row was missing — the section-3 scope exists because of it.
**10/10 mutations bite.**

Also fixed: fifteen tracked files from the packaging round were left owned by
`root` in the working tree, including `app/runtime.py` and everything under
`deploy/docker/`. The application and the reconciler both run as `satom`; a
root-owned tracked file makes the checkout that deploys those very files fail.
The tree is back to zero root-owned tracked files.

### Packaging — a third installation shape: containers, with the host-only features removed rather than broken (2026-08-31)

SATOM had two installation shapes (full install, package-only). It now has a
third. The work that mattered was not the Dockerfile.

**SATOM is an appliance that administers its own host.** Measured on
satom-node-1: 21 `systemctl` call sites, 40 references to nginx, a root
`satom-updater.service` whose job is installing unit files, and fourteen
`satom-*` units. Packaging that without a decision produces the worst outcome
available — an image that boots, answers `/healthz` 200, and has four menu
entries that fail the first time somebody needs them.

So the container variant **renounces** four capabilities explicitly, in code:
in-place self-update, service control, certificate activation, and systemd unit
health. Each refuses with a message naming the alternative
(`docker compose restart`, "deploy a new image tag", "install the certificate
on the reverse proxy"). Everything else is unchanged.

- **The runtime is a declaration, not an inference** (`app/runtime.py`,
  `SATOM_RUNTIME=container` set by the image). `system_health.is_container()`
  already existed and would have been the obvious probe — and it returns
  **true on satom-node-1 and satom-node-2**, which are LXC containers.
  Autodetection would have disabled self-update on the two production nodes:
  the exact inverse of the intent. Only the literal value `container` counts,
  so a typo can never silently strip an appliance of its updater.
- **One image, three roles** (`SATOM_ROLE=web|scheduler|cron`). Three images
  would let the scheduler run code the web worker does not have, and that
  difference stays invisible until a scheduled action behaves differently from
  the same action fired by hand.
- **`scheduler` and `cron` are primary-only**, by the same looping
  `pg_is_in_recovery()` guard the host units use — promotion starts them with
  no external coordination, and two nodes never both fire an action. A double
  firmware-upgrade action means a double flash.
- **The metrics store publishes no port.** VictoriaMetrics has no
  authentication; on a host install the `127.0.0.1` bind is the only thing
  protecting the fleet's metrics. In the stack that job is done by the absence
  of a `ports:` entry, so the absence is asserted by a test. Its version is
  pinned to `deploy/metrics-store.env`, and a test fails if the two drift.
- **Production is a two-node cluster**: primary plus a streaming-replica
  standby carried as `backup` by the reverse proxy. The standby's entrypoint
  **refuses to rebuild a promoted node** — that node holds every write accepted
  since the failover, and a re-basebackup would discard exactly those, quietly,
  with a healthy container afterwards.
- `vm_store.base_url()` gained an environment fallback for the sidecar
  endpoint, ranked **below** the operator's `metrics.vm_url` setting. Above it,
  the settings field would have become silently ineffective on a container
  node — which is the failure that function's own docstring already records
  once.

Found by writing the tests, not by reading the code: a service-level
`environment:` **replaces** the mapping inherited through a YAML merge key
instead of merging into it, so giving `scheduler` its `SATOM_ROLE` had silently
dropped the database URI, the rate-limit URI and the metrics URL from that
container. It would have started, fallen back to the `127.0.0.1` values in
`.env`, connected to nothing, and logged normally.

Docs: `docs/docker.md`. Guards: `tests/test_container_runtime.py` (45 checks).

### Documentation — the manual stops naming a repository that was deleted (2026-08-30)

Publication was consolidated onto a single public mirror and the intermediate
one was retired. Nothing failed when the documentation kept describing the old
shape, which is exactly why it survived in three places at once: a stale
instruction does not break a build, it breaks the person following it.

- **`INSTALL.md` told operators to clone a repository that no longer exists**,
  in the install command and again under *Support*, and warned them to expect a
  credential prompt that the real default has never produced. The installer's
  own default has pointed at the public repository all along — the page was
  wrong, not the code — so an operator who trusted the page over the tool got a
  `404` in the middle of a maintenance window.
- **`release-pipeline.md` drew a destination that had been deleted** and named
  GitHub Pages as the public site, which is switched off for this project. It
  now states the two-repository premise outright, says why the third was
  retired (it was always pinned to the same commit as the public mirror, so it
  added a hop that could fail without adding a copy that could be restored
  from), and records that release assets are taken from the build output rather
  than from that mirror's package registry.
- **Stage 2 now documents what the PEM rule matches.** It used to fire on a bare
  header, so a `placeholder=` attribute and a fixture body of repeated `B`s
  aborted a publish exactly as a real key would; the scan runs over the whole
  history, so neutralising the files at `HEAD` unblocked nothing and the public
  repository sat frozen for twelve days. The header must now be followed by 40
  base64 characters within 200 bytes, and the narrowing ships with a generator
  that proves eight real key encodings still abort.
- **Stage 4 records the two guards that protect a published artefact**: a
  release refuses to carry asset filenames that disagree with `VERSION`, and
  every commit is stamped with an attributable identity. Both failures are
  invisible after the fact — the release is created, the files upload, and every
  step reports success.
- **User guide §26.4 says which remote belongs in the Repository card**, and what
  to do with a node still pointing at the retired one.

### Changed — Stored Assets arranges devices the way YOU arrange your bookmarks (2026-08-30)

`/adom-assets/` grouped devices by family and stopped there. The bookmarks rail
on the right of every page already nests the same devices by a per-user stack
of classification dimensions (`line › zone › department` until you change it),
and two arrangements of one estate is not a cosmetic difference: an operator
who knows their DMZ boxes live under *dmz* on the rail and finds them somewhere
else here concludes that one of the two pages is lying about the fleet.

- **The family stays the outermost level and your lens nests below it.** The
  heading names the whole order — *Product › Line › Zone › Department* — and
  links to the profile page where you change it. It is yours alone: two people
  reading one ADOM see different headings over identical rows, which is why the
  page says so instead of leaving it to be discovered.
- **`kind` is dropped from the nested part.** The family heading already IS
  `kind`; nesting it under itself gives every family one child named after the
  family — the chain of single-child folders the profile form refuses.
- **The chain is truncated exactly as the rail truncates it.** A device
  classified nowhere gets one `(unclassified)` bucket, not three; a device with
  no line but a real zone still gets `(unclassified) → dmz`, because that zone
  is a fact.
- **A bucket counts its whole subtree and draws only its own rows.** Folding
  never takes a number off the page, and a device that stops one level above
  its neighbours is still drawn.
- `(unclassified)` and `(no segment)` sort **last** at every level: a bracket
  sorts before every letter, so plain sorting would open each family with the
  bucket that says nothing about the fleet.
- **Firmware is grouped by family and by nothing else, and the card says so.**
  Line, zone and department describe a device; an image on a shelf has not been
  installed on anything.
- The **filter card no longer folds**. Every other card holds an answer, and
  folding an answer hides something the page is telling you; this one holds the
  question that decides which rows those answers describe.
- A fragment link to a section now opens it even when followed from the page
  you are already on (`hashchange`, not just first paint).

### Fixed — the bookmarks rail works in the ADC, FortiAnalyzer and FortiAuthenticator consoles (2026-08-30)

The rail reported *"Your session expired — reload the page to use bookmarks."*
in three of the five ADOMs. The session was fine.

- **`base.html` renders the rail into every page of every ADOM, but
  `bookmarks` was in none of the three per-ADOM allowlists**, so the product
  gate answered the rail's own `GET /bookmarks/panel` with a **redirect to the
  ADOM home**. `fetch` follows redirects, the answer carried no `X-SATOM-Panel`
  header, and the rail said the only thing it knew how to say. It is the fifth
  entry those three hand-kept copies have forgotten, so the fix is **one
  authority** — `CHROME_BPS`, consulted by the gate beside its always-allowed
  endpoints — and not a fourth copy.
- **Reachable is not visible.** Every row the panel serves still goes through
  `product_scope` / `visible_appliances`: each console reaches its own rail and
  keeps seeing only its own devices and its own bookmarks.
- **A routing bounce is no longer called an expiry.** Only an answer that
  actually came from the login page says the session expired; anything else
  names its own status and path, because "it did not work" is what made this
  report cost a browser session to diagnose.

### Changed — every Stored Assets section and family folds, and starts folded (2026-08-30)

`/adom-assets/` now opens with all four artefact cards, the filter card and
every device-family group **collapsed**. At fleet scale the expanded page is a
minute of scrolling; folded, it is an index you open where you need it.

- **Two levels.** Opening a card shows its family headers (`FortiWeb — 8
  device(s) · 12 backup file(s)`); opening a family shows its rows. A device's
  *Files* table stays a third, separate control and is not force-opened by
  *Expand all*.
- **The state is the set of OPEN ids**, stored per ADOM under
  `satom.assets.open.<adom>`. An empty set by default *is* "everything folded",
  with no first-run flag to keep in sync — and a stored closed-set later read as
  an open-set would expand exactly the sections the operator had folded.
- **Nothing that warns can be folded away.** The bundle card's "the backup
  server is a single point of failure for SATOM's own recovery" notice, the
  truncated-upload list and the unreachable-server banner all render outside the
  collapsible body.
- **A folded Filter card still names what it filters** (`filtered · type:
  fortiweb · state: never`). Otherwise a filtered URL and an unfiltered one look
  identical, and "3 devices" stops being a statement about the search box.
- Each header keeps its counts, so a closed card still says what it holds;
  `Expand all` / `Collapse all` sit in the page header; and a link to
  `#sec-backups`, `#sec-sot`, `#sec-firmware` or `#sec-satom` opens that section
  on arrival.
- The folded state is in the markup, and the rule that honours it carries the
  same CSP nonce as the toggle script, so the page can neither paint expanded
  and then fold itself, nor arrive folded with no way to open it.

### Changed — Stored Assets is one card per artefact, not one table with everything in it (2026-08-30)

`/adom-assets/` now splits into **1 · device config backups**, **2 ·
configuration SoT**, **3 · firmware images** and **4 · SATOM's own backup**,
with the filter bar lifted above all four.

- **The four are not copies of each other.** A backup is a file the appliance
  wrote and pushed; a SoT version is a snapshot SATOM recorded itself under its
  own retention; a firmware image flows *towards* the device; a bundle is the
  console backing up itself. One row carrying "21 backups" beside "11 versions"
  invited the reading that one was a copy of the other.
- **The backup-state filter narrows card 1 only, on purpose.** It grades the
  backup server, and a device that has never pushed a file can still hold a
  hundred recorded versions — filtering *never pushed* and then hiding those
  rows from the SoT card would hide exactly what was being looked for. The card
  says so with a badge and carries its own *showing N of M*. Family, free text
  and *hide de-registered* describe the device, so they narrow every card;
  `type=` narrows the firmware card too.
- **Firmware is grouped by family** in the same registry order as the device
  cards, so one family name means one thing across the page. An image with no
  family lands in `unassigned` rather than under a real appliance line.
- **SATOM's own bundles appear in Global only** — a bundle is a dump of every
  ADOM at once, so filing it under one would claim it belongs there. Each is
  badged `this node` and `backup server` independently, since only a bundle
  with both is redundant; having *only* one or *only* the other is called out,
  as is a name whose two copies disagree on size (a truncated upload). An
  unreadable inventory renders as an error, never as "no backups". Read-only:
  create, restore and retention stay on System Backup & Restore.
- Sections carry their own SoT counters, and a device with **no configuration
  history at all** is reported by name in its section and in a total, the same
  way *never pushed* already was on the backup side.

### Fixed — the bookmarks rail stopped working everywhere, twice over (2026-08-30)

Reported as *"the bookmarks tab does not work anywhere"*. Two defects, both of
which rendered perfectly and neither of which raised. The rail is
`data-turbo-permanent`, so both were **permanent for the rest of the session,
on every page**, until a full browser reload.

- **A 200 that was not the panel got painted as one.** The CSRF error handler
  answers a POST that does not declare itself an XHR with a *302 to the
  referring page*; `fetch` follows redirects, so the rail received a whole
  console page with `r.ok` true and pasted 60 KB of `<!DOCTYPE html>` into a
  300px column, killing every control in it. The trigger was ordinary: the
  rail's CSRF token is minted once per full page load and lives an hour, so
  the first click on any bookmark control an hour into a session did it —
  **expanding a folder was enough**, because that persists the open set.
  The rail now declares its fetches `X-Requested-With: XMLHttpRequest` (so the
  handler *refuses* instead of redirecting), the panel fragment identifies
  itself with `X-SATOM-Panel`, and nothing without that header is rendered
  into the panel. Every panel answer also hands back a fresh `X-CSRF-Token`
  that the rail adopts, so the token stops going stale under normal use.
- **The open/closed state lived on a `<body>` Turbo throws away.** `bm-open`
  is a class on `<body>`, which Turbo replaces on every visit, while the rail
  survives — and that survival is exactly why the one-shot restore never ran
  again (it sits below the `data-bm-wired` early return). The rail therefore
  shut itself on every navigation, and a navigation is what clicking a
  bookmark *is*. The state is now re-applied on `turbo:render`/`turbo:load`
  from a listener on `document`, which Turbo does not replace, and only on
  pages that actually carry the rail.
- A refused mutation can no longer die inside `r.json()` when the 400 is not
  JSON, and the panel's own GET says *"session expired — reload the page"*
  where the tree would have been instead of pasting a login form into it.
- 19 guards in `tests/test_bookmarks_session_expiry.py`; safeguards §149.

### Added — the operator console says what it is and under what licence (2026-08-30)

`satom` with no arguments now opens with a SATOM wordmark in ASCII blocks, the
version and node identity read from the node, `Made by VisionEBC`, and the full
Elastic License 2.0 declaration.

- Art is blocks of `#` only, so it is identical with `--ascii`, through a pipe
  and on a serial console — where Unicode blocks fold to garbage.
- Below 78 columns the banner collapses to its one-line header (the licence is
  fixed-width prose and would wrap); a **pipe** suppresses nothing, so
  redirected transcripts keep the declaration.
- All seven rows of the wordmark start in the same column. A two-column lead
  on the top row was applied on request and withdrawn the same day once it was
  seen in a real terminal: it hangs the top bars of S/A/T/O and the peaks of
  the M right of their own stems. `_ART_TOP_EXTRA` restores it in one edit and
  a guard pins the value, so it cannot drift back silently.
- `SATOM_CLI_NO_BANNER=1` restores the previous one-line header for runbooks.
- Ninth licence surface, guarded by `tests/test_cli_banner.py` against the same
  assertions as the site footer. The attribution reads `VisionEBC`; the
  copyright keeps the licensor's legal name `Vision EBC`.


### Fixed — three ADOMs could not reach the pages their own menus drew (2026-08-30)

Reported as *"only the Global and FortiWeb menus work — ADC, FortiAuth and
Analyzer do not"*. Three separate defects, none of which raised.

- **Four device ADOMs shared three session slots.** The selected-device slot was
  a hardcoded `if` chain matching `fortiadc` and `fortianalyzer` by name;
  **`fortiauthenticator` fell through to FortiWeb's slot**. Both directions were
  live: picking a FortiWeb device blanked the FortiAuthenticator console, whose
  entire menu then answered *"No FortiAuthenticator is selected"*, and picking
  the FAC device made a FortiAuthenticator the FortiWeb ADOM's implicit
  context — `/web/workspace/` opened `fac01`'s workspace. **The slot is now
  derived from the ADOM registry**, one per ADOM, with the three existing key
  names kept verbatim so open sessions keep their pick.
- **An ADOM holding exactly one appliance now uses it everywhere, not just on
  its dashboard.** `faz.index` and `fac.index` each carried their own
  `header_dev = current or fleet[0]` fallback, so the FortiAuthenticator front
  page rendered the live unit's firmware, CPU and licence counters while every
  menu page in the same ADOM said no device was selected. One authority
  (`device_context._sole_device`), and it is **read-only** — resolving the
  context never records a choice the operator did not make.
- **AI Advisor and Stored Assets are reachable from the ADC / FAZ / FAC
  consoles.** Both are drawn into every sidebar by a shared partial and neither
  was in the three per-ADOM allowlists, so the product gate redirected them to
  the ADOM home — a live-looking entry that goes nowhere, exactly what
  `scheduled_actions` did on 2026-08-10. The new guard walks **every link the
  sidebar renders in every ADOM** rather than naming the entry of the week.
  (`docs` also left those lists: that blueprint was deleted on 2026-08-02 and
  the string had been allowing nothing since.)

See `docs/safeguards.md` §147 and `docs/user-guide.md` §3.1.

### Fixed — Stored Assets showed one family in every ADOM, and one row per ADOM per device (2026-08-30)

- **The page now reads the ADOM of the request.** `_scope()` asked
  `branding.get_product(None)`, which falls through to the default product, so
  `/adom-assets/` rendered **FortiWeb in every ADOM including Global** —
  FortiADC, FortiAnalyzer and FortiAuthenticator devices appeared nowhere at
  all. It now reads `g.product`, resolved per request by the product gate.
- **One row per DEVICE, not per ADOM.** A FortiWeb in ADOM mode is one
  appliance row per ADOM with one flash partition and one `execute backup`, so
  its ADOM rows can never own a backup folder — they carried a permanent
  *never pushed* badge each (six of twelve on this fleet). They are folded onto
  the chassis and **their version counts, byte totals and any folder a sibling
  really pushes under are added, never dropped**; delete and download still
  address the folder each file is actually in.
- **The chassis is stored, and never guessed.** New `device_identity.chassis_slug`
  / `.adom`, resolved from the appliance row (via `appliance_name_parts`, only
  when `vdom` explains the `@` suffix), else from the hostname the device
  reported in its own snapshot, else itself — and a snapshot hostname is adopted
  only when it names a device of the same family that SATOM already knows.
  Stored because the appliance row is gone by the time anybody asks about a
  de-registered device.
- **The table is split into a section per device family**, in the order of the
  ADOM switcher, with an explicit **unassigned** section.
- **Server-side filter in the URL**: device type, backup state, free text over
  the name *and every former name* plus serial/host/model, and hide
  de-registered. An unrecognised value narrows nothing; the tiles always
  describe the whole ADOM, never the filter. See `docs/safeguards.md` §146.

### Fixed — the 500 page's Copy button can no longer fail in silence (2026-08-30)

- **A failed copy now stays on screen and names its reason.** The button flashed
  a ✗ for two seconds and then restored its label, which is indistinguishable
  from a button that does nothing — and it took the diagnosis with it. A failure
  now keeps the label, **selects the reference**, and shows a persistent line
  with the browser's own error name.
- **The legacy fallback moved back inside the click.** It was being called from
  the promise's rejection handler, where `document.execCommand('copy')` no
  longer has the click's transient activation — so it could only ever report a
  second failure. It now runs only for the non-secure-context case, inside the
  handler itself.
- **`writeText()` has a 1.5 s deadline.** A permission prompt that never appears
  used to leave the button silent for good.
- **The reference is click-to-select**, a path that depends on no clipboard API.
- Verified in a real Chromium over CDP with a *trusted* click (a synthetic
  `.click()` carries no user activation and would have proved nothing), on the
  byte-identical page and CSP header, across secure, non-secure and
  permission-denied origins. See `docs/safeguards.md` §145.

### Added — the change log gets a window, and it is archived before it leaves (2026-08-30)

- **Days of change log kept in the database**, a third field on every SoT policy
  card. Default **365**, per ADOM with the same three-deep resolution as the
  payload boxes, and `0` is a real value here meaning *never trim* (in the two
  payload boxes zero stays meaningless and reads as unset; a blank box is a
  third state again and restores the default).
- **The log is archived off-box before any of it is deleted.** Whole past
  calendar months are written to `<system_path>/sot-log/` on the backup server
  as one plain JSONL file per device and month — every field of every row, so
  it stands on its own and can be pulled straight off the server with `sftp`
  without restoring the database. Rows leave only after that file is **listed
  back at exactly the size that was written**; an unreachable server archives
  nothing, a file already on the server is never overwritten, and a month whose
  snapshots are not off-box yet is held whole.
- `offload()` (and the button, and `device_inspect`) now runs push → evacuate →
  archive, in that order: a month may only leave once its snapshots are
  off-box, and the evacuation is what puts them there.

### Changed

- **Per-ADOM SoT settings are gated on the ADOM being active.** An inactive
  device family no longer gets a retention card. An override written before it
  was switched off keeps resolving, so those are listed separately with their
  numbers and a **Clear the override** button rather than disappearing.
- **"Apply the payload policy now" / "Push and evacuate now" is now "Free space
  on this node now" / "Upload and free space now".** The card states in its
  first line that it does *not* discard history, names the two things it
  removes locally, and prints where the change-log archive lands and what the
  last run did. The old wording named the mechanism and left the consequence to
  be guessed.

### Added — the change log became permanent and the payload learned to leave (2026-08-30)

- **The Configuration SoT index is now kept forever, and `prune()` no longer
  deletes a single row.** The row *is* the change log — the list an operator
  walks back through to find the value a parameter used to have. Nothing failed
  before this: deleting rows was the documented behaviour, the page rendered,
  the suite was green. It became a data-loss defect the moment a one-day local
  policy was asked for, because the history would have gone inside a day while
  every byte sat safely on the backup server, unreachable, since `load()` and
  `diff()` only ever opened the local file. There is deliberately **no setting**
  to shorten the index.
- **Snapshot payload now leaves the node instead.** Two numbers govern it — the
  newest **N** versions and **D** days, a union, defaults **2** and **1** — and
  they are set **per ADOM**, three levels deep (ADOM → house → product default),
  with each card printing which level answered. A FortiAnalyzer snapshot is
  ~6 MB raw where a FortiWeb's is ~0.5 MB.
- **Confirm off-box, then delete — per blob, never per server.** Evacuation
  uploads first, lists the server, and removes locally only what that listing
  confirms; a listing that fails yields an empty set, so an unreachable server
  evacuates nothing. **An evacuated version still opens**: `load()` and `diff()`
  fetch the blob back on demand and verify it hashes to the name it was stored
  under before adopting it.
- **Devices now carry their serial number**, read off the *same* status call the
  firmware probe already makes — every reader was already extracting it to guess
  `hw_type` and discarding it, so no new device call exists anywhere.
- **New `device_identity` table, deliberately with no foreign key**, so the
  record of who a device is — and *was* — outlives de-registration. Everything
  else hanging off `appliances.id` is `ON DELETE CASCADE`, which is exactly
  backwards for the question asked about a file on the backup server: whose is
  this? One serial with three names is one box renamed twice; on FortiWeb the
  chassis and its per-ADOM rows share one serial, which is why a backup from
  that chassis covers all of them.
- **New page: `Administration → Stored Assets`**, in every ADOM. Per device:
  backups on the server with a **days-since-last-push** grade, SoT versions
  split local vs off-box, firmware, identity and every earlier name — including
  **retired devices** and two buckets that were previously invisible: folders on
  the server no device claims, and configuration history with no identity row.
  **"Never pushed" is its own state**, not another shade of stale. An
  unreachable server reads as *unknown*, never as *no backups*. Deleting a
  backup needs an exact filename and a typed **DELETE**, and is audited whether
  or not it succeeds; there is no bulk delete.

### Added — system bundles live off the node they back up (2026-08-30)

- **Backup Server → Local bundle retention**, default **0**: after a verified
  upload the node keeps none. A bundle is SATOM's own backup, so the one place
  it is worth least is beside the thing it backs up. `0` is a **real value**
  here rather than "unset", which is the convention everywhere else in Settings.
- A local bundle is removed **only when the server holds it at the same size** —
  name alone would accept a truncated upload. **Download and restore fetch an
  off-box bundle back automatically**, so the policy cannot make a bundle
  unrestorable. The page lists the union of local and off-box copies;
  `/healthz/backups` and the primary/standby comparison stay **local-only** on
  purpose.

### Fixed (2026-08-30)

- `data/system_backups` and `data/backups` were the last on-disk stores not
  isolated from the production tree in tests. They had been write-only, so the
  litter was tolerable; the day local eviction started **deleting** there, an
  un-isolated suite could have destroyed real bundles. Both now honour
  `SATOM_BACKUPS_DIR` / `SATOM_VAULT_DIR`, set by `conftest`.
- `evacuate()` derived its retention rule twice. Two authors of one rule mean
  breaking either changes nothing observable, so no test could tell one intact
  layer from two — refactored to a single authority.

### Added — the system bundle says when, not only where (2026-08-29)

- **Backup Server → System bundle schedule**: new card next to the three paths.
  *System bundles path* stated where this node's own backups land and nothing
  about when they are written; the hour lived only in the Automation list, under
  an action name. The field is a **daily wall-clock time**, with the console's
  **timezone printed beside it** — an hour with no zone is the ambiguity that
  had nightly jobs drifting an hour twice a year.
- It writes the **`system_backup` schedule row**, not a settings key of its own,
  and **recomputes `next_run`** in that timezone, so a new hour takes effect
  tonight and the Settings and Automation pages cannot disagree about the same
  row. The pane names the driving action, says loudly when it is **disabled**,
  and prints last and next run.
- **A bundle scheduled some other way is reported and locked, never converted**,
  and no second nightly run is created: unlike a SoT harvest, a duplicate bundle
  costs a full copy each. If nothing is scheduled, saving creates it. An
  unreadable submit keeps the hour already in force rather than falling back to
  midnight.

### Changed — the repository form hides, the SoT gets a cadence, the paths explain themselves (2026-08-29)

- **Software Update Repository**: the *Configure Repository* card is gone as a
  standalone card. Its form now lives **inside** the Repository card behind an
  **Edit** button, and opens by itself on exactly one kind of node — one with no
  `origin` at all, i.e. never registered at installation, which is also told so
  in as many words. Previously three boxes that render *empty* until an async
  fetch fills them sat permanently open, one submit away from writing blanks
  over a working remote. Whether a repository exists is decided server-side on
  the first render.
- **Configuration SoT**: new **Refresh frequency** field — how often appliances
  are harvested, in minutes. Default **60**, clamped to **5 – 10080**; `0`,
  blank or garbage means *unset*, never "never". It writes the `device_sync`
  schedule row rather than a settings key of its own (two authors of one cadence
  is how a panel ends up showing an interval the scheduler never fires on) and
  **recomputes `next_run`**, so a shortened interval applies now instead of
  after the fire that was already pending. A wall-clock harvest is reported, not
  converted; if no harvest exists at all, saving creates one fleet-wide.
- **Backup Server**: each of the three paths carries a **“?”** saying what lands
  in it and **who writes it** — the distinction that decides whose fault an
  empty folder is. Text lives in `title`, so it degrades to the browser's native
  tooltip.

### Changed — one Settings tab held three subjects; now each has its own (2026-08-29)

`Settings → SoT & Backup` carried a firmware git URL, the SFTP credentials of
the backup box, and nothing about appliance configuration — under a heading
whose first word names an authority. Nothing failed; the word simply covered
more than it was true of.

- **Added** the **Source of Truth & Backup** group, holding two entries:
  **Configuration SoT** (`#tab-sot`) and **Backup Server** (`#tab-backupsrv`).
  Each pane states what it is *not* and links to the other two.
- **Renamed** the `Git` panel to **Software Update Repository**. It is the repo
  this node downloads its own *code* from; it has never held a device
  configuration or a firmware image, and "Git" is a tool name that
  distinguished it from neither of the others. The target `#tab-git` is
  unchanged, so every deep link and manual reference still lands.
- **Removed** `sot.firmware_repo_url` / `sot.firmware_repo_branch`. Every
  consumer was presentational — the URL was rendered as a link and nothing ever
  read the manifest — while the repo they named declared `firmwares: []` with
  two images loaded. **Firmware is not a source of truth in this product**; its
  authority is `firmware_images` + `data/firmware/` (Infrastructure →
  Firmware), which is indexed, hashed and backed up. The System Backup page no
  longer labels the firmware folder a "manifest SoT".
- **Fixed** the SoT retention settings, which had never worked: `sot_store`
  read them through `settings_store.get`, **a function this product has never
  defined**, so every harvest raised `AttributeError` inside a blanket `except`
  and silently used the hard-coded 60/180. They are now read through
  `settings_store.sot_retention()` and are editable on the Configuration SoT
  pane. A stored `0` or a malformed value means *unset*, not *keep nothing*.
- **Fixed** two panes sharing one POST: saving a retention number rewrote the
  SFTP credentials and could redirect to the other pane. `POST /settings/sot`
  and `POST /settings/backup-server` now own one pane each and return to it.
  (`/settings/sot-backup/test` moved to `/settings/backup-server/test`.)
- **Fixed** the backup server's **system bundles path**, which the save read
  with a default while the form did not offer it — so every submit quietly
  rewrote a customised value back to `/system`. All three paths are on the form.
- **Changed** the pane cross-reference hook from `data-theme-jump` (bound
  inside the Appearance block, which returns early when the theme form is
  absent) to a delegated `data-tab-jump`. It clicks the menu button rather than
  showing the pane, so the lateral menu's selection follows.
- Guards: `tests/test_sot_settings_split.py` (22), safeguards §140.
  Manual §26 rewritten — §26.4 is the update repository, §26.5 the
  Configuration SoT, §26.5b the Backup Server.


### Added — the SPO wizard lets the operator choose the backend (2026-08-28)

The registry gained N rows the same day, and the wizard still resolved in
silence: whichever row the declared scopes happened to select did the work,
and the page never showed the list.

- **Added** an **IPAM backend** and a **DNS backend** selector to
  `Workspace → New Server Policy`. Both default to **Auto**, which is
  byte-for-byte the previous behaviour, so an install that never picks
  anything is unchanged. Each option carries the provider and the declared
  scope, because a name is not what decides which backend answers.
- **Added** `resolver.choose(role, query, backend_id)` — the single author of
  "which backend", pick or no pick. A pick is **validated, not trusted**: the
  row must exist, be enabled, carry the role and claim the query, and each
  failure has its own code (`backend_unknown`, `backend_disabled`,
  `backend_wrong_role`, `backend_out_of_scope`) because each has a different
  fix.
- **Changed** an invalid pick is **refused, never downgraded to Auto**. A
  fallback would run the work on a backend nobody named while the page still
  showed the one that was chosen.
- **Changed** `apply_plan` acts on the backend ids the **plan recorded**
  instead of resolving a second time — the registry is editable between
  Preview and Apply, and a second answer could send the address and the record
  to systems the summary never named. `allocate_address` and `create_record`
  gained a validated `backend_id`.
- **Added** two blockers, `ipam_backend_rejected` / `dns_backend_rejected`,
  kept apart from the scope-level `*_not_resolved`: one sends the operator to
  the row they named, the other to the scope rules.
- **Added** warnings when a chosen backend cannot do anything (IPAM picked
  with the reserve box off; DNS picked with no hostname). A control that
  silently does nothing reads as a control that worked.
- **Fixed** `resolve_ipam` lowered the pool query while `split_list`
  deliberately preserved the declaration, so a pool named `Prod-DMZ` could
  never be matched. Pool matching now has one author, `pool_matches`, exact
  and case-preserving on both sides. Zones still fold case; the asymmetry is
  the point.
- See safeguards §137.


### Added — N DNS/IPAM backends with optional roles and scopes (2026-08-28)

`Settings → DNS Records` was one global provider. It is now a registry: add,
edit, enable/disable, test and delete as many backends as the install needs,
each declaring which of the two jobs it does and which zones / pools it serves.

- **Added** the `dns_backends` table (`app/models_dnsbackend.py`): name,
  provider, **roles** (IPAM / DNS, both on by default), **scope** (zones and
  pools, empty = catch-all), priority, encrypted secret, last-test outcome.
- **Added** `services/dns_providers/resolver.py` — the single author of "which
  backend answers this". Most specific scope wins; priority breaks a tie
  between equals; **an exact tie is refused and names the candidates** rather
  than being broken by row order.
- **Added** roles are validated against a static per-provider maximum:
  `role_dns` is refused on phpIPAM (no record CRUD in any install) and allowed
  on NetBox (netbox-dns may be present — the live probe decides). See
  safeguards §136.
- **Added** `provision_runs.ip_backend_id` / `.dns_backend_id`: rollback
  releases and deletes against the backend that ACTED, and refuses rather than
  redirecting when that backend is gone. Nullable, no backfill.
- **Added** a backend selector in the **+DNS Records** modal, shown only when
  there is a genuine choice; a stale or unknown id is refused, never silently
  replaced.
- **Changed** `capabilities()` split into `ipam_capabilities()` /
  `dns_capabilities()` / `capabilities_of(row)`. With roles, "can something
  reserve an address" and "can something publish a name" are different
  questions with different answers.
- **Changed** the provisioning runner and the SPO wizard now distinguish *no
  DDI configured* (a supported deployment — warn, keep going) from *no backend
  claims this name* and *two claim it equally* (misconfiguration — block).
  New blocker codes `ipam_not_resolved`, `dns_not_resolved`,
  `ipam_unreachable`, `dns_unreachable`.
- **Added** the resolver's own three answers are **never folded** into
  one: `NO_BACKEND` (nothing registered), `NO_MATCH` (no backend claims
  this name) and `AMBIGUOUS` (two claim it equally). The first only
  **warns** — an install with no DDI is supported; the other two
  **block**, because a run that proceeds past either one publishes into
  a zone or a pool nobody chose.
- **Migration** the old `dnsrecords.*` settings are folded into one **unscoped**
  row on first boot, keeping the encrypted secret and the old `default_zone` /
  `default_pool` as defaults — not as a scope, which would have narrowed a
  working install at upgrade time. One-shot, guarded by its own flag so
  deleting every backend does not resurrect it.
- **Added** `save_backend` **refuses** a `default_zone` / `default_pool`
  that falls outside the row's own declared scope, and writes nothing
  when it refuses. The two contradict each other: the resolver would
  route that zone away from the very backend about to write into it.
  Refused, not silently rewritten — an operator who typed both meant
  both.
- **Added** `tests/test_dns_backends.py` (54 guards) and the §130 guards moved
  onto the new seam.

### Changed — a network segment is ONE row per network (2026-08-27)

Reported as "two departments can share a network, but in the SPO wizard I
cannot see the department and the entries repeat". The repetition was the
visible half. The invisible half: three separate resolvers indexed segments by
name and **disagreed** about which of two same-named rows won, so a plan could
describe one row's network while allocating from the other's CIDR — silently.

- **Changed** a segment now carries `departments` (a list) instead of a single
  `department`. `cidr`/`interface`/`gateway` are properties of the network, so
  a network two departments share is one row naming both. Blobs written before
  this read through unchanged.
- **Added** `save_segments` refuses duplicate segment names, and writes nothing
  when it refuses. Exact match, not case-folded — see safeguards §135.
- **Added** `line_plan` blocks on a duplicated segment name instead of picking.
- **Added** a Department control on the SPO wizard that NARROWS the segment
  choice, enforced server-side; the segment options now print the departments
  they serve, and the plan summary names the one being built for.
- **Changed** one indexer (`line_profiles.index_by_name`) and one segments-form
  parser (`views._segments_form`) replace three and two respectively.
- **Added** `scripts/migrate_segment_departments.py` — folds per-department
  rows into one row per network; refuses to merge rows that disagree.
- 47 guards in `tests/test_segment_departments.py`, 36/36 mutations killed.


### Fixed — the SPO wizard's script was blocked by the CSP (2026-08-27)

The wizard's Segment dropdown stayed empty however many network segments a line
had, and Preview and Apply did nothing. The data was always there — the page
shipped the segments in its `PLANS` payload — but the single inline `<script>`
that is the wizard's whole UI carried no `nonce`, and the app serves
`script-src-elem` with a nonce and no `'unsafe-inline'`, so the browser dropped
it. No control on that page had ever worked.

- **Fixed** `workspace/spo_wizard.html`: the block carries the CSP nonce.
- **Fixed** `artifacts/object.html`: same defect on an inline `<style>`
  (`style-src-elem` is nonce-gated too), found by sweeping the template tree —
  the artifacts editor/viewer had been rendering unstyled.
- **Added** a guard that renders the wizard and asserts every inline block
  carries the nonce **the response actually served**, so a page that loses its
  header fails too. `tests/test_csp_nonce.py` already covered the class and was
  simply not run when the page was added (see `docs/safeguards.md` §134).

### New Server Policy from a line — one wizard, and a failure that cleans up after itself (2026-08-27)

The last piece: pick a line, and its profile supplies the network, the
certificate class and the Web Protection Profile. IPAM reserves the VIP, DNS
publishes the name, the CA issues the certificate and the device gets the
objects — in that order, with a preview that writes nowhere and a failure that
undoes what it took.

- **Added** `/web/workspace/<id>/spo-wizard` (linked from the policies page,
  beside "New Server Policy") and `services.spo_wizard`.
- **Plan first.** `build_plan` writes nothing and returns every reason the run
  cannot proceed, including a **live name-collision check** against the device
  — a run that would die after reserving an address is worse than one that
  never started. An unreachable device is itself a blocker, not an assumption
  that the box is empty.
- **A blocked plan is never applied**, in dry run or not. Letting one "just
  preview" is how a blocker becomes advisory.
- **Compensation is driven by recorded facts.** A DNS failure releases the
  address *by its handle*, and only if IPAM gave it to us — a hand-typed VIP
  is not ours to hand back. A device failure removes the record we created and
  releases the address we took.
- **What is NOT undone is named, never silently done.** An issued certificate
  is reported and **not revoked**: revocation is destructive and irreversible,
  and a certificate that exists is not harmful. Objects already written to the
  device are listed rather than deleted, because deleting one a human may
  already have bound elsewhere is a destructive guess. The report keeps
  "undone" and "left behind" as separate lists.
- **It refuses to guess.** A segment the line does not receive is refused (the
  wrong-network failure this whole feature exists to prevent). Several
  segments must be chosen, not auto-picked. A blank hostname means *do not
  publish*, and does not quietly become the web address. A read-only DNS
  backend plus a requested hostname is a refusal, not a step reporting success
  (§130's rule, in a new place).
- **Bug found by its own guard:** the first version used invented naming keys
  (`policy`/`vserver`/`pool`) where `services.naming` emits `server_policy` /
  `virtual_server` / `server_pool`. Every lookup returned `None`, every object
  would have been created with an **empty name**, and the collision check
  silently did nothing — with no crash anywhere. There is now a blocker for an
  empty rendered name and a guard pinning the keys to what `naming` emits.
- Guards: `tests/test_spo_wizard.py` (37), 31 mutations, safeguards §133.


### Line Profiles — a line's networks become a declaration, not a string match (2026-08-27)

"Which networks does this line receive?" was answered by matching the line name
against `segments[].line`. Nothing declared that relationship, so nothing could
be wrong about it — and nothing could be right about it either. A segment typed
differently simply stopped matching, and the consumer saw a line with no
networks, which is indistinguishable from a line that legitimately has none.

Survivable while the answer only colours a page. Not survivable once it picks
the network a **production server policy** is built on: the policy is created
perfectly, on the wrong segment, and nothing raises.

- **Added** `line_profiles` (new page under Administrator, admin-only): per
  classification line, the segments it receives, its certificate class, its
  Web Protection Profile template and an optional IPAM pool override.
- **Added** `services.line_profiles.line_plan` — the **only** place either
  answer is derived. A plan is labelled `declared` or `inferred`, and the two
  are never blended: a line nobody has declared still gets the old string
  match, but it says so, and a caller about to change the world must treat
  that as a question.
- A **declaration that stops resolving is a problem, not a shorter list**. A
  profile naming a segment that has since been renamed reports
  `missing_segment` and blocks; it does **not** quietly fall back to the guess,
  because that would hide the breakage behind the very answer the operator
  overrode.
- **Approval is checked when the template is USED**, not frozen when the
  profile was saved: a WPP template approved on Monday and rejected on Tuesday
  stops being instantiable on Tuesday. A template from another product blocks
  too.
- A blank certificate class means **not decided** and is reported. `server`
  would be a plausible guess; guessing is how a client-auth line gets a
  server-only certificate. Likewise `pool_for` returns empty rather than
  reaching for the provider's fleet-wide default pool.
- **Changed** `classification_ops` to treat a profile as a **reference**: it is
  counted in `usage()` (so deleting a line has to say what happens to it) and
  moved on rename. Clearing a line deletes its profile and reports that;
  reassigning onto a line that already has one is refused rather than silently
  merged, since (product, line) is unique and picking one would make a line
  quietly hand out a different set of networks.
- Guards: `tests/test_line_profiles.py` (34), 26 mutations, safeguards §132.


### The clone only adds what is missing (2026-08-27)

Ported from the standalone SATOM Policy Clone 1.27.0. The web clone had the
same two write paths INTO an object the destination already owns, and only one
of them was under an operator's control:

- `update` — a row colliding on its unique key was **rewritten**, governed by
  `reconcile_rows` (default ON).
- `create` — a row the source has and the destination does not was **appended
  to the live object**, labelled *"missing under an existing parent —
  recreating"*, governed by nothing at all.

The append is the dangerous one precisely because it reads as housekeeping. A
server pool that GAINS a real server is serving traffic it was not serving a
minute ago — as modified as a pool whose member was rewritten. A mode that only
closed the rewrite would have left the pool changed, and reported green.

- **Added** `additive_only`: the unit of *"the destination already has this"*
  moves from the ROW to the OBJECT. An object the destination lacks is still
  created whole, with all of its rows; an object it already has is left exactly
  as it is.
- **Added** the status `untouched` — amber in the report, its own mark (`/`) in
  the plan text, **never folded into `exists`**: "the destination has this row"
  and "the destination does NOT have it and we chose not to add it" are opposite
  facts, and only one of them leaves the operator something to do.
- **Added** a checkbox on the clone/migrate dialog, **default ON**; changing it
  invalidates the preview, because the plan on screen was classified with the
  value that was set when Analyse ran.
- **Added** the cutover gate: a migration whose copy held rows back leaves the
  **source ENABLED**, on the same reasoning already used for a file-backed
  object whose bytes never arrived — a migration claims the two are
  interchangeable, and a knowingly short copy is not.
- **Refuses** additive mode together with *"new, compare and decide"*, before
  any device is read: the second exists to change a profile the destination
  already serves, and the first promises not to.
- Defaults **ON at the HTTP layer** and **OFF in `policy_ops`**. The
  operator-facing surface is where the safe posture belongs; the engine has
  library callers whose deliveries must keep completing.
- 25 guards (`tests/test_clone_additive.py`), 22/22 mutations killed by the
  guard each one names. `docs/safeguards.md` §138.


### The workspace identifies a box by the name it calls itself (2026-08-27)

The workspace chrome printed the management address where it identifies the
appliance, while the breadcrumb above it printed a name. Neither was the
DEVICE's own hostname.

- **Added** `appliances.device_hostname` and `device_hostname_at`, filled from
  the **same status call `firmware_probe` already makes** — FortiWeb answers
  `hostName` (measured on fortiweb12/13). No second request: "exactly one
  status call per appliance" is what makes that module safe to expose on
  `/api/v1`.
- **Added** `display_host` / `host_title` as single authors for what the chrome
  prints and how it qualifies it. Three templates deciding this for themselves
  is how the identifier and the breadcrumb came to disagree.
- **Changed** `workspace/policies.html`, `browse.html` and `index.html` to
  print the hostname, falling back to the address when none was ever observed.
- The hostname timestamp is stamped **only when a name actually came back**,
  and a later silent answer does not erase a known one. This is not
  hypothetical: **FortiAuthenticator's status payload contains no hostname
  field at all** (measured on fac01), so a single shared
  `firmware_checked_at` would attest a reading that never happened. `fac01`
  correctly keeps showing its address.
- An **ADOM row** answers with the CHASSIS hostname, which is qualified in the
  tooltip rather than rewritten. The qualification keys on the operator having
  named the row `<device>@<adom>` — **not** on `vdom` being set, because every
  FortiWeb carries `vdom='root'` whether or not ADOM mode is in use. The first
  version got this wrong and labelled two ordinary devices as shared chassis;
  it was caught rendering against the live fleet, not by a test.
- Guards: `tests/test_device_hostname.py` (20), 21 mutations, safeguards §131.


### IPAM allocation exists now, and the DNS step stopped lying (2026-08-27)

`provision_runner` imported four functions that had never been written —
`allocate_address`, `release_address`, `create_record`, `delete_record` — each
inside `try: ... except ImportError`. Nothing raised, nothing logged, and the
two steps reported the opposite of the truth:

- ticking **"allocate from IPAM"** always failed, blaming the operator's
  provider (*"no DNS/IPAM provider exposes address allocation"*) on an
  installation where one was configured and healthy;
- the **DNS step always returned OK** with *"no DNS provider configured"* even
  when a provider was configured. A provisioning run could finish green having
  published no record at all.

- **Added** address allocation to the provider abstraction: `Capabilities`
  grew `can_allocate` / `needs_pool`, and a new `Address` record carries the
  provider-native reservation handle. `can_allocate` is **deliberately
  separate** from `can_write`: phpIPAM and plugin-less NetBox are address pools
  that cannot publish a name, and folding the two into one flag is what let
  "this backend can reserve an address" imply "this backend will publish the
  hostname".
- **Added** `allocate_address` / `release_address` for **EfficientIP
  SOLIDserver** (`ip_block_subnet_list` -> `ip_find_free_address` -> `ip_add`,
  released by `ip_id`), **phpIPAM** (`POST /addresses/first_free/`, released by
  address id) and **NetBox core** (`POST /prefixes/{id}/available-ips/`,
  released by ip-address id). A **Default IPAM pool** field was added to all
  three provider forms in Settings -> DNS Records.
- **Added** module-level `capabilities()`. Whether a missing provider is fatal
  is the caller's judgement, so "not configured" is now **raised**, never
  returned as a value that looks like a successful write — and the two are
  told apart by asking, not by catching an exception.
- **Changed** the DNS step to three outcomes instead of two. No provider is
  still a pass, but the detail says in words nobody can misread that the name
  was **not** published; a provider that *cannot write records* is now a
  **failure**, because answering "fine" to a requested hostname the backend
  will never publish is the same lie in a new place.
- **Changed** rollback to release against the **recorded handle**, not the
  address string. Between the reservation and the rollback the pool may have
  legitimately given that address to somebody else, and a string-keyed release
  frees their entry. New `provision_runs.ip_ref` / `ip_pool` columns, added by
  the boot migration (nullable, no backfill: a run that predates them really
  did take its address without a handle).
- **Changed** netmask arithmetic to a single author in `dns_providers.base`,
  and it refuses to guess: a subnet size that is not a power of two yields no
  prefix rather than a fabricated mask, and NetBox's absent gateway comes back
  empty rather than as `.1`. Both are written into a real appliance's default
  route at first boot.
- Guards: `tests/test_ipam_allocation.py` (63), 29 mutations, safeguards §130.

**Still UNVERIFIED end-to-end**: there is no SOLIDserver, phpIPAM or NetBox in
the fleet, so the wire shapes are exercised against `httpx.MockTransport`
built from each vendor's documented API — not against an appliance.


### WAF audit against a live appliance (2026-08-27)

The custom-signature catalogue added in Tanda 0 was carried from the admin
guide. Read off a live FortiWeb 7.6.8 it was wrong in five places, and every
one of them failed the same way: authorable in the UI, refused by the box with
an opaque `-651` at deploy time.

- **Fixed** the meet-condition shape. The device's fields are `expression`
  (the only mandatory one), `operator`, `request-target`, `response-target`
  and `case-sensitive` — not the guide's dialog labels. `target` was one field
  where the box has two, split by the parent rule's Direction.
- **Fixed** the operator tokens: `EQ`/`NE`/`GT`/`LT`/`RE`, not the spelled-out
  words.
- **Fixed** the action set. It is DIRECTION-DEPENDENT: 7 actions for a request
  rule, 9 for a response rule. Three the guide omits are real
  (`client-id-block-period`, `deny_no_log`, `redirect`) and the erase pair is
  response-only — enforced rather than merely listed.
- **Fixed** `severity`: the token is `Info`; "Informative" is the device's
  description of it.
- **Added** the JSON Schema name rule. Measured: a `.json`/`.txt`/`.schema`
  suffix is refused with `-61`, the bare name uploads and reads back
  byte-identical. This is the INVERSE of the OpenAPI rule (`.json`/`.yaml`
  required, `-20007` otherwise) — the two are now a table, and the other four
  file kinds were measured to accept any name, so their silence is a result.
- **Added** a write-path gate. `plan_injection` now returns `invalid` for a
  value the device's own enum does not contain, instead of letting it reach
  the appliance. Deliberately narrower than `validate_payload`: required and
  format rules stay in the authoring form, because enforcing them at deploy
  would turn carve-outs authored before a rule existed into errors on the push
  to a second appliance.
- **Fixed** a stray `@bp.route('/<id>/detect')` decorator that had stacked
  onto `clone_for_policy`, so posting to the detect endpoint ran the
  clone-and-rebind planner and returned a payload with no `found` key. The
  detect button had been silently dead.
- **Guards**: `tests/test_wire_shapes.py` (23) and
  `tests/test_mutation_survivors.py` (3, closing mutations that survived the
  previous harness: delete-version ordering, restorable vs a live lineage, and
  a deploy destination outside the visible set).


### WAF — the fleet view leaves the building: one ZIP, the formats you tick

- **New export panel on all five `Fleet -> WAF` pages** and endpoint
  `GET /waf/export`. Tick the contents (overview figures & charts, server
  policies, protection profiles, coverage, artifacts, exceptions with their
  profiles) and the formats (CSV, Excel `.xlsx`, PDF with the charts drawn in);
  you get one ZIP with exactly that. The selection lives in the URL, so a
  bundle is bookmarkable and a support request can quote the link that made a
  file.
- **Exceptions become fleet-visible for the first time.** `/exceptions` is
  pinned to one device; the export joins every authored carve-out in the
  visible fleet to the profile it names — is that profile in the snapshot, how
  many server policies bind it (a WPP is usually SHARED, so that number is the
  blast radius), are the policies it was authored for still there — and carries
  its payload, so an export can be used to re-author one.
- **Provenance travels with the data.** Every page here carries a
  scope-and-freshness banner because its figures are only as fresh as the last
  harvest; a spreadsheet in someone's mail has none. So `MANIFEST.txt`, the
  workbook's FIRST sheet and the PDF's first page all carry the same block from
  one `provenance()` call: when, by whom, how many scopes are covered, how many
  actually reported, and the stale and never-harvested ones BY NAME.
- **Charts travel as their series, not only as pictures.** The PDF draws them
  server-side (no browser, no canvas capture — this product installs into
  isolated networks); the CSV and the workbook carry every chart's
  (label, value) rows from the SAME `ChartSpec`, so the drawing and the numbers
  printed beside it cannot disagree.
- **The bundle is always the WHOLE visible fleet.** The per-table CSV link is
  the one that exports the rows you filtered, and says so. A ZIP that also
  narrowed — invisibly, because nobody can see the filter bar the file came
  from — is the safeguards §119 drift with a longer fuse.
- **Nothing ticked is not an empty export**: the panel flashes a message and
  returns you to the page. A zero-content ZIP downloads perfectly happily and
  reads as "the fleet had nothing", which is a claim about the estate.
- **`services/pdf_kit`** — the chart and table flowables move out of
  `db_reports` so both PDF producers render through the same code instead of a
  copy of it. The palette stays a parameter: DB reports keep the fleet blue,
  the WAF export uses the `.fw-badge-*` set calibrated against white (§9m).

### WAF — the artifacts the estate needs, and the ones it does not have

- **New page `Fleet -> WAF -> Artifacts`** (`/waf/artifacts`, feed
  `/waf/api/artifacts.json`): every file-backed WAF object (XML Schema, DTD,
  WSDL, OpenAPI, gRPC IDL, JSON Schema, Lua) the visible estate REFERENCES or
  HOLDS, in one table, with six charts, per-type and per-scope breakdowns and a
  CSV that carries exactly the filtered rows. `/artifacts/*` stays pinned to
  the session's (device, ADOM) — that is deliberate and guarded — which left
  the fleet question with no home at all.
- **Demand against supply, in one row per (scope, object).** The four verdicts
  are unchanged and now have ONE author,
  `services.artifact_refs.verdict_of`, shared with `device_audit` and
  `artifact_stats.scope_stats`: the expression used to be copied into all three
  under a comment promising they were identical.
- **Two states that are NOT verdicts.** A stored copy no walked policy names is
  an `orphan` — there is no need behind it, and folding it into "held" would
  inflate the share of the estate that is ready to move with copies nobody is
  waiting for. The library-wide bucket gets its own rows and reports how many
  scopes resolve to it, which is the blast radius of editing that one file.
- **A `borrowed` row served by the LIBRARY gets its own sentence.** `resolve()`
  prefers the library over any other appliance, so "a deliberate shared copy"
  and "whichever box happens to hold the name" are different branches; the
  library-backed count is published beside `borrowed` rather than folded into
  it, because reading N borrowed as "N guesses" overstates the risk by exactly
  that number.
- **EMPTY is a flag, not a state.** A zero-byte newest version is `ok` for
  every "do we have it?" check in the codebase and configures nothing; it is
  counted, badged and filterable here. Emptiness is decided on byte count
  alone, the same rule as `/artifacts/inventory` — decompressing every blob on
  a page that lists the whole estate is not a trade this page can make.
- **The page's blind spot is a NUMBER.** The configuration snapshot knows how
  many server policies a scope has; the sweep knows how many it walked. The
  difference (`never walked`) is printed per scope and fleet-wide, so a
  migration plan copied off this page does not silently inherit it. A scope
  with no snapshot reports `-` — unknown, never zero — and is excluded from the
  fleet figure.
- **Absence is not zero, again.** A scope with no scan row at all is `never
  swept` and stays out of the denominators: "nobody looked" and "we looked and
  it carries nothing" are the two answers this subsystem exists to keep apart.
- `artifact_stats.fleet_stats` accepts a preloaded `(refs, scans, stored)`
  triple so a page that already read those tables does not scan them twice.

### WAF — a fleet-wide inventory, its statistics and its charts

- **New area `Fleet -> WAF`, four pages over ONE universe.** `/waf/` (overview:
  KPIs, six charts, freshness), `/waf/inventory` (every server policy in the
  visible fleet, filterable, CSV), `/waf/profiles` (every web protection
  profile, its usage and its gaps, CSV) and `/waf/coverage` (protection x
  device/ADOM matrix, CSV). `/waf/api/summary.json` serves the chart payload,
  so the figures on the page and the figures in the charts have ONE author.
- **It reads the source-of-truth store, not the appliances.** Rendering these
  pages contacts no device. The measurement that forced the metrics rewrite on
  2026-08-05 applies unchanged: at the target fleet (60 FortiWebs) a live
  aggregation would spend tens of seconds of device I/O per view, per worker,
  per operator. The cost of the choice is that the numbers are as old as the
  last harvest, which is why freshness is a column and a banner here, not a
  footnote.
- **Absence is not zero.** A registered device with no snapshot is carried as
  *never harvested*, named in a banner, excluded from every denominator, and
  the pages state how many scopes actually contributed. A snapshot older than
  26 h is marked *stale* and still shown — it is the best evidence there is,
  and a page that hides it answers "the fleet is compliant" with "the fleet WAS
  compliant".
- **A slot a profile does not HAVE is not an unfilled slot.** FortiWeb's
  offline collection carries ~38 of the 41 protection fields; counting the
  missing ones as "off" would have invented a fleet-wide gap no operator can
  close. Coverage denominators are per profile, and the matrix renders
  *not applicable* as a grey dash, never as a red zero.
- **The posture doughnut adds up, and the tiles say what it swallowed.** Each
  policy lands in exactly one bucket by precedence (disabled -> no profile ->
  monitor-mode -> blocking), so the un-bucketed totals are published beside it:
  a disabled policy that ALSO has no profile is invisible in a partition.
- **Findings carry their remedy and a link that lands on the rows described**
  (monitor-mode, no profile, dangling profile reference, deprecated TLS,
  certificate-less TLS, disabled, orphan profiles). A count with no way to
  reach the rows is a number the operator has to reproduce by hand.
- **Scope.** Fleet-wide by design, like Fleet Objects — and only over what the
  console may see: the universe is narrowed ONCE through
  `models.visible_appliances()` and then to `kind == 'fortiweb'`, so
  maintenance devices stay hidden without the permission and no other
  product's device can appear. Offered in the Global and FortiWeb consoles
  only; the other three ADOMs redirect, because the pages count objects those
  products do not have.
- **Guards:** `tests/test_waf_fleet.py` (22), `docs/safeguards.md` §126.

### Exceptions — catalog (custom signatures, operator coupling, orphan type)

- **Custom Signature is now a first-class exception type.** `custom_signature_item`,
  `custom_signature_condition_item` and `custom_signature_group_item` were added to the
  catalog. Field names and enum tokens were read off a live FortiWeb 7.6.8
  (`waf/custom-protection-rule`, `waf/custom-protection-group`) and the generated SDK
  catalog, not from the admin guide's GUI labels — the guide's "Request"/"Response"
  Direction is the device's lowercase `type`, and storing the label produces a payload
  the appliance rejects.
- **`operator` is coupled to the element type.** The picker offered the union of all six
  operations for every element type, so `HOST` + `INCLUDE` was authorable and savable.
  `OPERATORS_BY_TARGET` encodes only the mappings the admin guide states outright;
  anything unlisted stays unconstrained, because forbidding a legitimate carve-out is a
  worse failure than the one being fixed.
- **The orphan `disabled_signature_item` is resolved and migrated.** One live row carried
  an `exc_type` no catalog entry defined: `type_for()` returned `None`, so it rendered
  unlabelled and skipped validation entirely on the way in. `TYPE_ALIASES` maps it (the
  guard against recurrence) and the stored row was normalised (the cleanup).
- **The meet-condition no longer has two names.** `signature_group_rule_condition` carried
  only a match-target/operator/value fragment and held zero rows; it is aliased onto
  `custom_signature_condition_item` and removed from the catalog.
- **Not changed, deliberately:** the three element-type conventions in this catalog
  (`CLIENT_IP` / `FULL-URL` / `"Client IP"`) were left alone. Every matching subtable on
  the live appliance was empty, so which convention each endpoint accepts could not be
  established. Recorded in `UNVERIFIED_SHAPES` rather than normalised on a guess.

### Removed

- **`/artifacts/manage` — it was a second copy of the inventory.** Same rows,
  same verbs, one more place for a scope gate or a validation to be fixed on
  only one of the two. The three add verbs moved onto `/artifacts/inventory`
  as **three buttons, one dialog each** (upload / author / capture — they
  differ in what they touch, and a single "Add content" dialog left the
  operator to notice which of its three columns reaches out to a live
  appliance). They POST to the SAME endpoints; `back=manage` is still accepted
  as an input so a bookmarked round trip lands on the inventory instead of a
  404.

- **"Push this version to an appliance".** Content reaches a device at CREATE
  time and nowhere else: the clone/migrate engine uploads the bytes for every
  file-backed object that run creates, under a pre-flight that refuses to
  proceed unacknowledged when one of them is absent or empty. The standalone
  button was the one control that wrote to a box with **nothing bound to the
  write** — no plan, no policy, no reconciliation report — and its only real
  use, repairing a hand-made or empty object, left content SATOM could not tie
  to anything. The route is gone, not merely unlinked.

- **The migration-coverage table on `/artifacts/inventory`.** "Which server
  policies can move today" is asked WHEN MIGRATING, and it is answered where a
  migration is decided: the clone/migrate pre-flight checklist and, per device
  and exportable, `/artifacts/audit`. On a holdings page it cost a blob read
  **per edge on every render** to answer a question nobody had asked yet. The
  one counter it fed ("walks that FAILED") is read from the scan rows instead.

### Fixed

- **An EMPTY stored copy is a warned state, everywhere it matters.** `blob is
  None` was the whole test for "can this object travel", so a zero-byte (or
  whitespace-only) version **resolved**: the pre-flight counted it under "will
  be copied WITH content", the coverage verdict said `ready`, and the apply
  uploaded it. What lands at the destination is an object the device shows as
  configured while the rule bound to it enforces nothing. An emptiness is
  worse than an absence precisely because every "is it held?" check answers
  yes — so nothing reported it.

  * `waf_artifacts.is_empty()` is the one predicate, and it keeps ABSENT and
    EMPTY apart: the remedies differ (capture or upload vs re-author), so
    telling an operator to capture a file they already hold is a useless
    instruction.
  * `resolve_for_plan` marks an empty copy **unresolved**, with its own reason;
    the pre-flight gate says EMPTY instead of "the device stores only the
    NAME"; the apply skips it and **refuses without an acknowledgement**,
    exactly as it does for an absent one.
  * `policy_coverage` counts `empty` apart from `missing` and no longer calls
    such a policy `ready`.
  * The inventory has a **"Held, but EMPTY"** card, a headline counter and a
    row badge. The card is built from everything the pair holds, never from
    the filtered rows: a warning a filter can hide is a warning that is not
    there.
  * The three doors are closed too — upload now tests `.strip()` (a file
    holding one newline used to pass), and a capture that comes back empty
    stores nothing.

- **Scope labels name the DEVICE, not its management address.** Reported for
  "todas las secciones" of `/artifacts/*`: an operator standing on
  `fortiweb12 / adom_prod` was told they were on `192.0.2.14` — the address of a
  chassis carrying four ADOM rows, so it names none of them. Every label now
  goes through `models.appliance_name_parts` (the product's one answer to
  "what is this device called"); the address stays available as a hover,
  because it is still what an operator types into a browser.

- **The inventory's "Used on (device / ADOM)" column is a count now.** The page
  stands on one pair and the narrowing drops every edge belonging to any other,
  so the column could only ever repeat the pair already printed in the banner
  and in the row's own Device and ADOM cells — and its empty state, **"no known
  user"**, was read as a fact about the fleet when it only ever meant "no
  walked policy OF THIS PAIR names it".

- **Every action on the inventory says what it does on hover.** An icon-only
  control is a guess, and one of them leads to the page that can delete a
  version.

- **`/artifacts/*` takes its (device, ADOM) from the SESSION, like every other
  per-device page — and nothing in the section answers for anything else.**
  Reported a third time (*"estamos en un device x con el adom y y veo todo"*),
  and the two fixes before it could not have helped: they narrowed by
  `?appl=`, **a query argument the operator's navigation never produces**. The
  operator picks a device on the Architecture map; that lands in
  `session['appliance_id']`, and Backups, Server Objects, Web Protection,
  Exceptions, Section Config, Analysis and FortiAnalyzer all read it back
  through `device_context.current_appliance()`. `/artifacts/*` was the **only**
  per-device area that never called it, so with a device selected it rendered
  the fleet — 163 mentions of other pairs on one page, measured on the live
  node.

  * `index`, `inventory`, `object` and `audit` narrow to the session
    pair before a figure is computed; with **no** device chosen they send the
    operator to the map, as Backups does, instead of showing the fleet.
  * **The pickers were the other half of the report** (*"en los filtros"*).
    Every `<select name="appliance_id">` now offers that pair alone, the
    inventory's appliance filter — whose neutral option was the page's own way
    back to the fleet — is replaced by a *within-scope* `held=own|library`, and
    the audit's device filter is gone.
  * A narrowed control is decoration, so **every verb is gated on the route**:
    `upload`, `capture`, `save` and `refs/refresh` refuse an
    `appliance_id` that is not the pair the page stands on (library-wide stays
    allowed where it is the shared bucket this pair reads).
  * Old `?appl=`/`?scope=` links still work — they **move** the session device
    and re-issue the request without the argument, so the URL bar and the nav
    badge can no longer disagree about where the operator is standing.

- **The routes that name their target by ID or by PATH are scoped too.**
  `/blob/<id>`, `/raw/<id>`, `delete` and `push` name a stored version by
  primary key: the device is never mentioned in the request at all. The object
  page had stopped *listing* other pairs' versions, but an unlisted row is
  decoration — the ids are consecutive integers, and `delete` answered for
  every one of them. All four now refuse a version outside the pair (404 for
  the two readers: in this page's universe that row does not exist), `push`
  checks **both** ends, and `/api/list`, `/api/refs` and
  `/api/coverage/<appliance_id>/<policy>` — the same pages with the HTML
  stripped off, all three answering for the whole store, the last one taking
  the scope in its **path** — are cut to the session pair and answer `409` when
  no device is chosen. `waf_artifacts.history()` gained `scope_id`, applied in
  the **query**, so the 200-row limit cannot be filled by another pair's
  versions and the remainder reported as everything there is.

- **A fork lands on the pair the page stands on.** The "only this device/ADOM"
  branch of a shared-copy save offered a `<select>` of every affected pair —
  a control that forked a copy onto a device the page is not named for. The
  destination is now the session pair, the posted `only_appliance_id` is
  ignored, and a fork is still refused where no walked policy reads the copy
  (it would resolve to nothing and shadow whatever that pair does read).

- **`/artifacts/inventory`: the (device, ADOM) selection is the page's
  universe, not a filter laid over a fleet page.** An operator on one device
  and one ADOM still saw the fleet, and was right: `?appl=` narrowed the row
  table and the coverage table and **nothing else**. The nine headline
  counters came from `wa.stats()` / `ar.stats()`, which take no scope and
  cannot answer for anything but the whole store; "By object type" and "Where
  the copies live" were built from the unfiltered index. Measured on the live
  node, a page cut to one ADOM printed **170 objects over a list of 30** and
  enumerated all five device/ADOM pairs, including a second chassis (37
  mentions of a host the operator was not on).

  The narrowing now happens **once, in `_narrow()`, before a single figure is
  computed**, so a section added later inherits it instead of having to
  remember to repeat the filter. Two consequences worth naming:

  * the per-row user list is keyed `(kind, name)` with **no scope in the key**,
    so a copy held here whose *name* another chassis also uses arrived carrying
    that chassis's edges — dropped;
  * a copy held for **another** scope is no longer listed as held here. It
    moves to "needed and NOT held" flagged **held elsewhere**, which is what it
    is: `resolve()` would fall back to another box's bytes, the `borrowed`
    guess the device audit exists to surface.

  A library-wide copy the pair reads is still listed — it is served here today
  — and now carries the count of **other pairs that read the same file**, so
  the copy-on-write warning survives the narrowing.

- **The selection survives a click.** `/artifacts/` published `?scope=` and the
  inventory read `?appl=`: two names for one concept, and every cross-page
  link dropped both, so picking a device on the statistics page and clicking
  *Inventory* landed on the fleet. Both names are now read by one helper, the
  four artifact pages and the sidebar carry the active scope, and the by-type
  links stop resetting it.

- **A scope id that matches nothing complains** instead of silently widening —
  answering a question about one ADOM with twelve ADOMs' rows looks exactly
  like a correct answer. The page also states which pair it is showing, or
  says *whole fleet*: two ADOMs of one chassis legitimately hold the same
  number of objects, so an unlabelled narrowed page is indistinguishable from
  one that never narrowed.


### Added

- **`/artifacts/inventory` says WHERE, and a save can no longer change a file
  for devices nobody named.** Four changes, one round.

  *Location is the pair.* The list printed the registered appliance NAME, which
  is unique per ADOM and therefore answers "which chassis, which ADOM" only for
  a reader who knows the naming convention. Rows now carry a **Device** column
  (the chassis address) and an **ADOM** column, and the users column collapsed
  to the distinct **device / ADOM** pairs that reference the object, with the
  policy count beside each. The policy and profile names moved to the object
  page: four lines of `policy → profile` per row pushed the one fact this page
  is read for off the right-hand edge. Same treatment on "where the copies
  live", on the not-held table and on the version list.

  *Adding content without leaving the page.* An **Add content** button opens a
  dialog with the three verbs from `/artifacts/manage` — upload, author,
  capture — posting to the **same three endpoints**. A modal-flavoured second
  set of routes is how the copy that lacks the empty-body refusal ends up
  storing an artifact that pushes as `-7694`; the only difference is
  `back=inventory`, resolved server-side.

  *The eye.* Every row gets a view action carrying the object's **scope** and
  the page's full query string, and the object page grew a **Back** button that
  returns to the filtered list. Without the scope the object page opens
  whichever version sorts first, which under one name can be a different file;
  a link to the bare inventory would look identical and silently drop the
  filter that made the row findable.

  *Copy-on-write, and it is the load-bearing one.* A library-wide copy that
  three ADOMs resolve to **is one file**: editing it "for prod" edited dev and
  dmz too, both kept working, and the divergence surfaced only the next time
  somebody diffed them. `artifact_files.scope_impact()` now computes who a save
  reaches **before** the write — grounded in `waf_artifacts.resolve()`'s search
  order, so a device holding its own copy is correctly reported as NOT affected
  — and a save on a shared copy is **refused** until the operator says `all`
  (a new version everyone gets) or `only` (fork a copy scoped to one pair and
  leave the shared copy exactly as it was). Neither is pre-selected: a default
  here is the defect in miniature, since `all` edits devices nobody named and
  `only` quietly stops a fleet-wide fix from reaching the fleet. The fork is
  reported as a fork, including the consequence — that pair stops receiving
  later edits of the shared copy.

  17 guards in `tests/test_artifact_inventory_scope.py`, **13 mutations, 13
  bite**. See `docs/safeguards.md` §120.

- **`/artifacts/` now NAMES the scope it is showing.** The filter was applied
  correctly and the page said nothing about it, which on a real screen is not
  the same thing. Per-ADOM counters of a symmetric estate collide: the four
  ADOMs of `192.0.2.13` hold **disjoint** data (`pol-root-*` / `pol-prod-*` /
  `pol-dmz-*` / `pol-dev-*`, zero overlap) but five policies each, so all four
  print the same six headline figures. Switching ADOM in the picker moved
  nothing on screen and read as a filter that was never applied.

  A narrowed page now carries a banner naming **device → ADOM**, and says
  plainly that identical totals across sibling ADOMs are a property of the
  estate rather than a failed filter — pointing at the profile names below,
  which are unique to one ADOM and are the only thing an operator can actually
  check. The unnarrowed page is labelled **whole fleet** rather than left
  blank: an unlabelled page is not neutral, it reads as whichever scope the
  reader last had in mind.

  Guarded at the **route**, not at `fleet_stats()`. Every existing scope test
  called the service directly, which is how a page that computed the right
  numbers and rendered them unlabelled shipped: the arithmetic was tested and
  the rendering never was. The fixture is deliberately **symmetric** (two ADOMs,
  identical counts, disjoint names) with a control test asserting the symmetry
  — two ADOMs of different sizes would let an unfiltered page pass by printing
  a different number.

- **`/artifacts/` is the statistics page, cut by (device, ADOM).** It answered
  only "what are the seven types" while every number about them lived one page
  away. It now leads with the figures and keeps the reference below them: how
  many **Web Protection Profiles carry files**, how many policies name one, per
  object type the references / distinct objects / policies / profiles / held /
  not-held / versions / bytes, the store split by captured vs uploaded vs
  orphaned, and a per-profile table. A `?scope=<appliance>` selector narrows
  every figure to one ADOM.

  The scope is **(device, ADOM) and never the chassis**, and that is the whole
  design rather than a formatting choice. SATOM registers one appliance record
  per administrative domain, so `192.0.2.13` is four records (`root`,
  `adom_prod`, `adom_dmz`, `adom_dev`). A profile called `wpp-a` in `adom_prod`
  and a profile called `wpp-a` in `adom_dev` are different profiles that may
  bind different files under one name — counted per chassis, one ADOM's
  uploaded copy would read as coverage for another ADOM's object, and the two
  files never met. Chassis rollups therefore come from `models.chassis_key`
  (which the repo already owns, and which correctly refuses to bucket HA
  cluster containers together), and the profile and object counts are
  recomputed from `(appliance_id, …)` pairs rather than summed.

  Three things the page refuses to round off:

  - the three attribution states stay apart. A named profile counts towards
    *profiles with files*; `""` is **policy-level** (Lua scripting hangs off the
    server policy and passes through no profile at all) and is reported as a
    finding; `NULL` is **not attributed** and is reported as an unanswered
    question. Folding either into the first invents a profile that does not
    mention the file.
  - an ADOM nobody ever walked renders **"never swept"**, not a row of zeros —
    zeros read as *walked, and it carries nothing*, which is the false
    all-clear this subsystem exists to withhold.
  - a `?scope=` that matches nothing **complains** and says it fell back, rather
    than silently answering a question about one ADOM with the fleet's numbers.

- **WAF Artifacts is one sub-menu with four pages, not three siblings.** The
  entries lived flat in the WAF group and two of them carried `fw-nav-sub` — a
  class with **no rule in `fortiweb.css`** (the sheet defines `fw-nav-subitem`
  and `fw-nav-subgroup`; neither matches). With nothing to style them the
  children rendered at their parent's weight: three top-level entries wearing
  the word *Artifact*, and no group to collapse. They now use the product's own
  shape — `<details class="fw-so-parent">` with `fw-so-nav-flat` leaves, the
  same as Server Objects and Web Protection — and open only on their own
  blueprint so the accordion still holds.

  - **Object types** (`/artifacts/`) — reference and theory: the seven types,
    why their content is not in the configuration, and the four-link chain a
    file travels (*policy → profile → rule → file*). The upload/capture forms
    and the push table that used to sit here moved to **Files**: two authors
    for one verb is how they drift, and a destructive control has no business
    on the page an operator opens to look something up.
  - **Inventory** (`/artifacts/inventory`) — unchanged in purpose, now naming
    the profile behind every user.
  - **Files** (`/artifacts/manage`) — every verb, and each row states **which
    Web Protection Profile it is assigned to** rather than a bare count. A
    count said somebody used the file but not where, one click from *delete*.
  - **Device audit** (`/artifacts/audit`) — **new**: everything SATOM knows,
    grouped by device and exportable as **JSON or CSV**, at one row per
    *(device, policy, profile, artifact)*.

- **Every artifact reference now names the Web Protection Profile it travels
  through** (`services/artifact_wpp.py`, column `waf_artifact_ref.wpp_mkey`).
  A FortiWeb operator does not bind a schema to a policy — they bind it to a
  rule inside a profile, and the policy names the profile. The attribution is
  **walked** up the clone planner's own referrer graph, never assumed, and it
  has **three distinct states**: a profile name; `""` = walked and it hangs off
  the **server policy itself**; `NULL` = **not attributed**, nobody looked. The
  column is nullable with no back-fill for exactly that reason — a `DEFAULT ''`
  would have re-labelled 432 historical edges as a finding the walk never made.

- **Four migration verdicts per artifact, per device.** `ok` (a copy scoped
  here), `borrowed` (no copy here, but another appliance holds that name — a
  **guess**, which the new *same name, different content* report exists to
  qualify), `at-risk` (no copy, still capturable off a live box) and `blocked`
  (no copy anywhere and no FortiWeb will ever hand this type back — the policy
  cannot be migrated until someone uploads the file).

### Fixed

- **The shortcut that would have mislabelled every Lua script.** "The plan
  contains one profile, so every artifact belongs to it" is wrong twice:
  `cmdb/server-policy/scripting` hangs off the **policy** and never passes a
  profile, and a policy with content routing can bind **several** profiles.
  Re-derived live across the fleet: **432 edges, 16 profiles, and the 48
  `policy-level` edges are all — and only — `scripting`.**

- `/artifacts/` no longer runs a full `history()` scan of every artifact
  version to build a list the page stopped rendering.

- **Artifacts stopped being a flat store.** The library knew *what* file-backed
  objects it held and *which appliance* they came from, but never *which
  policy needs them* — so the only way to answer "can I migrate this SPO?" was
  to start a clone pre-flight against a chosen destination and read the
  fallout. Three pages now answer it before the decision:

  - **`/artifacts/manage`** — uploads and file management. Three verbs, kept
    distinct on purpose: **upload** a file from disk, **author** one in the
    browser, **capture** one off an appliance. Anything stored here can be
    **pushed** into a FortiWeb, which is the advantage the appliance itself
    does not give you.
  - **`/artifacts/object/<kind>/<name>`** — the object itself: view the
    content online, edit it in place, every save is a **new version**, and any
    two versions can be **compared** with a structural diff.
  - **`/artifacts/inventory`** — statistics, where each object lives, a
    **"used by"** column naming the policies that reference it, and filters by
    kind, appliance, orphan and staleness.

- **The policy→artifact index is DERIVED, never typed.** `waf_artifact_ref`
  records observations — *this policy named this object on this appliance at
  this time* — produced by the same dependency walk the clone planner already
  performs, run source-only. A hand-maintained field would go stale the day a
  rule changed schema and nothing would fail; it would simply become false,
  and the cost of that falsehood is a migration that ships without a WSDL the
  destination will never receive.

- **Edges are scoped by (appliance, policy), never by policy name.** The same
  name on two chassis can point at different schemas; collapsing them
  manufactures the exact all-clear this index exists to deny.

- **A failed walk never deletes edges; a successful one deletes what it no
  longer produces.** The first rule makes one unreachable appliance unable to
  "prove" that none of its policies need anything. The second stops the index
  from growing forever off one historical reference.

- **"Walked, needs nothing" and "never walked" do not render the same.** The
  first clears a migration; the second means nobody looked.

- Scheduled action **`artifact_refs`** refreshes the index on a cadence;
  bounded sweeps report their remainder, because a truncated run otherwise
  reads exactly like a complete one. The clone pre-flight **donates** its walk
  instead of re-walking.

## [1.20.0] - 2026-08-24

### Added

- **The "?" reached the pages.** Settings → Sentinel has explained every knob
  since 1.16; the four operational pages explained nothing. 27 explanations now
  sit beside the controls they describe — nine on the incidents console, seven
  on Context, six on Response policy, five on Border blocklist — drawn by the
  same `partials/_hint.html` macro, so the text is in `title` and survives
  JavaScript failing to load.

  The prose for the health chips was **not written for this release**. It
  already existed as `UI_HINTS['health.*']` and rendered only in Settings,
  which is the actual defect this closes: an operator reading
  *"4416/4720 buckets usable (93.6 %) — an immature bucket never fires"* on the
  console had the sentence that explains it one page away and invisible.
  `hint_for()` falls through to the settings catalog rather than copying it;
  a guard fails if any `health.*` key is ever duplicated into `PAGE_HINTS`.

### Changed

- `sn_hint` is registered as an **application-wide Jinja global**, not as a key
  each view adds to its own context. Every Sentinel section renders on two
  surfaces — a standalone page and an Admin Console pane — from one partial
  driven by two different view functions, and a context key threaded by one and
  forgotten by the other is precisely how `/settings/` began answering 500 when
  the edge group landed in 1.18.0. A global cannot be forgotten by half the
  callers.

- Sentinel's explanatory prose now lives in **one file** (`sentinel/config.py`,
  `UI_HINTS` + `PAGE_HINTS`) rather than being spread through templates. Two
  authors of one sentence is how the licence footer acquired two spellings.

### Notes

- **Sentinel → Documentation was deliberately left alone.** That page is
  already the explanation; a "?" on prose is a second copy of it.
- The behavioural baseline still trains on **infrastructure telemetry only**
  (CPU, memory, sessions, connection rate, RTT, throughput, VM and host). Attack
  volume and block volume — `satom_sentinel_events_new`, and the
  blocked/passed split the pipeline already derives per event — are **not**
  baselined. Adding them changes what fires, so it is proposed rather than
  shipped here.

## [1.19.0] - 2026-08-23

### Added

- **The border blocklist — a list SATOM publishes, never a write it performs.**
  Sentinel can now put a source address on a text feed a FortiGate reads as an
  External Connector threat feed (*Threat Feed → IP Address*). There is still
  **no FortiGate client in this product and no credential that could write
  one**: the operator pre-creates the deny policy that references the feed,
  exactly as they pre-create the FortiWeb IP list `block_ip` appends to.

  New table `sentinel_block_entry`, new page **Sentinel → Border blocklist**
  (a pane in the Admin Console and a standalone page at `/sentinel/blocklist`,
  rendered from one file), a **List on border blocklist** control on every
  incident, and the endpoint `GET /sentinel/feed/<token>/blocklist.txt`.

  Nothing reaches the list without passing the border veto shipped in 1.18.0.
  FortiWeb reports the true client when a policy reads `X-Forwarded-For` and
  the CDN's own address when it does not, and nothing in the attack log
  distinguishes them — listing the second kind removes every legitimate client
  behind a shared egress. **That is why this shipped after the veto and not
  with it.**

- **A release point, and it keeps the record.** One click takes an address off
  the feed immediately, reachable whether or not the feed is enabled, the
  mirror works or the border is answering. It is not a delete: the row stays
  with who released it and why, because a list whose false positives vanish
  without trace cannot be reviewed for the pattern that produced them.
  `sentinel_block_entry.incident_id` is `SET NULL` on delete for the inverse
  reason — cascade would make deleting an old incident silently unblock an
  address still inside its TTL.

- **Optional git audit mirror**, off by default and with **no default remote**.
  It must be a separate repository: SATOM's own source repo is mirrored to a
  public host by the release tooling, and a blocklist committed there would
  disclose which addresses attacked which customer. The working copy also
  lives outside `data/`, where the standby's `rsync --delete` datasync would
  wipe a git working tree mid-commit. The mirror is the audit copy; a mirror
  that cannot reach its remote never blocks a listing or a release.

- Action `block_edge_ip` in the catalog — `handoff=True`, `verified=False`,
  **capped at recommend permanently**. Its blast radius is every FortiGate and
  VDOM whose connector reads the feed, and so every service behind them: wider
  than any FortiWeb action in this product. There is no transport, so the
  runner refuses it *by name* rather than looking for a device write that
  cannot exist.

- Scheduled action `sentinel_feed_publish` (suggested every 15 minutes) —
  bookkeeping and history only, see below.

- Settings group **Border blocklist feed**: `feed_enabled` (off),
  `feed_token`, `feed_ttl_hours` (24, hard ceiling 720h in code),
  `feed_max_entries` (500), `feed_stale_minutes` (30), `feed_git_remote`
  (empty), `feed_git_branch`, `feed_git_token`, `feed_git_auto` (off).

- The border verdict is now **persisted as evidence** on the incident. It was
  scored — `edge_corroboration` is the largest independent positive in the
  table — but recorded nowhere, so a reviewer asking on what grounds an
  address was listed had no answer, and the listing route would have had to
  re-query, which asks a different question than the one that authorised the
  entry.

### Changed

- **The published TTL is a property of the data, not of a job.** `block_ip` on
  FortiWeb uses `action=block-period`: the appliance expires the block and
  that expiry survives Sentinel being dead. A feed has no device-side timer,
  and the obvious implementation — a job rewriting a file — would move the TTL
  onto SATOM staying alive, turning every block permanent the moment the
  scheduler stops. So the feed is **rendered from the database on every
  request** and filtered by `expires_at`; there is no file in the serving
  path. The residual regression is stated rather than hidden: a border that
  cannot *reach* this node keeps its last fetch and those entries freeze, so
  every rendered body carries `generated_at` and `stale_after` in its header
  and the console reports staleness.

- The Sentinel menu now has **six** entries; *Border blocklist* sits last of
  the four configuration surfaces because it is the one read by something
  outside this product.

### Fixed

- `not_listable()` accepted **multicast** addresses. `ipaddress` answers
  `is_global == True` for `224.0.0.1`, because that property asks "outside the
  private ranges", not "a host something could have connected from" — so a
  guard whose docstring claimed to exclude multicast, reserved and
  unspecified space did not. Each class is now named separately so a future
  edit cannot drop one silently. Found by mutation, with the guards green.

### Security

- The feed answers **without a login**, because a threat-feed connector cannot
  log in. Consequences, all deliberate and all guarded: an **unset** token
  matches nothing including an empty candidate (`compare_digest("", "")` is
  `True`, so the emptiness check is the guard); a wrong token and a
  non-existent feed are both **404**, since distinguishing them tells a scanner
  it found something; `Cache-Control: no-store`, because a cached blocklist
  outlives its entries' TTLs; and rotating the token has no grace period and
  no second valid token.

- Nothing is listed while `sentinel.protect_cidrs` contains a line that does
  not parse. An unreadable never-block list is not an empty one, and the
  permissive reading of a broken protection list is *protect nothing* — the
  same argument that makes the access gate answer 503 rather than serve.

- At the entry ceiling a listing is **refused, never evicted**: dropping the
  oldest live row silently unblocks an address still inside its TTL, and the
  only telemetry would be traffic resuming.

- An operator may set the border veto aside, but only as a recorded act with a
  **written reason** — and the override relaxes the border veto only. The
  never-block list is not overridable: there is no judgement available about
  our own infrastructure.

## [1.18.0] - 2026-08-23

### Added

- **Border corroboration — Sentinel can ask the firewall in front whether a
  source is a real peer.** A new operator-entered map (Sentinel → Context →
  *Border map*) ties each protected appliance to a FortiAnalyzer, an ADOM, a
  FortiGate and a VDOM; the correlator then asks that collector whether the
  border logged the same source in the same window. Every field is typed by
  the operator — nothing is inferred from a hostname or discovered from an
  ADOM listing, because a wrong guess here does not fail, it points the
  lookup at somebody else's traffic and the answer still looks like an answer.

  The answer does two different jobs:

  - **Evidence.** `edge_corroboration` (+12) when the border independently
    logged the source, and `edge_multi_target` (+10) when it saw that source
    reach more distinct destinations than the configured scanning floor. Both
    are independent of the appliance — every other positive factor in the
    table is ultimately derived from the same WAF's view of the same traffic.
    This matters most where it is needed most: an installation with no
    hypervisor access loses up to 18 points it can never recover
    (`vm_anomaly` + `host_anomaly`), and a FortiGate is the thing such an
    installation usually *does* have.
  - **A veto.** FortiWeb reports the true client when the policy reads
    `X-Forwarded-For` and the CDN's own address when it does not, and nothing
    in the attack log distinguishes them. In the first case a border block is
    inert; in the second it removes **every** client behind that egress. So
    an address the border never confirmed cannot enter a border blocklist
    while *Require border corroboration* is on — which is the shipped
    default.

  There is deliberately **no negative weight** in this layer. Silence at the
  border is a fact about addressing, not about hostility, and subtracting for
  it would systematically under-score exactly the customers who run a CDN.

- Seven settings under a new **Border corroboration** group, each with the
  long-form `?` explanation the rest of the page carries. Two of them are the
  ones that fail silently and so are called out here: **Collector clock offset
  from UTC** (a mismatch returns zero rows forever, which is byte-identical to
  a source the border never saw) and **Require border corroboration** (the
  veto).

- A **Test lookup** button on every mapped appliance, which runs one read
  against the live collector and shows the raw device refusal. This exists
  because the failure mode of this whole layer is silence: a wrong ADOM, a
  wrong device name, a clock offset and a genuinely absent source all return
  zero rows, and only one of the four is an answer.

### Fixed

- The Admin Console pane for Sentinel → Context re-listed the section's
  context keys by hand, so a key added to the single shared builder reached
  the standalone page and not the pane. A guard now derives the required key
  set from `context_context()` itself and fails when the pane does not deploy
  all of it.

### Notes

- **The mechanism is unverified and the console says so.** There is no live
  FortiAnalyzer in the development fleet to prove the `logsearch` route
  against (`faz01` is retired on a `.invalid` host), so it ships as a
  specification with its provenance stated — the same contract
  `actions.CATALOG` already applies to response actions. Every failure path
  degrades to *border layer not evaluated*, never to *the border says no*.
- This module never writes to a FortiAnalyzer or a FortiGate. A guard asserts
  the absence of `set` / `update` / `delete`, and that the one `add` verb
  (which is how FortiAnalyzer *creates a search task*) targets only the
  logsearch route.


## [1.17.1] - 2026-08-23

### Fixed

- **The two buttons that reveal a sibling pane did nothing.** *Response engine
  → Response policy* (in the Incidents console) and *Architecture → Incidents
  console* both carried `data-bs-toggle="tab"` while sitting inside a card,
  outside the tab list. Bootstrap 5.3 resolves a tab list with
  `closest('.list-group, .nav, [role="tablist"]')` and **returns** when it
  finds nothing — but the element still matches the click data-api, so its
  handler runs into `querySelectorAll.call(undefined, …)` and throws
  `Illegal invocation`. Nothing failed server-side: valid markup, 200 on the
  route, every render assertion green. The only symptom was a button that did
  nothing, which looks exactly like a button nobody pressed. Both now forward
  the click to the menu entry that owns the pane — the trigger Bootstrap can
  actually construct — which also keeps the menu highlighting the section the
  operator is looking at. Each carries a fallback URL to its standalone page,
  so "nothing happens" is not an available outcome. Reported by an operator;
  measured and re-verified in chromium under the app's real CSP.

## [1.17.0] - 2026-08-23

Sentinel's four surfaces are now panes of the Admin Console, autonomy has four
named modes, and the on-demand sweep is a job over the devices you pick.

### Added

- **Context and Response policy are panes of the Admin Console**
  (`Settings → Sentinel → Context` / `Response policy`), each rendered from the
  same partial as its standalone URL. `/sentinel/context` and
  `/sentinel/policies` are unchanged and still reachable. Sentinel's menu group
  now offers five entries, ordered by what they are: the three configuration
  surfaces, then the architecture document, then the live console.
- **Four operating modes** — *Alert only*, *Alert and block*, *High*,
  *Ultra high* — on the Response policy section. A mode is a **named set of
  values** for knobs that already existed: no gate anywhere asks which mode is
  active, so the label cannot describe behaviour the table below it does not
  have. The live mode is **derived on every render**; edit any of its values by
  hand and the page reads *Custom* at once, naming the keys that differ.
  No mode touches consent (`ai_enabled`, `vuln_sync_enabled`, the API key) or
  containment (`protect_cidrs`, the hardened-profile list): those are not
  sensitivity settings. `block_country` stays capped at *recommend* in every
  mode, Ultra high included.
- **A device picker for `Run sweep now`.** FortiWeb appliances only — a sweep
  ingests the FortiWeb attack log and a FortiADC has none. Devices the
  pipeline skips (maintenance, retired `.invalid` hosts) are listed with the
  reason rather than hidden. Selecting nothing sweeps every eligible device,
  which is what the button always did.

### Changed

- **The on-demand sweep runs as a job**, not inside the request. It used to
  hold one gunicorn worker for as long as the slowest appliance took, with no
  progress reported and no way to stop it; it now reports per device, survives
  the page and stops at a safe checkpoint between devices. The scheduled
  `sentinel_sweep` action is unaffected — `sweep()` with no argument still
  reads every eligible device.
- **The incidents console no longer draws its own Architecture and Context
  buttons.** Both became menu entries in this same release, which is the only
  reason they could go: until now the Context button was the *only* way to
  reach that page.

### Fixed

- Every POST form in the Context, Response policy and incidents-console
  sections carries the return marker, so a save or a delete fired inside the
  Admin Console comes back to the pane it was fired from. The per-row forms
  (remove a trusted source, remove a window, save a topology row) were the ones
  a render-only check could not see.


## [1.16.1] - 2026-08-23

The Admin Console menu could not be opened. Eleven inline blocks were being
dropped by the browser, silently.

### Fixed

- **The Admin Console side menu expands again.** The accordion script moved
  into the shared `settings/_nav.html` partial in 1.14.0 and lost the
  `nonce="{{ csp_nonce }}"` attribute on the way. The app serves
  `script-src-elem 'self' 'nonce-...'`, so the browser refused to execute it:
  the markup was correct, the route returned 200, every test passed, and not
  one group on any Settings surface could be opened. Measured in chromium
  against the live policy: **0 of 9 groups opened; with the identical page and
  no policy, 9 of 9.**
- **Ten more inline blocks were in the same state** and had never run in a
  browser — the Vault tab's test/migrate script, the incident page's
  time-aligned layer charts, the integrations hook and index pages, the change
  request document and form, both upgrade-flow pages, and the inline `<style>`
  of the change-request form and the concept map (`style-src-elem` names a
  nonce too, so those styles never applied).

### Added

- **`tests/test_csp_nonce.py` (safeguards §108)** — every inline script and
  style in every template must carry the nonce; the rendered Settings surfaces
  must ship none the browser would drop; the policy itself must still require
  a nonce, or the whole guard would be vacuous. The scan blanks comments before
  reading, because prose about this rule necessarily spells the markup it
  forbids, and it asserts a census of the files it walked — a scan pointed at
  the wrong directory reads nothing and passes everything.

## [1.16.0] - 2026-08-23

Every control in the Sentinel settings section explains itself, on hover.

### Added

- **A "?" beside every element of `Settings → Sentinel → Settings`** — all 25
  knobs, the five group headings, the four health chips and the three links
  out. Hovering (or focusing, or tapping) one opens a panel of prose that says
  what the control actually does, where the code reads it, and what breaks at
  each extreme. Seven settings previously had no explanation anywhere at all —
  the correlation windows, the severity floor, the mirror source and the three
  AI endpoint fields.
- **`config.SPEC[*].hint` and `config.UI_HINTS`** — the explanations live in
  the same catalog the form is generated from, next to the knob each one
  describes. The catalog docstring already argued this for the FORM; nothing
  fails when prose and control drift apart, and a stale explanation of a
  switch that arms a firewall is worse than no explanation.
- **`app/templates/partials/_hint.html`** — one macro, importable anywhere. The
  text goes in `title`, so with JavaScript unavailable the browser still shows
  its native tooltip; a component whose only job is to explain must not go
  silent when a script fails to load. `type="button"` because these sit inside
  the settings form, and a default `<button>` would have saved the page every
  time someone read a hint.
- **`app/static/js/fw_hints.js`** — upgrades those to Bootstrap tooltips,
  with the container pinned to `<body>`. `.fw-card` is `overflow: hidden`, and
  a panel parented inside it is clipped — measured headless, a 132px
  explanation in a 123px card paints 58px — while still looking like a working
  tooltip. Bootstrap 5 already defaults to `<body>`, so the pin is a lock
  against a future default, not a fix for today's. Loaded in `<head>`, so its
  Turbo listeners
  register once, and it disposes every tooltip on `turbo:before-render` —
  Popper's panels are not part of Turbo's body swap, so without that each
  visit strands its own and a hover pops up help for a control that is gone.
- **`tests/test_sentinel_hints.py`** (13 tests, safeguards §107) — a knob added
  to `SPEC` without a hint fails here, as does a hint that never reaches the
  HTML on **either** surface. 16 mutations, all biting.

### Fixed

- Two of those guards read `fw_hints.js` for `container: 'body'` and
  `turbo:before-render` and were answered by the file's own header comment,
  which names both — they passed against code that said the opposite. Guards
  now strip comments before asserting. Eighth occurrence of this failure in
  this repo; the helper is now shared.


## [1.15.0] - 2026-08-23

Sentinel's Architecture and Incidents console are rendered in the Admin
Console, beside its settings.

### Added

- **`Settings → Sentinel → Architecture`** and **`Settings → Sentinel →
  Incidents console`** are now **panes**, not links out. Both render the same
  content their standalone URLs serve — the architecture document generated
  from the live weight table, action catalog and settings spec; and the live
  console with its four health tiles, the seven-day figures and the incident
  table. Two of the three entries in a group about one subject used to take
  the whole page away, and the way back was the browser.
- **`app/templates/sentinel/_docs_section.html`** and
  **`app/templates/sentinel/_console_section.html`** — one file per section,
  included by its pane and by its own page. The same arrangement the Sentinel
  settings section already used: a hand-copied second surface is a second
  place for numbers generated from live tables to be read wrongly, and nothing
  fails when two copies disagree.
- **`sentinel.console_context()` / `sentinel.docs_context()`** — one context
  builder per section, shared by both surfaces, so the pane and the page
  cannot answer differently.

### Changed

- **Controls inside the panes stay inside the console.** The sweep and the
  baseline rebuild carry `return_to` and come back to the pane they were fired
  from; the status filter reloads Settings (`?sn_status=`) instead of jumping
  to `/sentinel/`; the Architecture button switches the sibling pane. A
  control that works perfectly *somewhere else* is the failure this removes.
  Opening one incident still leaves, because an incident is a page of its own.
- **No entry in the Sentinel group carries the leaving arrow** — none of them
  leaves. The marker's branch stays in the menu for the next entry that really
  does: an arrow on a row that only swaps a pane warns of a page change that
  never happens.
- The incident table is wrapped in a scroller. Nine columns do not fit the
  Admin Console's single, narrower column, and a table cut off at the edge
  reports nothing.
- `/settings/` builds the metrics-store health **once** and hands it to all
  three Sentinel sections, rather than asking three times for an answer that
  cannot have changed between them.
- §26 of the manual describes the three panes, and a new guard derived from
  the menu literal fails if it goes back to calling two of them links out.

## [1.14.0] - 2026-08-23

The Admin Console menu is defined once and included everywhere.

### Added

- **`app/templates/settings/_nav.html` — the menu, in one file.** The group
  list, the render loop and the accordion script now live together in a single
  partial that every Settings surface includes. Copying the markup into a page
  is how the horizontal strip this menu replaced ended up with two entries for
  one pane, and nothing fails when two copies disagree: the operator simply
  gets a different menu depending on which URL they arrived by. A guard asserts
  the literal exists in exactly one template and names the files that include
  it.
- **The standalone `/settings/sentinel` page keeps the submenu.** It is reached
  by deep link and by the save redirect from outside the console, and it used
  to render bare — the whole Admin Console menu gone, the browser's Back button
  the only way home. It now includes the same menu in `links` mode: the entries
  navigate back into the console (`/settings/#tab-users`) instead of switching
  panes that are not on that page, and the entry being shown is marked. A tab
  button there would be a row that highlights on hover and then does nothing.

### Changed

- **Sentinel is the last group in the menu**, below *Monitoring & Alerts*
  (operator's request). The two configure-once groups now sit together at the
  bottom, under the groups opened every day.
- The accordion script moved out of the console page and into the menu partial.
  Left behind, it would have made every standalone Settings page render a menu
  whose groups cannot be opened — and the groups are collapsed by default, so
  that is a menu with nothing in it.
- §26 of the manual documents the single-source menu and the standalone
  behaviour, and a new guard asserts its group table lists the groups **in the
  order the menu draws them**: every previous guard stayed green while the two
  orders drifted, because each row was still present and still correct.

### Fixed

- `tests/test_settings_nav_groups.py` sliced the menu script by anchoring on
  the line that happened to follow it in the console page. With the script in
  its own partial that anchor made the slice unbounded — it swallowed the whole
  page's JavaScript, and every rule about the accordion became a statement
  about unrelated code (one promptly tripped on a `.push()` in the Sentinel
  demo lab). It now ends at the partial's own `</script>`.

## [1.13.0] - 2026-08-23

Settings → Sentinel is now a full section, not a form in a pane.

### Added

- **`/settings/sentinel` — the whole Sentinel section.** The pane held the
  form and nothing else, so "what will this thing actually DO?" was answered
  only by the architecture page's prose. The section answers it in escalating
  commitment before showing a single knob: the pipeline drawn stage by stage
  (CSS-only animation, honours `prefers-reduced-motion`), the score bands and
  the weight table rendered from the live `WEIGHTS` dict, and then the form —
  the same catalog-generated form as before, in one place only.
- **A demo lab: ten scenarios runnable against the live engine.** The same ten
  scenarios the test suite asserts on every commit, pushed through the real
  `score_context`, the real band thresholds and the real policy gates when
  the button is pressed. Only the events and metric readings are staged; the
  gate audit reads the installation's live kill switch, policy rows and hourly
  budget. Nothing is written and no device is touched — both halves of that
  sentence are asserted by `tests/test_sentinel_settings_page.py`, along
  with each scenario's published band, so a weight tune that moves a scenario
  breaks the build in the commit that tunes it instead of on the Settings page.
- **Sentinel is its own group in the Admin Console menu**, holding three
  entries: **Settings** (the section itself), **Architecture** and **Incidents
  console**. It used to be one entry under *Monitoring & Alerts*, which left
  two of its three surfaces reachable only from a button inside the third.
  The two page entries are drawn as links with a leaving arrow, because a row
  that replaces the whole page must not look identical to one that swaps a
  pane.
- **The Settings pane at `#tab-sentinel` renders the whole section inline** —
  pipeline, weights, demo lab and form — instead of a doorway card whose only
  control opened another URL. Both surfaces render
  `settings/_sentinel_section.html`, so there is still exactly one form: a
  hand-copied second one would put a second `id="sn-enabled"` on the page and
  point every `<label for>` at the wrong input.

### Changed

- **Monitoring & Alerts moved to the bottom of the Settings menu** (operator's
  request): the alert plumbing is configured once and then left alone, unlike
  the groups above it. Nothing was renamed — every `#tab-*` deep link still
  lands where it did.
- Saving Sentinel settings returns **where the form was rendered**: the pane
  posts `return_to=pane` and comes back to `/settings/#tab-sentinel`; anything
  else (a deep link, a bookmark, a script) still lands on
  `/settings/sentinel#config`. Being moved out of the console by pressing Save
  is the indirection the inline section exists to remove.
- Concept Map gained the section (89 pages); user guide §26/§39 and the
  Sentinel architecture document updated to match.


## [1.12.0] - 2026-08-22

Four rounds of clone work landed after 1.11.0 with an empty `[Unreleased]`
block. This release documents all of it, and repairs the one defect that
auditing it uncovered: **a declined section was only half declined, and the
missing half was the half that writes.**

### Added

- **An SNI policy is cloned at all.** `clone._CERT_URNS` held
  `system/certificate.sni`, so the object was classified `cert` — "SSH-only,
  not cloned over REST" — and every member row under it then fell to `empty`
  ("parent object is not being created"). The copy landed naming an SNI table
  the destination had never seen. Measured with this project's own client on
  FortiWeb 7.6.8: the object is `name` + `sz_members` and the row is
  `domain` / `local-cert` / `inter-group` / `lets-certificate` / `verify` —
  **no PEM anywhere**, `POST` 200 for both. ⚠ One collection, **two
  spellings**: the row calls the chain group `inter-group`, the policy calls it
  `intermediate-certificate-group`, so the *children* are shared and the node
  is not.
- **Backend reachability, from two vantages that are never merged** — the
  destination appliance over `execute ping`, and this node over TCP to the real
  port. `unknown` stays its own bucket: folding it into "reachable" signs off a
  real outage, folding it into "down" manufactures a false one. Off by default.
  ⚠ `execute` is **not** added to the read-verb allowlist (that verb also
  spells `reboot` and `factoryreset`); the probe carries a whole-command gate
  of its own.
- **Certificate material carried over SSH, inside the clone.** `show` inside
  the entry prints the certificate *and* the private key; `get` prints neither,
  and REST prints neither for either field. Carried **before the first write**,
  because a certificate is a dependency and a `-651` halfway through an apply
  means the operator is already committed. A name the destination already holds
  is left alone; the private key never reaches a plan, a report or a log.
- **New, compare and decide** — the third profile policy. The planner had
  always compared sub-table *rows*; it never compared the profile **object**,
  so a profile whose ~40 lists matched but whose own switches differed read as
  identical and was not. ⚠ The slice runs **backwards**: the plan is post-order,
  so a profile's descendants are the contiguous run *before* it that is deeper
  than it (measured: 111 items backwards, 1 forwards). Nothing is pre-ticked.
- **Rows the destination already owns are reconciled, not re-created.** The
  appliance enforces uniqueness on a **natural key** — a subset of the row — so
  a destination row with the same key and different content was absent to the
  planner and present to the box: the plan said `create`, the box refused the
  duplicate, and the destination kept serving the old value.
- **Reuse a destination profile (`dst_wpp`), and create a profile only if it is
  missing (`wpp_only_if_missing`)**, both reaching the single-policy dialog and
  the bulk job from the same function. Profiles are deduplicated **once per
  bulk run**, keyed on the *pair* (source profile, landing profile).
- **`trigger` and the Custom Signature filter edge.** A `trigger` names a
  `log/trigger-policy` and nothing ever created it; on a destination lacking
  the policy the appliance rejected the **whole object** (HTTP 500, no errcode).
  Keyed by **field**, not by tree position — `trigger` is carried by 10 object
  collections, and only 51 of 130 had any row on the lab appliance, so keying on
  measured parents would have left the defect latent in the other 79.
- **The two datasource fields beside `redirect-url` on a Web Protection
  Profile** — `custom-response` and `quarantined-ip-trigger`. Reported as "the
  redirect URL is not being cloned"; `redirect-url` is a string and always
  travelled. A dangling reference made the destination answer `-651` to the
  **whole profile**, so every setting was lost with it.
- **Parallel pre-flight analysis.** Measured in vivo: 10 policies,
  **51.45 s → 20.99 s (2.45×)** at 4 workers, with an identical plan footprint.
- **A sizing formula, and the requirements built on it**
  ([`sizing.md`](docs/sizing.md)). Every requirements table in this manual used
  to state a *floor* — what the installer needs to finish — and nothing said how
  big a node must be for the fleet pointed at it. The new document gives one
  formula per resource with the constants measured on a running node, and the
  headline is that **the ceiling is device I/O, not storage**: a node spends
  **0.82 s per device per 3-minute window**, so `D_max = (W × u) / t_dev` puts
  **~110 devices** on one installation at a 50 % duty cycle. Storage is
  arithmetic on measured constants — **1.08 bytes per stored sample**
  (1,571,997 samples in 1.70 MB), **1.66 KB per config-object row** (35,330
  rows / 56 MB), ~**0.45 MB per server policy**, ~**70 KB per retained
  source-of-truth version** — and the surprise is that the **config index
  outgrows the metrics store roughly 2:1**, because the store costs ~1,500×
  less per data point. `INSTALL.md` §1.1 now says it is a floor and links the
  tiers; the user guide says it where the intervals that move it are edited.
- **The alert engine states the machine's condition when it cannot raise a
  finding about it.** Every finding is recorded and dispatched *through the
  database*, so the one condition the engine can never report is the one that
  takes the database down with it. Measured: a node filled its disk, PostgreSQL
  spent five hours in crash → recovery → PANIC unable to write a checkpoint,
  `satom-alerts` failed every fifteen minutes with a connection trace, and the
  words "filesystem full" appeared nowhere — while `/healthz` answered 200
  throughout. Disk thresholds existed (warn 80 %, crit 92 %) and were useless
  for exactly that reason. The wrapper now prints `df` / `free` /
  `/proc/loadavg` to the journal on failure: no database, no network, nothing
  that can be down at the same moment. It is a legible failure, not a fix —
  free space still has to be watched from outside the node.

### Fixed

- ⚠ **A decline is now honoured in the fields that NAME the declined section.**
  Declining a section removed the item from the plan and stopped there — while
  the profile that **named** it was still written with the **source's** value
  for that field. The destination ended up naming a sub-policy that box does
  not have, and this firmware answers such a write by seating a default of its
  own. The operator who asked to keep the destination's original got **neither
  tree**. Two repairs, because only one of the two situations has an original
  to keep: an item that already **exists** at the destination has the field put
  back to the value the destination reads *today* (never to a blank — on this
  firmware an empty reference field is not "no profile", it is an unparsable
  one); an item that is itself a **create** has nothing to keep, so it is
  dropped too, **transitively**, and named in the report.
- ⚠ **An accepted row whose parent object was declined is dropped too.** A row
  does not *name* its parent in a field — it is addressed by `parent_mkey` — so
  matching payload values alone let it survive and be written with `?mkey=`
  pointing at an object that was never going to exist. Parenthood is matched on
  the **pair** (collection, key), so two unrelated objects sharing a name cannot
  drag each other's rows out of the plan. A test that asserted the old
  behaviour was correcting the record, not the code: it had pinned the defect.
- **The destination row is fetched by the call that decides**, not after it. A
  revert with no destination snapshot has nothing to revert *to*.
- ⚠ **Entering the certificate table is refused at the top level on an
  ADOM-enabled appliance** and accepted on one without. The existing import sent
  its whole block — PEM and private key included — starting with that line, so
  on half a fleet everything after the first rejected line was interpreted at
  whatever prompt happened to be current. One scope primitive now, three
  callers.
- **Three options never reached the engine from HTTP.** `dst_wpp`,
  `wpp_only_if_missing` and `reconcile_rows` were not parsed in `_parse_action`,
  so nothing a browser sent could reach them. An option the engine honours and
  the HTTP layer drops is worse than an absent one: the service reads its own
  default and the run looks like it obeyed.
- **Subtree membership is matched by identity, not by `==`.** `CloneItem` is a
  dataclass, so two rows carrying equal fields compare equal and a value test
  could pull an item outside the profile subtree into a decision nobody was
  asked about.
- ⚠ **The pre-write reference check refused saves the appliance would have
  accepted.** `waf/ftp-protection-profile` is resolved by the CLI and refused by
  REST with errcode **-20001** on 7.6.8 — and -20001 is precisely what the
  client classifies as `absent`, one of the two states that license a rejection.
  Every valid FTP server-policy save came back as *"this firmware has no
  waf/ftp-protection-profile collection"*. The mapping itself is correct and the
  dependency tree needs it, so the fix is that a collection REST cannot read is
  now an `unverified` warning and never a refusal, from **one** table
  (`fortiweb_field_schema.REST_UNREADABLE`) that the clone derives its own from
  — the two can no longer disagree about which collections are readable.
- ⚠ **Sentinel's `arm` form carried no CSRF token**, so the one form in the
  product that arms an automatic blocking response was rejected on submit with
  *"your session expired or the form was stale"*. Every other form on the page
  had one.
- **Literal PEM private-key headers** in a template placeholder and two test
  fixtures. The release publisher's secret scanner aborts on these and cannot
  tell a fixture from a real key; the headers are now built at runtime.
- **Five Sentinel endpoints were on neither the concept map nor its exclusion
  list**, so the map's own guarantee — every page is mapped or excluded with a
  written reason — was false, and Sentinel was unreachable from search.
- **Internal node names in shipped source** (four files, prose only).
- **A guard that passed alone and failed in the suite.** The store-read-failure
  test induced its failure by running with no Flask application context, which
  is true when the file runs by itself and false the moment an earlier module
  leaves one pushed — then the store reads fine and the test fails on a healthy
  code path. It now raises from the ORM call itself.

### Documentation

- The settings intro claimed **24 panels in 8 groups**; the live shape is
  **26**, and the two missing were **Vault** and **Sentinel**. The concept-map
  section claimed 84 mapped / 111 excluded pages against a live 88 / 112.
  Both are guarded, both had drifted since the pages were added.

## [1.11.0] - 2026-08-20

### Added

- **Sentinel: the remaining device transports, captured rather than specified.**
  `block_country` and `raise_protection` were run against a live FortiWeb 7.6.8
  and read back, so the catalog is now 4/4 — with one of the four labelled a
  *hand-off* rather than counted as executable. Both captures corrected the
  design rather than confirming it:
  - the geo child collection is **`country-list`, not `members`**, and its key
    is **`country-name` carrying a full country name**; `{"country": "AD"}`
    answers `errcode -7950`. The source country is therefore stored verbatim as
    the device reported it, and the transport refuses a short code with a
    reason instead of guessing an expansion;
  - **a wrong child path is not an error on this appliance.** `GET
    waf/geo-block-list/members` answers **200 with the parent object**, so a
    verification that trusted the status code would confirm a write against an
    endpoint incapable of holding it. `_child_rows()` treats anything that is
    not a list as no rows;
  - **`raise_protection` has no device-side timer**, unlike a blocked address.
    Its undo is a write, so the previous profile is read off the device first
    and carried in the handle, and rollback **refuses an empty binding** —
    unbinding a profile would strip protection from every client of the policy,
    which is worse than the state being undone.
- **Gate `executable_mechanism`.** `tune_signature` writes nothing to an
  appliance; it drafts a carve-out that a person applies in the existing
  exception flow. It is refused by name, ahead of the autonomy gate, so the
  console says where the work happens instead of "level too low" — which was
  true and useless, because no level would have helped.
- **`actions.GATE_ORDER`** publishes the thirteen gates as data, and
  `/sentinel/docs` §2 renders **four flow diagrams** — reference architecture,
  processing pipeline, the decision ladder, and the response / verification /
  rollback loop — as inline SVG. No chart library and no JavaScript, so they
  render in an offline bundle and in a print. The ladder is generated from
  `GATE_ORDER`, and a test asserts that a full pass through `evaluate()` emits
  exactly those names in exactly that order. The same four diagrams are in
  `docs/sentinel-architecture.md` §2.
- **Country blocking is armed separately from address blocking** on the Context
  page. One button doing both would make the larger decision a side effect of
  asking for the smaller.
- Setting **`sentinel.hardened_profiles`** — the only profiles
  `raise_protection` may move a policy onto. Empty by default, which means that
  action can never run: the profile bound to a policy is the security posture
  of every client behind it, and Sentinel must not be the one choosing it.
- The three Sentinel scheduled actions joined `satom execute seed actions` and
  `satom diagnose install`, so a fresh install is armed and a missing sweep is
  reported. Without the sweep the module has every table, page and gate, opens
  no incident, and looks exactly like a quiet week.
- `satom-responder.timer` and `satom-responder.service` are installed and
  enabled by the installer. Expiry of a live block lives in that tick: a node
  without it can hold a block that nothing will ever lift.

### Fixed

- **The response runner had no role guard.** Found by reading the standby after
  the rest of this round had shipped: the timer is present there and disabled,
  which was correct only because nobody had enabled it — nothing in the code
  said so. Two nodes applying and expiring against the same appliance would
  race, one deleting the member the other had just written, and the winner
  would depend on tick order. The read-only replica is not the guard either:
  relying on it turns a design error into a database error at 3am inside the
  one component that changes firewalls, and it evaporates the moment a standby
  is promoted. `tick()` now refuses on anything that is not the primary, and
  `unknown` counts as not-primary — a node that cannot say what it is must not
  be the one writing enforcement.
- **A run without the production environment now refuses instead of reporting
  a clean pass.** `python -m app.cli_sentinel` binds the config at import time,
  before wsgi loads the `.env`, so a run from a bare shell (systemd passes it
  via `EnvironmentFile`; `runuser` does not) falls back to the SQLite
  development database. Every query then succeeds against an empty file: no
  actions to apply, no TTLs to expire, and a clean-looking tick while a real
  block sits on a firewall. The refusal names *that*, and says which unit to
  use instead. `wsgi.py` additionally loads the `.env` beside itself rather
  than whichever one the working directory happens to reach.
- **`satom get system health` did not know about the response runner.** TTL
  expiry happens in that timer's tick, so a node where it is off can hold a
  block nothing will ever lift — and the one output an operator reads to answer
  "is this node healthy?" was silent about it. It is not in `RESTARTABLE`: like
  the update runner, it is the component that writes to appliances, and a CLI
  verb that restarts it re-enters the privilege boundary sideways.
- **`sentinel_event.country` was `VARCHAR(8)`.** FortiWeb reports `srccountry`
  as a full name, so a source in the United States was recorded as `United S` —
  mislabelled on the page, and stripped of the one value the geo block list
  accepts. Widened to 64 on both the event and the incident; the existing
  boot-time widener applies it in place.

### Added

- **Sentinel phase 7 — a response that can actually execute, for exactly one
  action.** `block_ip`'s transport was captured from a live FortiWeb 7.6.8
  (create list, add member, re-read, delete member, delete list, zero residue),
  so it is now marked verified and the last gate lets it through. Execution
  runs in a separate unit (`satom-responder.timer`, once a minute) which
  re-evaluates every gate at the moment it acts and asks the appliance whether
  it can enforce before writing. Applied is proved by re-reading the object,
  never by the 200. Effectiveness is judged separately: an action that landed
  and changed nothing takes its incident back out of `mitigated` and is never
  retried. Expiry runs even with the kill switch off, so disarming cannot
  strand a live block, and the IP list carries a device-side block period so
  the appliance lifts it even if Sentinel is down.
- **Sentinel phase 8 — autonomy, shipped disarmed.** A policy at level 3 skips
  the approval step for a decision the gates already permitted; it can never
  raise a ceiling, widen an action or extend a TTL, and the effective level is
  still capped by the catalog (`block_country` stays at *recommend* whatever an
  operator sets). Proposals are deduplicated per incident and action, so one
  decision stays one row across sweeps.
- Sentinel Context page gained **response arming**: binding Sentinel's IP list
  to a policy's protection profile, as an explicit human action recorded in the
  audit log. The response runner will not do this for itself.

### Removed

- **Sentinel action `rate_limit_ip`.** Probing fortiweb12 showed the route its
  mechanism named (`waf/http-access-limit`) answers `-20001 invalid URL` on
  this firmware. FortiWeb's flood-prevention rules apply to every client of a
  profile, not to one address, so the entry promised a blast radius of one
  source that no available mechanism can deliver. Orphaned policy rows are
  pruned unless actions reference them.

- **SATOM Sentinel — security correlation and (proposed) autonomous response.**
  A new module at `/sentinel` that correlates FortiWeb attack signatures, HTTP
  response outcomes, appliance counters, VM and hypervisor metrics and
  vulnerability intelligence into single incidents, each of which explains
  itself from measured evidence. 14 tables (`sentinel_*`), a services package
  (`app/services/sentinel/`), four pages (console, incident, context,
  documentation), a response-policy page, a Settings section and three
  scheduled actions (`sentinel_sweep`, `sentinel_baseline`,
  `sentinel_vuln_sync`). Full write-up: `docs/sentinel-architecture.md`.

  The decisions worth knowing before reading the code:

  - **The language model is not in the deciding path.** It reads a finished
    incident and writes prose plus a recommendation from a closed enum; it has
    no tools, no network of its own, no credentials, and cannot change a score.
    The number that gates a firewall change has to be reproducible during a
    post-mortem, and a sampled one is not. With every AI component down, the
    pipeline still detects, scores, explains and gates — it loses the narrative.
  - **Baselines are median + MAD per hour-of-week, not mean + sigma.** A
    security baseline is trained on data containing attacks; with a mean, each
    flood raises the centre so the next one scores as *less* anomalous. Flat
    series cannot produce an infinite deviation, and immature buckets never
    fire.
  - **Negative scoring factors are half the value.** A wall of attacks the
    appliance blocked does not page anyone; an exploit aimed at software the
    backend does not run is noise; and an authorised scanner produces a
    byte-identical log to an intruder, so context outweighs any single positive.
  - **An unmeasured layer reports `unknown`, never "no impact".** Those drive
    opposite operator decisions. `None` survives from the correlator to the page.
  - **Vulnerability enrichment never leaves the node.** A live per-incident
    lookup would hand a third party a real-time map of the fleet's attack
    surface. The mirror sync is a separate, off-by-default switch, and a test
    asserts the incident path opens no socket. EPSS and CISA KEV outrank CVSS.
  - **Response ships as proposals only.** All five catalog entries are marked
    unverified and the last gate refuses them, because a live sweep on
    2026-08-20 found 22 of 237 documented FortiWeb routes answer `-20001
    "invalid URL"` — written from the manual, never validated on a device.
    TTL is the rollback; `block_country` can never be autonomous.

- **`http_status` and `infra` collectors** joined the fleet collection
  registry, so their cadence is edited on the same page as every other
  collector. `http_status` counts response classes from the **traffic log** —
  `policy_status` was probed live against fortiweb12 (7.6.8) and carries no
  response-class counters at all, so an earlier draft reading `http_2xx` from
  it would have published a flat line of zeros indistinguishable from a quiet
  service.

- **`HypervisorClient.vm_metrics()` / `node_metrics()`** — telemetry as an
  optional provider capability, implemented for Proxmox. A backend that cannot
  answer raises and the caller reports the layer as unknown. Cumulative
  counters are published as counters so the store derives rates and survives
  the reset a VM restart causes.

- **The step that actually removes the local copy.** Settings → Vault gained a
  *Remove the local copies* card (`scrub_local_copies`, route
  `/settings/vault/scrub`). Until it runs, switching to `vault` only changes
  where the NEXT write goes: every credential already stored keeps its Fernet
  copy, and the key that decrypts it keeps sitting on the same disk — so the
  page could say `vault only` while nothing had actually moved. The scrub
  replaces each local copy with the sentinel, and it is deliberately separate
  from the migration because copying is reversible and this is not. It is
  refused unless the vault is the authoritative store (in `mirror` the local
  copy is the documented fallback), it is **dry-run by default**, and every
  secret is read back FROM THE VAULT and compared with the local plaintext
  before that plaintext is destroyed — a vault copy that is missing, different
  or unreachable means the local one is the last working copy, so the row is
  kept and reported as failed. Guards in `tests/test_vault_scrub.py`
  (safeguards §104).

- **A credential can now live in an external vault — and by default it still
  does not.** New Settings → Vault tab (`services/secret_backend.py`) points the
  product at an OpenBao or HashiCorp Vault KV v2 mount for appliance passwords,
  the LDAP/AD bind password and the FortiAuthenticator shared secret. Storing
  them in SATOM itself is **unchanged and remains the default**: an install that
  never opens this tab contacts nothing and behaves exactly as before. The
  reason to add the option is that `FERNET_KEY` lives on the same host as the
  database it decrypts, so whoever reads that disk reads every appliance
  password; a vault moves the key material off the node. Three modes, and the
  page says plainly what each one costs: `local` (Fernet only), `mirror` (both;
  vault-first reads with local fallback — safe to roll back from, but the local
  copy still exists so the exposure is **not** yet closed), and `vault` (the
  vault is the only copy — the mode that closes it, and the mode in which a
  vault outage makes credentials unavailable). In `vault` mode a failed read
  **raises**: returning the local sentinel would hand the literal
  `__stored-in-vault__` to an appliance as a password, which fails a login while
  looking like a wrong credential rather than an outage. Migration is dry-run by
  default and reads every secret back before counting it, because a write that
  returns 200 and stores nothing is invisible to a caller that only checks the
  status code. Only the auth token is cached, never a secret value — a fleet
  sweep must not open one session per appliance, and the vault's audit log has
  to stay truthful about who read what. Guarded by
  `tests/test_secret_backend.py` (30 tests, safeguards §103).

### Fixed

- **A stale process could send `__stored-in-vault__` to an appliance as a
  password.** Both vault read paths now raise when the local column holds the
  sentinel and the vault did not answer in that process. This is not
  hypothetical: `satom-scheduler` is a separate long-lived process, and the one
  still running pre-vault code sent the marker to the whole fleet the moment the
  local copies were removed — every collector returned 401 and
  `satom_scrape_up` fell to 0, with not one line in the vault audit log to
  explain it. Returning the marker turns "this process cannot reach the vault"
  into "the password is wrong". **Restart every SATOM process after changing the
  secret backend, not just `satom.service`.** Guards in
  `tests/test_vault_sentinel_never_sent.py` (safeguards §106).

- **`.git/config` was world-readable, and it holds the push token.** This
  product embeds its Gitea credential in the origin URL, so that file is a
  secret file — and git creates it in mode 644, which is not an error and
  therefore never surfaced. `_harden_git_config()` now narrows it to 600 from
  the writer (`git_configure`, right after `remote set-url`) and from
  `git_info`, because a repository the installer cloned never passes through
  the writer. `installers/install-satom.sh` chmods it straight after
  `git clone` as well: without that, every new installation re-introduces the
  defect. Guards in `tests/test_git_config_perms.py` (safeguards §105).

- **A policy with a Lua script could not be cloned — the reference field holds a
  LIST, not a name.** Measured on FortiWeb 7.6.8: a policy with one script reads
  `scripting-list = "HTTP_CUSTOM_REPLY "` and with two,
  `"HTTP_CUSTOM_REPLY SSL_COMMANDS "` — a space separator **and a trailing
  space**. `clone.referenced_names` took the whole value as one name, so the
  source read answered `-3 The entry is not found`, the item's payload came back
  empty and `validate_completeness` **refused the entire clone** with *"source
  tree incomplete"*. The ONE-script case failed too, not just the multi-script
  one — which is why having the script on the destination never helped: with the
  name wrong, the destination was never consulted. The split is declared **per
  field** (`_LIST_REF_FIELDS`), not applied globally: a space is a legal
  character in a FortiWeb object name nearly everywhere (a health check, a URL
  access policy, a WPP and an SNI policy all accept `"zz probe space"`, and one
  named `"zztrail "` keeps its trailing space and can only be deleted with it),
  so a global split or strip would turn one legal name into two that do not
  exist — the same block, moved. It is unambiguous here because the scripting
  collection refuses a name containing a space (`-2004`). The same parser feeds
  the **deep-capture SoT snapshots**, which had silently been omitting the
  script from every snapshot of a policy that binds one, and the **file-backed
  content read**: with the trimmed name the source returns the Lua source
  (2 559 bytes measured), with the trailing space it returns nothing, so a
  script created at the destination would have been an empty shell.

- **Server Objects is the FortiWeb menu again — entries, order and the tabs
  inside them.** The curated menu had drifted from the appliance and nothing
  failed, because a menu that is missing an entry still renders. Measured
  against two independent oracles (the appliance's own Angular bundle on
  FortiWeb 7.6.8, and a 554-page sweep of the 7.6 admin guide):
  **Certificates has TWELVE entries, not the ten SATOM showed** — and the near
  miss in the count hid the real shape, because three of those ten (*CA Group*,
  *TSL CA*, *Intermediate CA Group*) are **tabs inside another page**, not menu
  entries. Six entries were missing outright (*XML Certificate*, *URL
  Certificate*, *Sign CA*, *Certificate Verify*, *Public Key Pinning*, plus
  *Multi-certificate* and *Offline SNI* as tabs), and so were *Traffic Mirror*,
  *Global Allow List*, *Policy Based Allow List* and *URL Replacer* elsewhere
  in the section. A GUI page and a REST collection are not the same unit:
  FortiWeb renders siblings as **tabs of one page**, so the menu now models
  pages (one sidebar row) owning tabs (one collection each), and the object
  list grew a tab strip. **No new REST endpoint was needed — all 40 collections
  were already in the registry**; every one answers HTTP 200 live on 7.6.8.

- **`Intermediate CA` pointed at a collection that does not exist.**
  `system/certificate.intermediate` answers **HTTP 500 / errcode -20001** on
  every FortiWeb measured (fw09, fw11), while the shipped API matrix already
  recorded it as `absent`; the collection that exists is
  `system/certificate.intermediate-certificate`. That page had never worked on
  any firmware. The phantom is also suppressed in the generic Configuration
  browse, so it cannot come back through the "everything else" list.

- **`Virtual IP` moved to Network, where FortiWeb files it**
  (`/ng2/network/virtual-ip`) — and it was given a home on the way:
  `system/vip` categorises as `Other`, so dropping it from Server Objects
  without adding it to the Network menu would have left the collection
  unreachable from the entire UI.

### Added

- **The appliance roster folds the ADOMs of one chassis under their device,
  and device-wide verbs live on the root row only.** A FortiWeb in ADOM mode
  can only be registered one row per ADOM (the auth token carries exactly
  one), so the list printed one physical appliance as N devices — each of them
  offering firmware, the CLI console and the config-backup vault. Those act on
  the BOX: one flash partition, one boot image, and one `execute backup` that
  contains every ADOM, so "restore `@adom_dev`" would in fact have restored
  the other ADOMs too, with nothing on the page saying so. The other ADOMs now
  render as folded children of the device row (the fold remembers what you
  OPENED, and a search still reaches inside it), and those verbs are offered
  — and enforced on the route, not just hidden — on the row whose ADOM is
  `root`. **Classification (zone / line / department), policies, discovery and
  each row's own credential stay per-ADOM**, which is the reason they are
  separate rows at all. A device registered once is unaffected.

- **SATOM keeps the file-backed WAF objects FortiWeb will not give back.**
  Seven API-Protection types (XML Schema, XML DTD, WSDL, OpenAPI, gRPC IDL,
  JSON Schema and Lua scripting) store only their NAME in the configuration,
  so the tree clone alone created them EMPTY at the destination — and a
  validation rule bound to an empty object answers `-7694`. Worse, when the
  rule already existed on the target, the shell landed silently and the policy
  ran with that protection off. New **WAF Artifacts** page (`/artifacts`) and
  a content-addressed store under `data/artifacts/` (same split, directory and
  replication path as the SoT store — the standby datasync and the system
  backup bundles already carry it). Three verbs: **upload** (an operator hands
  SATOM the file — the only way XML Schema, WSDL and gRPC IDL can ever enter
  the store, because no FortiWeb will read them back and they are absent from
  the device's own `full-config` backup), **capture** (read it live off a
  device; available for the four readable types) and **push** (write a stored
  copy onto an appliance).
- **Clone and migrate now copy the CONTENT, not just the name.** Every
  file-backed object in a plan is resolved before the first write — source
  device first, SATOM's store second — and uploaded through the per-type
  multipart endpoint, which is not under `/cmdb/` and uses a different field
  name per type. Verified end to end against two live appliances: the copy
  lands with its bytes and the rule that references it links with `200`.
- **A pre-flight ALERT the operator accepts or rejects.** When no content can
  be obtained, the checklist raises a `warn` (never a block) naming the object
  and the consequence, and Apply stays disabled until the operator ticks
  *"clone anyway"*. The check stays `warn` after acceptance — a checklist that
  turns green because someone ticked a box has stopped describing the device.

- **Interfaces are declared with a PURPOSE at device registration.**
  `ApplianceInterface` gains `role` (a controlled vocabulary: management,
  front-side traffic, back-side traffic, one-arm, inline pair, HA sync, HA
  reserved, mirror, unused, other) and `segment` (free-text network, e.g.
  "DMZ / VLAN 20"). Both are editable on the appliance edit page and, new,
  in the **Add Appliance** dialog — the registration form collected no
  interfaces at all before. Existing ports read as **Not declared**, which is
  the truth: a role cannot be back-filled from the device, because the device
  has no field that says what a port is *for*. Rediscovery keeps refreshing
  name, media type and IP and never touches the role or the segment.

- **Clone/migrate now checks which interface the copy will be bound to.**
  A new pre-flight row resolves every `system/interface` binding the planned
  tree carries (`interface` on the VIP and the vserver row, plus the policy's
  `data-capture-port` / `block-port` — the field list is derived from
  `fortiweb_field_schema.REF_ENDPOINTS`, not restated) against the
  destination's live port inventory, and a **selector** lets the operator
  re-bind each source port to a destination port. Three outcomes, previously
  one: the port is **missing** at the destination → block; the port exists but
  neither side declared what it is for → warn; roles (or segments) disagree →
  warn naming both. The chosen mapping is applied to the payload that is
  actually written (`clone.set_interface`), per port name, on `create` items
  only, and it is forwarded by `migrate_to` as well as `clone_to`.

- **Chassis grouping — several appliance rows that are one physical device.**
  A FortiWeb in ADOM mode partitions its config, not its hardware, and the
  auth token carries exactly one ADOM with no per-request override, so a
  multi-ADOM device can only be registered as one row per ADOM.
  `models.chassis_key` / `chassis_siblings` derive the grouping from
  (kind, host, port) — never stored, so it cannot go stale. Consequences
  wired up: **capacity headroom counts the whole chassis** (three ADOM rows
  were getting three independent budgets against one CPU, and each reported
  room) and says so in its message; **interface roles resolve chassis-wide**,
  with a row's own declaration winning over a sibling's; and clone/migrate
  **warns when source and destination are the same box** — a "migration"
  between two ADOMs of one chassis does not move the policy off the hardware,
  the ports and the outage domain.

  Measured live on fortiweb09 (FortiWeb-KVM 7.6.8, `adom-admin enable`, three
  ADOMs): `server-policy/policy` differs per ADOM, while `system/interface`
  and `system/vip` are identical from all four. That asymmetry is the whole
  basis for the split above.

### Changed

- **The manual documents how a change is promoted and how it is tested.**
  `docs/engineering.md` §2 gains the two-node code path — the standby fetches
  from the **primary** over a restricted, read-only SSH key instead of from the
  remote, which is what makes "validated on both nodes before it reaches the
  remote" achievable at all — including why `origin` must be reassigned rather
  than added (`self_update.py` hardcodes the remote name), why the HA rsync key
  must not be reused for it (it authenticates as root), and the euid wrapper
  that lets one keypair serve both the reconciler and the privileged runner.
  §10 now states the testing policy: targeted runs by zone, mutation testing as
  the substitute for breadth, judging by exit code (`rc == 1`, never a grep for
  `failed`), one pytest per checkout, and what a suite run on the standby does
  and does not prove — it exercises SQLite in a tmpdir, so it measures the disk,
  not the deployment. `docs/release-pipeline.md` gains **Stage 0**, the ordered
  promotion chain with the gate at each hop, and `docs/git-backup-and-outage.md`
  is corrected: a standby wired to the primary keeps converging during a remote
  outage.
- An unresolvable file-backed object is **SKIPPED, not created empty**: it is
  marked `no-content` (`~` in the plan text, its own bucket in the clone
  report) and the referencing rule then fails loudly with `-651` instead of
  landing a shell that makes the destination look configured.
- **A migrate no longer disables the source when anything was skipped.**
  Accepting a missing artifact authorises an incomplete COPY, not an
  unprotected cutover; `failed == 0` does not cover this, because the
  referencing rule only fails when it is itself in the plan.

### Fixed

- The *View Backups* link is emitted once, not once per branch. Splitting it
  into an owns-the-chassis case and a points-at-the-owner case duplicated the
  dead `fw-btn-*` spelling and pushed the frozen budget that keeps that debt
  from growing. The owner is resolved before the markup, so one anchor covers
  both cases and the rendered page is byte-for-byte what it was.
- §39 of the user guide states the live page and exclusion counts again.
  Both numbers are hand-typed prose about a generated map; the map grew and
  the prose did not, so the manual under-reported what the console contains.

- The XML DTD read is parsed with a tolerant decoder. The firmware's two-byte
  buffer over-run put an invalid UTF-8 byte inside the JSON body, so `.json()`
  raised and a **working** endpoint read as a dead one; the junk is trimmed
  without touching a legitimate trailing newline.
- The OpenAPI read no longer doubles every line break: `htmlArray` elements
  already carry their newline, and for YAML that is not cosmetic — the file
  round-trips, parses, and is not the same document.
- **A device in ADOM mode with no ADOM pinned reports an EMPTY policy list and
  no error.** With `adom-admin` enabled, `server-policy/policy` returns `[]`
  for a token that carries no ADOM — the same shape as a device with no
  policies. Any appliance row left at `vdom = NULL` on such a device shows an
  empty workspace and flags nothing. Found by enabling ADOM mode on
  fortiweb09; the row is now pinned to `root`. (No code change guards this
  yet — see the known-gaps note in `docs/safeguards.md` §101.)

- **The roster's header tiles counted ROWS, not appliances.** A FortiWeb
  in ADOM mode is registered one row per ADOM, so a fleet of ten boxes
  read as thirteen devices — and Online / Offline summed over the same
  inflated set, so two tiles describing one fleet could never agree. A
  chassis now votes once, folded on exactly the key the list groups it by;
  HA cluster members still count separately, because they are separate
  boxes with their own power supply. A fifth tile reports how many ADOMs
  those appliances carry, counted PER APPLIANCE: `root` on two chassis is
  two administrative domains with two credentials, not one name.

### Known gaps

- `system/vlan` does not exist over REST on FortiWeb 7.6.8 (`-20001`, "The
  REST API has invalid URL"), and `BaseClient.list_with_error` reports that
  500 as an **empty list with no error** — an unsupported endpoint is
  indistinguishable from an empty one. VLAN interfaces must be created over
  the CLI. Not fixed here; it is a client-layer change with a wide blast
  radius.

## [1.10.1] - 2026-08-17

### Added

- **Sharded test runner** — `scripts/run_test_shards.sh` splits the suite
  across 2-4 parallel shards (by file, never within a file) and
  `scripts/test_shard_plan.py` builds the partition, weighing files either by
  a static AST proxy or by measured `--durations=0` seconds from a previous
  run. Aggregation is by exit code only, and rc 4 (usage error) and rc 5 (no
  tests collected) are reported as errors rather than read as passes. The
  concurrency guard parses `/proc/<pid>/cmdline` as argv instead of
  substring-matching it, because `pgrep -f pytest` returns any process that
  merely *mentions* the word.

### Changed

- **`SQLAlchemy` is pinned to `2.0.52`** in `requirements.txt` (previously
  unpinned, so an offline bundle built on two different days could ship two
  different ORM versions).

### Fixed

- **Three POST buttons could never be submitted.** The Rebuild button on
  `/registry/versions`, Revoke on the section-template catalog and "Scan
  devices" on the certificate manager were plain `<form method="post">`
  blocks with no `csrf_token` hidden input, so Flask-WTF's `CSRFProtect`
  rejected every submission and the app's `CSRFError` handler flashed *"Your
  session expired or the form was stale — please try again."* The message
  blames the operator's session; the session was fine and the form was never
  submittable. The `fetch()` shim in `main.js` injects `X-CSRFToken` on every
  same-origin state-changing call, which is why JSON callers never hit this —
  a native form submit does not go through `fetch()`. New guard
  `tests/test_form_csrf.py` re-parses every template and resolves each
  `<form>` block itself, so a tokenless POST form breaks the suite in the
  commit that adds it (safeguards §100).

- **Ten buttons in the three new diagnostic tools were unstyled.** `fortiweb.css`
  defines `.btn-fw-primary` / `.btn-fw-outline` / `.btn-fw-secondary`; the
  certificate inspector, false-positive explainer and transaction tracer were
  written with the word order reversed — `fw-btn-primary` — which matches no
  selector in any stylesheet the product loads, so those buttons fell back to
  the browser's native grey bevelled `<button>` inside a flat white modal. The
  same round also substituted `fw-card p-3` for the real `fw-card-header` /
  `fw-card-body` sub-structure (16px instead of 20px, and no header tint or
  bottom border at all), titled its modals with `h5` where the two older tools
  in the same Tools menu use `h6`, sized every form control full-size next to
  `btn-sm` buttons, and built its tabs out of `<a href="#">` instead of
  `<button>`. Opening Network Calculator and then Certificate inspector from
  the same dropdown showed two different header heights and two different form
  densities. Nothing failed: the pages rendered, the handlers fired, and the
  round's own check ("0 dark-theme tokens") was true and did not verify that
  the classes it used resolved to a rule. `tests/test_tool_modal_chrome.py`
  (31 guards, safeguards §99) now resolves every `fw-*` / `btn-fw-*` class the
  tool JavaScript emits against the stylesheets the product actually links,
  and freezes the 108 pre-existing occurrences of the reversed spelling in
  older templates so the count cannot grow.

- **The suite leaked one temp directory per pytest process.**
  `tests/conftest.py` creates its temp root with `tempfile.mkdtemp()` at import
  time and nothing removed it — 2841 orphaned `/tmp/fmw-test-*` directories had
  accumulated. An inode leak rather than a byte leak, but unbounded, and
  sharding multiplies it by the shard count. Cleanup is now registered with
  `atexit` at import time.

- **The PEM guard had never looked at a JavaScript file.**
  `tests/test_no_pem_literals.py` sweeps the source tree for literal
  `-----BEGIN … PRIVATE KEY-----` headers, because the publisher aborts the
  public mirror if it finds one in *any* blob of *any* commit. Its `SUFFIXES`
  set listed `.py`, `.sh`, `.yaml`, `.json`, `.html`, `.md`, `.txt` and
  `.conf` — but not `.js`, so the guard had been passing vacuously over the
  entire JavaScript tree. The certificate inspector's textarea placeholder
  carried the header literally, and it reached a version cut. The placeholder
  is now assembled at runtime (`'-'.repeat(5) + 'BEGIN PRIVATE KEY' + …`), the
  rendered markup is byte-identical, and `SUFFIXES` gains `.js`, `.mjs`, `.ts`
  and `.css`. The lesson generalises past this one file: a guard whose scope
  is narrower than the scope of the system that actually decides — here the
  publisher, which reads every blob in history — is decorative, and every gap
  between the two scopes is a literal waiting to ship.

## [1.10.0] - 2026-08-17

### Security

- **A saved link bookmark can no longer carry a `javascript:` URL.** The only
  check on the field was that it was non-empty, so any account able to save a
  bookmark could store `javascript:…` and — once the bookmark was shared with
  the team — have it rendered as an `href` in every colleague's sidebar, on
  every page of the console, including for the read-only users who cannot
  delete it. One click ran it in this origin with the session cookie: stored
  XSS with no visible symptom, because the row renders exactly like any other.

  Links are now restricted to `http`, `https`, or a path beginning with `/`.
  An allowlist rather than a blocklist, because `data:`, `vbscript:` and
  `blob:` are the same attack in other clothes; control characters are refused
  outright, because browsers strip TAB/CR/LF/NUL *before* reading the scheme
  and `java\tscript:` navigates as `javascript:`; and a protocol-relative
  `//host` is refused despite the leading slash, since one character separates
  "a page of this console" from "somebody else's server". The check runs on the
  way **in** and again on the way **out** — a bundle restore and a Postgres
  replica both land rows without passing through the create path, so checking
  only at write time trusts every row the process did not write. A refused link
  keeps its row and states why rather than silently losing its `href`, which
  would read as a UI bug and leave the bad URL in place.

### Added

- **Three tools that know something a browser tab does not: a certificate
  inspector, a false-positive explainer and a three-leg transaction tracer.**
  Reachable from the header Tools menu.

  The **certificate inspector** takes a pasted PEM/fullchain (or an
  `openssl s_client` transcript) or probes a live `host:port`, and reports the
  chain in leaf-first order with **every link verified by actually checking the
  child's signature with the parent's key** — plus expiry, key size, signature
  hash, RFC 6125 hostname coverage and whether a pasted private key matches.
  Built because this project already paid for not having it: CT 346 served a
  chain one certificate short and the diagnosis was `unable to get local issuer
  certificate` plus a manual count. Chain completeness can come back **UNKNOWN**
  — on a node without `openssl` only the leaf is readable, and "not measured"
  is not "incomplete"; the two send you to different places.

  The **false-positive explainer** turns a pasted attack-log entry (syslog
  `key=value`, JSON, or a raw HTTP request) into the same row the device-backed
  carve-out panel consumes, and calls that same engine — so which module
  blocked, which carve-out type addresses it, which fields scope it and the
  exact FortiWeb payload are computed once, not twice. It reports the keys it
  could **not** place and the fields the entry does **not** carry with what each
  one decides, and peels percent/entity/hex/base64 layers off the payload. It
  has **no save endpoint**, deliberately: a carve-out is assembled from the
  entry as the device reported it, and pasted text is client-supplied.

  The **transaction tracer** runs leg A (through the appliance) and leg C
  (straight to the backend, carrying the same `Host`), and derives leg B — what
  the appliance forwards — from the device's own configuration. Leg B is
  labelled derived at every layer, names the object and field behind each row,
  and lists the settings it could not read separately from the ones that are
  off. The A/C diff answers *is it the WAF or is it the app?* in one sentence,
  with per-leg TCP/TLS/TTFB timing, TLS detail, and `curl` (with `--resolve`)
  and HAR exports.

  `GET`/`HEAD`/`OPTIONS` are free; a mutating method is a real write to someone
  else's application issued from inside the management network, so it needs the
  new `monitoring.probe_free` permission and an explicit per-call tick.
  Inventory destinations are always available; a free `host:port` needs that
  same permission. Cloud instance-metadata addresses are refused in every mode
  and that is not configurable. Names are resolved once and the **address** is
  dialled, with the hostname carried as SNI/`Host`, so a name cannot answer
  differently between the check and the connection. Every probe and trace,
  including every refusal, is audited.

- **The reconcile page and the firmware-line API matrix are documented, and the
  manual no longer stops at section 30.3.** Both pages shipped in the last
  two rounds and neither existed on paper: an operator could reach a screen
  offering to disable catalog entries with no written explanation of what
  `absent` means, and a preflight whose most important answer — `unmeasured` —
  is worthless unless the reader knows it is not a yes.

  `docs/device-api.md` gains **§6 Reconciling the catalog against the fleet**
  and **§7 Firmware lines: which fields a line actually serves**: the three
  sweep verdicts and which of them is evidence about the catalog versus about
  the device, the 25 % error ratio that disqualifies a witness and the live
  incident that set it, the six buckets and why `unsweepable` is not filed
  under "never measured", the firmware caveat in full, the two evidence kinds
  that are never subtracted from each other, and the CLI exit-code contract in
  which `unmeasured` deliberately does not share a code with "go ahead".

  `docs/user-guide.md` gains **§30.4** and **§30.5**, written from the screen
  rather than from the code: the cards in the order they appear, the warning to
  read before pressing Disable, and the three CLI commands for a node whose web
  interface is down.

  `tests/test_api_matrix_docs.py` (39 guards) derives every claim from the
  thing it describes — the bucket names from the report the service returns,
  the verdicts and preflight statuses from the modules that define them, the
  card titles from the templates that render them, the page addresses from the
  live URL map, and the documented `unmeasured` exit code by **running** the
  CLI entry point. A new bucket, status, card or page now fails the suite in
  the same commit that adds it, instead of quietly making a sentence false.

- **Alerting has a reference document, and the manual no longer describes a
  smaller product than the one that shipped.** Two rounds of delivery work —
  per-sink routing, the syslog/CEF feed, the signed webhook, the `alert.fired`
  hook event and its starters — left three surfaces describing the previous
  version of themselves: the hook catalog in the user guide still said six
  events on the day the seventh was the point of the release, the settings page
  still introduced the engine as routing to "in-app bell, email, and a
  syslog/CEF feed", and there was nowhere at all to read the wire contract.

  New **[Alerting & notification delivery](docs/alerting.md)**, published with
  the rest of the manual: the two delivery paths and why the feed carries no
  cooldown, the per-sink severity floor and family mask, the key-prefix to
  family map, the signed webhook envelope with a verification recipe and the
  exact retry policy, the RFC 5424 and CEF line shapes with the three severity
  scales side by side, the `alert.fired` payload and the starter registry, and
  a table of what is deliberately **not** implemented.

  The staleness itself is now a test rather than a habit. `tests/
  test_alerting_docs.py` derives every claim from the code that implements it
  — the sink roster, the family map, the event catalog, the starter registry,
  the retried HTTP statuses, both wire encodings and both severity scales — so
  adding a sink, an event or a starter without documenting it fails the suite
  in the same commit that adds it. Nothing *fails* when a manual goes stale;
  the sentence just stops being true, which is why this had happened twice.

- **The Classification catalogs are edited one value at a time, and a rename
  now moves everything that points at it.** Zones, lines and departments used
  to be three free-text boxes, one value per line. That shape cannot express
  the difference between *rename `internal` to `Internal`* and *delete
  `internal`, add `Internal`* — and to the rest of the product those are
  opposite instructions, because every appliance, baseline combo and network
  segment stores the value as a plain string with no foreign key behind it.

  Each value is now its own row, showing how many appliances, combos and
  segments reference it. Editing the text renames it and carries those
  references with it, in one transaction. Removing a value that is still
  referenced is refused until you say what happens to the references — clear
  them, or move them to another value — and the message names the counts
  rather than saying "in use". Values that are in use but missing from the
  catalog (exactly what the old textarea produced) are listed with a one-click
  button to adopt them back.

- **The device-type bucket in the rail carries the product's real name and the
  reader's own banner colour.** Grouping the bookmarks panel by Product used to
  print the raw column — `fortiweb`, `fortiadc` — in the same plain type as a
  zone or a department, so the one bucket that says *what kind of box this is*
  was the hardest one to pick out. It is now labelled from the ADOM registry
  (**FortiWeb**, **FortiADC**, **FortiAnalyzer**, **FortiAuthenticator**) and
  set in a pill washed with the top-bar banner that reader chose on their own
  profile, at 8% — a hint of colour on paper, not a coloured label. Only the
  fill is tinted: the text keeps the primary token, because a word painted in
  an 8% brand colour is a word nobody can read. A kind with no registry row
  still gets its first letter raised and every other letter left alone, and
  `(unclassified)` stays plain text — it is a sentence about the record, not a
  product. The node key is still the raw stored value, so renaming a product
  in the registry cannot collapse the branch of every reader who had it open.

- **A direct link to the device, beside the link into SATOM.** Every device row
  in the rail — and the `Host` line on the appliance detail page — now carries
  a second destination: the name opens what SATOM knows about the appliance,
  the arrow opens the appliance's own management UI in a new tab. Both come
  from one function, so the two surfaces cannot start disagreeing about where a
  device lives.

  The URL is **derived from `host`/`port` on every render, never stored**: a
  `mgmt_url` column is a second copy of the management address, and the copy is
  the one that survives a re-IP. The host is **parsed before it is allowed to
  be an authority** — `host` is free text an administrator types and the link
  is rendered for everyone, read-only users included, and `fw1@evil.example`
  renders as "the device" while navigating to `evil.example`, because
  everything before the `@` is userinfo. An IPv6 literal is bracketed. The
  scheme is always `https` and is **not** read from `verify_ssl`: that flag
  records whether *we* trust the certificate, and a self-signed appliance is
  still an HTTPS appliance. `rel` carries both `noopener` and `noreferrer` —
  the destination is an appliance under audit, and either token alone leaves
  half of it open. A device with no usable address (the retired appliances
  parked on `.invalid`, which RFC 6761 guarantees never resolve) keeps its
  slot, dimmed, with the reason on it: a link that looks live and dies in the
  browser makes people debug the device instead of the record.

- **A bookmarks rail** — a collapsible right-hand panel, shaped like a browser
  sidebar: folders with a folder icon and their name beside them, nested groups
  that collapse, and a search box. Everything boots **collapsed**, and the
  stored preference is the set of nodes left **open**, never the set left
  closed — on a hundred-appliance fleet an empty preference has to mean "all
  folded", and storing the collapsed set would make "no preference yet" mean
  "expand everything". Three stores that are always present (Favourites,
  Folders, Shared) plus **one inventory lens**.

  The lens is **derived, never copied**. It lists the live inventory rather
  than the bookmark table, so the panel is useful before anybody has
  bookmarked anything and a device added to the fleet appears with no
  migration; starring or filing one *adopts* it, idempotently, and that is the
  only thing that creates a row. Re-zoning a device re-files it with no write
  anywhere. A bookmark stores the appliance **id** and nothing else: a stored
  copy of the name, zone or product is the first field to go stale after a
  rename, and it goes stale invisibly.

  **The reader's permissions decide the list, never the sharer's.** Every row
  passes the ADOM stamp filter and `visible_appliances` for the person looking,
  so sharing is not a way to hand somebody a device in maintenance or one from
  another product. No by-id route touches `Bookmark.query.get`: an id belonging
  to somebody else resolves to **404, never 403**, because a 403 confirms the
  row exists and turns the favourite button into an oracle for enumerating what
  other people have marked. Sharing moves a bookmark rather than copying it —
  two rows diverge and nobody can say which one is authoritative — and it is
  **audited**, because it changes what every operator sees. Placement is the
  one exception: a shared bookmark is filed **per user**, so each person keeps
  their own arrangement of the same row, and a row nobody has filed yet appears
  in **Shared**, which is therefore the default destination rather than a
  folder anybody can delete. Hiding is per-user and never silent: the counts of
  unfiled and hidden rows render whether or not the tray is open, because "it
  never reached me" has to stay checkable.

- **The grouping order is a per-user setting** (Profile → *Bookmarks — grouping
  order*), and the lens root is **named after it**. A `<select>` in the panel
  could only answer "how is this grouped right now" once you opened it, and
  four fixed roots answered a question nobody asked — "how *could* it be
  grouped". Any order of Line, Zone, Department, Product, Network segment and
  Tag nests outside-in; the default reproduces the previous fixed root exactly,
  so upgrading cannot re-shape a tree nobody asked to re-shape. A dimension may
  appear **once**: below its first level every device already shares one value,
  so a repeat adds depth and no information, and the form refuses it by name
  rather than silently de-duplicating — a form that saves something other than
  what was submitted leaves the page disagreeing with the tree. Blank levels
  are skipped, an empty order is refused (the alternative takes every device
  off the panel to honour a preference nobody can see they set), and saving is
  audited. Reading the preference is deliberately forgiving where writing it is
  strict: the rail renders on every page in the console, so a value a later
  release stops recognising degrades to the default instead of taking the whole
  product down.

- **A signed, retried webhook sink** (`services/alert_webhook.py`), configured
  by form on Settings → Admin console → Alerts. One HTTP POST per evaluation
  carrying every finding that sink accepted — not one call per finding, which
  would put back the hose the router exists to remove. It is a *notification*
  sink, not a feed: it carries the cooldown, it counts towards `dispatched`,
  and it obeys the engine master switch, because a chat channel is a recipient
  and a recipient that hears the same finding every fifteen minutes mutes the
  channel. Three things in an HTTP POST are the product's job rather than the
  integrator's, and all three are here: **a versioned envelope** a receiver can
  still parse next year; **an HMAC-SHA256 signature over `v1:<timestamp>:<body>`**
  — the timestamp is *inside* the signed string, because a signature over the
  body alone stays valid forever and a captured POST replays cleanly; and **a
  selective retry** — 408/425/429 and 5xx are repeated with bounded backoff
  while every other 4xx fails once and reports the status, since repeating a
  rejected request neither fixes it nor tells anyone. The body is serialised
  **once** and those exact bytes are both signed and sent: signing one dump and
  sending another yields a signature the receiver correctly rejects whenever
  key order differs, intermittently, with nothing on this side ever seeing an
  error. Two encodings ship — the SATOM envelope and the flat `{"text": ...}`
  that Slack, Mattermost and Rocket.Chat accept. The signing secret is stored
  Fernet-encrypted and **never rendered back into the page**, so a blank field
  means "unchanged" and removing one needs its own explicit control. Private
  network targets are allowed on purpose: an automation host on the management
  LAN is the normal case in every install this ships to.

- **`alert.fired` in the integration-hook catalogue, plus Telegram, Slack and
  Teams starters.** The hook runner — sandboxed subprocess, secret vault,
  audit, dry-run — has existed for months with six events, none of them about
  alerts. It now has a seventh, fired once per finding that passed a new
  **"Integration hooks" sink** (default off, same severity floor and family
  mask as every other outlet). Hooks are **enqueued, not delivered**, and the
  engine now says so: they are stamped into the cooldown, because otherwise a
  Telegram starter re-sends every finding every fifteen minutes, and they are
  **counted as `queued` and never as `dispatched`**, because the runner that
  executes a hook is a separate systemd unit that has been found disabled on a
  live node. A sink enabled with **no hook bound to the event stamps nothing** —
  crediting an empty dispatch would suppress the finding for the whole window
  on behalf of a subscriber that does not exist. The three starters are
  examples the operator owns on save, not adapters SATOM maintains: each
  encodes the part that is hard to discover — the Teams Adaptive-Card
  attachment envelope (sending the bare card returns 202 and posts nothing),
  Telegram's parse-mode trap (alert detail is full of `_ * [` and a Markdown
  parse_mode turns the message into a 400), and that a non-2xx must be reported
  rather than swallowed.

- **Issue tracker integration (Jira Cloud, OpenProject, Vikunja).** Settings →
  Integrations gains a native ticketing backend, so raising the CRQ on a change
  request opens a real ticket and writes its reference and URL back onto the
  change — with no Python hook to write or maintain. Until now the only route
  to a tracker was `data/integrations/<slug>/hook.py`: the right tool for a
  bespoke in-house CRM, the wrong one for the three trackers most people
  actually run. Asking a network operator to write Python — and to get its
  timeouts, retries and secret handling right — so SATOM can POST one JSON
  document is a configuration problem dressed up as a programming problem. The
  ticket carries the appliances **by name**, the affected services, the stored
  pre-upgrade evidence and, named rather than implied, the appliances that have
  none. **The Python hooks are not replaced** and still fire alongside it.
  Each backend's real trap is handled rather than left to the operator:
  Vikunja creates with `PUT` (`POST` is its *update* verb, so a POST creates
  nothing and does not look like a failure), Jira API v3 takes Atlassian
  Document Format rather than a string description, and OpenProject
  authenticates with the literal username `apikey`.
- **A change that already carries a CRQ reference is never given a second
  ticket.** Idempotency is enforced in `cr_orchestrator`, not by disabling a
  button, so a double-click, a browser retry or a second operator cannot each
  open another ticket for the same window — after which change management has
  no way to tell which one is real.
- **The tracker's Test connection probes the configured project, not just the
  credential.** A token that authenticates but cannot see the project is
  otherwise indistinguishable from a working one until a change window is
  opening. The probe reports who it authenticated as *and* whether the project
  is reachable, with the elapsed time; a tick with no numbers behind it is not
  evidence.

- **The API surface is now keyed by FIRMWARE LINE, not just by API version.**
  FortiWeb 7.6 and 8.0 both speak `v2.0`, so the registry's `api_version` axis
  cannot express the difference between them — and the difference is real.
  Measured on this fleet's own artifacts: `admin` has 40 fields on 7.6 and
  **42** on 8.0 (`fortiai`, `old-password`), `global` 60 vs **63**, `ntp` 3 vs
  **4**. Building a payload against one line and writing it to a box running
  the other is the failure that had no name. New `services/api_matrix.py`
  derives, per `(product, firmware line, endpoint)`, what that line was
  *observed* to serve, out of evidence that was already on disk and already
  unread: the rediscovery sweep records both a per-endpoint verdict and the
  objects it read back, and the keys of those objects **are** the fields that
  firmware serves. New **API versions** page in each product's API hub
  (`/web/registry/versions`, `/adc/api/versions`, `REGISTRY_EDIT`) with a
  line-to-line comparison, and `satom get api versions` / `get api preflight`
  on the CLI.

- **Preflight**: `satom get api preflight <appliance|line> <object> <field>…`
  answers whether a payload would be understood on that line *before* it is
  written. Five outcomes, deliberately not four: `ok`, `unknown_fields`,
  `absent`, `fields_unknown` and **`unmeasured`**. `unmeasured` is a real
  answer with its own exit code — asking about a line SATOM has no evidence
  for must never be reachable from the same result as "yes".

- **Alerts route to sinks now, each with its own severity floor and family
  mask — and a new syslog/CEF feed.** The engine has had seven checks, three
  severities and a cooldown since it shipped, but exactly one control: an
  engine-wide on/off switch. Every finding went to email and to the in-app
  bell, including the `info` ones. That is survivable with two outlets and
  fatal with five — an operator who wires a chat channel, receives every drift
  note and turns the integration off takes the `critical` alerts with it. New
  `services/alert_routing.py` gives each sink two dimensions and no more: how
  bad a finding has to be (`min_severity`) and which of the seven families it
  has to belong to. Both reuse the vocabulary already printed on the same
  Settings page. A pattern language over the finding key was rejected: the rule
  everybody writes is `.*`, which is this with more surface to get wrong.
  **Defaults reproduce the pre-filter behaviour exactly** — the bell and email
  stay on, at `info`, unmasked — so upgrading an install cannot quietly narrow
  a path nobody asked to narrow. **Engine failures and findings from a check
  the router does not recognise bypass both filters**: a channel silenced by a
  crashed check is indistinguishable from a healthy quiet one, and an
  unrecognised prefix is a silent loss if dropped and mere noise if delivered.

- **Syslog / CEF feed to a FortiAnalyzer or SIEM** (`services/alert_syslog.py`,
  off by default). RFC 5424 or CEF over UDP/TCP, configurable facility, framing
  and escaping owned by the product rather than by whoever writes the
  integration — an unescaped `|` in an alert title truncates a CEF header at
  the collector and the event lands mangled. **This sink is a record, not a
  recipient**, so it is deliberately *not* one more entry in a list of
  destinations: it carries **no cooldown** and it runs on the **read-only
  standby** as well. A record queried after the fact ("was fw08 unreachable at
  03:10?") cannot have six-hour holes in it, because a hole reads exactly like
  "it was fine" — and without the standby emitting, that node's own cert, host
  and reachability findings never leave it at all. It is also **excluded from
  `dispatched`**: a healthy collector must not be able to make a dead mailbox
  look alive. TLS transport and the LEEF encoding are not implemented.

- **Settings → Email & Alerts** grows a *Delivery sinks* table (three rows, on/
  off + floor + seven family boxes) and a *Syslog collector* block. The
  **Preview** button now answers the question the filter created: not just what
  would fire, but which sinks would actually hear it.

- **The rediscovery sweep now records a verdict per endpoint, and the catalog
  reads them back.** New page **Registry reconcile** on both API hubs
  (`/web/registry/reconcile`, `/adc/api/reconcile`, `REGISTRY_EDIT`). The sweep
  already GET-ed every enabled endpoint against a live appliance; it kept only
  the rows. Each endpoint is now classified `ok` / `absent` / `error` into
  `_config.json → endpoint_status`, and `services/registry_reconcile.py` groups
  the fleet's verdicts into **proposals** (every live appliance says the path
  does not exist), **divergent** (served by some, absent on others — a firmware
  split, never proposed), **partial**, **unproven** and **unsweepable** (rows
  outside the sweep plan, which no sweep can ever answer). Approving a proposal
  performs the existing soft-delete; the service **re-derives the proposal set
  server-side**, so the checkbox list filters the evidence and never extends it.
  Every finding carries the **firmware line** that produced it, because absence
  is a claim about a firmware and the catalog is a deliberate cross-firmware
  superset: when the whole quorum runs one line, the page leads with that
  warning instead of a delete button. First run against the real fleet: **38
  FortiWeb endpoints served by no live appliance**, agreed on by fortiweb09 and
  fortiweb10 (both 7.6.8) — several of them 8.0 features, not dead rows. The
  FortiADC catalog (8.0.3) came back clean.

- **The console can now reboot or upgrade an appliance BY NAME — without
  becoming a second way to authorize one.** `satom execute device reboot
  <device> --yes` and `satom execute device upgrade <device> --yes`. The
  privilege was never actually missing: `execute scheduler run <id>` has always
  been able to fire a reboot action. What was missing was the *addressing* —
  turning "reboot fortiweb08" into the one action id allowed to do it — and
  that gap fell on the operator who is on SSH, inside a maintenance window,
  because the web UI is exactly what is unavailable.

  So the new verbs **select and never execute**. `device_ops.select_action()`
  resolves the device to a single scheduled action that is already bound to an
  approved change request, and hands that id to the same `execute_and_record()`
  the scheduler uses — which re-runs the change-request gate itself. Every
  check in the selector can therefore only refuse *earlier* than the gate
  would; none of them can permit something the gate would have stopped. A CLI
  that called the device directly would be a second implementation of one
  authorization boundary, and the weaker of two implementations is the one that
  ends up being the real one.

  It refuses in five ways and names which one fired: no such action, an action
  bound to no change request, a change request that is not approved / has no
  window / whose window has closed, an action that targets other devices too,
  an action that targets the whole fleet (never narrowed — the recorded row is
  what an auditor reads), and two runnable candidates (never disambiguated by
  row order). A bare "not authorized" at 03:00 is worse than useless: the
  operator cannot tell a missing action from a window that shut twenty minutes
  ago, and the fastest way out of an undiagnosable refusal is to go around it.

- **`satom get device config` reads a device's configuration from the LOCAL
  store, never from the box.** Three levels — sections, tables, rows — over the
  content-addressed source-of-truth store, with `--version <id>` for an older
  snapshot. It answers with the appliance unreachable, its credentials rotated
  or its management plane rebooting, which is precisely when an operator
  reaches for it. Resolving a section or table name prefers an exact match,
  accepts a unique prefix, and **refuses an ambiguous one** rather than
  choosing: printing a different section under the heading that was typed is a
  configuration confusion in the middle of a change window. A `--version` that
  belongs to another device is refused for the same reason.

- **External teams can file their own FortiWeb WAF carve-outs — and, when
  trusted, apply them — over `/api/v1`.** Until now the integration API was
  read-biased: the only mutation was triggering a scheduled action an operator
  had already created. A security or application team that needed an exception
  on the WAF in front of its own app had to ask someone to retype it. Two new
  resources close that gap without opening the appliance:
  `/api/v1/waf/exceptions` (FortiWeb, desired-state first) and
  `/api/v1/adc/rules` (FortiADC).

  What it is deliberately **not** is a proxy to the device configuration
  database. That database does not distinguish "a WAF carve-out" from an admin
  account, an interface or a static route, so an endpoint that writes whatever
  object type it is handed is not a rules API — it is a way to take over the
  appliance. The authorable types come from the curated carve-out catalog the
  console already uses, and in this version only the *exception* half of it: a
  signature customisation edits a shared signature set that every policy
  binding it inherits, and that blast radius stays with operators.

  The two audiences the operator described — teams that file a request for
  approval, and teams that write directly — are **not** a flag in the request.
  A caller must never be able to elect its own privilege. They are two separate
  capabilities on the token (`waf_exception_draft`, `waf_exception_apply`;
  `adc_rule_draft`, `adc_rule_apply`), and a draft-only token that asks to apply
  is told so rather than quietly downgraded — a silent downgrade returns success
  to an automation that then believes the hole is closed on the appliance.

  Both capabilities are **explicit grants**. For scheduled actions an empty
  capability list has always meant "unrestricted"; reusing that default here
  would have handed WAF config-write to every token already in a third party's
  hands, retroactively and without anyone approving it.

  Four guarantees carry the rest. Every API-authored record carries its author,
  so a token can only withdraw what it filed and an operator's carve-out is
  invisible to it. A retried request is deduplicated on the *content* of the
  carve-out, so a SOAR that retries does not leave a second identical row for
  the alignment report to double-count. An AppID-scoped token must name the
  server policies it is authoring for, and they must be its own. And — the one
  that is easy to miss — owning those policies is not owning the profile they
  share: a Web Protection Profile is usually bound to several policies, so a
  carve-out "for my app" lands on every other app on the same profile. A scoped
  token is refused when the target profile reaches outside its scope, and
  refused again when SATOM cannot prove that it does not.

  FortiADC differs in one honest way: it has no desired-state store, so SATOM
  cannot record who authored a rule, so there is **no delete** on that half —
  an endpoint that cannot tell an external team's object from an operator's is
  a way to remove someone else's protection. The API says so in its own type
  listing rather than leaving an integrator to discover it.

- **Concept Map (`/map`) — every page in the console, grouped by
  what it is for.** The sidebar answers "what can I do in this ADOM?"; it has never
  answered "where does X live?", which is the question a new operator actually
  asks. The new page draws the whole console as a mind map — SATOM at the
  centre, one card per concept around it, every page listed inside its card and
  clickable — with one search box that matches a page's name, its purpose, its
  path and the words someone types under pressure ("certificate", "rollback",
  "who changed it"). A list view renders the same set for reading and printing;
  both views share the search box, so toggling never changes the result set.
  Linked from the footer of every page, and reachable from all five ADOMs.

  Two things keep it honest rather than decorative. The URL map is the
  authority on what exists: every reachable page is either on the map or
  explicitly excluded with a reason, and a page added without an entry fails a
  test instead of quietly never appearing — the page itself also states its own
  coverage, so an incomplete map says so out loud rather than looking finished.
  And nothing is restated: paths come from the router and the permission each
  page requires is read off the view function itself, so the map hides the
  doors this user cannot open and can never drift into advertising a 403.

- **Config-drift alerts say who made the change.** When a device's
  configuration changes, SATOM now checks its own audit log for a write it made
  to that device inside the interval the change has to fall in, and names the
  author, the time and the client address instead of ending with "if nobody
  edited it via SATOM…" — a correlation the product had already performed and
  thrown away. An unexplained change is still reported exactly as before, and
  now states the interval that was searched, so "no write recorded" is a fact
  the reader can weigh rather than a claim they have to trust.

  The interval is bounded by the last harvest that CONFIRMED the old
  configuration, not by the older snapshot's timestamp: an unchanged device
  mints no new version, so those two can be days apart, and the wider window
  would credit the wrong write. Previews, writes the device refused, read-only
  API-console calls and writes to a neighbouring appliance are all excluded —
  crediting a device-side change to SATOM would downgrade a real intrusion to
  an approving nod, so anything short of positive evidence counts as no
  receipt. New setting under Settings → Alerts: report an attributed change as
  informational (default), keep it at warning, or do not report it.

- **Settings → Languages: choose which languages this installation offers.**
  SATOM speaks five; an administrator can now decide which of them users may
  pick here. A withdrawn language disappears from the profile picker, from the
  change-document language question **and** from browser language negotiation —
  so a browser asking for French stops being served French once French is off,
  which was the half nobody would have noticed missing. The source language
  (English) cannot be switched off: it is what every translation derives from
  and what a page falls back to, so an installation without it would have no
  readable fallback.

  Withdrawing deletes nothing. A user who had already chosen the language keeps
  their choice — it is simply not honoured while the language is off, and their
  profile says so in as many words — and the translated text stays in place, so
  switching a language back on restores it complete rather than empty. The
  console lists every language, including the withdrawn ones, and shows how
  many users have picked each one *before* you switch it off, because
  withdrawing a language changes the language other people's pages render in.

- **A maintenance window is now one staged workflow: Automation → Upgrade
  Flow.** Pre-flight every appliance in the window in one sweep, raise a single
  change request that cites *all* of that evidence, export the consolidated
  customer impact, then execute. Each stage already existed; each was
  per-device or unlinked, so an operator upgrading sixty appliances walked the
  path sixty times and still finished holding a change document whose evidence
  covered one box.

- **Per-appliance execution progress, written as it happens.** A change request
  now has a live panel showing every appliance it covers and what has happened
  to it: pending, running, ok, failed — and, distinctly, *interrupted* for a
  device the run opened and never closed. Progress is measured in appliances
  reported, never in elapsed window time. "Start now" brings the approved
  change's one-shot action forward and lets the scheduler execute it out of
  process; it does not run the upgrade in the web request, and it does not
  bypass the window (the executor re-checks the approval at fire time
  regardless).

- **Batched rollouts: split a selection into waves, one change per wave.**
  Appliances are chunked in name order and each chunk becomes an ordinary
  change request with its own window, its own approval and its own evidence, so
  the first group can be watched before the next is approved. Windows are
  consecutive and never overlap — each wave starts at the previous one's end
  plus the configured gap. Nothing about approval, execution, the change
  document or the customer-impact export needed a wave-shaped variant, and
  giving them one would have re-created the two-implementations defect below.

- **The manual describes the console you are actually looking at.** §26 opened
  with "one page with **22 tabs**"; Settings has been a grouped sidebar (8
  groups, 24 panels) for weeks. Nothing failed — the page rendered, the suite
  passed, and a publicly published document simply described a screen the
  reader did not have in front of them. Three shipped features had no manual
  entry at all, so the only way to learn they existed was to notice them in
  the sidebar: **§38 Bookmarks** (the four kinds, personal vs team, and the two
  rules that decide what you see — the *reader's* permissions filter the list,
  and filtering a row out never destroys its placement), **§39 Concept Map**
  (ten clusters, 83 mapped pages and 106 excluded with a written reason) and
  **§40 Upgrade Flow** (the four stages of a maintenance window as one
  workflow, and the two limits that refuse naming the number rather than
  quietly doing less). Plus **§26.12b Languages**, a whole settings panel with
  no entry. `tests/test_user_guide_features.py` derives every assertion from
  the artefact — the groups and panels are parsed out of the template that
  renders the menu, the languages from `langs.SUPPORTED`, the limits from
  `views.upgrade_flow` — so adding a group, a language, a kind or a page
  breaks the suite in the commit that adds it.

### Changed

- **Pointing at a row in the bookmarks sidebar now lights it in the reader's
  own banner colour** instead of the flat grey it used to take, washed to a
  fraction of that colour so the label keeps its full-contrast text. The
  colour comes from the same per-user setting the top bar is painted from, so
  two people looking at the same fleet each see their own.

  The wash is deliberately lighter than the device-type chip and does not
  share its number: the chip paints its own translucent fill *over* the row,
  so at equal weight the one chip that stopped reading as a chip would be the
  chip you were pointing at. It is also declared *above* the drag-and-drop
  rule rather than below it — dragging a row means hovering it, both rules
  carry the same specificity, and the operator has to keep seeing where the
  row is about to land. The colour travels as a single custom property on the
  tree, read with a fallback to the old neutral surface, so a row rendered
  outside the tree still answers the pointer.

  A focused row now lights up the same way. The row already revealed its
  action buttons on `:focus-within`; a keyboard reader was getting those
  buttons on a row with no highlight under them.

- **`dispatched` is now the count of findings a notification sink actually
  accepted and delivered**, and the cooldown stamps exactly those. Previously
  both were computed over the whole fresh set, which was correct only while
  every finding went to every channel. With a filter in play, stamping a
  finding that reached nobody would suppress it for the full window — so
  widening a mask tomorrow would appear not to work until the window it never
  earned expired.

- The CEF header now carries **local time plus an unambiguous `rt=` epoch**.
  The RFC 3164 header CEF rides on has no timezone field, so a collector reads
  it as the sender's local clock; emitting UTC there filed every event at the
  wrong hour on any install not running UTC — invisibly, because the event
  itself was perfectly well formed. The RFC 5424 line is unaffected: it has a
  zone field and states it.

- **The duplicate carve-out implementation from the 2026-08-12 collision is
  retired — the coverage it held is not.** Two sessions built the `/api/v1`
  object-authoring surface within the same hour. One was wired into the
  blueprint and shipped; the other stayed on disk, imported by nothing, for
  three rounds. Its 35 tests could never pass, because they targeted the module
  that was never wired up — but seven of the promises they pinned were pinned
  nowhere else. Those seven are now expressed against the live surface, in the
  suite that already covers it: an unauthenticated call is answered as 401 JSON
  on every route rather than a redirect to the HTML login form; an applied
  carve-out leaves an audit receipt naming the token *and* the human who owns
  it; a preview is never filed as a write; a refused call is recorded, so
  probing the surface leaves a trail; a FortiADC create leaves its own receipt,
  which is the only record that exists on that half; key order is not part of a
  carve-out's identity, so a caller that re-serialises between retries does not
  author twice; and no request field can steer the device path. The audit ones
  reach past the API: a change SATOM makes on a device without leaving a
  receipt is reported back to the operator as drift with no known author.

  The retired files were committed **before** they were removed. Deleting an
  untracked file leaves no trace anywhere — no diff, no history, nothing to
  read later — so the independent implementation, its tests and the ad-hoc
  route probe are in the history at the commit that precedes their removal.

- **The Admin Console menu keeps one group open.** Opening a group — or
  selecting a section inside one — now folds every other group. Selecting is
  the half that is easy to miss: a section can be activated without ever
  touching a group header (the in-page links, the URL-hash restore, the
  redirect after a save), so the fold is driven from the routine all of those
  paths go through rather than from the header handler, and it fires on the
  entry as well as on the header — Bootstrap stays silent when the clicked
  section is already the active one, and an accordion that sometimes does not
  fold reads as a bug. Stores written by the previous multi-open version keep
  their key and restore the group opened most recently, rewritten to that one
  alone.
- **Admin Console: the lateral menu now starts fully collapsed.** Eight groups
  holding twenty-four sections expanded into a wall taller than the viewport, so
  the operator had to close what they never opened. The collapsed state is
  rendered server-side rather than applied by the script, so the first paint is
  already the default — a menu that flashes open and folds a frame later reads
  as a bug. The store was inverted with it: it now holds the OPEN groups under a
  new key (`satom.settingsnav.open.v1`), and the retired key is deleted rather
  than left to rot, because a set saved under the old name means the opposite
  and would expand exactly what someone chose to collapse. Reaching a section
  without the menu (in-page `#tab-…` links, the redirect after a save) still
  opens its group.
- **Admin Console: pane content is laid out in a single column.** Every block
  of a pane — cards, tables, banners — takes the whole width and stacks in the
  order it is written, at every depth: the pane's own grid, the top-level row
  that used to put `col-lg-7` beside `col-lg-5`, and the grids inside a card
  body that laid two tables abreast. `col-auto` is the one exception, because
  it means "size to the content" and is how the page writes an inline toolbar
  or the button beside a field; stretching those would produce a stack of
  buttons rather than a column. Long badges and `<code>` runs still wrap
  instead of running past their card.

- **The Admin Console menu is lateral and grouped by theme.** Twenty-four
  sections were reached from one horizontal strip that wrapped onto three rows
  on a normal screen: the row a section sat on moved as the window resized, so
  there was no stable place to look for anything, and nothing on screen said
  which sections belonged together. They are now a column beside the panes,
  grouped under eight headings — System, Access & Identity, Certificates &
  Trust, Monitoring & Alerts, Network & DNS, Fleet & Devices, User Interface,
  My Account — and every group collapses to its heading. The menu opens fully
  expanded, so the console still shows everything it did before; what an
  operator collapses is remembered per browser. Nothing about the sections
  themselves changed: same entries, same icons, same panes, same in-page links
  and URL hashes (`…/settings/#tab-auth`).

  The remembered state is the set of groups an operator has CLOSED, never the
  set they left open: the default is "everything expanded", and a store of open
  groups would have collapsed the whole console for every operator who had
  never touched it. A section reached without the menu — an in-page link, a
  redirect after a save, a URL hash — reveals its group, so the selection is
  never hidden inside a collapsed heading.

- **The external CRQ now carries the window, not just its primary keys.** The
  `change.requested` hook sent `device_ids` — bare integers, meaningful only
  inside SATOM's database — and a flat list of policy names. It now also sends
  the change reference printed on the document, every appliance resolved by
  name, product, management host and current firmware, one pre-upgrade summary
  per appliance that has one (verdict, timestamp, firmware, backup name,
  affected-service count), and the names of the appliances that have none. The
  affected-policy list is capped for a fleet-sized window, and the true total
  travels beside it with an explicit truncation flag — a receiver that reads a
  capped list and believes it is the whole outage under-states it by an order
  of magnitude. The payload also states whether the receiving system holds the
  approval gate, and carries any existing ticket reference so a re-request
  updates a ticket instead of opening a second one for the same window.

### Fixed

- **A standby that serves traffic is now restarted by an update, instead of
  being left running the previous release's routing table.** The updater's
  standby path was built on the premise that the application is stopped on a
  read-only replica, so it restarted only the scheduler and validated with
  `import app`. On a standby that is enabled, active and published, that left
  the workers holding a `url_map` older than the templates on disk: a layout
  calling `url_for()` for a blueprint the process never registered raises
  `BuildError`, so **every authenticated page returned HTTP 500** — for about
  fifteen hours, while the update reported success. Both existing checks were
  structurally incapable of seeing it: `import app` runs in a fresh interpreter
  (green exactly when the workers are stale) and `/healthz` renders no
  template. The runner now asks systemd what the node was actually doing before
  it touches anything and restores that state, validating over HTTP whenever
  the application was running — on a standby too. A node that was deliberately
  stopped still stays stopped.

- **A template that references an endpoint which does not exist now fails the
  update instead of the page.** A new route audit resolves every literal
  `url_for()` in the templates against the real URL map, and runs as a gate on
  every code, package and library update. Because "the check could not run" and
  "the check found a problem" are different facts, the audit reports three
  outcomes: a failure to even start it is recorded as unmeasured and does not
  roll a healthy update back.

- **Regex Lab now names the engine that judged the pattern, and flags where it disagrees with the appliance.** The modal footer claimed "Tested server-side against a PCRE-compatible engine — matches FortiWeb & FortiADC"; the lab in fact judges with Python `re`, so a pattern using `\p{L}`, `\K`, `\z`, `(?R)` or PCRE-style `(?<name>)` was reported INVALID for a pattern the appliance accepts. Every verdict (match, rewrite, invalid and empty) now carries an `engine` block plus a `divergences` list, rendered under the verdict. The flavor note warning that possessive quantifiers and atomic groups "aren't supported in this tester" was also stale — Python 3.11 added both. The engine caveat is pinned to the head of `guide_notes`, because `(harvested + base)[:10]` used to truncate it away on FortiWeb.

- **Renaming a classification value no longer orphans every row that used it.**
  The old textarea rewrote the catalog and nothing else, so the ~30 rows still
  holding the previous string simply stopped matching: appliances fell into
  Architecture's "(no zone)" bucket and the bookmarks lens's unclassified one,
  and — the one that changes behaviour rather than display —
  `baselines.appliances_in_scope()` filters on `Appliance.zone ==
  baseline.zone`, so a half-applied rename returned an empty scope, which reads
  exactly like "no appliance matches this baseline yet". Worst of all, combos
  are auto-generated from the catalogs: leaving 24 baselines on the old triple
  meant the next generation pass built a **second full grid** for the new one.
  A combo whose scope moves is now renamed with it when its name is the
  generated one, and left alone when an operator named it by hand.

- **The Settings console no longer keeps a second, unguarded writer for these
  catalogs.** `POST /settings/classification` survived the page's move to the
  Administrator section: no template posted to it any more, but it was still a
  live `USER_MANAGE` endpoint calling the catalog store directly, with none of
  the reference handling above. One URL bypassed every guard on the page. It is
  gone, and an AST walk in the test suite now fails if any module other than
  `services/classification_ops.py` calls the store's writer.

- The **"nothing was sent"** warning on a change request no longer claims that
  hooks are the only path. It now names both the tracker backend and the hook
  binding, so an operator whose CRQ went nowhere is not sent to write Python
  when the fix is a dropdown.

- **The registry readers ignored `api_version` while the seeders honoured it.**
  Every `seed_*_from_yaml` has always scoped its insert-only check by
  `(product, api_version)`; every reader filtered on product alone and built
  `{name: urn}`. The moment a second `api_version` row existed for a name that
  dict collapsed — one row won by arbitrary query order and its URN was served
  to *every* consumer (`scheduled_actions`, `clone`, `write_through`,
  `exception_inject`, `objedit`) with no error and no log. The `api_version`
  box on the New/Edit Endpoint modal is free text, so any `REGISTRY_EDIT`
  holder could arm it. All four products now read the active version from one
  `API_VERSION` map, and an AST guard fails the build if either half goes back
  to a literal. Reproduced live before and after the fix.

- **The sweep read the running firmware and threw it away.** `appliances.firmware`
  was filled only by `_apply_inventory`, from `_model_from_status`, which
  returns `None` for FortiWeb — so 8 of 10 appliances had an empty firmware
  column while their own snapshots said `7.6.8` / `8.0.3`, and anything keyed
  by firmware line had to treat most of the fleet as "unknown line". The sweep
  now persists what it measured.

- **`errors[]` was empty on every rediscovery snapshot ever written — including
  ones taken from an appliance that was rejecting a URN outright.**
  `FortiWebClient._results_list` folds a device error envelope into `[]`, so the
  sweep could not tell "this collection is empty" from "this firmware has no
  such endpoint" and recorded neither. That is how `interface` →
  `system/network.interface` (`errcode -20001`) stayed enabled and clickable in
  the API Explorer for months. The sweep now classifies with the same codes
  `cmdb_names_checked` already trusts (`-20001`/`-3` absent on FortiWeb, HTTP
  404 on FortiADC), and keeps `absent` OUT of `errors[]` so real failures are
  not buried under dozens of benign rows.
- **A sick appliance can no longer speak for the catalog.** A ledger where more
  than 25% of endpoints failed, one older than 45 days, and a pre-verdict
  snapshot are all refused as evidence, with the reason shown on the page.
  Verified live: fortiweb08 answered `-20010 "The license of peer VM FortiWeb is
  not valid"` to 283 of 321 reads while the inventory still called it `online` —
  read naively it would have proposed deleting the entire catalog.

- **`upgrade` asserted a change-request requirement it never declared.** Its
  own `summary` said it was "authorized by an approved Change Request inside
  its maintenance window", and `_do_upgrade`'s docstring said the check was
  "enforced upstream in `execute_and_record`". Neither was true: the unbound
  refusal reads `spec.requires_change_request`, and the `upgrade` spec never
  set it — so an upgrade action with no bound CR passed the gate. It was
  harmless only because the executor is still a guarded stub that flashes
  nothing; the day the flash runbook lands it would have been a destructive
  action running unapproved while three separate pieces of prose swore it could
  not. This is the same shape as `upgrade_prep` once shipping
  destructive-and-ungated while the gate watched only `upgrade`. The flag is
  now declared, and the guard pins the **rule** (danger + a schedule forced to
  `once` requires a change request) rather than the word `upgrade`, so the next
  fixed-date destructive action arrives gated instead of arriving free.

- **The API manual described an API that no longer existed.** `docs/api_v1.md`
  opened by telling integrators that *"mutations happen only through pre-created
  Scheduled Actions"* — false since object authoring shipped — and its endpoint
  table, the page's own list of what the API serves, named **6 of the 13** live
  routes. The seven `/waf/*` and `/adc/*` routes were described further down in
  sections 6 and 7, so the page contradicted itself: a reader who trusted the
  table concluded the product could not do what it had just been given. The
  preamble, the token-limits table (capabilities are now the fourth chained
  limit, and the one that decides object writes), section 3 and the error tables
  now describe the shipping surface. Three codes an integrator can genuinely
  receive — `bad_request`, `registry_mismatch`, `device_unreachable` — were
  absent from every table and are documented.

- **The manual claimed to be generated from the live routes. It is hand-written.**
  That sentence is worse than a missing endpoint: it tells the reader that a gap
  is impossible, which is the belief that lets one open. Replaced with the truth
  and with the guard that now enforces it — `tests/test_api_v1_manual.py` pins
  every `/api/v1` rule in the URL map, every object-write capability the model
  defines, and every error code the API modules literally emit, against the page.
  The published copy `site/docs/api.html` was regenerated: it had been built
  before sections 6 and 7 existed, so the *public* manual — the one an external
  team actually reads — described none of it.


- **The field-catalog harvest can no longer file a device's configuration under a
  firmware line it does not run.** The line came from the operator's environment
  (`SATOM_FIELD_CATALOG_SOURCES="fortiweb=8.0:<box>"`) and was written into both
  the folder path and the artefact's `source` string verbatim; nothing asked the
  device what it actually ran. Pointing an 8.0 line at a 7.6.8 appliance produced
  a complete, well-formed, confidently-labelled 8.0 catalog built from 7.6 data —
  and undetectable afterwards, because every artefact agreed with every other
  artefact. This estate makes that the *likely* mistake rather than an exotic one:
  there is no 8.0 FortiWeb left in it (fortiweb08/09/10 are all 7.6.8), while
  `data/field_schemas/fortiweb/8.0/` exists and was harvested from `fw1`, a box
  that has since left the inventory. The harvest now reads the firmware, refuses
  the line on a mismatch, and records both `device_firmware` and `line_mismatch`
  in every artefact so a reader can tell a verified line from an asserted one.
  `--allow-line-mismatch` overrides it deliberately, and the artefact says so.

- **A harvested schema records when it was harvested.** The payload carried a
  literal `"generated_at": "2026-06-28"`, so every rebuild re-asserted a June
  date. Nothing failed; the artefact simply could not report the one property a
  rebuild exists to deliver.

- **An empty harvest now says WHICH kind of empty it hit.** `_safe_one()` returns
  `{}` both for a table the operator never populated and for a URN the device
  rejects, and the harvest printed the same "empty live object" line for both.
  That is how a dead registry entry stayed invisible: `interface` pointed at
  `/api/v2.0/cmdb/system/network.interface`, which FortiWeb 7.6.8 answers with
  `errcode -20001 "The REST API has invalid URL."`, and it read as "nothing
  configured".

- **The dead `interface` endpoint is retired and provisioning points at the
  working key.** `interface_2` (`/api/v2.0/cmdb/system/interface`, 200, 3 rows) is
  what `interface_inventory`, `analysis`, `config_sections` and the inventory
  tests already treat as canonical. The broken key was enabled in the registry, so
  an operator clicking it in the API Explorer got `-20001` with no explanation,
  and the provisioning catalog pointed at it — which is why **Network interface**,
  the object an operator is most likely to configure, had never had a field
  schema. Fixed on all three surfaces: the provisioning spec, `endpoints.yaml` (so
  a fresh install cannot recreate it) and the live registry row (soft-disabled,
  because the YAML seeder is INSERT-ONLY and would never rewrite an existing row).

- **Six field schemas that never existed.** `interface` (34 fields),
  `snmp_community` (19), `snmp_user` (19), `radius` (16), `user_group` (8) and
  `syslog` (7), harvested read-only from fortiweb08 (7.6.8) into `7.6/` and
  `_default/`. `ldap` remains absent, correctly: the reference box has no LDAP
  server configured, so there is nothing to learn field names from — and the
  harvest now says exactly that instead of implying a defect.

- **Change documents are produced in French and Italian.** Both languages were
  one and two strings short of a complete catalogue (of 292), and a catalogue
  that is one string short withdraws the whole language — deliberately, because
  a partial one prints an English paragraph under an approver's signature. The
  three missing units are translated, so French and Italian now render a
  complete document and the profile picker stops marking them "change documents
  not translated yet". Spanish was already complete; it is not offered only
  because this installation has it switched off in Settings → Languages.

- **A translated action profile came back empty (`KeyError` on render).**
  `cr_document` builds a non-authored language by overlaying the catalogue in
  `_Localized.__missing__`, which `dict.get()` never calls — and the profile
  lookup used `.get()`. The effect depended on the gate and so appeared in the
  worst possible order: while a language was incomplete the renderer degraded
  it to English and nothing looked wrong, and the moment its catalogue was
  completed the document raised instead. The lookup now subscripts, and
  degrades to the authored English rather than to an empty profile. See
  `docs/safeguards.md` §70.

- **A navigation guard that had quietly stopped guarding.** The check that every
  Administrator block in the sidebar reaches Collection through the one shared
  partial located those blocks by their rendered label, so translating the nav
  left it matching nothing and iterating over an empty list. It now anchors on
  `data-nav-group`, the group's structural identity, closes each block by
  counting its own tags (a block that lost its closing tags used to run on and
  find the *next* block's entry), and a new guard fails if that identity is ever
  routed through the translation catalog.

- **Upgrade Flow wrote its own prose; it now reads Administration → Change
  Types like every other change form.** Stage 2 offered a title box with an
  English placeholder compiled into the template, a free-text reason with
  another, and no rollback field at all — while the single-change form next
  door proposed all three from the change type, an administrator's wording
  winning per field. Nothing failed: an administrator renamed the change to
  whatever their change board actually calls it, the single change followed,
  and the bulk one — the one covering forty appliances — kept offering the
  shipped sentence. Both stages (one window, and the batched wave rollout) now
  share ONE set of proposed fields, in the document language the operator
  chooses, with the pre-flight run deliberately *not* quoted: the per-device
  draft names one run by id and this stage rests on N. A change type disabled
  on that page is now reported here instead of being discovered when the form
  is submitted, after the sweep. Waves additionally carry the reason, the
  rollback and the document language they never forwarded before, refuse an
  untitled plan rather than filing changes called "— wave 1/6", and reserve the
  wave marker out of the title budget so a long title cannot truncate away the
  only thing that tells two waves apart.

- **The monitor was raising ~790 alerts a week for conditions that were not
  happening.** Four independent checks each asserted something false; nothing
  crashed, nothing was slow, and no test failed, so the only visible symptom
  was a mailbox the operator learned to ignore. All four are fixed together
  because the fifth defect was the noise itself: two genuine drift events of
  the same week sat underneath ~825 alerts.

  - *Config drift on a device whose config did not change.* The source-of-truth
    identity hashed fields the appliance moves by itself — its own wall clock,
    the internal `*_val` handles it renumbers when proxyd restarts, the
    reverse-reference lists it emits in an unstable order, and the rolling
    `allow-time` window. Measured across every consecutive version pair in the
    live store, 194 of 206 differed in **nothing but the clock**, so a FortiADC
    wrote a fresh ~500 KB version every hour and raised an alert for it. The
    exclusion applies to the identity only: the stored snapshot keeps every
    field, so history, diff and restore are unchanged.

  - *"Host degraded — CPU load 220% of 3 cores" on an idle container.* lxcfs
    does not virtualise `/proc/loadavg` or `/proc/uptime`, so both are the
    hypervisor's. The manager divided the **host's** load average by the
    **container's** core count; a hypervisor at 27% of 24 cores rendered as a
    degraded node, and both HA members alerted in the same second with the same
    load to the decimal. CPU is now read from this container's own cgroup
    accounting, averaged over the window since the previous reading, and uptime
    is derived from our PID 1. The host's load average is still shown, labelled
    as the host's.

  - *"ALL backends down" over servers the appliance reported as up.*
    `healthCheckStatus: "disable"` means no health check is **configured** for
    that pool member, not that the member is down — its own status still reads
    up. The two were graded as one fact, so a policy without health checks read
    `crit` forever: 302 consecutive hourly buckets without a single healthy
    sample. It is now reported as **unverified** at `warn`, with its own
    governable severity, so an untested backend is still not green but the
    console no longer states something the device contradicts.

  - *`dispatched: 2` on runs that delivered nothing.* Every alert mail was
    refused by the relay (`454 4.7.1 Relay access denied`) and the engine
    counted them as sent, then stamped the cooldown, suppressing the finding
    for six hours. `dispatched` now counts what actually left on some channel,
    each failed channel is named, the cooldown is only stamped for what was
    delivered, and a run that reaches nobody exits non-zero so the timer's unit
    goes `failed` where systemctl and the Monitoring page both show it.

- **A change request's page claimed its evidence came from one pre-upgrade
  run.** "Captured by upgrade preparation #88" was true of a single-device
  change and false of a window over twenty appliances, whose frozen inventory
  is merged across every bound run. The page now lists each appliance with the
  run that covers it, and names the ones that carry no baseline instead of
  leaving them as ordinary rows.

- **A duplicate key in the boot-time column migration silently dropped three
  columns.** `_ensure_columns` is one dict literal keyed by table name; a table
  written twice keeps only the last entry and every column under the earlier
  one is never added — no exception, no log line, a clean boot. A guard now
  parses the source and fails on a repeated key, because by the time the dict
  is a value the duplicates have already collapsed and no runtime check can see
  them.


- **The profile's About card drew the ACTIVE ADOM, not the console.** It
  sourced its emblem from `product.mark`, so under Global it showed the globe
  and inside a FortiWeb ADOM it showed the FortiWeb logo — next to this
  console's own name and version, which makes it a claim about what SATOM *is*.
  It now uses the brand emblem the topbar and the login page already use (the
  active theme's logo, falling back to the shipped mark). The version badge
  also moves up beside the product name: name and version are one statement and
  no longer render two lines apart. The brand guard that should have caught
  this enumerated three templates and this card was a fourth, so it stopped
  covering without ever failing; the roster is now derived from the templates
  that actually render the console's identity, and an unclassified new one
  fails the suite.

- **The pre-upgrade had two implementations, and the only one that accepted
  more than one device stored nothing.** The appliance page ran the full
  pre-flight — configuration backup, health battery, maintenance permission and
  an HTTP baseline of every published service — and kept it as citable
  evidence. The scheduled action of the same name took a backup and a health
  read, and kept nothing at all: no service baseline, no affected-service
  inventory, no verdict, no record. Nothing ever failed. Pre-flighting a whole
  window simply produced no evidence a change request could cite, which is why
  a bulk pre-upgrade could not feed a change in the first place. There is now
  one implementation, and the scheduled action uses it.

- **A change request could rest on the evidence of a single appliance.** The
  link was one-to-one, and the create path silently dropped any pre-upgrade run
  whose device was not the change's own — so a twenty-device window carried one
  device's baseline, and an approver reading *the pre-upgrade passed* was told
  the truth about one box and nothing about the other nineteen. A change now
  cites one run per device it covers, and each run is checked against the
  change's devices individually.

- **The customer-impact spreadsheet under-stated the outage for exactly the
  same reason.** It is generated from the inventory frozen when the change was
  raised, and that inventory came off the single cited run. It is now merged
  across every bound run and de-duplicated, so a re-run does not double-count
  its services and two appliances publishing the same policy name do not
  collapse into one row.

- **The API-versions page named a command that does not exist.** Its preflight
  hint read `satom api preflight …`; there is no `satom api` branch, so an
  operator following the page's own instruction got `unknown command` and exit
  2. The command is `satom get api preflight`. Corrected, and
  `tests/test_documented_commands.py` now resolves every `satom …` invocation
  in the user guide and in every template against the live command tree — the
  rule "verify a command before documenting it" had only ever been enforced for
  `docs/cli.md`, which was correct all along, while the interface was not.

## [1.9.3] - 2026-08-10

### Added

- **The interface itself is translated — Spanish, German, French and Italian,
  chosen from your profile.** Until now only the change *document* could change
  language; the chrome was English written by hand inside the templates, so a
  saved preference of *Español* still produced an English menu. The 163
  templates are now marked for translation (3 468 distinct strings) and the
  language is resolved per request: the saved profile preference first, then the
  browser's `Accept-Language` narrowed to what we actually ship, then English.

  **Translation happens once, offline, into catalogue files — never on a
  request.** The pages read a compiled binary catalogue in memory (~7 µs per
  lookup); no page render talks to a model. Three reasons this is not
  negotiable: a model call is ~50 000× slower than a lookup and a page carries
  dozens of strings; a model returns different wording each time, so the same
  button would be renamed between reloads; and an installation in a customer's
  own datacentre cannot depend on our GPU to paint a menu. The catalogues are
  plain text — a wrong translation is corrected in the `.po` and recompiled,
  with no code change.

  Four defects behind this, each of which failed *silently*:

  * **A stray `%` in a translated string crashed the page that carried it.**
    Jinja's `gettext` applies `rv % variables` to the translated text
    unconditionally, so `Warn at %` raised `ValueError: incomplete format` at
    render time — on the pages containing that string and nowhere else. Such
    strings are no longer extracted, and a guard rejects any translation that
    invents a `%` the source did not have.
  * **The machine translator echoed its own untrusted-data fence into the
    catalogue**, which printed `[[END_UNTRUSTED]]` in the navigation under *AI
    Advisor*. The existing guard knew only the English spelling of that marker,
    so a translated fence — `UNvertrauenswürdige Quelle` — walked straight past
    it. Residue is now judged against the source in every shipped language: a
    reply that raises trust vocabulary the source never does cannot be a
    translation of it. `TLS trust store` still becomes `TLS-Vertrauensspeicher`,
    because that source *does* raise it.
  * **A repaired catalogue was still serving the broken text.** The `.po` files
    were fixed while the compiled `.mo` the application reads was older — a fix
    that was never delivered, with every text-level check green. A guard now
    fails when a `.mo` is older than its `.po`.
  * **`flask-babel` was installed in the virtualenv but absent from
    `requirements.txt`.** The installer rebuilds the venv, so the next
    reinstallation would have removed a dependency the application cannot start
    without.

- **Change documents are produced in five languages, and a language is offered
  only when it can actually be produced.** Spanish, French and Italian join
  English and German. The prose is not a fourth and fifth copy of the action
  profiles in Python — it lives in the translation catalogue and is overlaid on
  the authored English at render time, so the original stays the single author
  of every sentence.
  The gate is now **measured, not declared**. The picker previously read a
  hardcoded set of authored languages; it now asks whether every one of the 292
  strings a document can print exists for that language and is not stale. One
  missing or outdated unit withdraws the whole language, because the failure it
  prevents is a document half in Spanish and half in English *under an
  approver's signature line* — which raises nothing and looks finished.
- **Your language is a profile preference, and the change document stops
  guessing it.** **Profile → Language** stores the language you work in against
  your account in the database — not a cookie, and not shared with other users —
  and the top-bar user menu shows the current choice next to the entry that
  changes it. The *Document language* question on **New Change Request** is
  pre-answered from it.

  Three rules behind this, each guarding something that fails without an error:

  * **"No preference" is not "English."** They are stored distinctly, so the
    profile can show which one is true and the form knows whether it still has
    to ask. Collapsing them would make the setting unobservable and would
    re-ask an operator who deliberately chose English, forever.
  * **Nothing is pre-selected without an answer behind it.** The first language
    is no longer checked by position. Without a saved preference the question is
    genuinely open, the radio group is `required`, and the form says where to
    set the preference so it stops being asked.
  * **A preference the product cannot honour is stated, never downgraded.** The
    registry declares five languages; complete change documents exist in
    English and German. A profile set to Spanish, French or Italian is kept —
    it is your language, and the rest of the product adopts it as text is
    translated — but the change-request form says so on the page and still
    asks, instead of quietly producing an English document under a signature
    block.
- **The Change Request form's type picker and its text are administrator-owned.**
  A new page, **Administration → Change Types**, owns the options in the *type
  of change* picker and every sentence a chosen option contributes: the proposed
  title, reason and rollback plan, and the eight profile paragraphs the printed
  document quotes (purpose, justification, impact, downtime, risk, rollback
  steps, work, validation). Until now both lived in Python source, so adding a
  category — or fixing a paragraph an auditor objected to — meant a release.
  Built-in change types can be **reworded**; types you add are **documentary**:
  the change request is raised, approved and printed, and the work is carried
  out by hand. Saving fans the changed fields out to the other four languages
  through the translation service added earlier in this cycle, and every call is
  billed to `translation_run` with wall time and token counts.

  Four things about this fail silently, so each is a rule with a guard behind
  it:

  * **An empty box is not an override.** "Leave it blank to keep the product's
    wording" is a promise about a value nobody typed; writing it through would
    blank a section of a signed document with nothing raising. Overrides are
    per FIELD — correcting one paragraph of a built-in type does not cost you
    the other eleven, and it does not stop the next release's corrections from
    reaching this install.
  * **Executability is never stored.** Whether a change type can be *run* is
    read from the automation registry on every call. A checkbox here would let
    somebody create a category that looks runnable, bind it to a one-shot
    scheduled action, and have it resolve to no targets at fire time — inside
    the window, closing the change as failed hours after anyone could act on
    it. `schedule_change_request()` refuses a type with no executor, the form
    says so before you pick it, and the Schedule button is not offered.
  * **Approval freezes the wording.** The resolved prose is photographed onto
    the change request when it is approved, per document language, and the
    document prints the photograph. Without it, correcting a paragraph this
    morning would rewrite every document already signed, and the reprint would
    differ from the paper in the file with nothing saying so. Drafts render
    live, because they were signed against nothing.
  * **A machine translation stays labelled as one.** Text a model produced
    carries `origin=machine` and the model's name for good; marking it reviewed
    records who accepted it, and does not promote it to something a person
    wrote. Text you typed by hand in another language is never overwritten by a
    re-run, and editing the source marks the translations **stale** rather than
    deleting them.

  Hiding a built-in type removes it from the **form only** — the action stays in
  the product and the executor still knows it, because a menu is not a
  permission. Deleting a type of your own leaves the change requests already
  raised with it fully printable. The editor is reachable from the
  Administration group of **every** ADOM through a single nav partial, and is
  admitted to each ADOM's routing allowlist, so no console gets a live-looking
  menu entry that redirects.
- **The Automation section is in every ADOM, and each ADOM shows only its own.**
  Scheduled Actions, Device Provisioning and Change Requests now appear in the
  Global, FortiWeb, FortiADC, FortiAnalyzer and FortiAuthenticator consoles —
  and in any ADOM declared from here on. The pages always existed and always
  answered by URL; four of the five consoles simply had no way to navigate to
  them, which is not an error anyone sees. The group has ONE author
  (`partials/nav_automation.html`), so an entry added to it lands in every ADOM
  in the same commit rather than in whichever branch someone remembered.
  Reaching them needed the router too: `scheduled_actions` was pinned to the
  FortiWeb ADOM, so the concrete ADOMs would have bounced off the link and the
  Global console would have been silently re-pinned — its automation calendar
  was FortiWeb's, wearing Global's chrome. Scoping is by row instead
  (`ScheduledAction.product`), and it now covers the **five by-id routes** as
  well as the list: edit, toggle, delete, run-now and history read the table raw
  until now, and a page that hides a row and then serves it one URL away is not
  scoped, it is decorated. The editor follows the same rule — the catalog is cut
  to the actions whose declared products include this ADOM, and the posted
  action and target list are re-checked server-side, because the form is a hint
  and this is the rule. Its device picker was hardcoded to `kind='fortiweb'`,
  which rendered an **empty** roster in every other ADOM: no error, no message,
  a form that silently could not target anything. **System Provisioning stays
  FortiWeb-only on purpose** — it composes FortiWeb `cmdb` objects out of a
  registry stamped `product='fortiweb'`, so offering it in the FortiAnalyzer
  ADOM would aim FortiWeb configuration at a box that has none of those objects.
- **The new change request asks two questions and proposes the rest.**
  `/change-requests/new` now asks, in this order, the **document language**
  (English / Deutsch) and then the **type of change** — and fills in title,
  reason, rollback plan, change owner and notification recipients from those two
  answers plus the pre-flight run the change cites. The order is the point: the
  proposed prose is written in the language you picked, so picking it afterwards
  would mean rewriting everything already on screen. What is *not* proposed is
  the device list and the maintenance window — those are decisions, and a
  guessed window is worse than an empty one.
  The proposed text is **not** a copy of the action's standard justification or
  standard rollback steps: the rendered document already prints those (§4, §7)
  and prints the change's own wording beside them, so copying would print the
  same paragraph twice and make the operator's statement indistinguishable from
  boilerplate. It is composed from what is true of *this* change — the action,
  the devices, and the cited run's number, timestamp, verdict, firmware and
  configuration backup. A backup that did not complete is never named in a
  rollback plan, because a plan quoting a file nobody took reads exactly like a
  correct one.
  Every sentence is authored **server-side, in both languages, for every
  change-controlled action**, and handed to the page as data; the page only
  substitutes the device names. Composing sentences in JavaScript would give a
  document that gets signed a second author. The fields stop updating the moment
  you type in one — an answer changed after you have written something must not
  wipe your words — and "Restore proposal" puts them back. Owner and recipients
  are pre-filled **visibly, in the field** (your account; the default recipients
  from Settings → Email) rather than derived at save time: §1 of the document
  attributes the change to a name, and accountability you never saw assigned is
  not accountability. With scripting off the whole form is still present and
  submittable — the two-question flow is a progressive reveal, not a server-side
  wizard holding half a change request.
- **Recorded pre-flight runs can be read back** (`GET /appliances/<id>/upgrade/
  prep/<prep_id>.json`, "View result" on every row of the runs table). The runs
  were already stored, listed and citable by a change request — and not
  readable. The table said *passed, 12 services*; the health battery, the backup
  filename and the per-policy baseline that produced that verdict sat in the row
  with no way out. Evidence you cannot open is a receipt, not evidence. A stored
  run is painted by the SAME renderer as a live one, from the same payload
  shape, because a second renderer for one payload drifts silently — both would
  still paint, and nothing on screen would say which description of the evidence
  is true. It is also LABELLED as recorded, with the run number, its timestamp
  and who ran it: the panel is the same panel, and a two-day-old health battery
  looks exactly like one taken thirty seconds ago. The appliance is part of the
  lookup key, so a run belonging to another device is a 404 rather than a
  pre-flight rendered under the wrong box's heading.
- **The frozen inventory is visible with its run.** The published services a
  window takes offline were captured with every pre-flight and only ever shown
  as a count; the list a change request actually cites is now on the page. Its
  column headings come from `prep_store.FIELDS`, the same catalog the CSV and
  XLSX exports are built from, so the screen and the signed sheet cannot name
  one column two ways. The three probe states stay three: *not probed* is not
  *unreachable* — collapsing unknown into down invents an outage, collapsing it
  into up hides one.
- **Change requests run on the operator's clock.** Window start/end are read in
  the timezone configured under Settings → General (`general.timezone`) through
  a new `settings_store.parse_local` — the exact inverse of the `to_local` every
  screen already displayed through. Before this the two halves were asymmetric:
  every timestamp was SHOWN in local time while every form value was STORED as
  if the operator had typed UTC, so a window entered as 22:00 on a Europe/Zurich
  console opened at midnight local — two hours after the customer had been told
  the outage would start. Nothing errored, and the schedule and the maintenance
  notice agreed with each other while both disagreed with the human. The window
  fields now NAME their timezone: a `datetime-local` input carries none of its
  own, so the label is the only thing that says which clock you are typing in.
- **Wall-clock schedules honour that timezone too.** `scheduler.compute_next_run`
  takes a `tz` argument for the `daily` / `weekly` / `monthly` kinds — passed
  DOWN by the callers, never read from the DB inside, so the schedule math stays
  pure. "Back up every night at 02:00" is a statement about local night; computed
  in UTC on a Zurich fleet it fired at 03:00 in winter and 04:00 in summer, and
  nothing logged the move. `interval` is untouched (a duration is not a
  wall-clock time) and so is `once` (already an absolute instant).
- **Formal change document, English or German** (`services/cr_document`, new
  route `/change-requests/<id>/document`, viewable or downloadable as Markdown).
  Thirteen numbered sections — general information, purpose, affected systems,
  justification, impact, risk, rollback, prerequisites, work to be performed,
  post-change validation, communication plan, approvals, outcome — with §2, §5,
  §6, §9 and §10 varying per action across all nine change-controlled actions.
  The German text describes what a Fortinet upgrade actually is (a firmware
  image uploaded by REST, then a reboot into the target partition) and never
  operating-system patching, which is guarded by an explicit forbidden-phrase
  list: a document that describes work which does not happen is worse than no
  document, because the approver signs the wrong thing. `custom_rest` prints the
  literal method/URN/body and refuses to estimate an impact it cannot know.
  §12 prints the ONE approval SATOM actually records and leaves the other roles
  blank for manual signature rather than fabricating them.
- **`ChangeRequest.ref` / `.owner` / `.doc_lang`** — the human change id
  (`CR-2026-0042`) is stamped once at creation and never recomputed, so a
  restore that reseeds the id sequence cannot renumber documents already in
  circulation.
- **The pre-upgrade is persisted** (`models.UpgradePrep`, `services/prep_store`).
  It used to be a fire-and-forget REST call: `upgrade.prepare()` ran, its result
  was painted into the browser, and it vanished with the tab — so the chain the
  operator wants (pre-upgrade passed → therefore raise the change) had nothing
  to attach. Runs are **append-only**: an approved change cites a specific run,
  and evidence that can be overwritten in place is not evidence. The verdict
  grades only the sections that were REQUESTED, and an unreachable published
  service is recorded as a **baseline**, not as a failure — discovering that a
  policy is already down before the change is the most valuable thing the
  pre-flight produces, and grading it red would train operators to re-run until
  it turns green.
- **The affected-service inventory is FROZEN onto the change** when it is
  raised (`ChangeRequest.inventory_at`), and the detail page, the document and
  the export all read that snapshot. A live read at render time would let the
  fleet drift between approval and execution, so the document somebody signed
  and the document describing what ran would not be the same document. Drift
  against the devices right now is available on request and is REPORTED, never
  silently merged.
- **Export the inventory with chosen columns**, `.xlsx` or `.csv`. Column
  *order* is fixed regardless of tick order so two exports of the same change
  are comparable, and ticking nothing exports the default five columns rather
  than producing a zero-column file. The `.xlsx` writer (`services/xlsx_writer`)
  is pure standard library — no `openpyxl`, no `xlsxwriter` — because the
  product ships offline bundles and a new binary dependency is a cost every
  installation pays forever.
- **"Upgrade preparation" now leads to a change request.** A finished run offers
  *Raise change request* with the appliance, the action and the run itself
  pre-selected, and every stored run is listed on the page with its verdict.

- **Change Requests cover every Forti product, not just FortiWeb.** The device
  picker was hard-filtered to `kind='fortiweb'` and the page itself was pinned
  to the FortiWeb ADOM by the product gate, so a FortiADC, FortiAnalyzer or
  FortiAuthenticator could never be named in a change window. The page is now
  reachable from every ADOM and rows are scoped by the devices they name
  (by-id routes included), instead of by which console you opened.
- **`reboot` action** (danger, one-shot, `requires_change_request`): reboots a
  target appliance inside an approved window. The FortiWeb URN
  (`/api/v2.0/system/status.systemoperationreboot`, body `{reason}`, 100-char
  cap) was read off fortiweb08's own GUI bundle; products without a URN
  verified against their own hardware are refused BY NAME, never guessed at.
- `ActionSpec.requires_change_request`: an action can declare that it only runs
  bound to an approved CR. The executor honours the flag, so a newly registered
  dangerous action arrives gated instead of arriving free.


- **Import directory users before their first sign-in, on RADIUS too.** The
  user importer (Settings → Authentication → *Sync directory users*) used to
  refuse anything that was not AD/LDAP, which left the FortiAuthenticator /
  RADIUS backend with no roster at all. It has one now. Said plainly because it
  is the whole design: **RADIUS cannot be enumerated** — an Access-Request is a
  yes/no question about one credential, and the protocol has no verb for
  "list the members of this group". So the roster is read over a *second*
  channel, the FortiAuthenticator REST API, using the API key of a FAC already
  registered under Appliances; no new secret is stored and **sign-in keeps going
  over RADIUS**. Pick the appliance and the group under the RADIUS section.
  The roster comes from `/api/v1/localgroup-memberships/`, not
  `/api/v1/localusers/`: on FortiAuthenticator 8.0.3 the latter **under-reports**
  (it returned 1 of 3 local users, hiding accounts that plainly exist), so
  trusting it would silently import a partial group. Naming a group the
  appliance does not have is reported as an error listing the groups it does
  have — importing nobody and calling it success hides a typo forever.
- **An approval gate for directory users** (Settings → Authentication, applies
  to every external backend). With it on, a first-time directory sign-in creates
  the account **disabled** and refuses entry until an admin enables and profiles
  it under Users — the same state the importer produces, so import-then-approve
  and sign-in-then-approve converge instead of racing. The refusal says
  *awaiting administrator approval*, never *invalid password*: the bind
  succeeded, and blaming the credential sends the user to reset one that was
  correct. Existing accounts are never re-gated.
- **More than one sign-in source at a time, in an explicit order.** The setting
  used to hold one string, so Active Directory *or* LDAP *or* RADIUS. It now
  holds an ordered list and sign-in walks it, first acceptance wins. The local
  database is not on the list because it is not optional: it is the anti-lockout
  floor, always live, and a local account is never handed to a directory. Order
  is not cosmetic and the page says so — an unreachable source burns its whole
  timeout before the next is tried, and every source ahead of the winner counts
  a wrong password against its own lockout policy. A source list that cannot be
  parsed disables external sign-in rather than falling back to the value it
  replaced: local still works, so nobody is locked out, and no directory is
  consulted on the strength of a policy nobody can read.
- **Several import groups per source, each with its own profile.** "Import
  `grp_ops` as operator and `grp_ro` as readonly" is now one configuration
  instead of two passes. A user listed by two groups keeps the first row's
  profile, and a blank profile inherits the global default. One group name the
  appliance does not have **fails the whole import** and names the groups it
  does have — a partial roster reported as success is how a typo becomes
  permanent. The per-group profile is an *import-time* concept on purpose: a
  RADIUS Access-Accept carries no group, and resolving one would put a REST
  round-trip to the FortiAuthenticator on the critical path of every first
  sign-in. Just-in-time users get the global default instead, which is why that
  default is now `readonly` and why the approval gate exists.

### Changed
- **One SATOM mark on every surface — the emblem the product already had.**
  The console, the repo site and the product site each drew something different:
  the emblem, and — on the product site — the CHARACTER `S` in a gradient box, a
  placeholder that outlived its excuse. All three now ship the same emblem
  (`satom-mark.png`, byte-identical across `app/static/img/` and
  `site/assets/`), with `favicon.png` / `favicon.ico` / `apple-touch-icon.png`
  as its icon sizes. A first pass replaced the artwork with an invented
  rounded-square mark; that was a misreading and is reverted. Replacing a
  product's identity is a change where nothing fails — every page renders, every
  asset answers 200, the tab shows *an* icon — so `tests/test_brand_mark.py` now
  pins WHICH mark is canonical, in both directions: the copies must be
  byte-identical, the substitute mark may not return as a file or as a
  reference, every `site/` page with a `class="brand"` must show the mark, and
  the generator template must stamp the same string the pages carry — a page
  fixed by hand is reverted by the next regeneration.
- **The installation manual is in English.** `docs/INSTALL.md` was the only
  document in the manual written in Spanish — and it is the one handed to a
  systems team alongside the privilege request, so its reader is the one least
  likely to share the author's language. Nothing failed: the page rendered, the
  public site published it, every cross-reference resolved. It simply could not
  be acted on by the people it is addressed to. Section numbering, every command
  block and every path are unchanged, so the `§` citations from `README.md`,
  `cli.md`, `safeguards.md` and this changelog still land where they did.

### Removed
- **The appearance preset named after the vendor.** `LOGIN_BG_PRESETS` shipped
  an entry keyed `fortinet`, labelled "Fortinet", in the vendor's corporate red
  `#ee3124` — a choice offered in SATOM's own settings menu under someone else's
  name, next to an "Ember Red" that already covered the same taste. The
  constant is read nowhere, so no installation's appearance changes. Nominative
  use stays exactly where it was: the appliance-type marks, the capacity
  ceilings attributed to the vendor's datasheet, and every sentence describing
  what the vendor's own firmware does are facts about their product, not us
  wearing their name. The `<!-- Favicon (Fortinet) -->` comment in `base.html`
  went with it: a comment is not served, but it is what the next reader believes
  the asset IS, and that belief is how the vendor glyph kept its seat through
  three project renames (§8d).
- **A live firmware upgrade requires an approved, open change window.** This was
  the hole: the headless executor had refused to flash outside a window since
  the gate was generalised, but the button a human actually clicks went straight
  to `push_firmware` with nothing but `CONFIG_WRITE` and a typed device name —
  the path that works had no gate and the path with the gate was a stub. Change
  control that only binds the unused code path is decoration. Dry runs are NOT
  gated: they send nothing to the appliance, and gating them would push
  operators to skip validation entirely. An authorised flash moves its change to
  `in_progress` and closes it with the real outcome through a single seam, so no
  exit path can leave a change parked at `in_progress` forever.
- Scheduling a firmware upgrade from the appliance page reads its date/time in
  the configured timezone as well; it used to store the raw `datetime-local`
  value as UTC.

- **Change Requests cover every Forti product, not just FortiWeb.** The device
  picker was hard-filtered to `kind='fortiweb'` and the page itself was pinned
  to the FortiWeb ADOM by the product gate, so a FortiADC, FortiAnalyzer or
  FortiAuthenticator could never be named in a change window. The page is now
  reachable from every ADOM and rows are scoped by the devices they name
  (by-id routes included), instead of by which console you opened.
- **`reboot` action** (danger, one-shot, `requires_change_request`): reboots a
  target appliance inside an approved window. The FortiWeb URN
  (`/api/v2.0/system/status.systemoperationreboot`, body `{reason}`, 100-char
  cap) was read off fortiweb08's own GUI bundle; products without a URN
  verified against their own hardware are refused BY NAME, never guessed at.
- `ActionSpec.requires_change_request`: an action can declare that it only runs
  bound to an approved CR. The executor honours the flag, so a newly registered
  dangerous action arrives gated instead of arriving free.


- **Import directory users before their first sign-in, on RADIUS too.** The
  user importer (Settings → Authentication → *Sync directory users*) used to
  refuse anything that was not AD/LDAP, which left the FortiAuthenticator /
  RADIUS backend with no roster at all. It has one now. Said plainly because it
  is the whole design: **RADIUS cannot be enumerated** — an Access-Request is a
  yes/no question about one credential, and the protocol has no verb for
  "list the members of this group". So the roster is read over a *second*
  channel, the FortiAuthenticator REST API, using the API key of a FAC already
  registered under Appliances; no new secret is stored and **sign-in keeps going
  over RADIUS**. Pick the appliance and the group under the RADIUS section.
  The roster comes from `/api/v1/localgroup-memberships/`, not
  `/api/v1/localusers/`: on FortiAuthenticator 8.0.3 the latter **under-reports**
  (it returned 1 of 3 local users, hiding accounts that plainly exist), so
  trusting it would silently import a partial group. Naming a group the
  appliance does not have is reported as an error listing the groups it does
  have — importing nobody and calling it success hides a typo forever.
- **An approval gate for directory users** (Settings → Authentication, applies
  to every external backend). With it on, a first-time directory sign-in creates
  the account **disabled** and refuses entry until an admin enables and profiles
  it under Users — the same state the importer produces, so import-then-approve
  and sign-in-then-approve converge instead of racing. The refusal says
  *awaiting administrator approval*, never *invalid password*: the bind
  succeeded, and blaming the credential sends the user to reset one that was
  correct. Existing accounts are never re-gated.
- **More than one sign-in source at a time, in an explicit order.** The setting
  used to hold one string, so Active Directory *or* LDAP *or* RADIUS. It now
  holds an ordered list and sign-in walks it, first acceptance wins. The local
  database is not on the list because it is not optional: it is the anti-lockout
  floor, always live, and a local account is never handed to a directory. Order
  is not cosmetic and the page says so — an unreachable source burns its whole
  timeout before the next is tried, and every source ahead of the winner counts
  a wrong password against its own lockout policy. A source list that cannot be
  parsed disables external sign-in rather than falling back to the value it
  replaced: local still works, so nobody is locked out, and no directory is
  consulted on the strength of a policy nobody can read.
- **Several import groups per source, each with its own profile.** "Import
  `grp_ops` as operator and `grp_ro` as readonly" is now one configuration
  instead of two passes. A user listed by two groups keeps the first row's
  profile, and a blank profile inherits the global default. One group name the
  appliance does not have **fails the whole import** and names the groups it
  does have — a partial roster reported as success is how a typo becomes
  permanent. The per-group profile is an *import-time* concept on purpose: a
  RADIUS Access-Accept carries no group, and resolving one would put a REST
  round-trip to the FortiAuthenticator on the critical path of every first
  sign-in. Just-in-time users get the global default instead, which is why that
  default is now `readonly` and why the approval gate exists.

- **New directory accounts default to `readonly`, not `operator`.** Least
  privilege: an account nobody has looked at yet gets the profile that cannot
  change anything, and elevation is an explicit admin action. An unknown profile
  name anywhere in the chain falls back *down* it, never up.
- The CR action menu is DERIVED from the automation catalog (every targeted
  action that is `danger` or user-scope) instead of a hand-written pair. This
  puts `policy_set_status`, `backend_set_status`, `backend_set_config`,
  `swap_certificate`, `cert_lifecycle` and `custom_rest` under change control
  for the first time.
- `upgrade_prep` now declares `products=("fortiweb", "fortiadc")`, matching the
  ADC branch `upgrade.prepare()` has had all along.
- `cert_lifecycle` is flagged `danger`. It revokes superseded certificates and
  DELETES certificate material off the appliance; the flag was missing, so the
  UI did not warn and the sweep was not eligible for change control.
- The "clients affected by this window" read is per product: FortiWeb server
  policies, FortiADC virtual servers. Reading only the FortiWeb shape made
  every ADC in a window look like it had no clients at all.
- **The per-username allowlist** (`Settings → Access Control → Allowed Users`).
  It was a fourth gate stacked behind the directory group filter, the approval
  gate and the profile, and it enforced nothing the three of them did not —
  while going stale on every import: a user could be imported, approved, enabled
  and still take a blanket `403` on every page, whose only trace was one log
  line. It also protected the wrong people, since admins were exempt by design,
  so it only ever restricted `readonly` and `operator` accounts. **Profiles
  decide what a user may do; the directory group decides who may authenticate.**
  The IP whitelist on the same card stays, because it answers a question none of
  the others do: *where* a session may come from.
  An install that stored a list is told so — at boot in the log and on the
  Access Control page — and offered a button to clear the dead row, because
  removing a gate silently is how an install gets wider without anybody
  noticing.

- **The vendor mark, as a file** (`app/static/img/favicon.svg`). A previous
  round stopped every live template from *referencing* Fortinet's registered
  glyph in `#ee3124`, but left the artwork in the tree — so `GET
  /static/img/favicon.svg` still answered **200** from SATOM's own origin.
  Under Elastic License 2.0 this product is sold, which makes a vendor mark on
  our static path a trademark surface rather than a stale asset. The
  appliance-type marks (`fortiweb-mark.svg`, `fortiadc-mark.svg`,
  `fortianalyzer-mark.svg`, `fortiauthenticator-mark.svg`) **stay**: they label
  which kind of box a row is about, which is nominative use, and none of them
  uses the corporate red. Deleting a file is the change where *nothing* fails,
  so the guards are assertions of absence — one of them over HTTP, because "not
  in the repo" and "not served" are different claims — plus a sweep that would
  catch the same artwork under a different filename, which is how this one
  survived three project renames in the first place.

### Fixed

- **The translation layer had never produced a single translation.** It read
  `.content` off the provider result, whose field is `.text`, through a
  `getattr` with a default — so every call returned an empty string and was
  reported to the operator as *"the provider returned an empty translation"*,
  blaming the model for a reader bug. The test that covered it built its own
  stand-in object carrying the misspelled attribute, so the test and the defect
  agreed with each other. The double is now the production class.
- **A translated string can no longer corrupt the document it is written into.**
  Placeholders (`{devices}`, `{action}`, `%s`) and backticked identifiers are
  hidden from the model behind markers rather than requested back: asked to
  preserve them, the model translated the words inside them — `{devices}` came
  back as `{dispositivos}`, `` `approved_by` `` as `` `aprobado_por` ``. A reply
  that still drops, invents or alters one gets a single corrective retry and is
  then refused, never stored.
- **Echoed delimiters no longer reach the catalogue.** The model translates the
  untrusted-input fence it is told to ignore, in shapes that keep changing
  (`<<<FIN NO CONFIABLE>>>`, `<<<NON FIDATO>>/>>`, `<<(fin de UNTRUSTED)>>`).
  Both ends of a reply are now stripped by shape, and anything left is judged
  against the source rather than against a list of known shapes — enumerating
  them is a race that always runs one shape behind.
- **The change-type picker could not be answered with its own first entry.**
  On `/change-requests/new` reached directly — no pre-flight run to cite — the
  picker opened with the first change-controlled action *already selected*, and
  the page only learned the question had been answered from a `change` event.
  Choosing the entry that was already selected fires no such event, so an
  operator who wanted that type clicked their answer and watched nothing happen:
  step 3 never appeared and no wording was ever proposed. Nothing failed; the
  page simply never heard the answer. It is the identical trap the language
  radios were fixed for, left standing on the select beside them. The picker now
  opens on a **question** (`— Choose the type of change — / — Art der Änderung
  wählen —`, following the chosen language like every other proposed string),
  carrying no value and marked `required`: every real choice is a change of
  value, so it always fires. Returning to that entry closes step 3 again rather
  than leaving three filled-in fields describing a change type nobody chose.
  Arriving from an appliance's pre-flight page is unaffected — the link already
  answers question 2, and the question is not re-asked in front of its answer.
- `Appliance._own_client()` returned a **FortiWeb** client for a
  FortiAuthenticator, so every generic caller spoke the wrong dialect to a FAC:
  `probe_status()` reported `fac01` OFFLINE (measured) while its own client
  answered fine.
- The new-CR form coerced an unrecognised action to `upgrade` — the most
  destructive entry on the menu. It is now rejected.
- The form now refuses a device whose product the chosen action does not
  support, and refuses several devices for a `single_target` action. Both used
  to save happily and then resolve to zero (or one) targets at fire time,
  reporting `skipped` — which the lifecycle grades as failed, hours later.



- **The login page was rate-limited as if viewing it were a login attempt.**
  `/auth/login` carried a flat `5 per minute`, counting `GET` and `POST` alike,
  so five *renders* in a minute — a logout redirect, a couple of reloads, one
  failed attempt — answered `429 Too Many Requests` on the **form**, locking the
  operator out without a single password having been guessed. The limit now
  applies to `POST` only, which is the verb that carries a credential; the
  per-account lockout still covers the distributed case. Verified live: 12
  consecutive page loads all `200`, the 6th POST still `429`, and the page stays
  reachable *while* POSTs are being refused — a user who is being throttled has
  to be able to read the screen telling them so.
- **Signing in could sign you straight back out.** Requesting `/auth/logout`
  without a session redirects through `@login_required` to
  `/auth/login?next=/auth/logout`, and the login view honoured that `next` — so
  a successful sign-in immediately hit logout. `next` is now refused when it
  resolves to the logout endpoint, matched on the resolved path rather than on
  the substring `logout`, which a legitimate page may well contain.

- **NetBox is now the maintenance window.** Settings → Integrations wires SATOM
  to a NetBox instance (URL, encrypted token, TLS verification, a hard timeout
  and a per-appliance device mapping) and opens a real maintenance window when a
  change request starts running, closing it from the outcome when the run ends.
  Stated plainly because it decides how this works: **NetBox core has no
  maintenance-window object** — that lives in third-party plugins — so SATOM
  records the window using core models only (a journal entry, a device tag, or
  device custom fields, selectable) and therefore works against any NetBox, with
  or without plugins. Every window time carries an explicit `+00:00` offset:
  SATOM stores naive UTC, and a naive timestamp handed to another system is read
  in *that* system's timezone. That is not theoretical — against NetBox 4.6.7 a
  naive value round-trips with no `Z`, i.e. it was taken in the server's own
  zone, which is how a window silently moves by hours.
- **Integration hooks — your own Python, run out of process.** A hook is a small
  script SATOM runs when it emits an event (`change.requested`,
  `change.approved`, `window.opening`, `window.closing`, `upgrade.finished`,
  `upgrade.failed`) — for example, opening a change ticket in your own CRM and
  handing the reference back to the change request. Hooks **never execute inside
  the web application**: saving one only writes it to disk, and a privileged
  runner (`satom-integrations.service`, watching a queue directory exactly like
  `satom-updater`) executes it as an unprivileged user, in its own process
  group, with a hard timeout, and with only the secrets the hook declared. A
  syntax error is refused at save time with its message rather than discovered
  at 03:00 inside a maintenance window; captured output is truncated and any
  declared secret's value is redacted before it is stored. A hook returns its
  result through a dedicated channel, not by printing JSON — otherwise a script
  could fake its own verdict.
- **Fail-closed external approval.** A change request can be bound to an
  external change authority (Approval → *External*); it is then runnable only
  once that authority explicitly approved it. Unreachable, slow, ambiguous and
  never-asked all land on the same side of that line — the entire reason to
  route approval through a change-management system is that silence means no.
  Withdrawing an approval clears the record, so it cannot still open a window.
  Change requests that predate this default to *Manual* and behave exactly as
  before.
- The change-request page now shows the external ticket reference and link, the
  window's state in NetBox, and an integration log. That state distinguishes
  **“none requested”** from **“error”** — collapsing them would let an
  integration outage read as a deliberate decision and hide that NetBox may
  still show a device in maintenance.


- **The affected users are emailed when the window closes**, on success and on
  failure, with the reason attached. Recipients come from the change request's
  own *Notify on completion* list, falling back to the default recipients in
  Settings → Email; when neither is set nothing is sent and the request records
  why — SATOM never guesses an address. The notice is sent once, is deliberately
  not the pre-window warning (that one tells a customer to brace for an outage
  that is already over), and a send failure never re-grades the change: an
  upgrade that worked worked whether or not the SMTP server answered. A failed
  send records no delivery timestamp, so the notice stays retryable.


- **The hardened runner sandbox silently broke its own queue.** The
  integration-hooks unit granted four separate `ReadWritePaths=`, and systemd
  makes each one its own bind-mount: the runner's claim step is a `rename(2)`
  between two of those directories, which across mounts is `EXDEV`. The runner
  reads that error as “another runner claimed it first”, so the request was
  never executed, nothing was logged, the status stayed `queued`, and because
  the watch is level-triggered the unit re-fired until systemd hit its start
  limit. The queue now lives under one parent with a single grant — narrow
  enough that a hook still cannot reach `data/sot/` or `data/jobs/` — and a
  guard asserts both halves so a future tidy-up cannot reintroduce it.

- **Deleting an object other objects still point at is refused.** SATOM sent a
  `DELETE` for any object the operator named and let the appliance decide.
  FortiWeb does not reliably refuse a referenced object, and when it does not,
  nothing fails: the holders keep naming something that no longer resolves and
  the first symptom is broken traffic. Every delete now reads the device's own
  `q_ref` bookkeeping first and refuses while the count is non-zero, **naming
  the holders** when the collection reports them
  (`inline-protection(wpp-full-lab)`). The check runs on the **Preview** too,
  so the refusal appears before the confirmation prompt rather than after it.
  An object whose refcount could not be read is **not** deleted; a firmware
  that does not report refcounts at all is not blocked, because a missing
  capability is not a missing answer. `force: true` on the delete endpoint
  overrides a refcount the firmware got wrong and is stamped in the audit
  detail as `ref_check=forced`.
- **A Change Request can now end.** The lifecycle declared seven states and only
  three had anything that wrote them: `approved`, `cancelled` and `scheduled`.
  Nothing ever assigned `in_progress`, `completed` or `failed`, so a change
  request that fired its upgrade stayed at `scheduled` for good — the bound
  action is a one-shot, so nothing was ever coming back to close it. Nothing
  failed while that was true; the record simply stopped describing reality. The
  executor now moves the request to `in_progress` when the window authorizes the
  fire and closes it from the outcome afterwards. A run that skipped is graded
  **failed**, not left open: a window that elapsed without the change happening
  did not succeed, and the operator has to see the reason.
- **The maintenance-window gate applied to one action name.** It was keyed off
  `action == "upgrade"` while the change-request form already offered
  `upgrade_prep`, so that one fired with no approval and outside its window —
  the one thing the gate exists to prevent. Any action bound to a change request
  is now gated by it.
- **Device output was rendered, complete, and invisible.** `.fw-pre` — the panel
  the SSH health battery, the inspector's JSON dump, the three git consoles in
  Settings and the formal change document all print into — was a dark-theme
  leftover: `rgba(0,0,0,0.30)` over a white card composites to a light-grey slab
  and its `#94a3b8` text sits at about 1.3:1 on it. Nothing failed; the text was
  simply not readable. The panel now paints from the product tokens, and keeps
  `white-space: pre` with its own scroll so column-aligned CLI output stays
  aligned and a long line can never widen the card that holds it.
- **Upgrade-preparation results no longer overflow their tiles.** A firmware
  build string and a timestamped backup filename were rendered as `.h5` headings
  inside quarter-width columns, where long unbroken tokens do not wrap. They now
  use a tile built for strings rather than for counts, and the backup filename
  has moved out of its badge onto its own line: the badge states the verdict,
  the filename is the evidence.
- **The page uses the product's chrome.** It was assembled from raw Bootstrap
  cards, badges and alerts; `.card` has no override in the product stylesheet, so
  it rendered unlike every other page, and the Bootstrap status colours are not
  the ones calibrated against white. Values read off the appliance are now
  HTML-escaped before reaching `innerHTML` — a policy name carrying `<` silently
  ate the rest of its row, which looks exactly like missing data.


- **The About card in your profile announced `v1.0`.** It had been wrong for
  eight releases. `app/version.py` exists precisely to kill hand-written
  version numbers — its own docstring records that the footer and Settings →
  System Information each carried a `v1.0` that "quietly rotted through 1.1,
  1.2, 1.2.1 and 1.2.2 while the release pipeline dutifully published the real
  number everywhere else". The card now interpolates the shipped version.

  **The guard that should have caught it was an enumerated list.** It walked
  exactly two templates, `base.html` and `settings/index.html`; the literal
  lived in a third. An allowlist written by hand over a tree that keeps growing
  stops covering new files without ever failing. The rule now sweeps *every*
  template and an exemption must carry a written reason — the four that remain
  are appliance-API versions (`v2.0`), not ours.

- **The same card described SATOM as a FortiWeb console.** It advertised an
  `API Target` of "FortiWeb 7.6 REST API", a "Custom FortiWeb 7.6 Theme" and a
  "Multi-user FortiWeb & FortiADC management console". SATOM routes four
  distinct appliance clients — FortiWeb, FortiADC, FortiAuthenticator and
  FortiAnalyzer — so naming one API was not incomplete, it was false. The API
  row is gone and the description no longer names a family. The description was
  also never marked for translation, so it stayed English in all five
  languages; it is translated now, as is the card's title.

- **Settings → Default appliance platform offered three of the four families,
  and discarded the others in silence.** FortiAuthenticator and FortiAnalyzer
  were missing, and `FortiWeb-Cloud` — a family SATOM has no client for — was
  offered as though it worked. Worse than the missing options was the
  server-side rule behind them: a hardcoded three-value whitelist folded
  anything else to `FortiWeb` with no error, so a posted `fortiauthenticator`
  was *stored as FortiWeb*. The operator chose one thing and the system saved
  another.

  The list now has a single author — the same product registry that drives the
  appliance form (`product_scope.device_products()`) — and the server validates
  against that registry rather than a copy of it. Values written before this
  change still read back: the old `FortiWeb`/`FortiADC` spellings map onto the
  registry keys, and `FortiWeb-Cloud` folds to `fortiweb`. Without that
  migration an existing installation would have opened the page with *no*
  option selected and the operator would have read it as a lost setting.

- **The setting now does what its help text has always claimed.** "Pre-selected
  when registering a new appliance" was untrue: `default_kind` was written and
  displayed, and nothing ever read it — the appliance form ignored it entirely,
  and its vocabulary (`FortiWeb`) could not have matched the form's
  (`fortiweb`) even if it had. Registering an appliance now starts on the
  configured platform.

## [1.9.2] - 2026-08-09

### Fixed

- **The object editor no longer offers a free text box for a field that only
  accepts the name of an existing object.** Twenty reference fields — eighteen
  on the Web Protection Profile, two on the Server Policy — had no entry in the
  schema's reference map, so they fell through to a plain text input while
  their neighbours were dropdowns. A value typed there went to the appliance and
  came back as `errcode -651: Invalid input value.`, which names neither the
  field nor the value; FortiWeb refuses the whole write, so the good fields in
  the same save were discarded with it. Each of the twenty collections was
  probed on a live appliance before it was mapped, and the ones whose collection
  could not be proven were deliberately left unmapped — a wrong mapping would
  populate the dropdown from the wrong collection and reject valid values.

### Added

- **Reference fields are checked against the appliance before the write.** Every
  operator-facing save and create resolves each submitted field to the cmdb
  collection it selects from and asks the device whether the value is there,
  on the preview path as well as on apply. The refusal names the field, the
  value, the collection and the names that do exist. "Collection empty",
  "collection absent on this firmware" and "could not ask the device" are kept
  apart — all three answer with zero names and they mean opposite things, and
  only the first two justify refusing. A device that cannot be read never
  blocks a save; the affected fields come back as `unverified_refs`.

## [1.9.1] - 2026-08-09

### Fixed

- **A migrated Custom Access Rule now carries the conditions it matches on.**
  A rule was declared in the dependency map as a leaf, so a clone or a
  cross-appliance migrate copied its NAME and none of the per-rule filter
  sub-tables that hold its whole meaning — which URL, which source IP, which
  rate limit. The job reported success, the GUI showed the rule on the
  destination, and the rule enforced nothing. Found on a real migration:
  `car-ratelimit` moved from one appliance to another with its URL filter
  (`^/api/`) and its rate limit (100) dropped, leaving a rule that looked
  migrated and matched no traffic. All seventeen filter sub-tables the endpoint
  registry knows about are now walked with the rule.

  Widening the map is only safe because of the second half of this fix.
  FortiWeb does not answer an unimplemented sub-table path with a 404 — it
  echoes the PARENT OBJECT back, so every name added to the map is a path that,
  on a firmware that lacks it, would have manufactured a filter row built out
  of the rule itself. By-parent reads now drop that echo, on the source and on
  the destination. The destination half is the quieter one: the echo is matched
  against the source row by content, so a row whose fields are a subset of the
  parent's was classified *already present* and silently never created.

- **A cloned Web Protection Profile now owns its whole tree.** The guided clone
  runs the tree engine with the SAME appliance as source and destination, and
  that engine's central verdict — *already at the destination, do not copy* —
  is correct across two boxes and inverts its meaning on one: every sub-object
  of the source profile already existed, so the "clone" was the root profile
  renamed with roughly forty sub-policies still shared with the original.
  Nothing failed and nothing warned; the plan said `exists` for every child,
  which was true. The consequence was found on a live appliance: a profile
  cloned for one Server Policy still named the original's allow-method policy,
  so an allow-list authored for that one site went live for five. The clone now
  recreates every sub-object the new profile may own under this policy's own
  name and re-points the references, and the re-point rewrites only the
  dependency field that names the object — never any string that happens to
  match it.

- **A duplicate is no longer reported as a refusal.** Pushing a carve-out
  writes in two steps, and the first — create the named container — POSTed
  unconditionally despite an option that says *create the container if it does
  not exist*. On any appliance where the container was already there it always
  came back `errcode -5`, and because the result was the AND of both steps it
  dragged down a second step that had just written the exception successfully.
  The operator was told the appliance had rejected a carve-out that was live,
  and pressed the button again. The container is now probed before it is
  created, a `-5` is recognised as "already there" rather than a rejection, and
  a carve-out already on the box is reported as such — never as *created*, and
  never as *rejected*. Errors that are not duplicates still fail, and the code
  is matched, not the sentence, which is the localisable half of the answer.

- **The audit listing is now totally ordered.** It sorted by timestamp alone, so
  rows written in the same second came back in whatever order the database chose
  — which it is free to change between two queries, letting one row appear on two
  pages or on none. `id` is now the tiebreak. The new ID column is also what makes
  such a duplicate visible at all.

### Added

- **The clone says what it cannot copy, before it writes.** Three things are
  never duplicated silently: FortiWeb's own predefined objects (detected from
  the `can_view` marker the appliance sets, verified against a live 7.6.8 box),
  objects an approved template governs, and anything whose parent stays shared
  — re-pointing a reference is a write to the parent, so copying a child under
  a shared parent would leak the change to every profile behind it. The
  Exceptions page now previews the clone before authorising it, listing what
  will be copied and what will stay shared with the source; the first two can
  be overridden object by object, the third is a consequence and is not offered
  as a choice. Applying a plan that leaves anything shared requires an explicit
  acknowledgement.

- **Capacity is checked per object type, for the whole plan.** The clone used
  to ask one question — is there room for one more Web Protection Profile? —
  which was the whole story while it created one object. It now sums the plan
  per capped type before the first write, because the failure to prevent is not
  a rejected POST but a clone that dies half-written and is never re-bound.
  Object types with no configured limit are reported as unchecked rather than
  skipped in silence.

- **Every audit entry now shows the ID it always had.** `audit_logs` rows have
  carried a primary key since the table existed, and nothing ever displayed it —
  so the only way to point at one entry was to quote its timestamp, which is not
  unique: a single apply writes several rows inside the same second. The listing
  gained a leading **ID** column (click it to copy, without opening the drawer),
  the detail panel opens with the ID and its own copy control, and the search box
  resolves an ID back to its row — bare (`4821`), as the table prints it
  (`#4821`) or as a ticket tends to quote it (`AUD-004821`).

  The ID search is **OR-ed into** the existing text search, never substituted for
  it: a numeric query like `8443` still matches the targets and payloads that
  contain it. And it is not a way around ADOM scoping — a FortiWeb session that
  guesses a FortiADC row's number still gets nothing.

## [1.9.0] - 2026-08-08

### Changed

- **The required scope is ticked, not demanded.** An Allow Method or
  HTTP-constraint exception is keyed by FortiWeb on a URL pattern, and the
  panel knew all three of the things that follow from that: which field it is,
  that the entry carried a value for it, and that leaving it unticked produces
  no exception at all — only a refusal naming `request-type` and `request-file`,
  keys the operator never typed. It spent them on an instruction pointing at an
  unlabelled checkbox in a twenty-two row table in the card above. The panel now
  ticks that box itself, in the table where it can be seen as well as in the
  state that gets posted, and the scope list reports what is actually ticked
  rather than what it meant to tick. Only fields that NARROW are ever
  pre-ticked, so the default cannot widen a carve-out; unticking is still
  allowed and immediately restores the explanation of what is missing. A
  required field the entry does not carry is reported as absent instead of as
  something to go and tick, because no row is drawn for a field with no value
  and there would be no checkbox to find.

- **Asking the AI about a field now answers on the click.** The chat icon on
  each element of an attack-log entry used to open an empty box and wait for
  the operator to compose a question — a second gesture to get the thing they
  had just asked for. It now sends the exchange immediately and renders the
  Advisor's answer under the local explanation of that element, keeping the box
  below it for the reply. The question itself is still left empty by the
  browser so the server supplies its default text: that is the string the audit
  row records, and a browser-side default would put a question in the log that
  the provider was never sent. The automatic exchange fires at most once per
  field per opened entry — after an answer *or* an error — because an automatic
  retry against a provider that just failed spends tokens to reproduce a
  failure already on screen. Time and tokens are stamped on it by the same
  single cost chip every other analysis on the page uses.

### Fixed

- **A carve-out on a shared profile reported failure for a change it had
  already made.** Authoring an exception against a Server Policy whose Web
  Protection Profile is shared correctly cloned the profile and re-bound the
  policy — both written to the appliance — and then answered *"An unexpected
  error occurred"* and discarded the draft. The clone was never the problem.
  The cache refresh that runs afterwards recorded its `SyncRun` under a
  27-character label in a `varchar(24)` column; Postgres raised on the flush,
  which leaves the SQLAlchemy session in a failed transaction, and the
  best-effort `except` swallowed the error without clearing it — so the next
  write, the operator's own carve-out, died with `PendingRollbackError`. All
  three links are closed: the label fits, an overlong one is now clipped rather
  than raised, and a swallowed best-effort failure rolls the session back so a
  caller can never inherit a dead transaction. A new guard fails the build for
  any `trigger=` literal that does not fit the column, which is where this
  should have been caught: nothing about a bookkeeping label was ever supposed
  to be able to kill the work it describes.

- **Every audited action was attributed to the reverse proxy.** SATOM is always
  served through nginx, so `request.remote_addr` is the proxy — and the audit
  log recorded it verbatim, leaving 193 of the last 200 rows on a live node
  stamped `127.0.0.1`. An audit trail that cannot tell two operators apart is
  not an audit trail, on a product whose entire job is authorising changes to a
  WAF. The helper that resolves this correctly had existed all along and had
  exactly one caller, the rate limiter. Audit rows, API-token last-used stamps,
  500 correlation records and the account-lockout log lines all use it now.
  Historical rows are left as they are: they are wrong, and rewriting an audit
  trail to make it look right is worse than leaving it legible.

- **The `FORBIDDEN` log line let the prober choose which address it blamed.**
  It read `X-Forwarded-For` directly, with no check that the peer was a trusted
  proxy, so any client could set the header and be recorded as someone else on
  the one line whose purpose is attributing a probe. It now resolves the
  address through the same helper, which honours the header only when the
  direct peer is a configured proxy and takes the proxy-appended hop.

- **Every attack-log entry was opened twice.** The panel registered its boot on
  `DOMContentLoaded`, which Turbo remaps to `turbo:load`, and registered
  `turbo:load` as well so it survives the body swap — so both fired on a first
  load and the result table carried two click handlers. One click read the
  entry off the appliance twice, rendered the builder twice, and left anything
  holding a handle to a rendered node pointing at whichever render lost the
  race. The table is now bound once per render, flagged on the table itself so
  a real navigation still binds.
- **An Allow Method exception could not carry the method it was supposed to
  allow.** `allow-request` is the allow list itself, and the carve-out builder
  never set it. Ticking *Method* — the obvious move on an entry blocked by the
  Allow Method check — was answered with "FortiWeb has nowhere to put it", and
  the payload that did pass validation held a URL and no allow list at all: a
  row FortiWeb stores, applies, and which allows nothing, leaving the request
  blocked with nothing on screen to say why. The method is now taken from the
  entry itself (the appliance already recorded which one it rejected) and the
  allow list is a required field for this type everywhere it can be authored,
  including the manual Exceptions form.
- **"Explain this field" did nothing.** The attack-entry panel bound its
  delegated handlers each time an entry was opened, to an element the panel
  refills but never replaces. Every open added one more handler to the same
  node, so from the second entry onwards a click toggled the explanation open
  and shut within itself and nothing appeared. The handlers are now bound once,
  where the element is created.
- **A required scope was offered as an optional narrowing.** FortiWeb keys
  Allow Method and HTTP-constraint exceptions on a URL pattern, but the panel
  listed the URL under *tick any of these to narrow it* and then failed with
  `'request-file' is required for this carve-out type` — a device field name
  the operator never typed. Required scopes are now marked as such up front,
  and a missing key names the box that supplies it, worked out by re-running
  the real assembly rather than from a second table that could drift from it.
- **Every status badge in the Attack ID pages was unstyled.** The verdict, risk,
  breadth and action badges asked for `fw-badge-ok` / `-warn` / `-crit` /
  `-neutral`, which are not classes the stylesheet defines; the base `.fw-badge`
  sets no colour, so `true-attack` and `false-positive` rendered identically.
  They now use the calibrated `-success` / `-warning` / `-danger` / `-secondary`
  set, and a guard fails the build if any badge class used anywhere is not
  defined in the stylesheet.
- **An exception could be authored on a Web Protection Profile that several
  Server Policies share, with nothing said about it.** SATOM refused a
  carve-out on a *template-managed* profile and asked no other question — but a
  WPP applies its exceptions to every Server Policy that binds it, and FortiWeb
  records nothing about which policy one was authored for. An ordinary,
  unlocked profile bound by four sites took the carve-out in silence and
  applied it to all four. `wpp_scope` now reads the bindings off the device and
  refuses a shared profile the same way it refuses a template, naming the other
  policies in the refusal and offering the same guided clone. A policy that
  already owns its profile outright gets no clone — there is nothing to protect
  it from. A device that cannot be read answers *unknown*, never *no one*.
  Enforced hardest at the push, which is where the leak physically happens.

### Added

- **The results table shows the Web Protection Profile behind each policy, and
  whether it is shared.** Whether the profile is exclusive to this Server Policy
  decides whether authoring an exception is one click or a profile clone and a
  re-bind of live traffic — and the page already knew, because it reads the
  bindings to run the scope gate. It just never said so until after the operator
  had committed. Shared profiles name the other policies; a profile that cannot
  be read renders as `unknown` rather than blank, because "SATOM could not ask
  the appliance" and "this policy binds nothing" are opposite facts and an empty
  cell is how the harmless one looks. One device read per table, whatever the
  row count, and the derived value is kept beside the entries rather than
  written into them — a row is evidence the appliance reported, and a derived
  field mixed into it would reach the AI prompt and the audit trail dressed up
  as something the device said.

- **The field picker opens with the scope already chosen, and says why for each
  box.** It used to open empty, which asks the operator the one question they
  came here unable to answer: which of twenty-two fields scope *this* kind of
  exception. Everything needed to answer it was already declared — which fields
  exist, which are required, which order is most precise — so the
  recommendation is derived from the same table the picker renders. Required
  fields are always taken. A signature exception takes exactly one element, the
  most precise the entry carries, because FortiWeb matches one per row and
  ticking more would recommend a selection the device cannot honour. The source
  address is held back while the request can be described by URL or host — it
  identifies the caller, not the traffic, so an exception scoped to it stops
  applying the moment that integration is re-addressed — but it is one click
  away, and the reason it was left off is on screen rather than implied. The
  selection is proved by running the real assembly, so a default that would not
  validate says so on arrival instead of at Preview. Everything remains
  editable; this is a starting point, not a decision.

- **Ask the AI about one field, and read the answer where the field is
  explained.** Each row of the attack entry now carries a second icon beside
  the explain one. It opens a conversation about that single element, directly
  under its local explanation rather than in another page: leave the box empty
  for a general reading, or type the question in your own words and press
  Ctrl+Enter. Follow-ups continue the same thread, so a second question does
  not mean restating the entry. SATOM sends only which entry and which field —
  the value is re-read from the appliance, exactly as every other acting path
  on this page does, because a browser that can supply the evidence can invent
  it. This path explains and cannot author: it is told not to draft a
  carve-out, returns none to the screen, and any the model drafts anyway is
  dismissed rather than left sitting as an unreviewed pending draft. Every
  search, question and answer is recorded, with the question verbatim.
- **Every analysis on the panel now states what it cost.** One line under each
  result: which engine produced it, how long it took, and how many tokens it
  spent — including the failures, because a provider that burned forty seconds
  and then errored spent them. The local field explanation reports "no tokens",
  which is a fact; a reply whose provider omitted the usage block reports
  "tokens not reported", which is not the same claim as zero and is never
  rendered as one. While a call is in flight the wait carries a running clock.

- **Field-by-field investigation in the attack-entry panel.** Every field now
  explains what it is, what this value classifies as, and what to check next:
  address scope (RFC1918 / CGNAT / documentation range / public) with the
  reminder that a private source means the real client is in X-Forwarded-For,
  percent-decoded URLs with the decoded form judged rather than the raw one,
  query parameters broken out, port and method semantics, user-agent
  classification, signature-class decomposition, and how often the same value
  appears across the last 100 entries on that appliance. All computed locally —
  no WHOIS, geolocation or threat-feed lookup, and the panel says so.
- **Build an exception from the fields you tick, whatever the Advisor
  concluded.** The Advisor drafts one only for a false positive at acceptable
  risk, which left no route for the commonest real case: a genuine attack
  pattern that one known caller must still be allowed to send. Tick the fields
  the exception must be scoped to, pick the kind, and SATOM assembles a
  FortiWeb-valid payload from the entry **as the device reported it**. A
  carve-out that contradicts the Advisor is allowed and requires a written
  justification, stored with the rule and in the audit trail.
- **SATOM says which kind of exception the block actually calls for.** A
  protocol-constraint block is not fixed by a signature exception, and the log
  row does not say so in those words. The candidate types are ranked for the
  entry, each with its reason, narrowest first.
- **Drafts are reviewed as a description, not as JSON.** Where the rule lands
  (Server Policy → profile → module → type, and which FortiWeb object holds
  it), how wide it reaches, what stops being inspected and what stays enforced
  — with the raw payload still one click away for editing. Breadth is computed
  from the payload, not the type: a per-signature exception with no element to
  match is reported as wider than its type suggests, because it is.
- **Insert the exception into the appliance from this page.** Two calls: a
  preview that returns the exact method, endpoint and body and writes nothing,
  then the write. The page previously stopped at the draft and sent the
  operator to another screen to push it.

## [1.8.0] - 2026-08-07

### Fixed

- **The AI Advisor's replies were saved and never shown.** After Send, the
  page sat silent and the answer only appeared on a reload — with no cost
  figures, because those are drawn with the reply. The cause was one
  identifier: a nested callback assigned to `input`, a variable that belonged
  to a sibling function's scope. JavaScript resolves that to nothing, so the
  callback threw on that line and never reached the next one, which was the
  call that redraws the thread. Every server-side test passed, because the
  server was right the whole time. Fixed at the root rather than patched: all
  DOM handles are now declared once at the top of the script and the send path
  takes what it needs as arguments, so the cross-scope reference is no longer
  writable. Guards enforce the convention, including one that fails when the
  script calls a function it never defines.


- **`update_status()` built a filesystem path out of an unvalidated URL
  segment**, so a traversing request id turned an admin-only status reader
  into "read any `.json` the service account can read". Request ids are
  minted in one place and always match `[A-Za-z0-9_-]+`; the check now
  lives where the path is assembled rather than in each caller, because
  validating per caller leaves the next caller to remember. Found while
  wiring the peer status poll.

### Added

- **The chat streams, shows that it is working, and can be stopped.** The
  reply now appears as it is generated, with an animated indicator, a live
  elapsed clock, and a chip per tool call while the model is using one. A
  **Stop** button cancels: aborting the request closes the socket, which closes
  SATOM's connection to the model, so generation genuinely ends rather than
  continuing invisibly and billing for it. Whatever was produced is kept,
  marked as stopped, and written to the ledger as a cancelled call — throwing
  it away would discard tokens that were really spent and leave the next page
  load blank. A heartbeat keeps the connection alive through a cold model load
  (up to ~90 silent seconds on a 32B local model) and is what lets Stop take
  effect within a couple of seconds instead of at the next token. The response
  carries `X-Accel-Buffering: no`, because nginx buffers proxied responses by
  default and this product's vhost is written by the installer rather than
  carried in git — a directive there would never reach an existing install.
  The blocking `POST /advisor/<id>/send` is unchanged; both paths run the same
  engine, so the tool loop, redaction and ledger cannot drift apart.
- Errors now render in place of the reply instead of an alert box, and the
  composer keeps what was typed when an external-provider preview is declined.

### Changed

- `deploy/satom.service` raises the gunicorn worker timeout to 600s. It was
  120s while the provider timeout is 180s — inverted, so a slow model had its
  worker killed before the provider could report a timeout, and a diagnosable
  error arrived as an opaque dropped connection. A test now fails if the
  ordering is ever reversed.

- **The AI Advisor's read-only tools are now actually reachable by the
  model.** They shipped as a set of functions with nothing that invoked
  them: the catalog was served over HTTP and `call_tool` was never called
  from the chat path, so the model could not use a tool whatever it emitted.
  The chat now runs a bounded tool loop, and the catalog grows from three
  entries to eight — `list_appliances` (which every other tool depends on,
  because they all take an `appliance_id` the model had no way to learn),
  `list_server_policies`, `device_health`, `list_probes` and
  `recent_config_changes`, alongside the existing SoT, exception and Lua
  lookups. All read from the database and the harvest cache, so an answer
  still arrives with the appliance powered off.
- **Tool output is redacted before it can leave the LAN.** Redaction
  previously covered the operator's message and the attachments they chose.
  A tool result is neither — the model asks for it and SATOM injects it — so
  the model could have pulled hostnames and addresses from the device cache
  and handed them to an external provider, around the preview the operator
  approved. Tool results are also wrapped as untrusted input, the loop is
  capped, oversized results announce their truncation in band, and tools are
  advertised to the model only while they are switched on.
- **Response time and token cost, per reply and in a ledger.** Every reply
  shows how long it took and what it cost; every provider call — local
  Ollama included, failures included — writes a row to the new
  `advisor_request_log`, readable at `/advisor/usage`. The duration spans
  the whole exchange including tool round-trips, which is what the operator
  waited for. Unreported usage is stored as `NULL` and shown as *tokens not
  reported*, never as `0`: several OpenAI-compatible gateways omit the usage
  block, and a confident zero would be a number the product never measured.
  A failed call still leaves a row, so a provider timeout cannot vanish.

- **Every node re-asserts its own metrics store on every code update.**
  The store binary and its data directory live outside the app tree by
  design — the data-sync replicates `data/` with `rsync --delete` and a
  time-series database cannot be rsynced under a live process — so nothing
  carried the store between nodes: not git, not the data-sync, not a
  database dump. The installer wrote it once and nothing wrote it again, so
  a node that joined the pair later, or was rebuilt, ran the analytics
  pages, the collection schedule and the service entry the diagnostics
  check with no store behind any of them; its panels returned a query
  error, which reads as a interface bug rather than a missing subsystem.
  New `deploy/install-metrics-store.sh`, called by the installer, by
  **both** update paths in the privileged runner, and by
  `satom execute reinstall metrics-store`. It is symmetric across an HA
  pair without any node reaching across another: the standby's reconciler
  enqueues rather than updating itself, so every node runs its own runner
  and repairs its own node-local artefacts. It can never abort an update —
  on an isolated network the download always fails, and making that fatal
  would trade a missing optional subsystem for an un-updatable product —
  and it arms the service only when the capability was genuinely absent, so
  a deliberate stop from Settings → General is not undone by the next
  update. `satom diagnose install` now grades the binary against its
  anchored digest and prints the service's runtime state without grading
  it. The digest gains a single home in `deploy/metrics-store.env`, pinned
  by test to the four shell files that must keep literal copies.

- **Start, stop and restart this node's services from the console.**
  Settings → General grows a **Services** card covering the web app, the
  scheduler, the reconciler, the metrics store, the alert / certificate /
  data-sync timers, nginx and PostgreSQL. The web worker never runs
  `systemctl` itself and is not granted it — a generic `sudo systemctl`
  reaches every unit on the box, so it is root spelled differently. Each
  action is queued for the privileged updater, which applies it, re-reads
  the unit's state (an exit code of 0 means the job was accepted, not that
  the daemon came up) and health-checks the three units that can take the
  console down. What a console admin can reach is a table, duplicated into
  the root runner and kept honest by a test that fails when the copies
  drift. `satom-updater` is not in it and is denied by name: stopping the
  runner means no later request can be processed, including the one that
  would start it again. `stop` is withheld from the web app, nginx and the
  database — each would leave recovery possible only from a shell, which is
  exactly what the operator using this page does not have. Runtime-only:
  nothing is enabled or disabled, and the card prints the boot state next
  to the live state. See `docs/safeguards.md` §33.

- **The standby's services can be controlled from the primary.** The card
  renders one section per node, because systemd is node-local and an HA
  pair has no single "the services". A peer is *asked*, never commanded:
  the primary POSTs a unit name and an action to the peer's own endpoint
  behind the shared node identity key, and the peer re-validates against
  its OWN allowlist before its OWN root runner does the work — a peer
  holding a valid key still cannot reach a unit that node does not permit,
  or the updater at all. Hosts are resolved from the node registry by name,
  never taken from the request. Unreachable is reported as unreachable and
  never as "queued" or as an empty unit list, a 2xx without an id is not
  success, a peer answering 404 is named as probably running an older
  release, and a poll that fails mid-restart says *polling* — that is the
  expected middle of a successful restart, not a failure. Peers load from
  their own endpoint so a dead standby cannot make a healthy primary's card
  look broken. See `docs/safeguards.md` §33b.


- **Service buttons are state-aware and colour-coded.** A stopped unit
  offers only Start, a running one only Restart and Stop, and colour
  carries the consequence: green adds capacity, red takes it away, amber
  interrupts and returns. What is *offered* is derived from live state;
  what is *permitted* is not — the endpoint gate stays a fixed table, so
  clicking a button that a poll invalidated a second earlier is a systemd
  no-op instead of a refusal the operator would read as a broken console.
  Units that may only be restarted (the web app, PostgreSQL) still offer
  Restart while they are stopped: `systemctl restart` starts a stopped
  unit, and withholding it would leave a dead unit with no button at all.

- **The General settings tab is laid out in two columns**, and **System
  Information is a full-width card split in two** — the facts and the
  library inventory used to be stacked in a narrow side column, which made
  it the tallest thing on the page. Side by side the card is about half as
  tall and neither table wraps.


## [1.7.1] - 2026-08-07

Recovery-custody fix. **1.7.0 shipped the sealed envelope in a state that could
not work**: the seal was written by root and read by the service account, so it
reached neither the peer nor any bundle while `diagnose recovery` reported the
durability problem solved. Anyone who sealed on 1.7.0 should re-run
`satom execute seal recovery` on the primary and confirm the check reports the
envelope as reachable. 1.7.0 stays published; this entry is the public record
that it carries the defect.

### Fixed

- **The sealed recovery envelope was unreachable by every mechanism that
  carries it.** `satom execute seal recovery` runs as root and wrote
  `data/recovery/` as `root:root`, while the HA datasync and the backup
  writer both read as the service account: the envelope existed, was
  cryptographically sound, and reached neither the peer nor any bundle —
  and `diagnose recovery` reported the durability problem solved. Sealing
  now hands the envelope to the tree owner (derived from the app root,
  never a hardcoded account name) before publishing it, and reachability
  is reported as its own fact. An unreachable envelope is a **critical**
  finding, deliberately worse than an honest "not sealed".
- **`diagnose recovery` could never report ok on a correctly sealed node.**
  A live, reachable, current seal now satisfies the "never exported"
  finding for the kind it covers — a stale, unreachable, or unreadable
  seal does not, and an unevaluable one stays noisy. The `sealed envelope`
  row is printed next to the `exported` rows so a quiet check is not an
  unexplained one.
- **Two CLI commands crashed formatting their own success.**
  `Result.rows()` takes the heading first; `seal recovery` wrote the
  envelope and then printed `[FAIL]`, and the same unexploded bug sat in
  `reset theme` — the anti-lockout command. A guard now walks the AST of
  every CLI module rather than the two known call sites.

### Added
- **The operator manual now documents recovery custody.** 1.7.0 shipped two CLI
  verbs, a diagnostic and a passphrase the operator must store outside the fleet,
  and `docs/user-guide.md` did not mention any of it. A capability nobody is told
  about is a capability nobody uses; a passphrase nobody is told to write down is
  one that is lost the first time it matters. §11 now states the fact that makes
  the envelope necessary — a bundle restored onto a rebuilt node is a database of
  unreadable secrets — plus where the passphrase comes from, why sealing belongs
  on the primary, and the three verbs. §32 gains the unreachable-envelope symptom.
- **`tests/test_manual_recovery.py`** — the manual must carry those facts, and
  must not hand-type a CLI command count. §20 claimed "94 commands in 34 groups"
  while the generated reference said 98 in 36: a number correct for exactly one
  release, ageing the same way the footer carried `v1.0` through four. The fix is
  not a better number but no number — the section points at `satom show tree` and
  the generated `docs/cli.md`, neither of which can drift. A counterweight test
  keeps the count in the generated document, so the rule cannot be satisfied by
  deleting it everywhere.

## [1.7.0] - 2026-08-07

### Added
- `tests/test_no_pem_literals.py` - no source file may carry a literal PEM
  private-key header. The publisher scans every blob of the sanitised mirror
  and refuses to push when it finds one; it cannot tell a test fixture from a
  real key, and must not learn to, because a scanner that skips headers
  followed by the word "fake" is one a real key walks past. A fixture that
  needs PEM-shaped bytes now builds the header at runtime. The rule costs a
  failing test at commit time instead of an aborted release.
- **Sealed recovery custody.** `FERNET_KEY` and the internal CA key are carried
  by no automatic copy — git excludes them, the HA datasync carries only
  `data/`, and the backup bundle leaves them out on purpose. The cost was that
  a bundle restored onto a rebuilt node is a database of unreadable secrets.
  They are now wrapped in a scrypt+AES-GCM envelope written to
  `data/recovery/seal.json`, which the datasync replicates to the peer within
  five minutes and every bundle carries off-box from then on. That is only safe
  because it is sealed: whoever steals a bundle holds ciphertext, while the
  operator holding a passphrase and nothing else can rebuild the installation
  from any copy. New verbs `satom execute seal recovery` and
  `satom execute unseal recovery`; `satom diagnose recovery` now reports an
  absent, unreadable or stale envelope.
- **The seal passphrase is created at INSTALL, not at cluster join.** A
  standalone node never joins and has no second copy of anything, so it needs
  the envelope more than a pair does; a secondary inherits the passphrase
  through the join key so both nodes open the same envelope. This adds no new
  class of secret — the join key already carries `fernet_key` and `ca_key` in
  the clear.
- **Recovery custody for the two secrets no backup carries**
  (`app/services/recovery.py`, `satom diagnose recovery`,
  `satom execute export recovery-key`). `FERNET_KEY` opens every encrypted
  column in the database and the internal CA key is the sole issuer for
  replication mTLS; neither is replicated by git, by the HA datasync, or by a
  backup bundle. The consequence was invisible and total: **a bundle restored
  onto a rebuilt node is a database of unreadable secrets**, with nothing
  anywhere explaining why. Putting the key into the bundle was rejected
  deliberately - a bundle is retained, mirrored to the peer and pushed off-box
  over SFTP using a password that itself lives in an encrypted column, so a
  bundle carrying the key that opens it would collapse the estate into one
  file in three places. Instead the manifest records a **fingerprint**
  (domain-separated, truncated - identity without disclosure), a restore
  compares it and **names** a key mismatch, and the operator gets an explicit
  audited export path plus a check that reports when it has never been used.
  On the primary this reported, the day it shipped, that **neither secret had
  ever been exported**.
- `app/services/ssh_pinning.py` - one implementation of SSH host-key pinning
  for all three channels that open SSH, replacing one weak copy and two
  channels that had no host-key store at all.

- **AI Advisor** — a read-only chat assistant (Settings \u2192 AI Advisor,
  `/advisor`) for WAF false-positive triage, Lua-script drafting, and
  searching the device configuration source of truth. Local Ollama by
  default (no data leaves the LAN); OpenAI-compatible and Anthropic
  providers are opt-in behind an explicit "allow external providers" flag,
  redact known internal identifiers before sending, and show the operator a
  pre-send preview of exactly what will leave the LAN. Untrusted device data
  (WAF logs, policy content) is delimited in the prompt against injection.
  The model **never writes anywhere**: a proposed WAF exception or Lua
  script is a schema-validated, pending `AdvisorProposal` that becomes a
  DRAFT row in the same tables (`WppException`, `LuaScript`) and behind the
  same permission (`config_write` / `studio.lua_studio`) the manual forms
  already require. Two new granular permissions, `advisor.use` and
  `advisor.configure`. See `docs/ai-advisor.md`.

### Fixed
- **Nine probes answered "I could not tell" with a value that means "fine".**
  Scoping resolved to the Global console and showed every product; a malformed
  access-control row read as *no restriction configured*; a repository git
  could not read reported itself clean and in sync; the HA interlock derived
  *standalone* and let the primary skip standby validation; the pre-reset guard
  reported *nothing to preserve* and proceeded to a hard reset; hypervisor TLS
  reported *verified* while never once consulting the operator CA; an
  unreadable host-key store read as first contact; an unparseable colour
  produced no contrast finding. None crashed, none logged, and each answered a
  safety question with the reassuring default - so the system reported health
  precisely when it had lost the ability to measure it. Each now distinguishes
  a third state, and the permissive default that was legitimate in each case is
  preserved rather than tightened.
- **`hypervisors/base._ssl_context` imported a function that has never
  existed** (`trust_store.verify_target`; the real entry point is
  `verify_param`). The `ImportError` was swallowed on every call, so a
  hypervisor with `verify_ssl=True` was always checked against public roots
  only and never against an imported CA. The feature had not worked once.
- **Two SSH channels had no host-key store at all** - the certificate autopull,
  which carries the node TLS private key, and the ESXi shell transport, which
  runs commands as root on a hypervisor. Both accepted any key, every time.
  Trust-on-first-use is preserved for a genuinely fresh host; what is refused
  is a store that exists and cannot be read in full.
- **Four unit templates were never refreshed by the update runner** because the
  list was hand-typed and had fallen behind `deploy/`; three installed units
  still declared a service account that no longer exists, and ran only because
  a drop-in overrode them. The list is now derived from the directory.
- **The out-of-tree helper scripts had no installer.** The replicator itself
  was three months behind its source, missing the fix that separates *"I could
  not evaluate the peer"* from *"there is no peer"* - so it could report
  success while replicating nothing.
- **A retired mechanism was still documented as live on four operator-facing
  surfaces**, including the install manual, which instructed the operator to
  arm it on a fresh node, and the High Availability page. The script it named
  had no source in the repository. The System Backup page also claimed a
  specific hypervisor topology that had since changed, and told the operator
  the surviving copy was the one that is in fact co-located with the others;
  it now states the invariant to check instead of asserting an estate fact the
  product cannot know.
- The `restore` runbook claimed total loss was recoverable from a bundle. It is
  not: the key that decrypts it is deliberately not in it.

- **The site-rules overlay was replicated by nothing.** It is untracked on
  purpose — it names the estate — but it also sat beside the application
  rather than inside `data/`, which is the only directory the HA datasync
  carries. git ignored it by design, the datasync never saw it, and the backup
  bundle did not package it: three mechanisms, and the file fell between all
  three. The standby ran for days on a copy whose device rule predated half
  the registered appliances. It now lives in `data/publication-rules.local.json`
  (still ignored, by `/data/`), so the datasync replicates it and the bundle
  carries it. The old path is still read so that updating to this commit does
  not brick a node that has not been migrated yet.
- **The overlay loader answered "absent", "malformed" and "one bad regex" with
  the same value** — an empty rule table, which every caller reads as *nothing
  to redact*. The comment above it promised the opposite ("a node that loses it
  fails loudly instead of quietly redacting less"); that promise was kept only
  by a test asserting the file exists at collection time. Malformed JSON and
  unusable entries now raise. A missing overlay raises **on a deployment** and
  still loads generic rules on a bare checkout — the published mirror has no
  overlay and must not have one, so absence alone could never be the signal;
  the presence of `.env` distinguishes the two.
- Backup bundles now carry node-local config, and a restore places it only
  where the node has none — the live copy is likelier to be current than one
  frozen into an old bundle.

## [1.6.0] - 2026-08-07

### Added

- Monitoring is provisioned from **one seam**. Saving an appliance now creates
  both its scrape targets and its threshold probes; until now `ensure_baseline`
  was reachable only from *Discover*, so a device added through the form had
  metrics and no thresholds and nothing said so.
- **FortiADC virtual servers** (`vservers` collector). FortiADC has no
  `monitor/` namespace — every guessed endpoint 404s — so the runtime surface
  was censused from the appliance's own GUI bundle and verified live on 8.0.3.
  `status_history/vs_status` carries the whole vdom in ONE call, so 500 virtual
  servers cost one round trip. Interfaces extended to FortiADC.
- **FortiAuthenticator identity inventory** (`identity` collector) — accounts,
  groups, tokens, certificates, RADIUS/TACACS+ clients. Counted via Tastypie
  `meta.total_count`, so a 50 000-user directory costs the same as an empty one.
- **FortiAnalyzer** (`faz` collector) — log volume, storage, alerts, incidents,
  registered devices and task queue. Counters only; no log body is ever
  fetched. FortiAnalyzer previously had **no collectors at all**.
- **Dashboard variables** with two drill-down boards. One board answers for
  every device in the fleet instead of one board per device, and the service
  picker is *chained* to the device picker so it offers only what exists on the
  selected appliance.

- **Search on the published manual.** The hub carries a client-side index of
  every published document and **every h2/h3 heading in it** — 573 headings
  across 27 documents — so a result deep-links to the subsection rather than
  dropping the reader at the top of a two-thousand-line page. The index is
  derived from the same render that produces the pages, not from a second
  parse, and is inlined rather than fetched: the site is published to a static
  host we do not configure, and the publication leak scan only sees what the
  build returns.
- **Search across every release.** The release notes index all 226 changelog
  entries, and each result is labelled with the version it shipped in and
  links into that release's own page. The version rail filters to the releases
  that actually contain a hit, so the left side answers "which versions is
  this in?" without reading the results.
- **Nine sections of the user guide that had no coverage at all** — Studio
  (custom views, plugins, Lua), High availability, AppIDs, a tab-by-tab
  Settings reference, log collection and offline backup import, system
  provisioning profiles and baselines, the template library and section
  catalog, the endpoint registry and API explorer, and release notes. The
  manual went from 23 sections to 32 and now says where to read what changed
  in a version — it had never mentioned the changelog.

### Changed

- **The release notes are a rail and a panel, not a wall of cards.** Versions
  on the left, that version's changes on the right, newest first, opening on
  the shipped version because "what is running on my node" is the question the
  page is opened with. Each version page carries the whole rail, so "when did
  this change?" stops being a scroll through the changelog.
- **The manual and the release notes read at 80% of the screen** above
  1400px. Only above: 80% of a 1280px screen is 1024px, which is *narrower*
  than the 1120px it replaces, so widening unconditionally would have made the
  manual harder to read on the machines most operators use. Marketing pages
  stay narrow deliberately.

### Removed

- **Lua Studio is no longer reachable from the FortiAuthenticator ADOM.** It
  was in the ADOM's blueprint set, but `LuaScript.TARGETS` is FortiWeb and
  FortiADC — the unit is an identity store with no scripting object anywhere in
  its API, so the page listed zero targets and zero devices. A page that can
  only fail is worse than one that is not offered.

### Fixed

- **The publication redaction rule was a roster, not a shape.** It enumerated
  the appliances that existed the day it was written, so every unit onboarded
  afterwards silently stopped being redacted — and the leak scanner, which
  carries its own copy of the same list, could not catch what the redactor had
  missed. Twelve appliance names were live on the public site. The rule now
  matches a product prefix followed by digits, so the next device is covered
  the day it is racked; bare ADOM keys (`fadc`, `faz`) and URL segments like
  `/fadc/api/` still pass through untouched, because the product has to remain
  nameable.
- **A reference-appliance roster was hardcoded in the field-catalog
  harvester.** `SOURCES` named two boxes of this estate, so a checkout carried
  someone else's device names and a run elsewhere would have harvested from
  hosts that do not exist. It reads `SATOM_FIELD_CATALOG_SOURCES` now, with no
  default and a refusal that names the variable — the same rule the Firecrawl
  endpoint in that file already followed.

- Dashboard variable values were escaped with `re.escape`, which escapes a
  hyphen as `\-`. RE2 — the engine VictoriaMetrics uses — rejects that as an
  invalid escape and answered **HTTP 422**. Every device and policy name in
  this fleet contains a hyphen, so the common case was broken and the rare one
  worked. Found end-to-end against the live store; a unit test on the escaper
  alone could not see it, because the output is only invalid to the engine.

- **Entering the FortiAuthenticator ADOM landed on the FortiWeb home.**
  `_home_for()` had branches for FortiADC and FortiAnalyzer and then a
  placeholder check; FortiAuthenticator stopped being a placeholder and fell
  through to `fortiweb_home`. Every route into the ADOM — the product picker,
  the sidebar, the device rail — silently opened the wrong product and then
  pinned the session to it. `/fac/` was reachable only by typing the URL.
- **The Global home page hardcoded two ADOMs.** It shipped a stat-card for
  FortiWeb and FortiADC and nothing else, and its fleet table could render only
  those two kinds — so FortiAuthenticator and FortiAnalyzer units were
  invisible on the one console meant to see everything. Cards and table now
  come from the ADOM registry, so the next product appears without touching
  this page; devices whose kind matches no active ADOM are listed too, because
  Global is the only console that can see them.
- **An ADOM with registered appliances could be deleted.** The guard was a
  hardcoded set of three keys. An appliance's `kind` IS an ADOM key, so
  deleting the row silently un-managed every device stamped with it: the boxes
  stay in the table, no console can reach them, and nothing raises. The guard is
  derived now — the three core keys plus any ADOM owning at least one
  appliance, recomputed per check, so onboarding the first unit of a product
  protects it immediately. The refusal also says which of the two reasons it
  is, and how many appliances are in the way.
- The FortiAuthenticator ADOM had no top-bar search icon and no device-rail
  link, though `search` was already in its blueprint set.
- **Table-of-contents entries were escaped twice** — the sidebar of every
  manual page rendered `Backups &amp;amp; restore`, which a reader sees as a
  literal entity. markdown's toc tokens arrive already HTML-escaped and were
  escaped again on the way out. It only shows on a heading containing
  `& < > "`, which is why it survived until a search index inherited it.
- **A guard that counts workspaces was tied to the sentence, not the number.**
  It matched the exact string `The app hosts N workspaces`, so inserting one
  adverb while rewriting the ADOM section made it stop guarding rather than
  fail. It is anchored on the claim now (`<number-word> workspaces`) and checks
  **every** occurrence — the count is stated twice, and only one of the two was
  ever covered.

### Notes

- **Service Monitor was NOT retired**, though its four kinds are each covered
  1:1 by a collector that does the same work in one call instead of N. The
  alert engine has no reference to the metrics store and Collection has no
  grading layer, so retiring it today would delete the "every backend behind
  this policy is down" signal with nothing to replace it. Prerequisite: alert
  rules evaluated over the store. See `docs/safeguards.md` §25c.
- The FortiAnalyzer collector is **unverified against live hardware** (none
  reachable since July 2026). Payload shapes are read defensively and an
  unrecognised shape yields nothing rather than a plausible wrong number.

- **The `adoms` table beats `branding.py`, and one ADOM proves it.** The
  FortiAuthenticator entry seeds `cap_firmware`/`cap_naming`/`cap_regex` False
  and carried a comment asserting they *stay* False; the live row has all three
  on, set by an admin through Settings → ADOMs on 2026-08-05. The seed is
  insert-only by design, so operator edits win — the comment was describing an
  intent the registry had already overridden. The comment now says these are
  seed defaults and points at the table. **The row was left alone:** overriding
  an operator's own edit through the mechanism that promises to respect it
  would be the actual bug. Live effect is narrow — `/naming/` and `/regex-lab/`
  still redirect out of the FAC workspace (the blueprint gate, not the
  capability, controls reachability); only the firmware library opens, and §17.2
  now says so.
## [1.5.0] - 2026-08-06

### Added
- **Settings > Thresholds** — a 22nd tab, and the first place in this product
  where a limit can be stated once instead of once per probe. Six scopes: the
  four product ADOMs, SATOM itself and the SATOM host. A probe column left empty
  **inherits** its product's value at grading time; `0` still means "switch this
  level off", and the two never collapse into each other. Both probe pages print
  the resolved number **and where it came from** (`set on this probe` /
  `inherited from <product>` / `factory default`), because a grade produced by a
  number nobody typed has to be locatable.
- **Binary-fact severity.** Conditions with no number to compare against — every
  backend of a policy down, a policy administratively disabled, `proxyd` gone, a
  monitored interface moving — can now be raised, lowered or silenced per
  product. **A silenced fact is still printed on the probe**: silencing changes
  the grade, never the visibility.
- **Targeted, expiring probe mute.** Suppress one probe for up to 720 hours with
  a recorded reason. It keeps running and keeps showing its own status; it stops
  raising the device badge and the alert mail, and is reported as lost coverage
  in both. There is no permanent mute.
- **Host health (`app/services/host_health.py`)** — disk, memory and load of the
  machine, graded on **both HA nodes** and wired into a new `alerts.check.host`.
  Nothing in the product measured its own box before: on 2026-07-28 the primary
  reached 95 % disk in six minutes with every unit active, `/healthz` at 200, the
  badge green and no mail sent. Disk criticality is 92 %, deliberately below 95:
  a full filesystem stops Postgres writing WAL.


- **Settings > Hypervisors** — register the Proxmox and/or ESXi endpoints SATOM
  may build machines on, more than one of each. Credentials are Fernet-encrypted
  and never returned to the browser; a blank secret on edit keeps the stored
  one. The **Test** button reports what the host will actually permit, including
  the read-only-API case, so the limit is learned there rather than three steps
  into a run that already reserved an address. The tab also carries a
  capability comparison of the two backends and the reasons behind it.
- **Device Provisioning** (`/device-provisioning`) in every ADOM — build an
  appliance machine from nothing, then hand it to System Provisioning for its
  configuration. Five modes (`full`, `semi`, `dhcp`, `vm_only`, `config_only`),
  each with its advantages and disadvantages spelled out on the page, and each
  preflighted against the live hypervisor before anything changes. Runs are
  stamped with their ADOM and filtered on the query; a run from another ADOM
  answers 404.
- **Provisioning orchestrator** (`app/services/provision_runner.py`) — the
  `ProvisionRun` state machine with per-step logging and a rollback that undoes
  only what the run recorded creating.
- **ESXi host-shell transport** (`app/services/hypervisors/esxi_shell.py`) — the
  free vSphere Hypervisor licence makes the remote API read-only, while the
  host's own shell is a different code path inside ESXi. Given SSH credentials
  SATOM creates, powers and deletes machines with `vim-cmd` instead. SATOM
  detects that `TSM-SSH` is off and prints the line to enable it; it never
  enables it. The shell is claimed only after a command has run on it.

- **Analysis page for the FortiAuthenticator ADOM.** An identity appliance has
  no throughput to plot and no policy fan-out to map, so the new page answers
  the questions it actually has: entitlement headroom (an unlicensed unit
  refuses the sixth user outright — a cliff no CPU chart shows), what identity
  objects exist, and the authentication settings whose *absence* is the finding.
  Inventory rows are derived from the endpoint registry rather than a list in
  the page, so an endpoint added later appears without a second edit, and
  "not harvested" is rendered distinctly from `0` because the two demand
  opposite actions. Entitlement is reported, never re-graded: the licence and
  token probes own the thresholds, and a capacity row with no probe reads
  `unmonitored`, not `ok`.
- **Analytics boards for FortiAuthenticator** — `fac-entitlement` (licence and
  token series from the metrics store) and `fac-identity` (the same signals
  through their probes, carrying the operator's thresholds).

- **Hypervisor provisioning — build an appliance from nothing.** New
  `app/services/hypervisors/` layer with two backends, both plain HTTPS and
  neither adding a Python dependency (this product ships offline bundles;
  `proxmoxer`/`pyVmomi` would each force a rebuild of three bundles).
  - **Proxmox VE** over `/api2/json`, API-token or ticket auth. Verified end
    to end against a live host: create, power on, power off, delete, and
    delete again.
  - **VMware ESXi** over vSphere SOAP `/sdk`, parsed with the standard
    library. A standalone host serves no vSphere REST API (`/api` and `/rest`
    answer HTTP 400), so REST-based code would look correct and fail on every
    standalone host in the field. Read operations verified live against ESXi
    8.0.3.
  - `Capabilities` is resolved against the **live endpoint** and reports what
    a backend cannot do rather than assuming it can, including the reason.
    Unknown state is never treated as permission.
  - `HypervisorTarget` (multi-target: a site may run several of each) with
    Fernet-encrypted passwords and API-token secrets, same pattern as
    `Appliance`; `public()` is the only shape the browser sees.
  - `ProvisionRun` records the pipeline as an explicit state machine so a run
    that dies mid-way can be undone. `ip_from_ipam` exists because a
    user-typed address is not ours to release. Five modes (`full`, `semi`,
    `dhcp`, `vm_only`, `config_only`) because the product cannot promise
    unattended first boot on a hypervisor with no API serial console.
- **Firmware repository distinguishes install images from upgrade images.**
  Fortinet publishes two artefacts per release and they are not
  interchangeable. `FirmwareImage.image_kind` (`upgrade` | `install`,
  defaulting to `upgrade` because every pre-existing row is one) and
  `hypervisor` (`kvm` | `vmware`). Accepted extensions follow the kind in
  **both** upload paths — the page previously had a single `.out` allow-list
  and was structurally unable to hold install media at all.
- `docs/provisioning-hypervisors.md`, published to the manual.

- **TLS trust store — import your own Root and Intermediate CA.** Until now
  `Appliance.verify_ssl` meant either "validate against the PUBLIC root store",
  which no privately-signed appliance can satisfy, or "validate nothing" — so
  every device in a private fleet ended up with certificate checking disabled.
  Settings → **Trust store** has a labelled slot for the **root** and one for
  the **intermediate**, each taking pasted PEM or an uploaded file, imported
  together in a single transaction so a chain cannot land half-applied (a whole
  chain in one blob is still fine; each certificate is stored separately). The
  labels are a hint only — the role is read from the certificate, so a root
  pasted in the intermediate box is still recorded as a root. The client
  layer now verifies against the public roots **plus** those CAs. Non-CA
  certificates are rejected at import with the reason, because OpenSSL cannot
  anchor a chain on a self-signed leaf and accepting one would fail every
  handshake instead of failing the import. An incomplete chain is surfaced on
  the page rather than discovered at handshake time, and a per-device probe
  separates the three causes of a failure — untrusted issuer, hostname
  mismatch, expired leaf — because they need three different fixes. The CAs
  live in Postgres, so they reach the standby and the backup bundles; the
  on-disk bundle each node feeds to OpenSSL is a derived cache.
  See `docs/safeguards.md` section 20.

- **FortiAuthenticator is now a managed product**, not a placeholder ADOM.
  Verified against `FACVMKVM v8.0.3 build0099`: a REST client for its
  Django/Tastypie API, a registry of **40 endpoints seeded from a live census
  of all 58 the unit advertises**, 28 section pages mirroring the unit's own
  `nav_menu_definition`, an API console (dry-run by default, audited,
  permission-gated) and a configuration harvest wired into the existing
  source-of-truth store and the fleet-wide scheduled sweeps.
  See `docs/fortiauthenticator.md`.

- **The user guide now describes five ADOMs, not three.** `docs/user-guide.md`
  still opened with "the app hosts three workspaces" and a table listing only
  Global, FortiWeb and FortiADC — FortiAnalyzer had been shipping since July
  and FortiAuthenticator since August with no entry at all, and that manual is
  published publicly. Nothing fails when a manual goes stale; the claim simply
  stops being true, which is exactly how it drifted a month. Added: the
  five-ADOM table, the two missing device kinds plus the TLS-verification and
  API-key notes that go with registering one, a product-by-product Analysis
  table (the page is deliberately per-product and has no shared fallback), the
  FortiAuthenticator entitlement probe kinds and the per-product restrictions
  on deep monitors, and section 17 recast as *Product workspaces* with
  FortiADC, FortiAuthenticator and FortiAnalyzer subsections.
- **The user guide now covers provisioning, updates, the metrics store and
  the trust store.** Five areas shipped without a line in the manual that is
  published publicly: hypervisor provisioning, offline signed update packages,
  Monitoring → Collection, Analytics boards, period reports, and the TLS trust
  store. New sections 21 (*Provisioning new appliances*) and 22 (*Updating
  SATOM itself*), plus 10.1, 14.7, 14.8 and 14.9. Nothing fails when a manual
  goes stale, so the structure is now guarded mechanically: contents entries
  must resolve to real sections, section numbers must be a gapless sequence,
  every linked manual must exist, and every collector and provisioning mode in
  the code must be named in the section that explains it.
- **The provisioning section now carries the trade-offs, not just the steps.**
  Section 21 gained a backend comparison (Proxmox against ESXi, with the reason
  *Full* is reachable on one and not the other at any licence tier), the ESXi
  host-shell transport and what accepting it costs, the two Proxmox storage
  roles that are routinely on different storages, an advantages/disadvantages
  column for every mode, and where the management address comes from. Seven
  provisioning entries were added to Troubleshooting. An operator choosing a
  mode was previously told where each one stops but not what it costs, which
  is the half of the decision that matters.

### Changed
- **Analysis moved into the Monitoring submenu.** It was a bare Fleet item
  written out five times in `base.html`, once per ADOM block — the exact drift
  `partials/nav_monitoring.html` exists to prevent, and which had already
  happened to Metrics once. Five copies means an edit lands in one ADOM and is
  silently missing from the other four, and nothing fails when it does. One
  definition, five call sites; the submenu now re-opens on the Analysis page
  like every other entry in it.
- The device roll-up (`stale_hours`, the critical multiplier, the harvest-failure
  streak and the capacity levels) is resolved **per product** instead of from one
  fleet-wide constant. A FortiAnalyzer legitimately lives at a different cache
  cadence than a FortiWeb, and one number for both is how a correct product ends
  up permanently amber.
- Discovery no longer stamps `80 / 95` (or `0 / 0`) onto a new probe; it leaves
  the columns NULL so the probe inherits. Existing rows still holding exactly the
  historical creation literal were handed back to inheritance on first boot,
  which changes no behaviour on the day and makes it tunable from then on. A
  column holding anything else was left alone.
- Alert bodies now name the Thresholds scope that governs the finding.

### Fixed
- **`satom diagnose code` now sees the artifact gunicorn actually caches.** It
  compared the newest `.py` against each process start time, so a change that
  touched only templates was invisible — and Jinja caches a compiled template
  for the life of the worker, per worker and lazily, so an edit without a
  restart leaves some workers serving the old markup and some the new. The
  symptom is a page element that appears and vanishes with no pattern. Template
  mtime is charged to the **web** process only (nothing else renders Jinja), the
  read-out names which artifact moved, and the note names both the per-worker
  cache and the fact that a `test_client` render — a fresh process reading from
  disk — reports the change present while the running service serves it to
  nobody.
- **Neither freshness scan counts an artifact no loader reads.** The template
  tree carries editor backups and the repo root collects hidden scratch scripts;
  a module name cannot begin with a dot, so a hidden `.py` can never be
  imported. Both were being reported as the newest artifact, sending the
  operator to restart a service because of a throwaway file.
- `alerts._check_devices` resolved capacity thresholds **once for the whole
  fleet** and passed the same pair to every appliance, which silently defeated
  per-product capacity limits for the one caller that actually sends the mail.
- The `transactions` probe reads its lookback window from `stale_after_h`, which
  is now nullable; the old `or 1` fallback would have narrowed a six-hour window
  to one hour on every migrated probe — fewer transactions counted, read as a
  quiet service.
- The chart threshold lines were drawn from the raw probe column, so a probe that
  inherits its levels would have shown no threshold line at all while still being
  graded against one.


- **"New appliance" could not add a FortiAuthenticator.** The platform roster
  was a hardcoded three-item list repeated in four templates and never updated
  when the product shipped, so its own ADOM had no way to onboard its own
  devices. The roster is now derived from the ADOM registry, so a new product is
  offerable the day it is declared.
- **Every ADOM offered every platform, and the server accepted it.** Adding a
  device from one ADOM while picking another product's platform saved a row the
  creating session could not see -- indistinguishable from a save that failed. A
  product ADOM now offers exactly its own platform, Global offers all of them,
  and the posted value is re-checked server-side on create and on edit.
- **Appliance detail, edit and delete were reachable across ADOMs by id.** The
  appliance LIST was product-scoped but the by-id loader was not, so every
  per-appliance route answered 200 for another product's device to anyone who
  knew the id. `visible_appliance_or_404()` now applies the same product filter
  the list does; Global still reaches everything.

- **`list_datastores()` reported a false capability.** Proxmox splits `images`
  (can hold a disk) from `import` (can receive an upload) across different
  storages. The listing filtered on `images` first and only then read `import`,
  so the stock `local` storage — which has `import` and not `images` — was
  dropped before its flag was evaluated, and the probe told the operator to add
  a content type the host already had. `disk_datastores()` and
  `import_datastores()` now name the two questions separately.
- **`list_vms()` answered "does this exist" from a cache.**
  `/cluster/resources` is refreshed on `pvestatd`'s cycle: a machine SATOM had
  just created and powered on was absent from it, while the rollback that
  followed deleted the same machine without trouble. With a node in hand the
  live `/nodes/<node>/qemu` endpoint is used instead.
- **Saving a hypervisor target failed the first time, every time.** The
  uniqueness check ran after `db.session.add()`, so autoflush pushed the pending
  INSERT to satisfy the very query looking for a duplicate — the row collided
  with itself. It also left a credential-less row behind, which then failed its
  connection test with an authentication error pointing at the wrong cause.
- **`models_provision` was never imported**, so `db.create_all()` never created
  `hypervisor_targets` or `provision_runs`. The models were dead code that
  looked alive.
- **Device provisioning was registered as a FortiWeb area.** Membership of
  `fortiweb_scoped` means "opening this from Global is an ADOM jump into
  FortiWeb", which made the Global ADOM silently become FortiWeb: a Global
  operator saw only FortiWeb runs and never got the product picker Global
  needs.

- **The FortiADC ADOM showed the FortiWeb WAF dashboard.** `/analysis/` mapped
  `fortiadc` to the FortiWeb page as acknowledged debt, so the ADOM rendered
  server policies, web-protection profiles, App IDs and signature exceptions —
  every panel at zero, because a FortiADC harvest contains none of those
  objects. Nothing failed; the page simply answered another product's
  questions, and an empty panel reads as "quiet" rather than "not applicable".
  FortiADC now has `analysis_adc` and `analysis/adc.html`, written against the
  objects an ADC actually has: virtual servers, pools and their members, real
  servers, health checks, the security profiles a virtual server references,
  client-SSL profiles and local certificates. Against the live cache it reports
  five real findings where the old page reported nothing — including a
  certificate 26 days from expiry and a pool forwarding to its member with no
  health check configured.

- **Three analytical surfaces were showing every ADOM another product's
  questions.** Analysis dispatched through an `else`, so FortiADC and then
  FortiAuthenticator inherited the FortiWeb WAF dashboard and rendered every
  panel empty. Reports stored a product on the row and then computed the fleet
  section over the *whole* metrics store, so a FortiAuthenticator report
  carried FortiWeb's throughput under a heading naming the identity ADOM.
  Analytics seeded its built-in boards Global, so the FortiWeb-only `traffic`
  and `service-health` boards appeared in every ADOM. Nothing failed in any of
  the three — an empty panel reads as "quiet", not as "not applicable".
  Analysis now dispatches from an explicit map with no fallthrough; the report
  fleet section scopes both its metric set and every query by `kind`, and omits
  the policy roll-up where it cannot apply rather than reporting zero; the
  FortiWeb-only boards are product-scoped. Documented as safeguards §21.

- **The firmware page leaked images across ADOMs.** `index()` listed every
  row regardless of the active product, and `upload()` validated the product
  against every firmware-capable product rather than against the ADOM. The
  list is now filtered in the **query** (a row hidden by a template is still
  a row the page fetched, and the JSON callers kept leaking it) and both
  upload endpoints re-derive the product from the request scope — a
  hand-crafted POST could otherwise file a FortiWeb image under FortiADC.
- **The firmware page was unreachable from two ADOMs.** It sat in the
  FortiAnalyzer blueprint set only, so FortiADC and FortiAuthenticator
  sessions bounced off it while a FortiAnalyzer session could see FortiWeb
  images. It is now in every product ADOM, scoped by row.

- **An ADOM showed other products' data, and the new product showed up in
  everyone else's.** Two defects with one cause, both fired by adding a fourth
  product. `product_scope` recognised ADOM keys from a hardcoded tuple that did
  not contain `fortiauthenticator`, so inside that ADOM the effective product
  resolved to the empty string — the value that also means "a background
  worker, show it everything" — and every scoping filter became a no-op: the
  FortiAuthenticator ADOM listed all six appliances and all 322 notifications.
  Separately, the FortiWeb branch was written as an *exclusion* ("not a
  FortiADC and not a FortiAnalyzer"), a shape that cannot know about a product
  added later, so the new appliance appeared under FortiWeb. The same exclusion
  had been copied into the alert engine, the Certificate Manager, the plugin
  sandbox's device selector and the Metrics change-history filter, and Metrics
  additionally served the FortiWeb inventory totals under any unrecognised
  ADOM's own labels. The key set is now derived from the ADOM registry
  (inactive rows included, so deactivating an ADOM cannot silently disable its
  filters) and every filter names what it keeps. A product declared in the
  registry is scoped the day it is declared.
  See `docs/safeguards.md` section 19.

- **Two alert engines read the wrong source and complained permanently.**
  Device freshness graded the `deep` cache layer -- refreshed once a night by
  the FortiWeb-only `deep_capture` -- against the six-hour budget of the
  *hourly* sync, so a healthy appliance reported a stale cache eighteen hours
  out of twenty-four, and every non-FortiWeb product reported "no cached
  configuration" while holding a snapshot minutes old. `cache_meta` now reports
  the age of the newest layer that actually has a snapshot. Config drift diffed
  git history for `reports/<slug>/_config.json`; the source of truth left git
  in the same release, so the migration commit read as fifteen device-side
  edits. Drift now reads the content-addressed `sot_version` store, where an
  unchanged device mints no row, and it honours `maintenance` -- retired
  appliances no longer alert. See `docs/safeguards.md` section 18.

- **The product-scoping columns could not hold an 18-character ADOM key.**
  Every product key the app had ever written was at most 13 characters
  (`fortianalyzer`), so `appliances.kind` and the `product` column on twelve
  other tables were declared `varchar(16)`. `fortiauthenticator` is 18 — which
  is why that ADOM could exist as a placeholder for months without anyone
  noticing: a placeholder never writes a row. The first real insert failed, and
  the columns that would have failed *later* are the ones that hurt (an audit
  entry, a device alert, an API token — writes that happen long after the
  operator believes the device is integrated). All thirteen were widened to
  `varchar(32)`, chosen by inspecting their stored values rather than matching
  their names: `monitor_probe.kind`, `notifications.kind` and `plugins.kind`
  share a column name but a different domain and were left alone. A guard now
  compares against the longest key declared in `branding._FALLBACK`, so a
  longer fifth product is caught the day it is declared.
- **An existing installation never received that widening.** The models were
  widened to 32, but `db.create_all()` never ALTERs and `_ensure_columns()` only
  ADDs — so an installation that predates the change kept `varchar(16)` forever
  and would fail on the first row written for the fourth ADOM, in an audit row
  or an alert, long after the operator had registered the appliance and
  concluded it worked. `_ensure_widths()` now widens any VARCHAR column the
  models outgrew, derived from the model metadata rather than a hand-written
  list. It only ever widens: narrowing can truncate committed rows. Widening a
  `varchar` in PostgreSQL is a catalog-only change and replicates through WAL;
  SQLite does not enforce the length and is skipped. `_ensure_columns()` was
  also still emitting `VARCHAR(16)` for five `product` columns of its own, so
  the ceiling could return even after a manual widening.
- **Maintenance now silences the probe sweep, not just alerts.** A parked
  appliance was still probed over SSH and REST every few minutes:
  `deep_monitor.due_probes` filtered on `enabled` alone. Scheduled runs now
  skip parked appliances; *Probe now* still reaches them, and a probe with no
  appliance row (a bare URL check) is never treated as parked.
- **`get monitor status` no longer calls a parked box's disabled probes lost
  coverage.** Disabling them is the correct response to parking the device, and
  counting it as loss held the check at a permanent `FAIL`. A live probe in
  `crit` still fails it.
- Root-level hidden scratch (`.patch_a.py`, `.runsuite.sh`) is git-ignored, so
  an unrelated `git add -A` can no longer sweep another session's throwaway
  into a commit. Anchoring this exposed a real one: unanchored `backups/` was
  shadowing the tracked templates under `app/templates/backups/`.


## [1.4.1] - 2026-08-05

### Fixed

- **The installation page was answering a question about the appliances.**
  1.4.0 split Fleet health into SATOM health and Device health but left the
  *device* HA counter on SATOM health. Nothing about the number was wrong — one
  appliance, standalone, confirmed against the box itself — and it was still a
  false statement, because a page headed *"this installation"* reading
  `0 clustered · 1 standalone` says the installation is a single node. It was a
  two-node pair with live streaming replication, and the manager's own posture
  was a grey one-line note underneath. The rows moved to Device health, where
  they are built from `visible_appliances()` rather than the unscoped
  `Appliance.query` they used before — on a page every ADOM can reach, the old
  query would have listed the FortiADCs to the FortiWeb ADOM. The manager feed
  now carries no device key at all.

- **SATOM health states its own HA posture.** The installation is reported as
  `clustered` / `standalone` / `unknown` with the same badge and the same
  evidence rule the appliances get. The verdict comes from peer facts (nodes
  registered, hot standby present, streaming replication live), not from the
  `mode` switch: a node left on `standalone` while a replica streams is still a
  pair, and reading the switch would report it as single. A probe that could not
  count nodes is `unknown`, never `standalone`. Split-brain is its own badge.

### Changed

- The HA pill on both pages uses the product's own `fw-badge` set instead of a
  local palette, so cluster state reads like every other status in the console.
- Device cards show a derived HA chip when the harvest says the box is
  clustered. The chip previously came from the appliance form's `ha_mode`
  column, which nothing else writes and which was empty on the whole fleet.

## [1.4.0] - 2026-08-05

### Added

- **SATOM health and Device health are two pages.** Fleet health carried the
  appliances and the manager's own installation, and only the second is
  Global-only, so the page had to hide half of itself in every product ADOM.
  **SATOM health** now answers *is this installation healthy* (HA nodes,
  database, systemd units, redundancy, encryption in transit) and **Device
  health** answers *are the appliances healthy* (cards, capacity guardrails,
  health alerts). The nav carries them as a nested submenu under Fleet health.
  The split is enforced on the routes and not by hiding sections:
  `/monitoring/satom` redirects out of a product ADOM and
  `/monitoring/satom-data` answers 403, because every card on that page names
  node hostnames and infrastructure addresses. The manager feed also stopped
  computing the per-device capacity roll-up it never rendered.

- **`satom-metrics` is a monitored unit.** The store is where Analytics boards
  and the Collection page read every number they draw, and it was absent from
  the Services & redundancy list — it could be dead while every light on the
  panel stayed green. Four more units that are unconditionally expected to run
  joined it (`nginx`, `satom-reconciler`, `satom-updater.path`). Units that are
  inactive *by design* were deliberately left off: `satom-ha-datasync` is
  role-guarded and inert on the primary, `satom-git-publish` was retired with
  the git SoT, and a check that always complains is a check the operator learns
  to skip.

- **Device HA posture, derived from the harvest.** *Device HA clusters* printed
  *"No HA clusters registered"* on a fleet whose hourly sweep had `system_ha`
  cached for every appliance: the panel read `Appliance.members`, a table
  written only by the appliance form, and threw away the standalone count it
  had just computed. The new `ha_inventory` service reads the cache and reports
  one row per appliance — mode, group, VIP, and the evidence behind the
  verdict. *Clustered* requires peer evidence (a heartbeat device, a group
  name, a peer address, a node list longer than one), never the `mode` field
  alone: FortiWeb and FortiADC report it as an unambiguous string, but
  FortiAnalyzer reports an **int** whose enum could not be verified against a
  live device, and guessing it would label a standalone box "primary". A device
  with no cached HA is `unknown`, never `standalone`. Rows parked on the
  reserved `.invalid` TLD are excluded outright — they name no real box.

- **A node reports the state that exists only here.** `satom diagnose git`
  gains a *state that exists only here* section: modified tracked files (named,
  not just counted), commits absent from the upstream branch, parked
  `refs/backup/*` refs, and untracked files. It exists because the operation
  that destroys unique work looks routine — an applied update package once
  reverted another session's uncommitted changes, and the copy that survived
  was on the standby, purely because nobody had reconciled it yet. Only dirty
  tracked files and unpushed commits raise the grade; untracked files are
  listed but never graded, because `reset --hard` does not delete them and the
  primary legitimately carries an untracked `reports` symlink — a permanent
  warn is indistinguishable from no check at all. With no upstream branch the
  unpushed count reports *cannot tell* rather than zero. The accompanying rule
  is written down in `docs/safeguards.md` 4b: converging the standby is
  `satom-reconciler`'s job, not an operator's, and never a side effect of
  unrelated work. Stated as a limit, this is a read-out and not an interlock —
  nothing refuses a `git reset --hard` typed by root, and nothing should.

- **Release notes, one page per version, on the public site.** The changelog
  was published whole — a thousand lines, so "what shipped in 1.3.3 and do I
  need it?" could only be answered by scrolling. The site gains a **Releases**
  section in the top navigation: a hub listing every version newest-first with
  its date and the headlines of its own entries, and one page per version.
  Every fact on those pages is derived from `CHANGELOG.md` (the version list is
  its headings, the dates are its dates, the teasers are its bold lead-ins) and
  the *current release* badge is read from the `VERSION` file, so no number on
  the site can drift from the repository. A version added without regenerating,
  a page left behind by a rename, or a page missing from the hub each fail the
  suite. `docs/release_notes.md` — the *vendor's* known-issue corpus behind the
  upgrade advisor — was also renamed on the site, because two documents called
  "Release notes" is how an upgrade gets planned from the wrong one.

- **Scrape targets are provisioned when a device is saved.** Adding an
  appliance now creates its metrics collectors immediately, from every creation
  path (create, edit, cluster-member add), instead of only on the next
  `metrics_scrape` sweep — which on an installation with no seeded scheduled
  action meant never. The eligibility rule (skip parked and retired devices)
  moved into `metrics_collect.provisionable()` so the four call sites cannot
  drift apart, and a provisioning failure can no longer abort the device save.
  **Monitoring → Collection** now also names every device that produces no
  targets, with the reason — a FortiAnalyzer has no collectors yet, and a silent
  no-op is indistinguishable from coverage.

- **Fleet metrics collection and a local time-series store.** Measured against
  the live system on 2026-08-05: at the target fleet (60 FortiWeb + 30 FortiADC
  + 10 FortiAnalyzer, ~750 policies each) the per-probe design needed ~180,000
  configuration rows, ~56 minutes of device I/O per 3-minute window and ~450 GB
  in PostgreSQL. Collection is now one scrape per (device, collector) — a single
  `policy_status` call returns every policy's counters in 14 ms — and samples go
  to a loopback-only VictoriaMetrics store (`satom-metrics.service`, Apache-2.0,
  one static binary) that holds the same three months at full resolution in
  ~8 GB instead of hourly averages in ~450 GB. New page **Monitoring →
  Collection** shows every target with its own editable interval and last
  outcome; expensive per-policy collectors run less often and against the top-N
  policies by live connection rate. New scheduled action `metrics_scrape`.
  Rationale and the full measurement: `docs/metrics-architecture.md`.

- **Selector-driven dashboards (MetricsQL).** Analytics panels gain a third
  selection mode that resolves against the store instead of enumerating probe
  rows — the only mode that works when the series are counted in tens of
  thousands. Expressions are validated by executing them against the store
  before they are saved, a failed query renders as an error rather than an empty
  chart, and gaps stay gaps. New built-in board **Fleet metrics (store)**.

- **Reports read the fleet, and can leave the node.** Period summaries now carry
  a section computed from the metrics store (min/avg/max per device per metric,
  policies that were down, collectors that failed) instead of describing only
  what someone wrote a probe for. `params.push_server=1` uploads the summary to
  the external backup server as both JSON and text.

- **`NOTICE` attributes what SATOM redistributes.** The offline bundles ship
  two third-party binaries (VictoriaMetrics, Apache-2.0; lego, MIT) and the
  application serves vendored browser assets (Chart.js, Bootstrap -- both MIT,
  vendored so an isolated management network renders correctly). None were
  named. SATOM is ELv2 and those components are not; `NOTICE` now says so and
  states that their terms are not superseded.

### Changed

- **Collection moved from Monitoring to Administrator.** The other six
  Monitoring entries display a measurement; this one configures how measurement
  happens — which (device, collector) pairs run, how often, how many policies
  deep — and needs `CONFIG_WRITE` to change anything. It sits next to Capacity
  Limits, which is the same kind of knob. It ships as a shared partial included
  by all four Administrator groups: those groups have drifted before (one of
  them is still titled "Administration"), and a single definition is the only
  thing that stops an entry being added to Global and forgotten in the other
  three. The enable/disable toggle on that page became a real button — it POSTs
  and changes state, and a bare link reads as navigation.

- **The device source of truth left git.** `reports/<device>/_config.json` was
  committed hourly; one FortiAnalyzer snapshot is ~8.4 MB and git keeps every
  byte of every revision, so at fleet scale the repository outgrows the node in
  weeks. Versioning moved to a content-addressed local store
  (`data/sot/`, index in PostgreSQL): the hash is the identity, so an unchanged
  config costs zero bytes, and retention is a policy instead of "forever".
  History, structural diff and restore stay in System Backup & Restore; blobs
  ride the existing standby rsync and the backup bundles, and are pushed to the
  external backup server. `satom-git-publish.timer` is retired and no longer
  installed; the scheduled `git_bundle` action is retired (the handler remains
  for manual code-repository bundles). **Git still carries application code**
  and the update path is unchanged. The live JSON tree moved to `data/reports/`
  with a compatibility symlink.


- **Analytics boards — many series on one chart, over windows up to 90 days.**
  New page under Monitoring → Analytics. Every existing chart in the product is
  bound to a single probe, which cannot answer the comparative question ("how do
  the FortiWebs differ", "did throughput move this month"). Boards compose
  panels across devices and metrics: line, area, bar, stat, gauge, heatmap,
  table and availability strip, with a min/max band, threshold lines, a
  secondary metric, compare-with-previous-period, drag to reorder, per-panel
  range override and optional auto-refresh. Three boards — Fleet overview,
  Traffic & sessions, Service health — ship built in and are reconciled from
  code on every boot; duplicate one to get an editable copy.

  Panels select probes by **rule** (metric + devices + name match) rather than a
  frozen id list, so a probe recreated by Discover, or a newly registered
  appliance, joins the panel with no edit.

  Nothing new is collected and no new scheduler is introduced: this reads the
  hourly and daily rollups the monitor sweep already stores, so a board opens
  instantly and keeps opening with every appliance powered off.

- **Monitoring reports — persisted daily / weekly / monthly summaries.** New
  page under Monitoring → Reports. Each report records availability,
  min / avg / p95 / peak per metric, threshold breaches, drift events (daemon
  restarts, interface changes), an incident timeline and the change against the
  preceding period. Reports are stored rather than recomputed on view: raw
  samples age out at each probe's retention, so a summary rebuilt six months
  later would answer from coarser data than the one read at the time while
  looking identical to it. Viewable in the console, exportable as JSON / CSV /
  text, and mailable through the existing SMTP configuration.

  Recurring runs use a new `monitor_report` scheduled action (`params.period` =
  daily / weekly / monthly, `params.email=1` to send, `params.keep=N` to prune)
  rather than a second scheduler. As with every other automation in this
  product, **no schedule is seeded** — the Reports page states which periods are
  armed and which are not, so an empty list cannot be misread as "nothing
  happened" when it means "nothing is scheduled".

- **Collection cadence is now visible, and honest.** A probe fires only once its
  own interval has elapsed *and* the sweep ticks, so its real cadence is
  `tick × ceil(interval ÷ tick)`: a 5-minute probe under a 3-minute sweep is a
  6-minute probe, and its row still says 5. That silent rounding is what
  degraded `proxyd` — the check that exists to catch a mute daemon restart — when
  the sweep moved to 3 minutes. Analytics → Collection cadence lists every
  probe's declared and effective interval and flags each mismatch. With no sweep
  scheduled it reports no cadence at all rather than a plausible default.

- `deep_monitor.series()` accepts an optional `force_source`, and the resolution
  choice is split out as `source_for()`. This lets a multi-series panel ask each
  probe which table it needs and then pin the coarsest answer for all of them —
  two series drawn from two tables on one axis is a lie no legend repairs. The
  single-probe drill-down is unchanged and still chooses per probe.

- **Offline update packages — update a node with no route to the git remote.**
  Download a signed package, upload it from Settings → Software Update, apply
  it with no internet, no repository and no package mirror. The package carries
  the application code and every pinned Python wheel, so it is about a quarter
  the size of the offline *install* bundle. Preflight verifies the signature and
  reports what applying it would do — version change, dependency changes,
  interpreter match, disk, upgrade path — before anything is applied. The
  privileged runner then re-verifies everything as root, takes a database
  backup, installs the tree, installs the wheels with `--no-index`, restarts,
  and **rolls back automatically** if the health check fails. Also available
  from the console for a node with no browser: `satom execute update package`.
  New: `installers/build-update-package.sh`, `deploy/sign_update_package.py`,
  `deploy/update_package.py`, `app/services/update_package_service.py`,
  `docs/offline-update-packages.md`. [SATOM-UPDATE-PACKAGE]

- **A trust store, so the product contains no secret.** A node accepts a package
  only if it is signed by a key `root` placed in `/etc/satom/update-keys`. The
  Vision EBC release public key ships in the repository — a public key can only
  *verify*, so publishing it is safe, exactly like an SSH `authorized_keys`
  entry. Operators and forks add their own keys and sign their own packages;
  nothing here depends on the vendor. The private half never touches a managed
  node: signing is a separate step from building, run wherever the key lives.
  New commands: `satom show trust`, `satom show package`,
  `satom execute trust add-key`, `satom execute trust remove-key`,
  `satom diagnose updates` (also folded into `diagnose all`).

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

- **A missing systemd unit is no longer reported as a failed one.**
  `systemctl is-active` answers `inactive` for a unit that does not exist,
  which is indistinguishable from a unit that exists and stopped. A standalone
  install without an `nftables` package is fine; a node whose metrics store
  died is not. `LoadState` separates them and an uninstalled unit renders
  neutral.

- **SECURITY: the privileged update runner ran root-owned code out of a tree the
  service account owns.** `satom-updater.service` runs as **root** and its
  shipped unit points at `/opt/satom/deploy/self_update_runner.py`, inside the
  application tree — which belongs to the unprivileged service account after the
  de-privilege. The web worker could therefore rewrite the script root was about
  to execute and then enqueue a request, which it is *designed* to be able to
  do, and the next trigger would run its code as root. That is a complete
  escalation across the boundary `docs/privilege-model.md` exists to defend, and
  it is present in every release from 1.2 onward. A second path in the same
  process: `_pip_allowlist()` imported `app.services.system_info`, executing the
  entire Flask package as root out of the same writable tree.
  `deploy/install-runner.sh` now installs a `root:root` copy of the runner and
  its verifier in `/usr/local/lib/satom-runner`, run by a **system** interpreter,
  and redirects the unit with a drop-in — not an edit, because the update runner
  re-copies `deploy/<unit>` on every update. It runs from the installer, the
  de-privilege migrator, every code update and
  `satom execute reinstall runner`. The curated pip allowlist is now local to
  the runner, with a test asserting it still equals `system_info._LIBRARIES`.
  **Existing nodes are not fixed by updating alone** — run
  `satom execute reinstall runner` (or re-run the installer), then confirm with
  `satom diagnose updates`. Found while building the package feature: signature
  verification performed by a script the attacker can edit verifies nothing.
  [SATOM-RUNNER-ROOT-COPY]

- `client_max_body_size` raised to 400M in the generated vhost, matching the
  application's own upload limit. Below it, a valid package dies with an opaque
  nginx 413 that the application never sees and therefore cannot explain.

- **The unread badge on the topbar bell floated off the bell.** It was
  positioned with Bootstrap's `.top-0 .start-100 .translate-middle`, which
  anchor to the offset parent's border box — the button's padded hit area, not
  the icon in it. `.fw-topbar-btn` declared no `display`, so the bell (nested in
  a `.dropdown`, unlike the search button, which the flex container blockifies)
  stayed `display: inline` with a 34x28 box around a 14x16 glyph. Measured on a
  rendered page, the bubble sat at y 2–18 while the bell sat at y 16–32: ~14 px
  above the thing it annotates and 1 px inside the user menu, which reads as the
  bell moving and losing its formatting. The button now declares its own box and
  the bubble has a dedicated themed class, defined once and consumed by both the
  server-rendered markup and the live poller; it also picks up `--fw-danger` and
  `--fw-topbar-bg`, so a custom theme retints it. All four topbar buttons now
  report the same height. Guarded by `tests/test_topbar_bell.py`; see
  `docs/safeguards.md` 8g. [SATOM-BELL-BADGE]

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

- **The metrics store was never installed by the installer.** VictoriaMetrics
  was placed by hand on the development pair, so a freshly installed node got
  the analytics pages, the `metrics_scrape` scheduled action and the
  `satom-metrics.service` entry that `diagnose all` checks -- with no store
  behind any of them. An air-gapped install was worse than degraded: with no
  route to the internet there was no way to obtain the binary at all.
  `install-satom.sh` now installs it (bundle first, pinned download second,
  sha256 verified, warn rather than abort), creates `/var/lib/satom-metrics`
  and enables the unit *after* the service-account drop-in exists; all three
  offline builders carry the binary and **fail** rather than ship a bundle
  without it; and the digest is a single pinned value shared by installer and
  builders, because drift means a bundle one of them would refuse -- a failure
  that surfaces only on an air-gapped node. The artefact name is pinned and
  the `-enterprise` / `-cluster` builds published under the same upstream tag
  are refused: they are not Apache-2.0 and this product redistributes what it
  fetches. Same failure class as `sudo` missing from the 1.1 bundles and
  `lego` from the RHEL bundle; see `docs/safeguards.md` 16.
  [SATOM-METRICS-STORE] [SATOM-METRICS-BUNDLE]

- **The changelog stacked duplicate sections, and the published release pages
  showed them.** Sessions appended their own `### Changed` / `### Fixed`
  headings independently, so `[Unreleased]` carried three "Changed" and two
  "Fixed", and the already-published `[1.3]` block carried 25 sections where
  three were meant. Nothing errored -- the file parsed, the site built, and
  each release page simply rendered the same heading several times, reading as
  though one version contained several releases. Both blocks are merged (no
  entry text changed; 168 bullets before and after) and a guard now fails on a
  repeated kind inside a flat block. Blocks that group entries under
  descriptive sub-headings are exempt: repeats across sub-sections are correct
  there, and the release-notes generator renders them as written.

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

- **The changelog is published on all three surfaces.** The same file is now
  readable in the repository, inside the application under **Documentation**,
  and on the public documentation site. One source, three renderings — no copy
  to fall out of date. A test fails the suite if any surface stops carrying it.

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

- **Device cards start folded and tile densely.** Expanded-by-default is
  unusable past a handful of appliances: a hundred of them was a kilometre of
  scroll. The cards now open collapsed, tile in a dense ~258 px grid so a large
  fleet fits in one screenful, and an expanded card takes the full row (the
  policy table needs the width, and a tall item in a narrow column stretches
  every tile beside it). The persisted state is now the set of **open** cards,
  not the closed ones, under a new `localStorage` key — the old key held the
  inverse set, and reusing the name would have expanded exactly the cards an
  operator had folded.

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

- **A scheduled deep-monitor sweep now reports whether it RAN, not whether it
  liked what it found.** `ok` was `worst in ("ok","unknown")`, so a single
  policy with every backend down marked the sweep *failed* and kept it failed
  until the backend was repaired — making a sweep that could not execute look
  identical to a healthy one that found something, and pinning the action
  permanently red. The worst status and per-status counts moved into the
  summary. See `docs/safeguards.md` §9d.

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

- **The application reported version 1.0 through four releases.** The footer
  and Settings -> System Information each carried a hand-written literal that
  was correct exactly once, while the release pipeline published the real
  number everywhere else. Both now read the repo-root `VERSION` file, which is
  the same file the offline-bundle builders and the operator console already
  read. The public site's hero badge is derived from it too, by the same
  stamping pass that versions the stylesheet, so it cannot drift either. A
  test fails the suite if a version literal reappears in a template or a page.

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

- **`transactions` could report a silent zero on a saturated policy.** Found by
  a real load test against fortiweb08 (2026-07-28): a policy carrying
  ~2 700 req/s reported **0** transactions in every bucket, and **417 059** the
  moment a `web-protection-profile` was attached to it — nothing else changed,
  and enabling the global traffic log beforehand made no difference. The probe
  now cross-checks `policystatus` **only when the count is zero**; if the policy
  is carrying sessions or connections it grades `warn` and names the likely
  cause, instead of a green row on a busy service. Mutation-tested.

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
