# Release Notes & Upgrade Planning

A searchable corpus of FortiWeb **known** and **resolved** issues (plus the prose
sections) across firmware versions, harvested from `docs.fortinet.com` — built to
**plan upgrades**: diff your current firmware against a target and see what you
*gain* (issues fixed) and *inherit* (issues still open).

- **Service:** `app/services/release_notes.py` (pure — no Qt, no DB)
- **Store:** the JSON corpus `reports/_release_notes.json` — read with
  `load_db()`, merged with `merge_db()`, written with `save_db()`. There are
  **no** release-notes DB tables. `reports/` is a **symlink into the gitignored
  `data/reports/`**: the corpus is local to each node and reaches the standby
  through `satom-ha-datasync`, never through git (§3).
- **UI:** account menu (top right) → **Release Notes** — a modal
  (`app/templates/partials/release_notes_modal.html`,
  `app/static/js/release_notes.js`) served by `app/views/release_notes.py`
  (blueprint `release_notes`, url prefix `/release-notes`)
- **Harvest:** `POST /release-notes/scan` (the modal's 🔎 button) — there is
  **no** CLI entry point

## 1. Where the data comes from

Fortinet publishes a *Release Notes* document per version at
`docs.fortinet.com/document/fortiweb/<version>/release-notes/<id>/<slug>`. The
section ids are **stable** across the recent docsets:

| Section | id | slug | kind |
|---|---|---|---|
| Known issues | `54989` | `known-issues` | Bug-ID table |
| Resolved issues | `91537` | `resolved-issues` | Bug-ID table |
| What's new | `639023` | `whats-new` | prose |
| Upgrade notes & important information | `745354` | `upgrade-notes-and-important-information` | prose |
| Upgrading from previous releases | `81434` | `upgrading-from-previous-releases` | prose |
| Repartitioning the hard disk | `159021` | `repartitioning-the-hard-disk` | prose |
| Upgrading an HA cluster | `903663` | `upgrading-an-ha-cluster` | prose |
| Downgrading to a previous release | `750287` | `downgrading-to-a-previous-release` | prose |
| Image checksums | `754338` | `image-checksums` | prose |
| FortiWeb-VM license validation | `439600` | `fortiweb-vm-license-validation` | prose |
| Product integration & support | `756870` | `product-integration-and-support` | prose |

The five middle rows were added 2026-09-13. They are **siblings** of *Upgrading
from previous releases* under the *Upgrade instructions* TOC node (`489959`), not
children of it — so harvesting the two obvious ones left every blocking
prerequisite (disk repartition, HA upgrade order, downgrade support, VM licence
re-validation) outside the corpus. `UPGRADE_SECTIONS` names the subset the
advisory reads; `PROSE_SECTIONS` is everything searchable in the Notes tab.

The issue sections are two-column `Bug ID` / `Description` tables (a known issue
often embeds a `Workaround:` — split into its own field). The pages are served
**server-side** (no JS), so a plain `httpx` GET works headless; a **Firecrawl**
transport (self-hosted LAN or cloud) is available as a fallback.

> **The key fact for upgrade planning:** the *same* Bug ID flips
> **Known → Resolved** across versions, so "what does upgrading current → target
> fix / leave open" is a pure diff over this data.

### Two renderers, and the three states a page can be in

Fortinet changed renderer mid-docset. FortiWeb **up to 8.0.6** (and all of
FortiADC) is MadCap — the article sits in `id="mc-main-content"`. FortiWeb **from
8.0.7** is a markdown pipeline: no MadCap container, no HTML tables on some
pages, and the whole article repeated a second time inside a `mobile-content`
wrapper. `has_release_content()` recognises both containers; `_main_content()`
closes the src-md slice on `mobile-content` / `thin-footer`, because a slice that
runs to the end of the document harvests every row twice.

Every page therefore falls into exactly one of three states, and the second one
is the whole reason this section exists:

| state | how it is recognised | scanner behaviour |
|---|---|---|
| **absent** | no `document-content src-XX` wrapper at all — a 200 landing of pure chrome (~442 KB) | skipped, silently. The only branch allowed to be quiet. |
| **unreadable** | an article is present but the parser produced nothing | recorded in `ReleaseNotesDB.unreadable`, logged `✗ … UNREADABLE`, surfaced in the scan result and as a **warning** bell |
| **read** | parsed | stored |

> **Why this matters.** Before 2026-09-13 the scanner collapsed *unreadable* into
> *absent*: any page it could not parse was `continue`d. When 8.0.7 switched
> renderer, every scan finished green, the log said *"8.0.7 — no release notes
> found"*, and the corpus silently stopped two releases short — including the
> release whose *Supported upgrade paths* announces a mandatory intermediate hop.
> A scan that could not read a published page now never lights a success bell.

An issues page that is *genuinely* empty says so in prose ("There are no known
issues in version 8.0.7"); `declares_no_issues()` recognises that statement, so an
empty table and an unreadable table are no longer the same observation.

## 2. Topics (curated)

Issues have **no** category column upstream, so each is tagged with a **curated**
topic by a deterministic, offline keyword classifier (`TOPIC_RULES` /
`classify_topic`): *SSL/TLS & Certificates, High Availability, Authentication &
SSO, Logging & Reports, FortiGuard & Updates, GeoIP & IP Reputation, WAF /
Signatures, API Protection, Server Policy & Pools, Networking, Machine Learning,
Bot Mitigation, Caching & Compression, GUI / Web UI, Upgrade & Configuration,
System & Performance,* else *General*. The modal's topic filter reflects the topics
actually present (`_topics()` in `app/views/release_notes.py`), so tuning the rules
never breaks the UI.

## 3. The modal (account menu → Release Notes)

Reading needs `VIEW`; the 🔎 scan needs `USER_MANAGE` (admin). Three tabs:

- **Issues** — filter by version / status (known·resolved) / topic / keyword;
  double-click a row for the full description + workaround + the source link.
- **Upgrade advisor** — pick **current → target**. Two answers, stacked, and
  they are different KINDS of answer:
  - **Scout advisory** (top) — the verdicts: what will block or complicate this
    window, each with the vendor's sentence attached. See §7.
  - the bug diff (below) — issues *resolved in the range* (gained), issues
    *still known in the target* (inherited), and the upgrade-notes prose
    (`GET /release-notes/advise?current=…&target=…` →
    `services.release_notes.advise`).
- **Notes** — full-text search the prose sections (What's new / Upgrade notes / …).

### 🔎 Scan from Fortinet

**Discover first, then tick.** Opening the scan panel fetches the version list
(one page fetch, ~1 s) and renders it as checkboxes grouped by line, with the
versions missing from the corpus **pre-ticked**. Only the ticked versions are
scanned, verbatim — discovery is a suggestion, the ticks are the order.

This replaced a free-text `major.minor` box sitting next to an "All discovered"
checkbox, and it fixed two defects at once:

1. the box could not express a single maintenance release — the filter matched on
   `major.minor`, so typing `8.0.7` matched nothing and the scan died with *"No
   versions matched"*;
2. the checkbox **silently overrode** the box. On 2026-09-13 an operator with
   `8.0` typed in the box got all 59 versions harvested, and nothing anywhere
   said which of the two controls had decided.

The endpoint still accepts the legacy `majors` / `all` filter for scripted use,
but a request that sends a contradiction (`all` **and** `majors`, or `versions`
**and** either) is now refused with 400 instead of resolving itself.

**No appliance needed** — it reads the public docs directly with a Firecrawl
fallback (both transports on by default). Admin only (`USER_MANAGE`).

### The two git controls were removed on 2026-09-14

`Publish to git` (a checkbox on the scan panel) and `⤓ Sync from git` (a button
in the modal header) are **gone**, along with `POST /release-notes/sync`. Three
separate defects, one removal:

1. **Neither could move the corpus.** `reports/` is a symlink into the
   gitignored `data/reports/`; git refuses a path under it outright —
   `fatal: pathspec '…' is beyond a symbolic link`. True since the git
   source-of-truth was retired on 2026-08-05 on volume grounds (see the
   metrics-architecture note), so **every scan since then logged**
   *"(git publish reported an issue — corpus saved locally)"*.
2. **`/sync` ran `git pull` over the running code tree, for `VIEW`.** The same
   operation is gated behind `USER_MANAGE` in `settings.git_pull` and is owned
   by `satom-reconciler`. A read-only user could move the application's code
   out from under the workers. This is why the endpoint was deleted rather
   than hidden — a hidden button keeps its URL.
3. **The success message was false either way.** `_load()` re-reads the JSON on
   every request, so *"Ingested N issues … from the shared reference"* always
   described the local file. Nothing was ever ingested from anywhere.

In their place, **⟳ Reload corpus** (`POST /release-notes/reload`, any logged-in
user) re-reads the JSON from disk and reports **where from** (`source`) and
**how old** (`generated_at`) — which is what the button was reaching for: the
counts on screen go stale while another gunicorn worker finishes a scan, or
while `satom-ha-datasync` drops a fresher corpus in.

**Sharing between nodes is data replication, not git.** The primary harvests;
`satom-ha-datasync` carries `data/` to the standby within 5 minutes. A separate
installation harvests its own. Guards: `tests/test_release_notes_nogit.py`.

## 4. Data model

`ReleaseIssue(product, version, status, bug_id, description, workaround, topic,
source_url)` and `ReleaseSection(product, version, section, title, content,
source_url)`, serialised to `reports/_release_notes.json`
(`{generated_at, versions[], issues[], sections[]}`).

There is **no DB projection** — the JSON corpus *is* the store. A scan merges into
it (`merge_db`) and rewrites it (`save_db`); each request re-reads and
product-scopes it (`load_db`, via `_load()` in `app/views/release_notes.py`).
`version_key` zero-pads a version so a plain sort ranks versions, and the filters
are pure functions over the loaded lists — `filter_issues(issues, version=,
status=, topic=, query=)` for the Issues tab, `advise(...)` for the advisor.

The upgrade advisory is a pure function `advise(issues, sections, current, target)`
→ `UpgradeAdvisory(resolved, known_in_target, notes, is_upgrade)`, exposed to the
modal as `GET /release-notes/advise?current=…&target=…`.

## 5. Running a scan (there is no CLI)

The harvest runs **in the app**, as a background thread behind the modal's
🔎 **Scan from Fortinet** button (`_do_scan` in `app/views/release_notes.py`):

```http
POST /release-notes/discover      → {versions:[{version,major,in_corpus}], count, new}
{"use_direct": true, "use_firecrawl": true}

POST /release-notes/scan          → 202 {started:true}
{"versions": ["8.0.7"], "use_direct": true}

GET  /release-notes/scan/status   → {running, lines[], result, error}
POST /release-notes/reload        → {counts, message, source, generated_at}
                                    re-reads the corpus from disk; no git
```

`result` now carries `unreadable[]` — the `(version, section)` pairs that were
published and could not be parsed. **A non-empty `unreadable` means the corpus is
incomplete**, and the UI says so instead of "done".

Legacy selection (still accepted, one filter at a time): `{"majors": "7.6,8.0"}`
or `{"all": true}`. `majors` defaults to `7.0,7.2,7.4,7.6,8.0`.

## 6. Scout Advisory (`services/release_advisor.py`)

`GET /release-notes/advisory?current=…&target=…` → an `Advisory`:

```
verdict        blocker | caution | clear | unknown
findings[]     {rule, severity, title, detail, evidence, version, section,
                source_url, data}
path[]         the required hop sequence, when one was stated
gaps[]         the (version, section) pairs the advisory NEEDED and does not have
read[]         the coverage it did have
rules_digest   a seal over the rules' own source
```

`detail` is our instruction; `evidence` is the vendor's sentence **verbatim**. A
rule that paraphrases a prerequisite and gets it slightly wrong is worse than no
rule, because it is believed.

**The case it was built for.** FortiWeb 8.0.7 is a maintenance release whose
*Supported upgrade paths* states that anything at 7.6.1 or lower must land on
7.6.2 first, and that 7.6.2 expands the partition and needs 1.5 GB free on the log
disk. Both sentences sit inside a 13 000-character page — which is exactly the
page an operator skims when the version number ends in `.7`.

Three rules of the house, carried over from Scout's ladder:

- **Absence is never innocence.** Missing coverage yields `unknown`, never
  `clear`, and the gaps are named. A gap says WHICH kind it is: a version nobody
  harvested, or a version harvested before these sections were collected (which
  is fixed by scanning it again).
- **The criteria are not editable.** `RULES` is the single author of every
  verdict and `rules_digest()` hashes the rules' own source onto the report, so an
  archived advisory names the rule set that produced it. An editable threshold
  would make a second author of a verdict nobody can reproduce.
- **A catch-all beats a complete list.** `vendor-marked` carries through every
  block Fortinet themselves flagged *Caution* / *Warning*, so prose no tailored
  rule understands still reaches the operator — with no verdict attached and no
  pretence of one. Where a tailored rule already cites the same block, the
  catch-all copy is dropped: printed twice, the weaker one sits under an
  instruction that already said what to do.

Rules are direction-aware: an upgrade advisory never quotes the *Downgrading*
page, and a rollback advisory never quotes *Supported upgrade paths*.

### Switching it off

`scout.enabled` (Settings → Scout → **Availability**, and the switch beside the
advisory in the modal — **the same flag**, not a second one). Off is enforced on
the **blueprint**: hiding a nav entry closes nothing, because the URL, the
bookmark and the link in a ticket all still work. `/scout/*` answers **503**, not
404 — "switched off" and "does not exist" are different answers to the operator's
next question — and the menu entry stays visible but disabled with the reason,
because an absent entry reads as a product that never had the feature.

## 7. Tests

- `tests/test_release_notes.py` — HTML-fixture parsing, the content guard, the
  curated topic classifier, `version_key` ordering, the scan (fake fetcher),
  merge, the advisory diff, and the store projection + range queries.
- `tests/test_release_notes_docsets.py` — the two renderers, the mobile-duplicate
  slice, the absent/unreadable/read trichotomy, the whole upgrade branch, and the
  selection routes (discover, explicit ticks, the refused contradiction).
- `tests/test_release_advisor.py` — the rules, driven over VERBATIM vendor prose;
  gating, collapsing, scope, coverage and the seal.
- `tests/test_scout_switch.py` — the switch, enforced on the route.

No network in any of them.
