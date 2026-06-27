# Release Notes & Upgrade Planning

A searchable corpus of FortiWeb **known** and **resolved** issues (plus the prose
sections) across firmware versions, harvested from `docs.fortinet.com` — built to
**plan upgrades**: diff your current firmware against a target and see what you
*gain* (issues fixed) and *inherit* (issues still open).

- **Service:** `app/services/release_notes.py` (pure — no Qt, no DB)
- **DB projection:** `release_note_issue` + `release_note_section` (store **v12**)
- **Git-shared reference:** `reports/_release_notes.json`
- **GUI:** Settings → Operation → **Release Notes** (`ui/pages/release_notes_page.py`)
- **CLI:** `scripts/sync_release_notes.py`

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
| Product integration & support | `756870` | `product-integration-and-support` | prose |

The issue sections are two-column `Bug ID` / `Description` tables (a known issue
often embeds a `Workaround:` — split into its own field). The pages are served
**server-side** (no JS), so a plain `httpx` GET works headless; a **Firecrawl**
transport (self-hosted LAN or cloud) is available as a fallback.

> **The key fact for upgrade planning:** the *same* Bug ID flips
> **Known → Resolved** across versions, so "what does upgrading current → target
> fix / leave open" is a pure diff over this data.

### Coverage / limitation

Only pages that carry the MadCap `mc-main-content` article are harvested
(`has_release_content`). **Older maintenance releases** whose section ids drifted
resolve to a 200 *landing* (just the version-switcher chrome) — those are skipped
so nothing bogus is stored. In practice the harvested range is the recent,
upgrade-relevant releases (validated: FortiWeb **7.6.5–7.6.9** and **8.0.2–8.0.5**,
181 issues / 36 sections as of 2026-06). Versions that don't publish parseable web
release notes simply have no data (better than garbage).

## 2. Topics (curated)

Issues have **no** category column upstream, so each is tagged with a **curated**
topic by a deterministic, offline keyword classifier (`TOPIC_RULES` /
`classify_topic`): *SSL/TLS & Certificates, High Availability, Authentication &
SSO, Logging & Reports, FortiGuard & Updates, GeoIP & IP Reputation, WAF /
Signatures, API Protection, Server Policy & Pools, Networking, Machine Learning,
Bot Mitigation, Caching & Compression, GUI / Web UI, Upgrade & Configuration,
System & Performance,* else *General*. The page's topic filter reflects the topics
actually present (`store.release_topics`), so tuning the rules never breaks the UI.

## 3. The page (Settings → Operation → Release Notes)

Admin-only (the whole Settings area is). Three tabs:

- **Issues** — filter by version / status (known·resolved) / topic / keyword;
  double-click a row for the full description + workaround + the source link.
- **Upgrade advisor** — pick **current → target**: the issues *resolved in the
  range* (gained), the issues *still known in the target* (inherited), and the
  upgrade-notes prose. (`AdvisoryWidget` — reused from the firmware Upgrade dialog
  via the **📋 Release-notes advisory** button, target prefilled from the image
  filename.)
- **Notes** — full-text search the prose sections (What's new / Upgrade notes / …).

### 🔎 Scan from Fortinet

Auto-discovers every version from the docs site and harvests the selected
`major.minor` families (or **all**) into `reports/_release_notes.json` and the DB.
**No appliance needed** — it reads the public docs directly with a Firecrawl
fallback (both transports on by default). Optionally publishes to git (multiuser-
safe, like the inspector reports). CONFIG_WRITE + unlock.

`⤓ Sync from git` pulls the shared reference and re-ingests it (a fresh clone that
pulled the JSON also self-heals into the DB on first open).

## 4. Data model

`ReleaseIssue(product, version, status, bug_id, description, workaround, topic,
source_url)` and `ReleaseSection(product, version, section, title, content,
source_url)`, serialised to `reports/_release_notes.json`
(`{generated_at, versions[], issues[], sections[]}`).

In the DB they are a **full projection** (replaced wholesale on ingest):
`store.replace_release_notes(issues, sections)`. Each row carries a zero-padded
`version_key` so plain `ORDER BY` / range filters rank versions. Queries:
`release_issues(version, status, topic, query, version_gt, version_le)`,
`release_sections(...)`, `release_versions()`, `release_topics()`,
`release_counts()`.

The upgrade advisory is a pure function `advise(issues, sections, current, target)`
→ `UpgradeAdvisory(resolved, known_in_target, notes, is_upgrade)`; the GUI computes
the same via the `version_gt`/`version_le` store filters.

## 5. CLI

```bash
# the relevant upgrade-planning range (default 7.0–8.0)
arch -arm64 .venv/bin/python scripts/sync_release_notes.py
# everything the docs site lists (5.x–8.x — slow)
arch -arm64 .venv/bin/python scripts/sync_release_notes.py --all
# a specific set + a Firecrawl fallback endpoint
arch -arm64 .venv/bin/python scripts/sync_release_notes.py --majors 7.6,8.0 \
    --firecrawl http://192.0.2.66:3002
```

Writes `reports/_release_notes.json` and ingests it into the app DB. Review/commit
the JSON (or use the GUI's Publish-to-git) to share with the team.

## 6. Tests

`tests/test_release_notes.py` — HTML-fixture parsing, the content guard, the
curated topic classifier, `version_key` ordering, the scan (fake fetcher), merge,
the advisory diff, and the store projection + range queries (no network, no Qt).
