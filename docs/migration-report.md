# Migration report — will this appliance's configuration survive build X?

> **Audience:** operators planning a firmware upgrade (or a downgrade, or a move
> to another box) and change approvers who read the verdict. The data comes from
> the [API library](api-library.md) §13; the operator walkthrough is in the
> [User guide](user-guide.md) §40.3.
>
> **Since:** SATOM 2.13.0 (unreleased).

[Build compatibility](build-compatibility.md) checks a **payload** before a
write. The migration report checks a **whole appliance**: every object and field
it holds today, against what the API library knows about a target build. It
answers the question an upgrade window starts with — *what of this box's
configuration does 8.0.6 reject, rename, or change behind my back?* — before the
image is uploaded.

---

## 1. Input and output

**Input:** an appliance and a target build. The appliance's real state is its
**`show full-configuration`** dump: it prints every field of every object that
exists, defaults included, while REST is the operating channel, not an
inventory. The report reads the newest usable dump of the appliance from the
backup vault (or a backup you pick), parses it **in memory** and checks it
against the target build's CLI schema (`cli_tree`: fields, enum options, types,
ranges), the CLI half of `api_library.compare` (objects and fields removed and
added, option and type changes, rename candidates by CLI id),
`api_library.channels_at` (is the field there at all, how complete is the
target) and the operator's field maps.

**Output:** one row per finding, with a severity and a code, per-object counts
and a verdict. Nothing is stored; the report is computed on request.

**Values never leave memory.** A row names the object, its CLI path, the field,
how many rows are affected and library facts (option lists, defaults, ranges,
types). It never carries a configuration value, and neither do the JSON and CSV
exports. A report can be attached to a change request or mailed to a vendor
without leaking the configuration.

---

## 2. Classes

| Severity | Code | Meaning |
|---|---|---|
| **block** | `object_removed` | the target has no such object and the device uses it |
| | `field_removed` | the target dropped the field and the device holds a non-default value (any value when the default is unknown) |
| | `option_invalid` | the device's value is an enum option the target no longer accepts |
| | `value_out_of_range` | the value is outside the target's range |
| | `type_changed` | the type changed and the device's value does not satisfy the new one |
| **translate** | `rename_mapped` | a rename an operator field map covers (`from` → `to`) |
| **warn** | `rename_candidate`, `object_rename_candidate` | same CLI attribute id under another name on the target, no field map yet |
| | `default_changed` | the device leaves the field at its default and the default changed (behaviour changes without anyone touching it; only when both defaults are known) |
| | `type_changed` | a type change the report cannot prove the value satisfies |
| | `no_target_evidence` | the library has no evidence for that object or field on the target |
| | `source_unmeasured` | the source build has no CLI schema, so "removed" cannot be told from "never existed" |
| | `target_incomplete` | the target build is not completely measured; the row gives the percentage |
| **info** | `object_added`, `field_added` | new in the target, with its default when known |
| | `object_removed_unused`, `field_removed_unused`, `type_changed` | a change that does not touch anything the device uses |
| | `same_build` | source and target are the same build |

A rename candidate is reported, never applied. Confirm it with a field map at
**API field renames** (`/web/registry/field-map`) and the next report lists it
as `translate`.

### 2.1 Verdicts

| Verdict | When |
|---|---|
| **ready** | no block and no warn (also: same build, nothing to migrate) |
| **ready with warnings** | at least one warn, no block |
| **blocked** | at least one block |
| **cannot assess** | no usable dump, the source build is unknown, no target was given, or the target build has no CLI schema in the library |

A target older than the source runs the same checks and is labelled
`downgrade`.

---

## 3. Where to read it

- **Automation → Migration Report** (`/web/migration-report/`): pick an
  appliance and a target build. The target list offers the builds of that
  product that have a CLI schema in the library. The report page shows the
  verdict and its reason, the dump it read, how much of the target is measured,
  per-object counts and every finding; **JSON** and **CSV** export the same rows.
- **Appliance page → Migration Report** (FortiWeb, FortiADC and FortiGate
  appliances).
- **Upgrade Flow, stage 1**: each appliance shows the migration verdict for the
  move its newest pre-upgrade recorded, with a link to the full report. The
  library comparison is computed once per move; at most 20 appliances are
  assessed per page render, the rest link to their report.

**Permission:** the Upgrade Flow's own gate (`backup`, granted by
`backups.create` or `backups.restore`). Appliances of another ADOM, or hidden by
maintenance, answer 404.

### 3.1 From the console

```bash
sudo satom execute migration report fweb-01 --target 8.0.6
sudo satom execute migration report 34 --target 8.0.6 --backup 1207
sudo satom --json execute migration report fweb-01 --target 8.0.6   # the full report
```

The plain output is the move, the verdict, the counts per class and the first
ten block and warn rows. It runs `flask apilib migration-report` as the service
account. Read-only.

---

## 4. Example (anonymised, FortiWeb 7.6.8 → 8.0.6)

A lab FortiWeb 7.6.8 carrying a production-sized configuration, checked against
8.0.6 with the library both builds were harvested into:

| | |
|---|---|
| Objects checked | 212 |
| block / translate / warn / info | **10 / 0 / 11 / 104** |
| Verdict | **blocked** |

The top findings, by field name only:

| Severity | Code | Object | Field |
|---|---|---|---|
| block | `option_invalid` | `waf/web-protection-profile.inline-protection` | `mobile-app-identification` (8.0.6 no longer accepts `enable`/`disable`; it takes `jwt-token-secret`, `jwt-public-key` or `jwks-endpoint`) |
| block | `object_removed` | `waf/file-exception-policy` (and its `exception-list`) | — |
| block | `field_removed` | `waf/web-protection-profile.inline-protection` | `file-exception-policy` |
| block | `field_removed` | `system/ntp` | `syncsamples` |
| warn | `rename_candidate` | `waf/web-protection-profile.inline-protection` | `token-header` → `jwt-token-name` |
| warn | `rename_candidate` | `system/global` | `appsec-cloud-connection-url` → `threat-analytics-authurl` |
| warn | `rename_candidate` | `server-policy/pattern.threat-weight` | `sql-xss-sbd-op` → `sbd-op` |
| warn | `type_changed` | `waf/dos-prevention-exception/exception-element-list` | `ip` (`<string>` → `<userdef>`) |
| warn | `target_incomplete` | — | the share of 8.0.6 fields whose channel is still unknown |
| info | `field_removed_unused` | `waf/web-protection-profile.inline-protection` | `http-authen-policy` |

Recording the field map `token-header` → `jwt-token-name` turns that row into
`translate`/`rename_mapped` on the next run.

---

## 5. Limits

- **The dump decides what the device uses.** No usable `show
  full-configuration` dump in the vault means *cannot assess*. Take a backup
  first.
- **A field the dump does not print is not "unused" on the build.** `show
  full-configuration` prints only the fields that apply under the row's current
  settings. The report reads the dump for what the device *uses* and the
  library's `tree` for what the build *has*.
- **The target must be harvested.** A build with no `cli_tree` evidence cannot be
  assessed. Harvest a box on it, or import a knowledge pack (API library §13.12).
- **Products.** FortiWeb (verified schema and path rule), FortiGate (CLI schema
  verified) and FortiADC (path rule unverified: no lab device). FortiAuthenticator
  and FortiAnalyzer have no migration report.
- **Behaviour, not syntax.** The report proves that a value is accepted, not that
  the feature behaves the same. Read the vendor's upgrade notes (Release Notes →
  Upgrade advisor) as well.
