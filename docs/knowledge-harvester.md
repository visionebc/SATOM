# SATOM Knowledge Harvester — where the shipped API knowledge comes from

> **Audience:** administrators who want to know what the packs contain and how
> a node gets them, and maintainers who run the harvester. Customers do **not**
> need the tool. The pack format, the trust model and the import rules are in
> the [API library](api-library.md) §12 (3.0, schema `satom.api-pack/2`) and
> §11 (the 2.x packs); the CLI channel it feeds is §14.
>
> **Since:** SATOM 2.13.0; in 3.0.0 it became the **only** source of vendor
> knowledge.

The **SATOM Knowledge Harvester** (`satom-harvester`) is a **separate tool**,
in its own repository, that collects what Fortinet products expose about their
configuration API — from lab devices, the vendor documentation and public
vendor collections — and turns it into **signed packs** that SATOM imports.
Nothing in the product calls the harvester, and the harvester never talks to a
customer's node. The tool itself is not distributed: what customers receive
are its packs.

```
collect                          snapshot + gate               publish (two lanes, same content)
lab devices (SSH, REST, --+                                    api_pack  : satom-apipack-<SATOM version>
 read-only)               |--> evidence, release notes,  -->     inside each release (api-packs/)
vendor documentation    --+    field schemas, CLI coverage,    knowledge : satom-apipack-kb-YYYYMMDD[.N]
public vendor collections-+    factory profiles, renames,         the knowledge feed (rolling)
earlier signed packs    --+    baselines, signature metadata   each lane signed with its own key
```

---

## 1. Why a separate tool

- **Firecrawl lives only there.** Crawling the vendor's documentation site at
  scale (release notes of every version, CLI references) is a maintainer's job
  with a maintainer's tooling: a crawler service, a cache, rate limits, retries.
  SATOM 2.13 removed its own Firecrawl fallback: SATOM 3.0 removed the last
  direct download of docs.fortinet.com as well. An operator never configures a
  crawler, and a node never contacts a vendor documentation site.
- **Lab devices live only there.** Measuring a build means a box running it. The
  harvester reads lab devices (SSH `tree`, `show full-configuration`, REST GETs
  and schemas) so that a customer who has never run a build still knows what it
  serves.
- **One trust path per purpose.** What reaches a node is a signed file,
  verified before anything is read — against the keys of the pack's **lane**,
  never against the update key (API library §12.3). There is no unsigned
  channel to secure.

---

## 2. What a pack carries

Both lanes carry the **same sections**, and every pack is a **full snapshot**,
never a delta:

| Section | Kind | Content |
|---|---|---|
| `library` | `evidence` | evidence documents per exact build: `cli_tree` (the CLI schema), `cli_full` (field names `show full-configuration` prints), `sweep` (REST field names and types, verdict by response shape), `schema` (FortiGate `?action=schema`, FortiAuthenticator Tastypie), `vendor_doc` (CLI reference parameter tables and the public Ansible collections, pinned to the version they describe) |
| `docs` | `release-notes` | the vendor release-notes corpus (Known/Resolved issue tables, upgrade notes, special notices) for FortiWeb, FortiADC, FortiAuthenticator, FortiAnalyzer and FortiGate |
| `docs` | `field-schemas` | the field catalog per product and firmware line (type, options, range, help, key), generated from the CLI schema |
| `cli-coverage` | `cli-coverage` | per product and version, the CLI-only blocks and near matches (names only) |
| `factory` | `factory-wpp` | the FortiWeb predefined Web Protection Profiles per build, in the exact shape SATOM's factory catalog stores |
| `field-map` | `field-map` | field rename **candidates** between two builds, from equal CLI attribute ids |
| `baselines` | `baseline` | measured endpoint baselines per build, as reference |
| `signature-meta` | `signature-meta` | public FortiGuard metadata for signature ids (see below) |

**Signature metadata ships empty.** The harvester checks the FortiGuard site's
`robots.txt` and terms of use before it reads anything there. They do not
permit automated collection and redistribution, so the FortiGuard enrichment is
**disabled** and the `signature-meta` section stays empty until that is
permitted. SATOM shows signature ids without the extra metadata in the
meantime; the signatures themselves never travel in a pack (each appliance
downloads its own from FortiGuard).

The same rules as SATOM's own export apply, enforced at build time, each one
refusing the whole pack:

- **No configuration values.** Field specs carry names and types. A `default`
  is allowed only in `vendor_doc`/`schema` evidence, or in lab-flagged
  `cli_full` evidence (a freshly created lab row, whose values ARE the
  defaults); secrets, certificates, addresses and identity fields are dropped.
- **No estate identity.** Device names become stable `witness-<hmac>`
  pseudonyms; serials, addresses and hostnames are never recorded; any known
  device name, serial or address that survives anywhere refuses the build.
- **Signed** with Ed25519 — with the lane's key when it is published (§3).

### Sources a snapshot covers

| Source | What it adds |
|---|---|
| Lab devices | FortiWeb 7.6.8 and 8.0.6, FortiGate 8.0.1 build0245, FortiAuthenticator 8.0.3 build0099: CLI schema, `show full-configuration` names, REST sweeps and schemas, factory profiles, lab defaults |
| Vendor documentation | release notes of every product and version listed above, CLI reference tables |
| Public Ansible collections | `fortinet.fortios` 2.6.0 and `fortinet.fortianalyzer` 1.10.0, as `vendor_doc` evidence |
| Archive of our own packs | evidence from earlier release-signed packs (for example `satom-apipack-2.13.0`) for builds no lab device can re-measure today (FortiADC 8.0.3, FortiWeb 8.0.5), marked `attrs.origin = "archive:<pack>"` and superseded automatically when a device measures that build |

---

## 3. From snapshot to published pack

1. **Snapshot.** One harvester run builds every section into one snapshot,
   named `satom-apipack-kb-YYYYMMDD[.N]`, with a date-free
   `content_fingerprint` (identical content, identical value).
2. **Content gate.** The snapshot is compared with the previous **approved**
   snapshot, per section, kind, product and build or version. Additions only:
   approved automatically. Any removal or change: **held** until a maintainer
   approves it, with a typed confirmation and a reason, audited. Knowledge never
   disappears from a pack by accident.
3. **Publish, per lane.** The approved snapshot is re-manifested and signed with
   the lane's key, then tested by importing it into a staging SATOM; only a
   clean import is published.
   - **knowledge** (`satom-knowledge-2026`): whenever the approved content
     changes, to the `knowledge` release of the public repository (a
     prerelease, never "Latest"), with its `.sha256` and the feed file
     `latest.json`.
   - **api_pack** (`satom-apipack-2026`): at every SATOM release, as
     `satom-apipack-<version>` pinned to that release, inside `api-packs/` and
     as a release asset. A parity gate refuses the release if any (product,
     build, source) the previous API pack carried is missing.

Public keys and fingerprints are in the [API library](api-library.md) §12.3.

---

## 4. How the knowledge reaches a node

| Node | How |
|---|---|
| Online install or update | the release's **API pack** is in `api-packs/`; the installer and the update runner import it on the primary. The scheduled action `knowledge_fetch` then imports each new **knowledge pack** from the feed (user guide §22.4) |
| Air-gapped node | download the knowledge pack and its `.sha256` elsewhere, upload it under **Settings → Software Update → API library packs**, or `sudo satom execute apipack import ./satom-apipack-kb-YYYYMMDD.tar.gz --yes` |
| A node with its own appliances | measures its own builds as well; **local measurement wins** — an item this node measured itself is shown `local` and never replaced |

Between packs, the **newer snapshot** wins whatever its lane, so a knowledge
correction lands without waiting for the next release (API library §12.5). A
pack signed by a key the node does not trust for that lane is refused with the
`satom execute trust add-key --purpose <lane>` command that fixes it.

---

## 5. What it measured

| Product | CLI schema | REST | Verified on |
|---|---|---|---|
| FortiWeb | `tree` | shape sweep of every `tree` object | 7.6.8 and 8.0.6 lab VMs |
| FortiAuthenticator | `config <object>` + `set ?` help walk (no `tree`) | Tastypie schema, directory complete | 8.0.3 build0099 |
| FortiGate | `tree` (nested tables folded into their top object) | `?action=schema` | 8.0.1 build0245 |
| FortiADC | `tree` (FortiOS-family format assumed) | — | not verified: no lab device (8.0.3 from the archive) |
| FortiAnalyzer | JSON-RPC `get` with `option: syntax` | same answer | not verified: no lab device |

Findings the packs carry with them (FortiWeb 7.6.8 → 8.0.6): +21/−10 objects,
+135/−25 fields, 15 enum changes, 1 type change, 18 field renames detected by
an equal CLI attribute id (4,121 of 4,121 field ids stable), 0 hidden fields, 0
REST-versus-CLI field-set gaps on objects REST serves. A lab write-and-read pass
on empty tables cut the `unknown` fields by 63 % (7.6.8) and 65 % (8.0.6) and
recorded 876 and 1,074 lab defaults.

---

## 6. For maintainers

The tool's own README documents installation, configuration (device secrets by
file or environment variable, never inline), its commands and the workspace
layout. Rules that matter on the SATOM side:

- The harvester's SSH session sends only `get system status`, `tree` and
  `show …`; REST sends only GET. Lab write-verification is a separate capture
  the harvester only reads.
- A harvester `diff` reports a build with no evidence for a channel as
  *unmeasured*, never as "no change" — the same rule SATOM's `compare()` follows.
- The harvester signs only its transport snapshot (lane `harvester`). SATOM
  refuses that lane by name: only the re-signed `api_pack` and `knowledge`
  packs are importable.
