# SATOM Knowledge Harvester — where the shipped API knowledge comes from

> **Audience:** administrators who want to know what the API pack in each
> release contains and how an offline node gets it, and maintainers who run the
> harvester. Customers do **not** need the tool. The pack format and import
> rules are in the [API library](api-library.md) §11; the CLI channel it feeds is
> §13.
>
> **Since:** SATOM 2.13.0 (unreleased).

The **SATOM Knowledge Harvester** (`satom-harvester`) is a **separate tool**,
in its own repository, that collects what Fortinet products expose about their
configuration API — from the vendor documentation and from lab devices — and
ships it as a **signed API pack** in the same format SATOM's own export writes
(`satom.api-pack/1`). SATOM imports that pack like any other pack. Nothing in
the product calls the harvester, and the harvester never talks to a customer's
node.

```
collect                          normalise                  ship
docs.fortinet.com   --+                                     satom-apipack-kb-YYYYMMDD.tar.gz
lab devices (SSH,   --+--> evidence documents + vendor --> signed (Ed25519), leak-scanned
 REST, read-only)            release-notes corpus           -> api-packs/ of the next release
```

---

## 1. Why a separate tool

- **Firecrawl lives only there.** Crawling the vendor's documentation site at
  scale (release notes of every version, CLI references) is a maintainer's job
  with a maintainer's tooling: a crawler service, a cache, rate limits, retries.
  SATOM 2.13 removed its own Firecrawl fallback: a node scans release notes with
  a plain direct download of docs.fortinet.com, or receives them in a pack. An
  operator never configures a crawler.
- **Lab devices live only there.** Measuring a build means a box running it. The
  harvester reads lab devices (SSH `tree`, `show full-configuration`, REST GETs
  and schemas) so that a customer who has never run a build still knows what it
  serves.
- **One trust path.** What reaches a node is a signed file, verified against the
  node's root-owned trust store before anything is read — the same path as
  update packages. There is no second channel to secure.

---

## 2. What a knowledge pack carries

| Section | Content |
|---|---|
| `library` | evidence documents per exact build: `cli_tree` (the CLI schema), `cli_full` (field names `show full-configuration` prints), `sweep` (REST field names and types, verdict by response shape), `schema` (FortiGate `?action=schema`, FortiAuthenticator Tastypie), `vendor_doc` (CLI reference parameter tables, pinned to the version they were published for) |
| `docs` | the vendor release-notes corpus (Known/Resolved issue tables, upgrade notes, special notices) for FortiWeb, FortiADC, FortiAuthenticator, FortiAnalyzer and FortiGate |

The same rules as SATOM's own export apply, enforced at build time, each one
refusing the whole pack:

- **No configuration values.** Field specs carry names and types. A `default`
  is allowed only in `vendor_doc`/`schema` evidence, or in lab-flagged
  `cli_full` evidence (a freshly created lab row, whose values ARE the
  defaults); secrets, certificates, addresses and identity fields are dropped.
- **No estate identity.** Device names become stable `witness-<hmac>`
  pseudonyms; serials, addresses and hostnames are never recorded; any known
  device name, serial or address that survives anywhere refuses the build.
- **Signed.** Ed25519, with the SATOM release key.

Knowledge packs are versioned `kb-YYYYMMDD` (or `kb-YYYYMMDD.N`) and sort after
SATOM's numbered release packs.

---

## 3. How the knowledge reaches a node

| Node | How |
|---|---|
| Online or offline install, update | the release commits the knowledge pack to **`api-packs/`** in the repository beside its own pack; the installer and the update runner import the shipped packs automatically (API library §11.5) |
| Air-gapped node that skipped a release | import the pack by hand: **Settings → Software Update → API library packs** (upload), or `sudo satom execute apipack import ./satom-apipack-kb-YYYYMMDD.tar.gz --yes` |
| A node with its own appliances | measures its own builds as well; **local measurement wins** — an item this node measured itself for the same source and build is shown `local` and never replaced |

Import only ever adds. A pack signed by a key the node does not trust is
refused with the `satom execute trust add-key` command that fixes it.

---

## 4. What it measured for 2.13

| Product | CLI schema | REST | Verified on |
|---|---|---|---|
| FortiWeb | `tree` | shape sweep of every `tree` object | 7.6.8 and 8.0.6 lab VMs |
| FortiAuthenticator | `config <object>` + `set ?` help walk (no `tree`) | Tastypie schema, directory complete | 8.0.3 build0099 |
| FortiGate | `tree` (nested tables folded into their top object) | `?action=schema` | 8.0.1 build0245 |
| FortiADC | `tree` (FortiOS-family format assumed) | — | not verified: no lab device |
| FortiAnalyzer | JSON-RPC `get` with `option: syntax` | same answer | not verified: no lab device |

Findings the pack carries with it (FortiWeb 7.6.8 → 8.0.6): +21/−10 objects,
+135/−25 fields, 15 enum changes, 1 type change, 18 field renames detected by
an equal CLI attribute id (4,121 of 4,121 field ids stable), 0 hidden fields, 0
REST-versus-CLI field-set gaps on objects REST serves. A lab write-and-read pass
on empty tables cut the `unknown` fields by 63 % (7.6.8) and 65 % (8.0.6) and
recorded 876 and 1,074 lab defaults.

---

## 5. For maintainers

The tool's own README documents installation, configuration (device secrets by
file or environment variable, never inline), the `docs`, `device`, `pack` and
`diff` commands and the workspace layout. Two rules that matter on the SATOM
side:

- The harvester's SSH session sends only `get system status`, `tree` and
  `show …`; REST sends only GET. Lab write-verification is a separate capture
  the harvester only reads.
- A harvester `diff` reports a build with no evidence for a channel as
  *unmeasured*, never as "no change" — the same rule SATOM's `compare()` follows.
