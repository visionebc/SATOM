# API library packs

This folder holds the signed API packs a release ships, each file with its
`.sha256`:

| Pack | Schema | Built by | Signed with | Kept |
|------|--------|----------|-------------|------|
| `satom-apipack-<x.y.z>.tar.gz` from 3.0.0 | `satom.api-pack/2`, lane `api_pack`, pinned to that release | the separate **SATOM Knowledge Harvester**: the newest approved snapshot, checked for parity against the previous API pack | the `api_pack` key `satom-apipack-2026` | every release |
| `satom-apipack-<x.y.z>.tar.gz` up to 2.13 | `satom.api-pack/1` | the release host's own library | the release key `satom-release-2026` | every release |

From 3.0.0 the release no longer carries a **knowledge pack**
(`satom-apipack-kb-*`). Knowledge packs are the rolling lane of the same
content: a node gets them from the knowledge feed (Settings → Software Update →
Knowledge packs, or `satom execute knowledge fetch`) or, on an air-gapped
network, by downloading one from the `knowledge` release of the public
repository and uploading it.

A pack carries what SATOM knows about vendor APIs, so that a node with no
appliance of a given firmware build and no internet access still starts with a
useful API library:

| Section          | Contents |
|------------------|----------|
| `library`        | Which endpoints and fields each firmware build serves: lab sweeps and schemas (field names and types only, never a configuration value or a device name), the CLI schema, vendor documentation claims. |
| `docs`           | Release notes (full text) for FortiWeb, FortiADC, FortiAuthenticator, FortiAnalyzer and FortiGate, the field catalog per firmware line, the FortiWeb field help overlay. |
| `cli-coverage`   | Per firmware version, the configuration blocks that exist in the CLI and not in the REST API (block paths and `set` names only). |
| `factory`        | The FortiWeb predefined Web Protection Profiles per build (3.0). |
| `field-map`      | Field rename candidates between builds — shown, never applied (3.0). |
| `baselines`      | Measured endpoint baselines per build, as reference (3.0). |
| `signature-meta` | Public FortiGuard signature metadata — empty until redistribution is permitted (3.0). |

The design and the safety rules are in `docs/api-library.md` §11 (2.x packs)
and §12 (3.0: lanes, trust, item kinds, import precedence).

## How a node gets it

- **Installer (online and offline):** the pack travels with the code, and the
  installer imports it on the primary or standalone node once the console is
  healthy. `SATOM_API_PACK=none` skips it; `SATOM_API_PACK_PRODUCTS=fortiweb,fortiadc`
  limits it to some products.
- **Update:** after a successful update on the primary, the runner imports the
  pending shipped pack itself (non-fatal; `SATOM_API_PACK_AUTO=0` in the
  runner's environment turns it off). Software Update shows a notice while a
  shipped pack is pending. The 3.0 API pack supersedes the 2.x packs in this
  folder.
- **Software Update page:** *API library packs* lists these packs and any pack
  you upload, shows per item what importing would do (`new`, `update`,
  `present`, `local`, `rejected`, `unknown`) and imports the items you tick.
- **Console:** `sudo satom execute apipack import shipped` (dry run), then the
  same with `--yes`. A pack downloaded on its own:
  `sudo satom execute apipack import ./satom-apipack-<version>.tar.gz --yes`.

## Verify before you import

```bash
sha256sum -c satom-apipack-<version>.tar.gz.sha256
```

The import checks the signature itself. A 3.0 pack is verified only with the
keys of its lane, which ship in `deploy/pack-keys/<lane>/` (and any you add in
`/etc/satom/pack-keys/<lane>/`); a 2.x pack only with the update trust store.
`satom show trust` lists the keys per purpose with their fingerprints:

| Key | Purpose | Fingerprint |
|-----|---------|-------------|
| `satom-apipack-2026` | `api_pack` | `SHA256:tHXWO5UWTnvgoTloIzBpsN7J9Vj/NVbcTZFsdgww0ks` |
| `satom-knowledge-2026` | `knowledge` | `SHA256:hVYALGlEVZISwsSFRvr6ymysCuYUo1NxecpUhLJXDjE` |

What the node measured itself always wins and is never overwritten. A copy an
earlier pack wrote is replaced only by a pack built from a newer snapshot.

This folder is maintained by the release pipeline: each release ADDS its pack
and never removes an older release pack. Do not edit it by hand.
