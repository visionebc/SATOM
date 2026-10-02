# API library packs

This folder holds the signed **API library pack of every release**:
`satom-apipack-<version>.tar.gz` and its `.sha256`, one pair per version. Any
SATOM from 2.6.0 on can import any of them; the newest is the one the
installer and the update runner import (`shipped` means "newest by version").

A pack carries what SATOM has learned about vendor APIs, so that a node with
no appliance of a given firmware build, no internet access and no documentation
crawler still starts with a useful API library:

| Section        | Contents |
|----------------|----------|
| `library`      | Which endpoints and fields each firmware build serves: sweeps of real appliances (anonymised: field names and types only, never a configuration value or a device name), schemas, the vendor documentation claims. |
| `docs`         | Release notes (full text), the field catalog per firmware line, the FortiWeb field help overlay. |
| `cli-coverage` | Per firmware line, the configuration blocks that exist in the CLI and not in the REST API (block paths and `set` names only). |

The design and the safety rules are in `docs/api-library.md` §11.

## How a node gets it

- **Installer (online and offline):** the pack travels with the code, and the
  installer imports it on the primary or standalone node once the console is
  healthy. `SATOM_API_PACK=none` skips it; `SATOM_API_PACK_PRODUCTS=fortiweb,fortiadc`
  limits it to some products.
- **Update (2.7.0 on):** after a successful update on the primary, the runner
  imports the newest pack itself (non-fatal; `SATOM_API_PACK_AUTO=0` in the
  runner's environment turns it off). Software Update shows a notice while the
  newest pack has never been imported on the node.
- **Software Update page:** *API library packs* lists these packs and any pack you
  upload, shows per item whether it is new, already present or measured by the
  node itself, and imports the items you tick.
- **Console:** `sudo satom execute apipack import shipped` (dry run), then the
  same with `--yes`. A pack downloaded on its own from the release page:
  `sudo satom execute apipack import ./satom-apipack-<version>.tar.gz --yes`.

## Verify before you import

```bash
sha256sum -c satom-apipack-<version>.tar.gz.sha256
```

The import checks the signature itself, against the update trust store
(`satom show trust`). The pack is signed with the release key
`satom-release-2026` — the same key as the update packages; its public half
ships in `deploy/update-keys/` and is installed by the installer.

Importing only ever **adds**: what the node measured itself always wins, and
nothing it already holds is overwritten.

This folder is maintained by the release pipeline: each release ADDS its pack
and never removes an older one (about 400 KB per release). Do not edit it by
hand.
