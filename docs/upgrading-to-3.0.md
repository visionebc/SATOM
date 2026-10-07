# Upgrading to 3.0

> **Audience:** administrators updating a SATOM 2.x node or pair to 3.0.0. The
> update itself is the normal one (user guide §22); this page lists what 3.0
> changes underneath it, what you have to do, how to check it worked, and how
> to go back.

SATOM 3.0 changes **where the vendor knowledge comes from and who may sign
it**. The code update is signed and applied exactly as before. What is new is
that release notes, the Scout advisory, upgrade paths, the API library's
knowledge of builds you do not run, and signature metadata now arrive only in
**signed packs**, in two lanes with their own keys.

---

## 1. What breaks

| Change | What it means for you |
|---|---|
| **Pack schema `satom.api-pack/2`** | Packs published from 3.0.0 on carry a `lane`, a `min_satom`, the harvester snapshot and a `kind` on every item. **SATOM 2.13 and older refuse them** (`unsupported pack schema`). 3.0 still imports the 2.x `/1` packs. A pack whose `min_satom` is newer than the node is refused whole, with the version it needs. |
| **Split trust: one key, one use** | Update packages are verified only with the update trust store (`/etc/satom/update-keys/`, unchanged). A `/2` pack is verified only with the keys of its lane: `api_pack` or `knowledge`. A pack signed with the release key, or with the other lane's key, is refused. The lane keys ship inside the release, so nothing has to be installed first. |
| **The docs.fortinet.com crawler is gone** | SATOM no longer contacts any vendor documentation site. The **Scan from Fortinet** panel and its routes are removed. Release notes, Scout and upgrade paths read the corpus imported from packs. A crawler service or proxy allowance you kept only for SATOM's scans can be retired. |
| **Knowledge packs are no longer inside the update** | Up to 2.13 a release carried a knowledge pack (`satom-apipack-kb-*`) in `api-packs/`. From 3.0 the release carries only its **API pack** (`satom-apipack-3.0.0`, lane `api_pack`). The rolling **knowledge pack** comes from the knowledge feed, or by upload on an air-gapped network. |
| **New tables and columns** | Migration `apipack06_knowledge_lanes` adds `knowledge_signature_meta` and the `status` / `origin` columns of the API field-map table. It runs as part of the update. |

What does **not** change: the update packages and their key
(`satom-release-2026`), the update procedure, the console URL, permissions,
appliance credentials, and every piece of data this node measured itself —
**local data always wins over any pack**.

## 2. What you have to do

### Online node or pair (reaches the Internet, directly or by proxy)

1. **Update as usual** (Software Update → *Check* / *Apply*, or an offline
   package). On a pair, update each node (user guide §22.2).
2. **Arm the two new scheduled actions, once, on the primary:**

   ```bash
   sudo satom execute seed actions          # shows the plan
   sudo satom execute seed actions --yes    # creates what is missing
   ```

   Scheduled actions are data, not code: no update creates them. Seeding adds
   only the missing rows — **`knowledge_fetch`** (daily, keeps the knowledge
   current) and **`signature_check`** (daily, signature database freshness) —
   and never touches rows you edited. You can also create them on the
   Scheduled Actions page.
3. Nothing else. The update imports the shipped 3.0 API pack on the primary,
   and from then on `knowledge_fetch` (default mode **Download and import**)
   brings each new knowledge pack. To pull one immediately: Software Update →
   **Knowledge packs** → **Check now** → **Import**, or
   `sudo satom execute knowledge fetch --import --yes`.

If your nodes reach an internal mirror and not the Internet, set the **Feed
URL** on the Knowledge packs card of the primary (any `https://` URL).

### Air-gapped node or pair

1. Update with the offline package as usual, then seed the actions (step 2
   above). Set `knowledge_fetch` to **Off** or **Notify** if the feed can never
   be reached.
2. On a machine with Internet access, download the newest knowledge pack and
   its `.sha256` from the `knowledge` release of the public repository
   (`https://github.com/visionebc/SATOM/releases/tag/knowledge`; its
   `latest.json` names the current file). Check it:
   `sha256sum -c satom-apipack-kb-<date>.tar.gz.sha256`.
3. Carry the file over and import it on the primary: Software Update → **API
   library packs** → upload → **Import selected**, or
   `sudo satom execute apipack import ./satom-apipack-kb-<date>.tar.gz --yes`.
   The signature is checked against the shipped knowledge key; nothing else
   needs to be trusted.
4. Repeat step 2–3 whenever you want newer knowledge. The release notes modal,
   Scout and the Migration report show a **stale** badge when the knowledge is
   older than 30 days.

### Container nodes

The image carries `api-packs/` and the lane keys. Importing packs on a
container install is not covered yet (API library §11.8), and neither is the
knowledge feed there: on a container node the knowledge lanes are a
known gap of 3.0.0.

## 3. How to verify

```bash
satom show version                 # 3.0.0 on every node
satom show trust                   # keys per purpose
satom show knowledge               # installed pack per lane, age, mode, last fetch
satom show apipack                 # packs on this node and the import history
```

`satom show trust` must list three purposes, with these public keys:

| Purpose | Key | Fingerprint |
|---|---|---|
| `update` | `satom-release-2026` | `SHA256:cYv9NxiJjMn/K6srKxXg2kdvROP2g6fzgfMXU6sxPyA` |
| `api_pack` | `satom-apipack-2026` | `SHA256:tHXWO5UWTnvgoTloIzBpsN7J9Vj/NVbcTZFsdgww0ks` |
| `knowledge` | `satom-knowledge-2026` | `SHA256:hVYALGlEVZISwsSFRvr6ymysCuYUo1NxecpUhLJXDjE` |

`satom show knowledge` should show the API pack `satom-apipack-3.0.0` as
installed and, after the first fetch or upload, a knowledge pack with its age.
In the web console:

- **Software Update → Knowledge packs**: one row per lane, no *stale* badge.
- **Release Notes** modal (top bar): *"Knowledge from `<pack>` (`<date>`)"*.
- **Administrator → Signatures**: every FortiWeb with a signature database
  status (*current*, *stale* or *unreadable*) after the first
  `signature_check` run.

## 4. Rolling back

A rollback to 2.13 is a normal downgrade (Software Update with the explicit
downgrade confirmation, or `--allow-downgrade` on the console), and the usual
rule applies: **a downgrade does not reverse database migrations**
([offline update packages](offline-update-packages.md) §7).

- **The clean way back is the database backup the 3.0 update took.** Downgrade
  the code, then restore that backup (`satom get backup list`,
  `satom execute restore db <bundle> --yes`). Anything recorded after the
  update is lost with it.
- **Without the restore,** the 3.0 tables and columns stay. 2.13 does not read
  `knowledge_signature_meta`. It also does not know the field-map `status`
  column, so rename **candidates** a 3.0 pack imported (which 3.0 never
  applies) would read as ordinary field maps on 2.13: retire them on the API
  field renames page (`/web/registry/field-map`, user guide §30.9) before you
  downgrade, or restore the backup.
- A 2.13 node refuses every 3.0 pack (`unsupported pack schema`); the release
  notes already imported stay readable, but nothing newer arrives until the
  node runs 3.0 again.
- Keys added under `/etc/satom/pack-keys/` are ignored by 2.13 and can stay.

## 5. Where to read more

- [API library](api-library.md) §12 — lanes, the `/2` manifest, trust, item
  kinds, import precedence and provenance.
- [User guide](user-guide.md) §22.3–§22.4 (packs on Software Update), §8.1
  (signature freshness), §31.1 (release notes from packs), §45 (this upgrade in
  short).
- [Knowledge Harvester](knowledge-harvester.md) — where the packs come from.
- [Alerting](alerting.md) — the signature-freshness device finding.
- [FortiGate](fortigate.md) — the new read-only FortiGate workspace.
- [Changelog](../CHANGELOG.md) — the full 3.0.0 entry.
