# Device APIs & the endpoint registry

There are **two** different APIs in this product, and confusing them is the
most common way to waste an afternoon.

| | **API v1** | **Device API consoles** |
|---|---|---|
| Direction | someone drives **the platform** | the platform drives **an appliance** |
| Who calls it | a third-party script, over the network | an operator, from inside the web console |
| Auth | a Bearer token you were issued | your own logged-in session |
| Surface | 5 stable, versioned endpoints | the appliance's own REST/JSON-RPC API |
| Documented in | [API v1 — integration manual](api.html) | **this page** |

If you are writing an integration, you want API v1. If you are chasing a field
the interface does not expose yet, verifying what firmware actually returns, or
repairing the platform after a firmware upgrade moved a URI — you want this page.

---

## 1. The endpoint registry

### 1.1 Why it exists

Appliance vendors move REST paths between firmware releases. If those paths are
written into the source, every move is a code change, a release and a
deployment — for a one-line string. Worse, the breakage shows up as a feature
that quietly returns nothing.

So no code in this platform hardcodes a device path. Callers resolve a **logical
name** (`server_policy`, `system_interface`, `vip`) through the registry, and the
registry maps that name to the URN the firmware in front of you actually serves.

**The payoff is the whole point: when an upgrade moves a URI, the fix is editing
one row in a table, from the browser, by an administrator. No patch, no release,
no restart.**

A second consequence, which is easy to misread: the registry is a **cross-firmware
superset**. It deliberately contains names your particular firmware may not
implement. Such an endpoint answers "not found" — that is a correct answer about
your device, not a broken catalog entry.

### 1.2 Storage and identity

One table, `registry_endpoints`. A row is identified by a **three-part key**:

```
(product, api_version, name)   →   urn
```

`product` is the ADOM the entry belongs to, `api_version` is the registry's own
versioning bucket (so a future firmware API generation can live beside the
current one instead of replacing it), and `name` is the logical key that code
resolves. The key is unique; the catalogs never collide.

Rows also carry `enabled`, `updated_by` and `updated_at`, so the catalog is
auditable and every operator edit is attributable.

Because it is an ordinary table, the nightly database backup already contains
it — a restored database restores your endpoint edits with it.

### 1.3 The three catalogs

| Product | `api_version` | Transport | Seed file | Entries |
|---|---|---|---|---|
| FortiWeb | `v2.0` | REST, `/api/v2.0/…` | `endpoints.yaml` | 507 |
| FortiADC | `v1` | REST, `/api/<object>` | `endpoints_fortiadc.yaml` | 255 |
| FortiAnalyzer | `jsonrpc` | JSON-RPC, `POST /jsonrpc` | `endpoints_fortianalyzer.yaml` | 64 |

826 entries seeded in total. Counts are what the shipped seeds contain; the
live catalog is whatever your administrators have made of it — on the reference
installation 11 FortiADC entries are disabled, so 815 are active.

The FortiADC URNs are derived from the appliance's own CLI object tree, which
makes them predictable: `config load-balance virtual-server` becomes
`/api/load_balance_virtual_server`.

### 1.4 Reads: database first, file as the floor

A lookup asks the database first and falls back to the YAML seed shipped in the
repository. That fallback is not a nicety — it is what lets standalone scripts,
first-boot code and a tree with no database at all still resolve endpoint names
instead of crashing.

Reads are cached per worker process for **60 seconds**. An edit invalidates the
cache of the worker that served it immediately; the other workers converge
within that window. If a change you just made does not appear in another tab,
wait a minute before concluding it did not save.

### 1.5 Writes: the seed never overwrites you

Two rules protect operator edits, and they are the reason this design survives
upgrades:

- **Seeding is INSERT-ONLY.** On every boot, names present in the seed file but
  missing from the database are added. A name that already exists is *never*
  touched — enabled or disabled, edited or not. Your correction outlives every
  deployment.
- **Deletion is a SOFT delete.** Disabling sets `enabled = false` and keeps the
  row. If the row were removed, the next boot would helpfully resurrect it from
  the seed file, and the endpoint you deliberately retired would come back on
  its own.

Disabled rows stay visible in the editor precisely so they can be restored.

---

## 2. The three consoles

Each product's API area is one page fusing two halves:

- **left — the catalog**, browsed as that product's own menu, with
  New / Edit / Disable controls for administrators;
- **right — a live console**: pick a device, pick a verb, pick a logical
  endpoint (or type a raw path), optionally supply a JSON body, execute, read
  the raw response.

The catalogs are product-scoped, so work in one never touches another.

### 2.1 FortiWeb — `/web/api-explorer/`

REST over `/api/v2.0/…` with ordinary HTTP methods. The catalog tree is grouped
into the sections the appliance itself uses:

> Dashboard / Monitor · System · Network · Server Policy · Server Objects ·
> Application Delivery · Web Protection · API Protection · Bot Mitigation ·
> DoS Protection · IP Protection · Machine Learning · Tracking ·
> User & Authentication · Log & Report · Other

The method selector is a display heuristic, not a permission: configuration
(`cmdb`) objects offer `GET`/`POST`/`PUT`/`DELETE`, everything else offers
`GET`. What you are actually *allowed* to send is decided by your permissions
(§3), not by the dropdown.

The older standalone Registry page was folded into this one. Existing links to
it still resolve — they redirect here.

### 2.2 FortiADC — `/adc/api/`

The same page scoped to FortiADC. The transport difference worth knowing:
**FortiADC REST paths carry no version segment** — they are `/api/<object>`.
The catalog is browsed as the FortiADC menu.

### 2.3 FortiAnalyzer — `/faz/api/`

FortiAnalyzer does not expose a REST tree at all. **Every call is a `POST` to a
single `/jsonrpc` endpoint**, so the console asks for a JSON-RPC *verb* instead
of an HTTP method:

```
get · exec · add · set · update · delete
```

`get` reads; the other five mutate.

There is a second trap the console handles for you. FortiAnalyzer speaks **two
JSON-RPC dialects**, and picking the wrong one is rejected outright:

| Dialect | URL families | Envelope |
|---|---|---|
| legacy | `/sys` `/cli` `/dvmdb` `/task` `/um` `/pm` | classic request envelope |
| apiver 3 | `/logview` `/eventmgmt` `/incidentmgmt` `/report` `/fortiview` `/fazsys` | additionally requires `"jsonrpc": "2.0"` and `"apiver": 3` |

The client selects the dialect from the URL family. Sending an apiver-3 family
call with the legacy envelope fails with a protocol error, not an empty result —
which is why hand-rolling these calls elsewhere is rarely worth it.

The console also refuses a device of the wrong kind: a FortiAnalyzer verb
against a non-FortiAnalyzer is rejected before anything leaves the platform.

### 2.4 At a glance

| | FortiWeb | FortiADC | FortiAnalyzer |
|---|---|---|---|
| Page | `/web/api-explorer/` | `/adc/api/` | `/faz/api/` |
| Transport | REST `/api/v2.0/…` | REST `/api/…` | JSON-RPC `POST /jsonrpc` |
| Verbs | HTTP methods | HTTP methods | `get`/`exec`/`add`/`set`/`update`/`delete` |
| Read verb | `GET` | `GET` | `get` |
| Raw path escape | `/api/v2.0/…` | `/api/…` | any `/…` JSON-RPC url |

---

## 3. Permissions, and what is actually gated

Four distinct permissions govern this area. They are separate on purpose:
browsing the catalog, editing the catalog and firing a write at a live appliance
are three different amounts of trust.

| Permission | Grants |
|---|---|
| `registry.view` | Browse the catalog and the console |
| `registry.edit` | Create, edit and disable catalog entries |
| `registry.execute_write` | Send `POST`/`PUT`/`DELETE`/`PATCH` — or any non-`get` JSON-RPC verb — at a device |
| `registry_edit` (role permission) | The role-level capability that unlocks the editor; held by administrators |

Two rules follow from that table and are worth stating plainly:

- **Reads are always allowed** to anyone who can open the page. `GET` and `get`
  need nothing beyond access.
- **`registry.execute_write` is not scoped to one endpoint or one device.** It
  authorises every mutating call the console can make, on every device visible
  in that ADOM. Grant it like the administrative credential it is.

**Every execution is written to the audit log** — who, which device, which verb,
which endpoint. Catalog edits are audited too. The console is a power tool, and
it keeps receipts.

---

## 4. ADOM scoping

The device list in a console is never the whole fleet: it is the devices visible
in the ADOM the request is running in. A console cannot reach a device belonging
to another product.

Opening a product's API page is an explicit **ADOM jump for that browser tab** —
the URL declares the product, so following a link into a console switches that
tab's context to that product and leaves your other tabs alone. Conversely, from
a concrete product ADOM, another product's pages bounce you back to your own
area.

---

## 5. Recipes

### 5.1 A firmware upgrade moved a URI

This is the case the whole design exists for.

1. Open the product's API page.
2. Find the logical name in the catalog tree — the symptom is usually a feature
   that started returning nothing after the upgrade.
3. **Edit** the entry and correct the URN.
4. Verify immediately in the console on the right: same name, `GET`/`get`,
   execute, read the response.

The fix is live for the worker that served it at once and everywhere else within
the cache window. Nothing is deployed and nothing restarts. The edit survives
the next upgrade because seeding never overwrites an existing name.

### 5.2 Add an endpoint the catalog does not have

Use **New** on the same page: give it a logical name and the URN. Names accept
letters, digits, `_`, `.` and `-`. It is immediately resolvable by both the
console and the rest of the platform.

### 5.3 Restore an endpoint someone disabled

Disabled entries are listed separately in the editor — restoring one is a
toggle. That list exists exactly because the boot seeder will not bring the
entry back for you.

### 5.4 Call something that is not in the catalog at all

Both halves accept a **raw path** typed straight into the console: a
`/api/v2.0/…` or `/api/…` path, or a JSON-RPC url. Nothing is added to the
catalog. This is the right tool for a one-off probe — if you find yourself
typing the same raw path twice, make it an entry.

---

## 6. Limits & gotchas

- **A "not found" is usually the truth.** The catalog is a cross-firmware
  superset; an endpoint your firmware does not implement is a correct empty
  answer, not a defect.
- **Sixty seconds of eventual consistency.** After an edit, other worker
  processes converge within the cache window. Do not diagnose a save failure
  faster than that.
- **A device presenting a self-signed certificate must be registered with
  certificate verification disabled.** Otherwise every call dies during the TLS
  handshake, *before* authentication — the device shows as never having
  synchronised, with no useful error. This is the first thing to check when a
  newly added appliance never works at all.
- **A licensing block hits the configuration API, not the whole device.** An
  unlicensed appliance can reject every configuration read while still answering
  status and telemetry calls normally. Reachability therefore proves very little:
  the console will tell you which half is refusing you.
- **The console is not an approval path.** Configuration changes that should be
  reviewed belong in the platform's own change and template workflows. Use the
  console to inspect, to probe, and to repair the catalog.
