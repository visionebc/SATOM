# FortiGate — the read-only ADOM (base)

> **Since:** SATOM 3.0.0. This is the **base** of the FortiGate workspace: it
> reads a FortiGate live over the FortiOS REST API and writes nothing. Editors,
> an API console and registry binding are later rounds on top of the same shell.
> Measured against a FortiGate-VM running FortiOS **8.0.1 build0245**.

## 1. What it is

The `/fgt/` ADOM is SATOM's sixth workspace (user guide §3 and §17.4). It gives
an operator who knows the FortiOS GUI the same top-level menu, and every pane
behind it is a **read-only table read live from the selected FortiGate**:

- a **dashboard** with the device picker, the live unit status (hostname,
  firmware, build, serial, model, log disk) and a map of every section;
- **30 section pages** in **7 areas** that follow the FortiOS 8.0 menu —
  Network, Policy & Objects, Security Profiles, VPN, User & Authentication,
  System, Log & Report — covering **43 cmdb tables**, one tab per table;
- the shared, product-scoped pages every ADOM has: Appliances, Jobs,
  Notifications, Audit log, Monitoring, Metrics, Search, Architecture,
  Analysis, Change requests, Scheduled actions, Process, API tokens, the
  Release Notes modal, and the API library pages **Build compatibility** and
  **Schema builds**.

SATOM is still not a firewall manager: nothing in this ADOM changes a
FortiGate.

## 2. Registering a FortiGate

Administrator → **Appliances** → *Add appliance*, kind **`fortigate`**:

| Field | What to enter |
|---|---|
| Host / port | the FortiGate's management address and HTTPS port (default 443) |
| Username | informational only: the REST API user's name |
| Password | a **REST API administrator token** (`execute api-user generate-key <api-user>` on the FortiGate), **not** a login password. FortiOS 8.0 refuses password logins on the REST API |
| ADOM (vdom, optional) | the FortiGate VDOM; when set, every read carries `?vdom=<name>` |
| TLS verification | as for any appliance: import the FortiGate's CA under Settings → Trust store, or turn verification off for that device |

The token is stored encrypted in the same column as the other products'
credentials. A **read-only admin profile** on the FortiGate is enough and is
the recommended choice: the ADOM only ever sends `GET`.

> **Licence.** A FortiGate-VM **without a valid licence** answers `401` to every
> REST call except `license/status`. SATOM's error text says so, because "wrong
> token" and "no licence" look identical on the wire.

## 3. Using it

1. Open the **FortiGate** workspace from the product selector.
2. On the dashboard, **Select** the FortiGate to work with (one slot per ADOM,
   per browser tab — user guide §3.1). With exactly one FortiGate registered it
   is selected for you.
3. Open any section from the sidebar or the dashboard map. Each tab is one cmdb
   read, shown as a table (a single-instance setting is shown as key/value).

What every section page guarantees:

- **A refusal is never an empty table.** A `401`, `403`, `404` or any other
  device error is shown as an error with the device's reason. An empty table
  says *"The device answered successfully with zero objects — this is not an
  error."*
- **Secrets are never shown.** Fields named like a password, pre-shared key,
  private key or secret, and every value FortiOS returns as `ENC …`, are
  dropped before the row reaches the page.
- **Bounded.** A table shows at most 500 rows and says so when it truncated.
  The first columns are the identity fields (`name`, `policyid`, `seq-num`,
  `id`); the full row is in the *raw* expander.

| Area | Sections (cmdb tables) |
|---|---|
| Network | Interfaces (`system/interface`, `system/zone`), DNS, Routing (static and policy routes), SD-WAN, DHCP servers |
| Policy & Objects | Firewall Policy, Addresses (IPv4, IPv6, groups), Services (custom, groups), Schedules, Virtual IPs, IP Pools, Traffic Shaping |
| Security Profiles | AntiVirus, Web Filter, DNS Filter, Application Control, Intrusion Prevention, SSL/SSH Inspection |
| VPN | IPsec Tunnels (phase 1 and phase 2 interface mode), SSL-VPN Settings |
| User & Authentication | User Definition, User Groups, Authentication Servers (LDAP, RADIUS), Authentication Settings |
| System | Settings (global, VDOM settings, NTP), Administrators (admins, REST API users, admin profiles), HA, SNMP, Certificates (local, CA) |
| Log & Report | Log Settings (log settings, syslog) |

> **An empty Administrators tab is the profile, not the device.** A token whose
> admin profile is read-only is served **no administrators at all**
> (`system/admin` answers 0 rows even though an admin exists).

## 4. How FortiOS answers (what shaped the client)

- Every answer, success or error, carries `version`, `build` and `serial`, so
  the build of the box is known from any call.
- An unknown cmdb path answers **400**, not `200` with the parent's rows the way
  FortiWeb does: on a FortiGate a `200` really means "served".
- A read-only admin profile reads cmdb and monitor **per table**, but the global
  schema index (`/api/v2/cmdb/?action=schema` with no table) answers `403`.

| Device answer | What SATOM shows |
|---|---|
| `401` | the token was refused, or the FortiGate-VM has no valid licence |
| `403` | the token authenticated but its admin profile does not grant this table, or the source address is not a trusted host of that API user |
| `404` | no such resource on this firmware |
| other `4xx`/`5xx` | `HTTP <code>` with the device's summary |

## 5. FortiGate in the API library

The FortiGate schema (the CLI `tree` and the per-table REST
`?action=schema`) is part of the API library like any other product's, with a
FortiGate adapter verified on 8.0.1 build0245 ([API library](api-library.md)
§14.10). The ADOM itself does not harvest it: FortiGate evidence arrives in the
knowledge packs (or `flask apilib schema-import`), and the **Build
compatibility** and **Schema builds** pages read it from the FortiGate sidebar.
FortiGate vendor release notes arrive in the same packs and are shown by the
Release Notes modal of this ADOM ([release notes](release_notes.md)).

## 6. What is not there yet

| Not in the base ADOM | Why |
|---|---|
| Any write (object editor, raw JSON, policy changes) | read-only by design in this round; the client refuses every verb but `GET` |
| API console / endpoint registry binding | section paths are literal; a rename after an upgrade is not yet a Registry edit |
| Backups, restore, firmware upgrade, templates, Lua | no FortiGate transport exists in those features; the workspace does not offer them |
| Migration report | needs a stored `show full-configuration` dump, and no FortiGate backup is stored yet |
| HA status | not read; the HA tab shows the HA settings table only |
| The whole FortiOS GUI | only the panes an operator opens first; the full table list per build is in the API library |
| Monitoring kinds for FortiGate, Thresholds scope | the shared monitoring pages are reachable, but no FortiGate-specific probe or threshold scope exists yet |

## 7. Troubleshooting

### "401 unauthorized — the API token was refused, or the FortiGate-VM has no valid licence"

**Possible causes:** the token in the password field is wrong or was
regenerated; the password field holds a login password; the VM is unlicensed.

**Solution:** generate a new key for the REST API user on the FortiGate and
store it as the appliance password; license the VM.

**Verification:** the dashboard's *Unit status* card shows hostname, firmware
and build.

### "403 forbidden — the token authenticated but its admin profile does not grant this resource"

**Possible causes:** the API user's admin profile lacks read access to that
area, or SATOM's address is not in the API user's trusted hosts.

**Solution:** grant read access to the area in the profile, or add SATOM's
address as a trusted host.

### "404 — no such resource on this firmware"

The table does not exist on the FortiOS build the device runs. Compare builds
on **Build compatibility**.

### The dashboard says "The device refused the status read."

The first read of the dashboard failed; the message under it is the device's
reason (see the three entries above). The section pages still render, each with
its own error.
