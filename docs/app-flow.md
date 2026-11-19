# App flow — journeys, screens and navigation

> Also in the Documentation Center as `app-flow`. Links of the form `[text](slug)` point at Documentation Center articles; `:::` blocks are Documentation Center callouts. When this changes, both copies change in the same round.

This page is the map. It shows how you move through SATOM: where you land
after signing in, which menu holds which screens, and the path through each
everyday task. Each journey links to the article with the full detail. For a
tour of the screen itself (top bar, sidebar, footer), see
[Navigation](navigation).

## From sign-in to your first screen

:::flow
Open the console | https://satom.example.com — not signed in, you are sent to the sign-in page (/auth/login)
Sign In | Username and Password on one form, for local and directory (Active Directory, LDAP, RADIUS) accounts
Two-Factor Authentication | only if you set it up: Authentication code (or a backup code), then Verify
Landing page | the page you were sent from, or the Global home
Choose where to work | Switch Product, ‹ Global, or the ADOMs list in the Global sidebar
:::

**What decides the landing page.** SATOM checks the page that sent you to
sign in, which it remembers in the sign-in URL:

- If you were sent to sign in from a page of the console (an expired session
  or a bookmark, for example), you go back to that page once you are signed in.
  SATOM only goes back to an address on its own site, and never to **Sign Out**.
- Otherwise you land on `/`, the [Global home](global-home). Opening `/`
  always puts the browser tab in the Global ADOM.
- If you open `/auth/login` while you are already signed in, SATOM sends you to `/`.
- If the page belongs to a published app with its own sign-in page, you see
  that app's sign-in page instead of the console form (see
  [App sign-in](app-sign-in)).

**Entering an ADOM.** **Switch Product** (*Select the product you want to
manage* → **Open →**), **‹ Global** and the Global sidebar's **ADOMs** list
take you to the ADOM's home page:

| ADOM | Lands on | URL |
|---|---|---|
| Global | Global home | `/` |
| FortiWeb | The Server Policy list of the selected device; the **Service Diagram** when no device is selected | `/web/` |
| FortiADC, FortiAnalyzer, FortiAuthenticator, FortiGate | The ADOM's dashboard | `/adc/`, `/faz/`, `/fac/`, `/fgt/` |

If your profile does not include an ADOM, SATOM shows *"Your profile does not
include the <name> ADOM."* and opens Global instead. Sign-in details,
two-factor authentication and the session lock are covered in
[First login](first-login). How ADOMs keep data apart is in
[ADOMs and products](adoms-and-products).

## Screen map

The sidebar changes with the ADOM. In the Global ADOM the first block is
**Global**; in a device ADOM (FortiWeb, FortiADC, FortiAnalyzer,
FortiAuthenticator, FortiGate) it is **Operations**, followed by the device's
own menu. The groups below are the same in every ADOM. An entry appears only
when your profile can open the page behind it.

| Menu | Main screens | URL pattern | Permission |
|---|---|---|---|
| Top bar | Switch Product, Search, notifications bell, Profile, Sign Out | `/product/select`, `/search/`, `/notifications`, `/auth/profile`, `/auth/logout` | Signed in; Search needs any view permission |
| **Global** (Global ADOM) | Dashboard (Global home), Observability, Incidents, Search, Automation, Plugins, Jobs | `/`, `/observability/monitoring/`, `/incidents/`, `/jobs/manager` | Dashboard and Jobs: signed in; Observability: {{perm:observability.access}} plus a view permission; the others: a view permission such as {{perm:monitoring.view}}; Incidents: {{perm:operations.view}} |
| **ADOMs** (Global ADOM) | One link per product ADOM | `/product/enter/<adom>` | ADOMs included in your profile |
| **Operations** (device ADOMs) | The Global block's pages, plus Device Backups, Import Backup | `/web/backups/<id>`, `/web/import-backup/` | {{perm:backups.view}}; Import Backup: {{perm:backups.restore}} |
| Device menu (for example **FortiWeb**) | All pages, the device's own menu, Server Policy | `/web/workspace/<id>` | {{perm:protection.view}} to read; write access to change |
| **Observability › Monitoring** (the Observability area, dark theme, its own sidebar; one *Observability* entry in SATOM's menu) | Device health, Metrics, Analysis, Deep monitors, Service Monitor, Service checks, Dashboards, Reports (Scheduled / On-demand); SATOM health in Global only | `/observability/monitoring/` and its siblings; the old `/monitoring/`, `/metrics/`, `/analysis/` answer 308 there | {{perm:observability.access}} (operator and admin by default) plus a view permission; writing service checks also a configuration-write key and {{perm:monitoring.probe_free}} |
| **Automation** (in Global or Operations) | Scheduler, Upgrade Flow, Migration Report, Change Requests, Certificate Manager, Mass Deploy | `/web/automations/`, `/web/upgrade-flow/`, `/web/change-requests/` | Write access (for example {{perm:operations.apply}}); Upgrade Flow: {{perm:backups.create}} or {{perm:backups.restore}}; Change Requests: {{perm:users.manage}} |
| **Plugins** (in Global or Operations) | Published Plugin Studio apps, Report Studio, Lua Studio | `/apps/<app>` | Each app: the ADOMs and users ticked in its **Settings** |
| **Plugin Studio** | Apps, Data stores, Connections, API Catalog, console | `/studio/` | {{perm:studio.script_library}} or {{perm:studio.python_console}} |
| **Diagrams** (every ADOM) | Diagram Studio, Architecture (*Live*), Service Diagram (*Live*), the published diagrams in folders | `/diagram-studio/`, `/net-architecture/`, `/architecture/`, `/diagrams/<id>` | Diagram Studio and published diagrams: {{perm:diagrams.view}}; Architecture and Service Diagram: a view permission such as {{perm:monitoring.view}}, as before |
| **Administrator** | Access (API Tokens, Audit Log, Groups, Users) · API · Devices (Appliances, Firmware, Device Provisioning…) · Objects · System | `/appliances/`, `/users/`, `/audit/`, `/web/firmware/` | {{perm:users.manage}} for the group; each entry also has its own permission (Audit Log: {{perm:audit.view}}) |
| Foot of the sidebar | Settings (administrators); a read-only Users list for {{perm:users.view}} holders | `/settings/`, `/users/` | {{perm:users.manage}} / {{perm:users.view}} |

The complete, ADOM-by-ADOM entry list (and which entries are greyed out for
which product) is in [Navigation](navigation#the-sidebar). To find a page by
what it does instead, use the [Concept Map](concept-map) in the footer.

:::note
In the FortiWeb ADOM, a per-device page (for example **Device Backups** or the
Server Policy list) opened with no device selected sends you to the
**Service Diagram** so you can pick one first.
:::

## Core journeys

Every journey below uses `fweb-01` as the appliance. Labels are the ones on
screen.

### Register a device

:::flow
Open Appliances | Administrator → Appliances; without the administrator capability, Appliances is in Operations (Global block in Global)
Add Appliance | Name, Kind, Host / IP, Port, Username, Password, optional Zone, Line, Department
Add Appliance (submit) | "Appliance fweb-01 created." and the appliance page opens
Test Connection | Connection OK, or Connection failed: <reason>; correct it with Edit
Discovery | Start discovery; SATOM reads the configuration into its own copy, nothing is written
Select it | top bar device area → Switch device → fweb-01
:::

Needs {{perm:appliances.view}} to open, write access such as
{{perm:appliances.edit}} to create, and {{perm:appliances.apply}} to discover.
Detail: [Appliances](appliances), [Rediscovery](rediscovery),
[Quick start](quick-start).

### Take and restore a backup

:::flow
Device Backups | FortiWeb ADOM → Operations → Device Backups (or View Backups on the appliance page)
Create Backup | transport Auto (REST → SSH) by default; Create First Backup on an empty vault
Track it | the flash points to the Jobs dock; the bell reports Backup ready: fweb-01
Restore | appliance page → Restore (administrators)
Dry run | choose the stored backup, keep Dry run ticked, Validate / Restore — nothing is sent
Live restore | untick Dry run, type fweb-01 to authorise, Validate / Restore
Verify | a job takes a pre-restore backup, uploads, waits for the reboot and reads the configuration back
:::

Detail: [Device backups](backups), [Configuration restore](config-restore).

### Change a FortiWeb server policy

Every change to a device follows the same guarded path: you see the change
before it is sent, SATOM checks it, writes it, reads it back and records it.

:::flow
Select the device | top bar → Switch device → fweb-01
Open the list | FortiWeb → Server Policy (FortiWeb → Policy → Server Policy when the build's GUI layout is imported)
Edit | double-click a row, press Enter, or Edit
Change and Save | changed fields are highlighted until you save
Review the change | every field shown as Was and New before anything is sent
Apply to fweb-01 | template lock, edit lease, reference check and build compatibility are checked first
Read-back | SATOM re-reads what it wrote and checks the device kept it
Audit | before and after recorded in the audit log; Enable, Disable, Delete, Clone run as a job
:::

SATOM's own policy view (used when no GUI layout is imported) names the
review step **Confirm change to the live device** and the button **Apply to
device**. Detail: [Server policies](server-policy).

### Upgrade firmware

For a maintenance window across several FortiWeb appliances:

:::flow
Upgrade Flow | FortiWeb ADOM → Operations → Automation → Upgrade Flow
Upgrade to | choose the destination version
Run pre-upgrade on selected | stage 1: config backup, health battery (SSH), service validation per appliance
Create draft | stage 2: one change request that cites the evidence of every appliance
Approve | stage 3: an administrator approves the change
Save as scheduled task | stage 4: rounds of N appliances inside the window
Follow execution | the execution page, appliance by appliance (/web/upgrade-flow/change/<id>)
:::

For one appliance, use the appliance page: **Upgrade Prep** → **Run
preparation** → **Raise change request**, then, once the change is approved,
**Upgrade** → **Validate / Accept** with **Dry run** ticked, then live. A
live upgrade outside an approved change is refused. Detail:
[Upgrade Flow](upgrade-flow), [Firmware upgrade](firmware-upgrade).

### Raise and approve a change request

:::flow
New Change Request | Automation → Change Requests → New Change Request
Type of change | Change type and Risk
Scope & window | Affected devices, Window start, Window end
Proposed wording | Title, Reason, Rollback plan, Approval (Manual or External)
Create draft | the change is saved as a draft
Approve | moves it to approved and records who and when
Schedule | binds a one-shot scheduled action at the window start
Close | the run closes the change with its outcome; a documentary change uses Mark completed or Mark failed
:::

Detail: [Change requests](change-requests).

### Respond to a monitoring alert

:::flow
Bell | the red counter shows unread notifications; alert notifications go to administrators
Open the entry | it opens the related page, or the notification on the Notifications page
How to resolve | What it means, Common causes, What to do, Related pages
Device health | Observability › Monitoring → Device health: each card names the failing signal; Open device
Open incident | Incidents (right below Monitoring) → New incident, to track the problem
Update | Add a note, Add a vendor / L3 ticket, set the status to Resolved when fixed
:::

Detail: [Notifications](notifications), [Device health](device-health),
[Incidents](incidents), [Alerting](alerting).

### Build and publish a Plugin Studio app

:::flow
New app | Plugin Studio → New app → Flow
Settings | Where it appears (ADOMs) and Who may use it, then Save settings
Form | Add field for each input, then Save form
Diagram | Add a step, join the steps, Save diagram, then Analyze
Test | tick Rehearsal, then Run the saved draft — nothing is written
Publish | clear Fix before publishing, then Publish
Use it | the app appears under Plugins for the chosen ADOMs and users (/apps/<app>)
:::

Detail: [Your first Plugin Studio app](plugin-studio-first-app).

### Create a profile and a user (administrators)

:::flow
Profiles | Settings → Access & Identity → Profiles → New Profile
Name it | Profile name, then Create & set permissions
Permissions | tick the permissions, then Save permissions
Users | Settings → Access & Identity → Users (or Administrator → Users) → Add User
Fill in | Username, Password (at least 12 characters), Confirm Password, Profile
Create User | "User <name> created." — the user's next request uses the profile
:::

Detail: [Users and profiles](users-and-profiles).

## How your role changes the flow

The three system profiles are {{role:viewer}} (`readonly`),
{{role:operator}} and {{role:admin}}. A custom profile can mix any permissions;
the table shows the system profiles.

| Journey | Viewer | Operator | Admin |
|---|---|---|---|
| Sidebar | Global or Operations, Monitoring, device menu, Jobs | Adds **Automation** (Scheduler, Upgrade Flow, Migration Report, provisioning) and Scout (when configured) | Adds **Administrator**, Change Requests, Certificate Manager, Calendar, Plugin Studio, Settings |
| Audit log | Readable at `/audit/`; no sidebar link | Readable at `/audit/`; no sidebar link | **Administrator → Audit Log** |
| Register a device | No | Yes | Yes |
| Backups | List the vault | Create, upload, download | Also restore |
| Change a policy | Read only | Yes | Yes |
| Upgrade firmware | No | Prep and dry run; a live upgrade needs an approved change | Raises, approves and schedules the change |
| Change requests | No | No | Yes |
| Plugin Studio | No | No | Yes; published apps go to whoever they are given to |
| Users and profiles | No | No | Yes |
| Jobs | Own jobs | Own jobs | Every user's jobs |

### What you see without a permission

- **The menu entry is not drawn.** The sidebar asks the same permission as the
  page, so a link never leads to a refusal.
- **Buttons are hidden.** For example a viewer sees no **Create Backup** in the
  vault, and the server policy view says *"Read-only: changing this policy
  needs the config_write permission."*
- **A direct URL answers 403.** The page *Access denied — You don't have
  permission to view this page.* offers **Return home**.
- **An ADOM outside your profile** sends you to Global with *"Your profile
  does not include the <name> ADOM."*
- **Another user's job**, or a change request outside your ADOM, answers
  *404* rather than revealing that it exists.
- **Signed out**, any page sends you to sign in with *"Please log in to access
  this page."*

A greyed-out entry with a slash icon is not about your permissions: the page
does not work for that ADOM's product. Hover it to read why. See
[Navigation](navigation#a-menu-entry-is-greyed-out) and
[Permissions](permissions).

## Where long operations go

Anything that talks to an appliance and takes longer than a moment becomes a
**job**. You never have to wait on the page.

| You started | It runs as | You get back to it from |
|---|---|---|
| A device action from a button (backup, bulk policy action, hardware scan) | A job with a toast in the Jobs dock that follows you across pages | **View job →** in the dock, or **Jobs** in the sidebar (`/jobs/manager`) |
| A device action from a form (restore, upgrade) | The wait page (`/jobs/<id>/wait`) | **Keep working — it continues in the background**, **Open in Jobs**, **Show result** |
| A finished or failed job, an alert | A notification | The bell, **View all notifications ›** (`/notifications`), **Open related page** |
| Any write | An audit entry | **Administrator → Audit Log**, or `/audit/` for any {{perm:audit.view}} holder; searchable by user, action and entry ID |
| A scheduled change | A scheduled action bound to the change request | **Automation → Scheduler**, the change request's page, the [Calendar](calendar) |
| A firmware flash | A before/after report | **Firmware Reports** on the appliance page |

Leaving a wait page stops nothing. Detail: [Jobs](jobs),
[Notifications](notifications), [Audit log](audit-log).

## Related

- [Navigation](navigation) — every element of the screen.
- [Concept Map](concept-map) — every page grouped by what it is for.
- [Core concepts](core-concepts) — ADOM, appliance, job, change request,
  profile.
