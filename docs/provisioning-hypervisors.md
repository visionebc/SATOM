# Hypervisor provisioning — building appliances from nothing

SATOM can create the virtual machine an appliance runs on, not just configure
one that already exists. This document covers the machine half: the hypervisor
backends, what each one can and cannot do, the firmware split that feeds it,
and the failure modes that shaped the design.

The *configuration* half — System Profiles applied to a reachable appliance —
is unchanged and documented separately; provisioning hands off to it.

---

## 1. Why the capability probe is the centre of this feature

Every backend is asked what it can actually do **against the live endpoint**,
and the answer is reported rather than assumed. That is not defensive
programming for its own sake. Three real constraints, all found by running the
code against real hardware rather than by reading vendor documentation:

| constraint | consequence |
|---|---|
| A standalone ESXi host reports `apiType=HostAgent` and serves **no** vSphere Automation REST API (`/api` and `/rest` answer HTTP 400) | the ESXi backend speaks SOAP `/sdk`; REST-based code would look correct and fail on every standalone host |
| VMware's **free** licence (`esx.hypervisor.*`, "vSphere Hypervisor") makes the vSphere API **read-only** | inventory works; `CreateVM_Task` is refused by the host. The probe reports `create_vm=False` and names the licence |
| A Proxmox storage only accepts an appliance disk through the API if it advertises the `import` content type | without it `disk_import=False`, and the note tells the operator which storage setting unlocks it |

A capability record that optimistically claimed `create_vm=True` would let a
run reserve an address, create a DNS record, and only then die at the first
write — leaving three systems dirty and an error message that reads like a
SATOM bug. **Unknown state is never treated as permission**: if the licence
cannot be read, writes are reported unavailable.

---

## 2. Backends

Both clients are plain HTTPS against a documented API. Neither adds a Python
dependency, deliberately: this product ships offline bundles for air-gapped
management networks, and this repository has four recorded incidents of
something that did not travel in the bundle (`sudo` and `openssh-*` in 1.1,
`docs/safeguards.md` in 1.2/1.2.1, `lego` in the RHEL bundle, `git` in the
SUSE one). `proxmoxer` and `pyVmomi` would each require a rebuild of three
bundles and a new entry in the curated pip allowlist to buy a thin wrapper
over JSON and XML we can write directly.

### 2.1 Proxmox VE — `app/services/hypervisors/proxmox.py`

Plain JSON over `/api2/json`. Authentication supports both forms Proxmox
offers: an **API token** (`user@realm!tokenid` + secret, preferred — no
session, no expiry, scopeable below root) and a **ticket** (username +
password, what an operator can configure without touching the hypervisor
first, so it is the Settings default). Writes carry `CSRFPreventionToken`;
without it Proxmox answers "401 no ticket", which points at authentication
rather than at the missing header.

Verified end to end against a live host: create → power on → power off →
delete → delete again (idempotent).

Two things the live round-trip taught that the code did not say:

* **`?type=any` is not a valid network filter.** Proxmox answers a bare HTTP
  400 and the accepted set differs across releases. The client asks for the
  whole interface list and filters client-side — version-proof, one small
  response.
* **`destroy-unreferenced-disks=1` makes the destroy scan every configured
  storage**, so a single offline one (an unmounted NFS/CIFS share) aborts it
  half-way and leaves a zombie guest: config file present, disks gone. The
  flag is deliberately not set. The VM's own disks are removed either way.
  This was reproduced live and left two zombies before it was found.

Appliance disks are attached with `import-from` at creation time, with size
`0` so the size comes from the source image — an explicit size silently
truncates a larger appliance disk.

### 2.2 VMware ESXi — `app/services/hypervisors/esxi.py`

vSphere SOAP over `/sdk`, parsed with the standard library. Sessions, the
PropertyCollector, container views and managed-object resolution are all
implemented directly; the well-known standalone identifiers (`ha-root-pool`,
`ha-folder-vm`, `ha-host`) are **resolved live**, not hardcoded.

Read operations are verified against a live ESXi 8.0.3 host: datastores,
networks, virtual machines, resource pool, VM folder, host system, licence.

**Write operations are blocked on that host by its licence** (see §1). The
client implements them, the capability probe reports them unavailable, and the
UI must hide the entry point rather than show a button that errors — a control
the operator cannot action is worse than no control.

**The disk-format constraint.** Fortinet ships ESXi appliances as an OVF plus
`streamOptimized` VMDKs, which cannot be attached to a VM as-is. The usual
conversion tool is `vmkfstools` over SSH, and SSH is closed on the target host.
The remaining supported path is `OvfManager.CreateImportSpec` → `ImportVApp` →
`HttpNfcLease`, where ESXi converts the disk as it streams in. That is why the
ESXi path is an OVF import rather than a datastore upload plus attach.

---

## 3. Firmware: install images and upgrade images are different artefacts

Fortinet publishes **two** files per release and they are not interchangeable:

* an **upgrade** image (`.out`) applied to a running appliance, and
* an **install** image (`.zip` of an OVF + VMDKs, or a `.qcow2`) used to build
  a machine from nothing.

Before this change the firmware repository modelled only the first: a single
`.out` allow-list meant the page was structurally unable to hold install
media. `FirmwareImage` now carries `image_kind` (`upgrade` | `install`,
defaulting to `upgrade` because every pre-existing row is one) and, for
install images, `hypervisor` (`kvm` | `vmware`). Accepted extensions follow
the kind, in **both** upload paths — the multipart one and the resumable
chunked one, which had two independent copies of the same hardcoded check.

Offering the wrong artefact is not a validation nicety. An operator who picks
an upgrade file to build a new VM learns about it from a machine that will not
boot.

### 3.1 Every ADOM, and only its own images

The firmware page is now reachable from **all** product ADOMs. It previously
sat in the FortiAnalyzer set only, which is why a FortiAnalyzer session could
see FortiWeb images, and FortiADC and FortiAuthenticator sessions could not
reach the page at all.

Two rules, both enforced on the **route**, not in the template:

* **The list is filtered in the query.** A row hidden by a template is still a
  row the page fetched, and the JSON callers would keep leaking it.
* **The ADOM overrules the form.** The product selector is not rendered inside
  a concrete ADOM, and the POST handler re-derives the product from the
  request scope in both upload endpoints. A hand-crafted POST would otherwise
  file a FortiWeb image under FortiADC. Same rule as `ProvisionRun.product`:
  scope comes from the request, never from a field the client controls.

Global sees everything, as it does everywhere else.

---

## 4. The run state machine

An end-to-end provision touches five systems that fail independently: IPAM,
DNS, the hypervisor, the appliance itself, and the certificate authority. A
single function that dies in the middle leaves a reserved address, a DNS
record and a half-built VM that nobody cleans up, and the operator cannot tell
which of those actually happened.

`ProvisionRun` records the pipeline explicitly:

```
draft → ip_reserved → dns_created → vm_created → image_attached
      → booted → reachable → onboarded → cert_installed
      → profile_applied → done
```

Each step stores enough to be undone, and rollback retraces them in reverse.
Appending a step is safe; reordering is not — the index in `STEPS` is what
"how far did it get" means, so existing rows would claim the wrong progress.

`ip_from_ipam` exists because **a user-typed address is not ours to release**.
Rollback frees an address only when SATOM allocated it.

### 4.1 Modes — the operator chooses how far unattended goes

The product cannot promise unattended first boot everywhere. A factory
Fortinet VM boots to `admin` with an empty password and a forced change
dialog; the REST API does not exist until that dialog is completed, and
sending commands at it blindly turns them into failed logins against an
`admin-lockout-threshold` of 3. Proxmox exposes the serial port over the API
(`termproxy`), so the dialog can be walked; a standalone ESXi does not.

| mode | what it does |
|---|---|
| `full` | create, boot, configure and onboard without stopping |
| `semi` | create and boot, then stop for the first-boot console; resume once the appliance answers |
| `dhcp` | create and boot; the appliance takes a lease and SATOM finds it, then continues |
| `vm_only` | create the machine and stop |
| `config_only` | the machine exists already — reserve the address, issue the certificate, apply the profile |

`semi` is the mode that always works. `full` is offered only where the
capability probe says the serial console is reachable.

### 4.2 Addressing

IPAM is used **only** when a provider is configured *and* the operator turns it
on for that run. Otherwise the address is typed in. A provisioning flow that
hard-required an IPAM would be unusable on every site that does not run one.

---

## 5. Credentials

Hypervisor targets live in `hypervisor_targets` (a table, not an
`app_settings` key, because a site may run several Proxmox and several ESXi
hosts). Passwords and API token secrets are Fernet-encrypted in the same
pattern as `Appliance.password_enc`, and `HypervisorTarget.public()` is the
only shape handed to the browser — secrets never cross that boundary.

`verify_ssl` defaults off because hypervisors ship self-signed certificates,
but it stays a per-target setting rather than a hardcoded `False`, so a site
that imported its CA into the SATOM trust store can turn it on and have it
mean something.

---

## 6. Verifying the backends are wired

```bash
# Both clients, live, from the node:
satom diagnose all                       # includes hypervisor reachability
```

From a shell with the app context, the honest smoke test is the round-trip:
create a throwaway VM, power it on, power it off, delete it, and delete it
again — the second delete must succeed, because rollback runs against
machines that may already be gone.

Watch for the two traps the live run exposed:

* a `delete` that does not **wait for the task** reports success while the VM
  is still in the inventory, so a rollback claims to have cleaned up and a
  retry collides with a vmid that is not free yet;
* a capability record that was never probed against the endpoint will happily
  advertise writes on a read-only licence.

## 7. Choosing a mode — advantages and disadvantages

A factory Fortinet appliance boots into a first-boot dialog: `admin` with an
empty password and a forced change. Nothing can reach its API until that dialog
is completed. So "fully automatic" turns entirely on one question — **does the
hypervisor expose a scriptable serial console?** Proxmox does (`termproxy`); a
standalone ESXi does not, at any licence tier. Every mode below is a different
answer to that fact.

| Mode | What it does | Advantages | Disadvantages |
|---|---|---|---|
| **full** | Address, DNS, machine, boot, walks the first-boot dialog over the serial console, registers the appliance, hands off to the configuration profile. | No human step. Repeatable and auditable end to end; every action lands in the run log. | **Proxmox only** — needs an API serial console. Most moving parts, so the widest surface for a mid-run failure; this is what rollback exists for. |
| **semi** | Builds and boots, then stops. The operator completes the first-boot dialog on the hypervisor console and resumes. | Works on **every** backend, including a free-licensed ESXi. The one manual step is the one a human is genuinely required for. | Not unattended — a run waits until somebody acts on it. |
| **dhcp** | Builds and boots; the appliance takes a lease and SATOM finds it there. | Unattended without a serial console. | Needs DHCP reachable from the machine's network, and the address is not the one you chose. Not every appliance takes a lease on its factory configuration. |
| **vm_only** | Creates and powers on the machine. Stops. | Smallest blast radius. Right when the appliance is configured by another team or tool. | No address, no DNS, no registration — nothing else in SATOM knows the machine exists. |
| **config_only** | Skips machine creation: address, DNS, registration and profile against a machine that already exists. | Needs **no hypervisor at all**. The path for physical appliances and anything built outside SATOM. | You built the machine, so its CPU, memory, disk and network are outside the run log and outside the audit trail. |

`MODE_STEPS` in `app/services/provision_runner.py` is the single source for
these plans, and the UI renders the plan from it before anything runs. Adding a
mode is one dict entry, not an `if` inside the loop.

**Stopping is not failing.** `semi` and `vm_only` are *designed* to stop; the
run lands in `paused` with its reason in `MODE_STOP_REASON` and the operator
resumes it. Marking a deliberate handoff as `failed` teaches people to ignore
the status column, and then they ignore the real failures too.

## 8. The ESXi host-shell transport

The free `esx.hypervisor.*` licence gates the **remote VIM API write methods**
— `CreateVM_Task`, `PowerOnVM_Task`, `ImportVApp` — while every read keeps
working. The host's own shell (`vim-cmd`, `vmkfstools`, `esxcli`) is a
different code path inside ESXi and is not gated the same way. Give a target
SSH credentials and `app/services/hypervisors/esxi_shell.py` becomes a second
write path.

| | API transport | Shell transport |
|---|---|---|
| Needs | nothing extra | `TSM-SSH` running on the host |
| Create / power / delete | licence-gated | `vim-cmd` |
| Attach a disk | `ImportVApp` (OVF only) | `vmkfstools -i` converts anything |
| Advantage | no extra service, no extra credential | works on a free licence |
| Disadvantage | unusable on a free licence | a permanent remote-root path on the hypervisor; the operator owns that decision |

Three things the transport refuses to do, and why:

1. **It never enables SSH itself.** Turning on `TSM-SSH` is a durable change to
   the security posture of someone else's hypervisor. SATOM detects the state
   and prints the one line to run. A capability probe that silently opens a
   root shell to make its own feature work is the definition of a surprise.
2. **It never claims the shell until a command has actually run on it.**
   `EsxiShell.probe()` runs `vmware -v`. A flag set from "the port looks open"
   would promise a pipeline that dies three steps later, after an address and a
   DNS row were already committed.
3. **It never interpolates operator input into a shell string.** Every value is
   `shlex.quote`d and names are validated against `SAFE_NAME`. A VM called
   `foo; rm -rf /vmfs` is rejected at the boundary, not escaped halfway down.
   Commands are restricted to `ALLOWED_BINARIES`.

**Honest status:** this path is [Probable], not [Verified], on the fleet host it
was written against — `TSM-SSH` is `policy=off` there, so it has not been
exercised end to end. `capabilities()` reports exactly that rather than
assuming success.

Even with the shell, **`full` stays unavailable on ESXi**: the only console is
graphical (MKS), and a network serial port would itself be a config write. The
ceiling on ESXi is `semi`.

## 9. Two Proxmox storage roles that are not the same role

Proxmox splits these across **different** storages, and nothing requires one
storage to do both:

* `images` — can hold a running VM disk (`can_disk`)
* `import` — can receive an uploaded appliance image (`can_import`)

On the fleet host the stock `local` storage carries `import` **without**
`images`, while every LVM-thin pool carries `images` without `import`.

`list_datastores()` originally filtered on `images` first and only then looked
at `import`, so `local` was dropped before its import flag was ever read — and
the capability probe told the operator to "add import to a storage" on a host
that already had one. **Never narrow a list by one role while reporting on
another.** `disk_datastores()` and `import_datastores()` now name the two
questions separately, and the Test button prints both.

## 10. `/cluster/resources` is a cache

`list_vms()` used `/cluster/resources?type=vm`, an aggregate refreshed on
`pvestatd`'s cycle. Verified: a machine SATOM had just created and powered on
was **absent** from it, while the rollback that followed deleted the same
machine without trouble. On a provisioning page that reads as "the machine was
not created", which is the opposite of the truth.

With a node in hand, `/nodes/<node>/qemu` answers from that node's own state and
shows the machine immediately. The cached aggregate is kept only for the
node-less, whole-cluster view, where it is the single-call option.

Two more Proxmox behaviours worth keeping in mind:

* `DELETE` returns a UPID. Without waiting on the task, rollback reports
  "deleted" while the machine is still in the inventory, and a retry collides
  with a vmid that is not free yet.
* `destroy-unreferenced-disks=1` makes Proxmox scan **every** storage, so one
  offline storage aborts the destroy halfway and leaves a guest with a config
  file and no disks. The flag stays off; the machine's own disks are removed
  regardless.

## 11. Rollback undoes only what the run recorded

Every arm is guarded by a **recorded fact**, never by looking at the world:

* an address is released only when `ip_from_ipam` says SATOM took it — a
  hand-typed address is not ours to hand back to a pool;
* a machine is deleted only when `vm_ref` says SATOM built it;
* an `Appliance` row created by the run is **left in place on purpose** and
  named in the log. By the time onboarding happened the device was answering,
  and deleting the record would orphan any harvest, snapshot or note already
  attached to it.

Inferring ownership from current state is how a rollback deletes somebody
else's machine.

## 12. Where the ADOM boundary is enforced

`ProvisionRun.product` is stamped from the request scope, never from a form
field: a run that could re-label its own ADOM would let a FortiADC session
build a FortiWeb and file it under FortiWeb. From the Global ADOM — which has
no single answer — the product is an explicit required choice.

Filtering happens on the **query** (`product_scope.scope_query`), not in the
template: a row hidden by a template is still a row the page fetched, and the
JSON feed would return it. A run belonging to another ADOM answers **404**, not
403 — from this ADOM it does not exist, and 403 would confirm that a run with
that id exists somewhere.

`device_provision` is deliberately **not** in `fortiweb_scoped`. Membership
there means "opening this from Global is an ADOM jump into FortiWeb", which is
right for `/workspace` and wrong for a page mirrored into every ADOM: it made
the Global ADOM silently become FortiWeb, so a Global operator saw only
FortiWeb runs and never got the product picker Global specifically needs.
`firmware`, `monitoring` and `metrics` are the precedent.

## 13. Do not mount a blueprint under `/provisioning`

The legacy-URL shim in `create_app` rewrites every path beginning with
`/provisioning` onto `/web/...` for the 2026-07-07 ADOM split. A blueprint
mounted at `/provisioning/device` was rewritten to `/web/provisioning/device`,
which matches no route — a 404 in Global and FortiWeb and a gate redirect
elsewhere, with the blueprint registered correctly the whole time. Device
provisioning lives at `/device-provisioning` for that reason.

## 14. Verifying the guards are armed

```sh
# The two storage roles are asked separately, not conflated.
grep -n "can_disk\|can_import" app/services/hypervisors/proxmox.py

# The shell is only claimed after a command ran.
grep -n "def probe" -A6 app/services/hypervisors/esxi_shell.py

# The uniqueness check runs BEFORE the row joins the session (autoflush).
grep -n "clash = HypervisorTarget" -B4 app/views/settings.py

# Device provisioning is not a FortiWeb area.
grep -c "device_provision" <<< "$(sed -n '/fortiweb_scoped = {/,/}/p' app/__init__.py)"   # -> 0

# Every ADOM reaches it and sees only its own rows.
for a in global fortiweb fortiadc fortianalyzer fortiauthenticator; do
  curl -sk -H "X-ADOM: $a" "https://<node>/device-provisioning/data?_adom=$a" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["scope"], len(d["runs"]))'
done
```
