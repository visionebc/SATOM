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
