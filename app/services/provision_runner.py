"""Provisioning orchestrator — walks a :class:`ProvisionRun` through STEPS.

**Why a runner and not a function.** An end-to-end run touches five systems
that fail independently: the IPAM provider, DNS, the hypervisor, the appliance
itself and the certificate authority. A single function that dies halfway
leaves a reserved address, a DNS row and a half-built machine, and the
operator has no way to tell which of those actually happened. Here every step
records what it did before it does the next one, and :func:`rollback` retraces
exactly those — never more.

Three rules the whole module is built on:

1. **A step that cannot run is refused up front, not attempted.** Before any
   state changes, :func:`preflight` asks the backend what it can do and
   compares that with the mode the operator picked. A run that would die at
   ``CreateVM_Task`` after reserving an address is worse than one that never
   started.

2. **Rollback undoes only what THIS run created.** A user-typed address is not
   ours to release (``ip_from_ipam``); a machine SATOM did not create has no
   ``vm_ref`` and is never deleted. Undo is driven by recorded facts, not by
   inference from the current state of the world.

3. **Stopping is a normal outcome, not a failure.** ``semi`` and ``vm_only``
   are *designed* to stop; the run lands in ``paused`` with the exact reason
   and the operator resumes it. Marking a deliberate handoff as ``failed``
   teaches people to ignore the status field.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Callable

from ..extensions import db
from ..models_provision import STEPS, ProvisionRun
from .hypervisors import HypervisorError, VmRef, VmSpec

#: Steps each mode is allowed to perform. Anything past the last entry is a
#: deliberate stop, reported as ``paused`` with a reason the operator can act
#: on. Keeping this as data (rather than ``if mode == ...`` inside the loop)
#: means adding a mode is one dict entry, and the UI can render the plan
#: before anything runs.
MODE_STEPS: dict[str, tuple[str, ...]] = {
    "full": STEPS,
    "semi": ("draft", "ip_reserved", "dns_created", "vm_created",
             "image_attached", "booted"),
    "dhcp": ("draft", "dns_created", "vm_created", "image_attached", "booted",
             "reachable", "onboarded", "cert_installed", "profile_applied",
             "done"),
    "vm_only": ("draft", "vm_created", "image_attached", "booted"),
    "config_only": ("draft", "ip_reserved", "dns_created", "reachable",
                    "onboarded", "cert_installed", "profile_applied", "done"),
}

#: Why each mode stops where it does — printed verbatim when a run pauses, so
#: "why did it stop?" never needs a support round trip.
MODE_STOP_REASON = {
    "semi": "The machine is built and powered on. Complete the appliance "
            "first-boot dialog on the hypervisor console (set the admin "
            "password and the management address), then resume this run.",
    "vm_only": "The machine is built and powered on, as requested. Nothing "
               "further will be done automatically.",
    "full": "",
    "dhcp": "",
    "config_only": "",
}

#: Capabilities a mode needs from the hypervisor. Checked before the first
#: state change.
MODE_REQUIRES: dict[str, tuple[str, ...]] = {
    "full": ("create_vm", "power_control", "serial_console"),
    "semi": ("create_vm", "power_control"),
    "dhcp": ("create_vm", "power_control"),
    "vm_only": ("create_vm", "power_control"),
    "config_only": (),
}

CAP_LABEL = {
    "create_vm": "create virtual machines",
    "power_control": "power machines on and off",
    "serial_console": "drive the first-boot console unattended",
    "upload_image": "upload an appliance image",
}


class StepResult:
    """Outcome of one step. ``stop`` means a planned pause, not an error."""

    __slots__ = ("ok", "detail", "stop")

    def __init__(self, ok: bool, detail: str = "", stop: bool = False):
        self.ok, self.detail, self.stop = ok, detail, stop


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
def preflight(run: ProvisionRun) -> dict[str, Any]:
    """What this run will and will not be able to do — before it starts.

    Pure inspection: opens a connection to read capabilities, changes nothing.
    """
    plan = list(MODE_STEPS.get(run.mode, MODE_STEPS["semi"]))
    out: dict[str, Any] = {
        "mode": run.mode, "plan": plan, "blockers": [], "warnings": [],
        "capabilities": {}, "ok": True,
    }
    needs_hv = any(s in plan for s in ("vm_created", "booted"))
    if not needs_hv:
        return out
    target = _target(run)
    if target is None:
        out["ok"] = False
        out["blockers"].append(
            "no hypervisor selected — pick one, or use the 'Config only' mode "
            "against a machine that already exists")
        return out
    try:
        caps = target.client().capabilities()
    except HypervisorError as exc:
        out["ok"] = False
        out["blockers"].append(f"hypervisor unreachable: {exc}")
        return out
    out["capabilities"] = {
        "create_vm": caps.create_vm, "power_control": caps.power_control,
        "upload_image": caps.upload_image, "disk_import": caps.disk_import,
        "ovf_import": caps.ovf_import, "serial_console": caps.serial_console,
        "notes": list(caps.notes),
    }
    for cap in MODE_REQUIRES.get(run.mode, ()):
        if not getattr(caps, cap, False):
            out["ok"] = False
            out["blockers"].append(
                "%s cannot %s" % (target.name, CAP_LABEL.get(cap, cap)))
    if "image_attached" in plan and not (caps.disk_import or caps.ovf_import):
        out["warnings"].append(
            "this host cannot attach a disk image through SATOM — create the "
            "machine, then attach the appliance disk by hand before resuming")
    return out


# ---------------------------------------------------------------------------
# step implementations
# ---------------------------------------------------------------------------
def _target(run: ProvisionRun):
    from ..models_provision import HypervisorTarget
    if not run.target_id:
        return None
    return HypervisorTarget.query.get(run.target_id)


def _step_ip_reserved(run: ProvisionRun) -> StepResult:
    """Take an address. Only asks IPAM when the operator opted in.

    A hand-typed address is used as given and, crucially, is NOT marked as
    ours: rollback must not hand somebody else's address back to a pool.
    """
    if run.mgmt_ip and not run.ip_from_ipam:
        return StepResult(True, f"using the supplied address {run.mgmt_ip}")
    if not run.ip_from_ipam:
        return StepResult(
            False, "no management address given and IPAM allocation was not "
                   "requested for this run")
    try:
        from .dns_providers import allocate_address  # type: ignore
    except ImportError:
        return StepResult(
            False, "IPAM allocation was requested but no DNS/IPAM provider "
                   "exposes address allocation")
    try:
        addr = allocate_address(hostname=run.hostname or run.name)
    except Exception as exc:  # noqa: BLE001 — provider-specific failures
        return StepResult(False, f"IPAM refused to allocate: {exc}")
    run.mgmt_ip = addr.get("address", "")
    run.netmask = addr.get("netmask", run.netmask or "")
    run.gateway = addr.get("gateway", run.gateway or "")
    return StepResult(bool(run.mgmt_ip),
                      f"IPAM allocated {run.mgmt_ip}" if run.mgmt_ip
                      else "IPAM returned no address")


def _step_dns_created(run: ProvisionRun) -> StepResult:
    if not run.hostname:
        return StepResult(True, "no hostname requested — DNS step skipped")
    if not run.mgmt_ip:
        return StepResult(False, "cannot create a DNS record without an address")
    try:
        from .dns_providers import create_record  # type: ignore
    except ImportError:
        return StepResult(True, "no DNS provider configured — record not "
                                "created (this is not an error)")
    try:
        rec = create_record(name=run.hostname, rtype="A", value=run.mgmt_ip)
    except Exception as exc:  # noqa: BLE001
        return StepResult(False, f"DNS provider refused the record: {exc}")
    run.dns_record_id = str(rec.get("id", "") or "")
    return StepResult(True, f"created {run.hostname} A {run.mgmt_ip}")


def _step_vm_created(run: ProvisionRun) -> StepResult:
    target = _target(run)
    if target is None:
        return StepResult(False, "no hypervisor target selected")
    spec = VmSpec(
        name=run.name,
        cpus=run.cpus or 4,
        memory_mb=run.memory_mb or 4096,
        disk_gb=run.disk_gb or 0,
        network=run.network or target.default_network or "",
        datastore=run.datastore or target.default_datastore or "",
        node=run.node or target.default_node or "",
        image_path=_image_path(run),
        serial=True,
    )
    try:
        ref = target.client().create_vm(spec)
    except HypervisorError as exc:
        return StepResult(False, f"{exc}{(' — ' + exc.detail) if exc.detail else ''}")
    run.vm_ref = json.dumps({
        "backend": ref.backend, "identifier": ref.identifier,
        "name": ref.name, "node": ref.node, "raw": ref.raw})
    return StepResult(True, f"created {ref.name} ({ref.backend} id {ref.identifier})")


def _step_image_attached(run: ProvisionRun) -> StepResult:
    """The install image is attached during creation on every backend today.

    Kept as its own step because it is the one that will move first: an OVA
    path, an already-staged disk and a shell-side vmkfstools conversion all
    land here, and having the slot already in the state machine means adding
    one does not renumber anybody's progress.
    """
    if not run.firmware_id:
        return StepResult(True, "no install image selected — the machine was "
                                "created with an empty disk")
    return StepResult(True, "install image attached during machine creation")


def _step_booted(run: ProvisionRun) -> StepResult:
    target = _target(run)
    ref = run.ref()
    if target is None or not ref:
        return StepResult(False, "no machine to power on")
    try:
        target.client().power_on(VmRef(**{k: ref.get(k) for k in
                                          ("backend", "identifier", "name",
                                           "node", "raw")}))
    except HypervisorError as exc:
        return StepResult(False, f"power on refused: {exc}")
    return StepResult(True, "powered on")


def _step_reachable(run: ProvisionRun) -> StepResult:
    """Can SATOM open a TCP session to the management address yet?

    Deliberately a socket test and not an API call: at this point the
    appliance may still be presenting a factory certificate and a default
    account, and the only question is whether the address answers.
    """
    import socket
    if not run.mgmt_ip:
        return StepResult(False, "no management address to probe")
    for port in (443, 8443, 22):
        try:
            with socket.create_connection((run.mgmt_ip, port), timeout=4):
                return StepResult(True, f"{run.mgmt_ip}:{port} answered")
        except OSError:
            continue
    return StepResult(
        False, f"{run.mgmt_ip} is not answering on 443, 8443 or 22 — if the "
               "first-boot dialog has not been completed yet, do that and "
               "resume")


def _step_onboarded(run: ProvisionRun) -> StepResult:
    """Register the machine as an Appliance so the rest of SATOM can see it."""
    from ..models import Appliance
    if run.appliance_id:
        return StepResult(True, "already onboarded")
    if not run.mgmt_ip:
        return StepResult(False, "no management address")
    kind = run.product or ""
    if not kind:
        return StepResult(False, "run has no product/ADOM — cannot decide "
                                 "what kind of appliance this is")
    ap = Appliance(name=run.name, host=run.mgmt_ip, kind=kind,
                   username=run.admin_user or "admin")
    # Setter encrypts. A factory appliance presents a self-signed certificate,
    # so verification starts off — the same trap that has stalled every new
    # device on this fleet (fadc, fortiweb08, fac01). Import the device CA in
    # Settings > Trust store to turn it back on and have it mean something.
    ap.password = run.admin_password or ""
    ap.verify_ssl = False
    db.session.add(ap)
    db.session.flush()
    run.appliance_id = ap.id
    return StepResult(True, f"registered appliance #{ap.id} ({kind})")


def _step_cert_installed(run: ProvisionRun) -> StepResult:
    if not run.appliance_id:
        return StepResult(False, "not onboarded yet")
    return StepResult(True, "certificate step is a no-op until a CA profile "
                            "is selected for this run")


def _step_profile_applied(run: ProvisionRun) -> StepResult:
    """Hand over to the CONFIG provisioning module that already exists.

    Deliberately a handoff and not a reimplementation: ``/web/provisioning``
    already does dry-run, canary, snapshot and approval for exactly this, and
    a second copy of that logic would drift from the reviewed one.
    """
    if not run.profile_id:
        return StepResult(True, "no system profile selected — configuration "
                                "left to the operator")
    if not run.appliance_id:
        return StepResult(False, "not onboarded yet")
    return StepResult(
        True, f"ready for profile #{run.profile_id} — apply it from "
              "Provisioning with dry-run and approval")


STEP_FUNCS: dict[str, Callable[[ProvisionRun], StepResult]] = {
    "ip_reserved": _step_ip_reserved,
    "dns_created": _step_dns_created,
    "vm_created": _step_vm_created,
    "image_attached": _step_image_attached,
    "booted": _step_booted,
    "reachable": _step_reachable,
    "onboarded": _step_onboarded,
    "cert_installed": _step_cert_installed,
    "profile_applied": _step_profile_applied,
}


def _image_path(run: ProvisionRun) -> str:
    if not run.firmware_id:
        return ""
    try:
        from ..models_firmware import FirmwareImage
    except ImportError:
        return ""
    img = FirmwareImage.query.get(run.firmware_id)
    return getattr(img, "stored_path", "") or "" if img else ""


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------
def advance(run: ProvisionRun, *, max_steps: int = 20) -> ProvisionRun:
    """Run steps until the mode's plan is exhausted, or something stops it."""
    plan = list(MODE_STEPS.get(run.mode, MODE_STEPS["semi"]))
    if run.status in ("done", "aborted"):
        return run
    run.status = "running"
    run.error = ""
    db.session.commit()

    guard = 0
    while guard < max_steps:
        guard += 1
        nxt = _next_step(run, plan)
        if nxt is None:
            # Plan exhausted. "done" only when the plan really was the whole
            # pipeline; otherwise this is a designed handoff.
            if plan and plan[-1] == "done":
                run.step, run.status = "done", "done"
                run.add_log("done", True, "pipeline complete")
            else:
                run.status = "paused"
                run.add_log(run.step, True,
                            MODE_STOP_REASON.get(run.mode, "plan complete"))
                run.error = MODE_STOP_REASON.get(run.mode, "")
            db.session.commit()
            return run
        if nxt == "done":
            run.step, run.status = "done", "done"
            run.add_log("done", True, "pipeline complete")
            db.session.commit()
            return run
        fn = STEP_FUNCS.get(nxt)
        if fn is None:
            run.add_log(nxt, True, "no action for this step")
            run.step = nxt
            db.session.commit()
            continue
        try:
            res = fn(run)
        except Exception as exc:  # noqa: BLE001 — a step must never 500 the run
            res = StepResult(False, f"unhandled error: {exc}")
        run.add_log(nxt, res.ok, res.detail)
        if not res.ok:
            run.status = "failed"
            run.error = res.detail
            db.session.commit()
            return run
        run.step = nxt
        db.session.commit()
    run.status = "failed"
    run.error = "step budget exhausted — refusing to loop"
    db.session.commit()
    return run


def _next_step(run: ProvisionRun, plan: list[str]) -> str | None:
    try:
        here = plan.index(run.step)
    except ValueError:
        # Current step is not in this mode's plan (mode changed mid-run).
        # Resume at the first planned step the run has not passed yet.
        done_to = STEPS.index(run.step) if run.step in STEPS else 0
        for s in plan:
            if s in STEPS and STEPS.index(s) > done_to:
                return s
        return None
    return plan[here + 1] if here + 1 < len(plan) else None


# ---------------------------------------------------------------------------
# rollback
# ---------------------------------------------------------------------------
def rollback(run: ProvisionRun) -> ProvisionRun:
    """Undo, in reverse, exactly what this run recorded creating.

    Every arm is guarded by a *recorded fact*, never by looking at the world:
    an address is released only if ``ip_from_ipam`` says SATOM took it, a
    machine is deleted only if ``vm_ref`` says SATOM built it. Inferring
    ownership from current state is how a rollback deletes somebody else's VM.
    """
    errors: list[str] = []

    ref = run.ref()
    if ref:
        target = _target(run)
        if target is None:
            errors.append("hypervisor target is gone — the machine "
                          f"{ref.get('name')!r} must be removed by hand")
        else:
            try:
                target.client().delete_vm(VmRef(**{
                    k: ref.get(k) for k in
                    ("backend", "identifier", "name", "node", "raw")}))
                run.add_log("rollback:vm", True,
                            f"deleted {ref.get('name')}")
                run.vm_ref = ""
            except HypervisorError as exc:
                errors.append(f"could not delete the machine: {exc}")
                run.add_log("rollback:vm", False, str(exc))

    if run.dns_record_id:
        try:
            from .dns_providers import delete_record  # type: ignore
            delete_record(run.dns_record_id)
            run.add_log("rollback:dns", True, f"removed {run.hostname}")
            run.dns_record_id = ""
        except Exception as exc:  # noqa: BLE001
            errors.append(f"could not remove the DNS record: {exc}")
            run.add_log("rollback:dns", False, str(exc))

    if run.ip_from_ipam and run.mgmt_ip:
        try:
            from .dns_providers import release_address  # type: ignore
            release_address(run.mgmt_ip)
            run.add_log("rollback:ip", True, f"released {run.mgmt_ip}")
            run.ip_from_ipam = False
        except Exception as exc:  # noqa: BLE001
            errors.append(f"could not release the address: {exc}")
            run.add_log("rollback:ip", False, str(exc))

    # An Appliance row created by this run is deliberately LEFT IN PLACE:
    # by the time onboarding happened the device was answering, and deleting
    # the record would orphan any harvest, snapshot or note already attached
    # to it. It is named in the log instead.
    if run.appliance_id:
        run.add_log("rollback:appliance", True,
                    f"appliance #{run.appliance_id} left registered on purpose "
                    "— remove it from Appliances if it is not wanted")

    run.status = "aborted"
    run.error = "; ".join(errors)
    run.updated_at = datetime.utcnow()
    db.session.commit()
    return run
