"""ESXi host-shell transport — the way around a read-only vSphere API.

**Why this module exists.** The free ``esx.hypervisor.*`` licence gates the
*remote VIM API write methods*: ``CreateVM_Task``, ``PowerOnVM_Task``,
``ImportVApp`` and friends answer

    Current license or ESXi version prohibits execution of the requested
    operation

...while every read (inventory, datastores, networks, licence state) keeps
working. That single restriction is enough to make SATOM unable to provision
on an otherwise perfectly healthy host.

The host shell is a **different code path inside ESXi**. ``vim-cmd``,
``vmkfstools`` and ``esxcli`` run locally as root against hostd and are not
subject to the same remote-API licence gate. So a host whose API refuses to
build a VM can usually still build one when told to from its own shell.

**Three things this module refuses to do, and why:**

1. **It never enables SSH itself.** ``TSM-SSH`` is off by default on ESXi and
   turning it on is a durable change to the security posture of someone
   else's hypervisor — a permanent remote root path. SATOM detects the
   service state and *tells the operator the one line to run*; it does not
   flip it. (A capability probe that silently opens a root shell to make its
   own feature work is the definition of a surprise.)
2. **It never reports the shell as available until it has actually run a
   command on it.** ``capabilities()`` exists so the UI can explain a
   disabled button. A flag set from "SSH port looks open" would promise a
   provisioning path that dies three steps later, after an address and a DNS
   row were already committed.
3. **It never interpolates operator input into a shell string.** Every value
   that reaches a command goes through :func:`_q` (single-quote shell
   quoting) and datastore/VM names are additionally validated against
   :data:`SAFE_NAME`. A VM called ``foo; rm -rf /vmfs`` is rejected at the
   boundary, not escaped halfway down.

**Honest limitation.** This transport is [Probable], not [Verified], on the
fleet host it was written against: ``TSM-SSH`` is ``policy=off`` there, so the
path has not been exercised end to end. The code reports exactly that state
rather than assuming success — see :meth:`EsxiShell.probe`.
"""
from __future__ import annotations

from pathlib import Path

import posixpath
import re
import shlex
from dataclasses import dataclass
from typing import Any

from .base import HypervisorError, VmRef, VmSpec

#: Datastore and VM names we will put in a command line. Deliberately narrow:
#: ESXi tolerates more, but every character allowed here has to be safe in a
#: path *and* in a ``.vmx`` value, and "be liberal in what you accept" is how
#: injection bugs get written.
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")

#: Commands the transport is allowed to run. Anything not starting with one of
#: these is refused before it reaches the wire — the same allowlist discipline
#: as ``ssh_ops.assert_readonly`` and the curated pip list, applied to a path
#: that legitimately needs to write.
ALLOWED_BINARIES = ("vim-cmd", "vmkfstools", "esxcli", "vmware", "ls", "mkdir",
                    "stat", "cat", "df", "rm")


def _q(value: Any) -> str:
    """Shell-quote a single value. Never build a command without this."""
    return shlex.quote(str(value))


def _safe_name(value: str, what: str) -> str:
    v = (value or "").strip()
    if not SAFE_NAME.match(v):
        raise HypervisorError(
            f"unsafe {what} {value!r}",
            detail="letters, digits, dot, dash and underscore only; must "
                   "start with a letter or digit and be at most 63 characters")
    return v


@dataclass
class ShellState:
    """What the probe actually established. Every field is measured."""

    reachable: bool = False
    #: ``vmware -v`` output, proving a command really ran.
    version: str = ""
    #: Populated when the probe failed — shown verbatim to the operator.
    error: str = ""
    #: The one command the operator runs to unlock this path.
    remedy: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"reachable": self.reachable, "version": self.version,
                "error": self.error, "remedy": self.remedy}


class EsxiShell:
    """Run write operations on an ESXi host over SSH.

    Constructed by :class:`~.esxi.EsxiClient` only when the operator has filled
    in shell credentials for the target. Absent credentials mean "this path is
    not configured", which is reported, not worked around.
    """

    #: Shown by the UI and by ``capabilities()`` when the shell is off.
    ENABLE_HINT = (
        "On the ESXi host: Host > Manage > Services > TSM-SSH > Start "
        "(or, in the DCUI, Troubleshooting Options > Enable SSH). SATOM will "
        "not enable it for you — it is a durable remote-root path on your "
        "hypervisor and that decision is yours.")

    def __init__(self, host: str, username: str, password: str, *,
                 port: int = 22, timeout: int = 30):
        self.host = host
        self.username = username
        self.password = password
        self.port = int(port or 22)
        self.timeout = int(timeout or 30)
        self._client = None

    # -- connection -----------------------------------------------------
    def _connect(self):
        if self._client is not None:
            return self._client
        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover — paramiko is pinned
            raise HypervisorError(
                "paramiko is not installed; the ESXi shell transport is "
                "unavailable", detail=str(exc)) from exc
        cli = paramiko.SSHClient()
        # This channel runs shell commands as root on a hypervisor, so "trust
        # whatever answers" is not a pragmatic default -- it is no
        # authentication of the peer at all.
        #
        # The original comment was right that an ESXi host key changes on
        # reinstall, and that pinning must not make the feature unusable on a
        # fresh host. Trust-on-first-use satisfies both: an ABSENT store is
        # still first contact and still just works. What is refused is the
        # case that comment did not consider -- a store that exists and cannot
        # be read, where accepting a new key silently discards a pin that was
        # protecting this connection yesterday.
        from ..ssh_pinning import load_pins, persist
        known = (Path(__file__).resolve().parents[3] / "data" / "known_hosts")
        try:
            load_pins(cli, known, HypervisorError)
        except HypervisorError:
            raise
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            cli.connect(self.host, port=self.port, username=self.username,
                        password=self.password, timeout=self.timeout,
                        allow_agent=False, look_for_keys=False)
        except Exception as exc:  # noqa: BLE001 — paramiko raises broadly
            raise HypervisorError(
                f"SSH to the ESXi host failed: {exc}",
                detail=self.ENABLE_HINT, retryable=True) from exc
        persist(cli, known, HypervisorError)
        self._client = cli
        return cli

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            finally:
                self._client = None

    # -- execution ------------------------------------------------------
    def run(self, argv: list[str], *, timeout: int | None = None) -> str:
        """Run one command from :data:`ALLOWED_BINARIES`. Returns stdout.

        ``argv`` is a list, quoted here — callers never hand in a string, so
        there is no place for an unquoted value to slip through.
        """
        if not argv:
            raise HypervisorError("empty command")
        binary = argv[0]
        if binary not in ALLOWED_BINARIES:
            raise HypervisorError(
                f"command {binary!r} is not permitted on the ESXi shell",
                detail="allowed: " + ", ".join(ALLOWED_BINARIES))
        cmd = " ".join([binary] + [_q(a) for a in argv[1:]])
        cli = self._connect()
        try:
            _in, out, err = cli.exec_command(
                cmd, timeout=timeout or self.timeout)
            rc = out.channel.recv_exit_status()
            stdout = out.read().decode("utf-8", "replace")
            stderr = err.read().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            raise HypervisorError(f"ESXi shell command failed: {exc}",
                                  detail=cmd, retryable=True) from exc
        if rc != 0:
            raise HypervisorError(
                f"ESXi shell command exited {rc}",
                detail=f"{cmd}\n{(stderr or stdout)[:600]}")
        return stdout

    # -- probe ----------------------------------------------------------
    def probe(self) -> ShellState:
        """Establish — by running a command — whether this path works.

        Never infers from an open port. The returned state is what the UI
        prints, so it has to be the truth about a command that ran.
        """
        try:
            ver = self.run(["vmware", "-v"], timeout=15).strip()
        except HypervisorError as exc:
            return ShellState(reachable=False, error=str(exc),
                              remedy=self.ENABLE_HINT)
        return ShellState(reachable=True, version=ver)

    # -- write operations -----------------------------------------------
    def datastore_path(self, datastore: str, *parts: str) -> str:
        ds = _safe_name(datastore, "datastore name")
        safe = [_safe_name(p, "path segment") for p in parts if p]
        return posixpath.join("/vmfs/volumes", ds, *safe)

    def create_vm(self, spec: VmSpec, *, vmx_extra: str = "") -> VmRef:
        """Build and register a VM with ``vim-cmd``.

        Deliberately a *register*, not a clone: SATOM already staged the
        appliance disk, so the only thing missing is a machine definition
        pointing at it. Registering is atomic from the host's point of view
        and leaves exactly one artefact to undo.
        """
        name = _safe_name(spec.name, "VM name")
        ds = _safe_name(spec.datastore, "datastore name")
        folder = self.datastore_path(ds, name)
        vmx_path = posixpath.join(folder, f"{name}.vmx")
        self.run(["mkdir", "-p", folder])
        vmx = self._render_vmx(spec, name, vmx_extra=vmx_extra)
        # Written with a quoted heredoc so nothing in the body is expanded by
        # the remote shell.
        cli = self._connect()
        sftp = cli.open_sftp()
        try:
            with sftp.open(vmx_path, "w") as fh:
                fh.write(vmx)
        finally:
            sftp.close()
        out = self.run(["vim-cmd", "solo/registervm", vmx_path])
        vmid = (out or "").strip().splitlines()[-1].strip() if out.strip() else ""
        if not vmid.isdigit():
            raise HypervisorError(
                "ESXi registered the VM but returned no id",
                detail=f"registervm output: {out[:200]!r}")
        return VmRef(backend="esxi", identifier=vmid, name=name,
                     raw={"vmx": vmx_path, "transport": "shell",
                          "folder": folder})

    def _render_vmx(self, spec: VmSpec, name: str, *,
                    vmx_extra: str = "") -> str:
        disk = ""
        if spec.image_path:
            disk = ('scsi0:0.present = "TRUE"\n'
                    'scsi0:0.deviceType = "scsi-hardDisk"\n'
                    f'scsi0:0.fileName = "{spec.image_path}"\n')
        serial = ""
        if spec.serial:
            # A file-backed serial port: readable afterwards for the first-boot
            # transcript even though it cannot be driven interactively.
            serial = ('serial0.present = "TRUE"\n'
                      'serial0.fileType = "file"\n'
                      f'serial0.fileName = "{name}-serial.log"\n')
        firmware = "efi" if spec.firmware == "ovmf" else "bios"
        return (
            '.encoding = "UTF-8"\n'
            'config.version = "8"\n'
            'virtualHW.version = "20"\n'
            f'displayName = "{name}"\n'
            f'guestOS = "{spec.guest_os or "other-64"}"\n'
            f'firmware = "{firmware}"\n'
            f'numvcpus = "{int(spec.cpus)}"\n'
            f'memSize = "{int(spec.memory_mb)}"\n'
            'scsi0.present = "TRUE"\n'
            'scsi0.virtualDev = "pvscsi"\n'
            f'{disk}'
            'ethernet0.present = "TRUE"\n'
            'ethernet0.virtualDev = "vmxnet3"\n'
            f'ethernet0.networkName = "{spec.network or "VM Network"}"\n'
            'ethernet0.addressType = "generated"\n'
            f'{serial}'
            f'{vmx_extra}'
        )

    def power_on(self, ref: VmRef) -> None:
        self.run(["vim-cmd", "vmsvc/power.on", ref.identifier])

    def power_off(self, ref: VmRef, *, hard: bool = False) -> None:
        verb = "power.off" if hard else "power.shutdown"
        try:
            self.run(["vim-cmd", f"vmsvc/{verb}", ref.identifier])
        except HypervisorError:
            if hard:
                raise
            # A guest with no VMware Tools ignores a graceful shutdown. Falling
            # back is correct here: the caller asked for the machine to stop.
            self.run(["vim-cmd", "vmsvc/power.off", ref.identifier])

    def delete_vm(self, ref: VmRef) -> None:
        """Undo ``create_vm``. Safe on a half-created machine.

        ``destroy`` refuses on a powered-on VM, so power is removed first and
        a failure there is swallowed — the machine may never have booted, and
        the caller's intent is that nothing is left behind.
        """
        try:
            self.run(["vim-cmd", "vmsvc/power.off", ref.identifier])
        except HypervisorError:
            pass
        self.run(["vim-cmd", "vmsvc/destroy", ref.identifier])

    def convert_disk(self, source: str, dest: str, *,
                     thin: bool = True) -> str:
        """``vmkfstools -i`` — the conversion the API cannot be asked for.

        A Fortinet KVM image is qcow2 and a Fortinet OVA carries a
        ``streamOptimized`` vmdk; neither is directly attachable. The API path
        makes ESXi do this inside ``ImportVApp``; over the shell it is
        explicit.
        """
        argv = ["vmkfstools", "-i", source, dest]
        if thin:
            argv += ["-d", "thin"]
        self.run(argv, timeout=3600)
        return dest

    def vm_status(self, ref: VmRef) -> dict[str, Any]:
        out = self.run(["vim-cmd", "vmsvc/power.getstate", ref.identifier])
        state = "unknown"
        low = out.lower()
        if "powered on" in low:
            state = "poweredOn"
        elif "powered off" in low:
            state = "poweredOff"
        elif "suspended" in low:
            state = "suspended"
        return {"status": state, "raw": out.strip()}
