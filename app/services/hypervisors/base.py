"""Hypervisor abstraction — the contract every backend must satisfy.

Mirrors ``app/services/dns_providers/`` on purpose: a ``Capabilities`` record,
a small ABC, Fernet-backed credentials in ``app_settings``, and a registry.
Adding a hypervisor is a new module plus one registry entry — never an edit
scattered across the views.

Two rules this layer exists to enforce:

1. **A capability the backend does not have is reported, never faked.** A
   standalone ESXi host has no vCenter REST API and no ``vmkfstools`` unless
   SSH is on; a Proxmox ``dir`` storage without the ``import`` content type
   cannot receive a disk image. The UI must be able to say *why* a step is
   unavailable, because "provisioning failed" sends the operator to the wrong
   end of the problem.
2. **Nothing here reaches for a device on import.** Every network call happens
   inside a method, so the module imports cleanly on a node whose credentials
   are missing, wrong, or pointing at a box that is powered off.
"""
from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from typing import Any


class HypervisorError(RuntimeError):
    """Any backend failure. Carries the operator-facing reason verbatim."""

    def __init__(self, message: str, *, detail: str = "", retryable: bool = False):
        super().__init__(message)
        self.detail = detail
        self.retryable = retryable


@dataclass(frozen=True)
class Capabilities:
    """What a backend can actually do, resolved against the LIVE endpoint.

    Every flag defaults to False. A backend opts in to what it proved it can
    do; an unimplemented method must never leave a flag optimistically True.
    """

    create_vm: bool = False
    delete_vm: bool = False
    power_control: bool = False
    list_networks: bool = False
    list_datastores: bool = False
    #: Can accept a disk/appliance image through the API (no shell access).
    upload_image: bool = False
    #: Can import an OVF/OVA (ESXi converts streamOptimized disks in flight).
    ovf_import: bool = False
    #: Can import a raw/qcow2 disk when creating the VM (PVE ``import-from``).
    disk_import: bool = False
    #: Serial console reachable through the API — the only way to walk a
    #: factory Fortinet first-boot dialog without a human at the keyboard.
    serial_console: bool = False
    notes: tuple[str, ...] = ()

    def missing_for_full_provision(self) -> list[str]:
        """Human-readable list of what blocks an unattended end-to-end run."""
        gaps: list[str] = []
        if not self.create_vm:
            gaps.append("cannot create virtual machines")
        if not (self.ovf_import or self.disk_import):
            gaps.append("cannot attach an appliance image")
        if not self.serial_console:
            gaps.append(
                "no API serial console — the appliance first-boot dialog "
                "(admin password change) needs an operator or DHCP")
        return gaps


@dataclass
class VmSpec:
    """What to build. Backend-neutral; each client maps it to its own API."""

    name: str
    cpus: int = 4
    memory_mb: int = 4096
    disk_gb: int = 0            # 0 = size comes from the appliance image
    network: str = ""           # bridge (PVE) / port group (ESXi)
    datastore: str = ""         # storage id (PVE) / datastore name (ESXi)
    node: str = ""              # PVE node; ignored by standalone ESXi
    vmid: int | None = None     # PVE only; None = allocate next free
    image_path: str = ""        # absolute path or storage volume of the image
    guest_os: str = "l26"       # PVE ostype / ESXi guestId
    firmware: str = "seabios"   # seabios | ovmf (uefi)
    serial: bool = True         # attach a serial port (first-boot console)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class VmRef:
    """Identity of a machine that now exists. Enough to undo its creation."""

    backend: str
    identifier: str             # PVE vmid as str / ESXi MoRef value
    name: str
    node: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class HypervisorClient:
    """Base class. Subclasses implement only what they can honestly support."""

    #: Registry key. Must match the module's entry in ``__init__.REGISTRY``.
    backend = "base"

    def __init__(self, *, host: str, username: str, password: str,
                 verify_ssl: bool = False, port: int | None = None,
                 timeout: int = 30, **kwargs: Any):
        self.host = (host or "").strip()
        self.username = username
        self.password = password
        self.verify_ssl = bool(verify_ssl)
        self.port = port
        self.timeout = timeout
        self.options = kwargs

    # -- lifecycle ------------------------------------------------------
    def test_connection(self) -> dict[str, Any]:
        """Authenticate and return identifying facts. Raises on failure."""
        raise NotImplementedError

    def capabilities(self) -> Capabilities:
        """Resolve capabilities against the live endpoint."""
        raise NotImplementedError

    # -- inventory ------------------------------------------------------
    def list_nodes(self) -> list[dict[str, Any]]:
        return []

    def list_networks(self, node: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError

    def list_datastores(self, node: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError

    def list_vms(self, node: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError

    # -- machine lifecycle ----------------------------------------------
    def create_vm(self, spec: VmSpec) -> VmRef:
        raise NotImplementedError

    def power_on(self, ref: VmRef) -> None:
        raise NotImplementedError

    def power_off(self, ref: VmRef, *, hard: bool = False) -> None:
        raise NotImplementedError

    def delete_vm(self, ref: VmRef) -> None:
        """Undo ``create_vm``. Must be safe to call on a half-created VM."""
        raise NotImplementedError

    def vm_status(self, ref: VmRef) -> dict[str, Any]:
        raise NotImplementedError

    # -- helpers --------------------------------------------------------
    def _ssl_context(self) -> ssl.SSLContext | bool:
        """httpx ``verify=`` value. False only when the operator asked for it.

        A self-signed hypervisor certificate is the norm, so ``verify_ssl``
        defaults off — but it stays an explicit per-target setting rather than
        a hardcoded ``False``, so a site with an internal CA in the SATOM trust
        store can turn it on and have it mean something.
        """
        if not self.verify_ssl:
            return False
        try:
            from ..trust_store import verify_target  # type: ignore
            return verify_target()
        except Exception:  # noqa: BLE001 — trust store optional at this layer
            return True

    def __repr__(self) -> str:  # pragma: no cover — debugging aid
        return f"<{type(self).__name__} {self.username}@{self.host}>"
