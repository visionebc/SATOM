"""Proxmox VE backend — pure HTTPS/JSON against ``/api2/json``.

No ``proxmoxer``, no new wheel. This product ships offline bundles for
air-gapped management networks and this repo has four recorded incidents of a
dependency that did not travel in the bundle (``sudo`` and ``openssh-*`` in
1.1, ``docs/safeguards.md`` in 1.2, ``lego`` in the RHEL bundle, ``git`` in the
SUSE one). ``httpx`` is already a pinned dependency; the Proxmox API is plain
JSON over HTTPS. Adding a library here would buy nothing and cost a rebuild of
three bundles.

Authentication supports both forms Proxmox offers:

* **API token** (``user@realm!tokenid`` + secret) — preferred: no session, no
  expiry, and it can be scoped to a role narrower than root.
* **Ticket** (username + password) — what the operator can configure without
  touching the hypervisor first, so it is the default in Settings.

Writes carry ``CSRFPreventionToken``; Proxmox rejects them otherwise, and the
error it returns ("401 no ticket") points at authentication rather than at the
missing header, which is a good half hour of confusion.
"""
from __future__ import annotations

import time
from typing import Any

import httpx

from .base import Capabilities, HypervisorClient, HypervisorError, VmRef, VmSpec

#: Content type a storage must advertise before an appliance disk can be
#: uploaded through the API and consumed by ``import-from``. Proxmox 8.3+
#: exposes it on ``dir`` storages, but it is opt-in per storage.
IMPORT_CONTENT = "import"
# A storage that can hold a running VM disk. Distinct from IMPORT_CONTENT:
# the stock ``local`` storage carries "import" without "images".
DISK_CONTENT = "images"


class ProxmoxClient(HypervisorClient):
    backend = "proxmox"

    def __init__(self, *, token_id: str = "", token_secret: str = "", **kw: Any):
        super().__init__(**kw)
        self.token_id = (token_id or "").strip()
        self.token_secret = (token_secret or "").strip()
        self._ticket: str | None = None
        self._csrf: str | None = None
        self._ticket_at: float = 0.0

    # -- plumbing -------------------------------------------------------
    @property
    def _base(self) -> str:
        return f"https://{self.host}:{self.port or 8006}/api2/json"

    def _login(self) -> None:
        if self.token_id:
            return  # token auth is stateless
        # Proxmox tickets last 2h; refresh well before the edge.
        if self._ticket and (time.monotonic() - self._ticket_at) < 3000:
            return
        try:
            r = httpx.post(f"{self._base}/access/ticket",
                           data={"username": self.username,
                                 "password": self.password},
                           verify=self._ssl_context(), timeout=self.timeout)
        except httpx.HTTPError as exc:
            raise HypervisorError(f"cannot reach Proxmox at {self.host}",
                                  detail=str(exc), retryable=True) from exc
        if r.status_code == 401:
            raise HypervisorError("Proxmox rejected the credentials",
                                  detail=r.text[:300])
        if r.status_code >= 400:
            raise HypervisorError(f"Proxmox login failed (HTTP {r.status_code})",
                                  detail=r.text[:300])
        data = (r.json() or {}).get("data") or {}
        self._ticket = data.get("ticket")
        self._csrf = data.get("CSRFPreventionToken")
        self._ticket_at = time.monotonic()
        if not self._ticket:
            raise HypervisorError("Proxmox returned no ticket",
                                  detail=r.text[:300])

    def _headers(self, write: bool) -> dict[str, str]:
        if self.token_id:
            return {"Authorization":
                    f"PVEAPIToken={self.token_id}={self.token_secret}"}
        h: dict[str, str] = {"Cookie": f"PVEAuthCookie={self._ticket}"}
        if write and self._csrf:
            h["CSRFPreventionToken"] = self._csrf
        return h

    def _call(self, method: str, path: str, *, data: dict | None = None,
              timeout: int | None = None) -> Any:
        self._login()
        write = method.upper() not in ("GET", "HEAD")
        url = f"{self._base}{path}"
        try:
            r = httpx.request(method, url, data=data,
                              headers=self._headers(write),
                              verify=self._ssl_context(),
                              timeout=timeout or self.timeout)
        except httpx.HTTPError as exc:
            raise HypervisorError(f"Proxmox call failed: {method} {path}",
                                  detail=str(exc), retryable=True) from exc
        if r.status_code >= 400:
            raise HypervisorError(
                f"Proxmox {method} {path} -> HTTP {r.status_code}",
                detail=(r.text or "")[:400])
        try:
            return (r.json() or {}).get("data")
        except ValueError as exc:
            raise HypervisorError("Proxmox returned a non-JSON body",
                                  detail=(r.text or "")[:200]) from exc

    # -- lifecycle ------------------------------------------------------
    def test_connection(self) -> dict[str, Any]:
        ver = self._call("GET", "/version") or {}
        nodes = self.list_nodes()
        return {
            "ok": True,
            "backend": "proxmox",
            "version": ver.get("version", ""),
            "release": ver.get("release", ""),
            "nodes": [n.get("node") for n in nodes],
            "auth": "token" if self.token_id else "ticket",
        }

    def capabilities(self) -> Capabilities:
        notes: list[str] = []
        disk_import = False
        upload = False
        try:
            nodes = self.list_nodes()
            node = nodes[0]["node"] if nodes else ""
            stores = self.list_datastores(node) if node else []
            importable = [s["id"] for s in stores if s.get("can_import")]
            diskable = [s["id"] for s in stores if s.get("can_disk")]
            if importable:
                disk_import = upload = True
                notes.append("import-ready storage: " + ", ".join(importable))
            else:
                # Honest, actionable: name the fix instead of reporting a bare
                # "unsupported". Without this the operator sees a disabled
                # button and no way to learn what unlocks it.
                notes.append(
                    "no storage advertises the 'import' content type — add "
                    "'import' to a directory storage in Datacenter > Storage "
                    "to upload appliance images through the API")
            if diskable:
                notes.append("disk-capable storage: " + ", ".join(diskable))
            else:
                notes.append(
                    "no storage advertises the 'images' content type — a VM "
                    "created here would have nowhere to put its disk")
        except HypervisorError as exc:
            notes.append(f"capability probe incomplete: {exc}")
        return Capabilities(
            create_vm=True, delete_vm=True, power_control=True,
            list_networks=True, list_datastores=True,
            upload_image=upload, disk_import=disk_import,
            ovf_import=False,
            # qemu exposes the serial port over the API (``termproxy``), so a
            # factory first-boot dialog can be walked without a human.
            serial_console=True,
            notes=tuple(notes),
        )

    # -- inventory ------------------------------------------------------
    def list_nodes(self) -> list[dict[str, Any]]:
        return [{"node": n.get("node"), "status": n.get("status"),
                 "cpu": n.get("cpu"), "maxmem": n.get("maxmem")}
                for n in (self._call("GET", "/nodes") or [])]

    def list_networks(self, node: str = "") -> list[dict[str, Any]]:
        node = node or self._first_node()
        # No ``?type=`` filter: Proxmox rejects unknown type values with a
        # bare HTTP 400 and the accepted set differs across releases
        # (verified: ``type=any`` -> 400 on PVE 9.2.3). Filtering client
        # side is version-proof and costs one small response.
        rows = self._call("GET", f"/nodes/{node}/network") or []
        out = []
        for r in rows:
            if r.get("type") not in ("bridge", "OVSBridge"):
                continue
            out.append({"id": r.get("iface"), "name": r.get("iface"),
                        "kind": r.get("type"),
                        "active": bool(r.get("active")),
                        "comment": (r.get("comments") or "").strip()})
        return sorted(out, key=lambda x: x["id"] or "")

    def list_datastores(self, node: str = "") -> list[dict[str, Any]]:
        """Every active storage, each labelled with what it can be used for.

        Proxmox splits these two roles across DIFFERENT storages and there is
        no requirement that one storage does both:

        * ``images``  -> can hold a running VM disk   (``can_disk``)
        * ``import``  -> can receive an uploaded image (``can_import``)

        An earlier version filtered on ``images`` FIRST and only then looked
        at ``import``, so a storage that advertises ``import`` but not
        ``images`` — which is the default shape of the stock ``local`` storage
        — was dropped before its import flag was ever read. The capability
        probe then told the operator to "add import to a storage" on a host
        that already had one. Never narrow a list by one role while reporting
        on another.
        """
        node = node or self._first_node()
        rows = self._call("GET", f"/nodes/{node}/storage") or []
        out = []
        for r in rows:
            content = (r.get("content") or "")
            types = {c.strip() for c in content.split(",") if c.strip()}
            if not r.get("active"):
                continue
            can_disk = DISK_CONTENT in types
            can_import = IMPORT_CONTENT in types
            if not (can_disk or can_import):
                continue  # neither role — not a provisioning target
            avail = int(r.get("avail") or 0)
            out.append({
                "id": r.get("storage"), "name": r.get("storage"),
                "type": r.get("type"), "content": sorted(types),
                "avail_bytes": avail, "avail_gb": avail // (1024 ** 3),
                "total_gb": int(r.get("total") or 0) // (1024 ** 3),
                "can_disk": can_disk,
                "can_import": can_import,
            })
        return sorted(out, key=lambda x: -x["avail_bytes"])

    def disk_datastores(self, node: str = "") -> list[dict[str, Any]]:
        """Only the storages that can hold a VM disk."""
        return [s for s in self.list_datastores(node) if s.get("can_disk")]

    def import_datastores(self, node: str = "") -> list[dict[str, Any]]:
        """Only the storages that can receive an uploaded appliance image."""
        return [s for s in self.list_datastores(node) if s.get("can_import")]

    def list_vms(self, node: str = "") -> list[dict[str, Any]]:
        """Machines on one node (live) or across the cluster (cached).

        ``/cluster/resources`` is an aggregate refreshed on ``pvestatd``'s
        cycle, so a machine created seconds ago is genuinely absent from it —
        verified: a VM SATOM had just built and powered on did not appear,
        while the rollback that followed deleted it without trouble. On a
        provisioning page that reads as "the machine was not created", which
        is the opposite of the truth.

        With a node in hand, ``/nodes/<node>/qemu`` answers from that node's
        own state and shows the machine immediately. The cached aggregate is
        kept only for the node-less, whole-cluster view, where it is the only
        single-call option.
        """
        if node:
            rows = self._call("GET", f"/nodes/{node}/qemu") or []
            return [{"vmid": r.get("vmid"), "name": r.get("name"),
                     "node": node, "status": r.get("status"),
                     "type": "qemu"} for r in rows]
        rows = self._call("GET", "/cluster/resources?type=vm") or []
        return [{"vmid": r.get("vmid"), "name": r.get("name"),
                 "node": r.get("node"), "status": r.get("status"),
                 "type": r.get("type")} for r in rows]

    def _first_node(self) -> str:
        nodes = self.list_nodes()
        if not nodes:
            raise HypervisorError("Proxmox reported no nodes")
        return nodes[0]["node"]

    def next_vmid(self) -> int:
        return int(self._call("GET", "/cluster/nextid"))

    # -- machine lifecycle ----------------------------------------------
    def create_vm(self, spec: VmSpec) -> VmRef:
        node = spec.node or self._first_node()
        vmid = spec.vmid or self.next_vmid()
        params: dict[str, Any] = {
            "vmid": vmid,
            "name": spec.name,
            "cores": spec.cpus,
            "memory": spec.memory_mb,
            "ostype": spec.guest_os or "l26",
            "scsihw": "virtio-scsi-single",
            "onboot": 1,
            "agent": 0,
        }
        if spec.firmware == "ovmf":
            params["bios"] = "ovmf"
            params["efidisk0"] = f"{spec.datastore}:1"
        if spec.network:
            params["net0"] = f"virtio,bridge={spec.network}"
        if spec.serial:
            # Fortinet images expect a serial console on first boot and the
            # API ``termproxy`` endpoint can only attach if the device exists.
            params["serial0"] = "socket"
        if spec.image_path:
            # PVE >= 8.0: attach the appliance disk straight from an image
            # file. ``0`` means "size comes from the source image" — an
            # explicit size here silently truncates a larger appliance disk.
            params["scsi0"] = f"{spec.datastore}:0,import-from={spec.image_path}"
        elif spec.disk_gb:
            params["scsi0"] = f"{spec.datastore}:{spec.disk_gb}"
        for k, v in (spec.extra or {}).items():
            params.setdefault(k, v)

        upid = self._call("POST", f"/nodes/{node}/qemu", data=params,
                          timeout=max(self.timeout, 120))
        ref = VmRef(backend="proxmox", identifier=str(vmid), name=spec.name,
                    node=node, raw={"upid": upid, "params": params})
        if isinstance(upid, str):
            self.wait_task(node, upid, timeout=900)
        return ref

    def wait_task(self, node: str, upid: str, timeout: int = 600) -> dict:
        """Block until a Proxmox task ends. Raises on a non-OK exit status."""
        deadline = time.monotonic() + timeout
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            last = self._call(
                "GET", f"/nodes/{node}/tasks/{upid}/status") or {}
            if last.get("status") == "stopped":
                exit_status = (last.get("exitstatus") or "").strip()
                if exit_status and exit_status != "OK":
                    raise HypervisorError(
                        f"Proxmox task failed: {exit_status}",
                        detail=upid)
                return last
            time.sleep(2)
        raise HypervisorError(f"Proxmox task did not finish in {timeout}s",
                              detail=upid, retryable=True)

    def power_on(self, ref: VmRef) -> None:
        self._call("POST",
                   f"/nodes/{ref.node}/qemu/{ref.identifier}/status/start")

    def power_off(self, ref: VmRef, *, hard: bool = False) -> None:
        verb = "stop" if hard else "shutdown"
        self._call("POST",
                   f"/nodes/{ref.node}/qemu/{ref.identifier}/status/{verb}")

    def delete_vm(self, ref: VmRef) -> None:
        # Rollback path: the VM may be running, may be half-created, or may
        # already be gone. Stop best-effort, then delete; a 'does not exist'
        # is success, because the caller's goal is "it must not be there".
        try:
            self.power_off(ref, hard=True)
            time.sleep(2)
        except HypervisorError:
            pass
        try:
            # ``purge=1`` only detaches the vmid from backup/replication/HA
            # config. ``destroy-unreferenced-disks`` is deliberately NOT set:
            # it makes Proxmox scan EVERY configured storage, so a single
            # offline one (an unmounted NFS/CIFS share) aborts the destroy
            # half-way and leaves a zombie guest — config file present, disks
            # gone. Verified live: the fleet has an offline CIFS store and the
            # flag turned every rollback into garbage. The VM's own disks are
            # removed either way.
            upid = self._call("DELETE",
                              f"/nodes/{ref.node}/qemu/{ref.identifier}"
                              "?purge=1",
                              timeout=max(self.timeout, 120))
            # MUST wait: DELETE returns a task id immediately. Without this the
            # caller sees "deleted" while the VM is still in the inventory, so
            # a rollback reports success on a machine that still exists and a
            # retry collides with a vmid that is not free yet. Caught by the
            # live round-trip, not by reading the code.
            if isinstance(upid, str):
                self.wait_task(ref.node, upid, timeout=600)
        except HypervisorError as exc:
            if "does not exist" in (exc.detail or "").lower():
                return
            raise

    def vm_status(self, ref: VmRef) -> dict[str, Any]:
        d = self._call(
            "GET",
            f"/nodes/{ref.node}/qemu/{ref.identifier}/status/current") or {}
        return {"status": d.get("status"), "uptime": d.get("uptime"),
                "name": d.get("name"), "raw": d}

    # -- image staging ---------------------------------------------------
    def upload_image(self, node: str, storage: str, filename: str,
                     fh: Any, *, timeout: int = 3600) -> str:
        """Push an appliance disk into an import-capable storage.

        Returns the volume id usable as ``import-from``.
        """
        self._login()
        url = f"{self._base}/nodes/{node}/storage/{storage}/upload"
        try:
            r = httpx.post(url, headers=self._headers(True),
                           data={"content": IMPORT_CONTENT,
                                 "filename": filename},
                           files={"filename": (filename, fh)},
                           verify=self._ssl_context(), timeout=timeout)
        except httpx.HTTPError as exc:
            raise HypervisorError("upload to Proxmox failed",
                                  detail=str(exc), retryable=True) from exc
        if r.status_code >= 400:
            raise HypervisorError(
                f"Proxmox refused the upload (HTTP {r.status_code})",
                detail=(r.text or "")[:400])
        upid = (r.json() or {}).get("data")
        if isinstance(upid, str):
            self.wait_task(node, upid, timeout=timeout)
        return f"{storage}:import/{filename}"

    def serial_console_hint(self, ref: VmRef) -> dict[str, Any]:
        """Where the first-boot dialog can be driven from."""
        return {"kind": "termproxy",
                "endpoint": f"/nodes/{ref.node}/qemu/{ref.identifier}/termproxy",
                "note": "POST to open a serial session; requires serial0 on "
                        "the VM (SATOM always attaches one)."}
