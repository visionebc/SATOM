"""VMware ESXi backend — vSphere SOAP (``/sdk``) over plain HTTPS.

Why SOAP and not the REST API: a **standalone** ESXi host reports
``apiType=HostAgent`` and does not serve the vSphere Automation REST API.
Verified against the target host (ESXi 8.0.3 build-24677879): ``POST
/api/session`` and ``POST /rest/com/vmware/cis/session`` both answer HTTP 400,
while ``/sdk`` authenticates. ``/api`` only exists on vCenter. Code written
against REST would look correct, pass review, and fail on every standalone
host in the field.

Why no ``pyVmomi``: same reason as the Proxmox client — this product ships
offline bundles, and a dependency that does not travel in the bundle is a
documented, repeated failure mode here. The vSphere API is SOAP/XML over
HTTPS; ``httpx`` plus the standard library covers it.

**The disk-format constraint that shapes the whole ESXi path.** Fortinet ships
ESXi appliances as an OVF plus ``streamOptimized`` VMDKs. Those cannot be
attached to a VM as-is; they must be converted to a datastore format. The
usual conversion tool is ``vmkfstools`` over SSH — and SSH is closed on the
target host (verified: port 22 refused). The remaining supported path is
``OvfManager.CreateImportSpec`` -> ``ImportVApp`` -> ``HttpNfcLease``, where
ESXi performs the conversion itself as the disk streams in. That is why this
client implements the lease dance instead of a simpler datastore PUT.
"""
from __future__ import annotations

import re
import time
from typing import Any
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as xml_escape

import httpx

from .base import Capabilities, HypervisorClient, HypervisorError, VmRef, VmSpec
from .esxi_shell import EsxiShell, ShellState

VIM = "urn:vim25"
NS = {"s": "http://schemas.xmlsoap.org/soap/envelope/", "v": VIM}

#: Managed-object identifiers a standalone host always uses. Verified live
#: rather than assumed — ``RetrieveServiceContent`` returns ``ha-folder-root``
#: and the rest resolve underneath it.
HA_ROOT_FOLDER = "ha-folder-root"


def _txt(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


class EsxiClient(HypervisorClient):
    backend = "esxi"

    def __init__(self, **kw: Any):
        super().__init__(**kw)
        self._shell: EsxiShell | None = None
        self._cookie: str | None = None
        self._content: dict[str, str] = {}
        self._about: dict[str, str] = {}

    # -- plumbing -------------------------------------------------------
    @property
    def _url(self) -> str:
        return f"https://{self.host}:{self.port or 443}/sdk"

    def _soap(self, body: str, *, timeout: int | None = None,
              login: bool = True) -> ET.Element:
        if login and not self._cookie:
            self.login()
        headers = {"Content-Type": 'text/xml; charset=utf-8',
                   "SOAPAction": '"urn:vim25/8.0.0.0"'}
        if self._cookie:
            headers["Cookie"] = self._cookie
        envelope = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<s:Body>{body}</s:Body></s:Envelope>')
        try:
            r = httpx.post(self._url, content=envelope.encode("utf-8"),
                           headers=headers, verify=self._ssl_context(),
                           timeout=timeout or self.timeout)
        except httpx.HTTPError as exc:
            raise HypervisorError(f"cannot reach ESXi at {self.host}",
                                  detail=str(exc), retryable=True) from exc
        try:
            root = ET.fromstring(r.content)
        except ET.ParseError as exc:
            raise HypervisorError("ESXi returned a malformed SOAP body",
                                  detail=r.text[:300]) from exc
        fault = root.find(".//s:Fault", NS)
        if fault is not None:
            msg = _txt(fault.find("faultstring")) or "unknown SOAP fault"
            # The fault subtype is the actionable part: NotAuthenticated means
            # "log in again", InvalidLogin means "the credentials are wrong",
            # and conflating them costs a support round-trip.
            detail = ET.tostring(fault, encoding="unicode")[:600]
            raise HypervisorError(f"ESXi: {msg}", detail=detail)
        if r.status_code >= 400:
            raise HypervisorError(f"ESXi HTTP {r.status_code}",
                                  detail=r.text[:300])
        return root

    # -- lifecycle ------------------------------------------------------
    def login(self) -> None:
        body = (
            '<RetrieveServiceContent xmlns="urn:vim25">'
            '<_this type="ServiceInstance">ServiceInstance</_this>'
            '</RetrieveServiceContent>')
        root = self._soap(body, login=False)
        rv = root.find(".//v:RetrieveServiceContentResponse/v:returnval", NS)
        if rv is None:
            raise HypervisorError("ESXi did not return a service content")
        for child in rv:
            tag = child.tag.split("}", 1)[-1]
            if child.attrib.get("type"):
                self._content[tag] = (child.text or "").strip()
        about = rv.find("v:about", NS)
        if about is not None:
            self._about = {c.tag.split("}", 1)[-1]: (c.text or "")
                           for c in about}
        sm = self._content.get("sessionManager", "ha-sessionmgr")
        body = (
            f'<Login xmlns="urn:vim25"><_this type="SessionManager">{sm}</_this>'
            f'<userName>{xml_escape(self.username)}</userName>'
            f'<password>{xml_escape(self.password)}</password></Login>')
        headers = {"Content-Type": "text/xml; charset=utf-8",
                   "SOAPAction": '"urn:vim25/8.0.0.0"'}
        envelope = ('<?xml version="1.0" encoding="UTF-8"?>'
                    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/'
                    f'envelope/"><s:Body>{body}</s:Body></s:Envelope>')
        r = httpx.post(self._url, content=envelope.encode("utf-8"),
                       headers=headers, verify=self._ssl_context(),
                       timeout=self.timeout)
        if "<key>" not in r.text:
            fault = re.search(r"<faultstring>(.*?)</faultstring>", r.text)
            raise HypervisorError(
                "ESXi rejected the credentials"
                if not fault else f"ESXi: {fault.group(1)}",
                detail=r.text[:300])
        raw = r.headers.get("set-cookie", "")
        m = re.search(r'(vmware_soap_session="?[^;"]+"?)', raw)
        if not m:
            raise HypervisorError("ESXi returned no session cookie")
        self._cookie = m.group(1)

    def logout(self) -> None:
        if not self._cookie:
            return
        sm = self._content.get("sessionManager", "ha-sessionmgr")
        try:
            self._soap(f'<Logout xmlns="urn:vim25">'
                       f'<_this type="SessionManager">{sm}</_this></Logout>')
        except HypervisorError:
            pass
        self._cookie = None

    def test_connection(self) -> dict[str, Any]:
        self.login()
        return {
            "ok": True,
            "backend": "esxi",
            "version": self._about.get("version", ""),
            "build": self._about.get("build", ""),
            "full_name": self._about.get("fullName", ""),
            "api_type": self._about.get("apiType", ""),
            "standalone": self._about.get("apiType") == "HostAgent",
            "datastores": [d["name"] for d in self.list_datastores()],
            "networks": [n["name"] for n in self.list_networks()],
        }

    def license_info(self) -> dict[str, Any]:
        """Edition and evaluation state of the host license.

        This is not decoration. VMware's **free** licence ("vSphere
        Hypervisor", editionKey ``esx.hypervisor.*``) makes the vSphere API
        READ-ONLY: inventory works, ``CreateVM_Task`` answers *"Current
        license or ESXi version prohibits execution of the requested
        operation"*. Verified live on the target host. Without this probe the
        capability record would advertise ``create_vm=True`` and every
        provisioning run would die at the first write with an error that
        sounds like a bug in SATOM.
        """
        self.login()
        lm = self._content.get("licenseManager", "ha-license-manager")
        pc = self._content.get("propertyCollector", "ha-property-collector")
        body = ('<RetrievePropertiesEx xmlns="urn:vim25">'
                f'<_this type="PropertyCollector">{pc}</_this><specSet>'
                '<propSet><type>LicenseManager</type>'
                '<pathSet>licenses</pathSet><pathSet>evaluation</pathSet>'
                '</propSet>'
                f'<objectSet><obj type="LicenseManager">{lm}</obj>'
                '</objectSet></specSet><options/></RetrievePropertiesEx>')
        raw = ET.tostring(self._soap(body), encoding="unicode")
        edition = (re.search(r"<(?:\w+:)?editionKey>(.*?)</", raw) or [None, ""])[1] \
            if re.search(r"<(?:\w+:)?editionKey>(.*?)</", raw) else ""
        # The FIRST <name> in the response belongs to the ``evaluation``
        # propSet, not to the licence. Anchor on editionKey, which is emitted
        # immediately before the licence name inside
        # LicenseManagerLicenseInfo.
        name = ""
        m = re.search(r"<(?:\w+:)?editionKey>.*?<(?:\w+:)?name>([^<]*)<",
                      raw, re.S)
        if m:
            name = m.group(1)
        expired = "Evaluation period has expired" in raw
        # ``esx.hypervisor.*`` is the free edition family. Everything else
        # (esx.enterprisePlus, esx.standard, vCenter-managed) permits writes.
        free = edition.startswith("esx.hypervisor")
        return {"edition_key": edition, "name": name,
                "free": free, "evaluation_expired": expired,
                "api_writable": not free}

    # -- shell transport -------------------------------------------------
    def shell(self) -> EsxiShell | None:
        """The SSH transport for this target, or None if not configured.

        Not configured is a first-class answer: it means the operator has not
        given SATOM shell credentials, which is different from "SSH is off"
        and different again from "SSH works". All three are reported
        separately because they have three different remedies.
        """
        user = (self.options.get("ssh_user") or "").strip()
        if not user:
            return None
        if self._shell is None:
            self._shell = EsxiShell(
                self.host, user,
                self.options.get("ssh_password") or "",
                port=int(self.options.get("ssh_port") or 22),
                timeout=self.timeout)
        return self._shell

    def shell_state(self) -> ShellState:
        """Probe the shell path. Runs a command; never infers from a port."""
        sh = self.shell()
        if sh is None:
            return ShellState(
                reachable=False,
                error="no shell credentials configured for this target",
                remedy="Add an SSH username and password to the hypervisor "
                       "target in Settings > Hypervisors, then re-test.")
        return sh.probe()

    def _writer(self):
        """Whichever transport can actually write, or raise saying why.

        Order matters: the API is preferred when it is writable because it
        needs no extra service enabled on the host. The shell is the fallback
        for exactly the free-licence case.
        """
        try:
            if self.license_info()["api_writable"]:
                return None  # None == use the API path in EsxiClient
        except HypervisorError:
            pass
        sh = self.shell()
        if sh is None:
            raise HypervisorError(
                "this ESXi host will not accept writes over the API and no "
                "shell transport is configured",
                detail="The free vSphere Hypervisor licence makes the API "
                       "read-only. Either assign a paid licence / manage the "
                       "host through vCenter, or give SATOM SSH credentials "
                       "for this target so it can use the host shell. "
                       + EsxiShell.ENABLE_HINT)
        return sh

    def capabilities(self) -> Capabilities:
        notes: list[str] = []
        try:
            self.login()
        except HypervisorError as exc:
            return Capabilities(notes=(f"unreachable: {exc}",))
        standalone = self._about.get("apiType") == "HostAgent"
        if standalone:
            notes.append(
                "standalone host (no vCenter): the vSphere REST API is absent; "
                "SATOM drives it over SOAP /sdk")
        # Serial-over-network needs an explicitly configured virtual serial
        # port concentrator; there is no generic API console on a free ESXi.
        # Reporting this as available would promise unattended first boot and
        # then strand the run at the appliance password prompt.
        notes.append(
            "no API serial console — the appliance first-boot dialog needs "
            "the ESXi web console (MKS) or DHCP-based reachability")
        writable = True
        try:
            lic = self.license_info()
            writable = bool(lic["api_writable"])
            if not writable:
                notes.append(
                    f"licence {lic['name'] or lic['edition_key']!r} is the "
                    "free vSphere Hypervisor edition: the vSphere API is "
                    "READ-ONLY. Inventory works; creating, importing and "
                    "powering VMs is refused by the host. Assign a paid "
                    "licence or manage this host through vCenter to provision "
                    "from SATOM.")
            if lic["evaluation_expired"] and not writable:
                notes.append("the evaluation period has also expired")
        except HypervisorError as exc:
            # Unknown licence state is NOT permission to assume writable: a
            # run that dies at CreateVM_Task after reserving an address and a
            # DNS row is worse than one that never started.
            writable = False
            notes.append(f"licence state unreadable ({exc}) — write "
                         "operations treated as unavailable")
        # The shell is a SECOND write path, not a nicer name for the first.
        # It is only claimed after a command actually ran on it — a flag set
        # from an open port would promise a pipeline that dies three steps in,
        # after an address and a DNS row were already committed.
        shell_ok = False
        if not writable:
            st = self.shell_state()
            shell_ok = bool(st.reachable)
            if shell_ok:
                notes.append(
                    "host shell reachable over SSH — SATOM will create, power "
                    f"and delete machines with vim-cmd instead ({st.version})")
            elif st.error:
                notes.append("shell transport unavailable: " + st.error)
                if st.remedy:
                    notes.append(st.remedy)
        can_write = writable or shell_ok
        return Capabilities(
            create_vm=can_write, delete_vm=can_write, power_control=can_write,
            list_networks=True, list_datastores=True,
            # /folder upload is a plain HTTPS PUT and is NOT part of the VIM
            # API surface the licence gates; the shell can also stage a file.
            upload_image=can_write,
            ovf_import=writable,        # ImportVApp is API-only
            disk_import=shell_ok,       # vmkfstools is shell-only
            serial_console=False,
            notes=tuple(notes),
        )

    # -- property collector ---------------------------------------------
    def _retrieve(self, obj_type: str, path_set: list[str],
                  container: str = "") -> list[dict[str, Any]]:
        """One-shot container view + RetrievePropertiesEx."""
        vm = self._content.get("viewManager", "ViewManager")
        pc = self._content.get("propertyCollector", "ha-property-collector")
        root = container or self._content.get("rootFolder", HA_ROOT_FOLDER)
        body = (
            '<CreateContainerView xmlns="urn:vim25">'
            f'<_this type="ViewManager">{vm}</_this>'
            f'<container type="Folder">{root}</container>'
            f'<type>{obj_type}</type><recursive>true</recursive>'
            '</CreateContainerView>')
        rv = self._soap(body).find(".//v:returnval", NS)
        view = _txt(rv)
        props = "".join(f"<pathSet>{p}</pathSet>" for p in path_set)
        body = (
            '<RetrievePropertiesEx xmlns="urn:vim25">'
            f'<_this type="PropertyCollector">{pc}</_this><specSet>'
            f'<propSet><type>{obj_type}</type>{props}</propSet>'
            f'<objectSet><obj type="ContainerView">{view}</obj>'
            '<skip>true</skip><selectSet xsi:type="TraversalSpec" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<type>ContainerView</type><path>view</path><skip>false</skip>'
            '</selectSet></objectSet></specSet><options/>'
            '</RetrievePropertiesEx>')
        root_el = self._soap(body)
        out: list[dict[str, Any]] = []
        for objc in root_el.findall(".//v:objects", NS):
            obj = objc.find("v:obj", NS)
            rec: dict[str, Any] = {"_moref": _txt(obj),
                                   "_type": (obj.attrib.get("type", "")
                                             if obj is not None else "")}
            for ps in objc.findall("v:propSet", NS):
                rec[_txt(ps.find("v:name", NS))] = _txt(ps.find("v:val", NS))
            out.append(rec)
        # Container views are server-side objects; leaking them accumulates
        # until the session drops.
        try:
            self._soap('<DestroyView xmlns="urn:vim25">'
                       f'<_this type="ContainerView">{view}</_this>'
                       '</DestroyView>')
        except HypervisorError:
            pass
        return out

    def list_datastores(self, node: str = "") -> list[dict[str, Any]]:
        rows = self._retrieve("Datastore",
                              ["name", "summary.freeSpace",
                               "summary.capacity", "summary.type",
                               "summary.accessible"])
        out = []
        for r in rows:
            if (r.get("summary.accessible") or "true").lower() != "true":
                continue
            free = int(r.get("summary.freeSpace") or 0)
            out.append({"id": r["_moref"], "name": r.get("name", ""),
                        "type": r.get("summary.type", ""),
                        "avail_bytes": free,
                        "avail_gb": free // (1024 ** 3),
                        "total_gb": int(r.get("summary.capacity") or 0)
                        // (1024 ** 3),
                        "can_disk": True,
                        # A datastore is a filesystem: ESXi has no
                        # per-storage content roles like Proxmox, so
                        # both roles are always true here.
                        "can_import": True})
        return sorted(out, key=lambda x: -x["avail_bytes"])

    def list_networks(self, node: str = "") -> list[dict[str, Any]]:
        rows = self._retrieve("Network", ["name"])
        return sorted(({"id": r["_moref"], "name": r.get("name", ""),
                        "kind": r.get("_type", "Network"), "active": True}
                       for r in rows), key=lambda x: x["name"])

    def list_vms(self, node: str = "") -> list[dict[str, Any]]:
        rows = self._retrieve("VirtualMachine",
                              ["name", "runtime.powerState",
                               "config.guestFullName"])
        return [{"vmid": r["_moref"], "name": r.get("name", ""),
                 "status": r.get("runtime.powerState", ""),
                 "guest": r.get("config.guestFullName", "")} for r in rows]

    def _resource_pool(self) -> str:
        rows = self._retrieve("ResourcePool", ["name"])
        if not rows:
            raise HypervisorError("ESXi exposes no resource pool")
        return rows[0]["_moref"]

    def _vm_folder(self) -> str:
        rows = self._retrieve("Datacenter", ["name", "vmFolder"])
        if not rows:
            raise HypervisorError("ESXi exposes no datacenter")
        return rows[0].get("vmFolder") or "ha-folder-vm"

    def _host_system(self) -> str:
        rows = self._retrieve("HostSystem", ["name"])
        if not rows:
            raise HypervisorError("ESXi exposes no host system")
        return rows[0]["_moref"]

    # -- machine lifecycle ----------------------------------------------
    def create_vm(self, spec: VmSpec) -> VmRef:
        """Create an empty shell VM.

        Attaching a Fortinet appliance disk is a *separate* operation
        (``import_ovf``): the shipped VMDKs are streamOptimized and only the
        HttpNfcLease path converts them without shell access to the host.
        """
        self.login()
        ds = spec.datastore or (self.list_datastores() or [{}])[0].get("name")
        if not ds:
            raise HypervisorError("no datastore available for the new VM")
        pool, folder, host = (self._resource_pool(), self._vm_folder(),
                              self._host_system())
        devices = (
            '<deviceChange><operation>add</operation><device '
            'xsi:type="VirtualLsiLogicController" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<key>-1</key><busNumber>0</busNumber>'
            '<sharedBus>noSharing</sharedBus></device></deviceChange>')
        if spec.network:
            devices += (
                '<deviceChange><operation>add</operation><device '
                'xsi:type="VirtualVmxnet3" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
                '<key>-2</key><backing xsi:type="VirtualEthernetCardNetwork'
                'BackingInfo"><deviceName>'
                f'{xml_escape(spec.network)}</deviceName></backing>'
                '<connectable><startConnected>true</startConnected>'
                '<allowGuestControl>true</allowGuestControl>'
                '<connected>true</connected></connectable>'
                '</device></deviceChange>')
        if spec.serial:
            devices += (
                '<deviceChange><operation>add</operation><device '
                'xsi:type="VirtualSerialPort" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
                '<key>-3</key><backing xsi:type="VirtualSerialPortURIBacking'
                'Info"><serviceURI>telnet://:0</serviceURI>'
                '<direction>server</direction></backing>'
                '<yieldOnPoll>true</yieldOnPoll></device></deviceChange>')
        body = (
            '<CreateVM_Task xmlns="urn:vim25">'
            f'<_this type="Folder">{folder}</_this><config>'
            f'<name>{xml_escape(spec.name)}</name>'
            f'<guestId>{xml_escape(spec.guest_os or "other4xLinux64Guest")}'
            '</guestId>'
            f'<files><vmPathName>[{xml_escape(ds)}]</vmPathName></files>'
            f'<numCPUs>{int(spec.cpus)}</numCPUs>'
            f'<memoryMB>{int(spec.memory_mb)}</memoryMB>'
            f'{devices}</config>'
            f'<pool type="ResourcePool">{pool}</pool>'
            f'<host type="HostSystem">{host}</host>'
            '</CreateVM_Task>')
        task = _txt(self._soap(body).find(".//v:returnval", NS))
        result = self.wait_task(task, timeout=600)
        moref = result.get("result", "")
        if not moref:
            raise HypervisorError("ESXi created no VM reference",
                                  detail=str(result))
        return VmRef(backend="esxi", identifier=moref, name=spec.name,
                     raw={"task": task, "datastore": ds})

    def wait_task(self, task: str, timeout: int = 600) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            rows = self._retrieve_task(task)
            state = rows.get("info.state", "")
            if state == "success":
                return {"state": state, "result": rows.get("info.result", "")}
            if state == "error":
                raise HypervisorError(
                    "ESXi task failed: "
                    + (rows.get("info.error.localizedMessage") or "unknown"),
                    detail=task)
            time.sleep(2)
        raise HypervisorError(f"ESXi task did not finish in {timeout}s",
                              detail=task, retryable=True)

    def _retrieve_task(self, task: str) -> dict[str, Any]:
        pc = self._content.get("propertyCollector", "ha-property-collector")
        body = (
            '<RetrievePropertiesEx xmlns="urn:vim25">'
            f'<_this type="PropertyCollector">{pc}</_this><specSet>'
            '<propSet><type>Task</type><pathSet>info.state</pathSet>'
            '<pathSet>info.result</pathSet>'
            '<pathSet>info.error.localizedMessage</pathSet></propSet>'
            f'<objectSet><obj type="Task">{task}</obj></objectSet>'
            '</specSet><options/></RetrievePropertiesEx>')
        root = self._soap(body)
        rec: dict[str, Any] = {}
        for ps in root.findall(".//v:propSet", NS):
            rec[_txt(ps.find("v:name", NS))] = _txt(ps.find("v:val", NS))
        return rec

    def power_on(self, ref: VmRef) -> None:
        body = ('<PowerOnVM_Task xmlns="urn:vim25">'
                f'<_this type="VirtualMachine">{ref.identifier}</_this>'
                '</PowerOnVM_Task>')
        self.wait_task(_txt(self._soap(body).find(".//v:returnval", NS)))

    def power_off(self, ref: VmRef, *, hard: bool = False) -> None:
        if hard:
            body = ('<PowerOffVM_Task xmlns="urn:vim25">'
                    f'<_this type="VirtualMachine">{ref.identifier}</_this>'
                    '</PowerOffVM_Task>')
            self.wait_task(_txt(self._soap(body).find(".//v:returnval", NS)))
        else:
            self._soap('<ShutdownGuest xmlns="urn:vim25">'
                       f'<_this type="VirtualMachine">{ref.identifier}</_this>'
                       '</ShutdownGuest>')

    def delete_vm(self, ref: VmRef) -> None:
        try:
            self.power_off(ref, hard=True)
        except HypervisorError:
            pass  # already off, or never powered on
        body = ('<Destroy_Task xmlns="urn:vim25">'
                f'<_this type="VirtualMachine">{ref.identifier}</_this>'
                '</Destroy_Task>')
        try:
            self.wait_task(_txt(self._soap(body).find(".//v:returnval", NS)))
        except HypervisorError as exc:
            if "not found" in str(exc).lower() or "ManagedObjectNotFound" in (
                    exc.detail or ""):
                return  # the goal is "it must not be there"
            raise

    def vm_status(self, ref: VmRef) -> dict[str, Any]:
        pc = self._content.get("propertyCollector", "ha-property-collector")
        body = (
            '<RetrievePropertiesEx xmlns="urn:vim25">'
            f'<_this type="PropertyCollector">{pc}</_this><specSet>'
            '<propSet><type>VirtualMachine</type><pathSet>name</pathSet>'
            '<pathSet>runtime.powerState</pathSet>'
            '<pathSet>guest.ipAddress</pathSet></propSet>'
            f'<objectSet><obj type="VirtualMachine">{ref.identifier}</obj>'
            '</objectSet></specSet><options/></RetrievePropertiesEx>')
        rec: dict[str, Any] = {}
        for ps in self._soap(body).findall(".//v:propSet", NS):
            rec[_txt(ps.find("v:name", NS))] = _txt(ps.find("v:val", NS))
        return {"status": rec.get("runtime.powerState", ""),
                "name": rec.get("name", ""),
                "ip": rec.get("guest.ipAddress", ""), "raw": rec}
