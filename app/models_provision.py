"""Provisioning models — hypervisor targets and the run state machine.

Kept out of ``models.py`` on purpose (same reasoning as ``models_firmware`` and
``models_trust``): the feature stays self-contained and commits without
touching a file other sessions are editing. Imported by
``app.views.provision`` before ``db.create_all()`` in the app factory, so both
tables are auto-created at boot — no manual migration.

**Why a state machine and not a single "provision" function.** An end-to-end
run touches five systems that fail independently: IPAM, DNS, the hypervisor,
the appliance itself, and the certificate authority. A function that dies in
the middle leaves a reserved IP, a DNS row, and a half-built VM that nobody
cleans up, and the operator has no way to tell which of those actually
happened. Every step here records enough to be undone, and ``rollback``
retraces them in reverse.
"""
from __future__ import annotations

import json
from datetime import datetime

from .extensions import db
from .services.encryption import decrypt as _dec, encrypt as _enc

#: Ordered pipeline. ``ProvisionRun.step`` is always one of these, and the
#: index in this tuple is what "how far did it get" means. Appending a step is
#: safe; reordering is not (existing rows would claim the wrong progress).
STEPS: tuple[str, ...] = (
    "draft",
    "ip_reserved",
    "dns_created",
    "vm_created",
    "image_attached",
    "booted",
    "reachable",
    "onboarded",
    "cert_installed",
    "profile_applied",
    "done",
)

TERMINAL = ("done", "failed", "aborted")

#: How much of the pipeline the operator asked for. The product cannot promise
#: unattended first boot on every hypervisor (a standalone ESXi has no API
#: serial console), so the mode is a choice, not a guess.
MODES = {
    "full": "Full — create the VM, boot it, configure it and onboard it",
    "semi": "Semi — create and boot the VM, then stop for the first-boot "
            "console; resume once the appliance answers",
    "dhcp": "DHCP — create and boot; the appliance takes a lease and SATOM "
            "finds it, then continues",
    "vm_only": "VM only — create the machine and stop (configure by hand)",
    "config_only": "Config only — the machine already exists; reserve the "
                   "address, issue the certificate and apply the profile",
}


class HypervisorTarget(db.Model):
    """A Proxmox or ESXi endpoint SATOM may build machines on."""

    __tablename__ = "hypervisor_targets"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False, unique=True)
    backend = db.Column(db.String(16), nullable=False)  # proxmox | esxi
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer)
    username = db.Column(db.String(128), nullable=False, default="")
    password_enc = db.Column(db.Text, nullable=False, default="")
    # Proxmox API token (optional, preferred over user+password when present).
    token_id = db.Column(db.String(128), default="")
    token_secret_enc = db.Column(db.Text, default="")
    # Defaults off: hypervisors ship self-signed certificates. It stays a
    # per-target setting rather than a hardcoded False so a site that imported
    # its CA into the SATOM trust store can turn it on and have it mean
    # something. Same reasoning as Appliance.verify_ssl.
    verify_ssl = db.Column(db.Boolean, nullable=False, default=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    #: Preferred placement, remembered so the operator does not re-pick it.
    default_node = db.Column(db.String(64), default="")
    default_datastore = db.Column(db.String(128), default="")
    default_network = db.Column(db.String(128), default="")
    notes = db.Column(db.Text, default="")
    last_status = db.Column(db.String(16), default="unknown")
    last_checked_at = db.Column(db.DateTime)
    last_error = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # -- secrets --------------------------------------------------------
    @property
    def password(self) -> str:
        return _dec(self.password_enc) if self.password_enc else ""

    @password.setter
    def password(self, plaintext: str) -> None:
        self.password_enc = _enc(plaintext or "")

    @property
    def token_secret(self) -> str:
        return _dec(self.token_secret_enc) if self.token_secret_enc else ""

    @token_secret.setter
    def token_secret(self, plaintext: str) -> None:
        self.token_secret_enc = _enc(plaintext or "") if plaintext else ""

    def client(self, timeout: int = 30):
        """Build the backend client for this row. Never called at import."""
        from .services.hypervisors import build_client
        return build_client(self, timeout=timeout)

    def public(self) -> dict:
        """Shape handed to the browser. Secrets never cross this boundary."""
        return {
            "id": self.id, "name": self.name, "backend": self.backend,
            "host": self.host, "port": self.port, "username": self.username,
            "verify_ssl": bool(self.verify_ssl), "enabled": bool(self.enabled),
            "has_password": bool(self.password_enc),
            "has_token": bool(self.token_id and self.token_secret_enc),
            "token_id": self.token_id or "",
            "default_node": self.default_node or "",
            "default_datastore": self.default_datastore or "",
            "default_network": self.default_network or "",
            "last_status": self.last_status or "unknown",
            "last_error": self.last_error or "",
            "last_checked_at": (self.last_checked_at.isoformat()
                                if self.last_checked_at else ""),
            "notes": self.notes or "",
        }


class ProvisionRun(db.Model):
    """One attempt to bring an appliance into existence."""

    __tablename__ = "provision_runs"

    id = db.Column(db.Integer, primary_key=True)
    # Product ADOM this run belongs to. Set from the request scope, never from
    # a form field: a run that could re-label its own ADOM would let a
    # FortiADC session build a FortiWeb and file it under FortiWeb.
    product = db.Column(db.String(32), nullable=False, default="")
    name = db.Column(db.String(64), nullable=False)
    mode = db.Column(db.String(16), nullable=False, default="semi")

    target_id = db.Column(db.Integer,
                          db.ForeignKey("hypervisor_targets.id"))
    firmware_id = db.Column(db.Integer)   # FirmwareImage.id (install image)
    appliance_id = db.Column(db.Integer)  # set once the device is onboarded

    # Placement + addressing, all captured up front so a resumed run does not
    # have to re-ask.
    node = db.Column(db.String(64), default="")
    datastore = db.Column(db.String(128), default="")
    network = db.Column(db.String(128), default="")
    cpus = db.Column(db.Integer, default=4)
    memory_mb = db.Column(db.Integer, default=4096)
    disk_gb = db.Column(db.Integer, default=0)

    mgmt_ip = db.Column(db.String(64), default="")
    netmask = db.Column(db.String(64), default="")
    gateway = db.Column(db.String(64), default="")
    hostname = db.Column(db.String(255), default="")
    #: True when the address came from the IPAM provider (so rollback releases
    #: it). A user-typed address is not ours to release.
    ip_from_ipam = db.Column(db.Boolean, nullable=False, default=False)
    dns_record_id = db.Column(db.String(64), default="")

    admin_user = db.Column(db.String(64), default="admin")
    admin_password_enc = db.Column(db.Text, default="")

    profile_id = db.Column(db.Integer)   # SystemProfile handed to /provisioning

    step = db.Column(db.String(32), nullable=False, default="draft")
    status = db.Column(db.String(16), nullable=False, default="draft")
    vm_ref = db.Column(db.Text, default="")     # JSON VmRef — the undo handle
    log_json = db.Column(db.Text, default="[]")
    error = db.Column(db.Text, default="")

    created_by = db.Column(db.String(64), default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    # -- secrets --------------------------------------------------------
    @property
    def admin_password(self) -> str:
        return _dec(self.admin_password_enc) if self.admin_password_enc else ""

    @admin_password.setter
    def admin_password(self, plaintext: str) -> None:
        self.admin_password_enc = _enc(plaintext or "") if plaintext else ""

    # -- log ------------------------------------------------------------
    def log(self) -> list[dict]:
        try:
            rows = json.loads(self.log_json or "[]")
        except (ValueError, TypeError):
            return []
        return rows if isinstance(rows, list) else []

    def add_log(self, step: str, ok: bool, detail: str = "") -> None:
        rows = self.log()
        rows.append({"step": step, "ok": bool(ok), "detail": detail[:2000],
                     "at": datetime.utcnow().isoformat(timespec="seconds")})
        self.log_json = json.dumps(rows[-200:])

    # -- progress -------------------------------------------------------
    def step_index(self) -> int:
        try:
            return STEPS.index(self.step)
        except ValueError:
            return 0

    def progress_pct(self) -> int:
        return int(self.step_index() * 100 / (len(STEPS) - 1))

    def is_terminal(self) -> bool:
        return self.status in TERMINAL

    def ref(self) -> dict:
        try:
            return json.loads(self.vm_ref or "{}") or {}
        except (ValueError, TypeError):
            return {}

    def public(self) -> dict:
        return {
            "id": self.id, "name": self.name, "product": self.product,
            "mode": self.mode, "step": self.step, "status": self.status,
            "progress": self.progress_pct(), "error": self.error or "",
            "mgmt_ip": self.mgmt_ip or "", "hostname": self.hostname or "",
            "node": self.node or "", "datastore": self.datastore or "",
            "network": self.network or "", "appliance_id": self.appliance_id,
            "target_id": self.target_id, "firmware_id": self.firmware_id,
            "created_by": self.created_by or "",
            "created_at": self.created_at.isoformat() if self.created_at else "",
            "updated_at": self.updated_at.isoformat() if self.updated_at else "",
            "log": self.log(),
        }
