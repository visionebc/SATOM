"""SQLAlchemy ORM models."""
from __future__ import annotations

import enum
import json
import os
from datetime import datetime
from typing import Any

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from . import permissions as _perm
from .extensions import db


# ---------------------------------------------------------------------------
# RBAC primitives
# ---------------------------------------------------------------------------

class Role(enum.Enum):
    readonly = "readonly"
    operator = "operator"
    admin = "admin"


class Permission:
    VIEW = "view"
    BACKUP = "backup"
    CONFIG_WRITE = "config_write"
    REGISTRY_EDIT = "registry_edit"
    USER_MANAGE = "user_manage"


ROLE_PERMISSIONS: dict[str, set[str]] = {
    Role.readonly.value: {Permission.VIEW},
    Role.operator.value: {Permission.VIEW, Permission.BACKUP, Permission.CONFIG_WRITE},
    Role.admin.value: {
        Permission.VIEW,
        Permission.BACKUP,
        Permission.CONFIG_WRITE,
        Permission.REGISTRY_EDIT,
        Permission.USER_MANAGE,
    },
}


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    # ``role`` is retained for back-compat and display (badges/counters). The
    # authoritative permission source is ``profile`` when one is assigned.
    role = db.Column(db.String(16), nullable=False, default=Role.readonly.value)
    profile_id = db.Column(
        db.Integer, db.ForeignKey("profiles.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # External authentication + local 2FA (added 2026-06-30)
    auth_source = db.Column(db.String(16), nullable=False, default="local")
    totp_secret = db.Column(db.String(512), nullable=True)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    recovery_email = db.Column(db.String(256), nullable=True)
    backup_codes = db.Column(db.Text, nullable=True)

    # Per-account brute-force lockout (the IP rate-limit alone can't isolate a
    # targeted account when attempts arrive from many clients).
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    # audit relationship (back-ref from AuditLog)
    audit_logs = db.relationship("AuditLog", backref="user", lazy="dynamic")
    profile = db.relationship("Profile", lazy="joined", foreign_keys=[profile_id])

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_local(self) -> bool:
        """True for accounts that authenticate against the local DB."""
        return (self.auth_source or "local") == "local"

    @property
    def is_external(self) -> bool:
        """True for directory (AD/LDAP/RADIUS) accounts."""
        return not self.is_local

    @property
    def effective_permissions(self) -> set[str]:
        """The authoritative permission set for this user.

        Profile assigned  -> the profile's granular keys plus the legacy coarse
                             keys they imply (so old gates keep working).
        No profile        -> fall back to the legacy ``role`` table, expanded
                             with the granular keys those coarse keys imply.
        """
        if self.profile is not None:
            return self.profile.effective
        # No profile (un-migrated / freshly built object): treat the legacy
        # role as its equivalent system profile so both granular and coarse
        # gates resolve exactly like a migrated user would.
        gran = _perm.SYSTEM_PROFILES.get(_perm.role_to_profile_name(self.role), set())
        return _perm.expand(gran)

    def can(self, permission: str) -> bool:
        return permission in self.effective_permissions

    @property
    def permissions(self) -> set[str]:
        return self.effective_permissions

    @property
    def is_admin_capable(self) -> bool:
        """True if this user can administer access itself (manage users AND
        profiles). Drives the capability-based anti-lockout guard."""
        return _perm.ADMIN_CAPABILITIES <= self.effective_permissions

    def __repr__(self) -> str:
        return f"<User {self.username!r} role={self.role!r} profile_id={self.profile_id}>"


# ---------------------------------------------------------------------------
# Profile — admin-definable permission profile (granular keys)
# ---------------------------------------------------------------------------

class Profile(db.Model):
    """A named set of granular permission keys an admin composes once and
    assigns to users. The three seeded ``is_system`` profiles (readonly /
    operator / admin) reproduce the legacy 3-role behavior and cannot be
    renamed or deleted; custom profiles are fully editable."""

    __tablename__ = "profiles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False, index=True)
    description = db.Column(db.Text, nullable=True, default="")
    permissions = db.Column(db.Text, nullable=False, default="[]")  # JSON list of keys
    is_system = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    @property
    def permission_set(self) -> set[str]:
        try:
            raw = json.loads(self.permissions or "[]")
        except (ValueError, TypeError):
            return set()
        if not isinstance(raw, list):
            return set()
        # Only keep keys that exist in the current catalog — drops stale/bogus.
        return {k for k in raw if _perm.is_valid_key(k)}

    @permission_set.setter
    def permission_set(self, value) -> None:
        clean = sorted({k for k in (value or set()) if _perm.is_valid_key(k)})
        self.permissions = json.dumps(clean)

    def has(self, key: str) -> bool:
        return key in self.permission_set

    @property
    def effective(self) -> set[str]:
        """Granular keys plus the legacy coarse keys they imply."""
        return _perm.expand(self.permission_set)

    @property
    def derived_coarse(self) -> set[str]:
        return _perm.derive_coarse(self.permission_set)

    @property
    def is_admin_capable(self) -> bool:
        return _perm.ADMIN_CAPABILITIES <= self.effective

    @property
    def role_label(self) -> str:
        """Best-effort legacy role string for display."""
        return _perm.coarse_for_role_label(self.effective)

    def __repr__(self) -> str:
        return f"<Profile {self.name!r} system={self.is_system} perms={len(self.permission_set)}>"


# ---------------------------------------------------------------------------
# Appliance
# ---------------------------------------------------------------------------

def _fernet():
    """Lazy-load Fernet to avoid import-time env dependency."""
    from cryptography.fernet import Fernet
    key = os.environ.get("FERNET_KEY")
    if not key:
        raise RuntimeError("FERNET_KEY environment variable is not set.")
    return Fernet(key.encode() if isinstance(key, str) else key)


def _parse_tags(raw):
    """Tolerant tags parser: accepts JSON array, comma string, or empty."""
    if not raw:
        return []
    raw = raw.strip()
    if raw.startswith('['):
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            pass
    return [t.strip() for t in raw.split(',') if t.strip()]


class Appliance(db.Model):
    __tablename__ = "appliances"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False, index=True)
    kind = db.Column(db.String(16), nullable=False, default="fortiweb")  # 'fortiweb'|'fortiadc'
    host = db.Column(db.String(253), nullable=False)
    port = db.Column(db.Integer, nullable=False, default=443)
    username = db.Column(db.String(64), nullable=False)
    password_enc = db.Column(db.Text, nullable=False)  # Fernet-encrypted
    verify_ssl = db.Column(db.Boolean, nullable=False, default=True)
    vdom = db.Column(db.String(64), nullable=True)
    tags = db.Column(db.Text, nullable=True)           # JSON list of strings
    department = db.Column(db.String(128), nullable=True)
    zone = db.Column(db.String(128), nullable=True)
    line = db.Column(db.String(128), nullable=True)
    ssh_port = db.Column(db.Integer, nullable=True, default=22)
    # --- Maintenance mode (visibility gate) -----------------------------
    # True => the appliance is HIDDEN from anyone lacking the
    # 'appliances.view_maintenance' permission (operators / read-only).
    # Admins still see it (with a badge) and can use it for testing.
    # Enforced ONLY through models.visible_appliances /
    # visible_appliance_or_404 — never a stored 'hidden' flag. Default
    # False so every existing device stays visible after the migration.
    maintenance = db.Column(db.Boolean, nullable=False, default=False)
    # --- HA cluster (self-referential) ----------------------------------
    # node 0 = logical cluster container; members = ordinary appliances
    # pointing at node 0 via parent_id. See docs/superpowers/plans.
    is_cluster = db.Column(db.Boolean, nullable=False, default=False)
    is_cluster_member = db.Column(db.Boolean, nullable=False, default=False)
    parent_id = db.Column(
        db.Integer, db.ForeignKey('appliances.id', ondelete='CASCADE'),
        nullable=True, index=True,
    )
    ha_mode = db.Column(db.String(16), nullable=True)        # 'per_node'|'vip' (node 0)
    ha_role_hint = db.Column(db.String(16), nullable=True)   # 'primary'|'secondary' (member identity)
    ha_vip = db.Column(db.String(253), nullable=True)        # shared management VIP (vip mode)
    # Physical inventory — documentation only (not derived from the live device).
    hw_type = db.Column(db.String(16), nullable=False, default="unknown")  # 'hardware'|'vm'|'unknown'
    model = db.Column(db.String(128), nullable=True)        # e.g. "FortiWeb 600F"
    firmware = db.Column(db.String(64), nullable=True)      # last-known OS version string from system status
    datasheet_filename = db.Column(db.String(256), nullable=True)  # original PDF name; file on disk is <id>.pdf
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Cached connectivity status, populated by status probes (see probe_status).
    last_status = db.Column(db.String(16), nullable=False, default="unknown")
    last_checked_at = db.Column(db.DateTime, nullable=True)

    # Documented physical interfaces (manual; replace-all on edit). Cascade so
    # deleting an appliance removes its interface rows.
    interfaces = db.relationship(
        "ApplianceInterface",
        backref="appliance",
        cascade="all, delete-orphan",  # ORM-side cascade (portable; SQLite FK enforcement is off by default)
        order_by="ApplianceInterface.sort_order",
    )

    # Cluster members (node 0 -> p1/p2). ORM cascade so deleting a node 0
    # removes its member rows. remote_side=[id] makes this an adjacency list.
    members = db.relationship(
        'Appliance',
        backref=db.backref('parent', remote_side=[id]),
        cascade='all, delete-orphan',
        single_parent=True,
        foreign_keys='Appliance.parent_id',
        order_by='Appliance.ha_role_hint',
    )

    @property
    def is_standalone(self) -> bool:
        return not self.is_cluster and not self.is_cluster_member

    def cluster_members(self):
        """Member nodes ordered by role hint then name (stable display)."""
        return sorted(self.members, key=lambda m: (m.ha_role_hint or 'zz', m.name))

    @property
    def password(self) -> str:
        return _fernet().decrypt(self.password_enc.encode()).decode()

    @password.setter
    def password(self, plaintext: str) -> None:
        self.password_enc = _fernet().encrypt(plaintext.encode()).decode()

    def set_password(self, plaintext: str) -> None:
        self.password = plaintext

    def _own_client(self, timeout: float = 30.0):
        """The vendor client for THIS row's own host/creds (no HA resolution)."""
        from .clients.fortiweb import FortiWebClient
        from .clients.fortiadc import FortiADCClient
        from .clients.fortianalyzer import FortiAnalyzerClient
        if self.kind == "fortiadc":
            return FortiADCClient(self, timeout=timeout)
        if self.kind == "fortianalyzer":
            return FortiAnalyzerClient(self, timeout=timeout)
        return FortiWebClient(self, timeout=timeout)

    def build_client(self, timeout: float = 30.0):
        """Vendor client for this appliance. For a cluster node 0 this resolves
        to the live write target (primary member, or the VIP) so callers never
        need to know about HA; standalone appliances are unaffected."""
        if self.is_cluster:
            from .services.ha import resolve_write_target
            return resolve_write_target(self)._own_client(timeout=timeout)
        return self._own_client(timeout=timeout)

    def probe_status(self, timeout: float = 6.0) -> str:
        """Live connectivity probe -> 'online' | 'offline'. No DB writes, so it
        is safe to call from a worker thread."""
        try:
            self.build_client(timeout=timeout).status_check()
            return "online"
        except Exception:
            return "offline"

    @property
    def fw_version(self) -> str:
        """Short X.Y.Z firmware version, taken from the live firmware string
        (authoritative running OS) and falling back to the documented model."""
        import re as _re
        for src in (self.firmware, self.model):
            if src:
                m = _re.search(r"\d+\.\d+(?:\.\d+)?", src)
                if m:
                    return m.group(0)
        return ""

    @property
    def kind_badge(self) -> str:
        """Compact type+version label for the appliances table.
        fortiweb -> FW_VM_7.6.8 / FW_HW_7.6.8 (FW_7.6.8 if platform unknown);
        fortiadc -> FADC."""
        if self.kind == "fortiadc":
            return "FADC"
        if self.kind == "fortiweb":
            plat = {"vm": "VM", "hardware": "HW"}.get((self.hw_type or "").lower())
            ver = self.fw_version
            parts = ["FW"]
            if plat:
                parts.append(plat)
            if ver:
                parts.append(ver)
            return "_".join(parts)
        return self.kind

    @property
    def kind_tooltip(self) -> str:
        """Full, human-readable version detail for the badge hover."""
        parts = []
        if self.firmware:
            parts.append(f"Firmware: {self.firmware}")
        if self.model:
            parts.append(f"Model: {self.model}")
        plat = {"vm": "Virtual (VM)", "hardware": "Hardware appliance"}.get((self.hw_type or "").lower())
        if plat:
            parts.append(f"Platform: {plat}")
        return "\n".join(parts) if parts else (self.kind or "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "verify_ssl": self.verify_ssl,
            "maintenance": bool(self.maintenance),
            "vdom": self.vdom,
            "tags": _parse_tags(self.tags),
            "department": self.department,
            "zone": self.zone,
            "line": self.line,
            "is_cluster": bool(self.is_cluster),
            "is_cluster_member": bool(self.is_cluster_member),
            "parent_id": self.parent_id,
            "ha_mode": self.ha_mode,
            "ha_role_hint": self.ha_role_hint,
            "ha_vip": self.ha_vip,
            "ssh_port": self.ssh_port,
            "hw_type": self.hw_type or "unknown",
            "model": self.model,
            "datasheet_filename": self.datasheet_filename,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "status": self.last_status or "unknown",
            "last_checked_at": self.last_checked_at.isoformat() if self.last_checked_at else None,
        }

    def inventory_view(self) -> dict[str, Any]:
        """Read-only physical-inventory payload for the architecture modal.

        Pure data (no URLs); the view layer adds datasheet/detail URLs since
        ``url_for`` needs an application/request context.
        """
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "hw_type": self.hw_type or "unknown",
            "model": self.model or "",
            "host": self.host,
            "port": self.port,
            "vdom": self.vdom or "",
            "zone": self.zone or "",
            "line": self.line or "",
            "department": self.department or "",
            "status": self.last_status or "unknown",
            "has_datasheet": bool(self.datasheet_filename),
            "datasheet_filename": self.datasheet_filename or "",
            "interfaces": [
                i.to_dict()
                for i in sorted(self.interfaces, key=lambda x: (x.sort_order or 0, x.id or 0))
            ],
        }

    def __repr__(self) -> str:
        return f"<Appliance {self.name!r} kind={self.kind!r} host={self.host!r}>"


# ---------------------------------------------------------------------------
# Appliance visibility — the maintenance-mode gate (SINGLE choke point).
#
# Every USER-FACING appliance listing must route through visible_appliances();
# every user-facing by-id load through visible_appliance_or_404(). Background
# services (bulk, device_sync, scheduled actions, deep capture) intentionally
# act on the WHOLE fleet and keep using the raw query, so an admin's automation
# still reaches a maintenance box — that is the point of maintenance mode.
# ---------------------------------------------------------------------------

VIEW_MAINTENANCE_PERM = "appliances.view_maintenance"


def can_view_maintenance(user=None) -> bool:
    """True if *user* (default: the logged-in user) may see maintenance-mode
    appliances. Fails CLOSED on any error / anonymous user (cannot see)."""
    if user is None:
        from flask_login import current_user
        user = current_user
    try:
        return bool(getattr(user, "is_authenticated", False)) and user.can(VIEW_MAINTENANCE_PERM)
    except Exception:  # noqa: BLE001 — visibility must never crash a page; deny.
        return False


def visible_appliances(query=None, user=None):
    """Scope an Appliance query to what *user* may see: maintenance-mode rows
    are dropped unless the user holds ``appliances.view_maintenance``, and the
    active ADOM only sees its own product's devices (FortiADC -> fortiadc,
    FortiWeb -> everything else, Global/workers -> all)."""
    q = Appliance.query if query is None else query
    from .services.product_scope import scope_appliance_query
    q = scope_appliance_query(q, Appliance.kind)
    if can_view_maintenance(user):
        return q
    return q.filter(Appliance.maintenance.is_(False))


def visible_appliance_or_404(id, user=None):
    """Load one appliance by id, but abort 404 (never 403 — do not confirm the
    row exists) when it is in maintenance and *user* may not see it."""
    from flask import abort
    a = Appliance.query.get(id)
    if a is None or (a.maintenance and not can_view_maintenance(user)):
        abort(404)
    return a


# ---------------------------------------------------------------------------
# ApplianceInterface — documented physical port and what it connects to.
# Manual documentation (not pulled from the device); rebuilt replace-all when
# the appliance is edited. Removed with its appliance via ON DELETE CASCADE.
# ---------------------------------------------------------------------------

class ApplianceInterface(db.Model):
    __tablename__ = "appliance_interfaces"

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(
        db.Integer,
        db.ForeignKey("appliances.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = db.Column(db.String(64), nullable=False, default="")          # e.g. "port1"
    if_type = db.Column(db.String(64), nullable=True)                    # e.g. "10G SFP+"
    connected_to = db.Column(db.String(256), nullable=True)             # peer device + port
    ip_address = db.Column(db.String(64), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    sort_order = db.Column(db.Integer, nullable=False, default=0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name or "",
            "if_type": self.if_type or "",
            "connected_to": self.connected_to or "",
            "ip_address": self.ip_address or "",
            "notes": self.notes or "",
            "sort_order": self.sort_order or 0,
        }

    def __repr__(self) -> str:
        return f"<ApplianceInterface {self.name!r} of appliance={self.appliance_id}>"


# ---------------------------------------------------------------------------
# ApplianceNic - cached hardware address per port.
#
# Deliberately SEPARATE from ApplianceInterface: that table is operator-authored
# documentation and is rebuilt replace-all whenever the appliance is edited, so
# a machine-populated MAC would be wiped by the next save. MACs are not exposed
# by the REST cmdb on any of the three products (verified live), so they are
# probed with a read-only CLI command over SSH and cached here.
# ---------------------------------------------------------------------------

class ApplianceNic(db.Model):
    __tablename__ = "appliance_nics"

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(
        db.Integer,
        db.ForeignKey("appliances.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = db.Column(db.String(64), nullable=False, default="")     # e.g. "port1"
    mac = db.Column(db.String(32), nullable=True)                   # AA:BB:CC:DD:EE:FF
    source = db.Column(db.String(16), nullable=False, default="cli")
    fetched_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("appliance_id", "name", name="uq_appliance_nic"),
    )

    def __repr__(self) -> str:
        return f"<ApplianceNic {self.name!r} {self.mac!r} of appliance={self.appliance_id}>"


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username = db.Column(db.String(64), nullable=False, default="anonymous")
    action = db.Column(db.String(128), nullable=False)
    target = db.Column(db.String(256), nullable=True, default="")
    extra = db.Column(db.Text, nullable=True, default="{}")   # JSON-serialised dict
    ip_address = db.Column(db.String(45), nullable=True)      # IPv4 or IPv6
    # ADOM/product the action was performed in ('' / NULL = unscoped legacy).
    product = db.Column(db.String(16), nullable=True, default="")
    timestamp = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False, index=True
    )

    def __repr__(self) -> str:
        return f"<AuditLog {self.action!r} by {self.username!r} at {self.timestamp}>"


# ---------------------------------------------------------------------------
# AppSetting
# ---------------------------------------------------------------------------

class AppSetting(db.Model):
    """Key/value app settings. CONVENTION (product separation): keys are
    global by default (e.g. ``certmgr.*`` — one CA for the whole platform);
    a product-specific setting MUST be namespaced with the product prefix
    (``adc.*`` for FortiADC) so ADOMs never read each other's knobs."""

    __tablename__ = "app_settings"

    key = db.Column(db.String(128), primary_key=True)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    @classmethod
    def get(cls, key: str, default: str | None = None) -> str | None:
        row = cls.query.get(key)
        return row.value if row else default

    @classmethod
    def set(cls, key: str, value: str) -> None:
        row = cls.query.get(key)
        if row is None:
            row = cls(key=key)
            db.session.add(row)
        row.value = value
        row.updated_at = datetime.utcnow()
        db.session.commit()

    def __repr__(self) -> str:
        return f"<AppSetting {self.key!r}>"


# ---------------------------------------------------------------------------
# RegistryEndpoint — the DB-backed API endpoint registry
# ---------------------------------------------------------------------------

class RegistryEndpoint(db.Model):
    """One REST endpoint of the API registry (logical name → URN).

    The git-tracked ``endpoints.yaml`` is only the SEED: at boot an insert-only
    sync adds names the DB doesn't have yet (``registry.loader.seed_from_yaml``).
    Operator edits live here and always win; ``pg_dump`` backs them up with the
    rest of the runtime data. ``enabled=False`` is a SOFT delete — the row must
    stay so the boot seeder does not resurrect the name from the YAML.

    Two-dimensional key (product, api_version) so a future FortiWeb API v3 or a
    second product (FortiADC) is schema-ready — today everything is
    ``fortiweb`` / ``v2.0``.
    """

    __tablename__ = "registry_endpoints"

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False, default="fortiweb", index=True)
    api_version = db.Column(db.String(16), nullable=False, default="v2.0")
    name = db.Column(db.String(128), nullable=False)
    urn = db.Column(db.String(255), nullable=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    updated_by = db.Column(db.String(64), nullable=True)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    __table_args__ = (
        db.UniqueConstraint("product", "api_version", "name", name="uq_registry_endpoint_key"),
    )

    def __repr__(self) -> str:
        return f"<RegistryEndpoint {self.name!r} -> {self.urn!r}>"


# ---------------------------------------------------------------------------
# UserSetting — PER-USER preferences (branding, etc.)
# ---------------------------------------------------------------------------

class UserSetting(db.Model):
    """Per-user key/value preferences, persisted in the DB so a user's choices
    (e.g. their personal top-bar banner) survive logout, server restarts and are
    NOT carried in a cookie. Composite PK (user_id, key); rows are removed with
    the owning user via ON DELETE CASCADE."""

    __tablename__ = "user_settings"

    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    key = db.Column(db.String(128), primary_key=True)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    @classmethod
    def get(cls, user_id: int, key: str, default: str | None = None) -> str | None:
        row = cls.query.get((user_id, key))
        return row.value if row else default

    @classmethod
    def set(cls, user_id: int, key: str, value: str) -> None:
        row = cls.query.get((user_id, key))
        if row is None:
            row = cls(user_id=user_id, key=key)
            db.session.add(row)
        row.value = value
        row.updated_at = datetime.utcnow()
        db.session.commit()

    def __repr__(self) -> str:
        return f"<UserSetting u={self.user_id} {self.key!r}>"

class BugReport(db.Model):
    """A user-submitted bug/problem report, routed to opted-in admins.

    Stored in the DB; an admin resolves it with an optional note, which
    notifies the original reporter (bell badge + email).
    """

    __tablename__ = "bug_reports"

    STATUS_OPEN = "open"
    STATUS_RESOLVED = "resolved"

    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    # Snapshot so the report stays readable even if the user is deleted.
    reporter_username = db.Column(db.String(64), nullable=False, default="")

    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False, default="")
    page_url = db.Column(db.String(500), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)

    status = db.Column(
        db.String(16), nullable=False, default=STATUS_OPEN, index=True
    )
    resolved_by_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolution_note = db.Column(db.Text, nullable=True)

    # Cleared->True once the reporter has seen the resolution (dismisses their badge).
    reporter_seen = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    reporter = db.relationship("User", foreign_keys=[reporter_id])
    resolved_by = db.relationship("User", foreign_keys=[resolved_by_id])

    @property
    def is_open(self) -> bool:
        return self.status == self.STATUS_OPEN



# ---------------------------------------------------------------------------
# Template — desired-state library (web port of the desktop ``templates`` table)
# ---------------------------------------------------------------------------

class Template(db.Model):
    """A reusable desired-state object the admin authors once and pushes on
    demand: a Web Protection Profile, a system profile, a Server Policy skeleton
    or a config section. The ``body`` is the JSON payload; it is desired-state
    only and is NEVER a live mirror of a device (the device stays the source of
    truth). Secrets are entered at apply-time and never stored here.
    """

    __tablename__ = "templates"
    __table_args__ = (
        db.UniqueConstraint("kind", "name", "version", name="uq_template_kind_name_version"),
    )

    # Template kinds (mirror the desktop ``services.templates`` constants).
    KIND_WEB_PROTECTION = "web-protection-profile"
    KIND_SERVER_POLICY = "server-policy"
    KIND_SYSTEM = "system-profile"
    KIND_STRUCTURE = "structure"
    KINDS = (KIND_WEB_PROTECTION, KIND_SERVER_POLICY, KIND_SYSTEM, KIND_STRUCTURE)

    # Owning product/ADOM. Everything authored so far is FortiWeb; ADC-side
    # templates will carry 'fortiadc' so lists scope by session product.
    product = db.Column(db.String(16), nullable=False, default="fortiweb")
    # Approval lifecycle (separate from ``locked``: locked == curated/read-only,
    # status == approval state). A template is fleet-deployable only when APPROVED.
    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"
    STATUSES = (STATUS_PENDING, STATUS_APPROVED, STATUS_REJECTED)
    # Per-section FortiWeb configuration templates use a ``config:<section>``
    # kind (e.g. ``config:network``) — see the desktop SectionConfigPage.
    KIND_CONFIG_PREFIX = "config:"

    @classmethod
    def config_kind(cls, section: str) -> str:
        """Build the template kind for a FortiWeb config section."""
        return f"{cls.KIND_CONFIG_PREFIX}{section}"

    @classmethod
    def is_valid_kind(cls, kind: str) -> bool:
        """A kind is valid if it is a known kind or a ``config:<section>`` kind."""
        return kind in cls.KINDS or (kind or "").startswith(cls.KIND_CONFIG_PREFIX)

    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(64), nullable=False, index=True)
    name = db.Column(db.String(128), nullable=False)
    version = db.Column(db.Integer, nullable=False, default=1)
    body = db.Column(db.Text, nullable=False, default="{}")  # JSON-serialised dict
    exceptions = db.Column(db.Text, nullable=True, default="")  # JSON exceptions blob
    note = db.Column(db.Text, nullable=True, default="")
    author = db.Column(db.String(64), nullable=True, default="")
    locked = db.Column(db.Boolean, nullable=False, default=False)
    status = db.Column(db.String(16), nullable=False, default="pending", index=True)
    reject_reason = db.Column(db.Text, nullable=True, default="")
    reviewed_by = db.Column(db.String(64), nullable=True, default="")
    reviewed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    @property
    def body_dict(self) -> dict[str, Any]:
        try:
            data = json.loads(self.body or "{}")
            return data if isinstance(data, dict) else {}
        except (ValueError, TypeError):
            return {}

    @property
    def is_approved(self) -> bool:
        return self.status == self.STATUS_APPROVED

    def __repr__(self) -> str:
        return f"<Template {self.kind}/{self.name} v{self.version}>"


class TemplateReviewEvent(db.Model):
    """Append-only audit trail of a template's approval lifecycle.

    ``Template.reviewed_by`` / ``reviewed_at`` keep only the LATEST review; this
    table is the full history, so the page can show who approved AND who
    rejected (and who revoked) over time, each with a timestamp and reason.
    """

    __tablename__ = "template_review_events"

    ACTION_APPROVE = "approve"
    ACTION_REJECT = "reject"
    ACTION_REVOKE = "unapprove"

    id = db.Column(db.Integer, primary_key=True)
    template_id = db.Column(
        db.Integer, db.ForeignKey("templates.id", ondelete="CASCADE"),
        nullable=False, index=True)
    action = db.Column(db.String(16), nullable=False)
    reviewer = db.Column(db.String(64), nullable=True, default="")
    reason = db.Column(db.Text, nullable=True, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self) -> str:
        return (f"<TemplateReviewEvent {self.action} "
                f"t{self.template_id} by {self.reviewer!r}>")


# ---------------------------------------------------------------------------
# Baseline — a NAMED, scoped assembly of approved templates (the "armado").
# Templates carry no scope; the baseline does: it is bound to a zone/line/
# department and composed of several approved templates (one per section, or
# several). This is what Provisioning pushes to the devices that match the scope.
# ---------------------------------------------------------------------------

class Baseline(db.Model):
    __tablename__ = "baselines"
    __table_args__ = (
        db.UniqueConstraint("name", name="uq_baseline_name"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, index=True)
    # Owning product/ADOM (baselines compose FortiWeb templates today).
    product = db.Column(db.String(16), nullable=False, default="fortiweb")
    # Scope: plain strings matching Appliance.zone/line/department (catalogs live
    # in settings_store). "" / NULL means "any" for that facet.
    zone = db.Column(db.String(128), nullable=True, default="")
    line = db.Column(db.String(128), nullable=True, default="")
    department = db.Column(db.String(128), nullable=True, default="")
    note = db.Column(db.Text, nullable=True, default="")
    author = db.Column(db.String(64), nullable=True, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    items = db.relationship(
        "BaselineTemplate",
        backref="baseline",
        cascade="all, delete-orphan",
        order_by="BaselineTemplate.position",
    )

    def scope_dict(self) -> dict[str, str]:
        return {"zone": self.zone or "", "line": self.line or "",
                "department": self.department or ""}

    def __repr__(self) -> str:
        return f"<Baseline {self.name!r} zone={self.zone!r} line={self.line!r}>"


class BaselineTemplate(db.Model):
    """Junction: one approved template composing a baseline, tagged with the
    section it occupies and an ordering position. ``section`` is denormalised
    (derived from the template kind at link time) so the builder can group/sort
    without re-deriving, and so a future WPP-SECTION template slots in cleanly."""

    __tablename__ = "baseline_templates"
    __table_args__ = (
        db.UniqueConstraint("baseline_id", "template_id",
                            name="uq_baseline_template"),
    )

    id = db.Column(db.Integer, primary_key=True)
    baseline_id = db.Column(
        db.Integer, db.ForeignKey("baselines.id", ondelete="CASCADE"),
        nullable=False, index=True)
    template_id = db.Column(
        db.Integer, db.ForeignKey("templates.id", ondelete="CASCADE"),
        nullable=False, index=True)
    section = db.Column(db.String(64), nullable=False, default="")
    position = db.Column(db.Integer, nullable=False, default=0)

    def __repr__(self) -> str:
        return f"<BaselineTemplate b={self.baseline_id} t={self.template_id} {self.section}>"


# ---------------------------------------------------------------------------
# ChangeHistory — audit trail for live (and previewed) FortiWeb config writes
# ---------------------------------------------------------------------------

class ChangeHistory(db.Model):
    """One row per config write attempted through ``services.fortiweb_ops``.

    Records the before/after snapshot, whether it was a dry-run preview, and who
    performed it, so every live mutation (and every preview) is auditable.
    """

    __tablename__ = "change_history"

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(
        db.Integer, db.ForeignKey("appliances.id", ondelete="SET NULL"), nullable=True)
    endpoint = db.Column(db.String(256), nullable=False, default="")
    mkey = db.Column(db.String(256), nullable=True, default="")
    action = db.Column(db.String(16), nullable=False, default="")  # create|update|delete
    before = db.Column(db.Text, nullable=True, default="")          # JSON snapshot
    after = db.Column(db.Text, nullable=True, default="")           # JSON payload
    dry_run = db.Column(db.Boolean, nullable=False, default=True)
    username = db.Column(db.String(64), nullable=True, default="")
    ts = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<ChangeHistory {self.action} {self.endpoint} dry={self.dry_run}>"


# ---------------------------------------------------------------------------
# ScheduledAction — the admin's automation calendar (web port of the desktop
# ``scheduled_action`` table). Fired ONLY by the dedicated scheduler sidecar,
# never by the gunicorn web workers (which would fire each job N times).
# ---------------------------------------------------------------------------

class ScheduledAction(db.Model):
    __tablename__ = "scheduled_action"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, default="")
    scope = db.Column(db.String(16), nullable=False, default="admin")  # admin|user
    # ADOM/product owning this automation (the catalog is FortiWeb today).
    product = db.Column(db.String(16), nullable=False, default="fortiweb")
    action = db.Column(db.String(64), nullable=False)                  # catalog key
    targets = db.Column(db.Text, nullable=False, default="[]")         # JSON appliance ids ([]=fleet)
    params = db.Column(db.Text, nullable=False, default="{}")          # JSON params
    schedule_kind = db.Column(db.String(16), nullable=False, default="once")  # once|interval|daily|weekly|monthly
    schedule = db.Column(db.Text, nullable=False, default="{}")        # JSON schedule spec
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    catch_up = db.Column(db.Boolean, nullable=False, default=True)
    created_by = db.Column(db.String(64), nullable=True, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_run = db.Column(db.DateTime, nullable=True)
    last_status = db.Column(db.String(32), nullable=True, default="")
    next_run = db.Column(db.DateTime, nullable=True, index=True)
    # DB-claim lease replacing the desktop's in-process lock so exactly one
    # process (the sidecar) fires a given action even across workers.
    running_at = db.Column(db.DateTime, nullable=True)

    @property
    def targets_list(self) -> list:
        try:
            v = json.loads(self.targets or "[]")
            return v if isinstance(v, list) else []
        except (ValueError, TypeError):
            return []

    @property
    def params_dict(self) -> dict[str, Any]:
        try:
            v = json.loads(self.params or "{}")
            return v if isinstance(v, dict) else {}
        except (ValueError, TypeError):
            return {}

    @property
    def schedule_dict(self) -> dict[str, Any]:
        try:
            v = json.loads(self.schedule or "{}")
            return v if isinstance(v, dict) else {}
        except (ValueError, TypeError):
            return {}

    def __repr__(self) -> str:
        return f"<ScheduledAction {self.name!r} {self.action} {self.schedule_kind}>"


class ScheduledActionRun(db.Model):
    __tablename__ = "scheduled_action_run"

    id = db.Column(db.Integer, primary_key=True)
    action_id = db.Column(
        db.Integer, db.ForeignKey("scheduled_action.id", ondelete="CASCADE"),
        nullable=False, index=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    finished_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(32), nullable=False, default="running")  # running|ok|failed|skipped
    trigger = db.Column(db.String(16), nullable=False, default="schedule")  # schedule|manual
    summary = db.Column(db.Text, nullable=True, default="")
    log = db.Column(db.Text, nullable=True, default="")

    def __repr__(self) -> str:
        return f"<ScheduledActionRun a={self.action_id} {self.status}>"


# ---------------------------------------------------------------------------
# ChangeRequest — maintenance-window approval gating risky (upgrade) actions.
# Approving + scheduling a CR creates a one-shot ScheduledAction bound back via
# ``scheduled_action_id``; the upgrade executor refuses to run outside the window.
# ---------------------------------------------------------------------------

class ChangeRequest(db.Model):
    __tablename__ = "change_request"

    # draft -> approved -> scheduled -> in_progress -> completed|failed (or cancelled)
    STATUSES = ("draft", "approved", "scheduled", "in_progress", "completed", "failed", "cancelled")
    TERMINAL = ("completed", "failed", "cancelled")

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, default="")
    reason = db.Column(db.Text, nullable=True, default="")
    status = db.Column(db.String(16), nullable=False, default="draft")
    action = db.Column(db.String(64), nullable=False, default="upgrade")
    params = db.Column(db.Text, nullable=False, default="{}")
    device_ids = db.Column(db.Text, nullable=False, default="[]")
    policies = db.Column(db.Text, nullable=False, default="[]")
    window_start = db.Column(db.DateTime, nullable=True)
    window_end = db.Column(db.DateTime, nullable=True)
    risk = db.Column(db.String(16), nullable=False, default="medium")  # low|medium|high
    rollback = db.Column(db.Text, nullable=True, default="")
    requested_by = db.Column(db.String(64), nullable=True, default="")
    approved_by = db.Column(db.String(64), nullable=True, default="")
    approved_at = db.Column(db.DateTime, nullable=True)
    notify_status = db.Column(db.String(16), nullable=False, default="none")  # none|drafted|sent
    notify_log = db.Column(db.Text, nullable=True, default="")
    scheduled_action_id = db.Column(db.Integer, nullable=True)
    result_summary = db.Column(db.Text, nullable=True, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def device_ids_list(self) -> list:
        try:
            v = json.loads(self.device_ids or "[]")
            return v if isinstance(v, list) else []
        except (ValueError, TypeError):
            return []

    @property
    def params_dict(self) -> dict[str, Any]:
        try:
            v = json.loads(self.params or "{}")
            return v if isinstance(v, dict) else {}
        except (ValueError, TypeError):
            return {}

    def __repr__(self) -> str:
        return f"<ChangeRequest {self.title!r} {self.status}>"


class ChangeRequestEvent(db.Model):
    __tablename__ = "change_request_event"

    id = db.Column(db.Integer, primary_key=True)
    cr_id = db.Column(
        db.Integer, db.ForeignKey("change_request.id", ondelete="CASCADE"),
        nullable=False, index=True)
    ts = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    kind = db.Column(db.String(32), nullable=False, default="")
    by = db.Column(db.String(64), nullable=True, default="")
    detail = db.Column(db.Text, nullable=True, default="")

    def __repr__(self) -> str:
        return f"<ChangeRequestEvent cr={self.cr_id} {self.kind}>"


# ---------------------------------------------------------------------------
# WppException — desired-state WAF / signature carve-outs authored here.
# A Web Protection Profile is usually SHARED by several Server Policies, so an
# exception on it applies to every policy that binds it and FortiWeb has no
# record of which policy a carve-out was authored for. This records that intent
# (which policies it belongs to lives in wpp_exception_policies). NEVER secrets;
# the device stays the source of truth. Web port of the desktop store v7/v8.
# ---------------------------------------------------------------------------

class WppException(db.Model):
    __tablename__ = "wpp_exceptions"

    CAT_EXCEPTION = "exception"     # a WAF carve-out (HTTP-constraints, geo, …)
    CAT_SIGNATURE = "signature"     # a signature customisation (per-id exception…)

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(
        db.Integer, db.ForeignKey("appliances.id", ondelete="CASCADE"),
        nullable=True, index=True)
    wpp_mkey = db.Column(db.String(128), nullable=False, default="")
    category = db.Column(db.String(16), nullable=False,
                         default=CAT_EXCEPTION, index=True)
    exc_type = db.Column(db.String(64), nullable=False, default="")  # spec/form key
    name = db.Column(db.String(128), nullable=True, default="")
    payload = db.Column(db.Text, nullable=False, default="{}")       # FortiWeb-shaped entry
    reason = db.Column(db.Text, nullable=True, default="")
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    # Lifecycle flags (rule 1): set when the bound Server Policy was deleted or
    # re-bound to another WPP after this carve-out was authored. Never silently
    # deleted — the operator resolves it on the Exceptions page.
    stale = db.Column(db.Boolean, nullable=False, default=False)
    stale_reason = db.Column(db.Text, nullable=True, default="")
    author = db.Column(db.String(64), nullable=True, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    policies = db.relationship(
        "WppExceptionPolicy", backref="exception",
        cascade="all, delete-orphan", lazy="selectin")

    @property
    def payload_dict(self) -> dict[str, Any]:
        try:
            d = json.loads(self.payload or "{}")
            return d if isinstance(d, dict) else {}
        except (ValueError, TypeError):
            return {}

    @property
    def policy_names(self) -> list[str]:
        return sorted(p.server_policy for p in (self.policies or []) if p.server_policy)

    def __repr__(self) -> str:
        return f"<WppException {self.category}/{self.exc_type} wpp={self.wpp_mkey}>"


class WppExceptionPolicy(db.Model):
    """Junction: one carve-out → one Server Policy it is authored for (a carve-out
    may bind to several policies — the relationship FortiWeb itself can't record)."""

    __tablename__ = "wpp_exception_policies"
    __table_args__ = (
        db.UniqueConstraint("exception_id", "server_policy", name="uq_wpp_exc_policy"),
    )

    id = db.Column(db.Integer, primary_key=True)
    exception_id = db.Column(
        db.Integer, db.ForeignKey("wpp_exceptions.id", ondelete="CASCADE"),
        nullable=False, index=True)
    server_policy = db.Column(db.String(128), nullable=False, default="")

    def __repr__(self) -> str:
        return f"<WppExceptionPolicy exc={self.exception_id} pol={self.server_policy}>"


# ---------------------------------------------------------------------------
# ManagedCertificate — the Certificate Manager's source of truth.
#
# One row per certificate the manager generated / manages for a FortiWeb. The
# PRIVATE KEY is stored Fernet-encrypted (``private_key_enc``) exactly like an
# appliance password — it never lives in plaintext or in git — so a cert can be
# re-deployed / rotated without regenerating. Everything else (CSR, public cert
# PEM, subject, SANs, the ADCS request id needed for revoke, issue/expiry dates,
# where it is bound) is documentation the inventory + automation read. NEVER a
# device secret beyond the key it wraps.
# ---------------------------------------------------------------------------

class ManagedCertificate(db.Model):
    __tablename__ = "managed_certificate"

    # pending  -> generated + signed + deployed, not yet bound to any policy
    # active   -> currently the bound/live cert
    # expiring -> active but inside the renew-before window
    # superseded -> a newer cert replaced it (old one kept for the window)
    # revoked  -> revoked at the CA
    STATUSES = ("pending", "active", "expiring", "superseded", "revoked")
    CLASSES = ("server", "clientserver", "client")

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, default="")   # name on the FortiWeb
    appliance_id = db.Column(
        db.Integer, db.ForeignKey("appliances.id", ondelete="CASCADE"),
        nullable=True, index=True)
    cert_class = db.Column(db.String(16), nullable=False, default="server", index=True)
    subject = db.Column(db.String(512), nullable=True, default="")   # the DN used
    sans_json = db.Column(db.Text, nullable=False, default="[]")     # JSON list of SAN dns/ip
    serial = db.Column(db.String(128), nullable=True, default="")    # issued cert serial
    ca_request_id = db.Column(db.String(128), nullable=True, default="")  # ADCS request id (for revoke)
    issued_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True, index=True)
    status = db.Column(db.String(16), nullable=False, default="pending", index=True)
    cert_pem = db.Column(db.Text, nullable=True, default="")         # public cert (safe)
    csr_pem = db.Column(db.Text, nullable=True, default="")          # the CSR (safe)
    private_key_enc = db.Column(db.Text, nullable=True, default="")  # Fernet-encrypted PEM
    bound_policies_json = db.Column(db.Text, nullable=False, default="[]")  # server policies using it
    supersedes_id = db.Column(db.Integer, nullable=True)             # old cert this one replaces
    superseded_at = db.Column(db.DateTime, nullable=True)  # when THIS cert became superseded
    revoked_at = db.Column(db.DateTime, nullable=True)     # when THIS cert was revoked
    created_by = db.Column(db.String(64), nullable=True, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    events = db.relationship(
        "ManagedCertificateEvent", backref="certificate",
        cascade="all, delete-orphan", lazy="selectin",
        order_by="ManagedCertificateEvent.ts.desc()")

    # -- encrypted private key (mirror of Appliance.password) -------------
    @property
    def private_key(self) -> str:
        if not self.private_key_enc:
            return ""
        return _fernet().decrypt(self.private_key_enc.encode()).decode()

    @private_key.setter
    def private_key(self, pem: str) -> None:
        self.private_key_enc = (
            _fernet().encrypt((pem or "").encode()).decode() if pem else "")

    @property
    def has_private_key(self) -> bool:
        return bool(self.private_key_enc)

    # -- JSON helpers -----------------------------------------------------
    @property
    def sans(self) -> list[str]:
        try:
            v = json.loads(self.sans_json or "[]")
            return [str(x) for x in v] if isinstance(v, list) else []
        except (ValueError, TypeError):
            return []

    @sans.setter
    def sans(self, values) -> None:
        self.sans_json = json.dumps([str(v).strip() for v in (values or []) if str(v).strip()])

    @property
    def bound_policies(self) -> list[str]:
        try:
            v = json.loads(self.bound_policies_json or "[]")
            return [str(x) for x in v] if isinstance(v, list) else []
        except (ValueError, TypeError):
            return []

    @bound_policies.setter
    def bound_policies(self, values) -> None:
        self.bound_policies_json = json.dumps(
            sorted({str(v).strip() for v in (values or []) if str(v).strip()}))

    @property
    def days_left(self):
        """Whole days until expiry (may be negative). ``None`` if unknown."""
        if not self.expires_at:
            return None
        return (self.expires_at - datetime.utcnow()).days

    @property
    def is_bound(self) -> bool:
        return bool(self.bound_policies)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "appliance_id": self.appliance_id,
            "cert_class": self.cert_class,
            "subject": self.subject,
            "sans": self.sans,
            "serial": self.serial,
            "ca_request_id": self.ca_request_id,
            "issued_at": self.issued_at.isoformat() if self.issued_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status,
            "days_left": self.days_left,
            "bound_policies": self.bound_policies,
            "has_private_key": self.has_private_key,
            "superseded_at": self.superseded_at.isoformat() if self.superseded_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
        }

    def __repr__(self) -> str:
        return f"<ManagedCertificate {self.name!r} {self.cert_class} {self.status}>"


class ManagedCertificateEvent(db.Model):
    """Timeline entry for a managed certificate (generate / sign / deploy / swap /
    revoke / renew), so the whole lifecycle is auditable per cert."""

    __tablename__ = "managed_certificate_event"

    id = db.Column(db.Integer, primary_key=True)
    cert_id = db.Column(
        db.Integer, db.ForeignKey("managed_certificate.id", ondelete="CASCADE"),
        nullable=False, index=True)
    ts = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    kind = db.Column(db.String(32), nullable=False, default="")   # generate|sign|deploy|swap|revoke|renew|error
    ok = db.Column(db.Boolean, nullable=False, default=True)
    by = db.Column(db.String(64), nullable=True, default="")
    detail = db.Column(db.Text, nullable=True, default="")

    def __repr__(self) -> str:
        return f"<ManagedCertificateEvent cert={self.cert_id} {self.kind} ok={self.ok}>"


class DeviceCertificate(db.Model):
    """Cached inventory of certificates that live ON a FortiWeb (not ADCS-managed).

    A live REST sweep only exposes name/type/status/comment; the X.509 detail
    (validity, issuer, SANs, fingerprint) and the per-policy bindings are read
    over SSH/REST by a scan and PERSISTED here, so the Certificate Manager table
    can show expiry / days-left / SANs without a slow fleet sweep on every page
    load. Refreshed by the ``cert_scan`` scheduled action and the manual "Scan
    devices" button. One row per (appliance, store, name)."""

    __tablename__ = "device_certificate"
    __table_args__ = (
        db.UniqueConstraint("appliance_id", "store", "name",
                            name="uq_device_cert_appliance_store_name"),
    )

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(
        db.Integer, db.ForeignKey("appliances.id", ondelete="CASCADE"),
        nullable=False, index=True)
    store = db.Column(db.String(32), nullable=False, default="Local", index=True)
    name = db.Column(db.String(128), nullable=False, default="", index=True)

    # cmdb summary fields (cheap REST read)
    cert_type = db.Column(db.String(32), nullable=True, default="")
    status = db.Column(db.String(32), nullable=True, default="")
    comment = db.Column(db.String(512), nullable=True, default="")

    # decoded X.509 detail (SSH CLI / stored PEM / TLS probe)
    cn = db.Column(db.String(256), nullable=True, default="")
    issuer_cn = db.Column(db.String(256), nullable=True, default="")
    serial = db.Column(db.String(128), nullable=True, default="")
    sig_algo = db.Column(db.String(32), nullable=True, default="")
    key_type = db.Column(db.String(32), nullable=True, default="")
    not_before = db.Column(db.DateTime, nullable=True)
    not_after = db.Column(db.DateTime, nullable=True, index=True)
    sans_json = db.Column(db.Text, nullable=False, default="[]")
    fingerprint_sha256 = db.Column(db.String(128), nullable=True, default="")

    bindings_json = db.Column(db.Text, nullable=False, default="[]")
    detail_source = db.Column(db.String(16), nullable=True, default="")  # ssh|pem|tls
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False,
                           index=True)

    @property
    def sans(self) -> list[str]:
        try:
            v = json.loads(self.sans_json or "[]")
            return [str(x) for x in v] if isinstance(v, list) else []
        except (ValueError, TypeError):
            return []

    @sans.setter
    def sans(self, values) -> None:
        self.sans_json = json.dumps(
            [str(v).strip() for v in (values or []) if str(v).strip()])

    @property
    def bindings(self) -> list[str]:
        try:
            v = json.loads(self.bindings_json or "[]")
            return [str(x) for x in v] if isinstance(v, list) else []
        except (ValueError, TypeError):
            return []

    @bindings.setter
    def bindings(self, values) -> None:
        self.bindings_json = json.dumps(
            sorted({str(v).strip() for v in (values or []) if str(v).strip()}))

    @property
    def days_left(self):
        if not self.not_after:
            return None
        return (self.not_after - datetime.utcnow()).days

    @property
    def has_detail(self) -> bool:
        return bool(self.cn or self.not_after or self.sans)

    def apply_detail(self, detail: dict, source: str = "") -> None:
        """Merge a cert_probe detail dict (SSH/PEM/TLS) onto this row."""
        if not detail:
            return
        self.cn = detail.get("cn") or self.cn
        self.issuer_cn = detail.get("issuer_cn") or self.issuer_cn
        self.serial = detail.get("serial") or self.serial
        self.sig_algo = detail.get("sig_algo") or self.sig_algo
        self.key_type = detail.get("key_type") or self.key_type
        self.not_before = detail.get("not_before") or self.not_before
        self.not_after = detail.get("not_after") or self.not_after
        if detail.get("sans"):
            self.sans = detail["sans"]
        self.fingerprint_sha256 = (
            detail.get("fingerprint_sha256") or self.fingerprint_sha256)
        if source:
            self.detail_source = source

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "appliance_id": self.appliance_id,
            "store": self.store, "name": self.name,
            "cert_type": self.cert_type, "status": self.status,
            "comment": self.comment, "cn": self.cn, "issuer_cn": self.issuer_cn,
            "serial": self.serial, "sig_algo": self.sig_algo,
            "key_type": self.key_type,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "days_left": self.days_left, "sans": self.sans,
            "fingerprint_sha256": self.fingerprint_sha256,
            "bindings": self.bindings, "detail_source": self.detail_source,
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
        }

    def __repr__(self) -> str:
        return f"<DeviceCertificate {self.name!r}@{self.appliance_id} {self.store}>"


# ---------------------------------------------------------------------------
# CapacityLimit — per-(firmware, model) maximum object counts + operational cap
# ---------------------------------------------------------------------------

class CapacityLimit(db.Model):
    """A capacity guardrail for one object type on one FortiWeb model/firmware.

    ``hard_max`` is Fortinet's published ceiling for that (firmware major, model)
    — the number from Appendix B / the model datasheet. It is the ABSOLUTE limit
    the box will accept; the admin enters/confirms it (the fleet is unlicensed
    VMs that can't self-report a SKU). ``operational_cap`` is the admin's OWN
    lower limit (the "espacio de sobra" buffer) that automations honour BEFORE
    hitting the hardware ceiling — it may be NULL (=> effective cap = hard_max)
    and is validated <= hard_max (never above; going above just makes the box
    reject creates).

    ``object_type`` is a logical token from ``services.capacity.OBJECT_TYPES``
    (server_policy / web_protection_profile / certificate / sni / ...), not a raw
    registry name, so the catalog is stable and extensible. One row per
    (product, firmware_major, model, object_type). Seeded insert-only from
    ``capacity_seed.json``; admin edits always win (like RegistryEndpoint).
    """

    __tablename__ = "capacity_limits"
    __table_args__ = (
        db.UniqueConstraint("product", "firmware_major", "model", "object_type",
                            name="uq_capacity_limit_key"),
    )

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False, default="fortiweb", index=True)
    firmware_major = db.Column(db.String(16), nullable=False, index=True)
    model = db.Column(db.String(128), nullable=False, index=True)
    object_type = db.Column(db.String(64), nullable=False)
    hard_max = db.Column(db.Integer, nullable=True)
    operational_cap = db.Column(db.Integer, nullable=True)
    cap_percent = db.Column(db.Float, nullable=True)   # admin cap as % of hard_max
    source = db.Column(db.String(32), nullable=True, default="")
    updated_by = db.Column(db.String(64), nullable=True)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    @property
    def effective_cap(self) -> int | None:
        """The number automations must respect: the lower of the two, ignoring
        an operational cap that (illegally) exceeds the hard max."""
        vals = [v for v in (self.hard_max, self.operational_cap) if v is not None]
        if self.cap_percent is not None and self.hard_max is not None:
            try:
                p = float(self.cap_percent)
                if 0 < p <= 100:
                    vals.append(int(self.hard_max * p / 100.0))
            except (TypeError, ValueError):
                pass
        return min(vals) if vals else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "product": self.product,
            "firmware_major": self.firmware_major, "model": self.model,
            "object_type": self.object_type, "hard_max": self.hard_max,
            "operational_cap": self.operational_cap,
            "cap_percent": self.cap_percent,
            "effective_cap": self.effective_cap, "source": self.source,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return (f"<CapacityLimit {self.product}/{self.firmware_major}/{self.model}"
                f"/{self.object_type} max={self.hard_max} cap={self.operational_cap}>")


class DeviceHardware(db.Model):
    """Hardware inventory of one appliance, captured over SSH (works even when
    the REST API is license-locked — see services.hardware). One row per
    appliance, upserted by scan_appliance; raw command output kept for
    debugging. Consumed by the Monitoring dashboard and the Architecture map."""

    __tablename__ = "device_hardware"

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(db.Integer,
                             db.ForeignKey("appliances.id", ondelete="CASCADE"),
                             nullable=False, unique=True, index=True)
    cpu_count = db.Column(db.Integer, nullable=True)
    cpu_model = db.Column(db.String(128), nullable=True)
    mem_total_mb = db.Column(db.Integer, nullable=True)
    disks_json = db.Column(db.Text, nullable=True)   # [{"name", "size_gb"}]
    raw_json = db.Column(db.Text, nullable=True)     # {command: output}
    source = db.Column(db.String(16), nullable=True, default="ssh")
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    appliance = db.relationship(
        "Appliance", backref=db.backref("hardware", uselist=False))

    @property
    def disks(self) -> list:
        import json as _json
        try:
            return _json.loads(self.disks_json or "[]")
        except Exception:
            return []

    @property
    def disk_total_gb(self) -> float | None:
        total = sum((d.get("size_gb") or 0) for d in self.disks)
        return round(total, 1) if total else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "appliance_id": self.appliance_id, "cpu_count": self.cpu_count,
            "cpu_model": self.cpu_model, "mem_total_mb": self.mem_total_mb,
            "disks": self.disks, "disk_total_gb": self.disk_total_gb,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class DbReport(db.Model):
    """A user-authored report/dashboard over the read-only SQL layer.

    ``definition`` is JSON: {"widgets": [{"title", "sql", "viz", "x", "y",
    "limit", "width"}]}. Queries always execute through
    services.dbintrospect.run_query (SELECT-only, sensitive columns masked),
    so a report can never mutate or leak more than the SQL console can.
    """

    __tablename__ = "db_reports"

    VIZ_KINDS = ("table", "bar", "line", "pie", "stat")

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    definition = db.Column(db.Text, nullable=False, default="{}")
    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)
    builtin = db.Column(db.Boolean, nullable=False, default=False)

    @property
    def widgets(self) -> list:
        import json as _json
        try:
            data = _json.loads(self.definition or "{}")
        except Exception:
            return []
        w = data.get("widgets")
        return w if isinstance(w, list) else []

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name,
            "description": self.description,
            "widgets": self.widgets, "created_by": self.created_by,
            "builtin": bool(self.builtin),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<DbReport {self.id} {self.name!r}>"


# ---------------------------------------------------------------------------
# AppID — the billing + access-control authority (see services.appids)
# ---------------------------------------------------------------------------
class AppId(db.Model):
    """A customer application identifier.

    It is BOTH a billing key (which customer a Server Policy is charged to) and
    the unit an API token can be scoped to. The catalog is fed manually or by an
    ADDITIVE import (file / URL) through a saved column→field mapping; a row that
    vanishes from a feed is flagged ``stale`` — never deleted (that would de-bill
    a client). ``extra_json`` carries the extra columns a source PDF/CSV brings
    beyond the core fields, so the schema doesn't need a column per source field.
    """

    __tablename__ = "app_ids"
    __table_args__ = (
        # AppID is a GLOBAL catalog (spans FortiWeb + FortiADC): unique on the
        # NAME alone; which product a binding touches is decided by the appliance.
        db.UniqueConstraint("app_id", name="uq_appid_key"),
    )

    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.String(128), nullable=False, index=True)
    product = db.Column(db.String(16), nullable=False, default="global")
    customer = db.Column(db.String(200), nullable=False, default="")
    label = db.Column(db.String(200), nullable=False, default="")
    rate = db.Column(db.String(64), nullable=True, default="")
    extra_json = db.Column(db.Text, nullable=False, default="{}")
    source = db.Column(db.String(16), nullable=False, default="manual")  # manual|import
    active = db.Column(db.Boolean, nullable=False, default=True)
    stale = db.Column(db.Boolean, nullable=False, default=False)
    stale_reason = db.Column(db.Text, nullable=False, default="")
    last_seen = db.Column(db.DateTime, nullable=True)
    created_by = db.Column(db.String(64), nullable=True, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    @property
    def extra_dict(self) -> dict[str, Any]:
        try:
            v = json.loads(self.extra_json or "{}")
            return v if isinstance(v, dict) else {}
        except (ValueError, TypeError):
            return {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "app_id": self.app_id, "product": self.product,
            "customer": self.customer, "label": self.label, "rate": self.rate,
            "extra": self.extra_dict, "source": self.source,
            "active": bool(self.active), "stale": bool(self.stale),
            "stale_reason": self.stale_reason,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }

    def __repr__(self) -> str:
        return f"<AppId {self.app_id!r} product={self.product}>"


class AppIdPolicy(db.Model):
    """Binding of a FortiWeb Server Policy to exactly one :class:`AppId`.

    ``UNIQUE(appliance_id, server_policy)`` is what makes a policy belong to one
    AppID (one customer). This junction — not a policy comment — is the authority
    a token's scope and the billing rollup resolve against."""

    __tablename__ = "app_id_policies"
    __table_args__ = (
        db.UniqueConstraint("appliance_id", "server_policy",
                            name="uq_appidpolicy_policy"),
    )

    id = db.Column(db.Integer, primary_key=True)
    app_id_id = db.Column(
        db.Integer, db.ForeignKey("app_ids.id", ondelete="CASCADE"),
        nullable=False, index=True)
    appliance_id = db.Column(
        db.Integer, db.ForeignKey("appliances.id", ondelete="CASCADE"),
        nullable=False, index=True)
    server_policy = db.Column(db.String(256), nullable=False)
    assigned_by = db.Column(db.String(64), nullable=True, default="")
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    app = db.relationship("AppId", lazy="joined")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "app_id_id": self.app_id_id,
            "appliance_id": self.appliance_id, "server_policy": self.server_policy,
            "app_id": getattr(self.app, "app_id", None),
            "customer": getattr(self.app, "customer", None),
        }

    def __repr__(self) -> str:
        return f"<AppIdPolicy {self.server_policy!r} -> app={self.app_id_id}>"


# Device-structure cache models (source-of-truth substrate) — import so
# create_all()/Alembic register them.
from . import models_cache  # noqa: E402,F401


# ---------------------------------------------------------------------------
# Plugin Sandbox — operator-authored HTML/Jinja/JS views (super-admin only)
# ---------------------------------------------------------------------------
class Plugin(db.Model):
    """A super-admin authored custom view/widget.

    SECURITY MODEL (see services.plugin_sandbox):
      * The Jinja body renders in an ``ImmutableSandboxedEnvironment`` against a
        CURATED, READ-ONLY data API — it can never mutate the DB or reach app
        internals.
      * The rendered document (css + html + js) is served ONLY inside an
        ``<iframe sandbox="allow-scripts">`` WITHOUT ``allow-same-origin`` — an
        opaque origin, so the plugin's JS cannot read the app's cookies, DOM or
        session, and cannot call back to authenticated endpoints.
      * A render failure is caught and shown as an error card — a broken plugin
        never 500s the host app (see ``plugin_sandbox.safe_render``).
    Lifecycle: draft -> testing -> published. Only ``published`` plugins appear
    in the Custom Views nav; ``testing`` is previewable by the author only.
    """

    __tablename__ = "plugins"

    KINDS = ("view", "widget")
    STATUSES = ("draft", "testing", "published")

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(120), unique=True, nullable=False, index=True)
    kind = db.Column(db.String(16), nullable=False, default="view")
    status = db.Column(db.String(16), nullable=False, default="draft")
    icon = db.Column(db.String(32), nullable=False, default="bi-puzzle")
    # Author-supplied source. ``jinja`` is the server-rendered body (sandboxed);
    # css/js are injected verbatim into the isolated iframe document.
    jinja = db.Column(db.Text, nullable=False, default="")
    css = db.Column(db.Text, nullable=False, default="")
    js = db.Column(db.Text, nullable=False, default="")
    # JSON list of curated dataset keys this plugin is allowed to read.
    data_sources = db.Column(db.Text, nullable=False, default="[]")
    # JSON list of author-defined INPUT PARAMETERS (selectors) the consumer of
    # the view fills in; each filters the curated data in the plugin body via
    # ``params.<name>``. Optional by design — an empty selection shows all.
    params = db.Column(db.Text, nullable=False, default="[]")
    created_by = db.Column(db.String(64), nullable=False, default="")
    product = db.Column(db.String(16), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)
    published_at = db.Column(db.DateTime, nullable=True)

    @property
    def datasets(self) -> list:
        try:
            v = json.loads(self.data_sources or "[]")
            return [str(x) for x in v] if isinstance(v, list) else []
        except Exception:
            return []

    @property
    def param_defs(self) -> list:
        """Author-defined input parameters (selectors). List of dicts:
        {name,label,type,options,default,required}. Never raises."""
        try:
            v = json.loads(self.params or "[]")
            return v if isinstance(v, list) else []
        except Exception:
            return []

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "slug": self.slug,
            "kind": self.kind, "status": self.status, "icon": self.icon,
            "datasets": self.datasets, "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<Plugin {self.id} {self.slug!r} {self.status}>"


# ---------------------------------------------------------------------------
# Lua Script Studio — author / lint / analyze / deploy Lua for FortiWeb/ADC
# ---------------------------------------------------------------------------
class LuaScript(db.Model):
    """A Lua script targeting a FortiWeb or FortiADC scripting object.

    The studio LINTS with ``luac -p`` (parse only, NEVER executes device code),
    STATICALLY ANALYSES what the script does against a curated API dictionary,
    and DEPLOYS through the versioned scripting endpoint (dry-run default). The
    device stays the source of truth; ``analysis`` is the last computed report.
    """

    __tablename__ = "lua_scripts"

    TARGETS = ("fortiweb", "fortiadc")
    STATUSES = ("draft", "tested", "deployed")

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    target = db.Column(db.String(16), nullable=False, default="fortiweb")
    appliance_id = db.Column(db.Integer, nullable=True, index=True)
    deploy_object = db.Column(db.String(200), nullable=False, default="")
    code = db.Column(db.Text, nullable=False, default="")
    status = db.Column(db.String(16), nullable=False, default="draft")
    analysis = db.Column(db.Text, nullable=False, default="{}")
    created_by = db.Column(db.String(64), nullable=False, default="")
    product = db.Column(db.String(16), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)
    deployed_at = db.Column(db.DateTime, nullable=True)

    @property
    def analysis_obj(self) -> dict:
        try:
            v = json.loads(self.analysis or "{}")
            return v if isinstance(v, dict) else {}
        except Exception:
            return {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "target": self.target,
            "appliance_id": self.appliance_id, "deploy_object": self.deploy_object,
            "status": self.status, "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<LuaScript {self.id} {self.name!r} {self.target}>"


class AcmeDnsProvider(db.Model):
    """A DNS-01 provider the Certificate Manager can drive.

    THE CATALOG IS DATA, NOT CODE. Rows are seeded INSERT-ONLY from the
    git-tracked ``acme_providers.yaml`` at boot (same contract as the endpoint
    registry): an operator edit always wins and a brand-new provider is a row,
    not a deploy. ``fields`` is the JSON list of environment variables the
    provider reads — the Settings form is rendered FROM it, so supporting a
    provider nobody anticipated needs no template change either.

    Credentials are NOT stored here. They live per provider in ``app_settings``
    under ``certmgr.acme.creds.<slug>``, with every field marked ``secret``
    Fernet-encrypted (see services.settings_store.acme_provider_creds).
    """

    __tablename__ = "acme_dns_providers"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    label = db.Column(db.String(160), nullable=False, default="")
    # Value handed to the ACME client's DNS selector (lego: `--dns <flag>`).
    flag = db.Column(db.String(64), nullable=False, default="")
    doc_url = db.Column(db.String(300), nullable=False, default="")
    # JSON list: [{env, label, secret, required, help, default}, …]
    fields = db.Column(db.Text, nullable=False, default="[]")
    # True = shipped in acme_providers.yaml (protected from delete, still editable).
    builtin = db.Column(db.Boolean, nullable=False, default=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    sort = db.Column(db.Integer, nullable=False, default=100)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    @property
    def field_list(self) -> list[dict]:
        try:
            v = json.loads(self.fields or "[]")
            return [f for f in v if isinstance(f, dict) and f.get("env")]
        except Exception:  # noqa: BLE001 — a corrupt row must not 500 Settings
            return []

    @property
    def secret_envs(self) -> list[str]:
        return [str(f["env"]) for f in self.field_list if f.get("secret")]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "slug": self.slug, "label": self.label,
            "flag": self.flag, "doc_url": self.doc_url,
            "fields": self.field_list, "builtin": bool(self.builtin),
            "enabled": bool(self.enabled), "sort": self.sort,
        }

    def __repr__(self) -> str:
        return f"<AcmeDnsProvider {self.slug!r} flag={self.flag!r}>"


# ---------------------------------------------------------------------------
# Deep monitors (Monitoring → Deep monitors)
# ---------------------------------------------------------------------------

class MonitorProbe(db.Model):
    """One configured deep check: a service URL, an interface table, or a daemon.

    Kept as DATA rather than code so adding a monitor is a row, not a deploy —
    the same contract as ``registry_endpoints`` and ``acme_dns_providers``. A
    probe with no ``appliance_id`` is a bare URL check (useful for the published
    hostname in front of a VIP, which may traverse an upstream proxy).
    """

    __tablename__ = "monitor_probe"

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(
        db.Integer, db.ForeignKey("appliances.id", ondelete="CASCADE"),
        nullable=True, index=True)
    kind = db.Column(db.String(16), nullable=False, default="https", index=True)
    name = db.Column(db.String(120), nullable=False, default="")
    note = db.Column(db.String(250), nullable=True, default="")
    enabled = db.Column(db.Boolean, nullable=False, default=True)

    # https
    target = db.Column(db.String(120), nullable=True, default="")   # policy name
    url = db.Column(db.String(500), nullable=True, default="")
    expect_status = db.Column(db.Integer, nullable=False, default=0)  # 0 = any <400
    warn_ms = db.Column(db.Integer, nullable=False, default=2000)
    tls_warn_days = db.Column(db.Integer, nullable=False, default=21)

    # interface
    stale_after_h = db.Column(db.Integer, nullable=False, default=6)

    # proxyd / process
    process_name = db.Column(db.String(48), nullable=True, default="proxyd")
    warn_cpu = db.Column(db.Integer, nullable=False, default=80)
    warn_mem = db.Column(db.Integer, nullable=False, default=80)

    timeout_s = db.Column(db.Integer, nullable=False, default=10)
    interval_min = db.Column(db.Integer, nullable=False, default=5)
    retention = db.Column(db.Integer, nullable=False, default=500)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_run_at = db.Column(db.DateTime, nullable=True)
    last_status = db.Column(db.String(16), nullable=False, default="unknown")
    last_detail = db.Column(db.String(1000), nullable=True, default="")

    appliance = db.relationship("Appliance", lazy="joined")
    # NOT passive_deletes: the ORM must issue the child deletes itself. The FK
    # carries ON DELETE CASCADE for direct SQL, but SQLite ships with foreign
    # keys DISABLED, so leaning on the engine would leak orphan samples on any
    # non-Postgres deployment (and in the test suite). Retention caps a probe at
    # a few hundred rows, so the extra SELECT is free.
    samples = db.relationship(
        "MonitorSample", backref="probe", lazy="dynamic",
        cascade="all, delete-orphan")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "name": self.name,
            "note": self.note or "", "enabled": bool(self.enabled),
            "appliance_id": self.appliance_id,
            "appliance": getattr(self.appliance, "name", "") or "",
            "device_kind": getattr(self.appliance, "kind", "") or "",
            "target": self.target or "", "url": self.url or "",
            "expect_status": self.expect_status, "warn_ms": self.warn_ms,
            "tls_warn_days": self.tls_warn_days,
            "stale_after_h": self.stale_after_h,
            "process_name": self.process_name or "proxyd",
            "warn_cpu": self.warn_cpu, "warn_mem": self.warn_mem,
            "timeout_s": self.timeout_s, "interval_min": self.interval_min,
            "retention": self.retention,
            "last_run_at": self.last_run_at.isoformat(timespec="seconds")
                           if self.last_run_at else "",
            "last_status": self.last_status or "unknown",
            "last_detail": self.last_detail or "",
        }

    def __repr__(self) -> str:
        return f"<MonitorProbe {self.kind} {self.name!r}>"


class MonitorSample(db.Model):
    """One observation of a :class:`MonitorProbe`.

    ``fingerprint`` is what makes drift detectable: the PID set for a process,
    the ``name→ip/status`` hash for interfaces, the body hash for HTTPS. A
    sample whose fingerprint differs from its predecessor is an event even when
    every individual value still looks healthy.
    """

    __tablename__ = "monitor_sample"

    id = db.Column(db.Integer, primary_key=True)
    probe_id = db.Column(
        db.Integer, db.ForeignKey("monitor_probe.id", ondelete="CASCADE"),
        nullable=False, index=True)
    ts = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    status = db.Column(db.String(16), nullable=False, default="unknown")
    ok = db.Column(db.Boolean, nullable=False, default=False)
    value_num = db.Column(db.Float, nullable=True)    # latency ms | cpu% | ifaces with IP
    value2_num = db.Column(db.Float, nullable=True)   # tls days | mem% | iface count
    fingerprint = db.Column(db.String(64), nullable=True, default="")
    detail = db.Column(db.String(1000), nullable=True, default="")
    payload = db.Column(db.Text, nullable=True, default="")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "ts": self.ts.isoformat(timespec="seconds"),
            "status": self.status, "ok": bool(self.ok),
            "value_num": self.value_num, "value2_num": self.value2_num,
            "fingerprint": self.fingerprint or "",
            "detail": self.detail or "",
        }

    def __repr__(self) -> str:
        return f"<MonitorSample probe={self.probe_id} {self.status}>"
