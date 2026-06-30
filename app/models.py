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
        if self.kind == "fortiadc":
            return FortiADCClient(self, timeout=timeout)
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "verify_ssl": self.verify_ssl,
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
    timestamp = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False, index=True
    )

    def __repr__(self) -> str:
        return f"<AuditLog {self.action!r} by {self.username!r} at {self.timestamp}>"


# ---------------------------------------------------------------------------
# AppSetting
# ---------------------------------------------------------------------------

class AppSetting(db.Model):
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


# Device-structure cache models (source-of-truth substrate) — import so
# create_all()/Alembic register them.
from . import models_cache  # noqa: E402,F401
