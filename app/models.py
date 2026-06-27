"""SQLAlchemy ORM models."""
from __future__ import annotations

import enum
import json
import os
from datetime import datetime
from typing import Any

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

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
    role = db.Column(db.String(16), nullable=False, default=Role.readonly.value)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # audit relationship (back-ref from AuditLog)
    audit_logs = db.relationship("AuditLog", backref="user", lazy="dynamic")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def can(self, permission: str) -> bool:
        return permission in ROLE_PERMISSIONS.get(self.role, set())

    @property
    def permissions(self) -> set[str]:
        return ROLE_PERMISSIONS.get(self.role, set())

    def __repr__(self) -> str:
        return f"<User {self.username!r} role={self.role!r}>"


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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Cached connectivity status, populated by status probes (see probe_status).
    last_status = db.Column(db.String(16), nullable=False, default="unknown")
    last_checked_at = db.Column(db.DateTime, nullable=True)

    @property
    def password(self) -> str:
        return _fernet().decrypt(self.password_enc.encode()).decode()

    @password.setter
    def password(self, plaintext: str) -> None:
        self.password_enc = _fernet().encrypt(plaintext.encode()).decode()

    def set_password(self, plaintext: str) -> None:
        self.password = plaintext

    def build_client(self, timeout: float = 30.0):
        """Return the right vendor client for this appliance's kind."""
        from .clients.fortiweb import FortiWebClient
        from .clients.fortiadc import FortiADCClient
        if self.kind == "fortiadc":
            return FortiADCClient(self, timeout=timeout)
        return FortiWebClient(self, timeout=timeout)

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
            "ssh_port": self.ssh_port,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "status": self.last_status or "unknown",
            "last_checked_at": self.last_checked_at.isoformat() if self.last_checked_at else None,
        }

    def __repr__(self) -> str:
        return f"<Appliance {self.name!r} kind={self.kind!r} host={self.host!r}>"


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

    def __repr__(self) -> str:
        return f"<Template {self.kind}/{self.name} v{self.version}>"


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
