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
