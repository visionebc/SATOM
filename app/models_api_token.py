"""API tokens — the third-party / machine-to-machine credential model.

Session auth (flask-login cookie + CSRF) is for humans in a browser. A token is
a credential that lives OUTSIDE the browser: no CSRF, no auto-expiring session,
carried as ``Authorization: Bearer fmk_<public_id>_<secret>``. Because it can be
copied and leaked, the security bar is higher than a normal feature — hence:

* only a one-way HASH of the secret is stored (never the token itself);
* every token is scoped (read | write | admin), bound to ONE product/ADOM, and
  owned by a real user — a token can NEVER exceed its owner's RBAC;
* destructive firmware ops (upgrade/flash/reboot) are NOT exposed by /api/v1 at
  all, so no scope can reach them.

The plaintext token is shown to the operator EXACTLY ONCE, at creation.
"""
from __future__ import annotations

import json
import secrets
from datetime import datetime

from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db

# Coarse scope vocabulary. Ordered least -> most privileged; an endpoint that
# needs ``read`` is satisfied by any scope, ``write`` by write/admin, etc.
SCOPES = ("read", "write", "admin")
_SCOPE_RANK = {s: i for i, s in enumerate(SCOPES)}

# scope -> the owner RBAC permission it is allowed to exercise. A token can hold
# a scope only if its OWNER user holds the mapped permission (checked at auth
# time, so revoking the human also neuters their tokens).
SCOPE_REQUIRED_PERMISSION = {
    "read": "view",
    "write": "config_write",
    "admin": "user_manage",
}

VALID_PRODUCTS = ("fortiweb", "fortiadc", "global")

TOKEN_PREFIX = "fmk"  # Fortinet-Manager-Key

# --------------------------------------------------------------------------- #
#  Fine-grained authorization — the "what" and the "where" (Phase 2)           #
# --------------------------------------------------------------------------- #
# scope (read|write|admin) answers "how privileged". CAPABILITIES answer "which
# KINDS of action" and app_ids answer "on WHICH server policies". Both are
# ALLOW-LISTS with a permissive empty default so existing tokens keep working:
#
#   * capabilities == []  -> no action-type restriction (any non-danger action
#                            the scope + product already allow).
#   * capabilities != []  -> the action's capability tag MUST be in the list.
#   * app_ids == []       -> no location restriction.
#   * app_ids != []       -> the action must target a server policy bound to one
#                            of these AppIDs; a non-policy/fleet action is denied
#                            (an AppID-scoped token has no fleet-wide reach).
#
# This is exactly the operator's ask: "un token que SOLO puede editar backends
# de estos AppIDs".
CAPABILITIES = ("backend_edit", "backend_config", "policy_status", "cert_swap", "maintenance", "reports")

# Every runnable catalog action → the capability tag it belongs to. An action
# missing here has tag None, so a capability-restricted token can never run it
# (fail-closed) while an unrestricted token still can.
ACTION_CAPABILITY = {
    # user-scope object mutations (the AppID-scopable ones)
    "backend_set_status": "backend_edit",
    "backend_set_config": "backend_config",
    "policy_set_status": "policy_status",
    "swap_certificate": "cert_swap",
    # admin non-destructive maintenance
    "backup": "maintenance",
    "device_sync": "maintenance",
    "device_inspect": "maintenance",
    "deep_capture": "maintenance",
    "signature_sync": "maintenance",
    "system_backup": "maintenance",
    "cert_scan": "maintenance",
    "cert_lifecycle": "maintenance",
    "upgrade_prep": "maintenance",
    "appid_import": "maintenance",
    "custom_rest": "maintenance",
    # read/report style
    "stats": "reports",
    "inventory_snapshot": "reports",
    "health_check": "reports",
    "ha_check": "reports",
}

# Capabilities that act on ONE concrete server policy, so an AppID scope can be
# resolved and enforced. A token carrying an app_ids allow-list may run ONLY
# these; anything else (fleet maintenance/reports) is denied for such a token.
APPID_SCOPABLE = {"backend_edit", "backend_config", "policy_status", "cert_swap"}


def capability_for(action_key: str) -> str | None:
    """The capability tag of a catalog action key (None if unmapped)."""
    return ACTION_CAPABILITY.get(action_key)


class ApiToken(db.Model):
    __tablename__ = "api_tokens"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, default="")
    # Public, non-secret lookup id embedded in the token string; indexed so auth
    # is one indexed row read, then a constant-time hash compare of the secret.
    public_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    token_hash = db.Column(db.String(256), nullable=False)  # scrypt(secret)

    owner_user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True)
    owner = db.relationship("User", lazy="joined", foreign_keys=[owner_user_id])

    scopes = db.Column(db.Text, nullable=False, default='["read"]')  # JSON list
    product = db.Column(db.String(16), nullable=False, default="fortiweb")

    # Fine-grained authorization (Phase 2). Both JSON lists; empty = unrestricted.
    capabilities = db.Column(db.Text, nullable=False, default="[]")   # CAPABILITIES
    app_ids = db.Column(db.Text, nullable=False, default="[]")        # AppId.app_id names

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by = db.Column(db.String(64), nullable=True, default="")
    expires_at = db.Column(db.DateTime, nullable=True)
    last_used_at = db.Column(db.DateTime, nullable=True)
    last_used_ip = db.Column(db.String(64), nullable=True)
    revoked = db.Column(db.Boolean, nullable=False, default=False)

    # ------------------------------------------------------------------ scopes
    @property
    def scope_list(self) -> list[str]:
        try:
            v = json.loads(self.scopes or "[]")
            return [s for s in v if s in SCOPES] if isinstance(v, list) else []
        except (ValueError, TypeError):
            return []

    def set_scopes(self, scopes: list[str]) -> None:
        clean = [s for s in dict.fromkeys(scopes) if s in SCOPES]
        self.scopes = json.dumps(clean or ["read"])

    def has_scope(self, needed: str) -> bool:
        """True if any held scope is at least as privileged as *needed*."""
        want = _SCOPE_RANK.get(needed)
        if want is None:
            return False
        return any(_SCOPE_RANK.get(s, -1) >= want for s in self.scope_list)

    # ---------------------------------------------- capabilities + AppID scope
    @property
    def capability_list(self) -> list[str]:
        try:
            v = json.loads(self.capabilities or "[]")
            return [c for c in v if c in CAPABILITIES] if isinstance(v, list) else []
        except (ValueError, TypeError):
            return []

    def set_capabilities(self, caps: list[str]) -> None:
        clean = [c for c in dict.fromkeys(caps or []) if c in CAPABILITIES]
        self.capabilities = json.dumps(clean)

    @property
    def app_id_list(self) -> list[str]:
        try:
            v = json.loads(self.app_ids or "[]")
            return [str(a).strip() for a in v if str(a).strip()] if isinstance(v, list) else []
        except (ValueError, TypeError):
            return []

    def set_app_ids(self, ids: list[str]) -> None:
        clean = [s for s in dict.fromkeys((i or "").strip() for i in (ids or [])) if s]
        self.app_ids = json.dumps(clean)

    @property
    def is_appid_scoped(self) -> bool:
        return bool(self.app_id_list)

    def authorize_capability(self, action_key: str) -> tuple[bool, str, str]:
        """Gate an action by the token's capability allow-list (the "what").

        Returns ``(ok, error_code, message)``. Empty capability list = allow.
        An AppID-scoped token additionally may run ONLY AppID-scopable actions.
        """
        tag = ACTION_CAPABILITY.get(action_key)
        caps = self.capability_list
        if caps and tag not in caps:
            return (False, "capability_denied",
                    f"This token is not allowed to run '{action_key}' "
                    f"(capability '{tag}' not granted).")
        if self.is_appid_scoped and tag not in APPID_SCOPABLE:
            return (False, "not_appid_scopable",
                    "This token is AppID-scoped; it can only run actions that "
                    "target a specific server policy (backend/policy/cert ops), "
                    "not fleet-wide actions.")
        return (True, "", "")

    # --------------------------------------------------------------- lifecycle
    @property
    def is_expired(self) -> bool:
        return self.expires_at is not None and datetime.utcnow() >= self.expires_at

    @property
    def is_active(self) -> bool:
        return not self.revoked and not self.is_expired

    def verify(self, secret: str) -> bool:
        try:
            return check_password_hash(self.token_hash, secret)
        except Exception:  # noqa: BLE001 — a malformed hash must not 500
            return False

    @property
    def masked(self) -> str:
        """Display form — the public id, secret redacted."""
        return f"{TOKEN_PREFIX}_{self.public_id}_" + "•" * 8

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "public_id": self.public_id,
            "masked": self.masked,
            "owner": getattr(self.owner, "username", None),
            "scopes": self.scope_list,
            "capabilities": self.capability_list,
            "app_ids": self.app_id_list,
            "product": self.product,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "revoked": bool(self.revoked),
            "active": self.is_active,
        }

    def __repr__(self) -> str:
        return f"<ApiToken {self.name!r} {self.public_id} product={self.product}>"


# ---------------------------------------------------------------------------
# Minting + parsing
# ---------------------------------------------------------------------------

def _new_public_id() -> str:
    return secrets.token_hex(8)  # 16 hex chars


def mint_token(*, name, owner, scopes, product, expires_at=None, created_by="",
               capabilities=None, app_ids=None):
    """Create + persist a token. Returns ``(ApiToken, plaintext)``.

    The plaintext (``fmk_<public_id>_<secret>``) is returned ONCE and never
    stored — only ``scrypt(secret)`` lands in the DB.
    """
    if product not in VALID_PRODUCTS:
        raise ValueError(f"invalid product {product!r}")
    # Guarantee a unique public id (indexed unique column).
    for _ in range(5):
        public_id = _new_public_id()
        if not db.session.query(ApiToken.id).filter_by(public_id=public_id).first():
            break
    else:  # pragma: no cover — astronomically unlikely
        raise RuntimeError("could not allocate a unique token id")

    secret = secrets.token_urlsafe(32)
    tok = ApiToken(
        name=(name or "").strip()[:128] or "unnamed",
        public_id=public_id,
        token_hash=generate_password_hash(secret, method="scrypt"),
        owner_user_id=owner.id,
        product=product if product in VALID_PRODUCTS else "fortiweb",
        created_by=(created_by or "")[:64],
        expires_at=expires_at,
    )
    tok.set_scopes(scopes)
    tok.set_capabilities(capabilities or [])
    tok.set_app_ids(app_ids or [])
    db.session.add(tok)
    db.session.commit()
    plaintext = f"{TOKEN_PREFIX}_{public_id}_{secret}"
    return tok, plaintext


def parse_token(raw: str):
    """Split a presented token into ``(public_id, secret)`` or ``(None, None)``."""
    if not raw:
        return None, None
    raw = raw.strip()
    parts = raw.split("_", 2)
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX or not parts[1] or not parts[2]:
        return None, None
    return parts[1], parts[2]


def lookup(raw: str):
    """Resolve a presented token string to its ACTIVE, VERIFIED row, or None."""
    public_id, secret = parse_token(raw)
    if not public_id:
        return None
    tok = db.session.query(ApiToken).filter_by(public_id=public_id).first()
    if tok is None or not tok.is_active:
        return None
    if not tok.verify(secret):
        return None
    return tok
