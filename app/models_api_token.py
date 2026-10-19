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

# Products an API token can be scoped to. Derived LIVE from the ADOM registry
# (``cap_tokens``) — a live sequence so ``from ..models_api_token import
# VALID_PRODUCTS`` (api_tokens view) stays in sync after admin edits.
from .branding import live_products as _live_products  # noqa: E402

VALID_PRODUCTS = _live_products("tokens")

TOKEN_PREFIX = "fmk"  # legacy prefix, kept so tokens already issued stay valid

# --------------------------------------------------------------------------- #
#  Fine-grained authorization — the "what" and the "where" (Phase 2)           #
# --------------------------------------------------------------------------- #
# scope (read|write|admin) answers "how privileged". CAPABILITIES answer "which
# KINDS of action" and app_ids answer "on WHICH server policies". Both are
# ALLOW-LISTS with a permissive empty default so existing tokens keep working:
#
#   * capabilities == []  -> no action-type restriction (any non-danger action
#                            the scope + product already allow) -- except an
#                            action with no capability tag, which needs an
#                            owner holding ``user_manage``.
#   * capabilities != []  -> the action's capability tag MUST be in the list.
#   * app_ids == []       -> no location restriction.
#   * app_ids != []       -> the action must target a server policy bound to one
#                            of these AppIDs; a non-policy/fleet action is denied
#                            (an AppID-scoped token has no fleet-wide reach).
#
# This is exactly the operator's ask (translated from Spanish): "a token that can ONLY
# edit the backends of these AppIDs".
CAPABILITIES = ("backend_edit", "backend_config", "policy_status", "cert_swap",
                "maintenance", "reports",
                # --- object-write capabilities (see EXPLICIT_ONLY below) ------
                "waf_exception_draft", "waf_exception_apply",
                "adc_rule_draft", "adc_rule_apply",
                # --- live inventory (see EXPLICIT_ONLY below) -----------------
                "inventory",
                # --- catalog groups added 2026-10-15 (CATALOG_EXPLICIT below) -
                "cert_renew", "monitoring", "sentinel", "feeds",
                "api_library", "netbox")

# ---------------------------------------------------------------------------
# EXPLICIT-ONLY capabilities — the empty-list default does NOT grant these.
#
# For CATALOG ACTIONS an empty ``capabilities`` list means "unrestricted", which
# is safe there because /api/v1 only ever exposed actions the operator had
# already created and flagged non-danger. Reusing that default for the object
# writers below would SILENTLY grant WAF/ADC config-write to every token minted
# before this feature existed — a privilege grant nobody approved, applied
# retroactively to credentials already in third-party hands.
#
# So these are opt-in, always: the capability must be listed on the token.
# ``authorize_object`` is the only gate for them and it never falls back to the
# permissive default.
# ---------------------------------------------------------------------------
EXPLICIT_ONLY_CAPABILITIES = frozenset({
    "waf_exception_draft", "waf_exception_apply",
    "adc_rule_draft", "adc_rule_apply",
    # 'inventory' = POST /appliances/<id>/firmware-check. It writes nothing to
    # the device, but it DOES make SATOM open an authenticated session to a
    # firewall using stored admin credentials, on demand, from outside. That is
    # a capability an operator grants, not one every pre-existing token inherits
    # the day the feature ships.
    "inventory",
})

# ---------------------------------------------------------------------------
# CATALOG capabilities that the empty-list default does NOT grant either.
#
# Until 2026-10-15 these actions had no tag at all, so only a token whose
# owner holds ``user_manage`` could run them, and only with an EMPTY
# capability list -- a token could never be restricted to, say, "monitoring
# sweeps only". Tagging them lets an administrator mint exactly that. Granting
# them through the empty default would widen every token already issued, so
# an empty list keeps the old rule for them (owner with ``user_manage``).
# ---------------------------------------------------------------------------
CATALOG_EXPLICIT_CAPABILITIES = frozenset({
    "cert_renew", "monitoring", "sentinel", "feeds", "api_library", "netbox",
})

# What each capability lets a token do, and how the token form groups them.
# One table for the page, the docs and the tests; the template used to keep
# its own copy of the descriptions.
CAPABILITY_DESC = {
    "backend_edit": "enable/disable pool backends",
    "backend_config": "change a backend IP / port",
    "policy_status": "enable/disable server policies",
    "cert_swap": "swap a policy's certificate",
    "cert_renew": "renew Server / Client / Client+Server certificates (Cert Manager)",
    "maintenance": "backups / sync / deep capture / signature collect (fleet)",
    "reports": "stats / inventory / health / HA checks (read-only, fleet)",
    "monitoring": "deep-monitor sweep, metrics scrape, monitoring report",
    "sentinel": "Sentinel correlate, baselines, CVE mirror refresh, blocklist feed publish",
    "feeds": "signature freshness, knowledge packs, WAF artifact index, HSTS preload list",
    "api_library": "API library harvests (endpoint evidence, CLI schema, watch)",
    "netbox": "NetBox inventory reconcile",
    "waf_exception_draft": "FILE a FortiWeb WAF carve-out (desired state only — never touches a device)",
    "waf_exception_apply": "PUSH a filed FortiWeb carve-out onto the appliance",
    "adc_rule_draft": "PREVIEW a FortiADC carve-out (never touches a device)",
    "adc_rule_apply": "CREATE a FortiADC carve-out on the appliance",
    "inventory": "ASK a device its running firmware, live (reads the device, writes only this inventory)",
}
CAPABILITY_GROUPS = (
    ("Server policies (AppID-scopable)",
     ("backend_edit", "backend_config", "policy_status", "cert_swap")),
    ("Certificates", ("cert_renew",)),
    ("Fleet maintenance & reports", ("maintenance", "reports")),
    ("Monitoring & security", ("monitoring", "sentinel")),
    ("Feeds & integrations", ("feeds", "api_library", "netbox")),
    ("FortiWeb objects (always explicit)", ("waf_exception_draft", "waf_exception_apply")),
    ("FortiADC objects (always explicit)", ("adc_rule_draft", "adc_rule_apply")),
    ("Live inventory (always explicit)", ("inventory",)),
)

# An object capability is only meaningful on a token bound to the matching
# ADOM (or to ``global``). A FortiWeb-only token can never write ADC rules.
CAPABILITY_PRODUCTS = {
    "waf_exception_draft": ("fortiweb",),
    "waf_exception_apply": ("fortiweb",),
    "adc_rule_draft": ("fortiadc",),
    "adc_rule_apply": ("fortiadc",),
    # 'inventory' (live firmware check) applies to EVERY ADOM: asking a box its
    # own version is not a product feature. DERIVED from the registry rather
    # than written as a tuple -- product_scope's own docstring records what a
    # hardcoded product list costs here (adding FortiAuthenticator silently
    # un-scoped an entire ADOM). An ADOM declared tomorrow is covered the day
    # it is declared. 'global' is excluded because authorize_object() already
    # lets a global token through every product binding.
    "inventory": tuple(p for p in VALID_PRODUCTS if p != "global"),
}

# Every runnable catalog action → the capability tag it belongs to. An action
# missing here has tag None, so a capability-restricted token can never run it
# (fail-closed), and an unrestricted token only when its owner holds
# ``user_manage`` (see ``authorize_capability``).
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
    # catalog groups added 2026-10-15 -- explicit (CATALOG_EXPLICIT_CAPABILITIES)
    "cert_manager_server": "cert_renew",
    "cert_manager_clientserver": "cert_renew",
    "cert_manager_client": "cert_renew",
    "deep_monitor": "monitoring",
    "metrics_scrape": "monitoring",
    "observatory_scan": "monitoring",
    "monitor_report": "monitoring",
    "sentinel_sweep": "sentinel",
    "sentinel_baseline": "sentinel",
    "sentinel_vuln_sync": "sentinel",
    "sentinel_feed_publish": "sentinel",
    "signature_check": "feeds",
    "knowledge_fetch": "feeds",
    "hsts_preload_refresh": "feeds",
    "artifact_refs": "feeds",
    "apilib_harvest": "api_library",
    "schema_harvest": "api_library",
    "schema_watch": "api_library",
    "netbox_reconcile": "netbox",
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
    product = db.Column(db.String(32), nullable=False, default="fortiweb")

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

    def owner_may_use(self, needed: str) -> bool:
        """``has_scope`` AND the owner still holds the permission that scope
        maps to (SCOPE_REQUIRED_PERMISSION). ``token_required`` checks this for
        the scope an endpoint declares; a handler that branches on a HIGHER
        scope (``admin`` widening a listing) must ask this, not ``has_scope``,
        or an admin-scope token owned by an operator reads like an admin."""
        if not self.has_scope(needed):
            return False
        perm = SCOPE_REQUIRED_PERMISSION.get(needed)
        owner = self.owner
        return bool(perm is None or (owner is not None and owner.can(perm)))

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

        Returns ``(ok, error_code, message)``. Empty capability list = allow
        any MAPPED action. An action with no capability tag (git bundles,
        certificate-manager, feed publishing, NetBox reconcile, ...) is not
        covered by any grant, so the empty-list default does not reach it: it
        runs only for a token whose owner holds ``user_manage``.
        An AppID-scoped token additionally may run ONLY AppID-scopable actions.
        """
        tag = ACTION_CAPABILITY.get(action_key)
        caps = self.capability_list
        if (tag is None or tag in CATALOG_EXPLICIT_CAPABILITIES) and not caps:
            owner = self.owner
            if owner is None or not owner.can("user_manage"):
                if tag:
                    return (False, "capability_denied",
                            f"'{action_key}' needs the '{tag}' capability "
                            "granted explicitly, or a token owned by a user "
                            "administrator.")
                return (False, "capability_denied",
                        f"'{action_key}' has no API capability; only a token "
                        "owned by a user administrator can run it.")
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

    def authorize_object(self, cap: str) -> tuple[bool, str, str]:
        """Gate an OBJECT write (WAF carve-out / ADC rule) on an explicit grant.

        Deliberately NOT ``authorize_capability``: that one treats an empty
        allow-list as "unrestricted", which is right for catalog actions and
        catastrophic here (see EXPLICIT_ONLY_CAPABILITIES). This one requires
        the capability to be present on the token, always, and additionally
        requires the token's ADOM to match the capability's product.

        Returns ``(ok, error_code, message)``.
        """
        if cap not in EXPLICIT_ONLY_CAPABILITIES:
            return (False, "unknown_capability",
                    f"'{cap}' is not an object-write capability.")
        if cap not in self.capability_list:
            return (False, "capability_denied",
                    f"This token does not hold the '{cap}' capability. Ask an "
                    "administrator to grant it.")
        wanted = CAPABILITY_PRODUCTS.get(cap, ())
        if wanted and self.product not in wanted and self.product != "global":
            return (False, "wrong_product",
                    f"'{cap}' applies to {'/'.join(wanted)}; this token is bound "
                    f"to the '{self.product}' ADOM.")
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
