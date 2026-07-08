"""Token authentication for the /api/v1 machine-to-machine surface.

A request authenticates with ``Authorization: Bearer fmk_<public_id>_<secret>``.
The decorator resolves+verifies the token, enforces that (a) the required scope
is held AND (b) the token's OWNER still holds the RBAC permission that scope maps
to — so a token can never outlive or exceed the human behind it — then binds the
ADOM (``g.product``) from the token so ``product_scope`` scopes every query.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from functools import wraps

from flask import g, jsonify, request

from ..extensions import db
from ..models_api_token import SCOPE_REQUIRED_PERMISSION, lookup

_LAST_USED_THROTTLE = timedelta(seconds=60)


def _bearer() -> str:
    hdr = request.headers.get("Authorization", "")
    if hdr[:7].lower() == "bearer ":
        return hdr[7:].strip()
    return ""


def _err(status: int, code: str, message: str):
    resp = jsonify({"error": code, "message": message})
    resp.status_code = status
    if status == 401:
        resp.headers["WWW-Authenticate"] = 'Bearer realm="fortinet-manager"'
    return resp


def _touch(tok) -> None:
    """Best-effort, throttled last-used stamp (never a write per request)."""
    now = datetime.utcnow()
    if tok.last_used_at is not None and (now - tok.last_used_at) < _LAST_USED_THROTTLE:
        return
    try:
        tok.last_used_at = now
        tok.last_used_ip = request.remote_addr
        db.session.commit()
    except Exception:  # noqa: BLE001 — a stamp must never break the call
        db.session.rollback()


def token_required(scope: str = "read"):
    """Gate an /api/v1 view on a valid token that holds *scope* AND whose owner
    still holds the RBAC permission *scope* maps to."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            raw = _bearer()
            if not raw:
                return _err(401, "unauthenticated",
                            "Provide an API token: Authorization: Bearer <token>.")
            tok = lookup(raw)
            if tok is None:
                return _err(401, "invalid_token",
                            "Token is unknown, revoked, expired or malformed.")
            owner = tok.owner
            if owner is None or not getattr(owner, "is_active", False):
                return _err(403, "owner_disabled",
                            "The user that owns this token is disabled.")
            if not tok.has_scope(scope):
                return _err(403, "insufficient_scope",
                            f"This endpoint requires the '{scope}' scope.")
            required_perm = SCOPE_REQUIRED_PERMISSION.get(scope)
            if required_perm and not owner.can(required_perm):
                return _err(403, "owner_forbidden",
                            "The token owner lacks the permission this scope maps "
                            f"to ('{required_perm}').")
            # Bind identity + ADOM for downstream scoping / audit.
            g.api_token = tok
            g.api_token_owner = owner
            g.product = tok.product  # product_scope reads g.product first
            _touch(tok)
            return f(*args, **kwargs)
        return wrapper
    return decorator


def audit_extra(**more) -> dict:
    """Standard audit payload attributing the call to the token + its owner."""
    tok = getattr(g, "api_token", None)
    base = {"via": "api"}
    if tok is not None:
        base.update(token=tok.public_id, token_name=tok.name,
                    owner=getattr(tok.owner, "username", None))
    base.update(more)
    return base
