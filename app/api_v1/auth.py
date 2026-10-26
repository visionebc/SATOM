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


def rate_key() -> str:
    """Flask-Limiter key for /api/v1: the presented token's public id.

    The limiter keyed every API limit on the client IP. Behind a NAT or a CI
    runner farm, unrelated integrations shared one bucket and starved each
    other, while one token spread over many hosts was never limited at all. The
    public id is the non-secret half of ``fmk_<public_id>_<secret>``; a request
    without a parseable token falls back to the IP (it is about to get a 401).
    Runs BEFORE ``token_required`` (the limiter decorator is outermost), so it
    reads the header, never ``g.api_token``."""
    from ..extensions import real_client_ip
    from ..models_api_token import parse_token
    try:
        public_id, _secret = parse_token(_bearer())
    except Exception:  # noqa: BLE001 — malformed: limited by address
        public_id = None
    if public_id:
        return "tok:" + str(public_id)[:32]
    return "ip:" + str(real_client_ip() or "")


def _err(status: int, code: str, message: str):
    resp = jsonify({"error": code, "message": message})
    resp.status_code = status
    if status == 401:
        resp.headers["WWW-Authenticate"] = 'Bearer realm="satom"'
    return resp


def _touch(tok) -> None:
    """Best-effort, throttled last-used stamp (never a write per request)."""
    now = datetime.utcnow()
    if tok.last_used_at is not None and (now - tok.last_used_at) < _LAST_USED_THROTTLE:
        return
    try:
        from ..extensions import real_client_ip
        tok.last_used_at = now
        tok.last_used_ip = real_client_ip()
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
        # The scope is STAMPED on the view so the OpenAPI document
        # (app.api_v1.openapi) reads it off the function the router holds.
        # The document is derived from what runs, never from a second list
        # kept by hand -- a duplicated list is how the first one drifts.
        wrapper.api_scope = scope
        wrapper.api_capabilities = tuple(getattr(f, "api_capabilities", ()))
        return wrapper
    return decorator


def declares_capability(*caps: str):
    """Record the explicit capabilities a view asks the token for.

    Documentation only: enforcement stays inside the view, through
    ``ApiToken.authorize_object`` (the floor for every caller) and the extra
    checks the view makes for ``apply``. Applied BELOW ``token_required`` so
    the stamp reaches the wrapper the router holds.
    """
    def decorator(f):
        f.api_capabilities = tuple(caps)
        return f
    return decorator


def read_gate(cap: str):
    """``None`` when the token may read the data surface *cap*, else the 403.

    One door for every read capability (``ApiToken.authorize_read``), so the
    metrics, findings, node and config-history routes cannot drift apart again.
    """
    ok, code, msg = g.api_token.authorize_read(cap)
    return None if ok else _err(403, code, msg)


def owner_permission(perm: str):
    """``None`` when the token's owner holds *perm*, else the 403 response.

    A token never exceeds the human behind it: a surface the console gates on
    a named permission (templates on ``operations.view``, approval on
    ``operations.template_approve``) asks the OWNER for the same one, on top
    of the scope's own mapping.
    """
    owner = getattr(g, "api_token_owner", None)
    if owner is not None and owner.can(perm):
        return None
    return _err(403, "owner_forbidden",
                f"The token owner lacks the permission this call needs ('{perm}').")


def audit_extra(**more) -> dict:
    """Standard audit payload attributing the call to the token + its owner."""
    tok = getattr(g, "api_token", None)
    base = {"via": "api"}
    if tok is not None:
        base.update(token=tok.public_id, token_name=tok.name,
                    owner=getattr(tok.owner, "username", None))
    base.update(more)
    return base
