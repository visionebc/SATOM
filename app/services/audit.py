"""Audit logging service."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from flask_login import current_user

from ..extensions import db, real_client_ip
from ..models import AuditLog


def log_action(
    action: str,
    target: str = "",
    extra: dict[str, Any] | None = None,
    **kwargs: Any,
) -> None:
    # kwargs accepted for backward compat (appliance_id=, detail=, etc.)
    if kwargs and extra is None:
        extra = kwargs
    """Append one row to audit_logs and commit.

    Safe to call outside a request context (user_id/username/ip will be None).
    """
    try:
        user_id = current_user.id if current_user.is_authenticated else None
        username = current_user.username if current_user.is_authenticated else "anonymous"
    except Exception:  # noqa: BLE001 — audit is best-effort, never fatal
        user_id = None
        username = "system"

    # NOT ``request.remote_addr``. Every SATOM deployment is served through a
    # reverse proxy, so the peer address is the proxy — which is why every audit
    # row written before 2026-08-08 says ``127.0.0.1`` and the audit trail can
    # not tell two operators apart. ``real_client_ip`` (the helper the rate
    # limiter has always used, for exactly this reason) resolves the forwarded
    # address, and only trusts ``X-Forwarded-For`` when the direct peer is a
    # configured proxy, so a client cannot forge the address it is logged under.
    try:
        ip = real_client_ip()
    except Exception:  # noqa: BLE001 — audit is best-effort, never fatal
        ip = None

    try:
        from .product_scope import stamp
        product = stamp()
    except Exception:  # noqa: BLE001 — audit is best-effort, never fatal
        product = ""

    entry = AuditLog(
        product=product,
        user_id=user_id,
        username=username,
        action=action,
        target=target,
        extra=str(extra or {}),
        ip_address=ip,
        timestamp=datetime.utcnow(),
    )
    try:
        db.session.add(entry)
        db.session.commit()
    except Exception:  # noqa: BLE001 — audit is best-effort (read-only standby)
        db.session.rollback()
