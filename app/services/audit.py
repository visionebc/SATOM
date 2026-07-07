"""Audit logging service."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from flask import request
from flask_login import current_user

from ..extensions import db
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

    try:
        ip = request.remote_addr
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
    db.session.add(entry)
    db.session.commit()
