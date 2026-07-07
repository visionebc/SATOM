"""Notification service — the ONE place features raise a bell notification.

Every function is best-effort and NEVER raises: a notification failing to write
must not break the operation that triggered it (a firmware job, a bug-report
resolve…). Callers therefore never need a try/except of their own.

Usage::

    from ..services import notifications as notify
    notify.push(user_id, "firmware.out ready", kind="success",
                body="SHA-256 verified — 293 MB", link=url_for("firmware.index"))

This module owns its DB writes via the shared ``db.session``; it is import-safe
from a background-job worker thread as long as that thread holds an app context
(the firmware worker does).
"""
from __future__ import annotations

import logging

from ..extensions import db
from ..models_notifications import Notification
from .product_scope import scope_query as _scope_query, stamp as _stamp_product

logger = logging.getLogger(__name__)


def push(user_id: int, title: str, *, kind: str = Notification.KIND_INFO,
         body: str | None = None, link: str | None = None,
         product: str | None = None) -> Notification | None:
    """Create a notification for one user. Returns the row, or ``None`` on any
    failure (logged, never raised)."""
    if not user_id or not title:
        return None
    try:
        n = Notification(
            user_id=int(user_id),
            kind=kind or Notification.KIND_INFO,
            title=title[:200],
            body=body,
            link=link[:500] if link else None,
            product=(product if product is not None else _stamp_product()),
        )
        db.session.add(n)
        db.session.commit()
        return n
    except Exception:  # noqa: BLE001 — a notification must never break the caller
        logger.exception("notifications.push failed (user=%s title=%r)",
                         user_id, title)
        try:
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return None


def push_many(user_ids, title: str, **kw) -> int:
    """Push the same notification to several users (e.g. all admins). Returns the
    count actually written."""
    n = 0
    for uid in set(user_ids or []):
        if push(uid, title, **kw) is not None:
            n += 1
    return n


def unread_count(user_id: int) -> int:
    if not user_id:
        return 0
    try:
        return _scope_query(
            Notification.query.filter_by(user_id=user_id, read=False),
            Notification.product).count()
    except Exception:  # noqa: BLE001
        logger.debug("unread_count failed", exc_info=True)
        return 0


def recent(user_id: int, limit: int = 50) -> list[Notification]:
    if not user_id:
        return []
    try:
        return (_scope_query(Notification.query.filter_by(user_id=user_id),
                             Notification.product)
                .order_by(Notification.created_at.desc(), Notification.id.desc())
                .limit(limit).all())
    except Exception:  # noqa: BLE001
        logger.debug("recent failed", exc_info=True)
        return []


def mark_all_read(user_id: int) -> int:
    """Mark every unread notification for the user read. Returns rows updated."""
    if not user_id:
        return 0
    try:
        n = (_scope_query(Notification.query.filter_by(user_id=user_id,
                                                        read=False),
                          Notification.product)
             .update({"read": True}, synchronize_session=False))
        db.session.commit()
        return n
    except Exception:  # noqa: BLE001
        logger.exception("mark_all_read failed (user=%s)", user_id)
        try:
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return 0


def mark_read(user_id: int, notif_id: int) -> bool:
    if not user_id or not notif_id:
        return False
    try:
        n = Notification.query.filter_by(id=notif_id, user_id=user_id).first()
        if n is None:
            return False
        if not n.read:
            n.read = True
            db.session.commit()
        return True
    except Exception:  # noqa: BLE001
        logger.exception("mark_read failed (user=%s id=%s)", user_id, notif_id)
        try:
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return False


def clear_all(user_id: int) -> int:
    """Delete all notifications for the user (the page's 'Clear all')."""
    if not user_id:
        return 0
    try:
        n = _scope_query(Notification.query.filter_by(user_id=user_id),
                         Notification.product).delete(synchronize_session=False)
        db.session.commit()
        return n
    except Exception:  # noqa: BLE001
        logger.exception("clear_all failed (user=%s)", user_id)
        try:
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return 0
