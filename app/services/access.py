"""Access-administration helpers — capability-based anti-lockout counting.

A user "administers access" when they can manage BOTH users and profiles
(``permissions.ADMIN_CAPABILITIES``). The guards in the users/profiles views
must never let the number of ACTIVE such users fall to zero, regardless of the
legacy ``role`` string.
"""
from __future__ import annotations

from ..models import User


def admin_capable_users(exclude_id: int | None = None) -> list[User]:
    """All active users who can administer access (manage users + profiles)."""
    out = []
    for u in User.query.filter_by(is_active=True).all():
        if exclude_id is not None and u.id == exclude_id:
            continue
        if u.is_admin_capable:
            out.append(u)
    return out


def active_admin_count(exclude_id: int | None = None) -> int:
    return len(admin_capable_users(exclude_id=exclude_id))


def would_orphan_admins(exclude_id: int | None = None) -> bool:
    """True if excluding ``exclude_id`` would leave zero admin-capable users."""
    return active_admin_count(exclude_id=exclude_id) == 0
