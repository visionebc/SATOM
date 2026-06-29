"""DB-first read layer — the source of truth serves the UI; the box is touched
only on an explicit refresh (⟳). Centralises cached reads so views stop calling
the appliance on every page load (the 2000-policy problem).
"""
from __future__ import annotations

from datetime import datetime


def read_objects(appliance_id: int, logical_name: str, *, q: str | None = None,
                 page: int = 1, per_page: int = 10000, session=None):
    """Return (payloads, meta) for the top-level objects of a logical type.

    payloads keep the raw FortiWeb shape (hyphenated keys) so existing templates
    render unchanged. meta carries freshness: generated_at / source / total.
    """
    from ..extensions import db
    from ..models_cache import DeviceObject, DeviceSnapshot
    session = session or db.session

    query = session.query(DeviceObject).filter_by(
        appliance_id=appliance_id, logical_name=logical_name, depth=0)
    if q:
        query = query.filter(DeviceObject.mkey.ilike(f"%{q}%"))
    total = query.count()
    rows = (query.order_by(DeviceObject.idx)
            .limit(per_page).offset((page - 1) * per_page).all())
    payloads = [r.payload or {} for r in rows]

    section = rows[0].section if rows else None
    snap = None
    if section:
        snap = (session.query(DeviceSnapshot)
                .filter_by(appliance_id=appliance_id, section=section)
                .order_by(DeviceSnapshot.generated_at.desc()).first())
    meta = {
        "total": total,
        "count": len(payloads),
        "generated_at": snap.generated_at if snap else None,
        "source": snap.source if snap else None,
        "section": section,
        "cached": bool(rows),
    }
    return payloads, meta


def read_policies(appliance, *, q: str | None = None, session=None):
    """Server policies for the Server Policy page (DB-first)."""
    return read_objects(appliance.id, "server_policy", q=q, session=session)


def freshness_label(meta: dict) -> str:
    """Human 'DB · hace 3 h' style label for a freshness badge."""
    ga = meta.get("generated_at")
    if not ga:
        return "no local data — refresh"
    if isinstance(ga, str):
        try:
            ga = datetime.fromisoformat(ga)
        except ValueError:
            return "DB"
    delta = datetime.utcnow() - ga
    secs = int(delta.total_seconds())
    if secs < 60:
        ago = "just now"
    elif secs < 3600:
        ago = f"{secs // 60} min ago"
    elif secs < 86400:
        ago = f"{secs // 3600} h ago"
    else:
        ago = f"{secs // 86400} d ago"
    src = meta.get("source") or "DB"
    return f"DB · {ago}" + (f" · {src}" if src and src != "DB" else "")
