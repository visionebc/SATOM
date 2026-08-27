"""The versioner: record, compare and roll back an authored carve-out.

Every write path in :mod:`services.wpp_exceptions` funnels through
:func:`record`, which is a no-op when the content hash is unchanged. That
property is what makes it safe to call from the store's ``update`` without
first asking whether anything actually changed — and it is why a page that
re-saves a form untouched does not bury the real edits under identical rows.

**A rollback is a forward move.** :func:`rollback` reads an old version, writes
it onto the placement, and appends a NEW version carrying the old body under
:data:`~models_exceptions.ACT_ROLLBACK`. Nothing is deleted, so "we tried X,
then undid it" stays legible; a versioner that rewrote its own history would
lose exactly the trail an incident review needs.

The diff is STRUCTURAL, not textual. Two JSON bodies rendered as text differ on
key order, indentation and the position of a field that merely moved — the same
reason ``views/system_backup`` stopped diffing 600 KB snapshots as strings.
"""
from __future__ import annotations

from typing import Any

from ..models import db
from ..models_exceptions import (
    ACT_CLONE, ACT_CREATE, ACT_DELETE, ACT_IMPORT, ACT_RESTORE, ACT_ROLLBACK,
    ACT_UPDATE, ACTIONS, ExceptionVersion, body_of, new_uid, sha_of,
)

# Re-exported so callers version through ONE module. A view that imported
# body_of/sha_of straight from models_exceptions would be a second route to
# the hashing rules, and the first divergence would mint spurious versions.
__hash_helpers__ = (body_of, sha_of)


def scope_label(exc) -> str:
    """``device / adom`` for the appliance a placement sits on.

    Delegates to :mod:`services.waf_fleet` so this label and the one the WAF
    pages print have ONE author. A placement whose appliance is gone reports
    the id rather than an empty string: "" renders as a scope with no name,
    which reads like a bug in the page instead of a deleted appliance.
    """
    appl = getattr(exc, "appliance", None)
    if appl is None:
        aid = getattr(exc, "appliance_id", None)
        if not aid:
            return "(library)"
        from ..models import Appliance
        appl = db.session.get(Appliance, aid)
        if appl is None:
            return "(appliance #%s, removed)" % aid
    try:
        from . import waf_fleet
        return waf_fleet.scope_label(appl)
    except Exception:  # noqa: BLE001 — a label must never break a save
        return getattr(appl, "name", "") or ""


def ensure_lineage(exc) -> str:
    """Mint the stable identity on first use.

    Every carve-out authored before the versioner existed has ``lineage``
    NULL. Backfilling them all at boot would stamp today's timestamp on
    thirteen records as though they had just been created; minting lazily, on
    the first write that needs one, keeps the claim honest.
    """
    lin = getattr(exc, "lineage", None)
    if not lin:
        lin = new_uid()
        exc.lineage = lin
    return lin


def latest(lineage: str) -> ExceptionVersion | None:
    if not lineage:
        return None
    return (ExceptionVersion.query
            .filter_by(lineage=lineage)
            .order_by(ExceptionVersion.id.desc())
            .first())


def history(lineage: str, limit: int | None = None) -> list[ExceptionVersion]:
    """Newest first. An empty list means "never versioned", NOT "never changed"
    — a placement authored before the versioner shipped has no history and the
    page must say so rather than render an empty timeline as a clean one."""
    if not lineage:
        return []
    q = (ExceptionVersion.query
         .filter_by(lineage=lineage)
         .order_by(ExceptionVersion.id.desc()))
    if limit:
        q = q.limit(limit)
    return q.all()


def record(exc, *, action: str = ACT_UPDATE, author: str = "",
           note: str = "", body: dict | None = None,
           force: bool = False) -> ExceptionVersion | None:
    """Append a version for *exc* unless its content is unchanged.

    Returns the new row, or ``None`` when the hash matched the newest version
    (nothing was written). ``force`` is for the verbs whose MEANING is the
    event rather than the content — a delete records the body that was lost
    even though those exact bytes are already the newest version.
    """
    lineage = ensure_lineage(exc)
    payload = body if body is not None else body_of(exc)
    sha = sha_of(payload)
    prev = latest(lineage)
    if prev is not None and prev.sha256 == sha and not force:
        return None
    import json as _json
    row = ExceptionVersion(
        lineage=lineage,
        exception_id=getattr(exc, "id", None),
        appliance_id=getattr(exc, "appliance_id", None),
        scope=scope_label(exc),
        sha256=sha,
        body=_json.dumps(payload, sort_keys=True, ensure_ascii=False),
        action=action or ACT_UPDATE,
        author=author or "",
        note=note or "",
    )
    db.session.add(row)
    return row


def record_delete(exc, *, author: str = "", note: str = "") -> ExceptionVersion:
    """The last thing a carve-out does. ``force`` because the body is by
    definition identical to the newest version — what is being recorded is the
    disappearance, and skipping it would leave a history whose final entry
    claims the record is still live."""
    return record(exc, action=ACT_DELETE, author=author,
                  note=note or "placement deleted", force=True)


def restorable_for(appliance_id: int) -> list[dict]:
    """Lineages whose last recorded event on this scope was a DELETE.

    Derived, never stored: a "deleted carve-outs" table would be a second
    source of truth for a fact the history already carries, and the two would
    disagree the first time a restore was rolled back. A lineage that was
    deleted and later restored is excluded because a live placement exists —
    the same reason :func:`restore` refuses in that case.
    """
    from ..models import WppException
    rows = (ExceptionVersion.query
            .filter_by(appliance_id=appliance_id)
            .order_by(ExceptionVersion.id.desc())
            .all())
    live = {e.lineage for e in WppException.query
            .filter_by(appliance_id=appliance_id).all() if e.lineage}
    out: list[dict] = []
    seen: set[str] = set()
    for row in rows:
        if row.lineage in seen or row.lineage in live:
            continue
        seen.add(row.lineage)
        if row.action != ACT_DELETE:
            continue
        body = row.body_dict
        out.append({
            "lineage": row.lineage, "version_id": row.id,
            "name": body.get("name") or "", "exc_type": body.get("exc_type") or "",
            "category": body.get("category") or "",
            "wpp_mkey": body.get("wpp_mkey") or "",
            "policies": list(body.get("policies") or []),
            "scope": row.scope, "author": row.author or "",
            "note": row.note or "",
            "deleted_at": row.created_at.isoformat(timespec="seconds")
                          if row.created_at else "",
        })
    return out


def diff(old: dict, new: dict) -> dict[str, Any]:
    """Structural comparison of two bodies.

    ``policies`` is compared as a SET, not a list: the store keeps them sorted
    but an imported or hand-built body may not, and reporting a reorder as a
    change would make every import look like an edit.
    """
    old = old or {}
    new = new or {}
    changed: list[dict] = []
    added: list[dict] = []
    removed: list[dict] = []

    def _norm(k, v):
        if k == "policies":
            return sorted(v or [])
        return v

    keys = sorted(set(old) | set(new))
    for k in keys:
        if k == "payload":
            continue
        in_old, in_new = k in old, k in new
        ov, nv = _norm(k, old.get(k)), _norm(k, new.get(k))
        if in_old and not in_new:
            removed.append({"field": k, "old": ov})
        elif in_new and not in_old:
            added.append({"field": k, "new": nv})
        elif ov != nv:
            changed.append({"field": k, "old": ov, "new": nv})

    op, np_ = old.get("payload") or {}, new.get("payload") or {}
    for k in sorted(set(op) | set(np_)):
        label = "payload.%s" % k
        if k in op and k not in np_:
            removed.append({"field": label, "old": op[k]})
        elif k in np_ and k not in op:
            added.append({"field": label, "new": np_[k]})
        elif op[k] != np_[k]:
            changed.append({"field": label, "old": op[k], "new": np_[k]})

    return {"added": added, "removed": removed, "changed": changed,
            "identical": not (added or removed or changed)}


def diff_versions(a: ExceptionVersion, b: ExceptionVersion) -> dict[str, Any]:
    return diff(a.body_dict if a else {}, b.body_dict if b else {})


def rollback(exc, version_id: int, *, author: str = "",
             note: str = "") -> dict[str, Any]:
    """Write an old body back onto *exc* and append a rollback version.

    Refuses across lineages: a version id belonging to another carve-out would
    silently overwrite this one with a stranger's content, and the ids are
    sequential enough that a mistyped one usually EXISTS.
    """
    import json as _json
    lineage = getattr(exc, "lineage", None)
    row = db.session.get(ExceptionVersion, int(version_id or 0))
    if row is None:
        return {"ok": False, "error": "version not found"}
    if not lineage or row.lineage != lineage:
        return {"ok": False, "error": "version belongs to another carve-out"}

    old = row.body_dict
    before = body_of(exc)
    if sha_of(old) == sha_of(before):
        return {"ok": True, "changed": False, "version": None,
                "note": "already at that version"}

    exc.wpp_mkey = old.get("wpp_mkey") or ""
    exc.name = old.get("name") or ""
    exc.reason = old.get("reason") or ""
    exc.enabled = bool(old.get("enabled", True))
    exc.payload = _json.dumps(old.get("payload") or {})
    # exc_type and category are NOT restored: changing the type of a live
    # placement turns it into a different object whose payload no longer
    # validates, and the catalog is the authority on which fields exist.
    from . import wpp_exceptions as store
    store._set_policies(exc, list(old.get("policies") or []))

    new_row = record(exc, action=ACT_ROLLBACK, author=author,
                     note=note or ("rolled back to version #%d (%s)"
                                   % (row.id, (row.sha256 or "")[:12])),
                     force=True)
    db.session.commit()
    return {"ok": True, "changed": True,
            "version": new_row.to_dict() if new_row else None,
            "diff": diff(before, old)}


def restore(lineage: str, *, appliance_id: int, author: str = "") -> dict[str, Any]:
    """Re-create a DELETED placement from the last body its lineage recorded.

    The undo the FK cascade would have made impossible. Refuses when the
    lineage still has a live placement — restoring on top of a live record
    would duplicate it, and the operator's actual intent in that case is a
    rollback.
    """
    from ..models import WppException
    live = WppException.query.filter_by(lineage=lineage).first()
    if live is not None:
        return {"ok": False, "error": "this carve-out still exists — use rollback",
                "exc_id": live.id}
    rows = history(lineage, limit=None)
    if not rows:
        return {"ok": False, "error": "no history for this carve-out"}
    # The newest row is the delete marker; the body it carries is the state at
    # deletion, which is exactly what a restore should bring back.
    src = rows[0]
    body = src.body_dict
    if not body.get("exc_type"):
        return {"ok": False, "error": "recorded version carries no type"}
    from . import wpp_exceptions as store
    exc = store.add(appliance_id, wpp_mkey=body.get("wpp_mkey") or "",
                    exc_type=body["exc_type"], payload=body.get("payload") or {},
                    name=body.get("name") or "", reason=body.get("reason") or "",
                    author=author, policies=list(body.get("policies") or []),
                    category=body.get("category") or None,
                    lineage=lineage, version_action=ACT_RESTORE,
                    version_note="restored from version #%d" % src.id)
    return {"ok": True, "exc_id": exc.id, "lineage": lineage}


__all__ = [
    "ACTIONS", "ACT_CREATE", "ACT_UPDATE", "ACT_ROLLBACK", "ACT_DELETE",
    "ACT_RESTORE", "ACT_CLONE", "ACT_IMPORT",
    "scope_label", "ensure_lineage", "latest", "history", "record",
    "record_delete", "diff", "diff_versions", "rollback", "restore",
    "restorable_for", "body_of", "sha_of",
]
