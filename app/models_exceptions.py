"""Identity and history for authored WAF / signature carve-outs.

Two tables, and each exists because a question the operator asks has no
answer without it.

**"Which appliances have this carve-out?"** — :class:`WppException` records a
*placement*: one carve-out, on one (device, ADOM) scope, against one Web
Protection Profile. Nothing tied two placements together, so the same
carve-out authored on two FortiWebs was two unrelated rows and the estate-wide
question was not merely unanswered, it was unrepresentable.
:class:`ExceptionLibraryItem` is the *intent* — authored once, placed N times —
and a placement points at it through ``WppException.library_uid``.

**"Put it back the way it was."** — every mutation of a placement wrote over
the previous payload. :class:`ExceptionVersion` keeps each distinct body,
content-addressed by the sha256 of its canonical form, so an unchanged save
costs no row and a rollback is a NEW version rather than a rewrite of history.

Why the version rows carry ``lineage`` and not just a foreign key: a carve-out
that is deleted must still be restorable, and a ``FOREIGN KEY … ON DELETE
CASCADE`` would take its own history down with it — turning "undo the delete"
into the one operation the versioner cannot do. ``lineage`` is minted once at
creation and survives the row it describes.

Why the bodies live in the column and not in a content-addressed blob tree the
way ``services/sot_store`` keeps device snapshots: a snapshot is megabytes and
a carve-out is a few hundred bytes. The store exists to keep 90 MB/hour off
the disk; paying its indirection for a payload smaller than the row that
indexes it buys nothing and puts the history outside ``pg_dump``.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from .models import db

# Actions a version row can record. The set is closed so the history filter and
# the badge palette cannot drift apart; an unknown verb renders as itself.
ACT_CREATE = "create"
ACT_UPDATE = "update"
ACT_ROLLBACK = "rollback"
ACT_IMPORT = "import"
ACT_CLONE = "clone"
ACT_DELETE = "delete"
ACT_RESTORE = "restore"
ACTIONS = (ACT_CREATE, ACT_UPDATE, ACT_ROLLBACK, ACT_IMPORT,
           ACT_CLONE, ACT_DELETE, ACT_RESTORE)


def new_uid() -> str:
    """A stable identity string. uuid4 hex — 32 chars, fits VARCHAR(40)."""
    return uuid.uuid4().hex


#: Keys excluded from the content hash. ``updated_at`` moves on every save and
#: hashing it would mint a version for a save that changed nothing — the exact
#: failure ``sot_store.VOLATILE_KEYS`` exists to prevent, for the same reason.
VOLATILE_KEYS = ("updated_at", "created_at", "id")


def body_of(exc) -> dict[str, Any]:
    """The canonical, hashable body of a placement.

    Everything an operator could roll BACK to, and nothing else. The appliance
    is not in here: a version is the state of the carve-out, and moving one to
    another box is a placement change, not an edit of its content.
    """
    return {
        "exc_type": exc.exc_type or "",
        "category": exc.category or "",
        "wpp_mkey": exc.wpp_mkey or "",
        "name": exc.name or "",
        "reason": exc.reason or "",
        "enabled": bool(exc.enabled),
        "payload": exc.payload_dict,
        "policies": sorted(exc.policy_names or []),
    }


def sha_of(body: dict) -> str:
    """sha256 over the body serialised deterministically.

    ``sort_keys`` is not cosmetic: without it two identical bodies whose dicts
    were built in a different order hash differently, every save mints a
    version, and the "unchanged save costs nothing" property is gone.
    """
    clean = {k: v for k, v in (body or {}).items() if k not in VOLATILE_KEYS}
    raw = json.dumps(clean, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ExceptionLibraryItem(db.Model):
    """The fleet-level intent: one carve-out, authored once, placed N times.

    Deliberately holds NO appliance and NO Server Policy. Those belong to a
    placement — the library item is what two FortiWebs have in COMMON, and a
    device column here would make "the same exception" mean "the same exception
    on the same box", which is the thing that was already true and already
    useless.
    """

    __tablename__ = "exception_library"

    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(40), nullable=False, unique=True, index=True,
                    default=new_uid)
    name = db.Column(db.String(128), nullable=False, default="")
    exc_type = db.Column(db.String(64), nullable=False, default="", index=True)
    category = db.Column(db.String(16), nullable=False, default="", index=True)
    payload = db.Column(db.Text, nullable=False, default="{}")
    reason = db.Column(db.Text, nullable=True, default="")
    #: Free tags for the inventory filter. Comma-separated, never parsed for
    #: meaning — a taxonomy invented here would compete with exc_type.
    tags = db.Column(db.String(255), nullable=True, default="")
    author = db.Column(db.String(64), nullable=True, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    @property
    def payload_dict(self) -> dict[str, Any]:
        try:
            d = json.loads(self.payload or "{}")
            return d if isinstance(d, dict) else {}
        except (ValueError, TypeError):
            return {}

    def to_dict(self) -> dict:
        return {
            "id": self.id, "uid": self.uid, "name": self.name,
            "exc_type": self.exc_type, "category": self.category,
            "payload": self.payload_dict, "reason": self.reason or "",
            "tags": [t.strip() for t in (self.tags or "").split(",") if t.strip()],
            "author": self.author or "",
            "created_at": self.created_at.isoformat(timespec="seconds")
                          if self.created_at else "",
        }

    def __repr__(self) -> str:
        return f"<ExceptionLibraryItem {self.exc_type} {self.name!r}>"


class ExceptionVersion(db.Model):
    """One recorded state of one carve-out placement.

    Append-only. A rollback does not delete the versions in between — it
    appends the old body again under :data:`ACT_ROLLBACK`, so the record of
    what was tried and undone survives the undoing. History that can be edited
    is not history.
    """

    __tablename__ = "exception_version"
    __table_args__ = (
        db.Index("ix_exception_version_lineage_id", "lineage", "id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    #: Stable across delete/restore. NOT a foreign key — see module docstring.
    lineage = db.Column(db.String(40), nullable=False, index=True)
    #: The placement row this version described WHEN IT WAS WRITTEN. May now
    #: point at nothing (the placement was deleted); the lineage still resolves.
    exception_id = db.Column(db.Integer, nullable=True, index=True)
    appliance_id = db.Column(db.Integer, nullable=True, index=True)
    #: Human scope label frozen at write time. Resolving it live would make an
    #: old version claim a scope name the appliance only acquired later.
    scope = db.Column(db.String(160), nullable=False, default="")
    sha256 = db.Column(db.String(64), nullable=False, index=True)
    body = db.Column(db.Text, nullable=False, default="{}")
    action = db.Column(db.String(16), nullable=False, default=ACT_UPDATE)
    author = db.Column(db.String(64), nullable=True, default="")
    note = db.Column(db.Text, nullable=True, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           index=True)

    @property
    def body_dict(self) -> dict[str, Any]:
        try:
            d = json.loads(self.body or "{}")
            return d if isinstance(d, dict) else {}
        except (ValueError, TypeError):
            return {}

    def to_dict(self) -> dict:
        return {
            "id": self.id, "lineage": self.lineage,
            "exception_id": self.exception_id, "scope": self.scope,
            "sha256": self.sha256, "short": (self.sha256 or "")[:12],
            "action": self.action, "author": self.author or "",
            "note": self.note or "", "body": self.body_dict,
            "created_at": self.created_at.isoformat(timespec="seconds")
                          if self.created_at else "",
        }

    def __repr__(self) -> str:
        return f"<ExceptionVersion {self.lineage[:8]} {self.action} {self.sha256[:8]}>"
