"""Durable record of what a policy action COPIED or MOVED, and where.

Before this table the destination of a clone was **not recoverable**:

* the job file under ``data/jobs/<id>.json`` carries it, but ``jobs.prune()``
  deletes it after 7 days;
* the per-policy audit line (``policy_ops`` worker) writes the source policy and
  the destination *appliance*, but **never the name the copy landed under** —
  which for a same-box clone is the entire point, since source and destination
  appliance are the same box.

So a ``clone_here`` older than a week left nothing at all. This table is the
one place that answers "where did this go, when, and who did it".
"""
from __future__ import annotations

from datetime import datetime, timezone

from .extensions import db

# Verbs recorded here. ``migrate_to`` is deliberately NOT collapsed into
# "clone": a migrate DISABLES the source, so a row that reads "copied to X" over
# a policy that was actually MOVED would tell the operator he still has a live
# original. The verb is stored, and the UI reads it.
ACTIONS = ("clone_here", "clone_to", "migrate_to")


def utcnow() -> datetime:
    """Naive UTC — matches the rest of the schema (``models_cache``, bookmarks)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class PolicyCloneEvent(db.Model):
    """One EXECUTED clone/migrate of ONE server policy.

    Keyed to the source by ``(src_appliance_id, src_policy)`` as plain columns —
    never by a foreign key into ``device_server_policies``. That table is a
    denormalised projection **rebuilt from scratch on every ingest**
    (``models_cache``), so a row hanging off it would be destroyed by the next
    harvest, which is exactly the silence this table exists to end.

    ``dst_appliance`` stores the destination's name **as it was at the time**
    next to the live id. Retiring the destination nulls the id (``SET NULL``)
    but must not rewrite history: "cloned to fortiweb15" stays true after
    fortiweb15 is gone. Losing the source device, by contrast, makes every row
    unreachable by construction, so that side cascades.
    """

    __tablename__ = "policy_clone_events"

    id = db.Column(db.Integer, primary_key=True)

    # --- the source: what the operator is looking at in the row ---
    src_appliance_id = db.Column(
        db.Integer,
        db.ForeignKey("appliances.id", ondelete="CASCADE"),
        index=True, nullable=False)
    src_policy = db.Column(db.String(256), index=True, nullable=False)

    # --- what happened ---
    action = db.Column(db.String(32), nullable=False)
    dst_appliance_id = db.Column(
        db.Integer,
        db.ForeignKey("appliances.id", ondelete="SET NULL"),
        nullable=True)
    dst_appliance = db.Column(db.String(256), nullable=False, default="")
    dst_policy = db.Column(db.String(256), nullable=False, default="")

    # A FAILED attempt is recorded too. Finding half a copy on the destination
    # and having nothing that says anyone ever tried is the worse outcome; the
    # badge counts only successes, so a failure informs without inflating.
    ok = db.Column(db.Boolean, nullable=False, default=False)
    error = db.Column(db.String(512), nullable=False, default="")

    # --- when / who ---
    at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    by = db.Column(db.String(128), nullable=False, default="")
    job_id = db.Column(db.String(64), nullable=False, default="")

    __table_args__ = (
        db.Index("ix_policy_clone_src", "src_appliance_id", "src_policy"),
    )

    def __repr__(self) -> str:  # pragma: no cover — debug aid
        return "<PolicyCloneEvent %s %s -> %s/%s ok=%s>" % (
            self.action, self.src_policy, self.dst_appliance or "-",
            self.dst_policy, self.ok)
