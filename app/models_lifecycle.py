"""Object-lifecycle records — what the fleet has PROVEN about a disappearance.

The firmware comparison is DERIVED: it is rebuilt from evidence on every sweep
and it knows only the two scopes currently selected. That is the right shape
for a comparison and the wrong shape for a finding, because a finding needs to
outlive the page that produced it:

* *when* did we first prove this, and have we re-proved it since?
* *what* did each source say at the time?
* was a correction proposed, and did somebody accept or refuse it?

None of that survives in a derived file. So a corroborated absence gets a ROW,
and the row is the thing alerts fire from, the review queue reads, and any
later analysis joins against.

Kept out of ``models.py`` for the same reason as ``models_provision`` and
``models_lineprofile``: the feature commits without touching a file that four
other sessions are editing.

One row per ``(product, name, base_scope, target_scope)``. Re-proving the same
absence must not mint a second row — a table that grows one row per timer tick
turns "how long has this been true?" into a query nobody writes. ``seen_count``
and ``last_seen_at`` carry the repetition instead.

``previous_urn`` exists so an applied correction is REVERSIBLE from this table
alone. A correction that can only be undone by remembering what was there is
not a correction, it is a second incident.
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db

#: ``correction`` column values.
CORR_NONE = "none"          # nothing to propose (no alternative spelling)
CORR_PROPOSED = "proposed"  # a candidate exists and is waiting for a human
CORR_APPLIED = "applied"    # written to the endpoint catalog
CORR_DISMISSED = "dismissed"  # a human looked and said no
CORR_STATES = (CORR_NONE, CORR_PROPOSED, CORR_APPLIED, CORR_DISMISSED)


class ObjectAbsence(db.Model):
    """One name, proven absent on one scope relative to another."""

    __tablename__ = "object_absences"
    __table_args__ = (
        db.UniqueConstraint("product", "name", "base_scope", "target_scope",
                            name="uq_object_absence_key"),
    )

    id = db.Column(db.Integer, primary_key=True)

    product = db.Column(db.String(32), nullable=False, index=True)
    #: Catalog (friendly) name. The URN is recorded beside it rather than used
    #: as the key: the URN is the thing a correction CHANGES, so keying on it
    #: would make an applied correction look like a brand-new finding.
    name = db.Column(db.String(128), nullable=False, index=True)
    urn = db.Column(db.String(255), nullable=False, default="")

    #: The two firmware scopes compared, exactly as the comparison spelled
    #: them (a line like ``7.6`` or a build like ``8.0.5``). Stored verbatim so
    #: a row can never claim a build's authority for a line rollup.
    base_scope = db.Column(db.String(32), nullable=False)
    target_scope = db.Column(db.String(32), nullable=False)

    #: An ``absence_corroboration.STATE_*`` value.
    state = db.Column(db.String(24), nullable=False, index=True)

    #: What each source actually said, kept so a row explains itself without
    #: re-running the comparison against evidence that may since have changed.
    api_detail = db.Column(db.Text, nullable=False, default="")
    cli_base = db.Column(db.String(24), nullable=False, default="")
    cli_target = db.Column(db.String(24), nullable=False, default="")
    #: Which appliance produced the dump that answered, and when. A verdict
    #: whose evidence cannot be named is not reviewable.
    cli_device = db.Column(db.String(64), nullable=False, default="")
    cli_captured_at = db.Column(db.String(32), nullable=False, default="")

    #: The CLI spelling offered as an alternative, when one exists. A PATH, not
    #: a URN — see ``absence_corroboration.proposed_path``.
    proposed_path = db.Column(db.String(255), nullable=False, default="")
    correction = db.Column(db.String(16), nullable=False, default=CORR_NONE)
    correction_note = db.Column(db.Text, nullable=False, default="")
    previous_urn = db.Column(db.String(255), nullable=False, default="")
    reviewed_by = db.Column(db.String(64), nullable=False, default="")
    reviewed_at = db.Column(db.DateTime, nullable=True)

    first_seen_at = db.Column(db.DateTime, nullable=False,
                              default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, nullable=False,
                             default=datetime.utcnow)
    seen_count = db.Column(db.Integer, nullable=False, default=1)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (f"<ObjectAbsence {self.product}:{self.name} "
                f"{self.base_scope}->{self.target_scope} {self.state}>")
