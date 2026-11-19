"""Which SERVER POLICY needs which file-backed artifact — derived, never typed.

:mod:`models_artifacts` answers *"what bytes does SATOM hold?"*. It cannot
answer the question a migration actually asks, which is the inverse: *"if I
move this policy to another box, which of the seven content-less object types
travels with it, and does SATOM hold a copy of each?"*

That link already existed in the product, but only for the duration of one
clone run: :func:`services.waf_artifacts.plan_artifacts` derives it from the
dependency walk and throws it away. Persisting it is what turns a pre-flight
into a *planning* answer — one you can read BEFORE deciding to migrate, on a
box you have not chosen a destination for yet.

**It is derived, and that is the whole design.** A hand-typed "this artifact
belongs to these policies" field is a claim nothing falsifies: the day a rule
stops naming a schema, the label keeps saying it does, and nothing fails —
the sentence just quietly becomes false. This product has already been bitten
by exactly that class of rot (a published page claimed "667 guards" for four
releases). So every row here is an OBSERVATION with a timestamp and an origin,
and a row nobody re-observed is shown as *stale*, never as truth.

Two tables, and the second one is not redundant:

``waf_artifact_ref``   one (appliance, policy) → (kind, name) edge.
``waf_artifact_scan``  the walk itself: when it ran, whether it SUCCEEDED, and
                       what it cost. Without it, "this policy needs no
                       artifacts" and "we never walked this policy" are the
                       same empty result — and they are opposite answers. The
                       first clears a migration; the second means nobody looked.
"""
from __future__ import annotations

from datetime import datetime

from .models import db


def _wpp_text(wpp) -> str:
    """Operator-facing rendering of the three ``wpp_mkey`` states."""
    if wpp is None:
        return "not attributed"
    if wpp == "":
        return "on the policy itself"
    return wpp


class WafArtifactRef(db.Model):
    """One observed edge: *policy P on appliance A names artifact (kind, name)*.

    Scoped BY APPLIANCE on purpose. ``fortiweb12/pol-x`` and ``fortiweb13/pol-x``
    are different observations even when the names match, because two boxes can
    hold different content under one artifact name — that drift is precisely
    what a clone is supposed to carry, and collapsing the two would fabricate
    the all-clear this table exists to withhold.
    """

    __tablename__ = "waf_artifact_ref"
    __table_args__ = (
        db.UniqueConstraint("appliance_id", "policy_mkey", "kind", "name",
                            "wpp_mkey", name="uq_waf_artifact_ref_edge"),
    )

    id = db.Column(db.Integer, primary_key=True)
    #: The appliance the walk ran against. NOT nullable: an edge with no device
    #: is the collapsed form this table refuses.
    appliance_id = db.Column(db.Integer, nullable=False, index=True)
    #: mkey of the server policy that (transitively) names the artifact.
    policy_mkey = db.Column(db.String(255), nullable=False, index=True)
    kind = db.Column(db.String(32), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    #: The Web Protection Profile the artifact travels through, and the reason
    #: this column is NULLABLE with no default. THREE states, all distinct:
    #:   ``"wpp-a"``  reached through that profile;
    #:   ``""``       walked, and it hangs off the SERVER POLICY itself (Lua
    #:                scripting does exactly this — it never passes a profile);
    #:   ``NULL``     NOT ATTRIBUTED — the edge predates this column or was
    #:                donated without a referrer graph.
    #: A ``DEFAULT ''`` would have back-filled every historical row with case 2,
    #: printing "bound directly on the policy" for 432 edges nobody attributed.
    #: That is the same fabricated-certainty failure ``ok=False`` scans exist to
    #: prevent, one table over.
    wpp_mkey = db.Column(db.String(255), nullable=True, index=True)
    #: The dependency-map urn the walk classified the object under — kept so a
    #: row stays readable after ``KINDS`` is extended or re-keyed.
    urn = db.Column(db.String(128), nullable=False, default="")
    #: How this edge was produced, e.g. ``walk:server-policy`` or
    #: ``preflight:clone``. An edge whose origin is unknown is an edge nobody
    #: can re-derive, which is the same as an edge nobody can trust.
    derived_from = db.Column(db.String(64), nullable=False, default="")
    first_seen_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    #: Advanced by every re-derivation. Staleness is measured from HERE, not
    #: from ``first_seen_at``: an edge re-observed this morning is current no
    #: matter when it was first recorded.
    seen_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                        index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "appliance_id": self.appliance_id,
            "policy_mkey": self.policy_mkey, "kind": self.kind,
            "name": self.name, "urn": self.urn,
            "wpp": self.wpp_mkey,
            "wpp_text": _wpp_text(self.wpp_mkey),
            "derived_from": self.derived_from,
            "seen_at": self.seen_at.isoformat(timespec="seconds")
                       if self.seen_at else "",
        }


class WafArtifactScan(db.Model):
    """One dependency walk of one policy: when, whether it worked, what it found.

    ``ok=False`` is the load-bearing state. A walk that failed (device down,
    credentials rejected, ADOM wrong) must NEVER be allowed to delete the edges
    a previous successful walk recorded — an unreachable appliance would
    otherwise "prove" that none of its policies need any artifact, which is the
    exact false all-clear that would send someone into a migration unprepared.
    """

    __tablename__ = "waf_artifact_scan"
    __table_args__ = (
        db.UniqueConstraint("appliance_id", "policy_mkey",
                            name="uq_waf_artifact_scan_policy"),
    )

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(db.Integer, nullable=False, index=True)
    policy_mkey = db.Column(db.String(255), nullable=False, index=True)
    ok = db.Column(db.Boolean, nullable=False, default=False)
    #: Prose, not a code: "the box refused the read" and "the walk crashed" send
    #: an operator to different places.
    error = db.Column(db.String(500), nullable=False, default="")
    #: How many artifact edges the walk produced (0 is a real, useful answer —
    #: it means this policy carries no file-backed object).
    refs = db.Column(db.Integer, nullable=False, default=0)
    #: Objects visited by the walk, so a suspiciously cheap scan is visible.
    items = db.Column(db.Integer, nullable=False, default=0)
    ms = db.Column(db.Integer, nullable=False, default=0)
    scanned_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "appliance_id": self.appliance_id,
            "policy_mkey": self.policy_mkey, "ok": bool(self.ok),
            "error": self.error, "refs": self.refs, "items": self.items,
            "ms": self.ms,
            "scanned_at": self.scanned_at.isoformat(timespec="seconds")
                          if self.scanned_at else "",
        }
