"""Line profiles — the ONE authority on what a classification *line* gets.

**Why this table exists.** ``line`` is a free string on ``Appliance``, on
``Baseline`` and inside every network segment, and until now the answer to
"which networks does this line receive?" was derived by MATCHING THAT STRING
against ``segments[].line``. Nothing declared the relationship, so nothing
could be wrong about it — and nothing could be *right* about it either. A
segment whose ``line`` was typed differently simply stopped matching, and the
consumer saw a line with no networks, which is indistinguishable from a line
that legitimately has none.

That is survivable while the answer only colours a page. It stops being
survivable the moment the answer picks the network a **production server
policy** is built on: the policy is created perfectly, on the wrong segment,
and nothing raises. A guess that is right most of the time is worse than one
that is never made, because it passes in the laboratory and fails in the
field.

So the relationship becomes DECLARED:

* a profile names the segments a line receives, **by name**, and a named
  segment that no longer exists is a reported PROBLEM rather than a silent
  drop;
* it names the certificate class and the Web Protection Profile template a
  new policy on that line starts from;
* the string-match remains available as an explicitly labelled *inference*
  for lines nobody has declared yet — see ``services.line_profiles.line_plan``,
  which is the only place either answer is derived.

Kept out of ``models.py`` for the same reason as ``models_provision``: the
feature stays self-contained and commits without touching a file four other
sessions are editing.
"""
from __future__ import annotations

import json
from datetime import datetime

from .extensions import db


class LineProfile(db.Model):
    """What one classification line receives, declared rather than inferred."""

    __tablename__ = "line_profiles"
    __table_args__ = (
        # One profile per (product, line). Two profiles for one line would
        # reintroduce exactly the ambiguity this table removes.
        db.UniqueConstraint("product", "line", name="uq_lineprofile_product_line"),
    )

    id = db.Column(db.Integer, primary_key=True)
    #: Owning product/ADOM, mirroring ``Template.product``. A FortiADC session
    #: must not read a FortiWeb line's profile.
    product = db.Column(db.String(32), nullable=False, default="fortiweb",
                        index=True)
    #: The classification value this profile answers for. Moved by
    #: ``classification_ops`` when the catalog entry is renamed — a profile
    #: left behind on the old string is an orphan nothing would report.
    line = db.Column(db.String(128), nullable=False, index=True)

    #: JSON list of segment NAMES (``settings_store.segments()[].name``).
    #: Names, not indices: the segments list is a JSON blob that is rewritten
    #: whole on every edit, so an index means a different segment tomorrow.
    segment_names = db.Column(db.Text, nullable=False, default="[]")

    #: Certificate class a new policy on this line is issued under
    #: (``settings_store.CERT_CLASSES``). Empty = NOT DECLARED, which is
    #: deliberately distinct from any class: the wizard must ask rather than
    #: pick 'server' on the operator's behalf.
    cert_class = db.Column(db.String(32), nullable=False, default="")

    #: ``Template.id`` of a ``web-protection-profile`` template. NULL = not
    #: declared. Whether it is APPROVED is checked at plan time, not here —
    #: a template can be approved and un-approved after this row is written.
    wpp_template_id = db.Column(db.Integer, nullable=True)

    #: Pool to allocate management/VIP addresses from, when it is not simply
    #: the segment's own CIDR. Empty = use the segment.
    ipam_pool = db.Column(db.String(128), nullable=False, default="")

    note = db.Column(db.Text, nullable=False, default="")
    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    # -- segment names ---------------------------------------------------
    def segments(self) -> list[str]:
        """The declared segment names, order preserved, duplicates dropped."""
        try:
            rows = json.loads(self.segment_names or "[]")
        except (ValueError, TypeError):
            return []
        out: list[str] = []
        for row in rows if isinstance(rows, list) else []:
            name = str(row or "").strip()
            if name and name not in out:
                out.append(name)
        return out

    def set_segments(self, names) -> None:
        out: list[str] = []
        for row in names or []:
            name = str(row or "").strip()[:128]
            if name and name not in out:
                out.append(name)
        self.segment_names = json.dumps(out)

    def public(self) -> dict:
        return {
            "id": self.id, "product": self.product, "line": self.line,
            "segments": self.segments(), "cert_class": self.cert_class or "",
            "wpp_template_id": self.wpp_template_id,
            "ipam_pool": self.ipam_pool or "", "note": self.note or "",
            "created_by": self.created_by or "",
            "updated_at": (self.updated_at.isoformat()
                           if self.updated_at else ""),
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<LineProfile {self.product}/{self.line!r}>"
