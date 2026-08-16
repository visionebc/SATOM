"""Bookmarks — the right-hand panel's data model.

Three tables, and the split between them is the whole design.

**A bookmark never stores what the inventory already knows.** A
``kind='appliance'`` row holds ONLY ``appliance_id``; the name, product, zone,
line, department and tags are read live at render time. Copying the
classification into the bookmark would build a second inventory that goes stale
the moment somebody re-zones a device — and then the operator has two truths
and the sidebar shows the old one. The grouping the user sees ("by zone", "by
segment", …) is therefore DERIVED on every render, never persisted. See
:func:`app.services.bookmarks.group_key`.

**Placement is per-user, so it cannot live on the bookmark.** A shared bookmark
is ONE row that everybody sees; where each person files it is theirs alone
(:class:`BookmarkPlacement`). This is also why a bookmark carries no
``parent_id``/``position`` of its own: one placement mechanism, not two. A
personal bookmark simply has exactly one placement row — its owner's.

**No placement row is a meaningful state, not a missing one.** A team bookmark
nobody has filed yet renders in the "Shared" tray; a personal one renders at
the root. Filing something at the root is a real act that writes a row with
``parent_id = NULL`` — which is how "I deliberately keep it at the top" stays
distinguishable from "this arrived and I have not looked at it yet". Deleting
one's own folder therefore removes placements, never the shared bookmark: the
team's rows fall back to the tray instead of being destroyed by one member's
cleanup.

**Favourites and hiding are per-user for the same reason** — a column on a
shared row would be everybody's favourite and everybody's blind spot.
"""
from __future__ import annotations

import json
from datetime import datetime

from .models import db

#: A bookmark is either the author's alone or the whole team's. There is no
#: middle scope: the user defined "team" as everyone who operates this SATOM,
#: so membership is not modelled (no Team entity, no join table).
SCOPE_PERSONAL = "personal"
SCOPE_TEAM = "team"
SCOPES = (SCOPE_PERSONAL, SCOPE_TEAM)

#: ``appliance`` points at the inventory; ``link`` is any URL; ``view`` stores a
#: FILTER (not the rows it currently matches — that is the same staleness trap
#: as copying the classification); ``folder`` is the only manual grouping.
KIND_APPLIANCE = "appliance"
KIND_LINK = "link"
KIND_VIEW = "view"
KIND_FOLDER = "folder"
KINDS = (KIND_APPLIANCE, KIND_LINK, KIND_VIEW, KIND_FOLDER)


class Bookmark(db.Model):
    """One bookmark: a device, a link, a saved filter, or a folder."""

    __tablename__ = "bookmarks"

    id = db.Column(db.Integer, primary_key=True)
    scope = db.Column(db.String(16), nullable=False, default=SCOPE_PERSONAL,
                      index=True)
    # The author. Kept on team rows too: a shared bookmark with no traceable
    # origin is an unattributable change to what every operator sees.
    owner_user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    kind = db.Column(db.String(16), nullable=False, default=KIND_APPLIANCE)
    # Only for kind='appliance'. CASCADE: a retired device must not leave a
    # bookmark that resolves to nothing on every operator's panel.
    appliance_id = db.Column(
        db.Integer, db.ForeignKey("appliances.id", ondelete="CASCADE"),
        nullable=True, index=True,
    )
    url = db.Column(db.Text, nullable=True)          # kind='link'
    view_query = db.Column(db.Text, nullable=True)   # kind='view', JSON filter
    # NULL on an appliance bookmark means "use the device's live name", so a
    # rename in the inventory reaches the panel. A label is an override.
    label = db.Column(db.String(160), nullable=True)
    # ADOM stamp, same rule as every other scoped record: a link created in the
    # FortiADC console does not belong in the FortiWeb one. Appliance bookmarks
    # are scoped a SECOND time, by the device itself (see services.bookmarks).
    product = db.Column(db.String(32), nullable=False, default="", index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    appliance = db.relationship("Appliance", lazy="joined")
    owner = db.relationship("User", lazy="joined")

    def filters(self) -> dict:
        """The saved filter of a ``view`` bookmark, or ``{}``."""
        if not self.view_query:
            return {}
        try:
            data = json.loads(self.view_query)
        except (TypeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def display_label(self) -> str:
        """What the panel prints. An appliance without an explicit label
        follows the device's live name — that is the point of storing only the
        id."""
        if self.label:
            return self.label
        if self.kind == KIND_APPLIANCE and self.appliance is not None:
            return self.appliance.name
        return self.url or "(unnamed)"


class BookmarkPlacement(db.Model):
    """Where ONE user files ONE bookmark, and whether they hide it.

    Absent row = not filed: a team bookmark shows in the "Shared" tray, a
    personal one at the root. ``parent_id`` points at a folder bookmark owned
    by the same user.
    """

    __tablename__ = "bookmark_placements"

    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    bookmark_id = db.Column(
        db.Integer, db.ForeignKey("bookmarks.id", ondelete="CASCADE"),
        primary_key=True,
    )
    # NULL = filed at the root, deliberately. NOT the same as no row at all.
    parent_id = db.Column(
        db.Integer, db.ForeignKey("bookmarks.id", ondelete="CASCADE"),
        nullable=True, index=True,
    )
    position = db.Column(db.Integer, nullable=False, default=0)
    # Hiding is per-user and never silent: the tray header carries the count,
    # so "it never reached me" and "I hid it" stay distinguishable.
    hidden = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)


class BookmarkFavorite(db.Model):
    """A star. Always personal, including on a team bookmark — which is why it
    is a row and not a column on :class:`Bookmark`."""

    __tablename__ = "bookmark_favorites"

    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    bookmark_id = db.Column(
        db.Integer, db.ForeignKey("bookmarks.id", ondelete="CASCADE"),
        primary_key=True,
    )
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
