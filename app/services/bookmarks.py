"""Bookmarks service — visibility, authorship and the DERIVED grouping.

Three rules carry this module; everything else is plumbing.

1. **The reader's permissions decide the list, never the sharer's.** Every
   bookmark leaving :func:`visible_bookmarks` has passed the ADOM stamp filter
   AND — for device bookmarks — ``models.visible_appliances`` for the person
   looking. A shared bookmark is therefore not a way to hand somebody a device
   in maintenance, or one from another product. This product already learned
   that lesson the expensive way: until 2026-08-06 every by-id appliance route
   served another ADOM's device to anyone who knew the id.

2. **Filtering a bookmark out never destroys placement.** A device that enters
   maintenance disappears from the panel and comes back where its owner filed
   it. Deleting placements on an invisible row would wipe the whole team's
   filing the day one operator flips a maintenance switch.

3. **Grouping is computed, not stored.** :func:`group_key` reads the live
   appliance on every call, so re-zoning a device re-files its bookmark with no
   write. The only persisted grouping is the manual folder — the one thing that
   cannot be derived.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from urllib.parse import urlsplit

from ..extensions import db
from ..models import (
    Appliance, Permission, User, UserSetting, visible_appliances,
)
from ..models_bookmarks import (
    Bookmark, BookmarkFavorite, BookmarkPlacement,
    KIND_APPLIANCE, KIND_FOLDER, KIND_LINK, KIND_VIEW, KINDS,
    SCOPE_PERSONAL, SCOPE_TEAM,
)
from . import product_scope

#: Every way the panel can group. ``folder`` is the only one backed by stored
#: rows; the other seven are recomputed from the live inventory on each render,
#: which is why re-classifying a device needs no bookmark migration.
GROUP_FOLDER = "folder"
GROUP_MODES = (
    GROUP_FOLDER, "zone", "line", "department", "segment", "kind", "tag",
)


#: Every dimension the inventory lens can nest by: ``(key, label, icon)``.
#: The order here is only the order the profile page OFFERS them; the order
#: they NEST in is per-user and lives in :data:`LENS_SETTING_KEY`.
DIMENSIONS = (
    ("line", "Line", "bi-diagram-2"),
    ("zone", "Zone", "bi-diagram-3"),
    ("department", "Department", "bi-building"),
    ("kind", "Product", "bi-box-seam"),
    ("segment", "Network segment", "bi-hdd-rack"),
    ("tag", "Tag", "bi-tags"),
)
DIMENSION_KEYS = tuple(k for k, _lbl, _ico in DIMENSIONS)
DIMENSION_LABELS = {k: lbl for k, lbl, _ico in DIMENSIONS}

#: What somebody who has never opened the profile page sees. It reproduces the
#: previously hard-coded classification root EXACTLY. An upgrade that re-shaped
#: everybody's tree would be indistinguishable, from the operator's chair, from
#: somebody having re-classified the fleet overnight.
DEFAULT_LENS = ("line", "zone", "department")

#: One user setting, a comma-separated stack. Stored as text rather than JSON
#: because it is also what the profile form round-trips, and two encodings of
#: the same preference is how the two ends drift.
LENS_SETTING_KEY = "bookmarks.lens"

#: Devices whose classification field is empty. Shown, never hidden: half of a
#: real fleet is unclassified, and a panel that silently drops those rows is
#: worse than one that looks untidy — the untidy bucket is what gets them
#: classified.

# ---------------------------------------------------------------------------
# The link that leaves this console
# ---------------------------------------------------------------------------
#: RFC 6761 guarantees names under ``.invalid`` never resolve. The retired
#: appliances in this fleet are parked on exactly that TLD, so a link built
#: from their host would be a dead link that LOOKS live -- which is worse than
#: no link, because the operator blames the device instead of the record.
RESERVED_TLDS = frozenset({"invalid"})

#: One DNS label. Anchored, because the whole point is to reject a `host`
#: field that is not a host at all.
_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

#: The only schemes a saved link may carry. Everything else -- and there is
#: no useful "everything else" here -- is refused by name.
LINK_SCHEMES = frozenset({"http", "https"})


def safe_link_url(raw) -> tuple[str | None, str]:
    """``(url, reason)`` for a ``link`` bookmark's destination.

    Same contract as :func:`device_link`: a URL and an empty reason, or
    ``None`` and a reason a human can act on. Never both, never neither.

    A saved link is free text one person types and everybody renders. Share
    it with the team and it becomes an ``href`` in every colleague's
    sidebar, on every page of the console, for as long as it exists --
    including for the read-only users who cannot delete it. So:

    *   **``javascript:`` and ``data:`` are the whole reason this function
        exists.** ``javascript:`` in an ``href`` runs in this origin on one
        click, with the session cookie: it is stored XSS whose only entry
        requirement is the permission to save a bookmark. ``data:`` is the
        same attack wearing a document.

    *   **Control characters are stripped-and-rejected, not stripped.**
        Browsers delete NUL, TAB, CR and LF from a URL *before* reading the
        scheme, so ``java\\tscript:alert(1)`` navigates as ``javascript:``
        while a scheme check on the raw string sees ``java\\tscript``. The
        check has to be made on the same string the browser will read.

    *   **A protocol-relative ``//host`` is refused even though it starts
        with a slash.** It looks internal and resolves to somebody else's
        server; the operator asked for an internal path and got an external
        one. A scheme-less relative URL (``docs/x``) is refused for a duller
        reason: it resolves against whatever page the panel is drawn on, and
        the panel is drawn on every page.
    """
    url = (raw or "").strip()
    if not url:
        return None, "a link bookmark needs a URL"
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in url):
        return None, "the URL contains control characters"
    if url.startswith("//"):
        return None, ("a // URL points at another server, not at this "
                      "console \u2014 write it out with https://")
    if url.startswith("/"):
        return url, ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None, "the URL cannot be parsed"
    scheme = (parts.scheme or "").lower()
    if not scheme:
        return None, ("the URL needs a scheme \u2014 write it out with "
                      "https:// or start it with / for a page of this console")
    if scheme not in LINK_SCHEMES:
        return None, ("only http and https links can be saved, and this one "
                      "is %s:" % scheme)
    if not parts.netloc:
        return None, "the URL has no host"
    return url, ""


def device_link(appl) -> tuple[str | None, str]:
    """``(url, reason)`` for the device's OWN management UI.

    Returns the URL and an empty reason, or ``None`` and a reason a human can
    act on. Never both, never neither.

    Three decisions, each of which had an easier wrong answer:

    *   **Derived from ``host``/``port``, never stored.** A ``mgmt_url``
        column would be a second copy of the management address, and the copy
        is the one that survives a re-IP. Re-address the device in the
        inventory and every link in the console follows in the same write.

    *   **The host is VALIDATED, not merely interpolated.** ``host`` is free
        text typed by an administrator, and the link is rendered for everyone
        -- read-only users included. ``https://`` + ``fw1@evil.example``
        renders as a link to the device and navigates to somebody else's
        server, because everything before the ``@`` is userinfo. So the field
        must parse as an IP literal or a hostname before it is allowed to
        become an authority. An IPv6 literal is bracketed; unbracketed, the
        colons of the address are read as the port separator.

    *   **Scheme is always ``https``, and it is NOT read from
        ``verify_ssl``.** That flag records whether *our* client trusts the
        device's certificate -- a self-signed appliance is still an HTTPS
        appliance. Deriving the scheme from it would send an operator to
        ``http://`` on a box that only speaks TLS, and would put the phrase
        "we don't verify this cert" in charge of what the browser does.
    """
    if appl is None:
        return None, "no device on this bookmark"
    host = (getattr(appl, "host", "") or "").strip()
    if not host:
        return None, "no management address on record"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        authority = "[%s]" % host if ip.version == 6 else host
    else:
        name = host[:-1] if host.endswith(".") else host
        labels = name.split(".")
        if len(name) > 253 or not all(_LABEL_RE.match(x) for x in labels):
            return None, "the host on record is not a hostname or an IP address"
        if labels[-1].lower() in RESERVED_TLDS:
            return None, "reserved .invalid host \u2014 this device has no reachable address"
        authority = name
    port = getattr(appl, "port", None) or 443
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return None, "the management port on record is out of range"
    if port == 443:
        return "https://%s" % authority, ""
    return "https://%s:%d" % (authority, port), ""

UNCLASSIFIED = "(unclassified)"
#: Links, saved views and folders have no zone or segment. They get their own
#: bucket rather than being filed as "unclassified devices", which they are not.
NON_DEVICE = "(links and views)"
NO_SEGMENT = "(no segment)"

#: Sharing changes what EVERY operator sees, so it is an operator-grade act.
#: A read-only account can still keep personal bookmarks and star team ones.
SHARE_PERMISSION = Permission.CONFIG_WRITE


class BookmarkDenied(Exception):
    """Refusal with a machine-readable reason.

    The reason is never collapsed into a bare "not allowed": an operator who
    cannot tell *which* rule stopped them routes around the rule instead of
    satisfying it.
    """

    def __init__(self, reason: str, message: str = ""):
        self.reason = reason
        super().__init__(message or reason)


# ---------------------------------------------------------------------------
# Visibility
# ---------------------------------------------------------------------------

def _visible_appliance_ids(user) -> set[int]:
    return {
        row[0] for row in
        visible_appliances(db.session.query(Appliance.id), user=user).all()
    }


def visible_bookmarks(user) -> list[Bookmark]:
    """Every bookmark *user* may see: their own personal rows plus the team's,
    scoped by ADOM, with device bookmarks filtered through the appliance
    visibility gate of THIS user."""
    if user is None or not getattr(user, "is_authenticated", False):
        return []
    q = Bookmark.query.filter(
        db.or_(
            Bookmark.scope == SCOPE_TEAM,
            db.and_(Bookmark.scope == SCOPE_PERSONAL,
                    Bookmark.owner_user_id == user.id),
        )
    )
    q = product_scope.scope_query(q, Bookmark.product)
    rows = q.order_by(Bookmark.id).all()
    allowed = _visible_appliance_ids(user)
    return [
        b for b in rows
        if b.kind != KIND_APPLIANCE or b.appliance_id in allowed
    ]


def may_edit(bm: Bookmark, user) -> bool:
    """Who may change a bookmark's label, target or existence — the author, or
    an admin. Filing it, starring it and hiding it are NOT edits: those touch
    only the acting user's own rows."""
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if bm.owner_user_id == user.id:
        return True
    return bool(user.can(Permission.USER_MANAGE))


# ---------------------------------------------------------------------------
# Derived grouping
# ---------------------------------------------------------------------------

def segment_of(host: str, segments: Iterable[dict]) -> str:
    """The declared network segment containing *host*, or :data:`NO_SEGMENT`.

    Derived from the appliance's management address against the segments
    already declared in Settings — NOT a new ``network`` column. ``host`` is a
    string that may legitimately not be an IP at all (a FQDN, or the
    ``*.invalid`` placeholder a retired device carries); that is not an error,
    it simply has no segment.
    """
    try:
        addr = ipaddress.ip_address((host or "").strip())
    except ValueError:
        return NO_SEGMENT
    for seg in segments or []:
        cidr = (seg.get("cidr") or "").strip()
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if addr in net:
            return (seg.get("name") or "").strip() or cidr
    return NO_SEGMENT


def dimension_value(appl: Appliance, dim: str,
                    segments: Iterable[dict] = ()) -> str:
    """The bucket *appl* falls in for ONE classification dimension.

    Separate from :func:`group_key` because the tree nests several dimensions
    for the same device, and a function that took a bookmark could not answer
    for an appliance nobody has bookmarked yet — which is most of them on the
    first render.

    An empty field yields :data:`UNCLASSIFIED` rather than ``""``: half of a
    real fleet is unclassified, and the visible bucket is what gets it fixed.
    """
    if dim == "segment":
        return segment_of(appl.host, segments)
    if dim == "kind":
        return (appl.kind or "").strip() or UNCLASSIFIED
    if dim == "tag":
        tags = _tags(appl)
        return tags[0] if tags else UNCLASSIFIED
    if dim in ("zone", "line", "department"):
        return (getattr(appl, dim, None) or "").strip() or UNCLASSIFIED
    raise ValueError(f"unknown dimension: {dim}")


def dimension_label(dim: str, value: str) -> str:
    """How a lens bucket is WRITTEN. The node key keeps the raw value.

    Split from :func:`dimension_value` deliberately. The tree's open/closed set
    is indexed by node key and the key is built from the bucket value, so if
    the displayed name were also the key, renaming ``fortiweb`` to ``FortiWeb``
    would collapse every product branch every reader had left open -- punishing
    them for a cosmetic change they never made.

    For ``kind`` the name comes from the ADOM registry, which is where the
    operator already spells these products. ``fortiweb`` is stored lowercase
    and the product is called FortiWeb; capitalising the first letter would
    give "Fortiweb", which is not the name of anything. A kind with no
    registry row still gets its first letter raised -- and only the first,
    because ``str.capitalize`` would lower-case the rest and turn a correctly
    spelled custom kind into mush.

    The synthetic buckets are returned untouched: ``(unclassified)`` is a
    sentence about the record, not a product. That check is redundant while
    they are all spelled with a leading ``(`` -- a bracket has no upper case,
    so the fallback below would return them unchanged anyway. It is kept, and
    pinned by a test, because the redundancy is a property of today's spelling
    and not of this function.
    """
    value = value or ""
    if value in (UNCLASSIFIED, NO_SEGMENT, NON_DEVICE) or dim != "kind":
        return value
    try:
        from ..branding import get_product, is_valid
        # is_valid FIRST: get_product falls back to FortiWeb for an unknown
        # key, so calling it blind would label every unregistered kind
        # "FortiWeb" -- a wrong answer that looks like a right one.
        if is_valid(value):
            name = (get_product(value) or {}).get("name") or ""
            if name:
                return name
    except Exception:
        pass
    return value[:1].upper() + value[1:]


#: Every banner template resolves to ONE identifying colour for tinting.
#: Solid templates have a single stop; the gradients all ramp from a near-black
#: anchor to the colour the template is actually named after, so the LAST stop
#: is the one that tells Ocean from Ember. Tinting from the first stop would
#: render all fourteen gradients as the same grey wash.
_HEX_RE = re.compile(r"#(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b")

#: What a reader with no banner at all is tinted with (the "slate" solid).
BANNER_FALLBACK = "#162940"


def banner_accent(bg: str) -> str:
    """The identifying hex of a banner template's ``bg`` (solid or gradient)."""
    stops = _HEX_RE.findall(bg or "")
    if not stops:
        return BANNER_FALLBACK
    h = stops[-1].lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return "#" + h.lower()


def tint(hex_color: str, alpha: float) -> str:
    """``rgba()`` of *hex_color* at *alpha*, for washing a light surface.

    Returned as a colour to lay UNDER text, never as the text colour. A pill
    whose label is painted in a 10%-alpha brand colour reads at about 1.4:1 on
    white -- it would say ``FortiWeb`` and be unreadable, which is the exact
    defect this console already shipped once in its status pills.
    """
    h = banner_accent(hex_color).lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r}, {g}, {b}, {alpha:g})"


#: Alpha of the row hover wash. Deliberately BELOW the chip's 0.08 and not
#: shared with it: the type chip paints its own rgba OVER the row, so a hover
#: at the chip's alpha would leave the two at the same weight and the chip you
#: are pointing at would flatten into its own row. Kept as a named constant so
#: a future change to the chip cannot drag the row along by accident.
ROW_HOVER_ALPHA = 0.05


def reader_tint(user_id: int, product_key: str) -> dict[str, str]:
    """The fill/outline the *reader's own* banner choice washes a chip with.

    Per USER, not per install: the banner is a personal setting, so two people
    looking at the same fleet see their own colour. Resolution is delegated to
    ``user_settings_store.banner_bg`` -- the same function the top bar itself
    is painted from -- so the chip cannot drift from the banner it echoes.
    """
    try:
        from . import user_settings_store as _us
        raw = _us.banner_bg(user_id, product_key)
    except Exception:
        raw = BANNER_FALLBACK
    return {"fill": tint(raw, 0.08), "line": tint(raw, 0.20),
            "hover": tint(raw, ROW_HOVER_ALPHA),
            "accent": banner_accent(raw)}


def parse_lens(values: Iterable[str]) -> list[str]:
    """Validate a submitted dimension order, or refuse it by name.

    Blank slots are SKIPPED rather than rejected: the profile form is a fixed
    row of selects and leaving the tail empty is how you ask for a shallow
    tree, not a mistake.

    A repeated dimension is REFUSED, not silently de-duplicated. At its second
    occurrence every node in that branch already shares one value, so it can
    only produce a chain of single-child folders — and a form that saves
    something other than what was submitted leaves the operator reading a page
    that disagrees with their own tree.

    An empty stack is refused for the same reason: the inventory root would
    have nothing to nest by, and dropping the root would take every device off
    the panel to honour a preference nobody could see they had set.
    """
    stack = [str(v).strip() for v in values]
    stack = [v for v in stack if v]
    if not stack:
        raise BookmarkDenied(
            "empty_lens",
            "Pick at least one dimension — with none, the panel has no way "
            "to group the fleet.")
    unknown = [v for v in stack if v not in DIMENSION_KEYS]
    if unknown:
        raise BookmarkDenied(
            "unknown_dimension",
            "Not a grouping dimension: %s" % ", ".join(sorted(set(unknown))))
    dupes = sorted({v for v in stack if stack.count(v) > 1})
    if dupes:
        raise BookmarkDenied(
            "duplicate_dimension",
            "%s appears twice. A dimension can only split the fleet once; "
            "below its first level every device already shares one value, so "
            "the second would add depth and no information."
            % ", ".join(DIMENSION_LABELS[d] for d in dupes))
    return stack


def lens_for(user) -> list[str]:
    """The dimension order *user* sees. **Never raises.**

    The panel renders on EVERY page of this console, so a stored value a later
    release stops recognising must degrade to the default rather than take the
    whole product down. Reading is therefore forgiving where
    :func:`parse_lens` is strict: unknown and repeated entries are dropped on
    read and refused on write.
    """
    raw = UserSetting.get(user.id, LENS_SETTING_KEY, "") or ""
    out: list[str] = []
    for part in str(raw).split(","):
        part = part.strip()
        if part in DIMENSION_KEYS and part not in out:
            out.append(part)
    return out or list(DEFAULT_LENS)


def save_lens(user, stack: Iterable[str]) -> list[str]:
    """Persist a validated stack. Validation is NOT optional here — storing an
    unchecked value would make :func:`lens_for` the only thing standing between
    a typo and a tree nobody can explain."""
    clean = parse_lens(stack)
    UserSetting.set(user.id, LENS_SETTING_KEY, ",".join(clean))
    db.session.commit()
    return clean


def lens_title(stack: Iterable[str]) -> str:
    """The lens root's NAME is its order.

    This is the whole reason the dropdown went: a control can only tell you how
    the tree is grouped once you open it, whereas the heading says it while you
    are reading the tree it produced.
    """
    return " › ".join(DIMENSION_LABELS[d] for d in stack)


def group_key(bm: Bookmark, mode: str, segments: Iterable[dict] = ()) -> str:
    """The bucket *bm* falls in under *mode*, computed from the LIVE appliance.

    A bookmark that is not a device has no classification of its own and lands
    in :data:`NON_DEVICE`; a device with the field empty lands in
    :data:`UNCLASSIFIED`. Returning "" for both would merge two different facts
    ("this is a link" and "nobody has classified this device") into one bucket.
    """
    if mode == GROUP_FOLDER:
        raise ValueError("folder grouping is stored, not derived")
    if bm.kind != KIND_APPLIANCE or bm.appliance is None:
        return NON_DEVICE
    return dimension_value(bm.appliance, mode, segments)


def _tags(appl: Appliance) -> list[str]:
    import json
    try:
        data = json.loads(appl.tags or "[]")
    except (TypeError, ValueError):
        return []
    return [str(t) for t in data] if isinstance(data, list) else []


# ---------------------------------------------------------------------------
# Per-user state
# ---------------------------------------------------------------------------

def placements(user) -> dict[int, BookmarkPlacement]:
    rows = BookmarkPlacement.query.filter_by(user_id=user.id).all()
    return {r.bookmark_id: r for r in rows}


def favorites(user) -> set[int]:
    return {
        r.bookmark_id for r in
        BookmarkFavorite.query.filter_by(user_id=user.id).all()
    }


def tray_counts(user) -> dict[str, int]:
    """What the "Shared" header must always show: how many team bookmarks are
    waiting to be filed, and how many this user has hidden.

    Both numbers exist because the panel defaults to collapsed. A bookmark
    shared into a collapsed tray that nothing counts is a bookmark nobody ever
    sees, and a hidden one that nothing counts is how "it never reached me"
    becomes unfalsifiable.
    """
    placed = placements(user)
    unplaced = hidden = 0
    for bm in visible_bookmarks(user):
        if bm.scope != SCOPE_TEAM:
            continue
        row = placed.get(bm.id)
        if row is None:
            unplaced += 1
        elif row.hidden:
            hidden += 1
    return {"unplaced": unplaced, "hidden": hidden}


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------

def create(user, kind: str, *, appliance_id: int | None = None,
           url: str = "", view_query: str = "", label: str = "",
           parent_id: int | None = None) -> Bookmark:
    """Create a PERSONAL bookmark. Nothing is created straight into the team
    scope: sharing is a separate, audited act (:func:`share`), so every shared
    row has a moment somebody chose to publish it."""
    if kind not in KINDS:
        raise BookmarkDenied("bad_kind", f"unknown bookmark kind: {kind}")
    if kind == KIND_APPLIANCE:
        if appliance_id is None:
            raise BookmarkDenied("missing_appliance",
                                 "an appliance bookmark needs a device")
        allowed = _visible_appliance_ids(user)
        if appliance_id not in allowed:
            # Not "forbidden" — the same 404-shaped answer the rest of the
            # product gives, so bookmarking cannot be used to probe for the
            # existence of devices in another ADOM or in maintenance.
            raise BookmarkDenied("unknown_appliance",
                                 "no such device in this console")
    if kind == KIND_LINK:
        if not (url or "").strip():
            raise BookmarkDenied("missing_url", "a link bookmark needs a URL")
        # The scheme is checked HERE and again at render time. Both, because
        # they defend different things: this one stops the row being stored
        # at all and tells the author why, and the render-time one covers the
        # rows this function never saw -- a bundle restore and a Postgres
        # replica both land rows without passing through here.
        safe, why = safe_link_url(url)
        if safe is None:
            raise BookmarkDenied("bad_url", why)
        url = safe

    bm = Bookmark(
        scope=SCOPE_PERSONAL, owner_user_id=user.id, kind=kind,
        appliance_id=appliance_id if kind == KIND_APPLIANCE else None,
        url=(url or "").strip() or None,
        view_query=(view_query or "").strip() or None,
        label=(label or "").strip() or None,
        product=product_scope.stamp(),
    )
    db.session.add(bm)
    db.session.flush()
    # A personal bookmark is filed where its author made it, immediately —
    # otherwise it would render in the "not yet filed" state its author is
    # already looking at.
    place(user, bm, parent_id=parent_id, commit=False)
    db.session.commit()
    return bm


def adopt(user, appliance_id: int | None, parent_id: int | None = None) -> Bookmark:
    """The bookmark *user* owns for *appliance_id*, created only if absent.

    The inventory lenses list every device the reader may see, with no bookmark
    row behind them. Starring or filing one has to mint that row — and has to
    be **idempotent**, because starring a device twice must not leave two rows.
    Two bookmarks for one appliance is how a panel starts showing the same
    device twice with disagreeing stars, and neither one is wrong.

    Resolution goes through :func:`visible_bookmarks`, so this cannot reach a
    row stamped for another ADOM, and creation goes through :func:`create`, so
    the appliance itself is still checked against the reader's own gate.
    """
    if appliance_id is None:
        raise BookmarkDenied("missing_appliance",
                             "an appliance bookmark needs a device")
    for bm in visible_bookmarks(user):
        if (bm.kind == KIND_APPLIANCE and bm.appliance_id == appliance_id
                and bm.scope == SCOPE_PERSONAL and bm.owner_user_id == user.id):
            if parent_id is not None:
                place(user, bm, parent_id=parent_id)
            return bm
    return create(user, KIND_APPLIANCE, appliance_id=appliance_id,
                  parent_id=parent_id)


def share(bm: Bookmark, user) -> Bookmark:
    """Move a personal bookmark into the team scope. MOVE, not copy.

    A copy leaves two rows that drift: the author edits theirs, the team keeps
    reading the stale one, and nobody can tell which is authoritative. The
    author's own placement is preserved, so publishing something does not make
    it jump out of the folder they keep it in.
    """
    if bm.scope == SCOPE_TEAM:
        raise BookmarkDenied("already_shared", "this bookmark is already shared")
    if bm.owner_user_id != user.id:
        raise BookmarkDenied("not_owner", "only the author may share it")
    if not user.can(SHARE_PERMISSION):
        raise BookmarkDenied("insufficient_role",
                             "sharing changes what every operator sees")
    if bm.kind == KIND_FOLDER:
        # Folders are personal filing. Sharing one would publish a container
        # whose contents each member is entitled to re-file anyway.
        raise BookmarkDenied("folder_not_shareable",
                             "folders are personal; share their contents")
    bm.scope = SCOPE_TEAM
    db.session.commit()
    return bm


def place(user, bm: Bookmark, parent_id: int | None = None,
          position: int = 0, commit: bool = True) -> BookmarkPlacement:
    """File *bm* for *user* only. Filing a team bookmark is not editing it —
    this writes exclusively to the acting user's own placement row."""
    if parent_id is not None:
        folder = Bookmark.query.get(parent_id)
        if folder is None or folder.kind != KIND_FOLDER:
            raise BookmarkDenied("bad_folder", "no such folder")
        if folder.owner_user_id != user.id:
            # Filing into somebody else's folder would let one user rearrange
            # another's panel.
            raise BookmarkDenied("foreign_folder", "not your folder")
        if folder.id == bm.id:
            raise BookmarkDenied("folder_cycle", "a folder cannot contain itself")
    row = BookmarkPlacement.query.get((user.id, bm.id))
    if row is None:
        row = BookmarkPlacement(user_id=user.id, bookmark_id=bm.id)
        db.session.add(row)
    row.parent_id = parent_id
    row.position = position
    if commit:
        db.session.commit()
    return row


def set_hidden(user, bm: Bookmark, hidden: bool) -> BookmarkPlacement:
    """Hide/unhide a TEAM bookmark for *user* only.

    Refused on a personal bookmark, and the refusal is specific: hiding your
    own bookmark is deleting it with extra steps, and silently accepting it
    would leave rows nothing in the UI accounts for.
    """
    if bm.scope != SCOPE_TEAM:
        raise BookmarkDenied("not_shared",
                             "only shared bookmarks can be hidden; delete your own")
    row = BookmarkPlacement.query.get((user.id, bm.id))
    if row is None:
        row = BookmarkPlacement(user_id=user.id, bookmark_id=bm.id)
        db.session.add(row)
    row.hidden = bool(hidden)
    db.session.commit()
    return row


def set_favorite(user, bm: Bookmark, favorite: bool) -> None:
    """Star/unstar for *user* only — including on a team bookmark."""
    row = BookmarkFavorite.query.get((user.id, bm.id))
    if favorite and row is None:
        db.session.add(BookmarkFavorite(user_id=user.id, bookmark_id=bm.id))
    elif not favorite and row is not None:
        db.session.delete(row)
    db.session.commit()


def delete(bm: Bookmark, user) -> None:
    """Remove a bookmark. Author or admin only.

    Deleting a FOLDER never deletes what it holds: the children's placements
    are reset, so team bookmarks fall back to the shared tray and personal ones
    to the root. One member tidying their own panel must not destroy a shared
    resource — and the reset is done here explicitly rather than left to
    ``ON DELETE CASCADE``, because SQLite enforces foreign keys only when the
    connection asked it to.
    """
    if not may_edit(bm, user):
        raise BookmarkDenied("not_owner", "only the author or an admin may delete")
    if bm.kind == KIND_FOLDER:
        BookmarkPlacement.query.filter_by(parent_id=bm.id).delete(
            synchronize_session=False)
    BookmarkPlacement.query.filter_by(bookmark_id=bm.id).delete(
        synchronize_session=False)
    BookmarkFavorite.query.filter_by(bookmark_id=bm.id).delete(
        synchronize_session=False)
    db.session.delete(bm)
    db.session.commit()
