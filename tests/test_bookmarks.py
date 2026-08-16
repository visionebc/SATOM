"""Guards for the bookmarks panel.

What is being defended here is not "the code runs" — it is a set of claims that
FAIL SILENTLY when broken. A bookmark that quietly copied the inventory still
renders; it just renders yesterday's zone. A shared bookmark that skipped the
reader's visibility gate still renders; it just shows a device that person is
not allowed to see. A placement wiped by somebody else's cleanup still renders;
the panel simply looks tidy and is missing things.

So each test names a CLAIM and breaks it, and the mutation harness confirms the
guard bites. The authority is always the live inventory or the acting user's
permissions — never a second copy written down at bookmark-creation time.
"""
from __future__ import annotations

import json

import pytest

from app.extensions import db
from app.models import Appliance, User
from app.models_bookmarks import (
    Bookmark, BookmarkFavorite, BookmarkPlacement,
    KIND_APPLIANCE, KIND_FOLDER, KIND_LINK, SCOPE_PERSONAL, SCOPE_TEAM,
)
from app.services import bookmarks as bk


# --- helpers ---------------------------------------------------------------

def _user(session, username, role="operator"):
    u = User(username=username, role=role, is_active=True)
    u.set_password("pw")
    session.add(u)
    session.commit()
    return u


def _appl(session, name, host="192.0.2.13", **kw):
    a = Appliance(name=name, kind=kw.pop("kind", "fortiweb"), host=host,
                  port=443, username="admin", password_enc="x",
                  verify_ssl=False, **kw)
    session.add(a)
    session.commit()
    return a


SEGMENTS = [
    {"name": "LineP_Internal_LB", "cidr": "192.0.2.0/24"},
    {"name": "MGMT", "cidr": "192.0.2.0/24"},
    {"name": "broken", "cidr": "not-a-cidr"},
]


# --- claim: a bookmark stores the id, never the classification -------------

def test_appliance_bookmark_follows_a_device_rename(session):
    """CLAIM: the panel shows the device's LIVE name.

    If the name were copied at creation time nothing would break — the panel
    would just keep printing the old one after a rename, and the operator would
    search the console for a device that no longer answers to that name.
    """
    u = _user(session, "alice")
    a = _appl(session, "fortiweb08")
    bm = bk.create(u, KIND_APPLIANCE, appliance_id=a.id)
    assert bm.display_label() == "fortiweb08"

    a.name = "fortiweb08-renamed"
    session.commit()
    db.session.refresh(bm)
    assert bm.display_label() == "fortiweb08-renamed"


def test_an_explicit_label_overrides_the_live_name(session):
    u = _user(session, "alice")
    a = _appl(session, "fortiweb08")
    bm = bk.create(u, KIND_APPLIANCE, appliance_id=a.id, label="mi WAF")
    assert bm.display_label() == "mi WAF"


def test_grouping_is_recomputed_from_the_live_appliance(session):
    """CLAIM: re-zoning a device re-files its bookmark with no write.

    A stored zone would leave the bookmark in the old bucket forever — the
    second-inventory failure this whole design exists to avoid.
    """
    u = _user(session, "alice")
    a = _appl(session, "fortiweb08", zone="internal", line="P",
              department="WAF/LB")
    bm = bk.create(u, KIND_APPLIANCE, appliance_id=a.id)
    assert bk.group_key(bm, "zone") == "internal"

    a.zone = "dmz"
    session.commit()
    db.session.refresh(bm)
    assert bk.group_key(bm, "zone") == "dmz"


def test_unclassified_device_and_non_device_land_in_different_buckets(session):
    """CLAIM: "nobody classified this device" and "this is a link" are two
    facts. Merging them into one empty-string bucket hides the first, which is
    the one somebody has to act on."""
    u = _user(session, "alice")
    a = _appl(session, "fortiweb09", zone=None)
    dev = bk.create(u, KIND_APPLIANCE, appliance_id=a.id)
    link = bk.create(u, KIND_LINK, url="https://example.invalid/")

    assert bk.group_key(dev, "zone") == bk.UNCLASSIFIED
    assert bk.group_key(link, "zone") == bk.NON_DEVICE
    assert bk.UNCLASSIFIED != bk.NON_DEVICE


def test_unclassified_devices_are_shown_not_dropped(session):
    """CLAIM: the unclassified bucket is rendered. Half a real fleet has no
    zone; a panel that hides them looks tidy and is missing five devices."""
    u = _user(session, "alice")
    a = _appl(session, "fortiadc02", zone=None)
    bm = bk.create(u, KIND_APPLIANCE, appliance_id=a.id)
    keys = {bk.group_key(b, "zone") for b in bk.visible_bookmarks(u)}
    assert bk.UNCLASSIFIED in keys
    assert bm.id in {b.id for b in bk.visible_bookmarks(u)}


# --- claim: "network" is derived from host, never a new column -------------

def test_segment_is_derived_by_matching_host_against_declared_cidrs(session):
    u = _user(session, "alice")
    a = _appl(session, "fortiweb08", host="192.0.2.13")
    bm = bk.create(u, KIND_APPLIANCE, appliance_id=a.id)
    assert bk.group_key(bm, "segment", SEGMENTS) == "MGMT"


def test_a_host_outside_every_segment_says_so(session):
    u = _user(session, "alice")
    a = _appl(session, "fortiweb08", host="192.168.99.5")
    bm = bk.create(u, KIND_APPLIANCE, appliance_id=a.id)
    assert bk.group_key(bm, "segment", SEGMENTS) == bk.NO_SEGMENT


def test_a_non_ip_host_has_no_segment_and_does_not_raise(session):
    """CLAIM: a retired device's ``*.invalid`` placeholder is not an error.

    Letting ``ip_address()`` raise here would take down the whole panel for
    every user because one row is a FQDN.
    """
    u = _user(session, "alice")
    a = _appl(session, "fw6", host="fw6.invalid")
    bm = bk.create(u, KIND_APPLIANCE, appliance_id=a.id)
    assert bk.group_key(bm, "segment", SEGMENTS) == bk.NO_SEGMENT


def test_a_malformed_declared_cidr_is_skipped_not_fatal(session):
    """The live settings contain a junk segment row (``x``, empty CIDR). One
    bad row must not stop the good ones from matching."""
    u = _user(session, "alice")
    a = _appl(session, "fortiweb08", host="192.0.2.7")
    bm = bk.create(u, KIND_APPLIANCE, appliance_id=a.id)
    assert bk.group_key(bm, "segment", SEGMENTS) == "LineP_Internal_LB"


def test_segment_of_tolerates_an_empty_segment_list(session):
    assert bk.segment_of("192.0.2.1", []) == bk.NO_SEGMENT


def test_folder_mode_is_not_a_derived_group(session):
    """Folders are the ONE stored grouping. Asking group_key for them would
    silently return a wrong bucket instead of routing to the placement rows."""
    u = _user(session, "alice")
    bm = bk.create(u, KIND_LINK, url="https://example.invalid/")
    with pytest.raises(ValueError):
        bk.group_key(bm, bk.GROUP_FOLDER)


def test_tag_grouping_survives_malformed_tag_json(session):
    u = _user(session, "alice")
    a = _appl(session, "fortiweb08")
    a.tags = "{not json"
    session.commit()
    bm = bk.create(u, KIND_APPLIANCE, appliance_id=a.id)
    assert bk.group_key(bm, "tag") == bk.UNCLASSIFIED

    a.tags = json.dumps(["prod", "edge"])
    session.commit()
    db.session.refresh(bm)
    assert bk.group_key(bm, "tag") == "prod"


# --- claim: the READER's permissions decide the list -----------------------

def test_a_shared_bookmark_cannot_expose_a_maintenance_device(session):
    """CLAIM: the sharer does not decide what the reader sees.

    An admin bookmarks a maintenance device and shares it. An operator must not
    see it — otherwise "share" is a way to hand somebody a device the console
    deliberately hides from them.
    """
    admin = _user(session, "root2", role="admin")
    op = _user(session, "opuser", role="operator")
    a = _appl(session, "fw-retired", maintenance=True)
    bm = bk.create(admin, KIND_APPLIANCE, appliance_id=a.id)
    bk.share(bm, admin)

    assert bm.id in {b.id for b in bk.visible_bookmarks(admin)}
    assert bm.id not in {b.id for b in bk.visible_bookmarks(op)}


def test_filtering_a_bookmark_out_never_destroys_placement(session):
    """CLAIM: a device entering maintenance hides the bookmark; it does not
    unfile it. Deleting placements on invisible rows would wipe the whole
    team's filing the day one operator flips a switch."""
    admin = _user(session, "root2", role="admin")
    op = _user(session, "opuser", role="operator")
    a = _appl(session, "fortiweb08")
    bm = bk.create(admin, KIND_APPLIANCE, appliance_id=a.id)
    bk.share(bm, admin)
    folder = bk.create(op, KIND_FOLDER, label="Guardia")
    bk.place(op, bm, parent_id=folder.id)

    a.maintenance = True
    session.commit()
    assert bm.id not in {b.id for b in bk.visible_bookmarks(op)}
    row = BookmarkPlacement.query.get((op.id, bm.id))
    assert row is not None and row.parent_id == folder.id

    a.maintenance = False
    session.commit()
    assert bm.id in {b.id for b in bk.visible_bookmarks(op)}
    assert BookmarkPlacement.query.get((op.id, bm.id)).parent_id == folder.id


def test_another_users_personal_bookmark_is_invisible(session):
    alice = _user(session, "alice")
    bob = _user(session, "bob")
    bm = bk.create(alice, KIND_LINK, url="https://private.invalid/")
    assert bm.id in {b.id for b in bk.visible_bookmarks(alice)}
    assert bm.id not in {b.id for b in bk.visible_bookmarks(bob)}


def test_bookmarking_an_invisible_device_is_refused_as_unknown(session):
    """CLAIM: the refusal does not confirm the device exists. A distinct
    "forbidden" would turn the bookmark form into a probe for the names of
    devices in maintenance or in another ADOM."""
    op = _user(session, "opuser", role="operator")
    a = _appl(session, "fw-secret", maintenance=True)
    with pytest.raises(bk.BookmarkDenied) as e:
        bk.create(op, KIND_APPLIANCE, appliance_id=a.id)
    assert e.value.reason == "unknown_appliance"


def test_anonymous_sees_nothing(session):
    class _Anon:
        is_authenticated = False
        id = None
    assert bk.visible_bookmarks(_Anon()) == []
    assert bk.visible_bookmarks(None) == []


# --- claim: sharing moves, and is an operator-grade act --------------------

def test_share_moves_and_leaves_exactly_one_row(session):
    """CLAIM: no copy. Two rows would drift — the author edits theirs, the team
    keeps reading the stale one, and neither is authoritative."""
    u = _user(session, "alice")
    bm = bk.create(u, KIND_LINK, url="https://runbook.invalid/")
    before = Bookmark.query.count()
    bk.share(bm, u)
    assert Bookmark.query.count() == before
    assert bm.scope == SCOPE_TEAM
    assert Bookmark.query.filter_by(scope=SCOPE_PERSONAL,
                                    url="https://runbook.invalid/").count() == 0


def test_sharing_keeps_the_authors_own_placement(session):
    """CLAIM: publishing something does not make it jump out of the folder the
    author keeps it in. Otherwise sharing feels like losing."""
    u = _user(session, "alice")
    folder = bk.create(u, KIND_FOLDER, label="Runbooks")
    bm = bk.create(u, KIND_LINK, url="https://runbook.invalid/",
                   parent_id=folder.id)
    bk.share(bm, u)
    row = BookmarkPlacement.query.get((u.id, bm.id))
    assert row is not None and row.parent_id == folder.id


def test_readonly_cannot_share(session):
    ro = _user(session, "ro", role="readonly")
    bm = bk.create(ro, KIND_LINK, url="https://x.invalid/")
    with pytest.raises(bk.BookmarkDenied) as e:
        bk.share(bm, ro)
    assert e.value.reason == "insufficient_role"
    assert bm.scope == SCOPE_PERSONAL


def test_only_the_author_may_share(session):
    alice = _user(session, "alice")
    bob = _user(session, "bob")
    bm = bk.create(alice, KIND_LINK, url="https://x.invalid/")
    with pytest.raises(bk.BookmarkDenied) as e:
        bk.share(bm, bob)
    assert e.value.reason == "not_owner"


def test_sharing_twice_is_refused_distinguishably(session):
    u = _user(session, "alice")
    bm = bk.create(u, KIND_LINK, url="https://x.invalid/")
    bk.share(bm, u)
    with pytest.raises(bk.BookmarkDenied) as e:
        bk.share(bm, u)
    assert e.value.reason == "already_shared"


def test_a_folder_is_not_shareable(session):
    u = _user(session, "alice")
    f = bk.create(u, KIND_FOLDER, label="Guardia")
    with pytest.raises(bk.BookmarkDenied) as e:
        bk.share(f, u)
    assert e.value.reason == "folder_not_shareable"


# --- claim: placement is per-user and only ever touches your own rows ------

def test_two_users_file_the_same_shared_bookmark_differently(session):
    """CLAIM: filing a team bookmark writes ONLY the acting user's row. If it
    wrote the bookmark, one member's tidy-up would rearrange everybody's
    panel."""
    alice = _user(session, "alice")
    bob = _user(session, "bob")
    bm = bk.create(alice, KIND_LINK, url="https://x.invalid/")
    bk.share(bm, alice)

    fa = bk.create(alice, KIND_FOLDER, label="A")
    fb = bk.create(bob, KIND_FOLDER, label="B")
    bk.place(alice, bm, parent_id=fa.id)
    bk.place(bob, bm, parent_id=fb.id)

    assert BookmarkPlacement.query.get((alice.id, bm.id)).parent_id == fa.id
    assert BookmarkPlacement.query.get((bob.id, bm.id)).parent_id == fb.id


def test_filing_into_someone_elses_folder_is_refused(session):
    alice = _user(session, "alice")
    bob = _user(session, "bob")
    bm = bk.create(alice, KIND_LINK, url="https://x.invalid/")
    bk.share(bm, alice)
    fa = bk.create(alice, KIND_FOLDER, label="A")
    with pytest.raises(bk.BookmarkDenied) as e:
        bk.place(bob, bm, parent_id=fa.id)
    assert e.value.reason == "foreign_folder"


def test_a_folder_cannot_contain_itself(session):
    u = _user(session, "alice")
    f = bk.create(u, KIND_FOLDER, label="A")
    with pytest.raises(bk.BookmarkDenied) as e:
        bk.place(u, f, parent_id=f.id)
    assert e.value.reason == "folder_cycle"


def test_filing_into_a_non_folder_is_refused(session):
    u = _user(session, "alice")
    link = bk.create(u, KIND_LINK, url="https://x.invalid/")
    other = bk.create(u, KIND_LINK, url="https://y.invalid/")
    with pytest.raises(bk.BookmarkDenied) as e:
        bk.place(u, other, parent_id=link.id)
    assert e.value.reason == "bad_folder"


def test_no_placement_row_and_a_root_placement_are_different_states(session):
    """CLAIM: "this arrived and I have not triaged it" is not the same as "I
    deliberately keep it at the top". Collapsing them makes the shared tray
    permanently full, so its counter stops meaning anything."""
    alice = _user(session, "alice")
    bob = _user(session, "bob")
    bm = bk.create(alice, KIND_LINK, url="https://x.invalid/")
    bk.share(bm, alice)

    assert BookmarkPlacement.query.get((bob.id, bm.id)) is None
    assert bk.tray_counts(bob)["unplaced"] == 1

    bk.place(bob, bm, parent_id=None)
    row = BookmarkPlacement.query.get((bob.id, bm.id))
    assert row is not None and row.parent_id is None
    assert bk.tray_counts(bob)["unplaced"] == 0


# --- claim: one member's cleanup never destroys a shared resource ----------

def test_deleting_your_folder_keeps_the_shared_bookmark(session):
    """CLAIM: the bookmark survives and falls back to the tray. If the folder's
    deletion cascaded to the BOOKMARK, one operator tidying their own panel
    would delete a team resource for everybody."""
    alice = _user(session, "alice")
    bob = _user(session, "bob")
    bm = bk.create(alice, KIND_LINK, url="https://x.invalid/")
    bk.share(bm, alice)
    folder = bk.create(bob, KIND_FOLDER, label="Guardia")
    bk.place(bob, bm, parent_id=folder.id)

    bk.delete(folder, bob)

    assert Bookmark.query.get(bm.id) is not None
    assert BookmarkPlacement.query.get((bob.id, bm.id)) is None
    assert bk.tray_counts(bob)["unplaced"] == 1
    assert bm.id in {b.id for b in bk.visible_bookmarks(bob)}


def test_only_the_author_or_an_admin_may_delete(session):
    alice = _user(session, "alice")
    bob = _user(session, "bob")
    admin = _user(session, "root2", role="admin")
    bm = bk.create(alice, KIND_LINK, url="https://x.invalid/")
    bk.share(bm, alice)

    with pytest.raises(bk.BookmarkDenied) as e:
        bk.delete(bm, bob)
    assert e.value.reason == "not_owner"
    assert Bookmark.query.get(bm.id) is not None

    bk.delete(bm, admin)
    assert Bookmark.query.get(bm.id) is None


def test_filing_and_starring_are_not_edits(session):
    """CLAIM: may_edit gates label/target/delete only. If filing went through
    the same gate, nobody but the author could organise a shared bookmark —
    which is the entire feature the user asked for."""
    alice = _user(session, "alice")
    bob = _user(session, "bob")
    bm = bk.create(alice, KIND_LINK, url="https://x.invalid/")
    bk.share(bm, alice)

    assert bk.may_edit(bm, bob) is False
    bk.place(bob, bm, parent_id=None)          # allowed
    bk.set_favorite(bob, bm, True)             # allowed
    bk.set_hidden(bob, bm, True)               # allowed
    assert BookmarkPlacement.query.get((bob.id, bm.id)).hidden is True


# --- claim: favourites and hiding are personal ----------------------------

def test_starring_a_shared_bookmark_is_personal(session):
    """CLAIM: a favourite is a row, not a column. A column on a shared row
    would be everybody's favourite at once."""
    alice = _user(session, "alice")
    bob = _user(session, "bob")
    bm = bk.create(alice, KIND_LINK, url="https://x.invalid/")
    bk.share(bm, alice)
    bk.set_favorite(bob, bm, True)

    assert bk.favorites(bob) == {bm.id}
    assert bk.favorites(alice) == set()


def test_unstarring_removes_the_row(session):
    u = _user(session, "alice")
    bm = bk.create(u, KIND_LINK, url="https://x.invalid/")
    bk.set_favorite(u, bm, True)
    bk.set_favorite(u, bm, False)
    assert BookmarkFavorite.query.count() == 0
    bk.set_favorite(u, bm, False)  # idempotent
    assert BookmarkFavorite.query.count() == 0


def test_hiding_your_own_personal_bookmark_is_refused(session):
    """CLAIM: hiding is for shared rows. Accepting it on a personal one would
    leave rows the UI never accounts for — deleting is the honest verb."""
    u = _user(session, "alice")
    bm = bk.create(u, KIND_LINK, url="https://x.invalid/")
    with pytest.raises(bk.BookmarkDenied) as e:
        bk.set_hidden(u, bm, True)
    assert e.value.reason == "not_shared"


def test_hiding_is_counted_never_silent(session):
    """CLAIM: the tray header always carries the hidden count.

    A silent hide is what makes "it never reached me" unfalsifiable — and with
    the panel collapsed by default, an uncounted hide is indistinguishable from
    a bookmark that was never shared.
    """
    alice = _user(session, "alice")
    bob = _user(session, "bob")
    bm = bk.create(alice, KIND_LINK, url="https://x.invalid/")
    bk.share(bm, alice)

    assert bk.tray_counts(bob) == {"unplaced": 1, "hidden": 0}
    bk.set_hidden(bob, bm, True)
    assert bk.tray_counts(bob) == {"unplaced": 0, "hidden": 1}
    bk.set_hidden(bob, bm, False)
    assert bk.tray_counts(bob) == {"unplaced": 0, "hidden": 0}


def test_hiding_is_per_user(session):
    alice = _user(session, "alice")
    bob = _user(session, "bob")
    carol = _user(session, "carol")
    bm = bk.create(alice, KIND_LINK, url="https://x.invalid/")
    bk.share(bm, alice)
    bk.set_hidden(bob, bm, True)
    assert bk.tray_counts(bob)["hidden"] == 1
    assert bk.tray_counts(carol)["hidden"] == 0
    assert bk.tray_counts(carol)["unplaced"] == 1


# --- claim: creation refusals are specific --------------------------------

def test_an_unknown_kind_is_refused(session):
    u = _user(session, "alice")
    with pytest.raises(bk.BookmarkDenied) as e:
        bk.create(u, "wharrgarbl")
    assert e.value.reason == "bad_kind"


def test_a_device_bookmark_without_a_device_is_refused(session):
    u = _user(session, "alice")
    with pytest.raises(bk.BookmarkDenied) as e:
        bk.create(u, KIND_APPLIANCE)
    assert e.value.reason == "missing_appliance"


def test_a_link_bookmark_without_a_url_is_refused(session):
    u = _user(session, "alice")
    with pytest.raises(bk.BookmarkDenied) as e:
        bk.create(u, KIND_LINK, url="   ")
    assert e.value.reason == "missing_url"


def test_a_saved_view_stores_the_filter_not_the_rows(session):
    """CLAIM: "WAF internos" is a QUERY. Storing the matching devices would be
    correct today and wrong the moment a fortiweb11 is added — the same
    staleness that makes copying the zone a bug."""
    u = _user(session, "alice")
    bm = bk.create(u, "view",
                   view_query=json.dumps({"zone": "internal", "kind": "fortiweb"}),
                   label="WAF internos")
    assert bm.filters() == {"zone": "internal", "kind": "fortiweb"}
    assert bm.appliance_id is None


def test_a_malformed_saved_filter_reads_as_empty_not_a_crash(session):
    u = _user(session, "alice")
    bm = bk.create(u, "view", view_query="{not json", label="roto")
    assert bm.filters() == {}


# --- claim: bookmarks carry the ADOM stamp like every other scoped row -----

def test_a_link_created_in_one_adom_does_not_leak_into_another(app, session):
    """CLAIM: bookmarks are product-scoped. A link bookmark has no appliance to
    scope it, so without its own stamp a FortiADC runbook would appear in the
    FortiWeb console."""
    u = _user(session, "alice")
    with app.test_request_context("/"):
        from flask import session as flask_session
        flask_session["product"] = "fortiadc"
        bm = bk.create(u, KIND_LINK, url="https://adc.invalid/")
        assert bm.product == "fortiadc"
        assert bm.id in {b.id for b in bk.visible_bookmarks(u)}

    with app.test_request_context("/"):
        from flask import session as flask_session
        flask_session["product"] = "fortiweb"
        assert bm.id not in {b.id for b in bk.visible_bookmarks(u)}
