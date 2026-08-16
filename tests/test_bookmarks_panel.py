"""Guards for the bookmarks PANEL — the routes, the tree and the search.

The service layer is pinned by ``test_bookmarks.py``. What this file defends is
the layer between the service and the operator, where the failures are
invisible rather than loud:

* A by-id route that resolves with ``Bookmark.query.get`` serves another user's
  row and renders **perfectly**. Nothing throws, nothing looks wrong, and the
  only symptom is that somebody saw something they should not have.
* A refusal collapsed into a bare 400 still "works": the operator just cannot
  tell which rule stopped them, so they route around it.
* A search that filters in the BROWSER renders identically to one that filters
  on the server, and leaves rows in the DOM that the reader's own permissions
  had removed from the answer.
* A hidden count that stops rendering leaves "it never reached me" impossible
  to check — the panel looks tidy and is quietly missing things.
* A tree that boots expanded looks *better* on a five-device demo and is
  unusable on the hundred-device fleet this ships to.

Every assertion names the claim it defends, and none of them assert on a
substring that the template would contain anyway — ``"hidden" in body`` was a
real guard here once, and it passed against a panel whose counter had been
deleted, because ``hidden`` is also an HTML attribute on every collapsed node.
"""
from __future__ import annotations

import json
import os
import re

import pytest

from app.extensions import db
from app.models import Appliance, User, UserSetting
from app.models_bookmarks import (
    Bookmark, BookmarkPlacement, KIND_APPLIANCE, KIND_FOLDER, KIND_LINK,
    SCOPE_PERSONAL, SCOPE_TEAM,
)
from app.services import bookmarks as bk
from app.views import bookmarks as view

from tests.conftest import admin_user_id, login, make_user


# --- helpers ---------------------------------------------------------------

def _appl(app, name, host="192.0.2.13", **kw):
    with app.app_context():
        a = Appliance(name=name, kind=kw.pop("kind", "fortiweb"), host=host,
                      port=443, username="admin", password_enc="x",
                      verify_ssl=False, **kw)
        db.session.add(a)
        db.session.commit()
        return a.id


def _bm(app, owner_id, **kw):
    with app.app_context():
        bm = Bookmark(owner_user_id=owner_id,
                      scope=kw.pop("scope", SCOPE_PERSONAL),
                      kind=kw.pop("kind", KIND_LINK),
                      url=kw.pop("url", "https://example.invalid"),
                      label=kw.pop("label", "row"),
                      product=kw.pop("product", "fortiweb"), **kw)
        db.session.add(bm)
        db.session.commit()
        return bm.id


def _folder(app, owner_id, label):
    return _bm(app, owner_id, kind=KIND_FOLDER, url=None, label=label)


def _panel(client, q=None):
    url = "/bookmarks/panel" + (f"?q={q}" if q else "")
    r = client.get(url)
    assert r.status_code == 200
    return r.get_data(as_text=True)


# --- claim: an id is never authority ---------------------------------------

def test_another_users_private_bookmark_is_not_found(app, client):
    """CLAIM: a by-id route answers 404 — not 403 — for a row the caller may
    not see.

    404 and 403 are not interchangeable here. A 403 confirms the row exists,
    which turns the favourite button into an oracle for enumerating what other
    operators have bookmarked. And the shape that produces a 403 is the same
    one that produces a 200 the day somebody trims the ownership check."""
    owner = make_user(app, username="owner", role="operator")
    other = make_user(app, username="other", role="operator")
    bid = _bm(app, owner)

    login(client, other)
    for path in ("favorite", "hidden", "share", "delete", "place"):
        r = client.post(f"/bookmarks/{bid}/{path}", data={})
        assert r.status_code == 404, f"{path} leaked a foreign bookmark"


def test_a_shared_bookmark_to_an_invisible_device_is_not_found(app, client):
    """CLAIM: the READER's appliance gate decides, not the sharer's.

    A device in maintenance is invisible; a team bookmark pointing at it must
    be unreachable by id too. Filtering it only out of the RENDER would leave
    every mutation route as a way to confirm the device exists."""
    admin = admin_user_id(app)
    aid = _appl(app, "fw-maint", maintenance=True)
    bid = _bm(app, admin, scope=SCOPE_TEAM, kind=KIND_APPLIANCE,
              appliance_id=aid, url=None, label=None)

    # The sharer is an admin, who MAY see maintenance rows. The reader is not:
    # that asymmetry is the whole point, and a test run as the sharer would
    # have passed against a route with no gate at all.
    reader = make_user(app, username="nomaint", role="readonly")
    with app.app_context():
        from app.models import can_view_maintenance, User
        assert not can_view_maintenance(User.query.get(reader))
    login(client, reader)
    assert client.post(f"/bookmarks/{bid}/favorite",
                       data={"favorite": "1"}).status_code == 404


def test_the_device_picker_cannot_enumerate_hidden_devices(app, client):
    """CLAIM: the "add bookmark" picker is scoped by the same gate as the rest
    of the console. A picker with its own query is a second implementation of
    a visibility boundary, and the weaker one becomes the real one."""
    _appl(app, "fw-visible", host="192.0.2.13")
    _appl(app, "fw-hidden", host="192.0.2.99", maintenance=True)

    reader = make_user(app, username="picker", role="readonly")
    login(client, reader)
    names = {d["name"] for d in client.get("/bookmarks/devices").get_json()["devices"]}
    assert "fw-visible" in names
    assert "fw-hidden" not in names


def test_the_inventory_lenses_are_scoped_to_the_reader(app, client):
    """CLAIM: the tree lists the LIVE inventory, and that listing goes through
    the same gate.

    This is the new blast radius of the redesign: the classification roots show
    devices nobody has bookmarked, so a lens built from its own query would
    publish the whole fleet to every reader — a leak with no bookmark row
    behind it to notice."""
    _appl(app, "fw-open", host="192.0.2.13")
    _appl(app, "fw-secret", host="192.0.2.99", maintenance=True)
    reader = make_user(app, username="lens-reader", role="readonly")
    login(client, reader)
    body = _panel(client)
    assert "fw-open" in body
    assert "fw-secret" not in body, "a lens enumerated an invisible device"


# --- claim: a refusal names its rule ---------------------------------------

def test_a_refusal_carries_the_reason(app, client):
    """CLAIM: BookmarkDenied.reason reaches the browser.

    'not allowed' at 03:00 is what makes an operator look for a way around the
    rule. 'insufficient_role' tells them what to ask for."""
    reader = make_user(app, username="reader", role="readonly")
    bid = _bm(app, reader)

    login(client, reader)
    r = client.post(f"/bookmarks/{bid}/share", data={})
    assert r.status_code == 400
    assert r.get_json()["reason"] == "insufficient_role"


def test_hiding_your_own_bookmark_is_refused_by_name(app, client):
    """CLAIM: hiding is for SHARED rows only, and the refusal says so.

    Accepting it silently would leave a personal row that nothing in the UI
    accounts for: not in the tray (it is not shared), not in the tree (it is
    hidden), and not in any count."""
    admin = admin_user_id(app)
    bid = _bm(app, admin)
    login(client, admin)
    r = client.post(f"/bookmarks/{bid}/hidden", data={"hidden": "1"})
    assert r.status_code == 400
    assert r.get_json()["reason"] == "not_shared"


# --- claim: sharing is audited ---------------------------------------------

def test_sharing_writes_an_audit_row(app, client):
    """CLAIM: publishing to the team is attributable afterwards.

    Sharing changes what every operator sees. An unaudited visibility change is
    one nobody can trace back to a person or a moment."""
    from app.models import AuditLog
    admin = admin_user_id(app)
    bid = _bm(app, admin)
    login(client, admin)
    assert client.post(f"/bookmarks/{bid}/share", data={}).status_code == 200
    with app.app_context():
        rows = AuditLog.query.filter_by(action="bookmark.share").all()
        assert len(rows) == 1, "sharing left no trace"


def test_a_refused_share_is_not_audited_as_a_share(app, client):
    """CLAIM: the audit trail records what HAPPENED. Logging a refused share
    would make the log claim a visibility change that never occurred."""
    from app.models import AuditLog
    reader = make_user(app, username="reader2", role="readonly")
    bid = _bm(app, reader)
    login(client, reader)
    client.post(f"/bookmarks/{bid}/share", data={})
    with app.app_context():
        assert AuditLog.query.filter_by(action="bookmark.share").count() == 0


# --- claim: the tree boots collapsed, and stores what is OPEN ---------------

def test_every_branch_is_collapsed_on_a_first_render(app, client):
    """CLAIM: a user with no stored preference sees a fully collapsed tree.

    Not a cosmetic default. With ~100 appliances across four lenses, an
    expanded boot is several hundred rows in a 300px rail, and the operator's
    first action is always to close it again. The empty stored set has to MEAN
    collapsed — which it only does because the set holds the OPEN nodes."""
    _appl(app, "fw-one", zone="internal", line="P", department="WAF/LB")
    fresh = make_user(app, username="fresh", role="operator")
    login(client, fresh)
    body = _panel(client)

    assert 'data-bm-kids=' in body, "no tree rendered at all"
    for chunk in body.split('data-bm-kids="')[1:]:
        head = chunk.split(">")[0]
        assert "hidden" in head, f"a branch booted expanded: {head[:60]}"


def test_the_open_set_stores_what_is_EXPANDED(app, client):
    """CLAIM: the persisted set is the OPEN one.

    Storing the collapsed set makes 'no preference yet' mean 'expand
    everything' — the one state a hundred-device fleet must never boot into —
    and re-using an older key would read a saved closed-set as an open-set,
    expanding exactly the branches the operator had shut."""
    admin = admin_user_id(app)
    login(client, admin)
    client.post("/bookmarks/prefs", data={"open": json.dumps([view.ROOT_FOLDERS])})
    with app.app_context():
        assert json.loads(UserSetting.get(admin, view.K_OPEN)) == [view.ROOT_FOLDERS]
    body = _panel(client)
    head = body.split(f'data-bm-kids="{view.ROOT_FOLDERS}"')[1].split(">")[0]
    assert "hidden" not in head, "a stored-open branch rendered collapsed"


def test_a_malformed_open_set_is_refused(app, client):
    """CLAIM: a bad payload is a named 400, not a silent reset.

    Coercing it to an empty set would collapse the operator's whole tree with
    no error to explain why their layout keeps vanishing."""
    login(client, admin_user_id(app))
    for payload in ("{", '"nope"', "42"):
        r = client.post("/bookmarks/prefs", data={"open": payload})
        assert r.status_code == 400, payload
        assert r.get_json()["reason"] == "bad_open"


# --- claim: the tree is a tree ---------------------------------------------

def test_the_classification_root_nests_line_then_zone_then_department(app, client):
    """CLAIM: the classification lens nests three levels, outside-in.

    A flat 'group by zone' cannot express *Line P → Internal → WAF/LB*, which
    is the shape the operator asked for and the shape the segments page already
    uses. Depth is the feature; a one-level grouping that happens to contain
    the same names is not the same answer."""
    _appl(app, "fw-deep", zone="internal", line="P", department="WAF/LB")
    login(client, admin_user_id(app))
    body = _panel(client)

    assert 'data-bm-node="r:lens"' in body
    assert 'data-bm-node="r:lens|P"' in body
    assert 'data-bm-node="r:lens|P|internal"' in body
    assert 'data-bm-node="r:lens|P|internal|WAF/LB"' in body
    # …and the device sits at the bottom of that path, not beside it.
    assert 'bm-d4' in body.split('r:lens|P|internal|WAF/LB')[-1][:1200]


def test_a_folder_renders_as_an_icon_with_its_name_beside_it(app, client):
    """CLAIM: folders look like folders.

    The operator asked for the browser shape explicitly. A <select> whose
    options happen to be folder names is not it, and the difference is the
    whole point of the redesign."""
    admin = admin_user_id(app)
    _folder(app, admin, "Tuesday shift")
    login(client, admin)
    body = _panel(client)
    row = [c for c in body.split('<div class="bm-row') if "Tuesday shift" in c][0]
    head = row.split(">")[0]
    assert "bi-folder2" in row and "bm-ico-grp" in row, "no folder icon"
    assert "bm-name" in row and "Tuesday shift" in row
    # A folder is a GROUP, not a row that merely wears a folder icon: it has a
    # node key, a caret and a container. Asserting only on the icon passes
    # against a build where folders stopped nesting anything at all.
    assert "data-bm-node=" in head, "the folder is not a tree node"
    assert "bm-caret" in row, "a folder rendered with no way to expand it"
    assert f'data-bm-kids="{view.ROOT_FOLDERS}|f' in body


def test_devices_are_in_the_tree_before_anybody_bookmarks_them(app, client):
    """CLAIM: the lenses list the inventory, not the bookmark table.

    Seeding one bookmark per appliance would have produced the same first
    screenshot and a second copy of the inventory that drifts the moment a
    device is added, renamed or retired. Here there is nothing to drift: a new
    appliance appears with no bookmark migration."""
    _appl(app, "fw-unbookmarked", zone="internal", line="P")
    login(client, admin_user_id(app))
    body = _panel(client)
    assert "fw-unbookmarked" in body
    with app.app_context():
        assert Bookmark.query.count() == 0, "the tree minted rows just to render"


def test_synthetic_buckets_sort_after_the_real_ones(app, client):
    """CLAIM: ``(unclassified)`` is shown and sorted LAST.

    Half a real fleet is unclassified — five of ten devices on this very node.
    Hiding that bucket drops devices on the floor; letting it sort first buries
    the classified tree under it. Shown, and out of the way."""
    _appl(app, "fw-classified", host="192.0.2.13", line="P")
    _appl(app, "fw-nowhere", host="192.0.2.14", line=None)
    login(client, admin_user_id(app))
    body = _panel(client)
    root = body.split('data-bm-node="r:lens"')[1]
    assert root.index(">P<") < root.index(bk.UNCLASSIFIED), \
        "the unclassified bucket outranked the real tree"


# --- claim: search filters on the SERVER -----------------------------------

def test_search_removes_non_matching_rows_from_the_DOM(app, client):
    """CLAIM: the filtered tree is the ANSWER, not an overlay.

    A client-side ``display:none`` renders identically and leaves every
    non-matching row in the document — including rows a different reader's
    permissions would have removed. Filtering server-side is the only version
    where 'not shown' and 'not sent' are the same thing."""
    _appl(app, "fw-alpha", host="192.0.2.13")
    _appl(app, "fw-beta", host="192.0.2.14")
    login(client, admin_user_id(app))

    body = _panel(client, "alpha")
    assert "fw-alpha" in body
    assert "fw-beta" not in body, "a non-match survived in the DOM"


def test_search_matches_the_management_address_too(app, client):
    """CLAIM: the subtitle is searchable.

    At 03:00 an operator remembers ``.14`` far more reliably than they
    remember which of ten near-identical names it belongs to."""
    _appl(app, "fw-alpha", host="192.0.2.13")
    _appl(app, "fw-beta", host="192.0.2.14")
    login(client, admin_user_id(app))
    body = _panel(client, "192.0.2.14")
    assert "fw-beta" in body and "fw-alpha" not in body


def test_a_group_whose_name_matches_keeps_its_whole_subtree(app, client):
    """CLAIM: searching for a bucket shows the bucket's CONTENTS.

    Returning the zone header with none of its devices is a worse answer than
    returning nothing: it looks like the zone is empty."""
    _appl(app, "fw-child", zone="internal", line="P", department="WAF/LB")
    login(client, admin_user_id(app))
    body = _panel(client, "internal")
    assert "fw-child" in body, "a matching group was emptied of its children"


def test_search_expands_what_it_found(app, client):
    """CLAIM: matches render OPEN.

    A hit buried inside a collapsed branch is indistinguishable from no hit at
    all — the operator types a name, sees a closed tree, and concludes the
    device is not there."""
    _appl(app, "fw-needle", zone="internal", line="P")
    login(client, admin_user_id(app))
    body = _panel(client, "needle")
    branch = body.split('data-bm-kids="r:lens"')[1].split(">")[0]
    assert "hidden" not in branch, "the match stayed folded away"


def test_searching_does_not_overwrite_the_stored_layout(app, client):
    """CLAIM: a forced-open search tree is not a preference.

    Persisting it would flatten the operator's carefully collapsed hundred-node
    tree into the shape of one throwaway query — and they would never connect
    the two events."""
    admin = admin_user_id(app)
    login(client, admin)
    client.post("/bookmarks/prefs", data={"open": json.dumps([view.ROOT_FOLDERS])})
    _panel(client, "anything")
    with app.app_context():
        assert json.loads(UserSetting.get(admin, view.K_OPEN)) == [view.ROOT_FOLDERS]


def test_a_mutation_answers_inside_the_active_search(app, client):
    """CLAIM: starring a row while filtered returns the FILTERED tree.

    Every mutation replaces the whole panel. Answering with the unfiltered tree
    would throw the operator out of their own search on every click, which
    reads as 'the star button reset my search'."""
    _appl(app, "fw-alpha", host="192.0.2.13")
    _appl(app, "fw-beta", host="192.0.2.14")
    admin = admin_user_id(app)
    bid = _bm(app, admin, label="alpha-link")
    login(client, admin)
    body = client.post(f"/bookmarks/{bid}/favorite",
                       data={"favorite": "1", "q": "alpha"}).get_data(as_text=True)
    assert "alpha-link" in body
    assert "fw-beta" not in body, "the mutation dropped the active search"


# --- claim: adopting a device is idempotent --------------------------------

def test_starring_an_unbookmarked_device_mints_exactly_one_row(app, client):
    """CLAIM: adopt is idempotent.

    The lens shows devices with no bookmark behind them, so the star has to
    create one. Creating a second on the next click would show the same
    appliance twice with disagreeing stars, and neither row would be wrong."""
    aid = _appl(app, "fw-adopt", host="192.0.2.13")
    admin = admin_user_id(app)
    login(client, admin)
    for _ in range(3):
        assert client.post("/bookmarks/adopt",
                           data={"appliance_id": aid, "favorite": "1"}).status_code == 200
    with app.app_context():
        rows = Bookmark.query.filter_by(appliance_id=aid).all()
        assert len(rows) == 1, f"adopt minted {len(rows)} rows for one device"
        assert rows[0].scope == SCOPE_PERSONAL


def test_adopt_cannot_reach_a_device_the_reader_may_not_see(app, client):
    """CLAIM: adopt is not a back door around the appliance gate.

    It is the only route that takes an APPLIANCE id rather than a bookmark id,
    so it is the only one where the by-id discipline of this module does not
    apply by construction. It has to be checked explicitly, and the refusal has
    to be the same 404-shaped 'no such device' the rest of the console gives —
    a distinct 'forbidden' would confirm the device exists."""
    aid = _appl(app, "fw-invisible", host="192.0.2.99", maintenance=True)
    reader = make_user(app, username="adopter", role="readonly")
    login(client, reader)
    r = client.post("/bookmarks/adopt", data={"appliance_id": aid})
    assert r.status_code == 400
    assert r.get_json()["reason"] == "unknown_appliance"
    with app.app_context():
        assert Bookmark.query.count() == 0


def test_adopt_into_someone_elses_folder_is_refused(app, client):
    """CLAIM: filing is per-user. Dropping a device into another operator's
    folder would let one person rearrange another's panel."""
    admin = admin_user_id(app)
    other = make_user(app, username="folder-owner", role="operator")
    fid = _folder(app, other, "not yours")
    aid = _appl(app, "fw-drop", host="192.0.2.13")
    login(client, admin)
    r = client.post("/bookmarks/adopt", data={"appliance_id": aid, "parent_id": fid})
    assert r.status_code == 400
    assert r.get_json()["reason"] == "foreign_folder"


def test_adopt_needs_a_device(app, client):
    login(client, admin_user_id(app))
    r = client.post("/bookmarks/adopt", data={})
    assert r.status_code == 400 and r.get_json()["reason"] == "missing_appliance"


# --- claim: nothing shared becomes invisible -------------------------------

def test_the_unfiled_count_is_rendered_even_when_the_tray_is_collapsed(app, client):
    """CLAIM: the count is on the Shared row, which renders whether the tray is
    open or not.

    The panel defaults to collapsed. A bookmark shared into a collapsed tray
    that nothing counts is a bookmark nobody ever sees — the feature would
    appear to work and quietly deliver nothing."""
    admin = admin_user_id(app)
    other = make_user(app, username="colleague", role="operator")
    _bm(app, other, scope=SCOPE_TEAM, label="from a colleague")

    login(client, admin)
    body = _panel(client)
    row = body.split(f'data-bm-node="{view.ROOT_SHARED}"')[1].split("</div>")[0]
    assert "fw-badge-primary" in row, "no unfiled badge on the Shared row"
    assert "waiting to be filed" in row


def test_the_hidden_count_survives_hiding_the_row(app, client):
    """CLAIM: hiding is never silent — the counter renders the NUMBER.

    The previous version of this guard asserted ``"hidden" in body``, which
    passes against a panel whose counter has been deleted: ``hidden`` is also
    the HTML attribute on every collapsed branch. It has to assert on the
    rendered count and on a string only the counter produces."""
    admin = admin_user_id(app)
    other = make_user(app, username="colleague2", role="operator")
    bid = _bm(app, other, scope=SCOPE_TEAM, label="noisy")
    login(client, admin)
    assert client.post(f"/bookmarks/{bid}/hidden",
                       data={"hidden": "1"}).status_code == 200

    body = _panel(client)
    row = body.split(f'data-bm-node="{view.ROOT_SHARED}"')[1].split("</div>")[0]
    assert "hidden by you" in row, "the hidden counter stopped rendering"
    assert "1 " in row.split("hidden by you")[1][:40]


def test_a_hidden_row_is_out_of_the_tree_but_still_reachable(app, client):
    """CLAIM: hiding files a row away; it does not delete it. 'Show hidden'
    brings it back — otherwise hiding is an irreversible act wearing the
    costume of a view toggle."""
    admin = admin_user_id(app)
    other = make_user(app, username="colleague3", role="operator")
    bid = _bm(app, other, scope=SCOPE_TEAM, label="quiet-row")
    login(client, admin)
    client.post(f"/bookmarks/{bid}/hidden", data={"hidden": "1"})
    assert "quiet-row" not in _panel(client)
    client.post("/bookmarks/prefs", data={"showhidden": "1"})
    assert "quiet-row" in _panel(client)


def test_an_unfiled_team_bookmark_is_in_the_tray_not_the_folder_root(app, client):
    """CLAIM: 'Shared' is the destination of what nobody has filed yet.

    That is what lets it work with no migration and no first-run flag: no
    placement row at all means unfiled. If unfiled rows also rendered at the
    root of Folders, every operator would see each shared bookmark twice."""
    admin = admin_user_id(app)
    other = make_user(app, username="colleague4", role="operator")
    _bm(app, other, scope=SCOPE_TEAM, label="unfiled-row")
    login(client, admin)
    body = _panel(client)
    folders = body.split(f'data-bm-kids="{view.ROOT_FOLDERS}"')[1] \
                  .split('data-bm-node="' + view.ROOT_SHARED)[0]
    assert "unfiled-row" not in folders
    assert "unfiled-row" in body


# --- claim: grouping stays derived -----------------------------------------

def test_the_tree_regroups_after_a_rezone_with_no_write(app, client):
    """CLAIM: re-classifying a device re-files it by itself.

    This is the whole reason nothing stores a zone. If it ever stops holding,
    the panel becomes a second, stale copy of the inventory — and the operator
    has two answers to 'where is this device'."""
    aid = _appl(app, "fw-move", zone="internal", line="P")
    login(client, admin_user_id(app))
    assert 'data-bm-node="r:lens|P|internal"' in _panel(client)

    with app.app_context():
        Appliance.query.get(aid).zone = "external"
        db.session.commit()
    body = _panel(client)
    assert 'data-bm-node="r:lens|P|external"' in body
    assert 'data-bm-node="r:lens|P|internal"' not in body


def test_only_folders_accept_a_drop(app, client):
    """CLAIM: derived buckets are not drop targets.

    A drop into a computed bucket cannot persist — the next render recomputes
    it from the inventory. Letting the operator drag a row there and watch it
    snap back with no explanation is a bug report; marking only the targets
    that can accept it is the explanation."""
    admin = admin_user_id(app)
    _folder(app, admin, "mine")
    _appl(app, "fw-drag", zone="internal", line="P")
    login(client, admin)
    body = _panel(client)

    assert 'draggable="true"' in body, "nothing could be dragged at all"
    rows = re.findall(r'<div class="bm-row[^>]*>', body)
    drops = [r for r in rows if "data-bm-drop" in r]
    assert drops, "nothing accepted a drop at all"
    for r in drops:
        m = re.search(r'data-bm-node="([^"]+)"', r)
        key = m.group(1) if m else ""
        assert key == view.ROOT_FOLDERS or "|f" in key, \
            f"a derived bucket accepted drops: {r[:120]}"


def test_a_device_classified_nowhere_does_not_sink_three_levels(app, client):
    """CLAIM: an all-empty classification collapses to ONE bucket.

    Found by rendering against the live database, not by reading the code: five
    of the ten appliances on this node have no line, zone or department, and the
    naive walk filed them under
    ``(unclassified) → (unclassified) → (unclassified)`` — three clicks of depth
    carrying no information, on exactly the rows that most need to be noticed.

    The truncation is conditional on purpose: a device with no line but a real
    zone keeps ``(unclassified) → internal``, because that zone is a fact and
    swallowing it would make the tree lie by omission."""
    _appl(app, "fw-nowhere", host="192.0.2.13", zone=None, line=None, department=None)
    _appl(app, "fw-partial", host="192.0.2.14", zone="internal", line=None,
          department=None)
    login(client, admin_user_id(app))
    body = _panel(client)

    assert f'data-bm-node="r:lens|{bk.UNCLASSIFIED}"' in body
    assert f'data-bm-node="r:lens|{bk.UNCLASSIFIED}|{bk.UNCLASSIFIED}"' not in body
    # The half-classified device keeps the level it actually has.
    assert f'data-bm-node="r:lens|{bk.UNCLASSIFIED}|internal"' in body


def test_an_unclassified_device_gets_a_visible_bucket(app, client):
    """CLAIM: half a real fleet is unclassified and the panel SHOWS it.

    Hiding those rows makes the panel look tidy while dropping devices on the
    floor. The untidy bucket is what gets them classified."""
    _appl(app, "fw-null", zone=None, line=None)
    login(client, admin_user_id(app))
    body = _panel(client)
    assert bk.UNCLASSIFIED in body and "fw-null" in body


# --- claim: a starred row keeps its place ----------------------------------

def test_starring_does_not_remove_a_row_from_its_group(app, client):
    """CLAIM: Favourites is a VIEW, not a move.

    If starring relocated the row, an operator would star a device and watch it
    disappear from the zone they were looking at — indistinguishable from
    having deleted it."""
    admin = admin_user_id(app)
    aid = _appl(app, "fw-star", zone="internal", line="P")
    login(client, admin)
    body = client.post("/bookmarks/adopt",
                       data={"appliance_id": aid, "favorite": "1"}).get_data(as_text=True)
    assert view.ROOT_FAV in body
    assert body.count("fw-star") >= 2, "the starred row left its own group"


# --- claim: the panel wears the product's own chrome -----------------------

def test_the_panel_carries_no_dark_theme_leftovers(app, client):
    """CLAIM: light chrome only.

    This product has no dark mode. A slate card with backdrop-filter over the
    #F3F6FC page renders as an opaque grey slab, and dark-theme pastel pills
    fall to ~1.4:1 on it — a badge that says 'crit' and cannot be read."""
    login(client, admin_user_id(app))
    body = _panel(client)
    for token in ("#080d1a", "backdrop-filter", "rgba(30,41,59", "#8b5cf6", "#3b82f6"):
        assert token not in body, f"dark-theme token {token} in the panel"


def test_indentation_is_a_class_not_an_inline_style(app, client):
    """CLAIM: depth is expressed with ``bm-d<n>``.

    A per-row ``style="padding-left:…"`` renders identically today and stops
    working the day this console's CSP drops ``unsafe-inline`` from
    ``style-src`` — at which point the entire tree collapses to one column and
    nothing in the test suite notices.

    This used to assert that the whole fragment contained no ``style=`` at
    all. That is wider than the claim above, and the difference matters: a
    ``style=`` that declares only a *custom property* WITH a stylesheet
    fallback degrades to the fallback under a strict CSP, whereas a
    ``padding-left`` degrades to a flat list. The narrowed assertion below is
    the claim; :func:`test_a_style_attribute_may_only_carry_a_custom_property`
    keeps the rest of the ground the old one covered."""
    _appl(app, "fw-deep2", zone="internal", line="P", department="WAF/LB")
    login(client, admin_user_id(app))
    body = _panel(client)
    assert "bm-d2" in body
    for row in re.findall(r"<div class=\"bm-row[^>]*>", body):
        assert "style=" not in row, f"an inline style crept into a row: {row}"


def test_a_style_attribute_may_only_carry_a_custom_property(app, client):
    """CLAIM: nothing in this fragment expresses LAYOUT inline.

    The panel is allowed exactly one shape of inline style — a ``--bm-*``
    declaration that hands the stylesheet a colour it cannot know at build
    time. Two conditions, and dropping either brings back what the old
    fragment-wide ban was really guarding:

    *   the declaration is a custom property, so a CSP that refuses it removes
        a colour and not a rule;
    *   the stylesheet reads it through ``var(--x, fallback)``, so the removed
        colour has a defined replacement rather than an unset one.
    """
    login(client, admin_user_id(app))
    body = _panel(client)
    for decls in re.findall(r'style="([^"]*)"', body):
        for decl in filter(None, (d.strip() for d in decls.split(";"))):
            prop = decl.split(":", 1)[0].strip()
            assert prop.startswith("--bm-"), (
                f"inline style {decl!r} is not a bookmarks custom property")
    import os
    css_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "app/static/css/fortiweb.css")
    css = open(css_path, encoding="utf-8").read()
    for prop in set(re.findall(r"(--bm-[a-z-]+)\s*:", body)):
        assert re.search(re.escape(prop) + r"\s*,", css), (
            f"{prop} is read without a fallback — a CSP that strips it would "
            f"leave the property unset, not defaulted")


def test_the_rail_is_on_every_page_and_starts_closed(app, client):
    """CLAIM: the rail ships in base.html, collapsed.

    Open-by-default on a hundred-device fleet is a wall of text over the page
    the operator actually navigated to."""
    login(client, admin_user_id(app))
    body = client.get("/", follow_redirects=True).get_data(as_text=True)
    assert 'id="fw-bookmarks"' in body
    assert "data-turbo-permanent" in body.split('id="fw-bookmarks"')[1][:400]
    assert "bm-open" not in body.split("<script")[0]


def test_the_rail_is_not_rendered_without_an_authenticated_user(app):
    """CLAIM: base.html itself gates the rail on an authenticated user.

    The obvious version of this guard — fetch ``/`` logged out and assert the
    rail is absent — passed against a base.html with the gate DELETED, because
    ``auth/login.html`` does not extend base.html at all, so the anonymous
    request never reaches the branch. It measured the redirect, not the rule.
    Rendering the template anonymously is not possible either, and that is a
    finding rather than an obstacle: base.html calls ``current_user.can(...)``
    unconditionally at line ~253, so it raises for an anonymous user before it
    ever reaches the rail. The gate is therefore **defensive, not load-bearing**
    — no anonymous request can reach this template today. The guard that
    remains honest is over the template SOURCE: the rail must sit inside a
    conditional that tests authentication, so the day somebody makes base.html
    renderable to visitors, the rail does not come along."""
    src = open(os.path.join(app.root_path, "templates", "base.html"),
               encoding="utf-8").read()
    before = src.split('id="fw-bookmarks"')[0]
    guard = before.rsplit("{% if ", 1)[1].split("%}")[0]
    assert "current_user" in guard and "is_authenticated" in guard, \
        f"the rail's nearest enclosing condition does not test auth: {guard!r}"


def test_an_anonymous_page_has_no_rail(app, client):
    """CLAIM: and the same holds end to end, through the login redirect."""
    body = client.get("/", follow_redirects=True).get_data(as_text=True)
    assert 'id="fw-bookmarks"' not in body


def test_the_bookmarks_stylesheet_stays_light(app):
    """CLAIM: the RAIL'S OWN CSS carries no dark-theme tokens.

    The panel-body guard above can never see this: a stylesheet is not in the
    fragment it styles. That gap is how the grey Service Monitor cards shipped
    — the templates were clean and the CSS was not. This product has no dark
    mode; a slate row on the #F3F6FC panel renders as an opaque grey slab."""
    css = open(os.path.join(app.root_path, "static", "css", "fortiweb.css"),
               encoding="utf-8").read()
    assert "BOOKMARKS RAIL" in css
    # The comments EXPLAINING the rule name every token the rule forbids, and
    # the section marker itself lives INSIDE one of them. An assertion over raw
    # text matches its own rationale and fails against a perfectly light
    # stylesheet. Start after the section banner closes, then drop the
    # remaining comments, then assert on what actually ships.
    block = css[css.index("*/", css.index("BOOKMARKS RAIL")) + 2:]
    block = re.sub(r"/\*.*?\*/", "", block, flags=re.S)
    for token in ("#080d1a", "backdrop-filter", "rgba(30,41,59", "#8b5cf6",
                  "#3b82f6", "rgba(15,23,42"):
        assert token not in block, f"dark-theme token {token} in the rail stylesheet"
