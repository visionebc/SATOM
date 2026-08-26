"""Guards: the /artifacts/* routes that name their target by ID or by PATH.

The round before this one made the session's (device, ADOM) the universe of the
four rendered pages and gated the form verbs that carry an ``appliance_id``.
What it could not gate is the half of the blueprint where the device is never
mentioned in the request at all:

* ``/blob/<id>``, ``/raw/<id>``, ``delete`` and ``push`` name a stored VERSION
  by primary key. ``object_page`` stopped listing other pairs' versions, but a
  row that is merely unlisted is decoration — the ids are consecutive integers
  and the routes still answered for every one of them, including ``delete``.
* ``/api/list``, ``/api/refs`` and ``/api/coverage/<appliance_id>/<policy>``
  are the same pages with the HTML stripped off, and all three answered for the
  whole store. The last one takes the scope in the PATH: it was the one place
  where any device in the fleet could simply be typed.

Fixture shape is deliberate (and shared with test_artifact_session_scope):
prod and dev are mirror images of ONE chassis — same counts, disjoint names —
so no guard here can pass merely because a number changed.
"""
from __future__ import annotations

import re
from datetime import datetime

import pytest

from tests.conftest import admin_user_id, login

CHASSIS = "192.0.2.1"
OTHER = "192.0.2.2"


@pytest.fixture()
def ctx(app, tmp_path, monkeypatch):
    monkeypatch.setenv("SATOM_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    with app.app_context():
        from app import db
        yield db


def _appl(name, host, vdom):
    from app import db
    from app.models import Appliance

    row = Appliance(name=name, kind="fortiweb", host=host, port=443,
                    username="u", password_enc="x", vdom=vdom)
    db.session.add(row)
    db.session.commit()
    return row


def _ref(aid, policy, kind, name, wpp="wpp-x"):
    from app import db
    from app.models_artifact_refs import WafArtifactRef

    now = datetime.utcnow()
    db.session.add(WafArtifactRef(appliance_id=aid, policy_mkey=policy,
                                  kind=kind, name=name, wpp_mkey=wpp, urn="",
                                  derived_from="test", first_seen_at=now,
                                  seen_at=now))
    db.session.commit()


def _put(kind, name, body, appliance_id=None):
    from app.services import waf_artifacts as wa
    wa.put(kind, name, body.encode("utf-8"), appliance_id=appliance_id,
           source="uploaded")


def _row(kind, name, appliance_id):
    """The newest stored version of one copy — what a row-addressed URL names."""
    from app.models_artifacts import WafArtifact
    return (WafArtifact.query
            .filter_by(kind=kind, name=name, appliance_id=appliance_id)
            .order_by(WafArtifact.id.desc()).first())


def _fleet():
    """Two ADOMs of one chassis + a second chassis, plus one SHARED copy.

    ``sch-shared`` is library-wide and both ADOMs' policies walk to it: that is
    the only shape in which the "all / only this pair" fork question appears.
    """
    prod = _appl("fw@prod", CHASSIS, "adom_prod")
    dev = _appl("fw@dev", CHASSIS, "adom_dev")
    other = _appl("fw2@root", OTHER, "adom_root")

    for appl, tag in ((prod, "prod"), (dev, "dev"), (other, "other")):
        _put("wsdl", "sch-%s-1" % tag, "<x/>", appliance_id=appl.id)
        _put("wsdl", "sch-%s-2" % tag, "<x/>", appliance_id=appl.id)
        _ref(appl.id, "pol-%s" % tag, "wsdl", "sch-%s-1" % tag)
        _ref(appl.id, "pol-%s" % tag, "wsdl", "sch-%s-2" % tag)

    _put("wsdl", "sch-shared", "<shared/>")
    _ref(prod.id, "pol-prod", "wsdl", "sch-shared")
    _ref(dev.id, "pol-dev", "wsdl", "sch-shared")
    return prod, dev, other


def _stand_on(client, app, appliance_id):
    """Exactly what picking a device on the Architecture map leaves behind.

    ``g`` is cleared because ``current_appliance()`` memoises there and the
    ``ctx`` fixture holds ONE app context open across every request in a test.
    """
    from flask import g

    login(client, admin_user_id(app))
    with client.session_transaction() as sess:
        sess["appliance_id"] = appliance_id
    g.__dict__.pop("_current_appliance", None)


# ------------------------------------------------ row-addressed reads (bytes)

def test_the_bytes_of_another_pairs_version_are_not_downloadable_by_id(
        ctx, app, client):
    prod, dev, _o = _fleet()
    _stand_on(client, app, prod.id)
    theirs = _row("wsdl", "sch-dev-1", dev.id)

    r = client.get("/artifacts/blob/%d" % theirs.id)

    assert r.status_code == 404, (
        "a row this page refuses to LIST still served its bytes by id")


def test_the_bytes_of_another_pairs_version_are_not_viewable_by_id(
        ctx, app, client):
    prod, dev, _o = _fleet()
    _stand_on(client, app, prod.id)
    theirs = _row("wsdl", "sch-dev-2", dev.id)

    assert client.get("/artifacts/raw/%d" % theirs.id).status_code == 404


def test_control_this_pairs_own_and_library_versions_still_download(
        ctx, app, client):
    """The gate must not be a wall: the pair's own copies AND the library-wide
    bucket it reads are exactly what ``resolve()`` serves it."""
    prod, _d, _o = _fleet()
    _stand_on(client, app, prod.id)

    mine = _row("wsdl", "sch-prod-1", prod.id)
    shared = _row("wsdl", "sch-shared", None)

    assert client.get("/artifacts/blob/%d" % mine.id).status_code == 200
    assert client.get("/artifacts/blob/%d" % shared.id).status_code == 200
    assert client.get("/artifacts/raw/%d" % shared.id).status_code == 200


# --------------------------------------------------------- the destructive one

def test_another_pairs_version_cannot_be_deleted_by_id(ctx, app, client):
    """The only destructive verb in the blueprint, and the only one whose whole
    target is a bare integer."""
    prod, dev, _o = _fleet()
    _stand_on(client, app, prod.id)
    theirs = _row("wsdl", "sch-dev-1", dev.id)

    client.post("/artifacts/delete", data={"id": str(theirs.id)})

    assert _row("wsdl", "sch-dev-1", dev.id) is not None, (
        "a version belonging to another device/ADOM was destroyed from a page "
        "that names this one")


def test_control_this_pairs_own_version_still_deletes(ctx, app, client):
    prod, _d, _o = _fleet()
    _stand_on(client, app, prod.id)
    mine = _row("wsdl", "sch-prod-1", prod.id)

    client.post("/artifacts/delete", data={"id": str(mine.id)})

    assert _row("wsdl", "sch-prod-1", prod.id) is None


# ------------------------------------------------------------- push, both ends
#
# The two guards that lived here (an off-scope ROW may not be pushed, and the
# control that this pair's own row still could) went with the route. Scoping a
# verb is the second-best answer to "this writes to a device"; not having the
# verb is the first, and content now reaches an appliance only as part of a
# clone that creates the object.
#
# What replaces them is `test_artifact_empty_content.py`'s assertion that the
# endpoint is unrouted — a scope test on a dead route would keep passing after
# somebody re-added an unscoped one under another name.


# ------------------------------------------------------------- the JSON feeds

def test_the_json_row_feed_is_the_same_universe_as_the_page(ctx, app, client):
    prod, _d, _o = _fleet()
    _stand_on(client, app, prod.id)

    data = client.get("/artifacts/api/list").get_json()

    names = sorted(r["name"] for r in data["rows"])
    assert names == ["sch-prod-1", "sch-prod-2", "sch-shared"], names
    assert data["stats"]["versions"] == len(data["rows"]), (
        "a store-wide total printed over a scoped list is the header/table "
        "contradiction this product already fixed once")
    assert data["scope"]["adom"] == "adom_prod"


def test_the_json_ref_feed_only_carries_this_pairs_edges(ctx, app, client):
    prod, dev, _o = _fleet()
    _stand_on(client, app, prod.id)

    data = client.get("/artifacts/api/refs").get_json()

    assert {r["appliance_id"] for r in data["refs"]} == {prod.id}
    assert data["stats"]["edges"] == len(data["refs"])

    one = client.get("/artifacts/api/refs?kind=wsdl&name=sch-shared").get_json()
    assert {r["appliance_id"] for r in one["refs"]} == {prod.id}, (
        "the shared copy's users on OTHER pairs were listed as this pair's")


def test_a_coverage_verdict_for_another_device_is_not_served(ctx, app, client):
    """The only route with the scope in its PATH."""
    prod, dev, _o = _fleet()
    _stand_on(client, app, prod.id)

    r = client.get("/artifacts/api/coverage/%d/pol-dev" % dev.id)
    assert r.status_code == 404

    mine = client.get("/artifacts/api/coverage/%d/pol-prod" % prod.id)
    assert mine.status_code == 200 and mine.get_json()["ok"] is True


def test_the_json_feeds_answer_409_with_no_device_chosen(ctx, app, client):
    """A redirect to /architecture renders as a parse error in a fetch(), which
    is why require_device_scope settled on 409 for JSON callers."""
    _fleet()
    login(client, admin_user_id(app))

    for path in ("/artifacts/api/list", "/artifacts/api/refs"):
        r = client.get(path)
        assert r.status_code == 409, path
        assert r.get_json()["ok"] is False


# ------------------------------------------------- the narrowing is in the SQL

def test_the_row_limit_cannot_eat_this_pairs_versions(ctx, app):
    """Narrowing the rows that came BACK lets another pair's newer versions
    fill the limit and the remainder gets reported as everything there is."""
    prod, _d, other = _fleet()
    from app.services import waf_artifacts as wa
    for i in range(6):
        _put("wsdl", "noise-%d" % i, "<n%d/>" % i, appliance_id=other.id)

    rows = wa.history(limit=3, scope_id=prod.id)

    assert {r["name"] for r in rows} == {"sch-prod-1", "sch-prod-2",
                                         "sch-shared"}


# ------------------------------------------------------------ the fork target

def test_the_fork_control_offers_no_device_but_the_one_we_stand_on(
        ctx, app, client):
    prod, _d, _o = _fleet()
    _stand_on(client, app, prod.id)

    html = client.get("/artifacts/object/wsdl/sch-shared").get_data(as_text=True)

    assert 'name="only_appliance_id"' not in html, (
        "the fork picker listed every affected pair — a control that writes to "
        "a device this page is not named for")
    block = re.search(r'data-fork-target[^>]*>(.*?)</div>', html, re.S)
    assert block, "the fork no longer says where it lands"
    assert "adom_prod" in block.group(1) and "adom_dev" not in block.group(1)


def test_a_fork_lands_on_the_session_pair_whatever_the_form_says(
        ctx, app, client):
    """The gate, not the UI: a POST carries whatever its author types."""
    prod, dev, _o = _fleet()
    _stand_on(client, app, prod.id)

    client.post("/artifacts/save",
                data={"kind": "wsdl", "name": "sch-shared", "appliance_id": "",
                      "content": "<forked/>", "scope_mode": "only",
                      "only_appliance_id": str(dev.id)})

    assert _row("wsdl", "sch-shared", dev.id) is None, (
        "the fork was scoped to a device the page is not standing on")
    assert _row("wsdl", "sch-shared", prod.id) is not None
    from app.services import waf_artifacts as wa
    assert wa.resolve("wsdl", "sch-shared", dev.id)[0] == b"<shared/>", (
        "the other pair now resolves to content forked from a page it was "
        "never on")


def test_a_fork_is_refused_when_no_policy_here_reads_the_copy(
        ctx, app, client):
    """A fork nothing resolves to is not harmless: it SHADOWS whatever this
    pair does read."""
    prod, dev, other = _fleet()
    # ``other``'s policies never walk to sch-shared — prod's and dev's do.
    _stand_on(client, app, other.id)

    client.post("/artifacts/save",
                data={"kind": "wsdl", "name": "sch-shared", "appliance_id": "",
                      "content": "<nope/>", "scope_mode": "only"})

    assert _row("wsdl", "sch-shared", other.id) is None


# ------------------------------------------------------------------- control

def test_control_the_two_adoms_are_indistinguishable_by_their_numbers(
        ctx, app, client):
    """If prod and dev stop being mirror images, every guard above can go green
    for the wrong reason."""
    prod, dev, _o = _fleet()
    from app.services import artifact_files as af, artifact_refs as ar

    held = {a.id: len([o for o in af.object_index() if o["appliance_id"] == a.id])
            for a in (prod, dev)}
    assert held[prod.id] == held[dev.id] == 2
    edges = ar.usage_index()
    assert len([r for v in edges.values() for r in v
                if r["appliance_id"] == prod.id]) == \
           len([r for v in edges.values() for r in v
                if r["appliance_id"] == dev.id])
