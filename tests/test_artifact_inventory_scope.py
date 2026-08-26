"""Guards for the inventory's (device, ADOM) columns and for copy-on-write.

Four asks, one round, and each of them has a silent failure mode:

  * the inventory prints the appliance NAME, which is unique per ADOM and
    therefore answers "which chassis, which ADOM" only for a reader who already
    knows the naming convention — the page renders perfectly either way;
  * the add-modal grows its own routes, and the copy that is not the one with
    the empty-body refusal quietly stores an artifact that pushes as ``-7694``;
  * the eye link drops the scope, so the object page opens whichever version
    happens to sort first — a different file under the same name;
  * and the one that costs content: a save on a library-wide copy that three
    ADOMs resolve to edits all three. Both other devices keep working, nothing
    fails, and the divergence surfaces the next time somebody diffs them.

The last is why :func:`services.artifact_files.scope_impact` is computed BEFORE
the write and the write refuses without an answer. A default would be the
defect in miniature: ``all`` edits devices nobody named, ``only`` quietly stops
a fleet-wide fix from reaching the fleet.

No device and no network. The blob store is redirected to a tmp dir, because a
test that writes into ``data/artifacts`` leaves the production tree holding
objects nobody uploaded.
"""
from __future__ import annotations

from datetime import datetime

import pytest


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

    row, _created = wa.put(kind, name, body.encode("utf-8"),
                           appliance_id=appliance_id, source="uploaded")
    return row


# --------------------------------------------------------------------------- #
#  scope_impact — WHO a save reaches                                            #
# --------------------------------------------------------------------------- #
def test_a_library_copy_two_adoms_read_is_shared(ctx):
    """The reported case. One file, two readers, and the page must say so."""
    from app.services import artifact_files as af

    prod = _appl("fw@prod", "192.0.2.1", "adom_prod")
    dev = _appl("fw@dev", "192.0.2.1", "adom_dev")
    _put("wsdl", "sch-a", "<one/>")
    _ref(prod.id, "pol-prod", "wsdl", "sch-a")
    _ref(dev.id, "pol-dev", "wsdl", "sch-a")

    out = af.scope_impact("wsdl", "sch-a", None)
    assert out["shared"] is True
    assert sorted(out["affected"]) == sorted([prod.id, dev.id])


def test_a_reader_holding_its_own_copy_is_not_affected_by_a_library_edit(ctx):
    """Grounded in resolve()'s search order, not in a rule restated here: a
    device that holds its own copy never reads the library one.

    Listing it as affected is not a harmless over-count — it pushes the
    operator into forking a copy to protect a box that was never at risk, and
    that fork then stops receiving the fleet-wide edits it still wanted."""
    from app.services import artifact_files as af

    prod = _appl("fw2@prod", "192.0.2.2", "adom_prod")
    dev = _appl("fw2@dev", "192.0.2.2", "adom_dev")
    _put("wsdl", "sch-b", "<library/>")
    _put("wsdl", "sch-b", "<devs-own/>", appliance_id=dev.id)
    _ref(prod.id, "pol-prod", "wsdl", "sch-b")
    _ref(dev.id, "pol-dev", "wsdl", "sch-b")

    out = af.scope_impact("wsdl", "sch-b", None)
    assert out["affected"] == [prod.id]
    assert out["others"] == [dev.id]
    assert out["shared"] is False


def test_positive_control_the_same_two_readers_without_an_own_copy_are_both_hit(ctx):
    """Control for the test above. Without it, "dev is excluded" would also be
    explained by an impact function that never finds anybody."""
    from app.services import artifact_files as af

    prod = _appl("fw3@prod", "192.0.2.3", "adom_prod")
    dev = _appl("fw3@dev", "192.0.2.3", "adom_dev")
    _put("wsdl", "sch-c", "<library/>")
    _ref(prod.id, "pol-prod", "wsdl", "sch-c")
    _ref(dev.id, "pol-dev", "wsdl", "sch-c")

    out = af.scope_impact("wsdl", "sch-c", None)
    assert sorted(out["affected"]) == sorted([prod.id, dev.id])
    assert out["shared"] is True


def test_a_scoped_copy_is_never_shared_however_many_boxes_use_the_name(ctx):
    """A copy scoped to one (device, ADOM) is served to that pair only. The
    other boxes name the same mkey and read something else entirely."""
    from app.services import artifact_files as af

    prod = _appl("fw4@prod", "192.0.2.4", "adom_prod")
    dev = _appl("fw4@dev", "192.0.2.4", "adom_dev")
    _put("wsdl", "sch-d", "<prods-own/>", appliance_id=prod.id)
    _ref(prod.id, "pol-prod", "wsdl", "sch-d")
    _ref(dev.id, "pol-dev", "wsdl", "sch-d")

    out = af.scope_impact("wsdl", "sch-d", prod.id)
    assert out["shared"] is False
    assert out["affected"] == [prod.id]
    assert out["others"] == [dev.id]


def test_an_object_no_walked_policy_names_is_not_shared(ctx):
    """"Nobody has walked a policy that names it" is not "one reader"."""
    from app.services import artifact_files as af

    _put("wsdl", "sch-e", "<lonely/>")
    out = af.scope_impact("wsdl", "sch-e", None)
    assert out["shared"] is False
    assert out["affected"] == []


# --------------------------------------------------------------------------- #
#  /artifacts/save — the refusal and the fork                                   #
# --------------------------------------------------------------------------- #
def _shared_fixture():
    """One library copy, two ADOMs of one chassis reading it."""
    prod = _appl("fw5@prod", "192.0.2.5", "adom_prod")
    dev = _appl("fw5@dev", "192.0.2.5", "adom_dev")
    _put("wsdl", "sch-s", "<original/>")
    _ref(prod.id, "pol-prod", "wsdl", "sch-s")
    _ref(dev.id, "pol-dev", "wsdl", "sch-s")
    return prod, dev


def _rows(kind="wsdl", name="sch-s"):
    from app.models_artifacts import WafArtifact
    return WafArtifact.query.filter_by(kind=kind, name=name).all()


def test_a_save_on_a_shared_copy_without_an_answer_writes_nothing(app, client, ctx):
    """NOT saved, and said out loud. Picking a default here is the whole
    defect — "all" would edit devices the operator never named."""
    from tests.conftest import admin_user_id, login

    _shared_fixture()
    before = len(_rows())
    login(client, admin_user_id(app))
    r = client.post("/artifacts/save",
                    data={"kind": "wsdl", "name": "sch-s",
                          "appliance_id": "", "content": "<changed/>"},
                    follow_redirects=True)
    body = r.get_data(as_text=True)
    assert "Not saved" in body
    assert len(_rows()) == before, "a version was minted despite the refusal"


def test_scope_mode_all_writes_one_new_version_of_the_shared_copy(app, client, ctx):
    from tests.conftest import admin_user_id, login
    from app.services import waf_artifacts as wa

    _shared_fixture()
    login(client, admin_user_id(app))
    client.post("/artifacts/save",
                data={"kind": "wsdl", "name": "sch-s", "appliance_id": "",
                      "scope_mode": "all", "content": "<changed/>"},
                follow_redirects=True)
    assert wa.load(wa.latest("wsdl", "sch-s", None).sha256) == b"<changed/>"
    # and no scoped copy was invented on the way
    assert [r.appliance_id for r in _rows()] == [None, None]


def test_scope_mode_only_forks_a_copy_and_leaves_the_shared_one_alone(
        app, client, ctx):
    """The ask, in one assertion pair: the pair that was edited reads the new
    content, and every other reader still reads exactly what it read before."""
    from tests.conftest import admin_user_id, login
    from app.services import waf_artifacts as wa

    prod, dev = _shared_fixture()
    login(client, admin_user_id(app))
    client.post("/artifacts/save",
                data={"kind": "wsdl", "name": "sch-s", "appliance_id": "",
                      "scope_mode": "only", "only_appliance_id": str(prod.id),
                      "content": "<only-for-prod/>"},
                follow_redirects=True)

    scoped = wa.latest("wsdl", "sch-s", prod.id)
    assert scoped is not None and scoped.appliance_id == prod.id
    assert wa.load(scoped.sha256) == b"<only-for-prod/>"
    # The shared copy is untouched — this is the half that makes it a FORK and
    # not an edit with an extra row.
    assert wa.load(wa.latest("wsdl", "sch-s", None).sha256) == b"<original/>"
    # dev still resolves to the shared copy, not to prod's fork.
    blob, _origin, err = wa.resolve("wsdl", "sch-s", dev.id)
    assert err == "" and blob == b"<original/>"


def test_only_refuses_a_pair_that_does_not_read_this_copy(app, client, ctx):
    """A fork scoped to a box that reads something else is a copy nobody will
    ever be served — and it silently shadows whatever that box does read."""
    from tests.conftest import admin_user_id, login

    _shared_fixture()
    stranger = _appl("fw6@root", "192.0.2.6", "root")
    before = len(_rows())
    login(client, admin_user_id(app))
    r = client.post("/artifacts/save",
                    data={"kind": "wsdl", "name": "sch-s", "appliance_id": "",
                          "scope_mode": "only",
                          "only_appliance_id": str(stranger.id),
                          "content": "<nope/>"},
                    follow_redirects=True)
    assert "Not saved" in r.get_data(as_text=True)
    assert len(_rows()) == before


def test_an_unshared_save_still_needs_no_answer(app, client, ctx):
    """Backwards compatibility, and the reason the refusal is not simply "ask
    always": the manage page's author form posts a brand-new object with no
    scope_mode, and it must keep working."""
    from tests.conftest import admin_user_id, login
    from app.services import waf_artifacts as wa

    login(client, admin_user_id(app))
    client.post("/artifacts/save",
                data={"kind": "wsdl", "name": "sch-new", "appliance_id": "",
                      "content": "<fresh/>"},
                follow_redirects=True)
    assert wa.latest("wsdl", "sch-new", None) is not None


# --------------------------------------------------------------------------- #
#  /artifacts/inventory — the columns, the modal, the eye                       #
# --------------------------------------------------------------------------- #
def _held_table(html: str) -> str:
    """Only the held-artifacts table.

    The page carries four tables and the coverage one legitimately prints
    policy and profile names; a grep over the whole document would match it and
    report the opposite of what it measured."""
    start = html.index("data-held-table")
    return html[start:html.index("</table>", start)]


def test_a_row_names_the_device_and_the_adom(app, client, ctx):
    from tests.conftest import admin_user_id, login

    prod = _appl("fw7@prod", "192.0.2.7", "adom_prod")
    _put("wsdl", "sch-r", "<x/>", appliance_id=prod.id)
    login(client, admin_user_id(app))
    table = _held_table(client.get("/artifacts/inventory").get_data(as_text=True))
    assert "192.0.2.7" in table, "the device (chassis) is not on the row"
    assert "adom_prod" in table, "the ADOM is not on the row"


def test_the_used_on_column_carries_pairs_not_policy_and_profile_names(
        app, client, ctx):
    """The ask was device and ADOM, and only those. Four lines of policy →
    profile per row pushed the one fact this page is read for off the edge;
    the detail is one click away on the object page."""
    from tests.conftest import admin_user_id, login

    prod = _appl("fw8@prod", "192.0.2.8", "adom_prod")
    _put("wsdl", "sch-u", "<x/>")
    _ref(prod.id, "pol-secret-name", "wsdl", "sch-u", wpp="wpp-secret-name")
    login(client, admin_user_id(app))
    table = _held_table(client.get("/artifacts/inventory").get_data(as_text=True))
    assert "192.0.2.8" in table and "adom_prod" in table
    assert "pol-secret-name" not in table
    assert "wpp-secret-name" not in table


def test_the_eye_link_carries_the_scope_and_the_way_back(app, client, ctx):
    """Without the scope the object page opens whichever version sorts first —
    under one name that can be a different file."""
    from tests.conftest import admin_user_id, login

    prod = _appl("fw9@prod", "192.0.2.9", "adom_prod")
    _put("wsdl", "sch-eye", "<x/>", appliance_id=prod.id)
    login(client, admin_user_id(app))
    table = _held_table(
        client.get("/artifacts/inventory?kind=wsdl").get_data(as_text=True))
    # The EYE's own anchor, not the row. The object name in the first column
    # links to the same place, so a row-wide grep would pass with the eye
    # deleted — which is the control this guard exists to fail.
    at = table.index("data-eye")
    eye = table[table.rindex("<a ", 0, at):table.index("</a>", at)]
    assert "bi-eye" in eye
    assert "/artifacts/object/wsdl/sch-eye" in eye
    assert "appl=%d" % prod.id in eye
    assert "back=" in eye


def test_the_add_modal_posts_to_the_three_real_verbs(app, client, ctx):
    """One set of routes, not a modal-flavoured second set: the copy that is
    not the one with the empty-body refusal stores an artifact that pushes as
    -7694."""
    from tests.conftest import admin_user_id, login

    login(client, admin_user_id(app))
    html = client.get("/artifacts/inventory").get_data(as_text=True)
    assert 'id="artAddModal"' in html
    assert 'data-bs-target="#artAddModal"' in html
    for action in ("/artifacts/upload", "/artifacts/save", "/artifacts/capture"):
        assert 'action="%s"' % action in html, action


# --------------------------------------------------------------------------- #
#  /artifacts/object — the impact panel and the back button                     #
# --------------------------------------------------------------------------- #
def test_the_object_page_names_every_pair_a_save_would_reach(app, client, ctx):
    from tests.conftest import admin_user_id, login

    _shared_fixture()
    login(client, admin_user_id(app))
    html = client.get("/artifacts/object/wsdl/sch-s").get_data(as_text=True)
    assert 'data-scope-choice' in html, "no choice offered on a shared copy"
    assert 'value="all"' in html and 'value="only"' in html
    assert "adom_prod" in html and "adom_dev" in html


def test_an_unshared_object_page_offers_no_choice(app, client, ctx):
    """Control: the choice appears BECAUSE the copy is shared, not on every
    editable object."""
    from tests.conftest import admin_user_id, login

    _put("wsdl", "sch-solo", "<x/>")
    login(client, admin_user_id(app))
    html = client.get("/artifacts/object/wsdl/sch-solo").get_data(as_text=True)
    assert "data-scope-choice" not in html
    assert "data-scope-note" in html


def test_back_honours_a_local_path_and_refuses_an_offsite_one(app, client, ctx):
    """``//host`` is protocol-relative: it looks local in the template and
    sends the operator off this appliance."""
    from tests.conftest import admin_user_id, login

    _put("wsdl", "sch-back", "<x/>")
    login(client, admin_user_id(app))
    good = client.get("/artifacts/object/wsdl/sch-back"
                      "?back=%2Fartifacts%2Finventory%3Fkind%3Dwsdl"
                      ).get_data(as_text=True)
    assert 'href="/artifacts/inventory?kind=wsdl"' in good
    bad = client.get("/artifacts/object/wsdl/sch-back"
                     "?back=%2F%2Fevil.example%2Fx").get_data(as_text=True)
    assert "evil.example" not in bad
