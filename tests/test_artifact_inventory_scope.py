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

import re

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


def _stand_on(client, app, appliance_id):
    """Log in AND stand on a device.

    The artifact pages take their (device, ADOM) from the session, the way
    Backups and Server Objects do; a logged-in client with no device chosen is
    sent to the Architecture map instead of being shown the fleet. ``g`` is
    cleared because ``current_appliance()`` memoises there and the ``ctx``
    fixture keeps ONE app context open across every request in a test.
    """
    from flask import g

    from tests.conftest import admin_user_id, login

    login(client, admin_user_id(app))
    with client.session_transaction() as sess:
        sess["appliance_id"] = appliance_id
    g.__dict__.pop("_current_appliance", None)


def _rows(kind="wsdl", name="sch-s"):
    from app.models_artifacts import WafArtifact
    return WafArtifact.query.filter_by(kind=kind, name=name).all()


def test_a_save_on_a_shared_copy_without_an_answer_writes_nothing(app, client, ctx):
    """NOT saved, and said out loud. Picking a default here is the whole
    defect — "all" would edit devices the operator never named."""
    from tests.conftest import admin_user_id, login

    prod, _dev = _shared_fixture()
    before = len(_rows())
    _stand_on(client, app, prod.id)
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

    prod, _dev = _shared_fixture()
    _stand_on(client, app, prod.id)
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
    _stand_on(client, app, prod.id)
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
    ever be served — and it silently shadows whatever that box does read.

    The rule is unchanged; where it is ENFORCED moved. ``only`` now forks to
    the pair the page stands on, so a posted ``only_appliance_id`` is not
    validated — it is ignored, and the stranger is refused by standing on it.
    Both halves are asserted here: a field that is ignored quietly is how a
    control keeps writing to a device nobody named.
    """
    prod, _dev = _shared_fixture()
    stranger = _appl("fw6@root", "192.0.2.6", "root")

    before = len(_rows())
    _stand_on(client, app, stranger.id)
    r = client.post("/artifacts/save",
                    data={"kind": "wsdl", "name": "sch-s", "appliance_id": "",
                          "scope_mode": "only", "content": "<nope/>"},
                    follow_redirects=True)
    assert "Not saved" in r.get_data(as_text=True)
    assert len(_rows()) == before


def test_only_ignores_a_destination_named_by_the_form(app, client, ctx):
    """The other half of the same rule. A field that is ignored QUIETLY is how
    a control keeps writing to a device nobody named, so the fork is asserted
    to land on the pair the page stands on — not on the one posted.

    (Separate test on purpose: the fork it creates makes the library copy
    unshared, so the refusal above could not follow it in one body.)
    """
    prod, _dev = _shared_fixture()
    stranger = _appl("fw7@root", "192.0.2.7", "root")

    _stand_on(client, app, prod.id)
    client.post("/artifacts/save",
                data={"kind": "wsdl", "name": "sch-s", "appliance_id": "",
                      "scope_mode": "only",
                      "only_appliance_id": str(stranger.id),
                      "content": "<nope/>"},
                follow_redirects=True)

    assert [r for r in _rows() if r.appliance_id == stranger.id] == [], (
        "the form named the fork's destination and got it")
    assert [r for r in _rows() if r.appliance_id == prod.id], (
        "the fork did not land on the pair the page stands on")


def test_an_unshared_save_still_needs_no_answer(app, client, ctx):
    """Backwards compatibility, and the reason the refusal is not simply "ask
    always": the manage page's author form posts a brand-new object with no
    scope_mode, and it must keep working."""
    from tests.conftest import admin_user_id, login
    from app.services import waf_artifacts as wa

    _stand_on(client, app, _appl("fwN@prod", "192.0.2.10", "adom_prod").id)
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


def _visible(html: str) -> str:
    """The text a reader SEES — every tag (and therefore every attribute)
    stripped.

    The management address is still carried as a ``title=``, which is right: it
    is what an operator types into a browser. A guard that greps the raw markup
    therefore cannot tell "the row is labelled 192.0.2.7" from "the row is
    labelled fw7 and its address is one hover away" — the two readings are
    opposite and the whole complaint was about the first one.
    """
    return re.sub(r"<[^>]+>", " ", html)


def test_a_row_names_the_DEVICE_not_its_management_address(app, client, ctx):
    """The chassis address is not the device.

    One FortiWeb at 192.0.2.7 carries four ADOM rows, so its IP names none of
    them; ``appliance_name_parts`` is the product's one answer to "what is this
    device called" and every other per-device page already reads it. The
    address stays reachable on hover.
    """
    from tests.conftest import admin_user_id, login

    prod = _appl("fw7@prod", "192.0.2.7", "adom_prod")
    _put("wsdl", "sch-r", "<x/>", appliance_id=prod.id)
    _stand_on(client, app, prod.id)
    table = _held_table(client.get("/artifacts/inventory").get_data(as_text=True))
    assert "fw7@prod" in _visible(table), "the device NAME is not on the row"
    assert "adom_prod" in _visible(table), "the ADOM is not on the row"
    assert "192.0.2.7" not in _visible(table), \
        "the management address is being printed AS the device"
    # …and it is still one hover away, which is the half a plain deletion loses.
    assert 'title="192.0.2.7"' in table


def test_there_is_no_used_on_column_only_a_count(app, client, ctx):
    """Device and ADOM are the page, so they cannot also be a column.

    ``_narrow()`` drops every edge belonging to another pair before a figure is
    computed, so a "used on (device / ADOM)" column could only ever repeat the
    pair already printed in the banner and in this row's own two cells — and
    its empty state, "no known user", read as a statement about the fleet when
    it only ever meant "no walked policy OF THIS PAIR names it". What is left
    is the count, which is the part that varies.
    """
    from tests.conftest import admin_user_id, login

    prod = _appl("fw8@prod", "192.0.2.8", "adom_prod")
    _put("wsdl", "sch-u", "<x/>")
    _ref(prod.id, "pol-secret-name", "wsdl", "sch-u", wpp="wpp-secret-name")
    _stand_on(client, app, prod.id)
    html = client.get("/artifacts/inventory").get_data(as_text=True)
    table = _held_table(html)
    assert "Used on" not in html, "the redundant location column is back"
    assert "no known user" not in _visible(table), \
        "the orphan wording that was read as a fleet-wide claim is back"
    # The count of THIS pair's policies is what the column became.
    cell = table[table.index("data-policies-cell"):]
    cell = cell[:cell.index("</td>")]
    assert ">1<" in cell, "the policy count for this pair is not on the row"
    # The detail behind the count stays one click away, never on this list.
    assert "pol-secret-name" not in table
    assert "wpp-secret-name" not in table


def test_a_zero_count_does_not_claim_nobody_uses_it(app, client, ctx):
    """An object no WALKED policy names is not an object nothing uses.

    The old wording ("no known user") was the reported reading; the badge that
    replaced it says zero and explains on hover that an unwalked policy names
    nothing.
    """
    from tests.conftest import admin_user_id, login

    prod = _appl("fwZ@prod", "192.0.2.12", "adom_prod")
    _put("wsdl", "sch-orphan", "<x/>", appliance_id=prod.id)
    _stand_on(client, app, prod.id)
    table = _held_table(client.get("/artifacts/inventory").get_data(as_text=True))
    cell = table[table.index("data-policies-cell"):]
    cell = cell[:cell.index("</td>")]
    assert ">0<" in cell
    assert "not proof" in cell, "the zero is stated as a fact about the fleet"


def test_the_eye_link_carries_the_scope_and_the_way_back(app, client, ctx):
    """Without the scope the object page opens whichever version sorts first —
    under one name that can be a different file."""
    from tests.conftest import admin_user_id, login

    prod = _appl("fw9@prod", "192.0.2.9", "adom_prod")
    _put("wsdl", "sch-eye", "<x/>", appliance_id=prod.id)
    _stand_on(client, app, prod.id)
    table = _held_table(
        client.get("/artifacts/inventory?kind=wsdl").get_data(as_text=True))
    # The EYE's own anchor, not the row. The object name in the first column
    # links to the same place, so a row-wide grep would pass with the eye
    # deleted — which is the control this guard exists to fail.
    at = table.index("data-eye")
    eye = table[table.rindex("<a ", 0, at):table.index("</a>", at)]
    assert "bi-eye" in eye
    assert "/artifacts/object/wsdl/sch-eye" in eye
    assert "back=" in eye
    #: The scope used to be threaded through this href. It is the session's
    #: now, so what matters is where the link LANDS, not what it carries.
    href = re.search(r'href="([^"]+)"', eye).group(1)
    landed = client.get(href.replace("&amp;", "&"),
                        follow_redirects=True).get_data(as_text=True)
    assert "sch-eye" in landed


def test_each_add_verb_has_its_OWN_button_and_dialog(app, client, ctx):
    """Three verbs, three buttons, three dialogs.

    They differ in what they touch — upload and author write only SATOM,
    capture REACHES OUT to a live appliance — and a single dialog put all three
    side by side, leaving the operator to notice which column contacts a
    device. Each still posts to the SAME endpoint the retired manage page used:
    a modal-flavoured second set of routes is how the copy WITHOUT the
    empty-body refusal stores an artifact that pushes as -7694.
    """
    from tests.conftest import admin_user_id, login

    _stand_on(client, app, _appl("fwM@prod", "192.0.2.11", "adom_prod").id)
    html = client.get("/artifacts/inventory").get_data(as_text=True)
    assert 'id="artAddModal"' not in html, "the one-dialog-for-three-verbs is back"
    for modal, verb, action in (("artUploadModal", "upload", "/artifacts/upload"),
                                ("artAuthorModal", "author", "/artifacts/save"),
                                ("artCaptureModal", "capture", "/artifacts/capture")):
        assert 'id="%s"' % modal in html, modal
        assert 'data-bs-target="#%s"' % modal in html, modal
        assert 'data-add-verb="%s"' % verb in html, verb
        assert 'action="%s"' % action in html, action
    # A button an operator cannot read is a guess, and one of these contacts a
    # live appliance.
    head = html[html.index('data-add-verb="upload"'):]
    head = head[:head.index("</div>")]
    assert "title=" in head


def test_the_page_no_longer_links_the_duplicate_manage_page(app, client, ctx):
    """/artifacts/manage was a second list of these rows with the same verbs.

    Two pages answering one question is how a scope gate, a filter or a
    validation gets fixed on one of them; it was removed rather than kept in
    sync, and the endpoint is gone — so a link to it would be a 500 at
    url_for(), not a dead link.
    """
    from tests.conftest import admin_user_id, login

    _stand_on(client, app, _appl("fwD@prod", "192.0.2.13", "adom_prod").id)
    html = client.get("/artifacts/inventory").get_data(as_text=True)
    assert "/artifacts/manage" not in html
    assert client.get("/artifacts/manage").status_code == 404


# --------------------------------------------------------------------------- #
#  /artifacts/object — the impact panel and the back button                     #
# --------------------------------------------------------------------------- #
def test_the_object_page_names_every_pair_a_save_would_reach(app, client, ctx):
    from tests.conftest import admin_user_id, login

    prod, _dev = _shared_fixture()
    _stand_on(client, app, prod.id)
    html = client.get("/artifacts/object/wsdl/sch-s").get_data(as_text=True)
    assert 'data-scope-choice' in html, "no choice offered on a shared copy"
    assert 'value="all"' in html and 'value="only"' in html
    assert "adom_prod" in html and "adom_dev" in html


def test_an_unshared_object_page_offers_no_choice(app, client, ctx):
    """Control: the choice appears BECAUSE the copy is shared, not on every
    editable object."""
    from tests.conftest import admin_user_id, login

    _put("wsdl", "sch-solo", "<x/>")
    _stand_on(client, app, _appl("fwS@prod", "192.0.2.12", "adom_prod").id)
    html = client.get("/artifacts/object/wsdl/sch-solo").get_data(as_text=True)
    assert "data-scope-choice" not in html
    assert "data-scope-note" in html


def test_back_honours_a_local_path_and_refuses_an_offsite_one(app, client, ctx):
    """``//host`` is protocol-relative: it looks local in the template and
    sends the operator off this appliance."""
    from tests.conftest import admin_user_id, login

    _put("wsdl", "sch-back", "<x/>")
    _stand_on(client, app, _appl("fwB@prod", "192.0.2.13", "adom_prod").id)
    good = client.get("/artifacts/object/wsdl/sch-back"
                      "?back=%2Fartifacts%2Finventory%3Fkind%3Dwsdl"
                      ).get_data(as_text=True)
    assert 'href="/artifacts/inventory?kind=wsdl"' in good
    bad = client.get("/artifacts/object/wsdl/sch-back"
                     "?back=%2F%2Fevil.example%2Fx").get_data(as_text=True)
    assert "evil.example" not in bad

# --------------------------------------------------------------------------- #
#  The device NAME, on every page of the blueprint                              #
# --------------------------------------------------------------------------- #
def test_no_artifact_page_labels_the_scope_with_its_IP(app, client, ctx):
    """One guard per PAGE, because the label is written per template.

    The scope label was ``host or name`` in five places and the service layer
    computed it correctly the whole time — the same shape as every artifact
    defect reported so far: the calculation was right and the RENDER was what
    lied. A guard over the service would have passed while all five pages
    printed an address.

    Attributes are stripped before asserting: the address stays as a ``title=``
    on purpose (it is what an operator types into a browser), and the raw
    markup cannot distinguish "labelled 192.0.2.20" from "labelled fwLBL and its
    address is one hover away" — opposite readings, and the first one is the
    complaint.
    """
    import re as _re

    appl = _appl("fwLBL@prod", "192.0.2.20", "adom_prod")
    _put("wsdl", "sch-lbl", "<x/>", appliance_id=appl.id)
    _ref(appl.id, "pol-lbl", "wsdl", "sch-lbl")
    _stand_on(client, app, appl.id)

    pages = {
        "/artifacts/": None,
        "/artifacts/inventory": None,
        "/artifacts/audit": None,
        "/artifacts/object/wsdl/sch-lbl": None,
    }
    for path in list(pages):
        resp = client.get(path)
        assert resp.status_code == 200, "%s -> %s" % (path, resp.status_code)
        html = resp.get_data(as_text=True)
        visible = _re.sub(r"<[^>]+>", " ", html)
        assert "192.0.2.20" not in visible, (
            "%s prints the management address as the device" % path)
        assert "fwLBL" in visible, "%s does not name the device at all" % path
        # …and the address is still one hover away on the pages that scope.
        pages[path] = 'title="192.0.2.20"' in html
    assert pages["/artifacts/inventory"], \
        "the inventory dropped the address instead of moving it to the hover"


def test_a_picker_labels_its_option_with_the_device_name(app, client, ctx):
    """The half three earlier rounds of guards could not see: they stripped
    ``<select>`` before asserting, so the fleet — and then the address —
    survived inside the controls while six guards reported green."""
    import re as _re

    appl = _appl("fwSEL@prod", "192.0.2.21", "adom_prod")
    _stand_on(client, app, appl.id)
    html = client.get("/artifacts/inventory").get_data(as_text=True)

    opts = _re.findall(r"<option\b[^>]*>(.*?)</option>", html, _re.S)
    assert opts, "no picker at all — the guard would pass vacuously"
    named = [o for o in opts if "fwSEL" in o]
    assert named, "no picker offers the device by name"
    for o in opts:
        assert "192.0.2.21" not in o, "a picker option is labelled with the IP"
