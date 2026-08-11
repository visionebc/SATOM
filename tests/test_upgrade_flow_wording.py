"""The bulk flow's prose has ONE author: Administration → Change Types.

Stage 2 of the Upgrade Flow used to write its own. The title box carried an
English placeholder compiled into the template, the reason box carried another,
and there was no rollback box at all — while the single-change form next door
proposed all three from ``services.cr_types``, an administrator's wording
winning per field.

Nothing failed. An administrator corrected "Firmware upgrade" to whatever their
change board actually calls it, the single change picked it up, and the bulk
one kept offering the compiled sentence. Two documents about the same work,
raised from the same console, disagreeing — and the one that disagreed was the
one covering forty appliances.

Three shapes are guarded here, and they are the same shape three times:

1. **A second author.** Any sentence this page composes itself is a sentence
   the Change Types page cannot correct.
2. **A narrower carbon copy.** The batched (wave) path must carry the SAME
   wording, rollback and document language as the single one. A field that
   simply is not posted comes out empty, and an empty rollback prints as a
   change with no rollback plan rather than as a bug.
3. **A proposal that cites evidence it does not have.** The per-device draft
   quotes one pre-flight run by id; this stage rests on N. Quoting one would
   put a sentence about a single box on a document covering the window.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import admin_user_id, login

REPO = Path(__file__).resolve().parents[1]
TEMPLATE = REPO / "app" / "templates" / "upgrade_flow" / "index.html"
ACTION = "upgrade"


# --------------------------------------------------------------------------- #
#  helpers                                                                      #
# --------------------------------------------------------------------------- #
def _mk_appliance(name, *, kind="fortiweb"):
    from app.extensions import db
    from app.models import Appliance

    a = Appliance(name=name, host=f"{name}.example.invalid", port=443,
                  kind=kind, username="admin")
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


def _override(*, key=ACTION, lang="en", **fields):
    """Write an administrator's wording exactly as the Change Types page does.

    Every field goes in ONE call because that is what the save handler does,
    and it matters: ``save_texts`` walks the whole field list and writes an
    empty string over anything the payload omits — a second call carrying one
    field silently blanks the first one's.
    """
    from app.services import cr_types

    cr_types.upsert(key, source_lang=lang, enabled=True, username="tester")
    cr_types.save_texts(key, fields, source_lang=lang, username="tester")


def _field(html, ident):
    """The value of the input, or the body of the textarea, with id ``ident``."""
    m = re.search(rf'id="{ident}"[^>]*value="([^"]*)"', html)
    if m:
        return m.group(1)
    m = re.search(rf'id="{ident}"[^>]*>(.*?)</textarea>', html, re.S)
    return m.group(1).strip() if m else ""


def _page(client, app):
    login(client, admin_user_id(app))
    resp = client.get("/web/upgrade-flow/")
    assert resp.status_code == 200
    return resp.get_data(as_text=True)


# =========================================================================== #
#  1. one author                                                               #
# =========================================================================== #
def test_the_title_offered_in_bulk_is_the_administrators(app, client):
    """The defect, stated: correct the wording once, both forms follow."""
    with app.app_context():
        _mk_appliance("word-fw")
        _override(draft_title="CAB-Wartung: Firmware {devices}")

    body = _page(client, app)
    assert "CAB-Wartung: Firmware" in _field(body, "uf-title"), \
        "the bulk form proposes a title the Change Types page cannot correct"


def test_reason_and_rollback_are_offered_and_come_from_the_change_type(app,
                                                                      client):
    """The rollback box did not exist here at all — a bulk change went out with
    an empty rollback plan and read as a change that has none."""
    with app.app_context():
        _mk_appliance("word-fw2")
        _override(draft_reason="Quarterly patch round agreed with the CAB.",
                  draft_rollback="Reboot to the previous partition.")

    body = _page(client, app)
    assert "Quarterly patch round" in _field(body, "uf-reason")
    assert "previous partition" in _field(body, "uf-rollback")


def test_the_template_composes_no_proposal_of_its_own(app):
    """A hard-coded placeholder is an author nobody can reach.

    Comments are stripped first: the paragraph that EXPLAINS this rule names
    the strings it bans, and asserting over it would fail against the fixed
    template — the eighth time that trap has been paid for in this repo.
    """
    text = re.sub(r"\{#.*?#\}", "", TEMPLATE.read_text(encoding="utf-8"),
                  flags=re.S)
    for banned in ("Firmware upgrade — maintenance window",
                   "Firmware upgrade — batched rollout",
                   "Why this window exists"):
        assert banned not in text, \
            f"the template still writes its own proposal: {banned}"
    assert "crdoc.drafts" in text, \
        "the page no longer reads the change type's wording at all"


def test_the_page_links_to_the_place_the_wording_is_edited(app, client):
    """Text an operator can see and cannot find the source of gets retyped by
    hand into the box, and then it really is authored twice."""
    body = _page(client, app)
    assert "/administration/change-types/upgrade" in body


# =========================================================================== #
#  2. the batched path is not the narrower one                                 #
# =========================================================================== #
def test_the_wave_form_carries_the_same_wording_without_scripting(app, client):
    """Rendered server-side into the wave form, not only mirrored by JS: with
    scripting off the batched path would otherwise post an empty title and be
    refused, or worse, post an empty reason and be accepted."""
    with app.app_context():
        _mk_appliance("word-fw3")
        _override(draft_title="Rollout {devices}",
                  draft_reason="Agreed at the change board.")

    body = _page(client, app)
    assert "Rollout" in _field(body, "uf-w-title")
    assert "Agreed at the change board." in _field(body, "uf-w-reason")
    assert _field(body, "uf-w-lang"), "the wave form posts no document language"


def test_the_document_language_chosen_in_the_profile_is_the_one_proposed(app,
                                                                        client):
    """The proposal and the hidden wave mirror must agree with each other AND
    with the radio. A page that reads in German while the batched path posts
    English produces a rollout whose documents are in two languages, and the
    only symptom is that somebody eventually cannot read one of them."""
    from app.services import cr_document, user_settings_store

    with app.app_context():
        _mk_appliance("lang-fw")
        uid = admin_user_id(app)
        codes = [code for code, _label in cr_document.document_langs()]
        other = next((c for c in codes if c != "en"), None)
        if other is None:
            pytest.skip("only one document language is available")
        user_settings_store.save_language(uid, other)
        expected = cr_document.draft_fields(ACTION, other)["title"]
        expected = expected.split(cr_document.DEVICES_TOKEN)[0].strip()

    body = _page(client, app)
    assert _field(body, "uf-w-lang") == other, \
        "the batched path posts a different language than the page shows"
    assert expected and expected in _field(body, "uf-title"), \
        "the proposal is not in the language the operator reads in"


def test_every_wave_keeps_the_reason_rollback_and_language(app, client):
    """Fields the wave route never forwarded came out empty on every change in
    the rollout, and an empty field prints as an absent decision."""
    from app.models import ChangeRequest

    with app.app_context():
        ids = [_mk_appliance(f"wvw-{i}").id for i in range(3)]

    login(client, admin_user_id(app))
    resp = client.post("/web/upgrade-flow/waves", data={
        "title": "Fleet 7.6.2", "wave_size": "1",
        "reason": "Agreed at the change board.",
        "rollback": "Reboot to the previous partition.",
        "doc_lang": "de",
        "device_ids": [str(i) for i in ids],
    }, follow_redirects=True)
    assert resp.status_code == 200

    with app.app_context():
        made = (ChangeRequest.query
                .filter(ChangeRequest.wave_group.isnot(None),
                        ChangeRequest.wave_group != "")
                .order_by(ChangeRequest.wave_index).all())
        assert len(made) == 3
        for cr in made:
            assert cr.reason == "Agreed at the change board.", \
                "a wave was raised with no reason"
            assert cr.rollback == "Reboot to the previous partition.", \
                "a wave was raised with no rollback plan"
            assert cr.doc_lang == "de", \
                "the wave document is not in the language that was chosen"


def test_a_wave_plan_without_a_title_creates_nothing(app, client):
    """The suffix alone is non-empty, so an untitled plan sails past the
    create path's own check and lands in the register as '— wave 1/3'."""
    from app.models import ChangeRequest

    with app.app_context():
        ids = [_mk_appliance(f"wvt-{i}").id for i in range(3)]
        before = ChangeRequest.query.count()

    login(client, admin_user_id(app))
    resp = client.post("/web/upgrade-flow/waves", data={
        "title": "   ", "wave_size": "1",
        "device_ids": [str(i) for i in ids],
    }, follow_redirects=True)
    assert resp.status_code == 200
    with app.app_context():
        assert ChangeRequest.query.count() == before, \
            "an untitled wave plan created changes anyway"


def test_a_long_title_never_costs_the_wave_marker(app, client):
    """'… — wave 3/6' is the only thing on the change list that tells two
    waves apart, and it is the end of the string a blind truncation cuts."""
    from app.models import ChangeRequest

    with app.app_context():
        ids = [_mk_appliance(f"wvl-{i}").id for i in range(3)]

    login(client, admin_user_id(app))
    client.post("/web/upgrade-flow/waves", data={
        "title": "F" * 260, "wave_size": "1",
        "device_ids": [str(i) for i in ids],
    }, follow_redirects=True)

    with app.app_context():
        made = (ChangeRequest.query
                .filter(ChangeRequest.wave_group.isnot(None),
                        ChangeRequest.wave_group != "")
                .order_by(ChangeRequest.wave_index).all())
        assert len(made) == 3
        for index, cr in enumerate(made, 1):
            assert len(cr.title) <= 200
            assert cr.title.endswith(f"wave {index}/3"), \
                f"the wave marker was truncated away: {cr.title[-20:]!r}"


# =========================================================================== #
#  3. the proposal cites only what this stage actually has                     #
# =========================================================================== #
def test_the_bulk_proposal_quotes_no_single_pre_flight_run(app, client):
    """The per-device draft names one run by id, timestamp and backup. This
    stage rests on N of them; quoting one describes a single box on a document
    that covers the window."""
    from app.extensions import db
    from app.models import UpgradePrep
    from datetime import datetime
    import json

    with app.app_context():
        a = _mk_appliance("cite-fw")
        prep = UpgradePrep(appliance_id=a.id, created_by="op", ok=True,
                           summary="backup ok",
                           result=json.dumps({"firmware": "7.6.8",
                                              "backup": {"ok": True,
                                                         "name": "cfg-1.bak"}}),
                           inventory=json.dumps([]),
                           created_at=datetime.utcnow())
        db.session.add(prep)
        db.session.commit()
        prep_id = prep.id

    body = _page(client, app)
    for ident in ("uf-reason", "uf-rollback", "uf-title"):
        value = _field(body, ident)
        assert f"#{prep_id}" not in value, \
            f"{ident} cites one pre-flight run on a change covering many"
        assert "cfg-1.bak" not in value, \
            f"{ident} names one device's backup as the rollback point"


def test_the_devices_placeholder_is_never_left_as_a_raw_token(app, client):
    """``{devices}`` reaching the box is a title that reads like a bug; an
    empty gap where the device names belong is a document about nothing."""
    from app.services import cr_document

    with app.app_context():
        _mk_appliance("tok-fw")

    body = _page(client, app)
    assert cr_document.DEVICES_TOKEN not in _field(body, "uf-title")
    assert cr_document.DEVICES_TOKEN not in _field(body, "uf-w-title")


# =========================================================================== #
#  4. a type switched off is said, not discovered at submit time               #
# =========================================================================== #
def test_a_disabled_change_type_is_reported_instead_of_a_form_that_refuses(app,
                                                                          client):
    """``create_change_request`` rejects an action that is not on offer. Left
    unsaid here, the operator learns it after the pre-flight sweep — the
    expensive half — with the form filled in."""
    from app.services import cr_types

    with app.app_context():
        _mk_appliance("off-fw")
        cr_types.upsert(ACTION, source_lang="en", enabled=False,
                        username="tester")

    body = _page(client, app)
    assert 'id="uf-cr"' not in body, \
        "the form is still offered for a change type that cannot be raised"
    assert "Change Types" in body, \
        "the page does not say where the change type was switched off"
