"""New change request: ask the language, then the type, then propose the prose.

Requested 2026-08-10: on ``/change-requests/new`` the form should ask *first*
which language the document is in, *then* what kind of change it is, and fill in
title, reason, rollback plan, recipients and owner by itself.

The defect class this guards is the one with no exit code: **a proposal that is
plausible and wrong**. Nothing raises when a German change request is drafted
with English prose, when the proposed title silently drops the device it is
about, when the "reason" turns out to be a verbatim copy of the boilerplate the
document already prints two sections earlier, or when a backup filename is
quoted in a rollback plan for a backup that never completed. Every one of those
renders, saves, prints and gets signed.

Deliberately NOT guarded as a default: the affected devices and the maintenance
window. Those are decisions. A guessed window is worse than an empty one.
"""
from __future__ import annotations

import io
import json
import os
import re

import pytest

from app.models import Appliance, db
from app.services import cr_document as doc
from app.views.change_requests import cr_action_keys
from tests.conftest import admin_user_id, login

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TPL_PATH = os.path.join(REPO, "app", "templates", "change_requests", "form.html")

LANG_CODES = tuple(code for code, _label in doc.document_langs())

RESULT_FIXTURE = {
    "appliance": "draftbox",
    "firmware": "FortiWeb-VM 7.6.8,build1234",
    "backup": {"ok": True, "name": "draftbox-20260810-004500.conf", "stored": True},
    "health": {"ok": True, "text": "CPU 4%  MEM 31%"},
}
INVENTORY_FIXTURE = [{"policy": "www_prod"}, {"policy": "api_prod"}]


@pytest.fixture(scope="module")
def tpl():
    return io.open(TPL_PATH, encoding="utf-8").read()


def _flat(text: str) -> str:
    """Whitespace collapsed. The catalogue is hard-wrapped in the source, so a
    substring assertion on any phrase that crosses a line break fails against
    perfectly correct text (safeguards 7f)."""
    return re.sub(r"\s+", " ", str(text or "")).strip()


# --------------------------------------------------------------------------- #
#  The catalogue                                                                #
# --------------------------------------------------------------------------- #
def test_every_change_controlled_action_has_a_proposal_in_both_languages():
    """A missing entry does not fail: it renders an EMPTY title on a required
    field, and the operator types whatever unblocks the form."""
    for action in sorted(cr_action_keys()):
        for code in LANG_CODES:
            draft = doc.draft_fields(action, code)
            assert set(draft) == set(doc.DRAFT_FIELDS), (action, code)
            for key, value in draft.items():
                assert _flat(value), "%s/%s/%s is empty" % (action, code, key)


def test_the_catalogue_is_not_half_translated():
    """The failure mode this mirrors is a German document with one English
    paragraph in the middle of it -- which reads as a typo, not as a bug."""
    blocks = doc._DRAFT
    assert set(blocks) == set(LANG_CODES)
    reference = set(blocks[LANG_CODES[0]])
    for code in LANG_CODES:
        assert set(blocks[code]) == reference, "language %s is missing keys" % code


#: Fixed vocabulary that only ever appears in one language's proposals. Merely
#: asserting "the two differ" is not enough: half a sentence translated still
#: differs, and reads as a typo rather than as the bug it is.
_ONLY_IN = {
    "de": ("Wartungsfenster", "Geplante Durchführung", "Bei Fehlschlag"),
    "en": ("maintenance window", "Planned execution", "On failure"),
}

_PREP_CTX = {"id": 3, "at": "2026-08-10 09:12 CEST", "ok": False, "services": 5,
             "firmware": "7.6.8", "backup": "box-1.conf"}


def test_german_is_actually_german():
    """Falling back to English would satisfy every other guard here. Checked
    with AND without a cited run: the two share no sentence, so translating one
    of them proves nothing about the other."""
    for action in sorted(cr_action_keys()):
        for ctx in (None, _PREP_CTX):
            de = doc.draft_fields(action, "de", prep=ctx)
            en = doc.draft_fields(action, "en", prep=ctx)
            for key in doc.DRAFT_FIELDS:
                assert _flat(de[key]) != _flat(en[key]), (
                    "%s/%s did not translate" % (action, key))


def test_no_proposal_speaks_the_other_language():
    """One English paragraph inside a German change request is the failure this
    catches, and it is the one nothing else can see."""
    for action in sorted(cr_action_keys()):
        for code in LANG_CODES:
            other = "en" if code == "de" else "de"
            for ctx in (None, _PREP_CTX):
                text = " ".join(_flat(v) for v in
                                doc.draft_fields(action, code, prep=ctx).values())
                for marker in _ONLY_IN[other]:
                    assert marker not in text, (
                        "%s/%s carries %s prose: %r" % (action, code, other, marker))


def test_every_proposed_field_carries_the_device_token():
    """The names are substituted by the page. A field that lost its token stops
    naming the devices the change is about, and keeps rendering."""
    for action in sorted(cr_action_keys()):
        for code in LANG_CODES:
            for key, value in doc.draft_fields(action, code).items():
                assert doc.DEVICES_TOKEN in value, "%s/%s/%s" % (action, code, key)


def test_the_proposal_is_not_a_copy_of_the_printed_boilerplate():
    """The rendered document ALREADY prints the action's standard justification
    and standard rollback steps, and prints the change's own text beside them.
    Copying the profile into these fields prints the same paragraph twice and
    makes the operator's statement indistinguishable from boilerplate."""
    for action in sorted(cr_action_keys()):
        for code in LANG_CODES:
            profile = doc._profile_text(action, code)
            draft = doc.draft_fields(action, code)
            for src, dst in (("justification", "reason"), ("rollback", "rollback")):
                prose = _flat(profile.get(src, ""))
                if len(prose) < 40:
                    continue
                assert prose not in _flat(draft[dst]), (
                    "%s/%s: the %s field is a copy of the profile prose"
                    % (action, code, dst))


def test_a_cited_pre_flight_run_is_quoted_with_its_facts():
    ctx = {"id": 7, "at": "2026-08-10 09:12 CEST", "ok": True, "services": 12,
           "firmware": "7.6.8", "backup": "draftbox-1.conf"}
    for code in LANG_CODES:
        reason = _flat(doc.draft_fields("upgrade", code, prep=ctx)["reason"])
        assert "#7" in reason
        assert "2026-08-10 09:12 CEST" in reason
        assert "12" in reason
        assert "7.6.8" in reason
        assert "draftbox-1.conf" in reason


def test_a_failed_verdict_is_never_read_as_a_pass():
    """The word is the only difference between evidence and its opposite."""
    for code in LANG_CODES:
        ok = _flat(doc.draft_fields("upgrade", code,
                                    prep={"id": 1, "at": "x", "ok": True,
                                          "services": 1})["reason"])
        bad = _flat(doc.draft_fields("upgrade", code,
                                     prep={"id": 1, "at": "x", "ok": False,
                                           "services": 1})["reason"])
        assert ok != bad


def test_a_backup_that_did_not_happen_is_never_promised():
    """A rollback plan naming a backup nobody took is a plan with nothing to
    roll back to -- and it reads exactly like a correct one."""
    ctx = {"id": 9, "at": "x", "ok": True, "services": 3, "firmware": "7.6.8",
           "backup": ""}
    for code in LANG_CODES:
        with_run = doc.draft_fields("upgrade", code, prep=ctx)
        without = doc.draft_fields("upgrade", code)
        # No backup was taken, so the plan is the generic one -- it must not
        # cite a run as the source of a file that does not exist.
        assert _flat(with_run["rollback"]) == _flat(without["rollback"])
        assert "#9" not in _flat(with_run["rollback"])
        for value in with_run.values():
            assert "None" not in value and "{backup}" not in value


def test_an_unknown_action_or_language_still_produces_text():
    """A new registry key must not blank the required Title field."""
    draft = doc.draft_fields("no_such_action_at_all", "kl-KL")
    assert set(draft) == set(doc.DRAFT_FIELDS)
    for value in draft.values():
        assert _flat(value)
    # And it still NAMES something: a title of " -- <devices>" is non-empty and
    # says nothing about what is being changed.
    generic = doc.ACTION_PROFILES[doc.GENERIC_ACTION][doc.DEFAULT_LANG]["label"]
    assert generic in draft["title"]


def test_the_picker_the_title_and_the_document_name_the_action_identically():
    """Three names for one action is how a signed document stops matching the
    change somebody approved on screen."""
    for action in sorted(cr_action_keys()):
        for code in LANG_CODES:
            label = doc.action_label(action, code)
            assert label
            assert label == doc._profile_text(action, code)["label"]
            assert label in doc.draft_fields(action, code)["title"]


def test_the_empty_device_list_reads_as_a_blank_not_as_a_device():
    for code in LANG_CODES:
        assert _flat(doc.devices_placeholder(code))
    assert doc.devices_placeholder("de") != doc.devices_placeholder("en")


# --------------------------------------------------------------------------- #
#  The page                                                                     #
# --------------------------------------------------------------------------- #
def _appliance_with_prep(app):
    from app.models import UpgradePrep
    with app.app_context():
        a = Appliance(name="draftbox", host="192.0.2.99", port=443,
                      kind="fortiweb", username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        prep = UpgradePrep(
            appliance_id=a.id, created_by="operator", ok=True,
            firmware=RESULT_FIXTURE["firmware"],
            summary="backup ok, health ok",
            result=json.dumps(RESULT_FIXTURE),
            inventory=json.dumps(INVENTORY_FIXTURE))
        db.session.add(prep)
        db.session.commit()
        return a.id, prep.id


def test_the_form_asks_the_language_first(app, client):
    login(client, admin_user_id(app))
    html = client.get("/change-requests/new").get_data(as_text=True)
    # Scoped to the step-1 card on purpose: the page's own script selects
    # `input[name="doc_lang"]`, so a document-wide count matches the selector
    # that asks the question as well as the radios that answer it.
    card = html[html.index('id="cr-step-lang"'):html.index('id="cr-step-action"')]
    assert card.count('name="doc_lang"') == len(LANG_CODES)
    assert card.count('type="radio"') == len(LANG_CODES)
    for code in LANG_CODES:
        assert 'value="%s"' % code in card
    # Order on the page is the order of the questions: the language block has to
    # come before the change-type block, or "first" is only true in the prompt.
    assert html.index('id="cr-step-lang"') < html.index('id="cr-step-action"')
    assert html.index('id="cr-step-action"') < html.index('id="cr-step-rest"')


def test_the_page_carries_every_proposal_it_could_need(app, client):
    """Composed SERVER-side, handed over as data. Sentences assembled in
    JavaScript would give the printed document a second author."""
    login(client, admin_user_id(app))
    html = client.get("/change-requests/new").get_data(as_text=True)
    m = re.search(r"var DRAFTS = (\{.*?\});\n", html, re.S)
    assert m, "the proposal payload is gone from the page"
    drafts = json.loads(m.group(1))
    assert set(drafts) == set(cr_action_keys())
    for action, per_lang in drafts.items():
        assert set(per_lang) == set(LANG_CODES), action
        for code, fields in per_lang.items():
            assert set(fields) == set(doc.DRAFT_FIELDS)


def test_a_cited_run_reaches_the_page_payload(app, client):
    aid, pid = _appliance_with_prep(app)
    login(client, admin_user_id(app))
    html = client.get("/change-requests/new?prep_id=%d&action=upgrade" % pid
                      ).get_data(as_text=True)
    m = re.search(r"var DRAFTS = (\{.*?\});\n", html, re.S)
    drafts = json.loads(m.group(1))
    reason = _flat(drafts["upgrade"]["en"]["reason"])
    assert "#%d" % pid in reason
    assert RESULT_FIXTURE["backup"]["name"] in _flat(drafts["upgrade"]["en"]["rollback"])


def test_owner_and_recipients_are_proposed_visibly(app, client):
    """Pre-filled in the field, not derived at save time. Section 1 attributes
    the change to this name; an owner nobody saw assigned is not accountability."""
    login(client, admin_user_id(app))
    html = client.get("/change-requests/new").get_data(as_text=True)
    m = re.search(r"var DEFAULTS = (\{.*?\});\n", html, re.S)
    assert m, "the defaults payload is gone"
    defaults = json.loads(m.group(1))
    assert defaults["owner"], "the owner proposal is empty"
    assert "notify_to" in defaults
    assert 'id="cr-owner"' in html and 'id="cr-notify"' in html


def test_the_operators_own_words_are_never_overwritten(tpl):
    """The fields keep updating as the two answers change -- until the operator
    types. Without the flag, picking a language after writing the reason wipes
    it, and the wipe looks like the form working."""
    assert 'data-auto="1"' in tpl
    assert "el.setAttribute('data-auto', '0')" in tpl
    body = tpl[tpl.index("function paint("):tpl.index("function relabelActions(")]
    # The BRANCH is pinned, not merely the word: a guard that only proves the
    # flag is READ passes with the early return deleted, and the deletion is
    # exactly the regression. This is a source assertion and cannot execute the
    # page -- the behaviour itself is verified by rendering it in a browser.
    assert "var auto = el.getAttribute('data-auto') === '1';" in body
    assert "if (!auto) { return; }" in body, "paint() overwrites edited fields again"


def test_a_hidden_step_is_actually_hidden(tpl):
    """`.row` and `.fw-card` set `display`, and a class beats the UA stylesheet's
    `[hidden]` rule on equal specificity -- the section stays on screen with the
    attribute set, which is not a state any test can see."""
    rule = re.search(r"([^{}]*\[hidden\][^{}]*)\{([^}]*)\}", tpl)
    assert rule, "nothing forces a hidden step to be hidden"
    selector, body = rule.group(1), rule.group(2).replace(" ", "")
    assert "#cr-step-action[hidden]" in selector and "#cr-step-rest[hidden]" in selector
    assert "display:none!important" in body


def test_the_form_still_works_without_scripting(app, client, tpl):
    """The reveal is applied by script, never baked into the markup: with
    scripting off the whole form is present and submittable. That is the only
    reason this can be a progressive reveal instead of a server-side wizard
    holding half a change request."""
    login(client, admin_user_id(app))
    html = client.get("/change-requests/new").get_data(as_text=True)
    for step in ("cr-step-action", "cr-step-rest"):
        m = re.search(r'id="%s"[^>]*>' % step, html)
        assert m, step
        assert "hidden" not in m.group(0), "%s ships hidden in the markup" % step
    assert 'name="title"' in html and 'name="rollback"' in html


def test_the_new_chrome_stays_on_the_light_theme(tpl):
    """This product has no dark mode (safeguards 9m). A dark-theme colour here
    renders as a grey slab on a white card and its text goes to ~1.3:1 --
    complete, and unreadable."""
    open_tag = re.search(r"<style\b[^>]*>", tpl)
    assert open_tag, ("the page has no <style> block -- this guard "
                      "would check nothing; it was disarmed once when "
                      "the CSP nonce turned <style> into <style nonce=..>")
    block = tpl[open_tag.end():tpl.index("</style>")]
    for literal in ("rgba(0,0,0", "#94a3b8", "#0f172a", "#1e293b", "#cbd5e1",
                    "backdrop-filter"):
        assert literal not in block, "dark-theme leftover %s" % literal


def test_creating_a_change_still_stores_the_submitted_wording(app, client):
    """The guided form must not become a form that submits something else."""
    aid, pid = _appliance_with_prep(app)
    login(client, admin_user_id(app))
    r = client.post("/change-requests/new", data={
        "title": "Upgrade draftbox", "action": "upgrade", "risk": "high",
        "device_ids": [str(aid)], "prep_id": str(pid), "doc_lang": "de",
        "reason": "Weil es sein muss.", "rollback": "Zurueck auf Partition 1.",
        "owner": "operator", "notify_to": "ops@example.com",
    }, follow_redirects=True)
    assert r.status_code == 200
    from app.models import ChangeRequest
    with app.app_context():
        cr = ChangeRequest.query.order_by(ChangeRequest.id.desc()).first()
        assert cr is not None
        assert cr.title == "Upgrade draftbox"
        assert cr.doc_lang == "de"
        assert cr.reason == "Weil es sein muss."
        assert cr.rollback == "Zurueck auf Partition 1."
        assert cr.owner == "operator"
        assert cr.notify_to == "ops@example.com"


# --------------------------------------------------------------------------- #
#  Question 2 has to be ANSWERABLE                                              #
# --------------------------------------------------------------------------- #
def _strip_js_comments(text: str) -> str:
    """Line comments removed before asserting. Nine assertions in this repo have
    matched the comment that EXPLAINS them (safeguards 7f); a comment naming the
    construct a guard forbids is the tenth waiting to happen."""
    return re.sub(r"^\s*//.*$", "", text, flags=re.M)


def test_the_picker_opens_on_a_question_not_on_an_action(app, client):
    """The dead end this closes, reproduced in a browser: with a real action
    pre-selected, choosing THAT action fires no `change` event -- so an operator
    arriving directly and wanting the first entry on the list clicked their
    answer and watched nothing happen. No step 3, no proposed wording, no way
    forward. Nothing failed; the page simply never learned the question had been
    answered."""
    login(client, admin_user_id(app))
    html = client.get("/change-requests/new").get_data(as_text=True)
    sel = html[html.index('id="cr-action"'):]
    sel = sel[:sel.index("</select>")]
    options = re.findall(r"<option[^>]*>", sel)
    assert options, "the change-type picker lost its options"
    # The opening entry carries no value: it is a question, not an answer.
    assert 'value=""' in options[0] and "selected" in options[0], \
        "the picker opens on a real action, which cannot be chosen"
    # ...and no real action is pre-selected behind it.
    for opt in options[1:]:
        assert "selected" not in opt, "a change type is pre-selected: %s" % opt


def test_a_cited_run_still_arrives_with_its_type_chosen(app, client):
    """Coming from an appliance's pre-flight the type is decided by the link.
    The question must NOT be re-asked there -- and the un-answerable entry must
    not be sitting in front of the answer the link already gave."""
    aid, pid = _appliance_with_prep(app)
    login(client, admin_user_id(app))
    html = client.get("/change-requests/new?prep_id=%d&action=upgrade" % pid
                      ).get_data(as_text=True)
    sel = html[html.index('id="cr-action"'):]
    sel = sel[:sel.index("</select>")]
    assert 'value=""' not in sel, "the prompt is offered on top of a chosen type"
    m = re.search(r'<option value="upgrade"[^>]*>', sel)
    assert m and "selected" in m.group(0), "the linked type is not selected"


def test_the_question_is_not_a_submittable_change_type(app, client):
    """An empty action reaching the executor would be a change request bound to
    no action at all -- it saves, it prints, and it resolves to nothing when the
    window opens, long after anyone could act on it."""
    from app.models import ChangeRequest
    login(client, admin_user_id(app))
    with app.app_context():
        before = ChangeRequest.query.count()
    r = client.post("/change-requests/new", data={
        "title": "No type at all", "action": "", "risk": "medium",
        "doc_lang": "en"}, follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        assert ChangeRequest.query.count() == before, "an actionless change saved"
    html = client.get("/change-requests/new").get_data(as_text=True)
    m = re.search(r"<select[^>]*id=\"cr-action\"[^>]*>", html)
    assert m and "required" in m.group(0), "the browser would submit the question"


def test_the_question_is_asked_in_the_chosen_language(app, client, tpl):
    """A German form whose picker still says "Choose the type of change" is the
    same defect class as German prose in an English draft: it renders, it is
    read, and only a human notices."""
    login(client, admin_user_id(app))
    html = client.get("/change-requests/new").get_data(as_text=True)
    m = re.search(r"var PROMPT = (\{.*?\});\n", html, re.S)
    assert m, "the prompt payload is gone from the page"
    prompt = json.loads(m.group(1))
    assert set(prompt) == set(LANG_CODES)
    for code, text in prompt.items():
        assert text.strip(), code
        assert text == doc.action_placeholder(code)
    assert len(set(prompt.values())) == len(LANG_CODES), \
        "the two languages ask the question with the same words"
    # Distinct is not the same as translated: two different English strings pass
    # a distinctness check and leave a German form asking in English.
    assert "\u00c4nderung" in prompt["de"], "the German prompt is not German"
    assert "change" in prompt["en"].lower()
    assert "change" not in prompt["de"].lower()
    # The re-labeller has to handle the entry that has no catalogue label, or it
    # silently leaves it in the language it was rendered in.
    body = _strip_js_comments(
        tpl[tpl.index("function relabelActions("):tpl.index("function grow(")])
    assert "if (!opt.value)" in body and "PROMPT[code]" in body


def test_answering_is_read_from_the_control_never_asserted(tpl):
    """`actionAnswered = true` is the bug in one line: it makes returning to the
    opening entry leave step 3 open over a proposal that describes no change at
    all -- three filled-in fields for a change type nobody has chosen."""
    body = _strip_js_comments(tpl[tpl.index("actionSel.addEventListener('change'"):])
    body = body[:body.index("}")]
    assert "actionAnswered = !!actionSel.value;" in body
    assert "actionAnswered = true" not in _strip_js_comments(tpl), \
        "the answer is asserted somewhere instead of read from the picker"
