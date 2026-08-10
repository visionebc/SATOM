"""The document-language pick is a PROFILE preference, not a page default.

Requested 2026-08-10: *"En donde pusiste el icono para cambiar el idioma, este
se debe de guardar en las preferencias del usuario en el profile."*

The defect class here has no exit code. A language question that answers itself
produces a **complete, well-formed, signed document in a language nobody
chose** -- every field filled, every section rendered, no error anywhere. The
guards below therefore fix three things that are invisible at runtime:

1. **"no preference" is not "English."** Collapsing them makes the setting
   unobservable: the profile could never show which one is true, and an
   operator who deliberately picked English would be re-asked forever.
2. **Nothing is pre-selected without an answer behind it.** Before this change
   the first radio was ``checked`` by ``loop.first`` -- a default nobody gave.
3. **A preference the product cannot honour is stated, never downgraded.** A
   profile set to Français must not silently become an English document.
"""
from __future__ import annotations

import io
import os
import re

import pytest

from app.models import UserSetting, db
from app.services import cr_document as doc
from app.services import langs as lang_registry
from app.services import user_settings_store as ustore
from tests.conftest import admin_user_id, login

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORM_TPL = os.path.join(REPO, "app", "templates", "change_requests", "form.html")
PROFILE_TPL = os.path.join(REPO, "app", "templates", "auth", "profile.html")
BASE_TPL = os.path.join(REPO, "app", "templates", "base.html")

RENDERABLE = tuple(code for code, _label in doc.LANGS)
ALL_CODES = lang_registry.codes()
NOT_RENDERABLE = tuple(c for c in ALL_CODES if c not in RENDERABLE)


def _read(path):
    return io.open(path, encoding="utf-8").read()


def _flat(text):
    return re.sub(r"\s+", " ", str(text or "")).strip()


def _strip_js_comments(js: str) -> str:
    """Comments removed before asserting on code.

    Seventh time this repo has needed it: the comment that EXPLAINS a guard
    names the literal the guard prohibits, so a substring assertion matches its
    own documentation and passes with the code deleted (safeguards 9j).
    """
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", js)


def _radio_block(html: str) -> str:
    """Just the doc_lang radio inputs."""
    return "\n".join(re.findall(r"<input[^>]*name=\"doc_lang\"[^>]*>", html))


def _lang_select(html: str) -> str:
    """Just the profile's language <select>.

    Asserting against the whole page is how a guard passes on a marker that
    belongs to some other control: ``value=""`` appears on half a dozen inputs
    in this chrome, so "the no-preference option is there" was true with the
    option renamed out of existence.
    """
    m = re.search(r'<select[^>]*name="lang"[^>]*>(.*?)</select>', html, re.S)
    assert m, "no language <select> on the page"
    return m.group(1)


def _lang_options(html: str) -> dict:
    """``{code: option text}`` for the profile picker; ``""`` is the
    no-preference entry."""
    return {code: _flat(text) for code, text in
            re.findall(r'<option value="([a-z]*)"[^>]*>(.*?)</option>',
                       _lang_select(html), re.S)}


def _checked_codes(html: str):
    out = []
    for tag in re.findall(r"<input[^>]*name=\"doc_lang\"[^>]*>", html):
        if "checked" in tag:
            m = re.search(r'value="([a-z]{2})"', tag)
            if m:
                out.append(m.group(1))
    return out


@pytest.fixture()
def admin(app, client):
    uid = admin_user_id(app)
    login(client, uid)
    return uid


def _new_form(client):
    r = client.get("/change-requests/new")
    assert r.status_code == 200, r.status_code
    return r.get_data(as_text=True)


# --------------------------------------------------------------------------- #
#  The store: empty is a state, not a synonym for the default                   #
# --------------------------------------------------------------------------- #
def test_no_preference_reads_as_empty_not_as_english(app):
    """If "never chose" returned ``en`` the profile could not render the
    difference, and the form could not know whether to ask."""
    with app.app_context():
        uid = admin_user_id(app)
        assert ustore.language(uid) == ""


def test_saving_a_language_persists_it_in_the_database(app):
    with app.app_context():
        uid = admin_user_id(app)
        assert ustore.save_language(uid, "de") == "de"
        assert ustore.language(uid) == "de"
        # In the per-user table, not a cookie and not the global settings table.
        assert UserSetting.get(uid, ustore.K_LANG) == "de"


def test_clearing_stores_empty_never_the_default(app):
    """Writing ``en`` for "no preference" would answer the question the user
    just un-answered, in the language they did not choose."""
    with app.app_context():
        uid = admin_user_id(app)
        ustore.save_language(uid, "it")
        assert ustore.save_language(uid, "") == ""
        assert ustore.language(uid) == ""
        assert UserSetting.get(uid, ustore.K_LANG) == ""


@pytest.mark.parametrize("bogus", ["xx", "klingon", "  ", None, "de;drop"])
def test_an_unsupported_code_clears_rather_than_defaulting(app, bogus):
    with app.app_context():
        uid = admin_user_id(app)
        ustore.save_language(uid, "de")
        assert ustore.save_language(uid, bogus) == ""
        assert ustore.language(uid) == ""


@pytest.mark.parametrize("given,want", [("de-CH", "de"), ("es_MX", "es"),
                                        ("FR", "fr"), ("it-IT", "it")])
def test_regional_tags_degrade_to_their_base_language(app, given, want):
    """A browser header or a more specific stored tag must not fall through to
    the default just because it was more specific than the catalogue."""
    with app.app_context():
        uid = admin_user_id(app)
        assert ustore.save_language(uid, given) == want
        assert ustore.language(uid) == want


def test_every_registry_language_is_storable(app):
    """The picker offers five; the store must accept the same five. Two
    authors of that list is how a preference becomes unsavable in silence."""
    with app.app_context():
        uid = admin_user_id(app)
        for code in ALL_CODES:
            assert ustore.save_language(uid, code) == code


def test_a_corrupt_row_reads_as_no_preference(app):
    """Never raises: chrome on every page reads this."""
    with app.app_context():
        uid = admin_user_id(app)
        UserSetting.set(uid, ustore.K_LANG, "not-a-language")
        assert ustore.language(uid) == ""


# --------------------------------------------------------------------------- #
#  The route                                                                    #
# --------------------------------------------------------------------------- #
def test_saving_from_the_profile_page_stores_the_choice(app, client, admin):
    r = client.post("/auth/profile/language", data={"lang": "de"},
                    follow_redirects=False)
    assert r.status_code in (302, 303)
    assert r.headers["Location"].endswith("#language")
    with app.app_context():
        assert ustore.language(admin) == "de"


def test_saving_a_language_does_not_require_the_password(app, client, admin):
    """The guard against folding this back into the profile POST, which
    validates ``current_password`` and would demand one to change a display
    preference -- or tempt the next editor to relax that check for everyone."""
    r = client.post("/auth/profile/language", data={"lang": "es"})
    assert r.status_code in (302, 303)
    with app.app_context():
        assert ustore.language(admin) == "es"
    # And the password handler is still the password handler.
    r2 = client.post("/auth/profile", data={"current_password": "",
                                            "new_password": "abcdefgh",
                                            "confirm_password": "abcdefgh"})
    assert r2.status_code == 200
    assert "incorrect" in r2.get_data(as_text=True).lower()


def test_clearing_from_the_page_round_trips(app, client, admin):
    client.post("/auth/profile/language", data={"lang": "fr"})
    client.post("/auth/profile/language", data={"lang": ""})
    with app.app_context():
        assert ustore.language(admin) == ""


def test_anonymous_cannot_set_a_language(app, client):
    r = client.post("/auth/profile/language", data={"lang": "de"})
    assert r.status_code in (302, 401, 403)
    assert "/auth/profile/language" not in (r.headers.get("Location") or "")


def test_profile_page_offers_every_registry_language(app, client, admin):
    html = client.get("/auth/profile").get_data(as_text=True)
    assert 'name="lang"' in html
    for code, endonym in lang_registry.SUPPORTED:
        assert 'value="%s"' % code in html
        # Under its own name: a picker that says "German" to a German operator
        # is written for the wrong reader.
        assert endonym in html
    # "No preference" is offered explicitly, not implied by leaving it alone —
    # and it is an option of THIS select, with the empty value the clearing
    # path expects. A different value would post something the store treats as
    # unsupported, which happens to clear too: right outcome, wrong contract.
    options = _lang_options(html)
    assert "" in options, sorted(options)
    assert "No preference" in options[""]


def test_profile_page_says_which_languages_documents_exist_in(app, client, admin):
    """A preference the product cannot honour must say so where it is SET, not
    fail to appear later on a form the operator is already filling in.

    Checked PER OPTION, both ways round: a page that marks everything
    untranslated is as wrong as one that marks nothing, and a marker counted
    anywhere on the page cannot tell them apart."""
    with app.app_context():
        ustore.save_language(admin, "fr")
    html = client.get("/auth/profile").get_data(as_text=True)
    options = _lang_options(html)
    for code in RENDERABLE:
        assert "not translated yet" not in options[code], code
    for code in NOT_RENDERABLE:
        assert "not translated yet" in options[code], code
    # And the summary line names exactly the renderable set, not "whatever the
    # view happened to pass".
    m = re.search(r"Change documents can be produced in\s*<strong>(.*?)</strong>",
                  html, re.S)
    assert m, "the page does not say which languages documents exist in"
    listed = [c.strip() for c in _flat(m.group(1)).split(",") if c.strip()]
    assert listed == [c.upper() for c in RENDERABLE], listed


def test_profile_page_marks_the_saved_language(app, client, admin):
    with app.app_context():
        ustore.save_language(admin, "it")
    html = client.get("/auth/profile").get_data(as_text=True)
    m = re.search(r'<option value="it"[^>]*>', html)
    assert m and "selected" in m.group(0)


def test_profile_page_marks_no_preference_when_none_is_saved(app, client, admin):
    """"No preference" has to be the marked option, explicitly.

    Leaving it to fall out of "the browser selects the first option" is a
    default that holds only while that option stays first: reorder the list --
    alphabetically, say -- and the profile silently claims the user picked a
    language they never picked, with nothing failing. So the page must mark it,
    and it must mark exactly one.
    """
    with app.app_context():
        ustore.save_language(admin, "")
    html = client.get("/auth/profile").get_data(as_text=True)
    opts = re.findall(r'<option value="([a-z]*)"[^>]*>', html)
    marked = [c for c, tag in
              ((c, t) for c, t in
               ((m.group(1), m.group(0)) for m in
                re.finditer(r'<option value="([a-z]*)"[^>]*>', html)))
              if "selected" in tag]
    assert "" in opts, "the profile offers no 'no preference' entry"
    assert marked == [""], marked


# --------------------------------------------------------------------------- #
#  The change-request form                                                      #
# --------------------------------------------------------------------------- #
def test_without_a_preference_nothing_is_pre_selected(app, client, admin):
    """The whole point of the previous round, kept: an operator who clicks the
    option that is already selected fires no event and watches nothing happen."""
    html = _new_form(client)
    assert _checked_codes(html) == []


def test_the_saved_language_is_the_one_pre_selected(app, client, admin):
    with app.app_context():
        ustore.save_language(admin, "de")
    html = _new_form(client)
    assert _checked_codes(html) == ["de"]


@pytest.mark.parametrize("code", ALL_CODES)
def test_the_form_never_pre_selects_an_unrenderable_language(app, client, admin, code):
    """Property over the whole registry: whatever is checked must be a language
    a complete document can actually be produced in."""
    with app.app_context():
        ustore.save_language(admin, code)
    checked = _checked_codes(_new_form(client))
    assert all(c in RENDERABLE for c in checked)
    assert checked == ([code] if code in RENDERABLE else [])


@pytest.mark.parametrize("code", NOT_RENDERABLE or ("es",))
def test_an_unhonourable_preference_is_stated_not_downgraded(app, client, admin, code):
    with app.app_context():
        ustore.save_language(admin, code)
    flat = _flat(_new_form(client))
    assert "has no change-document text yet" in flat
    assert lang_registry.label(code) in flat


def test_the_language_question_is_required(app, client, admin):
    """With scripting off the form is still submittable; the browser must not
    let it through with the question unanswered."""
    block = _radio_block(_new_form(client))
    assert block.count("required") >= 1


def test_the_form_does_not_carry_the_old_first_is_default_rule(app):
    tpl = _read(FORM_TPL)
    assert "'checked' if loop.first" not in tpl
    assert "lang_preset" in tpl


def test_the_answer_is_read_from_the_control_never_asserted(app):
    """``langAnswered = true`` anywhere would open step 2 over a language
    nobody picked -- including on a reload that restored nothing."""
    js = _strip_js_comments(_read(FORM_TPL))
    assert re.search(r"langAnswered\s*=\s*!!\s*lang\(\)", js)
    assert not re.search(r"langAnswered\s*=\s*true", js)


def test_lang_returns_empty_and_rendering_uses_the_fallback(app):
    """Two functions on purpose: text has to come out in some language, the
    question does not have to be answered for that. One function doing both is
    how 'unanswered' became 'English' in the first place."""
    js = _strip_js_comments(_read(FORM_TPL))
    body = js.split("function lang()", 1)[1].split("function langOr", 1)[0]
    assert "return '';" in body
    assert "return 'en';" not in body
    assert "function langOr()" in js
    # Every render site goes through the fallback, none through the raw answer.
    assert "var code = lang();" not in js
    assert js.count("var code = langOr();") >= 2


def test_the_form_points_at_the_profile_so_the_setting_is_findable(app, client, admin):
    """A preference nobody can find is a preference nobody sets."""
    assert "/auth/profile" in _new_form(client)


# --------------------------------------------------------------------------- #
#  The chrome                                                                   #
# --------------------------------------------------------------------------- #
def test_the_top_bar_offers_the_language_entry(app):
    """Asserted against base.html, not against a rendered profile page: the
    profile card carries ``id="language"`` and the change-request form links to
    it, so both markers are present on those pages with the menu entry gone."""
    tpl = _read(BASE_TPL)
    items = re.findall(r"<a class=\"dropdown-item\"[^>]*>.*?</a>", tpl, re.S)
    hits = [i for i in items if "#language" in i]
    assert len(hits) == 1, "expected exactly one Language entry, got %d" % len(hits)
    entry = _flat(hits[0])
    assert "bi-translate" in entry
    assert ">Language" in entry.replace(" ", "") or "Language" in entry
    # It shows the current choice, which is the only reason it is in the bar
    # rather than buried in the profile.
    assert "user_lang" in entry


def test_the_top_bar_shows_the_current_choice(app, client, admin):
    with app.app_context():
        ustore.save_language(admin, "de")
    html = client.get("/auth/profile").get_data(as_text=True)
    assert re.search(r">\s*DE\s*<", html)


def test_the_top_bar_says_not_set_when_there_is_none(app, client, admin):
    html = client.get("/auth/profile").get_data(as_text=True)
    assert "not set" in html


def test_the_preference_key_has_one_author(app):
    """A second literal for the same key is how a page reads a preference
    another page never wrote."""
    hits = []
    for root, _dirs, files in os.walk(os.path.join(REPO, "app")):
        for name in files:
            if not name.endswith((".py", ".html")):
                continue
            path = os.path.join(root, name)
            if "i18n.lang" in _read(path):
                hits.append(os.path.relpath(path, REPO))
    assert hits == ["app/services/user_settings_store.py"], hits
