"""Which languages this installation OFFERS -- and what a withdrawal must not do.

The defect class this file guards is the one that does not fail: a language is
switched off in the admin console and *something* keeps offering it, or a
withdrawal silently rewrites a preference somebody set on purpose. Nothing
raises in either case; the product simply says something untrue.

So the assertions here are mostly about the surfaces that are NOT the checkbox:
the browser negotiation, the change-document picker, the stored preference, and
the ``<html lang>`` attribute a screen reader pronounces the page from.
"""
from __future__ import annotations

import pytest

from tests.conftest import admin_user_id, login, make_user


# --------------------------------------------------------------------------- #
#  The store                                                                   #
# --------------------------------------------------------------------------- #
def test_an_unconfigured_install_offers_every_language(app):
    """No row = "nobody decided", which cannot mean "offer nothing"."""
    from app.services import lang_policy, langs

    with app.app_context():
        assert lang_policy.offered_codes() == langs.codes()
        assert lang_policy.configured() is False
        assert lang_policy.withdrawn_codes() == ()


def test_a_broken_row_offers_every_language_instead_of_none(app):
    """A hand-edited/half-written row must not shrink the product.

    ``get_json`` answers "unset" and "unparseable" identically; this asserts we
    took the branch that treats a broken row as undecided rather than as an
    empty list, which would leave the install with English only and no clue
    why.
    """
    from app.models import AppSetting
    from app.services import lang_policy, langs

    with app.app_context():
        AppSetting.set(lang_policy.K_OFFERED, "{not json at all")
        assert lang_policy.offered_codes() == langs.codes()
        assert lang_policy.configured() is False


def test_the_source_language_survives_every_way_of_removing_it(app):
    """Empty post, junk post, explicit exclusion -- all keep the default.

    This is the lock-out rule. If it ever fails, an operator can leave the
    install with no language anybody can read, from a checkbox, with no way
    back in through the UI.
    """
    from app.services import lang_policy, langs

    with app.app_context():
        for payload in ([], None, ["zz"], ["es"], ["es", "fr"], ("",)):
            stored = lang_policy.save(payload)
            assert langs.DEFAULT in stored, payload
            assert langs.DEFAULT in lang_policy.offered_codes(), payload


def test_the_reader_forces_the_source_language_in_too_not_only_the_writer(app):
    """``save()`` is not the only way a row gets written.

    A migration, a restored backup or an operator with psql can leave a list
    without the source language. Asserting this through the READER is the point
    -- with the rule only in the writer, the mutation that removes it from the
    reader passes every test and the install is one hand-written row away from
    being unreadable.
    """
    from app.models import AppSetting
    from app.services import lang_policy, langs

    with app.app_context():
        AppSetting.set(lang_policy.K_OFFERED, '["es", "fr"]')
        assert langs.DEFAULT in lang_policy.offered_codes()


def test_offered_order_comes_from_the_registry_not_from_the_save(app):
    """A picker that reorders itself to match the order boxes were saved in is
    a picker the operator has to re-learn after every save.

    Asserted as an exact tuple, not as "different from what I posted": a set
    iterates in an order that is arbitrary but often *happens* to agree, so the
    loose form reported SURVIVES for a mutation that really had dropped the
    ordering.
    """
    from app.services import lang_policy

    with app.app_context():
        lang_policy.save(["it", "de", "en"])
        assert lang_policy.offered_codes() == ("en", "de", "it")


def test_unknown_codes_are_dropped_rather_than_stored(app):
    from app.services import lang_policy

    with app.app_context():
        stored = lang_policy.save(["en", "es", "klingon", "", None, 7])
        assert stored == ("en", "es")
        assert lang_policy.is_offered("klingon") is False


def test_a_regional_tag_is_normalised_on_the_way_in_not_discarded(app):
    """``de-CH`` names German. A save that only filtered (rather than
    normalised) would drop it, and the operator would watch a box they ticked
    come back unticked with no error anywhere."""
    from app.services import lang_policy

    with app.app_context():
        assert lang_policy.save(["de-CH", "es_MX"]) == ("en", "es", "de")


def test_a_broken_row_is_reported_as_broken_not_as_never_configured(app):
    """Both degrade to offering everything -- that is deliberate -- but only
    one of them means a row somebody saved is being ignored. Collapsing them
    tells an operator "never configured" while they look at their own setting.
    """
    from app.models import AppSetting
    from app.services import lang_policy

    with app.app_context():
        assert lang_policy.malformed() is False
        AppSetting.set(lang_policy.K_OFFERED, '{"nope": 1}')
        assert lang_policy.malformed() is True
        assert lang_policy.configured() is False
        lang_policy.save(["en", "es"])
        assert lang_policy.malformed() is False


def test_is_offered_is_strict_where_normalize_is_forgiving(app):
    """``normalize`` degrades anything to the default to keep a render alive.

    A gate that inherited that behaviour would answer "offered" for a language
    nobody declared -- the exact question it exists to refuse.
    """
    from app.services import lang_policy

    with app.app_context():
        lang_policy.save(["en", "de"])
        assert lang_policy.is_offered("de-CH") is True     # regional -> base
        assert lang_policy.is_offered("DE") is True        # case
        assert lang_policy.is_offered("fr") is False       # withdrawn
        assert lang_policy.is_offered("klingon") is False  # unknown
        assert lang_policy.is_offered("") is False
        assert lang_policy.is_offered(None) is False


# --------------------------------------------------------------------------- #
#  The surfaces that are not the checkbox                                      #
# --------------------------------------------------------------------------- #
def test_browser_negotiation_cannot_select_a_withdrawn_language(app):
    """``Accept-Language: fr`` must not render French once French is off."""
    from app.services import lang_policy, ui_locale

    with app.app_context():
        lang_policy.save(["en", "de"])
        with app.test_request_context(headers={"Accept-Language": "fr,en;q=0.3"}):
            assert ui_locale.resolve() != "fr"
        with app.test_request_context(headers={"Accept-Language": "de,en;q=0.3"}):
            assert ui_locale.resolve() == "de"


def test_negotiation_falls_to_the_browsers_next_choice_not_to_no_match(app):
    """``best_match`` picks from the list it is GIVEN.

    Handing it the full registry and filtering the winner afterwards would
    answer "no match" for a browser whose first choice is withdrawn but whose
    second is offered -- so this asserts the narrowing happens before the call.
    """
    from app.services import lang_policy, ui_locale

    with app.app_context():
        lang_policy.save(["en", "de"])
        with app.test_request_context(headers={"Accept-Language": "fr;q=0.9,de;q=0.8"}):
            assert ui_locale.resolve() == "de"


def test_a_withdrawn_preference_is_not_honoured_and_not_deleted(app, client):
    """The user's answer survives the withdrawal; only its effect stops."""
    from app.models import UserSetting
    from app.services import lang_policy
    from app.services import user_settings_store as us

    uid = make_user(app, username="pierre")
    with app.app_context():
        us.save_language(uid, "fr")
        lang_policy.save(["en", "de"])

    login(client, uid)
    # Not honoured: the page this user is served is not in French.
    assert '<html lang="fr"' not in client.get("/auth/profile").get_data(as_text=True)

    with app.app_context():
        # ...yet the answer is still there, verbatim.
        assert UserSetting.get(uid, us.K_LANG) == "fr"
        assert us.language(uid) == "fr"
        # ...and it applies again the moment French is offered again.
        lang_policy.save(["en", "de", "fr"])
        assert lang_policy.is_offered(us.language(uid)) is True

    assert '<html lang="fr"' in client.get("/auth/profile").get_data(as_text=True)


def test_the_document_language_picker_follows_the_gate(app):
    """A withdrawal withdraws from EVERY picker, not only the profile."""
    from app.services import cr_document, lang_policy

    with app.app_context():
        before = {c for c, _ in cr_document.document_langs()}
        assert "de" in before, "fixture assumption: German is renderable"
        lang_policy.save(["en"])
        after = {c for c, _ in cr_document.document_langs()}
        assert "de" not in after
        assert after, "the source language keeps the picker non-empty"


def test_renderable_langs_ignores_the_gate_so_the_console_can_explain_itself(app):
    """The admin table says "documents are produced in X" NEXT TO the switch
    for X. If that column were computed through the gate it would read
    "not translated" for everything switched off -- an answer that depends on
    the setting it is describing."""
    from app.services import cr_document, lang_policy

    with app.app_context():
        lang_policy.save(["en"])
        assert "de" in {c for c, _ in cr_document.renderable_langs()}
        assert "de" not in {c for c, _ in cr_document.document_langs()}


def test_normalize_lang_never_returns_a_withdrawn_language(app):
    """Whatever a stale form posts, the renderer must land on something the
    install offers -- otherwise the gate merely moved the problem downstream."""
    from app.services import cr_document, lang_policy

    with app.app_context():
        lang_policy.save(["en"])
        for value in ("de", "fr-CH", "es", "klingon", "", None):
            assert lang_policy.is_offered(cr_document.normalize_lang(value))


# --------------------------------------------------------------------------- #
#  The admin console                                                           #
# --------------------------------------------------------------------------- #
def test_the_console_lists_every_language_including_the_withdrawn_ones(app, client):
    """Listing only what is offered would make withdrawing irreversible from
    the page that does the withdrawing."""
    from app.services import lang_policy

    with app.app_context():
        lang_policy.save(["en"])
    login(client, admin_user_id(app))
    html = client.get("/settings/").get_data(as_text=True)
    assert 'id="tab-languages"' in html
    for code in ("en", "es", "de", "fr", "it"):
        assert 'value="%s" id="lang-%s"' % (code, code) in html, code


def test_the_source_language_checkbox_is_disabled_in_the_form(app, client):
    from app.services import langs

    login(client, admin_user_id(app))
    html = client.get("/settings/").get_data(as_text=True)
    marker = 'id="lang-%s"' % langs.DEFAULT
    row = html[html.index(marker) - 400:html.index(marker) + 200]
    assert "disabled" in row


def test_saving_with_no_boxes_ticked_still_leaves_a_readable_install(app, client):
    """The disabled checkbox does not post, so the POST handler receives a set
    without the source language on EVERY save. The rule cannot live in the
    form.

    Asserted on the STORED ROW, not only on what the reader computes: with the
    rule present in the reader alone, a handler that wrote the raw post would
    leave ``[]`` on disk and still look correct from every page -- until
    something else read the setting.
    """
    from app.models import AppSetting
    from app.services import lang_policy, langs

    login(client, admin_user_id(app))
    client.post("/settings/languages", data={}, follow_redirects=True)
    with app.app_context():
        assert lang_policy.offered_codes() == (langs.DEFAULT,)
        assert langs.DEFAULT in (AppSetting.get(lang_policy.K_OFFERED) or "")


def test_the_console_shows_which_languages_are_currently_offered(app, client):
    """A page whose switches do not reflect the stored state is a page that
    lies twice: once now, and once more when the operator saves it back."""
    from app.services import lang_policy

    with app.app_context():
        lang_policy.save(["en", "es"])
    login(client, admin_user_id(app))
    html = client.get("/settings/").get_data(as_text=True)

    def _input(code):
        """The whole ``<input>`` element, cut at its own ``>``.

        A fixed-width window truncated the tag mid-attribute and reported the
        page as wrong when it was right -- the same class of defect the
        assertion is meant to catch.
        """
        i = html.index('id="lang-%s"' % code)
        start = html.rindex("<input", 0, i)
        return html[start:html.index(">", i)]

    assert "checked" in _input("es")
    assert "checked" not in _input("fr")


def test_the_console_reports_document_readiness_independently_of_the_switch(app, client):
    """The "change documents" column describes the CATALOGUE. Computing it
    through the availability gate would print "not translated yet" for every
    language the operator has not ticked yet -- an answer that depends on the
    setting it is describing, discoverable only by switching the language on.
    """
    from app.services import lang_policy

    with app.app_context():
        lang_policy.save(["en"])           # German withdrawn, still renderable
    login(client, admin_user_id(app))
    html = client.get("/settings/").get_data(as_text=True)
    assert 'data-lang="de" data-doc="produced"' in html
    assert 'data-lang="it" data-doc="missing"' in html


def test_saving_records_an_audit_entry_naming_what_was_withdrawn(app, client):
    from app.models import AuditLog

    login(client, admin_user_id(app))
    client.post("/settings/languages", data={"offered": ["es"]},
                follow_redirects=True)
    with app.app_context():
        row = (AuditLog.query.filter_by(action="settings.languages")
               .order_by(AuditLog.id.desc()).first())
        assert row is not None
        assert "fr" in (row.extra or ""), row.extra
        assert "es" in (row.target or ""), row.target


def test_a_non_admin_cannot_change_language_availability(app, client):
    from app.services import lang_policy

    uid = make_user(app, username="ronly", role="readonly")
    login(client, uid)
    resp = client.post("/settings/languages", data={"offered": ["en"]})
    assert resp.status_code in (302, 403)
    with app.app_context():
        assert lang_policy.configured() is False


# --------------------------------------------------------------------------- #
#  The profile                                                                 #
# --------------------------------------------------------------------------- #
def test_the_profile_picker_offers_only_what_the_install_offers(app, client):
    from app.services import lang_policy

    uid = make_user(app, username="paula")
    with app.app_context():
        lang_policy.save(["en", "es"])
    login(client, uid)
    html = client.get("/auth/profile").get_data(as_text=True)
    assert 'value="es"' in html
    assert 'value="fr"' not in html


def test_a_withdrawn_preference_stays_visible_and_explained_in_the_profile(app, client):
    """Dropping it from the list would leave the user reading English with a
    profile that shows no reason -- and the first Save would clear the answer
    they never withdrew."""
    from app.services import lang_policy
    from app.services import user_settings_store as us

    uid = make_user(app, username="jean")
    with app.app_context():
        us.save_language(uid, "fr")
        lang_policy.save(["en", "es"])
    login(client, uid)
    html = client.get("/auth/profile").get_data(as_text=True)
    assert 'value="fr"' in html
    assert "no longer offered here" in html


def test_posting_a_withdrawn_language_is_refused_not_stored(app, client):
    """A stale form or a replayed post must not create the state the gate
    exists to prevent."""
    from app.models import UserSetting
    from app.services import lang_policy
    from app.services import user_settings_store as us

    uid = make_user(app, username="marc")
    with app.app_context():
        us.save_language(uid, "es")
        lang_policy.save(["en", "es"])
    login(client, uid)
    client.post("/auth/profile/language", data={"lang": "it"},
                follow_redirects=True)
    with app.app_context():
        assert UserSetting.get(uid, us.K_LANG) == "es", \
            "the refusal must also not clear the previous answer"


def test_clearing_the_preference_still_works_while_a_gate_is_configured(app, client):
    """"No preference" is a real answer and the refusal branch must not eat
    it -- an empty submission is not an unoffered language."""
    from app.models import UserSetting
    from app.services import lang_policy
    from app.services import user_settings_store as us

    uid = make_user(app, username="nora")
    with app.app_context():
        us.save_language(uid, "es")
        lang_policy.save(["en", "es"])
    login(client, uid)
    client.post("/auth/profile/language", data={"lang": ""},
                follow_redirects=True)
    with app.app_context():
        assert UserSetting.get(uid, us.K_LANG) == ""


# --------------------------------------------------------------------------- #
#  Counting, and the attribute a screen reader reads                           #
# --------------------------------------------------------------------------- #
def test_language_usage_counts_picks_not_rows(app):
    """"No preference" is stored as a blank row. Counting it would tell the
    operator that withdrawing a language affects users who never chose it."""
    from app.services import user_settings_store as us

    a = make_user(app, username="u1")
    b = make_user(app, username="u2")
    c = make_user(app, username="u3")
    with app.app_context():
        us.save_language(a, "es")
        us.save_language(b, "es")
        us.save_language(c, "")          # no preference
        usage = us.language_usage()
        assert usage.get("es") == 2
        assert "" not in usage
        assert usage.get("en", 0) == 0


def test_html_lang_carries_the_rendered_language_not_a_constant(app, client):
    """A screen reader pronounces the page in the language this attribute
    claims. Hardcoding "en" mispronounces every translated page and nothing
    fails."""
    from app.services import lang_policy

    uid = make_user(app, username="hans")
    with app.app_context():
        lang_policy.save(["en", "de"])
        from app.services import user_settings_store as us
        us.save_language(uid, "de")
    login(client, uid)
    html = client.get("/settings/").get_data(as_text=True)
    assert '<html lang="de"' in html


def test_html_lang_follows_the_withdrawal_too(app, client):
    from app.services import lang_policy
    from app.services import user_settings_store as us

    uid = make_user(app, username="hans2")
    with app.app_context():
        us.save_language(uid, "de")
        lang_policy.save(["en"])
    login(client, uid)
    html = client.get("/settings/").get_data(as_text=True)
    assert '<html lang="de"' not in html
    assert '<html lang="en"' in html
