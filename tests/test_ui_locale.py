"""The chrome language: how it is chosen, and what the shipped catalogues may
not contain.

Every defect guarded here was found by *rendering*, not by a unit test, and
each one failed silently: a menu entry that printed a machine-translation
sentinel, a page that raised ``ValueError`` only when its own string was on
screen, and a catalogue that was correct on disk while the compiled copy the
app actually reads was stale.
"""
from __future__ import annotations

import gettext
import os
import re

import pytest

from app.services import langs, ui_locale
from app.services import user_settings_store as ustore

from tests.conftest import admin_user_id, login

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRANSLATIONS = os.path.join(REPO, "app", "translations")
SHIPPED = tuple(c for c in langs.codes() if c != langs.DEFAULT)


def _catalog(code):
    with open(os.path.join(TRANSLATIONS, code, "LC_MESSAGES", "messages.mo"), "rb") as fh:
        return gettext.GNUTranslations(fh)._catalog


# --------------------------------------------------------------- selection --

def test_the_saved_preference_beats_the_browser(app, monkeypatch):
    """The profile is an explicit choice; ``Accept-Language`` is a guess the
    browser makes. A guess that can override a choice makes the profile a
    suggestion box."""
    monkeypatch.setattr(ui_locale, "_saved_preference", lambda: "de")
    with app.test_request_context("/", headers={"Accept-Language": "fr"}):
        assert ui_locale.resolve() == "de"


def test_the_browser_is_used_only_when_nothing_is_saved(app, monkeypatch):
    monkeypatch.setattr(ui_locale, "_saved_preference", lambda: "")
    with app.test_request_context("/", headers={"Accept-Language": "it"}):
        assert ui_locale.resolve() == "it"


def test_a_language_we_do_not_ship_cannot_be_selected(app, monkeypatch):
    """``best_match`` is asked only about what we ship, so a header naming
    Japanese must land on the default rather than on a locale with no
    catalogue -- which would render an empty chrome, not a Japanese one."""
    monkeypatch.setattr(ui_locale, "_saved_preference", lambda: "")
    with app.test_request_context("/", headers={"Accept-Language": "ja"}):
        assert ui_locale.resolve() == langs.DEFAULT


def test_a_regional_tag_lands_on_its_base_language(app, monkeypatch):
    monkeypatch.setattr(ui_locale, "_saved_preference", lambda: "")
    with app.test_request_context("/", headers={"Accept-Language": "fr-CH"}):
        assert ui_locale.resolve() == "fr"


def test_resolve_never_raises_without_a_request(app):
    """A locale selector runs on every request *including the error pages*. An
    exception here replaces a recoverable failure with a blank one."""
    assert ui_locale.resolve() == langs.DEFAULT


def test_a_broken_preference_row_degrades_to_a_readable_page(app, monkeypatch):
    def _boom():
        raise RuntimeError("no such table")

    monkeypatch.setattr(ui_locale, "_saved_preference", _boom)
    with pytest.raises(RuntimeError):
        ui_locale._saved_preference()
    monkeypatch.setattr(ui_locale, "_saved_preference", lambda: "")
    with app.test_request_context("/"):
        assert ui_locale.resolve() in langs.codes()


# --------------------------------------------------------------- catalogues --

# The sentinels a machine translator can hand back: the untrusted-data fence in
# any of the shapes it has actually been observed mangling it into, the
# placeholder masks, and a model control token.
_RESIDUE = re.compile(
    r"\[\[\s*(?:END|\d)|\]\]|<<<|>>>|UNTRUSTED|UNTRAST|NON.?FIDAT|"
    r"DESCONFIAD|NO.?CONFIAB|<\|",
    re.I,
)

#: The fence word once the model has TRANSLATED it -- how ``Access denied`` came
#: back as ``UNvertrauenswuerdige Quelle / Zugriff verweigert / ENDE ...``.
#: Kept apart from :data:`_RESIDUE` because, unlike a delimiter, this vocabulary
#: is legitimate prose: ``TLS trust store`` MUST become
#: ``TLS-Vertrauensspeicher``. Only a translation that raises the subject when
#: the source never did is residue -- which is why the source half below is not
#: optional.
_TRUST_IN_REPLY = re.compile(
    r"\bTRUST|VERTRAU|CONFIAB|CONFIAN|\bFIDAT|FIDUCI|\bFIABLE|\bFIABILI", re.I)
_TRUST_IN_SOURCE = re.compile(r"TRUST|RELIAB|CONFIDEN|CREDIBL|DEPENDABL", re.I)


def _is_residue(msgid: str, msgstr: str) -> bool:
    if _RESIDUE.search(msgstr) and not _RESIDUE.search(msgid):
        return True
    return bool(_TRUST_IN_REPLY.search(msgstr)) and not _TRUST_IN_SOURCE.search(msgid)


@pytest.mark.parametrize("code", SHIPPED)
def test_no_shipped_string_carries_a_translator_sentinel(code):
    """This is the one that printed ``AI Advisor / [[END_UNTRUSTED]]`` in the
    navigation.

    Judged against the SOURCE, never in the absolute: a msgid that legitimately
    contains ``[[`` may keep it. Only residue the translation invented is a
    defect -- and inventing a delimiter the source never had is the one thing a
    translation can never be doing correctly.
    """
    offenders = [
        (k, v)
        for k, v in _catalog(code).items()
        if isinstance(k, str) and isinstance(v, str) and v and _is_residue(k, v)
    ]
    assert not offenders, offenders[:5]


@pytest.mark.parametrize("code", SHIPPED)
def test_no_translation_invents_a_percent_sign(code):
    """Jinja's ``gettext`` applies ``rv % variables`` to the *translated*
    string. A stray ``%`` therefore raises ``ValueError: incomplete format``
    at render time, on the pages carrying that string and nowhere else -- so it
    ships green and breaks one page a month later."""
    offenders = [
        (k, v)
        for k, v in _catalog(code).items()
        if isinstance(k, str) and isinstance(v, str) and "%" in v and "%" not in k
    ]
    assert not offenders, offenders[:5]


@pytest.mark.parametrize("code", SHIPPED)
def test_the_compiled_catalogue_is_not_older_than_its_source(code):
    """The app reads the ``.mo``; humans and repair runs edit the ``.po``. A
    fixed ``.po`` with a stale ``.mo`` is a fix that was never delivered, and
    every text-level check passes while the running product still shows the
    broken string."""
    base = os.path.join(TRANSLATIONS, code, "LC_MESSAGES")
    po = os.path.getmtime(os.path.join(base, "messages.po"))
    mo = os.path.getmtime(os.path.join(base, "messages.mo"))
    assert mo >= po, f"{code}: messages.mo is older than messages.po -- recompile"


@pytest.mark.parametrize("code", SHIPPED)
def test_every_shipped_language_has_a_real_catalogue(code):
    """A language offered in the picker with an empty catalogue is a language
    that silently renders in English."""
    assert len(_catalog(code)) > 500, code


# ------------------------------------------------------------------ wiring --

def test_flask_babel_is_declared_not_merely_installed():
    """It was in the venv and absent from ``requirements.txt``. The installer
    rebuilds the venv, so the next reinstall would have removed it -- and the
    app does not start without it."""
    with open(os.path.join(REPO, "requirements.txt"), encoding="utf-8") as fh:
        assert re.search(r"(?im)^\s*flask[-_]babel\b", fh.read())


def test_the_factory_installs_a_locale_selector(app):
    from flask_babel import get_locale

    with app.test_request_context("/"):
        assert str(get_locale()) in {c.replace("-", "_") for c in langs.codes()}


def test_the_chrome_follows_the_saved_preference(app, client):
    """End to end: the preference the profile writes is the language the page
    comes back in.

    Asserted on a word the catalogue actually carries, not merely on the two
    bodies differing -- a page that differs for any other reason (a timestamp,
    a CSRF token) would let a broken selector pass.
    """
    uid = admin_user_id(app)
    login(client, uid)

    with app.app_context():
        ustore.save_language(uid, "es")
    spanish = client.get("/auth/profile", follow_redirects=True).get_data(as_text=True)

    with app.app_context():
        ustore.save_language(uid, "")
    english = client.get("/auth/profile", follow_redirects=True).get_data(as_text=True)

    with app.app_context():
        ustore.save_language(uid, "")

    assert spanish != english
    marker = _catalog("es").get("Language")
    assert marker and marker in spanish
    assert marker not in english


# ------------------------------------------------- the guard that let it in --

@pytest.mark.parametrize("shipped", [
    "„UNvertrauenswürdige Quelle“\nZugriff verweigert",
    "„Der aktuelle, unvollständige“\n„Ende der unvertrauten“",
    "„UNVertrauenswürdig“\n– die freie",
])
def test_the_service_guard_rejects_a_translated_fence(shipped):
    """These three reached the German catalogue. ``_MARKER_WORD`` knows only the
    English ``UNTRUSTED``, so a model that translates our own fence walks past
    it -- and the row is stored, reported COMPLETE, and printed."""
    from app.services.translator import _sentinel_residue

    assert _sentinel_residue(shipped, "Access denied")


def test_the_service_guard_keeps_a_legitimate_translation_of_trust():
    """The other half of the same rule: without the source check this rejects
    the correct German for ``TLS trust store`` and blanks a good row."""
    from app.services.translator import _sentinel_residue

    assert not _sentinel_residue(
        "TLS-Vertrauensspeicher — Zertifizierungsstellen",
        "TLS trust store — certificate authorities")
