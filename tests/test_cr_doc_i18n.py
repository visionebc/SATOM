"""Guards for the translated change-request document.

Every failure this file protects against is SILENT:

* a translation layer that reads the wrong attribute off the provider result
  returns "" for every call and reports it as "the provider returned an empty
  translation" -- blaming the model for a reader bug.  That shipped, and the
  test that should have caught it built its own double with the buggy
  attribute name, so the test and the defect agreed with each other.  Hence
  :func:`test_the_provider_double_is_the_production_class`.
* a model that echoes the untrusted fence stores a Spanish paragraph that
  literally begins ``<<<NO CONFIABLE>>>`` inside a signed document.
* a model that rewrites `` `fortiweb08` `` as ``{fortiweb08}`` invents a
  placeholder the renderer cannot fill and prints VERBATIM.
* a half-filled catalogue renders a document half in Spanish and half in
  English under an approver's signature line, and nothing raises.
"""
from __future__ import annotations

import pytest

from app.models import db
from app.models_i18n import ORIGIN_HUMAN, ORIGIN_MACHINE, TranslationUnit, source_digest
from app.services import cr_document as doc
from app.services import cr_i18n, langs, translator
from app.services.advisor_providers import ChatResult


@pytest.fixture()
def local_provider(monkeypatch):
    """A configured LOCAL provider — no redaction gate, no network."""
    prov = {"key": "ollama-local", "kind": "ollama", "label": "Local",
            "base_url": "http://127.0.0.1:11434", "model": "aya-expanse:8b"}
    monkeypatch.setattr(translator.advisor, "get_provider",
                        lambda k: prov if k in ("", None, "ollama-local") else None)
    monkeypatch.setattr(translator.advisor, "default_provider_key",
                        lambda: "ollama-local")
    monkeypatch.setattr(translator.advisor, "_provider_secret", lambda k: "")
    return prov

@pytest.fixture()
def ctx(app):
    """An application context — the app fixture builds the app but does
    not push one, and every catalogue read needs the ORM bound."""
    with app.app_context():
        yield app


# --------------------------------------------------------------------------- #
#  the reader bug that shipped                                                  #
# --------------------------------------------------------------------------- #

def test_the_provider_double_is_the_production_class():
    """A hand-rolled stand-in can carry an attribute the real result does not.

    That is exactly how ``getattr(res, "content", "")`` survived review: the
    only thing that ever exercised it was a double that HAD ``.content``.
    """
    assert not hasattr(ChatResult(text="x"), "content"), (
        "ChatResult grew a .content attribute — update translator._clean's "
        "reader and this guard together, or the two will drift again")
    assert ChatResult(text="x").text == "x"


def test_a_successful_call_returns_the_providers_text(ctx, local_provider, monkeypatch):
    monkeypatch.setattr(translator, "_provider_send",
                        lambda *a, **k: ChatResult(text="Reinicie el equipo."))
    res = translator.translate("Reboot the appliance.", src="en", dst="es")
    assert res.text == "Reinicie el equipo.", (
        "translate() must read ChatResult.text; a default-bearing getattr on "
        "the wrong name degrades EVERY call to an empty translation")


# --------------------------------------------------------------------------- #
#  the echoed fence                                                             #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("open_tag,close_tag", [
    ("<<<UNTRUSTED>>>", "<<<END_UNTRUSTED>>>"),
    ("<<<NO CONFIABLE>>>", "<<<FIN_NO CONFIABLE>>>"),   # observed from aya-expanse
    ("<<<NON CONFIABLE>>>", "<<<FIN_NON CONFIABLE>>>"),
    ("<<<NON fidato>>>", "<<<FINE NON fidato>>>"),
])
def test_an_echoed_fence_is_stripped_in_any_language(open_tag, close_tag):
    raw = f"{open_tag}\nReinicie el dispositivo.\n{close_tag}"
    assert translator._clean(raw) == "Reinicie el dispositivo."


def test_a_trailing_backtick_after_the_fence_does_not_defeat_the_strip():
    raw = "<<<NON fidato>>>\nRiavvia.\n<<<FINE NON fidato>>>`"
    assert translator._clean(raw) == "Riavvia."


def test_a_fence_shaped_line_in_the_MIDDLE_is_content():
    """Deleting it would silently drop part of a rollback plan."""
    raw = "Step one.\n<<<MARKER>>>\nStep two."
    assert translator._clean(raw) == raw


# --------------------------------------------------------------------------- #
#  token drift                                                                  #
# --------------------------------------------------------------------------- #

def test_an_invented_placeholder_ALONE_is_drift():
    """Isolated on purpose.  The realistic sample (`fortiweb08` -> `{fortiweb08}`)
    trips BOTH the invented-placeholder and the altered-literal branch, so it
    still fails with either one deleted — and a mutation that removes a real
    check then reads as covered.  No backticks here: only the brace is new."""
    d = translator._token_drift("Reboot the appliance now.",
                                "Reinicie el {aparato} ahora.")
    assert "invented" in d and "{aparato}" in d


def test_an_altered_backticked_literal_ALONE_is_drift():
    """Same isolation for the other branch: no placeholders anywhere, only a
    field identifier the model decided to translate."""
    d = translator._token_drift("Set `approved_by` before signing.",
                                "Defina `aprobado_por` antes de firmar.")
    assert "literal" in d and "approved_by" in d


def test_an_invented_placeholder_is_drift():
    # aya-expanse actually produced this, in Italian.
    d = translator._token_drift("Reboot `fortiweb08`.", "Riavvia `{fortiweb08}`.")
    assert d, "a brace added around a literal must be caught"
    assert "fortiweb08" in d


def test_a_dropped_placeholder_is_drift():
    d = translator._token_drift("Upgrade {devices} now.", "Actualice ahora.")
    assert "{devices}" in d


def test_identical_tokens_are_not_drift():
    assert translator._token_drift(
        "Run {action} on `fortiweb08`.",
        "Ejecute {action} en `fortiweb08`.") == ""


def test_a_drifted_translation_is_refused_not_stored(ctx, local_provider, monkeypatch):
    calls = []

    def _send(*a, **k):
        calls.append(k.get("system", ""))
        return ChatResult(text="Riavvia `{fortiweb08}`.")

    monkeypatch.setattr(translator, "_provider_send", _send)
    with pytest.raises(translator.TranslationError) as exc:
        translator.translate("Reboot `fortiweb08`.", src="en", dst="it")
    assert "load-bearing tokens" in str(exc.value)
    assert len(calls) == 2, "drift must get exactly one corrective retry"


def test_the_retry_does_not_crash_on_the_system_prompts_own_placeholder(
        ctx, local_provider, monkeypatch):
    """``_SYSTEM`` contains ``{name}`` as the example placeholder to preserve.

    Formatting the WHOLE system string turns every retry into KeyError('name')
    — which surfaces to the operator as a provider failure.
    """
    assert "{name}" in translator._SYSTEM
    seen = []

    def _send(*a, **k):
        seen.append(k.get("system", ""))
        return ChatResult(text="Riavvia `{fortiweb08}`.")

    monkeypatch.setattr(translator, "_provider_send", _send)
    with pytest.raises(translator.TranslationError) as exc:
        translator.translate("Reboot `fortiweb08`.", src="en", dst="it")
    assert "name" != str(exc.value).strip("'"), "retry raised KeyError('name')"
    assert "{name}" in seen[1], "the retry must keep the rules intact"
    assert "corrupted" in seen[1], "the retry must say what went wrong"


# --------------------------------------------------------------------------- #
#  the catalogue                                                                #
# --------------------------------------------------------------------------- #

def test_the_source_catalogue_covers_all_four_document_regions():
    units = cr_i18n.source_units()
    regions = {k.split(".")[0] for k in units}
    assert regions == {"titles", "t", "draft", "profile"}, (
        "a region dropped out of the catalogue does not fail — it renders in "
        "English inside an otherwise translated document")
    assert len(units) > 250


def test_every_profiled_action_contributes_its_required_keys():
    units = cr_i18n.source_units()
    for action in doc.ACTION_PROFILES:
        for key in doc.REQUIRED_PROFILE_KEYS:
            prefix = f"profile.{action}.{key}"
            assert any(k == prefix or k.startswith(prefix + ".") for k in units), \
                f"{prefix} is not translatable"


def test_overlay_preserves_shape_not_just_words():
    """A tuple that comes back as a string renders as one run-on step."""
    node = {"purpose": "A", "work": ("one", "two")}
    out = cr_i18n.overlay(node, "p", {"p.purpose": "Objetivo",
                                      "p.work.0": "uno", "p.work.1": "dos"})
    assert out == {"purpose": "Objetivo", "work": ("uno", "dos")}
    assert isinstance(out["work"], tuple)


def test_overlay_falls_back_to_english_never_to_blank():
    out = cr_i18n.overlay({"purpose": "A", "risk": "B"}, "p", {"p.purpose": "Objetivo"})
    assert out == {"purpose": "Objetivo", "risk": "B"}


# --------------------------------------------------------------------------- #
#  offering a language                                                          #
# --------------------------------------------------------------------------- #

def _fill(lang, *, skip=0, stale_keys=()):
    units = cr_i18n.source_units()
    keys = sorted(units)
    for key in keys[skip:]:
        text = units[key]
        src = "DIFFERENT SOURCE" if key in stale_keys else text
        db.session.add(TranslationUnit(
            namespace=cr_i18n.NAMESPACE, key=key, lang=lang,
            text=f"[{lang}] {text}", origin=ORIGIN_MACHINE,
            source_hash=source_digest(src), source_lang="en"))
    db.session.commit()


def test_no_catalogue_means_only_the_authored_languages(ctx):
    assert {c for c, _ in doc.document_langs()} == set(doc.AUTHORED_LANGS)


def test_a_partial_catalogue_does_NOT_offer_the_language(ctx):
    _fill("es", skip=1)          # one unit short of complete
    cov = cr_i18n.coverage("es")
    assert cov["missing"], "fixture did not actually leave a gap"
    assert not cov["complete"]
    assert "es" not in {c for c, _ in doc.document_langs()}, (
        "one missing unit means one English paragraph under a signature line")


def test_a_complete_catalogue_offers_the_language_in_registry_order(ctx):
    _fill("es")
    assert cr_i18n.coverage("es")["complete"]
    assert doc.document_langs() == (("en", "English"), ("es", "Español"),
                                    ("de", "Deutsch"))


def test_a_single_stale_unit_withdraws_the_whole_language(ctx):
    keys = sorted(cr_i18n.source_units())
    _fill("es", stale_keys={keys[5]})
    cov = cr_i18n.coverage("es")
    assert cov["stale"] == [keys[5]]
    assert not cov["complete"], (
        "stale is not 'slightly old': it is prose describing a source the "
        "author already retracted")
    assert "es" not in {c for c, _ in doc.document_langs()}


def test_normalize_lang_degrades_an_unrenderable_language_to_english(ctx):
    assert doc.normalize_lang("es") == "en"
    assert doc.normalize_lang("zz") == "en"
    assert doc.normalize_lang("de-CH") == "de"


def test_normalize_lang_accepts_a_language_once_it_is_complete(ctx):
    _fill("es")
    assert doc.normalize_lang("es") == "es"


# --------------------------------------------------------------------------- #
#  rendering                                                                    #
# --------------------------------------------------------------------------- #

def test_the_overlay_reaches_the_rendered_document(ctx):
    _fill("es")
    titles = doc.SECTION_TITLES["es"]
    assert all(t.startswith("[es] ") for t in titles)
    assert isinstance(titles, tuple)
    profile = doc.ACTION_PROFILES["upgrade"]["es"]
    assert profile["purpose"].startswith("[es] ")
    assert isinstance(profile["work"], tuple)


def test_an_unavailable_language_raises_rather_than_silently_serving_english(ctx):
    with pytest.raises(KeyError):
        doc._T["fr"]


# --------------------------------------------------------------------------- #
#  the constant that had to go                                                  #
# --------------------------------------------------------------------------- #

def test_there_is_exactly_one_author_of_the_offered_language_list():
    assert not hasattr(doc, "LANGS"), (
        "cr_document.LANGS was a module-level tuple: it could only ever "
        "describe the languages authored in Python, so every picker reading "
        "it was blind to the translated catalogue. document_langs() is the "
        "one answer")
    assert "document_langs" in doc.__all__


# --------------------------------------------------------------------------- #
#  fence shapes observed in production, one test per shape                      #
# --------------------------------------------------------------------------- #
#  A line-anchored matcher caught only the tidy variant.  Every case below was
#  produced by aya-expanse:8b against SATOM's own strings and reached the
#  catalogue before the matcher was rebuilt.

@pytest.mark.parametrize("raw,expected", [
    # inline with the first words, plus a comma the model added
    ("<<<NO CONFIABLE>>>, firmware al momento {x}", "firmware al momento {x}"),
    # closer only, and malformed
    ("Informazioni generali\n<<<FINE_NON fidato>>", "Informazioni generali"),
    # both ends malformed
    ("<<<NON FIDATO>>/>>\nPrincipali rischi\n<<<FINE NON FIDATO>>/>>",
     "Principali rischi"),
    # a stray backtick right after the opener
    ("<<<NON FIABLE>>>`\nSource : %s\n<<<FIN NON FIABLE>>>`", "Source : %s"),
    # a full stop the model appended after the closer
    ("Gestore Certificati\n<<<FINE NON fidato>>>.", "Gestore Certificati"),
    # doubled angle + parenthesis, seen on a parenthesised source string
    # the parenthesis is the SOURCE's own ("(no devices selected yet)") and
    # must survive; only the angle run is the model's
    ("<<(no se han seleccionado)<<(fin de UNTRUSTED)>>", "(no se han seleccionado)"),
])
def test_every_fence_shape_seen_in_production_is_stripped(raw, expected):
    assert translator._clean(raw) == expected


def test_a_fence_that_survives_cleaning_fails_the_translation(ctx, local_provider,
                                                              monkeypatch):
    """Belt to the braces: an unanticipated shape must not be stored.

    Coverage is computed from stored rows, so one polluted row would report a
    language COMPLETE while the document prints the delimiter.
    """
    monkeypatch.setattr(translator, "_provider_send",
                        lambda *a, **k: ChatResult(text="uno <<<RARO>>> dos"))
    with pytest.raises(translator.TranslationError) as exc:
        translator.translate("one marker two", src="en", dst="es")
    assert "delimiter" in str(exc.value)


def test_a_polluted_row_is_not_counted_as_a_translation(ctx):
    units = cr_i18n.source_units()
    keys = sorted(units)
    for key in keys:
        text = units[key]
        db.session.add(TranslationUnit(
            namespace=cr_i18n.NAMESPACE, key=key, lang="es",
            text=("<<<FIN NO CONFIABLE>>> x" if key == keys[0] else f"[es] {text}"),
            origin=ORIGIN_MACHINE, source_hash=source_digest(text),
            source_lang="en"))
    db.session.commit()
    cov = cr_i18n.coverage("es")
    assert cov["missing"] == [keys[0]]
    assert not cov["complete"]
    assert "es" not in {c for c, _ in doc.document_langs()}


# --------------------------------------------------------------------------- #
#  masking                                                                      #
# --------------------------------------------------------------------------- #

def test_placeholders_are_hidden_from_the_model_not_merely_requested():
    """aya-expanse translates the WORD inside a placeholder: ``{devices}`` came
    back as ``{dispositivos}``, ``{action}`` as ``{azione}``.  Asking a small
    model to preserve a token loses; not showing it the word wins."""
    masked, table = translator._mask("Run {action} on {devices} via `cli`.")
    assert "{action}" not in masked and "{devices}" not in masked
    assert "`cli`" not in masked
    assert table == ["{action}", "{devices}", "`cli`"]
    restored, problem = translator._unmask(masked, table)
    assert problem == ""
    assert restored == "Run {action} on {devices} via `cli`."


def test_printf_placeholders_are_masked_too():
    masked, table = translator._mask("Generated %s for %s.")
    assert "%s" not in masked
    assert table == ["%s", "%s"]


def test_a_lost_marker_is_drift_not_a_silent_truncation(ctx, local_provider,
                                                        monkeypatch):
    monkeypatch.setattr(translator, "_provider_send",
                        lambda *a, **k: ChatResult(text="Ejecute en todos."))
    with pytest.raises(translator.TranslationError) as exc:
        translator.translate("Run {action} on {devices}.", src="en", dst="es")
    assert "marker" in str(exc.value)


def test_masking_leaves_text_without_tokens_untouched():
    masked, table = translator._mask("Reboot the appliance.")
    assert masked == "Reboot the appliance." and table == []


def test_residue_is_judged_against_the_source_not_a_list_of_known_shapes():
    """A source that legitimately contains ``>>`` must not be rejected."""
    assert translator._fence_residue("resultado >> fichero", "output >> file") == ""
    assert translator._fence_residue("resultado >> fichero", "output to file")
