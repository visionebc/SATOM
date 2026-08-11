"""Guards for the language registry and the translation ledger.

None of what this file protects FAILS when it breaks — that is why it exists:

* a second author of the language list does not raise, it just offers a
  language nothing can render;
* a stale translation renders perfectly, in confident prose, describing a
  source the author already retracted;
* a machine translation stored as human is indistinguishable from the
  operator's own declaration in the signed change document;
* a provider call that is never billed makes the feature look free.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.models import db
from app.models_i18n import (ORIGIN_HUMAN, ORIGIN_MACHINE, TranslationRun,
                             TranslationUnit, source_digest)
from app.services import langs, translator
from app.services.advisor_providers import ChatResult

APP_DIR = Path(__file__).resolve().parents[1] / "app"


def _Res(content, prompt_tokens=11, completion_tokens=22):
    """What advisor_providers.send returns — the PRODUCTION class.

    This was a hand-rolled double whose field was named .content.  The reader
    in translator.py had the same typo, so the double and the defect agreed
    with each other and 34 guards passed over a layer that had never produced
    a single translation.  A test double for a provider result must BE the
    provider result.
    """
    return ChatResult(text=content, prompt_tokens=prompt_tokens,
                      completion_tokens=completion_tokens)


@pytest.fixture()
def local_provider(monkeypatch):
    """A configured LOCAL provider — the safe default the product ships."""
    prov = {"key": "ollama-local", "kind": "ollama", "label": "Local",
            "base_url": "http://127.0.0.1:11434", "model": "qwen2.5:7b"}
    monkeypatch.setattr(translator.advisor, "get_provider",
                        lambda k: prov if k in ("", None, "ollama-local") else None)
    monkeypatch.setattr(translator.advisor, "default_provider_key",
                        lambda: "ollama-local")
    monkeypatch.setattr(translator.advisor, "_provider_secret", lambda k: "")
    return prov


def _send(monkeypatch, fn):
    monkeypatch.setattr(translator, "_provider_send", fn)


# ---------------------------------------------------------------------------
# the registry
# ---------------------------------------------------------------------------

def test_the_five_languages_the_product_claims():
    assert langs.codes() == ("en", "es", "de", "fr", "it")


def test_english_is_the_source_language_and_comes_first():
    # Every translation derives from exactly one origin. If the default were
    # not first in the list it would also stop being the picker's default.
    assert langs.DEFAULT == "en"
    assert langs.codes()[0] == "en"


def test_regional_tags_degrade_to_their_base_language():
    # de-CH must reach German, not fall through to English just because the
    # browser was more specific than the catalogue.
    for tag in ("de-CH", "de_AT", "DE", " de "):
        assert langs.normalize(tag) == "de"
    assert langs.normalize("es-MX") == "es"


def test_an_unknown_or_broken_language_never_raises():
    for bad in (None, "", 17, "klingon", object(), [], "zz-ZZ"):
        assert langs.normalize(bad) == langs.DEFAULT


def test_is_supported_rejects_what_normalize_would_have_defaulted():
    # normalize() is lenient by design; is_supported() must NOT be, or an
    # admin form would accept "klingon" and store English under that name.
    assert langs.is_supported("de-CH") is True
    assert langs.is_supported("klingon") is False
    assert langs.is_supported("") is False


def test_every_language_has_an_endonym_and_label_never_returns_empty():
    for code in langs.codes():
        assert langs.label(code).strip()
    assert langs.label("klingon").strip()   # degrades, never blank


def test_others_excludes_only_the_given_language():
    assert langs.others("en") == ("es", "de", "fr", "it")
    assert langs.others("de-CH") == ("en", "es", "fr", "it")


def test_the_registry_is_the_only_author_of_the_language_list():
    """cr_document must READ the registry, not keep a second copy.

    Two lists is how a picker offers a language the renderer cannot produce.
    Asserting on the source (not on the value) is deliberate: a duplicated
    literal that happens to agree today passes a value check and diverges on
    the next edit.
    """
    src = (APP_DIR / "services" / "cr_document.py").read_text(encoding="utf-8")
    src = re.sub(r"#.*", "", src)          # a comment may legitimately name it
    src = re.sub(r'""".*?"""', "", src, flags=re.S)
    assert not re.search(r"^LANGS\s*[:=]", src, flags=re.M), (
        "cr_document must not re-introduce a module-level LANGS constant: a "
        "tuple fixed at import can only describe the languages authored in "
        "Python, so every picker reading it is blind to the translated "
        "catalogue")
    # The derivation lives in ``renderable_langs`` and ``document_langs``
    # narrows it by the install's availability gate. The guard follows the
    # code rather than the other way round: anchoring on "document_langs
    # mentions langs.codes()" would fail against a correct split (it did, when
    # the gate was added) while still passing against a second hardcoded list
    # in the function next to it -- an anchor that reports the wrong thing in
    # both directions.
    def _body(name: str) -> str:
        m = re.search(r"def %s\(\).*?\n(.*?)\n\n\ndef " % name, src, flags=re.S)
        assert m, f"cr_document must still declare {name}()"
        return m.group(1)

    derive = _body("renderable_langs")
    assert "langs.codes()" in derive and "langs.label(" in derive, (
        "renderable_langs() must derive order and labels from services.langs, "
        f"not re-list the languages itself; found: {derive!r}")
    gate = _body("document_langs")
    assert "renderable_langs()" in gate, (
        "document_langs() must narrow renderable_langs(), not re-derive the "
        f"list: a second derivation is a second author; found: {gate!r}")
    assert "langs.label(" not in gate, (
        "document_langs() must not label languages itself -- two labellers is "
        f"how one of them goes stale; found: {gate!r}")


def test_the_document_picker_only_offers_languages_it_can_render():
    """A language with no authored action profiles must NOT appear in the CR
    picker: choosing it would produce a document half in English."""
    from app.services import cr_document
    offered = {c for c, _ in cr_document.document_langs()}
    assert offered <= set(langs.codes())
    for code in offered:
        assert cr_document._profile_text("reboot", code), \
            f"{code} is offered but has no authored profile"


# ---------------------------------------------------------------------------
# staleness — the reason source_hash exists
# ---------------------------------------------------------------------------

def test_editing_the_source_makes_every_translation_stale(app):
    with app.app_context():
        translator.set_source("cr_field", "title.label", "Title", username="ana")
        translator.store_translation("cr_field", "title.label", "es", "Título",
                                     source_text="Title", source_lang="en",
                                     model="m")
        unit = translator.get_unit("cr_field", "title.label", "es")
        assert unit.is_stale("Title") is False
        assert unit.is_stale("Change title") is True


def test_whitespace_only_edits_count_as_edits(app):
    # Whitespace changes the rendered document, so it genuinely invalidates.
    with app.app_context():
        translator.store_translation("ns", "k", "es", "Hola",
                                     source_text="Hello", source_lang="en")
        assert translator.get_unit("ns", "k", "es").is_stale("Hello ") is True


def test_a_source_row_is_never_stale(app):
    with app.app_context():
        unit = translator.set_source("ns", "k", "Hello")
        assert unit.source_hash == ""
        assert unit.is_stale("anything at all") is False


def test_source_digest_is_of_the_exact_bytes():
    assert source_digest("a") != source_digest("a ")
    assert source_digest("") == source_digest(None)


# ---------------------------------------------------------------------------
# provenance — a machine translation is labelled as one, forever
# ---------------------------------------------------------------------------

def test_a_machine_translation_is_stored_as_machine_with_its_model(app):
    with app.app_context():
        translator.store_translation("ns", "k", "fr", "Bonjour",
                                     source_text="Hello", source_lang="en",
                                     model="qwen2.5:7b", provider_key="p1")
        unit = translator.get_unit("ns", "k", "fr")
        assert unit.origin == ORIGIN_MACHINE
        assert unit.model == "qwen2.5:7b"
        assert unit.reviewed is False


def test_a_machine_translation_never_overwrites_human_text(app):
    with app.app_context():
        translator.set_source("ns", "k", "Hola", lang="es", username="ana")
        with pytest.raises(translator.TranslationError):
            translator.store_translation("ns", "k", "es", "Machine text",
                                         source_text="Hello", source_lang="en")
        assert translator.get_unit("ns", "k", "es").text == "Hola"
        assert translator.get_unit("ns", "k", "es").origin == ORIGIN_HUMAN


def test_re_translating_clears_a_previous_review(app):
    # The reviewer approved different words; carrying the flag forward would
    # present unreviewed text as reviewed.
    with app.app_context():
        u = translator.store_translation("ns", "k", "it", "Ciao",
                                         source_text="Hello", source_lang="en")
        u.reviewed, u.reviewed_by = True, "ana"
        db.session.commit()
        translator.store_translation("ns", "k", "it", "Salve",
                                     source_text="Hi", source_lang="en")
        unit = translator.get_unit("ns", "k", "it")
        assert unit.reviewed is False and unit.reviewed_by == ""


# ---------------------------------------------------------------------------
# the ledger — every call is billed, including the failures
# ---------------------------------------------------------------------------

def test_a_successful_call_records_time_and_tokens(app, local_provider,
                                                   monkeypatch):
    with app.app_context():
        _send(monkeypatch, lambda *a, **k: _Res("Hola", 30, 12))
        res = translator.translate("Hello", src="en", dst="es",
                                   namespace="ns", key="k", username="ana")
        assert res.text == "Hola"
        run = TranslationRun.query.one()
        assert run.ok is True and run.target_lang == "es"
        assert run.prompt_tokens == 30 and run.completion_tokens == 12
        assert run.total_tokens == 42
        assert run.duration_ms >= 0
        assert run.chars_in == 5 and run.chars_out == 4
        assert run.username == "ana" and run.model == "qwen2.5:7b"


def test_a_FAILED_call_is_billed_too(app, local_provider, monkeypatch):
    with app.app_context():
        def boom(*a, **k):
            raise RuntimeError("connection refused")
        _send(monkeypatch, boom)
        with pytest.raises(translator.TranslationError):
            translator.translate("Hello", src="en", dst="es", namespace="ns",
                                 key="k")
        run = TranslationRun.query.one()
        assert run.ok is False and "connection refused" in run.error
        # A ledger that only records successes cannot answer why a language
        # is missing.
        assert TranslationUnit.query.count() == 0


def test_an_empty_reply_is_a_failure_not_an_empty_translation(app,
                                                              local_provider,
                                                              monkeypatch):
    with app.app_context():
        _send(monkeypatch, lambda *a, **k: _Res("   "))
        with pytest.raises(translator.TranslationError):
            translator.translate("Hello", src="en", dst="es")
        assert TranslationRun.query.one().ok is False


def test_unreported_tokens_stay_None_and_are_not_counted_as_zero(app,
                                                                 local_provider,
                                                                 monkeypatch):
    with app.app_context():
        _send(monkeypatch, lambda *a, **k: _Res("Hola", None, None))
        translator.translate("Hello", src="en", dst="es")
        run = TranslationRun.query.one()
        assert run.prompt_tokens is None and run.total_tokens is None
        summary = translator.usage_summary()
        assert summary["prompt_tokens"] is None
        assert summary["unreported_token_calls"] == 1


def test_usage_summary_counts_failures_and_their_wall_time(app, local_provider,
                                                           monkeypatch):
    with app.app_context():
        _send(monkeypatch, lambda *a, **k: _Res("Hola", 5, 5))
        translator.translate("Hello", src="en", dst="es")

        def boom(*a, **k):
            raise RuntimeError("timeout")
        _send(monkeypatch, boom)
        with pytest.raises(translator.TranslationError):
            translator.translate("Hello", src="en", dst="de")

        s = translator.usage_summary()
        assert s["calls"] == 2 and s["ok"] == 1 and s["failed"] == 1


# ---------------------------------------------------------------------------
# the boundary — a translation is not worth crossing the redaction line
# ---------------------------------------------------------------------------

def test_no_provider_configured_is_a_clear_error_not_a_crash(app, monkeypatch):
    with app.app_context():
        monkeypatch.setattr(translator.advisor, "get_provider", lambda k: None)
        monkeypatch.setattr(translator.advisor, "default_provider_key",
                            lambda: "")
        with pytest.raises(translator.TranslationError) as e:
            translator.translate("Hello", src="en", dst="es")
        assert "provider" in str(e.value).lower()


def test_an_external_provider_still_needs_the_external_gate(app, monkeypatch):
    prov = {"key": "oai", "kind": "openai", "base_url": "https://api.x",
            "model": "gpt"}
    with app.app_context():
        monkeypatch.setattr(translator.advisor, "get_provider", lambda k: prov)
        monkeypatch.setattr(translator.advisor, "default_provider_key",
                            lambda: "oai")
        monkeypatch.setattr(translator.advisor, "external_allowed",
                            lambda: False)
        called = []
        _send(monkeypatch, lambda *a, **k: called.append(1) or _Res("x"))
        with pytest.raises(translator.TranslationError):
            translator.translate("Hello", src="en", dst="es")
        assert not called, "the gate must stop the call, not report it after"


def test_text_that_would_be_redacted_is_refused_not_sent_with_holes(
        app, monkeypatch):
    prov = {"key": "oai", "kind": "openai", "base_url": "https://api.x",
            "model": "gpt"}
    with app.app_context():
        monkeypatch.setattr(translator.advisor, "get_provider", lambda k: prov)
        monkeypatch.setattr(translator.advisor, "default_provider_key",
                            lambda: "oai")
        monkeypatch.setattr(translator.advisor, "external_allowed",
                            lambda: True)
        monkeypatch.setattr(translator.advisor, "redact_with_count",
                            lambda t: ("[REDACTED]", 1))
        called = []
        _send(monkeypatch, lambda *a, **k: called.append(1) or _Res("x"))
        with pytest.raises(translator.TranslationError) as e:
            translator.translate("reboot fortiweb08", src="en", dst="es")
        assert not called
        assert "redact" in str(e.value).lower()


def test_a_local_provider_sends_the_text_verbatim(app, local_provider,
                                                  monkeypatch):
    seen = {}

    def capture(kind, **kw):
        seen.update(kw)
        return _Res("Hola")
    with app.app_context():
        _send(monkeypatch, capture)
        translator.translate("reboot fortiweb08", src="en", dst="es")
        body = seen["messages"][0]["content"]
        assert "fortiweb08" in body, "local traffic must not be redacted"


def test_the_payload_is_wrapped_as_untrusted_data(app, local_provider,
                                                  monkeypatch):
    """The string being translated is operator input. Unwrapped, 'ignore the
    previous instructions' inside a rollback plan is an instruction."""
    seen = {}

    def capture(kind, **kw):
        seen.update(kw)
        return _Res("Hola")
    with app.app_context():
        _send(monkeypatch, capture)
        translator.translate("Hello", src="en", dst="es")
        raw = seen["messages"][0]["content"]
        assert raw != "Hello", "the payload was passed through unwrapped"
        assert "Hello" in raw
        assert "DATA" in seen["system"] or "data" in seen["system"]


# ---------------------------------------------------------------------------
# fan-out
# ---------------------------------------------------------------------------

def test_a_save_fans_out_to_the_other_four_languages(app, local_provider,
                                                     monkeypatch):
    with app.app_context():
        _send(monkeypatch, lambda *a, **k: _Res("T", 3, 4))
        translator.set_source("ns", "k", "Hello", username="ana")
        rep = translator.fan_out("ns", "k", "Hello", username="ana")
        assert rep["ok"] == 4
        assert set(rep["targets"]) == {"es", "de", "fr", "it"}
        assert rep["prompt_tokens"] == 12 and rep["completion_tokens"] == 16
        assert TranslationRun.query.count() == 4


def test_one_failed_language_does_not_lose_the_other_three(app, local_provider,
                                                           monkeypatch):
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("model unloaded")
        return _Res("T")
    with app.app_context():
        _send(monkeypatch, flaky)
        rep = translator.fan_out("ns", "k", "Hello")
        assert rep["ok"] == 3 and rep["failed"] == 1
        failed = [c for c, v in rep["targets"].items()
                  if v["status"] == "failed"]
        assert len(failed) == 1
        assert "model unloaded" in rep["targets"][failed[0]]["error"]


def test_a_rerun_is_idempotent_and_does_not_re_bill(app, local_provider,
                                                    monkeypatch):
    with app.app_context():
        _send(monkeypatch, lambda *a, **k: _Res("T"))
        translator.fan_out("ns", "k", "Hello")
        assert TranslationRun.query.count() == 4
        rep = translator.fan_out("ns", "k", "Hello")
        assert rep["ok"] == 0 and rep["skipped"] == 4
        assert TranslationRun.query.count() == 4, "a no-op re-run was billed"


def test_a_changed_source_DOES_re_translate(app, local_provider, monkeypatch):
    with app.app_context():
        _send(monkeypatch, lambda *a, **k: _Res("T"))
        translator.fan_out("ns", "k", "Hello")
        rep = translator.fan_out("ns", "k", "Goodbye")
        assert rep["ok"] == 4, "stale translations were left in place"


def test_fan_out_keeps_human_translations_even_when_stale(app, local_provider,
                                                          monkeypatch):
    with app.app_context():
        _send(monkeypatch, lambda *a, **k: _Res("T"))
        translator.set_source("ns", "k", "Hola corregido", lang="es",
                              username="ana")
        rep = translator.fan_out("ns", "k", "Hello")
        assert rep["targets"]["es"]["status"] == "kept-human"
        assert translator.get_unit("ns", "k", "es").text == "Hola corregido"


def test_translating_into_the_source_language_is_refused(app, local_provider,
                                                         monkeypatch):
    with app.app_context():
        _send(monkeypatch, lambda *a, **k: _Res("T"))
        with pytest.raises(translator.TranslationError):
            translator.translate("Hello", src="en", dst="en")
        assert TranslationRun.query.count() == 0


def test_catalogue_reports_staleness_against_the_source_it_is_asked_about(
        app, local_provider, monkeypatch):
    with app.app_context():
        _send(monkeypatch, lambda *a, **k: _Res("T"))
        translator.fan_out("ns", "k", "Hello")
        cat = translator.catalogue("ns", "k", "Hello")
        assert all(v["stale"] is False for v in cat.values())
        cat = translator.catalogue("ns", "k", "Goodbye")
        assert all(v["stale"] is True for v in cat.values())


def test_a_whole_fence_is_stripped_but_an_inner_one_is_content():
    assert translator._clean("```\nHola\n```") == "Hola"
    assert translator._clean("```text\nHola\n```") == "Hola"
    body = "Paso 1\n```\nexecute reboot\n```\nPaso 2"
    assert translator._clean(body) == body
