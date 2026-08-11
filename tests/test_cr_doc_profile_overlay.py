"""Guards for the ACTION PROFILE of a translated change-request document.

The defect these protect against was invisible for as long as it mattered
least, and became a 500 the moment it mattered most.

``_Localized.__missing__`` builds a translated language by overlaying the
catalogue onto the authored English.  ``__missing__`` is only consulted by
SUBSCRIPTION -- ``dict.get()`` does not call it, ever.  ``_profile_text``
asked with ``.get(lang)``, so for every language that exists only as a
catalogue the action profile came back empty:

* while the language was gated (catalogue incomplete, or the administrator
  had not switched it on) ``normalize_lang`` degraded it to English first, so
  nothing failed and nothing looked wrong;
* the day the catalogue completed, the gate opened, the degrade stopped, and
  the renderer reached ``p['label']`` on an empty dict -- ``KeyError`` in
  front of an approver waiting for paper.

So the guard cannot be "rendering French works".  It has to be "the profile
is OVERLAID", checked with a catalogue whose text is distinguishable from the
English, plus a structural guard on the lookup itself: a future edit back to
``.get()`` reintroduces a silent English profile, and a test that only renders
today's languages would keep passing until the next catalogue completes.
"""
from __future__ import annotations

import ast
import inspect

import pytest

from app.services import cr_document as doc
from app.services import cr_i18n

from tests.test_cr_doc_i18n import _fill, ctx  # noqa: F401 — ctx is a fixture
from tests.test_cr_document import StubCR

#: A language that is NOT authored in Python — the whole point is that it can
#: only be produced by the overlay.
TRANSLATED = "fr"
MARK = f"[{TRANSLATED}] "        # _fill's marker; English never carries it


# --------------------------------------------------------------------------- #
#  the overlay actually reaches the action profile                              #
# --------------------------------------------------------------------------- #

def test_a_translated_action_profile_is_complete(ctx):
    """Every required key, not merely a non-empty dict.

    ``p['label']` was the key that raised, but the renderer reads nine of
    them; a profile that answers for one and not the rest prints an English
    paragraph in the middle of a French document instead of failing.
    """
    _fill(TRANSLATED)
    block = doc._profile_text("upgrade", TRANSLATED)
    missing = [k for k in doc.REQUIRED_PROFILE_KEYS if not block.get(k)]
    assert not missing, (
        f"the {TRANSLATED} action profile is missing {missing} — the overlay "
        "did not reach it (dict.get does not call __missing__)")


def test_a_translated_action_profile_carries_the_CATALOGUE_text(ctx):
    """Not the authored English wearing the right key names.

    Falling back to the English profile would satisfy the completeness test
    above while printing English prose under a French heading — which is the
    failure the language gate exists to prevent, arriving by another door.
    """
    _fill(TRANSLATED)
    block = doc._profile_text("upgrade", TRANSLATED)
    assert block["label"].startswith(MARK), (
        f"label={block['label']!r} came from the authored English, not the "
        f"{TRANSLATED} catalogue")


def test_the_generic_fallback_is_translated_too(ctx):
    """An action with no profile of its own still gets a translated one.

    The fallback branch has its own lookup, and a fix applied to only the
    first one leaves every unprofiled action printing English.
    """
    _fill(TRANSLATED)
    block = doc._profile_text("no-such-action-key", TRANSLATED)
    assert block, "the generic fallback returned nothing for a translated language"
    assert block["label"].startswith(MARK), (
        "the generic fallback answered in English for a translated language")


def test_rendering_a_translated_language_does_not_raise(ctx):
    """The KeyError, end to end."""
    _fill(TRANSLATED)
    assert TRANSLATED in {c for c, _ in doc.document_langs()}, (
        "fixture did not actually open the gate")
    out = doc.render(StubCR(), lang=TRANSLATED)
    assert MARK in out, "the rendered document contains no catalogue text at all"


def test_every_offered_document_language_renders(ctx):
    """Whatever the registry offers must actually print.

    Pinning the guard to today's five codes would go quiet the day a sixth is
    added — which is precisely when a new language's overlay is untested.
    """
    _fill(TRANSLATED)
    for code, label in doc.document_langs():
        try:
            out = doc.render(StubCR(), lang=code)
        except Exception as exc:  # noqa: BLE001 — the guard IS the exception
            pytest.fail(f"rendering the document in {code} ({label}) raised "
                        f"{type(exc).__name__}: {exc}")
        assert out.strip(), f"the {code} document rendered empty"


# --------------------------------------------------------------------------- #
#  the lookup itself                                                            #
# --------------------------------------------------------------------------- #

def test_the_language_lookup_never_uses_dict_get(ctx):
    """Structural, over the AST — not a substring scan.

    A substring test for ``.get(`` matches this test's own prose and the
    docstrings that EXPLAIN the rule, so it can pass while the defect is
    present.  The question is structural, so it is asked of the tree: no
    ``<expr>.get(...)`` call anywhere in the profile-lookup helpers may take
    the language as its first argument.
    """
    src = inspect.getsource(doc)
    tree = ast.parse(src)
    guarded = {"_lang_block", "_profile_text"}
    offenders = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name in guarded):
            continue
        langargs = {a.arg for a in node.args.args} & {"lang"}
        for call in ast.walk(node):
            if not (isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "get"):
                continue
            if call.args and isinstance(call.args[0], ast.Name) \
                    and call.args[0].id in langargs:
                offenders.append(f"{node.name}:{call.lineno}")
    assert not offenders, (
        f"{offenders} looks a language up with dict.get() — that does NOT "
        "call _Localized.__missing__, so the translated profile silently "
        "comes back empty and the document prints English (or raises).")


def test_the_overlay_is_reached_only_by_subscription(ctx):
    """The property the guard above defends, asserted on the real class.

    If ``_Localized`` ever grew a ``get`` override the structural guard would
    be over-strict rather than wrong — this test says which behaviour is the
    load-bearing one, so a future author can see the trade in one place.
    """
    block = doc.ACTION_PROFILES["upgrade"]
    _fill(TRANSLATED)
    assert block.get(TRANSLATED) is None, (
        "_Localized.get now answers for a translated language — the structural "
        "guard in this file can be relaxed, but only deliberately")
    assert isinstance(block[TRANSLATED], dict), (
        "subscription must still build the language via __missing__")


# --------------------------------------------------------------------------- #
#  the branches the first mutation pass could not tell apart                    #
# --------------------------------------------------------------------------- #

def test_a_language_with_no_catalogue_degrades_to_ENGLISH_not_to_a_blank(ctx):
    """No ``_fill`` here — the catalogue genuinely does not exist.

    The gate makes this unreachable in production, so it is tempting to
    return ``{}``.  That is the branch that converts a gate bug into a
    ``KeyError`` under a signature line: an empty profile does not print an
    empty section, it raises on the first key read.  ``cr_i18n`` states the
    rule for the overlay ("never to a blank"); the lookup in front of it must
    keep the same promise.
    """
    block = doc._profile_text("upgrade", TRANSLATED)
    english = doc._profile_text("upgrade", "en")
    missing = [k for k in doc.REQUIRED_PROFILE_KEYS if not block.get(k)]
    assert not missing, (
        f"an uncatalogued language returned a profile missing {missing} — "
        "the renderer raises on the first one it reads")
    assert block["label"] == english["label"], (
        "an uncatalogued language must degrade to the authored English")


def test_an_unlocalized_profile_still_falls_back_to_the_generic_one(monkeypatch, ctx):
    """The second lookup in ``_profile_text``, isolated.

    ``profile_for`` already returns the generic profile for an UNKNOWN action,
    so the fallback branch is only reached by a KNOWN action whose block
    cannot answer for the language — a plain dict that never went through
    ``_localize_all``.  Without a case that produces one, the branch is
    indistinguishable from dead code and a future author deletes it.
    """
    _fill(TRANSLATED)
    plain = dict(doc.ACTION_PROFILES)
    plain["upgrade"] = {"en": {}}          # authored-shaped, never localized
    monkeypatch.setattr(doc, "ACTION_PROFILES", plain)
    block = doc._profile_text("upgrade", TRANSLATED)
    assert block, "an unlocalized profile produced nothing at all"
    missing = [k for k in doc.REQUIRED_PROFILE_KEYS if not block.get(k)]
    assert not missing, (
        f"the generic fallback did not fill {missing} for an unlocalized profile")
