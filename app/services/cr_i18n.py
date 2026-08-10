"""The change-request document in a language nobody hand-wrote it in.

``cr_document`` carries English and German as authored Python literals.  Adding
Spanish, French and Italian the same way would mean three more copies of ~1400
lines of prose that no reviewer can keep in step with the original: the fifth
copy goes stale, the document prints the stale sentence, and nothing fails.

So the other languages live as :class:`TranslationUnit` rows and are overlaid
onto the authored structures at render time.  Three consequences worth stating
because each of them is load-bearing:

* **A language is offered only when its catalogue is COMPLETE.**  Partial
  coverage would print a document half in Spanish and half in English *under an
  approver's signature line* -- the exact failure the old hardcoded
  ``AUTHORED_LANGS`` frozenset existed to prevent.  This module keeps that
  promise by measuring instead of declaring.
* **Stale counts as missing.**  ``TranslationUnit`` hashes its source; when the
  English changes, the Spanish is not wrong-looking, it is silently obsolete.
  A stale unit therefore withdraws the whole language rather than serving a
  sentence the author already retired.
* **The overlay never invents.**  Any key the catalogue lacks falls back to the
  authored English, so a bug here degrades to English -- never to a blank.
"""

from __future__ import annotations

from . import langs
from ..models_i18n import ORIGIN_HUMAN  # noqa: F401  (kept for callers)

#: Namespace for every unit that composes a change-request document.
NAMESPACE = "cr_doc"

_SOURCE_LANG = langs.DEFAULT


# --------------------------------------------------------------------------- #
#  walking the authored structures                                             #
# --------------------------------------------------------------------------- #

def _flatten(node, prefix: str, out: dict) -> None:
    """Collect every leaf string under ``node`` into ``out`` by dotted path.

    Tuples keep their index in the path.  Order and arity are part of the
    contract: section 7 is a numbered work plan, so re-joining a translated
    list in a different order would renumber the operator's steps.
    """
    if isinstance(node, str):
        if node.strip():
            out[prefix] = node
    elif isinstance(node, (tuple, list)):
        for i, item in enumerate(node):
            _flatten(item, f"{prefix}.{i}", out)
    elif isinstance(node, dict):
        for key, value in node.items():
            _flatten(value, f"{prefix}.{key}" if prefix else str(key), out)


def source_units() -> dict:
    """``{key: english_text}`` for everything a rendered document can print.

    Imported lazily: ``cr_document`` imports this module, so a module-level
    import would be circular.
    """
    from . import cr_document as cd

    out: dict = {}
    _flatten(cd.SECTION_TITLES.get(_SOURCE_LANG, ()), "titles", out)
    _flatten(cd._T.get(_SOURCE_LANG, {}), "t", out)
    _flatten(cd._DRAFT.get(_SOURCE_LANG, {}), "draft", out)
    for action, per_lang in cd.ACTION_PROFILES.items():
        _flatten(per_lang.get(_SOURCE_LANG, {}), f"profile.{action}", out)
    return out


# --------------------------------------------------------------------------- #
#  reading the catalogue                                                       #
# --------------------------------------------------------------------------- #

def _rows(lang: str) -> dict:
    from ..models_i18n import TranslationUnit
    return {r.key: r for r in TranslationUnit.query.filter_by(
        namespace=NAMESPACE, lang=langs.normalize(lang)).all()}


def _polluted(text: str, source: str = "") -> bool:
    """True when stored text still carries a model-echoed untrusted fence."""
    from .translator import _fence_residue
    return bool(_fence_residue(text or "", source or ""))


def coverage(lang: str) -> dict:
    """How complete ``lang`` is: totals, and WHICH keys are missing or stale.

    The lists are truncated by the caller, not here -- a diagnostics page that
    cannot name the three missing keys sends the operator back to guessing.
    """
    lang = langs.normalize(lang)
    source = source_units()
    if lang == _SOURCE_LANG:
        return {"lang": lang, "total": len(source), "have": len(source),
                "missing": [], "stale": [], "complete": True, "authored": True}
    try:
        rows = _rows(lang)
    except Exception:          # no app context / table absent -> not complete
        return {"lang": lang, "total": len(source), "have": 0,
                "missing": sorted(source), "stale": [], "complete": False,
                "authored": False}
    missing, stale, have = [], [], 0
    for key, text in source.items():
        row = rows.get(key)
        if row is None or not (row.text or "").strip() \
                or _polluted(row.text, text):
            # A row carrying an echoed model delimiter is not a translation.
            # Counting it as one lets a language report COMPLETE while the
            # document prints "<<<FIN NON FIABLE>>>" under a signature line.
            missing.append(key)
        elif row.is_stale(text):
            stale.append(key)
        else:
            have += 1
    from . import cr_document as cd
    authored = lang in cd.AUTHORED_LANGS
    return {"lang": lang, "total": len(source), "have": have,
            "missing": sorted(missing), "stale": sorted(stale),
            "complete": authored or (not missing and not stale),
            "authored": authored}


def ready_langs() -> tuple:
    """Every supported code whose document can actually be produced, in the
    registry's display order.  English is always in it; it is the source."""
    out = []
    for code in langs.codes():
        if code == _SOURCE_LANG or coverage(code)["complete"]:
            out.append(code)
    return tuple(out)


def texts(lang: str) -> dict:
    """``{key: translated_text}`` for one language; ``{}`` when unavailable."""
    lang = langs.normalize(lang)
    if lang == _SOURCE_LANG:
        return {}
    try:
        return {k: r.text for k, r in _rows(lang).items() if (r.text or "").strip()}
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
#  overlaying                                                                  #
# --------------------------------------------------------------------------- #

def overlay(node, prefix: str, table: dict):
    """Rebuild ``node`` with ``table``'s strings substituted by dotted path.

    Shape is preserved exactly -- tuples stay tuples, because
    ``cr_document`` distinguishes "a paragraph" (str) from "a numbered list"
    (tuple) by type alone, and a list that arrives as a string renders as one
    run-on step.
    """
    if isinstance(node, str):
        return table.get(prefix, node)
    if isinstance(node, tuple):
        return tuple(overlay(v, f"{prefix}.{i}", table) for i, v in enumerate(node))
    if isinstance(node, list):
        return [overlay(v, f"{prefix}.{i}", table) for i, v in enumerate(node)]
    if isinstance(node, dict):
        return {k: overlay(v, f"{prefix}.{k}" if prefix else str(k), table)
                for k, v in node.items()}
    return node


# --------------------------------------------------------------------------- #
#  per-request memoisation                                                     #
# --------------------------------------------------------------------------- #
#  Rendering one document asks for the catalogue dozens of times.  Caching for
#  the life of the PROCESS would be cheaper still and wrong: a gunicorn worker
#  would keep serving a sentence an operator has already corrected, and only a
#  restart would fix it.  The request is the correct lifetime -- long enough to
#  pay for itself, short enough that an edit is visible on the next page load.

def _cache() -> dict | None:
    try:
        from flask import g, has_request_context
        if not has_request_context():
            return None
        store = getattr(g, "_cr_i18n_cache", None)
        if store is None:
            store = {}
            g._cr_i18n_cache = store
        return store
    except Exception:  # noqa: BLE001 — no flask, no cache, still correct
        return None


def cached_texts(lang: str) -> dict:
    lang = langs.normalize(lang)
    store = _cache()
    if store is None:
        return texts(lang)
    hit = store.get(("texts", lang))
    if hit is None:
        hit = texts(lang)
        store[("texts", lang)] = hit
    return hit


def cached_ready() -> tuple:
    store = _cache()
    if store is None:
        return ready_langs()
    hit = store.get("ready")
    if hit is None:
        hit = ready_langs()
        store["ready"] = hit
    return hit
