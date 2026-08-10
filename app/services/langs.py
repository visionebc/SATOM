"""The one place that knows which languages SATOM speaks.

Before this module the answer lived in :data:`app.services.cr_document.LANGS`
-- a change-document detail the rest of the product had no reason to import.
Two authors of the same list is how a picker ends up offering a language the
renderer cannot produce: the picker changes, the renderer does not, and
nothing fails.  Every surface (document language picker, administration,
translation jobs) reads from here instead.

English is the source language on purpose.  The action profiles, the CLI help
and the docs are authored in English, so every translation has exactly one
origin and never a chain (en -> de -> es), which compounds error silently.

Declaring a language here does NOT claim any text exists in it.  That claim
belongs to whoever renders the text -- see
:func:`app.services.cr_document.document_langs`, which offers only the
languages a complete document can actually be produced in.
"""

from __future__ import annotations

#: Display order, source language first.  ``(code, endonym)`` -- a language is
#: listed under its own name because a picker that says "German" to a German
#: operator is written for the wrong reader.
SUPPORTED: tuple[tuple[str, str], ...] = (
    ("en", "English"),
    ("es", "Español"),
    ("de", "Deutsch"),
    ("fr", "Français"),
    ("it", "Italiano"),
)

#: The language authored text is written in and every translation derives from.
DEFAULT = "en"

_LABELS = dict(SUPPORTED)


def codes() -> tuple[str, ...]:
    """The supported language codes, in display order."""
    return tuple(c for c, _ in SUPPORTED)


def label(code: str) -> str:
    """The endonym for ``code``; the code itself when it is unknown.

    Never raises and never returns an empty string: a missing label must
    degrade to something an operator can still read, not to a blank option.
    """
    return _LABELS.get(normalize(code), str(code or DEFAULT))


def is_supported(value) -> bool:
    """True when ``value`` names a supported language exactly (after the same
    normalisation :func:`normalize` applies)."""
    if not isinstance(value, str) or not value.strip():
        return False
    return _base(value) in _LABELS


def normalize(value) -> str:
    """Coerce anything to a supported code.  Never raises.

    Regional tags degrade to their base language (``de-CH`` -> ``de``,
    ``es_MX`` -> ``es``) and case is ignored, so a browser header or a stored
    preference cannot fall through to the default just because it was more
    specific than the catalogue.  Anything still unknown becomes
    :data:`DEFAULT` -- a language pick must never break a render.
    """
    base = _base(value)
    return base if base in _LABELS else DEFAULT


def _base(value) -> str:
    try:
        return str(value or "").strip().lower().replace("_", "-").split("-")[0]
    except Exception:  # noqa: BLE001 — a language pick must never raise
        return ""


def others(code: str) -> tuple[str, ...]:
    """Every supported language except ``code`` -- the fan-out of a save."""
    keep = normalize(code)
    return tuple(c for c in codes() if c != keep)
