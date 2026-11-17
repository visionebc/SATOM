"""Which of the languages SATOM speaks this INSTALL actually OFFERS.

:mod:`app.services.langs` answers a build-time question -- "which languages
does the product speak" -- and its answer is identical on every install.  This
module answers an operator's question, which is not the same one: "which of
them may a user pick HERE".  A site with no French operators does not want
French in the profile picker, and an install mid-way through a translation pass
wants to hold a language back until its catalogue is worth reading.

Three rules are enforced here rather than in the form, because a form can be
bypassed and a second author of a rule is how the rule quietly stops being
true:

* **The source language is always offered.**  Every render needs *some*
  language and :data:`langs.DEFAULT` is the one every translation derives from.
  An install able to switch it off could lock every user out of a readable page
  -- from a settings checkbox, with no way back in.

* **Withdrawing a language never rewrites anybody's answer.**  The stored
  per-user preference stays exactly as the user wrote it; it merely stops being
  honoured while the language is withdrawn, and the profile page SAYS so.
  Deleting the row would answer, on the user's behalf and silently, a question
  they had already answered -- and re-enabling would not bring it back.

* **Unset or unreadable means everything.**  An install that never opened this
  page, and a row somebody hand-edited into nonsense, must not silently shrink
  the product.  Offering fewer languages is a change an operator makes on
  purpose, never one a broken row makes for them.

What this gate does NOT touch: the translation catalogues.  Text keeps being
authored and translated for every language in the registry, so a language
switched back on is complete the moment it reappears instead of starting from
an empty catalogue.  Enabling changes what is OFFERED, never what exists.
"""
from __future__ import annotations

from . import langs

#: JSON list of the language codes this install offers.  An ABSENT row means
#: "never configured", which is not the same as an empty list and is answered
#: with the whole registry (see the module docstring).
K_OFFERED = "i18n.offered"


def _stored():
    """The raw stored list, ``None`` when unset, and :data:`_BROKEN` when the
    row exists but is not a JSON list.

    Never raises: this runs inside the Babel locale selector, which runs on
    every request including the error pages.  An exception here would replace a
    recoverable failure with a blank one.
    """
    try:
        from . import settings_store as store

        val = store.get_json_checked(K_OFFERED, None, want=list)
        return _BROKEN if val is store.MALFORMED else val
    except Exception:  # noqa: BLE001 — no app context, no table, no DB
        return None


class _Broken:
    __slots__ = ()

    def __repr__(self) -> str:      # pragma: no cover - debugging aid
        return "<BROKEN i18n.offered>"


_BROKEN = _Broken()


def configured() -> bool:
    """True when an operator has actually chosen a set.

    A page that says "all languages are offered" for an unset install and for
    one that ticked every box is telling the truth either way, but only one of
    them is a decision -- and the difference matters when a later release adds
    a language.
    """
    return isinstance(_stored(), list)


def malformed() -> bool:
    """True when the stored row EXISTS but cannot be read as a language list.

    Reported rather than folded into "not configured", which is what plain
    :func:`settings_store.get_json` would have done. Both degrade to offering
    everything -- that part is deliberate -- but only one of them means a row
    somebody wrote is being ignored. Without this distinction the console would
    say "never configured" to an operator looking straight at a setting they
    saved, and the next thing they would do is save it again.
    """
    return _stored() is _BROKEN


def offered_codes() -> tuple[str, ...]:
    """The offered codes in the registry's display order, source language
    always included.

    Order comes from :mod:`langs`, never from the stored row: a picker whose
    order depends on the sequence checkboxes happened to be saved in reorders
    itself under the operator for no reason.
    """
    raw = _stored()
    if not isinstance(raw, list):
        return langs.codes()
    picked = {langs.normalize(c) for c in raw if langs.is_supported(c)}
    picked.add(langs.DEFAULT)
    return tuple(c for c in langs.codes() if c in picked)


def offered() -> tuple[tuple[str, str], ...]:
    """``((code, endonym), ...)`` for every offered language, display order."""
    return tuple((c, langs.label(c)) for c in offered_codes())


def withdrawn_codes() -> tuple[str, ...]:
    """Supported but not offered here -- what the operator switched off."""
    keep = set(offered_codes())
    return tuple(c for c in langs.codes() if c not in keep)


def is_offered(value) -> bool:
    """True when ``value`` names a language this install offers.

    Deliberately strict where :func:`langs.normalize` is forgiving: an unknown
    value is NOT offered.  ``normalize`` exists to keep a render alive by
    degrading to the default; answering "yes, offered" for a language nobody
    declared would let an unknown code through the gate this module exists to
    be.
    """
    return langs.is_supported(value) and langs.normalize(value) in offered_codes()


def save(codes) -> tuple[str, ...]:
    """Persist the offered set; return what was stored.

    Unknown codes are dropped and :data:`langs.DEFAULT` is added back
    unconditionally, so no submission -- hand-crafted, replayed, or a form with
    every box cleared -- can leave the install with a language nobody can read.
    """
    keep = {langs.normalize(c) for c in (codes or ()) if langs.is_supported(c)}
    keep.add(langs.DEFAULT)
    ordered = [c for c in langs.codes() if c in keep]
    from . import settings_store as store

    store.set_json(K_OFFERED, ordered)
    return tuple(ordered)
