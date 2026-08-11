"""Which language the *chrome* is rendered in.

Deliberately separate from the **document** language (:mod:`app.services.langs`
+ ``cr_document``).  A change request is written and *signed* in one language,
so "no preference" there must stay unanswered and keep being asked.  The chrome
has no such obligation: every page needs *some* language on every request, and
refusing to pick one would leave the navigation blank.

The stored preference therefore stays exactly as the profile wrote it — empty
when the user never chose — and the fallback happens *here*, at render time.
That keeps "no preference" observable in the profile (the rule that
``user_settings_store.language`` exists to protect) while still giving an
anonymous or undecided visitor a readable page.
"""
from __future__ import annotations

from . import lang_policy, langs


def resolve() -> str:
    """Best supported UI language for the current request.

    Order: the signed-in user's saved preference, then the browser's
    ``Accept-Language``, then the default.  Every step is narrowed to what this
    install OFFERS (:mod:`app.services.lang_policy`); the default is offered
    unconditionally, so the chain always ends somewhere readable.

    Never raises.  A locale selector runs on *every* request, including the
    error pages, so an exception here would replace a recoverable failure with
    a blank one.
    """
    saved = _saved_preference()
    if saved:
        return saved
    negotiated = _from_browser()
    if negotiated:
        return negotiated
    return langs.DEFAULT


def _saved_preference() -> str:
    """The signed-in user's stored ``i18n.lang``, or ``""``.

    Anonymous requests, a missing table during a fresh install, or a broken row
    all degrade to "no preference" rather than taking down the render.

    A preference the install no longer OFFERS is treated as no preference, not
    as an error and not as a reason to rewrite the row: the administrator
    withdrew the language, so the chrome stops rendering in it, while the
    user's answer survives for the day it is offered again (see
    :mod:`app.services.lang_policy`).  The profile page is where that gap is
    made visible; hiding it here as well would leave a user staring at English
    with their preference still reading "Français" and nothing to explain it.
    """
    try:
        from flask_login import current_user
        from .user_settings_store import language as _stored

        if getattr(current_user, "is_authenticated", False):
            saved = _stored(current_user.id) or ""
            return saved if lang_policy.is_offered(saved) else ""
    except Exception:  # noqa: BLE001 — chrome must not break on a preference
        pass
    return ""


def _from_browser() -> str:
    """``Accept-Language`` narrowed to the OFFERED set, or ``""``.

    ``best_match`` is asked only about codes this install offers, so neither a
    header naming a language we do not have nor one naming a language the
    administrator withdrew can select it.  Narrowing here rather than
    afterwards matters: ``best_match`` picks the browser's highest-weighted
    match from the list it is given, so handing it the full registry and
    filtering the winner would answer "no match" for a browser whose *second*
    choice is offered.  Returning ``""`` (not the default) keeps the two
    fallback steps distinguishable for tests.
    """
    try:
        from flask import request

        best = request.accept_languages.best_match(lang_policy.offered_codes())
    except Exception:  # noqa: BLE001 — no request context (CLI, jobs)
        return ""
    if not best:
        return ""
    return langs.normalize(best)
