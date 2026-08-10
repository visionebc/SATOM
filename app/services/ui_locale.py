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

from . import langs


def resolve() -> str:
    """Best supported UI language for the current request.

    Order: the signed-in user's saved preference, then the browser's
    ``Accept-Language`` narrowed to what we actually ship, then the default.

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
    """
    try:
        from flask_login import current_user
        from .user_settings_store import language as _stored

        if getattr(current_user, "is_authenticated", False):
            return _stored(current_user.id) or ""
    except Exception:  # noqa: BLE001 — chrome must not break on a preference
        pass
    return ""


def _from_browser() -> str:
    """``Accept-Language`` narrowed to the supported set, or ``""``.

    ``best_match`` is asked only about codes we ship, so a header naming a
    language we do not have cannot select it.  Returning ``""`` (not the
    default) keeps the two fallback steps distinguishable for tests.
    """
    try:
        from flask import request

        best = request.accept_languages.best_match(langs.codes())
    except Exception:  # noqa: BLE001 — no request context (CLI, jobs)
        return ""
    if not best:
        return ""
    return langs.normalize(best)
