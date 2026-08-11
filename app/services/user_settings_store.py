"""Per-USER settings (DB-backed, no cookie).

User settings live in the ``user_settings`` table (``UserSetting.get/set``),
keyed by ``(user_id, key)`` — distinct from the GLOBAL ``app_settings`` table
that ``settings_store`` manages. Today the only user setting is the personal
top-bar **banner** per product; ``about`` is informational (nothing to store).

Banner templates themselves are shared chrome, so we reuse ``BANNER_TEMPLATES``
/ ``BANNER_DEFAULT`` from the global store. A user with no saved choice falls
back to the global banner, then to the product default — so existing installs
keep their look until each user picks their own.
"""
from __future__ import annotations

from typing import Any

from ..models import UserSetting
from . import settings_store as _g

K_BANNER_PREFIX = "branding.banner."   # + fortiweb|fortiadc -> template id
PRODUCTS = _g.BANNER_PRODUCTS


def banner_template(user_id: int, product: str) -> str:
    """The user's chosen template id for ``product`` (DB), else the global /
    default template."""
    val = _g.resolve_banner_template(
        UserSetting.get(user_id, K_BANNER_PREFIX + product))
    if val in _g.BANNER_TEMPLATES:
        return val
    return _g.banner_template(product)


def banner_bg(user_id: int, product: str) -> str:
    return _g.BANNER_TEMPLATES[banner_template(user_id, product)]["bg"]


def all_banners(user_id: int) -> dict[str, str]:
    return {p: banner_template(user_id, p) for p in PRODUCTS}


def save_banners(user_id: int, mapping: dict[str, Any]) -> None:
    for product, tpl in (mapping or {}).items():
        if product in PRODUCTS and tpl in _g.BANNER_TEMPLATES:
            UserSetting.set(user_id, K_BANNER_PREFIX + product, tpl)


# ---------------------------------------------------------------------------
# Architecture / Fleet-map filters (per user, DB-backed JSON)
# ---------------------------------------------------------------------------
import json as _json

K_ARCH_FILTERS = "architecture.filters"
_ARCH_KEYS = ("zone", "line", "department", "text", "status",
              "kind", "firmware", "data", "proto", "waf", "view")


def architecture_filters(user_id: int) -> dict:
    """The user's saved Fleet-map filters, or empty strings. Tolerant of a
    missing/corrupt row."""
    raw = UserSetting.get(user_id, K_ARCH_FILTERS)
    out = {k: "" for k in _ARCH_KEYS}
    if raw:
        try:
            data = _json.loads(raw)
            for k in _ARCH_KEYS:
                v = data.get(k)
                if isinstance(v, str):
                    out[k] = v
        except Exception:
            pass
    return out


def save_architecture_filters(user_id: int, mapping: dict) -> None:
    clean = {k: str((mapping or {}).get(k) or "") for k in _ARCH_KEYS}
    UserSetting.set(user_id, K_ARCH_FILTERS, _json.dumps(clean))


# ---------------------------------------------------------------------------
# Language (per user, DB-backed)
# ---------------------------------------------------------------------------
from . import langs as _langs                                    # noqa: E402

K_LANG = "i18n.lang"


def language(user_id: int) -> str:
    """The language this user picked in their profile, or ``""`` when they
    never picked one.

    Empty is NOT the same as ``"en"``. A user who has never answered the
    question must still be asked it where the answer is consequential -- the
    change document is written in one language and *signed* in it -- while a
    user who deliberately picked English must never be asked again. Collapsing
    the two into the default makes the setting unobservable: "no preference"
    and "prefers the default" would render identically, so the profile could
    never show which one is true.
    """
    raw = UserSetting.get(user_id, K_LANG)
    return _langs.normalize(raw) if _langs.is_supported(raw) else ""


def save_language(user_id: int, code) -> str:
    """Persist ``code`` as this user's language; return what was stored.

    A blank or unsupported code CLEARS the preference instead of storing the
    default. "No preference" is a choice the profile offers explicitly, and
    writing ``en`` for it would answer the question the user just un-answered
    -- silently, and in the language they did not choose.
    """
    value = _langs.normalize(code) if _langs.is_supported(code) else ""
    UserSetting.set(user_id, K_LANG, value)
    return value


def language_usage() -> dict:
    """``{code: how many users picked it}`` -- only languages somebody chose.

    The admin console shows this beside each availability switch because
    withdrawing a language is not a display tweak: it changes the language
    other people's pages render in. An operator should read "2 users" before
    clicking, not discover it from a ticket afterwards.

    Blank rows ("no preference") are not counted -- they are not a pick -- and
    a row naming a language the registry no longer knows is ignored rather than
    reported under a code nothing can label.
    """
    out: dict = {}
    try:
        rows = UserSetting.query.filter_by(key=K_LANG).all()
    except Exception:  # noqa: BLE001 — a count must not break the console
        return out
    for row in rows:
        raw = getattr(row, "value", "")
        if not _langs.is_supported(raw):
            continue
        code = _langs.normalize(raw)
        out[code] = out.get(code, 0) + 1
    return out
