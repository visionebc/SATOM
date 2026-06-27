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
PRODUCTS = ("fortiweb", "fortiadc")


def banner_template(user_id: int, product: str) -> str:
    """The user's chosen template id for ``product`` (DB), else the global /
    default template."""
    val = UserSetting.get(user_id, K_BANNER_PREFIX + product)
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
