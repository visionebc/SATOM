"""Map a Template ``kind`` to a logical config SECTION + label.

A template carries no scope and no section column — its section is DERIVED from
its kind. This single source of truth backs the approved-template catalog
(FortiWeb Sections) and the baseline builder's grouping.
"""
from __future__ import annotations

from ..models import Template
from . import config_catalog

# Built-in (non config:) kinds -> (kind, section_key, label). Order = display order.
_BUILTIN: tuple[tuple[str, str, str], ...] = (
    (Template.KIND_WEB_PROTECTION, "web_protection", "Web Protection"),
    (Template.KIND_SERVER_POLICY, "server_policy", "Server Policy"),
    (Template.KIND_SYSTEM, "system", "System"),
    (Template.KIND_STRUCTURE, "structure", "Structure"),
)
_KIND_TO_SECTION = {k: sec for k, sec, _ in _BUILTIN}
_SECTION_LABEL = {sec: lbl for _, sec, lbl in _BUILTIN}


def section_for_kind(kind: str) -> str:
    """Return the logical section key for a template kind."""
    kind = kind or ""
    if kind in _KIND_TO_SECTION:
        return _KIND_TO_SECTION[kind]
    if kind.startswith(Template.KIND_CONFIG_PREFIX):
        sub = kind[len(Template.KIND_CONFIG_PREFIX):]
        # Future WPP-section saves (config:wpp.<sub>) live under Web Protection.
        if sub.startswith("wpp.") or sub == "wpp":
            return "web_protection"
        return sub
    return "other"


def section_label(section_key: str) -> str:
    """Human label for a logical section key."""
    if section_key in _SECTION_LABEL:
        return _SECTION_LABEL[section_key]
    sec = config_catalog.SECTION_BY_KEY.get(section_key)
    if sec is not None:
        return sec.label
    return section_key.replace("_", " ").title() if section_key else "Other"


def known_sections() -> list[dict]:
    """Ordered list of every section a template can belong to: the WPP /
    Server-Policy / System / Structure built-ins first, then each FortiWeb config
    section. Each item is ``{'key', 'label'}``."""
    out: list[dict] = [{"key": sec, "label": lbl} for _, sec, lbl in _BUILTIN]
    seen = {s["key"] for s in out}
    for s in config_catalog.CONFIG_SECTIONS:
        if s.key not in seen:
            out.append({"key": s.key, "label": s.label})
            seen.add(s.key)
    return out
