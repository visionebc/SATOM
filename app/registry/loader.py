"""Load and index the FortiWeb REST endpoint registry from ``endpoints.yaml``.

The registry file is a flat ``friendly_key: urn`` map; UI sections are derived
at read time via :func:`categories.category_for`. All helpers return
display-ready dicts shaped for both the registry index/section templates and
the API explorer (``name``/``urn``/``path``/``section``/``methods``/``method``).
"""
from __future__ import annotations

import os

import yaml

_registry: dict | None = None


def load_registry() -> dict:
    """Return the cached ``{friendly_key: urn}`` map loaded from endpoints.yaml."""
    global _registry
    if _registry is None:
        yaml_path = os.path.join(os.path.dirname(__file__), '..', '..', 'endpoints.yaml')
        try:
            with open(yaml_path) as f:
                _registry = yaml.safe_load(f) or {}
        except FileNotFoundError:
            _registry = {}
    return _registry


def _methods_for(urn: str) -> list:
    """Best-effort HTTP methods for display: CMDB objects are CRUD, the rest read-only."""
    return ['GET', 'POST', 'PUT', 'DELETE'] if '/cmdb/' in (urn or '') else ['GET']


def _section_of(urn: str) -> str | None:
    from .categories import category_for
    sec, _ = category_for(urn)
    return sec[0] if sec else None


def _endpoint_dict(name: str, urn: str, section: str | None) -> dict:
    methods = _methods_for(urn)
    return {
        'name': name,
        'urn': urn,
        'path': urn,
        'section': section,
        'methods': methods,
        'method': methods[0],
    }


def get_all_endpoints() -> list:
    """Every registry endpoint as a display dict, sorted by section then name."""
    reg = load_registry()
    result = [_endpoint_dict(name, urn, _section_of(urn)) for name, urn in reg.items()]
    return sorted(result, key=lambda e: ((e['section'] or '~'), e['name']))


def get_endpoints_by_section(section: str) -> list:
    """All endpoints whose derived section equals ``section``."""
    return [e for e in get_all_endpoints() if e['section'] == section]


def get_all_sections() -> list:
    """The ordered list of UI section names."""
    from .categories import SECTION_ORDER
    return list(SECTION_ORDER)
