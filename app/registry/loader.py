"""DB-first FortiWeb REST endpoint registry, seeded from ``endpoints.yaml``.

The registry lives in the ``registry_endpoints`` table (PostgreSQL — editable
in production from the Registry page, captured by the nightly ``pg_dump``).
The git-tracked ``endpoints.yaml`` (flat ``friendly_key: urn`` map) is the
SEED and the fallback:

* at boot :func:`seed_from_yaml` INSERT-ONLY syncs YAML → DB (a name already
  in the DB is never touched, so operator edits/disables always win);
* if the DB is unreachable or empty (early scripts, standalone tools), the
  YAML map is served directly so nothing ever breaks on a fresh tree.

Reads go through a per-process cache with a short TTL: an edit invalidates the
cache of the worker that served it immediately, the other gunicorn workers
converge within ``_CACHE_TTL`` seconds.

UI sections are derived at read time via :func:`categories.category_for`. All
helpers return display-ready dicts shaped for the registry/API-explorer
templates (``name``/``urn``/``path``/``section``/``methods``/``method``).
"""
from __future__ import annotations

import os
import time

import yaml

_CACHE_TTL = 60.0  # seconds — cross-worker convergence window after an edit

_yaml_cache: dict | None = None
_db_cache: dict = {"map": None, "ts": 0.0}


# ---------------------------------------------------------------------------
# sources
# ---------------------------------------------------------------------------

def _yaml_registry() -> dict:
    """The raw ``{friendly_key: urn}`` map from endpoints.yaml (cached)."""
    global _yaml_cache
    if _yaml_cache is None:
        yaml_path = os.path.join(os.path.dirname(__file__), '..', '..', 'endpoints.yaml')
        try:
            with open(yaml_path) as f:
                _yaml_cache = yaml.safe_load(f) or {}
        except FileNotFoundError:
            _yaml_cache = {}
    return _yaml_cache


def _db_registry() -> dict | None:
    """``{name: urn}`` from ``registry_endpoints`` (enabled rows only), or
    ``None`` when the DB can't serve it (no app context / table missing /
    never seeded) — the caller then falls back to the YAML."""
    now = time.monotonic()
    if _db_cache["map"] is not None and (now - _db_cache["ts"]) < _CACHE_TTL:
        return _db_cache["map"]
    try:
        from ..models import RegistryEndpoint
        rows = RegistryEndpoint.query.filter_by(product="fortiweb", enabled=True).all()
        if not rows:
            return None
        reg = {r.name: r.urn for r in rows}
    except Exception:  # noqa: BLE001 — any DB hiccup → YAML fallback
        return None
    _db_cache["map"] = reg
    _db_cache["ts"] = now
    return reg


def invalidate_cache() -> None:
    """Drop the per-process DB cache (called after every registry write)."""
    _db_cache["map"] = None
    _db_cache["ts"] = 0.0


def load_registry() -> dict:
    """Return the active ``{friendly_key: urn}`` map (DB first, YAML fallback)."""
    reg = _db_registry()
    if reg is not None:
        return reg
    return _yaml_registry()


def seed_from_yaml() -> int:
    """INSERT-ONLY sync endpoints.yaml → registry_endpoints; returns rows added.

    A name already present in the DB (enabled OR disabled) is never modified —
    operator edits and soft-deletes survive every boot/deploy. Unique-constraint
    races between gunicorn workers roll back cleanly.
    """
    from sqlalchemy.exc import IntegrityError

    from ..extensions import db
    from ..models import RegistryEndpoint

    yaml_map = _yaml_registry()
    if not yaml_map:
        return 0
    existing = {
        name for (name,) in db.session.query(RegistryEndpoint.name)
        .filter_by(product="fortiweb", api_version="v2.0")
    }
    added = 0
    for name, urn in yaml_map.items():
        if not urn or name in existing:
            continue
        db.session.add(RegistryEndpoint(
            product="fortiweb", api_version="v2.0",
            name=str(name), urn=str(urn), updated_by="seed",
        ))
        added += 1
    if added:
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()  # another worker seeded first — fine
            added = 0
    invalidate_cache()
    return added


# ---------------------------------------------------------------------------
# FortiADC registry (product='fortiadc', api_version='v1')
# ---------------------------------------------------------------------------
# Same DB-first + YAML-fallback contract as FortiWeb, kept as a parallel,
# product-scoped set of helpers so the (hot) FortiWeb paths stay untouched.
# FortiADC REST has no version segment in the URL (paths are /api/<object>);
# 'v1' is the registry's own versioning bucket. Seed file: the repo-root
# ``endpoints_fortiadc.yaml`` (flat ``friendly_key: urn`` map, urns derived
# from the CLI object tree — ``config load-balance virtual-server`` →
# ``/api/load_balance_virtual_server``).

_adc_yaml_cache: dict | None = None
_adc_db_cache: dict = {"map": None, "ts": 0.0}


def _adc_yaml_registry() -> dict:
    global _adc_yaml_cache
    if _adc_yaml_cache is None:
        yaml_path = os.path.join(os.path.dirname(__file__), '..', '..',
                                 'endpoints_fortiadc.yaml')
        try:
            with open(yaml_path) as f:
                _adc_yaml_cache = yaml.safe_load(f) or {}
        except FileNotFoundError:
            _adc_yaml_cache = {}
    return _adc_yaml_cache


def _adc_db_registry() -> dict | None:
    now = time.monotonic()
    if _adc_db_cache["map"] is not None and (now - _adc_db_cache["ts"]) < _CACHE_TTL:
        return _adc_db_cache["map"]
    try:
        from ..models import RegistryEndpoint
        rows = RegistryEndpoint.query.filter_by(product="fortiadc", enabled=True).all()
        if not rows:
            return None
        reg = {r.name: r.urn for r in rows}
    except Exception:  # noqa: BLE001 — any DB hiccup → YAML fallback
        return None
    _adc_db_cache["map"] = reg
    _adc_db_cache["ts"] = now
    return reg


def invalidate_adc_cache() -> None:
    _adc_db_cache["map"] = None
    _adc_db_cache["ts"] = 0.0


def load_adc_registry() -> dict:
    """The active FortiADC ``{friendly_key: urn}`` map (DB first, YAML fallback)."""
    reg = _adc_db_registry()
    if reg is not None:
        return reg
    return _adc_yaml_registry()


def resolve_adc(name: str) -> str:
    """Resolve a FortiADC logical endpoint name to its ``/api/...`` path."""
    reg = load_adc_registry()
    try:
        return reg[name]
    except KeyError:
        raise KeyError(f"unknown FortiADC registry endpoint: {name!r}") from None


def seed_adc_from_yaml() -> int:
    """INSERT-ONLY sync endpoints_fortiadc.yaml → registry_endpoints
    (product='fortiadc'); returns rows added. Operator edits/disables in the
    DB always win — same contract as the FortiWeb seed."""
    from sqlalchemy.exc import IntegrityError

    from ..extensions import db
    from ..models import RegistryEndpoint

    yaml_map = _adc_yaml_registry()
    if not yaml_map:
        return 0
    existing = {
        name for (name,) in db.session.query(RegistryEndpoint.name)
        .filter_by(product="fortiadc", api_version="v1")
    }
    added = 0
    for name, urn in yaml_map.items():
        if not urn or name in existing:
            continue
        db.session.add(RegistryEndpoint(
            product="fortiadc", api_version="v1",
            name=str(name), urn=str(urn), updated_by="seed",
        ))
        added += 1
    if added:
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()  # another worker seeded first — fine
            added = 0
    invalidate_adc_cache()
    return added


# ---------------------------------------------------------------------------
# FortiAnalyzer registry (product='fortianalyzer', api_version='jsonrpc')
# ---------------------------------------------------------------------------
# Same DB-first + YAML-fallback contract as FortiWeb/FortiADC, kept as a
# parallel, product-scoped set of helpers. URNs are JSON-RPC urls (single
# transport POST /jsonrpc — dialect picked by the client from the URL family,
# see app/clients/fortianalyzer.py). Seed file: the repo-root
# ``endpoints_fortianalyzer.yaml`` (flat ``friendly_key: urn`` map, every
# entry probed live against faz01 v7.6.7).

_faz_yaml_cache: dict | None = None
_faz_db_cache: dict = {"map": None, "ts": 0.0}


def _faz_yaml_registry() -> dict:
    global _faz_yaml_cache
    if _faz_yaml_cache is None:
        yaml_path = os.path.join(os.path.dirname(__file__), '..', '..',
                                 'endpoints_fortianalyzer.yaml')
        try:
            with open(yaml_path) as f:
                _faz_yaml_cache = yaml.safe_load(f) or {}
        except FileNotFoundError:
            _faz_yaml_cache = {}
    return _faz_yaml_cache


def _faz_db_registry() -> dict | None:
    now = time.monotonic()
    if _faz_db_cache["map"] is not None and (now - _faz_db_cache["ts"]) < _CACHE_TTL:
        return _faz_db_cache["map"]
    try:
        from ..models import RegistryEndpoint
        rows = RegistryEndpoint.query.filter_by(product="fortianalyzer", enabled=True).all()
        if not rows:
            return None
        reg = {r.name: r.urn for r in rows}
    except Exception:  # noqa: BLE001 — any DB hiccup → YAML fallback
        return None
    _faz_db_cache["map"] = reg
    _faz_db_cache["ts"] = now
    return reg


def invalidate_faz_cache() -> None:
    _faz_db_cache["map"] = None
    _faz_db_cache["ts"] = 0.0


def load_faz_registry() -> dict:
    """The active FortiAnalyzer ``{friendly_key: urn}`` map (DB first, YAML fallback)."""
    reg = _faz_db_registry()
    if reg is not None:
        return reg
    return _faz_yaml_registry()


def resolve_faz(name: str) -> str:
    """Resolve a FortiAnalyzer logical endpoint name to its JSON-RPC url."""
    reg = load_faz_registry()
    try:
        return reg[name]
    except KeyError:
        raise KeyError(f"unknown FortiAnalyzer registry endpoint: {name!r}") from None


def seed_faz_from_yaml() -> int:
    """INSERT-ONLY sync endpoints_fortianalyzer.yaml → registry_endpoints
    (product='fortianalyzer'); returns rows added. Operator edits/disables in
    the DB always win — same contract as the FortiWeb/FortiADC seeds."""
    from sqlalchemy.exc import IntegrityError

    from ..extensions import db
    from ..models import RegistryEndpoint

    yaml_map = _faz_yaml_registry()
    if not yaml_map:
        return 0
    existing = {
        name for (name,) in db.session.query(RegistryEndpoint.name)
        .filter_by(product="fortianalyzer", api_version="jsonrpc")
    }
    added = 0
    for name, urn in yaml_map.items():
        if not urn or name in existing:
            continue
        db.session.add(RegistryEndpoint(
            product="fortianalyzer", api_version="jsonrpc",
            name=str(name), urn=str(urn), updated_by="seed",
        ))
        added += 1
    if added:
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()  # another worker seeded first — fine
            added = 0
    invalidate_faz_cache()
    return added


# ---------------------------------------------------------------------------
# display helpers (unchanged contract)
# ---------------------------------------------------------------------------

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


def resolve(name: str) -> str:
    """Resolve a logical endpoint name to its ``/api/v2.0/...`` path.

    The single point where services turn a friendly key into a URL — callers
    never hardcode paths (see docs/engineering.md §13). Raises ``KeyError`` if the name is
    not in the registry, so a typo/renamed endpoint fails loudly instead of
    silently building a phantom URL.
    """
    reg = load_registry()
    try:
        return reg[name]
    except KeyError:
        raise KeyError(f"unknown registry endpoint: {name!r}") from None
