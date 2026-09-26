"""DB-first REST endpoint registry, seeded from a build-pinned baseline.

The registry lives in the ``registry_endpoints`` table (PostgreSQL — editable
in production from the Registry page, captured by the nightly ``pg_dump``).
Its seed is the product's endpoint BASELINE (``services.api_baseline``): the
catalog promoted from what the API library measured on one firmware build and
shipped sealed in ``app/registry/baselines/<product>.json``. The four
hand-written ``endpoints*.yaml`` files this replaced are gone.

* at boot ``api_baseline.boot`` inserts the shipped baseline and reconciles the
  registry to it — rows an operator edited or disabled are never touched;
* if the DB is unreachable or empty (early scripts, standalone tools), the
  shipped baseline is served directly so nothing breaks on a fresh tree.

Reads go through a per-process cache with a short TTL: an edit invalidates the
cache of the worker that served it immediately, the other gunicorn workers
converge within ``_CACHE_TTL`` seconds.

UI sections are derived at read time via :func:`categories.category_for`. All
helpers return display-ready dicts shaped for the registry/API-explorer
templates (``name``/``urn``/``path``/``section``/``methods``/``method``).
"""
from __future__ import annotations

import time

_CACHE_TTL = 60.0  # seconds — cross-worker convergence window after an edit

# The registry key is (product, api_version, name) — the ACTIVE api_version per
# product, in ONE place, read by the baseline and the reader.
#
# Until this existed the two halves disagreed: every old YAML seeder had
# always scoped its INSERT-ONLY check by api_version, while every reader
# filtered on product alone and built ``{r.name: r.urn}``. The moment a second
# api_version row exists for a name the dict collapses — one row wins by
# arbitrary query order and its URN is served to *every* consumer
# (scheduled_actions, clone, write_through, exception_inject, objedit) with no
# error and no log. The ``api_version`` box on the New/Edit Endpoint modal is
# free text, so any REGISTRY_EDIT holder could arm that today.
#
# Note this is the API version, NOT the firmware line: FortiWeb 7.6 and 8.0
# both speak v2.0 and differ in FIELDS, which is ``services.api_matrix``.
API_VERSION = {
    "fortiweb": "v2.0",
    "fortiadc": "v1",
    "fortianalyzer": "jsonrpc",
    "fortiauthenticator": "v1",
}

_shipped_cache: dict | None = None
_db_cache: dict = {"map": None, "ts": 0.0}


# ---------------------------------------------------------------------------
# sources
# ---------------------------------------------------------------------------

def _shipped_registry() -> dict:
    """``{name: urn}`` of the shipped fortiweb baseline — the no-database fallback."""
    global _shipped_cache
    if _shipped_cache is None:
        from ..services.api_baseline import artifact_map
        _shipped_cache = artifact_map("fortiweb")
    return _shipped_cache


def _db_registry() -> dict | None:
    """``{name: urn}`` from ``registry_endpoints`` (enabled rows only), or
    ``None`` when the DB can't serve it (no app context / table missing /
    never seeded) — the caller then falls back to the shipped baseline."""
    now = time.monotonic()
    if _db_cache["map"] is not None and (now - _db_cache["ts"]) < _CACHE_TTL:
        return _db_cache["map"]
    try:
        from ..models import RegistryEndpoint
        rows = RegistryEndpoint.query.filter_by(
            product="fortiweb", api_version=API_VERSION["fortiweb"], enabled=True).all()
        if not rows:
            return None
        reg = {r.name: r.urn for r in rows}
    except Exception:  # noqa: BLE001 — any DB hiccup → shipped baseline
        return None
    _db_cache["map"] = reg
    _db_cache["ts"] = now
    return reg


def invalidate_cache() -> None:
    """Drop the per-process DB cache (called after every registry write)."""
    _db_cache["map"] = None
    _db_cache["ts"] = 0.0


def load_registry() -> dict:
    """Return the active ``{friendly_key: urn}`` map (DB first, shipped-baseline fallback)."""
    reg = _db_registry()
    if reg is not None:
        return reg
    return _shipped_registry()



# ---------------------------------------------------------------------------
# FortiADC registry (product='fortiadc', api_version='v1')
# ---------------------------------------------------------------------------
# Same DB-first + shipped-baseline contract as FortiWeb, kept as a parallel,
# product-scoped set of helpers so the (hot) FortiWeb paths stay untouched.
# FortiADC REST has no version segment in the URL (paths are /api/<object>);
# 'v1' is the registry's own versioning bucket. URNs derive from the CLI
# object tree (``config load-balance virtual-server`` →
# ``/api/load_balance_virtual_server``).

_adc_shipped_cache: dict | None = None
_adc_db_cache: dict = {"map": None, "ts": 0.0}


def _adc_shipped_registry() -> dict:
    """``{name: urn}`` of the shipped fortiadc baseline — the no-database fallback."""
    global _adc_shipped_cache
    if _adc_shipped_cache is None:
        from ..services.api_baseline import artifact_map
        _adc_shipped_cache = artifact_map("fortiadc")
    return _adc_shipped_cache


def _adc_db_registry() -> dict | None:
    now = time.monotonic()
    if _adc_db_cache["map"] is not None and (now - _adc_db_cache["ts"]) < _CACHE_TTL:
        return _adc_db_cache["map"]
    try:
        from ..models import RegistryEndpoint
        rows = RegistryEndpoint.query.filter_by(
            product="fortiadc", api_version=API_VERSION["fortiadc"], enabled=True).all()
        if not rows:
            return None
        reg = {r.name: r.urn for r in rows}
    except Exception:  # noqa: BLE001 — any DB hiccup → shipped baseline
        return None
    _adc_db_cache["map"] = reg
    _adc_db_cache["ts"] = now
    return reg


def invalidate_adc_cache() -> None:
    """Drop the FortiADC catalog AND the GUI menu grouped from it.

    ``adc_menu`` memoises its grouping of this catalog; dropping one cache
    and not the other puts a new endpoint in the catalog and leaves it out
    of the menu -- present and invisible. One owner, so no caller can do
    half of it.
    """
    _adc_db_cache["map"] = None
    _adc_db_cache["ts"] = 0.0
    from ..services import adc_menu  # lazy: adc_menu reads this module

    adc_menu.invalidate()


def load_adc_registry() -> dict:
    """The active FortiADC ``{friendly_key: urn}`` map (DB first, shipped-baseline fallback)."""
    reg = _adc_db_registry()
    if reg is not None:
        return reg
    return _adc_shipped_registry()


def resolve_adc(name: str) -> str:
    """Resolve a FortiADC logical endpoint name to its ``/api/...`` path."""
    reg = load_adc_registry()
    try:
        return reg[name]
    except KeyError:
        raise KeyError(f"unknown FortiADC registry endpoint: {name!r}") from None



# ---------------------------------------------------------------------------
# FortiAnalyzer registry (product='fortianalyzer', api_version='jsonrpc')
# ---------------------------------------------------------------------------
# Same DB-first + shipped-baseline contract as FortiWeb/FortiADC, kept as a
# parallel, product-scoped set of helpers. URNs are JSON-RPC urls (single
# transport POST /jsonrpc — dialect picked by the client from the URL family,
# see app/clients/fortianalyzer.py).

_faz_shipped_cache: dict | None = None
_faz_db_cache: dict = {"map": None, "ts": 0.0}


def _faz_shipped_registry() -> dict:
    """``{name: urn}`` of the shipped fortianalyzer baseline — the no-database fallback."""
    global _faz_shipped_cache
    if _faz_shipped_cache is None:
        from ..services.api_baseline import artifact_map
        _faz_shipped_cache = artifact_map("fortianalyzer")
    return _faz_shipped_cache


def _faz_db_registry() -> dict | None:
    now = time.monotonic()
    if _faz_db_cache["map"] is not None and (now - _faz_db_cache["ts"]) < _CACHE_TTL:
        return _faz_db_cache["map"]
    try:
        from ..models import RegistryEndpoint
        rows = RegistryEndpoint.query.filter_by(
            product="fortianalyzer", api_version=API_VERSION["fortianalyzer"], enabled=True).all()
        if not rows:
            return None
        reg = {r.name: r.urn for r in rows}
    except Exception:  # noqa: BLE001 — any DB hiccup → shipped baseline
        return None
    _faz_db_cache["map"] = reg
    _faz_db_cache["ts"] = now
    return reg


def invalidate_faz_cache() -> None:
    _faz_db_cache["map"] = None
    _faz_db_cache["ts"] = 0.0


def load_faz_registry() -> dict:
    """The active FortiAnalyzer ``{friendly_key: urn}`` map (DB first, shipped-baseline fallback)."""
    reg = _faz_db_registry()
    if reg is not None:
        return reg
    return _faz_shipped_registry()


def resolve_faz(name: str) -> str:
    """Resolve a FortiAnalyzer logical endpoint name to its JSON-RPC url."""
    reg = load_faz_registry()
    try:
        return reg[name]
    except KeyError:
        raise KeyError(f"unknown FortiAnalyzer registry endpoint: {name!r}") from None




# ---------------------------------------------------------------------------
# FortiAuthenticator registry (product='fortiauthenticator', api_version='v1')
# ---------------------------------------------------------------------------
# Same DB-first + shipped-baseline contract as the other three products, kept as a
# parallel, product-scoped set of helpers. URNs here are plain REST paths
# (``/api/v1/<resource>/``) — FortiAuthenticator is a Django/Tastypie API, not
# the Fortinet CMDB tree, and not JSON-RPC.

_fac_shipped_cache: dict | None = None
_fac_db_cache: dict = {"map": None, "ts": 0.0}


def _fac_shipped_registry() -> dict:
    """``{name: urn}`` of the shipped fortiauthenticator baseline — the no-database fallback."""
    global _fac_shipped_cache
    if _fac_shipped_cache is None:
        from ..services.api_baseline import artifact_map
        _fac_shipped_cache = artifact_map("fortiauthenticator")
    return _fac_shipped_cache


def _fac_db_registry() -> dict | None:
    now = time.monotonic()
    if _fac_db_cache["map"] is not None and (now - _fac_db_cache["ts"]) < _CACHE_TTL:
        return _fac_db_cache["map"]
    try:
        from ..models import RegistryEndpoint
        rows = RegistryEndpoint.query.filter_by(
            product="fortiauthenticator",
            api_version=API_VERSION["fortiauthenticator"], enabled=True).all()
        if not rows:
            return None
        reg = {r.name: r.urn for r in rows}
    except Exception:  # noqa: BLE001 — any DB hiccup -> shipped baseline
        return None
    _fac_db_cache["map"] = reg
    _fac_db_cache["ts"] = now
    return reg


def invalidate_fac_cache() -> None:
    _fac_db_cache["map"] = None
    _fac_db_cache["ts"] = 0.0


def load_fac_registry() -> dict:
    """The active FortiAuthenticator ``{friendly_key: urn}`` map (DB first,
    shipped-baseline fallback)."""
    reg = _fac_db_registry()
    if reg is not None:
        return reg
    return _fac_shipped_registry()


def resolve_fac(name: str) -> str:
    """Resolve a FortiAuthenticator logical endpoint name to its REST path."""
    reg = load_fac_registry()
    try:
        return reg[name]
    except KeyError:
        raise KeyError(
            f"unknown FortiAuthenticator registry endpoint: {name!r}") from None


def load_product_registry(product: str) -> dict:
    """The active ``{name: urn}`` map of any registry product."""
    return {
        "fortiweb": load_registry,
        "fortiadc": load_adc_registry,
        "fortianalyzer": load_faz_registry,
        "fortiauthenticator": load_fac_registry,
    }[product]()


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
