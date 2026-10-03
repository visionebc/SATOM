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

import logging
import time

log = logging.getLogger(__name__)

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
    invalidate_build_views("fortiweb")


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
    """Drop the FortiADC catalog AND the views derived from it.

    ``adc_menu`` memoises its grouping of this catalog and ``adc_objform`` its
    editor allow-list + child-table index; dropping one cache and not the
    others puts a new endpoint in the catalog and leaves it out of the menu
    or the editor -- present and invisible (or disabled and still editable).
    One owner, so no caller can do half of it. Both are also keyed on this
    map's identity, so the OTHER workers converge on the TTL refresh.
    """
    _adc_db_cache["map"] = None
    _adc_db_cache["ts"] = 0.0
    invalidate_build_views("fortiadc")
    from ..services import adc_menu, adc_objform  # lazy: both read this module

    adc_menu.invalidate()
    adc_objform.invalidate()


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
    invalidate_build_views("fortianalyzer")


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
    invalidate_build_views("fortiauthenticator")


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


def _resolve_registry(product: str, name: str) -> str:
    """The product's pure-registry resolver (its ``KeyError`` message included)."""
    return {
        "fortiweb": resolve,
        "fortiadc": resolve_adc,
        "fortianalyzer": resolve_faz,
        "fortiauthenticator": resolve_fac,
    }[product](name)


# ---------------------------------------------------------------------------
# per-build resolution (registry + the API library's evidence for one build)
# ---------------------------------------------------------------------------
# The registry holds ONE URN per name for the whole fleet. A baseline pinned at
# one build disables names that build measured ABSENT — and some of those are
# served by a newer build another box runs. ``resolve_for`` / ``registry_for``
# answer per build, with the same authority order as
# ``api_baseline.resolve_at``: an operator's row wins, then what the library
# MEASURED on that exact build, then the enabled registry. Contract:
# docs/api-library.md §9 "Per-build resolution in the services".

class EndpointNotServed(KeyError):
    """``name`` is known and NOT served by this build (evidence or operator).

    A ``KeyError`` so every caller that already turns an unknown name into a
    named error keeps doing so; the message says why instead of "unknown".
    """

    def __init__(self, product: str, name: str, version: str, authority: str):
        self.product = product
        self.name = name
        self.version = version
        self.authority = authority
        self.message = "%s is not served by %s %s (%s)" % (
            name, product, version or "?", authority)
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


def version_of(obj) -> str:
    """The short firmware build an appliance (or a client built from one) runs.

    ``""`` for anything that does not carry a string ``fw_version`` — a test
    double or a bare namespace must read as "build unknown", never as a
    version parsed out of an object's repr.
    """
    v = getattr(obj, "fw_version", "") if obj is not None else ""
    return v if isinstance(v, str) else ""


def _build_of(version) -> str:
    """The exact X.Y.Z build ``version`` names, or ``""``.

    A line (``"8.0"``) is not a build: evidence recorded against a line never
    said which patch served it, and a per-build answer must not rest on it.
    """
    if not isinstance(version, str) or not version:
        return ""
    from ..services import firmware_versions as fv
    v = fv.normalize(version)
    return v if v and not fv.is_line_only(v) else ""


def _has_db() -> bool:
    """False outside an app context (scripts, import time): no evidence to read,
    and the registry readers already fall back to the shipped baseline there."""
    try:
        from flask import has_app_context
        return has_app_context()
    except Exception:  # noqa: BLE001
        return False


#: ``{(product, build): {"view": dict, "ts": float}}`` — same TTL as the maps.
_build_cache: dict = {}
_fleet_cache: dict = {"map": None, "ts": 0.0}


def invalidate_build_views(product: str | None = None) -> None:
    """Drop the per-build views (of ``product``, or all) and the fleet view."""
    for key in list(_build_cache):
        if product is None or key[0] == product:
            _build_cache.pop(key, None)
    if product in (None, "fortiweb"):
        _fleet_cache["map"] = None
        _fleet_cache["ts"] = 0.0


def _build_view(product: str, build: str) -> dict:
    """Everything the per-build rules need for ``product`` at ``build``.

    ``rows``: ``{name: (enabled, urn, operator, updated_by)}`` for every
    registry row; ``measured``: ``{name: (verdict, urn, sources)}`` from
    MEASURED evidence of that exact build; ``map``: the resulting
    ``{name: urn}``. Raises on a DB error — the callers fall back.
    """
    now = time.monotonic()
    hit = _build_cache.get((product, build))
    if hit is not None and (now - hit["ts"]) < _CACHE_TTL:
        return hit["view"]
    from ..models import RegistryEndpoint
    from ..services import api_baseline

    rows = {r.name: (bool(r.enabled), r.urn, not api_baseline.is_owned(r.updated_by),
                     r.updated_by or "")
            for r in RegistryEndpoint.query.filter_by(
                product=product, api_version=API_VERSION[product]).all()}
    measured = {n: (e.get("verdict"), e.get("urn") or "", list(e.get("sources") or []))
                for n, e in api_baseline._measured_at(product, build).items()}

    reg = dict(load_product_registry(product))
    out: dict = {}
    for name, urn in reg.items():
        row = rows.get(name)
        if row is not None and row[2]:
            out[name] = urn                      # (a) an operator's enabled row
            continue
        m = measured.get(name)
        if m is not None and m[0] == "absent":
            continue                             # (b) measured absent here
        out[name] = m[1] if (m is not None and m[0] == "ok" and m[1]) else urn
    for name, row in rows.items():
        if name in out or row[2]:
            continue
        m = measured.get(name)
        if m is not None and m[0] == "ok" and m[1]:
            out[name] = m[1]                     # baseline-owned row, served here
    view = {"rows": rows, "measured": measured, "map": out}
    _build_cache[(product, build)] = {"view": view, "ts": now}
    return view


def _safe_build_view(product: str, build: str) -> dict | None:
    """:func:`_build_view`, or ``None`` (with a warning) when evidence is unreadable."""
    if not _has_db():
        return None
    try:
        return _build_view(product, build)
    except Exception as exc:  # noqa: BLE001 — never break a caller over evidence
        log.warning("per-build registry view of %s %s unavailable, serving the "
                    "registry: %s", product, build, exc)
        try:
            from ..extensions import db
            db.session.rollback()
        except Exception:  # noqa: BLE001 — no app context: nothing to roll back
            pass
        return None


def resolve_for(product: str, name: str, version) -> str:
    """Resolve ``name`` for a box of ``product`` running ``version``.

    (a) an operator's row wins: enabled → its URN, disabled →
    :class:`EndpointNotServed`; (b) the library's MEASURED evidence of that
    exact build: ok with a URN → that URN, absent → :class:`EndpointNotServed`;
    (c) the enabled registry; (d) the product's usual ``KeyError``.

    An empty or unparseable ``version`` is exactly the pure registry resolver.
    Unreadable evidence (DB error) falls through to (c) with a warning.
    """
    build = _build_of(version)
    view = _safe_build_view(product, build) if build else None
    if view is not None:
        row = view["rows"].get(name)
        if row is not None and row[2]:
            if row[0]:
                return row[1]
            raise EndpointNotServed(product, name, build,
                                    "registry row disabled by %s" % (row[3] or "unknown"))
        m = view["measured"].get(name)
        if m is not None and m[0] == "ok" and m[1]:
            return m[1]
        if m is not None and m[0] == "absent":
            raise EndpointNotServed(product, name, build,
                                    "evidence: %s" % (", ".join(m[2]) or "measured"))
    return _resolve_registry(product, name)


def registry_for(product: str, version) -> dict:
    """The ``{name: urn}`` map a box of ``product`` on ``version`` is served.

    The enabled registry, minus names measured absent on that build (unless an
    operator's enabled row), with the measured URN in place of the registry's
    (unless an operator's row), plus names whose baseline-owned row is disabled
    but that build measured served. Empty/unparseable ``version`` → the pure
    registry. Cached per (product, build) with the registry's TTL.
    """
    build = _build_of(version)
    view = _safe_build_view(product, build) if build else None
    if view is None:
        return load_product_registry(product)
    return view["map"]


def _fleet_extras() -> dict:
    """``{name: urn}`` of baseline-owned DISABLED FortiWeb rows that a build
    running in the live fleet measured served (newest build's URN wins)."""
    from ..services import api_library
    from ..services import firmware_versions as fv

    builds = sorted({b for b in (_build_of(w.get("version") or "")
                                 for w in api_library._fleet("fortiweb").values()) if b},
                    key=fv.sort_key)
    extras: dict = {}
    for build in builds:
        view = _build_view("fortiweb", build)
        for name, row in view["rows"].items():
            if row[0] or row[2]:
                continue                  # enabled already, or an operator's row
            m = view["measured"].get(name)
            if m is not None and m[0] == "ok" and m[1]:
                extras[name] = m[1]
    return extras


def load_fleet_registry() -> dict:
    """The FortiWeb ``{name: urn}`` the fleet-wide consumers offer.

    The enabled registry ∪ names whose baseline-owned row is disabled but that
    are measured served on at least one build a live box runs today — so an
    8.0.x-only endpoint stays in the menus and the sweep while an 8.0.x box is
    in the fleet. :func:`load_registry` stays the pure registry.
    """
    reg = load_registry()
    if not _has_db():
        return reg
    now = time.monotonic()
    extras = _fleet_cache["map"]
    if extras is None or (now - _fleet_cache["ts"]) >= _CACHE_TTL:
        try:
            extras = _fleet_extras()
        except Exception as exc:  # noqa: BLE001 — never break a menu over evidence
            log.warning("fleet registry view unavailable, serving the registry: %s", exc)
            try:
                from ..extensions import db
                db.session.rollback()
            except Exception:  # noqa: BLE001
                pass
            return reg
        _fleet_cache["map"] = extras
        _fleet_cache["ts"] = now
    if not extras:
        return reg
    out = dict(reg)
    for name, urn in extras.items():
        out.setdefault(name, urn)
    return out


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


def _display(reg: dict) -> list:
    result = [_endpoint_dict(name, urn, _section_of(urn)) for name, urn in reg.items()]
    return sorted(result, key=lambda e: ((e['section'] or '~'), e['name']))


def get_all_endpoints() -> list:
    """The FLEET view of the FortiWeb catalog as display dicts, sorted by
    section then name: the enabled registry plus the names a live build still
    serves after a baseline disabled them (:func:`load_fleet_registry`). What
    the nav menus, the sweep plan and the editor allow-lists offer."""
    return _display(load_fleet_registry())


def get_registry_endpoints() -> list:
    """The PURE registry (enabled rows only) as display dicts — for the pages
    that administer or account for the registry itself."""
    return _display(load_registry())


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
