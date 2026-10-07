"""Schema adapters: one per product, all feeding the SAME per-build, per-channel model.

Every Fortinet product describes its configuration schema differently:

=====================  ===========================  ==============================
product                CLI schema                   REST schema
=====================  ===========================  ==============================
FortiWeb               ``tree`` (types, options)    shape probe of each tree object
FortiADC               ``tree`` (assumed FortiOS    none implemented (unverified)
                       family, unverified)
FortiAuthenticator     no ``tree``: ``config X`` +  Tastypie ``/api/v1/<res>/schema/``
                       ``set ?`` help per object    (the directory is complete)
FortiGate              ``tree`` (FortiOS format)    ``GET /api/v2/cmdb/?action=schema``
FortiAnalyzer          JSON-RPC ``get`` with        same answer (the JSON-RPC
                       ``option: syntax``           ``/cli/global/...`` URL IS the CLI path)
=====================  ===========================  ==============================

Whatever the product, an adapter ends in the same place: evidence documents
of the library sources (``cli_tree`` / ``cli_full`` / ``schema`` / ``sweep``)
keyed by the canonical REST path, stored through ``api_library.ingest`` and
read back per build and per channel by ``api_library.channels_at``.

Each adapter DECLARES what it can do (:class:`Capabilities`) and how far that
was checked (``verified`` + the device and build it was verified on, or
``None``). The UI shows the unverified flag; nothing here claims a check that
did not happen.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class Capabilities:
    #: the CLI prints the whole schema (``tree``, or FAC's ``set ?`` walk)
    tree: bool = False
    #: ``show full-configuration`` reveals field names (hidden fields)
    show_full: bool = False
    #: the device serves a REST/JSON-RPC schema (types, options, ranges)
    rest_schema: bool = False
    #: REST fields are measured by probing objects (no schema served)
    rest_probe: bool = False


@dataclass(frozen=True)
class Verification:
    """Where and when an adapter was checked against a real device."""
    date: str
    device: str
    build: str
    note: str = ""


@dataclass(frozen=True)
class Adapter:
    product: str
    label: str
    capabilities: Capabilities
    #: ``None`` = never checked against a device; every claim is a documented
    #: convention and the UI says so.
    verified_on: tuple = ()
    #: per capability that is NOT verified, why (shown in the UI)
    unverified: dict = field(default_factory=dict)
    #: True when SATOM can run the harvest live (an Appliance of this kind and
    #: the credentials it needs). FortiGate is catalog-only: evidence arrives by
    #: pack or by file import.
    live: bool = False
    #: the CLI-channel source this adapter writes (what "schema harvested" means
    #: for the new-build watch).
    cli_source: str = "cli_tree"
    notes: str = ""

    @property
    def verified(self) -> bool:
        return bool(self.verified_on) and not self.unverified

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verified"] = self.verified
        d["verified_on"] = [asdict(v) for v in self.verified_on]
        return d


_REGISTRY: dict = {}


def register(adapter: Adapter, harvest=None) -> Adapter:
    _REGISTRY[adapter.product] = (adapter, harvest)
    return adapter


def get(product: str) -> Adapter | None:
    _load()
    hit = _REGISTRY.get(product or "")
    return hit[0] if hit else None


def harvester(product: str):
    """The live ``harvest(appliance, **kw) -> dict`` of a product, or None."""
    _load()
    hit = _REGISTRY.get(product or "")
    return hit[1] if hit else None


def all_adapters() -> list:
    _load()
    return [a for a, _h in sorted(_REGISTRY.values(), key=lambda t: t[0].product)]


def harvest(appliance, **kw) -> dict:
    """Harvest ``appliance`` through its product's adapter. NEVER raises."""
    product = getattr(appliance, "kind", "") or ""
    fn = harvester(product)
    if fn is None:
        return {"ok": False, "reason": "unsupported", "product": product,
                "msg": "no schema adapter can harvest %s live" % (product or "this appliance")}
    try:
        return fn(appliance, **kw)
    except Exception as exc:  # noqa: BLE001 — one box must never break a caller
        return {"ok": False, "reason": "error", "product": product,
                "msg": ("%s: %s" % (type(exc).__name__, exc))[:300]}


_LOADED = False


def _load() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    from . import fortiadc, fortianalyzer, fortiauthenticator, fortigate, fortiweb  # noqa: F401


__all__ = ["Capabilities", "Verification", "Adapter", "register", "get", "harvester",
           "all_adapters", "harvest"]
