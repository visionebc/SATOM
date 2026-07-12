"""Product branding registry — DB-backed single source of truth.

The app ships several "ADOMs" that share the same chrome but differ in
identity and scope:

* ``global``    — the fleet-wide console at ``/`` spanning both products.
* ``fortiweb``  — the full Web Application Firewall manager (under ``/web``).
* ``fortiadc``  — Application Delivery Controller (under ``/adc``).
* ``fortiauthenticator`` / ``fortianalyzer`` — placeholder ADOMs: selectable
  and branded (own colored banner), scaffold dashboard only.

**As of 2026-07-12 the registry lives in the ``adoms`` table** (model
``models_adom.Adom``), edited from Settings → ADOMs. This module reads that
table (cached with a short TTL so all gunicorn workers converge after an edit)
and exposes exactly the same public surface the rest of the app already imports:

* ``PRODUCTS``  — a live ``Mapping`` of ACTIVE ADOMs, ``key -> branding dict``.
                  Same object identity forever, so ``from .branding import
                  PRODUCTS`` stays live across edits.
* ``get_product`` / ``is_valid`` / ``DEFAULT_PRODUCT``.
* Capability sequences — ``live_products(cap)`` returns a live sequence of the
  ACTIVE keys that declare a capability. These replace the old hardcoded lists
  (``BANNER_PRODUCTS``, ``VALID_PRODUCTS``, firmware ``_PRODUCTS``,
  ``naming``/``regex_lab`` PRODUCTS) — one flag on the ADOM row now drives them
  all, so a new ADOM can never silently miss a subsystem again.

If the DB is unreachable (pre-migration boot, CLI import outside an app
context), everything falls back to :data:`_FALLBACK` so the app still works.
"""
from __future__ import annotations

import time
from collections.abc import Mapping, Sequence

DEFAULT_PRODUCT = "fortiweb"

# Canonical seed / offline fallback. Also the source for ``seed_defaults()``.
# Order here is the display order (sort_order is assigned from it).
_FALLBACK: list[dict] = [
    {
        "key": "global", "name": "Global", "title": "OFortMAut",
        "tagline": "Global — all products", "mark": "img/global-mark.svg",
        "description": "One console over the whole fleet — dashboards, "
                       "metrics, jobs, certificates and administration "
                       "across FortiWeb and FortiADC.",
        "active": True, "placeholder": False, "banner_default": "slate",
        "cap_banner": False, "cap_tokens": True, "cap_firmware": False,
        "cap_naming": False, "cap_regex": False,
    },
    {
        "key": "fortiweb", "name": "FortiWeb", "title": "OFortMAut",
        "tagline": "Web Application Firewall", "mark": "img/fortiweb-mark.svg",
        "description": "Manage server policies, web protection, exceptions, "
                       "backups and the full FortiWeb appliance fleet.",
        "active": True, "placeholder": False, "banner_default": "slate",
        "cap_banner": True, "cap_tokens": True, "cap_firmware": True,
        "cap_naming": True, "cap_regex": True,
    },
    {
        "key": "fortiadc", "name": "FortiADC", "title": "OFortMAut",
        "tagline": "Application Delivery Controller",
        "mark": "img/fortiadc-mark.svg",
        "description": "Manage virtual servers, server/link/global load "
                       "balancing, WAF, network security and the FortiADC "
                       "appliance fleet.",
        "active": True, "placeholder": False, "banner_default": "ember",
        "cap_banner": True, "cap_tokens": True, "cap_firmware": True,
        "cap_naming": True, "cap_regex": True,
    },
    {
        "key": "fortiauthenticator", "name": "FortiAuthenticator",
        "title": "OFortMAut", "tagline": "Identity & Access Management",
        "mark": "img/fortiauthenticator-mark.svg",
        "description": "Identity management, two-factor authentication, "
                       "certificate authority and RADIUS/LDAP services — "
                       "scaffold in place, modules coming soon.",
        "active": True, "placeholder": True, "banner_default": "indigo",
        "cap_banner": True, "cap_tokens": False, "cap_firmware": False,
        "cap_naming": False, "cap_regex": False,
    },
    {
        "key": "fortianalyzer", "name": "FortiAnalyzer", "title": "OFortMAut",
        "tagline": "Logging & Analytics",
        "mark": "img/fortianalyzer-mark.svg",
        "description": "Centralized logging, reporting and security analytics "
                       "across the fabric — scaffold in place, modules "
                       "coming soon.",
        "active": True, "placeholder": True, "banner_default": "amber",
        "cap_banner": True, "cap_tokens": False, "cap_firmware": False,
        "cap_naming": False, "cap_regex": False,
    },
]

_CAPS = ("banner", "tokens", "firmware", "naming", "regex")

# ── DB-backed cache ─────────────────────────────────────────────────────────
_TTL = 15.0          # seconds; edits become visible fleet-wide within this
_cache_active: "dict[str, dict] | None" = None   # active only, ordered
_cache_all: "list[dict] | None" = None           # every row (admin console)
_cache_ts: float = 0.0


def _fallback_active() -> dict:
    return {d["key"]: dict(d) for d in _FALLBACK if d.get("active", True)}


def _fallback_all() -> list[dict]:
    out = []
    for i, d in enumerate(_FALLBACK):
        row = dict(d)
        row.setdefault("sort_order", i)
        out.append(row)
    return out


def _refresh() -> None:
    """(Re)load the registry from the DB into the module cache. Falls back to
    ``_FALLBACK`` on any failure (no app context, table missing, DB down)."""
    global _cache_active, _cache_all, _cache_ts
    try:
        from .models_adom import Adom
        rows = Adom.query.order_by(Adom.sort_order, Adom.key).all()
        if not rows:
            raise RuntimeError("adoms table empty")
        alld = [r.to_branding() for r in rows]
        _cache_all = alld
        _cache_active = {r["key"]: r for r in alld if r.get("active", True)}
    except Exception:
        _cache_all = _fallback_all()
        _cache_active = _fallback_active()
    _cache_ts = time.monotonic()


def _ensure_fresh() -> None:
    if _cache_active is None or (time.monotonic() - _cache_ts) > _TTL:
        _refresh()


def invalidate() -> None:
    """Force the next read to hit the DB (call right after an admin edit)."""
    global _cache_ts
    _cache_ts = 0.0


def _active() -> "dict[str, dict]":
    _ensure_fresh()
    return _cache_active or _fallback_active()


def all_adoms() -> list[dict]:
    """Every ADOM (active AND inactive), ordered — for the admin console."""
    _ensure_fresh()
    return list(_cache_all if _cache_all is not None else _fallback_all())


# ── live PRODUCTS mapping (active ADOMs) ─────────────────────────────────────
class _ProductRegistry(Mapping):
    """A live, read-only mapping over the ACTIVE ADOMs. Same object identity
    forever so ``from .branding import PRODUCTS`` keeps working after edits."""

    def __getitem__(self, key):
        return _active()[key]

    def __iter__(self):
        return iter(_active())

    def __len__(self):
        return len(_active())

    def __contains__(self, key):
        return key in _active()

    def __repr__(self):
        return "PRODUCTS(%r)" % (list(_active().keys()),)


PRODUCTS = _ProductRegistry()


def get_product(key: str | None) -> dict:
    """Return the branding dict for ``key`` (defaults to FortiWeb)."""
    active = _active()
    if key and key in active:
        return active[key]
    if DEFAULT_PRODUCT in active:
        return active[DEFAULT_PRODUCT]
    # Last resort if the default itself was deactivated.
    return next(iter(active.values())) if active else dict(_FALLBACK[1])


def is_valid(key: str | None) -> bool:
    return key in _active()


# ── capability sequences (replace the old hardcoded lists) ───────────────────
def products_with(cap: str) -> tuple[str, ...]:
    """Tuple of ACTIVE ADOM keys that declare capability ``cap``."""
    flag = "cap_" + cap
    return tuple(k for k, p in _active().items() if p.get(flag))


class _LiveSeq(Sequence):
    """A live, tuple-like sequence recomputed on every access. Binding it with
    ``from x import NAME`` stays live because access re-reads the registry."""

    def __init__(self, producer):
        self._producer = producer

    def _t(self):
        return tuple(self._producer())

    def __getitem__(self, i):
        return self._t()[i]

    def __len__(self):
        return len(self._t())

    def __iter__(self):
        return iter(self._t())

    def __contains__(self, v):
        return v in self._t()

    def __repr__(self):
        return repr(self._t())

    def __eq__(self, other):
        return tuple(self._t()) == tuple(other)

    def __hash__(self):
        return hash(self._t())


def live_products(cap: str) -> _LiveSeq:
    """Live sequence of the ACTIVE ADOM keys with capability ``cap``."""
    return _LiveSeq(lambda: products_with(cap))


def naming_products() -> _LiveSeq:
    """Live ``((key, name), ...)`` pairs for naming-capable active ADOMs."""
    return _LiveSeq(
        lambda: tuple((k, p["name"]) for k, p in _active().items()
                      if p.get("cap_naming")))


# ── seeding (called at boot, after db.create_all) ────────────────────────────
def seed_defaults() -> int:
    """Insert-only seed of the canonical ADOMs. Existing rows (operator edits)
    are never touched. Returns the number of rows inserted."""
    from .extensions import db
    from .models_adom import Adom
    added = 0
    existing = {a.key for a in Adom.query.all()}
    for i, d in enumerate(_FALLBACK):
        if d["key"] in existing:
            continue
        a = Adom(
            key=d["key"], name=d["name"], title=d.get("title", "OFortMAut"),
            tagline=d.get("tagline", ""), description=d.get("description", ""),
            mark=d.get("mark", "img/global-mark.svg"),
            active=d.get("active", True), placeholder=d.get("placeholder", False),
            sort_order=i, banner_default=d.get("banner_default", "slate"),
            cap_banner=d.get("cap_banner", False),
            cap_tokens=d.get("cap_tokens", False),
            cap_firmware=d.get("cap_firmware", False),
            cap_naming=d.get("cap_naming", False),
            cap_regex=d.get("cap_regex", False),
        )
        db.session.add(a)
        added += 1
    if added:
        db.session.commit()
        invalidate()
    return added
