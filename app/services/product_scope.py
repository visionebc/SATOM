"""Product (ADOM) scoping — the ONE place that decides which product a new
record is stamped with and which records the active session may see.

Sessions carry ``session['product']`` (set by ``views.product`` / the
app-factory product gate). Visibility rule, as of 2026-08-05:

* a CONCRETE ADOM sees only the rows stamped with ITS OWN key;
* ``fortiweb`` additionally sees the NULL/'' rows — it is the only product
  that predates stamping, so unscoped rows are FortiWeb-era by construction;
* ``global`` / no request context (background workers) sees everything.

Stamping mirrors it: a record created inside a concrete ADOM carries that
product; anything created from the global ADOM or a worker thread stays ''
(unscoped). Callers may always pass an explicit product to override.

**Why the rule is an INCLUSION and the key set is DERIVED.** Until 2026-08-05
the FortiWeb branch was written as an exclusion (``kind NOT IN (fortiadc,
fortianalyzer)``) and the recognised keys were a hardcoded tuple. Both are
bug generators, and adding FortiAuthenticator fired both at once:

* the exclusion list never learned the new key, so ``fac01`` showed up in the
  FortiWeb ADOM;
* the hardcoded tuple did not contain ``'fortiauthenticator'``, so
  :func:`session_product` returned '' inside the FAC ADOM and every filter
  below became a no-op — that ADOM saw EVERY product's rows.

Neither failure raises. A new ADOM is a row in the registry, so the key set is
read from the registry (:func:`app.branding.all_adoms`, inactive rows
included) and each filter names the product it keeps. A product declared
tomorrow is scoped the day it is declared.
"""
from __future__ import annotations

from flask import has_request_context, session

FORTIWEB = "fortiweb"
FORTIADC = "fortiadc"
FORTIANALYZER = "fortianalyzer"
FORTIAUTHENTICATOR = "fortiauthenticator"
FORTIGATE = "fortigate"
GLOBAL = "global"

# The one product that also owns the unscoped rows (see module docstring).
LEGACY_PRODUCT = FORTIWEB

#: Returned by :func:`session_product` when the ADOM of the ACTIVE REQUEST
#: could not be determined. Deliberately NOT '': '' is the legitimate "Global
#: console / background worker — show everything", and reusing one value for
#: both "everything, on purpose" and "I could not tell" is the whole bug. Every
#: filter below maps this to ZERO rows and :func:`stamp` refuses to write it.
#: :func:`product_keys` discards it, so no registry key can ever impersonate it.
UNRESOLVED = "__unresolved__"


class ProductScopeUnresolved(RuntimeError):
    """Raised by :func:`stamp` when the ADOM of this request is unknown.

    A new record has to land in an ADOM. Writing '' instead files it as
    unscoped, and unscoped rows belong to the FortiWeb ADOM by construction —
    a wrong ADOM the operator cannot see is worse than a failed save it can.
    """

# Offline fallback only — used when the ADOM registry cannot be read (CLI
# import outside an app context, pre-migration boot). Never the primary source.
_FALLBACK_KEYS = frozenset(
    {GLOBAL, FORTIWEB, FORTIADC, FORTIANALYZER, FORTIAUTHENTICATOR,
     FORTIGATE})


def product_keys() -> frozenset[str]:
    """Every ADOM key this installation has, ``global`` included.

    Read from the registry rather than declared here. INACTIVE rows count:
    deactivating an ADOM must not make its key unrecognised, because an
    unrecognised key does not fail closed — it falls through every filter
    below and shows that session everything."""
    try:
        from ..branding import all_adoms
        keys = {str(r.get("key") or "").strip().lower() for r in all_adoms()}
        keys.discard("")
        keys.discard(UNRESOLVED)   # no ADOM may impersonate the sentinel
        if keys:
            return frozenset(keys | {GLOBAL})
    except Exception:  # noqa: BLE001 — scoping must never break a caller
        pass
    return _FALLBACK_KEYS


def concrete_products() -> frozenset[str]:
    """The product ADOMs — every key except ``global``. A session in one of
    these is filtered; anything else (``global``, '', a worker thread) is not."""
    return product_keys() - {GLOBAL}


def registry_degraded() -> bool:
    """True when the ADOM key set is the OFFLINE FALLBACK, not the registry.

    :func:`app.branding.all_adoms` never raises: when the table cannot be read
    it returns a hardcoded six-ADOM list. So the ``except`` in
    :func:`product_keys` is NOT the path a degraded registry takes — the
    fallback arrives looking like a successful answer, and a sixth ADOM an
    operator declared is simply missing from it. A session holding that key
    used to resolve to '' and see every product's rows.

    The import is deliberately not wrapped: renaming ``is_fallback`` must fail
    loudly here rather than quietly restore the fail-open default.
    """
    from ..branding import is_fallback
    return bool(is_fallback())


def session_product() -> str:
    """The EFFECTIVE product of the active request, '' outside a request
    context. Per-tab ADOM (2026-07-07): resolution order is ``g.product``
    (stamped by the app-factory product gate: URL scope > X-ADOM header >
    session) > the raw ``X-ADOM`` header (a caller running before/without
    the gate) > the session cookie. The session is only the default for
    header-less requests — one browser tab switching ADOM no longer changes
    what another tab sees.

    Every source is validated against :func:`product_keys`. The session cookie
    used to be returned unchecked, which is how a key the filters below did not
    recognise reached them.

    Three outcomes, and the middle one is new (2026-08-07):

    * a recognised key — that ADOM;
    * :data:`UNRESOLVED` — a request DID name an ADOM, it is not in the key
      set, and :func:`registry_degraded` says the key set itself is the offline
      fallback. We cannot prove the key is bogus, so we refuse to guess: every
      filter below yields zero rows and :func:`stamp` raises. Failing closed is
      recoverable; showing one ADOM another's fleet is not;
    * '' — no ADOM was named at all (Global console, background worker, CLI).
      That is a LEGITIMATE "show everything" and it stays exactly as it was.
    """
    try:
        in_request = has_request_context()
    except Exception:  # noqa: BLE001 — no Flask at all (plain CLI import)
        return ""
    if not in_request:
        return ""              # background worker / CLI — everything, by design
    degraded = registry_degraded()
    try:
        from flask import g, request
        valid = product_keys()
        p = getattr(g, "product", None)
        if p in valid:
            return p
        h = (request.headers.get("X-ADOM") or "").strip().lower()
        if h in valid:
            return h
        s = (session.get("product") or "").strip().lower()
        if s in valid:
            return s
        named = (p if isinstance(p, str) else "") or h or s
    except Exception:  # noqa: BLE001 — scoping must never break a caller
        return UNRESOLVED if degraded else ""
    if named and degraded:
        return UNRESOLVED
    return ""


#: Per-request cache key for :func:`restricted_adoms` (``flask.g``).
_G_ADOMS = "_satom_allowed_adoms"
_NOT_CACHED = object()


def adoms_of(user) -> frozenset[str] | None:
    """The ADOM keys ``user`` is confined to, ``None`` for every ADOM.

    Reads :attr:`app.models.User.allowed_adoms` (the profile). Any error reading
    it confines to NOTHING: a restriction that cannot be read must not turn
    into "everything"."""
    if user is None or not getattr(user, "is_authenticated", False):
        return None
    try:
        allowed = user.allowed_adoms
    except Exception:  # noqa: BLE001 — fail closed, never open
        return frozenset()
    if allowed is None:
        return None
    return frozenset(str(k).strip().lower() for k in allowed)


def _current_user():
    """Whose ADOMs and devices apply to this request: the OWNER of the API
    token on /api/v1 (2026-11-07: until then a token saw its product's whole
    fleet whatever its owner's profile confined -- the API never signs a user
    in), else the signed-in user."""
    try:
        from flask import g
        owner = g.get("api_token_owner")
        if owner is not None:
            return owner
    except Exception:  # noqa: BLE001
        pass
    try:
        from flask_login import current_user
        return current_user._get_current_object()
    except Exception:  # noqa: BLE001 -- no login manager (bare test app)
        return None


def restricted_adoms() -> frozenset[str] | None:
    """ADOM confinement of the SIGNED-IN user of this request.

    ``None`` = unrestricted: outside a request (background workers, CLI — they
    act on the whole fleet, as they always did), anonymous requests, and every
    user whose profile names no ADOM. A confined user's Global console is the
    UNION of their ADOMs, never the whole fleet: every filter below applies the
    set, and the app-factory gate refuses a concrete ADOM outside it."""
    try:
        if not has_request_context():
            return None
    except Exception:  # noqa: BLE001
        return None
    from flask import g
    cached = getattr(g, _G_ADOMS, _NOT_CACHED)
    if cached is not _NOT_CACHED:
        return cached
    allowed = adoms_of(_current_user())
    setattr(g, _G_ADOMS, allowed)
    return allowed


def adom_allowed(key: str | None, allowed=_NOT_CACHED) -> bool:
    """May the signed-in user (or ``allowed``) enter ADOM ``key``? Global is
    always allowed — for a confined user it is the union of their ADOMs."""
    if allowed is _NOT_CACHED:
        allowed = restricted_adoms()
    k = (key or "").strip().lower()
    if allowed is None or k == GLOBAL:
        return True
    return k in allowed


def _allowed_clause(column, allowed: frozenset[str]):
    """SQL condition: ``column`` is one of ``allowed``. NULL/'' rows are the
    FortiWeb ADOM's (module docstring), so they count only when FortiWeb is in
    the set. An empty set yields FALSE — zero rows, never all rows."""
    from sqlalchemy import false, or_
    if not allowed:
        return false()
    conds = [column.in_(sorted(allowed))]
    if LEGACY_PRODUCT in allowed:
        conds += [column.is_(None), column == ""]
    return or_(*conds)


def stamp() -> str:
    """Value to store on a record created now ('' = unscoped).

    Raises :class:`ProductScopeUnresolved` when the ADOM could not be
    determined — see :data:`UNRESOLVED`.

    A user confined to some ADOMs who creates something from the Global
    console does not get an unscoped record — unscoped rows belong to the
    FortiWeb ADOM, which they may not see. It lands in their only ADOM, in
    '' when FortiWeb is one of theirs, else in the first of theirs in
    registry order: always somewhere its creator can see it.
    """
    p = session_product()
    if p == UNRESOLVED:
        raise ProductScopeUnresolved(
            "the ADOM of this request could not be determined (the ADOM "
            "registry is serving its offline fallback); refusing to stamp the "
            "record unscoped, which would file it under the FortiWeb ADOM")
    if p in concrete_products():
        return p
    allowed = restricted_adoms()
    if allowed is None:
        return ""
    if not allowed:
        raise ProductScopeUnresolved(
            "this account is confined to no ADOM it can write into")
    if len(allowed) == 1:
        return next(iter(allowed))
    if LEGACY_PRODUCT in allowed:
        return ""
    order = [k for k, _ in device_products() if k in allowed]
    return order[0] if order else sorted(allowed)[0]


def visible_product(record_product: str | None) -> bool:
    """Pure visibility check for file/JSON-backed records (the job store)."""
    p = session_product()
    if p == UNRESOLVED:
        return False       # ADOM unknown → show nothing, never everything
    allowed = restricted_adoms()
    rp = (record_product or "").strip().lower()
    if p not in concrete_products():
        if allowed is None:
            return True
        if not rp:
            return LEGACY_PRODUCT in allowed
        return rp in allowed
    if allowed is not None and p not in allowed:
        return False
    if not rp:
        return p == LEGACY_PRODUCT
    return rp == p


def scope_query(query, column, any_adom: bool = False):
    """Apply the same rule to a SQLAlchemy query. ``column`` is the model's
    ``product`` column; NULL/'' rows count as unscoped (visible to FortiWeb
    and Global, hidden from every other ADOM). A user confined to some ADOMs
    sees, in Global, only the rows of those ADOMs.

    ``any_adom=True`` applies the GLOBAL rule whatever ADOM the request is in:
    every ADOM the signed-in user may enter, and still nothing of the others.
    For records that follow their reader from ADOM to ADOM (bookmarks,
    2026-11-08). An unresolved ADOM still yields zero rows."""
    p = session_product()
    if p == UNRESOLVED:
        from sqlalchemy import false
        return query.filter(false())   # ADOM unknown → zero rows, not all rows
    if any_adom:
        p = GLOBAL
    allowed = restricted_adoms()
    if allowed is not None and p in concrete_products() and p not in allowed:
        from sqlalchemy import false
        return query.filter(false())
    if p not in concrete_products():
        if allowed is not None:
            return query.filter(_allowed_clause(column, allowed))
        return query
    if p == LEGACY_PRODUCT:
        from sqlalchemy import or_
        return query.filter(or_(
            column.is_(None), column == "", column == p))
    return query.filter(column == p)


# ── device kinds (the appliance roster an ADOM may show / create) ───────────
# An appliance's ``kind`` IS an ADOM key, so the roster of kinds is the roster
# of product ADOMs. Deriving it here is the same rule the module docstring
# already argues for the key set: a hardcoded list in a form is how
# FortiAuthenticator ended up unofferable in "New appliance" for a day after it
# became a real product, with nothing raising — the option was simply absent.
_FALLBACK_DEVICE_PRODUCTS = (
    (FORTIWEB, "FortiWeb"),
    (FORTIADC, "FortiADC"),
    (FORTIAUTHENTICATOR, "FortiAuthenticator"),
    (FORTIANALYZER, "FortiAnalyzer"),
)


def device_products() -> tuple[tuple[str, str], ...]:
    """``((key, display name), ...)`` for every ACTIVE product ADOM, in
    registry order. ``global`` is excluded: it is a console, not a device."""
    try:
        from ..branding import all_adoms
        out = []
        for row in all_adoms():
            key = str(row.get("key") or "").strip().lower()
            if not key or key == GLOBAL or not row.get("active", True):
                continue
            out.append((key, str(row.get("name") or key)))
        if out:
            return tuple(out)
    except Exception:  # noqa: BLE001 — scoping must never break a caller
        pass
    return _FALLBACK_DEVICE_PRODUCTS


def creatable_kinds() -> tuple[tuple[str, str], ...]:
    """The kinds the ACTIVE session may put on an appliance.

    A concrete ADOM gets exactly ONE: its own. Offering the others there
    creates a device the creating session cannot see the moment it is saved —
    the row lands in a different ADOM and the operator reads it as a failed
    save. Global, which sees everything, gets the full roster."""
    everything = device_products()
    p = session_product()
    if p == UNRESOLVED:
        return ()          # nothing may be created into an unknown ADOM
    allowed = restricted_adoms()
    if allowed is not None and p in concrete_products() and p not in allowed:
        return ()
    if p not in concrete_products():
        if allowed is not None:
            return tuple(t for t in everything if t[0] in allowed)
        return everything
    mine = tuple(t for t in everything if t[0] == p)
    # An ADOM deactivated mid-session still has to be able to name itself,
    # or its console would render a form with no platform to choose.
    return mine or ((p, p),)


def may_assign_kind(kind: str | None) -> bool:
    """Server side of :func:`creatable_kinds`. The form is a hint; this is the
    rule. Without it, a posted ``kind`` field is a one-field ADOM jump."""
    k = (kind or "").strip().lower()
    return bool(k) and k in {key for key, _ in creatable_kinds()}


# ── device scope (2026-11-07): WHERE inside the ADOMs ───────────────────────
_G_IDS = "_satom_allowed_appliance_ids"
_G_DSCOPE = "_satom_device_scope"


def device_scope_of(user):
    """The device scope of ``user`` (``Profile.device_scope_map``); ``None`` =
    no scope. An error reading it confines to NOTHING."""
    if user is None or not getattr(user, "is_authenticated", False):
        return None
    try:
        return user.device_scope
    except Exception:  # noqa: BLE001 -- fail closed, never open
        from ..models import Profile
        return dict(Profile.DEVICE_SCOPE_DENY)


def restricted_device_scope():
    """Device scope of the signed-in user of this request (``None`` outside a
    request, like :func:`restricted_adoms`: workers act on the whole fleet)."""
    try:
        if not has_request_context():
            return None
    except Exception:  # noqa: BLE001
        return None
    from flask import g
    cached = getattr(g, _G_DSCOPE, _NOT_CACHED)
    if cached is not _NOT_CACHED:
        return cached
    scope = device_scope_of(_current_user())
    setattr(g, _G_DSCOPE, scope)
    return scope


def reachable_appliance_ids(adoms, scope) -> frozenset[int] | None:
    """Every appliance id a profile with ``adoms`` and ``scope`` reaches;
    ``None`` when neither restricts. Also what a job snapshots at enqueue."""
    if adoms is None and scope is None:
        return None
    from ..models import Appliance
    from . import device_scope as DS
    return frozenset(a.id for a in Appliance.query.all() if DS.reaches(a, adoms, scope))


def allowed_appliance_ids() -> frozenset[int] | None:
    """The ONE answer to "which devices may the signed-in user reach": the
    intersection of the profile's ADOMs and its device scope, cached for the
    request. ``None`` = unrestricted (no ADOM confinement and no device
    scope, or no request: workers act on the whole fleet)."""
    try:
        if not has_request_context():
            return None
    except Exception:  # noqa: BLE001
        return None
    from flask import g
    cached = getattr(g, _G_IDS, _NOT_CACHED)
    if cached is not _NOT_CACHED:
        return cached
    ids = reachable_appliance_ids(restricted_adoms(), restricted_device_scope())
    setattr(g, _G_IDS, ids)
    return ids


def job_appliance_ids(job: dict) -> set[int]:
    """The devices a job names: ``meta.appliance_id`` / ``meta.appliance_ids``
    and the ones it wrote to."""
    meta = (job or {}).get("meta") or {}
    out = set()
    vals = [meta.get("appliance_id")] + list(meta.get("appliance_ids") or []) \
        + list((job or {}).get("wrote_to") or [])
    for v in vals:
        try:
            if v is not None and str(v).strip():
                out.add(int(v))
        except (TypeError, ValueError):
            continue
    return out


def job_visible(job: dict) -> bool:
    """A job is shown when its ADOM is (:func:`visible_product`) and every
    device it names is one the user reaches -- the confined_appliance_ids
    rule for the file-backed job store."""
    if not visible_product(((job or {}).get("meta") or {}).get("product")):
        return False
    ids = allowed_appliance_ids()
    return ids is None or job_appliance_ids(job) <= set(ids)


def partial_chassis(appl) -> bool:
    """The signed-in user reaches only SOME partitions of this device's box."""
    from . import device_scope as DS
    return DS.partial(appl, restricted_device_scope())


def scope_appliance_query(query, kind_column, any_adom: bool = False):
    """ADOM rule (:func:`_scope_appliance_query_adom`) plus, for a profile with
    a device scope, only the appliances it reaches (an id is all a by-id
    route needs to 404 a device outside the scope). ``any_adom`` as in
    :func:`scope_query`; the device scope applies either way."""
    q = _scope_appliance_query_adom(query, kind_column, any_adom=any_adom)
    if restricted_device_scope() is None:
        return q
    from ..models import Appliance
    if getattr(kind_column, "class_", None) is not Appliance:
        return q
    ids = allowed_appliance_ids()
    if ids is None:
        return q
    if not ids:
        from sqlalchemy import false
        return q.filter(false())
    return q.filter(Appliance.id.in_(sorted(ids)))


def _scope_appliance_query_adom(query, kind_column, any_adom: bool = False):
    """Scope an Appliance query by device KIND: a concrete ADOM sees only the
    boxes of its own product; the FortiWeb ADOM also sees NULL/'' kinds
    (FortiWeb-era by construction); Global/workers see all.

    A device whose ``kind`` matches no registered ADOM is therefore visible in
    the Global ADOM only. That is deliberate — no product console can manage
    it — and Global is where it stays discoverable."""
    p = session_product()
    if p == UNRESOLVED:
        from sqlalchemy import false
        return query.filter(false())   # ADOM unknown → zero rows, not all rows
    if any_adom:
        p = GLOBAL
    allowed = restricted_adoms()
    if allowed is not None and p in concrete_products() and p not in allowed:
        from sqlalchemy import false
        return query.filter(false())
    if p not in concrete_products():
        if allowed is not None:
            # A confined user's Global: the devices of their ADOMs only. A kind
            # no ADOM owns is Global-only (docstring) — not theirs.
            return query.filter(_allowed_clause(kind_column, allowed))
        return query
    if p == LEGACY_PRODUCT:
        from sqlalchemy import or_
        return query.filter(or_(
            kind_column.is_(None), kind_column == "", kind_column == p))
    return query.filter(kind_column == p)


def confined_appliance_ids() -> frozenset[int] | None:
    """Every appliance id the signed-in user's PROFILE reaches, whatever the
    active ADOM is; ``None`` when the profile names no ADOM and has no device
    scope (since 2026-11-07 it is :func:`allowed_appliance_ids`).

    For records that name several devices across ADOMs (a change request, an
    upgrade window): the per-ADOM rule shows such a record in every ADOM that
    owns ANY of its devices. A confined profile must not open one that also
    names a device outside its ADOMs — the page would list that device and
    could act on it."""
    return allowed_appliance_ids()
