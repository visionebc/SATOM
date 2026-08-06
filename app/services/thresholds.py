"""Threshold policy — declare a limit once, apply it to every probe that
inherits it, and always say where the number came from.

Until 2026-08-06 every graded number in this product had exactly two homes: a
column on the individual probe row, and a literal in the code that created that
row. Measured on the live primary that day, **all 42 probes carried the
identical pair 80 / 95** — the discovery default, never once edited. That is
not a fleet whose thresholds were considered and found to agree; it is a fleet
with no way to *state* a threshold. Tuning the target fleet (60 FortiWeb + 30
FortiADC + 10 FortiAnalyzer, ~2 000 probes) meant ~2 000 individual form edits.

The stored values were also partly meaningless: ``warn_pct = 80`` sat on
``interface``, ``proxyd``, ``throughput`` and ``transactions`` rows, none of
which grade on a percentage. Noise that reads as configuration.

This module is the ONE place a threshold is declared, resolved and explained.

Four properties it has to keep
------------------------------

**1. The registry is DATA.** Adding a field is an entry in :data:`MEASURE`,
:data:`ROLLUP`, :data:`FACTS`, :data:`SATOM` or :data:`HOST`; the form, the
validator, the resolver and the origin report all read that entry. The same
contract as ``registry_endpoints`` / ``adoms`` / ``acme_dns_providers``. A
second hand-written list is how a product ends up offerable in a form and
refused by the runner.

**2. Resolution is LIVE, not copy-on-create.** A probe column holding ``NULL``
means *inherit*; the scope default is read at grading time. Copy-on-create is
what already exists — it just spells the literal differently, and it leaves
every probe created before the edit frozen for ever. The cost of live
inheritance is real and is paid deliberately: a probe nobody touched can change
severity because somebody edited a product default. That is the entire point,
and it is why property 3 is not optional.

**3. Every resolved value carries its ORIGIN.** ``probe`` (an explicit override
on this row) / ``scope`` (inherited from a product, the manager or the host) /
``default`` (shipped in this file). Without it a critical appears with no
visible cause and the operator is worse off than with the frozen literals.

**4. ``0`` disables a level; ``NULL`` inherits.** They are different answers and
the storage keeps them different. This is why the migration may only blank a
column that still holds the historical creation default — a ``0`` an operator
chose means "never page me for this", and inheriting over it would page them.

Scopes
------
Six, and they are not interchangeable:

``fortiweb`` ``fortiadc`` ``fortianalyzer`` ``fortiauthenticator``
    The product ADOMs, derived from the ADOM registry (never hardcoded — see
    :mod:`app.services.product_scope` for why that list is derived).
``satom``
    The manager application. Its fields deliberately **store into the existing
    ``alerts.*`` keys** rather than growing a parallel ``thresholds.satom.*``
    namespace. Two keys for one number is drift with a nicer form on top.
``host``
    The machine the manager runs on. Everything here is NEW: before
    2026-08-06 nothing in this product measured its own disk, memory or load.
    satom-node-1 reached 95 % disk on 2026-07-28 and no signal existed to say
    so — it was found by hand.
"""
from __future__ import annotations

import time
from typing import Any, NamedTuple

SCOPE_SATOM = "satom"
SCOPE_HOST = "host"

#: Storage-key prefix owned by this module.
PREFIX = "thresholds."

#: How long a resolved settings snapshot is reused. Same TTL as branding: long
#: enough that a 42-probe sweep is one query, short enough that an operator who
#: saves the form sees the effect on their next page load.
_TTL_S = 15.0


class Field(NamedTuple):
    """One tunable number (or severity choice).

    ``key`` doubles as the probe column name for :data:`MEASURE` fields, so the
    override and the default cannot drift apart by being spelled differently.
    """

    key: str
    label: str
    type: str                 # pct | num | int | hours | ms | days | sev
    default: Any
    unit: str = ""
    help: str = ""
    store: str | None = None  # explicit settings key (SATOM scope)
    legacy: str | None = None # older key still honoured, below the scope value


class Fact(NamedTuple):
    """A BINARY condition — true or false, with no number to compare against.

    "All backends of this policy are down" is not a threshold; it is a fact.
    What the operator can govern is how loudly it lands, and only that. The
    severity may be lowered to ``warn`` or silenced to ``off``, but the fact
    itself is **always printed in the probe detail** — silencing changes the
    grade, never the visibility. A hidden fact is an outage nobody can see.
    """

    key: str
    label: str
    default: str              # crit | warn | off
    kinds: tuple[str, ...]
    help: str = ""


SEVERITIES = ("crit", "warn", "off")


# ── Layer A — measurement, per probe kind ──────────────────────────────────
# The key of every entry IS the MonitorProbe column it overrides. Kinds absent
# from this map grade on facts alone (``proxyd``) or on operator config that is
# not a threshold (``https`` expect_status).
MEASURE: dict[str, tuple[Field, ...]] = {
    "https": (
        Field("warn_ms", "Slow response", "ms", 2000, "ms",
              "Round trip at or above this is a warning. 0 disables."),
        Field("tls_warn_days", "Certificate expiry", "days", 21, "days",
              "Warn when the served certificate has this many days left."),
    ),
    "interface": (
        Field("stale_after_h", "Harvest age budget", "hours", 6, "h",
              "This probe reads the harvest cache, not the device. Older than "
              "this and the reading is reported as stale rather than as "
              "'no change'."),
    ),
    "cpu": (
        Field("warn_pct", "CPU warning", "pct", 80, "%", "0 disables."),
        Field("crit_pct", "CPU critical", "pct", 95, "%", "0 disables."),
    ),
    "memory": (
        Field("warn_pct", "Memory warning", "pct", 80, "%", "0 disables."),
        Field("crit_pct", "Memory critical", "pct", 95, "%", "0 disables."),
    ),
    "sessions": (
        Field("warn_num", "Concurrent sessions warning", "num", 0, "sessions",
              "Absolute count. 0 disables — there is no universally sane "
              "session ceiling, so nothing is shipped enabled."),
        Field("crit_num", "Concurrent sessions critical", "num", 0, "sessions",
              "0 disables."),
    ),
    "policy_sessions": (
        Field("warn_num", "Policy sessions warning", "num", 0, "sessions",
              "MEASURED CAVEAT: on short-lived HTTP this counter stays near "
              "zero under heavy load (594–657 conn/s against 0–3 sessions on "
              "fortiweb08). A threshold here rarely fires; conn/s is what "
              "moves. 0 disables."),
        Field("crit_num", "Policy sessions critical", "num", 0, "sessions",
              "0 disables."),
        Field("warn_ms", "Application latency", "ms", 2000, "ms",
              "Back-end application response time at or above this is a "
              "warning. 0 disables."),
    ),
    "throughput": (
        Field("warn_num", "Throughput warning", "num", 0, "Mbps",
              "Graded on the PEAK of the sampling window, not the mean. "
              "0 disables."),
        Field("crit_num", "Throughput critical", "num", 0, "Mbps", "0 disables."),
    ),
    "transactions": (
        Field("warn_num", "Transactions warning", "num", 0, "transactions",
              "0 disables."),
        Field("crit_num", "Transactions critical", "num", 0, "transactions",
              "0 disables."),
    ),
    "licence": (
        Field("warn_num", "Licence consumed warning", "pct", 80, "% consumed",
              "Percent of the entitlement in use. 0 disables."),
        Field("crit_num", "Licence consumed critical", "pct", 95, "% consumed",
              "0 disables."),
    ),
    "tokens": (
        Field("warn_num", "Token pool warning", "pct", 80, "% consumed",
              "0 disables."),
        Field("crit_num", "Token pool critical", "pct", 95, "% consumed",
              "0 disables."),
    ),
}

#: The value a freshly discovered probe used to be stamped with, per kind and
#: column. The migration blanks a column ONLY when it still holds exactly this
#: — anything else is a choice an operator made and inheriting over it would
#: change what they are paged for.
HISTORICAL_DEFAULT: dict[str, dict[str, Any]] = {
    "*": {"warn_pct": 80, "crit_pct": 95, "warn_ms": 2000,
          "tls_warn_days": 21, "stale_after_h": 6, "warn_mem": 80,
          "warn_num": 0.0, "crit_num": 0.0},
    # FortiAuthenticator probes were created at 80/95 in the numeric columns
    # (FAC_WARN_PCT / FAC_CRIT_PCT), so 80/95 is THEIR historical default and
    # 0 there would be a deliberate silencing.
    "licence": {"warn_num": 80.0, "crit_num": 95.0},
    "tokens": {"warn_num": 80.0, "crit_num": 95.0},
}


# ── Layer B — device roll-up (per product scope) ───────────────────────────
ROLLUP: tuple[Field, ...] = (
    Field("stale_hours", "Cache age budget", "hours", 6.0, "h",
          "A cached configuration older than this makes the device a warning. "
          "Match it to how often this product is actually harvested.",
          legacy="monitoring.stale_hours"),
    Field("crit_stale_mult", "Critical multiplier", "num", 4.0, "x",
          "Cache older than budget x this is critical."),
    Field("error_streak_crit", "Harvest failures before critical", "int", 3,
          "runs", "One failed harvest is a warning; this many in a row is "
                  "critical."),
    Field("capacity_warn_pct", "Object capacity warning", "pct", 80, "%",
          "Against the admin cap for an object type. Types with no cap are "
          "reported as unknown, never as passing."),
    Field("capacity_crit_pct", "Object capacity critical", "pct", 95, "%"),
)


# ── Layer C — binary facts (per product scope) ─────────────────────────────
FACTS: tuple[Fact, ...] = (
    Fact("backends_all_down", "Every backend of a server policy is down",
         "crit", ("policy_sessions",),
         "The front end answers and nothing is behind it."),
    Fact("backends_partial_down", "Some backends of a server policy are down",
         "warn", ("policy_sessions",)),
    Fact("policy_disabled", "Server policy is administratively disabled",
         "warn", ("policy_sessions",),
         "Not admitting traffic. Lower this only where disabled policies are "
         "a normal parking state."),
    Fact("policy_shape_changed", "Server policy membership changed",
         "warn", ("policy_sessions",)),
    Fact("proxyd_absent", "The proxy daemon is not running", "crit",
         ("proxyd",)),
    Fact("proxyd_restarted", "The proxy daemon's PID set changed", "warn",
         ("proxyd",), "A silent restart no ordinary health check surfaces."),
    Fact("iface_changed", "A monitored interface changed IP or link state",
         "crit", ("interface",)),
    Fact("iface_missing", "A monitored interface vanished from the harvest",
         "crit", ("interface",),
         "Named explicitly rather than dropping out of a shorter list."),
    Fact("transactions_zero_under_load",
         "Transaction counter reads zero while the policy carries traffic",
         "warn", ("transactions",),
         "Probably an unattached protection profile. A silent zero over a "
         "saturated service is the failure this grade exists to prevent."),
)

FACT_BY_KEY = {f.key: f for f in FACTS}


# ── The manager application ────────────────────────────────────────────────
# These write the PRE-EXISTING alerts.* keys. The Email tab and this tab are
# two views of one number, deliberately: a thresholds.satom.* twin would be a
# second source and they would drift the first time somebody edited the older
# form.
SATOM: tuple[Field, ...] = (
    # NOTE: every ``default`` below must equal ``alerts.DEFAULTS`` for the same
    # key. They are duplicated rather than derived because a NamedTuple default
    # is evaluated at import and importing the alert engine here would be a
    # cycle -- so the equality is enforced by a test instead
    # (``test_thresholds.py::test_manager_defaults_match_the_alert_engine``).
    # Printing a "factory default" the engine does not actually use is a lie
    # that nothing raises about.
    Field("cert_days", "Certificate expiry warning", "int", 14, "days",
          "Warn when the node's own certificate has this many days left.",
          store="alerts.cert_days"),
    Field("git_behind_max", "Standby commits behind", "int", 25, "commits",
          "", store="alerts.git_behind_max"),
    Field("git_ahead_max_hours", "Unpushed commit age", "hours", 6, "h",
          "Work that exists only on this node. See safeguards §4b.",
          store="alerts.git_ahead_max_hours"),
    Field("backup_max_hours", "Newest backup bundle age", "hours", 48, "h",
          "", store="alerts.backup_max_hours"),
    Field("action_fail_streak_crit", "Scheduled action failures before critical",
          "int", 3, "runs", "", store="alerts.action_fail_streak_crit"),
    Field("action_overdue_hours", "Scheduled action overdue", "hours", 3, "h",
          "An enabled action this late to fire. Without this signal a dead "
          "scheduler grades healthy: it produces no failed runs to count.",
          store="alerts.action_overdue_hours"),
)


# ── The machine ────────────────────────────────────────────────────────────
# Everything below is new. ``crit`` for disk is 92, not 95: by 95 % Postgres can
# already fail to write WAL, so the paging line has to sit before the point of
# damage rather than on it.
HOST: tuple[Field, ...] = (
    Field("disk_warn_pct", "Filesystem used — warning", "pct", 80, "%"),
    Field("disk_crit_pct", "Filesystem used — critical", "pct", 92, "%",
          "Deliberately below 95: a full filesystem stops Postgres writing "
          "WAL, and the page has to arrive before that, not with it."),
    Field("mem_warn_pct", "Memory used — warning", "pct", 85, "%"),
    Field("mem_crit_pct", "Memory used — critical", "pct", 95, "%"),
    Field("load_warn_pct", "Load average per CPU — warning", "num", 150,
          "% of cores",
          "1-minute load as a percentage of core count. 100 % means one "
          "runnable task per core; sustained excess is queueing."),
    Field("load_crit_pct", "Load average per CPU — critical", "num", 400,
          "% of cores"),
)


# ── scope registry ─────────────────────────────────────────────────────────

def product_scopes() -> tuple[tuple[str, str], ...]:
    """``((key, name), ...)`` for the product ADOMs, from the registry."""
    from .product_scope import device_products
    return device_products()


def all_scopes() -> tuple[dict, ...]:
    """Every scope the Thresholds page offers, in display order."""
    out = [{"key": k, "name": n, "type": "product"} for k, n in product_scopes()]
    out.append({"key": SCOPE_SATOM, "name": "SATOM (the application)",
                "type": "manager"})
    out.append({"key": SCOPE_HOST, "name": "SATOM host (the machine)",
                "type": "host"})
    return tuple(out)


def scope_type(scope: str) -> str:
    for s in all_scopes():
        if s["key"] == scope:
            return s["type"]
    return ""


def is_scope(scope: str) -> bool:
    return bool(scope) and any(s["key"] == scope for s in all_scopes())


def fields_for(scope: str, group: str, kind: str | None = None) -> tuple[Field, ...]:
    """The declared fields of one (scope, group).

    ``measure`` is per probe kind and is filtered by what the product can
    actually measure — offering a ``proxyd`` threshold on FortiADC would be a
    control with nothing behind it.
    """
    st = scope_type(scope)
    if group == "satom":
        return SATOM if st == "manager" else ()
    if group == "host":
        return HOST if st == "host" else ()
    if st != "product":
        return ()
    if group == "rollup":
        return ROLLUP
    if group == "measure":
        from .deep_monitor import supports
        if kind is not None:
            return MEASURE.get(kind, ()) if supports(kind, scope) else ()
        return tuple(f for k in measurable_kinds(scope) for f in MEASURE[k])
    return ()


def measurable_kinds(scope: str) -> tuple[str, ...]:
    """Probe kinds this product can measure AND that have tunable numbers."""
    from .deep_monitor import supports
    return tuple(k for k in MEASURE if supports(k, scope))


def facts_for(scope: str) -> tuple[Fact, ...]:
    """Facts reachable on this product — a fact whose kinds the product cannot
    run is not offered, for the same reason as :func:`fields_for`."""
    if scope_type(scope) != "product":
        return ()
    from .deep_monitor import supports
    return tuple(f for f in FACTS if any(supports(k, scope) for k in f.kinds))


# ── storage ────────────────────────────────────────────────────────────────

def store_key(scope: str, field: Field, kind: str | None = None) -> str:
    """Where one field's override lives in ``app_settings``."""
    if field.store:
        return field.store
    if kind:
        return "%s%s.%s.%s" % (PREFIX, scope, kind, field.key)
    return "%s%s.%s" % (PREFIX, scope, field.key)


def fact_key(scope: str, name: str) -> str:
    return "%s%s.fact.%s" % (PREFIX, scope, name)


_cache: dict[str, str] = {}
_cache_at = 0.0


def _settings() -> dict[str, str]:
    """Every key this module can read, in one query, cached for :data:`_TTL_S`.

    A sweep grades ~42 probes with two fields each; per-field ``AppSetting.get``
    would be ~90 round trips every three minutes for values that change when a
    human saves a form.
    """
    global _cache, _cache_at
    now = time.monotonic()
    if _cache_at and (now - _cache_at) < _TTL_S:
        return _cache
    data: dict[str, str] = {}
    try:
        from ..models import AppSetting
        for row in AppSetting.query.all():
            k = getattr(row, "key", None)
            if not k:
                continue
            if k.startswith(PREFIX) or k.startswith("alerts.") \
                    or k == "monitoring.stale_hours":
                data[k] = getattr(row, "value", None)
    except Exception:  # noqa: BLE001 — a threshold read must never break a probe
        return _cache
    _cache, _cache_at = data, now
    return data


def invalidate() -> None:
    """Drop the snapshot (called after a save so the next read is fresh)."""
    global _cache_at
    _cache_at = 0.0


def _coerce(field: Field, raw: Any) -> Any:
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    try:
        if field.type in ("int", "ms", "days"):
            return int(float(str(raw).strip()))
        if field.type == "sev":
            v = str(raw).strip().lower()
            return v if v in SEVERITIES else None
        return float(str(raw).strip())
    except (TypeError, ValueError):
        return None


# ── resolution ─────────────────────────────────────────────────────────────

class Resolved(NamedTuple):
    """A value plus the honest answer to "why is it this?"."""

    value: Any
    origin: str        # probe | scope | default
    scope: str = ""    # which scope supplied it, when origin == "scope"

    @property
    def explain(self) -> str:
        if self.origin == "probe":
            return "set on this probe"
        if self.origin == "scope":
            return "inherited from %s" % (self.scope or "scope")
        return "factory default"


def scope_value(scope: str, field: Field, kind: str | None = None) -> Any:
    """The stored override for one field, or ``None`` if the scope is silent.

    A legacy key is consulted BELOW the scope value and ABOVE the shipped
    default, so an operator who set ``monitoring.stale_hours`` years ago keeps
    what they set until they say otherwise here.
    """
    data = _settings()
    v = _coerce(field, data.get(store_key(scope, field, kind)))
    if v is not None:
        return v
    if field.legacy:
        return _coerce(field, data.get(field.legacy))
    return None


def resolve(scope: str, field: Field, kind: str | None = None) -> Resolved:
    """Scope override, else the shipped default. No probe involved."""
    v = scope_value(scope, field, kind)
    if v is not None:
        return Resolved(v, "scope", scope)
    return Resolved(field.default, "default")


def field_of(kind: str, key: str) -> Field | None:
    for f in MEASURE.get(kind, ()):
        if f.key == key:
            return f
    return None


def probe_scope(probe) -> str:
    """The scope a probe inherits from — its appliance's product.

    A probe with no appliance (a bare URL check against a published hostname)
    inherits from nothing and takes the shipped defaults. Guessing a product
    for it would attach it to a fleet policy it is not part of.
    """
    ap = getattr(probe, "appliance", None)
    return (getattr(ap, "kind", "") or "").strip().lower() if ap else ""


def for_probe(probe, key: str, kind: str | None = None) -> Resolved:
    """Resolve one measurement field for one probe.

    ``NULL`` on the column means inherit; ``0`` means the operator switched
    that level off and is honoured as an explicit answer.
    """
    kind = kind or (getattr(probe, "kind", "") or "")
    field = field_of(kind, key)
    if field is None:
        return Resolved(None, "default")
    raw = getattr(probe, key, None)
    if raw is not None:
        v = _coerce(field, raw)
        if v is not None:
            return Resolved(v, "probe")
    scope = probe_scope(probe)
    if scope:
        v = scope_value(scope, field, kind)
        if v is not None:
            return Resolved(v, "scope", scope)
    return Resolved(field.default, "default")


def num(probe, key: str, kind: str | None = None) -> float:
    """:func:`for_probe` as a bare float — the call site inside a classifier."""
    v = for_probe(probe, key, kind).value
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def probe_origins(probe) -> list[dict]:
    """Every tunable of one probe with value, unit and origin — what the row
    prints so a grade is never unexplained."""
    kind = (getattr(probe, "kind", "") or "")
    out = []
    for f in MEASURE.get(kind, ()):
        r = for_probe(probe, f.key, kind)
        out.append({"key": f.key, "label": f.label, "unit": f.unit,
                    "value": r.value, "origin": r.origin, "scope": r.scope,
                    "explain": r.explain,
                    "inherited": r.origin != "probe"})
    return out


def rollup(scope: str, key: str) -> Resolved:
    for f in ROLLUP:
        if f.key == key:
            return resolve(scope, f)
    return Resolved(None, "default")


def manager(key: str) -> Resolved:
    for f in SATOM:
        if f.key == key:
            return resolve(SCOPE_SATOM, f)
    return Resolved(None, "default")


def host(key: str) -> Resolved:
    for f in HOST:
        if f.key == key:
            return resolve(SCOPE_HOST, f)
    return Resolved(None, "default")


def fact_severity(scope: str, name: str) -> str:
    """``crit`` / ``warn`` / ``off`` for one binary fact on one product."""
    f = FACT_BY_KEY.get(name)
    if f is None:
        return "off"
    if not scope:
        return f.default
    raw = _settings().get(fact_key(scope, name))
    v = (str(raw).strip().lower() if raw is not None else "")
    return v if v in SEVERITIES else f.default


def fact_status(scope: str, name: str) -> str | None:
    """The status a fact contributes, or ``None`` when silenced.

    ``None`` means *do not raise the grade*. The caller still appends the fact
    to the detail text — silencing a fact must never hide it.
    """
    sev = fact_severity(scope, name)
    return None if sev == "off" else sev


# ── writes ─────────────────────────────────────────────────────────────────

def save_scope(scope: str, form: dict) -> dict:
    """Persist one scope's form. Returns ``{saved, cleared, errors}``.

    A BLANK input clears the override (back to inherit / factory default); it
    never stores an empty string, because an empty string would coerce to
    ``None`` on read and look identical while occupying the key.
    """
    from ..models import AppSetting, db

    saved, cleared, errors = 0, 0, []

    def _put(key: str, field: Field, raw: str) -> None:
        nonlocal saved, cleared
        raw = (raw or "").strip()
        if raw == "":
            if AppSetting.get(key, None) is not None:
                AppSetting.set(key, "")
                cleared += 1
            return
        v = _coerce(field, raw)
        if v is None:
            errors.append("%s: %r is not a %s" % (field.label, raw[:24],
                                                  field.type))
            return
        if field.type in ("pct",) and not (0 <= float(v) <= 100):
            errors.append("%s: %s must be 0-100" % (field.label, v))
            return
        if float(v) < 0:
            errors.append("%s: must not be negative" % field.label)
            return
        AppSetting.set(key, str(v))
        saved += 1

    st = scope_type(scope)
    if st == "product":
        for kind in measurable_kinds(scope):
            for f in MEASURE[kind]:
                name = "m__%s__%s" % (kind, f.key)
                if name in form:
                    _put(store_key(scope, f, kind), f, form.get(name))
        for f in ROLLUP:
            name = "r__%s" % f.key
            if name in form:
                _put(store_key(scope, f), f, form.get(name))
        for fact in facts_for(scope):
            name = "f__%s" % fact.key
            if name in form:
                v = (form.get(name) or "").strip().lower()
                if v in SEVERITIES:
                    AppSetting.set(fact_key(scope, fact.key), v)
                    saved += 1
                else:
                    errors.append("%s: unknown severity %r" % (fact.label, v))
    elif st in ("manager", "host"):
        for f in (SATOM if st == "manager" else HOST):
            name = "s__%s" % f.key
            if name in form:
                _put(store_key(scope, f), f, form.get(name))

    db.session.commit()
    invalidate()
    return {"saved": saved, "cleared": cleared, "errors": errors}


def reset_scope(scope: str) -> int:
    """Clear every override a scope owns. Returns how many were cleared.

    The anti-lockout path: a scope tuned into permanent red is one button from
    the shipped behaviour. ``alerts.*``-backed fields are cleared too, which is
    why the manager scope resets to *this file's* defaults and not to whatever
    the Email tab last held.
    """
    from ..models import AppSetting, db
    n = 0
    st = scope_type(scope)
    keys: list[str] = []
    if st == "product":
        for kind in measurable_kinds(scope):
            keys += [store_key(scope, f, kind) for f in MEASURE[kind]]
        keys += [store_key(scope, f) for f in ROLLUP]
        keys += [fact_key(scope, f.key) for f in facts_for(scope)]
    elif st == "manager":
        keys += [store_key(scope, f) for f in SATOM]
    elif st == "host":
        keys += [store_key(scope, f) for f in HOST]
    for k in keys:
        if AppSetting.get(k, None) is not None:
            AppSetting.set(k, "")
            n += 1
    db.session.commit()
    invalidate()
    return n


def state(scope: str) -> dict:
    """Everything the Thresholds tab renders for one scope."""
    st = scope_type(scope)
    out: dict[str, Any] = {"scope": scope, "type": st,
                           "scopes": list(all_scopes())}
    if st == "product":
        out["measure"] = [
            {"kind": kind,
             "fields": [_field_state(scope, f, kind) for f in MEASURE[kind]]}
            for kind in measurable_kinds(scope)]
        out["rollup"] = [_field_state(scope, f) for f in ROLLUP]
        out["facts"] = [
            {"key": f.key, "label": f.label, "help": f.help,
             "value": fact_severity(scope, f.key), "default": f.default,
             "overridden": fact_severity(scope, f.key) != f.default}
            for f in facts_for(scope)]
    elif st in ("manager", "host"):
        out["fields"] = [_field_state(scope, f)
                         for f in (SATOM if st == "manager" else HOST)]
    return out


def _field_state(scope: str, f: Field, kind: str | None = None) -> dict:
    r = resolve(scope, f, kind)
    return {"key": f.key, "label": f.label, "unit": f.unit, "help": f.help,
            "type": f.type, "default": f.default, "value": r.value,
            "origin": r.origin, "explain": r.explain,
            "raw": "" if r.origin == "default" else r.value,
            "store": store_key(scope, f, kind)}
