"""Capacity guardrails — how many of each object a FortiWeb model can hold.

Two numbers per (model, object type):

* the **factory limit** — Fortinet's published ceiling. It arrives in the
  ``capacity-limits`` items of the signed API / knowledge packs (the harvester
  reads the Max Value Table API and Appendix B of the admin guide) and is
  stored per exact build in ``capacity_factory`` (models_capacity). Hardware
  models carry a number; FortiWeb-VM carries a RULE on the VM's memory
  (``MemTotal`` of ``diagnose hardware mem list``, rounded down to whole GB —
  Fortinet's own wording), evaluated against ``device_hardware``;
* the **admin's limit** in ``CapacityLimit`` — a number or a percent of the
  factory limit (``operational_cap`` / ``cap_percent``), plus ``hard_max`` as
  an OVERRIDE of the factory number for the rare case Fortinet is wrong.

The effective cap is the lowest of them. Automations call ``check_headroom``
BEFORE creating an object so they never push the box past a limit it will
reject.

A factory number the device already EXCEEDS is not enforced: the box itself
proves it accepts more (an older build, a licence tier the model string does
not show), and blocking on a number the device contradicts would stop work
the box would take. It is shown, marked, and the admin's own limit still
applies.

Pure-ish: the only side of this that touches the network is nothing — counts
come from the local device-object cache (``DeviceObject``), never a live box.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from ..extensions import db
from ..models import CapacityLimit
from ..models_cache import DeviceObject


# ---------------------------------------------------------------------------
# Object-type catalog — the stable logical tokens the caps are keyed by.
# ``count_logicals`` = the device-cache ``logical_name`` values that make up a
# live count of this type (verified against the real cache on fortiweb17).
# ``cli`` = the CLI table the factory limit is published for (the Max Value
# API's object name). ``scope`` = where Fortinet counts it: ``appliance``
# (GLOBAL — the whole chassis, every ADOM row of it) or ``adom`` (VDOM — each
# ADOM row on its own).
# ---------------------------------------------------------------------------
OBJECT_TYPES: dict[str, dict] = {
    "server_policy": {
        "label": "Server Policies",
        "count_logicals": ["server_policy"],
        "cli": "server-policy.policy", "scope": "appliance",
        "order": 10,
    },
    # Inline and offline profiles have SEPARATE ceilings (256 each per ADOM on
    # every build measured); one shared type checked them against one number.
    "web_protection_profile": {
        "label": "Web Protection Profiles (inline)",
        "count_logicals": ["webprotection_profile_inline"],
        "cli": "waf web-protection-profile.inline-protection", "scope": "adom",
        "order": 20,
    },
    "web_protection_profile_offline": {
        "label": "Web Protection Profiles (offline)",
        "count_logicals": ["webprotection_profile_offline"],
        "cli": "waf web-protection-profile.offline-protection", "scope": "adom",
        "order": 25,
    },
    "certificate": {
        "label": "Local Certificates",
        "count_logicals": ["certificate"],
        "cli": "system certificate.local", "scope": "adom",
        "order": 30,
    },
    "sni": {
        "label": "SNI Policies",
        "count_logicals": ["certificate_sni"],
        "cli": "system certificate.sni", "scope": "adom",
        "order": 40,
    },
    "server_pool": {
        "label": "Server Pools",
        "count_logicals": ["server_pool"],
        "cli": "server-policy.server-pool", "scope": "appliance",
        "order": 50,
    },
    "virtual_server": {
        "label": "Virtual Servers",
        "count_logicals": ["vserver"],
        "cli": "server-policy.vserver", "scope": "adom",
        "order": 60,
    },
    "virtual_ip": {
        "label": "Virtual IPs",
        "count_logicals": ["vip"],
        "cli": "system.vip", "scope": "appliance",
        "order": 70,
    },
}

PRODUCT_DEFAULT = "fortiweb"

# Suggested model/SKU list for the registration dropdown. FortiWeb-VM caps scale
# with the licensed vCPU/vRAM tier; hardware models carry their own datasheet
# numbers. This is only the pick-list — the NUMBERS live in CapacityLimit and
# are admin-entered (nothing here is invented as a limit).
KNOWN_MODELS: list[str] = [
    "FortiWeb-VM",
    "FortiWeb-100E", "FortiWeb-400E", "FortiWeb-600E",
    "FortiWeb-1000E", "FortiWeb-2000E", "FortiWeb-3000E", "FortiWeb-4000E",
    "FortiWeb-100F", "FortiWeb-400F", "FortiWeb-600F",
    "FortiWeb-1000F", "FortiWeb-2000F", "FortiWeb-3000F", "FortiWeb-4000F",
]


def object_types_ordered() -> list[tuple[str, dict]]:
    return sorted(OBJECT_TYPES.items(), key=lambda kv: kv[1]["order"])


def firmware_major(firmware: str | None) -> str | None:
    """'7.6.8' -> '7.6', 'FortiWeb-VM 8.0.5 build...' -> '8.0'. None if unparseable."""
    if not firmware:
        return None
    m = re.search(r"(\d+)\.(\d+)", str(firmware))
    return f"{m.group(1)}.{m.group(2)}" if m else None


def firmware_build(firmware: str | None) -> str | None:
    """'FortiWeb-KVM 7.6.8,build1128(GA.M)' -> '7.6.8'. None if no X.Y.Z."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", str(firmware or ""))
    return ".".join(m.groups()) if m else None


# ---------------------------------------------------------------------------
# Platform — the key Fortinet publishes limits for
# ---------------------------------------------------------------------------

#: Hypervisor / cloud words in a model string: every one of them is FortiWeb-VM.
_VM_WORDS = re.compile(r"\b(?:VM\d*|KVM|VMWARE|HYPERV|HYPER-V|XEN|AWS|AZURE|GCP|OCI|"
                       r"ALI(?:CLOUD)?|OPC|NUTANIX)\b", re.I)


def platform_id(model: str | None, product: str = PRODUCT_DEFAULT) -> str | None:
    """The token Fortinet keys limits by: ``FortiWeb-KVM 7.6.8`` -> ``VM``,
    ``FortiWeb-1000F 7.6.8`` / ``FortiWeb 1000F`` -> ``1000F``.

    ``appliances.model`` is what ``get system status`` printed, and on
    FortiWeb that string carries the firmware ("FortiWeb-KVM 7.6.8"): keying
    the catalog by it made one "model" per patch release, none of which
    Fortinet publishes a number for."""
    s = str(model or "").strip()
    if not s:
        return None
    s = re.sub(r"\s+v?\d+\.\d+(?:\.\d+)?\b.*$", "", s)      # trailing firmware
    prefix = {"fortiweb": "FortiWeb", "fortiadc": "FortiADC",
              "fortigate": "FortiGate"}.get(product or PRODUCT_DEFAULT, "")
    if prefix:
        s = re.sub(r"^%s" % prefix, "", s, flags=re.I)
    s = s.strip(" -_")
    if _VM_WORDS.search(s) or s.upper().startswith("VM"):
        m = re.fullmatch(r"VM(\d{2})", s.upper())
        return "VM" + m.group(1) if m and m.group(1) == "16" else "VM"
    tok = re.sub(r"[\s\-_]+", "", s).upper()
    return tok or None


def platform_label(pid: str | None, product: str = PRODUCT_DEFAULT) -> str | None:
    """``VM`` -> ``FortiWeb-VM``; ``1000F`` -> ``FortiWeb-1000F``."""
    if not pid:
        return None
    prefix = {"fortiweb": "FortiWeb", "fortiadc": "FortiADC",
              "fortigate": "FortiGate"}.get(product or PRODUCT_DEFAULT, product or "")
    return "%s-%s" % (prefix, pid)


def catalog_model(model: str | None, product: str = PRODUCT_DEFAULT) -> str | None:
    """The CapacityLimit ``model`` key for a free-text model (a registered
    appliance's or one typed on the page). A string that names neither the
    product nor a hypervisor is kept as typed: re-spelling an arbitrary label
    would only make it unfindable."""
    s = str(model or "").strip()
    prefix = {"fortiweb": "FortiWeb", "fortiadc": "FortiADC",
              "fortigate": "FortiGate"}.get(product or PRODUCT_DEFAULT, "")
    if not s or not ((prefix and s.lower().startswith(prefix.lower()))
                     or _VM_WORDS.search(s)):
        return s or None
    return platform_label(platform_id(s, product), product)


# ---------------------------------------------------------------------------
# Limit lookups (DB)
# ---------------------------------------------------------------------------

def get_limit(model: str | None, fw_major: str | None, object_type: str,
              product: str = PRODUCT_DEFAULT) -> CapacityLimit | None:
    if not model or not fw_major:
        return None
    return CapacityLimit.query.filter_by(
        product=product, firmware_major=fw_major, model=model,
        object_type=object_type).first()


def limit_for_appliance(appliance, object_type: str) -> CapacityLimit | None:
    product = appliance.kind or PRODUCT_DEFAULT
    return get_limit(catalog_model(appliance.model, product),
                     firmware_major(appliance.firmware), object_type, product=product)


# ---------------------------------------------------------------------------
# Live counts (from the local device-object cache — no box call)
# ---------------------------------------------------------------------------

def current_count(appliance_id: int, object_type: str) -> int:
    """Objects of ``object_type`` recorded against ONE appliance ROW.

    Kept as THE counting seam: ``chassis_count`` sums this per sibling rather
    than issuing its own widened query. A second query path would have moved
    the seam that existing callers and tests already intercept, and the first
    symptom of that is a test that stops isolating the database — which is
    exactly how this refactor first broke tests/test_capacity_plan.py."""
    spec = OBJECT_TYPES.get(object_type)
    if not spec:
        return 0
    logicals = spec["count_logicals"]
    # DISTINCT (logical, mkey): the cache keeps the same object in more than
    # one layer (``config`` and ``deep``), and a plain count read fortiweb17's
    # 50 server policies as 100 (measured 2026-10-24, `show server-policy
    # policy` over SSH = 50). A DISTINCT subquery, not count(distinct (a, b)):
    # SQLite has no row values inside an aggregate.
    return int(db.session.query(DeviceObject.logical_name, DeviceObject.mkey).filter(
        DeviceObject.appliance_id == appliance_id,
        DeviceObject.logical_name.in_(logicals)).distinct().count() or 0)


def chassis_count(appliance, object_type: str) -> tuple[int, int]:
    """``(used in the scope Fortinet counts the type in, rows counted)``.

    An ``appliance``-scope cap (server policies, pools, VIPs) is a property of
    the HARDWARE — it comes from the model and the firmware, not from the
    ADOM. A multi-ADOM device registered as three rows was therefore getting
    three independent budgets against one physical box, and every one of them
    reported room. Verified live on fortiweb09: the policy list differs per
    ADOM (so the rows really do hold different objects) while
    ``system/interface`` is identical from all of them (so the hardware really
    is shared). An ``adom``-scope cap (profiles, certificates, virtual
    servers: Fortinet's VDOM scope) is counted on the row alone — summing the
    chassis would block an ADOM that has room.

    Degrades to the single row whenever the grouping cannot be resolved — an
    unknown chassis must NARROW, never widen to unrelated devices."""
    if (OBJECT_TYPES.get(object_type) or {}).get("scope") == "adom":
        return current_count(appliance.id, object_type), 1
    try:
        from ..models import chassis_siblings
        rows = chassis_siblings(appliance)
    except Exception:  # noqa: BLE001 — no app context / unit-test fakes
        rows = [appliance]
    ids = [r.id for r in rows if getattr(r, "id", None) is not None] \
        or [appliance.id]
    ids = sorted(set(ids))
    return sum(current_count(i, object_type) for i in ids), len(ids)


# ---------------------------------------------------------------------------
# Factory limits (capacity_factory, from the packs)
# ---------------------------------------------------------------------------

@dataclass
class Factory:
    """Fortinet's published ceiling for one object type on one appliance."""
    value: int | None = None
    build: str | None = None        # the build whose document answered
    exact: bool = False             # that build == the appliance's build
    source: str = ""                # max-value-api | admin-guide
    note: str = ""                  # why there is no value / how it was derived
    doubtful: bool = False          # the source cell was flagged by the harvester
    rule: str = ""                  # VM rule in words

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _vkey(v: str) -> tuple:
    return tuple(int(x) for x in v.split("."))


def factory_doc(product: str, build: str | None) -> tuple[dict | None, str | None, bool]:
    """``(document, build it is for, exact)``: the appliance's own build when a
    pack shipped it, else the nearest build of the SAME major (the highest one
    not newer than it, else the oldest newer one). Never another major: limits
    move between majors (7.6.1 and 7.6.4 changed several)."""
    if not build:
        return None, None, False
    from ..models_capacity import CapacityFactory
    rows = CapacityFactory.query.filter_by(product=product).all()
    by = {r.firmware: r for r in rows}
    if build in by:
        return by[build].document, build, True
    major = firmware_major(build)
    same = sorted((v for v in by if firmware_major(v) == major), key=_vkey)
    if not same:
        return None, None, False
    older = [v for v in same if _vkey(v) <= _vkey(build)]
    pick = older[-1] if older else same[0]
    return by[pick].document, pick, False


def mem_gb(appliance) -> int | None:
    """Whole GB of ``MemTotal`` (rounded DOWN, as Fortinet's VM rule says),
    from the last hardware scan; None when the device was never scanned."""
    from ..models import DeviceHardware
    row = DeviceHardware.query.filter_by(appliance_id=appliance.id).first()
    if row is None or not row.mem_total_mb:
        return None
    return int(row.mem_total_mb) // 1024


def _cmp(op: str, a: int, b: int) -> bool:
    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}.get(op, False)


def eval_vm_rule(rule: dict, gb: int) -> int | None:
    """A FortiWeb-VM rule from the pack, evaluated for ``gb`` whole GB."""
    kind = (rule or {}).get("rule")
    if kind == "fixed":
        return rule.get("value")
    tiers = rule.get("tiers") or []
    for t in tiers:
        if kind == "linear" and t.get("op") in (">=", ">") and _cmp(t["op"], gb, t["gb"]):
            return t.get("value")
        if kind == "tiers" and _cmp(t.get("op", ""), gb, t.get("gb", 0)):
            return t.get("value")
    if kind == "linear":
        n = rule["base"] + rule["per_gb"] * max(0, gb - rule.get("from_gb", 1))
        return min(n, rule["cap"]) if rule.get("cap") is not None else n
    return None


def describe_vm_rule(rule: dict) -> str:
    kind = (rule or {}).get("rule")
    if kind == "fixed":
        return "%s on every FortiWeb-VM" % rule.get("value")
    if kind == "linear":
        s = "%d for the first GB of RAM + %d per extra GB, at most %d" % (
            rule["base"], rule["per_gb"], rule["cap"])
        for t in rule.get("tiers") or []:
            s += "; %d with %s %d GB" % (t["value"], t["op"], t["gb"])
        return s
    if kind == "tiers":
        return "; ".join("%d with RAM %s %d GB" % (t["value"], t["op"], t["gb"])
                         for t in rule.get("tiers") or [])
    return ""


def factory_for(appliance, object_type: str) -> Factory:
    """Fortinet's ceiling for ``object_type`` on ``appliance`` (never raises:
    a missing pack, an unknown model or no app context is a Factory with no
    value and a note saying why)."""
    spec = OBJECT_TYPES.get(object_type) or {}
    product = getattr(appliance, "kind", None) or PRODUCT_DEFAULT
    try:
        doc, build, exact = factory_doc(product, firmware_build(appliance.firmware))
    except Exception:  # noqa: BLE001 — no app context / table not created yet
        return Factory(note="factory limits unavailable")
    if doc is None:
        return Factory(note="no factory limits for this build yet (they arrive with the "
                            "knowledge / API packs)")
    obj = (doc.get("objects") or {}).get(spec.get("cli", ""))
    src = (obj or {}).get("source", "")
    if not obj:
        return Factory(build=build, exact=exact,
                       note="Fortinet publishes no limit for %s" % spec.get("cli", object_type))
    pid = platform_id(appliance.model, product)
    values = obj.get("values") or {}
    doubt = pid in (obj.get("doubtful") or [])
    if pid == "VM" and obj.get("vm"):
        rule = describe_vm_rule(obj["vm"])
        try:
            gb = mem_gb(appliance)
        except Exception:  # noqa: BLE001
            gb = None
        if gb is None:
            return Factory(build=build, exact=exact, source=src, rule=rule,
                           note="depends on the VM's memory: run a hardware scan")
        return Factory(eval_vm_rule(obj["vm"], gb), build, exact, src,
                       "%d GB of RAM" % gb, doubt, rule)
    if pid in values:
        return Factory(values[pid], build, exact, src, "", doubt)
    if "*" in values:
        return Factory(values["*"], build, exact, src, "same on every other model", doubt)
    return Factory(build=build, exact=exact, source=src,
                   note="Fortinet publishes no %s value for %s"
                        % (spec.get("cli", object_type), platform_label(pid, product) or "?"))


@dataclass
class Headroom:
    object_type: str
    label: str
    used: int
    hard_max: int | None
    operational_cap: int | None
    effective_cap: int | None
    free: int | None          # effective_cap - used (None if no cap defined)
    ok: bool                  # would a +1 create stay within the cap?
    known: bool               # is there a cap row at all?
    # How many appliance ROWS the `used` count spans. 1 for an ordinary
    # device; N for a multi-ADOM chassis. Carried on the measurement itself so
    # every consumer describes the number it was given — asking a second time
    # would be a second measurement, and a stubbed Headroom (the unit tests)
    # would then be paired with a live DB query.
    rows: int = 1
    #: Fortinet's ceiling for this device (None = not published / not known)
    factory: int | None = None
    factory_info: dict = field(default_factory=dict)
    #: the device already holds MORE than the factory number: not enforced
    contradicted: bool = False
    scope: str = "appliance"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def effective_limit(factory: int | None, lim, *, used: int | None = None) -> tuple:
    """``(effective cap, base, contradicted)`` from the factory number and the
    admin row. Base = the admin override (``hard_max``) or else the factory
    number; the admin's number and percent (of the base) can only LOWER it.
    A factory number the device already exceeds is dropped from the base
    (see the module docstring); an override is the admin's word and stays."""
    override = lim.hard_max if lim is not None else None
    contradicted = (override is None and factory is not None and used is not None
                    and used > factory)
    base = override if override is not None else (None if contradicted else factory)
    vals = [v for v in (base, lim.operational_cap if lim is not None else None)
            if v is not None]
    pct = lim.cap_percent if lim is not None else None
    if pct is not None and base is not None:
        try:
            p = float(pct)
            if 0 < p <= 100:
                vals.append(int(base * p / 100.0))
        except (TypeError, ValueError):
            pass
    return (min(vals) if vals else None), base, contradicted


def headroom(appliance, object_type: str, want: int = 0) -> Headroom:
    """Capacity picture for one object type on one appliance. ``want`` = how many
    MORE the caller intends to create (0 = just report). ``ok`` is True when no
    cap is known (fail-open — a missing cap must not block work) or when
    used+want stays within the effective cap."""
    spec = OBJECT_TYPES.get(object_type, {})
    label = spec.get("label", object_type)
    # In the scope Fortinet counts it: CHASSIS-wide for appliance limits (a
    # multi-ADOM device is several rows on one box), the row for ADOM limits.
    used, n_rows = chassis_count(appliance, object_type)
    lim = limit_for_appliance(appliance, object_type)
    fac = factory_for(appliance, object_type)
    eff, _base, contradicted = effective_limit(fac.value, lim, used=used)
    free = (eff - used) if eff is not None else None
    ok = True if eff is None else (used + max(want, 0) <= eff)
    return Headroom(object_type, label, used, lim.hard_max if lim else None,
                    lim.operational_cap if lim else None, eff, free, ok,
                    known=eff is not None, rows=n_rows, factory=fac.value,
                    factory_info=fac.to_dict(), contradicted=contradicted,
                    scope=spec.get("scope", "appliance"))


def fleet_headroom(appliance) -> list[Headroom]:
    return [headroom(appliance, k) for k, _ in object_types_ordered()]


def check_headroom(appliance, object_type: str, want: int = 1) -> tuple[bool, str]:
    """The guardrail automations call before creating ``want`` objects.

    Returns (allowed, message). Fail-OPEN when no cap is configured (so an
    un-provisioned model never blocks work) but the message says so. Fail-CLOSED
    only when a cap exists and would be exceeded."""
    h = headroom(appliance, object_type, want=want)
    # When the count spans several ADOM rows, SAY SO. "used 812" against a row
    # the operator believes holds 300 reads as a bug in the counter unless the
    # message names the other rows it is counting. Read off the Headroom that
    # was already computed — a second chassis_count here would query the DB
    # even when the caller stubbed `headroom`, which is precisely the coupling
    # that broke tests/test_capacity_plan.py.
    scope = (f" across {h.rows} ADOM rows on {appliance.host}"
             if getattr(h, "rows", 1) > 1 else "")
    if not h.known or h.effective_cap is None:
        why = (f"the device already holds {h.used}, more than Fortinet's published "
               f"{h.factory}: that number is not enforced"
               if getattr(h, "contradicted", False) else "No capacity limit set")
        return True, (f"{why} for {appliance.model or '?'} "
                      f"{firmware_major(appliance.firmware) or '?'} / {h.label}; "
                      f"allowing (used={h.used}{scope}).")
    if h.ok:
        return True, (f"OK: {h.used}+{want} <= {h.effective_cap} {h.label} "
                      f"(free {h.free}{scope}).")
    fac = getattr(h, "factory", None)
    ceiling = (f"Fortinet's limit {fac}" if fac is not None and h.hard_max is None
               else f"hard max {h.hard_max}")
    return False, (f"Capacity limit reached for {h.label} on {appliance.name}: "
                   f"used {h.used}{scope} + {want} would exceed cap "
                   f"{h.effective_cap} ({ceiling}).")


def object_type_for_logical(logical: str) -> str | None:
    """The capped object type a registry LOGICAL name counts towards."""
    for otype, spec in OBJECT_TYPES.items():
        if logical in spec["count_logicals"]:
            return otype
    return None


def check_plan_headroom(appliance, wants: dict[str, int]
                        ) -> tuple[bool, list[str], list[str]]:
    """The guardrail for a plan that creates MANY objects of MANY types.

    ``check_headroom`` answers "is there room for one more Web Protection
    Profile?", which was the whole question while a WPP clone renamed the root
    and created nothing else. A deep same-device clone creates dozens of objects
    across ~15 types, and the failure it has to prevent is not a rejected POST —
    it is a clone that dies HALF-WRITTEN, because ``clone_and_rebind`` then
    refuses to re-bind and the operator is left with orphans to find by hand.

    Returns ``(allowed, messages, unchecked)``. ``unchecked`` lists the logical
    names with no capped type at all: a plan that silently skipped them would
    read as "capacity verified" when most of it was never looked at.
    """
    messages: list[str] = []
    unchecked: list[str] = []
    per_type: dict[str, int] = {}
    for logical, n in (wants or {}).items():
        otype = object_type_for_logical(logical)
        if otype is None:
            unchecked.append(logical)
            continue
        per_type[otype] = per_type.get(otype, 0) + int(n)

    allowed = True
    for otype in sorted(per_type):
        ok, msg = check_headroom(appliance, otype, want=per_type[otype])
        messages.append(msg)
        if not ok:
            allowed = False
    return allowed, messages, sorted(set(unchecked))


# ---------------------------------------------------------------------------
# Admin plumbing — ensure editable rows, seed
# ---------------------------------------------------------------------------

def ensure_rows_for(model: str, fw_major: str, product: str = PRODUCT_DEFAULT,
                    commit: bool = True) -> int:
    """Create empty (hard_max=NULL) rows for every object type of a
    (platform, firmware major) so the admin has a full editable set.
    Insert-only. ``model`` is normalised to the platform Fortinet publishes
    limits for (``FortiWeb-KVM 7.6.8`` -> ``FortiWeb-VM``)."""
    model = catalog_model(model, product) or model
    if not model or not fw_major:
        return 0
    added = 0
    for otype in OBJECT_TYPES:
        exists = CapacityLimit.query.filter_by(
            product=product, firmware_major=fw_major, model=model,
            object_type=otype).first()
        if exists is None:
            db.session.add(CapacityLimit(
                product=product, firmware_major=fw_major, model=model,
                object_type=otype, source="admin"))
            added += 1
    if commit and added:
        db.session.commit()
    return added


def _seed_path() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "registry", "data", "capacity_seed.json")


def seed_from_json() -> int:
    """Insert-only seed of published limits from capacity_seed.json (admin edits
    always win — an existing (product,fw,model,otype) row is never touched)."""
    path = _seed_path()
    if not os.path.exists(path):
        return 0
    try:
        rows = json.load(open(path, encoding="utf-8"))
    except (ValueError, OSError):
        return 0
    added = 0
    for r in rows:
        key = dict(product=r.get("product", PRODUCT_DEFAULT),
                   firmware_major=r["firmware_major"], model=r["model"],
                   object_type=r["object_type"])
        if CapacityLimit.query.filter_by(**key).first() is not None:
            continue
        db.session.add(CapacityLimit(
            **key, hard_max=r.get("hard_max"),
            operational_cap=r.get("operational_cap"),
            source=r.get("source", "seed")))
        added += 1
    if added:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            return 0
    return added
