"""Delivery analytics for the FortiADC ADOM — DB-first.

``services.analysis`` answers WAF questions, and it answers them by reading
``server_policy`` objects plus the ``DeviceServerPool`` /
``DeviceWebProtectionProfile`` projections. All three are FortiWeb shapes. A
FortiADC harvest contains none of them: it has ``load_balance_virtual_server``,
``load_balance_pool``, ``load_balance_real_server`` and a security model built
from profiles attached to a virtual server. Pointed at a FortiADC ADOM that
page therefore rendered a complete WAF dashboard with every panel at zero —
the same failure this repo has now corrected for FortiAnalyzer and
FortiAuthenticator: a page that *cannot* say anything still looks like a page
saying nothing is wrong.

An ADC is a traffic device, so unlike the authenticator the questions do
resemble FortiWeb's — but the nouns are different and so are the risks:

* **Delivery.** A virtual server is the unit of published service. Which ones
  are enabled, what they front, and whether the pool they name still exists.
* **Backend health.** A pool with no health check keeps sending traffic to a
  dead real server. That is the ADC's signature outage and it is a *config*
  fact, visible with the box powered off.
* **Security attachment.** The ADC ships WAF, IPS, AV and DoS profiles that do
  nothing until a virtual server references them. "Profiles exist" and
  "profiles are applied" are different statements and only the second one
  protects anything.
* **TLS posture.** Which client-SSL profiles still permit TLS 1.0/1.1, and
  which local certificates have expired.

Four rules carry the correctness here.

**Never touch an appliance.** Same contract as the other analysis modules: the
config cache and the manager's own tables, nothing else. The page opens with
the unit powered off — which is exactly the state the only FortiADC row in
this fleet is in.

**"Not harvested" is not "zero".** A section the sweep never collected and a
section that collected nothing render identically as ``0`` and demand opposite
actions. Every block reports ``harvested`` for its source and refuses to emit
findings from a section that was never collected: a dangling-pool warning
derived from an unharvested pool section is a fabricated outage.

**Field names come from a live payload, never from the docs.** FortiADC mixes
separators inside a single object — ``waf-profile`` and ``av-profile`` are
hyphenated while ``ips_profile``, ``dos_profile``, ``auth_policy`` and
``ztna_profile`` are not — and a guessed key reads as "nothing attached",
which is the most dangerous wrong answer this page could give. It also pads
values with trailing spaces (``"status": "up "``, ``"port": "80 "``), so every
read is stripped.

**Factory objects are labelled, not counted as work.** ``_noneditable: 1``
marks a shipped object. Three WAF profiles that are all factory defaults is a
different sentence from three profiles somebody tuned, and rolling them
together lets an untouched box look configured.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from ..extensions import db
from ..models import Appliance, visible_appliances
from ..models_cache import DeviceObject

PRODUCT = "fortiadc"

# --- logical names, all verified against a live FortiADC 8.0.3 harvest ------ #
_VS = "load_balance_virtual_server"
_POOL = "load_balance_pool"
_MEMBER = "load_balance_pool/pool_member"
_RS = "load_balance_real_server"
_HC = "system_health_check"
_WAF = "security_waf_profile"
_IPS = "security_ips_profile"
_CSSL = "load_balance_client_ssl_profile"
_CERT = "system_certificate_local"

#: Security profile slots on a virtual server: ``payload key -> label``.
#: The separator is inconsistent in the vendor payload (see module docstring);
#: these keys are transcribed from a real object, not from the CLI reference.
_VS_SECURITY_SLOTS = (
    ("waf-profile", "WAF"),
    ("ips_profile", "IPS"),
    ("av-profile", "Antivirus"),
    ("dos_profile", "DoS"),
    ("auth_policy", "Authentication"),
    ("ztna_profile", "ZTNA"),
)

#: Keys on a WAF profile that are settings or metadata rather than a reference
#: to a protection module. Everything else on the object is treated as a module
#: slot, so a firmware that adds a module is measured without a code change —
#: the same reason the inventory is derived from the registry.
_WAF_NON_MODULE = frozenset({
    "mkey", "desc", "_noneditable", "_nondeletable",
    "use_original_ip", "rule_match_record", "exception_name",
})

#: TLS versions that should not be reachable on a published service.
_LEGACY_TLS = ("sslv3", "tlsv1.0", "tlsv1.1")

#: Registry endpoints that describe *scale*. A singleton like ``system_dns``
#: is always exactly one object and "1" tells the operator nothing. The list is
#: policed by a test: any endpoint holding more than one object on a device in
#: scope must appear here, so the next firmware's new collection cannot go
#: missing silently.
_COUNTABLE_PREFIX = (
    "load_balance_", "link_load_balance_", "global_load_balance_",
    "global_dns_server_", "security_", "router_", "firewall_",
    "system_accprofile", "system_address", "system_admin", "system_alert",
    "system_certificate", "system_health_check", "system_isp_",
    "system_scripting", "system_service", "system_stream_scripting",
    "log_report", "log_setting",
)

#: A cert whose remaining life is under this is called out.
_CERT_WARN_DAYS = 30


# --------------------------------------------------------------------------- #
#  Helpers                                                                     #
# --------------------------------------------------------------------------- #
def _scoped_appliances(device_ids: list[int] | None = None) -> list:
    rows = visible_appliances().filter(Appliance.kind == PRODUCT).all()
    if device_ids:
        want = set(device_ids)
        rows = [a for a in rows if a.id in want]
    return rows


def _s(payload: dict, key: str, default: str = "") -> str:
    """Stripped string read. FortiADC pads values with trailing spaces, so a
    raw comparison against ``"up"`` or ``"80"`` silently fails."""
    val = (payload or {}).get(key, default)
    if val is None:
        return default
    return str(val).strip()


def _on(payload: dict, key: str) -> bool:
    return _s(payload, key).lower() in ("enable", "enabled", "on", "true", "1")


def _factory(payload: dict) -> bool:
    return str((payload or {}).get("_noneditable") or "0") not in ("0", "", "False")


def _objects(ids: list[int], logical: str) -> list:
    """Config-layer objects for a logical name, de-duplicated by ``mkey``.

    The harvest writes one snapshot per menu section rather than one per sweep,
    so duplicates are not expected today — but a re-sweep that lands mid-page
    would double every count, and a count that doubles is a count nobody can
    act on. Newest row wins.
    """
    if not ids:
        return []
    rows = (DeviceObject.query
            .filter(DeviceObject.appliance_id.in_(ids),
                    DeviceObject.logical_name == logical,
                    DeviceObject.layer == "config")
            .order_by(DeviceObject.id.asc())
            .all())
    seen: dict[tuple, Any] = {}
    for o in rows:
        seen[(o.appliance_id, o.mkey, o.parent_id)] = o
    return list(seen.values())


def _harvested(ids: list[int], logical: str) -> bool:
    if not ids:
        return False
    return db.session.query(
        DeviceObject.query
        .filter(DeviceObject.appliance_id.in_(ids),
                DeviceObject.logical_name == logical,
                DeviceObject.layer == "config")
        .exists()).scalar()


def _dist(items) -> list[dict]:
    return [{"label": k, "count": v} for k, v in Counter(items).most_common()]


def _label(name: str) -> str:
    """``load_balance_virtual_server`` -> ``Load balance virtual server``.

    Plain humanisation, deliberately. Stripping the leading domain word reads
    better for some endpoints and destroys others (``log_report_queryset`` ->
    "Queryset" loses the subject entirely), and the raw endpoint key is
    rendered beside the label anyway.
    """
    text = " ".join(p for p in name.replace("/", " ").replace("-", " ")
                    .split("_") if p) or name
    return text[:1].upper() + text[1:]


def _parse_validto(raw: str):
    """``"2056-01-18 19:14:07 PST"`` -> ``datetime`` (naive, appliance-local).

    The trailing token is a timezone ABBREVIATION, which ``%Z`` cannot parse
    reliably for arbitrary zones, so it is dropped and the result is treated as
    day-precision. Good enough to answer "expired?" and "expiring?"; deliberately
    not used for anything finer.
    """
    text = (raw or "").strip()
    if not text:
        return None
    try:
        return datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- #
#  Delivery — virtual servers                                                  #
# --------------------------------------------------------------------------- #
def delivery(appliances: list) -> dict:
    ids = [a.id for a in appliances]
    name_by_id = {a.id: a.name for a in appliances}
    vs_harvested = _harvested(ids, _VS)
    pool_harvested = _harvested(ids, _POOL)

    pool_names = defaultdict(set)
    for o in _objects(ids, _POOL):
        pool_names[o.appliance_id].add((o.mkey or "").strip())

    rows, findings = [], []
    for o in _objects(ids, _VS):
        p = o.payload or {}
        dev = name_by_id.get(o.appliance_id, str(o.appliance_id))
        pool = _s(p, "pool")
        enabled = _on(p, "status")
        attached = [lbl for key, lbl in _VS_SECURITY_SLOTS if _s(p, key)]
        row = {
            "device": dev, "device_id": o.appliance_id,
            "name": (o.mkey or "").strip(),
            "status": "enabled" if enabled else "disabled",
            "type": _s(p, "type") or "(unset)",
            "address": _s(p, "address"),
            "port": _s(p, "port"),
            "interface": _s(p, "interface"),
            "pool": pool,
            "method": _s(p, "method"),
            "profile": _s(p, "profile"),
            "persistence": _s(p, "persistence"),
            "availability": _s(p, "availability") or "unknown",
            "traffic_log": _on(p, "traffic-log"),
            "security": attached,
            "security_count": len(attached),
            "connection_limit": _s(p, "connection-limit"),
        }
        rows.append(row)

        if not pool:
            findings.append((dev, "warn", "Virtual server has no pool",
                             "%s publishes %s:%s and names no back-end pool."
                             % (row["name"], row["address"] or "?",
                                row["port"] or "?")))
        elif pool_harvested and pool not in pool_names[o.appliance_id]:
            findings.append((dev, "warn", "Virtual server names a missing pool",
                             "%s points at pool '%s', which is not in the "
                             "harvested configuration." % (row["name"], pool)))
        if enabled and not attached:
            findings.append((dev, "warn", "Published service has no security profile",
                             "%s is enabled with no WAF, IPS, antivirus or DoS "
                             "profile attached." % row["name"]))
        if enabled and not row["traffic_log"]:
            findings.append((dev, "info", "Traffic logging is off",
                             "%s serves traffic that is not being logged."
                             % row["name"]))

    enabled_rows = [r for r in rows if r["status"] == "enabled"]
    return {
        "harvested": vs_harvested,
        "total": len(rows),
        "enabled": len(enabled_rows),
        "disabled": len(rows) - len(enabled_rows),
        "rows": sorted(rows, key=lambda r: (r["device"], r["name"])),
        "by_type": _dist([r["type"] for r in rows]),
        "by_status": _dist([r["status"] for r in rows]),
        "by_availability": _dist([r["availability"] for r in rows]),
        "per_device": _dist([r["device"] for r in rows]),
        "findings": findings,
    }


# --------------------------------------------------------------------------- #
#  Backends — pools, members, real servers                                     #
# --------------------------------------------------------------------------- #
def backends(appliances: list) -> dict:
    ids = [a.id for a in appliances]
    name_by_id = {a.id: a.name for a in appliances}
    pool_harvested = _harvested(ids, _POOL)
    rs_harvested = _harvested(ids, _RS)

    members_by_pool = defaultdict(list)
    referenced_rs = defaultdict(set)
    for m in _objects(ids, _MEMBER):
        members_by_pool[m.parent_id].append(m)
        rs = _s(m.payload or {}, "real_server_id")
        if rs:
            referenced_rs[m.appliance_id].add(rs)

    hc_names = defaultdict(set)
    for h in _objects(ids, _HC):
        hc_names[h.appliance_id].add((h.mkey or "").strip())

    rows, findings = [], []
    member_total = down_members = 0
    for o in _objects(ids, _POOL):
        p = o.payload or {}
        dev = name_by_id.get(o.appliance_id, str(o.appliance_id))
        mems = members_by_pool.get(o.id, [])
        member_total += len(mems)
        up = [m for m in mems if _on(m.payload or {}, "status")]
        down_members += len(mems) - len(up)
        # The ADC carries BOTH a flag and a list. Either one on its own is a
        # configured check; requiring both would under-report, requiring only
        # the flag would miss a list-driven setup.
        hc_list = [n for n in _s(p, "health_check_list").split() if n]
        has_hc = _on(p, "health_check") or bool(hc_list)
        rows.append({
            "device": dev, "device_id": o.appliance_id,
            "name": (o.mkey or "").strip(),
            "type": _s(p, "type") or "(unset)",
            "pool_type": _s(p, "pool_type"),
            "service_port": _s(p, "service_port"),
            "availability": _s(p, "availability") or "unknown",
            "health_check": has_hc,
            "health_check_list": hc_list,
            "health_check_action": _s(p, "health_check_action"),
            "members": len(mems),
            "members_up": len(up),
            "member_rows": [{
                "id": (m.mkey or "").strip(),
                "address": _s(m.payload or {}, "address"),
                "port": _s(m.payload or {}, "port"),
                "weight": _s(m.payload or {}, "weight"),
                "backup": _on(m.payload or {}, "backup"),
                "status": "enabled" if _on(m.payload or {}, "status") else "disabled",
                "real_server": _s(m.payload or {}, "real_server_id"),
            } for m in sorted(mems, key=lambda x: (x.mkey or ""))],
        })
        if not has_hc:
            findings.append((dev, "warn", "Pool has no health check",
                             "'%s' keeps forwarding to its %d member(s) whether "
                             "or not they answer." % (rows[-1]["name"], len(mems))))
        elif hc_list and hc_names.get(o.appliance_id) is not None:
            missing = [n for n in hc_list if n not in hc_names[o.appliance_id]]
            if missing and _harvested(ids, _HC):
                findings.append((dev, "warn", "Pool names a missing health check",
                                 "'%s' references %s, which is not in the "
                                 "harvested configuration."
                                 % (rows[-1]["name"], ", ".join(missing))))
        if not mems:
            findings.append((dev, "warn", "Pool has no members",
                             "'%s' has no real server behind it."
                             % rows[-1]["name"]))
        elif not up:
            findings.append((dev, "warn", "Every pool member is disabled",
                             "'%s' has %d member(s), all administratively "
                             "disabled." % (rows[-1]["name"], len(mems))))

    rs_rows = []
    for o in _objects(ids, _RS):
        p = o.payload or {}
        dev = name_by_id.get(o.appliance_id, str(o.appliance_id))
        name = (o.mkey or "").strip()
        used = name in referenced_rs.get(o.appliance_id, set())
        rs_rows.append({
            "device": dev, "name": name,
            "address": _s(p, "address") or _s(p, "FQDN"),
            "type": _s(p, "type"),
            "status": "enabled" if _on(p, "status") else "disabled",
            "referenced": used,
        })
        # Only assertable when the member section was harvested: with no
        # members in cache EVERY real server looks unreferenced.
        if not used and _harvested(ids, _MEMBER):
            findings.append((dev, "info", "Real server is not in any pool",
                             "'%s' (%s) is defined but no pool member points "
                             "at it." % (name, rs_rows[-1]["address"] or "?")))

    return {
        "harvested": pool_harvested,
        "rs_harvested": rs_harvested,
        "pools": len(rows),
        "members": member_total,
        "members_down": down_members,
        "real_servers": len(rs_rows),
        "unreferenced_real_servers": sum(1 for r in rs_rows if not r["referenced"]),
        "pools_without_health_check": sum(1 for r in rows if not r["health_check"]),
        "rows": sorted(rows, key=lambda r: (r["device"], r["name"])),
        "real_server_rows": sorted(rs_rows, key=lambda r: (r["device"], r["name"])),
        "health_checks": sum(len(v) for v in hc_names.values()),
        "findings": findings,
    }


# --------------------------------------------------------------------------- #
#  Security — profiles defined vs profiles attached                            #
# --------------------------------------------------------------------------- #
def security(appliances: list) -> dict:
    ids = [a.id for a in appliances]
    name_by_id = {a.id: a.name for a in appliances}
    vs_objs = _objects(ids, _VS)
    vs_harvested = _harvested(ids, _VS)

    coverage = []
    for key, lbl in _VS_SECURITY_SLOTS:
        attached = sum(1 for o in vs_objs if _s(o.payload or {}, key))
        coverage.append({"slot": lbl, "field": key, "attached": attached,
                         "bare": len(vs_objs) - attached})

    waf_rows, findings = [], []
    for o in _objects(ids, _WAF):
        p = o.payload or {}
        dev = name_by_id.get(o.appliance_id, str(o.appliance_id))
        slots = {k: v for k, v in p.items() if k not in _WAF_NON_MODULE
                 and isinstance(v, str)}
        filled = sorted(k for k, v in slots.items() if v.strip())
        waf_rows.append({
            "device": dev, "name": (o.mkey or "").strip(),
            "factory": _factory(p),
            "modules_total": len(slots),
            "modules_filled": len(filled),
            "filled": [_label(k) for k in filled],
        })

    ips_rows = []
    for o in _objects(ids, _IPS):
        p = o.payload or {}
        # TRAP: the IPS profile object carries an EMPTY mkey; the name lives in
        # ``ips_profile_name``. Reading o.mkey renders a table of blank rows.
        ips_rows.append({
            "device": name_by_id.get(o.appliance_id, str(o.appliance_id)),
            "name": _s(p, "ips_profile_name") or (o.mkey or "").strip() or "(unnamed)",
            "comments": _s(p, "comments"),
            "factory": _factory(p),
        })

    # Gated on the WAF section, not the virtual-server one, and reported PER
    # DEVICE: rolling several appliances into one finding attributed to
    # whichever happened to sort first is a sentence about nobody.
    if _harvested(ids, _WAF):
        per_device = defaultdict(list)
        for r in waf_rows:
            per_device[r["device"]].append(r)
        for dev, rows_ in sorted(per_device.items()):
            if rows_ and not any(not r["factory"] for r in rows_):
                findings.append((dev, "info",
                                 "Every WAF profile is a factory default",
                                 "%d profile(s) present, none tuned for this "
                                 "deployment." % len(rows_)))

    return {
        "harvested": vs_harvested,
        "virtual_servers": len(vs_objs),
        "coverage": coverage,
        "fully_bare": sum(1 for o in vs_objs
                          if not any(_s(o.payload or {}, k)
                                     for k, _l in _VS_SECURITY_SLOTS)),
        "waf_profiles": waf_rows,
        "waf_total": len(waf_rows),
        "waf_tuned": sum(1 for r in waf_rows if not r["factory"]),
        "ips_profiles": ips_rows,
        "ips_total": len(ips_rows),
        "findings": findings,
    }


# --------------------------------------------------------------------------- #
#  TLS — client-SSL profiles and local certificates                            #
# --------------------------------------------------------------------------- #
def tls(appliances: list) -> dict:
    ids = [a.id for a in appliances]
    name_by_id = {a.id: a.name for a in appliances}
    now = datetime.utcnow()

    prof_rows, findings = [], []
    for o in _objects(ids, _CSSL):
        p = o.payload or {}
        dev = name_by_id.get(o.appliance_id, str(o.appliance_id))
        versions = [v for v in _s(p, "ssl-allowed_versions").lower().split() if v]
        legacy = [v for v in versions if v in _LEGACY_TLS]
        prof_rows.append({
            "device": dev, "name": (o.mkey or "").strip(),
            "factory": _factory(p),
            "versions": versions,
            "legacy": legacy,
            "renegotiation": _s(p, "ssl_secure_renegotiation"),
            "forward_proxy": _on(p, "forward_proxy"),
        })
        if legacy:
            findings.append((dev, "warn", "Client-SSL profile allows legacy TLS",
                             "'%s' permits %s." % (prof_rows[-1]["name"],
                                                   ", ".join(legacy))))

    cert_rows = []
    for o in _objects(ids, _CERT):
        p = o.payload or {}
        dev = name_by_id.get(o.appliance_id, str(o.appliance_id))
        valid_to = _parse_validto(_s(p, "validto"))
        days = (valid_to - now).days if valid_to else None
        cert_rows.append({
            "device": dev, "name": (o.mkey or "").strip(),
            "subject": _s(p, "subject"), "issuer": _s(p, "issuer"),
            "type": _s(p, "type"), "status": _s(p, "status"),
            "valid_to": _s(p, "validto"),
            "days_left": days,
            "factory": _factory(p),
        })
        if days is None:
            continue
        if days < 0:
            findings.append((dev, "crit", "Local certificate has expired",
                             "'%s' expired %d day(s) ago (%s)."
                             % (cert_rows[-1]["name"], -days,
                                cert_rows[-1]["valid_to"])))
        elif days <= _CERT_WARN_DAYS:
            findings.append((dev, "warn", "Local certificate expires soon",
                             "'%s' has %d day(s) left (%s)."
                             % (cert_rows[-1]["name"], days,
                                cert_rows[-1]["valid_to"])))

    return {
        "harvested": _harvested(ids, _CSSL) or _harvested(ids, _CERT),
        "profiles": sorted(prof_rows, key=lambda r: (r["device"], r["name"])),
        "profile_total": len(prof_rows),
        "profiles_with_legacy": sum(1 for r in prof_rows if r["legacy"]),
        "certificates": sorted(cert_rows, key=lambda r: (
            r["days_left"] if r["days_left"] is not None else 10 ** 6)),
        "cert_total": len(cert_rows),
        "cert_expired": sum(1 for r in cert_rows
                            if r["days_left"] is not None and r["days_left"] < 0),
        "cert_expiring": sum(1 for r in cert_rows
                             if r["days_left"] is not None
                             and 0 <= r["days_left"] <= _CERT_WARN_DAYS),
        "findings": findings,
    }


# --------------------------------------------------------------------------- #
#  Inventory                                                                   #
# --------------------------------------------------------------------------- #
def _cached(ids: list[int]) -> dict:
    if not ids:
        return {}
    rows = (db.session.query(DeviceObject.appliance_id,
                             DeviceObject.logical_name,
                             db.func.count(DeviceObject.id))
            .filter(DeviceObject.appliance_id.in_(ids),
                    DeviceObject.layer == "config")
            .group_by(DeviceObject.appliance_id, DeviceObject.logical_name)
            .all())
    return {(a, n): c for a, n, c in rows}


def _sections(ids: list[int]) -> dict:
    """``logical_name -> section``, taken from the harvest itself.

    The sweep stores the section it read the object from, so this needs no
    second copy of the menu and cannot drift from it.
    """
    if not ids:
        return {}
    rows = (db.session.query(DeviceObject.logical_name, DeviceObject.section)
            .filter(DeviceObject.appliance_id.in_(ids),
                    DeviceObject.layer == "config")
            .distinct().all())
    return {n: (s or "Other") for n, s in rows}


def inventory(appliances: list) -> dict:
    """Delivery objects the cache holds, per endpoint, per device.

    Rows are DERIVED FROM THE REGISTRY, never from a list written here: a
    hand-written list is a copy, and the first endpoint a firmware adds would
    go missing with nothing failing to say so.
    """
    from ..registry import loader

    try:
        reg = loader.load_adc_registry() or {}
    except Exception:  # noqa: BLE001 — an unreadable registry is not a crash
        reg = {}
    ids = [a.id for a in appliances]
    counts = _cached(ids)
    sect = _sections(ids)
    seen_ep = {n for (_a, n) in counts}

    names = sorted(set(reg) | seen_ep)
    rows = []
    for name in names:
        if not name.startswith(_COUNTABLE_PREFIX):
            continue
        per = [{"device": a.name, "device_id": a.id,
                "count": int(counts.get((a.id, name), 0)),
                "harvested": (a.id, name) in counts}
               for a in appliances]
        rows.append({"endpoint": name, "label": _label(name),
                     "section": sect.get(name, "Other"),
                     "in_registry": name in reg,
                     "total": sum(p["count"] for p in per),
                     "devices": per})
    # "Other" is where never-harvested registry endpoints land; sink it so the
    # sections that actually hold objects are not buried behind ~100 zero rows.
    rows.sort(key=lambda r: (1 if r["section"] == "Other" else 0,
                             r["section"], -r["total"], r["endpoint"]))
    return {"rows": rows, "endpoints_known": len(reg),
            "endpoints_present": len(seen_ep),
            "sections": sorted({r["section"] for r in rows})}


# --------------------------------------------------------------------------- #
#  Freshness                                                                   #
# --------------------------------------------------------------------------- #
def freshness(appliances: list) -> dict:
    from . import device_health

    rows = []
    for a in appliances:
        try:
            meta = device_health.cache_meta(a) or {}
        except Exception:  # noqa: BLE001
            meta = {}
        gen = meta.get("generated_at")
        rows.append({
            "device": a.name, "device_id": a.id, "host": a.host,
            "maintenance": bool(getattr(a, "maintenance", False)),
            "cached": bool(meta.get("cached")),
            # ISO string, not the raw datetime: /analysis/data serialises this
            # and jsonify would emit an HTTP date while the template printed a
            # Python repr — two renderings of the same instant.
            "generated_at": (gen.isoformat() if hasattr(gen, "isoformat")
                             else (str(gen) if gen else "")),
            "age_hours": meta.get("age_hours"),
            "layer": meta.get("layer") or "",
        })
    return {"rows": rows}


# --------------------------------------------------------------------------- #
#  Composite                                                                   #
# --------------------------------------------------------------------------- #
_SEVERITY_ORDER = {"crit": 0, "warn": 1, "info": 2, "ok": 3}


def _collect(*blocks) -> list[dict]:
    out = []
    for block in blocks:
        for dev, sev, title, detail in block.get("findings", []):
            out.append({"device": dev, "severity": sev, "title": title,
                        "detail": detail})
    out.sort(key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9),
                            f["device"], f["title"]))
    return out


def analyze(filters: dict | None = None) -> dict:
    filters = filters or {}
    appliances = _scoped_appliances(filters.get("device_ids") or None)
    d = delivery(appliances)
    b = backends(appliances)
    s = security(appliances)
    t = tls(appliances)
    return {
        "product": PRODUCT,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "devices": [{"id": a.id, "name": a.name, "host": a.host,
                     "status": a.last_status or "unknown"}
                    for a in appliances],
        "delivery": d,
        "backends": b,
        "security": s,
        "tls": t,
        "findings": _collect(d, b, s, t),
        "inventory": inventory(appliances),
        "freshness": freshness(appliances),
        "summary": {
            "devices": len(appliances),
            "virtual_servers": d["total"],
            "virtual_servers_enabled": d["enabled"],
            "pools": b["pools"],
            "pool_members": b["members"],
            "real_servers": b["real_servers"],
            "pools_without_health_check": b["pools_without_health_check"],
            "bare_virtual_servers": s["fully_bare"],
            "waf_profiles": s["waf_total"],
            "ips_profiles": s["ips_total"],
            "certificates": t["cert_total"],
            "certificates_expired": t["cert_expired"],
            "legacy_tls_profiles": t["profiles_with_legacy"],
        },
    }


def filter_options() -> dict:
    return {"devices": [{"id": a.id, "name": a.name}
                        for a in _scoped_appliances()]}
