"""DB-first fleet & per-device analytics for the Analysis dashboard.

Reads ONLY the local cache (device_objects + typed projections) and the
manager's own tables (appliances, wpp_exceptions, change_history, audit_logs,
segments via settings_store). It NEVER calls a live appliance, so the dashboard
is cheap and safe to refresh and stays consistent with the source-of-truth DB.

Every public function returns plain JSON-serialisable Python (dicts/lists), so
the view can ``jsonify`` it straight to the dynamic dashboard.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from ..models import (Appliance, AppSetting, AuditLog, ChangeHistory,
                      WppException, visible_appliances,
                      visible_appliance_or_404)
from ..models_cache import (DeviceObject, DeviceServerPool,
                            DeviceWebProtectionProfile)
from . import settings_store
from sqlalchemy import func

from ..extensions import db

APPID_REGEX_KEY = "analysis.appid_regex"
DEFAULT_APPID_REGEX = r"app\d{5}"

# server_policy payload keys are hyphenated (FortiWeb wire names).
_K_WPP = "web-protection-profile"
_K_MODE = "deployment-mode"
_K_HTTPS = "https-service"
_K_SVC = "service"


# --------------------------------------------------------------------------- #
# App ID extraction (configurable regex)                                      #
# --------------------------------------------------------------------------- #
def appid_regex_raw() -> str:
    return (AppSetting.get(APPID_REGEX_KEY) or DEFAULT_APPID_REGEX).strip() or DEFAULT_APPID_REGEX


def appid_pattern() -> re.Pattern:
    try:
        return re.compile(appid_regex_raw(), re.IGNORECASE)
    except re.error:
        return re.compile(DEFAULT_APPID_REGEX, re.IGNORECASE)


def set_appid_regex(raw: str) -> str:
    """Validate + persist the App ID regex. Returns the stored value.

    Raises ``re.error`` if the pattern does not compile.
    """
    raw = (raw or "").strip() or DEFAULT_APPID_REGEX
    re.compile(raw)  # validate (raises on bad pattern)
    AppSetting.set(APPID_REGEX_KEY, raw)
    return raw


def extract_appid(text, pat: re.Pattern | None = None):
    if not text:
        return None
    pat = pat or appid_pattern()
    m = pat.search(str(text))
    return m.group(0).lower() if m else None


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _truthy(v) -> bool:
    return str(v).strip().lower() in ("enable", "enabled", "on", "true", "1", "yes")


def _dist(items, top: int | None = None) -> list[dict]:
    """Counter over ``items`` -> [{label, count}] sorted by count desc."""
    c = Counter(x for x in items)
    rows = [{"label": str(k), "count": v} for k, v in c.most_common(top)]
    return rows


def _cidr_hosts(cidr: str) -> int:
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except (ValueError, AttributeError):
        return 0
    # usable hosts: subtract network+broadcast for IPv4 prefixes < /31
    n = net.num_addresses
    if net.version == 4 and net.prefixlen < 31 and n >= 2:
        return n - 2
    return n


# --------------------------------------------------------------------------- #
# Filter options + selection                                                   #
# --------------------------------------------------------------------------- #
def filter_options() -> dict:
    appls = visible_appliances().order_by(Appliance.name).all()
    return {
        "zones": sorted({a.zone for a in appls if a.zone}),
        "lines": sorted({a.line for a in appls if a.line}),
        "departments": sorted({a.department for a in appls if a.department}),
        "platforms": sorted({a.kind for a in appls if a.kind}),
        "devices": [
            {"id": a.id, "name": a.name, "kind": a.kind,
             "zone": a.zone or "", "line": a.line or "",
             "department": a.department or ""}
            for a in appls
        ],
        "appid_regex": appid_regex_raw(),
    }


def _selected_appliances(f: dict) -> list[Appliance]:
    q = visible_appliances()
    ids = f.get("device_ids") or []
    if ids:
        q = q.filter(Appliance.id.in_(ids))
    if f.get("platform"):
        q = q.filter(Appliance.kind == f["platform"])
    if f.get("zone"):
        q = q.filter(Appliance.zone == f["zone"])
    if f.get("line"):
        q = q.filter(Appliance.line == f["line"])
    if f.get("department"):
        q = q.filter(Appliance.department == f["department"])
    return q.order_by(Appliance.name).all()


def _parse_day(s):
    if not s:
        return None
    try:
        return datetime.strptime(s.strip()[:10], "%Y-%m-%d")
    except (ValueError, AttributeError):
        return None


# --------------------------------------------------------------------------- #
# Main aggregation                                                             #
# --------------------------------------------------------------------------- #
def analyze(f: dict | None = None) -> dict:
    f = f or {}
    appls = _selected_appliances(f)
    ids = [a.id for a in appls]
    name_by_id = {a.id: a.name for a in appls}
    pat = appid_pattern()

    out: dict = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "scope": {
            "devices": [{"id": a.id, "name": a.name, "kind": a.kind,
                         "zone": a.zone or "", "line": a.line or "",
                         "department": a.department or "",
                         "status": a.last_status or "unknown"} for a in appls],
            "device_count": len(appls),
        },
    }

    # ---- device breakdowns ------------------------------------------------ #
    out["devices"] = {
        "by_platform": _dist([a.kind or "(unset)" for a in appls]),
        "by_zone": _dist([a.zone or "(unset)" for a in appls]),
        "by_line": _dist([a.line or "(unset)" for a in appls]),
        "by_department": _dist([a.department or "(unset)" for a in appls]),
        "by_hw_type": _dist([a.hw_type or "unknown" for a in appls]),
        "by_status": _dist([a.last_status or "unknown" for a in appls]),
    }

    if not ids:
        # empty fleet/selection -> zeroed structures so the UI renders cleanly
        out.update(_empty_payload())
        out["segments"] = _segments_block(f)
        out["changes"] = _changes_block([], name_by_id, f)
        return out

    # ---- server policies (from device_objects payload = full fields) ------ #
    spol = (DeviceObject.query
            .filter(DeviceObject.appliance_id.in_(ids),
                    DeviceObject.logical_name == "server_policy")
            .all())
    pol_rows = []
    appid_map: dict[str, list] = defaultdict(list)
    no_appid: list = []
    wpp_usage: Counter = Counter()
    wpp_per_device: dict = defaultdict(Counter)   # device -> Counter(wpp)
    pols_per_device: Counter = Counter()
    for o in spol:
        p = o.payload or {}
        dev = name_by_id.get(o.appliance_id, str(o.appliance_id))
        wpp = (p.get(_K_WPP) or "").strip()
        comment = p.get("comment") or ""
        appid = extract_appid(comment, pat)
        row = {
            "device": dev, "device_id": o.appliance_id, "name": o.mkey,
            "deployment_mode": p.get(_K_MODE) or "",
            "status": p.get("status") or "",
            "tlog": _truthy(p.get("tlog")),
            "vserver": p.get("vserver") or "",
            "server_pool": p.get("server-pool") or "",
            "wpp": wpp,
            "service": p.get(_K_SVC) or "",
            "https_service": p.get(_K_HTTPS) or "",
            "appid": appid or "",
            "comment": comment,
        }
        pol_rows.append(row)
        pols_per_device[dev] += 1
        if wpp:
            wpp_usage[wpp] += 1
            wpp_per_device[dev][wpp] += 1
        if appid:
            appid_map[appid].append(row)
        else:
            no_appid.append(row)

    n_pol = len(pol_rows)
    out["policies"] = {
        "total": n_pol,
        "rows": pol_rows,
        "by_deployment_mode": _dist([r["deployment_mode"] or "(unset)" for r in pol_rows]),
        "by_status": _dist(["enabled" if _truthy(r["status"]) else "disabled" for r in pol_rows]),
        "tlog": [
            {"label": "tlog enabled", "count": sum(1 for r in pol_rows if r["tlog"])},
            {"label": "tlog disabled", "count": sum(1 for r in pol_rows if not r["tlog"])},
        ],
        "tls": [
            {"label": "HTTPS service", "count": sum(1 for r in pol_rows if r["https_service"])},
            {"label": "HTTP only", "count": sum(1 for r in pol_rows if not r["https_service"])},
        ],
        "per_device": _dist_from_counter(pols_per_device),
    }

    # ---- WPP inventory + usage ------------------------------------------- #
    wpps = (DeviceWebProtectionProfile.query
            .filter(DeviceWebProtectionProfile.appliance_id.in_(ids)).all())
    wpp_names = {w.name for w in wpps if w.name}
    used = set(wpp_usage.keys())
    unused = sorted(wpp_names - used)
    out["wpp"] = {
        "total": len(wpps),
        "by_kind": _dist([w.kind or "(unset)" for w in wpps]),
        "by_device": _dist([name_by_id.get(w.appliance_id, str(w.appliance_id)) for w in wpps]),
        "usage": [{"label": k, "count": v} for k, v in wpp_usage.most_common()],
        "unused": unused,
        "unused_count": len(unused),
        # which policies use which WPP, per device (the matrix the user asked for)
        "per_device_matrix": [
            {"device": dev, "wpp": w, "policies": c}
            for dev, ctr in wpp_per_device.items()
            for w, c in ctr.most_common()
        ],
    }

    # ---- backends / pools ------------------------------------------------- #
    pools = (DeviceServerPool.query
             .filter(DeviceServerPool.appliance_id.in_(ids)).all())
    out["pools"] = {
        "total": len(pools),
        "by_type": _dist([pp.type or "(unset)" for pp in pools]),
        "by_protocol": _dist([pp.protocol or "(unset)" for pp in pools]),
        "per_device": _dist([name_by_id.get(pp.appliance_id, str(pp.appliance_id)) for pp in pools]),
    }

    # ---- services --------------------------------------------------------- #
    svc_custom = _count_objs(ids, "services_custom")
    svc_pre = _count_objs(ids, "services_predefined")
    out["services"] = {
        "custom": svc_custom,
        "predefined": svc_pre,
        "total": svc_custom + svc_pre,
        "policy_service_ports": _dist([r["service"] for r in pol_rows if r["service"]]),
        "policy_https_ports": _dist([r["https_service"] for r in pol_rows if r["https_service"]]),
    }

    # ---- objects by section (whole cache for the selection) --------------- #
    sec_counter: Counter = Counter()
    for o in (DeviceObject.query
              .with_entities(DeviceObject.section)
              .filter(DeviceObject.appliance_id.in_(ids))):
        sec_counter[o.section or "(unset)"] += 1
    out["objects_by_section"] = _dist_from_counter(sec_counter)

    # ---- full object inventory (every section & type, per device) -------- #
    out["inventory"] = _inventory_block(ids, name_by_id)

    # ---- App IDs ---------------------------------------------------------- #
    appid_rows = sorted(
        ({"appid": k, "policies": len(v),
          "devices": sorted({r["device"] for r in v}),
          "policy_names": sorted(r["name"] for r in v)}
         for k, v in appid_map.items()),
        key=lambda r: (-r["policies"], r["appid"]))
    out["appids"] = {
        "total": len(appid_map),
        "regex": appid_regex_raw(),
        "rows": appid_rows,
        "with_appid": n_pol - len(no_appid),
        "without_appid": len(no_appid),
        "without_appid_rows": [{"device": r["device"], "name": r["name"],
                                "comment": r["comment"]} for r in no_appid],
        "coverage": [
            {"label": "with App ID", "count": n_pol - len(no_appid)},
            {"label": "without App ID", "count": len(no_appid)},
        ],
    }

    # ---- exceptions ------------------------------------------------------- #
    out["exceptions"] = _exceptions_block(ids, name_by_id)

    # ---- segments --------------------------------------------------------- #
    out["segments"] = _segments_block(f)

    # ---- change activity -------------------------------------------------- #
    out["changes"] = _changes_block(ids, name_by_id, f)

    # ---- summary cards ---------------------------------------------------- #
    out["summary"] = {
        "devices": len(appls),
        "server_policies": n_pol,
        "wpp": len(wpps),
        "pools": len(pools),
        "services": svc_custom + svc_pre,
        "exceptions": out["exceptions"]["total"],
        "exception_duplicates": out["exceptions"]["duplicate_count"],
        "segments": out["segments"]["total"],
        "segment_ips": out["segments"]["total_ips"],
        "appids": len(appid_map),
        "policies_without_appid": len(no_appid),
        "tlog_enabled": sum(1 for r in pol_rows if r["tlog"]),
        "objects": out["inventory"]["total_objects"],
        "object_types": out["inventory"]["type_count"],
    }
    return out


# --------------------------------------------------------------------------- #
# Sub-blocks                                                                   #
# --------------------------------------------------------------------------- #
def _count_objs(ids, logical_name) -> int:
    return (DeviceObject.query
            .filter(DeviceObject.appliance_id.in_(ids),
                    DeviceObject.logical_name == logical_name)
            .count())


def _dist_from_counter(ctr: Counter) -> list[dict]:
    return [{"label": str(k), "count": v} for k, v in ctr.most_common()]


def _exceptions_block(ids, name_by_id) -> dict:
    excs = WppException.query.filter(WppException.appliance_id.in_(ids)).all()
    by_cat, by_type, by_device = Counter(), Counter(), Counter()
    dup_key: dict = defaultdict(list)
    for e in excs:
        by_cat[e.category or "(unset)"] += 1
        by_type[e.exc_type or "(unset)"] += 1
        by_device[name_by_id.get(e.appliance_id, str(e.appliance_id))] += 1
        # duplicate = same device + WPP + type + payload
        key = (e.appliance_id, e.wpp_mkey, e.exc_type, (e.payload or "").strip())
        dup_key[key].append(e)
    duplicates = []
    for (aid, wpp, typ, _payload), group in dup_key.items():
        if len(group) > 1:
            duplicates.append({
                "device": name_by_id.get(aid, str(aid)),
                "wpp": wpp, "exc_type": typ, "count": len(group),
                "names": sorted(g.name or f"#{g.id}" for g in group),
            })
    duplicates.sort(key=lambda d: -d["count"])
    return {
        "total": len(excs),
        "by_category": _dist_from_counter(by_cat),
        "by_type": _dist_from_counter(by_type),
        "by_device": _dist_from_counter(by_device),
        "duplicates": duplicates,
        "duplicate_count": sum(d["count"] for d in duplicates),
    }


def _segments_block(f: dict) -> dict:
    segs = settings_store.segments() or []
    # scope filter: keep segments whose zone/line/dept match the active filter
    def keep(s):
        for key in ("zone", "line", "department"):
            want = f.get(key)
            if want and (s.get(key) or "") and s.get(key) != want:
                return False
        return True
    rows = []
    total_ips = 0
    for s in segs:
        if not keep(s):
            continue
        hosts = _cidr_hosts(s.get("cidr") or "")
        total_ips += hosts
        rows.append({
            "name": s.get("name") or "", "cidr": s.get("cidr") or "",
            "ips": hosts, "interface": s.get("interface") or "",
            "gateway": s.get("gateway") or "",
            "zone": s.get("zone") or "", "line": s.get("line") or "",
            "department": s.get("department") or "",
        })
    rows.sort(key=lambda r: -r["ips"])
    return {
        "total": len(rows),
        "total_ips": total_ips,
        "rows": rows,
        "ips_by_segment": [{"label": r["name"] or r["cidr"], "count": r["ips"]} for r in rows],
        "by_zone": _dist([r["zone"] or "(unset)" for r in rows]),
    }


def _changes_block(ids, name_by_id, f: dict) -> dict:
    d_from = _parse_day(f.get("date_from"))
    d_to = _parse_day(f.get("date_to"))
    if d_to:
        d_to = d_to + timedelta(days=1)   # inclusive end-of-day

    # ChangeHistory (config writes / previews)
    chq = ChangeHistory.query
    if ids:
        chq = chq.filter(ChangeHistory.appliance_id.in_(ids))
    if d_from:
        chq = chq.filter(ChangeHistory.ts >= d_from)
    if d_to:
        chq = chq.filter(ChangeHistory.ts < d_to)
    changes = chq.order_by(ChangeHistory.ts.desc()).all()

    by_day, by_device, by_action = Counter(), Counter(), Counter()
    live, dry = 0, 0
    recent = []
    last_by_device: dict = {}
    for c in changes:
        day = c.ts.strftime("%Y-%m-%d") if c.ts else "?"
        dev = name_by_id.get(c.appliance_id, str(c.appliance_id) if c.appliance_id else "(fleet)")
        by_day[day] += 1
        by_device[dev] += 1
        by_action[c.action or "(unknown)"] += 1
        if c.dry_run:
            dry += 1
        else:
            live += 1
        if dev not in last_by_device and c.ts:
            last_by_device[dev] = c.ts.isoformat()
        if len(recent) < 60:
            recent.append({
                "ts": c.ts.isoformat() if c.ts else "", "device": dev,
                "action": c.action or "", "endpoint": c.endpoint or "",
                "mkey": c.mkey or "", "dry_run": bool(c.dry_run),
                "user": c.username or "",
            })

    # AuditLog timeline (broader activity, no appliance scoping column)
    auq = AuditLog.query
    if d_from:
        auq = auq.filter(AuditLog.timestamp >= d_from)
    if d_to:
        auq = auq.filter(AuditLog.timestamp < d_to)
    audit_by_day, audit_by_action = Counter(), Counter()
    for a in auq.order_by(AuditLog.timestamp.desc()).limit(5000):
        audit_by_day[a.timestamp.strftime("%Y-%m-%d") if a.timestamp else "?"] += 1
        audit_by_action[a.action or "(unknown)"] += 1

    # ordered day series for the line chart (union of both sources)
    days = sorted(set(by_day) | set(audit_by_day))
    series = [{"day": d, "changes": by_day.get(d, 0),
               "audit": audit_by_day.get(d, 0)} for d in days if d != "?"]

    return {
        "total": len(changes),
        "live": live, "dry_run": dry,
        "by_action": _dist_from_counter(by_action),
        "by_device": _dist_from_counter(by_device),
        "timeline": series,
        "recent": recent,
        "last_by_device": [{"device": k, "ts": v} for k, v in
                           sorted(last_by_device.items(), key=lambda kv: kv[1], reverse=True)],
        "audit_total": int(sum(audit_by_action.values())),
        "audit_by_action": _dist_from_counter(audit_by_action)[:15],
    }



# --------------------------------------------------------------------------- #
# Full object inventory — every section, every object type, per device         #
# --------------------------------------------------------------------------- #
_ACRONYMS = {
    "http", "https", "ssl", "tls", "ip", "dns", "ntp", "dos", "ddos", "waf",
    "url", "csrf", "ha", "snmp", "saml", "dlp", "siem", "fds", "csf", "raid",
    "vip", "xff", "fips", "cc", "sso", "ca", "crl", "ocsp", "sni", "api",
    "wsdl", "xml", "json", "grpc", "cors", "mitb", "hsts", "wvs", "oauth",
    "icap", "hsm", "cpu", "mem", "av", "id",
}

# Curated labels where prettifying the registry name isn't enough.
_LABELS = {
    "server_policy": "Server Policy",
    "server_pool": "Server Pool",
    "vserver": "Virtual Server",
    "server_pool_health_check": "Health Check",
    "server_pool_persistence": "Persistence Policy",
    "policy_scripting": "Scripting",
    "services_custom": "Custom Service",
    "services_predefined": "Predefined Service",
    "ssl_cyphers": "SSL Ciphers",
    "allow_list": "Allow List",
    "http_content_routing": "HTTP Content Routing",
    "server_policy_setting": "Server Policy Setting",
    "server_policy_pattern_threat_weight": "Threat Weight",
    "x_forwarded_for": "X-Forwarded-For",
    "dos_policy": "DoS Protection Policy",
    "ip_intel": "IP Reputation",
    "geo_block": "Geo IP Block",
    "ip_list": "IP List",
    "ip_intelligence_ignore_xff": "IP Intelligence Ignore XFF",
    "webprotection_profile_inline": "WPP (Inline)",
    "webprotection_profile_offline": "WPP (Offline)",
    "http_protocol": "HTTP Protocol Constraints",
    "signature": "Signature",
    "bot_mitigation_policy_2": "Bot Mitigation",
    "bot_known_bots": "Known Bots",
    "custom_rule": "Custom Access Rule",
    "custom_policy": "Custom Access",
    "file_security_policy": "File Security",
    "file_security_rule": "File Security Rule",
    "http_header_security": "HTTP Header Security",
    "allow_method_policy": "Allow Method",
    "hidden_field_protection_policy": "Hidden Fields",
    "parameter_validation_policy": "Parameter Validation",
    "csrf_protection": "CSRF Protection",
    "url_access_policy": "URL Access",
    "padding_oracle": "Padding Oracle",
    "cookie_security": "Cookie Security",
    "syntax_based_detection": "Syntax-Based Detection",
    "web_shell_detection_policy": "Web Shell Detection",
    "waf_staged_signature_list": "Staged Signature List",
    "waf_signature_update_policy": "Signature Update Policy",
    "waf_dlp_dictionary": "DLP Dictionary",
    "ddos_http_flood_prevention": "DDoS HTTP Flood Prevention",
    "ddos_http_access_limit": "DDoS HTTP Access Limit",
    "ddos_tcp_flood_prevention": "DDoS TCP Flood Prevention",
    "ddos_malicious_ip": "DDoS Malicious IP",
    "site_publish_form_delegation": "Site Publish Form Delegation",
    "http_constraint_exception": "HTTP Constraint Exception",
    "interface_2": "Interface",
    "route": "Static Route",
    "router_setting": "Router Setting",
    "network_option": "Network Option",
    "log_siem_message_policy": "SIEM Message Policy",
    "log_syslog": "Syslog",
    "log_disk": "Log Disk",
    "traffic_log": "Traffic Log",
    "attack_log": "Attack Log",
    "event_log": "Event Log",
    "fortianalyzer": "FortiAnalyzer",
    "sensitive": "Sensitive Data",
    "user_oauth_user_request": "OAuth User Request",
    "user_oauth_user_server": "OAuth User Server",
    "wvs_template": "Vuln-Scan Template",
    "wvs_limit": "Vuln-Scan Limit",
    "accprofile": "Access Profile",
    "global": "Global",
    "advanced": "Advanced",
    "certificate": "Certificate",
}


def _humanize(name: str) -> str:
    if name in _LABELS:
        return _LABELS[name]
    parts = str(name).replace("-", "_").split("_")
    out = []
    for p in parts:
        if not p:
            continue
        out.append(p.upper() if p.lower() in _ACRONYMS else p[:1].upper() + p[1:])
    return " ".join(out) or str(name)


def _inventory_block(ids, name_by_id) -> dict:
    """Every top-level object type, grouped by GUI section, counted per device.

    One grouped query over the whole cache -> a section -> type -> per-device
    matrix, so EVERY server object (not just the curated few) is analysable and
    filterable in the dashboard.
    """
    dev_names = [name_by_id.get(i, str(i)) for i in ids]
    rows = (db.session.query(
                DeviceObject.section, DeviceObject.logical_name,
                DeviceObject.appliance_id, func.count(DeviceObject.id))
            .filter(DeviceObject.appliance_id.in_(ids),
                    DeviceObject.depth == 0)
            .group_by(DeviceObject.section, DeviceObject.logical_name,
                      DeviceObject.appliance_id)
            .all())

    sec_types: dict = defaultdict(lambda: defaultdict(dict))   # sec -> log -> {aid:n}
    sec_total: Counter = Counter()
    type_total: Counter = Counter()
    total_objects = 0
    for section, logical, aid, cnt in rows:
        section = section or "(unset)"
        sec_types[section][logical][aid] = cnt
        sec_total[section] += cnt
        type_total[_humanize(logical)] += cnt
        total_objects += cnt

    sections = []
    type_count = 0
    for section in sorted(sec_total, key=lambda s: -sec_total[s]):
        types = []
        for logical, per in sorted(sec_types[section].items(),
                                   key=lambda kv: -sum(kv[1].values())):
            types.append({
                "logical_name": logical,
                "label": _humanize(logical),
                "total": sum(per.values()),
                "per_device": [per.get(i, 0) for i in ids],
            })
        type_count += len(types)
        sections.append({
            "section": section,
            "total": sec_total[section],
            "type_count": len(types),
            "types": types,
        })

    return {
        "total_objects": total_objects,
        "type_count": type_count,
        "device_names": dev_names,
        "by_section": _dist_from_counter(sec_total),
        "top_types": [{"label": k, "count": v}
                      for k, v in type_total.most_common(15)],
        "sections": sections,
    }


def _empty_payload() -> dict:
    z = lambda: {"total": 0}
    return {
        "policies": {"total": 0, "rows": [], "by_deployment_mode": [],
                     "by_status": [], "tlog": [], "tls": [], "per_device": []},
        "wpp": {"total": 0, "by_kind": [], "by_device": [], "usage": [],
                "unused": [], "unused_count": 0, "per_device_matrix": []},
        "pools": {"total": 0, "by_type": [], "by_protocol": [], "per_device": []},
        "services": {"custom": 0, "predefined": 0, "total": 0,
                     "policy_service_ports": [], "policy_https_ports": []},
        "objects_by_section": [],
        "inventory": {"total_objects": 0, "type_count": 0,
                      "device_names": [], "by_section": [],
                      "top_types": [], "sections": []},
        "appids": {"total": 0, "regex": appid_regex_raw(), "rows": [],
                   "with_appid": 0, "without_appid": 0,
                   "without_appid_rows": [], "coverage": []},
        "exceptions": {"total": 0, "by_category": [], "by_type": [],
                       "by_device": [], "duplicates": [], "duplicate_count": 0},
        "summary": {"devices": 0, "server_policies": 0, "wpp": 0, "pools": 0,
                    "services": 0, "exceptions": 0, "exception_duplicates": 0,
                    "segments": 0, "segment_ips": 0, "appids": 0,
                    "policies_without_appid": 0, "tlog_enabled": 0,
                    "objects": 0, "object_types": 0},
    }


def deep_freshness(device_ids=None) -> dict:
    """Per-device deep-layer capture timestamp (the honest freshness badge —
    None means no deep capture yet). At fleet scale you refresh subsets, so a
    single page-level 'data from DATE' would lie; this is per device."""
    from ..models_cache import DeviceSnapshot
    q = (db.session.query(DeviceSnapshot.appliance_id,
                          func.max(DeviceSnapshot.generated_at))
         .filter(DeviceSnapshot.layer == "deep")
         .group_by(DeviceSnapshot.appliance_id))
    if device_ids:
        q = q.filter(DeviceSnapshot.appliance_id.in_(list(device_ids)))
    return {str(aid): {"captured_at": ts.isoformat() if ts else None}
            for aid, ts in q.all()}
