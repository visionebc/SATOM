"""DNS & LB Lookup — the manager's port of the team's ``dns.php`` field tool.

Two halves, both ADOM-aware:

* **DNS lookups** — ``dig`` against a CONFIGURABLE server list stored in
  ``AppSetting`` key ``dnstool.servers`` (global key by convention; edited in
  Settings → admin console). The list is variable — servers are added and
  removed there, never hardcoded.
* **LB matching** — instead of the PHP tool's flat ``data.txt`` export, rows
  come from the manager's own data: FortiWeb server policies from the DEVICE
  CACHE (deep/config layers via ``read_layer``, zero box calls), FortiADC
  virtual servers from a live read-only sweep. ``fleet_lb_rows`` walks
  ``visible_appliances()``, so the active ADOM automatically cuts the output
  to its own product (Global sees both).
"""
from __future__ import annotations

import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor

RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "PTR"}

SERVERS_KEY = "dnstool.servers"
DEFAULT_SERVERS = [
    {"name": "AdGuard", "server": "192.0.2.3", "enabled": True},
    {"name": "OPNsense", "server": "192.0.2.2", "enabled": True},
]

MAX_ENTRIES = 50
DIG_TIMEOUT = 6  # subprocess hard kill; dig itself gets +time/+tries below

# Characters allowed in a lookup entry (hostname / IP / wildcard / "name TYPE").
_ENTRY_CLEAN_RE = re.compile(r"[^A-Za-z0-9 .:*_\-/]")
_IP_RE = re.compile(r"^[0-9a-fA-F.:]+$")

# App ID convention: the policy/VS *comment* carries "AppID: <token>" (also
# accepted: app-id=..., app_id ..., or a bracketed [APP-123] tag) — the same
# per-service application identifier column the dns.php sheet tracked.
_APP_ID_RE = re.compile(
    r"app[\s_-]?id\s*[:=#]?\s*([A-Za-z0-9][A-Za-z0-9._-]*)", re.IGNORECASE)
_APP_ID_BRACKET_RE = re.compile(r"\[((?:APP|ID)-[A-Za-z0-9._-]+)\]", re.IGNORECASE)

# Result-table column catalog (key, label) — every LB row carries all keys.
COLUMNS = [
    ("product", "Product"),
    ("gateway", "Gateway"),
    ("adom", "ADOM"),
    ("policy", "Server Policy / Virtual Server"),
    ("service_ip", "Service IP"),
    ("http", "HTTP Service"),
    ("https", "HTTPS Service"),
    ("pool", "Pool"),
    ("members", "Members"),
    ("cert_cn", "Cert CN"),
    ("certificate", "Certificate"),
    ("ssl_verify", "SSL Client Verify"),
    ("type", "Type"),
    ("routing", "Content Routing"),
    ("sni", "SNI"),
    ("waf", "WAF Policy"),
    ("app_id", "App ID"),
    ("comment", "Comment"),
    ("status", "Status"),
    ("zone", "Zone"),
    ("line", "Line"),
    ("department", "Department"),
]


# ---------------------------------------------------------------- servers

def dns_servers() -> list[dict]:
    """The configured DNS server list (Settings → admin console)."""
    from ..models import AppSetting
    raw = AppSetting.get(SERVERS_KEY)
    if not raw:
        return [dict(s) for s in DEFAULT_SERVERS]
    try:
        rows = json.loads(raw)
    except (ValueError, TypeError):
        return [dict(s) for s in DEFAULT_SERVERS]
    out = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        name = str(r.get("name") or "").strip()
        server = str(r.get("server") or "").strip()
        if name and server:
            out.append({"name": name[:64], "server": server[:128],
                        "enabled": bool(r.get("enabled", True))})
    return out


def save_dns_servers(rows) -> list[dict]:
    """Validate + persist the server list; returns what was stored."""
    from ..extensions import db
    from ..models import AppSetting
    clean: list[dict] = []
    for r in rows or []:
        name = str(r.get("name") or "").strip()[:64]
        server = str(r.get("server") or "").strip()[:128]
        if not name or not server:
            continue
        if re.search(r"[^A-Za-z0-9.:\-]", server):  # IP or plain hostname only
            raise ValueError(f"Invalid DNS server address: {server!r}")
        clean.append({"name": name, "server": server,
                      "enabled": bool(r.get("enabled", True))})
    AppSetting.set(SERVERS_KEY, json.dumps(clean))
    db.session.commit()
    return clean


# ---------------------------------------------------------------- parsing

def clean_entry(raw: str) -> str:
    """Sanitize one input line (defense in depth — dig runs argv-style)."""
    return _ENTRY_CLEAN_RE.sub("", (raw or "").strip())[:200]


def parse_entry(entry: str) -> tuple[str, str | None]:
    """``'host TYPE'`` → (host, TYPE); bare host → (host, None)."""
    parts = (entry or "").split()
    if len(parts) >= 2 and parts[-1].upper() in RECORD_TYPES:
        return " ".join(parts[:-1]).strip(), parts[-1].upper()
    return (entry or "").strip(), None


def resolve_wildcard(query: str) -> str:
    """``*.x.y.z`` → ``x.x.y.z`` (probe a wildcard with its first label)."""
    q = (query or "").strip()
    if q.startswith("*."):
        rest = q[2:]
        first = rest.split(".", 1)[0]
        return f"{first}.{rest}"
    return q


def _is_ip(value: str) -> bool:
    if not _IP_RE.match(value or ""):
        return False
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------- dig

def dig_lookup(entry: str, server: str, *, show_ttl: bool = False) -> list[str]:
    """One ``dig`` against one server; returns answer values (or a marker)."""
    query, rtype = parse_entry(entry)
    target = resolve_wildcard(query)
    if not target:
        return ["No result"]
    if _is_ip(target):
        cmd = ["dig", f"@{server}", "-x", target,
               "+noall", "+answer", "+time=2", "+tries=1"]
    else:
        cmd = ["dig", f"@{server}", target, rtype or "A",
               "+noall", "+answer", "+time=2", "+tries=1"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=DIG_TIMEOUT)
        out = proc.stdout or ""
    except (subprocess.TimeoutExpired, OSError):
        return ["timeout"]
    results = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(None, 4)
        if len(parts) >= 5 and parts[1].isdigit() and parts[2].upper() == "IN":
            results.append(f"{parts[4]} (TTL:{parts[1]})" if show_ttl else parts[4])
    return results or ["No result"]


def lookup_many(entries: list[str], servers: list[dict], *,
                show_ttl: bool = False) -> dict[tuple[str, str], list[str]]:
    """All (entry, server) lookups in parallel → {(entry, server_name): [..]}."""
    jobs = [(e, s) for e in entries for s in servers]
    if not jobs:
        return {}
    results: dict[tuple[str, str], list[str]] = {}
    with ThreadPoolExecutor(max_workers=min(8, len(jobs))) as pool:
        futs = {pool.submit(dig_lookup, e, s["server"], show_ttl=show_ttl):
                (e, s["name"]) for e, s in jobs}
        for fut, key in futs.items():
            try:
                results[key] = fut.result()
            except Exception:  # noqa: BLE001 — one dead server never sinks the page
                results[key] = ["error"]
    return results


# ---------------------------------------------------------------- LB rows

def _app_id(comment: str) -> str:
    m = _APP_ID_RE.search(comment or "")
    if m:
        return m.group(1)
    m = _APP_ID_BRACKET_RE.search(comment or "")
    return m.group(1) if m else ""


def _svc_label(name: str, port) -> str:
    if not name:
        return ""
    return f"{name}:{port}" if port else name


def _base_row(appliance, product: str) -> dict:
    return {key: "" for key, _ in COLUMNS} | {
        "product": product,
        "gateway": appliance.name,
        "adom": "fortiadc" if product == "FortiADC" else "fortiweb",
        "zone": appliance.zone or "",
        "line": appliance.line or "",
        "department": appliance.department or "",
    }


def _fortiweb_rows(appliance) -> list[dict]:
    """One row per cached server policy (deep layer preferred) — no box call."""
    from ..extensions import db
    from ..models import DeviceCertificate
    from ..models_cache import DeviceObject
    from . import read_layer
    from ..views.architecture import _custom_service_ports, _policy_names, _service_port

    names = _policy_names(appliance.id, "deep") or _policy_names(appliance.id, "config")
    if not names:
        return []
    svc_ports = _custom_service_ports(appliance.id)
    certs = {c.name: c for c in DeviceCertificate.query.filter_by(
        appliance_id=appliance.id).all()}
    # SNI members: domain -> local-cert rows cached under certificate_sni
    sni_domains: dict[str, list[str]] = {}
    for r in (db.session.query(DeviceObject)
              .filter_by(appliance_id=appliance.id,
                         logical_name="certificate_sni", depth=0).all()):
        kids = (db.session.query(DeviceObject)
                .filter_by(appliance_id=appliance.id, parent_id=r.id).all())
        doms = [str((k.payload or {}).get("domain") or "") for k in kids]
        sni_domains[r.mkey] = [d for d in doms if d]

    rows = []
    for name in names:
        try:
            data, cr_entries, _meta = read_layer.policy_full_cached(appliance.id, name)
        except Exception:  # noqa: BLE001
            data = None
            cr_entries = []
        if not data:
            continue
        pol = data.get("policy") or {}
        pool = data.get("pool") or {}
        vips = [v.get("effective_ip") or "" for v in (data.get("vips") or [])]
        backends = [{"ip": str(b.get("ip") or ""),
                     "port": str(b.get("port") or ""),
                     "status": str(b.get("status") or "")}
                    for b in (data.get("backends") or [])]
        members = [f"{b['ip']}:{b['port']}" for b in backends]
        cert_name = pol.get("certificate") or ""
        cert = certs.get(cert_name)
        cn_bits = []
        if cert:
            if cert.cn:
                cn_bits.append(cert.cn)
            cn_bits += [s for s in cert.sans if s and s != cert.cn]
        sni_cert = pol.get("sni-certificate") or ""
        sni_label = sni_cert
        if sni_cert and sni_domains.get(sni_cert):
            sni_label = f"{sni_cert} ({', '.join(sni_domains[sni_cert])})"
        routing = [str(e.get("content-routing-policy-name") or "")
                   for e in (cr_entries or [])]
        row = _base_row(appliance, "FortiWeb")
        row.update({
            "policy": name,
            "service_ip": ", ".join(v for v in vips if v),
            "http": _svc_label(pol.get("service") or "",
                               _service_port(pol.get("service"), svc_ports)),
            "https": _svc_label(pol.get("https-service") or "",
                                _service_port(pol.get("https-service"), svc_ports)),
            "pool": pool.get("name") or pol.get("server-pool") or "",
            "members": ", ".join(m for m in members if m != ":"),
            "cert_cn": ", ".join(cn_bits),
            "certificate": cert_name,
            "ssl_verify": pol.get("ssl-client-verify") or "",
            "type": pol.get("deployment-mode") or "",
            "routing": ", ".join(r for r in routing if r),
            "sni": sni_label if pol.get("sni") == "enable" or sni_cert else "",
            "waf": (pol.get("web-protection-profile")
                    or (data.get("wpp") or {}).get("name") or ""),
            "comment": pol.get("comment") or "",
            "app_id": _app_id(pol.get("comment") or ""),
            "status": pol.get("status") or "",
        })
        # Private keys (not columns, skipped by match/clipboard): deep-link +
        # the policy→backends mini-graph the page renders per match.
        row["_aid"] = appliance.id
        row["_kind"] = "fortiweb"
        row["_backends"] = backends
        rows.append(row)
    return rows


def _fortiadc_rows(appliance) -> list[dict]:
    """One row per virtual server — live read-only sweep (no ADC deep cache)."""
    from flask import current_app
    from ..clients import client_for

    client = client_for(appliance)
    vs_rows, err = client.list_with_error("load_balance_virtual_server")
    if err:
        current_app.logger.info("dns_tool: %s virtual-server read failed: %s",
                                appliance.name, err)
        return []
    pool_members: dict[str, list[dict]] = {}
    try:
        for vs in vs_rows or []:
            pname = str(vs.get("pool") or "").strip()
            if not pname or pname in pool_members:
                continue
            rows, perr = client.list_with_error(
                "load_balance_pool_child_pool_member", pkey=pname)
            if perr:
                pool_members[pname] = []
                continue
            pool_members[pname] = [
                {"ip": str(m.get("pool_member_service_ip") or m.get("ip")
                           or m.get("address") or ""),
                 "port": str(m.get("pool_member_service_port")
                             or m.get("port") or ""),
                 "status": str(m.get("pool_member_status")
                               or m.get("status") or "")}
                for m in rows or []]
    except Exception:  # noqa: BLE001 — member detail is best-effort
        pass

    out = []
    for vs in vs_rows or []:
        comment = str(vs.get("comments") or vs.get("comment") or "")
        backends = pool_members.get(str(vs.get("pool") or ""), [])
        row = _base_row(appliance, "FortiADC")
        row.update({
            "policy": str(vs.get("mkey") or vs.get("name") or ""),
            "service_ip": str(vs.get("address") or vs.get("ip") or ""),
            "http": str(vs.get("port") or ""),
            "pool": str(vs.get("pool") or ""),
            "members": ", ".join(
                f"{b['ip']}:{b['port']}" for b in backends
                if b["ip"] or b["port"]),
            "certificate": str(vs.get("ssl-certificate") or ""),
            "type": str(vs.get("type") or ""),
            "waf": str(vs.get("waf-profile") or ""),
            "comment": comment,
            "app_id": _app_id(comment),
            "status": str(vs.get("status") or ""),
        })
        row["_aid"] = appliance.id
        row["_kind"] = "fortiadc"
        row["_backends"] = backends
        out.append(row)
    return out


def fleet_lb_rows() -> list[dict]:
    """LB rows across every appliance the active ADOM may see."""
    from flask import current_app
    from ..models import Appliance, visible_appliances

    rows: list[dict] = []
    for a in visible_appliances().order_by(Appliance.name).all():
        try:
            if getattr(a, "kind", "") == "fortiadc":
                rows.extend(_fortiadc_rows(a))
            else:
                rows.extend(_fortiweb_rows(a))
        except Exception as exc:  # noqa: BLE001 — one device never sinks the sweep
            current_app.logger.info("dns_tool: %s row build failed: %s", a.name, exc)
    return rows


def match_rows(rows: list[dict], query: str, resolved: str, *,
               exact: bool = False) -> list[dict]:
    """PHP-parity matching: any column, substring by default, exact optional."""
    hits = []
    q, r = (query or "").lower(), (resolved or "").lower()
    for row in rows:
        for key, value in row.items():
            if key.startswith("_"):  # private (link/graph) keys never match
                continue
            v = str(value).lower()
            if exact:
                tokens = [t.strip() for t in v.split(",")]
                if q in (v, *tokens) or r in (v, *tokens):
                    hits.append(row)
                    break
            elif (q and q in v) or (r and r in v):
                hits.append(row)
                break
    return hits
