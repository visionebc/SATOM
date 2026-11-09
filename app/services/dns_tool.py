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
# Empty by design. The docstring above promises the list is never hardcoded,
# and it has to stay true on someone else's network: a shipped resolver is
# either unreachable there (the tool looks broken) or reachable and wrong (the
# tool silently answers from a foreign cache). The Settings page seeds the
# list on first use; until then the panel says so.
DEFAULT_SERVERS: list[dict] = []

MAX_ENTRIES = 50
DIG_TIMEOUT = 6  # subprocess hard kill; dig itself gets +time/+tries below

# Characters allowed in a lookup entry (hostname / IP / wildcard / "name TYPE").
_ENTRY_CLEAN_RE = re.compile(r"[^A-Za-z0-9 .:*_\-/]")
_IP_RE = re.compile(r"^[0-9a-fA-F.:]+$")
# What may reach dig's argv as a query name or a server. dig reads ANY argument
# starting with '-' as an option (``-f FILE`` makes it read a local file as a
# query batch), so the first character is never '-' — nor '+', dig's other
# option prefix.
_DIG_NAME_RE = re.compile(r"^[A-Za-z0-9_*][A-Za-z0-9_.*\-]{0,252}$")
_DIG_SERVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,127}$")

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
    # PTR of the service IP against the configured resolvers (SA-0027): a
    # lookup by policy name finds the policy, and this says which published
    # name it serves. Filled for MATCHED rows only (add_service_names). Named
    # "Name" since SA-0028: an FQDN lookup puts the forward name there too.
    ("service_name", "Name"),
    ("http", "HTTP Service"),
    ("https", "HTTPS Service"),
    ("pool", "Pool"),
    ("members", "Members"),
    ("backends", "Backends (status)"),
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

def valid_dig_name(value: str) -> bool:
    """A hostname or IP address that dig cannot read as an option."""
    return _is_ip(value) or bool(_DIG_NAME_RE.match(value or ""))


def valid_dig_server(value: str) -> bool:
    """A server (IP or hostname) that is safe to pass as ``@server``."""
    return _is_ip(value) or bool(_DIG_SERVER_RE.match(value or ""))


def dig_lookup(entry: str, server: str, *, show_ttl: bool = False) -> list[str]:
    """One ``dig`` against one server; returns answer values (or a marker)."""
    query, rtype = parse_entry(entry)
    target = resolve_wildcard(query)
    if not target:
        return ["No result"]
    # The last gate before argv: every caller (the lookup page, process steps)
    # lands here, and an entry like ``-f/opt/satom/.env`` would otherwise be an
    # option, not a name.
    if not valid_dig_name(target):
        return ["invalid name"]
    if not valid_dig_server(server):
        return ["invalid server"]
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


def member_addr(b: dict) -> str:
    """``ip:port`` of one pool member; a domain member (FortiWeb server-type
    domain, FortiADC FQDN real server) by its name."""
    host = b.get("ip") or b.get("domain") or ""
    return "%s%s" % (host, ":%s" % b["port"] if b.get("port") else "") if host else ""


def backends_text(backends: list[dict]) -> str:
    """``ip:port (status)`` per backend: the CONFIGURED status the cache holds
    (enable / disable / maintain), so Copy LB carries what the page draws.
    The weight, when the cache has one, follows the status."""
    out = []
    for b in backends or []:
        addr = member_addr(b)
        if addr:
            st = b.get("status") or "unknown"
            if b.get("weight") not in (None, ""):
                st = "%s, weight %s" % (st, b["weight"])
            out.append("%s (%s)" % (addr, st))
    return "; ".join(out)


# ---------------------------------------------------------------- IP fields
# SA-0028: an IP lookup searches the server policy's ADDRESSES, not its text:
# the VIP, the pool members and any other field of the policy, its virtual
# server and its pool that holds an address. Each row carries them as
# ``_ips`` = [(field label, address)], built from the same cached payloads the
# row is drawn from, so the search never reads anything the table does not.

_IP_TOKEN_SPLIT = re.compile(r"[\s,;]+")
_NOT_AN_ADDRESS = {"0.0.0.0", "::", "255.255.255.255"}


def norm_ip(value) -> str:
    """The canonical form of one address (``192.0.2.5/32`` -> ``192.0.2.5``,
    IPv6 compressed), or "" when *value* is not one."""
    import ipaddress
    s = str(value or "").strip().split("/", 1)[0].strip()
    if not s or not _IP_RE.match(s):
        return ""
    try:
        ip = ipaddress.ip_address(s).compressed
    except ValueError:
        return ""
    return "" if ip in _NOT_AN_ADDRESS else ip


def ips_in_payload(payload, source: str, *, skip=()) -> list[tuple[str, str]]:
    """``[(f"{source} {key}", ip)]`` for every address in a cached payload's
    scalar values (lists and space-separated values too). ``skip`` names the
    keys the caller already reports under a better label (the VIP)."""
    out: list[tuple[str, str]] = []
    if not isinstance(payload, dict):
        return out
    for key, value in payload.items():
        if key in skip or str(key).startswith("_"):
            continue
        vals = value if isinstance(value, (list, tuple)) else [value]
        for v in vals:
            if isinstance(v, (dict, list, tuple)) or v is None:
                continue
            for tok in _IP_TOKEN_SPLIT.split(str(v)):
                ip = norm_ip(tok)
                if ip and (f"{source} {key}", ip) not in out:
                    out.append((f"{source} {key}", ip))
    return out


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


def _vip_note(data: dict, pol: dict) -> str:
    """Why a FortiWeb policy has no Service IP, said on the row instead of a
    bare dash (SA-0029). "" when it has one."""
    vips = data.get("vips")
    if any((v or {}).get("effective_ip") for v in vips or []):
        return ""
    if not pol.get("vserver"):
        return "the server policy has no virtual server"
    if vips is None:
        return ("only the config layer is cached; a deep capture resolves the virtual "
                "server's VIPs")
    if not vips:
        return "virtual server %s has no VIP" % pol.get("vserver")
    why = []
    for v in vips:
        src = str((v or {}).get("ip_source") or "")
        if src.startswith("interface"):
            why.append("%s: no address cached for that interface" % src)
        elif src:
            why.append(src)
    return "; ".join(why) or "the VIP has no address in SATOM's copy"


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
                     "status": str(b.get("status") or ""),
                     # SA-0028: the weight and a domain member's name, both in
                     # the cached pserver-list row (FortiWeb 7.6.8).
                     "weight": str(b.get("weight") if b.get("weight") is not None else ""),
                     "domain": str(b.get("domain") or "") if not b.get("ip") else ""}
                    for b in (data.get("backends") or [])]
        members = [member_addr(b) for b in backends]
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
            "backends": backends_text(backends),
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
        # The config layer alone has no pserver-list: say why the members are
        # missing instead of drawing an empty pool (SA-0028).
        row["_backends_note"] = ("" if "backends" in data or not row["pool"]
                                 else "only the config layer is cached; a deep "
                                      "capture lists the pool members")
        row["_vip_note"] = _vip_note(data, pol)
        ips = [("VIP", norm_ip(v)) for v in vips if norm_ip(v)]
        ips += [("Pool member", norm_ip(b["ip"])) for b in backends if norm_ip(b["ip"])]
        ips += ips_in_payload(pol, "Server policy")
        ips += ips_in_payload(data.get("vserver"), "Virtual server")
        ips += ips_in_payload(pool, "Server pool")
        row["_ips"] = ips
        rows.append(row)
    return rows


def _adc_profile_certs(client) -> dict[str, list[str]]:
    """``client-SSL profile -> [certificate]`` for one FortiADC.

    Best-effort and read-only: a leg that fails contributes nothing, because a
    blank Certificate cell is the status quo and a WRONG one would be new.
    """
    out: dict[str, list[str]] = {}
    try:
        groups, gerr = client.list_with_error(
            "system_certificate_local_cert_group")
        if gerr:
            return out
        members: dict[str, list[str]] = {}
        for g in groups or []:
            gname = str((g or {}).get("mkey") or "").strip()
            if not gname:
                continue
            rows, merr = client.list_with_error(
                "system_certificate_local_cert_group_child_group_member",
                pkey=gname)
            if merr:
                continue
            members[gname] = [
                str(m.get("local_cert") or "").strip() for m in rows or []
                if isinstance(m, dict) and m.get("local_cert")]
        profiles, perr = client.list_with_error(
            "load_balance_client_ssl_profile")
        if perr:
            return out
        for p in profiles or []:
            if not isinstance(p, dict):
                continue
            pname = str(p.get("mkey") or "").strip()
            grp = str(p.get("local_certificate_group") or "").strip()
            if pname and grp:
                out[pname] = members.get(grp, [])
    except Exception:  # noqa: BLE001 — the sweep never dies on a cert column
        return out
    return out


def _adc_s(payload, *keys) -> str:
    """First non-empty stripped value (FortiADC pads values: ``"443 "``)."""
    for k in keys:
        v = str((payload or {}).get(k) or "").strip()
        if v:
            return v
    return ""


def _adc_member(m: dict, real_servers: dict) -> dict:
    """One pool member as ``{ip, port, status, weight, domain}``.

    A FortiADC 8 pool member carries ``address: 0.0.0.0`` and names its
    ``real_server_id``; the address lives on the real server (cached
    ``load_balance_real_server``, fadc 8.0.3). Reading the member alone drew
    every backend as ``0.0.0.0`` or blank (SA-0028)."""
    rs = real_servers.get(_adc_s(m, "real_server_id")) or {}
    ip = norm_ip(_adc_s(m, "pool_member_service_ip", "ip", "address")) \
        or norm_ip(_adc_s(rs, "address")) or norm_ip(_adc_s(rs, "address6"))
    return {"ip": ip,
            "port": _adc_s(m, "pool_member_service_port", "port"),
            "status": _adc_s(m, "pool_member_status", "status"),
            "weight": _adc_s(m, "weight"),
            "domain": "" if ip else (_adc_s(rs, "FQDN") or _adc_s(m, "real_server_id"))}


def _adc_row(appliance, vs: dict, backends: list[dict], certificate: str) -> dict:
    comment = _adc_s(vs, "comments", "comment")
    row = _base_row(appliance, "FortiADC")
    row.update({
        "policy": _adc_s(vs, "mkey", "name"),
        "service_ip": _adc_s(vs, "address", "ip"),
        "http": _adc_s(vs, "port"),
        "pool": _adc_s(vs, "pool"),
        "members": ", ".join(a for a in (member_addr(b) for b in backends) if a),
        "backends": backends_text(backends),
        "certificate": certificate,
        "type": _adc_s(vs, "type"),
        "waf": _adc_s(vs, "waf-profile"),
        "comment": comment,
        "app_id": _app_id(comment),
        "status": _adc_s(vs, "status"),
    })
    row["_aid"] = appliance.id
    row["_kind"] = "fortiadc"
    row["_backends"] = backends
    row["_backends_note"] = ""
    # An IPv6 virtual server carries its VIP in address6 (address stays
    # 0.0.0.0); an empty Service IP says why (SA-0029).
    if not norm_ip(row["service_ip"]) and norm_ip(_adc_s(vs, "address6")):
        row["service_ip"] = _adc_s(vs, "address6")
    row["_vip_note"] = "" if norm_ip(row["service_ip"]) else \
        "the virtual server has no address in SATOM's copy"
    ips = [("VIP", norm_ip(row["service_ip"]))] if norm_ip(row["service_ip"]) else []
    ips += [("Pool member", norm_ip(b["ip"])) for b in backends if norm_ip(b["ip"])]
    ips += ips_in_payload(vs, "Virtual server", skip=("address", "ip"))
    row["_ips"] = ips
    return row


def _fortiadc_cached_rows(appliance) -> list[dict] | None:
    """One row per virtual server from SATOM's COPY (config layer), or None
    when nothing of this ADC's virtual servers is cached (the caller then
    sweeps live, as before SA-0028). Zero device calls."""
    from ..models_cache import DeviceObject

    def objs(logical):
        return (DeviceObject.query
                .filter(DeviceObject.appliance_id == appliance.id,
                        DeviceObject.logical_name == logical,
                        DeviceObject.layer == "config")
                .order_by(DeviceObject.id.asc()).all())
    vs_objs = objs("load_balance_virtual_server")
    if not vs_objs:
        return None
    real_servers = {(o.mkey or "").strip(): (o.payload or {})
                    for o in objs("load_balance_real_server")}
    pool_ids = {(o.mkey or "").strip(): o.id for o in objs("load_balance_pool")}
    members: dict[int, list[dict]] = {}
    for o in objs("load_balance_pool/pool_member"):
        members.setdefault(o.parent_id, []).append(o)
    profiles = {(o.mkey or "").strip(): (o.payload or {})
                for o in objs("load_balance_client_ssl_profile")}
    out, seen = [], set()
    for o in reversed(vs_objs):            # newest row of a name wins
        vs = o.payload or {}
        name = _adc_s(vs, "mkey") or (o.mkey or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        pool_rows = sorted(members.get(pool_ids.get(_adc_s(vs, "pool")), []),
                           key=lambda r: (r.idx, r.mkey or ""))
        backends = [_adc_member(r.payload or {}, real_servers) for r in pool_rows]
        # The certificate group's members are not in the copy: name the
        # client-SSL profile and its group rather than leave the cell blank.
        prof = _adc_s(vs, "client_ssl_profile")
        grp = _adc_s(profiles.get(prof), "local_certificate_group")
        cert = ("%s (group %s)" % (prof, grp) if grp else prof) if prof else ""
        out.append(_adc_row(appliance, dict(vs, mkey=name), backends, cert))
    out.sort(key=lambda r: r["policy"])
    return out


def _fortiadc_rows(appliance) -> list[dict]:
    """One row per virtual server: SATOM's copy first (SA-0028); a live
    read-only sweep only when the copy holds no virtual server."""
    cached = _fortiadc_cached_rows(appliance)
    if cached is not None:
        return cached
    return _fortiadc_live_rows(appliance)


def _fortiadc_live_rows(appliance) -> list[dict]:
    """One row per virtual server — live read-only sweep (no ADC cache)."""
    from flask import current_app
    from ..clients import client_for

    client = client_for(appliance)
    vs_rows, err = client.list_with_error("load_balance_virtual_server")
    if err:
        current_app.logger.info("dns_tool: %s virtual-server read failed: %s",
                                appliance.name, err)
        return []
    pool_members: dict[str, list[dict]] = {}
    real_servers: dict[str, dict] = {}
    try:
        rs_rows, rs_err = client.list_with_error("load_balance_real_server")
        if not rs_err:
            real_servers = {_adc_s(r, "mkey"): r for r in rs_rows or []
                            if isinstance(r, dict)}
    except Exception:  # noqa: BLE001 — addresses are best-effort
        real_servers = {}
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
            pool_members[pname] = [_adc_member(m, real_servers)
                                   for m in rows or [] if isinstance(m, dict)]
    except Exception:  # noqa: BLE001 — member detail is best-effort
        pass

    # A FortiADC virtual server has NO ``ssl-certificate`` field: the chain is
    # virtual server -> client-SSL profile -> local-cert group -> certificate
    # (the shape `cert_adc._bindings` walks; confirmed on a captured fadc
    # config, where every VS carries `client_ssl_profile` and no cert field).
    # Reading the missing field left this column permanently blank, so the
    # Certificate / Cert CN cells lied by omission on every ADC row.
    profile_certs = _adc_profile_certs(client)

    out = []
    for vs in vs_rows or []:
        if not isinstance(vs, dict):
            continue
        backends = pool_members.get(str(vs.get("pool") or "").strip(), [])
        out.append(_adc_row(appliance, vs, backends, ", ".join(profile_certs.get(
            str(vs.get("client_ssl_profile") or "").strip(), []))))
    return out


def fleet_lb_rows() -> list[dict]:
    """LB rows across every appliance the active ADOM may see."""
    from flask import current_app
    from ..models import Appliance, visible_appliances

    rows: list[dict] = []
    appliances = visible_appliances().order_by(Appliance.name).all()
    for a in appliances:
        try:
            if getattr(a, "kind", "") == "fortiadc":
                rows.extend(_fortiadc_rows(a))
            else:
                rows.extend(_fortiweb_rows(a))
        except Exception as exc:  # noqa: BLE001 — one device never sinks the sweep
            current_app.logger.info("dns_tool: %s row build failed: %s", a.name, exc)
    try:
        attach_appids(rows)
    except Exception as exc:  # noqa: BLE001 — the LB half renders without AppIDs
        current_app.logger.info("dns_tool: AppID lookup failed: %s", exc)
    try:
        groups = cluster_map(appliances)
        for r in rows:
            if r.get("_aid") in groups:
                r["_group"] = groups[r["_aid"]]
    except Exception as exc:  # noqa: BLE001 — rows stay one per device
        current_app.logger.info("dns_tool: cluster grouping failed: %s", exc)
    return rows


# ---------------------------------------------------------------- clusters
# SA-0028: "if an entry is in a cluster it should say so and not appear twice
# -- that would cause problems when deleting or editing it". The same server
# policy cached on two members of one HA cluster / config-sync group is ONE
# service; the page shows it once, on the member an edit must target.
#
# Membership comes from what SATOM already knows, in this order of strength:
#   1. the cluster SATOM has REGISTERED (``Appliance.is_cluster`` node 0 and
#      its ``is_cluster_member`` rows, ``parent_id``; ``ha_mode``,
#      ``ha_role_hint``) -- the model every write already goes through
#      (``services.ha.resolve_write_target``);
#   2. the HA block in SATOM's copy (``system_ha``): devices of one product
#      whose cached HA mode is not standalone and that share a group name;
#   3. FortiWeb config sync in SATOM's copy (``system_conf_sync.ip`` naming
#      another registered FortiWeb's address).
# Which member is the PRIMARY is never asked of a device here (a page load is
# DB-first). A vip-mode node 0 is the write target by construction; otherwise
# the member SATOM records as primary (``ha_role_hint``, set by an operator);
# otherwise the role is unknown and the page says so, picking by name then id.

GROUP_SOURCE = {"registered": "registered in SATOM",
                "ha": "HA group in SATOM's copy (system_ha)",
                "config_sync": "config sync in SATOM's copy (system_conf_sync)"}


def _cached_payloads(ids: list[int], logical: str) -> dict[int, dict]:
    """``{appliance_id: payload}`` of one top-level cached object (newest)."""
    from ..models_cache import DeviceObject
    if not ids:
        return {}
    out: dict[int, dict] = {}
    for o in (DeviceObject.query
              .filter(DeviceObject.appliance_id.in_(ids),
                      DeviceObject.logical_name == logical,
                      DeviceObject.depth == 0)
              .order_by(DeviceObject.id.asc()).all()):
        if isinstance(o.payload, dict):
            out[o.appliance_id] = o.payload
    return out


def cluster_map(appliances) -> dict[int, dict]:
    """``{appliance_id: group}`` for every appliance that shares a cluster
    with another one in *appliances* (module comment above). One dict per
    group, shared by its members::

        {"key", "name", "source", "members": [names], "count": int,
         "rank": {aid: tuple}, "role": {aid: str}}

    ``rank`` orders the members for the representative (lowest first);
    ``role`` says why ("primary", "vip", "cluster", "unknown")."""
    appliances = [a for a in appliances or [] if getattr(a, "id", None) is not None]
    by_id = {a.id: a for a in appliances}
    parent: dict[int, int] = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    sources: dict[int, set] = {}
    names: dict[int, str] = {}

    def mark(aid, src, name=""):
        sources.setdefault(aid, set()).add(src)
        if name:
            names.setdefault(aid, name)

    for a in appliances:
        if getattr(a, "is_cluster_member", False) and getattr(a, "parent_id", None):
            union(a.id, a.parent_id)
            node0 = by_id.get(a.parent_id) or getattr(a, "parent", None)
            mark(a.id, "registered", getattr(node0, "name", "") or "")
            mark(a.parent_id, "registered", getattr(node0, "name", "") or "")
        if getattr(a, "is_cluster", False):
            mark(a.id, "registered", a.name)
    ids = list(by_id)
    kind = {a.id: (getattr(a, "kind", "") or "fortiweb").lower() for a in appliances}
    # A string mode is trustworthy on FortiWeb / FortiADC only (ha_inventory's
    # evidence rule); a group name is required, because every unnamed pair
    # shares group-id 0 and would merge unrelated clusters.
    ha_groups: dict[tuple, list[tuple[int, str]]] = {}
    for aid, p in _cached_payloads(ids, "system_ha").items():
        raw = p.get("mode")
        grp = str(p.get("group-name") or p.get("group_name") or "").strip()
        if not isinstance(raw, str) or raw.strip().lower() in ("", "standalone", "disable", "off"):
            continue
        if grp:
            ha_groups.setdefault((kind[aid], grp.lower(), str(p.get("group-id") or "")),
                                 []).append((aid, grp))
    for pairs in ha_groups.values():
        if len(pairs) > 1:
            for aid, grp in pairs:
                union(pairs[0][0], aid)
                mark(aid, "ha", grp)
    hosts = {}
    for a in appliances:
        h = norm_ip(getattr(a, "host", "")) or str(getattr(a, "host", "") or "").strip().lower()
        if h:
            hosts.setdefault((kind[a.id], h), []).append(a.id)
    for aid, p in _cached_payloads(ids, "system_conf_sync").items():
        peer = norm_ip(p.get("ip"))
        for other in hosts.get((kind[aid], peer), []) if peer else []:
            if other != aid:
                union(aid, other)
                mark(aid, "config_sync")
                mark(other, "config_sync")

    members: dict[int, list[int]] = {}
    for aid in list(parent):
        members.setdefault(find(aid), []).append(aid)
    out: dict[int, dict] = {}
    for root, aids in members.items():
        if len(aids) < 2:
            continue
        rows = [by_id[x] for x in aids if x in by_id]
        node0s = [a for a in rows if getattr(a, "is_cluster", False)]
        srcs = set().union(*(sources.get(x, set()) for x in aids))
        src = next(s for s in ("registered", "ha", "config_sync") if s in srcs) \
            if srcs else "registered"
        if node0s:
            gname = node0s[0].name
        else:
            gname = next((names[x] for x in sorted(aids) if names.get(x)), "") or \
                " / ".join(sorted(a.name for a in rows))
        rank, role = {}, {}
        for a in rows:
            hint = (getattr(a, "ha_role_hint", "") or "").strip().lower()
            if getattr(a, "is_cluster", False):
                vip = (getattr(a, "ha_mode", "") or "").strip().lower() == "vip"
                r, why = (0, "vip") if vip else (2, "cluster")
            elif hint == "primary":
                r, why = 1, "primary"
            elif hint == "secondary":
                r, why = 4, "secondary"
            else:
                r, why = 3, "unknown"
            rank[a.id] = (r, a.name or "", a.id)
            role[a.id] = why
        # "N members": the boxes, never the node-0 container.
        boxes = [a for a in rows if not getattr(a, "is_cluster", False)]
        group = {"key": "g%d" % root, "name": gname, "source": GROUP_SOURCE[src],
                 "members": sorted(a.name for a in boxes) or sorted(a.name for a in rows),
                 "count": len(boxes) or len(rows), "rank": rank, "role": role}
        for a in rows:
            out[a.id] = group
    return out


#: Keys a match carries for ONE lookup (copied onto the representative).
_MATCH_KEYS = ("_match_field", "_mode", "_fwd_name", "_via")


def collapse_clusters(matches: list[dict], all_rows: list[dict] | None = None) -> list[dict]:
    """One row per (cluster, product, policy): the copies of one server policy
    on the members of one cluster become the member an edit must target
    (``cluster_map``'s rank), carrying ``_cluster``. *all_rows* (the whole
    sweep) lets the representative be the primary's copy even when only a
    secondary's copy matched. Rows without a group pass through unchanged."""
    index: dict[tuple, list[dict]] = {}
    for r in all_rows if all_rows is not None else matches:
        g = r.get("_group")
        if g:
            index.setdefault((g["key"], r.get("_kind"), r.get("policy")), []).append(r)
    out: list[dict] = []
    seen: dict[tuple, dict] = {}
    for m in matches:
        g = m.get("_group")
        if not g:
            out.append(m)
            continue
        k = (g["key"], m.get("_kind"), m.get("policy"))
        if k in seen:
            rep = seen[k]
            for f in (m.get("_match_field") or "").split(", "):
                if f and f not in (rep.get("_match_field") or "").split(", "):
                    rep["_match_field"] = ", ".join(x for x in (rep.get("_match_field"), f) if x)
            continue
        copies = index.get(k) or [m]
        if m not in copies:
            copies = copies + [m]
        best = min(copies, key=lambda r: g["rank"].get(r.get("_aid"), (9, r.get("gateway") or "",
                                                                       r.get("_aid") or 0)))
        rep = dict(best)
        for key in _MATCH_KEYS:
            if key in m:
                rep[key] = m[key]
        role = g["role"].get(rep.get("_aid"), "unknown")
        rep["_cluster"] = {
            "name": g["name"], "source": g["source"], "count": g["count"],
            "members": g["members"], "node": rep.get("gateway") or "",
            "role": role, "role_known": role in ("primary", "vip", "cluster"),
            "seen_on": sorted({c.get("gateway") or "" for c in copies} - {""}),
        }
        seen[k] = rep
        out.append(rep)
    return out


def cluster_text(m: dict) -> str:
    """The Cluster cell of Copy LB (English, like the other TSV labels)."""
    c = m.get("_cluster")
    if not c:
        return ""
    if c["role"] == "primary":
        return "Cluster: %s (primary %s, %d members)" % (c["name"], c["node"], c["count"])
    if c["role"] in ("vip", "cluster"):
        return "Cluster: %s (primary resolved by the cluster, %d members)" % (c["name"],
                                                                               c["count"])
    return "Cluster: %s (role unknown, showing %s, %d members)" % (c["name"], c["node"],
                                                                   c["count"])


def attach_appids(rows: list[dict]) -> None:
    """The AppID of each row from the CATALOG (SA-0027): the binding first,
    then the comment read with Analysis > AppID pattern -- the same answer the
    AppIDs page gives. ``app_id`` becomes that AppID; ``_appid`` carries the
    catalog facts (``fields``) and where they came from (``source``). A row
    neither knows keeps the comment token this page always showed."""
    from . import appids
    pairs = [(r.get("_aid"), r.get("policy")) for r in rows]
    comments = {(r.get("_aid"), r.get("policy")): r.get("comment") or "" for r in rows}
    info = appids.policy_info(pairs, comments)
    for r in rows:
        hit = info.get((r.get("_aid"), r.get("policy")))
        if hit:
            r["app_id"] = hit["app_id"]
            r["_appid"] = hit
        elif r.get("app_id"):
            r["_appid"] = {"app_id": r["app_id"], "source": "comment (not in catalog)",
                           "fields": {"app_id": r["app_id"]}}


# ---------------------------------------------------------------- reverse

PTR_MAX_IPS = 100


def _service_ips(m: dict) -> list[str]:
    """The addresses in a Service IP cell. A FortiWeb VIP carries its prefix
    (``172.0.0.1/32``, measured on FortiWeb 7.6.8): the PTR is of the
    address, so the length goes."""
    return [ip.strip().split("/", 1)[0]
            for ip in str(m.get("service_ip") or "").split(",") if ip.strip()]


def match_ips(matches: list[dict]) -> list[str]:
    """The service IPs of *matches*, each once, at most PTR_MAX_IPS."""
    ips: list[str] = []
    for m in matches:
        for ip in _service_ips(m):
            if _is_ip(ip) and ip not in ips:
                ips.append(ip)
    return ips[:PTR_MAX_IPS]


def add_service_names(matches: list[dict], servers: list[dict], answers=None) -> None:
    """Fill ``service_name`` with the PTR names of each match's service IP(s),
    asked of every configured resolver in parallel (names in the order the
    resolvers answered, each once). Only MATCHED rows: the whole fleet would be
    a PTR storm per search. Resolver markers (No result / timeout / error) are
    not names and are dropped; no resolver configured leaves the column blank."""
    # SA-0028: an empty Name is never left unexplained. ``_name_state`` says
    # why: ok / no_ip (no service IP) / no_resolver / no_ptr (every resolver
    # answered, none with a name) / error (``_name_error``: which resolver
    # failed how). ``service_name`` keeps the names only.
    if not matches:
        return
    if not servers:
        for m in matches:
            m["_name_state"] = "no_resolver" if _service_ips(m) else "no_ip"
        return
    ips = match_ips(matches)
    if answers is None:                 # lookup() passes the PTRs it already asked
        answers = lookup_many(ips, servers) if ips else {}
    names: dict[str, list[str]] = {}
    errors: dict[str, list[str]] = {}
    for ip in ips:
        got: list[str] = []
        for s in servers:
            for v in answers.get((ip, s["name"]), []):
                v = v.rstrip(".")
                if v in ("timeout", "error"):
                    errors.setdefault(ip, []).append("%s %s" % (s["name"], v))
                elif v and v != "No result" and v not in got:
                    got.append(v)
        names[ip] = got
    for m in matches:
        found: list[str] = []
        errs: list[str] = []
        mine = [ip for ip in _service_ips(m) if ip in names]
        for ip in mine:
            for n in names.get(ip, []):
                if n not in found:
                    found.append(n)
            errs += [e for e in errors.get(ip, []) if e not in errs]
        m["service_name"] = ", ".join(found)
        if found:
            m["_name_state"] = "ok"
        elif not mine:
            m["_name_state"] = "no_ip"
        elif errs:
            m["_name_state"], m["_name_error"] = "error", "; ".join(errs)
        else:
            m["_name_state"] = "no_ptr"


#: What the Name cell says when it has no name (Copy LB; the page translates).
NAME_STATE_TEXT = {"no_ptr": "no PTR", "no_ip": "no service IP",
                   "no_resolver": "no resolver configured", "error": "PTR error"}


def name_text(m: dict) -> str:
    """The Name cell as text: the forward name an FQDN lookup resolved to this
    service, then the PTR names of its service IP -- or why there is none."""
    names = [m["_fwd_name"]] if m.get("_fwd_name") else []
    names += [n for n in str(m.get("service_name") or "").split(", ") if n and n not in names]
    if m.get("_spo_fqdn") and m["_spo_fqdn"] not in names:
        names.append(m["_spo_fqdn"])            # SA-0029: the name the policy is named after
    state = m.get("_name_state") or ""
    if m.get("service_name") or not state or state == "ok":
        return ", ".join(names)
    why = NAME_STATE_TEXT.get(state, state)
    if state == "error" and m.get("_name_error"):
        why = "%s: %s" % (why, m["_name_error"])
    elif state == "no_ip" and m.get("_vip_note"):
        why = "%s: %s" % (why, m["_vip_note"])
    return "%s (%s)" % (", ".join(names), why) if names else why


def spo_text(m: dict) -> str:
    """``www.example.com -> 192.0.2.5`` (SPO Regex FQDN and what it resolves
    to), or the FQDN alone, or ""."""
    f = m.get("_spo_fqdn") or ""
    ips = m.get("_spo_ips") or []
    return "%s -> %s" % (f, ", ".join(ips)) if f and ips else f


# ---------------------------------------------------------------- Copy LB

def _tsv_cell(value) -> str:
    """One TSV cell: a tab or line break inside a comment would split the row
    and shift every column after it, so whitespace runs become one space."""
    return " ".join(str("" if value is None else value).split())


def lb_tsv_header(appid_cols=()) -> list[str]:
    """Copy LB's columns: the entry, every LB column (Name says why it is
    empty), then how the entry was looked up, which field matched and the
    cluster (SA-0028), the AppID facts of the catalog (the AppID itself is
    already the App ID column) and where the AppID came from. ``appid_cols``
    is ``appids.info_columns()``."""
    return (["Entry"] + [label for _k, label in COLUMNS]
            + ["Lookup", "Matched on", "Cluster", "SPO Regex FQDN"]
            + ["AppID %s" % label for k, label in appid_cols if k != "app_id"]
            + ["AppID source"])


def lb_tsv_line(entry: str, m: dict, appid_cols=()) -> list[str]:
    info = m.get("_appid") or {}
    fields = info.get("fields") or {}
    cell = {"service_name": name_text(m)}
    return ([_tsv_cell(entry)]
            + [_tsv_cell(cell[k] if k in cell else m.get(k, "")) for k, _l in COLUMNS]
            + [_tsv_cell(MODE_LABELS.get(m.get("_mode"), m.get("_mode") or "")),
               _tsv_cell(m.get("_match_field", "")), _tsv_cell(cluster_text(m)),
               _tsv_cell(spo_text(m))]
            + [_tsv_cell(fields.get(k, "")) for k, _l in appid_cols if k != "app_id"]
            + [_tsv_cell(info.get("source", ""))])


def match_rows(rows: list[dict], query: str, resolved: str, *,
               exact: bool = False) -> list[dict]:
    """PHP-parity matching: any column, substring by default, exact optional."""
    return [row for row in rows if _text_hits(row, query, resolved, exact=exact, first=True)]


def _text_hits(row: dict, query: str, resolved: str, *, exact: bool = False,
               first: bool = False) -> list[str]:
    """The keys of *row* whose text matches (match_rows' rule); with *first*
    the first one only."""
    keys = []
    q, r = (query or "").lower(), (resolved or "").lower()
    for key, value in row.items():
        if key.startswith("_"):  # private (link/graph) keys never match
            continue
        v = str(value).lower()
        if exact:
            tokens = [t.strip() for t in v.split(",")]
            hit = q in (v, *tokens) or r in (v, *tokens)
        else:
            hit = bool((q and q in v) or (r and r in v))
        if hit:
            keys.append(key)
            if first:
                break
    return keys


# ---------------------------------------------------------------- SA-0028
# Three lookups, chosen per entry (or forced by the Lookup selector):
#   element -- any text of the config (policy, pool, certificate, comment...):
#              the match's VIP is its Service IP, its PTR the Name;
#   ip      -- the address in any SPO's ADDRESS fields (VIP, pool members,
#              other address fields): never a substring, so 192.0.2.5 does not
#              find 192.0.2.50; the row says which field held it;
#   fqdn    -- resolve the name (A and AAAA, every resolver), then look up
#              each address as ``ip`` does, plus the name's own text (an SNI,
#              a certificate CN, a host field).

MODES = ("auto", "element", "ip", "fqdn")
MODE_LABELS = {"element": "Element", "ip": "IP", "fqdn": "FQDN"}
_FQDN_RE = re.compile(
    r"^(\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?$")
NO_ANSWER = ("No result", "timeout", "error")


def detect_mode(query: str) -> str:
    """``ip`` / ``fqdn`` / ``element`` for one entry (its name part)."""
    q = (query or "").strip()
    if _is_ip(q):
        return "ip"
    if _FQDN_RE.match(q):
        return "fqdn"
    return "element"


def entry_mode(query: str, forced: str = "auto") -> str:
    """The mode one entry is looked up with: the selector's, unless it is
    ``auto`` or asks ``ip`` of something that is not an address."""
    if forced == "ip" and not _is_ip((query or "").strip()):
        return detect_mode(query)
    return forced if forced in MODE_LABELS else detect_mode(query)


def ip_hits(rows: list[dict], ip: str) -> list[tuple[dict, list[str]]]:
    """``[(row, [field labels])]`` of the rows holding *ip* in an address
    field (``_ips``), exact address equality."""
    want = norm_ip(ip)
    out = []
    if not want:
        return out
    for row in rows:
        fields = []
        for label, value in row.get("_ips") or []:
            if value == want and label not in fields:
                fields.append(label)
        if fields:
            out.append((row, fields))
    return out


def answer_ips(values) -> list[str]:
    """The addresses among resolver answers (a CNAME target and the markers
    are not; ``(TTL:n)`` suffixes go)."""
    out = []
    for v in values or []:
        ip = norm_ip(str(v).split(" (TTL:")[0])
        if ip and ip not in out:
            out.append(ip)
    return out


def match_entry(rows: list[dict], query: str, resolved: str, mode: str, *,
                exact: bool = False, fwd_ips=()) -> list[dict]:
    """The matches of one entry, each a COPY of its row with ``_mode``,
    ``_match_field`` (which field held it) and, for an FQDN, ``_fwd_name``
    when the row's VIP is one of the name's addresses."""
    labels = dict(COLUMNS)
    order: list[int] = []
    found: dict[int, tuple[dict, list[str], bool]] = {}

    def add(row, fields, fwd=False):
        k = id(row)
        if k not in found:
            found[k] = (row, [], False)
            order.append(k)
        r, have, was_fwd = found[k]
        have += [f for f in fields if f not in have]
        found[k] = (r, have, was_fwd or fwd)

    if mode == "ip":
        for row, fields in ip_hits(rows, resolved or query):
            add(row, fields)
    else:
        for row in rows:
            keys = _text_hits(row, query, resolved, exact=exact)
            if keys:
                add(row, [labels.get(k, k) for k in keys])
        if mode == "fqdn":
            for ip in fwd_ips or ():
                for row, fields in ip_hits(rows, ip):
                    add(row, ["%s (%s)" % (f, ip) for f in fields],
                        fwd=any(f == "VIP" for f in fields))
            # SA-0029: the policy NAMED after this FQDN (SPO Regex), even when
            # the name resolves to an address that is not its VIP.
            want = (resolved or query).strip().rstrip(".").lower()
            for row in rows:
                if want and row.get("_spo_fqdn") == want:
                    add(row, [SPO_FIELD], fwd=True)
    out = []
    for k in order:
        row, fields, fwd = found[k]
        m = dict(row)
        m["_mode"] = mode
        m["_match_field"] = ", ".join(fields)
        if fwd:
            m["_fwd_name"] = (resolved or query).rstrip(".")
        out.append(m)
    return out


# ---------------------------------------------------------------- SA-0029
# SPO Regex: how this site names its server policies / virtual servers after
# the service they publish (``spo_www_example_com_443`` -> ``www.example.com``).
# Ordered rules, the first that turns the name into an FQDN wins. With it an
# FQDN finds its policy by NAME even when the address it resolves to is not
# the VIP (NAT, a CDN in front), and an element lookup says which name the
# policy serves. Stored console-wide like the resolvers.

SPO_REGEX_KEY = "dnstool.spo_regex"
SPO_RULES_MAX = 10
SPO_PATTERN_MAX = 300
SPO_REPLACE_MAX = 200
SPO_NAME_MAX = 128          # policy names are <= 63 on FortiWeb/FortiADC
SPO_FIELD = "SPO name (SPO Regex)"


def _clean_rule(r) -> dict | None:
    if not isinstance(r, dict):
        return None
    pattern = str(r.get("pattern") or "").strip()
    if not pattern:
        return None
    return {"pattern": pattern[:SPO_PATTERN_MAX],
            "replace": str(r.get("replace") or "").strip()[:SPO_REPLACE_MAX],
            "dots": bool(r.get("dots")),
            "enabled": bool(r.get("enabled", True))}


def spo_rules() -> list[dict]:
    """The SPO Regex rules (AppSetting ``dnstool.spo_regex``), in order."""
    from ..models import AppSetting
    try:
        rows = json.loads(AppSetting.get(SPO_REGEX_KEY) or "[]")
    except (ValueError, TypeError):
        return []
    out = [c for c in (_clean_rule(r) for r in (rows if isinstance(rows, list) else []))
           if c]
    return out[:SPO_RULES_MAX]


def save_spo_rules(rows) -> list[dict]:
    """Validate (every pattern compiles, at most SPO_RULES_MAX) and persist."""
    from ..extensions import db
    from ..models import AppSetting
    clean = [c for c in (_clean_rule(r) for r in (rows or [])) if c]
    if len(clean) > SPO_RULES_MAX:
        raise ValueError("at most %d SPO Regex rules" % SPO_RULES_MAX)
    for c in clean:
        try:
            re.compile(c["pattern"])
        except re.error as exc:
            raise ValueError("SPO Regex %r does not compile: %s" % (c["pattern"], exc)) from None
    AppSetting.set(SPO_REGEX_KEY, json.dumps(clean))
    db.session.commit()
    return clean


def spo_apply(name: str, rule: dict) -> tuple[str, str]:
    """``(fqdn, why_not)`` of one rule on one policy name. The result is the
    replacement (``\\1``, ``\\g<name>``) or, without one, the group named
    ``fqdn``, else group 1, else the whole match; "Underscores to dots"
    turns ``www_example_com`` into ``www.example.com``. Only a valid FQDN
    counts."""
    name = str(name or "")[:SPO_NAME_MAX]
    try:
        rx = re.compile(rule["pattern"], re.IGNORECASE)
        m = rx.search(name)
        if not m:
            return "", "no match"
        if rule.get("replace"):
            out = m.expand(rule["replace"])
        elif "fqdn" in rx.groupindex:
            out = m.group("fqdn") or ""
        else:
            out = m.group(1) if rx.groups else m.group(0)
    except (re.error, IndexError) as exc:
        return "", "rule error: %s" % exc
    if rule.get("dots"):
        out = out.replace("_", ".")
    out = (out or "").strip().strip(".").lower()
    if not _FQDN_RE.match(out):
        return "", "%r is not an FQDN" % out
    return out, ""


def spo_fqdn(name: str, rules: list[dict]) -> str:
    """The FQDN the first enabled rule gives *name*, or ""."""
    for rule in rules or ():
        if rule.get("enabled", True):
            out, _why = spo_apply(name, rule)
            if out:
                return out
    return ""


def spo_test(names: list[str], rules: list[dict]) -> list[dict]:
    """The SPO Regex dialog's preview: per name, the FQDN and which rule gave
    it -- or why each rule did not."""
    out = []
    for n in names:
        row = {"name": n, "fqdn": "", "rule": None, "why": []}
        for i, rule in enumerate(rules or ()):
            if not rule.get("enabled", True):
                row["why"].append("rule %d: off" % (i + 1))
                continue
            fqdn, why = spo_apply(n, rule)
            if fqdn:
                row.update(fqdn=fqdn, rule=i + 1)
                break
            row["why"].append("rule %d: %s" % (i + 1, why))
        out.append(row)
    return out


def _spo_resolve(matches: list[dict], servers: list[dict]) -> None:
    """``_spo_ips`` = the addresses the SPO Regex FQDN of each match resolves
    to (A, every resolver), so an element lookup by policy name says which
    name -- and which address -- the policy serves."""
    names = []
    for m in matches:
        f = m.get("_spo_fqdn")
        if f and f not in names:
            names.append(f)
    names = names[:PTR_MAX_IPS]
    if not names or not servers:
        return
    answers = lookup_many(names, servers)
    ips: dict[str, list[str]] = {}
    for n in names:
        got: list[str] = []
        for s in servers:
            got += [ip for ip in answer_ips(answers.get((n, s["name"]), [])) if ip not in got]
        ips[n] = got
    for m in matches:
        if m.get("_spo_fqdn"):
            m["_spo_ips"] = ips.get(m["_spo_fqdn"], [])


def _merge_answers(a: list[str], aaaa: list[str]) -> list[str]:
    real = []
    for v in list(a or []) + list(aaaa or []):
        if v not in NO_ANSWER and v not in real:
            real.append(v)
    return real or list(a or ["No result"])


def lookup(entries: list[str], servers: list[dict], lb_rows: list[dict], *,
           mode: str = "auto", exact: bool = False, show_ttl: bool = False,
           names: bool = True, spo_rules=None) -> tuple[list[dict], list[str]]:
    """The page's search: ``(results, not_found)``. One result per entry::

        {entry, resolved, is_wildcard, mode, dns: {server: [answers]},
         fwd_ips, dns_state, dns_errors, matches, gateways}

    ``dns_state`` (FQDN): resolved / no_answer / error / no_resolver.
    Matches are cluster-collapsed (``collapse_clusters``) and, with *names*,
    named by the PTR of their service IP.

    SA-0029: with *spo_rules* every row carries ``_spo_fqdn`` (the FQDN its
    name gives, SPO Regex), an FQDN also finds the policy named after it, and
    an element match says which address its SPO FQDN resolves to. In
    ``auto``, an entry that is not FQDN-shaped but that the resolvers answer
    with addresses is looked up as an FQDN: what DNS answered is searched."""
    mode = mode if mode in MODES else "auto"
    for row in lb_rows or ():
        row["_spo_fqdn"] = spo_fqdn(row.get("policy") or "", spo_rules) if spo_rules else ""
    parsed = []
    jobs = list(entries)
    for e in entries:
        query, rtype = parse_entry(e)
        m = entry_mode(query, mode)
        parsed.append((e, query, rtype, m))
        if m == "fqdn" and rtype is None:
            jobs.append("%s AAAA" % query)          # A is the entry itself
    dns_map = lookup_many(jobs, servers, show_ttl=show_ttl)
    results, not_found = [], []
    for e, query, rtype, m in parsed:
        resolved = resolve_wildcard(query)
        if mode == "auto" and m == "element" and rtype is None and any(
                answer_ips(dns_map.get((e, s["name"]), [])) for s in servers):
            m = "fqdn"          # it resolved: search what DNS answered (SA-0029)
        per_server = {}
        fwd_ips: list[str] = []
        errs: list[str] = []
        for s in servers:
            a = dns_map.get((e, s["name"]), ["No result"])
            if m == "fqdn" and rtype is None:
                aaaa = dns_map.get(("%s AAAA" % query, s["name"]), ["No result"])
                vals = _merge_answers(a, aaaa)
                errs += ["%s %s" % (s["name"], v) for v in set(a + aaaa)
                         if v in ("timeout", "error")]
            else:
                vals = a
                errs += ["%s %s" % (s["name"], v) for v in a if v in ("timeout", "error")]
            per_server[s["name"]] = vals
            if m == "fqdn":
                fwd_ips += [ip for ip in answer_ips(vals) if ip not in fwd_ips]
        if m != "fqdn" or rtype not in (None, "A", "AAAA"):
            state = ""                 # "name MX" asks for no address
        elif not servers:
            state = "no_resolver"
        elif fwd_ips:
            state = "resolved"
        elif errs:
            state = "error"
        else:
            state = "no_answer"
        matches = match_entry(lb_rows, query, resolved, m, exact=exact,
                              fwd_ips=fwd_ips) if lb_rows else []
        matches = collapse_clusters(matches, lb_rows)
        no_dns = all(all(v in NO_ANSWER for v in vals) for vals in per_server.values())
        if no_dns and not matches:
            not_found.append(e)
        results.append({
            "entry": e, "resolved": resolved, "is_wildcard": query.startswith("*."),
            "mode": m, "dns": per_server, "fwd_ips": fwd_ips, "dns_state": state,
            "dns_errors": sorted(set(errs)), "matches": matches,
            "gateways": sorted({x.get("gateway") or "" for x in matches} - {""}),
        })
    every = [x for r in results for x in r["matches"]]
    ptr = lookup_many(match_ips(every), servers) if every and servers else {}
    for r in results:
        if r["mode"] == "element" and r["matches"]:
            vip_dns(r, ptr, servers)
    if names:
        add_service_names(every, servers, answers=ptr)
        _spo_resolve(every, servers)
    return results, not_found


VIP_SEP = " → "


def vip_dns(r: dict, ptr: dict, servers: list[dict]) -> None:
    """SA-0029: an ELEMENT (a policy name, a pool...) is not a DNS name, so
    asking the resolvers for it answers nothing. Its DNS columns are the
    reverse lookup of the VIP of what it matched, per resolver, as
    ``"<vip> → <answer>"``; ``dns_via`` says so (``vip``), or that no match
    has a VIP (``no_vip``, the entry's own answers stay)."""
    ips = match_ips(r["matches"])
    if not ips:
        r["dns_via"] = "no_vip"
        return
    errs = []
    for s in servers:
        vals = []
        for ip in ips:
            for v in ptr.get((ip, s["name"])) or ["No result"]:
                vals.append(ip + VIP_SEP + v)
                if v in ("timeout", "error"):
                    errs.append("%s %s %s" % (s["name"], ip, v))
        r["dns"][s["name"]] = vals
    r["dns_via"], r["vip_ips"], r["dns_errors"] = "vip", ips, sorted(set(errs))


# --------------------------------------------------------------------------- #
#  the page, as one call (2026-11-09)                                          #
# --------------------------------------------------------------------------- #
# The DNS & LB Lookup page (views.dns_tool.index) and its plugin (the
# Plugin Studio step ``dns_lb_lookup`` + ``dns_page_context``, services.
# studio_dns) draw the SAME thing because they call these two functions:
# nothing of the search is decided twice.

def appid_columns() -> list:
    """The catalog's own column names (AppIDs page), so the AppID table of a
    match reads like the catalog it comes from."""
    from . import appids
    try:
        return [list(c) for c in appids.info_columns()]
    except Exception:  # noqa: BLE001 -- no catalog yet: the AppID column alone
        return [["app_id", "AppID"]]


def clipboards(results, servers, appid_cols=()) -> tuple[str, str]:
    """TSV exports mirroring the PHP tool's Copy DNS / Copy LB buttons.

    Copy LB carries the FULL row (SA-0027): the entry it matched, every LB
    column -- whole comment, PTR name, each backend with its status -- and the
    AppID facts of the catalog (``lb_tsv_*``, shared with the lb_lookup step)."""
    dns_lines = ["\t".join(["Entry"] + [s["name"] for s in servers])]
    for r in results:
        dns_lines.append("\t".join(
            [r["entry"]] + ["; ".join(r["dns"].get(s["name"], [])) for s in servers]))
    lb_lines = ["\t".join(lb_tsv_header(appid_cols))]
    for r in results:
        for m in r["matches"]:
            lb_lines.append("\t".join(lb_tsv_line(r["entry"], m, appid_cols)))
    return "\n".join(dns_lines), "\n".join(lb_lines)


def page_context(user) -> dict:
    """What the page shows before any search: the resolvers it asks, the
    DNS backends, the SPO Regex rules, and what *user* may do there."""
    from . import dns_providers

    def can(perm):
        return bool(user is not None and getattr(user, "can", None) and user.can(perm))
    return {"servers": [s for s in dns_servers() if s.get("enabled", True)],
            "appid_cols": appid_columns(), "columns": [list(c) for c in COLUMNS],
            "dns_backends": [r.public() for r in dns_providers.enabled_backends("dns")],
            "can_manage_records": can("user_manage"), "can_decommission": can("config_write"),
            "can_edit_spo": can("user_manage"), "can_live_health": can("protection.view"),
            "spo_rules": spo_rules(), "spo_rules_max": SPO_RULES_MAX}


def _on(v) -> bool:
    return v is True or str(v or "").strip().lower() in ("on", "yes", "true", "1")


def search(form) -> dict:
    """The page's search: *form* has entries, mode, lb, quick (the page's
    form fields; a missing box is unticked). Must run where the person's
    scope applies (a request, or studio_dns.as_operator): fleet_lb_rows reads
    the ADOM's devices only."""
    servers = [s for s in dns_servers() if s.get("enabled", True)]
    appid_cols = appid_columns()
    opts = {"lb": _on(form.get("lb")), "quick": _on(form.get("quick"))}
    mode = str(form.get("mode") or "auto")
    if mode not in MODES:
        mode = "auto"
    entries_raw = str(form.get("entries") or "")
    entries = []
    for line in entries_raw.splitlines():
        e = clean_entry(line)
        if e and e not in entries:
            entries.append(e)
    entries = entries[:MAX_ENTRIES]
    lb_rows, lb_error = [], None
    if entries and (opts["lb"] or opts["quick"]):
        try:
            lb_rows = fleet_lb_rows()
        except Exception as exc:  # noqa: BLE001 -- the DNS half still renders
            lb_error = str(exc)
    results, not_found = lookup(entries, servers, lb_rows, mode=mode, names=opts["lb"],
                                spo_rules=spo_rules())
    clip_dns, clip_lb = clipboards(results, servers, appid_cols)
    return {"searched": True, "opts": opts, "mode": mode, "entries_raw": entries_raw,
            "results": results, "not_found": not_found, "clip_dns": clip_dns,
            "clip_lb": clip_lb, "lb_error": lb_error}
