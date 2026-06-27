"""Service-policy validation for the upgrade runbook — resolve every server
policy's published front-end and HTTP-probe it like ``curl`` would, so the
operator can diff service reachability before vs after a firmware upgrade.

Web port of the desktop ``services/service_probe.py``. The pure layers
(``probe_url`` / ``diff_probes`` / ``render_status_html``) are copied almost
verbatim — they are network-free and firmware-agnostic. The desktop's
``resolve_targets`` walked a full topology snapshot; here we resolve straight
off the web client's composite :meth:`FortiWebClient.policy_full` plus the
``system/vip`` and ``system/interface`` tables (explicit IP → system VIP IP →
bound-interface IP — the same order FortiWeb itself uses), which keeps the web
app's deliberately-small client surface without porting the topology stack.
"""
from __future__ import annotations

import hashlib
import html
import time
from dataclasses import asdict, dataclass, field
from typing import Any

# response headers worth capturing/diffing (a small, stable subset)
_KEY_HEADERS = ("server", "content-type", "location", "content-length")

# Predefined FortiWeb service → port (the common ones; custom objects resolved
# from the services-custom table at runtime).
_PREDEFINED_PORTS = {
    "HTTP": 80, "HTTPS": 443, "HTTP_8080": 8080, "HTTPS_8443": 8443,
}


@dataclass
class ServiceTarget:
    policy: str
    scheme: str = "http"
    host: str = ""
    port: int | None = None
    url: str = ""
    vserver: str = ""
    pool: str = ""
    backends: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class ProbeResult:
    url: str = ""
    ok: bool = False
    status: int | None = None
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body_len: int | None = None
    body_sha8: str = ""
    elapsed_ms: int | None = None
    error: str = ""


def _truthy(v: Any) -> bool:
    return str(v).strip().lower() in ("enable", "enabled", "yes", "true", "1", "on")


def _usable_ip(ip: str) -> str:
    ip = (ip or "").split("/", 1)[0].strip()
    return "" if ip in ("", "0.0.0.0", "::") else ip


def _port_for(service: str, custom_ports: dict[str, int], is_https: bool) -> int:
    svc = (service or "").strip()
    if svc.upper() in _PREDEFINED_PORTS:
        return _PREDEFINED_PORTS[svc.upper()]
    if svc in custom_ports:
        return custom_ports[svc]
    # trailing number? (e.g. a custom "HTTPS_9443")
    tail = "".join(ch for ch in svc[::-1] if ch.isdigit())[::-1]
    if tail.isdigit():
        return int(tail)
    return 443 if is_https else 80


def resolve_targets_from_client(client) -> list[ServiceTarget]:
    """Resolve every server policy on a connected client to a probe target.

    Best-effort and clearly-noted when a VIP IP can't be resolved (the before/
    after diff still works for the policies that do resolve).
    """
    # name → IP for system VIP objects and interfaces (host resolution sources)
    vip_ip: dict[str, str] = {}
    for v in client._safe_list("/api/v2.0/cmdb/system/vip"):
        name = str(v.get("name") or v.get("mkey") or "").strip()
        ip = _usable_ip(v.get("vip") or v.get("ip") or "")
        if name and ip:
            vip_ip[name] = ip
    iface_ip: dict[str, str] = {}
    for i in client._safe_list("/api/v2.0/cmdb/system/interface"):
        name = str(i.get("name") or i.get("mkey") or "").strip()
        raw = str(i.get("ip") or i.get("ipv4") or "").split()  # "192.0.2.5/24" or "192.0.2.5 mask"
        ip = _usable_ip(raw[0]) if raw else ""
        if name and ip:
            iface_ip[name] = ip
    custom_ports: dict[str, int] = {}
    for s in client._safe_list("/api/v2.0/cmdb/server-policy/service-custom"):
        name = str(s.get("name") or s.get("mkey") or "").strip()
        raw = str(s.get("port") or "").strip().split("-")[0].split()
        if name and raw and raw[0].isdigit():
            custom_ports[name] = int(raw[0])

    targets: list[ServiceTarget] = []
    for row in client._results_list(client.list_server_policies()):
        name = str(row.get("name") or row.get("mkey") or "").strip()
        if not name:
            continue
        try:
            full = client.policy_full(name)
        except Exception:  # noqa: BLE001 — one bad policy never sinks the rest
            full = {"policy": row}
        policy = full.get("policy") or row
        host = ""
        for vip in full.get("vips") or []:
            host = (_usable_ip(vip.get("ip") or vip.get("vip-ip") or "")
                    or vip_ip.get(str(vip.get("vip") or vip.get("name") or ""), "")
                    or iface_ip.get(str(vip.get("interface") or ""), ""))
            if host:
                break
        if not host:  # fall back to the vserver's own interface, if any
            vs = full.get("vserver") or {}
            host = iface_ip.get(str(vs.get("interface") or ""), "")
        service = str(policy.get("service") or "")
        is_https = _truthy(policy.get("ssl")) or "HTTPS" in service.upper()
        port = _port_for(service, custom_ports, is_https)
        scheme = "https" if (is_https or port == 443) else "http"
        url = f"{scheme}://{host}:{port}/" if host else ""
        backends = []
        for m in full.get("backends") or []:
            ip = _usable_ip(m.get("ip") or m.get("server-ip") or m.get("domain") or "")
            p = m.get("port")
            if ip:
                backends.append(f"{ip}:{p}" if p else ip)
        targets.append(ServiceTarget(
            policy=name, scheme=scheme, host=host, port=port, url=url,
            vserver=str(policy.get("vserver") or ""),
            pool=str(policy.get("server-pool") or ""),
            backends=backends,
            note="" if url else "could not resolve a VIP IP for this policy",
        ))
    return targets


def probe_url(url: str, timeout: float = 10.0) -> ProbeResult:
    """HTTP GET a URL and capture the response (curl-equivalent, self-signed OK)."""
    if not url:
        return ProbeResult(url=url, ok=False, error="no target URL resolved")
    import httpx

    t0 = time.time()
    try:
        r = httpx.get(url, verify=False, timeout=timeout, follow_redirects=False)
        body = r.content or b""
        return ProbeResult(
            url=url, ok=True, status=r.status_code, reason=r.reason_phrase,
            headers={k: r.headers.get(k, "") for k in _KEY_HEADERS if r.headers.get(k)},
            body_len=len(body), body_sha8=hashlib.sha256(body).hexdigest()[:8],
            elapsed_ms=int((time.time() - t0) * 1000),
        )
    except Exception as e:  # noqa: BLE001 — any transport/TLS failure = unreachable
        return ProbeResult(
            url=url, ok=False, error=f"{type(e).__name__}: {e}".strip()[:200],
            elapsed_ms=int((time.time() - t0) * 1000),
        )


def probe_targets(targets: list[ServiceTarget], timeout: float = 10.0) -> list[dict]:
    out: list[dict] = []
    for t in targets:
        out.append({"target": asdict(t), "result": asdict(probe_url(t.url, timeout))})
    return out


def diff_probes(before: list[dict], after: list[dict]) -> list[dict]:
    """Match before/after by policy name → per-policy verdict + change list."""
    bmap = {p["target"]["policy"]: p for p in before}
    amap = {p["target"]["policy"]: p for p in after}
    changes: list[dict] = []
    for name in sorted(set(bmap) | set(amap)):
        b, a = bmap.get(name), amap.get(name)
        if b and not a:
            changes.append({"policy": name, "verdict": "removed", "diffs": ["policy gone after upgrade"]})
            continue
        if a and not b:
            changes.append({"policy": name, "verdict": "new", "diffs": ["policy new after upgrade"]})
            continue
        br, ar = b["result"], a["result"]
        diffs: list[str] = []
        if br.get("ok") != ar.get("ok"):
            diffs.append(f"reachable: {br.get('ok')} -> {ar.get('ok')}")
        if br.get("status") != ar.get("status"):
            diffs.append(f"HTTP status: {br.get('status')} -> {ar.get('status')}")
        for h in _KEY_HEADERS:
            bv, av = br.get("headers", {}).get(h, ""), ar.get("headers", {}).get(h, "")
            if bv != av:
                diffs.append(f"header {h}: '{bv}' -> '{av}'")
        if br.get("body_sha8") != ar.get("body_sha8"):
            diffs.append("response body changed")
        changes.append({"policy": name, "verdict": "changed" if diffs else "same", "diffs": diffs})
    return changes


def _esc(v: Any) -> str:
    return html.escape(str(v if v is not None else ""))


def _result_cell(res: dict) -> str:
    if not res:
        return '<span class="muted">-</span>'
    if res.get("ok"):
        st = res.get("status")
        cls = "ok" if isinstance(st, int) and st < 400 else "warn"
        extra = f" - {res['elapsed_ms']}ms" if res.get("elapsed_ms") is not None else ""
        return f'<span class="{cls}">{_esc(st)} {_esc(res.get("reason"))}{_esc(extra)}</span>'
    return f'<span class="bad">unreachable</span><div class="muted small">{_esc(res.get("error"))}</div>'


_VERDICT_CLS = {"same": "ok", "changed": "warn", "new": "warn", "removed": "bad"}


def render_status_html(meta: dict, before: list[dict], after: list[dict], diff: list[dict]) -> str:
    """Render the upgrade service-validation page. Pure (caller writes/serves it)."""
    bmap = {p["target"]["policy"]: p for p in before}
    amap = {p["target"]["policy"]: p for p in after}
    dmap = {d["policy"]: d for d in diff}

    changed = sum(1 for d in diff if d["verdict"] != "same")
    n_pol = len(set(bmap) | set(amap))
    overall_ok = bool(meta.get("reachable_after")) and changed == 0
    badge = ("OK - no service changes" if overall_ok
             else f"ATTENTION - {changed} service change(s)" if meta.get("reachable_after")
             else "ATTENTION - appliance not recovered")
    badge_cls = "ok" if overall_ok else "bad"

    rows = []
    for name in sorted(set(bmap) | set(amap)):
        b, a = bmap.get(name), amap.get(name)
        tgt = (a or b)["target"]
        d = dmap.get(name, {"verdict": "same", "diffs": []})
        vcls = _VERDICT_CLS.get(d["verdict"], "warn")
        url = tgt.get("url") or f'<span class="muted">{_esc(tgt.get("note") or "no URL")}</span>'
        backends = ", ".join(tgt.get("backends") or []) or "-"
        difftext = "<br>".join(_esc(x) for x in d["diffs"]) or "-"
        rows.append(
            f"<tr><td><b>{_esc(name)}</b><div class='muted small'>vs: {_esc(tgt.get('vserver'))} - "
            f"pool: {_esc(tgt.get('pool'))}</div></td>"
            f"<td class='mono small'>{url if isinstance(url, str) and url.startswith('<') else _esc(url)}</td>"
            f"<td class='mono small'>{_esc(backends)}</td>"
            f"<td>{_result_cell(b['result']) if b else '-'}</td>"
            f"<td>{_result_cell(a['result']) if a else '-'}</td>"
            f"<td><span class='pill {vcls}'>{_esc(d['verdict'])}</span><div class='muted small'>{difftext}</div></td></tr>"
        )
    table = ("\n".join(rows) if rows else
             "<tr><td colspan='6' class='muted'>No server policies were found to validate.</td></tr>")
    return (
        f'<div class="sp-badge {badge_cls}">{_esc(badge)}</div>'
        f'<div class="sp-meta muted small">policies: {n_pol} - changed: {changed} - '
        f'firmware: {_esc(meta.get("firmware_before") or "?")} -&gt; {_esc(meta.get("firmware_after") or "?")}</div>'
        '<table class="table table-sm fw-table sp-table"><thead><tr>'
        '<th>Server policy</th><th>Probed URL</th><th>Back-end</th>'
        '<th>Before</th><th>After</th><th>Verdict</th></tr></thead><tbody>'
        f'{table}</tbody></table>'
    )


__all__ = [
    "ServiceTarget", "ProbeResult", "resolve_targets_from_client",
    "probe_url", "probe_targets", "diff_probes", "render_status_html",
]
