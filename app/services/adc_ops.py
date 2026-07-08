"""FortiADC appliance operations — the ADC side of the appliance actions.

Gives ``kind='fortiadc'`` appliances the SAME action set the FortiWeb detail
page offers (console presets, health battery, VS inspector, service probing,
firmware string), each implemented against the FortiADC CLI/REST conventions
(docs/fortiadc.md). Everything here was LIVE-VERIFIED on FortiADC-KVM 8.0.3
(fadc, 2026-07-07):

* SSH: FortiADC accepts the same session mechanics as FortiWeb — the
  ``config system console / set output standard / end`` pager disable and the
  ``hostname # `` prompt — so :class:`app.services.ssh_ops.FortiWebReadonlySSH`
  is reused as-is; only the ``diagnose``/``get`` command TREE differs (e.g.
  ``diagnose system ha status`` is FortiWeb-only, ADC uses ``get system ha``).
* REST: ``/api/platform/version`` → ``{build, hostname, model, version}`` is
  the status/firmware source (``/api/system/status`` does NOT exist on ADC).
"""
from __future__ import annotations

from typing import Any

from .inspector import _attrs, render_tree
from .service_probe import ServiceTarget

# Read-only console presets — every command verified on FortiADC-KVM 8.0.3.
TROUBLESHOOT_ADC: dict[str, str] = {
    "System status": "get system status",
    "Performance": "get system performance",
    "HA status": "get system ha",
    "Interfaces": "get system interface",
    "Routing table": "get router info routing-table all",
    "Netlink interfaces": "diagnose netlink interface list",
    "Disk usage": "diagnose system df",
}

# The pre-flight health battery = the same verified read-only set.
HEALTH_BATTERY_ADC: list[str] = list(TROUBLESHOOT_ADC.values())


def health_text(appliance) -> str:
    """The ADC diagnostic battery rendered as one labelled text blob."""
    from .ssh_ops import FortiWebReadonlySSH

    with FortiWebReadonlySSH(appliance, timeout=25.0) as ssh:
        out = ssh.run_battery(HEALTH_BATTERY_ADC)
    blocks = [f"===== {cmd} =====\n{text}".rstrip() for cmd, text in out.items()]
    return "\n\n".join(blocks)


def firmware_string(client) -> str:
    """Human firmware string off ``/api/platform/version`` (e.g.
    ``FortiADC-KVM v8.0.3 build0093,260401``). Empty string on failure."""
    try:
        p = client.platform_version()
        ver = str(p.get("version") or "").replace("-", ".")
        model = str(p.get("model") or "").strip()
        build = str(p.get("build") or "").strip()
        head = f"FortiADC-{model}" if model else "FortiADC"
        return " ".join(x for x in (head, f"v{ver}" if ver else "", build) if x)
    except Exception:  # noqa: BLE001
        return ""


# --------------------------------------------------------------------------- #
#  Discovery sweep (the ADC side of services/rediscovery — kept HERE so the    #
#  fortiadc/adc_menu imports stay inside an ADC module; the import direction   #
#  is enforced by tests/test_product_separation.py)                            #
# --------------------------------------------------------------------------- #

def discovery_plan() -> list[dict]:
    """Every enabled ``product='fortiadc'`` registry endpoint EXCEPT child
    tables (``…_child_…`` needs a ``pkey``; their deep contents are the VS
    Inspector's layer). Sections come from the ADC GUI menu; anything the menu
    doesn't surface lands in "Other". Must run in app context (the registry is
    DB-first) — the rediscovery worker thread only consumes the resolved plan."""
    from ..registry import loader
    from . import adc_menu

    reg = loader.load_adc_registry()
    section_of: dict[str, str] = {}
    try:
        for g in adc_menu.menu():
            for item in g.items:
                for t in item.tabs:
                    section_of.setdefault(t.logical, g.label)
    except Exception:  # noqa: BLE001 — the menu is cosmetic for the sweep
        pass
    plan: list[dict] = []
    for name, urn in sorted(reg.items()):
        if "_child_" in name or "_child_" in (urn or ""):
            continue
        plan.append({"name": name, "urn": urn,
                     "section": section_of.get(name, "Other")})
    return plan


def make_fetcher(appliance):
    """A ``fetch(plan_entry) -> rows`` closure over one authenticated FortiADC
    client, for the rediscovery worker (duck-typed appliance snapshot — only
    host/port/verify_ssl/username/password are read)."""
    from ..clients.fortiadc import FortiADCClient

    client = FortiADCClient(appliance, timeout=20.0)

    def _fetch(ep: dict) -> list:
        resp = client._api("GET", ep["urn"])
        err = client._device_error(resp)
        if err:
            raise RuntimeError(err)
        rows = client._payload(resp)
        if isinstance(rows, dict):
            rows = [rows]
        return rows if isinstance(rows, list) else []

    return _fetch


_VM_HINTS = ("KVM", "VM", "XEN", "HYPERV", "AWS", "AZURE", "GCP", "OPENSTACK")


def model_inventory(appliance) -> tuple[str | None, str | None, str | None]:
    """Best-effort ``(model, hw_type, firmware)`` off ``/api/platform/version``
    (live-verified 8.0.3). ``(None, None, None)`` on any failure."""
    try:
        from ..clients.fortiadc import FortiADCClient
        p = FortiADCClient(appliance, timeout=15.0).platform_version()
    except Exception:  # noqa: BLE001
        return None, None, None
    model = str(p.get("model") or "").strip()           # e.g. "KVM"
    ver = str(p.get("version") or "").replace("-", ".")  # "8-0-3" → "8.0.3"
    build = str(p.get("build") or "").strip()
    hw = "vm" if any(h in model.upper() for h in _VM_HINTS) \
        else ("hardware" if model else None)
    fw = " ".join(x for x in (ver, build) if x) or None
    return (f"FortiADC-{model}" if model else None), hw, fw


# --------------------------------------------------------------------------- #
#  Virtual Server Inspector — the ADC counterpart of the Policy Inspector      #
# --------------------------------------------------------------------------- #

def _vs_full(client, name: str) -> dict:
    """Composite read of one virtual server: VS + pool + members."""
    vs = client.get_object("load_balance_virtual_server", name)
    pool_name = str(vs.get("pool") or "").strip()
    pool: dict = {}
    members: list[dict] = []
    if pool_name:
        try:
            pool = client.get_object("load_balance_pool", pool_name)
        except Exception:  # noqa: BLE001 — a dangling ref never sinks the tree
            pool = {}
        rows, err = client.list_with_error(
            "load_balance_pool_child_pool_member", pkey=pool_name)
        if not err:
            members = [r for r in rows if isinstance(r, dict)]
    return {"vs": vs, "pool": pool, "members": members}


def build_vs_node(full: dict) -> dict:
    """Turn a ``_vs_full`` composite into the ``{label, children}`` tree the
    shared inspector renderer draws."""
    vs = full.get("vs") or {}
    name = vs.get("mkey") or "(unnamed)"
    addr = str(vs.get("address") or "").strip()
    port = str(vs.get("port") or "").strip()
    root: dict[str, Any] = {
        "label": f"Virtual Server: {name}"
        + _attrs(vs, ("status", "availability", "interface", "profile",
                      "method", "packet-fwd-method")),
        "children": [],
    }
    if addr:
        root["children"].append({
            "label": f"Listener: {addr}:{port or '-'}"
            + _attrs(vs, ("addr-type", "public-ip")),
            "children": [],
        })
    pool = full.get("pool") or {}
    members = full.get("members") or []
    if pool or vs.get("pool"):
        pool_node = {
            "label": f"Real Server Pool: {vs.get('pool') or pool.get('mkey') or '-'}"
            + _attrs(pool, ("pool_type", "health-check", "healthcheck",
                            "rs-profile", "comments")),
            "children": [],
        }
        for m in members:
            ip = str(m.get("address") or m.get("FQDN") or "-").strip()
            mport = str(m.get("port") or "").strip()
            label = f"Member: {ip}:{mport}" if mport else f"Member: {ip}"
            pool_node["children"].append({
                "label": label + _attrs(m, ("status", "weight", "availability",
                                            "backup", "cookie")),
                "children": [],
            })
        root["children"].append(pool_node)
    # profile chain worth a leaf each when bound
    for key, lbl in (("profile", "Profile"),
                     ("client-ssl-profile", "Client SSL Profile"),
                     ("waf-profile", "WAF Profile"),
                     ("http2https", "HTTP→HTTPS redirect"),
                     ("content-routing", "Content Routing"),
                     ("persistence", "Persistence")):
        v = str(vs.get(key) or "").strip()
        if v and v not in ("disable", "0"):
            root["children"].append({"label": f"{lbl}: {v}", "children": []})
    return root


def inspect_vs(client, name: str) -> dict:
    """Composite read + rendered tree for one virtual server."""
    full = _vs_full(client, name)
    return {"name": name, "full": full, "tree": render_tree(build_vs_node(full))}


def inspect_all(client) -> dict:
    """Inspect every virtual server on the appliance — same result shape as
    :func:`app.services.inspector.inspect_all` so the template is shared."""
    rows, err = client.list_with_error("load_balance_virtual_server")
    if err:
        raise RuntimeError(f"virtual-server list failed: {err}")
    vss: list[dict] = []
    errors: list[dict] = []
    for r in rows:
        name = str(r.get("mkey") or "").strip()
        if not name:
            continue
        try:
            vss.append(inspect_vs(client, name))
        except Exception as exc:  # noqa: BLE001 — one VS never sinks the page
            errors.append({"name": name, "error": f"{type(exc).__name__}: {exc}"})
    return {"policies": vss, "errors": errors, "count": len(vss)}


# --------------------------------------------------------------------------- #
#  Published-service resolution (upgrade-prep probe baseline)                  #
# --------------------------------------------------------------------------- #

_TLS_HINTS = ("SSL", "HTTPS", "TLS")


def resolve_targets(client) -> list[ServiceTarget]:
    """One :class:`ServiceTarget` per enabled virtual server: URL from the VS
    address + port (scheme https when the profile/client-ssl hints TLS or the
    port is 443), back-end list from the pool members."""
    rows, err = client.list_with_error("load_balance_virtual_server")
    if err:
        raise RuntimeError(f"virtual-server list failed: {err}")
    targets: list[ServiceTarget] = []
    for vs in rows:
        name = str(vs.get("mkey") or "").strip()
        if not name:
            continue
        addr = str(vs.get("address") or "").strip()
        port_s = str(vs.get("port") or "").strip().split()[0] if vs.get("port") else ""
        port = int(port_s) if port_s.isdigit() else None
        profile = str(vs.get("profile") or "").upper()
        tls = bool(str(vs.get("client-ssl-profile") or "").strip()) \
            or any(h in profile for h in _TLS_HINTS) or port == 443
        scheme = "https" if tls else "http"
        backends: list[str] = []
        pool_name = str(vs.get("pool") or "").strip()
        if pool_name:
            mrows, merr = client.list_with_error(
                "load_balance_pool_child_pool_member", pkey=pool_name)
            if not merr:
                for m in mrows:
                    ip = str(m.get("address") or m.get("FQDN") or "").strip()
                    mp = str(m.get("port") or "").strip().split()[0] if m.get("port") else ""
                    if ip:
                        backends.append(f"{ip}:{mp}" if mp else ip)
        url, note = "", ""
        if addr and addr != "0.0.0.0" and port:
            default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
            url = f"{scheme}://{addr}" + ("" if default else f":{port}")
        else:
            note = "no address/port resolved"
        targets.append(ServiceTarget(
            policy=name, scheme=scheme, host=addr, port=port, url=url,
            vserver=name, pool=pool_name, backends=backends, note=note,
        ))
    return targets


__all__ = ["TROUBLESHOOT_ADC", "HEALTH_BATTERY_ADC", "health_text",
           "firmware_string", "inspect_vs", "inspect_all", "build_vs_node",
           "resolve_targets", "discovery_plan", "make_fetcher",
           "model_inventory"]
