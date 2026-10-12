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


def capture_health(appliance, *, timeout: float = 25.0) -> dict[str, str]:
    """Run the ADC read-only battery -> ``{command: output}`` (same shape as
    ``ssh_ops.capture_health``, which is the FortiWeb battery)."""
    from .ssh_ops import FortiWebReadonlySSH

    with FortiWebReadonlySSH(appliance, timeout=timeout) as ssh:
        return ssh.run_battery(HEALTH_BATTERY_ADC)


def health_text(appliance) -> str:
    """The ADC diagnostic battery rendered as one labelled text blob."""
    out = capture_health(appliance)
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
        # The sweep GETs every row, and on FortiADC some GETs reboot or reset
        # the box. The registry is editable, so this is checked here, not
        # assumed of the seed.
        if side_effect_path(urn):
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


def make_probe(appliance):
    """A ``probe(plan_entry) -> (rows, verdict, detail)`` closure — the ADC half
    of the rediscovery ledger.

    Same three verdicts as the FortiWeb probe, with the ADC's own shapes:

    * ``absent`` — **HTTP 404** with the plain-text body ``404 page not found``.
      Verified live against fortiadc02 (2026-08-13): a real object answers 200,
      a URN the appliance does not implement answers 404 and is NOT a JSON
      envelope, so ``_device_error`` alone cannot tell it from a transport
      failure.
    * ``error``  — anything else, including the negative-integer ``payload``
      the ADC uses to signal a refusal.
    * ``ok``     — the device answered; an empty list means an empty collection.

    ``make_fetcher`` is kept for callers that only want rows.
    """
    import httpx

    from ..clients.base import DeviceAuthError, response_summary
    from ..clients.fortiadc import FortiADCClient

    client = FortiADCClient(appliance, timeout=20.0)

    def _refused(resp) -> DeviceAuthError:
        detail = response_summary(resp)
        return DeviceAuthError(
            f"HTTP {resp.status_code}: the appliance rejected the credentials"
            + (f" ({detail})" if detail else "")
            + " — check the username and password on the appliance record and"
              " that the admin account is not locked out")

    def _login():
        # A refused login raised on EVERY endpoint before, i.e. one failed
        # admin login per endpoint. DeviceAuthError is the one error the
        # sweep stops on.
        try:
            client.login()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                raise _refused(exc.response) from None
            raise

    def _probe(ep: dict):
        # ``params`` carries the ``pkey`` of a child-table read (the depth
        # pass, services.adc_vstree); a plan entry of the sweep has none.
        params = ep.get("params") or None
        if not client._token:
            _login()
        resp = client._api("GET", ep["urn"], params=params)
        if resp.status_code == 401:
            # One fresh login decides: an expired token is renewed and the
            # read retried once; refused credentials stop the sweep.
            client._token = None
            _login()
            resp = client._api("GET", ep["urn"], params=params)
            if resp.status_code == 401:
                raise _refused(resp)
        if resp.status_code == 404:
            return [], "absent", "HTTP 404 (path not served)"
        err = client._device_error(resp)
        if err:
            return [], "error", str(err)[:200]
        rows = client._payload(resp)
        if isinstance(rows, dict):
            rows = [rows]
        return (rows if isinstance(rows, list) else []), "ok", ""

    return _probe


_VM_HINTS = ("KVM", "VM", "XEN", "HYPERV", "AWS", "AZURE", "GCP", "OPENSTACK")


def model_inventory(appliance) -> tuple[str | None, str | None, str | None]:
    """Best-effort ``(model, hw_type, firmware)`` off ``/api/platform/version``
    (live-verified 8.0.3). ``(None, None, None)`` on any failure."""
    try:
        from ..clients.fortiadc import FortiADCClient
        p = FortiADCClient(appliance, timeout=15.0).platform_version()
    except Exception:  # noqa: BLE001
        return None, None, None
    return model_inventory_from(p)


def platform_payload(appliance) -> dict:
    """The raw ``/api/platform/version`` payload, letting the device error
    PROPAGATE (unlike :func:`model_inventory`, which swallows it into None).

    Exists so a fleet-wide caller (:mod:`app.services.firmware_probe`) can read
    an ADC without importing :mod:`app.clients.fortiadc` itself. Constructing
    the ADC client is ADC business and belongs in an ADC module -- that is the
    contract ``tests/test_product_separation.py`` locks, and the alternative
    (whitelisting the generic caller as a platform module) would widen the one
    list that keeps the two products apart."""
    from ..clients.fortiadc import FortiADCClient

    return FortiADCClient(appliance, timeout=15.0).platform_version()


def model_inventory_from(p: dict) -> tuple[str | None, str | None, str | None]:
    """The PURE half of :func:`model_inventory`: an already-fetched
    ``/api/platform/version`` payload -> ``(model, hw_type, firmware)``.

    Split out on 2026-08-13 so :mod:`app.services.firmware_probe` can surface
    the device error (``model_inventory`` swallows every exception into
    ``None``, which a live-check endpoint must not do) while still producing
    the EXACT same firmware string this function has always produced. Two
    formatters for one column is how an estate ends up with two spellings of
    the same version and a dedupe key that no longer matches."""
    if not isinstance(p, dict):
        return None, None, None
    model = str(p.get("model") or "").strip()           # e.g. "KVM"
    ver = str(p.get("version") or "").replace("-", ".")  # "8-0-3" → "8.0.3"
    build = str(p.get("build") or "").strip()
    hw = "vm" if any(h in model.upper() for h in _VM_HINTS) \
        else ("hardware" if model else None)
    fw = " ".join(x for x in (ver, build) if x) or None
    return (f"FortiADC-{model}" if model else None), hw, fw


# --------------------------------------------------------------------------- #
#  REST door of the measured GUI pages (services.gui_products)                 #
# --------------------------------------------------------------------------- #

def rest_call(appliance, method: str, path: str, *, params: dict | None = None,
              body=None, timeout: float = 20.0) -> tuple:
    """``(payload, error)`` of ONE call on an already-resolved FortiADC path
    (``/api/<entity>``), for the measured GUI pages' adapter
    (``gui_products.FortiADCAdapter``).

    The payload is what the device put in its ``{"payload": ...}`` envelope,
    unflattened: a list for a collection, an object for a settings singleton
    (``system_global``), a number for a write. A device refusal (HTTP >= 400,
    a negative errcode payload) and a transport failure come back as
    ``error`` -- never raised, never an empty list. Kept here so the
    fleet-wide GUI engine never constructs the ADC client itself (the import
    direction ``tests/test_product_separation.py`` locks)."""
    from ..clients.fortiadc import FortiADCClient

    try:
        client = FortiADCClient(appliance, timeout=timeout)
        kw = {"params": params or None}
        if body is not None:
            kw["json"] = body
        resp = client._api(method.upper(), path, **kw)
    except Exception as exc:  # noqa: BLE001 -- a dead device is an answer
        return None, f"{type(exc).__name__}: {exc}"
    err = FortiADCClient._device_error(resp)
    if err:
        return None, err
    try:
        return FortiADCClient._payload(resp), None
    except Exception as exc:  # noqa: BLE001
        return None, f"unparseable response body: {type(exc).__name__}"


# --------------------------------------------------------------------------- #
#  Virtual Server Inspector — the ADC counterpart of the Policy Inspector      #
# --------------------------------------------------------------------------- #

def inspect_vs(client, name: str) -> dict:
    """Composite read + rendered tree for one virtual server (every reference
    followed — :mod:`app.services.adc_vstree`)."""
    from . import adc_vstree
    got = adc_vstree.trees(adc_vstree.index_live(client, only=name), only=name)
    if not got:
        raise RuntimeError(f"virtual server {name!r} not found on the device")
    return got[0]


def list_virtual_servers(client):
    """``(rows, error)`` — the appliance's own list of virtual servers.

    The ONE place that names the endpoint. Scout's object picker, its live
    existence source and its object count all read through here, so the three
    can never drift into three different answers to "what does this device
    serve". ``error`` is passed through untouched: a refused read must stay
    distinguishable from a device with no virtual servers.
    """
    return client.list_with_error("load_balance_virtual_server")


def inspect_all(client) -> dict:
    """Inspect every virtual server on the appliance — same result shape as
    :func:`app.services.inspector.inspect_all` so the template is shared.
    One index read serves every tree (each VS used to re-read its pool)."""
    from . import adc_vstree
    rows, err = list_virtual_servers(client)
    if err:
        raise RuntimeError(f"virtual-server list failed: {err}")
    index = adc_vstree.index_live(client)
    vss = adc_vstree.trees(index)
    return {"policies": vss, "errors": index.get("errors") or [],
            "count": len(vss)}


# --------------------------------------------------------------------------- #
#  Firmware and boot partitions — the ADC side of services/upgrade             #
# --------------------------------------------------------------------------- #
#
# Every path below was read off the FortiADC 7.6.7 GUI's own bundle (System >
# Settings > Firmware and Backup & Restore, crawl of fortiadc10 on 2026-10-10)
# and the reads were run against fortiadc10 on 2026-10-11:
#
# * ``GET  /api/system_global/boot_partition`` -> ``[{partno, active, partid,
#   timestamp}]``; an empty ``partid`` is an empty partition (fortiadc10:
#   partition 2 is empty).
# * Upload & install = ``GET /api/system_global/clear_tmp_space`` then a
#   multipart ``POST /api/upload/image`` (form field ``hasync`` 0/1 = "HA
#   Cluster Upgrade"; the file field name is free). ``payload == 0`` means
#   accepted: the box installs into the inactive partition and reboots.
# * ``GET /api/system_global/swap_boot_partition`` reboots into the inactive
#   partition. A GET.
# * ``/api/platform/info`` carries ``isSystemAdmin`` / ``isSystemWritable``:
#   the GUI disables its firmware controls unless both hold.

ADC_BOOT_PARTITION = "/api/system_global/boot_partition"
ADC_SWAP_PARTITION = "/api/system_global/swap_boot_partition"
ADC_CLEAR_TMP = "/api/system_global/clear_tmp_space"
ADC_UPLOAD_IMAGE = "/api/upload/image"
ADC_PLATFORM_INFO = "/api/platform/info"

#: GETs that CHANGE the box. FortiADC drives reboot, shutdown, factory reset and
#: the partition swap through plain GETs (``entity:"platform", _method:"reboot"``
#: and friends in the 7.6.7 GUI bundle), so "it is only a GET" proves nothing
#: here. Every generic REST door (the API console, a scheduled custom call)
#: refuses these; each one has its own page with its own gates, or none at all.
ADC_SIDE_EFFECT_PATHS: tuple[str, ...] = (
    "platform/reboot", "platform/shutdown", "platform/reset",
    "system_global/swap_boot_partition", "system_global/clear_tmp_space",
    "system_global/restore_config_local", "system_global/restore_config_disk",
    "system_global/delete_config_disk", "upload/image", "upload/check_config",
    "upload/vmlicense",
)


def side_effect_path(path: str) -> str:
    """The entry of :data:`ADC_SIDE_EFFECT_PATHS` that ``path`` reaches, or
    ``""``. Matched on the path alone (query string dropped, case folded,
    ``/api/`` prefix and doubled slashes ignored) so ``/API//platform/Reboot?x``
    cannot slip past."""
    p = (path or "").split("?", 1)[0].split("#", 1)[0].strip().lower()
    p = "/".join(seg for seg in p.split("/") if seg)
    if p.startswith("api/"):
        p = p[4:]
    for entry in ADC_SIDE_EFFECT_PATHS:
        if p == entry or p.startswith(entry + "/"):
            return entry
    return ""


def is_adc_client(client) -> bool:
    """True for a FortiADC REST client. Lets a caller outside the ADC modules
    branch on the product without importing the ADC client itself."""
    from ..clients.fortiadc import FortiADCClient

    return isinstance(client, FortiADCClient)


def firmware_line(client) -> str:
    """``"7.6.7 build0676,260522"`` — the same spelling
    :func:`model_inventory_from` writes into ``Appliance.firmware``, so a flash
    compares before/after in one format. ``""`` on failure."""
    try:
        return model_inventory_from(client.platform_version())[2] or ""
    except Exception:  # noqa: BLE001
        return ""


def maintenance_permission(client) -> bool | None:
    """May this account flash firmware? The GUI's own test: ``isSystemAdmin``
    and ``isSystemWritable`` on ``/api/platform/info``. ``None`` = unknown."""
    try:
        resp = client._api("GET", ADC_PLATFORM_INFO, params={"vdom": "root"})
        if client._device_error(resp):
            return None
        p = client._payload(resp)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(p, dict) or "isSystemWritable" not in p:
        return None
    return bool(p.get("isSystemWritable")) and bool(p.get("isSystemAdmin", True))


def boot_partitions(client) -> dict:
    """The partition table in the shape ``upgrade.read_partitions`` returns for
    FortiWeb: ``{partitions:[{partition, active, version, lastUpgrade}], active,
    alternate}``. ``alternate`` is the inactive partition only when it HOLDS a
    build — an empty one is never something to boot."""
    resp = client._api("GET", ADC_BOOT_PARTITION)
    err = client._device_error(resp)
    if err:
        raise RuntimeError(f"boot partition read failed: {err}")
    raw = client._payload(resp)
    parts = []
    for row in raw if isinstance(raw, list) else []:
        if not isinstance(row, dict):
            continue
        parts.append({"partition": row.get("partno"),
                      "active": 1 if str(row.get("active")) in ("1", "true", "True") else 0,
                      "version": str(row.get("partid") or "").strip(),
                      "lastUpgrade": str(row.get("timestamp") or "").strip()})
    active = next((p for p in parts if p["active"]), None)
    alternate = next((p for p in parts if not p["active"] and p["version"]), None)
    return {"partitions": parts, "active": active, "alternate": alternate,
            "needs_clean_install": False, "last_backup": None}


def upload_image(client, filename: str, image_bytes: bytes, *,
                 ha_sync: bool = False, timeout: float = 1800.0) -> tuple:
    """Upload + install one image the way the GUI does it. Returns
    ``(http_status, payload, steps)``; ``payload == 0`` = accepted. The tmp
    clean-up is best-effort, as in the GUI (its result is not checked there)."""
    steps = []
    try:
        r = client._api("GET", ADC_CLEAR_TMP)
        steps.append({"sent": "clear_tmp_space", "status": r.status_code})
    except Exception as exc:  # noqa: BLE001
        steps.append({"sent": "clear_tmp_space", "error": f"{type(exc).__name__}: {exc}"[:160]})
    if not client._token:
        client.login()
    resp = client._request(
        "POST", ADC_UPLOAD_IMAGE,
        headers={"Authorization": f"Bearer {client._token}"},
        cookies=client._cookies,
        files={"upload": (filename, image_bytes, "application/octet-stream")},
        data={"hasync": "1" if ha_sync else "0"}, timeout=timeout)
    try:
        payload = resp.json().get("payload")
    except Exception:  # noqa: BLE001
        payload = None
    steps.append({"sent": "upload/image", "status": resp.status_code, "payload": payload})
    return resp.status_code, payload, steps


def error_text(client, code) -> str:
    """The box's own wording for a negative payload, off ``/api/platform/errMsg``
    (the table the GUI loads at start: 1276 entries on fortiadc10, e.g. ``-28``
    = "File is not an update file."). ``""`` when unknown or unreadable."""
    try:
        resp = client._api("GET", "/api/platform/errMsg", params={"vdom": "root"})
        table = client._payload(resp)
        return str((table or {}).get(str(code)) or "").strip() if isinstance(table, dict) else ""
    except Exception:  # noqa: BLE001
        return ""


def swap_boot_partition(client) -> tuple:
    """Reboot into the inactive partition. ``(http_status, payload)``; the
    caller must have checked that the partition holds a build."""
    resp = client._api("GET", ADC_SWAP_PARTITION)
    try:
        payload = resp.json().get("payload")
    except Exception:  # noqa: BLE001
        payload = None
    return resp.status_code, payload


# --------------------------------------------------------------------------- #
#  Published-service resolution (upgrade-prep probe baseline)                  #
# --------------------------------------------------------------------------- #

_TLS_HINTS = ("SSL", "HTTPS", "TLS")


def resolve_targets(client) -> list[ServiceTarget]:
    """One :class:`ServiceTarget` per enabled virtual server: URL from the VS
    address + port (scheme https when the profile/client-ssl hints TLS or the
    port is 443), back-end list from the pool members."""
    rows, err = list_virtual_servers(client)
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


__all__ = ["TROUBLESHOOT_ADC", "HEALTH_BATTERY_ADC", "capture_health", "health_text",
           "firmware_string", "inspect_vs", "inspect_all", "build_vs_node",
           "resolve_targets", "discovery_plan", "make_fetcher",
           "model_inventory", "boot_partitions", "upload_image",
           "swap_boot_partition", "maintenance_permission", "firmware_line",
           "is_adc_client", "side_effect_path", "ADC_SIDE_EFFECT_PATHS"]
