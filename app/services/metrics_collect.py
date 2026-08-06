"""Fleet metrics collection — scrape targets → VictoriaMetrics.

The unit of configuration is (appliance, collector), never (appliance,
policy): ``policy_status`` returns EVERY policy's counters in one 14 ms call,
so per-policy probes multiply device round-trips by N for data that is free
in aggregate. Measured 2026-08-05: the per-series design needed ~56 min of
device I/O per 3-minute window at fleet scale; this one needs seconds.

Cost tiers (defaults; every target's interval is operator-editable):

* cheap-and-complete — one call covers the device: ``box``, ``policies``,
  ``interfaces``. Default every 3 min.
* expensive-per-policy — one call PER policy: ``traffic`` (60 s of 1 Hz
  samples), ``transactions``. Default 15/60 min, and only the top-N policies
  by live connection rate (plus the device-total pseudo-policy for traffic) —
  full fidelity where the traffic is, bounded cost where it is not.

Rules carried over from the probe subsystem's scars:

* ``maintenance=True`` suppresses SCHEDULED collection entirely (the deep
  monitors forgot this once and probed recycled IPs every 3 minutes).
* A sweep that ran is ``ok`` even when devices errored — per-target status
  carries the failures; the action must not stick permanently red.
* Absence of data is never health: a failed collector writes
  ``satom_scrape_up 0``, it does not silently write nothing.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from . import vm_store

# Tolerance subtracted from the interval when deciding "due": the sweep runs
# on the scheduler tick, so a probe interval that misses the tick by seconds
# would silently double its effective cadence (the 5-under-3 lesson).
DUE_SLACK_S = 45

MAX_WORKERS = 8

COLLECTORS: dict = {
    "box": {
        "label": "Box resources (CPU, memory, sessions)",
        "products": ("fortiweb", "fortiadc", "fortiauthenticator"),
        "interval": 3, "params": {},
    },
    "capacity": {
        "label": "Licence headroom & FortiToken pools (one call, all counters)",
        "products": ("fortiauthenticator",),
        "interval": 3, "params": {},
    },
    "policies": {
        "label": "Server policies — sessions / conn rate / RTT (one call, all policies)",
        "products": ("fortiweb",),
        "interval": 3, "params": {},
    },
    "interfaces": {
        "label": "Interfaces — link state + byte counters",
        "products": ("fortiweb", "fortiadc"),
        "interval": 3, "params": {},
    },
    "traffic": {
        "label": "Throughput — device total + top-N policies",
        "products": ("fortiweb",),
        "interval": 15, "params": {"top_n": 10},
    },
    "faz": {
        "label": "Log collector — volume, storage, alerts, incidents, devices, tasks",
        "products": ("fortianalyzer",),
        "interval": 15, "params": {},
    },
    "identity": {
        "label": "Identity inventory — accounts, groups, tokens, certs, clients",
        "products": ("fortiauthenticator",),
        "interval": 15, "params": {},
    },
    "vservers": {
        "label": "Virtual servers — sessions / RTT / pool health (one call, all VS)",
        "products": ("fortiadc",),
        "interval": 3, "params": {"vdom": "root"},
    },
    "transactions": {
        "label": "HTTP transactions — top-N policies",
        "products": ("fortiweb",),
        "interval": 60, "params": {"top_n": 10, "hours": 1},
    },
}


# ── provisioning ─────────────────────────────────────────────────────────────

def collectors_for(kind: str) -> list:
    """Collector keys this product supports (empty for a product with none)."""
    return [k for k, spec in COLLECTORS.items() if kind in spec["products"]]


def provisionable(appliance) -> bool:
    """Whether this device should own scrape targets at all.

    The rule lives HERE, not in each caller: targets are created from three
    different appliance-creation paths plus the sweep, and a rule copied four
    times is a rule that drifts. A parked device (``maintenance``) and a
    retired row (host neutralised to ``*.invalid``) get none — same guard the
    sweep applies before touching a device.
    """
    if appliance is None or appliance.maintenance:
        return False
    host = (appliance.host or "").strip()
    return bool(host) and not host.endswith(".invalid")


def ensure_targets(appliance) -> int:
    """Create missing scrape targets for one appliance (INSERT-only: operator
    edits — intervals, enabled, params — always win). Returns rows created.

    Safe to call from any path that creates or edits an appliance: it is
    idempotent and self-guarding, so a new device is collectable the moment
    it is saved instead of on the next sweep.
    """
    from ..models import db
    from ..models_metrics import ScrapeTarget

    if not provisionable(appliance):
        return 0
    existing = {t.collector for t in
                ScrapeTarget.query.filter_by(appliance_id=appliance.id).all()}
    created = 0
    for key, spec in COLLECTORS.items():
        if appliance.kind not in spec["products"] or key in existing:
            continue
        t = ScrapeTarget(appliance_id=appliance.id, collector=key,
                         interval_min=spec["interval"])
        t.params = dict(spec["params"])
        db.session.add(t)
        created += 1
    if created:
        db.session.commit()
    return created


def coverage_gaps(appliances) -> list:
    """Devices that produce no scrape targets, each with the reason why.

    Absence is not health. The collection page lists ``ScrapeTarget`` rows, so
    a device that yields none — a FortiAnalyzer (no collectors exist for that
    product yet), a parked device, a retired row — would appear nowhere and
    read as covered. Naming them is the difference between "nothing to collect"
    and "nothing is being collected".
    """
    from ..models_metrics import ScrapeTarget

    counts: dict = {}
    for t in ScrapeTarget.query.all():
        counts[t.appliance_id] = counts.get(t.appliance_id, 0) + 1

    gaps = []
    for a in appliances:
        if counts.get(a.id):
            continue
        if not collectors_for(a.kind):
            reason = "no collectors exist for %s yet" % a.kind
        elif a.maintenance:
            reason = "device is in maintenance"
        elif (a.host or "").strip().endswith(".invalid"):
            reason = "retired — host neutralised"
        elif not (a.host or "").strip():
            reason = "no host configured"
        else:
            reason = "not provisioned yet — runs on the next sweep"
        gaps.append({"id": a.id, "name": a.name, "kind": a.kind,
                     "reason": reason})
    return gaps


def due_targets(now: datetime | None = None) -> list:
    """Enabled targets whose interval has elapsed, on live (non-maintenance,
    non-retired) appliances."""
    from ..models import Appliance
    from ..models_metrics import ScrapeTarget

    now = now or datetime.utcnow()
    rows = (ScrapeTarget.query.join(Appliance)
            .filter(ScrapeTarget.enabled.is_(True),
                    Appliance.maintenance.is_(False))
            .all())
    due = []
    for t in rows:
        host = (t.appliance.host or "") if t.appliance else ""
        if host.endswith(".invalid"):
            continue   # neutralised/retired device — structurally unreachable
        if t.last_run_at is None:
            due.append(t)
            continue
        elapsed = (now - t.last_run_at).total_seconds()
        if elapsed >= t.interval_min * 60 - DUE_SLACK_S:
            due.append(t)
    return due


# ── collectors ───────────────────────────────────────────────────────────────

def _num(v):
    try:
        return float(str(v).rstrip("%"))
    except (TypeError, ValueError):
        return None


def _labels(appliance, **extra) -> dict:
    d = {"device": appliance.name, "kind": appliance.kind}
    d.update(extra)
    return d


def _collect_box(appliance, params, ts) -> list:
    if appliance.kind == "fortiweb":
        from ..clients.fortiweb import FortiWebClient
        client = FortiWebClient(appliance, timeout=10.0)
        res, err = client.system_resource()
        if err:
            raise RuntimeError(str(err)[:150])
        row = res if isinstance(res, dict) else (res[0] if res else {})
        L = _labels(appliance)
        return [
            vm_store.line("satom_box_cpu_pct", L, _num(row.get("cpu")), ts),
            vm_store.line("satom_box_mem_pct", L, _num(row.get("mem")), ts),
            vm_store.line("satom_box_disk_pct", L, _num(row.get("diskUsage")), ts),
            vm_store.line("satom_box_logdisk_pct", L, _num(row.get("logDisk")), ts),
            vm_store.line("satom_box_sessions", L, _num(row.get("sessionCount")), ts),
            vm_store.line("satom_box_conn_per_sec", L, _num(row.get("connCntPerSec")), ts),
        ]
    if appliance.kind == "fortiauthenticator":
        # REST, not CLI. `get system performance` and `diagnose system top` are
        # both "No such command." on this product (VERIFIED on fac01 v8.0.3) —
        # a successful SSH round trip carrying no reading, which the FortiADC
        # branch below would have parsed into two empty series.
        from ..clients.fortiauthenticator import FortiAuthenticatorClient
        from . import deep_monitor as dm
        info = FortiAuthenticatorClient(appliance, timeout=10.0).sys_status()
        f = dm.parse_fac_systeminfo(info)
        L = _labels(appliance)
        return [
            vm_store.line("satom_box_cpu_pct", L, f.get("cpu_busy"), ts),
            vm_store.line("satom_box_mem_pct", L, f.get("mem_used_pct"), ts),
            vm_store.line("satom_box_disk_pct", L, f.get("disk_used_pct"), ts),
            vm_store.line("satom_box_mem_used_bytes", L,
                          f.get("mem_used_bytes"), ts),
            vm_store.line("satom_box_mem_total_bytes", L,
                          f.get("mem_total_bytes"), ts),
            vm_store.line("satom_box_disk_used_bytes", L,
                          f.get("disk_used_bytes"), ts),
            vm_store.line("satom_box_disk_total_bytes", L,
                          f.get("disk_total_bytes"), ts),
        ]
    # FortiADC: `get system performance` over read-only SSH — same parser the
    # deep monitors trust (REST has no equivalent on this product).
    from . import deep_monitor as dm
    from . import ssh_ops
    raw = ssh_ops.run_command(appliance, dm.PERF_CMD, timeout=12.0)
    perf = dm.parse_performance(raw)
    L = _labels(appliance)
    return [
        vm_store.line("satom_box_cpu_pct", L, perf.get("cpu_used"), ts),
        vm_store.line("satom_box_mem_pct", L, perf.get("mem_used"), ts),
    ]


def _collect_capacity(appliance, params, ts) -> list:
    """FortiAuthenticator licence + FortiToken series, from ONE systeminfo call.

    This is the identity product's equivalent of FortiWeb's per-policy traffic:
    an authenticator does not run out of bandwidth, it runs out of ENTITLEMENT.
    fac01 ships ``users_usage_detail {max: 5}`` unlicensed, and the 6th user is
    simply refused — a cliff no CPU or memory series would ever show.

    A counter with no ceiling emits ``used`` and ``total`` but **no percentage**
    (``vm_store.line`` drops a ``None``), so a chart of "percent consumed" never
    shows a fabricated 0 % for a feature that has no limit. The label carries
    the counter name, so one expression covers the whole fleet.
    """
    from ..clients.fortiauthenticator import FortiAuthenticatorClient
    from . import deep_monitor as dm

    info = FortiAuthenticatorClient(appliance, timeout=10.0).sys_status()
    f = dm.parse_fac_systeminfo(info)
    out = []
    for name, block in (f.get("capacity") or {}).items():
        if not block:
            continue
        L = _labels(appliance, resource=name)
        out.append(vm_store.line("satom_fac_licence_used", L, block["used"], ts))
        out.append(vm_store.line("satom_fac_licence_total", L, block["total"], ts))
        out.append(vm_store.line("satom_fac_licence_pct", L, block["pct"], ts))
    for name, block in (f.get("tokens") or {}).items():
        if not block:
            continue
        L = _labels(appliance, pool=name)
        out.append(vm_store.line("satom_fac_token_used", L, block["used"], ts))
        out.append(vm_store.line("satom_fac_token_total", L, block["total"], ts))
        out.append(vm_store.line("satom_fac_token_pct", L, block["pct"], ts))
    # HA peer presence as a 0/1 series. FortiAuthenticator exposes no HA
    # resource at all (58 resources censused); ``systeminfo.ha_sn`` is the only
    # signal it gives, and a config harvest cannot carry it because that object
    # is excluded from the SoT for churn.
    out.append(vm_store.line("satom_fac_ha_peer", _labels(appliance),
                             1 if f.get("ha_peer_sn") else 0, ts))
    return out


def _collect_policies(appliance, params, ts) -> list:
    from ..clients.fortiweb import FortiWebClient
    client = FortiWebClient(appliance, timeout=10.0)
    rows, err = client.policy_status()
    if err:
        raise RuntimeError(str(err)[:150])
    lines = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        name = row.get("name") or row.get("policy_name")
        if not name:
            continue
        L = _labels(appliance, policy=name)
        up = 1 if str(row.get("status", "")).lower() in ("enable", "up", "1", "running") else 0
        lines += [
            vm_store.line("satom_policy_up", L, up, ts),
            vm_store.line("satom_policy_sessions", L, _num(row.get("sessionCount")), ts),
            vm_store.line("satom_policy_conn_per_sec", L, _num(row.get("connCntPerSec")), ts),
            vm_store.line("satom_policy_client_rtt_ms", L, _num(row.get("client_rtt")), ts),
            vm_store.line("satom_policy_server_rtt_ms", L, _num(row.get("server_rtt")), ts),
            vm_store.line("satom_policy_app_response_ms", L, _num(row.get("app_response_time")), ts),
        ]
    lines.append(vm_store.line("satom_policy_count", _labels(appliance),
                               len(rows or []), ts))
    return lines


def _collect_interfaces(appliance, params, ts) -> list:
    if appliance.kind == "fortiadc":
        # Censused out of the GUI bundle and verified live on 8.0.3: FortiADC
        # answers interface runtime at ``system_interface/interface_info``.
        # Dispatch by PRODUCT rather than assuming one shape — the FortiWeb
        # branch below would raise on this device, which reads as a broken
        # device rather than a collector pointed at the wrong endpoint.
        from ..clients.fortiadc import FortiADCClient
        adc = FortiADCClient(appliance, timeout=10.0)
        adc.login()
        rows = adc.interface_info(vdom=str(params.get("vdom") or "root"))
    else:
        from ..clients.fortiweb import FortiWebClient
        client = FortiWebClient(appliance, timeout=10.0)
        res, err = client.system_operation()
        if err:
            raise RuntimeError(str(err)[:150])
        # Live shape (verified on fortiweb08 7.6.8): a dict whose "network" key
        # holds the interface list; older builds returned a bare list.
        rows = res if isinstance(res, list) else (res or {}).get("network") or []
    lines = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("name") or row.get("interface")
        if not name:
            continue
        L = _labels(appliance, iface=name)
        link_up = 1 if str(row.get("link", "")).lower() in ("up", "1", "true") else 0
        lines.append(vm_store.line("satom_iface_up", L, link_up, ts))
        # Cumulative counters — rate() in MetricsQL turns them into bandwidth.
        for metric, key in (("satom_iface_rx_bytes_total", "rx_bytes"),
                            ("satom_iface_tx_bytes_total", "tx_bytes")):
            val = _num(row.get(key))
            if val is not None:
                lines.append(vm_store.line(metric, L, val, ts))
    return lines


def _top_policies(client, n: int) -> list:
    rows, err = client.policy_status()
    if err:
        raise RuntimeError(str(err)[:150])
    scored = []
    for row in rows or []:
        if isinstance(row, dict) and (row.get("name") or row.get("policy_name")):
            scored.append((_num(row.get("connCntPerSec")) or 0.0,
                           row.get("name") or row.get("policy_name")))
    scored.sort(reverse=True)
    return [name for _score, name in scored[:max(1, n)]]


def _tp_values(res) -> list:
    """policy_traffic returns a bare list (no cache) or a dict with
    ``throughput``; values are BYTES/s as strings."""
    vals = res.get("throughput") if isinstance(res, dict) else res
    out = []
    for v in vals or []:
        n = _num(v)
        if n is not None:
            out.append(n)
    return out


def _collect_traffic(appliance, params, ts) -> list:
    from ..clients.fortiweb import FortiWebClient
    client = FortiWebClient(appliance, timeout=15.0)
    lines = []
    # Device total first: the aggregate pseudo-policy — one call, whole box.
    res, err = client.policy_traffic("Total HTTP Throughput")
    if not err:
        vals = _tp_values(res)
        if vals:
            L = _labels(appliance)
            lines.append(vm_store.line("satom_total_throughput_bps", L,
                                       sum(vals) / len(vals) * 8, ts))
            lines.append(vm_store.line("satom_total_throughput_peak_bps", L,
                                       max(vals) * 8, ts))
    for name in _top_policies(client, int(params.get("top_n") or 10)):
        res, err = client.policy_traffic(name)
        if err:
            continue
        vals = _tp_values(res)
        if not vals:
            continue
        L = _labels(appliance, policy=name)
        lines.append(vm_store.line("satom_policy_throughput_bps", L,
                                   sum(vals) / len(vals) * 8, ts))
        lines.append(vm_store.line("satom_policy_throughput_peak_bps", L,
                                   max(vals) * 8, ts))
    return lines


def _collect_transactions(appliance, params, ts) -> list:
    from ..clients.fortiweb import FortiWebClient
    client = FortiWebClient(appliance, timeout=15.0)
    hours = int(params.get("hours") or 1)
    lines = []
    for name in _top_policies(client, int(params.get("top_n") or 10)):
        rows, err = client.http_transactions(name, hours=hours)
        if err:
            continue
        total = 0
        for b in rows or []:
            if isinstance(b, dict):
                total += int(_num(b.get("count") or b.get("value") or 0) or 0)
        L = _labels(appliance, policy=name)
        lines.append(vm_store.line("satom_policy_transactions_window", L,
                                   total, ts))
    return lines


def _collect_vservers(appliance, params, ts) -> list:
    """FortiADC virtual servers — the ADC analogue of FortiWeb's ``policies``.

    ONE call (``status_history/vs_status``) carries the whole vdom's counters,
    so a device with 500 virtual servers costs one round trip. That shape is
    the entire reason this is a collector and not a probe-per-service.

    Metric NAMES are deliberately shared with FortiWeb's server policies. A
    server policy and a virtual server are the same concept — a published
    service — and ``sessions``/``client_rtt``/``server_rtt``/``app_response``
    mean the same thing on both. The ``kind`` label says which product a
    series came from, so one fleet-wide expression covers both instead of
    every dashboard carrying a per-product branch.

    Endpoint provenance: censused out of the GUI bundle and verified live on
    FortiADC-KVM 8.0.3 (2026-08-06). FortiADC has no ``monitor/`` namespace —
    every guessed name 404s.
    """
    from ..clients.fortiadc import FortiADCClient

    client = FortiADCClient(appliance, timeout=15.0)
    client.login()
    vdom = str(params.get("vdom") or "root")
    lines = []

    agg = client.vs_status(vdom=vdom)
    if agg is None:
        raise RuntimeError("vs_status returned no payload")
    L = _labels(appliance)
    for metric, key in (
            ("satom_adc_sessions", "current_sessions"),
            ("satom_adc_sessions_limit", "limit_sessions"),
            ("satom_adc_sessions_total", "total_sessions"),
            ("satom_adc_requests_total", "requests"),
            ("satom_adc_request_errors_total", "request_errors"),
            ("satom_adc_response_errors_total", "response_errors"),
            ("satom_adc_in_bytes_total", "in_bytes"),
            ("satom_adc_out_bytes_total", "out_bytes"),
            ("satom_policy_client_rtt_ms", "client_rtt"),
            ("satom_policy_server_rtt_ms", "server_rtt"),
            ("satom_policy_app_response_ms", "app_response")):
        lines.append(vm_store.line(metric, L, _num(agg.get(key)), ts))

    # Per-virtual-server rows. UNVERIFIED SHAPE: both lab FortiADCs are
    # factory-fresh (vs_list returns []), so the field names below are read
    # defensively with fallbacks rather than asserted. A row whose name cannot
    # be determined is skipped — an unnamed series is worse than none, because
    # it silently merges with every other unnamed one.
    vs_rows = client.vs_list(vdom=vdom)
    for row in vs_rows:
        if not isinstance(row, dict):
            continue
        name = (row.get("vsname") or row.get("name")
                or row.get("mkey") or row.get("vs_name"))
        if not name:
            continue
        VL = _labels(appliance, policy=str(name))
        state = str(row.get("status") or row.get("state")
                    or row.get("real_server_status") or "").lower()
        lines.append(vm_store.line(
            "satom_policy_up", VL,
            1 if state in ("up", "enable", "enabled", "1", "healthy", "running")
            else 0, ts))
        for metric, keys in (
                ("satom_policy_sessions", ("current_sessions", "sessions",
                                           "sessionCount")),
                ("satom_policy_conn_per_sec", ("conn_per_sec", "cps",
                                               "connCntPerSec"))):
            for k in keys:
                if k in row:
                    lines.append(vm_store.line(metric, VL, _num(row[k]), ts))
                    break
    lines.append(vm_store.line("satom_policy_count", L, len(vs_rows), ts))

    # Pool members: the backend-down signal. A virtual server that is "up"
    # with every member down still serves errors, which is exactly the state
    # the FortiWeb side already surfaces per policy.
    members = client.pool_member_list(vdom=vdom)
    down = 0
    for m in members:
        if not isinstance(m, dict):
            continue
        nm = m.get("member_name") or m.get("name") or m.get("mkey")
        if not nm:
            continue
        st = str(m.get("status") or m.get("health") or
                 m.get("health_check_status") or "").lower()
        up = 1 if st in ("up", "enable", "enabled", "1", "healthy") else 0
        down += (0 if up else 1)
        lines.append(vm_store.line(
            "satom_pool_member_up",
            _labels(appliance, pool=str(m.get("pool") or m.get("pool_name")
                                        or "unknown"), member=str(nm)), up, ts))
    lines.append(vm_store.line("satom_pool_member_count", L, len(members), ts))
    lines.append(vm_store.line("satom_pool_member_down", L, down, ts))
    return lines


#: FortiAuthenticator identity inventory: (series suffix, registry logical).
#: Counts only — never the rows. ``limit=1`` makes each call a few hundred
#: bytes and Tastypie's ``meta.total_count`` still reports the TRUE total, so
#: a directory with 50 000 users costs the same as an empty one. Fetching rows
#: to count them would be the per-policy mistake in another costume.
FAC_INVENTORY = (
    ("local_users",        "auth_local_users"),
    ("radius_users",       "auth_radius_users"),
    ("ldap_users",         "auth_ldap_users"),
    ("iam_users",          "auth_iam_users"),
    ("user_groups",        "auth_user_groups"),
    ("group_memberships",  "auth_local_group_members"),
    ("mac_devices",        "auth_mac_devices"),
    ("fortitokens",        "token_fortitokens"),
    ("user_certificates",  "cert_user_certificates"),
    ("radius_clients",     "radius_clients"),
    ("tacplus_clients",    "tacplus_clients"),
    ("sso_groups",         "sso_groups"),
)


def _collect_identity(appliance, params, ts) -> list:
    """FortiAuthenticator identity inventory — what the directory CONTAINS.

    An authenticator's health is not bandwidth; it is entitlement and
    directory state. ``capacity`` already covers the licence cliff. This
    covers the inventory that fills it: accounts, groups, tokens, certs, and
    the RADIUS/TACACS+ clients allowed to ask.

    KNOWN LIMIT, stated here because a dashboard would otherwise imply
    otherwise: there is NO authentication-RATE signal. All 58 resources were
    censused (2026-08-05) and none reports auth success/failure counters —
    that lives in syslog, which this product deliberately does not ingest.
    These series answer "what exists", never "is it authenticating".

    A resource that fails is REPORTED, not skipped: a directory that silently
    reports 11 of 12 counters looks exactly like a directory with one empty
    resource.
    """
    from ..clients.fortiauthenticator import FortiAuthenticatorClient

    client = FortiAuthenticatorClient(appliance, timeout=10.0)
    lines, failed = [], []
    for suffix, logical in FAC_INVENTORY:
        try:
            payload, err = client._call("GET", client._resolve(logical),
                                        params={"limit": 1})
        except Exception as exc:                     # noqa: BLE001
            payload, err = None, f"{type(exc).__name__}: {exc}"
        if err or not isinstance(payload, dict):
            failed.append(suffix)
            continue
        total = ((payload.get("meta") or {}).get("total_count"))
        if total is None:
            failed.append(suffix)
            continue
        lines.append(vm_store.line("satom_fac_inventory",
                                   _labels(appliance, resource=suffix),
                                   _num(total), ts))
    if failed and len(failed) == len(FAC_INVENTORY):
        raise RuntimeError("every identity resource failed: %s"
                           % ", ".join(failed[:4]))
    if failed:
        # Partial success still ingests what worked, but the gap is a series
        # of its own so it can be alerted on rather than eyeballed.
        lines.append(vm_store.line("satom_fac_inventory_failed",
                                   _labels(appliance), len(failed), ts))
    else:
        lines.append(vm_store.line("satom_fac_inventory_failed",
                                   _labels(appliance), 0, ts))
    return lines


#: FortiAnalyzer operational signals: (series suffix, registry logical).
#: Chosen so NO LOG IS EVER FETCHED. Every one of these is a counter or a
#: state summary; the log bodies stay on the analyser, which is the whole point
#: of monitoring a log collector rather than mirroring it.
FAZ_SIGNALS = (
    ("logstats",   "logview_logstats"),      # log volume + rate
    ("storage",    "storage_info"),          # log-disk occupancy
    ("logfiles",   "logview_logfiles"),      # logfile state
    ("alerts",     "eventmgmt_alerts"),      # open alerts
    ("incidents",  "incidentmgmt_incidents"),# open incidents
    ("devices",    "dvmdb_device"),          # registered devices
    ("tasks",      "task_task"),             # task queue
)

#: Numeric keys worth publishing when a signal returns an object rather than a
#: collection. Read defensively: this product reports several enums as ints and
#: the exact key set varies by firmware.
FAZ_NUMERIC_KEYS = (
    "used", "total", "free", "used_percent", "percent", "size",
    "count", "total_count", "num", "rate", "lograte", "logs",
    "disk_use", "disk_free", "total_disk", "used_disk",
)


def _faz_numbers(payload) -> dict:
    """Flatten a FortiAnalyzer payload to {key: number} for the keys we publish.

    A collection is reduced to its LENGTH (open alerts, registered devices,
    queued tasks are all "how many"), an object to its recognised numeric
    fields. Anything else yields nothing rather than a guess — a fabricated
    zero on a log collector reads as "no logs arriving", which is precisely
    the outage this collector exists to reveal.
    """
    out: dict = {}
    if isinstance(payload, list):
        out["count"] = float(len(payload))
        return out
    if not isinstance(payload, dict):
        return out
    for k, v in payload.items():
        kl = str(k).lower().replace("-", "_")
        if kl not in FAZ_NUMERIC_KEYS:
            continue
        n = _num(v)
        if n is not None:
            out[kl] = n
    for nest in ("data", "result", "storage", "logstats"):
        inner = payload.get(nest)
        if isinstance(inner, (dict, list)) and not out:
            out.update(_faz_numbers(inner))
    return out


def _collect_faz(appliance, params, ts) -> list:
    """FortiAnalyzer operational health — counters only, never log bodies.

    UNVERIFIED AGAINST A LIVE DEVICE. Every FortiAnalyzer in this fleet has
    been unreachable since July 2026, so the endpoint NAMES come from the
    registry (seeded from a live census in July and enabled) while the payload
    SHAPES are read defensively rather than asserted. That is why
    :func:`_faz_numbers` publishes only keys it recognises and emits nothing
    for a shape it does not: a wrong key would publish a plausible number, and
    a plausible wrong number on a log collector is worse than a gap.

    A signal that fails is COUNTED, not skipped — ``satom_faz_signals_failed``
    is the series that distinguishes "this analyser has no incidents" from
    "we could not ask it about incidents".
    """
    from ..clients.fortianalyzer import FortiAnalyzerClient

    client = FortiAnalyzerClient(appliance, timeout=15.0)
    client.login()
    lines, failed = [], []
    try:
        for suffix, logical in FAZ_SIGNALS:
            try:
                rows, err = client.list_with_error(logical)
            except Exception as exc:                 # noqa: BLE001
                rows, err = None, f"{type(exc).__name__}: {exc}"
            if err or rows is None:
                failed.append(suffix)
                continue
            nums = _faz_numbers(rows)
            if not nums:
                failed.append(suffix)
                continue
            for key, val in nums.items():
                lines.append(vm_store.line(
                    "satom_faz_%s" % suffix,
                    _labels(appliance, resource=key), val, ts))
    finally:
        try:
            client.logout()
        except Exception:                            # noqa: BLE001
            pass

    if len(failed) == len(FAZ_SIGNALS):
        raise RuntimeError("every FortiAnalyzer signal failed: %s"
                           % ", ".join(failed[:4]))
    lines.append(vm_store.line("satom_faz_signals_failed",
                               _labels(appliance), len(failed), ts))
    return lines


_RUNNERS = {
    "box": _collect_box,
    "capacity": _collect_capacity,
    "policies": _collect_policies,
    "interfaces": _collect_interfaces,
    "traffic": _collect_traffic,
    "transactions": _collect_transactions,
    "vservers": _collect_vservers,
    "identity": _collect_identity,
    "faz": _collect_faz,
}

# A collector declared in COLLECTORS but missing here is provisioned onto every
# device of its product and then fails with a KeyError on every sweep — a row
# that looks configured and is permanently red. Fail at import instead, where
# the author is still looking.
assert set(_RUNNERS) == set(COLLECTORS), (
    "collector/runner mismatch: %s" % sorted(set(_RUNNERS) ^ set(COLLECTORS)))


# ── execution ────────────────────────────────────────────────────────────────

def run_target(target) -> dict:
    """Run ONE target: collect → ingest → record outcome on the row.
    Returns {ok, series, ms, detail}. Never raises."""
    from ..models import db

    t0 = time.time()
    ts = int(t0 * 1000)
    appliance = target.appliance
    ok, detail, lines = True, "", []
    try:
        fn = _RUNNERS[target.collector]
        lines = [l for l in fn(appliance, target.params, ts) if l]
    except Exception as exc:  # noqa: BLE001 — a dead box is a result
        ok, detail = False, str(exc)[:250]
    # The scrape's own health is a metric too: a broken collector must be
    # VISIBLE in the store, not an absence someone has to notice.
    lines.append(vm_store.line(
        "satom_scrape_up",
        {"device": appliance.name, "kind": appliance.kind,
         "collector": target.collector}, 1 if ok else 0, ts))
    ing = vm_store.ingest(lines)
    if not ing["ok"]:
        ok, detail = False, (detail + " | ingest: " + ing["detail"]).strip(" |")
    ms = int((time.time() - t0) * 1000)
    target.last_run_at = datetime.utcnow()
    target.last_status = "ok" if ok else "error"
    target.last_detail = detail
    target.last_series = max(0, len(lines) - 1)
    target.last_ms = ms
    db.session.commit()
    return {"ok": ok, "series": target.last_series, "ms": ms, "detail": detail}


def sweep() -> dict:
    """One scheduled pass: auto-provision targets for new appliances, then run
    everything due, concurrently across devices."""
    from ..models import Appliance

    created = 0
    for a in Appliance.query.all():
        created += ensure_targets(a)   # self-guarding: see provisionable()
    due = due_targets()
    results = []
    if due:
        # Concurrency is per-target; each worker commits its own row, and
        # SQLAlchemy sessions are not thread-safe — so collect first, run
        # serially through the session-bound update. The device I/O dominates
        # (a policy_status is ~14 ms; SSH perf ~1 s), so parallelise ONLY the
        # device calls via a thread pool bounded well below the appliances'
        # admin-session limits.
        from flask import current_app
        app_obj = current_app._get_current_object()

        def _one(t_id):
            with app_obj.app_context():
                from ..models_metrics import ScrapeTarget
                t = ScrapeTarget.query.get(t_id)
                return run_target(t) if t else {"ok": False, "detail": "gone"}

        ids = [t.id for t in due]
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            results = list(pool.map(_one, ids))
    n_ok = sum(1 for r in results if r["ok"])
    return {"targets": len(due), "ok": n_ok,
            "errors": len(results) - n_ok, "created": created,
            "series": sum(r.get("series", 0) for r in results),
            "ms": sum(r.get("ms", 0) for r in results)}
