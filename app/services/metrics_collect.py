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

Surviving a promote — optional peer dual-write
----------------------------------------------
The store is node-local and stays that way: it lives outside ``data/`` because
satom-ha-datasync rsyncs data/ with ``--delete`` and a TSDB must never be
rsynced under a live process, and it stays out of the backup bundle because
~8 GB per bundle is not viable. Both of those are correct and neither is
touched here. What they left behind was the real gap: the standby had no store
and no collection, so a promote produced a primary with zero history AND zero
ability to make new history.

The fix is VictoriaMetrics' own HA shape — two independent single-node stores
fed the SAME samples — implemented at the COLLECTION layer: when a peer is
configured, every scrape is written to the local store and then mirrored to the
peer's. Consequences that are deliberate, not incidental:

* **OFF by default.** ``metrics.peer_dual_write`` must be switched on. A node
  with no peer performs exactly the work it performed before, writes no state
  file and raises no warning.
* **The mirror never costs the original.** A failed peer write cannot turn a
  good local scrape into a failed one. Local collection is the primary duty;
  degrading it to keep a mirror in step would trade the thing that works for
  the thing that is optional.
* **But a failing mirror is loud.** Consecutive failures and the time of the
  last success are journalled and surfaced. Silence here would recreate the bug
  this product keeps hitting, where a probe that cannot answer looks healthy.
* **The peer write is authenticated, never an open port.** It rides
  ``node_security.peer_post`` (HTTPS :8443 + ``X-FM-Node-Key``). The store
  itself has no authentication at all — the loopback bind is the only thing
  protecting the whole fleet's telemetry — so it is never rebound, and nothing
  here names its address.
* **"no peer" and "peer down" are different facts** and never collapse into one
  state; so does "the transport is not deployed on this node yet".
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

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


# ── HA: optional peer dual-write ─────────────────────────────────────────────

#: Switch. Absent/empty means OFF — a single-node install must never opt in by
#: accident, because a peer write it did not ask for is pure latency plus a
#: permanent "degraded" badge.
K_DUAL_WRITE = "metrics.peer_dual_write"
#: Optional explicit peer address. Unset -> derived from the HA node registry,
#: which is the same source ``infra_health`` and ``cluster`` already trust.
K_PEER_HOST = "metrics.peer_host"

#: Receiving endpoints on the OTHER node (both identity-key gated).
PEER_INGEST_PATH = "/monitoring/collection/peer/ingest"
PEER_STORE_PATH = "/monitoring/collection/peer/store"

#: Short: a slow peer must not stretch the scrape window. The local write has
#: already happened by the time we get here, so giving up early loses at most
#: one sample on the mirror.
PEER_TIMEOUT = 5.0
PEER_PROBE_TIMEOUT = 2.5

# Peer-write states. Every one of these is a DIFFERENT operator action, which
# is precisely why they may not be folded into a boolean:
PEER_OFF = "off"                    # not switched on — not a fault
PEER_UNCONFIGURED = "unconfigured"  # switched on, but no peer address known
PEER_UNAVAILABLE = "unavailable"    # node_security.peer_post missing HERE
PEER_PENDING = "pending"            # configured, nothing attempted yet
PEER_NOTHING = "nothing"            # attempted with an empty scrape
PEER_UNREACHABLE = "unreachable"    # peer did not answer
PEER_REJECTED = "rejected"          # peer answered, and said no
PEER_OK = "ok"

# Per-node store states for the Collection page.
STORE_REACHABLE = "reachable"
STORE_UNREACHABLE = "unreachable"
STORE_NOT_CONFIGURED = "not-configured"
STORE_UNAUTHORIZED = "unauthorized"
STORE_ERROR = "error"

_TRUE = ("1", "true", "on", "yes", "enabled")

# Node-local, outside data/ — same reasoning as the renewal journal: the
# standby's Postgres is read-only, so the node whose mirror is failing is
# exactly the node that could not write a DB row about it, and anything under
# data/ is erased by the rsync --delete datasync within five minutes.
STATE_DIR = Path(os.environ.get("SATOM_STATE_DIR") or "/opt/satom/state")
PEER_STATE_FILE = STATE_DIR / "metrics-peer.json"


def _peer_post_fn():
    """``node_security.peer_post`` if this node has it, else None.

    Resolved at CALL time, never imported at module scope: the authenticated
    POST channel is landing in node_security separately, and a module that
    cannot be imported until it does would take local collection down with it
    — the exact trade this whole feature refuses to make.
    """
    try:
        from . import node_security as nsec
    except Exception:  # noqa: BLE001 — a broken import is a missing transport
        return None
    fn = getattr(nsec, "peer_post", None)
    return fn if callable(fn) else None


def _setting(key: str, default: str = "") -> str:
    try:
        from . import settings_store as ss
        return (ss.get_str(key, default) or "").strip()
    except Exception:  # noqa: BLE001 — no app context (CLI, sidecar boot)
        return default


def _derived_peer_host():
    """The other HA node's address from the node registry, or None."""
    try:
        from . import self_update as su
        me = su.this_node_name()
        for n in su.node_reports():
            host = (n.get("host") or "").strip()
            if n.get("name") == me or n.get("self") or not host:
                continue
            if host in ("127.0.0.1", "::1", "localhost"):
                continue
            return host
    except Exception:  # noqa: BLE001
        pass
    return None


def _peer_node_name():
    try:
        from . import self_update as su
        me = su.this_node_name()
        for n in su.node_reports():
            if n.get("name") and n.get("name") != me and not n.get("self"):
                return n.get("name")
    except Exception:  # noqa: BLE001
        pass
    return None


def peer_config() -> dict:
    """{enabled, host} — the two facts that decide whether a mirror exists."""
    return {"enabled": _setting(K_DUAL_WRITE).lower() in _TRUE,
            "host": _setting(K_PEER_HOST) or _derived_peer_host()}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_state() -> dict:
    try:
        return json.loads(PEER_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — absent or corrupt reads as "nothing yet"
        return {}


def _record(state: str, detail: str, status, host: str) -> dict:
    """Journal ONE peer-write attempt. Never raises: a journal problem must not
    turn a successful scrape into a failed one, nor mask the real error."""
    ok = state == PEER_OK
    prev = _read_state()
    st = {
        "state": state,
        "status": status,
        "detail": detail[:300],
        "peer_host": host,
        "last_attempt_at": _now(),
        "last_success_at": _now() if ok else prev.get("last_success_at"),
        "consecutive_failures": 0 if ok else int(prev.get("consecutive_failures") or 0) + 1,
        "last_error": "" if ok else (detail[:300] or state),
        "last_error_at": prev.get("last_error_at") if ok else _now(),
    }
    try:
        PEER_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        PEER_STATE_FILE.write_text(json.dumps(st), encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    return {"attempted": True, "ok": ok, "state": state, "status": status,
            "detail": detail[:300]}


def _status_of(res):
    """peer_post's status code, tolerant of the shape it settles on.

    ``peer_get`` returns ``(status, body, secure)``; this accepts that, a bare
    status, or a dict — an assumption about a sibling module's return shape is
    not worth failing a mirror over.
    """
    if res is None:
        return None
    if isinstance(res, (tuple, list)):
        return res[0] if res else None
    if isinstance(res, dict):
        return res.get("status") or res.get("code")
    if isinstance(res, int):
        return res
    return getattr(res, "status", None) or getattr(res, "code", None)


def peer_write(lines) -> dict:
    """Mirror ``lines`` into the PEER node's store. Never raises.

    Returns ``{attempted, ok, state, status, detail}``. ``ok`` is None when
    nothing was attempted — a mirror that was never asked to run is not a
    mirror that failed, and the caller must be able to tell them apart.
    """
    cfg = peer_config()
    if not cfg["enabled"]:
        return {"attempted": False, "ok": None, "state": PEER_OFF,
                "status": None, "detail": "dual-write disabled"}
    host = cfg["host"]
    if not host:
        # Switched on with nowhere to write. NOT "unreachable": nobody is down,
        # somebody has to type an address.
        return {"attempted": False, "ok": None, "state": PEER_UNCONFIGURED,
                "status": None,
                "detail": "dual-write enabled but no peer host is configured"}
    fn = _peer_post_fn()
    if fn is None:
        # The transport is missing on THIS node. Fixed by deploying code here,
        # not by going to look at the other box.
        return {"attempted": False, "ok": None, "state": PEER_UNAVAILABLE,
                "status": None,
                "detail": "node_security.peer_post is not available on this node"}
    body = "\n".join(l for l in lines if l)
    if not body:
        return {"attempted": False, "ok": None, "state": PEER_NOTHING,
                "status": None, "detail": "no samples to mirror"}
    try:
        res = fn(host, PEER_INGEST_PATH, body.encode("utf-8"),
                 timeout=PEER_TIMEOUT)
    except TypeError as exc:  # signature drift in node_security
        return {"attempted": False, "ok": None, "state": PEER_UNAVAILABLE,
                "status": None,
                "detail": "peer_post signature mismatch: %s" % str(exc)[:200]}
    except Exception as exc:  # noqa: BLE001 — a dead peer is a result
        return _record(PEER_UNREACHABLE, str(exc)[:250], None, host)
    status = _status_of(res)
    if status is None:
        return _record(PEER_UNREACHABLE, "peer did not answer", None, host)
    try:
        code = int(status)
    except (TypeError, ValueError):
        return _record(PEER_REJECTED, "unreadable status %r" % (status,), None, host)
    if 200 <= code < 300:
        return _record(PEER_OK, "", code, host)
    return _record(PEER_REJECTED, "peer answered HTTP %d" % code, code, host)


def peer_health() -> dict:
    """Everything the Collection page needs to say whether this node's samples
    exist in two places — and, when they do not, which of the four reasons.

    ``redundant`` is True ONLY on a confirmed successful mirror. ``alarm`` is
    True only when the node CLAIMS redundancy (dual-write on) and does not have
    it: an off switch is not a fault, and a fresh, never-attempted mirror is not
    a failure either.
    """
    cfg = peer_config()
    st = _read_state()
    dependency_ready = _peer_post_fn() is not None
    if not cfg["enabled"]:
        state = PEER_OFF
    elif not cfg["host"]:
        state = PEER_UNCONFIGURED
    elif not dependency_ready:
        state = PEER_UNAVAILABLE
    else:
        state = st.get("state") or PEER_PENDING
    return {
        "enabled": cfg["enabled"],
        "host": cfg["host"],
        "state": state,
        "dependency_ready": dependency_ready,
        "redundant": state == PEER_OK,
        "alarm": bool(cfg["enabled"]) and state not in (PEER_OK, PEER_PENDING),
        "consecutive_failures": int(st.get("consecutive_failures") or 0),
        "last_success_at": st.get("last_success_at"),
        "last_attempt_at": st.get("last_attempt_at"),
        "last_error": st.get("last_error") or "",
        "last_error_at": st.get("last_error_at"),
        "detail": st.get("detail") or "",
        "ingest_path": PEER_INGEST_PATH,
    }


# ── HA: per-node store report ────────────────────────────────────────────────

def local_store_report() -> dict:
    """This node's store, from the loopback client."""
    h = vm_store.health()
    return {"state": STORE_REACHABLE if h.get("up") else STORE_UNREACHABLE,
            "up": bool(h.get("up")), "series": h.get("series"),
            "url": h.get("url"), "detail": h.get("detail") or ""}


def peer_store_report(host=None) -> dict:
    """The PEER node's store, asked over the authenticated node channel.

    ``not-configured`` (there is no second node) and ``unreachable`` (there is
    one and it will not answer) are the two facts an operator most needs kept
    apart here: rendered the same, a single-node install looks broken and a
    broken pair looks single.
    """
    host = host or peer_config()["host"]
    blank = {"up": False, "series": None, "url": None, "detail": "",
             "host": host}
    if not host:
        return dict(blank, state=STORE_NOT_CONFIGURED,
                    detail="no peer node is registered")
    try:
        from . import node_security as nsec
        st, body, secure = nsec.peer_get(host, PEER_STORE_PATH,
                                         timeout=PEER_PROBE_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        return dict(blank, state=STORE_UNREACHABLE, detail=str(exc)[:200])
    if st is None:
        return dict(blank, state=STORE_UNREACHABLE,
                    detail="peer did not answer")
    if st in (401, 403):
        return dict(blank, state=STORE_UNAUTHORIZED,
                    detail="peer rejected our identity key")
    if st != 200:
        return dict(blank, state=STORE_ERROR, detail="peer answered HTTP %s" % st)
    try:
        payload = json.loads(body.decode("utf-8", "replace")) or {}
        store = payload.get("store") or {}
    except Exception as exc:  # noqa: BLE001
        return dict(blank, state=STORE_ERROR, detail=str(exc)[:200])
    return {"state": STORE_REACHABLE if store.get("up") else STORE_UNREACHABLE,
            "up": bool(store.get("up")), "series": store.get("series"),
            "url": store.get("url"), "detail": store.get("detail") or "",
            "host": host, "secure": secure}


def _local_last_write():
    """When this node last wrote a sample — from the scrape rows, not a new
    file, so an unconfigured node still creates no state of its own."""
    try:
        from ..models_metrics import ScrapeTarget
        rows = [t.last_run_at for t in ScrapeTarget.query.all() if t.last_run_at]
        return max(rows).isoformat() if rows else None
    except Exception:  # noqa: BLE001
        return None


def stores_report() -> list:
    """Per-node store state for the Collection page: is this pair ACTUALLY
    redundant, or does it only claim to be. Does peer network I/O — serve it
    from its own endpoint, never from a page render."""
    try:
        from . import self_update as su
        me = su.this_node_name()
    except Exception:  # noqa: BLE001
        me = "this node"
    host = peer_config()["host"]
    return [
        {"node": me, "host": None, "is_local": True,
         "store": local_store_report(), "last_write_at": _local_last_write(),
         "peer_write": peer_health()},
        {"node": _peer_node_name() or "peer", "host": host, "is_local": False,
         "store": peer_store_report(host), "last_write_at": None},
    ]


# ── HA: consistent hot snapshots ─────────────────────────────────────────────

def _store_api(path: str, timeout: float = 60.0) -> dict:
    """POST a VictoriaMetrics admin endpoint on the LOOPBACK store. The address
    comes from ``vm_store.base_url()`` so this module never names it."""
    req = urllib.request.Request(vm_store.base_url() + path, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return json.loads(r.read().decode("utf-8", "replace"))


def snapshot_create() -> dict:
    """Take a consistent hot snapshot of the local store (VM >= 1.148 supports
    ``/snapshot/create``; it is a hardlink tree, so it is near-free in space
    and instant). Never raises — a snapshot that could not be taken must SAY
    so, because a silent 'ok' here is a backup that does not exist."""
    try:
        d = _store_api("/snapshot/create")
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "snapshot": None, "detail": str(exc)[:250]}
    name = (d or {}).get("snapshot")
    if (d or {}).get("status") == "ok" and name:
        return {"ok": True, "snapshot": name, "detail": ""}
    return {"ok": False, "snapshot": None, "detail": str(d)[:250]}


def snapshot_list() -> dict:
    """Existing snapshots. Reported, not just taken: the unit carries no
    ``-snapshotsMaxAge``, so nothing expires them and an unwatched snapshot
    directory is a slow disk leak."""
    try:
        d = _store_api("/snapshot/list")
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "snapshots": [], "detail": str(exc)[:250]}
    return {"ok": (d or {}).get("status") == "ok",
            "snapshots": (d or {}).get("snapshots") or [], "detail": ""}


def snapshot_delete(name: str) -> dict:
    """Drop one snapshot — the other half of ``snapshot_create``. Offering a
    trigger with no way to reclaim the space would hand the operator a disk
    leak dressed as a feature."""
    import urllib.parse
    if not name:
        return {"ok": False, "detail": "no snapshot named"}
    try:
        d = _store_api("/snapshot/delete?" + urllib.parse.urlencode(
            {"snapshot": name}))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "detail": str(exc)[:250]}
    ok = (d or {}).get("status") == "ok"
    return {"ok": ok, "detail": "" if ok else str(d)[:250]}


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
    # The HA mirror. Deliberately AFTER the local write, deliberately unable to
    # touch `ok` or `detail`, and deliberately wrapped: the peer store is the
    # optional copy, this node's store is the duty. Its outcome is journalled
    # and reported by peer_health() — not silently swallowed, and not allowed
    # to mark a good scrape bad.
    try:
        peer = peer_write(lines)
    except Exception as exc:  # noqa: BLE001 — belt and braces; peer_write is total
        peer = {"attempted": True, "ok": False, "state": PEER_UNREACHABLE,
                "status": None, "detail": str(exc)[:200]}
    ms = int((time.time() - t0) * 1000)
    target.last_run_at = datetime.utcnow()
    target.last_status = "ok" if ok else "error"
    target.last_detail = detail
    target.last_series = max(0, len(lines) - 1)
    target.last_ms = ms
    db.session.commit()
    return {"ok": ok, "series": target.last_series, "ms": ms, "detail": detail,
            "peer": peer}


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
    # The mirror's state rides along with the sweep result so the scheduled
    # action can report a silently-failing peer instead of a green sweep that
    # is only half-written. Extra keys are harmless to the existing
    # "%(ok)d/%(targets)d" summary formatting.
    return {"targets": len(due), "ok": n_ok,
            "errors": len(results) - n_ok, "created": created,
            "series": sum(r.get("series", 0) for r in results),
            "ms": sum(r.get("ms", 0) for r in results),
            "peer": peer_health()}
