"""Two collectors Sentinel needs that the fleet metrics layer did not have.

``http_status`` — response-code behaviour, from the TRAFFIC log
---------------------------------------------------------------
An HTTP status code is not a vulnerability and this collector does not pretend
otherwise. What it captures is the OUTCOME of each request, and the outcome
separates the two cases a signature count cannot:

* the appliance answered 403 → the defence worked;
* the origin answered 200 to a request carrying an attack signature → it did
  not.

**Where the data comes from, measured rather than assumed.** The obvious
source, ``policy_status``, was probed live against fortiweb12 (7.6.8) on
2026-08-20 and carries NO response-class counters at all. Its full field set
is::

    _id, app_response_time, client_rtt, connCntPerSec, httpPort, id, mode,
    name, policy, protocol, server_rtt, sessionCount, status, vserver

An earlier draft of this module read ``http_2xx``/``http_5xx`` from those rows.
Those field names do not exist; the collector would have raised on every run,
or — worse, had it defaulted them — published a flat line of zeros that reads
on a chart exactly like a quiet service.

The real source is the **traffic log**, reached by the same GUI-session path
:mod:`app.services.attack_log` recovered for the attack log:
``GET /api/v2.0/log/logaccess.traffic?log=tlog.log``. That endpoint was probed
live on the same device: **HTTP 200, correct ``results.payload`` envelope**.

⚠ **Known limit, stated rather than hidden.** fortiweb12/13 are a laboratory
with no live traffic, so all three log endpoints returned ZERO rows. The
endpoint is verified; the individual FIELD NAMES inside a traffic-log row are
NOT — there was no row to read them from. :data:`_STATUS_FIELDS` therefore
accepts several spellings, and :func:`collect_http_status` raises a sentence
naming the keys it actually saw when none match. It will not invent a value.

``infra`` — the VM and the hypervisor host under the appliance
--------------------------------------------------------------
Reached through ``sentinel_topology``, the join that makes the lower layers
addressable at all. A device with no topology row yields no series and the
correlation engine reports those layers as *unknown* — never as healthy.
Publishing a zero for a layer nobody mapped is how a saturated hypervisor
reads as a quiet one.

Cost
----
One call per device per run for each. The measurement that shaped this whole
subsystem (2026-08-05: per-policy probing needed ~56 min of device I/O per
3-minute window at fleet scale) is not reopened. ``infra`` talks to the
hypervisor API, never to the appliance: during an incident the appliance is by
hypothesis already loaded, and a monitor that adds round-trips then becomes
part of the outage.
"""
from __future__ import annotations

from .. import vm_store

#: Traffic-log field names that could carry the response code. Several
#: spellings because the exact one is UNVERIFIED (see the module docstring) and
#: because this product has already been burnt trusting a single field name.
_STATUS_FIELDS = ("http_status", "status_code", "http_response_code",
                  "response_code", "http_code", "status")

#: Field carrying the server policy the request hit.
_POLICY_FIELDS = ("policy", "policy_name", "srcpolicy")


def _labels(appliance, **extra) -> dict:
    d = {"device": appliance.name, "kind": appliance.kind}
    d.update(extra)
    return d


def _pick(row: dict, names) -> str:
    for n in names:
        v = row.get(n)
        if v not in (None, "", "N/A"):
            return str(v).strip()
    return ""


def _status_of(row: dict):
    """The response code as an int, or ``None``.

    ``status`` is last in :data:`_STATUS_FIELDS` and is validated as a number
    on purpose: on several Fortinet log types ``status`` is a WORD
    (``accept`` / ``deny``), and coercing that to a number would silently
    classify every row as ``unknown`` while looking like it worked.
    """
    raw = _pick(row, _STATUS_FIELDS)
    if not raw:
        return None
    try:
        code = int(float(raw))
    except (TypeError, ValueError):
        return None
    return code if 100 <= code <= 599 else None


# --------------------------------------------------------------------------- #
#  http_status                                                                  #
# --------------------------------------------------------------------------- #
def read_traffic_log(appliance, pages: int = 1, page_size_hint: int = 0) -> list:
    """Traffic-log rows via the GUI session. Read-only; never writes config.

    Deliberately reuses :mod:`app.services.attack_log`'s session machinery
    rather than opening a second one: that module already owns login, session
    reuse, the 403-retry and the invalidation path, and a second copy of that
    logic is a second thing to keep in step with a firmware move.
    """
    from .. import attack_log as al

    base = f"https://{appliance.host}:{appliance.port}"
    client = al._session_for(appliance)
    rows: list = []
    for page in range(1, max(1, pages) + 1):
        params = {"log": "tlog.log", "page": page, "filter_offset": 0,
                  "filter": "[]"}
        resp = client.get(base + "/api/v2.0/log/logaccess.traffic", params=params)
        if resp.status_code == 403 or "logincheck" in resp.text[:400]:
            al.invalidate(appliance)
            client = al._session_for(appliance)
            resp = client.get(base + "/api/v2.0/log/logaccess.traffic",
                              params=params)
        if resp.status_code != 200:
            raise RuntimeError(
                f"{appliance.host} answered HTTP {resp.status_code} on the "
                f"traffic-log endpoint. On 7.6.8 this path is internal to the "
                f"GUI; a firmware upgrade may have moved it.")
        body = resp.json()
        results = body.get("results", body)
        if not isinstance(results, dict) or "payload" not in results:
            raise RuntimeError(
                f"{appliance.host} answered an unexpected traffic-log shape "
                f"(keys: {sorted(results)[:8] if isinstance(results, dict) else type(results).__name__})")
        page_rows = list(results.get("payload") or [])
        rows.extend(page_rows)
        if not page_rows:
            break
    return rows


def collect_http_status(appliance, params, ts) -> list:
    """Response-class counts per policy, computed from traffic-log rows.

    Counted from rows this collector actually read, so the number is
    verifiable by construction — no device counter is trusted for it.

    An EMPTY traffic log is a legitimate, reportable answer and yields
    ``satom_http_status_rows 0`` rather than nothing: the difference between
    "this device served nothing" and "this collector is broken" must be
    visible on a graph, and silence renders identically for both.
    """
    pages = int((params or {}).get("pages") or 1)
    rows = read_traffic_log(appliance, pages=pages)

    labels = _labels(appliance)
    lines = [vm_store.line("satom_http_status_rows", labels, len(rows), ts)]
    if not rows:
        return lines

    per_policy: dict = {}
    unknown = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        code = _status_of(row)
        if code is None:
            unknown += 1
            continue
        policy = _pick(row, _POLICY_FIELDS) or "-"
        bucket = per_policy.setdefault(policy, {})
        klass = f"{code // 100}xx"
        bucket[klass] = bucket.get(klass, 0) + 1

    if not per_policy:
        raise RuntimeError(
            "traffic log returned %d row(s) but none carried a recognisable "
            "response code. Fields seen on the first row: %s"
            % (len(rows), sorted(rows[0].keys())[:20] if rows else []))

    for policy, classes in per_policy.items():
        total = sum(classes.values())
        for klass, count in classes.items():
            lines.append(vm_store.line(
                "satom_http_status_total",
                dict(labels, policy=policy, code_class=klass), count, ts))
        lines.append(vm_store.line(
            "satom_http_status_rate", dict(labels, policy=policy), total, ts))
    if unknown:
        lines.append(vm_store.line("satom_http_status_unparsed", labels,
                                   unknown, ts))
    return lines


# --------------------------------------------------------------------------- #
#  infra                                                                        #
# --------------------------------------------------------------------------- #
def collect_infra(appliance, params, ts) -> list:
    """VM + hypervisor-host series for one appliance, via its topology row."""
    from ...models_provision import HypervisorTarget
    from ...models_sentinel import SentinelTopology
    from .. import hypervisors

    topo = SentinelTopology.query.filter_by(appliance_id=appliance.id).first()
    if topo is None or not topo.complete:
        raise RuntimeError(
            "no complete topology mapping for this device (hypervisor target, "
            "VM id and node are all required) — the VM and host layers stay "
            "UNKNOWN rather than being reported as healthy")

    target = HypervisorTarget.query.get(topo.hypervisor_target_id)
    if target is None:
        raise RuntimeError(f"hypervisor target {topo.hypervisor_target_id} is gone")

    client = hypervisors.build_client(target, timeout=15)
    ref = hypervisors.VmRef(identifier=str(topo.vm_id), node=topo.node)

    lines: list = []
    vm_labels = _labels(appliance, node=topo.node, vmid=str(topo.vm_id))
    vm = client.vm_metrics(ref)
    for metric, key in (("satom_vm_cpu_pct", "cpu_pct"),
                        ("satom_vm_mem_pct", "mem_pct"),
                        ("satom_vm_mem_bytes", "mem_bytes"),
                        ("satom_vm_uptime_s", "uptime_s")):
        if vm.get(key) is not None:
            lines.append(vm_store.line(metric, vm_labels, vm[key], ts))
    # Cumulative counters keep the _total suffix and stay counters: the store
    # derives rates and handles the reset a VM restart causes. A rate computed
    # here from a remembered sample goes negative across that restart, which
    # becomes a nonsense spike exactly while someone reads the graph.
    for metric, key in (("satom_vm_disk_read_bytes_total", "disk_read_bytes"),
                        ("satom_vm_disk_write_bytes_total", "disk_write_bytes"),
                        ("satom_vm_net_in_bytes_total", "net_in_bytes"),
                        ("satom_vm_net_out_bytes_total", "net_out_bytes")):
        if vm.get(key) is not None:
            lines.append(vm_store.line(metric, vm_labels, vm[key], ts))

    host = client.node_metrics(topo.node)
    host_labels = {"node": topo.node, "hypervisor": target.name}
    for metric, key in (("satom_host_cpu_pct", "cpu_pct"),
                        ("satom_host_mem_pct", "mem_pct"),
                        ("satom_host_disk_pct", "disk_pct"),
                        ("satom_host_load1", "load1")):
        if host.get(key) is not None:
            lines.append(vm_store.line(metric, host_labels, host[key], ts))

    if not lines:
        raise RuntimeError("hypervisor answered but carried no usable readings")
    return lines


#: Registry entries injected into ``metrics_collect``. Kept here so the whole
#: Sentinel collection surface is one file, and injected THERE so the operator
#: edits cadence on the same page as every other collector — a second
#: collection settings page is how two cadence models drift apart.
SPECS = {
    "http_status": {
        "label": "HTTP response classes — counted from the traffic log",
        "products": ("fortiweb",),
        "interval": 5, "params": {"pages": 1},
        "runner": collect_http_status,
    },
    "infra": {
        "label": "VM + hypervisor host metrics (via the Sentinel topology map)",
        "products": ("fortiweb", "fortiadc"),
        "interval": 3, "params": {},
        "runner": collect_infra,
    },
}


def register() -> int:
    """Add the Sentinel collectors to the fleet collection registry.

    Idempotent, and it re-asserts the invariant ``metrics_collect`` asserts for
    itself: every collector has a runner. A collector registered without one
    creates scrape-target rows that raise ``KeyError`` on every sweep —
    visible only as a permanently red target nobody provisioned on purpose.
    """
    from .. import metrics_collect as mc
    added = 0
    for key, spec in SPECS.items():
        if key in mc.COLLECTORS:
            continue
        mc.COLLECTORS[key] = {"label": spec["label"],
                              "products": spec["products"],
                              "interval": spec["interval"],
                              "params": spec["params"]}
        mc._RUNNERS[key] = spec["runner"]
        added += 1
    assert set(mc._RUNNERS) == set(mc.COLLECTORS), (
        "collector/runner mismatch after Sentinel registration: %s"
        % sorted(set(mc._RUNNERS) ^ set(mc.COLLECTORS)))
    return added
