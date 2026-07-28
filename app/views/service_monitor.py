"""Service Monitor — runtime telemetry read over the appliance's monitor API.

Split out of Deep monitors on 2026-07-28 at the operator's request. The four
kinds here answer *how much is this service actually carrying right now*:
concurrent sessions box-wide, sessions + latency + backend health per server
policy, HTTP throughput, and HTTP transaction volume.

Why they earn their own page rather than five more rows under Deep monitors:

* **Different acquisition.** Every kind here is a REST call to the appliance's
  monitor API. None opens an SSH session. VERIFIED on fw7 (2026-07-28): the
  cmdb is licence-locked — every config read returns HTTP 423 ``-20010`` — and
  ``status.systemresource``, ``policystatus`` and ``policytraffic`` still answer
  200. These probes cover exactly the devices whose hourly ``device_sync`` has
  been failing for days.
* **Different question.** Deep monitors ask *is it up*. These ask *how much*.
  A page that mixes a binary health check with a traffic gauge makes the reader
  do the sorting.
* **Different product surface.** FortiWeb only — FortiADC and FortiAnalyzer
  expose runtime telemetry under entirely different paths, so discovery refuses
  to create these there rather than reporting silent zeroes.

What is deliberately NOT split: the storage (``monitor_probe`` /
``monitor_sample``), the runner (``services.deep_monitor.run_probe``) and the
``deep_monitor`` scheduled action, which sweeps both pages every five minutes.
Two runners would mean two sweeps and two sets of samples for the same box.

The daemon-restart check (``proxyd``, PID-set fingerprint) stays in Deep
monitors: no endpoint on FortiWeb exposes process state — 100+ non-cmdb paths
enumerated from the GUI bundle, none of them — so that check has to be CLI and
remains the authoritative restart signal.
"""
from __future__ import annotations

from flask import Blueprint

from ..services import jobs as jobsvc  # noqa: F401  (tests patch this handle)
from . import monitor_probes as mp

bp = Blueprint('service_monitor', __name__, url_prefix='/monitoring/services')

# Owned kinds = the REST-telemetry set, straight from the service module.
KINDS = tuple(mp.dm.API_KINDS)

SPEC = mp.PageSpec(
    key="service_monitor",
    title="Service Monitor",
    icon="bi-speedometer2",
    kinds=KINDS,
    template='monitoring/services.html',
    discover=('api',),
    blurb=(
        "How much is each service actually carrying? Concurrent sessions, HTTP "
        "throughput and transaction volume — box-wide and per server policy — "
        "read over the appliance's REST monitor API. No SSH, and no dependency "
        "on the config API, so these keep reporting on a device whose "
        "<em>cmdb</em> is licence-locked."),
    footnote=(
        "Every kind here is a REST call: <code>system/status.systemresource</code> "
        "for box sessions and connection rate, <code>policy/policystatus</code> "
        "for per-policy sessions, latency and backend health, "
        "<code>policy/policytraffic</code> for throughput (60 one-second samples "
        "per run — a sampling window, not full coverage, which is why throughput "
        "is graded on the window <b>peak</b>) and "
        "<code>system/status.httptransactions</code> for request volume. FortiWeb "
        "only. Thresholds are absolute, and 0 disables that level. Whether the "
        "<code>proxyd</code> daemon has restarted is <em>not</em> answerable over "
        "the API — that check lives in <b>Deep monitors</b> and reads the PID set "
        "over the read-only CLI."),
    job_label="service_monitor",
)

mp.attach(bp, SPEC)
