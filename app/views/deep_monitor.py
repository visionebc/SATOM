"""Deep monitors — the checks that reach INTO the appliance.

Fleet health is *is the box alive*; Metrics is *how much does it hold*. This is
*is the service actually serving*: synthetic HTTPS against the published
front-end of a server policy, interface IP / link drift, processor load, memory
usage, and the ``proxyd`` daemon's worker count and restarts.

The REST-telemetry kinds (sessions, per-policy sessions, throughput, HTTP
transactions) moved to **Service Monitor** on 2026-07-28 — see
``app/views/service_monitor.py``. Same tables, same runner, same scheduled
action; a different page, because these five need SSH or a synthetic request
into the box and those four only need its monitor API.

Contract, identical to the other Monitoring views: **a page load never touches
an appliance.** The page renders from ``monitor_probe`` / ``monitor_sample``
rows; probing is a background job (``/run``) or the ``deep_monitor`` scheduled
action. Reads need VIEW; creating, editing, deleting or triggering a probe needs
CONFIG_WRITE.
"""
from __future__ import annotations

from flask import Blueprint

from ..services import jobs as jobsvc  # noqa: F401  (tests patch this handle)
from . import monitor_probes as mp

bp = Blueprint('deep_monitor', __name__, url_prefix='/monitoring/deep')

# The kinds this page owns: everything that is NOT REST telemetry. Derived from
# the service module rather than re-listed, so a kind added there lands on
# exactly one of the two pages instead of silently on neither.
KINDS = tuple(k for k in mp.dm.KINDS if k not in mp.dm.API_KINDS)

SPEC = mp.PageSpec(
    key="deep_monitor",
    title="Deep monitors",
    icon="bi-broadcast-pin",
    kinds=KINDS,
    template='monitoring/deep.html',
    discover=('policies', 'baseline', 'interfaces'),
    blurb=(
        "Does the service actually serve? Synthetic HTTPS against a server "
        "policy's published front-end, interface IP&nbsp;/&nbsp;link drift, "
        "processor load, memory usage and the <code>proxyd</code> daemon — each "
        "its own probe with its own thresholds, and each stored as a time "
        "series, because the signal is the value <em>changing</em>."),
    footnote=(
        "Interface data comes from the device cache refreshed by the hourly "
        "<code>device_sync</code>, so interface drift is detected at harvest "
        "cadence, not instantly. Processor load and memory usage read "
        "<code>get system performance</code> over the read-only CLI on FortiWeb "
        "and FortiADC; <code>proxyd</code> reads <code>diagnose system top</code> "
        "and is FortiWeb-only &mdash; it reports the memory consumed and free on "
        "the box, never the daemon's <code>%VSZ</code> (virtual size, which sums "
        "past 100&nbsp;% across processes). Runtime telemetry read over the "
        "appliance's monitor API lives in <b>Service Monitor</b>."),
    job_label="deep_monitor",
)

mp.attach(bp, SPEC)
