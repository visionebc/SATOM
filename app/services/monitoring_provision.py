"""One seam for "this device is now monitored".

Two subsystems answer different questions about the same appliance and were
provisioned from different places:

* **Collection** (``metrics_collect.ensure_targets``) — the time-series layer.
  One scrape target per *collector*, so a device with 10 000 server policies
  still costs five rows and five calls. Already wired into every
  appliance-creation path.
* **Deep monitors** (``deep_monitor.ensure_baseline``) — the *threshold* layer.
  Per-DEVICE rows (interfaces, CPU, memory, and — FortiWeb only — proxyd) that
  carry warn/crit levels and feed the ``probe`` signal of Fleet health.
  Until now this ran ONLY from the *Discover* button, so a device added through
  the normal form had metrics but **no thresholds and no alerting**, and
  nothing on either page said so.

Provisioning both from one function is what keeps them from drifting apart
again: a third subsystem added later has exactly one call site to join.

Why the baseline is NOT trimmed
-------------------------------
The obvious-looking saving — "Collection already reads CPU and memory, drop
those probes" — is wrong twice over. Those rows are per *device*, not per
policy: fifty appliances cost two hundred rows, which is not the scale problem.
And Collection has no concept of a threshold, so deleting them would remove
alerting from devices that had it while every page kept showing data. That is
the failure :func:`deep_monitor.split_legacy_proxyd` exists to prevent.

The scale rule that DOES matter is enforced by a guard, not by a comment:
nothing in :data:`deep_monitor.API_KINDS` — the per-policy kinds — may ever
enter the baseline set. Those are created deliberately, from *Discover*, by an
operator who chose the policies.
"""

from ..errors import log_exception


def provision_monitoring(appliance, *, session=None) -> dict:
    """Give a saved appliance everything it needs to be monitored.

    Returns ``{"targets": int, "probes": [kind, ...], "errors": [str, ...]}``.

    Never raises. Monitoring is downstream of device inventory: a hiccup in
    either subsystem must not cost the operator the device row they just saved.
    Each half is guarded separately so a failure in one still provisions the
    other — and the failure is reported rather than swallowed, because a device
    that is half-monitored looks exactly like a device that is monitored.
    """
    from ..models import db
    from . import deep_monitor as dm
    from . import metrics_collect as mc

    session = session or db.session
    out = {"targets": 0, "probes": [], "errors": []}

    if not mc.provisionable(appliance):
        # Parked or retired: the same guard the sweep applies. Not an error —
        # this is the correct answer for a device nobody expects to answer.
        out["skipped"] = "device is parked or retired"
        return out

    try:
        out["targets"] = mc.ensure_targets(appliance)
    except Exception as exc:                     # noqa: BLE001
        session.rollback()
        log_exception(exc, context="monitoring.ensure_targets")
        out["errors"].append("scrape targets: %s" % str(exc)[:120])

    try:
        out["probes"] = (dm.ensure_baseline(appliance, session=session)
                         or {}).get("created", [])
    except Exception as exc:                     # noqa: BLE001
        session.rollback()
        log_exception(exc, context="monitoring.ensure_baseline")
        out["errors"].append("threshold probes: %s" % str(exc)[:120])

    return out
