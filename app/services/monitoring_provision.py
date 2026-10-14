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

    Returns ``{"targets": int, "probes": [kind, ...], "errors": [str, ...],
    "system_automations": [name, ...]}`` — the last one non-empty only for the
    node's first device (services/system_automations).

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

    # The node's own housekeeping (System Automations) arms itself with its
    # first device (operator, 2026-10-14) — BEFORE the parked/retired check:
    # a node whose first device is parked still needs its nightly backup.
    # Only from zero; see services/system_automations.
    from . import system_automations as sysauto
    seeded = sysauto.ensure_seeded(session=session)
    out["system_automations"] = seeded.get("created", [])
    out["errors"].extend(seeded.get("errors", []))

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


def backfill_baselines(*, session=None) -> dict:
    """Give the baseline to every provisionable device that has NO probe at all.

    The scheduled Collection sweep already self-heals scrape targets for every
    appliance; the threshold half had no such net, so any creation path that
    skipped the seam left a device with metrics and no alerting, forever.
    Measured 2026-10-14: fortiweb18 and fgt02 had 7 and 1 scrape targets and
    zero probes -- one was inserted in bulk with fortiweb17, the other came in
    through a path that never called :func:`provision_monitoring`.

    ZERO probes, not "a baseline kind is missing": an operator who deleted a
    device's CPU probe made a choice, and a sweep that re-creates it every
    three minutes would overrule it. A device with no probe at all is never a
    choice anyone can see -- Fleet health shows it as "no deep monitors
    configured" -- and to silence one, its probes are disabled, not deleted.
    """
    from ..models import Appliance, MonitorProbe, db
    from . import deep_monitor as dm
    from . import metrics_collect as mc

    session = session or db.session
    covered = {aid for (aid,) in session.query(MonitorProbe.appliance_id).distinct()}
    out = {"devices": [], "errors": []}
    for a in session.query(Appliance).order_by(Appliance.id).all():
        if a.id in covered or not mc.provisionable(a):
            continue
        try:
            made = (dm.ensure_baseline(a, session=session) or {}).get("created", [])
        except Exception as exc:                 # noqa: BLE001
            session.rollback()
            log_exception(exc, context="monitoring.backfill_baselines")
            out["errors"].append("%s: %s" % (a.name, str(exc)[:120]))
            continue
        if made:
            out["devices"].append(a.name)
    return out
